//! Сырой USB-захват (USBPcap) через движок: фейковый `USBPcapCMD` печатает подготовленный
//! pcap (3 пакета), движок пишет события `transport=usb`, `detach()` закрывает сессию.
//!
//! `USBPcapCMD` подменяется маленьким Rust-лаунчером (env `FTDI_LOGGER_USBPCAP_CMD`):
//! он пишет байты pcap в stdout и висит, пока его не завершат — как настоящий USBPcapCMD.
//! Тест не требует установленного USBPcap и прав администратора.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ftdi_logger::capture::CaptureManager;
use ftdi_logger::config::Config;
use ftdi_logger::models::{Event, ServerMsg, SessionMeta};
use ftdi_logger::store::SessionStore;
use tokio::sync::broadcast;

const LINKTYPE_USBPCAP: u32 = 249;

struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    fn new(keys: &[&'static str]) -> Self {
        Self {
            saved: keys
                .iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect(),
        }
    }
    fn set(&self, key: &'static str, value: impl AsRef<std::ffi::OsStr>) {
        std::env::set_var(key, value);
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// pcap global header (little-endian, linktype USBPcap).
fn global_header() -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    header.extend_from_slice(&2u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&65535u32.to_le_bytes());
    header.extend_from_slice(&LINKTYPE_USBPCAP.to_le_bytes());
    header
}

/// USBPcap v2-заголовок пакета + данные (формат — как в usbpcap.rs tests).
fn usbpcap_packet(bus: u16, device: u16, endpoint: u8, transfer: u8, data: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&28u16.to_le_bytes()); // headerLen
    header.extend_from_slice(&0x1122_3344u64.to_le_bytes()); // irpId
    header.extend_from_slice(&0u32.to_le_bytes()); // status
    header.extend_from_slice(&0x9u16.to_le_bytes()); // function
    header.extend_from_slice(&0u16.to_le_bytes()); // info
    header.extend_from_slice(&bus.to_le_bytes());
    header.extend_from_slice(&device.to_le_bytes());
    header.push(endpoint);
    header.push(transfer);
    header.extend_from_slice(&(data.len() as u32).to_le_bytes());
    header.extend_from_slice(data);
    header
}

fn pcap_record(seconds: u32, micros: u32, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&seconds.to_le_bytes());
    record.extend_from_slice(&micros.to_le_bytes());
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

/// Три пакета: bulk OUT (4 Б), bulk IN (2 Б), control setup без данных.
fn sample_pcap(ts: f64) -> Vec<u8> {
    let seconds = ts.trunc() as u32;
    let micros = ((ts.fract()) * 1_000_000.0) as u32;
    let mut pcap = global_header();
    pcap.extend_from_slice(&pcap_record(
        seconds,
        micros,
        &usbpcap_packet(1, 4, 0x01, 3, &[0x12, 0x04, 0x0d, 0x1b]),
    ));
    pcap.extend_from_slice(&pcap_record(
        seconds,
        micros + 50_000,
        &usbpcap_packet(1, 4, 0x81, 3, &[0xa0, 0x5a]),
    ));
    // control: 8 байт setup, payload пустой → событие Sys, байты setup сохраняются.
    pcap.extend_from_slice(&pcap_record(
        seconds,
        micros + 100_000,
        &usbpcap_packet(1, 4, 0x00, 2, &[0x40, 0x01, 0x00, 0x00, 0, 0, 0, 0]),
    ));
    pcap
}

fn rustc_path() -> Option<PathBuf> {
    if let Ok(rustc) = std::env::var("RUSTC") {
        let path = PathBuf::from(rustc);
        if path.is_file() {
            return Some(path);
        }
    }
    let ok = Command::new("rustc")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    ok.then(|| PathBuf::from("rustc"))
}

/// Собирает фейковый `USBPcapCMD`: печатает pcap-файл и висит до принудительного завершения.
fn build_fake_usbpcap(dir: &Path) -> Option<PathBuf> {
    let rustc = rustc_path()?;
    let source = dir.join("fake_usbpcap.rs");
    let exe = dir.join("FakeUSBPcapCMD.exe");
    std::fs::write(
        &source,
        r#"
use std::io::Write;
fn main() {
    let path = std::env::var("FTDI_FAKE_PCAP").expect("FTDI_FAKE_PCAP");
    let data = std::fs::read(path).expect("pcap file");
    let mut stdout = std::io::stdout();
    stdout.write_all(&data).expect("write pcap");
    stdout.flush().expect("flush");
    if std::env::var_os("FTDI_FAKE_EXIT").is_none() {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
"#,
    )
    .ok()?;
    let output = Command::new(&rustc)
        .arg(&source)
        .arg("-O")
        .arg("-o")
        .arg(&exe)
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "rustc не собрал фейковый USBPcapCMD: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    Some(exe)
}

fn engine(root: &Path) -> (Arc<CaptureManager>, Arc<SessionStore>) {
    let sessions = root.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let cfg = Arc::new(Config {
        root: root.to_path_buf(),
        sessions_dir: sessions.clone(),
        ui_dist: root.join("ui"),
        port: 0,
        python: PathBuf::from("python"),
        sidecar: root.join("bridge.py"),
        script: root.join("agent.js"),
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(1024);
    (Arc::new(CaptureManager::new(cfg, store.clone(), bus)), store)
}

fn read_meta(dir: &str) -> SessionMeta {
    let text = std::fs::read_to_string(Path::new(dir).join("session.json")).expect("session.json");
    serde_json::from_str(&text).expect("meta json")
}

fn read_events(dir: &str) -> Vec<Event> {
    let text = std::fs::read_to_string(Path::new(dir).join("events.jsonl")).unwrap_or_default();
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Event>(line).ok())
        .collect()
}

fn wait_until(mut check: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    check()
}

#[test]
fn raw_usbpcap_capture_writes_events_and_finishes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Сначала — без USBPcapCMD: понятная ошибка, а не паника/сессия-призрак.
    {
        let (manager, store) = engine(&root.join("missing"));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(async { manager.start_raw_usb(r"\\.\USBPcap1").await })
            .expect_err("без USBPcapCMD старт обязан падать");
        assert!(
            format!("{err:#}").contains("USBPcap"),
            "непонятная ошибка: {err:#}"
        );
        assert!(store.list().is_empty(), "сессия создана без захвата");
    }

    // Фейковый USBPcapCMD + подготовленный pcap.
    let Some(fake_cmd) = build_fake_usbpcap(root) else {
        eprintln!("rustc недоступен — тест raw USB пропущен");
        return;
    };
    let pcap_path = root.join("sample.pcap");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(1_700_000_000.0);
    std::fs::write(&pcap_path, sample_pcap(ts)).unwrap();

    let env = EnvGuard::new(&["FTDI_LOGGER_USBPCAP_CMD", "FTDI_FAKE_PCAP", "FTDI_FAKE_EXIT"]);
    env.set("FTDI_LOGGER_USBPCAP_CMD", &fake_cmd);
    env.set("FTDI_FAKE_PCAP", &pcap_path);
    std::env::remove_var("FTDI_FAKE_EXIT");

    let (manager, store) = engine(&root.join("run"));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let meta = rt
        .block_on(async { manager.start_raw_usb(r"\\.\USBPcap1").await })
        .expect("start_raw_usb с фейковым USBPcapCMD");
    assert_eq!(meta.transport, "usb");
    assert_eq!(meta.process.as_deref(), Some("USBPcapCMD"));
    assert!(
        meta.facts.iter().any(|fact| fact.contains("# usbpcap: device=")),
        "нет факта про устройство: {:?}",
        meta.facts
    );
    assert!(
        meta.facts.iter().any(|fact| fact.contains("# usbpcap: cmd=")),
        "нет факта про путь USBPcapCMD: {:?}",
        meta.facts
    );

    // Статус: идёт запись, моста нет, транспорт usb.
    let status = manager.status();
    assert!(status.recording, "recording=false сразу после старта raw USB");
    assert!(!status.bridge, "bridge=true в raw USB");
    assert_eq!(status.hooks, "off");

    // Ждём 3 пакета.
    assert!(
        wait_until(
            || read_events(&meta.dir).len() >= 3,
            Duration::from_secs(10)
        ),
        "не пришло 3 события: {:?}",
        read_events(&meta.dir)
    );

    // Шаги/метки работают и в raw-режиме (скриншот без окна просто не снимается).
    let step = rt
        .block_on(async { manager.start_step("raw step".into()).await })
        .expect("start_step в raw USB");
    assert_eq!(step.idx, 1);
    rt.block_on(async { manager.mark("raw mark".into()).await })
        .expect("mark в raw USB");
    rt.block_on(async { manager.note("raw note".into()).await })
        .expect("note в raw USB");
    let summary = rt
        .block_on(async { manager.end_step().await })
        .expect("end_step в raw USB");
    assert_eq!(summary.idx, 1);
    assert!(summary.png.is_none(), "в raw-режиме окна нет — png должен быть None");

    let finished = rt
        .block_on(async { manager.detach().await })
        .expect("detach raw USB")
        .expect("мета завершённой сессии");
    assert_eq!(finished.status, "finished");
    assert!(!manager.status().recording, "после detach recording=true");

    // ── события ────────────────────────────────────────────────────────
    let events = read_events(&finished.dir);
    let usb_events: Vec<&Event> = events
        .iter()
        .filter(|event| {
            matches!(event.api.as_str(), "USBRAW" | "USBRAW-SETUP")
                || event.raw.contains("USBRAW")
        })
        .collect();
    assert_eq!(usb_events.len(), 3, "ожидались 3 пакета USBRAW: {usb_events:?}");
    let first = usb_events
        .iter()
        .find(|event| event.api == "USBRAW" && event.direction.is_some())
        .expect("первый Tx/Rx пакет");
    assert_eq!(first.transport, ftdi_logger::models::Transport::Usb);
    assert_eq!(first.hex, "12 04 0d 1b");
    assert!(first.raw.contains("USBRAW"));
    assert_eq!(first.meta.get("usbpcap"), Some(&serde_json::Value::Bool(true)));
    assert_eq!(first.meta.get("bus"), Some(&serde_json::json!(1)));
    assert!(first.t >= 0.0 && first.t < 3600.0, "t пакета: {}", first.t);
    assert!(first.wall.starts_with("20"), "wall не RFC3339: {}", first.wall);
    let control = usb_events
        .iter()
        .find(|event| event.api == "USBRAW-SETUP")
        .expect("control setup событие");
    assert_eq!(control.kind, ftdi_logger::models::EventKind::Sys);
    assert_eq!(control.hex, "40 01 00 00 00 00 00 00");
    assert_eq!(control.len, 8);

    // ── counts и session.json ─────────────────────────────────────────
    let saved = read_meta(&finished.dir);
    assert_eq!(saved.counts.tx, 1, "tx count: {:?}", saved.counts);
    assert_eq!(saved.counts.rx, 1, "rx count: {:?}", saved.counts);
    assert_eq!(saved.counts.tx_bytes, 4);
    assert_eq!(saved.counts.rx_bytes, 2);
    assert_eq!(saved.counts.steps, 1);
    let usbpcap_fact = saved
        .facts
        .iter()
        .find(|fact| fact.starts_with("# usbpcap: packets="))
        .unwrap_or_else(|| panic!("нет итогового факта packets: {:?}", saved.facts));
    assert!(
        usbpcap_fact.contains("packets=3") && usbpcap_fact.contains("bytes=14"),
        "итоговый факт: {usbpcap_fact}"
    );

    // ── raw.log и шаг ─────────────────────────────────────────────────
    let raw = std::fs::read_to_string(Path::new(&finished.dir).join("raw.log")).expect("raw.log");
    assert!(
        raw.lines().next().unwrap_or("").starts_with("# capture start: label=USB raw:"),
        "raw.log без баннера: {}",
        raw.lines().next().unwrap_or("")
    );
    assert!(raw.contains("USBRAW"), "raw.log без строк USBRAW");
    assert!(
        raw.lines().last().unwrap_or("").starts_with("# totals: events="),
        "raw.log без totals"
    );
    assert!(
        Path::new(&finished.dir).join("steps").join("01.json").is_file(),
        "steps/01.json не сохранён"
    );
    let report_exists = Path::new(&finished.dir).join("report.txt").is_file()
        || Path::new(&finished.dir).join("report.md").is_file();
    assert!(report_exists, "отчёты не сформированы");

    // ── сценарий: USBPcapCMD умер сам → авто-аборт сессии ─────────────
    env.set("FTDI_FAKE_EXIT", "1");
    let death_meta = rt
        .block_on(async { manager.start_raw_usb(r"\\.\USBPcap1").await })
        .expect("start_raw_usb для сценария смерти");
    let aborted = wait_until(
        || {
            store
                .list()
                .iter()
                .any(|session| session.id == death_meta.id && session.status == "aborted")
        },
        Duration::from_secs(8),
    );
    assert!(aborted, "сессия не стала aborted после смерти USBPcapCMD");
    assert!(
        wait_until(|| !manager.status().recording, Duration::from_secs(5)),
        "recording=true после смерти USBPcapCMD"
    );
    let death_saved = read_meta(&death_meta.dir);
    assert_eq!(death_saved.status, "aborted");
    assert!(
        death_saved
            .facts
            .iter()
            .any(|fact| fact.contains("# usbpcap-lost:")),
        "нет факта # usbpcap-lost: {:?}",
        death_saved.facts
    );
    let detached = rt.block_on(async { manager.detach().await });
    assert!(detached.is_ok(), "detach после смерти USBPcapCMD: {detached:?}");
    assert!(
        detached.unwrap().is_none(),
        "detach вернул уже закрытую сессию"
    );
    std::env::remove_var("FTDI_FAKE_EXIT");
}


