//! EDIABAS/WinKFP: подключение трасс `api.trc`/`IFH.trc` к дирижёру сессии.
//!
//! Проверяем то, чего не было до интеграции: `attach` собирает INI-факты и offset'ы трасс,
//! `end_step` забирает ТОЛЬКО приращение api.trc (job'ы не дублируются между шагами),
//! пишет `# PHASE N   winkfp: ...` в raw.log до PHASE-JSON, сохраняет приращения и полные
//! копии трасс, а обычный процесс без EDIABAS не получает ни фактов, ни событий.
//!
//! Тест не требует установленного EDIABAS: пути подменяются переменными окружения
//! (`FTDI_LOGGER_EDIABAS_INI`, `_OBD_INI`, `_WINKFP_INI`, `_TRACE_DIR`).
//! Frida-мост — заглушка из `sidecar/bridge.py` (реальный Python), цель — скрытый python-процесс.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ftdi_logger::capture::CaptureManager;
use ftdi_logger::config::Config;
use ftdi_logger::models::{ServerMsg, SessionMeta, StepSummary};
use ftdi_logger::store::SessionStore;
use tokio::sync::broadcast;

/// Кусок реального формата `api.trc` (reference/logs/ediabas/api.trc).
const API_TRC_HEAD: &str = "#'Mon Oct 12 02:00:00 2026;!Xh;V7.3.0;#\n\
Initialization\nJob\n\t\"bms46ds0\"\n\t\"ident\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
Results:\n\t[ 0 ]\n\tOBJECT = \"bms46ds0\"\n\tID_BMW_NR = \"1430940\"\n\tID_SW_NR = \"F0\"\n\
Initialization\nJob\n\t\"ms450\"\n\t\"FLASH_PROGRAMMIEREN\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
Error (134) API-0014: RESULT NOT FOUND\n";

const IFH_TRC_HEAD: &str = "_STD      >>> Interface Communication Trace <<<\n\
_STD      INPUT: --\n_STD      OUTPUT: 12 04 0D 1B\n";

const API_TRC_STEP1: &str = "Initialization\nJob\n\t\"ms41\"\n\t\"STATUS\"\n\t\"\"\n\t0\n\
\t\"\"\n\t0\n\t0\nResults:\n\t[ 0 ]\n\tOBJECT = \"ms41\"\n\tID_SW_NR = \"ABC123\"\n";

const API_TRC_STEP2: &str = "Initialization\nJob\n\t\"ms41\"\n\t\"FLASH_PROGRAMMIEREN\"\n\
\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\nError (134) API-0014: RESULT NOT FOUND\n";

const FAKE_SIDECAR: &str = r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        # attach теперь считается успешным только после ready (CAP-05).
        print(json.dumps({"type": "hello", "bridge": "fake", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 1, "script": "agent.js"}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 0}), flush=True)
        sys.exit(0)
"#;

/// Сохраняет/восстанавливает переменные окружения, чтобы подмена путей была локальной.
struct EnvGuard {
    saved: Vec<(&'static str, Option<OsString>)>,
}

impl EnvGuard {
    fn new(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        Self { saved }
    }

    fn set(&self, key: &'static str, value: impl AsRef<std::ffi::OsStr>) {
        std::env::set_var(key, value);
    }

    fn remove(&self, key: &'static str) {
        std::env::remove_var(key);
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

fn python_available() -> bool {
    Command::new("python")
        .args(["-c", "print(1)"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn append(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap_or_else(|err| panic!("открыть {} на дозапись: {err}", path.display()));
    file.write_all(text.as_bytes())
        .unwrap_or_else(|err| panic!("дописать {}: {err}", path.display()));
}

fn read_step(dir: &Path, idx: u32) -> StepSummary {
    let path = dir.join("steps").join(format!("{idx:02}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("нет {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("битый {}: {err}", path.display()))
}

fn read_meta(dir: &Path) -> SessionMeta {
    let path = dir.join("session.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("нет session.json: {err}"));
    serde_json::from_str(&text).expect("session.json парсится")
}

fn read_raw(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("raw.log")).expect("raw.log существует")
}

fn line_index(lines: &[&str], needle: &str) -> Option<usize> {
    lines.iter().position(|line| line.contains(needle))
}

fn session_path(sessions: &Path, id: &str) -> PathBuf {
    sessions.join(id)
}

/// Основной сценарий: два шага, между ними дописываем job'ы в api.trc.
#[test]
fn ediabas_traces_are_attributed_to_steps() {
    if !python_available() {
        eprintln!("python недоступен — тест EDIABAS-интеграции пропущен");
        return;
    }

    // ── окружение теста ────────────────────────────────────────────────
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let sessions = root.join("sessions");
    let trace_dir = root.join("TRACE");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::create_dir_all(&trace_dir).unwrap();

    let sidecar = root.join("bridge.py");
    let script = root.join("agent.js");
    std::fs::write(&sidecar, FAKE_SIDECAR).unwrap();
    std::fs::write(&script, "// заглушка Frida-агента\n").unwrap();

    let api_trc = trace_dir.join("api.trc");
    let ifh_trc = trace_dir.join("IFH.trc");
    std::fs::write(&api_trc, API_TRC_HEAD).unwrap();
    std::fs::write(&ifh_trc, IFH_TRC_HEAD).unwrap();

    let ediabas_ini = root.join("EDIABAS.INI");
    std::fs::write(
        &ediabas_ini,
        format!(
            "Interface=STD:OBD\nTracePath={}\nApiTrace=1\nIfhTrace=1\nTraceSize=2048\n",
            trace_dir.display()
        ),
    )
    .unwrap();
    let obd_ini = root.join("OBD.INI");
    std::fs::write(&obd_ini, "Port=COM1\nHardware=OBD\nRETRY=2\n").unwrap();
    let winkfp_ini = root.join("Winkfpt.ini");
    std::fs::write(&winkfp_ini, "API_TRACE=1\nIFH_TRACE=1\nSCHNELLE_BAUDRATE=1\n").unwrap();

    let env = EnvGuard::new(&[
        "FTDI_LOGGER_EDIABAS_INI",
        "FTDI_LOGGER_OBD_INI",
        "FTDI_LOGGER_WINKFP_INI",
        "FTDI_LOGGER_TRACE_DIR",
        "FTDI_LOGGER_EDIABAS",
    ]);
    env.set("FTDI_LOGGER_EDIABAS_INI", &ediabas_ini);
    env.set("FTDI_LOGGER_OBD_INI", &obd_ini);
    env.set("FTDI_LOGGER_WINKFP_INI", &winkfp_ini);
    env.set("FTDI_LOGGER_TRACE_DIR", &trace_dir);
    env.remove("FTDI_LOGGER_EDIABAS"); // авто-детект: активные трассы

    // ── цель и движок ──────────────────────────────────────────────────
    let mut target = Command::new("python")
        .args(["-c", "import time; time.sleep(120)"])
        .spawn()
        .expect("запустить python-цель");
    std::thread::sleep(std::time::Duration::from_millis(800));

    let cfg = Arc::new(Config {
        root: root.to_path_buf(),
        sessions_dir: sessions.clone(),
        ui_dist: root.join("ui"),
        port: 0,
        python: PathBuf::from("python"),
        sidecar: sidecar.clone(),
        script: script.clone(),
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(4096);
    let manager = CaptureManager::new(cfg.clone(), store, bus);
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let pid = target.id();

    let (meta, step1, step2) = rt.block_on(async {
        let meta = manager
            .attach(pid, "EDIABAS e2e".into(), None)
            .await
            .expect("attach");
        // attach обязан собрать INI-факты и включить режим (свежие трассы).
        assert!(
            meta.facts.iter().any(|fact| fact.starts_with("# ediabas-ini:")),
            "нет INI-фактов в session.json: {:?}",
            meta.facts
        );

        // Шаг 1: пишем job в api.trc уже после attach (стартовые job'ы не должны попасть).
        manager.start_step("шаг 1".into()).await.expect("start_step 1");
        append(&api_trc, API_TRC_STEP1);
        append(&ifh_trc, "_STD      INPUT: 10 85\n_STD      OUTPUT: 50 85\n");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let step1 = manager.end_step().await.expect("end_step 1");

        // Шаг 2: ещё один job — в шаг должны попасть только новые.
        manager.start_step("шаг 2".into()).await.expect("start_step 2");
        append(&api_trc, API_TRC_STEP2);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let step2 = manager.end_step().await.expect("end_step 2");

        let finished = manager
            .detach()
            .await
            .expect("detach")
            .expect("мета завершённой сессии");
        (finished, step1, step2)
    });
    let _ = target.kill();
    let _ = target.wait();

    assert_eq!(meta.status, "finished");
    let session_dir = session_path(&sessions, &meta.id);

    // ── шаг 1: только job STATUS ───────────────────────────────────────
    assert_eq!(step1.winkfp_jobs.len(), 1, "в шаге 1 должен быть ровно один job");
    assert_eq!(step1.winkfp_jobs[0].job, "STATUS");
    assert_eq!(step1.winkfp_jobs[0].sgbd, "ms41");
    // ── шаг 2: только новый FLASH + ошибка ─────────────────────────────
    assert_eq!(step2.winkfp_jobs.len(), 1, "в шаге 2 не должно быть дублей");
    assert_eq!(step2.winkfp_jobs[0].job, "FLASH_PROGRAMMIEREN");
    assert_eq!(step2.winkfp_jobs[0].errors.len(), 1, "ошибка job'а потерялась");

    // steps/NN.json на диске.
    let saved1 = read_step(&session_dir, 1);
    let saved2 = read_step(&session_dir, 2);
    assert_eq!(saved1.winkfp_jobs.len(), 1);
    assert_eq!(saved1.winkfp_jobs[0].job, "STATUS");
    assert!(
        saved1.winkfp_jobs.iter().all(|j| j.job != "FLASH_PROGRAMMIEREN"),
        "в шаг 1 попал job из шага 2"
    );
    assert_eq!(saved2.winkfp_jobs.len(), 1);
    assert_eq!(saved2.winkfp_jobs[0].job, "FLASH_PROGRAMMIEREN");
    assert!(
        saved2.winkfp_jobs.iter().all(|j| j.job != "STATUS"),
        "шаг 2 повторил job шага 1"
    );

    // raw.log: winkfp-строки до PHASE-JSON, без дублей.
    let raw = read_raw(&session_dir);
    let lines: Vec<&str> = raw.lines().collect();
    let ph1 = line_index(&lines, "# PHASE 1   winkfp: job=\"STATUS\" sgbd=\"ms41\"")
        .unwrap_or_else(|| panic!("нет winkfp-строки шага 1 в raw.log:\n{raw}"));
    let pj1 = lines
        .iter()
        .position(|line| line.starts_with("# PHASE-JSON") && line.contains("\"idx\":1"))
        .unwrap_or_else(|| panic!("нет PHASE-JSON шага 1:\n{raw}"));
    assert!(ph1 < pj1, "winkfp-строка шага 1 должна идти до PHASE-JSON");
    let ph2 = line_index(
        &lines,
        "# PHASE 2   winkfp: job=\"FLASH_PROGRAMMIEREN\" sgbd=\"ms41\"",
    )
    .unwrap_or_else(|| panic!("нет winkfp-строки шага 2 в raw.log:\n{raw}"));
    assert!(ph2 > pj1, "строки шага 2 должны быть после PHASE-JSON шага 1");
    assert_eq!(
        raw.matches("# PHASE 2   winkfp: job=\"STATUS\"").count(),
        0,
        "job шага 1 продублирован в шаге 2"
    );
    assert!(
        raw.contains("ОШИБКА: Error (134) API-0014: RESULT NOT FOUND"),
        "ошибка job'а не попала в raw.log:\n{raw}"
    );

    // Сырые приращения трасс и полные копии.
    let step1_api = session_dir.join("winkfp").join("step-01-api.trc");
    let step2_api = session_dir.join("winkfp").join("step-02-api.trc");
    let step1_api_text = std::fs::read_to_string(&step1_api).expect("step-01-api.trc");
    let step2_api_text = std::fs::read_to_string(&step2_api).expect("step-02-api.trc");
    assert!(step1_api_text.contains("STATUS"));
    assert!(!step1_api_text.contains("FLASH_PROGRAMMIEREN"));
    assert!(step2_api_text.contains("FLASH_PROGRAMMIEREN"));
    assert!(!step2_api_text.contains("\"STATUS\""));
    assert!(session_dir
        .join("winkfp")
        .join("step-01-IFH.trc")
        .is_file(), "приращение IFH.trc не сохранено");
    let full_api = std::fs::read_to_string(session_dir.join("winkfp").join("api.trc"))
        .expect("полная копия api.trc");
    assert!(full_api.contains("bms46ds0"), "полная копия потеряла стартовые job'ы");
    assert!(full_api.contains("STATUS") && full_api.contains("FLASH_PROGRAMMIEREN"));

    // Факты сессии: INI, шаги, итог.
    let stored = read_meta(&session_dir);
    assert!(stored.facts.iter().any(|f| f.starts_with("# ediabas-ini:")));
    assert!(
        stored.facts.iter().any(|f| f.contains("# winkfp step 1: jobs=1")),
        "нет факта шага 1: {:?}",
        stored.facts
    );
    assert!(
        stored
            .facts
            .iter()
            .any(|f| f.contains("job'ов за сессию 2, с ошибками 1")),
        "нет итогового факта EDIABAS: {:?}",
        stored.facts
    );

    // События: sys-факты EDIABAS попали в поток (UI их видит).
    let events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
    assert!(
        events.contains("\"api\":\"EDIABAS\"") && events.contains("# ediabas-ini:"),
        "sys-события EDIABAS не попали в events.jsonl"
    );

    // ── сценарий 2: трасс нет, процесс не EDIABAS → никаких фактов/строк ──
    let empty_trace_dir = root.join("TRACE_EMPTY");
    std::fs::create_dir_all(&empty_trace_dir).unwrap();
    env.set("FTDI_LOGGER_TRACE_DIR", &empty_trace_dir);

    let mut target2 = Command::new("python")
        .args(["-c", "import time; time.sleep(120)"])
        .spawn()
        .expect("запустить вторую python-цель");
    std::thread::sleep(std::time::Duration::from_millis(800));
    let pid2 = target2.id();

    let plain_meta = rt.block_on(async {
        let meta = manager
            .attach(pid2, "plain quickflash".into(), None)
            .await
            .expect("attach без трасс");
        assert_eq!(meta.pid, Some(pid2));
        manager.start_step("обычный шаг".into()).await.expect("start_step");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let summary = manager.end_step().await.expect("end_step без трасс");
        assert!(
            summary.winkfp_jobs.is_empty(),
            "без трасс winkfp_jobs должен быть пуст"
        );
        manager
            .detach()
            .await
            .expect("detach")
            .expect("мета завершённой сессии")
    });
    let _ = target2.kill();
    let _ = target2.wait();

    let plain_dir = session_path(&sessions, &plain_meta.id);
    let plain_stored = read_meta(&plain_dir);
    assert!(
        plain_stored.facts.iter().all(|f| !f.starts_with("# ediabas-ini:")),
        "обычному процессу добавились EDIABAS-факты: {:?}",
        plain_stored.facts
    );
    let plain_raw = read_raw(&plain_dir);
    assert!(
        !plain_raw.contains("winkfp:"),
        "обычному процессу добавились winkfp-строки:\n{plain_raw}"
    );
    let plain_steps = read_step(&plain_dir, 1);
    assert!(plain_steps.winkfp_jobs.is_empty());
}
