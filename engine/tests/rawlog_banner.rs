//! Совместимость `raw.log` живой сессии со старым логером:
//! баннер (`# capture start:` и т.д.) в начале, `# totals:` в конце, и проверка
//! `tools/legacy/parse_family.py` — он должен видеть сессию, а не «преамбулу».
//!
//! Плюс ручной (`#[ignore]`) прогон на РЕАЛЬНОМ sidecar/Frida с `tests/e2e/dummy_target.py`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ftdi_logger::capture::CaptureManager;
use ftdi_logger::config::Config;
use ftdi_logger::models::ServerMsg;
use ftdi_logger::store::SessionStore;
use tokio::sync::broadcast;

fn python_available() -> bool {
    Command::new("python")
        .args(["-c", "print(1)"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("engine/ имеет родителя — корень репозитория")
        .to_path_buf()
}

fn parse_family(raw: &Path) -> String {
    let script = repo_root().join("tools").join("legacy").join("parse_family.py");
    assert!(script.is_file(), "нет legacy-парсера {}", script.display());
    let output = Command::new("python")
        .arg(&script)
        .arg("--log")
        .arg(raw)
        .args(["--gap", "2.0", "--no-dump", "--no-reads"])
        // Иначе кириллица из Windows-консоли приходит в cp1251 и строки не сравнить.
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUTF8", "1")
        .output()
        .expect("запустить parse_family.py");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "parse_family.py упал ({}):\n{stderr}\n{stdout}",
        output.status
    );
    assert!(
        !stdout.contains("Преамбула"),
        "parse_family считает живой экшен преамбулой:\n{stdout}"
    );
    stdout
}

/// Движок с отдельными каталогами и своим fake-sidecar.
fn engine(root: &Path, sidecar_script: &str) -> (Arc<CaptureManager>, PathBuf) {
    let sessions = root.join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let sidecar = root.join("bridge.py");
    let script = root.join("agent.js");
    std::fs::write(&sidecar, sidecar_script).unwrap();
    std::fs::write(&script, "// заглушка Frida-агента\n").unwrap();
    let cfg = Arc::new(Config {
        root: root.to_path_buf(),
        sessions_dir: sessions,
        ui_dist: root.join("ui"),
        port: 0,
        python: PathBuf::from("python"),
        sidecar,
        script,
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(1024);
    (Arc::new(CaptureManager::new(cfg, store, bus)), root.to_path_buf())
}

fn read_raw(meta_dir: &str) -> String {
    std::fs::read_to_string(Path::new(meta_dir).join("raw.log")).expect("raw.log")
}

const SIDECAR_WITH_EXCHANGE: &str = r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "fake", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 1, "script": "agent.js"}), flush=True)
        print(json.dumps({"type": "event", "line": "[+0.100s] TX ftd2xx FT_Write rc=0 len=2 n=2 : aa bb", "wall": "2026-01-01T00:00:00.000Z"}), flush=True)
        print(json.dumps({"type": "event", "line": "[+0.150s] RX ftd2xx FT_Read rc=0 want=64 n=2 : a0 5a", "wall": "2026-01-01T00:00:00.050Z"}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 2}), flush=True)
        sys.exit(0)
"#;

const SIDECAR_QUIET: &str = r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "fake", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 1, "script": "agent.js"}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 0}), flush=True)
        sys.exit(0)
"#;

fn spawn_target() -> std::process::Child {
    Command::new("python")
        .args(["-c", "import time; time.sleep(120)"])
        .spawn()
        .expect("запустить python-цель")
}

#[test]
fn raw_log_has_legacy_banner_and_totals() {
    if !python_available() {
        eprintln!("python недоступен — тест баннера raw.log пропущен");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut target = spawn_target();
    std::thread::sleep(Duration::from_millis(700));
    let pid = target.id();

    // ── сессия с обменом: баннер + события + totals, parse_family видит сессию ──
    {
        let (manager, root) = engine(&tmp.path().join("exchange"), SIDECAR_WITH_EXCHANGE);
        let meta = rt
            .block_on(async { manager.attach(pid, "Banner Test".into(), None).await })
            .expect("attach с обменом");
        assert_eq!(meta.pid, Some(pid));
        assert_eq!(meta.label, "Banner Test");
        rt.block_on(async { tokio::time::sleep(Duration::from_millis(400)).await });
        let finished = rt
            .block_on(async { manager.detach().await })
            .expect("detach")
            .expect("мета сессии");
        let raw = read_raw(&finished.dir);
        let lines: Vec<&str> = raw.lines().collect();
        assert!(!lines.is_empty());
        // Баннер идёт с первой строки, до него нет «=»/мусора (иначе parse_family даст преамбулу).
        assert!(
            lines[0].starts_with("# capture start: label=Banner Test"),
            "первая строка raw.log без capture start: {:?}",
            lines[0]
        );
        assert!(
            lines[1].starts_with("# tool: ") && !lines[1].trim_end_matches("# tool: ").is_empty(),
            "нет строки # tool: {:?}",
            lines.get(1)
        );
        let exe_line = lines
            .iter()
            .find(|l| l.starts_with("# exe: "))
            .unwrap_or_else(|| panic!("нет строки # exe: в {raw}"));
        assert!(exe_line.contains(" size="), "нет size в {exe_line:?}");
        assert!(exe_line.contains(" sha256="), "нет sha256 в {exe_line:?}");
        assert!(
            raw.lines().any(|l| l.starts_with("# wall(start)=")),
            "нет wall(start) в raw.log"
        );
        assert!(
            raw.lines().any(|l| l.starts_with("# host: user=") && l.contains(" computer=")),
            "нет host в raw.log"
        );
        assert_eq!(raw.matches("# capture start:").count(), 1, "баннер продублирован");
        // Итоги в самом конце.
        let last = lines.last().copied().unwrap_or_default();
        assert!(
            last.starts_with("# totals: events=2 "),
            "последняя строка raw.log не totals: {last:?}"
        );
        assert!(last.contains(" tx=1/2 "), "totals без tx=1/2: {last:?}");
        assert!(last.contains(" rx=1/2 "), "totals без rx=1/2: {last:?}");
        assert!(last.contains(" steps=0"), "totals без steps: {last:?}");
        // Legacy-парсер: сессия распознана, преамбулы нет.
        let parsed = parse_family(Path::new(&finished.dir).join("raw.log").as_path());
        assert!(
            parsed.contains("СЕССИЯ"),
            "parse_family не увидел сессию:\n{parsed}"
        );
        assert!(parsed.contains("обменов="), "parse_family без обменов:\n{parsed}");
        let _ = root;
    }

    // ── сессия без обменов (как dummy_target): всё равно не преамбула ──
    {
        let (manager, _root) = engine(&tmp.path().join("quiet"), SIDECAR_QUIET);
        let meta = rt
            .block_on(async { manager.attach(pid, "Quiet Test".into(), None).await })
            .expect("attach без обменов");
        let finished = rt
            .block_on(async { manager.detach().await })
            .expect("detach")
            .expect("мета сессии");
        assert_eq!(finished.id, meta.id);
        let raw = read_raw(&finished.dir);
        let lines: Vec<&str> = raw.lines().collect();
        assert!(lines[0].starts_with("# capture start: label=Quiet Test"));
        assert!(
            lines.last().unwrap_or(&"").starts_with("# totals: events=0 "),
            "totals без событий: {:?}",
            lines.last()
        );
        let parsed = parse_family(Path::new(&finished.dir).join("raw.log").as_path());
        assert!(
            !parsed.contains("Преамбула"),
            "0-обменная сессия распознана как преамбула:\n{parsed}"
        );
    }

    let _ = target.kill();
    let _ = target.wait();
}

/// Найти python с установленным frida (как в config::default_python).
fn python_with_frida() -> Option<PathBuf> {
    let candidates = [
        r"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python313\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python311\python.exe",
    ];
    for candidate in candidates {
        let path = Path::new(candidate);
        if !path.is_file() {
            continue;
        }
        let ok = Command::new(path)
            .args(["-c", "import frida"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if ok {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// Ручной прогон на РЕАЛЬНОМ sidecar (Frida) + `tests/e2e/dummy_target.py`.
///
/// `#[ignore]`: нужен установленный frida и интерактивная Windows-сессия.
/// Запуск: `cargo test --test rawlog_banner -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_dummy_target_ready_and_parse_family() {
    let Some(python) = python_with_frida() else {
        eprintln!("python с frida не найден — ручной E2E пропущен");
        return;
    };
    let repo = repo_root();
    let dummy = repo.join("tests").join("e2e").join("dummy_target.py");
    assert!(dummy.is_file(), "нет {}", dummy.display());
    let sidecar = repo.join("sidecar").join("bridge.py");
    let script = repo.join("sidecar").join("agents").join("ftdi_capture.js");
    assert!(sidecar.is_file() && script.is_file(), "sidecar/агент не собраны");

    let tmp = tempfile::tempdir().expect("tempdir");
    let sessions = tmp.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let cfg = Arc::new(Config {
        root: repo.clone(),
        sessions_dir: sessions,
        ui_dist: repo.join("ui").join("dist"),
        port: 0,
        python: python.clone(),
        sidecar,
        script,
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(4096);
    let manager = Arc::new(CaptureManager::new(cfg, store, bus));

    let mut target = Command::new(&python)
        .arg(&dummy)
        .args(["--seconds", "25", "--bytes"])
        .spawn()
        .expect("запустить dummy_target.py");
    std::thread::sleep(Duration::from_millis(1500));
    let rt = tokio::runtime::Runtime::new().unwrap();

    // attach теперь ждёт ready от реального sidecar (CAP-05).
    let meta = rt
        .block_on(async { manager.attach(target.id(), "dummy-target".into(), None).await })
        .expect("attach к реальному dummy_target через Frida");
    eprintln!("attach ok: session={} pid={:?}", meta.id, meta.pid);
    // Дать агенту захватить стартовые вызовы FT_*.
    rt.block_on(async { tokio::time::sleep(Duration::from_secs(3)).await });
    let status = manager.status();
    eprintln!(
        "status: recording={} bridge={} hooks={} events={}",
        status.recording, status.bridge, status.hooks, status.counts.events
    );
    let finished = rt
        .block_on(async { manager.detach().await })
        .expect("detach")
        .expect("мета сессии");
    let _ = target.kill();
    let _ = target.wait();
    assert_eq!(finished.status, "finished");

    let raw_path = Path::new(&finished.dir).join("raw.log");
    let raw = std::fs::read_to_string(&raw_path).expect("raw.log");
    assert!(
        raw.lines().next().unwrap_or("").starts_with("# capture start: label=dummy-target"),
        "raw.log без баннера"
    );
    assert!(
        raw.lines().last().unwrap_or("").starts_with("# totals: events="),
        "raw.log без totals"
    );
    let parsed = parse_family(&raw_path);
    assert!(
        !parsed.contains("Преамбула"),
        "реальная сессия распознана как преамбула:\n{parsed}"
    );
    eprintln!("parse_family на реальной сессии:\n{parsed}");
}