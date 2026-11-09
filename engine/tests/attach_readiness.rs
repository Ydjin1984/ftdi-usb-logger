//! CAP-05: attach считается успешным только после `BridgeMsg::Ready`, а смерть моста
//! после attach закрывает сессию как `aborted` (без «висящего» recording=true).
//!
//! Сценарии (в одном тесте, чтобы не гонять env-переменные параллельно):
//!  (а) attach к несуществующему pid → ошибка, сессии нет;
//!  (б) sidecar присылает fatal Error до ready → attach-ошибка, сессия aborted, повторный
//!      attach не получает вечный 409;
//!  (в) sidecar молчит → attach падает по таймауту ready (env-переопределение), сессия aborted;
//!  (г) успешный attach (ready + события), затем sidecar умирает → status перестаёт быть
//!      recording, сессия aborted с причиной в facts, detach проходит без ошибок;
//!  (д) обычный успешный attach/detach и повторный attach после detach работают.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ftdi_logger::capture::CaptureManager;
use ftdi_logger::config::Config;
use ftdi_logger::models::{ServerMsg, SessionMeta};
use ftdi_logger::store::SessionStore;
use tokio::sync::broadcast;

fn python_available() -> bool {
    Command::new("python")
        .args(["-c", "print(1)"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Временная подмена таймаута ready.
struct EnvGuard {
    key: &'static str,
    saved: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let saved = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.saved.take() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

/// Движок с отдельными каталогами сессий и своим sidecar-скриптом.
fn engine(root: &Path, sidecar_script: &str) -> (Arc<CaptureManager>, Arc<SessionStore>) {
    let session_root = root.join("sessions");
    std::fs::create_dir_all(&session_root).unwrap();
    let sidecar = root.join("bridge.py");
    let script = root.join("agent.js");
    std::fs::write(&sidecar, sidecar_script).unwrap();
    std::fs::write(&script, "// заглушка Frida-агента\n").unwrap();
    let cfg = Arc::new(Config {
        root: root.to_path_buf(),
        sessions_dir: session_root.clone(),
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
    let manager = Arc::new(CaptureManager::new(cfg, store.clone(), bus));
    (manager, store)
}

fn read_meta(dir: &Path) -> Option<SessionMeta> {
    let text = std::fs::read_to_string(dir.join("session.json")).ok()?;
    serde_json::from_str(&text).ok()
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
fn attach_requires_ready_and_aborts_when_bridge_dies() {
    if !python_available() {
        eprintln!("python недоступен — тест CAP-05 пропущен");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Живая цель для сценариев б/в/г/д — скрытый python-процесс без окна.
    let mut target = Command::new("python")
        .args(["-c", "import time; time.sleep(180)"])
        .spawn()
        .expect("запустить python-цель");
    std::thread::sleep(Duration::from_millis(700));
    let pid = target.id();

    // ── (а) несуществующий pid: ошибка, сессии нет ─────────────────────
    {
        let (manager, store) = engine(&root.join("a"), "// sidecar не запустится\n");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(async { manager.attach(0xFFFF_FFF0, "none".into(), None).await })
            .expect_err("attach к несуществующему pid должен падать");
        let text = format!("{err:#}");
        assert!(
            text.contains("не найден"),
            "непонятная ошибка attach: {text}"
        );
        assert!(
            rt.block_on(async { manager.detach().await }).unwrap().is_none(),
            "после провала attach detach должен быть пустым"
        );
        assert!(store.list().is_empty(), "сессия для несуществующего pid создана");
    }

    // ── (б) fatal Error до ready: attach-ошибка, сессия aborted ─────────
    {
        let sidecar = r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "error", "fatal": True, "msg": "frida: unable to attach to pid"}), flush=True)
        sys.exit(2)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 0}), flush=True)
        sys.exit(0)
"#;
        let (manager, store) = engine(&root.join("b"), sidecar);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(async { manager.attach(pid, "fatal-before-ready".into(), None).await })
            .expect_err("attach должен падать при fatal Error до ready");
        let text = format!("{err:#}");
        assert!(
            text.contains("unable to attach"),
            "причина ошибки потеряна: {text}"
        );
        assert!(
            !text.contains("уже идёт"),
            "после провала attach состояние не очищено: {text}"
        );
        let status = manager.status();
        assert!(!status.recording, "recording=true после провала attach");
        assert_eq!(status.hooks, "off");
        assert!(!status.bridge);
        assert!(manager.active().is_none(), "active() не очищен после провала");
        // Сессия создана, но закрыта как aborted и с причиной в facts.
        let sessions = store.list();
        assert_eq!(sessions.len(), 1, "ожидалась одна aborted-сессия");
        let session_dir = PathBuf::from(&sessions[0].dir);
        let saved = read_meta(&session_dir).expect("session.json");
        assert_eq!(saved.status, "aborted");
        assert!(
            saved.facts.iter().any(|f| f.contains("# attach-failed:") && f.contains("unable to attach")),
            "причина провала не попала в facts: {:?}",
            saved.facts
        );
        // (г-часть для этого сценария) повторный attach не упирается в 409.
        let retry = rt.block_on(async { manager.attach(pid, "retry".into(), None).await });
        let retry_text = format!("{:?}", retry.err().expect("и повторный attach падает"));
        assert!(
            !retry_text.contains("уже идёт"),
            "повторный attach после провала заблокирован: {retry_text}"
        );
    }

    // ── (в) sidecar молчит: таймаут ready, сессия aborted ──────────────
    {
        let _timeout = EnvGuard::set("FTDI_LOGGER_READY_TIMEOUT_MS", "400");
        let silent = r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if msg.get("cmd") == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 0}), flush=True)
        sys.exit(0)
"#;
        let (manager, store) = engine(&root.join("c"), silent);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let started = Instant::now();
        let err = rt
            .block_on(async { manager.attach(pid, "silent".into(), None).await })
            .expect_err("attach без ready должен падать по таймауту");
        let text = format!("{err:#}");
        assert!(
            text.contains("ready не пришёл"),
            "непонятная ошибка таймаута: {text}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "таймаут ready слишком долгий: {:?}",
            started.elapsed()
        );
        assert!(!manager.status().recording);
        let sessions = store.list();
        assert_eq!(sessions.len(), 1);
        let saved = read_meta(&PathBuf::from(&sessions[0].dir)).expect("session.json");
        assert_eq!(saved.status, "aborted");
        assert!(
            saved.facts.iter().any(|f| f.contains("# attach-failed:")),
            "facts без причины: {:?}",
            saved.facts
        );
    }

    // ── (г) успешный attach, затем смерть моста ────────────────────────
    {
        let dying = r#"
import json
import sys
import time

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "fake", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 1, "script": "agent.js"}), flush=True)
        for i in range(3):
            print(json.dumps({"type": "event", "line": "[+%.3fs] TX ftd2xx FT_Write rc=0 len=2 n=2 : aa %02x" % (0.05 * i, i), "wall": "2026-01-01T00:00:00.000Z"}), flush=True)
        time.sleep(0.5)
        print(json.dumps({"type": "error", "fatal": True, "msg": "frida script crashed"}), flush=True)
        sys.exit(3)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 0}), flush=True)
        sys.exit(0)
"#;
        let (manager, store) = engine(&root.join("g"), dying);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = rt
            .block_on(async { manager.attach(pid, "dying".into(), None).await })
            .expect("attach с ready должен проходить");
        assert_eq!(meta.pid, Some(pid));
        // Сразу после ready запись идёт.
        let ready_status = manager.status();
        assert!(ready_status.recording, "после ready recording=false");
        assert!(ready_status.bridge, "мост не запущен после ready");
        // Ждём смерти моста и авто-аборта сессии.
        let aborted = wait_until(
            || {
                manager
                    .store()
                    .list()
                    .iter()
                    .any(|m| m.id == meta.id && m.status == "aborted")
            },
            Duration::from_secs(8),
        );
        assert!(aborted, "сессия не стала aborted после смерти моста");
        assert!(
            wait_until(|| manager.active().is_none(), Duration::from_secs(5)),
            "active() остался после авто-аборта"
        );
        let status = manager.status();
        assert!(!status.recording, "recording=true после смерти моста");
        assert!(!status.bridge, "bridge=true после смерти моста");
        assert_eq!(status.hooks, "off");
        let session_dir = PathBuf::from(&meta.dir);
        let saved = read_meta(&session_dir).expect("session.json");
        assert_eq!(saved.status, "aborted");
        assert!(
            saved.facts.iter().any(|f| f.contains("# bridge-lost:")),
            "причина смерти моста не в facts: {:?}",
            saved.facts
        );
        // События до смерти успели записаться.
        let events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap_or_default();
        assert!(events.contains("FT_Write"), "события моста не записались");
        // detach после авто-аборта — без ошибок, сессия уже закрыта.
        let detached = rt.block_on(async { manager.detach().await });
        assert!(
            detached.is_ok(),
            "detach после смерти моста вернул ошибку: {detached:?}"
        );
        assert!(detached.unwrap().is_none(), "detach вернул уже закрытую сессию");
        let _ = store;
    }

    // ── (д) обычный attach/detach и повторный attach ───────────────────
    {
        let stable = r#"
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
        let (manager, store) = engine(&root.join("d"), stable);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = rt
            .block_on(async { manager.attach(pid, "stable-1".into(), None).await })
            .expect("первый attach");
        assert!(manager.status().recording);
        let finished = rt
            .block_on(async { manager.detach().await })
            .expect("detach")
            .expect("мета завершённой сессии");
        assert_eq!(finished.id, meta.id);
        assert_eq!(finished.status, "finished");
        // Повторный attach после detach — работает (нет вечного 409).
        let second = rt
            .block_on(async { manager.attach(pid, "stable-2".into(), None).await })
            .expect("повторный attach после detach");
        assert_eq!(second.pid, Some(pid));
        assert!(manager.status().recording);
        let finished2 = rt
            .block_on(async { manager.detach().await })
            .expect("второй detach")
            .expect("мета второй сессии");
        assert_eq!(finished2.id, second.id);
        assert!(store.list().iter().filter(|m| m.status == "finished").count() >= 2);
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

/// Ручной репро CAP-05 на РЕАЛЬНОМ sidecar/Frida: attach к системному pid=4 (System)
/// обязан вернуть ошибку, оставить сессию aborted (recording=false) и не блокировать
/// повторный attach.
///
/// `#[ignore]`: нужен установленный frida и интерактивная Windows-сессия.
/// Запуск: `cargo test --test attach_readiness -- --ignored --nocapture`.
#[test]
#[ignore]
fn real_attach_to_system_pid_fails_cleanly() {
    let Some(python) = python_with_frida() else {
        eprintln!("python с frida не найден — ручной репро pid=4 пропущен");
        return;
    };
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("корень репозитория")
        .to_path_buf();
    let sidecar = repo.join("sidecar").join("bridge.py");
    let script = repo.join("sidecar").join("agents").join("ftdi_capture.js");
    assert!(sidecar.is_file() && script.is_file(), "sidecar/агент не собраны");
    let _timeout = EnvGuard::set("FTDI_LOGGER_READY_TIMEOUT_MS", "8000");

    let tmp = tempfile::tempdir().expect("tempdir");
    let sessions = tmp.path().join("sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let cfg = Arc::new(Config {
        root: repo.clone(),
        sessions_dir: sessions,
        ui_dist: repo.join("ui").join("dist"),
        port: 0,
        python,
        sidecar,
        script,
        open_ui: false,
        no_bridge: false,
        discovery_ms: 2000,
        max_event_bytes: 64 * 1024,
    });
    let store = Arc::new(SessionStore::open(&cfg.sessions_dir).expect("store"));
    let (bus, _) = broadcast::channel::<ServerMsg>(1024);
    let manager = Arc::new(CaptureManager::new(cfg, store.clone(), bus));
    let rt = tokio::runtime::Runtime::new().unwrap();

    // PID 4 = System: Frida не может прицепиться.
    let err = rt
        .block_on(async { manager.attach(4, "System".into(), None).await })
        .expect_err("attach к pid=4 обязан падать");
    let text = format!("{err:#}");
    eprintln!("attach(4) ошибка: {text}");
    assert!(!text.is_empty());
    let status = manager.status();
    assert!(!status.recording, "recording=true после провала attach к pid=4");
    assert_eq!(status.hooks, "off");
    assert!(!status.bridge);
    assert!(manager.active().is_none());
    // Сессия есть, но aborted; причина в facts.
    let sessions = store.list();
    assert_eq!(sessions.len(), 1, "ожидалась одна aborted-сессия");
    let saved = read_meta(&PathBuf::from(&sessions[0].dir)).expect("session.json");
    assert_eq!(saved.status, "aborted");
    assert!(
        saved.facts.iter().any(|f| f.contains("# attach-failed:")),
        "причина не в facts: {:?}",
        saved.facts
    );
    // Повторный attach не упирается в 409 (снова ошибка, но не «уже идёт»).
    let retry = rt.block_on(async { manager.attach(4, "System-2".into(), None).await });
    let retry_text = format!("{:?}", retry.err().expect("повторный attach тоже падает"));
    assert!(
        !retry_text.contains("уже идёт"),
        "повторный attach заблокирован: {retry_text}"
    );
    // detach после провала — без ошибок.
    assert!(rt.block_on(async { manager.detach().await }).is_ok());
}