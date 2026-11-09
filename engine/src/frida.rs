//! Мост к Python-сайдкару (Frida). Владелец: boba.
//!
//! Запускаем `python -u sidecar/bridge.py` с piped stdin/stdout и `CREATE_NO_WINDOW`,
//! читаем stdout построчно (JSON Lines → `models::BridgeMsg`) и рассылаем в `broadcast`,
//! команды пишем JSON-строкой в stdin. Смерть процесса/EOF превращается в
//! `BridgeMsg::Error { fatal: true }`, который дирижёр превращает в `ServerMsg::Toast`.
//!
//! Правила: без паник, `stop()` не висит дольше 3 с (потом kill), все хэндлы закрываются.

use crate::config::Config;
use crate::models::BridgeMsg;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::broadcast;

/// `CREATE_NO_WINDOW`: не мигать консолью Python у оператора.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Сколько ждём грациозного завершения sidecar по `{"cmd":"stop"}`.
const STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Общее состояние моста: поля читаются из фоновых задач (Arc + атомики/мьютексы).
struct BridgeInner {
    cfg: Arc<Config>,
    /// Мост запущен и должен работать (сбрасывается при смерти процесса/stop).
    running: AtomicBool,
    /// Идёт штатная остановка: EOF/выход процесса не считается аварийным.
    stopping: AtomicBool,
    /// PID целевого процесса, к которому прицепился Frida.
    pid: parking_lot::Mutex<Option<u32>>,
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    child: tokio::sync::Mutex<Option<Child>>,
}

pub struct BridgeManager {
    inner: Arc<BridgeInner>,
}

impl BridgeManager {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self {
            inner: Arc::new(BridgeInner {
                cfg,
                running: AtomicBool::new(false),
                stopping: AtomicBool::new(false),
                pid: parking_lot::Mutex::new(None),
                stdin: tokio::sync::Mutex::new(None),
                child: tokio::sync::Mutex::new(None),
            }),
        }
    }

    pub fn cfg(&self) -> &Arc<Config> {
        &self.inner.cfg
    }

    /// Запустить sidecar и отправить ему `attach`. `tx` — канал, куда пойдут `BridgeMsg`.
    pub async fn start(
        &self,
        pid: u32,
        label: &str,
        tx: broadcast::Sender<BridgeMsg>,
    ) -> anyhow::Result<()> {
        use anyhow::{bail, Context};

        if self.is_running() {
            bail!("мост уже запущен (pid {:?})", self.pid());
        }
        let cfg = self.inner.cfg.clone();
        if cfg.no_bridge {
            bail!("Frida-мост отключён ключом --no-bridge");
        }
        if !cfg.sidecar.is_file() {
            bail!(
                "не найден sidecar: {} — захват невозможен (запустите сборку sidecar)",
                cfg.sidecar.display()
            );
        }
        if !cfg.script.is_file() {
            bail!(
                "не найден Frida-агент: {} — захват невозможен",
                cfg.script.display()
            );
        }

        // ── запуск процесса ────────────────────────────────────────────────
        let mut command = tokio::process::Command::new(&cfg.python);
        command
            .arg("-u")
            .arg(&cfg.sidecar)
            .current_dir(&cfg.root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PYTHONIOENCODING", "utf-8")
            .env("PYTHONUNBUFFERED", "1");
        #[cfg(windows)]
        {
            // Применяем флаг создания процесса, чтобы окно консоли не появлялось.
            use std::os::windows::process::CommandExt as _;
            // tokio::process::Command::as_std_mut даёт std::process::Command, куда и
            // применяется creation_flags.
            command.as_std_mut().creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command.spawn().with_context(|| {
            format!(
                "не запустить sidecar: {} {}",
                cfg.python.display(),
                cfg.sidecar.display()
            )
        })?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        *self.inner.stdin.lock().await = stdin;
        *self.inner.child.lock().await = Some(child);
        *self.inner.pid.lock() = Some(pid);
        self.inner.stopping.store(false, Ordering::SeqCst);
        self.inner.running.store(true, Ordering::SeqCst);

        // ── фоновые задачи чтения ─────────────────────────────────────────
        if let Some(stdout) = stdout {
            tokio::spawn(read_stdout(self.inner.clone(), stdout, tx.clone()));
        } else {
            tracing::warn!("у sidecar нет stdout — поток сообщений моста невозможен");
        }
        if let Some(stderr) = stderr {
            tokio::spawn(read_stderr(self.inner.clone(), stderr, tx.clone()));
        }
        tokio::spawn(watch_child(self.inner.clone(), tx.clone()));

        // ── attach ────────────────────────────────────────────────────────
        let attach = serde_json::json!({
            "cmd": "attach",
            "pid": pid,
            "script": cfg.script.to_string_lossy(),
            "label": label,
        });
        if let Err(err) = self.command(attach).await {
            let _ = self.stop().await;
            return Err(err).context("отправить attach в sidecar");
        }
        tracing::info!("Frida-мост запущен: pid={pid}, label={label:?}");
        Ok(())
    }

    /// Записать одну JSON-строку в stdin sidecar.
    pub async fn command(&self, cmd: serde_json::Value) -> anyhow::Result<()> {
        use anyhow::{bail, Context};

        let mut guard = self.inner.stdin.lock().await;
        let Some(stdin) = guard.as_mut() else {
            bail!("мост не запущен: stdin sidecar закрыт");
        };
        let mut line = serde_json::to_vec(&cmd).context("сериализовать команду моста")?;
        line.push(b'\n');
        stdin
            .write_all(&line)
            .await
            .context("записать команду в stdin моста")?;
        stdin.flush().await.context("flush stdin моста")?;
        Ok(())
    }

    /// Остановить мост: `{"cmd":"stop"}`, ожидание ≤ 3 с, затем kill.
    pub async fn stop(&self) -> anyhow::Result<()> {
        if !self.inner.running.load(Ordering::SeqCst)
            && self.inner.child.lock().await.is_none()
        {
            *self.inner.stdin.lock().await = None;
            *self.inner.pid.lock() = None;
            return Ok(());
        }
        self.inner.stopping.store(true, Ordering::SeqCst);
        // Мягкая остановка: sidecar сам делает detach и выходит.
        let _ = self.command(serde_json::json!({"cmd": "stop"})).await;

        let mut slot = self.inner.child.lock().await;
        if let Some(mut child) = slot.take() {
            match tokio::time::timeout(STOP_TIMEOUT, child.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    tracing::warn!("sidecar не завершился за 3 с — завершаем принудительно");
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            }
        }
        drop(slot);

        *self.inner.stdin.lock().await = None;
        *self.inner.pid.lock() = None;
        self.inner.running.store(false, Ordering::SeqCst);
        self.inner.stopping.store(false, Ordering::SeqCst);
        tracing::info!("Frida-мост остановлен");
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    pub fn pid(&self) -> Option<u32> {
        *self.inner.pid.lock()
    }
}

// ─────────────────────────────── фоновые задачи ──────────────────────────

/// Построчное чтение stdout: JSON-строка → `BridgeMsg` в broadcast.
async fn read_stdout(
    inner: Arc<BridgeInner>,
    stdout: ChildStdout,
    tx: broadcast::Sender<BridgeMsg>,
) {
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<BridgeMsg>(line) {
                    Ok(msg) => {
                        // Нет подписчиков — не ошибка: сообщение просто некому отдать.
                        let _ = tx.send(msg);
                    }
                    Err(err) => {
                        let _ = tx.send(BridgeMsg::Log {
                            level: "warn".into(),
                            msg: format!(
                                "не-JSON строка sidecar ({err}): {}",
                                truncate(line, 300)
                            ),
                        });
                    }
                }
            }
            Ok(None) => break,
            Err(err) => {
                let _ = tx.send(BridgeMsg::Log {
                    level: "error".into(),
                    msg: format!("чтение stdout sidecar: {err}"),
                });
                break;
            }
        }
    }

    // stdout закрыт — процесс либо умер, либо штатно завершился.
    let was_running = inner.running.swap(false, Ordering::SeqCst);
    if was_running && !inner.stopping.load(Ordering::SeqCst) {
        let _ = tx.send(BridgeMsg::Error {
            msg: "мост неожиданно завершился (stdout sidecar закрыт)".into(),
            fatal: true,
        });
    }
}

/// Построчное чтение stderr: диагностика Python/Frida уходит в лог и в UI.
async fn read_stderr(
    inner: Arc<BridgeInner>,
    stderr: ChildStderr,
    tx: broadcast::Sender<BridgeMsg>,
) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        tracing::warn!(target: "bridge", "{line}");
        if inner.stopping.load(Ordering::SeqCst) {
            continue;
        }
        let _ = tx.send(BridgeMsg::Log {
            level: "warn".into(),
            msg: truncate(line, 2000),
        });
    }
}

/// Сторож процесса: если sidecar умер сам — сбрасываем статус и шлём фатальную ошибку.
async fn watch_child(inner: Arc<BridgeInner>, tx: broadcast::Sender<BridgeMsg>) {
    loop {
        tokio::time::sleep(Duration::from_millis(400)).await;
        if !inner.running.load(Ordering::SeqCst) {
            break;
        }
        let mut slot = inner.child.lock().await;
        let Some(child) = slot.as_mut() else {
            break;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into());
                drop(slot);
                inner.running.store(false, Ordering::SeqCst);
                *inner.stdin.lock().await = None;
                if !inner.stopping.load(Ordering::SeqCst) {
                    let _ = tx.send(BridgeMsg::Error {
                        msg: format!("sidecar завершился (код {code})"),
                        fatal: true,
                    });
                }
                break;
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!("не опросить состояние sidecar: {err}");
                break;
            }
        }
    }
}

/// Обрезать длинную строку для UI/лога, не разрывая UTF-8 внутри символа.
fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_keeps_utf8_boundaries() {
        assert_eq!(truncate("абв", 5), "абв");
        assert_eq!(truncate("абвгде", 3), "абв…");
    }

    #[test]
    fn stop_without_start_is_ok() {
        let cfg = Arc::new(Config {
            root: std::env::temp_dir(),
            sessions_dir: std::env::temp_dir(),
            ui_dist: std::env::temp_dir(),
            port: 0,
            python: std::path::PathBuf::from("python.exe"),
            sidecar: std::env::temp_dir().join("no_bridge.py"),
            script: std::env::temp_dir().join("no_agent.js"),
            open_ui: false,
            no_bridge: false,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
        });
        let bridge = BridgeManager::new(cfg);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert!(!bridge.is_running());
            assert!(bridge.stop().await.is_ok());
            assert_eq!(bridge.pid(), None);
        });
    }

    /// Мост с настоящим Python и заглушкой sidecar: hello/ready/event → broadcast, stop ≤3 с.
    ///
    /// Если Python в системе нет — тест пропускается (не падает в окружениях без Python).
    #[test]
    fn bridge_with_fake_sidecar_streams_json_and_stops() {
        let python_ok = std::process::Command::new("python")
            .args(["-c", "print(1)"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !python_ok {
            eprintln!("python недоступен — тест моста пропущен");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sidecar = root.join("bridge.py");
        let script = root.join("agent.js");
        std::fs::write(
            &sidecar,
            r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "test", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 3, "script": "agent.js"}), flush=True)
        print(json.dumps({"type": "event", "line": "[+0.100s] TX ftd2xx FT_Write rc=0 len=2 n=2 : aa bb", "wall": "2026-01-01T00:00:00.000Z"}), flush=True)
    elif cmd == "hookctl":
        print(json.dumps({"type": "rpc", "name": "hookctl", "result": msg.get("value")}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 1}), flush=True)
        sys.exit(0)
"#,
        )
        .unwrap();
        std::fs::write(&script, "// заглушка Frida-агента для теста\n").unwrap();

        let cfg = Arc::new(Config {
            root: root.to_path_buf(),
            sessions_dir: root.join("sessions"),
            ui_dist: root.join("ui"),
            port: 0,
            python: std::path::PathBuf::from("python"),
            sidecar: sidecar.clone(),
            script: script.clone(),
            open_ui: false,
            no_bridge: false,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
        });
        let bridge = BridgeManager::new(cfg);
        let (tx, mut rx) = broadcast::channel::<BridgeMsg>(64);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            bridge.start(4242, "test", tx).await.expect("мост стартует");
            assert!(bridge.is_running());
            assert_eq!(bridge.pid(), Some(4242));

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut ready = false;
            let mut event_line = None;
            while tokio::time::Instant::now() < deadline && !(ready && event_line.is_some()) {
                match tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
                    Ok(Ok(BridgeMsg::Ready { pid, .. })) => {
                        assert_eq!(pid, 4242);
                        ready = true;
                    }
                    Ok(Ok(BridgeMsg::Event { line, .. })) => event_line = Some(line),
                    Ok(Ok(_)) => {}
                    _ => {}
                }
            }
            assert!(ready, "sidecar не прислал ready");
            let line = event_line.expect("sidecar не прислал event");
            assert!(line.contains("FT_Write"), "неожиданная строка: {line}");

            // hookctl доходит до sidecar и возвращается rpc.
            bridge
                .command(serde_json::json!({"cmd": "hookctl", "value": "pause"}))
                .await
                .expect("команда hookctl");
            let mut got_rpc = false;
            let rpc_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            while tokio::time::Instant::now() < rpc_deadline && !got_rpc {
                if let Ok(Ok(BridgeMsg::Rpc { name, result })) =
                    tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
                {
                    assert_eq!(name, "hookctl");
                    assert!(result.contains("pause"), "результат rpc: {result}");
                    got_rpc = true;
                }
            }
            assert!(got_rpc, "sidecar не ответил rpc");

            let started = std::time::Instant::now();
            bridge.stop().await.expect("мост останавливается");
            assert!(!bridge.is_running());
            assert_eq!(bridge.pid(), None);
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "stop() должен укладываться в 3 с + запас"
            );
        });
    }
}
