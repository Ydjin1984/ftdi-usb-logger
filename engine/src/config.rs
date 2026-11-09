//! Конфигурация и CLI.

use anyhow::Context;
use clap::Parser;
use std::path::{Path, PathBuf};

/// FTDI/USB Logger: захват, разметка и разбор обмена FTDI-инструментов.
#[derive(Debug, Clone, Parser)]
#[command(name = "ftdi-logger", version, about)]
pub struct Cli {
    /// Корень репозитория/установки (где лежат ui/, sidecar/, sessions/).
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Порт локального HTTP/WS.
    #[arg(long, default_value_t = 7811)]
    pub port: u16,
    /// Не открывать окно интерфейса при старте.
    #[arg(long)]
    pub no_open: bool,
    /// python.exe с установленным frida.
    #[arg(long)]
    pub python: Option<PathBuf>,
    /// Путь к sidecar/bridge.py.
    #[arg(long)]
    pub sidecar: Option<PathBuf>,
    /// Путь к JS-агенту Frida.
    #[arg(long)]
    pub script: Option<PathBuf>,
    /// Уровень логирования (error|warn|info|debug|trace).
    #[arg(long, default_value = "info")]
    pub log_level: String,
    /// Только отдать UI и работать с сессиями, не поднимая мост.
    #[arg(long)]
    pub no_bridge: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub sessions_dir: PathBuf,
    pub ui_dist: PathBuf,
    pub port: u16,
    pub python: PathBuf,
    pub sidecar: PathBuf,
    pub script: PathBuf,
    pub open_ui: bool,
    pub no_bridge: bool,
    pub discovery_ms: u64,
    pub max_event_bytes: usize,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let root = match &cli.root {
            Some(p) => p.clone(),
            None => detect_root(),
        };
        let root = root.canonicalize().unwrap_or(root);
        let python = cli
            .python
            .clone()
            .or_else(default_python)
            .unwrap_or_else(|| PathBuf::from("python.exe"));
        let sidecar = cli.sidecar.clone().unwrap_or_else(|| root.join("sidecar/bridge.py"));
        let script = cli
            .script
            .clone()
            .unwrap_or_else(|| {
            let universal = root.join("sidecar/agents/universal_capture.js");
            if universal.is_file() {
                universal
            } else {
                root.join("sidecar/agents/ftdi_capture.js")
            }
        });
        Ok(Self {
            sessions_dir: root.join("sessions"),
            ui_dist: root.join("ui/dist"),
            port: cli.port,
            python,
            sidecar,
            script,
            open_ui: !cli.no_open,
            no_bridge: cli.no_bridge,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
            root,
        })
    }

    pub fn ensure_dirs(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.sessions_dir)
            .with_context(|| format!("не создать {}", self.sessions_dir.display()))?;
        Ok(())
    }
}

/// Ищем корень: вверх от cwd/exe, пока не увидим `sidecar` или `ui`, иначе cwd.
fn detect_root() -> PathBuf {
    if let Ok(explicit) = std::env::var("FTDI_LOGGER_ROOT") {
        let p = PathBuf::from(explicit);
        if p.is_dir() {
            return p;
        }
    }
    let starts: Vec<PathBuf> = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .into_iter()
        .chain(std::env::current_dir().ok())
        .collect();
    for start in starts {
        let mut cur = Some(start.as_path());
        while let Some(dir) = cur {
            if dir.join("sidecar").is_dir() || dir.join("ui").is_dir() {
                return dir.to_path_buf();
            }
            cur = dir.parent();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn default_python() -> Option<PathBuf> {
    let candidates = [
        r"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python313\python.exe",
        r"C:\Users\User\AppData\Local\Programs\Python\Python311\python.exe",
    ];
    for c in candidates {
        if Path::new(c).is_file() {
            return Some(PathBuf::from(c));
        }
    }
    for name in ["python.exe", "python3.exe", "py.exe"] {
        if let Some(p) = which(name) {
            return Some(p);
        }
    }
    None
}

fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

