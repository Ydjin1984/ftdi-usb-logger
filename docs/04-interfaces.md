# Интерфейсы модулей движка (Rust)

Этот документ — обязательный контракт. Если меняешь сигнатуру — обнови документ и сообщи Lead.
Порядок в `lib.rs` фиксирован.

## `models.rs` (Lead, общий)

Типы данных, сериализуются в API/WS. См. `engine/src/models.rs`.

## `config.rs` (boba)

```rust
#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,          // корень репозитория/установки
    pub sessions_dir: PathBuf,  // <root>/sessions
    pub ui_dist: PathBuf,       // <root>/ui/dist
    pub port: u16,              // 7811
    pub python: PathBuf,        // python.exe с frida
    pub sidecar: PathBuf,       // <root>/sidecar/bridge.py
    pub script: PathBuf,        // <root>/sidecar/agents/ftdi_capture.js
    pub open_ui: bool,
    pub discovery_ms: u64,
    pub max_event_bytes: usize,
}
#[derive(Debug, Clone, clap::Parser)]
pub struct Cli { /* --root --port --no-open --python --sidecar --script --log-level */ }
impl Config {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self>;
    pub fn ensure_dirs(&self) -> anyhow::Result<()>;
}
```

## `discovery.rs` (boba)

```rust
pub fn list_ftdi_devices() -> Vec<models::FtdiDevice>;      // D2XX через libftd2xx (libloading), затем реестр
pub fn registry_devices() -> Vec<models::FtdiDevice>;       // HKLM\SYSTEM\CurrentControlSet\Enum\FTDIBUS / USB
```

## `procscan.rs` (boba)

```rust
pub fn list_candidates(known: &[&str]) -> Vec<models::ToolProcess>;
pub fn process_detail(pid: u32) -> Option<models::ProcessDetail>;
pub fn exe_meta(path: &str) -> models::ExeMeta;             // size, mtime, sha256, version
```

## `screenshot.rs` (boba)

```rust
pub fn capture_window_for_pid(pid: u32, out: &std::path::Path) -> anyhow::Result<()>;
```

## `frida.rs` (boba)

```rust
pub struct BridgeManager { /* … */ }
impl BridgeManager {
    pub fn new(cfg: std::sync::Arc<Config>) -> Self;
    pub async fn start(&self, pid: u32, label: &str, tx: tokio::sync::broadcast::Sender<models::BridgeMsg>) -> anyhow::Result<()>;
    pub async fn command(&self, cmd: serde_json::Value) -> anyhow::Result<()>;
    pub async fn stop(&self) -> anyhow::Result<()>;
    pub fn is_running(&self) -> bool;
    pub fn pid(&self) -> Option<u32>;
}
```

## `capture.rs` (boba) — дирижёр сессии

```rust
pub struct CaptureManager { /* … */ }
impl CaptureManager {
    pub fn new(cfg: Arc<Config>, store: Arc<store::SessionStore>, bus: broadcast::Sender<models::ServerMsg>) -> Self;
    pub async fn attach(&self, pid: u32, label: String, adapter: Option<String>) -> anyhow::Result<models::SessionMeta>;
    pub async fn detach(&self) -> anyhow::Result<Option<models::SessionMeta>>;
    pub async fn hookctl(&self, value: &str) -> anyhow::Result<()>;
    pub async fn start_step(&self, title: String) -> anyhow::Result<models::StepEvent>;
    pub async fn end_step(&self) -> anyhow::Result<models::StepSummary>;
    pub async fn mark(&self, title: String) -> anyhow::Result<models::Event>;
    pub async fn note(&self, text: String) -> anyhow::Result<()>;
    pub async fn shot(&self) -> anyhow::Result<String>;   // относительный путь
    pub fn status(&self) -> models::CaptureStatus;
    pub fn active(&self) -> Option<models::SessionMeta>;
}
```

## `store.rs` (ded-bekend)

```rust
pub struct SessionStore { /* … */ }
impl SessionStore {
    pub fn open(root: &Path) -> anyhow::Result<Self>;
    pub fn list(&self) -> Vec<models::SessionMeta>;
    pub fn get(&self, id: &str) -> Option<models::SessionMeta>;
    pub fn create(&self, meta: models::SessionMeta) -> anyhow::Result<SessionWriter>;
    pub fn writer(&self, id: &str) -> anyhow::Result<SessionWriter>;   // append в существующую
    pub fn reader(&self, id: &str) -> anyhow::Result<SessionReader>;
    pub fn delete(&self, id: &str) -> anyhow::Result<()>;
    pub fn update_meta(&self, meta: &models::SessionMeta) -> anyhow::Result<()>;
}
pub struct SessionWriter { /* … */ }
impl SessionWriter {
    pub fn append(&mut self, ev: &mut models::Event) -> std::io::Result<()>;      // присваивает seq
    pub fn append_many(&mut self, evs: &mut [models::Event]) -> std::io::Result<()>;
    pub fn write_raw_line(&mut self, line: &str) -> std::io::Result<()>;
    pub fn save_step(&self, s: &models::StepSummary) -> std::io::Result<()>;
    pub fn finish(&mut self, meta: &models::SessionMeta) -> anyhow::Result<()>;
}
pub struct SessionReader { /* … */ }
impl SessionReader {
    pub fn meta(&self) -> &models::SessionMeta;
    pub fn events(&self, from: Option<u64>, to: Option<u64>, limit: usize) -> Vec<models::Event>;
    pub fn all_events(&self) -> Vec<models::Event>;
    pub fn steps(&self) -> Vec<models::StepSummary>;
    pub fn count_events(&self) -> u64;
    pub fn repair(&mut self) -> anyhow::Result<()>;   // закрыть незакрытые шаги
}
```

## `decode.rs` (ded-bekend)

```rust
pub fn parse_capture_line(line: &str) -> Option<models::Event>;
pub fn split_telegrams(events: &[models::Event]) -> Vec<models::Telegram>;
pub fn summarize_step(events: &[models::Event], idx: u32, title: &str, dur: f64, png: Option<String>) -> models::StepSummary;
pub fn decode_payload(hex: &str) -> models::PayloadDecode;   // KWP-разбор для инспектора
```

## `report.rs` (ded-bekend)

```rust
pub fn render_text(meta: &models::SessionMeta, steps: &[models::StepSummary]) -> String;
pub fn render_markdown(meta: &models::SessionMeta, steps: &[models::StepSummary]) -> String;
pub fn write_session_reports(dir: &Path, meta: &models::SessionMeta, steps: &[models::StepSummary]) -> anyhow::Result<()>;
pub fn export_zip(session_dir: &Path, out_zip: &Path) -> anyhow::Result<()>;
pub fn export_csv(events: &[models::Event], out: &Path) -> anyhow::Result<()>;
pub fn export_jsonl(dir: &Path, out: &Path) -> anyhow::Result<()>;
```

## `import.rs` (ded-bekend)

```rust
pub fn import_legacy_log(store: &SessionStore, path: &Path, label: Option<String>) -> anyhow::Result<models::SessionMeta>;
```

## `ediabas.rs` (ded-bekend)

```rust
pub const EDIABAS_INI: &str = r"C:\EDIABAS\BIN\EDIABAS.INI";
pub fn ini_facts() -> Vec<(String, String)>;
pub fn snapshot_trace(path: &Path) -> std::io::Result<u64>;
pub fn read_from(path: &Path, offset: u64) -> std::io::Result<(Vec<u8>, u64)>;
pub fn parse_api_trace(text: &str) -> Vec<models::WinkfpJob>;
pub fn parse_ifh_trace(text: &str) -> Vec<String>;
```

## `api.rs` (ded-bekend)

```rust
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<SessionStore>,
    pub capture: Arc<CaptureManager>,
    pub bus: tokio::sync::broadcast::Sender<models::ServerMsg>,
    pub started: std::time::Instant,
}
pub fn router(state: AppState) -> axum::Router;   // REST + /ws + статика ui/dist
```
