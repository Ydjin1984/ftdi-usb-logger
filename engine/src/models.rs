//! Общие типы данных: сериализуются в REST/WS и в файлы сессии.
//!
//! Контракт зафиксирован в `docs/02-architecture.md` §3 и `docs/04-interfaces.md`.
//! Меняя поля, помни: UI (`ui/src/types.ts`) и sidecar (`sidecar/`) обязаны обновиться
//! синхронно.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ───────────────────────────── события потока ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Передача байт в устройство.
    Tx,
    /// Приём байт из устройства.
    Rx,
    /// Метка без шага.
    Mark,
    /// Шаг открыт.
    StepStart,
    /// Шаг закрыт (в meta.summary лежит сводка).
    StepEnd,
    /// Открытие/закрытие/запись файла приложением.
    File,
    /// Хеш файла.
    FileHash,
    /// Системная строка (баннер, версия, INI, состояние).
    Sys,
    /// Загрузка модуля.
    Module,
    /// Открытие COM-порта / VCP-событие.
    Vcp,
    /// Заметка оператора.
    Note,
    /// Скриншот.
    Shot,
    /// Сводка (например, разбор после шага).
    Summary,
    /// Ошибка.
    Error,
    /// Неизвестная строка, сохранена как есть.
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Ftd2xx,
    Vcp,
    File,
    App,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Tx,
    Rx,
}

/// Одно событие захвата.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Монотонный номер в сессии (0 — служебные до старта).
    pub seq: u64,
    /// Секунды от якоря t0 (совместимо с `+70.537s`).
    pub t: f64,
    /// Время по стенным часам, RFC3339 UTC.
    pub wall: String,
    pub kind: EventKind,
    pub transport: Transport,
    /// Имя API-функции или псевдоним: `FT_Write`, `WriteFile`, `MARK`, `FILE`, …
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub direction: Option<Direction>,
    /// Длина полезной нагрузки.
    #[serde(default)]
    pub len: u32,
    /// Полная нагрузка в виде «12 04 0d 1b».
    #[serde(default)]
    pub hex: String,
    /// Короткий предпросмотр/декод для ленты.
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub rc: Option<i32>,
    /// Номер шага, во время которого пришло событие.
    #[serde(default)]
    pub step: Option<u32>,
    /// Исходная строка лога — для экспорта и обратной совместимости.
    #[serde(default)]
    pub raw: String,
    /// Расширения: com, handle, n, ovl, checksum, truncated, …
    #[serde(default)]
    pub meta: Value,
}

impl Event {
    pub fn new(kind: EventKind, transport: Transport, t: f64, wall: impl Into<String>) -> Self {
        Self {
            seq: 0,
            t,
            wall: wall.into(),
            kind,
            transport,
            api: String::new(),
            direction: None,
            len: 0,
            hex: String::new(),
            text: None,
            rc: None,
            step: None,
            raw: String::new(),
            meta: Value::Null,
        }
    }

    pub fn with_hex(mut self, hex: impl Into<String>) -> Self {
        self.hex = hex.into();
        self
    }

    pub fn with_len(mut self, len: u32) -> Self {
        self.len = len;
        self
    }

    pub fn with_api(mut self, api: impl Into<String>) -> Self {
        self.api = api.into();
        self
    }

    pub fn with_meta(mut self, meta: Value) -> Self {
        self.meta = meta;
        self
    }

    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = raw.into();
        self
    }

    pub fn payload(&self) -> Vec<u8> {
        util::hex_to_bytes(&self.hex)
    }

    /// Строка в формате старого логера — для `raw.log` и экспорта.
    pub fn to_legacy_line(&self) -> String {
        if !self.raw.is_empty() {
            return self.raw.clone();
        }
        match self.kind {
            EventKind::Mark => format!(
                "# MARK wall={} rel=+{:.3}s {}",
                legacy_wall(&self.wall),
                self.t,
                self.text.clone().unwrap_or_default()
            ),
            // Шаг в raw.log пишется как в старом логере: `# MARK ... START/END N: имя`.
            // `rel=` добавляем, чтобы старый parse_family.py тоже видел метки
            // (его MARK_RE требует rel, а старый логер его не писал).
            EventKind::StepStart => {
                let idx = self
                    .meta
                    .get("idx")
                    .and_then(Value::as_u64)
                    .or_else(|| self.step.map(u64::from))
                    .unwrap_or(0);
                format!(
                    "# MARK wall={} rel=+{:.3}s START {}: {}",
                    legacy_wall(&self.wall),
                    self.t,
                    idx,
                    self.text.clone().unwrap_or_default()
                )
            }
            EventKind::StepEnd => {
                let idx = self
                    .meta
                    .get("idx")
                    .and_then(Value::as_u64)
                    .or_else(|| self.step.map(u64::from))
                    .unwrap_or(0);
                let dur = self.meta.get("dur").and_then(Value::as_f64).unwrap_or(0.0);
                format!(
                    "# MARK wall={} rel=+{:.3}s END {}: {} ({:.1} с)",
                    legacy_wall(&self.wall),
                    self.t,
                    idx,
                    self.text.clone().unwrap_or_default(),
                    dur
                )
            }
            _ => {
                let mut s = format!("[+{:.3}s] {} {}", self.t, self.api, self.text.clone().unwrap_or_default());
                if !self.hex.is_empty() {
                    s.push_str(" : ");
                    s.push_str(&self.hex);
                }
                s
            }
        }
    }
}

// ─────────────────────────────── сессия ──────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionCounts {
    #[serde(default)]
    pub events: u64,
    #[serde(default)]
    pub tx: u64,
    #[serde(default)]
    pub rx: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub steps: u64,
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub errors: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdapterInfo {
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub com_port: Option<u32>,
    #[serde(default)]
    pub vendor_id: Option<u16>,
    #[serde(default)]
    pub product_id: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub t: f64,
    pub wall: String,
    pub text: String,
    /// `user` | `system`
    #[serde(default = "note_author")]
    pub author: String,
}

fn note_author() -> String {
    "user".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub started_at: String,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub tool_path: Option<String>,
    #[serde(default)]
    pub tool_sha256: Option<String>,
    #[serde(default)]
    pub tool_version: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub process: Option<String>,
    /// `ftd2xx` | `vcp` | `mixed` | `import`
    #[serde(default = "transport_default")]
    pub transport: String,
    #[serde(default)]
    pub adapter: Option<AdapterInfo>,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub counts: SessionCounts,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: Vec<Note>,
    /// `recording` | `finished` | `imported` | `aborted`
    #[serde(default = "status_default")]
    pub status: String,
    #[serde(default)]
    pub engine_version: String,
    #[serde(default)]
    pub dir: String,
    /// Дополнительные факты: EDIABAS INI, лицензионный гейт, версия ftd2xx …
    #[serde(default)]
    pub facts: Vec<String>,
}

fn transport_default() -> String {
    "ftd2xx".into()
}
fn status_default() -> String {
    "recording".into()
}

impl SessionMeta {
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            started_at: now_rfc3339(),
            ended_at: None,
            label: label.into(),
            tool_path: None,
            tool_sha256: None,
            tool_version: None,
            pid: None,
            process: None,
            transport: transport_default(),
            adapter: None,
            host: host_name(),
            counts: SessionCounts::default(),
            tags: Vec::new(),
            notes: Vec::new(),
            status: status_default(),
            engine_version: env!("CARGO_PKG_VERSION").into(),
            dir: String::new(),
            facts: Vec::new(),
        }
    }
}

// ─────────────────────────────── шаг ─────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepRead {
    pub start: u64,
    pub len: u64,
    #[serde(default)]
    pub blocks: u64,
    #[serde(default)]
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileHash {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub mode: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WinkfpJob {
    #[serde(default)]
    pub sgbd: String,
    #[serde(default)]
    pub job: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub results: serde_json::Map<String, Value>,
    #[serde(default)]
    pub errors: Vec<String>,
    /// Сколько результатов не вошло в `results` (полный JSON в отчёте).
    #[serde(default)]
    pub results_total: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepVerdict {
    #[serde(default)]
    pub denied: u64,
    #[serde(default)]
    pub no_answer: u64,
    #[serde(default)]
    pub echo: bool,
    #[serde(default)]
    pub unparsed: u64,
}

/// Сводка шага — надмножество старого `PHASE-JSON`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSummary {
    pub idx: u32,
    #[serde(default)]
    pub title: String,
    pub dur: f64,
    #[serde(default)]
    pub exchanges: u64,
    #[serde(default)]
    pub tx_bytes: u64,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub cmd_hist: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub resp_hist: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    pub reads: Vec<StepRead>,
    #[serde(default)]
    pub filehash: Vec<FileHash>,
    #[serde(default)]
    pub png: Option<String>,
    #[serde(default)]
    pub winkfp_jobs: Vec<WinkfpJob>,
    #[serde(default)]
    pub verdict: StepVerdict,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub ended_at: String,
}

impl StepSummary {
    pub fn new(idx: u32, title: impl Into<String>) -> Self {
        Self {
            idx,
            title: title.into(),
            dur: 0.0,
            exchanges: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            cmd_hist: Default::default(),
            resp_hist: Default::default(),
            reads: Vec::new(),
            filehash: Vec::new(),
            png: None,
            winkfp_jobs: Vec::new(),
            verdict: Default::default(),
            started_at: String::new(),
            ended_at: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEvent {
    pub action: String, // start | end
    pub idx: u32,
    #[serde(default)]
    pub title: String,
    pub t: f64,
    pub wall: String,
}

// ──────────────────────────── разбор полезной нагрузки ───────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Telegram {
    pub t: f64,
    /// Направление первого кадра.
    pub dir: Option<Direction>,
    #[serde(default)]
    pub api: String,
    #[serde(default)]
    pub hex: String,
    /// Разобранная команда: `SVC(10,85)`, `READ(0x3FD60+46)`, `cmd=0x07`, `7F(10,33)`.
    #[serde(default)]
    pub cmd: Option<String>,
    /// Ответ: `A0 payload=46B`, `7F(10,33)`, `no-answer`.
    #[serde(default)]
    pub resp: Option<String>,
    #[serde(default)]
    pub echo: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayloadDecode {
    #[serde(default)]
    pub len: usize,
    #[serde(default)]
    pub hex: String,
    #[serde(default)]
    pub ascii: String,
    /// KWP-команда, если распознана.
    #[serde(default)]
    pub cmd: Option<String>,
    /// Тело после эха.
    #[serde(default)]
    pub payload_hex: String,
    #[serde(default)]
    pub echo: Option<u8>,
    #[serde(default)]
    pub notes: Vec<String>,
}

// ───────────────────────────── discovery ────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FtdiDevice {
    pub index: u32,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub flags: u32,
    #[serde(default)]
    pub dev_type: u32,
    #[serde(default)]
    pub vendor_id: Option<u16>,
    #[serde(default)]
    pub product_id: Option<u16>,
    #[serde(default)]
    pub com_port: Option<u32>,
    /// `d2xx` | `registry`
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExeMeta {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub mtime: String,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub company: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolProcess {
    pub pid: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub has_ftd2xx: bool,
    #[serde(default)]
    pub known_tool: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub window_title: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessDetail {
    #[serde(flatten)]
    pub proc: ToolProcess,
    #[serde(default)]
    pub exe_meta: ExeMeta,
    #[serde(default)]
    pub modules: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureStatus {
    #[serde(default)]
    pub recording: bool,
    #[serde(default)]
    pub session: Option<String>,
    /// `on` | `paused` | `off` | `unavailable`
    #[serde(default)]
    pub hooks: String,
    #[serde(default)]
    pub bridge: bool,
    #[serde(default)]
    pub target: Option<ToolProcess>,
    #[serde(default)]
    pub counts: SessionCounts,
    #[serde(default)]
    pub step: Option<StepEvent>,
    #[serde(default)]
    pub started_at: Option<String>,
}

// ───────────────────────────── сообщения моста ──────────────────────────

/// Что sidecar присылает движку (stdout, JSON lines).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BridgeMsg {
    Hello {
        #[serde(default)]
        bridge: String,
        #[serde(default)]
        frida: String,
        #[serde(default)]
        python: String,
    },
    Ready {
        pid: u32,
        #[serde(default)]
        arch: String,
        #[serde(default)]
        modules: u32,
        #[serde(default)]
        script: String,
    },
    Event {
        line: String,
        #[serde(default)]
        wall: String,
    },
    Rpc {
        name: String,
        #[serde(default)]
        result: String,
    },
    Log {
        #[serde(default)]
        level: String,
        msg: String,
    },
    Error {
        msg: String,
        #[serde(default)]
        fatal: bool,
    },
    Bye {
        #[serde(default)]
        code: i32,
        #[serde(default)]
        events: u64,
    },
}

// ───────────────────────── сообщения UI (WS) ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Hello {
        server_version: String,
        active_session: Option<String>,
    },
    Batch {
        session: String,
        events: Vec<Event>,
        counts: SessionCounts,
    },
    Status {
        session: Option<String>,
        target: Option<ToolProcess>,
        hooks: String,
        recording: bool,
        counts: SessionCounts,
    },
    Step {
        action: String,
        step: serde_json::Value,
    },
    Toast {
        level: String,
        text: String,
    },
    // --- управляющие сообщения клиента (тоже через ServerMsg-канал не идут; см. api::ClientMsg)
}

/// Что UI присылает по WS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientMsg {
    Subscribe {
        session: Option<String>,
        #[serde(default)]
        since: u64,
    },
    Ping,
}

// ───────────────────────────── утилиты ──────────────────────────────────

/// RFC3339 UTC → локальное время в формате старого логера `%Y-%m-%d %H:%M:%S`.
pub fn legacy_wall(wall: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(wall)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| wall.to_string())
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "host".into())
}

pub mod util {
    /// «12 04 0d 1b» → байты. Терпит лишние пробелы и `0x`-префиксы.
    pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let mut cur = String::with_capacity(2);
        for ch in hex.chars() {
            if ch.is_ascii_hexdigit() {
                cur.push(ch);
                if cur.len() == 2 {
                    if let Ok(b) = u8::from_str_radix(&cur, 16) {
                        out.push(b);
                    }
                    cur.clear();
                }
            } else if ch == 'x' || ch == 'X' {
                cur.clear();
            }
        }
        out
    }

    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 3);
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn ascii_preview(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
            .collect()
    }

    pub fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    pub fn slug(text: &str) -> String {
        let mut out = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() {
                out.push(ch.to_ascii_lowercase());
            } else if (ch.is_whitespace() || ch == '-' || ch == '_') && !out.ends_with('-') {
                out.push('-');
            }
        }
        out.trim_matches('-').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::util::*;

    #[test]
    fn hex_roundtrip() {
        let b = hex_to_bytes("12 04 0d 1b");
        assert_eq!(b, vec![0x12, 0x04, 0x0d, 0x1b]);
        assert_eq!(bytes_to_hex(&b), "12 04 0d 1b");
        assert_eq!(ascii_preview(b"OK\x00"), "OK.");
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}



