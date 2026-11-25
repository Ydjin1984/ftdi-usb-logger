//! Осциллограф «Хелтег да Винчи»: HTTP-клиент, разбор кадров, запись сессии.
//!
//! Почему без сетевых крейтов: служба локальная и отвечает на один GET одним
//! JSON, поэтому достаточно `TcpStream` и ручного разбора ответа. Так в проекте
//! нет ни TLS, ни редиректов, ни пула соединений — нечему «зависнуть» в фоне,
//! а формат ответа (Content-Length / chunked) разбирается явно и тестируемо.
//!
//! Кадр `/api/capture/v2` — min/max-огибающая в милливольтах: little-endian i16,
//! пара (lo, hi) на столбец, столбцы подряд по каналам, всё в base64. Записываем
//! `columns_b64` как есть: распаковка «на лету» стоила бы памяти, а потребителю
//! (графику) нужны те же столбцы. Целостность проверяет `frame_sanity`.
//!
//! Числа в ответах могут быть `null` (канал выключен, частота не измерена) —
//! поэтому все измерения в структурах `Option`, а не «0.0 вместо неизвестного».

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Адрес службы «по умолчанию»: столько показывает штатный установщик.
pub const DEFAULT_URL: &str = "http://127.0.0.1:7411";

/// Таймаут одного запроса. Служба локальная, кадр ~100–500 КБ, поэтому две
/// секунды — это уже «она не ответила», а не «медленно считает».
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
/// Читаем ответ кусками по 64 КБ: тело кадра не влезает в один `read`.
const READ_BUF: usize = 64 * 1024;
/// Потолок тела ответа. Без него битый сервер может «лить» бесконечно, а
/// дедлайн по времени память не ограничивает.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Запас сверх `max_mb`, в котором ещё пишем деградированные строки (только
/// статистика, без base64). Дальше — `Capped`, чтобы диск не забился совсем.
const CAP_EXTRA_BYTES: u64 = 8 * 1024 * 1024;
/// Пауза между повторами, когда служба не отвечает (по контракту 1 с).
const POLL_RETRY_MS: u64 = 1000;
/// Сколько ждём «стоп» при паузе опросчика: чтобы поток не висел секунду после
/// нажатия «Стоп».
const STOP_SLICE: Duration = Duration::from_millis(50);
/// Стартовая ширина кадра до первого ответа: заведомо покрывает и 999 отсчётов
/// (3 канала), и 499 (8 каналов), поэтому первый же кадр пишется точными
/// отсчётами, а не огибающей.
const AUTO_WIDTH: usize = 1200;
/// Сколько интервалов публикаций держим для медианы/p95. 50 000 — это больше
/// двух часов при 6.5 кадрах/с; дальше храним только максимум.
const INTERVALS_CAP: usize = 50_000;

const META_FORMAT: &str = "scope-session/1";
const FRAME_FORMAT: &str = "scope-frame/1";
const SUMMARY_FORMAT: &str = "scope-summary/1";
const CONTRACT: &str = "davinci /api/capture/v2 (dav2)";

// ─────────────────────────────── настройки ───────────────────────────────

/// Настройки интеграции. Живут в `prefs.json` рядом с языком интерфейса.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScopeConfig {
    pub enabled: bool,
    pub url: String,
    pub interval_ms: u64,
    pub width: usize,
    pub max_mb: u64,
    /// Профиль ролей каналов стенда. `bench-gpt` — CH1 GPT1, CH2 GPT2,
    /// CH3 питание (docs/16 §3); пустая строка — ролей нет, сводка сигналов
    /// строится только по номерам каналов.
    pub profile: String,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            // Осциллограф — внешняя служба: по умолчанию не лезем к ней без
            // явного согласия пользователя.
            enabled: false,
            url: DEFAULT_URL.to_string(),
            interval_ms: 50,
            width: 500,
            max_mb: 512,
            profile: "bench-gpt".to_string(),
        }
    }
}

impl ScopeConfig {
    /// Привести настройки к рабочему диапазону.
    ///
    /// Границы не косметика: `interval_ms=1` превратил бы опрос в busy-loop и
    /// загрузил службу, `width=8000` — в кадр на мегабайты, а `max_mb=0` уже
    /// означает «без предела», поэтому верхняя граница применяется только к
    /// ненулевому значению.
    pub fn sanitized(mut self) -> Self {
        let mut url = self.url.trim().to_string();
        if url.is_empty() {
            url = DEFAULT_URL.to_string();
        }
        // Хвостовой '/' склеивается с путём ручки в двойной слэш, а служба
        // такие адреса не понимает. Но «http://» без хоста портить нельзя,
        // поэтому срезаем только лишние разделители после authority.
        while url.ends_with('/') && url.matches('/').count() > 2 {
            url.pop();
        }
        self.url = url;
        self.interval_ms = self.interval_ms.clamp(20, 1000);
        self.width = self.width.clamp(200, 2000);
        self.max_mb = self.max_mb.min(65_536);
        self.profile = match self.profile.trim().to_ascii_lowercase().as_str() {
            "bench-gpt" => "bench-gpt".to_string(),
            _ => String::new(),
        };
        self
    }
}

/// Роли каналов профиля стенда: (канал, роль, имя).
///
/// `bench-gpt` — стенд «Хелтег да Винчи»: CH1 GPT1, CH2 GPT2, CH3 питание.
/// Список короткий и явный: анализ сигналов не угадывает роли по форме сигнала.
pub fn profile_roles(profile: &str) -> &'static [(usize, &'static str, &'static str)] {
    match profile {
        "bench-gpt" => &[
            (1, "gpt1", "GPT1"),
            (2, "gpt2", "GPT2"),
            (3, "power", "Питание"),
        ],
        _ => &[],
    }
}

/// Проставить роли каналов по профилю; прежние роли очищаются.
pub fn apply_profile(channels: &mut [ChannelInfo], profile: &str) {
    for ch in channels.iter_mut() {
        ch.role.clear();
        ch.name.clear();
    }
    for (n, role, name) in profile_roles(profile) {
        if let Some(ch) = channels.iter_mut().find(|c| c.ch == *n) {
            ch.role = (*role).to_string();
            ch.name = (*name).to_string();
        }
    }
}

/// Прочитать настройки из `<root>/prefs.json` (ключ `scope`).
///
/// Битый или отсутствующий файл — это `Default`, а не ошибка: интерфейс должен
/// подниматься и без настроек. Значения прогоняются через `sanitized`, чтобы
/// руками испорченный `prefs.json` не превратился в busy-loop.
pub fn load_config(root: &Path) -> ScopeConfig {
    let path = root.join("prefs.json");
    let Ok(raw) = fs::read_to_string(&path) else {
        return ScopeConfig::default();
    };
    let Ok(root_value) = serde_json::from_str::<Value>(&raw) else {
        return ScopeConfig::default();
    };
    match root_value.get("scope").cloned() {
        Some(value) => serde_json::from_value::<ScopeConfig>(value)
            .map(ScopeConfig::sanitized)
            .unwrap_or_default(),
        None => ScopeConfig::default(),
    }
}

/// Записать настройки в `<root>/prefs.json`, сохранив прочие ключи.
///
/// `prefs.json` общий с интерфейсом (там же `lang`), поэтому пишем не «файл
/// настроек осциллографа», а merge в существующий объект: иначе сохранение
/// осциллографа затирало бы выбранный язык.
pub fn save_config(root: &Path, cfg: &ScopeConfig) -> anyhow::Result<ScopeConfig> {
    let clean = cfg.clone().sanitized();
    let path = root.join("prefs.json");
    let mut map = fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| match value {
            Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    map.insert("scope".to_string(), serde_json::to_value(&clean)?);
    write_json_pretty(&path, &Value::Object(map))?;
    Ok(clean)
}

// ─────────────────────────── структуры контракта ─────────────────────────

/// Канал в «человеческой» нумерации CH1..CH8.
///
/// `raw_ch` хранит индекс API (0..7): он нужен, чтобы сверять подписи с
/// `columns_b64`, где столбцы идут именно в порядке API.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ChannelInfo {
    pub ch: usize,
    pub raw_ch: usize,
    pub enabled: bool,
    pub range: String,
    pub range_id: u8,
    pub full_scale_v: f64,
    pub center_v: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub pp: Option<f64>,
    pub freq: Option<f64>,
    pub duty: Option<f64>,
    pub aliased: bool,
    /// АЦП в насыщении на этом канале (кадр это видел).
    pub saturated: bool,
    /// Одиночные сбои АЦП, которые служба починила в этом кадре.
    pub dropouts: usize,
    /// Кумулятивные экстремумы за сеанс на момент кадра.
    pub peak_min: Option<f64>,
    pub peak_max: Option<f64>,
    /// Роль канала в профиле стенда: `gpt1`, `gpt2`, `power` (docs/16 §3).
    /// Пусто — роль не задана (старая сессия или профиль без ролей).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// Человеческое имя из профиля: `GPT1`, `Питание`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// Измерения кадра по одному каналу (`stats` в ответе API).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stat {
    pub ch: usize,
    pub vmin: Option<f64>,
    pub vmax: Option<f64>,
    pub vpp: Option<f64>,
    pub mean: Option<f64>,
    pub rms: Option<f64>,
    pub freq: Option<f64>,
    pub duty: Option<f64>,
    pub n: usize,
    pub window_s: f64,
    pub aliased: bool,
}

/// Один кадр `/api/capture/v2`.
///
/// `columns_b64` остаётся строкой: потребитель либо пишет её в JSONL, либо сам
/// распаковывает для графика. Так кадр — это ровно то, что отдала служба, без
/// потерь на перекодирование.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Frame {
    pub frame_id: u64,
    pub generation: u64,
    pub dt_s: f64,
    pub sample_rate: f64,
    pub n_block: usize,
    pub window_s: f64,
    /// Ширина, которую служба реально отдала в `columns_b64`. Запрошенная и
    /// фактическая могут разойтись (клампинг), а от этого зависит, столбец —
    /// это один отсчёт или огибающая нескольких.
    pub width: usize,
    /// Сколько отсчётов попало в окно кадра (по ним видно, точные это отсчёты
    /// или огибающая: `width >= window_samples` — по одному на столбец).
    pub window_samples: f64,
    /// `blocks_total` из `/api/info` на момент опроса: номер блока АЦП, а не
    /// номер публикации. По нему потребитель считает настоящие пропуски блоков.
    pub blocks_total: Option<u64>,
    pub start_sample: f64,
    pub state: String,
    pub held: bool,
    pub channels: Vec<usize>,
    pub channel_meta: Vec<ChannelInfo>,
    pub stats: Vec<Stat>,
    pub trigger: Value,
    /// В деградированной строке `frames.jsonl` здесь `null`, поэтому чтение
    /// записанного кадра обратно во `Frame` не должно падать (см.
    /// `de_string_or_null`).
    #[serde(default, deserialize_with = "de_string_or_null")]
    pub columns_b64: String,
    pub columns_bytes: usize,
}

/// Прочитать строку, допуская `null` (деградированная строка записи).
fn de_string_or_null<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// Результат проверки связи из интерфейса («Проверить»).
#[derive(Clone, Debug, Default, Serialize)]
pub struct Probe {
    /// Истина только когда живы и страница службы, и кадр: половина ответа
    /// («/api/info отвечает, а кадра нет») — это не рабочая связь.
    pub ok: bool,
    pub page_ok: bool,
    pub page_status: u16,
    pub page_ms: u64,
    pub frame_ok: bool,
    pub frame_ms: u64,
    pub url: String,
    pub error: Option<String>,
    pub frame: Option<Frame>,
    pub service: Option<Value>,
    pub channels: Vec<ChannelInfo>,
}

/// Снимок состояния записи осциллографа для `/api/scope/status`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub url: String,
    pub interval_ms: u64,
    pub width: usize,
    pub state: String,
    pub session: Option<String>,
    pub frames: u64,
    pub lines: u64,
    pub bytes: u64,
    pub last_frame_id: Option<u64>,
    pub last_t: Option<f64>,
    pub last_wall: Option<String>,
    pub gaps: u64,
    pub gap_blocks: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub degraded: bool,
    pub channels: Vec<ChannelInfo>,
    pub page_ok: bool,
    pub frame_ok: bool,
    pub sample_rate: f64,
    pub dt_s: f64,
    pub n_block: usize,
    pub updated_at: String,
    pub started_at: Option<String>,
}

/// Счётчики записи. Отдаются и в `counters()`, и в `summary.json`.
#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub frames: u64,
    pub lines: u64,
    pub bytes: u64,
    pub gaps: u64,
    pub gap_blocks: u64,
    pub degraded: bool,
    pub last_frame_id: Option<u64>,
    pub t_first: Option<f64>,
    pub t_last: Option<f64>,
    /// Суммарная длительность окон сигнала, с: кадр — окно блока АЦП (1.66 мс),
    /// а не интервал опроса. По этой сумме считается реальное покрытие.
    pub window_s_sum: f64,
    /// Сколько кадров дало вклад в `window_s_sum` (для среднего окна).
    pub window_count: u64,
    /// Интервалы между публикациями кадров, мс: медиана/p95/максимум. Это
    /// наблюдаемые величины; точность привязки к фронту ими не измеряется.
    pub interval_p50_ms: f64,
    pub interval_p95_ms: f64,
    pub interval_max_ms: f64,
}

/// Что произошло с кадром при записи.
#[derive(Clone, Debug, PartialEq)]
pub enum Accept {
    /// Строка кадра записана. `line_bytes` — сколько байт легло в файл вместе
    /// с переводом строки (это же приращение счётчика `bytes`).
    Frame { gap_blocks: u64, line_bytes: u64 },
    /// Тот же `frame_id` (hold/триггер не двигают кадр) — писать нечего.
    Duplicate { repeats: u64 },
    /// Достигнут `max_mb`: пишем только статистику, без `columns_b64`.
    Degraded { gap_blocks: u64 },
    /// Предел исчерпан и для статистики — кадр не записан, счётчики не растут.
    Capped,
}

/// Сообщения потока-опросчика в tokio-канал.
#[derive(Debug)]
pub enum PollMsg {
    Frame {
        frame: Box<Frame>,
        wall: String,
        /// Время приёма кадра на логгере (секунды эпохи). Писатель переводит его
        /// в `t` сессии сам: иначе в `t` попадала бы задержка очереди писателя,
        /// а не момент, когда кадр действительно пришёл (до 0.6 с на всплеске).
        recv_epoch: f64,
    },
    Link {
        ok: bool,
        page_ok: bool,
        frame_ok: bool,
        error: Option<String>,
        service: Option<Value>,
    },
    Channels(Vec<ChannelInfo>),
}

// ─────────────────────────────── HTTP-клиент ─────────────────────────────

/// Разобранный адрес: только `http://host[:port]/path?query`.
#[derive(Debug, Clone, PartialEq)]
struct Target {
    host: String,
    port: u16,
    path: String,
}

impl Target {
    fn host_header(&self) -> String {
        // Порт 80 в Host не пишут: часть серверов на этом спотыкается.
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Разобрать адрес службы.
///
/// Разбираем сами, а не через крейт: поддерживается ровно то, что нужно
/// (http, host[:port], path?query), и любая попытка https/редиректа должна
/// падать явной ошибкой, а не «тихо не работать».
fn parse_target(url: &str) -> Result<Target, String> {
    let raw = url.trim();
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err("TLS не поддерживается: адрес службы должен начинаться с http://".into());
    }
    if !lower.starts_with("http://") {
        return Err(format!(
            "адрес {raw:?} не поддержан: нужен http://host[:port]/path"
        ));
    }
    let rest = &raw[7..];
    if rest.is_empty() {
        return Err("в адресе нет хоста".into());
    }
    // Отделяем authority от пути: путь начинается с '/', запрос — с '?'.
    let (authority, tail) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("в адресе нет хоста".into());
    }
    if authority.contains('@') {
        return Err("логин/пароль в адресе службы не поддерживается".into());
    }
    let (host, port_text) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some((host, tail)) = stripped.split_once(']') else {
            return Err(format!("незакрытая скобка IPv6 в {authority:?}"));
        };
        let port = match tail.strip_prefix(':') {
            Some(port) => Some(port),
            None if tail.is_empty() => None,
            None => return Err(format!("мусор после IPv6-адреса: {tail:?}")),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => (host.to_string(), Some(port)),
            _ => (authority.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err("пустой хост в адресе службы".into());
    }
    let port = match port_text {
        None => 80,
        Some(text) if text.is_empty() => 80,
        Some(text) => text
            .parse::<u16>()
            .map_err(|_| format!("порт {text:?} не число"))?,
    };
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    Ok(Target { host, port, path })
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("таймаут запроса".into());
    }
    Ok(deadline - now)
}

/// Выполнить один GET и вернуть (статус, тело).
///
/// Дедлайн общий на всё: подключение + отправку + чтение. Иначе медленный
/// сервер, отдающий по байту, держал бы поток неограниченно долго.
fn http_get(url: &str, timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let target = parse_target(url)?;
    let deadline = Instant::now() + timeout;
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| format!("резолв {}: {e}", target.host))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("адрес {} не резолвится", target.host));
    }
    let mut last_error: Option<String> = None;
    let mut stream: Option<TcpStream> = None;
    for addr in addrs {
        let left = remaining(deadline)?;
        match TcpStream::connect_timeout(&addr, left) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last_error = Some(format!("подключение {addr}: {e}")),
        }
    }
    let Some(mut stream) = stream else {
        return Err(last_error.unwrap_or_else(|| format!("{}: нет доступных адресов", target.host)));
    };
    stream.set_nodelay(true).ok();
    // Мелкий таймаут на один read: внешний дедлайн проверяем сами, иначе
    // блокирующее чтение «съело» бы весь бюджет одного вызова.
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ftdi-logger/{version} scope\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        path = target.path,
        host = target.host_header(),
        version = env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("отправка запроса: {e}"))?;
    let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; READ_BUF];
    loop {
        if Instant::now() >= deadline {
            return Err(format!("таймаут чтения ответа ({url})"));
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_BODY {
                    return Err(format!("ответ больше {MAX_BODY} байт — отказ"));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("чтение ответа: {e}")),
        }
    }
    parse_response(&raw)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Разобрать сырой HTTP-ответ: строка статуса, заголовки (без учёта регистра),
/// тело по Content-Length или chunked.
///
/// Вынесено отдельной функцией, чтобы тестировать на синтетических байтах без
/// сокетов: именно здесь ломается всё, что ломается в HTTP.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    if raw.is_empty() {
        return Err("пустой ответ службы".into());
    }
    // Тело начинается сразу после пустой строки; смещение запоминаем, а не
    // режем буфер: заголовки нужны только как текст, тело — как байты.
    let (head, body_off) = if let Some(idx) = find_bytes(raw, b"\r\n\r\n") {
        (&raw[..idx], idx + 4)
    } else if let Some(idx) = find_bytes(raw, b"\n\n") {
        (&raw[..idx], idx + 2)
    } else {
        return Err("в ответе нет конца заголовков".into());
    };
    let head_text = String::from_utf8_lossy(head);
    let mut lines = head_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "в ответе нет строки статуса".to_string())?;
    let mut parts = status_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        let head: String = status_line.chars().take(60).collect();
        return Err(format!("ответ не HTTP: {head:?}"));
    }
    let status: u16 = parts
        .next()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("статус {status_line:?} не число"))?;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            // "chunked" может идти не один: Transfer-Encoding: gzip, chunked.
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => chunked = true,
            "content-length" => content_length = value.parse::<usize>().ok(),
            _ => {}
        }
    }
    let body = &raw[body_off..];
    if chunked {
        return Ok((status, decode_chunked(body)?));
    }
    match content_length {
        Some(expected) => {
            if body.len() < expected {
                return Err(format!("ответ оборван: {} из {expected} байт", body.len()));
            }
            Ok((status, body[..expected].to_vec()))
        }
        // Без длины тело читается до закрытия соединения (Connection: close).
        None => Ok((status, body.to_vec())),
    }
}

/// Раскодировать `Transfer-Encoding: chunked`.
///
/// Расширения чанков (`;part=1`) и трейлеры игнорируем: в них нет данных, а
/// спотыкаться о них нельзя — прокси их добавляют произвольно.
fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(body.len());
    let mut pos = 0usize;
    loop {
        let rest = &body[pos..];
        let line_end = match find_bytes(rest, b"\r\n") {
            Some(idx) => pos + idx,
            None => match find_bytes(rest, b"\n") {
                Some(idx) => pos + idx,
                None => return Err("chunked: нет строки размера".into()),
            },
        };
        let line = String::from_utf8_lossy(&body[pos..line_end]);
        let size_text = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| format!("chunked: размер {size_text:?} не hex"))?;
        pos = line_end
            + if body[line_end..].starts_with(b"\r\n") {
                2
            } else {
                1
            };
        if size == 0 {
            // Трейлеры после нулевого чанка не нужны: тело уже собрано.
            return Ok(out);
        }
        if pos + size > body.len() {
            return Err("chunked: чанк обрывается".into());
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if body[pos..].starts_with(b"\r\n") {
            pos += 2;
        } else if body[pos..].starts_with(b"\n") {
            pos += 1;
        }
    }
}

/// Декодировать стандартный base64 (с паддингом, без URL-алфавита).
///
/// Нужен, чтобы проверить `columns_b64` на целостность: `columns_bytes` в
/// ответе — это длина РАСПАКОВАННОГО буфера, и расхождение означает обрезанный
/// кадр, который нельзя показывать как достоверный.
fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = false;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding = true;
                continue;
            }
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            other => return Err(format!("base64: недопустимый байт {other:#04x}")),
        };
        if padding {
            return Err("base64: данные после '='".into());
        }
        acc = ((acc << 6) | value as u32) & 0xFFFF_FFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
            acc &= if bits == 0 { 0 } else { (1u32 << bits) - 1 };
        }
    }
    if bits >= 6 {
        return Err("base64: хвост короче байта".into());
    }
    Ok(out)
}

// ─────────────────────────── разбор ответов службы ───────────────────────

fn number_i64(value: Option<&Value>) -> Option<i64> {
    match value? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn get_f64(value: &Value, key: &str) -> Option<f64> {
    match value.get(key)? {
        Value::Number(n) => n.as_f64(),
        // Строковые числа встречаются в отладочных сборках службы — принимаем.
        Value::String(s) => s.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn get_u64(value: &Value, key: &str) -> Option<u64> {
    match value.get(key)? {
        Value::Number(n) => n.as_u64().or_else(|| {
            n.as_f64()
                .filter(|f| f.is_finite() && *f >= 0.0)
                .map(|f| f as u64)
        }),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn get_usize(value: &Value, key: &str) -> Option<usize> {
    get_u64(value, key).map(|n| n.min(usize::MAX as u64) as usize)
}

fn get_bool(value: &Value, key: &str) -> Option<bool> {
    match value.get(key)? {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => Some(n.as_f64().unwrap_or(0.0) != 0.0),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn get_str(value: &Value, key: &str) -> Option<String> {
    match value.get(key)? {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Похоже ли множество индексов на 1-based (1..=8) вместо контрактного 0-based.
///
/// В живом `/api/channels` поле `ch` приходит 1..8, хотя контракт обещает 0..7.
/// Признак надёжный: 0-based набор из восьми каналов всегда содержит 0 и не
/// содержит 8, поэтому «нет нуля и есть восьмёрка» однозначно означает сдвиг.
fn looks_one_based(values: &[i64]) -> bool {
    !values.is_empty() && !values.contains(&0) && values.iter().any(|&v| v == 8)
}

/// «±6 V» / «±20 V» — подпись диапазона, когда API даёт только полную шкалу.
fn range_label(full_scale_v: f64) -> String {
    if !full_scale_v.is_finite() || full_scale_v <= 0.0 {
        return "—".to_string();
    }
    format!("±{} V", trim_number(full_scale_v))
}

fn trim_number(value: f64) -> String {
    let text = format!("{value:.2}");
    let text = text.trim_end_matches('0').trim_end_matches('.');
    if text.is_empty() || text == "-" {
        "0".to_string()
    } else {
        text.to_string()
    }
}

/// Разобрать `/api/channels` (массив из восьми объектов).
fn parse_channels_value(value: &Value) -> Result<Vec<ChannelInfo>, String> {
    let items = match value {
        Value::Array(items) => items,
        Value::Object(map) => map
            .get("channels")
            .and_then(Value::as_array)
            .ok_or_else(|| "в ответе нет массива каналов".to_string())?,
        _ => return Err("ответ /api/channels не массив".to_string()),
    };
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let declared: Vec<i64> = items
        .iter()
        .filter_map(|item| number_i64(item.get("ch")))
        .collect();
    // Нет нуля в объявленных индексах → служба нумерует каналы с единицы. Если
    // поля `ch` нет вовсе, остаётся порядок массива (0-based по позиции).
    let base = if declared.is_empty() || declared.contains(&0) {
        0
    } else {
        1
    };
    let mut out: Vec<ChannelInfo> = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let raw = match number_i64(item.get("ch")) {
            Some(decl) => decl - base,
            None => idx as i64,
        };
        if !(0..8).contains(&raw) {
            continue;
        }
        let raw = raw as usize;
        let full_scale_v = get_f64(item, "range_v")
            .or_else(|| get_f64(item, "full_scale_v"))
            .unwrap_or(0.0);
        // Строка `range` службы бывает противоречивой: у CH1/CH2 она «±20 V»
        // при `range_v` 6 В и кадре ±6 В. Подпись строим по фактической шкале;
        // строку службы берём только если шкала неизвестна (иначе интерфейс
        // показывал бы не тот предел).
        let range = if full_scale_v > 0.0 {
            range_label(full_scale_v)
        } else {
            get_str(item, "range").unwrap_or_default()
        };
        out.push(ChannelInfo {
            ch: raw + 1,
            raw_ch: raw,
            enabled: get_bool(item, "enabled").unwrap_or(true),
            range,
            range_id: get_u64(item, "range_id").unwrap_or(0).min(u8::MAX as u64) as u8,
            full_scale_v,
            center_v: get_f64(item, "center_v").unwrap_or(0.0),
            min: get_f64(item, "min"),
            max: get_f64(item, "max"),
            pp: get_f64(item, "pp"),
            freq: get_f64(item, "freq"),
            duty: get_f64(item, "duty"),
            aliased: get_bool(item, "aliased").unwrap_or(false),
            saturated: get_bool(item, "saturated").unwrap_or(false),
            dropouts: get_usize(item, "dropouts").unwrap_or(0),
            peak_min: get_f64(item, "peak_min"),
            peak_max: get_f64(item, "peak_max"),
            role: String::new(),
            name: String::new(),
        });
    }
    out.sort_by_key(|info| info.ch);
    Ok(out)
}

/// Разобрать `channel_meta` кадра: там только шкала и пики, измерений нет.
fn parse_channel_meta(
    value: Option<&Value>,
    channels: &[usize],
    one_based: bool,
) -> Vec<ChannelInfo> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let declared: Vec<i64> = items
        .iter()
        .filter_map(|item| number_i64(item.get("ch")))
        .collect();
    // Сдвиг применяем, только если в meta действительно нет нуля: иначе
    // 1-based набор превратил бы ch=0 в -1 и потерял бы канал.
    let shift = one_based && !declared.contains(&0);
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(decl) = number_i64(item.get("ch")) else {
            continue;
        };
        let raw = if shift { decl - 1 } else { decl };
        if !(0..8).contains(&raw) {
            continue;
        }
        let raw = raw as usize;
        let full_scale_v = get_f64(item, "full_scale_v").unwrap_or(0.0);
        let peak_min = get_f64(item, "peak_min");
        let peak_max = get_f64(item, "peak_max");
        out.push(ChannelInfo {
            ch: raw + 1,
            raw_ch: raw,
            // meta приходит только по присутствующим каналам, поэтому «есть
            // запись» и означает «включён».
            enabled: channels.is_empty() || channels.contains(&(raw + 1)),
            range: range_label(full_scale_v),
            range_id: get_u64(item, "range_id").unwrap_or(0).min(u8::MAX as u64) as u8,
            full_scale_v,
            center_v: get_f64(item, "center_v").unwrap_or(0.0),
            min: peak_min,
            max: peak_max,
            pp: match (peak_min, peak_max) {
                (Some(lo), Some(hi)) => Some((hi - lo).abs()),
                _ => None,
            },
            freq: None,
            duty: None,
            aliased: false,
            saturated: get_bool(item, "saturated").unwrap_or(false),
            dropouts: get_usize(item, "dropouts").unwrap_or(0),
            peak_min,
            peak_max,
            role: String::new(),
            name: String::new(),
        });
    }
    out.sort_by_key(|info| info.ch);
    out
}

/// Разобрать `stats` кадра.
fn parse_stats(value: Option<&Value>, one_based: bool) -> Vec<Stat> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    let declared: Vec<i64> = items
        .iter()
        .filter_map(|item| number_i64(item.get("ch")))
        .collect();
    let shift = one_based && !declared.contains(&0);
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(decl) = number_i64(item.get("ch")) else {
            continue;
        };
        let raw = if shift { decl - 1 } else { decl };
        if !(0..8).contains(&raw) {
            continue;
        }
        let raw = raw as usize;
        out.push(Stat {
            ch: raw + 1,
            vmin: get_f64(item, "vmin"),
            vmax: get_f64(item, "vmax"),
            vpp: get_f64(item, "vpp"),
            mean: get_f64(item, "mean"),
            rms: get_f64(item, "rms"),
            freq: get_f64(item, "freq"),
            duty: get_f64(item, "duty"),
            n: get_usize(item, "n").unwrap_or(0),
            window_s: get_f64(item, "window_s").unwrap_or(0.0),
            aliased: get_bool(item, "aliased").unwrap_or(false),
        });
    }
    out.sort_by_key(|stat| stat.ch);
    out
}

/// Разобрать кадр из JSON-объекта.
fn parse_frame_value(value: &Value) -> Result<Frame, String> {
    if !value.is_object() {
        return Err("кадр не JSON-объект".into());
    }
    if let Some(format) = get_str(value, "format") {
        if format != "dav2" {
            return Err(format!("формат кадра {format:?}, ожидался dav2"));
        }
    }
    let Some(frame_id) = get_u64(value, "frame_id") else {
        // Без идентификатора невозможна дедупликация — кадр бесполезен.
        return Err("в кадре нет frame_id".into());
    };
    let declared_channels: Vec<i64> = value
        .get("channels")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| number_i64(Some(item)))
                .collect()
        })
        .unwrap_or_default();
    let one_based = looks_one_based(&declared_channels);
    let mut channels: Vec<usize> = declared_channels
        .iter()
        .filter_map(|&decl| {
            let raw = if one_based { decl - 1 } else { decl };
            if (0..8).contains(&raw) {
                Some(raw as usize + 1)
            } else {
                None
            }
        })
        .collect();
    // Порядок НЕ сортируем: столбцы в `columns_b64` уложены «подряд по каналам
    // из channels», и перестановка сломала бы соответствие данных подписям.
    // Убираем только повторы (служба их не даёт, но кадр должен быть валиден).
    channels.dedup();
    let mut channel_meta = parse_channel_meta(value.get("channel_meta"), &channels, one_based);
    let stats = parse_stats(value.get("stats"), one_based);
    // Пики из meta — это экстремумы за окно, а stats считает по тем же
    // отсчётам; для графика важнее stats, поэтому берём их, а meta остаётся
    // запасным вариантом (канал без stats).
    for info in &mut channel_meta {
        if let Some(stat) = stats.iter().find(|stat| stat.ch == info.ch) {
            info.min = stat.vmin.or(info.min);
            info.max = stat.vmax.or(info.max);
            info.pp = stat.vpp.or(info.pp);
            info.freq = stat.freq;
            info.duty = stat.duty;
            info.aliased = stat.aliased;
        }
    }
    let columns_b64 = value
        .get("columns_b64")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let columns_bytes = get_usize(value, "columns_bytes").unwrap_or(columns_b64.len() * 3 / 4);
    Ok(Frame {
        frame_id,
        generation: get_u64(value, "generation").unwrap_or(0),
        dt_s: get_f64(value, "dt_s").unwrap_or(0.0),
        sample_rate: get_f64(value, "sample_rate").unwrap_or(0.0),
        n_block: get_usize(value, "n_block").unwrap_or(0),
        window_s: get_f64(value, "window_s").unwrap_or(0.0),
        width: get_usize(value, "width").unwrap_or(0),
        window_samples: get_f64(value, "window_samples").unwrap_or(0.0),
        // В ответе /api/capture/v2 поля нет — его подставляет опросчик из
        // /api/info, чтобы строка записи знала номер блока АЦП.
        blocks_total: None,
        start_sample: get_f64(value, "start_sample").unwrap_or(0.0),
        state: get_str(value, "state").unwrap_or_default(),
        held: get_bool(value, "held").unwrap_or(false),
        channels,
        channel_meta,
        stats,
        trigger: value.get("trigger").cloned().unwrap_or(Value::Null),
        columns_b64,
        columns_bytes,
    })
}

fn parse_frame_text(text: &str) -> Result<Frame, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("JSON кадра: {e}"))?;
    parse_frame_value(&value)
}

/// Проверить, что кадр целостен: base64 распаковывается и сходится с
/// `columns_bytes`, а длина кратна четырём байтам на канал (i16 lo + i16 hi).
fn frame_sanity(frame: &Frame) -> Result<(), String> {
    if frame.columns_b64.is_empty() {
        // Кадр без каналов (всё выключено) — это не битый кадр.
        return Ok(());
    }
    let decoded = b64_decode(&frame.columns_b64)?;
    if decoded.len() != frame.columns_bytes {
        return Err(format!(
            "columns_bytes={} не совпадает с base64 ({} байт)",
            frame.columns_bytes,
            decoded.len()
        ));
    }
    if !frame.channels.is_empty() {
        let stride = frame.channels.len() * 4;
        if stride > 0 && frame.columns_bytes % stride != 0 {
            return Err(format!(
                "columns_bytes={} не кратно {stride} (каналов {})",
                frame.columns_bytes,
                frame.channels.len()
            ));
        }
    }
    Ok(())
}

// ─────────────────────────── запросы к службе ────────────────────────────

fn endpoint(cfg: &ScopeConfig, path: &str) -> String {
    format!("{}{}", cfg.url.trim_end_matches('/'), path)
}

fn http_error(status: u16, body: &[u8]) -> String {
    let snippet = String::from_utf8_lossy(&body[..body.len().min(200)]);
    let snippet = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    if snippet.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {snippet}")
    }
}

/// `GET /api/info` — состояние службы и счётчики блоков.
pub fn fetch_info(cfg: &ScopeConfig) -> Result<Value, String> {
    let url = endpoint(cfg, "/api/info");
    let (status, body) = http_get(&url, HTTP_TIMEOUT).map_err(|e| format!("GET {url}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: {}", http_error(status, &body)));
    }
    serde_json::from_slice(&body).map_err(|e| format!("JSON /api/info: {e}"))
}

/// `GET /api/channels` — паспорт восьми каналов (диапазон, измерения).
pub fn fetch_channels(cfg: &ScopeConfig) -> Result<Vec<ChannelInfo>, String> {
    let url = endpoint(cfg, "/api/channels");
    let (status, body) = http_get(&url, HTTP_TIMEOUT).map_err(|e| format!("GET {url}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: {}", http_error(status, &body)));
    }
    let value: Value =
        serde_json::from_slice(&body).map_err(|e| format!("JSON /api/channels: {e}"))?;
    parse_channels_value(&value)
}

/// `GET /api/capture/v2?width=N` — последний кадр с шириной из настроек.
pub fn fetch_frame(cfg: &ScopeConfig) -> Result<Frame, String> {
    fetch_frame_width(cfg, cfg.width)
}

/// Кадр с явно заданной шириной.
///
/// Ширина — не украшение: при `width >= window_samples` каждый столбец несёт
/// ровно один отсчёт (точные выборки), при меньшей — огибающую min/max.
/// Опросчик подбирает её по факту ответа, а не по константе.
pub fn fetch_frame_width(cfg: &ScopeConfig, width: usize) -> Result<Frame, String> {
    // Верхняя граница API — 8192; снизу 16. Настройки уже ограничены, но
    // страхуемся: чужой вызов не должен просить кадр на гигабайт.
    let width = width.clamp(16, 8192);
    let url = endpoint(cfg, &format!("/api/capture/v2?width={width}"));
    let (status, body) = http_get(&url, HTTP_TIMEOUT).map_err(|e| format!("GET {url}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(format!("GET {url}: {}", http_error(status, &body)));
    }
    let text = std::str::from_utf8(&body).map_err(|e| format!("тело кадра не UTF-8: {e}"))?;
    parse_frame_text(text)
}

/// Проверка связи: страница службы, каналы, кадр.
///
/// Три запроса, потому что «связь есть» — это не только `/api/info`: служба
/// может отвечать на страницу и при этом не отдавать кадр (нет устройства).
pub fn probe(cfg: &ScopeConfig) -> Probe {
    let mut out = Probe {
        url: cfg.url.trim_end_matches('/').to_string(),
        ..Probe::default()
    };
    let mut page_error: Option<String> = None;
    let mut frame_error: Option<String> = None;

    let info_url = endpoint(cfg, "/api/info");
    let started = Instant::now();
    match http_get(&info_url, HTTP_TIMEOUT) {
        Ok((status, body)) => {
            out.page_status = status;
            out.page_ms = started.elapsed().as_millis() as u64;
            if (200..300).contains(&status) {
                match serde_json::from_slice::<Value>(&body) {
                    Ok(value) => {
                        out.page_ok = true;
                        out.service = Some(value);
                    }
                    Err(e) => page_error = Some(format!("JSON /api/info: {e}")),
                }
            } else {
                page_error = Some(http_error(status, &body));
            }
        }
        Err(e) => {
            out.page_ms = started.elapsed().as_millis() as u64;
            page_error = Some(format!("GET /api/info: {e}"));
        }
    }

    // Каналы на `ok` не влияют: без них интерфейс просто не покажет подписи,
    // но связь с кадрами от этого не перестаёт быть рабочей.
    if let Ok(channels) = fetch_channels(cfg) {
        out.channels = channels;
    }

    let started = Instant::now();
    match fetch_frame(cfg) {
        Ok(frame) => {
            out.frame_ms = started.elapsed().as_millis() as u64;
            match frame_sanity(&frame) {
                Ok(()) => {
                    out.frame_ok = true;
                    out.frame = Some(frame);
                }
                Err(e) => frame_error = Some(e),
            }
        }
        Err(e) => {
            out.frame_ms = started.elapsed().as_millis() as u64;
            frame_error = Some(e);
        }
    }

    out.ok = out.page_ok && out.frame_ok;
    // Ошибку показываем только когда связь действительно неполная: при
    // успешной проверке поле должно быть пустым.
    out.error = if !out.page_ok {
        page_error
    } else if !out.frame_ok {
        frame_error
    } else {
        None
    };
    out
}

// ─────────────────────────────── запись ─────────────────────────────────

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Атомарная запись JSON: временный файл рядом + rename.
///
/// Свой мини-хелпер, а не `store::write_json_atomic`, чтобы модуль не зависел
/// от раскладки хранилища: писать приходится и в `prefs.json`, который лежит
/// вне сессий.
fn write_json_pretty<T: Serialize + ?Sized>(path: &Path, value: &T) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(value).context("сериализация JSON")?;
    write_bytes_atomic(path, text.as_bytes())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("не создать каталог {}", parent.display()))?;
    }
    let tmp = match path.file_name() {
        Some(name) => path.with_file_name(format!(
            ".{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id()
        )),
        None => path.to_path_buf(),
    };
    {
        let mut file =
            File::create(&tmp).with_context(|| format!("не создать {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("не записать {}", tmp.display()))?;
        // fsync: файл настроек/сводки должен пережить аварийное выключение.
        file.sync_all().ok();
    }
    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(first) => {
            // На Windows rename поверх существующего файла иногда упирается в
            // открытый хэндл — пробуем ещё раз после удаления.
            let _ = fs::remove_file(path);
            fs::rename(&tmp, path).map_err(|second| {
                anyhow!("не заменить {}: {first}; повтор: {second}", path.display())
            })
        }
    }
}

#[derive(Serialize)]
struct MetaLine<'a> {
    format: &'a str,
    session_id: &'a str,
    url: &'a str,
    interval_ms: u64,
    width: usize,
    max_mb: u64,
    /// Профиль ролей каналов: по нему отчёт называет GPT1/GPT2/питание.
    profile: &'a str,
    contract: &'a str,
    engine_version: &'a str,
    started_at: &'a str,
}

#[derive(Serialize)]
struct SummaryLine<'a> {
    format: &'a str,
    stopped_at: &'a str,
    t_stop: f64,
    frames: u64,
    lines: u64,
    bytes: u64,
    gaps: u64,
    gap_blocks: u64,
    degraded: bool,
    last_frame_id: Option<u64>,
    t_first: Option<f64>,
    t_last: Option<f64>,
    /// Суммарная длительность записанных окон сигнала, с, и средняя длина окна.
    signal_s: f64,
    window_ms: f64,
    /// Наблюдаемые интервалы публикаций, мс. Не «точность»: по ним видно, как
    /// часто кадр реально приходил (в разборе 0.5.0 — медиана 52 мс, максимум 597).
    interval_p50_ms: f64,
    interval_p95_ms: f64,
    interval_max_ms: f64,
    /// Сегмент записи: сколько раз служба перезапускалась за сессию.
    segment: u32,
    /// Последняя ошибка записи (диск/сериализация), если была.
    last_error: Option<&'a str>,
    notes: &'a [String],
}

/// Одна строка `frames.jsonl`.
///
/// Поля идут в порядке контракта (serde сохраняет порядок объявления), а
/// служебные флаги опускаются, когда ложны: `"gap_blocks":0` в каждой строке
/// только раздувал бы файл.
#[derive(Serialize)]
struct FrameLine<'a> {
    format: &'a str,
    t: f64,
    wall: &'a str,
    /// Время приёма кадра на логгере в секундах эпохи: вместе с `t` даёт
    /// смещение часов, а `time_source` честно говорит, что часы источника
    /// недоступны (ТЗ §4.2).
    rcv_epoch: f64,
    time_source: &'a str,
    /// Точность привязки, мс: интервал опроса + задержка HTTP. Меньше интервала
    /// опроса утверждать нельзя — блок мог появиться в любой момент между ними.
    accuracy_ms: u64,
    frame_id: u64,
    generation: u64,
    dt_s: f64,
    sample_rate: f64,
    n_block: usize,
    window_s: f64,
    window_samples: f64,
    start_sample: f64,
    state: &'a str,
    held: bool,
    width: usize,
    /// `samples` — в столбце один отсчёт (точные выборки), `envelope` —
    /// min/max нескольких отсчётов. Пики сохраняются в обоих случаях.
    representation: &'a str,
    samples_per_column: f64,
    exact: bool,
    unit: &'a str,
    quantization_mv: u32,
    /// Пустой столбец кодируется как `lo > hi` (в i16 это 32767/-32768) и
    /// напряжением не является.
    empty: &'a str,
    blocks_total: Option<u64>,
    segment: u32,
    channels: &'a [usize],
    channel_meta: &'a [ChannelInfo],
    stats: &'a [Stat],
    trigger: &'a Value,
    columns_b64: Option<&'a str>,
    columns_bytes: usize,
    #[serde(skip_serializing_if = "is_false")]
    degraded: bool,
    #[serde(skip_serializing_if = "is_zero_u64")]
    gap_blocks: u64,
    #[serde(skip_serializing_if = "is_false")]
    first: bool,
    #[serde(skip_serializing_if = "is_false")]
    restart: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// Пишет кадры сессии в `<session>/scope/{meta.json,frames.jsonl}`.
///
/// Дедупликация и пропуски — не «оптимизация», а смысл записи: в режиме hold
/// служба отдаёт один и тот же `frame_id` десятки раз, и без дедупа файл
/// раздувался бы копиями без новой информации; при этом разрыв в нумерации
/// (потерянные блоки) обязан быть виден потребителю, а не растворяться.
pub struct Recorder {
    dir: PathBuf,
    cfg: ScopeConfig,
    frames_file: File,
    errors_file: Option<File>,
    limit_bytes: u64,
    cap_bytes: u64,
    bytes: u64,
    n_frames: u64,
    n_lines: u64,
    gaps: u64,
    gap_blocks: u64,
    errors: u64,
    degraded: bool,
    capped: bool,
    last_frame_id: Option<u64>,
    /// Номер блока АЦП последнего кадра: по нему ловится перезапуск службы,
    /// который по `frame_id` не виден (например, после простоя публикаций).
    last_blocks_total: Option<u64>,
    /// Сегмент записи: растёт на каждом перезапуске службы. Через границу
    /// сегмента пропуски и время не склеиваются.
    segment: u32,
    repeats: u64,
    t_first: Option<f64>,
    t_last: Option<f64>,
    /// Суммарная длительность окон и число кадров: покрытие сигнала, а не
    /// длительность сессии. Кадр — 1.66 мс окна, поэтому 20 кадров/с дают ~3 %.
    window_sum: f64,
    window_count: u64,
    /// Интервалы публикаций, мс: копим для медианы/p95. Предел — чтобы часовая
    /// запись не держала в памяти миллионы чисел; хвост распределения всё равно
    /// виден по `interval_max`.
    intervals: Vec<f64>,
    interval_max: f64,
    /// Медиана и p95, посчитанные в `finish()` (в живых счётчиках — 0).
    p50: f64,
    p95: f64,
    /// Последняя ошибка записи (диск/сериализация) — попадает в `summary.json`.
    last_error: Option<String>,
}

impl Recorder {
    /// Открыть запись в каталоге сессии.
    ///
    /// `frames.jsonl` открывается на дозапись: если сессию переоткрыли, старые
    /// строки должны остаться, а `bytes` — продолжить счёт с текущего размера,
    /// иначе лимит `max_mb` после перезапуска считался бы с нуля.
    pub fn open(session_dir: &Path, cfg: &ScopeConfig, session_id: &str) -> anyhow::Result<Self> {
        let cfg = cfg.clone().sanitized();
        let dir = session_dir.join("scope");
        fs::create_dir_all(&dir).with_context(|| format!("не создать {}", dir.display()))?;
        let frames_path = dir.join("frames.jsonl");
        let frames_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&frames_path)
            .with_context(|| format!("не открыть {}", frames_path.display()))?;
        let bytes = frames_file.metadata().map(|meta| meta.len()).unwrap_or(0);
        // Журнал ошибок необязателен: без него запись всё равно продолжается.
        let errors_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("errors.log"))
            .ok();
        let limit_bytes = if cfg.max_mb == 0 {
            u64::MAX
        } else {
            cfg.max_mb.saturating_mul(1024 * 1024)
        };
        let cap_bytes = if cfg.max_mb == 0 {
            u64::MAX
        } else {
            limit_bytes.saturating_add(CAP_EXTRA_BYTES)
        };
        let started_at = now_rfc3339();
        let meta = MetaLine {
            format: META_FORMAT,
            session_id,
            url: &cfg.url,
            interval_ms: cfg.interval_ms,
            width: cfg.width,
            max_mb: cfg.max_mb,
            profile: &cfg.profile,
            contract: CONTRACT,
            engine_version: env!("CARGO_PKG_VERSION"),
            started_at: &started_at,
        };
        write_json_pretty(&dir.join("meta.json"), &meta)
            .with_context(|| format!("не записать meta.json в {}", dir.display()))?;
        Ok(Self {
            dir,
            cfg,
            frames_file,
            errors_file,
            limit_bytes,
            cap_bytes,
            bytes,
            n_frames: 0,
            n_lines: 0,
            gaps: 0,
            gap_blocks: 0,
            errors: 0,
            degraded: false,
            capped: false,
            last_frame_id: None,
            last_blocks_total: None,
            segment: 0,
            repeats: 0,
            t_first: None,
            t_last: None,
            window_sum: 0.0,
            window_count: 0,
            intervals: Vec::new(),
            interval_max: 0.0,
            p50: 0.0,
            p95: 0.0,
            last_error: None,
        })
    }

    /// Принять кадр. `t` — монотонное время сессии, `wall` — UTC RFC3339.
    pub fn accept(&mut self, t: f64, wall: &str, frame: &Frame) -> Accept {
        // 1. Дедупликация: hold и «free» без нового блока дают тот же frame_id.
        if let Some(last) = self.last_frame_id {
            if frame.frame_id == last {
                self.repeats = self.repeats.saturating_add(1);
                return Accept::Duplicate {
                    repeats: self.repeats,
                };
            }
        }
        // Перезапуск службы: номер публикации или номер блока ушёл назад. Через
        // такую границу пропуски не считаем — это уже другой экземпляр, и его
        // нумерация начинается заново.
        let id_restart = matches!(self.last_frame_id, Some(last) if frame.frame_id < last);
        let block_restart = matches!(
            (self.last_blocks_total, frame.blocks_total),
            (Some(last), Some(now)) if now < last
        );
        let restart = id_restart || block_restart;
        let first = self.last_frame_id.is_none();
        let segment = self.segment.saturating_add(u32::from(restart));
        // `frame_id` — номер ПУБЛИКАЦИИ, а не блока: в Normal/Single служба
        // публикует кадр только по фронту, поэтому разрыв здесь означает
        // «пропущенные публикации». Настоящие блоки видны по `blocks_total`.
        let gap_blocks = if restart || first {
            0
        } else {
            match self.last_frame_id {
                Some(last) => frame.frame_id.saturating_sub(last.saturating_add(1)),
                None => 0,
            }
        };
        // 2. Лимит. Сравниваем уже записанное: строка, которая «пробила» порог,
        // пишется целиком, а деградация начинается со следующей — так в файле
        // остаётся хотя бы один полный кадр за порогом.
        if self.bytes > self.cap_bytes {
            self.capped = true;
            // Счётчики не растут: писать больше нечего и некуда.
            return Accept::Capped;
        }
        let degraded = self.bytes >= self.limit_bytes;
        let columns_b64 = if degraded {
            None
        } else {
            Some(frame.columns_b64.as_str())
        };
        let columns_bytes = if degraded { 0 } else { frame.columns_bytes };
        // Ширина фактическая, а не запрошенная: клампинг службы сделал бы
        // «500 столбцов» ложью, а от ширины зависит трактовка данных.
        let width = if frame.width > 0 {
            frame.width
        } else {
            self.cfg.width
        };
        let window_samples = if frame.window_samples > 0.0 {
            frame.window_samples
        } else if frame.dt_s > 0.0 {
            frame.window_s / frame.dt_s
        } else {
            0.0
        };
        // Один отсчёт на столбец — точные выборки; меньше — огибающая min/max
        // (пики в ней сохраняются, форма внутри пары — нет).
        let exact = width > 0 && window_samples > 0.0 && width as f64 >= window_samples;
        let samples_per_column = if width > 0 {
            window_samples / width as f64
        } else {
            0.0
        };
        let rcv_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let line = FrameLine {
            format: FRAME_FORMAT,
            t,
            wall,
            rcv_epoch,
            time_source: "delivery",
            accuracy_ms: self.cfg.interval_ms,
            frame_id: frame.frame_id,
            generation: frame.generation,
            dt_s: frame.dt_s,
            sample_rate: frame.sample_rate,
            n_block: frame.n_block,
            window_s: frame.window_s,
            window_samples,
            start_sample: frame.start_sample,
            state: &frame.state,
            held: frame.held,
            width,
            representation: if exact { "samples" } else { "envelope" },
            samples_per_column,
            exact,
            unit: "mV",
            quantization_mv: 1,
            empty: "lo>hi",
            blocks_total: frame.blocks_total,
            segment,
            channels: &frame.channels,
            channel_meta: &frame.channel_meta,
            stats: &frame.stats,
            trigger: &frame.trigger,
            columns_b64,
            columns_bytes,
            degraded,
            gap_blocks,
            first,
            restart,
        };
        let mut buf = match serde_json::to_vec(&line) {
            Ok(buf) => buf,
            Err(e) => {
                self.note_error(&format!("сериализация кадра {}: {e}", frame.frame_id));
                // Ни один вариант `Accept` не описывает «не смогли даже
                // сериализовать»; `Capped` — единственный «строка не
                // записана, счётчики не растут».
                return Accept::Capped;
            }
        };
        buf.push(b'\n');
        if let Err(e) = self.write_line(&buf) {
            // Диск/хэндл — сбой среды, а не повод падать: пишем в errors.log и
            // идём дальше, чтобы остальные кадры (и сводка) уцелели.
            self.note_error(&format!("запись кадра {}: {e}", frame.frame_id));
            self.degraded = true;
            return Accept::Capped;
        }
        let line_bytes = buf.len() as u64;
        self.bytes = self.bytes.saturating_add(line_bytes);
        self.n_frames = self.n_frames.saturating_add(1);
        self.n_lines = self.n_lines.saturating_add(1);
        if let Some(prev) = self.t_last {
            let dt_ms = (t - prev) * 1000.0;
            if dt_ms > 0.0 {
                self.interval_max = self.interval_max.max(dt_ms);
                if self.intervals.len() < INTERVALS_CAP {
                    self.intervals.push(dt_ms);
                }
            }
        }
        if frame.window_s > 0.0 {
            self.window_sum += frame.window_s;
            self.window_count = self.window_count.saturating_add(1);
        }
        if first {
            self.t_first = Some(t);
        }
        self.t_last = Some(t);
        self.last_frame_id = Some(frame.frame_id);
        self.last_blocks_total = frame.blocks_total.or(self.last_blocks_total);
        self.segment = segment;
        self.repeats = 0;
        if gap_blocks > 0 {
            self.gaps = self.gaps.saturating_add(1);
            self.gap_blocks = self.gap_blocks.saturating_add(gap_blocks);
        }
        self.degraded |= degraded;
        if degraded {
            Accept::Degraded { gap_blocks }
        } else {
            Accept::Frame {
                gap_blocks,
                line_bytes,
            }
        }
    }

    /// Записать паспорт каналов (включая выключенные) в `scope/channels.json`.
    ///
    /// В кадре присутствуют только включённые каналы, поэтому «CH4 выключен»
    /// иначе нигде не сказано. Здесь — все восемь с флагом `enabled`, диапазоном
    /// и шкалой на момент начала записи; ТЗ §4.2 требует обозначать отключённый
    /// канал явно.
    pub fn write_channels(&self, channels: &[ChannelInfo]) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct ChannelsFile<'a> {
            format: &'a str,
            captured_at: &'a str,
            profile: &'a str,
            channels: &'a [ChannelInfo],
        }
        let captured_at = now_rfc3339();
        // Роли пишем в файл сессии: иначе по ZIP нельзя понять, что CH1 — GPT1,
        // и разбор сигналов применяет профиль по умолчанию (docs/16 §3).
        let mut channels = channels.to_vec();
        apply_profile(&mut channels, &self.cfg.profile);
        let body = ChannelsFile {
            format: "scope-channels/1",
            captured_at: &captured_at,
            profile: &self.cfg.profile,
            channels: &channels,
        };
        write_json_pretty(&self.dir.join("channels.json"), &body)
            .with_context(|| format!("не записать channels.json в {}", self.dir.display()))
    }
    pub fn counters(&self) -> Counters {
        Counters {
            frames: self.n_frames,
            lines: self.n_lines,
            bytes: self.bytes,
            gaps: self.gaps,
            gap_blocks: self.gap_blocks,
            degraded: self.degraded,
            last_frame_id: self.last_frame_id,
            t_first: self.t_first,
            t_last: self.t_last,
            window_s_sum: self.window_sum,
            window_count: self.window_count,
            interval_p50_ms: self.p50,
            interval_p95_ms: self.p95,
            interval_max_ms: self.interval_max,
        }
    }

    /// Завершить запись: сбросить буферы и положить `summary.json`.
    pub fn finish(&mut self, t: f64) -> Counters {
        let _ = self.frames_file.flush();
        let mut notes: Vec<String> = Vec::new();
        if self.degraded {
            notes.push(format!(
                "достигнут предел max_mb={}: строки писались без отсчётов (columns_b64=null)",
                self.cfg.max_mb
            ));
        }
        if self.capped {
            notes.push("предел статистики исчерпан: новые кадры не записывались".to_string());
        }
        if self.errors > 0 {
            notes.push(format!("ошибок записи: {}", self.errors));
        }
        // Медиана/p95 считаются здесь, а не на каждом кадре: живой статус в них
        // не нуждается, а сортировка десятков тысяч чисел на кадр — лишняя работа.
        if !self.intervals.is_empty() {
            let mut sorted = self.intervals.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            self.p50 = percentile(&sorted, 0.50);
            self.p95 = percentile(&sorted, 0.95);
        }
        let stopped_at = now_rfc3339();
        let counters = self.counters();
        let window_ms = if counters.window_count > 0 {
            counters.window_s_sum / counters.window_count as f64 * 1000.0
        } else {
            0.0
        };
        let summary = SummaryLine {
            format: SUMMARY_FORMAT,
            stopped_at: &stopped_at,
            t_stop: t,
            frames: counters.frames,
            lines: counters.lines,
            bytes: counters.bytes,
            gaps: counters.gaps,
            gap_blocks: counters.gap_blocks,
            degraded: counters.degraded,
            last_frame_id: counters.last_frame_id,
            t_first: counters.t_first,
            t_last: counters.t_last,
            signal_s: counters.window_s_sum,
            window_ms,
            interval_p50_ms: counters.interval_p50_ms,
            interval_p95_ms: counters.interval_p95_ms,
            interval_max_ms: counters.interval_max_ms,
            segment: self.segment,
            last_error: self.last_error.as_deref(),
            notes: &notes,
        };
        if let Err(e) = write_json_pretty(&self.dir.join("summary.json"), &summary) {
            // Сводка — не повод терять уже записанные кадры: фиксируем ошибку
            // и возвращаем честные счётчики.
            self.note_error(&format!("summary.json: {e}"));
        }
        let _ = self.frames_file.flush();
        counters
    }

    fn write_line(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.frames_file.write_all(bytes)?;
        // Flush на каждую строку: при 20 кадрах/с это дёшево, а падение
        // процесса не должно терять уже принятые кадры.
        self.frames_file.flush()
    }

    /// Ошибка записи: считаем, кладём строку в `errors.log`, продолжаем.
    /// Ошибок записи (диск/сериализация) за сессию.
    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// Текст последней ошибки записи (для `summary.json`/диагностики).
    pub fn last_error_text(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    fn note_error(&mut self, message: &str) {
        self.errors = self.errors.saturating_add(1);
        self.last_error = Some(message.to_string());
        if let Some(file) = self.errors_file.as_mut() {
            let line = format!("{} {message}\n", now_rfc3339());
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }
}

// ─────────────────────────────── опросчик ───────────────────────────────

/// Поток опроса службы: сначала каналы, затем кадры с интервалом.
///
/// Сеть синхронная (std-сокеты), поэтому и поток std: tokio-задача не должна
/// блокироваться на 2-секундных таймаутах. Канал ёмкостью 64 сглаживает
/// всплески, а `blocking_send` из std-потока в tokio — штатный путь.
pub fn spawn_poller(
    cfg: ScopeConfig,
    session_id: String,
    tx: tokio::sync::mpsc::Sender<PollMsg>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("scope-poller".to_string())
        .spawn(move || poller_loop(cfg.sanitized(), &session_id, &tx, &stop))
        // Поток не создать — состояние процесса уже ненормальное; сигнатура
        // требует JoinHandle, поэтому паника здесь честнее молчаливого отказа.
        .expect("поток опроса осциллографа")
}

fn poller_loop(
    cfg: ScopeConfig,
    session_id: &str,
    tx: &tokio::sync::mpsc::Sender<PollMsg>,
    stop: &Arc<AtomicBool>,
) {
    tracing::debug!(session = session_id, url = %cfg.url, "опрос осциллографа запущен");
    // Каналы уходят сразу: интерфейс успевает нарисовать подписи до кадра.
    let channels = fetch_channels(&cfg).unwrap_or_default();
    if tx.blocking_send(PollMsg::Channels(channels)).is_err() {
        return;
    }
    // Ширина: настройка — нижняя граница, а не истина. При `width >= window_samples`
    // столбец несёт ровно один отсчёт (точные выборки), при меньшей — огибающую.
    // Поэтому первый запрос берём с запасом, а дальше поднимаем до окна кадра:
    // 3 канала дают 999 отсчётов, 8 каналов — 499.
    let mut width = cfg.width.max(AUTO_WIDTH);
    let mut was_ok: Option<bool> = None;
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // `/api/info` даёт номер блока АЦП и признак удержания — без них
        // `frame_id` (номер публикации) нельзя трактовать как номер блока.
        let info = fetch_info(&cfg).ok();
        match fetch_frame_width(&cfg, width) {
            Ok(mut frame) => {
                if let Some(info) = info.as_ref() {
                    frame.blocks_total = get_u64(info, "blocks_total");
                    if let Some(held) = get_bool(info, "held") {
                        frame.held = held;
                    }
                    if frame.state.is_empty() {
                        if let Some(state) = get_str(info, "state") {
                            frame.state = state;
                        }
                    }
                }
                if frame.window_samples >= 1.0 {
                    let needed = (frame.window_samples.ceil() as usize).saturating_add(2);
                    width = width.max(needed.clamp(200, 2000));
                }
                let wall = now_rfc3339();
                if tx
                    .blocking_send(PollMsg::Frame {
                        frame: Box::new(frame),
                        wall,
                        recv_epoch: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0),
                    })
                    .is_err()
                {
                    break;
                }
                // Событие связи — только на переходе «было плохо → стало хорошо»:
                // на каждом кадре оно превращало бы журнал в мусор.
                if was_ok == Some(false) {
                    if tx
                        .blocking_send(PollMsg::Link {
                            ok: true,
                            page_ok: true,
                            frame_ok: true,
                            error: None,
                            service: info,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                was_ok = Some(true);
                pause(stop, cfg.interval_ms);
            }
            Err(error) => {
                // Страницу спрашиваем только на первом сбое серии: при каждом
                // повторе это удваивало бы паузу до следующей попытки.
                let service = if was_ok != Some(false) {
                    fetch_info(&cfg).ok()
                } else {
                    None
                };
                let page_ok = service.is_some();
                if was_ok != Some(false) {
                    if tx
                        .blocking_send(PollMsg::Link {
                            ok: false,
                            page_ok,
                            frame_ok: false,
                            error: Some(error),
                            service,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                was_ok = Some(false);
                pause(stop, POLL_RETRY_MS);
            }
        }
    }
    tracing::debug!(session = session_id, "опрос осциллографа остановлен");
}
/// Пауза с проверкой «стоп»: чтобы остановка не ждала целую секунду.
fn pause(stop: &Arc<AtomicBool>, ms: u64) {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        std::thread::sleep(left.min(STOP_SLICE));
    }
}

/// Заглушка состояния для UI, когда записи нет.
///
/// `enabled=false` — «off» (пользователь не включал), иначе «connecting»:
/// интерфейс не должен показывать «recording», пока поток ещё не поднялся.
pub fn status_shell(cfg: &ScopeConfig) -> Status {
    Status {
        enabled: cfg.enabled,
        url: cfg.url.clone(),
        interval_ms: cfg.interval_ms,
        width: cfg.width,
        state: if cfg.enabled { "connecting" } else { "off" }.to_string(),
        updated_at: now_rfc3339(),
        ..Status::default()
    }
}

// ─────────────────────────────── тесты ──────────────────────────────────

/// Квантиль по уже отсортированному ряду (ближайший ранг).
fn percentile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame_with(id: u64, columns: &str) -> Frame {
        Frame {
            frame_id: id,
            generation: 0,
            dt_s: 1.0 / 600_000.0,
            sample_rate: 600_000.0,
            n_block: 1000,
            window_s: 0.001_666,
            width: 500,
            window_samples: 999.0,
            blocks_total: Some(id),
            start_sample: 0.0,
            state: "free".to_string(),
            held: false,
            channels: vec![1, 2],
            channel_meta: vec![ChannelInfo {
                ch: 1,
                raw_ch: 0,
                enabled: true,
                range: "±20 V".to_string(),
                range_id: 3,
                full_scale_v: 20.0,
                center_v: 0.0,
                min: Some(-1.0),
                max: Some(1.0),
                pp: Some(2.0),
                freq: None,
                duty: None,
                aliased: false,
                saturated: false,
                dropouts: 0,
                peak_min: Some(-1.0),
                peak_max: Some(1.0),
                role: String::new(),
                name: String::new(),
            }],
            stats: vec![Stat {
                ch: 1,
                vmin: Some(-1.0),
                vmax: Some(1.0),
                vpp: Some(2.0),
                mean: Some(0.0),
                rms: Some(0.5),
                freq: None,
                duty: None,
                n: 1000,
                window_s: 0.001_666,
                aliased: false,
            }],
            trigger: json!({"mode": "free"}),
            columns_b64: columns.to_string(),
            columns_bytes: columns.len() * 3 / 4,
        }
    }

    fn read_json_lines(session: &Path) -> Vec<Value> {
        let text = fs::read_to_string(session.join("scope").join("frames.jsonl")).unwrap();
        text.lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect()
    }

    #[test]
    fn config_defaults_match_contract() {
        let cfg = ScopeConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.url, DEFAULT_URL);
        assert_eq!(cfg.interval_ms, 50);
        assert_eq!(cfg.width, 500);
        assert_eq!(cfg.max_mb, 512);
    }

    #[test]
    fn config_sanitized_bounds() {
        let cfg = ScopeConfig {
            enabled: true,
            url: "   http://10.0.0.5:7411/   ".to_string(),
            interval_ms: 1,
            width: 10,
            max_mb: 999_999,
            profile: "bench-gpt".to_string(),
        }
        .sanitized();
        assert_eq!(cfg.url, "http://10.0.0.5:7411");
        assert_eq!(cfg.interval_ms, 20);
        assert_eq!(cfg.width, 200);
        assert_eq!(cfg.max_mb, 65_536);
        assert!(cfg.enabled, "sanitized не должен трогать enabled");

        // Пустой адрес — это «по умолчанию», а не пустая строка.
        let cfg = ScopeConfig {
            url: "   ".to_string(),
            interval_ms: 9_999,
            width: 9_999,
            max_mb: 0,
            ..ScopeConfig::default()
        }
        .sanitized();
        assert_eq!(cfg.url, DEFAULT_URL);
        assert_eq!(cfg.interval_ms, 1_000);
        assert_eq!(cfg.width, 2_000);
        assert_eq!(cfg.max_mb, 0, "0 = без предела, его нельзя поднимать");

        // Границы не «переворачиваются»: значения на краях остаются как есть.
        let cfg = ScopeConfig {
            interval_ms: 20,
            width: 2_000,
            ..ScopeConfig::default()
        }
        .sanitized();
        assert_eq!(cfg.interval_ms, 20);
        assert_eq!(cfg.width, 2_000);

        // Адрес без пути не должен схлопнуться в "http:" при срезании '/'.
        assert_eq!(
            ScopeConfig {
                url: "http://".to_string(),
                ..ScopeConfig::default()
            }
            .sanitized()
            .url,
            "http://"
        );
    }

    #[test]
    fn config_load_save_merges_prefs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        // Нет файла — значения по умолчанию, без паники.
        assert_eq!(load_config(root), ScopeConfig::default());

        fs::write(root.join("prefs.json"), br#"{"lang":"ru","zoom":1.5}"#).unwrap();
        let wanted = ScopeConfig {
            enabled: true,
            url: "http://127.0.0.1:7411/".to_string(),
            interval_ms: 5_000,
            width: 64,
            max_mb: 1,
            profile: "bench-gpt".to_string(),
        };
        let saved = save_config(root, &wanted).unwrap();
        assert_eq!(saved.interval_ms, 1_000);
        assert_eq!(saved.width, 200);
        assert_eq!(saved.url, "http://127.0.0.1:7411");
        assert!(saved.enabled);

        let raw = fs::read_to_string(root.join("prefs.json")).unwrap();
        let value: Value = serde_json::from_str(&raw).unwrap();
        // Чужие ключи обязаны выжить: за их счёт живёт выбор языка.
        assert_eq!(value["lang"], json!("ru"));
        assert_eq!(value["zoom"], json!(1.5));
        assert_eq!(value["scope"]["url"], json!("http://127.0.0.1:7411"));
        assert_eq!(value["scope"]["interval_ms"], json!(1_000));
        assert_eq!(value["scope"]["width"], json!(200));
        assert_eq!(value["scope"]["max_mb"], json!(1));
        assert_eq!(value["scope"]["enabled"], json!(true));
        // Файл записан «красиво» — его читают и люди.
        assert!(raw.contains('\n'), "prefs.json должен быть pretty: {raw}");

        assert_eq!(load_config(root), saved);

        // Битый файл и ключ неверного типа — это Default, а не ошибка.
        fs::write(root.join("prefs.json"), b"{not json").unwrap();
        assert_eq!(load_config(root), ScopeConfig::default());
        fs::write(root.join("prefs.json"), br#"{"scope":42}"#).unwrap();
        assert_eq!(load_config(root), ScopeConfig::default());
    }

    #[test]
    fn target_parsing_accepts_only_plain_http() {
        let target = parse_target("http://127.0.0.1:7411").unwrap();
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 7411);
        assert_eq!(target.path, "/");
        assert_eq!(target.host_header(), "127.0.0.1:7411");

        let target = parse_target("http://scope.local/api/capture/v2?width=500").unwrap();
        assert_eq!(target.host, "scope.local");
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/api/capture/v2?width=500");
        assert_eq!(target.host_header(), "scope.local");

        let target = parse_target("http://[::1]:7411/api/info").unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 7411);
        assert_eq!(target.path, "/api/info");

        for bad in [
            "https://127.0.0.1:7411",
            "ftp://127.0.0.1",
            "http://",
            "http://host:abc",
            "127.0.0.1:7411",
            "http://user:pass@host/",
        ] {
            assert!(
                parse_target(bad).is_err(),
                "адрес {bad:?} должен отвергаться"
            );
        }
    }

    #[test]
    fn response_parsing_content_length() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: application/json\r\n\r\nhello";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello".to_vec());

        // Заголовки без учёта регистра, тело — ровно по длине.
        let raw = b"HTTP/1.1 404 Not Found\r\nCONTENT-LENGTH: 2\r\n\r\n{}tail";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 404);
        assert_eq!(body, b"{}".to_vec());

        // Нет Content-Length — читаем до закрытия соединения.
        let raw = b"HTTP/1.0 200 OK\r\n\r\ntrailing";
        assert_eq!(parse_response(raw).unwrap().1, b"trailing".to_vec());

        // Обрыв тела — ошибка, а не «частично валидный» кадр.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        assert!(parse_response(raw).unwrap_err().contains("оборван"));

        assert!(parse_response(b"").is_err());
        assert!(parse_response(b"NOT HTTP\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx").is_ok());
    }

    #[test]
    fn response_parsing_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello world".to_vec());

        // Расширения чанков и трейлеры — не данные, но и не повод падать.
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n4;part=1\r\nabcd\r\n3\r\nefg\r\n0\r\nX-Trailer: y\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().1, b"abcdefg".to_vec());

        // Верхний регистр hex в размере.
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n";
        assert_eq!(parse_response(raw).unwrap().1, b"0123456789".to_vec());

        // Обрыв чанка — ошибка.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
        assert!(parse_response(raw).is_err());
    }

    #[test]
    fn base64_decoder_handles_padding_and_garbage() {
        assert_eq!(b64_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(b64_decode("TWFu").unwrap(), b"Man".to_vec());
        assert_eq!(b64_decode("TWE=").unwrap(), b"Ma".to_vec());
        assert_eq!(b64_decode("TQ==").unwrap(), b"M".to_vec());
        // Переводы строк — обычное дело в JSON-строках больших буферов.
        assert_eq!(b64_decode("TW\r\nFu").unwrap(), b"Man".to_vec());
        assert!(b64_decode("TW$u").is_err());
        assert!(b64_decode("TQ==TQ==").is_err());
    }

    #[test]
    fn frame_parsing_tolerates_nulls_and_zeros() {
        let text = r#"{"format":"dav2","frame_id":7,"sample_rate":600000.0,
            "channels":[0,3],
            "channel_meta":[{"ch":0,"full_scale_v":20.0,"peak_min":-0.5,"peak_max":0.5},{"ch":3,"full_scale_v":6.0}],
            "stats":[{"ch":0,"vpp":null,"freq":null,"duty":null,"n":1000},{"ch":3,"vpp":0.5}],
            "trigger":null}"#;
        let frame = parse_frame_text(text).unwrap();
        assert_eq!(frame.frame_id, 7);
        // channels в API 0-based, в структуре — 1-based.
        assert_eq!(frame.channels, vec![1, 4]);
        assert_eq!(frame.channel_meta[1].ch, 4);
        assert_eq!(frame.channel_meta[1].raw_ch, 3);
        assert_eq!(frame.channel_meta[0].range, "±20 V");
        assert_eq!(frame.channel_meta[1].range, "±6 V");
        assert!(frame.stats[0].vpp.is_none());
        assert!(frame.stats[0].freq.is_none());
        assert_eq!(frame.stats[1].vpp, Some(0.5));
        assert!(frame.trigger.is_null());
        assert_eq!(frame.columns_b64, "");
        assert_eq!(frame.columns_bytes, 0);
        // Пики без stats.vpp: pp считается из peak_min/peak_max.
        assert_eq!(frame.channel_meta[0].pp, Some(1.0));

        assert!(parse_frame_text(r#"{"format":"dav1","frame_id":1}"#).is_err());
        assert!(parse_frame_text(r#"{"format":"dav2"}"#).is_err());
        assert!(parse_frame_text("не json").is_err());

        // Порядок каналов сохраняется: столбцы в columns_b64 уложены в этом же
        // порядке, сортировка сломала бы соответствие данных подписям.
        let frame = parse_frame_text(r#"{"format":"dav2","frame_id":9,"channels":[2,0]}"#).unwrap();
        assert_eq!(frame.channels, vec![3, 1]);
    }

    #[test]
    fn channels_without_index_field_fall_back_to_position() {
        // Поля `ch` может не быть (другая сборка службы) — тогда нумерация
        // берётся по позиции массива, иначе CH1 пропал бы из списка.
        let value = json!([{"enabled": true, "range_v": 5.0}, {"enabled": false, "range_v": 20.0}]);
        let list = parse_channels_value(&value).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].ch, list[0].raw_ch), (1, 0));
        assert_eq!((list[1].ch, list[1].raw_ch), (2, 1));
        assert_eq!(list[0].range, "±5 V", "подпись строится из полной шкалы");
        assert!(!list[1].enabled);
    }

    #[test]
    fn frame_sanity_detects_truncated_columns() {
        // 8 байт = два канала по 4 (i16 lo + i16 hi на столбец).
        let mut frame = frame_with(1, "AAAAAAAAAAA=");
        frame.columns_bytes = 8;
        assert!(frame_sanity(&frame).is_ok());
        frame.columns_bytes = 99;
        assert!(frame_sanity(&frame).is_err());
        // Длина не кратна четырём байтам на канал — кадр неполный.
        frame.columns_bytes = 7;
        assert!(frame_sanity(&frame).is_err());
        // Пустой кадр (все каналы выключены) — не битый.
        let empty = Frame::default();
        assert!(frame_sanity(&empty).is_ok());
    }

    #[test]
    fn recorded_degraded_line_reads_back_as_frame() {
        // Деградированная строка пишет columns_b64=null; чтение записи обратно
        // во Frame не должно падать, иначе разбор сессии ломается ровно на
        // пределе max_mb.
        let line = json!({
            "format": FRAME_FORMAT,
            "t": 1.0,
            "wall": "2026-01-01T00:00:01.000Z",
            "frame_id": 5,
            "generation": 0,
            "dt_s": 1e-6,
            "sample_rate": 600000.0,
            "n_block": 1000,
            "window_s": 0.001,
            "start_sample": 0.0,
            "state": "free",
            "held": false,
            "width": 500,
            "channels": [1],
            "channel_meta": [],
            "stats": [],
            "trigger": null,
            "columns_b64": null,
            "columns_bytes": 0,
            "degraded": true,
        });
        let frame: Frame = serde_json::from_value(line).unwrap();
        assert_eq!(frame.frame_id, 5);
        assert_eq!(frame.channels, vec![1]);
        assert!(frame.columns_b64.is_empty());
        assert_eq!(frame.columns_bytes, 0);
    }

    #[test]
    fn recorder_first_frame_dedup_and_gap() {
        let dir = tempfile::tempdir().unwrap();
        // max_mb=0 — без предела: тест не должен упираться в лимит.
        let cfg = ScopeConfig {
            enabled: true,
            max_mb: 0,
            ..ScopeConfig::default()
        };
        let mut rec = Recorder::open(dir.path(), &cfg, "sess-1").unwrap();

        let result = rec.accept(1.0, "2026-01-01T00:00:00.000Z", &frame_with(100, "AAAA"));
        match result {
            Accept::Frame {
                gap_blocks,
                line_bytes,
            } => {
                assert_eq!(gap_blocks, 0);
                assert!(line_bytes > 0);
            }
            other => panic!("первый кадр должен записаться, получили {other:?}"),
        }
        let lines = read_json_lines(dir.path());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["format"], json!(FRAME_FORMAT));
        assert_eq!(lines[0]["frame_id"], json!(100));
        assert_eq!(lines[0]["first"], json!(true));
        assert_eq!(lines[0]["width"], json!(500));
        assert_eq!(lines[0]["channels"], json!([1, 2]));
        assert_eq!(lines[0]["columns_bytes"], json!(3));
        // gap_blocks=0 и degraded=false не пишутся вовсе.
        assert!(lines[0].get("gap_blocks").is_none());
        assert!(lines[0].get("degraded").is_none());

        // Тот же frame_id — строку не пишем, но повтор считаем.
        let counters_before = rec.counters();
        assert_eq!(
            rec.accept(1.05, "2026-01-01T00:00:00.050Z", &frame_with(100, "AAAA")),
            Accept::Duplicate { repeats: 1 }
        );
        assert_eq!(rec.counters().lines, counters_before.lines);
        assert_eq!(rec.counters().bytes, counters_before.bytes);
        assert_eq!(read_json_lines(dir.path()).len(), 1);
        assert_eq!(
            rec.accept(1.10, "2026-01-01T00:00:00.100Z", &frame_with(100, "AAAA")),
            Accept::Duplicate { repeats: 2 }
        );

        // Разрыв: 100 → 105, значит потеряны 101..104.
        match rec.accept(1.2, "2026-01-01T00:00:00.200Z", &frame_with(105, "BBBB")) {
            Accept::Frame { gap_blocks, .. } => assert_eq!(gap_blocks, 4),
            other => panic!("кадр с разрывом должен записаться, получили {other:?}"),
        }
        let counters = rec.counters();
        assert_eq!(counters.frames, 2);
        assert_eq!(counters.lines, 2);
        assert_eq!(counters.gaps, 1);
        assert_eq!(counters.gap_blocks, 4);
        assert_eq!(counters.last_frame_id, Some(105));
        assert_eq!(counters.t_first, Some(1.0));
        assert_eq!(counters.t_last, Some(1.2));
        let lines = read_json_lines(dir.path());
        assert_eq!(lines[1]["gap_blocks"], json!(4));
        assert!(
            lines[1].get("first").is_none(),
            "first только у первого кадра"
        );

        // Перезапуск службы: нумерация пошла с меньшего значения — строка
        // пишется с "restart":true, но это не разрыв.
        match rec.accept(2.0, "2026-01-01T00:00:02.000Z", &frame_with(3, "CCCC")) {
            Accept::Frame { gap_blocks, .. } => assert_eq!(gap_blocks, 0),
            other => panic!("перезапуск должен записаться, получили {other:?}"),
        }
        let counters = rec.counters();
        assert_eq!(counters.gaps, 1);
        assert_eq!(counters.gap_blocks, 4);
        let lines = read_json_lines(dir.path());
        assert_eq!(lines[2]["restart"], json!(true));
        // После перезапуска дедуп сброшен: тот же id снова считается дублем.
        assert_eq!(
            rec.accept(2.1, "2026-01-01T00:00:02.100Z", &frame_with(3, "CCCC")),
            Accept::Duplicate { repeats: 1 }
        );
    }

    #[test]
    fn recorder_degrades_then_caps() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ScopeConfig {
            enabled: true,
            max_mb: 1,
            ..ScopeConfig::default()
        };
        let mut rec = Recorder::open(dir.path(), &cfg, "sess-limit").unwrap();
        // ~1.2 МБ base64: уже первый кадр переводит запись за порог в 1 МиБ.
        let big = "A".repeat(1_600_000);
        match rec.accept(1.0, "2026-01-01T00:00:01.000Z", &frame_with(1, &big)) {
            Accept::Frame { line_bytes, .. } => assert!(line_bytes > 1_000_000),
            other => panic!("первый кадр пишется целиком, получили {other:?}"),
        }
        assert!(rec.counters().bytes >= 1024 * 1024);

        // Следующий кадр — деградированный: статистика есть, отсчётов нет.
        let bytes_before = rec.counters().bytes;
        match rec.accept(1.1, "2026-01-01T00:00:01.100Z", &frame_with(2, &big)) {
            Accept::Degraded { gap_blocks } => assert_eq!(gap_blocks, 0),
            other => panic!("ожидали Degraded, получили {other:?}"),
        }
        assert!(rec.counters().degraded);
        // Деградированная строка маленькая — иначе лимит не имел бы смысла.
        let grown = rec.counters().bytes - bytes_before;
        assert!(
            grown < 4 * 1024,
            "деградированная строка должна быть ~1 КБ, а выросла на {grown}"
        );
        let lines = read_json_lines(dir.path());
        assert_eq!(lines.len(), 2);
        assert!(lines[1]["columns_b64"].is_null());
        assert_eq!(lines[1]["columns_bytes"], json!(0));
        assert_eq!(lines[1]["degraded"], json!(true));

        // Доводим счётчик до предела статистики так, как это случилось бы на
        // живой сессии (после деградации байты растут медленно, поэтому порог
        // в тесте выставляем напрямую — поле приватное, тест в том же модуле).
        rec.bytes = 1024 * 1024 + CAP_EXTRA_BYTES + 1;
        let before = rec.counters();
        assert_eq!(
            rec.accept(1.2, "2026-01-01T00:00:01.200Z", &frame_with(3, &big)),
            Accept::Capped
        );
        let after = rec.counters();
        assert_eq!(after.lines, before.lines, "Capped не пишет строку");
        assert_eq!(after.frames, before.frames);
        assert_eq!(after.last_frame_id, before.last_frame_id);
        assert_eq!(read_json_lines(dir.path()).len(), 2);
    }

    #[test]
    fn recorder_writes_meta_and_summary() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = ScopeConfig {
            enabled: true,
            url: "http://127.0.0.1:7411".to_string(),
            interval_ms: 50,
            width: 500,
            max_mb: 512,
            profile: "bench-gpt".to_string(),
        };
        let mut rec = Recorder::open(dir.path(), &cfg, "sess-42").unwrap();
        rec.accept(1.0, "2026-01-01T00:00:01.000Z", &frame_with(1, "AAAA"));
        rec.accept(2.0, "2026-01-01T00:00:02.000Z", &frame_with(2, "BBBB"));
        let counters = rec.finish(9.5);
        assert_eq!(counters.frames, 2);
        assert_eq!(counters.t_last, Some(2.0));

        let meta_raw = fs::read_to_string(dir.path().join("scope").join("meta.json")).unwrap();
        let meta: Value = serde_json::from_str(&meta_raw).unwrap();
        assert_eq!(meta["format"], json!(META_FORMAT));
        assert_eq!(meta["session_id"], json!("sess-42"));
        assert_eq!(meta["url"], json!("http://127.0.0.1:7411"));
        assert_eq!(meta["interval_ms"], json!(50));
        assert_eq!(meta["width"], json!(500));
        assert_eq!(meta["max_mb"], json!(512));
        assert_eq!(meta["contract"], json!(CONTRACT));
        assert_eq!(meta["engine_version"], json!(env!("CARGO_PKG_VERSION")));
        let started = meta["started_at"].as_str().unwrap();
        assert!(
            started.ends_with('Z'),
            "started_at должен быть UTC: {started}"
        );

        let summary_raw =
            fs::read_to_string(dir.path().join("scope").join("summary.json")).unwrap();
        let summary: Value = serde_json::from_str(&summary_raw).unwrap();
        assert_eq!(summary["format"], json!(SUMMARY_FORMAT));
        assert_eq!(summary["frames"], json!(2));
        assert_eq!(summary["lines"], json!(2));
        assert_eq!(summary["gaps"], json!(0));
        assert_eq!(summary["gap_blocks"], json!(0));
        assert_eq!(summary["degraded"], json!(false));
        assert_eq!(summary["last_frame_id"], json!(2));
        assert_eq!(summary["t_first"], json!(1.0));
        assert_eq!(summary["t_last"], json!(2.0));
        assert_eq!(summary["t_stop"], json!(9.5));
        // Покрытие: два окна по 1.666 мс, интервал публикаций 1 с. Без этих
        // полей «2 кадра» читались бы как записанные 9.5 с сигнала.
        assert!((summary["signal_s"].as_f64().unwrap() - 0.003_332).abs() < 1e-9);
        assert!((summary["window_ms"].as_f64().unwrap() - 1.666).abs() < 1e-6);
        assert!((summary["interval_p50_ms"].as_f64().unwrap() - 1000.0).abs() < 1e-6);
        assert!((summary["interval_p95_ms"].as_f64().unwrap() - 1000.0).abs() < 1e-6);
        assert!((summary["interval_max_ms"].as_f64().unwrap() - 1000.0).abs() < 1e-6);
        assert!((counters.window_s_sum - 0.003_332).abs() < 1e-9);
        assert_eq!(counters.window_count, 2);
        let stopped = summary["stopped_at"].as_str().unwrap();
        assert!(stopped.ends_with('Z'));
        // bytes в сводке — это реальный размер frames.jsonl.
        let file_len = fs::metadata(dir.path().join("scope").join("frames.jsonl"))
            .unwrap()
            .len();
        assert_eq!(summary["bytes"], json!(file_len));
        assert_eq!(counters.bytes, file_len);
        assert!(summary["notes"].is_array());
    }

    #[test]
    fn recorder_keeps_all_eight_channels() {
        // Стенд с тремя щупами не доказывает, что восемь каналов не потеряются:
        // проверяем запись кадра со всеми CH1..CH8 и паспорт каналов.
        let dir = tempfile::tempdir().unwrap();
        let cfg = ScopeConfig {
            enabled: true,
            width: 500,
            ..ScopeConfig::default()
        };
        let mut rec = Recorder::open(dir.path(), &cfg, "sess-8").unwrap();
        let mut frame = frame_with(1, "AAAA");
        frame.channels = (1..=8).collect();
        frame.channel_meta = (1..=8)
            .map(|ch| ChannelInfo {
                ch,
                raw_ch: ch - 1,
                enabled: true,
                range: if ch <= 2 { "±6 V" } else { "±20 V" }.to_string(),
                range_id: if ch <= 2 { 3 } else { 7 },
                full_scale_v: if ch <= 2 { 6.0 } else { 20.0 },
                center_v: 0.0,
                min: Some(-0.1),
                max: Some(0.1),
                pp: Some(0.2),
                freq: None,
                duty: None,
                aliased: false,
                saturated: false,
                dropouts: 0,
                peak_min: Some(-0.2),
                peak_max: Some(0.2),
                role: String::new(),
                name: String::new(),
            })
            .collect();
        frame.stats = Vec::new();
        assert!(matches!(rec.accept(1.0, "2026-01-01T00:00:01.000Z", &frame), Accept::Frame { .. }));
        rec.finish(2.0);

        let raw = fs::read_to_string(dir.path().join("scope").join("frames.jsonl")).unwrap();
        let line: Value = serde_json::from_str(raw.lines().next().unwrap()).unwrap();
        assert_eq!(line["channels"].as_array().unwrap().len(), 8);
        assert_eq!(line["channel_meta"].as_array().unwrap().len(), 8);
        assert_eq!(line["channel_meta"][7]["ch"], json!(8));
        assert_eq!(line["channel_meta"][7]["range"], json!("±20 V"));
    }

    #[test]
    fn status_shell_reflects_enabled_flag() {
        let off = status_shell(&ScopeConfig::default());
        assert!(!off.enabled);
        assert_eq!(off.state, "off");
        assert_eq!(off.url, DEFAULT_URL);
        assert!(off.updated_at.ends_with('Z'));

        let cfg = ScopeConfig {
            enabled: true,
            ..ScopeConfig::default()
        };
        let connecting = status_shell(&cfg);
        assert!(connecting.enabled);
        assert_eq!(connecting.state, "connecting");
        assert_eq!(connecting.width, 500);
        assert_eq!(connecting.frames, 0);
    }
}
