//! Операции: клик пользователя → вызовы J2534 → сигналы стенда → итог.
//!
//! Раньше в отчёте были отдельно «действия пользователя», «отрезки обмена» и
//! «кадры осциллографа», и связать их можно было только глазами по колонке `t`.
//! Модуль сводит подтверждённые действия, обмен, вызовы драйвера, сигналы и
//! авторизацию в одну карточку с устойчивым `operation_id`.
//!
//! Три правила, которые нельзя нарушать:
//!
//! 1. **Фокус — не нажатие.** Операцию открывает только подтверждённый клик
//!    (`activation=invoke|click`, `confirmed=true`); `focus` остаётся уликой.
//! 2. **Границы, выведенные из обмена, — предположительные.** Если операция
//!    начата не кликом (внешняя программа без UIA), это явно помечено
//!    `origin=derived`, а не выдано за подтверждённое действие.
//! 3. **Порядок сигнала и клика честный.** Фронт сигнала известен только как
//!    интервал между двумя кадрами, а время клика — момент регистрации, не
//!    физическое нажатие. Если разница меньше допуска, `order=ambiguous`.
//!
//! Содержимое авторизационных сообщений в `operations.json` не хранится:
//! только длины, тайминги и хеш. Полные пары seed→key — отдельный
//! `seedkeys.jsonl` (docs/16).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::decode::{self, BusSegment};
use crate::models::{Event, EventKind, SessionMeta};
use crate::signals::{ScopeAnalysis, SignalEvent};
use crate::textfix;

pub const OPERATIONS_FORMAT: &str = "operations/1";
pub const OPERATIONS_FILE: &str = "operations.json";
pub const SEEDKEYS_FILE: &str = "seedkeys.jsonl";

/// Допуск неразличимости порядка «клик ↔ фронт сигнала», с.
///
/// Время клика — момент регистрации через UI Automation (опрос мыши 25 мс плюс
/// чтение свойств элемента), физическое нажатие раньше на неизмеренную величину.
/// Внутри 200 мс утверждать порядок нельзя; это сказано в отчёте, а не спрятано.
pub const CLICK_ORDER_TOL_S: f64 = 0.2;

/// Пауза, которая делит обмен на участки внутри одной операции (как в отчёте).
const SEGMENT_GAP_S: f64 = 1.0;

pub const ACTION_IDENTIFY: &str = "identify";
pub const ACTION_READ: &str = "read";
pub const ACTION_WRITE: &str = "write";
pub const ACTION_ERASE: &str = "erase";
pub const ACTION_VERIFY: &str = "verify";
pub const ACTION_ERRORS: &str = "errors";
pub const ACTION_RESET: &str = "reset";

fn is_primary(action: &str) -> bool {
    matches!(
        action,
        ACTION_IDENTIFY
            | ACTION_READ
            | ACTION_WRITE
            | ACTION_ERASE
            | ACTION_VERIFY
            | ACTION_ERRORS
            | ACTION_RESET
    )
}

pub fn action_label(action: &str) -> &'static str {
    match action {
        ACTION_IDENTIFY => "Идентификация",
        ACTION_READ => "Чтение",
        ACTION_WRITE => "Запись",
        ACTION_ERASE => "Стирание",
        ACTION_VERIFY => "Проверка",
        ACTION_ERRORS => "Ошибки",
        ACTION_RESET => "Сброс",
        "save" => "Сохранение",
        "open" => "Открытие файла",
        "confirm" => "Подтверждение",
        _ => "Действие",
    }
}

// ─────────────────────────────── типы ─────────────────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SegmentSlice {
    pub idx: u32,
    pub t0: f64,
    pub t1: f64,
    /// Пауза перед участком внутри операции, с.
    pub gap_before: f64,
    pub tx: u64,
    pub rx: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Сервисы запросов: `0x80×49, 0x27×3`.
    pub services: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallSummary {
    /// Вызовы `PassThruWriteMsgs` (outer-слой).
    pub write_calls: u64,
    /// Вызовы `PassThruReadMsgs`, вернувшие сообщение.
    pub read_calls: u64,
    pub ok: u64,
    /// Опросы без сообщения: rc=16 (ERR_TIMEOUT), n_out=0. Это не ошибка драйвера.
    pub empty_polls: u64,
    /// rc вне {0, 16} — ошибка драйвера/адаптера.
    pub driver_errors: u64,
    /// Гистограмма rc: `0x10` → 4.
    pub rc_values: BTreeMap<String, u64>,
    pub channels: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_call_t: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_call_t: Option<f64>,
    /// Запрошено сообщений (`n_in`) и фактически возвращено (`n_out`).
    pub requested: u64,
    pub returned: u64,
    pub tx_msgs: u64,
    pub rx_msgs: u64,
    /// RX-события без данных: подтверждение чтения (`rxs=0x2`), не ответ ЭБУ.
    /// В журнале их столько же, сколько TX, поэтому «RX в events.jsonl» вдвое
    /// больше числа ответов — это объяснено в отчёте.
    pub rx_empty: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallRecord {
    pub op: String,
    pub call: u64,
    pub t0: f64,
    pub t1: f64,
    pub dur_ms: f64,
    pub rc: i32,
    pub channel: String,
    pub n_in: u64,
    pub n_out: u64,
    /// `ok` | `empty` | `timeout` | `error`.
    pub outcome: String,
    pub seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthStage {
    /// `seed_request` | `seed` | `key` | `access_ok` | `denied` | `timeout`.
    pub kind: String,
    pub t: f64,
    pub seq: u64,
    pub service: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sub: String,
    pub len: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nrc: Option<u8>,
    /// Первые 8 hex SHA-256 значения: сверить событие, не раскрывая содержимое.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value_hash: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedPair {
    pub seed_t: f64,
    pub seed_seq: u64,
    pub seed_len: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_t: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_seq: Option<u64>,
    #[serde(default)]
    pub key_len: u32,
    /// `Some(true)` — 67 80 после ключа; `Some(false)` — 7F 27; `None` — ответа нет.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_seq: Option<u64>,
}

/// Полная пара для отдельного файла `seedkeys.jsonl` (содержимое — чувствительное).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeedPairFull {
    pub seed: String,
    pub key: String,
    pub seed_seq: u64,
    pub key_seq: u64,
    pub seed_t: f64,
    pub key_t: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Milestone {
    pub t: f64,
    /// `click` | `dialog` | `signal` | `tx` | `rx` | `auth` | `call` | `file` | `disconnect`.
    pub kind: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// `confirmed` | `derived` | `bracket` | `heuristic`.
    pub confidence: String,
    /// Источник часов: `uia` — регистрация UI Automation; `bridge` — строка
    /// моста (`meta.t_line`, часы источника); `scope-delivery` — приём кадра
    /// логгером (`time_source=delivery`); `session` — шкала сессии.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t_source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignalNote {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t_before: Option<f64>,
    pub t_after: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width_ms: Option<f64>,
    pub text: String,
    /// `before` | `after` | `ambiguous` | `unknown` — относительно ближайшего клика.
    pub order: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_ms: Option<f64>,
    /// К какому клику считали порядок: `старт` или имя диалога.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub anchor: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OperationResult {
    /// `answer` | `denied` | `timeout` | `driver_error` | `unknown` | `no_exchange`.
    pub status: String,
    pub text: String,
    pub requests: u64,
    pub answers: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_request_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_answer_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nrc: Option<u8>,
}

/// Сверка «входной образ записи ↔ контрольное чтение после записи».
///
/// Появляется только у операции `write`, если после неё в сессии есть `read`
/// и оба файла доступны. `unverified_bytes` — разница длин: она не проверена,
/// а не «совпала». `verdict`: `match` | `mismatch` | `partial`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyReport {
    pub expected_path: String,
    pub actual_path: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub compared_bytes: u64,
    pub different_bytes: u64,
    pub unverified_bytes: u64,
    pub verdict: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub id: String,
    pub idx: u32,
    pub action: String,
    /// «Идентификация», «Чтение», «Запись» или исходное имя действия.
    pub name: String,
    /// `confirmed` — открыта подтверждённым кликом; `derived` — границы из обмена.
    pub origin: String,
    pub start_confidence: String,
    pub end_confidence: String,
    pub t0: f64,
    pub t1: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click_t: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub click_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    pub segments: Vec<SegmentSlice>,
    pub calls: CallSummary,
    pub notable_calls: Vec<CallRecord>,
    pub auth: Vec<AuthStage>,
    /// `granted` | `denied` | `timeout` | `unknown` | `none`.
    pub auth_status: String,
    pub seeds: Vec<SeedPair>,
    pub dialogs: Vec<Milestone>,
    pub milestones: Vec<Milestone>,
    pub signals: Vec<SignalNote>,
    pub files: Vec<String>,
    /// Сверка с контрольным чтением (только для `write`, если чтение было).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify: Option<VerifyReport>,
    pub result: OperationResult,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationsDoc {
    pub format: String,
    pub session_id: String,
    pub generated_at: String,
    pub operations: Vec<Operation>,
    pub seed_pairs: u64,
    pub notes: Vec<String>,
}

impl OperationsDoc {
    pub fn empty(session_id: &str) -> Self {
        Self {
            format: OPERATIONS_FORMAT.into(),
            session_id: session_id.into(),
            generated_at: now_rfc3339(),
            operations: Vec::new(),
            seed_pairs: 0,
            notes: vec!["событий нет — операции не построены".into()],
        }
    }
}

// ─────────────────────────────── помощники ────────────────────────────────

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn is_outer(ev: &Event) -> bool {
    ev.meta.get("parent").is_none()
}

fn meta_str<'a>(ev: &'a Event, key: &str) -> Option<&'a str> {
    ev.meta.get(key).and_then(Value::as_str)
}

fn meta_u64(ev: &Event, key: &str) -> Option<u64> {
    ev.meta.get(key).and_then(Value::as_u64)
}

fn meta_i64(ev: &Event, key: &str) -> Option<i64> {
    ev.meta.get(key).and_then(Value::as_i64)
}

/// Тело сообщения без транспортного заголовка KWP2000/ISO-TP.
fn body(ev: &Event) -> Vec<u8> {
    let payload = ev.payload();
    if payload.is_empty() {
        return payload;
    }
    let proto = meta_str(ev, "protocol").unwrap_or("");
    let is_can = proto.contains("CAN") || proto.contains("ISO15765");
    if is_can {
        if payload[0] & 0xF0 == 0x00 && payload.len() >= 2 {
            return payload[1..].to_vec();
        }
        return payload;
    }
    // KWP: 00 <len> <service> ...; len — длина начиная с service.
    if payload.len() >= 3 && payload[0] == 0 && payload[1] as usize == payload.len() - 2 {
        return payload[2..].to_vec();
    }
    payload
}

fn svc_of(ev: &Event) -> Option<(u8, bool)> {
    if let Some(text) = meta_str(ev, "svc") {
        let v = u8::from_str_radix(text.trim_start_matches("0x"), 16).ok()?;
        let resp = meta_u64(ev, "svc_resp").map(|x| x != 0).unwrap_or(v & 0x40 != 0);
        return Some((v, resp));
    }
    let body = body(ev);
    let first = *body.first()?;
    Some((first, first & 0x40 != 0))
}

fn is_data(ev: &Event) -> bool {
    !ev.hex.is_empty() || ev.len > 0
}

fn value_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(&h.finalize()[..4])
}

fn nrc_name(nrc: u8) -> &'static str {
    match nrc {
        0x10 => "generalReject",
        0x11 => "serviceNotSupported",
        0x12 => "subFunctionNotSupported",
        0x13 => "incorrectMessageLength",
        0x22 => "conditionsNotCorrect",
        0x24 => "requestSequenceError",
        0x31 => "requestOutOfRange",
        0x33 => "invalidKey",
        0x35 => "invalidKey",
        0x36 => "exceedNumberOfAttempts",
        0x37 => "requiredTimeDelayNotExpired",
        _ => "код не расшифрован",
    }
}

fn action_of(ev: &Event) -> String {
    let stored = meta_str(ev, "action").unwrap_or("");
    if is_primary(stored) || matches!(stored, "save" | "open" | "confirm") {
        return stored.to_string();
    }
    let name = ev.text.as_deref().map(textfix::clean).unwrap_or_default();
    let by_name = crate::uiactions::classify(&name);
    if by_name != "other" {
        return by_name.to_string();
    }
    let lower = name.to_lowercase();
    if lower.contains("сохран") || lower.starts_with("save") {
        "save".into()
    } else if lower.contains("откр") || lower.starts_with("open") {
        "open".into()
    } else if matches!(lower.trim(), "да" | "yes" | "ок" | "ok" | "принять" | "apply") {
        "confirm".into()
    } else {
        "other".into()
    }
}

struct Click {
    t: f64,
    seq: u64,
    action: String,
    name: String,
    window: Option<String>,
    activation: String,
}

fn collect_clicks(events: &[&Event]) -> Vec<Click> {
    let mut out = Vec::new();
    for ev in events {
        if ev.kind != EventKind::UiAction {
            continue;
        }
        if !ev.meta.get("confirmed").and_then(Value::as_bool).unwrap_or(false) {
            continue;
        }
        let activation = meta_str(ev, "activation").unwrap_or("");
        if !matches!(activation, "click" | "invoke") {
            continue;
        }
        let name = ev.text.as_deref().map(textfix::clean).unwrap_or_default();
        out.push(Click {
            t: ev.t,
            seq: ev.seq,
            action: action_of(ev),
            name: if name.is_empty() {
                action_label(&action_of(ev)).to_string()
            } else {
                name
            },
            window: meta_str(ev, "window").map(textfix::clean),
            activation: activation.to_string(),
        });
    }
    out.sort_by(|a, b| a.t.partial_cmp(&b.t).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Куда отнести диалог: назад к текущей операции или вперёд к следующей.
fn attach_forward(dialog: &Click, next: Option<f64>) -> bool {
    match dialog.action.as_str() {
        // «Сохранить» — результат уже сделанного чтения.
        "save" => false,
        // «Да»/«ОК» подтверждают текущее окно, а не открывают следующую операцию.
        "confirm" => false,
        // «Открыть»/обзор файла — подготовка следующей операции.
        "open" => next.is_some(),
        _ => match next {
            Some(t) => t - dialog.t <= 60.0,
            None => false,
        },
    }
}

// ─────────────────────────────── построение ───────────────────────────────

/// Побайтная сверка входного образа записи с результатом контрольного чтения.
///
/// Сравниваются только доступные файлы не больше 64 МиБ. Разница длин попадает
/// в `unverified_bytes`, а не маскируется под совпадение.
fn compare_pair(expected: &str, actual: &str) -> Option<VerifyReport> {
    let ea = std::fs::read(expected).ok()?;
    let ab = std::fs::read(actual).ok()?;
    let compared = ea.len().min(ab.len());
    let different = ea
        .iter()
        .zip(ab.iter())
        .filter(|(a, b)| a != b)
        .count() as u64;
    let unverified = ea.len().abs_diff(ab.len()) as u64;
    let verdict = if different == 0 && unverified == 0 {
        "match"
    } else if different > 0 {
        "mismatch"
    } else {
        "partial"
    };
    Some(VerifyReport {
        expected_path: expected.to_string(),
        actual_path: actual.to_string(),
        expected_sha256: crate::models::util::sha256_hex(&ea),
        actual_sha256: crate::models::util::sha256_hex(&ab),
        compared_bytes: compared as u64,
        different_bytes: different,
        unverified_bytes: unverified,
        verdict: verdict.to_string(),
    })
}

/// Для каждой записи найти контрольное чтение после неё и сверить файлы.
///
/// Связка — по времени: чтение должно начаться после конца записи (допуск 1 с).
/// Если чтения в сессии нет, `verify` остаётся `None` — это честное «не проверено».
fn attach_verify(doc: &mut OperationsDoc) {
    let n = doc.operations.len();
    let mut plans: Vec<(usize, String, String)> = Vec::new();
    for i in 0..n {
        if doc.operations[i].action != ACTION_WRITE || doc.operations[i].files.is_empty() {
            continue;
        }
        let t1 = doc.operations[i].t1;
        let expected = doc.operations[i].files[0].clone();
        let actual = doc
            .operations
            .iter()
            .skip(i + 1)
            .find(|o| o.action == ACTION_READ && o.t0 >= t1 - 1.0 && !o.files.is_empty())
            .map(|o| o.files[0].clone());
        if let Some(actual) = actual {
            plans.push((i, expected, actual));
        }
    }
    for (i, expected, actual) in plans {
        doc.operations[i].verify = compare_pair(&expected, &actual);
    }
}

/// Собрать операции из событий, участков обмена и анализа сигналов.
pub fn build(events: &[Event], meta: &SessionMeta, analysis: &ScopeAnalysis) -> OperationsDoc {
    // Порядок — по времени, а не по seq: поздняя пачка моста несёт ранние `t`.
    let mut evs: Vec<&Event> = events.iter().collect();
    evs.sort_by(|a, b| {
        a.t.partial_cmp(&b.t)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.seq.cmp(&b.seq))
    });

    let mut doc = OperationsDoc {
        format: OPERATIONS_FORMAT.into(),
        session_id: meta.id.clone(),
        generated_at: now_rfc3339(),
        operations: Vec::new(),
        seed_pairs: 0,
        notes: Vec::new(),
    };

    let clicks = collect_clicks(&evs);
    let mut primaries: Vec<&Click> = clicks.iter().filter(|c| is_primary(&c.action)).collect();
    let mut dialogs: Vec<&Click> = clicks.iter().filter(|c| !is_primary(&c.action)).collect();

    // Сессия без подтверждённых действий: границы выводим из обмена и честно
    // помечаем их предположительными.
    if primaries.is_empty() {
        let segments = decode::bus_segments_refs(&evs, SEGMENT_GAP_S);
        for (i, seg) in segments.iter().enumerate() {
            doc.operations.push(derived_operation(i as u32 + 1, seg, &evs, analysis));
        }
        if doc.operations.is_empty() {
            doc.notes
                .push("ни подтверждённых действий, ни обмена — операций нет".into());
        } else {
            doc.notes.push(
                "подтверждённых действий нет: границы операций выведены из обмена — предположительно"
                    .into(),
            );
        }
        attach_verify(&mut doc);
        doc.seed_pairs = count_seed_pairs(&doc.operations);
        return doc;
    }

    primaries.sort_by(|a, b| a.t.partial_cmp(&b.t).unwrap_or(std::cmp::Ordering::Equal));

    // Привязка диалогов: правило по типу действия, затем близость по времени.
    let mut attached: Vec<Vec<Milestone>> = vec![Vec::new(); primaries.len()];
    for dialog in dialogs.drain(..) {
        let next_idx = primaries.iter().position(|p| p.t > dialog.t);
        let prev_idx = primaries
            .iter()
            .rposition(|p| p.t <= dialog.t);
        let forward = attach_forward(dialog, next_idx.map(|i| primaries[i].t));
        let target = if forward {
            next_idx
        } else {
            prev_idx.or(next_idx)
        };
        let Some(ti) = target else { continue };
        let p = primaries[ti];
        let confidence = if dialog.action == "open" || dialog.action == "save" {
            "heuristic"
        } else if (dialog.t - p.t).abs() <= 300.0 {
            "heuristic"
        } else {
            "derived"
        };
        attached[ti].push(Milestone {
            t: dialog.t,
            kind: "dialog".into(),
            label: dialog.name.clone(),
            seq: Some(dialog.seq),
            confidence: confidence.into(),
            t_source: "uia".into(),
            detail: format!(
                "{} · {}",
                action_label(&dialog.action),
                if dialog.t < p.t { "до старта" } else { "внутри операции" }
            ),
        });
    }

    // Внешние кадры обмена и весь контекст операции (sys/file/disconnect),
    // сгруппированные по стартовому клику.
    let starts: Vec<f64> = primaries.iter().map(|p| p.t).collect();
    let mut bucket: Vec<Vec<&Event>> = vec![Vec::new(); primaries.len()];
    let mut ctx_bucket: Vec<Vec<&Event>> = vec![Vec::new(); primaries.len()];
    for ev in &evs {
        let Some(idx) = last_start_before(&starts, ev.t) else {
            // Кадры до первого клика — та же попытка подключения: берём их в
            // первую операцию, только если они рядом по времени (не больше 60 с).
            if !starts.is_empty() && ev.t >= starts[0] - 60.0 {
                ctx_bucket[0].push(ev);
                if matches!(ev.kind, EventKind::Tx | EventKind::Rx) && is_outer(ev) {
                    bucket[0].push(ev);
                }
            }
            continue;
        };
        ctx_bucket[idx].push(ev);
        if matches!(ev.kind, EventKind::Tx | EventKind::Rx) && is_outer(ev) {
            bucket[idx].push(ev);
        }
    }

    // Участки обмена считаем по всем событиям сразу: они не зависят от привязки.
    let segments = decode::bus_segments_refs(&evs, SEGMENT_GAP_S);

    let mut global_pairs: Vec<SeedPairFull> = Vec::new();
    for (i, p) in primaries.iter().enumerate() {
        let assignment_end = primaries.get(i + 1).map(|n| n.t).unwrap_or(f64::INFINITY);
        let op_segments: Vec<&BusSegment> = segments
            .iter()
            .filter(|s| s.t1 >= p.t && s.t0 <= assignment_end)
            .collect();
        let op = build_operation(
            i as u32 + 1,
            p,
            &attached[i],
            &bucket[i],
            &ctx_bucket[i],
            &op_segments,
            analysis,
            assignment_end,
        );
        if !attached[i].is_empty() {
            doc.notes.push(format!(
                "{}: привязка диалогов к операции — эвристика по типу действия и времени",
                op.name
            ));
        }
        global_pairs.extend(seed_pairs_full(&op, &bucket[i]));
        doc.operations.push(op);
    }
    attach_verify(&mut doc);
    doc.seed_pairs = global_pairs.len() as u64;
    doc.notes.sort();
    doc.notes.dedup();
    doc
}

fn last_start_before(starts: &[f64], t: f64) -> Option<usize> {
    match starts.iter().rposition(|s| *s <= t) {
        Some(i) => Some(i),
        // Ранние кадры до первого клика не выбрасываем: они относятся к попытке
        // подключения перед первым действием и попадут в первую операцию.
        None => None,
    }
}

fn derived_operation(
    idx: u32,
    seg: &BusSegment,
    events: &[&Event],
    analysis: &ScopeAnalysis,
) -> Operation {
    let ctx_events: Vec<&Event> = events
        .iter()
        .copied()
        .filter(|e| e.t >= seg.t0 && e.t <= seg.t1)
        .collect();
    let op_events: Vec<&Event> = ctx_events
        .iter()
        .copied()
        .filter(|e| matches!(e.kind, EventKind::Tx | EventKind::Rx) && is_outer(e))
        .collect();
    let slices = vec![slice_of(seg)];
    let calls = call_summary(&op_events, &ctx_events, seg.t0, seg.t1);
    let (auth, auth_status, seeds) = auth_of(&op_events);
    let mut op = Operation {
        id: format!("op-{idx}-other"),
        idx,
        action: "other".into(),
        name: format!("Обмен {idx}"),
        origin: "derived".into(),
        start_confidence: "derived".into(),
        end_confidence: "derived".into(),
        t0: seg.t0,
        t1: seg.t1,
        click_t: None,
        click_seq: None,
        activation: None,
        window: None,
        segments: slices,
        calls,
        notable_calls: notable_calls(&op_events, &ctx_events, seg.t0, seg.t1),
        auth,
        auth_status,
        seeds,
        dialogs: Vec::new(),
        milestones: Vec::new(),
        signals: signals_for(None, &[], seg.t0, seg.t1, analysis),
        files: Vec::new(),
        verify: None,
        result: OperationResult::default(),
        notes: vec![
            "границы операции выведены из обмена, а не из действия программы — предположительно"
                .into(),
        ],
    };
    op.result = operation_result(&op_events);
    op.milestones = milestones_for(&op, &op_events, &ctx_events);
    op
}

fn slice_of(seg: &BusSegment) -> SegmentSlice {
    SegmentSlice {
        idx: seg.idx,
        t0: seg.t0,
        t1: seg.t1,
        gap_before: seg.gap_before,
        tx: seg.tx,
        rx: seg.rx,
        tx_bytes: seg.tx_bytes,
        rx_bytes: seg.rx_bytes,
        services: seg.services_text(),
    }
}

fn build_operation(
    idx: u32,
    primary: &Click,
    dialogs: &[Milestone],
    exchange: &[&Event],
    ctx: &[&Event],
    segments: &[&BusSegment],
    analysis: &ScopeAnalysis,
    assignment_end: f64,
) -> Operation {
    let tx: Vec<&Event> = exchange.iter().copied().filter(|e| e.kind == EventKind::Tx).collect();
    let rx: Vec<&Event> = exchange.iter().copied().filter(|e| e.kind == EventKind::Rx).collect();
    let exchange_t0 = tx.first().map(|e| e.t).or_else(|| rx.first().map(|e| e.t));
    let exchange_t1 = tx.last().map(|e| e.t).or_else(|| rx.last().map(|e| e.t));

    // Конец операции: последний кадр обмена, затем disconnect/close рядом с ним,
    // затем последний привязанный диалог (итоговое окно программы).
    let mut end = exchange_t1.unwrap_or(primary.t);
    let mut end_confidence = if exchange_t1.is_some() {
        "exchange_stop"
    } else {
        "derived"
    };
    for ev in ctx {
        if ev.kind == EventKind::Sys
            && (ev.api.contains("disconnect") || ev.api.contains("close"))
            && ev.t >= end
            && ev.t - end <= 10.0
        {
            end = ev.t;
            end_confidence = "disconnect";
        }
    }
    let last_dialog = dialogs
        .iter()
        .map(|d| d.t)
        .fold(None::<f64>, |acc, t| Some(acc.map_or(t, |x| x.max(t))));
    if let Some(last) = last_dialog {
        if last > end {
            end = last;
            end_confidence = "dialog";
        }
    }
    if end >= assignment_end {
        end = assignment_end.min(end);
    }

    let mut notes = Vec::new();
    if exchange_t0.is_none() {
        notes.push(
            "обмена после клика нет: операция видна только по действию пользователя".into(),
        );
    }
    let mut op = Operation {
        id: format!("op-{idx}-{}", primary.action),
        idx,
        action: primary.action.clone(),
        name: action_label(&primary.action).to_string(),
        origin: "confirmed".into(),
        start_confidence: "confirmed_click".into(),
        end_confidence: end_confidence.into(),
        t0: primary.t,
        t1: end,
        click_t: Some(primary.t),
        click_seq: Some(primary.seq),
        activation: Some(primary.activation.clone()),
        window: primary.window.clone(),
        segments: segments.iter().map(|s| slice_of(s)).collect(),
        calls: call_summary(exchange, ctx, primary.t, end),
        notable_calls: notable_calls(exchange, ctx, primary.t, end),
        auth: Vec::new(),
        auth_status: "none".into(),
        seeds: Vec::new(),
        dialogs: dialogs.to_vec(),
        milestones: Vec::new(),
        signals: signals_for(
            Some(primary),
            dialogs,
            primary.t,
            end,
            analysis,
        ),
        files: Vec::new(),
        verify: None,
        result: OperationResult::default(),
        notes,
    };
    // Участки: обрезаем по границам операции, чтобы карточка не показывала чужое.
    for seg in op.segments.iter_mut() {
        seg.t0 = seg.t0.max(primary.t);
        seg.t1 = seg.t1.min(end);
        if seg.t1 < seg.t0 {
            seg.t1 = seg.t0;
        }
    }
    let (auth, auth_status, seeds) = auth_of(exchange);
    op.auth = auth;
    op.auth_status = auth_status;
    op.seeds = seeds;
    op.result = operation_result(exchange);
    // Файлы операции: только те, что открыты на запись (`0x40000000`) или на
    // чтение как исходник (`0x-80000000`), плюс фактические записи. Перебор
    // каталога в диалоге даёт десятки `open access=0x80` — это не файлы
    // операции, и в карточку они не идут.
    let mut files = Vec::new();
    for ev in ctx.iter() {
        if ev.kind != EventKind::File {
            continue;
        }
        // Только окно самой операции (и 10 с подготовки перед стартом): файлы,
        // которые программа перебирала в диалоге следующей операции, — не её.
        if ev.t < primary.t - 10.0 || ev.t > end {
            continue;
        }
        let op = meta_str(ev, "op").unwrap_or("");
        let access = meta_str(ev, "access").unwrap_or("");
        let meaningful = op == "write" || access.contains("40000000") || access.contains("-80000000");
        if !meaningful {
            continue;
        }
        if let Some(path) = meta_str(ev, "path") {
            let path = textfix::clean(path);
            if !files.contains(&path) {
                files.push(path);
            }
        }
    }
    if files.len() > 12 {
        files.truncate(12);
    }
    op.files = files;
    op.milestones = milestones_for(&op, exchange, ctx);
    op
}

fn signals_for(
    primary: Option<&Click>,
    dialogs: &[Milestone],
    t0: f64,
    t1: f64,
    analysis: &ScopeAnalysis,
) -> Vec<SignalNote> {
    let mut out = Vec::new();
    for ev in analysis.events_between(t0 - 1.0, t1 + 1.0) {
        out.push(signal_note(ev, primary, dialogs));
    }
    out
}

fn signal_note(ev: &SignalEvent, primary: Option<&Click>, dialogs: &[Milestone]) -> SignalNote {
    let mut note = SignalNote {
        kind: ev.kind.clone(),
        name: ev.name.clone(),
        t_before: ev.t_before,
        t_after: ev.t_after,
        width_ms: ev.width_ms,
        text: ev.text.clone(),
        order: "unknown".into(),
        delta_ms: None,
        anchor: String::new(),
        note: String::new(),
    };
    let Some(primary) = primary else {
        note.note = "подтверждённого клика нет — порядок не с чем сравнивать".into();
        return note;
    };
    // Ближайший подтверждённый клик операции (старт или диалог): по нему и
    // считаем порядок. Если ближайший клик далеко (например, «Сохранить» через
    // 22 с после конца обмена), он не объясняет фронт — тогда якорем остаётся
    // старт операции, и это сказано словами.
    let lo = ev.t_before.unwrap_or(ev.t_after);
    let hi = ev.t_after;
    let mut best = (f64::INFINITY, primary.t, primary.name.clone(), true);
    for m in dialogs {
        if m.kind != "dialog" {
            continue;
        }
        let d = distance_to(m.t, lo, hi);
        if d < best.0 {
            best = (d, m.t, m.label.clone(), false);
        }
    }
    let d_start = distance_to(primary.t, lo, hi);
    if d_start < best.0 {
        best = (d_start, primary.t, primary.name.clone(), true);
    }
    // 5 с — порог «клик рядом и объясняет фронт». Дальше порядок внутри
    // операции всё равно известен, но привязывать его к далёкому диалогу нельзя.
    if best.0 > 5.0 && !best.3 {
        best = (d_start, primary.t, primary.name.clone(), true);
    }
    note.anchor = best.2.clone();
    let (dist, anchor_t) = (best.0, best.1);
    if dist <= CLICK_ORDER_TOL_S {
        note.order = "ambiguous".into();
        note.delta_ms = Some(dist * 1000.0);
        note.note = format!(
            "порядок с кликом «{}» неразличим: разница {} при допуске {:.0} мс; время клика — момент регистрации, точность не измерялась",
            note.anchor,
            fmt_delta_ms(dist * 1000.0),
            CLICK_ORDER_TOL_S * 1000.0
        );
    } else if anchor_t < lo {
        note.order = "after".into();
        note.delta_ms = Some((hi - anchor_t) * 1000.0);
        note.note = format!(
            "после клика «{}» на {} (фронт — в интервале {:.0} мс между кадрами)",
            note.anchor,
            fmt_delta_ms((hi - anchor_t) * 1000.0),
            ev.width_ms.unwrap_or(0.0)
        );
    } else {
        note.order = "before".into();
        note.delta_ms = Some((anchor_t - lo) * 1000.0);
        note.note = format!(
            "до клика «{}» на {}",
            note.anchor,
            fmt_delta_ms((anchor_t - lo) * 1000.0)
        );
    }
    note
}

fn fmt_delta_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2} с", ms / 1000.0)
    } else {
        format!("{ms:.0} мс")
    }
}

fn distance_to(t: f64, lo: f64, hi: f64) -> f64 {
    if t < lo {
        lo - t
    } else if t > hi {
        t - hi
    } else {
        0.0
    }
}

fn call_summary(exchange: &[&Event], all: &[&Event], t0: f64, t1: f64) -> CallSummary {
    let mut out = CallSummary::default();
    let mut channels: Vec<String> = Vec::new();
    for ev in all {
        let Some(channel) = meta_str(ev, "channel") else { continue };
        if !channels.iter().any(|c| c == channel) {
            channels.push(channel.to_string());
        }
    }
    out.channels = channels;
    for ev in exchange {
        match ev.kind {
            EventKind::Tx if is_data(ev) => {
                out.tx_msgs += 1;
                out.write_calls += u64::from(meta_u64(ev, "call").is_some());
                out.requested += meta_u64(ev, "n_in").unwrap_or(1);
                out.returned += meta_u64(ev, "n_out").unwrap_or(1);
                let rc = ev.rc.unwrap_or(0);
                count_rc(&mut out, rc);
                touch_call(&mut out, ev.t);
            }
            EventKind::Rx if is_data(ev) => {
                out.rx_msgs += 1;
                out.read_calls += u64::from(meta_u64(ev, "call").is_some());
                out.requested += meta_u64(ev, "n_in").unwrap_or(1);
                out.returned += meta_u64(ev, "n_out").unwrap_or(1);
                let rc = ev.rc.unwrap_or(0);
                count_rc(&mut out, rc);
                touch_call(&mut out, ev.t);
            }
            EventKind::Rx => {
                // Пустой RX — подтверждение чтения, а не ответ: считаем отдельно,
                // иначе «TX 54 / RX 108» читается как 54 лишних ответа.
                out.rx_empty += 1;
            }
            _ => {}
        }
    }
    // Холостые опросы и ошибки — по системным строкам драйвера (слой driver,
    // иначе один и тот же опрос пришёл бы из прокси и от драйвера дважды).
    for ev in all {
        if ev.t < t0 || ev.t > t1 {
            continue;
        }
        if ev.kind == EventKind::Sys && ev.api == "J2534 rx-empty" {
            // У сводки `rx-empty` поля `layer` может не быть вовсе; прокси-копию
            // отбрасываем по явному `layer=proxy`, иначе опрос посчитан дважды.
            if meta_str(ev, "layer") != Some("proxy") {
                let n = meta_u64(ev, "n").unwrap_or(1);
                out.empty_polls += n;
                out.requested += n;
                let rc = meta_i64(ev, "last_rc").unwrap_or(16) as i32;
                // `n` — сколько опросов свернула сводка: в гистограмму идёт
                // каждый, иначе 24 пустых опроса выглядели как 8.
                for _ in 0..n {
                    count_rc(&mut out, rc);
                }
            }
        }
        if ev.kind == EventKind::Sys && ev.api == "J2534 call" {
            if meta_str(ev, "layer") == Some("driver") {
                let rc = meta_i64(ev, "rc").unwrap_or(0) as i32;
                // rc=16 (ERR_TIMEOUT) уже посчитан сводкой `rx-empty` с учётом
                // `n`: второй раз в гистограмму его не добавляем.
                if rc != 0 && rc != 16 {
                    out.driver_errors += 1;
                    count_rc(&mut out, rc);
                }
            }
        }
    }
    out.ok = out.write_calls.saturating_sub(out.driver_errors);
    out
}

fn touch_call(out: &mut CallSummary, t: f64) {
    out.first_call_t = Some(out.first_call_t.map_or(t, |x| x.min(t)));
    out.last_call_t = Some(out.last_call_t.map_or(t, |x| x.max(t)));
}

fn count_rc(out: &mut CallSummary, rc: i32) {
    let key = format!("0x{rc:02X}");
    *out.rc_values.entry(key).or_insert(0) += 1;
}

fn notable_calls(exchange: &[&Event], ctx: &[&Event], t0: f64, t1: f64) -> Vec<CallRecord> {
    let mut out = Vec::new();
    for ev in exchange {
        if !is_data(ev) {
            continue;
        }
        let Some(call) = meta_u64(ev, "call") else { continue };
        let rc = ev.rc.unwrap_or(0);
        let n_in = meta_u64(ev, "n_in").unwrap_or(1);
        let n_out = meta_u64(ev, "n_out").unwrap_or(1);
        // В карточку — только то, что объясняет остановку: ненулевой rc или
        // несовпадение «запрошено/возвращено». Остальное остаётся в событиях.
        let interesting = rc != 0 || n_out != n_in;
        if !interesting {
            continue;
        }
        let dur_ms = meta_u64(ev, "dur").unwrap_or(0) as f64 / 1000.0;
        let op = meta_str(ev, "op")
            .unwrap_or(if ev.kind == EventKind::Tx {
                "WriteMsgs"
            } else {
                "ReadMsgs"
            })
            .to_string();
        let outcome = if rc == 0 {
            "ok"
        } else if rc == 16 && n_out == 0 {
            "empty"
        } else if rc == 16 {
            "timeout"
        } else {
            "error"
        };
        out.push(CallRecord {
            op,
            call,
            t0: ev.t - dur_ms / 1000.0,
            t1: ev.t,
            dur_ms,
            rc,
            channel: meta_str(ev, "channel").unwrap_or("").to_string(),
            n_in,
            n_out,
            outcome: outcome.into(),
            seq: ev.seq,
        });
        if out.len() >= 24 {
            break;
        }
    }
    // Отказы драйвера (rc вне {0, 16}) приходят системной строкой — её в
    // карточку тоже нужно, иначе причина остановки остаётся в raw.log.
    for ev in ctx {
        if ev.t < t0 || ev.t > t1 {
            continue;
        }
        if ev.kind != EventKind::Sys || ev.api != "J2534 call" {
            continue;
        }
        if meta_str(ev, "layer") != Some("driver") {
            continue;
        }
        let rc = meta_i64(ev, "rc").unwrap_or(0) as i32;
        if rc == 0 {
            continue;
        }
        let dur_ms = meta_u64(ev, "dur").unwrap_or(0) as f64 / 1000.0;
        let n_out = meta_u64(ev, "n_out").unwrap_or(0);
        out.push(CallRecord {
            op: meta_str(ev, "op").unwrap_or("ReadMsgs").to_string(),
            call: meta_u64(ev, "call").unwrap_or(0),
            t0: ev.t - dur_ms / 1000.0,
            t1: ev.t,
            dur_ms,
            rc,
            channel: meta_str(ev, "channel").unwrap_or("").to_string(),
            n_in: meta_u64(ev, "n_in").unwrap_or(0),
            n_out,
            outcome: (if rc == 16 && n_out == 0 {
                "empty"
            } else if rc == 16 {
                "timeout"
            } else {
                "error"
            })
            .to_string(),
            seq: ev.seq,
        });
        if out.len() >= 32 {
            break;
        }
    }
    // Плюс первая и последняя результативные записи с реальной длительностью
    // вызова: у карточки должны быть начало и конец обмена, даже если
    // отклонений не было.
    if let Some(first) = exchange.iter().find(|e| is_data(e)) {
        if let Some(rec) = call_record_of(first) {
            if !out.iter().any(|c| c.call == rec.call) {
                out.insert(0, rec);
            }
        }
    }
    if let Some(last) = exchange.iter().rev().find(|e| is_data(e)) {
        if let Some(rec) = call_record_of(last) {
            if !out.iter().any(|c| c.call == rec.call) {
                out.push(rec);
            }
        }
    }
    out.sort_by(|a, b| {
        a.t1
            .partial_cmp(&b.t1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

/// Одна запись о вызове J2534 по событию TX/RX.
fn call_record_of(ev: &Event) -> Option<CallRecord> {
    let call = meta_u64(ev, "call")?;
    let rc = ev.rc.unwrap_or(0);
    let n_in = meta_u64(ev, "n_in").unwrap_or(1);
    let n_out = meta_u64(ev, "n_out").unwrap_or(1);
    let dur_ms = meta_u64(ev, "dur").unwrap_or(0) as f64 / 1000.0;
    let op = meta_str(ev, "op")
        .unwrap_or(if ev.kind == EventKind::Tx {
            "WriteMsgs"
        } else {
            "ReadMsgs"
        })
        .to_string();
    let outcome = if rc == 0 {
        "ok"
    } else if rc == 16 && n_out == 0 {
        "empty"
    } else if rc == 16 {
        "timeout"
    } else {
        "error"
    };
    Some(CallRecord {
        op,
        call,
        t0: ev.t - dur_ms / 1000.0,
        t1: ev.t,
        dur_ms,
        rc,
        channel: meta_str(ev, "channel").unwrap_or("").to_string(),
        n_in,
        n_out,
        outcome: outcome.into(),
        seq: ev.seq,
    })
}

fn operation_result(exchange: &[&Event]) -> OperationResult {
    let mut result = OperationResult::default();
    let mut last_request: Option<&Event> = None;
    let mut last_answer: Option<&Event> = None;
    for ev in exchange {
        if !is_data(ev) {
            continue;
        }
        let Some((svc, resp)) = svc_of(ev) else { continue };
        if !resp {
            result.requests += 1;
            last_request = Some(ev);
        } else {
            result.answers += 1;
            last_answer = Some(ev);
            if svc == 0x7F {
                let body = body(ev);
                if body.len() >= 3 && body[1] == 0x27 {
                    result.nrc = Some(body[2]);
                }
            }
        }
    }
    result.last_request_seq = last_request.map(|e| e.seq);
    result.last_answer_seq = last_answer.map(|e| e.seq);
    if result.requests == 0 {
        result.status = "no_exchange".into();
        result.text = "обмена не было".into();
        return result;
    }
    let denied = exchange.iter().any(|ev| {
        if !is_data(ev) {
            return false;
        }
        let body = body(ev);
        body.len() >= 2 && body[0] == 0x7F && body[1] == 0x27
    });
    if denied {
        let nrc = result.nrc.unwrap_or(0);
        result.status = "denied".into();
        result.text = format!("ЭБУ отказал: 7F 27 {nrc:02X} ({})", nrc_name(nrc));
        return result;
    }
    // Последний запрос без ответа после него — тайм-аут, а не «успех».
    if let (Some(req), Some(ans)) = (last_request, last_answer) {
        if ans.t < req.t {
            result.status = "timeout".into();
            result.text = format!(
                "последний запрос (seq {}) без ответа — результат не установлен",
                req.seq
            );
            return result;
        }
    }
    if result.answers == 0 {
        result.status = "timeout".into();
        result.text = "запросы без ответов — результат не установлен".into();
        return result;
    }
    if result.answers < result.requests {
        result.status = "unknown".into();
        result.text = format!(
            "ответов {} из {} запросов — захват неполный, результат не установлен",
            result.answers, result.requests
        );
        return result;
    }
    result.status = "answer".into();
    result.text = format!(
        "ответ получен: {} запросов / {} ответов, отказов ЭБУ нет",
        result.requests, result.answers
    );
    result
}

/// Авторизация по порядку кадров: запрос seed → seed → ключ → 67 80/7F 27.
fn auth_of(exchange: &[&Event]) -> (Vec<AuthStage>, String, Vec<SeedPair>) {
    let mut stages = Vec::new();
    let mut pairs: Vec<SeedPair> = Vec::new();
    let mut current_seed: Option<(f64, u64, u32, String)> = None; // t, seq, len, hash
    let mut last_req: Option<(f64, u64, u32)> = None;
    let mut status = "none".to_string();
    for ev in exchange {
        if !is_data(ev) {
            continue;
        }
        let body = body(ev);
        if body.is_empty() {
            continue;
        }
        let t = ev.t;
        let seq = ev.seq;
        if ev.kind == EventKind::Tx {
            if body[0] == 0x27 && body.len() >= 2 {
                // KWP2000: 27 7F seed / 27 80 key. UDS: 27 01 seed / 27 02 key
                // (и далее 03/04…): нечётный подадрес — запрос seed, чётный —
                // отправка ключа. Ключ KWP ровно 130 байт тела (docs/16 §5),
                // у UDS длина зависит от ЭБУ — сохраняем фактическую.
                let sub = body[1];
                let sub_text = format!("0x{sub:02X}");
                let is_kwp_key = sub == 0x80;
                if sub & 1 != 0 {
                    stages.push(AuthStage {
                        kind: "seed_request".into(),
                        t,
                        seq,
                        service: "0x27".into(),
                        sub: sub_text,
                        len: body.len() as u32,
                        nrc: None,
                        value_hash: String::new(),
                        text: "запрос seed".into(),
                    });
                    last_req = Some((t, seq, body.len() as u32));
                } else if sub > 0
                    && body.len() > 2
                    && (!is_kwp_key || body.len() >= 130)
                {
                    let key = &body[2..];
                    stages.push(AuthStage {
                        kind: "key".into(),
                        t,
                        seq,
                        service: "0x27".into(),
                        sub: sub_text,
                        len: key.len() as u32,
                        nrc: None,
                        value_hash: value_hash(key),
                        text: format!("ключ отправлен: {} байт", key.len()),
                    });
                    if let Some((st, sseq, slen, _)) = current_seed.take() {
                        pairs.push(SeedPair {
                            seed_t: st,
                            seed_seq: sseq,
                            seed_len: slen,
                            key_t: Some(t),
                            key_seq: Some(seq),
                            key_len: key.len() as u32,
                            accepted: None,
                            accepted_seq: None,
                        });
                    }
                }
            }
        } else {
            if body[0] == 0x67 && body.len() >= 2 && (body[1] & 1) != 0 {
                let seed = &body[2..];
                stages.push(AuthStage {
                    kind: "seed".into(),
                    t,
                    seq,
                    service: "0x67".into(),
                    sub: format!("0x{:02X}", body[1]),
                    len: seed.len() as u32,
                    nrc: None,
                    value_hash: value_hash(seed),
                    text: format!("seed получен: {} байт", seed.len()),
                });
                // Предыдущий seed без ключа не выбрасываем: инструмент запросил
                // seed повторно, и по отчёту должно быть видно, что он не был
                // использован.
                if let Some((st, sseq, slen, _)) = current_seed.take() {
                    pairs.push(SeedPair {
                        seed_t: st,
                        seed_seq: sseq,
                        seed_len: slen,
                        key_t: None,
                        key_seq: None,
                        key_len: 0,
                        accepted: None,
                        accepted_seq: None,
                    });
                }
                current_seed = Some((t, seq, seed.len() as u32, value_hash(seed)));
                last_req = None;
                status = "seed".into();
            } else if body[0] == 0x67 && body.len() >= 2 && body[1] > 0 {
                stages.push(AuthStage {
                    kind: "access_ok".into(),
                    t,
                    seq,
                    service: "0x67".into(),
                    sub: format!("0x{:02X}", body[1]),
                    len: body.len() as u32,
                    nrc: None,
                    value_hash: String::new(),
                    text: "ключ принят (67 80)".into(),
                });
                if let Some(pair) = pairs.last_mut() {
                    pair.accepted = Some(true);
                    pair.accepted_seq = Some(seq);
                }
                status = "granted".into();
            } else if body[0] == 0x7F && body.len() >= 3 && body[1] == 0x27 {
                let nrc = body[2];
                stages.push(AuthStage {
                    kind: "denied".into(),
                    t,
                    seq,
                    service: "0x7F".into(),
                    sub: "0x27".into(),
                    len: body.len() as u32,
                    nrc: Some(nrc),
                    value_hash: String::new(),
                    text: format!("ключ отклонён: 7F 27 {nrc:02X} ({})", nrc_name(nrc)),
                });
                if let Some(pair) = pairs.last_mut() {
                    pair.accepted = Some(false);
                    pair.accepted_seq = Some(seq);
                }
                status = "denied".into();
            }
        }
    }
    // Запрос seed без ответа до конца операции — тайм-аут, а не «нет данных».
    if let Some((t, seq, len)) = last_req {
        stages.push(AuthStage {
            kind: "timeout".into(),
            t,
            seq,
            service: "0x27".into(),
            sub: "0x7F".into(),
            len,
            nrc: None,
            value_hash: String::new(),
            text: "ответ на запрос seed не получен — результат не установлен".into(),
        });
        status = "timeout".into();
    }
    // Последний seed без ключа тоже попадает в список: «запросил и не отправил».
    if let Some((t, seq, len, _)) = current_seed.take() {
        pairs.push(SeedPair {
            seed_t: t,
            seed_seq: seq,
            seed_len: len,
            key_t: None,
            key_seq: None,
            key_len: 0,
            accepted: None,
            accepted_seq: None,
        });
    }
    if status == "seed" {
        status = "granted".into();
    }
    // seed без ключа — тоже факт: инструмент запросил и не отправил ключ.
    // Если доступ в итоге подтверждён, статус операции остаётся `granted`:
    // неиспользованные seed видны в списке пар, а не подменяют итог.
    let unmatched = pairs.iter().any(|p| p.key_seq.is_none());
    if unmatched && status == "none" {
        status = "seed_only".into();
    }
    (stages, status, pairs)
}

fn seed_pairs_full(op: &Operation, exchange: &[&Event]) -> Vec<SeedPairFull> {
    let mut out = Vec::new();
    for pair in &op.seeds {
        let Some(key_seq) = pair.key_seq else { continue };
        let Some(seed_ev) = exchange.iter().find(|e| e.seq == pair.seed_seq) else {
            continue;
        };
        let Some(key_ev) = exchange.iter().find(|e| e.seq == key_seq) else {
            continue;
        };
        let seed_bytes: Vec<u8> = body(seed_ev).into_iter().skip(2).collect();
        let key_body = body(key_ev);
        let key_bytes: Vec<u8> = key_body.into_iter().skip(2).collect();
        out.push(SeedPairFull {
            seed: hex::encode(seed_bytes),
            key: hex::encode(key_bytes),
            seed_seq: pair.seed_seq,
            key_seq,
            seed_t: pair.seed_t,
            key_t: pair.key_t.unwrap_or(0.0),
            accepted: pair.accepted,
        });
    }
    out
}

fn count_seed_pairs(ops: &[Operation]) -> u64 {
    ops.iter().map(|o| o.seeds.iter().filter(|p| p.key_seq.is_some()).count() as u64).sum()
}

fn milestones_for(op: &Operation, exchange: &[&Event], ctx: &[&Event]) -> Vec<Milestone> {
    let mut out: Vec<Milestone> = Vec::new();
    if let (Some(t), Some(seq)) = (op.click_t, op.click_seq) {
        out.push(Milestone {
            t,
            kind: "click".into(),
            label: format!("клик «{}»", op.name),
            seq: Some(seq),
            confidence: "confirmed".into(),
            t_source: "uia".into(),
            detail: format!(
                "{} · {}",
                op.activation.clone().unwrap_or_default(),
                op.window.clone().unwrap_or_default()
            ),
        });
    }
    out.extend(op.dialogs.iter().cloned());
    for sig in &op.signals {
        out.push(Milestone {
            t: sig.t_after,
            kind: "signal".into(),
            label: format!("{}: {}", sig.name, sig.text),
            seq: None,
            confidence: "bracket".into(),
            t_source: "scope-delivery".into(),
            detail: sig.note.clone(),
        });
    }
    if let Some(first_tx) = exchange.iter().find(|e| e.kind == EventKind::Tx && is_data(e)) {
        out.push(Milestone {
            t: first_tx.t,
            kind: "tx".into(),
            label: format!("первый TX: {} байт", first_tx.len),
            seq: Some(first_tx.seq),
            confidence: "confirmed".into(),
            t_source: "bridge".into(),
            detail: first_tx.hex.chars().take(48).collect(),
        });
    }
    if let Some(last_rx) = exchange
        .iter()
        .filter(|e| e.kind == EventKind::Rx && is_data(e))
        .last()
    {
        out.push(Milestone {
            t: last_rx.t,
            kind: "rx".into(),
            label: format!("последний RX: {} байт", last_rx.len),
            seq: Some(last_rx.seq),
            confidence: "confirmed".into(),
            t_source: "bridge".into(),
            detail: String::new(),
        });
    }
    for stage in &op.auth {
        out.push(Milestone {
            t: stage.t,
            kind: "auth".into(),
            label: stage.text.clone(),
            seq: Some(stage.seq),
            confidence: "confirmed".into(),
            t_source: "bridge".into(),
            detail: if stage.value_hash.is_empty() {
                String::new()
            } else {
                format!("sha256[:8]={}", stage.value_hash)
            },
        });
    }
    for rec in &op.notable_calls {
        out.push(Milestone {
            t: rec.t1,
            kind: "call".into(),
            label: format!("{} rc=0x{:02X} {}→{}", rec.op, rec.rc, rec.n_in, rec.n_out),
            seq: Some(rec.seq),
            confidence: "confirmed".into(),
            t_source: "bridge".into(),
            detail: format!("канал {} · {:.1} мс", rec.channel, rec.dur_ms),
        });
    }
    for ev in ctx {
        if ev.kind == EventKind::Sys
            && (ev.api.contains("disconnect") || ev.api.contains("close"))
            && meta_str(ev, "layer") == Some("driver")
            && ev.t >= op.t0
            && ev.t <= op.t1 + 0.001
        {
            out.push(Milestone {
                t: ev.t,
                kind: "disconnect".into(),
                label: if ev.api.contains("disconnect") {
                    "disconnect".into()
                } else {
                    "close".into()
                },
                seq: Some(ev.seq),
                confidence: "confirmed".into(),
                t_source: "bridge".into(),
                detail: String::new(),
            });
        }
    }
    out.sort_by(|a, b| {
        a.t.partial_cmp(&b.t)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.kind.cmp(&b.kind))
    });
    // Одинаковые отметки (например, disconnect прокси и драйвера) схлопываем.
    out.dedup_by(|a, b| (a.t - b.t).abs() < 0.0005 && a.label == b.label);
    out.truncate(80);
    out
}

// ──────────────────────────── файловый уровень ────────────────────────────

/// Пересобрать анализ сигналов и операции для каталога сессии, записать файлы.
///
/// Возвращает документ; `seedkeys.jsonl` пишется рядом (полные пары — отдельно,
/// потому что в `operations.json` содержимое намеренно скрыто).
pub fn rebuild(dir: &Path, meta: &SessionMeta, events: &[Event]) -> anyhow::Result<OperationsDoc> {
    rebuild_with(dir, meta, events, None)
}

/// Тот же переразбор с уже посчитанным анализом кадров: офлайн-инструменту и
/// тестам не нужно читать 129 МБ дважды.
pub fn rebuild_with(
    dir: &Path,
    meta: &SessionMeta,
    events: &[Event],
    analysis: Option<&crate::signals::ScopeAnalysis>,
) -> anyhow::Result<OperationsDoc> {
    let owned;
    let analysis = match analysis {
        Some(a) => a,
        None => {
            owned = crate::signals::analyze(dir, meta).context("анализ кадров осциллографа")?;
            &owned
        }
    };
    crate::signals::save(dir, analysis)?;
    let doc = build(events, meta, analysis);
    write_seedkeys(dir, &collect_pairs_full(&doc, events))?;
    let path = dir.join(OPERATIONS_FILE);
    crate::store::write_json_atomic(&path, &doc)?;
    Ok(doc)
}

fn collect_pairs_full(doc: &OperationsDoc, events: &[Event]) -> Vec<SeedPairFull> {
    let mut exchange: Vec<&Event> = events.iter().collect();
    exchange.sort_by(|a, b| {
        a.t.partial_cmp(&b.t)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.seq.cmp(&b.seq))
    });
    let mut out = Vec::new();
    for op in &doc.operations {
        out.extend(seed_pairs_full(op, &exchange));
    }
    // Одинаковые пары (например, если операция пересеклась) — один раз.
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(format!("{}+{}", p.seed, p.key)));
    out
}

fn write_seedkeys(dir: &Path, pairs: &[SeedPairFull]) -> anyhow::Result<()> {
    let path = dir.join(SEEDKEYS_FILE);
    if pairs.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    let mut text = String::new();
    for p in pairs {
        text.push_str(&serde_json::to_string(p)?);
        text.push('\n');
    }
    crate::store::write_text_atomic(&path, &text)
}

/// Прочитать `operations.json`, если он есть и относится к сессии.
pub fn load(dir: &Path, session_id: &str) -> Option<OperationsDoc> {
    let text = std::fs::read_to_string(dir.join(OPERATIONS_FILE)).ok()?;
    let doc: OperationsDoc = serde_json::from_str(&text).ok()?;
    if doc.format != OPERATIONS_FORMAT || doc.session_id != session_id {
        return None;
    }
    Some(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Direction, Event, EventKind, Transport};
    use crate::signals::ScopeAnalysis;

    fn click(t: f64, name: &str, action: &str) -> Event {
        let mut ev = Event::new(EventKind::UiAction, Transport::App, t, "");
        ev.text = Some(name.into());
        ev.meta = serde_json::json!({
            "action": action, "activation": "click", "confirmed": true,
            "window": "PCMflash", "automation_id": "1", "control_type": "Button"
        });
        ev
    }

    fn frame_event(t: f64, dir: Direction, hex: &str, svc: &str, resp: bool, call: u64) -> Event {
        let kind = if dir == Direction::Tx {
            EventKind::Tx
        } else {
            EventKind::Rx
        };
        let mut ev = Event::new(kind, Transport::J2534, t, "");
        ev.direction = Some(dir);
        ev.hex = hex.into();
        ev.len = hex.split_whitespace().count() as u32;
        ev.meta = serde_json::json!({
            "svc": svc, "svc_resp": resp, "call": call, "channel": "1",
            "n_in": 1, "n_out": 1, "layer": "proxy", "protocol": "0x8003"
        });
        ev
    }

    fn meta() -> SessionMeta {
        let mut m = SessionMeta::new("ops-1", "pcmflash");
        m.status = "finished".into();
        m.transport = "j2534".into();
        m
    }

    #[test]
    fn confirmed_click_opens_operation_and_focus_does_not() {
        let mut focus = click(1.5, "Чтение", "read");
        focus.meta["activation"] = "focus".into();
        focus.meta["confirmed"] = false.into();
        let events = vec![click(1.0, "Идентификация", "identify"), focus];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.operations[0].name, "Идентификация");
        assert_eq!(doc.operations[0].origin, "confirmed");
    }

    #[test]
    fn auth_pair_and_status_are_built_without_values() {
        let key_hex = format!("00 82 27 80 {}", "00 ".repeat(128).trim_end());
        let events = vec![
            click(10.0, "Идентификация", "identify"),
            frame_event(11.0, Direction::Tx, "00 02 27 7f", "0x27", false, 1),
            frame_event(11.1, Direction::Rx, "00 0d 67 7f 11 22 33 44 55 66 77 88 99 aa bb", "0x67", true, 2),
            frame_event(11.2, Direction::Tx, &key_hex, "0x27", false, 3),
            frame_event(11.3, Direction::Rx, "00 03 67 80 34", "0x67", true, 4),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        let op = &doc.operations[0];
        assert_eq!(op.auth_status, "granted");
        assert_eq!(op.seeds.len(), 1);
        assert_eq!(op.seeds[0].key_len, 128);
        assert_eq!(op.seeds[0].accepted, Some(true));
        // В operations.json нет ни seed, ни ключа.
        let text = serde_json::to_string(&doc).unwrap();
        assert!(!text.contains("11 22 33"), "seed не должен попадать в operations.json");
    }

    #[test]
    fn denied_key_sets_status_and_nrc() {
        let key_hex = format!("00 82 27 80 {}", "aa ".repeat(128).trim_end());
        let events = vec![
            click(1.0, "Запись", "write"),
            frame_event(2.0, Direction::Tx, "00 02 27 7f", "0x27", false, 1),
            frame_event(2.1, Direction::Rx, "00 0d 67 7f 01 02 03 04 05 06 07 08 09 0a 0b", "0x67", true, 2),
            frame_event(2.2, Direction::Tx, &key_hex, "0x27", false, 3),
            frame_event(2.3, Direction::Rx, "00 03 7f 27 33", "0x7f", true, 4),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        let op = &doc.operations[0];
        assert_eq!(op.auth_status, "denied");
        assert_eq!(op.result.status, "denied");
        assert_eq!(op.result.nrc, Some(0x33));
        assert!(op.result.text.contains("invalidKey"), "{}", op.result.text);
        assert_eq!(op.seeds[0].accepted, Some(false));
    }

    #[test]
    fn uds_27_01_02_is_recognised() {
        // UDS: 27 01 → 67 01 seed, 27 02 → 67 02 key. Длина ключа 4 байта:
        // у UDS она зависит от ЭБУ, порог «130 байт» относится только к 27 80.
        let events = vec![
            click(1.0, "Запись", "write"),
            frame_event(2.0, Direction::Tx, "00 02 27 01", "0x27", false, 1),
            frame_event(2.1, Direction::Rx, "00 06 67 01 11 22 33 44", "0x67", true, 2),
            frame_event(2.2, Direction::Tx, "00 06 27 02 aa bb cc dd", "0x27", false, 3),
            frame_event(2.3, Direction::Rx, "00 02 67 02", "0x67", true, 4),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        let op = &doc.operations[0];
        assert_eq!(op.auth_status, "granted");
        assert_eq!(op.seeds.len(), 1);
        assert_eq!(op.seeds[0].seed_len, 4);
        assert_eq!(op.seeds[0].key_len, 4);
        assert_eq!(op.seeds[0].accepted, Some(true));
    }

    #[test]
    fn unanswered_last_request_is_timeout() {
        let events = vec![
            click(1.0, "Чтение", "read"),
            frame_event(2.0, Direction::Tx, "00 02 27 7f", "0x27", false, 1),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        let op = &doc.operations[0];
        assert_eq!(op.result.status, "timeout");
        assert_eq!(op.auth_status, "timeout");
    }

    #[test]
    fn dialogs_attach_to_the_right_operation() {
        let events = vec![
            click(10.0, "Чтение", "read"),
            click(20.0, "Сохранить", "other"),
            click(30.0, "Запись", "write"),
            click(31.0, "Да", "other"),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        assert_eq!(doc.operations.len(), 2);
        assert!(doc.operations[0].dialogs.iter().any(|d| d.label == "Сохранить"));
        assert!(doc.operations[1].dialogs.iter().any(|d| d.label == "Да"));
    }

    #[test]
    fn three_exchange_segments_stay_in_one_operation() {
        let events = vec![
            click(1.0, "Запись", "write"),
            frame_event(2.0, Direction::Tx, "00 02 10 92", "0x10", false, 1),
            frame_event(2.1, Direction::Rx, "00 02 50 92", "0x50", true, 2),
            frame_event(5.0, Direction::Tx, "00 02 10 92", "0x10", false, 3),
            frame_event(5.1, Direction::Rx, "00 02 50 92", "0x50", true, 4),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.operations[0].segments.len(), 2);
        assert_eq!(doc.operations[0].calls.tx_msgs, 2);
    }

    #[test]
    fn derived_operations_without_clicks_are_marked() {
        let events = vec![
            frame_event(1.0, Direction::Tx, "00 02 10 92", "0x10", false, 1),
            frame_event(1.1, Direction::Rx, "00 02 50 92", "0x50", true, 2),
        ];
        let doc = build(&events, &meta(), &ScopeAnalysis::empty("ops-1"));
        assert_eq!(doc.operations.len(), 1);
        assert_eq!(doc.operations[0].origin, "derived");
        assert!(doc.operations[0].notes[0].contains("предположительно"));
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;

    #[test]
    fn compare_pair_matches_and_reports_differences() {
        let dir = std::env::temp_dir().join(format!("ftdi-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("expected.bin");
        let b = dir.join("actual.bin");
        std::fs::write(&a, [1u8, 2, 3, 4]).unwrap();
        std::fs::write(&b, [1u8, 2, 3, 4]).unwrap();
        let m = compare_pair(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert_eq!(m.verdict, "match");
        assert_eq!(m.different_bytes, 0);
        assert_eq!(m.unverified_bytes, 0);
        assert_eq!(m.compared_bytes, 4);
        std::fs::write(&b, [1u8, 9, 3]).unwrap();
        let m2 = compare_pair(a.to_str().unwrap(), b.to_str().unwrap()).unwrap();
        assert_eq!(m2.verdict, "mismatch");
        assert_eq!(m2.different_bytes, 1);
        assert_eq!(m2.unverified_bytes, 1);
        std::fs::remove_dir_all(&dir).ok();
    }
}
