//! Разбор лога и сводки шагов. Владелец: ded-bekend.
//!
//! Грамматика — канонический старый лог Quickflash-семейства
//! (`[+70.537s] TX ftd2xx FT_Write …`, `VCP TX WriteFile(COM6) …`, `# MARK …`).
//! Эталон поведения — `E:\Replica\work\orig-capture\parse_family.py`; тесты на
//! `reference/logs/` сверяют команды/ответы/чтения/sha256 с реальным логом.

use crate::models::util::{ascii_preview, bytes_to_hex, hex_to_bytes, sha256_hex};
use crate::models::{
    Direction, Event, EventKind, FileHash, PayloadDecode, StepRead, StepSummary, StepVerdict,
    Telegram, Transport, WinkfpJob,
};
use serde_json::{json, Map, Value};

/// Предел полезной нагрузки события: длинные дампы режем (`meta.truncated = true`).
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
/// Сколько байт payload влезает в 64 КиБ hex-текста («12 04 …» = 3 символа на байт).
const MAX_PAYLOAD_BYTES: usize = MAX_EVENT_BYTES / 3;

/// Коды отказа KWP2000 (вторая половина кадра `7F <svc> <nrc>`).
const KWP_NRC: &[(u8, &str)] = &[
    (0x10, "generalReject"),
    (0x11, "serviceNotSupported"),
    (0x12, "subFunctionNotSupported"),
    (0x13, "badLength"),
    (0x21, "busyRepeat"),
    (0x22, "conditionsNotCorrect"),
    (0x31, "requestOutOfRange"),
    (0x33, "securityAccessDenied"),
    (0x35, "invalidKey"),
    (0x78, "responsePending"),
];

/// Сервисы, у которых печатается подфункция в подписи TX.
const KWP_SUB_SVC: &[u8] = &[0x10, 0x27, 0x30, 0x31, 0x3E, 0x85];

pub fn kwp_nrc_name(nrc: u8) -> Option<&'static str> {
    KWP_NRC.iter().find(|(k, _)| *k == nrc).map(|(_, v)| *v)
}

// ─────────────────────────── разбор одной строки ──────────────────────────

/// Разобрать каноническую строку захвата (`[+70.537s] VCP TX WriteFile(COM6) …`).
///
/// `None` — только для пустых строк. Всё нераспознанное сохраняется как
/// `EventKind::Raw`/`Sys`, чтобы импорт ничего не терял.
pub fn parse_capture_line(line: &str) -> Option<Event> {
    let raw = line.trim_end_matches(['\r', '\n']).to_string();
    let trimmed = raw.trim_end();
    if trimmed.trim().is_empty() {
        return None;
    }
    let (t, body) = split_time_prefix(trimmed);
    let ev = if body.starts_with('#') {
        parse_comment(body, t, &raw)
    } else {
        parse_body(body, t, &raw)
    };
    Some(ev)
}

/// `[+70.537s] остаток` → (70.537, "остаток"); без префикса → (0.0, вся строка).
fn split_time_prefix(line: &str) -> (f64, &str) {
    if let Some(rest) = line.strip_prefix("[+") {
        if let Some(pos) = rest.find("] ") {
            let num = &rest[..pos];
            let num = num.strip_suffix('s').unwrap_or(num);
            if let Ok(t) = num.trim().parse::<f64>() {
                return (t, &rest[pos + 2..]);
            }
        }
    }
    (0.0, line)
}

fn meta_slot(ev: &mut Event) -> &mut Map<String, Value> {
    if !ev.meta.is_object() {
        ev.meta = Value::Object(Map::new());
    }
    ev.meta.as_object_mut().expect("meta object")
}

fn set_meta(ev: &mut Event, key: &str, value: Value) {
    meta_slot(ev).insert(key.to_string(), value);
}

/// Разложить `key=value`-пары из хвоста строки в `meta` (числа — числами, остальное строками).
fn apply_kv_meta(ev: &mut Event, body: &str) {
    for token in body.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let key = key.trim_end_matches(',');
        let value = value.trim_end_matches(',');
        if key.is_empty() || value.is_empty() || key == "rc" {
            continue;
        }
        if let Ok(n) = value.parse::<i64>() {
            set_meta(ev, key, json!(n));
        } else if let Some(hex) = value
            .strip_prefix("0x")
            .and_then(|h| i64::from_str_radix(h, 16).ok())
        {
            set_meta(ev, key, json!(hex));
        } else {
            set_meta(ev, key, json!(value));
        }
    }
}

fn meta_bool(ev: &Event, key: &str) -> bool {
    ev.meta.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Запись внутреннего слоя J2534: агент ставит `parent=<call>`, когда вызов
/// пришёл из настоящего драйвера внутри вызова прокси (docs/13 §6.2).
///
/// Такая строка остаётся в логе и в `events.jsonl` — по ней видно, что вернул
/// драйвер, — но в счётчики обмена не входит: обмен уже посчитан слоем выше.
pub fn is_inner(ev: &Event) -> bool {
    ev.meta
        .as_object()
        .map(|meta| meta.contains_key("parent"))
        .unwrap_or(false)
}

fn meta_idx(ev: &Event) -> Option<u32> {
    ev.meta
        .get("idx")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
}

/// Первое значение `key=...` в тексте (граница — пробел, `)`, `,`).
fn tag_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("{key}=");
    let bytes = text.as_bytes();
    let mut search = 0usize;
    while let Some(p) = text[search..].find(&pat) {
        let abs = search + p;
        let before_ok = abs == 0
            || matches!(bytes[abs - 1], b' ' | b'\t' | b'(' | b',' | b';')
            || bytes[abs - 1] == b'='; // «rc==0» — не наш случай, но не падаем
        if before_ok {
            let vstart = abs + pat.len();
            let vend = text[vstart..]
                .find(|c: char| c.is_whitespace() || c == ')' || c == ',' || c == ';')
                .map(|x| vstart + x)
                .unwrap_or(text.len());
            return Some(text[vstart..vend].trim());
        }
        search = abs + pat.len();
    }
    None
}

fn tag_u64(text: &str, key: &str) -> Option<u64> {
    tag_value(text, key).and_then(|v| v.trim().parse().ok())
}

fn tag_i32(text: &str, key: &str) -> Option<i32> {
    tag_value(text, key).and_then(|v| v.trim().parse().ok())
}

/// Разделить «шапка : hex» по последнему ` : `.
fn split_payload(text: &str) -> (&str, Option<&str>) {
    match text.rfind(" : ") {
        Some(p) => (&text[..p], Some(text[p + 3..].trim())),
        None => (text, None),
    }
}

fn paren_arg(text: &str) -> Option<&str> {
    let open = text.find('(')?;
    let close = text[open..].find(')')? + open;
    Some(&text[open + 1..close])
}

/// Записать payload в событие с учётом предела 64 КиБ и заявленной длины.
fn set_payload(ev: &mut Event, hex: Option<&str>, declared: Option<u64>) {
    let bytes = hex.map(hex_to_bytes).unwrap_or_default();
    let mut payload = bytes;
    let mut truncated = false;
    if payload.len() > MAX_PAYLOAD_BYTES {
        payload.truncate(MAX_PAYLOAD_BYTES);
        truncated = true;
    }
    let got = payload.len() as u64;
    ev.hex = bytes_to_hex(&payload);
    match declared {
        Some(d) => {
            ev.len = d.min(u32::MAX as u64) as u32;
            if d > 0 && got < d {
                set_meta(ev, "short", json!(true));
            }
        }
        None => ev.len = got as u32,
    }
    if truncated {
        set_meta(ev, "truncated", json!(true));
    }
}

fn make_event(kind: EventKind, transport: Transport, t: f64, raw: &str) -> Event {
    let mut ev = Event::new(kind, transport, t, "");
    ev.raw = raw.to_string();
    ev
}

fn parse_comment(body: &str, t: f64, raw: &str) -> Event {
    let c = body.trim_start_matches('#').trim_start();

    // MARK: `# MARK wall=2026-10-16 11:53:45 START 1: читаю идентификаторы`
    if let Some(rest) = c.strip_prefix("MARK") {
        return parse_mark(rest.trim_start(), t, raw);
    }

    // PHASE-JSON {...}
    if let Some(rest) = c.strip_prefix("PHASE-JSON") {
        let text = rest.trim();
        let mut ev = make_event(EventKind::Summary, Transport::None, t, raw);
        ev.api = "PHASE-JSON".into();
        match serde_json::from_str::<Value>(text) {
            Ok(v) => {
                if let Some(title) = v.get("title").and_then(Value::as_str) {
                    ev.text = Some(title.to_string());
                }
                ev.meta = v;
            }
            Err(_) => {
                ev.text = Some(text.to_string());
                set_meta(&mut ev, "parse_error", json!(true));
            }
        }
        return ev;
    }

    // PHASE 1: … | PHASE 1   команды/ответы/чтение …
    if let Some(rest) = c.strip_prefix("PHASE") {
        let mut ev = make_event(EventKind::Summary, Transport::None, t, raw);
        ev.api = "PHASE".into();
        ev.text = Some(c.to_string());
        let tail = rest.trim_start();
        let idx: String = tail.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if let Ok(n) = idx.parse::<u32>() {
            set_meta(&mut ev, "idx", json!(n));
        }
        return ev;
    }

    // `# filehash <path> size=N sha256=…`
    if let Some(rest) = c.strip_prefix("filehash ") {
        let mut ev = make_event(EventKind::FileHash, Transport::File, t, raw);
        ev.api = "FILEHASH".into();
        let (path, attrs) = split_file_attrs(rest, &[" size="]);
        ev.text = Some(path.to_string());
        set_meta(&mut ev, "path", json!(path));
        if let Some(size) = tag_u64(attrs, "size") {
            set_meta(&mut ev, "size", json!(size));
        }
        if let Some(digest) = tag_value(attrs, "sha256") {
            set_meta(&mut ev, "sha256", json!(digest));
        }
        return ev;
    }

    // `# module + …`
    if let Some(rest) = c.strip_prefix("module ") {
        let mut ev = make_event(EventKind::Module, Transport::None, t, raw);
        ev.api = "MODULE".into();
        ev.text = Some(rest.to_string());
        return ev;
    }

    // `# capture start: label=…` / `# capture stop: reason=…`
    if let Some(rest) = c.strip_prefix("capture ") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "CAPTURE".into();
        let action = rest.split_whitespace().next().unwrap_or("").to_string();
        set_meta(&mut ev, "action", json!(action));
        if let Some(label) = tag_value(rest, "label") {
            set_meta(&mut ev, "label", json!(label));
            ev.text = Some(label.to_string());
        } else {
            ev.text = Some(rest.to_string());
        }
        if let Some(reason) = tag_value(rest, "reason") {
            set_meta(&mut ev, "reason", json!(reason));
        }
        return ev;
    }

    // `# wall(start)=…`, `# time=…`
    for (prefix, api) in [("wall(start)=", "WALL"), ("time=", "TIME")] {
        if let Some(rest) = c.strip_prefix(prefix) {
            let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
            ev.api = api.into();
            ev.text = Some(rest.trim().to_string());
            return ev;
        }
    }

    // `# attached pid=…`, `# spawned pid=…`, `# resumed`, `# hooks loaded`
    for (prefix, api) in [
        ("attached ", "ATTACHED"),
        ("spawned ", "SPAWNED"),
        ("resumed", "RESUMED"),
        ("hooks loaded", "HOOKS"),
    ] {
        if let Some(rest) = c.strip_prefix(prefix) {
            let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
            ev.api = api.into();
            let tail = rest.trim();
            if let Some(pid) = tag_u64(tail, "pid") {
                set_meta(&mut ev, "pid", json!(pid));
            }
            ev.text = Some(if tail.is_empty() {
                prefix.trim().to_string()
            } else {
                tail.to_string()
            });
            return ev;
        }
    }

    // ── расширенная шапка универсального захвата (docs/11 §1) ────────────
    // `# api: 04.04 dll="smj2534.dll" ver="1.0.0.120" path="…" pid=8120 bits=32 dec=1`
    if let Some(rest) = c.strip_prefix("api:") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "API".into();
        let tail = rest.trim_start();
        // Версия ABI — первый токен строки. Ключ meta `api_version`, потому что
        // `ev.api` уже занят маркером "API".
        let version = tail.split_whitespace().next().unwrap_or("");
        if !version.is_empty() {
            set_meta(&mut ev, "api_version", json!(version));
        }
        set_meta_str(&mut ev, "dll", tag_quoted(tail, "dll"));
        set_meta_str(&mut ev, "ver", tag_quoted(tail, "ver"));
        set_meta_str(&mut ev, "path", tag_quoted(tail, "path"));
        // `reason=ambiguous` — ABI не подтверждён, декодировать нельзя (dec=0).
        set_meta_str(&mut ev, "reason", tag_quoted(tail, "reason"));
        set_num_pairs(
            &mut ev,
            tail,
            &[("pid", "pid"), ("bits", "bits"), ("dec", "dec")],
        );
        ev.text = Some(tail.to_string());
        return ev;
    }

    // `# hooks-names mod="smj2534.dll" names="PassThruOpen,PassThruClose,…"`
    if let Some(rest) = c.strip_prefix("hooks-names ") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "HOOKS-NAMES".into();
        set_meta_str(&mut ev, "mod", tag_quoted(rest, "mod"));
        set_meta_str(&mut ev, "names", tag_quoted(rest, "names"));
        ev.text = Some(rest.trim().to_string());
        return ev;
    }

    // `# hooks mod="smj2534.dll" base=0x6d830000 load=1 exports=14 attached=14 dup=0 failed=0`
    // `load=` — module_load_id (счётчик загрузок имени), а не адрес базы.
    if let Some(rest) = c.strip_prefix("hooks ") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "HOOKS".into();
        set_meta_str(&mut ev, "mod", tag_quoted(rest, "mod"));
        // `base` — hex-адрес как пришёл: он нужен для сверки с `MODULE … base=`.
        set_meta_str(&mut ev, "base", tag_quoted(rest, "base"));
        set_num_pairs(
            &mut ev,
            rest,
            &[
                ("load", "load"),
                ("exports", "exports"),
                ("attached", "attached"),
                ("dup", "dup"),
                ("failed", "failed"),
            ],
        );
        let module = tag_quoted(rest, "mod").unwrap_or_default();
        ev.text = Some(format!("hooks {module}").trim_end().to_string());
        return ev;
    }

    // `# counters …` (итог движка) и `# agent-counters …` (счётчики агента и моста).
    // Префиксы разные, чтобы в логе нельзя было спутать две разные строки.
    if let Some(rest) = c
        .strip_prefix("agent-counters ")
        .or_else(|| c.strip_prefix("counters "))
    {
        let agent = c.starts_with("agent-counters ");
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "COUNTERS".into();
        // Ключи берём как есть: набор счётчиков может расти, meta не должна отставать.
        apply_kv_meta(&mut ev, rest);
        set_meta(&mut ev, "source", json!(if agent { "agent" } else { "engine" }));
        ev.text = Some(rest.trim().to_string());
        return ev;
    }

    // `# session incomplete: reason=queue_overflow dropped=12`
    if let Some(rest) = c.strip_prefix("session incomplete:") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "SESSION-INCOMPLETE".into();
        set_meta_str(&mut ev, "reason", tag_quoted(rest, "reason"));
        set_num_pairs(&mut ev, rest, &[("dropped", "dropped")]);
        ev.text = Some(rest.trim().to_string());
        return ev;
    }

    // `# agent: universal_capture.js mode=full`
    if let Some(rest) = c.strip_prefix("agent:") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "AGENT".into();
        let tail = rest.trim_start();
        let script = tail.split_whitespace().next().unwrap_or("");
        if !script.is_empty() {
            set_meta(&mut ev, "agent", json!(script));
        }
        apply_kv_meta(&mut ev, tail);
        ev.text = Some(tail.to_string());
        return ev;
    }

    // `# attach: spawn` / `# attach: early` / `# attach: late`
    if let Some(rest) = c.strip_prefix("attach:") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "ATTACH".into();
        let tail = rest.trim_start();
        let mode = tail.split_whitespace().next().unwrap_or("");
        if !mode.is_empty() {
            // `attach` — как в строке; `mode` — для тех, кто читает режим по имени.
            set_meta(&mut ev, "attach", json!(mode));
            set_meta(&mut ev, "mode", json!(mode));
        }
        apply_kv_meta(&mut ev, tail);
        ev.text = Some(tail.to_string());
        return ev;
    }

    // Общий вид `# ключ: значение` → api = КЛЮЧ.
    if let Some((key, value)) = c.split_once(':') {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = normalize_key(key);
        ev.text = Some(value.trim().to_string());
        set_meta(&mut ev, "key", json!(key.trim()));
        return ev;
    }

    // Любой прочий `# …` — системная строка как есть.
    let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
    ev.api = "SYS".into();
    ev.text = Some(c.to_string());
    ev
}

fn normalize_key(key: &str) -> String {
    let mut out = String::new();
    for ch in key.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if (ch == ' ' || ch == '-' || ch == '_' || ch == '.') && !out.ends_with('-') {
            out.push('-');
        }
    }
    if out.is_empty() {
        "SYS".into()
    } else {
        out.trim_matches('-').to_string()
    }
}

fn split_file_attrs<'a>(text: &'a str, markers: &[&str]) -> (&'a str, &'a str) {
    let mut best: Option<usize> = None;
    for marker in markers {
        if let Some(p) = text.find(marker) {
            best = Some(best.map_or(p, |b: usize| b.min(p)));
        }
    }
    match best {
        Some(p) => (text[..p].trim(), &text[p..]),
        None => (text.trim(), ""),
    }
}

fn strip_duration(s: &str) -> (String, Option<f64>) {
    for suffix in [" с)", " c)", " s)"] {
        if let Some(rest) = s.strip_suffix(suffix) {
            if let Some(p) = rest.rfind(" (") {
                let num = rest[p + 2..].trim().replace(',', ".");
                if let Ok(d) = num.parse::<f64>() {
                    return (rest[..p].trim().to_string(), Some(d));
                }
            }
        }
    }
    (s.trim().to_string(), None)
}

fn parse_mark(rest: &str, t: f64, raw: &str) -> Event {
    // Определяем границу действия: " START " / " END ".
    let mut action: Option<&str> = None;
    let mut at = rest.len();
    for (needle, name) in [(" START ", "start"), (" END ", "end")] {
        if let Some(p) = rest.find(needle) {
            if p < at {
                at = p;
                action = Some(name);
            }
        }
    }
    let (wall_part, tail) = match action {
        Some(_) => (rest[..at].trim(), rest[at..].trim_start()),
        None => (rest, ""),
    };
    let mut rel: Option<f64> = None;
    if let Some(rel_txt) = wall_part.split(" rel=").nth(1) {
        let cleaned = rel_txt
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_start_matches('+')
            .trim_end_matches('s');
        if let Ok(v) = cleaned.parse::<f64>() {
            rel = Some(v);
        }
    }
    // Две независимые шкалы: `[+Xs]` (от загрузки агента) и `rel=+Xs` (от t0_epoch).
    // Префикс есть — не трогаем t; нет — берём rel, иначе 0.
    let t = if t == 0.0 { rel.unwrap_or(0.0) } else { t };
    let wall = wall_part
        .strip_prefix("wall=")
        .unwrap_or(wall_part)
        .split(" rel=")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let mut ev = make_event(
        match action {
            Some("start") => EventKind::StepStart,
            Some("end") => EventKind::StepEnd,
            _ => EventKind::Mark,
        },
        Transport::None,
        t,
        raw,
    );
    ev.api = "MARK".into();
    ev.wall = wall.clone();
    set_meta(&mut ev, "wall", json!(wall));
    set_meta(&mut ev, "action", json!(action.unwrap_or("mark")));
    if let Some(rel) = rel {
        set_meta(&mut ev, "rel", json!(rel));
    }

    if let Some(act) = action {
        let rest_tail = if act == "start" {
            tail.strip_prefix("START").unwrap_or(tail).trim_start()
        } else {
            tail.strip_prefix("END").unwrap_or(tail).trim_start()
        };
        let digits: String = rest_tail
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        let idx = digits.parse::<u32>().unwrap_or(0);
        set_meta(&mut ev, "idx", json!(idx));
        let after_num = rest_tail[digits.len()..].trim_start();
        let title = after_num.strip_prefix(':').unwrap_or(after_num).trim();
        let (title, dur) = strip_duration(title);
        if !title.is_empty() {
            set_meta(&mut ev, "title", json!(title));
            ev.text = Some(title);
        }
        if let Some(dur) = dur {
            set_meta(&mut ev, "dur", json!(dur));
        }
    } else if !tail.is_empty() {
        let (text, dur) = strip_duration(tail);
        if !text.is_empty() {
            ev.text = Some(text);
        }
        if let Some(dur) = dur {
            set_meta(&mut ev, "dur", json!(dur));
        }
    }
    ev
}

fn parse_body(rest: &str, t: f64, raw: &str) -> Event {
    if let Some(ev) = parse_ft_line(rest, t, raw) {
        return ev;
    }
    if let Some(ev) = parse_vcp_line(rest, t, raw) {
        return ev;
    }
    if rest.starts_with("COM ") {
        return parse_com_settings_line(rest, t, raw);
    }
    if rest.starts_with("FILE ") {
        return parse_file_line(rest, t, raw);
    }
    if let Some(after) = rest.strip_prefix("MODULE") {
        return parse_module_line(after, t, raw);
    }
    // ── универсальный захват (docs/02 §11.3) ──────────────────────────
    if rest == "J2534" || rest.starts_with("J2534 ") {
        return parse_j2534_line(rest, t, raw);
    }
    if rest == "LAN" || rest.starts_with("LAN ") {
        return parse_lan_line(rest, t, raw);
    }
    if rest == "USBRAW" || rest.starts_with("USBRAW ") {
        return parse_usbraw_line(rest, t, raw);
    }
    if ["USB ", "WINUSB ", "HID ", "LIBUSB "]
        .iter()
        .any(|p| rest.starts_with(p))
    {
        return parse_usb_line(rest, t, raw);
    }
    if rest.starts_with("FT_") {
        let mut ev = make_event(EventKind::Sys, Transport::Ftd2xx, t, raw);
        let api_end = rest.find(['(', ' ']).unwrap_or(rest.len());
        ev.api = rest[..api_end].to_string();
        ev.text = Some(rest[api_end..].trim().to_string());
        if let Some(rc) = tag_i32(rest, "rc") {
            ev.rc = Some(rc);
        }
        return ev;
    }
    if rest.contains("ftd2xx.dll hooks installed") || rest.contains("ftd2xx.dll not loaded yet") {
        let mut ev = make_event(EventKind::Sys, Transport::Ftd2xx, t, raw);
        ev.api = "FTD2XX".into();
        ev.text = Some(rest.to_string());
        return ev;
    }
    if let Some(after) = rest.strip_prefix("capture script loaded:") {
        let mut ev = make_event(EventKind::Sys, Transport::App, t, raw);
        ev.api = "SCRIPT".into();
        ev.text = Some(after.trim().to_string());
        if let Some(pid) = tag_u64(after, "pid") {
            set_meta(&mut ev, "pid", json!(pid));
        }
        return ev;
    }
    if rest.contains("script-error") || rest.contains("<read-error") || rest.contains("hook fail") {
        let mut ev = make_event(EventKind::Error, Transport::None, t, raw);
        ev.api = "ERROR".into();
        ev.text = Some(rest.to_string());
        return ev;
    }
    if rest.starts_with("VCP ") {
        let mut ev = make_event(EventKind::Vcp, Transport::Vcp, t, raw);
        let after = rest.strip_prefix("VCP ").unwrap_or(rest);
        let api_end = after.find(['(', ' ']).unwrap_or(after.len());
        ev.api = after[..api_end].to_string();
        ev.text = Some(after[api_end..].trim().to_string());
        return ev;
    }
    if rest.starts_with("===") || rest.starts_with("---") {
        let mut ev = make_event(EventKind::Sys, Transport::None, t, raw);
        ev.api = "SEP".into();
        ev.text = Some(rest.to_string());
        return ev;
    }
    let mut ev = make_event(EventKind::Raw, Transport::None, t, raw);
    ev.api = "RAW".into();
    ev.text = Some(rest.to_string());
    ev
}

/// `COM SetCommState(COM8) baud=19200 data=8 parity=NONE stop=1 flow=RTS_CTS rc=0`
///
/// Скорость и тайминги VCP-порта: приложение может менять baud/timeouts на ходу
/// (адаптер переключает скорость) — фиксируем каждое изменение отдельным SYS-событием.
fn parse_com_settings_line(rest: &str, t: f64, raw: &str) -> Event {
    let after = rest.strip_prefix("COM ").unwrap_or(rest);
    let api_end = after.find(['(', ' ']).unwrap_or(after.len());
    let api = after[..api_end].trim().to_string();
    let mut ev = make_event(EventKind::Sys, Transport::Vcp, t, raw);
    ev.api = format!("COM {api}");
    if let Some(port) = paren_arg(after) {
        set_meta_str(&mut ev, "port", Some(port.to_string()));
    }
    if let Some(close) = after.find(')') {
        let body = after[close + 1..].trim();
        if !body.is_empty() {
            ev.text = Some(body.to_string());
            apply_kv_meta(&mut ev, body);
        }
    }
    if let Some(rc) = tag_i32(rest, "rc") {
        ev.rc = Some(rc);
    }
    ev
}

fn parse_ft_line(rest: &str, t: f64, raw: &str) -> Option<Event> {
    let (dir, after) = if let Some(a) = rest.strip_prefix("TX ftd2xx ") {
        (Direction::Tx, a)
    } else if let Some(a) = rest.strip_prefix("RX ftd2xx ") {
        (Direction::Rx, a)
    } else {
        return None;
    };
    let api = after.split_whitespace().next().unwrap_or("").to_string();
    let kind = match dir {
        Direction::Tx => EventKind::Tx,
        Direction::Rx => EventKind::Rx,
    };
    let mut ev = make_event(kind, Transport::Ftd2xx, t, raw);
    ev.api = api;
    ev.direction = Some(dir);
    let (kv, hex) = split_payload(after);
    if let Some(rc) = tag_i32(kv, "rc") {
        ev.rc = Some(rc);
    }
    let declared = tag_u64(kv, "n").or_else(|| tag_u64(kv, "len"));
    set_payload(&mut ev, hex, declared);
    if let Some(want) = tag_u64(kv, "want") {
        set_meta(&mut ev, "want", json!(want));
    }
    Some(ev)
}

fn parse_vcp_line(rest: &str, t: f64, raw: &str) -> Option<Event> {
    let (dir, after) = if let Some(a) = rest.strip_prefix("VCP TX ") {
        (Some(Direction::Tx), a)
    } else if let Some(a) = rest.strip_prefix("VCP RX ") {
        (Some(Direction::Rx), a)
    } else if let Some(a) = rest.strip_prefix("VCP ") {
        // VCP-события без направления: CreateFileW / CloseHandle / настройка порта.
        (None, a)
    } else {
        return None;
    };
    let api_end = after.find(['(', ' ']).unwrap_or(after.len());
    let api = after[..api_end].trim().to_string();
    let com = paren_arg(after).map(|s| s.to_string());
    let after_close = match after.find(')') {
        Some(p) => &after[p + 1..],
        None => &after[api_end..],
    };

    // CreateFileW / CloseHandle — VCP-события без байтов.
    if api == "CreateFileW" || api == "CloseHandle" {
        let mut ev = make_event(EventKind::Vcp, Transport::Vcp, t, raw);
        ev.api = api;
        let (kv, _) = split_payload(after_close);
        if let Some(handle) = tag_value(kv, "handle") {
            set_meta(&mut ev, "handle", json!(handle));
        }
        if let Some(invalid) = tag_value(kv, "invalid") {
            set_meta(&mut ev, "invalid", json!(invalid == "true"));
        }
        if let Some(com) = com {
            set_meta(&mut ev, "com", json!(com.clone()));
            ev.text = Some(com);
        }
        return Some(ev);
    }

    let Some(dir) = dir else {
        // Прочие VCP-вызовы (SetCommState и т.п.) — событие без байтов.
        let mut ev = make_event(EventKind::Vcp, Transport::Vcp, t, raw);
        ev.api = api;
        if let Some(com) = com {
            set_meta(&mut ev, "com", json!(com));
        }
        ev.text = Some(after_close.trim().to_string());
        return Some(ev);
    };

    let kind = match dir {
        Direction::Tx => EventKind::Tx,
        Direction::Rx => EventKind::Rx,
    };
    let mut ev = make_event(kind, Transport::Vcp, t, raw);
    ev.api = api;
    ev.direction = Some(dir);
    if let Some(com) = com {
        set_meta(&mut ev, "com", json!(com));
    }
    let (kv, hex) = split_payload(after_close);
    if let Some(rc) = tag_i32(kv, "rc") {
        ev.rc = Some(rc);
    }
    let n = tag_u64(kv, "n");
    if let Some(ovl) = tag_u64(kv, "ovl") {
        set_meta(&mut ev, "ovl", json!(ovl));
    }
    if kv.contains("одиночные байты") {
        set_meta(&mut ev, "single_bytes", json!(true));
    }
    // Overlapped-чтение: счётчика байт ещё нет, содержимое буфера недостоверно.
    if dir == Direction::Rx && n == Some(0) {
        set_meta(&mut ev, "ovl_zero", json!(true));
    }
    set_payload(&mut ev, hex, n);
    Some(ev)
}

fn parse_file_line(rest: &str, t: f64, raw: &str) -> Event {
    let after = rest.strip_prefix("FILE ").unwrap_or(rest);
    let op = after
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let body = after[op.len()..].trim_start();
    let (path, attrs) = match op.as_str() {
        "open" => split_file_attrs(body, &[" access="]),
        "close" => split_file_attrs(body, &[" bytes="]),
        "write" => split_file_attrs(body, &[" offset=", " n=", " len=", " total="]),
        // Новый формат без пути: `FILE read h=0xe10 off=0x1F0000 len=0x1000 total=0x400000`
        // (docs/11 §8). Путь пустой, дескриптор и смещения — в attrs.
        "read" => {
            let head = body.trim_start();
            if head.starts_with("h=") || head.starts_with("handle=") {
                ("", head)
            } else {
                split_file_attrs(body, &[" offset=", " n=", " len=", " total="])
            }
        }
        "hash" => split_file_attrs(body, &[" size=", " sha256="]),
        _ => split_file_attrs(body, &[" access=", " bytes=", " size="]),
    };

    if op == "hash" {
        let mut ev = make_event(EventKind::FileHash, Transport::File, t, raw);
        ev.api = "FILEHASH".into();
        ev.text = Some(path.to_string());
        set_meta(&mut ev, "path", json!(path));
        if let Some(size) = tag_u64(attrs, "size") {
            set_meta(&mut ev, "size", json!(size));
        }
        if let Some(digest) = tag_value(attrs, "sha256") {
            set_meta(&mut ev, "sha256", json!(digest));
        }
        return ev;
    }

    let mut ev = make_event(EventKind::File, Transport::File, t, raw);
    ev.api = format!("FILE {op}");
    // У нового `FILE read h=…` пути нет: в text кладём остаток строки с ключами.
    let head = if path.is_empty() { attrs.trim() } else { path };
    ev.text = Some(head.to_string());
    set_meta(&mut ev, "op", json!(op));
    if !path.is_empty() {
        set_meta(&mut ev, "path", json!(path));
    }
    if let Some(access) = tag_value(attrs, "access") {
        set_meta(&mut ev, "access", json!(access));
    }
    // Дескриптор: `handle=` (старая форма) или `h=` (docs/11 §8).
    if let Some(handle) = tag_value(attrs, "handle").or_else(|| tag_value(attrs, "h")) {
        set_meta(&mut ev, "handle", json!(handle));
    }
    if let Some(bytes) = tag_u64(attrs, "bytes") {
        set_meta(&mut ev, "bytes", json!(bytes));
        ev.len = bytes.min(u32::MAX as u64) as u32;
    }
    if let Some(writes) = tag_u64(attrs, "writes") {
        set_meta(&mut ev, "writes", json!(writes));
    }
    if let Some(n) = tag_u64(attrs, "n") {
        set_meta(&mut ev, "n", json!(n));
    }
    // `offset=`/`off=` и `len=` — смещение и длина чтения/записи (docs/11 §8).
    set_num_pairs(
        &mut ev,
        attrs,
        &[("offset", "offset"), ("off", "offset"), ("len", "len")],
    );
    if let Some(len) = num_value(tag_value(attrs, "len").unwrap_or("")) {
        // Для чтения len — фактический объём, он же длина события.
        if op == "read" {
            ev.len = len.clamp(0, u32::MAX as i64) as u32;
        }
    }
    if let Some(total) = tag_value(attrs, "total").and_then(num_value) {
        // `total=` бывает и десятичным (старая форма), и `0x400000` (docs/11 §8).
        set_meta(&mut ev, "total", json!(total));
    }
    if let Some(size) = tag_u64(attrs, "size") {
        set_meta(&mut ev, "size", json!(size));
    }
    if let Some(digest) = tag_value(attrs, "sha256") {
        set_meta(&mut ev, "sha256", json!(digest));
    }
    ev
}

fn parse_module_line(after: &str, t: f64, raw: &str) -> Event {
    let mut ev = make_event(EventKind::Module, Transport::None, t, raw);
    ev.api = "MODULE".into();
    let mut text = after.trim_start();
    let mut op = String::new();
    if let Some(inner) = text.strip_prefix('(') {
        if let Some(close) = inner.find(')') {
            op = inner[..close].to_string();
            text = inner[close + 1..].trim_start();
        }
    } else if let Some(rest) = text.strip_prefix('+') {
        op = "+".into();
        text = rest.trim_start();
    } else if let Some(rest) = text.strip_prefix('-') {
        op = "-".into();
        text = rest.trim_start();
    }
    let (head, base) = split_file_attrs(text, &[" base="]);
    let name = head.split_whitespace().next().unwrap_or("").to_string();
    set_meta(&mut ev, "op", json!(op));
    set_meta(&mut ev, "name", json!(name));
    set_meta(&mut ev, "path", json!(head));
    if let Some(base) = tag_value(base, "base") {
        set_meta(&mut ev, "base", json!(base));
    }
    ev.text = Some(head.to_string());
    ev
}

// ─────────────────── J2534 / USB (универсальный захват) ──────────────────

/// Значение `key=...` с поддержкой кавычек (`name="Scanmatik - SM2 USB"`).
fn tag_quoted(text: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let bytes = text.as_bytes();
    let mut search = 0usize;
    while let Some(p) = text[search..].find(&pat) {
        let abs = search + p;
        let before_ok = abs == 0 || matches!(bytes[abs - 1], b' ' | b'\t' | b',' | b'(');
        if !before_ok {
            search = abs + pat.len();
            continue;
        }
        let rest = &text[abs + pat.len()..];
        if let Some(stripped) = rest.strip_prefix('"') {
            return stripped.find('"').map(|end| stripped[..end].to_string());
        }
        let vend = rest
            .find(|c: char| c.is_whitespace() || c == ',' || c == ')')
            .unwrap_or(rest.len());
        return Some(rest[..vend].trim().to_string());
    }
    None
}

/// Значение «до пробела» — для полей, внутри которых есть запятые и `=`
/// (`params=11:0x1aa8c780=5000,…`): `tag_quoted` такие рвёт по запятой.
fn tag_word(text: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let mut search = 0usize;
    while let Some(p) = text[search..].find(&pat) {
        let abs = search + p;
        let before_ok = abs == 0
            || matches!(
                text.as_bytes()[abs - 1],
                b' ' | b'\t' | b',' | b'('
            );
        if !before_ok {
            search = abs + pat.len();
            continue;
        }
        let rest = &text[abs + pat.len()..];
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        return Some(rest[..end].to_string());
    }
    None
}

fn set_meta_str(ev: &mut Event, key: &str, value: Option<String>) {
    if let Some(v) = value {
        if !v.is_empty() {
            set_meta(ev, key, json!(v));
        }
    }
}

/// Разобрать число как `123`, `-1` или `0x1F0000`.
fn num_value(raw: &str) -> Option<i64> {
    let v = raw.trim();
    if let Ok(n) = v.parse::<i64>() {
        return Some(n);
    }
    let hex = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"))?;
    i64::from_str_radix(hex, 16).ok()
}

/// Разложить пары `(тег в строке, ключ в meta)` числами: числовые значения —
/// `json!(n)`, всё остальное (hex-id, `1/2`, имена) — строкой как пришло.
///
/// Нужно, чтобы новые ключи контракта (docs/11 §11) попадали в `meta` без
/// дублирования одного и того же `if let Some(...)` на каждый ключ.
fn set_num_pairs(ev: &mut Event, text: &str, pairs: &[(&str, &str)]) {
    for (tag, key) in pairs {
        let Some(raw) = tag_value(text, tag) else {
            continue;
        };
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        match num_value(raw) {
            Some(n) => set_meta(ev, key, json!(n)),
            None => set_meta(ev, key, json!(raw)),
        }
    }
}

/// `rc=` → поле `ev.rc` и дубль в `meta` (контракт docs/11 §11 требует `rc` в meta).
/// Код возврата бывает и десятичным, и hex (`rc=0x11` в docs/11 §4).
fn set_rc(ev: &mut Event, text: &str) {
    if let Some(rc) = tag_value(text, "rc").and_then(num_value) {
        ev.rc = Some(rc as i32);
        set_meta(ev, "rc", json!(rc));
    }
}

/// `J2534 open/connect-enter/connect/call/TX/RX/ioctl/filter/periodic/disconnect/err`
/// плюс агрегаты компактного режима (`rx-empty`, `tx-err-stat`, `rx-sof-stat`,
/// `chan-miss`, `chan-possibly-open`) — docs/11 (контракт грамматики).
fn parse_j2534_line(rest: &str, t: f64, raw: &str) -> Event {
    let after = rest.strip_prefix("J2534").unwrap_or(rest).trim_start();
    let op_raw = after.split_whitespace().next().unwrap_or("");
    let op = op_raw.to_ascii_lowercase();
    let body = after[op_raw.len()..].trim_start();

    let mut ev = match op.as_str() {
        "tx" | "rx" => {
            let (dir, kind) = if op == "tx" {
                (Direction::Tx, EventKind::Tx)
            } else {
                (Direction::Rx, EventKind::Rx)
            };
            let (kv, hex) = split_payload(body);
            let mut ev = make_event(kind, Transport::J2534, t, raw);
            ev.api = format!("J2534 {}", if dir == Direction::Tx { "TX" } else { "RX" });
            ev.direction = Some(dir);
            set_meta_str(&mut ev, "channel", tag_quoted(kv, "ch").or_else(|| tag_quoted(kv, "channel")));
            let protocol = tag_quoted(kv, "proto").or_else(|| tag_quoted(kv, "protocol"));
            let can_id = tag_quoted(kv, "id").or_else(|| tag_quoted(kv, "can_id"));
            set_meta_str(&mut ev, "protocol", protocol.clone());
            set_meta_str(&mut ev, "can_id", can_id.clone());
            set_meta_str(&mut ev, "flags", tag_quoted(kv, "flags"));
            set_meta_str(&mut ev, "rxs", tag_quoted(kv, "rxs"));
            // Поля вызова (docs/11 §5, §11): сквозной номер вызова, индекс сообщения
            // `i=k/n`, счётчики n_in/n_out, поток, метка драйвера `ts` (всегда,
            // включая нулевую), длительность `dur` и признак SOF-кадра `sof=1`.
            // Любого из них может не быть — строка всё равно разбирается.
            set_num_pairs(
                &mut ev,
                kv,
                &[
                    ("call", "call"),
                    ("n_in", "n_in"),
                    ("n_out", "n_out"),
                    ("th", "thread"),
                    ("ts", "ts"),
                    ("dur", "dur"),
                    ("sof", "sof"),
                    ("xdi", "xdi"),
                    ("idlen", "idlen"),
                ],
            );
            // `i=1/2` — строка как пришла: это не число, а «k из n».
            set_meta_str(&mut ev, "i", tag_quoted(kv, "i"));
            // Сервисный байт кадра: агент вытаскивает его из вендорной обёртки
            // (PCMflash/Scanmatik `0x8003`) или из ISO-TP SF, чтобы сводка шага
            // показывала `0x27 SecurityAccess`, а не `0x8003 ?`.
            let svc = tag_quoted(kv, "svc");
            set_meta_str(&mut ev, "svc", svc.clone());
            if let Some(v) = svc.as_deref().and_then(parse_hex_byte) {
                set_meta(&mut ev, "svc_resp", json!((v & 0x40) != 0));
            }
            if let Some(rc) = tag_i32(kv, "rc") {
                ev.rc = Some(rc);
            }
            let label = match (&can_id, &svc) {
                (Some(id), _) => id.clone(),
                (None, Some(s)) => s.clone(),
                _ => "?".into(),
            };
            ev.text = Some(format!(
                "{} {}",
                protocol.unwrap_or_else(|| "ISO15765".into()),
                label
            ));
            set_payload(&mut ev, hex, tag_u64(kv, "len"));
            ev
        }
        "open" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 open".into();
            let name = tag_quoted(body, "name");
            set_meta_str(&mut ev, "device", name.clone());
            set_meta_str(&mut ev, "vendor", tag_quoted(body, "vendor"));
            set_meta_str(&mut ev, "dll", tag_quoted(body, "dll"));
            // `dev=` — DeviceID из выходного параметра (-1 при ошибке), `th=` — поток.
            // `mod=` — идентификатор загрузки DLL: второй Open без выгрузки даёт тот же mod.
            set_num_pairs(
                &mut ev,
                body,
                &[("dev", "dev"), ("th", "thread"), ("mod", "mod")],
            );
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            ev.text = Some(format!("J2534 open {}", name.unwrap_or_default()).trim_end().to_string());
            ev
        }
        // Вход Connect пишется до вызова, выход — после (docs/11 §3).
        "connect-enter" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 connect-enter".into();
            let protocol = tag_quoted(body, "proto").or_else(|| tag_quoted(body, "protocol"));
            let baud = tag_quoted(body, "baud");
            set_meta_str(&mut ev, "device", tag_quoted(body, "dev"));
            set_meta_str(&mut ev, "protocol", protocol.clone());
            set_meta_str(&mut ev, "flags", tag_quoted(body, "flags"));
            set_meta_str(&mut ev, "baud", baud.clone());
            set_num_pairs(&mut ev, body, &[("th", "thread")]);
            ev.text = Some(format!(
                "connect-enter proto={} baud={}",
                protocol.unwrap_or_else(|| "?".into()),
                baud.unwrap_or_else(|| "?".into())
            ));
            ev
        }
        // Строка вызова (docs/11 §4): когда сообщений нет, их несколько или
        // вызов завершился ошибкой — общие поля живут здесь, а не на сообщениях.
        "call" => {
            let (kv, _hex) = split_payload(body);
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 call".into();
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(kv, "ch").or_else(|| tag_quoted(kv, "channel")),
            );
            set_meta_str(&mut ev, "op", tag_quoted(kv, "op"));
            set_num_pairs(
                &mut ev,
                kv,
                &[
                    ("call", "call"),
                    ("n_in", "n_in"),
                    ("n_out", "n_out"),
                    ("th", "thread"),
                    ("dur", "dur"),
                    ("timeout_ms", "timeout_ms"),
                ],
            );
            // Признаки нарушения контракта драйвера: `partial=1` — сообщения при
            // rc!=0, `contract=` — n_out > n_in или пустой ответ с сообщениями.
            set_meta_str(&mut ev, "partial", tag_quoted(kv, "partial"));
            set_meta_str(&mut ev, "contract", tag_quoted(kv, "contract"));
            set_rc(&mut ev, kv);
            ev.text = Some(format!(
                "{} ch={} call={} n_in={} n_out={}",
                tag_quoted(kv, "op").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "ch").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "call").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "n_in").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "n_out").unwrap_or_else(|| "?".into()),
            ));
            ev
        }
        "connect" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 connect".into();
            let channel = tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel"));
            let protocol = tag_quoted(body, "proto").or_else(|| tag_quoted(body, "protocol"));
            set_meta_str(&mut ev, "device", tag_quoted(body, "dev"));
            set_meta_str(&mut ev, "channel", channel.clone());
            set_meta_str(&mut ev, "protocol", protocol.clone());
            set_meta_str(&mut ev, "flags", tag_quoted(body, "flags"));
            set_meta_str(&mut ev, "baud", tag_quoted(body, "baud"));
            // `gen` растёт после успешного connect этого канала (ключ канала:
            // pid | module_load_id | ch | gen), `th` — поток, `dur` — длительность.
            set_num_pairs(
                &mut ev,
                body,
                &[("gen", "gen"), ("th", "thread"), ("dur", "dur")],
            );
            set_rc(&mut ev, body);
            ev.text = Some(format!(
                "connect proto={} ch={}",
                protocol.unwrap_or_else(|| "?".into()),
                channel.unwrap_or_else(|| "?".into())
            ));
            ev
        }
        "ioctl" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 ioctl".into();
            let channel = tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel"));
            let ioctl_id = tag_quoted(body, "id").or_else(|| tag_quoted(body, "ioctl"));
            set_meta_str(&mut ev, "channel", channel.clone());
            set_meta_str(&mut ev, "ioctl_id", ioctl_id.clone());
            // `(FAST_INIT)` — имя IOCTL из таблицы PT_IOCTL_NAMES (docs/11 §6).
            set_meta_str(&mut ev, "ioctl_name", paren_arg(body).map(|s| s.trim().to_string()));
            // `in=`/`out=` — Data[DataSize] слитным hex; `out=none` — содержимое
            // недоступно (есть только причина в `reason=`).
            set_meta_str(&mut ev, "in", tag_quoted(body, "in"));
            set_meta_str(&mut ev, "out", tag_quoted(body, "out"));
            set_meta_str(&mut ev, "reason", tag_quoted(body, "reason"));
            set_num_pairs(
                &mut ev,
                body,
                &[
                    ("call", "call"),
                    ("in_size", "in_size"),
                    ("out_size", "out_size"),
                    ("dec", "dec"),
                    ("len_invalid", "len_invalid"),
                    ("in_ptr", "in_ptr"),
                    ("out_ptr", "out_ptr"),
                    ("th", "thread"),
                    ("dur", "dur"),
                ],
            );
            set_rc(&mut ev, body);
            ev.text = Some(format!(
                "ioctl {} ch={}",
                ioctl_id.unwrap_or_else(|| "?".into()),
                channel.unwrap_or_else(|| "?".into())
            ));
            ev
        }
        // Фильтр (docs/11 §7, F3): маска и паттерн — Data[DataSize] слитным hex,
        // `flow=-` при pFlowControlMsg = NULL, `id=` — FilterID из выхода.
        "filter" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 filter".into();
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel")),
            );
            set_meta_str(&mut ev, "filter_type", tag_quoted(body, "type"));
            set_meta_str(&mut ev, "mask", tag_quoted(body, "mask"));
            set_meta_str(&mut ev, "pattern", tag_quoted(body, "pattern"));
            set_meta_str(&mut ev, "flow", tag_quoted(body, "flow"));
            set_meta_str(&mut ev, "mask_proto", tag_quoted(body, "mask_proto"));
            set_meta_str(&mut ev, "mask_flags", tag_quoted(body, "mask_flags"));
            set_meta_str(&mut ev, "pattern_proto", tag_quoted(body, "pattern_proto"));
            set_meta_str(&mut ev, "pattern_flags", tag_quoted(body, "pattern_flags"));
            // `proto`/`flags` в хвосте — из pPatternMsg.
            set_meta_str(&mut ev, "proto", tag_quoted(body, "proto"));
            set_meta_str(&mut ev, "flags", tag_quoted(body, "flags"));
            set_meta_str(&mut ev, "filter_id", tag_quoted(body, "id"));
            set_num_pairs(&mut ev, body, &[("call", "call"), ("th", "thread"), ("dur", "dur")]);
            set_rc(&mut ev, body);
            ev.text = Some(format!(
                "filter type={} id={} ch={}",
                tag_quoted(body, "type").unwrap_or_else(|| "?".into()),
                tag_quoted(body, "id").unwrap_or_else(|| "?".into()),
                tag_quoted(body, "ch").unwrap_or_else(|| "?".into())
            ));
            ev
        }
        // `filter-stop` / `periodic-stop`: снятие фильтра и периодики.
        "filter-stop" | "periodic-stop" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = format!("J2534 {op}");
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel")),
            );
            set_meta_str(&mut ev, "filter_id", tag_quoted(body, "id"));
            set_num_pairs(&mut ev, body, &[("call", "call"), ("th", "thread"), ("dur", "dur")]);
            set_rc(&mut ev, body);
            ev.text = Some(format!(
                "{op} id={} ch={}",
                tag_quoted(body, "id").unwrap_or_else(|| "?".into()),
                tag_quoted(body, "ch").unwrap_or_else(|| "?".into())
            ));
            ev
        }
        // Периодическая посылка (docs/11 §7): `ms=` — интервал, payload — `: hex`.
        "periodic-start" => {
            let (kv, hex) = split_payload(body);
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 periodic-start".into();
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(kv, "ch").or_else(|| tag_quoted(kv, "channel")),
            );
            set_meta_str(&mut ev, "filter_id", tag_quoted(kv, "id"));
            set_meta_str(&mut ev, "protocol", tag_quoted(kv, "proto"));
            set_meta_str(&mut ev, "flags", tag_quoted(kv, "flags"));
            set_num_pairs(
                &mut ev,
                kv,
                &[("call", "call"), ("ms", "interval"), ("th", "thread"), ("dur", "dur")],
            );
            set_rc(&mut ev, kv);
            set_payload(&mut ev, hex, tag_u64(kv, "len"));
            ev.text = Some(format!(
                "periodic-start id={} ms={} ch={}",
                tag_quoted(kv, "id").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "ms").unwrap_or_else(|| "?".into()),
                tag_quoted(kv, "ch").unwrap_or_else(|| "?".into())
            ));
            ev
        }
        // Агрегаты компактного режима и диагностика рассинхронизации канала
        // (docs/11 §3, §5). `rx-empty` — штатный таймаут опроса, а не ошибка:
        // в `errors` он попадал и создавал ложную картину (docs/12 §10).
        "rx-empty" | "tx-err-stat" | "chan-miss" => {
            let kind = if op_raw == "rx-empty" {
                EventKind::Sys
            } else {
                EventKind::Error
            };
            let mut ev = make_event(kind, Transport::J2534, t, raw);
            ev.api = format!("J2534 {op}");
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel")),
            );
            set_meta_str(&mut ev, "first_op", tag_quoted(body, "first_op"));
            // `timeout_ms=` в контракте, `timeout=` — запасное имя того же поля.
            set_num_pairs(
                &mut ev,
                body,
                &[
                    ("call", "call"),
                    ("n", "n"),
                    ("gen", "gen"),
                    ("mod", "mod"),
                    ("th", "thread"),
                    ("timeout_ms", "timeout_ms"),
                    ("timeout", "timeout_ms"),
                    ("last_rc", "last_rc"),
                ],
            );
            // `last_rc` уже разложен выше числами; здесь только дубль в поле `rc`.
            // Для этих строк `rc=` — код прошлого вызова, а не результат строки.
            if let Some(rc) =
                tag_value(body, "last_rc").or_else(|| tag_value(body, "rc")).and_then(num_value)
            {
                ev.rc = Some(rc as i32);
            }
            ev.text = Some(body.to_string());
            ev
        }
        "chan-possibly-open" | "rx-sof-stat" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = format!("J2534 {op}");
            set_meta_str(
                &mut ev,
                "channel",
                tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel")),
            );
            set_meta_str(&mut ev, "reason", tag_quoted(body, "reason"));
            set_num_pairs(&mut ev, body, &[("gen", "gen"), ("n", "n")]);
            ev.text = Some(body.to_string());
            ev
        }
        // SET_CONFIG: параметры канала, включая DATA_RATE (битрейт CAN/ISO15765),
        // тайминги W1..W5, P1..P4, ISO15765_BS/STMIN — «скорость и тайминги» J2534.
        "config" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 config".into();
            set_meta_str(&mut ev, "channel", tag_quoted(body, "ch"));
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            if let Some(pos) = body.find("rc=") {
                let cfg = body[..pos].trim();
                ev.text = Some(cfg.to_string());
                apply_kv_meta(&mut ev, cfg);
            } else {
                ev.text = Some(body.to_string());
                apply_kv_meta(&mut ev, body);
            }
            ev
        }
        "disconnect" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = "J2534 disconnect".into();
            let channel = tag_quoted(body, "ch").or_else(|| tag_quoted(body, "channel"));
            set_meta_str(&mut ev, "channel", channel.clone());
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            ev.text = Some(format!("disconnect ch={}", channel.unwrap_or_else(|| "?".into())));
            ev
        }
        "err" | "error" | "rx-error" | "tx-error" => {
            let mut ev = make_event(EventKind::Error, Transport::J2534, t, raw);
            ev.api = format!(
                "J2534 {}",
                if op_raw.is_empty() { "err" } else { op_raw }
            );
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            set_meta_str(&mut ev, "channel", tag_quoted(body, "ch"));
            set_meta_str(&mut ev, "op", tag_quoted(body, "op"));
            ev.text = Some(body.to_string());
            ev
        }
        // Вендорские ординалы 1377-1379: дамп аргументов и разобранные пары
        // (docs/13 §6.3). Дампы mem/pre в meta не копируем — только длины:
        // они и так лежат в raw и в raw-proxy.log, а JSONL не должен пухнуть.
        "vendor" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            let ord = tag_quoted(body, "ord").unwrap_or_default();
            ev.api = "J2534 vendor".into();
            set_meta_str(&mut ev, "ord", Some(ord.clone()));
            set_meta_str(&mut ev, "op", tag_quoted(body, "op"));
            set_meta_str(&mut ev, "arg", tag_quoted(body, "arg"));
            set_meta_str(&mut ev, "a2", tag_quoted(body, "a2"));
            set_meta_str(&mut ev, "a3", tag_quoted(body, "a3"));
            set_meta_str(&mut ev, "ret", tag_quoted(body, "ret"));
            if let Some(params) = tag_word(body, "params") {
                if let Some((count, _)) = params.split_once(':') {
                    if let Ok(n) = count.parse::<u64>() {
                        set_meta(&mut ev, "count", json!(n));
                    }
                }
                set_meta_str(&mut ev, "params", Some(params));
            }
            for key in ["mem", "pre"] {
                if let Some(dump) = tag_word(body, key) {
                    if dump != "-" && dump != "<unreadable>" {
                        set_meta(&mut ev, format!("{key}_len").as_str(), json!(dump.len() / 2));
                    }
                }
            }
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            ev.text = Some(format!(
                "vendor {ord} op={} ret={} params={}",
                tag_quoted(body, "op").unwrap_or_default(),
                tag_quoted(body, "ret").unwrap_or_default(),
                tag_word(body, "params").unwrap_or_default()
            ));
            ev
        }
        // PassThruSetProgrammingVoltage: питание на пине (BitBox/Scanmatik включают 12 В им),
        // PassThruReadVersion: версии FW/DLL/API. Оба — SYS, к обмену не относятся,
        // но без них в логе слепые зоны (почему адаптер молчит 5 секунд и т.п.).
        "voltage" | "version" | "close" | "config-get" | "select" => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = format!(
                "J2534 {}",
                if op_raw.is_empty() { "?" } else { op_raw }
            );
            set_meta_str(&mut ev, "channel", tag_quoted(body, "ch"));
            set_meta_str(&mut ev, "pin", tag_quoted(body, "pin"));
            set_meta_str(&mut ev, "voltage", tag_quoted(body, "mv"));
            set_meta_str(&mut ev, "fw", tag_quoted(body, "fw"));
            set_meta_str(&mut ev, "dll", tag_quoted(body, "dll"));
            set_meta_str(&mut ev, "api", tag_quoted(body, "api"));
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            ev.text = Some(body.to_string());
            ev
        }
        _ => {
            let mut ev = make_event(EventKind::Sys, Transport::J2534, t, raw);
            ev.api = format!(
                "J2534 {}",
                if op_raw.is_empty() { "?" } else { op_raw }
            );
            set_meta_str(&mut ev, "channel", tag_quoted(body, "ch"));
            if let Some(rc) = tag_i32(body, "rc") {
                ev.rc = Some(rc);
            }
            // Незнакомая операция не теряется: все её `ключ=значение` уходят в meta
            // (docs/11, общие правила), а строка целиком — в text и raw.
            apply_kv_meta(&mut ev, body);
            ev.text = Some(body.to_string());
            ev
        }
    };

    // Слой и вложенность проставляет агент на каждый вызов J2534 (docs/13 §6.2),
    // поэтому их надо сохранить у ЛЮБОЙ операции, а не только у незнакомой:
    // без `parent=` вложенный вызов прокси не отличить от самостоятельного, и
    // счётчики удваивают трафик.
    set_meta_str(&mut ev, "layer", tag_quoted(body, "layer"));
    if let Some(parent) = tag_u64(body, "parent") {
        set_meta(&mut ev, "parent", json!(parent));
    }
    ev
}

/// LAN/Winsock — сетевой обмен (docs/02 §11.4): J2534-по-IP, DoIP (ISO 13400),
/// BMW ICOM/HSFZ, любые диагностические адаптеры с Ethernet/Wi-Fi.
///
/// ```text
/// LAN CONNECT tcp fd=0x1a4 local=192.168.1.5:50123 remote=192.168.1.10:13400 rc=0
/// LAN TX tcp local=192.168.1.5:50123 remote=192.168.1.10:13400 len=32 : 02 fd 00 01 …
/// LAN RX tcp local=192.168.1.10:13400 remote=192.168.1.5:50123 len=40 : 02 fd 80 01 …
/// LAN CLOSE tcp fd=0x1a4 local=… remote=… bytes=1234 reads=9 writes=7
/// LAN ERR tcp fd=0x1a4 op=WSARecv rc=-1 wsa=10054
/// ```
///
/// TX/RX несут payload и попадают в сводку шага; connect/close/err — служебные `sys`,
/// чтобы в потоке было видно установку, обрыв и ошибки сокета.
fn parse_lan_line(rest: &str, t: f64, raw: &str) -> Event {
    let after = rest.strip_prefix("LAN").unwrap_or(rest).trim_start();
    let op_raw = after.split_whitespace().next().unwrap_or("");
    let op = op_raw.to_ascii_lowercase();
    let body = after[op_raw.len()..].trim_start();
    let (kv, hex) = split_payload(body);

    // Первый токен после операции — протокол L4 (`tcp`/`udp`), как его пишет агент.
    let l4 = kv
        .split_whitespace()
        .next()
        .filter(|s| s.eq_ignore_ascii_case("tcp") || s.eq_ignore_ascii_case("udp"))
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    let local = tag_quoted(kv, "local");
    let remote = tag_quoted(kv, "remote");

    if op == "tx" || op == "rx" {
        let (dir, kind) = if op == "tx" {
            (Direction::Tx, EventKind::Tx)
        } else {
            (Direction::Rx, EventKind::Rx)
        };
        let mut ev = make_event(kind, Transport::Lan, t, raw);
        ev.api = format!("LAN {}", if dir == Direction::Tx { "TX" } else { "RX" });
        ev.direction = Some(dir);
        set_meta_str(&mut ev, "l4", Some(l4.clone()));
        set_meta_str(&mut ev, "local", local.clone());
        set_meta_str(&mut ev, "remote", remote.clone());
        if let Some(rc) = tag_i32(kv, "rc") {
            ev.rc = Some(rc);
        }
        let payload = hex.map(hex_to_bytes).unwrap_or_default();
        let proto = lan_proto_hint(&l4, remote.as_deref(), &payload);
        set_meta_str(&mut ev, "protocol", Some(proto.clone()));
        ev.text = Some(format!(
            "{proto} {}",
            remote.clone().unwrap_or_else(|| l4.to_ascii_uppercase())
        ));
        set_payload(&mut ev, hex, tag_u64(kv, "len"));
        return ev;
    }

    let mut ev = make_event(EventKind::Sys, Transport::Lan, t, raw);
    // `LAN module: ws2_32.dll …` — двоеточие в имени операции не часть api.
    let op_name = op_raw.trim_end_matches(':');
    ev.api = format!("LAN {}", if op_name.is_empty() { "?" } else { op_name });
    set_meta_str(&mut ev, "l4", Some(l4));
    set_meta_str(&mut ev, "local", local);
    set_meta_str(&mut ev, "remote", remote);
    set_meta_str(&mut ev, "fd", tag_quoted(kv, "fd"));
    set_meta_str(&mut ev, "op", tag_quoted(kv, "op"));
    if let Some(bytes) = tag_u64(kv, "bytes") {
        set_meta(&mut ev, "bytes", json!(bytes));
    }
    if let Some(rc) = tag_i32(kv, "rc") {
        ev.rc = Some(rc);
    }
    ev.text = Some(body.to_string());
    ev
}

/// Подсказка «что за протокол поверх TCP/UDP»: DoIP по заголовку, дальше — по порту.
/// Это именно подсказка: неизвестный порт остаётся `TCP`/`UDP`.
fn lan_proto_hint(l4: &str, remote: Option<&str>, payload: &[u8]) -> String {
    if payload.len() >= 2 && payload[0] == 0x02 && payload[1] == 0xFD {
        return "DoIP".to_string();
    }
    let port = remote
        .and_then(|r| r.rsplit(':').next())
        .and_then(|p| p.parse::<u16>().ok());
    match port {
        Some(13400) => "DoIP".to_string(),
        Some(6801) => "HSFZ".to_string(),
        Some(7777) | Some(7778) => "J2534-IP".to_string(),
        _ => l4.to_ascii_uppercase(),
    }
}

/// `USB open/close`, `WINUSB/HID/LIBUSB TX/RX` и `USB/HID ioctl` (docs/02 §11.3).
fn parse_usb_line(rest: &str, t: f64, raw: &str) -> Event {
    let (prefix, after) = if let Some(a) = rest.strip_prefix("WINUSB ") {
        ("WINUSB", a)
    } else if let Some(a) = rest.strip_prefix("HID ") {
        ("HID", a)
    } else if let Some(a) = rest.strip_prefix("LIBUSB ") {
        ("LIBUSB", a)
    } else {
        ("USB", rest.strip_prefix("USB ").unwrap_or(rest))
    };
    let op_raw = after.split_whitespace().next().unwrap_or("");
    let op = op_raw.to_ascii_lowercase();
    let body = after[op_raw.len()..].trim_start();
    let (kv, hex) = split_payload(body);

    // Обмен WINUSB/HID/LIBUSB (и USB, если когда-нибудь появится).
    if matches!(prefix, "WINUSB" | "HID" | "LIBUSB" | "USB") && (op == "tx" || op == "rx") {
        let (dir, kind) = if op == "tx" {
            (Direction::Tx, EventKind::Tx)
        } else {
            (Direction::Rx, EventKind::Rx)
        };
        let mut ev = make_event(kind, Transport::Usb, t, raw);
        ev.api = format!("{prefix} {}", if dir == Direction::Tx { "TX" } else { "RX" });
        ev.direction = Some(dir);
        let attr = match prefix {
            "WINUSB" => ("pipe", tag_quoted(kv, "pipe")),
            "LIBUSB" => ("ep", tag_quoted(kv, "ep")),
            "HID" => ("report", tag_quoted(kv, "report")),
            _ => ("pipe", tag_quoted(kv, "pipe")),
        };
        set_meta_str(&mut ev, attr.0, attr.1.clone());
        if let Some(rc) = tag_i32(kv, "rc") {
            ev.rc = Some(rc);
        }
        ev.text = Some(match attr.1 {
            Some(v) => format!("{prefix} {}={v}", attr.0),
            None => format!("{prefix} {}", if dir == Direction::Tx { "TX" } else { "RX" }),
        });
        set_payload(&mut ev, hex, tag_u64(kv, "len"));
        return ev;
    }

    // USB open/close/ioctl и прочие USB*-вызовы — EventKind::Usb.
    let mut ev = make_event(EventKind::Usb, Transport::Usb, t, raw);
    ev.api = format!("{prefix} {}", if op_raw.is_empty() { "?" } else { op_raw });
    let path = tag_quoted(kv, "path");
    set_meta_str(&mut ev, "path", path.clone());
    set_meta_str(&mut ev, "device", path.clone());
    set_meta_str(&mut ev, "kind", tag_quoted(kv, "kind"));
    set_meta_str(&mut ev, "handle", tag_quoted(kv, "handle"));
    if let Some(bytes) = tag_u64(kv, "bytes") {
        set_meta(&mut ev, "bytes", json!(bytes));
        ev.len = bytes.min(u32::MAX as u64) as u32;
    }
    if let Some(writes) = tag_u64(kv, "writes") {
        set_meta(&mut ev, "writes", json!(writes));
    }
    if let Some(rc) = tag_i32(kv, "rc") {
        ev.rc = Some(rc);
    }
    if let Some(hex) = hex {
        if !hex.is_empty() {
            set_payload(&mut ev, Some(hex), tag_u64(kv, "len"));
        }
    }
    let mut text = format!("{prefix} {op_raw}");
    if let Some(path) = &path {
        text.push(' ');
        text.push_str(path);
    } else if !body.is_empty() {
        text.push(' ');
        text.push_str(body);
    }
    ev.text = Some(text.trim().to_string());
    ev
}

/// USBPcap raw-захват:
/// `USBRAW bus=1 dev=4 ep=0x01 bulk fdo->pdo func=0x9 status=0x0 len=4 : 12 04 0d 1b`.
///
/// Направление `fdo->pdo` — TX, `pdo->fdo` — RX. Кадры без данных (`len=0`, обычно
/// control) идут как `EventKind::Sys`, чтобы не засорять поток обмена.
fn parse_usbraw_line(rest: &str, t: f64, raw: &str) -> Event {
    let after = rest.strip_prefix("USBRAW").unwrap_or(rest).trim_start();
    let (kv, hex) = split_payload(after);

    let mut transfer = String::new();
    let mut direction: Option<Direction> = None;
    for token in kv.split_whitespace() {
        match token.to_ascii_lowercase().as_str() {
            "isochronous" | "interrupt" | "control" | "bulk" | "unknown" => {
                transfer = token.to_ascii_lowercase()
            }
            "fdo->pdo" | "out" => direction = Some(Direction::Tx),
            "pdo->fdo" | "in" => direction = Some(Direction::Rx),
            _ => {}
        }
    }

    let bus = tag_u64(kv, "bus");
    let device = tag_u64(kv, "dev").or_else(|| tag_u64(kv, "device"));
    let endpoint = tag_quoted(kv, "ep").or_else(|| tag_quoted(kv, "endpoint"));
    let function = tag_quoted(kv, "func").or_else(|| tag_quoted(kv, "function"));
    let status = tag_quoted(kv, "status");
    let declared = tag_u64(kv, "len");
    let payload_bytes = hex.map(hex_to_bytes).unwrap_or_default();
    let no_data = payload_bytes.is_empty() && declared.unwrap_or(0) == 0;

    let mut ev = if no_data {
        make_event(EventKind::Sys, Transport::Usb, t, raw)
    } else {
        let dir = direction.unwrap_or_else(|| {
            let ep = endpoint
                .as_deref()
                .map(|s| s.trim())
                .map(|s| s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s))
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .unwrap_or(0);
            if ep & 0x80 != 0 {
                Direction::Rx
            } else {
                Direction::Tx
            }
        });
        let kind = if dir == Direction::Tx {
            EventKind::Tx
        } else {
            EventKind::Rx
        };
        let mut e = make_event(kind, Transport::Usb, t, raw);
        e.direction = Some(dir);
        e
    };
    // Как и в живых событиях capture (boba): control-setup без данных — `USBRAW-SETUP`,
    // остальной обмен — `USBRAW`. Это сохраняет одинаковую семантику после импорта raw.log.
    ev.api = if no_data && transfer == "control" {
        "USBRAW-SETUP".into()
    } else {
        "USBRAW".into()
    };
    if let Some(bus) = bus {
        set_meta(&mut ev, "bus", json!(bus));
    }
    if let Some(device) = device {
        set_meta(&mut ev, "device", json!(device));
    }
    if let Some(endpoint) = &endpoint {
        set_meta(&mut ev, "endpoint", json!(endpoint));
    }
    if !transfer.is_empty() {
        set_meta(&mut ev, "transfer", json!(transfer));
    }
    if let Some(function) = &function {
        set_meta(&mut ev, "function", json!(function));
    }
    if let Some(status) = &status {
        set_meta(&mut ev, "status", json!(status));
    }
    set_meta(&mut ev, "usbpcap", json!(true));
    if no_data {
        ev.len = 0;
    } else {
        set_payload(&mut ev, hex, declared);
    }
    let ep_text = endpoint.unwrap_or_else(|| "?".into());
    ev.text = Some(if transfer.is_empty() {
        format!("USBRAW ep={ep_text}")
    } else {
        format!("USBRAW {transfer} ep={ep_text}")
    });
    ev
}

// ────────────────────────────── телеграммы ───────────────────────────────
struct Exchange {
    tx_t: f64,
    api: String,
    tx: Vec<u8>,
    rx: Vec<u8>,
    rx_trunc: bool,
}

impl Exchange {
    fn new(ev: &Event) -> Self {
        Self {
            tx_t: ev.t,
            api: ev.api.clone(),
            tx: ev.payload(),
            rx: Vec::new(),
            rx_trunc: false,
        }
    }

    fn push_rx(&mut self, ev: &Event) {
        if meta_bool(ev, "ovl_zero") {
            // содержимое буфера недостоверно — в разбор не берём (как старый логер)
            self.rx_trunc = true;
            return;
        }
        self.rx.extend_from_slice(&ev.payload());
        if meta_bool(ev, "short") || meta_bool(ev, "truncated") {
            self.rx_trunc = true;
        }
    }
}

fn collect_exchanges(events: &[&Event]) -> Vec<Exchange> {
    let mut out: Vec<Exchange> = Vec::new();
    for ev in events {
        // J2534/USB-обмен разбирается отдельно (по can_id/pipe), не как serial-телеграммы.
        let serial = matches!(
            ev.transport,
            Transport::Ftd2xx | Transport::Vcp | Transport::None
        );
        if !serial {
            continue;
        }
        match ev.kind {
            EventKind::Tx => out.push(Exchange::new(ev)),
            EventKind::Rx => {
                if let Some(cur) = out.last_mut() {
                    cur.push_rx(ev);
                }
            }
            _ => {}
        }
    }
    out
}

/// «Есть эхо?» + остаток после эха (эхо — точный префикс RX, равный TX).
pub fn split_echo_response(tx: &[u8], rx: &[u8]) -> (bool, Vec<u8>) {
    if !tx.is_empty() && rx.starts_with(tx) {
        (true, rx[tx.len()..].to_vec())
    } else {
        (false, rx.to_vec())
    }
}

fn fmt_hex(bytes: &[u8], max_bytes: usize) -> String {
    let mut s = bytes
        .iter()
        .take(max_bytes)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > max_bytes {
        s.push_str(&format!(" … ({} B)", bytes.len()));
    }
    s
}

/// Короткая подпись TX-посылки: `SVC(10,85)` для KWP-кадров ME7.2, иначе `cmd=0xNN`.
pub fn tx_summary(tx: &[u8]) -> String {
    if tx.len() >= 5 && tx[0] == 0xB8 {
        let svc = tx[4];
        if KWP_SUB_SVC.contains(&svc) && tx.len() > 5 {
            return format!("SVC({svc:02X},{:02X})", tx[5]);
        }
        return format!("SVC({svc:02X})");
    }
    if tx.len() >= 3 {
        return format!("cmd=0x{:02X}", tx[2]);
    }
    bytes_to_hex(tx)
}

/// Разобрать кадр ответа. Класс: `A0` / `A2-denied` / `0xNN` / `7F(svc,nrc[-имя])` /
/// `pos(svc)` / `b8(..)` / `unparsed(..)` / `no-answer`.
pub fn parse_frame(tx: &[u8], residual: &[u8]) -> (String, Vec<u8>, Vec<u8>) {
    if residual.is_empty() {
        return ("no-answer".into(), Vec::new(), Vec::new());
    }
    if !tx.is_empty() && tx[0] == 0xB8 && residual[0] == 0xB8 && residual.len() >= 5 {
        let ln = residual[3] as usize;
        let total = 4 + ln + 1;
        if total <= residual.len() {
            let data = &residual[4..4 + ln];
            let tail = residual[total..].to_vec();
            if data.is_empty() {
                return ("b8-empty".into(), Vec::new(), tail);
            }
            if data[0] == 0x7F {
                if data.len() >= 3 {
                    let nrc = kwp_nrc_name(data[2]);
                    let name = nrc.map(|n| format!("-{n}")).unwrap_or_default();
                    return (
                        format!("7F({:02X},{:02X}{})", data[1], data[2], name),
                        Vec::new(),
                        tail,
                    );
                }
                return ("7F-short".into(), Vec::new(), tail);
            }
            if data[0] & 0xC0 == 0x40 {
                return (format!("pos({:02X})", data[0] - 0x40), data[1..].to_vec(), tail);
            }
            return (format!("b8({:02X})", data[0]), data[1..].to_vec(), tail);
        }
        return (format!("b8-short(len={ln})"), Vec::new(), Vec::new());
    }
    if !tx.is_empty() && residual.len() >= 3 && residual[0] == tx[0] {
        let ln = residual[1] as usize;
        if (3..=residual.len()).contains(&ln) {
            let frame = &residual[..ln];
            let tail = residual[ln..].to_vec();
            let status = frame[2];
            if status == 0xA0 {
                let payload = if ln >= 4 {
                    frame[3..ln - 1].to_vec()
                } else {
                    Vec::new()
                };
                return ("A0".into(), payload, tail);
            }
            if status == 0xA2 {
                return ("A2-denied".into(), Vec::new(), tail);
            }
            return (format!("0x{status:02X}"), Vec::new(), tail);
        }
        return (format!("short-frame(len={ln})"), Vec::new(), Vec::new());
    }
    (
        format!("unparsed({})", fmt_hex(residual, 8)),
        Vec::new(),
        Vec::new(),
    )
}

/// Семейное чтение памяти: `12 <len> 06 <addr32> <blen> <cks>` → (addr, blen).
pub fn read_telegram(tx: &[u8]) -> Option<(u32, u8)> {
    if tx.len() >= 9 && tx[2] == 0x06 {
        let addr = u32::from_be_bytes([tx[3], tx[4], tx[5], tx[6]]);
        return Some((addr, tx[7]));
    }
    None
}

/// Склеить чтения в потоки: последовательные адреса объединяются.
pub fn stream_ranges(read_events: &[(u32, Vec<u8>, f64)]) -> Vec<StepRead> {
    let mut out: Vec<(u32, Vec<u8>, u64)> = Vec::new();
    for (addr, blob, _t) in read_events {
        if let Some(last) = out.last_mut() {
            if last.0 as u64 + last.1.len() as u64 == *addr as u64 {
                last.1.extend_from_slice(blob);
                last.2 += 1;
                continue;
            }
        }
        out.push((*addr, blob.clone(), 1));
    }
    out.into_iter()
        .map(|(start, bytes, blocks)| StepRead {
            start: start as u64,
            len: bytes.len() as u64,
            blocks,
            sha256: sha256_hex(&bytes),
        })
        .collect()
}

pub fn split_telegrams(events: &[Event]) -> Vec<Telegram> {
    let refs: Vec<&Event> = events.iter().collect();
    collect_exchanges(&refs)
        .into_iter()
        .map(|ex| {
            let (echo, residual) = split_echo_response(&ex.tx, &ex.rx);
            let (klass, payload, tail) = parse_frame(&ex.tx, &residual);
            let cmd = if let Some((addr, blen)) = read_telegram(&ex.tx) {
                if payload.is_empty() {
                    tx_summary(&ex.tx)
                } else {
                    format!("READ 0x{addr:06X} +{blen}")
                }
            } else {
                tx_summary(&ex.tx)
            };
            let mut resp = klass;
            if !payload.is_empty() {
                resp.push_str(&format!(" payload={}B {}", payload.len(), fmt_hex(&payload, 6)));
            }
            if !tail.is_empty() {
                resp.push_str(&format!(" tail={}", fmt_hex(&tail, 8)));
            }
            Telegram {
                t: ex.tx_t,
                dir: Some(Direction::Tx),
                api: ex.api.clone(),
                hex: bytes_to_hex(&ex.tx),
                cmd: Some(cmd),
                resp: Some(resp),
                echo,
            }
        })
        .collect()
}

// ────────────────────────────── сводка шага ──────────────────────────────

fn event_marker_idx(ev: &Event) -> Option<u32> {
    meta_idx(ev)
}

fn select_step_events<'a>(events: &'a [Event], idx: u32) -> Vec<&'a Event> {
    if let Some(start) = events
        .iter()
        .position(|e| e.kind == EventKind::StepStart && event_marker_idx(e) == Some(idx))
    {
        // Старый логер считает сводку по срезу файла от MARK START до блока PHASE:
        // хвост после MARK END (filehash, хвосты обмена) тоже входит в шаг.
        let mut out = Vec::new();
        for ev in &events[start + 1..] {
            match ev.kind {
                EventKind::StepStart => break,
                EventKind::Summary => {
                    out.push(ev);
                    if ev.api == "PHASE-JSON" && event_marker_idx(ev) == Some(idx) {
                        break; // PHASE-JSON — последняя строка блока шага
                    }
                }
                _ => out.push(ev),
            }
        }
        return out;
    }
    if events.iter().any(|e| e.step == Some(idx)) {
        return events.iter().filter(|e| e.step == Some(idx)).collect();
    }
    events.iter().collect()
}

fn phase_json_for(events: &[Event], idx: u32) -> Option<Value> {
    events
        .iter()
        .rev()
        .find(|e| {
            e.api == "PHASE-JSON" && e.kind == EventKind::Summary && meta_idx(e) == Some(idx)
        })
        .map(|e| e.meta.clone())
}

/// Дополнить сведения об адаптере из события `J2534 open` / `J2534 version`.
///
/// Данные адаптера есть только в логе: `open` даёт вендора и имя DLL, `version` —
/// прошивку (`FW:1060 HW:02 SN:A62122`), версию DLL и ветку API. Раньше
/// `adapter` заполнялся лишь ручным выбором шнурка и был `null` при захвате
/// J2534 (docs/12 §10).
pub fn apply_adapter_event(info: &mut crate::models::AdapterInfo, ev: &Event) {
    let field = |key: &str| {
        ev.meta
            .get(key)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    if ev.api == "J2534 open" {
        // `vendor=` драйвер заполняет сам; если он пуст (драйвера нет в реестре),
        // берём имя устройства, которое передало приложение (`PassThruOpen(name)`).
        if let Some(vendor) = field("vendor").or_else(|| field("device")) {
            if info.description.is_empty() {
                info.description = vendor.clone();
            }
            if info.vendor.is_none() {
                info.vendor = Some(vendor);
            }
        }
        if let Some(dll) = field("dll") {
            if info.dll.is_none() {
                info.dll = Some(dll);
            }
        }
        return;
    }
    if let Some(fw) = field("fw") {
        if info.serial.is_empty() {
            if let Some(rest) = fw.split("SN:").nth(1) {
                let sn = rest.split_whitespace().next().unwrap_or("").to_string();
                if !sn.is_empty() {
                    info.serial = sn;
                }
            }
        }
        if info.firmware.is_none() {
            info.firmware = Some(fw);
        }
    }
    if info.dll_version.is_none() {
        info.dll_version = field("dll");
    }
    if info.api.is_none() {
        info.api = field("api");
    }
}

fn read_file_hashes(events: &[&Event]) -> Vec<FileHash> {
    let mut out = Vec::new();
    for ev in events {
        if ev.kind != EventKind::FileHash {
            continue;
        }
        let path = ev
            .meta
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if path.is_empty() {
            continue;
        }
        out.push(FileHash {
            path,
            size: ev.meta.get("size").and_then(Value::as_u64).unwrap_or(0),
            sha256: ev
                .meta
                .get("sha256")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            mode: "import".into(),
        });
    }
    out
}

/// Файлы, в которые инструмент писал во время шага: хэш считается по факту.
///
/// Раньше `filehash` у шага был пуст, если в логе нет явной строки `# filehash`,
/// хотя PCMflash сохраняет прочитанное в `.bin` — и именно эта пара
/// «файл ↔ сырой поток» нужна для сверки дампа (docs/12 §10).
/// Файл читается только если он есть, не больше `HASH_MAX_BYTES`; иначе в
/// `mode` остаётся `too-big`, а размер — фактический.
fn hash_written_files(events: &[&Event]) -> Vec<FileHash> {
    const HASH_MAX_BYTES: u64 = 64 * 1024 * 1024;
    let mut out: Vec<FileHash> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    for ev in events {
        if ev.kind != EventKind::File {
            continue;
        }
        // Пишем только про закрытые файлы: у `open`/`write` размер ещё не итоговый.
        if ev.api != "FILE close" {
            continue;
        }
        let path = ev
            .meta
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if path.is_empty() || seen.contains(&path) {
            continue;
        }
        let bytes = ev.meta.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        let writes = ev.meta.get("writes").and_then(Value::as_u64).unwrap_or(0);
        if writes == 0 && bytes == 0 {
            continue; // открытие/чтение без записи: хэшировать нечего
        }
        seen.insert(path.clone());
        let meta = std::fs::metadata(&path);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(bytes);
        let (sha256, mode) = match meta {
            Ok(m) if m.is_file() && size <= HASH_MAX_BYTES => {
                match std::fs::read(&path) {
                    Ok(data) => (crate::models::util::sha256_hex(&data), "written".to_string()),
                    Err(_) => (String::new(), "unreadable".to_string()),
                }
            }
            Ok(_) => (String::new(), "too-big".to_string()),
            Err(_) => (String::new(), "gone".to_string()),
        };
        out.push(FileHash {
            path,
            size,
            sha256,
            mode,
        });
    }
    out
}

/// Ключ гистограммы LAN: для DoIP — тип сообщения (и UDS-сервис внутри diagnostic
/// message), иначе протокол + удалённый адрес (`TCP 192.168.1.10:7777`).
fn lan_hist_key(ev: &Event) -> String {
    if let Some(f) = doip_frame(&ev.payload()) {
        if let Some(uds) = f.uds {
            let name = service_name(uds & !0x40).unwrap_or("");
            let arrow = if uds & 0x40 != 0 { "resp" } else { "cmd" };
            return if name.is_empty() {
                format!("DoIP UDS {arrow} 0x{uds:02X}")
            } else {
                format!("DoIP UDS {arrow} 0x{uds:02X} {name}")
            };
        }
        return format!("DoIP 0x{:04X} {}", f.ptype, doip_type_name(f.ptype));
    }
    let proto = ev
        .meta
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("LAN");
    let remote = ev
        .meta
        .get("remote")
        .and_then(Value::as_str)
        .unwrap_or("?");
    format!("{proto} {remote}")
}

/// Заголовок DoIP (ISO 13400-2): `02 FD <type:u16> <length:u32> <payload…>`.
struct DoipFrame {
    ptype: u16,
    len: u32,
    src: Option<u16>,
    dst: Option<u16>,
    /// Первый байт UDS внутри diagnostic message (0x8001).
    uds: Option<u8>,
}

fn doip_frame(bytes: &[u8]) -> Option<DoipFrame> {
    if bytes.len() < 8 || bytes[0] != 0x02 || bytes[1] != 0xFD {
        return None;
    }
    let ptype = u16::from_be_bytes([bytes[2], bytes[3]]);
    let len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut f = DoipFrame {
        ptype,
        len,
        src: None,
        dst: None,
        uds: None,
    };
    if ptype == 0x8001 && bytes.len() >= 12 {
        f.src = Some(u16::from_be_bytes([bytes[8], bytes[9]]));
        f.dst = Some(u16::from_be_bytes([bytes[10], bytes[11]]));
        f.uds = bytes.get(12).copied();
    }
    Some(f)
}

fn doip_type_name(ptype: u16) -> &'static str {
    match ptype {
        0x0000 => "generic nack",
        0x0001 => "vehicle identification request",
        0x0002 => "vehicle identification request EID",
        0x0003 => "vehicle identification request VIN",
        0x0004 => "vehicle announcement",
        0x0005 => "routing activation request",
        0x0006 => "routing activation response",
        0x0007 => "alive check request",
        0x0008 => "alive check response",
        0x4001 => "entity status request",
        0x4002 => "entity status response",
        0x4003 => "power mode request",
        0x4004 => "power mode response",
        0x8001 => "diagnostic message",
        0x8002 => "diagnostic message ack",
        0x8003 => "diagnostic message nack",
        _ => "unknown",
    }
}

/// Разбор DoIP-сообщения для инспектора: тип, адреса, UDS-сервис и NRC.
fn decode_doip(bytes: &[u8]) -> Option<PayloadDecode> {
    let f = doip_frame(bytes)?;
    let mut out = PayloadDecode {
        len: bytes.len(),
        hex: bytes_to_hex(bytes),
        ascii: ascii_preview(bytes),
        ..Default::default()
    };
    out.cmd = Some(format!("DoIP 0x{:04X} {}", f.ptype, doip_type_name(f.ptype)));
    out.notes.push(format!("заявленная длина {}", f.len));
    if (f.len as usize) + 8 != bytes.len() {
        out.notes.push(format!(
            "длина в заголовке {} не совпадает с принятыми {}",
            f.len,
            bytes.len().saturating_sub(8)
        ));
    }
    if let (Some(src), Some(dst)) = (f.src, f.dst) {
        out.notes.push(format!("source 0x{src:04X} → target 0x{dst:04X}"));
    }
    if let Some(uds) = f.uds {
        let body = &bytes[12..];
        out.payload_hex = bytes_to_hex(body);
        if uds == 0x7F && body.len() >= 3 {
            let svc = body[1];
            let nrc = body[2];
            let name = kwp_nrc_name(nrc).unwrap_or("");
            out.cmd = Some(format!("DoIP UDS 7F ({svc:02X},{nrc:02X})"));
            if !name.is_empty() {
                out.notes.push(format!("NRC: {name}"));
            }
        } else {
            let base = uds & !0x40;
            let name = service_name(base).unwrap_or("");
            let arrow = if uds & 0x40 != 0 { "ответ" } else { "запрос" };
            out.notes.push(if name.is_empty() {
                format!("UDS 0x{uds:02X} ({arrow})")
            } else {
                format!("UDS 0x{uds:02X} {name} ({arrow})")
            });
        }
    }
    Some(out)
}

/// Транспорт(ы) сессии по событиям.
///
/// Раньше любой второй транспорт давал `mixed`, и у PCMflash через Scanmatik
/// выходило `mixed` только потому, что драйвер адаптера попутно светил свои
/// USB-ioctl, а обмен шёл через J2534. Теперь считаем вклад каждого транспорта
/// в обмен (TX/RX) и пишем `mixed` только если второй сопоставим с первым.
pub fn transport_summary(events: &[Event]) -> String {
    use std::collections::BTreeMap;
    let name = |t: Transport| match t {
        Transport::Ftd2xx => Some("ftd2xx"),
        Transport::Vcp => Some("vcp"),
        Transport::Usb => Some("usb"),
        Transport::J2534 => Some("j2534"),
        Transport::Lan => Some("lan"),
        _ => None,
    };
    let mut traffic: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut seen: Vec<&'static str> = Vec::new();
    for ev in events {
        let Some(n) = name(ev.transport) else { continue };
        if !seen.contains(&n) {
            seen.push(n);
        }
        if matches!(ev.kind, EventKind::Tx | EventKind::Rx) {
            *traffic.entry(n).or_insert(0) += 1;
        }
    }
    if traffic.len() > 1 {
        let mut ranked: Vec<(&str, u64)> = traffic.iter().map(|(k, v)| (*k, *v)).collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let (top, top_n) = ranked[0];
        let (second, second_n) = ranked[1];
        // Второй транспорт — не «шум драйвера», а реальный второй канал?
        if top_n > 0 && second_n * 5 >= top_n {
            return "mixed".to_string();
        }
        let _ = second;
        return top.to_string();
    }
    if let Some((only, _)) = traffic.iter().next() {
        return (*only).to_string();
    }
    // Ни одного TX/RX не было (сессия-«пустышка»): выводить `mixed` не из чего —
    // пусть остаётся стартовая догадка вызывающего.
    let _ = seen;
    String::new()
}

/// Русское склонение по числу: `1 посылка`, `2 посылки`, `11 посылок`.
pub fn plural<'a>(n: u64, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let n100 = n % 100;
    let n10 = n % 10;
    if (11..=14).contains(&n100) {
        many
    } else if n10 == 1 {
        one
    } else if (2..=4).contains(&n10) {
        few
    } else {
        many
    }
}

/// Пауза в обмене, которая делит сессию на отрезки (попытки).
///
/// 1 с выбрана по фактам: в логе 20261119-181253 две попытки прошивки шли по
/// 0.5 с и 2.5 с с паузой 22.5 с между ними, а внутри попытки приложение само
/// выдерживало до 0.58 с между кадрами — порог 0.5 с рвал попытку на куски.
pub const BUS_SEGMENT_GAP: f64 = 1.0;

/// Непрерывный отрезок обмена шины: пауза больше `gap` секунд закрывает его.
#[derive(Debug, Clone, Default)]
pub struct BusSegment {
    pub idx: u32,
    pub t0: f64,
    pub t1: f64,
    pub tx: u64,
    pub rx: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Сервисы запросов в порядке первого появления: `(0x27, 3)`.
    pub services: Vec<(u8, u64)>,
    /// Пауза перед этим отрезком (0 у первого).
    pub gap_before: f64,
}

impl BusSegment {
    pub fn dur(&self) -> f64 {
        (self.t1 - self.t0).max(0.0)
    }

    /// `0x80×30, 0x27×3` — по первому появлению сервиса.
    pub fn services_text(&self) -> String {
        self.services
            .iter()
            .map(|(sid, n)| format!("0x{sid:02X}×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Разбить обмен шины на отрезки по паузам. Сеть (Winsock) не в счёт: это не
/// обмен с ЭБУ, и её события шли бы «между» кадрами адаптера.
pub fn bus_segments(events: &[Event], gap: f64) -> Vec<BusSegment> {
    let mut out: Vec<BusSegment> = Vec::new();
    for ev in events {
        if matches!(ev.transport, Transport::Lan) {
            continue;
        }
        if !matches!(ev.kind, EventKind::Tx | EventKind::Rx) {
            continue;
        }
        // Внутренний слой (прокси → драйвер) — та же посылка, посчитанная выше:
        // в отрезки она не входит, иначе «посылок» было бы вдвое больше.
        if is_inner(ev) {
            continue;
        }
        let start_new = match out.last() {
            None => true,
            Some(seg) => ev.t - seg.t1 > gap,
        };
        let gap_before = out.last().map(|s| (ev.t - s.t1).max(0.0)).unwrap_or(0.0);
        if start_new {
            out.push(BusSegment {
                idx: out.len() as u32 + 1,
                t0: ev.t,
                t1: ev.t,
                gap_before: if out.is_empty() { 0.0 } else { gap_before },
                ..Default::default()
            });
        }
        let Some(seg) = out.last_mut() else { continue };
        seg.t1 = ev.t;
        match ev.kind {
            EventKind::Tx => {
                seg.tx += 1;
                seg.tx_bytes += ev.payload().len() as u64;
                if let Some((sid, _)) = j2534_service(ev) {
                    match seg.services.iter_mut().find(|(s, _)| *s == sid) {
                        Some((_, n)) => *n += 1,
                        None => seg.services.push((sid, 1)),
                    }
                }
            }
            _ => {
                seg.rx += 1;
                seg.rx_bytes += ev.payload().len() as u64;
            }
        }
    }
    out
}

/// Факты об отрезках обмена для шапки отчёта.
///
/// Сессии без шагов (типичный J2534-лог: приложение не размечает шаги) раньше
/// давали пустую Mermaid-схему `Start --> End` — по отчёту нельзя было понять,
/// что обмен шёл двумя попытками с паузой 22 с.
pub fn bus_segments_facts(segs: &[BusSegment]) -> Vec<String> {
    if segs.is_empty() {
        return Vec::new();
    }
    if segs.len() == 1 {
        let s = &segs[0];
        return vec![format!(
            "# обмен: непрерывный, {:.2}–{:.2} с ({:.2} с) · {} посылок · TX {} B / RX {} B · {}",
            s.t0,
            s.t1,
            s.dur(),
            s.tx,
            s.tx_bytes,
            s.rx_bytes,
            s.services_text()
        )];
    }
    let mut out = vec![format!(
        "# обмен: {} {} (пауза > {BUS_SEGMENT_GAP:.0} с делит сессию на отрезки)",
        segs.len(),
        plural(segs.len() as u64, "отрезок", "отрезка", "отрезков")
    )];
    for s in segs {
        let gap = if s.idx > 1 {
            format!(" · перед ним пауза {:.1} с", s.gap_before)
        } else {
            String::new()
        };
        out.push(format!(
            "# обмен {}: {:.2}–{:.2} с ({:.2} с) · {} посылок · TX {} B / RX {} B · {}{}",
            s.idx,
            s.t0,
            s.t1,
            s.dur(),
            s.tx,
            s.tx_bytes,
            s.rx_bytes,
            s.services_text(),
            gap
        ));
    }
    out
}

/// Ключ гистограммы J2534: протокол + CAN-id/сервис.
///
/// Раньше ключ был строго `{proto} {can_id}`, поэтому для vendor-протоколов без
/// CAN-id (например `0x8003` у PCMflash/Scanmatik) вся сводка шага схлопывалась
/// в бесполезное `0x8003 ?`. Теперь:
///   * CAN/ISO15765 (proto 5/6) — `ISO15765 0x7E0` и сервис, если он читается;
///   * прочие протоколы — сервис из payload (`svc=0x27`), иначе первые два байта.
fn j2534_hist_key(ev: &Event) -> String {
    let proto = ev
        .meta
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("ISO15765");
    let id = ev
        .meta
        .get("can_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let base = if id.is_empty() {
        proto.to_string()
    } else {
        format!("{proto} {id}")
    };
    match j2534_service(ev) {
        Some((svc, resp)) => {
            let name = service_name(svc & !0x40).unwrap_or("");
            let arrow = if resp { "resp" } else { "cmd" };
            if name.is_empty() {
                format!("{base} {arrow} 0x{svc:02X}")
            } else {
                format!("{base} {arrow} 0x{svc:02X} {name}")
            }
        }
        None => base,
    }
}

/// Сервисный байт кадра J2534 (с учётом вендорной обёртки) и признак ответа.
///
/// Агент кладёт `svc=0xNN` в строку, когда сервис читается однозначно; если меты нет,
/// пробуем вытащить сервис из payload сами (ISO-TP SF для CAN, иначе первый байт
/// после 2-байтового BE-префикса длины — так устроены кадры PCMflash/Scanmatik).
fn j2534_service(ev: &Event) -> Option<(u8, bool)> {
    if let Some(svc) = ev.meta.get("svc").and_then(Value::as_str) {
        if let Some(v) = parse_hex_byte(svc) {
            let resp = ev
                .meta
                .get("svc_resp")
                .and_then(Value::as_u64)
                .map(|x| x != 0)
                .unwrap_or(v & 0x40 != 0);
            return Some((v, resp));
        }
    }
    let bytes = ev.payload();
    if bytes.is_empty() {
        return None;
    }
    let proto = ev
        .meta
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("");
    let is_can = proto.contains("CAN") || proto.contains("ISO15765");
    if is_can {
        // ISO-TP одиночный кадр: старшая тетрада PCI == 0, сервис — следующий байт.
        if bytes[0] & 0xF0 == 0x00 && bytes.len() >= 2 {
            return Some((bytes[1], bytes[1] & 0x40 != 0));
        }
        return None;
    }
    // ISO 14230-2 / ISO 9141: сначала заголовок, сервис идёт после него.
    //   FMT & 0xC0 == 0x00 — без адреса, заголовок 1 байт;
    //   FMT & 0xC0 == 0x80 — с адресом (TGT, SRC), заголовок 3 байта;
    //   FMT & 0xC0 == 0xC0 — с адресом и байтом длины, заголовок 4 байта.
    if proto.contains("ISO14230") || proto.contains("ISO9141") || proto.contains("KWP") {
        let fmt = bytes[0];
        let off = match fmt & 0xC0 {
            0x80 => 3,
            0xC0 => 4,
            _ => 1,
        };
        return bytes
            .get(off)
            .map(|v| (*v, (*v & 0x40) != 0));
    }
    // Вендорная обёртка: 2 байта BE-длины, затем сервис.
    let off = if bytes.len() >= 3
        && u16::from_be_bytes([bytes[0], bytes[1]]) as usize == bytes.len() - 2
    {
        2
    } else {
        0
    };
    bytes
        .get(off)
        .map(|v| (*v, (*v & 0x40) != 0))
}

fn parse_hex_byte(text: &str) -> Option<u8> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    u8::from_str_radix(t, 16).ok()
}

/// Ключ гистограммы USB-обмена: текст события (`WINUSB pipe=0x01`) или api.
fn usb_hist_key(ev: &Event) -> String {
    ev.text
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            if ev.api.is_empty() {
                "USB".to_string()
            } else {
                ev.api.clone()
            }
        })
}

/// Сводка шага — надмножество старого `PHASE-JSON`.
///
/// `events` может быть как срезом шага, так и всем потоком сессии: границы
/// определяются по `MARK START/END` (или по полю `Event::step`).
pub fn summarize_step(
    events: &[Event],
    idx: u32,
    title: &str,
    dur: f64,
    png: Option<String>,
) -> StepSummary {
    let mut summary = StepSummary::new(idx, title);
    let slice = select_step_events(events, idx);

    // Границы и заголовок из MARK-событий.
    let mut start_ev: Option<&Event> = None;
    let mut end_ev: Option<&Event> = None;
    let mut marker_title = String::new();
    let mut marker_dur: Option<f64> = None;
    for ev in events {
        if event_marker_idx(ev) != Some(idx) {
            continue;
        }
        match ev.kind {
            EventKind::StepStart => {
                start_ev = Some(ev);
                if let Some(t) = ev.text.as_deref() {
                    marker_title = t.to_string();
                }
            }
            EventKind::StepEnd => {
                end_ev = Some(ev);
                marker_dur = ev.meta.get("dur").and_then(Value::as_f64);
                if marker_title.is_empty() {
                    if let Some(t) = ev.text.as_deref() {
                        marker_title = t.to_string();
                    }
                }
            }
            _ => {}
        }
    }
    if !marker_title.is_empty() {
        summary.title = marker_title;
    }
    summary.started_at = start_ev.map(|e| e.wall.clone()).unwrap_or_default();
    summary.ended_at = end_ev.map(|e| e.wall.clone()).unwrap_or_default();
    summary.dur = if let (Some(s), Some(e)) = (start_ev, end_ev) {
        if e.t > s.t {
            e.t - s.t
        } else {
            marker_dur.unwrap_or(dur)
        }
    } else {
        marker_dur.unwrap_or(dur)
    };
    summary.png = png;

    let mut exchanges = 0u64;
    let mut tx_bytes = 0u64;
    let mut rx_bytes = 0u64;
    let mut read_events: Vec<(u32, Vec<u8>, f64)> = Vec::new();
    let mut denied = 0u64;
    let mut no_answer = 0u64;
    let mut unparsed = 0u64;
    let mut echo_any = false;

    for ex in collect_exchanges(&slice) {
        exchanges += 1;
        tx_bytes += ex.tx.len() as u64;
        rx_bytes += ex.rx.len() as u64;
        let (echo, residual) = split_echo_response(&ex.tx, &ex.rx);
        echo_any |= echo;
        let (klass, payload, _tail) = parse_frame(&ex.tx, &residual);
        match klass.as_str() {
            "A2-denied" => denied += 1,
            "no-answer" => no_answer += 1,
            k if k.starts_with("unparsed") || k.starts_with("short-frame") || k.starts_with("b8-short") => {
                unparsed += 1
            }
            _ => {}
        }
        *summary.resp_hist.entry(klass).or_insert(0) += 1;

        let read = read_telegram(&ex.tx);
        if let Some((addr, blen)) = read {
            if !payload.is_empty() {
                read_events.push((addr, payload.clone(), ex.tx_t));
                *summary.cmd_hist.entry("READ(0x06)".to_string()).or_insert(0) += 1;
                let _ = blen; // заявленная длина блока: несовпадение видно по payload в отчёте
                continue;
            }
        }
        *summary.cmd_hist.entry(tx_summary(&ex.tx)).or_insert(0) += 1;
    }

    // Универсальный захват: гистограммы J2534 по протоколу/сервису, USB — по pipe/report,
    // LAN — по протоколу/адресу. Пустые RX-сообщения J2534 (`rxs=0x02 START_OF_MESSAGE`,
    // `len=0`) — это статус драйвера, а не ответ: в гистограмму и байты они не идут,
    // иначе один ответ считался дважды (в логе PCMflash было 112 «ответов» на 56 TX).
    let mut status_msgs = 0u64;
    let mut net_tx = 0u64;
    let mut net_rx = 0u64;
    for ev in &slice {
        match (ev.transport, ev.kind) {
            (Transport::J2534, EventKind::Tx) => {
                exchanges += 1;
                tx_bytes += ev.payload().len() as u64;
                *summary.cmd_hist.entry(j2534_hist_key(ev)).or_insert(0) += 1;
            }
            (Transport::J2534, EventKind::Rx) => {
                let bytes = ev.payload();
                if bytes.is_empty() {
                    status_msgs += 1;
                    continue;
                }
                rx_bytes += bytes.len() as u64;
                *summary.resp_hist.entry(j2534_hist_key(ev)).or_insert(0) += 1;
            }
            (Transport::Usb, EventKind::Tx) => {
                exchanges += 1;
                tx_bytes += ev.payload().len() as u64;
                *summary.cmd_hist.entry(usb_hist_key(ev)).or_insert(0) += 1;
            }
            (Transport::Usb, EventKind::Rx) => {
                rx_bytes += ev.payload().len() as u64;
                *summary.resp_hist.entry(usb_hist_key(ev)).or_insert(0) += 1;
            }
            // Сетевой обмен — отдельная гистограмма: лицензионный сервер и
            // прочий TCP процесса к протоколу ЭБУ не относятся (docs/12 §10).
            (Transport::Lan, EventKind::Tx) => {
                net_tx = net_tx.saturating_add(ev.payload().len() as u64);
                *summary.net_hist.entry(lan_hist_key(ev)).or_insert(0) += 1;
            }
            (Transport::Lan, EventKind::Rx) => {
                net_rx = net_rx.saturating_add(ev.payload().len() as u64);
                *summary.net_hist.entry(lan_hist_key(ev)).or_insert(0) += 1;
            }
            _ => {}
        }
    }
    let _ = status_msgs;   // статусные RX учтены только для того, чтобы не попасть в hist

    summary.exchanges = exchanges;
    summary.tx_bytes = tx_bytes;
    summary.rx_bytes = rx_bytes;
    summary.net_tx = net_tx;
    summary.net_rx = net_rx;
    summary.reads = stream_ranges(&read_events);
    summary.filehash = read_file_hashes(&slice);
    // Файлы, записанные инструментом в этом шаге: дамп PCMflash и т.п.
    for fh in hash_written_files(&slice) {
        if !summary.filehash.iter().any(|f| f.path == fh.path) {
            summary.filehash.push(fh);
        }
    }
    summary.verdict = StepVerdict {
        denied,
        no_answer,
        echo: echo_any,
        unparsed,
    };

    // Дополнения из старого PHASE-JSON (WinKFP-задания, png, точная длительность).
    if let Some(v) = phase_json_for(events, idx) {
        if let Some(d) = v.get("dur").and_then(Value::as_f64) {
            if d > 0.0 {
                summary.dur = d;
            }
        }
        if summary.title.is_empty() || summary.title == "?" {
            if let Some(t) = v.get("title").and_then(Value::as_str) {
                summary.title = t.to_string();
            }
        }
        if summary.png.is_none() {
            if let Some(p) = v.get("png").and_then(Value::as_str) {
                summary.png = Some(p.to_string());
            }
        }
        if let Some(jobs) = v.get("winkfp_jobs") {
            if let Ok(list) = serde_json::from_value::<Vec<WinkfpJob>>(jobs.clone()) {
                summary.winkfp_jobs = list;
            }
        }
    }

    summary
}

// ─────────────────────────── KWP-разбор для UI ───────────────────────────

/// KWP/DS2-разбор payload для инспектора.
pub fn decode_payload(hex: &str) -> PayloadDecode {
    let bytes = hex_to_bytes(hex);
    let mut out = PayloadDecode {
        len: bytes.len(),
        hex: bytes_to_hex(&bytes),
        ascii: ascii_preview(&bytes),
        ..Default::default()
    };
    if bytes.is_empty() {
        out.notes.push("пустой payload".into());
        return out;
    }
    // DoIP (ISO 13400-2): `02 FD …` — сетевой обмен, разбираем до KWP-эвристик.
    if let Some(doip) = decode_doip(&bytes) {
        return doip;
    }
    out.echo = Some(bytes[0]);
    out.payload_hex = bytes_to_hex(&bytes[1..]);

    // DS2-кадр: 12 <len> <status/cmd> <payload…> <cks>
    if bytes[0] == 0x12 && bytes.len() >= 3 {
        let b2 = bytes[2];
        match b2 {
            0xA0 => {
                out.cmd = Some("A0".into());
                let body = if bytes.len() >= 4 {
                    &bytes[3..bytes.len() - 1]
                } else {
                    &bytes[3..]
                };
                out.payload_hex = bytes_to_hex(body);
                out.notes.push("положительный ответ A0".into());
            }
            0xA2 => {
                out.cmd = Some("A2-denied".into());
                out.notes.push("отказ (A2-denied)".into());
            }
            0x06 if bytes.len() >= 9 => {
                let addr = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
                let blen = bytes[7];
                out.cmd = Some(format!("READ(0x{addr:06X}+{blen})"));
                out.notes
                    .push(format!("семейное чтение 0x{addr:06X}, заявлено {blen} B"));
            }
            0x7F if bytes.len() >= 4 => {
                let svc = bytes[3];
                let nrc = bytes.get(4).copied().unwrap_or(0);
                let name = kwp_nrc_name(nrc).unwrap_or("");
                out.cmd = Some(format!("7F({svc:02X},{nrc:02X})"));
                if !name.is_empty() {
                    out.notes.push(format!("NRC: {name}"));
                }
            }
            other => out.cmd = Some(format!("cmd=0x{other:02X}")),
        }
        return out;
    }

    // KWP2000 в обёртке b8: b8 <dst> <src> <len> <data…> <cks>
    if bytes[0] == 0xB8 && bytes.len() >= 5 {
        let ln = bytes[3] as usize;
        if 4 + ln + 1 <= bytes.len() {
            let data = &bytes[4..4 + ln];
            out.payload_hex = bytes_to_hex(data);
            if data.is_empty() {
                out.cmd = Some("b8-empty".into());
            } else if data[0] == 0x7F && data.len() >= 3 {
                let name = kwp_nrc_name(data[2]).unwrap_or("");
                out.cmd = Some(format!("7F({:02X},{:02X})", data[1], data[2]));
                if !name.is_empty() {
                    out.notes.push(format!("NRC: {name}"));
                }
            } else if data[0] & 0xC0 == 0x40 {
                out.cmd = Some(format!("pos({:02X})", data[0] - 0x40));
            } else if KWP_SUB_SVC.contains(&data[0]) && data.len() > 1 {
                out.cmd = Some(format!("SVC({:02X},{:02X})", data[0], data[1]));
            } else {
                out.cmd = Some(format!("SVC({:02X})", data[0]));
            }
        } else {
            out.cmd = Some(format!("b8-short(len={ln})"));
            out.notes.push("кадр b8 короче заявленного".into());
        }
        return out;
    }

    if bytes[0] == 0x7F && bytes.len() >= 3 {
        let name = kwp_nrc_name(bytes[2]).unwrap_or("");
        out.cmd = Some(format!("7F({:02X},{:02X})", bytes[1], bytes[2]));
        if !name.is_empty() {
            out.notes.push(format!("NRC: {name}"));
        }
        return out;
    }

    if bytes.len() >= 3 {
        out.cmd = Some(format!("cmd=0x{:02X}", bytes[2]));
    } else {
        out.cmd = Some(format!("cmd=0x{:02X}", bytes[0]));
        out.notes.push("короткий payload".into());
    }
    out
}

/// Разбор payload события с учётом транспорта: J2534 с `can_id` — ISOTP/CAN,
/// LAN — DoIP (если заголовок `02 FD`), иначе общий KWP-разбор.
pub fn decode_payload_event(ev: &Event) -> PayloadDecode {
    if ev.transport == Transport::J2534 {
        if let Some(can_id) = ev.meta.get("can_id").and_then(Value::as_str) {
            let protocol = ev
                .meta
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("ISO15765");
            return decode_isotp(&ev.hex, can_id, protocol);
        }
    }
    decode_payload(&ev.hex)
}

fn service_name(sid: u8) -> Option<&'static str> {
    Some(match sid {
        0x10 => "StartDiagnosticSession",
        0x11 => "ECUReset",
        0x14 => "ClearDiagnosticInformation",
        0x19 => "ReadDTCInformation",
        0x22 => "ReadDataByIdentifier",
        0x23 => "ReadMemoryByAddress",
        0x27 => "SecurityAccess",
        0x28 => "CommunicationControl",
        0x2E => "WriteDataByIdentifier",
        0x2F => "InputOutputControlByIdentifier",
        0x31 => "RoutineControl",
        0x34 => "RequestDownload",
        0x35 => "RequestUpload",
        0x36 => "TransferData",
        0x37 => "RequestTransferExit",
        0x3E => "TesterPresent",
        0x85 => "ControlDTCSetting",
        0x86 => "ResponseOnEvent",
        0x87 => "LinkControl",
        _ => return None,
    })
}

/// ISOTP (ISO 15765-2) поверх CAN-кадра: SF/FF/CF/FC + service id KWP/UDS.
pub fn decode_isotp(hex: &str, can_id: &str, protocol: &str) -> PayloadDecode {
    let bytes = hex_to_bytes(hex);
    let mut out = PayloadDecode {
        len: bytes.len(),
        hex: bytes_to_hex(&bytes),
        ascii: ascii_preview(&bytes),
        ..Default::default()
    };
    if bytes.is_empty() {
        out.cmd = Some(format!("{protocol} {can_id} · пусто"));
        out.notes.push("пустой CAN-кадр".into());
        return out;
    }

    let b0 = bytes[0];
    let pci = b0 >> 4;
    let low = (b0 & 0x0F) as usize;
    let (desc, payload): (String, Vec<u8>) = match pci {
        0x0 => {
            // Single Frame: длина в младшем ниббле.
            let end = (1 + low).min(bytes.len());
            let body = bytes[1..end].to_vec();
            out.notes.push(format!("ISOTP PCI: SF, заявлено {low} B"));
            (format!("SF {low}B"), body)
        }
        0x1 => {
            // First Frame: 12-битная длина.
            let total = (low << 8) | bytes.get(1).copied().unwrap_or(0) as usize;
            let body = if bytes.len() > 2 {
                bytes[2..].to_vec()
            } else {
                Vec::new()
            };
            out.notes
                .push(format!("ISOTP PCI: FF, всего {total} B"));
            (format!("FF {total}B"), body)
        }
        0x2 => {
            // Consecutive Frame: порядковый номер.
            let seq = low & 0x0F;
            let body = if bytes.len() > 1 {
                bytes[1..].to_vec()
            } else {
                Vec::new()
            };
            out.notes.push(format!("ISOTP PCI: CF seq={seq}"));
            (format!("CF seq={seq}"), body)
        }
        0x3 => {
            // Flow Control: статус + block size + STmin.
            let status = match low & 0x0F {
                0 => "CTS",
                1 => "WAIT",
                2 => "OVFLW",
                _ => "?",
            };
            if bytes.len() >= 3 {
                out.notes.push(format!(
                    "ISOTP PCI: FC {status}, block={}, STmin={}ms",
                    bytes[1], bytes[2]
                ));
            } else {
                out.notes.push(format!("ISOTP PCI: FC {status} (короткий кадр)"));
            }
            out.payload_hex = if bytes.len() > 1 {
                bytes_to_hex(&bytes[1..])
            } else {
                String::new()
            };
            out.cmd = Some(format!("{protocol} {can_id} · FC {status}"));
            return out;
        }
        _ => {
            out.notes
                .push(format!("неизвестный ISOTP PCI 0x{b0:02X}"));
            let body = if bytes.len() > 1 {
                bytes[1..].to_vec()
            } else {
                Vec::new()
            };
            (format!("PCI 0x{b0:02X}"), body)
        }
    };

    out.ascii = ascii_preview(&payload);
    out.payload_hex = bytes_to_hex(&payload);
    out.cmd = Some(format!("{protocol} {can_id} · {desc}"));
    if let Some(&sid) = payload.first() {
        if sid == 0x7F && payload.len() >= 3 {
            let nrc = payload[2];
            let name = kwp_nrc_name(nrc).unwrap_or("");
            let svc = payload[1];
            out.notes.push(format!(
                "негативный ответ 7F на 0x{svc:02X}{}",
                if name.is_empty() {
                    String::new()
                } else {
                    format!(" ({name})")
                }
            ));
        } else if sid >= 0x40 {
            let request = sid - 0x40;
            let name = service_name(request)
                .map(|n| format!(" — ответ на {n} (0x{request:02X})"))
                .unwrap_or_default();
            out.notes.push(format!("service id 0x{sid:02X}{name}"));
        } else {
            let name = service_name(sid)
                .map(|n| format!(" {n}"))
                .unwrap_or_default();
            out.notes.push(format!("service id 0x{sid:02X}{name}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn j2534_layer_and_parent_are_kept_and_hex_stays_clean() {
        // Внешний вызов прокси: слой есть, родителя нет.
        let outer = parse_capture_line(
            "[+8.240241s] J2534 TX ch=1 call=1 i=1/1 n_in=1 n_out=2 th=31152 ts=0 \
             flags=0x0 proto=0x8003 svc=0x80 len=5 dur=3543 rc=0 layer=proxy : 00 03 80 e1 01",
        )
        .expect("внешний TX");
        assert_eq!(outer.kind, EventKind::Tx);
        assert_eq!(outer.meta.get("layer").and_then(Value::as_str), Some("proxy"));
        assert!(!is_inner(&outer), "у внешнего вызова родителя нет");
        // `layer=proxy` стоит ДО ` : ` и не должен попасть в payload.
        assert_eq!(outer.hex, "00 03 80 e1 01");
        assert_eq!(outer.len, 5);

        // Вложенный вызов драйвера: тот же кадр, но с родителем.
        let inner = parse_capture_line(
            "[+8.237046s] J2534 TX ch=1 call=2 i=1/1 n_in=1 n_out=2 th=31152 ts=0 \
             flags=0x0 proto=0x8003 svc=0x80 len=5 dur=60 rc=0 layer=driver parent=1 : 00 03 80 e1 01",
        )
        .expect("вложенный TX");
        assert!(is_inner(&inner), "parent= делает запись внутренней");
        assert_eq!(inner.meta.get("parent").and_then(Value::as_u64), Some(1));
        assert_eq!(inner.meta.get("layer").and_then(Value::as_str), Some("driver"));
        assert_eq!(inner.hex, "00 03 80 e1 01");
    }

    #[test]
    fn vendor_line_is_parsed_with_params() {
        // Строка из proxy\tests\out\vendor\log.txt (фикстура vendor_dump.ps1):
        // ровно тот формат, который пишет прокси для 1377 (docs/13 §6.3).
        let line = "[+0.019497s] J2534 vendor ord=1377 op=0xb arg=0x004FE67C a2=0x0 a3=0x0 \
                    ret=vendor_host.exe+0x1343 rc=0 th=17588 dur=6 \
                    mem=0011223344556677 pre=8899aabbccddeeff \
                    params=11:0x1aa8c780=5000,0x1aa8c721=1,0x1aa8c724=64000";
        let ev = parse_capture_line(line).expect("vendor line");
        assert_eq!(ev.kind, EventKind::Sys);
        assert_eq!(ev.transport, Transport::J2534);
        assert_eq!(ev.api, "J2534 vendor");
        assert_eq!(ev.meta.get("ord").and_then(Value::as_str), Some("1377"));
        assert_eq!(ev.meta.get("op").and_then(Value::as_str), Some("0xb"));
        assert_eq!(
            ev.meta.get("ret").and_then(Value::as_str),
            Some("vendor_host.exe+0x1343")
        );
        assert_eq!(ev.meta.get("count").and_then(Value::as_u64), Some(11));
        // Дампы в meta не копируются — только их длина в байтах.
        assert_eq!(ev.meta.get("mem_len").and_then(Value::as_u64), Some(8));
        assert_eq!(ev.meta.get("pre_len").and_then(Value::as_u64), Some(8));
        let params = ev.meta.get("params").and_then(Value::as_str).unwrap_or("");
        assert!(params.starts_with("11:0x1aa8c780=5000,"), "{params}");
        assert!(ev.text.unwrap_or_default().starts_with("vendor 1377 op=0xb"));
    }

    #[test]
    fn bus_segments_ignore_the_inner_layer() {
        let lines = [
            "[+1.000000s] J2534 TX ch=1 call=1 proto=0x8003 len=5 layer=proxy : 00 03 80 e1 01",
            "[+1.000100s] J2534 TX ch=1 call=2 proto=0x8003 len=5 layer=driver parent=1 : 00 03 80 e1 01",
            "[+1.001000s] J2534 TX ch=1 call=3 proto=0x8003 len=5 layer=proxy : 00 03 80 e1 02",
            "[+1.001100s] J2534 TX ch=1 call=4 proto=0x8003 len=5 layer=driver parent=3 : 00 03 80 e1 02",
        ];
        let events: Vec<Event> = lines
            .iter()
            .filter_map(|line| parse_capture_line(line))
            .collect();
        assert_eq!(events.len(), 4);
        let segs = bus_segments(&events, BUS_SEGMENT_GAP);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].tx, 2, "два обмена, а не четыре записи");
        assert_eq!(segs[0].tx_bytes, 10);
        assert_eq!(segs[0].services_text(), "0x80×2");
    }

    #[test]
    fn time_prefix_and_payload() {
        let ev = parse_capture_line("[+70.537s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b").unwrap();
        assert_eq!(ev.kind, EventKind::Tx);
        assert_eq!(ev.transport, Transport::Vcp);
        assert_eq!(ev.api, "WriteFile");
        assert!((ev.t - 70.537).abs() < 1e-9);
        assert_eq!(ev.len, 4);
        assert_eq!(ev.payload(), vec![0x12, 0x04, 0x0d, 0x1b]);
    }

    #[test]
    fn merged_single_bytes_marker() {
        let ev = parse_capture_line(
            "[+70.604s] VCP RX ReadFile(COM6) одиночные байты n=3 : 12 4c a0",
        )
        .unwrap();
        assert_eq!(ev.kind, EventKind::Rx);
        assert_eq!(ev.len, 3);
        assert!(meta_bool(&ev, "single_bytes"));
    }

    #[test]
    fn mark_and_phase() {
        let ev =
            parse_capture_line("# MARK wall=2026-10-16 11:53:45 START 1: читаю идентификаторы")
                .unwrap();
        assert_eq!(ev.kind, EventKind::StepStart);
        assert_eq!(meta_idx(&ev), Some(1));
        assert_eq!(ev.text.as_deref(), Some("читаю идентификаторы"));
        let ev = parse_capture_line(
            "# MARK wall=2026-10-16 11:53:47 END 1: читаю идентификаторы (1.6 с)",
        )
        .unwrap();
        assert_eq!(ev.kind, EventKind::StepEnd);
        assert_eq!(ev.meta.get("dur").and_then(Value::as_f64), Some(1.6));
        let ev = parse_capture_line("# PHASE 1: читаю | длительность 1.6 с | TX 248 посылок").unwrap();
        assert_eq!(ev.kind, EventKind::Summary);
        assert_eq!(ev.api, "PHASE");
        let ev = parse_capture_line(r#"# PHASE-JSON {"idx": 1, "title": "x"}"#).unwrap();
        assert_eq!(ev.api, "PHASE-JSON");
        assert_eq!(meta_idx(&ev), Some(1));
    }

    #[test]
    fn unknown_and_empty() {
        assert!(parse_capture_line("").is_none());
        assert!(parse_capture_line("   \r\n").is_none());
        let ev = parse_capture_line("какая-то мусорная строка").unwrap();
        assert_eq!(ev.kind, EventKind::Raw);
        let ev = parse_capture_line("====").unwrap();
        assert_eq!(ev.kind, EventKind::Sys);
    }

    #[test]
    fn payload_truncated_to_limit() {
        let payload = (0..40_000u32)
            .map(|i| format!("{:02x}", (i % 256) as u8))
            .collect::<Vec<_>>()
            .join(" ");
        let line = format!("[+1.000s] VCP TX WriteFile(COM6) n=40000 : {payload}");
        let ev = parse_capture_line(&line).unwrap();
        assert!(meta_bool(&ev, "truncated"));
        assert!(ev.hex.len() <= MAX_EVENT_BYTES);
        assert_eq!(ev.len, 40_000);
    }

    // ── LAN / DoIP ───────────────────────────────────────────────────────────

    #[test]
    fn lan_tx_parses_peers_and_doip() {
        let ev = parse_capture_line(
            "[+3.100s] LAN TX tcp local=192.168.1.5:50123 remote=192.168.1.10:13400 len=8 : \
             02 fd 80 01 00 00 00 02",
        )
        .unwrap();
        assert_eq!(ev.kind, EventKind::Tx);
        assert_eq!(ev.transport, Transport::Lan);
        assert_eq!(ev.api, "LAN TX");
        assert_eq!(ev.direction, Some(Direction::Tx));
        assert_eq!(ev.len, 8);
        assert_eq!(ev.meta.get("l4").and_then(Value::as_str), Some("tcp"));
        assert_eq!(
            ev.meta.get("remote").and_then(Value::as_str),
            Some("192.168.1.10:13400")
        );
        assert_eq!(ev.meta.get("protocol").and_then(Value::as_str), Some("DoIP"));
        assert_eq!(ev.payload(), vec![0x02, 0xfd, 0x80, 0x01, 0x00, 0x00, 0x00, 0x02]);
    }

    #[test]
    fn lan_connect_and_close_are_sys() {
        let ev = parse_capture_line(
            "[+1.000s] LAN CONNECT tcp fd=0x1a4 local=192.168.1.5:50123 \
             remote=192.168.1.10:6801 rc=0",
        )
        .unwrap();
        assert_eq!(ev.kind, EventKind::Sys);
        assert_eq!(ev.transport, Transport::Lan);
        assert_eq!(ev.rc, Some(0));
        assert_eq!(
            ev.meta.get("remote").and_then(Value::as_str),
            Some("192.168.1.10:6801")
        );
        let ev = parse_capture_line("[+9.000s] LAN CLOSE tcp fd=0x1a4 bytes=1234 reads=9 writes=7")
            .unwrap();
        assert_eq!(ev.kind, EventKind::Sys);
        assert_eq!(ev.meta.get("bytes").and_then(Value::as_u64), Some(1234));
    }

    #[test]
    fn doip_diagnostic_message_decodes_uds() {
        // DoIP diagnostic message: source 0x0E80 → target 0x1001, UDS ReadDataByIdentifier.
        let ev = parse_capture_line(
            "[+3.100s] LAN RX tcp local=192.168.1.10:13400 remote=192.168.1.5:50123 \
             len=16 : 02 fd 80 01 00 00 00 08 0e 80 10 01 22 f1 90 00",
        )
        .unwrap();
        let d = decode_payload_event(&ev);
        assert_eq!(d.cmd.as_deref(), Some("DoIP 0x8001 diagnostic message"));
        assert!(d
            .notes
            .iter()
            .any(|n| n.contains("UDS 0x22 ReadDataByIdentifier")));
        assert!(d.notes.iter().any(|n| n.contains("0x0E80")));
    }

    #[test]
    fn doip_length_mismatch_is_reported() {
        // Заголовок обещает 4 байта тела, пришло 3.
        let bytes = vec![0x02, 0xfd, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03];
        let d = decode_payload(&bytes_to_hex(&bytes));
        assert_eq!(
            d.cmd.as_deref(),
            Some("DoIP 0x0005 routing activation request")
        );
        assert!(d.notes.iter().any(|n| n.contains("не совпадает")));
    }

    // ── J2534: вендорный протокол PCMflash/Scanmatik ────────────────────────

    #[test]
    fn j2534_vendor_proto_yields_service_in_hist() {
        // Ровно то, что писал PCMflash через smj2534.dll: proto=0x8003, без CAN-id,
        // плюс пустой RX_STATUS (rxs=0x2, len=0) перед каждым ответом.
        let lines = [
            "# MARK wall=2026-11-18 16:00:07 START 1: Идентификация",
            "[+10.000s] J2534 TX ch=1 proto=0x8003 flags=0x0 len=4 : 00 02 27 7f",
            "[+10.010s] J2534 RX ch=1 proto=0x8003 rxs=0x2 len=0 : ",
            "[+10.011s] J2534 RX ch=1 proto=0x8003 rxs=0x0 len=5 : 00 03 67 7f 34",
        ];
        let events: Vec<Event> = lines
            .iter()
            .filter_map(|l| parse_capture_line(l))
            .collect();
        let summary = summarize_step(&events, 1, "Идентификация", 0.02, None);
        assert_eq!(summary.exchanges, 1, "одна посылка TX");
        assert_eq!(summary.tx_bytes, 4);
        assert_eq!(summary.rx_bytes, 5, "пустой RX_STATUS не идёт в байты");
        assert!(
            summary
                .cmd_hist
                .keys()
                .any(|k| k.contains("0x8003") && k.contains("SecurityAccess")),
            "cmd_hist={:?}",
            summary.cmd_hist
        );
        assert!(
            summary
                .resp_hist
                .keys()
                .any(|k| k.contains("resp") && k.contains("SecurityAccess")),
            "resp_hist={:?}",
            summary.resp_hist
        );
        assert_eq!(
            summary.resp_hist.values().sum::<u64>(),
            1,
            "ответ посчитан один раз, а не дважды: {:?}",
            summary.resp_hist
        );
    }

    #[test]
    fn j2534_iso14230_header_is_skipped_before_service() {
        // ISO 14230-2: сервис идёт после заголовка, а не первым байтом.
        // 1) без адреса: FMT=0x02, дальше SID 0x10.
        let e = parse_capture_line(
            "[+1.000s] J2534 TX ch=1 proto=ISO14230 len=3 : 02 10 03",
        )
        .unwrap();
        assert_eq!(j2534_service(&e), Some((0x10, false)));
        // 2) с адресом (FMT=0x81): FMT TGT SRC SID.
        let e = parse_capture_line(
            "[+1.100s] J2534 TX ch=1 proto=ISO14230 len=4 : 81 f1 10 3e",
        )
        .unwrap();
        assert_eq!(j2534_service(&e), Some((0x3E, false)));
        // 3) с адресом и байтом длины (FMT=0xC1): FMT TGT SRC LEN SID.
        let e = parse_capture_line(
            "[+1.200s] J2534 RX ch=1 proto=ISO14230 len=5 : c1 f1 10 02 7e",
        )
        .unwrap();
        assert_eq!(j2534_service(&e), Some((0x7E, true)), "0x7E = ответ на 0x3E");
    }

    #[test]
    fn j2534_svc_meta_from_agent_wins() {
        let ev = parse_capture_line(
            "[+1.000s] J2534 TX ch=1 proto=0x8003 flags=0x0 svc=0x10 len=3 : 00 01 10",
        )
        .unwrap();
        assert_eq!(ev.text.as_deref(), Some("0x8003 0x10"));
        let key = j2534_hist_key(&ev);
        assert!(key.contains("0x10") && key.contains("StartDiagnosticSession"), "{key}");
    }

    #[test]
    fn j2534_can_hist_keeps_can_id() {
        let ev = parse_capture_line(
            "[+2.000s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 flags=0x0 len=8 : \
             02 10 03 00 00 00 00 00",
        )
        .unwrap();
        let key = j2534_hist_key(&ev);
        assert!(key.starts_with("ISO15765 0x7E0"), "{key}");
        assert!(key.contains("StartDiagnosticSession"), "{key}");
    }

    #[test]
    fn transport_summary_recognizes_lan() {
        let lan = parse_capture_line(
            "[+1.000s] LAN TX udp local=192.168.1.5:50123 remote=192.168.1.10:13400 len=1 : 02",
        )
        .unwrap();
        assert_eq!(transport_summary(&[lan]), "lan");
    }
}

