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

fn meta_bool(ev: &Event, key: &str) -> bool {
    ev.meta.get(key).and_then(Value::as_bool).unwrap_or(false)
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
    if rest.starts_with("FILE ") {
        return parse_file_line(rest, t, raw);
    }
    if let Some(after) = rest.strip_prefix("MODULE") {
        return parse_module_line(after, t, raw);
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
        "read" => split_file_attrs(body, &[" offset=", " n=", " len="]),
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
    ev.text = Some(path.to_string());
    set_meta(&mut ev, "op", json!(op));
    set_meta(&mut ev, "path", json!(path));
    if let Some(access) = tag_value(attrs, "access") {
        set_meta(&mut ev, "access", json!(access));
    }
    if let Some(handle) = tag_value(attrs, "handle") {
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
    if let Some(total) = tag_u64(attrs, "total") {
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

    summary.exchanges = exchanges;
    summary.tx_bytes = tx_bytes;
    summary.rx_bytes = rx_bytes;
    summary.reads = stream_ranges(&read_events);
    summary.filehash = read_file_hashes(&slice);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

