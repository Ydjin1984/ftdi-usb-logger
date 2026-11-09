//! Импорт старых логов в новую схему. Владелец: ded-bekend.
//!
//! `import_legacy_log` принимает `capture.log` (канонический лог) и `logger.out`
//! (консольный транскрипт старого логера): копирует исходник в `import/`, гонит строки
//! через `decode::parse_capture_line`, пересобирает шаги по `# MARK START/END` + `# PHASE`
//! и пишет `status="imported"`, `transport="import"`.

use crate::decode;
use crate::models::{Event, EventKind, SessionMeta, StepSummary};
use crate::report;
use crate::store::{self, SessionStore};
use anyhow::Context;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Сколько строк баннера просматриваем максимум.
const BANNER_SCAN_LINES: usize = 160;

#[derive(Default)]
struct Banner {
    label: Option<String>,
    tool: Option<String>,
    pid: Option<u32>,
    wall_start: Option<String>,
    facts: Vec<String>,
}

fn strip_hash_prefix(line: &str) -> &str {
    line.trim_start_matches('#').trim_start()
}

fn note_fact(facts: &mut Vec<String>, text: &str) {
    let text = text.trim();
    if text.is_empty() || facts.len() >= 24 {
        return;
    }
    if !facts.iter().any(|f| f == text) {
        facts.push(text.to_string());
    }
}

fn scan_banner(text: &str) -> Banner {
    let mut banner = Banner::default();
    for (n, line) in text.lines().enumerate() {
        if n >= BANNER_SCAN_LINES {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("[+") || trimmed.starts_with("# MARK") {
            break; // начался поток обмена
        }
        if trimmed.is_empty() || trimmed.starts_with('=') || trimmed.starts_with('-') {
            continue;
        }

        // logger.out: «ЛОГЕР — блок: WinKFP»
        if trimmed.contains("— блок:") || trimmed.contains("- блок:") {
            if let Some((_, tail)) = trimmed.split_once("блок:") {
                let label = tail.trim();
                if !label.is_empty() {
                    banner.label = Some(label.to_string());
                }
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("приложение :") {
            banner.tool = Some(rest.trim().to_string());
            note_fact(&mut banner.facts, &format!("приложение: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("сессия     :") {
            note_fact(&mut banner.facts, &format!("сессия: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("EDIABAS    :") {
            note_fact(&mut banner.facts, &format!("EDIABAS: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("трассы     :") {
            note_fact(&mut banner.facts, &format!("трассы: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("лог        :") {
            note_fact(&mut banner.facts, &format!("лог: {}", rest.trim()));
            continue;
        }

        if !trimmed.starts_with('#') {
            continue;
        }
        let c = strip_hash_prefix(trimmed);

        if let Some(rest) = c.strip_prefix("capture start") {
            if let Some(label) = tag_value(rest, "label") {
                banner.label = Some(label.to_string());
            }
            continue;
        }
        if let Some(rest) = c.strip_prefix("tool:") {
            banner.tool = Some(rest.trim().to_string());
            note_fact(&mut banner.facts, &format!("tool: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = c.strip_prefix("exe=") {
            let path = rest.trim();
            if banner.tool.is_none() {
                banner.tool = Some(path.to_string());
            }
            note_fact(&mut banner.facts, &format!("exe: {path}"));
            continue;
        }
        if let Some(rest) = c.strip_prefix("exe:") {
            note_fact(&mut banner.facts, &format!("exe: {}", rest.trim()));
            continue;
        }
        if let Some(rest) = c.strip_prefix("wall(start)=") {
            banner.wall_start = Some(rest.trim().trim_start_matches('=').trim().to_string());
            continue;
        }
        if let Some(rest) = c.strip_prefix("time=") {
            banner.wall_start.get_or_insert_with(|| rest.trim().to_string());
            continue;
        }
        if let Some(rest) = c.strip_prefix("attached ") {
            if let Some(pid) = tag_u32(rest, "pid") {
                banner.pid = Some(pid);
            }
            continue;
        }
        if let Some(rest) = c.strip_prefix("spawned ") {
            if let Some(pid) = tag_u32(rest, "pid") {
                banner.pid = Some(pid);
            }
            continue;
        }
        for prefix in [
            "EDIABAS.INI:",
            "EDIABAS OBD.INI",
            "WinKFP ini:",
            "EDIABAS trace",
            "license-gate:",
            "ftd2xx:",
            "adapter:",
            "host:",
            "note:",
            "script:",
            "log:",
            "app-dir:",
            "ecu:",
            "cmdline=",
        ] {
            if c.starts_with(prefix) {
                note_fact(&mut banner.facts, c);
                break;
            }
        }
    }
    // Если label не нашли — первая факт-строка «блок:» уже обработана.
    banner
}

fn tag_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("{key}=");
    let abs = text.find(&pat)?;
    let vstart = abs + pat.len();
    let vend = text[vstart..]
        .find(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .map(|x| vstart + x)
        .unwrap_or(text.len());
    Some(text[vstart..vend].trim())
}

fn tag_u32(text: &str, key: &str) -> Option<u32> {
    tag_value(text, key).and_then(|v| v.trim().parse().ok())
}

fn event_meta_idx(ev: &Event) -> Option<u32> {
    ev.meta
        .get("idx")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
}

/// Длина фактического payload события в байтах.
fn payload_len(ev: &Event) -> u64 {
    if ev.hex.is_empty() {
        0
    } else {
        crate::models::util::hex_to_bytes(&ev.hex).len() as u64
    }
}

fn wall_to_rfc3339(raw: &str) -> Option<String> {
    use chrono::TimeZone;
    let cleaned = raw.trim().trim_start_matches('=').trim();
    if cleaned.is_empty() {
        return None;
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
    ] {
        if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(cleaned, fmt) {
            if let Some(dt) = chrono::Local.from_local_datetime(&ndt).earliest() {
                return Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, false));
            }
        }
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(cleaned) {
        return Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, false));
    }
    Some(cleaned.to_string())
}

fn file_mtime_rfc3339(path: &Path) -> Option<String> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    let dt: chrono::DateTime<chrono::Local> = modified.into();
    Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, false))
}

fn source_file_name(path: &Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "import.log".into())
}

/// Импортировать старый лог (`capture.log`, `logger.out`) в новую схему сессии.
pub fn import_legacy_log(
    store: &SessionStore,
    path: &Path,
    label: Option<String>,
) -> anyhow::Result<SessionMeta> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("не прочитать лог {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let banner = scan_banner(&text);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "import".into());
    let label = label
        .or(banner.label.clone())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(stem);

    let mut meta = SessionMeta::new(String::new(), label.clone());
    meta.status = "imported".into();
    meta.transport = "import".into();
    meta.tags = vec!["import".into()];
    meta.pid = banner.pid;
    meta.tool_path = banner.tool.clone();
    meta.facts = banner.facts.clone();
    if let Some(wall) = banner.wall_start.as_deref() {
        if let Some(started) = wall_to_rfc3339(wall) {
            meta.started_at = started;
        }
    } else if let Some(started) = file_mtime_rfc3339(path) {
        meta.started_at = started;
    }

    let source_name = source_file_name(path);
    let mut writer = store.create(meta)?;
    let dir = writer.dir().to_path_buf();
    let copy_path = dir.join("import").join(&source_name);
    std::fs::copy(path, &copy_path)
        .with_context(|| format!("не скопировать исходник в {}", copy_path.display()))?;

    let mut steps: Vec<StepSummary> = Vec::new();
    let mut current: Option<u32> = None;
    let mut acc: Vec<Event> = Vec::new();
    let mut last_step_idx: Option<u32> = None;

    // Один проход: события пишем сразу, срез шага копим для сводки.
    for line in text.lines() {
        let Some(mut ev) = decode::parse_capture_line(line) else {
            continue;
        };
        // Шкалы времени не смешиваем: t уже либо из `[+Xs]`, либо из `rel=`, либо 0.

        match ev.kind {
            EventKind::StepStart => {
                if let Some(idx) = current.take() {
                    finalize_step(&mut writer, &mut steps, idx, &mut acc)?;
                }
                let idx = event_meta_idx(&ev).unwrap_or(0);
                ev.step = Some(idx);
                writer.append(&mut ev)?;
                acc.push(ev.clone());
                current = Some(idx);
                last_step_idx = Some(idx);
            }
            EventKind::Summary if ev.api == "PHASE-JSON" => {
                let idx = event_meta_idx(&ev).or(current).unwrap_or(0);
                ev.step = Some(idx);
                writer.append(&mut ev)?;
                if current == Some(idx) || current.is_none() {
                    if let Some(cur_idx) = current.take() {
                        if cur_idx == idx {
                            acc.push(ev.clone());
                        }
                        finalize_step(&mut writer, &mut steps, cur_idx, &mut acc)?;
                    } else {
                        // PHASE-JSON без открытого шага: синтезируем шаг только из него.
                        acc.push(ev.clone());
                        finalize_step(&mut writer, &mut steps, idx, &mut acc)?;
                    }
                }
                last_step_idx = Some(idx);
            }
            _ => {
                if let Some(idx) = current {
                    ev.step = Some(idx);
                    writer.append(&mut ev)?;
                    acc.push(ev.clone());
                } else if ev.kind == EventKind::StepEnd {
                    // END без START — закрываем последний известный шаг.
                    let idx = event_meta_idx(&ev).or(last_step_idx).unwrap_or(0);
                    ev.step = Some(idx);
                    writer.append(&mut ev)?;
                    acc.push(ev.clone());
                    finalize_step(&mut writer, &mut steps, idx, &mut acc)?;
                } else {
                    writer.append(&mut ev)?;
                }
            }
        }
    }
    if let Some(idx) = current.take() {
        finalize_step(&mut writer, &mut steps, idx, &mut acc)?;
    }

    let mut meta = writer.meta.clone();
    meta.counts = writer.meta.counts.clone();
    meta.counts.steps = steps.len() as u64;
    meta.status = "imported".into();
    meta.transport = "import".into();
    meta.label = label;
    meta.facts = banner.facts;
    meta.pid = banner.pid;
    meta.tool_path = banner.tool;
    writer.finish(&meta)?;
    let meta = writer.meta.clone();

    // Финальные отчёты пишем из уже закрытых файлов шагов.
    let steps_on_disk = read_steps(&dir);
    let steps_for_report = if steps_on_disk.len() >= steps.len() {
        steps_on_disk
    } else {
        steps
    };
    report::write_session_reports(&dir, &meta, &steps_for_report)?;
    Ok(meta)
}

fn finalize_step(
    writer: &mut store::SessionWriter,
    steps: &mut Vec<StepSummary>,
    idx: u32,
    acc: &mut Vec<Event>,
) -> anyhow::Result<()> {
    let summary = decode::summarize_step(acc, idx, "", 0.0, None);
    writer
        .save_step(&summary)
        .with_context(|| format!("не сохранить шаг {idx}"))?;
    steps.push(summary);
    acc.clear();
    Ok(())
}

fn read_steps(dir: &Path) -> Vec<StepSummary> {
    let dir = dir.join("steps");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    paths.retain(|p| p.extension().map(|e| e == "json").unwrap_or(false));
    paths.sort();
    paths
        .iter()
        .filter_map(|p| {
            std::fs::read(p)
                .ok()
                .and_then(|b| serde_json::from_slice::<StepSummary>(&b).ok())
        })
        .collect()
}

/// Сгруппировать события потока в шаги по `MARK START/END` + `PHASE-JSON`.
fn group_steps(events: &[Event]) -> Vec<(u32, Vec<Event>)> {
    let mut out: Vec<(u32, Vec<Event>)> = Vec::new();
    let mut current: Option<u32> = None;
    let mut acc: Vec<Event> = Vec::new();
    for ev in events {
        match ev.kind {
            EventKind::StepStart => {
                if let Some(idx) = current.take() {
                    out.push((idx, std::mem::take(&mut acc)));
                }
                let idx = event_meta_idx(ev).unwrap_or(0);
                acc.push(ev.clone());
                current = Some(idx);
            }
            EventKind::Summary if ev.api == "PHASE-JSON" => {
                let idx = event_meta_idx(ev).or(current).unwrap_or(0);
                acc.push(ev.clone());
                if current == Some(idx) {
                    out.push((idx, std::mem::take(&mut acc)));
                    current = None;
                }
            }
            _ => {
                if current.is_some() {
                    acc.push(ev.clone());
                }
            }
        }
    }
    if let Some(idx) = current {
        out.push((idx, acc));
    }
    out
}

/// Пересобрать сводки шагов и отчёты существующей сессии (повторный reparse идемпотентен).
pub fn reparse_session(store: &SessionStore, id: &str) -> anyhow::Result<SessionMeta> {
    let reader = store.reader(id)?;
    let meta = reader.meta().clone();
    if meta.status == "recording" {
        anyhow::bail!("сессия {id} пишется: reparse запрещён");
    }
    let events = reader.all_events();
    let groups = group_steps(&events);

    // Старые сводки — чтобы сохранить png, если в потоке его нет.
    let old_steps = reader.steps();
    let dir = reader.dir().to_path_buf();
    let steps_dir = dir.join("steps");
    std::fs::create_dir_all(&steps_dir)?;

    let mut new_steps: Vec<StepSummary> = Vec::new();
    for (idx, slice) in &groups {
        let png = old_steps
            .iter()
            .find(|s| s.idx == *idx)
            .and_then(|s| s.png.clone());
        let summary = decode::summarize_step(slice, *idx, "", 0.0, png);
        store::write_json_atomic(&steps_dir.join(format!("{idx:02}.json")), &summary)?;
        new_steps.push(summary);
    }

    // Убираем файлы шагов, которых больше нет в потоке.
    let keep: std::collections::HashSet<u32> = new_steps.iter().map(|s| s.idx).collect();
    if let Ok(rd) = std::fs::read_dir(&steps_dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let idx = path
                    .file_stem()
                    .and_then(|s| s.to_string_lossy().parse::<u32>().ok());
                if let Some(idx) = idx {
                    if !keep.contains(&idx) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }

    let mut meta = meta;
    meta.counts.events = events.len() as u64;
    meta.counts.steps = new_steps.len() as u64;
    meta.counts.tx = events.iter().filter(|e| e.kind == EventKind::Tx).count() as u64;
    meta.counts.rx = events.iter().filter(|e| e.kind == EventKind::Rx).count() as u64;
    // Байты считаем по фактическому payload, а не по длине hex-строки:
    // у «12 04 0d 1b» hex.len() == 11, и деление на 3 теряет по байту на событие.
    meta.counts.tx_bytes = events
        .iter()
        .filter(|e| e.kind == EventKind::Tx)
        .map(payload_len)
        .sum();
    meta.counts.rx_bytes = events
        .iter()
        .filter(|e| e.kind == EventKind::Rx)
        .map(payload_len)
        .sum();
    store.update_meta(&meta)?;
    report::write_session_reports(&dir, &meta, &new_steps)?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_from_capture_log() {
        let text = "====\n# capture start: label=WinKFP\n# tool: C:\\EC-APPS\\NFS\\BIN\\winkfpt.exe\n# wall(start)=2026-10-12 02:04:20\n# attached pid=32808\n# EDIABAS.INI: Interface=STD:OBD\n[+0.001s] VCP CreateFileW(COM6) handle=0x1\n";
        let banner = scan_banner(text);
        assert_eq!(banner.label.as_deref(), Some("WinKFP"));
        assert_eq!(banner.tool.as_deref(), Some(r"C:\EC-APPS\NFS\BIN\winkfpt.exe"));
        assert_eq!(banner.pid, Some(32808));
        assert_eq!(banner.wall_start.as_deref(), Some("2026-10-12 02:04:20"));
        assert!(banner.facts.iter().any(|f| f.starts_with("EDIABAS.INI:")));
    }

    #[test]
    fn banner_from_logger_out() {
        let text = "===\n ЛОГЕР — блок: WinKFP\n   приложение : C:\\EC-APPS\\NFS\\BIN\\winkfpt.exe\n   EDIABAS    : Interface=STD:OBD; obd.ini [OBD] Port=Com1\n   трассы     : C:\\EDIABAS\\TRACE\n===\n[+67.539s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b\n";
        let banner = scan_banner(text);
        assert_eq!(banner.label.as_deref(), Some("WinKFP"));
        assert_eq!(banner.tool.as_deref(), Some(r"C:\EC-APPS\NFS\BIN\winkfpt.exe"));
        assert!(banner.facts.iter().any(|f| f.starts_with("EDIABAS:")));
    }

    #[test]
    fn wall_conversion() {
        let s = wall_to_rfc3339("2026-10-12 02:04:20").unwrap();
        assert!(s.starts_with("2026-10-12T02:04:20"));
    }
}
