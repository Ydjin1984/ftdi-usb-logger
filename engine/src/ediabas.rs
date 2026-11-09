//! EDIABAS / WinKFP: INI-факты и разбор трасс. Владелец: ded-bekend.
//!
//! Эталон — `E:\Replica\work\orig-capture\winkfp.py`: `ediabas_facts()`, `parse_api_trc()`,
//! `TraceWatcher` (чтение прироста трасс по offset с учётом ротации по TraceSize).

use crate::models::WinkfpJob;
use serde_json::{Map, Value};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const EDIABAS_INI: &str = r"C:\EDIABAS\BIN\EDIABAS.INI";
pub const OBD_INI: &str = r"C:\EDIABAS\BIN\OBD.INI";
pub const WINKFP_INI: &str = r"C:\EC-APPS\NFS\BIN\Winkfpt.ini";
pub const TRACE_DIR: &str = r"C:\EDIABAS\TRACE";

/// Служебные строки api.trc, которые не являются результатами job'а.
const RESULT_SKIP: &[&str] = &["OBJECT", "JOBNAME", "VARIANTE", "JOBSTATUS", "SAETZE", "SETZE"];

fn read_ini_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    // EDIABAS-ини могут быть в cp1251/latin-1; для фактов достаточно lossy.
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Первое `key=value` из ini (комментарии `;`/`#` игнорируем).
pub fn ini_get(path: &Path, key: &str) -> String {
    let Some(text) = read_ini_text(path) else {
        return String::new();
    };
    for line in text.lines() {
        let s = line.trim();
        if s.is_empty() || s.starts_with(';') || s.starts_with('#') || s.starts_with('[') {
            continue;
        }
        let Some((k, v)) = s.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            return v.trim().to_string();
        }
    }
    String::new()
}

fn push_kv(parts: &mut Vec<String>, key: &str, value: &str) {
    if !value.is_empty() {
        parts.push(format!("{key}={value}"));
    }
}

/// Факты окружения EDIABAS/WinKFP из конкретных ini-файлов (для тестов и импорта).
pub fn ini_facts_from(ediabas_ini: &Path, obd_ini: &Path, winkfp_ini: &Path) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    let mut parts = Vec::new();
    for (key, value) in [
        ("Interface", ini_get(ediabas_ini, "Interface")),
        ("TracePath", ini_get(ediabas_ini, "TracePath")),
        ("ApiTrace", ini_get(ediabas_ini, "ApiTrace")),
        ("IfhTrace", ini_get(ediabas_ini, "IfhTrace")),
        ("TraceSize", ini_get(ediabas_ini, "TraceSize")),
    ] {
        push_kv(&mut parts, key, &value);
    }
    if !parts.is_empty() {
        out.push((EDIABAS_INI.into(), parts.join(" ")));
    }

    let mut parts = Vec::new();
    for (key, value) in [
        ("Port", ini_get(obd_ini, "Port")),
        ("Hardware", ini_get(obd_ini, "Hardware")),
        ("RETRY", ini_get(obd_ini, "RETRY")),
    ] {
        push_kv(&mut parts, key, &value);
    }
    if !parts.is_empty() {
        out.push((format!("{OBD_INI} [OBD]"), parts.join("; ")));
    }

    let mut parts = Vec::new();
    for key in [
        "API_TRACE",
        "IFH_TRACE",
        "SCHNELLE_BAUDRATE",
        "TEST_CHECKSUMME",
        "TRACE_SIZE",
    ] {
        let value = ini_get(winkfp_ini, key);
        push_kv(&mut parts, key, &value);
    }
    if !parts.is_empty() {
        out.push((WINKFP_INI.into(), parts.join(" ")));
    }
    out
}

/// Факты окружения по стандартным путям EDIABAS/WinKFP (только существующие файлы).
pub fn ini_facts() -> Vec<(String, String)> {
    ini_facts_from(
        Path::new(EDIABAS_INI),
        Path::new(OBD_INI),
        Path::new(WINKFP_INI),
    )
}

/// Текущий размер трассы; отсутствующий файл — 0 (как `_size()` в winkfp.py).
pub fn snapshot_trace(path: &Path) -> std::io::Result<u64> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err),
    }
}

/// Прочитать прирост трассы с `offset`. При ротации (файл стал короче) — всё с начала.
/// Возвращает (данные, новый offset).
pub fn read_from(path: &Path, offset: u64) -> std::io::Result<(Vec<u8>, u64)> {
    let mut f = std::fs::File::open(path)?;
    let size = f.metadata()?.len();
    let start = if size < offset { 0 } else { offset };
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let new_offset = start + buf.len() as u64;
    Ok((buf, new_offset))
}

fn value_display(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Разобрать текст `api.trc` в список job'ов (sgbd/job/args/results/errors).
pub fn parse_api_trace(text: &str) -> Vec<WinkfpJob> {
    #[derive(PartialEq)]
    enum Mode {
        Idle,
        Job,
        Results,
    }
    let mut jobs: Vec<WinkfpJob> = Vec::new();
    let mut mode = Mode::Idle;

    for raw in text.lines() {
        let s = raw.trim();
        if s.is_empty() {
            continue;
        }
        if s == "Job" {
            jobs.push(WinkfpJob::default());
            mode = Mode::Job;
            continue;
        }
        if s.starts_with("Results") || s.starts_with("Ergebnis") {
            mode = Mode::Results;
            continue;
        }
        if s == "Initialization" || s == "End" || s == "Ende" {
            mode = Mode::Idle;
            continue;
        }

        // `Error (134) API-0014: RESULT NOT FOUND` / `Fehler (…) …`
        let lowered = s.to_ascii_lowercase();
        if lowered.starts_with("error") || lowered.starts_with("fehler") {
            if let Some(open) = s.find('(') {
                if let Some(close) = s[open..].find(')') {
                    let close = open + close;
                    let code = &s[open + 1..close];
                    let rest = s[close + 1..].trim();
                    let err = format!("Error ({code}) {rest}");
                    if let Some(cur) = jobs.last_mut() {
                        if cur.errors.last() != Some(&err) {
                            cur.errors.push(err); // api.trc повторяет ошибку подряд
                        }
                    }
                }
            }
            mode = Mode::Idle;
            continue;
        }

        let Some(cur) = jobs.last_mut() else {
            continue;
        };
        match mode {
            Mode::Job => {
                // Аргументы job'а в трассе — строки в кавычках: "sgbd", "job", "args"…
                let is_quoted = s.len() >= 2 && s.starts_with('"') && s.ends_with('"');
                if !is_quoted {
                    continue;
                }
                let val = &s[1..s.len() - 1];
                if cur.sgbd.is_empty() {
                    cur.sgbd = val.to_string();
                } else if cur.job.is_empty() {
                    cur.job = val.to_string();
                } else if !val.is_empty() {
                    cur.args.push(val.to_string());
                }
            }
            Mode::Results => {
                let Some((key, value)) = s.split_once('=') else {
                    continue;
                };
                let key = key.trim();
                if key.is_empty()
                    || !key.chars().next().map(|c| c.is_ascii_alphabetic() || c == '_').unwrap_or(false)
                    || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    continue;
                }
                if RESULT_SKIP.contains(&key) {
                    continue;
                }
                let mut map: Map<String, Value> = Map::new();
                map.insert(key.to_string(), Value::String(value.trim().to_string()));
                for (k, v) in &cur.results {
                    map.entry(k.clone()).or_insert_with(|| v.clone());
                }
                cur.results = map;
                cur.results_total = cur.results.len();
            }
            Mode::Idle => {}
        }
    }
    jobs
}

/// Выбрать из `IFH.trc` строки обмена (INPUT/OUTPUT/ошибки) для отчёта.
pub fn parse_ifh_trace(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let s = raw.trim();
        if s.is_empty() || s.contains(">>>") || s.contains("<<<") {
            continue;
        }
        let upper = s.to_ascii_uppercase();
        if upper.contains("INPUT:")
            || upper.contains("OUTPUT:")
            || upper.contains("ERROR")
            || upper.contains("FEHLER")
            || upper.contains("TIMEOUT")
        {
            out.push(s.to_string());
        }
    }
    out
}

/// Человекочитаемая строка job'а для лога/отчёта шага (как `format_job` в winkfp.py).
pub fn format_job(job: &WinkfpJob) -> String {
    let job_name = if job.job.is_empty() { "?" } else { &job.job };
    let sgbd = if job.sgbd.is_empty() { "?" } else { &job.sgbd };
    let mut head = format!("job=\"{job_name}\" sgbd=\"{sgbd}\"");
    if !job.args.is_empty() {
        let args = job
            .args
            .iter()
            .take(3)
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(",");
        head.push_str(&format!(" args={args}"));
    }
    let mut parts = vec![head];
    if !job.errors.is_empty() {
        parts.push(format!("ОШИБКА: {}", job.errors.join("; ")));
    }
    if !job.results.is_empty() {
        let items: Vec<(&String, &Value)> = job.results.iter().collect();
        let shown = items
            .iter()
            .take(10)
            .map(|(k, v)| format!("{k}={}", value_display(v)))
            .collect::<Vec<_>>()
            .join(" ");
        let more = if items.len() > 10 {
            format!(" …+{}", items.len() - 10)
        } else {
            String::new()
        };
        parts.push(format!(
            "результатов={} {shown}{more}",
            job.results_total.max(items.len())
        ));
    }
    parts.join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_trace_jobs() {
        let text = "#'Mon Oct 12 02:00:00 2026;!Xh;V7.3.0;#\n\
                    Initialization\nJob\n\t\"bms46ds0\"\n\t\"ident\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
                    Results:\n\t[ 0 ]\n\tOBJECT = \"bms46ds0\"\n\tID_BMW_NR = \"1430940\"\n\tID_SW_NR = \"F0\"\n\
                    Initialization\nJob\n\t\"ms450\"\n\t\"FLASH_PROGRAMMIEREN\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
                    Error (134) API-0014: RESULT NOT FOUND\n";
        let jobs = parse_api_trace(text);
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].sgbd, "bms46ds0");
        assert_eq!(jobs[0].job, "ident");
        assert_eq!(jobs[0].results_total, 2);
        assert_eq!(
            jobs[0].results.get("ID_BMW_NR"),
            Some(&Value::String("\"1430940\"".into()))
        );
        assert_eq!(jobs[1].job, "FLASH_PROGRAMMIEREN");
        assert_eq!(jobs[1].errors, vec!["Error (134) API-0014: RESULT NOT FOUND"]);
    }
}
