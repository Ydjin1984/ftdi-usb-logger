//! Прогон готового `raw.log` через декодер без запуска сервера.
//!
//! Нужен для приёмки «старый лог разбирается новой сборкой» (docs/09 §10):
//! скрипт на готовом `events.jsonl` проверяет только скрипт, а не изменение
//! логгера, поэтому декодер гоняется по исходному `raw.log`.
//!
//! ```text
//! cargo run --example decode_raw -- <raw.log> [--json events.jsonl]
//! ```
//!
//! Печатает: число строк/событий, распределение по `api`, сумму байт `hex`,
//! число событий с непустым `hex` и первые ошибки (если разбор где-то сорвался).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};

use ftdi_logger::decode::parse_capture_line;

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: decode_raw <raw.log> [--json events.jsonl]");
        std::process::exit(2);
    };
    let mut json_path: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--json" {
            json_path = args.next();
        }
    }

    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);

    let mut lines = 0u64;
    let mut events = 0u64;
    let mut empty = 0u64;
    let mut with_hex = 0u64;
    let mut hex_bytes = 0u64;
    let mut api_hist: BTreeMap<String, u64> = BTreeMap::new();
    let mut kind_hist: BTreeMap<String, u64> = BTreeMap::new();
    let mut raw_fallback = 0u64;

    let mut json_out = match &json_path {
        Some(p) => Some(std::io::BufWriter::new(std::fs::File::create(p)?)),
        None => None,
    };

    for line in reader.lines() {
        let line = line?;
        lines += 1;
        match parse_capture_line(&line) {
            Some(ev) => {
                events += 1;
                if !ev.hex.is_empty() {
                    with_hex += 1;
                    hex_bytes += (ev.hex.len() as u64 + 1) / 3;
                }
                *api_hist.entry(ev.api.clone()).or_insert(0) += 1;
                *kind_hist
                    .entry(format!("{:?}", ev.kind).to_ascii_lowercase())
                    .or_insert(0) += 1;
                if ev.api == "RAW" && ev.text.is_none() {
                    raw_fallback += 1;
                }
                if let Some(out) = json_out.as_mut() {
                    let text = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".into());
                    writeln!(out, "{text}")?;
                }
            }
            None => empty += 1,
        }
    }
    if let Some(out) = json_out.as_mut() {
        out.flush()?;
    }

    println!("файл: {path}");
    println!("строк: {lines}, событий: {events}, пустых: {empty}");
    println!("с hex: {with_hex}, байт в hex: {hex_bytes}");
    println!("нераспознанных (api=RAW без text): {raw_fallback}");
    println!("--- виды событий ---");
    for (kind, n) in &kind_hist {
        println!("{n:>8}  {kind}");
    }
    println!("--- api (топ 25) ---");
    let mut apis: Vec<(&String, &u64)> = api_hist.iter().collect();
    apis.sort_by(|a, b| b.1.cmp(a.1));
    for (api, n) in apis.iter().take(25) {
        println!("{n:>8}  {api}");
    }
    Ok(())
}
