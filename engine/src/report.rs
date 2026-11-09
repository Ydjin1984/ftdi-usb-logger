//! Отчёты и экспорт. Владелец: ded-bekend.
//!
//! `report.txt` — формат старого логера (шапка сессии + блоки `# PHASE`), `report.md` —
//! Markdown со сводной Mermaid-схемой шагов. Экспорт: zip / jsonl / csv.

use crate::models::{Event, EventKind, SessionMeta, StepSummary};
use crate::store::write_text_atomic;
use anyhow::Context;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const BAR: &str = "================================================================================";
const DASH: &str = "--------------------------------------------------------------------------------";

/// Строковое имя вида события (REST/CSV).
pub fn kind_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Tx => "tx",
        EventKind::Rx => "rx",
        EventKind::Mark => "mark",
        EventKind::StepStart => "step_start",
        EventKind::StepEnd => "step_end",
        EventKind::File => "file",
        EventKind::FileHash => "file_hash",
        EventKind::Sys => "sys",
        EventKind::Module => "module",
        EventKind::Vcp => "vcp",
        EventKind::Usb => "usb",
        EventKind::Note => "note",
        EventKind::Shot => "shot",
        EventKind::Summary => "summary",
        EventKind::Error => "error",
        EventKind::Raw => "raw",
    }
}

fn top_hist(hist: &std::collections::BTreeMap<String, u64>) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = hist.iter().map(|(k, v)| (k.clone(), *v)).collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
}

fn hist_line(hist: &std::collections::BTreeMap<String, u64>) -> String {
    let items = top_hist(hist);
    if items.is_empty() {
        return "нет".into();
    }
    items
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn png_label(png: &Option<String>) -> String {
    match png {
        Some(p) if !p.is_empty() => p.clone(),
        _ => "нет".into(),
    }
}

fn event_dir(ev: &Event) -> &'static str {
    match ev.direction {
        Some(crate::models::Direction::Tx) => "tx",
        Some(crate::models::Direction::Rx) => "rx",
        None => "",
    }
}

/// Факт относится к USB/J2534-окружению (для отдельной группы в шапке отчёта).
fn is_usb_or_j2534_fact(fact: &str) -> bool {
    let lower = fact.to_ascii_lowercase();
    [
        "usb", "j2534", "passthru", "pass-thru", "winusb", "hid", "libusb", "usbpcap",
        "scanmatik", "chipsoft", "openport", "tactrix", "vxdiag",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

// ────────────────────────────── report.txt ───────────────────────────────

/// Текстовый отчёт в формате старого логера.
pub fn render_text(meta: &SessionMeta, steps: &[StepSummary]) -> String {
    let mut out = String::new();
    out.push_str(BAR);
    out.push('\n');
    out.push_str(&format!(
        "СЕССИЯ {:<24} start={}   статус={}   посылок={}   шагов={}   TX={}B RX={}B   файлов={}   ошибок={}\n",
        meta.label,
        meta.started_at,
        meta.status,
        meta.counts.tx,
        steps.len(),
        meta.counts.tx_bytes,
        meta.counts.rx_bytes,
        meta.counts.files,
        meta.counts.errors,
    ));
    if let Some(ended) = &meta.ended_at {
        out.push_str(&format!("  конец: {ended}\n"));
    }
    let transport = if meta.transport.is_empty() {
        "?".to_string()
    } else {
        meta.transport.clone()
    };
    out.push_str(&format!(
        "  транспорт(ы): {transport}   версия движка: {}   машина: {}\n",
        meta.engine_version, meta.host
    ));
    if let Some(tool) = &meta.tool_path {
        out.push_str(&format!("  инструмент: {tool}"));
        if let Some(pid) = meta.pid {
            out.push_str(&format!("   pid={pid}"));
        }
        if let Some(ver) = &meta.tool_version {
            out.push_str(&format!("   версия={ver}"));
        }
        out.push('\n');
        if let Some(sha) = &meta.tool_sha256 {
            out.push_str(&format!("  sha256 инструмента: {sha}\n"));
        }
    }
    if let Some(adapter) = &meta.adapter {
        out.push_str(&format!(
            "  адаптер: serial={} desc={} com={} vid={:04X} pid={:04X}\n",
            adapter.serial,
            adapter.description,
            adapter
                .com_port
                .map(|p| format!("COM{p}"))
                .unwrap_or_else(|| "?".into()),
            adapter.vendor_id.unwrap_or(0),
            adapter.product_id.unwrap_or(0),
        ));
    }
    if !meta.facts.is_empty() {
        // Универсальный захват: USB/J2534-факты показываем отдельной группой.
        let (usb_facts, other_facts): (Vec<&String>, Vec<&String>) = meta
            .facts
            .iter()
            .partition(|fact| is_usb_or_j2534_fact(fact));
        if !other_facts.is_empty() {
            out.push_str(&format!("  факты ({}):\n", other_facts.len()));
            for fact in &other_facts {
                out.push_str(&format!("    {fact}\n"));
            }
        }
        if !usb_facts.is_empty() {
            out.push_str(&format!("  USB/J2534-факты ({}):\n", usb_facts.len()));
            for fact in &usb_facts {
                out.push_str(&format!("    {fact}\n"));
            }
        }
    }
    if !meta.tags.is_empty() {
        out.push_str(&format!("  теги: {}\n", meta.tags.join(", ")));
    }

    if steps.is_empty() {
        out.push_str(&format!("{DASH}\n  шагов нет: сессия без размеченных обменов\n"));
    }

    for step in steps {
        out.push_str(&format!(
            "  # PHASE {}: {} | длительность {:.1} с | TX {} посылок / {} B | RX {} B | скриншот {}\n",
            step.idx,
            step.title,
            step.dur,
            step.exchanges,
            step.tx_bytes,
            step.rx_bytes,
            png_label(&step.png),
        ));
        out.push_str(&format!(
            "  # PHASE {}   команды: {}\n",
            step.idx,
            hist_line(&step.cmd_hist)
        ));
        out.push_str(&format!(
            "  # PHASE {}   ответы: {}\n",
            step.idx,
            hist_line(&step.resp_hist)
        ));
        if step.reads.is_empty() {
            out.push_str(&format!("  # PHASE {}   чтения: нет\n", step.idx));
        }
        for read in &step.reads {
            out.push_str(&format!(
                "  # PHASE {}   чтение 0x{:06X}..0x{:06X} {} B блоков {} sha256={}\n",
                step.idx,
                read.start,
                read.start + read.len,
                read.len,
                read.blocks,
                read.sha256,
            ));
        }
        for file in &step.filehash {
            out.push_str(&format!(
                "  # PHASE {}   файл-хеш: size={} sha256={} {}\n",
                step.idx, file.size, file.sha256, file.path
            ));
        }
        for job in &step.winkfp_jobs {
            out.push_str(&format!(
                "  # PHASE {}   winkfp: {}\n",
                step.idx,
                crate::ediabas::format_job(job)
            ));
        }
        out.push_str(&format!(
            "  # PHASE {}   вердикт: denied={} no_answer={} unparsed={} echo={}\n",
            step.idx,
            step.verdict.denied,
            step.verdict.no_answer,
            step.verdict.unparsed,
            if step.verdict.echo { "да" } else { "нет" },
        ));
    }

    out.push_str(DASH);
    out.push('\n');
    let tx: u64 = steps.iter().map(|s| s.tx_bytes).sum();
    let rx: u64 = steps.iter().map(|s| s.rx_bytes).sum();
    let exchanges: u64 = steps.iter().map(|s| s.exchanges).sum();
    let denied: u64 = steps.iter().map(|s| s.verdict.denied).sum();
    let no_answer: u64 = steps.iter().map(|s| s.verdict.no_answer).sum();
    out.push_str(&format!(
        "ИТОГО: шагов={}  посылок={}  TX={}B  RX={}B  denied={}  no_answer={}\n",
        steps.len(),
        exchanges,
        tx,
        rx,
        denied,
        no_answer,
    ));
    if !meta.notes.is_empty() {
        out.push_str(DASH);
        out.push('\n');
        out.push_str("ЗАМЕТКИ:\n");
        for note in &meta.notes {
            out.push_str(&format!("  {} ({}) {}\n", note.t, note.author, note.text));
        }
    }
    out
}

// ───────────────────────────── report.md ────────────────────────────────

fn md_cell(text: &str) -> String {
    text.replace('|', "/").replace('\n', " ")
}

fn mermaid_label(text: &str) -> String {
    text.replace('"', "'")
        .replace('[', "(")
        .replace(']', ")")
        .replace('\n', " ")
}

/// Markdown-отчёт с Mermaid-сводкой шагов.
/// Строки `# PHASE ...` одного шага без отступа — ровно так они пишутся в `raw.log`
/// (в формате старого логера) и потом могут быть импортированы обратно.
pub fn render_step_phase(step: &StepSummary) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!(
        "# PHASE {}: {} | длительность {:.1} с | TX {} посылок / {} B | RX {} B | скриншот {}",
        step.idx,
        step.title,
        step.dur,
        step.exchanges,
        step.tx_bytes,
        step.rx_bytes,
        png_label(&step.png),
    ));
    out.push(format!(
        "# PHASE {}   команды: {}",
        step.idx,
        hist_line(&step.cmd_hist)
    ));
    out.push(format!(
        "# PHASE {}   ответы: {}",
        step.idx,
        hist_line(&step.resp_hist)
    ));
    if step.reads.is_empty() {
        out.push(format!("# PHASE {}   чтения: нет", step.idx));
    }
    for read in &step.reads {
        out.push(format!(
            "# PHASE {}   чтение 0x{:06X}..0x{:06X} {} B блоков {} sha256={}",
            step.idx,
            read.start,
            read.start + read.len,
            read.len,
            read.blocks,
            read.sha256,
        ));
    }
    for file in &step.filehash {
        out.push(format!(
            "# PHASE {}   файл-хеш: size={} sha256={} {}",
            step.idx, file.size, file.sha256, file.path
        ));
    }
    for job in &step.winkfp_jobs {
        out.push(format!(
            "# PHASE {}   winkfp: {}",
            step.idx,
            crate::ediabas::format_job(job)
        ));
    }
    out.push(format!(
        "# PHASE {}   вердикт: denied={} no_answer={} unparsed={} echo={}",
        step.idx,
        step.verdict.denied,
        step.verdict.no_answer,
        step.verdict.unparsed,
        if step.verdict.echo { "да" } else { "нет" },
    ));
    out
}

pub fn render_markdown(meta: &SessionMeta, steps: &[StepSummary]) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Отчёт сессии «{}»\n\n", meta.label));
    out.push_str("| Поле | Значение |\n|---|---|\n");
    let rows: Vec<(String, String)> = vec![
        ("ID".into(), meta.id.clone()),
        ("Начало".into(), meta.started_at.clone()),
        (
            "Конец".into(),
            meta.ended_at.clone().unwrap_or_else(|| "—".into()),
        ),
        ("Статус".into(), meta.status.clone()),
        ("Транспорт".into(), meta.transport.clone()),
        ("Машина".into(), meta.host.clone()),
        (
            "Инструмент".into(),
            meta.tool_path.clone().unwrap_or_else(|| "—".into()),
        ),
        ("Событий".into(), meta.counts.events.to_string()),
        ("Шагов".into(), steps.len().to_string()),
        ("TX, байт".into(), meta.counts.tx_bytes.to_string()),
        ("RX, байт".into(), meta.counts.rx_bytes.to_string()),
        ("Ошибок".into(), meta.counts.errors.to_string()),
    ];
    for (key, value) in rows {
        out.push_str(&format!("| {} | {} |\n", md_cell(&key), md_cell(&value)));
    }
    out.push('\n');

    if !meta.facts.is_empty() {
        out.push_str("## Факты окружения\n\n");
        for fact in &meta.facts {
            out.push_str(&format!("- {fact}\n"));
        }
        out.push('\n');
    }

    out.push_str("## Сводная схема шагов\n\n```mermaid\nflowchart TD\n");
    out.push_str("    Start([Старт сессии])\n");
    let mut prev = "Start".to_string();
    for step in steps {
        let node = format!("S{}", step.idx);
        let label = format!(
            "Шаг {}: {}<br/>{:.1} с · TX {} / {} B",
            step.idx, step.title, step.dur, step.exchanges, step.tx_bytes
        );
        out.push_str(&format!("    {node}[\"{}\"]\n", mermaid_label(&label)));
        out.push_str(&format!("    {prev} --> {node}\n"));
        prev = node;
    }
    out.push_str("    End([Финиш])\n");
    out.push_str(&format!("    {prev} --> End\n"));
    out.push_str("```\n\n");

    out.push_str("## Итоги\n\n| Метрика | Значение |\n|---|---|\n");
    let exchanges: u64 = steps.iter().map(|s| s.exchanges).sum();
    let tx: u64 = steps.iter().map(|s| s.tx_bytes).sum();
    let rx: u64 = steps.iter().map(|s| s.rx_bytes).sum();
    let denied: u64 = steps.iter().map(|s| s.verdict.denied).sum();
    let no_answer: u64 = steps.iter().map(|s| s.verdict.no_answer).sum();
    let unparsed: u64 = steps.iter().map(|s| s.verdict.unparsed).sum();
    for (k, v) in [
        ("Посылок", exchanges.to_string()),
        ("TX, байт", tx.to_string()),
        ("RX, байт", rx.to_string()),
        ("denied", denied.to_string()),
        ("no-answer", no_answer.to_string()),
        ("unparsed", unparsed.to_string()),
        (
            "Эхо",
            if steps.iter().any(|s| s.verdict.echo) {
                "да"
            } else {
                "нет"
            }
            .into(),
        ),
    ] {
        out.push_str(&format!("| {} | {} |\n", k, v));
    }
    out.push('\n');

    if steps.is_empty() {
        out.push_str("## Шаги\n\nШагов нет.\n");
    }

    for step in steps {
        out.push_str(&format!("## Шаг {} — {}\n\n", step.idx, step.title));
        out.push_str("| Параметр | Значение |\n|---|---|\n");
        for (k, v) in [
            ("Длительность, с", format!("{:.1}", step.dur)),
            ("Посылок", step.exchanges.to_string()),
            ("TX, байт", step.tx_bytes.to_string()),
            ("RX, байт", step.rx_bytes.to_string()),
            ("Начало", if step.started_at.is_empty() { "—".into() } else { step.started_at.clone() }),
            ("Конец", if step.ended_at.is_empty() { "—".into() } else { step.ended_at.clone() }),
            ("Скриншот", png_label(&step.png)),
            (
                "Вердикт",
                format!(
                    "denied={} · no_answer={} · unparsed={} · echo={}",
                    step.verdict.denied,
                    step.verdict.no_answer,
                    step.verdict.unparsed,
                    if step.verdict.echo { "да" } else { "нет" }
                ),
            ),
        ] {
            out.push_str(&format!("| {} | {} |\n", k, md_cell(&v)));
        }
        out.push('\n');

        out.push_str(&format!("**Команды:** {}\n\n", hist_line(&step.cmd_hist)));
        out.push_str(&format!("**Ответы:** {}\n\n", hist_line(&step.resp_hist)));

        if !step.reads.is_empty() {
            out.push_str("**Потоки чтения**\n\n| Начало | Конец | Длина, B | Блоков | SHA-256 |\n|---|---|---|---|---|\n");
            for read in &step.reads {
                out.push_str(&format!(
                    "| 0x{:06X} | 0x{:06X} | {} | {} | `{}` |\n",
                    read.start,
                    read.start + read.len,
                    read.len,
                    read.blocks,
                    read.sha256
                ));
            }
            out.push('\n');
        }
        if !step.filehash.is_empty() {
            out.push_str("**Файлы**\n\n| Путь | Размер | SHA-256 |\n|---|---|---|\n");
            for file in &step.filehash {
                out.push_str(&format!(
                    "| {} | {} | `{}` |\n",
                    md_cell(&file.path),
                    file.size,
                    file.sha256
                ));
            }
            out.push('\n');
        }
        if !step.winkfp_jobs.is_empty() {
            out.push_str("**WinKFP / EDIABAS**\n\n");
            for job in &step.winkfp_jobs {
                out.push_str(&format!("- `{}`\n", crate::ediabas::format_job(job)));
            }
            out.push('\n');
        }
    }
    out
}

/// Записать `report.txt` и `report.md` в каталог сессии.
pub fn write_session_reports(
    dir: &Path,
    meta: &SessionMeta,
    steps: &[StepSummary],
) -> anyhow::Result<()> {
    let txt = render_text(meta, steps);
    let md = render_markdown(meta, steps);
    write_text_atomic(&dir.join("report.txt"), &txt)?;
    write_text_atomic(&dir.join("report.md"), &md)?;
    Ok(())
}

// ─────────────────────────────── экспорт ─────────────────────────────────

/// ZIP-архив каталога сессии (пути внутри — относительно каталога).
pub fn export_zip(session_dir: &Path, out_zip: &Path) -> anyhow::Result<()> {
    if let Some(parent) = out_zip.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(out_zip)
        .with_context(|| format!("не создать архив {}", out_zip.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in walkdir::WalkDir::new(session_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path
            .strip_prefix(session_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel.starts_with("export/") {
            continue; // не пакуем прошлые экспорты
        }
        zip.start_file(rel, options)
            .with_context(|| format!("zip: не добавить {}", path.display()))?;
        let mut src = File::open(path)?;
        std::io::copy(&mut src, &mut zip)?;
    }
    zip.finish().context("zip: финализация")?;
    Ok(())
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// CSV: `seq,t,wall,kind,api,dir,len,hex,step`.
pub fn export_csv(events: &[Event], out: &Path) -> anyhow::Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut text = String::with_capacity(events.len() * 96 + 64);
    text.push_str("seq,t,wall,kind,api,dir,len,hex,step\n");
    for ev in events {
        text.push_str(&format!(
            "{},{:.3},{},{},{},{},{},{},{}\n",
            ev.seq,
            ev.t,
            csv_field(&ev.wall),
            kind_name(ev.kind),
            csv_field(&ev.api),
            event_dir(ev),
            ev.len,
            csv_field(&ev.hex),
            ev.step.map(|s| s.to_string()).unwrap_or_default(),
        ));
    }
    write_text_atomic(out, &text)
}

/// JSONL-экспорт: копия `events.jsonl` сессии.
pub fn export_jsonl(dir: &Path, out: &Path) -> anyhow::Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let src = dir.join("events.jsonl");
    let data = std::fs::read(&src).unwrap_or_default();
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = File::create(out)?;
    f.write_all(&data)?;
    Ok(())
}

/// Markdown-экспорт отчёта в произвольный файл.
pub fn export_markdown(meta: &SessionMeta, steps: &[StepSummary], out: &Path) -> anyhow::Result<()> {
    write_text_atomic(out, &render_markdown(meta, steps))
}

