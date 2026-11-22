//! Отчёты и экспорт. Владелец: ded-bekend.
//!
//! `report.txt` — формат старого логера (шапка сессии + блоки `# PHASE`), `report.md` —
//! Markdown со сводной Mermaid-схемой шагов. Экспорт: zip / jsonl / csv.

use crate::models::{Event, EventKind, ProxyLane, SessionMeta, StepSummary};
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
        EventKind::Scope => "scope",
        EventKind::UiAction => "ui_action",
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

/// Факт относится к USB/J2534/LAN-окружению (для отдельной группы в шапке отчёта).
fn is_usb_or_j2534_fact(fact: &str) -> bool {
    let lower = fact.to_ascii_lowercase();
    [
        "usb", "j2534", "passthru", "pass-thru", "winusb", "hid", "libusb", "usbpcap",
        "scanmatik", "chipsoft", "openport", "tactrix", "vxdiag",
        "lan", "doip", "winsock", "ws2_32", "tcp", "udp",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

// ───────────────────────────── J2534-прокси ──────────────────────────────

/// Доля потерянных кадров основного канала, выше которой молчать нельзя.
const PROXY_LOSS_WARN: f64 = 5.0;

/// Предупреждение о потере второго канала (`None`, если потерь мало).
///
/// Порог 5 % — из контракта (docs/13 §8): ниже него расхождение объясняется
/// тем, что frida цепляется позже прокси, и предупреждение было бы шумом.
fn proxy_loss_warning(lane: &ProxyLane) -> Option<String> {
    let main = lane.cross.main_frames();
    let missing = lane.cross.missing();
    if main == 0 || missing == 0 {
        return None;
    }
    let percent = missing as f64 * 100.0 / main as f64;
    (percent > PROXY_LOSS_WARN).then(|| {
        format!(
            "в прокси потеряно {missing} из {main} кадров основного канала \
             ({percent:.1} %) — второй канал неполон"
        )
    })
}

/// Строка сверки — одна на оба формата отчёта, чтобы txt и md не расходились.
fn proxy_cross_line(lane: &ProxyLane) -> String {
    if lane.cross.main_frames() == 0 {
        return "нет основного канала".to_string();
    }
    format!(
        "совпало TX {} / RX {}, потеряно в прокси {} (TX {} / RX {}), лишних {}",
        lane.cross.tx_matched,
        lane.cross.rx_matched,
        lane.cross.missing(),
        lane.cross.tx_missing,
        lane.cross.rx_missing,
        lane.cross.extra,
    )
}

/// Раздел «J2534 прокси» для `report.txt`.
fn proxy_text_block(lane: &ProxyLane) -> String {
    let mut out = String::new();
    out.push_str("  J2534 прокси:\n");
    out.push_str(&format!(
        "    Журналов: {} ({:.1} КБ)\n",
        lane.files,
        lane.bytes as f64 / 1024.0
    ));
    out.push_str(&format!("    Кадры: TX {} / RX {}\n", lane.tx, lane.rx));
    out.push_str(&format!(
        "    Вызовов: {}, ошибок: {}\n",
        lane.calls, lane.errors
    ));
    out.push_str(&format!(
        "    Сверка с основным каналом: {}\n",
        proxy_cross_line(lane)
    ));
    if let (Some(first), Some(last)) = (lane.first_t, lane.last_t) {
        out.push_str(&format!(
            "    Время прокси (от загрузки DLL): +{first:.3}…+{last:.3} с\n"
        ));
    }
    for note in lane
        .notes
        .iter()
        .filter(|note| note.as_str() != "нет основного канала")
    {
        out.push_str(&format!("    · {note}\n"));
    }
    if let Some(warning) = proxy_loss_warning(lane) {
        out.push_str(&format!("    ВНИМАНИЕ: {warning}\n"));
    }
    out
}

/// Раздел «J2534 прокси» для `report.md`.
fn proxy_md_block(lane: &ProxyLane) -> String {
    let mut out = String::new();
    out.push_str("## J2534 прокси\n\n| Метрика | Значение |\n|---|---|\n");
    out.push_str(&format!(
        "| Журналов | {} ({:.1} КБ) |\n",
        lane.files,
        lane.bytes as f64 / 1024.0
    ));
    out.push_str(&format!(
        "| Кадры | TX {} / RX {} |\n",
        lane.tx, lane.rx
    ));
    out.push_str(&format!(
        "| Вызовов | {} (ошибок {}) |\n",
        lane.calls, lane.errors
    ));
    out.push_str(&format!(
        "| Сверка с основным каналом | {} |\n",
        md_cell(&proxy_cross_line(lane))
    ));
    if let (Some(first), Some(last)) = (lane.first_t, lane.last_t) {
        out.push_str(&format!(
            "| Время прокси (от загрузки DLL) | +{first:.3}…+{last:.3} с |\n"
        ));
    }
    out.push('\n');
    if let Some(warning) = proxy_loss_warning(lane) {
        out.push_str(&format!("> **ВНИМАНИЕ:** {warning}\n\n"));
    }
    out
}

// ────────────────────────────── report.txt ───────────────────────────────

/// Текстовый отчёт в формате старого логера.
pub fn render_text(meta: &SessionMeta, steps: &[StepSummary]) -> String {
    let mut out = String::new();
    out.push_str(BAR);
    out.push('\n');
    out.push_str(&format!(
        "СЕССИЯ {:<24} start={}   статус={}   посылок={}   шагов={}   TX={}B RX={}B   файлов={}   ошибок={}   холостых опросов={}\n",
        meta.label,
        meta.started_at,
        meta.status,
        meta.counts.tx,
        steps.len(),
        meta.counts.tx_bytes,
        meta.counts.rx_bytes,
        meta.counts.files,
        meta.counts.errors,
        meta.counts.empty_polls,
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
    if let Some(proto) = protocol_summary(meta) {
        out.push_str(&format!("  протокол: {proto}\n"));
    }
    if meta.counts.net_bytes > 0 {
        out.push_str(&format!(
            "  сеть (не шина): {} B, TX {} / RX {} событий\n",
            meta.counts.net_bytes, meta.counts.net_tx, meta.counts.net_rx
        ));
    }
    if meta.counts.untracked_channels > 0 {
        out.push_str(&format!(
            "  каналов без PassThruConnect: {} (не ошибка — см. docs/12 §10)\n",
            meta.counts.untracked_channels
        ));
    }
    // «Ошибок: 0» при непустом events.jsonl — вопрос без ответа. Диагностика
    // (chan-miss и подобные) идёт отдельной строкой и в ошибки не входит.
    if meta.counts.diagnostics > 0 {
        out.push_str(&format!(
            "  диагностика: {} событий (не ошибки) — подробности в events.jsonl, kind=error\n",
            meta.counts.diagnostics
        ));
    }
    out.push_str(&layers_text(meta));
    // Вендорские вызовы: без них не видно, что конфигурация GPT вообще снята.
    if meta.counts.vendor_calls > 0 {
        out.push_str(&format!(
            "  вендорские J2534: {} ({})\n",
            meta.counts.vendor_calls,
            vendor_ops_label(meta)
        ));
        if !meta.counts.vendor_gpt.is_empty() {
            out.push_str(&format!(
                "  GPT (1377 op=0x0b): {}\n",
                meta.counts.vendor_gpt
            ));
        }
    }
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
        let mut parts: Vec<String> = Vec::new();
        if let Some(vendor) = &adapter.vendor {
            parts.push(format!("vendor={vendor}"));
        }
        if !adapter.serial.is_empty() {
            parts.push(format!("serial={}", adapter.serial));
        }
        if !adapter.description.is_empty() {
            parts.push(format!("desc={}", adapter.description));
        }
        if let Some(fw) = &adapter.firmware {
            parts.push(format!("fw={fw}"));
        }
        if let Some(ver) = &adapter.dll_version {
            parts.push(format!("dll={ver}"));
        }
        if let Some(api) = &adapter.api {
            parts.push(format!("api={api}"));
        }
        if let Some(com) = adapter.com_port {
            parts.push(format!("COM{com}"));
        }
        out.push_str(&format!("  адаптер: {}\n", parts.join(" ")));
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
    // Полоса J2534-прокси — отдельным блоком, а не строкой в фактах: это второй
    // канал, и его потеря видна только в сверке с основным (docs/13 §8).
    if let Some(lane) = &meta.proxy {
        out.push_str(&proxy_text_block(lane));
    }
    if meta.counts.errors > 0 && !meta.counts.error_samples.is_empty() {
        // Ошибок мало и они важны: показываем, что именно попало в счётчик.
        out.push_str(&format!("  ошибки ({}):\n", meta.counts.errors));
        for sample in &meta.counts.error_samples {
            out.push_str(&format!("    {sample}\n"));
        }
        let shown = meta.counts.error_samples.len() as u64;
        if meta.counts.errors > shown {
            out.push_str(&format!(
                "    … ещё {} — полный список в events.jsonl (kind=error)\n",
                meta.counts.errors - shown
            ));
        }
    }

    if steps.is_empty() {
        out.push_str(&format!(
            "{DASH}\n  шагов нет: границы обмена не размечены (отрезки — в фактах `# обмен …`)\n"
        ));
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
        if !step.net_hist.is_empty() {
            out.push_str(&format!(
                "  # PHASE {}   сеть (не протокол ЭБУ): {} | TX {} B / RX {} B\n",
                step.idx,
                hist_line(&step.net_hist),
                step.net_tx,
                step.net_rx
            ));
        }
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
    // Объём сессии берём из счётчиков: шаги распознаются не всегда (bulk-чтение
    // флеша идёт как 11k обменов без шагов), и суммирование по шагам обнуляло
    // «Итоги» — 0 при 132492 B TX в шапке того же отчёта.
    let by_steps = !steps.is_empty();
    let tx: u64 = if by_steps {
        steps.iter().map(|s| s.tx_bytes).sum()
    } else {
        meta.counts.tx_bytes
    };
    let rx: u64 = if by_steps {
        steps.iter().map(|s| s.rx_bytes).sum()
    } else {
        meta.counts.rx_bytes
    };
    let exchanges: u64 = if by_steps {
        steps.iter().map(|s| s.exchanges).sum()
    } else {
        meta.counts.tx
    };
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
    if !by_steps {
        out.push_str("  объём — по счётчикам сессии (шаги не распознаны)\n");
    }
    for line in scope_lines(meta) {
        out.push_str(&format!("  {line}\n"));
    }
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

/// Читаемое имя протокола J2534 по `ProtocolID` из PASSTHRU_MSG.
fn protocol_label(proto: &str) -> String {
    let name = match proto.to_ascii_lowercase().as_str() {
        "0x8001" => "J1850 PWM",
        "0x8002" => "J1850 VPW",
        "0x8003" => "ISO 14230 KWP2000",
        "0x8004" => "ISO 9141",
        "0x8005" => "CAN 11/500",
        "0x8006" => "CAN 29/500",
        "0x8007" => "CAN 11/250",
        "0x8008" => "CAN 29/250",
        "0x8009" => "ISO 15765 (CAN)",
        _ => "",
    };
    if name.is_empty() {
        proto.to_string()
    } else {
        format!("{proto} ({name})")
    }
}

/// Основной протокол сессии: самый частый в TX и его доля.
///
/// Нужен, потому что в bulk-сессиях (чтение/запись флеша) шагов нет, и отчёт
/// иначе вообще не говорил, по какой шине шёл обмен.
fn protocol_summary(meta: &SessionMeta) -> Option<String> {
    let (proto, n) = meta.counts.protocols.iter().max_by_key(|(_, n)| **n)?;
    let total: u64 = meta.counts.protocols.values().sum();
    Some(format!("{} · {} из {}", protocol_label(proto), n, total))
}

/// Вендорские вызовы по op: `0xb×11, 0x0×2`.
fn vendor_ops_label(meta: &SessionMeta) -> String {
    meta.counts
        .vendor_ops
        .iter()
        .map(|(op, n)| format!("{op}×{n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Слои J2534 человеческим языком: `прокси + драйвер`.
fn layers_label(meta: &SessionMeta) -> String {
    if meta.counts.j2534_layers.is_empty() {
        // Старая сессия без разметки: показываем хотя бы модули, которые
        // реально открывались — по ним и видно схему «прокси → драйвер».
        if !meta.counts.j2534_modules.is_empty() {
            return meta.counts.j2534_modules.join(" + ");
        }
        return "не размечено".into();
    }
    let mut parts: Vec<String> = Vec::new();
    for layer in &meta.counts.j2534_layers {
        parts.push(match layer.as_str() {
            "proxy" => "прокси".to_string(),
            "driver" => "драйвер".to_string(),
            other => other.to_string(),
        });
    }
    parts.join(" + ")
}

/// Признак схемы «два слоя»: размеченные слои либо два разных модуля J2534.
fn two_layers(meta: &SessionMeta) -> bool {
    meta.counts.j2534_layers.len() > 1 || meta.counts.j2534_modules.len() > 1
}

/// Строка `report.txt` про слои и внутренние записи.
///
/// Две задачи: показать, что связь вызовов сработала (иначе «почему TX вдвое
/// меньше, чем строк TX в логе» — вопрос без ответа), и предупредить, если в
/// сессии видны два слоя, но связи нет: такую сессию снял старый агент, и её
/// сводка может быть удвоена.
fn layers_text(meta: &SessionMeta) -> String {
    if meta.counts.j2534_layers.is_empty()
        && meta.counts.inner_events == 0
        && !two_layers(meta)
    {
        return String::new();
    }
    let c = &meta.counts;
    let mut out = format!("  слои J2534: {}\n", layers_label(meta));
    // Прямой ответ на вопрос «почему в журнале RX вдвое больше, чем в сводке»:
    // каждый кадр виден дважды (прокси и драйвер под ним), но в сводку входит
    // только внешний слой — иначе трафик удваивался (docs/13 §6.2).
    out.push_str(&format!(
        "  кадры обмена в сводке: TX {} / RX {}\n",
        c.tx, c.rx
    ));
    if c.inner_events > 0 {
        out.push_str(&format!(
            "  записи в events.jsonl: TX {} / RX {} — из них внутренний слой TX {} / RX {} ({} B), байты в сводке считаются один раз\n",
            c.tx + c.inner_tx,
            c.rx + c.inner_rx,
            c.inner_tx,
            c.inner_rx,
            c.inner_bytes
        ));
    }
    if two_layers(meta) && c.inner_events == 0 {
        out.push_str(
            "  ВНИМАНИЕ: два слоя без связи вызовов (старый агент) — сводка может быть удвоена\n",
        );
    }
    out
}

/// Длительность сессии по стенным часам, с. `None` — метки не разобрались.
fn session_span_s(meta: &SessionMeta) -> Option<f64> {
    let start = chrono::DateTime::parse_from_rfc3339(&meta.started_at).ok()?;
    let end = match meta.ended_at.as_deref() {
        Some(text) => chrono::DateTime::parse_from_rfc3339(text).ok()?,
        None => return None,
    };
    let span = (end - start).num_milliseconds() as f64 / 1000.0;
    (span > 0.0).then_some(span)
}

/// Строки раздела «Осциллограф»: только когда запись действительно была.
///
/// Ограничения напечатаны рядом с числами, а не только в документации: отчёт
/// читают, чтобы понять, что наблюдалось на самом деле, — и «между кадрами
/// сигнал не наблюдался» является частью ответа (ТЗ §4.2, §5 B7).
fn scope_lines(meta: &SessionMeta) -> Vec<String> {
    let c = &meta.counts;
    if c.scope_frames == 0 && c.scope_bytes == 0 && !c.scope_degraded && c.ui_actions == 0 {
        return Vec::new();
    }
    let mb = c.scope_bytes as f64 / (1024.0 * 1024.0);
    let mut out = vec![format!(
        "Осциллограф: кадров {}, {:.1} МБ, окно кадра ~{:.2} мс",
        c.scope_frames, mb, c.scope_window_ms
    )];
    // Покрытие — главная честная цифра: кадр это окно 1.66 мс, а не интервал
    // опроса. Без неё «20 кадров/с» читается как непрерывная запись.
    if c.scope_signal_s > 0.0 {
        match session_span_s(meta) {
            Some(span) if span > 0.0 => out.push(format!(
                "  покрытие сигнала: {:.2} с из {:.2} с сессии ({:.1} %); между кадрами сигнал не наблюдался",
                c.scope_signal_s,
                span,
                c.scope_signal_s / span * 100.0
            )),
            _ => out.push(format!(
                "  покрытие сигнала: {:.2} с записанных окон (длительность сессии неизвестна)",
                c.scope_signal_s
            )),
        }
    }
    if c.scope_interval_max_ms > 0.0 {
        out.push(format!(
            "  публикации кадров: медиана {:.0} мс, p95 {:.0} мс, максимум {:.0} мс",
            c.scope_interval_p50_ms, c.scope_interval_p95_ms, c.scope_interval_max_ms
        ));
    }
    if c.scope_gaps > 0 {
        out.push(format!(
            "  разрывы нумерации публикаций: {} ({} блоков) — это недополученные публикации, а не пропуск сигнала",
            c.scope_gaps, c.scope_gap_blocks
        ));
    }
    let actions = if c.ui_actions_confirmed + c.ui_actions_focus > 0 {
        format!(
            "Действий пользователя: {} (подтверждено {}, только фокус {})",
            c.ui_actions, c.ui_actions_confirmed, c.ui_actions_focus
        )
    } else {
        format!("Действий пользователя: {}", c.ui_actions)
    };
    out.push(actions);
    out.push("Файлы: scope/frames.jsonl · scope/meta.json · scope/summary.json".to_string());
    out.push(
        "Время кадра — время приёма на логгере (часов источника нет); точность привязки не измерялась, интервал опроса — не погрешность"
            .to_string(),
    );
    out.push(
        "Кадр — окно блока АЦП; столбец samples = один отсчёт, envelope = min/max (пики сохранены), пустой столбец lo>hi"
            .to_string(),
    );
    if c.scope_degraded {
        out.push(
            "ВНИМАНИЕ: запись шла в режиме только статистики (лимит объёма) — отсчётов в этих строках нет"
                .to_string(),
        );
    }
    out
}
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
    let rows: Vec<(String, String)> = {
        let mut rows = vec![
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
            (
                "Диагностика (не ошибки)".into(),
                meta.counts.diagnostics.to_string(),
            ),
            (
                "Холостых опросов".into(),
                meta.counts.empty_polls.to_string(),
            ),
        ];
        if let Some(proto) = protocol_summary(meta) {
            rows.push(("Протокол".into(), proto));
        }
        // Сеть — отдельной строкой: в `TX/RX` она не входит, но и молчать о ней
        // нельзя — иначе непонятно, куда делись 922 байта из общего числа событий.
        if meta.counts.net_bytes > 0 {
            rows.push((
                "Сеть (не шина), байт".into(),
                format!(
                    "{} (TX {} / RX {})",
                    meta.counts.net_bytes, meta.counts.net_tx, meta.counts.net_rx
                ),
            ));
        }
        if meta.counts.untracked_channels > 0 {
            rows.push((
                "Каналов без Connect".into(),
                meta.counts.untracked_channels.to_string(),
            ));
        }
        // Два слоя J2534: одна строка, по которой видно, что обмен посчитан
        // один раз, а внутренние записи остались в деталях (docs/13 §6.2).
        if !meta.counts.j2534_layers.is_empty() || meta.counts.inner_events > 0 || two_layers(meta)
        {
            rows.push(("Слои J2534".into(), layers_label(meta)));
            if meta.counts.inner_events > 0 {
                rows.push((
                    "Внутренних записей".into(),
                    format!(
                        "{} (TX {} / RX {}, {} B) — не в счётчиках",
                        meta.counts.inner_events,
                        meta.counts.inner_tx,
                        meta.counts.inner_rx,
                        meta.counts.inner_bytes
                    ),
                ));
            } else if two_layers(meta) {
                // Старая сессия: два модуля/слоя есть, связи нет — предупреждаем,
                // а не молчим (docs/13 §6.2).
                rows.push((
                    "Двойной учёт".into(),
                    "возможен: два слоя без связи вызовов (старый агент)".into(),
                ));
            }
        }
        // Вендорские вызовы: одна строка + разобранная конфигурация GPT.
        if meta.counts.vendor_calls > 0 {
            rows.push((
                "Вендорские вызовы".into(),
                format!(
                    "{} ({})",
                    meta.counts.vendor_calls,
                    vendor_ops_label(meta)
                ),
            ));
            if !meta.counts.vendor_gpt.is_empty() {
                rows.push(("GPT (1377 op=0x0b)".into(), meta.counts.vendor_gpt.clone()));
            }
        }
        rows
    };
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

    // Второй канал — своим разделом: он появляется только когда прокси реально
    // писал журнал (docs/13 §8), иначе отчёт не должен о нём заикаться.
    if let Some(lane) = &meta.proxy {
        out.push_str(&proxy_md_block(lane));
    }

    if meta.counts.errors > 0 && !meta.counts.error_samples.is_empty() {
        // «Ошибок: 1» без расшифровки — это вопрос без ответа: в отчёте должно
        // быть видно, ЧТО попало в счётчик (в этом логе — пропущенный Connect).
        out.push_str(&format!("## Ошибки ({})\n\n", meta.counts.errors));
        for sample in &meta.counts.error_samples {
            out.push_str(&format!("- {}\n", md_cell(sample)));
        }
        let shown = meta.counts.error_samples.len() as u64;
        if meta.counts.errors > shown {
            out.push_str(&format!(
                "- … ещё {} (полный список — `events.jsonl`, `kind=error`)\n",
                meta.counts.errors - shown
            ));
        }
        out.push('\n');
    }

    if steps.is_empty() {
        // Пустая схема `Start --> End` — не «нет данных», а мусор: в логе
        // 20261119-181253 она ничего не говорила про две попытки обмена с
        // паузой 22.5 с. Отрезки считаются по фактам (`# обмен …`).
        out.push_str("## Обмен\n\n");
        out.push_str(
            "Шагов приложение не размечает — схема не строится. Границы обмена видны \
             по паузам: факты `# обмен …` в разделе «Факты окружения» (сколько было \
             отрезков, их время и объём, паузы между ними).\n\n",
        );
    } else {
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
    }

    out.push_str("## Итоги\n\n| Метрика | Значение |\n|---|---|\n");
    // См. render_text: без шагов объём считаем по счётчикам сессии, иначе
    // «Итоги» обнулялись и противоречили шапке отчёта.
    let by_steps = !steps.is_empty();
    let exchanges: u64 = if by_steps {
        steps.iter().map(|s| s.exchanges).sum()
    } else {
        meta.counts.tx
    };
    let tx: u64 = if by_steps {
        steps.iter().map(|s| s.tx_bytes).sum()
    } else {
        meta.counts.tx_bytes
    };
    let rx: u64 = if by_steps {
        steps.iter().map(|s| s.rx_bytes).sum()
    } else {
        meta.counts.rx_bytes
    };
    let denied: u64 = steps.iter().map(|s| s.verdict.denied).sum();
    let no_answer: u64 = steps.iter().map(|s| s.verdict.no_answer).sum();
    let unparsed: u64 = steps.iter().map(|s| s.verdict.unparsed).sum();
    for (k, v) in [
        ("Посылок", exchanges.to_string()),
        ("TX, байт", tx.to_string()),
        ("RX, байт", rx.to_string()),
        (
            "Объём",
            if by_steps {
                "по шагам"
            } else {
                "по счётчикам сессии (шаги не распознаны)"
            }
            .to_string(),
        ),
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

    let scope = scope_lines(meta);
    if !scope.is_empty() {
        out.push_str("## Осциллограф\n\n");
        for line in &scope {
            out.push_str(&format!("- {}\n", md_cell(line)));
        }
        out.push('\n');
    }
    // Пустой раздел «## Шаги / Шагов нет» дублировал «## Обмен» выше: если
    // шагов нет, о них уже сказано там.

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
        if !step.net_hist.is_empty() {
            out.push_str(&format!(
                "**Сеть (не протокол ЭБУ):** {} · TX {} B / RX {} B\n\n",
                hist_line(&step.net_hist),
                step.net_tx,
                step.net_rx
            ));
        }

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
///
/// Строки идут по времени события, а не по `seq`: пачка моста может прийти
/// позже, неся более ранние `t`, и в файле для разбора время не должно идти
/// назад. `seq` остаётся столбцом — по нему виден порядок поступления.
pub fn export_csv(events: &[Event], out: &Path) -> anyhow::Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut rows: Vec<&Event> = events.iter().collect();
    rows.sort_by(|a, b| {
        a.t.partial_cmp(&b.t)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.seq.cmp(&b.seq))
    });
    let mut text = String::with_capacity(events.len() * 96 + 64);
    text.push_str("seq,t,wall,kind,api,dir,len,hex,step\n");
    for ev in rows {
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

