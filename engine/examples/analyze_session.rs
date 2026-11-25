//! Офлайн-переразбор каталога сессии: операции, сигналы и отчёт.
//!
//! ```text
//! cargo run --example analyze_session -- "C:\...\sessions\20261122-183516-pcmflash"
//! ```
//!
//! Пишет `operations.json`, `seedkeys.jsonl`, `scope/analysis.json` и заново
//! собирает `report.txt` / `report.md` — ровно то, что делает `POST /reparse`.
//! Нужен, когда движок не запущен, а отчёт по снятому ZIP надо получить сейчас.

use std::path::PathBuf;

use ftdi_logger::models::SessionMeta;
use ftdi_logger::{operations, report, signals, store};

fn phase<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let t = std::time::Instant::now();
    let value = f();
    println!("{name}: {:?}", t.elapsed());
    value
}

fn main() -> anyhow::Result<()> {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("укажите каталог сессии"))?;
    let meta_text = std::fs::read_to_string(dir.join("session.json"))?;
    let mut meta: SessionMeta = serde_json::from_str(&meta_text)?;
    if meta.dir.is_empty() {
        meta.dir = dir.to_string_lossy().to_string();
    }
    let events = phase("события", || store::read_events_dir(&dir));
    println!("событий: {}", events.len());
    let analysis = phase("кадры", || signals::analyze(&dir, &meta))?;

    let doc = phase("сборка", || {
        operations::rebuild_with(&dir, &meta, &events, Some(&analysis))
    })?;
    println!(
        "операций: {} (пар seed→key: {})",
        doc.operations.len(),
        doc.seed_pairs
    );
    for op in &doc.operations {
        println!(
            "\n[{}] {} · {:.2}–{:.2} с · участков {} · TX {} / RX {} · {}",
            op.idx,
            op.name,
            op.t0,
            op.t1,
            op.segments.len(),
            op.calls.tx_msgs,
            op.calls.rx_msgs,
            op.result.text
        );
        println!("   авторизация: {}", op.auth_status);
        for sig in &op.signals {
            println!(
                "   сигнал {}: {} [{:?}–{:.2}] {}",
                sig.name, sig.text, sig.t_before, sig.t_after, sig.order
            );
        }
        for seg in &op.segments {
            println!(
                "   участок {}: {:.2}–{:.2} с · {} посылок · {}",
                seg.idx, seg.t0, seg.t1, seg.tx + seg.rx, seg.services
            );
        }
    }

    // Шаги в этой сессии не размечались; отчёт сам скажет об этом.
    let steps: Vec<ftdi_logger::models::StepSummary> = Vec::new();
    report::write_session_reports(&dir, &meta, &steps)?;
    println!("\nотчёт: {}", dir.join("report.md").display());
    Ok(())
}
