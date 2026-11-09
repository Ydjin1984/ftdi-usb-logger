//! Отчёты (txt/md) и экспорт (zip/jsonl/csv/md).

use ftdi_logger::models::{
    Direction, Event, EventKind, FileHash, SessionCounts, SessionMeta, StepRead, StepSummary,
    Transport, WinkfpJob,
};
use ftdi_logger::report;
use ftdi_logger::store::SessionStore;

fn sample_meta() -> SessionMeta {
    let mut meta = SessionMeta::new("report-session", "BMS46 тест");
    meta.status = "finished".into();
    meta.transport = "vcp".into();
    meta.ended_at = Some("2026-10-16T11:53:47.000+05:00".into());
    meta.tool_path = Some(r"C:\EC-APPS\NFS\BIN\winkfpt.exe".into());
    meta.facts = vec!["EDIABAS.INI: Interface=STD:OBD".into()];
    meta.counts = SessionCounts {
        events: 248,
        tx: 248,
        rx: 255,
        tx_bytes: 22026,
        rx_bytes: 25523,
        steps: 1,
        files: 1,
        errors: 0,
    };
    meta
}

fn sample_step() -> StepSummary {
    let mut step = StepSummary::new(1, "читаю идентификаторы");
    step.dur = 1.583;
    step.exchanges = 248;
    step.tx_bytes = 22026;
    step.rx_bytes = 25523;
    step.cmd_hist.insert("cmd=0x07".into(), 223);
    step.cmd_hist.insert("READ(0x06)".into(), 12);
    step.resp_hist.insert("A0".into(), 247);
    step.resp_hist.insert("A2-denied".into(), 1);
    step.reads.push(StepRead {
        start: 261472,
        len: 92,
        blocks: 2,
        sha256: "3bb12e4c51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f".into(),
    });
    step.filehash.push(FileHash {
        path: r"D:\tune.bin".into(),
        size: 65536,
        sha256: "abc".into(),
        mode: "requested".into(),
    });
    step.winkfp_jobs.push(WinkfpJob {
        sgbd: "bms46ds0".into(),
        job: "ident".into(),
        args: vec![],
        results: serde_json::Map::new(),
        errors: vec![],
        results_total: 0,
    });
    step.verdict.denied = 1;
    step.verdict.echo = true;
    step
}

#[test]
fn text_and_markdown_reports() {
    let meta = sample_meta();
    let steps = vec![sample_step()];
    let txt = report::render_text(&meta, &steps);
    assert!(txt.contains("СЕССИЯ BMS46 тест"));
    assert!(txt.contains("# PHASE 1: читаю идентификаторы"));
    assert!(txt.contains("# PHASE 1   команды: cmd=0x07=223, READ(0x06)=12"));
    assert!(txt.contains("# PHASE 1   ответы:"));
    assert!(txt.contains("sha256=3bb12e4c"));
    assert!(txt.contains("файл-хеш: size=65536"));
    assert!(txt.contains("winkfp: job=\"ident\""));
    assert!(txt.contains("вердикт: denied=1"));
    assert!(txt.contains("ИТОГО: шагов=1"));
    assert!(txt.contains("транспорт"));

    let md = report::render_markdown(&meta, &steps);
    assert!(md.contains("# Отчёт сессии «BMS46 тест»"));
    assert!(md.contains("```mermaid"));
    assert!(md.contains("flowchart TD"));
    assert!(md.contains("S1["));
    assert!(md.contains("## Шаг 1 — читаю идентификаторы"));
    assert!(md.contains("**Потоки чтения**"));
    assert!(md.contains("| 0x03FD60 |"));
}

#[test]
fn csv_jsonl_zip_markdown_exports() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let mut meta = SessionMeta::new("export-1", "export");
    meta.status = "finished".into();
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();

    for (kind, t, hex, dirn) in [
        (EventKind::Tx, 1.0, "12 04 0d 1b", Some(Direction::Tx)),
        (EventKind::Rx, 1.1, "12 04 0d 1b", Some(Direction::Rx)),
    ] {
        let mut ev = Event::new(kind, Transport::Vcp, t, "");
        ev.api = if kind == EventKind::Tx {
            "WriteFile".to_string()
        } else {
            "ReadFile".to_string()
        };
        ev.direction = dirn;
        ev.len = 4;
        ev.hex = hex.into();
        ev.step = Some(1);
        ev.meta = serde_json::json!({"com": "COM6"});
        w.append(&mut ev).unwrap();
    }
    let mut step = sample_step();
    step.winkfp_jobs.clear();
    w.save_step(&step).unwrap();
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);

    let steps = vec![step];
    let meta = store.get("export-1").unwrap();
    report::write_session_reports(&dir, &meta, &steps).unwrap();
    assert!(dir.join("report.txt").is_file());
    assert!(dir.join("report.md").is_file());

    // CSV
    let events = store.reader("export-1").unwrap().all_events();
    let csv_path = dir.join("export/events.csv");
    report::export_csv(&events, &csv_path).unwrap();
    let csv = std::fs::read_to_string(&csv_path).unwrap();
    let mut lines = csv.lines();
    assert_eq!(lines.next(), Some("seq,t,wall,kind,api,dir,len,hex,step"));
    let row0 = lines.next().unwrap();
    assert!(row0.starts_with("0,1.000,"), "row={row0}");
    assert!(row0.contains(",tx,WriteFile,tx,4,12 04 0d 1b,1"));
    let row1 = lines.next().unwrap();
    assert!(row1.contains(",rx,ReadFile,rx,"));
    assert_eq!(lines.count(), 0);

    // JSONL
    let jsonl_path = dir.join("export/events.jsonl");
    report::export_jsonl(&dir, &jsonl_path).unwrap();
    let jsonl = std::fs::read_to_string(&jsonl_path).unwrap();
    assert_eq!(jsonl.lines().count(), events.len());
    assert!(jsonl.contains("\"kind\":\"tx\""));

    // Markdown
    let md_path = dir.join("export/report.md");
    report::export_markdown(&meta, &steps, &md_path).unwrap();
    assert!(std::fs::read_to_string(&md_path).unwrap().contains("mermaid"));

    // ZIP
    let zip_path = dir.join("export/session.zip");
    report::export_zip(&dir, &zip_path).unwrap();
    assert!(zip_path.is_file());
    let f = std::fs::File::open(&zip_path).unwrap();
    let mut archive = zip::ZipArchive::new(f).unwrap();
    let names: Vec<String> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(names.iter().any(|n| n == "events.jsonl"), "{names:?}");
    assert!(names.iter().any(|n| n == "session.json"));
    assert!(names.iter().any(|n| n == "report.txt"));
    assert!(!names.iter().any(|n| n.starts_with("export/")), "экспорт не пакуем");
}

#[test]
fn empty_session_report_has_no_phase_but_valid_header() {
    let meta = SessionMeta::new("empty", "пустая");
    let txt = report::render_text(&meta, &[]);
    assert!(txt.contains("СЕССИЯ пустая"));
    assert!(txt.contains("шагов нет"));
    let md = report::render_markdown(&meta, &[]);
    assert!(md.contains("flowchart TD"));
    assert!(md.contains("Шагов нет"));
}
