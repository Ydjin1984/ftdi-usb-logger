//! Сверка decode/import с эталоном parse_family.py на реальных логах из reference/logs.

use ftdi_logger::decode::{parse_capture_line, summarize_step};
use ftdi_logger::import::{import_legacy_log, reparse_session};
use ftdi_logger::models::EventKind;
use ftdi_logger::store::SessionStore;
use std::path::{Path, PathBuf};

fn ref_log(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/logs")
        .join(name)
}

fn read_lines(path: &Path) -> Vec<ftdi_logger::models::Event> {
    let text = std::fs::read_to_string(path).expect("прочитать лог");
    text.lines()
        .filter_map(parse_capture_line)
        .collect()
}

const E2E_READS: &[(u64, u64, u64, &str)] = &[
    (261472, 92, 2, "3bb12e4c51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f"),
    (261472, 46, 1, "562c8c418f8d2dcf3ad6ea4eb4bfed7a8cdcdfbb3ed07d6034291b41a0018a0c"),
    (261472, 92, 2, "3bb12e4c51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f"),
    (261472, 46, 1, "562c8c418f8d2dcf3ad6ea4eb4bfed7a8cdcdfbb3ed07d6034291b41a0018a0c"),
    (16358, 16, 1, "9f47eb7d5ca8480098c649bd9cba2e72106838b5ba960636df5204947d7dbb3e"),
    (261296, 70, 1, "44f2b5292875a29bfd3a8714f89ef86485aebc5216e325e3dd35e07510381684"),
    (261472, 92, 2, "3bb12e4c51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f"),
    (261472, 46, 1, "562c8c418f8d2dcf3ad6ea4eb4bfed7a8cdcdfbb3ed07d6034291b41a0018a0c"),
    (83357, 1, 1, "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4"),
];

fn assert_reads(reads: &[ftdi_logger::models::StepRead]) {
    assert_eq!(reads.len(), E2E_READS.len(), "число потоков чтения");
    for (got, want) in reads.iter().zip(E2E_READS) {
        assert_eq!(got.start, want.0, "start");
        assert_eq!(got.len, want.1, "len");
        assert_eq!(got.blocks, want.2, "blocks");
        assert_eq!(got.sha256, want.3, "sha256");
    }
}

#[test]
fn import_e2e_capture_matches_phase_json() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let meta = import_legacy_log(&store, &ref_log("winkfp-e2e-capture.log"), None).unwrap();

    assert_eq!(meta.status, "imported");
    assert_eq!(meta.transport, "import");
    assert_eq!(meta.label, "WinKFP");
    assert!(meta.started_at.starts_with("2026-10-12T02:04:20"), "{}", meta.started_at);
    assert!(meta.facts.iter().any(|f| f.contains("EDIABAS.INI")));

    // Исходник скопирован в import/.
    let copied = store.dir_for(&meta.id).join("import/winkfp-e2e-capture.log");
    assert!(copied.is_file(), "исходник должен быть в import/");

    let reader = store.reader(&meta.id).unwrap();
    let steps = reader.steps();
    assert_eq!(steps.len(), 1, "в логе один MARK-шаг");
    let step = &steps[0];
    assert_eq!(step.idx, 1);
    assert_eq!(step.title, "читаю идентификаторы");
    assert_eq!(step.exchanges, 248);
    assert_eq!(step.tx_bytes, 22026);
    assert_eq!(step.rx_bytes, 25523);
    assert_eq!(step.dur, 1.583);

    // cmd_hist из PHASE-JSON — байт в байт.
    assert_eq!(step.cmd_hist.len(), 5);
    assert_eq!(step.cmd_hist.get("cmd=0x07"), Some(&223));
    assert_eq!(step.cmd_hist.get("READ(0x06)"), Some(&12));
    assert_eq!(step.cmd_hist.get("cmd=0x0D"), Some(&7));
    assert_eq!(step.cmd_hist.get("cmd=0x00"), Some(&3));
    assert_eq!(step.cmd_hist.get("cmd=0x90"), Some(&3));
    assert_eq!(step.resp_hist.get("A0"), Some(&247));
    assert_eq!(step.resp_hist.get("unparsed(12 0a)"), Some(&1));
    assert_reads(&step.reads);

    // WinKFP job'ы из PHASE-JSON (api.trc-уровень).
    assert_eq!(step.winkfp_jobs.len(), 2);
    assert_eq!(step.winkfp_jobs[0].sgbd, "bms46ds0");
    assert_eq!(step.winkfp_jobs[0].job, "ident");
    assert_eq!(step.winkfp_jobs[0].results_total, 2);
    assert_eq!(step.winkfp_jobs[1].job, "FLASH_PROGRAMMIEREN");
    assert_eq!(
        step.winkfp_jobs[1].errors,
        vec!["Error (134) API-0014: RESULT NOT FOUND"]
    );

    // Отчёты записаны в старом формате.
    let report_txt = std::fs::read_to_string(store.dir_for(&meta.id).join("report.txt")).unwrap();
    assert!(report_txt.contains("СЕССИЯ WinKFP"));
    assert!(report_txt.contains("# PHASE 1: читаю идентификаторы"));
    assert!(report_txt.contains("ИТОГО"));
    let report_md = std::fs::read_to_string(store.dir_for(&meta.id).join("report.md")).unwrap();
    assert!(report_md.contains("```mermaid"));
}

#[test]
fn import_logger_out_gives_same_summary_as_capture_log() {
    // logger.out — консольный транскрипт, где одиночные RX склеены в «одиночные байты n=32».
    // Сводка обязана совпасть с capture.log (одни и те же байты, другая запись).
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let meta = import_legacy_log(&store, &ref_log("winkfp-e2e-logger.out"), None).unwrap();
    assert_eq!(meta.status, "imported");
    assert_eq!(meta.label, "WinKFP");

    let reader = store.reader(&meta.id).unwrap();
    let steps = reader.steps();
    assert_eq!(steps.len(), 1);
    let step = &steps[0];
    assert_eq!(step.exchanges, 248, "logger.out: число посылок");
    assert_eq!(step.tx_bytes, 22026);
    assert_eq!(step.rx_bytes, 25523);
    assert_eq!(step.cmd_hist.get("cmd=0x07"), Some(&223));
    assert_eq!(step.resp_hist.get("A0"), Some(&247));
    assert_reads(&step.reads);
}

#[test]
fn ftd2xx_session_matches_reference() {
    let raws = read_lines(&ref_log("ftd2xx-bms46-session.log"));
    assert!(raws.len() > 1000);
    let events: Vec<_> = raws.into_iter().collect();
    let step = summarize_step(&events, 1, "?", 0.0, None);

    // Эталон parse_family.py на этом логе: посылок=201 TX=1789B RX=2834B.
    assert_eq!(step.exchanges, 201);
    assert_eq!(step.tx_bytes, 1789);
    assert_eq!(step.rx_bytes, 2834);
    assert_eq!(step.verdict.denied, 194, "A2-denied");
    assert_eq!(step.verdict.no_answer, 1);
    assert_eq!(step.resp_hist.get("A0"), Some(&6), "остальные — A0");

    assert_eq!(step.reads.len(), 2);
    for read in &step.reads {
        assert_eq!(read.start, 0x0003_FD60);
        assert_eq!(read.len, 13);
        assert_eq!(
            read.sha256,
            "773cdf4f076c4a3605de1d2065ca62d17eda904cb0a61ab27861c361c22aa750"
        );
    }
}

#[test]
fn import_counts_match_golden() {
    // Золото: reference/expected/<лог>.summary.json (parse_family.py, --gap 2.0).
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();

    let meta = import_legacy_log(&store, &ref_log("winkfp-e2e-capture.log"), None).unwrap();
    let counts = &meta.counts;
    assert_eq!(counts.events, 4033, "events = все разобранные строки лога, counts={counts:?}");
    assert_eq!(counts.tx, 248, "tx = число TX-событий");
    assert_eq!(counts.rx, 3745, "rx = число RX-chunk событий");
    assert_eq!(counts.tx_bytes, 22026, "tx_bytes = сумма payload TX");
    assert_eq!(counts.rx_bytes, 25523, "rx_bytes = сумма payload RX");

    let meta = import_legacy_log(&store, &ref_log("ftd2xx-bms46-session.log"), None).unwrap();
    let counts = &meta.counts;
    assert_eq!(counts.tx, 201, "ftd2xx: TX-телеграмм 201");
    assert_eq!(counts.tx_bytes, 1789, "ftd2xx: TX-байт");
    assert_eq!(counts.rx, 402, "ftd2xx: RX-chunk событий 402");
    assert_eq!(counts.rx_bytes, 2834, "ftd2xx: RX-байт");
}

#[test]
fn reparse_does_not_double_counts() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let meta = import_legacy_log(&store, &ref_log("winkfp-e2e-capture.log"), None).unwrap();
    let before = meta.counts.clone();

    for _ in 0..3 {
        let reparsed = reparse_session(&store, &meta.id).unwrap();
        let counts = &reparsed.counts;
        assert_eq!(counts.events, before.events, "events не удваиваются");
        assert_eq!(counts.tx, before.tx, "tx не удваивается");
        assert_eq!(counts.rx, before.rx, "rx не удваивается");
        assert_eq!(counts.tx_bytes, before.tx_bytes, "tx_bytes не удваиваются");
        assert_eq!(counts.rx_bytes, before.rx_bytes, "rx_bytes не удваиваются");
        assert_eq!(counts.tx_bytes, 22026);
        assert_eq!(counts.rx_bytes, 25523);
    }
}

#[test]
fn empty_log_imports_without_steps() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let empty = td.path().join("empty.log");
    std::fs::write(&empty, "").unwrap();
    let meta = import_legacy_log(&store, &empty, None).unwrap();
    assert_eq!(meta.counts.events, 0);
    assert_eq!(meta.counts.steps, 0);
    let reader = store.reader(&meta.id).unwrap();
    assert!(reader.steps().is_empty());
    assert_eq!(reader.count_events(), 0);
    assert!(store.dir_for(&meta.id).join("report.txt").is_file());
    // Повторный импорт — новая сессия, не паника.
    let meta2 = import_legacy_log(&store, &empty, None).unwrap();
    assert_ne!(meta.id, meta2.id);
}

#[test]
fn garbage_lines_are_kept_as_raw() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let log = td.path().join("garbage.log");
    std::fs::write(
        &log,
        "какая-то мусорная строка\n\x00\x01\x02 битые байты\n[+1.000s] VCP TX WriteFile(COM6) n=2 : 12 04\n",
    )
    .unwrap();
    let meta = import_legacy_log(&store, &log, None).unwrap();
    let reader = store.reader(&meta.id).unwrap();
    let events = reader.all_events();
    assert!(events.iter().any(|e| e.kind == EventKind::Raw));
    assert!(events.iter().any(|e| e.kind == EventKind::Tx));
}

#[test]
fn reparse_twice_is_idempotent() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let meta = import_legacy_log(&store, &ref_log("winkfp-e2e-capture.log"), None).unwrap();

    let first = reparse_session(&store, &meta.id).unwrap();
    let reader = store.reader(&meta.id).unwrap();
    let steps1 = reader.steps();
    assert_eq!(steps1.len(), 1);
    let sha1 = steps1[0].reads[0].sha256.clone();
    let cmd1 = steps1[0].cmd_hist.clone();

    let second = reparse_session(&store, &meta.id).unwrap();
    assert_eq!(first.counts.events, second.counts.events);
    let steps2 = store.reader(&meta.id).unwrap().steps();
    assert_eq!(steps2.len(), 1);
    assert_eq!(steps2[0].reads[0].sha256, sha1);
    assert_eq!(steps2[0].cmd_hist, cmd1);
}
