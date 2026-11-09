//! Хранилище: round-trip writer → reader, индекс, шаги, repair, update_meta, delete.

use ftdi_logger::models::{Event, EventKind, SessionMeta, StepSummary, Transport};
use ftdi_logger::store::SessionStore;

fn tx(t: f64, hex: &str) -> Event {
    let mut ev = Event::new(EventKind::Tx, Transport::Vcp, t, "");
    ev.api = "WriteFile".into();
    ev.len = 4;
    ev.hex = hex.into();
    ev
}

fn rx(t: f64, hex: &str) -> Event {
    let mut ev = Event::new(EventKind::Rx, Transport::Vcp, t, "");
    ev.api = "ReadFile".into();
    ev.len = 4;
    ev.hex = hex.into();
    ev
}

#[test]
fn raw_log_keeps_consecutive_duplicate_lines() {
    // Побайтовые RX WinKFP дают много подряд идущих ОДИНАКОВЫХ строк.
    // raw.log обязан быть байт-в-байт (раньше дедуп терял 240 строк на winkfp-логе).
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let mut w = store.create(SessionMeta::new("raw-dup", "raw")).unwrap();
    let dir = w.dir().to_path_buf();
    let mut evs: Vec<Event> = (0..5)
        .map(|i| {
            let mut e = rx(i as f64, "a0");
            e.raw = "[+1.000s] VCP RX ReadFile(COM6) n=1 : a0".into();
            e
        })
        .collect();
    w.append_many(&mut evs).unwrap();
    let meta = w.meta.clone();
    w.finish(&meta).unwrap();
    drop(w);
    let raw = std::fs::read_to_string(dir.join("raw.log")).unwrap();
    let n = raw.lines().filter(|l| l.contains("ReadFile")).count();
    assert_eq!(n, 5, "raw.log потерял подряд идущие одинаковые строки:\n{raw}");
}

#[test]
fn writer_reader_roundtrip_and_index() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let mut meta = SessionMeta::new("roundtrip-1", "Тест round-trip");
    meta.status = "recording".into();
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();
    assert_eq!(dir, store.dir_for("roundtrip-1"));

    // 2 500 событий: файл переходит индексную границу (каждые 1000).
    let mut events: Vec<Event> = (0..2500)
        .map(|i| {
            if i % 2 == 0 {
                tx(i as f64 / 1000.0, "12 04 0d 1b")
            } else {
                rx(i as f64 / 1000.0, "12 04 0d 1b")
            }
        })
        .collect();
    w.append_many(&mut events).unwrap();
    assert_eq!(events[0].seq, 0);
    assert_eq!(events[2499].seq, 2499);

    w.write_raw_line("# MARK wall=2026-10-16 11:53:45 START 1: тест")
        .unwrap();
    let mut step = StepSummary::new(1, "тест");
    step.exchanges = 1250;
    w.save_step(&step).unwrap();
    let mut final_meta = w.meta.clone();
    final_meta.status = "finished".into();
    final_meta.counts.steps = 1;
    w.finish(&final_meta).unwrap();
    drop(w);

    for name in [
        "session.json",
        "state.json",
        "events.jsonl",
        "raw.log",
        "events.idx",
        "steps/01.json",
    ] {
        assert!(dir.join(name).is_file(), "нет файла {name}");
    }
    assert!(td.path().join("index.json").is_file());
    assert!(td.path().join("index.md").is_file());
    let raw = std::fs::read_to_string(dir.join("raw.log")).unwrap();
    assert!(raw.contains("# MARK wall=2026-10-16 11:53:45 START 1: тест"));
    assert!(raw.contains("VCP TX WriteFile") || raw.contains("WriteFile"));
    let idx = std::fs::read_to_string(dir.join("events.idx")).unwrap();
    assert!(idx.lines().count() >= 2, "индекс должен писать смещения");

    let reader = store.reader("roundtrip-1").unwrap();
    assert_eq!(reader.count_events(), 2500);
    let all = reader.all_events();
    assert_eq!(all.len(), 2500);
    assert_eq!(all[1000].seq, 1000);

    let page = reader.events(Some(1500), None, 10);
    assert_eq!(page.len(), 10);
    assert_eq!(page[0].seq, 1500);
    let page = reader.events(None, Some(5), 10);
    assert_eq!(page.len(), 5);
    let page = reader.events(None, None, 1);
    assert_eq!(page.len(), 1);
    let page = reader.events(Some(2499), Some(2600), 0);
    assert_eq!(page.len(), 1);

    let steps = reader.steps();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].idx, 1);
    assert_eq!(steps[0].title, "тест");
    drop(reader);

    // Переоткрытие стора: индекс поднимается с диска.
    drop(store);
    let store = SessionStore::open(td.path()).unwrap();
    assert_eq!(store.list().len(), 1);
    let stored = store.get("roundtrip-1").unwrap();
    assert_eq!(stored.status, "finished");
    assert_eq!(stored.counts.events, 2500);
    assert!(stored.ended_at.is_some());

    // update_meta
    let mut changed = stored.clone();
    changed.label = "Новое имя".into();
    changed.tags = vec!["t1".into()];
    store.update_meta(&changed).unwrap();
    assert_eq!(store.get("roundtrip-1").unwrap().label, "Новое имя");
    let disk: SessionMeta =
        serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap();
    assert_eq!(disk.label, "Новое имя");

    // delete
    store.delete("roundtrip-1").unwrap();
    assert!(store.get("roundtrip-1").is_none());
    assert!(!dir.exists());
    assert_eq!(store.list().len(), 0);

    // Повторный append в существующую сессию продолжает seq.
    let mut meta = SessionMeta::new("append-1", "append");
    meta.status = "finished".into();
    let mut w = store.create(meta).unwrap();
    let mut e = tx(0.0, "12 04");
    w.append(&mut e).unwrap();
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);
    let mut w = store.writer("append-1").unwrap();
    let mut e2 = tx(1.0, "12 04");
    w.append(&mut e2).unwrap();
    assert_eq!(e2.seq, 1, "seq продолжается после переоткрытия writer'а");
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    assert_eq!(store.reader("append-1").unwrap().count_events(), 2);
}

#[test]
fn repair_closes_unfinished_steps() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let mut meta = SessionMeta::new("repair-1", "repair");
    meta.status = "recording".into();
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();

    let mut start = Event::new(EventKind::StepStart, Transport::None, 1.0, "");
    start.kind = EventKind::StepStart;
    start.api = "MARK".into();
    start.text = Some("пишем".into());
    start.meta = serde_json::json!({"action": "start", "idx": 1, "title": "пишем"});
    w.append(&mut start).unwrap();
    let mut e_tx = tx(1.1, "12 09 06 00 03 fd 60 2e ad");
    e_tx.len = 9;
    e_tx.step = Some(1);
    w.append(&mut e_tx).unwrap();
    let mut e_rx = rx(1.2, "12 09 06 00 03 fd 60 2e ad");
    e_rx.len = 9;
    e_rx.step = Some(1);
    w.append(&mut e_rx).unwrap();
    // Обрыв: StepEnd так и не записан.
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);

    let mut reader = store.reader("repair-1").unwrap();
    reader.repair().unwrap();
    assert_eq!(reader.meta().status, "aborted");
    let steps = reader.steps();
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].idx, 1);
    assert_eq!(steps[0].exchanges, 1);
    // RX — только эхо, payload нет: чтение не собирается, команда без READ(0x06).
    assert_eq!(steps[0].cmd_hist.get("cmd=0x06"), Some(&1));
    assert_eq!(steps[0].resp_hist.get("no-answer"), Some(&1));

    let events = reader.all_events();
    assert!(events
        .iter()
        .any(|e| e.kind == EventKind::StepEnd && e.meta.get("idx") == Some(&serde_json::json!(1))));
    let raw = std::fs::read_to_string(dir.join("raw.log")).unwrap();
    // Шаг в raw.log пишется в формате старого логера: `# MARK ... START/END N: имя`.
    assert!(
        raw.lines().any(|l| l.contains("# MARK") && l.contains("START")),
        "нет MARK START в raw.log:\n{raw}"
    );
    assert!(
        raw.lines().any(|l| l.contains("# MARK") && l.contains("END")),
        "нет MARK END в raw.log:\n{raw}"
    );
    assert!(dir.join("steps/01.json").is_file());
}
