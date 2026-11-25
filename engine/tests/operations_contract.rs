//! Контракт операций: `operations.json`, `seedkeys.jsonl`, разделы отчёта.
//!
//! Проверяем то, что нельзя проверить на живом стенде: файлы сессии и
//! повторяемость переразбора. Живой ZIP (20261122-183516-pcmflash) даёт те же
//! три операции, но здесь важно, что результат не зависит от движка и не
//! теряется при повторном прогоне.

use ftdi_logger::models::{
    Direction, Event, EventKind, ProxyCross, ProxyLane, SessionCounts, SessionMeta, Transport,
};
use ftdi_logger::operations::{self, OPERATIONS_FILE, SEEDKEYS_FILE};
use ftdi_logger::report;
use ftdi_logger::signals;
use ftdi_logger::store::SessionStore;

fn click(t: f64, name: &str, action: &str, confirmed: bool) -> Event {
    let mut ev = Event::new(EventKind::UiAction, Transport::App, t, "");
    ev.text = Some(name.into());
    ev.meta = serde_json::json!({
        "action": action,
        "activation": if confirmed { "click" } else { "focus" },
        "confirmed": confirmed,
        "window": "PCMflash [1.2.0]",
        "automation_id": "1",
        "control_type": "Button",
    });
    ev
}

fn kline(t: f64, dir: Direction, hex: &str, svc: &str, resp: bool, call: u64) -> Event {
    let kind = if dir == Direction::Tx {
        EventKind::Tx
    } else {
        EventKind::Rx
    };
    let mut ev = Event::new(kind, Transport::J2534, t, "");
    ev.direction = Some(dir);
    ev.hex = hex.into();
    ev.len = hex.split_whitespace().count() as u32;
    ev.meta = serde_json::json!({
        "svc": svc, "svc_resp": resp, "call": call, "channel": "1",
        "n_in": 1, "n_out": 1, "layer": "proxy", "protocol": "0x8003",
    });
    ev
}

#[test]
fn rebuild_writes_operations_seedkeys_and_report_sections() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let mut meta = SessionMeta::new("ops-int", "pcmflash");
    meta.status = "finished".into();
    meta.transport = "j2534".into();
    meta.started_at = "2026-11-22T13:35:16.303Z".into();
    meta.ended_at = Some("2026-11-22T13:35:26.303Z".into());
    meta.counts = SessionCounts {
        events: 6,
        tx: 2,
        rx: 2,
        ..Default::default()
    };
    meta.proxy = Some(ProxyLane {
        tx: 2,
        rx: 2,
        cross: ProxyCross {
            tx_matched: 2,
            rx_matched: 2,
            ..Default::default()
        },
        ..Default::default()
    });
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();

    let key = format!("00 82 27 80 {}", "aa ".repeat(128).trim_end());
    let mut events = vec![
        // Фокус до клика: операции не создаёт.
        click(0.5, "Запись", "write", false),
        click(1.0, "Идентификация", "identify", true),
        kline(1.2, Direction::Tx, "00 02 10 92", "0x10", false, 1),
        kline(1.3, Direction::Rx, "00 02 50 92", "0x50", true, 2),
        kline(1.4, Direction::Tx, "00 02 27 7f", "0x27", false, 3),
        kline(1.5, Direction::Rx, "00 0d 67 7f 11 22 33 44 55 66 77 88 99 aa bb", "0x67", true, 4),
        kline(1.6, Direction::Tx, &key, "0x27", false, 5),
        kline(1.7, Direction::Rx, "00 03 67 80 34", "0x67", true, 6),
    ];
    for ev in events.iter_mut() {
        w.append(ev).unwrap();
    }
    // Кадры осциллографа: PWM появляется, затем питание.
    std::fs::create_dir_all(dir.join("scope")).unwrap();
    std::fs::write(
        dir.join("scope/channels.json"),
        serde_json::json!({
            "format": "scope-channels/1",
            "profile": "bench-gpt",
            "channels": [
                {"ch": 1, "enabled": true, "role": "gpt1", "name": "GPT1", "full_scale_v": 6.0},
                {"ch": 2, "enabled": true, "role": "gpt2", "name": "GPT2", "full_scale_v": 6.0},
                {"ch": 3, "enabled": true, "role": "power", "name": "Питание", "full_scale_v": 20.0}
            ]
        })
        .to_string(),
    )
    .unwrap();
    let mut frames = String::new();
    for (i, (vpp, vmax)) in [(0.05, -0.35), (1.8, -0.33), (1.8, 13.9), (1.8, 13.9)]
        .iter()
        .enumerate()
    {
        let t = 0.1 + i as f64 * 0.052;
        frames.push_str(
            &serde_json::json!({
                "t": t,
                "frame_id": 100 + i as u64,
                "window_s": 0.001665,
                "stats": [
                    {"ch": 1, "vpp": vpp, "vmax": vmax, "mean": -0.4, "freq": 15789.0},
                    {"ch": 2, "vpp": vpp, "vmax": vmax, "mean": -0.4, "freq": 10000.0},
                    {"ch": 3, "vpp": 0.05, "vmax": vmax, "mean": if *vmax > 6.0 { 13.9 } else { -0.35 }}
                ]
            })
            .to_string(),
        );
        frames.push('\n');
    }
    std::fs::write(dir.join("scope/frames.jsonl"), frames).unwrap();

    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);

    let meta = store.get("ops-int").unwrap();
    let events = store.reader("ops-int").unwrap().all_events();
    let doc = operations::rebuild(&dir, &meta, &events).unwrap();
    assert_eq!(doc.operations.len(), 1, "фокус не должен открывать операцию");
    let op = &doc.operations[0];
    assert_eq!(op.name, "Идентификация");
    assert_eq!(op.origin, "confirmed");
    assert_eq!(op.auth_status, "granted");
    assert_eq!(op.seeds.len(), 1);
    assert_eq!(op.seeds[0].key_len, 128);
    assert!(op.signals.iter().any(|s| s.kind == "pwm_on"));
    assert!(op.signals.iter().any(|s| s.kind == "power_on"));

    // Файлы на месте и не содержат значений авторизации в operations.json.
    let ops_json = std::fs::read_to_string(dir.join(OPERATIONS_FILE)).unwrap();
    assert!(!ops_json.contains("11 22 33"), "seed не должен попадать в operations.json");
    let seeds = std::fs::read_to_string(dir.join(SEEDKEYS_FILE)).unwrap();
    assert!(seeds.contains("\"seed\":\"112233445566778899aabb\""), "{seeds}");
    assert!(seeds.contains("\"key\":\"aaaa"), "ключ — в отдельном файле");

    let steps = store.reader("ops-int").unwrap().steps();
    report::write_session_reports(&dir, &meta, &steps).unwrap();
    let md = std::fs::read_to_string(dir.join("report.md")).unwrap();
    assert!(md.contains("## Операции"), "{md}");
    assert!(md.contains("### Операция 1 — Идентификация"), "{md}");
    assert!(md.contains("**Авторизация:**"), "{md}");
    assert!(md.contains("сверка с прокси"), "счётчики сверены с прокси:\n{md}");
    assert!(md.contains("### Сигналы стенда"), "{md}");
    assert!(md.contains("CH1 GPT1"), "профиль каналов назван:\n{md}");

    // Повторный прогон даёт тот же состав операций (детерминизм).
    let again = operations::rebuild(&dir, &meta, &events).unwrap();
    assert_eq!(
        serde_json::to_string(&doc.operations).unwrap(),
        serde_json::to_string(&again.operations).unwrap()
    );
    // Выжимка сигналов тоже сохраняется и перечитывается.
    let analysis = signals::load(&dir, "ops-int").expect("scope/analysis.json");
    assert!(analysis.profile_assumed == false);
    assert_eq!(analysis.channels.len(), 3);
}

#[test]
fn session_zip_import_keeps_events_and_scope_layers() {
    use ftdi_logger::import;

    let src = tempfile::tempdir().unwrap();
    let store = SessionStore::open(src.path()).unwrap();
    let mut meta = SessionMeta::new("zip-src", "pcmflash");
    meta.status = "finished".into();
    meta.transport = "j2534".into();
    let mut w = store.create(meta).unwrap();
    let dir = w.dir().to_path_buf();
    let mut ev = click(1.0, "Чтение", "read", true);
    w.append(&mut ev).unwrap();
    let mut tx = kline(1.1, Direction::Tx, "00 02 10 92", "0x10", false, 1);
    w.append(&mut tx).unwrap();
    std::fs::create_dir_all(dir.join("scope")).unwrap();
    std::fs::write(
        dir.join("scope/frames.jsonl"),
        "{\"t\":0.1,\"frame_id\":1,\"window_s\":0.001665,\"stats\":[]}\n",
    )
    .unwrap();
    let m = w.meta.clone();
    w.finish(&m).unwrap();
    drop(w);
    let zip_path = dir.join("export/session.zip");
    report::export_zip(&dir, &zip_path).unwrap();

    // Импорт в чистый корень: данные и слои на месте, id уникален.
    let dst = tempfile::tempdir().unwrap();
    let store2 = SessionStore::open(dst.path()).unwrap();
    let imported = import::import_session_zip(&store2, &zip_path).unwrap();
    assert_eq!(imported.id, "zip-src");
    assert!(store2.dir_for("zip-src").join("events.jsonl").is_file());
    assert!(store2.dir_for("zip-src").join("scope/frames.jsonl").is_file());
    let events = store2.reader("zip-src").unwrap().all_events();
    assert_eq!(events.len(), 2, "оба события на месте: {events:?}");

    // Повторный импорт того же архива не перезаписывает первую сессию.
    let again = import::import_session_zip(&store2, &zip_path).unwrap();
    assert_eq!(again.id, "zip-src-2");
    assert_eq!(store2.list().len(), 2);
}
