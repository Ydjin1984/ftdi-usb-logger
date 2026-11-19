//! Приёмка «лог компактнее и честнее» на реальном сыром логе (docs/09 §8, docs/12 §10).
//!
//! Запуск (PowerShell):
//! ```text
//! $env:FTDI_ACCEPTANCE_LOG = "C:\...\20261119-154616-pcmflash\raw.log"
//! cargo test --test acceptance_size -- --ignored --nocapture
//! ```
//!
//! Проверяется то, что нельзя проверить на синтетике: настоящий лог PCMflash
//! на 30 МБ с тремя шагами, сетью, пустыми опросами и дампом 4 МБ.

use std::path::{Path, PathBuf};

use ftdi_logger::store::SessionStore;

fn log_path() -> Option<PathBuf> {
    let path = std::env::var_os("FTDI_ACCEPTANCE_LOG")?;
    let path = PathBuf::from(path);
    path.is_file().then_some(path)
}

fn session_dir(meta: &ftdi_logger::models::SessionMeta) -> PathBuf {
    let raw = meta.dir.trim_start_matches(r"\\?\").to_string();
    PathBuf::from(raw)
}

#[test]
#[ignore = "нужен реальный raw.log в FTDI_ACCEPTANCE_LOG"]
fn imported_session_is_compact_and_honest() {
    let Some(log) = log_path() else {
        eprintln!("FTDI_ACCEPTANCE_LOG не задан — прогон пропущен");
        return;
    };
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let meta = ftdi_logger::import::import_legacy_log(&store, Path::new(&log), None).unwrap();
    let dir = session_dir(&meta);

    let jsonl = std::fs::metadata(dir.join("events.jsonl")).map(|m| m.len()).unwrap_or(0);
    let rawlog = std::fs::metadata(&log).map(|m| m.len()).unwrap_or(0);
    let ratio = jsonl as f64 / rawlog.max(1) as f64;
    println!(
        "raw.log={:.1} МБ  events.jsonl={:.1} МБ  отношение={ratio:.2}",
        rawlog as f64 / 1_048_576.0,
        jsonl as f64 / 1_048_576.0
    );
    // Убрано поле `raw` — байт-в-байт копия строки raw.log (было 84 МБ, 2.72×).
    // Бюджет docs/09 §8 задан для raw.log и ZIP, а не для JSONL: у JSONL на
    // каждое событие приходится ~15 имён полей, поэтому «плотнее строки лога»
    // он быть не может, пока контракт §7 требует `api` и `hex` в открытом виде.
    assert!(
        ratio < 1.7,
        "events.jsonl ({jsonl} B) раздулся относительно raw.log ({rawlog} B): {ratio:.2}×"
    );
    assert!(
        jsonl < rawlog * 2,
        "регрессия дублирования: поле raw снова в JSONL?"
    );

    // Холостые опросы не считаются ошибками.
    println!(
        "counts: events={} errors={} empty_polls={}",
        meta.counts.events, meta.counts.errors, meta.counts.empty_polls
    );
    // В логе 20 строк `rx-empty` (суммарно 76 опросов) и 3 настоящих `chan-miss`:
    // ошибками остаются только вторые.
    assert_eq!(meta.counts.errors, 3, "ошибки — только chan-miss, не rx-empty");
    assert_eq!(meta.counts.empty_polls, 76, "холостые опросы посчитаны по n");

    // Адаптер восстановлен из лога.
    let adapter = meta.adapter.as_ref().expect("адаптер из J2534 open/version");
    println!("adapter: {adapter:?}");
    assert_eq!(adapter.vendor.as_deref(), Some("Scanmatik"));
    assert_eq!(adapter.serial, "A62122");
    assert!(adapter.firmware.as_deref().unwrap_or("").contains("FW:1060"));
    assert!(adapter.dll_version.as_deref().unwrap_or("").starts_with("1.0.0.120"));

    // Сеть не попала в ответы шага.
    let mut checked = 0;
    for step in store.reader(&meta.id).unwrap().steps() {
        assert!(
            !step.resp_hist.keys().any(|k| k.contains("TCP")),
            "шаг {}: сеть в ответах: {:?}",
            step.idx,
            step.resp_hist
        );
        if !step.net_hist.is_empty() {
            checked += 1;
            println!("шаг {}: net_hist={:?}", step.idx, step.net_hist);
        }
    }
    assert!(checked > 0, "сетевой трафик должен быть виден отдельной гистограммой");

    // Дамп, записанный инструментом, получил хэш.
    let steps = store.reader(&meta.id).unwrap().steps();
    let hashed: Vec<_> = steps.iter().flat_map(|s| s.filehash.iter()).collect();
    println!("filehash: {}", hashed.len());
    assert!(
        !hashed.is_empty(),
        "файл, записанный инструментом, должен попасть в filehash шага"
    );
    assert!(hashed.iter().any(|f| f.size >= 1024 * 1024), "дамп 4 МБ");
}
