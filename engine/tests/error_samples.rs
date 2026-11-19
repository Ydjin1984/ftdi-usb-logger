//! Ошибка сессии должна быть объяснена в отчёте, а не только посчитана.
//!
//! Первая версия этого теста опиралась на `J2534 chan-miss` как на ошибку — так
//! было в 0.3.5. Логи 20261119-173309-pcmflash показали, что это неверно:
//! приложение вообще не зовёт `PassThruConnect`, канал открывает драйвер, все
//! вызовы идут с `rc=0`, дамп флеша 4 МБ снимается успешно — а отчёт пишет
//! «Ошибок: 3». Теперь `chan-miss` — отдельный счётчик `untracked_channels`,
//! а в `errors` попадают только настоящие сбои обмена.
//!
//! Конвейер, который проверяется: строка лога → kind → счётчики →
//! `report.txt`/`report.md`.

use ftdi_logger::import::import_legacy_log;
use ftdi_logger::store::SessionStore;

/// Рабочий лог: канал открыт мимо `PassThruConnect`, обмен идёт, всё rc=0.
const LOG_CLEAN_CHANMISS: &str = "\
# capture start: label=pcmflash
# tool: C:\\Program Files (x86)\\PCMflash\\pcmflash.exe
# wall(start)=2026-11-19 17:33:09
# attach: late
# MARK wall=2026-11-19 17:33:15 rel=+5.900s START 1: Чтение флеша
[+5.537486s] J2534 module: smj2534.dll C:\\Program Files (x86)\\Scanmatik\\smj2534.dll base=0x6d830000 exports=14
[+5.548335s] J2534 open name=\"\" vendor=\"Scanmatik\" dll=\"smj2534.dll\" dev=1 mod=1 rc=0 th=26780
[+5.687464s] J2534 chan-miss ch=1 gen=1 first_op=ioctl mod=1 th=26780
[+5.687846s] J2534 ioctl ch=1 call=1 id=0x000a (CLEAR_MSG_FILTERS) rc=0 th=26780 dur=378 in_ptr=0 out_ptr=0
[+7.325828s] J2534 TX ch=1 call=15 i=1/1 n_in=1 n_out=1 th=23940 ts=0 flags=0x0 proto=0x8003 svc=0x80 len=5 dur=1254 rc=0 : 00 03 80 e1 01
[+7.327363s] J2534 RX ch=1 call=16 i=1/1 n_in=1 n_out=1 th=23940 ts=2780817704 rxs=0x2 sof=1 proto=0x8003 len=0 dur=1446 rc=0
# MARK wall=2026-11-19 17:37:20 rel=+250.900s END 1: Чтение флеша (245.0 с)
# counters dropped_events=0 truncated_payloads=0 decode_errors=0 evicted_events=0 partial_results=0 contract_violations=0 rx_sof=1 calls=3 bridge_events=3 bridge_batches=1 bridge_backlog_max=1
";

/// Тот же лог плюс настоящий сбой обмена: адаптер вернул `ERR_TIMEOUT`.
const LOG_WITH_REAL_ERROR: &str = "\
# capture start: label=pcmflash
# wall(start)=2026-11-19 17:33:09
# attach: late
# MARK wall=2026-11-19 17:33:15 rel=+5.900s START 1: Чтение флеша
[+7.325828s] J2534 TX ch=1 call=15 i=1/1 n_in=1 n_out=1 th=23940 ts=0 flags=0x0 proto=0x8003 svc=0x80 len=5 dur=1254 rc=0 : 00 03 80 e1 01
[+7.427363s] J2534 rx-error ch=1 rc=39 op=ReadMsgs th=23940
# MARK wall=2026-11-19 17:37:20 rel=+250.900s END 1: Чтение флеша (245.0 с)
";

#[test]
fn chan_miss_is_not_an_error_in_session_or_reports() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let log = td.path().join("capture.log");
    std::fs::write(&log, LOG_CLEAN_CHANMISS).unwrap();

    let meta = import_legacy_log(&store, &log, Some("pcmflash".into())).unwrap();

    assert_eq!(meta.counts.errors, 0, "рабочая сессия без ошибок");
    assert!(
        meta.counts.error_samples.is_empty(),
        "и расшифровывать нечего: {:?}",
        meta.counts.error_samples
    );
    assert_eq!(meta.counts.untracked_channels, 1, "канал без Connect посчитан");

    let dir = store.dir_for(&meta.id);
    let txt = std::fs::read_to_string(dir.join("report.txt")).unwrap();
    let md = std::fs::read_to_string(dir.join("report.md")).unwrap();

    assert!(!md.contains("## Ошибки"), "раздела ошибок быть не должно:\n{md}");
    assert!(!txt.contains("ошибки ("), "в тексте тоже:\n{txt}");
    assert!(
        md.contains("| Каналов без Connect | 1 |"),
        "канал назван в таблице:\n{md}"
    );
    assert!(
        txt.contains("каналов без PassThruConnect: 1"),
        "и в текстовом отчёте:\n{txt}"
    );
}

#[test]
fn real_error_is_named_in_session_and_reports() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let log = td.path().join("capture.log");
    std::fs::write(&log, LOG_WITH_REAL_ERROR).unwrap();

    let meta = import_legacy_log(&store, &log, Some("pcmflash".into())).unwrap();

    assert_eq!(meta.counts.errors, 1, "ровно одна ошибка");
    assert_eq!(meta.counts.error_samples.len(), 1, "она расшифрована");
    let sample = &meta.counts.error_samples[0];
    assert!(sample.contains("rx-error"), "что за ошибка: {sample}");
    assert!(sample.contains("шаг 1"), "шаг указан: {sample}");
    assert!(sample.starts_with("+7.427s"), "время указано: {sample}");

    let dir = store.dir_for(&meta.id);
    let txt = std::fs::read_to_string(dir.join("report.txt")).unwrap();
    let md = std::fs::read_to_string(dir.join("report.md")).unwrap();

    assert!(
        txt.contains("ошибки (1):") && txt.contains("rx-error"),
        "report.txt объясняет ошибку:\n{txt}"
    );
    assert!(
        md.contains("## Ошибки (1)") && md.contains("rx-error"),
        "report.md объясняет ошибку:\n{md}"
    );
}

#[test]
fn no_error_section_when_clean() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let log = td.path().join("capture.log");
    std::fs::write(
        &log,
        "# capture start: label=clean\n# wall(start)=2026-11-19 17:01:38\n# attach: late\n",
    )
    .unwrap();

    let meta = import_legacy_log(&store, &log, Some("clean".into())).unwrap();
    assert_eq!(meta.counts.errors, 0);
    assert!(meta.counts.error_samples.is_empty());

    let dir = store.dir_for(&meta.id);
    let md = std::fs::read_to_string(dir.join("report.md")).unwrap();
    assert!(!md.contains("## Ошибки"), "чистая сессия без раздела ошибок");
}
