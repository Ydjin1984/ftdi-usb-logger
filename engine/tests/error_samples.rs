//! Ошибка сессии должна быть объяснена в отчёте, а не только посчитана.
//!
//! В логе идентификации PCMflash единственной «ошибкой» был `J2534 chan-miss`
//! (пропущенный `PassThruConnect`), но отчёт показывал голое «Ошибок: 1» —
//! приходилось лезть в `events.jsonl`, чтобы понять, что это. Тест фиксирует
//! весь конвейер: строка лога → `kind=error` → `counts.error_samples` →
//! `report.txt`/`report.md`.

use ftdi_logger::import::import_legacy_log;
use ftdi_logger::store::SessionStore;

const LOG: &str = "\
# capture start: label=pcmflash
# tool: C:\\Program Files (x86)\\PCMflash\\pcmflash.exe
# wall(start)=2026-11-19 17:01:38
# attach: late
# MARK wall=2026-11-19 17:01:42 rel=+4.053s START 1: Идентификация
[+6.298621s] J2534 module: smj2534.dll C:\\Program Files (x86)\\Scanmatik\\smj2534.dll base=0x63c90000 exports=14
[+6.308271s] J2534 open name=\"\" vendor=\"Scanmatik\" dll=\"smj2534.dll\" dev=1 mod=1 rc=0 th=16728
[+6.445617s] J2534 chan-miss ch=1 gen=1 first_op=ioctl mod=1 th=16728
[+6.445878s] J2534 ioctl ch=1 call=1 id=0x000a (CLEAR_MSG_FILTERS) rc=0 th=16728 dur=258 in_ptr=0 out_ptr=0
[+10.714889s] J2534 close dev=1 rc=0 th=31928 dur=6593
# MARK wall=2026-11-19 17:01:54 rel=+16.333s END 1: Идентификация (12.3 с)
# counters dropped_events=0 truncated_payloads=0 decode_errors=0 evicted_events=0 partial_results=0 contract_violations=0 rx_sof=0 calls=2 bridge_events=5 bridge_batches=1 bridge_backlog_max=1
";

#[test]
fn error_is_named_in_session_and_reports() {
    let td = tempfile::tempdir().unwrap();
    let store = SessionStore::open(td.path()).unwrap();
    let log = td.path().join("capture.log");
    std::fs::write(&log, LOG).unwrap();

    let meta = import_legacy_log(&store, &log, Some("pcmflash".into())).unwrap();

    assert_eq!(meta.counts.errors, 1, "ровно одна ошибка");
    assert_eq!(meta.counts.error_samples.len(), 1, "она расшифрована");
    let sample = &meta.counts.error_samples[0];
    assert!(sample.contains("chan-miss"), "что за ошибка: {sample}");
    assert!(sample.contains("first_op=ioctl"), "контекст ошибки: {sample}");
    assert!(sample.contains("шаг 1"), "шаг указан: {sample}");
    assert!(sample.starts_with("+6.446s"), "время указано: {sample}");

    let dir = store.dir_for(&meta.id);
    let txt = std::fs::read_to_string(dir.join("report.txt")).unwrap();
    let md = std::fs::read_to_string(dir.join("report.md")).unwrap();

    assert!(
        txt.contains("ошибки (1):") && txt.contains("chan-miss"),
        "report.txt объясняет ошибку:\n{txt}"
    );
    assert!(
        md.contains("## Ошибки (1)") && md.contains("chan-miss"),
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
