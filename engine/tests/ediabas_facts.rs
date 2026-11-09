//! EDIABAS/WinKFP: INI-факты, api.trc, IFH.trc, чтение прироста трасс с ротацией.

use ftdi_logger::ediabas;
use std::path::{Path, PathBuf};

fn ref_log(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../reference/logs")
        .join(name)
}

#[test]
fn api_trace_jobs_from_reference() {
    let text = std::fs::read_to_string(ref_log("ediabas/api.trc")).unwrap();
    let jobs = ediabas::parse_api_trace(&text);
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[0].sgbd, "bms46ds0");
    assert_eq!(jobs[0].job, "ident");
    assert_eq!(jobs[0].results_total, 2);
    assert_eq!(jobs[0].errors, Vec::<String>::new());
    assert_eq!(
        jobs[0].results.get("ID_BMW_NR").and_then(|v| v.as_str()),
        Some("\"1430940\"")
    );
    assert_eq!(
        jobs[0].results.get("ID_SW_NR").and_then(|v| v.as_str()),
        Some("\"F0\"")
    );
    assert_eq!(jobs[1].sgbd, "ms450");
    assert_eq!(jobs[1].job, "FLASH_PROGRAMMIEREN");
    assert_eq!(
        jobs[1].errors,
        vec!["Error (134) API-0014: RESULT NOT FOUND".to_string()]
    );
    // Служебные OBJECT и т.п. не попадают в результаты.
    assert!(!jobs[0].results.contains_key("OBJECT"));

    let job_line = ediabas::format_job(&jobs[0]);
    assert!(job_line.contains("job=\"ident\""));
    assert!(job_line.contains("sgbd=\"bms46ds0\""));
    let err_line = ediabas::format_job(&jobs[1]);
    assert!(err_line.contains("ОШИБКА"));
}

#[test]
fn ifh_trace_lines_from_reference() {
    let text = std::fs::read_to_string(ref_log("ediabas/IFH.trc")).unwrap();
    let lines = ediabas::parse_ifh_trace(&text);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].contains("INPUT"));
    assert!(lines[1].contains("OUTPUT: 12 04 0D 1B"));
}

#[test]
fn ini_facts_and_get() {
    let td = tempfile::tempdir().unwrap();
    let ed = td.path().join("EDIABAS.INI");
    let obd = td.path().join("OBD.INI");
    let wf = td.path().join("Winkfpt.ini");
    std::fs::write(
        &ed,
        "; comment\r\nInterface=STD:OBD\r\nTracePath=C:\\EDIABAS\\TRACE\r\nApiTrace=1\r\nIfhTrace=1\r\n",
    )
    .unwrap();
    std::fs::write(
        &obd,
        "[OBD]\r\nPort=Com1\r\nHardware=USB\r\nRETRY=ON\r\n",
    )
    .unwrap();
    std::fs::write(
        &wf,
        "[KFP]\r\nAPI_TRACE=1\r\nIFH_TRACE=1\r\nSCHNELLE_BAUDRATE=OFF\r\nTEST_CHECKSUMME=ON\r\n",
    )
    .unwrap();

    assert_eq!(ediabas::ini_get(&ed, "Interface"), "STD:OBD");
    assert_eq!(ediabas::ini_get(&ed, "ifhtrace"), "1");
    assert_eq!(ediabas::ini_get(&obd, "Port"), "Com1");
    assert_eq!(ediabas::ini_get(&wf, "API_TRACE"), "1");

    let facts = ediabas::ini_facts_from(&ed, &obd, &wf);
    assert_eq!(facts.len(), 3);
    assert!(facts[0].1.contains("Interface=STD:OBD"));
    assert!(facts[1].1.contains("Port=Com1"));
    assert!(facts[1].1.contains("RETRY=ON"));
    assert!(facts[2].1.contains("API_TRACE=1"));
}

#[test]
fn read_from_handles_rotation() {
    let td = tempfile::tempdir().unwrap();
    let path = td.path().join("api.trc");
    assert_eq!(ediabas::snapshot_trace(&path).unwrap(), 0);

    std::fs::write(&path, b"abcdef").unwrap();
    assert_eq!(ediabas::snapshot_trace(&path).unwrap(), 6);
    let (data, offset) = ediabas::read_from(&path, 4).unwrap();
    assert_eq!(data, b"ef");
    assert_eq!(offset, 6);

    // Ротация: файл стал короче сохранённого offset → читаем с начала.
    std::fs::write(&path, b"xy").unwrap();
    let (data, offset) = ediabas::read_from(&path, 6).unwrap();
    assert_eq!(data, b"xy");
    assert_eq!(offset, 2);

    let (data, offset) = ediabas::read_from(&path, 0).unwrap();
    assert_eq!(data, b"xy");
    assert_eq!(offset, 2);
}
