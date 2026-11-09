//! Грамматика старого лога: все формы строк, обрезка длинных дампов, телеграммы.

use ftdi_logger::decode::{
    decode_payload, parse_capture_line, read_telegram, split_echo_response, split_telegrams,
    summarize_step, MAX_EVENT_BYTES,
};
use ftdi_logger::models::{Direction, EventKind, Transport};
use serde_json::Value;

fn ev(line: &str) -> ftdi_logger::models::Event {
    parse_capture_line(line).unwrap_or_else(|| panic!("не разобрана строка: {line}"))
}

#[test]
fn ftd2xx_grammar() {
    let e = ev("[+2.673s] TX ftd2xx FT_Write rc=0 len=16 n=16 : 12 04 0d 1b");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Ftd2xx);
    assert_eq!(e.api, "FT_Write");
    assert_eq!(e.direction, Some(Direction::Tx));
    assert_eq!(e.rc, Some(0));
    assert_eq!(e.len, 16);
    assert_eq!(e.payload().len(), 4);

    let e = ev("[+2.674s] RX ftd2xx FT_Read rc=0 want=64 n=4 : 12 09 06 00");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.api, "FT_Read");
    assert_eq!(e.direction, Some(Direction::Rx));
    assert_eq!(e.meta.get("want").and_then(Value::as_u64), Some(64));
}

#[test]
fn vcp_grammar() {
    let e = ev("[+70.537s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Vcp);
    assert_eq!(e.api, "WriteFile");
    assert_eq!(e.meta.get("com").and_then(Value::as_str), Some("COM6"));
    assert_eq!(e.payload(), vec![0x12, 0x04, 0x0d, 0x1b]);

    // С rc и ovl (другой логер/хук).
    let e = ev("[+70.537s] VCP TX WriteFile(COM6) rc=0 n=2 ovl=0 : 12 04");
    assert_eq!(e.rc, Some(0));
    assert_eq!(e.meta.get("ovl").and_then(Value::as_u64), Some(0));

    // Одиночные байты, склеенные логером для показа.
    let e = ev("[+70.604s] VCP RX ReadFile(COM6) одиночные байты n=3 : 12 4c a0");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.len, 3);
    assert_eq!(e.meta.get("single_bytes").and_then(Value::as_bool), Some(true));

    // Overlapped-чтение: счётчика байт нет, буфер недостоверен.
    let e = ev("[+70.604s] VCP RX ReadFile(COM6) n=0 ovl=1 : ff ff");
    assert_eq!(e.len, 0);
    assert_eq!(e.meta.get("ovl_zero").and_then(Value::as_bool), Some(true));

    let e = ev("[+67.539s] VCP CreateFileW(COM6) handle=0x2b4 invalid=false");
    assert_eq!(e.kind, EventKind::Vcp);
    assert_eq!(e.api, "CreateFileW");
    assert_eq!(e.meta.get("handle").and_then(Value::as_str), Some("0x2b4"));
    assert_eq!(e.meta.get("invalid").and_then(Value::as_bool), Some(false));

    let e = ev("[+98.172s] VCP CloseHandle(COM6)");
    assert_eq!(e.kind, EventKind::Vcp);
    assert_eq!(e.api, "CloseHandle");
}

#[test]
fn file_and_module_grammar() {
    let e = ev(r"[+1.000s] FILE open C:\tmp\tune.bin access=0x80000000 handle=0x1a4");
    assert_eq!(e.kind, EventKind::File);
    assert_eq!(e.api, "FILE open");
    assert_eq!(e.text.as_deref(), Some(r"C:\tmp\tune.bin"));
    assert_eq!(e.meta.get("access").and_then(Value::as_str), Some("0x80000000"));

    let e = ev(r"[+2.000s] FILE close C:\tmp\tune.bin bytes=65536 writes=8");
    assert_eq!(e.api, "FILE close");
    assert_eq!(e.meta.get("bytes").and_then(Value::as_u64), Some(65536));
    assert_eq!(e.meta.get("writes").and_then(Value::as_u64), Some(8));

    let e = ev(r"[+3.000s] FILE write C:\tmp\x.bin n=16 total=65552 offset=0");
    assert_eq!(e.api, "FILE write");
    assert_eq!(e.meta.get("total").and_then(Value::as_u64), Some(65552));

    let e = ev(r"[+2.010s] MODULE + ftd2xx.dll C:\Windows\SYSTEM32\FTD2XX.DLL base=0x7ffaffe90000");
    assert_eq!(e.kind, EventKind::Module);
    assert_eq!(e.meta.get("op").and_then(Value::as_str), Some("+"));
    assert_eq!(e.meta.get("base").and_then(Value::as_str), Some("0x7ffaffe90000"));

    let e = ev(r"[+0.001s] MODULE(now) ftd2xx.dll C:\Windows\ftd2xx.dll base=0x180000000");
    assert_eq!(e.meta.get("op").and_then(Value::as_str), Some("now"));
}

#[test]
fn marks_two_formats_and_phase() {
    // Логер: без rel.
    let e = ev("# MARK wall=2026-10-16 11:53:45 START 1: читаю идентификаторы");
    assert_eq!(e.kind, EventKind::StepStart);
    assert_eq!(e.wall, "2026-10-16 11:53:45");
    assert_eq!(e.meta.get("idx").and_then(Value::as_u64), Some(1));
    assert_eq!(e.text.as_deref(), Some("читаю идентификаторы"));
    assert_eq!(e.t, 0.0);

    let e = ev("# MARK wall=2026-10-16 11:53:47 END 1: читаю идентификаторы (1.6 с)");
    assert_eq!(e.kind, EventKind::StepEnd);
    assert_eq!(e.meta.get("dur").and_then(Value::as_f64), Some(1.6));

    // Внешний mark.py: с rel — t берётся из rel, если нет [+Xs].
    let e = ev("# MARK wall=2026-10-16 11:53:45 rel=+70.537s START 2: тест");
    assert_eq!(e.meta.get("rel").and_then(Value::as_f64), Some(70.537));
    assert!((e.t - 70.537).abs() < 1e-9);
    assert_eq!(e.meta.get("idx").and_then(Value::as_u64), Some(2));

    let e = ev("# PHASE 1: читаю | длительность 1.6 с | TX 248 посылок / 22026 B");
    assert_eq!(e.kind, EventKind::Summary);
    assert_eq!(e.api, "PHASE");
    assert_eq!(e.meta.get("idx").and_then(Value::as_u64), Some(1));

    let e = ev(r#"# PHASE-JSON {"idx": 1, "title": "x", "reads": []}"#);
    assert_eq!(e.api, "PHASE-JSON");
    assert_eq!(e.meta.get("idx").and_then(Value::as_u64), Some(1));
    assert_eq!(e.text.as_deref(), Some("x"));

    let e = ev(r"# filehash D:\firmware.bin size=65536 sha256=abc123");
    assert_eq!(e.kind, EventKind::FileHash);
    assert_eq!(e.meta.get("size").and_then(Value::as_u64), Some(65536));
    assert_eq!(e.meta.get("sha256").and_then(Value::as_str), Some("abc123"));
}

#[test]
fn comments_and_unknown_lines() {
    let e = ev("# capture start: label=WinKFP");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "CAPTURE");
    assert_eq!(e.meta.get("label").and_then(Value::as_str), Some("WinKFP"));

    let e = ev("# wall(start)=2026-10-12 02:04:20");
    assert_eq!(e.api, "WALL");
    assert_eq!(e.text.as_deref(), Some("2026-10-12 02:04:20"));

    let e = ev("# EDIABAS.INI: Interface=STD:OBD TracePath=C:\\EDIABAS\\TRACE");
    assert_eq!(e.kind, EventKind::Sys);
    assert!(e.api.starts_with("EDIABAS"));

    let e = ev("# attached pid=32808");
    assert_eq!(e.api, "ATTACHED");
    assert_eq!(e.meta.get("pid").and_then(Value::as_u64), Some(32808));

    let e = ev("совсем непонятная строка");
    assert_eq!(e.kind, EventKind::Raw);
    assert_eq!(e.api, "RAW");

    assert!(parse_capture_line("").is_none());
    assert!(parse_capture_line("  \r\n").is_none());

    let e = ev("[+0.010s] script-error: TypeError x is not a function");
    assert_eq!(e.kind, EventKind::Error);
}

#[test]
fn long_payload_is_truncated_to_64k() {
    let payload: String = (0..40_000u32)
        .map(|i| format!("{:02x}", (i % 256) as u8))
        .collect::<Vec<_>>()
        .join(" ");
    let line = format!("[+5.000s] VCP TX WriteFile(COM6) n=40000 : {payload}");
    let e = parse_capture_line(&line).unwrap();
    assert_eq!(e.len, 40_000);
    assert_eq!(
        e.meta.get("truncated").and_then(Value::as_bool),
        Some(true),
        "длинный дамп обязан быть помечен"
    );
    assert!(
        e.hex.len() <= MAX_EVENT_BYTES,
        "hex {} > {}", e.hex.len(), MAX_EVENT_BYTES
    );
    // Предел держим по hex-тексту, поэтому байт меньше 64 КиБ.
    let bytes = e.payload().len();
    assert!(bytes > 20_000 && bytes < 22_000, "bytes={bytes}");
}

#[test]
fn telegrams_echo_a0_read_and_7f() {
    // Первый ответ: кадр `12 4c a0 <72 B payload> <cks>` (76 байт), как на живом логе.
    let mut lines: Vec<String> = vec![
        "[+70.537s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b".into(),
        "[+70.543s] VCP RX ReadFile(COM6) n=4 : 12 04 0d 1b".into(),
    ];
    let mut frame = vec!["12".to_string(), "4c".to_string(), "a0".to_string()];
    frame.extend((0u16..72).map(|i| format!("{:02x}", i % 256)));
    frame.push("00".into()); // checksum
    for chunk in frame.chunks(32) {
        lines.push(format!(
            "[+70.604s] VCP RX ReadFile(COM6) одиночные байты n={} : {}",
            chunk.len(),
            chunk.join(" ")
        ));
    }
    // Второй обмен: чтение памяти 0x03FD60 +46 (ответ 50 байт).
    lines.push("[+70.742s] VCP TX WriteFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad".into());
    lines.push("[+70.754s] VCP RX ReadFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad".into());
    lines.push(
        "[+70.809s] VCP RX ReadFile(COM6) одиночные байты n=32 : 12 32 a0 20 2c a2 95 0c 10 07 01 34 c4 04 22 44 00 ee 62 00 72 74 24 03 4a 00 15 d2 6a 00 72 74"
            .into(),
    );
    lines.push(
        "[+70.844s] VCP RX ReadFile(COM6) одиночные байты n=18 : 23 00 30 30 30 30 30 00 00 61 00 00 00 00 f0 00 00 fd"
            .into(),
    );

    let events: Vec<_> = lines
        .iter()
        .map(|l| parse_capture_line(l).unwrap())
        .collect();
    let t = split_telegrams(&events);
    assert_eq!(t.len(), 2);
    assert!(t[0].echo);
    assert_eq!(t[0].cmd.as_deref(), Some("cmd=0x0D"));
    assert!(
        t[0].resp.as_deref().unwrap().starts_with("A0 payload=72B"),
        "resp={:?}",
        t[0].resp
    );
    assert!(t[1].echo);
    assert_eq!(t[1].cmd.as_deref(), Some("READ 0x03FD60 +46"));
    assert!(t[1].resp.as_deref().unwrap().starts_with("A0 payload=46B"));

    // Чтение памяти распознаётся по TX.
    let tx = vec![0x12, 0x09, 0x06, 0x00, 0x03, 0xfd, 0x60, 0x2e, 0xad];
    assert_eq!(read_telegram(&tx), Some((0x0003_FD60, 0x2e)));

    // 7F svc nrc: b8-обёртка KWP2000 (ME7.2).
    let tx = vec![0xb8, 0x13, 0xf1, 0x02, 0x10, 0x85, 0x00];
    let residual = vec![0xb8, 0x13, 0xf1, 0x03, 0x7f, 0x10, 0x33, 0x00];
    let (class, payload, _tail) = ftdi_logger::decode::parse_frame(&tx, &residual);
    assert_eq!(class, "7F(10,33-securityAccessDenied)");
    assert!(payload.is_empty());

    let echo = split_echo_response(&[0x12, 0x04], &[0x12, 0x04, 0x0d]);
    assert_eq!(echo, (true, vec![0x0d]));
}

#[test]
fn step_summary_and_payload_decode() {
    let lines = [
        "# MARK wall=2026-10-16 11:53:45 START 1: тест",
        "[+70.537s] VCP TX WriteFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad",
        "[+70.543s] VCP RX ReadFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad",
        "[+70.604s] VCP RX ReadFile(COM6) n=32 : 12 32 a0 20 2c a2 95 0c 10 07 01 34 c4 04 22 44 00 ee 62 00 72 74 24 03 4a 00 15 d2 6a 00 72 74",
        "[+70.844s] VCP RX ReadFile(COM6) n=18 : 23 00 30 30 30 30 30 00 00 61 00 00 00 00 f0 00 00 fd",
        "# MARK wall=2026-10-16 11:53:47 END 1: тест (1.6 с)",
    ];
    let events: Vec<_> = lines
        .iter()
        .map(|l| parse_capture_line(l).unwrap())
        .collect();
    let summary = summarize_step(&events, 1, "", 0.0, None);
    assert_eq!(summary.exchanges, 1);
    assert_eq!(summary.tx_bytes, 9);
    assert_eq!(summary.rx_bytes, 9 + 32 + 18);
    assert_eq!(summary.cmd_hist.get("READ(0x06)"), Some(&1));
    assert_eq!(summary.resp_hist.get("A0"), Some(&1));
    assert_eq!(summary.reads.len(), 1);
    assert_eq!(summary.reads[0].start, 0x0003_FD60);
    assert_eq!(summary.reads[0].len, 46);
    assert_eq!(summary.verdict.echo, true);

    let decoded = decode_payload("12 04 0d 1b");
    assert_eq!(decoded.echo, Some(0x12));
    assert_eq!(decoded.cmd.as_deref(), Some("cmd=0x0D"));

    let decoded = decode_payload("12 32 a0 20 2c");
    assert_eq!(decoded.cmd.as_deref(), Some("A0"));
    assert_eq!(decoded.payload_hex, "20");
    let decoded = decode_payload("12 08 a0 20 2c a2 95 0c 00");
    assert_eq!(decoded.cmd.as_deref(), Some("A0"));
    assert_eq!(decoded.payload_hex, "20 2c a2 95 0c");

    let decoded = decode_payload("12 09 06 00 03 fd 60 2e ad");
    assert!(decoded.cmd.as_deref().unwrap().starts_with("READ(0x03FD60"));
}
#[test]
fn short_frame_does_not_panic() {
    // residual len=2 при совпадении первого байта раньше давал `frame[2]` ->
    // index out of bounds (паника в writer-задаче на закрытии шага).
    let tx = ev("[+1.000s] VCP TX WriteFile(COM6) n=3 : 12 02 03");
    let rx = ev("[+1.100s] VCP RX ReadFile(COM6) n=3 : 12 02 00");
    let s = summarize_step(&[tx, rx], 1, "short", 1.0, None);
    assert_eq!(s.idx, 1);
    assert!(s.exchanges <= 1);
}
