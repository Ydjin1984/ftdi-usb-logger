//! Универсальный захват: грамматика J2534/USB (docs/02 §11.3), ISOTP-декод,
//! гистограммы J2534 в сводке шага. Старые golden-тесты не затронуты.

use ftdi_logger::decode::{
    decode_isotp, decode_payload_event, parse_capture_line, summarize_step,
};
use ftdi_logger::models::{Direction, Event, EventKind, Transport};
use serde_json::Value;

fn ev(line: &str) -> Event {
    parse_capture_line(line).unwrap_or_else(|| panic!("не разобрана строка: {line}"))
}

fn j2534_event(kind: EventKind, hex: &str, can_id: &str, protocol: &str, t: f64) -> Event {
    let mut e = Event::new(kind, Transport::J2534, t, "");
    e.hex = hex.into();
    e.len = ftdi_logger::models::util::hex_to_bytes(hex).len() as u32;
    e.meta = serde_json::json!({"can_id": can_id, "protocol": protocol, "channel": "1"});
    e
}

#[test]
fn j2534_open_connect_ioctl_disconnect() {
    let e = ev(r#"[+1.234s] J2534 open name="Scanmatik - SM2 USB" vendor="Scanmatik" dll="smj2534.dll" rc=0"#);
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.api, "J2534 open");
    assert_eq!(
        e.meta.get("device").and_then(Value::as_str),
        Some("Scanmatik - SM2 USB")
    );
    assert_eq!(e.meta.get("vendor").and_then(Value::as_str), Some("Scanmatik"));
    assert_eq!(e.meta.get("dll").and_then(Value::as_str), Some("smj2534.dll"));
    assert_eq!(e.rc, Some(0));
    assert!(e.text.as_deref().unwrap().starts_with("J2534 open"));

    let e = ev("[+1.300s] J2534 connect dev=1 ch=1 proto=ISO15765 flags=0x0 baud=500000 rc=0");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(
        e.meta.get("protocol").and_then(Value::as_str),
        Some("ISO15765")
    );
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("baud").and_then(Value::as_str), Some("500000"));
    assert_eq!(e.text.as_deref(), Some("connect proto=ISO15765 ch=1"));

    let e = ev("[+3.000s] J2534 ioctl ch=1 id=0x0701 rc=0");
    assert_eq!(e.api, "J2534 ioctl");
    assert_eq!(e.meta.get("ioctl_id").and_then(Value::as_str), Some("0x0701"));
    assert_eq!(e.text.as_deref(), Some("ioctl 0x0701 ch=1"));

    let e = ev("[+3.100s] J2534 disconnect ch=1 rc=0");
    assert_eq!(e.api, "J2534 disconnect");
    assert_eq!(e.text.as_deref(), Some("disconnect ch=1"));

    let e = ev(r#"[+3.200s] J2534 err ch=1 code=0x10 msg="bus error""#);
    assert_eq!(e.kind, EventKind::Error);
    assert_eq!(e.transport, Transport::J2534);
    assert!(e.text.as_deref().unwrap().contains("bus error"));
}

#[test]
fn j2534_tx_rx_meta_and_text() {
    let e = ev("[+2.100s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 flags=0x0 len=8 : 02 10 03 00 00 00 00 00");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.direction, Some(Direction::Tx));
    assert_eq!(e.api, "J2534 TX");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(
        e.meta.get("protocol").and_then(Value::as_str),
        Some("ISO15765")
    );
    assert_eq!(e.meta.get("can_id").and_then(Value::as_str), Some("0x7E0"));
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.len, 8);
    assert_eq!(e.payload()[0..3], [0x02, 0x10, 0x03]);
    assert_eq!(e.text.as_deref(), Some("ISO15765 0x7E0"));

    let e = ev("[+2.150s] J2534 RX ch=1 proto=ISO15765 id=0x7E8 rxs=0x0 len=8 : 06 50 03 00 00 00 00 00");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.direction, Some(Direction::Rx));
    assert_eq!(e.api, "J2534 RX");
    assert_eq!(e.meta.get("can_id").and_then(Value::as_str), Some("0x7E8"));
    assert_eq!(e.meta.get("rxs").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.text.as_deref(), Some("ISO15765 0x7E8"));
}

#[test]
fn usb_open_close_and_ioctl() {
    let e = ev(r#"[+4.000s] USB open path="\\?\hid#vid_046d&pid_c52b" kind=hid handle=0x2b4"#);
    assert_eq!(e.kind, EventKind::Usb);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.api, "USB open");
    assert_eq!(
        e.meta.get("path").and_then(Value::as_str),
        Some(r"\\?\hid#vid_046d&pid_c52b")
    );
    assert_eq!(e.meta.get("kind").and_then(Value::as_str), Some("hid"));
    assert_eq!(e.meta.get("handle").and_then(Value::as_str), Some("0x2b4"));
    assert!(e.text.as_deref().unwrap().contains("USB open"));

    let e = ev(r#"[+4.100s] USB close path="\\?\hid#vid_046d&pid_c52b" bytes=64 writes=3"#);
    assert_eq!(e.kind, EventKind::Usb);
    assert_eq!(e.meta.get("bytes").and_then(Value::as_u64), Some(64));
    assert_eq!(e.meta.get("writes").and_then(Value::as_u64), Some(3));

    let e = ev("[+4.150s] USB ioctl handle=0x2b4 code=0x0b01 rc=0");
    assert_eq!(e.kind, EventKind::Usb);
    assert_eq!(e.api, "USB ioctl");
    assert_eq!(e.meta.get("handle").and_then(Value::as_str), Some("0x2b4"));
    assert_eq!(e.rc, Some(0));
}

#[test]
fn winusb_hid_libusb_exchange() {
    let e = ev("[+4.200s] WINUSB TX pipe=0x01 len=8 : 12 04 0d 1b 00 00 00 00");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.direction, Some(Direction::Tx));
    assert_eq!(e.meta.get("pipe").and_then(Value::as_str), Some("0x01"));
    assert_eq!(e.text.as_deref(), Some("WINUSB pipe=0x01"));
    assert_eq!(e.len, 8);

    let e = ev("[+4.250s] WINUSB RX pipe=0x81 len=2 : aa bb");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.meta.get("pipe").and_then(Value::as_str), Some("0x81"));

    let e = ev("[+4.300s] HID TX report=0x02 len=9 : 01 02 03 04 05 06 07 08 09");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.meta.get("report").and_then(Value::as_str), Some("0x02"));
    assert_eq!(e.text.as_deref(), Some("HID report=0x02"));

    let e = ev("[+4.350s] HID RX report=0x01 len=1 : 00");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.text.as_deref(), Some("HID report=0x01"));

    let e = ev("[+4.400s] LIBUSB TX ep=0x01 len=8 : 12 04 0d 1b 00 00 00 00");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.meta.get("ep").and_then(Value::as_str), Some("0x01"));
    assert_eq!(e.text.as_deref(), Some("LIBUSB ep=0x01"));

    let e = ev("[+4.450s] LIBUSB RX ep=0x81 len=8 : 12 04 0d 1b 00 00 00 00");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.meta.get("ep").and_then(Value::as_str), Some("0x81"));

    // ioctl-ветки HID/USB не падают.
    let e = ev("[+4.500s] HID ioctl handle=0x1 code=0x1 rc=0");
    assert_eq!(e.kind, EventKind::Usb);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.api, "HID ioctl");
}

#[test]
fn summarize_j2534_histograms_and_no_reads() {
    let events = vec![
        ev("# MARK wall=2026-11-09 12:00:00 START 1: J2534 тест"),
        ev("[+1.000s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 flags=0x0 len=8 : 02 10 03 00 00 00 00 00"),
        ev("[+1.050s] J2534 RX ch=1 proto=ISO15765 id=0x7E8 rxs=0x0 len=8 : 06 50 03 00 00 00 00 00"),
        ev("[+1.100s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 flags=0x0 len=2 : 01 3E"),
        ev("[+1.150s] J2534 RX ch=1 proto=ISO15765 id=0x7E8 rxs=0x0 len=2 : 01 7E"),
        ev("# MARK wall=2026-11-09 12:00:02 END 1: J2534 тест (1.15 с)"),
    ];
    let summary = summarize_step(&events, 1, "", 0.0, None);
    assert_eq!(summary.exchanges, 2, "две J2534-посылки");
    assert_eq!(summary.tx_bytes, 8 + 2);
    assert_eq!(summary.rx_bytes, 8 + 2);
    // Ключ гистограммы — протокол + CAN-id (+ сервис, если он читается из ISO-TP SF).
    let cmd_total: u64 = summary
        .cmd_hist
        .iter()
        .filter(|(k, _)| k.starts_with("ISO15765 0x7E0"))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(cmd_total, 2, "команды J2534 по can_id: {:?}", summary.cmd_hist);
    assert!(
        summary
            .cmd_hist
            .keys()
            .any(|k| k.contains("StartDiagnosticSession")),
        "сервис 0x10 распознан: {:?}",
        summary.cmd_hist
    );
    let resp_total: u64 = summary
        .resp_hist
        .iter()
        .filter(|(k, _)| k.starts_with("ISO15765 0x7E8"))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(resp_total, 2, "ответы J2534 по can_id: {:?}", summary.resp_hist);
    assert!(summary.reads.is_empty(), "J2534 не даёт K-line чтений");
}

#[test]
fn isotp_pci_decoding() {
    // SF запрос: 02 10 03 — SID 0x10 (StartDiagnosticSession).
    let e = j2534_event(EventKind::Tx, "02 10 03 00 00 00 00 00", "0x7E0", "ISO15765", 1.0);
    let d = decode_payload_event(&e);
    assert!(d.cmd.as_deref().unwrap().contains("ISO15765 0x7E0 · SF 2B"), "{:?}", d.cmd);
    assert_eq!(d.payload_hex, "10 03");
    assert!(d.notes.iter().any(|n| n.contains("ISOTP PCI: SF")));
    assert!(d.notes.iter().any(|n| n.contains("0x10") && n.contains("StartDiagnosticSession")));

    // SF положительный ответ: 06 50 03 ... — ответ на 0x10.
    let e = j2534_event(EventKind::Rx, "06 50 03 00 00 00 00 00", "0x7E8", "ISO15765", 1.1);
    let d = decode_payload_event(&e);
    assert!(d.cmd.as_deref().unwrap().contains("SF 6B"));
    assert!(d.notes.iter().any(|n| n.contains("0x50")));

    // FF: 12-битная длина 0x14 = 20 B.
    let e = j2534_event(EventKind::Tx, "10 14 36 01 02 03", "0x7E0", "ISO15765", 1.2);
    let d = decode_payload_event(&e);
    assert!(d.cmd.as_deref().unwrap().contains("FF 20B"), "{:?}", d.cmd);
    assert_eq!(d.payload_hex, "36 01 02 03");

    // CF: seq = 1.
    let e = j2534_event(EventKind::Tx, "21 36 01 02", "0x7E0", "ISO15765", 1.3);
    let d = decode_payload_event(&e);
    assert!(d.cmd.as_deref().unwrap().contains("CF seq=1"));
    assert!(d.notes.iter().any(|n| n.contains("CF seq=1")));

    // FC: CTS, block=0, STmin=0.
    let e = j2534_event(EventKind::Rx, "30 00 00 00 00 00 00 00", "0x7E8", "ISO15765", 1.4);
    let d = decode_payload_event(&e);
    assert!(d.cmd.as_deref().unwrap().contains("FC CTS"), "{:?}", d.cmd);
    assert!(d.notes.iter().any(|n| n.contains("block=0") && n.contains("STmin=0")));

    // Негативный ответ 7F 22 31.
    let e = j2534_event(EventKind::Rx, "03 7F 22 31", "0x7E8", "ISO15765", 1.5);
    let d = decode_payload_event(&e);
    assert!(d.notes.iter().any(|n| n.contains("негативный") && n.contains("0x22")));
}

#[test]
fn short_and_broken_universal_lines_do_not_panic() {
    let lines = [
        "J2534",
        "J2534 TX",
        "J2534 TX ch=1 id=0x7E0 len=8 : ",
        "J2534 open name=\"незакрытая кавычка",
        "USB open path=",
        "USB close",
        "WINUSB TX len=8",
        "WINUSB",
        "HID RX report=",
        "LIBUSB RX ep=",
        "USB ",
    ];
    for line in lines {
        let parsed = parse_capture_line(line);
        assert!(parsed.is_some(), "строка должна сохраниться как событие: {line:?}");
    }

    // ISOTP на коротких/битых данных не паникует.
    for (hex, tag) in [
        ("", "пусто"),
        ("02", "SF"),
        ("10", "FF"),
        ("21", "CF"),
        ("30", "FC"),
        ("ff", "мусор"),
    ] {
        let d = decode_isotp(hex, "0x7E8", "ISO15765");
        assert!(d.cmd.is_some(), "нет cmd для {tag}");
        assert!(!d.notes.is_empty(), "нет notes для {tag}");
    }
}

#[test]
fn mixed_step_keeps_serial_reads_and_j2534_hist() {
    // Смешанный шаг: K-line чтение + J2534 обмен. Чтения — только из K-line.
    let events = vec![
        ev("# MARK wall=2026-11-09 12:00:00 START 1: mixed"),
        ev("[+1.000s] VCP TX WriteFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad"),
        ev("[+1.010s] VCP RX ReadFile(COM6) n=9 : 12 09 06 00 03 fd 60 2e ad"),
        ev("[+1.020s] VCP RX ReadFile(COM6) n=32 : 12 32 a0 20 2c a2 95 0c 10 07 01 34 c4 04 22 44 00 ee 62 00 72 74 24 03 4a 00 15 d2 6a 00 72 74"),
        ev("[+1.030s] VCP RX ReadFile(COM6) n=18 : 23 00 30 30 30 30 30 00 00 61 00 00 00 00 f0 00 00 fd"),
        ev("[+1.100s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 flags=0x0 len=2 : 01 3E"),
        ev("[+1.150s] J2534 RX ch=1 proto=ISO15765 id=0x7E8 rxs=0x0 len=2 : 01 7E"),
        ev("# MARK wall=2026-11-09 12:00:02 END 1: mixed (1.15 с)"),
    ];
    let summary = summarize_step(&events, 1, "", 0.0, None);
    assert_eq!(summary.reads.len(), 1, "K-line чтение собрано");
    assert_eq!(summary.reads[0].start, 0x0003_FD60);
    assert_eq!(summary.reads[0].len, 46);
    assert_eq!(summary.cmd_hist.get("READ(0x06)"), Some(&1));
    assert!(
        summary
            .cmd_hist
            .iter()
            .any(|(k, v)| k.starts_with("ISO15765 0x7E0") && *v == 1),
        "команда J2534: {:?}",
        summary.cmd_hist
    );
    assert_eq!(summary.resp_hist.get("A0"), Some(&1));
    assert!(
        summary
            .resp_hist
            .iter()
            .any(|(k, v)| k.starts_with("ISO15765 0x7E8") && *v == 1),
        "ответ J2534: {:?}",
        summary.resp_hist
    );
}

#[test]
fn usbraw_packets() {
    // Bulk TX: кадр из usbpcap::UsbPacket::to_line().
    let e = ev("[+12.345s] USBRAW bus=1 dev=4 ep=0x01 bulk fdo->pdo func=0x9 status=0x0 len=4 : 12 04 0d 1b");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.direction, Some(Direction::Tx));
    assert_eq!(e.api, "USBRAW");
    assert_eq!(e.len, 4);
    assert_eq!(e.payload(), vec![0x12, 0x04, 0x0d, 0x1b]);
    assert_eq!(e.meta.get("bus").and_then(Value::as_u64), Some(1));
    assert_eq!(e.meta.get("device").and_then(Value::as_u64), Some(4));
    assert_eq!(e.meta.get("endpoint").and_then(Value::as_str), Some("0x01"));
    assert_eq!(e.meta.get("transfer").and_then(Value::as_str), Some("bulk"));
    assert_eq!(e.meta.get("function").and_then(Value::as_str), Some("0x9"));
    assert_eq!(e.meta.get("status").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("usbpcap").and_then(Value::as_bool), Some(true));
    assert_eq!(e.text.as_deref(), Some("USBRAW bulk ep=0x01"));
    assert!(e.raw.contains("fdo->pdo"), "raw обязан сохраниться");

    // Bulk RX: pdo->fdo.
    let e = ev("[+12.400s] USBRAW bus=1 dev=4 ep=0x81 bulk pdo->fdo func=0x9 status=0x0 len=2 : aa bb");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.direction, Some(Direction::Rx));
    assert_eq!(e.payload(), vec![0xaa, 0xbb]);

    // Control без данных: len=0 → Sys, не обмен.
    let e = ev("[+12.500s] USBRAW bus=1 dev=4 ep=0x00 control fdo->pdo func=0x9 status=0x0 len=0");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::Usb);
    assert_eq!(e.api, "USBRAW-SETUP");
    assert_eq!(e.len, 0);
    assert!(e.payload().is_empty());
    assert_eq!(e.meta.get("transfer").and_then(Value::as_str), Some("control"));
    assert_eq!(e.meta.get("usbpcap").and_then(Value::as_bool), Some(true));

    // Битые строки не паникуют.
    for line in [
        "USBRAW",
        "USBRAW len=4",
        "USBRAW bus=1 dev=4 ep=0x01 bulk fdo->pdo len=4 : ",
        "USBRAW bus=x dev=y ep=zz bulk ???",
    ] {
        assert!(parse_capture_line(line).is_some(), "не разобрана: {line}");
    }
}

#[test]
fn transport_summary_detects_mixed() {
    use ftdi_logger::decode::transport_summary;
    let mut vcp = Event::new(EventKind::Tx, Transport::Vcp, 1.0, "");
    vcp.hex = "12 04".into();
    let mut j = Event::new(EventKind::Tx, Transport::J2534, 2.0, "");
    j.hex = "02 10 03".into();
    let mut usb = Event::new(EventKind::Tx, Transport::Usb, 3.0, "");
    usb.hex = "aa".into();
    assert_eq!(transport_summary(&[vcp.clone()]), "vcp");
    assert_eq!(transport_summary(&[j.clone()]), "j2534");
    assert_eq!(transport_summary(&[usb.clone()]), "usb");
    assert_eq!(transport_summary(&[vcp.clone(), j.clone()]), "mixed");
    assert_eq!(transport_summary(&[vcp, j, usb]), "mixed");
    assert_eq!(transport_summary(&[]), "");
}

#[test]
fn com_line_settings_logged() {
    let e = ev("[+2.100s] COM SetCommState(COM8) baud=19200 data=8 parity=NONE stop=1 flow=RTS_CTS rc=0");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::Vcp);
    assert_eq!(e.api, "COM SetCommState");
    assert_eq!(e.meta.get("port").and_then(Value::as_str), Some("COM8"));
    assert_eq!(e.meta.get("baud").and_then(Value::as_i64), Some(19200));
    assert_eq!(e.meta.get("data").and_then(Value::as_i64), Some(8));
    assert_eq!(e.meta.get("parity").and_then(Value::as_str), Some("NONE"));
    assert_eq!(e.rc, Some(0));
    assert!(e.text.as_deref().unwrap().contains("baud=19200"));

    let e = ev("[+2.101s] COM SetCommTimeouts(COM8) read_interval=0 read_total_mul=0 read_total_const=800 write_total_mul=0 write_total_const=800 rc=0");
    assert_eq!(e.api, "COM SetCommTimeouts");
    assert_eq!(
        e.meta.get("read_total_const").and_then(Value::as_i64),
        Some(800)
    );
    assert_eq!(
        e.meta.get("write_total_const").and_then(Value::as_i64),
        Some(800)
    );
}

#[test]
fn j2534_set_config_logged() {
    let e = ev("[+5.000s] J2534 config ch=1 DATA_RATE=500000 W1=0 ISO15765_BS=8 rc=0");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.api, "J2534 config");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("DATA_RATE").and_then(Value::as_i64), Some(500000));
    assert_eq!(e.meta.get("W1").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("ISO15765_BS").and_then(Value::as_i64), Some(8));
    assert_eq!(e.rc, Some(0));
    assert!(e.text.as_deref().unwrap().contains("DATA_RATE=500000"));
}

#[test]
fn com_initial_state_and_timeouts_logged() {
    let e = ev("[+2.257s] COM state(COM1) baud=9600 data=8 parity=EVEN stop=1 flow=NONE (текущие на момент attach)");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::Vcp);
    assert_eq!(e.api, "COM state");
    assert_eq!(e.meta.get("port").and_then(Value::as_str), Some("COM1"));
    assert_eq!(e.meta.get("baud").and_then(Value::as_i64), Some(9600));
    assert_eq!(e.meta.get("parity").and_then(Value::as_str), Some("EVEN"));

    let e = ev("[+2.258s] COM timeouts(COM1) read_interval=4294967295 read_total_mul=4294967295 read_total_const=1000 write_total_mul=0 write_total_const=1000 (текущие на момент attach)");
    assert_eq!(e.api, "COM timeouts");
    assert_eq!(e.meta.get("read_total_const").and_then(Value::as_i64), Some(1000));
    assert_eq!(e.meta.get("write_total_const").and_then(Value::as_i64), Some(1000));
}

// ───────── docs/11-capture-grammar.md: кейс на каждый новый формат ─────────

#[test]
fn grammar_api_banner() {
    // `# api: 04.04 dll="…" ver="…" path="…" pid=8120 bits=32 dec=1`
    let e = ev(r#"# api: 04.04 dll="smj2534.dll" ver="1.0.0.120" path="C:\PCMflash\smj2534.dll" pid=8120 bits=32 dec=1"#);
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "API");
    assert_eq!(e.meta.get("api_version").and_then(Value::as_str), Some("04.04"));
    assert_eq!(e.meta.get("dll").and_then(Value::as_str), Some("smj2534.dll"));
    assert_eq!(e.meta.get("ver").and_then(Value::as_str), Some("1.0.0.120"));
    assert_eq!(
        e.meta.get("path").and_then(Value::as_str),
        Some(r"C:\PCMflash\smj2534.dll")
    );
    assert_eq!(e.meta.get("pid").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("bits").and_then(Value::as_i64), Some(32));
    assert_eq!(e.meta.get("dec").and_then(Value::as_i64), Some(1));

    // ABI не подтверждён: `dec=0` и причина.
    let e = ev(r#"# api: unknown dll="x.dll" ver="" path="C:\x\x.dll" pid=8120 bits=32 dec=0 reason=ambiguous"#);
    assert_eq!(e.api, "API");
    assert_eq!(e.meta.get("api_version").and_then(Value::as_str), Some("unknown"));
    assert_eq!(e.meta.get("dec").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("reason").and_then(Value::as_str), Some("ambiguous"));
}

#[test]
fn grammar_hooks_and_hook_names() {
    let e = ev(r#"# hooks mod="smj2534.dll" base=0x6d830000 load=1 exports=14 attached=14 dup=0 failed=0"#);
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "HOOKS");
    assert_eq!(e.meta.get("mod").and_then(Value::as_str), Some("smj2534.dll"));
    assert_eq!(e.meta.get("base").and_then(Value::as_str), Some("0x6d830000"));
    assert_eq!(e.meta.get("load").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("exports").and_then(Value::as_i64), Some(14));
    assert_eq!(e.meta.get("attached").and_then(Value::as_i64), Some(14));
    assert_eq!(e.meta.get("dup").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("failed").and_then(Value::as_i64), Some(0));

    let e = ev(r#"# hooks-names mod="smj2534.dll" names="PassThruOpen,PassThruClose,PassThruConnect""#);
    assert_eq!(e.api, "HOOKS-NAMES");
    assert_eq!(e.meta.get("mod").and_then(Value::as_str), Some("smj2534.dll"));
    assert_eq!(
        e.meta.get("names").and_then(Value::as_str),
        Some("PassThruOpen,PassThruClose,PassThruConnect")
    );
}

#[test]
fn grammar_counters_and_session_incomplete() {
    let e = ev("# counters dropped_events=0 truncated_payloads=0 decode_errors=0 rx_sof=0 calls=0");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "COUNTERS");
    for (key, want) in [
        ("dropped_events", 0),
        ("truncated_payloads", 0),
        ("decode_errors", 0),
        ("rx_sof", 0),
        ("calls", 0),
    ] {
        assert_eq!(e.meta.get(key).and_then(Value::as_i64), Some(want), "нет {key}");
    }

    let e = ev("# session incomplete: reason=queue_overflow dropped=12");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "SESSION-INCOMPLETE");
    assert_eq!(e.meta.get("reason").and_then(Value::as_str), Some("queue_overflow"));
    assert_eq!(e.meta.get("dropped").and_then(Value::as_i64), Some(12));
}

#[test]
fn grammar_agent_and_attach_banner() {
    let e = ev("# agent: universal_capture.js mode=full");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "AGENT");
    assert_eq!(
        e.meta.get("agent").and_then(Value::as_str),
        Some("universal_capture.js")
    );
    assert_eq!(e.meta.get("mode").and_then(Value::as_str), Some("full"));

    let e = ev("# attach: spawn");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "ATTACH");
    assert_eq!(e.meta.get("attach").and_then(Value::as_str), Some("spawn"));
    assert_eq!(e.text.as_deref(), Some("spawn"));
}

#[test]
fn grammar_open_dev_and_thread() {
    let e = ev(r#"[+1.200000s] J2534 open name="Scanmatik - SM2 USB" vendor="Scanmatik" dll="smj2534.dll" dev=1 rc=0 th=8120"#);
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.api, "J2534 open");
    assert_eq!(
        e.meta.get("device").and_then(Value::as_str),
        Some("Scanmatik - SM2 USB")
    );
    assert_eq!(e.meta.get("vendor").and_then(Value::as_str), Some("Scanmatik"));
    assert_eq!(e.meta.get("dll").and_then(Value::as_str), Some("smj2534.dll"));
    assert_eq!(e.meta.get("dev").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.rc, Some(0));
}

#[test]
fn grammar_connect_enter_and_connect_gen() {
    // Вход Connect пишется до вызова (docs/11 §3).
    let e = ev("[+31.850000s] J2534 connect-enter dev=1 proto=0x8003 flags=0x0 baud=250000 th=8120");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.api, "J2534 connect-enter");
    assert_eq!(e.meta.get("device").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("protocol").and_then(Value::as_str), Some("0x8003"));
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("baud").and_then(Value::as_str), Some("250000"));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));

    // Выход Connect: + gen / th / dur (gen растёт после успешного connect).
    let e = ev("[+31.907431s] J2534 connect dev=1 ch=1 proto=0x8003 flags=0x0 baud=250000 rc=0 gen=1 th=8120 dur=57431");
    assert_eq!(e.api, "J2534 connect");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("device").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("gen").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(57431));
    assert_eq!(e.rc, Some(0));
    assert_eq!(e.meta.get("rc").and_then(Value::as_i64), Some(0));
    assert_eq!(e.text.as_deref(), Some("connect proto=0x8003 ch=1"));
}

#[test]
fn grammar_call_line() {
    let e = ev("[+32.100000s] J2534 call ch=1 call=1247 op=ReadMsgs n_in=10 n_out=3 rc=0 th=8120 dur=20134");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.transport, Transport::J2534);
    assert_eq!(e.api, "J2534 call");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(1247));
    assert_eq!(e.meta.get("op").and_then(Value::as_str), Some("ReadMsgs"));
    assert_eq!(e.meta.get("n_in").and_then(Value::as_i64), Some(10));
    assert_eq!(e.meta.get("n_out").and_then(Value::as_i64), Some(3));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(20134));
    assert_eq!(e.rc, Some(0));
    assert!(e.text.as_deref().unwrap().contains("ReadMsgs"));

    // Ошибка вызова приходит hex-кодом: `rc=0x11`.
    let e = ev("[+33.000000s] J2534 call ch=1 call=1248 op=ReadMsgs n_in=10 n_out=0 rc=0x11 th=8120 dur=20001");
    assert_eq!(e.meta.get("n_out").and_then(Value::as_i64), Some(0));
    assert_eq!(e.rc, Some(0x11));
    assert_eq!(e.meta.get("rc").and_then(Value::as_i64), Some(0x11));

    let e = ev("[+33.100000s] J2534 call ch=1 call=1249 op=WriteMsgs n_in=5 n_out=2 rc=0 th=8120 dur=812");
    assert_eq!(e.meta.get("op").and_then(Value::as_str), Some("WriteMsgs"));
    assert_eq!(e.meta.get("n_in").and_then(Value::as_i64), Some(5));
    assert_eq!(e.meta.get("n_out").and_then(Value::as_i64), Some(2));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(812));
}

#[test]
fn grammar_tx_rx_single_message_fields() {
    let e = ev("[+32.100000s] J2534 RX ch=1 call=1247 i=1/1 n_in=10 n_out=1 th=8120 ts=0 rxs=0x0 proto=ISO15765 id=0x7E8 svc=0x50 len=8 dur=20134 rc=0 : 06 50 03 00 00 00 00 00");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.direction, Some(Direction::Rx));
    assert_eq!(e.api, "J2534 RX");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(1247));
    assert_eq!(e.meta.get("i").and_then(Value::as_str), Some("1/1"));
    assert_eq!(e.meta.get("n_in").and_then(Value::as_i64), Some(10));
    assert_eq!(e.meta.get("n_out").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("ts").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(20134));
    assert_eq!(e.meta.get("rxs").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("can_id").and_then(Value::as_str), Some("0x7E8"));
    assert_eq!(e.meta.get("svc").and_then(Value::as_str), Some("0x50"));
    assert!(e.meta.get("sof").is_none(), "обычный кадр не SOF");
    assert_eq!(e.len, 8);
    assert_eq!(e.payload()[0..3], [0x06, 0x50, 0x03]);
    assert_eq!(e.text.as_deref(), Some("ISO15765 0x7E8"));

    let e = ev("[+32.000000s] J2534 TX ch=1 call=1246 i=1/1 n_in=1 n_out=1 th=8120 ts=0 flags=0x0 proto=0x8003 svc=0x27 len=4 dur=812 rc=0 : 00 02 27 7f");
    assert_eq!(e.kind, EventKind::Tx);
    assert_eq!(e.direction, Some(Direction::Tx));
    assert_eq!(e.api, "J2534 TX");
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(1246));
    assert_eq!(e.meta.get("n_out").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(812));
    assert_eq!(e.len, 4);
    assert_eq!(e.payload(), vec![0x00, 0x02, 0x27, 0x7f]);

    // `ts=` присутствует всегда, включая нулевой; лишний неизвестный ключ не мешает.
    let e = ev("[+2.100s] J2534 TX ch=1 proto=ISO15765 id=0x7E0 extra_key=7 len=2 : 01 3e");
    assert_eq!(e.meta.get("ts"), None);
    assert_eq!(e.len, 2);
    assert_eq!(e.payload(), vec![0x01, 0x3e]);
}

#[test]
fn grammar_sof_frame_and_multi_message_call() {
    // Несколько сообщений: общие поля — на строке вызова, на сообщениях `call` и `i`.
    let call = ev("[+32.100000s] J2534 call ch=1 call=1247 op=ReadMsgs n_in=10 n_out=2 rc=0 th=8120 dur=20134");
    assert_eq!(call.api, "J2534 call");
    assert_eq!(call.meta.get("n_out").and_then(Value::as_i64), Some(2));

    // SOF-кадр: rxs=0x2 START_OF_MESSAGE, DataSize=0, без секции `: hex`.
    let e = ev("[+32.100000s] J2534 RX ch=1 call=1247 i=1/2 ts=0 rxs=0x2 proto=0x8003 sof=1 len=0");
    assert_eq!(e.kind, EventKind::Rx);
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(1247));
    assert_eq!(e.meta.get("i").and_then(Value::as_str), Some("1/2"));
    assert_eq!(e.meta.get("sof").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("rxs").and_then(Value::as_str), Some("0x2"));
    assert_eq!(e.len, 0);
    assert!(e.payload().is_empty());

    let e = ev("[+32.100010s] J2534 RX ch=1 call=1247 i=2/2 ts=0 rxs=0x0 proto=0x8003 svc=0x50 len=5 : 00 03 67 7f 34");
    assert_eq!(e.meta.get("i").and_then(Value::as_str), Some("2/2"));
    assert!(e.meta.get("sof").is_none());
    assert_eq!(e.len, 5);
    assert_eq!(e.payload(), vec![0x00, 0x03, 0x67, 0x7f, 0x34]);
}

#[test]
fn grammar_ioctl_fast_init_and_raw_forms() {
    // FAST_INIT: оба указателя — PASSTHRU_MSG, `in=`/`out=` — Data[DataSize].
    let e = ev("[+31.900000s] J2534 ioctl ch=1 call=88 id=0x0005 (FAST_INIT) rc=0 th=8120 dur=1520 in_proto=0x8003 in_rxs=0x0 in_flags=0x0 in_ts=0 in_edi=0 in_size=6 in=0002277f out_proto=0x8003 out_rxs=0x0 out_flags=0x0 out_ts=0 out_edi=0 out_size=3 out=0003677f34");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "J2534 ioctl");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("ioctl_id").and_then(Value::as_str), Some("0x0005"));
    assert_eq!(e.meta.get("ioctl_name").and_then(Value::as_str), Some("FAST_INIT"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(88));
    assert_eq!(e.meta.get("in").and_then(Value::as_str), Some("0002277f"));
    assert_eq!(e.meta.get("out").and_then(Value::as_str), Some("0003677f34"));
    assert_eq!(e.meta.get("in_size").and_then(Value::as_i64), Some(6));
    assert_eq!(e.meta.get("out_size").and_then(Value::as_i64), Some(3));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(1520));
    assert_eq!(e.rc, Some(0));
    assert_eq!(e.text.as_deref(), Some("ioctl 0x0005 ch=1"));

    // Только выход: READ_VBATT.
    let e = ev("[+31.910000s] J2534 ioctl ch=1 call=89 id=0x0003 (READ_VBATT) rc=0 th=8120 dur=300 out=00000c1a");
    assert_eq!(e.meta.get("ioctl_name").and_then(Value::as_str), Some("READ_VBATT"));
    assert_eq!(e.meta.get("out").and_then(Value::as_str), Some("00000c1a"));
    assert!(e.meta.get("in").is_none());

    // Только вход: SET_CONFIG.
    let e = ev("[+31.920000s] J2534 ioctl ch=1 call=90 id=0x0002 (SET_CONFIG) rc=0 th=8120 dur=200 in=0c000000f4010000");
    assert_eq!(e.meta.get("ioctl_name").and_then(Value::as_str), Some("SET_CONFIG"));
    assert_eq!(e.meta.get("in").and_then(Value::as_str), Some("0c000000f4010000"));
    assert!(e.meta.get("out").is_none());

    // Неизвестный id: содержимое не читается, видны только указатели и dec=0.
    let e = ev("[+31.930000s] J2534 ioctl ch=1 call=91 id=0x0123 rc=0 th=8120 dur=100 in_ptr=1 out_ptr=0 dec=0");
    assert_eq!(e.meta.get("in_ptr").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("out_ptr").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("dec").and_then(Value::as_i64), Some(0));
    assert!(e.meta.get("ioctl_name").is_none());
    assert!(e.meta.get("in").is_none());
    assert!(e.meta.get("out").is_none());

    // Выход недоступен/невалиден: `out=none` + причина, а не hex.
    let e = ev("[+31.940000s] J2534 ioctl ch=1 call=92 id=0x0005 (FAST_INIT) rc=0 th=8120 dur=120 in_ptr=1 out_ptr=1 out=none reason=len_invalid dec=1 len_invalid=1 in_size=4130");
    assert_eq!(e.meta.get("out").and_then(Value::as_str), Some("none"));
    assert_eq!(e.meta.get("reason").and_then(Value::as_str), Some("len_invalid"));
    assert_eq!(e.meta.get("len_invalid").and_then(Value::as_i64), Some(1));
    assert_eq!(e.meta.get("in_size").and_then(Value::as_i64), Some(4130));
}

#[test]
fn grammar_filter_and_periodic() {
    let e = ev("[+31.800000s] J2534 filter ch=1 call=90 type=0x0001 (PASS_FILTER) rc=0 th=8120 dur=410 mask=ffffffff pattern=000007e0 flow=- mask_proto=0x8003 mask_flags=0x0 pattern_proto=0x8003 pattern_flags=0x0 proto=ISO15765 flags=0x0 id=0x1");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "J2534 filter");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(90));
    assert_eq!(e.meta.get("filter_type").and_then(Value::as_str), Some("0x0001"));
    assert_eq!(e.meta.get("mask").and_then(Value::as_str), Some("ffffffff"));
    assert_eq!(e.meta.get("pattern").and_then(Value::as_str), Some("000007e0"));
    assert_eq!(e.meta.get("flow").and_then(Value::as_str), Some("-"));
    assert_eq!(e.meta.get("mask_proto").and_then(Value::as_str), Some("0x8003"));
    assert_eq!(e.meta.get("mask_flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("pattern_proto").and_then(Value::as_str), Some("0x8003"));
    assert_eq!(e.meta.get("pattern_flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("proto").and_then(Value::as_str), Some("ISO15765"));
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("filter_id").and_then(Value::as_str), Some("0x1"));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(410));
    assert_eq!(e.rc, Some(0));

    let e = ev("[+31.810000s] J2534 filter-stop ch=1 call=91 id=0x1 rc=0 th=8120 dur=90");
    assert_eq!(e.api, "J2534 filter-stop");
    assert_eq!(e.meta.get("filter_id").and_then(Value::as_str), Some("0x1"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(91));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(90));
    assert_eq!(e.rc, Some(0));

    let e = ev("[+31.820000s] J2534 periodic-start ch=1 call=92 id=0x1 ms=1000 proto=0x8003 flags=0x0 len=8 rc=0 th=8120 dur=140 : 00 06 3e 00 00 00 00 00");
    assert_eq!(e.api, "J2534 periodic-start");
    assert_eq!(e.meta.get("filter_id").and_then(Value::as_str), Some("0x1"));
    assert_eq!(e.meta.get("interval").and_then(Value::as_i64), Some(1000));
    assert_eq!(e.meta.get("protocol").and_then(Value::as_str), Some("0x8003"));
    assert_eq!(e.meta.get("flags").and_then(Value::as_str), Some("0x0"));
    assert_eq!(e.meta.get("dur").and_then(Value::as_i64), Some(140));
    assert_eq!(e.len, 8);
    assert_eq!(e.payload()[0..3], [0x00, 0x06, 0x3e]);

    let e = ev("[+31.830000s] J2534 periodic-stop ch=1 call=93 id=0x1 rc=0 th=8120 dur=60");
    assert_eq!(e.api, "J2534 periodic-stop");
    assert_eq!(e.meta.get("filter_id").and_then(Value::as_str), Some("0x1"));
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(93));
    assert_eq!(e.rc, Some(0));
}

#[test]
fn grammar_file_read_descriptor_form() {
    // Новый формат без пути (docs/11 §8).
    let e = ev("[+5.000000s] FILE read h=0xe10 off=0x1F0000 len=0x1000 total=0x400000");
    assert_eq!(e.kind, EventKind::File);
    assert_eq!(e.transport, Transport::File);
    assert_eq!(e.api, "FILE read");
    assert_eq!(e.meta.get("handle").and_then(Value::as_str), Some("0xe10"));
    assert_eq!(e.meta.get("offset").and_then(Value::as_i64), Some(0x1F0000));
    assert_eq!(e.meta.get("len").and_then(Value::as_i64), Some(0x1000));
    assert_eq!(e.meta.get("total").and_then(Value::as_i64), Some(0x400000));
    assert_eq!(e.len, 0x1000);
    assert!(e.meta.get("path").is_none(), "у строки h=… пути нет");
    assert!(e.text.as_deref().unwrap().contains("h=0xe10"));

    // Старая форма с путём обязана читаться по-прежнему.
    let e = ev(r"[+1.000000s] FILE read C:\tmp\tune.bin offset=0 n=4096 len=4096");
    assert_eq!(e.api, "FILE read");
    assert_eq!(e.text.as_deref(), Some(r"C:\tmp\tune.bin"));
    assert_eq!(e.meta.get("path").and_then(Value::as_str), Some(r"C:\tmp\tune.bin"));
    assert_eq!(e.meta.get("n").and_then(Value::as_u64), Some(4096));
    assert_eq!(e.meta.get("offset").and_then(Value::as_i64), Some(0));
    assert_eq!(e.meta.get("len").and_then(Value::as_i64), Some(4096));
    assert_eq!(e.len, 4096);

    // `handle=` — старое имя того же ключа.
    let e = ev("[+1.100000s] FILE read handle=0x1a4 off=0 len=16 total=65536");
    assert_eq!(e.meta.get("handle").and_then(Value::as_str), Some("0x1a4"));
    assert_eq!(e.meta.get("total").and_then(Value::as_i64), Some(65536));
}

#[test]
fn grammar_channel_diag_and_loss_stats() {
    // Рассинхронизация канала.
    let e = ev("[+31.907500s] J2534 chan-miss ch=1 gen=2 first_op=filter th=8120");
    assert_eq!(e.kind, EventKind::Error);
    assert_eq!(e.api, "J2534 chan-miss");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("gen").and_then(Value::as_i64), Some(2));
    assert_eq!(e.meta.get("first_op").and_then(Value::as_str), Some("filter"));
    assert_eq!(e.meta.get("thread").and_then(Value::as_i64), Some(8120));

    let e = ev("[+40.000000s] J2534 chan-possibly-open ch=1 gen=2 reason=resume");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "J2534 chan-possibly-open");
    assert_eq!(e.meta.get("gen").and_then(Value::as_i64), Some(2));
    assert_eq!(e.meta.get("reason").and_then(Value::as_str), Some("resume"));

    // SOF в компактном режиме — только счётчик.
    let e = ev("[+41.000000s] J2534 rx-sof-stat ch=1 n=33777");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "J2534 rx-sof-stat");
    assert_eq!(e.meta.get("n").and_then(Value::as_i64), Some(33777));

    // Агрегаты пустых опросов и ошибок записи (docs/11 §11).
    let e = ev("[+33.000000s] J2534 rx-empty ch=1 call=1248 n=10 timeout_ms=20000 last_rc=0x11");
    assert_eq!(e.kind, EventKind::Error);
    assert_eq!(e.api, "J2534 rx-empty");
    assert_eq!(e.meta.get("call").and_then(Value::as_i64), Some(1248));
    assert_eq!(e.meta.get("n").and_then(Value::as_i64), Some(10));
    assert_eq!(e.meta.get("timeout_ms").and_then(Value::as_i64), Some(20000));
    assert_eq!(e.meta.get("last_rc").and_then(Value::as_i64), Some(0x11));
    assert_eq!(e.rc, Some(0x11));

    let e = ev("[+33.100000s] J2534 tx-err-stat ch=1 call=1249 n=5 timeout_ms=20000 last_rc=0x10");
    assert_eq!(e.kind, EventKind::Error);
    assert_eq!(e.api, "J2534 tx-err-stat");
    assert_eq!(e.meta.get("n").and_then(Value::as_i64), Some(5));
    assert_eq!(e.meta.get("last_rc").and_then(Value::as_i64), Some(0x10));
}

#[test]
fn grammar_unknown_operation_and_keys_do_not_break() {
    let e = ev("[+9.000000s] J2534 weird-op ch=1 foo=42 bar=baz");
    assert_eq!(e.kind, EventKind::Sys);
    assert_eq!(e.api, "J2534 weird-op");
    assert_eq!(e.meta.get("channel").and_then(Value::as_str), Some("1"));
    assert_eq!(e.meta.get("foo").and_then(Value::as_i64), Some(42));
    assert_eq!(e.meta.get("bar").and_then(Value::as_str), Some("baz"));
    assert!(e.text.as_deref().unwrap().contains("foo=42"));
}
