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
    assert_eq!(
        summary.cmd_hist.get("ISO15765 0x7E0"),
        Some(&2),
        "команды J2534 по can_id"
    );
    assert_eq!(
        summary.resp_hist.get("ISO15765 0x7E8"),
        Some(&2),
        "ответы J2534 по can_id"
    );
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
    assert_eq!(summary.cmd_hist.get("ISO15765 0x7E0"), Some(&1));
    assert_eq!(summary.resp_hist.get("A0"), Some(&1));
    assert_eq!(summary.resp_hist.get("ISO15765 0x7E8"), Some(&1));
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
