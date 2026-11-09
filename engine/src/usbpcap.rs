//! Сырой захват USB-шины через USBPcap (опционально).
//!
//! Зачем: хуки ловят FTDI/COM/WinUSB/HID/libusb/J2534 — но приложение может работать
//! с устройством через собственный драйвер, и тогда единственный универсальный способ —
//! снимать трафик на уровне USB-шины драйвером USBPcap.
//!
//! Модуль самодостаточен: разбор pcap-потока USBPcap (global header + packet records +
//! usbpcaphdr) и запуск `USBPcapCMD.exe` с выводом в stdout. Требует установленного
//! USBPcap и прав администратора; при отсутствии — `available()` = false.

use crate::models::Direction;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

pub const LINKTYPE_USBPCAP: u32 = 249;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Default)]
pub struct UsbPacket {
    /// Секунды с эпохи (из заголовка записи pcap).
    pub ts: f64,
    pub bus: u16,
    pub device: u16,
    pub endpoint: u8,
    /// 0=isochronous, 1=interrupt, 2=control, 3=bulk (для control 8 байт setup включены).
    pub transfer: u8,
    pub function: u16,
    pub info: u16,
    pub status: u32,
    pub irp_id: u64,
    pub data: Vec<u8>,
}

impl UsbPacket {
    pub fn transfer_name(&self) -> &'static str {
        transfer_name(self.transfer)
    }

    pub fn direction(&self) -> Direction {
        // endpoint bit 0x80 = IN (устройство -> хост); для control смотрим байт bmRequestType.
        if self.transfer == 2 && self.data.len() >= 8 {
            if self.data[0] & 0x80 != 0 {
                Direction::Rx
            } else {
                Direction::Tx
            }
        } else if self.endpoint & 0x80 != 0 {
            Direction::Rx
        } else {
            Direction::Tx
        }
    }

    /// Полезная нагрузка без 8-байтового setup-пакета control-транзакции.
    pub fn payload(&self) -> &[u8] {
        if self.transfer == 2 && self.data.len() >= 8 {
            &self.data[8..]
        } else {
            &self.data
        }
    }

    /// Строка в формате захвата: `[+0.000s] USBRAW bus=1 dev=4 ep=0x01 BULK fdo->pdo len=4 : 12 04 0d 1b`
    pub fn to_line(&self) -> String {
        let dir = match self.direction() {
            Direction::Tx => "fdo->pdo",
            Direction::Rx => "pdo->fdo",
        };
        let mut s = format!(
            "USBRAW bus={} dev={} ep=0x{:02x} {} {} func=0x{:x} status=0x{:x} len={}",
            self.bus,
            self.device,
            self.endpoint,
            self.transfer_name(),
            dir,
            self.function,
            self.status,
            self.payload().len()
        );
        if !self.payload().is_empty() {
            s.push_str(" : ");
            s.push_str(&crate::models::util::bytes_to_hex(&self.payload()[..self.payload().len().min(4096)]));
        }
        s
    }
}

pub fn transfer_name(t: u8) -> &'static str {
    match t {
        0 => "isochronous",
        1 => "interrupt",
        2 => "control",
        3 => "bulk",
        _ => "unknown",
    }
}

/// Разбор заголовка USBPcap (v1 = 27 байт, v2 = 28+ байт).
/// Возвращает (пакет без данных, длина заголовка).
pub fn parse_header(header: &[u8], endian: Endian) -> Option<(UsbPacket, usize)> {
    let rd16 = |b: &[u8], off: usize| -> Option<u16> {
        let s = b.get(off..off + 2)?;
        Some(match endian {
            Endian::Little => u16::from_le_bytes([s[0], s[1]]),
            Endian::Big => u16::from_be_bytes([s[0], s[1]]),
        })
    };
    let rd32 = |b: &[u8], off: usize| -> Option<u32> {
        let s = b.get(off..off + 4)?;
        Some(match endian {
            Endian::Little => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
            Endian::Big => u32::from_be_bytes([s[0], s[1], s[2], s[3]]),
        })
    };
    let rd64 = |b: &[u8], off: usize| -> Option<u64> {
        let s = b.get(off..off + 8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(s);
        Some(match endian {
            Endian::Little => u64::from_le_bytes(arr),
            Endian::Big => u64::from_be_bytes(arr),
        })
    };
    let header_len = rd16(header, 0)? as usize;
    if header_len < 27 || header_len > header.len() {
        return None;
    }
    let p = UsbPacket {
        irp_id: rd64(header, 2)?,
        status: rd32(header, 10)?,
        function: rd16(header, 14)?,
        info: rd16(header, 16)?,
        bus: rd16(header, 18)?,
        device: rd16(header, 20)?,
        endpoint: *header.get(22)?,
        transfer: *header.get(23)?,
        ..Default::default()
    };
    // Данные лежат сразу после header_len; dataLength из заголовка избыточен.
    Some((p, header_len))
}

/// Инкрементальный разбор pcap-потока USBPcap.
pub struct PcapParser {
    buf: Vec<u8>,
    endian: Option<Endian>,
    snaplen: u32,
    linktype: u32,
    broken: bool,
}

impl Default for PcapParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapParser {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            endian: None,
            snaplen: 0,
            linktype: 0,
            broken: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buf.len() < n {
            return None;
        }
        let out: Vec<u8> = self.buf.drain(..n).collect();
        Some(out)
    }

    fn parse_global(&mut self) -> Result<(), String> {
        let Some(hdr) = self.take(24) else {
            return Err("мало данных для pcap-заголовка".into());
        };
        let magic = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        self.endian = match magic {
            0xa1b2_c3d4 => Some(Endian::Little),
            0xd4c3_b2a1 => Some(Endian::Big),
            0xa1b2_3c4d | 0x4d3c_b2a1 => {
                return Err("pcapng не поддерживается (нужен classic pcap от USBPcapCMD)".into())
            }
            _ => return Err(format!("неизвестная сигнатура pcap: 0x{magic:08x}")),
        };
        let e = self.endian.unwrap();
        let rd32 = |off: usize| -> u32 {
            let s = [hdr[off], hdr[off + 1], hdr[off + 2], hdr[off + 3]];
            match e {
                Endian::Little => u32::from_le_bytes(s),
                Endian::Big => u32::from_be_bytes(s),
            }
        };
        let major = {
            let s = [hdr[4], hdr[5]];
            match e {
                Endian::Little => u16::from_le_bytes(s),
                Endian::Big => u16::from_be_bytes(s),
            }
        };
        if major != 2 {
            return Err(format!("неизвестная версия pcap: {major}"));
        }
        self.snaplen = rd32(16);
        self.linktype = rd32(20);
        if self.snaplen == 0 || self.snaplen > 16 * 1024 * 1024 {
            self.snaplen = 1024 * 1024;
        }
        Ok(())
    }

    /// Следующий USB-пакет; `None` — нужно больше данных.
    pub fn next_packet(&mut self) -> Option<Result<UsbPacket, String>> {
        if self.broken {
            return None;
        }
        if self.endian.is_none() {
            if let Err(e) = self.parse_global() {
                self.broken = true;
                return Some(Err(e));
            }
        }
        let e = self.endian.unwrap_or(Endian::Little);
        if self.buf.len() < 16 {
            return None;
        }
        let hdr: Vec<u8> = self.buf[..16].to_vec();
        let rd32 = |off: usize| -> u32 {
            let s = [hdr[off], hdr[off + 1], hdr[off + 2], hdr[off + 3]];
            match e {
                Endian::Little => u32::from_le_bytes(s),
                Endian::Big => u32::from_be_bytes(s),
            }
        };
        let ts_sec = rd32(0) as f64;
        let ts_usec = rd32(4) as f64;
        let incl_len = rd32(8) as usize;
        if incl_len > self.snaplen as usize || incl_len > 16 * 1024 * 1024 {
            self.broken = true;
            return Some(Err(format!("битая длина пакета: {incl_len}")));
        }
        if self.buf.len() < 16 + incl_len {
            return None;
        }
        let _ = self.take(16);
        let payload = self.take(incl_len)?;
        if self.linktype != LINKTYPE_USBPCAP && self.linktype != 220 {
            // Некоторые сборки пишут 220; содержимое всё равно USBPcap-формат — не отбрасываем,
            // но сообщаем один раз через ошибку-предупреждение невозможно, поэтому просто парсим.
        }
        let Some((mut pkt, header_len)) = parse_header(&payload, e) else {
            return Some(Err("не разобрать заголовок USBPcap".into()));
        };
        let data_len = payload.len().saturating_sub(header_len);
        pkt.data = payload[header_len..header_len + data_len].to_vec();
        pkt.ts = ts_sec + ts_usec / 1_000_000.0;
        Some(Ok(pkt))
    }
}

/// Путь к USBPcapCMD.exe (или None).
pub fn command_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("FTDI_LOGGER_USBPCAP_CMD") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let candidates = [
        r"C:\Program Files\USBPcap\USBPcapCMD.exe",
        r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
        r"C:\USBPcap\USBPcapCMD.exe",
    ];
    for c in candidates {
        let pb = PathBuf::from(c);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let pb = dir.join("USBPcapCMD.exe");
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    None
}

/// Запуск `USBPcapCMD -d <device> -o -` с бинарным pcap в stdout.
pub fn spawn(device: &str) -> std::io::Result<Child> {
    let cmd = command_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "USBPcapCMD.exe не найден (установите USBPcap: https://desowin.org/usbpcap/)",
        )
    })?;
    Command::new(cmd)
        .arg("-d")
        .arg(device)
        .arg("-o")
        .arg("-")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// Удобная обёртка: читать пакеты из stdout процесса.
pub fn read_packets(child: &mut Child, mut on_packet: impl FnMut(UsbPacket)) -> std::io::Result<()> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "нет stdout USBPcapCMD"))?;
    let mut reader = BufReader::new(stdout);
    let mut parser = PcapParser::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        parser.push(&chunk[..n]);
        while let Some(res) = parser.next_packet() {
            match res {
                Ok(p) => on_packet(p),
                Err(_) => break,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_header(endian: Endian, linktype: u32) -> Vec<u8> {
        let mut h = Vec::new();
        let magic: u32 = 0xa1b2_c3d4;
        let v: [u8; 4] = match endian {
            Endian::Little => magic.to_le_bytes(),
            Endian::Big => magic.to_be_bytes(),
        };
        h.extend_from_slice(&v);
        h.extend_from_slice(&2u16.to_le_bytes());
        h.extend_from_slice(&4u16.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&65535u32.to_le_bytes());
        h.extend_from_slice(&linktype.to_le_bytes());
        h
    }

    fn usbpcap_v2(bus: u16, dev: u16, ep: u8, transfer: u8, data: &[u8]) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&28u16.to_le_bytes()); // headerLen
        h.extend_from_slice(&0x1122_3344u64.to_le_bytes()); // irpId
        h.extend_from_slice(&0u32.to_le_bytes()); // status
        h.extend_from_slice(&0x9u16.to_le_bytes()); // function IRP_MJ_WRITE? произвольный
        h.extend_from_slice(&0u16.to_le_bytes()); // info
        h.extend_from_slice(&bus.to_le_bytes());
        h.extend_from_slice(&dev.to_le_bytes());
        h.push(ep);
        h.push(transfer);
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(data);
        h
    }

    fn record(ts: (u32, u32), payload: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&ts.0.to_le_bytes());
        r.extend_from_slice(&ts.1.to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        r.extend_from_slice(payload);
        r
    }

    #[test]
    fn parses_bulk_packet() {
        let mut parser = PcapParser::new();
        let data = [0x12u8, 0x04, 0x0d, 0x1b];
        let payload = usbpcap_v2(1, 4, 0x01, 3, &data);
        parser.push(&global_header(Endian::Little, LINKTYPE_USBPCAP));
        parser.push(&record((100, 250_000), &payload));
        let pkt = parser.next_packet().expect("нужен пакет").expect("пакет");
        assert_eq!(pkt.bus, 1);
        assert_eq!(pkt.device, 4);
        assert_eq!(pkt.endpoint, 0x01);
        assert!(pkt.ts > 100.0);
        assert_eq!(pkt.payload(), &data);
        assert_eq!(pkt.direction(), Direction::Tx);
        assert!(pkt.to_line().contains("USBRAW bus=1 dev=4"));
        assert!(pkt.to_line().contains("bulk"));
        assert!(pkt.to_line().contains("12 04 0d 1b"));
    }

    #[test]
    fn direction_from_endpoint() {
        let mut parser = PcapParser::new();
        parser.push(&global_header(Endian::Little, LINKTYPE_USBPCAP));
        parser.push(&record((1, 0), &usbpcap_v2(1, 2, 0x81, 3, &[0xa0])));
        let pkt = parser.next_packet().unwrap().unwrap();
        assert_eq!(pkt.direction(), Direction::Rx);
    }

    #[test]
    fn incomplete_stream_waits() {
        let mut parser = PcapParser::new();
        parser.push(&global_header(Endian::Little, LINKTYPE_USBPCAP));
        let payload = usbpcap_v2(1, 1, 0x01, 3, &[1, 2, 3, 4]);
        parser.push(&record((0, 0), &payload)[..10]);
        assert!(parser.next_packet().is_none());
    }

    #[test]
    fn bad_magic_errors_once() {
        let mut parser = PcapParser::new();
        parser.push(&[0u8; 24]);
        let res = parser.next_packet();
        assert!(matches!(res, Some(Err(_))));
        assert!(parser.next_packet().is_none());
    }

    #[test]
    fn control_setup_direction() {
        let mut parser = PcapParser::new();
        parser.push(&global_header(Endian::Little, LINKTYPE_USBPCAP));
        // setup: bmRequestType=0x80 (IN), bRequest=0x06
        let data = [0x80u8, 0x06, 0x00, 0x01, 0, 0, 0x12, 0];
        parser.push(&record((0, 0), &usbpcap_v2(1, 3, 0x00, 2, &data)));
        let pkt = parser.next_packet().unwrap().unwrap();
        assert_eq!(pkt.direction(), Direction::Rx);
        assert_eq!(pkt.payload().len(), 0);
    }
}



