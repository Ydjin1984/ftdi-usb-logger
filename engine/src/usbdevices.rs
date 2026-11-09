//! Перечисление USB-устройств и проверка наличия USBPcap. Владелец: boba.
//!
//! Источники:
//!  * SetupAPI (`SetupDiGetClassDevs` с `GUID_DEVINTERFACE_USB_DEVICE`) — «живые» устройства;
//!  * реестр `HKLM\SYSTEM\CurrentControlSet\Enum\USB` — серийники/описания/сервис/COM-порт;
//!  * `USBPcapCMD.exe` + драйвер USBPcap — возможность сырого захвата USB-шины.
//!
//! SetupAPI-функции объявлены extern-блоком (а не фичами windows-крейта), чтобы не менять
//! общий `Cargo.toml`. Ни одна функция не паникует: максимум пустой список/false.

use crate::models::UsbDevice;

#[cfg(windows)]
use windows::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE};

// ─────────────────────────────── публичный API ───────────────────────────

/// Список USB-устройств: сначала присутствующие, затем отсутствующие (история PnP).
///
/// Без паники при отсутствии прав/устройств — вернёт то, что удалось прочитать.
pub fn list_usb_devices() -> Vec<UsbDevice> {
    #[cfg(windows)]
    {
        let present_paths = setupapi_present_paths();
        let mut devices = registry_usb_devices(&present_paths);
        append_present_only(&present_paths, &mut devices);
        // Сначала подключённые, потом по описанию/имени (детерминированно).
        devices.sort_by(|a, b| {
            b.present
                .cmp(&a.present)
                .then_with(|| {
                    a.description
                        .to_lowercase()
                        .cmp(&b.description.to_lowercase())
                })
                .then_with(|| a.id.cmp(&b.id))
        });
        devices
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Установлен ли USBPcap (драйвер + `USBPcapCMD.exe`) — нужен для сырого захвата шины.
pub fn usbpcap_available() -> bool {
    #[cfg(windows)]
    {
        find_usbpcap_cmd().is_some() && (service_exists("USBPcap") || driver_file_present())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Имена устройств USBPcap (`\\.\USBPcap1`, …) для выбора в UI.
///
/// Пробуем открыть `\\.\USBPcapN`; `ACCESS_DENIED` тоже означает, что устройство есть.
pub fn usbpcap_devices() -> Vec<String> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        let mut misses = 0u32;
        for index in 1..=32 {
            let path = format!(r"\\.\USBPcap{index}");
            match std::fs::OpenOptions::new().read(true).open(&path) {
                Ok(file) => {
                    drop(file);
                    out.push(path);
                    misses = 0;
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    // Драйвер есть, но нужны права администратора — устройство существует.
                    out.push(path);
                    misses = 0;
                }
                Err(_) => {
                    misses += 1;
                    // После двух подряд отсутствующих номеров дальше искать бессмысленно.
                    if misses >= 2 {
                        break;
                    }
                }
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ───────────────────────── реестр Enum\USB ───────────────────────────────

#[cfg(windows)]
struct DeviceRow {
    device: UsbDevice,
    /// Имя ключа-экземпляра (серийник или `5&…&0&1`) — для сопоставления с SetupAPI.
    instance: String,
}

/// Данные дочернего интерфейса (COM-порт, FriendlyName) для привязки по `ContainerID`.
#[cfg(windows)]
#[derive(Clone, Default)]
struct InterfaceLink {
    com_port: Option<u32>,
    friendly_name: String,
    interface_name: Option<String>,
}

#[cfg(windows)]
fn registry_usb_devices(present_paths: &[String]) -> Vec<UsbDevice> {
    let root = HKEY_LOCAL_MACHINE;
    let base = r"SYSTEM\CurrentControlSet\Enum\USB";
    // COM-порт/FriendlyName живут на дочернем интерфейсе (MI_00 у составных, VCP-узел
    // FTDIBUS у FTDI). Связываем их с базовым устройством по общему ContainerID.
    let links = interface_links();
    let families = registry_enum_subkeys(root, base);
    let mut rows: Vec<DeviceRow> = Vec::new();

    for family in &families {
        let upper = family.to_ascii_uppercase();
        if !upper.contains("VID_") || !upper.contains("PID_") {
            continue; // ROOT_HUB30 и прочие не-устройства
        }
        // Интерфейсы (&MI_xx) не отдельные устройства: их данные придут через ContainerID.
        if upper.contains("&MI_") {
            continue;
        }
        let (Some(vid), Some(pid)) = parse_vid_pid(&upper) else {
            continue;
        };
        let family_path = format!(r"{base}\{family}");
        let mut instances = registry_enum_subkeys(root, &family_path);
        if instances.is_empty() {
            instances.push(String::new());
        }
        for instance in instances {
            let inst_path = if instance.is_empty() {
                family_path.clone()
            } else {
                format!(r"{family_path}\{instance}")
            };
            let description = clean_inf_string(
                &registry_read_string(root, &inst_path, "DeviceDesc").unwrap_or_default(),
            );
            let friendly_name = clean_inf_string(
                &registry_read_string(root, &inst_path, "FriendlyName").unwrap_or_default(),
            );
            let manufacturer = clean_inf_string(
                &registry_read_string(root, &inst_path, "Mfg").unwrap_or_default(),
            );
            let service = registry_read_string(root, &inst_path, "Service").unwrap_or_default();
            let class_name =
                registry_read_string(root, &inst_path, "Class").unwrap_or_default();
            let mut com_port = registry_port_name(root, &inst_path)
                .or_else(|| child_port_names(root, &inst_path).into_iter().next());
            let serial = instance_serial(&instance);
            let container = registry_container_id(root, &inst_path);
            let mut friendly_name = friendly_name;
            let mut interfaces: Vec<String> = Vec::new();
            if let Some(link) = links.get(&container) {
                if com_port.is_none() {
                    com_port = link.com_port;
                }
                if friendly_name.is_empty() && !link.friendly_name.is_empty() {
                    friendly_name = link.friendly_name.clone();
                }
                if let Some(name) = &link.interface_name {
                    interfaces.push(name.clone());
                }
            }

            let id = format!(
                r"USB\VID_{vid:04X}&PID_{pid:04X}\{}",
                if instance.is_empty() { "?" } else { &instance }
            );
            let device = UsbDevice {
                id,
                vid: Some(vid),
                pid: Some(pid),
                serial,
                description: if !friendly_name.is_empty() {
                    friendly_name.clone()
                } else {
                    description
                },
                manufacturer,
                friendly_name,
                service: service.clone(),
                class_name: class_name.clone(),
                com_port,
                present: false, // проставим ниже по SetupAPI
                interfaces: interfaces.clone(),
                kind: classify_usb_kind(vid, &service, &class_name, !interfaces.is_empty())
                    .to_string(),
            };
            rows.push(DeviceRow {
                device,
                instance: if instance.is_empty() {
                    family.clone()
                } else {
                    instance
                },
            });
        }
    }

    let mut devices = Vec::with_capacity(rows.len());
    for row in rows {
        let mut device = row.device;
        device.present = is_present(&row.instance, device.vid, device.pid, &device.serial, present_paths);
        devices.push(device);
    }
    devices
}

/// Карта `ContainerID → {COM-порт, FriendlyName, MI_xx}` по дочерним интерфейсам.
///
/// Источники: `Enum\USB\...&MI_xx\...` (составные устройства: usbser/CDC) и
/// `Enum\FTDIBUS\VID_…+PID_…+<parent-instance>\0000` (FTDI VCP: `USB Serial Port (COM1)`).
#[cfg(windows)]
fn interface_links() -> std::collections::HashMap<String, InterfaceLink> {
    let root = HKEY_LOCAL_MACHINE;
    let mut map: std::collections::HashMap<String, InterfaceLink> =
        std::collections::HashMap::new();

    // 1) Составные интерфейсы в Enum\USB (VID_xxxx&PID_xxxx&MI_xx).
    for family in registry_enum_subkeys(root, r"SYSTEM\CurrentControlSet\Enum\USB") {
        let upper = family.to_ascii_uppercase();
        if !upper.contains("&MI_") {
            continue;
        }
        let mi = upper
            .rsplit("&MI_")
            .next()
            .unwrap_or("00")
            .chars()
            .take(2)
            .collect::<String>();
        let family_path = format!(r"SYSTEM\CurrentControlSet\Enum\USB\{family}");
        let mut instances = registry_enum_subkeys(root, &family_path);
        if instances.is_empty() {
            instances.push(String::new());
        }
        for instance in instances {
            let path = if instance.is_empty() {
                family_path.clone()
            } else {
                format!(r"{family_path}\{instance}")
            };
            merge_interface_link(root, &path, Some(format!("MI_{mi}")), &mut map);
        }
    }

    // 2) FTDI VCP: Enum\FTDIBUS\<VID+PID+parent-instance>\<child> c FriendlyName/PortName.
    for family in registry_enum_subkeys(root, r"SYSTEM\CurrentControlSet\Enum\FTDIBUS") {
        let family_path = format!(r"SYSTEM\CurrentControlSet\Enum\FTDIBUS\{family}");
        let mut instances = registry_enum_subkeys(root, &family_path);
        if instances.is_empty() {
            instances.push(String::new());
        }
        for instance in instances {
            let path = if instance.is_empty() {
                family_path.clone()
            } else {
                format!(r"{family_path}\{instance}")
            };
            merge_interface_link(root, &path, None, &mut map);
        }
    }
    map
}

/// Добавить/дополнить запись по `ContainerID` данными одного узла-интерфейса.
#[cfg(windows)]
fn merge_interface_link(
    root: HKEY,
    path: &str,
    interface_name: Option<String>,
    map: &mut std::collections::HashMap<String, InterfaceLink>,
) {
    let container = registry_container_id(root, path);
    if container.is_empty() {
        return;
    }
    let entry = map.entry(container).or_default();
    if entry.com_port.is_none() {
        entry.com_port =
            registry_port_name(root, path).or_else(|| child_port_names(root, path).into_iter().next());
    }
    if entry.friendly_name.is_empty() {
        let friendly = clean_inf_string(
            &registry_read_string(root, path, "FriendlyName").unwrap_or_default(),
        );
        let desc = clean_inf_string(
            &registry_read_string(root, path, "DeviceDesc").unwrap_or_default(),
        );
        if !friendly.is_empty() {
            entry.friendly_name = friendly;
        } else if !desc.is_empty() {
            entry.friendly_name = desc;
        }
    }
    if entry.interface_name.is_none() {
        if let Some(name) = interface_name {
            entry.interface_name = Some(name);
        }
    }
}

/// `ContainerID` устройства (стабильный общий идентификатор родителя и интерфейсов).
#[cfg(windows)]
fn registry_container_id(root: HKEY, path: &str) -> String {
    registry_read_string(root, path, "ContainerID")
        .map(|value| value.trim().to_lowercase())
        .unwrap_or_default()
}

/// Добавить устройства, которые видны SetupAPI, но отсутствуют в реестре Enum\USB.
#[cfg(windows)]
fn append_present_only(present_paths: &[String], devices: &mut Vec<UsbDevice>) {
    for path in present_paths {
        let (vid, pid) = parse_vid_pid(&path.to_ascii_uppercase());
        let serial = serial_from_path(path);
        let known = devices.iter().any(|dev| {
            dev.vid == vid
                && dev.pid == pid
                && (dev.serial.is_empty()
                    || serial.is_empty()
                    || dev.serial.eq_ignore_ascii_case(&serial))
        });
        if known {
            continue;
        }
        let (Some(vid), Some(pid)) = (vid, pid) else {
            continue;
        };
        devices.push(UsbDevice {
            id: path.clone(),
            vid: Some(vid),
            pid: Some(pid),
            serial,
            description: format!("USB device {vid:04X}:{pid:04X}"),
            manufacturer: String::new(),
            friendly_name: String::new(),
            service: String::new(),
            class_name: String::new(),
            com_port: None,
            present: true,
            interfaces: Vec::new(),
            kind: classify_usb_kind(vid, "", "", false).to_string(),
        });
    }
}

/// `VID_0403&PID_6001` → (0x0403, 0x6001).
#[cfg(windows)]
fn parse_vid_pid(text: &str) -> (Option<u16>, Option<u16>) {
    let upper = text.to_ascii_uppercase();
    let vid = upper
        .find("VID_")
        .map(|pos| &upper[pos + 4..])
        .and_then(|tail| tail.get(..4))
        .and_then(|hex| u16::from_str_radix(hex, 16).ok());
    let pid = upper
        .find("PID_")
        .map(|pos| &upper[pos + 4..])
        .and_then(|tail| tail.get(..4))
        .and_then(|hex| u16::from_str_radix(hex, 16).ok());
    (vid, pid)
}

/// `5&115a75a8&0&1` → это не серийник (путь инстанса), а `A63UJ38H` — серийник.
#[cfg(windows)]
fn instance_serial(instance: &str) -> String {
    let trimmed = instance.trim();
    if trimmed.is_empty() || trimmed == "0" || trimmed.contains('&') {
        String::new()
    } else {
        trimmed.to_string()
    }
}

/// Серийник/инстанс из пути SetupAPI: `\\?\usb#vid_0403&pid_6001#A63UJ38H#{…}`.
#[cfg(windows)]
fn serial_from_path(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    // Отбрасываем `\\?\` и префикс-класс, делим по '#'.
    let body = lower.strip_prefix(r"\\?\").unwrap_or(&lower);
    let parts: Vec<&str> = body.split('#').collect();
    // parts[0]="usb", parts[1]="vid_…&pid_…", parts[2]=серийник/инстанс, parts[3]="{guid}"
    parts
        .get(2)
        .map(|part| part.trim_matches('{').trim_matches('}').to_string())
        .filter(|part| !part.is_empty() && part != "0" && !part.contains('&'))
        .unwrap_or_default()
}

/// Устройство присутствует сейчас: путь интерфейса SetupAPI содержит VID/PID и
/// серийник (или instance id, или `&mi_` для композита).
#[cfg(windows)]
fn is_present(
    instance: &str,
    vid: Option<u16>,
    pid: Option<u16>,
    serial: &str,
    present_paths: &[String],
) -> bool {
    let (Some(vid), Some(pid)) = (vid, pid) else {
        return false;
    };
    let vidpid = format!("vid_{vid:04x}&pid_{pid:04x}");
    let instance_l = instance.to_ascii_lowercase();
    present_paths.iter().any(|path| {
        if !path.contains(&vidpid) {
            return false;
        }
        if !serial.is_empty() && path.contains(&serial.to_ascii_lowercase()) {
            return true;
        }
        if !instance_l.is_empty() && path.contains(&instance_l) {
            return true;
        }
        // Композитное устройство: есть интерфейс этого VID/PID.
        path.contains(&format!("{vidpid}&mi_"))
    })
}

/// `kind`: ftdi | serial | hid | composite | usb.
#[cfg(windows)]
fn classify_usb_kind(vid: u16, service: &str, class_name: &str, has_interfaces: bool) -> &'static str {
    let service_l = service.to_ascii_lowercase();
    if vid == 0x0403 || service_l == "ftdibus" || service_l == "ftser2k" {
        return "ftdi";
    }
    if service_l == "usbser" || service_l == "usbser.sys" || class_name.eq_ignore_ascii_case("Ports") {
        return "serial";
    }
    if class_name.eq_ignore_ascii_case("HIDClass") || service_l == "hidusb" {
        return "hid";
    }
    if service_l == "usbccgp" || has_interfaces {
        return "composite";
    }
    "usb"
}

/// `@oem157.inf,%usb\vid_0403&pid_6001.devicedesc%;USB Serial Converter` → текст после `;`.
#[cfg(windows)]
fn clean_inf_string(raw: &str) -> String {
    match raw.rsplit_once(';') {
        Some((_, tail)) if !tail.trim().is_empty() => tail.trim().to_string(),
        _ => raw.trim().to_string(),
    }
}

/// `Device Parameters\PortName` → COM-номер (`COM6` → 6).
#[cfg(windows)]
fn registry_port_name(root: HKEY, instance_path: &str) -> Option<u32> {
    let path = format!(r"{instance_path}\Device Parameters");
    parse_com(&registry_read_string(root, &path, "PortName")?)
}

#[cfg(windows)]
fn parse_com(name: &str) -> Option<u32> {
    name.trim()
        .to_ascii_uppercase()
        .strip_prefix("COM")
        .and_then(|n| n.trim().parse::<u32>().ok())
}

/// COM-порт у дочерних подключей инстанса (`…\Device Parameters`, интерфейсы).
#[cfg(windows)]
fn child_port_names(root: HKEY, instance_path: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for child in registry_enum_subkeys(root, instance_path) {
        if let Some(com) = registry_port_name(root, &format!(r"{instance_path}\{child}")) {
            out.push(com);
        }
    }
    out
}

// ───────────────────────── SetupAPI (extern) ─────────────────────────────

#[cfg(windows)]
const DIGCF_PRESENT: u32 = 0x0000_0002;
#[cfg(windows)]
const DIGCF_DEVICEINTERFACE: u32 = 0x0000_0010;
#[cfg(windows)]
const ERROR_NO_MORE_ITEMS: i32 = 259;
#[cfg(windows)]
const INVALID_HANDLE_VALUE: isize = -1;

/// `GUID_DEVINTERFACE_USB_DEVICE` = {A5DCBF10-6530-11D2-901F-00C04FB951ED}.
#[cfg(windows)]
const GUID_DEVINTERFACE_USB_DEVICE: windows::core::GUID = windows::core::GUID {
    data1: 0xA5DC_BF10,
    data2: 0x6530,
    data3: 0x11D2,
    data4: [0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED],
};

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct SpDeviceInterfaceData {
    cb_size: u32,
    interface_class_guid: windows::core::GUID,
    flags: u32,
    reserved: usize,
}

#[cfg(windows)]
#[repr(C)]
#[allow(dead_code)]
struct SpDeviceInterfaceDetailData {
    cb_size: u32,
    device_path: [u16; 1],
}

#[cfg(windows)]
#[link(name = "setupapi")]
extern "system" {
    fn SetupDiGetClassDevsW(
        class_guid: *const windows::core::GUID,
        enumerator: *const u16,
        parent: isize,
        flags: u32,
    ) -> isize;
    fn SetupDiEnumDeviceInterfaces(
        device_info_set: isize,
        device_info_data: *const core::ffi::c_void,
        interface_class_guid: *const windows::core::GUID,
        member_index: u32,
        device_interface_data: *mut SpDeviceInterfaceData,
    ) -> i32;
    fn SetupDiGetDeviceInterfaceDetailW(
        device_info_set: isize,
        device_interface_data: *const SpDeviceInterfaceData,
        device_interface_detail_data: *mut SpDeviceInterfaceDetailData,
        device_interface_detail_data_size: u32,
        required_size: *mut u32,
        device_info_data: *mut core::ffi::c_void,
    ) -> i32;
    fn SetupDiDestroyDeviceInfoList(device_info_set: isize) -> i32;
}

/// Пути всех присутствующих USB-интерфейсов (lowercase) через SetupAPI.
///
/// Возвращает пустой список, если SetupAPI недоступен — реестр всё равно даст устройства.
#[cfg(windows)]
fn setupapi_present_paths() -> Vec<String> {
    let mut out = Vec::new();
    // SAFETY: классический SetupAPI-цикл; все буферы локальны и проверяются на размер,
    // дескриптор набора устройств закрывается в конце.
    unsafe {
        let dev_info = SetupDiGetClassDevsW(
            &GUID_DEVINTERFACE_USB_DEVICE,
            std::ptr::null(),
            0,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if dev_info == INVALID_HANDLE_VALUE || dev_info == 0 {
            return out;
        }
        let mut interface = SpDeviceInterfaceData {
            cb_size: std::mem::size_of::<SpDeviceInterfaceData>() as u32,
            interface_class_guid: windows::core::GUID::default(),
            flags: 0,
            reserved: 0,
        };
        let mut index = 0u32;
        loop {
            let ok = SetupDiEnumDeviceInterfaces(
                dev_info,
                std::ptr::null(),
                &GUID_DEVINTERFACE_USB_DEVICE,
                index,
                &mut interface,
            );
            if ok == 0 {
                // 259 = ERROR_NO_MORE_ITEMS — перечисление закончилось.
                let _ = ERROR_NO_MORE_ITEMS;
                break;
            }
            index += 1;
            if interface.cb_size as usize != std::mem::size_of::<SpDeviceInterfaceData>() {
                interface.cb_size = std::mem::size_of::<SpDeviceInterfaceData>() as u32;
            }
            // Буфер под detail: заголовок + путь до 2048 UTF-16 символов.
            let mut buffer = vec![0u8; std::mem::size_of::<SpDeviceInterfaceDetailData>() + 4096];
            let detail = buffer.as_mut_ptr() as *mut SpDeviceInterfaceDetailData;
            (*detail).cb_size = std::mem::size_of::<SpDeviceInterfaceDetailData>() as u32;
            let mut required = 0u32;
            let detail_ok = SetupDiGetDeviceInterfaceDetailW(
                dev_info,
                &interface,
                detail,
                buffer.len() as u32,
                &mut required,
                std::ptr::null_mut(),
            );
            if detail_ok == 0 {
                continue;
            }
            // Путь лежит сразу после cbSize (offset 4) как NUL-terminated UTF-16.
            let utf16 = std::slice::from_raw_parts(
                buffer.as_ptr().add(4) as *const u16,
                (buffer.len() - 4) / 2,
            );
            let len = utf16.iter().position(|&c| c == 0).unwrap_or(utf16.len());
            if len > 0 {
                let path = String::from_utf16_lossy(&utf16[..len]);
                if !path.is_empty() {
                    out.push(path.to_ascii_lowercase());
                }
            }
        }
        let _ = SetupDiDestroyDeviceInfoList(dev_info);
    }
    out
}

// ───────────────────────── USBPcap ───────────────────────────────────────

/// Найти `USBPcapCMD.exe`: PATH, затем стандартные каталоги установки.
#[cfg(windows)]
fn find_usbpcap_cmd() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("USBPcapCMD.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            roots.push(std::path::PathBuf::from(dir).join("USBPcap"));
        }
    }
    roots.push(std::path::PathBuf::from(r"C:\Program Files\USBPcap"));
    roots.push(std::path::PathBuf::from(r"C:\Program Files (x86)\USBPcap"));
    roots
        .into_iter()
        .map(|dir| dir.join("USBPcapCMD.exe"))
        .find(|candidate| candidate.is_file())
}

/// Есть ли служба/драйвер `HKLM\SYSTEM\CurrentControlSet\Services\USBPcap`.
#[cfg(windows)]
fn service_exists(name: &str) -> bool {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    let path = format!(r"SYSTEM\CurrentControlSet\Services\{name}");
    registry_key_exists(HKEY_LOCAL_MACHINE, &path)
}

/// Файл драйвера в System32\drivers (на случай, если служба удалена).
#[cfg(windows)]
fn driver_file_present() -> bool {
    let windir = std::env::var_os("WINDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    windir
        .join("System32")
        .join("drivers")
        .join("USBPcap.sys")
        .is_file()
}

// ───────────────────────── реестр: низкоуровневые хелперы ────────────────

#[cfg(windows)]
fn open_read_key(root: HKEY, path: &str) -> Option<HKEY> {
    use windows::Win32::System::Registry::{RegOpenKeyExW, KEY_READ, KEY_WOW64_64KEY};
    use windows::core::PCWSTR;

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: ключ только открывается на чтение; дескриптор закрывает вызывающий.
    unsafe {
        let mut hkey = HKEY(std::ptr::null_mut());
        let rc = RegOpenKeyExW(
            root,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        );
        if rc == windows::Win32::Foundation::ERROR_SUCCESS {
            Some(hkey)
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn registry_key_exists(root: HKEY, path: &str) -> bool {
    use windows::Win32::System::Registry::RegCloseKey;
    match open_read_key(root, path) {
        Some(key) => {
            let _ = unsafe { RegCloseKey(key) };
            true
        }
        None => false,
    }
}

#[cfg(windows)]
fn registry_enum_subkeys(root: HKEY, path: &str) -> Vec<String> {
    use windows::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW};
    use windows::core::PWSTR;

    let mut out = Vec::new();
    // SAFETY: только перечисление подключей; дескриптор закрывается.
    unsafe {
        let Some(key) = open_read_key(root, path) else {
            return out;
        };
        let mut index = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut len = name.len() as u32;
            let rc = RegEnumKeyExW(
                key,
                index,
                PWSTR(name.as_mut_ptr()),
                &mut len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            );
            if rc == windows::Win32::Foundation::ERROR_NO_MORE_ITEMS {
                break;
            }
            index += 1;
            if rc == windows::Win32::Foundation::ERROR_SUCCESS {
                out.push(String::from_utf16_lossy(&name[..len as usize]));
            }
        }
        let _ = RegCloseKey(key);
    }
    out
}

#[cfg(windows)]
fn registry_read_raw(root: HKEY, path: &str, name: &str) -> Option<(u32, Vec<u8>)> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegQueryValueExW, REG_VALUE_TYPE,
    };
    use windows::core::PCWSTR;

    let key = open_read_key(root, path)?;
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: чтение значения реестра; буферы локальны, ключ закрывается.
    unsafe {
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let rc = RegQueryValueExW(
            key,
            PCWSTR(wide_name.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        let value = if rc == ERROR_SUCCESS && size > 0 {
            let mut buf = vec![0u8; size as usize];
            let mut size2 = size;
            let rc2 = RegQueryValueExW(
                key,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr()),
                Some(&mut size2),
            );
            if rc2 == ERROR_SUCCESS {
                buf.truncate(size2 as usize);
                Some((kind.0, buf))
            } else {
                None
            }
        } else {
            None
        };
        let _ = RegCloseKey(key);
        value
    }
}

#[cfg(windows)]
fn registry_read_string(root: HKEY, path: &str, name: &str) -> Option<String> {
    let (kind, bytes) = registry_read_raw(root, path, name)?;
    // REG_SZ=1, REG_EXPAND_SZ=2
    if kind != 1 && kind != 2 {
        return None;
    }
    let text = utf16_from_bytes(&bytes);
    (!text.is_empty()).then_some(text)
}

#[cfg(windows)]
fn utf16_from_bytes(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16_lossy(&units).trim().to_string()
}

// ─────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ftdi_present(devices: &[UsbDevice]) -> bool {
        devices.iter().any(|dev| {
            dev.vid == Some(0x0403) || dev.kind == "ftdi"
        })
    }

    #[test]
    fn usb_enum_returns_devices_with_valid_fields() {
        let devices = list_usb_devices();
        eprintln!("USB-устройств: {}", devices.len());
        for dev in devices.iter().take(8) {
            eprintln!(
                "present={} kind={} vid={:?} pid={:?} com={:?} serial={:?} desc={:?} svc={:?}",
                dev.present, dev.kind, dev.vid, dev.pid, dev.com_port, dev.serial, dev.description,
                dev.service
            );
        }
        assert!(!devices.is_empty(), "на машине должны быть USB-устройства");
        assert!(
            devices
                .iter()
                .all(|dev| !dev.id.is_empty() && !dev.kind.is_empty()),
            "у устройства пустой id/kind"
        );
        assert!(
            devices.iter().any(|dev| dev.present),
            "ни одного присутствующего USB-устройства"
        );
        // На этой машине есть FTDI (VID 0403) — проверяем хотя бы при наличии.
        if devices.iter().any(|dev| dev.vid == Some(0x0403)) {
            assert!(ftdi_present(&devices));
            // FTDI «USB Serial Converter» (0000:6001) должен получить COM-порт и
            // FriendlyName от дочернего VCP-узла FTDIBUS («USB Serial Port (COM1)»).
            let ftdi_serial: Vec<&UsbDevice> = devices
                .iter()
                .filter(|dev| dev.vid == Some(0x0403) && dev.pid == Some(0x6001))
                .collect();
            if !ftdi_serial.is_empty() {
                eprintln!(
                    "FTDI serial: {:?}",
                    ftdi_serial
                        .iter()
                        .map(|dev| (&dev.id, dev.com_port, &dev.friendly_name))
                        .collect::<Vec<_>>()
                );
                assert!(
                    ftdi_serial.iter().any(|dev| dev.com_port.is_some()),
                    "у FTDI 0403:6001 не найден COM-порт дочернего интерфейса"
                );
                assert!(
                    ftdi_serial
                        .iter()
                        .any(|dev| dev.friendly_name.contains("USB Serial Port")),
                    "у FTDI 0403:6001 нет FriendlyName от VCP-узла"
                );
            }
        }
    }

    #[test]
    fn usb_present_devices_first() {
        let devices = list_usb_devices();
        let mut seen_absent = false;
        for dev in &devices {
            if !dev.present {
                seen_absent = true;
            } else {
                assert!(!seen_absent, "присутствующие устройства должны идти первыми");
            }
        }
    }

    #[test]
    fn usbpcap_probe_does_not_panic() {
        let available = usbpcap_available();
        let devices = usbpcap_devices();
        eprintln!("usbpcap_available={available} devices={devices:?}");
        if !available {
            assert!(devices.is_empty(), "USBPcap не установлен, но устройства нашлись");
        }
        // Наличие/отсутствие — свойство машины; главное, что без паники.
    }
}


