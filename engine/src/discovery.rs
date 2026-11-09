//! Обнаружение FTDI-устройств (D2XX через libftd2xx, затем реестр). Владелец: boba.
//!
//! Два независимых источника:
//! * D2XX — `ftd2xx.dll` грузится лениво через `libloading`; если DLL нет (или она не
//!   отвечает), честно возвращаем пустой список и уходим в реестр;
//! * реестр — `HKLM\SYSTEM\CurrentControlSet\Enum\FTDIBUS` (VCP-шнурки, там же `PortName`),
//!   фолбэк — `Enum\USB` с `VID_0403` (устройство могло остаться только в USB-ветке).
//!
//! Правило: ни одна функция этого модуля не паникует на отсутствующих ресурсах —
//! максимум пустой `Vec`/`None`. Все вызовы Win32 обёрнуты в `unsafe` с комментариями.

use crate::models::FtdiDevice;
#[cfg(windows)]
use std::path::Path;

/// VID FTDI по определению семейства FTDI (в D2XX-структуре VID не отдаётся).
const FTDI_VID: u16 = 0x0403;

/// Список шнурков: D2XX — основной источник, реестр — фолбэк И дополнение.
///
/// Если D2XX ничего не видит (нет DLL / нет устройств) — отдаём только реестр.
/// Если видит — добавляем из реестра те устройства, которых нет в D2XX-списке (VCP-шнурки
/// видны только в реестре), сопоставляя по серийнику или COM-порту, чтобы не дублировать.
pub fn list_ftdi_devices() -> Vec<FtdiDevice> {
    let mut out = d2xx_devices();
    let reg = registry_devices();
    if out.is_empty() {
        out = reg;
    } else {
        for device in reg {
            // 1) тот же серийник — обогащаем D2XX-запись и не дублируем.
            if !device.serial.is_empty() {
                if let Some(existing) = out
                    .iter_mut()
                    .find(|d| !d.serial.is_empty() && d.serial.eq_ignore_ascii_case(&device.serial))
                {
                    if existing.com_port.is_none() {
                        existing.com_port = device.com_port;
                    }
                    if existing.vendor_id.is_none() {
                        existing.vendor_id = device.vendor_id;
                    }
                    if existing.product_id.is_none() {
                        existing.product_id = device.product_id;
                    }
                    continue;
                }
            }
            // 2) без серийника сопоставляем по COM-порту (и для дублей USB/FTDIBUS).
            if let Some(com) = device.com_port {
                if out.iter().any(|d| d.com_port == Some(com)) {
                    continue;
                }
            }
            out.push(device);
        }
    }
    out.iter_mut().enumerate().for_each(|(i, d)| d.index = i as u32);
    out
}

// ─────────────────────────────── D2XX (libloading) ───────────────────────

#[cfg(windows)]
fn d2xx_devices() -> Vec<FtdiDevice> {
    // SAFETY: библиотека грузится по фиксированным именам, символы проверяются по сигнатуре
    // FTDI D2XX API; указатели передаются только на локальные переменные, живущие дольше вызова.
    unsafe { d2xx_devices_inner() }
}

/// Загрузка первой доступной `ftd2xx*.dll`. Порядок: обыск по PATH → System32.
#[cfg(windows)]
fn load_ftd2xx() -> Option<libloading::Library> {
    fn try_load(name: &Path) -> Option<libloading::Library> {
        // SAFETY: имя — константный путь; произвольный код DLL исполняется только её
        // точками входа, которые мы вызываем ниже.
        unsafe { libloading::Library::new(name.as_os_str()).ok() }
    }

    for name in ["ftd2xx.dll", "ftd2xx64.dll"] {
        if let Some(lib) = try_load(Path::new(name)) {
            return Some(lib);
        }
    }
    if let Some(win) = std::env::var_os("WINDIR") {
        let system32 = Path::new(&win).join("System32");
        for name in ["ftd2xx.dll", "ftd2xx64.dll"] {
            let candidate = system32.join(name);
            if candidate.is_file() {
                if let Some(lib) = try_load(&candidate) {
                    return Some(lib);
                }
            }
        }
    }
    tracing::debug!("ftd2xx.dll не найдена — discovery уходит в реестр");
    None
}

#[cfg(windows)]
unsafe fn d2xx_devices_inner() -> Vec<FtdiDevice> {
    let lib = match load_ftd2xx() {
        Some(lib) => lib,
        None => return Vec::new(),
    };

    type FtCreateDeviceInfoList = unsafe extern "system" fn(*mut u32) -> u32;
    type FtGetDeviceInfoDetail = unsafe extern "system" fn(
        u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u32,
        *mut u8,
        *mut u8,
        *mut *mut core::ffi::c_void,
    ) -> u32;
    type FtGetComPortNumber =
        unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> u32;

    // SAFETY: сигнатуры соответствуют FTDI D2XX Programmer's Guide (FT_STATUS = u32).
    let create_list: libloading::Symbol<FtCreateDeviceInfoList> =
        match unsafe { lib.get(b"FT_CreateDeviceInfoList\0") } {
            Ok(sym) => sym,
            Err(_) => return Vec::new(),
        };
    let get_detail: libloading::Symbol<FtGetDeviceInfoDetail> =
        match unsafe { lib.get(b"FT_GetDeviceInfoDetail\0") } {
            Ok(sym) => sym,
            Err(_) => return Vec::new(),
        };
    // Необязательный символ: старые DLL могут его не экспортировать.
    let get_com_port: Option<libloading::Symbol<FtGetComPortNumber>> =
        unsafe { lib.get(b"FT_GetComPortNumber\0") }.ok();

    let mut count: u32 = 0;
    // SAFETY: count — валидный указатель на локальную переменную.
    if unsafe { create_list(&mut count) } != 0 {
        return Vec::new();
    }
    if count == 0 {
        return Vec::new();
    }
    // Защита от мусора в ответе: реальных шнурков не бывает тысячи.
    let count = count.min(1024);

    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        let mut flags: u32 = 0;
        let mut dev_type: u32 = 0;
        let mut id: u32 = 0;
        let mut loc_id: u32 = 0;
        let mut serial = [0u8; 16];
        let mut desc = [0u8; 64];
        let mut handle: *mut core::ffi::c_void = std::ptr::null_mut();

        // SAFETY: все out-указатели — на локальные буферы нужного D2XX размера.
        let status = unsafe {
            get_detail(
                index,
                &mut flags,
                &mut dev_type,
                &mut id,
                &mut loc_id,
                serial.as_mut_ptr(),
                desc.as_mut_ptr(),
                &mut handle,
            )
        };
        if status != 0 {
            continue;
        }

        // COM-номер отдаётся только для открытого хэндла; FT_GetDeviceInfoDetail обычно
        // возвращает 0, если устройство не открыто этим процессом. Поэтому дёргаем
        // функцию только на непустом хэндле — устройства не открываем и не сбрасываем.
        let mut com_port: Option<u32> = None;
        if !handle.is_null() {
            if let Some(get_com) = get_com_port.as_ref() {
                let mut port: i32 = -1;
                // SAFETY: handle получен от самой D2XX для этого индекса.
                let st = unsafe { get_com(handle, &mut port) };
                if st == 0 && port > 0 {
                    com_port = Some(port as u32);
                }
            }
        }

        let serial_text = c_buf_string(&serial);
        out.push(FtdiDevice {
            index,
            serial: serial_text,
            description: c_buf_string(&desc),
            flags,
            dev_type,
            vendor_id: Some(FTDI_VID),
            product_id: None,
            com_port,
            source: "d2xx".into(),
        });
    }
    out
}

#[cfg(not(windows))]
fn d2xx_devices() -> Vec<FtdiDevice> {
    Vec::new()
}

/// ASCII/UTF-8 C-буфер FTDI (`CHAR[16]` / `CHAR[64]`) → строка без хвостовых NUL/пробелов.
fn c_buf_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim_end().to_string()
}

// ─────────────────────────────── реестр FTDIBUS/USB ──────────────────────

/// Устройства из ветки реестра `Enum\FTDIBUS`, при пустоте — из `Enum\USB` (VID_0403).
pub fn registry_devices() -> Vec<FtdiDevice> {
    #[cfg(windows)]
    {
        let ftdibus = registry_from_branch(r"SYSTEM\CurrentControlSet\Enum\FTDIBUS", "FTDIBUS");
        if !ftdibus.is_empty() {
            return ftdibus;
        }
        registry_from_branch(r"SYSTEM\CurrentControlSet\Enum\USB", "USB")
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
fn registry_from_branch(path: &str, source: &str) -> Vec<FtdiDevice> {
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::Registry::{
        RegEnumKeyExW, HKEY_LOCAL_MACHINE,
    };
    use windows::core::PWSTR;

    let mut out = Vec::new();
    // SAFETY: ключ реестра только читается; дескриптор закрывается ниже.
    unsafe {
        let Some(hkey) = open_read_key(HKEY_LOCAL_MACHINE, path) else {
            return out;
        };

        // 1) перечисляем семейства устройств: VID_xxxx+PID_xxxx+[serial]
        let mut idx = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut len = name.len() as u32;
            let rc = RegEnumKeyExW(
                hkey,
                idx,
                PWSTR(name.as_mut_ptr()),
                &mut len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            );
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            idx += 1;
            if rc != windows::Win32::Foundation::ERROR_SUCCESS {
                continue;
            }
            let family = String::from_utf16_lossy(&name[..len as usize]);
            let family = family.trim_end_matches('\0');
            let (vid, pid, serial_hint) = parse_instance_family(family);
            // В USB-ветке берём только FTDI; FTDIBUS сам по себе всегда FTDI.
            if source == "USB" && vid != FTDI_VID {
                continue;
            }

            // 2) у семейства перечисляем экземпляры (обычно "0000", "0001", …)
            let family_key = format!(r"{}\{}", path, family);
            let mut instances = registry_enum_subkeys(&family_key);
            if instances.is_empty() {
                instances.push(String::new()); // ключ-экземпляр может совпадать с family
            }
            for instance in instances {
                let inst_path = if instance.is_empty() {
                    family_key.clone()
                } else {
                    format!(r"{}\{}", family_key, instance)
                };
                let mut serial = serial_hint.clone();
                if serial.is_empty() {
                    serial = instance.trim_start_matches('0').trim().to_string();
                }
                let friendly = registry_read_string_at(
                    windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                    &inst_path,
                    "FriendlyName",
                );
                let device_desc = registry_read_string_at(
                    windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                    &inst_path,
                    "DeviceDesc",
                );
                let description = friendly
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| device_desc.map(|s| clean_device_desc(&s)))
                    .unwrap_or_default();
                let com_port = registry_read_string_at(
                    windows::Win32::System::Registry::HKEY_LOCAL_MACHINE,
                    &format!(r"{}\Device Parameters", inst_path),
                    "PortName",
                )
                .and_then(|p| parse_com_number(&p));

                out.push(FtdiDevice {
                    index: out.len() as u32,
                    serial,
                    description,
                    flags: 0,
                    dev_type: 0,
                    vendor_id: Some(vid),
                    product_id: if pid == 0 { None } else { Some(pid) },
                    com_port,
                    // Контракт models::FtdiDevice: `d2xx` | `registry` (ветка не теряется —
                    // она видна в vendor/product и в описании устройства).
                    source: "registry".into(),
                });
            }
        }
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
    }

    // Фильтр мусора: реальному шнурку нужен VID FTDI (в ветке USB уже отфильтровано),
    // а пустые записи без описания и серийника не показываем.
    out.retain(|d| !d.serial.is_empty() || !d.description.is_empty());
    // Дубли схлопываем: один COM-порт не может принадлежать двум активным устройствам,
    // поэтому ключ — номер порта, иначе серийник/описание (у композитных узлов серийника нет).
    let mut seen = std::collections::HashSet::new();
    out.retain(|d| {
        let key = if let Some(com) = d.com_port {
            format!("com{com}")
        } else if !d.serial.is_empty() {
            d.serial.to_lowercase()
        } else {
            d.description.to_lowercase()
        };
        !key.is_empty() && seen.insert(key)
    });
    out
}

/// `VID_0403+PID_6001+A50285BI+A` → (0x0403, 0x6001, "A50285BI").
///
/// У композитных экземпляров вместо серийника стоит путь инстанса (`5&115a75a8&0&1`);
/// такие токены серийником не считаем — остаётся честно пустой serial.
#[cfg(windows)]
fn parse_instance_family(family: &str) -> (u16, u16, String) {
    let mut vid = 0u16;
    let mut pid = 0u16;
    let mut serial = String::new();
    let mut serial_taken = false;
    for (i, part) in family.split('+').enumerate() {
        let lower = part.to_ascii_lowercase();
        if let Some(hex) = lower.strip_prefix("vid_") {
            vid = u16::from_str_radix(hex, 16).unwrap_or(0);
        } else if let Some(hex) = lower.strip_prefix("pid_") {
            pid = u16::from_str_radix(hex, 16).unwrap_or(0);
        } else if i >= 2
            && !serial_taken
            && !part.is_empty()
            && part != "0"
            && !part.contains('&')
        {
            // Третий элемент — серийник; последний элемент (если есть) — номер интерфейса.
            serial = part.to_string();
            serial_taken = true;
        }
    }
    (vid, pid, serial)
}

/// `@ftdibus.inf,%ftdi_ser%;FTDI USB Serial Port` → `FTDI USB Serial Port`.
fn clean_device_desc(raw: &str) -> String {
    match raw.rsplit_once(';') {
        Some((_, tail)) if !tail.trim().is_empty() => tail.trim().to_string(),
        _ => raw.trim().to_string(),
    }
}

/// `COM6` → `Some(6)`; не COM-порт → `None`.
fn parse_com_number(port_name: &str) -> Option<u32> {
    port_name
        .trim()
        .to_ascii_uppercase()
        .strip_prefix("COM")
        .and_then(|n| n.trim().parse::<u32>().ok())
}

// ─────────────────────────────── вспомогательные Win32-хелперы ───────────

/// Открыть ключ реестра на чтение (64-битное представление).
#[cfg(windows)]
fn open_read_key(
    root: windows::Win32::System::Registry::HKEY,
    path: &str,
) -> Option<windows::Win32::System::Registry::HKEY> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, HKEY, KEY_READ, KEY_WOW64_64KEY,
    };
    use windows::core::PCWSTR;

    // SAFETY: ключ только открывается на чтение; дескриптор закрывает вызывающий.
    unsafe {
        let mut hkey = HKEY(std::ptr::null_mut());
        let wpath = wide(path);
        if RegOpenKeyExW(
            root,
            PCWSTR(wpath.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        ) == windows::Win32::Foundation::ERROR_SUCCESS
        {
            Some(hkey)
        } else {
            None
        }
    }
}

/// Прочитать строковое значение (REG_SZ/REG_EXPAND_SZ) из ветки реестра.
#[cfg(windows)]
pub(crate) fn registry_read_string_at(
    root: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegQueryValueExW, REG_EXPAND_SZ, REG_SZ,
    };
    use windows::core::PCWSTR;

    // SAFETY: чтение значения реестра; буферы живут дольше вызова, ключ закрывается.
    unsafe {
        let hkey = open_read_key(root, path)?;
        let wname = wide(name);
        let mut kind = windows::Win32::System::Registry::REG_VALUE_TYPE::default();
        let mut size = 0u32;
        let rc = RegQueryValueExW(
            hkey,
            PCWSTR(wname.as_ptr()),
            None,
            Some(&mut kind),
            None,
            Some(&mut size),
        );
        let value = if rc == ERROR_SUCCESS && size > 0 && (kind == REG_SZ || kind == REG_EXPAND_SZ) {
            let mut buf = vec![0u8; size as usize];
            let mut size2 = size;
            let rc2 = RegQueryValueExW(
                hkey,
                PCWSTR(wname.as_ptr()),
                None,
                Some(&mut kind),
                Some(buf.as_mut_ptr()),
                Some(&mut size2),
            );
            if rc2 == ERROR_SUCCESS {
                let u16s: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&u| u != 0)
                    .collect();
                Some(String::from_utf16_lossy(&u16s).trim().to_string())
            } else {
                None
            }
        } else {
            None
        };
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        value.filter(|s| !s.is_empty())
    }
}

/// Прочитать DWORD-значение из ветки реестра (например, `ProxyEnable`).
#[cfg(windows)]
pub(crate) fn registry_read_u32(
    root: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<u32> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::RegQueryValueExW;
    use windows::core::PCWSTR;

    // SAFETY: чтение DWORD; буфер — локальная переменная.
    unsafe {
        let hkey = open_read_key(root, path)?;
        let wname = wide(name);
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let rc = RegQueryValueExW(
            hkey,
            PCWSTR(wname.as_ptr()),
            None,
            None,
            Some(&mut value as *mut u32 as *mut u8),
            Some(&mut size),
        );
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        if rc == ERROR_SUCCESS && size == std::mem::size_of::<u32>() as u32 {
            Some(value)
        } else {
            None
        }
    }
}

/// Подключи реестра по пути (`HKLM\...`) → имена подключа.
#[cfg(windows)]
fn registry_enum_subkeys(path: &str) -> Vec<String> {
    use windows::Win32::Foundation::ERROR_NO_MORE_ITEMS;
    use windows::Win32::System::Registry::RegEnumKeyExW;
    use windows::core::PWSTR;

    let mut out = Vec::new();
    // SAFETY: только перечисление подключей, дескриптор закрывается.
    unsafe {
        let Some(hkey) = open_read_key(windows::Win32::System::Registry::HKEY_LOCAL_MACHINE, path)
        else {
            return out;
        };
        let mut idx = 0u32;
        loop {
            let mut name = [0u16; 512];
            let mut len = name.len() as u32;
            let rc = RegEnumKeyExW(
                hkey,
                idx,
                PWSTR(name.as_mut_ptr()),
                &mut len,
                None,
                PWSTR(std::ptr::null_mut()),
                None,
                None,
            );
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            idx += 1;
            if rc == windows::Win32::Foundation::ERROR_SUCCESS {
                out.push(String::from_utf16_lossy(&name[..len as usize]));
            }
        }
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
    }
    out
}

/// `&str` → NUL-terminated UTF-16 для Win32 `PCWSTR`.
#[cfg(windows)]
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ─────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_buf_stops_at_nul() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"FTDI");
        assert_eq!(c_buf_string(&buf), "FTDI");
        assert_eq!(c_buf_string(&[0u8; 8]), "");
    }

    #[test]
    fn parse_com_port_name() {
        assert_eq!(parse_com_number("COM6"), Some(6));
        assert_eq!(parse_com_number(" com12 "), Some(12));
        assert_eq!(parse_com_number("LPT1"), None);
        assert_eq!(parse_com_number(""), None);
    }

    #[test]
    fn clean_desc_strips_inf_prefix() {
        assert_eq!(
            clean_device_desc("@ftdibus.inf,%ftdi_ser%;FTDI USB Serial Port"),
            "FTDI USB Serial Port"
        );
        assert_eq!(clean_device_desc("FTDI USB Serial Port"), "FTDI USB Serial Port");
    }

    #[test]
    fn family_parse_vid_pid_serial() {
        let (vid, pid, serial) = parse_instance_family("VID_0403+PID_6001+A50285BI+A");
        assert_eq!(vid, 0x0403);
        assert_eq!(pid, 0x6001);
        assert_eq!(serial, "A50285BI");
    }

    /// В любой системе функция обязана вернуть валидный (возможно пустой) список без паники.
    #[test]
    fn list_devices_never_panics() {
        let devices = list_ftdi_devices();
        for d in &devices {
            assert!(!d.source.is_empty());
            assert!(
                d.source == "d2xx" || d.source == "registry",
                "неизвестный source: {}",
                d.source
            );
        }
        let _ = registry_devices();
    }

    /// Ручная проверка на реальном железе (нужен вставленный FTDI-шнурок).
    ///
    /// `#[ignore]`: результат зависит от машины, поэтому не входит в обычный прогон.
    /// Запуск: `cargo test --lib -- discovery::tests::real_devices -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_devices() {
        let devices = list_ftdi_devices();
        eprintln!("FTDI-устройств найдено: {}", devices.len());
        for d in &devices {
            eprintln!(
                "#{} source={} vid={:?} pid={:?} serial={:?} com={:?} desc={:?}",
                d.index, d.source, d.vendor_id, d.product_id, d.serial, d.com_port, d.description
            );
        }
        for d in &devices {
            assert!(
                !d.serial.is_empty() || !d.description.is_empty(),
                "устройство без серийника и описания: {d:?}"
            );
        }
        let reg = registry_devices();
        eprintln!("реестр FTDIBUS/USB: {}", reg.len());
        for d in &reg {
            eprintln!(
                "  source={} vid={:?} pid={:?} serial={:?} com={:?} desc={:?}",
                d.source, d.vendor_id, d.product_id, d.serial, d.com_port, d.description
            );
        }
        if cfg!(windows) {
            // Ветка реестра обязана хотя бы не падать и отдавать корректный source.
            assert!(reg.iter().all(|d| d.source == "registry"));
        }
    }
}
