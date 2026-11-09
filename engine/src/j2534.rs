//! J2534 (PassThru 04.04): зарегистрированные драйверы и распознавание модулей.
//! Владелец: boba.
//!
//! Реестр: `HKLM\SOFTWARE\WOW6432Node\PassThruSupport.04.04` (32-бит) и
//! `HKLM\SOFTWARE\PassThruSupport.04.04` (64-бит). Каждый подключ содержит
//! `Name`, `Vendor`, `FunctionLibrary`, `ConfigApplication` и версии протоколов.
//! Драйвер, зарегистрированный в обеих ветках, в списке должен быть один раз.

use crate::models::J2534Driver;

/// Ветки реестра PassThruSupport 04.04: (путь, человекочитаемый вид).
const PASSTHRU_BRANCHES: &[(&str, &str)] = &[
    (r"SOFTWARE\WOW6432Node\PassThruSupport.04.04", "32-bit"),
    (r"SOFTWARE\PassThruSupport.04.04", "64-bit"),
];

/// Все зарегистрированные J2534-драйверы (Scanmatik SM2/SM3, CHIPSOFT, OpenPort, VXDIAG, …).
///
/// `dll_present` = файл `FunctionLibrary` существует; `version` из ресурса версии DLL
/// (пустая, если версия не определяется). Без паники: нет прав/ветки — пустой/частичный список.
pub fn list_drivers() -> Vec<J2534Driver> {
    #[cfg(windows)]
    {
        let mut out: Vec<J2534Driver> = Vec::new();
        for (path, _view) in PASSTHRU_BRANCHES {
            for driver in drivers_from_branch(path) {
                // Один и тот же драйвер может быть зарегистрирован в 32- и 64-битной ветке.
                let duplicate = out.iter().any(|existing| {
                    existing.name.eq_ignore_ascii_case(&driver.name)
                        && (existing.dll.eq_ignore_ascii_case(&driver.dll)
                            || driver.dll.is_empty())
                });
                if duplicate {
                    continue;
                }
                out.push(driver);
            }
        }
        out.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then_with(|| a.registry_key.cmp(&b.registry_key))
        });
        out
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Регулярные подстроки имён DLL/модулей, которые считаем J2534/PassThru.
pub fn module_patterns() -> &'static [&'static str] {
    &[
        "j2534",
        "passthru",
        "pass-thru",
        "ptshim",
        "op20pt",
        "smj2534",
        "vcxpt",
        "evcucm",
        "ucdsj2534",
        "canflasher",
        "tactrix",
        "scanmatik",
        "chipsoft",
    ]
}

/// Похоже ли имя модуля на J2534/PassThru-драйвер.
pub fn is_j2534_module(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    module_patterns().iter().any(|pattern| lower.contains(pattern))
}

// ───────────────────────── реестр PassThruSupport ────────────────────────

#[cfg(windows)]
fn drivers_from_branch(branch: &str) -> Vec<J2534Driver> {
    use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;

    let mut out = Vec::new();
    for subkey in registry_enum_subkeys(HKEY_LOCAL_MACHINE, branch) {
        let key_path = format!(r"{branch}\{subkey}");
        let name = registry_read_string(HKEY_LOCAL_MACHINE, &key_path, "Name")
            .unwrap_or_else(|| subkey.clone());
        let vendor = registry_read_string(HKEY_LOCAL_MACHINE, &key_path, "Vendor").unwrap_or_default();
        let dll = registry_read_string(HKEY_LOCAL_MACHINE, &key_path, "FunctionLibrary")
            .map(|value| expand_env_vars(value.trim()))
            .unwrap_or_default();
        let dll_present = !dll.is_empty() && std::path::Path::new(&dll).is_file();
        let version = if dll_present {
            crate::procscan::file_version(&dll)
        } else {
            String::new()
        };
        out.push(J2534Driver {
            registry_key: key_path,
            name,
            vendor,
            dll,
            dll_present,
            version,
        });
    }
    out
}

/// `%SystemRoot%\System32\x.dll` → развёрнутый путь (только `%VAR%`-подстановки).
#[cfg(windows)]
fn expand_env_vars(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            out.push_str(rest);
            return out;
        };
        let var = &after[..end];
        match std::env::var(var) {
            Ok(value) => out.push_str(&value),
            Err(_) => {
                out.push('%');
                out.push_str(var);
                out.push('%');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(windows)]
fn registry_enum_subkeys(
    root: windows::Win32::System::Registry::HKEY,
    path: &str,
) -> Vec<String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, KEY_READ, KEY_WOW64_64KEY,
    };
    use windows::core::{PCWSTR, PWSTR};

    let mut out = Vec::new();
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: только перечисление подключей; дескриптор закрывается.
    unsafe {
        let mut key = windows::Win32::System::Registry::HKEY(std::ptr::null_mut());
        if RegOpenKeyExW(
            root,
            PCWSTR(wide_path.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        ) != windows::Win32::Foundation::ERROR_SUCCESS
        {
            return out;
        }
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
fn registry_read_string(
    root: windows::Win32::System::Registry::HKEY,
    path: &str,
    name: &str,
) -> Option<String> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, KEY_READ, KEY_WOW64_64KEY,
        REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };
    use windows::core::PCWSTR;

    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: чтение строкового значения; буферы локальны, ключ закрывается.
    unsafe {
        let mut key = windows::Win32::System::Registry::HKEY(std::ptr::null_mut());
        if RegOpenKeyExW(
            root,
            PCWSTR(wide_path.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        ) != ERROR_SUCCESS
        {
            return None;
        }
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
        let value = if rc == ERROR_SUCCESS && size > 0 && (kind == REG_SZ || kind == REG_EXPAND_SZ) {
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
                let units: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .take_while(|&unit| unit != 0)
                    .collect();
                Some(String::from_utf16_lossy(&units).trim().to_string())
            } else {
                None
            }
        } else {
            None
        };
        let _ = RegCloseKey(key);
        value.filter(|text| !text.is_empty())
    }
}

// ─────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn j2534_patterns_detect_drivers() {
        for name in [
            "smj2534.dll",
            "op20pt32.dll",
            "j2534_interface.dll",
            "PassThru.dll",
            "vcxpt.dll",
            "UCDSJ2534.dll",
        ] {
            assert!(is_j2534_module(name), "{name} должен считаться J2534");
        }
        for name in ["kernel32.dll", "winusb.dll", "hid.dll"] {
            assert!(!is_j2534_module(name), "{name} не J2534");
        }
    }

    #[test]
    fn list_drivers_finds_registered_passthru() {
        let drivers = list_drivers();
        eprintln!("J2534-драйверов: {}", drivers.len());
        for driver in drivers.iter().take(5) {
            eprintln!(
                "name={:?} vendor={:?} dll_present={} version={:?} dll={:?}",
                driver.name, driver.vendor, driver.dll_present, driver.version, driver.dll
            );
        }
        assert!(!drivers.is_empty(), "на машине должны быть J2534-драйверы");
        assert!(
            drivers.iter().any(|driver| driver.dll_present),
            "ни у одного драйвера не найден FunctionLibrary"
        );
        assert!(
            drivers.iter().all(|driver| !driver.registry_key.is_empty()),
            "пустой registry_key"
        );
        // Дубликатов по (name,dll) быть не должно (32/64-битные ветки схлопнуты).
        for (index, a) in drivers.iter().enumerate() {
            for b in drivers.iter().skip(index + 1) {
                assert!(
                    !(a.name.eq_ignore_ascii_case(&b.name) && a.dll.eq_ignore_ascii_case(&b.dll)),
                    "дубликат драйвера: {} / {}",
                    a.name,
                    b.registry_key
                );
            }
        }
    }

    #[test]
    fn expand_env_vars_keeps_unknown() {
        let text = expand_env_vars(r"%SystemRoot%\System32\smj2534.dll");
        assert!(text.to_lowercase().contains("system32"), "не развернулось: {text}");
        assert_eq!(expand_env_vars("%NO_SUCH_VAR%\\x.dll"), "%NO_SUCH_VAR%\\x.dll");
    }
}