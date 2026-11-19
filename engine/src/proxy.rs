//! J2534-прокси: состояние поставки, установка/снятие и полоса журнала в сессии.
//! Контракт: docs/13-j2534-proxy.md (§4 конфиг, §5 реестр, §6 формат журнала, §8 полоса).
//!
//! Модуль намеренно не знает ни про axum, ни про захват: он умеет только
//! «прочитать состояние», «изменить состояние» и «собрать журналы в полосу».
//! Так одна и та же логика обслуживает HTTP-обработчик, helper-бин установщика
//! (`ftdi-j2534proxy-setup`) и финализацию сессии — расхождений между ними нет.
//!
//! Почему установка начинается с проверки прав, а не с записи в ini: контракт
//! требует «без прав — понятная ошибка, без частичных записей». Проверка прав
//! первой гарантирует, что после отказа не останется ни ini с `Enabled=1`, ни
//! полузаписанного ключа реестра, из-за которого прокси «как бы включён».

use crate::models::{ProxyCross, ProxyLane};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

// ─────────────────────────────── константы ───────────────────────────────

/// Имя прокси-DLL. Файл обязан содержать `j2534` в имени: по этому признаку
/// Frida-агент относит модуль к J2534, и полоса frida продолжает работать,
/// когда приложение грузит прокси вместо настоящего драйвера (docs/13 §3).
const DLL_NAME: &str = "j2534proxy.dll";
const INI_NAME: &str = "j2534proxy.ini";
/// Резервный способ задать настоящую библиотеку (docs/13 §4, третий приоритет).
const REAL_DLL_TXT: &str = "real_dll.txt";
/// Путь J2534-устройства — ровно та ветка, которую видят 32-битные приложения 04.04.
const PASSTHRU_BRANCH: &str = r"SOFTWARE\WOW6432Node\PassThruSupport.04.04";
/// Выбор адаптера PCMflash: значение `Adapter` в HKCU (docs/13 §5).
const PCMFLASH_KEY: &str = r"Software\PCMFlash";
const PCMFLASH_VALUE: &str = "Adapter";
/// Бэкап прежнего адаптера лежит рядом с журналами (docs/13 §5).
const ADAPTER_BACKUP: &str = "pcmflash-adapter.bak";
const DEVICE_DEFAULT: &str = "Scanmatik - SM2 Proxy";
const VENDOR_DEFAULT: &str = "DaVinci Cyber Engineering";
/// `LogDir` по умолчанию пишется НЕразвёрнутым: ini переживает смену пользователя
/// и переустановку, а `%LOCALAPPDATA%` каждый раз раскрывается заново.
const LOG_DIR_DEFAULT: &str = r"%LOCALAPPDATA%\FTDI_USB_Logger\j2534proxy";
/// Сколько секунд до старта сессии считаются «своими» журналами: прокси создаёт
/// файл при первом вызове, а `started_at` фиксируется чуть раньше (docs/13 §8).
const LOG_WINDOW_BACK: i64 = 5;

// ─────────────────────────────── состояние ───────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyDll {
    pub path: String,
    pub present: bool,
    /// Версия из ресурса версии DLL (пустая, если файла нет или версия не читается).
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyIni {
    pub path: String,
    pub present: bool,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyRegistry {
    pub registered: bool,
    /// Человеческий путь ключа — его показывают UI и helper.
    pub key: String,
    pub device_name: String,
    pub function_library: String,
}

/// Настоящая библиотека, в которую прокси форвардит вызовы.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyReal {
    pub path: String,
    pub present: bool,
    /// Откуда путь: `env` | `ini` | `file` | `registry`.
    pub from: String,
}

/// Выбор адаптера в PCMflash: `HKCU\Software\PCMFlash\Adapter`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyPcmflash {
    pub adapter: String,
    pub proxy_selected: bool,
    /// Прежнее значение из `pcmflash-adapter.bak` (пусто, если бэкапа нет).
    pub backup: String,
}

/// Состояние J2534-прокси — ровно форма JSON из docs/13 §8.
///
/// `ok` здесь всегда `true`: это ответ «состояние прочитано». Отказ действия
/// (`install` без прав) отдаётся вызывающим как `{"ok": false, "notes": […]}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyStatus {
    pub ok: bool,
    pub elevated: bool,
    pub install_dir: String,
    pub dll: ProxyDll,
    pub ini: ProxyIni,
    pub registry: ProxyRegistry,
    pub real: ProxyReal,
    pub log_dir: String,
    pub log_files: usize,
    pub pcmflash: ProxyPcmflash,
    pub notes: Vec<String>,
}

/// Значения ini как они записаны: `LogDir` — неразвёрнутый.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyIniValues {
    pub present: bool,
    pub enabled: bool,
    pub real_library: String,
    pub log_dir: String,
    pub max_data_bytes: u32,
    pub name: String,
    pub vendor: String,
}

// ───────────────────────────── чтение ini ────────────────────────────────

/// Прочитать `j2534proxy.ini`. Нет файла — значения по умолчанию (не ошибка):
/// выключенный прокси — это состояние, а не поломка.
pub fn read_ini(install_dir: &Path) -> ProxyIniValues {
    let mut out = ProxyIniValues {
        max_data_bytes: 4128,
        ..Default::default()
    };
    let Ok(bytes) = std::fs::read(install_dir.join(INI_NAME)) else {
        return out;
    };
    out.present = true;
    let text = decode_text(&bytes);
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        // `;` и `#` — комментарии INI; пустые строки пропускаем молча.
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match (section.as_str(), key.as_str()) {
            ("proxy", "enabled") => {
                out.enabled = matches!(
                    value.to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            }
            ("proxy", "reallibrary") => out.real_library = value.to_string(),
            ("proxy", "logdir") => out.log_dir = value.to_string(),
            ("proxy", "maxdatabytes") => {
                if let Ok(parsed) = value.parse() {
                    out.max_data_bytes = parsed;
                }
            }
            ("device", "name") => out.name = value.to_string(),
            ("device", "vendor") => out.vendor = value.to_string(),
            _ => {}
        }
    }
    out
}

/// Записать ini (docs/13 §4). Существующие `Name`/`Vendor`/`LogDir` сохраняются:
/// переключение `Enabled` не должно терять настройку устройства.
pub fn write_ini(install_dir: &Path, enabled: bool, real: Option<&str>) -> Result<ProxyIniValues> {
    let current = read_ini(install_dir);
    let real_library = real
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or(current.real_library);
    let name = if current.name.trim().is_empty() {
        DEVICE_DEFAULT.to_string()
    } else {
        current.name
    };
    let vendor = if current.vendor.trim().is_empty() {
        VENDOR_DEFAULT.to_string()
    } else {
        current.vendor
    };
    let log_dir = if current.log_dir.trim().is_empty() {
        LOG_DIR_DEFAULT.to_string()
    } else {
        current.log_dir
    };
    // `\` в конце строки съедает перевод строки и отступ — ini остаётся без
    // ведущих пробелов, как его ждёт парсер прокси (ASCII, без BOM).
    let text = format!(
        "; J2534-прокси FTDI/USB Logger. Файл пишет движок (docs/13 §4).\n\
         [proxy]\n\
         Enabled={}\n\
         RealLibrary={}\n\
         LogDir={}\n\
         MaxDataBytes={}\n\
         \n\
         [device]\n\
         Name={}\n\
         Vendor={}\n",
        u8::from(enabled),
        real_library,
        log_dir,
        if current.max_data_bytes == 0 {
            4128
        } else {
            current.max_data_bytes
        },
        name,
        vendor
    );
    crate::store::write_text_atomic(&install_dir.join(INI_NAME), &text)
        .with_context(|| format!("записать {}", install_dir.join(INI_NAME).display()))?;
    Ok(read_ini(install_dir))
}

/// Текст файла в UTF-8. Установщик пишет ASCII, но ini правят и руками:
/// «Блокнот» сохраняет UTF-16 с BOM, и такой файл должен читаться, а не
/// превращаться в мусор из чередующихся нулей.
fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8_lossy(body).into_owned()
}

/// Каталог журналов: `LogDir` из ini (с раскрытием `%VAR%`), иначе стандартный.
pub fn log_dir_for(install_dir: &Path) -> PathBuf {
    let ini = read_ini(install_dir);
    let raw = if ini.log_dir.trim().is_empty() {
        LOG_DIR_DEFAULT.to_string()
    } else {
        ini.log_dir
    };
    PathBuf::from(crate::j2534::expand_env_vars(raw.trim()))
}

/// Включён ли прокси по-настоящему: `Enabled=1` И DLL на месте.
///
/// Без DLL запись `Enabled=1` бессмысленна — приложение её просто не загрузит,
/// а сессия получила бы ложный факт «прокси включён» (docs/13 §7).
pub fn is_active(install_dir: &Path) -> bool {
    // `FTDI_J2534_PROXY_OFF=1` — жёсткое выключение без правки ini (docs/13 §4):
    // так прокси глушат из скрипта, не трогая файл установки.
    if proxy_off_by_env() {
        return false;
    }
    let ini = read_ini(install_dir);
    ini.enabled && install_dir.join(DLL_NAME).is_file()
}

fn proxy_off_by_env() -> bool {
    is_truthy(std::env::var("FTDI_J2534_PROXY_OFF").ok().as_deref())
}

fn is_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Точный путь журнала из окружения — приоритет 1 в таблице источников §4.
fn env_log_file() -> Option<PathBuf> {
    let value = std::env::var("FTDI_J2534_PROXY_LOG").ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| PathBuf::from(crate::j2534::expand_env_vars(value)))
}

/// Факт в шапку сессии — ровно один раз, при старте захвата.
pub fn session_fact(install_dir: &Path) -> Option<String> {
    if !is_active(install_dir) {
        return None;
    }
    Some(format!(
        "# j2534proxy: включён, лог {}",
        log_dir_for(install_dir).display()
    ))
}

// ─────────────────────────────── статус ──────────────────────────────────

pub fn status(install_dir: &Path) -> ProxyStatus {
    build_status(install_dir, Vec::new())
}

fn build_status(install_dir: &Path, extra_notes: Vec<String>) -> ProxyStatus {
    let ini_values = read_ini(install_dir);
    let device = device_name(&ini_values);
    let dll_path = install_dir.join(DLL_NAME);
    let dll_present = dll_path.is_file();
    let registry = read_registry(&device);
    let log_dir = log_dir_for(install_dir);
    let log_files = count_logs(&log_dir);
    let adapter = reg::read_adapter().unwrap_or_default();
    let backup = read_adapter_backup(&log_dir).unwrap_or_default();
    let real = resolve_real_status(install_dir, &ini_values);
    let elevated = reg::is_elevated();

    let mut notes = extra_notes;
    if !elevated {
        notes.push("без прав администратора: регистрация устройства и включение недоступны".into());
    }
    if !dll_present {
        notes.push(format!(
            "{DLL_NAME} не найдена в {} — прокси не загрузится",
            install_dir.display()
        ));
    }
    if !ini_values.present {
        notes.push(format!(
            "{INI_NAME} нет — прокси выключен (состояние по умолчанию)"
        ));
    }
    if real.path.is_empty() {
        notes.push(
            "настоящий J2534-драйвер не найден — укажите RealLibrary или выберите адаптер в PCMflash"
                .into(),
        );
    }
    if ini_values.enabled && !registry.registered && dll_present {
        notes.push("включено в ini, но устройство не зарегистрировано — нужен action=install".into());
    }

    ProxyStatus {
        ok: true,
        elevated,
        install_dir: display_path(install_dir),
        dll: ProxyDll {
            path: display_path(&dll_path),
            present: dll_present,
            version: if dll_present {
                crate::procscan::file_version(&dll_path.to_string_lossy())
            } else {
                String::new()
            },
        },
        ini: ProxyIni {
            path: display_path(&install_dir.join(INI_NAME)),
            present: ini_values.present,
            enabled: ini_values.enabled,
        },
        registry,
        real,
        log_dir: display_path(&log_dir),
        log_files,
        pcmflash: ProxyPcmflash {
            proxy_selected: adapter.eq_ignore_ascii_case(&proxy_adapter_name(&device)),
            adapter,
            backup,
        },
        notes,
    }
}

fn device_name(ini: &ProxyIniValues) -> String {
    let name = ini.name.trim();
    if name.is_empty() {
        DEVICE_DEFAULT.to_string()
    } else {
        name.to_string()
    }
}

/// Путь для JSON и для записи в реестр — без префикса `\\?\`.
///
/// Префикс добавляет канонизация (`Config::from_cli` канонизирует `root`), а
/// человеку, установщику и `FunctionLibrary` нужен обычный путь: контракт
/// (docs/13 §8) показывает именно такой. Для файловых операций префикс остаётся.
fn display_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{unc}");
    }
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
}

/// Значение, которое должно стоять в PCMflash: `J2534: <device.Name>` (docs/13 §5).
fn proxy_adapter_name(device: &str) -> String {
    format!("J2534: {device}")
}

fn count_logs(dir: &Path) -> usize {
    // Явный путь из окружения перебивает каталог (docs/13 §4): тогда журнал
    // ровно один — тот, что указали.
    if let Some(exact) = env_log_file() {
        return usize::from(exact.is_file());
    }
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return 0;
    };
    read_dir
        .flatten()
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            name.starts_with("proxy-") && name.ends_with(".log")
        })
        .count()
}

// ───────────────────────── настоящая библиотека ──────────────────────────

/// Найти настоящий J2534-драйвер по реестру (docs/13 §4: `RealLibrary`
/// подставляется из уже зарегистрированного драйвера).
///
/// Приоритет: устройство, выбранное в PCMflash (без префикса `J2534: `), иначе
/// первый зарегистрированный с существующим файлом. Источник — `registry`:
/// другое значение здесь невозможно, путь взят из `FunctionLibrary`.
pub fn resolve_real_library() -> Option<(String, String)> {
    let adapter = reg::read_adapter().unwrap_or_default();
    let adapter = adapter.trim();
    let wanted = adapter
        .strip_prefix("J2534: ")
        .unwrap_or(adapter)
        .trim()
        .to_string();
    let drivers: Vec<crate::models::J2534Driver> = crate::j2534::list_drivers()
        .into_iter()
        // Свою же запись нельзя объявлять «настоящим драйвером»: прокси
        // форвардил бы вызовы в себя (docs/13 §7, `real == self`).
        .filter(|driver| driver.dll_present && !is_proxy_dll(&driver.dll))
        .collect();
    if !wanted.is_empty() {
        if let Some(found) = pick_driver(&drivers, &wanted) {
            return Some((found.dll.clone(), "registry".to_string()));
        }
    }
    drivers
        .into_iter()
        .next()
        .map(|driver| (driver.dll, "registry".to_string()))
}

/// Выбрать драйвер по имени из PCMflash.
///
/// Точное совпадение — первым, но в реестре устройство часто названо короче:
/// PCMflash пишет `Scanmatik - SM2 USB`, а ключ зарегистрирован как `SM2 USB`.
/// Поэтому второй проход — по вхождению целого имени в строку PCMflash (не
/// наоборот: короткое `SM2` иначе перебивало бы `SM2 USB`).
fn pick_driver<'a>(
    drivers: &'a [crate::models::J2534Driver],
    wanted: &str,
) -> Option<&'a crate::models::J2534Driver> {
    if let Some(found) = drivers
        .iter()
        .find(|driver| driver.name.eq_ignore_ascii_case(wanted))
    {
        return Some(found);
    }
    let wanted = wanted.to_ascii_lowercase();
    drivers.iter().find(|driver| {
        let name = driver.name.trim().to_ascii_lowercase();
        !name.is_empty() && wanted.contains(&name)
    })
}

/// `real` для статуса: цепочка приоритетов §4 (env → ini → real_dll.txt → реестр).
fn resolve_real_status(install_dir: &Path, ini: &ProxyIniValues) -> ProxyReal {
    let mut from = String::new();
    let mut path = String::new();
    if let Ok(value) = std::env::var("FTDI_J2534_REAL_DLL") {
        let value = value.trim();
        if !value.is_empty() {
            path = crate::j2534::expand_env_vars(value);
            from = "env".into();
        }
    }
    if path.is_empty() && !ini.real_library.trim().is_empty() {
        path = crate::j2534::expand_env_vars(ini.real_library.trim());
        from = "ini".into();
    }
    if path.is_empty() {
        if let Ok(text) = std::fs::read_to_string(install_dir.join(REAL_DLL_TXT)) {
            // Первая непустая строка, не начинающаяся с `#`.
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                path = crate::j2534::expand_env_vars(line);
                from = "file".into();
                break;
            }
        }
    }
    if path.is_empty() {
        if let Some((found, source)) = resolve_real_library() {
            path = found;
            from = source;
        }
    }
    let present = !path.is_empty() && Path::new(&path).is_file();
    ProxyReal {
        path,
        present,
        from,
    }
}

fn is_proxy_dll(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().eq_ignore_ascii_case(DLL_NAME))
        .unwrap_or(false)
}

// ─────────────────────────── установка/снятие ────────────────────────────

/// Установка: ini + запись `PassThruSupport.04.04\<device.Name>` (docs/13 §5).
///
/// Порядок шагов выбран так, чтобы отказ не оставлял полусостояния: сначала
/// права, затем реестр (самое вероятное место отказа), затем ini. Если ini не
/// записался — ключ реестра снимается обратно.
pub fn install(install_dir: &Path, real: Option<&str>) -> Result<ProxyStatus> {
    require_admin("регистрация J2534-устройства в HKLM")?;
    let ini = read_ini(install_dir);
    let dll = install_dir.join(DLL_NAME);
    if !dll.is_file() {
        bail!(
            "{DLL_NAME} не найдена в {} — сначала установите сам прокси",
            install_dir.display()
        );
    }
    // Откуда берём настоящий драйвер (docs/13 §4, для установки — свой порядок):
    // явный аргумент → уже записанный ini → бэкап адаптера PCMflash (его мы
    // подменили, значит он и есть «настоящий») → реестр по выбранному адаптеру.
    //
    // Последний шаг — единственное место, где возможна ошибка выбора: если в
    // PCMflash уже стоит наше же устройство, имя ни с чем не совпадёт, а
    // драйверов на машине бывает больше десяти. Поэтому «первый попавшийся»
    // разрешён только как fallback и всегда с предупреждением в notes.
    let log_dir = log_dir_for(install_dir);
    // Драйверы, которые вообще могут быть «настоящими» (наша запись исключена).
    let drivers: Vec<crate::models::J2534Driver> = crate::j2534::list_drivers()
        .into_iter()
        .filter(|driver| driver.dll_present && !is_proxy_dll(&driver.dll))
        .collect();
    let adapter = reg::read_adapter().unwrap_or_default();
    let adapter_name = adapter
        .trim()
        .strip_prefix("J2534: ")
        .unwrap_or(adapter.trim())
        .to_string();
    let by_adapter = if adapter_name.is_empty() {
        None
    } else {
        pick_driver(&drivers, &adapter_name).map(|found| found.dll.clone())
    };
    let by_backup = read_adapter_backup(&log_dir).and_then(|name| {
        let name = name.trim();
        let name = name.strip_prefix("J2534: ").unwrap_or(name).trim().to_string();
        pick_driver(&drivers, &name).map(|found| found.dll.clone())
    });
    let device = device_name(&ini);
    // PCMflash уже переключён на наше устройство? Тогда «что было до нас»
    // хранится в бэкапе, и он важнее значения в ini: именно этот случай —
    // переустановка/обновление, где ini мог остаться от автовыбора.
    let adapter_is_ours = !adapter_name.is_empty() && adapter_name.eq_ignore_ascii_case(&device);
    let ini_real = {
        let value = crate::j2534::expand_env_vars(ini.real_library.trim());
        (!value.is_empty() && Path::new(&value).is_file()).then_some(value)
    };

    let (real_path, real_from) = if let Some(explicit) = real
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        (explicit.to_string(), "явно")
    } else if adapter_is_ours {
        match (by_backup, ini_real) {
            (Some(path), _) => (path, "бэкап адаптера"),
            (None, Some(path)) => (path, "ini"),
            (None, None) => (
                by_adapter
                    .unwrap_or_else(|| drivers.first().map(|f| f.dll.clone()).unwrap_or_default()),
                "реестр",
            ),
        }
    } else if let Some(path) = ini_real {
        (path, "ini")
    } else if let Some(path) = by_backup {
        (path, "бэкап адаптера")
    } else if let Some(path) = by_adapter {
        (path, "реестр")
    } else {
        (
            drivers.first().map(|found| found.dll.clone()).unwrap_or_default(),
            "первый из реестра",
        )
    };
    if real_path.is_empty() {
        bail!("настоящий J2534-драйвер не найден — укажите его явно (RealLibrary)");
    }
    if same_path(&real_path, &dll.to_string_lossy()) {
        bail!("настоящая библиотека указывает на саму прокси — рекурсия запрещена");
    }
    // В реестр — обычный путь: `\\?\` в FunctionLibrary работает, но выглядит
    // как ошибка и путает установщик (docs/13 §5: «полным путём»).
    reg::create_device(&device, VENDOR_DEFAULT, &display_path(&dll))
        .map_err(|err| reg_error(err, "записать HKLM PassThruSupport.04.04"))?;
    let written = write_ini(install_dir, true, Some(&real_path));
    let ini_values = match written {
        Ok(values) => values,
        Err(err) => {
            // Реестр уже записан — снимаем: «зарегистрировано, но не включено»
            // это ровно то полусостояние, которое контракт запрещает.
            let _ = reg::delete_device(&device);
            return Err(err);
        }
    };
    let mut notes = vec![format!(
        "устройство зарегистрировано как «{device}», Enabled={}",
        u8::from(ini_values.enabled)
    )];
    if real_from == "первый из реестра" && drivers.len() > 1 {
        // Молча выбрать «первый попавшийся» из десятка драйверов — значит
        // увести прокси на чужое железо (на живой машине так и вышло: CHIPSOFT
        // вместо Scanmatik). Регистрация состоялась, но пользователь обязан
        // увидеть, что выбор сделан наугад.
        notes.push(format!(
            "настоящий драйвер выбран автоматически ({real_path}) — если это не ваш \
             адаптер, впишите RealLibrary в j2534proxy.ini"
        ));
    } else if real_from == "реестр" || real_from == "бэкап адаптера" {
        notes.push(format!("настоящий драйвер: {real_path} ({real_from})"));
    }
    Ok(build_status(install_dir, notes))
}

/// Снятие: удаляется только наша запись реестра, ini остаётся (docs/13 §5).
pub fn remove(install_dir: &Path) -> Result<ProxyStatus> {
    require_admin("удаление J2534-устройства из HKLM")?;
    let ini = read_ini(install_dir);
    let device = device_name(&ini);
    reg::delete_device(&device).map_err(|err| reg_error(err, "удалить HKLM PassThruSupport.04.04"))?;
    Ok(build_status(
        install_dir,
        vec![format!("устройство «{device}» снято с регистрации")],
    ))
}

/// `Enabled=0/1`. Включение требует прав: по контракту (§5) включение —
/// администраторское действие, даже если ini пишется в пользовательский каталог.
pub fn set_enabled(install_dir: &Path, on: bool) -> Result<ProxyStatus> {
    if on {
        require_admin("включение прокси")?;
    }
    let values = write_ini(install_dir, on, None)?;
    let mut notes = vec![format!("Enabled={}", u8::from(values.enabled))];
    if on && !values.real_library.trim().is_empty() && !Path::new(&values.real_library).is_file() {
        notes.push(format!(
            "RealLibrary указывает на отсутствующий файл: {}",
            values.real_library
        ));
    }
    Ok(build_status(install_dir, notes))
}

/// Переключить выбор адаптера в PCMflash на прокси (или вернуть прежний).
///
/// Бэкап пишется только когда в PCMflash стоит ЧУЖОЕ значение: повторное
/// включение затёрло бы бэкап нашим же `J2534: <proxy>` и откат стал бы
/// невозможен — а именно откат здесь и есть цель (docs/13 §5).
pub fn select_adapter(install_dir: &Path, on: bool) -> Result<ProxyStatus> {
    let ini = read_ini(install_dir);
    let device = device_name(&ini);
    let want = proxy_adapter_name(&device);
    let log_dir = log_dir_for(install_dir);
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("не создать каталог журналов {}", log_dir.display()))?;
    let backup_path = log_dir.join(ADAPTER_BACKUP);
    let current = reg::read_adapter().unwrap_or_default();
    let mut notes = Vec::new();

    if on {
        if current.eq_ignore_ascii_case(&want) {
            notes.push(format!("адаптер PCMflash уже выбран: {want}"));
        } else {
            crate::store::write_text_atomic(&backup_path, &current)
                .with_context(|| format!("не сохранить бэкап {}", backup_path.display()))?;
            write_pcmflash_adapter(&want)?;
            notes.push(format!("адаптер PCMflash переключён на {want}"));
            if !current.is_empty() {
                notes.push(format!("прежнее значение сохранено: {current}"));
            }
        }
    } else {
        match read_adapter_backup(&log_dir) {
            Some(previous) => {
                write_pcmflash_adapter(&previous)?;
                notes.push(if previous.is_empty() {
                    "бэкап пуст — адаптер PCMflash сброшен".to_string()
                } else {
                    format!("адаптер PCMflash восстановлен: {previous}")
                });
            }
            // Без бэкапа восстанавливать нечего: придумывать значение нельзя,
            // иначе мы бы «вернули» адаптер, которого пользователь не выбирал.
            None => notes.push(format!(
                "бэкап {} не найден — адаптер оставлен как есть",
                backup_path.display()
            )),
        }
    }
    Ok(build_status(install_dir, notes))
}

/// Вернуть адаптер PCMflash из бэкапа (docs/13 §5: «выключение»).
pub fn restore_adapter(install_dir: &Path) -> Result<ProxyStatus> {
    select_adapter(install_dir, false)
}

fn read_adapter_backup(log_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(log_dir.join(ADAPTER_BACKUP)).ok()?;
    Some(text.trim_end_matches(['\r', '\n']).to_string())
}

/// Записать выбор адаптера. Вынесено из `select_adapter`, чтобы не-админское
/// выключение не тащило за собой учёт прав.
fn write_pcmflash_adapter(value: &str) -> Result<()> {
    reg::write_adapter(value)
        .map_err(|err| reg_error(err, "записать HKCU\\Software\\PCMFlash\\Adapter"))
}

fn same_path(a: &str, b: &str) -> bool {
    let canon = |value: &str| {
        std::fs::canonicalize(value)
            .map(|path| path.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_else(|_| value.to_ascii_lowercase())
    };
    canon(a) == canon(b)
}

fn require_admin(what: &str) -> Result<()> {
    if reg::is_elevated() {
        Ok(())
    } else {
        // Текст ищет helper-бин установщика (`needs_admin`): по нему он решает
        // вернуть код 2 и попросить UAC ещё раз, а не «поломка, зовите поддержку».
        Err(anyhow!("требуются права администратора: {what}"))
    }
}

fn reg_error(err: reg::RegError, what: &str) -> anyhow::Error {
    match err {
        reg::RegError::AccessDenied => anyhow!("требуются права администратора: {what}"),
        reg::RegError::Other(code) => anyhow!("{what}: код Windows {code}"),
    }
}

// ─────────────────────────────── реестр ──────────────────────────────────

#[cfg(windows)]
mod reg {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE,
        KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
    };

    use super::{PASSTHRU_BRANCH, PCMFLASH_KEY, PCMFLASH_VALUE};

    #[derive(Debug, Clone, Copy)]
    pub(super) enum RegError {
        AccessDenied,
        Other(u32),
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn map(rc: WIN32_ERROR) -> RegError {
        if rc == ERROR_ACCESS_DENIED {
            RegError::AccessDenied
        } else {
            RegError::Other(rc.0)
        }
    }

    /// Права администратора в текущем процессе (`IsUserAnAdmin`).
    ///
    /// Не «вошёл ли админом», а «поднят ли процесс»: UAC-фильтр отдаёт обычный
    /// токен даже администратору, и запись в HKLM без повышения всё равно упадёт.
    pub(super) fn is_elevated() -> bool {
        // SAFETY: IsUserAnAdmin только читает токен текущего процесса.
        unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
    }

    fn open(root: HKEY, path: &str, access: REG_SAM_FLAGS) -> Option<HKEY> {
        let path = wide(path);
        let mut key = HKEY(std::ptr::null_mut());
        // SAFETY: путь — локальный буфер с NUL; при успехе дескриптор закрывает вызывающий.
        let rc = unsafe { RegOpenKeyExW(root, PCWSTR(path.as_ptr()), 0, access, &mut key) };
        (rc == ERROR_SUCCESS).then_some(key)
    }

    fn read_string(root: HKEY, path: &str, name: &str) -> Option<String> {
        let key = open(root, path, KEY_READ | KEY_WOW64_64KEY)?;
        let name = wide(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size = 0u32;
        // SAFETY: два вызова — сначала размер, потом чтение в свой буфер.
        unsafe {
            let rc = RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut kind),
                None,
                Some(&mut size),
            );
            let value = if rc == ERROR_SUCCESS && size > 0 && kind == REG_SZ {
                let mut buf = vec![0u8; size as usize];
                let mut size2 = size;
                let rc2 = RegQueryValueExW(
                    key,
                    PCWSTR(name.as_ptr()),
                    None,
                    Some(&mut kind),
                    Some(buf.as_mut_ptr()),
                    Some(&mut size2),
                );
                if rc2 == ERROR_SUCCESS {
                    let units: Vec<u16> = buf
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .take_while(|unit| *unit != 0)
                        .collect();
                    Some(String::from_utf16_lossy(&units))
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

    fn write_string(key: HKEY, name: &str, value: &str) -> std::result::Result<(), RegError> {
        let name = wide(name);
        // REG_SZ хранится вместе с завершающим NUL — иначе часть приложений
        // прочитает хвост мусора из соседней памяти.
        let data: Vec<u8> = value
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        // SAFETY: буфер живёт до конца вызова; ключ открыт вызывающим.
        let rc = unsafe { RegSetValueExW(key, PCWSTR(name.as_ptr()), 0, REG_SZ, Some(&data)) };
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(map(rc))
        }
    }

    fn create_key(root: HKEY, path: &str) -> std::result::Result<HKEY, RegError> {
        let path = wide(path);
        let mut key = HKEY(std::ptr::null_mut());
        // SAFETY: локальные буферы с NUL; класс и атрибуты не нужны — null.
        let rc = unsafe {
            RegCreateKeyExW(
                root,
                PCWSTR(path.as_ptr()),
                0,
                PCWSTR(std::ptr::null()),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE | KEY_WOW64_64KEY,
                None,
                &mut key,
                None,
            )
        };
        if rc == ERROR_SUCCESS {
            Ok(key)
        } else {
            Err(map(rc))
        }
    }

    /// Создать/перезаписать ключ устройства: `Name`, `Vendor`, `FunctionLibrary`,
    /// `ConfigApplication`, `ConfigApplicationArguments` (docs/13 §5).
    pub(super) fn create_device(
        name: &str,
        vendor: &str,
        function_library: &str,
    ) -> std::result::Result<(), RegError> {
        let key = create_key(HKEY_LOCAL_MACHINE, &format!(r"{PASSTHRU_BRANCH}\{name}"))?;
        let result = write_string(key, "Name", name)
            .and_then(|_| write_string(key, "Vendor", vendor))
            .and_then(|_| write_string(key, "FunctionLibrary", function_library))
            .and_then(|_| write_string(key, "ConfigApplication", ""))
            .and_then(|_| write_string(key, "ConfigApplicationArguments", ""));
        // SAFETY: дескриптор получен выше и больше не нужен.
        unsafe {
            let _ = RegCloseKey(key);
        }
        if result.is_err() {
            // Частично заполненный ключ хуже отсутствующего: приложение увидит
            // устройство без FunctionLibrary и упадёт на загрузке драйвера.
            let _ = delete_device(name);
        }
        result
    }

    /// Удалить ключ устройства вместе с подключами (`RegDeleteTreeW`).
    pub(super) fn delete_device(name: &str) -> std::result::Result<(), RegError> {
        let path = wide(&format!(r"{PASSTHRU_BRANCH}\{name}"));
        // SAFETY: путь — локальный буфер с NUL.
        let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr())) };
        // ERROR_FILE_NOT_FOUND — «уже нет»: снятие идемпотентно, это не ошибка.
        if rc == ERROR_SUCCESS || rc.0 == 2 {
            Ok(())
        } else {
            Err(map(rc))
        }
    }

    pub(super) fn read_adapter() -> Option<String> {
        read_string(HKEY_CURRENT_USER, PCMFLASH_KEY, PCMFLASH_VALUE)
    }

    /// Записать `HKCU\Software\PCMFlash\Adapter` (ключ создаётся при отсутствии).
    pub(super) fn write_adapter(value: &str) -> std::result::Result<(), RegError> {
        let key = create_key(HKEY_CURRENT_USER, PCMFLASH_KEY)?;
        let result = write_string(key, PCMFLASH_VALUE, value);
        // SAFETY: дескриптор получен выше и больше не нужен.
        unsafe {
            let _ = RegCloseKey(key);
        }
        result
    }

    /// Есть ли ключ устройства (для `registry.registered`).
    pub(super) fn device_exists(name: &str) -> bool {
        open(
            HKEY_LOCAL_MACHINE,
            &format!(r"{PASSTHRU_BRANCH}\{name}"),
            KEY_READ | KEY_WOW64_64KEY,
        )
        .map(|key| {
            // SAFETY: ключ открыт выше и закрывается здесь.
            unsafe {
                let _ = RegCloseKey(key);
            }
        })
        .is_some()
    }

    /// Имя значения `Name` из ключа устройства (для `registry.device_name`).
    pub(super) fn read_device_name(device: &str) -> Option<String> {
        read_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"{PASSTHRU_BRANCH}\{device}"),
            "Name",
        )
    }

    /// `FunctionLibrary` из ключа устройства (для `registry.function_library`).
    pub(super) fn read_function_library(device: &str) -> Option<String> {
        read_string(
            HKEY_LOCAL_MACHINE,
            &format!(r"{PASSTHRU_BRANCH}\{device}"),
            "FunctionLibrary",
        )
    }
}

#[cfg(not(windows))]
mod reg {
    #[derive(Debug, Clone, Copy)]
    pub(super) enum RegError {
        AccessDenied,
        Other(u32),
    }

    pub(super) fn is_elevated() -> bool {
        false
    }
    pub(super) fn create_device(_: &str, _: &str, _: &str) -> std::result::Result<(), RegError> {
        Err(RegError::Other(0))
    }
    pub(super) fn delete_device(_: &str) -> std::result::Result<(), RegError> {
        Ok(())
    }
    pub(super) fn read_adapter() -> Option<String> {
        None
    }
    pub(super) fn write_adapter(_: &str) -> std::result::Result<(), RegError> {
        Err(RegError::Other(0))
    }
    pub(super) fn device_exists(_: &str) -> bool {
        false
    }
    pub(super) fn read_device_name(_: &str) -> Option<String> {
        None
    }
    pub(super) fn read_function_library(_: &str) -> Option<String> {
        None
    }
}

/// Прочитать запись устройства из HKLM (или «не зарегистрировано»).
fn read_registry(device: &str) -> ProxyRegistry {
    ProxyRegistry {
        registered: reg::device_exists(device),
        key: format!(r"HKLM\{PASSTHRU_BRANCH}\{device}"),
        device_name: reg::read_device_name(device).unwrap_or_else(|| device.to_string()),
        function_library: reg::read_function_library(device).unwrap_or_default(),
    }
}

// ─────────────────────────── полоса в сессии ─────────────────────────────

struct LogFile {
    mtime: SystemTime,
    path: PathBuf,
}

/// Собрать журналы прокси в полосу сессии (docs/13 §8).
///
/// `None` — в окне сессии журналов не было (прокси не использовался). Ошибки
/// чтения/записи не глотаются: вызывающий решает, писать ли факт в сессию —
/// молчание здесь означало бы «второго канала не было», а это разные вещи.
pub fn collect(session_dir: &Path, started_at: &str, log_dir: &Path) -> Result<Option<ProxyLane>> {
    let (threshold, started_parsed) = start_threshold(started_at);
    let mut files: Vec<LogFile> = Vec::new();
    if let Some(exact) = env_log_file() {
        // Явный путь важнее каталога и окна: так забирают журнал, принесённый
        // с другой машины, где mtime ничего не говорит о старте сессии.
        if let Ok(meta) = std::fs::metadata(&exact) {
            files.push(LogFile {
                mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                path: exact,
            });
        }
    } else if let Ok(read_dir) = std::fs::read_dir(log_dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if !name.starts_with("proxy-") || !name.ends_with(".log") {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            // Окно старта: журнал, созданный задолго до сессии, — от прошлого
            // запуска приложения, и его кадры к этой сессии не относятся.
            if let Some(threshold) = threshold {
                if mtime < threshold {
                    continue;
                }
            }
            files.push(LogFile { mtime, path });
        }
    }
    if files.is_empty() {
        return Ok(None);
    }
    // Склейка по времени: имена содержат время создания, но порядок задаёт
    // mtime — он остаётся верным, даже если файл переименовали руками.
    files.sort_by(|a, b| a.mtime.cmp(&b.mtime).then_with(|| a.path.cmp(&b.path)));

    let mut text = String::new();
    let mut bytes = 0u64;
    for file in &files {
        let data = std::fs::read(&file.path)
            .with_context(|| format!("не прочитать журнал {}", file.path.display()))?;
        bytes += data.len() as u64;
        if !text.is_empty() && !text.ends_with('\n') {
            // Шапка второго журнала начинается с новой строки: иначе
            // `# capture start` приклеится к хвосту предыдущего файла.
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&data));
    }
    std::fs::create_dir_all(session_dir)
        .with_context(|| format!("не создать {}", session_dir.display()))?;
    let raw_path = session_dir.join("raw-proxy.log");
    crate::store::write_text_atomic(&raw_path, &text)
        .with_context(|| format!("не записать {}", raw_path.display()))?;

    let mut lane = ProxyLane {
        files: files.len() as u64,
        bytes,
        ..Default::default()
    };
    if !started_parsed {
        lane.notes.push(
            "время старта сессии не разобрано — взяты все журналы каталога, окно не применялось"
                .into(),
        );
    }

    // Разбор — тем же парсером грамматики, что и обычный raw.log: журнал прокси
    // специально написан в формате docs/11 (docs/13 §6), отдельный разборщик
    // означал бы вторую грамматику и расхождение с полосой frida.
    let events: Vec<crate::models::Event> = text
        .lines()
        .filter_map(crate::decode::parse_capture_line)
        .collect();

    let mut calls_seen: BTreeSet<u64> = BTreeSet::new();
    let mut stop_calls: Option<u64> = None;
    let mut frames: BTreeMap<(u8, String), u64> = BTreeMap::new();
    let mut first: Option<f64> = None;
    let mut last: Option<f64> = None;
    let mut short_frames = 0u64;
    for ev in &events {
        use crate::models::EventKind;
        if matches!(ev.kind, EventKind::Tx | EventKind::Rx) && !ev.hex.is_empty() {
            if is_short(ev) {
                // Обрезанная hex-секция (`hex` короче `len`) — не кадр: сверять
                // половину кадра с полным бессмысленно, а «лишним» он бы стал
                // в чужой полосе. Такие строки считаем отдельно и говорим о них.
                short_frames += 1;
            } else {
                // Пустая полезная нагрузка (`rxs=0x02`, `len=0`) — статус SOF,
                // а не кадр: в счётчики обмена и в сверку он не входит.
                if ev.kind == EventKind::Tx {
                    lane.tx += 1;
                } else {
                    lane.rx += 1;
                }
                first = Some(first.map_or(ev.t, |value| value.min(ev.t)));
                last = Some(last.map_or(ev.t, |value| value.max(ev.t)));
                let dir = if ev.kind == EventKind::Tx { b't' } else { b'r' };
                *frames.entry((dir, normalize_hex(&ev.hex))).or_insert(0) += 1;
            }
        }
        if ev.rc.is_some_and(|rc| rc != 0) || ev.kind == crate::models::EventKind::Error {
            lane.errors += 1;
        }
        if let Some(call) = ev.meta.get("call").and_then(serde_json::Value::as_u64) {
            calls_seen.insert(call);
        }
        let trimmed = ev.raw.trim_start();
        if trimmed.starts_with("# proxy stop") {
            stop_calls = parse_tag_number(trimmed, "calls=");
        }
    }
    lane.first_t = first;
    lane.last_t = last;
    if short_frames > 0 {
        lane.notes.push(format!(
            "пропущено обрезанных кадров: {short_frames} (hex короче объявленного len)"
        ));
    }
    // Итоговая строка самого прокси точнее подсчёта по строкам: вызов может
    // не оставить ни одного кадра (например, `PassThruClose`).
    lane.calls = stop_calls.unwrap_or(calls_seen.len() as u64);

    let main_events = main_channel_events(session_dir);
    if main_events.is_empty() {
        // Сверять не с чем: matched/missing остаются нулями, а `extra` — тоже,
        // потому что «лишний» имеет смысл только относительно второго канала.
        lane.notes.push("нет основного канала".into());
    } else {
        lane.cross = cross(&main_events, &frames);
    }

    let lane_path = session_dir.join("proxy.json");
    crate::store::write_json_atomic(&lane_path, &lane)
        .with_context(|| format!("не записать {}", lane_path.display()))?;
    Ok(Some(lane))
}

/// Сверка полос: сколько кадров основного канала нашлось в прокси и наоборот.
///
/// Мультимножество, а не множество: одинаковые кадры (повтор запроса) должны
/// считаться столько раз, сколько их было, иначе потеря половины обмена
/// выглядела бы как полное совпадение.
fn cross(
    main_events: &[crate::models::Event],
    proxy_frames: &BTreeMap<(u8, String), u64>,
) -> ProxyCross {
    let mut main_frames: BTreeMap<(u8, String), u64> = BTreeMap::new();
    for ev in main_events {
        // Только J2534: в сессии рядом живут COM/LAN/USB-кадры другого канала,
        // и «потерей прокси» они быть не могут. На живом логе PCMflash 22.5 %
        // «потерь» оказались 44 кадрами HTTP-пробы лицензии по Winsock.
        if ev.transport != crate::models::Transport::J2534 {
            continue;
        }
        if !matches!(ev.kind, crate::models::EventKind::Tx | crate::models::EventKind::Rx)
            || ev.hex.is_empty()
            || is_short(ev)
        {
            continue;
        }
        let dir = if ev.kind == crate::models::EventKind::Tx {
            b't'
        } else {
            b'r'
        };
        *main_frames.entry((dir, normalize_hex(&ev.hex))).or_insert(0) += 1;
    }
    let mut out = ProxyCross::default();
    for (key, in_main) in &main_frames {
        let in_proxy = proxy_frames.get(key).copied().unwrap_or(0);
        let matched = (*in_main).min(in_proxy);
        if key.0 == b't' {
            out.tx_matched += matched;
            out.tx_missing += in_main - matched;
        } else {
            out.rx_matched += matched;
            out.rx_missing += in_main - matched;
        }
    }
    let proxy_total: u64 = proxy_frames.values().sum();
    out.extra = proxy_total.saturating_sub(out.tx_matched + out.rx_matched);
    out
}

/// События основного канала: `events.jsonl`, а если он пуст — `raw.log`.
///
/// Второй путь нужен живой сессии и сессиям, у которых `events.jsonl` чинили
/// руками: `raw.log` разбирается тем же `parse_capture_line`, своего парсера нет.
fn main_channel_events(session_dir: &Path) -> Vec<crate::models::Event> {
    let events = crate::store::read_events_dir(session_dir);
    if !events.is_empty() {
        return events;
    }
    let Ok(text) = std::fs::read_to_string(session_dir.join("raw.log")) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(crate::decode::parse_capture_line)
        .collect()
}

/// «00 02 27 7F» → «0002277f»: регистр и пробелы не должны влиять на сверку.
fn normalize_hex(hex: &str) -> String {
    hex.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

/// Кадр, у которого реальных байт меньше объявленного `len` (`short=1`).
///
/// Такую строку парсер разбирает (лучше неполный кадр, чем потеря строки), но
/// опознать её в сверке нельзя: в чужой полосе тот же кадр полный.
fn is_short(ev: &crate::models::Event) -> bool {
    ev.meta
        .get("short")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Первое число после `key` в строке (`calls=2876 tx=…`).
fn parse_tag_number(text: &str, key: &str) -> Option<u64> {
    let start = text.find(key)? + key.len();
    let digits: String = text[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Порог окна сессии: `started_at - 5 c`. Второй элемент — удалось ли разобрать
/// время (иначе окно не применяется, и об этом пишется note).
fn start_threshold(started_at: &str) -> (Option<SystemTime>, bool) {
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(started_at.trim()) else {
        return (None, false);
    };
    let since = parsed - chrono::Duration::seconds(LOG_WINDOW_BACK);
    let millis = since.timestamp_millis();
    if millis < 0 {
        return (None, true);
    }
    let time = SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(millis as u64);
    (Some(time), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_parses_sections_and_comments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let text = "; комментарий\n[proxy]\nEnabled=1\nRealLibrary=C:\\x\\smj2534.dll\nLogDir=%LOCALAPPDATA%\\FTDI_USB_Logger\\j2534proxy\n\n[device]\nName=Scanmatik - SM2 Proxy\nVendor=DaVinci\n";
        std::fs::write(dir.path().join(INI_NAME), text).expect("ini");
        let ini = read_ini(dir.path());
        assert!(ini.present && ini.enabled);
        assert_eq!(ini.name, "Scanmatik - SM2 Proxy");
        assert_eq!(ini.real_library, r"C:\x\smj2534.dll");
        assert_eq!(ini.max_data_bytes, 4128);
    }

    #[test]
    fn normalize_hex_ignores_case_and_spaces() {
        assert_eq!(normalize_hex("00 02 27 7F"), "0002277f");
        assert_eq!(normalize_hex("0002277f"), "0002277f");
    }

    #[test]
    fn cross_ignores_foreign_transport_frames() {
        // Живой лог PCMflash: рядом с K-line в сессии лежат кадры HTTP-пробы
        // лицензии (Winsock). Они не наш канал и «потерей прокси» быть не
        // могут — иначе отчёт показывал 22.5 % потерь на ровном месте.
        let main: Vec<crate::models::Event> = [
            "[+1.000000s] J2534 RX ch=1 proto=0x8003 rxs=0x0 len=5 : 00 03 67 7f 34",
            "[+1.010000s] LAN RX tcp local=10.0.0.118:54009 remote=45.132.18.119:80 len=3 : aa bb cc",
            "[+1.020000s] USBRAW bus=1 dev=2 ep=0x81 transfer=bulk len=2 : 12 04",
        ]
        .iter()
        .filter_map(|line| crate::decode::parse_capture_line(line))
        .collect();
        assert_eq!(main.len(), 3, "все три строки должны разбираться");

        let mut proxy: BTreeMap<(u8, String), u64> = BTreeMap::new();
        proxy.insert((b'r', normalize_hex("00 03 67 7f 34")), 1);
        let cross = cross(&main, &proxy);
        assert_eq!(cross.rx_matched, 1);
        assert_eq!(cross.rx_missing, 0, "LAN/VCP-кадры не должны попадать в сверку");
        assert_eq!(cross.extra, 0);
    }

    #[test]
    fn parse_tag_number_takes_digits_only() {
        assert_eq!(
            parse_tag_number("# proxy stop: calls=2876 tx=1959 rx=3917 errors=0", "calls="),
            Some(2876)
        );
        assert_eq!(parse_tag_number("# proxy stop: tx=1", "calls="), None);
    }

    #[test]
    fn is_truthy_accepts_documented_forms_only() {
        // docs/13 §4: `FTDI_J2534_PROXY_OFF=1`; остальные записи — на всякий
        // случай, но «0» и мусор выключением не считаются.
        for value in ["1", " true ", "YES", "on"] {
            assert!(is_truthy(Some(value)), "{value} должен считаться «да»");
        }
        for value in ["0", "false", "", "нет", "2"] {
            assert!(!is_truthy(Some(value)), "{value} не должен считаться «да»");
        }
        assert!(!is_truthy(None), "переменная не задана — «нет»");
    }

    fn driver(name: &str, dll: &str) -> crate::models::J2534Driver {
        crate::models::J2534Driver {
            name: name.into(),
            dll: dll.into(),
            dll_present: true,
            ..Default::default()
        }
    }

    #[test]
    fn pick_driver_matches_short_registry_name() {
        let drivers = vec![
            driver("CHIPSOFT J2534 ISO/CAN", r"C:\chipsoft\j2534_interface.dll"),
            driver("SM2 USB", r"C:\Scanmatik\smj2534.dll"),
            driver("SM3 USB", r"C:\Scanmatik\smj2534_0403.dll"),
        ];
        // PCMflash пишет длинное имя, ключ в реестре — короткое.
        assert_eq!(
            pick_driver(&drivers, "Scanmatik - SM2 USB").map(|found| found.name.as_str()),
            Some("SM2 USB")
        );
        // Точное совпадение важнее вхождения.
        assert_eq!(
            pick_driver(&drivers, "SM3 USB").map(|found| found.name.as_str()),
            Some("SM3 USB")
        );
        // Незнакомое имя — None: вызывающий возьмёт первый с существующим файлом.
        assert!(pick_driver(&drivers, "VXDIAG").is_none());
    }
}
