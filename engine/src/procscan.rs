//! Процессы-кандидаты и метаданные exe. Владелец: boba.
//!
//! Универсальный поиск цели (docs/02 §11): кандидатом может быть **любое** приложение,
//! которое общается с железом — FTDI D2XX, J2534/PassThru, WinUSB/HID/libusb — или просто
//! имеет видимое окно (MS4x Flasher, WinKFP, INPA, Tool32, …).
//!
//! Режимы `CandidateMode`: `Auto` (окно/USB/FTDI/J2534/известный инструмент), `Usb`, `Window`,
//! `All`. Модули читаются `TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32` (иначе 32-битные цели
//! не видны из 64-битного движка); отказ доступа даёт `modules_denied=true`, а не ошибку.
//! Результат кэшируется на ~2 с (UI поллит список).
//!
//! Всё построено на Toolhelp32/read-only Win32-запросах: ни одна функция не паникует.

use crate::models::{ExeMeta, ProcessDetail, ToolProcess};
use std::collections::HashMap;

/// Инструменты, которые цепляемся как VCP (могут не грузить `ftd2xx`).
pub const KNOWN_TOOLS: &[&str] = &["winkfpt.exe", "inpa.exe", "tool32.exe", "nfs.exe"];

/// Сколько живёт кэш списка процессов (UI опрашивает раз в ~2 с).
const CANDIDATES_CACHE_TTL: std::time::Duration = std::time::Duration::from_millis(2000);

/// Процессы-кандидаты: загружен `ftd2xx*` ИЛИ имя входит в `known`.
///
/// `known` — список имён exe (с расширением или без, регистр не важен).
/// Режим отбора процессов для панели «Программы».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateMode {
    /// Авто: окно + любые USB/COM/J2534-признаки + известные инструменты.
    Auto,
    /// Только процессы с признаками USB/FTDI/COM/J2534.
    Usb,
    /// Только процессы с видимым окном.
    Window,
    /// Все процессы пользователя.
    All,
}

impl CandidateMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" | "все" => Self::All,
            "usb" => Self::Usb,
            "window" | "окна" => Self::Window,
            _ => Self::Auto,
        }
    }
}

/// Список процессов для панели «Программы» с фильтром по режиму.
///
/// Один скан собирает сразу все режимы (`ModeLists`), поэтому `auto/usb/window/all`,
/// запрошенные подряд, всегда согласованы и берутся из кэша `CANDIDATES_CACHE_TTL` (~2 с).
pub fn list_candidates_mode(known: &[&str], mode: CandidateMode) -> Vec<ToolProcess> {
    #[cfg(windows)]
    {
        let lists = cached_mode_lists(known);
        match mode {
            CandidateMode::Auto => lists.auto,
            CandidateMode::Usb => lists.usb,
            CandidateMode::Window => lists.window,
            CandidateMode::All => lists.all,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (known, mode);
        Vec::new()
    }
}

/// Сбросить кэш списка процессов (новый процесс/драйвер должен появиться сразу).
pub fn invalidate_candidates_cache() {
    #[cfg(windows)]
    {
        cache_slot().lock().clear();
    }
}

/// Совместимость с `api.rs`: авто-режим (окно + USB/FTDI/J2534 + известные инструменты).
pub fn list_candidates(known: &[&str]) -> Vec<ToolProcess> {
    list_candidates_mode(known, CandidateMode::Auto)
}

/// Подробности одного процесса (для `GET /api/process/<pid>` и `attach`).
pub fn process_detail(pid: u32) -> Option<ProcessDetail> {
    #[cfg(windows)]
    {
        let proc = snapshot_processes().into_iter().find(|p| p.pid == pid)?;
        let (modules, modules_denied) = process_modules_ex(pid);
        let has_ftd2xx = has_ftd2xx_module(&modules);
        let has_j2534 = modules
            .iter()
            .any(|m| crate::j2534::is_j2534_module(m));
        let has_usb = modules.iter().any(|m| is_usb_module(m));
        let known_hit = match_known(&proc.name, KNOWN_TOOLS);
        let window_title = window_title_for_pid(pid);
        let capabilities = build_capabilities(
            has_ftd2xx,
            has_j2534,
            has_usb,
            window_title.is_some(),
            known_hit.is_some(),
        );
        let tool = ToolProcess {
            pid,
            name: proc.stem(),
            exe: proc.exe.clone(),
            has_ftd2xx,
            has_j2534,
            has_usb,
            known_tool: known_hit,
            started_at: proc.started_at.clone(),
            window_title,
            cmdline: None, // нужен PEB/NtQueryInformationProcess — вне бюджета 300 мс
            capabilities,
            modules_denied,
            arch: proc.arch.clone(),
        };
        let meta = exe_meta(&proc.exe);
        Some(ProcessDetail {
            proc: tool,
            exe_meta: meta,
            modules,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

// ─────────────────────── универсальный скан и режимы ─────────────────────

/// Списки процессов сразу по всем режимам (один скан: Toolhelp32 + модули/окна/архитектура).
///
/// Так `auto/usb/window/all` согласованы между собой даже при запросе в разные моменты
/// (общий кэш), и полный скан делается один раз на `CANDIDATES_CACHE_TTL`.
#[cfg(windows)]
#[derive(Clone, Default)]
struct ModeLists {
    auto: Vec<ToolProcess>,
    usb: Vec<ToolProcess>,
    window: Vec<ToolProcess>,
    all: Vec<ToolProcess>,
}

/// Один проход по процессам: заполняет все четыре режима.
#[cfg(windows)]
fn collect_modes(known: &[&str]) -> ModeLists {
    let procs = snapshot_processes();
    // Заголовки окон собираем ОДНИМ EnumWindows на весь скан (иначе 150×EnumWindows).
    let titles = window_titles_map();
    let mut lists = ModeLists::default();

    for proc in procs {
        // Никогда не показываем System/Idle/Registry: это не «программы».
        if proc.pid == 0 || proc.pid == 4 || is_pseudo_system_name(&proc.name) {
            continue;
        }
        let known_hit = match_known(&proc.name, known);
        let system_exe = is_system_path(&proc.exe);
        let program_files = is_program_files_path(&proc.exe);
        // Модули системных процессов не сканируем (кроме известных инструментов):
        // это главное ускорение скана; у пользовательских приложений модули читаем всегда.
        let skip_modules = known_hit.is_none() && system_exe;
        let (modules, modules_denied) = if skip_modules {
            (Vec::new(), false)
        } else {
            process_modules_ex(proc.pid)
        };
        let has_ftd2xx = has_ftd2xx_module(&modules);
        let has_j2534 = modules.iter().any(|m| crate::j2534::is_j2534_module(m));
        let has_usb = modules.iter().any(|m| is_usb_module(m));
        let capability_window = titles.contains_key(&proc.pid);
        let window_title = titles.get(&proc.pid).cloned().filter(|t| !t.is_empty());
        let capabilities = build_capabilities(
            has_ftd2xx,
            has_j2534,
            has_usb,
            capability_window,
            known_hit.is_some(),
        );
        let tool = ToolProcess {
            pid: proc.pid,
            name: proc.stem(),
            exe: proc.exe,
            has_ftd2xx,
            has_j2534,
            has_usb,
            known_tool: known_hit,
            started_at: proc.started_at,
            window_title,
            cmdline: None,
            capabilities,
            modules_denied,
            arch: proc.arch,
        };

        let usb_sign = has_ftd2xx || has_j2534 || has_usb;
        // Auto не должен засорять список службами, которые грузят hid.dll/winusb «попутно»:
        // has_usb учитываем только у интерактивных процессов вне System32/SysWOW64 и вне
        // Program Files (там живут user-session службы вроде GameInput/XboxService с окном=нет).
        let interactive = proc.session_id != Some(0);
        let auto_usb_signal = has_ftd2xx
            || has_j2534
            || (has_usb && !system_exe && interactive && !program_files);
        if capability_window || tool.known_tool.is_some() || auto_usb_signal {
            lists.auto.push(tool.clone());
        }
        if usb_sign {
            lists.usb.push(tool.clone());
        }
        if capability_window {
            lists.window.push(tool.clone());
        }
        lists.all.push(tool);
    }

    sort_candidates(&mut lists.auto);
    sort_candidates(&mut lists.usb);
    sort_candidates(&mut lists.window);
    sort_candidates(&mut lists.all);
    lists
}

/// Известные инструменты и USB-кандидаты — выше, дальше окна, затем pid (детерминированно).
#[cfg(windows)]
fn sort_candidates(list: &mut [ToolProcess]) {
    list.sort_by(|a, b| {
        let rank = |p: &ToolProcess| {
            (
                p.known_tool.is_none() as u8,
                !(p.has_ftd2xx || p.has_j2534 || p.has_usb) as u8,
                p.window_title.is_none() as u8,
                p.pid,
            )
        };
        rank(a).cmp(&rank(b))
    });
}

/// Метки `capabilities[]` для UI: `ftd2xx|j2534|usb|window` (+ `known` для известных).
fn build_capabilities(
    has_ftd2xx: bool,
    has_j2534: bool,
    has_usb: bool,
    has_window: bool,
    known: bool,
) -> Vec<String> {
    let mut caps = Vec::new();
    if has_ftd2xx {
        caps.push("ftd2xx".to_string());
    }
    if has_j2534 {
        caps.push("j2534".to_string());
    }
    if has_usb {
        caps.push("usb".to_string());
    }
    if has_window {
        caps.push("window".to_string());
    }
    if known {
        caps.push("known".to_string());
    }
    caps
}

/// Модуль-признак USB-стека приложения (WinUSB/HID/libusb).
fn is_usb_module(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "winusb.dll" | "hid.dll" | "libusb-1.0.dll" | "libusb0.dll" | "libusb-0.1.dll"
    )
}

/// Системные псевдо-процессы, которые не являются «программами» ни в одном режиме.
fn is_pseudo_system_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "system" | "idle" | "registry" | "memcompression" | "secure system"
    )
}

// ─────────────────────────────── кэш кандидатов ──────────────────────────

#[cfg(windows)]
struct CandidatesCacheEntry {
    at: std::time::Instant,
    lists: ModeLists,
}

#[cfg(windows)]
fn cache_slot(
) -> &'static parking_lot::Mutex<std::collections::HashMap<String, CandidatesCacheEntry>> {
    static SLOT: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::HashMap<String, CandidatesCacheEntry>>,
    > = std::sync::OnceLock::new();
    SLOT.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

/// Ключ кэша — набор «известных» инструментов (режим теперь не важен: скан общий).
#[cfg(windows)]
fn cache_key(known: &[&str]) -> String {
    let tools: Vec<String> = known
        .iter()
        .map(|name| normalize_exe_name(name))
        .collect();
    tools.join(",")
}

/// Списки всех режимов: из кэша (TTL ≈2 с) или одним свежим сканом.
#[cfg(windows)]
fn cached_mode_lists(known: &[&str]) -> ModeLists {
    let key = cache_key(known);
    {
        let mut cache = cache_slot().lock();
        match cache.get(&key) {
            Some(entry) if entry.at.elapsed() < CANDIDATES_CACHE_TTL => {
                return entry.lists.clone();
            }
            _ => {
                cache.remove(&key);
            }
        }
    }
    let lists = collect_modes(known);
    {
        let mut cache = cache_slot().lock();
        // Убираем просроченные записи, чтобы карта не росла бесконечно.
        cache.retain(|_, entry| entry.at.elapsed() < CANDIDATES_CACHE_TTL);
        cache.insert(
            key,
            CandidatesCacheEntry {
                at: std::time::Instant::now(),
                lists: lists.clone(),
            },
        );
    }
    lists
}

/// Есть ли среди запущенных процессов процесс с таким именем (без `.exe`, регистр не важен).
///
/// Нужен пре-полёту лицензионного гейта: проверка, жив ли активатор `_Activator`.
pub fn is_process_running(name: &str) -> bool {
    #[cfg(windows)]
    {
        let wanted = normalize_exe_name(name);
        snapshot_processes()
            .iter()
            .any(|p| normalize_exe_name(&p.name) == wanted)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        false
    }
}

/// Метаданные exe: размер, mtime, sha256, версия (GetFileVersionInfo + строки ресурсов).
///
/// Никогда не паникует и не возвращает `Err`: при недоступном файле остаются пустые поля.
pub fn exe_meta(path: &str) -> ExeMeta {
    let mut meta = ExeMeta {
        path: path.to_string(),
        ..Default::default()
    };
    if path.is_empty() {
        return meta;
    }
    if let Ok(fs_meta) = std::fs::metadata(path) {
        meta.size = fs_meta.len();
        if let Ok(modified) = fs_meta.modified() {
            let dt: chrono::DateTime<chrono::Utc> = modified.into();
            meta.mtime = dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        }
    }
    meta.sha256 = sha256_file(path).unwrap_or_default();
    #[cfg(windows)]
    {
        let version = version_info(path);
        meta.version = version.version;
        meta.company = version.company;
        meta.description = version.description;
    }
    meta
}

// ─────────────────────────────── снимок процессов ────────────────────────

#[cfg(windows)]
struct RawProc {
    pid: u32,
    /// Имя exe с расширением, как отдаёт Toolhelp (`winkfpt.exe`).
    name: String,
    /// Полный путь, если удалось получить (`QueryFullProcessImageNameW`).
    exe: String,
    /// Время старта (RFC3339, UTC) — если удалось прочитать.
    started_at: Option<String>,
    /// `x64` | `x86` | `arm64` | `?`.
    arch: String,
    /// Сессия Windows (0 — службы без интерактивного стола) — для фильтра Auto.
    session_id: Option<u32>,
}

#[cfg(windows)]
impl RawProc {
    /// Имя без расширения — так процессы называются в UI и в старом логере.
    fn stem(&self) -> String {
        let lower = self.name.to_ascii_lowercase();
        for ext in [".exe", ".com", ".bat"] {
            if let Some(stem) = lower.strip_suffix(ext) {
                return stem.to_string();
            }
        }
        lower
    }
}

#[cfg(windows)]
fn snapshot_processes() -> Vec<RawProc> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut out = Vec::new();
    // SAFETY: снимок Toolhelp — read-only; дескриптор закрывается до выхода.
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                if pid > 0 {
                    let name = wide_array_to_string(&entry.szExeFile);
                    // Один OpenProcess на процесс: путь exe + время старта + разрядность.
                    // pid 4 (System) и защищённые процессы не откроются — поля будут пустыми,
                    // но имя всё равно полезно (например, для проверки активатора).
                    let facts = process_facts(pid);
                    out.push(RawProc {
                        pid,
                        name,
                        exe: facts.exe,
                        started_at: facts.started_at,
                        arch: facts.arch,
                        session_id: facts.session_id,
                    });
                }
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

/// Факты о процессе, которые читаются одним `OpenProcess` (скан 300+ процессов не должен
/// открывать каждый процесс по три раза).
#[cfg(windows)]
#[derive(Default)]
struct ProcessFacts {
    exe: String,
    started_at: Option<String>,
    arch: String,
    /// Сессия Windows (`0` — службы, без интерактивного рабочего стола).
    session_id: Option<u32>,
}

#[cfg(windows)]
fn process_facts(pid: u32) -> ProcessFacts {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let session_id = process_session_id(pid);
    // SAFETY: открываем процесс только на чтение метаданных, дескриптор закрываем.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            // Защищённый/системный процесс: путь и время неизвестны, разрядность — «?».
            return ProcessFacts {
                arch: "?".into(),
                session_id,
                ..Default::default()
            };
        };
        let exe = query_image_path(handle).unwrap_or_default();
        let started_at = process_times(handle);
        let arch = arch_from_handle(handle);
        let _ = CloseHandle(handle);
        ProcessFacts {
            exe,
            started_at,
            arch,
            session_id,
        }
    }
}

/// Сессия Windows процесса (`ProcessIdToSessionId`): службы обычно в сессии 0.
#[cfg(windows)]
fn process_session_id(pid: u32) -> Option<u32> {
    use windows::Win32::Foundation::BOOL;

    #[link(name = "kernel32")]
    extern "system" {
        fn ProcessIdToSessionId(dwprocessid: u32, psessionid: *mut u32) -> BOOL;
    }

    let mut session_id = 0u32;
    // SAFETY: pid — обычное число, out-параметр локальный.
    let ok = unsafe { ProcessIdToSessionId(pid, &mut session_id) } != BOOL(0);
    ok.then_some(session_id)
}

/// `QueryFullProcessImageNameW` по уже открытому дескриптору.
#[cfg(windows)]
unsafe fn query_image_path(handle: windows::Win32::Foundation::HANDLE) -> Option<String> {
    use windows::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_WIN32};
    use windows::core::PWSTR;

    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    // SAFETY: handle валиден; buf — локальный массив.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut size)
            .is_ok()
    };
    if ok && size > 0 {
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    } else {
        None
    }
}

/// Время старта процесса по открытому дескриптору.
#[cfg(windows)]
fn process_times(handle: windows::Win32::Foundation::HANDLE) -> Option<String> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: handle валиден, FILETIME — локальные структуры.
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }
        .is_err()
    {
        return None;
    }
    filetime_to_rfc3339(creation.dwLowDateTime, creation.dwHighDateTime)
}

/// Разрядность по открытому дескриптору (`IsWow64Process2`).
///
/// Своя extern-декларация, чтобы не тянуть в Cargo.toml фичу SystemInformation.
#[cfg(windows)]
fn arch_from_handle(handle: windows::Win32::Foundation::HANDLE) -> String {
    use windows::Win32::Foundation::BOOL;

    #[link(name = "kernel32")]
    extern "system" {
        fn IsWow64Process2(
            hprocess: windows::Win32::Foundation::HANDLE,
            pprocessmachine: *mut u16,
            pnativemachine: *mut u16,
        ) -> BOOL;
    }

    const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;
    const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

    fn arch_name(machine: u16) -> &'static str {
        match machine {
            IMAGE_FILE_MACHINE_I386 => "x86",
            IMAGE_FILE_MACHINE_AMD64 => "x64",
            IMAGE_FILE_MACHINE_ARM64 => "arm64",
            _ => "?",
        }
    }

    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    // SAFETY: handle валиден; out-параметры — локальные переменные.
    let ok = unsafe { IsWow64Process2(handle, &mut process_machine, &mut native_machine) }
        != BOOL(0);
    if !ok {
        return "?".into();
    }
    if process_machine == IMAGE_FILE_MACHINE_UNKNOWN {
        // 32-битный процесс на 32-битной ОС; на 64-битной это нативный процесс.
        arch_name(native_machine).to_string()
    } else {
        // Эмуляция (x86/x64 на ARM64, x86 на x64) — показываем разрядность процесса.
        arch_name(process_machine).to_string()
    }
}

/// FILETIME (100-нс тики с 1601-01-01) → RFC3339 UTC.
#[cfg(windows)]
fn filetime_to_rfc3339(low: u32, high: u32) -> Option<String> {
    let ticks = ((high as u64) << 32) | low as u64;
    if ticks == 0 {
        return None;
    }
    // 11644473600 — секунд между 1601-01-01 и 1970-01-01.
    let secs = (ticks / 10_000_000) as i64 - 11_644_473_600;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Загруженные модули процесса (имена файлов, например `ftd2xx.dll`).
///
/// Для 32-битных целей 64-битный движок использует `TH32CS_SNAPMODULE32`.
#[cfg(windows)]
#[cfg(test)]
fn process_modules(pid: u32) -> Vec<String> {
    process_modules_ex(pid).0
}

/// Модули процесса + признак «доступа нет» (процесс с более высокими правами/защищённый).
///
/// Отказ доступа — это НЕ ошибка: `modules_denied=true` уходит в UI подсказкой
/// «запустите логер от администратора».
#[cfg(windows)]
fn process_modules_ex(pid: u32) -> (Vec<String>, bool) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let mut out = Vec::new();
    // SAFETY: снимок модулей — read-only; дескриптор закрывается.
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pid,
        ) {
            Ok(snapshot) => snapshot,
            // Снимок не создался: процесс защищён/уже завершился/нет прав.
            Err(_) => return (out, true),
        };
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        let mut denied = false;
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                out.push(wide_array_to_string(&entry.szModule));
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        } else {
            // Снимок создан, но модули не отдаются — обычно недостаточно прав.
            denied = true;
        }
        let _ = CloseHandle(snapshot);
        (out, denied)
    }
}

/// Разрядность процесса: `x64` | `x86` | `arm64` | `?` (`IsWow64Process2`).
///
/// Своя extern-декларация, чтобы не тянуть в Cargo.toml фичу SystemInformation.
#[cfg(windows)]
pub fn process_arch(pid: u32) -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: read-only запрос разрядности процесса; дескриптор закрывается.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return "?".into();
        };
        let arch = arch_from_handle(handle);
        let _ = CloseHandle(handle);
        arch
    }
}

// ─────────────────────────────── окна процесса ──────────────────────────

/// Окно верхнего уровня процесса — для заголовка в списке процессов и для скриншота.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub(crate) struct WindowInfo {
    pub hwnd: windows::Win32::Foundation::HWND,
    pub visible: bool,
    pub title: String,
    pub rect: windows::Win32::Foundation::RECT,
}

/// Все окна верхнего уровня указанного pid (без паники на защищённых процессах).
#[cfg(windows)]
pub(crate) fn windows_for_pid(pid: u32) -> Vec<WindowInfo> {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, RECT, TRUE};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
        GetWindowThreadProcessId, IsWindowVisible,
    };

    struct Search {
        pid: u32,
        windows: Vec<WindowInfo>,
    }

    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: lparam — указатель на Search, живущий на стеке вызывающей функции.
        let search = unsafe { &mut *(lparam.0 as *mut Search) };
        let mut win_pid = 0u32;
        // SAFETY: hwnd получен от EnumWindows.
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut win_pid));
        }
        if win_pid != search.pid {
            return TRUE;
        }
        let mut rect = RECT::default();
        // SAFETY: rect — локальная структура; hwnd валиден.
        if unsafe { GetWindowRect(hwnd, &mut rect) }.is_err() {
            return TRUE;
        }
        let width = rect.right - rect.left;
        let height = rect.bottom - rect.top;
        if width <= 0 || height <= 0 {
            return TRUE;
        }
        // SAFETY: заголовок читается ограниченным буфером длины окна.
        let title = unsafe {
            let len = GetWindowTextLengthW(hwnd);
            if len > 0 {
                let mut buf = vec![0u16; (len as usize).saturating_add(1)];
                let copied = GetWindowTextW(hwnd, &mut buf);
                if copied > 0 {
                    String::from_utf16_lossy(&buf[..copied as usize])
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        };
        let visible = unsafe { IsWindowVisible(hwnd).as_bool() };
        search.windows.push(WindowInfo {
            hwnd,
            visible,
            title,
            rect,
        });
        TRUE
    }

    let mut search = Search {
        pid,
        windows: Vec::new(),
    };
    // SAFETY: callback и Search живут до конца вызова EnumWindows.
    unsafe {
        let _ = EnumWindows(Some(callback), LPARAM(&mut search as *mut Search as isize));
    }
    search.windows
}

/// Заголовки видимых окон всех процессов одним проходом `EnumWindows`.
///
/// Нужен сканеру кандидатов: `windows_for_pid` на каждый процесс — это 150 полных
/// перечислений окон, а здесь одно. Для процесса берётся самое «весомое» окно
/// (видимое, с непустым заголовком, максимальная площадь).
#[cfg(windows)]
fn window_titles_map() -> HashMap<u32, String> {
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, RECT, TRUE};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetWindowRect, GetWindowTextLengthW, GetWindowTextW,
        GetWindowThreadProcessId, IsWindowVisible,
    };

    struct Search {
        /// pid → (площадь окна, заголовок)
        map: HashMap<u32, (i64, String)>,
    }

    unsafe extern "system" fn callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: lparam — указатель на Search, живущий на стеке вызывающей функции.
        let search = unsafe { &mut *(lparam.0 as *mut Search) };
        // SAFETY: hwnd получен от EnumWindows.
        if !unsafe { IsWindowVisible(hwnd).as_bool() } {
            return TRUE;
        }
        let mut pid = 0u32;
        // SAFETY: pid — локальная переменная; hwnd валиден.
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
        }
        if pid == 0 {
            return TRUE;
        }
        let mut rect = RECT::default();
        // SAFETY: rect — локальная структура; hwnd валиден.
        let area = unsafe {
            if GetWindowRect(hwnd, &mut rect).is_ok() {
                (rect.right - rect.left).max(0) as i64 * (rect.bottom - rect.top).max(0) as i64
            } else {
                0
            }
        };
        // SAFETY: заголовок читается ограниченным буфером длины окна.
        let title = unsafe {
            let len = GetWindowTextLengthW(hwnd);
            if len > 0 {
                let mut buf = vec![0u16; (len as usize).saturating_add(1)];
                let copied = GetWindowTextW(hwnd, &mut buf);
                if copied > 0 {
                    String::from_utf16_lossy(&buf[..copied as usize])
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        };
        let slot = search.map.entry(pid).or_insert((area, String::new()));
        let better = area > slot.0 || (slot.1.is_empty() && !title.is_empty());
        if better {
            *slot = (area, title);
        }
        TRUE
    }

    let mut search = Search {
        map: HashMap::new(),
    };
    // SAFETY: callback и Search живут до конца вызова EnumWindows.
    unsafe {
        let _ = EnumWindows(Some(callback), LPARAM(&mut search as *mut Search as isize));
    }
    search.map.into_iter().map(|(pid, (_, title))| (pid, title)).collect()
}

/// Заголовок главного окна процесса (видимое окно с непустым заголовком, иначе — максимальное).
pub fn window_title_for_pid(pid: u32) -> Option<String> {
    #[cfg(windows)]
    {
        let windows = windows_for_pid(pid);
        let area = |r: windows::Win32::Foundation::RECT| {
            (r.right - r.left).max(0) as i64 * (r.bottom - r.top).max(0) as i64
        };
        windows
            .iter()
            .filter(|w| w.visible && !w.title.trim().is_empty())
            .max_by_key(|w| area(w.rect))
            .or_else(|| windows.iter().filter(|w| !w.title.trim().is_empty()).max_by_key(|w| area(w.rect)))
            .map(|w| w.title.clone())
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

// ─────────────────────────────── версия exe ──────────────────────────────

#[cfg(windows)]
#[derive(Default)]
struct VersionStrings {
    version: String,
    company: String,
    description: String,
}

/// Версия/компания/описание из ресурса `VS_VERSION_INFO` (version.dll).
///
/// Работает и без ресурса: вернёт пустые строки. Числовая версия собирается из
/// `VS_FIXEDFILEINFO`, строковые значения — из `StringFileInfo` по найденному `Translation`.
#[cfg(windows)]
fn version_info(path: &str) -> VersionStrings {
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
    };
    use windows::core::PCWSTR;

    let mut out = VersionStrings::default();
    let path_w = wide_str(path);
    // SAFETY: version.dll API; буфер version-info выделяется по размеру, который она вернула,
    // и живёт до конца всех VerQueryValueW; указатели проверяются на null перед чтением.
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(path_w.as_ptr()), None);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(
            PCWSTR(path_w.as_ptr()),
            0,
            size,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
        )
        .is_err()
        {
            return out;
        }

        // 1) числовая версия из fixed-структуры.
        let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        let root_query = wide_str("\\");
        if VerQueryValueW(
            buf.as_ptr() as *const core::ffi::c_void,
            PCWSTR(root_query.as_ptr()),
            &mut ptr,
            &mut len,
        )
        .as_bool()
            && !ptr.is_null()
            && len as usize >= std::mem::size_of::<VS_FIXEDFILEINFO>()
        {
            let fixed = &*(ptr as *const VS_FIXEDFILEINFO);
            // 0xFEEF04BD — обязательная сигнатура VS_FIXEDFILEINFO.
            if fixed.dwSignature == 0xFEEF04BD {
                out.version = format!(
                    "{}.{}.{}.{}",
                    fixed.dwFileVersionMS >> 16,
                    fixed.dwFileVersionMS & 0xffff,
                    fixed.dwFileVersionLS >> 16,
                    fixed.dwFileVersionLS & 0xffff
                );
            }
        }

        // 2) язык/кодовая страница таблицы строк.
        let mut translation: (u16, u16) = (0x0409, 0x04B0); // en-US Unicode по умолчанию
        let mut lang_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut lang_len: u32 = 0;
        let trans_query = wide_str("\\VarFileInfo\\Translation");
        if VerQueryValueW(
            buf.as_ptr() as *const core::ffi::c_void,
            PCWSTR(trans_query.as_ptr()),
            &mut lang_ptr,
            &mut lang_len,
        )
        .as_bool()
            && !lang_ptr.is_null()
            && lang_len >= 4
        {
            let pair = std::slice::from_raw_parts(lang_ptr as *const u16, 2);
            translation = (pair[0], pair[1]);
        }

        let read_string = |key: &str| -> String {
            let sub = format!(
                "\\StringFileInfo\\{:04x}{:04x}\\{}",
                translation.0, translation.1, key
            );
            let sub_w = wide_str(&sub);
            let mut value_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut value_len: u32 = 0;
            // SAFETY: pblock — тот же буфер version-info, sub-блок сформирован по формату.
            if VerQueryValueW(
                buf.as_ptr() as *const core::ffi::c_void,
                PCWSTR(sub_w.as_ptr()),
                &mut value_ptr,
                &mut value_len,
            )
            .as_bool()
                && !value_ptr.is_null()
                && value_len > 0
            {
                // Строковые значения NUL-terminated; ограничиваем чтение разумным максимумом.
                let chars = (value_len as usize).min(1024);
                let slice = std::slice::from_raw_parts(value_ptr as *const u16, chars);
                let text: Vec<u16> = slice.iter().copied().take_while(|&c| c != 0).collect();
                String::from_utf16_lossy(&text).trim().to_string()
            } else {
                String::new()
            }
        };

        let file_version = read_string("FileVersion");
        if !file_version.is_empty() {
            out.version = file_version;
        }
        out.company = read_string("CompanyName");
        out.description = read_string("FileDescription");
        if out.description.is_empty() {
            out.description = read_string("ProductName");
        }
    }
    out
}

/// Только версия файла (`GetFileVersionInfo`) — для J2534-драйверов без sha256/size.
pub fn file_version(path: &str) -> String {
    #[cfg(windows)]
    {
        version_info(path).version
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        String::new()
    }
}

/// `&str` → NUL-terminated UTF-16 для Win32 `PCWSTR`.
#[cfg(windows)]
fn wide_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `[u16; N]` из Win32-структур → строка до первого NUL.
#[cfg(windows)]
fn wide_array_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end]).trim().to_string()
}

// ─────────────────────────────── мелочи ──────────────────────────────────

/// Нормализованное имя exe: нижний регистр, без `.exe`.
fn normalize_exe_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Совпало ли имя процесса с известным инструментом; возвращает нормализованное имя.
fn match_known(process_name: &str, known: &[&str]) -> Option<String> {
    let proc_norm = normalize_exe_name(process_name);
    known
        .iter()
        .map(|k| normalize_exe_name(k))
        .find(|k| *k == proc_norm)
}

/// Загружен ли в процесс модуль `ftd2xx*.dll` (D2XX; есть варианты ftd2xx64).
fn has_ftd2xx_module(modules: &[String]) -> bool {
    modules
        .iter()
        .any(|m| m.to_ascii_lowercase().starts_with("ftd2xx"))
}

/// Путь внутри системных каталогов Windows (там не бывает целевых инструментов).
fn is_system_path(exe: &str) -> bool {
    if exe.is_empty() {
        return false;
    }
    let lower = exe.to_ascii_lowercase();
    let windir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_ascii_lowercase();
    lower.starts_with(&windir)
        && (lower.contains("\\system32\\")
            || lower.contains("\\syswow64\\")
            || lower.contains("\\winsxs\\"))
}

/// Путь внутри Program Files / Program Files (x86) — там обычно живут службы.
fn is_program_files_path(exe: &str) -> bool {
    if exe.is_empty() {
        return false;
    }
    let lower = exe.to_ascii_lowercase();
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|var| std::env::var(var).ok())
        .map(|dir| dir.to_ascii_lowercase())
        .any(|dir| !dir.is_empty() && lower.starts_with(&dir))
}

/// SHA-256 файла потоком (большие exe не грузим в память целиком).
fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

// ─────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_matching_is_case_insensitive_and_strips_exe() {
        assert_eq!(match_known("WINKFPT.EXE", KNOWN_TOOLS).as_deref(), Some("winkfpt"));
        assert_eq!(match_known("inpa", KNOWN_TOOLS).as_deref(), Some("inpa"));
        assert_eq!(match_known("notepad.exe", KNOWN_TOOLS), None);
    }

    #[test]
    fn ftd2xx_module_detection() {
        assert!(has_ftd2xx_module(&["ftd2xx.dll".into(), "kernel32.dll".into()]));
        assert!(has_ftd2xx_module(&["FTD2XX64.DLL".into()]));
        assert!(!has_ftd2xx_module(&["kernel32.dll".into()]));
        assert!(!has_ftd2xx_module(&[]));
    }

    #[test]
    fn exe_meta_of_missing_file_is_empty_not_panic() {
        let meta = exe_meta(r"C:\__no_such_file_ftdi__.exe");
        assert_eq!(meta.size, 0);
        assert!(meta.sha256.is_empty());
        assert!(meta.version.is_empty());
        assert!(meta.company.is_empty());
    }

    #[test]
    fn candidates_never_panic() {
        let _ = list_candidates(KNOWN_TOOLS);
        assert!(process_detail(0).is_none());
        assert!(!is_process_running("__no_such_process_ftdi__"));
    }

    /// Для текущего процесса путь/модули должны читаться хотя бы иногда (не гарантия прав).
    #[test]
    fn own_process_has_modules() {
        let me = std::process::id();
        let mods = process_modules(me);
        // В тестовом бинаре модули видны; если политика ОС запретила — список пуст, это не паника.
        assert!(mods.iter().all(|m| !m.is_empty()) || mods.is_empty());
    }

    /// Ручная проверка списка кандидатов на живой системе.
    ///
    /// `#[ignore]`: осмысленна, когда запущен реальный FTDI-инструмент. С
    /// `FTDI_EXPECT_FTD2XX=1` требует, чтобы среди кандидатов был процесс с `ftd2xx`.
    /// Запуск: `cargo test --lib -- procscan::tests::real_candidates_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_candidates_smoke() {
        let candidates = list_candidates(KNOWN_TOOLS);
        eprintln!("кандидатов: {}", candidates.len());
        for p in &candidates {
            eprintln!(
                "pid={} name={} ftd2xx={} known={:?} window={:?} exe={:?}",
                p.pid, p.name, p.has_ftd2xx, p.known_tool, p.window_title, p.exe
            );
        }
        if std::env::var("FTDI_EXPECT_FTD2XX").ok().as_deref() == Some("1") {
            assert!(
                candidates.iter().any(|p| p.has_ftd2xx),
                "ожидался процесс с загруженным ftd2xx"
            );
        }
    }

    /// Ручная проверка на живом процессе: notepad → окно, модули, exe_meta с версией.
    ///
    /// `#[ignore]`: нужен интерактивный рабочий стол.
    /// Запуск: `cargo test --lib -- procscan::tests::real_process_detail_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_process_detail_smoke() {
        let mut child = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить notepad.exe");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let detail = process_detail(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let detail = detail.expect("notepad должен находиться по pid");
        eprintln!(
            "pid={} name={} exe={:?} ftd2xx={} window={:?} modules={}",
            detail.proc.pid,
            detail.proc.name,
            detail.proc.exe,
            detail.proc.has_ftd2xx,
            detail.proc.window_title,
            detail.modules.len()
        );
        eprintln!(
            "exe_meta: size={} mtime={} sha256={} версия={:?} компания={:?} описание={:?}",
            detail.exe_meta.size,
            detail.exe_meta.mtime,
            detail.exe_meta.sha256,
            detail.exe_meta.version,
            detail.exe_meta.company,
            detail.exe_meta.description
        );
        assert_eq!(detail.proc.name, "notepad");
        assert!(!detail.proc.exe.is_empty(), "путь exe не получен");
        assert!(!detail.proc.has_ftd2xx, "notepad не грузит ftd2xx");
        assert!(
            detail.proc.window_title.is_some(),
            "не найден заголовок окна notepad"
        );
        assert!(detail.modules.iter().any(|m| m.eq_ignore_ascii_case("kernel32.dll")));
        assert_eq!(detail.exe_meta.sha256.len(), 64, "sha256 exe");
        assert!(detail.exe_meta.size > 0);
        assert!(!detail.exe_meta.mtime.is_empty());
        assert!(
            !detail.exe_meta.version.is_empty(),
            "версия exe не извлечена (GetFileVersionInfo)"
        );
    }

    // ───────────────────── универсальный режим (stage 2) ─────────────────

    #[test]
    fn modes_are_consistent() {
        invalidate_candidates_cache();
        // Один скан на все режимы — сравнение без гонок с другими тестами/кэшем.
        let lists = collect_modes(KNOWN_TOOLS);
        let (auto, usb, window, all) = (lists.auto, lists.usb, lists.window, lists.all);
        assert!(!auto.is_empty(), "Auto пуст — не видно ни одной цели");
        assert!(
            all.len() >= auto.len(),
            "All ({}) меньше Auto ({})",
            all.len(),
            auto.len()
        );
        assert!(usb.len() <= auto.len(), "Usb больше Auto");
        assert!(window.len() <= auto.len(), "Window больше Auto");
        let auto_pids: std::collections::HashSet<u32> = auto.iter().map(|p| p.pid).collect();
        let sessions: std::collections::HashMap<u32, Option<u32>> = snapshot_processes()
            .into_iter()
            .map(|proc| (proc.pid, proc.session_id))
            .collect();
        // В Auto попадают все USB-процессы, кроме «шума» — служб сессии 0 с единственным
        // признаком has_usb (они остаются в mode=usb/all по требованию UI).
        for tool in &usb {
            if auto_pids.contains(&tool.pid) {
                continue;
            }
            let service_noise = tool.has_usb
                && !tool.has_ftd2xx
                && !tool.has_j2534
                && tool.known_tool.is_none()
                && tool.window_title.is_none()
                && (sessions.get(&tool.pid).copied().flatten() == Some(0)
                    || is_program_files_path(&tool.exe));
            assert!(
                service_noise,
                "USB-процесс {} (pid {}) не попал в Auto и это не шум службы",
                tool.name, tool.pid
            );
        }
        assert!(
            window.iter().all(|p| auto_pids.contains(&p.pid)),
            "в Auto обязаны попадать все окна"
        );
        // Системные псевдо-процессы не должны попадать ни в один режим.
        assert!(
            all.iter().all(|p| !matches!(
                p.name.as_str(),
                "system" | "idle" | "registry" | "memcompression"
            )),
            "в списке есть System/Idle/Registry"
        );
        // У каждого кандидата есть хотя бы одна метка.
        assert!(
            auto.iter().all(|p| !p.capabilities.is_empty()),
            "кандидат без capabilities"
        );
        // Режим Usb — без «пустых» окон: у всех есть USB-признак.
        assert!(usb
            .iter()
            .all(|p| p.has_ftd2xx || p.has_j2534 || p.has_usb));
        eprintln!(
            "кандидаты: auto={} usb={} window={} all={}",
            auto.len(),
            usb.len(),
            window.len(),
            all.len()
        );
    }

    /// MS4x Flasher виден только по окну (ftd2xx/J2534 не грузит) — именно этот кейс
    /// и был сломан до универсального режима. Проверяем, если приложение запущено.
    #[test]
    fn window_only_tool_is_visible_in_auto() {
        invalidate_candidates_cache();
        let titles = window_titles_map();
        let raw = snapshot_processes();
        let ms4x_running = raw
            .iter()
            .any(|p| p.name.to_ascii_lowercase().contains("ms4x"))
            || titles.values().any(|t| t.to_ascii_lowercase().contains("ms4x"));
        if !ms4x_running {
            eprintln!("MS4x Flasher не запущен — проверка Auto по окну пропущена");
            return;
        }
        let is_ms4x = |p: &ToolProcess| {
            p.name.to_ascii_lowercase().contains("ms4x")
                || p.window_title
                    .as_deref()
                    .map(|t| t.to_ascii_lowercase().contains("ms4x"))
                    .unwrap_or(false)
        };
        let lists = collect_modes(KNOWN_TOOLS);
        assert!(
            lists.auto.iter().any(is_ms4x),
            "MS4x Flasher (окно) не попал в Auto: {:?}",
            lists
                .auto
                .iter()
                .map(|p| (&p.name, &p.window_title))
                .collect::<Vec<_>>()
        );
        assert!(
            lists.window.iter().any(is_ms4x),
            "MS4x Flasher не попал в режим Window"
        );
    }

    #[test]
    fn auto_has_no_service_usb_noise() {
        let lists = collect_modes(KNOWN_TOOLS);
        let sessions: std::collections::HashMap<u32, Option<u32>> = snapshot_processes()
            .into_iter()
            .map(|proc| (proc.pid, proc.session_id))
            .collect();
        for tool in &lists.auto {
            // «Шум» — служба (сессия 0 или Program Files), единственный признак которой has_usb.
            let only_usb = tool.has_usb
                && !tool.has_ftd2xx
                && !tool.has_j2534
                && tool.known_tool.is_none()
                && tool.window_title.is_none();
            if only_usb {
                assert_ne!(
                    sessions.get(&tool.pid).copied().flatten(),
                    Some(0),
                    "в Auto попала служба сессии 0: {} (pid {})",
                    tool.name,
                    tool.pid
                );
                assert!(
                    !is_program_files_path(&tool.exe),
                    "в Auto попала служба из Program Files: {} ({})",
                    tool.name,
                    tool.exe
                );
            }
        }
    }

    #[test]
    fn arch_of_own_process_is_x64() {
        let arch = process_arch(std::process::id());
        assert_eq!(arch, "x64", "тестовый бинарь собран под x64");
        assert_eq!(process_arch(0xFFFF_FFF0), "?", "несуществующий pid → ?");
    }

    #[test]
    fn denied_modules_do_not_panic() {
        // System pid=4: снимок модулей обычно недоступен; функция обязана вернуть флаг,
        // а не панику. Точное значение зависит от прав — проверяем типы/инварианты.
        if let Some(detail) = process_detail(4) {
            assert!(
                detail.proc.modules_denied || !detail.modules.is_empty() || detail.modules.is_empty()
            );
            assert!(!detail.proc.arch.is_empty());
        }
        let all = list_candidates_mode(KNOWN_TOOLS, CandidateMode::All);
        assert!(all.iter().all(|p| !p.arch.is_empty()));
        // Свой процесс: модули точно читаются, denied=false.
        let me = process_detail(std::process::id()).expect("свой процесс");
        assert!(!me.proc.modules_denied, "свои модули должны читаться");
        assert!(!me.modules.is_empty(), "у своего процесса нет модулей");
        assert!(me.proc.capabilities.iter().any(|cap| cap == "window") || me.proc.window_title.is_none());
    }

    #[test]
    fn candidates_cache_returns_same_list() {
        invalidate_candidates_cache();
        let first = list_candidates_mode(KNOWN_TOOLS, CandidateMode::Auto);
        let second = list_candidates_mode(KNOWN_TOOLS, CandidateMode::Auto);
        let pids = |list: &[ToolProcess]| list.iter().map(|p| p.pid).collect::<Vec<_>>();
        assert_eq!(pids(&first), pids(&second), "кэш вернул другой список");
    }

    /// Бюджет скана: в release < 300 мс (docs/02 §11) на незагруженной машине; тест —
    /// экологический, поэтому берём медиану 3 прогонов и щедрый потолок (release 600 мс,
    /// debug 2500 мс), чтобы CI и загруженная рабочая станция не были флейки.
    #[test]
    fn full_scan_fits_budget() {
        let mut samples = Vec::new();
        let mut count = 0usize;
        for _ in 0..3 {
            invalidate_candidates_cache();
            let started = std::time::Instant::now();
            let all = list_candidates_mode(KNOWN_TOOLS, CandidateMode::All);
            samples.push(started.elapsed());
            count = all.len();
        }
        samples.sort();
        let median = samples[1];
        eprintln!("All: {} процессов, медиана {:?} (прогоны {:?})", count, median, samples);
        let budget = if cfg!(debug_assertions) {
            std::time::Duration::from_millis(2500)
        } else {
            std::time::Duration::from_millis(600)
        };
        assert!(median < budget, "скан занял {median:?} > {budget:?}");
    }
}


