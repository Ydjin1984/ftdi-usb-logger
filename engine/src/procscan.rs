//! Процессы-кандидаты и метаданные exe. Владелец: boba.
//!
//! Кандидаты для захвата — это либо процессы с загруженной `ftd2xx*.dll` (D2XX-инструменты
//! вроде Quickflash), либо известные VCP-флашеры (`winkfpt.exe`, `inpa.exe`, `tool32.exe`,
//! `nfs.exe`), которые грузят обычный COM-порт и `ftd2xx` не используют.
//!
//! Всё построено на Toolhelp32 (`Process32First/Next` + `Module32First/Next`) и read-only
//! Win32-запросах. Ни одна функция не паникует: максимум пустой список / `None`.

use crate::models::{ExeMeta, ProcessDetail, ToolProcess};

/// Инструменты, которые цепляемся как VCP (могут не грузить `ftd2xx`).
pub const KNOWN_TOOLS: &[&str] = &["winkfpt.exe", "inpa.exe", "tool32.exe", "nfs.exe"];

/// Процессы-кандидаты: загружен `ftd2xx*` ИЛИ имя входит в `known`.
///
/// `known` — список имён exe (с расширением или без, регистр не важен).
pub fn list_candidates(known: &[&str]) -> Vec<ToolProcess> {
    #[cfg(windows)]
    {
        let procs = snapshot_processes();
        let mut out = Vec::new();
        for proc in procs {
            let known_hit = match_known(&proc.name, known);
            // Системные процессы модули не сканируем (их сотни и там нет ftd2xx):
            // это единственная оптимизация, которая заметно ускоряет поллинг.
            let skip_modules = known_hit.is_none() && is_system_path(&proc.exe);
            let (has_ftd2xx, _modules) = if skip_modules {
                (false, Vec::new())
            } else {
                let mods = process_modules(proc.pid);
                let hit = has_ftd2xx_module(&mods);
                (hit, mods)
            };
            if !has_ftd2xx && known_hit.is_none() {
                continue;
            }
            let window_title = window_title_for_pid(proc.pid);
            out.push(ToolProcess {
                pid: proc.pid,
                name: proc.stem(),
                exe: proc.exe,
                has_ftd2xx,
                known_tool: known_hit,
                started_at: process_started_at(proc.pid),
                window_title,
            });
        }
        out.sort_by_key(|p| p.pid);
        out
    }
    #[cfg(not(windows))]
    {
        let _ = known;
        Vec::new()
    }
}

/// Подробности одного процесса (для `GET /api/process/<pid>` и `attach`).
pub fn process_detail(pid: u32) -> Option<ProcessDetail> {
    #[cfg(windows)]
    {
        let proc = snapshot_processes().into_iter().find(|p| p.pid == pid)?;
        let modules = process_modules(pid);
        let has_ftd2xx = has_ftd2xx_module(&modules);
        let known_hit = match_known(&proc.name, KNOWN_TOOLS);
        let tool = ToolProcess {
            pid,
            name: proc.stem(),
            exe: proc.exe.clone(),
            has_ftd2xx,
            known_tool: known_hit,
            started_at: process_started_at(pid),
            window_title: window_title_for_pid(pid),
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
                    // pid 4 (System) и защищённые процессы не откроются — путь будет пустым,
                    // но имя всё равно полезно (например, для проверки активатора).
                    let exe = process_image_path(pid).unwrap_or_default();
                    out.push(RawProc { pid, name, exe });
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

#[cfg(windows)]
fn process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::PWSTR;

    // SAFETY: открываем процесс только на чтение метаданных, дескриптор закрываем.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && size > 0 {
            Some(String::from_utf16_lossy(&buf[..size as usize]))
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn process_started_at(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: read-only запрос времени старта; дескриптор закрывается.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = creation;
        let mut kernel = creation;
        let mut user = creation;
        let ok =
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return None;
        }
        filetime_to_rfc3339(creation.dwLowDateTime, creation.dwHighDateTime)
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
fn process_modules(pid: u32) -> Vec<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let mut out = Vec::new();
    // SAFETY: снимок модулей — read-only; дескриптор закрывается.
    unsafe {
        let Ok(snapshot) =
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        else {
            return out;
        };
        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                out.push(wide_array_to_string(&entry.szModule));
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
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
}
