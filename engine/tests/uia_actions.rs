//! Интеграционный тест семантических событий UI Automation (Windows, вручную):
//!
//! ```text
//! cargo test --test uia_actions -- --ignored --nocapture
//! ```
//!
//! Что проверяется на живой программе, а не на моках:
//!  1. `availability(pid)` находит окно, строит дерево и видит кнопку с InvokePattern;
//!  2. `spawn(pid, …)` реально подписывается на события;
//!  3. нажатие кнопки «Идентификация» через UIA InvokePattern даёт `ActionEvent`
//!     с правильными `name`, `action`, `pid`.
//!
//! Почему окно создаётся нативным Win32-окном, а не WinForms-формой: у WinForms
//! доступность идёт через MSAA-мост, и Invoke_Invoked от него **не приходит вообще**
//! (проверено: WinForms-кнопка, нажатая и через UIA Invoke, и настоящей мышью, не
//! дала ни одного события, тогда как нативная кнопка в charmap.exe дала и invoke,
//! и focus). Нативная кнопка — это ровно тот случай, что и PCMflash (Win32/VCL),
//! поэтому тест воспроизводит именно его. Событие принимается любого из двух видов:
//! `invoke` (провайдер поднял Invoke) или `focus` (резервный канал, который работает
//! и у legacy-провайдеров); какой именно вид пришёл — печатается в вывод.
//!
//! Все ожидания с таймаутами; powershell убивается через guard даже при панике.

#![cfg(windows)]

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ftdi_logger::uiactions::{availability, spawn, ActionEvent};
use windows::core::{Interface, Result as WinResult};
use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationInvokePattern,
    TreeScope_Subtree, UIA_InvokePatternId,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    SendMessageW, BM_CLICK,
};

/// Кнопка, которую тест ищет и нажимает (и имя действия в `classify`).
const BUTTON_NAME: &str = "Идентификация";

/// Скрипт, который поднимает настоящее Win32-окно с нативной кнопкой.
///
/// `-STA` обязателен: UIA-провайдеры и оконные сообщения в тестовом окне живут в
/// однопоточной квартире. Окно само закрывается таймером через 45 с, но тест всё
/// равно убивает процесс — таймер нужен лишь чтобы не оставить окно при аварии.
const SCRIPT: &str = r##"
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class FtdiUiaTestWindow
{
    private const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
    private const uint WS_VISIBLE = 0x10000000;
    private const uint WS_CHILD = 0x40000000;
    private const int WM_TIMER = 0x0113;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEXW
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ushort RegisterClassExW(ref WNDCLASSEXW wc);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateWindowExW(uint exStyle, string className, string windowName,
        uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hwnd, int cmd);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr DefWindowProcW(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetMessageW(out MSG msg, IntPtr hwnd, uint min, uint max);

    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG msg);

    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessageW(ref MSG msg);

    [DllImport("user32.dll")]
    private static extern IntPtr SetTimer(IntPtr hwnd, IntPtr id, uint ms, IntPtr proc);

    [DllImport("user32.dll")]
    private static extern void PostQuitMessage(int code);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandleW(string name);

    public static void Run(int seconds)
    {
        WndProcDelegate proc = WndProc;
        WNDCLASSEXW wc = new WNDCLASSEXW();
        wc.cbSize = (uint)Marshal.SizeOf(typeof(WNDCLASSEXW));
        wc.lpfnWndProc = Marshal.GetFunctionPointerForDelegate(proc);
        wc.hInstance = GetModuleHandleW(null);
        wc.lpszClassName = "FtdiUiaActionsTest";
        RegisterClassExW(ref wc);

        IntPtr hwnd = CreateWindowExW(0, "FtdiUiaActionsTest", "UIA Actions Test",
            WS_OVERLAPPEDWINDOW, 120, 120, 460, 240, IntPtr.Zero, IntPtr.Zero, wc.hInstance, IntPtr.Zero);
        CreateWindowExW(0, "BUTTON", "Идентификация", WS_CHILD | WS_VISIBLE,
            40, 60, 170, 44, hwnd, (IntPtr)1001, wc.hInstance, IntPtr.Zero);
        ShowWindow(hwnd, 5);
        SetTimer(hwnd, (IntPtr)1, (uint)(seconds * 1000), IntPtr.Zero);

        MSG msg;
        while (GetMessageW(out msg, IntPtr.Zero, 0, 0) > 0)
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }
        GC.KeepAlive(proc);
    }

    private static IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wparam, IntPtr lparam)
    {
        if (msg == WM_TIMER)
        {
            PostQuitMessage(0);
            return IntPtr.Zero;
        }
        return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}
'@
[FtdiUiaTestWindow]::Run(45)
"##;

/// Убивает powershell при любом выходе из теста, включая панику.
struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn pid(&self) -> u32 {
        self.0.as_ref().map(|child| child.id()).unwrap_or_default()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Держит `CoUninitialize` ровно тогда, когда поток инициализировали мы сами.
struct ComGuard(bool);

impl ComGuard {
    fn init() -> Self {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self(hr.is_ok())
    }
}

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

fn window_text(hwnd: HWND) -> String {
    let len = unsafe { GetWindowTextLengthW(hwnd) };
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; len as usize + 1];
    let copied = unsafe { GetWindowTextW(hwnd, &mut buf) };
    if copied <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..copied as usize])
}

/// Ищет видимое окно процесса (то же правило, что в модуле: заголовок непустой).
fn find_window(pid: u32) -> Option<(HWND, String)> {
    struct Search {
        pid: u32,
        found: Option<(HWND, String)>,
    }

    unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> windows::Win32::Foundation::BOOL {
        let search = unsafe { &mut *(lparam.0 as *mut Search) };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner as *mut u32)) };
        if owner == search.pid && unsafe { IsWindowVisible(hwnd) }.as_bool() {
            let title = window_text(hwnd);
            if !title.trim().is_empty() {
                search.found = Some((hwnd, title));
            }
        }
        windows::Win32::Foundation::TRUE
    }

    let mut search = Search { pid, found: None };
    let _ = unsafe { EnumWindows(Some(enum_proc), LPARAM(&mut search as *mut Search as isize)) };
    search.found
}

fn wait_for_window(pid: u32, timeout: Duration) -> Option<(HWND, String)> {
    let deadline = Instant::now() + timeout;
    let mut last_report = Instant::now();
    loop {
        if let Some(found) = find_window(pid) {
            return Some(found);
        }
        if Instant::now() >= deadline {
            return None;
        }
        if last_report.elapsed() > Duration::from_secs(5) {
            println!("... ждём окно pid={pid} (Add-Type/JIT иногда занимает секунды)");
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn uia_instance() -> WinResult<IUIAutomation> {
    unsafe { CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER) }
}

/// Ищет элемент кнопки по её UIA-имени (точное совпадение).
fn find_button(uia: &IUIAutomation, root: &IUIAutomationElement) -> Option<IUIAutomationElement> {
    let condition = unsafe { uia.CreateTrueCondition() }.ok()?;
    let all = unsafe { root.FindAll(TreeScope_Subtree, &condition) }.ok()?;
    let total = unsafe { all.Length() }.ok()?;
    for index in 0..total {
        let Ok(element) = (unsafe { all.GetElement(index) }) else {
            continue;
        };
        let name = unsafe { element.CurrentName() }
            .map(|text| text.to_string())
            .unwrap_or_default();
        println!("  элемент[{index}] name={name:?}");
        if name == BUTTON_NAME {
            return Some(element);
        }
    }
    None
}

/// Нажимает кнопку: сначала честный UIA InvokePattern, иначе BM_CLICK в её HWND.
fn press_button(element: &IUIAutomationElement) -> String {
    if let Ok(pattern) = unsafe { element.GetCurrentPattern(UIA_InvokePatternId) } {
        if let Ok(invoke) = pattern.cast::<IUIAutomationInvokePattern>() {
            return match unsafe { invoke.Invoke() } {
                Ok(()) => "UIA InvokePattern::Invoke".to_string(),
                Err(err) => format!("UIA InvokePattern::Invoke вернул ошибку {err}"),
            };
        }
    }
    let hwnd = unsafe { element.CurrentNativeWindowHandle() }.unwrap_or_default();
    if hwnd.is_invalid() {
        return "нет ни InvokePattern, ни HWND".to_string();
    }
    unsafe { SendMessageW(hwnd, BM_CLICK, windows::Win32::Foundation::WPARAM(0), LPARAM(0)) };
    "SendMessage(BM_CLICK)".to_string()
}

#[test]
#[ignore = "живой UIA-тест: поднимает powershell-окно и нажимает кнопку; запускать вручную с --ignored"]
fn uia_invoke_event_reaches_channel() {
    let _com = ComGuard::init();

    let child = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-STA",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            SCRIPT,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("не удалось запустить powershell.exe");
    let guard = ChildGuard(Some(child));
    let pid = guard.pid();
    println!("powershell pid={pid}; ждём окно «UIA Actions Test»");

    // Add-Type компилирует C# при первом запуске, поэтому ждём с запасом (10 с по
    // спецификации не хватает на холодный старт CSC).
    let Some((_hwnd, title)) = wait_for_window(pid, Duration::from_secs(20)) else {
        panic!(
            "окно тестовой программы не появилось за 20 с (pid={pid}); \
             смотрите stderr powershell выше: обычно это ошибка Add-Type/C#"
        );
    };
    println!("окно найдено: title={title:?}");

    // 1. Разовые сведения о доступности.
    let av = availability(pid);
    println!("availability: {av:#?}");
    assert!(
        av.ok,
        "availability: UIA-дерево не открылось: {:?}",
        av.error
    );
    assert!(av.buttons >= 1, "в окне не нашлось ни одной кнопки");
    assert!(
        av.invokable >= 1,
        "ни одна кнопка не поддерживает InvokePattern — нажимать нечем"
    );
    assert!(av.events_registered, "UIA-обработчики не зарегистрировались");

    // 2. Подписка.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ActionEvent>(64);
    let stop = Arc::new(AtomicBool::new(false));
    let handle = spawn(pid, tx, Arc::clone(&stop)).expect("spawn вернул None: окно/подписка не удались");
    println!("подписка оформлена");

    // 3. Нажатие кнопки через UIA. Окно берём то же, что выбрал модуль
    //    (`av.hwnd`), иначе тест мог бы нажать кнопку в другом окне процесса.
    let pressed_hwnd = HWND(av.hwnd as isize as *mut std::ffi::c_void);
    let uia = uia_instance().expect("IUIAutomation не создался");
    let root = unsafe { uia.ElementFromHandle(pressed_hwnd) }.expect("ElementFromHandle");
    let button = find_button(&uia, &root).expect("кнопка «Идентификация» не найдена в дереве");
    let method = press_button(&button);
    println!("нажатие: {method}");

    // 4. Ожидание события: 5 с. Invoke предпочтительнее, но у части провайдеров
    //    приходит только focus — резервный канал именно для этого и нужен.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("tokio runtime");
    let received: Option<ActionEvent> = runtime.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut candidate: Option<ActionEvent> = None;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(event)) => {
                    println!(
                        "событие: event={} name={:?} action={} pid={} ct={} window={:?}",
                        event.event,
                        event.name,
                        event.action,
                        event.pid,
                        event.control_type,
                        event.window
                    );
                    if event.name != BUTTON_NAME {
                        continue;
                    }
                    if event.event == "invoke" {
                        candidate = Some(event);
                        break;
                    }
                    if candidate.is_none() {
                        candidate = Some(event);
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        candidate
    });

    // 5. Останавливаем подписку до любых assert'ов, чтобы не оставить поток.
    stop.store(true, Ordering::Relaxed);
    let stopped = wait_thread(handle, Duration::from_secs(5));
    println!("поток подписки остановлен: {stopped}");
    // Окно больше не нужно: гасим powershell до проверок, чтобы падение assert'а
    // не оставило висящий процесс (guard всё равно убьёт его в Drop).
    drop(guard);
    assert!(stopped, "поток подписки не завершился за 5 с после stop=true");

    let event = received.expect(
        "за 5 с не пришло ни одного события с именем «Идентификация» \
         (проверьте, что окно теста было видимо и кнопка существует)",
    );
    assert_eq!(event.name, BUTTON_NAME);
    assert_eq!(event.action, "identify", "classify не распознал действие");
    assert_eq!(event.pid, pid, "событие пришло от другого процесса");
    assert_eq!(event.source, "uia");
    assert!(
        event.event == "invoke" || event.event == "focus",
        "неожиданный вид события: {}",
        event.event
    );
    assert!(!event.wall.is_empty(), "wall пуст");
    assert!(
        event.window.contains("UIA Actions Test"),
        "заголовок окна не тот: {:?}",
        event.window
    );
    println!(
        "OK: name={:?} action={} event={} pid={}",
        event.name, event.action, event.event, event.pid
    );
}

/// Ждёт завершения потока, не подвешивая тест навсегда.
fn wait_thread(handle: std::thread::JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if handle.is_finished() {
            let _ = handle.join();
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
