//! Семантические события UI Automation целевого процесса: «оператор нажал кнопку X».
//!
//! Зачем модуль: USB/FTDI-сниффер видит байты, но не видит смысла — какое действие
//! запустил человек. UI Automation даёт семантику **без глобального перехвата
//! клавиатуры и мыши**: мы подписываемся на события Invoke внутри дерева главного окна
//! целевого pid и на смену фокуса (резервный канал), а соседние процессы отбрасываем
//! по `CurrentProcessId`. Поэтому «чужие» кнопки в журнал не попадают.
//!
//! Что важно знать про устройство подписки (проверено на этой машине):
//!
//! * `AddAutomationEventHandler(UIA_AutomationFocusChangedEventId, …)` невозможен:
//!   UIA отвечает `E_INVALIDARG` («события фокуса следует регистрировать через
//!   AddFocusChangedEventHandler»). Поэтому фокус регистрируется отдельным методом
//!   `AddFocusChangedEventHandler`, а он **глобальный** — фильтр по pid обязателен.
//!   Кэш-запрос на `ProcessId`/`ControlType` делает фильтр дешёвым: значения берутся
//!   из кэша события, без лишнего cross-process вызова в чужую программу.
//! * Обработчик COM-события реализован вручную (vtable из `IUIAutomationEventHandler_Vtbl`)
//!   а не через `#[implement]`: макрос `windows`-0.58 разворачивается в пути
//!   `::windows_core::…`, а этот крейт не является прямой зависимостью движка
//!   (`windows` реэкспортирует его только как `windows::core`). Добавлять зависимость
//!   `windows-core` ради макроса запрещено, поэтому vtable собран руками — те же
//!   три метода IUnknown плюс сам колбэк, с честным подсчётом ссылок.
//! * Один настоящий клик может дать **пару** событий: `invoke` и `focus`. Ключ
//!   подавления включает вид события, поэтому пара остаётся парой — это осознанно:
//!   интеграция сама решает, схлопывать ли её в журнале.
//! * Обработчик только читает свойства элементов. Никаких `Invoke`/`SetValue` из
//!   колбэка: инструмент наблюдения не имеет права нажимать кнопки в измеряемой
//!   программе (иначе он менял бы то, что измеряет).
//!
//! Windows-only: на других платформах остаются заглушки с честной ошибкой в
//! `Availability`, а `spawn` возвращает `None`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Одно семантическое действие оператора в целевой программе.
///
/// Поля сериализуются в журнал сессии как есть; `wall` — UTC RFC3339 с миллисекундами,
/// чтобы событие можно было сопоставить с USB-пакетами по времени.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ActionEvent {
    pub wall: String,
    pub name: String,
    pub automation_id: String,
    pub control_type: String,
    pub window: String,
    pub process: String,
    pub pid: u32,
    /// `"invoke"` — провайдер поднял Invoke; `"focus"` — резервный канал (смена фокуса);
    /// `"click"` — клик-канал увидел нажатие кнопки мыши над элементом.
    pub event: String,
    /// Чем действие **подтверждено**: `"invoke"`, `"click"` или `""` (только фокус).
    ///
    /// `focus` — это ещё не нажатие: фокус приходит и при переходе по Tab, и при
    /// возврате фокуса в окно после закрытия диалога. Раньше журнал показывал все
    /// такие события как «нажата кнопка», и отметка «Сохранить» появлялась позже
    /// фактической записи файла. Теперь вид канала хранится отдельно, а команда
    /// считается выполненной только при `confirmed=true`.
    #[serde(default)]
    pub activation: String,
    /// `true` — нажатие подтверждено (`invoke`/`click`); `false` — только фокус.
    #[serde(default)]
    pub confirmed: bool,
    pub source: String,
    pub action: String,
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Разовые сведения о доступности UIA для процесса: нужны UI/диагностике, чтобы
/// показать «события недоступны» до попытки подписки, а не после тишины в журнале.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Availability {
    pub ok: bool,
    pub pid: u32,
    pub window: String,
    pub hwnd: i64,
    pub elements: usize,
    pub buttons: usize,
    pub invokable: usize,
    pub events_registered: bool,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Классификация названий и подавление дублей (платформонезависимая часть)
// ---------------------------------------------------------------------------

/// Нормализует название кнопки в действие для `meta.action`.
///
/// Сопоставление по **корням слов** (рус/англ), регистронезависимо: «Считать…»,
/// «Считать (full)», «Read ROM» — это одно действие, а не три разных.
///
/// Приоритет ветвлений не случаен: «Стереть ошибки» и «Сброс ошибок» — работа с
/// ошибками, поэтому `errors` проверяется раньше `erase` и `reset`; иначе кнопка
/// очистки кодов неисправностей попала бы в «стирание» и «сброс».
pub fn classify(name: &str) -> &'static str {
    const RULES: [(&str, &[&str]); 7] = [
        ("errors", &["ошиб", "error", "dtc", "fault", "clear"]),
        (
            "verify",
            &["провер", "верифик", "верифиц", "verify", "verif", "checksum"],
        ),
        (
            "erase",
            &["стира", "стере", "сотр", "удали", "erase", "delete", "remov"],
        ),
        ("write", &["запис", "запиш", "write"]),
        ("read", &["счит", "чтен", "прочит", "read", "dump"]),
        ("identify", &["идентифи", "identif"]),
        ("reset", &["адаптац", "adapt", "сброс", "reset"]),
    ];

    let words = name_words(name);
    for (action, roots) in RULES {
        for word in &words {
            if roots.iter().any(|root| word.starts_with(root)) {
                return action;
            }
        }
    }
    "other"
}

/// Слова названия в нижнем регистре: пунктуация (включая «…») разделяет, а не мешает.
fn name_words(name: &str) -> Vec<String> {
    name.split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_lowercase())
        .collect()
}

/// Ключ подавления дублей: `name|automation_id|control_type|event` в нормализованном виде.
///
/// Нормализация (регистр, повторные пробелы) обязательна: UIA умеет присылать одно
/// нажатие дважды — от legacy-провайдера и от прокси — и эти две копии отличаются
/// только регистром/пробелами в имени.
pub fn dedupe_key(e: &ActionEvent) -> String {
    format!(
        "{}|{}|{}|{}",
        collapse(&e.name),
        collapse(&e.automation_id),
        collapse(&e.control_type),
        collapse(&e.event)
    )
}

/// Ключ элемента без вида события: `name|automation_id|control_type`.
///
/// Один клик по кнопке VCL приходит двумя записями — `focus` от UIA и `click`
/// от клик-канала. Ключ позволяет считать их одним действием при разборе, не
/// теряя ни одну запись в журнале.
pub fn element_key(e: &ActionEvent) -> String {
    format!(
        "{}|{}|{}",
        collapse(&e.name),
        collapse(&e.automation_id),
        collapse(&e.control_type)
    )
}

/// trim + схлопывание внутренних пробелов + нижний регистр (Unicode, не только ASCII:
/// названия кнопок русские).
fn collapse(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut pending_space = false;
    for ch in value.trim().chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        for lower in ch.to_lowercase() {
            out.push(lower);
        }
    }
    out
}

/// Подавитель дублей: одно и то же событие в пределах окна — дубль.
///
/// Время последнего **принятого** события не обновляется при отказе: иначе поток
/// событий с интервалом меньше окна подавлялся бы бесконечно, а «быстрые повторные
/// нажатия» (интервал больше окна) должны сохраняться.
pub struct Deduper {
    window: Duration,
    seen: HashMap<String, Instant>,
}

impl Deduper {
    pub fn new(window_ms: u64) -> Self {
        Self {
            window: Duration::from_millis(window_ms),
            seen: HashMap::new(),
        }
    }

    /// `true` — событие новое и его надо писать; `false` — дубль, отбрасываем.
    pub fn accept(&mut self, key: &str) -> bool {
        let now = Instant::now();
        if let Some(previous) = self.seen.get(key) {
            if now.duration_since(*previous) < self.window {
                return false;
            }
        }
        self.seen.insert(key.to_string(), now);
        // Журнал живёт часами: редкая чистка не даёт карте расти бесконечно,
        // но и не делает приём события дороже самого события.
        if self.seen.len() > 512 {
            let window = self.window;
            self.seen.retain(|_, at| now.duration_since(*at) < window);
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Windows-реализация
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
    use std::sync::mpsc::{sync_channel, SyncSender};
    use std::sync::Arc;
    use std::time::Duration;

    use tracing::{debug, warn};
    use windows::core::{imp::IAgileObject, GUID, HRESULT, IUnknown, Interface, Type};
    use windows::Win32::Foundation::{CloseHandle, HWND, LPARAM, POINT, RECT, RPC_E_CHANGED_MODE};
    use windows::Win32::Foundation::{E_NOINTERFACE, E_POINTER, S_OK};
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationCacheRequest, IUIAutomationElement,
        IUIAutomationElementArray, IUIAutomationEventHandler,
        IUIAutomationEventHandler_Vtbl, IUIAutomationFocusChangedEventHandler,
        IUIAutomationFocusChangedEventHandler_Vtbl, IUIAutomationInvokePattern,
        TreeScope_Subtree, UIA_ButtonControlTypeId, UIA_PaneControlTypeId,
        UIA_CheckBoxControlTypeId, UIA_CONTROLTYPE_ID, UIA_ControlTypePropertyId, UIA_EVENT_ID,
        UIA_Invoke_InvokedEventId, UIA_InvokePatternId, UIA_LegacyIAccessibleNamePropertyId,
        UIA_ListItemControlTypeId, UIA_MenuItemControlTypeId, UIA_ProcessIdPropertyId,
        UIA_RadioButtonControlTypeId, UIA_TabItemControlTypeId,
    };
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetAncestor, GetCursorPos, GetWindowLongW, GetWindowRect, GetWindowTextLengthW,
        GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible, WindowFromPoint,
        GA_ROOT, GWL_STYLE, WS_OVERLAPPEDWINDOW,
    };

    use super::{classify, element_key, ActionEvent, Availability, Deduper};

    /// Предел обхода дерева при разовом подсчёте: `FindAll` по всему поддереву большого
    /// приложения — это сотни cross-process вызовов, а для индикатора «есть ли кнопки»
    /// хватает головы дерева.
    const MAX_SCAN: i32 = 4000;

    /// Сколько `spawn` ждёт подтверждения подписки, прежде чем вернуть `None`.
    const READY_TIMEOUT: Duration = Duration::from_secs(10);

    /// Окно подавления дублей, мс.
    const DEDUPE_WINDOW_MS: u64 = 250;

    // -----------------------------------------------------------------------
    // COM-квартира
    // -----------------------------------------------------------------------

    /// Держит `CoUninitialize` ровно тогда, когда поток инициализировали мы сами.
    ///
    /// `RPC_E_CHANGED_MODE` означает, что поток уже в STA: UIA работает и так, но
    /// снимать чужой счётчик инициализации нельзя.
    struct ComApartment {
        owns: bool,
    }

    impl ComApartment {
        fn new() -> Result<Self, String> {
            let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
            if hr.is_ok() {
                return Ok(Self { owns: true });
            }
            if hr == RPC_E_CHANGED_MODE {
                debug!("поток UIA уже инициализирован в STA — используем как есть");
                return Ok(Self { owns: false });
            }
            Err(format!("CoInitializeEx: 0x{:08X} {}", hr.0 as u32, hr.message()))
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            if self.owns {
                unsafe { CoUninitialize() };
            }
        }
    }

    // -----------------------------------------------------------------------
    // Поиск главного окна процесса
    // -----------------------------------------------------------------------

    struct WindowSearch {
        pid: u32,
        best: Option<WindowCandidate>,
    }

    struct WindowCandidate {
        hwnd: HWND,
        title: String,
        overlapped: bool,
        area: i64,
    }

    impl WindowSearch {
        fn visit(&mut self, hwnd: HWND) {
            if hwnd.is_invalid() {
                return;
            }
            let mut owner = 0u32;
            unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner as *mut u32)) };
            if owner != self.pid {
                return;
            }
            if !unsafe { IsWindowVisible(hwnd) }.as_bool() {
                return;
            }
            let title = window_text(hwnd);
            if title.trim().is_empty() {
                return;
            }
            let style = unsafe { GetWindowLongW(hwnd, GWL_STYLE) } as u32;
            // Главное окно приложения — то, у которого есть рамка WS_OVERLAPPEDWINDOW;
            // без этого предпочтения «самое большое по площади» иногда выбирает
            // невидимую панель-подложку вместо настоящего окна программы.
            let overlapped = style & WS_OVERLAPPEDWINDOW.0 == WS_OVERLAPPEDWINDOW.0;
            let mut rect = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            let area = if unsafe { GetWindowRect(hwnd, &mut rect) }.is_ok() {
                i64::from((rect.right - rect.left).max(0)) * i64::from((rect.bottom - rect.top).max(0))
            } else {
                0
            };
            let better = match &self.best {
                None => true,
                Some(best) => (overlapped, area) > (best.overlapped, best.area),
            };
            if better {
                self.best = Some(WindowCandidate {
                    hwnd,
                    title,
                    overlapped,
                    area,
                });
            }
        }
    }

    /// Главное окно pid: видимое, с непустым заголовком, предпочтительно
    /// `WS_OVERLAPPEDWINDOW`, из подходящих — самое большое.
    fn find_main_window(pid: u32) -> Option<(HWND, String)> {
        unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> windows::Win32::Foundation::BOOL {
            // SAFETY: lparam — указатель на WindowSearch, живущий весь вызов EnumWindows.
            let search = unsafe { &mut *(lparam.0 as *mut WindowSearch) };
            search.visit(hwnd);
            windows::Win32::Foundation::TRUE
        }

        let mut search = WindowSearch { pid, best: None };
        let _ = unsafe {
            EnumWindows(
                Some(enum_proc),
                LPARAM(&mut search as *mut WindowSearch as isize),
            )
        };
        search.best.map(|candidate| (candidate.hwnd, candidate.title))
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

    /// Имя exe целевого pid (`pcmflash.exe`). Пустая строка — прочитать не разрешили
    /// (защищённый процесс); это честное «не знаю», а не повод бросать подписку.
    fn process_name(pid: u32) -> String {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
        else {
            return String::new();
        };
        let mut buf = vec![0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
            .is_ok()
        };
        let _ = unsafe { CloseHandle(handle) };
        if !ok || size == 0 {
            return String::new();
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        path.rsplit(['\\', '/'])
            .next()
            .unwrap_or_default()
            .to_string()
    }

    // -----------------------------------------------------------------------
    // Ручная реализация COM-обработчиков UIA
    // -----------------------------------------------------------------------

    /// Ключ колбэка: общий для Invoke и Focus; `None` — пробная подписка availability.
    struct SinkData {
        tx: tokio::sync::mpsc::Sender<ActionEvent>,
        shared: Arc<Shared>,
        stop: Arc<AtomicBool>,
        dedup: parking_lot::Mutex<Deduper>,
    }

    /// Состояние подписки, разделяемое потоком-владельцем и колбэками.
    struct Shared {
        pid: u32,
        process: String,
        /// Кэш главного окна: по нему подписываемся и по нему же размечаем события,
        /// у которых провайдер не дал `CurrentNativeWindowHandle`.
        main_hwnd: AtomicIsize,
        /// Канал закрыт — подписка больше не нужна, поток должен завершиться.
        dead: AtomicBool,
    }

    /// COM-объект обработчика.
    ///
    /// `vtbl` обязан быть первым полем: интерфейсный указатель COM — это адрес объекта,
    /// а по его первому слову лежит vtable. Второе слово и далее — наши данные, их
    /// COM не трогает.
    #[repr(C)]
    struct SinkObject {
        vtbl: *const c_void,
        refs: AtomicU32,
        data: Option<Arc<SinkData>>,
    }

    impl SinkObject {
        fn new(vtbl: *const c_void, data: Option<Arc<SinkData>>) -> Box<Self> {
            Box::new(Self {
                vtbl,
                refs: AtomicU32::new(1),
                data,
            })
        }
    }

    /// Разделяемая часть QueryInterface: сам объект + IAgileObject (объект без
    /// привязки к квартире: внутри только атомики и мьютекс) + свой интерфейс.
    unsafe fn query_interface(
        this: *mut c_void,
        iid: *const GUID,
        out: *mut *mut c_void,
        own: &GUID,
    ) -> HRESULT {
        if out.is_null() {
            return E_POINTER;
        }
        let iid = unsafe { &*iid };
        if *iid == IUnknown::IID || *iid == IAgileObject::IID || *iid == *own {
            unsafe { (*(this as *mut SinkObject)).refs.fetch_add(1, Ordering::Relaxed) };
            unsafe { *out = this };
            S_OK
        } else {
            unsafe { *out = std::ptr::null_mut() };
            E_NOINTERFACE
        }
    }

    unsafe extern "system" fn sink_add_ref(this: *mut c_void) -> u32 {
        unsafe { (*(this as *mut SinkObject)).refs.fetch_add(1, Ordering::Relaxed) + 1 }
    }

    unsafe extern "system" fn sink_release(this: *mut c_void) -> u32 {
        let object = this as *mut SinkObject;
        let previous = unsafe { (*object).refs.fetch_sub(1, Ordering::AcqRel) };
        if previous == 1 {
            // Последняя ссылка: освобождаем объект и данные подписки.
            drop(unsafe { Box::from_raw(object) });
            0
        } else {
            previous - 1
        }
    }

    unsafe extern "system" fn invoke_query_interface(
        this: *mut c_void,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> HRESULT {
        unsafe { query_interface(this, iid, out, &IUIAutomationEventHandler::IID) }
    }

    unsafe extern "system" fn focus_query_interface(
        this: *mut c_void,
        iid: *const GUID,
        out: *mut *mut c_void,
    ) -> HRESULT {
        unsafe { query_interface(this, iid, out, &IUIAutomationFocusChangedEventHandler::IID) }
    }

    /// Данные подписки из `this`. `None` — пробный обработчик availability.
    unsafe fn sink_data<'a>(this: *mut c_void) -> Option<&'a SinkData> {
        let object = unsafe { &*(this as *const SinkObject) };
        object.data.as_deref()
    }

    unsafe extern "system" fn invoke_event(
        this: *mut c_void,
        sender: *mut c_void,
        eventid: UIA_EVENT_ID,
    ) -> HRESULT {
        if eventid == UIA_Invoke_InvokedEventId && !sender.is_null() {
            if let Some(data) = unsafe { sink_data(this) } {
                // SAFETY: sender живёт весь колбэк; ссылку мы не сохраняем.
                if let Some(element) = unsafe { IUIAutomationElement::from_raw_borrowed(&sender) } {
                    data.observe(element, "invoke");
                }
            }
        }
        S_OK
    }

    unsafe extern "system" fn focus_event(this: *mut c_void, sender: *mut c_void) -> HRESULT {
        if !sender.is_null() {
            if let Some(data) = unsafe { sink_data(this) } {
                if let Some(element) = unsafe { IUIAutomationElement::from_raw_borrowed(&sender) } {
                    data.observe(element, "focus");
                }
            }
        }
        S_OK
    }

    static INVOKE_VTBL: IUIAutomationEventHandler_Vtbl = IUIAutomationEventHandler_Vtbl {
        base__: windows::core::IUnknown_Vtbl {
            QueryInterface: invoke_query_interface,
            AddRef: sink_add_ref,
            Release: sink_release,
        },
        HandleAutomationEvent: invoke_event,
    };

    static FOCUS_VTBL: IUIAutomationFocusChangedEventHandler_Vtbl =
        IUIAutomationFocusChangedEventHandler_Vtbl {
            base__: windows::core::IUnknown_Vtbl {
                QueryInterface: focus_query_interface,
                AddRef: sink_add_ref,
                Release: sink_release,
            },
            HandleFocusChangedEvent: focus_event,
        };

    /// Оборачивает наш объект в интерфейс windows-крейта: `IUIAutomationEventHandler`
    /// получает владение одной ссылкой и освобождает её при `Drop`.
    fn new_invoke_sink(data: Option<Arc<SinkData>>) -> IUIAutomationEventHandler {
        let object = SinkObject::new(&INVOKE_VTBL as *const _ as *const c_void, data);
        let raw = Box::into_raw(object) as *mut c_void;
        // SAFETY: указатель не нулевой и ведёт на объект с корректной vtable.
        unsafe { Type::from_abi(raw) }.expect("обработчик UIA: ненулевой указатель")
    }

    fn new_focus_sink(data: Option<Arc<SinkData>>) -> IUIAutomationFocusChangedEventHandler {
        let object = SinkObject::new(&FOCUS_VTBL as *const _ as *const c_void, data);
        let raw = Box::into_raw(object) as *mut c_void;
        unsafe { Type::from_abi(raw) }.expect("обработчик фокуса UIA: ненулевой указатель")
    }

    // -----------------------------------------------------------------------
    // Чтение свойств элемента и разметка события
    // -----------------------------------------------------------------------

    impl SinkData {
        /// Единственная точка, где рождается `ActionEvent`. Ошибки чтения свойств
        /// не пробрасываются: событие от чужого/уже закрытого окна — не повод
        /// ронять поток подписки.
        fn observe(&self, element: &IUIAutomationElement, event: &str) {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(pid) = (unsafe { element.CurrentProcessId() }) else {
                return;
            };
            if pid as u32 != self.shared.pid {
                // Соседние окна: главный фильтр модуля. Ничего не пишем даже в debug,
                // иначе чужой фокус зальёт лог.
                return;
            }
            let Ok(control_type) = (unsafe { element.CurrentControlType() }) else {
                return;
            };
            // Резервный канал шумит: фокус в текстовом поле — не действие оператора.
            // Delphi/VCL (PCMflash) отдаёт кнопки как Pane с Win32-классом Button:
            // без этой ветки фокус на «Идентификации» отбрасывался, хотя событие
            // приходит и имя у него есть (проверено живым прогоном).
            let class_name = bstr_text(unsafe { element.CurrentClassName() });
            let vcl_button =
                control_type == UIA_PaneControlTypeId && class_name.eq_ignore_ascii_case("button");
            if event == "focus" && !is_actionable(control_type) && !vcl_button {
                return;
            }

            let automation_id = bstr_text(unsafe { element.CurrentAutomationId() });
            let mut name = bstr_text(unsafe { element.CurrentName() });
            if name.is_empty() {
                // Legacy-провайдеры (Delphi/VCL, MFC) нередко отдают пустой CurrentName.
                name = legacy_name(element);
            }
            if name.is_empty() {
                name = automation_id.clone();
            }
            if name.is_empty() {
                debug!(pid = self.shared.pid, event, "событие UIA без имени — пропущено");
                return;
            }

            let Some(window) = event_window(element, &self.shared) else {
                debug!(pid = self.shared.pid, event, "событие UIA из чужого окна — пропущено");
                return;
            };

            let (x, y, w, h) = bounding_rect(element);
            let action = classify(&name);
            let ev = ActionEvent {
                wall: now_rfc3339(),
                name: name.clone(),
                automation_id,
                control_type: if vcl_button {
                    "Button".to_string()
                } else {
                    control_type_name(control_type).to_string()
                },
                window,
                process: self.shared.process.clone(),
                pid: self.shared.pid,
                event: event.to_string(),
                activation: event.to_string(),
                confirmed: event == "invoke",
                source: "uia".to_string(),
                action: action.to_string(),
                x,
                y,
                w,
                h,
            };

            // Один клик даёт до двух записей: `invoke` от провайдера и `focus`
            // от резервного канала. Для журнала это одно действие, поэтому
            // ключ подавления склеивает их — имя, AutomationId и тип элемента,
            // без вида события. Публичный `dedupe_key` вид события различает
            // (нужен для диагностики), здесь — пара.
            let pair = super::element_key(&ev);
            if !self.dedup.lock().accept(&pair) {
                debug!(pid = self.shared.pid, event, name, "дубль события UIA подавлен");
                return;
            }
            if self.tx.blocking_send(ev).is_err() {
                // Приёмник закрыт: подписка больше не нужна, поток увидит dead.
                self.shared.dead.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Заголовок окна, к которому относится элемент. `None` — событие отброшено:
    /// корневое окно элемента принадлежит другому процессу (провайдер мог отдать
    /// чужой HWND), либо окно не удалось определить вовсе.
    fn event_window(element: &IUIAutomationElement, shared: &Shared) -> Option<String> {
        let native = unsafe { element.CurrentNativeWindowHandle() }.unwrap_or_default();
        if !native.is_invalid() {
            let root = unsafe { GetAncestor(native, GA_ROOT) };
            let root = if root.is_invalid() { native } else { root };
            let mut owner = 0u32;
            unsafe { GetWindowThreadProcessId(root, Some(&mut owner as *mut u32)) };
            if owner != shared.pid {
                return None;
            }
            let title = window_text(root);
            if !title.is_empty() {
                return Some(title);
            }
        }
        // HWND нет (часть WPF/UIA-провайдеров) или заголовок пуст — берём главное окно pid.
        main_window(shared).map(|(_, title)| title)
    }

    /// Главное окно pid с кэшем. Кэш обновляется **только при промахе**: иначе
    /// всплывший popup вытеснил бы главное окно и все последующие заголовки стали бы
    /// «чужими».
    fn main_window(shared: &Shared) -> Option<(HWND, String)> {
        let cached = shared.main_hwnd.load(Ordering::Relaxed);
        if cached != 0 {
            let hwnd = HWND(cached as *mut c_void);
            if unsafe { IsWindow(hwnd) }.as_bool() {
                let title = window_text(hwnd);
                if !title.is_empty() {
                    return Some((hwnd, title));
                }
            }
        }
        let found = find_main_window(shared.pid)?;
        shared
            .main_hwnd
            .store(found.0 .0 as isize, Ordering::Relaxed);
        Some(found)
    }

    fn bstr_text(value: windows::core::Result<windows::core::BSTR>) -> String {
        match value {
            Ok(text) => text.to_string().trim().to_string(),
            Err(_) => String::new(),
        }
    }

    /// `UIA_LegacyIAccessibleNamePropertyId` — единственный источник имени у части
    /// legacy-провайдеров, где `CurrentName` пуст.
    fn legacy_name(element: &IUIAutomationElement) -> String {
        let Ok(value) = (unsafe {
            element.GetCurrentPropertyValue(UIA_LegacyIAccessibleNamePropertyId)
        }) else {
            return String::new();
        };
        windows::core::BSTR::try_from(&value)
            .map(|text| text.to_string().trim().to_string())
            .unwrap_or_default()
    }

    fn bounding_rect(element: &IUIAutomationElement) -> (i32, i32, i32, i32) {
        match unsafe { element.CurrentBoundingRectangle() } {
            Ok(rect) => (
                rect.left,
                rect.top,
                (rect.right - rect.left).max(0),
                (rect.bottom - rect.top).max(0),
            ),
            Err(_) => (0, 0, 0, 0),
        }
    }

    fn now_rfc3339() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// Типы элементов, у которых нажатие/фокус означает действие оператора.
    fn is_actionable(control_type: UIA_CONTROLTYPE_ID) -> bool {
        control_type == UIA_ButtonControlTypeId
            || control_type == UIA_MenuItemControlTypeId
            || control_type == UIA_TabItemControlTypeId
            || control_type == UIA_CheckBoxControlTypeId
            || control_type == UIA_RadioButtonControlTypeId
            || control_type == UIA_ListItemControlTypeId
    }

    fn control_type_name(control_type: UIA_CONTROLTYPE_ID) -> &'static str {
        if control_type == UIA_ButtonControlTypeId {
            "Button"
        } else if control_type == UIA_MenuItemControlTypeId {
            "MenuItem"
        } else if control_type == UIA_TabItemControlTypeId {
            "TabItem"
        } else if control_type == UIA_CheckBoxControlTypeId {
            "CheckBox"
        } else if control_type == UIA_RadioButtonControlTypeId {
            "RadioButton"
        } else if control_type == UIA_ListItemControlTypeId {
            "ListItem"
        } else {
            "Other"
        }
    }

    // -----------------------------------------------------------------------
    // Подписка
    // -----------------------------------------------------------------------

    fn create_uia() -> Result<IUIAutomation, String> {
        unsafe {
            CoCreateInstance::<Option<&IUnknown>, IUIAutomation>(
                &CUIAutomation,
                None,
                CLSCTX_INPROC_SERVER,
            )
        }
        .map_err(|err| format!("CoCreateInstance(CUIAutomation): {err}"))
    }

    /// Кэш только тех свойств, которые нужны фильтру: `ProcessId` и `ControlType`.
    /// Благодаря нему глобальный обработчик фокуса не делает cross-process вызов
    /// в каждое приложение, где оператор просто переключил окно.
    fn cache_request(uia: &IUIAutomation) -> Option<IUIAutomationCacheRequest> {
        let cache = unsafe { uia.CreateCacheRequest() }.ok()?;
        unsafe {
            cache.AddProperty(UIA_ProcessIdPropertyId).ok()?;
            cache.AddProperty(UIA_ControlTypePropertyId).ok()?;
        }
        Some(cache)
    }

    /// Разово проверяет, что оба канала событий реально регистрируются.
    /// Пробные обработчики снимаются тут же: `availability` не оставляет подписок.
    fn probe_events(uia: &IUIAutomation, root: &IUIAutomationElement) -> bool {
        let invoke = new_invoke_sink(None);
        let focus = new_focus_sink(None);
        let invoke_ok = unsafe {
            uia.AddAutomationEventHandler(
                UIA_Invoke_InvokedEventId,
                root,
                TreeScope_Subtree,
                None,
                &invoke,
            )
        }
        .is_ok();
        let cache = cache_request(uia);
        let focus_ok = unsafe { uia.AddFocusChangedEventHandler(cache.as_ref(), &focus) }.is_ok();
        unsafe {
            let _ = uia.RemoveFocusChangedEventHandler(&focus);
            let _ = uia.RemoveAllEventHandlers();
        }
        drop(invoke);
        drop(focus);
        if !invoke_ok {
            debug!("пробная регистрация Invoke-обработчика не удалась");
        }
        if !focus_ok {
            debug!("пробная регистрация обработчика фокуса не удалась");
        }
        invoke_ok && focus_ok
    }

    /// Разовые сведения: главное окно pid, размер дерева, кнопки и их InvokePattern.
    pub fn availability(pid: u32) -> Availability {
        let mut out = Availability {
            pid,
            ..Default::default()
        };
        let _com = match ComApartment::new() {
            Ok(guard) => guard,
            Err(err) => {
                out.error = Some(err);
                return out;
            }
        };
        let Some((hwnd, title)) = find_main_window(pid) else {
            out.error = Some(format!(
                "видимое окно с заголовком у процесса pid={pid} не найдено"
            ));
            return out;
        };
        out.hwnd = hwnd.0 as isize as i64;
        out.window = title;

        let uia = match create_uia() {
            Ok(uia) => uia,
            Err(err) => {
                out.error = Some(err);
                return out;
            }
        };
        let root = match unsafe { uia.ElementFromHandle(hwnd) } {
            Ok(element) => element,
            Err(err) => {
                out.error = Some(format!("ElementFromHandle: {err}"));
                return out;
            }
        };
        let condition = match unsafe { uia.CreateTrueCondition() } {
            Ok(condition) => condition,
            Err(err) => {
                out.error = Some(format!("CreateTrueCondition: {err}"));
                return out;
            }
        };
        // Легаси-провайдер изредка отвечает пустым деревом на первый запрос
        // (наблюдалось на PCMflash: 24 элемента, затем 0, затем снова 24).
        // Пустое дерево — не «нет интерфейса», поэтому пробуем несколько раз.
        let mut all: IUIAutomationElementArray = match unsafe { root.FindAll(TreeScope_Subtree, &condition) } {
            Ok(array) => array,
            Err(err) => {
                out.error = Some(format!("FindAll: {err}"));
                return out;
            }
        };
        let mut total = unsafe { all.Length() }.unwrap_or(0).max(0);
        let mut attempt = 0;
        while total == 0 && attempt < 4 {
            attempt += 1;
            std::thread::sleep(Duration::from_millis(350));
            if let Ok(array) = unsafe { root.FindAll(TreeScope_Subtree, &condition) } {
                total = unsafe { array.Length() }.unwrap_or(0).max(0);
                all = array;
            }
        }
        out.elements = total as usize;
        out.ok = true;

        for index in 0..total.min(MAX_SCAN) {
            let Ok(element) = (unsafe { all.GetElement(index) }) else {
                continue;
            };
            let Ok(control_type) = (unsafe { element.CurrentControlType() }) else {
                continue;
            };
            // Delphi/VCL отдаёт кнопки как Pane с Win32-классом Button: без этой
            // ветки «кнопок 0» выглядело бы как отсутствие интерфейса.
            let class = bstr_text(unsafe { element.CurrentClassName() });
            let vcl_button = class.eq_ignore_ascii_case("button")
                || class.eq_ignore_ascii_case("combobox")
                || class.eq_ignore_ascii_case("checkBox");
            if !is_actionable(control_type) && !vcl_button {
                continue;
            }
            out.buttons += 1;
            let invokable = match unsafe { element.GetCurrentPattern(UIA_InvokePatternId) } {
                Ok(pattern) => pattern.cast::<IUIAutomationInvokePattern>().is_ok(),
                Err(_) => false,
            };
            if invokable {
                out.invokable += 1;
            }
        }

        out.events_registered = probe_events(&uia, &root);
        out
    }

    /// Подписка на события целевого pid.
    ///
    /// Окно ищется синхронно (без него подписка бессмысленна), а регистрация
    /// обработчиков происходит в отдельном потоке: UIA-события приходят на потоки
    /// MTA, и держать их надо там же, где создан `IUIAutomation`. `spawn` ждёт
    /// подтверждения регистрации, поэтому `None` означает «подписки нет», а не
    /// «может быть, она появится позже».
    pub fn spawn(
        pid: u32,
        tx: tokio::sync::mpsc::Sender<ActionEvent>,
        stop: Arc<AtomicBool>,
    ) -> Option<std::thread::JoinHandle<()>> {
        let (hwnd, _title) = find_main_window(pid)?;
        let process = process_name(pid);
        let shared = Arc::new(Shared {
            pid,
            process,
            main_hwnd: AtomicIsize::new(hwnd.0 as isize),
            dead: AtomicBool::new(false),
        });
        let (ready_tx, ready_rx) = sync_channel::<bool>(1);
        let thread_shared = Arc::clone(&shared);
        let handle = match std::thread::Builder::new()
            .name(format!("uia-{pid}"))
            .spawn(move || run(pid, tx, stop, thread_shared, ready_tx))
        {
            Ok(handle) => handle,
            Err(err) => {
                warn!(pid, %err, "не удалось запустить поток подписки UIA");
                return None;
            }
        };
        match ready_rx.recv_timeout(READY_TIMEOUT) {
            Ok(true) => Some(handle),
            Ok(false) => {
                let _ = handle.join();
                None
            }
            Err(_) => {
                shared.dead.store(true, Ordering::Relaxed);
                warn!(pid, "поток UIA не подтвердил подписку за {:?}", READY_TIMEOUT);
                None
            }
        }
    }

    /// Клик-канал для программ, которые не поднимают ни `Invoke`, ни `focus`.
    ///
    /// Delphi/VCL (PCMflash) отдаёт кнопки как `ControlType.Pane` с Win32-классом
    /// `Button`: ни `InvokePattern`, ни событий фокуса у них нет — проверено
    /// прогоном на живом PCMflash. Поэтому действие определяется по клику:
    /// состояние левой кнопки читается 40 раз в секунду, а элемент — через
    /// `ElementFromPoint`, и только если окно под курсором принадлежит целевому
    /// pid. Чужие окна отбрасываются до чтения имени; клавиатура не читается и
    /// не перехватывается, события не подменяются.
    pub fn spawn_click_watch(
        pid: u32,
        tx: tokio::sync::mpsc::Sender<ActionEvent>,
        stop: Arc<AtomicBool>,
    ) -> Option<std::thread::JoinHandle<()>> {
        std::thread::Builder::new()
            .name(format!("uia-click-{pid}"))
            .spawn(move || click_loop(pid, tx, stop))
            .ok()
    }

    /// Цикл клик-канала: фронт нажатия → элемент под курсором → событие.
    fn click_loop(pid: u32, tx: tokio::sync::mpsc::Sender<ActionEvent>, stop: Arc<AtomicBool>) {
        let _com = match ComApartment::new() {
            Ok(guard) => guard,
            Err(err) => {
                warn!(pid, %err, "клик-канал: COM не инициализирован");
                return;
            }
        };
        let uia = match create_uia() {
            Ok(uia) => uia,
            Err(err) => {
                warn!(pid, %err, "клик-канал не начат");
                return;
            }
        };
        let process = process_name(pid);
        let mut dedup = Deduper::new(250);
        let mut was_down = false;
        while !stop.load(Ordering::Relaxed) {
            let down = unsafe { GetAsyncKeyState(VK_LBUTTON.0 as i32) } as u16 & 0x8000 != 0;
            if down && !was_down {
                was_down = true;
                if let Some(ev) = click_event(&uia, pid, &process) {
                    let pair = element_key(&ev);
                    if dedup.accept(&pair) && tx.blocking_send(ev).is_err() {
                        break;
                    }
                }
            } else if !down {
                was_down = false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        debug!(pid, "клик-канал остановлен");
    }

    /// Событие клика по элементу целевого окна. `None` — клик мимо цели.
    fn click_event(uia: &IUIAutomation, pid: u32, process: &str) -> Option<ActionEvent> {
        let mut point = POINT::default();
        unsafe { GetCursorPos(&mut point) }.ok()?;
        let under = unsafe { WindowFromPoint(point) };
        if under.is_invalid() {
            return None;
        }
        let root = unsafe { GetAncestor(under, GA_ROOT) };
        let root = if root.is_invalid() { under } else { root };
        let mut owner = 0u32;
        unsafe { GetWindowThreadProcessId(root, Some(&mut owner as *mut u32)) };
        if owner != pid {
            return None;
        }
        let element = unsafe { uia.ElementFromPoint(point) }.ok()?;
        let mut name = bstr_text(unsafe { element.CurrentName() });
        if name.is_empty() {
            name = legacy_name(&element);
        }
        let automation_id = bstr_text(unsafe { element.CurrentAutomationId() });
        if name.is_empty() {
            name = automation_id.clone();
        }
        if name.is_empty() {
            return None;
        }
        // VCL отдаёт кнопку как Pane; настоящий тип виден по Win32-классу окна.
        let class = bstr_text(unsafe { element.CurrentClassName() });
        let control_type = unsafe { element.CurrentControlType() }.unwrap_or_default();
        let control_name = match class.to_ascii_lowercase().as_str() {
            "button" => "Button".to_string(),
            "combobox" => "ComboBox".to_string(),
            _ => control_type_name(control_type).to_string(),
        };
        // Поля ввода, подписи и списки — не команда оператора: их не пишем.
        if !matches!(
            control_name.as_str(),
            "Button" | "SplitButton" | "MenuItem" | "TabItem" | "CheckBox" | "RadioButton"
        ) {
            return None;
        }
        let (x, y, w, h) = bounding_rect(&element);
        let title = window_text(root);
        let window = if title.is_empty() {
            find_main_window(pid)
                .map(|(_, title)| title)
                .unwrap_or_default()
        } else {
            title
        };
        Some(ActionEvent {
            wall: now_rfc3339(),
            name: name.clone(),
            automation_id,
            control_type: control_name,
            window,
            process: process.to_string(),
            pid,
            event: "click".to_string(),
            activation: "click".to_string(),
            confirmed: true,
            source: "uia_click".to_string(),
            action: classify(&name).to_string(),
            x,
            y,
            w,
            h,
        })
    }
    /// Тело потока подписки: инициализация COM, регистрация, ожидание stop, снятие.
    fn run(
        pid: u32,
        tx: tokio::sync::mpsc::Sender<ActionEvent>,
        stop: Arc<AtomicBool>,
        shared: Arc<Shared>,
        ready: SyncSender<bool>,
    ) {
        let _com = match ComApartment::new() {
            Ok(guard) => guard,
            Err(err) => {
                warn!(pid, %err, "подписка UIA не начата: COM не инициализирован");
                let _ = ready.send(false);
                return;
            }
        };
        let uia = match create_uia() {
            Ok(uia) => uia,
            Err(err) => {
                warn!(pid, %err, "подписка UIA не начата");
                let _ = ready.send(false);
                return;
            }
        };
        let hwnd = HWND(shared.main_hwnd.load(Ordering::Relaxed) as *mut c_void);
        let root = match unsafe { uia.ElementFromHandle(hwnd) } {
            Ok(element) => element,
            Err(err) => {
                warn!(pid, %err, "ElementFromHandle не удался — подписки нет");
                let _ = ready.send(false);
                return;
            }
        };

        let data = Arc::new(SinkData {
            tx,
            shared: Arc::clone(&shared),
            stop: Arc::clone(&stop),
            dedup: parking_lot::Mutex::new(Deduper::new(DEDUPE_WINDOW_MS)),
        });
        let invoke_sink = new_invoke_sink(Some(Arc::clone(&data)));
        let focus_sink = new_focus_sink(Some(Arc::clone(&data)));

        if let Err(err) = unsafe {
            uia.AddAutomationEventHandler(
                UIA_Invoke_InvokedEventId,
                &root,
                TreeScope_Subtree,
                None,
                &invoke_sink,
            )
        } {
            warn!(pid, %err, "не удалось подписаться на событие Invoke");
            let _ = ready.send(false);
            return;
        }
        let cache = cache_request(&uia);
        match unsafe { uia.AddFocusChangedEventHandler(cache.as_ref(), &focus_sink) } {
            Ok(()) => debug!(pid, "резервная подписка на смену фокуса активна"),
            Err(err) => warn!(
                pid,
                %err,
                "подписка на фокус не удалась — останется только Invoke"
            ),
        }

        if ready.send(true).is_err() {
            // Вызывающий уже не ждёт ответа; жизнь потока решают stop/dead.
            debug!(pid, "подтверждение подписки UIA никому не нужно");
        }

        // MTA не требует насоса сообщений: колбэки приходят на потоки MTA от UIA.
        while !stop.load(Ordering::Relaxed) && !shared.dead.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }

        // Снимаем обработчики до освобождения ссылок: иначе UIA держала бы объект
        // (и наш поток не завершился бы вместе с процессом при закрытии окна).
        unsafe {
            let _ = uia.RemoveFocusChangedEventHandler(&focus_sink);
            let _ = uia.RemoveAllEventHandlers();
        }
        drop(invoke_sink);
        drop(focus_sink);
        drop(data);
        debug!(pid, "подписка UIA остановлена");
    }
}

#[cfg(windows)]
pub use platform::{availability, spawn, spawn_click_watch};

#[cfg(not(windows))]
pub fn availability(pid: u32) -> Availability {
    Availability {
        pid,
        error: Some("только Windows".to_string()),
        ..Default::default()
    }
}

#[cfg(not(windows))]
pub fn spawn(
    _pid: u32,
    _tx: tokio::sync::mpsc::Sender<ActionEvent>,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

#[cfg(not(windows))]
pub fn spawn_click_watch(
    _pid: u32,
    _tx: tokio::sync::mpsc::Sender<ActionEvent>,
    _stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    None
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn event(name: &str, automation_id: &str, control_type: &str, kind: &str) -> ActionEvent {
        ActionEvent {
            name: name.to_string(),
            automation_id: automation_id.to_string(),
            control_type: control_type.to_string(),
            event: kind.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn classify_identify() {
        assert_eq!(classify("Идентификация"), "identify");
        assert_eq!(classify("ИДЕНТИФИКАЦИЯ"), "identify");
        assert_eq!(classify("Identification"), "identify");
        assert_eq!(classify("Identify ECU"), "identify");
    }

    #[test]
    fn classify_read() {
        assert_eq!(classify("Считать…"), "read");
        assert_eq!(classify("Чтение"), "read");
        assert_eq!(classify("Прочитать full"), "read");
        assert_eq!(classify("Read ROM"), "read");
    }

    #[test]
    fn classify_write() {
        assert_eq!(classify("Записать (full)"), "write");
        assert_eq!(classify("Запись"), "write");
        assert_eq!(classify("write flash"), "write");
    }

    #[test]
    fn classify_verify_and_erase_and_reset() {
        assert_eq!(classify("Проверка КС"), "verify");
        assert_eq!(classify("Verify checksum"), "verify");
        assert_eq!(classify("Стереть"), "erase");
        assert_eq!(classify("Удалить файл"), "erase");
        assert_eq!(classify("Erase flash"), "erase");
        assert_eq!(classify("Сброс"), "reset");
        assert_eq!(classify("Адаптации"), "reset");
        assert_eq!(classify("Reset adaptations"), "reset");
    }

    #[test]
    fn classify_errors_wins_over_erase_and_reset() {
        // «ошибки» приоритетнее: это очистка кодов неисправностей, а не стирание/сброс.
        assert_eq!(classify("Стереть ошибки"), "errors");
        assert_eq!(classify("Сброс ошибок"), "errors");
        assert_eq!(classify("Clear"), "errors");
        assert_eq!(classify("Read DTC"), "errors");
        assert_eq!(classify("Fault codes"), "errors");
    }

    #[test]
    fn classify_other() {
        assert_eq!(classify("OK"), "other");
        assert_eq!(classify("Закрыть"), "other");
        assert_eq!(classify(""), "other");
        assert_eq!(classify("..."), "other");
    }

    #[test]
    fn dedupe_key_is_stable_and_normalized() {
        let first = event("Идентификация", "btnIdentify", "Button", "invoke");
        let same = event("  идентификация ", "BTNIDENTIFY", " button ", "INVOKE");
        assert_eq!(dedupe_key(&first), dedupe_key(&same));
        assert_eq!(dedupe_key(&first), dedupe_key(&first.clone()));
    }

    #[test]
    fn dedupe_key_separates_event_kind() {
        let invoke = event("Считать", "btnRead", "Button", "invoke");
        let focus = event("Считать", "btnRead", "Button", "focus");
        assert_ne!(dedupe_key(&invoke), dedupe_key(&focus));
        let other_name = event("Записать", "btnRead", "Button", "invoke");
        assert_ne!(dedupe_key(&invoke), dedupe_key(&other_name));
    }

    #[test]
    fn dedupe_key_escapes_empty_fields() {
        // Пустые имена — не паника и не «склейка» с соседним событием.
        let empty = ActionEvent::default();
        assert_eq!(dedupe_key(&empty), "|||");
        let mut named = ActionEvent::default();
        named.name = "OK".to_string();
        assert_ne!(dedupe_key(&empty), dedupe_key(&named));
    }

    #[test]
    fn deduper_suppresses_within_window_and_allows_after() {
        let mut deduper = Deduper::new(250);
        assert!(deduper.accept("k"));
        assert!(!deduper.accept("k"), "второе событие в окне — дубль");
        std::thread::sleep(Duration::from_millis(300));
        assert!(deduper.accept("k"), "после окна событие снова новое");
        assert!(deduper.accept("other"), "другой ключ — не дубль");
    }

    #[test]
    fn deduper_zero_window_accepts_everything() {
        let mut deduper = Deduper::new(0);
        assert!(deduper.accept("k"));
        assert!(deduper.accept("k"));
    }
}
