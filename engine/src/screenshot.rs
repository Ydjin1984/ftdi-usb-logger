//! Скриншоты окна целевого процесса. Владелец: boba.
//!
//! Порядок:
//! 1. ищем окна верхнего уровня нужного pid; **скрытые окна отбрасываем** — иначе
//!    PrintWindow отдаёт пустой белый кадр, который нельзя отличить от «нормального»;
//! 2. проверяем непустую клиентскую область (`GetClientRect`);
//! 3. пробуем `PrintWindow(PW_RENDERFULLCONTENT)` — он рисует содержимое даже для
//!    перекрытых/свёрнутых окон и не зависит от z-order;
//! 4. если кадр однотонный (пустой/белый) — второй способ: `BitBlt` с экранного DC по
//!    тому же rect (аналог `snap.ps1`/`CopyFromScreen`);
//! 5. если оба способа дали пустоту — понятная ошибка с hwnd/rect/размером, чтобы UI
//!    показал toast, а не сохранил белый файл;
//! 6. PNG пишется атомарно: временный файл рядом + `rename`.
//!
//! `ShotInfo` (hwnd, rect, метод) уходит в мету событий `shot`/`step_end`, чтобы было видно,
//! каким способом снят кадр. Возвращаемый путь — всегда относительный, со слэшами `/`.

use anyhow::{bail, Context};
use std::path::Path;

// `PrintWindow` с флагом 2 (`PW_RENDERFULLCONTENT`) не объявлен в windows-0.58 без фичи
// `Win32_Storage_Xps`, поэтому линкуем user32 напрямую — сигнатура ровно как в winuser.h.
#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    #[link_name = "PrintWindow"]
    fn print_window(
        hwnd: windows::Win32::Foundation::HWND,
        hdc: windows::Win32::Graphics::Gdi::HDC,
        flags: u32,
    ) -> windows::Win32::Foundation::BOOL;
}

/// Флаг `PW_RENDERFULLCONTENT`: рендерить содержимое, отрисованное DirectComposition.
#[cfg(windows)]
const PW_RENDERFULLCONTENT: u32 = 0x0000_0002;

/// Геометрия снятого окна (в экранных координатах, как `GetWindowRect`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RectInfo {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl RectInfo {
    pub fn width(&self) -> i32 {
        self.right - self.left
    }
    pub fn height(&self) -> i32 {
        self.bottom - self.top
    }
    /// `(left,top)-(right,bottom)` для логов/меты.
    pub fn describe(&self) -> String {
        format!(
            "({},{})-({},{}) {}x{}",
            self.left,
            self.top,
            self.right,
            self.bottom,
            self.width(),
            self.height()
        )
    }
}

/// Что и как сняли — уходит в `meta` события `shot`/`step_end`.
#[derive(Debug, Clone, Default)]
pub struct ShotInfo {
    pub hwnd: isize,
    pub rect: RectInfo,
    pub width: u32,
    pub height: u32,
    /// `printwindow` | `bitblt-screen`
    pub method: String,
    pub visible: bool,
    pub minimized: bool,
}

impl ShotInfo {
    /// Представление для `Event::meta`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hwnd": format!("0x{:x}", self.hwnd as usize),
            "rect": self.rect.describe(),
            "w": self.width,
            "h": self.height,
            "method": self.method,
            "visible": self.visible,
            "minimized": self.minimized,
        })
    }
}

/// Скриншот окна процесса `pid` в PNG-файл `out` (родительские каталоги создаются).
///
/// Контракт `docs/04-interfaces.md`; подробности (hwnd/rect/метод) — через
/// [`capture_window_for_pid_info`].
pub fn capture_window_for_pid(pid: u32, out: &Path) -> anyhow::Result<()> {
    capture_window_for_pid_info(pid, out).map(|_| ())
}

/// То же, но возвращает [`ShotInfo`] для меты события/лога.
pub fn capture_window_for_pid_info(pid: u32, out: &Path) -> anyhow::Result<ShotInfo> {
    #[cfg(windows)]
    {
        capture_impl(pid, out)
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, out);
        bail!("скриншоты окна поддерживаются только на Windows")
    }
}

#[cfg(windows)]
fn capture_impl(pid: u32, out: &Path) -> anyhow::Result<ShotInfo> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::UI::WindowsAndMessaging::{GetClientRect, IsIconic};

    fn area(rect: RECT) -> i64 {
        (rect.right - rect.left).max(0) as i64 * (rect.bottom - rect.top).max(0) as i64
    }

    let windows = crate::procscan::windows_for_pid(pid);
    if windows.is_empty() {
        bail!(
            "окно целевой программы не найдено (pid={pid}): у процесса нет окон верхнего уровня"
        );
    }
    // Скрытые окна не рендерим: PrintWindow по ним отдаёт пустой белый кадр.
    let visible: Vec<_> = windows.iter().filter(|w| w.visible).collect();
    if visible.is_empty() {
        bail!(
            "окно целевой программы не найдено или скрыто (pid={pid}): все {} окна невидимы",
            windows.len()
        );
    }
    let best = visible
        .iter()
        .max_by_key(|w| area(w.rect))
        .expect("visible не пуст — проверено выше");

    // IsIconic до проверки клиентской области: у свёрнутого окна GetClientRect отдаёт 0x0,
    // но PrintWindow(PW_RENDERFULLCONTENT) всё ещё может отрисовать содержимое.
    let minimized = unsafe { IsIconic(best.hwnd).as_bool() };

    let mut client = RECT::default();
    // SAFETY: rect — локальная структура, hwnd получен из перечисления окон этого pid.
    let client_ok = unsafe { GetClientRect(best.hwnd, &mut client) }.is_ok();
    let client_w = client.right - client.left;
    let client_h = client.bottom - client.top;
    if !client_ok || client_w <= 0 || client_h <= 0 {
        if !minimized {
            bail!(
                "клиентская область окна pid={pid} пустая ({client_w}x{client_h}) — окно скрыто \
                 или не имеет содержимого, hwnd=0x{:x}",
                best.hwnd.0 as usize
            );
        }
        // Свёрнутое окно: пробуем рендер по window rect ниже; если пусто — будет внятная ошибка.
        tracing::debug!(
            "окно pid={pid} свёрнуто, клиентская область {client_w}x{client_h} — пробую PrintWindow"
        );
    }

    let rect = RectInfo {
        left: best.rect.left,
        top: best.rect.top,
        right: best.rect.right,
        bottom: best.rect.bottom,
    };
    let width = rect.width();
    let height = rect.height();
    if width <= 0 || height <= 0 {
        if minimized {
            bail!(
                "окно pid={pid} свёрнуто и имеет пустой размер ({width}x{height}) — разверните окно \
                 и повторите скриншот"
            );
        }
        bail!("окно pid={pid} имеет пустой размер ({width}x{height})");
    }

    // SAFETY: GDI-объекты создаются и освобождаются внутри render_window; HWND взят из
    // перечисления окон этого pid (если окно закроется — PrintWindow/BitBlt просто вернут пусто).
    let (pixels, method) = unsafe { render_window(best.hwnd, rect) }.with_context(|| {
        format!(
            "окно pid={pid} (hwnd=0x{:x}, rect={}, свёрнуто={minimized}{})",
            best.hwnd.0 as usize,
            rect.describe(),
            if minimized {
                " — возможно, окно свёрнуто; разверните его"
            } else {
                ""
            }
        )
    })?;

    save_png_atomic(out, &pixels, width as u32, height as u32)?;
    tracing::debug!(
        "скриншот pid={pid}: метод={method} hwnd=0x{:x} rect={} {}x{} свёрнуто={minimized}",
        best.hwnd.0 as usize,
        rect.describe(),
        width,
        height
    );
    Ok(ShotInfo {
        hwnd: best.hwnd.0 as isize,
        rect,
        width: width as u32,
        height: height as u32,
        method: method.to_string(),
        visible: best.visible,
        minimized,
    })
}

/// GDI-рендер окна: PrintWindow → (если кадр пустой) BitBlt с экрана.
///
/// Возвращает RGBA-пиксели и имя метода; пустой кадр от обоих способов — ошибка.
/// SAFETY: вызывать только с валидным hwnd; все GDI-дескрипторы создаются/освобождаются здесь.
#[cfg(windows)]
unsafe fn render_window(
    hwnd: windows::Win32::Foundation::HWND,
    rect: RectInfo,
) -> anyhow::Result<(Vec<u8>, &'static str)> {
    use windows::Win32::Foundation::{BOOL, HWND};
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        ReleaseDC, SelectObject, SRCCOPY,
    };

    let width = rect.width();
    let height = rect.height();
    let null_hwnd = HWND(std::ptr::null_mut());
    // SAFETY: см. контракт функции; дескрипторы освобождаются до возврата.
    unsafe {
        let screen = GetDC(null_hwnd);
        if screen.0.is_null() {
            bail!("GetDC(NULL) вернул пустой HDC");
        }
        let mem = CreateCompatibleDC(screen);
        if mem.0.is_null() {
            let _ = ReleaseDC(null_hwnd, screen);
            bail!("CreateCompatibleDC вернул пустой HDC");
        }
        let bitmap = CreateCompatibleBitmap(screen, width, height);
        if bitmap.0.is_null() {
            let _ = DeleteDC(mem);
            let _ = ReleaseDC(null_hwnd, screen);
            bail!("CreateCompatibleBitmap({width}x{height}) не создал битмап");
        }
        let old_object = SelectObject(mem, bitmap);

        let result = (|| -> anyhow::Result<(Vec<u8>, &'static str)> {
            // 1) PrintWindow(PW_RENDERFULLCONTENT): не зависит от перекрытия и z-order.
            let printed = print_window(hwnd, mem, PW_RENDERFULLCONTENT) != BOOL(0);
            let print_pixels = read_dib(screen, bitmap, width, height)?;
            if printed && !is_blank(&print_pixels) {
                return Ok((print_pixels, "printwindow"));
            }

            // 2) BitBlt с экрана по тому же rect (как snap.ps1 через CopyFromScreen).
            //    Используется только как фолбэк, когда PrintWindow дал пустой/белый кадр.
            let _ = BitBlt(
                mem,
                0,
                0,
                width,
                height,
                screen,
                rect.left,
                rect.top,
                SRCCOPY,
            );
            let screen_pixels = read_dib(screen, bitmap, width, height)?;
            if !is_blank(&screen_pixels) {
                return Ok((screen_pixels, "bitblt-screen"));
            }

            if printed {
                bail!(
                    "окно не отрисовалось: PrintWindow вернул пустой кадр, BitBlt с экрана тоже пуст \
                     (rect={}, {}x{})",
                    rect.describe(),
                    width,
                    height
                );
            }
            bail!(
                "окно не отрисовалось: PrintWindow завершился ошибкой, BitBlt с экрана дал пустой кадр \
                 (rect={}, {}x{}, возможно окно свёрнуто за пределами экрана)",
                rect.describe(),
                width,
                height
            );
        })();

        let _ = SelectObject(mem, old_object);
        let _ = DeleteObject(bitmap);
        let _ = DeleteDC(mem);
        let _ = ReleaseDC(null_hwnd, screen);
        result
    }
}

/// Скопировать пиксели битмапа в BGRA-буфер (32 бита, top-down) и сразу отдать RGBA.
#[cfg(windows)]
unsafe fn read_dib(
    screen: windows::Win32::Graphics::Gdi::HDC,
    bitmap: windows::Win32::Graphics::Gdi::HBITMAP,
    width: i32,
    height: i32,
) -> anyhow::Result<Vec<u8>> {
    use windows::Win32::Graphics::Gdi::{
        GetDIBits, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS,
    };

    let mut info = BITMAPINFO::default();
    info.bmiHeader = BITMAPINFOHEADER {
        biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width,
        // Отрицательная высота = top-down DIB (первая строка — верхняя).
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: 0, // BI_RGB
        biSizeImage: (width as u32) * (height as u32) * 4,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let mut buf = vec![0u8; (width as usize) * (height as usize) * 4];
    // SAFETY: buf имеет ровно width*height*4 байт под 32-битный DIB.
    let lines = unsafe {
        GetDIBits(
            screen,
            bitmap,
            0,
            height as u32,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    if lines == 0 {
        bail!("GetDIBits не вернул ни одной строки пикселей");
    }
    Ok(bgra_to_rgba(buf))
}

/// Атомарно записать RGBA как PNG: временный файл рядом, затем `rename`.
#[cfg(windows)]
fn save_png_atomic(out: &Path, rgba: &[u8], width: u32, height: u32) -> anyhow::Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("не создать каталог {}", parent.display()))?;
        }
    }
    let name = out
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "shot.png".into());
    let tmp = out.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let write_result = image::save_buffer_with_format(
        &tmp,
        rgba,
        width,
        height,
        image::ColorType::Rgba8,
        image::ImageFormat::Png,
    );
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow::anyhow!("записать временный PNG {}: {err}", tmp.display()));
    }
    match std::fs::rename(&tmp, out) {
        Ok(()) => Ok(()),
        Err(first) => {
            // На Windows rename поверх существующего файла может капризничать — заменяем явно.
            let _ = std::fs::remove_file(out);
            std::fs::rename(&tmp, out).map_err(|second| {
                let _ = std::fs::remove_file(&tmp);
                anyhow::anyhow!(
                    "заменить {}: {first}; повторно: {second}",
                    out.display()
                )
            })
        }
    }
}

/// Кадр однотонный (белый/чёрный/пустой) — признак неудачного PrintWindow.
fn is_blank(pixels: &[u8]) -> bool {
    let Some(first) = pixels.get(..4) else {
        return true;
    };
    pixels.chunks_exact(4).all(|px| px == first)
}

/// BGRA (как отдаёт GDI на little-endian) → RGBA для PNG; альфа принудительно непрозрачная.
fn bgra_to_rgba(mut pixels: Vec<u8>) -> Vec<u8> {
    for px in pixels.chunks_exact_mut(4) {
        px.swap(0, 2);
        px[3] = 255;
    }
    pixels
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bgra_swaps_channels_and_forces_opaque() {
        let out = bgra_to_rgba(vec![1, 2, 3, 0, 10, 20, 30, 40]);
        assert_eq!(out, vec![3, 2, 1, 255, 30, 20, 10, 255]);
    }

    #[test]
    fn blank_detection() {
        assert!(is_blank(&[]));
        assert!(is_blank(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(is_blank(&[255, 255, 255, 255, 255, 255, 255, 255]));
        assert!(!is_blank(&[0, 0, 0, 0, 1, 0, 0, 0]));
    }

    #[test]
    fn rect_description_and_size() {
        let rect = RectInfo {
            left: 10,
            top: 20,
            right: 110,
            bottom: 220,
        };
        assert_eq!(rect.width(), 100);
        assert_eq!(rect.height(), 200);
        assert_eq!(rect.describe(), "(10,20)-(110,220) 100x200");
    }

    #[test]
    fn shot_info_json_has_method_and_rect() {
        let info = ShotInfo {
            hwnd: 0x1234,
            rect: RectInfo {
                left: 0,
                top: 0,
                right: 64,
                bottom: 32,
            },
            width: 64,
            height: 32,
            method: "printwindow".into(),
            visible: true,
            minimized: false,
        };
        let value = info.to_json();
        assert_eq!(value["hwnd"], "0x1234");
        assert_eq!(value["method"], "printwindow");
        assert_eq!(value["w"], 64);
        assert_eq!(value["rect"], "(0,0)-(64,32) 64x32");
    }

    #[test]
    fn missing_window_is_error_not_panic() {
        // pid 0xFFFF_FFF0 заведомо не существует у обычного пользователя.
        let out = std::env::temp_dir().join("ftdi_never_written.png");
        let err = capture_window_for_pid(0xFFFF_FFF0, &out).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("окно"), "непонятная ошибка: {text}");
        assert!(!out.exists());
    }

    /// У текущего тестового процесса нет окна: ошибка про окно, а не пустой PNG.
    #[test]
    fn own_process_without_window_errors() {
        let out = std::env::temp_dir().join("ftdi_own_process.png");
        let err = capture_window_for_pid_info(std::process::id(), &out).unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("окно") && (text.contains("не найдено") || text.contains("скрыто")),
            "неожиданная ошибка: {text}"
        );
        assert!(!out.exists());
    }

    /// Ручная проверка на живом окне: запускает notepad, снимает PNG, закрывает notepad.
    ///
    /// `#[ignore]`: нужен интерактивный рабочий стол, поэтому в обычном `cargo test` не идёт.
    /// Запуск: `cargo test --lib -- screenshot::tests::real_window_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_window_smoke() {
        let mut child = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить notepad.exe");
        // Даём окну появиться.
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let out = std::env::temp_dir().join("ftdi-notepad-smoke.png");
        let result = capture_window_for_pid_info(child.id(), &out);
        let _ = child.kill();
        let _ = child.wait();
        let info = result.expect("скриншот окна notepad");
        eprintln!(
            "скриншот: {} метод={} hwnd=0x{:x} rect={} {}x{} свёрнуто={}",
            out.display(),
            info.method,
            info.hwnd as usize,
            info.rect.describe(),
            info.width,
            info.height,
            info.minimized
        );
        assert!(info.visible, "окно notepad должно быть видимым");
        assert!(!info.method.is_empty());
        let meta = std::fs::metadata(&out).expect("PNG создан");
        assert!(meta.len() > 100, "PNG подозрительно маленький: {} Б", meta.len());
        let img = image::open(&out).expect("PNG читается image");
        assert!(img.width() > 40 && img.height() > 20, "размер {}x{}", img.width(), img.height());
        // Окно notepad не должно получиться однотонным (иначе PrintWindow/BitBlt дали пустой кадр).
        let rgba = img.to_rgba8();
        let mut colors = std::collections::HashSet::new();
        for px in rgba.pixels().step_by(101) {
            colors.insert((px[0], px[1], px[2]));
            if colors.len() >= 4 {
                break;
            }
        }
        assert!(colors.len() >= 2, "скриншот однотонный — окно не отрисовано");
        eprintln!("разных цветов в выборке: {}", colors.len());
        if std::env::var_os("FTDI_KEEP_SHOT").is_none() {
            let _ = std::fs::remove_file(&out);
        }
    }

    /// Ручная проверка перекрытого окна: второй notepad накрывает первый, но
    /// PrintWindow(PW_RENDERFULLCONTENT) должен отрисовать содержимое первого.
    ///
    /// Запуск: `cargo test --lib -- screenshot::tests::overlapped_window_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn overlapped_window_smoke() {
        let mut first = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить первый notepad");
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let mut second = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить второй notepad");
        std::thread::sleep(std::time::Duration::from_millis(1500));

        let out = std::env::temp_dir().join("ftdi-notepad-overlapped.png");
        let result = capture_window_for_pid_info(first.id(), &out);
        let _ = second.kill();
        let _ = first.kill();
        let _ = second.wait();
        let _ = first.wait();

        let info = result.expect("перекрытое окно должно сниматься");
        eprintln!(
            "перекрытое окно: метод={} rect={} {}x{}",
            info.method,
            info.rect.describe(),
            info.width,
            info.height
        );
        assert_eq!(info.method, "printwindow", "ожидался PrintWindow, не BitBlt с экрана");
        let img = image::open(&out).expect("PNG читается");
        let rgba = img.to_rgba8();
        let mut colors = std::collections::HashSet::new();
        for px in rgba.pixels().step_by(101) {
            colors.insert((px[0], px[1], px[2]));
            if colors.len() >= 4 {
                break;
            }
        }
        assert!(colors.len() >= 2, "перекрытое окно отрисовано однотонным кадром");
        let _ = std::fs::remove_file(&out);
    }

    /// Ручная проверка свёрнутого окна: PrintWindow(PW_RENDERFULLCONTENT) должен отрисовать
    /// содержимое; если не может — внятная ошибка (не белый PNG).
    ///
    /// Запуск: `cargo test --lib -- screenshot::tests::minimized_window_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn minimized_window_smoke() {
        use windows::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_MINIMIZE};

        let mut child = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить notepad.exe");
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let windows = crate::procscan::windows_for_pid(child.id());
        let Some(window) = windows.iter().find(|w| w.visible) else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("у notepad нет видимого окна");
        };
        // SAFETY: hwnd принадлежит запущенному notepad; ShowWindow — обычный вызов user32.
        unsafe {
            let _ = ShowWindow(window.hwnd, SW_MINIMIZE);
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        let out = std::env::temp_dir().join("ftdi-notepad-minimized.png");
        let result = capture_window_for_pid_info(child.id(), &out);
        let _ = child.kill();
        let _ = child.wait();
        match result {
            Ok(info) => {
                eprintln!(
                    "свёрнутое окно: метод={} rect={} {}x{}",
                    info.method,
                    info.rect.describe(),
                    info.width,
                    info.height
                );
                assert!(info.minimized, "окно должно считаться свёрнутым");
                assert!(!info.method.is_empty());
                let img = image::open(&out).expect("PNG читается");
                let rgba = img.to_rgba8();
                let mut colors = std::collections::HashSet::new();
                for px in rgba.pixels().step_by(101) {
                    colors.insert((px[0], px[1], px[2]));
                    if colors.len() >= 4 {
                        break;
                    }
                }
                assert!(
                    colors.len() >= 2,
                    "свёрнутое окно отрисовано однотонным кадром"
                );
                let _ = std::fs::remove_file(&out);
            }
            Err(err) => {
                let text = format!("{err:#}");
                eprintln!("свёрнутое окно: ошибка (это допустимо): {text}");
                assert!(
                    text.contains("окн") && (
                        text.contains("свёрнут")
                            || text.contains("скрыт")
                            || text.contains("не найдено")
                            || text.contains("пуст")
                            || text.contains("не отрисовалось")
                    ),
                    "непонятная ошибка: {text}"
                );
                assert!(!out.exists(), "при ошибке PNG не должен сохраняться");
            }
        }
    }
}
