//! Поддельный J2534-драйвер: две функции, без устройства и без побочек.
//!
//! Нужен, чтобы воспроизвести поведение PCMflash: после своей операции он делает
//! `PassThruClose` + `FreeLibrary(smj2534.dll)`, а для следующего действия грузит
//! DLL заново — Windows при этом часто кладёт её по тому же base. Если логер не
//! перевешивает хуки, второй проход уходит в пустоту (в логе только первый шаг).

#[no_mangle]
pub extern "system" fn PassThruOpen(_name: *const u8, dev: *mut u32) -> i32 {
    if !dev.is_null() {
        unsafe { *dev = 1 };
    }
    0
}

#[no_mangle]
pub extern "system" fn PassThruClose(_dev: u32) -> i32 {
    0
}
