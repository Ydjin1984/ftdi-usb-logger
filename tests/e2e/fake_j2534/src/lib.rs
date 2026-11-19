//! Поддельный J2534-драйвер (PassThru 04.04) без устройства и без побочек.
//!
//! Два назначения:
//!
//! 1. **Регрессия «логируется только первый шаг».** PCMflash после своей операции
//!    делает `PassThruClose` + `FreeLibrary(smj2534.dll)`, а для следующего
//!    действия грузит DLL заново — Windows часто кладёт её по тому же base. Без
//!    перевешивания хуков второй проход уходит в пустоту.
//! 2. **Стенд полноты захвата (docs/09 §10).** Экспортирует все 14 функций
//!    штатного набора, поэтому прогон проверяет: `# hooks attached=14`,
//!    `connect`/`gen`, пакетный `WriteMsgs` (n_in=5, драйвер принял 2),
//!    пакетный `ReadMsgs` (3 сообщения, из них одно SOF), `FAST_INIT` с
//!    `PASSTHRU_MSG` на входе и выходе, фильтр с маской и паттерном,
//!    подавленные `ERR_TIMEOUT`/`ERR_BUFFER_EMPTY`.
//!
//! Раскладка `PASSTHRU_MSG` — как в 04.04: шесть 4-байтовых полей (24) плюс
//! `Data[4128]`; `unsigned long` в J2534 остаётся 4-байтовым и на x64.

use std::sync::atomic::{AtomicUsize, Ordering};

pub const STATUS_NOERROR: i32 = 0;
pub const ERR_TIMEOUT: i32 = 0x11;
pub const ERR_BUFFER_EMPTY: i32 = 0x10;

/// `PASSTHRU_MSG` 04.04: 24 байта заголовка + `Data[4128]` = 4152.
#[repr(C)]
pub struct PassThruMsg {
    pub protocol_id: u32,
    pub rx_status: u32,
    pub tx_flags: u32,
    pub timestamp: u32,
    pub data_size: u32,
    pub extra_data_index: u32,
    pub data: [u8; 4128],
}

/// `SCONFIG`: пара «параметр = значение» (DATA_RATE = 0x01).
#[repr(C)]
pub struct SConfig {
    pub parameter: u32,
    pub value: u32,
}

/// `SCONFIG_LIST`: счётчик + указатель (выравнивание по указателю).
#[repr(C)]
pub struct SConfigList {
    pub num_of_params: u32,
    pub config_ptr: *mut SConfig,
}

/// Сколько раз вызывали `ReadMsgs`: первые два вызова отдают `ERR_TIMEOUT`,
/// чтобы в логе появилась строка `rx-empty` (D3), а не тишина.
static READ_CALLS: AtomicUsize = AtomicUsize::new(0);

// Счётчики вызовов у «пустых» функций. Нужны не для логики, а чтобы код каждой
// функции отличался: оптимизатор склеивает идентичные тела в один адрес, и
// тогда Frida не может поставить хук на второй (identical code folding).
static CLOSE_CALLS: AtomicUsize = AtomicUsize::new(0);
static DISC_CALLS: AtomicUsize = AtomicUsize::new(0);
static STOPF_CALLS: AtomicUsize = AtomicUsize::new(0);
static STOPP_CALLS: AtomicUsize = AtomicUsize::new(0);
static VOLT_CALLS: AtomicUsize = AtomicUsize::new(0);

fn msg_zeroed() -> PassThruMsg {
    PassThruMsg {
        protocol_id: 0,
        rx_status: 0,
        tx_flags: 0,
        timestamp: 0,
        data_size: 0,
        extra_data_index: 0,
        data: [0u8; 4128],
    }
}

/// Записать сообщение в массив драйвера (по индексу).
unsafe fn put_msg(base: *mut PassThruMsg, index: usize, proto: u32, rxs: u32, flags: u32, bytes: &[u8]) {
    put_msg_xdi(base, index, proto, rxs, flags, bytes, 0);
}

/// То же + `ExtraDataIndex` (для ISO15765 extra-данных; стенд проверяет `xdi=`).
unsafe fn put_msg_xdi(
    base: *mut PassThruMsg,
    index: usize,
    proto: u32,
    rxs: u32,
    flags: u32,
    bytes: &[u8],
    xdi: u32,
) {
    let slot = base.add(index);
    let mut m = msg_zeroed();
    m.protocol_id = proto;
    m.rx_status = rxs;
    m.tx_flags = flags;
    m.timestamp = 0;
    m.data_size = bytes.len() as u32;
    m.extra_data_index = xdi;
    let n = bytes.len().min(4128);
    m.data[..n].copy_from_slice(&bytes[..n]);
    std::ptr::write(slot, m);
}

unsafe fn write_str(dst: *mut u8, text: &str) {
    if dst.is_null() {
        return;
    }
    for (i, byte) in text.as_bytes().iter().enumerate() {
        *dst.add(i) = *byte;
    }
    *dst.add(text.len()) = 0;
}

#[no_mangle]
pub extern "system" fn PassThruOpen(_name: *const u8, dev: *mut u32) -> i32 {
    if !dev.is_null() {
        unsafe { *dev = 1 };
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruClose(_dev: u32) -> i32 {
    CLOSE_CALLS.fetch_add(1, Ordering::Relaxed);
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruConnect(
    _dev: u32,
    _proto: u32,
    _flags: u32,
    _baud: u32,
    channel: *mut u32,
) -> i32 {
    if !channel.is_null() {
        unsafe { *channel = 1 };
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruDisconnect(_channel: u32) -> i32 {
    DISC_CALLS.fetch_add(1, Ordering::Relaxed);
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruReadMsgs(
    _channel: u32,
    msgs: *mut PassThruMsg,
    num: *mut u32,
    timeout: u32,
) -> i32 {
    if num.is_null() {
        return ERR_BUFFER_EMPTY;
    }
    let want = unsafe { *num } as usize;

    // ── сценарии стенда (docs/12 §9), выбираются значением `timeout` ────────
    // 777: драйвер снял сообщения с очереди, но вернул код «пусто». Контракт
    // разрешает такие частичные результаты — логгер обязан их сохранить.
    if timeout == 777 {
        if msgs.is_null() || want < 2 {
            unsafe { *num = 0 };
            return ERR_BUFFER_EMPTY;
        }
        unsafe {
            put_msg(msgs, 0, 0x8003, 0x00, 0, &[0x00, 0x03, 0x67, 0x85, 0x11]);
            put_msg(msgs, 1, 0x8003, 0x00, 0, &[0x00, 0x02, 0xc1, 0x00]);
            *num = 2;
        }
        return ERR_BUFFER_EMPTY;
    }
    // 778: драйвер записал больше, чем дали (n_out > n_in). Пишем только в
    // пределах входной ёмкости, но счётчик выставляем на 12 — логгер обязан
    // прочитать ровно `n_in` и зафиксировать нарушение контракта.
    if timeout == 778 {
        let slots = want.min(10);
        unsafe {
            for i in 0..slots {
                put_msg(msgs, i, 0x8003, 0x00, 0, &[0x00, 0x03, 0xc0, 0x0e + i as u8]);
            }
            *num = 12;
        }
        return STATUS_NOERROR;
    }
    // 779: CAN-кадр: первые 4 байта Data — идентификатор, ExtraDataIndex=9.
    if timeout == 779 {
        if msgs.is_null() || want < 1 {
            unsafe { *num = 0 };
            return ERR_BUFFER_EMPTY;
        }
        unsafe {
            put_msg_xdi(
                msgs,
                0,
                5,
                0,
                0,
                &[0x00, 0x00, 0x07, 0xe8, 0x06, 0x50, 0x03, 0x00, 0x00, 0xaa, 0xbb],
                9,
            );
            *num = 1;
        }
        return STATUS_NOERROR;
    }

    let call = READ_CALLS.fetch_add(1, Ordering::SeqCst);
    // D3: штатные «ответа нет» — ERR_TIMEOUT, затем ERR_BUFFER_EMPTY.
    if call < 2 {
        unsafe { *num = 0 };
        return ERR_TIMEOUT;
    }
    if call == 2 {
        unsafe { *num = 0 };
        return ERR_BUFFER_EMPTY;
    }
    if msgs.is_null() || want < 3 {
        unsafe { *num = 0 };
        return ERR_BUFFER_EMPTY;
    }
    unsafe {
        // 1) маркер начала сообщения: rxs=0x02, данных нет (D2).
        put_msg(msgs, 0, 0x8003, 0x02, 0, &[]);
        // 2) и 3) полезные кадры вендорного протокола Scanmatik/PCMflash.
        put_msg(msgs, 1, 0x8003, 0x00, 0, &[0x00, 0x03, 0x67, 0x7F, 0x34]);
        put_msg(msgs, 2, 0x8003, 0x00, 0, &[0x00, 0x02, 0x67, 0x01]);
        *num = 3;
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruWriteMsgs(
    _channel: u32,
    _msgs: *mut PassThruMsg,
    num: *mut u32,
    _timeout: u32,
) -> i32 {
    if num.is_null() {
        return ERR_BUFFER_EMPTY;
    }
    // Приложение передало 5 сообщений, драйвер принял 2 — полнота TX (§3):
    // в логе обязаны остаться все пять входных и n_out=2.
    unsafe { *num = 2 };
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruStartMsgFilter(
    _channel: u32,
    _kind: u32,
    _mask: *mut PassThruMsg,
    _pattern: *mut PassThruMsg,
    _flow: *mut PassThruMsg,
    filter_id: *mut u32,
) -> i32 {
    if !filter_id.is_null() {
        unsafe { *filter_id = 1 };
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruStopMsgFilter(_channel: u32, _filter_id: u32) -> i32 {
    STOPF_CALLS.fetch_add(1, Ordering::Relaxed);
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruStartPeriodicMsg(
    _channel: u32,
    _msg: *mut PassThruMsg,
    msg_id: *mut u32,
    _interval: u32,
) -> i32 {
    if !msg_id.is_null() {
        unsafe { *msg_id = 7 };
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruStopPeriodicMsg(_channel: u32, _msg_id: u32) -> i32 {
    STOPP_CALLS.fetch_add(1, Ordering::Relaxed);
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruIoctl(
    _channel: u32,
    ioctl_id: u32,
    input: *mut u8,
    output: *mut u8,
) -> i32 {
    unsafe {
        match ioctl_id {
            // FAST_INIT: на входе PASSTHRU_MSG, на выходе тоже (не «4 байта»).
            0x05 => {
                if !output.is_null() {
                    let out = output as *mut PassThruMsg;
                    put_msg(out, 0, 0x8003, 0x00, 0, &[0x00, 0x03, 0x67]);
                }
                if !input.is_null() {
                    // Эхо входа не нужно: агент читает вход до вызова сам.
                }
                STATUS_NOERROR
            }
            // READ_VBATT: unsigned long на выходе.
            0x03 => {
                if !output.is_null() {
                    let value: u32 = 12_000;
                    std::ptr::write(output as *mut u32, value);
                }
                STATUS_NOERROR
            }
            // SET_CONFIG: SCONFIG_LIST на входе (DATA_RATE).
            0x02 => {
                if !input.is_null() {
                    let list = input as *mut SConfigList;
                    let n = (*list).num_of_params as usize;
                    if !(*list).config_ptr.is_null() && n > 0 {
                        // Читаем — это доказывает, что указатель валиден.
                        let _rate = (*(*list).config_ptr).value;
                    }
                }
                STATUS_NOERROR
            }
            _ => STATUS_NOERROR,
        }
    }
}

#[no_mangle]
pub extern "system" fn PassThruGetLastError(desc: *mut u8) -> i32 {
    unsafe { write_str(desc, "no error") };
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruReadVersion(
    _dev: u32,
    firmware: *mut u8,
    dll: *mut u8,
    api: *mut u8,
) -> i32 {
    unsafe {
        write_str(firmware, "FW:1060 HW:02 SN:TEST01");
        write_str(dll, "1.0.0.120");
        // Именно эта строка подтверждает ABI: 04.04 → раскладка PASSTHRU_MSG верна.
        write_str(api, "04.04");
    }
    STATUS_NOERROR
}

#[no_mangle]
pub extern "system" fn PassThruSetProgrammingVoltage(_dev: u32, _pin: u32, _voltage: u32) -> i32 {
    VOLT_CALLS.fetch_add(1, Ordering::Relaxed);
    STATUS_NOERROR
}
