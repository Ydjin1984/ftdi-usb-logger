//! Полоса J2534-прокси в сессии (docs/13 §6, §8): разбор журнала, сверка с
//! основным каналом, ini и состояние на пустом каталоге.
//!
//! Настоящий реестр здесь не трогается вообще: `install/remove/select-adapter`
//! пишут в HKLM/HKCU, а тест на чужой машине не имеет права менять чужие ключи.
//! Проверяются те части, которые работают с файлами: ini и чтение состояния.

use ftdi_logger::models::{now_rfc3339, ProxyLane};
use ftdi_logger::proxy;
use std::path::Path;

/// Окно сессии: журнал, созданный «сейчас», обязан попасть в сбор.
fn started_now() -> String {
    now_rfc3339()
}

/// Синтетический журнал ровно по грамматике docs/13 §6.
///
/// Числа в тесте выведены из этого текста, а не подогнаны: 2 кадра TX, 1 RX,
/// один `J2534 err` (rc=0x08), итоговая строка прокси `calls=10`.
const PROXY_LOG: &str = concat!(
    "# capture start: label=J2534 proxy\n",
    "# proxy: dll=\"C:\\app\\j2534proxy\\j2534proxy.dll\" real=\"C:\\Program Files (x86)\\Scanmatik\\smj2534.dll\" pid=8120 bits=32\n",
    "# wall(start)=2026-11-19 18:56:10.123\n",
    "# api: 04.04 dll=\"j2534proxy.dll\" ver=\"1.0.0.120\" path=\"C:\\app\\j2534proxy\\j2534proxy.dll\" pid=8120 bits=32 dec=1\n",
    "# agent: j2534proxy.dll mode=proxy\n",
    "[+0.100000s] J2534 open name=\"Scanmatik - SM2 USB\" dev=1 rc=0 th=8120\n",
    "[+0.200000s] J2534 connect dev=1 ch=1 proto=0x8003 flags=0x1000 baud=57600 rc=0 gen=1 th=8120 dur=57431\n",
    "[+0.300000s] J2534 call ch=1 call=7 op=PassThruIoctl ioctl=0x05(FAST_INIT) rc=0 th=8120 dur=812\n",
    "[+0.400000s] J2534 TX ch=1 call=8 i=1/1 n_in=1 n_out=1 th=8120 ts=0 flags=0x0 proto=0x8003 svc=0x27 len=4 dur=812 rc=0 : 00 02 27 7f\n",
    "[+0.500000s] J2534 RX ch=1 call=9 i=1/1 n_in=10 n_out=1 th=8120 ts=0 rxs=0x0 proto=0x8003 svc=0x50 len=8 dur=20134 rc=0 : 06 50 03 00 00 00 00 00\n",
    "[+0.600000s] J2534 vendor ord=1377 op=0x0 rc=0 th=8120 dur=31\n",
    "[+0.700000s] J2534 err op=PassThruConnect rc=0x08\n",
    "[+0.800000s] J2534 TX ch=1 call=10 i=1/1 n_in=1 n_out=1 th=8120 ts=0 flags=0x0 proto=0x8003 svc=0x3e len=2 dur=700 rc=0 : 3e 00\n",
    "# proxy stop: calls=10 tx=2 rx=1 errors=1\n",
);

fn write_log(dir: &Path, name: &str, text: &str) {
    std::fs::create_dir_all(dir).expect("каталог журналов");
    std::fs::write(dir.join(name), text).expect("журнал");
}

/// Событие основного канала в формате `events.jsonl` (как его пишет store).
fn main_event(seq: u64, kind: &str, hex: &str, len: u32) -> String {
    format!(
        r#"{{"seq":{seq},"t":{t},"wall":"2026-11-19T18:56:11Z","kind":"{kind}","transport":"j2534","api":"J2534 {api}","direction":"{kind}","len":{len},"hex":"{hex}"}}"#,
        t = seq as f64 / 10.0,
        api = if kind == "tx" { "TX" } else { "RX" },
    )
}

fn write_main(session_dir: &Path, lines: &[String]) {
    std::fs::create_dir_all(session_dir).expect("каталог сессии");
    let text = lines.join("\n") + "\n";
    std::fs::write(session_dir.join("events.jsonl"), text).expect("events.jsonl");
}

#[test]
fn proxy_log_is_parsed_into_lane() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_dir = tmp.path().join("logs");
    let session_dir = tmp.path().join("session");
    write_log(
        &log_dir,
        "proxy-20261119-185610-pid8120.log",
        PROXY_LOG,
    );
    // Основной канал: те же TX и RX, что в прокси, плюс один «свой» кадр.
    write_main(
        &session_dir,
        &[
            main_event(1, "tx", "00 02 27 7f", 4),
            main_event(2, "rx", "06 50 03 00 00 00 00 00", 8),
        ],
    );

    let lane = proxy::collect(&session_dir, &started_now(), &log_dir)
        .expect("сбор не должен падать")
        .expect("журнал в окне сессии — полоса обязана появиться");

    assert_eq!(lane.files, 1, "подхваченных журналов");
    assert_eq!(
        lane.bytes,
        PROXY_LOG.len() as u64,
        "байты — суммарный размер журналов"
    );
    assert_eq!(lane.tx, 2, "кадров TX в журнале");
    assert_eq!(lane.rx, 1, "кадров RX в журнале");
    assert_eq!(lane.calls, 10, "вызовы — из строки `# proxy stop`");
    assert_eq!(lane.errors, 1, "ошибки — `J2534 err rc=0x08`");
    assert_eq!(lane.first_t, Some(0.4), "первый кадр по времени прокси");
    assert_eq!(lane.last_t, Some(0.8), "последний кадр по времени прокси");

    // Оба кадра основного канала нашлись в прокси, лишний — только в прокси.
    assert_eq!(lane.cross.tx_matched, 1, "TX совпал");
    assert_eq!(lane.cross.rx_matched, 1, "RX совпал");
    assert_eq!(lane.cross.tx_missing, 0);
    assert_eq!(lane.cross.rx_missing, 0);
    assert_eq!(lane.cross.extra, 1, "кадр `3e 00` есть только в прокси");

    // Артефакты сессии: склейка и разобранная полоса (docs/13 §8).
    let raw = std::fs::read_to_string(session_dir.join("raw-proxy.log")).expect("raw-proxy.log");
    assert_eq!(raw, PROXY_LOG, "склейка должна быть байт-в-байт");
    let saved: ProxyLane =
        serde_json::from_str(&std::fs::read_to_string(session_dir.join("proxy.json")).expect("proxy.json"))
            .expect("proxy.json разбирается обратно");
    assert_eq!(saved.tx, lane.tx);
    assert_eq!(saved.calls, lane.calls);
}

#[test]
fn broken_lines_do_not_break_parsing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_dir = tmp.path().join("logs");
    let session_dir = tmp.path().join("session");
    // Мусор без времени, обрезанная hex-секция, чужие ключи, RX без нагрузки.
    let text = concat!(
        "это вообще не строка захвата\n",
        "[[[ ]]] мусор\n",
        "[+0.410000s] J2534 TX ch=1 call=11 len=4 : 00 02 27\n",
        "[+0.420000s] J2534 TX ch=1 call=12 len=4 : zz zz zz zz\n",
        "[+0.430000s] J2534 TX ch=1 call=13 неизвестный_ключ=1 frobnicate=2 len=2 : 01 02\n",
        "[+0.440000s] J2534 RX ch=1 call=14 rxs=0x02 len=0 : \n",
    );
    write_log(&log_dir, "proxy-20261119-190000-pid42.log", text);
    write_main(&session_dir, &[]);

    let lane = proxy::collect(&session_dir, &started_now(), &log_dir)
        .expect("битые строки не должны ронять разбор")
        .expect("файл в окне есть — полоса должна быть");

    // Кадром считаются только полные строки: обрезанная hex (`len=4`, 3 байта)
    // и неhex-мусор — нет. Остаются `01 02` и... только он: `00 02 27` объявлен
    // как 4 байта, а пришло 3 → short.
    assert_eq!(lane.tx, 1, "кадров TX: только строка с полной нагрузкой");
    assert_eq!(lane.rx, 0, "RX без нагрузки — статус, а не кадр");
    assert!(
        lane.notes
            .iter()
            .any(|note| note.contains("обрезанных")),
        "про обрезанный кадр должно быть сказано: {:?}",
        lane.notes
    );
    assert!(
        lane.notes.iter().any(|note| note == "нет основного канала"),
        "пустой основной канал — отдельная заметка: {:?}",
        lane.notes
    );
    assert_eq!(lane.cross.tx_matched, 0, "сверять не с чем");
    assert_eq!(lane.cross.extra, 0, "extra без основного канала не считается");
}

#[test]
fn cross_reports_matched_missing_and_extra() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_dir = tmp.path().join("logs");
    let session_dir = tmp.path().join("session");
    // Три кадра в прокси: A, B, C.
    let text = concat!(
        "[+0.100000s] J2534 TX ch=1 call=1 len=4 : 00 01 10 03\n",
        "[+0.200000s] J2534 TX ch=1 call=2 len=3 : 02 10 03\n",
        "[+0.300000s] J2534 RX ch=1 call=3 len=3 : 03 3e 00\n",
    );
    write_log(&log_dir, "proxy-20261119-191500-pid7.log", text);
    // Основной канал: A, B (совпадут) и D (в прокси его нет → missing).
    write_main(
        &session_dir,
        &[
            main_event(1, "tx", "00011003", 4),
            main_event(2, "tx", "02 10 03", 3),
            main_event(3, "tx", "04 20 00", 3),
        ],
    );

    let lane = proxy::collect(&session_dir, &started_now(), &log_dir)
        .expect("сбор")
        .expect("полоса");

    assert_eq!(lane.tx, 2);
    assert_eq!(lane.rx, 1);
    assert_eq!(lane.cross.tx_matched, 2, "два кадра frida нашлись в прокси");
    assert_eq!(lane.cross.tx_missing, 1, "третий кадр frida потерян в прокси");
    assert_eq!(lane.cross.rx_missing, 0);
    // Лишний — тот, что видит только прокси (значит, его потеряла frida).
    assert_eq!(lane.cross.extra, 1, "`03 3e 00` есть только в прокси");
    assert_eq!(lane.cross.main_frames(), 3, "кадров основного канала");
    assert_eq!(lane.cross.missing(), 1);
}

#[test]
fn log_outside_session_window_is_ignored() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let log_dir = tmp.path().join("logs");
    let session_dir = tmp.path().join("session");
    write_log(&log_dir, "proxy-20260101-000000-pid1.log", PROXY_LOG);
    // Журнал от прошлого запуска: mtime на час раньше окна сессии.
    let path = log_dir.join("proxy-20260101-000000-pid1.log");
    let file = std::fs::File::options().write(true).open(&path).expect("файл");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    file.set_modified(old).expect("mtime");
    drop(file);

    let lane = proxy::collect(&session_dir, &started_now(), &log_dir).expect("сбор");
    assert!(
        lane.is_none(),
        "журнал вне окна сессии не должен попадать в полосу"
    );
}

#[test]
fn ini_roundtrip_keeps_enabled_real_and_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("j2534proxy");
    std::fs::create_dir_all(&dir).expect("каталог установки");

    let values = proxy::write_ini(
        &dir,
        true,
        Some(r"C:\Program Files (x86)\Scanmatik\smj2534.dll"),
    )
    .expect("запись ini");
    assert!(values.enabled, "Enabled=1 записан");
    assert_eq!(values.name, "Scanmatik - SM2 Proxy", "имя устройства по умолчанию");
    assert_eq!(
        values.real_library,
        r"C:\Program Files (x86)\Scanmatik\smj2534.dll"
    );
    assert!(
        values.log_dir.contains("j2534proxy"),
        "LogDir указывает на каталог журналов прокси: {}",
        values.log_dir
    );

    // Чтение — с диска, а не из возвращённой структуры.
    let read = proxy::read_ini(&dir);
    assert!(read.present && read.enabled);
    assert_eq!(read.name, "Scanmatik - SM2 Proxy");
    assert_eq!(read.vendor, "DaVinci Cyber Engineering");
    assert_eq!(read.max_data_bytes, 4128);

    // Выключение не теряет настоящую библиотеку и имя: их задаёт установщик,
    // а переключатель только меняет Enabled.
    let off = proxy::write_ini(&dir, false, None).expect("выключение");
    assert!(!off.enabled, "Enabled=0 записан");
    assert_eq!(off.real_library, read.real_library, "RealLibrary сохранена");
    assert_eq!(off.name, read.name, "Name сохранено");
    assert!(!proxy::read_ini(&dir).enabled, "диск отдаёт Enabled=0");
}

#[test]
fn status_of_empty_dir_is_calm_and_present_false() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("нет-такого-каталога");

    let status = proxy::status(&dir);

    assert!(status.ok, "status — это «состояние прочитано», а не действие");
    assert!(!status.dll.present, "DLL нет — present=false");
    assert!(!status.ini.present, "ini нет — present=false");
    // `log_files` не проверяем на ноль: без ini LogDir — общий
    // `%LOCALAPPDATA%\FTDI_USB_Logger\j2534proxy`, а там на рабочей машине
    // вполне может лежать живой журнал. Тест не должен зависеть от машины.
    assert!(
        status.log_dir.contains("j2534proxy"),
        "LogDir по умолчанию ведёт в каталог прокси: {}",
        status.log_dir
    );
    assert_eq!(status.install_dir, dir.to_string_lossy());
    assert!(
        status.dll.path.ends_with("j2534proxy.dll"),
        "путь DLL строится из каталога установки: {}",
        status.dll.path
    );
    assert!(
        !status.notes.is_empty(),
        "пользователь должен видеть, чего не хватает"
    );
    assert!(
        status.notes.iter().any(|note| note.contains("j2534proxy.dll")),
        "в заметках — отсутствующая DLL: {:?}",
        status.notes
    );
    // Реестр на чужой машине может быть любым; важно, что статус не паникует
    // и не врёт про «зарегистрировано» без ключа.
    assert!(!status.registry.key.is_empty(), "путь ключа всегда показан");
}
