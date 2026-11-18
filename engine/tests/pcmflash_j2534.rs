//! Регресс на живой лог PCMflash через Scanmatik (18.11.2026).
//!
//! Что было сломано (этот файл — фикстура того самого лога):
//!   * сводка шага схлопывалась в `0x8003 ?` — вендорный протокол без CAN-id
//!     не давал ни сервиса, ни имени команды;
//!   * пустые RX-сообщения (`rxs=0x02 START_OF_MESSAGE`, `len=0`) считались
//!     ответами: на 56 запросов в отчёте было 112 «ответов»;
//!   * вторая половина обмена (чтение флеша) в отчёт не попадала вовсе —
//!     шаг 2 не был закрыт, а `session.json` держал нулевые счётчики.
//!
//! Тест держит первые два пункта: разбор реального `raw.log` и сводку шага 1.

use ftdi_logger::decode;
use ftdi_logger::models::{Event, EventKind, Transport};

/// Фикстура — живой лог (195 КБ) и в репозиторий не кладётся (`reference/logs/*`
/// в .gitignore, как и остальные эталоны). На чистом клоне тест честно
/// пропускается, а не падает.
fn fixture() -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("reference")
        .join("logs")
        .join("pcmflash-20261118.raw.log");
    match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(err) => {
            eprintln!("ПРОПУСК: нет фикстуры {}: {err}", path.display());
            None
        }
    }
}

fn events() -> Option<Vec<Event>> {
    Some(
        fixture()?
            .lines()
            .filter_map(decode::parse_capture_line)
            .collect(),
    )
}

#[test]
fn pcmflash_transport_is_j2534() {
    let Some(evs) = events() else { return };
    assert!(evs.len() > 400, "событий: {}", evs.len());
    assert_eq!(decode::transport_summary(&evs), "j2534");
    let j2534_tx = evs
        .iter()
        .filter(|e| e.transport == Transport::J2534 && e.kind == EventKind::Tx)
        .count();
    assert_eq!(j2534_tx, 56, "TX-посылок в логе");
}

#[test]
fn pcmflash_step1_summary_has_services_not_question_marks() {
    let Some(evs) = events() else { return };
    let summary = decode::summarize_step(&evs, 1, "Идентификация", 0.0, None);

    // Цифры старого логера (PHASE-JSON шага 1): 56 посылок, 4054 B TX, 401 B RX.
    assert_eq!(summary.exchanges, 56, "посылок в шаге");
    assert_eq!(summary.tx_bytes, 4054, "байт TX");
    assert_eq!(summary.rx_bytes, 401, "байт RX");

    // Главное: вместо `0x8003 ?` — реальные сервисы KWP.
    let keys = summary
        .cmd_hist
        .keys()
        .cloned()
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        !keys.contains('?'),
        "в сводке остались нераспознанные команды: {keys}"
    );
    assert!(
        keys.contains("SecurityAccess"),
        "нет SecurityAccess в cmd_hist: {keys}"
    );
    assert!(
        keys.contains("0x8003"),
        "протокол потерян в cmd_hist: {keys}"
    );

    // Один ответ на один запрос: пустые RX_STATUS больше не считаются ответами.
    let resp_total: u64 = summary.resp_hist.values().sum();
    assert_eq!(
        resp_total, 56,
        "ответов в сводке (было 112 из-за пустых RX_STATUS): {:?}",
        summary.resp_hist
    );
    assert!(
        summary
            .resp_hist
            .keys()
            .all(|k| !k.ends_with('?')),
        "нераспознанные ответы: {:?}",
        summary.resp_hist
    );
}

#[test]
fn pcmflash_empty_rx_status_is_not_a_response() {
    let Some(evs) = events() else { return };
    let empty_rx = evs
        .iter()
        .filter(|e| e.transport == Transport::J2534 && e.kind == EventKind::Rx && e.payload().is_empty())
        .count();
    assert_eq!(empty_rx, 56, "пустых RX_STATUS в логе");
}
