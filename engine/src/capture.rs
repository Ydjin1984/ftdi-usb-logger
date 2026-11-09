//! Дирижёр сессии: attach/detach, шаги, метки, скриншоты. Владелец: boba.
//!
//! Устройство:
//! * `CaptureManager` — фасад для API: attach/detach/start_step/end_step/mark/note/shot/
//!   hookctl/status. Держит общее состояние для `status()` и канал команд писателю.
//! * Задача-писатель (`SessionWriterTask`) — единственный владелец `SessionWriter`:
//!   принимает строки от моста, разбирает их `decode::parse_capture_line`, проставляет
//!   `step`, пишет в `events.jsonl`/`raw.log`, копит `ServerMsg::Batch` и рассылает их
//!   в broadcast (≤256 событий / ≤32 КиБ, коалесценция 50 мс ≈ не чаще 20 раз в секунду).
//! * Подписка на мост (`bridge_pump`) перекладывает `BridgeMsg` в команды писателя.
//!
//! Шаг: `start_step` пишет событие `StepStart` (meta.idx), `end_step` закрывает его
//! `StepEnd`, считает `decode::summarize_step`, снимает скриншот окна в `shots/`,
//! сохраняет `steps/NN.json` и рассылает `ServerMsg::Step`.
//!
//! Никаких паник на отсутствующем мосте/окне/сессии: всё возвращает `anyhow::Error`.

use crate::config::Config;
use crate::ediabas;
use crate::models::{
    now_rfc3339, AdapterInfo, BridgeMsg, CaptureStatus, Event, EventKind, Note, ServerMsg,
    SessionCounts, SessionMeta, StepEvent, StepSummary, ToolProcess, Transport, WinkfpJob,
};
use crate::store::{SessionStore, SessionWriter};
use anyhow::{anyhow, bail, Context};
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{broadcast, mpsc, oneshot};

/// Предел событий в одном `ServerMsg::Batch`.
const BATCH_MAX_EVENTS: usize = 256;
/// Предел приблизительного размера одного `ServerMsg::Batch`.
const BATCH_MAX_BYTES: usize = 32 * 1024;
/// Коалесценция батчей: 50 мс → не чаще ~20 рассылок в секунду.
const BATCH_INTERVAL: Duration = Duration::from_millis(50);
/// Очередь команд писателю (строки моста + управление сессией).
const CMD_QUEUE: usize = 8192;
/// Сколько событий шага держим в памяти для сводки; при переполнении режем самую старую часть.
const STEP_EVENT_CAP: usize = 300_000;
/// Таймаут запроса к писателю (end_step может ждать GDI-скриншот).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Бюджет на чтение/разбор приращения EDIABAS-трасс в конце шага.
const EDIABAS_STEP_TIMEOUT: Duration = Duration::from_millis(300);
/// «Свежие» трассы: если процесс не опознан как EDIABAS, а api.trc/IFH.trc менялись
/// недавно — считаем, что идёт сессия неизвестного EDIABAS-приложения.
const EDIABAS_TRACE_FRESH: Duration = Duration::from_secs(600);
/// Имена процессов/путей, которые ходят в ЭБУ через EDIABAS (WinKFP/INPA/Tool32/NFS).
const EDIABAS_TARGET_MARKERS: &[&str] = &["winkfp", "inpa", "tool32", "nfs", "ediabas"];
/// Сколько ждём `BridgeMsg::Ready` от sidecar после `attach` (Frida грузит скрипт).
const BRIDGE_READY_TIMEOUT: Duration = Duration::from_secs(12);

/// Таймаут ожидания ready (можно укоротить переменной окружения — для тестов/отладки).
fn bridge_ready_timeout() -> Duration {
    std::env::var("FTDI_LOGGER_READY_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(BRIDGE_READY_TIMEOUT)
}

pub struct CaptureManager {
    cfg: Arc<Config>,
    store: Arc<SessionStore>,
    bus: broadcast::Sender<ServerMsg>,
    bridge: crate::frida::BridgeManager,
    /// Канал сообщений моста (сюда пишет `BridgeManager`, отсюда читает `bridge_pump`).
    bridge_tx: broadcast::Sender<BridgeMsg>,
    shared: Arc<Shared>,
    /// Активный сырой USB-захват (USBPcapCMD): pid процесса и reader-задача.
    raw_usb: Mutex<Option<RawUsbSession>>,
}

/// Состояние сырого USB-захвата: USBPcapCMD крутится отдельным процессом.
struct RawUsbSession {
    /// PID USBPcapCMD (для принудительного завершения при detach).
    child_pid: u32,
    /// Задача, читающая pcap-поток (внутри spawn_blocking).
    reader: Option<tokio::task::JoinHandle<()>>,
}

/// Состояние, которое нужно одновременно фасаду (status) и писателю (counts/step).
struct Shared {
    active: Mutex<Option<SessionMeta>>,
    hooks: Mutex<String>,
    counts: Mutex<SessionCounts>,
    current_step: Mutex<Option<StepEvent>>,
    target: Mutex<Option<ToolProcess>>,
    started_at: Mutex<Option<String>>,
    pid: Mutex<Option<u32>>,
    cmd_tx: Mutex<Option<mpsc::Sender<Cmd>>>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Идёт штатная остановка (detach/провал attach): смерть источника в этот момент не авария.
    stopping: AtomicBool,
    /// Источник готов (Frida `Ready` или запущенный USBPcapCMD) — только тогда это «запись».
    bridge_ready: AtomicBool,
    /// Активен сырой USB-режим (USBPcapCMD), а не Frida-мост.
    raw_usb: AtomicBool,
}

/// Пути EDIABAS/WinKFP. Каждый путь можно подменить переменной окружения, чтобы
/// гонять тесты без установленного EDIABAS (по умолчанию — константы `ediabas.rs`).
///
/// `FTDI_LOGGER_EDIABAS_INI`, `FTDI_LOGGER_OBD_INI`, `FTDI_LOGGER_WINKFP_INI`,
/// `FTDI_LOGGER_TRACE_DIR`; `FTDI_LOGGER_EDIABAS=0|1` принудительно выключает/включает режим.
#[derive(Debug, Clone)]
struct EdiabasPaths {
    ediabas_ini: PathBuf,
    obd_ini: PathBuf,
    winkfp_ini: PathBuf,
    trace_dir: PathBuf,
}

impl EdiabasPaths {
    /// Разрешить пути: env-переменная → `TracePath` из EDIABAS.INI → константа.
    fn from_env() -> Self {
        let ediabas_ini = env_path("FTDI_LOGGER_EDIABAS_INI", ediabas::EDIABAS_INI);
        let obd_ini = env_path("FTDI_LOGGER_OBD_INI", ediabas::OBD_INI);
        let winkfp_ini = env_path("FTDI_LOGGER_WINKFP_INI", ediabas::WINKFP_INI);
        let trace_dir = match non_empty_env("FTDI_LOGGER_TRACE_DIR") {
            Some(value) => PathBuf::from(value),
            None => {
                // EDIABAS.INI может переопределять TracePath (как в старом winkfp.py).
                let from_ini = ediabas::ini_get(&ediabas_ini, "TracePath");
                let from_ini = from_ini.trim();
                if from_ini.is_empty() {
                    PathBuf::from(ediabas::TRACE_DIR)
                } else {
                    PathBuf::from(from_ini)
                }
            }
        };
        Self {
            ediabas_ini,
            obd_ini,
            winkfp_ini,
            trace_dir,
        }
    }

    fn api_trace(&self) -> PathBuf {
        self.trace_dir.join("api.trc")
    }

    fn ifh_trace(&self) -> PathBuf {
        self.trace_dir.join("IFH.trc")
    }

    /// Есть ли хоть одна трасса (case-независимо на Windows).
    fn traces_present(&self) -> bool {
        self.api_trace().is_file() || self.ifh_trace().is_file()
    }

    /// Трассы менялись недавно — вероятно, идёт живая EDIABAS-сессия.
    fn traces_fresh(&self) -> bool {
        [self.api_trace(), self.ifh_trace()]
            .iter()
            .filter_map(|path| std::fs::metadata(path).ok()?.modified().ok())
            .filter_map(|mtime| SystemTime::now().duration_since(mtime).ok())
            .any(|age| age <= EDIABAS_TRACE_FRESH)
    }
}

/// Состояние EDIABAS-режима одной сессии: пути, offset'ы трасс и счётчики job'ов.
#[derive(Debug, Clone)]
struct EdiabasState {
    paths: EdiabasPaths,
    api_offset: u64,
    ifh_offset: u64,
    jobs_total: u64,
    jobs_errors: u64,
}

/// Приращение трасс, собранное в конце шага.
struct EdiabasDelta {
    jobs: Vec<WinkfpJob>,
    api_delta: Vec<u8>,
    ifh_delta: Vec<u8>,
    api_offset: u64,
    ifh_offset: u64,
}

fn env_path(var: &str, default: &str) -> PathBuf {
    match non_empty_env(var) {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(default),
    }
}

fn non_empty_env(var: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(var).filter(|value| !value.is_empty())
}

/// Цель (имя процесса/путь exe) относится к EDIABAS-классу? Регистр не важен, ищем подстроку.
fn is_ediabas_target(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    EDIABAS_TARGET_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Включать ли EDIABAS-ветку для этой сессии.
///
/// Приоритет: явное `FTDI_LOGGER_EDIABAS` → класс процесса → свежие трассы.
/// Свежесть нужна, чтобы обычный Quickflash на машине со старыми `api.trc` не получал
/// лишних фактов/событий, но неизвестное EDIABAS-приложение с активной трассой — получал.
fn ediabas_mode_enabled(target_name: &str, paths: &EdiabasPaths) -> bool {
    if let Some(value) = non_empty_env("FTDI_LOGGER_EDIABAS") {
        let value = value.to_string_lossy().trim().to_ascii_lowercase();
        match value.as_str() {
            "1" | "on" | "true" | "yes" => return true,
            "0" | "off" | "false" | "no" => return false,
            _ => {}
        }
    }
    is_ediabas_target(target_name) || paths.traces_fresh()
}

/// Прочитать приращение api.trc/IFH.trc с offset'ов и разобрать job'ы (blocking-часть шага).
fn collect_ediabas_delta(
    paths: &EdiabasPaths,
    api_offset: u64,
    ifh_offset: u64,
) -> std::io::Result<EdiabasDelta> {
    let mut api_delta = Vec::new();
    let mut api_offset_new = api_offset;
    match ediabas::read_from(&paths.api_trace(), api_offset) {
        Ok((bytes, offset)) => {
            api_delta = bytes;
            api_offset_new = offset;
        }
        // Нет файла — это нормально (трассы могли не создаваться).
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut ifh_delta = Vec::new();
    let mut ifh_offset_new = ifh_offset;
    match ediabas::read_from(&paths.ifh_trace(), ifh_offset) {
        Ok((bytes, offset)) => {
            ifh_delta = bytes;
            ifh_offset_new = offset;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let text = String::from_utf8_lossy(&api_delta);
    let jobs = ediabas::parse_api_trace(&text);
    Ok(EdiabasDelta {
        jobs,
        api_delta,
        ifh_delta,
        api_offset: api_offset_new,
        ifh_offset: ifh_offset_new,
    })
}

/// Сохранить сырое приращение трассы в `sessions/<id>/winkfp/step-NN-<name>`.
fn save_ediabas_delta(dir: &Path, idx: u32, name: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let winkfp_dir = dir.join("winkfp");
    if let Err(err) = std::fs::create_dir_all(&winkfp_dir) {
        tracing::warn!("не создать {}: {err}", winkfp_dir.display());
        return;
    }
    let path = winkfp_dir.join(format!("step-{idx:02}-{name}"));
    if let Err(err) = std::fs::write(&path, bytes) {
        tracing::warn!("не записать {}: {err}", path.display());
    }
}

/// Команды задаче-писателю. Все изменяющие операции возвращают ответ через `oneshot`.
enum Cmd {
    /// Строка потока от моста (`{"type":"event","line":…}`).
    Line { line: String, wall: String },
    /// Ошибка моста — превращается в событие `Error`.
    BridgeError { msg: String },
    /// Служебное sys-событие (факты EDIABAS и т.п.).
    Sys { text: String },
    /// Пакет сырого USB-захвата (USBPcapCMD). Времена/kind вычисляет writer.
    UsbRaw {
        /// Секунды с эпохи из pcap-заголовка.
        ts: f64,
        /// `true` — хост→устройство (Tx), `false` — устройство→хост (Rx).
        tx: bool,
        /// control-транзакция без данных (setup): пишем как Sys, но байты не теряем.
        control_setup: bool,
        /// Полные байты пакета (для control — вместе с 8-байтовым setup).
        hex: String,
        len: u32,
        meta: serde_json::Value,
        /// Каноническая строка `UsbPacket::to_line()` — для raw.log/экспорта.
        raw: String,
        text: String,
    },
    StartStep {
        title: String,
        reply: oneshot::Sender<anyhow::Result<StepEvent>>,
    },
    EndStep {
        reply: oneshot::Sender<anyhow::Result<StepSummary>>,
    },
    Mark {
        title: String,
        reply: oneshot::Sender<anyhow::Result<Event>>,
    },
    Note {
        text: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    Shot {
        rel: String,
        /// hwnd/rect/метод (`ShotInfo::to_json`) — чтобы в ленте было видно, как снят кадр.
        meta: serde_json::Value,
        reply: oneshot::Sender<anyhow::Result<Event>>,
    },
    /// Завершить сессию штатно (`finished`).
    Detach {
        reply: oneshot::Sender<anyhow::Result<Option<SessionMeta>>>,
    },
    /// Завершить сессию аварийно (`aborted`) с причиной в `meta.facts`.
    Abort {
        reason: String,
        reply: oneshot::Sender<anyhow::Result<Option<SessionMeta>>>,
    },
    /// Мост/источник умер после ready без явного detach — сессия сама становится `aborted`.
    Abandon {
        reason: String,
        /// Готовая строка факта (`# bridge-lost: …` / `# usbpcap-lost: …`).
        fact: String,
    },
}

impl CaptureManager {
    pub fn new(cfg: Arc<Config>, store: Arc<SessionStore>, bus: broadcast::Sender<ServerMsg>) -> Self {
        let bridge = crate::frida::BridgeManager::new(cfg.clone());
        // Канал моста живёт всё время работы движка; ёмкость с запасом на всплеск событий.
        let (bridge_tx, _) = broadcast::channel::<BridgeMsg>(2048);
        Self {
            cfg,
            store,
            bus,
            bridge,
            bridge_tx,
            shared: Arc::new(Shared {
                active: Mutex::new(None),
                hooks: Mutex::new("off".into()),
                counts: Mutex::new(SessionCounts::default()),
                current_step: Mutex::new(None),
                target: Mutex::new(None),
                started_at: Mutex::new(None),
                pid: Mutex::new(None),
                cmd_tx: Mutex::new(None),
                pump: Mutex::new(None),
                stopping: AtomicBool::new(false),
                bridge_ready: AtomicBool::new(false),
                raw_usb: AtomicBool::new(false),
            }),
            raw_usb: Mutex::new(None),
        }
    }

    pub fn bridge(&self) -> &crate::frida::BridgeManager {
        &self.bridge
    }

    // ─────────────────────────── attach / detach ─────────────────────────

    /// Начать захват уже запущенного процесса `pid`.
    pub async fn attach(
        &self,
        pid: u32,
        label: String,
        adapter: Option<String>,
    ) -> anyhow::Result<SessionMeta> {
        if self.shared.active.lock().is_some() {
            bail!("сессия уже идёт — сначала завершите текущий захват");
        }
        if self.cfg.no_bridge {
            bail!("захват недоступен: движок запущен с --no-bridge");
        }
        precheck_bridge(&self.cfg)?;

        // Прошлые аварийно не закрытые сессии чиним до старта новой.
        self.recover_stale();

        let detail = crate::procscan::process_detail(pid).ok_or_else(|| {
            anyhow!("процесс pid={pid} не найден — запустите инструмент и повторите attach")
        })?;
        let label = {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                detail.proc.name.clone()
            } else {
                trimmed.to_string()
            }
        };
        let session_id = session_id_for(&label);
        let mut meta = SessionMeta::new(session_id, label.clone());
        meta.pid = Some(pid);
        meta.process = Some(detail.proc.name.clone());
        if !detail.proc.exe.is_empty() {
            meta.tool_path = Some(detail.proc.exe.clone());
        }
        if !detail.exe_meta.sha256.is_empty() {
            meta.tool_sha256 = Some(detail.exe_meta.sha256.clone());
        }
        if !detail.exe_meta.version.is_empty() {
            meta.tool_version = Some(detail.exe_meta.version.clone());
        }
        meta.transport = if detail.proc.has_ftd2xx { "ftd2xx" } else { "vcp" }.into();
        meta.adapter = resolve_adapter(adapter.as_deref());
        meta.facts.push(format!(
            "# process: pid={pid} ftd2xx_loaded={} known_tool={}",
            detail.proc.has_ftd2xx,
            detail.proc.known_tool.as_deref().unwrap_or("-")
        ));
        if let Some(m) = detail
            .modules
            .iter()
            .find(|m| m.to_ascii_lowercase().starts_with("ftd2xx"))
        {
            meta.facts.push(format!("# ftd2xx module: {m}"));
        }
        meta.facts.extend(license_gate_facts());
        let (ediabas_facts, ediabas_sys, ediabas_state) =
            prepare_ediabas(&detail.proc.name, &detail.proc.exe);
        meta.facts.extend(ediabas_facts);

        let mut writer = self
            .store
            .create(meta.clone())
            .context("создать каталог сессии")?;
        // store.create мог подобрать другой id/выставить dir — берём каноническое meta.
        let meta = writer.meta.clone();
        tracing::info!("сессия {}: каталог {}", meta.id, meta.dir);

        // Баннер старого логера в начало raw.log: legacy-парсер (tools/legacy/parse_family.py)
        // начинает сессию только со строки `# capture start:` и иначе считает всё преамбулой.
        for line in raw_banner(&meta.label, &detail) {
            if let Err(err) = writer.write_raw_line(&line) {
                tracing::warn!("raw.log: баннер не записан: {err}");
            }
        }

        // Общее состояние для status().
        *self.shared.active.lock() = Some(meta.clone());
        *self.shared.counts.lock() = writer.meta.counts.clone();
        *self.shared.current_step.lock() = None;
        *self.shared.target.lock() = Some(detail.proc.clone());
        *self.shared.started_at.lock() = Some(meta.started_at.clone());
        *self.shared.pid.lock() = Some(pid);
        *self.shared.hooks.lock() = "off".into();
        self.shared.stopping.store(false, Ordering::SeqCst);
        self.shared.bridge_ready.store(false, Ordering::SeqCst);

        let (tx, rx) = mpsc::channel::<Cmd>(CMD_QUEUE);
        *self.shared.cmd_tx.lock() = Some(tx);

        // Задача-писатель (единственный владелец SessionWriter).
        {
            let task = SessionWriterTask::new(
                self.cfg.clone(),
                self.bus.clone(),
                self.shared.clone(),
                self.store.clone(),
                writer,
                meta.clone(),
                pid,
                ediabas_state,
                false, // raw USB выключен: обычный Frida-захват
            );
            tokio::spawn(task.run(rx));
        }

        // Факты EDIABAS — в поток sys-событиями, чтобы UI их показал сразу после attach.
        for text in ediabas_sys {
            // Важно: не держать guard `cmd_tx` в `if let` через await (future станет !Send).
            let sender = self.shared.cmd_tx.lock().clone();
            if let Some(tx) = sender {
                let _ = tx.send(Cmd::Sys { text }).await;
            }
        }

        // Подписка на мост: до старта моста, чтобы не потерять `hello`/`ready`.
        let bridge_rx = self.bridge_tx.subscribe();
        let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();
        let pump = tokio::spawn(bridge_pump(
            bridge_rx,
            self.shared.clone(),
            self.bus.clone(),
            Some(ready_tx),
        ));
        *self.shared.pump.lock() = Some(pump);

        // Старт Frida-моста (attach-команда отправляется внутри bridge.start()).
        if let Err(err) = self
            .bridge
            .start(pid, &label, self.bridge_tx.clone())
            .await
        {
            return Err(self
                .fail_attach(format!("не запустить Frida-мост: {err:#}"))
                .await);
        }

        // CAP-05: attach успешен только после BridgeMsg::Ready от sidecar (скрипт загружен).
        // Иначе сессия оставалась бы recording без моста — «висяк» для UI.
        let ready_timeout = bridge_ready_timeout();
        let ready_failure = match tokio::time::timeout(ready_timeout, ready_rx).await {
            Ok(Ok(Ok(()))) => {
                self.shared.bridge_ready.store(true, Ordering::SeqCst);
                None
            }
            Ok(Ok(Err(reason))) => Some(reason),
            Ok(Err(_)) => Some("мост закрылся до ready".to_string()),
            Err(_) => Some(format!(
                "Frida не прицепилась к pid {pid}: ready не пришёл за {} мс",
                ready_timeout.as_millis()
            )),
        };
        if let Some(reason) = ready_failure {
            return Err(self.fail_attach(reason).await);
        }

        toast(
            &self.bus,
            "info",
            format!(
                "захват начат: {} (pid {pid}), сессия {}",
                meta.process.as_deref().unwrap_or("процесс"),
                meta.id
            ),
        );
        Ok(meta)
    }

    /// Аварийно свернуть только что созданную сессию: session.status=aborted, причина в facts,
    /// мост заглушён, shared очищен — повторный attach после этого снова возможен.
    async fn fail_attach(&self, reason: String) -> anyhow::Error {
        tracing::warn!("attach не удался: {reason}");
        self.shared.stopping.store(true, Ordering::SeqCst);
        self.shared.bridge_ready.store(false, Ordering::SeqCst);
        if let Some(pump) = self.shared.pump.lock().take() {
            pump.abort();
        }
        let _ = self.bridge.stop().await;
        let _ = self
            .request(|reply| Cmd::Abort {
                reason: reason.clone(),
                reply,
            })
            .await;
        self.clear_shared();
        anyhow!("{reason}")
    }

    // ───────────────────────── сырой USB (USBPcap) ───────────────────────

    /// Начать сырой захват USB-шины через `USBPcapCMD` на устройстве `device`
    /// (`\\.\USBPcap1` из `usbdevices::usbpcap_devices()`).
    ///
    /// Сессия живёт тем же writer-task'ом, что и Frida-захват; `detach()` останавливает
    /// USBPcapCMD и закрывает сессию. Требует установленного USBPcap и прав администратора.
    pub async fn start_raw_usb(&self, device: &str) -> anyhow::Result<SessionMeta> {
        if self.shared.active.lock().is_some() {
            bail!("сессия уже идёт — сначала завершите текущий захват");
        }
        // Прошлые аварийно не закрытые сессии чиним до старта новой.
        self.recover_stale();
        let Some(cmd_path) = crate::usbpcap::command_path() else {
            bail!("USBPcapCMD.exe не найден — установите USBPcap (desowin.org/usbpcap)");
        };
        let mut child = crate::usbpcap::spawn(device).context("запустить USBPcapCMD")?;
        let child_pid = child.id();

        let label = format!("USB raw: {device}");
        let mut meta = SessionMeta::new(session_id_for(&label), label.clone());
        meta.transport = "usb".into();
        meta.process = Some("USBPcapCMD".into());
        meta.tool_path = Some(cmd_path.to_string_lossy().to_string());
        meta.pid = Some(child_pid);
        meta.facts.push(format!("# usbpcap: device={device}"));
        meta.facts.push(format!("# usbpcap: cmd={}", cmd_path.display()));
        meta.facts
            .push(format!("# process: pid={child_pid} usbpcap_raw=true"));

        let mut writer = match self.store.create(meta.clone()) {
            Ok(writer) => writer,
            Err(err) => {
                let _ = child.kill();
                return Err(err).context("создать каталог сессии");
            }
        };
        let meta = writer.meta.clone();
        // Баннер в raw.log — legacy-парсер (parse_family.py) ждёт `# capture start:`.
        for line in raw_banner_for_tool(&meta.label, &cmd_path.to_string_lossy()) {
            if let Err(err) = writer.write_raw_line(&line) {
                tracing::warn!("raw.log: баннер не записан: {err}");
            }
        }

        *self.shared.active.lock() = Some(meta.clone());
        *self.shared.counts.lock() = writer.meta.counts.clone();
        *self.shared.current_step.lock() = None;
        *self.shared.target.lock() = None;
        *self.shared.started_at.lock() = Some(meta.started_at.clone());
        *self.shared.pid.lock() = Some(child_pid);
        *self.shared.hooks.lock() = "off".into();
        self.shared.stopping.store(false, Ordering::SeqCst);
        // Источник готов сразу: USBPcapCMD уже запущен и пишет pcap в stdout.
        self.shared.bridge_ready.store(true, Ordering::SeqCst);
        self.shared.raw_usb.store(true, Ordering::SeqCst);

        let (tx, rx) = mpsc::channel::<Cmd>(CMD_QUEUE);
        *self.shared.cmd_tx.lock() = Some(tx.clone());
        {
            let task = SessionWriterTask::new(
                self.cfg.clone(),
                self.bus.clone(),
                self.shared.clone(),
                self.store.clone(),
                writer,
                meta.clone(),
                child_pid,
                None,
                true,
            );
            tokio::spawn(task.run(rx));
        }

        let reader = self.spawn_usbpcap_reader(child, tx);
        *self.raw_usb.lock() = Some(RawUsbSession {
            child_pid,
            reader: Some(reader),
        });

        toast(
            &self.bus,
            "info",
            format!("сырой USB-захват начат: {device}, сессия {}", meta.id),
        );
        Ok(meta)
    }

    /// Reader-задача USBPcapCMD: в блокирующем потоке читает pcap и шлёт пакеты писателю.
    ///
    /// Смерть процесса без явного detach → авто-аборт сессии (как CAP-05).
    fn spawn_usbpcap_reader(
        &self,
        mut child: std::process::Child,
        tx: mpsc::Sender<Cmd>,
    ) -> tokio::task::JoinHandle<()> {
        let shared = self.shared.clone();
        tokio::spawn(async move {
            let packet_tx = tx.clone();
            let joined = tokio::task::spawn_blocking(move || {
                crate::usbpcap::read_packets(&mut child, move |packet| {
                    // try_send: блокирующий поток не должен стоять на переполненной очереди.
                    if let Err(err) = packet_tx.try_send(packet_to_cmd(&packet)) {
                        tracing::debug!("raw USB: пакет пропущен ({err})");
                    }
                })
            })
            .await;
            let reason = match joined {
                Ok(Ok(())) => "USBPcapCMD завершился (EOF)".to_string(),
                Ok(Err(err)) => format!("чтение USBPcapCMD: {err}"),
                Err(err) => format!("reader USBPcapCMD: {err}"),
            };
            if !shared.stopping.load(Ordering::SeqCst) {
                tracing::warn!("raw USB: {reason}");
                maybe_abandon_session(
                    &shared,
                    format!("сырой USB-захват прерван: {reason}"),
                    "# usbpcap-lost",
                )
                .await;
            }
        })
    }

    /// Остановить USBPcapCMD и дождаться reader-задачи (для detach/cleanup).
    async fn stop_raw_usb(&self) {
        let session = self.raw_usb.lock().take();
        let Some(session) = session else {
            self.shared.raw_usb.store(false, Ordering::SeqCst);
            return;
        };
        if !terminate_process(session.child_pid) {
            tracing::warn!(
                "raw USB: не удалось завершить USBPcapCMD pid={}",
                session.child_pid
            );
        }
        if let Some(reader) = session.reader {
            if tokio::time::timeout(Duration::from_secs(5), reader)
                .await
                .is_err()
            {
                tracing::warn!("raw USB: reader не завершился за 5 с");
            }
        }
        self.shared.raw_usb.store(false, Ordering::SeqCst);
    }

    /// Завершить захват: остановить источник (Frida-мост и/или USBPcapCMD), закрыть
    /// незакрытый шаг, сформировать отчёты.
    pub async fn detach(&self) -> anyhow::Result<Option<SessionMeta>> {
        if self.shared.active.lock().is_none() {
            // Источник мог остаться запущенным после сбоя — глушим.
            self.stop_raw_usb().await;
            let _ = self.bridge.stop().await;
            return Ok(None);
        }
        // Штатная остановка: смерть источника в этот момент не должна трактоваться как авария.
        self.shared.stopping.store(true, Ordering::SeqCst);
        *self.shared.hooks.lock() = "off".into();
        if self.shared.raw_usb.load(Ordering::SeqCst) {
            self.stop_raw_usb().await;
        }
        if let Err(err) = self.bridge.stop().await {
            tracing::warn!("остановка моста: {err}");
            toast(&self.bus, "warn", format!("остановка моста: {err}"));
        }
        if let Some(pump) = self.shared.pump.lock().take() {
            pump.abort();
        }
        let result = self.request(|reply| Cmd::Detach { reply }).await;
        self.clear_shared();
        match result {
            Ok(Some(meta)) => {
                toast(&self.bus, "info", format!("сессия {} завершена", meta.id));
                Ok(Some(meta))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(err.context("завершить сессию")),
        }
    }

    /// PID активной цели (для watchdog'а «программа закрылась»).
    pub fn target_pid(&self) -> Option<u32> {
        *self.shared.pid.lock()
    }

    /// Программа закрылась/упала: отпускаем захват и устройства, сессию финализируем.
    /// Иначе UI продолжал бы показывать «сессия идёт» уже для мёртвого процесса.
    pub async fn on_target_gone(&self) {
        if self.shared.active.lock().is_none() {
            return;
        }
        toast(
            &self.bus,
            "warn",
            String::from("целевая программа завершилась — захват остановлен, устройства освобождены"),
        );
        match tokio::time::timeout(Duration::from_secs(8), self.detach()).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                tracing::warn!("target-exit detach: {err:#}");
                self.detach_force().await;
            }
            Err(_) => {
                tracing::warn!("target-exit detach не ответил за 8 с — принудительно");
                self.detach_force().await;
            }
        }
    }

    /// Раз в секунду проверяет, жива ли цель; при выходе программы сам закрывает сессию.
    pub fn spawn_target_watchdog(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(1000));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if let Some(pid) = this.target_pid() {
                    if !process_alive(pid) {
                        this.on_target_gone().await;
                    }
                }
            }
        });
    }
    /// Аварийное завершение, если штатный `detach` завис (мост/писатель не отвечают).
    ///
    /// Не ждём writer-задачу: глушим источник, снимаем pump и очищаем состояние. Сессия
    /// помечается `aborted`; при следующем старте движка `recover_stale` доведёт отчёты.
    pub async fn detach_force(&self) -> Option<SessionMeta> {
        let active = self.shared.active.lock().clone();
        self.shared.stopping.store(true, Ordering::SeqCst);
        *self.shared.hooks.lock() = "off".into();
        if self.shared.raw_usb.load(Ordering::SeqCst) {
            self.stop_raw_usb().await;
        }
        let _ = self.bridge.stop().await;
        if let Some(pump) = self.shared.pump.lock().take() {
            pump.abort();
        }
        self.clear_shared();
        if let Some(mut meta) = active {
            meta.status = "aborted".into();
            meta.ended_at.get_or_insert_with(now_rfc3339);
            if let Err(err) = self.store.update_meta(&meta) {
                tracing::warn!(session = %meta.id, "force-abort: не обновить мету: {err:#}");
            }
            toast(&self.bus, "warn", format!("сессия {} остановлена принудительно", meta.id));
            return Some(meta);
        }
        None
    }

    // ─────────────────────────── управление хуками ───────────────────────

    /// `pause` | `resume` — управление хуками Frida-агента через мост.
    pub async fn hookctl(&self, value: &str) -> anyhow::Result<()> {
        let normalized = match value.trim().to_ascii_lowercase().as_str() {
            "pause" | "paused" | "off" => "pause",
            "resume" | "on" | "start" | "run" => "resume",
            other => bail!("hookctl: ожидается pause|resume, получено {other:?}"),
        };
        if !self.bridge.is_running() {
            *self.shared.hooks.lock() = "unavailable".into();
            bail!("мост не запущен — управление хуками недоступно");
        }
        self.bridge
            .command(serde_json::json!({"cmd": "hookctl", "value": normalized}))
            .await
            .context("команда hookctl")?;
        *self.shared.hooks.lock() = if normalized == "pause" { "paused" } else { "on" }.to_string();
        Ok(())
    }

    // ─────────────────────────────── шаги ────────────────────────────────

    /// Открыть новый шаг. Если предыдущий не закрыт — он закрывается автоматически.
    pub async fn start_step(&self, title: String) -> anyhow::Result<StepEvent> {
        self.request(|reply| Cmd::StartStep { title, reply }).await
    }

    /// Закрыть текущий шаг: сводка, скриншот, `steps/NN.json`, `ServerMsg::Step`.
    pub async fn end_step(&self) -> anyhow::Result<StepSummary> {
        self.request(|reply| Cmd::EndStep { reply }).await
    }

    /// Поставить метку в поток (событие `Mark`).
    pub async fn mark(&self, title: String) -> anyhow::Result<Event> {
        self.request(|reply| Cmd::Mark { title, reply }).await
    }

    /// Заметка оператора: событие `Note` + `meta.notes` в `session.json`.
    pub async fn note(&self, text: String) -> anyhow::Result<()> {
        self.request(|reply| Cmd::Note { text, reply }).await
    }

    /// Ручной скриншот окна целевого процесса; возвращает путь относительно каталога сессии.
    pub async fn shot(&self) -> anyhow::Result<String> {
        let meta = self
            .shared
            .active
            .lock()
            .clone()
            .ok_or_else(|| anyhow!("сессия не идёт — скриншот некуда сохранять"))?;
        let pid = self
            .shared
            .pid
            .lock()
            .ok_or_else(|| anyhow!("не известен pid целевого процесса"))?;
        if meta.dir.is_empty() {
            bail!("у сессии не задан каталог");
        }
        let dir = PathBuf::from(&meta.dir);
        let name = format!("shot-{}.png", chrono::Local::now().format("%Y%m%d-%H%M%S"));
        let (rel, info) = capture_shot(pid, &dir, name)
            .await
            .map_err(|err| anyhow!("не удалось снять скриншот окна pid={pid}: {err}"))?;
        let meta_json = info.to_json();
        let _ = self
            .request(|reply| Cmd::Shot {
                rel: rel.clone(),
                meta: meta_json,
                reply,
            })
            .await?;
        Ok(rel)
    }

    // ─────────────────────────────── статус ─────────────────────────────

    /// Статус для API/UI. `recording=true` только если источник реально жив: Frida-мост
    /// прислал `ready`, либо запущен USBPcapCMD (сырой USB). После смерти источника
    /// (до авто-аборта) UI уже не должен показывать запись.
    pub fn status(&self) -> CaptureStatus {
        let active = self.shared.active.lock().clone();
        let bridge_running = self.bridge.is_running();
        let bridge_ready = self.shared.bridge_ready.load(Ordering::SeqCst);
        let raw_usb = self.shared.raw_usb.load(Ordering::SeqCst);
        CaptureStatus {
            recording: active.is_some() && bridge_ready && (bridge_running || raw_usb),
            session: active.as_ref().map(|m| m.id.clone()),
            hooks: if bridge_running {
                self.shared.hooks.lock().clone()
            } else {
                "off".into()
            },
            bridge: bridge_running,
            target: self.shared.target.lock().clone(),
            counts: self.shared.counts.lock().clone(),
            step: self.shared.current_step.lock().clone(),
            started_at: self.shared.started_at.lock().clone(),
        }
    }

    /// Активная сессия для API привязки (`require_active`). Если Frida-мост умер, а writer
    /// ещё не успел закрыть сессию, отдаём статус `aborted`, а не «recording».
    /// В сыром USB-режиме моста нет — статус не трогаем (транспорт `usb`).
    pub fn active(&self) -> Option<SessionMeta> {
        let mut meta = self.shared.active.lock().clone()?;
        let raw_usb = self.shared.raw_usb.load(Ordering::SeqCst);
        if meta.status == "recording"
            && !raw_usb
            && self.shared.bridge_ready.load(Ordering::SeqCst)
            && !self.bridge.is_running()
        {
            meta.status = "aborted".into();
        }
        Some(meta)
    }

    pub fn bus(&self) -> &broadcast::Sender<ServerMsg> {
        &self.bus
    }

    pub fn store(&self) -> &Arc<SessionStore> {
        &self.store
    }

    pub fn cfg(&self) -> &Arc<Config> {
        &self.cfg
    }

    /// Запускается фоновыми задачами при старте движка (сейчас — починка прошлых сессий).
    pub async fn spawn_workers(&self) -> anyhow::Result<()> {
        self.recover_stale();
        Ok(())
    }

    /// Обработчик одного сообщения моста (для тестов/ручных сценариев).
    pub async fn on_bridge_msg(&self, msg: BridgeMsg) {
        handle_bridge_msg(&self.shared, &self.bus, msg).await;
    }

    // ─────────────────────────── внутреннее ─────────────────────────────

    /// Отправить команду писателю и дождаться ответа (с таймаутом).
    async fn request<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<anyhow::Result<T>>) -> Cmd,
    ) -> anyhow::Result<T> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let sender = self
            .shared
            .cmd_tx
            .lock()
            .clone()
            .ok_or_else(|| anyhow!("сессия не запущена"))?;
        if sender.send(make(reply_tx)).await.is_err() {
            bail!("задача записи сессии остановлена");
        }
        match tokio::time::timeout(REQUEST_TIMEOUT, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => bail!("задача записи сессии не ответила"),
            Err(_) => bail!("таймаут операции с сессией"),
        }
    }

    /// Закрыть прошлые сессии, оставшиеся в статусе `recording` после аварийного выхода.
    fn recover_stale(&self) {
        let active_id = self.shared.active.lock().as_ref().map(|m| m.id.clone());
        for mut meta in self.store.list() {
            if meta.status != "recording" {
                continue;
            }
            if active_id.as_deref() == Some(meta.id.as_str()) {
                continue;
            }
            tracing::warn!(
                "сессия {} осталась незакрытой — чиню незакрытые шаги и ставлю status=aborted",
                meta.id
            );
            if let Ok(mut reader) = self.store.reader(&meta.id) {
                if let Err(err) = reader.repair() {
                    tracing::warn!("repair сессии {}: {err}", meta.id);
                }
            }
            meta.status = "aborted".into();
            if meta.ended_at.is_none() {
                meta.ended_at = Some(now_rfc3339());
            }
            if let Err(err) = self.store.update_meta(&meta) {
                tracing::warn!("update_meta сессии {}: {err}", meta.id);
            }
        }
    }

    fn clear_shared(&self) {
        // Если raw-процесс ещё жив (провал/аварийный путь) — гасим, чтобы не остался висеть.
        if let Some(session) = self.raw_usb.lock().take() {
            let _ = terminate_process(session.child_pid);
            if let Some(reader) = session.reader {
                reader.abort();
            }
        }
        self.shared.raw_usb.store(false, Ordering::SeqCst);
        *self.shared.active.lock() = None;
        *self.shared.counts.lock() = SessionCounts::default();
        *self.shared.current_step.lock() = None;
        *self.shared.target.lock() = None;
        *self.shared.started_at.lock() = None;
        *self.shared.pid.lock() = None;
        *self.shared.cmd_tx.lock() = None;
        *self.shared.hooks.lock() = "off".into();
        self.shared.bridge_ready.store(false, Ordering::SeqCst);
        self.shared.stopping.store(false, Ordering::SeqCst);
    }
}

// ─────────────────────────────── задача-писатель ─────────────────────────

/// Открытый шаг: событие старта + буфер событий для сводки.
struct OpenStep {
    event: StepEvent,
    started: Instant,
    started_wall: String,
    /// Все события шага, начиная с `StepStart` (нужны `decode::summarize_step`).
    buffer: Vec<Event>,
    dropped: u64,
}

/// Единственный писатель сессии: события, батчи, шаги, финализация.
struct SessionWriterTask {
    bus: broadcast::Sender<ServerMsg>,
    shared: Arc<Shared>,
    store: Arc<SessionStore>,
    writer: SessionWriter,
    meta: SessionMeta,
    pid: u32,
    t0: Instant,
    open: Option<OpenStep>,
    pending: Vec<Event>,
    pending_bytes: usize,
    steps: Vec<StepSummary>,
    next_idx: u32,
    /// EDIABAS/WinKFP-режим (None у обычного Quickflash — никаких лишних чтений/фактов).
    ediabas: Option<EdiabasState>,
    /// Сырой USB-режим (USBPcapCMD): времена берутся из pcap, а не из `+t.s` строк.
    raw_usb: bool,
    raw_packets: u64,
    raw_bytes: u64,
    /// Секунды с эпохи на момент старта writer-task (для `t = packet.ts - t0`).
    raw_t0_epoch: f64,
    /// Резервное относительное время, если pcap отдал подозрительно маленький ts.
    raw_fallback_t: f64,
}

impl SessionWriterTask {
    fn new(
        _cfg: Arc<Config>,
        bus: broadcast::Sender<ServerMsg>,
        shared: Arc<Shared>,
        store: Arc<SessionStore>,
        writer: SessionWriter,
        meta: SessionMeta,
        pid: u32,
        ediabas: Option<EdiabasState>,
        raw_usb: bool,
    ) -> Self {
        let raw_t0_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0);
        Self {
            bus,
            shared,
            store,
            writer,
            meta,
            pid,
            t0: Instant::now(),
            open: None,
            pending: Vec::new(),
            pending_bytes: 0,
            steps: Vec::new(),
            next_idx: 1,
            ediabas,
            raw_usb,
            raw_packets: 0,
            raw_bytes: 0,
            raw_t0_epoch,
            raw_fallback_t: 0.0,
        }
    }

    /// Основной цикл: команды + периодический сброс батчей/буферов.
    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>) {
        let mut ticker = tokio::time::interval(BATCH_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(cmd) => {
                            if self.handle(cmd).await {
                                break;
                            }
                        }
                        None => {
                            // Все отправители пропали (движок останавливается).
                            self.finalize("aborted").await;
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    if !self.pending.is_empty() {
                        self.flush_batches();
                    }
                    if let Err(err) = self.writer.flush() {
                        tracing::warn!("flush сессии: {err}");
                    }
                }
            }
        }
    }

    /// Обработать команду; `true` — писатель останавливается.
    async fn handle(&mut self, cmd: Cmd) -> bool {
        match cmd {
            Cmd::Line { line, wall } => {
                let Some(mut ev) = crate::decode::parse_capture_line(&line) else {
                    return false; // пустая строка — не событие
                };
                if ev.wall.is_empty() {
                    ev.wall = if wall.trim().is_empty() {
                        now_rfc3339()
                    } else {
                        wall
                    };
                }
                if ev.raw.is_empty() {
                    ev.raw = line;
                }
                if let Err(err) = self.append_event(ev).await {
                    tracing::warn!("событие моста не записано: {err}");
                }
                false
            }
            Cmd::BridgeError { msg } => {
                let mut ev = Event::new(EventKind::Error, Transport::None, self.t(), now_rfc3339());
                ev.api = "BRIDGE".into();
                ev.text = Some(msg.clone());
                ev.meta = serde_json::json!({"bridge": true});
                if let Err(err) = self.append_event(ev).await {
                    tracing::warn!("ошибка моста не записана: {err}");
                }
                false
            }
            Cmd::Sys { text } => {
                let mut ev = Event::new(EventKind::Sys, Transport::None, self.t(), now_rfc3339());
                ev.api = "EDIABAS".into();
                ev.text = Some(text.clone());
                ev.meta = serde_json::json!({"source": "ediabas"});
                if let Err(err) = self.append_event(ev).await {
                    tracing::warn!("sys-событие EDIABAS не записано: {err}");
                }
                false
            }
            Cmd::UsbRaw {
                ts,
                tx,
                control_setup,
                hex,
                len,
                meta,
                raw,
                text,
            } => {
                let (t, wall) = self.raw_times(ts);
                let (kind, direction) = if control_setup {
                    (EventKind::Sys, None)
                } else if tx {
                    (EventKind::Tx, Some(crate::models::Direction::Tx))
                } else {
                    (EventKind::Rx, Some(crate::models::Direction::Rx))
                };
                let mut ev = Event::new(kind, Transport::Usb, t, wall);
                ev.api = if control_setup { "USBRAW-SETUP" } else { "USBRAW" }.into();
                ev.direction = direction;
                ev.hex = hex;
                ev.len = len;
                ev.text = Some(text);
                ev.meta = meta;
                ev.raw = raw;
                self.raw_packets = self.raw_packets.saturating_add(1);
                self.raw_bytes = self.raw_bytes.saturating_add(len as u64);
                if let Err(err) = self.append_event(ev).await {
                    tracing::warn!("пакет raw USB не записан: {err}");
                }
                false
            }
            Cmd::StartStep { title, reply } => {
                let result = self.start_step(title).await;
                let _ = reply.send(result);
                false
            }
            Cmd::EndStep { reply } => {
                let result = self.end_step(true).await;
                let _ = reply.send(result);
                false
            }
            Cmd::Mark { title, reply } => {
                let mut ev = Event::new(EventKind::Mark, Transport::None, self.t(), now_rfc3339());
                ev.api = "MARK".into();
                ev.text = Some(title.clone());
                ev.meta = serde_json::json!({"title": title});
                let result = self.append_event(ev).await;
                let _ = reply.send(result);
                false
            }
            Cmd::Note { text, reply } => {
                let result = self.note(text).await;
                let _ = reply.send(result);
                false
            }
            Cmd::Shot { rel, meta, reply } => {
                let mut ev = Event::new(EventKind::Shot, Transport::None, self.t(), now_rfc3339());
                ev.api = "SHOT".into();
                ev.text = Some(rel.clone());
                ev.meta = serde_json::json!({"path": rel, "shot": meta});
                let result = self.append_event(ev).await;
                let _ = reply.send(result);
                false
            }
            Cmd::Detach { reply } => {
                let meta = self.finalize("finished").await;
                let _ = reply.send(Ok(meta));
                true
            }
            Cmd::Abort { reason, reply } => {
                if !reason.trim().is_empty() {
                    self.meta.facts.push(format!("# attach-failed: {reason}"));
                }
                let meta = self.finalize("aborted").await;
                let _ = reply.send(Ok(meta));
                true
            }
            Cmd::Abandon { reason, fact } => {
                // Источник (мост или USBPcapCMD) умер без detach: сессия становится aborted,
                // shared очищается, чтобы /api/capture/status не показывал recording=true.
                self.meta.facts.push(fact);
                let _ = self.finalize("aborted").await;
                let _ = self.bus.send(ServerMsg::Toast {
                    level: "error".into(),
                    text: format!("захват прерван: {reason}"),
                });
                let _ = self.bus.send(ServerMsg::Status {
                    session: None,
                    target: None,
                    hooks: "off".into(),
                    recording: false,
                    counts: self.writer.meta.counts.clone(),
                });
                *self.shared.active.lock() = None;
                *self.shared.counts.lock() = SessionCounts::default();
                *self.shared.current_step.lock() = None;
                *self.shared.target.lock() = None;
                *self.shared.started_at.lock() = None;
                *self.shared.pid.lock() = None;
                *self.shared.cmd_tx.lock() = None;
                *self.shared.hooks.lock() = "off".into();
                self.shared.bridge_ready.store(false, Ordering::SeqCst);
                self.shared.raw_usb.store(false, Ordering::SeqCst);
                self.shared.stopping.store(false, Ordering::SeqCst);
                true
            }
        }
    }
}

// ─── продолжение: события/шаги/финализация ───────────────────────────────

impl SessionWriterTask {
    /// Секунды от старта сессии (якорь t0 этого писателя).
    fn t(&self) -> f64 {
        self.t0.elapsed().as_secs_f64()
    }

    /// Время пакета сырого USB: из pcap `ts` относительно t0; при мусорном/маленьком `ts`
    /// (некоторые версии USBPcap пишут относительное время) — монотонный счётчик.
    fn raw_times(&mut self, ts: f64) -> (f64, String) {
        if self.raw_usb && ts.is_finite() && ts >= 1.0e9 {
            let t = (ts - self.raw_t0_epoch).max(0.0);
            return (t, rfc3339_from_epoch(ts));
        }
        self.raw_fallback_t += 0.001;
        (self.raw_fallback_t, now_rfc3339())
    }

    /// Записать событие в сессию: seq/counts/raw.log делает `SessionWriter::append`,
    /// мы добавляем `step`, копим батч для UI и буфер шага для сводки.
    async fn append_event(&mut self, mut ev: Event) -> anyhow::Result<Event> {
        if ev.wall.trim().is_empty() {
            ev.wall = now_rfc3339();
        }
        if ev.t == 0.0 {
            ev.t = self.t();
        }
        if let Some(open) = &self.open {
            ev.step = Some(open.event.idx);
        }
        if let Err(err) = self.writer.append(&mut ev) {
            let _ = self.bus.send(ServerMsg::Toast {
                level: "error".into(),
                text: format!("запись события: {err}"),
            });
            return Err(anyhow!("записать событие: {err}"));
        }
        // SessionWriter сам ведёт counts (включая tx/rx байты) — зеркалим их в UI.
        *self.shared.counts.lock() = self.writer.meta.counts.clone();

        // Буфер шага (для decode::summarize_step); StepStart кладётся первым.
        if let Some(open) = &mut self.open {
            if open.buffer.len() >= STEP_EVENT_CAP {
                // Режем старую половину пачкой, сохраняя StepStart в [0].
                let drop_to = (STEP_EVENT_CAP / 2).max(2);
                open.buffer.drain(1..drop_to);
                open.dropped += (drop_to - 1) as u64;
                let _ = self.bus.send(ServerMsg::Toast {
                    level: "warn".into(),
                    text: format!(
                        "шаг {}: буфер событий переполнен, древние события не войдут в сводку",
                        open.event.idx
                    ),
                });
            }
            open.buffer.push(ev.clone());
        }
        self.push_pending(ev.clone());
        Ok(ev)
    }

    /// Положить событие в очередь UI-батча.
    ///
    /// Обычно батч уходит по таймеру (50 мс ⇒ ≤20 рассылок/с); при аномальном всплеске
    /// (очередь выросла до 4× лимита) отправляем досрочно, чтобы не копить память.
    fn push_pending(&mut self, ev: Event) {
        self.pending_bytes += estimate_event_bytes(&ev);
        self.pending.push(ev);
        if self.pending.len() >= BATCH_MAX_EVENTS * 4 {
            self.flush_batches();
        }
    }

    /// Разложить накопленные события на `ServerMsg::Batch` (≤256 событий и ≤32 КиБ на батч).
    fn flush_batches(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let session = self.meta.id.clone();
        let counts = self.writer.meta.counts.clone();
        let mut chunk: Vec<Event> = Vec::new();
        let mut chunk_bytes = 0usize;
        for ev in self.pending.drain(..) {
            let ev_bytes = estimate_event_bytes(&ev);
            if !chunk.is_empty()
                && (chunk.len() >= BATCH_MAX_EVENTS
                    || chunk_bytes + ev_bytes > BATCH_MAX_BYTES)
            {
                let _ = self.bus.send(ServerMsg::Batch {
                    session: session.clone(),
                    events: std::mem::take(&mut chunk),
                    counts: counts.clone(),
                });
                chunk_bytes = 0;
            }
            chunk.push(ev);
            chunk_bytes += ev_bytes;
        }
        if !chunk.is_empty() {
            let _ = self.bus.send(ServerMsg::Batch {
                session,
                events: chunk,
                counts,
            });
        }
        self.pending_bytes = 0;
    }

    /// Открыть шаг: пишет `StepStart` (meta.idx), закрывает предыдущий незакрытый.
    async fn start_step(&mut self, title: String) -> anyhow::Result<StepEvent> {
        if self.open.is_some() {
            // Незакрытый шаг (оператор забыл end) — закрываем без скриншота.
            let _ = self.end_step(false).await;
        }
        let idx = self.next_idx;
        self.next_idx = self.next_idx.saturating_add(1);
        let wall = now_rfc3339();
        let t = self.t();
        let step_event = StepEvent {
            action: "start".into(),
            idx,
            title: title.clone(),
            t,
            wall: wall.clone(),
        };
        self.open = Some(OpenStep {
            event: step_event.clone(),
            started: Instant::now(),
            started_wall: wall.clone(),
            buffer: Vec::new(),
            dropped: 0,
        });
        let mut ev = Event::new(EventKind::StepStart, Transport::None, t, wall);
        ev.api = format!("STEP START {idx}");
        ev.text = Some(title.clone());
        ev.step = Some(idx);
        ev.meta = serde_json::json!({"idx": idx, "title": title});
        self.append_event(ev).await?;
        *self.shared.current_step.lock() = Some(step_event.clone());
        let _ = self.bus.send(ServerMsg::Step {
            action: "start".into(),
            step: serde_json::to_value(&step_event).unwrap_or(serde_json::Value::Null),
        });
        Ok(step_event)
    }

    /// Закрыть шаг: скриншот (опционально), сводка `decode::summarize_step`,
    /// `steps/NN.json`, событие `StepEnd`, `ServerMsg::Step`.
    async fn end_step(&mut self, take_shot: bool) -> anyhow::Result<StepSummary> {
        let Some(open) = self.open.take() else {
            bail!("шаг не открыт — закрывать нечего");
        };
        let idx = open.event.idx;
        let title = open.event.title.clone();
        let dur = open.started.elapsed().as_secs_f64();
        // Скриншот шага: при скрытом/свёрнутом окне — None + toast, белый PNG не сохраняем.
        let mut png: Option<String> = None;
        let mut shot_meta = serde_json::Value::Null;
        let mut shot_error: Option<String> = None;
        if take_shot {
            let name = format!("{:02}-step-{:02}.png", idx, idx);
            match capture_shot(self.pid, self.writer.dir(), name).await {
                Ok((rel, info)) => {
                    self.meta.facts.push(format!(
                        "# shot {idx}: {} hwnd=0x{:x} rect={} {}x{}",
                        info.method,
                        info.hwnd as usize,
                        info.rect.describe(),
                        info.width,
                        info.height
                    ));
                    shot_meta = info.to_json();
                    png = Some(rel);
                }
                Err(err) => {
                    self.meta
                        .facts
                        .push(format!("# shot {idx}: FAIL {err}"));
                    let _ = self.bus.send(ServerMsg::Toast {
                        level: "warn".into(),
                        text: format!("скриншот шага {idx} не снят: {err}"),
                    });
                    shot_error = Some(err);
                }
            }
        }
        let wall = now_rfc3339();
        let t_end = (open.event.t + dur).max(self.t());
        let mut end_ev = Event::new(EventKind::StepEnd, Transport::None, t_end, wall.clone());
        end_ev.api = format!("STEP END {idx}");
        end_ev.text = Some(title.clone());
        end_ev.step = Some(idx);
        end_ev.meta = serde_json::json!({
            "idx": idx,
            "dur": dur,
            "png": png.clone(),
            "shot": shot_meta,
            "shot_error": shot_error,
        });

        // Сводка по срезу шага вместе с только что сформированным StepEnd
        // (decode берёт из него границу и длительность).
        let mut slice = open.buffer;
        slice.push(end_ev.clone());
        let mut summary = crate::decode::summarize_step(&slice, idx, &title, dur, png.clone());
        if summary.started_at.is_empty() {
            summary.started_at = open.started_wall.clone();
        }
        if summary.ended_at.is_empty() {
            summary.ended_at = wall.clone();
        }
        if summary.dur <= 0.0 {
            summary.dur = dur;
        }

        // ── EDIABAS/WinKFP: job-уровень из приращения api.trc (только в EDIABAS-режиме) ──
        let ediabas_mode = self.ediabas.is_some();
        if ediabas_mode {
            let offsets = self
                .ediabas
                .as_ref()
                .map(|s| (s.paths.clone(), s.api_offset, s.ifh_offset));
            if let Some((paths, api_offset, ifh_offset)) = offsets {
                let read = tokio::time::timeout(
                    EDIABAS_STEP_TIMEOUT,
                    tokio::task::spawn_blocking(move || {
                        collect_ediabas_delta(&paths, api_offset, ifh_offset)
                    }),
                )
                .await;
                match read {
                    Ok(Ok(Ok(delta))) => {
                        let jobs = delta.jobs;
                        let n_errors = jobs.iter().filter(|j| !j.errors.is_empty()).count();
                        if let Some(state) = self.ediabas.as_mut() {
                            state.api_offset = delta.api_offset;
                            state.ifh_offset = delta.ifh_offset;
                            state.jobs_total += jobs.len() as u64;
                            state.jobs_errors += n_errors as u64;
                        }
                        for job in &jobs {
                            tracing::debug!(
                                "EDIABAS шаг {idx}: job {}",
                                ediabas::format_job(job)
                            );
                        }
                        save_ediabas_delta(self.writer.dir(), idx, "api.trc", &delta.api_delta);
                        save_ediabas_delta(self.writer.dir(), idx, "IFH.trc", &delta.ifh_delta);
                        self.meta.facts.push(format!(
                            "# winkfp step {idx}: jobs={} errors={} api+{} Б ifh+{} Б",
                            jobs.len(),
                            n_errors,
                            delta.api_delta.len(),
                            delta.ifh_delta.len()
                        ));
                        summary.winkfp_jobs = jobs;
                    }
                    Ok(Ok(Err(err))) => {
                        tracing::warn!("EDIABAS-трассы шага {idx}: {err}");
                        self.meta.facts.push(format!(
                            "# winkfp step {idx}: ошибка чтения трасс: {err}"
                        ));
                        let _ = self.bus.send(ServerMsg::Toast {
                            level: "warn".into(),
                            text: format!("EDIABAS-трассы шага {idx}: {err}"),
                        });
                    }
                    Ok(Err(err)) => {
                        tracing::warn!("EDIABAS-трассы шага {idx}: задача чтения: {err}");
                        self.meta.facts.push(format!(
                            "# winkfp step {idx}: ошибка чтения трасс: {err}"
                        ));
                    }
                    Err(_) => {
                        tracing::warn!(
                            "EDIABAS-трассы шага {idx}: таймаут {EDIABAS_STEP_TIMEOUT:?}"
                        );
                        self.meta
                            .facts
                            .push(format!("# winkfp step {idx}: таймаут чтения трасс"));
                        let _ = self.bus.send(ServerMsg::Toast {
                            level: "warn".into(),
                            text: format!(
                                "EDIABAS-трассы шага {idx}: таймаут {} мс",
                                EDIABAS_STEP_TIMEOUT.as_millis()
                            ),
                        });
                    }
                }
            }
        }

        let save_result = self
            .writer
            .save_step(&summary)
            .map_err(|err| anyhow!("сохранить шаг {idx}: {err}"));
        // Событие StepEnd первым: его строка в raw.log — `# MARK ... END N: имя (dur)`,
        // как в старом логере. Затем блок `# PHASE ...` и последняя строка `# PHASE-JSON`,
        // чтобы raw.log можно было импортировать заново без потерь.
        self.steps.push(summary.clone());
        if let Err(err) = self.append_event(end_ev).await {
            tracing::warn!("событие StepEnd шага {idx} не записано: {err}");
        }
        for line in crate::report::render_step_phase(&summary) {
            if let Err(err) = self.writer.write_raw_line(&line) {
                tracing::warn!("raw.log (PHASE) шага {idx}: {err}");
            }
        }
        let json = serde_json::to_string(&summary).unwrap_or_default();
        if let Err(err) = self.writer.write_raw_line(&format!("# PHASE-JSON {json}")) {
            tracing::warn!("raw.log (PHASE-JSON) шага {idx}: {err}");
        }
        // SessionWriter считает events/tx/rx/files/errors, а шаги учитывает дирижёр.
        self.writer.meta.counts.steps = self.writer.meta.counts.steps.saturating_add(1);
        *self.shared.counts.lock() = self.writer.meta.counts.clone();
        *self.shared.current_step.lock() = None;
        let _ = self.bus.send(ServerMsg::Step {
            action: "end".into(),
            step: serde_json::to_value(&summary).unwrap_or(serde_json::Value::Null),
        });
        if let Err(err) = save_result {
            let _ = self.bus.send(ServerMsg::Toast {
                level: "error".into(),
                text: err.to_string(),
            });
            return Err(err);
        }
        Ok(summary)
    }

    /// Заметка оператора: событие `Note` + запись в `meta.notes` (`session.json`).
    async fn note(&mut self, text: String) -> anyhow::Result<()> {
        let t = self.t();
        let wall = now_rfc3339();
        self.meta.notes.push(Note {
            t,
            wall: wall.clone(),
            text: text.clone(),
            author: "user".into(),
        });
        if let Err(err) = self.store.update_meta(&self.meta) {
            tracing::warn!("заметка не сохранена в session.json: {err}");
        }
        let mut ev = Event::new(EventKind::Note, Transport::None, t, wall);
        ev.api = "NOTE".into();
        ev.text = Some(text);
        ev.meta = serde_json::json!({"author": "user"});
        self.append_event(ev).await?;
        Ok(())
    }

    /// Финализация сессии: дозакрыть шаг, сбросить буферы, отчёты, `session.json`.
    async fn finalize(&mut self, status: &str) -> Option<SessionMeta> {
        if self.open.is_some() {
            let _ = self.end_step(false).await;
        }
        self.flush_batches();
        if let Err(err) = self.writer.flush() {
            tracing::warn!("flush при завершении сессии: {err}");
        }
        self.meta.status = status.to_string();
        self.meta.ended_at = Some(now_rfc3339());
        self.meta.counts = self.writer.meta.counts.clone();
        if self.meta.dir.is_empty() {
            self.meta.dir = self.writer.dir().to_string_lossy().to_string();
        }
        // EDIABAS: трассы ротируются, поэтому best-effort копируем их целиком в сессию.
        if let Some(state) = self.ediabas.as_ref() {
            let winkfp_dir = self.writer.dir().join("winkfp");
            if let Err(err) = std::fs::create_dir_all(&winkfp_dir) {
                tracing::warn!("не создать {}: {err}", winkfp_dir.display());
            } else {
                for (src, name) in [
                    (state.paths.api_trace(), "api.trc"),
                    (state.paths.ifh_trace(), "IFH.trc"),
                ] {
                    if !src.is_file() {
                        continue;
                    }
                    let dest = winkfp_dir.join(name);
                    if let Err(err) = std::fs::copy(&src, &dest) {
                        tracing::warn!(
                            "не скопировать трассу {} → {}: {err}",
                            src.display(),
                            dest.display()
                        );
                        self.meta
                            .facts
                            .push(format!("# ediabas: не скопирована трасса {}: {err}", name));
                    }
                }
            }
            self.meta.facts.push(format!(
                "# ediabas: job'ов за сессию {}, с ошибками {}",
                state.jobs_total, state.jobs_errors
            ));
        }
        // Сырой USB: итог по пакетам/байтам в шапку сессии.
        if self.raw_usb {
            self.meta.facts.push(format!(
                "# usbpcap: packets={} bytes={}",
                self.raw_packets, self.raw_bytes
            ));
        }
        // Шаги пишутся в steps/*.json в процессе; если в памяти пусто — дочитаем из сессии.
        let steps = if self.steps.is_empty() {
            self.store
                .reader(&self.meta.id)
                .map(|reader| reader.steps())
                .unwrap_or_default()
        } else {
            self.steps.clone()
        };
        if let Err(err) =
            crate::report::write_session_reports(self.writer.dir(), &self.meta, &steps)
        {
            tracing::warn!("отчёты сессии {}: {err}", self.meta.id);
            let _ = self.bus.send(ServerMsg::Toast {
                level: "warn".into(),
                text: format!("отчёты не сформированы: {err}"),
            });
        }
        // Итоги в конец raw.log (`# totals: events=N tx=P/TxB rx=Q/RxB steps=S`) — как в
        // старом CLI-логере; legacy-скриптам удобно, на разбор не влияет.
        let c = &self.writer.meta.counts;
        let totals = format!(
            "# totals: events={} tx={}/{} rx={}/{} steps={}",
            c.events, c.tx, c.tx_bytes, c.rx, c.rx_bytes, c.steps
        );
        if let Err(err) = self.writer.write_raw_line(&totals) {
            tracing::warn!("raw.log: totals не записаны: {err}");
        }
        if let Err(err) = self.writer.finish(&self.meta) {            tracing::warn!("finish сессии {}: {err}", self.meta.id);
        }
        let _ = self.store.update_meta(&self.meta);
        let _ = self.bus.send(ServerMsg::Status {
            session: None,
            target: None,
            hooks: "off".into(),
            recording: false,
            counts: self.meta.counts.clone(),
        });
        Some(self.meta.clone())
    }
}

// ─────────────────────────── подписка на мост ────────────────────────────

/// Перекладывает `BridgeMsg` в команды писателя и в UI; завершается, когда писатель пропал.
///
/// `ready` — одноразовый сигнал для `attach`: `Ready` → Ok, фатальная ошибка/`Bye` до
/// ready → Err(причина). После ready канал больше не нужен.
async fn bridge_pump(
    mut rx: broadcast::Receiver<BridgeMsg>,
    shared: Arc<Shared>,
    bus: broadcast::Sender<ServerMsg>,
    mut ready: Option<oneshot::Sender<Result<(), String>>>,
) {
    loop {
        match rx.recv().await {
            Ok(msg) => {
                // Сигнал готовности — до обработки (handle_bridge_msg может слать toast).
                match &msg {
                    BridgeMsg::Ready { .. } => {
                        // Ready означает, что скрипт Frida загружен: помечаем сессию живой
                        // уже здесь, чтобы мгновенная смерть моста после ready тоже привела
                        // к авто-аборту (attach ниже подтвердит флаг идемпотентно).
                        shared.bridge_ready.store(true, Ordering::SeqCst);
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }
                    BridgeMsg::Error { fatal: true, msg } => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err(format!("sidecar: {msg}")));
                        }
                    }
                    BridgeMsg::Bye { code, .. } => {
                        if let Some(tx) = ready.take() {
                            let _ = tx.send(Err(format!(
                                "sidecar завершился до ready (bye, код {code})"
                            )));
                        }
                    }
                    _ => {}
                }
                if !handle_bridge_msg(&shared, &bus, msg).await {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(lost)) => {
                toast(
                    &bus,
                    "warn",
                    format!("мост: движок не успевал читать, потеряно сообщений: {lost}"),
                );
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    // Если pump завершился раньше ready (канал закрыт) — attach получит Err(RecvError).
}

/// Обработать одно сообщение моста. `false` — писатель больше не принимает команды.
async fn handle_bridge_msg(
    shared: &Arc<Shared>,
    bus: &broadcast::Sender<ServerMsg>,
    msg: BridgeMsg,
) -> bool {
    match msg {
        BridgeMsg::Event { line, wall } => {
            let Some(tx) = shared.cmd_tx.lock().clone() else {
                return false;
            };
            if tx.send(Cmd::Line { line, wall }).await.is_err() {
                return false;
            }
        }
        BridgeMsg::Hello {
            bridge,
            frida,
            python,
        } => {
            tracing::info!("sidecar: bridge={bridge} frida={frida} python={python}");
            toast(
                bus,
                "info",
                format!("мост: sidecar {bridge}, Frida {frida}, Python {python}"),
            );
        }
        BridgeMsg::Ready {
            pid,
            arch,
            modules,
            script,
        } => {
            *shared.hooks.lock() = "on".into();
            tracing::info!("мост готов: pid={pid} arch={arch} modules={modules} script={script}");
            toast(
                bus,
                "info",
                format!("Frida прицепилась: pid {pid} ({arch}), модулей {modules}"),
            );
        }
        BridgeMsg::Log { level, msg } => {
            tracing::info!(target: "bridge", "[{level}] {msg}");
            if level.eq_ignore_ascii_case("error") {
                toast(bus, "warn", msg);
            }
        }
        BridgeMsg::Rpc { name, result } => {
            tracing::info!("rpc {name}: {result}");
            if name.to_ascii_lowercase().contains("hook") {
                *shared.hooks.lock() = normalize_hooks_result(&result);
            }
        }
        BridgeMsg::Error { msg, fatal } => {
            tracing::warn!("мост: {msg} (fatal={fatal})");
            if fatal {
                *shared.hooks.lock() = "off".into();
            }
            toast(bus, "error", msg.clone());
            let Some(tx) = shared.cmd_tx.lock().clone() else {
                return false;
            };
            let _ = tx.send(Cmd::BridgeError { msg: msg.clone() }).await;
            if fatal {
                maybe_abandon_session(
                    shared,
                    format!("мост умер: {msg}"),
                    "# bridge-lost",
                )
                .await;
            }
        }
        BridgeMsg::Bye { code, events } => {
            tracing::info!("sidecar: bye code={code} events={events}");
            *shared.hooks.lock() = "off".into();
            toast(
                bus,
                "info",
                format!("мост завершил работу (код {code}, событий {events})"),
            );
            // Штатный detach сам останавливает мост (stopping=true) — тогда это не авария.
            maybe_abandon_session(
                shared,
                format!("мост завершил работу без detach (bye, код {code})"),
                "# bridge-lost",
            )
            .await;
        }
    }
    true
}

/// Мост умер/завершился после `ready`, а явного detach не было → закрываем сессию как
/// `aborted`. Если сессия ещё не была готова или уже останавливается, ничего не делаем.
// (реализация — `maybe_abandon_session` выше, с префиксом факта; здесь оставлен маркер места)

// ─────────────────────────────── хелперы ─────────────────────────────────

/// Баннер в начало `raw.log` в формате старого `attach_capture.py`.
///
/// `tools/legacy/parse_family.py` начинает сессию только со строки `# capture start:`;
/// без неё весь лог считается преамбулой. Импорт чужих логов сюда не попадает — там
/// `raw.log` пишется из событий и баннер уже есть.
fn raw_banner(label: &str, detail: &crate::models::ProcessDetail) -> Vec<String> {
    let mut lines = vec![format!("# capture start: label={label}")];
    if !detail.proc.exe.is_empty() {
        lines.push(format!("# tool: {}", detail.proc.exe));
        let meta = &detail.exe_meta;
        let mut exe_line = String::from("# exe:");
        let mut any = false;
        if meta.size > 0 {
            exe_line.push_str(&format!(" size={}", meta.size));
            any = true;
        }
        if let Some(mtime) = local_time_from_rfc3339(&meta.mtime) {
            exe_line.push_str(&format!(" mtime={mtime}"));
            any = true;
        }
        if !meta.sha256.is_empty() {
            exe_line.push_str(&format!(" sha256={}", meta.sha256));
            any = true;
        }
        if any {
            lines.push(exe_line);
        }
    }
    lines.push(format!(
        "# wall(start)={}",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    ));
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "?".into());
    let computer = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "?".into());
    lines.push(format!("# host: user={user} computer={computer}"));
    lines
}

/// RFC3339 (UTC, как в `exe_meta.mtime`) → локальное `%Y-%m-%d %H:%M:%S`.
fn local_time_from_rfc3339(text: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string())
}

/// Баннер raw.log для сессии «внешнего инструмента» (USBPcapCMD): без exe-меты.
fn raw_banner_for_tool(label: &str, tool: &str) -> Vec<String> {
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "?".into());
    let computer = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "?".into());
    vec![
        format!("# capture start: label={label}"),
        format!("# tool: {tool}"),
        format!(
            "# wall(start)={}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ),
        format!("# host: user={user} computer={computer}"),
    ]
}

/// Пакет USBPcap → команда писателю (события строятся уже в writer-task).
fn packet_to_cmd(packet: &crate::usbpcap::UsbPacket) -> Cmd {
    use crate::models::Direction;
    use crate::models::util::bytes_to_hex;

    let payload_len = packet.payload().len();
    let tx = packet.direction() == Direction::Tx;
    // control без данных (setup) — служебное событие, но байты setup сохраняем в hex.
    let control_setup = packet.transfer == 2 && payload_len == 0;
    let text = if control_setup {
        if packet.data.len() >= 8 {
            format!(
                "USBRAW control ep=0x{:02x} bmRequestType=0x{:02x} bRequest=0x{:02x}",
                packet.endpoint, packet.data[0], packet.data[1]
            )
        } else {
            format!("USBRAW control ep=0x{:02x} setup", packet.endpoint)
        }
    } else {
        format!(
            "USBRAW {} ep=0x{:02x} len={payload_len}",
            packet.transfer_name(),
            packet.endpoint
        )
    };
    let meta = serde_json::json!({
        "bus": packet.bus,
        "device": packet.device,
        "endpoint": packet.endpoint,
        "transfer": packet.transfer,
        "function": packet.function,
        "status": packet.status,
        "irp_id": packet.irp_id,
        "payload_len": payload_len,
        "usbpcap": true,
    });
    Cmd::UsbRaw {
        ts: packet.ts,
        tx,
        control_setup,
        hex: bytes_to_hex(&packet.data),
        len: packet.data.len() as u32,
        meta,
        raw: packet.to_line(),
        text,
    }
}

/// Принудительно завершить процесс по pid (аналог `Child::kill` для чужой задачи).
#[cfg(windows)]
fn terminate_process(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    // SAFETY: открываем процесс только с правом завершения; дескриптор закрывается.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) else {
            return false;
        };
        let ok = TerminateProcess(handle, 1).is_ok();
        let _ = CloseHandle(handle);
        ok
    }
}

#[cfg(not(windows))]
fn terminate_process(_pid: u32) -> bool {
    false
}

/// Жив ли процесс (для watchdog'а цели). Не смогли открыть — считаем живым,
/// чтобы не закрыть сессию из-за прав доступа.
#[cfg(windows)]
fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: дескриптор открывается с минимальными правами и закрывается.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        let mut code = 0u32;
        let ok = GetExitCodeProcess(handle, &mut code).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return true;
        }
        code == 259 // STILL_ACTIVE
    }
}

#[cfg(not(windows))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// Unix-секунды (float) → RFC3339 UTC (миллисекунды); при мусоре — текущее время.
fn rfc3339_from_epoch(ts: f64) -> String {
    if !ts.is_finite() || ts < 0.0 {
        return now_rfc3339();
    }
    let secs = ts.trunc() as i64;
    let nanos = ((ts.fract().abs()) * 1_000_000_000.0) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos.min(999_999_999))
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(now_rfc3339)
}

/// Разделитель между «источник смерти» и фактом: `# bridge-lost: …` / `# usbpcap-lost: …`.
async fn maybe_abandon_session(
    shared: &Arc<Shared>,
    reason: String,
    fact_prefix: &str,
) {
    if shared.stopping.load(Ordering::SeqCst) {
        return;
    }
    if !shared.bridge_ready.load(Ordering::SeqCst) {
        return;
    }
    if shared.active.lock().is_none() {
        return;
    }
    tracing::warn!("сессия будет закрыта: {reason}");
    *shared.hooks.lock() = "off".into();
    let sender = shared.cmd_tx.lock().clone();
    if let Some(tx) = sender {
        let _ = tx
            .send(Cmd::Abandon {
                fact: format!("{fact_prefix}: {reason}"),
                reason,
            })
            .await;
    }
}

/// Подготовить EDIABAS-режим: факты для шапки `session.json`, 2-3 sys-строки для потока
/// и стартовое состояние трасс (offset'ы). Для обычного Quickflash возвращает пустые
/// векторы и `None` — никаких лишних чтений/событий.
fn prepare_ediabas(
    proc_name: &str,
    exe: &str,
) -> (Vec<String>, Vec<String>, Option<EdiabasState>) {
    let paths = EdiabasPaths::from_env();
    let target = if proc_name.trim().is_empty() {
        exe
    } else {
        proc_name
    };
    if !ediabas_mode_enabled(target, &paths) {
        return (Vec::new(), Vec::new(), None);
    }

    let mut facts: Vec<String> = Vec::new();
    let ini_facts = ediabas::ini_facts_from(&paths.ediabas_ini, &paths.obd_ini, &paths.winkfp_ini);
    for (file, pairs) in &ini_facts {
        facts.push(format!("# ediabas-ini: {file}: {pairs}"));
    }

    // Предупреждения как в старом winkfp.py/tracing_problem: трассы выключены/не найдены.
    let mut warnings: Vec<String> = Vec::new();
    for key in ["ApiTrace", "IfhTrace"] {
        let value = ediabas::ini_get(&paths.ediabas_ini, key);
        if value.trim() == "0" {
            warnings.push(format!("{key}=0 в {}", paths.ediabas_ini.display()));
        }
    }
    if !paths.trace_dir.is_dir() {
        warnings.push(format!(
            "каталог трасс не найден: {}",
            paths.trace_dir.display()
        ));
    } else if !paths.traces_present() {
        warnings.push("api.trc/IFH.trc не найдены".into());
    }
    if !warnings.is_empty() {
        facts.push(format!(
            "# ediabas: ВНИМАНИЕ: {} — job-уровень может быть неполным",
            warnings.join("; ")
        ));
    }

    let snapshot = |path: &Path| match ediabas::snapshot_trace(path) {
        Ok(size) => size,
        Err(err) => {
            tracing::warn!("размер трассы {}: {err}", path.display());
            0
        }
    };
    let api_offset = snapshot(&paths.api_trace());
    let ifh_offset = snapshot(&paths.ifh_trace());

    // 2-3 sys-события: режим, INI-факты, предупреждение.
    let mut sys = Vec::new();
    let why = if is_ediabas_target(target) {
        format!("target={target}")
    } else {
        "активная трасса EDIABAS".to_string()
    };
    sys.push(format!(
        "# ediabas: режим EDIABAS включён ({why}), трассы={}",
        paths.trace_dir.display()
    ));
    if !ini_facts.is_empty() {
        let joined = ini_facts
            .iter()
            .take(3)
            .map(|(file, pairs)| format!("{file}: {pairs}"))
            .collect::<Vec<_>>()
            .join(" | ");
        sys.push(format!("# ediabas-ini: {joined}"));
    }
    if !warnings.is_empty() {
        sys.push(format!("# ediabas: {}", warnings.join("; ")));
    }

    let state = EdiabasState {
        paths,
        api_offset,
        ifh_offset,
        jobs_total: 0,
        jobs_errors: 0,
    };
    (facts, sys, Some(state))
}

/// Проверка наличия sidecar и Frida-агента до создания сессии.
fn precheck_bridge(cfg: &Config) -> anyhow::Result<()> {
    if !cfg.sidecar.is_file() {
        bail!(
            "не найден sidecar: {} — захват невозможен (соберите sidecar)",
            cfg.sidecar.display()
        );
    }
    if !cfg.script.is_file() {
        bail!(
            "не найден Frida-агент: {} — захват невозможен",
            cfg.script.display()
        );
    }
    Ok(())
}

/// Отправить `ServerMsg::Toast` (без паники, если UI ещё не подключён).
fn toast(bus: &broadcast::Sender<ServerMsg>, level: &str, text: impl Into<String>) {
    let _ = bus.send(ServerMsg::Toast {
        level: level.to_string(),
        text: text.into(),
    });
}

/// Ответ sidecar на `hookctl` → строка статуса хуков для UI.
fn normalize_hooks_result(result: &str) -> String {
    match result.trim().to_ascii_lowercase().as_str() {
        "paused" | "pause" | "off" => "paused".into(),
        "on" | "resume" | "resumed" | "running" => "on".into(),
        other if !other.is_empty() => other.to_string(),
        _ => "on".into(),
    }
}

/// Оценка размера события для лимита 32 КиБ на батч (точный JSON не сериализуем).
fn estimate_event_bytes(ev: &Event) -> usize {
    ev.raw.len()
        + ev.hex.len()
        + ev.api.len()
        + ev.text.as_deref().map(str::len).unwrap_or(0)
        + 220
}

/// Идентификатор сессии в стиле старого логера: `<YYYYmmdd-HHMMSS>-<slug(label)>`.
fn session_id_for(label: &str) -> String {
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let slug = crate::models::util::slug(label);
    let slug = if slug.is_empty() {
        "session".to_string()
    } else {
        slug
    };
    format!("{stamp}-{slug}")
}

/// Сопоставить выбор оператора (`Option<String>`) с реальным шнурком.
///
/// Строка может содержать серийник и/или описание (как старый `"desc serial"`);
/// если совпадения нет — сохраняем выбор как описание, чтобы не потерять его.
fn resolve_adapter(selection: Option<&str>) -> Option<AdapterInfo> {
    let devices = crate::discovery::list_ftdi_devices();
    let from_device = |dev: &crate::models::FtdiDevice| AdapterInfo {
        serial: dev.serial.clone(),
        description: dev.description.clone(),
        com_port: dev.com_port,
        vendor_id: dev.vendor_id,
        product_id: dev.product_id,
    };
    if let Some(selection) = selection {
        let needle = selection.to_lowercase();
        if let Some(dev) = devices.iter().find(|dev| {
            (!dev.serial.is_empty() && needle.contains(&dev.serial.to_lowercase()))
                || (!dev.description.is_empty()
                    && needle.contains(&dev.description.to_lowercase()))
        }) {
            return Some(from_device(dev));
        }
        return Some(AdapterInfo {
            description: selection.to_string(),
            ..Default::default()
        });
    }
    if devices.len() == 1 {
        return Some(from_device(&devices[0]));
    }
    None
}

/// Пре-полёт лицензионного гейта семейства BTT (Quickflash).
///
/// Старый логер проверял прокси-активатор и маршруты через PowerShell; здесь — только
/// локальные факты без сети: `ProxyEnable/ProxyServer` из HKCU и жив ли `_Activator`.
/// Маршрутную проверку `accts/checker` делает внешний инструмент (нужен HTTP-клиент).
fn license_gate_facts() -> Vec<String> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Registry::HKEY_CURRENT_USER;

        const INTERNET_SETTINGS: &str =
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let enable = crate::discovery::registry_read_u32(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            "ProxyEnable",
        )
        .unwrap_or(0);
        let server = crate::discovery::registry_read_string_at(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            "ProxyServer",
        )
        .unwrap_or_default();
        let activator = crate::procscan::is_process_running("_Activator");
        let mut facts = vec![format!(
            "# license-gate: ProxyEnable={enable} ProxyServer={} активатор={}",
            if server.is_empty() { "?" } else { &server },
            if activator { "жив" } else { "НЕТ" }
        )];
        if enable == 0 {
            facts.push(
                "# license-gate: ВНИМАНИЕ: прокси-активатор выключен — сервер активации \
                 (Cloudflare) приложению недоступен, прошивка может не пойти"
                    .into(),
            );
        }
        facts
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

/// Скриншот окна процесса в `dir/shots/<name>`; возвращает относительный путь или `None`.
///
/// GDI-вызовы блокирующие, поэтому уводим их в `spawn_blocking`.
/// Скриншот окна процесса в `dir/shots/<name>`: возвращает относительный путь
/// (всегда со слэшем `/`) и `ShotInfo` либо текст ошибки для toast.
///
/// GDI-вызовы блокирующие, поэтому уводим их в `spawn_blocking`.
async fn capture_shot(
    pid: u32,
    dir: &Path,
    name: String,
) -> Result<(String, crate::screenshot::ShotInfo), String> {
    let path = dir.join("shots").join(&name);
    let file_name = name.clone();
    let joined = tokio::task::spawn_blocking(move || {
        crate::screenshot::capture_window_for_pid_info(pid, &path)
    })
    .await;
    match joined {
        Ok(Ok(info)) => {
            // Путь относительный и с прямыми слэшами: UI отдаёт его через
            // GET /api/sessions/{id}/file/{path}.
            let rel = format!("shots/{file_name}");
            tracing::info!(
                "скриншот: {} метод={} hwnd=0x{:x} rect={}",
                rel,
                info.method,
                info.hwnd as usize,
                info.rect.describe()
            );
            Ok((rel, info))
        }
        Ok(Err(err)) => {
            let text = format!("{err:#}");
            tracing::warn!("скриншот pid={pid}: {text}");
            Err(text)
        }
        Err(err) => {
            tracing::warn!("скриншот pid={pid}: задача прервана: {err}");
            Err(format!("задача скриншота прервана: {err}"))
        }
    }
}

// ─────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(root: &Path) -> Arc<Config> {
        Arc::new(Config {
            root: root.to_path_buf(),
            sessions_dir: root.join("sessions"),
            ui_dist: root.join("ui"),
            port: 0,
            python: PathBuf::from("python.exe"),
            sidecar: root.join("sidecar").join("bridge.py"),
            script: root.join("sidecar").join("agents").join("ftdi_capture.js"),
            open_ui: false,
            no_bridge: false,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
        })
    }

    fn test_manager(root: &Path) -> CaptureManager {
        let cfg = test_cfg(root);
        std::fs::create_dir_all(&cfg.sessions_dir).unwrap();
        let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
        let (bus, _) = broadcast::channel(64);
        CaptureManager::new(cfg, store, bus)
    }

    #[test]
    fn session_id_is_slugged() {
        let id = session_id_for("ME72 Quickflash");
        assert!(id.ends_with("-me72-quickflash"), "id={id}");
        assert!(session_id_for("").contains("session"));
    }

    #[test]
    fn hooks_result_normalization() {
        assert_eq!(normalize_hooks_result("paused"), "paused");
        assert_eq!(normalize_hooks_result("OFF"), "paused");
        assert_eq!(normalize_hooks_result("resume"), "on");
        assert_eq!(normalize_hooks_result(""), "on");
    }

    #[test]
    fn event_size_estimate_is_positive() {
        let ev = Event::new(EventKind::Rx, Transport::Ftd2xx, 1.0, now_rfc3339())
            .with_hex("12 04")
            .with_raw("[+1.000s] RX …");
        assert!(estimate_event_bytes(&ev) >= 230);
    }

    #[test]
    fn status_without_session_is_not_recording() {
        let dir = tempfile::tempdir().unwrap();
        let manager = test_manager(dir.path());
        let status = manager.status();
        assert!(!status.recording);
        assert_eq!(status.bridge, false);
        assert!(status.session.is_none());
        assert!(manager.active().is_none());
    }

    #[test]
    fn attach_without_bridge_assets_is_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let manager = test_manager(dir.path());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // sidecar/агент не собраны — attach обязан вернуть понятную ошибку, не панику.
            let err = manager
                .attach(u32::MAX, "test".into(), None)
                .await
                .unwrap_err();
            let text = format!("{err:#}");
            assert!(
                text.contains("sidecar") || text.contains("Frida") || text.contains("процесс"),
                "неожиданная ошибка: {text}"
            );
        });
    }

    #[test]
    fn detach_without_session_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let manager = test_manager(dir.path());
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert!(manager.detach().await.unwrap().is_none());
        });
    }

    #[test]
    fn recover_stale_marks_recording_sessions_aborted() {
        let dir = tempfile::tempdir().unwrap();
        let manager = test_manager(dir.path());
        let meta = SessionMeta::new("20260101-000000-old", "old");
        manager.store().create(meta).unwrap();
        manager.recover_stale();
        let list = manager.store().list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, "aborted");
        assert!(list[0].ended_at.is_some());
    }

    /// Полный ручной E2E: настоящий Python + заглушка sidecar + живой notepad как цель.
    ///
    /// Проверяет `attach` (store.create + мост + подписка), поток событий, шаг со скриншотом,
    /// `steps/01.json`, отчёты и `detach` (status=finished). Нужен рабочий стол и Python.
    ///
    /// `#[ignore]`, запуск:
    /// `cargo test --lib -- capture::tests::real_attach_detach_smoke -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_attach_detach_smoke() {
        let python_ok = std::process::Command::new("python")
            .args(["-c", "print(1)"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !python_ok {
            eprintln!("python недоступен — E2E пропущен");
            return;
        }
        // Обычный (не EDIABAS) захват: принудительно выключаем EDIABAS-ветку, чтобы тест
        // не зависел от свежести реальных C:\EDIABAS\TRACE на машине разработчика.
        let previous_ediabas_env = std::env::var_os("FTDI_LOGGER_EDIABAS");
        std::env::set_var("FTDI_LOGGER_EDIABAS", "0");

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sidecar = root.join("bridge.py");
        let script = root.join("agent.js");
        std::fs::write(
            &sidecar,
            r#"
import json
import sys
import time

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "e2e", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 2, "script": "agent.js"}), flush=True)
        for i in range(3):
            print(json.dumps({"type": "event", "line": "[+%.3fs] TX ftd2xx FT_Write rc=0 len=2 n=2 : aa %02x" % (0.1 * i, i), "wall": "2026-01-01T00:00:00.000Z"}), flush=True)
            time.sleep(0.05)
        for i in range(2):
            print(json.dumps({"type": "event", "line": "[+%.3fs] RX ftd2xx FT_Read rc=0 want=64 n=2 : a0 %02x" % (0.5 + 0.05 * i, 0x5a + i), "wall": "2026-01-01T00:00:00.500Z"}), flush=True)
            time.sleep(0.05)
    elif cmd == "hookctl":
        print(json.dumps({"type": "rpc", "name": "hookctl", "result": msg.get("value")}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 5}), flush=True)
        sys.exit(0)
"#,
        )
        .unwrap();
        std::fs::write(&script, "// заглушка Frida-агента для E2E\n").unwrap();

        let mut notepad = std::process::Command::new("notepad.exe")
            .spawn()
            .expect("запустить notepad.exe");
        std::thread::sleep(std::time::Duration::from_millis(1200));

        let cfg = Arc::new(Config {
            root: root.to_path_buf(),
            sessions_dir: root.join("sessions"),
            ui_dist: root.join("ui"),
            port: 0,
            python: PathBuf::from("python"),
            sidecar: sidecar.clone(),
            script: script.clone(),
            open_ui: false,
            no_bridge: false,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
        });
        std::fs::create_dir_all(&cfg.sessions_dir).unwrap();
        let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
        let (bus, _) = broadcast::channel::<ServerMsg>(1024);
        let manager = CaptureManager::new(cfg, store, bus);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let pid = notepad.id();
        let (meta, summary) = rt.block_on(async {
            let meta = manager
                .attach(pid, "E2E ноутпад".into(), None)
                .await
                .expect("attach");
            assert_eq!(meta.pid, Some(pid));
            // Ждём, пока мост пришлёт hello/ready и первые события.
            tokio::time::sleep(Duration::from_millis(600)).await;
            let step = manager
                .start_step("шаг E2E".into())
                .await
                .expect("start_step");
            assert_eq!(step.idx, 1);
            tokio::time::sleep(Duration::from_millis(400)).await;
            let summary = manager.end_step().await.expect("end_step");
            assert_eq!(summary.idx, 1);
            assert_eq!(summary.title, "шаг E2E");
            // У видимого notepad скриншот должен сняться, путь — относительный и с `/`.
            let png = summary.png.clone().expect("png шага");
            assert!(png.starts_with("shots/"), "путь не относительный: {png}");
            assert!(!png.contains('\\'), "в пути есть обратные слэши: {png}");
            let finished = manager
                .detach()
                .await
                .expect("detach")
                .expect("мета завершённой сессии");
            (finished, summary)
        });
        let _ = notepad.kill();
        let _ = notepad.wait();

        assert_eq!(meta.status, "finished");
        assert!(meta.ended_at.is_some());
        let session_dir = PathBuf::from(&meta.dir);
        eprintln!("сессия E2E: {}", session_dir.display());
        let events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
        eprintln!(
            "событий в events.jsonl: {}",
            events.lines().filter(|l| !l.trim().is_empty()).count()
        );
        assert!(events.contains("FT_Write"), "в потоке нет событий моста");
        assert!(events.contains("FT_Read"), "в потоке нет RX-событий");
        assert!(events.contains("step_start") && events.contains("step_end"));
        assert!(session_dir.join("shots").is_dir());
        assert!(
            session_dir.join("steps").join("01.json").is_file(),
            "steps/01.json отсутствует"
        );
        let shot_ok = std::fs::read_dir(session_dir.join("shots"))
            .map(|entries| entries.flatten().any(|e| e.path().extension().is_some_and(|x| x == "png")))
            .unwrap_or(false);
        eprintln!("скриншот шага снят: {shot_ok}");
        let report_exists = session_dir.join("report.txt").is_file()
            || session_dir.join("report.md").is_file();
        eprintln!("отчёты записаны: {report_exists}");
        let stored: SessionMeta =
            serde_json::from_str(&std::fs::read_to_string(session_dir.join("session.json")).unwrap())
                .unwrap();
        assert_eq!(stored.status, "finished");
        assert!(stored.counts.events >= 5, "counts.events={}", stored.counts.events);
        assert!(stored.counts.tx >= 3, "counts.tx={}", stored.counts.tx);
        assert!(stored.counts.rx >= 2, "counts.rx={}", stored.counts.rx);
        assert_eq!(stored.counts.steps, 1);
        // Обычный Quickflash-подобный захват не должен получить EDIABAS-фактов/событий/строк.
        assert!(
            stored.facts.iter().all(|f| !f.starts_with("# ediabas")),
            "не-EDIABAS процесс получил факты EDIABAS: {:?}",
            stored.facts
        );
        assert!(
            !events.contains("\"api\":\"EDIABAS\""),
            "не-EDIABAS процесс получил sys-события EDIABAS"
        );
        let raw = std::fs::read_to_string(session_dir.join("raw.log")).unwrap();
        assert!(
            !raw.contains("winkfp:"),
            "не-EDIABAS процесс получил winkfp-строки"
        );
        assert!(summary.winkfp_jobs.is_empty());
        // Восстанавливаем окружение.
        match previous_ediabas_env {
            Some(value) => std::env::set_var("FTDI_LOGGER_EDIABAS", value),
            None => std::env::remove_var("FTDI_LOGGER_EDIABAS"),
        }
    }

    /// Цель без видимого окна (как скрытый dummy_target): шаг закрывается, но белый PNG
    /// НЕ сохраняется — в StepEnd-событии `shot_error`, в UI toast, `png = null`.
    ///
    /// `#[ignore]`, запуск:
    /// `cargo test --lib -- capture::tests::real_hidden_target_shot_degrades -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_hidden_target_shot_degrades() {
        let python_ok = std::process::Command::new("python")
            .args(["-c", "print(1)"])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        if !python_ok {
            eprintln!("python недоступен — тест скрытого окна пропущен");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let sidecar = root.join("bridge.py");
        let script = root.join("agent.js");
        std::fs::write(
            &sidecar,
            r#"
import json
import sys

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    cmd = msg.get("cmd")
    if cmd == "attach":
        print(json.dumps({"type": "hello", "bridge": "hidden", "frida": "0", "python": "test"}), flush=True)
        print(json.dumps({"type": "ready", "pid": msg.get("pid"), "arch": "x64", "modules": 1, "script": "agent.js"}), flush=True)
        print(json.dumps({"type": "event", "line": "[+0.100s] TX ftd2xx FT_Write rc=0 len=2 n=2 : aa bb", "wall": "2026-01-01T00:00:00.000Z"}), flush=True)
    elif cmd == "stop":
        print(json.dumps({"type": "bye", "code": 0, "events": 1}), flush=True)
        sys.exit(0)
"#,
        )
        .unwrap();
        std::fs::write(&script, "// заглушка Frida-агента\n").unwrap();

        // Цель без окон: консольный python, который просто спит.
        let mut target = std::process::Command::new("python")
            .args(["-c", "import time; time.sleep(60)"])
            .spawn()
            .expect("запустить python-цель");
        std::thread::sleep(std::time::Duration::from_millis(800));

        let cfg = Arc::new(Config {
            root: root.to_path_buf(),
            sessions_dir: root.join("sessions"),
            ui_dist: root.join("ui"),
            port: 0,
            python: PathBuf::from("python"),
            sidecar: sidecar.clone(),
            script: script.clone(),
            open_ui: false,
            no_bridge: false,
            discovery_ms: 2000,
            max_event_bytes: 64 * 1024,
        });
        std::fs::create_dir_all(&cfg.sessions_dir).unwrap();
        let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
        let (bus, _) = broadcast::channel::<ServerMsg>(1024);
        let manager = CaptureManager::new(cfg, store, bus);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let pid = target.id();
        let (summary, meta) = rt.block_on(async {
            let meta = manager.attach(pid, "hidden".into(), None).await.expect("attach");
            assert_eq!(meta.pid, Some(pid));
            tokio::time::sleep(Duration::from_millis(400)).await;
            manager.start_step("скрытая цель".into()).await.expect("start_step");
            tokio::time::sleep(Duration::from_millis(200)).await;
            let summary = manager.end_step().await.expect("end_step не должен падать");
            let meta = manager
                .detach()
                .await
                .expect("detach")
                .expect("мета сессии");
            (summary, meta)
        });
        let _ = target.kill();
        let _ = target.wait();

        assert_eq!(summary.idx, 1);
        assert!(
            summary.png.is_none(),
            "для скрытого окна png должен быть None, получено {:?}",
            summary.png
        );
        let session_dir = PathBuf::from(&meta.dir);
        let events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
        eprintln!("StepEnd-событие: {}", events.lines().rev().find(|l| l.contains("step_end")).unwrap_or(""));
        assert!(events.contains("shot_error"), "нет shot_error в StepEnd");
        assert!(
            events.contains("окно"),
            "ошибка должна говорить про окно: {events}"
        );
        let shots: Vec<_> = std::fs::read_dir(session_dir.join("shots"))
            .map(|rd| rd.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        eprintln!("файлов в shots/: {}", shots.len());
        assert!(
            shots.iter().all(|p| p.extension().is_none()),
            "при ошибке в shots/ не должно быть файлов: {shots:?}"
        );
        let stored: SessionMeta =
            serde_json::from_str(&std::fs::read_to_string(session_dir.join("session.json")).unwrap())
                .unwrap();
        assert_eq!(stored.status, "finished");
        assert!(
            stored.facts.iter().any(|f| f.contains("# shot 1: FAIL")),
            "нет факта об ошибке скриншота: {:?}",
            stored.facts
        );
    }

    /// Полный конвейер писателя без Frida: строки → события → шаг → сводка → финализация.
    #[test]
    fn writer_pipeline_records_events_steps_and_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_cfg(dir.path());
        std::fs::create_dir_all(&cfg.sessions_dir).unwrap();
        let store = Arc::new(SessionStore::open(&cfg.sessions_dir).unwrap());
        let (bus, mut bus_rx) = broadcast::channel::<ServerMsg>(512);
        let shared = Arc::new(Shared {
            active: Mutex::new(None),
            hooks: Mutex::new("off".into()),
            counts: Mutex::new(SessionCounts::default()),
            current_step: Mutex::new(None),
            target: Mutex::new(None),
            started_at: Mutex::new(None),
            pid: Mutex::new(None),
            cmd_tx: Mutex::new(None),
            pump: Mutex::new(None),
            stopping: AtomicBool::new(false),
            bridge_ready: AtomicBool::new(false),
            raw_usb: AtomicBool::new(false),
        });
        let writer = store.create(SessionMeta::new("pipeline-test", "pipeline")).unwrap();
        let meta = writer.meta.clone();
        *shared.active.lock() = Some(meta.clone());
        *shared.started_at.lock() = Some(meta.started_at.clone());
        let task = SessionWriterTask::new(
            cfg.clone(),
            bus.clone(),
            shared.clone(),
            store.clone(),
            writer,
            meta.clone(),
            0xFFFF_FFF0, // заведомо несуществующий pid: скриншот просто не снимется
            None,        // EDIABAS-режим в этом тесте не нужен
            false,       // raw USB не нужен
        );
        let (tx, rx) = mpsc::channel::<Cmd>(64);
        *shared.cmd_tx.lock() = Some(tx.clone());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let worker = rt.spawn(task.run(rx));

        let summary = rt.block_on(async move {
            // 1) строка потока до шага.
            tx.send(Cmd::Line {
                line: "[+0.500s] VCP TX WriteFile(COM6) rc=0 n=4 ovl=0 : 12 04 0d 1b".into(),
                wall: now_rfc3339(),
            })
            .await
            .unwrap();
            // 2) шаг.
            let (reply, wait) = oneshot::channel();
            tx.send(Cmd::StartStep {
                title: "читаю идентификаторы".into(),
                reply,
            })
            .await
            .unwrap();
            let step = wait.await.unwrap().unwrap();
            assert_eq!(step.idx, 1);
            assert_eq!(step.action, "start");
            // 3) строка внутри шага.
            tx.send(Cmd::Line {
                line: "[+1.000s] VCP RX ReadFile(COM6) rc=0 n=2 : a0 5a".into(),
                wall: now_rfc3339(),
            })
            .await
            .unwrap();
            // 4) метка и заметка.
            let (reply, wait) = oneshot::channel();
            tx.send(Cmd::Mark {
                title: "нажал ОК".into(),
                reply,
            })
            .await
            .unwrap();
            let mark = wait.await.unwrap().unwrap();
            assert!(mark.seq > 0);
            assert_eq!(mark.kind, EventKind::Mark);
            let (reply, wait) = oneshot::channel();
            tx.send(Cmd::Note {
                text: "после цикла питания".into(),
                reply,
            })
            .await
            .unwrap();
            wait.await.unwrap().unwrap();
            // 5) закрыть шаг.
            let (reply, wait) = oneshot::channel();
            tx.send(Cmd::EndStep { reply }).await.unwrap();
            let summary = wait.await.unwrap().unwrap();
            assert_eq!(summary.idx, 1);
            assert_eq!(summary.title, "читаю идентификаторы");
            // 6) завершить сессию.
            let (reply, wait) = oneshot::channel();
            tx.send(Cmd::Detach { reply }).await.unwrap();
            let finished = wait.await.unwrap().unwrap().expect("мета сессии");
            assert_eq!(finished.status, "finished");
            assert!(finished.ended_at.is_some());
            summary
        });
        assert!(!summary.title.is_empty());
        rt.block_on(worker).expect("писатель должен завершиться без паники");

        // ── проверки на диске ────────────────────────────────────────────
        let session_dir = PathBuf::from(&meta.dir);
        let events = std::fs::read_to_string(session_dir.join("events.jsonl")).unwrap();
        let lines: Vec<&str> = events.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(lines.len() >= 5, "ожидались события, получено {}", lines.len());
        assert!(events.contains("step_start"));
        assert!(events.contains("step_end"));
        assert!(
            events.contains("\"step\":1"),
            "событие внутри шага должно иметь step=1: {events}"
        );
        let raw = std::fs::read_to_string(session_dir.join("raw.log")).unwrap();
        assert!(raw.contains("12 04 0d 1b"), "raw.log без полезной нагрузки: {raw}");
        assert!(
            session_dir.join("steps").join("01.json").is_file(),
            "steps/01.json не сохранён"
        );
        let stored_meta: SessionMeta =
            serde_json::from_str(&std::fs::read_to_string(session_dir.join("session.json")).unwrap())
                .unwrap();
        assert_eq!(stored_meta.status, "finished");
        assert!(stored_meta.counts.events >= 5);
        assert_eq!(stored_meta.counts.tx, 1);
        assert_eq!(stored_meta.counts.rx, 1);

        // ── сообщения UI ────────────────────────────────────────────────
        let mut batches = 0usize;
        let mut steps = 0usize;
        while let Ok(msg) = bus_rx.try_recv() {
            match msg {
                ServerMsg::Batch { events, .. } => {
                    batches += 1;
                    assert!(events.len() <= BATCH_MAX_EVENTS);
                }
                ServerMsg::Step { .. } => steps += 1,
                _ => {}
            }
        }
        assert!(batches >= 1, "UI не получил ни одного Batch");
        assert!(steps >= 2, "UI не получил Step start/end, получено {steps}");
    }

    // ───────────────────────── EDIABAS/WinKFP ────────────────────────────

    /// Кусок реального формата api.trc (как reference/logs/ediabas/api.trc).
    const API_TRC_HEAD: &str = "#'Mon Oct 12 02:00:00 2026;!Xh;V7.3.0;#\n\
Initialization\nJob\n\t\"bms46ds0\"\n\t\"ident\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
Results:\n\t[ 0 ]\n\tOBJECT = \"bms46ds0\"\n\tID_BMW_NR = \"1430940\"\n\tID_SW_NR = \"F0\"\n\
Initialization\nJob\n\t\"ms450\"\n\t\"FLASH_PROGRAMMIEREN\"\n\t\"\"\n\t0\n\t\"\"\n\t0\n\t0\n\
Error (134) API-0014: RESULT NOT FOUND\n";

    const API_TRC_STEP1: &str = "Initialization\nJob\n\t\"ms41\"\n\t\"STATUS\"\n\t\"\"\n\t0\n\
\t\"\"\n\t0\n\t0\nResults:\n\t[ 0 ]\n\tOBJECT = \"ms41\"\n\tID_SW_NR = \"ABC123\"\n";

    fn test_ediabas_paths(dir: &Path) -> EdiabasPaths {
        EdiabasPaths {
            ediabas_ini: dir.join("EDIABAS.INI"),
            obd_ini: dir.join("OBD.INI"),
            winkfp_ini: dir.join("Winkfpt.ini"),
            trace_dir: dir.join("TRACE"),
        }
    }

    #[test]
    fn ediabas_target_detection() {
        for name in ["winkfpt", "WINKFPT.EXE", "INPA", "tool32.exe", "nfs", "EDIABAS"] {
            assert!(is_ediabas_target(name), "{name} должен быть EDIABAS-целью");
        }
        for name in ["quickflash", "me72quickflash", "notepad.exe", ""] {
            assert!(!is_ediabas_target(name), "{name} не EDIABAS-цель");
        }
    }

    #[test]
    fn ediabas_mode_uses_fresh_traces_only() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_ediabas_paths(dir.path());
        std::fs::create_dir_all(&paths.trace_dir).unwrap();
        // Трасс нет: класс решает.
        assert!(!ediabas_mode_enabled("quickflash", &paths));
        assert!(ediabas_mode_enabled("winkfpt.exe", &paths));
        // Свежая трасса включает режим и для неизвестного процесса.
        std::fs::write(paths.api_trace(), "Initialization\n").unwrap();
        assert!(paths.traces_present());
        assert!(paths.traces_fresh());
        assert!(ediabas_mode_enabled("quickflash", &paths));
    }

    #[test]
    fn ediabas_collect_returns_only_delta() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_ediabas_paths(dir.path());
        std::fs::create_dir_all(&paths.trace_dir).unwrap();
        std::fs::write(paths.api_trace(), API_TRC_HEAD).unwrap();
        std::fs::write(paths.ifh_trace(), "_STD INPUT: --\n_STD OUTPUT: 12 04\n").unwrap();

        let api_offset = ediabas::snapshot_trace(&paths.api_trace()).unwrap();
        let ifh_offset = ediabas::snapshot_trace(&paths.ifh_trace()).unwrap();
        // Стартовые job'ы в offset не входят.
        let first = collect_ediabas_delta(&paths, api_offset, ifh_offset).unwrap();
        assert!(first.jobs.is_empty(), "стартовые job'ы не должны попадать в шаг");
        assert!(first.api_delta.is_empty());

        // Дописываем job — он должен прийти ровно один раз.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(paths.api_trace())
                .unwrap();
            f.write_all(API_TRC_STEP1.as_bytes()).unwrap();
        }
        let second = collect_ediabas_delta(&paths, first.api_offset, first.ifh_offset).unwrap();
        assert_eq!(second.jobs.len(), 1);
        assert_eq!(second.jobs[0].job, "STATUS");
        assert_eq!(second.jobs[0].sgbd, "ms41");
        assert!(!second.api_delta.is_empty());

        // Ещё раз с новых offset'ов — ничего нового.
        let third =
            collect_ediabas_delta(&paths, second.api_offset, second.ifh_offset).unwrap();
        assert!(third.jobs.is_empty());
    }

    #[test]
    fn ediabas_collect_missing_traces_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_ediabas_paths(dir.path());
        let delta = collect_ediabas_delta(&paths, 0, 0).expect("нет трасс — не ошибка");
        assert!(delta.jobs.is_empty());
        assert!(delta.api_delta.is_empty() && delta.ifh_delta.is_empty());
    }

    /// «Нет трасс, процесс не EDIABAS» — шаг проходит без winkfp-данных (Quickflash-путь).
    #[test]
    fn quickflash_gets_no_ediabas_data() {
        let dir = tempfile::tempdir().unwrap();
        let paths = test_ediabas_paths(dir.path());
        std::fs::create_dir_all(&paths.trace_dir).unwrap();
        assert!(!ediabas_mode_enabled("ME72 Quickflash", &paths));
        assert!(
            collect_ediabas_delta(&paths, 0, 0)
                .map(|d| d.jobs.is_empty())
                .unwrap_or(false)
        );
    }
}


