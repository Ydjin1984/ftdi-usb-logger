/** Типы, зеркалящие `engine/src/models.rs`. Держать синхронно! */

export type EventKind =
  | "tx"
  | "rx"
  | "mark"
  | "step_start"
  | "step_end"
  | "file"
  | "file_hash"
  | "sys"
  | "module"
  | "vcp"
  | "note"
  | "shot"
  | "summary"
  | "error"
  | "raw";

export type Transport = "ftd2xx" | "vcp" | "usb" | "j2534" | "lan" | "file" | "app" | "none";
export type Direction = "tx" | "rx";

export interface Event {
  seq: number;
  t: number;
  wall: string;
  kind: EventKind;
  transport: Transport;
  api: string;
  direction?: Direction | null;
  len: number;
  hex: string;
  text?: string | null;
  rc?: number | null;
  step?: number | null;
  raw: string;
  meta?: Record<string, unknown> | null;
}

export interface SessionCounts {
  events: number;
  tx: number;
  rx: number;
  tx_bytes: number;
  rx_bytes: number;
  steps: number;
  files: number;
  errors: number;
  /** Первые ошибки с расшифровкой — в отчёте это раздел «Ошибки». */
  error_samples?: string[];
  /** Холостые опросы (`rx-empty`): штатные таймауты, не ошибки. */
  empty_polls?: number;
  /** Каналы, замеченные без `PassThruConnect` (`chan-miss`): тоже не ошибки. */
  untracked_channels?: number;
  /** Протоколы по запросам: `{"0x8003": 11096}`. */
  protocols?: Record<string, number>;
  /** Внутренние записи второго слоя J2534 (прокси → драйвер): не в счётчиках. */
  inner_events?: number;
  inner_tx?: number;
  inner_rx?: number;
  inner_bytes?: number;
  /** Слои J2534: `proxy`, `driver` (docs/13 §6.2). */
  j2534_layers?: string[];
  /** Модули J2534, которые открывались (для старых логов без разметки). */
  j2534_modules?: string[];
}

export interface AdapterInfo {
  serial: string;
  description: string;
  com_port?: number | null;
  vendor_id?: number | null;
  product_id?: number | null;
  /** Вендор из `J2534 open` (Scanmatik, CHIPSOFT, …). */
  vendor?: string | null;
  /** Строка прошивки из `J2534 version`: `FW:1060 HW:02 SN:A62122`. */
  firmware?: string | null;
  dll_version?: string | null;
  api?: string | null;
  dll?: string | null;
}

export interface Note {
  t: number;
  wall: string;
  text: string;
  author: string;
}

/* ── J2534-прокси: второй канал захвата (docs/13-j2534-proxy.md, §8) ─────── */

/** Файл прокси-DLL в каталоге установки. */
export interface ProxyDll {
  path: string;
  present: boolean;
  /** Версия из ресурсов DLL (`1.0.0.123`); пустая — прочитать не удалось. */
  version: string;
  /** `CompanyName` из ресурса версии: чей это файл (docs/13 §3.1). */
  company?: string;
  /** `FileDescription` из ресурса версии. */
  description?: string;
  /** Разрядность из PE-заголовка: `x86` | `x64` | `arm64` | `?`. */
  arch?: string;
  /** Файл — наш прокси, а не чужая библиотека на его месте. */
  ours?: boolean;
}

/** `j2534proxy.ini`: `Enabled` — главный признак включённости прокси. */
export interface ProxyIni {
  path: string;
  present: boolean;
  enabled: boolean;
}

/** Запись устройства в `HKLM\SOFTWARE\WOW6432Node\PassThruSupport.04.04`. */
export interface ProxyRegistry {
  registered: boolean;
  key: string;
  device_name: string;
  function_library: string;
}

/** Настоящий (вендорный) драйвер, в который прокси форвардит вызовы. */
export interface ProxyReal {
  path: string;
  present: boolean;
  /** Откуда взят путь: `env`, `ini`, `file`, `registry`. */
  from: string;
}

/** Выбор адаптера в PCMflash и сохранённый прежний выбор. */
export interface ProxyPcmflash {
  adapter: string;
  proxy_selected: boolean;
  /** Прежний адаптер — восстанавливается при выключении; пусто, если бэкапа нет. */
  backup: string;
}

/** Один загруженный прокси: файл `proxy-live-<pid>.state` (docs/13 §6.1). */
export interface ProxyLiveItem {
  pid: number;
  /** `live` — DLL не выгружалась; `stopped` — выгружена. */
  state: string;
  exe: string;
  exe_name: string;
  dll: string;
  real: string;
  log: string;
  device: string;
  /** `wall(start)` из шапки журнала. */
  started: string;
  /** Секунд с последнего обновления файла (то есть с последнего обмена). */
  age_s: number;
  calls: number;
  tx: number;
  rx: number;
  errors: number;
  gen: number;
  bits: number;
  /** Настоящий драйвер не открылся: вызовы вернут 0x08. */
  fatal: boolean;
  version: string;
  /** Процесс жив и это тот же exe — прокси работает прямо сейчас. */
  alive: boolean;
}

/** Сводка «подхватился ли прокси»: `loaded` | `recent` | `idle`. */
export interface ProxyLive {
  state: string;
  items: ProxyLiveItem[];
  files: number;
  /** Что это значит и что делать — текстом. */
  notes: string[];
}

/** Зарегистрированный J2534-драйвер как вариант «какой шнурок проксировать». */
export interface ProxyDevice {
  name: string;
  vendor: string;
  dll: string;
  present: boolean;
  api: string;
  /** Это текущий `RealLibrary` прокси. */
  current: boolean;
  /** Наше собственное устройство: проксировать его нельзя. */
  is_proxy: boolean;
}

/** Полное состояние прокси: ответ `GET /j2534/proxy`. */
export interface ProxyStatus {
  ok: boolean;
  elevated: boolean;
  install_dir: string;
  dll: ProxyDll;
  ini: ProxyIni;
  registry: ProxyRegistry;
  real: ProxyReal;
  log_dir: string;
  log_files: number;
  pcmflash: ProxyPcmflash;
  /** Живое состояние: подхвачен ли прокси и сколько он уже видел. */
  live?: ProxyLive;
  /** Из чего выбирать «шнурок». */
  devices?: ProxyDevice[];
  /** Причины отказа при `ok:false` — показываются пользователю как есть. */
  notes: string[];
}

/** Сверка полос: сколько кадров frida нашлось в журнале прокси. */
export interface ProxyCross {
  tx_matched: number;
  /** Есть в frida, нет в прокси — потеря второго канала. */
  tx_missing: number;
  rx_matched: number;
  rx_missing: number;
  /** Есть в прокси, нет в frida — потеря первого канала. */
  extra: number;
}

/** Полоса прокси в сессии (`session.json.proxy`). */
export interface ProxyLane {
  /** Сколько журналов и байт подхвачено. */
  files: number;
  bytes: number;
  tx: number;
  rx: number;
  calls: number;
  errors: number;
  /** Границы по времени прокси. */
  first_t?: number | null;
  last_t?: number | null;
  cross: ProxyCross;
  notes?: string[];
}

export interface SessionMeta {
  id: string;
  started_at: string;
  ended_at?: string | null;
  label: string;
  tool_path?: string | null;
  tool_sha256?: string | null;
  tool_version?: string | null;
  pid?: number | null;
  process?: string | null;
  transport: string;
  adapter?: AdapterInfo | null;
  host: string;
  counts: SessionCounts;
  tags: string[];
  notes: Note[];
  status: string;
  engine_version: string;
  dir: string;
  facts: string[];
  /** Полоса прокси, если в окне сессии нашлись её журналы (§8). */
  proxy?: ProxyLane | null;
}

export interface StepRead {
  start: number;
  len: number;
  blocks: number;
  sha256: string;
}

export interface FileHash {
  path: string;
  size: number;
  sha256: string;
  mode?: string;
}

export interface WinkfpJob {
  sgbd: string;
  job: string;
  args: string[];
  results: Record<string, unknown>;
  errors: string[];
  results_total: number;
}

export interface StepVerdict {
  denied: number;
  no_answer: number;
  echo: boolean;
  unparsed: number;
}

export interface StepSummary {
  idx: number;
  title: string;
  dur: number;
  exchanges: number;
  tx_bytes: number;
  rx_bytes: number;
  cmd_hist: Record<string, number>;
  resp_hist: Record<string, number>;
  /** Сетевой обмен процесса (Winsock/DoIP) — не протокол ЭБУ. */
  net_hist?: Record<string, number>;
  net_tx?: number;
  net_rx?: number;
  reads?: StepRead[];
  filehash?: FileHash[];
  png?: string | null;
  winkfp_jobs: WinkfpJob[];
  verdict: StepVerdict;
  started_at: string;
  ended_at: string;
}

export interface StepEvent {
  action: "start" | "end";
  idx: number;
  title: string;
  t: number;
  wall: string;
}

export interface FtdiDevice {
  index: number;
  serial: string;
  description: string;
  flags: number;
  dev_type: number;
  vendor_id?: number | null;
  product_id?: number | null;
  com_port?: number | null;
  source: string;
}

export interface ExeMeta {
  path: string;
  size: number;
  mtime: string;
  sha256: string;
  version: string;
  company: string;
  description: string;
}

export interface ToolProcess {
  pid: number;
  name: string;
  exe: string;
  has_ftd2xx: boolean;
  has_j2534?: boolean;
  has_usb?: boolean;
  known_tool?: string | null;
  started_at?: string | null;
  window_title?: string | null;
  cmdline?: string | null;
  capabilities?: string[];
  modules_denied?: boolean;
  arch?: string;
}

export interface UsbDevice {
  id: string;
  vid?: number | null;
  pid?: number | null;
  serial: string;
  description: string;
  manufacturer: string;
  friendly_name: string;
  service: string;
  class_name: string;
  com_port?: number | null;
  present: boolean;
  interfaces: string[];
  kind: string;
}

export interface J2534Driver {
  registry_key: string;
  name: string;
  vendor: string;
  dll: string;
  dll_present: boolean;
  version: string;
}

export interface EnvCapabilities {
  process_scan: boolean;
  usb_enum: boolean;
  ftd2xx: boolean;
  j2534: number;
  usbpcap: boolean;
  usbpcap_devices: string[];
}

export interface ProcessDetail {
  proc: ToolProcess;
  exe_meta: ExeMeta;
  modules: string[];
}

export interface CaptureStatus {
  recording: boolean;
  session?: string | null;
  hooks: string;
  bridge: boolean;
  target?: ToolProcess | null;
  counts: SessionCounts;
  step?: StepEvent | null;
  started_at?: string | null;
}

export interface Health {
  version: string;
  uptime_s: number;
  bridge: boolean;
  capture: CaptureStatus;
  sessions: number;
  ui_dist: boolean;
  python: string;
  capabilities?: EnvCapabilities;
  universal?: boolean;
  /** Запущен ли движок с правами администратора (нужны Frida-хукам). */
  admin?: boolean;
}

export interface PayloadDecode {
  len: number;
  hex: string;
  ascii: string;
  cmd?: string | null;
  payload_hex: string;
  echo?: number | null;
  notes: string[];
}

export interface SessionDetail {
  meta: SessionMeta;
  steps: StepSummary[];
}

export interface EventsPage {
  events: Event[];
  counts?: SessionCounts;
  total?: number;
}

/* ───────────────────────────── WS-сообщения ────────────────────────────── */

export type ServerMsg =
  | { type: "hello"; server_version: string; active_session: string | null }
  | { type: "batch"; session: string; events: Event[]; counts: SessionCounts }
  | {
      type: "status";
      session: string | null;
      target: ToolProcess | null;
      hooks: string;
      recording: boolean;
      counts: SessionCounts;
    }
  | { type: "step"; action: "start" | "end"; step: StepEvent | StepSummary }
  | { type: "toast"; level: "info" | "warn" | "error"; text: string };

export type ClientMsg =
  | { op: "subscribe"; session: string | null; since: number }
  | { op: "ping" };
export interface NewSessionResult {
  stopped: SessionMeta | null;
  devices: FtdiDevice[];
  tools: ToolProcess[];
  usb_devices: UsbDevice[];
  j2534_drivers: J2534Driver[];
  capabilities?: EnvCapabilities;
}
