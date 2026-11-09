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

export type Transport = "ftd2xx" | "vcp" | "usb" | "j2534" | "file" | "app" | "none";
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
}

export interface AdapterInfo {
  serial: string;
  description: string;
  com_port?: number | null;
  vendor_id?: number | null;
  product_id?: number | null;
}

export interface Note {
  t: number;
  wall: string;
  text: string;
  author: string;
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
  reads: StepRead[];
  filehash: FileHash[];
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
