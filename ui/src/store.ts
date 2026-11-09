/** Состояние приложения и действия. Компоненты читают state и вызывают методы. */

import { api, ApiError, isDemoMode, WsClient } from "./api";
import { demoCounts, demoEvents, demoJ2534Drivers, demoSession, demoSteps, demoUsbDevices } from "./demo";
import { sound } from "./sound";
import type {
  CaptureStatus,
  Event,
  EventKind,
  FtdiDevice,
  Health,
  Note,
  SessionCounts,
  SessionMeta,
  StepEvent,
  StepSummary,
  ToolProcess,
  UsbDevice,
  J2534Driver,
} from "./types";

const RING = 60_000;
const PAGE = 3000;

export type ToastLevel = "info" | "ok" | "warn" | "error";
export interface Toast {
  id: number;
  level: ToastLevel;
  text: string;
}

export interface StoreState {
  mode: "live" | "demo";
  booted: boolean;
  bootError: string | null;
  wsState: "connecting" | "open" | "closed";

  health: Health | null;
  status: CaptureStatus | null;
  sessions: SessionMeta[];
  active: SessionMeta | null;
  steps: StepSummary[];
  notes: Note[];

  events: Event[];
  firstSeq: number;
  lastSeq: number;
  total: number;
  hasMoreBefore: boolean;

  devices: FtdiDevice[];
  tools: ToolProcess[];
  usbDevices: UsbDevice[];
  j2534Drivers: J2534Driver[];
  toolsMode: "auto" | "usb" | "window" | "all";
  loadingTargets: boolean;

  filters: Set<EventKind>;
  query: string;
  selection: Event | null;
  follow: boolean;
  pendingNew: number;

  currentStep: StepEvent | null;
  stepStartEpoch: number;
  quickTitles: string[];
  tick: number;
  toasts: Toast[];
}

const ALL_KINDS: EventKind[] = [
  "tx",
  "rx",
  "mark",
  "step_start",
  "step_end",
  "file",
  "file_hash",
  "vcp",
  "module",
  "note",
  "sys",
  "error",
];

const DEFAULT_TITLES = ["идентификация", "чтение калибровки", "запись тюна", "проверка", "сброс ошибок"];

function loadTitles(): string[] {
  try {
    const raw = localStorage.getItem("ftdi.quickTitles");
    if (raw) {
      const arr = JSON.parse(raw) as unknown;
      if (Array.isArray(arr) && arr.every((x) => typeof x === "string") && arr.length) return arr as string[];
    }
  } catch {
    /* ignore */
  }
  return [...DEFAULT_TITLES];
}

function emptyCounts(): SessionCounts {
  return { events: 0, tx: 0, rx: 0, tx_bytes: 0, rx_bytes: 0, steps: 0, files: 0, errors: 0 };
}

class Store {
  state: StoreState;
  private listeners = new Set<() => void>();
  private ws: WsClient | null = null;
  private toastSeq = 0;
  private pollTimer: number | null = null;
  private tickTimer: number | null = null;

  constructor() {
    const demo = isDemoMode();
    this.state = {
      mode: demo ? "demo" : "live",
      booted: false,
      bootError: null,
      wsState: "connecting",
      health: null,
      status: null,
      sessions: [],
      active: null,
      steps: [],
      notes: [],
      events: [],
      firstSeq: 0,
      lastSeq: 0,
      total: 0,
      hasMoreBefore: false,
      devices: [],
      tools: [],
      usbDevices: [],
      j2534Drivers: [],
      toolsMode: "auto",
      loadingTargets: false,
      filters: new Set(ALL_KINDS),
      query: "",
      selection: null,
      follow: true,
      pendingNew: 0,
      currentStep: null,
      stepStartEpoch: 0,
      quickTitles: loadTitles(),
      tick: Date.now(),
      toasts: [],
    };
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(): void {
    for (const fn of this.listeners) fn();
  }

  toast(level: ToastLevel, text: string): void {
    const id = ++this.toastSeq;
    this.state.toasts = [...this.state.toasts.slice(-4), { id, level, text }];
    this.emit();
    window.setTimeout(() => {
      this.state.toasts = this.state.toasts.filter((t) => t.id !== id);
      this.emit();
    }, level === "error" ? 9000 : 4200);
  }

  dismissToast(id: number): void {
    this.state.toasts = this.state.toasts.filter((t) => t.id !== id);
    this.emit();
  }

  /* ───────────────────────────── инициализация ───────────────────────── */

  async init(): Promise<void> {
    if (this.state.mode === "demo") {
      this.initDemo();
      return;
    }
    try {
      const health = await api.health();
      this.state.health = health;
      this.state.status = health.capture ?? null;
      const [sessions, devices, tools, usb, j2534] = await Promise.all([
        api.sessions().catch(() => [] as SessionMeta[]),
        api.devices().catch(() => [] as FtdiDevice[]),
        api.tools("auto").catch(() => [] as ToolProcess[]),
        api.usbDevices().catch(() => [] as UsbDevice[]),
        api.j2534Drivers().catch(() => [] as J2534Driver[]),
      ]);
      this.state.sessions = sessions;
      this.state.devices = devices;
      this.state.tools = tools;
      this.state.usbDevices = usb;
      this.state.j2534Drivers = j2534;
      this.state.booted = true;
      this.emit();

      this.connectWs();
      const preferred = health.capture?.session || sessions[0]?.id || null;
      if (preferred) await this.selectSession(preferred);
      this.startPolling();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : (e as Error).message;
      this.state.bootError = msg;
      this.emit();
    }
  }

  private initDemo(): void {
    const session = demoSession();
    const events = demoEvents();
    const steps = demoSteps();
    session.counts = { ...demoCounts(), events: events.length };
    this.state.health = {
      version: "0.1.0-demo",
      uptime_s: 42,
      bridge: true,
      capture: {
        recording: true,
        session: session.id,
        hooks: "on",
        bridge: true,
        target: {
          pid: 8421,
          name: "BMS46 Quickflash.exe",
          exe: session.tool_path || "",
          has_ftd2xx: true,
          known_tool: "BMS46 Quickflash",
          window_title: "BMS46 Quickflash 1.0.3",
        },
        counts: session.counts,
        step: null,
        started_at: session.started_at,
      },
      sessions: 1,
      ui_dist: true,
      python: "demo",
    };
    this.state.status = this.state.health.capture;
    this.state.sessions = [session];
    this.state.devices = [
      {
        index: 0,
        serial: "A1B2C3D4",
        description: "FT232R USB UART",
        flags: 1,
        dev_type: 0,
        vendor_id: 1027,
        product_id: 24577,
        com_port: 6,
        source: "d2xx",
      },
    ];
    this.state.tools = [
      {
        pid: 8421,
        name: "BMS46 Quickflash.exe",
        exe: session.tool_path || "",
        has_ftd2xx: true,
        known_tool: "BMS46 Quickflash",
        window_title: "BMS46 Quickflash 1.0.3",
      },
      {
        pid: 11208,
        name: "winkfpt.exe",
        exe: "C:\\EC-APPS\\NFS\\BIN\\winkfpt.exe",
        has_ftd2xx: false,
        known_tool: "WinKFP",
        window_title: "WinKFP - Winkfp",
      },
    ];
    this.state.usbDevices = demoUsbDevices();
    this.state.j2534Drivers = demoJ2534Drivers();
    this.state.active = session;
    this.state.steps = steps;
    this.state.notes = session.notes;
    this.state.events = events;
    this.state.firstSeq = 0;
    this.state.lastSeq = events.length ? events[events.length - 1].seq : 0;
    this.state.total = events.length;
    this.state.wsState = "open";
    this.state.booted = true;
    this.state.currentStep = { action: "start", idx: 3, title: "запись тюна", t: 108, wall: session.started_at };
    this.state.stepStartEpoch = Date.now() - 132_000;
    this.startTicking();
    this.emit();
    this.toast("info", "демо-режим: данные синтетические, устройство не требуется");
  }

  private startPolling(): void {
    if (this.pollTimer != null) window.clearInterval(this.pollTimer);
    let idleTicks = 0;
    this.pollTimer = window.setInterval(() => {
      void api
        .health()
        .then((h) => {
          this.state.health = h;
          this.state.status = h.capture ?? this.state.status;
          this.emit();
          // Когда захвата нет — раз в ~12 с обновляем список процессов/устройств,
          // чтобы запущенная «прямо сейчас» программа появлялась сама.
          idleTicks += 1;
          if (!h.capture?.recording && !this.state.loadingTargets && idleTicks % 3 === 0) {
            void this.refreshTargets();
          }
        })
        .catch(() => {
          this.state.wsState = "closed";
          this.emit();
        });
    }, 4000);
    this.startTicking();
  }

  private startTicking(): void {
    if (this.tickTimer != null) window.clearInterval(this.tickTimer);
    this.tickTimer = window.setInterval(() => {
      this.state.tick = Date.now();
      this.emit();
    }, 1000);
  }

  private connectWs(): void {
    this.ws = new WsClient();
    this.ws.onState = (s) => {
      this.state.wsState = s;
      this.emit();
    };
    this.ws.onMessage = (msg) => this.onWs(msg);
  }

  private onWs(msg: import("./types").ServerMsg): void {
    switch (msg.type) {
      case "hello":
        this.state.wsState = "open";
        this.emit();
        break;
      case "batch":
        if (msg.session === this.state.active?.id) {
          this.appendEvents(msg.events);
          if (this.state.status) this.state.status.counts = msg.counts;
          this.emit();
        }
        break;
      case "status":
        this.state.status = {
          recording: msg.recording,
          session: msg.session,
          hooks: msg.hooks,
          bridge: this.state.status?.bridge ?? true,
          target: msg.target,
          counts: msg.counts,
          step: this.state.currentStep,
          started_at: this.state.status?.started_at ?? null,
        };
        this.emit();
        break;
      case "step": {
        if (msg.action === "start") {
          const st = msg.step as StepEvent;
          this.state.currentStep = st;
          this.state.stepStartEpoch = Date.now();
          sound.stepStart();
        } else {
          const summary = msg.step as StepSummary;
          this.state.currentStep = null;
          this.state.stepStartEpoch = 0;
          if (!this.state.steps.some((s) => s.idx === summary.idx)) {
            this.state.steps = [...this.state.steps, summary];
          } else {
            this.state.steps = this.state.steps.map((s) => (s.idx === summary.idx ? summary : s));
          }
          sound.stepEnd();
          this.toast("ok", `шаг ${summary.idx} закрыт: ${summary.exchanges} обменов, ${summary.dur.toFixed(1)} с`);
        }
        this.emit();
        break;
      }
      case "toast": {
        const level = msg.level === "error" ? "error" : msg.level === "warn" ? "warn" : "info";
        this.toast(level, msg.text);
        break;
      }
    }
  }

  /* ───────────────────────────── сессии ──────────────────────────────── */

  async refreshSessions(): Promise<void> {
    if (this.state.mode === "demo") return;
    try {
      this.state.sessions = await api.sessions();
      this.emit();
    } catch (e) {
      this.toast("warn", `не удалось обновить список сессий: ${(e as Error).message}`);
    }
  }

  async selectSession(id: string): Promise<void> {
    if (this.state.mode === "demo") return;
    try {
      const [detail, page] = await Promise.all([
        api.session(id),
        api.events(id, { limit: PAGE }).catch(() => ({ events: [] as Event[] })),
      ]);
      const total = detail.meta.counts?.events ?? page.events.length;
      let events = page.events;
      // Если сессия большая — грузим хвост, а не начало.
      if (total > PAGE) {
        const from = Math.max(0, total - PAGE);
        const tail = await api.events(id, { from, limit: PAGE }).catch(() => null);
        if (tail?.events?.length) events = tail.events;
      }
      this.state.active = detail.meta;
      this.state.steps = detail.steps ?? [];
      this.state.notes = detail.meta.notes ?? [];
      this.state.events = events;
      this.state.firstSeq = events.length ? events[0].seq : 0;
      this.state.lastSeq = events.length ? events[events.length - 1].seq : 0;
      this.state.total = total;
      this.state.hasMoreBefore = this.state.firstSeq > 0;
      this.state.selection = null;
      this.state.follow = true;
      this.state.pendingNew = 0;
      this.state.currentStep = null;
      this.state.stepStartEpoch = 0;
      this.ws?.subscribe(id, this.state.lastSeq + 1);
      this.emit();
    } catch (e) {
      this.toast("error", `сессия не открылась: ${(e as Error).message}`);
    }
  }

  async loadOlder(): Promise<void> {
    const s = this.state;
    if (s.mode === "demo" || !s.active || !s.hasMoreBefore) return;
    const from = Math.max(0, s.firstSeq - PAGE);
    try {
      const page = await api.events(s.active.id, { from, to: s.firstSeq, limit: PAGE });
      if (!page.events.length) {
        s.hasMoreBefore = false;
        this.emit();
        return;
      }
      const merged = [...page.events, ...s.events];
      s.events = merged.slice(-RING);
      s.firstSeq = s.events.length ? s.events[0].seq : 0;
      s.hasMoreBefore = from > 0;
      this.emit();
    } catch (e) {
      this.toast("warn", `не удалось догрузить историю: ${(e as Error).message}`);
    }
  }

  private appendEvents(events: Event[]): void {
    if (!events.length) return;
    const s = this.state;
    const fresh = events.filter((e) => e.seq > s.lastSeq);
    if (!fresh.length) return;
    s.events = [...s.events, ...fresh];
    if (s.events.length > RING) s.events = s.events.slice(s.events.length - RING);
    s.lastSeq = fresh[fresh.length - 1].seq;
    if (s.firstSeq === 0 && s.events.length) s.firstSeq = s.events[0].seq;
    s.total = Math.max(s.total + fresh.length, s.lastSeq + 1);
    if (!s.follow) s.pendingNew += fresh.length;
    // Автозакрытие шага, если пришёл step_end.
    for (const e of fresh) {
      if (e.kind === "step_end" && s.currentStep && e.step === s.currentStep.idx) {
        s.currentStep = null;
        s.stepStartEpoch = 0;
      }
    }
  }

  setFollow(v: boolean): void {
    this.state.follow = v;
    if (v) this.state.pendingNew = 0;
    this.emit();
  }

  selectEvent(ev: Event | null): void {
    this.state.selection = ev;
    this.emit();
  }

  toggleFilter(kind: EventKind): void {
    const f = new Set(this.state.filters);
    if (f.has(kind)) f.delete(kind);
    else f.add(kind);
    this.state.filters = f;
    this.emit();
  }

  setFilters(kinds: EventKind[]): void {
    this.state.filters = new Set(kinds);
    this.emit();
  }

  setQuery(q: string): void {
    this.state.query = q;
    this.emit();
  }

  visibleEvents(): Event[] {
    const { events, filters, query } = this.state;
    const q = query.trim().toLowerCase();
    if (q) {
      return events.filter(
        (e) =>
          filters.has(e.kind) &&
          (e.hex.includes(q) ||
            e.api.toLowerCase().includes(q) ||
            (e.text || "").toLowerCase().includes(q) ||
            e.raw.toLowerCase().includes(q)),
      );
    }
    if (filters.size === ALL_KINDS.length) return events;
    return events.filter((e) => filters.has(e.kind));
  }

  /* ───────────────────────────── захват ──────────────────────────────── */

  async setToolsMode(mode: "auto" | "usb" | "window" | "all"): Promise<void> {
    this.state.toolsMode = mode;
    this.emit();
    if (this.state.mode === "demo") return;
    try {
      this.state.tools = await api.tools(mode);
      this.emit();
    } catch (e) {
      this.toast("warn", `список программ: ${(e as Error).message}`);
    }
  }

  /** Прицепиться к PID вручную — универсальный путь, если драйвер не виден. */
  async attachPid(pid: number, label?: string): Promise<void> {
    if (!Number.isFinite(pid) || pid <= 0) {
      this.toast("warn", "нужен корректный PID");
      return;
    }
    const name = label?.trim() || `pid ${pid}`;
    await this.attach(pid, name);
  }

  async refreshTargets(): Promise<void> {
    if (this.state.mode === "demo") return;
    this.state.loadingTargets = true;
    this.emit();
    try {
      const [devices, tools, usb, j2534] = await Promise.all([
        api.devices().catch(() => this.state.devices),
        api.tools(this.state.toolsMode).catch(() => this.state.tools),
        api.usbDevices().catch(() => this.state.usbDevices),
        api.j2534Drivers().catch(() => this.state.j2534Drivers),
      ]);
      this.state.devices = devices;
      this.state.tools = tools;
      this.state.usbDevices = usb;
      this.state.j2534Drivers = j2534;
    } catch (e) {
      this.toast("warn", `не удалось обновить устройства: ${(e as Error).message}`);
    } finally {
      this.state.loadingTargets = false;
      this.emit();
    }
  }

  /** Сырой захват USB-шины через USBPcap (нужен драйвер + права администратора). */
  async startUsbpcap(device: string): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", "демо-режим: USBPcap недоступен");
      return;
    }
    try {
      const meta = await api.startUsbpcap(device);
      this.state.active = meta;
      this.state.sessions = [meta, ...this.state.sessions.filter((s) => s.id !== meta.id)];
      this.state.events = [];
      this.state.steps = [];
      this.state.firstSeq = 0;
      this.state.lastSeq = 0;
      this.state.total = 0;
      this.state.currentStep = null;
      this.ws?.subscribe(meta.id, 0);
      this.toast("ok", `сырой USB-захват: ${device}`);
      this.emit();
    } catch (e) {
      this.toast("error", `USBPcap не запустился: ${(e as Error).message}`);
    }
  }

  async attach(pid: number, label?: string): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", "демо-режим: attach недоступен");
      return;
    }
    try {
      const meta = await api.attach(pid, label);
      this.state.active = meta;
      this.state.sessions = [meta, ...this.state.sessions.filter((s) => s.id !== meta.id)];
      this.state.events = [];
      this.state.steps = [];
      this.state.firstSeq = 0;
      this.state.lastSeq = 0;
      this.state.total = 0;
      this.state.currentStep = null;
      this.ws?.subscribe(meta.id, 0);
      this.toast("ok", `захват запущен: ${meta.label}`);
      this.emit();
    } catch (e) {
      this.toast("error", `attach не удался: ${(e as Error).message}`);
    }
  }

  async detach(): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", "демо-режим: detach недоступен");
      return;
    }
    try {
      const meta = await api.detach();
      if (meta) {
        this.state.sessions = this.state.sessions.map((s) => (s.id === meta.id ? meta : s));
        if (this.state.active?.id === meta.id) this.state.active = meta;
      }
      this.state.currentStep = null;
      this.toast("ok", "сессия остановлена, отчёт собран");
      await this.refreshSessions();
    } catch (e) {
      this.toast("error", `detach не удался: ${(e as Error).message}`);
    }
  }

  async hookctl(value: "pause" | "resume"): Promise<void> {
    if (this.state.mode === "demo") {
      if (this.state.status) this.state.status.hooks = value === "pause" ? "paused" : "on";
      this.toast("info", value === "pause" ? "хуки сняты (демо)" : "хуки возвращены (демо)");
      this.emit();
      return;
    }
    try {
      await api.hookctl(value);
      if (this.state.status) this.state.status.hooks = value === "pause" ? "paused" : "on";
      this.toast(value === "pause" ? "warn" : "ok", value === "pause" ? "хуки сняты: повторите операцию" : "хуки возвращены");
      this.emit();
    } catch (e) {
      this.toast("error", `hookctl: ${(e as Error).message}`);
    }
  }

  /* ───────────────────────────── шаги ────────────────────────────────── */

  private defaultTitle(): string {
    const n = (this.state.steps.length || 0) + 1;
    const last = this.state.steps[this.state.steps.length - 1]?.title;
    return last ? last : `шаг ${n}`;
  }

  async startStep(title?: string): Promise<void> {
    const s = this.state;
    if (!s.active) {
      this.toast("warn", "нет активной сессии — сначала подключитесь к программе");
      return;
    }
    const name = (title ?? "").trim() || this.defaultTitle();
    if (s.mode === "demo") {
      const idx = (s.steps[s.steps.length - 1]?.idx ?? 0) + 1;
      const ev: Event = {
        seq: ++s.lastSeq,
        t: 0,
        wall: new Date().toISOString(),
        kind: "step_start",
        transport: "none",
        api: "STEP",
        len: 0,
        hex: "",
        text: name,
        step: idx,
        raw: "",
        meta: null,
      };
      s.events = [...s.events, ev];
      s.currentStep = { action: "start", idx, title: name, t: 0, wall: ev.wall };
      s.stepStartEpoch = Date.now();
      sound.stepStart();
      this.toast("ok", `шаг ${idx} открыт: ${name}`);
      this.emit();
      return;
    }
    try {
      const st = await api.stepStart(s.active.id, name);
      s.currentStep = st;
      s.stepStartEpoch = Date.now();
      sound.stepStart();
      this.toast("ok", `шаг ${st.idx} открыт: ${name}`);
      this.emit();
    } catch (e) {
      this.toast("error", `шаг не открылся: ${(e as Error).message}`);
    }
  }

  async endStep(): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    if (!s.currentStep) {
      this.toast("warn", "нет открытого шага");
      return;
    }
    if (s.mode === "demo") {
      const cur = s.currentStep;
      const summary: StepSummary = {
        idx: cur.idx,
        title: cur.title,
        dur: (Date.now() - s.stepStartEpoch) / 1000,
        exchanges: 0,
        tx_bytes: 0,
        rx_bytes: 0,
        cmd_hist: {},
        resp_hist: {},
        reads: [],
        filehash: [],
        png: null,
        winkfp_jobs: [],
        verdict: { denied: 0, no_answer: 0, echo: false, unparsed: 0 },
        started_at: cur.wall,
        ended_at: new Date().toISOString(),
      };
      s.steps = [...s.steps.filter((x) => x.idx !== cur.idx), summary];
      s.events = [
        ...s.events,
        {
          seq: ++s.lastSeq,
          t: 0,
          wall: summary.ended_at,
          kind: "step_end",
          transport: "none",
          api: "STEP",
          len: 0,
          hex: "",
          text: `${cur.title} · ${summary.dur.toFixed(1)} с`,
          step: cur.idx,
          raw: "",
          meta: null,
        },
      ];
      s.currentStep = null;
      s.stepStartEpoch = 0;
      sound.stepEnd();
      this.toast("ok", `шаг ${cur.idx} закрыт`);
      this.emit();
      return;
    }
    try {
      const summary = await api.stepEnd(s.active.id);
      s.steps = [...s.steps.filter((x) => x.idx !== summary.idx), summary];
      s.currentStep = null;
      s.stepStartEpoch = 0;
      sound.stepEnd();
      this.toast("ok", `шаг ${summary.idx} закрыт: ${summary.exchanges} обменов`);
      this.emit();
    } catch (e) {
      this.toast("error", `шаг не закрылся: ${(e as Error).message}`);
    }
  }

  async mark(title: string): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    const text = title.trim();
    if (!text) return;
    if (s.mode === "demo") {
      s.events = [
        ...s.events,
        {
          seq: ++s.lastSeq,
          t: 0,
          wall: new Date().toISOString(),
          kind: "mark",
          transport: "none",
          api: "MARK",
          len: 0,
          hex: "",
          text,
          step: s.currentStep?.idx ?? null,
          raw: "",
          meta: null,
        },
      ];
      this.toast("ok", `метка: ${text}`);
      this.emit();
      return;
    }
    try {
      await api.mark(s.active.id, text);
      this.toast("ok", `метка: ${text}`);
    } catch (e) {
      this.toast("error", `метка не записалась: ${(e as Error).message}`);
    }
  }

  async addNote(text: string): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    const t = text.trim();
    if (!t) return;
    if (s.mode === "demo") {
      s.notes = [...s.notes, { t: 0, wall: new Date().toISOString(), text: t, author: "user" }];
      this.emit();
      return;
    }
    try {
      await api.note(s.active.id, t);
      s.notes = [...s.notes, { t: 0, wall: new Date().toISOString(), text: t, author: "user" }];
      this.toast("ok", "заметка сохранена");
      this.emit();
    } catch (e) {
      this.toast("error", `заметка не сохранилась: ${(e as Error).message}`);
    }
  }

  async shot(): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    if (s.mode === "demo") {
      this.toast("info", "демо-режим: скриншот недоступен");
      return;
    }
    try {
      const r = await api.shot(s.active.id);
      this.toast("ok", `скриншот: ${r.path}`);
    } catch (e) {
      this.toast("error", `скриншот не снят: ${(e as Error).message}`);
    }
  }

  saveQuickTitles(titles: string[]): void {
    const clean = titles.map((t) => t.trim()).filter(Boolean).slice(0, 8);
    this.state.quickTitles = clean.length ? clean : [...DEFAULT_TITLES];
    try {
      localStorage.setItem("ftdi.quickTitles", JSON.stringify(this.state.quickTitles));
    } catch {
      /* ignore */
    }
    this.emit();
  }

  /* ───────────────────────────── экспорт ─────────────────────────────── */

  async exportSession(format: "zip" | "jsonl" | "csv" | "md"): Promise<string | null> {
    const s = this.state;
    if (!s.active) return null;
    if (s.mode === "demo") {
      this.toast("info", "демо-режим: экспорт недоступен");
      return null;
    }
    try {
      const r = await api.exportSession(s.active.id, format);
      this.toast("ok", `готово: ${r.path}`);
      return r.path;
    } catch (e) {
      this.toast("error", `экспорт не удался: ${(e as Error).message}`);
      return null;
    }
  }

  async share(url: string): Promise<void> {
    const s = this.state;
    if (!s.active || !url.trim()) return;
    try {
      await api.share(s.active.id, url.trim());
      this.toast("ok", "лог отправлен на сервер");
    } catch (e) {
      this.toast("error", `отправка не удалась: ${(e as Error).message}`);
    }
  }

  async importLog(): Promise<void> {
    this.pickFile();
  }

  pickFile(): void {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".log,.txt,.out,.jsonl";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (file) await this.importUpload(file);
    };
    input.click();
  }

  /** Импорт файла, выбранного или перетащенного в окно (путь браузер не отдаёт). */
  async importUpload(file: File): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", "демо-режим: импорт недоступен");
      return;
    }
    try {
      this.toast("info", `импортирую ${file.name}…`);
      const bytes = await file.arrayBuffer();
      const r = await api.importUpload(file.name, bytes);
      this.toast("ok", "лог импортирован, переразбор готов");
      await this.refreshSessions();
      await this.selectSession(r.session_id);
    } catch (e) {
      this.toast("error", `импорт не удался: ${(e as Error).message}`);
    }
  }
}

export const store = new Store();






