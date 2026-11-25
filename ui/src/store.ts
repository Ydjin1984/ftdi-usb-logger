/** Состояние приложения и действия. Компоненты читают state и вызывают методы. */

import { api, ApiError, isDemoMode, WsClient } from "./api";
import { errText, msg, t } from "./i18n";
import { demoCounts, demoEvents, demoJ2534Drivers, demoSession, demoSteps, demoUsbDevices } from "./demo";
import { sound } from "./sound";
import type {
  CaptureStatus,
  Event,
  EventKind,
  FtdiDevice,
  Health,
  Note,
  OperationsDoc,
  ScopeAnalysis,
  SessionCounts,
  SessionMeta,
  StepEvent,
  StepSummary,
  ToolProcess,
  UsbDevice,
  J2534Driver,
  ProxyStatus,
  ScopeConfig,
  ScopeStatus,
  ExportJobStatus,
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
  connectionLost: boolean;
  needsReload: boolean;
  wsState: "connecting" | "open" | "closed";

  health: Health | null;
  status: CaptureStatus | null;
  sessions: SessionMeta[];
  active: SessionMeta | null;
  steps: StepSummary[];
  notes: Note[];
  /** Операции сессии: клик → вызовы → сигналы → итог (docs/16). */
  operations: OperationsDoc | null;
  /** Выжимка по сигналам стенда: события PWM/питания и покрытие. */
  scopeAnalysis: ScopeAnalysis | null;

  events: Event[];
  firstSeq: number;
  lastSeq: number;
  total: number;
  hasMoreBefore: boolean;

  devices: FtdiDevice[];
  tools: ToolProcess[];
  usbDevices: UsbDevice[];
  j2534Drivers: J2534Driver[];
  /** Состояние J2534-прокси: индикатор «подхвачен» в шапке (docs/13 §6.1). */
  proxy: ProxyStatus | null;
  /**
   * Осциллограф: живое состояние сервиса на 127.0.0.1:7411.
   * `scopeSupported === false` — движок старой версии (404), интеграции нет.
   */
  scope: ScopeStatus | null;
  scopeSupported: boolean | null;
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
  // События осциллографа и нажатий кнопок видны по умолчанию, как и остальные.
  "scope",
  "ui_action",
];

msg({
  "импорт готов: сессия открыта": "import done: session opened",
  "событие seq {seq} не найдено": "event seq {seq} not found",
  "не открыть событие: {msg}": "cannot open event: {msg}",
  "Идентификация": "Identification",
  "Чтение калибровок": "Read calibrations",
  "Чтение фулл флеш": "Read full flash",
  "Запись калибровок": "Write calibrations",
  "Запись фулл флеш": "Write full flash",
  "Сброс ошибок": "Clear fault codes",
  "Сброс адаптаций": "Reset adaptations",
  "Верификация": "Verification",
  "запись тюна": "tune write",
  "осциллограф включён": "oscilloscope enabled",
  "осциллограф выключен": "oscilloscope disabled",
  "настройки осциллографа сохранены": "oscilloscope settings saved",
  "демо-режим: осциллограф недоступен": "demo mode: the oscilloscope is unavailable",
  "движок не поддерживает осциллограф": "the engine does not support the oscilloscope",
  "осциллограф: {msg}": "oscilloscope: {msg}",
  "нажатие (клик)": "press (click)",
  "нажатие (Invoke)": "press (Invoke)",
  "фокус (не подтверждено)": "focus (not confirmed)",
});

/**
 * Пресеты действий по умолчанию — канонические русские ключи.
 *
 * Храним именно ключи (а не перевод): список пресетов лежит в localStorage и
 * переживает смену языка. Переводятся они только при показе, иначе список,
 * сохранённый на русском, оставался бы русским в английском интерфейсе.
 */
function defaultTitles(): string[] {
  return [
    "Идентификация",
    "Чтение калибровок",
    "Чтение фулл флеш",
    "Запись калибровок",
    "Запись фулл флеш",
    "Сброс ошибок",
    "Сброс адаптаций",
    "Верификация",
  ];
}

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
  return defaultTitles();
}

function emptyCounts(): SessionCounts {
  return { events: 0, tx: 0, rx: 0, tx_bytes: 0, rx_bytes: 0, steps: 0, files: 0, errors: 0 };
}

/** Поля meta одной строкой для поиска: `ключ=значение`, без JSON.stringify. */
function metaText(ev: Event): string {
  const meta = ev.meta as Record<string, unknown> | null | undefined;
  if (!meta || typeof meta !== "object") return "";
  let out = "";
  for (const key of Object.keys(meta)) {
    const value = meta[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out += key + "=" + String(value) + " ";
    }
  }
  return out.toLowerCase();
}
class Store {
  state: StoreState;
  private listeners = new Set<() => void>();
  private ws: WsClient | null = null;
  private toastSeq = 0;
  private pollTimer: number | null = null;
  private healthFails = 0;
  private tickTimer: number | null = null;
  /** Осциллограф: опрос статуса (2 с, только при видимой вкладке). */
  private scopeTimer: number | null = null;
  private scopeInFlight = false;
  private scopeVisibilityBound = false;
  /** Кэш хронологического порядка: `src` — массив событий, `out` — тот же или отсортированный. */
  private orderCache: { src: Event[]; out: Event[] } | null = null;

  constructor() {
    const demo = isDemoMode();
    this.state = {
      mode: demo ? "demo" : "live",
      booted: false,
      bootError: null,
      connectionLost: false,
      needsReload: false,
      wsState: "connecting",
      health: null,
      status: null,
      sessions: [],
      active: null,
      steps: [],
      notes: [],
      operations: null,
      scopeAnalysis: null,
      events: [],
      firstSeq: 0,
      lastSeq: 0,
      total: 0,
      hasMoreBefore: false,
      devices: [],
      tools: [],
      usbDevices: [],
      j2534Drivers: [],
      proxy: null,
      scope: null,
      scopeSupported: null,
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
      // Осциллограф: первый статус — сразу, дальше — опрос раз в 2 с.
      void this.refreshScope();
      this.startScopePolling();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : errText(e);
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
    this.state.currentStep = { action: "start", idx: 3, title: t("запись тюна"), t: 108, wall: session.started_at };
    this.state.stepStartEpoch = Date.now() - 132_000;
    this.startTicking();
    this.emit();
    this.toast("info", t("демо-режим: данные синтетические, устройство не требуется"));
  }

  /** Только устройства (USB/COM/J2534) — дешёвый опрос, работает и во время записи. */
  async refreshDevices(): Promise<void> {
    if (this.state.mode === "demo") return;
    const [devices, usb, j2534] = await Promise.allSettled([api.devices(), api.usbDevices(), api.j2534Drivers()]);
    if (devices.status === "fulfilled") this.state.devices = devices.value;
    if (usb.status === "fulfilled") this.state.usbDevices = usb.value;
    if (j2534.status === "fulfilled") this.state.j2534Drivers = j2534.value;
    this.emit();
  }

  /** Состояние J2534-прокси — для индикатора в шапке (docs/13 §6.1). */
  async refreshProxy(): Promise<void> {
    if (this.state.mode === "demo") return;
    try {
      this.state.proxy = await api.j2534ProxyStatus();
      this.emit();
    } catch {
      /* движок не ответил: прежнее состояние не затираем, чтобы индикатор не мигал */
    }
  }

  /* ───────────────────────────── осциллограф ─────────────────────────── */

  /**
   * Прочитать живое состояние осциллографа.
   *
   * Ошибка не показывает тост: опрос идёт каждые 2 с, иначе уведомления
   * перекрывали бы работу. 404 — движок старой сборки: интеграции нет,
   * пилюля не рисуется, опрос останавливаем, чтобы не долбить сервер.
   */
  async refreshScope(): Promise<void> {
    if (this.state.mode === "demo") return;
    if (this.state.scopeSupported === false) return;
    if (this.scopeInFlight) return;
    this.scopeInFlight = true;
    try {
      this.state.scope = await api.scopeStatus();
      this.state.scopeSupported = true;
      this.emit();
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        this.state.scope = null;
        this.state.scopeSupported = false;
        this.stopScopePolling();
        this.emit();
      }
      // Прочие ошибки (движок перезапускается) — молча: прежнее состояние не
      // затираем, следующий опрос попробует снова.
    } finally {
      this.scopeInFlight = false;
    }
  }

  /** Включить/выключить осциллограф. Ответ сервера — источник правды. */
  async setScopeEnabled(enabled: boolean): Promise<boolean> {
    const ok = await this.postScopeConfig({ enabled });
    if (ok) this.toast("ok", enabled ? t("осциллограф включён") : t("осциллограф выключен"));
    return ok;
  }

  /** Сохранить адрес и параметры из диалога. */
  async saveScopeConfig(patch: Partial<ScopeConfig>): Promise<boolean> {
    const ok = await this.postScopeConfig(patch);
    if (ok) this.toast("ok", t("настройки осциллографа сохранены"));
    return ok;
  }

  private async postScopeConfig(patch: Partial<ScopeConfig>): Promise<boolean> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: осциллограф недоступен"));
      return false;
    }
    try {
      const res = await api.scopeSetConfig(patch);
      // Частичный ответ не затирает прочитанное: обновляем только пришедшее.
      if (res.config && this.state.scope) this.state.scope = { ...this.state.scope, ...res.config };
      this.state.scopeSupported = true;
      this.emit();
      await this.refreshScope();
      return res.ok !== false;
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        this.state.scope = null;
        this.state.scopeSupported = false;
        this.stopScopePolling();
        this.emit();
        this.toast("error", t("движок не поддерживает осциллограф"));
      } else {
        this.toast("error", t("осциллограф: {msg}", { msg: errText(e) }));
      }
      // Перечитываем состояние, чтобы переключатель не врал.
      await this.refreshScope();
      return false;
    }
  }

  /**
   * Опрос статуса раз в 2 с. Скрытая вкладка не опрашивается (без пользы
   * грузит движок и сервис), а при возврате статус читается сразу.
   */
  private startScopePolling(): void {
    if (this.scopeTimer != null) window.clearInterval(this.scopeTimer);
    if (!this.scopeVisibilityBound) {
      this.scopeVisibilityBound = true;
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") void this.refreshScope();
      });
    }
    this.scopeTimer = window.setInterval(() => {
      if (document.visibilityState === "visible") void this.refreshScope();
    }, 2000);
  }

  private stopScopePolling(): void {
    if (this.scopeTimer != null) {
      window.clearInterval(this.scopeTimer);
      this.scopeTimer = null;
    }
  }

  private startPolling(): void {
    if (this.pollTimer != null) window.clearInterval(this.pollTimer);
    let idleTicks = 0;
    this.pollTimer = window.setInterval(() => {
      void api
        .health()
        .then((h) => {
          this.healthFails = 0;
          if (this.state.connectionLost) {
            // Движок вернулся (например, перезапущен ярлыком) — перезагружаем страницу,
            // чтобы синхронизировать сессии/статус и убрать слой «нет связи».
            this.state.connectionLost = false;
            this.state.needsReload = true;
          }
          this.state.health = h;
          this.state.status = h.capture ?? this.state.status;
          this.emit();
          // Прокси — каждый опрос: индикатор «подхвачен» должен меняться сам,
          // когда программу запустили или закрыли, без перезагрузки страницы.
          void this.refreshProxy();
          // Устройства обновляем всегда (шнурок могли заменить во время записи),
          // процессы — только когда захват не идёт.
          idleTicks += 1;
          if (idleTicks % 3 === 0 && !this.state.loadingTargets) {
            void this.refreshDevices();
            if (!h.capture?.recording) void this.refreshTargets();
          }
        })
        .catch(() => {
          this.state.wsState = "closed";
          // Движок остановлен/перезапускается: после 3 подряд неудач показываем
          // блокирующий слой «нет связи» (иначе UI навсегда показывает старый REC).
          this.healthFails += 1;
          if (this.healthFails >= 3 && !this.state.connectionLost) {
            this.state.connectionLost = true;
            this.state.status = null;
          }
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
          this.toast("ok", t("шаг {n} закрыт: {exchanges} обменов, {dur} с", { n: summary.idx, exchanges: summary.exchanges, dur: summary.dur.toFixed(1) }));
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
      this.toast("warn", t("не удалось обновить список сессий: {msg}", { msg: errText(e) }));
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
      this.state.operations = null;
      this.state.scopeAnalysis = null;
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
      // Операции для старой сессии считаются на первом запросе (до ~15 с на
      // 129 МБ кадров): не блокируем открытие, панель появится, когда готово.
      void api
        .operations(id)
        .then((ops) => {
          if (this.state.active?.id !== id) return;
          this.state.operations = ops.operations;
          this.state.scopeAnalysis = ops.scope;
          this.emit();
        })
        .catch(() => {
          /* панель просто не появится; отчёт и лента уже открыты */
        });
    } catch (e) {
      this.toast("error", t("сессия не открылась: {msg}", { msg: errText(e) }));
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
      this.toast("warn", t("не удалось догрузить историю: {msg}", { msg: errText(e) }));
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

  /** Текст meta для поиска: `ключ=значение` парами, без JSON.stringify. */
  private static metaText(ev: Event): string {
    const meta = ev.meta as Record<string, unknown> | null | undefined;
    if (!meta || typeof meta !== "object") return "";
    let out = "";
    for (const key of Object.keys(meta)) {
      const value = meta[key];
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        out += key + "=" + String(value) + " ";
      }
    }
    return out.toLowerCase();
  }

  /**
   * События в порядке времени, а не прихода.
   *
   * `seq` — порядок поступления: мост шлёт пачки, и поздняя пачка может нести
   * события более раннего `t` (буферизация Frida/прокси). Показывать их в
   * порядке `seq` — значит рисовать таймлайн, где время идёт назад; поэтому
   * список сортируется по `(t, seq)`, а `seq` остаётся идентификатором записи.
   * Сортировка кэшируется по ссылке массива: пересчёт — один раз на батч.
   */
  private orderedEvents(): Event[] {
    const src = this.state.events;
    if (this.orderCache && this.orderCache.src === src) return this.orderCache.out;
    let out = src;
    for (let i = 1; i < src.length; i++) {
      if (src[i].t < src[i - 1].t) {
        out = [...src].sort((a, b) => a.t - b.t || a.seq - b.seq);
        break;
      }
    }
    this.orderCache = { src, out };
    return out;
  }

  visibleEvents(): Event[] {
    const { filters, query } = this.state;
    const events = this.orderedEvents();
    const q = query.trim().toLowerCase();
    if (q) {
      return events.filter(
        (e) =>
          filters.has(e.kind) &&
          ((e.hex || "").includes(q) ||
            (e.api || "").toLowerCase().includes(q) ||
            (e.text || "").toLowerCase().includes(q) ||
            (e.raw || "").toLowerCase().includes(q) ||
            // В events.jsonl поле raw больше не дублируется (docs/12 §10):
            // искать нужно и по разобранным полям, иначе ключи вроде
            // `channel=1` или `timeout_ms=500` перестанут находиться.
            metaText(e).includes(q)),
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
      this.toast("warn", t("список программ: {msg}", { msg: errText(e) }));
    }
  }

  /** Прицепиться к PID вручную — универсальный путь, если драйвер не виден. */
  async attachPid(pid: number, label?: string): Promise<void> {
    if (!Number.isFinite(pid) || pid <= 0) {
      this.toast("warn", t("нужен корректный PID"));
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
      this.toast("warn", t("не удалось обновить устройства: {msg}", { msg: errText(e) }));
    } finally {
      this.state.loadingTargets = false;
      this.emit();
    }
  }

  /** Сырой захват USB-шины через USBPcap (нужен драйвер + права администратора). */
  async startUsbpcap(device: string): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: USBPcap недоступен"));
      return;
    }
    try {
      const meta = await api.startUsbpcap(device);
      this.state.active = meta;
      this.state.sessions = [meta, ...this.state.sessions.filter((s) => s.id !== meta.id)];
      this.state.events = [];
      this.state.steps = [];
      this.state.operations = null;
      this.state.scopeAnalysis = null;
      this.state.firstSeq = 0;
      this.state.lastSeq = 0;
      this.state.total = 0;
      this.state.currentStep = null;
      this.ws?.subscribe(meta.id, 0);
      this.toast("ok", t("сырой USB-захват: {device}", { device }));
      this.emit();
    } catch (e) {
      this.toast("error", t("USBPcap не запустился: {msg}", { msg: errText(e) }));
    }
  }

  /** «Новая сессия»: остановить текущую (если идёт), пересканировать всё окружение. */
  async newSession(): Promise<import("./types").NewSessionResult | null> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: новая сессия недоступна"));
      return null;
    }
    try {
      const res = await api.newSession();
      this.state.devices = res.devices ?? [];
      this.state.tools = res.tools ?? [];
      this.state.usbDevices = res.usb_devices ?? [];
      this.state.j2534Drivers = res.j2534_drivers ?? [];
      if (res.capabilities && this.state.health) this.state.health.capabilities = res.capabilities;
      if (res.stopped) {
        const st = res.stopped;
        this.state.sessions = this.state.sessions.map((s) => (s.id === st.id ? st : s));
        this.toast("ok", t("сессия {id} завершена", { id: st.id }));
      }
      this.state.active = null;
      this.state.events = [];
      this.state.steps = [];
      this.state.notes = [];
      this.state.operations = null;
      this.state.scopeAnalysis = null;
      this.state.selection = null;
      this.state.currentStep = null;
      this.state.stepStartEpoch = 0;
      this.state.firstSeq = 0;
      this.state.lastSeq = 0;
      this.state.total = 0;
      this.state.pendingNew = 0;
      this.ws?.subscribe(null, 0);
      await this.refreshSessions();
      this.emit();
      return res;
    } catch (e) {
      this.toast("error", t("новая сессия: {msg}", { msg: errText(e) }));
      return null;
    }
  }

  async attach(pid: number, label?: string, adapter?: string): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: attach недоступен"));
      return;
    }
    try {
      const meta = await api.attach(pid, label, adapter);
      this.state.active = meta;
      this.state.sessions = [meta, ...this.state.sessions.filter((s) => s.id !== meta.id)];
      this.state.events = [];
      this.state.steps = [];
      this.state.operations = null;
      this.state.scopeAnalysis = null;
      this.state.firstSeq = 0;
      this.state.lastSeq = 0;
      this.state.total = 0;
      this.state.currentStep = null;
      this.ws?.subscribe(meta.id, 0);
      this.toast("ok", t("захват запущен: {label}", { label: meta.label }));
      this.emit();
    } catch (e) {
      this.toast("error", t("attach не удался: {msg}", { msg: errText(e) }));
    }
  }

  async detach(): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: detach недоступен"));
      return;
    }
    try {
      const meta = await api.detach();
      if (meta) {
        this.state.sessions = this.state.sessions.map((s) => (s.id === meta.id ? meta : s));
        if (this.state.active?.id === meta.id) this.state.active = meta;
      }
      this.state.currentStep = null;
      this.toast("ok", t("сессия остановлена, отчёт собран"));
      await this.refreshSessions();
    } catch (e) {
      this.toast("error", t("detach не удался: {msg}", { msg: errText(e) }));
    }
  }

  async hookctl(value: "pause" | "resume"): Promise<void> {
    if (this.state.mode === "demo") {
      if (this.state.status) this.state.status.hooks = value === "pause" ? "paused" : "on";
      this.toast("info", value === "pause" ? t("хуки сняты (демо)") : t("хуки возвращены (демо)"));
      this.emit();
      return;
    }
    try {
      await api.hookctl(value);
      if (this.state.status) this.state.status.hooks = value === "pause" ? "paused" : "on";
      this.toast(value === "pause" ? "warn" : "ok", value === "pause" ? t("хуки сняты: повторите операцию") : t("хуки возвращены"));
      this.emit();
    } catch (e) {
      this.toast("error", t("hookctl: {msg}", { msg: errText(e) }));
    }
  }

  /* ───────────────────────────── шаги ────────────────────────────────── */

  private defaultTitle(): string {
    const n = (this.state.steps.length || 0) + 1;
    const last = this.state.steps[this.state.steps.length - 1]?.title;
    return last ? last : t("шаг {n}", { n });
  }

  async startStep(title?: string): Promise<void> {
    const s = this.state;
    if (!s.active) {
      this.toast("warn", t("нет активной сессии — сначала подключитесь к программе"));
      return;
    }
    const raw = (title ?? "").trim();
    // Пресеты хранятся каноническими русскими ключами (переживают смену языка),
    // а в журнал шаг пишется уже на текущем языке интерфейса.
    const name = raw ? t(raw) : this.defaultTitle();
    if (raw) this.addQuickTitle(raw);
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
      this.toast("ok", t("шаг {n} открыт: {title}", { n: idx, title: name }));
      this.emit();
      return;
    }
    try {
      const st = await api.stepStart(s.active.id, name);
      s.currentStep = st;
      s.stepStartEpoch = Date.now();
      sound.stepStart();
      this.toast("ok", t("шаг {n} открыт: {title}", { n: st.idx, title: name }));
      this.emit();
    } catch (e) {
      this.toast("error", t("шаг не открылся: {msg}", { msg: errText(e) }));
    }
  }

  async endStep(): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    if (!s.currentStep) {
      this.toast("warn", t("нет открытого шага"));
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
          text: t("{title} · {dur} с", { title: cur.title, dur: summary.dur.toFixed(1) }),
          step: cur.idx,
          raw: "",
          meta: null,
        },
      ];
      s.currentStep = null;
      s.stepStartEpoch = 0;
      sound.stepEnd();
      this.toast("ok", t("шаг {n} закрыт", { n: cur.idx }));
      this.emit();
      return;
    }
    try {
      const summary = await api.stepEnd(s.active.id);
      s.steps = [...s.steps.filter((x) => x.idx !== summary.idx), summary];
      s.currentStep = null;
      s.stepStartEpoch = 0;
      sound.stepEnd();
      this.toast("ok", t("шаг {n} закрыт: {exchanges} обменов", { n: summary.idx, exchanges: summary.exchanges }));
      this.emit();
    } catch (e) {
      this.toast("error", t("шаг не закрылся: {msg}", { msg: errText(e) }));
    }
  }

  /// Открыть событие по seq из карточки операции: грузим окно вокруг него,
  /// потому что в потоке лежит только хвост длинной сессии.
  async focusEvent(seq: number): Promise<void> {
    const id = this.state.active?.id;
    if (!id || this.state.mode === "demo") return;
    try {
      const page = await api.context(id, seq, 40);
      const ev = page.events.find((e) => e.seq === seq) ?? null;
      if (!ev) {
        this.toast("warn", t("событие seq {seq} не найдено", { seq }));
        return;
      }
      this.state.selection = ev;
      this.emit();
    } catch (e) {
      this.toast("warn", t("не открыть событие: {msg}", { msg: errText(e) }));
    }
  }

  async mark(title: string): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    const text = title.trim();
    if (!text) return;
    this.addQuickTitle(text);
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
      this.toast("ok", t("метка: {text}", { text }));
      this.emit();
      return;
    }
    try {
      await api.mark(s.active.id, text);
      this.toast("ok", t("метка: {text}", { text }));
    } catch (e) {
      this.toast("error", t("метка не записалась: {msg}", { msg: errText(e) }));
    }
  }

  async addNote(text: string): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    const note = text.trim();
    if (!note) return;
    if (s.mode === "demo") {
      s.notes = [...s.notes, { t: 0, wall: new Date().toISOString(), text: note, author: "user" }];
      this.emit();
      return;
    }
    try {
      await api.note(s.active.id, note);
      s.notes = [...s.notes, { t: 0, wall: new Date().toISOString(), text: note, author: "user" }];
      this.toast("ok", t("заметка сохранена"));
      this.emit();
    } catch (e) {
      this.toast("error", t("заметка не сохранилась: {msg}", { msg: errText(e) }));
    }
  }

  async shot(): Promise<void> {
    const s = this.state;
    if (!s.active) return;
    if (s.mode === "demo") {
      this.toast("info", t("демо-режим: скриншот недоступен"));
      return;
    }
    try {
      const r = await api.shot(s.active.id);
      this.toast("ok", t("скриншот: {path}", { path: r.path }));
    } catch (e) {
      this.toast("error", t("скриншот не снят: {msg}", { msg: errText(e) }));
    }
  }

  saveQuickTitles(titles: string[]): void {
    const seen = new Set<string>();
    const clean: string[] = [];
    for (const raw of titles) {
      const t = raw.trim().replace(/^[-*]\s*/, "");
      if (!t) continue;
      const key = t.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      clean.push(t);
    }
    this.state.quickTitles = clean.length ? clean.slice(0, 40) : defaultTitles();
    try {
      localStorage.setItem("ftdi.quickTitles", JSON.stringify(this.state.quickTitles));
    } catch {
      /* ignore */
    }
    this.emit();
  }

  /** Сохранить название как пресет (если его ещё нет) — вызывается при ручном шаге/метке. */
  addQuickTitle(title: string): void {
    const t = title.trim();
    if (!t) return;
    if (this.state.quickTitles.some((x) => x.toLowerCase() === t.toLowerCase())) return;
    this.saveQuickTitles([...this.state.quickTitles, t]);
  }

  /** Вернуть стандартный набор пресетов. */
  resetQuickTitles(): void {
    this.state.quickTitles = defaultTitles();
    try {
      localStorage.setItem("ftdi.quickTitles", JSON.stringify(this.state.quickTitles));
    } catch {
      /* ignore */
    }
    this.emit();
  }

  /* ───────────────────────────── экспорт ─────────────────────────────── */

  /**
   * Экспорт через фоновое задание: движок отвечает id сразу, а сборка ZIP идёт
   * в отдельном потоке. `onProgress` получает проценты и стадию — из них UI
   * рисует прогресс-бар, вместо неподвижного «собираю…».
   */
  async exportSession(
    format: "zip" | "jsonl" | "csv" | "md",
    onProgress?: (status: ExportJobStatus) => void,
  ): Promise<string | null> {
    const s = this.state;
    if (!s.active) return null;
    if (s.mode === "demo") {
      this.toast("info", t("демо-режим: экспорт недоступен"));
      return null;
    }
    try {
      const { id } = await api.exportStart(s.active.id, format);
      const started = Date.now();
      for (;;) {
        await new Promise((resolve) => window.setTimeout(resolve, 350));
        const status = await api.exportStatus(s.active.id, id);
        onProgress?.(status);
        if (status.state === "done") {
          const path = status.path ?? "";
          this.toast("ok", t("готово: {path}", { path }));
          return path;
        }
        if (status.state === "error") {
          throw new Error(status.error || t("экспорт не удался"));
        }
        // Защита от «вечного» опроса: задание в движке всё равно продолжится.
        if (Date.now() - started > 30 * 60 * 1000) {
          throw new Error(t("таймаут экспорта: 30 минут"));
        }
      }
    } catch (e) {
      this.toast("error", t("экспорт не удался: {msg}", { msg: errText(e) }));
      return null;
    }
  }

  async share(url: string): Promise<void> {
    const s = this.state;
    if (!s.active || !url.trim()) return;
    try {
      await api.share(s.active.id, url.trim());
      this.toast("ok", t("лог отправлен на сервер"));
    } catch (e) {
      this.toast("error", t("отправка не удалась: {msg}", { msg: errText(e) }));
    }
  }

  async importLog(): Promise<void> {
    this.pickFile();
  }

  pickFile(): void {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".log,.txt,.out,.jsonl,.zip";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (file) await this.importUpload(file);
    };
    input.click();
  }

  /** Импорт файла, выбранного или перетащенного в окно (путь браузер не отдаёт). */
  async importUpload(file: File): Promise<void> {
    if (this.state.mode === "demo") {
      this.toast("info", t("демо-режим: импорт недоступен"));
      return;
    }
    try {
      this.toast("info", t("импортирую {name}…", { name: file.name }));
      const bytes = await file.arrayBuffer();
      const r = await api.importUpload(file.name, bytes);
      this.toast("ok", t("импорт готов: сессия открыта"));
      await this.refreshSessions();
      await this.selectSession(r.session_id);
    } catch (e) {
      this.toast("error", t("импорт не удался: {msg}", { msg: errText(e) }));
    }
  }
}

export const store = new Store();










