/** REST-клиент и WebSocket-подписка на живой поток. */

import type {
  CaptureStatus,
  EventsPage,
  FtdiDevice,
  Health,
  PayloadDecode,
  ProcessDetail,
  UsbDevice,
  J2534Driver,
  ServerMsg,
  SessionCounts,
  SessionDetail,
  SessionMeta,
  StepEvent,
  StepSummary,
  ToolProcess,
} from "./types";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.status = status;
  }
}

const ENGINE_OVERRIDE = (() => {
  try {
    const p = new URLSearchParams(location.search).get("engine");
    return p ? p.replace(/\/$/, "") : "";
  } catch {
    return "";
  }
})();

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(ENGINE_OVERRIDE + path, {
      headers: { "content-type": "application/json" },
      ...init,
    });
  } catch (e) {
    throw new ApiError(`движок недоступен: ${(e as Error).message}`);
  }
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    // HTML-страницы (404 от чужого сервера) в сообщение не тащим: только статус.
    const asText = typeof body === "string" && body && !body.trimStart().startsWith("<") ? body : "";
    const msg =
      body && typeof body === "object" && "error" in body
        ? String((body as { error: unknown }).error)
        : asText || `HTTP ${res.status}`;
    throw new ApiError(msg, res.status);
  }
  return body as T;
}

const json = (payload: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(payload) });

export const api = {
  health: () => req<Health>("/api/health"),

  sessions: () => req<SessionMeta[]>("/api/sessions"),
  session: (id: string) => req<SessionDetail>(`/api/sessions/${encodeURIComponent(id)}`),
  events: (
    id: string,
    opts: { from?: number; to?: number; limit?: number; kinds?: string[]; q?: string } = {},
  ) => {
    const q = new URLSearchParams();
    if (opts.from != null) q.set("from", String(opts.from));
    if (opts.to != null) q.set("to", String(opts.to));
    q.set("limit", String(opts.limit ?? 1000));
    if (opts.kinds?.length) q.set("kinds", opts.kinds.join(","));
    if (opts.q) q.set("q", opts.q);
    return req<EventsPage>(`/api/sessions/${encodeURIComponent(id)}/events?${q}`);
  },
  stepSummary: (id: string, idx: number) =>
    req<StepSummary>(`/api/sessions/${encodeURIComponent(id)}/steps/${idx}`),
  /** Отчёт отдаётся как text/plain (txt) или text/markdown (?format=md). */
  report: async (id: string, format: "txt" | "md" = "txt"): Promise<string> => {
    const res = await fetch(
      ENGINE_OVERRIDE + `/api/sessions/${encodeURIComponent(id)}/report?format=${format}`,
    );
    if (!res.ok) throw new ApiError(`отчёт: HTTP ${res.status}`, res.status);
    return res.text();
  },
  decode: (id: string, seq: number) =>
    req<PayloadDecode>(`/api/sessions/${encodeURIComponent(id)}/events/${seq}/decode`),

  devices: () => req<FtdiDevice[]>("/api/devices"),
  tools: (mode: "auto" | "usb" | "window" | "all" = "auto") =>
    req<ToolProcess[]>(`/api/tools?mode=${mode}`),
  usbDevices: () => req<UsbDevice[]>("/api/usb/devices"),
  usbpcapDevices: () => req<string[]>("/api/usbpcap/devices"),
  startUsbpcap: (device: string) => req<SessionMeta>("/api/usbpcap/start", json({ device })),
  j2534Drivers: () => req<J2534Driver[]>("/api/j2534/drivers"),
  toolDetail: (pid: number) => req<ProcessDetail>(`/api/tools/${pid}/detail`),

  attach: (pid: number, label?: string, adapter?: string) =>
    req<SessionMeta>("/api/capture/attach", json({ pid, label, adapter })),
  detach: () => req<SessionMeta | null>("/api/capture/detach", json({})),
  hookctl: (value: "pause" | "resume") => req<{ hooks?: string }>("/api/capture/hookctl", json({ value })),
  captureStatus: () => req<CaptureStatus>("/api/capture/status"),

  stepStart: (id: string, title: string) =>
    req<StepEvent>(`/api/sessions/${encodeURIComponent(id)}/step/start`, json({ title })),
  stepEnd: (id: string) =>
    req<StepSummary>(`/api/sessions/${encodeURIComponent(id)}/step/end`, json({})),
  mark: (id: string, title: string) =>
    req<{ seq: number }>(`/api/sessions/${encodeURIComponent(id)}/mark`, json({ title })),
  note: (id: string, text: string) =>
    req<{ ok: boolean }>(`/api/sessions/${encodeURIComponent(id)}/note`, json({ text })),
  shot: (id: string) =>
    req<{ path: string }>(`/api/sessions/${encodeURIComponent(id)}/shot`, json({})),

  reparse: (id: string) => req<{ ok: boolean }>(`/api/sessions/${encodeURIComponent(id)}/reparse`, json({})),
  exportSession: (id: string, format: "zip" | "jsonl" | "csv" | "md") =>
    req<{ path: string }>(`/api/sessions/${encodeURIComponent(id)}/export`, json({ format })),
  share: (id: string, url: string) =>
    req<{ ok: boolean; status?: string }>(`/api/sessions/${encodeURIComponent(id)}/share`, json({ url })),
  importLog: (path: string) => req<{ session_id: string }>("/api/import", json({ path })),
  /** Импорт через загрузку байтов: браузер не отдаёт путь файла. */
  importUpload: async (name: string, bytes: ArrayBuffer) => {
    let res: Response;
    try {
      res = await fetch(ENGINE_OVERRIDE + `/api/import/upload?name=${encodeURIComponent(name)}`, {
        method: "POST",
        headers: { "content-type": "application/octet-stream" },
        body: bytes,
      });
    } catch (e) {
      throw new ApiError(`движок недоступен: ${(e as Error).message}`);
    }
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try {
        const body = (await res.json()) as { error?: string };
        if (body?.error) msg = body.error;
      } catch {
        /* ignore */
      }
      throw new ApiError(msg, res.status);
    }
    return (await res.json()) as { session_id: string };
  },
  deleteSession: (id: string) =>
    req<{ ok: boolean }>(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }),
};

/* ───────────────────────────── WebSocket ───────────────────────────────── */

export type WsState = "connecting" | "open" | "closed";

export class WsClient {
  private ws: WebSocket | null = null;
  private closedByUser = false;
  private retry = 0;
  private session: string | null = null;
  private since = 0;
  private timer: number | null = null;
  private pingTimer: number | null = null;

  onMessage: (msg: ServerMsg) => void = () => {};
  onState: (state: WsState) => void = () => {};

  constructor() {
    this.connect();
  }

  private url(): string {
    const base = ENGINE_OVERRIDE || location.origin;
    const u = new URL(base);
    u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
    u.pathname = "/ws";
    return u.toString();
  }

  private connect(): void {
    if (this.closedByUser) return;
    this.onState("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(this.url());
    } catch {
      this.scheduleRetry();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      this.retry = 0;
      this.onState("open");
      this.send({ op: "subscribe", session: this.session, since: this.since });
      if (this.pingTimer != null) window.clearInterval(this.pingTimer);
      this.pingTimer = window.setInterval(() => {
        if (this.ws?.readyState === WebSocket.OPEN) this.send({ op: "ping" });
      }, 20_000);
    };
    ws.onmessage = (e) => {
      let msg: ServerMsg;
      try {
        msg = JSON.parse(String(e.data)) as ServerMsg;
      } catch {
        return;
      }
      if (msg && typeof msg === "object" && "type" in msg) this.onMessage(msg);
    };
    ws.onclose = () => {
      this.onState("closed");
      if (this.pingTimer != null) {
        window.clearInterval(this.pingTimer);
        this.pingTimer = null;
      }
      if (!this.closedByUser) this.scheduleRetry();
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }

  private scheduleRetry(): void {
    if (this.timer != null) window.clearTimeout(this.timer);
    const delay = Math.min(5000, 400 * 2 ** Math.min(this.retry, 4));
    this.retry += 1;
    this.timer = window.setTimeout(() => this.connect(), delay);
  }

  send(msg: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  subscribe(session: string | null, since: number): void {
    this.session = session;
    this.since = since;
    this.send({ op: "subscribe", session, since });
  }

  close(): void {
    this.closedByUser = true;
    this.ws?.close();
    if (this.timer != null) window.clearTimeout(this.timer);
  }
}

export function isDemoMode(): boolean {
  return new URLSearchParams(location.search).has("demo");
}

export function engineBase(): string {
  return ENGINE_OVERRIDE;
}

export function sessionFileUrl(id: string, rel: string): string {
  return `/api/sessions/${encodeURIComponent(id)}/file/${rel
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
}

export type { SessionCounts, StepSummary, StepEvent };




