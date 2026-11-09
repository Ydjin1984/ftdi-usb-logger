/** Форматирование значений для ленты и инспектора. */

export function fmtTime(t: number): string {
  const sign = t < 0 ? "-" : "+";
  const v = Math.abs(t);
  if (v < 60) return `${sign}${v.toFixed(3)}s`;
  const m = Math.floor(v / 60);
  const s = v - m * 60;
  return `${sign}${m}:${s.toFixed(2).padStart(5, "0")}`;
}

export function fmtDurationSeconds(s: number): string {
  if (!isFinite(s) || s < 0) return "—";
  if (s < 60) return `${s.toFixed(s < 10 ? 2 : 1)} с`;
  const m = Math.floor(s / 60);
  const rest = s - m * 60;
  return `${m} мин ${rest.toFixed(0).padStart(2, "0")} с`;
}

export function fmtClock(seconds: number): string {
  const v = Math.max(0, Math.floor(seconds));
  const h = Math.floor(v / 3600);
  const m = Math.floor((v % 3600) / 60);
  const s = v % 60;
  return h > 0
    ? `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
    : `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MiB`;
}

export function fmtBytesShort(n: number): string {
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
  return `${(n / 1_000_000).toFixed(2)}M`;
}

export function fmtNum(n: number): string {
  return n.toLocaleString("ru-RU");
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtTimeOnly(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function wallToEpoch(iso: string | null | undefined): number {
  if (!iso) return 0;
  const v = Date.parse(iso);
  return isNaN(v) ? 0 : v;
}

/** hex-строка «12 04 0d» → байты. */
export function hexToBytes(hex: string): Uint8Array {
  const out: number[] = [];
  let nibble = -1;
  for (let i = 0; i < hex.length; i++) {
    const c = hex.charCodeAt(i);
    let v = -1;
    if (c >= 48 && c <= 57) v = c - 48;
    else if (c >= 97 && c <= 102) v = c - 87;
    else if (c >= 65 && c <= 70) v = c - 55;
    if (v < 0) continue;
    if (nibble < 0) nibble = v;
    else {
      out.push((nibble << 4) | v);
      nibble = -1;
    }
  }
  return new Uint8Array(out);
}

export function bytesToHex(bytes: Uint8Array, max = Infinity): string {
  const n = Math.min(bytes.length, max);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) parts.push(bytes[i].toString(16).padStart(2, "0"));
  return parts.join(" ");
}

export function asciiPreview(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".";
  }
  return s;
}

/** Короткая подпись события для ленты. */
export function eventPreview(ev: {
  kind: string;
  api: string;
  hex: string;
  text?: string | null;
  len: number;
  rc?: number | null;
}): string {
  if (ev.kind === "mark" || ev.kind === "note" || ev.kind === "step_start" || ev.kind === "step_end") {
    return ev.text || "";
  }
  if (ev.text) return ev.text;
  if (ev.hex) {
    const bytes = hexToBytes(ev.hex);
    return bytesToHex(bytes.slice(0, 24)) + (bytes.length > 24 ? " …" : "");
  }
  return ev.api;
}

export function kindLabel(kind: string): string {
  switch (kind) {
    case "tx":
      return "TX";
    case "rx":
      return "RX";
    case "mark":
      return "MARK";
    case "step_start":
      return "STEP";
    case "step_end":
      return "STEP";
    case "file":
      return "FILE";
    case "file_hash":
      return "HASH";
    case "sys":
      return "SYS";
    case "module":
      return "MOD";
    case "vcp":
      return "VCP";
    case "note":
      return "NOTE";
    case "shot":
      return "SHOT";
    case "summary":
      return "SUM";
    case "error":
      return "ERR";
    default:
      return "RAW";
  }
}

export function kindClass(kind: string): string {
  switch (kind) {
    case "tx":
      return "row--tx";
    case "rx":
      return "row--rx";
    case "mark":
    case "note":
      return "row--mark";
    case "step_start":
    case "step_end":
      return "row--step";
    case "file":
    case "file_hash":
      return "row--file";
    case "error":
      return "row--error";
    case "module":
    case "vcp":
      return "row--sys";
    case "sys":
    case "summary":
    case "shot":
      return "row--sys";
    default:
      return "row--sys";
  }
}

export function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
