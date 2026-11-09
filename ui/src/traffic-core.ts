/**
 * Чистые вычисления телеметрии обмена: без DOM и без обращения к store.
 *
 * Здесь живут Δ-колонка потока (`buildDeltaMap`), окно 30 с для карточек и
 * графика (`computeTraffic`) и извлечение подтверждённой скорости линии
 * (`extractBaud`). Функции детерминированы и не зависят от состояния UI,
 * поэтому юнит-тесты гоняют их напрямую, без браузера.
 */

import type { Event } from "./types";

/** Готовое окно телеметрии: столбцы по секундам и сводные значения. */
export interface TrafficWindow {
  /** Окна по 1 с слева направо: [end − windowSec, end]; последний bin — свежая секунда. */
  bins: { tx: number; rx: number }[];
  /** Скорость TX за последнюю полную секунду, Б/с; null — эта секунда не покрыта данными. */
  txRate: number | null;
  /** Скорость RX за последнюю полную секунду, Б/с; null — эта секунда не покрыта данными. */
  rxRate: number | null;
  /** Медиана Δ (мс) по событиям обмена внутри окна; null — пар Δ нет. */
  medianDelta: number | null;
  /** Пик по столбцам: max(tx, rx) среди секунд окна, байт за секунду. */
  peak: number;
  /** Окно целиком покрыто известным диапазоном данных (не обрезано и не «моложе» 30 с). */
  fullWindow: boolean;
  /** Сколько секунд окна реально покрыто загруженными данными (0…windowSec). */
  coveredSec: number;
}

/** Параметры окна: правый край, длина и признак «левая граница данных известна». */
export interface TrafficOptions {
  /** Правый край окна в секундах от старта сессии. */
  end: number;
  /** Длина окна в секундах (по ТЗ — 30). */
  windowSec: number;
  /**
   * true — левая граница диапазона данных достоверно известна (живая запись:
   * t отсчитывается от старта захвата; сохранённая сессия с полностью
   * загруженной историей). false — история обрезана, данные начинаются
   * с первого загруженного события.
   */
  windowStartKnown: boolean;
}

/** Строка подтверждённой настройки линии. */
export interface BaudEntry {
  /** Канал: handle D2XX, имя COM-порта или канал/устройство J2534. */
  channel: string;
  /** Скорость линии, бод. */
  baud: number;
  /** API, которым настройка подтверждена. */
  api: string;
}

/** Событие — реальный обмен: направление tx/rx, ненулевая нагрузка, конечная метка. */
function isTraffic(ev: Event): boolean {
  return (ev.kind === "tx" || ev.kind === "rx") && ev.len > 0 && Number.isFinite(ev.t);
}

/**
 * Δ между соседними непустыми TX/RX в порядке лога, мс, ключ — `seq` события.
 *
 * «Соседние» считаются по порядку лога, а не по t: метки времени пишутся
 * одним писателем и обычно монотонны, но битая/переставленная метка не должна
 * давать отрицательный интервал — для неё записи нет (в UI будет «—»).
 *
 * Результат округляется до микросекунды: (0.25 − 0.20) × 1000 в IEEE-754 даёт
 * 49.999999999999986, а в карточке и колонке должно быть ровно 50 мс.
 */
/** Состояние инкрементального расчёта Δ: докуда дошли и время последнего TX/RX. */
export interface DeltaState {
  /** Сколько событий массива уже учтено. */
  count: number;
  /** `t` последнего учтённого непустого TX/RX (`null` — ещё не было). */
  prevT: number | null;
}

/** Начальное состояние инкрементального расчёта Δ. */
export function emptyDeltaState(): DeltaState {
  return { count: 0, prevT: null };
}

/**
 * Дописать Δ для событий, добавленных в конец уже обработанного массива.
 *
 * Нужно живому потоку: `store` на каждый WS-батч создаёт новый массив событий,
 * и полный пересчёт 60k строк на батч (8–16 мс) — лишняя работа. Здесь считается
 * только хвост, начиная с `state.count`.
 */
export function extendDeltaMap(
  out: Map<number, number>,
  events: Event[],
  state: DeltaState,
): DeltaState {
  let prevT = state.prevT ?? undefined;
  for (let i = Math.max(0, Math.min(state.count, events.length)); i < events.length; i++) {
    const ev = events[i];
    if (!isTraffic(ev)) continue;
    if (prevT !== undefined && ev.t >= prevT) out.set(ev.seq, Math.round((ev.t - prevT) * 1_000_000) / 1000);
    prevT = ev.t;
  }
  return { count: events.length, prevT: prevT ?? null };
}

export function buildDeltaMap(events: Event[]): Map<number, number> {
  const out = new Map<number, number>();
  extendDeltaMap(out, events, emptyDeltaState());
  return out;
}

/**
 * Посчитать окно телеметрии по **всему** массиву событий (до фильтрации).
 *
 * Окно — полуинтервал [end − windowSec, end): правая граница исключается.
 * Столбец i покрывает [start + i, start + i + 1), поэтому событие ровно на
 * t === end не попадает ни в один столбец и не считается дважды при сдвиге
 * окна на секунду.
 *
 * Скорость направления — сумма `len` за последнюю полную секунду [end − 1, end)
 * делить на 1 с; null, если эта секунда не покрыта известными данными.
 */
export function computeTraffic(events: Event[], opts: TrafficOptions): TrafficWindow {
  const windowSec = Math.max(1, Math.floor(opts.windowSec));
  const end = opts.end;
  const knownEnd = Number.isFinite(end);
  const windowStart = knownEnd ? end - windowSec : 0;
  const bins: { tx: number; rx: number }[] = Array.from({ length: windowSec }, () => ({ tx: 0, rx: 0 }));

  // Левая граница известного диапазона. t — секунды от старта сессии, поэтому
  // при известной границе данные начинаются с 0; при обрезанной истории —
  // с первого загруженного события.
  let firstT = Infinity;
  for (const ev of events) {
    if (Number.isFinite(ev.t) && ev.t < firstT) firstT = ev.t;
  }
  const coverageStart = opts.windowStartKnown ? 0 : firstT;
  const coveredSec =
    knownEnd && Number.isFinite(coverageStart)
      ? Math.min(windowSec, Math.max(0, end - Math.max(windowStart, coverageStart)))
      : 0;
  const fullWindow = knownEnd && Number.isFinite(coverageStart) && windowStart >= coverageStart;

  const deltas = buildDeltaMap(events);
  const windowDeltas: number[] = [];
  if (knownEnd) {
    for (const ev of events) {
      if (!isTraffic(ev)) continue;
      // Полуинтервал [windowStart, end): правая граница не входит в окно.
      const rel = ev.t - windowStart;
      if (rel < 0 || rel >= windowSec) continue;
      const idx = Math.min(windowSec - 1, Math.floor(rel));
      bins[idx][ev.kind === "tx" ? "tx" : "rx"] += ev.len;
      const delta = deltas.get(ev.seq);
      if (delta !== undefined) windowDeltas.push(delta);
    }
  }

  let peak = 0;
  for (const bin of bins) peak = Math.max(peak, bin.tx, bin.rx);

  windowDeltas.sort((a, b) => a - b);
  let medianDelta: number | null = null;
  if (windowDeltas.length > 0) {
    const mid = windowDeltas.length >> 1;
    medianDelta =
      windowDeltas.length % 2 === 1 ? windowDeltas[mid] : (windowDeltas[mid - 1] + windowDeltas[mid]) / 2;
  }

  const lastSecondCovered = knownEnd && Number.isFinite(coverageStart) && end - 1 >= coverageStart;
  const lastBin = bins[windowSec - 1];
  return {
    bins,
    txRate: lastSecondCovered ? lastBin.tx / 1 : null,
    rxRate: lastSecondCovered ? lastBin.rx / 1 : null,
    medianDelta,
    peak,
    fullWindow,
    coveredSec,
  };
}

/* ───────────────────── скорость линии (baud) ───────────────────────── */

/** `rc=<n>` из текста события (движок пишет rc как int32). */
function parseRc(src: string): number | null {
  const m = /rc\s*=\s*(-?\d+)/i.exec(src);
  return m ? Number(m[1]) : null;
}

/** rc из текста события; запасной вариант — engine уже разобрал его в `event.rc`. */
function resolveRc(src: string, ev: Event): number | null {
  const parsed = parseRc(src);
  if (parsed !== null) return parsed;
  return typeof ev.rc === "number" && Number.isFinite(ev.rc) ? ev.rc : null;
}

/** Число из `meta.baud`: движок кладёт число (VCP/J2534) или строку (J2534). */
function metaBaud(ev: Event): number | null {
  const raw = ev.meta ? ev.meta["baud"] : undefined;
  if (typeof raw === "number" && Number.isFinite(raw) && raw > 0) return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) {
    const n = Number(raw);
    return n > 0 ? n : null;
  }
  return null;
}

function metaString(ev: Event, key: string): string {
  const raw = ev.meta ? ev.meta[key] : undefined;
  return typeof raw === "string" ? raw : typeof raw === "number" ? String(raw) : "";
}

/** Канал J2534: `ch=` → `channel=` → `meta.channel` → `dev=`. */
function j2534Channel(src: string, ev: Event): string {
  const ch = /\bch\s*=\s*([^\s,)]+)/i.exec(src);
  if (ch) return ch[1];
  const channel = /\bchannel\s*=\s*([^\s,)]+)/i.exec(src);
  if (channel) return channel[1];
  const meta = metaString(ev, "channel");
  if (meta) return meta;
  const dev = /\bdev\s*=\s*([^\s,)]+)/i.exec(src);
  return dev ? `dev=${dev[1]}` : "J2534";
}

/**
 * Подтверждённые настройки скорости линии из событий — только успешные вызовы.
 *
 * Форматы — фактические строки проекта (sidecar/agents/*.js):
 *  - D2XX: `FT_SetBaudRate(handle=<h>, <baud>) rc=<rc>`, успех `rc === 0`;
 *  - Win32 COM: `COM SetCommState(<port>) baud=<baud> data=… rc=<rc>`,
 *    успех `rc !== 0` (Win32 BOOL: ненулевое значение = TRUE);
 *  - J2534: `J2534 connect dev=… ch=… proto=… flags=… baud=<baud> rc=<rc>`
 *    (в ТЗ записан как `PassThruConnect(...) … baud=… rc=…`), успех `rc === 0`.
 *
 * При нескольких замерах одного канала побеждает последний успешный.
 */
export function extractBaud(events: Event[]): { entries: BaudEntry[] } {
  const byChannel = new Map<string, BaudEntry>();
  for (const ev of events) {
    const src = `${ev.text ?? ""} ${ev.raw ?? ""}`;

    // D2XX: channel = handle.
    if (/FT_SetBaudRate/i.test(src)) {
      const m = /FT_SetBaudRate\s*\(([^)]*)\)/i.exec(src);
      if (!m) continue;
      const inner = m[1];
      const handleMatch = /handle\s*=\s*([^,)\s]+)/i.exec(inner);
      const withoutHandle = inner.replace(/handle\s*=\s*[^,)]+/i, "");
      const nums = withoutHandle.match(/\d+/g);
      const baud = nums && nums.length > 0 ? Number(nums[nums.length - 1]) : NaN;
      const rc = resolveRc(src, ev);
      if (!Number.isInteger(baud) || baud <= 0 || rc !== 0) continue;
      const channel = handleMatch ? handleMatch[1] : "handle";
      byChannel.set(channel, { channel, baud, api: ev.api || "FT_SetBaudRate" });
      continue;
    }

    // Win32 COM: успех — ненулевой BOOL, канал = имя порта.
    if (/COM\s+SetCommState/i.test(src)) {
      const m = /COM\s+SetCommState\s*\(([^)]*)\)/i.exec(src);
      if (!m) continue;
      const port = m[1].trim() || "COM";
      const tail = src.slice((m.index ?? 0) + m[0].length);
      const baudMatch = /baud\s*=\s*(\d+)/i.exec(tail) ?? /baud\s*=\s*(\d+)/i.exec(src);
      const baud = baudMatch ? Number(baudMatch[1]) : NaN;
      const rc = resolveRc(tail, ev);
      if (!Number.isInteger(baud) || baud <= 0 || rc === null || rc === 0) continue;
      byChannel.set(port, { channel: port, baud, api: ev.api || "COM SetCommState" });
      continue;
    }

    // J2534: успех rc === 0.
    if (/PassThruConnect|J2534\s+connect/i.test(src)) {
      const baudMatch = /baud\s*=\s*(\d+)/i.exec(src);
      const baud = baudMatch ? Number(baudMatch[1]) : metaBaud(ev);
      const rc = resolveRc(src, ev);
      if (baud === null || !Number.isInteger(baud) || baud <= 0 || rc !== 0) continue;
      const channel = j2534Channel(src, ev);
      byChannel.set(channel, { channel, baud, api: ev.api || "J2534 connect" });
    }
  }
  return { entries: [...byChannel.values()] };
}
