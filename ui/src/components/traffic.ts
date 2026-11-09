/**
 * Блок «Тайминги и скорость обмена» над потоком.
 *
 * Только отрисовка: все расчёты — в `traffic-core.ts` (чистые функции).
 * `el` вставляется в поток методом `Stream.mountPanel()`; `update()` вызывает
 * общий `render()` из main.ts. Пересчёт не чаще 1 Гц и только при смене ключа
 * (массив events, сессия, секунда, запись, started_at) — наведение и ввод
 * поиска метрики не пересчитывают.
 */

import { el } from "../dom";
import { store } from "../store";
import type { Event } from "../types";
import { computeTraffic, extractBaud } from "../traffic-core";
import type { TrafficWindow } from "../traffic-core";

/** Окно графика и медианы, секунд. */
const WINDOW_SEC = 30;
/** Минимальный интервал между пересчётами, мс (не чаще 1 Гц). */
const MIN_INTERVAL_MS = 1000;
/**
 * Сдвиг правого края закреплённого окна (saved/imported/demo), секунд.
 * computeTraffic использует полуинтервал [start, end), поэтому без сдвига
 * последний пакет лога ровно на t = maxT выпадал бы из окна; 1 мкс возвращает
 * его в (end−1, end] и в последний столбец графика.
 */
const PIN_EPS = 1e-6;
const SVG_NS = "http://www.w3.org/2000/svg";

/** Скорость потока: Б/с до 1 КиБ/с, дальше КиБ/с. */
function fmtRate(bytesPerSec: number): string {
  return bytesPerSec >= 1024 ? `${(bytesPerSec / 1024).toFixed(2)} КиБ/с` : `${Math.round(bytesPerSec)} Б/с`;
}

/** Интервал в мс: до секунды — «мс», дальше — «с». */
function fmtDelta(ms: number): string {
  if (ms < 1000) return `${trimZeros(ms.toFixed(2))} мс`;
  return `${trimZeros((ms / 1000).toFixed(3))} с`;
}

function trimZeros(s: string): string {
  return s.includes(".") ? s.replace(/0+$/, "").replace(/\.$/, "") : s;
}

/** Текст скорости линии для карточки: одно значение / «несколько каналов» / «—». */
function baudText(entries: ReturnType<typeof extractBaud>["entries"]): {
  value: string;
  channels: string;
  hint: string;
} {
  if (entries.length === 0) {
    return {
      value: "—",
      channels: "",
      hint: "в логе нет успешных настроек линии: FT_SetBaudRate rc=0, COM SetCommState rc≠0, PassThruConnect rc=0",
    };
  }
  const fmt = (n: number): string => `${n.toLocaleString("ru-RU")} бод`;
  const list = entries.map((e) => `${e.channel} = ${fmt(e.baud)}`).join(" · ");
  const distinct = [...new Set(entries.map((e) => e.baud))];
  if (distinct.length === 1) {
    return { value: fmt(distinct[0]), channels: entries.length > 1 ? list : "", hint: `успешные настройки: ${list}` };
  }
  return { value: "несколько каналов", channels: list, hint: `разные скорости линии: ${list}` };
}

export class TrafficMeter {
  /** Контейнер блока: `<details class="traffic-meter" open>`. */
  el: HTMLElement;
  private cards: HTMLElement;
  private svg: SVGSVGElement;
  private note: HTMLElement;

  /** Ключ последнего пересчёта и его время (троттлинг 1 Гц). */
  private lastKey = "";
  private lastAt = 0;
  /** Поколение массива events: смена ссылки = новые данные. */
  private eventsGen = 0;
  private lastEvents: Event[] | null = null;
  /** Кэш скорости линии: зависит только от событий, не от времени. */
  private baudGen = -1;
  private baudCache: { value: string; channels: string; hint: string } = { value: "—", channels: "", hint: "" };

  constructor() {
    const details = el("details", "traffic-meter");
    details.open = true;
    const summary = el("summary", "", "Тайминги и скорость обмена");
    this.cards = el("div", "traffic-cards");
    this.svg = document.createElementNS(SVG_NS, "svg");
    this.svg.setAttribute("viewBox", "0 0 600 52");
    this.svg.setAttribute("preserveAspectRatio", "none");
    this.svg.setAttribute("role", "img");
    this.svg.setAttribute("aria-label", "Скорость TX и RX за последние 30 секунд лога");
    this.note = el("p", "traffic-note", "Ожидание событий с временными метками");
    details.append(summary, this.cards, this.svg, this.note);
    this.el = details;
    this.update();
  }

  /** Пересчитать и перерисовать блок (вызывается из общего render()). */
  update(): void {
    const s = store.state;
    const now = Date.now();
    const events = s.events;
    if (events !== this.lastEvents) {
      this.lastEvents = events;
      this.eventsGen += 1;
    }
    const recording = !!s.status?.recording;
    const startedAt = s.status?.started_at ?? s.active?.started_at ?? null;
    const startedMs = startedAt ? Date.parse(startedAt) : NaN;
    // Скользящее окно по стенным часам — только для настоящей живой записи
    // (mode === "live" + recording + started_at). Демо — статическая фикстура без
    // живого потока, сессия без записи — снимок: окно ставим на конец лога.
    const live = s.mode === "live" && recording && Number.isFinite(startedMs);
    // Секунда входит в ключ только для живой записи: у закреплённого окна правый
    // край не движется, и пересчитывать 60k событий каждую секунду незачем.
    const secondBucket = live ? Math.floor(now / 1000) : 0;
    const key = `${this.eventsGen}|${s.active?.id ?? ""}|${secondBucket}|${recording}|${startedAt ?? ""}`;
    if (key === this.lastKey) return;
    if (now - this.lastAt < MIN_INTERVAL_MS) return;
    this.lastKey = key;
    this.lastAt = now;

    // Правый край окна: живая запись сдвигается по стенным часам даже без
    // пакетов; сохранённая сессия стоит на максимуме t загруженного лога.
    let maxT = -Infinity;
    for (const ev of events) {
      if (Number.isFinite(ev.t) && ev.t > maxT) maxT = ev.t;
    }
    // Для закреплённого окна конец лога — это последний пакет, поэтому end
    // сдвинут на PIN_EPS: полуинтервал [start, end) в computeTraffic включает
    // событие ровно на t = maxT. Для живой записи правый край — стенное время.
    const end = live
      ? Math.max(Number.isFinite(maxT) ? maxT : 0, (now - startedMs) / 1000)
      : Number.isFinite(maxT)
        ? maxT + PIN_EPS
        : 0;
    // В живой записи t отсчитывается от старта захвата — левая граница известна.
    const windowStartKnown = live ? true : !s.hasMoreBefore;

    const win = computeTraffic(events, { end, windowSec: WINDOW_SEC, windowStartKnown });
    // Скорость линии зависит только от набора событий: на каждый батч — один
    // проход по новым данным, а не раз в секунду по всему логу.
    if (this.baudGen !== this.eventsGen) {
      this.baudGen = this.eventsGen;
      this.baudCache = baudText(extractBaud(events).entries);
    }
    this.renderCards(win, this.baudCache);
    this.renderChart(win);
    this.note.textContent = this.buildNote(win, live, s.mode === "demo", events.length > 0);
  }

  private renderCards(win: TrafficWindow, baud: { value: string; channels: string; hint: string }): void {
    const medianValue = win.medianDelta === null || !win.fullWindow ? "—" : fmtDelta(win.medianDelta);
    const items: Array<{ label: string; value: string; tone: string; extra: string; hint: string }> = [
      {
        label: "TX · последняя 1 с",
        value: win.txRate === null ? "—" : fmtRate(win.txRate),
        tone: "tx",
        extra: "",
        hint: "сумма len TX за последнюю полную секунду лога ÷ 1 с",
      },
      {
        label: "RX · последняя 1 с",
        value: win.rxRate === null ? "—" : fmtRate(win.rxRate),
        tone: "rx",
        extra: "",
        hint: "сумма len RX за последнюю полную секунду лога ÷ 1 с",
      },
      {
        label: "Медиана Δ · 30 с",
        value: medianValue,
        tone: "",
        extra: "",
        hint: win.fullWindow
          ? "медиана Δ между соседними непустыми TX/RX в окне 30 с; не путать с временем ответа ЭБУ"
          : "«—»: окно неполное — медиана за 30 с по обрезанным данным не показывается",
      },
      { label: "Скорость линии", value: baud.value, tone: "", extra: baud.channels, hint: baud.hint },
    ];
    const frag = document.createDocumentFragment();
    for (const item of items) {
      const box = el("div");
      const small = el("small", "", item.label);
      const strong = el("strong", item.tone, item.value);
      box.append(small, strong);
      if (item.extra) box.append(el("small", "", item.extra));
      box.title = item.hint;
      frag.append(box);
    }
    this.cards.replaceChildren(frag);
  }

  private renderChart(win: TrafficWindow): void {
    const bins = win.bins;
    const n = bins.length;
    const slot = 600 / n;
    const barW = slot * 0.4;
    const peak = Math.max(1, win.peak);
    const frag = document.createDocumentFragment();
    const dirs: Array<{ dir: "tx" | "rx"; x: number; color: string }> = [
      { dir: "tx", x: slot * 0.05, color: "#68d9ff" },
      { dir: "rx", x: slot * 0.5, color: "#7be0ab" },
    ];
    for (let i = 0; i < n; i++) {
      const bin = bins[i];
      for (const { dir, x, color } of dirs) {
        const value = bin[dir];
        if (value <= 0) continue;
        const h = (value / peak) * 48;
        const rect = document.createElementNS(SVG_NS, "rect");
        rect.setAttribute("x", String(i * slot + x));
        rect.setAttribute("y", String(51 - h));
        rect.setAttribute("width", String(barW));
        rect.setAttribute("height", String(h));
        rect.setAttribute("fill", color);
        const title = document.createElementNS(SVG_NS, "title");
        title.textContent = `${dir.toUpperCase()} · ${fmtRate(value)} · ${n - i - 1}–${n - i} с до конца окна`;
        rect.append(title);
        frag.append(rect);
      }
    }
    this.svg.replaceChildren(frag);
  }

  private buildNote(win: TrafficWindow, live: boolean, demo: boolean, hasEvents: boolean): string {
    if (!hasEvents && !live) return "Ожидание событий с временными метками";
    // Граница окна подписана честно: живая запись — «сейчас», демо — «демо-лог»,
    // сохранённая/импортированная сессия — «конец лога».
    const boundary = live
      ? `−${WINDOW_SEC} с → сейчас`
      : demo
        ? `−${WINDOW_SEC} с → конец демо-лога`
        : `−${WINDOW_SEC} с → конец лога`;
    const parts = [
      boundary,
      "1 столбец на направление за секунду",
      `пик ${fmtRate(win.peak)}`,
      "TX голубой / RX зелёный",
    ];
    if (!win.fullWindow) {
      const covered = win.coveredSec >= 10 ? Math.round(win.coveredSec) : Math.round(win.coveredSec * 10) / 10;
      parts.push(`окно неполное: загружено ${covered} с из ${WINDOW_SEC}`);
    }
    return parts.join(" · ");
  }
}
