/**
 * Центральная лента: виртуализированный поток событий, фильтры, поиск.
 *
 * Разметка и поведение перенесены из референса дизайна (components__stream.ts):
 * heading, чипы групп, поиск, .new-events-pill, виртуализация ROW_H=34/OVERSCAN=14,
 * клавиатурная навигация. Сверх референса — пятая колонка «Δ обмена» и
 * `mountPanel()` для блока телеметрии.
 */

import { el, iconButton } from "../dom";
import { eventPreview, fmtBytes, fmtTime, kindClass, kindLabel } from "../format";
import { store } from "../store";
import { emptyDeltaState, extendDeltaMap, type DeltaState } from "../traffic-core";
import type { Event, EventKind } from "../types";
import { msg, t } from "../i18n";
import { localizeEventText } from "../engine-text";

msg({
  "Интервал между записями обмена в загруженном логе":
    "Interval between exchange records in the loaded log",
  "показать/скрыть {label}": "show/hide {label}",
  "фильтр по hex, api, тексту…": "filter by hex, api, text…",
  "сбросить поиск": "reset search",
  "МОНИТОР ОБМЕНА": "EXCHANGE MONITOR",
  "Поток событий": "Event stream",
  "Поиск по событиям": "Search events",
  "Время": "Time",
  "Тип": "Type",
  "Вызов / данные": "Call / data",
  "Байт": "Bytes",
  "Δ обмена": "Δ interval",
  "↓ {n} новых": "↓ {n} new",
  "{shown} · всего {total}": "{shown} · total {total}",
  "Поток пуст": "The stream is empty",
  "Выберите программу на FTDI в левой колонке и нажмите «подключить». Поток обмена появится здесь.":
    "Pick an FTDI program in the left column and press \"attach\". The exchange stream will appear here.",
  "Ничего не найдено": "Nothing found",
  "Под фильтры и поиск не подходит ни одно событие.": "No event matches the filters and the search.",
  "Ожидание обмена": "Waiting for traffic",
  "Захват поднят, хуки на месте. Сделайте действие в программе — строки появятся автоматически.":
    "Capture is up and hooks are in place. Do an action in the tool — rows will appear automatically.",
  "ШАГ {n} · ": "STEP {n} · ",
  "МЕТКА": "MARK",
  "ШАГ": "STEP",
  "ФАЙЛ": "FILE",
  "ОШИБКА": "ERR",
  "мс": "ms",
  "с": "s",
});

/** Высота строки и запас виртуализации — как в референсе. */
const ROW_H = 34;
const OVERSCAN = 14;

interface FilterGroup {
  id: string;
  label: string;
  kinds: EventKind[];
}

const GROUPS: FilterGroup[] = [
  { id: "tx", label: "TX", kinds: ["tx"] },
  { id: "rx", label: "RX", kinds: ["rx"] },
  { id: "mark", label: "МЕТКА", kinds: ["mark", "note"] },
  { id: "step", label: "ШАГ", kinds: ["step_start", "step_end"] },
  { id: "file", label: "ФАЙЛ", kinds: ["file", "file_hash"] },
  { id: "sys", label: "SYS", kinds: ["sys", "module", "vcp"] },
  // Осциллограф: события сервиса и нажатия кнопок целевой программы.
  { id: "scope", label: "SCOPE", kinds: ["scope"] },
  { id: "ui", label: "UI", kinds: ["ui_action"] },
  { id: "err", label: "ОШИБКА", kinds: ["error"] },
];

// Подсказка вычисляется при показе: язык из настроек приложения приходит уже
// после импорта модулей, и замороженная строка осталась бы русской.
const deltaHint = (): string => t("Интервал между записями обмена в загруженном логе");

/** Мс → «50 мс» / «1.25 с»; хвостовые нули не показываем. */
function fmtDelta(ms: number): string {
  if (ms < 1000) return `${trimZeros(ms.toFixed(2))} ${t("мс")}`;
  return `${trimZeros((ms / 1000).toFixed(3))} ${t("с")}`;
}

function trimZeros(s: string): string {
  return s.includes(".") ? s.replace(/0+$/, "").replace(/\.$/, "") : s;
}

export class Stream {
  /** Контейнер панели потока. */
  el: HTMLElement;
  private viewport: HTMLElement;
  private canvas: HTMLElement;
  private rows: HTMLElement;
  private search: HTMLInputElement;
  private stat: HTMLElement;
  private chips: HTMLElement;
  private empty: HTMLElement;
  private pill: HTMLButtonElement;
  private heading: HTMLElement;

  private vis: Event[] = [];
  private lastEventsRef: Event[] | null = null;
  private lastFilters: Set<EventKind> | null = null;
  private lastQuery = "\u0000";
  private lastSelection: Event | null = null;
  private lastActiveId: string | null = null;
  private rendered = new Set<number>();
  private programmatic = false;
  private rafPending = false;
  private pendingOlder = false;

  /** Δ мс по seq: пересчитывается только при смене массива events/сессии. */
  private deltas = new Map<number, number>();
  private deltaSource: Event[] | null = null;
  /** Сколько событий уже учтено в `deltas` — живой поток дописывает только хвост. */
  private deltaState: DeltaState = emptyDeltaState();

  constructor() {
    this.el = el("section", "stream");

    const toolbar = el("div", "stream__toolbar");
    this.chips = el("div", "filters");
    for (const g of GROUPS) {
      const chip = el("button", `chip chip--${g.id}`);
      chip.type = "button";
      chip.dataset.group = g.id;
      chip.append(el("span", "chip__dot"), document.createTextNode(t(g.label)));
      chip.addEventListener("click", () => this.toggleGroup(g));
      chip.title = t("показать/скрыть {label}", { label: t(g.label) });
      this.chips.append(chip);
    }

    const search = el("div", "search");
    this.search = el("input");
    this.search.type = "search";
    this.search.placeholder = t("фильтр по hex, api, тексту…");
    this.search.spellcheck = false;
    const clear = iconButton("close", t("сбросить поиск"), () => {
      this.search.value = "";
      store.setQuery("");
    }, "search__clear");
    search.append(this.search, clear);

    this.stat = el("div", "stream__stat");
    toolbar.append(this.chips, search, this.stat);

    this.viewport = el("div", "stream__viewport");
    this.viewport.tabIndex = 0;
    this.canvas = el("div", "stream__canvas");
    this.rows = el("div", "stream__rows");
    this.canvas.append(this.rows);
    this.empty = el("div", "stream__empty");
    this.empty.hidden = true;
    this.pill = el("button", "new-events-pill");
    this.pill.type = "button";
    this.pill.hidden = true;
    this.pill.addEventListener("click", () => {
      store.setFollow(true);
      this.scrollToBottom();
    });

    this.viewport.append(this.canvas, this.empty, this.pill);
    this.heading = el("header", "stream-heading");
    this.heading.append(el("span", "eyebrow", t("МОНИТОР ОБМЕНА")), el("h1", "", t("Поток событий")));
    this.search.setAttribute("aria-label", t("Поиск по событиям"));

    const columns = el("div", "stream-columns");
    const columnLabels = [t("Время"), t("Тип"), t("Вызов / данные"), t("Байт"), t("Δ обмена")];
    for (let i = 0; i < columnLabels.length; i++) {
      const span = el("span", "", columnLabels[i]);
      // Подсказка у нового заголовка: Δ — интервал в логе, а не время ответа ЭБУ.
      if (i === columnLabels.length - 1) span.title = deltaHint();
      columns.append(span);
    }

    this.el.append(this.heading, toolbar, columns, this.viewport);

    let debounce = 0;
    this.search.addEventListener("input", () => {
      window.clearTimeout(debounce);
      debounce = window.setTimeout(() => store.setQuery(this.search.value), 110);
    });

    this.viewport.addEventListener("scroll", () => this.onScroll(), { passive: true });
    this.viewport.addEventListener("keydown", (e) => this.onKey(e));

    this.updateChips();
    this.update();
  }

  /** Вставить блок над тулбаром: сразу после .stream-heading (контракт main.ts). */
  mountPanel(node: HTMLElement): void {
    const toolbar = this.el.querySelector<HTMLElement>(".stream__toolbar");
    if (toolbar) this.el.insertBefore(node, toolbar);
    else this.heading.after(node);
  }

  update(): void {
    this.updateDeltas(store.state.events);
    const s = store.state;
    const changed =
      s.events !== this.lastEventsRef ||
      s.filters !== this.lastFilters ||
      s.query !== this.lastQuery ||
      s.active?.id !== this.lastActiveId;

    this.pill.hidden = s.pendingNew === 0 || s.follow;
    if (!this.pill.hidden) {
      this.pill.textContent = t("↓ {n} новых", { n: s.pendingNew });
    }

    if (!changed) {
      if (s.selection !== this.lastSelection) {
        this.lastSelection = s.selection;
        this.highlightSelection();
      }
      return;
    }

    this.lastEventsRef = s.events;
    this.lastFilters = s.filters;
    this.lastQuery = s.query;
    this.lastActiveId = s.active?.id ?? null;
    this.vis = store.visibleEvents();
    this.canvas.style.height = `${this.vis.length * ROW_H}px`;
    void this.canvas.offsetHeight; // сброс layout: дальше scrollTop считается по новой высоте
    this.stat.textContent = s.active
      ? t("{shown} · всего {total}", { shown: this.vis.length === s.events.length ? s.events.length : `${this.vis.length} из ${s.events.length}`, total: s.total })
      : "";
    this.updateChips();
    this.renderEmpty();

    this.afterRender(() => {
      if (s.follow) {
        this.scrollToBottom();
        return;
      }
      const vp = this.viewport;
      const max = Math.max(0, vp.scrollHeight - vp.clientHeight);
      if (vp.scrollTop > max) {
        this.programmatic = true;
        vp.scrollTop = max;
      }
      this.renderWindow();
    });
  }

  /**
   * Пересчитать кэш Δ. Живой поток приходит новым массивом на каждый WS-батч:
   * если это тот же лог с дописанным хвостом — считаем только новые события,
   * иначе (смена сессии, подгрузка истории, усечение ring-буфера) — полный пересчёт.
   */
  private updateDeltas(events: Event[]): void {
    if (this.deltaSource === events) return;
    const old = this.deltaSource;
    const keep =
      old !== null &&
      old.length >= this.deltaState.count &&
      events.length >= this.deltaState.count &&
      (this.deltaState.count === 0 || old[this.deltaState.count - 1]?.seq === events[this.deltaState.count - 1]?.seq);
    if (!keep) {
      this.deltas.clear();
      this.deltaState = emptyDeltaState();
    }
    this.deltaState = extendDeltaMap(this.deltas, events, this.deltaState);
    this.deltaSource = events;
  }

  private renderEmpty(): void {
    const s = store.state;
    const show = this.vis.length === 0;
    this.empty.hidden = !show;
    if (!show) return;
    this.empty.replaceChildren();
    if (!s.active) {
      this.empty.append(
        title(t("Поток пуст")),
        p(t("Выберите программу на FTDI в левой колонке и нажмите «подключить». Поток обмена появится здесь.")),
      );
      return;
    }
    if (s.events.length > 0) {
      this.empty.append(title(t("Ничего не найдено")), p(t("Под фильтры и поиск не подходит ни одно событие.")));
      return;
    }
    this.empty.append(
      title(t("Ожидание обмена")),
      p(t("Захват поднят, хуки на месте. Сделайте действие в программе — строки появятся автоматически.")),
    );
  }

  private updateChips(): void {
    const filters = store.state.filters;
    for (const chip of Array.from(this.chips.querySelectorAll<HTMLElement>(".chip"))) {
      const g = GROUPS.find((x) => x.id === chip.dataset.group);
      if (!g) continue;
      const on = g.kinds.every((k) => filters.has(k));
      chip.classList.toggle("is-on", on);
    }
  }

  private toggleGroup(g: FilterGroup): void {
    const filters = new Set(store.state.filters);
    const on = g.kinds.every((k) => filters.has(k));
    for (const k of g.kinds) {
      if (on) filters.delete(k);
      else filters.add(k);
    }
    store.setFilters([...filters]);
  }

  /* ── виртуализация ───────────────────────────────────────────────────── */

  private renderWindow(): void {
    // После смены фильтра/высоты полотна scrollTop мог остаться от старого
    // содержимого: сначала приводим его в допустимые границы, потом считаем окно.
    const maxTop = Math.max(0, this.vis.length * ROW_H - this.viewport.clientHeight);
    if (this.viewport.scrollTop > maxTop) {
      this.programmatic = true;
      this.viewport.scrollTop = maxTop;
    }
    const top = this.viewport.scrollTop;
    const h = this.viewport.clientHeight;
    const first = Math.min(Math.max(0, this.vis.length - 1), Math.max(0, Math.floor(top / ROW_H) - OVERSCAN));
    const last = Math.min(this.vis.length, Math.ceil((top + h) / ROW_H) + OVERSCAN);

    if (first < 40 && this.vis.length > 0 && store.state.hasMoreBefore && !this.pendingOlder) {
      this.pendingOlder = true;
      void store.loadOlder().finally(() => {
        this.pendingOlder = false;
      });
    }

    this.rows.style.transform = `translateY(${first * ROW_H}px)`;
    const frag = document.createDocumentFragment();
    const rendered = new Set<number>();
    for (let i = first; i < last; i++) {
      const ev = this.vis[i];
      if (!ev) continue;
      rendered.add(ev.seq);
      frag.append(this.rowFor(ev));
    }
    this.rows.replaceChildren(frag);
    this.rendered = rendered;
    this.highlightSelection();
  }

  private rowFor(ev: Event): HTMLElement {
    const row = el("div", `row ${rowKindClass(ev.kind)}`);
    row.dataset.seq = String(ev.seq);
    row.append(el("span", "row__t", fmtTime(ev.t)), el("span", "row__kind", rowKindLabel(ev.kind)));

    const main = el("div", "row__main");
    const showApi = [
      "tx",
      "rx",
      "file",
      "file_hash",
      "module",
      "vcp",
      "error",
      "scope",
      "ui_action",
    ].includes(ev.kind);
    const apiText = showApi && ev.api && ev.api !== rowKindLabel(ev.kind) ? ev.api : "";
    const api = el("span", "row__api", apiText);
    let preview =
      ev.kind === "step_start" || ev.kind === "step_end"
        ? `${ev.step ? t("ШАГ {n} · ", { n: ev.step }) : ""}${eventPreview(ev)}`
        : eventPreview(ev);
    // Фокус — не нажатие: Tab и возврат фокуса в окно дают такое же событие.
    // Показываем вид канала рядом с именем, чтобы журнал не выдавал фокус за
    // выполненную команду (docs/14 §6).
    if (ev.kind === "ui_action") {
      preview += ` · ${actionLabel(ev)}`;
    }
    const text = el("span", "row__text", preview);
    main.append(api, text);

    const bytes = el("span", "row__bytes", ev.len ? fmtBytes(ev.len) : "");
    // Δ обмена: интервал до предыдущего непустого TX/RX; нет пары/битая метка — «—».
    const deltaCell = el("span", "row__delta");
    const deltaMs = this.deltas.get(ev.seq);
    deltaCell.textContent = deltaMs === undefined ? "—" : fmtDelta(deltaMs);
    deltaCell.title = deltaHint();

    row.append(main, bytes, deltaCell);
    // Подсказка: сырой текст плюс meta новых типов (действие, окно, кадры).
    const metaHint = scopeMetaHint(ev);
    row.title = [localizeEventText(ev.raw || `${ev.api} ${ev.hex}`.trim()), metaHint]
      .filter(Boolean)
      .join("\n");
    row.addEventListener("click", () => {
      store.selectEvent(ev);
      this.viewport.focus({ preventScroll: true });
    });
    row.addEventListener("dblclick", () => {
      recordStepShortcut(ev);
    });
    if (ev.kind === "step_start" || ev.kind === "step_end") {
      row.style.cursor = "pointer";
    }
    return row;
  }

  private highlightSelection(): void {
    const sel = store.state.selection;
    for (const node of Array.from(this.rows.children) as HTMLElement[]) {
      node.classList.toggle("is-selected", !!sel && node.dataset.seq === String(sel.seq));
    }
  }

  private onScroll(): void {
    if (this.programmatic) {
      this.programmatic = false;
      return;
    }
    const vp = this.viewport;
    const nearBottom = vp.scrollHeight - vp.scrollTop - vp.clientHeight < 48;
    const s = store.state;
    if (nearBottom && !s.follow) store.setFollow(true);
    else if (!nearBottom && s.follow) store.setFollow(false);
    this.renderWindow();
  }

  private scrollToBottom(): void {
    this.programmatic = true;
    // offsetHeight заставляет браузер применить новую высоту полотна до чтения.
    const bottom = Math.max(0, this.canvas.offsetHeight - this.viewport.clientHeight);
    this.viewport.scrollTop = bottom;
    this.renderWindow();
  }

  scrollToSeq(seq: number): void {
    const idx = this.vis.findIndex((e) => e.seq === seq);
    if (idx < 0) return;
    const vp = this.viewport;
    const target = Math.max(0, idx * ROW_H - vp.clientHeight / 2);
    store.setFollow(false);
    this.programmatic = true;
    vp.scrollTop = target;
    this.renderWindow();
    store.selectEvent(this.vis[idx]);
  }

  focusSearch(): void {
    this.search.focus();
    this.search.select();
  }

  /** Перерисовать принудительно (например, после resize). */
  refresh(): void {
    this.lastEventsRef = null;
    this.lastFilters = null;
    this.lastQuery = "\u0000";
    this.lastActiveId = null;
    this.deltaSource = null;
    this.deltaState = emptyDeltaState();
    this.deltas.clear();
    this.update();
  }

  private afterRender(fn: () => void): void {
    if (this.rafPending) return;
    this.rafPending = true;
    requestAnimationFrame(() => {
      this.rafPending = false;
      fn();
    });
  }

  private onKey(e: KeyboardEvent): void {
    const s = store.state;
    const vis = this.vis;
    if (!vis.length) return;
    let idx = s.selection ? vis.findIndex((x) => x.seq === s.selection?.seq) : -1;
    const page = Math.max(1, Math.floor(this.viewport.clientHeight / ROW_H) - 2);
    let handled = true;
    switch (e.key) {
      case "ArrowDown":
        idx = Math.min(vis.length - 1, idx + 1);
        break;
      case "ArrowUp":
        idx = Math.max(0, idx - 1);
        break;
      case "PageDown":
        idx = Math.min(vis.length - 1, idx + page);
        break;
      case "PageUp":
        idx = Math.max(0, idx - page);
        break;
      case "Home":
        idx = 0;
        break;
      case "End":
        idx = vis.length - 1;
        break;
      default:
        handled = false;
    }
    if (!handled) return;
    e.preventDefault();
    const ev = vis[idx];
    if (ev) this.scrollToSeq(ev.seq);
  }
}

function title(text: string): HTMLElement {
  return el("h3", "", text);
}

function p(text: string): HTMLElement {
  return el("p", "", text);
}

function recordStepShortcut(ev: Event): void {
  if (ev.kind === "step_start" || ev.kind === "step_end") {
    store.selectEvent(ev);
  }
}

/* ── SCOPE и UI: новые типы событий ─────────────────────────────────────── */

/**
 * Подпись бейджа. `format.ts` знает только старые kind и вернул бы «RAW»,
 * поэтому новые типы подписываем здесь, не трогая общий форматер.
 */
function rowKindLabel(kind: EventKind): string {
  if (kind === "scope") return "SCOPE";
  if (kind === "ui_action") return "UI";
  return kindLabel(kind);
}

/** Класс строки: свои цвета для SCOPE/UI, остальные — прежние. */
function rowKindClass(kind: EventKind): string {
  if (kind === "scope") return "row--scope";
  if (kind === "ui_action") return "row--ui";
  return kindClass(kind);
}

/**
 * Подпись действия: чем подтверждено нажатие.
 *
 * `confirmed` ставит движок: `invoke` от провайдера или клик-канал (нажатие
 * кнопки мыши). `focus` без подтверждения — переход по Tab, возврат фокуса
 * после диалога и т.п.; команда при этом не считается выполненной.
 */
function actionLabel(ev: Event): string {
  const meta = ev.meta as Record<string, unknown> | null | undefined;
  const activation = typeof meta?.activation === "string" ? meta.activation : "";
  if (meta?.confirmed === true) {
    return activation === "click" ? t("нажатие (клик)") : t("нажатие (Invoke)");
  }
  return t("фокус (не подтверждено)");
}

/**
 * Скалярные поля meta в подсказку строки: у новых событий нет hex, и без
 * этого наведение показывало бы только «SCOPE  ».
 */
function scopeMetaHint(ev: Event): string {
  if (ev.kind !== "scope" && ev.kind !== "ui_action") return "";
  const meta = ev.meta as Record<string, unknown> | null | undefined;
  if (!meta || typeof meta !== "object") return "";
  const parts: string[] = [];
  for (const key of Object.keys(meta)) {
    const value = meta[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      parts.push(`${key}=${String(value)}`);
    }
  }
  return parts.join(" · ");
}
