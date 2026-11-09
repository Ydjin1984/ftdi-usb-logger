/** Центральная лента: виртуализированный поток событий, фильтры, поиск. */

import { el, icon, iconButton } from "../dom";
import { eventPreview, fmtBytes, fmtTime, kindClass, kindLabel } from "../format";
import { store } from "../store";
import type { Event, EventKind } from "../types";

const ROW_H = 22;
const OVERSCAN = 14;

interface FilterGroup {
  id: string;
  label: string;
  kinds: EventKind[];
}

const GROUPS: FilterGroup[] = [
  { id: "tx", label: "TX", kinds: ["tx"] },
  { id: "rx", label: "RX", kinds: ["rx"] },
  { id: "mark", label: "MARK", kinds: ["mark", "note"] },
  { id: "step", label: "STEP", kinds: ["step_start", "step_end"] },
  { id: "file", label: "FILE", kinds: ["file", "file_hash"] },
  { id: "sys", label: "SYS", kinds: ["sys", "module", "vcp"] },
  { id: "err", label: "ERR", kinds: ["error"] },
];

export class Stream {
  el: HTMLElement;
  private viewport: HTMLElement;
  private canvas: HTMLElement;
  private rows: HTMLElement;
  private search: HTMLInputElement;
  private stat: HTMLElement;
  private chips: HTMLElement;
  private empty: HTMLElement;
  private pill: HTMLButtonElement;

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

  constructor() {
    this.el = el("section", "stream");

    const toolbar = el("div", "stream__toolbar");
    this.chips = el("div", "filters");
    for (const g of GROUPS) {
      const chip = el("button", `chip chip--${g.id}`);
      chip.type = "button";
      chip.dataset.group = g.id;
      chip.append(el("span", "chip__dot"), document.createTextNode(g.label));
      chip.addEventListener("click", () => this.toggleGroup(g));
      chip.title = `показать/скрыть ${g.label}`;
      this.chips.append(chip);
    }

    const search = el("div", "search");
    this.search = el("input");
    this.search.type = "search";
    this.search.placeholder = "фильтр по hex, api, тексту…";
    this.search.spellcheck = false;
    const clear = iconButton("close", "сбросить поиск", () => {
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
    this.el.append(toolbar, this.viewport);

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

  update(): void {
    const s = store.state;
    const changed =
      s.events !== this.lastEventsRef ||
      s.filters !== this.lastFilters ||
      s.query !== this.lastQuery ||
      s.active?.id !== this.lastActiveId;

    this.pill.hidden = s.pendingNew === 0 || s.follow;
    if (!this.pill.hidden) {
      this.pill.textContent = `↓ ${s.pendingNew} новых`;
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
      ? `${this.vis.length === s.events.length ? s.events.length : `${this.vis.length} из ${s.events.length}`} · всего ${s.total}`
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

  private renderEmpty(): void {
    const s = store.state;
    const show = this.vis.length === 0;
    this.empty.hidden = !show;
    if (!show) return;
    this.empty.replaceChildren();
    if (!s.active) {
      this.empty.append(
        title("Поток пуст"),
        p("Выберите программу на FTDI в левой колонке и нажмите «подключить». Поток обмена появится здесь."),
      );
      return;
    }
    if (s.events.length > 0) {
      this.empty.append(title("Ничего не найдено"), p("Под фильтры и поиск не подходит ни одно событие."));
      return;
    }
    this.empty.append(
      title("Ожидание обмена"),
      p("Захват поднят, хуки на месте. Сделайте действие в программе — строки появятся автоматически."),
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
    const row = el("div", `row ${kindClass(ev.kind)}`);
    row.dataset.seq = String(ev.seq);
    row.append(el("span", "row__t", fmtTime(ev.t)), el("span", "row__kind", kindLabel(ev.kind)));

    const main = el("div", "row__main");
    const showApi = ["tx", "rx", "file", "file_hash", "module", "vcp", "error"].includes(ev.kind);
    const apiText = showApi && ev.api && ev.api !== kindLabel(ev.kind) ? ev.api : "";
    const api = el("span", "row__api", apiText);
    const text = el("span", "row__text", ev.kind === "step_start" || ev.kind === "step_end" ? `${ev.step ? `ШАГ ${ev.step} · ` : ""}${eventPreview(ev)}` : eventPreview(ev));
    main.append(api, text);

    const bytes = el("span", "row__bytes", ev.len ? fmtBytes(ev.len) : "");
    row.append(main, bytes);
    row.title = ev.raw || `${ev.api} ${ev.hex}`.trim();
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
  const h = el("h3", "", text);
  return h;
}

function p(text: string): HTMLElement {
  return el("p", "", text);
}

function recordStepShortcut(ev: Event): void {
  if (ev.kind === "step_start" || ev.kind === "step_end") {
    store.selectEvent(ev);
  }
}




