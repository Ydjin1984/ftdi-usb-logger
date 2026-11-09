/**
 * Рабочее пространство: грип-разделитель на правой границе левой панели,
 * кнопка «скрыть/показать панель» в шапке и сохранение ширины между запусками.
 *
 * Ширина живёт в CSS-переменной `--rail-size` на `.app-shell`, видимость —
 * в `data-rail-hidden` на нём же (см. layout/components CSS референса).
 *
 * Важно: «желаемая» ширина (её выбрал пользователь) и «применённая» (с учётом
 * максимума от текущего окна) хранятся раздельно. При сужении окна панель
 * ужимается, но при обратном расширении возвращается к желаемой.
 */

import { el } from "./dom";

const STORAGE_KEY = "ftdi.rail.v1";
const RAIL_ID = "session-rail";
/** Минимальная ширина панели, px. */
const MIN_WIDTH = 210;
/** Нижняя граница максимума: даже в узком окне панель не уже 230px. */
const MAX_FLOOR = 230;
/** Верхний предел максимума, px. */
const MAX_CAP = 620;
/** Шаг клавиатуры ←/→, px. */
const KEY_STEP = 16;
/** Панель не должна занимать больше этой доли ширины приложения. */
const MAX_SHARE = 0.38;

interface RailState {
  hidden: boolean;
  width: number | null;
}

export class Workspace {
  /** Элемент-грип (разделитель) в grid-area rail. */
  el: HTMLElement;

  private app: HTMLElement;
  private rail: HTMLElement;
  private toggle: HTMLButtonElement;

  /** Желаемая ширина, выбранная пользователем (210..620); null — ширина из CSS. */
  private desiredWidth: number | null = null;
  /** Фактически применённая ширина после клампа по текущему окну. */
  private appliedWidth: number | null = null;
  private hidden = false;
  private drag: { pointerId: number; startX: number; startWidth: number } | null = null;
  private resizeScheduled = false;

  constructor(app: HTMLElement, topbar: HTMLElement, rail: HTMLElement) {
    this.app = app;
    this.rail = rail;
    // Якорь для aria-controls: панель обязана иметь этот id.
    rail.id = RAIL_ID;

    this.el = el("div", "rail-grip");
    this.el.tabIndex = 0;
    this.el.setAttribute("role", "separator");
    this.el.setAttribute("aria-orientation", "vertical");
    this.el.setAttribute("aria-controls", RAIL_ID);
    this.el.setAttribute("aria-label", "ширина левой панели");
    this.el.title = "потяните или используйте стрелки ←/→, Home/End";

    this.toggle = el("button", "btn rail-toggle");
    this.toggle.type = "button";
    this.toggle.setAttribute("aria-controls", RAIL_ID);
    this.toggle.title = "скрыть или показать левую панель";
    this.toggle.addEventListener("click", () => this.setHidden(!this.hidden));
    const brand = topbar.querySelector(".brand");
    if (brand) brand.after(this.toggle);
    else topbar.prepend(this.toggle);

    // Состояние из прошлого запуска (битый JSON не должен ронять интерфейс).
    const saved = this.loadState();
    this.hidden = saved.hidden;
    if (saved.width != null) {
      // На момент сборки #app может быть ещё hidden, поэтому clientWidth = 0:
      // кламп по окну применится по documentElement в maxWidth().
      this.desiredWidth = this.clampBasic(saved.width);
      this.renderWidth(false);
    }
    this.applyHidden();
    this.syncToggle();
    this.syncAria();

    this.el.addEventListener("pointerdown", (e) => this.onPointerDown(e));
    this.el.addEventListener("pointermove", (e) => this.onPointerMove(e));
    this.el.addEventListener("pointerup", (e) => this.onPointerUp(e));
    this.el.addEventListener("pointercancel", (e) => this.onPointerUp(e));
    this.el.addEventListener("lostpointercapture", () => this.finishDrag());
    this.el.addEventListener("keydown", (e) => this.onKeyDown(e));
    this.el.addEventListener("focus", () => this.syncAria());
    // Сужение окна ужимает панель, расширение — возвращает желаемую ширину.
    // Свой resize не шлём: мы уже внутри обработчика, поток обновит main.ts.
    window.addEventListener("resize", () => {
      if (this.desiredWidth != null) this.renderWidth(false, false);
      else this.syncAria();
    });

    // Первый кадр: каркас уже смонтирован, можно показать реальную ширину.
    requestAnimationFrame(() => this.syncAria());
  }

  /* ── ширина ───────────────────────────────────────────────────────────── */

  /** Максимум: max(230, min(620, floor(ширина приложения * 0.38))). */
  private maxWidth(): number {
    const width = this.app.clientWidth || document.documentElement.clientWidth || window.innerWidth || 0;
    return Math.max(MAX_FLOOR, Math.min(MAX_CAP, Math.floor(width * MAX_SHARE)));
  }

  private clampBasic(width: number): number {
    return Math.max(MIN_WIDTH, Math.min(MAX_CAP, Math.round(width)));
  }

  private clampToViewport(width: number): number {
    return Math.max(MIN_WIDTH, Math.min(this.maxWidth(), Math.round(width)));
  }

  /** Текущая ширина для aria и старта перетаскивания. */
  private currentWidth(): number {
    if (this.appliedWidth != null) return this.appliedWidth;
    const measured = Math.round(this.rail.getBoundingClientRect().width);
    return measured > 0 ? measured : MIN_WIDTH;
  }

  /**
   * Перерисовать ширину: желаемая остаётся, в CSS пишется клампнутая по окну.
   * persist — записать желаемую ширину в localStorage.
   */
  private renderWidth(persist: boolean, notify = true): void {
    if (this.desiredWidth == null) return;
    this.appliedWidth = this.clampToViewport(this.desiredWidth);
    this.app.style.setProperty("--rail-size", `${this.appliedWidth}px`);
    this.syncAria();
    if (notify) this.notifyResize();
    if (persist) this.saveState();
  }

  /** Задать желаемую ширину (перетаскивание/клавиатура). */
  private applyWidth(width: number, persist: boolean): void {
    this.desiredWidth = this.clampBasic(width);
    this.renderWidth(persist);
  }

  private applyHidden(): void {
    if (this.hidden) this.app.dataset.railHidden = "true";
    else delete this.app.dataset.railHidden;
  }

  private setHidden(hidden: boolean): void {
    if (this.hidden === hidden) return;
    this.hidden = hidden;
    this.applyHidden();
    this.syncToggle();
    // При показе возвращаем последнюю ширину (с клампом по текущему окну).
    if (!hidden && this.desiredWidth != null) this.renderWidth(false, false);
    this.notifyResize();
    this.saveState();
  }

  private syncAria(): void {
    this.el.setAttribute("aria-valuemin", String(MIN_WIDTH));
    this.el.setAttribute("aria-valuemax", String(this.maxWidth()));
    this.el.setAttribute("aria-valuenow", String(this.currentWidth()));
  }

  private syncToggle(): void {
    this.toggle.textContent = this.hidden ? "› Показать панель" : "‹ Скрыть панель";
    this.toggle.setAttribute("aria-expanded", String(!this.hidden));
  }

  /** Поток перерисовывается по resize — шлём не чаще одного раза на кадр. */
  private notifyResize(): void {
    if (this.resizeScheduled) return;
    this.resizeScheduled = true;
    requestAnimationFrame(() => {
      this.resizeScheduled = false;
      window.dispatchEvent(new Event("resize"));
    });
  }

  /* ── перетаскивание ───────────────────────────────────────────────────── */

  private onPointerDown(e: PointerEvent): void {
    if (this.hidden) return;
    if (e.pointerType === "mouse" && e.button !== 0) return;
    e.preventDefault();
    this.drag = { pointerId: e.pointerId, startX: e.clientX, startWidth: this.currentWidth() };
    this.el.dataset.dragging = "true";
    this.el.setPointerCapture(e.pointerId);
    document.body.style.userSelect = "none";
    this.syncAria();
  }

  private onPointerMove(e: PointerEvent): void {
    const drag = this.drag;
    if (!drag || e.pointerId !== drag.pointerId) return;
    e.preventDefault();
    // persist=false: localStorage пишем один раз на отпускании указателя.
    this.applyWidth(drag.startWidth + (e.clientX - drag.startX), false);
  }

  private onPointerUp(e: PointerEvent): void {
    const drag = this.drag;
    if (!drag || e.pointerId !== drag.pointerId) return;
    this.finishDrag();
  }

  private finishDrag(): void {
    const drag = this.drag;
    if (!drag) return;
    this.drag = null;
    delete this.el.dataset.dragging;
    document.body.style.userSelect = "";
    if (this.el.hasPointerCapture(drag.pointerId)) this.el.releasePointerCapture(drag.pointerId);
    this.saveState();
  }

  /* ── клавиатура ──────────────────────────────────────────────────────── */

  private onKeyDown(e: KeyboardEvent): void {
    if (this.hidden) return;
    const current = this.currentWidth();
    let next: number | null = null;
    if (e.key === "ArrowLeft") next = current - KEY_STEP;
    else if (e.key === "ArrowRight") next = current + KEY_STEP;
    else if (e.key === "Home") next = MIN_WIDTH;
    else if (e.key === "End") next = this.maxWidth();
    if (next == null) return;
    e.preventDefault();
    this.applyWidth(next, true);
  }

  /* ── localStorage ────────────────────────────────────────────────────── */

  private loadState(): RailState {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { hidden: false, width: null };
      const parsed: unknown = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return { hidden: false, width: null };
      const rec = parsed as { hidden?: unknown; width?: unknown };
      const width = typeof rec.width === "number" && Number.isFinite(rec.width) ? Math.round(rec.width) : null;
      return { hidden: rec.hidden === true, width };
    } catch {
      // Битый JSON или недоступный localStorage — стартуем с состояния по умолчанию.
      return { hidden: false, width: null };
    }
  }

  private saveState(): void {
    try {
      // Сохраняем желаемую ширину, а не ужатую текущим окном.
      const state: RailState = { hidden: this.hidden, width: this.desiredWidth };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
      /* приватный режим/квота: состояние просто не сохранится */
    }
  }
}
