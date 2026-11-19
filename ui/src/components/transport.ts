/**
 * Нижняя панель: статистика записи, шаг с пресетами и действия.
 *
 * Разметку группирует сам компонент (в референсе это делала демо-обвязка
 * setupLayout): `.transport` — это grid из трёх групп:
 *   .transport__stats   — индикатор записи, таймер сессии/шага, счётчики TX/RX;
 *   .transport__steps   — шестерёнка пресетов, кнопка шага, комбо пресетов;
 *   .transport__actions — Метка, Пауза|Продолжить, Снимок, Стоп, Экспорт, Импорт.
 */

import { el, icon } from "../dom";
import { fmtBytes, fmtClock, fmtNum } from "../format";
import { store } from "../store";
import { openExportDialog, openMarkPrompt, openStopConfirm, openTemplatesDialog } from "./dialogs";
import { msg, t } from "../i18n";

msg({
  "сессия": "session",
  "пресеты действий: добавить, удалить, вернуть стандартные":
    "action presets: add, remove, restore defaults",
  "Настроить быстрые действия": "Configure quick actions",
  "пресеты действий: выберите — шаг откроется (предыдущий закроется). Шестерёнка — редактировать список":
    "action presets: pick one to open a step (the previous one closes). The gear edits the list",
  "Пауза": "Pause",
  "Продолжить": "Resume",
  "пауза хуков": "hooks paused",
  "Экспорт": "Export",
  "экспорт сессии": "export session",
  "Метка": "Mark",
  "метка в потоке": "mark in the stream",
  "Снимок": "Shot",
  "скриншот окна": "window screenshot",
  "Стоп": "Stop",
  "остановить сессию": "stop the session",
  "Импорт": "Import",
  "импорт старого лога": "import an old log",
  "шаг {n} · {title}": "step {n} · {title}",
  "сессия идёт": "recording",
  "ожидание": "idle",
  "Завершить шаг": "End step",
  "Новый шаг": "New step",
  "закрыть шаг и собрать сводку (F2)": "close the step and collect a summary (F2)",
  "открыть шаг с автоназванием (F2); Shift+F2 — с названием":
    "open a step with an automatic name (F2); Shift+F2 for a manual name",
  "следующее действие…": "next action…",
  "быстрое действие…": "quick action…",
  "нет сессии": "no session",
  "вернуть хуки (F6)": "restore hooks (F6)",
  "снять хуки на время операции (F6)": "remove hooks for the operation (F6)",
  "Продолжить запись": "Resume recording",
  "Пауза записи": "Pause recording",
});

export class Transport {
  el: HTMLElement;
  private timerValue: HTMLElement;
  private timerLabel: HTMLElement;
  private rec: HTMLElement;
  private countsEl: HTMLElement;
  private stepBtn: HTMLButtonElement;
  private presetSel: HTMLSelectElement;
  private pauseBtn: HTMLButtonElement;
  private lastKey = "";

  constructor() {
    this.el = el("footer", "transport");

    /* ── 1. Статистика: rec-индикатор, таймер и счётчики ─────────────────── */
    const stats = el("div", "transport__stats");
    const timer = el("div", "transport__group transport__timer");
    this.rec = el("div", "rec");
    const timerText = el("div");
    this.timerLabel = el("div", "transport__timer-label", t("сессия"));
    this.timerValue = el("div", "transport__timer-value", "00:00");
    timerText.append(this.timerLabel, this.timerValue);
    timer.append(this.rec, timerText);
    this.countsEl = el("div", "transport__counts");
    stats.append(timer, this.countsEl);
    this.el.append(stats);

    /* ── 2. Шаг: настройка пресетов, кнопка шага, комбо пресетов ─────────── */
    const steps = el("div", "transport__group transport__steps");

    // Шестерёнка — редактор списка быстрых действий (была справа от комбо).
    const presetEdit = el("button", "btn btn--icon");
    presetEdit.type = "button";
    presetEdit.title = t("пресеты действий: добавить, удалить, вернуть стандартные");
    presetEdit.setAttribute("aria-label", t("Настроить быстрые действия"));
    presetEdit.append(icon("settings"));
    presetEdit.addEventListener("click", () => openTemplatesDialog());

    this.stepBtn = el("button", "btn btn--step btn--icon");
    this.stepBtn.type = "button";
    this.stepBtn.addEventListener("click", () => void this.toggleStep());
    this.stepBtn.replaceChildren(icon("step"));

    this.presetSel = el("select", "transport__preset");
    this.presetSel.title = t(
      "пресеты действий: выберите — шаг откроется (предыдущий закроется). Шестерёнка — редактировать список",
    );
    this.presetSel.addEventListener("change", () => void this.applyPreset());

    steps.append(presetEdit, this.stepBtn, this.presetSel);
    this.el.append(steps);

    /* ── 3. Действия — ровно в порядке ТЗ, с видимым текстом ─────────────── */
    const actions = el("div", "transport__actions");

    this.pauseBtn = this.action(t("Пауза"), t("пауза хуков"), "F6", "pause", () => {
      const paused = store.state.status?.hooks === "paused";
      void store.hookctl(paused ? "resume" : "pause");
    });

    const exportBtn = this.action(t("Экспорт"), t("экспорт сессии"), "Ctrl+E", "download", () => openExportDialog());
    exportBtn.classList.add("btn--primary");

    actions.append(
      this.action(t("Метка"), t("метка в потоке"), "F5", "mark", () => openMarkPrompt()),
      this.pauseBtn,
      this.action(t("Снимок"), t("скриншот окна"), "F8", "camera", () => void store.shot()),
      this.action(t("Стоп"), t("остановить сессию"), "Esc", "stop", () => openStopConfirm()),
      exportBtn,
      this.action(t("Импорт"), t("импорт старого лога"), "Ctrl+O", "upload", () => void store.importLog()),
    );
    this.el.append(actions);

    this.update();
  }

  /** Кнопка действия: иконка + подпись; полное название и горячая клавиша — в title/aria-label. */
  private action(text: string, label: string, hint: string, ic: string, onClick: () => void): HTMLButtonElement {
    const b = el("button", "btn btn--icon");
    b.type = "button";
    b.title = hint ? `${label} (${hint})` : label;
    b.setAttribute("aria-label", label);
    b.append(icon(ic), document.createTextNode(text));
    b.addEventListener("click", onClick);
    return b;
  }

  private async toggleStep(): Promise<void> {
    if (store.state.currentStep) await store.endStep();
    else await store.startStep();
  }

  /** Выбранный пресет: закрыть текущий шаг (если открыт) и открыть новый. */
  private async applyPreset(): Promise<void> {
    const value = this.presetSel.value;
    this.presetSel.value = "";
    if (!value) return;
    if (!store.state.active) {
      store.toast("warn", t("нет активной сессии — сначала подключитесь к программе"));
      return;
    }
    if (store.state.currentStep) await store.endStep();
    await store.startStep(value);
  }

  update(): void {
    const s = store.state;
    const stepOpen = !!s.currentStep;
    const recording = !!s.status?.recording;

    // Таймер: при открытом шаге считаем от шага, иначе от старта сессии.
    const base = stepOpen ? s.stepStartEpoch : s.status?.started_at ? Date.parse(s.status.started_at) : 0;
    const seconds = base ? (s.tick - base) / 1000 : 0;
    this.timerValue.textContent = base ? fmtClock(seconds) : "00:00";
    this.timerLabel.textContent = stepOpen
      ? t("шаг {n} · {title}", { n: s.currentStep?.idx ?? 0, title: s.currentStep?.title ?? "" }).slice(0, 42)
      : recording
        ? t("сессия идёт")
        : t("ожидание");
    this.rec.classList.toggle("rec--on", recording && !stepOpen);
    this.rec.classList.toggle("rec--step", stepOpen);
    if (stepOpen) {
      this.rec.style.borderColor = "var(--mark)";
      this.rec.style.background = "var(--mark)";
    } else {
      this.rec.style.borderColor = "";
      this.rec.style.background = "";
    }

    // Счётчики TX/RX: число и объём с единицами, без переноса и с tabular-nums.
    const counts = s.status?.counts ?? s.active?.counts ?? null;
    this.countsEl.replaceChildren(
      countItem("TX", counts ? fmtNum(counts.tx) : "0", counts ? fmtBytes(counts.tx_bytes) : "", "tx"),
      countItem("RX", counts ? fmtNum(counts.rx) : "0", counts ? fmtBytes(counts.rx_bytes) : "", "rx"),
    );

    // Перерисовываем кнопки только при изменении значимого состояния.
    const key = [
      recording,
      stepOpen,
      s.currentStep?.idx ?? 0,
      s.active?.id ?? "",
      s.quickTitles.join(","),
      s.status?.hooks ?? "",
      s.active ? 1 : 0,
    ].join("|");
    if (key !== this.lastKey) {
      this.lastKey = key;

      this.stepBtn.replaceChildren(
        icon(stepOpen ? "stepStop" : "step"),
        document.createTextNode(stepOpen ? t("Завершить шаг") : t("Новый шаг")),
      );
      this.stepBtn.classList.toggle("is-open", stepOpen);
      this.stepBtn.disabled = !s.active;
      this.stepBtn.title = stepOpen
        ? t("закрыть шаг и собрать сводку (F2)")
        : t("открыть шаг с автоназванием (F2); Shift+F2 — с названием");

      // Комбо пресетов: строится из сохранённого списка.
      const current = this.presetSel.value;
      this.presetSel.replaceChildren();
      const placeholder = el("option");
      placeholder.value = "";
      placeholder.textContent = s.active
        ? stepOpen
          ? t("следующее действие…")
          : t("быстрое действие…")
        : t("нет сессии");
      this.presetSel.append(placeholder);
      for (const title of s.quickTitles) {
        const o = el("option");
        o.value = title;
        o.textContent = t(title);
        this.presetSel.append(o);
      }
      this.presetSel.value = current && s.quickTitles.includes(current) ? current : "";
      this.presetSel.disabled = !s.active;

      const paused = s.status?.hooks === "paused";
      this.pauseBtn.replaceChildren(
        icon(paused ? "play" : "pause"),
        document.createTextNode(paused ? t("Продолжить") : t("Пауза")),
      );
      this.pauseBtn.title = paused ? t("вернуть хуки (F6)") : t("снять хуки на время операции (F6)");
      this.pauseBtn.setAttribute("aria-label", paused ? t("Продолжить запись") : t("Пауза записи"));
      this.pauseBtn.classList.toggle("is-open", paused);
      this.pauseBtn.disabled = !recording || !s.status?.bridge;
    }
  }
}

/** Ячейка счётчика: подпись, значение и объём в байтах (каждая строка не переносится). */
function countItem(label: string, value: string, bytes: string, cls: string): HTMLElement {
  const d = el("div");
  const l = el("div", "transport__timer-label", label);
  const v = el("div", `mono ${cls}`.trim());
  v.style.fontSize = "13px";
  v.style.fontVariantNumeric = "tabular-nums";
  v.style.whiteSpace = "nowrap";
  v.textContent = value;
  const b = el("div", "transport__timer-label", bytes);
  b.style.fontVariantNumeric = "tabular-nums";
  b.style.whiteSpace = "nowrap";
  d.append(l, v, b);
  return d;
}
