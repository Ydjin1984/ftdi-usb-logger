/** Транспортная панель: шаг, пресеты действий, метка, пауза, скриншот, стоп, экспорт. */

import { el, icon } from "../dom";
import { fmtBytes, fmtClock, fmtNum } from "../format";
import { store } from "../store";
import { openExportDialog, openMarkPrompt, openStopConfirm, openTemplatesDialog } from "./dialogs";

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

    // Таймер и счётчики
    const timer = el("div", "transport__group transport__timer");
    this.rec = el("div", "rec");
    const timerText = el("div");
    this.timerLabel = el("div", "transport__timer-label", "сессия");
    this.timerValue = el("div", "transport__timer-value", "00:00");
    timerText.append(this.timerLabel, this.timerValue);
    timer.append(this.rec, timerText);

    this.countsEl = el("div", "transport__counts");
    this.el.append(timer, this.countsEl);

    // Шаг: компактная кнопка + комбо пресетов + настройка пресетов
    const stepGroup = el("div", "transport__group");
    this.stepBtn = el("button", "btn btn--step btn--icon");
    this.stepBtn.type = "button";
    this.stepBtn.addEventListener("click", () => void this.toggleStep());
    this.stepBtn.replaceChildren(icon("step"));

    this.presetSel = el("select", "transport__preset");
    this.presetSel.title = "пресеты действий: выберите — шаг откроется (предыдущий закроется). Шестерёнка — редактировать список";
    this.presetSel.addEventListener("change", () => void this.applyPreset());

    const presetEdit = el("button", "btn btn--icon");
    presetEdit.type = "button";
    presetEdit.title = "пресеты действий: добавить, удалить, вернуть стандартные";
    presetEdit.appendChild(icon("settings"));
    presetEdit.addEventListener("click", () => openTemplatesDialog());

    stepGroup.append(this.stepBtn, this.presetSel, presetEdit);
    this.el.append(stepGroup);

    const spacer = el("div", "transport__spacer");
    this.el.append(spacer);

    // Действия — только иконки, название всплывает при наведении
    const actions = el("div", "transport__group");
    actions.append(
      this.action("F5", "метка в потоке", "mark", () => openMarkPrompt()),
      (this.pauseBtn = this.action("F6", "пауза хуков", "pause", () => {
        const paused = store.state.status?.hooks === "paused";
        void store.hookctl(paused ? "resume" : "pause");
      })),
      this.action("F8", "скриншот окна", "camera", () => void store.shot()),
      this.action("Esc", "остановить сессию", "stop", () => openStopConfirm()),
    );
    this.el.append(actions);

    const right = el("div", "transport__group");
    const exportBtn = this.action("Ctrl+E", "экспорт сессии", "download", () => openExportDialog());
    exportBtn.classList.add("btn--primary");
    const importBtn = this.action("Ctrl+O", "импорт старого лога", "upload", () => void store.importLog());
    right.append(exportBtn, importBtn);
    this.el.append(right);

    this.update();
  }

  /** Иконка без подписи; полное название и горячая клавиша — в подсказке при наведении. */
  private action(hint: string, label: string, ic: string, onClick: () => void): HTMLButtonElement {
    const b = el("button", "btn btn--icon");
    b.type = "button";
    b.title = hint ? `${label} (${hint})` : label;
    b.setAttribute("aria-label", label);
    b.appendChild(icon(ic));
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
      store.toast("warn", "нет активной сессии — сначала подключитесь к программе");
      return;
    }
    if (store.state.currentStep) await store.endStep();
    await store.startStep(value);
  }

  update(): void {
    const s = store.state;
    const stepOpen = !!s.currentStep;
    const recording = !!s.status?.recording || s.mode === "demo";

    // Таймер
    const base = stepOpen ? s.stepStartEpoch : s.status?.started_at ? Date.parse(s.status.started_at) : 0;
    const seconds = base ? (s.tick - base) / 1000 : 0;
    this.timerValue.textContent = base ? fmtClock(seconds) : "00:00";
    this.timerLabel.textContent = stepOpen
      ? `шаг ${s.currentStep?.idx} · ${s.currentStep?.title ?? ""}`.slice(0, 42)
      : recording
        ? "сессия идёт"
        : "ожидание";
    this.rec.classList.toggle("rec--on", recording && !stepOpen);
    this.rec.classList.toggle("rec--step", stepOpen);
    if (stepOpen) {
      this.rec.style.borderColor = "var(--mark)";
      this.rec.style.background = "var(--mark)";
    } else {
      this.rec.style.borderColor = "";
      this.rec.style.background = "";
    }

    const counts = s.status?.counts ?? s.active?.counts ?? null;
    this.countsEl.replaceChildren(
      countItem("TX", counts ? fmtNum(counts.tx) : "0", counts ? fmtBytes(counts.tx_bytes) : "", "tx"),
      countItem("RX", counts ? fmtNum(counts.rx) : "0", counts ? fmtBytes(counts.rx_bytes) : "", "rx"),
    );

    const key = [
      stepOpen,
      s.currentStep?.idx ?? 0,
      s.active?.id ?? "",
      s.quickTitles.join(","),
      s.status?.hooks ?? "",
      s.active ? 1 : 0,
    ].join("|");
    if (key !== this.lastKey) {
      this.lastKey = key;

      this.stepBtn.replaceChildren(icon(stepOpen ? "stepStop" : "step"));
      this.stepBtn.classList.toggle("is-open", stepOpen);
      this.stepBtn.disabled = !s.active;
      this.stepBtn.title = stepOpen
        ? "закрыть шаг и собрать сводку (F2)"
        : "открыть шаг с автоназванием (F2); Shift+F2 — с названием";

      // Комбо пресетов: строится из сохранённого списка
      const current = this.presetSel.value;
      this.presetSel.replaceChildren();
      const placeholder = el("option");
      placeholder.value = "";
      placeholder.textContent = s.active
        ? stepOpen
          ? "следующее действие…"
          : "быстрое действие…"
        : "нет сессии";
      this.presetSel.append(placeholder);
      for (const title of s.quickTitles) {
        const o = el("option");
        o.value = title;
        o.textContent = title;
        this.presetSel.append(o);
      }
      this.presetSel.value = current && s.quickTitles.includes(current) ? current : "";
      this.presetSel.disabled = !s.active;

      const paused = s.status?.hooks === "paused";
      this.pauseBtn.replaceChildren(icon(paused ? "play" : "pause"));
      this.pauseBtn.title = paused ? "вернуть хуки (F6)" : "снять хуки на время операции (F6)";
      this.pauseBtn.classList.toggle("is-open", paused);
      this.pauseBtn.disabled = s.mode === "demo" ? true : !s.status?.bridge;
    }
  }
}

function countItem(label: string, value: string, bytes: string, cls: string): HTMLElement {
  const d = el("div");
  const l = el("div", "transport__timer-label", label);
  const v = el("div", `mono ${cls}`.trim());
  v.style.fontSize = "13px";
  v.textContent = value;
  const b = el("div", "transport__timer-label", bytes);
  d.append(l, v, b);
  return d;
}
