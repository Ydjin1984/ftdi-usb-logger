/** Транспортная панель: шаг, метки, пауза хуков, скриншот, стоп, экспорт. */

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
  private pauseBtn: HTMLButtonElement;
  private chips: HTMLElement;
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

    // Шаг и быстрые названия
    const stepGroup = el("div", "transport__group");
    this.stepBtn = el("button", "btn btn--step");
    this.stepBtn.type = "button";
    this.stepBtn.addEventListener("click", () => void this.toggleStep());
    stepGroup.append(this.stepBtn);

    this.chips = el("div", "transport__group");
    stepGroup.append(this.chips);
    this.el.append(stepGroup);

    const spacer = el("div", "transport__spacer");
    this.el.append(spacer);

    // Действия
    const actions = el("div", "transport__group");
    actions.append(
      this.action("F5", "метка", "mark", () => openMarkPrompt()),
      (this.pauseBtn = this.action("F6", "пауза хуков", "pause", () => {
        const paused = store.state.status?.hooks === "paused";
        void store.hookctl(paused ? "resume" : "pause");
      })),
      this.action("F8", "скриншот", "camera", () => void store.shot()),
      this.action("Esc", "стоп", "stop", () => openStopConfirm()),
    );
    this.el.append(actions);

    const right = el("div", "transport__group");
    const exportBtn = this.action("Ctrl+E", "экспорт", "download", () => openExportDialog());
    exportBtn.classList.add("btn--primary");
    const importBtn = this.action("Ctrl+O", "импорт", "upload", () => void store.importLog());
    const templates = this.action("", "", "settings", () => openTemplatesDialog());
    right.append(exportBtn, importBtn, templates);
    this.el.append(right);

    this.update();
  }

  private action(hint: string, label: string, ic: string, onClick: () => void): HTMLButtonElement {
    const b = el("button", "btn");
    b.type = "button";
    b.appendChild(icon(ic));
    if (label) b.appendChild(el("span", "", label));
    if (hint) {
      const k = el("span", "kbd", hint);
      k.style.marginLeft = "2px";
      b.appendChild(k);
    }
    b.addEventListener("click", onClick);
    return b;
  }

  private async toggleStep(): Promise<void> {
    if (store.state.currentStep) await store.endStep();
    else await store.startStep();
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

    const key = [stepOpen, s.currentStep?.idx ?? 0, s.active?.id ?? "", s.quickTitles.join(","), s.status?.hooks ?? ""].join("|");
    if (key !== this.lastKey) {
      this.lastKey = key;
      // Кнопка шага
      this.stepBtn.replaceChildren(icon(stepOpen ? "stepStop" : "step"));
      this.stepBtn.append(
        el("span", "", stepOpen ? "ЗАКРЫТЬ ШАГ" : "ШАГ"),
        el("span", "kbd", "F2"),
      );
      this.stepBtn.classList.toggle("is-open", stepOpen);
      this.stepBtn.disabled = !s.active;
      this.stepBtn.title = stepOpen
        ? "закрыть шаг и собрать сводку (F2)"
        : "открыть шаг с автоназванием (F2), Shift+F2 — с названием";

      // Быстрые названия
      this.chips.replaceChildren();
      if (!stepOpen) {
        for (const title of s.quickTitles.slice(0, 4)) {
          const b = el("button", "chip", title);
          b.type = "button";
          b.title = `открыть шаг «${title}»`;
          b.disabled = !s.active;
          b.addEventListener("click", () => void store.startStep(title));
          this.chips.append(b);
        }
      }

      // Пауза хуков
      const paused = s.status?.hooks === "paused";
      this.pauseBtn.replaceChildren(icon(paused ? "play" : "pause"), el("span", "", paused ? "вернуть" : "пауза"));
      this.pauseBtn.title = paused ? "вернуть хуки (F6)" : "снять хуки на время операции (F6)";
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
