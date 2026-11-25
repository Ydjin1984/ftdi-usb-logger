/**
 * «Операции»: подтверждённый клик → вызовы J2534 → сигналы стенда → итог.
 *
 * Смысл панели — отвечать на вопросы, которые раньше требовали сверки трёх
 * файлов: где закончилась операция, был ли ответ ЭБУ, что происходило с GPT1,
 * GPT2 и питанием между кадрами, и какие вызовы драйвера остановили обмен.
 *
 * Правила отображения (docs/16):
 *  • «подтверждено кликом» — только `activation=invoke|click`; фокус операций
 *    не открывает и сюда не попадает;
 *  • границы из обмена помечены «предположительно»;
 *  • порядок «клик ↔ фронт сигнала» показывается как «неразличим», если он
 *    внутри допуска: фронт известен интервалом кадра, клик — моментом
 *    регистрации UI Automation.
 *
 * Компонент только рисует. Расчёт — в движке (`operations.json`).
 */

import { el } from "../dom";
import { store } from "../store";
import { msg, t } from "../i18n";
import type { Operation, OperationMilestone, OperationSignalNote } from "../types";

msg({
  "ОПЕРАЦИИ": "OPERATIONS",
  "подтверждено кликом": "confirmed click",
  "границы из обмена — предположительно": "derived from exchange — provisional",
  "ответ получен": "answer received",
  "ЭБУ отказал": "ECU denied",
  "тайм-аут": "timeout",
  "результат не установлен": "result unknown",
  "обмена не было": "no exchange",
  "доступ подтверждён": "access granted",
  "ключ отклонён": "key denied",
  "seed без ключа": "seed without key",
  "ключ не отправлен": "key not sent",
  "нет авторизации": "no security access",
  "участков: {n}": "segments: {n}",
  "до клика": "before click",
  "после клика": "after click",
  "порядок неразличим": "order indistinguishable",
  "порядок неизвестен": "order unknown",
  "шкала операции": "operation timeline",
  "ещё {n} сигналов…": "{n} more signals…",
  "файлы:": "files:",
  "нажмите на отметку — событие откроется в инспекторе":
    "click a mark to open the event in the inspector",
  "нет операций: подтверждённых действий и обмена не найдено":
    "no operations: no confirmed actions or exchange found",
  "подтверждённый клик": "confirmed click",
  "интервал кадра": "frame interval",
  "эвристика": "heuristic",
  "предположительно": "provisional",
});

function fmt2(v: number): string {
  return v.toFixed(2);
}

function fmtDur(sec: number): string {
  if (sec >= 60) return `${(sec / 60).toFixed(1)} мин`;
  return `${sec.toFixed(2)} с`;
}

function orderRu(order: string): string {
  switch (order) {
    case "before":
      return t("до клика");
    case "after":
      return t("после клика");
    case "ambiguous":
      return t("порядок неразличим");
    default:
      return t("порядок неизвестен");
  }
}

function resultRu(status: string): string {
  switch (status) {
    case "answer":
      return t("ответ получен");
    case "denied":
      return t("ЭБУ отказал");
    case "timeout":
      return t("тайм-аут");
    case "no_exchange":
      return t("обмена не было");
    case "driver_error":
      return t("ошибка драйвера");
    default:
      return t("результат не установлен");
  }
}

function authRu(status: string): string {
  switch (status) {
    case "granted":
      return t("доступ подтверждён");
    case "denied":
      return t("ключ отклонён");
    case "timeout":
      return t("тайм-аут");
    case "seed_only":
      return t("seed без ключа");
    case "none":
      return t("нет авторизации");
    default:
      return t("результат не установлен");
  }
}

function confidenceRu(confidence: string): string {
  switch (confidence) {
    case "bracket":
      return t("интервал кадра");
    case "heuristic":
      return t("эвристика");
    case "derived":
      return t("предположительно");
    default:
      return "";
  }
}

export class Operations {
  /** `<details class="ops-panel">`; вставляется в поток через `Stream.mountPanel`. */
  el: HTMLElement;
  private body: HTMLElement;
  private count: HTMLElement;
  private lastKey = "";

  constructor(private onPick?: (seq: number) => void) {
    const details = el("details", "ops-panel");
    details.open = true;
    const summary = el("summary", "ops-panel__summary");
    summary.append(el("span", "ops-panel__title", t("ОПЕРАЦИИ")));
    this.count = el("span", "ops-panel__count", "");
    summary.append(this.count);
    this.body = el("div", "ops-panel__body");
    details.append(summary, this.body);
    this.el = details;
  }

  update(): void {
    const doc = store.state.operations;
    const key = doc
      ? `${doc.session_id}|${doc.generated_at}|${doc.operations.length}`
      : "none";
    if (key === this.lastKey) return;
    this.lastKey = key;
    this.body.replaceChildren();
    if (!doc || doc.operations.length === 0) {
      this.el.hidden = true;
      return;
    }
    this.el.hidden = false;
    this.count.textContent = String(doc.operations.length);
    for (const op of doc.operations) this.body.append(this.card(op));
  }

  private card(op: Operation): HTMLElement {
    const card = el("article", `op-card op-card--${op.result.status}`);
    const head = el("div", "op-card__head");
    head.append(el("span", "op-card__idx", String(op.idx)));
    head.append(el("span", "op-card__name", op.name));
    head.append(
      el(
        "span",
        `op-card__origin ${op.origin === "confirmed" ? "is-confirmed" : "is-derived"}`,
        op.origin === "confirmed" ? t("подтверждено кликом") : t("границы из обмена — предположительно"),
      ),
    );
    head.append(el("span", "op-card__time", `${fmt2(op.t0)}–${fmt2(op.t1)} с`));
    card.append(head);

    const meta = el("div", "op-card__meta");
    meta.append(el("span", `op-chip op-chip--${op.result.status}`, resultRu(op.result.status)));
    meta.append(el("span", "op-chip op-chip--mute", fmtDur(op.t1 - op.t0)));
    meta.append(el("span", "op-chip", t("участков: {n}", { n: op.segments.length })));
    meta.append(el("span", "op-chip", `TX ${op.calls.tx_msgs} / RX ${op.calls.rx_msgs}`));
    if (op.calls.rx_empty > 0) {
      meta.append(el("span", "op-chip op-chip--mute", `+${op.calls.rx_empty} пустых`));
    }
    if (op.calls.empty_polls > 0) {
      meta.append(el("span", "op-chip op-chip--warn", `опросов без ответа: ${op.calls.empty_polls}`));
    }
    if (op.calls.driver_errors > 0) {
      meta.append(el("span", "op-chip op-chip--err", `ошибок драйвера: ${op.calls.driver_errors}`));
    }
    if (op.auth_status !== "none") {
      meta.append(el("span", `op-chip op-chip--auth-${op.auth_status}`, authRu(op.auth_status)));
    }
    card.append(meta);

    if (op.signals.length) {
      const sig = el("div", "op-card__signals");
      for (const s of op.signals.slice(0, 6)) sig.append(this.signalRow(s));
      if (op.signals.length > 6) {
        sig.append(el("div", "op-card__more", t("ещё {n} сигналов…", { n: op.signals.length - 6 })));
      }
      card.append(sig);
    }

    const det = el("details", "op-card__timeline");
    det.append(el("summary", "", t("шкала операции")));
    const list = el("ol", "op-milestones");
    for (const m of op.milestones) list.append(this.milestoneRow(m));
    det.append(list);
    det.title = t("нажмите на отметку — событие откроется в инспекторе");
    card.append(det);

    card.append(el("div", "op-card__result", op.result.text));
    if (op.files.length) {
      card.append(el("div", "op-card__files", `${t("файлы:")} ${op.files.join(" · ")}`));
    }
    for (const note of op.notes) card.append(el("div", "op-card__note", note));
    return card;
  }

  private signalRow(s: OperationSignalNote): HTMLElement {
    const row = el("div", `op-sig op-sig--${s.order}`);
    row.append(el("span", "op-sig__name", s.name));
    row.append(el("span", "op-sig__order", orderRu(s.order)));
    row.append(el("span", "op-sig__text", s.text));
    const bracket =
      s.t_before != null ? `${fmt2(s.t_before)}–${fmt2(s.t_after)}` : fmt2(s.t_after);
    row.append(el("span", "op-sig__time", `${bracket} с`));
    if (s.note) row.title = s.note;
    return row;
  }

  private milestoneRow(m: OperationMilestone): HTMLElement {
    const li = el("li", `op-ms op-ms--${m.kind}`);
    li.append(el("span", "op-ms__t", m.t.toFixed(3)));
    li.append(el("span", "op-ms__dot"));
    li.append(el("span", "op-ms__label", m.label));
    if (m.t_source) li.append(el("span", "op-ms__src", m.t_source));
    const conf = confidenceRu(m.confidence);
    if (conf) li.append(el("span", "op-ms__conf", conf));
    if (m.detail) li.title = m.detail;
    if (m.seq != null && this.onPick) {
      li.classList.add("is-clickable");
      li.addEventListener("click", () => this.onPick?.(m.seq as number));
    }
    return li;
  }
}
