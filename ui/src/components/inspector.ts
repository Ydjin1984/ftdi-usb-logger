/** Правая колонка: инспектор события, шага и сессии. */

import { api, sessionFileUrl } from "../api";
import { el, icon, iconButton } from "../dom";
import { fmtBytes, fmtDurationSeconds, fmtNum, fmtTime, asciiPreview, bytesToHex, fmtDate } from "../format";
import { store } from "../store";
import type { Event, StepSummary } from "../types";
import { openImage } from "./dialogs";
import { msg, t } from "../i18n";
import {
  j2534LayersLine,
  proxyBadge,
  proxyLine,
  proxyLineTitle,
  proxyNeedsAttention,
} from "../proxy";

msg({
  "событие": "event",
  "шаг": "step",
  "сессия": "session",
  "СОБЫТИЕ": "EVENT",
  "Кликните строку в потоке — здесь появится HEX/ASCII, декод и контекст.":
    "Click a row in the stream — HEX/ASCII, decoding and context will appear here.",
  "СОБЫТИЕ #{seq}": "EVENT #{seq}",
  "скопировать hex": "copy hex",
  "скопировано": "copied",
  "тип": "type",
  "время": "time",
  "длина": "length",
  "ШАГ": "STEP",
  "Нет активной сессии.": "No active session.",
  "ШАГ {n}": "STEP {n}",
  "идёт · {dur}": "running · {dur}",
  "обменов": "exchanges",
  "длительность": "duration",
  "СВОДКИ ШАГОВ · {n}": "STEP SUMMARIES · {n}",
  "Шаг идёт — сводка появится после закрытия (F2).":
    "The step is running — a summary appears after it closes (F2).",
  "Шагов пока нет. F2 открывает шаг, повторное F2 — закрывает и собирает сводку.":
    "No steps yet. F2 opens a step, F2 again closes it and collects a summary.",
  "без названия": "untitled",
  "чтений": "reads",
  "КОМАНДЫ": "COMMANDS",
  "ОТВЕТЫ": "RESPONSES",
  "ЧТЕНИЯ ПАМЯТИ": "MEMORY READS",
  "ФАЙЛЫ": "FILES",
  "СКРИНШОТ": "SCREENSHOT",
  "ВЕРДИКТ": "VERDICT",
  "{bytes} · блоков {n} · {sha}…": "{bytes} · blocks {n} · {sha}…",
  "файл": "file",
  "скриншот шага {n}": "screenshot of step {n}",
  "шаг {n}: {title}": "step {n}: {title}",
  "шаг {n} · {title}": "step {n} · {title}",
  "эхо": "echo",
  "да": "yes",
  "отказов": "denied",
  "без ответа": "no answer",
  "не разобрано": "unparsed",
  "СЕССИЯ": "SESSION",
  "Сессия не выбрана.": "No session selected.",
  "событий": "events",
  "начало": "start",
  "конец": "end",
  "процесс": "process",
  "транспорт": "transport",
  "шнурок": "cable",
  "версия": "version",
  "движок": "engine",
  "факт": "fact",
  "СКРИНШОТЫ · {n}": "SCREENSHOTS · {n}",
  "ОТЧЁТ": "REPORT",
  "скрыть отчёт": "hide report",
  "собрать и показать отчёт": "build and show the report",
  "собираю…": "packing…",
  "отчёт не собрался: {msg}": "the report was not built: {msg}",
  "ЗАМЕТКИ · {n}": "NOTES · {n}",
  "Пока нет заметок.": "No notes yet.",
  "заметка к сессии (Ctrl+Enter — сохранить)": "session note (Ctrl+Enter to save)",
  "добавить заметку": "add note",
  "байт": "bytes",
  "направление": "direction",
  "RX (из ЭБУ)": "RX (from ECU)",
  "TX (в ЭБУ)": "TX (to ECU)",
  "ответ": "response",
  "A0 (положительный), payload {n} B": "A0 (positive), payload {n} B",
  "nrc": "nrc",
  "команда": "command",
  "операция": "operation",
  "адрес": "address",
  // События осциллографа и нажатий кнопок целевой программы.
  "действие": "action",
  "тип элемента": "control type",
  "окно": "window",
  "источник": "source",
  "состояние": "state",
  "кадры": "frames",
  "пропуски": "gaps",
  "деградация": "degraded",
  "название": "name",
  "описание": "description",
});


type Tab = "event" | "step" | "session";

export class Inspector {
  el: HTMLElement;
  private tabsEl: HTMLElement;
  private body: HTMLElement;
  private tab: Tab = "step";
  private lastKey = "";
  private stepOpenIdx: number | null = null;
  private reportText: string | null = null;
  private reportFor: string | null = null;

  constructor() {
    this.el = el("aside", "inspect");
    this.tabsEl = el("div", "tabs");
    // A11y: вкладки как tablist/tab (сверх референса — требование ТЗ).
    this.tabsEl.setAttribute("role", "tablist");
    const defs: Array<[Tab, string]> = [
      ["event", t("событие")],
      ["step", t("шаг")],
      ["session", t("сессия")],
    ];
    for (const [id, label] of defs) {
      const b = el("button", "tab", label);
      b.type = "button";
      b.dataset.tab = id;
      b.setAttribute("role", "tab");
      b.setAttribute("aria-selected", String(id === this.tab));
      b.addEventListener("click", () => {
        this.tab = id;
        this.refresh(true);
      });
      this.tabsEl.append(b);
    }
    this.body = el("div", "inspect__body");
    this.el.append(this.tabsEl, this.body);
    this.refresh(true);
  }

  update(): void {
    const s = store.state;
    const key = [
      this.tab,
      s.selection?.seq ?? "none",
      s.currentStep?.idx ?? "none",
      s.steps.length,
      s.active?.id ?? "none",
      s.events.length,
      s.notes.length,
      Math.floor((s.tick % 1000) / 1000),
    ].join("|");
    if (key === this.lastKey) return;
    this.lastKey = key;
    this.refresh(false);
  }

  private refresh(markTabs: boolean): void {
    if (markTabs) {
      for (const b of Array.from(this.tabsEl.children) as HTMLElement[]) {
        const active = b.dataset.tab === this.tab;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", String(active));
      }
    } else {
      for (const b of Array.from(this.tabsEl.children) as HTMLElement[]) {
        const active = b.dataset.tab === this.tab;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", String(active));
      }
    }
    this.body.replaceChildren();
    if (this.tab === "event") this.renderEvent();
    else if (this.tab === "step") this.renderStep();
    else this.renderSession();
  }

  /* ────────────────────────────── событие ─────────────────────────────── */

  private renderEvent(): void {
    const s = store.state;
    const ev = s.selection;
    if (!ev) {
      this.body.append(
        section(t("СОБЫТИЕ"), t("Кликните строку в потоке — здесь появится HEX/ASCII, декод и контекст.")),
      );
      return;
    }
    const sec = el("section", "sec");
    const head = el("div", "sec__head");
    head.append(el("span", "sec__title", t("СОБЫТИЕ #{seq}", { seq: ev.seq })));
    const copy = iconButton("copy", t("скопировать hex"), () => {
      void navigator.clipboard?.writeText(ev.hex || ev.raw);
      store.toast("ok", t("скопировано"));
    });
    head.append(copy);
    sec.append(head);

    const props = el("div", "decoded");
    prop(props, t("тип"), `${ev.kind} · ${ev.transport}`);
    prop(props, t("время"), `${fmtTime(ev.t)} · ${fmtDate(ev.wall)}`);
    prop(props, "api", ev.api || "—");
    // Номер вызова, индекс сообщения, счётчики и тайминги J2534 (контракт 0.3.3).
    for (const [label, value] of j2534CallProps(ev)) prop(props, label, value);
    if (ev.len) prop(props, t("длина"), fmtBytes(ev.len));
    if (ev.rc != null) prop(props, "rc", String(ev.rc));
    if (ev.step != null) prop(props, t("шаг"), String(ev.step));
    sec.append(props);

    // Новые типы (осциллограф и нажатия кнопок): в meta лежит всё содержательное,
    // и без отдельной ветки инспектор показывал бы только «RAW».
    const kindMeta = kindMetaProps(ev);
    if (kindMeta.length) {
      sec.append(el("hr", "hr"));
      const box = el("div", "decoded");
      for (const [k, v] of kindMeta) prop(box, k, v);
      sec.append(box);
    }

    if (ev.hex) {
      sec.append(el("hr", "hr"));
      const hexBox = el("div", "hex");
      for (const line of hexLines(ev.hex)) {
        const row = el("div", "hex__line");
        row.append(
          el("span", "hex__addr", line.addr),
          el("span", "hex__bytes", line.bytes),
          el("span", "hex__ascii", line.ascii),
        );
        hexBox.append(row);
      }
      sec.append(hexBox);

      const dec = decodeKwp(ev.hex, ev.direction ?? undefined);
      if (dec.length) {
        sec.append(el("hr", "hr"));
        const box = el("div", "decoded");
        for (const [k, v, cls] of dec) prop(box, k, v, cls);
        sec.append(box);
      }
    }

    if (ev.raw) {
      sec.append(el("hr", "hr"));
      const raw = el("div", "decoded__val");
      raw.style.fontFamily = "var(--font-mono)";
      raw.style.fontSize = "10.5px";
      raw.style.color = "var(--text-dim)";
      raw.style.overflowWrap = "anywhere";
      raw.textContent = ev.raw;
      sec.append(raw);
    }
    this.body.append(sec);
  }

  /* ────────────────────────────── шаг ─────────────────────────────────── */

  private renderStep(): void {
    const s = store.state;
    if (!s.active) {
      this.body.append(section(t("ШАГ"), t("Нет активной сессии.")));
      return;
    }

    // Текущий открытый шаг
    if (s.currentStep) {
      const cur = s.currentStep;
      const live = (s.tick - s.stepStartEpoch) / 1000;
      const stats = this.liveStepStats(cur.idx);
      const sec = el("section", "sec");
      const card = el("div");
      const titleEl = el("div", "step-card__title");
      titleEl.append(
        el("span", "step-card__no", t("ШАГ {n}", { n: cur.idx })),
        el("span", "", cur.title),
      );
      const sub = el("div", "muted");
      sub.style.fontSize = "11px";
      sub.textContent = t("идёт · {dur}", { dur: fmtDurationSeconds(live) });
      card.append(titleEl, sub);
      const grid = el("div", "step-card__stats");
      grid.append(
        stat(t("обменов"), fmtNum(stats.exchanges)),
        stat(t("длительность"), fmtDurationSeconds(live)),
        stat("TX", fmtBytes(stats.tx_bytes), "tx"),
        stat("RX", fmtBytes(stats.rx_bytes), "rx"),
      );
      card.append(grid);
      sec.append(card);
      this.body.append(sec);
    }

    // Сводки
    const steps = [...s.steps].sort((a, b) => a.idx - b.idx);
    const secList = el("section", "sec");
    const head = el("div", "sec__head");
    head.append(el("span", "sec__title", t("СВОДКИ ШАГОВ · {n}", { n: steps.length })));
    secList.append(head);
    if (!steps.length) {
      secList.append(
        div(
          "muted",
          s.currentStep
            ? t("Шаг идёт — сводка появится после закрытия (F2).")
            : t("Шагов пока нет. F2 открывает шаг, повторное F2 — закрывает и собирает сводку."),
        ),
      );
    } else {
      const list = el("div", "decoded");
      for (const st of steps) {
        const row = el("button", "session-item");
        row.type = "button";
        row.style.width = "100%";
        row.style.textAlign = "left";
        const title = el("div", "session-item__title");
        title.append(el("span", "step-card__no", String(st.idx)), el("span", "", st.title || t("без названия")));
        const time = el("div", "session-item__time", fmtDurationSeconds(st.dur));
        const meta = el("div", "session-item__meta");
        meta.append(
          bpair(t("обменов"), fmtNum(st.exchanges)),
          bpair("TX", fmtBytes(st.tx_bytes)),
          bpair("RX", fmtBytes(st.rx_bytes)),
          bpair(t("чтений"), String((st.reads ?? []).length)),
        );
        if (this.stepOpenIdx === st.idx) row.classList.add("is-active");
        row.append(title, time, meta);
        row.addEventListener("click", () => {
          this.stepOpenIdx = this.stepOpenIdx === st.idx ? null : st.idx;
          this.lastKey = "";
          this.update();
        });
        list.append(row);
        if (this.stepOpenIdx === st.idx) list.append(this.stepDetails(st));
      }
      secList.append(list);
    }
    this.body.append(secList);
  }

  /** Живые счётчики открытого шага по уже загруженным событиям. */
  private liveStepStats(idx: number): { exchanges: number; tx_bytes: number; rx_bytes: number } {
    let exchanges = 0;
    let tx_bytes = 0;
    let rx_bytes = 0;
    for (const e of store.state.events) {
      if (e.step !== idx) continue;
      if (e.kind === "tx") {
        exchanges += 1;
        tx_bytes += e.len;
      } else if (e.kind === "rx") {
        exchanges += 1;
        rx_bytes += e.len;
      }
    }
    return { exchanges, tx_bytes, rx_bytes };
  }

  private stepDetails(st: StepSummary): HTMLElement {    const box = el("div");
    box.style.padding = "8px 0 4px";
    box.style.borderBottom = "1px solid var(--line)";

    const grid = el("div", "step-card__stats");
    grid.append(
      stat(t("длительность"), fmtDurationSeconds(st.dur)),
      stat(t("обменов"), fmtNum(st.exchanges)),
      stat("TX", fmtBytes(st.tx_bytes), "tx"),
      stat("RX", fmtBytes(st.rx_bytes), "rx"),
    );
    box.append(grid);

    const cmdEntries = Object.entries(st.cmd_hist ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (cmdEntries.length) {
      box.append(subTitle(t("КОМАНДЫ")));
      box.append(bars(cmdEntries, "tx"));
    }
    const respEntries = Object.entries(st.resp_hist ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (respEntries.length) {
      box.append(subTitle(t("ОТВЕТЫ")));
      box.append(bars(respEntries, "resp"));
    }
    const stepReads = st.reads ?? [];
    if (stepReads.length) {
      box.append(subTitle(t("ЧТЕНИЯ ПАМЯТИ")));
      const list = el("div", "decoded");
      for (const r of stepReads.slice(0, 8)) {
        prop(
          list,
          `0x${r.start.toString(16).toUpperCase().padStart(6, "0")}`,
          t("{bytes} · блоков {n} · {sha}…", { bytes: fmtBytes(r.len), n: r.blocks, sha: r.sha256.slice(0, 12) }),
        );
      }
      box.append(list);
    }
    const stepFiles = st.filehash ?? [];
    if (stepFiles.length) {
      box.append(subTitle(t("ФАЙЛЫ")));
      const list = el("div", "decoded");
      for (const f of stepFiles) prop(list, t("файл"), `${f.path} · ${fmtBytes(f.size)} · ${f.sha256.slice(0, 12)}…`);
      box.append(list);
    }
    if (st.png) {
      box.append(subTitle(t("СКРИНШОТ")));
      const img = el("img", "shot");
      img.alt = t("скриншот шага {n}", { n: st.idx });
      img.src = st.png.startsWith("data:") ? st.png : sessionFileUrl(store.state.active?.id ?? "", st.png);
      img.addEventListener("click", () =>
        openImage(img.src, t("шаг {n}: {title}", { n: st.idx, title: st.title })),
      );
      box.append(img);
    }
    const v = st.verdict;
    if (v && (v.denied || v.no_answer || v.unparsed)) {
      box.append(subTitle(t("ВЕРДИКТ")));
      const list = el("div", "decoded");
      if (v.echo) prop(list, t("эхо"), t("да"));
      if (v.denied) prop(list, t("отказов"), String(v.denied), "kwp");
      if (v.no_answer) prop(list, t("без ответа"), String(v.no_answer));
      if (v.unparsed) prop(list, t("не разобрано"), String(v.unparsed));
      box.append(list);
    }
    return box;
  }

  /* ────────────────────────────── сессия ──────────────────────────────── */

  private renderSession(): void {
    const s = store.state;
    const meta = s.active;
    if (!meta) {
      this.body.append(section(t("СЕССИЯ"), t("Сессия не выбрана.")));
      return;
    }
    const sec = el("section", "sec");
    const head = el("div", "sec__head");
    head.append(el("span", "sec__title", t("СЕССИЯ")));
    head.append(el("span", "badge-tag", meta.status));
    // Второй канал захвата: бейдж полосы прокси (docs/13 §8).
    const proxy = meta.proxy;
    const proxyWarn = proxy ? proxyNeedsAttention(proxy) : false;
    if (proxy) {
      head.append(
        el("span", `badge-tag${proxyWarn ? " badge-tag--warn" : ""}`.trim(), proxyBadge()),
      );
    }
    sec.append(head);

    const card = el("div");
    card.append(el("div", "step-card__title", meta.label || meta.id));
    const idLine = el("div", "muted");
    idLine.style.fontFamily = "var(--font-mono)";
    idLine.style.fontSize = "10.5px";
    idLine.textContent = meta.id;
    card.append(idLine);
    sec.append(card);

    const grid = el("div", "step-card__stats");
    grid.append(
      stat(t("событий"), fmtNum(meta.counts?.events ?? s.events.length)),
      stat(t("шагов"), fmtNum(meta.counts?.steps ?? s.steps.length)),
      stat("TX", fmtBytes(meta.counts?.tx_bytes ?? 0), "tx"),
      stat("RX", fmtBytes(meta.counts?.rx_bytes ?? 0), "rx"),
    );
    sec.append(grid);

    // Полоса прокси: счётчики TX/RX и сверка с полосой frida (§8, §9).
    if (proxy) {
      const line = el("div", `session-item__proxy${proxyWarn ? " is-warn" : ""}`.trim());
      line.style.marginTop = "8px";
      if (proxyWarn) line.append(icon("warn"));
      line.append(el("span", "", proxyLine(proxy)));
      line.title = proxyLineTitle(proxy);
      sec.append(line);
    }

    // Слои J2534: один обмен в схеме «прокси → драйвер» виден дважды, но
    // считается один раз. Строка доказывает, что связь вызовов сработала
    // (docs/13 §6.2), а для старых сессий предупреждает о возможном удвоении.
    const layers = j2534LayersLine(meta.counts);
    if (layers) {
      const line = el("div", `session-item__proxy${layers.warn ? " is-warn" : ""}`.trim());
      line.style.marginTop = "6px";
      if (layers.warn) line.append(icon("warn"));
      line.append(el("span", "", layers.text));
      line.title = layers.title;
      sec.append(line);
    }

    const props = el("div", "decoded");
    prop(props, t("начало"), fmtDate(meta.started_at));
    if (meta.ended_at) prop(props, t("конец"), fmtDate(meta.ended_at));
    prop(props, t("процесс"), meta.process ? `${meta.process} (pid ${meta.pid ?? "?"})` : "—");
    prop(props, t("транспорт"), meta.transport);
    if (meta.adapter) prop(props, t("шнурок"), `${meta.adapter.description} · ${meta.adapter.serial}${meta.adapter.com_port != null ? ` · COM${meta.adapter.com_port}` : ""}`);
    if (meta.tool_version) prop(props, t("версия"), meta.tool_version);
    if (meta.tool_sha256) prop(props, "sha256", meta.tool_sha256.slice(0, 24) + "…");
    prop(props, t("движок"), meta.engine_version);
    sec.append(props);

    if (meta.facts?.length) {
      sec.append(el("hr", "hr"));
      const facts = el("div", "decoded");
      for (const f of meta.facts) prop(facts, t("факт"), f);
      sec.append(facts);
    }
    this.body.append(sec);

    // Скриншоты шагов
    const shots = s.steps.filter((st) => !!st.png);
    if (shots.length) {
      const galSec = el("section", "sec");
      galSec.append(subTitle(t("СКРИНШОТЫ · {n}", { n: shots.length })));
      const gal = el("div", "gallery");
      for (const st of shots) {
        const item = el("div", "gallery__item");
        const img = el("img");
        img.alt = t("шаг {n}: {title}", { n: st.idx, title: st.title });
        img.src = st.png!.startsWith("data:") ? st.png! : sessionFileUrl(meta.id, st.png!);
        const cap = el("div", "gallery__cap", t("шаг {n} · {title}", { n: st.idx, title: st.title }));
        item.append(img, cap);
        item.addEventListener("click", () => openImage(img.src, t("шаг {n}: {title}", { n: st.idx, title: st.title })));
        gal.append(item);
      }
      galSec.append(gal);
      this.body.append(galSec);
    }

    // Отчёт
    const repSec = el("section", "sec");
    repSec.append(subTitle(t("ОТЧЁТ")));
    if (this.reportFor === meta.id && this.reportText != null) {
      const pre = el("pre", "report-pre");
      pre.textContent = this.reportText;
      repSec.append(pre);
      const hide = el("button", "btn btn--sm", t("скрыть отчёт"));
      hide.type = "button";
      hide.style.marginTop = "6px";
      hide.addEventListener("click", () => {
        this.reportText = null;
        this.reportFor = null;
        this.lastKey = "";
        this.update();
      });
      repSec.append(hide);
    } else {
      const load = el("button", "btn btn--sm", t("собрать и показать отчёт"));
      load.type = "button";
      load.addEventListener("click", async () => {
        load.disabled = true;
        load.textContent = t("собираю…");
        try {
          this.reportText = await api.report(meta.id, "txt");
          this.reportFor = meta.id;
          this.lastKey = "";
          this.update();
        } catch (e) {
          store.toast("error", t("отчёт не собрался: {msg}", { msg: (e as Error).message }));
          load.disabled = false;
          load.textContent = t("собрать и показать отчёт");
        }
      });
      repSec.append(load);
    }
    this.body.append(repSec);

    // Заметки
    const notesSec = el("section", "sec");
    notesSec.append(subTitle(t("ЗАМЕТКИ · {n}", { n: s.notes.length })));
    const list = el("div", "decoded");
    if (!s.notes.length) list.append(div("muted", t("Пока нет заметок.")));
    for (const n of s.notes) prop(list, fmtDate(n.wall), n.text);
    notesSec.append(list);
    const ta = el("textarea");
    ta.placeholder = t("заметка к сессии (Ctrl+Enter — сохранить)");
    ta.rows = 2;
    ta.style.width = "100%";
    ta.style.marginTop = "8px";
    ta.style.border = "1px solid var(--line-2)";
    ta.style.borderRadius = "var(--r-2)";
    ta.style.background = "var(--bg)";
    ta.style.color = "var(--text)";
    ta.style.padding = "6px 8px";
    ta.style.fontFamily = "var(--font-ui)";
    ta.style.fontSize = "12px";
    ta.style.resize = "vertical";
    const save = () => {
      const text = ta.value.trim();
      if (!text) return;
      void store.addNote(text);
      ta.value = "";
    };
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        save();
      }
    });
    const addBtn = el("button", "btn btn--sm", t("добавить заметку"));
    addBtn.type = "button";
    addBtn.style.marginTop = "6px";
    addBtn.addEventListener("click", save);
    notesSec.append(ta, addBtn);
    this.body.append(notesSec);
  }
}

/* ─────────────────────────────── хелперы ───────────────────────────────── */

function section(titleText: string, emptyText?: string): HTMLElement {
  const sec = el("section", "sec");
  const head = el("div", "sec__head");
  head.append(el("span", "sec__title", titleText));
  sec.append(head);
  if (emptyText) sec.append(div("sec__empty", emptyText));
  return sec;
}

function div(cls: string, text: string): HTMLElement {
  return el("div", cls, text);
}

function subTitle(text: string): HTMLElement {
  const d = el("div", "sec__title");
  d.style.margin = "10px 0 6px";
  d.textContent = text;
  return d;
}

/**
 * Поля вызова J2534 из `meta` (контракт `docs/11-capture-grammar.md`, 0.3.3).
 *
 * Возвращает готовые пары «подпись → значение» в порядке грамматики. Движок
 * кладёт короткие имена (`dur`, `th`), но старые сборки писали длинные
 * (`duration`, `thread`) — принимаем обе формы. Длительность всегда в
 * микросекундах: `dur` в логе — мкс, не секунды.
 */
function j2534CallProps(ev: Event): Array<[string, string]> {
  const m = ev.meta;
  if (!m) return [];
  const pick = (...names: string[]): unknown => {
    for (const name of names) {
      const v = m[name];
      if (v != null && v !== "") return v;
    }
    return undefined;
  };
  const out: Array<[string, string]> = [];

  const call = pick("call");
  if (call != null) out.push([t("вызов"), String(call)]);

  const idx = pick("i");
  if (idx != null) out.push([t("сообщение"), String(idx)]);

  const nIn = pick("n_in");
  if (nIn != null) out.push([t("запрошено"), String(nIn)]);

  const nOut = pick("n_out");
  if (nOut != null) out.push([t("получено"), String(nOut)]);

  const dur = pick("duration", "dur");
  if (dur != null) {
    const n = typeof dur === "number" ? dur : Number(dur);
    if (Number.isFinite(n)) out.push([t("длительность, мкс"), String(Math.round(n))]);
  }

  const th = pick("thread", "th");
  if (th != null) out.push([t("поток"), String(th)]);

  const ts = pick("ts");
  if (ts != null) out.push([t("время драйвера"), String(ts)]);

  const sof = pick("sof");
  if (sof != null) {
    const on = sof === true || sof === 1 || sof === "1" || sof === "true";
    out.push([t("начало сообщения"), on ? t("да") : t("нет")]);
  }

  return out;
}

/**
 * Поля meta событий осциллографа и нажатий кнопок (`kind: scope | ui_action`).
 *
 * Движок кладёт сюда действие, AutomationId, окно и процесс, а для scope —
 * состояние и счётчики. Незнакомые скалярные ключи тоже показываем: старые и
 * новые сборки не должны терять данные молча.
 */
function kindMetaProps(ev: Event): Array<[string, string]> {
  if (ev.kind !== "scope" && ev.kind !== "ui_action") return [];
  const m = ev.meta;
  if (!m) return [];
  const labels: Record<string, string> = {
    action: t("действие"),
    automation_id: "automation_id",
    control_type: t("тип элемента"),
    window: t("окно"),
    process: t("процесс"),
    pid: "pid",
    source: t("источник"),
    event: t("событие"),
    state: t("состояние"),
    frames: t("кадры"),
    gaps: t("пропуски"),
    bytes: t("байт"),
    last_error: t("ошибка"),
    degraded: t("деградация"),
  };
  const out: Array<[string, string]> = [];
  // Название кнопки движок кладёт в text: без него в meta остаётся только action.
  if (ev.text) {
    out.push([ev.kind === "ui_action" ? t("название") : t("описание"), ev.text]);
  }
  for (const key of Object.keys(labels)) {
    const value = m[key];
    if (value == null || value === "" || typeof value === "object") continue;
    out.push([labels[key], String(value)]);
  }
  const known = new Set(Object.keys(labels));
  for (const key of Object.keys(m)) {
    if (known.has(key)) continue;
    const value = m[key];
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out.push([key, String(value)]);
    }
  }
  return out;
}

function prop(box: HTMLElement, key: string, value: string, cls = ""): void {
  const row = el("div", "decoded__row");
  row.append(el("div", "decoded__key", key), el("div", `decoded__val ${cls}`.trim(), value));
  box.append(row);
}

function stat(label: string, value: string, cls = ""): HTMLElement {
  const d = el("div", "stat");
  d.append(el("div", "stat__label", label), el("div", `stat__value ${cls}`.trim(), value));
  return d;
}

function bpair(label: string, value: string): HTMLElement {
  const s = el("span");
  s.append(document.createTextNode(label + " "), el("b", "", value));
  return s;
}

function bars(entries: Array<[string, number]>, kind: "tx" | "resp"): HTMLElement {
  const box = el("div", "bars");
  const max = Math.max(...entries.map(([, v]) => v), 1);
  for (const [label, value] of entries) {
    const row = el("div", "bar");
    row.append(
      el("span", "bar__label", label),
      el("span", "bar__num", fmtNum(value)),
      (() => {
        const track = el("div", "bar__track");
        const fill = el("div", `bar__fill${kind === "resp" ? " bar__fill--resp" : ""}`);
        fill.style.width = `${Math.max(2, Math.round((value / max) * 100))}%`;
        track.append(fill);
        return track;
      })(),
    );
    box.append(row);
  }
  return box;
}

function hexLines(hex: string): Array<{ addr: string; bytes: string; ascii: string }> {
  const bytes = Array.from((() => {
    const out: number[] = [];
    const parts = hex.trim().split(/\s+/);
    for (const p of parts) {
      const v = parseInt(p, 16);
      if (!isNaN(v)) out.push(v & 0xff);
    }
    return out;
  })());
  const lines: Array<{ addr: string; bytes: string; ascii: string }> = [];
  for (let i = 0; i < bytes.length; i += 8) {
    const chunk = bytes.slice(i, i + 8);
    lines.push({
      addr: i.toString(16).padStart(6, "0"),
      bytes: bytesToHex(new Uint8Array(chunk)).padEnd(23, " "),
      ascii: asciiPreview(new Uint8Array(chunk)),
    });
  }
  return lines;
}

/** Локальный KWP-декодер для инспектора (серверный декод — через API). */
function decodeKwp(hex: string, dir?: string): Array<[string, string, string?]> {
  const parts = hex.trim().split(/\s+/).map((p) => parseInt(p, 16));
  const b = parts.filter((v) => !isNaN(v));
  if (!b.length) return [];
  const out: Array<[string, string, string?]> = [];
  out.push([t("байт"), String(b.length)]);
  const isResponse = dir === "rx";
  out.push([t("направление"), isResponse ? t("RX (из ЭБУ)") : dir === "tx" ? t("TX (в ЭБУ)") : "?"]);

  if (isResponse && b.includes(0xa0)) {
    const at = b.indexOf(0xa0);
    out.push([t("ответ"), t("A0 (положительный), payload {n} B", { n: Math.max(0, b.length - at - 1) }), "kwp"]);
  }
  if (b[2] === 0x7f) {
    const svc = b[3] ?? 0;
    const nrc = b[4] ?? 0;
    out.push([t("ответ"), `7F: svc=0x${svc.toString(16)} nrc=0x${nrc.toString(16)}`, "kwp"]);
    const names: Record<number, string> = {
      0x10: "generalReject",
      0x11: "serviceNotSupported",
      0x12: "subFunctionNotSupported",
      0x22: "conditionsNotCorrect",
      0x33: "securityAccessDenied",
      0x78: "responsePending",
    };
    if (names[nrc]) out.push([t("nrc"), names[nrc], "kwp"]);
  }
  const svc = b[0];
  if (!isResponse && svc != null) {
    out.push([t("команда"), `SVC(0x${svc.toString(16)})`]);
  }
  if (!isResponse && svc === 0x07 && b.length >= 3) {
    out.push([t("операция"), `cmd=0x07 mode=0x${(b[1] ?? 0).toString(16)}`]);
  }
  if (!isResponse && svc === 0x12 && b[2] === 0x06 && b.length >= 7) {
    const addr = ((b[5] << 8) | b[6]) >>> 0;
    out.push(
      [t("операция"), `READ 0x${addr.toString(16).toUpperCase().padStart(6, "0")} +${b[7] ?? 0}`],
      [t("адрес"), `0x${addr.toString(16).toUpperCase()}`],
    );
  }
  if (!isResponse && svc === 0x12 && b[2] === 0x07 && b.length >= 7) {
    const addr = ((b[5] << 8) | b[6]) >>> 0;
    out.push(
      [t("операция"), `WRITE 0x${addr.toString(16).toUpperCase().padStart(6, "0")} · ${b.length - 7} B`],
      [t("адрес"), `0x${addr.toString(16).toUpperCase()}`],
    );
  }
  const ascii = asciiPreview(new Uint8Array(b));
  if (/[0-9A-Za-z]{4,}/.test(ascii)) out.push(["ascii", ascii]);
  return out;
}




