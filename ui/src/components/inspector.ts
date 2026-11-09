/** Правая колонка: инспектор события, шага и сессии. */

import { api, sessionFileUrl } from "../api";
import { el, icon, iconButton } from "../dom";
import { fmtBytes, fmtDurationSeconds, fmtNum, fmtTime, asciiPreview, bytesToHex, fmtDate } from "../format";
import { store } from "../store";
import type { Event, StepSummary } from "../types";
import { openImage } from "./dialogs";

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
    const defs: Array<[Tab, string]> = [
      ["event", "событие"],
      ["step", "шаг"],
      ["session", "сессия"],
    ];
    for (const [id, label] of defs) {
      const b = el("button", "tab", label);
      b.type = "button";
      b.dataset.tab = id;
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
        b.classList.toggle("is-active", b.dataset.tab === this.tab);
      }
    } else {
      for (const b of Array.from(this.tabsEl.children) as HTMLElement[]) {
        b.classList.toggle("is-active", b.dataset.tab === this.tab);
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
        section("СОБЫТИЕ", "Кликните строку в потоке — здесь появится HEX/ASCII, декод и контекст."),
      );
      return;
    }
    const sec = el("section", "sec");
    const head = el("div", "sec__head");
    head.append(el("span", "sec__title", `СОБЫТИЕ #${ev.seq}`));
    const copy = iconButton("copy", "скопировать hex", () => {
      void navigator.clipboard?.writeText(ev.hex || ev.raw);
      store.toast("ok", "скопировано");
    });
    head.append(copy);
    sec.append(head);

    const props = el("div", "decoded");
    prop(props, "тип", `${ev.kind} · ${ev.transport}`);
    prop(props, "время", `${fmtTime(ev.t)} · ${fmtDate(ev.wall)}`);
    prop(props, "api", ev.api || "—");
    if (ev.len) prop(props, "длина", fmtBytes(ev.len));
    if (ev.rc != null) prop(props, "rc", String(ev.rc));
    if (ev.step != null) prop(props, "шаг", String(ev.step));
    sec.append(props);

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
      this.body.append(section("ШАГ", "Нет активной сессии."));
      return;
    }

    // Текущий открытый шаг
    if (s.currentStep) {
      const cur = s.currentStep;
      const live = (s.tick - s.stepStartEpoch) / 1000;
      const stats = this.liveStepStats(cur.idx);
      const sec = el("section", "sec");
      const card = el("div");
      const t = el("div", "step-card__title");
      t.append(el("span", "step-card__no", `ШАГ ${cur.idx}`), el("span", "", cur.title));
      const sub = el("div", "muted");
      sub.style.fontSize = "11px";
      sub.textContent = `идёт · ${fmtDurationSeconds(live)}`;
      card.append(t, sub);
      const grid = el("div", "step-card__stats");
      grid.append(
        stat("обменов", fmtNum(stats.exchanges)),
        stat("длительность", fmtDurationSeconds(live)),
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
    head.append(el("span", "sec__title", `СВОДКИ ШАГОВ · ${steps.length}`));
    secList.append(head);
    if (!steps.length) {
      secList.append(
        div(
          "muted",
          s.currentStep
            ? "Шаг идёт — сводка появится после закрытия (F2)."
            : "Шагов пока нет. F2 открывает шаг, повторное F2 — закрывает и собирает сводку.",
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
        title.append(el("span", "step-card__no", String(st.idx)), el("span", "", st.title || "без названия"));
        const time = el("div", "session-item__time", fmtDurationSeconds(st.dur));
        const meta = el("div", "session-item__meta");
        meta.append(
          bpair("обменов", fmtNum(st.exchanges)),
          bpair("TX", fmtBytes(st.tx_bytes)),
          bpair("RX", fmtBytes(st.rx_bytes)),
          bpair("чтений", String(st.reads.length)),
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
      stat("длительность", fmtDurationSeconds(st.dur)),
      stat("обменов", fmtNum(st.exchanges)),
      stat("TX", fmtBytes(st.tx_bytes), "tx"),
      stat("RX", fmtBytes(st.rx_bytes), "rx"),
    );
    box.append(grid);

    const cmdEntries = Object.entries(st.cmd_hist ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    if (cmdEntries.length) {
      box.append(subTitle("КОМАНДЫ"));
      box.append(bars(cmdEntries, "tx"));
    }
    const respEntries = Object.entries(st.resp_hist ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
    if (respEntries.length) {
      box.append(subTitle("ОТВЕТЫ"));
      box.append(bars(respEntries, "resp"));
    }
    if (st.reads.length) {
      box.append(subTitle("ЧТЕНИЯ ПАМЯТИ"));
      const list = el("div", "decoded");
      for (const r of st.reads.slice(0, 8)) {
        prop(
          list,
          `0x${r.start.toString(16).toUpperCase().padStart(6, "0")}`,
          `${fmtBytes(r.len)} · блоков ${r.blocks} · ${r.sha256.slice(0, 12)}…`,
        );
      }
      box.append(list);
    }
    if (st.filehash.length) {
      box.append(subTitle("ФАЙЛЫ"));
      const list = el("div", "decoded");
      for (const f of st.filehash) prop(list, "файл", `${f.path} · ${fmtBytes(f.size)} · ${f.sha256.slice(0, 12)}…`);
      box.append(list);
    }
    if (st.png) {
      box.append(subTitle("СКРИНШОТ"));
      const img = el("img", "shot");
      img.alt = `скриншот шага ${st.idx}`;
      img.src = st.png.startsWith("data:") ? st.png : sessionFileUrl(store.state.active?.id ?? "", st.png);
      img.addEventListener("click", () => openImage(img.src, `шаг ${st.idx}: ${st.title}`));
      box.append(img);
    }
    const v = st.verdict;
    if (v && (v.denied || v.no_answer || v.unparsed)) {
      box.append(subTitle("ВЕРДИКТ"));
      const list = el("div", "decoded");
      if (v.echo) prop(list, "эхо", "да");
      if (v.denied) prop(list, "отказов", String(v.denied), "kwp");
      if (v.no_answer) prop(list, "без ответа", String(v.no_answer));
      if (v.unparsed) prop(list, "не разобрано", String(v.unparsed));
      box.append(list);
    }
    return box;
  }

  /* ────────────────────────────── сессия ──────────────────────────────── */

  private renderSession(): void {
    const s = store.state;
    const meta = s.active;
    if (!meta) {
      this.body.append(section("СЕССИЯ", "Сессия не выбрана."));
      return;
    }
    const sec = el("section", "sec");
    const head = el("div", "sec__head");
    head.append(el("span", "sec__title", "СЕССИЯ"));
    head.append(el("span", "badge-tag", meta.status));
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
      stat("событий", fmtNum(meta.counts?.events ?? s.events.length)),
      stat("шагов", fmtNum(meta.counts?.steps ?? s.steps.length)),
      stat("TX", fmtBytes(meta.counts?.tx_bytes ?? 0), "tx"),
      stat("RX", fmtBytes(meta.counts?.rx_bytes ?? 0), "rx"),
    );
    sec.append(grid);

    const props = el("div", "decoded");
    prop(props, "начало", fmtDate(meta.started_at));
    if (meta.ended_at) prop(props, "конец", fmtDate(meta.ended_at));
    prop(props, "процесс", meta.process ? `${meta.process} (pid ${meta.pid ?? "?"})` : "—");
    prop(props, "транспорт", meta.transport);
    if (meta.adapter) prop(props, "шнурок", `${meta.adapter.description} · ${meta.adapter.serial}${meta.adapter.com_port != null ? ` · COM${meta.adapter.com_port}` : ""}`);
    if (meta.tool_version) prop(props, "версия", meta.tool_version);
    if (meta.tool_sha256) prop(props, "sha256", meta.tool_sha256.slice(0, 24) + "…");
    prop(props, "движок", meta.engine_version);
    sec.append(props);

    if (meta.facts?.length) {
      sec.append(el("hr", "hr"));
      const facts = el("div", "decoded");
      for (const f of meta.facts) prop(facts, "факт", f);
      sec.append(facts);
    }
    this.body.append(sec);

    // Скриншоты шагов
    const shots = s.steps.filter((st) => !!st.png);
    if (shots.length) {
      const galSec = el("section", "sec");
      galSec.append(subTitle(`СКРИНШОТЫ · ${shots.length}`));
      const gal = el("div", "gallery");
      for (const st of shots) {
        const item = el("div", "gallery__item");
        const img = el("img");
        img.alt = `шаг ${st.idx}: ${st.title}`;
        img.src = st.png!.startsWith("data:") ? st.png! : sessionFileUrl(meta.id, st.png!);
        const cap = el("div", "gallery__cap", `шаг ${st.idx} · ${st.title}`);
        item.append(img, cap);
        item.addEventListener("click", () => openImage(img.src, `шаг ${st.idx}: ${st.title}`));
        gal.append(item);
      }
      galSec.append(gal);
      this.body.append(galSec);
    }

    // Отчёт
    const repSec = el("section", "sec");
    repSec.append(subTitle("ОТЧЁТ"));
    if (this.reportFor === meta.id && this.reportText != null) {
      const pre = el("pre", "report-pre");
      pre.textContent = this.reportText;
      repSec.append(pre);
      const hide = el("button", "btn btn--sm", "скрыть отчёт");
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
      const load = el("button", "btn btn--sm", "собрать и показать отчёт");
      load.type = "button";
      load.addEventListener("click", async () => {
        load.disabled = true;
        load.textContent = "собираю…";
        try {
          this.reportText = await api.report(meta.id, "txt");
          this.reportFor = meta.id;
          this.lastKey = "";
          this.update();
        } catch (e) {
          store.toast("error", `отчёт не собрался: ${(e as Error).message}`);
          load.disabled = false;
          load.textContent = "собрать и показать отчёт";
        }
      });
      repSec.append(load);
    }
    this.body.append(repSec);

    // Заметки
    const notesSec = el("section", "sec");
    notesSec.append(subTitle(`ЗАМЕТКИ · ${s.notes.length}`));
    const list = el("div", "decoded");
    if (!s.notes.length) list.append(div("muted", "Пока нет заметок."));
    for (const n of s.notes) prop(list, fmtDate(n.wall), n.text);
    notesSec.append(list);
    const ta = el("textarea");
    ta.placeholder = "заметка к сессии (Ctrl+Enter — сохранить)";
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
    const addBtn = el("button", "btn btn--sm", "добавить заметку");
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
  out.push(["байт", String(b.length)]);
  const isResponse = dir === "rx";
  out.push(["направление", isResponse ? "RX (из ЭБУ)" : dir === "tx" ? "TX (в ЭБУ)" : "?"]);

  if (isResponse && b.includes(0xa0)) {
    const at = b.indexOf(0xa0);
    out.push(["ответ", `A0 (положительный), payload ${Math.max(0, b.length - at - 1)} B`, "kwp"]);
  }
  if (b[2] === 0x7f) {
    const svc = b[3] ?? 0;
    const nrc = b[4] ?? 0;
    out.push(["ответ", `7F: svc=0x${svc.toString(16)} nrc=0x${nrc.toString(16)}`, "kwp"]);
    const names: Record<number, string> = {
      0x10: "generalReject",
      0x11: "serviceNotSupported",
      0x12: "subFunctionNotSupported",
      0x22: "conditionsNotCorrect",
      0x33: "securityAccessDenied",
      0x78: "responsePending",
    };
    if (names[nrc]) out.push(["nrc", names[nrc], "kwp"]);
  }
  const svc = b[0];
  if (!isResponse && svc != null) {
    out.push(["команда", `SVC(0x${svc.toString(16)})`]);
  }
  if (!isResponse && svc === 0x07 && b.length >= 3) {
    out.push(["операция", `cmd=0x07 mode=0x${(b[1] ?? 0).toString(16)}`]);
  }
  if (!isResponse && svc === 0x12 && b[2] === 0x06 && b.length >= 7) {
    const addr = ((b[5] << 8) | b[6]) >>> 0;
    out.push(
      ["операция", `READ 0x${addr.toString(16).toUpperCase().padStart(6, "0")} +${b[7] ?? 0}`],
      ["адрес", `0x${addr.toString(16).toUpperCase()}`],
    );
  }
  if (!isResponse && svc === 0x12 && b[2] === 0x07 && b.length >= 7) {
    const addr = ((b[5] << 8) | b[6]) >>> 0;
    out.push(
      ["операция", `WRITE 0x${addr.toString(16).toUpperCase().padStart(6, "0")} · ${b.length - 7} B`],
      ["адрес", `0x${addr.toString(16).toUpperCase()}`],
    );
  }
  const ascii = asciiPreview(new Uint8Array(b));
  if (/[0-9A-Za-z]{4,}/.test(ascii)) out.push(["ascii", ascii]);
  return out;
}




