/** Диалоги: экспорт/отправка, метки, шаги, шаблоны, справка, светофор. */

import { el, icon, iconButton } from "../dom";
import { fmtBytes, fmtDurationSeconds } from "../format";
import { store } from "../store";

interface ModalOpts {
  title: string;
  body: HTMLElement;
  footer?: HTMLElement[];
  width?: number;
  onClose?: () => void;
}

function modal(opts: ModalOpts): { close: () => void; body: HTMLElement } {
  const backdrop = el("div", "modal-backdrop");
  const box = el("div", "modal");
  if (opts.width) box.style.width = `min(${opts.width}px, 100%)`;
  const head = el("div", "modal__head");
  head.append(el("div", "modal__title", opts.title));
  const closeBtn = iconButton("close", "закрыть", () => close());
  head.append(closeBtn);

  const body = el("div", "modal__body");
  body.append(opts.body);
  box.append(head, body);
  if (opts.footer?.length) {
    const foot = el("div", "modal__foot");
    foot.append(...opts.footer);
    box.append(foot);
  }
  backdrop.append(box);
  document.body.append(backdrop);

  const onKey = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  };
  document.addEventListener("keydown", onKey, true);
  backdrop.addEventListener("mousedown", (e) => {
    if (e.target === backdrop) close();
  });

  let closed = false;
  function close(): void {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey, true);
    backdrop.remove();
    opts.onClose?.();
  }
  return { close, body };
}

function field(label: string, control: HTMLElement, hint?: string): HTMLElement {
  const f = el("div", "field");
  f.append(el("label", "field__label", label), control);
  if (hint) f.append(el("div", "field__hint", hint));
  return f;
}

function textInput(placeholder: string, value = ""): HTMLInputElement {
  const i = el("input");
  i.type = "text";
  i.placeholder = placeholder;
  i.value = value;
  i.spellcheck = false;
  return i;
}

function primary(label: string, onClick: () => void): HTMLButtonElement {
  const b = el("button", "btn btn--primary", label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function ghost(label: string, onClick: () => void): HTMLButtonElement {
  const b = el("button", "btn btn--ghost", label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

/* ─────────────────────────────── метка ─────────────────────────────────── */

export function openMarkPrompt(): void {
  if (!store.state.active) {
    store.toast("warn", "нет активной сессии");
    return;
  }
  const input = textInput("например: нажал «запись»", "");
  const list = el("datalist");
  list.id = "mark-titles";
  for (const t of store.state.quickTitles) {
    const o = el("option");
    o.value = t;
    list.append(o);
  }
  input.setAttribute("list", "mark-titles");
  const body = el("div");
  body.append(field("текст метки", input, "метка попадёт в поток и в отчёт, шаг не открывается"), list);
  const m = modal({
    title: "Метка в потоке",
    body,
    footer: [
      ghost("отмена", () => m.close()),
      primary("поставить (Enter)", () => submit()),
    ],
  });
  const submit = (): void => {
    const text = input.value.trim();
    if (!text) {
      input.focus();
      return;
    }
    m.close();
    void store.mark(text);
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  setTimeout(() => input.focus(), 30);
}

/* ─────────────────────────────── шаг ───────────────────────────────────── */

export function openStepPrompt(): void {
  if (!store.state.active) {
    store.toast("warn", "нет активной сессии");
    return;
  }
  const last = store.state.steps[store.state.steps.length - 1]?.title ?? "";
  const input = textInput("что делаете? например: нажал «идентификаторы»", last);
  const list = el("datalist");
  list.id = "step-titles";
  for (const t of store.state.quickTitles) {
    const o = el("option");
    o.value = t;
    list.append(o);
  }
  input.setAttribute("list", "step-titles");
  const body = el("div");
  body.append(
    field("название шага", input, "Enter — открыть шаг; пустое имя — автоназвание «шаг N»"),
    list,
  );
  const m = modal({
    title: "Открыть шаг",
    body,
    footer: [ghost("отмена", () => m.close()), primary("открыть", () => submit())],
  });
  const submit = (): void => {
    m.close();
    void store.startStep(input.value.trim());
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  setTimeout(() => {
    input.focus();
    input.select();
  }, 30);
}

/* ─────────────────────────────── стоп ──────────────────────────────────── */

export function openStopConfirm(): void {
  if (store.state.mode === "demo") {
    store.toast("info", "демо-режим: остановка недоступна");
    return;
  }
  if (!store.state.active) {
    store.toast("warn", "сессия не выбрана");
    return;
  }
  const body = el("div");
  body.append(
    el(
      "div",
      "sec__empty",
      "Захват остановится, хуки будут сняты, отчёт соберётся автоматически. Файлы сессии останутся на диске.",
    ),
  );
  const m = modal({
    title: "Остановить сессию?",
    body,
    footer: [
      ghost("продолжить запись", () => m.close()),
      primary("остановить", () => {
        m.close();
        void store.detach();
      }),
    ],
  });
  const stop = m.body.querySelector("button");
  stop?.focus();
}

/* ─────────────────────────────── экспорт ───────────────────────────────── */

export function openExportDialog(): void {
  const s = store.state;
  if (!s.active) {
    store.toast("warn", "сессия не выбрана");
    return;
  }
  let format: "zip" | "jsonl" | "csv" | "md" = "zip";
  const grid = el("div", "format-grid");
  const formats: Array<["zip" | "jsonl" | "csv" | "md", string, string]> = [
    ["zip", "ZIP", "вся сессия: события, шаги, скриншоты, отчёт"],
    ["jsonl", "JSONL", "машинный поток событий, по объекту в строке"],
    ["csv", "CSV", "таблица для Excel/скриптов"],
    ["md", "Markdown", "человекочитаемый отчёт со сводками шагов"],
  ];
  for (const [id, title, desc] of formats) {
    const b = el("button", `format-option${id === format ? " is-active" : ""}`);
    b.type = "button";
    b.append(el("div", "format-option__title", title), el("div", "format-option__desc", desc));
    b.addEventListener("click", () => {
      format = id;
      for (const node of Array.from(grid.children)) node.classList.remove("is-active");
      b.classList.add("is-active");
    });
    grid.append(b);
  }

  const result = el("div", "decoded");
  const shareInput = textInput("https://ваш-сервер/upload");
  const status = el("div", "field__hint", "");

  const body = el("div");
  body.append(
    field("формат", grid, `сессия: ${s.active.label || s.active.id} · ${s.steps.length} шагов`),
    field(
      "отправка на сервер (необязательно)",
      shareInput,
      "движок выполнит: curl -F file=@<zip> <url> — подходит любой приёмник, понимающий multipart",
    ),
    result,
    status,
  );

  const doExport = async (): Promise<void> => {
    status.textContent = "собираю…";
    status.style.color = "var(--text-mute)";
    const path = await store.exportSession(format);
    status.textContent = path ? `готово: ${path}` : "не удалось собрать экспорт";
    status.style.color = path ? "var(--ok)" : "var(--err)";
    if (path) {
      result.replaceChildren();
      const row = el("div", "decoded__row");
      row.append(el("div", "decoded__key", "файл"), el("div", "decoded__val", path));
      result.append(row);
      const copy = el("button", "btn btn--sm", "скопировать путь");
      copy.type = "button";
      copy.addEventListener("click", () => {
        void navigator.clipboard?.writeText(path);
        store.toast("ok", "путь скопирован");
      });
      result.append(copy);
      if (shareInput.value.trim()) await store.share(shareInput.value.trim());
    }
  };

  const footer = [
    ghost("закрыть", () => m.close()),
    primary("экспортировать", () => void doExport()),
  ];
  const m = modal({ title: "Экспорт и отправка", body, footer, width: 620 });
  void m;
}

/* ─────────────────────────────── USBPcap ───────────────────────────────── */

export function openUsbpcapDialog(devices: string[]): void {
  if (!devices.length) {
    store.toast(
      "warn",
      "USBPcap не найден. Установите USBPcap (desowin.org/usbpcap), перезагрузите ПК и запустите логер от администратора.",
    );
    return;
  }
  let chosen = devices[0];
  const list = el("div", "decoded");
  for (const dev of devices) {
    const row = el("button", `format-option${dev === chosen ? " is-active" : ""}`);
    row.type = "button";
    row.style.display = "flex";
    row.style.justifyContent = "space-between";
    row.append(el("span", "format-option__title", dev));
    row.addEventListener("click", () => {
      chosen = dev;
      for (const n of Array.from(list.children)) n.classList.remove("is-active");
      row.classList.add("is-active");
    });
    list.append(row);
  }
  const body = el("div");
  body.append(
    field("корневой USB-хаб для захвата", list, "нужны права администратора; трафик всех устройств на этом хабе"),
  );
  const m = modal({
    title: "Сырой захват USB-шины (USBPcap)",
    body,
    footer: [
      ghost("отмена", () => m.close()),
      primary("начать запись", () => {
        m.close();
        void store.startUsbpcap(chosen);
      }),
    ],
    width: 620,
  });
  void m;
}

/* ────────────────────────────── шаблоны ────────────────────────────────── */

export function openTemplatesDialog(): void {
  const ta = el("textarea");
  ta.rows = 7;
  ta.style.width = "100%";
  ta.style.border = "1px solid var(--line-2)";
  ta.style.borderRadius = "var(--r-2)";
  ta.style.background = "var(--bg)";
  ta.style.color = "var(--text)";
  ta.style.padding = "8px 10px";
  ta.style.fontFamily = "var(--font-mono)";
  ta.style.fontSize = "12px";
  ta.value = store.state.quickTitles.join("\n");

  const body = el("div");
  body.append(
    field("быстрые названия шагов", ta, "по одному в строке; первые четыре показываются на панели, остальные — в подсказке"),
  );
  const m = modal({
    title: "Шаблоны шагов",
    body,
    footer: [
      ghost("отмена", () => m.close()),
      primary("сохранить", () => {
        store.saveQuickTitles(ta.value.split("\n"));
        m.close();
        store.toast("ok", "шаблоны сохранены");
      }),
    ],
  });
  void m;
}

/* ─────────────────────────────── справка ───────────────────────────────── */

export function openHelpDialog(): void {
  const body = el("div");

  const workflow = el("div", "decoded");
  const steps: Array<[string, string]> = [
    ["1", "Запустите программу на FTDI (Quickflash, WinKFP) — как обычно."],
    ["2", "В колонке «Процессы на FTDI» нажмите «подключить» — откроется сессия и пойдёт поток."],
    ["3", "F2 — открыть шаг (название по шаблону), сделайте действие в программе, F2 — закрыть: сводка, скриншот, отчёт."],
    ["4", "Ctrl+E — экспорт/отправка, Ctrl+O — импорт старого лога для переразбора."],
  ];
  for (const [n, text] of steps) {
    const row = el("div", "decoded__row");
    row.append(el("div", "decoded__key", n), el("div", "decoded__val", text));
    workflow.append(row);
  }

  const keys: Array<[string, string]> = [
    ["F2", "шаг: открыть / закрыть со сводкой"],
    ["Shift+F2", "открыть шаг с названием вручную"],
    ["F5", "метка без шага"],
    ["F6", "снять / вернуть хуки (A/B-проверка записи)"],
    ["F8", "скриншот окна программы сейчас"],
    ["Ctrl+F", "поиск по потоку"],
    ["Ctrl+E", "экспорт и отправка"],
    ["Ctrl+O", "импорт старого лога"],
    ["↑ ↓ PgUp PgDn Home End", "навигация по потоку"],
    ["Esc", "остановить сессию (с подтверждением)"],
    ["F1", "эта справка"],
  ];
  const table = el("div", "decoded");
  for (const [k, v] of keys) {
    const row = el("div", "decoded__row");
    const key = el("div", "decoded__key");
    key.append(el("span", "kbd", k));
    row.append(key, el("div", "decoded__val", v));
    table.append(row);
  }

  body.append(
    el("div", "sec__title", "ПОРЯДОК РАБОТЫ"),
    workflow,
    el("div", "sec__title", "ГОРЯЧИЕ КЛАВИШИ"),
    table,
    el("div", "sec__title", "ЧТО ЗАПИСЫВАЕТСЯ"),
    el(
      "div",
      "sec__empty",
      "Каждый вызов FT_*/ReadFile/WriteFile, открытия файлов и модулей, метки и шаги. После закрытия шага — сводка: команды, ответы, чтения с sha256, файлы и скриншот. Всё это лежит в sessions/<id>/ и экспортируется одним архивом.",
    ),
    el("div", "sec__title", "ЕСЛИ ЗАПИСЬ НЕ ИДЁТ"),
    el(
      "div",
      "sec__empty",
      "Нажмите F6 (снять хуки), повторите операцию в программе. Если под паузой запись пошла — инструментирование мешает: снимайте хуки перед входом в программирование и возвращайте сразу после ответа pos(10). Если ошибка та же — дело не в логере.",
    ),
  );
  const m = modal({ title: "Как работать", body, footer: [primary("понятно", () => m.close())], width: 660 });
  void m;
}

/* ─────────────────────────────── картинка ──────────────────────────────── */

export function openImage(src: string, caption: string): void {
  const img = el("img");
  img.src = src;
  img.alt = caption;
  img.style.maxWidth = "100%";
  img.style.display = "block";
  img.style.border = "1px solid var(--line-2)";
  img.style.borderRadius = "var(--r-2)";
  const body = el("div");
  body.append(img);
  body.append(el("div", "field__hint", caption));
  modal({ title: "Скриншот", body, width: 980 });
}

/* ─────────────────────────────── тосты ─────────────────────────────────── */

export class Toasts {
  el: HTMLElement;
  private last: unknown = null;

  constructor() {
    this.el = document.getElementById("toasts") ?? el("div", "toasts");
    this.update();
  }

  update(): void {
    const list = store.state.toasts;
    if (list === this.last) return;
    this.last = list;
    this.el.replaceChildren();
    for (const t of list) {
      const box = el("div", `toast toast--${t.level}`);
      const bar = el("div", "toast__bar");
      const body = el("div", "toast__body");
      const titles: Record<string, string> = {
        ok: "готово",
        warn: "внимание",
        error: "ошибка",
        info: "подсказка",
      };
      body.append(el("b", "", titles[t.level] ?? t.level), el("span", "", t.text));
      box.append(bar, body);
      box.addEventListener("click", () => store.dismissToast(t.id));
      this.el.append(box);
    }
  }
}

