/** Диалоги: экспорт/отправка, метки, шаги, шаблоны, справка, светофор. */

import { el, iconButton } from "../dom";
import { store } from "../store";
import type { NewSessionResult } from "../types";
import { msg, t } from "../i18n";

msg({
  "нет активной сессии": "no active session",
  "например: нажал «запись»": "for example: pressed Record",
  "текст метки": "mark text",
  "метка попадёт в поток и в отчёт, шаг не открывается": "the mark goes into the stream and the report; no step is opened",
  "Метка в потоке": "Mark in the stream",
  "поставить (Enter)": "set (Enter)",
  "что делаете? например: нажал «идентификаторы»": "what are you doing? e.g. pressed Identifiers",
  "название шага": "step name",
  "Enter — открыть шаг; пустое имя — автоназвание «шаг N»":
    "Enter opens the step; an empty name gives the automatic name \"step N\"",
  "Открыть шаг": "Open step",
  "открыть": "open",
  "Демонстрационная запись остановится. Пример лога останется доступен для просмотра.":
    "The demo recording will stop. The sample log stays available for viewing.",
  "Захват остановится, хуки будут сняты, отчёт соберётся автоматически. Файлы сессии останутся на диске.":
    "Capture will stop, hooks will be removed, and the report will be collected automatically. Session files stay on disk.",
  "Остановить сессию?": "Stop the session?",
  "продолжить запись": "keep recording",
  "остановить": "stop",
  "вся сессия: события, шаги, скриншоты, отчёт":
    "the whole session: events, steps, screenshots, report",
  "машинный поток событий, по объекту в строке": "machine-readable event stream, one object per line",
  "таблица для Excel/скриптов": "a table for Excel/scripts",
  "человекочитаемый отчёт со сводками шагов": "a human-readable report with step summaries",
  "формат": "format",
  "сессия: {label} · {steps} шагов": "session: {label} · {steps} steps",
  "отправка на сервер (необязательно)": "upload to a server (optional)",
  "https://ваш-сервер/upload": "https://your-server/upload",
  "движок выполнит: curl -F file=@<zip> <url> — подходит любой приёмник, понимающий multipart":
    "the engine runs: curl -F file=@<zip> <url> — any multipart receiver works",
  "собираю…": "packing…",
  "не удалось собрать экспорт": "failed to build the export",
  "файл": "file",
  "экспортировать": "export",
  "Экспорт и отправка": "Export and upload",
  "USBPcap не найден. Установите USBPcap (desowin.org/usbpcap), перезагрузите ПК и запустите логер от администратора.":
    "USBPcap was not found. Install USBPcap (desowin.org/usbpcap), reboot the PC and start the logger as administrator.",
  "корневой USB-хаб для захвата": "root USB hub to capture",
  "нужны права администратора; трафик всех устройств на этом хабе":
    "administrator rights are required; traffic of every device on this hub",
  "Сырой захват USB-шины (USBPcap)": "Raw USB bus capture (USBPcap)",
  "начать запись": "start recording",
  "пресеты действий  (по одному в строке)": "action presets  (one per line)",
  "список показывается в комбо на нижней панели: выбрал — шаг открылся. Новые названия, введённые вручную, добавляются сюда автоматически.":
    "the list appears in the combo box on the bottom bar: pick one and the step opens. New names typed manually are added here automatically.",
  "Пресеты действий": "Action presets",
  "шаблоны сохранены": "presets saved",
  "1": "1",
  "Запустите программу на FTDI (Quickflash, WinKFP) — как обычно.":
    "Start the tool on the FTDI cable (Quickflash, WinKFP) — as usual.",
  "В колонке «Процессы на FTDI» нажмите «подключить» — откроется сессия и пойдёт поток.":
    "In the \"FTDI processes\" column press \"attach\" — a session opens and the stream starts.",
  "F2 — открыть шаг (название по шаблону), сделайте действие в программе, F2 — закрыть: сводка, скриншот, отчёт.":
    "F2 opens a step (name from a preset), do the action in the tool, F2 closes it: summary, screenshot, report.",
  "Ctrl+E — экспорт/отправка, Ctrl+O — импорт старого лога для переразбора.":
    "Ctrl+E exports/uploads, Ctrl+O imports an old log for reparsing.",
  "шаг: открыть / закрыть со сводкой; пресет — в комбо на нижней панели":
    "step: open/close with a summary; a preset sits in the bottom combo",
  "открыть шаг с названием вручную": "open a step with a manual name",
  "метка без шага": "mark without a step",
  "снять / вернуть хуки (A/B-проверка записи)": "remove/restore hooks (A/B recording check)",
  "скриншот окна программы сейчас": "screenshot the tool window now",
  "поиск по потоку": "search the stream",
  "экспорт и отправка": "export and upload",
  "импорт старого лога": "import an old log",
  "навигация по потоку": "navigate the stream",
  "остановить сессию (с подтверждением)": "stop the session (with confirmation)",
  "эта справка": "this help",
  "ПОРЯДОК РАБОТЫ": "WORKFLOW",
  "ГОРЯЧИЕ КЛАВИШИ": "HOTKEYS",
  "ЧТО ЗАПИСЫВАЕТСЯ": "WHAT IS RECORDED",
  "Каждый вызов FT_*/ReadFile/WriteFile, открытия файлов и модулей, метки и шаги. После закрытия шага — сводка: команды, ответы, чтения с sha256, файлы и скриншот. Всё это лежит в sessions/<id>/ и экспортируется одним архивом.":
    "Every FT_*/ReadFile/WriteFile call, file and module opens, marks and steps. When a step closes you get a summary: commands, responses, reads with sha256, files and a screenshot. All of it lives in sessions/<id>/ and exports as a single archive.",
  "ЕСЛИ ЗАПИСЬ НЕ ИДЁТ": "IF RECORDING DOES NOT WORK",
  "Нажмите F6 (снять хуки), повторите операцию в программе. Если под паузой запись пошла — инструментирование мешает: снимайте хуки перед входом в программирование и возвращайте сразу после ответа pos(10). Если ошибка та же — дело не в логере.":
    "Press F6 (remove hooks) and repeat the operation in the tool. If it works while paused, instrumentation interferes: remove hooks before entering programming and restore them right after the pos(10) response. If the error is the same, the logger is not the cause.",
  "Как работать": "How it works",
  "понятно": "got it",
  "Скриншот": "Screenshot",
  "Текущая сессия «{label}» будет завершена и сохранена, затем логер заново просканирует шнурки и программы.":
    "The current session \"{label}\" will be finished and saved, then the logger rescans cables and programs.",
  "Новая сессия": "New session",
  "завершить и пересканировать": "finish and rescan",
  "  Сканирую USB-устройства, J2534-драйверы и программы…":
    "  Scanning USB devices, J2534 drivers and programs…",
  "Выберите адаптер и программу. Перед запуском проверьте выбранную цель внизу окна.":
    "Choose an adapter and a program. Check the selected target at the bottom of the window before starting.",
  "01  /  Адаптер FTDI / USB": "01  /  FTDI / USB adapter",
  "FTDI-шнурки не найдены — проверьте драйвер и подключение.":
    "No FTDI cables found — check the driver and the connection.",
  "не указывать (любой шнурок)": "do not specify (any cable)",
  "02  /  Программа": "02  /  Program",
  "Поиск по имени, PID или окну": "Search by name, PID or window",
  "Поиск программы": "Search programs",
  "Нет совпадений. Измените запрос или укажите PID.": "No matches. Change the query or enter a PID.",
  "Программы не найдены — переключите фильтр в панели «ПРОГРАММЫ» или введите PID.":
    "No programs found — switch the filter in the \"PROGRAMS\" panel or enter a PID.",
  "окно": "window",
  "PID вручную, если программы нет в списке": "PID manually, if the program is not listed",
  "PID программы": "Program PID",
  "Выбрать PID": "Use PID",
  "Введите положительный целый PID (только цифры).": "Enter a positive integer PID (digits only).",
  "PID должен быть целым в диапазоне 1..2147483647.": "PID must be an integer in the range 1..2147483647.",
  "выбран PID {pid}": "PID {pid} selected",
  "начать сессию": "start session",
  "выберите программу или укажите PID": "choose a program or enter a PID",
  "сначала выберите программу (или введите PID)": "choose a program first (or enter a PID)",
  "Любой адаптер": "Any adapter",
  "Программа": "Program",
  "Выберите программу или PID": "Choose a program or PID",
  "Новая сессия: выбор цели": "New session: choose a target",
});

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
  const closeBtn = iconButton("close", t("закрыть"), () => close());
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
  // Запоминаем фокус и на время диалога делаем фон inert (как в референсе).
  const previous = document.activeElement;
  document.body.append(backdrop);
  const app = document.getElementById("app");
  if (app) app.inert = true;
  closeBtn.focus();

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
    if (app) app.inert = !!document.querySelector(".modal-backdrop");
    if (previous instanceof HTMLElement) previous.focus();
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
    store.toast("warn", t("нет активной сессии"));
    return;
  }
  const input = textInput(t("например: нажал «запись»"), "");
  const list = el("datalist");
  list.id = "mark-titles";
  for (const title of store.state.quickTitles) {
    const o = el("option");
    o.value = title;
    list.append(o);
  }
  input.setAttribute("list", "mark-titles");
  const body = el("div");
  body.append(field(t("текст метки"), input, t("метка попадёт в поток и в отчёт, шаг не открывается")), list);
  const m = modal({
    title: t("Метка в потоке"),
    body,
    footer: [
      ghost(t("отмена"), () => m.close()),
      primary(t("поставить (Enter)"), () => submit()),
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
    store.toast("warn", t("нет активной сессии"));
    return;
  }
  const last = store.state.steps[store.state.steps.length - 1]?.title ?? "";
  const input = textInput(t("что делаете? например: нажал «идентификаторы»"), last);
  const list = el("datalist");
  list.id = "step-titles";
  for (const title of store.state.quickTitles) {
    const o = el("option");
    o.value = title;
    list.append(o);
  }
  input.setAttribute("list", "step-titles");
  const body = el("div");
  body.append(
    field(t("название шага"), input, t("Enter — открыть шаг; пустое имя — автоназвание «шаг N»")),
    list,
  );
  const m = modal({
    title: t("Открыть шаг"),
    body,
    footer: [ghost(t("отмена"), () => m.close()), primary(t("открыть"), () => submit())],
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
  // В демо стоп имеет смысл только когда запись реально идёт.
  if (store.state.mode === "demo" && !store.state.status?.recording) return;
  if (!store.state.active) {
    store.toast("warn", t("сессия не выбрана"));
    return;
  }
  const body = el("div");
  body.append(
    el(
      "div",
      "sec__empty",
      store.state.mode === "demo"
        ? t("Демонстрационная запись остановится. Пример лога останется доступен для просмотра.")
        : t("Захват остановится, хуки будут сняты, отчёт соберётся автоматически. Файлы сессии останутся на диске."),
    ),
  );
  const m = modal({
    title: t("Остановить сессию?"),
    body,
    footer: [
      ghost(t("продолжить запись"), () => m.close()),
      primary(t("остановить"), () => {
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
    store.toast("warn", t("сессия не выбрана"));
    return;
  }
  let format: "zip" | "jsonl" | "csv" | "md" = "zip";
  const grid = el("div", "format-grid");
  const formats: Array<["zip" | "jsonl" | "csv" | "md", string, string]> = [
    ["zip", "ZIP", t("вся сессия: события, шаги, скриншоты, отчёт")],
    ["jsonl", "JSONL", t("машинный поток событий, по объекту в строке")],
    ["csv", "CSV", t("таблица для Excel/скриптов")],
    ["md", "Markdown", t("человекочитаемый отчёт со сводками шагов")],
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
  const shareInput = textInput(t("https://ваш-сервер/upload"));
  const status = el("div", "field__hint", "");

  const body = el("div");
  body.append(
    field(
      t("формат"),
      grid,
      t("сессия: {label} · {steps} шагов", { label: s.active.label || s.active.id, steps: s.steps.length }),
    ),
    field(
      t("отправка на сервер (необязательно)"),
      shareInput,
      t("движок выполнит: curl -F file=@<zip> <url> — подходит любой приёмник, понимающий multipart"),
    ),
    result,
    status,
  );

  const doExport = async (): Promise<void> => {
    status.textContent = t("собираю…");
    status.style.color = "var(--text-mute)";
    const path = await store.exportSession(format);
    status.textContent = path ? t("готово: {path}", { path }) : t("не удалось собрать экспорт");
    status.style.color = path ? "var(--ok)" : "var(--err)";
    if (path) {
      result.replaceChildren();
      const row = el("div", "decoded__row");
      row.append(el("div", "decoded__key", t("файл")), el("div", "decoded__val", path));
      result.append(row);
      const copy = el("button", "btn btn--sm", t("скопировать путь"));
      copy.type = "button";
      copy.addEventListener("click", () => {
        void navigator.clipboard?.writeText(path);
        store.toast("ok", t("путь скопирован"));
      });
      result.append(copy);
      if (shareInput.value.trim()) await store.share(shareInput.value.trim());
    }
  };

  const footer = [
    ghost(t("закрыть"), () => m.close()),
    primary(t("экспортировать"), () => void doExport()),
  ];
  const m = modal({ title: t("Экспорт и отправка"), body, footer, width: 620 });
  void m;
}

/* ─────────────────────────────── USBPcap ───────────────────────────────── */

export function openUsbpcapDialog(devices: string[]): void {
  if (!devices.length) {
    store.toast(
      "warn",
      t(
        "USBPcap не найден. Установите USBPcap (desowin.org/usbpcap), перезагрузите ПК и запустите логер от администратора.",
      ),
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
    field(t("корневой USB-хаб для захвата"), list, t("нужны права администратора; трафик всех устройств на этом хабе")),
  );
  const m = modal({
    title: t("Сырой захват USB-шины (USBPcap)"),
    body,
    footer: [
      ghost(t("отмена"), () => m.close()),
      primary(t("начать запись"), () => {
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
    field(
      t("пресеты действий  (по одному в строке)"),
      ta,
      t(
        "список показывается в комбо на нижней панели: выбрал — шаг открылся. Новые названия, введённые вручную, добавляются сюда автоматически.",
      ),
    ),
  );
  const m = modal({
    title: t("Пресеты действий"),
    body,
    footer: [
      ghost(t("отмена"), () => m.close()),
      primary(t("сохранить"), () => {
        store.saveQuickTitles(ta.value.split("\n"));
        m.close();
        store.toast("ok", t("шаблоны сохранены"));
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
    ["1", t("Запустите программу на FTDI (Quickflash, WinKFP) — как обычно.")],
    ["2", t("В колонке «Процессы на FTDI» нажмите «подключить» — откроется сессия и пойдёт поток.")],
    ["3", t("F2 — открыть шаг (название по шаблону), сделайте действие в программе, F2 — закрыть: сводка, скриншот, отчёт.")],
    ["4", t("Ctrl+E — экспорт/отправка, Ctrl+O — импорт старого лога для переразбора.")],
  ];
  for (const [n, text] of steps) {
    const row = el("div", "decoded__row");
    row.append(el("div", "decoded__key", n), el("div", "decoded__val", text));
    workflow.append(row);
  }

  const keys: Array<[string, string]> = [
    ["F2", t("шаг: открыть / закрыть со сводкой; пресет — в комбо на нижней панели")],
    ["Shift+F2", t("открыть шаг с названием вручную")],
    ["F5", t("метка без шага")],
    ["F6", t("снять / вернуть хуки (A/B-проверка записи)")],
    ["F8", t("скриншот окна программы сейчас")],
    ["Ctrl+F", t("поиск по потоку")],
    ["Ctrl+E", t("экспорт и отправка")],
    ["Ctrl+O", t("импорт старого лога")],
    ["↑ ↓ PgUp PgDn Home End", t("навигация по потоку")],
    ["Esc", t("остановить сессию (с подтверждением)")],
    ["F1", t("эта справка")],
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
    el("div", "sec__title", t("ПОРЯДОК РАБОТЫ")),
    workflow,
    el("div", "sec__title", t("ГОРЯЧИЕ КЛАВИШИ")),
    table,
    el("div", "sec__title", t("ЧТО ЗАПИСЫВАЕТСЯ")),
    el(
      "div",
      "sec__empty",
      t(
        "Каждый вызов FT_*/ReadFile/WriteFile, открытия файлов и модулей, метки и шаги. После закрытия шага — сводка: команды, ответы, чтения с sha256, файлы и скриншот. Всё это лежит в sessions/<id>/ и экспортируется одним архивом.",
      ),
    ),
    el("div", "sec__title", t("ЕСЛИ ЗАПИСЬ НЕ ИДЁТ")),
    el(
      "div",
      "sec__empty",
      t(
        "Нажмите F6 (снять хуки), повторите операцию в программе. Если под паузой запись пошла — инструментирование мешает: снимайте хуки перед входом в программирование и возвращайте сразу после ответа pos(10). Если ошибка та же — дело не в логере.",
      ),
    ),
  );
  const m = modal({ title: t("Как работать"), body, footer: [primary(t("понятно"), () => m.close())], width: 660 });
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
  modal({ title: t("Скриншот"), body, width: 980 });
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
    for (const toast of list) {
      const box = el("div", `toast toast--${toast.level}`);
      const bar = el("div", "toast__bar");
      const body = el("div", "toast__body");
      const titles: Record<string, string> = {
        ok: t("готово"),
        warn: t("внимание"),
        error: t("ошибка"),
        info: t("подсказка"),
      };
      body.append(el("b", "", titles[toast.level] ?? toast.level), el("span", "", toast.text));
      box.append(bar, body);
      box.addEventListener("click", () => store.dismissToast(toast.id));
      this.el.append(box);
    }
  }
}

/* ───────────────────────────── новая сессия ────────────────────────────── */

/** «Новая сессия»: остановить текущую, пересканировать устройства/программы, выбрать цель. */
export function openNewSessionDialog(): void {
  // Демо: движок не нужен — пикер строим на синтетических данных из store.
  if (store.state.mode === "demo") {
    renderNewSession({ devices: store.state.devices, tools: store.state.tools });
    return;
  }
  const active = store.state.active;
  const recording = !!store.state.status?.recording || active?.status === "recording";
  if (active && recording) {
    const body = el("div");
    body.append(
      el(
        "div",
        "sec__empty",
        t("Текущая сессия «{label}» будет завершена и сохранена, затем логер заново просканирует шнурки и программы.", {
          label: active.label || active.id,
        }),
      ),
    );
    const m: { close: () => void } = modal({
      title: t("Новая сессия"),
      body,
      footer: [
        ghost(t("отмена"), () => m.close()),
        primary(t("завершить и пересканировать"), () => {
          m.close();
          void runRescan();
        }),
      ],
    });
    return;
  }
  void runRescan();
}

async function runRescan(): Promise<void> {
  const body = el("div");
  const busy = el("div", "sec__empty");
  busy.append(el("span", "spinner"), document.createTextNode(t("  Сканирую USB-устройства, J2534-драйверы и программы…")));
  body.append(busy);
  const wait = modal({ title: t("Новая сессия"), body, width: 720 });
  const res = await store.newSession();
  wait.close();
  if (!res) return;
  renderNewSession(res);
}

function renderNewSession(res: Pick<NewSessionResult, "devices" | "tools">): void {
  const devices = res.devices ?? [];
  const tools = res.tools ?? [];

  // Адаптер по умолчанию — первый найденный шнурок; программу НЕ выбираем
  // заранее: иначе «начать сессию» цепляется к первому процессу в списке
  // (часто explorer) и кажется, что логер «держит» не то устройство.
  let chosenAdapter: string | null = devices.length ? devices[0].serial || devices[0].description : null;
  let chosenPid: number | null = null;
  let manualPid: number | null = null;

  const body = el("div", "session-picker");
  body.append(
    el(
      "p",
      "picker-intro",
      t("Выберите адаптер и программу. Перед запуском проверьте выбранную цель внизу окна."),
    ),
  );
  // Сводка выбранной цели — в футере рядом с кнопкой запуска.
  const summary = el("div", "picker-summary");

  /** Подсветить выбранную строку и проставить aria-pressed у остальных. */
  const selectOption = (container: HTMLElement, selected: Element | null): void => {
    for (const node of container.querySelectorAll("button")) {
      node.classList.toggle("is-active", node === selected);
      node.setAttribute("aria-pressed", String(node === selected));
    }
  };

  // 01 — адаптер FTDI / USB / COM-порт
  body.append(el("div", "sec__title", t("01  /  Адаптер FTDI / USB")));
  const adapters = el("div", "decoded");
  if (!devices.length) {
    adapters.append(div("muted", t("FTDI-шнурки не найдены — проверьте драйвер и подключение.")));
  } else {
    const none = el("button", "format-option", t("не указывать (любой шнурок)"));
    none.type = "button";
    none.addEventListener("click", () => {
      chosenAdapter = null;
      selectOption(adapters, none);
      updateStart();
    });
    adapters.append(none);
    for (const d of devices) {
      const row = el("button", "format-option");
      row.type = "button";
      const title = [d.description || "FTDI", d.serial ? `· ${d.serial}` : "", d.com_port != null ? `· COM${d.com_port}` : ""]
        .filter(Boolean)
        .join(" ");
      row.append(el("div", "format-option__title", title), el("div", "format-option__desc", d.source || ""));
      if (chosenAdapter === d.serial || (!d.serial && chosenAdapter === d.description)) row.classList.add("is-active");
      row.addEventListener("click", () => {
        chosenAdapter = d.serial || d.description;
        selectOption(adapters, row);
        updateStart();
      });
      adapters.append(row);
    }
  }
  selectOption(adapters, adapters.querySelector(".is-active"));
  body.append(adapters);

  // 02 — программа: поиск по имени, PID и заголовку окна
  const progTitle = el("div", "sec__title", t("02  /  Программа"));
  progTitle.style.marginTop = "12px";
  body.append(progTitle);
  const programs = el("div", "decoded");
  programs.classList.add("picker-programs");
  const query = textInput(t("Поиск по имени, PID или окну"));
  query.type = "search";
  query.setAttribute("aria-label", t("Поиск программы"));
  const noResults = el("p", "muted", t("Нет совпадений. Измените запрос или укажите PID."));
  noResults.hidden = true;
  body.append(query);
  // Фильтр по тексту строки: в нём есть имя/known_tool, «pid N» и заголовок окна.
  query.oninput = () => {
    const needle = query.value.trim().toLowerCase();
    let found = 0;
    for (const row of programs.querySelectorAll("button")) {
      row.hidden = !(row.textContent ?? "").toLowerCase().includes(needle);
      if (!row.hidden) found++;
    }
    noResults.hidden = found > 0;
  };
  if (!tools.length) {
    programs.append(
      div("muted", t("Программы не найдены — переключите фильтр в панели «ПРОГРАММЫ» или введите PID.")),
    );
  }
  for (const tool of tools) {
    const row = el("button", "format-option");
    row.type = "button";
    const caps = [
      tool.has_ftd2xx ? "FTDI" : "",
      tool.has_j2534 ? "J2534" : "",
      tool.has_usb ? "USB" : "",
      tool.window_title ? t("окно") : "",
    ]
      .filter(Boolean)
      .join(" · ");
    row.append(
      el("div", "format-option__title", `${tool.known_tool || tool.name}  ·  pid ${tool.pid}`),
      el("div", "format-option__desc", [caps, tool.window_title].filter(Boolean).join(" · ")),
    );
    if (chosenPid === tool.pid) row.classList.add("is-active");
    row.addEventListener("click", () => {
      chosenPid = tool.pid;
      manualPid = null;
      selectOption(programs, row);
      manualHint.textContent = "";
      updateStart();
    });
    programs.append(row);
  }
  // Ни один процесс не выбран заранее: старт заблокирован до явного выбора.
  selectOption(programs, null);
  body.append(programs, noResults);

  // Ручной PID — на случай, если процесса нет в списке.
  const manual = el("div", "rail-pid");
  manual.style.marginTop = "8px";
  manual.classList.add("picker-pid");
  const manualInput = textInput(t("PID вручную, если программы нет в списке"), "");
  manualInput.inputMode = "numeric";
  manualInput.setAttribute("aria-label", t("PID программы"));
  const manualBtn = primary(t("Выбрать PID"), () => {
    const raw = manualInput.value.trim();
    // PID Win32: только цифры, целое в диапазоне 1..2147483647.
    if (!/^\d+$/.test(raw)) {
      manualHint.textContent = t("Введите положительный целый PID (только цифры).");
      manualInput.focus();
      return;
    }
    const pid = Number(raw);
    if (!Number.isInteger(pid) || pid < 1 || pid > 2147483647) {
      manualHint.textContent = t("PID должен быть целым в диапазоне 1..2147483647.");
      manualInput.focus();
      return;
    }
    manualPid = pid;
    chosenPid = pid;
    selectOption(programs, null);
    manualHint.textContent = t("выбран PID {pid}", { pid });
    updateStart();
  });
  manualInput.onkeydown = (e) => {
    if (e.key === "Enter") manualBtn.click();
  };
  manual.append(manualInput, manualBtn);
  const manualHint = el("div", "field__hint", "");
  body.append(manual, manualHint);

  let m: { close: () => void };
  const start = primary(t("начать сессию"), () => {
    const pid = manualPid ?? chosenPid;
    if (!pid) {
      store.toast("warn", t("выберите программу или укажите PID"));
      return;
    }
    const tool = tools.find((x) => x.pid === pid);
    const label = tool?.known_tool || tool?.name?.replace(/\.exe$/i, "") || `pid ${pid}`;
    m.close();
    // Программа из списка → attach с выбранным адаптером; PID введён вручную
    // без адаптера → attachPid (универсальный путь по номеру процесса).
    if (manualPid !== null && !chosenAdapter) void store.attachPid(pid, label);
    else void store.attach(pid, label, chosenAdapter ?? undefined);
  });
  const cancel = ghost(t("отмена"), () => m.close());
  start.disabled = true;
  start.title = t("сначала выберите программу (или введите PID)");
  const updateStart = (): void => {
    const pid = manualPid ?? chosenPid;
    const tool = tools.find((x) => x.pid === pid);
    summary.textContent = [
      chosenAdapter || t("Любой адаптер"),
      pid ? `${tool?.known_tool || tool?.name || t("Программа")} · PID ${pid}` : t("Выберите программу или PID"),
    ].join("  /  ");
    start.disabled = !pid;
    start.title = pid ? "" : t("сначала выберите программу (или введите PID)");
  };
  updateStart();
  m = modal({
    title: t("Новая сессия: выбор цели"),
    body,
    footer: [summary, cancel, start],
    width: 720,
  });
}

function div(cls: string, text: string): HTMLElement {
  const d = el("div", cls, text);
  return d;
}
