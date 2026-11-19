/**
 * i18n: русский (по умолчанию) и английский.
 *
 * Ключ перевода — русская фраза (шаблон), значения — английские. Для русского
 * языка словарь не нужен: t() возвращает сам ключ. Подстановки — {name}.
 *
 * Модули регистрируют свои фразы через msg({...}) на верхнем уровне — так
 * переводы лежат рядом с местом использования и не конфликтуют между файлами.
 * Общие фразы (отмена/закрыть/готово…) собраны ниже.
 *
 * Смена языка перезагружает страницу: компоненты строят текст один раз в
 * конструкторе, и полный перезапуск — самый надёжный путь без утечек слушателей.
 *
 * Выбор языка хранится в двух местах: в адресе (`?lang=en`) и в localStorage.
 * Адрес — основной канал: он работает и при заблокированном хранилище, где
 * переключение раньше молча не применялось.
 */

export type Lang = "ru" | "en";

const STORAGE_KEY = "ftdi.lang";
const URL_PARAM = "lang";

/** Язык из адреса: `?lang=en`. */
function langFromUrl(): Lang | null {
  try {
    const v = new URL(location.href).searchParams.get(URL_PARAM);
    return v === "en" || v === "ru" ? (v as Lang) : null;
  } catch {
    return null;
  }
}

function readLang(): Lang {
  // Адрес — самый надёжный носитель выбора: он работает и тогда, когда
  // localStorage недоступен (гостевой/инкогнито-профиль, запрет данных сайтов,
  // переполнение квоты). Раньше в этом случае setLang молча не срабатывал:
  // выбор писался в никуда, перезагрузка читала «ru», интерфейс оставался
  // русским — без единой ошибки в консоли.
  const fromUrl = langFromUrl();
  if (fromUrl) return fromUrl;
  try {
    return localStorage.getItem(STORAGE_KEY) === "en" ? "en" : "ru";
  } catch {
    return "ru";
  }
}

let current: Lang = readLang();
const listeners = new Set<(lang: Lang) => void>();

/**
 * Пометить страницу как непереводимую и выставить ей настоящий язык.
 *
 * UI открывается в Edge (`--app`), а у Edge есть встроенный переводчик: если
 * страница выглядит английской, он может перевести её обратно на русский —
 * и выбор английского «не срабатывал». Свои подписи приложение переводит
 * само, браузерный перевод ему только мешает, поэтому страница объявляется
 * непереводимой (`translate="no"`, `notranslate`, meta google).
 */
function applyDocumentLang(): void {
  const root = document.documentElement;
  root.lang = current;
  root.setAttribute("translate", "no");
  root.classList.add("notranslate");
  document.body?.classList.add("notranslate");
}

applyDocumentLang();

/** Английские переводы. Ключ — русская фраза (шаблон). */
const EN: Record<string, string> = {
  // ── общее ──────────────────────────────────────────────────────────────
  "закрыть": "close",
  "отмена": "cancel",
  "сохранить": "save",
  "готово": "done",
  "внимание": "attention",
  "ошибка": "error",
  "подсказка": "tip",
  "скопировать": "copy",
  "скопировать путь": "copy path",
  "путь скопирован": "path copied",
  "повторить": "retry",
  "обновить": "refresh",
  "поиск": "search",
  "фильтр": "filter",
  "все": "all",
  "нет данных": "no data",
  "не удалось": "failed",
  "сессия не выбрана": "no session selected",
  "нет активной сессии": "no active session",
  "демо-режим": "demo mode",
  "демо-режим: {what}": "demo mode: {what}",
  "секунд": "seconds",
  "секунды": "seconds",
  "обменов": "exchanges",
  "шагов": "steps",
  "байт": "bytes",
  "событий": "events",
  "ошибок": "errors",
  "файлов": "files",
  "чтений": "reads",
  "снимок": "screenshot",
  "скриншот": "screenshot",
  "метка": "mark",
  "заметка": "note",
  "шаг": "step",
  "сессия": "session",
  "шаг {n}": "step {n}",
  "шаг {n} открыт": "step {n} opened",
  "шаг {n} открыт: {title}": "step {n} opened: {title}",
  "шаг {n} закрыт": "step {n} closed",
  "{title} · {dur} с": "{title} · {dur} s",
  "шаг {n} закрыт: {exchanges} обменов": "step {n} closed: {exchanges} exchanges",
  "шаг {n} закрыт: {exchanges} обменов, {dur} с": "step {n} closed: {exchanges} exchanges, {dur} s",
  "шаг не открылся: {msg}": "step did not open: {msg}",
  "шаг не закрылся: {msg}": "step did not close: {msg}",
  "нет открытого шага": "no open step",
  "шаг открыт": "step open",
  "нет активной сессии — сначала подключитесь к программе":
    "no active session — connect to the tool first",
  // ── действия/тосты ─────────────────────────────────────────────────────
  "сессия {id} завершена": "session {id} finished",
  "сессия остановлена, отчёт собран": "session stopped, report collected",
  "захват запущен: {label}": "capture started: {label}",
  "attach не удался: {msg}": "attach failed: {msg}",
  "detach не удался: {msg}": "detach failed: {msg}",
  "новая сессия: {msg}": "new session: {msg}",
  "хуки сняты: повторите операцию": "hooks removed: repeat the operation",
  "хуки возвращены": "hooks restored",
  "хуки сняты (демо)": "hooks removed (demo)",
  "хуки возвращены (демо)": "hooks restored (demo)",
  "hookctl: {msg}": "hookctl: {msg}",
  "не удалось обновить список сессий: {msg}": "failed to refresh sessions: {msg}",
  "сессия не открылась: {msg}": "session did not open: {msg}",
  "не удалось догрузить историю: {msg}": "failed to load history: {msg}",
  "не удалось обновить устройства: {msg}": "failed to refresh devices: {msg}",
  "список программ: {msg}": "tool list: {msg}",
  "нужен корректный PID": "a valid PID is required",
  "USBPcap не запустился: {msg}": "USBPcap did not start: {msg}",
  "сырой USB-захват: {device}": "raw USB capture: {device}",
  "демо-режим: USBPcap недоступен": "demo mode: USBPcap is unavailable",
  "демо-режим: новая сессия недоступна": "demo mode: new session is unavailable",
  "демо-режим: attach недоступен": "demo mode: attach is unavailable",
  "демо-режим: detach недоступен": "demo mode: detach is unavailable",
  "демо-режим: скриншот недоступен": "demo mode: screenshot is unavailable",
  "демо-режим: экспорт недоступен": "demo mode: export is unavailable",
  "демо-режим: импорт недоступен": "demo mode: import is unavailable",
  "демо-режим: данные синтетические, устройство не требуется":
    "demo mode: synthetic data, no device required",
  "метка: {text}": "mark: {text}",
  "метка не записалась: {msg}": "mark was not saved: {msg}",
  "заметка сохранена": "note saved",
  "заметка не сохранилась: {msg}": "note was not saved: {msg}",
  "скриншот: {path}": "screenshot: {path}",
  "скриншот не снят: {msg}": "screenshot failed: {msg}",
  "готово: {path}": "done: {path}",
  "экспорт не удался: {msg}": "export failed: {msg}",
  "лог отправлен на сервер": "log sent to the server",
  "отправка не удалась: {msg}": "upload failed: {msg}",
  "импортирую {name}…": "importing {name}…",
  "лог импортирован, переразбор готов": "log imported, reparse ready",
  "импорт не удался: {msg}": "import failed: {msg}",
};

/** Добавить переводы домена (вызывается модулями на верхнем уровне). */
export function msg(map: Record<string, string>): void {
  for (const key of Object.keys(map)) EN[key] = map[key];
}

export function getLang(): Lang {
  return current;
}

/** Перевести фразу. Без английского перевода возвращается русский оригинал. */
export function t(template: string, vars?: Record<string, string | number>): string {
  const base = current === "en" ? (EN[template] ?? template) : template;
  if (!vars) return base;
  return base.replace(/\{(\w+)\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : whole,
  );
}

/**
 * Типовые ошибки движка (engine/src) — на английский. Движок отвечает
 * по-русски; без этого английский интерфейс показывал бы русский текст
 * в тостах. Незнакомое сообщение возвращается как есть.
 */
const SERVER_ERRORS: Array<[RegExp, string]> = [
  [/^сессия (\S+) не найдена$/, "session $1 not found"],
  [/^лог не найден:\s*(.*)$/, "log not found: $1"],
  [/^файл не найден:\s*(.*)$/, "file not found: $1"],
  [/^нечего экспортировать$/, "nothing to export"],
  [/^сессия уже идёт — сначала завершите текущий захват$/,
    "a session is already running — finish the current capture first"],
  [/^захват недоступен: движок запущен с --no-bridge$/,
    "capture is unavailable: the engine runs with --no-bridge"],
  [/^USBPcapCMD\.exe не найден — установите USBPcap \(desowin\.org\/usbpcap\)$/,
    "USBPcapCMD.exe not found — install USBPcap (desowin.org/usbpcap)"],
  [/^hookctl: ожидается pause\|resume, получено (.*)$/, "hookctl: pause|resume expected, got $1"],
  [/^мост не запущен — управление хуками недоступно$/,
    "the bridge is not running — hook control is unavailable"],
  [/^мост уже запущен.*$/, "the bridge is already running"],
  [/^Frida-мост отключён ключом --no-bridge$/, "the Frida bridge is disabled by --no-bridge"],
  [/^мост не запущен: stdin sidecar закрыт$/, "the bridge is not running: sidecar stdin is closed"],
  [/^шаг не открыт — закрывать нечего$/, "no step is open — nothing to close"],
  [/^сессия (\S+) пишется: reparse запрещён$/, "session $1 is recording: reparse is not allowed"],
  [/^процесс pid=(\d+) не найден — запустите инструмент и повторите attach$/,
    "process pid=$1 not found — start the tool and attach again"],
  [/^сессия не идёт — скриншот некуда сохранять$/,
    "no session is running — there is nowhere to save the screenshot"],
  [/^не известен pid целевого процесса$/, "the target process pid is unknown"],
  [/^не удалось снять скриншот окна pid=(\d+): (.*)$/, "failed to capture window pid=$1: $2"],
  [/^сессия не запущена$/, "no session is running"],
  [/^записать событие: (.*)$/, "write event: $1"],
  [/^сохранить шаг (\d+): (.*)$/, "save step $1: $2"],
  [/^пустой id сессии$/, "empty session id"],
  [/^недопустимый id сессии: (.*)$/, "invalid session id: $1"],
  [/^не удалось подобрать уникальный id сессии$/, "could not pick a unique session id"],
  [/^каталог сессии (.*) отсутствует$/, "session directory $1 is missing"],
  [/^недопустимый путь сессии$/, "invalid session path"],
  [/^скриншоты окна поддерживаются только на Windows$/,
    "window screenshots are supported on Windows only"],
  [/^окно pid=(\d+) имеет пустой размер \((\d+)x(\d+)\)$/,
    "window pid=$1 has an empty size ($2x$3)"],
  [/^таймаут операции с сессией$/, "session operation timed out"],
  [/^задача записи сессии не ответила$/, "the session writer did not respond"],
  [/^задача записи сессии остановлена$/, "the session writer was stopped"],
  [/^у сессии не задан каталог$/, "the session has no directory"],
  [/^HTTP (\d+)$/, "HTTP $1"],
];

/** Перевести сообщение об ошибке движка под текущий язык. */
export function errText(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err);
  if (current !== "en") return raw;
  for (const [re, repl] of SERVER_ERRORS) {
    if (re.test(raw)) return raw.replace(re, repl);
  }
  return raw;
}

export function onLangChange(fn: (lang: Lang) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Сменить язык и перезагрузить интерфейс (весь текст строится заново). */
export function setLang(next: Lang): void {
  if (next === current) return;
  current = next;
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    /* хранилище недоступно — выбранный язык поедет в адресе */
  }
  // Выбор дублируем в настройки приложения (prefs.json рядом с сессиями):
  // профиль браузера может смениться, а язык должен остаться.
  void savePrefs(next);
  for (const fn of listeners) fn(next);
  // Компоненты строят текст один раз в конструкторе, поэтому язык применяем
  // полной перезагрузкой. Выбор передаём в адресе (`?lang=en`), а не полагаемся
  // только на хранилище: так смена языка срабатывает и при заблокированном
  // localStorage, и переживает ручную перезагрузку страницы (F5).
  try {
    const url = new URL(location.href);
    url.searchParams.set(URL_PARAM, next);
    location.replace(url.toString());
  } catch {
    location.reload();
  }
}

/**
 * Перенести язык из адреса в хранилище и убрать параметр из адресной строки.
 * Если сохранить не удалось, параметр остаётся: тогда он — единственный носитель
 * выбора и переживёт следующую перезагрузку.
 */
export function syncLangParam(): void {
  const fromUrl = langFromUrl();
  if (!fromUrl) return;
  let saved = false;
  try {
    localStorage.setItem(STORAGE_KEY, fromUrl);
    saved = true;
  } catch {
    /* хранилище недоступно — оставляем язык в адресе */
  }
  if (!saved) return;
  try {
    const url = new URL(location.href);
    url.searchParams.delete(URL_PARAM);
    history.replaceState(history.state, "", url.toString());
  } catch {
    /* адрес не трогаем: роли не играет, язык уже применён */
  }
}

/**
 * Настройки языка в самом приложении (`prefs.json` в корне установки).
 *
 * localStorage живёт только в профиле браузера: гостевой профиль, очистка
 * данных, новый профиль Edge — и выбор терялся. Файл рядом с сессиями общий
 * для всех окон, профилей и браузеров, поэтому язык больше не «откатывается».
 */
const PREFS_URL = "/api/prefs";

async function fetchPrefs(): Promise<Lang | null> {
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 1200);
    const res = await fetch(PREFS_URL, { signal: ctl.signal, cache: "no-store" });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = (await res.json()) as { lang?: unknown };
    return data.lang === "en" || data.lang === "ru" ? (data.lang as Lang) : null;
  } catch {
    return null;
  }
}

async function savePrefs(lang: Lang): Promise<void> {
  try {
    await fetch(PREFS_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lang }),
    });
  } catch {
    /* движок недоступен — выбор останется в адресе и в хранилище */
  }
}

/**
 * Согласовать язык до построения интерфейса: явный `?lang=` главнее, иначе
 * берём сохранённый в приложении. Вызывается из main() до build().
 */
export async function syncLangPreference(): Promise<void> {
  const fromUrl = langFromUrl();
  if (fromUrl) {
    current = fromUrl;
    applyDocumentLang();
    await savePrefs(fromUrl);
    return;
  }
  const saved = await fetchPrefs();
  if (saved && saved !== current) {
    current = saved;
    try {
      localStorage.setItem(STORAGE_KEY, saved);
    } catch {
      /* хранилище недоступно — язык уже применён из настроек */
    }
    applyDocumentLang();
  }
}

/** Локализовать статическую разметку (index.html) и атрибут lang. */
export function localizeDom(root: ParentNode = document): void {
  document.documentElement.lang = current;
  const nodes = root.querySelectorAll<HTMLElement>("[data-i18n]");
  nodes.forEach((node) => {
    const key = node.dataset.i18n;
    if (key) node.textContent = t(key);
  });
  const titled = root.querySelectorAll<HTMLElement>("[data-i18n-title]");
  titled.forEach((node) => {
    const key = node.dataset.i18nTitle;
    if (key) node.title = t(key);
  });
  const placeheld = root.querySelectorAll<HTMLElement>("[data-i18n-placeholder]");
  placeheld.forEach((node) => {
    const key = node.dataset.i18nPlaceholder;
    if (key && node instanceof HTMLInputElement) node.placeholder = t(key);
  });
}
