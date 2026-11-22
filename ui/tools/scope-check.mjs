/**
 * E2E интеграции осциллографа в интерфейс через CDP (Edge headless).
 *
 *   node ui/tools/scope-check.mjs [pageUrl] [outDir]
 *
 * Движок ожидается на 127.0.0.1:7811 (адрес страницы — `SCOPE_PAGE`, порт CDP —
 * `SCOPE_CDP_PORT`). Если движок не запущен, проверять нечего: скрипт печатает
 * об этом и выходит с кодом 2 — поднимать движок он не имеет права.
 *
 * Что проверяется:
 *   1. кнопка `#scope-btn` и пилюля `#scope-pill` в шапке;
 *   2. клик по кнопке открывает диалог «Осциллограф»;
 *   3. переключатель реально меняет `enabled` (сверяемся с GET /api/scope/config);
 *   4. «Проверить связь» даёт page_ok/frame_ok; если сервис осциллографа не
 *      отвечает — это SKIP, а не FAIL (UI обязан пережить это без ошибок);
 *   5. в диалоге ровно восемь строк CH1–CH8;
 *   6. диалог закрывается, JS-ошибок в консоли нет;
 *   7. состояние пользователя восстанавливается: `enabled` возвращается к
 *      прежнему значению (в том числе при падении проверки).
 *
 * Старый движок без `/api/scope/*` (404) — не провал: проверяем аккуратную
 * деградацию (пилюли нет, диалог объясняет, что движок не поддерживает) и
 * помечаем остальные пункты SKIP.
 *
 * Внешних зависимостей нет: WebSocket встроен в Node 22+.
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ENGINE = (process.env.SCOPE_ENGINE ?? "http://127.0.0.1:7811").replace(/\/+$/, "");
const URL_ = process.argv[2] ?? process.env.SCOPE_PAGE ?? `${ENGINE}/`;
const OUT = process.argv[3] ?? "ui/shots";
const EDGE = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const CDP_PORT = Number(process.env.SCOPE_CDP_PORT ?? 9336);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const results = [];
function record(status, name, detail = "") {
  results.push({ status, name, detail });
  console.log(`${status}  ${name}${detail ? ` — ${detail}` : ""}`);
}
const pass = (name, detail) => record("PASS", name, detail);
const fail = (name, detail) => record("FAIL", name, detail);
const skip = (name, detail) => record("SKIP", name, detail);

/** Ожидание асинхронного условия (промис-предиката) с шагом 150 мс. */
async function waitUntil(fn, timeout = 6000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    try {
      if (await fn()) return true;
    } catch {
      /* ещё не готово */
    }
    await sleep(150);
  }
  return false;
}

async function getConfig() {
  try {
    const res = await fetch(`${ENGINE}/api/scope/config`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function setEnabled(enabled) {
  try {
    const res = await fetch(`${ENGINE}/api/scope/config`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled }),
      signal: AbortSignal.timeout(4000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/* ── 1. Движок: без него проверять нечего ──────────────────────────────── */

let engineOk = false;
try {
  const res = await fetch(`${ENGINE}/api/health`, { signal: AbortSignal.timeout(3000) });
  engineOk = res.ok;
} catch {
  engineOk = false;
}
if (!engineOk) {
  console.error(`движок не запущен на ${ENGINE}`);
  console.error("нужен запущенный движок на 127.0.0.1:7811 — e2e сам его не поднимает.");
  process.exit(2);
}

const beforeConfig = await getConfig();
const supported = beforeConfig != null;
console.log(
  `движок ${ENGINE}: осциллограф ${supported ? "поддерживается" : "НЕ поддерживается (404 — старая сборка)"}`,
);
const beforeEnabled = supported ? beforeConfig.enabled === true : null;

/* ── 2. Браузер ─────────────────────────────────────────────────────────── */

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ftdi-scope-cdp-${Date.now()}`);
mkdirSync(profile, { recursive: true });

const edge = spawn(
  EDGE,
  [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--window-size=1440,1000",
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    URL_,
  ],
  { stdio: "ignore" },
);

async function targets() {
  for (let i = 0; i < 80; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch {
      /* браузер ещё поднимается */
    }
    await sleep(250);
  }
  throw new Error("CDP не поднялся");
}

let nextId = 1;
class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.pending = new Map();
    this.handlers = new Map();
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
        return;
      }
      if (msg.method) {
        const handler = this.handlers.get(msg.method);
        if (handler) handler(msg.params);
      }
    });
  }
  on(method, handler) {
    this.handlers.set(method, handler);
  }
  send(method, params = {}) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression) {
    const r = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text ?? "eval failed");
    return r.result?.value;
  }
  async shot(name) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    const path = join(OUT, name);
    writeFileSync(path, Buffer.from(r.data, "base64"));
    console.log(`  shot: ${path}`);
  }
}

function openWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", (e) => reject(new Error(String(e.message ?? e))));
  });
}

async function waitFor(cdp, expr, timeout = 8000) {
  return waitUntil(() => cdp.eval(expr), timeout);
}

const jsErrors = [];

try {
  const page = await targets();
  const ws = await openWs(page.webSocketDebuggerUrl);
  const cdp = new Cdp(ws);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Log.enable");
  cdp.on("Runtime.exceptionThrown", (p) => {
    jsErrors.push(p?.exceptionDetails?.text ?? "exception");
  });
  cdp.on("Log.entryAdded", (p) => {
    const entry = p?.entry;
    if (!entry || entry.level !== "error") return;
    // Сетевые 404 (favicon и т.п.) — не JS-ошибки.
    if (entry.source !== "javascript" && entry.source !== "exception") return;
    jsErrors.push(`${entry.source}: ${entry.text}`);
  });

  // Свои слушатели на будущее (ошибки после загрузки страницы).
  await cdp.eval(`(() => {
    window.__scopeErrors = [];
    window.addEventListener("error", (e) => window.__scopeErrors.push(String(e.message || e.type)));
    window.addEventListener("unhandledrejection", (e) => window.__scopeErrors.push(String(e.reason)));
    return true;
  })()`);

  const booted = await waitFor(
    cdp,
    `!!document.getElementById('app') && !document.getElementById('app').hidden`,
    20000,
  );
  booted ? pass("страница загрузилась") : fail("страница загрузилась");
  await cdp.shot("scope-01-topbar.png");

  // Страница может быть собрана БЕЗ интеграции: движок раздаёт собственную
  // копию ui/dist из каталога установки, а не свежую сборку репозитория.
  // Это не дефект UI, поэтому дальше не проверяем и говорим прямо.
  const pageHasScope = await cdp.eval(`!!document.querySelector('#scope-btn')`);
  if (!pageHasScope) {
    fail(
      "кнопка «Осциллограф» в шапке",
      "на странице нет интеграции: движок раздаёт свою ui/dist — соберите ui и обновите установку",
    );
    skip("остальные проверки интерфейса", "страница собрана без интеграции осциллографа");
  } else if (supported) {
    /* ── Полная проверка на движке с поддержкой осциллографа ───────────── */

    const hasBtn = await cdp.eval(`!!document.querySelector('#scope-btn')`);
    hasBtn ? pass("кнопка «Осциллограф» в шапке") : fail("кнопка «Осциллограф» в шапке");

    // Пилюля появляется после первого опроса статуса (старт + каждые 2 с).
    const hasPill = await waitFor(cdp, `!!document.querySelector('#scope-pill')`, 15000);
    const pillText = hasPill
      ? await cdp.eval(`(document.querySelector('#scope-pill')?.innerText || '').replace(/\\n/g, ' ')`)
      : "";
    hasPill ? pass("пилюля осциллографа в шапке", pillText) : fail("пилюля осциллографа в шапке");

    await cdp.eval(`document.querySelector('#scope-btn')?.click()`);
    const dialog = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.modal-backdrop .modal');
         const title = box ? (box.querySelector('.modal__title')?.textContent || '') : '';
         return !!box && /Осциллограф|Oscilloscope/.test(title);
       })()`,
      6000,
    );
    dialog ? pass("диалог открывается кнопкой из шапки") : fail("диалог открывается кнопкой из шапки");

    const chips = await cdp.eval(`document.querySelectorAll('.scope-ch').length`);
    chips === 8 ? pass("список CH1–CH8: восемь строк", `${chips}`) : fail("список CH1–CH8: восемь строк", `найдено ${chips}`);

    // Переключатель: реально меняем enabled и сверяемся с API.
    const want = !beforeEnabled;
    const clicked = await cdp.eval(`(() => {
      const el = document.querySelector('#scope-enabled');
      if (!el) return null;
      const was = el.checked;
      if (was !== ${want}) el.click();
      return { was, now: document.querySelector('#scope-enabled').checked };
    })()`);
    let flipOk = false;
    if (clicked) {
      flipOk = await waitUntil(async () => {
        const cfg = await getConfig();
        return !!cfg && cfg.enabled === want;
      }, 8000);
    }
    flipOk
      ? pass("переключатель меняет enabled через API", `enabled=${want}`)
      : fail("переключатель меняет enabled через API", clicked ? `было ${clicked.was}, стало ${clicked.now}` : "чекбокс не найден");

    // Проверка связи: сервис осциллографа может быть не запущен — это SKIP.
    // Кнопка блокируется на время предыдущего запроса — дожидаемся её.
    await waitUntil(
      () =>
        cdp.eval(
          `(() => { const b = document.querySelector('[data-testid="scope-test"]'); return !!b && !b.disabled; })()`,
        ),
      8000,
    );
    await cdp.eval(`document.querySelector('[data-testid="scope-test"]')?.click()`);
    const tested = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.scope-test');
         return !!box && (box.dataset.ok === '1' || box.dataset.ok === '0');
       })()`,
      20000,
    );
    const testInfo = await cdp.eval(`(() => {
      const box = document.querySelector('.scope-test');
      return box ? { ok: box.dataset.ok, text: (box.innerText || '').replace(/\\n/g, ' | ') } : null;
    })()`);
    if (!tested || !testInfo) {
      fail("проверка связи: страница и кадр", "результат не появился");
    } else if (testInfo.ok === "1") {
      const hasPage = /HTTP\s*\d+/.test(testInfo.text);
      const hasFrame = /#\d+/.test(testInfo.text);
      hasPage && hasFrame
        ? pass("проверка связи: страница и кадр", testInfo.text)
        : fail("проверка связи: страница и кадр", testInfo.text);
    } else {
      skip("проверка связи: страница и кадр", `сервис осциллографа недоступен — ${testInfo.text}`);
    }

    await cdp.shot("scope-02-dialog.png");
    await cdp.eval(`document.querySelector('[data-testid="scope-close"]')?.click()`);
    const closed = await waitUntil(async () => !(await cdp.eval(`!!document.querySelector('.modal-backdrop')`)), 5000);
    closed ? pass("диалог закрывается") : fail("диалог закрывается");
    // Пилюля в состоянии записи: диалог закрыт, шапка видна целиком.
    await waitFor(cdp, `!!document.querySelector('#scope-pill')`, 5000);
    await cdp.shot("scope-03-recording.png");

    // Состояние пользователя: возвращаем enabled, как было до проверки.
    if (beforeEnabled != null) {
      const current = await getConfig();
      if (!current || current.enabled !== beforeEnabled) await setEnabled(beforeEnabled);
      const restored = await waitUntil(async () => {
        const cfg = await getConfig();
        return !!cfg && cfg.enabled === beforeEnabled;
      }, 8000);
      restored
        ? pass("прежнее enabled восстановлено", `enabled=${beforeEnabled}`)
        : fail("прежнее enabled восстановлено", `ожидали enabled=${beforeEnabled}`);
    }

    // Настройки → секция «Осциллограф» (пункт D) и вход в диалог из неё.
    const settingsOpened = await cdp.eval(`(() => {
      const btn = [...document.querySelectorAll('.icon-btn')].find((b) => (b.title || '').includes('J2534'));
      if (!btn) return false;
      btn.click();
      return true;
    })()`);
    const scopeSection = settingsOpened && (await waitFor(cdp, `!!document.querySelector('.scope-settings')`, 6000));
    scopeSection ? pass("секция «Осциллограф» в настройках") : fail("секция «Осциллограф» в настройках");
    // store обновляется опросом раз в 2 с: даём чекбоксу догнать восстановленное значение.
    await waitUntil(
      async () =>
        (await cdp.eval(
          `(() => { const cb = document.querySelector('#scope-settings-enabled'); return cb ? cb.checked : null; })()`,
        )) === beforeEnabled,
      6000,
    );
    const settingsSync = await cdp.eval(`(() => {
      const box = document.querySelector('.scope-settings');
      const cb = box ? box.querySelector('#scope-settings-enabled') : null;
      if (!box || !cb) return null;
      return { checked: cb.checked, text: (box.innerText || '').replace(/\\n/g, ' | ') };
    })()`);
    settingsSync && settingsSync.checked === beforeEnabled
      ? pass("чекбокс настроек совпадает с конфигом", `enabled=${settingsSync.checked}`)
      : fail("чекбокс настроек совпадает с конфигом", settingsSync ? `checked=${settingsSync.checked}` : "чекбокс не найден");
    await cdp.shot("scope-04-settings.png");

    // Переключение прямо в настройках тоже сохраняется через API (пункт E).
    const flipTo = !beforeEnabled;
    await cdp.eval(`(() => {
      const cb = document.querySelector('#scope-settings-enabled');
      if (cb && cb.checked !== ${flipTo}) cb.click();
      return true;
    })()`);
    const flipped = await waitUntil(async () => {
      const cfg = await getConfig();
      return !!cfg && cfg.enabled === flipTo;
    }, 8000);
    flipped
      ? pass("переключатель в настройках меняет enabled", `enabled=${flipTo}`)
      : fail("переключатель в настройках меняет enabled");
    // Возвращаем прежнее значение через тот же чекбокс (проверка обратимости).
    await waitUntil(
      () => cdp.eval(`!document.querySelector('#scope-settings-enabled')?.disabled`),
      8000,
    );
    await cdp.eval(`(() => {
      const cb = document.querySelector('#scope-settings-enabled');
      if (cb && cb.checked !== ${beforeEnabled}) cb.click();
      return true;
    })()`);
    await waitUntil(async () => {
      const cfg = await getConfig();
      return !!cfg && cfg.enabled === beforeEnabled;
    }, 8000);

    await cdp.eval(`document.querySelector('[data-testid="scope-configure"]')?.click()`);
    const fromSettings = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.modal-backdrop .modal');
         const title = box ? (box.querySelector('.modal__title')?.textContent || '') : '';
         return !!box && /Осциллограф|Oscilloscope/.test(title) && document.querySelectorAll('.scope-ch').length === 8;
       })()`,
      6000,
    );
    fromSettings
      ? pass("«Настроить…» открывает диалог осциллографа")
      : fail("«Настроить…» открывает диалог осциллографа");
    await cdp.eval(`document.querySelector('[data-testid="scope-close"]')?.click()`);
    await waitUntil(async () => !(await cdp.eval(`!!document.querySelector('.modal-backdrop')`)), 5000);

    // Поток и инспектор (пункт G): чипы SCOPE/UI, бейджи строк и meta события.
    // События подкладываем в store напрямую — движок-заглушка их не присылает,
    // а проверяется отрисовка, а не запись.
    const filterChips = await cdp.eval(
      `!!document.querySelector('.chip[data-group="scope"]') && !!document.querySelector('.chip[data-group="ui"]')`,
    );
    filterChips ? pass("чипы фильтра SCOPE и UI") : fail("чипы фильтра SCOPE и UI");

    await cdp.eval(`(() => {
      const st = window.__ftdi.store;
      const base = { transport: 'app', hex: '', len: 0, raw: '', rc: null, step: null };
      st.state.events = [
        { ...base, seq: 1, t: 1.5, wall: '2026-11-22T07:20:01Z', kind: 'scope', api: 'SCOPE',
          text: 'подключён к осциллографу', meta: { state: 'recording', frames: 420, gaps: 2 } },
        { ...base, seq: 2, t: 2.5, wall: '2026-11-22T07:20:02Z', kind: 'ui_action', api: 'UIA',
          text: 'Записать', meta: { action: 'write', automation_id: 'btnWrite', control_type: 'Button',
            window: 'PCMflash', process: 'PCMflash.exe', pid: 1234, source: 'uia', event: 'invoke' } },
      ];
      st.state.total = 2;
      st.state.lastSeq = 2;
      st.state.firstSeq = 1;
      st.emit();
      return true;
    })()`);
    const streamOk = await waitFor(
      cdp,
      `document.querySelectorAll('.row--scope').length > 0 && document.querySelectorAll('.row--ui').length > 0`,
      6000,
    );
    const badges = await cdp.eval(`(() => {
      const kind = (sel) => (document.querySelector(sel + ' .row__kind')?.textContent || '').trim();
      return { scope: kind('.row--scope'), ui: kind('.row--ui') };
    })()`);
    streamOk && badges.scope === "SCOPE" && badges.ui === "UI"
      ? pass("строки SCOPE и UI в потоке", `${badges.scope}/${badges.ui}`)
      : fail("строки SCOPE и UI в потоке", JSON.stringify(badges));

    // Инспектор: meta ui_action (название, action, automation_id, окно, процесс).
    await cdp.eval(`document.querySelector('.row--ui')?.click()`);
    await cdp.eval(`[...document.querySelectorAll('.tab')].find((t) => t.dataset.tab === 'event')?.click()`);
    const inspector = await cdp.eval(`(document.querySelector('.inspect')?.innerText || '').replace(/\\n/g, ' | ')`);
    /automation_id/i.test(inspector) && /PCMflash/.test(inspector) && /write/.test(inspector)
      ? pass("инспектор показывает meta ui_action")
      : fail("инспектор показывает meta ui_action", inspector.slice(0, 160));

    // Фильтр SCOPE: выключенный чип убирает строки, включённый возвращает.
    await cdp.eval(`document.querySelector('.chip[data-group="scope"]')?.click()`);
    const hidden = await waitFor(cdp, `document.querySelectorAll('.row--scope').length === 0`, 4000);
    await cdp.eval(`document.querySelector('.chip[data-group="scope"]')?.click()`);
    const shown = await waitFor(cdp, `document.querySelectorAll('.row--scope').length > 0`, 4000);
    hidden && shown ? pass("фильтр SCOPE скрывает и возвращает строки") : fail("фильтр SCOPE скрывает и возвращает строки");
  } else {
    /* ── Старый движок: аккуратная деградация, а не падение ─────────────── */

    const hasBtn = await cdp.eval(`!!document.querySelector('#scope-btn')`);
    hasBtn ? pass("кнопка «Осциллограф» в шапке") : fail("кнопка «Осциллограф» в шапке");

    const noPill = await cdp.eval(`!document.querySelector('#scope-pill')`);
    noPill ? pass("пилюля скрыта на старом движке") : fail("пилюля скрыта на старом движке");

    await cdp.eval(`document.querySelector('#scope-btn')?.click()`);
    const unsupported = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.scope-unsupported');
         return !!box && !box.hidden && (box.textContent || '').includes('не поддерживает');
       })()`,
      6000,
    );
    unsupported
      ? pass("диалог объясняет, что движок не поддерживает осциллограф")
      : fail("диалог объясняет, что движок не поддерживает осциллограф");

    await cdp.eval(`document.querySelector('[data-testid="scope-close"]')?.click()`);
    const closed = await waitUntil(async () => !(await cdp.eval(`!!document.querySelector('.modal-backdrop')`)), 5000);
    closed ? pass("диалог закрывается") : fail("диалог закрывается");

    // Настройки на старом движке: секция честно говорит об отсутствии поддержки.
    await cdp.eval(`(() => {
      const btn = [...document.querySelectorAll('.icon-btn')].find((b) => (b.title || '').includes('J2534'));
      if (!btn) return false;
      btn.click();
      return true;
    })()`);
    const section = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.scope-settings');
         return !!box && (box.innerText || '').includes('не поддерживает');
       })()`,
      6000,
    );
    section
      ? pass("секция настроек объясняет отсутствие поддержки")
      : fail("секция настроек объясняет отсутствие поддержки");
    const toggleDisabled = await cdp.eval(
      `!!document.querySelector('#scope-settings-enabled')?.disabled`,
    );
    toggleDisabled
      ? pass("переключатель настроек заблокирован")
      : fail("переключатель настроек заблокирован");
    await cdp.eval(`document.querySelector('[data-testid="scope-configure"]')?.click()`);
    const fromSettings = await waitFor(
      cdp,
      `(() => {
         const box = document.querySelector('.scope-unsupported');
         return !!box && !box.hidden;
       })()`,
      6000,
    );
    fromSettings
      ? pass("«Настроить…» открывает диалог на старом движке")
      : fail("«Настроить…» открывает диалог на старом движке");
    await cdp.eval(`document.querySelector('[data-testid="scope-close"]')?.click()`);
    await waitUntil(async () => !(await cdp.eval(`!!document.querySelector('.modal-backdrop')`)), 5000);

    skip("переключатель меняет enabled через API", "движок старой сборки: /api/scope/config → 404");
    skip("проверка связи: страница и кадр", "движок старой сборки: /api/scope/test → 404");
    skip("список CH1–CH8: восемь строк", "движок старой сборки: нет /api/scope/status");
  }

  // Ошибки, накопившиеся у страницы.
  const pageErrors = await cdp.eval(`Array.isArray(window.__scopeErrors) ? window.__scopeErrors.slice(0, 5) : []`);
  const errors = [...jsErrors, ...(pageErrors ?? [])].filter(Boolean);
  errors.length
    ? fail("консоль без JS-ошибок", errors.slice(0, 3).join(" | "))
    : pass("консоль без JS-ошибок");

  await ws.close();
} catch (e) {
  fail("исключение проверки", String(e?.message ?? e));
} finally {
  // Страховка: если проверка упала посреди переключения — вернуть enabled.
  if (beforeEnabled != null) {
    const cfg = await getConfig().catch(() => null);
    if (!cfg || cfg.enabled !== beforeEnabled) await setEnabled(beforeEnabled);
  }
  edge.kill();
  await sleep(400);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    /* профиль может быть занят — не критично */
  }
  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;
  const skipped = results.filter((r) => r.status === "SKIP").length;
  console.log(`\n${passed}/${passed + failed} passed${skipped ? `, ${skipped} skipped` : ""}`);
  process.exit(failed ? 1 : 0);
}

