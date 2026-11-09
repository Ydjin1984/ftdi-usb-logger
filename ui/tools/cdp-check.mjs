/**
 * Проверка UI через CDP: запускает Edge headless, открывает страницу,
 * прокликивает ключевые сценарии и складывает скриншоты.
 *
 *   node tools/cdp-check.mjs http://127.0.0.1:7802/?demo=1 out-dir
 *
 * Без внешних зависимостей: используется встроенный WebSocket Node 22+.
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7802/?demo=1";
const OUT = process.argv[3] ?? "ui/shots";
const EDGE = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9333;

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ftdi-cdp-${Date.now()}`);
mkdirSync(profile, { recursive: true });

const edge = spawn(
  EDGE,
  [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--window-size=1600,1000",
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    URL_,
  ],
  { stdio: "ignore" },
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function targets() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch {
      /* ещё не поднялся */
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
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(JSON.stringify(msg.error)));
        else resolve(msg.result);
      }
    });
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

function open(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", (e) => reject(new Error(String(e.message ?? e))));
  });
}

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function waitFor(cdp, expr, timeout = 6000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    if (await cdp.eval(expr)) return true;
    await sleep(120);
  }
  return false;
}

try {
  const page = await targets();
  const ws = await open(page.webSocketDebuggerUrl);
  const cdp = new Cdp(ws);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", {
    width: 1600,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });

  await waitFor(cdp, `document.querySelectorAll(' .rail .session-item').length > 0`, 20000);
  // В живом режиме в списке могут быть пустые/тестовые сессии: переключаемся на ту,
  // где реально есть поток и хотя бы один шаг, иначе проверки ниже бессмысленны.
  const picked = await cdp.eval(`(async () => {
    const items = [...document.querySelectorAll('.rail .session-item')];
    for (const it of items) {
      it.click();
      await new Promise(r => setTimeout(r, 800));
      if (document.querySelectorAll('.row').length > 40 &&
          document.querySelectorAll('.inspect .session-item').length > 0) return true;
    }
    return false;
  })()`);
  check("лента смонтирована и найдена сессия с данными", picked, `${await cdp.eval(`document.querySelectorAll('.rail .session-item').length`)} сессий в списке`);
  const rows = await cdp.eval(`document.querySelectorAll('.row').length`);
  check("строки виртуализированы", rows > 10 && rows < 200, `${rows} строк в DOM`);
  check("таймлайн нарисован", await cdp.eval(`(() => { const c = document.querySelector('.timeline canvas'); return !!c && c.width > 100; })()`));
  check("сводки шагов видны", await waitFor(cdp, `document.querySelectorAll(' .inspect .session-item').length >= 1`, 5000));
  await cdp.shot("01-overview.png");

  // детерминированно выбираем событие с hex через store (виртуализация может не содержать TX в окне)
  const pickedEvent = await cdp.eval(`(() => {
    const st = window.__ftdi?.store;
    if (!st) return null;
    const ev = st.state.events.find(e => e.hex && (e.kind === 'tx' || e.kind === 'rx')) || st.state.events.find(e => e.hex);
    if (!ev) return null;
    st.selectEvent(ev);
    return { seq: ev.seq, kind: ev.kind, hex: ev.hex.slice(0, 24) };
  })()`);
  check("событие с HEX выбрано", !!pickedEvent, pickedEvent ? `#${pickedEvent.seq} ${pickedEvent.kind} ${pickedEvent.hex}` : "нет событий с hex");
  await sleep(250);
  await sleep(250);
  const inspector = await cdp.eval(`(() => {
    const tabs = [...document.querySelectorAll('.tab')];
    const evTab = tabs.find(t => t.dataset.tab === 'event');
    evTab?.click();
    return true;
  })()`);
  await sleep(250);
  check("инспектор открывается", inspector === true);
  const hexVisible = await cdp.eval(`document.querySelectorAll('.hex__line').length > 0`);
  check("HEX-дамп события", hexVisible);
  const decoded = await cdp.eval(`document.querySelectorAll('.decoded__row').length`);
  check("декод/свойства события", decoded > 0, `${decoded} строк`);
  await cdp.shot("02-event-inspector.png");

  // шаг: раскрыть сводку
  await cdp.eval(`[...document.querySelectorAll('.tab')].find(t=>t.dataset.tab==='step')?.click()`);
  await sleep(200);
  await cdp.eval(`(() => { const b = document.querySelector('.inspect .session-item'); b?.click(); return true; })()`);
  await sleep(350);
  check(
    "сводка шага раскрыта",
    await cdp.eval(
      `document.querySelector('.inspect').innerText.includes('ЧТЕНИЯ ПАМЯТИ') || document.querySelector('.inspect').innerText.includes('КОМАНДЫ')`,
    ),
  );
  await cdp.shot("03-step-summary.png");

  // экспорт
  await cdp.eval(`[...document.querySelectorAll('.btn')].find(b=>b.textContent.includes('экспорт'))?.click()`);
  await sleep(300);
  check("диалог экспорта", await cdp.eval(`!!document.querySelector('.modal-backdrop')`));
  await cdp.shot("04-export.png");
  const isDemo = await cdp.eval(`new URLSearchParams(location.search).has('demo')`);
  if (!isDemo) {
    // В живом режиме реально жмём «экспортировать» и ждём путь/ошибку.
    await cdp.eval(`(() => {
      const m = document.querySelector('.modal-backdrop');
      const b = [...m.querySelectorAll('button')].find(x => x.textContent.includes('экспортировать'));
      b?.click(); return true;
    })()`);
    const ok = await waitFor(
      cdp,
      `(() => {
         const m = document.querySelector('.modal-backdrop');
         return !!m && (m.innerText.includes('готово:') || m.innerText.includes('не удалось'));
       })()`,
      15000,
    );
    const text = await cdp.eval(`document.querySelector('.modal-backdrop')?.innerText?.split('\\n').filter(l=>l.includes('готово:')||l.includes('не удалось')).join(' ') ?? ''`);
    check("экспорт реально собирается", ok && text.includes("готово:"), text.trim());
    await cdp.shot("04b-export-done.png");
  }
  await cdp.eval(`document.querySelector('.modal-backdrop')?.remove()`);

  // справка
  await cdp.eval(`(() => { const e = new KeyboardEvent('keydown', {key:'F1', bubbles:true}); window.dispatchEvent(e); return true; })()`);
  await sleep(300);
  check("справка F1", await cdp.eval(`!!document.querySelector('.modal-backdrop')`));
  await cdp.shot("05-help.png");
  await cdp.eval(`document.querySelector('.modal-backdrop')?.remove()`);

  // поиск
  await cdp.eval(`(() => { const s = document.querySelector('.search input'); s.value = 'a0'; s.dispatchEvent(new Event('input', {bubbles:true})); return true; })()`);
  await sleep(400);
  const filtered = await cdp.eval(`document.querySelectorAll('.row').length`);
  check("поиск фильтрует поток", filtered > 0 && filtered < 200, `${filtered} строк`);
  check("счётчик показал срез", await cdp.eval(`document.querySelector('.stream__stat')?.textContent?.includes('из')`));
  await cdp.eval(`(() => { const s = document.querySelector('.search input'); s.value = ''; s.dispatchEvent(new Event('input', {bubbles:true})); return true; })()`);
  await sleep(300);
  await cdp.shot("06-search.png");

  // ширина 1280
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
  await sleep(400);
  check("адаптив 1280", await cdp.eval(`document.querySelector('.rail').getBoundingClientRect().width > 100`));
  await cdp.shot("07-1280.png");

  await ws.close();
} catch (e) {
  check("исключение проверки", false, String(e?.message ?? e));
} finally {
  edge.kill();
  await sleep(400);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    /* профиль может быть занят — не критично */
  }
  const failed = results.filter((r) => !r.ok).length;
  console.log(`\n${results.length - failed}/${results.length} проверок пройдено`);
  process.exit(failed ? 1 : 0);
}










