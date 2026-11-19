/**
 * Проверка переключения языка «как у пользователя»: живой движок, селект в
 * шапке, перезагрузка, запись выбора в настройки приложения.
 *
 *   node tools/verify-lang-prefs.mjs http://127.0.0.1:7812/
 *
 * Проверяет три вещи:
 *   1) после выбора EN интерфейс действительно английский (кириллицы в подписях нет);
 *   2) выбор сохранён в prefs.json движка — переживёт смену профиля браузера;
 *   3) свежий профиль (без localStorage) открывается на сохранённом языке.
 */
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.argv[2] ?? "http://127.0.0.1:7811/";
const EDGE = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const CHROME = `(() => {
  const SKIP = ".device, .session-item, .row, .inspect, .tool, .timeline, .list__item, .hex, .decoded, datalist";
  let cyr = 0, latin = 0;
  const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walk.nextNode())) {
    const el = n.parentElement;
    if (!el || el.closest(SKIP)) continue;
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") continue;
    const t = (n.nodeValue ?? "").trim();
    if (!t) continue;
    if (/[А-Яа-яЁё]/.test(t)) cyr++; else if (/[A-Za-z]/.test(t)) latin++;
  }
  return { lang: document.documentElement.lang, cyr, latin, translate: document.documentElement.getAttribute("translate") };
})()`;

let nextId = 1;
function connect(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    const pending = new Map();
    ws.addEventListener("message", (ev) => {
      const m = JSON.parse(ev.data);
      if (m.id && pending.has(m.id)) {
        const { resolve: r, reject: j } = pending.get(m.id);
        pending.delete(m.id);
        if (m.error) j(new Error(JSON.stringify(m.error))); else r(m.result);
      }
    });
    ws.addEventListener("open", () => {
      resolve({
        ws,
        send: (method, params = {}) =>
          new Promise((r, j) => {
            const id = nextId++;
            pending.set(id, { resolve: r, reject: j });
            ws.send(JSON.stringify({ id, method, params }));
          }),
      });
    });
    ws.addEventListener("error", (e) => reject(new Error(String(e.message ?? e))));
  });
}

async function openPage(port, url) {
  const profile = join(tmpdir(), `ftdi-prefs-${Date.now()}-${Math.round(Math.random() * 1e6)}`);
  mkdirSync(profile, { recursive: true });
  const edge = spawn(
    EDGE,
    [
      "--headless=new",
      "--disable-gpu",
      "--hide-scrollbars",
      "--disable-features=Translate,TranslateUI",
      "--disable-translate",
      "--window-size=1600,1000",
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      url,
    ],
    { stdio: "ignore" },
  );

  let page = null;
  const until = Date.now() + 15000;
  while (Date.now() < until && !page) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      page = list.find((t) => t.type === "page" && t.url.startsWith("http")) ?? null;
    } catch {
      /* ещё поднимается */
    }
    if (!page) await sleep(150);
  }
  if (!page) throw new Error("CDP не поднялся");

  const cdp = await connect(page.webSocketDebuggerUrl);
  await cdp.send("Runtime.enable");
  const ev = async (expr) => {
    const r = await cdp.send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? "eval");
    return r.result?.value;
  };
  const waitFor = async (expr, ms = 20000) => {
    const t0 = Date.now();
    while (Date.now() - t0 < ms) {
      try {
        if (await ev(expr)) return true;
      } catch {
        /* контекст пересоздаётся при навигации */
      }
      await sleep(150);
    }
    return false;
  };
  return { cdp, ev, waitFor, close: () => { cdp.ws.close(); edge.kill(); } };
}

const results = [];
const check = (name, ok, info = "") => {
  results.push({ name, ok, info });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${info ? " — " + info : ""}`);
};

// ── 1. начинаем с русского и переключаем через селект ────────────────────────
const a = await openPage(9555, new URL("?lang=ru", BASE).toString());
await a.waitFor(`!!document.querySelector('select.lang-select')`);
const before = await a.ev(CHROME);
check("стартовый язык — русский", before.lang === "ru" && before.cyr > 0, `lang=${before.lang}, кириллицы ${before.cyr}`);

await a.ev(`(() => { const s = document.querySelector('select.lang-select'); s.value = 'en'; s.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
await sleep(3000);
await a.waitFor(`!!document.querySelector('select.lang-select') && document.documentElement.lang === 'en'`);
const after = await a.ev(CHROME);
check("после выбора EN интерфейс английский", after.lang === "en" && after.cyr === 0, `lang=${after.lang}, кириллицы ${after.cyr}`);
check("страница помечена как непереводимая", after.translate === "no");
a.close();

await sleep(800);
const prefs = await (await fetch(new URL("/api/prefs", BASE))).json();
check("выбор записан в настройки приложения", prefs.lang === "en", JSON.stringify(prefs));

// ── 2. свежий профиль: языка в localStorage нет, должен открыться английский ─
const b = await openPage(9556, BASE);
await b.waitFor(`!!document.querySelector('select.lang-select')`);
await sleep(1200);
const fresh = await b.ev(CHROME);
check("новый профиль открывается на сохранённом языке", fresh.lang === "en" && fresh.cyr === 0, `lang=${fresh.lang}, кириллицы ${fresh.cyr}`);
b.close();

// вернуть русский, чтобы не менять состояние машины
await fetch(new URL("/api/prefs", BASE), {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ lang: "ru" }),
});

const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} проверок пройдено`);
process.exit(failed ? 1 : 0);
