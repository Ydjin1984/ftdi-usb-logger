/**
 * UI-проверки крайних случаев для FTDI/USB Logger через CDP (Edge headless).
 *
 *   node tests/e2e/edge/cdp-edge.mjs \
 *     --static http://127.0.0.1:8101/ \
 *     --engine http://127.0.0.1:7831/ \
 *     --out tests/e2e/edge/out \
 *     --cdp-port 9335 \
 *     --known-session winkfp-20261109-122608 \
 *     [--big-session <id>] [--title-prefix ""]
 *
 * Проверяет: UI без движка, демо-режим, быстрые F2, пустой поиск, все фильтры
 * в ноль, resize 800x600, два таба с одной сессией, опционально большую сессию.
 * Без внешних зависимостей: глобальный WebSocket (Node 22+).
 *
 * Результат: out/ui-results.json + строка `__RESULTS__ {...}` в stdout.
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const argv = process.argv.slice(2);
function arg(name, fallback = null) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : fallback;
}
const STATIC = arg("--static", "http://127.0.0.1:8101/").replace(/\/?$/, "/");
const ENGINE = arg("--engine", "http://127.0.0.1:7831/").replace(/\/?$/, "/");
const OUT = arg("--out", join(process.cwd(), "tests", "e2e", "edge", "out"));
const CDP_PORT = Number(arg("--cdp-port", "9335"));
const KNOWN = arg("--known-session", "winkfp-20261109-122608");
const BIG = arg("--big-session", null);
const EDGE = process.env.EDGE_PATH || "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ftdi-edge-cdp-${Date.now()}`);
mkdirSync(profile, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];
const consoleErrors = [];
const screenshots = [];

function check(id, name, verdict, fact, extra = {}) {
  const row = { id, name, verdict, fact, ...extra };
  results.push(row);
  console.log(`${verdict === "PASS" ? "PASS" : verdict === "BUG" ? "BUG " : "FAIL"}  ${id} ${name} — ${fact}`);
}

function waitPort(port, timeoutMs = 20000) {
  const until = Date.now() + timeoutMs;
  return (async () => {
    while (Date.now() < until) {
      try {
        const res = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (res.ok) return await res.json();
      } catch {
        /* не поднялся */
      }
      await sleep(200);
    }
    throw new Error(`CDP ${port} не поднялся за ${timeoutMs} мс`);
  })();
}

let nextId = 1;
class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.pending = new Map();
    this.exceptions = [];
    ws.addEventListener("message", (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.method === "Runtime.exceptionThrown") {
        const d = msg.params?.exceptionDetails;
        this.exceptions.push(String(d?.exception?.description || d?.text || "exception"));
      }
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
  async eval(expression, timeout = 30000) {
    const t0 = Date.now();
    const r = await Promise.race([
      this.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }),
      new Promise((_, rej) => setTimeout(() => rej(new Error("eval timeout")), timeout)),
    ]);
    const ms = Date.now() - t0;
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text || "eval failed");
    }
    return { value: r.result?.value, ms };
  }
  async shot(name) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    const path = join(OUT, name);
    writeFileSync(path, Buffer.from(r.data, "base64"));
    screenshots.push(path);
    return path;
  }
}

function openWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", (e) => reject(new Error(String(e.message ?? e))));
  });
}

async function waitFor(cdp, expr, timeout = 10000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    try {
      const { value } = await cdp.eval(expr);
      if (value) return true;
    } catch {
      /* страница ещё грузится */
    }
    await sleep(120);
  }
  return false;
}

async function navigate(cdp, url, waitExpr = "document.readyState === 'complete'", timeout = 15000) {
  await cdp.send("Page.navigate", { url });
  await waitFor(cdp, waitExpr, timeout);
  await sleep(250);
}

const edgeArgs = [
  "--headless=new",
  "--disable-gpu",
  "--hide-scrollbars",
  "--force-device-scale-factor=1",
  "--window-size=1600,1000",
  `--remote-debugging-port=${CDP_PORT}`,
  `--user-data-dir=${profile}`,
  "--no-first-run",
  "--no-default-browser-check",
  "about:blank",
];
const edge = spawn(EDGE, edgeArgs, { stdio: "ignore" });

try {
  const version = await waitPort(CDP_PORT);
  const browserWs = await openWs(version.webSocketDebuggerUrl);
  const browser = new Cdp(browserWs);

  async function pageTarget() {
    const list = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
    return list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
  }

  const page = await pageTarget();
  const tab1 = new Cdp(await openWs(page.webSocketDebuggerUrl));
  await tab1.send("Page.enable");
  await tab1.send("Runtime.enable");
  await tab1.send("Emulation.setDeviceMetricsOverride", {
    width: 1600,
    height: 1000,
    deviceScaleFactor: 1,
    mobile: false,
  });

  /* ── UI-01: UI без движка (статика, backend недоступен) ──────────────── */
  await navigate(tab1, STATIC);
  await sleep(3500);
  const noEngine = (
    await tab1.eval(`(() => {
      const boot = document.querySelector('#boot');
      const app = document.querySelector('#app');
      const text = document.body.innerText || '';
      return {
        bodyText: text.slice(0, 2500),
        hasBoot: !!boot,
        bootRemoved: !boot,
        appHidden: app ? app.hidden : null,
        hasErrorClass: !!document.querySelector('.boot--error'),
        visibleError: /не ответил|движок недоступен|не удалось подключиться/i.test(text),
        buttons: [...document.querySelectorAll('button')].map(b => b.textContent.trim()).filter(Boolean).slice(0, 12),
      };
    })()`)
  ).value;
  await tab1.shot("ui-01-no-engine.png");
  if (noEngine.visibleError) {
    check("UI-01", "UI без движка показывает понятную ошибку", "PASS", `видимый текст с ошибкой: ${(noEngine.bodyText.match(/[^\n]*(?:не ответил|недоступен)[^\n]*/i) || [""])[0].slice(0, 160)}`);
  } else {
    check(
      "UI-01",
      "UI без движка показывает понятную ошибку",
      "BUG",
      `экран пустой/без ошибки: boot в DOM=${noEngine.hasBoot}, #boot удалён=${noEngine.bootRemoved}, app.hidden=${noEngine.appHidden}, текст=${JSON.stringify(noEngine.bodyText.slice(0, 200))}, кнопки=${JSON.stringify(noEngine.buttons)}`,
    );
  }

  /* ── UI-02: демо-режим грузится ──────────────────────────────────────── */
  await navigate(tab1, `${STATIC}?demo=1`);
  const demoOk = await waitFor(tab1, `document.querySelectorAll('.row').length > 0`, 12000);
  const demoState = (
    await tab1.eval(`(() => {
      const s = window.__ftdi?.store?.state;
      return {
        rows: document.querySelectorAll('.row').length,
        mode: s?.mode,
        sessions: document.querySelectorAll('.session-item').length,
        ws: s?.wsState,
        toasts: [...document.querySelectorAll('.toast')].map(t => t.textContent.trim()).slice(0, 4),
        chips: document.querySelectorAll('.chip').length,
      };
    })()`)
  ).value;
  await tab1.shot("ui-02-demo.png");
  if (demoOk && demoState.rows > 0 && demoState.mode === "demo") {
    check("UI-02", "демо-режим (?demo=1) рисует поток", "PASS", `строк=${demoState.rows}, шагов в списке=${demoState.sessions}, chips=${demoState.chips}, ws=${demoState.ws}`);
  } else {
    check("UI-02", "демо-режим (?demo=1) рисует поток", "BUG", `строк=${demoState.rows}, mode=${demoState.mode}, ws=${demoState.ws}`);
  }

  /* ── UI-03: быстрые повторные нажатия F2 ────────────────────────────── */
  const beforeF2 = (
    await tab1.eval(`(() => {
      const s = window.__ftdi.store.state;
      return { steps: s.steps.length, lastIdx: s.steps.length ? s.steps[s.steps.length-1].idx : 0,
               current: s.currentStep ? s.currentStep.idx : null, lastSeq: s.lastSeq,
               events: s.events.length, toasts: s.toasts.length };
    })()`)
  ).value;
  const f2ms = (
    await tab1.eval(`(async () => {
      const press = () => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'F2', code: 'F2', bubbles: true, cancelable: true }));
      const t0 = performance.now();
      for (let i = 0; i < 6; i++) { press(); await new Promise(r => setTimeout(r, 35)); }
      return performance.now() - t0;
    })()`)
  ).value;
  await sleep(500);
  const afterF2 = (
    await tab1.eval(`(() => {
      const s = window.__ftdi.store.state;
      return { steps: s.steps.length, lastIdx: s.steps.length ? s.steps[s.steps.length-1].idx : 0,
               current: s.currentStep ? s.currentStep.idx : null, lastSeq: s.lastSeq,
               events: s.events.length, toasts: s.toasts.length,
               dupStepIdx: (() => { const seen = new Set(); const dup = [];
                 for (const st of s.steps) { if (seen.has(st.idx)) dup.push(st.idx); seen.add(st.idx); } return dup; })(),
               rows: document.querySelectorAll('.row').length };
    })()`)
  ).value;
  const f2Expected = {
    steps: beforeF2.steps + 2,
    lastIdx: beforeF2.lastIdx + 2,
    current: beforeF2.lastIdx + 3,
    seq: beforeF2.lastSeq + 6,
  };
  const f2ok =
    beforeF2.current !== null &&
    afterF2.steps === f2Expected.steps &&
    afterF2.lastIdx === f2Expected.lastIdx &&
    afterF2.current === f2Expected.current &&
    afterF2.lastSeq === f2Expected.seq &&
    afterF2.dupStepIdx.length === 0 &&
    tab1.exceptions.length === 0;
  await tab1.shot("ui-03-f2-rapid.png");
  if (f2ok) {
    check("UI-03", "6 быстрых F2 подряд: шаги/состояние консистентны", "PASS",
      `6 нажатий за ${f2ms.toFixed(0)} мс: steps ${beforeF2.steps}→${afterF2.steps}, current ${beforeF2.current}→${afterF2.current}, lastSeq ${beforeF2.lastSeq}→${afterF2.lastSeq}, дублей нет`);
  } else {
    check("UI-03", "6 быстрых F2 подряд: шаги/состояние консистентны", "BUG",
      `до=${JSON.stringify(beforeF2)} после=${JSON.stringify(afterF2)} ожидалось=${JSON.stringify(f2Expected)} exceptions=${tab1.exceptions.length}`);
  }

  /* ── UI-04: поиск без результатов ───────────────────────────────────── */
  await tab1.eval(`(() => {
    const input = document.querySelector('.search input');
    input.value = 'zzz-нет-такого-события';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    return true;
  })()`);
  await sleep(500);
  const emptySearch = (
    await tab1.eval(`(() => {
      const empty = document.querySelector('.stream__empty');
      const s = window.__ftdi.store.state;
      return { rows: document.querySelectorAll('.row').length, emptyHidden: empty ? empty.hidden : null,
               emptyText: empty ? empty.innerText.trim() : null, query: s.query, visible: window.__ftdi.store.visibleEvents().length };
    })()`)
  ).value;
  await tab1.shot("ui-04-search-empty.png");
  if (emptySearch.rows === 0 && emptySearch.emptyHidden === false && /Ничего не найдено/.test(emptySearch.emptyText || "")) {
    check("UI-04", "поиск без результатов показывает пустое состояние", "PASS", `строк=0, пустое состояние: «${emptySearch.emptyText}»`);
  } else {
    check("UI-04", "поиск без результатов показывает пустое состояние", "BUG", JSON.stringify(emptySearch));
  }
  // сброс поиска
  await tab1.eval(`(() => { const i = document.querySelector('.search input'); i.value = ''; i.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
  await sleep(400);

  /* ── UI-05: все фильтры в ноль ──────────────────────────────────────── */
  const beforeFiltersRows = (await tab1.eval(`document.querySelectorAll('.row').length`)).value;
  await tab1.eval(`(() => { for (const c of document.querySelectorAll('.chip')) c.click(); return true; })()`);
  await sleep(500);
  const filtersOff = (
    await tab1.eval(`(() => {
      const s = window.__ftdi.store.state;
      const empty = document.querySelector('.stream__empty');
      return { filterCount: s.filters.size, rows: document.querySelectorAll('.row').length,
               emptyHidden: empty ? empty.hidden : null, emptyText: empty ? empty.innerText.trim() : null,
               canvasH: document.querySelector('.stream__canvas')?.style.height };
    })()`)
  ).value;
  await tab1.shot("ui-05-filters-zero.png");
  if (filtersOff.filterCount === 0 && filtersOff.rows === 0 && filtersOff.emptyHidden === false && /Ничего не найдено/.test(filtersOff.emptyText || "")) {
    check("UI-05", "все фильтры в ноль: пустое состояние, без падения", "PASS", `фильтров=0, строк=0, «${filtersOff.emptyText}», canvas=${filtersOff.canvasH}`);
  } else {
    check("UI-05", "все фильтры в ноль: пустое состояние, без падения", "BUG", JSON.stringify(filtersOff));
  }
  // включить обратно
  await tab1.eval(`(() => { for (const c of document.querySelectorAll('.chip')) c.click(); return true; })()`);
  await sleep(500);
  const filtersBack = (await tab1.eval(`({ filterCount: window.__ftdi.store.state.filters.size, rows: document.querySelectorAll('.row').length })`)).value;
  if (filtersBack.filterCount !== 12 || filtersBack.rows === 0) {
    check("UI-05b", "фильтры включаются обратно", "BUG", `после повторного клика фильтров=${filtersBack.filterCount}, строк=${filtersBack.rows}`);
  } else {
    check("UI-05b", "фильтры включаются обратно", "PASS", `фильтров=${filtersBack.filterCount}, строк=${filtersBack.rows}`);
  }

  /* ── UI-06: resize 800x600 ──────────────────────────────────────────── */
  await tab1.send("Emulation.setDeviceMetricsOverride", { width: 800, height: 600, deviceScaleFactor: 1, mobile: false });
  await sleep(700);
  const resized = (
    await tab1.eval(`(() => {
      const doc = document.documentElement;
      const stream = document.querySelector('.stream');
      const rect = stream ? stream.getBoundingClientRect() : null;
      return { iw: innerWidth, ih: innerHeight, scrollW: doc.scrollWidth, clientW: doc.clientWidth,
               overflow: doc.scrollWidth > innerWidth + 1,
               rows: document.querySelectorAll('.row').length,
               stream: rect ? { w: Math.round(rect.width), h: Math.round(rect.height), right: Math.round(rect.right) } : null };
    })()`)
  ).value;
  await tab1.shot("ui-06-resize-800x600.png");
  if (resized.overflow === false && resized.rows > 0 && resized.stream && resized.stream.right <= resized.iw + 1) {
    check("UI-06", "resize 800x600: без горизонтального скролла, поток жив", "PASS",
      `inner=${resized.iw}x${resized.ih}, scrollWidth=${resized.scrollW}, clientWidth=${resized.clientW}, строк=${resized.rows}, stream=${resized.stream.w}x${resized.stream.h}`);
  } else {
    check("UI-06", "resize 800x600: без горизонтального скролла, поток жив", "BUG", JSON.stringify(resized));
  }
  await tab1.send("Emulation.setDeviceMetricsOverride", { width: 1600, height: 1000, deviceScaleFactor: 1, mobile: false });
  await sleep(400);

  /* ── UI-07: два таба с одной сессией (живой движок) ─────────────────── */
  await navigate(tab1, ENGINE, `!!window.__ftdi`, 20000);
  await tab1.eval(`window.__ftdi.store.selectSession(${JSON.stringify(KNOWN)})`, 30000);
  const tab1Rows = await waitFor(tab1, `document.querySelectorAll('.row').length > 0`, 20000);
  const tab1State = (
    await tab1.eval(`(() => { const s = window.__ftdi.store.state;
      return { active: s.active?.id, total: s.total, events: s.events.length, rows: document.querySelectorAll('.row').length,
               ws: s.wsState, health: !!s.health }; })()`)
  ).value;

  await browser.send("Target.createTarget", { url: ENGINE });
  await sleep(1200);
  const list = await (await fetch(`http://127.0.0.1:${CDP_PORT}/json/list`)).json();
  const page2 = list.find((t) => t.type === "page" && t.url.startsWith(ENGINE) && t.id !== page.id);
  let tab2 = null;
  let tab2State = { rows: 0 };
  if (!page2) {
    check("UI-07", "два таба с одной сессией", "FAIL", "второй таб не создался (Target.createTarget)");
  } else {
    tab2 = new Cdp(await openWs(page2.webSocketDebuggerUrl));
    await tab2.send("Page.enable");
    await tab2.send("Runtime.enable");
    await waitFor(tab2, `!!window.__ftdi`, 20000);
    await tab2.eval(`window.__ftdi.store.selectSession(${JSON.stringify(KNOWN)})`, 30000);
    const tab2Rows = await waitFor(tab2, `document.querySelectorAll('.row').length > 0`, 20000);
    tab2State = (
      await tab2.eval(`(() => { const s = window.__ftdi.store.state;
        return { active: s.active?.id, total: s.total, events: s.events.length, rows: document.querySelectorAll('.row').length, ws: s.wsState }; })()`)
    ).value;
    const health = (await tab1.eval(`fetch('/api/health').then(r => r.json()).then(h => ({ version: h.version, sessions: h.sessions }))`, 15000)).value;
    await tab1.shot("ui-07-two-tabs.png");
    const ok =
      tab1Rows && tab2Rows &&
      tab1State.active === KNOWN && tab2State.active === KNOWN &&
      tab1State.rows > 0 && tab2State.rows > 0 &&
      tab1State.total === tab2State.total && tab1State.total > 0 &&
      tab1.exceptions.length === 0 && tab2.exceptions.length === 0;
    if (ok) {
      check("UI-07", "два таба с одной сессией", "PASS",
        `оба таба открыли ${KNOWN}: total=${tab1State.total}, events=${tab1State.events}/${tab2State.events}, rows=${tab1State.rows}/${tab2State.rows}, ws=${tab1State.ws}/${tab2State.ws}, health v${health.version}`);
    } else {
      check("UI-07", "два таба с одной сессией", "BUG",
        `tab1=${JSON.stringify(tab1State)} tab2=${JSON.stringify(tab2State)} exceptions=${tab1.exceptions.length}/${tab2.exceptions.length}`);
    }
  }

  /* ── UI-08: большая сессия — открыть и пролистать ───────────────────── */
  if (BIG) {
    const t0 = Date.now();
    try {
      await tab1.eval(`window.__ftdi.store.selectSession(${JSON.stringify(BIG)})`, 120000);
      const loaded = await waitFor(tab1, `(() => { const s = window.__ftdi.store.state; return s.active?.id === ${JSON.stringify(BIG)} && s.total > 0 && document.querySelectorAll('.row').length > 0; })()`, 120000);
      const loadMs = Date.now() - t0;
      const bigState = (
        await tab1.eval(`(() => { const s = window.__ftdi.store.state;
          return { active: s.active?.id, total: s.total, events: s.events.length, firstSeq: s.firstSeq, lastSeq: s.lastSeq,
                   rows: document.querySelectorAll('.row').length, hasMoreBefore: s.hasMoreBefore }; })()`)
      ).value;

      // «пролистать»: 3 раза вверх, каждый раз подгружаем историю
      const scrolls = [];
      for (let i = 0; i < 3; i++) {
        const s0 = Date.now();
        await tab1.eval(`(() => { const vp = document.querySelector('.stream__viewport'); vp.scrollTop = 0;
          vp.dispatchEvent(new Event('scroll')); return true; })()`);
        await sleep(1200);
        const st = (
          await tab1.eval(`(() => { const s = window.__ftdi.store.state;
            return { events: s.events.length, firstSeq: s.firstSeq, rows: document.querySelectorAll('.row').length, follow: s.follow }; })()`)
        ).value;
        scrolls.push({ ms: Date.now() - s0, ...st });
      }

      // отзывчивость вкладки: 3 простых eval
      const probeMs = [];
      for (let i = 0; i < 3; i++) probeMs.push((await tab1.eval(`document.title`)).ms);
      await tab1.shot("ui-08-big-session.png");
      const scrollOk = scrolls.every((s) => s.events > 0 && s.rows > 0);
      check("UI-08", `большая сессия ${BIG}: открыть и пролистать`, scrollOk && loaded ? "PASS" : "BUG",
        `открытие=${loadMs} мс, total=${bigState.total}, events=${bigState.events}, firstSeq=${bigState.firstSeq}/${bigState.lastSeq}, hasMoreBefore=${bigState.hasMoreBefore}, прокрутки=${JSON.stringify(scrolls.map(s => ({ ms: s.ms, events: s.events, first: s.firstSeq, rows: s.rows })))}, eval(ms)=${JSON.stringify(probeMs)}, exceptions=${tab1.exceptions.length}`);
    } catch (err) {
      check("UI-08", `большая сессия ${BIG}: открыть и пролистать`, "BUG", `исключение: ${err.message}, exceptions=${JSON.stringify(tab1.exceptions.slice(0, 3))}`);
    }
  }

  if (consoleErrors.length) {
    check("UI-09", "в UI нет необработанных JS-исключений", "BUG", consoleErrors.slice(0, 5).join(" | "));
  }
} catch (err) {
  check("UI-00", "CDP-прогон UI", "FAIL", `исключение: ${err.message}`);
} finally {
  try {
    edge.kill();
  } catch {
    /* ignore */
  }
  await sleep(400);
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
}

writeFileSync(join(OUT, "ui-results.json"), JSON.stringify({ static: STATIC, engine: ENGINE, known: KNOWN, big: BIG, results }, null, 2));
console.log(`__RESULTS__ ${JSON.stringify(results)}`);
process.exit(0);
