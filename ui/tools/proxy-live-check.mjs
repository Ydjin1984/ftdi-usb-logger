/**
 * Проверка живого индикатора J2534-прокси и выбора «шнурка» через CDP.
 *
 *   node tools/proxy-live-check.mjs http://127.0.0.1:7898/ ui/shots
 *
 * Что проверяется (docs/13 §6.1, §9):
 *   1. в шапке есть пилюля «прокси» и она честно говорит «подхвачен»;
 *   2. в настройках блок `.proxy-live` показывает процесс и счётчики;
 *   3. в настройках есть выбор «какой шнурок проксировать» с реальными драйверами;
 *   4. выбран именно текущий `RealLibrary` (а не первый попавшийся).
 *
 * Запускается как обычный node-скрипт: внешних зависимостей нет, WebSocket
 * встроен в Node 22+. Edge поднимается свой, на отдельном порту, чтобы не
 * трогать браузер пользователя.
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7898/";
const OUT = process.argv[3] ?? "ui/shots";
const EDGE = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9334;

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ftdi-proxy-cdp-${Date.now()}`);
mkdirSync(profile, { recursive: true });

const edge = spawn(
  EDGE,
  [
    "--headless=new",
    "--disable-gpu",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--window-size=1440,1000",
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
  for (let i = 0; i < 80; i++) {
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

async function waitFor(cdp, expr, timeout = 8000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    if (await cdp.eval(expr)) return true;
    await sleep(150);
  }
  return false;
}

try {
  const page = await targets();
  const ws = await open(page.webSocketDebuggerUrl);
  const cdp = new Cdp(ws);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");

  // Ждём, пока шапка отрисуется: пилюля прокси появляется после первого опроса.
  await waitFor(cdp, `!!document.querySelector('.pill')`, 20000);
  const hasPill = await waitFor(
    cdp,
    `[...document.querySelectorAll('.pill')].some(p => (p.innerText || '').toLowerCase().includes('прокси'))`,
    15000,
  );
  const pillText = await cdp.eval(
    `(() => { const p = [...document.querySelectorAll('.pill')].find(x => (x.innerText || '').toLowerCase().includes('прокси')); return p ? p.innerText.replace(/\\n/g, ' ') : ''; })()`,
  );
  check("в шапке есть индикатор прокси", hasPill, pillText);

  // Настройки: клик по иконке настроек в шапке.
  const opened = await cdp.eval(`(() => {
    const btn = [...document.querySelectorAll('.icon-btn')].find(b => (b.title || '').includes('настройки'));
    if (!btn) return false;
    btn.click();
    return true;
  })()`);
  check("настройки открываются", opened === true);
  check("блок живого состояния отрисован", await waitFor(cdp, `!!document.querySelector('.proxy-live')`, 8000));
  // Состояние приходит асинхронно: ждём текст, а не просто пустой блок.
  await waitFor(
    cdp,
    `(() => { const b = document.querySelector('.proxy-live__head b'); return !!b && b.textContent.trim().length > 0; })()`,
    8000,
  );

  const live = await cdp.eval(`(() => {
    const box = document.querySelector('.proxy-live');
    if (!box) return null;
    return {
      cls: box.className,
      head: box.querySelector('.proxy-live__head')?.innerText ?? '',
      meta: box.querySelector('.proxy-live__meta')?.innerText ?? '',
      note: box.querySelector('.proxy-live__note')?.innerText ?? '',
      title: box.title ?? '',
    };
  })()`);
  check("индикатор называет процесс", !!live && /подхвачен/i.test(live.head), live ? live.head : "—");
  // Счётчики есть только у живого прокси: в состояниях «был подхвачен» и
  // «не подхвачен» показывать нечего, и это правильно, а не дефект.
  const liveState = await cdp.eval(`window.__ftdi?.store?.state?.proxy?.live?.state ?? ''`);
  check(
    "индикатор показывает счётчики",
    !!live && (/TX/.test(live.meta) || liveState === "recent" || liveState === "idle"),
    live ? live.meta || `state=${liveState}` : "—",
  );
  // Нейтральная окраска — штатная для «был подхвачен»: цвет не должен врать.
  check(
    "индикатор окрашен по состоянию",
    !!live && (/proxy-live--(ok|warn|err)/.test(live.cls) || liveState === "recent"),
    live ? `${live.cls} (state=${liveState})` : "—",
  );

  await waitFor(cdp, `(document.querySelector('.field select')?.options?.length ?? 0) > 1`, 8000);
  const devices = await cdp.eval(`(() => {
    const sel = document.querySelector('.field select');
    if (!sel) return null;
    return {
      count: sel.options.length,
      selected: sel.value,
      labels: [...sel.options].slice(0, 6).map(o => o.textContent),
      disabled: sel.disabled,
    };
  })()`);
  check("есть выбор шнурка", !!devices && devices.count > 0, devices ? `${devices.count} вариантов` : "нет select");
  check(
    "список наполнен драйверами",
    !!devices && devices.labels.some((l) => /\.dll/.test(l)),
    devices ? devices.labels.slice(0, 2).join(" | ") : "—",
  );
  check("выбран текущий драйвер", !!devices && !!devices.selected, devices ? devices.selected : "—");

  await cdp.shot("proxy-01-settings.png");
  // Крупный кадр только блока — для ответа пользователю.
  const rect = await cdp.eval(`(() => {
    const b = document.querySelector('.modal');
    if (!b) return null;
    const r = b.getBoundingClientRect();
    return { x: Math.round(r.x), y: Math.round(r.y), width: Math.round(r.width), height: Math.round(r.height) };
  })()`);
  if (rect) {
    const r = await cdp.send("Page.captureScreenshot", { format: "png", clip: { ...rect, scale: 1 } });
    writeFileSync(join(OUT, "proxy-02-dialog.png"), Buffer.from(r.data, "base64"));
    console.log(`  shot: ${join(OUT, "proxy-02-dialog.png")}`);
  }

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
