/**
 * Финальная проверка переключения языка на том самом UI, что попал в установщик.
 *
 *   node tools/verify-lang-payload.mjs <каталог ui/dist> [--block-storage]
 *
 * Отдаёт каталог статикой, открывает в headless Edge, выбирает EN в селекте и
 * проверяет, что интерфейс стал английским. С --block-storage localStorage
 * ломается намеренно (гостевой профиль) — именно этот случай раньше не работал.
 */
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, extname, resolve } from "node:path";

const DIST = resolve(process.argv[2] ?? "ui/dist");
const BLOCK = process.argv.includes("--block-storage");
const PORT_WEB = 7804;
const PORT_CDP = 9336;
const EDGE = process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";

if (!existsSync(join(DIST, "index.html"))) {
  console.error(`нет ${join(DIST, "index.html")}`);
  process.exit(2);
}

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png" };
const server = createServer((req, res) => {
  const u = new URL(req.url, `http://127.0.0.1:${PORT_WEB}`);
  let p = join(DIST, decodeURIComponent(u.pathname));
  if (u.pathname === "/" || !existsSync(p)) p = join(DIST, "index.html");
  try {
    res.writeHead(200, { "content-type": MIME[extname(p)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(readFileSync(p));
  } catch {
    res.writeHead(404).end("nf");
  }
});
await new Promise((r) => server.listen(PORT_WEB, "127.0.0.1", r));

const profile = join(tmpdir(), `ftdi-verify-${Date.now()}`);
mkdirSync(profile, { recursive: true });
const edge = spawn(EDGE, [
  "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
  "--window-size=1600,1000", `--remote-debugging-port=${PORT_CDP}`, `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", `http://127.0.0.1:${PORT_WEB}/?demo=1`,
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function target() {
  for (let i = 0; i < 80; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT_CDP}/json/list`)).json();
      const t = list.find((x) => x.type === "page" && x.webSocketDebuggerUrl);
      if (t) return t;
    } catch { /* не поднялся */ }
    await sleep(250);
  }
  throw new Error("CDP не поднялся");
}

let nextId = 1;
const pending = new Map();
const t0 = await target();
const ws = await new Promise((res, rej) => {
  const s = new WebSocket(t0.webSocketDebuggerUrl);
  s.addEventListener("open", () => res(s));
  s.addEventListener("error", (e) => rej(new Error(String(e.message ?? e))));
});
ws.addEventListener("message", (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    const { resolve: r, reject: j } = pending.get(m.id);
    pending.delete(m.id);
    if (m.error) j(new Error(JSON.stringify(m.error))); else r(m.result);
  }
});
const send = (method, params = {}) =>
  new Promise((r, j) => {
    const id = nextId++;
    pending.set(id, { resolve: r, reject: j });
    ws.send(JSON.stringify({ id, method, params }));
  });
const ev = async (expr) => {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.text ?? "eval");
  return r.result?.value;
};

await send("Runtime.enable");
await send("Page.enable");
if (BLOCK) {
  await send("Page.addScriptToEvaluateOnNewDocument", {
    source: `(() => {
      const boom = () => { throw new DOMException('storage blocked', 'SecurityError'); };
      const stub = { getItem: boom, setItem: boom, removeItem: boom, clear: boom, key: boom, length: 0 };
      try { Object.defineProperty(window, 'localStorage', { get: () => stub, configurable: true }); } catch (e) {}
    })();`,
  });
  await ev(`location.reload()`);
  await sleep(2000);
}

async function waitFor(expr, ms = 20000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    try { if (await ev(expr)) return true; } catch { /* контекст пересоздаётся */ }
    await sleep(200);
  }
  return false;
}
await waitFor(`!!document.querySelector('.topbar')`);

const SAMPLE = `({ lang: document.documentElement.lang,
  sel: document.querySelector('select.lang-select')?.value ?? null,
  nav: (document.querySelector('.workspace-nav')?.textContent ?? '').trim() })`;

const before = await ev(SAMPLE);
await ev(`(() => { const s = document.querySelector('select.lang-select'); if (!s) return 'no-select';
  s.value = 'en'; s.dispatchEvent(new Event('change', { bubbles: true })); return 'ok'; })()`);
await sleep(2500);
await waitFor(`!!document.querySelector('.topbar')`);
const after = await ev(SAMPLE);

const ok = after.lang === "en" && /Sessions and USB/.test(after.nav);
console.log(JSON.stringify({ dist: DIST, blockStorage: BLOCK, before, after, result: ok ? "PASS" : "FAIL" }, null, 2));

ws.close();
edge.kill();
server.close();
try { rmSync(profile, { recursive: true, force: true }); } catch {}
process.exit(ok ? 0 : 1);
