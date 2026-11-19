/**
 * Аудит языка на ЖИВОМ интерфейсе: открывает UI в headless Edge с нужным
 * языком и показывает, что осталось непереведённым.
 *
 *   node tools/lang-audit-live.mjs http://127.0.0.1:7811/ en
 *   node tools/lang-audit-live.mjs http://127.0.0.1:7811/ ru
 *
 * Для en ищем кириллицу в тексте интерфейса (её быть не должно), для ru —
 * латиницу в подписях (кроме технических токенов: TX/RX/HEX/USB/…).
 * Скриншот кладётся в ui/shots/lang-<lang>.png.
 */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.argv[2] ?? "http://127.0.0.1:7811/";
const ARG = process.argv[3] === "en" ? "en" : process.argv[3] === "auto" ? "auto" : "ru";
const OUT = process.argv[4] ?? "ui/shots";
const EDGE =
  process.env.EDGE_PATH ??
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9444;

mkdirSync(OUT, { recursive: true });
const profile = join(tmpdir(), `ftdi-lang-${Date.now()}`);
mkdirSync(profile, { recursive: true });

const url = new URL(BASE);
if (ARG !== "auto") url.searchParams.set("lang", ARG);

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
    url.toString(),
  ],
  { stdio: "ignore" },
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function listTargets() {
  const r = await fetch(`http://127.0.0.1:${PORT}/json/list`);
  return r.json();
}

async function waitTarget(deadlineMs = 15000) {
  const until = Date.now() + deadlineMs;
  while (Date.now() < until) {
    try {
      const targets = await listTargets();
      const page = targets.find((t) => t.type === "page" && t.url.startsWith("http"));
      if (page) return page;
    } catch {
      /* ещё не поднялся */
    }
    await sleep(150);
  }
  throw new Error("CDP не поднялся");
}

function open(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener("open", () => resolve(ws));
    ws.addEventListener("error", (e) => reject(new Error(String(e.message ?? e))));
  });
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
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    }
    return r.result?.value;
  }
  async shot(name) {
    const r = await this.send("Page.captureScreenshot", { format: "png" });
    const path = join(OUT, name);
    writeFileSync(path, Buffer.from(r.data, "base64"));
    return path;
  }
}

async function waitFor(cdp, expr, ms = 8000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await cdp.eval(expr)) return true;
    await sleep(150);
  }
  return false;
}

const CYR = /[А-Яа-яЁё]/;
const LAT = /[A-Za-z]/;
// Текст данных, а не подписей интерфейса: имена устройств из PnP, названия
// процессов, пути файлов, содержимое журнала, названия шагов и меток. Их
// переводить нельзя — это записи, а не UI.
const DATA_SEL = ".device, .session-item, .row, .inspect, .tool, .timeline, .list__item, .hex, .decoded, datalist";
// Технические токены, которые остаются латиницей в русском интерфейсе.
const LAT_OK =
  /^(TX|RX|USB|HEX|UTF-8|PID|DLL|API|JSON|CSV|HTML|sha256|sha|LAN|TCP|RAW|SYS|FT_|SetComm|PassThru|J2534|USBPcap|Setup|EXE|KiB|MB|MiB|B\/s|SYS|dll|exe|log|json|txt|bin|PNG|JPG|SERIAL|USB\d|COM\d|0x[0-9a-f]+|mix|composite|off|admin|bridge|capture|demo)$/i;

function collect() {
  // Все видимые текстовые узлы + title/placeholder/aria-label, кроме данных.
  return `(() => {
    const SKIP = ${JSON.stringify(DATA_SEL)};
    const out = [];
    const push = (where, text) => {
      const t = (text ?? "").replace(/\\s+/g, " ").trim();
      if (t) out.push({ where, text: t });
    };
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walk.nextNode())) {
      const el = n.parentElement;
      if (!el) continue;
      if (el.closest(SKIP)) continue;
      const cs = getComputedStyle(el);
      if (cs.display === "none" || cs.visibility === "hidden" || el.offsetParent === null) continue;
      push(el.tagName.toLowerCase() + (el.className ? "." + String(el.className).split(" ")[0] : ""), n.nodeValue);
    }
    for (const el of document.querySelectorAll("[title],[placeholder],[aria-label]")) {
      if (el.closest(SKIP)) continue;
      const t = el.getAttribute("title") || el.getAttribute("placeholder") || el.getAttribute("aria-label");
      push("attr:" + el.tagName.toLowerCase(), t);
    }
    return out;
  })()`;
}

async function run(arg) {
  const target = await waitTarget();
  const ws = await open(target.webSocketDebuggerUrl);
  const cdp = new Cdp(ws);
  await cdp.send("Runtime.enable");

  const ready = await waitFor(cdp, `!document.getElementById('app')?.hasAttribute('hidden')`, 20000);
  await sleep(2500);

  const meta = await cdp.eval(
    `({ href: location.href, htmlLang: document.documentElement.lang, translate: document.documentElement.getAttribute('translate'), title: document.title })`,
  );
  const lang = arg === "auto" ? (meta.htmlLang === "en" ? "en" : "ru") : arg;
  const items = await cdp.eval(collect());

  const bad = [];
  for (const it of items) {
    const hasCyr = CYR.test(it.text);
    const hasLat = LAT.test(it.text);
    if (lang === "en" && hasCyr) bad.push(it);
    // Для русского ищем подписи, целиком набранные латиницей: смешанные
    // строки вроде «TX · последняя 1 с» — норма.
    if (lang === "ru" && !hasCyr && hasLat && it.text.length > 1 && !LAT_OK.test(it.text)) bad.push(it);
  }

  const shot = await cdp.shot(`lang-${lang}.png`);
  const noTranslate =
    meta.translate === "no" &&
    (await cdp.eval(
      `!!document.querySelector('meta[name="google"][content="notranslate"]') && document.documentElement.classList.contains('notranslate')`,
    ));
  console.log(`\n=== ${lang.toUpperCase()} ===`);
  console.log(`ready: ${ready}`);
  console.log(`url: ${meta.href}`);
  console.log(`html lang: ${meta.htmlLang}   translate attr: ${meta.translate}`);
  console.log(`title: ${meta.title}`);
  console.log(`запрет браузерного перевода: ${noTranslate ? "да" : "НЕТ"}`);
  console.log(`текстовых узлов: ${items.length}, подозрительных: ${bad.length}`);
  const seen = new Set();
  for (const b of bad) {
    const key = b.text;
    if (seen.has(key)) continue;
    seen.add(key);
    console.log(`  [${b.where}] ${b.text.slice(0, 160)}`);
  }
  console.log(`screenshot: ${shot}`);

  ws.close();
  return bad.length + (noTranslate ? 0 : 1);
}

let code = 1;
try {
  code = (await run(ARG)) === 0 ? 0 : 2;
} catch (e) {
  console.error("ошибка аудита:", e.message);
} finally {
  edge.kill();
  await sleep(300);
  process.exit(code);
}
