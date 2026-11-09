/** Проверка watchdog: если движок умирает, UI показывает слой «нет связи», а не старый REC. */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7846/";
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9338;
const profile = join(tmpdir(), `ftdi-offline-${Date.now()}`);
mkdirSync(profile, { recursive: true });
const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--window-size=1400,900", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, "--no-first-run", URL_], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let target;
for (let i = 0; i < 80 && !target; i++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
    target = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
  } catch {}
  if (!target) await sleep(250);
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let id = 1; const pending = new Map();
ws.addEventListener("message", (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
const send = (method, params = {}) => new Promise((r) => { const i = id++; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expression) => (await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result?.result?.value;
await send("Runtime.enable");
// ждём, пока UI загрузится (движок ещё жив)
for (let i = 0; i < 60; i++) { if (await ev(`!!document.querySelector('.btn--new-session')`)) break; await sleep(250); }
const recBefore = await ev(`!!window.__ftdi?.store?.state?.status?.recording || !!document.querySelector('.badge-rec')`);

let offline = false;
for (let i = 0; i < 60; i++) {
  offline = await ev(`!!document.querySelector('.boot--offline') || document.body.innerText.includes('Движок не отвечает')`);
  if (offline) break;
  await sleep(500);
}
const state = await ev(`(() => { const s = window.__ftdi?.store?.state; return { lost: !!s?.connectionLost, recording: !!s?.status?.recording, text: document.body.innerText.slice(0, 120) }; })()`);
const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync("D:\\FTDI_USB_Logger\\assets\\ui-offline.png", Buffer.from(shot.result.data, "base64"));
console.log(`rec-before=${recBefore} offline=${offline} state=${JSON.stringify(state)}`);
console.log(offline ? "PASS  слой «движок не отвечает» показан" : "FAIL  слой не появился");
ws.close(); edge.kill(); await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch {}
process.exit(offline ? 0 : 1);
