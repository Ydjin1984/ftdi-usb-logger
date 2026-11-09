/** Проверка кнопки «Новая сессия» через CDP: диалог, список целей, запуск сессии. */
import { spawn } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7842/";
const PICK = process.argv[3] ?? "MS4x";
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9337;
const profile = join(tmpdir(), `ftdi-newsess-${Date.now()}`);
mkdirSync(profile, { recursive: true });
const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", "--window-size=1600,1000", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, "--no-first-run", URL_], { stdio: "ignore" });
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
for (let i = 0; i < 60; i++) { if (await ev(`!!document.querySelector('.btn--new-session')`)) break; await sleep(250); }
const results = [];
const check = (n, ok, d = "") => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${n}${d ? " — " + d : ""}`); };

check("кнопка «НОВАЯ СЕССИЯ» есть", await ev(`!!document.querySelector('.btn--new-session')`));
await ev(`document.querySelector('.btn--new-session').click()`);
await sleep(1500);
check("диалог новой сессии открылся", await ev(`!!document.querySelector('.modal-backdrop') && document.body.innerText.includes('АДАПТЕР')`));
check("в диалоге есть программы", await ev(`document.body.innerText.includes('ПРОГРАММА')`));
const hasTarget = await ev(`(() => {
  const btns = [...document.querySelectorAll('.modal-backdrop .format-option')];
  return btns.some(b => b.innerText.includes(${JSON.stringify(PICK)}));
})()`);
check(`цель «${PICK}» в списке`, hasTarget);
if (hasTarget) {
  await ev(`(() => {
    const btns = [...document.querySelectorAll('.modal-backdrop .format-option')];
    const b = btns.find(x => x.innerText.includes(${JSON.stringify(PICK)}));
    b.click(); return true;
  })()`);
  await sleep(300);
  await ev(`(() => {
    const btns = [...document.querySelectorAll('.modal-backdrop button')];
    const b = btns.find(x => x.textContent.includes('начать сессию'));
    b?.click(); return true;
  })()`);
  let state = null;
  for (let i = 0; i < 40; i++) {
    state = await ev(`(() => { const s = window.__ftdi.store.state; return { recording: !!s.status?.recording, active: s.active?.label ?? null, target: s.status?.target?.name ?? null, bridge: s.status?.bridge ?? null, hooks: s.status?.hooks ?? null }; })()`);
    if (state && state.active && (state.recording || state.hooks === "on")) break;
    await sleep(500);
  }
  check("сессия запущена", !!state?.recording, JSON.stringify(state));
}
const shot = await send("Page.captureScreenshot", { format: "png" });
const { writeFileSync } = await import("node:fs");
writeFileSync("D:\\FTDI_USB_Logger\\assets\\ui-new-session-live.png", Buffer.from(shot.result.data, "base64"));
ws.close(); edge.kill(); await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch {}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} проверок`);
process.exit(failed ? 1 : 0);

