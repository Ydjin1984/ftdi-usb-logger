/** Проверка «Новая сессия» через CDP: detach текущей, пересканирование, выбор цели вручную. */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7850/";
const PICK = process.argv[3] ?? "BMWScan";
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9339;
const profile = join(tmpdir(), `ftdi-newsess2-${Date.now()}`);
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

// 1) сначала подцепляемся к программе через API страницы (имитация предыдущей сессии)
const attached = await ev(`(async () => {
  const tools = await (await fetch('/api/tools?mode=auto')).json();
  const t = tools.find(x => (x.name || '').toLowerCase().includes('bmw')) || tools[0];
  if (!t) return null;
  await window.__ftdi.store.attach(t.pid, 'probe prev session');
  return t.name;
})()`);
check("предыдущая сессия запущена через API", typeof attached === "string" && !attached.startsWith("error"), String(attached));

// 2) «НОВАЯ СЕССИЯ» — при активной записи должен быть диалог подтверждения
await ev(`document.querySelector('.btn--new-session').click()`);
await sleep(800);
const confirmShown = await ev(`document.body.innerText.includes('будет завершена') || document.body.innerText.includes('завершить и пересканировать')`);
check("подтверждение завершения текущей сессии", !!confirmShown);
if (confirmShown) {
  await ev(`(() => { const b=[...document.querySelectorAll('.modal-backdrop button')].find(x=>x.textContent.includes('завершить и пересканировать')); b?.click(); })()`);
}
// 3) ждём окно выбора цели после пересканирования
let dialog = false;
for (let i = 0; i < 40; i++) {
  dialog = await ev(`document.body.innerText.includes('АДАПТЕР') && document.body.innerText.includes('ПРОГРАММА')`);
  if (dialog) break;
  await sleep(500);
}
check("окно выбора цели после пересканирования", dialog);
const startDisabled = await ev(`(() => { const b=[...document.querySelectorAll('.modal-backdrop button')].find(x=>x.textContent.includes('начать сессию')); return !!b && b.disabled; })()`);
check("кнопка «начать сессию» заблокирована без цели", !!startDisabled);
const hasTarget = await ev(`(() => [...document.querySelectorAll('.modal-backdrop .format-option')].some(b => b.innerText.toLowerCase().includes(${JSON.stringify(PICK)}.toLowerCase()) && b.innerText.includes('pid ')))()`);
check(`цель «${PICK}» в свежем списке`, !!hasTarget);
if (hasTarget) {
  const dlgShot = await send("Page.captureScreenshot", { format: "png" });
  writeFileSync("D:\\FTDI_USB_Logger\\assets\\ui-new-session-dialog.png", Buffer.from(dlgShot.result.data, "base64"));
  await ev(`(() => { const b=[...document.querySelectorAll('.modal-backdrop .format-option')].find(x=>x.innerText.toLowerCase().includes(${JSON.stringify(PICK)}.toLowerCase()) && x.innerText.includes('pid ')); b.click(); })()`);
  await sleep(300);
  const enabled = await ev(`(() => { const b=[...document.querySelectorAll('.modal-backdrop button')].find(x=>x.textContent.includes('начать сессию')); return !!b && !b.disabled; })()`);
  check("после выбора цели кнопка активна", !!enabled);
  await ev(`(() => { const b=[...document.querySelectorAll('.modal-backdrop button')].find(x=>x.textContent.includes('начать сессию')); b?.click(); })()`);
  let started = false;
  for (let i = 0; i < 40; i++) {
    const st = await ev(`(() => { const s=window.__ftdi.store.state; return !!s.status?.recording; })()`);
    if (st) { started = true; break; }
    await sleep(500);
  }
  check("новая сессия запущена только после выбора", started);
}
const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync("D:\\FTDI_USB_Logger\\assets\\ui-new-session-live.png", Buffer.from(shot.result.data, "base64"));
ws.close(); edge.kill(); await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch {}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} проверок`);
process.exit(failed ? 1 : 0);



