/** Проверка пресетов действий: комбо на панели, сохранение, запуск шага выбранным пресетом. */
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const URL_ = process.argv[2] ?? "http://127.0.0.1:7806/?demo=1";
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PORT = 9340;
const profile = join(tmpdir(), `ftdi-presets-${Date.now()}`);
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
for (let i = 0; i < 60; i++) { if (await ev(`!!document.querySelector('.transport__preset')`)) break; await sleep(250); }

const results = [];
const check = (n, ok, d = "") => { results.push(ok); console.log(`${ok ? "PASS" : "FAIL"}  ${n}${d ? " — " + d : ""}`); };

const options = await ev(`(() => [...document.querySelectorAll('.transport__preset option')].map(o => o.value).filter(Boolean))()`);
const expected = ["Идентификация", "Чтение калибровок", "Чтение фулл флеш", "Запись калибровок", "Запись фулл флеш", "Сброс ошибок", "Сброс адаптаций", "Верификация"];
check("8 стандартных пресетов в комбо", expected.every((x) => options.includes(x)), `${options.length} опций: ${options.join(", ")}`);

// запуск шага выбранным пресетом
await ev(`(() => { const s = document.querySelector('.transport__preset'); s.value = 'Сброс ошибок'; s.dispatchEvent(new Event('change', { bubbles: true })); })()`);
let title = null;
for (let i = 0; i < 20; i++) {
  title = await ev(`window.__ftdi.store.state.currentStep?.title ?? null`);
  if (title) break;
  await sleep(200);
}
check("пресет открыл шаг с нужным названием", title === "Сброс ошибок", String(title));

// закрыть шаг, выбрать следующий пресет
await ev(`(() => document.querySelector('.btn--step').click())()`);
await sleep(600);
await ev(`(() => { const s = document.querySelector('.transport__preset'); s.value = 'Верификация'; s.dispatchEvent(new Event('change', { bubbles: true })); })()`);
title = null;
for (let i = 0; i < 20; i++) {
  title = await ev(`window.__ftdi.store.state.currentStep?.title ?? null`);
  if (title === "Верификация") break;
  await sleep(200);
}
check("переключение пресета закрывает предыдущий шаг", title === "Верификация", String(title));

// ручное название сохраняется в пресеты
await ev(`window.__ftdi.store.startStep('Моя метка X').then(() => {})`);
await sleep(800);
const saved = await ev(`JSON.parse(localStorage.getItem('ftdi.quickTitles') || '[]')`);
check("ручное название сохранено в пресеты", Array.isArray(saved) && saved.includes("Моя метка X"), Array.isArray(saved) ? saved.slice(-2).join(", ") : "нет");

// кнопки транспорта — только иконки с подсказками
const info = await ev(`(() => {
  const btns = [...document.querySelectorAll('.transport .btn')];
  return { total: btns.length, withText: btns.filter(b => b.textContent.trim().length > 0).length, withTitle: btns.filter(b => !!b.title).length };
})()`);
check("кнопки транспорта без подписей, но с title", info.total > 6 && info.withText === 0 && info.withTitle === info.total, JSON.stringify(info));

const shot = await send("Page.captureScreenshot", { format: "png" });
writeFileSync("D:\\FTDI_USB_Logger\\assets\\ui-presets.png", Buffer.from(shot.result.data, "base64"));
ws.close(); edge.kill(); await sleep(300);
try { rmSync(profile, { recursive: true, force: true }); } catch {}
const failed = results.filter((x) => !x).length;
console.log(`\n${results.length - failed}/${results.length} проверок`);
process.exit(failed ? 1 : 0);
