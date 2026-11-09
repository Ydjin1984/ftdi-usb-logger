/** Точка входа UI: собирает каркас, подписывается на состояние, вешает хоткеи. */

import "./styles/tokens.css";
import "./styles/layout.css";
import "./styles/components.css";

import { el } from "./dom";
import { store } from "./store";
import { Topbar } from "./components/topbar";
import { Rail } from "./components/rail";
import { Stream } from "./components/stream";
import { Inspector } from "./components/inspector";
import { Timeline } from "./components/timeline";
import { Transport } from "./components/transport";
import {
  Toasts,
  openExportDialog,
  openHelpDialog,
  openMarkPrompt,
  openNewSessionDialog,
  openStepPrompt,
  openStopConfirm,
} from "./components/dialogs";
import { isDemoMode } from "./api";

const app = document.getElementById("app") as HTMLElement;
const boot = document.getElementById("boot") as HTMLElement;
const bootText = document.getElementById("boot-text") as HTMLElement;

function build(): void {
  const topbar = new Topbar();
  const rail = new Rail();
  const stream = new Stream();
  const inspector = new Inspector();
  const timeline = new Timeline((seq) => stream.scrollToSeq(seq));
  const transport = new Transport();
  const toasts = new Toasts();

  app.replaceChildren(topbar.el, rail.el, stream.el, inspector.el, timeline.el, transport.el);
  app.hidden = false;

  let raf = 0;
  const render = (): void => {
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = 0;
      if (store.state.needsReload) {
        store.state.needsReload = false;
        location.reload();
        return;
      }
      if (store.state.connectionLost) showOffline();
      topbar.update();
      rail.update();
      stream.update();
      inspector.update();
      timeline.update();
      transport.update();
      toasts.update();
    });
  };
  store.subscribe(render);
  render();

  window.addEventListener("resize", () => {
    stream.refresh();
    render();
  });

  installHotkeys(stream);
  // Отладочный доступ: window.__ftdi.store (используется tests/e2e и ручной диагностикой).
  (window as unknown as { __ftdi: unknown }).__ftdi = { store, components: { stream } };
}

function installHotkeys(stream: Stream): void {
  window.addEventListener("keydown", (e) => {
    const target = e.target as HTMLElement | null;
    const typing =
      !!target &&
      (target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable);

    if (e.key === "F1") {
      e.preventDefault();
      openHelpDialog();
      return;
    }
    if (e.key === "F2") {
      e.preventDefault();
      if (e.shiftKey) openStepPrompt();
      else if (store.state.currentStep) void store.endStep();
      else void store.startStep();
      return;
    }
    if (e.key === "F5") {
      e.preventDefault();
      openMarkPrompt();
      return;
    }
    if (e.key === "F6") {
      e.preventDefault();
      const paused = store.state.status?.hooks === "paused";
      void store.hookctl(paused ? "resume" : "pause");
      return;
    }
    if (e.key === "F8") {
      e.preventDefault();
      void store.shot();
      return;
    }
    if (e.key === "Escape") {
      if (document.querySelector(".modal-backdrop")) return;
      if (typing) (target as HTMLElement).blur();
      else openStopConfirm();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
      e.preventDefault();
      stream.focusSearch();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "e") {
      e.preventDefault();
      openExportDialog();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.altKey && e.key.toLowerCase() === "n") {
      e.preventDefault();
      openNewSessionDialog();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "o") {
      e.preventDefault();
      pickAndImport();
      return;
    }
  });
}

function pickAndImport(): void {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".log,.txt,.out,.jsonl";
  input.onchange = async () => {
    const file = input.files?.[0];
    if (!file) return;
    await store.importUpload(file);
  };
  input.click();
}

function installDropzone(): void {
  // Отдельный класс, а не .modal-backdrop: иначе он перехватывает селекторы диалогов
  // и ломает их (первый .modal-backdrop в DOM оказывался этим скрытым слоем).
  const overlay = el("div", "dropzone");
  const box = el("div", "dropzone__box");
  const title = el("div", "sec__title", "ИМПОРТ ЛОГА");
  title.style.marginBottom = "10px";
  const body = el("div", "sec__empty");
  body.append(
    document.createTextNode("Отпустите файл "),
    el("b", "", ".log / .out / .txt"),
    document.createTextNode(" — он будет разобран и добавлен как сессия."),
  );
  box.append(title, body);
  overlay.append(box);
  document.body.append(overlay);

  let depth = 0;
  window.addEventListener("dragenter", (e) => {
    if (!e.dataTransfer?.types.includes("Files")) return;
    depth += 1;
    overlay.classList.add("is-active");
  });
  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
  });
  window.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) overlay.classList.remove("is-active");
  });
  window.addEventListener("drop", async (e) => {
    e.preventDefault();
    depth = 0;
    overlay.classList.remove("is-active");
    const file = e.dataTransfer?.files?.[0];
    if (file) await store.importUpload(file);
  });
}

function showOffline(): void {
  if (!boot.isConnected) document.body.prepend(boot);
  if (boot.classList.contains("boot--offline")) {
    boot.hidden = false;
    return;
  }
  boot.hidden = false;
  boot.classList.add("boot--error", "boot--offline");
  bootText.textContent = "";
  const wrap = el("div");
  wrap.append(
    el("div", "boot__text", "Движок не отвечает: логер остановлен или перезапускается. Предыдущая сессия уже не пишется."),
    el("div", "boot__hint", "Запустите ярлык logger.cmd заново — эта страница переподключится сама, как только движок поднимется."),
  );
  const actions = el("div", "row-actions");
  actions.style.justifyContent = "center";
  actions.style.marginTop = "14px";
  const retry = el("button", "btn btn--primary", "переподключиться");
  retry.type = "button";
  retry.addEventListener("click", () => location.reload());
  actions.append(retry);
  wrap.append(actions);
  bootText.replaceWith(wrap);
}

function showBootError(message: string): void {
  // Слой мог быть откреплён прошлой навигацией/сборкой — возвращаем его на экран.
  if (!boot.isConnected) document.body.prepend(boot);
  boot.hidden = false;
  boot.classList.add("boot--error");
  bootText.textContent = "";
  const wrap = el("div");
  const p = el("div", "boot__text", message);
  const actions = el("div", "row-actions");
  actions.style.justifyContent = "center";
  actions.style.marginTop = "14px";
  const retry = el("button", "btn btn--primary", "повторить подключение");
  retry.type = "button";
  retry.addEventListener("click", () => location.reload());
  const demo = el("button", "btn", "открыть демо-режим");
  demo.type = "button";
  demo.addEventListener("click", () => {
    const u = new URL(location.href);
    u.searchParams.set("demo", "1");
    location.href = u.toString();
  });
  actions.append(retry, demo);
  wrap.append(p, actions);
  bootText.replaceWith(wrap);
}

async function main(): Promise<void> {
  build();
  installDropzone();
  await store.init();
  if (store.state.bootError) {
    showBootError(
      isDemoMode()
        ? `демо-режим не загрузился: ${store.state.bootError}`
        : `Движок не ответил: ${store.state.bootError}. Запустите ftdi-logger.exe (или scripts\\run.ps1) и нажмите «повторить».`,
    );
    return;
  }
  if (boot.isConnected) boot.remove();
}

void main();





