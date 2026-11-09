/** Левая колонка: сессии, FTDI-устройства, процессы-кандидаты. */

import { el, icon, iconButton } from "../dom";
import { fmtDate, fmtNum, fmtBytesShort } from "../format";
import { store } from "../store";
import type { FtdiDevice, SessionMeta, ToolProcess } from "../types";

export class Rail {
  el: HTMLElement;
  private sessionsBody: HTMLElement;
  private sessionsCount: HTMLElement;
  private devicesBody: HTMLElement;
  private devicesCount: HTMLElement;
  private toolsBody: HTMLElement;
  private toolsCount: HTMLElement;

  private lastSessions: SessionMeta[] | null = null;
  private lastSessionsActive: string | null = null;
  private lastDevices: FtdiDevice[] | null = null;
  private lastTools: ToolProcess[] | null = null;

  constructor() {
    this.el = el("aside", "rail");

    const sessions = panel("СЕССИИ", () => {
      void store.refreshSessions();
    }, "refresh");
    this.sessionsBody = sessions.body;
    this.sessionsCount = sessions.count;
    sessions.root.classList.add("panel--grow");

    const devices = panel("FTDI-УСТРОЙСТВА", () => {
      void store.refreshTargets();
    }, "refresh");
    this.devicesBody = devices.body;
    this.devicesCount = devices.count;

    const tools = panel("ПРОЦЕССЫ НА FTDI", () => {
      void store.refreshTargets();
    }, "refresh");
    this.toolsBody = tools.body;
    this.toolsCount = tools.count;

    this.el.append(sessions.root, devices.root, tools.root);
    this.update();
  }

  update(): void {
    const s = store.state;
    if (s.sessions !== this.lastSessions || s.active?.id !== this.lastSessionsActive) {
      this.lastSessions = s.sessions;
      this.lastSessionsActive = s.active?.id ?? null;
      this.renderSessions();
    }
    if (s.devices !== this.lastDevices) {
      this.lastDevices = s.devices;
      this.renderDevices();
    }
    if (s.tools !== this.lastTools) {
      this.lastTools = s.tools;
      this.renderTools();
    }
  }

  private renderSessions(): void {
    const s = store.state;
    this.sessionsCount.textContent = String(s.sessions.length);
    this.sessionsBody.replaceChildren();
    if (!s.sessions.length) {
      this.sessionsBody.append(
        emptyBlock(
          s.mode === "demo"
            ? "Демо-режим: сессия сгенерирована локально."
            : "Сессий пока нет. Запустите программу на FTDI, найдите её в «Процессы на FTDI» ниже и нажмите «подключить».",
        ),
      );
      return;
    }
    for (const meta of s.sessions) {
      const item = el("div", `session-item${meta.id === s.active?.id ? " is-active" : ""}`);
      item.tabIndex = 0;
      const title = el("div", "session-item__title");
      const name = el("span", "", meta.label || meta.id);
      title.append(name);
      if (meta.status === "recording") title.append(el("span", "badge-rec", "REC"));
      if (meta.transport === "import") title.append(el("span", "badge-tag", "импорт"));
      const time = el("div", "session-item__time", fmtDate(meta.started_at));
      const stats = el("div", "session-item__meta");
      stats.append(
        spanBold("шагов", fmtNum(meta.counts?.steps ?? 0)),
        spanBold("TX", fmtBytesShort(meta.counts?.tx_bytes ?? 0) + "B"),
        spanBold("RX", fmtBytesShort(meta.counts?.rx_bytes ?? 0) + "B"),
      );
      item.append(title, time, stats);
      const open = () => void store.selectSession(meta.id);
      item.addEventListener("click", open);
      item.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      });
      this.sessionsBody.append(item);
    }
  }

  private renderDevices(): void {
    const devices = store.state.devices;
    this.devicesCount.textContent = String(devices.length);
    this.devicesBody.replaceChildren();
    if (!devices.length) {
      this.devicesBody.append(
        emptyBlock(
          store.state.loadingTargets
            ? "Опрос устройств…"
            : "FTDI-шнурков не видно. Проверьте драйвер D2XX (FTD2XX.DLL) и подключение.",
        ),
      );
      return;
    }
    for (const d of devices) {
      const row = el("div", "device");
      const ic = el("div", "device__icon");
      ic.appendChild(icon("usb"));
      const body = el("div");
      const title = el("div", "device__title", d.description || "FTDI device");
      const sub = el("div", "device__sub", `#${d.index} · ${d.serial || "no serial"}`);
      body.append(title, sub);
      if (d.com_port != null) {
        const sub2 = el("div", "device__sub", `COM${d.com_port} · ${d.source}`);
        body.append(sub2);
      }
      row.append(ic, body);
      row.title = `D2XX: ${d.serial} ${d.description}\nVID:PID ${(d.vendor_id ?? 0).toString(16)}:${(d.product_id ?? 0).toString(16)}`;
      this.devicesBody.append(row);
    }
  }

  private renderTools(): void {
    const tools = store.state.tools;
    this.toolsCount.textContent = String(tools.length);
    this.toolsBody.replaceChildren();
    if (!tools.length) {
      this.toolsBody.append(
        emptyBlock(
          store.state.loadingTargets
            ? "Ищем процессы…"
            : "Программ на FTDI не найдено. Сначала запустите Quickflash / WinKFP, затем обновите список.",
        ),
      );
      return;
    }
    for (const t of tools) {
      const row = el("div", "device");
      if (store.state.status?.target?.pid === t.pid) row.classList.add("is-target");
      const ic = el("div", "device__icon");
      ic.appendChild(icon("chip"));
      const body = el("div");
      const title = el("div", "device__title");
      title.append(el("span", "", t.known_tool || t.name));
      const attach = el("button", "btn btn--sm", "подключить");
      attach.type = "button";
      attach.style.marginLeft = "4px";
      attach.addEventListener("click", (e) => {
        e.stopPropagation();
        void store.attach(t.pid, t.known_tool || t.name.replace(/\.exe$/i, ""));
      });
      const sub = el("div", "device__sub");
      sub.textContent = `pid ${t.pid}${t.has_ftd2xx ? " · ftd2xx.dll" : ""}${t.window_title ? ` · ${t.window_title}` : ""}`;
      const sub2 = el("div", "device__sub", t.exe || "");
      body.append(title, sub, sub2, attach);
      row.append(ic, body);
      row.title = t.exe;
      this.toolsBody.append(row);
    }
  }
}

function spanBold(label: string, value: string): HTMLElement {
  const s = el("span");
  s.append(document.createTextNode(label + " "), el("b", "", value));
  return s;
}

function emptyBlock(text: string): HTMLElement {
  const d = el("div", "panel__empty");
  d.textContent = text;
  return d;
}

function panel(title: string, onRefresh: () => void, refreshIcon: string) {
  const root = el("section", "panel");
  const head = el("div", "panel__head");
  const count = el("span", "panel__count", "0");
  head.append(el("span", "panel__title", title), count, iconButton(refreshIcon, "обновить", onRefresh));
  const body = el("div", "panel__body");
  root.append(head, body);
  return { root, body, count };
}

