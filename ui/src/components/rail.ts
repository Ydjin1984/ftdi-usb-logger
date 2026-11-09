/** Левая колонка: сессии, USB-устройства/J2534-драйверы, процессы-кандидаты. */

import { el, icon, iconButton } from "../dom";
import { fmtDate, fmtNum, fmtBytesShort } from "../format";
import { store } from "../store";
import { openUsbpcapDialog } from "./dialogs";
import type { FtdiDevice, J2534Driver, SessionMeta, ToolProcess, UsbDevice } from "../types";

type UsbTab = "usb" | "j2534";

export class Rail {
  el: HTMLElement;
  private sessionsBody: HTMLElement;
  private sessionsCount: HTMLElement;
  private usbBody: HTMLElement;
  private usbCount: HTMLElement;
  private usbTabs: HTMLElement;
  private toolsBody: HTMLElement;
  private toolsCount: HTMLElement;
  private toolsModes: HTMLElement;
  private pidInput: HTMLInputElement;

  private usbTab: UsbTab = "usb";
  private lastSessions: SessionMeta[] | null = null;
  private lastSessionsActive: string | null = null;
  private lastDevices: FtdiDevice[] | null = null;
  private lastUsb: UsbDevice[] | null = null;
  private lastJ2534: J2534Driver[] | null = null;
  private lastTools: ToolProcess[] | null = null;
  private lastMode = "";

  constructor() {
    this.el = el("aside", "rail");

    const sessions = panel("СЕССИИ", () => void store.refreshSessions(), "refresh");
    this.sessionsBody = sessions.body;
    this.sessionsCount = sessions.count;
    sessions.root.classList.add("panel--grow");

    // USB / J2534 — один панель с табами
    const usb = panel("USB-УСТРОЙСТВА", () => void store.refreshTargets(), "refresh");
    this.usbBody = usb.body;
    this.usbCount = usb.count;
    this.usbTabs = el("div", "tabs");
    this.usbTabs.style.padding = "0";
    this.usbTabs.style.background = "transparent";
    for (const [id, label] of [
      ["usb", "USB"],
      ["j2534", "J2534"],
    ] as Array<[UsbTab, string]>) {
      const b = el("button", "tab", label);
      b.type = "button";
      b.dataset.tab = id;
      b.style.height = "22px";
      b.style.fontSize = "9px";
      b.addEventListener("click", () => {
        this.usbTab = id;
        this.renderUsb();
        this.updateTabs();
      });
      this.usbTabs.append(b);
    }
    const usbActions = el("div", "rail-controls");
    usbActions.style.padding = "5px 6px";
    const raw = el("button", "btn btn--sm", "записать USB-шину (USBPcap)");
    raw.type = "button";
    raw.title = "сырой захват USB через драйвер USBPcap (нужны права администратора)";
    raw.addEventListener("click", () => {
      const caps = store.state.health?.capabilities;
      void openUsbpcapDialog(caps?.usbpcap_devices ?? []);
    });
    usbActions.append(raw);
    usb.root.insertBefore(usbActions, usb.body);
    usb.root.insertBefore(this.usbTabs, usb.body);
    this.usbBody.classList.add("panel__body--short");

    const tools = panel("ПРОГРАММЫ", () => void store.refreshTargets(), "refresh");
    this.toolsBody = tools.body;
    this.toolsCount = tools.count;
    this.toolsBody.classList.add("panel__body--short");

    // Режим списка + ручной PID
    const controls = el("div", "rail-controls");
    this.toolsModes = el("div", "filters");
    this.toolsModes.style.flexWrap = "wrap";
    for (const [id, label, title] of [
      ["auto", "авто", "окно + драйверы USB/FTDI/J2534 + известные инструменты"],
      ["usb", "usb", "только процессы с USB/FTDI/J2534-модулями"],
      ["window", "окна", "только процессы с видимым окном"],
      ["all", "все", "все процессы пользователя"],
    ] as Array<[typeof store.state.toolsMode, string, string]>) {
      const b = el("button", "chip", label);
      b.type = "button";
      b.dataset.mode = id;
      b.title = title;
      b.style.height = "20px";
      b.style.fontSize = "9px";
      b.addEventListener("click", () => {
        void store.setToolsMode(id);
        this.updateModeChips();
      });
      this.toolsModes.append(b);
    }
    const pidRow = el("div", "rail-pid");
    this.pidInput = el("input");
    this.pidInput.type = "number";
    this.pidInput.min = "1";
    this.pidInput.placeholder = "PID";
    this.pidInput.title = "прицепиться к процессу по PID вручную";
    const pidBtn = el("button", "btn btn--sm", "→");
    pidBtn.type = "button";
    pidBtn.title = "подключиться к процессу с этим PID";
    const doAttach = (): void => {
      const pid = Number(this.pidInput.value);
      void store.attachPid(pid);
      this.pidInput.value = "";
    };
    pidBtn.addEventListener("click", doAttach);
    this.pidInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doAttach();
    });
    pidRow.append(this.pidInput, pidBtn);
    controls.append(this.toolsModes, pidRow);
    tools.root.insertBefore(controls, tools.body);

    this.el.append(sessions.root, usb.root, tools.root);
    this.update();
  }

  update(): void {
    const s = store.state;
    if (s.sessions !== this.lastSessions || s.active?.id !== this.lastSessionsActive) {
      this.lastSessions = s.sessions;
      this.lastSessionsActive = s.active?.id ?? null;
      this.renderSessions();
    }
    if (
      s.usbDevices !== this.lastUsb ||
      s.j2534Drivers !== this.lastJ2534 ||
      s.devices !== this.lastDevices
    ) {
      this.lastUsb = s.usbDevices;
      this.lastJ2534 = s.j2534Drivers;
      this.lastDevices = s.devices;
      this.renderUsb();
      this.updateTabs();
    }
    if (s.tools !== this.lastTools || s.toolsMode !== this.lastMode) {
      this.lastTools = s.tools;
      this.lastMode = s.toolsMode;
      this.renderTools();
      this.updateModeChips();
    }
  }

  /* ── сессии ───────────────────────────────────────────────────────────── */

  private renderSessions(): void {
    const s = store.state;
    this.sessionsCount.textContent = String(s.sessions.length);
    this.sessionsBody.replaceChildren();
    if (!s.sessions.length) {
      this.sessionsBody.append(
        emptyBlock(
          s.mode === "demo"
            ? "Демо-режим: сессия сгенерирована локально."
            : "Сессий пока нет. Запустите программу, найдите её в «ПРОГРАММЫ» и нажмите «подключить» (или введите PID вручную).",
        ),
      );
      return;
    }
    for (const meta of s.sessions) {
      const item = el("div", `session-item${meta.id === s.active?.id ? " is-active" : ""}`);
      item.tabIndex = 0;
      const title = el("div", "session-item__title");
      title.append(el("span", "", meta.label || meta.id));
      if (meta.status === "recording") title.append(el("span", "badge-rec", "REC"));
      if (meta.transport === "import") title.append(el("span", "badge-tag", "импорт"));
      else if (meta.transport === "mixed") title.append(el("span", "badge-tag", "mix"));
      const time = el("div", "session-item__time", fmtDate(meta.started_at));
      const stats = el("div", "session-item__meta");
      stats.append(
        spanBold("шагов", fmtNum(meta.counts?.steps ?? 0)),
        spanBold("TX", fmtBytesShort(meta.counts?.tx_bytes ?? 0) + "B"),
        spanBold("RX", fmtBytesShort(meta.counts?.rx_bytes ?? 0) + "B"),
      );
      item.append(title, time, stats);
      const open = (): void => void store.selectSession(meta.id);
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

  /* ── USB / J2534 ──────────────────────────────────────────────────────── */

  private updateTabs(): void {
    for (const b of Array.from(this.usbTabs.children) as HTMLElement[]) {
      b.classList.toggle("is-active", b.dataset.tab === this.usbTab);
    }
    const s = store.state;
    this.usbCount.textContent = String(
      this.usbTab === "usb" ? s.usbDevices.length : s.j2534Drivers.length,
    );
  }

  private renderUsb(): void {
    const s = store.state;
    this.usbBody.replaceChildren();
    if (this.usbTab === "usb") {
      const present = s.usbDevices.filter((d) => d.present);
      const absent = s.usbDevices.filter((d) => !d.present);
      if (!s.usbDevices.length) {
        this.usbBody.append(emptyBlock("USB-устройства не найдены (или нет доступа к PnP-дереву)."));
        return;
      }
      for (const d of [...present, ...absent]) this.usbBody.append(usbRow(d));
    } else {
      if (!s.j2534Drivers.length) {
        this.usbBody.append(
          emptyBlock(
            "J2534-драйверы не зарегистрированы. Установите драйвер адаптера (Scanmatik, CHIPSOFT, OpenPort, VXDIAG…).",
          ),
        );
        return;
      }
      for (const drv of s.j2534Drivers) this.usbBody.append(j2534Row(drv));
      this.usbBody.append(
        emptyBlock(
          "J2534-драйвер подхватывается хуком, когда программа загрузит его DLL. Прицепитесь к программе и работайте как обычно.",
        ),
      );
    }
  }

  /* ── процессы ─────────────────────────────────────────────────────────── */

  private updateModeChips(): void {
    const mode = store.state.toolsMode;
    for (const b of Array.from(this.toolsModes.children) as HTMLElement[]) {
      b.classList.toggle("is-on", b.dataset.mode === mode);
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
            ? "Опрос процессов…"
            : store.state.toolsMode === "usb"
              ? "Процессов с USB/FTDI/J2534-модулями не видно. Переключите фильтр на «окна» или «все» и найдите программу вручную."
              : "Процессов нет. Запустите программу и обновите список; либо введите её PID вручную выше.",
        ),
      );
      return;
    }
    for (const t of tools) {
      const row = el("div", "device");
      if (store.state.status?.target?.pid === t.pid) row.classList.add("is-target");
      const ic = el("div", "device__icon");
      ic.appendChild(icon(t.has_j2534 ? "chip" : "usb"));
      const body = el("div");
      const title = el("div", "device__title");
      title.append(el("span", "", t.known_tool || t.name));
      const attach = el("button", "btn btn--sm", "подключить");
      attach.type = "button";
      attach.style.marginTop = "3px";
      attach.addEventListener("click", (e) => {
        e.stopPropagation();
        void store.attach(t.pid, t.known_tool || t.name.replace(/\.exe$/i, ""));
      });
      const badges = el("div", "badges");
      for (const cap of capBadges(t)) badges.append(el("span", "badge-tag", cap));
      if (t.modules_denied) {
        const denied = el("span", "badge-tag badge-tag--warn", "нужен админ");
        denied.title = "не удалось прочитать модули процесса — запустите логер от администратора";
        badges.append(denied);
      }
      const sub = el("div", "device__sub");
      sub.textContent = `pid ${t.pid}${t.arch ? ` · ${t.arch}` : ""}${t.window_title ? ` · ${t.window_title}` : ""}`;
      body.append(title, badges, sub);
      if (t.exe) body.append(el("div", "device__sub", t.exe));
      body.append(attach);
      row.append(ic, body);
      row.title = [t.exe, t.cmdline].filter(Boolean).join("\n");
      this.toolsBody.append(row);
    }
  }
}

/* ── элементы ───────────────────────────────────────────────────────────── */

function capBadges(t: ToolProcess): string[] {
  const out: string[] = [];
  if (t.has_ftd2xx) out.push("FTDI");
  if (t.has_j2534) out.push("J2534");
  if (t.has_usb) out.push("USB");
  if (t.window_title) out.push("окно");
  if (!out.length && t.capabilities?.length) out.push(...t.capabilities);
  return out;
}

function usbRow(d: UsbDevice): HTMLElement {
  const row = el("div", "device");
  const ic = el("div", "device__icon");
  ic.appendChild(icon(d.kind === "ftdi" ? "usb" : "chip"));
  const body = el("div");
  const title = el("div", "device__title");
  title.append(el("span", "", d.friendly_name || d.description || d.id));
  if (d.kind) title.append(el("span", "badge-tag", d.kind));
  if (!d.present) title.append(el("span", "badge-tag", "off"));
  const vidpid =
    d.vid != null && d.pid != null
      ? `VID_${d.vid.toString(16).padStart(4, "0").toUpperCase()}&PID_${d.pid
          .toString(16)
          .padStart(4, "0")
          .toUpperCase()}`
      : "";
  const sub = el("div", "device__sub");
  sub.textContent = [vidpid, d.serial, d.com_port != null ? `COM${d.com_port}` : ""]
    .filter(Boolean)
    .join(" · ");
  const sub2 = el("div", "device__sub");
  sub2.textContent = [d.service, d.class_name, d.manufacturer].filter(Boolean).join(" · ");
  body.append(title, sub, sub2);
  row.append(ic, body);
  row.title = d.id;
  return row;
}

function j2534Row(d: J2534Driver): HTMLElement {
  const row = el("div", "device");
  const ic = el("div", "device__icon");
  ic.appendChild(icon("chip"));
  const body = el("div");
  const title = el("div", "device__title");
  title.append(el("span", "", d.name || d.registry_key));
  if (d.dll_present) title.append(el("span", "badge-tag", "dll"));
  else title.append(el("span", "badge-tag badge-tag--warn", "нет dll"));
  const sub = el("div", "device__sub");
  sub.textContent = [d.vendor, d.version].filter(Boolean).join(" · ");
  const sub2 = el("div", "device__sub", d.dll || "");
  body.append(title, sub, sub2);
  row.append(ic, body);
  row.title = `${d.registry_key}\n${d.dll}`;
  return row;
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

