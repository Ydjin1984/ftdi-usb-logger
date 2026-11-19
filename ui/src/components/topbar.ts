/** Шапка: бренд, живые статусы, часы, звук, язык, помощь. */

import { store } from "../store";
import { isMuted, setMuted } from "../sound";
import { button, el, icon, iconButton } from "../dom";
import { fmtTimeOnly } from "../format";
import { openHelpDialog, openNewSessionDialog } from "./dialogs";
import { getLang, msg, setLang, t, type Lang } from "../i18n";

msg({
  "DAVINCI  /  КОНСОЛЬ ЗАХВАТА": "DAVINCI  /  CAPTURE CONSOLE",
  "звуковые сигналы шагов": "step sound alerts",
  "+ Новая сессия": "+ New session",
  "завершить текущую сессию, пересканировать шнурки и программы (Ctrl+Alt+N)":
    "finish the current session, rescan cables and programs (Ctrl+Alt+N)",
  "как работать (F1)": "how it works (F1)",
  "язык интерфейса": "interface language",
  "админ": "admin",
  "есть": "yes",
  "нет": "no",
  "движок запущен с правами администратора: Frida-хуки и чтение чужих процессов доступны":
    "engine is running as administrator: Frida hooks and reading other processes are available",
  "движок запущен БЕЗ прав администратора: Frida-хуки не смогут подключиться к программе. Запустите FTDI_USB_Logger.exe (или logger.cmd) и разрешите UAC":
    "engine is running WITHOUT administrator rights: Frida hooks cannot attach to the tool. Start FTDI_USB_Logger.exe (or logger.cmd) and allow UAC",
  "мост": "bridge",
  "на связи": "online",
  "подключение": "connecting",
  "нет связи": "offline",
  "движок": "engine",
  "демоданные": "demo data",
  "готов": "ready",
  "ждёт цель": "waiting for target",
  "хуки": "hooks",
  "включены": "on",
  "пауза": "paused",
  "сняты": "removed",
  "цель": "target",
  "не выбрана": "not selected",
  "сессия": "session",
  "шина": "bus",
  "J2534-драйверов: {n}": "J2534 drivers: {n}",
  "FTDI: {value}": "FTDI: {value}",
  "USB-перечисление: {value}": "USB enumeration: {value}",
  "USBPcap: {value}": "USBPcap: {value}",
  "не установлен": "not installed",
  "да": "yes",
  "pid {pid}": "pid {pid}",
});

export class Topbar {
  el: HTMLElement;
  private pills: HTMLElement;
  private clock: HTMLElement;
  private mute: HTMLButtonElement;
  private langSelect: HTMLSelectElement;
  private lastKey = "";

  constructor() {
    this.el = el("header", "topbar");

    const brand = el("div", "brand");
    const mark = el("div", "brand__mark");
    mark.appendChild(icon("step"));
    const names = el("div");
    names.appendChild(el("div", "brand__name", "FTDI / USB Logger"));
    names.appendChild(el("div", "brand__sub", t("DAVINCI  /  КОНСОЛЬ ЗАХВАТА")));
    brand.append(mark, names);

    this.pills = el("div", "statusbar");
    const spacer = el("div", "topbar__spacer");

    this.clock = el("div", "clock");

    this.langSelect = el("select", "lang-select") as HTMLSelectElement;
    this.langSelect.title = t("язык интерфейса");
    this.langSelect.setAttribute("aria-label", t("язык интерфейса"));
    for (const code of ["ru", "en"] as Lang[]) {
      const opt = el("option") as HTMLOptionElement;
      opt.value = code;
      opt.textContent = code.toUpperCase();
      this.langSelect.append(opt);
    }
    this.langSelect.value = getLang();
    this.langSelect.addEventListener("change", () => {
      setLang((this.langSelect.value === "en" ? "en" : "ru") as Lang);
    });

    this.mute = iconButton(isMuted() ? "mute" : "volume", t("звуковые сигналы шагов"), () => {
      const next = !isMuted();
      setMuted(next);
      this.mute.replaceChildren(icon(next ? "mute" : "volume"));
    });
    const newSession = button(t("+ Новая сессия"), {
      cls: "btn--primary btn--new-session",
      title: t("завершить текущую сессию, пересканировать шнурки и программы (Ctrl+Alt+N)"),
      onClick: () => openNewSessionDialog(),
    });
    const help = iconButton("help", t("как работать (F1)"), () => openHelpDialog());

    this.el.append(brand, this.pills, spacer, newSession, this.clock, this.langSelect, this.mute, help);
    this.update();
  }

  update(): void {
    const s = store.state;
    this.clock.textContent = new Date().toLocaleTimeString(getLang() === "en" ? "en-GB" : "ru-RU");
    this.clock.title = fmtTimeOnly(new Date().toISOString());

    const bridge = s.health?.bridge ?? false;
    const hooks = s.status?.hooks ?? "off";
    const target = s.status?.target ?? null;
    const ws = s.wsState;

    const capsKey = s.health?.capabilities ? `${s.health.capabilities.j2534}:${s.health.capabilities.usbpcap}` : "";
    const admin = s.health?.admin;
    const key = [bridge, hooks, target?.pid ?? 0, s.active?.id ?? "", ws, s.mode, capsKey, String(admin)].join("|");
    if (key === this.lastKey) return;
    this.lastKey = key;

    this.pills.replaceChildren();
    // Права администратора: зелёный «админ есть» / красный «админ нет».
    // В демо-режиме health синтетический и признак неизвестен — пилюлю не рисуем.
    if (typeof admin === "boolean") {
      const p = pill(admin ? "ok" : "err", t("админ"), admin ? t("есть") : t("нет"));
      p.title = admin
        ? t("движок запущен с правами администратора: Frida-хуки и чтение чужих процессов доступны")
        : t("движок запущен БЕЗ прав администратора: Frida-хуки не смогут подключиться к программе. Запустите FTDI_USB_Logger.exe (или logger.cmd) и разрешите UAC");
      this.pills.append(p);
    }
    this.pills.append(
      pill(
        ws === "open" ? "ok" : ws === "connecting" ? "warn" : "err",
        t("мост"),
        ws === "open" ? t("на связи") : ws === "connecting" ? t("подключение") : t("нет связи"),
      ),
      pill(
        bridge ? "ok" : s.mode === "demo" ? "warn" : "",
        t("движок"),
        s.mode === "demo" ? t("демоданные") : bridge ? t("готов") : t("ждёт цель"),
      ),
      pill(
        hooks === "on" ? "ok" : hooks === "paused" ? "warn" : "err",
        t("хуки"),
        hooks === "on" ? t("включены") : hooks === "paused" ? t("пауза") : t("сняты"),
      ),
    );

    if (target) {
      this.pills.append(pill("ok", t("цель"), `${target.name} · pid ${target.pid}`));
    } else if (s.active) {
      this.pills.append(pill("warn", t("сессия"), s.active.label || s.active.id));
    } else {
      this.pills.append(pill("", t("цель"), t("не выбрана")));
    }

    const caps = s.health?.capabilities;
    if (caps && s.mode !== "demo") {
      const value = `USB/J2534 · ${caps.j2534}${caps.usbpcap ? " · raw" : ""}`;
      const tone = caps.j2534 > 0 || caps.usbpcap ? "ok" : "";
      const p = pill(tone, t("шина"), value);
      p.title = [
        t("J2534-драйверов: {n}", { n: caps.j2534 }),
        t("FTDI: {value}", { value: caps.ftd2xx ? t("да") : t("нет") }),
        t("USB-перечисление: {value}", { value: caps.usb_enum ? t("да") : t("нет") }),
        t("USBPcap: {value}", {
          value: caps.usbpcap ? caps.usbpcap_devices.join(", ") : t("не установлен"),
        }),
      ].join("\n");
      this.pills.append(p);
    }
  }
}

function pill(kind: "ok" | "warn" | "err" | "", label: string, value: string): HTMLElement {
  const p = el("div", `pill ${kind ? `pill--${kind}` : ""}`.trim());
  p.appendChild(el("span", "pill__dot"));
  const b = el("b", "", value);
  b.title = value;
  p.append(el("span", "pill__label", label), b);
  return p;
}
