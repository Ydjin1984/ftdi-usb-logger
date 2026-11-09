/** Шапка: бренд, живые статусы, часы, звук, помощь. */

import { store } from "../store";
import { isMuted, setMuted } from "../sound";
import { button, el, icon, iconButton } from "../dom";
import { fmtTimeOnly } from "../format";
import { openHelpDialog, openNewSessionDialog } from "./dialogs";

export class Topbar {
  el: HTMLElement;
  private pills: HTMLElement;
  private clock: HTMLElement;
  private mute: HTMLButtonElement;
  private lastKey = "";

  constructor() {
    this.el = el("header", "topbar");

    const brand = el("div", "brand");
    const mark = el("div", "brand__mark");
    mark.appendChild(icon("step"));
    const names = el("div");
    names.appendChild(el("div", "brand__name", "FTDI / USB Logger"));
    names.appendChild(el("div", "brand__sub", "DAVINCI  /  CAPTURE CONSOLE"));
    brand.append(mark, names);

    this.pills = el("div", "statusbar");
    const spacer = el("div", "topbar__spacer");

    this.clock = el("div", "clock");

    this.mute = iconButton(isMuted() ? "mute" : "volume", "звуковые сигналы шагов", () => {
      const next = !isMuted();
      setMuted(next);
      this.mute.replaceChildren(icon(next ? "mute" : "volume"));
    });
    const newSession = button("+ Новая сессия", {
      cls: "btn--primary btn--new-session",
      title: "завершить текущую сессию, пересканировать шнурки и программы (Ctrl+Alt+N)",
      onClick: () => openNewSessionDialog(),
    });
    const help = iconButton("help", "как работать (F1)", () => openHelpDialog());

    this.el.append(brand, this.pills, spacer, newSession, this.clock, this.mute, help);
    this.update();
  }

  update(): void {
    const s = store.state;
    this.clock.textContent = new Date().toLocaleTimeString("ru-RU");
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
      const p = pill(admin ? "ok" : "err", "админ", admin ? "есть" : "нет");
      p.title = admin
        ? "движок запущен с правами администратора: Frida-хуки и чтение чужих процессов доступны"
        : "движок запущен БЕЗ прав администратора: Frida-хуки не смогут подключиться к программе. Запустите FTDI_USB_Logger.exe (или logger.cmd) и разрешите UAC";
      this.pills.append(p);
    }
    this.pills.append(
      pill(
        ws === "open" ? "ok" : ws === "connecting" ? "warn" : "err",
        "мост",
        ws === "open" ? "на связи" : ws === "connecting" ? "подключение" : "нет связи",
      ),
      pill(
        bridge ? "ok" : s.mode === "demo" ? "warn" : "",
        "движок",
        s.mode === "demo" ? "демоданные" : bridge ? "готов" : "ждёт цель",
      ),
      pill(
        hooks === "on" ? "ok" : hooks === "paused" ? "warn" : "err",
        "хуки",
        hooks === "on" ? "включены" : hooks === "paused" ? "пауза" : "сняты",
      ),
    );

    if (target) {
      this.pills.append(pill("ok", "цель", `${target.name} · pid ${target.pid}`));
    } else if (s.active) {
      this.pills.append(pill("warn", "сессия", s.active.label || s.active.id));
    } else {
      this.pills.append(pill("", "цель", "не выбрана"));
    }

    const caps = s.health?.capabilities;
    if (caps && s.mode !== "demo") {
      const value = `USB/J2534 · ${caps.j2534}${caps.usbpcap ? " · raw" : ""}`;
      const tone = caps.j2534 > 0 || caps.usbpcap ? "ok" : "";
      const p = pill(tone, "шина", value);
      p.title = [
        `J2534-драйверов: ${caps.j2534}`,
        `FTDI: ${caps.ftd2xx ? "да" : "нет"}`,
        `USB-перечисление: ${caps.usb_enum ? "да" : "нет"}`,
        `USBPcap: ${caps.usbpcap ? caps.usbpcap_devices.join(", ") : "не установлен"}`,
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




