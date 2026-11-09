/** Шапка: бренд, живые статусы, часы, звук, помощь. */

import { store } from "../store";
import { isMuted, setMuted } from "../sound";
import { el, icon, iconButton } from "../dom";
import { fmtTimeOnly } from "../format";
import { openHelpDialog } from "./dialogs";

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
    names.appendChild(el("div", "brand__name", "FTDI/USB LOGGER"));
    names.appendChild(el("div", "brand__sub", "обмен · шаги · разбор"));
    brand.append(mark, names);

    this.pills = el("div", "statusbar");
    const spacer = el("div", "topbar__spacer");

    this.clock = el("div", "clock");

    this.mute = iconButton(isMuted() ? "mute" : "volume", "звуковые сигналы шагов", () => {
      const next = !isMuted();
      setMuted(next);
      this.mute.replaceChildren(icon(next ? "mute" : "volume"));
    });
    const help = iconButton("help", "как работать (F1)", () => openHelpDialog());

    this.el.append(brand, this.pills, spacer, this.clock, this.mute, help);
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

    const key = [bridge, hooks, target?.pid ?? 0, s.active?.id ?? "", ws, s.mode].join("|");
    if (key === this.lastKey) return;
    this.lastKey = key;

    this.pills.replaceChildren();
    this.pills.append(
      pill(
        ws === "open" ? "ok" : ws === "connecting" ? "warn" : "err",
        "мост",
        ws === "open" ? "на связи" : ws === "connecting" ? "подключение" : "нет связи",
      ),
      pill(
        bridge ? "ok" : s.mode === "demo" ? "warn" : "",
        "движок",
        s.mode === "demo" ? "демо" : bridge ? "готов" : "ждёт цель",
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

    if (s.mode === "demo") this.pills.append(pill("warn", "режим", "демо"));
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

