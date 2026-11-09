/** Мелкие DOM-хелперы и иконки (inline SVG, без внешних ассетов). */

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text != null) node.textContent = text;
  return node;
}

export function qs<T extends Element>(root: ParentNode, sel: string): T {
  const found = root.querySelector<T>(sel);
  if (!found) throw new Error(`не найден элемент: ${sel}`);
  return found;
}

const ICONS: Record<string, string> = {
  step: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="5.2"/><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none"/></svg>`,
  stepStop: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="5.2"/><rect x="5.8" y="5.8" width="4.4" height="4.4" fill="currentColor" stroke="none"/></svg>`,
  mark: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 14V2.5M4 3h7.5l-1.6 3 1.6 3H4"/></svg>`,
  pause: `<svg viewBox="0 0 16 16" fill="currentColor"><rect x="4.4" y="3" width="2.6" height="10" rx="0.6"/><rect x="9" y="3" width="2.6" height="10" rx="0.6"/></svg>`,
  play: `<svg viewBox="0 0 16 16" fill="currentColor"><path d="M5 3l8 5-8 5z"/></svg>`,
  camera: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2" y="4.6" width="12" height="8.4" rx="1.4"/><circle cx="8" cy="8.8" r="2.4"/><path d="M5.6 4.6l1-1.8h2.8l1 1.8"/></svg>`,
  stop: `<svg viewBox="0 0 16 16" fill="currentColor"><rect x="3.6" y="3.6" width="8.8" height="8.8" rx="1.2"/></svg>`,
  download: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2.5v7.2M4.8 6.9L8 10.2l3.2-3.3M3 12.8h10"/></svg>`,
  upload: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 10.2V3M4.8 6.1L8 2.8l3.2 3.3M3 12.8h10"/></svg>`,
  refresh: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 8a5 5 0 1 1-1.6-3.7M13 2.4V5.2h-2.8"/></svg>`,
  usb: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 14V5.5M8 5.5l-2.6 2M8 5.5l2.6 2"/><circle cx="8" cy="3.4" r="1.5"/><circle cx="5.4" cy="9.2" r="1.2"/><rect x="9.3" y="8.4" width="2.2" height="2.2" rx="0.4"/></svg>`,
  chip: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><rect x="4.4" y="4.4" width="7.2" height="7.2" rx="1"/><path d="M6.4 2v2M9.6 2v2M6.4 12v2M9.6 12v2M2 6.4h2M2 9.6h2M12 6.4h2M12 9.6h2"/></svg>`,
  search: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7.2" cy="7.2" r="4.2"/><path d="M10.4 10.4L14 14"/></svg>`,
  close: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M4 4l8 8M12 4l-8 8"/></svg>`,
  folder: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M2 4.4h4l1.2 1.6H14v6.6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1z"/></svg>`,
  share: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="12" cy="4" r="1.8"/><circle cx="4" cy="8" r="1.8"/><circle cx="12" cy="12" r="1.8"/><path d="M5.6 7.2l4.8-2.4M5.6 8.8l4.8 2.4"/></svg>`,
  copy: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="5.6" y="5.6" width="8" height="8" rx="1"/><path d="M10.4 5.6V3.4a1 1 0 0 0-1-1H3.4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h2.2"/></svg>`,
  settings: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="2.2"/><path d="M8 1.6v1.8M8 12.6v1.8M1.6 8h1.8M12.6 8h1.8M3.5 3.5l1.3 1.3M11.2 11.2l1.3 1.3M12.5 3.5l-1.3 1.3M4.8 11.2l-1.3 1.3"/></svg>`,
  help: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="8" cy="8" r="6"/><path d="M6.2 6.2A1.9 1.9 0 1 1 8.6 8.1c-.5.2-.7.6-.7 1.1"/><circle cx="8" cy="11.6" r=".8" fill="currentColor" stroke="none"/></svg>`,
  volume: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3 6.2h2l3-2.4v8.4l-3-2.4H3z"/><path d="M10.6 5.6a3.4 3.4 0 0 1 0 4.8M12.4 4a6 6 0 0 1 0 8"/></svg>`,
  mute: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M3 6.2h2l3-2.4v8.4l-3-2.4H3z"/><path d="M10.4 6.2l3.2 3.6M13.6 6.2l-3.2 3.6"/></svg>`,
  chevron: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M5.5 3.5L10 8l-4.5 4.5"/></svg>`,
  clock: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="8" cy="8" r="6"/><path d="M8 4.6V8l2.4 1.6"/></svg>`,
  check: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3.4 8.4l3 3 6.2-6.6"/></svg>`,
  warn: `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 2.4l6 11.2H2z"/><path d="M8 6.4v3.4"/><circle cx="8" cy="11.9" r=".7" fill="currentColor" stroke="none"/></svg>`,
};

export function icon(name: keyof typeof ICONS | string): HTMLSpanElement {
  const span = document.createElement("span");
  span.className = "ico";
  span.innerHTML = ICONS[name] ?? "";
  span.style.display = "inline-flex";
  span.style.width = "14px";
  span.style.height = "14px";
  span.style.flex = "none";
  const svg = span.firstElementChild as SVGElement | null;
  if (svg) {
    svg.setAttribute("width", "14");
    svg.setAttribute("height", "14");
    svg.style.display = "block";
  }
  return span;
}

export function button(
  label: string,
  opts: {
    cls?: string;
    icon?: string;
    title?: string;
    onClick?: (e: MouseEvent) => void;
  } = {},
): HTMLButtonElement {
  const b = el("button", `btn ${opts.cls ?? ""}`.trim());
  b.type = "button";
  if (opts.icon) b.appendChild(icon(opts.icon));
  if (label) b.appendChild(el("span", "", label));
  if (opts.title) b.title = opts.title;
  if (opts.onClick) b.addEventListener("click", opts.onClick);
  return b;
}

export function iconButton(ic: string, title: string, onClick: (e: MouseEvent) => void, cls = ""): HTMLButtonElement {
  const b = el("button", `icon-btn ${cls}`.trim());
  b.type = "button";
  b.title = title;
  b.setAttribute("aria-label", title);
  b.appendChild(icon(ic));
  b.addEventListener("click", onClick);
  return b;
}
