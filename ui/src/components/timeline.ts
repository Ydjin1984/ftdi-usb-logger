/** Таймлайн: плотность обмена, полосы шагов, клик — переход к событию. */

import { el } from "../dom";
import { fmtDurationSeconds, fmtTime } from "../format";
import { store } from "../store";

export class Timeline {
  el: HTMLElement;
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D;
  private wrap: HTMLElement;
  private hint: HTMLElement;
  private hoverX: number | null = null;
  private lastEvents = -1;
  private lastSteps = -1;
  private lastWidth = 0;
  private raf = 0;
  private onSeek: (seq: number) => void;

  constructor(onSeek: (seq: number) => void) {
    this.onSeek = onSeek;
    this.el = el("section", "timeline");
    const head = el("div", "timeline__head");
    head.append(el("span", "timeline__title", "ТАЙМЛАЙН"));
    this.hint = el("span", "timeline__hint", "плотность обмена · клик — перейти к событию");
    head.append(this.hint);
    this.wrap = el("div", "timeline__canvas-wrap");
    this.canvas = el("canvas");
    this.wrap.append(this.canvas);
    this.el.append(head, this.wrap);
    const ctx = this.canvas.getContext("2d");
    if (!ctx) throw new Error("canvas 2d недоступен");
    this.ctx = ctx;

    new ResizeObserver(() => this.draw()).observe(this.wrap);
    this.canvas.addEventListener("mousemove", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.hoverX = e.clientX - rect.left;
      this.scheduleDraw();
    });
    this.canvas.addEventListener("mouseleave", () => {
      this.hoverX = null;
      this.scheduleDraw();
    });
    this.canvas.addEventListener("click", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      this.seekToX(e.clientX - rect.left, rect.width);
    });
    this.update();
  }

  update(): void {
    const s = store.state;
    if (s.events.length !== this.lastEvents || s.steps.length !== this.lastSteps) {
      this.lastEvents = s.events.length;
      this.lastSteps = s.steps.length;
      this.scheduleDraw();
    }
  }

  private scheduleDraw(): void {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.draw();
    });
  }

  private seekToX(x: number, width: number): void {
    const s = store.state;
    if (!s.events.length) return;
    const maxT = this.maxT();
    const t = (x / width) * maxT;
    let best = s.events[0];
    let bestD = Infinity;
    for (const ev of s.events) {
      const d = Math.abs(ev.t - t);
      if (d < bestD) {
        bestD = d;
        best = ev;
      }
    }
    this.onSeek(best.seq);
  }

  private maxT(): number {
    const s = store.state;
    let max = 1;
    for (const e of s.events) if (e.t > max) max = e.t;
    for (const st of s.steps) {
      const end = Date.parse(st.ended_at || "");
      if (!isNaN(end)) continue;
    }
    return max * 1.02;
  }

  private draw(): void {
    const dpr = window.devicePixelRatio || 1;
    const w = this.wrap.clientWidth;
    const h = this.wrap.clientHeight;
    if (w <= 0 || h <= 0) return;
    this.canvas.width = Math.round(w * dpr);
    this.canvas.height = Math.round(h * dpr);
    this.canvas.style.width = `${w}px`;
    this.canvas.style.height = `${h}px`;
    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const s = store.state;
    const padX = 10;
    const innerW = w - padX * 2;
    const bandTop = 4;
    const bandH = 12;
    const chartTop = bandTop + bandH + 5;
    const chartH = h - chartTop - 6;
    const maxT = this.maxT();

    // сетка
    ctx.strokeStyle = "rgba(42,55,68,0.5)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let i = 0; i <= 4; i++) {
      const x = padX + (innerW * i) / 4;
      ctx.moveTo(x, bandTop);
      ctx.lineTo(x, h - 4);
    }
    ctx.stroke();

    if (!s.events.length) {
      ctx.fillStyle = "#5f6c7a";
      ctx.font = "10px " + (getComputedStyle(document.body).getPropertyValue("--font-mono") || "monospace");
      ctx.fillText("таймлайн появится вместе с потоком", padX + 4, chartTop + chartH / 2);
      this.drawHover(ctx, w, h, padX, innerW, maxT);
      return;
    }

    // плотность по бакетам
    const buckets = Math.max(40, Math.floor(innerW / 3));
    const tx = new Float32Array(buckets);
    const rx = new Float32Array(buckets);
    for (const ev of s.events) {
      const idx = Math.min(buckets - 1, Math.max(0, Math.floor((ev.t / maxT) * buckets)));
      if (ev.kind === "tx") tx[idx] += Math.max(1, ev.len);
      else if (ev.kind === "rx") rx[idx] += Math.max(1, ev.len);
      else if (ev.kind === "mark" || ev.kind === "step_start" || ev.kind === "step_end") rx[idx] += 6;
    }
    let maxV = 1;
    for (let i = 0; i < buckets; i++) maxV = Math.max(maxV, tx[i], rx[i]);
    const bw = innerW / buckets;
    for (let i = 0; i < buckets; i++) {
      const x = padX + i * bw;
      const hTx = (tx[i] / maxV) * chartH;
      const hRx = (rx[i] / maxV) * chartH;
      if (hTx > 0) {
        ctx.fillStyle = "rgba(53,208,255,0.55)";
        ctx.fillRect(x, chartTop + chartH - hTx, Math.max(1, bw - 0.6), hTx);
      }
      if (hRx > 0) {
        ctx.fillStyle = "rgba(126,231,135,0.4)";
        ctx.fillRect(x + Math.max(0.5, bw / 2 - 0.3), chartTop + chartH - hRx, Math.max(1, bw / 2), hRx);
      }
    }

    // полосы шагов
    for (const st of s.steps) {
      const start = Date.parse(st.started_at || "");
      const end = Date.parse(st.ended_at || "");
      if (isNaN(start) || isNaN(end) || end <= start) continue;
      const t0 = this.epochToT(start);
      const t1 = this.epochToT(end);
      const x0 = padX + (t0 / maxT) * innerW;
      const x1 = padX + (t1 / maxT) * innerW;
      ctx.fillStyle = "rgba(255,200,87,0.14)";
      ctx.fillRect(x0, bandTop, Math.max(2, x1 - x0), bandH);
      ctx.fillStyle = "rgba(255,200,87,0.6)";
      ctx.fillRect(x0, bandTop, 1, bandH);
      ctx.fillRect(x1 - 1, bandTop, 1, bandH);
      if (x1 - x0 <= 46) {
        ctx.fillStyle = "rgba(255,200,87,0.9)";
        ctx.font = "9px " + (getComputedStyle(document.body).getPropertyValue("--font-mono") || "monospace");
        ctx.fillText(String(st.idx), x0 + 3, bandTop + bandH - 3);
      }
      if (x1 - x0 > 46) {
        ctx.fillStyle = "rgba(255,200,87,0.85)";
        ctx.font = "9px " + (getComputedStyle(document.body).getPropertyValue("--font-mono") || "monospace");
        const label = `${st.idx} ${st.title}`.slice(0, Math.floor((x1 - x0) / 5.2));
        ctx.fillText(label, x0 + 4, bandTop + bandH - 3);
      }
    }

    // текущий шаг
    if (s.currentStep) {
      const st = s.stepStartEpoch;
      const t0 = (Date.now() - st) / 1000;
      const x0 = padX + Math.min(1, t0 / maxT) * innerW;
      ctx.fillStyle = "rgba(255,107,107,0.35)";
      ctx.fillRect(x0, bandTop, 2, bandH);
    }

    // playhead
    const lastT = s.events[s.events.length - 1].t;
    const px = padX + (lastT / maxT) * innerW;
    ctx.strokeStyle = "rgba(217,226,236,0.5)";
    ctx.beginPath();
    ctx.moveTo(px, bandTop);
    ctx.lineTo(px, h - 4);
    ctx.stroke();

    this.drawHover(ctx, w, h, padX, innerW, maxT);
  }

  private epochToT(epoch: number): number {
    const s = store.state;
    const events = s.events;
    if (!events.length) return 0;
    const base = Date.parse(events[0].wall);
    if (isNaN(base)) return 0;
    return Math.max(0, (epoch - base) / 1000);
  }

  private drawHover(
    ctx: CanvasRenderingContext2D,
    _w: number,
    _h: number,
    padX: number,
    innerW: number,
    maxT: number,
  ): void {
    if (this.hoverX == null) return;
    const t = ((this.hoverX - padX) / innerW) * maxT;
    if (t < 0 || t > maxT) return;
    ctx.strokeStyle = "rgba(53,208,255,0.55)";
    ctx.beginPath();
    ctx.moveTo(this.hoverX, 2);
    ctx.lineTo(this.hoverX, this.wrap.clientHeight - 2);
    ctx.stroke();
    const label = `${fmtTime(t)} · ${fmtDurationSeconds(t)}`;
    ctx.font = "10px " + (getComputedStyle(document.body).getPropertyValue("--font-mono") || "monospace");
    const tw = ctx.measureText(label).width;
    const x = Math.min(this.hoverX + 6, this.wrap.clientWidth - tw - 8);
    ctx.fillStyle = "rgba(14,19,25,0.9)";
    ctx.fillRect(x - 3, this.wrap.clientHeight - 17, tw + 6, 14);
    ctx.fillStyle = "#93a1b0";
    ctx.fillText(label, x, this.wrap.clientHeight - 6);
  }
}

