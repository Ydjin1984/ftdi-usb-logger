/** Звуковые подсказки для разметки шагов (WebAudio, без внешних файлов). */

let ctx: AudioContext | null = null;
let muted = false;

export function setMuted(v: boolean): void {
  muted = v;
  try {
    localStorage.setItem("ftdi.muted", v ? "1" : "0");
  } catch {
    /* приватный режим — не страшно */
  }
}

export function isMuted(): boolean {
  if (!ctx) {
    try {
      muted = localStorage.getItem("ftdi.muted") === "1";
    } catch {
      /* ignore */
    }
  }
  return muted;
}

function ensureCtx(): AudioContext | null {
  if (muted) return null;
  if (ctx) return ctx;
  const Ctor = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  ctx = new Ctor();
  return ctx;
}

function blip(freq: number, dur: number, gain: number, type: OscillatorType = "triangle"): void {
  const ac = ensureCtx();
  if (!ac) return;
  if (ac.state === "suspended") void ac.resume();
  const osc = ac.createOscillator();
  const g = ac.createGain();
  osc.type = type;
  osc.frequency.value = freq;
  const t0 = ac.currentTime;
  g.gain.setValueAtTime(0.0001, t0);
  g.gain.exponentialRampToValueAtTime(gain, t0 + 0.012);
  g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
  osc.connect(g).connect(ac.destination);
  osc.start(t0);
  osc.stop(t0 + dur + 0.02);
}

export const sound = {
  stepStart(): void {
    blip(620, 0.09, 0.05);
    setTimeout(() => blip(880, 0.1, 0.045), 70);
  },
  stepEnd(): void {
    blip(880, 0.09, 0.045);
    setTimeout(() => blip(560, 0.13, 0.05), 70);
  },
  error(): void {
    blip(180, 0.22, 0.06, "sawtooth");
  },
  click(): void {
    blip(1200, 0.03, 0.02, "square");
  },
};
