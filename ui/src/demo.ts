/** Демо-режим: реалистичная сессия без устройства и движка (`?demo=1`).
 *  Нужен для проверки интерфейса, обучения и скриншотов. */

import type { Event, SessionCounts, SessionMeta, StepSummary } from "./types";

const ID = "demo-20261109-120013-BMS46";

export function demoSession(): SessionMeta {
  return {
    id: ID,
    started_at: "2026-11-09T12:00:13.000Z",
    ended_at: null,
    label: "BMS46 Quickflash",
    tool_path: "D:\\BMW_Flashers\\BMS46 Quickflash\\BMS46 Quickflash.exe",
    tool_sha256: "4f1c9b7a0e2d63c5a8b1f0d9e7c4a2b6d8e0f1a3c5b7d9e2f4a6c8b0d2e4f6a1",
    tool_version: "1.0.3.0 | Bimmer Tuning Tools | 1.0.3",
    pid: 8421,
    process: "BMS46 Quickflash.exe",
    transport: "ftd2xx",
    adapter: { serial: "A1B2C3D4", description: "FT232R USB UART", com_port: 6, vendor_id: 1027, product_id: 24577 },
    host: "WORKSTATION",
    counts: { events: 1842, tx: 731, rx: 968, tx_bytes: 61820, rx_bytes: 63488, steps: 3, files: 2, errors: 0 },
    tags: ["BMS46", "запись"],
    notes: [{ t: 61, wall: "2026-11-09T12:01:14.000Z", text: "цикл питания после записи", author: "user" }],
    status: "recording",
    engine_version: "0.1.0",
    dir: "sessions/" + ID,
    facts: [
      "ftd2xx: C:\\Windows\\System32\\FTD2XX.DLL 1.4.12",
      "adapter: FT232R USB UART serial=A1B2C3D4",
      "hooks: 36 установлено",
    ],
  };
}

export function demoSteps(): StepSummary[] {
  return [
    {
      idx: 1,
      title: "нажал идентификаторы",
      dur: 12.4,
      exchanges: 248,
      tx_bytes: 22026,
      rx_bytes: 25523,
      cmd_hist: { "cmd=0x07": 223, "READ(0x06)": 12, "cmd=0x0D": 7, "cmd=0x90": 3 },
      resp_hist: { A0: 247, "unparsed(12 0a)": 1 },
      reads: [
        { start: 261472, len: 92, blocks: 2, sha256: "3bb12e4c51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f" },
        { start: 16358, len: 16, blocks: 1, sha256: "9f47eb7d5ca8480098c649bd9cba2e72106838b5ba960636df5204947d7dbb3e" },
      ],
      filehash: [],
      png: null,
      winkfp_jobs: [],
      verdict: { denied: 0, no_answer: 3, echo: true, unparsed: 1 },
      started_at: "2026-11-09T12:00:15.000Z",
      ended_at: "2026-11-09T12:00:27.400Z",
    },
    {
      idx: 2,
      title: "чтение калибровки",
      dur: 84.2,
      exchanges: 512,
      tx_bytes: 18432,
      rx_bytes: 16896,
      cmd_hist: { "READ(0x06)": 486, "cmd=0x0D": 24, "cmd=0x07": 2 },
      resp_hist: { A0: 510, "no-answer": 2 },
      reads: [
        { start: 32768, len: 32768, blocks: 342, sha256: "09a9e9de51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f" },
      ],
      filehash: [{ path: "D:\\tune_backup_1430940.bin", size: 65536, sha256: "9c1f2e7a3b4d5f6081a2b3c4d5e6f70819a2b3c4d5e6f708192a3b4c5d6e7f80" }],
      png: null,
      winkfp_jobs: [],
      verdict: { denied: 0, no_answer: 2, echo: true, unparsed: 0 },
      started_at: "2026-11-09T12:00:31.000Z",
      ended_at: "2026-11-09T12:01:55.200Z",
    },
    {
      idx: 3,
      title: "запись тюна",
      dur: 333.3,
      exchanges: 1204,
      tx_bytes: 61200,
      rx_bytes: 61800,
      cmd_hist: { "cmd=0x07": 1180, "READ(0x06)": 24 },
      resp_hist: { A0: 1201, "A2-denied": 2, "no-answer": 1 },
      reads: [
        { start: 32768, len: 65536, blocks: 342, sha256: "09a9e9de51c04e9c7f117094e423eb7beb1990eeccd0301a8da7bc289ae8b27f" },
        { start: 0, len: 65536, blocks: 128, sha256: "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899" },
      ],
      filehash: [{ path: "D:\\tune_v3.bin", size: 65536, sha256: "77aa88bb99cc00dd11ee22ff33aa44bb55cc66dd77ee88ff99aa00bb11cc22dd" }],
      png: demoShotDataUrl(3, "запись тюна"),
      winkfp_jobs: [],
      verdict: { denied: 2, no_answer: 1, echo: true, unparsed: 0 },
      started_at: "2026-11-09T12:02:10.000Z",
      ended_at: "2026-11-09T12:07:43.300Z",
    },
  ];
}

function hexOf(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

function seqBytes(seed: number, n: number): number[] {
  const out: number[] = [];
  let x = seed;
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out.push(x & 0xff);
  }
  return out;
}

export function demoEvents(): Event[] {
  const out: Event[] = [];
  let seq = 0;
  const push = (ev: Partial<Event> & Pick<Event, "kind" | "t" | "api">): void => {
    out.push({
      seq: seq++,
      t: ev.t,
      wall: new Date(Date.parse("2026-11-09T12:00:13.000Z") + ev.t * 1000).toISOString(),
      kind: ev.kind,
      transport: ev.transport ?? (ev.api.startsWith("FT_") ? "ftd2xx" : "vcp"),
      api: ev.api,
      direction: ev.direction ?? null,
      len: ev.len ?? 0,
      hex: ev.hex ?? "",
      text: ev.text ?? null,
      rc: ev.rc ?? null,
      step: ev.step ?? null,
      raw: ev.raw ?? "",
      meta: ev.meta ?? null,
    });
  };

  push({ kind: "sys", t: 0.004, api: "SYS", text: "capture start: label=BMS46 Quickflash transport=ftd2xx" });
  push({ kind: "sys", t: 0.006, api: "SYS", text: "exe: sha256=4f1c9b7a… size=2846720 version=1.0.3" });
  push({ kind: "sys", t: 0.011, api: "SYS", text: "ftd2xx.dll hooks installed (36) at 0x7ffb2c1e0000" });
  push({ kind: "module", t: 0.014, api: "MODULE", text: "MODULE + ftd2xx.dll  C:\\Windows\\System32\\FTD2XX.DLL base=0x7ffb2c1e0000" });
  push({ kind: "sys", t: 0.42, api: "FT_CreateDeviceInfoList", rc: 0, text: "rc=0 devices=1" });
  push({
    kind: "sys",
    t: 0.44,
    api: "FT_GetDeviceInfoDetail",
    rc: 0,
    text: 'idx=0 serial="A1B2C3D4" desc="FT232R USB UART"',
  });
  push({ kind: "sys", t: 0.51, api: "FT_Open", rc: 0, text: "FT_Open(idx=0) rc=0 handle=0x1" });
  push({ kind: "sys", t: 0.52, api: "FT_SetBaudRate", rc: 0, text: "FT_SetBaudRate(handle=0x1, 9600) rc=0" });

  // Шаг 1: идентификация
  push({ kind: "step_start", t: 1.9, api: "STEP", text: "нажал идентификаторы", step: 1 });
  push({ kind: "tx", t: 2.05, api: "FT_Write", direction: "tx", hex: "12 04 0d 1b", len: 4, rc: 0, step: 1, text: "echo-check" });
  push({
    kind: "rx",
    t: 2.11,
    api: "FT_Read",
    direction: "rx",
    hex: "12 4c a0 01 45 9a ff ff ff ff ff ff ff ff ff ff ff ff ff ff",
    len: 72,
    rc: 0,
    step: 1,
  });
  for (let i = 0; i < 26; i++) {
    const addr = 0x3fd60 + (i % 4) * 46;
    const req = [0x12, 0x09, 0x06, 0x00, 0x03, addr >> 8, addr & 0xff, 0x00, 0x00];
    push({ kind: "tx", t: 2.3 + i * 0.17, api: "FT_Write", direction: "tx", hex: hexOf(req), len: req.length, rc: 0, step: 1 });
    const payload = seqBytes(0x1234 + i, 46);
    push({
      kind: "rx",
      t: 2.31 + i * 0.17,
      api: "FT_Read",
      direction: "rx",
      hex: hexOf([0x12, 0x32, 0xa0, ...payload]),
      len: 49,
      rc: 0,
      step: 1,
    });
  }
  push({ kind: "tx", t: 9.4, api: "FT_Write", direction: "tx", hex: "12 04 90 42 4d 57 04 d6", len: 8, rc: 0, step: 1, text: "auth 90 42 4d 57" });
  push({ kind: "rx", t: 9.45, api: "FT_Read", direction: "rx", hex: "12 04 a0 01", len: 4, rc: 0, step: 1 });
  push({ kind: "step_end", t: 14.3, api: "STEP", text: "нажал идентификаторы · 12.4 с · TX 26 / 22 026 B · RX 25 523 B", step: 1 });

  // Шаг 2: чтение калибровки
  push({ kind: "step_start", t: 18.0, api: "STEP", text: "чтение калибровки", step: 2 });
  for (let i = 0; i < 120; i++) {
    const addr = 0x8000 + i * 0x40;
    const len = 0x40;
    const req = [0x12, 0x09, 0x06, 0x00, 0x03, (addr >> 8) & 0xff, addr & 0xff, len & 0xff, 0x00];
    push({ kind: "tx", t: 18.2 + i * 0.68, api: "FT_Write", direction: "tx", hex: hexOf(req), len: req.length, rc: 0, step: 2 });
    push({
      kind: "rx",
      t: 18.22 + i * 0.68,
      api: "FT_Read",
      direction: "rx",
      hex: hexOf([0x12, 0x32, 0xa0, ...seqBytes(addr, 16)]),
      len: 19,
      rc: 0,
      step: 2,
    });
    if (i % 40 === 39) {
      push({
        kind: "sys",
        t: 18.4 + i * 0.68,
        api: "READ",
        text: `чтение 0x${addr.toString(16).toUpperCase().padStart(6, "0")} блоками собрано в reads/`,
        step: 2,
      });
    }
  }
  push({
    kind: "file",
    t: 74.2,
    api: "FILE",
    text: "open D:\\tune_backup_1430940.bin access=0x40000000",
    step: 2,
    transport: "file",
  });
  push({
    kind: "file_hash",
    t: 75.0,
    api: "FILE",
    text: "hash D:\\tune_backup_1430940.bin size=65536 sha256=9c1f2e7a…",
    step: 2,
    transport: "file",
  });
  push({ kind: "step_end", t: 102.2, api: "STEP", text: "чтение калибровки · 84.2 с · TX 512 / 18 432 B", step: 2 });

  // Шаг 3: запись
  push({ kind: "step_start", t: 108.0, api: "STEP", text: "запись тюна", step: 3 });
  push({ kind: "tx", t: 108.2, api: "FT_Write", direction: "tx", hex: "12 04 10 85 00 00 87", len: 7, rc: 0, step: 3, text: "StartDiagnosticSession programming" });
  push({ kind: "rx", t: 108.26, api: "FT_Read", direction: "rx", hex: "12 04 50 85 00 00 c3", len: 7, rc: 0, step: 3, text: "pos(10)" });
  for (let i = 0; i < 260; i++) {
    const addr = i * 0x100;
    const payload = seqBytes(0x9000 + i, 24);
    const req = [0x12, 0x09, 0x07, 0x00, 0x03, (addr >> 8) & 0xff, addr & 0xff, ...payload];
    push({ kind: "tx", t: 109.0 + i * 1.15, api: "FT_Write", direction: "tx", hex: hexOf(req), len: req.length, rc: 0, step: 3 });
    push({
      kind: "rx",
      t: 109.02 + i * 1.15,
      api: "FT_Read",
      direction: "rx",
      hex: hexOf([0x12, 0x04, 0xa0, 0x01]),
      len: 4,
      rc: 0,
      step: 3,
    });
    if (i === 130) {
      push({ kind: "note", t: 109.0 + i * 1.15, api: "NOTE", text: "цикл питания после записи", step: 3 });
    }
  }
  push({ kind: "step_end", t: 441.3, api: "STEP", text: "запись тюна · 333.3 с · TX 1204 / 61 200 B · скриншот", step: 3 });
  return out;
}

export function demoCounts(): SessionCounts {
  return {
    events: demoEvents().length,
    tx: 731,
    rx: 968,
    tx_bytes: 61820,
    rx_bytes: 63488,
    steps: 3,
    files: 2,
    errors: 0,
  };
}

export function demoShotDataUrl(step: number, title: string): string {
  const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="600" viewBox="0 0 960 600">
  <rect width="960" height="600" fill="#0e1319"/>
  <rect x="0" y="0" width="960" height="34" fill="#121922"/>
  <text x="14" y="22" font-family="Consolas,monospace" font-size="13" fill="#8a97a6">BMS46 Quickflash 1.0.3</text>
  <rect x="862" y="8" width="18" height="18" fill="#1d2731"/><rect x="886" y="8" width="18" height="18" fill="#1d2731"/><rect x="910" y="8" width="18" height="18" fill="#1d2731"/>
  <text x="28" y="82" font-family="Consolas,monospace" font-size="12" fill="#5f6c7a">ECU-BEREICH</text>
  <rect x="28" y="96" width="904" height="1" fill="#1d2731"/>
  <text x="28" y="132" font-family="Consolas,monospace" font-size="16" fill="#d9e2ec">BMW ${esc(title)}</text>
  <text x="28" y="160" font-family="Consolas,monospace" font-size="12" fill="#7ee787">reading calibration ... 32768 / 65536</text>
  <rect x="28" y="176" width="904" height="10" fill="#17202a"/>
  <rect x="28" y="176" width="470" height="10" fill="#35d0ff"/>
  <text x="28" y="214" font-family="Consolas,monospace" font-size="12" fill="#93a1b0">${esc("ID_BMW_NR=1430940  ID_SW_NR=F0  status=OK")}</text>
  <rect x="28" y="232" width="450" height="2" fill="#1d2731"/>
  <text x="28" y="268" font-family="Consolas,monospace" font-size="12" fill="#b48cff">D:\\tune_v3.bin  -  65536 bytes</text>
  <text x="28" y="296" font-family="Consolas,monospace" font-size="12" fill="#93a1b0">step ${step}: ${esc(title)}</text>
  <rect x="28" y="316" width="904" height="252" fill="#0a0d11" stroke="#1d2731"/>
  <g font-family="Consolas,monospace" font-size="11" fill="#5f6c7a">
    <text x="44" y="342">[+109.000s] TX FT_Write len=32 : 12 09 07 00 03 00 00 9a ff 00 1c 08 10 62 00 72</text>
    <text x="44" y="362">[+109.020s] RX FT_Read  len=4  : 12 04 a0 01</text>
    <text x="44" y="382">[+110.150s] TX FT_Write len=32 : 12 09 07 00 03 01 00 9b 1c b0 00 61 00 74 00 24</text>
    <text x="44" y="402">[+110.170s] RX FT_Read  len=4  : 12 04 a0 01</text>
    <text x="44" y="422">[+111.300s] TX FT_Write len=32 : 12 09 07 00 03 02 00 9b 02 00 00 20 00 5b 00 00</text>
    <text x="44" y="442" fill="#7ee787">[+111.318s] RX FT_Read  len=4  : 12 04 a0 01</text>
  </g>
  <text x="28" y="590" font-family="Consolas,monospace" font-size="11" fill="#5f6c7a">F2: step  F6: hooks  Esc: stop   |   FTDI/USB Logger</text>
</svg>`;
  return "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svg)));
}
