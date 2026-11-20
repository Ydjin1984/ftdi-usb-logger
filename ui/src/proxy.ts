/**
 * Полоса J2534-прокси в карточке и инспекторе сессии (docs/13-j2534-proxy.md §8–§9).
 *
 * Сверка полос — мультимножество кадров `(dir, hex)`: `*_matched` — кадр полосы frida
 * нашёлся в журнале прокси, `*_missing` — есть в frida, но не в прокси (потеря второго
 * канала), `extra` — есть в прокси, но не в frida (потеря первого канала).
 */

import { fmtNum } from "./format";
import { msg, t } from "./i18n";
import type { ProxyDevice, ProxyLane, ProxyLive, ProxyLiveItem, SessionCounts } from "./types";

msg({
  // Подпись бейджа полосы — языконезависимая, записана явно, чтобы словарь был полным.
  "proxy": "proxy",
  "Прокси: TX {tx} / RX {rx}, сверка: совпало {matched}, потеряно {missing}":
    "Proxy: TX {tx} / RX {rx}, cross-check: {matched} matched, {missing} missing",
  "расхождение каналов: не сверилось {missing} из {total} кадров":
    "channel mismatch: {missing} of {total} frames did not match",

  /* Живое состояние (docs/13 §6.1): ответ на вопрос «подхватился или нет». */
  "прокси подхвачен": "proxy is picked up",
  "прокси был подхвачен": "proxy was picked up",
  "прокси не подхвачен": "proxy is not picked up",
  "подхвачен: {exe}": "picked up: {exe}",
  "был подхвачен: {exe}": "was picked up: {exe}",
  "не подхвачен": "not picked up",
  "{calls} вызовов": "{calls} calls",
  "обмен {sec} с назад": "last exchange {sec} s ago",
  "ошибок {n}": "{n} errors",
  "драйвер: {path}": "driver: {path}",
  "прокси включён, но ни одна программа его не загрузила":
    "the proxy is enabled but no program has loaded it",
  "выберите «шнурок», в который прокси будет форвардить вызовы":
    "pick the cable the proxy forwards calls to",
  "файла нет": "no file",
  "прокси": "proxy",
  "драйвер": "driver",
  "слои J2534: {layers}": "J2534 layers: {layers}",
  "внутри {n} записей, не в счётчиках": "{n} inner records, not counted",
  "возможен двойной учёт (старый агент)": "possible double counting (old agent)",
  "вызовы J2534 не захвачены": "J2534 calls were not captured",
  "внешний вызов идёт в счётчики, внутренний (прокси → драйвер) остаётся в деталях":
    "the outer call is counted, the inner one (proxy → driver) stays in the details",
});

/**
 * Порог предупреждения: доля несовпавших кадров, после которой полоса считается
 * подозрительной (§9: «при расхождении — предупреждение»). 5% от полосы.
 */
export const PROXY_MISS_WARN = 0.05;

/** Сколько кадров полосы frida нашлось в журнале прокси. */
export function proxyMatched(lane: ProxyLane): number {
  return (lane.cross?.tx_matched ?? 0) + (lane.cross?.rx_matched ?? 0);
}

/** Сколько кадров полосы frida потерялось (нет в журнале прокси). */
export function proxyMissing(lane: ProxyLane): number {
  return (lane.cross?.tx_missing ?? 0) + (lane.cross?.rx_missing ?? 0);
}

/** Доля потерянных кадров от всей сверенной полосы (0..1); пустая сверка — 0. */
export function proxyMissRatio(lane: ProxyLane): number {
  const matched = proxyMatched(lane);
  const missing = proxyMissing(lane);
  const total = matched + missing;
  return total > 0 ? missing / total : 0;
}

/** Пора ли показывать предупреждение о расхождении каналов. */
export function proxyNeedsAttention(lane: ProxyLane): boolean {
  return proxyMissRatio(lane) > PROXY_MISS_WARN;
}

/** Строка для карточки сессии: «Прокси: TX n / RX m, сверка: совпало X, потеряно Y». */
export function proxyLine(lane: ProxyLane): string {
  return t("Прокси: TX {tx} / RX {rx}, сверка: совпало {matched}, потеряно {missing}", {
    tx: fmtNum(lane.tx ?? 0),
    rx: fmtNum(lane.rx ?? 0),
    matched: fmtNum(proxyMatched(lane)),
    missing: fmtNum(proxyMissing(lane)),
  });
}

/** Всплывающая подсказка строки: проценты расхождения и хвост заметок движка. */
export function proxyLineTitle(lane: ProxyLane): string {
  const matched = proxyMatched(lane);
  const missing = proxyMissing(lane);
  const parts = [
    t("расхождение каналов: не сверилось {missing} из {total} кадров", {
      missing: fmtNum(missing),
      total: fmtNum(matched + missing),
    }),
  ];
  if (lane.cross?.extra) parts.push(`extra: ${fmtNum(lane.cross.extra)}`);
  if (lane.notes?.length) parts.push(...lane.notes);
  return parts.join("\n");
}

/** Бейдж полосы для карточки/инспектора. */
export function proxyBadge(): string {
  return t("proxy");
}

/* ───────────────────────── живое состояние прокси ───────────────────────── */

/**
 * Прокси, который работает прямо сейчас.
 *
 * `alive` выставляет движок: файл состояния `live` + процесс с этим pid жив и
 * это тот же exe (docs/13 §6.1). Один только файл ничего не доказывает — он
 * остаётся после выхода программы.
 */
export function proxyLiveActive(live: ProxyLive | null | undefined): ProxyLiveItem | null {
  return live?.items?.find((item) => item.alive) ?? null;
}

/** Тон индикатора: `ok` — подхвачен, `warn` — ждёт программу, `err` — драйвер не открылся. */
export function proxyLiveTone(live: ProxyLive | null | undefined): "ok" | "warn" | "err" | "" {
  const item = proxyLiveActive(live);
  if (item) return item.fatal ? "err" : "ok";
  if (live?.state === "recent") return "";
  return live?.state === "idle" ? "warn" : "";
}

/** Короткая строка для шапки: «подхвачен: PCMflash.exe» / «не подхвачен». */
export function proxyLiveShort(live: ProxyLive | null | undefined): string {
  const item = proxyLiveActive(live);
  if (item) {
    return t("подхвачен: {exe}", { exe: item.exe_name || `PID ${item.pid}` });
  }
  if (live?.state === "recent") {
    const last = live.items?.[0];
    return t("был подхвачен: {exe}", { exe: last?.exe_name || "—" });
  }
  return t("не подхвачен");
}

/** Подробная строка под индикатором: счётчики и свежесть последнего обмена. */
export function proxyLiveDetail(live: ProxyLive | null | undefined): string {
  const item = proxyLiveActive(live);
  if (!item) return "";
  const parts = [
    t("{calls} вызовов", { calls: fmtNum(item.calls) }),
    `TX ${fmtNum(item.tx)} / RX ${fmtNum(item.rx)}`,
    t("обмен {sec} с назад", { sec: fmtNum(item.age_s) }),
  ];
  if (item.errors) parts.push(t("ошибок {n}", { n: fmtNum(item.errors) }));
  return parts.join(" · ");
}

/** Подсказка: всё, что нужно, чтобы не открывать журналы руками. */
export function proxyLiveTitle(live: ProxyLive | null | undefined): string {
  const item = proxyLiveActive(live);
  const lines = [
    item
      ? t("прокси подхвачен")
      : live?.state === "recent"
        ? t("прокси был подхвачен")
        : t("прокси не подхвачен"),
  ];
  if (item) {
    lines.push(`PID ${item.pid} · ${item.exe}`);
    if (item.real) lines.push(t("драйвер: {path}", { path: item.real }));
    if (item.version) lines.push(`DLL ${item.version} · ${item.bits} бит`);
    if (item.log) lines.push(item.log);
    if (item.started) lines.push(`${item.started}`);
  }
  for (const note of live?.notes ?? []) lines.push(note);
  return lines.join("\n");
}

/** Подпись варианта в выборе «какой шнурок проксировать». */
export function proxyDeviceLabel(device: ProxyDevice): string {
  const name = device.name || device.dll || "—";
  const file = device.dll.split(/[\\/]/).pop() || device.dll;
  const parts = [name];
  if (file) parts.push(file);
  if (!device.present) parts.push(t("файла нет"));
  return parts.join(" · ");
}

/* ────────────────── слои J2534 в карточке сессии ────────────────── */

/**
 * Строка «слои J2534» для карточки/инспектора сессии (docs/13 §6.2).
 *
 * Показывает, что обмен шёл через прокси и драйвер, сколько записей отнесено
 * к внутреннему слою (они не в счётчиках) и — для старых сессий без связи
 * вызовов — что сводка может быть удвоена. `null`, если сказать нечего.
 */
export function j2534LayersLine(
  counts: SessionCounts | null | undefined,
): { text: string; title: string; warn: boolean } | null {
  if (!counts) return null;
  const layers = counts.j2534_layers ?? [];
  const modules = counts.j2534_modules ?? [];
  const inner = counts.inner_events ?? 0;
  if (!layers.length && !modules.length && !inner) return null;

  const names = layers.length
    ? layers
        .map((layer) =>
          layer === "proxy" ? t("прокси") : layer === "driver" ? t("драйвер") : layer,
        )
        .join(" + ")
    : modules.join(" + ");
  const parts = [t("слои J2534: {layers}", { layers: names })];
  let warn = false;
  if (inner) {
    parts.push(t("внутри {n} записей, не в счётчиках", { n: fmtNum(inner) }));
  } else if (layers.length > 1 || modules.length > 1) {
    warn = true;
    parts.push(t("возможен двойной учёт (старый агент)"));
  }
  if ((counts.tx ?? 0) === 0 && modules.length) {
    warn = true;
    parts.push(t("вызовы J2534 не захвачены"));
  }
  return {
    text: parts.join(" · "),
    title: [
      t("слои J2534: {layers}", { layers: names }),
      ...(modules.length ? [modules.join(", ")] : []),
      t(
        "внешний вызов идёт в счётчики, внутренний (прокси → драйвер) остаётся в деталях",
      ),
    ].join("\n"),
    warn,
  };
}
