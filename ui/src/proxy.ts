/**
 * Полоса J2534-прокси в карточке и инспекторе сессии (docs/13-j2534-proxy.md §8–§9).
 *
 * Сверка полос — мультимножество кадров `(dir, hex)`: `*_matched` — кадр полосы frida
 * нашёлся в журнале прокси, `*_missing` — есть в frida, но не в прокси (потеря второго
 * канала), `extra` — есть в прокси, но не в frida (потеря первого канала).
 */

import { fmtNum } from "./format";
import { msg, t } from "./i18n";
import type { ProxyLane } from "./types";

msg({
  // Подпись бейджа полосы — языконезависимая, записана явно, чтобы словарь был полным.
  "proxy": "proxy",
  "Прокси: TX {tx} / RX {rx}, сверка: совпало {matched}, потеряно {missing}":
    "Proxy: TX {tx} / RX {rx}, cross-check: {matched} matched, {missing} missing",
  "расхождение каналов: не сверилось {missing} из {total} кадров":
    "channel mismatch: {missing} of {total} frames did not match",
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
