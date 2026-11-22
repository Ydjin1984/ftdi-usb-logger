/**
 * Восьмиканальный осциллограф: состояние, подписи и элементы шапки.
 *
 * Сервис живёт отдельно от движка (по умолчанию `http://127.0.0.1:7411`), движок
 * только опрашивает его и складывает события `scope`/`ui_action` в поток сессии.
 * Здесь — чистые функции представления (пилюля, каналы, адрес) и сборка пары
 * «кнопка + пилюля» для верхней панели; сетевые вызовы — в store/api, диалог —
 * в dialogs.ts (там уже есть modal/field/checkRow).
 *
 * Подписи — локальным словарём: общие строки (закрыть/сохранить) берутся из i18n.ts.
 */

import { el, icon } from "./dom";
import { msg, t } from "./i18n";
import { store } from "./store";
import type { ScopeChannel, ScopeState, ScopeStatus } from "./types";

msg({
  "Осциллограф": "Oscilloscope",
  "осциллограф": "oscilloscope",
  "осциллограф выкл": "oscilloscope off",
  "подключение…": "connecting…",
  "осциллограф: {channels}": "oscilloscope: {channels}",
  "осциллограф: запись": "oscilloscope: recording",
  "осциллограф: готов": "oscilloscope: ready",
  "осциллограф: нет связи": "oscilloscope: no link",
  "осциллограф: остановлен": "oscilloscope: stopped",
  "осциллограф: настройки и состояние": "oscilloscope: settings and status",
  "ни один канал не включён": "no channel is enabled",

  /* Состояния — общие подписи для пилюли, настроек и диалога. */
  "выключен в настройках": "disabled in settings",
  "подключение": "connecting",
  "запись": "recording",
  "готов": "ready",
  "нет связи": "no link",
  "остановлен": "stopped",
  "неизвестно": "unknown",

  /* Подсказка пилюли: кадры, пропуски, байты, частота. */
  "состояние: {state}": "state: {state}",
  "кадров: {n}": "frames: {n}",
  "пропусков: {n}": "gaps: {n}",
  "байт: {n}": "bytes: {n}",
  "частота: {rate}": "rate: {rate}",
  "сессия: {id}": "session: {id}",
  "ошибка: {msg}": "error: {msg}",
  "деградация: часть кадров не записана": "degraded: some frames were not stored",

  /* Каналы. */
  "включён": "on",
  "выключен": "off",
  "мин": "min",
  "макс": "max",
  "алиас": "alias",
  "шкала {v}": "full scale {v}",
  "частота {v}": "freq {v}",
  "скважность {v}": "duty {v}",
  "канал включает сервис осциллографа — здесь только состояние":
    "the channel is enabled by the oscilloscope service — this is state only",
  "частота выше предела Найквиста: значение нельзя трактовать":
    "the frequency is above the Nyquist limit: the value cannot be interpreted",
  "запись · {channels} · кадров {n}": "recording · {channels} · frames {n}",
  "{state} · кадров {n}": "{state} · frames {n}",
});

/** Адрес сервиса по умолчанию — как в контракте движка. */
export const SCOPE_DEFAULT_URL = "http://127.0.0.1:7411";

/** Тон пилюли повторяет общие классы `.pill--*`. */
export type ScopePillTone = "ok" | "warn" | "err" | "";

export interface ScopePillModel {
  /** Текст пилюли целиком: «осциллограф: CH1,CH2,CH3». */
  text: string;
  tone: ScopePillTone;
  /** Подсказка: кадры, пропуски, байты, частота и причина отказа. */
  title: string;
}

/** Состояние словами — для настроек и диалога. */
export function scopeStateLabel(state: ScopeState | null | undefined): string {
  switch (state) {
    case "off":
      return t("выключен в настройках");
    case "connecting":
      return t("подключение");
    case "recording":
      return t("запись");
    case "idle":
      return t("готов");
    case "no_link":
      return t("нет связи");
    case "stopped":
      return t("остановлен");
    default:
      return t("неизвестно");
  }
}

/** Идёт ли сессия: изменения настроек применятся только со следующей. */
export function scopeSessionActive(status: ScopeStatus | null | undefined): boolean {
  return status?.state === "recording" || status?.state === "connecting";
}

/**
 * Включённые каналы одной строкой.
 *
 * До четырёх — перечисляем все (`CH1,CH2,CH3`), больше — первые три и «+N»:
 * `CH1–CH3 +2` для подряд идущих, иначе `CH1,CH2,CH5 +3` (диапазон не врёт).
 */
export function scopeChannelsLabel(channels: ScopeChannel[] | null | undefined): string {
  const nums = (channels ?? [])
    .filter((c) => c.enabled)
    .map((c) => c.ch)
    .sort((a, b) => a - b);
  if (!nums.length) return "";
  if (nums.length <= 4) return nums.map((n) => `CH${n}`).join(",");
  const [a, b, c] = nums;
  const head = c === b + 1 && b === a + 1 ? `CH${a}–CH${c}` : `CH${a},CH${b},CH${c}`;
  return `${head} +${nums.length - 3}`;
}

/** Частота в удобных единицах; хвостовые нули не показываем. */
export function fmtHz(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v) || v <= 0) return "—";
  if (v >= 1e6) return `${trimZeros((v / 1e6).toFixed(3))} MHz`;
  if (v >= 1e3) return `${trimZeros((v / 1e3).toFixed(3))} kHz`;
  return `${trimZeros(v.toFixed(3))} Hz`;
}

/** Напряжение в вольтах с тремя знаками: милливольты не теряются. */
export function fmtVolts(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v)) return "—";
  return `${trimZeros(v.toFixed(3))} V`;
}

/** Скважность в процентах. */
export function fmtDuty(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v)) return "—";
  return `${trimZeros(v.toFixed(1))} %`;
}

function trimZeros(s: string): string {
  return s.includes(".") ? s.replace(/0+$/, "").replace(/\.$/, "") : s;
}

/** Частота дискретизации сервиса — в подсказке пилюли и в диалоге. */
export function fmtSampleRate(v: number | null | undefined): string {
  if (v == null || !Number.isFinite(v) || v <= 0) return "—";
  if (v >= 1e6) return `${trimZeros((v / 1e6).toFixed(3))} MHz`;
  if (v >= 1e3) return `${trimZeros((v / 1e3).toFixed(3))} kHz`;
  return `${trimZeros(v.toFixed(0))} Hz`;
}

/**
 * Пилюля осциллографа в шапке.
 *
 * `null` — пилюлю не рисовать: движок старой версии (404) или состояние ещё не
 * прочитано. Так старая сборка не показывает ложное «выкл».
 */
export function scopePillModel(
  status: ScopeStatus | null | undefined,
  supported: boolean | null,
): ScopePillModel | null {
  if (supported === false || !status) return null;
  const channels = scopeChannelsLabel(status.channels);

  let text: string;
  let tone: ScopePillTone;
  switch (status.state) {
    case "off":
      text = t("осциллограф выкл");
      tone = "";
      break;
    case "connecting":
      text = t("подключение…");
      tone = "warn";
      break;
    case "recording":
      text = channels ? t("осциллограф: {channels}", { channels }) : t("осциллограф: запись");
      tone = "ok";
      break;
    case "idle":
      text = t("осциллограф: готов");
      tone = "";
      break;
    case "no_link":
      text = t("осциллограф: нет связи");
      tone = "err";
      break;
    case "stopped":
      text = t("осциллограф: остановлен");
      tone = "";
      break;
    default:
      text = t("осциллограф: остановлен");
      tone = "";
  }

  const lines = [
    t("состояние: {state}", { state: scopeStateLabel(status.state) }),
    t("кадров: {n}", { n: status.frames ?? 0 }),
    t("пропусков: {n}", { n: status.gaps ?? 0 }),
    t("байт: {n}", { n: status.bytes ?? 0 }),
    t("частота: {rate}", { rate: fmtSampleRate(status.sample_rate) }),
  ];
  if (channels) lines.push(channels);
  if (status.session) lines.push(t("сессия: {id}", { id: status.session }));
  if (status.degraded) lines.push(t("деградация: часть кадров не записана"));
  if (status.last_error) lines.push(t("ошибка: {msg}", { msg: status.last_error }));

  return { text, tone, title: lines.join("\n") };
}

/** Короткая строка для секции настроек: состояние + каналы + кадры. */
export function scopeSettingsLine(status: ScopeStatus | null | undefined): string {
  if (!status) return t("нет данных");
  const channels = scopeChannelsLabel(status.channels);
  if (status.state === "recording") {
    return t("запись · {channels} · кадров {n}", {
      channels: channels || t("ни один канал не включён"),
      n: status.frames ?? 0,
    });
  }
  return t("{state} · кадров {n}", { state: scopeStateLabel(status.state), n: status.frames ?? 0 });
}

/**
 * Проверить и нормализовать адрес сервиса.
 *
 * Принимаем только http(s)://host[:port][/path] без логина и пробелов: адрес
 * уходит в `window.open` и в движок, поэтому «http://» обязателен, а хвостовой
 * слэш убираем — иначе один и тот же адрес выглядел бы двумя разными.
 */
export function normalizeScopeUrl(raw: string): string | null {
  const value = raw.trim();
  if (!value || /\s/.test(value)) return null;
  if (!/^https?:\/\//i.test(value)) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (!url.hostname) return null;
  if (url.username || url.password) return null;
  if (url.port) {
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  }
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return `${url.protocol}//${url.host}${path}`;
}

/** Одна строка списка каналов: галочка, диапазон, шкала, Vpp/min/max, частота. */
export function buildScopeChannelRow(channel: ScopeChannel | null, index: number): HTMLElement {
  const ch = channel?.ch ?? index;
  const off = !!channel && !channel.enabled;
  const row = el("div", `scope-ch${off ? " is-off" : ""}`);
  row.dataset.ch = String(ch);

  const head = el("label", "scope-ch__head");
  const box = el("input") as HTMLInputElement;
  box.type = "checkbox";
  box.checked = !!channel?.enabled;
  // Каналы включаются в самом сервисе осциллографа: здесь только состояние,
  // иначе клик по галочке обещал бы действие, которого нет.
  box.disabled = true;
  box.setAttribute("aria-label", `${t("включён")} CH${ch}`);
  box.title = t("канал включает сервис осциллографа — здесь только состояние");
  head.append(box, el("span", "scope-ch__name", `CH${ch}`));
  if (channel?.enabled && channel.range) {
    head.append(el("span", "scope-ch__range", channel.range));
  }
  if (channel?.aliased) {
    const tag = el("span", "scope-ch__alias", t("алиас"));
    tag.title = t("частота выше предела Найквиста: значение нельзя трактовать");
    head.append(tag);
  }
  row.append(head);

  const stats = el("div", "scope-ch__stats");
  if (!channel) {
    stats.textContent = t("нет данных");
  } else if (!channel.enabled) {
    stats.textContent = t("выключен");
  } else {
    stats.append(
      el("span", "", t("шкала {v}", { v: fmtVolts(channel.full_scale_v) })),
      el("span", "", `Vpp ${fmtVolts(channel.pp)}`),
      el("span", "", `${t("мин")} ${fmtVolts(channel.min)}`),
      el("span", "", `${t("макс")} ${fmtVolts(channel.max)}`),
    );
    if (channel.freq != null) stats.append(el("span", "", t("частота {v}", { v: fmtHz(channel.freq) })));
    if (channel.duty != null) stats.append(el("span", "", t("скважность {v}", { v: fmtDuty(channel.duty) })));
  }
  row.append(stats);
  return row;
}

/** Список CH1…CH8: всегда восемь строк, отсутствующие каналы — «нет данных». */
export function buildScopeChannels(channels: ScopeChannel[] | null | undefined): HTMLElement {
  const byCh = new Map<number, ScopeChannel>();
  for (const channel of channels ?? []) byCh.set(channel.ch, channel);
  const box = el("div", "scope-channels");
  for (let ch = 1; ch <= 8; ch++) box.append(buildScopeChannelRow(byCh.get(ch) ?? null, ch));
  return box;
}

/**
 * Пара элементов шапки: кнопка «Осциллограф» и (если есть состояние) пилюля.
 *
 * Пилюля — `<button>`: клик по ней тоже открывает диалог, как и по кнопке.
 * При 404 от движка пилюля не рисуется совсем — кнопка остаётся, чтобы диалог
 * объяснил, что движок старый (требование «не падать»).
 */
export function buildScopeControls(onOpen: () => void): HTMLElement[] {
  const btn = el("button", "btn btn--sm scope-btn");
  btn.type = "button";
  btn.id = "scope-btn";
  btn.dataset.testid = "scope-btn";
  btn.title = t("осциллограф: настройки и состояние");
  btn.append(icon("chip"), el("span", "", t("Осциллограф")));
  btn.addEventListener("click", onOpen);

  const nodes: HTMLElement[] = [btn];
  const model = scopePillModel(store.state.scope, store.state.scopeSupported);
  if (!model) return nodes;

  const pill = el("button", `pill scope-pill ${model.tone ? `pill--${model.tone}` : ""}`.trim());
  pill.type = "button";
  pill.id = "scope-pill";
  pill.dataset.testid = "scope-pill";
  pill.title = model.title;
  pill.setAttribute("aria-label", `${t("Осциллограф")}: ${model.text}`);
  const value = el("b", "", model.text);
  value.title = model.title;
  pill.append(el("span", "pill__dot"), value);
  pill.addEventListener("click", onOpen);
  nodes.push(pill);
  return nodes;
}
