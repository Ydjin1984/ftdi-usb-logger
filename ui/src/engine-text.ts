/**
 * Локализация строк журнала, которые пишет движок и sidecar.
 *
 * Это не подписи интерфейса (их переводит i18n.ts по ключам), а текст событий:
 * sidecar/движок складывает его в events.jsonl как данные, поэтому в английском
 * интерфейсе такие строки раньше оставались русскими. Правила применяются при
 * показе, так что старые сессии тоже читаются на английском, а сами записи
 * журнала не переписываются.
 *
 * Технические строки движка изначально английские и в русском интерфейсе
 * остаются английскими — это журнал обмена, а не подписи.
 */
import { getLang } from "./i18n";

/** Русская строка журнала → английская. */
const RU_TO_EN: Array<[RegExp, string]> = [
  [
    /LAN: закрыто (\d+) сокетов без обмена \(проба\/резолвер\) — построчно не пишем/,
    "LAN: $1 sockets closed without exchange (probe/resolver) — not logged line by line",
  ],
  [
    /universal: сторож загрузки DLL активен \((\d+) хуков\) — перезагрузка адаптерных DLL не теряется/,
    "universal: DLL-load watchdog armed ($1 hooks) — adapter DLL reloads are not lost",
  ],
  [
    /universal: module observer НЕДОСТУПЕН \(Frida без attachModuleObserver\) — только уже загруженные модули/,
    "universal: module observer UNAVAILABLE (Frida without attachModuleObserver) — already loaded modules only",
  ],
  [
    /~ (.+) выгружена\/перезагружена — снято хуков (\d+), флагов (\d+); перевесим при загрузке/,
    "~ $1 unloaded/reloaded — removed $2 hooks, $3 flags; will re-hook on load",
  ],
  [
    /hookctl: ПАУЗА — снято хуков (\d+) \(байтовый поток и файлы не пишутся\); resume — вернуть/,
    "hookctl: PAUSED — removed $1 hooks (byte stream and files are not written); resume to restore",
  ],
  [/hookctl: возобновление — хуки поставлены заново/, "hookctl: resumed — hooks have been installed again"],
  [/hookctl: ftd2xx загружен, но хуки на паузе — пропускаю/, "hookctl: ftd2xx loaded, but hooks are paused — skipping"],
  [/ovl: FIFO fallback handle=(.+?) key=(.+) \(hEvent не совпал\)/, "ovl: FIFO fallback handle=$1 key=$2 (hEvent did not match)"],
];

/** Перевести текст события под текущий язык интерфейса. */
export function localizeEventText(text: string): string {
  if (!text || getLang() !== "en") return text;
  let out = text;
  for (const [re, repl] of RU_TO_EN) {
    if (re.test(out)) out = out.replace(re, repl);
  }
  return out;
}
