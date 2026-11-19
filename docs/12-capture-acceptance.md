# Приёмка захвата J2534 — v0.3.5

Отчёт по двум разборам: `docs/09-capture-changes-spec.md` §10 и ревизия кода
v0.3.3 (P0/P1 в `universal_capture.js`, `bridge.py`, `capture.rs`), плюс
дефекты отчёта из разбора лога `2026-11-19 15:57:20` (PCMflash + Scanmatik SM2).
Форматы строк — `docs/11-capture-grammar.md`.

## Проверка живого лога «Идентификация» (19.11.2026, 17:01)

Короткая сессия 12.3 с, 52 посылки K-line (`0x8003`), Scanmatik `A62122`.
Проверял не по отчёту, а по кадрам `raw.log` — сверил каждый счётчик вручную.

| Что | Заявлено | Сверено по `raw.log` |
|---|---|---|
| TX | 52 / 4040 B | 52 строки; 14×253 + 16×5 + 17×7 + 132+149+8+6+4 = **4040** |
| RX | 104 / 365 B | 104 строки = 52 SOF (`len=0`) + 52 данных; 32×5 + 17×10 + 15+14+6 = **365** |
| `calls` | 156 | 52 `WriteMsgs` + 104 `ReadMsgs` (приложение читает по одному сообщению) |
| ошибки | 1 | ровно один `kind=error`: `chan-miss` |
| холостые | 0 | ни одного `n_out=0`; каждый `ReadMsgs` вернул сообщение |
| шаг | 12.28 с | `started_at`→`ended_at` = 12.281 с |

Что в этом логе **не так** (и что сделано):

1. **Нет ни одной строки `PassThruConnect`.** Канал `ch=1` появился в `ioctl`
   без наблюдаемого `connect`; агент честно записал `J2534 chan-miss`, и это
   единственная «ошибка» сессии. Хук проверен отдельно: тот же
   `universal_capture.js` на этой же `smj2534.dll` ловит `connect-enter` и
   `connect` и при `spawn`, и при позднем `attach` (пробник на 32-битном
   PowerShell, `PassThruOpen → Connect(0x8003) → Ioctl → Disconnect → Close`).
   Значит точка входа экспорта не сработала, а не хук сломан; причина —
   в пути вызова внутри PCMflash (exe упакован: 4 импорта, API разрешаются
   вручную). Для диагностики в `chan-miss` добавлен `mod=` (id загрузки DLL),
   как в `rx-empty`.

2. **`Ошибок: 1` без расшифровки.** Теперь первые 10 ошибок попадают в
   `counts.error_samples` и печатаются в `report.txt` (`ошибки (1):`) и
   `report.md` (`## Ошибки (1)`); полный список — по-прежнему `events.jsonl`
   (`kind=error`). Регресс-тест: `engine/tests/error_samples.rs`.

3. **Живая сессия и импорт того же `raw.log` дают разное число событий**
   (209 против 224). Расходятся только служебные `#`-строки, которые живой
   путь кладёт в `facts`/пропускает, а импорт разбирает как `sys`/`summary`.
   TX/RX/шаги/байты совпадают до байта. Считать «события» между двумя
   представлениями одной сессии нельзя — это разные множества.

Ограничение, подтверждённое на этой DLL: у `smj2534.dll` 17 экспортов, из них
3 (ординалы 1377-1379 — J2534-2 `LogicalConnect`/`Select`/`QueueMsgs`) **без
имени**; `Module.enumerateExports()` их не отдаёт, поэтому они не хукаются и в
логе не видны. В `# hooks` считается только 14 поименованных `PassThru*`.

## Чем проверено

| Инструмент | Что покрывает |
|---|---|
| `cargo test` | парсер, модели, писатель сессии, отчёты, импорт (**142 теста**, 0 падений, 12 `#[ignore]`) |
| `tests/e2e/j2534_stand.py` | живой захват через Frida: агент → `bridge.py` → `raw.log` → **40 проверок** (full) / **38** (compact) |
| `tests/e2e/fake_j2534` | поддельный драйвер PassThru 04.04 на 14 экспортов + три контрактные ловушки |
| `tests/e2e/j2534_full_target.py` | цель: два прохода с выгрузкой DLL + третий `Open` без выгрузки |
| `engine/tests/acceptance_size.rs` | реальный `raw.log` 29.5 МБ → импорт → замер `events.jsonl`, счётчиков, адаптера, сети, `filehash` |
| `engine/examples/decode_raw.rs` | прогон готового `raw.log` через декодер |

## Что исправлено в этой версии

| Приоритет | Дефект | Как закрыт |
|---|---|---|
| P0 | `ReadMsgs` выходил при любом `rc != 0`, теряя сообщения, которые драйвер уже отдал | ветка «пусто» срабатывает только при `n_out=0`; при `rc != 0` и `n_out > 0` сообщения читаются и пишутся с `partial=1` |
| P0 | `n_out > n_in` не ограничивался ёмкостью входа | чтение ограничено `min(n_out, n_in, 256)`, нарушение фиксируется строкой `J2534 msgs-overflow` и `contract=n_out_gt_n_in` |
| P0 | CAN: первые 4 байта `Data` выносились из `hex` и терялись при обратной сборке | `hex` = все `Data[DataSize]`, `len` = их число, идентификатор — `id=` + `idlen=` |
| P0 | `ExtraDataIndex` не читался | `xdi=` в строке сообщения, `meta.xdi` в парсере, счётчик `xdi_events` |
| P0 | SOF отбрасывал `hex` независимо от длины | SOF без данных — короткая строка; SOF с данными сохраняет и статус, и байты |
| P0 | FTDI/VCP: больше 16 КиБ за событие обрезалось молча | `chunkedLog`: `part=i/n`, явная отметка `truncated=1 len=… logged=…`, счётчик `truncated_payloads` |
| P0 | `dropped_events` считал вытеснение из сводки шага, а не потери захвата | разведены `dropped_events` (агент + мост) и `evicted_events` (сводка шага, `# session note`) |
| P0 | `flush()` на каждое событие моста | батч 32 КиБ / 20 мс с сохранением порядка (`emit` сбрасывает батч), счётчики `bridge_events/batches/backlog_max` |
| P1 | `timeout_ms` не попадал в строку вызова | пишется для `ReadMsgs`/`WriteMsgs` |
| P1 | агрегат пустых опросов ключевался по `ch` и сливал разные `rc`/таймауты | ключ `module_load_id + gen + rc + timeout_ms`, в строке `mod=`/`gen=` |
| — | сеть попадала в `resp_hist` шага | отдельная `net_hist` + `net_tx/net_rx`, в отчёте строка «Сеть (не протокол ЭБУ)» |
| — | `adapter: null` при живой строке прошивки | `J2534 open`/`J2534 version` → `vendor/serial/firmware/dll_version/api`, работает и при импорте |
| — | `errors: 20` — это были `rx-empty` | `rx-empty` → `kind=sys`, отдельный счётчик `empty_polls` (по `n`), `errors` — только настоящие потери |
| — | `reads: []`, `filehash: []` не заполнялись | пустые поля не сериализуются; `filehash` заполняется по факту: файл, в который шёл `FILE write/close`, хэшируется (до 64 МиБ) |
| — | `events.jsonl` был 2.7× больше `raw.log` | поле `raw` (копия строки лога) больше не пишется; в JSONL остаётся только `kind=raw` |

## Замер на реальном логе

`20261119-154616-pcmflash` (PCMflash 1.2.0, Scanmatik SM2, MEVD17.2.G), импорт из
готового `raw.log`:

| Метрика | Было (v0.3.3) | Стало (v0.3.4) |
|---|---|---|
| `raw.log` | 30 915 902 B | 30 915 902 B |
| `events.jsonl` | 83 985 546 B (2.72×) | 49 474 860 B (**1.60×**, −41 %) |
| `errors` в `session.json` | 20 (`rx-empty`) | 3 (только `chan-miss`) |
| `empty_polls` | — | 76 (20 строк `rx-empty`, сумма `n`) |
| `adapter` | `null` | `Scanmatik`, SN `A62122`, `FW:1060 HW:02`, dll `1.0.0.120`, api `04.04` |
| сеть в `resp_hist` шага | `TCP 45.132.18.119:80` (21 и 142) | `net_hist` отдельно, в ответы не попадает |
| `filehash` шага | `[]` | дамп 4 МиБ с `mode=gone` (файл удалён с диска) |
| счётчики | `dropped_events` = вытеснение сводки | `dropped_events=0 evicted_events=0 partial_results=0 contract_violations=0 bridge_events=…` |

Почему JSONL всё ещё больше `raw.log`: бюджет `docs/09` §8 задан для `raw.log` и
ZIP (компактный режим — ≤50 % от файла), а не для JSONL. На каждое событие в
JSONL приходится ~15 имён полей, а контракт §7 требует `api` и `hex` в открытом
виде. Убранное поле `raw` было единственным настоящим дублированием — 30 МБ из 84.
Дальнейшее сокращение возможно только сменой контейнера (бинарный/колоночный
`events.bin` или gzip-поток), это отдельная работа.

## Чек-лист §10

| Пункт | Статус | Чем подтверждён |
|---|---|---|
| `J2534 connect` > 0 и `chan-miss` = 0 при захвате с запуска процесса | **да** | стенд: три `connect` (`gen=1`), `chan-miss` отсутствует |
| `# hooks` содержит `exports=14 attached=14 failed=0` | **да** | стенд: обе установки |
| `Close → Open` без выгрузки DLL | **да** | стенд: третий проход `reopen` — два `J2534 open` с **одинаковым** `mod=`, `FreeLibrary` между ними не было |
| `FAST_INIT`: вход/выход как `PASSTHRU_MSG` | **да** | стенд: `in_size=4 in=0002277f out_size=3 out=000367…` |
| `ReadMsgs` (`n_in=10`, `n_out=3`) | **да** | стенд: 3 строки RX на вызов, SOF отдельно |
| `ReadMsgs` при `rc != 0` | **да** | стенд: `n_out=2 timeout_ms=777 rc=0x10 partial=1` + оба сообщения |
| `ReadMsgs` при `n_out > n_in` | **да** | стенд: `msgs-overflow … read=10`, `contract=n_out_gt_n_in` |
| CAN: исходные байты и `ExtraDataIndex` | **да** | стенд: `id=0x7E8 idlen=4 xdi=9 len=11 : 00 00 07 e8 …` |
| `WriteMsgs` (`n_in=5`, `n_out=2`) | **да** | стенд: все 5 TX + `n_out=2` |
| `pause → resume` | **да** | стенд: `chan-possibly-open … reason=resume`, ложного `chan-miss` нет |
| `dropped_events = 0`, `truncated_payloads = 0`, `decode_errors = 0` | **да** | стенд: `# agent-counters` |
| Счётчики моста | **да** | стенд: `bridge_events=… bridge_batches=… bridge_backlog_max=…` |
| `cargo test` зелёный | **да** | 142 passed, 0 failed |
| Регресс декодера на старом `raw.log` | **да** | `tests/reference_decode.rs` + импорт реального лога: 102 458 событий, 0 ошибок разбора |

## Что осталось за стендом

| Пункт | Почему |
|---|---|
| Второй реальный драйвер (CHIPSOFT / OpenPort) | нужен адаптер и целевая программа |
| Живой `# attach: late` | проверяется одним attach к работающему PCMflash |
| Пассивные 05.00 (`dec=0`) «в бою» | на этой машине драйверов 05.00 нет |
| **Несколько источников в одной сессии** (PassThru + USBPcap) | сейчас `start_raw_usb` отказывается стартовать при активной сессии: у каждой сессии свой writer-task и свои часы. План: разрешить USBPcap-ребёнка при активном захвате, кормить его пакеты в тот же writer через `Cmd::UsbRaw`, тегировать события `source=`, а `raw_times` не привязывать к режиму сессии |

## Как повторить

```powershell
# модульные тесты
cargo test --manifest-path engine\Cargo.toml

# приёмка объёма на реальном логе (путь подставить свой)
$env:FTDI_ACCEPTANCE_LOG = "C:\Users\User\AppData\Local\FTDI_USB_Logger\sessions\20261119-154616-pcmflash\raw.log"
cargo test --manifest-path engine\Cargo.toml --test acceptance_size -- --ignored --nocapture

# стенд без железа (нужен python с frida)
cargo build --release --manifest-path tests\e2e\fake_j2534\Cargo.toml
python tests\e2e\j2534_stand.py --dll tests\e2e\fake_j2534\target\release\fake_j2534.dll `
    --out build\stand-full.raw.log --mode full
python tests\e2e\j2534_stand.py --dll tests\e2e\fake_j2534\target\release\fake_j2534.dll `
    --out build\stand-compact.raw.log --mode compact

# разбор готового лога
cargo run --release --manifest-path engine\Cargo.toml --example decode_raw -- <raw.log> --json events.jsonl
```
