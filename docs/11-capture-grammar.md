# Грамматика строк захвата (контракт v0.3.3)

Единый источник истины для `sidecar/agents/universal_capture.js` (пишет) и
`engine/src/decode.rs` (читает). Строки из `docs/09-capture-changes-spec.md`
реализуются **ровно** в этих формах; любое расхождение — дефект.

Общие правила:

* префикс `[+<секунды>s] ` — 6 знаков после точки (QPC), старые 3 знака тоже читаются;
* порядок ключей фиксирован, все значения — `ключ=значение` без пробелов внутри значения;
* hex без `:`-секции пишется **слитно** (`0002277f`); hex с `:`-секцией — через пробел;
* парсер обязан принимать неизвестные ключи (кладёт их в `meta`) и не ломаться на них.

## 1. Баннер и служебные комментарии

```
# capture start: label=PCMflash
# tool: C:\PCMflash\pcmflash.exe
# exe: size=1234567 mtime=2026-11-19 13:06:10 sha256=…
# wall(start)=2026-11-19 13:06:10
# host: user=User computer=PC
# agent: universal_capture.js mode=full
# attach: spawn
```

`# attach:` — `spawn` (захват с запуска процесса), `early` (attach до первой
операции с DLL), `late` (позднее подключение: часть жизни процесса не записана).

Эмитится агентом после определения ABI:

```
# api: 04.04 dll="smj2534.dll" ver="1.0.0.120" path="C:\…\smj2534.dll" pid=8120 bits=32 dec=1
# api: 05.00 dll="op20pt32.dll" ver="1.0.0.0" path="…" pid=8120 bits=32 dec=0
# api: unknown dll="x.dll" ver="" path="…" pid=8120 bits=32 dec=0 reason=ambiguous
```

Диагностика установки хуков (одна строка на модуль + одна со списком имён):

```
# hooks mod="smj2534.dll" base=0x6d830000 load=1 exports=14 attached=14 dup=0 failed=0
# hooks-names mod="smj2534.dll" names="PassThruOpen,PassThruClose,…"
```

`attached` инкрементируется только при реально установленном хуке. `load=` —
`module_load_id` (счётчик загрузок этого имени, не адрес базы).

Итоговый блок счётчиков (пишет движок в конце сессии):

```
# agent-counters dropped_events=0 truncated_payloads=0 decode_errors=0 rx_sof=0 calls=0 partial_results=0 contract_violations=0 xdi_events=0 bridge_events=12345 bridge_batches=87 bridge_backlog_max=64 mode=full
# counters dropped_events=0 truncated_payloads=0 decode_errors=0 evicted_events=0 partial_results=0 contract_violations=0 rx_sof=0 calls=0 bridge_events=12345 bridge_batches=87 bridge_backlog_max=64
# session incomplete: reason=capture_loss dropped=12 truncated=1 partial=1 contract=1
# session note: evicted_events=120 (сводка шага неполна, raw.log полон)
```

## 2. `J2534 open` (F6)

```
[+1.200000s] J2534 open name="Scanmatik - SM2 USB" vendor="Scanmatik" dll="smj2534.dll" dev=1 mod=1 rc=0 th=8120
```

`dev=` — `DeviceID` из выходного параметра (после успешного вызова), `-1` при ошибке.

## 3. `J2534 Connect` (D1)

Вход пишется **до** вызова, выход — после:

```
[+31.850000s] J2534 connect-enter dev=1 proto=0x8003 flags=0x0 baud=250000 th=8120
[+31.907431s] J2534 connect dev=1 ch=1 proto=0x8003 flags=0x0 baud=250000 rc=0 gen=1 th=8120 dur=57431
```

`gen` растёт **после успешного** `connect` этого канала. Ключ канала:
`pid | module_load_id | ch | gen`.

Диагностика рассинхронизации канала:

```
[+31.907500s] J2534 chan-miss ch=1 gen=2 first_op=filter th=8120
[+40.000000s] J2534 chan-possibly-open ch=1 gen=2 reason=resume
```

## 4. `J2534 call` — строка вызова (D2/§3)

Пишется, когда сообщений нет, их несколько, или вызов завершился ошибкой:

```
[+32.100000s] J2534 call ch=1 call=1247 op=ReadMsgs n_in=10 n_out=3 timeout_ms=20 rc=0 th=8120 dur=20134
[+33.000000s] J2534 call ch=1 call=1248 op=ReadMsgs n_in=10 n_out=0 timeout_ms=20 rc=0x11 th=8120 dur=20001
[+33.100000s] J2534 call ch=1 call=1249 op=WriteMsgs n_in=5 n_out=2 timeout_ms=100 rc=0 th=8120 dur=812
[+33.200000s] J2534 call ch=1 call=1250 op=ReadMsgs n_in=10 n_out=2 timeout_ms=500 rc=0x10 partial=1 th=8120 dur=513
[+33.300000s] J2534 call ch=1 call=1251 op=ReadMsgs n_in=10 n_out=12 timeout_ms=500 rc=0 contract=n_out_gt_n_in th=8120 dur=12
```

`op` — имя экспорта (`ReadMsgs`, `WriteMsgs`, `StartPeriodicMsg`, …).

* `timeout_ms=` — значение таймаута, которое приложение передало вызову. Без него
  по логу нельзя отличить штатное ожидание 20 мс от 500 мс, а агрегат пустых
  опросов (`rx-empty`) вообще нечем проверить.
* `partial=1` — сообщения записаны, но `rc != 0`. Контракт PassThru допускает
  уже снятые с очереди сообщения вместе с кодом ошибки; такие сообщения идут
  отдельными строками `J2534 RX/TX` с тем же `call`.
* `contract=` — нарушение контракта драйвером:
  `n_out_gt_n_in` (записал больше, чем дали — читаем ровно `n_in`),
  `empty_with_msgs` (`rc=0x10/0x11`, но счётчик сообщений не ноль).
  Каждое нарушение считает счётчик `contract_violations`.

## 5. Сообщения TX/RX (F4)

Одно сообщение (`rc=0`, счётчики сошлись) — все общие поля на строке сообщения:

```
[+32.100000s] J2534 RX ch=1 call=1247 i=1/1 n_in=10 n_out=1 th=8120 ts=0 rxs=0x0 proto=ISO15765 id=0x7E8 svc=0x50 len=8 dur=20134 rc=0 : 06 50 03 00 00 00 00 00
[+32.000000s] J2534 TX ch=1 call=1246 i=1/1 n_in=1 n_out=1 th=8120 ts=0 flags=0x0 proto=0x8003 svc=0x27 len=4 dur=812 rc=0 : 00 02 27 7f
```

Несколько сообщений — общие поля на строке `call`, на сообщениях только `call` и `i`:

```
[+32.100000s] J2534 call ch=1 call=1247 op=ReadMsgs n_in=10 n_out=2 rc=0 th=8120 dur=20134
[+32.100000s] J2534 RX ch=1 call=1247 i=1/2 ts=0 rxs=0x2 proto=0x8003 sof=1 len=0
[+32.100010s] J2534 RX ch=1 call=1247 i=2/2 ts=0 rxs=0x0 proto=0x8003 svc=0x50 len=5 : 00 03 67 7f 34
```

SOF-кадр (`rxs=0x2 START_OF_MESSAGE`, `DataSize=0`) — **без** секции `: hex`,
с `sof=1`, отдельной короткой строкой; в счётчик полезных сообщений не входит.

Если у SOF есть данные (`DataSize>0`), строка **сохраняет** и `sof=1`, и `: hex`:
статус кадра не отменяет его содержимое.

CAN (протоколы `CAN`/`ISO15765`): первые 4 байта `Data` — идентификатор кадра.
Он дублируется декодированным `id=`, но `hex` всегда содержит **все** байты
`Data[DataSize]`, а `len=` равен их числу; длина идентификатора — `idlen=`:

```
[+32.500000s] J2534 RX ch=1 call=1250 i=1/1 n_in=1 n_out=1 th=8120 ts=0 rxs=0x0 proto=CAN id=0x7E8 idlen=4 svc=0x50 xdi=9 len=11 dur=14 rc=0 : 00 00 07 e8 06 50 03 00 00 aa bb
```

`xdi=` — `ExtraDataIndex` из `PASSTHRU_MSG` (смещение 20): где в `Data`
начинаются extra-данные. Печатается, только если `0 < xdi < DataSize`.

В компактном режиме SOF без данных не пишется построчно, а агрегируется:

```
[+41.000000s] J2534 rx-sof-stat ch=1 n=33777
```

## 6. `J2534 ioctl` (D4)

```
[+31.900000s] J2534 ioctl ch=1 call=88 id=0x0005 (FAST_INIT) rc=0 th=8120 dur=1520 in_proto=0x8003 in_rxs=0x0 in_flags=0x0 in_ts=0 in_edi=0 in_size=6 in=0002277f out_proto=0x8003 out_rxs=0x0 out_flags=0x0 out_ts=0 out_edi=0 out_size=3 out=0003677f34
[+31.910000s] J2534 ioctl ch=1 call=89 id=0x0003 (READ_VBATT) rc=0 th=8120 dur=300 out=00000c1a
[+31.920000s] J2534 ioctl ch=1 call=90 id=0x0002 (SET_CONFIG) rc=0 th=8120 dur=200 in=0c000000f4010000
[+31.930000s] J2534 ioctl ch=1 call=91 id=0x0123 rc=0 th=8120 dur=100 in_ptr=1 out_ptr=0 dec=0
```

Правила:

* `FAST_INIT` (`0x05`): оба указателя — `PASSTHRU_MSG`, раскладка 04.04
  (`proto` 0, `rxs` 4, `flags` 8, `ts` 12, `size` 16, `edi` 20, `data` 24).
  `in=`/`out=` — `Data[DataSize]` слитным hex.
* `DataSize > 4128` → `len_invalid=1`, `Data` не читается.
* Выход недоступен или невалиден → `out=none reason=<len_invalid|null|abi|error>`.
* Неизвестный `id` → `in_ptr=0|1 out_ptr=0|1 dec=0`, содержимое не читается.
* ABI не подтверждён (см. §9) → `dec=0`.
* `(ИМЯ)` — из таблицы `PT_IOCTL_NAMES` (`0x01` GET_CONFIG, `0x02` SET_CONFIG,
  `0x03` READ_VBATT, `0x05` FAST_INIT, `0x07` CLEAR_TX_BUFFER,
  `0x08` CLEAR_RX_BUFFER, `0x09` CLEAR_RX_MSGS, `0x0A` CLEAR_MSG_FILTERS,
  `0x0B` CLEAR_PERIODIC_MSGS, `0x0C` CLEAR_EXTRA_MSGS, `0x0D` CLEAR_ISO15765_FLOW_CONTROL,
  `0x0E` CLEAR_ISO15765_BUFFERS).
* Старая строка `J2534 config ch=… <пары> rc=…` для `SET_CONFIG` сохраняется.

## 7. `J2534 filter`, периодические (D5)

```
[+31.800000s] J2534 filter ch=1 call=90 type=0x0001 (PASS_FILTER) rc=0 th=8120 dur=410 mask=ffffffff pattern=000007e0 flow=- mask_proto=0x8003 mask_flags=0x0 pattern_proto=0x8003 pattern_flags=0x0 proto=ISO15765 flags=0x0 id=0x1
[+31.810000s] J2534 filter-stop ch=1 call=91 id=0x1 rc=0 th=8120 dur=90
[+31.820000s] J2534 periodic-start ch=1 call=92 id=0x1 ms=1000 proto=0x8003 flags=0x0 len=8 rc=0 th=8120 dur=140 : 00 06 3e 00 00 00 00 00
[+31.830000s] J2534 periodic-stop ch=1 call=93 id=0x1 rc=0 th=8120 dur=60
```

`mask`/`pattern` — `Data[DataSize]` слитным hex; `flow=-` при `pFlowControlMsg = NULL`.
`proto`/`flags` в хвосте — из `pPatternMsg`.

## 8. `FILE read` (D6)

```
[+5.000000s] FILE read h=0xe10 off=0x1F0000 len=0x1000 total=0x400000
```

Старая форма `FILE read <path> offset=… n=… len=…` тоже обязана читаться.
Не более 4096 строк на сессию; дальше — только агрегат в `# counters`.

## 9. ABI, разрядность, 05.00

* `PT_MSG_SIZE = 4152` (24 + `Data[4128]`) действителен только для **04.04**.
* 05.00: вызовы и сырые указатели регистрируются, структура **не** декодируется,
  в строке `dec=0`.
* Подтверждение 04.04: (а) `PassThruReadVersion` вернул `api="04.04…"`;
  (б) DLL зарегистрирована **только** в ветке `PassThruSupport.04.04`
  (движок передаёт карту `dll→api` в attach).
* DLL в обеих ветках и версия не прочитана → `dec=0` до подтверждения.

## 10. Режимы сбора (§4)

| | `full` | `compact` |
|---|---|---|
| Вызовы | каждый | пустые опросы агрегируются по `ch`, `rc`, `timeout` |
| Сообщения | каждый элемент массива | каждый полезный кадр |
| SOF | отдельная короткая строка | счётчик `rx_sof` |
| Итог | разбор протокола | длинный прогон |

## 11. Что парсер обязан положить в `meta`

| Строка | meta |
|---|---|
| `TX`/`RX` | `channel, protocol, can_id, flags, rxs, svc, svc_resp, call, i, n_in, n_out, thread, ts, dur, sof, rc` |
| `call` | `channel, call, op, n_in, n_out, thread, dur, rc` |
| `connect` | `device, channel, protocol, flags, baud, gen, thread, dur, rc` |
| `connect-enter` | `device, protocol, flags, baud, thread` |
| `open` | `device, vendor, dll, dev, thread, rc` |
| `ioctl` | `channel, call, ioctl_id, ioctl_name, in, out, in_size, out_size, dec, len_invalid, thread, dur, rc` |
| `filter` | `channel, call, filter_type, mask, pattern, flow, proto, flags, filter_id, thread, dur, rc` |
| `periodic-start` | `channel, call, filter_id, interval, protocol, flags, thread, dur, rc` |
| `rx-empty`/`tx-err-stat` | `channel, call, n, timeout_ms, last_rc` |
| `chan-miss` | `channel, gen, first_op, thread` |
| `FILE read` | `handle, offset, len, total` |
| `# api:` | `api, dll, ver, path, pid, bits, dec` |
| `# hooks` | `mod, base, load, exports, attached, dup, failed` |
| `# counters` | `dropped_events, truncated_payloads, decode_errors, rx_sof, calls` |

## 12. Совместимость

* Старый `raw.log` (23.7 МБ, 102 789 строк) разбирается новой сборкой без ошибок.
* `events.jsonl`: `api` (`"J2534 TX"`/`"J2534 RX"`) и `hex` сохраняются — на них
  `re/01_extract_pairs.py`.
* Старые 3-знаковые метки, `J2534 rx-error`/`tx-error`, `FILE write <path> …`
  остаются рабочими.
