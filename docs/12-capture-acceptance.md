# Приёмка доработки захвата J2534 (v0.3.3)

Отчёт по `docs/09-capture-changes-spec.md` §10: что доказано автоматическими
проверками, а что требует стенда с железом. Форматы строк — `docs/11-capture-grammar.md`.

## Чем проверено

| Инструмент | Что покрывает |
|---|---|
| `cargo test --manifest-path engine\Cargo.toml` | парсер, модели, писатель сессии, отчёты (135 тестов) |
| `tests/e2e/j2534_stand.py` | живой захват через Frida: агент → `bridge.py` → `raw.log` → утверждения |
| `tests/e2e/fake_j2534` | поддельный драйвер PassThru 04.04, все 14 экспортов |
| `engine/examples/decode_raw.rs` | прогон готового `raw.log` через декодер и сверка с эталоном |
| `tests/e2e/j2534_full_target.py` | цель: полный набор вызовов, выгрузка DLL, повторная загрузка |

## Чек-лист §10

| Пункт | Статус | Чем подтверждён |
|---|---|---|
| `J2534 connect` > 0 и `chan-miss` = 0 при захвате с запуска процесса | **да** | стенд: 2 `connect` (`gen=1`), `chan-miss` отсутствует, `# attach: early` |
| `# hooks` содержит `exports=14 attached=14 failed=0` для драйвера | **да** | стенд: строка `attached=14 dup=0 failed=0` на обеих установках |
| `Close → Open` без выгрузки DLL: вторая сессия видна целиком | **да** | стенд: `load=1` → `load=2`, оба прохода записаны; хуки перевешены |
| Второй драйвер другого производителя (CHIPSOFT / OpenPort) | **нет стенда** | нужен реальный адаптер; на этой машине зарегистрирован CHIPSOFT `j2534_interface.dll`, но цели для него нет |
| `FAST_INIT`: каждый фактически вызванный вызов с входом, `rc` и валидным выходом | **да** | стенд: `(FAST_INIT) in_size=4 in=0002277f out_size=3 out=000367` |
| Пакетный `ReadMsgs` (`n_in=10`, `n_out=2`): 2 RX | **да** | стенд: `n_in=10 n_out=3` → 3 строки RX, из них одна SOF |
| Пакетный `WriteMsgs` (`n_in=5`, `n_out=2`): все 5 TX и `n_out=2` | **да** | стенд: строка `call` с `n_in=5 n_out=2` + 5 строк `i=1..5` |
| Позднее подключение: `# attach: late`, канал `chan-possibly-open` | **частично** | `# attach: late` пишется движком (не проверялся на живом late-attach); `chan-possibly-open` проверен в сценарии resume |
| `pause → открытие канала → resume` | **да** | стенд: `chan-possibly-open ch=1 gen=1 reason=resume`, ложного `chan-miss` нет |
| `dropped_events = 0`, `truncated_payloads = 0`, `decode_errors = 0` | **да** | стенд: `# counters dropped_events=0 truncated_payloads=0 decode_errors=0` |
| Полнота: `Σ n_out` (RX) и `Σ n_in` (TX) равны числу записанных сообщений | **да** | стенд: 3 RX на вызов, 5 TX на вызов, оба прохода |
| `cargo test` зелёный | **да** | 135 passed, 0 failed, 10 ignored |
| Регресс декодера на старом `raw.log` | **да** | 22.6 МБ / 102 789 строк: эталон v0.3.2 и новая сборка совпали по числу событий, `api`, `hex`, `len` (см. ниже) |

## Регресс декодера

Эталон собран из `HEAD` v0.3.2 в отдельном worktree тем же `decode_raw`:

```
base events: 102789 new events: 102789
расхождений api: 0
расхождений hex: 0
расхождений len: 0
гистограммы api совпадают: True
TX 33777 33777   RX 67554 67554
РЕЗУЛЬТАТ: PASS
```

Распознано 100 % строк (`нераспознанных: 0`), время разбора — 2.2 с.

## Что осталось за стендом

| Пункт | Почему |
|---|---|
| Второй драйвер (CHIPSOFT / OpenPort) | нужен адаптер и целевая программа |
| Бюджет §8 на реальном прогоне PCMflash | требует той же сессии с ЭБУ; ориентир: +10…13 % в `full` за счёт строк `call` и −SOF-hex, `compact` — меньше за счёт агрегации пустых опросов |
| `# attach: late` на живом позднем подключении | проверяется одним attach к уже работающему PCMflash |
| Passthru 05.00 `dec=0` «в бою» | на этой машине драйверов 05.00 нет; логика проверена на уровне кода и парсера |

## Как повторить

```powershell
# модульные тесты
cargo test --manifest-path engine\Cargo.toml

# стенд без железа (нужен python с frida)
cargo build --release --manifest-path tests\e2e\fake_j2534\Cargo.toml
python tests\e2e\j2534_stand.py --dll tests\e2e\fake_j2534\target\release\fake_j2534.dll `
    --out build\stand-full.raw.log --mode full
python tests\e2e\j2534_stand.py --dll tests\e2e\fake_j2534\target\release\fake_j2534.dll `
    --out build\stand-compact.raw.log --mode compact

# разбор готового лога (сверка с эталоном)
cargo run --release --manifest-path engine\Cargo.toml --example decode_raw -- <raw.log> --json events.jsonl
```
