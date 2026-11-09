#Requires -Version 7.0
param(
    [string]$Results = (Join-Path $PSScriptRoot "out\results.json"),
    [string]$OutFile = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path "docs\05-edge-cases.md")
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Results)) { throw "нет результатов: $Results" }
$rows = @(Get-Content $Results -Raw | ConvertFrom-Json)
$byId = @{}
foreach ($r in $rows) { $byId[$r.id] = $r }
# UI-05b приходит из cdp-edge.mjs без «ожидания/repro» в старых results.json — заполняем.
$overrides = @{ 'UI-05b' = @{ expect = 'Повторное включение всех фильтров: 12 kinds, поток снова отображается'; repro = 'после нулевых фильтров нажать все 7 .chip ещё раз' } }
foreach ($r in $rows) {
    if ($overrides.ContainsKey($r.id)) {
        $o = $overrides[$r.id]
        if (-not $r.expect) { $r.expect = $o.expect }
        if (-not $r.repro) { $r.repro = $o.repro }
    }
}

function Scrub([string]$text, [int]$max = 340) {
    if ($null -eq $text) { return "" }
    $t = ([string]$text) -replace "`r?`n", " / "
    $t = $t -replace '\|', '\|'
    $t = $t.Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max) + "…" }
    return $t
}
function FactOf([string]$id) { if ($byId.ContainsKey($id)) { return $byId[$id].fact } else { return "(нет кейса $id)" } }
function VerdictOf([string]$id) { if ($byId.ContainsKey($id)) { return $byId[$id].verdict } else { return "?" } }

$pass = @($rows | Where-Object { $_.verdict -eq "PASS" }).Count
$bugs = @($rows | Where-Object { $_.verdict -eq "BUG" })
$fails = @($rows | Where-Object { $_.verdict -eq "FAIL" })

# ───────────────────────────── таблица кейсов ────────────────────────────
$groups = @(
    @{ Title = "Импорт старых логов (IMP/RAW/DEC), 13 кейсов"; Pattern = '^(IMP|RAW|DEC)-' },
    @{ Title = "API: мусорные запросы и контракт ошибок (API/CORS), 21 кейс"; Pattern = '^(API|CORS)-' },
    @{ Title = "Захват без устройства (CAP), 18 кейсов"; Pattern = '^CAP-' },
    @{ Title = "Файлы сессии (FILE), 7 кейсов"; Pattern = '^FILE-' },
    @{ Title = "Долгий поток: импорт 100 МБ (BIG), 1 кейс"; Pattern = '^BIG-' },
    @{ Title = "UI через CDP (UI), 9 кейсов"; Pattern = '^UI-' },
    @{ Title = "Чистка и инфраструктура (CLEAN/INFRA), 1 кейс"; Pattern = '^(CLEAN|INFRA)-' }
)
$table = [System.Collections.Generic.List[string]]::new()
foreach ($g in $groups) {
    $list = @($rows | Where-Object { $_.id -match $g.Pattern })
    if ($list.Count -eq 0) { continue }
    $table.Add("### " + $g.Title)
    $table.Add("")
    $table.Add("| # | Кейс | Ожидание | Факт | Вердикт | Как воспроизвести |")
    $table.Add("|---|---|---|---|---|---|")
    foreach ($r in $list) {
        $table.Add("| $($r.id) | $(Scrub $r.name 120) | $(Scrub $r.expect 220) | $(Scrub $r.fact 340) | **$($r.verdict)** | $(Scrub $r.repro 220) |")
    }
    $table.Add("")
}
$tableText = $table -join "`n"

# ───────────────────────────── header ────────────────────────────────────
$header = @'
# 05. Крайние случаи: edge-тесты движка и UI

Жёсткая проверка крайних случаев FTDI/USB Logger: импорт мусора и больших логов, мусорные
запросы API, захват без устройства, файлы сессии, длинный поток и UI без движка.
В `engine/src`, `ui/src`, `sidecar` ничего не менялось — только тесты (`tests/e2e/edge/`) и этот отчёт.

> **Итог: __N__ кейсов, __PASS__ PASS, __BUG__ BUG-строк (7 разных дефектов: 3 важных, 4 мелочи), __FAIL__ FAIL.**
> Блокеров на финальной сборке нет: единственный блокер (id-траверсал в `session_file`) был найден
> в первой версии, исправлен Lead'ом и перепроверен — PASS.

| Параметр | Значение |
|---|---|
| Дата прогона | __DATE__ |
| Движок | `engine\target\debug\ftdi-logger.exe`, сборка 2026-11-09 13:17:21 (debug) |
| Порт движка | 7831 (изолированно от рабочих экземпляров) |
| UI | `ui/dist`, статика на `python http.server` :8101, CDP :9335, Edge headless |
| Запуск | `pwsh -File tests\e2e\edge\run-edge.ps1` |
| Результат | `tests/e2e/edge/out/results.json` (+ `results.csv`, `summary.txt`, `ui-results.json`) |

## 1. Обзор проверки

```mermaid
flowchart TD
    A["run-edge.ps1<br/>копия exe в %TEMP%"] --> B["engine :7831<br/>--root D:\\FTDI_USB_Logger"]
    B --> C["Импорт: пусто/CRLF/бинарь/9.7 МБ/100 МБ<br/>unicode-имя, traversal, повтор, параллель"]
    B --> D["API-мусор: неизвестный id, seq, limit,<br/>битый JSON, Content-Type, форматы, методы, CORS"]
    B --> E["Захват без устройства:<br/>pid 0 / 999999 / 4, dummy_target, пустые mark/note"]
    B --> F["Файлы сессии: traversal, 404, PNG из живой сессии"]
    B --> G["UI: статика без движка, demo, F2, поиск,<br/>фильтры, resize 800x600, два таба, большая сессия"]
    G --> H["cdp-edge.mjs<br/>Edge headless :9335"]
    C --> I["out/results.json<br/>PASS/BUG/FAIL + факты + repro"]
    D --> I
    E --> I
    F --> I
    H --> I
    I --> J["CLEAN-01: удалить свои сессии,<br/>проверить index.json"]
```

## 2. Что именно проверялось

| Блок | Кейсов | Кейсы |
|---|---|---|
| Импорт старых логов | 13 | IMP-01…11, RAW-01, DEC-01 |
| API: мусорные запросы | 21 | API-01…17, CORS-01…04 |
| Захват без устройства | 18 | CAP-01…18 |
| Файлы сессии | 7 | FILE-01…07 |
| Долгий поток 100 МБ | 1 | BIG-01 |
| UI (CDP) | 9 | UI-01…08 + UI-05b |
| Чистка/инфраструктура | 1 | CLEAN-01 |
'@
$header = $header.Replace('__N__', "$($rows.Count)").Replace('__PASS__', "$pass").Replace('__BUG__', "$($bugs.Count)").Replace('__FAIL__', "$($fails.Count)").Replace('__DATE__', (Get-Date -Format "yyyy-MM-dd HH:mm"))

# ───────────────────────────── история блокера ───────────────────────────
$blocker = @'
## 3. Бывший блокер: произвольное чтение файлов через `:id` (исправлен)

Первая версия движка (сборка до 13:10) отдавала любой локальный файл через
`GET /api/sessions/{id}/file/*path`, если подставить абсолютный путь или `..` в **сегмент `:id`**
(а не в `*path`). Штатные попытки из ТЗ (`/file/../../engine/Cargo.toml`, `/file/..%2f..%2fetc`)
резались 400 — дыра была именно через `:id`.

| Проверка | Факт до фикса | Факт после фикса | Вердикт |
|---|---|---|---|
| `GET /api/sessions/C:%5CWindows/file/win.ini` | 200 `text/plain`, содержимое `C:\Windows\win.ini` | 404 `{"error":"сессия C:\\Windows не найдена"}` | PASS |
| `GET /api/sessions/C:%2FWindows/file/win.ini` | 200 | 404 | PASS |
| `GET /api/sessions/../file/engine/Cargo.toml` | 200 `[package] name = "ftdi-logger"` | 404 | PASS |
| `GET /api/sessions/D:%5CFTDI_USB_Logger/file/README.md` | 200, README | 404 | PASS |
| `GET /api/sessions/<реальная>/file/shots/01-step-01.png` | 200 image/png | 200 image/png (не сломали) | PASS |

Причина: `session_file()` брал `:id` из URL и вызывал `store.dir_for(id) = sessions_root.join(id)`;
для `C:\Windows` `Path::join` уходит в абсолютный путь, а проверка `canonical.starts_with(base)`
сравнивала файл с тем же (атакующим) `base`. Исправлено: `id` резолвится только через
`SessionStore::get` (существующий id из индекса), затем `dir_for(meta.id)`; регрессия —
`engine/tests/api_smoke.rs`. Других мест, где `Path(id)` попадает в `dir_for/join`, в `api.rs`
не осталось (проверено grep по `engine/src`).
'@

# ───────────────────────────── проверка фиксов ───────────────────────────
$fixRows = @(
    ('| 1 | `session_file`: id-траверсал (только id из индекса) | FILE-07 | ' + (Scrub (FactOf 'FILE-07') 240) + ' | **' + (VerdictOf 'FILE-07') + '** |'),
    ('| 2 | Строгий CORS: host ровно 127.0.0.1/localhost/[::1], userinfo запрещён | CORS-01…04 | ' + (Scrub (FactOf 'CORS-01') 180) + '; ' + (Scrub (FactOf 'CORS-02') 160) + ' | **' + (VerdictOf 'CORS-01') + '** |'),
    ('| 3 | `store.rs`: убран дедуп подряд идущих строк `raw.log` | RAW-01 | ' + (Scrub (FactOf 'RAW-01') 240) + ' | **' + (VerdictOf 'RAW-01') + '** |'),
    ('| 4 | `decode.rs`: паника `frame[2]` при `ln=2` сужена до `ln>=3` | DEC-01 | ' + (Scrub (FactOf 'DEC-01') 240) + ' | **' + (VerdictOf 'DEC-01') + '** |'),
    ('| 5 | `raw.log` живого захвата: `# MARK … START/END N: имя`, блок `# PHASE`, последняя строка `# PHASE-JSON` | CAP-18 | ' + (Scrub (FactOf 'CAP-18') 260) + ' | **' + (VerdictOf 'CAP-18') + '** |')
)
$fixes = @'
## 4. Проверка исправлений, сделанных по ходу тестирования

Все исправления подтверждены на финальной сборке `engine\target\debug\ftdi-logger.exe`
от 2026-11-09 13:17:21; штатная отдача файлов сессии не задета (FILE-05: PNG 200).

| # | Исправление | Кейсы | Факт (сборка 13:17) | Вердикт |
|---|---|---|---|---|
'@ + ($fixRows -join "`n")

# ───────────────────────────── дефекты ───────────────────────────────────
$bugsSection = @'
## 5. Найденные дефекты (9 BUG-строк = 7 разных дефектов)

| # | Приоритет | Кейсы | Дефект | Ожидание | Вердикт |
|---|---|---|---|---|---|
| B1 | **важно** | API-01 | Несуществующий `session_id` → HTTP 500 вместо 404 (6 ручек) | 404 + `{"error":…}` | BUG |
| B2 | **важно** | CAP-05 | `attach` к pid=4 возвращает 200 и оставляет сессию в `recording` с мёртвым мостом (висяк) | 4xx/5xx или self-abort сессии | BUG |
| B3 | **важно** | UI-01 | UI без движка — пустой экран без ошибки (сообщение пишется в удалённый `#boot`) | Понятный экран ошибки + кнопки | BUG |
| B4 | мелочь | IMP-06 | Имя сессии при `upload` = `ftdi-import-<pid>-<uuid>-…`, юникод → `_` | label = имя загруженного файла | BUG |
| B5 | мелочь | CAP-02 | `hookctl` до `attach` → HTTP 500 вместо 4xx | 409 + `{"error":…}` | BUG |
| B6 | мелочь | API-12 | `DELETE` несуществующей сессии → 200 `{"ok":true}` | 404 | BUG |
| B7 | мелочь | API-07, API-09, API-15 | Ошибки разбора тела/запроса — `text/plain`, а не `{"error":…}` | 4xx + `{"error":…}` | BUG ×3 |

### B1. Несуществующий session_id → 500 (важно)

Факт: `GET /api/sessions/edge-no-such-session`, `/events`, `/report`, `/steps/1`,
`/events/0/decode` и `POST /reparse` вернули **500** `{"error":"сессия edge-no-such-session не найдена"}`
(API-01). Ожидание по `docs/02-architecture.md` §6: 404.

```bash
curl -i http://127.0.0.1:7831/api/sessions/edge-no-such-session
curl -i http://127.0.0.1:7831/api/sessions/edge-no-such-session/events
curl -i -X POST http://127.0.0.1:7831/api/sessions/edge-no-such-session/reparse -d '{}'
```

Причина: `st.store.reader(&id)?` в обработчиках; `SessionStore::reader` возвращает `anyhow::Error`,
а `AppError::from(anyhow::Error)` всегда даёт `INTERNAL_SERVER_ERROR`. Лечение: `store.get(id)`
до `reader` и `AppError::not_found(...)` (или typed-error в `reader`). Задевает `session_detail`,
`session_events`, `event_decode`, `event_context`, `step_detail`, `session_report`,
`session_reparse`, `session_export`, `session_share`.

### B2. attach pid=4: 200 + «висящая» recording-сессия (важно)

CAP-05: `POST /api/capture/attach {"pid":4,"label":"edge-system"}` → **HTTP 200**, сессия
`…-edge-system`, `status=recording`; через 4 с `GET /api/capture/status`:
`recording=true, bridge=false, hooks=off`; повторный `attach` → 409 «сессия уже идёт».
`detach` вручную закрывает сессию как `finished` (CAP-07), скриншот без окна даёт понятную
ошибку (CAP-06). То есть пользователь видит успешный старт захвата, которого нет.

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Attaching: POST /api/capture/attach (pid=4)
    Attaching --> Recording: ответ 200 (движок не ждёт ready)
    Recording --> Recording: Frida attach упала → error-event, сессия не абортится
    Recording --> Finished: ручной detach
    Attaching --> Aborted: ожидаемое поведение при фатальной ошибке моста
```

Воспроизведение:

```bash
curl -X POST http://127.0.0.1:7831/api/capture/attach -H "Content-Type: application/json" -d "{\"pid\":4}"
curl http://127.0.0.1:7831/api/capture/status
# повторно: attach → 409 «сессия уже идёт»
```

Причина: `CaptureManager::attach` создаёт сессию и возвращает `Ok(meta)` сразу после записи
`{"cmd":"attach"}` в sidecar, не дожидаясь `ready`; фатальная ошибка Frida приходит
асинхронно (`BridgeMsg::Error{fatal:true}`) и пишется только error-событием/тостом, но
`shared.active` не очищается и `status` сессии не меняется. Лечение: дождаться `ready` или
фатальной ошибки с таймаутом до 200; при `fatal` — `abort` сессии (`status="aborted"`) и
`clear_shared`, вернуть код ошибки вызывающему.

### B3. UI без движка: пустой экран вместо ошибки (важно)

UI-01: статика `ui/dist` на `python -m http.server 8101`, движок не запущен. Через 3.5 с:
`#boot` в DOM отсутствует, `#app` виден, панели пустые, текста ошибки и кнопок «повторить
подключение»/«демо-режим» нет. Скриншот: `tests/e2e/edge/out/ui-01-no-engine.png`.

Причина: `ui/src/main.ts` вызывает `build()` (внутри `boot.remove()`) до `await store.init()`;
при ошибке `showBootError()` пишет сообщение и кнопки в уже откреплённый `#boot-text` —
в DOM они не попадают. Плюс `bootError` для 404 от `http.server` содержит весь HTML-текст
404-страницы, а не короткое сообщение. Лечение: не удалять `#boot` до успешного `init()`
(или рендерить ошибку внутрь `#app`/пересоздавать boot); ошибку `res.ok` приводить к
короткому тексту.

Воспроизведение:

```bash
python -m http.server 8101 --bind 127.0.0.1 --directory ui/dist
# движок НЕ запущен; открыть http://127.0.0.1:8101/ в Edge
# ожидание: экран ошибки; факт: пустой каркас UI
```

### B4. Имя сессии при upload: течёт temp-путь/PID/UUID, юникод режется (мелочь)

IMP-06: upload `name=лог с пробелами — 测试-файл.log` → label
`ftdi-import-<enginePid>-<uuid>-____________________-____`,
id `ftdi-import-<enginePid>-<uuid>-20261109-131956` (IMP-05/06).
Причина: `import_upload` пишет тело во временный файл `ftdi-import-<pid>-<uuid>-<safe_name>`
и вызывает `import_legacy_log(store, &tmp, None)`; метка берётся из `file_stem()` временного
файла. `safe_upload_name` заменяет все не-ASCII символы на `_`. Лечение: передавать исходное
имя как `label`; для имени копии достаточно убрать разделители пути, сохранив UTF-8.

### B5. hookctl до attach → 500 (мелочь)

CAP-02: `POST /api/capture/hookctl {"value":"pause"}` без активной сессии → **500**
`{"error":"мост не запущен — управление хуками недоступно"}`. Ожидание: 409/400 с
`{"error":…}`. Причина: `capture_hookctl` использует `st.capture.hookctl(...).await?`
без маппинга в конфликт, `anyhow` → 500.

### B6. DELETE несуществующей сессии → 200 (мелочь)

API-12: `DELETE /api/sessions/edge-no-such-session` → 200 `{"ok":true}`.
Ожидание: 404. Причина: `SessionStore::delete` не проверяет наличие сессии (удаляет каталог,
если он есть, и фильтрует индекс, всегда возвращая `Ok`). Попутно перезаписывает `index.json`.

### B7. Ошибки разбора запроса — text/plain вместо JSON (мелочь)

| Кейс | Запрос | Факт |
|---|---|---|
| API-07 | `POST /api/capture/attach` с `{"pid":123,` | 400 `text/plain: Failed to parse the request body as JSON…` |
| API-09 | тот же запрос с `Content-Type: text/plain` | 415 `text/plain: Expected request with Content-Type: application/json` |
| API-15 | `GET /events?limit=abc` | 400 `text/plain: Failed to deserialize query string…` |

Ожидание (docs/02 §6): «Все ответы — JSON», ошибки 4xx/5xx + `{"error": …}`.
Причина: rejections экстракторов axum (`Json`, `Query`, `Path`) отдаются как plain text.
Лечение: кастомные `FromRequest`/`FromRequestParts` или `handle_rejection`, приводящие
любой 4xx/5xx к `{"error": "…"}`.
'@

# ───────────────────────────── долгий поток ──────────────────────────────
$bigRow = $byId["BIG-01"]
$uiBigRow = $byId["UI-08"]
$bigFacts = if ($bigRow) { $bigRow.fact } else { "BIG-01 пропущен" }
$uiBigFacts = if ($uiBigRow) { $uiBigRow.fact } else { "UI-08 пропущен" }
function Metric([string]$pattern, [string]$text, [int]$group = 1) {
    $m = [regex]::Match([string]$text, $pattern)
    if ($m.Success) { return $m.Groups[$group].Value } else { return "—" }
}
$scrollMs = if ($uiBigRow) { (@([regex]::Matches([string]$uiBigFacts, '"ms":(\d+)') | ForEach-Object { $_.Groups[1].Value }) -join '/') } else { "—" }
$evalMs = Metric 'eval\(ms\)=\[([^\]]+)\]' $uiBigFacts
$big = @'
## 6. Долгий поток: импорт 100 МБ и UI на большой сессии

Лог: `E:\Replica\MS45-Quickflash-capture-20261103-122230.log` (100 091 109 B, 1 914 832 строки),
копия в `%TEMP%` и `POST /api/import/upload`. Движок — debug-сборка, поэтому абсолютные числа
ниже относятся к debug, не к release.

| Метрика | Значение | Вывод |
|---|---|---|
| Импорт upload → 200 | __IMPMS__ мс | укладывается в минуты; таймаут 600 с не достигнут |
| Событий в сессии | __EVENTS__ | все строки лога разобраны |
| RSS движка (пик) | __RSS__ МБ | пик на разборе+записи JSONL, затем сбрасывается |
| `GET /api/health` во время импорта | max __HEALTH__ мс | HTTP не блокируется импортом |
| `GET /events?limit=1000` (хвост) | __PAGEMS__ мс | чтение по `events.idx`, без пересчёта потока |
| Report на большой сессии | __REPMS__ мс | отчёт собирается по шагам, не по 1.9M событий |
| UI: открытие сессии | __OPENMS__ мс | грузится хвост 3000 событий |
| UI: прокрутка вверх (loadOlder ×3) | __SCROLLMS__ мс | 3 подгрузки по 3000 без зависаний |
| UI: простой eval после прокрутки | __EVALMS__ мс | вкладка отзывчива |
| JS-исключения в UI | 0 | — |

Факты целиком:

- `BIG-01`: __BIGFACT__
- `UI-08`: __UIBIGFACT__

Диск: `sessions/<id>/events.jsonl` ≈ 437 МБ, `raw.log` ≈ 75 МБ, `import/<исходник>` 100 МБ;
после прогона сессия удалена (CLEAN-01), пик занятости ≈ 1.5 ГБ.
'@
$big = $big.Replace('__IMPMS__', (Metric 'upload=(\d+) мс' $bigFacts)).
    Replace('__EVENTS__', (Metric 'событий=(\d+)' $bigFacts)).
    Replace('__RSS__', (Metric 'RSS peak=(\d+) МБ' $bigFacts)).
    Replace('__HEALTH__', (Metric 'health max=(\d+) мс' $bigFacts)).
    Replace('__PAGEMS__', (Metric 'events\(1000\)=\d+ за (\d+) мс' $bigFacts)).
    Replace('__REPMS__', (Metric 'report=\d+ за (\d+) мс' $bigFacts)).
    Replace('__OPENMS__', (Metric 'открытие=(\d+) мс' $uiBigFacts)).
    Replace('__SCROLLMS__', $scrollMs).
    Replace('__EVALMS__', $evalMs).
    Replace('__BIGFACT__', (Scrub $bigFacts 700)).
    Replace('__UIBIGFACT__', (Scrub $uiBigFacts 700))

# ───────────────────────────── наблюдения ────────────────────────────────
$observations = @'
## 7. Наблюдения и риски (не классифицированы как дефекты)

| Наблюдение | Кейс | Что значит |
|---|---|---|
| Бинарный мусор 1 МБ импортируется без ошибки: 4077 событий `kind=raw` | IMP-03 | нет детекта «это не текстовый лог»; raw-fallback сохраняет любые строки — можно засорить список. Рекомендация: предупреждение или 4xx при доле непарсимых строк выше порога |
| Пустой файл: upload → 400, а `POST /api/import {"path":…}` → 200 и пустая сессия | IMP-01/IMP-11 | разное поведение двух импортов; стоит согласовать |
| `limit=0` клампится к 1, `limit=1000000` — к 10000 | API-04/05 | контракт не документирует кламп; UI никогда не шлёт 0 |
| `mark` с пустым title и `note` с пустым текстом принимаются (200) | CAP-14/15 | серверной валидации нет; UI такие значения не отправляет. Через API возможны мусорные события |
| `step/start` при уже открытом шаге автоматически закрывает предыдущий | проба вручную | ожидаемое поведение, дублей `steps/NN.json` нет |
| Два таба с одной сессией: обе вкладки получают WS-подписку, total одинаковый | UI-07 | регрессий нет |
| Все фильтры в ноль: пустое состояние, `canvas=0px` | UI-05 | без падений/отрицательных высот |
| Resize 800×600: `scrollWidth=800` | UI-06 | горизонтального скролла нет |
| CORS: `127.0.0.1.evil.com`, `localhost.evil.com`, userinfo — без ACAO; легальные origin — с ACAO | CORS-01…04 | строгий предикат работает |
| Во время импорта движок отвечает на `/api/health` (max 41 мс), UI не падает | BIG-01/UI-08 | блокировки UI на 100 МБ логе не видно |

### Что проверено «вручную» сверх автотестов

- `step/start` + `step/end` в живой сессии (dummy_target): сводка `steps/01.json`, скриншот
  при наличии окна; без окна — понятная ошибка (CAP-06).
- `raw.log` живого захвата: `# MARK … START/END N: имя`, блок `# PHASE …`, последняя строка
  `# PHASE-JSON {…}` (CAP-18).
- Импорт `raw.log` обратно: `raw.log` строится из `ev.to_legacy_line()`, поэтому импорт
  идемпотентен по числу событий (RAW-01: 4033 = 4033).
'@

# ───────────────────────────── чистка ────────────────────────────────────
$clean = @'
## 8. Чистка и состояние sessions/

`CLEAN-01` — **__CLEANVERDICT__**: __CLEANFACT__

- Тестовый прогон сам удаляет созданные им сессии (и `export/`, `shots/`, `import/` внутри них):
  17/17 удалены, `sessions/index.json` валиден, каталогов-сирот нет.
- Сессии, созданные другими агентами/до прогона, не трогались (baseline в начале прогона),
  «базовых потеряно=0».
- Движок после прогона остановлен; sidecar/статика/Edge/dummy-цели погашены.
- Ручная чистка не требуется: на момент отчёта тестовых сессий этого прогона в `sessions/` нет.
  В каталоге могут оставаться сессии других тестов (например `*-raw-live`, `winkfp-*` от
  параллельных агентов) — это не мусор этого прогона.
'@
$clean = $clean.Replace('__CLEANVERDICT__', (VerdictOf 'CLEAN-01')).Replace('__CLEANFACT__', ((Scrub (FactOf 'CLEAN-01') 520) -replace ' \(\)', ''))

# ───────────────────────────── howto ─────────────────────────────────────
$howto = @'
## 9. Как воспроизвести

Требования: Windows x64, собранный `engine\target\debug\ftdi-logger.exe` (debug), Node.js 22+
(глобальный `WebSocket`), Edge (`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`),
Python 3.12 с `frida` (для live-capture кейсов), свободные порты 7831/8101/9335.
Для BIG-01 — файл `E:\Replica\MS45-Quickflash-capture-20261103-122230.log`.

```powershell
# всё: API + импорт 100 МБ + UI (≈6 минут; 70 кейсов)
pwsh -File tests\e2e\edge\run-edge.ps1

# быстрее: без 100 МБ и без UI
pwsh -File tests\e2e\edge\run-edge.ps1 -SkipBig -SkipUi

# оставить движок после прогона (порт 7831) для ручной проверки
pwsh -File tests\e2e\edge\run-edge.ps1 -KeepEngine -SkipBig

# только UI-часть, против уже запущенного движка и статики
python -m http.server 8101 --bind 127.0.0.1 --directory ui\dist
node tests\e2e\edge\cdp-edge.mjs `
  --static http://127.0.0.1:8101/ `
  --engine http://127.0.0.1:7831/ `
  --out tests\e2e\edge\out `
  --cdp-port 9335 `
  --known-session winkfp-20261109-122608

# пересобрать этот отчёт из results.json
pwsh -File tests\e2e\edge\make-report.ps1
```

| Путь | Что это |
|---|---|
| `tests/e2e/edge/run-edge.ps1` | основной прогон: engine → импорт/API/захват/файлы/100 МБ → UI → чистка |
| `tests/e2e/edge/cdp-edge.mjs` | UI-проверки через CDP (Edge headless), без внешних зависимостей |
| `tests/e2e/edge/make-report.ps1` | генератор этого отчёта из `out/results.json` |
| `tests/e2e/edge/out/results.json` | машинный результат (все кейсы, факты, repro, вердикты) |
| `tests/e2e/edge/out/results.csv` | то же в CSV |
| `tests/e2e/edge/out/summary.txt` | краткий итог и список BUG |
| `tests/e2e/edge/out/ui-*.png` | скриншоты UI-кейсов (01 — пустой экран без движка, 08 — большая сессия) |
| `tests/e2e/edge/out/engine.err.log`, `engine-exit-code.txt` | диагностика, если движок умер (INFRA-01) |

Особенности раннера:

- движок запускается **из уникальной копии** exe в `%TEMP%` (не из `target\debug`):
  на общей машине параллельные агенты убивают процессы по имени `ftdi-logger.exe` и
  пересобирают target; копия это переживает. `-UseOriginalExe` — запускать оригинал.
- после каждой секции проверяется «движок жив»; внешнее убийство фиксируется как `INFRA-01`
  (FAIL), а не как десятки ложных BUG с HTTP 0.
- все созданные сессии удаляются в конце; `-NoCleanup` — оставить, `-KeepEngine` — оставить движок.
'@

# ───────────────────────────── ограничения ───────────────────────────────
$limits = @'
## 10. Ограничения прогона

- **Нет реального FTDI-обмена.** Живой захват проверен на `tests/e2e/dummy_target.py`
  (грузит `FTD2XX.DLL`, делает `FT_CreateDeviceInfoList`/`FT_ListDevices`) и на окно-независимой
  цели `pythonw`. Реальный Quickflash/WinKFP с записью/чтением ЭБУ не воспроизводился.
- **pid=4 (System)** — поведение Frida на этой машине/Windows; на другой сборке Frida текст
  ошибки может быть иным, но дефект B2 (200 + висяк) воспроизводится здесь детерминированно.
- UI-тесты — Edge headless через CDP; проверяются DOM-состояния/состояние store/скриншоты,
  визуальный дизайн и доступность не оценивались.
- Числа BIG-01 — debug-сборка; release может быть заметно быстрее.
- BIG-01 опционально пропускается, если нет `E:\Replica\MS45-….log` (`-SkipBig`).
- `sessions/` — общий каталог: параллельные агенты могут добавить свои сессии во время прогона;
  baseline фиксируется в начале, чужие сессии не удаляются.
- Пропускная способность/потери WS при 100 МБ живого потока не проверялись (нужен реальный
  источник событий); на импорте WS не задействован.
'@

$tail = @'
## 11. Полная таблица кейсов

'@ + $tableText + @'

## 12. Чек-лист приёмки

- [x] Импорт: пусто/CRLF/бинарь/5+МБ/unicode/traversal/повтор/параллель — проверен
- [x] API-мусор: несуществующий id, seq, from>to, limit, kinds, битый JSON, лишние поля, Content-Type, форматы, DELETE, методы — проверен
- [x] Захват без устройства: pid 0/4/999999, двойной attach, detach/step/hookctl/mark/note/shot без сессии — проверен
- [x] Файлы: traversal в *path и :id, 404, отдача PNG реальной сессии — проверен
- [x] UI без движка, demo, быстрые F2, пустой поиск, нулевые фильтры, resize, два таба — проверен
- [x] 100 МБ: время, пик RSS, отзывчивость health, UI-прокрутка — измерено
- [ ] Исправить B1–B7 (см. раздел 5) — за рамками задачи, нужна правка движка/UI
- [x] Чистка: тестовые сессии удалены, чужие не тронуты
'@

$doc = @($header, $blocker, $fixes, $bugsSection, $big, $observations, $clean, $howto, $limits, $tail) -join "`n`n"
[System.IO.File]::WriteAllText($OutFile, $doc, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "отчёт: $OutFile"
Write-Host "кейсов: $($rows.Count); PASS=$pass; BUG=$($bugs.Count); FAIL=$($fails.Count)"


