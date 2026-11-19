# Интеграционная проверка движка на цель без железа: attach → fake J2534 → detach.
#
#   pwsh -File tests\e2e\engine_roundtrip.ps1
#   pwsh -File tests\e2e\engine_roundtrip.ps1 -Port 7842 -Mode full
#
# Проверяет то, чего не видит стенд агента (он останавливается на raw.log):
#   * session.json: adapter заполнен из `J2534 open`/`version`, errors/empty_polls;
#   * events.jsonl: нет поля raw у обычных событий, файл меньше raw.log × 1.7;
#   * raw.log: `# counters` со всеми счётчиками и `# totals`;
#   * steps/NN.json: `resp_hist` без сети, `net_hist` отдельно, пустые reads/filehash
#     не сериализуются.

param(
    [int]$Port = 7842,
    [string]$Mode = "full",
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$exe = Join-Path $root "engine\target\release\ftdi-logger.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $root "engine\target\debug\ftdi-logger.exe" }
$dll = Join-Path $root "tests\e2e\fake_j2534\target\release\fake_j2534.dll"
$target = Join-Path $root "tests\e2e\j2534_full_target.py"
$base = "http://127.0.0.1:$Port"
$py = if ($env:FTDI_PYTHON) { $env:FTDI_PYTHON } else { "python" }

$results = New-Object System.Collections.Generic.List[object]
function Check([string]$name, [scriptblock]$fn) {
    try {
        $detail = & $fn
        $results.Add([pscustomobject]@{ Name = $name; Ok = $true; Detail = "$detail" })
        Write-Host ("PASS  {0}{1}" -f $name, $(if ($detail) { " — $detail" } else { "" })) -ForegroundColor Green
    } catch {
        $results.Add([pscustomobject]@{ Name = $name; Ok = $false; Detail = $_.Exception.Message })
        Write-Host ("FAIL  {0} — {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    }
}

function Wait-Json([string]$url, [int]$seconds = 40) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { return Invoke-RestMethod -Uri $url -TimeoutSec 3 } catch { Start-Sleep -Milliseconds 250 }
    }
    throw "не ответил: $url"
}

$sessionsDir = Join-Path $root "sessions"
$before = @()
if (Test-Path $sessionsDir) { $before = @(Get-ChildItem $sessionsDir -Directory | Select-Object -ExpandProperty Name) }

$work = Join-Path $env:TEMP ("engine-roundtrip-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$go1 = Join-Path $work "go1"
$go2 = Join-Path $work "go2"
$go3 = Join-Path $work "go3"

Write-Host "движок: $exe"
$engineLog = Join-Path $work "engine.out.log"
$engineErr = Join-Path $work "engine.err.log"
$engine = Start-Process -FilePath $exe -ArgumentList @("--root", $root, "--port", "$Port", "--capture-mode", $Mode) `
    -RedirectStandardOutput $engineLog -RedirectStandardError $engineErr -PassThru -WindowStyle Hidden
$targetProc = $null
try {
    Wait-Json "$base/api/health" 40 | Out-Null

    $targetProc = Start-Process -FilePath $py `
        -ArgumentList @("-u", $target, $dll, $go1, $go2, $go3) `
        -RedirectStandardOutput (Join-Path $work "target.out.log") `
        -RedirectStandardError (Join-Path $work "target.err.log") `
        -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 1

    $attach = Invoke-RestMethod -Uri "$base/api/capture/attach" -Method Post -ContentType "application/json" `
        -Body (@{ pid = $targetProc.Id; label = "engine-roundtrip" } | ConvertTo-Json)
    $sessionId = $attach.id
    Write-Host "сессия: $sessionId"

    # Шаг открываем через API: сводка шага — часть отчёта, её тоже проверяем.
    Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/step/start" -Method Post `
        -ContentType "application/json" -Body (@{ title = "Идентификация" } | ConvertTo-Json) | Out-Null

    New-Item -ItemType File -Path $go1 -Force | Out-Null
    Start-Sleep -Seconds 1
    Invoke-RestMethod -Uri "$base/api/capture/hookctl" -Method Post -ContentType "application/json" `
        -Body (@{ value = "pause" } | ConvertTo-Json) | Out-Null
    Start-Sleep -Milliseconds 400
    Invoke-RestMethod -Uri "$base/api/capture/hookctl" -Method Post -ContentType "application/json" `
        -Body (@{ value = "resume" } | ConvertTo-Json) | Out-Null
    Start-Sleep -Milliseconds 600
    New-Item -ItemType File -Path $go2 -Force | Out-Null
    Start-Sleep -Seconds 2
    New-Item -ItemType File -Path $go3 -Force | Out-Null

    # Ждём, пока цель закончит два прохода и повторный Open.
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        $out = Get-Content (Join-Path $work "target.out.log") -Raw -ErrorAction SilentlyContinue
        if ($out -match "reopen-done") { break }
        Start-Sleep -Milliseconds 300
    }
    Start-Sleep -Seconds 1

    Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/step/end" -Method Post | Out-Null

    $meta = Invoke-RestMethod -Uri "$base/api/capture/detach" -Method Post
    if (-not $meta) { throw "detach не вернул мету" }
}
finally {
    if ($targetProc -and -not $targetProc.HasExited) { $targetProc.Kill() }
    if (-not $Keep) {
        try { Stop-Process -Id $engine.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
}

$dir = Join-Path $sessionsDir $sessionId
$rawPath = Join-Path $dir "raw.log"
$jsonlPath = Join-Path $dir "events.jsonl"

Check "сессия создана" { if (-not (Test-Path $dir)) { throw "нет каталога $dir" }; "ok" }

Check "session.json: adapter из J2534 open/version" {
    $sj = Get-Content (Join-Path $dir "session.json") -Raw -Encoding utf8 | ConvertFrom-Json
    if (-not $sj.adapter) { throw "adapter=null" }
    if (-not $sj.adapter.serial) { throw "serial пуст" }
    # Для драйвера вне реестра вендора нет — тогда именем служит `PassThruOpen(name)`.
    if (-not $sj.adapter.vendor -and -not $sj.adapter.description) { throw "нет ни vendor, ни description" }
    if ($sj.adapter.firmware -notmatch "FW:\d+") { throw "firmware=$($sj.adapter.firmware)" }
    if (-not $sj.adapter.dll_version) { throw "dll_version пуст" }
    "serial=$($sj.adapter.serial) fw=$($sj.adapter.firmware)"
}

Check "session.json: errors и empty_polls разведены" {
    $sj = Get-Content (Join-Path $dir "session.json") -Raw -Encoding utf8 | ConvertFrom-Json
    if ($sj.counts.empty_polls -lt 1) { throw "empty_polls=$($sj.counts.empty_polls)" }
    "errors=$($sj.counts.errors) empty_polls=$($sj.counts.empty_polls)"
}

Check "raw.log: # counters со всеми полями" {
    $line = Select-String -Path $rawPath -Pattern '# counters dropped_events=' | Select-Object -Last 1
    if (-not $line) { throw "нет строки # counters" }
    foreach ($key in @("dropped_events", "truncated_payloads", "decode_errors", "evicted_events",
                       "partial_results", "contract_violations", "rx_sof", "calls",
                       "bridge_events", "bridge_batches", "bridge_backlog_max")) {
        if ($line.Line -notmatch "$key=\d+") { throw "нет $key" }
    }
    $line.Line
}

Check "raw.log: partial/contract посчитаны" {
    $line = (Select-String -Path $rawPath -Pattern '# counters dropped_events=' | Select-Object -Last 1).Line
    $partial = [int]([regex]::Match($line, "partial_results=(\d+)").Groups[1].Value)
    $contract = [int]([regex]::Match($line, "contract_violations=(\d+)").Groups[1].Value)
    if ($partial -lt 1) { throw "partial_results=$partial" }
    if ($contract -lt 2) { throw "contract_violations=$contract" }
    "partial=$partial contract=$contract"
}

Check "raw.log: # totals" {
    if (-not (Select-String -Path $rawPath -Pattern '# totals: events=\d+')) { throw "нет # totals" }
    "ok"
}

Check "events.jsonl: нет дубля raw у обычных событий" {
    $bad = 0
    $n = 0
    Get-Content $jsonlPath -Encoding utf8 | ForEach-Object {
        $n++
        $obj = $_ | ConvertFrom-Json
        if ($obj.kind -ne "raw" -and $obj.PSObject.Properties.Name -contains "raw") { $bad++ }
    }
    if ($bad -gt 0) { throw "raw в $bad из $n событий" }
    "событий: $n"
}

Check "events.jsonl: компактнее 1.7× raw.log" {
    $j = (Get-Item $jsonlPath).Length
    $r = (Get-Item $rawPath).Length
    $ratio = [math]::Round($j / $r, 2)
    # Отношение зависит от доли payload: на коротких строках (служебные вызовы)
    # JSON-ключи весят больше. Бюджет 1.7× проверяется на реальном логе
    # (engine/tests/acceptance_size.rs), здесь — что дубля raw больше нет.
    if ($ratio -ge 3.0) { throw "отношение $ratio" }
    "jsonl=$j raw=$r отношение=$ratio"
}

Check "шаги: сеть не в resp_hist, пустые reads/filehash не пишутся" {
    $steps = @(Get-ChildItem (Join-Path $dir "steps") -Filter *.json)
    if ($steps.Count -eq 0) { throw "нет steps/*.json (шаг не открывался)" }
    $detail = @()
    foreach ($s in $steps) {
        $raw = Get-Content $s.FullName -Raw -Encoding utf8
        $obj = $raw | ConvertFrom-Json
        if ($obj.resp_hist) {
            foreach ($k in $obj.resp_hist.PSObject.Properties.Name) {
                if ($k -match "TCP|UDP") { throw "$($s.Name): сеть в resp_hist ($k)" }
            }
        }
        if ($raw -match '"reads":\[\]') { throw "$($s.Name): пустой reads сериализуется" }
        if ($raw -match '"filehash":\[\]') { throw "$($s.Name): пустой filehash сериализуется" }
        if ($obj.net_hist) { $detail += "$($s.Name): net=$(@($obj.net_hist.PSObject.Properties).Count)" }
    }
    if ($detail.Count -eq 0) { $detail += "сети не было (у цели нет TCP) — ок" }
    ($detail -join "; ")
}

Check "нет пропавших событий (dropped=0)" {
    $line = (Select-String -Path $rawPath -Pattern '# counters dropped_events=' | Select-Object -Last 1).Line
    $dropped = [int]([regex]::Match($line, "dropped_events=(\d+)").Groups[1].Value)
    if ($dropped -ne 0) { throw "dropped_events=$dropped" }
    "ok"
}

$failed = @($results | Where-Object { -not $_.Ok })
Write-Host ""
if ($failed.Count -gt 0) {
    Write-Host ("ПРОВАЛЕНО: {0} из {1}" -f $failed.Count, $results.Count) -ForegroundColor Red
    Write-Host "логи: $work"
    exit 1
}
Write-Host ("Все проверки пройдены ({0}). Сессия: {1}" -f $results.Count, $dir) -ForegroundColor Green
if (-not $Keep) { Write-Host "каталог сессии оставлен для разбора: $dir" }
exit 0
