# E2E-смоук движка: поднять бинарь, проверить API, импортировать реальный лог,
# собрать отчёт и экспорт. Никакого устройства и Frida не требует.
#
#   pwsh -File tests\e2e\smoke.ps1
#   pwsh -File tests\e2e\smoke.ps1 -Port 7833 -Keep

param(
    [int]$Port = 7822,
    [switch]$Keep,
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$engineDir = Join-Path $root "engine"
$exe = Join-Path $engineDir "target\$(if ($Release) {'release'} else {'debug'})\ftdi-logger.exe"
$base = "http://127.0.0.1:$Port"
$results = New-Object System.Collections.Generic.List[object]
$logFile = Join-Path $env:TEMP "ftdi-logger-smoke-$Port.log"

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

function Wait-Http([string]$url, [int]$seconds = 30) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            return Invoke-RestMethod -Uri $url -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "движок не ответил за $seconds с: $url"
}

if (-not (Test-Path $exe)) {
    Write-Host "собираю движок ($exe)…"
    Push-Location $engineDir
    try {
        if ($Release) { cargo build --release } else { cargo build }
    } finally { Pop-Location }
}
if (-not (Test-Path $exe)) { throw "нет бинаря: $exe" }

$proc = Start-Process -FilePath $exe -ArgumentList @(
    "--root", "`"$root`"", "--port", "$Port", "--no-open", "--log-level", "info"
) -WorkingDirectory $root -PassThru -WindowStyle Hidden -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err"

try {
    Check "health отвечает" {
        $h = Wait-Http "$base/api/health"
        if (-not $h.version) { throw "нет поля version" }
        "version=$($h.version) sessions=$($h.sessions) ui_dist=$($h.ui_dist)"
    }

    Check "devices — массив" {
        $d = Invoke-RestMethod "$base/api/devices" -TimeoutSec 10
        if ($null -ne $d -and $d -isnot [array]) { $d = @($d) }
        "устройств: $(@($d).Count)"
    }

    Check "tools — массив" {
        $t = Invoke-RestMethod "$base/api/tools" -TimeoutSec 20
        if ($null -ne $t -and $t -isnot [array]) { $t = @($t) }
        "процессов: $(@($t).Count)"
    }

    $sample = Join-Path $root "reference\logs\winkfp-e2e-capture.log"
    $sessionId = $null
    Check "импорт старого лога (upload)" {
        if (-not (Test-Path $sample)) { throw "нет сэмпла $sample" }
        $name = [uri]::EscapeDataString((Split-Path -Leaf $sample))
        $r = Invoke-RestMethod -Uri "$base/api/import/upload?name=$name" -Method Post -InFile $sample `
            -ContentType "application/octet-stream" -TimeoutSec 120
        if (-not $r.session_id) { throw "нет session_id в ответе" }
        $script:sessionId = $r.session_id
        "session_id=$($r.session_id)"
    }

    Check "сессия в списке" {
        $list = Invoke-RestMethod "$base/api/sessions" -TimeoutSec 10
        $found = @($list) | Where-Object { $_.id -eq $sessionId }
        if (-not $found) { throw "сессии $sessionId нет в /api/sessions" }
        "сессий всего: $(@($list).Count)"
    }

    Check "детали сессии и шаги" {
        $detail = Invoke-RestMethod "$base/api/sessions/$sessionId" -TimeoutSec 20
        if (-not $detail.meta) { throw "нет meta" }
        if ($null -eq $detail.steps) { throw "нет steps" }
        "событий=$($detail.meta.counts.events) шагов=$(@($detail.steps).Count)"
    }

    Check "страница событий" {
        $page = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=500" -TimeoutSec 30
        if (@($page.events).Count -lt 10) { throw "слишком мало событий: $(@($page.events).Count)" }
        $first = @($page.events)[0]
        if (-not $first.kind) { throw "у события нет kind" }
        "событий на странице: $(@($page.events).Count), тип первого: $($first.kind)"
    }

    Check "событие декодируется" {
        $page = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=50" -TimeoutSec 20
        $ev = @($page.events) | Where-Object { $_.hex } | Select-Object -First 1
        if (-not $ev) { return "нет событий с hex — пропуск" }
        $dec = Invoke-RestMethod "$base/api/sessions/$sessionId/events/$($ev.seq)/decode" -TimeoutSec 20
        if ($null -eq $dec.len) { throw "нет len в декоде" }
        "len=$($dec.len) ascii=$($dec.ascii)"
    }

    Check "отчёт собирается" {
        # /report отдаёт text/plain (txt по умолчанию) или text/markdown (?format=md)
        $resp = Invoke-WebRequest "$base/api/sessions/$sessionId/report" -TimeoutSec 60 -UseBasicParsing
        $len = $resp.Content.Length
        if ($len -lt 50) { throw "отчёт пустой ($len символов)" }
        $md = Invoke-WebRequest "$base/api/sessions/$sessionId/report?format=md" -TimeoutSec 60 -UseBasicParsing
        if (-not $md.Content.Contains("##")) { throw "markdown-отчёт без заголовков" }
        "report.txt: $len символов, report.md: $($md.Content.Length) символов"
    }

    $zip = $null
    Check "экспорт ZIP" {
        $r = Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/export" -Method Post -Body '{"format":"zip"}' `
            -ContentType "application/json" -TimeoutSec 120
        if (-not $r.path) { throw "нет path" }
        if (-not (Test-Path $r.path)) { throw "файла нет: $($r.path)" }
        $script:zip = $r.path
        "zip: $((Get-Item $r.path).Length) байт"
    }

    Check "экспорт JSONL и CSV" {
        $j = Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/export" -Method Post -Body '{"format":"jsonl"}' `
            -ContentType "application/json" -TimeoutSec 60
        $c = Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/export" -Method Post -Body '{"format":"csv"}' `
            -ContentType "application/json" -TimeoutSec 60
        if (-not (Test-Path $j.path)) { throw "нет jsonl" }
        if (-not (Test-Path $c.path)) { throw "нет csv" }
        "jsonl=$((Get-Item $j.path).Length) B, csv=$((Get-Item $c.path).Length) B"
    }

    Check "повторный reparse идемпотентен" {
        $before = (Invoke-RestMethod "$base/api/sessions/$sessionId" -TimeoutSec 20).meta.counts.events
        Invoke-RestMethod -Uri "$base/api/sessions/$sessionId/reparse" -Method Post -Body '{}' `
            -ContentType "application/json" -TimeoutSec 120 | Out-Null
        $after = (Invoke-RestMethod "$base/api/sessions/$sessionId" -TimeoutSec 20).meta.counts.events
        if ($before -ne $after) { throw "событий было $before, стало $after" }
        "событий до/после: $before/$after"
    }

    Check "UI отдаётся" {
        $r = Invoke-WebRequest "$base/" -TimeoutSec 10 -UseBasicParsing
        if ($r.StatusCode -ne 200) { throw "HTTP $($r.StatusCode)" }
        if ($r.Content -notmatch "FTDI") { throw "в HTML нет FTDI" }
        "index.html: $($r.RawContentLength) B"
    }

    Check "health после импорта" {
        $h = Wait-Http "$base/api/health"
        if ($h.sessions -lt 1) { throw "sessions=$($h.sessions)" }
        "sessions=$($h.sessions)"
    }
} finally {
    if (-not $Keep) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch { }
        Start-Sleep -Milliseconds 400
    } else {
        Write-Host "движок оставлен на $base (pid $($proc.Id)), лог: $logFile"
    }
}

$failed = @($results | Where-Object { -not $_.Ok }).Count
Write-Host ""
Write-Host ("Итог: {0}/{1} проверок пройдено" -f ($results.Count - $failed), $results.Count)
if ($failed -gt 0) {
    Write-Host "`n--- вывод движка (последние строки) ---"
    if (Test-Path $logFile) { Get-Content $logFile -Tail 30 }
    if (Test-Path "$logFile.err") { Get-Content "$logFile.err" -Tail 30 }
    exit 1
}
exit 0


