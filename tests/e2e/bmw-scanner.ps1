# BMW Scanner 1.4.0 (P.A.Soft): живой e2e — приложение ходит в адаптер через FTDI D2XX.
#
#   pwsh -File tests\e2e\bmw-scanner.ps1
#   pwsh -File tests\e2e\bmw-scanner.ps1 -StartApp -Port 7848
#
# Проверяет: детект процесса по окну, attach к 32-битному Delphi-приложению,
# хуки ftd2xx.dll, поток FT_Write/FT_Read, транспорт ftd2xx в отчёте, detach.
param(
    [int]$Port = 7848,
    [switch]$StartApp,
    [string]$ExePath = "",
    [string]$RootPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ExePath) { $ExePath = Join-Path $root "engine\target\debug\ftdi-logger.exe" }
if (-not $RootPath) { $RootPath = $root }
$base = "http://127.0.0.1:$Port"
$results = New-Object System.Collections.Generic.List[object]

function Check([string]$name, [scriptblock]$fn) {
    try {
        $detail = & $fn
        $results.Add([pscustomobject]@{ Name = $name; Ok = $true })
        Write-Host ("PASS  {0}{1}" -f $name, $(if ($detail) { " — $detail" } else { "" })) -ForegroundColor Green
    } catch {
        $results.Add([pscustomobject]@{ Name = $name; Ok = $false })
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

$app = Get-CimInstance Win32_Process -Filter "Name='BMWScan140.exe'" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $app) {
    if (-not $StartApp) { Write-Host "BMWScan140.exe не запущен (добавьте -StartApp)" -ForegroundColor Yellow; exit 2 }
    $proc = Start-Process -FilePath "C:\BMWScan140\BMWScan140.exe" -WorkingDirectory "C:\BMWScan140" -PassThru
    Start-Sleep -Seconds 6
    $app = Get-CimInstance Win32_Process -Filter "Name='BMWScan140.exe'" | Select-Object -First 1
}
$targetPid = [int]$app.ProcessId
Write-Host "цель: BMWScan140 pid=$targetPid"

$eng = Start-Process -FilePath $ExePath -ArgumentList @("--root", "`"$RootPath`"", "--port", "$Port", "--no-open") `
    -WorkingDirectory $RootPath -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$env:TEMP\bmw-e2e.out.log" -RedirectStandardError "$env:TEMP\bmw-e2e.err.log"
$sessionId = $null
try {
    Check "detect: BMWScan в tools?mode=auto" {
        $tools = Wait-Json "$base/api/tools?mode=auto"
        $hit = @($tools) | Where-Object { $_.pid -eq $targetPid }
        if (-not $hit) { throw "pid $targetPid нет в auto" }
        "caps=$($hit[0].capabilities -join ',')"
    }
    Check "attach к 32-битному Delphi-процессу" {
        $meta = Invoke-RestMethod -Uri "$base/api/capture/attach" -Method Post `
            -Body (@{ pid = $targetPid; label = "BMW Scanner e2e" } | ConvertTo-Json) `
            -ContentType "application/json" -TimeoutSec 60
        $script:sessionId = $meta.id
        "session=$($meta.id) transport=$($meta.transport)"
    }
    Check "ftd2xx.dll захукан, идут FT_Write/FT_Read" {
        $deadline = (Get-Date).AddSeconds(20)
        $tx = @(); $rx = @()
        while ((Get-Date) -lt $deadline) {
            $ev = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=4000" -TimeoutSec 30
            $tx = @($ev.events) | Where-Object { $_.api -eq "FT_Write" }
            $rx = @($ev.events) | Where-Object { $_.api -eq "FT_Read" }
            if ($tx.Count -ge 3 -and $rx.Count -ge 3) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($tx.Count -lt 3) { throw "FT_Write: $($tx.Count)" }
        if ($rx.Count -lt 3) { throw "FT_Read: $($rx.Count)" }
        $sample = ($tx[0].hex + " " + $rx[0].hex).Trim()
        "TX=$($tx.Count) RX=$($rx.Count), пример: $sample"
    }
    Check "отчёт: транспорт ftd2xx, дублей USB TX/RX нет" {
        $det = Invoke-RestMethod -Uri "$base/api/capture/detach" -Method Post -Body '{}' `
            -ContentType "application/json" -TimeoutSec 90
        if (-not $det) { throw "detach null" }
        if ($det.transport -ne "ftd2xx") { throw "transport=$($det.transport)" }
        $raw = Invoke-WebRequest "$base/api/sessions/$sessionId/events?limit=4000" -TimeoutSec 60 -UseBasicParsing
        $usbDup = ([regex]::Matches($raw.Content, '"api":"USB (TX|RX)"')).Count
        if ($usbDup -gt 0) { throw "дубли USB TX/RX: $usbDup" }
        "transport=$($det.transport) tx=$($det.counts.tx) rx=$($det.counts.rx)"
    }
} finally {
    Stop-Process -Id $eng.Id -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object { -not $_.Ok }).Count
Write-Host ""
Write-Host ("Итог: {0}/{1} проверок пройдено" -f ($results.Count - $failed), $results.Count)
if ($sessionId) { Write-Host "сессия: $sessionId" }
if ($failed -gt 0) {
    Get-Content "$env:TEMP\bmw-e2e.err.log" -Tail 15 -ErrorAction SilentlyContinue
    exit 1
}
exit 0
