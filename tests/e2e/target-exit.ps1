# Проверка: при выходе целевой программы движок сам завершает сессию и отпускает захват.
#
#   pwsh -File tests\e2e\target-exit.ps1
param(
    [int]$Port = 7849,
    [string]$ExePath = "",
    [string]$RootPath = ""
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ExePath) { $ExePath = Join-Path $root "engine\target\debug\ftdi-logger.exe" }
if (-not $RootPath) { $RootPath = $root }
$base = "http://127.0.0.1:$Port"
$py = "C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = (Get-Command python).Source }

$tgt = Start-Process -FilePath $py -ArgumentList @((Join-Path $root "tests\e2e\dummy_target.py"), "--seconds", "120") `
    -WorkingDirectory $root -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 1
$eng = Start-Process -FilePath $ExePath -ArgumentList @("--root", "`"$RootPath`"", "--port", "$Port", "--no-open") `
    -WorkingDirectory $RootPath -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$env:TEMP\target-exit.out.log" -RedirectStandardError "$env:TEMP\target-exit.err.log"
$ok = $false
try {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try { Invoke-RestMethod "$base/api/health" -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Milliseconds 250 }
    }
    $meta = Invoke-RestMethod -Uri "$base/api/capture/attach" -Method Post `
        -Body (@{ pid = $tgt.Id; label = "target-exit e2e" } | ConvertTo-Json) `
        -ContentType "application/json" -TimeoutSec 40
    Write-Host "attach: $($meta.id)"
    Start-Sleep -Seconds 2
    $st = Invoke-RestMethod "$base/api/capture/status" -TimeoutSec 10
    if (-not $st.recording) { throw "сессия не началась" }
    Write-Host "recording before kill: true (target=$($st.target.pid))"

    Stop-Process -Id $tgt.Id -Force
    Write-Host "target killed"

    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 700
        $st = Invoke-RestMethod "$base/api/capture/status" -TimeoutSec 10
        if (-not $st.recording) { break }
    }
    if ($st.recording) { throw "сессия не закрылась после выхода цели" }
    $sess = Invoke-RestMethod "$base/api/sessions/$($meta.id)" -TimeoutSec 10
    Write-Host "after kill: recording=$($st.recording) hooks=$($st.hooks) session=$($sess.meta.status)"
    if ($sess.meta.status -ne "finished" -and $sess.meta.status -ne "aborted") { throw "статус сессии: $($sess.meta.status)" }
    $ok = $true
    Write-Host "PASS  авто-закрытие сессии при выходе цели" -ForegroundColor Green
} finally {
    Stop-Process -Id $eng.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $tgt.Id -Force -ErrorAction SilentlyContinue
}
if (-not $ok) { Get-Content "$env:TEMP\target-exit.err.log" -Tail 15 -ErrorAction SilentlyContinue; exit 1 }
exit 0
