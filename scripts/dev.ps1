#Requires -Version 5.1
<#
    Режим разработки: движок (cargo run, порт 7811) + vite dev для ui/.

    Vite проксирует /api и /ws на движок (см. ui/vite.config.ts), поэтому интерфейс
    открывается с dev-сервера vite, а данные идут из движка.

    Примеры:
        powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
        powershell -ExecutionPolicy Bypass -File scripts\dev.ps1 -Port 7811 -NoVite
#>
[CmdletBinding()]
param(
    [int]$Port = 7811,
    [switch]$NoVite
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$UiDir = Join-Path $Root 'ui'

function Warn([string]$Message) {
    Write-Host ("[dev] ВНИМАНИЕ: " + $Message) -ForegroundColor Yellow
}

function Fail([string]$Message) {
    Write-Host ("[dev] ОШИБКА: " + $Message) -ForegroundColor Red
    exit 1
}

function Resolve-Tool([string[]]$Names) {
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

$cargo = Resolve-Tool @('cargo.exe', 'cargo')
if (-not $cargo) {
    Fail 'cargo не найден. Установите Rust: https://rustup.rs'
}

$vite = $null
if (-not $NoVite) {
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'package.json'))) {
        Fail 'UI не готов: нет ui\package.json (запустите с -NoVite, чтобы поднять только движок).'
    }
    $pnpm = Resolve-Tool @('pnpm.cmd', 'pnpm.exe', 'pnpm')
    if (-not $pnpm) {
        Fail 'pnpm не найден. Установите Node.js 20+ и pnpm (npm install -g pnpm).'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'node_modules'))) {
        Warn 'нет ui\node_modules — при первом старте vite может ругаться. Выполните: pnpm -C ui install'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'vite.config.ts')) -and
        -not (Test-Path -LiteralPath (Join-Path $UiDir 'vite.config.js'))) {
        Warn 'нет ui\vite.config.*: прокси /api и /ws на порт 7811 должен настроить UI-владелец.'
    }
    elseif ((Test-Path -LiteralPath (Join-Path $UiDir 'package.json'))) {
        $pkg = Get-Content -LiteralPath (Join-Path $UiDir 'package.json') -Raw
        $cfgPath = Join-Path $UiDir 'vite.config.ts'
        if (-not (Test-Path -LiteralPath $cfgPath)) { $cfgPath = Join-Path $UiDir 'vite.config.js' }
        $cfg = Get-Content -LiteralPath $cfgPath -Raw
        if (($cfg -notmatch '/api') -or ($cfg -notmatch '/ws')) {
            Warn ('в vite.config нет прокси /api или /ws — dev-интерфейс не увидит движок на порту ' + $Port)
        }
    }

    Write-Host '[dev] стартую vite dev...' -ForegroundColor Cyan
    $vite = Start-Process -FilePath 'cmd.exe' `
        -ArgumentList '/c', 'pnpm -C ui dev' `
        -WorkingDirectory $Root -NoNewWindow -PassThru
    Start-Sleep -Seconds 3
    if ($vite.HasExited) {
        Fail ('vite dev завершился сразу (код ' + $vite.ExitCode + '). Запустите вручную: pnpm -C ui dev')
    }
    Write-Host ('[dev] vite dev pid=' + $vite.Id + ' (адрес смотрите в его выводе выше, обычно http://localhost:5173)')
}
else {
    Write-Host '[dev] vite пропущен (-NoVite): только движок.'
}

try {
    Write-Host ('[dev] движок: http://127.0.0.1:' + $Port + '  (API/WS; UI собранный — если есть ui\dist)') -ForegroundColor Green
    Write-Host '[dev] Ctrl+C — остановить движок и vite.'
    & $cargo run --manifest-path (Join-Path $Root 'engine\Cargo.toml') -- --root $Root --port $Port --no-open
}
finally {
    if ($vite -and -not $vite.HasExited) {
        Write-Host '[dev] останавливаю vite...'
        & taskkill /PID $vite.Id /T /F 2>$null | Out-Null
    }
}
