#Requires -Version 5.1
<#
    Сборка продукта FTDI/USB Logger.

    Итог: dist\FTDI_USB_Logger\
        ftdi-logger.exe   — движок (release)
        ui\dist\          — собранный интерфейс (рядом с exe, как ждёт Config.ui_dist)
        sidecar\          — Python-мост + Frida-агент
        sessions\         — каталог сессий
        logger.cmd        — запуск двойным кликом / с ярлыка

    Примеры:
        powershell -ExecutionPolicy Bypass -File scripts\build.ps1
        powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipUi
        powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipUi -SkipInstall
#>
[CmdletBinding()]
param(
    [switch]$SkipUi,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$UiDir = Join-Path $Root 'ui'
$EngineDir = Join-Path $Root 'engine'
$DistDir = Join-Path $Root 'dist\FTDI_USB_Logger'

function Step([string]$Message) {
    Write-Host ''
    Write-Host ("==> " + $Message) -ForegroundColor Cyan
}

function Warn([string]$Message) {
    Write-Host ("[build] ВНИМАНИЕ: " + $Message) -ForegroundColor Yellow
}

function Fail([string]$Message) {
    Write-Host ''
    Write-Host ("[build] ОШИБКА: " + $Message) -ForegroundColor Red
    exit 1
}

function Resolve-Tool([string[]]$Names) {
    foreach ($name in $Names) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

Set-Location -LiteralPath $Root
Write-Host '=== FTDI/USB Logger: сборка ===' -ForegroundColor Green
Write-Host ("корень:  " + $Root)
Write-Host ("итог:    " + $DistDir)

# ── 0. Обязательные исходники ────────────────────────────────────────────────
Step 'Проверяю исходники'
$required = @(
    (Join-Path $EngineDir 'Cargo.toml'),
    (Join-Path $Root 'sidecar\bridge.py'),
    (Join-Path $Root 'sidecar\agents\ftdi_capture.js'),
    (Join-Path $Root 'logger.cmd')
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path)) {
        Fail ("нет обязательного файла: " + $path)
    }
}

# ── 1. UI ────────────────────────────────────────────────────────────────────
$uiBuilt = $false
$uiDist = Join-Path $UiDir 'dist'
if ($SkipUi) {
    Warn 'UI пропущен (-SkipUi): интерфейс в сборку не попадёт, движок поднимется только с API/WS.'
    if (Test-Path -LiteralPath (Join-Path $uiDist 'index.html')) {
        Warn 'найден старый ui\dist — скопирую его как есть (может быть устаревшим).'
        $uiBuilt = $true
    }
}
else {
    Step 'UI: pnpm -C ui install && pnpm -C ui build'
    if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'package.json'))) {
        Fail ('UI не готов: нет ui\package.json. ' +
              'Либо дождитесь UI-части, либо соберите движок без интерфейса: scripts\build.ps1 -SkipUi')
    }
    $pnpm = Resolve-Tool @('pnpm.cmd', 'pnpm.exe', 'pnpm')
    if (-not $pnpm) {
        Fail ('pnpm не найден в PATH. Установите Node.js 20+ и pnpm (npm install -g pnpm), ' +
              'либо используйте -SkipUi.')
    }
    Write-Host ("pnpm: " + $pnpm)
    if (-not $SkipInstall) {
        & $pnpm -C ui install
        if ($LASTEXITCODE -ne 0) { Fail ('pnpm -C ui install завершился с кодом ' + $LASTEXITCODE) }
    }
    else {
        Warn 'pnpm install пропущен (-SkipInstall): используются текущие ui\node_modules.'
        if (-not (Test-Path -LiteralPath (Join-Path $UiDir 'node_modules'))) {
            Fail 'нет ui\node_modules, а -SkipInstall указан. Уберите -SkipInstall.'
        }
    }
    & $pnpm -C ui build
    if ($LASTEXITCODE -ne 0) { Fail ('pnpm -C ui build завершился с кодом ' + $LASTEXITCODE) }
    if (-not (Test-Path -LiteralPath (Join-Path $uiDist 'index.html'))) {
        Fail 'после pnpm -C ui build не появился ui\dist\index.html — проверьте вывод сборки UI.'
    }
    $uiBuilt = $true
}

# ── 2. Rust-движок ───────────────────────────────────────────────────────────
Step 'Движок: cargo build --release'
$cargo = Resolve-Tool @('cargo.exe', 'cargo')
if (-not $cargo) {
    Fail ('cargo не найден в PATH. Установите Rust: https://rustup.rs (rustup-init.exe), ' +
          'затем перезапустите терминал.')
}
Write-Host ("cargo: " + $cargo)
& $cargo build --release --manifest-path (Join-Path $EngineDir 'Cargo.toml')
if ($LASTEXITCODE -ne 0) { Fail ('cargo build --release завершился с кодом ' + $LASTEXITCODE) }
$engineExe = Join-Path $EngineDir 'target\release\ftdi-logger.exe'
if (-not (Test-Path -LiteralPath $engineExe)) {
    Fail ('сборка прошла, но нет ' + $engineExe)
}

# ── 3. Python + Frida (не фатально: движок умеет жить без моста) ────────────
Step 'Проверяю python + frida для моста'
$python = $null
$pythonCandidates = @(
    $env:FTDI_PYTHON,
    (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python312\python.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
    'C:\Python312\python.exe',
    'C:\Python313\python.exe'
)
foreach ($candidate in $pythonCandidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        $python = $candidate
        break
    }
}
if (-not $python) {
    $pyCmd = Resolve-Tool @('python.exe', 'python')
    if ($pyCmd) { $python = $pyCmd }
}
if (-not $python) {
    Warn ('python не найден: мост (Frida) будет недоступен, UI покажет «мост недоступен». ' +
          'Захват работать не будет, разбор/импорт — будут.')
}
else {
    Write-Host ("python:  " + $python)
    $fridaVersion = & $python -c "import frida; print(frida.__version__)" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Warn ('в ' + $python + ' нет frida. Поставьте: ' + $python +
              ' -m pip install -r sidecar\requirements.txt')
    }
    else {
        Write-Host ("frida:   " + $fridaVersion)
    }
}

# ── 4. Сборка dist ──────────────────────────────────────────────────────────
Step 'Собираю dist'
# Чистим весь dist\, а не только dist\FTDI_USB_Logger: от сломанных запусков
# старого лаунчера там оседают каталоги вида «FTDI_USB_Logger --port 7811».
$DistRoot = Join-Path $Root 'dist'
if (Test-Path -LiteralPath $DistRoot) {
    Remove-Item -LiteralPath $DistRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir 'sessions') -Force | Out-Null

Copy-Item -LiteralPath $engineExe -Destination (Join-Path $DistDir 'ftdi-logger.exe') -Force
Write-Host '  + ftdi-logger.exe'

if ($uiBuilt) {
    $dstUi = Join-Path $DistDir 'ui\dist'
    New-Item -ItemType Directory -Path (Split-Path -Parent $dstUi) -Force | Out-Null
    Copy-Item -LiteralPath $uiDist -Destination $dstUi -Recurse -Force
    Write-Host '  + ui\dist'
}
else {
    Warn 'ui\dist не скопирован — интерфейса в сборке нет.'
}

# sidecar без __pycache__/ *.pyc
$sidecarSrc = Join-Path $Root 'sidecar'
$sidecarDst = Join-Path $DistDir 'sidecar'
& robocopy $sidecarSrc $sidecarDst /E /XD __pycache__ /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { Fail ('robocopy sidecar завершился с кодом ' + $LASTEXITCODE) }
Write-Host '  + sidecar\'

# splash-логотип, иконка приложения и сам splash-скрипт
foreach ($asset in @('splash.png', 'app.ico')) {
    $src = Join-Path $Root ('assets\' + $asset)
    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $DistDir $asset) -Force
        Write-Host ('  + ' + $asset)
    } else {
        Warn ('нет assets\' + $asset + ' — splash/иконка не попадут в dist')
    }
}
$splashScript = Join-Path $Root 'scripts\splash.ps1'
if (Test-Path -LiteralPath $splashScript) {
    Copy-Item -LiteralPath $splashScript -Destination (Join-Path $DistDir 'splash.ps1') -Force
    Write-Host '  + splash.ps1'
}

# logger.cmd самоопределяет раскладку (рядом exe = dist; иначе репозиторий),
# поэтому копируется в dist как есть, без подстановки путей.
Copy-Item -LiteralPath (Join-Path $Root 'logger.cmd') -Destination (Join-Path $DistDir 'logger.cmd') -Force
Write-Host '  + logger.cmd'

# ── 4b. Независимый лаунчер (FTDI_USB_Logger.exe) ───────────────────────────
# Отдельный exe с иконкой, встроенным логотипом (2 c) и UAC-манифестом
# администратора. Именно его запускают ярлыки и установщик.
Step 'Собираю лаунчер'
$launcherScript = Join-Path $Root 'scripts\build-launcher.ps1'
if (Test-Path -LiteralPath $launcherScript) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File $launcherScript -DistDir $DistDir
    if ($LASTEXITCODE -ne 0) { Fail ('build-launcher.ps1 завершился с кодом ' + $LASTEXITCODE) }
    Write-Host '  + FTDI_USB_Logger.exe'
}
else {
    Warn 'нет scripts\build-launcher.ps1 — независимый лаунчер не собран'
}

# ── 5. Итог ─────────────────────────────────────────────────────────────────
Step 'Готово'
$total = 0
Get-ChildItem -LiteralPath $DistDir -Recurse -File | ForEach-Object { $total += $_.Length }
$sizeMb = [Math]::Round($total / 1MB, 1)
Write-Host ("каталог: " + $DistDir + "  (" + $sizeMb + " МБ)")
Write-Host ''
Write-Host 'Запуск:' -ForegroundColor Green
Write-Host ('  scripts\run.ps1                 (или двойной клик по ' + (Join-Path $DistDir 'logger.cmd') + ')')
Write-Host '  http://127.0.0.1:7811           (UI движка)'
Write-Host ('  scripts\dev.ps1                 (движок + vite dev)')
if (-not $uiBuilt) {
    Write-Host ''
    Warn 'Сборка без UI: чтобы получить интерфейс, пересоберите без -SkipUi.'
}
exit 0
