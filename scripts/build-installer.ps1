# Сборка установщика FTDI/USB Logger (per-user, без администратора).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1 -ForceSfx
#
# Основной путь — Inno Setup 6 (ISCC.exe): настоящий мастер установки, иконка
# приложения у Setup.exe, запись в «Установка и удаление программ», штатный
# uninstall, закрытие запущенных процессов перед установкой.
# Если ISCC не найден (или указан -ForceSfx) — запасной путь: 7-Zip SFX.
#
# Требуется Inno Setup 6 (или 7-Zip для запасного пути) и интернет для первого
# скачивания embeddable Python (кешируется в build\cache).
# Результат: dist\FTDI_USB_Logger_Setup.exe
param(
    [switch]$SkipPortable,
    [switch]$ForceSfx,
    [string]$PythonVersion = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root "build"
$InstallerDir = Join-Path $Build "installer"
$Payload = Join-Path $InstallerDir "payload"
$PayloadApp = Join-Path $Payload "FTDI_USB_Logger"
$PortableApp = Join-Path $Build "portable\FTDI_USB_Logger"
$SetupOut = Join-Path $Root "dist\FTDI_USB_Logger_Setup.exe"

# Версия приложения для AppVersion/VersionInfo установщика.
$engineToml = Join-Path $Root "engine\Cargo.toml"
$appVersion = "0.1.0"
if (Test-Path -LiteralPath $engineToml) {
    $toml = Get-Content -LiteralPath $engineToml -Raw
    if ($toml -match '(?m)^version\s*=\s*"([^"]+)"') { $appVersion = $Matches[1] }
}

if (-not $SkipPortable) {
    Write-Host "==> portable-сборка" -ForegroundColor Cyan
    $portableArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Root "scripts\build-portable.ps1"))
    if ($PythonVersion) { $portableArgs += @("-PythonVersion", $PythonVersion) }
    & powershell @portableArgs
    if ($LASTEXITCODE -ne 0) { throw "build-portable.ps1 завершился с кодом $LASTEXITCODE" }
}
if (-not (Test-Path (Join-Path $PortableApp "ftdi-logger.exe"))) { throw "нет portable-сборки: $PortableApp" }
if (-not (Test-Path (Join-Path $PortableApp "FTDI_USB_Logger.exe"))) {
    throw "в portable-сборке нет лаунчера FTDI_USB_Logger.exe — пересоберите scripts\build.ps1 (нужен csc из .NET Framework 4.x)"
}

Write-Host "==> готовлю payload" -ForegroundColor Cyan
if (Test-Path $InstallerDir) { Remove-Item $InstallerDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Payload | Out-Null
& robocopy $PortableApp $PayloadApp /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy payload: $LASTEXITCODE" }

$readme = @"
FTDI/USB Logger — установка

1. Запустите FTDI_USB_Logger_Setup.exe и пройдите мастер.
2. Установка per-user: %LOCALAPPDATA%\FTDI_USB_Logger, права администратора для
   установки не нужны. Ярлыки — на рабочем столе и в меню «Пуск» (можно снять галки).
3. При первом запуске лаунчер FTDI_USB_Logger.exe запросит UAC: движку нужны права
   администратора для Frida-хуков и чтения чужих процессов.
4. Сначала 2 секунды показывается логотип, затем открывается окно журнала.
5. Удаление — «Параметры → Приложения → FTDI/USB Logger» или ярлык
   «Удалить FTDI USB Logger» в меню «Пуск». Сессии в каталоге установки сохраняются.
"@
Set-Content -Path (Join-Path $Payload "README.txt") -Value $readme -Encoding UTF8

# ── Основной путь: Inno Setup 6 ────────────────────────────────────────────
$isccCandidates = @()
if ($env:INNO_SETUP_DIR) { $isccCandidates += (Join-Path $env:INNO_SETUP_DIR "ISCC.exe") }
$isccCandidates += @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$isccCmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($isccCmd) { $isccCandidates += $isccCmd.Source }
$iscc = $isccCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1

if ($iscc -and -not $ForceSfx) {
    Write-Host ("==> Inno Setup: " + $iscc) -ForegroundColor Cyan
    $iss = Join-Path $Root "installer\ftdi-logger.iss"
    if (-not (Test-Path -LiteralPath $iss)) { throw "нет скрипта установщика: $iss" }
    if (Test-Path -LiteralPath $SetupOut) { Remove-Item -LiteralPath $SetupOut -Force }
    & $iscc "/Q" ("/DAppVersion=" + $appVersion) $iss
    if ($LASTEXITCODE -ne 0) { throw "ISCC завершился с кодом $LASTEXITCODE" }
    if (-not (Test-Path -LiteralPath $SetupOut)) { throw "ISCC не создал $SetupOut" }

    $sizeSetup = [Math]::Round((Get-Item -LiteralPath $SetupOut).Length / 1MB, 1)
    Write-Host ""
    Write-Host ("установщик (Inno Setup): " + $SetupOut + "  (" + $sizeSetup + " МБ)") -ForegroundColor Green
    Write-Host ("  версия " + $appVersion + ", per-user установка в %LOCALAPPDATA%\FTDI_USB_Logger")
    Write-Host "  мастер установки, иконка приложения, запись в «Приложения», штатный uninstall"
    exit 0
}

# ── Запасной путь: 7-Zip SFX ───────────────────────────────────────────────
Write-Host "==> ISCC не найден — запасной 7-Zip SFX (установите Inno Setup 6 для нормального мастера)" -ForegroundColor Yellow
$sevenZip = "C:\Program Files\7-Zip\7z.exe"
if (-not (Test-Path $sevenZip)) { $sevenZip = "C:\Program Files (x86)\7-Zip\7z.exe" }
if (-not (Test-Path $sevenZip)) { throw "не найден 7z.exe (установите 7-Zip)" }
$sfxModule = Join-Path (Split-Path -Parent $sevenZip) "7z.sfx"
if (-not (Test-Path $sfxModule)) { throw "не найден 7z.sfx рядом с 7z.exe" }

Copy-Item (Join-Path $Root "scripts\installer\install.cmd") (Join-Path $Payload "install.cmd") -Force
Copy-Item (Join-Path $Root "scripts\installer\install.ps1") (Join-Path $Payload "install.ps1") -Force
Copy-Item (Join-Path $Root "scripts\installer\uninstall.cmd") (Join-Path $PayloadApp "uninstall.cmd") -Force
Copy-Item (Join-Path $Root "scripts\installer\uninstall.ps1") (Join-Path $PayloadApp "uninstall.ps1") -Force

$archive = Join-Path $InstallerDir "payload.7z"
Push-Location $Payload
try {
    & $sevenZip a -t7z -mx=9 $archive * | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z a: $LASTEXITCODE" }
} finally { Pop-Location }

$config = Join-Path $InstallerDir "config.sfx"
$configText = @"
;!@Install@!UTF-8!
Title="FTDI/USB Logger"
BeginPrompt="Установить FTDI/USB Logger?"
RunProgram="install.cmd"
;!@InstallEnd@!
"@
Set-Content -Path $config -Value $configText -Encoding utf8
$sfx = Join-Path $InstallerDir "sfx.exe"
Copy-Item $sfxModule $sfx -Force

if (Test-Path -LiteralPath $SetupOut) { Remove-Item -LiteralPath $SetupOut -Force }
& cmd /c "copy /b `"$sfx`" + `"$config`" + `"$archive`" `"$SetupOut`" >nul"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $SetupOut)) { throw "не удалось собрать setup.exe" }

$sizeSetup = [Math]::Round((Get-Item -LiteralPath $SetupOut).Length / 1MB, 1)
Write-Host ""
Write-Host ("установщик (SFX): " + $SetupOut + "  (" + $sizeSetup + " МБ)") -ForegroundColor Green
Write-Host ("  версия " + $appVersion + ", per-user установка, ярлыки и uninstall-запись")
