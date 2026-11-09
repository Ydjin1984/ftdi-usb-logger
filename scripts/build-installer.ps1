# Сборка установщика FTDI/USB Logger (per-user, без администратора).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-installer.ps1
#
# Требуется 7-Zip (C:\Program Files\7-Zip\7z.exe) и интернет для первого скачивания
# embeddable Python (кешируется в build\cache).
# Результат: dist\FTDI_USB_Logger_Setup.exe
param(
    [switch]$SkipPortable
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Build = Join-Path $Root "build"
$InstallerDir = Join-Path $Build "installer"
$Payload = Join-Path $InstallerDir "payload"
$PayloadApp = Join-Path $Payload "FTDI_USB_Logger"
$PortableApp = Join-Path $Build "portable\FTDI_USB_Logger"

$sevenZip = "C:\Program Files\7-Zip\7z.exe"
if (-not (Test-Path $sevenZip)) { $sevenZip = "C:\Program Files (x86)\7-Zip\7z.exe" }
if (-not (Test-Path $sevenZip)) { throw "не найден 7z.exe (установите 7-Zip)" }
$sfxModule = Join-Path (Split-Path -Parent $sevenZip) "7z.sfx"
if (-not (Test-Path $sfxModule)) { throw "не найден 7z.sfx рядом с 7z.exe" }

if (-not $SkipPortable) {
    Write-Host "==> portable-сборка" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\build-portable.ps1")
}
if (-not (Test-Path (Join-Path $PortableApp "ftdi-logger.exe"))) { throw "нет portable-сборки: $PortableApp" }

Write-Host "==> готовлю payload" -ForegroundColor Cyan
if (Test-Path $InstallerDir) { Remove-Item $InstallerDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Payload | Out-Null
& robocopy $PortableApp $PayloadApp /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy payload: $LASTEXITCODE" }
Copy-Item (Join-Path $Root "scripts\installer\install.cmd") (Join-Path $Payload "install.cmd") -Force
Copy-Item (Join-Path $Root "scripts\installer\install.ps1") (Join-Path $Payload "install.ps1") -Force
Copy-Item (Join-Path $Root "scripts\installer\uninstall.cmd") (Join-Path $PayloadApp "uninstall.cmd") -Force
Copy-Item (Join-Path $Root "scripts\installer\uninstall.ps1") (Join-Path $PayloadApp "uninstall.ps1") -Force

$readme = @"
FTDI/USB Logger — установка

1. Запустите FTDI_USB_Logger_Setup.exe.
2. Программа установится в %LOCALAPPDATA%\FTDI_USB_Logger (без прав администратора),
   создаст ярлыки на рабочем столе и в меню Пуск и запустится.
3. Удаление — ярлык «Удалить FTDI/USB Logger» в меню Пуск (сессии можно сохранить).

Портативная версия: распакуйте FTDI_USB_Logger_portable.zip и запустите logger.cmd.
"@
Set-Content -Path (Join-Path $Payload "README.txt") -Value $readme -Encoding UTF8

Write-Host "==> упаковываю 7z" -ForegroundColor Cyan
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

$setup = Join-Path $Root "dist\FTDI_USB_Logger_Setup.exe"
if (Test-Path $setup) { Remove-Item $setup -Force }
Write-Host "==> собираю setup.exe" -ForegroundColor Cyan
& cmd /c "copy /b `"$sfx`" + `"$config`" + `"$archive`" `"$setup`" >nul"
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $setup)) { throw "не удалось собрать setup.exe" }

$sizeSetup = [Math]::Round((Get-Item $setup).Length / 1MB, 1)
Write-Host ""
Write-Host ("установщик: " + $setup + "  (" + $sizeSetup + " МБ)") -ForegroundColor Green
Write-Host "  per-user установка в %LOCALAPPDATA%\FTDI_USB_Logger, ярлыки и uninstall-запись"

