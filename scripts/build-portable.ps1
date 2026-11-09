# Сборка portable-версии: dist + встроенный Python с frida (на чужой машине ничего ставить не нужно).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-portable.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build-portable.ps1 -SkipBuild
#
# Результат: build\portable\FTDI_USB_Logger\  и  build\FTDI_USB_Logger_portable.zip
param(
    [switch]$SkipBuild,
    [string]$PythonVersion = "3.12.4"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist\FTDI_USB_Logger"
$Build = Join-Path $Root "build"
$Cache = Join-Path $Build "cache"
$PortableRoot = Join-Path $Build "portable"
$AppDir = Join-Path $PortableRoot "FTDI_USB_Logger"

if (-not $SkipBuild) {
    Write-Host "==> Собираю dist" -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\build.ps1")
}
if (-not (Test-Path (Join-Path $Dist "ftdi-logger.exe"))) { throw "нет dist\FTDI_USB_Logger\ftdi-logger.exe" }

New-Item -ItemType Directory -Force -Path $Cache, $PortableRoot | Out-Null
if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force }
Write-Host "==> Копирую приложение" -ForegroundColor Cyan
& robocopy $Dist $AppDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy приложения: $LASTEXITCODE" }

# ── Python embeddable + frida ────────────────────────────────────────────────
Write-Host "==> Готовлю встроенный Python $PythonVersion" -ForegroundColor Cyan
$zip = Join-Path $Cache "python-$PythonVersion-embed-amd64.zip"
if (-not (Test-Path $zip)) {
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
    Write-Host "  скачиваю $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
}
$PyDir = Join-Path $AppDir "python"
if (Test-Path $PyDir) { Remove-Item $PyDir -Recurse -Force }
Expand-Archive -LiteralPath $zip -DestinationPath $PyDir -Force

# site-packages + import site в ._pth
$pth = Get-ChildItem $PyDir -Filter "*._pth" | Select-Object -First 1
if (-not $pth) { throw "в embeddable Python нет ._pth" }
$lines = Get-Content $pth.FullName
if ($lines -notcontains "Lib\site-packages") { $lines += "Lib\site-packages" }
$lines = $lines -replace '^#\s*import site\s*$', 'import site'
Set-Content $pth.FullName ($lines -join "`r`n") -Encoding ASCII
New-Item -ItemType Directory -Force -Path (Join-Path $PyDir "Lib\site-packages") | Out-Null

# frida из установленного Python (frida.__file__)
$sysPy = "C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $sysPy)) { $sysPy = (Get-Command python).Source }
$fridaDir = & $sysPy -c "import frida, os; print(os.path.dirname(frida.__file__))"
if (-not $fridaDir -or -not (Test-Path $fridaDir)) { throw "не найден установленный frida (pip install frida)" }
$fridaDir = $fridaDir.Trim()
Write-Host "  frida: $fridaDir"
$sp = Join-Path $PyDir "Lib\site-packages"
Copy-Item $fridaDir (Join-Path $sp "frida") -Recurse -Force

# Проверка встроенного Python
$pyExe = Join-Path $PyDir "python.exe"
$check = & $pyExe -c "import frida, sys; print(frida.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host $check
    throw "встроенный Python не импортирует frida"
}
Write-Host "  frida во встроенном Python: $check"

# Проверка моста
$selfTest = & $pyExe (Join-Path $AppDir "sidecar\bridge.py") --self-test 2>&1 | Select-Object -Last 1
if ($LASTEXITCODE -ne 0) { Write-Host $selfTest; throw "self-test моста во встроенном Python не прошёл" }
Write-Host "  bridge self-test: ok"

# ── Итог ─────────────────────────────────────────────────────────────────────
$zipOut = Join-Path $Build "FTDI_USB_Logger_portable.zip"
if (Test-Path $zipOut) { Remove-Item $zipOut -Force }
Write-Host "==> Упаковываю portable zip" -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $PortableRoot "*") -DestinationPath $zipOut -CompressionLevel Optimal
$sizeApp = [Math]::Round((Get-ChildItem $AppDir -Recurse -File | Measure-Object Length -Sum).Sum / 1MB, 1)
$sizeZip = [Math]::Round((Get-Item $zipOut).Length / 1MB, 1)
Write-Host ""
Write-Host ("portable: " + $AppDir + "  (" + $sizeApp + " МБ)") -ForegroundColor Green
Write-Host ("zip:      " + $zipOut + "  (" + $sizeZip + " МБ)") -ForegroundColor Green
