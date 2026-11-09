# Сборка независимого лаунчера FTDI/USB Logger (один .exe, WinForms).
#
#   powershell -ExecutionPolicy Bypass -File scripts\build-launcher.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\build-launcher.ps1 -TestBuild   # без UAC-манифеста
#
# Требуется только csc.exe из .NET Framework 4.x (есть в Windows 10/11).
# Результат: dist\FTDI_USB_Logger\FTDI_USB_Logger.exe
#   * иконка приложения assets\app.ico;
#   * логотип assets\splash.png встроен ресурсом (SplashImage), показывается 2 c;
#   * манифест requireAdministrator (кроме -TestBuild).
param(
    [string]$DistDir = "",
    [switch]$TestBuild
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $DistDir) { $DistDir = Join-Path $Root "dist\FTDI_USB_Logger" }

$csc = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path -LiteralPath $csc)) {
    $csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
}
if (-not (Test-Path -LiteralPath $csc)) {
    throw "не найден csc.exe (.NET Framework 4.x). Установите .NET Framework 4.8."
}

$source = Join-Path $Root "launcher\Launcher.cs"
$icon = Join-Path $Root "assets\app.ico"
$splash = Join-Path $Root "assets\splash.png"
$manifest = Join-Path $Root "launcher\app.manifest"
foreach ($f in @($source, $icon, $splash, $manifest)) {
    if (-not (Test-Path -LiteralPath $f)) { throw "нет файла: $f" }
}
if (-not (Test-Path -LiteralPath $DistDir)) { New-Item -ItemType Directory -Path $DistDir -Force | Out-Null }

$out = Join-Path $DistDir "FTDI_USB_Logger.exe"
$args = @(
    "/nologo",
    "/target:winexe",
    "/platform:anycpu",
    "/optimize+",
    "/win32icon:$icon",
    "/resource:$splash,SplashImage",
    "/reference:System.dll",
    "/reference:System.Core.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Windows.Forms.dll",
    "/out:$out"
)
if (-not $TestBuild) { $args += "/win32manifest:$manifest" }
$args += $source

Write-Host "==> csc: FTDI_USB_Logger.exe $(if ($TestBuild) { '(тестовая сборка без UAC)' } else { '(requireAdministrator)' })" -ForegroundColor Cyan
& $csc @args
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $out)) {
    throw "csc завершился с кодом $LASTEXITCODE"
}

# Проверка: манифест действительно встроен (иначе UAC не появится).
$bytes = [System.IO.File]::ReadAllBytes($out)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$hasManifest = $text.Contains("requireAdministrator")
$hasIcon = $bytes.Length -gt 0
Write-Host ("  размер: " + [Math]::Round((Get-Item $out).Length / 1KB, 1) + " КБ")
Write-Host ("  UAC-манифест: " + $(if ($hasManifest) { "встроен" } else { "НЕТ" }))
if (-not $TestBuild -and -not $hasManifest) { throw "манифест requireAdministrator не попал в exe" }
Write-Host ("готово: " + $out) -ForegroundColor Green
exit 0
