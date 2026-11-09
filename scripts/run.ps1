#Requires -Version 5.1
<#
    Запуск собранного продукта (dist) или, если dist ещё не собран, — release-бинаря из
    engine\target\release.

    Примеры:
        powershell -ExecutionPolicy Bypass -File scripts\run.ps1
        powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Port 7812
        powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -NoOpen
#>
[CmdletBinding()]
param(
    [int]$Port = 7811,
    [switch]$NoOpen,
    [string]$Exe = '',
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs = @()
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

function Fail([string]$Message) {
    Write-Host ("[run] ОШИБКА: " + $Message) -ForegroundColor Red
    exit 1
}

$candidates = @()
if ($Exe) { $candidates += $Exe }
$candidates += (Join-Path $Root 'dist\FTDI_USB_Logger\ftdi-logger.exe')
$candidates += (Join-Path $Root 'engine\target\release\ftdi-logger.exe')

$exePath = $null
foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $exePath = (Resolve-Path -LiteralPath $candidate).Path
        break
    }
}
if (-not $exePath) {
    Write-Host '[run] Продукт не собран: нет dist\FTDI_USB_Logger\ftdi-logger.exe.' -ForegroundColor Yellow
    Write-Host '      Соберите: powershell -ExecutionPolicy Bypass -File scripts\build.ps1' -ForegroundColor Yellow
    Write-Host '      Или без UI: powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipUi' -ForegroundColor Yellow
    exit 1
}

# Корень для движка: dist-каталог (в нём лежат sidecar/ и ui/dist) либо корень репозитория.
$distRoot = Join-Path $Root 'dist\FTDI_USB_Logger'
$engineRoot = $Root
if ($exePath.StartsWith($distRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    $engineRoot = $distRoot
}

$arguments = @('--root', $engineRoot, '--port', "$Port")
if ($NoOpen) { $arguments += '--no-open' }
foreach ($extra in $ExtraArgs) { $arguments += $extra }

Write-Host ('[run] ' + $exePath) -ForegroundColor Green
Write-Host ('[run] http://127.0.0.1:' + $Port + '   (Ctrl+C — остановить)')
& $exePath @arguments
exit $LASTEXITCODE
