# proxy\tests\vendor_dump.ps1 -- проверка дампа аргументов вендорских вызовов.
#
#   powershell -ExecutionPolicy Bypass -File proxy\tests\vendor_dump.ps1
#
# Что делает:
#   1. собирает x86-прокси (proxy\build.ps1 -Arch x86);
#   2. собирает x86 фикстуру: fakevendor.dll (PassThru + NONAME 1377-1379)
#      и vendor_host.exe, который вызывает ординал 1377 с блоком из 11 пар;
#   3. гоняет фикстуру и проверяет журнал: ret=модуль+RVA, mem/pre, params=11
#      с теми же значениями, что BitBox снял на живом PCMflash;
#      плюс pin/voltage и FAST_INIT in/out.
#
# Артефакт прогона: proxy\tests\out\vendor\log.txt

[CmdletBinding()]
param(
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$testsDir  = $PSScriptRoot
$proxyRoot = Split-Path $testsDir -Parent
$outDir    = Join-Path $testsDir 'out\vendor'
$logPath   = Join-Path $outDir 'log.txt'
$proxyDll  = Join-Path $proxyRoot 'out\x86\j2534proxy.dll'
$fakeDll   = Join-Path $outDir 'fakevendor.dll'
$hostExe   = Join-Path $outDir 'vendor_host.exe'

function Find-VsInstall {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($found) {
            $path = @($found)[0].Trim()
            if ($path) { return $path }
        }
    }
    foreach ($candidate in @(
            'C:\Program Files\Microsoft Visual Studio\2022\Community',
            'C:\Program Files (x86)\Microsoft Visual Studio\2022\Community',
            'C:\Program Files\Microsoft Visual Studio\2022\Professional')) {
        if (Test-Path (Join-Path $candidate 'Common7\Tools\VsDevCmd.bat')) { return $candidate }
    }
    return $null
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

if (-not $SkipBuild) {
    Write-Host '== step 1/3: build x86 proxy ==' -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $proxyRoot 'build.ps1') -Arch x86
    if ($LASTEXITCODE -ne 0) { Write-Host 'proxy build failed' -ForegroundColor Red; exit 1 }
}

if (-not (Test-Path $proxyDll)) { Write-Host "ERROR: proxy DLL not found: $proxyDll" -ForegroundColor Red; exit 1 }

$vs = Find-VsInstall
if (-not $vs) { Write-Host 'ERROR: Visual Studio (C++) not found' -ForegroundColor Red; exit 1 }
$vsDev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'

Write-Host '== step 2/3: build x86 fixture ==' -ForegroundColor Cyan
$cmd = 'call "{0}" -no_logo -arch=x86 -host_arch=x64 >nul && cd /d "{1}" && ' +
       'cl /nologo /O2 /MT /W3 /Fo"{2}\\" fakevendor.c /LD /link /DEF:fakevendor.def /OUT:"{3}" && ' +
       'cl /nologo /O2 /MT /W3 /Fo"{2}\\" vendor_host.c /Fe:"{4}" /link user32.lib'
$cmd = $cmd -f $vsDev, $testsDir, $outDir, $fakeDll, $hostExe
cmd.exe /c $cmd
if ($LASTEXITCODE -ne 0) { Write-Host 'fixture build failed' -ForegroundColor Red; exit 1 }

Write-Host '== step 3/3: run vendor_host.exe ==' -ForegroundColor Cyan
& $hostExe $proxyDll $fakeDll $logPath
$code = $LASTEXITCODE

Write-Host ''
Write-Host "== journal: $logPath ==" -ForegroundColor Cyan
if (Test-Path $logPath) {
    Get-Content -LiteralPath $logPath | ForEach-Object { Write-Host $_ }
}
Write-Host ''
if ($code -eq 0) { Write-Host 'VENDOR DUMP PASSED' -ForegroundColor Green }
else { Write-Host "VENDOR DUMP FAILED (exit $code)" -ForegroundColor Red }
exit $code
