# proxy\tests\smoke.ps1 -- build and run the x64 smoke test of the J2534 proxy.
#
#   powershell -ExecutionPolicy Bypass -File proxy\tests\smoke.ps1
#
# What it does:
#   1. builds proxy\out\x64\j2534proxy.dll (proxy\build.ps1 -Arch x64);
#   2. compiles tests\smoke.c into tests\out\x64\smoke.exe;
#   3. runs smoke.exe (proxy -> fake_j2534.dll -> journal checks);
#   4. prints the journal it produced.
#
# The journal artifact of the run is proxy\tests\out\smoke.log.

[CmdletBinding()]
param(
    [string]$ProxyDll = '',
    [string]$FakeDll = '',
    [string]$LogPath = '',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

$testsDir  = $PSScriptRoot
$proxyRoot = Split-Path $testsDir -Parent
$repoRoot  = Split-Path $proxyRoot -Parent
$outDir    = Join-Path $testsDir 'out\x64'

if (-not $LogPath)  { $LogPath  = Join-Path $testsDir 'out\smoke.log' }
if (-not $FakeDll)  { $FakeDll  = Join-Path $repoRoot 'tests\e2e\fake_j2534\target\release\fake_j2534.dll' }
if (-not $ProxyDll) { $ProxyDll = Join-Path $proxyRoot 'out\x64\j2534proxy.dll' }

function Find-VsInstall {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($found) {
            $path = @($found)[0].Trim()
            if ($path -and (Test-Path (Join-Path $path 'Common7\Tools\VsDevCmd.bat'))) { return $path }
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

if (-not $SkipBuild -and $ProxyDll -eq (Join-Path $proxyRoot 'out\x64\j2534proxy.dll')) {
    Write-Host '== step 1/3: build x64 proxy ==' -ForegroundColor Cyan
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $proxyRoot 'build.ps1') -Arch x64
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'build.ps1 failed' -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path $ProxyDll)) { Write-Host "ERROR: proxy DLL not found: $ProxyDll" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $FakeDll))  { Write-Host "ERROR: fake driver not found: $FakeDll" -ForegroundColor Red; exit 1 }

$vs = Find-VsInstall
if (-not $vs) { Write-Host 'ERROR: Visual Studio C++ toolset not found.' -ForegroundColor Red; exit 1 }
$vsDev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$exe = Join-Path $outDir 'smoke.exe'
$obj = Join-Path $outDir 'smoke.obj'

Write-Host ''
Write-Host '== step 2/3: compile smoke.c (x64) ==' -ForegroundColor Cyan
$cmd = (@'
call "{0}" -no_logo -arch=amd64 -host_arch=x64 >nul && cd /d "{1}" && cl /nologo /O2 /MT /W3 /Fo"{2}" /Fe"{3}" smoke.c
'@ -f $vsDev, $testsDir, $obj, $exe).Trim()
$compile = & cmd.exe /c $cmd 2>&1 | Out-String
if ($compile.Trim()) { Write-Host $compile.TrimEnd() }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) {
    Write-Host 'smoke.c did not compile' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '== step 3/3: run smoke.exe ==' -ForegroundColor Cyan
& $exe $LogPath $FakeDll $ProxyDll
$code = $LASTEXITCODE

Write-Host ''
Write-Host "== journal: $LogPath ==" -ForegroundColor Cyan
if (Test-Path $LogPath) {
    Get-Content -LiteralPath $LogPath | ForEach-Object { Write-Host $_ }
    $info = Get-Item $LogPath
    Write-Host ''
    Write-Host ("{0} lines, {1} bytes" -f (Get-Content -LiteralPath $LogPath).Count, $info.Length)
} else {
    Write-Host 'journal was not created' -ForegroundColor Red
}

Write-Host ''
if ($code -eq 0) { Write-Host 'SMOKE PASSED' -ForegroundColor Green }
else { Write-Host "SMOKE FAILED (exit $code)" -ForegroundColor Red }
exit $code
