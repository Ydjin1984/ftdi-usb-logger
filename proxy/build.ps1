# proxy\build.ps1 -- build the FTDI/USB Logger J2534 proxy.
#
#   powershell -ExecutionPolicy Bypass -File proxy\build.ps1            # x86 + x64
#   powershell -ExecutionPolicy Bypass -File proxy\build.ps1 -Arch x86  # product only
#   powershell -ExecutionPolicy Bypass -File proxy\build.ps1 -Arch x64  # smoke test only
#
# Result:
#   proxy\out\x86\j2534proxy.dll   (delivered; 32-bit, with vendor ordinals)
#   proxy\out\x64\j2534proxy.dll   (tests; vendor ordinals are stubs)
#
# The script finds the compiler through vswhere.exe and falls back to the
# fixed VS 2022 Community path.  It is idempotent: every run wipes its own
# out\<arch> directory and rebuilds from scratch.  After linking it checks
# with dumpbin /exports that all 14 Pass-Thru names and ordinals 1377-1379
# are present and exits 1 if anything is missing.

[CmdletBinding()]
param(
    [ValidateSet('both', 'x86', 'x64')]
    [string]$Arch = 'both'
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

function Find-VsInstall {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($found) {
            $path = @($found)[0].Trim()
            if ($path -and (Test-Path (Join-Path $path 'Common7\Tools\VsDevCmd.bat'))) {
                return $path
            }
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

function Invoke-BuildCommand {
    param([string]$CommandLine)
    $text = & cmd.exe /c $CommandLine 2>&1 | Out-String
    return [pscustomobject]@{ Text = $text; Code = $LASTEXITCODE }
}

$vs = Find-VsInstall
if (-not $vs) {
    Write-Host 'ERROR: Visual Studio with the C++ toolset was not found (vswhere + fixed paths failed).' -ForegroundColor Red
    exit 1
}
$vsDev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
Write-Host "VS:        $vs"

$targets = switch ($Arch) {
    'x86' { @('x86') }
    'x64' { @('x64') }
    default { @('x86', 'x64') }
}

$requiredNames = @(
    'PassThruOpen', 'PassThruClose', 'PassThruConnect', 'PassThruDisconnect',
    'PassThruReadMsgs', 'PassThruWriteMsgs', 'PassThruStartPeriodicMsg',
    'PassThruStopPeriodicMsg', 'PassThruStartMsgFilter', 'PassThruStopMsgFilter',
    'PassThruSetProgrammingVoltage', 'PassThruReadVersion',
    'PassThruGetLastError', 'PassThruIoctl')
$requiredOrdinals = @(1377, 1378, 1379)

$failed = $false

foreach ($target in $targets) {
    $vsArch  = if ($target -eq 'x86') { 'x86' } else { 'amd64' }
    $machine = if ($target -eq 'x86') { 'X86' } else { 'X64' }

    $outDir = Join-Path $root "out\$target"
    if (Test-Path $outDir) { Remove-Item (Join-Path $outDir '*') -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $res = Join-Path $outDir 'version.res'
    $obj = Join-Path $outDir 'j2534proxy.obj'
    $dll = Join-Path $outDir 'j2534proxy.dll'
    $lib = Join-Path $outDir 'j2534proxy.lib'
    $pdb = Join-Path $outDir 'j2534proxy.pdb'

    $cmd = (@'
call "{0}" -no_logo -arch={1} -host_arch=x64 >nul && cd /d "{2}" && rc /nologo /fo "{3}" version.rc && cl /nologo /O2 /MT /LD /W3 /Fo"{4}" j2534proxy.c /link /DEF:j2534proxy.def "{3}" /MACHINE:{5} /OUT:"{6}" /IMPLIB:"{7}" /PDB:"{8}"
'@ -f $vsDev, $vsArch, $root, $res, $obj, $machine, $dll, $lib, $pdb).Trim()

    Write-Host ''
    Write-Host "[$target] building ..." -ForegroundColor Cyan
    $build = Invoke-BuildCommand $cmd
    if ($build.Text.Trim()) { Write-Host $build.Text.TrimEnd() }
    if ($build.Code -ne 0 -or -not (Test-Path $dll)) {
        Write-Host "[$target] BUILD FAILED (exit $($build.Code))" -ForegroundColor Red
        $failed = $true
        continue
    }

    $warnings = @([regex]::Matches($build.Text, '(?im)^.*warning[ :].*$') | ForEach-Object { $_.Value.Trim() })
    if ($warnings.Count -gt 0) {
        Write-Host "[$target] compiler warnings: $($warnings.Count)" -ForegroundColor Yellow
        $warnings | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    }

    # ---- verify the export table ------------------------------------
    $dump = Invoke-BuildCommand ('call "{0}" -no_logo -arch=x86 -host_arch=x64 >nul && dumpbin /nologo /exports "{1}"' -f $vsDev, $dll)
    if ($dump.Code -ne 0) {
        Write-Host "[$target] dumpbin failed (exit $($dump.Code))" -ForegroundColor Red
        Write-Host $dump.Text
        $failed = $true
        continue
    }
    $exp = $dump.Text

    $missingNames = @()
    foreach ($name in $requiredNames) {
        $pattern = '(?m)^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+' + [regex]::Escape($name) + '\s*$'
        if ($exp -notmatch $pattern) { $missingNames += $name }
    }
    $missingOrdinals = @()
    foreach ($ord in $requiredOrdinals) {
        # NONAME rows have no hint column and are marked [NONAME] by dumpbin
        $pattern = '(?m)^\s*' + $ord + '\s+.*\[NONAME\]\s*$'
        if ($exp -notmatch $pattern) { $missingOrdinals += $ord }
    }

    # print the export section verbatim (from "ordinal hint RVA" on)
    $lines = $exp -split "`r?`n"
    $start = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'ordinal\s+hint\s+RVA') { $start = $i; break }
    }
    if ($start -ge 0) {
        $table = @()
        for ($i = $start; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -eq '' -and $table.Count -gt 0) { continue }
            if ($lines[$i] -match '^\s*Summary') { break }
            $table += $lines[$i].TrimEnd()
        }
        $table | ForEach-Object { Write-Host "  $_" }
    }

    $info = (Get-Item $dll)
    $ver = $info.VersionInfo.FileVersion
    $names = @([regex]::Matches($exp, '(?m)^\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)\s*$') |
        ForEach-Object { $_.Groups[1].Value })
    Write-Host ("  file: {0}  {1} bytes  FileVersion={2}  named exports={3}" -f `
            $dll, $info.Length, $ver, $names.Count)

    $deps = Invoke-BuildCommand ('call "{0}" -no_logo -arch=x86 -host_arch=x64 >nul && dumpbin /nologo /dependents "{1}"' -f $vsDev, $dll)
    foreach ($line in ($deps.Text -split "`r?`n")) {
        if ($line -match '^\s+\S+\.dll\s*$') { Write-Host "  depends on:$($line.TrimEnd())" }
    }

    if ($missingNames.Count -gt 0 -or $missingOrdinals.Count -gt 0) {
        Write-Host "[$target] EXPORT MISMATCH" -ForegroundColor Red
        if ($missingNames.Count -gt 0) { Write-Host ("  missing names:    " + ($missingNames -join ', ')) -ForegroundColor Red }
        if ($missingOrdinals.Count -gt 0) { Write-Host ("  missing ordinals: " + ($missingOrdinals -join ', ')) -ForegroundColor Red }
        $failed = $true
    } else {
        Write-Host ("[$target] OK: 14 named exports + ordinals 1377,1378,1379") -ForegroundColor Green
    }
}

if ($failed) { exit 1 }
Write-Host ''
Write-Host 'done.' -ForegroundColor Green
exit 0
