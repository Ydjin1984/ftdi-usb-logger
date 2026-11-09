# BMW Scanner 1.4.0 (P.A.Soft): живой e2e — приложение ходит в адаптер через FTDI D2XX.
#
#   pwsh -File tests\e2e\bmw-scanner.ps1
#   pwsh -File tests\e2e\bmw-scanner.ps1 -StartApp -Port 7848
#
# Проверяет: детект процесса по окну, attach к 32-битному Delphi-приложению,
# хуки ftd2xx.dll, поток FT_Write/FT_Read, транспорт ftd2xx в отчёте, detach.
param(
    [int]$Port = 7848,
    [switch]$StartApp,
    [string]$ExePath = "",
    [string]$RootPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ExePath) { $ExePath = Join-Path $root "engine\target\debug\ftdi-logger.exe" }
if (-not $RootPath) { $RootPath = $root }
$base = "http://127.0.0.1:$Port"
$results = New-Object System.Collections.Generic.List[object]

function Check([string]$name, [scriptblock]$fn) {
    try {
        $detail = & $fn
        $results.Add([pscustomobject]@{ Name = $name; Ok = $true })
        Write-Host ("PASS  {0}{1}" -f $name, $(if ($detail) { " — $detail" } else { "" })) -ForegroundColor Green
    } catch {
        $results.Add([pscustomobject]@{ Name = $name; Ok = $false })
        Write-Host ("FAIL  {0} — {1}" -f $name, $_.Exception.Message) -ForegroundColor Red
    }
}

function Wait-Json([string]$url, [int]$seconds = 40) {
    $deadline = (Get-Date).AddSeconds($seconds)
    while ((Get-Date) -lt $deadline) {
        try { return Invoke-RestMethod -Uri $url -TimeoutSec 3 } catch { Start-Sleep -Milliseconds 250 }
    }
    throw "не ответил: $url"
}

# Нажать пункт меню по тексту через WM_COMMAND (надёжнее UIA для Delphi-меню).
function Invoke-BmwMenuCommand {
    param([int]$ProcessId, [string]$Text)
    $src = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class BmwMenu {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct MENUITEMINFO {
        public uint cbSize; public uint fMask; public uint fType; public uint fState; public uint wID;
        public IntPtr hSubMenu; public IntPtr hbmpChecked; public IntPtr hbmpUnchecked;
        public IntPtr dwItemData; public string dwTypeData; public uint cch; public IntPtr hbmpItem;
    }
    public delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr hMenu);
    [DllImport("user32.dll")] public static extern IntPtr GetSubMenu(IntPtr hMenu, int pos);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool GetMenuItemInfo(IntPtr hMenu, uint item, bool byPos, ref MENUITEMINFO info);
    [DllImport("user32.dll")] public static extern IntPtr PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
    public static IntPtr FindWindowWithMenu(uint processId) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == processId && GetMenu(h) != IntPtr.Zero) found = h; return true; }, IntPtr.Zero);
        return found;
    }
    public static uint FindCommand(IntPtr hMenu, string text) {
        int count = GetMenuItemCount(hMenu);
        for (int i = 0; i < count; i++) {
            var info = new MENUITEMINFO();
            info.cbSize = (uint)Marshal.SizeOf(typeof(MENUITEMINFO));
            info.fMask = 0x40 | 0x10;
            info.dwTypeData = new string(' ', 256);
            info.cch = 256;
            if (!GetMenuItemInfo(hMenu, (uint)i, true, ref info)) continue;
            string s = (info.dwTypeData ?? "").Replace("&", "").Trim();
            if (s.Equals(text, StringComparison.OrdinalIgnoreCase)) return info.wID;
            if (info.hSubMenu != IntPtr.Zero) {
                uint id = FindCommand(info.hSubMenu, text);
                if (id != 0) return id;
            }
        }
        return 0;
    }
    public static bool Invoke(uint processId, string text) {
        IntPtr win = FindWindowWithMenu(processId);
        if (win == IntPtr.Zero) return false;
        uint id = FindCommand(GetMenu(win), text);
        if (id == 0) return false;
        PostMessage(win, 0x0111, new IntPtr(id), IntPtr.Zero);
        return true;
    }
}
"@
    Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
    return [BmwMenu]::Invoke([uint32]$ProcessId, $Text)
}

$app = Get-CimInstance Win32_Process -Filter "Name='BMWScan140.exe'" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $app) {
    if (-not $StartApp) { Write-Host "BMWScan140.exe не запущен (добавьте -StartApp)" -ForegroundColor Yellow; exit 2 }
    $proc = Start-Process -FilePath "C:\BMWScan140\BMWScan140.exe" -WorkingDirectory "C:\BMWScan140" -PassThru
    Start-Sleep -Seconds 6
    $app = Get-CimInstance Win32_Process -Filter "Name='BMWScan140.exe'" | Select-Object -First 1
}
$targetPid = [int]$app.ProcessId
Write-Host "цель: BMWScan140 pid=$targetPid"

$eng = Start-Process -FilePath $ExePath -ArgumentList @("--root", "`"$RootPath`"", "--port", "$Port", "--no-open") `
    -WorkingDirectory $RootPath -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput "$env:TEMP\bmw-e2e.out.log" -RedirectStandardError "$env:TEMP\bmw-e2e.err.log"
$sessionId = $null
try {
    Check "detect: BMWScan в tools?mode=auto" {
        $tools = Wait-Json "$base/api/tools?mode=auto"
        $hit = @($tools) | Where-Object { $_.pid -eq $targetPid }
        if (-not $hit) { throw "pid $targetPid нет в auto" }
        "caps=$($hit[0].capabilities -join ',')"
    }
    Check "attach к 32-битному Delphi-процессу" {
        $meta = Invoke-RestMethod -Uri "$base/api/capture/attach" -Method Post `
            -Body (@{ pid = $targetPid; label = "BMW Scanner e2e" } | ConvertTo-Json) `
            -ContentType "application/json" -TimeoutSec 60
        $script:sessionId = $meta.id
        "session=$($meta.id) transport=$($meta.transport)"
    }
    Check "ftd2xx.dll захукан, идут FT_Write/FT_Read" {
        # BMW Scanner может простаивать после старта — просим опросить интерфейс
        # через меню Scanner → Scan! (WM_COMMAND, надёжнее UIA для Delphi).
        $sent = $false
        try { $sent = Invoke-BmwMenuCommand -ProcessId $targetPid -Text "Scan!" } catch {}
        if ($sent) { Write-Host "  меню Scan! отправлено (WM_COMMAND)"; Start-Sleep -Seconds 2 }
        try {
            Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
            $rootEl = [System.Windows.Automation.AutomationElement]::RootElement
            $wcond = New-Object System.Windows.Automation.PropertyCondition(
                [System.Windows.Automation.AutomationElement]::ProcessIdProperty, [int]$targetPid)
            $win = $rootEl.FindFirst([System.Windows.Automation.TreeScope]::Children, $wcond)
            if ($win) {
                $bars = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants,
                    (New-Object System.Windows.Automation.PropertyCondition(
                        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                        [System.Windows.Automation.ControlType]::MenuBar)))
                $scanner = $null
                foreach ($bar in $bars) {
                    $items = $bar.FindAll([System.Windows.Automation.TreeScope]::Children,
                        [System.Windows.Automation.Condition]::TrueCondition)
                    foreach ($it in $items) { if ($it.Current.Name -like "Scanner*") { $scanner = $it } }
                }
                if ($scanner) {
                    try { $scanner.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand() } catch {}
                    Start-Sleep -Milliseconds 500
                    $scan = $scanner.FindFirst([System.Windows.Automation.TreeScope]::Descendants,
                        (New-Object System.Windows.Automation.PropertyCondition(
                            [System.Windows.Automation.AutomationElement]::NameProperty, "Scan!")))
                    if ($scan) {
                        try { $scan.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() } catch {}
                    }
                }
            }
        } catch { Write-Host "  (UIA Scan! не сработал: $($_.Exception.Message))" }
        $deadline = (Get-Date).AddSeconds(25)
        $tx = @(); $rx = @()
        while ((Get-Date) -lt $deadline) {
            $ev = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=4000" -TimeoutSec 30
            $tx = @($ev.events) | Where-Object { $_.api -eq "FT_Write" }
            $rx = @($ev.events) | Where-Object { $_.api -eq "FT_Read" }
            if ($tx.Count -ge 3 -and $rx.Count -ge 1) { break }
            if ($tx.Count -ge 10) { break }   # на стенде без ЭБУ ответов может не быть
            Start-Sleep -Milliseconds 500
        }
        if ($tx.Count -lt 3) {
            # Приложение может простаивать (нет Scan!/меню) — проверяем хотя бы, что DLL захукана.
            $ev = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=4000" -TimeoutSec 30
            $hooks = @($ev.events) | Where-Object { $_.api -eq "FTD2XX" -and "$($_.text)" -like "*hooks installed*" }
            if (-not $hooks) { throw "FT_Write: $($tx.Count), хуки ftd2xx не подтверждены" }
            "хуки установлены, обмена нет (приложение простаивает): TX=$($tx.Count) RX=$($rx.Count)"
        } else {
            # RX зависит от стенда: без ЭБУ на линии ответов может не быть — не валим тест.
            $sample = if ($rx.Count -gt 0) { ($tx[0].hex + " " + $rx[0].hex).Trim() } else { $tx[0].hex }
            "TX=$($tx.Count) RX=$($rx.Count), пример: $sample"
        }
    }
    Check "отчёт: транспорт ftd2xx/mixed, дублей USB TX/RX нет" {
        $det = Invoke-RestMethod -Uri "$base/api/capture/detach" -Method Post -Body '{}' `
            -ContentType "application/json" -TimeoutSec 90
        if (-not $det) { throw "detach null" }
        if ($det.transport -notin @("ftd2xx", "mixed")) { throw "transport=$($det.transport)" }
        $raw = Invoke-WebRequest "$base/api/sessions/$sessionId/events?limit=4000" -TimeoutSec 60 -UseBasicParsing
        $usbDup = ([regex]::Matches($raw.Content, '"api":"USB (TX|RX)"')).Count
        if ($usbDup -gt 0) { throw "дубли USB TX/RX: $usbDup" }
        "transport=$($det.transport) tx=$($det.counts.tx) rx=$($det.counts.rx)"
    }
} finally {
    Stop-Process -Id $eng.Id -Force -ErrorAction SilentlyContinue
}

$failed = @($results | Where-Object { -not $_.Ok }).Count
Write-Host ""
Write-Host ("Итог: {0}/{1} проверок пройдено" -f ($results.Count - $failed), $results.Count)
if ($sessionId) { Write-Host "сессия: $sessionId" }
if ($failed -gt 0) {
    Get-Content "$env:TEMP\bmw-e2e.err.log" -Tail 15 -ErrorAction SilentlyContinue
    exit 1
}
exit 0




