# Универсальный захват: живой e2e на MS4x Flasher (VCP/overlapped) через UIA.
#
#   pwsh -File tests\e2e\universal.ps1
#   pwsh -File tests\e2e\universal.ps1 -Port 7834 -StartApp
#
# Проверяет: USB-инвентарь, J2534-драйверы, режимы /api/tools, attach к процессу
# без ftd2xx (MS4x держит COM1 через .NET SerialPort), перехват TX/RX, detach и отчёт.
# Кнопку «Identify» в MS4x нажимаем через UI Automation — это read-only операция.

param(
    [int]$Port = 7834,
    [switch]$StartApp,
    [switch]$Keep,
    [string]$ExePath = "",
    [string]$RootPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ($ExePath) { $exe = $ExePath } else { $exe = Join-Path $root "engine\target\debug\ftdi-logger.exe" }
$engineRoot = if ($RootPath) { $RootPath } else { $root }
$base = "http://127.0.0.1:$Port"
$results = New-Object System.Collections.Generic.List[object]

function Check([string]$name, [scriptblock]$fn) {
    try {
        $detail = & $fn
        $results.Add([pscustomobject]@{ Name = $name; Ok = $true; Detail = "$detail" })
        Write-Host ("PASS  {0}{1}" -f $name, $(if ($detail) { " — $detail" } else { "" })) -ForegroundColor Green
    } catch {
        $results.Add([pscustomobject]@{ Name = $name; Ok = $false; Detail = $_.Exception.Message })
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

# --- цель ---------------------------------------------------------------
$app = Get-CimInstance Win32_Process -Filter "Name='MS4x Flasher.exe'" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $app) {
    if (-not $StartApp) {
        Write-Host "MS4x Flasher не запущен. Запустите его или добавьте -StartApp." -ForegroundColor Yellow
        exit 2
    }
    $proc = Start-Process -FilePath "C:\Program Files\MS4x Flasher\MS4x Flasher.exe" `
        -WorkingDirectory "C:\Program Files\MS4x Flasher" -PassThru
    Start-Sleep -Seconds 8
    $targetPid = $proc.Id
} else {
    $targetPid = $app.ProcessId
}
Write-Host "цель: MS4x Flasher pid=$targetPid"

if (-not (Test-Path $exe)) {
    Push-Location (Join-Path $root "engine")
    try { cargo build } finally { Pop-Location }
}

$eng = Start-Process -FilePath $exe -ArgumentList @(
    "--root", "`"$engineRoot`"", "--port", "$Port", "--no-open"
) -WorkingDirectory $engineRoot -PassThru -WindowStyle Hidden `
  -RedirectStandardOutput "$env:TEMP\universal-e2e.out.log" -RedirectStandardError "$env:TEMP\universal-e2e.err.log"

$sessionId = $null
try {
    Check "health: universal и возможности" {
        $h = Wait-Json "$base/api/health"
        if (-not $h.universal) { throw "universal != true" }
        $c = $h.capabilities
        if (-not $c) { throw "нет capabilities" }
        "j2534=$($c.j2534) usb_enum=$($c.usb_enum) ftd2xx=$($c.ftd2xx) usbpcap=$($c.usbpcap)"
    }

    Check "USB-устройства перечисляются" {
        $u = Invoke-RestMethod "$base/api/usb/devices" -TimeoutSec 30
        if (@($u).Count -lt 3) { throw "устройств: $(@($u).Count)" }
        "устройств: $(@($u).Count)"
    }

    Check "J2534-драйверы найдены" {
        $j = Invoke-RestMethod "$base/api/j2534/drivers" -TimeoutSec 30
        if (@($j).Count -lt 1) { throw "нет драйверов" }
        $present = @($j | Where-Object { $_.dll_present }).Count
        "драйверов: $(@($j).Count), с DLL: $present"
    }

    Check "tools?mode=auto содержит цель по окну" {
        $t = Invoke-RestMethod "$base/api/tools?mode=auto" -TimeoutSec 60
        $hit = @($t) | Where-Object { $_.pid -eq $targetPid }
        if (-not $hit) { throw "pid $targetPid нет в auto" }
        "auto: $(@($t).Count), цель caps=$($hit[0].capabilities -join ',')"
    }

    Check "tools?mode=all >= auto" {
        $autoList = Invoke-RestMethod "$base/api/tools?mode=auto" -TimeoutSec 60
        $allList = Invoke-RestMethod "$base/api/tools?mode=all" -TimeoutSec 60
        $auto = @($autoList).Count
        $all = @($allList).Count
        if ($all -lt $auto) { throw "all=$all < auto=$auto" }
        "auto=$auto all=$all"
    }

    Check "attach к процессу без ftd2xx" {
        # PID мог смениться (приложение перезапускалось) — берём актуальный и один ретрай.
        $lastErr = $null
        foreach ($attempt in 1..2) {
            $proc = Get-CimInstance Win32_Process -Filter "Name='MS4x Flasher.exe'" -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if (-not $proc) { throw "MS4x Flasher не запущен" }
            $script:targetPid = [int]$proc.ProcessId
            try {
                $meta = Invoke-RestMethod -Uri "$base/api/capture/attach" -Method Post `
                    -Body (@{ pid = $script:targetPid; label = "MS4x universal e2e" } | ConvertTo-Json) `
                    -ContentType "application/json" -TimeoutSec 60
                $script:sessionId = $meta.id
                return "session=$($meta.id) transport=$($meta.transport) pid=$($script:targetPid)"
            } catch {
                $lastErr = $_.ErrorDetails.Message
                if ($_.Exception.Response) {
                    try {
                        $lastErr = (New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())).ReadToEnd()
                    } catch { }
                }
                Start-Sleep -Seconds 2
            }
        }
        throw "attach не удался: $lastErr"
    }

    Start-Sleep -Seconds 2

    Check "Identify через UI Automation" {
        Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
        $rootEl = [System.Windows.Automation.AutomationElement]::RootElement
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty, [int]$targetPid)
        $win = $rootEl.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
        if (-not $win) { throw "окно MS4x не найдено" }
        $all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition)
        $ident = $null
        foreach ($e in $all) { if ($e.Current.Name -eq "Identify") { $ident = $e; break } }
        if (-not $ident) { throw "кнопка Identify не найдена" }
        $ident.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        "нажато"
    }

    Check "пойман TX slow-init 12 04 0d 1b" {
        $deadline = (Get-Date).AddSeconds(15)
        while ((Get-Date) -lt $deadline) {
            $ev = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=2000" -TimeoutSec 30
            $tx = @($ev.events) | Where-Object {
                $_.kind -eq "tx" -and ($_.hex -replace " ", "").ToLower().Contains("12040d1b")
            }
            if ($tx.Count -gt 0) { return "$($tx.Count) совпадений, api=$($tx[0].api)" }
            Start-Sleep -Milliseconds 500
        }
        throw "TX 12 04 0d 1b не появился"
    }

    Check "пойманы RX с реальными байтами (n>0)" {
        # Ответ ЭБУ может прийти на несколько сотен мс позже TX — ждём до 15 с.
        $deadline = (Get-Date).AddSeconds(15)
        $rx = @()
        while ((Get-Date) -lt $deadline) {
            $ev = Invoke-RestMethod "$base/api/sessions/$sessionId/events?limit=3000" -TimeoutSec 30
            $rx = @($ev.events) | Where-Object { $_.kind -eq "rx" -and $_.len -gt 0 }
            if ($rx.Count -ge 3) { break }
            Start-Sleep -Milliseconds 500
        }
        if ($rx.Count -lt 3) { throw "RX с байтами: $($rx.Count)" }
        $sample = $rx[0].hex.Substring(0, [Math]::Min(24, $rx[0].hex.Length))
        "RX-событий с данными: $($rx.Count), пример: $sample"
    }

    Check "сводка/отчёт после detach" {
        $det = Invoke-RestMethod -Uri "$base/api/capture/detach" -Method Post -Body '{}' `
            -ContentType "application/json" -TimeoutSec 90
        if (-not $det) { throw "detach вернул null" }
        $rep = Invoke-WebRequest "$base/api/sessions/$sessionId/report" -TimeoutSec 60 -UseBasicParsing
        if ($rep.Content.Length -lt 50) { throw "отчёт пуст" }
        "status=$($det.status) transport=$($det.transport) report=$($rep.Content.Length) символов"
    }
} finally {
    if (-not $Keep) {
        try { Stop-Process -Id $eng.Id -Force -ErrorAction SilentlyContinue } catch { }
    } else {
        Write-Host "движок оставлен: $base (pid $($eng.Id))"
    }
}

$failed = @($results | Where-Object { -not $_.Ok }).Count
Write-Host ""
Write-Host ("Итог: {0}/{1} проверок пройдено" -f ($results.Count - $failed), $results.Count)
if ($failed -gt 0) {
    Write-Host "--- stderr движка ---"
    Get-Content "$env:TEMP\universal-e2e.err.log" -Tail 20 -ErrorAction SilentlyContinue
    exit 1
}
if ($sessionId) { Write-Host "сессия: $sessionId" }
exit 0



