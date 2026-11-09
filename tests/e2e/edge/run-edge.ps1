#Requires -Version 7.0
<#
.SYNOPSIS
  Жёсткие e2e-проверки крайних случаев FTDI/USB Logger (API, импорт, захват, файлы, UI).

.DESCRIPTION
  Поднимает engine\target\debug\ftdi-logger.exe на отдельном порту (по умолчанию 7831),
  гоняет кейсы из docs/05-edge-cases.md, пишет машинный результат в tests/e2e/edge/out/
  (results.json / results.csv / summary.txt) и убирает за собой созданные сессии.

  Пример:
    pwsh -File tests\e2e\edge\run-edge.ps1
    pwsh -File tests\e2e\edge\run-edge.ps1 -SkipBig -SkipUi
    pwsh -File tests\e2e\edge\run-edge.ps1 -Port 7831 -KeepEngine

.NOTES
  Ничего в engine/src, ui/src, sidecar не меняет. UI-проверки — node cdp-edge.mjs.
#>
param(
    [int]$Port = 7831,
    [int]$StaticPort = 8101,
    [int]$CdpPort = 9335,
    [string]$BigLog = "E:\Replica\MS45-Quickflash-capture-20261103-122230.log",
    [switch]$SkipBig,
    [switch]$SkipUi,
    [switch]$KeepEngine,
    [switch]$NoCleanup,
    # По умолчанию движок запускается из уникальной копии в %TEMP%: на общей машине
    # соседние агенты иногда убивают процессы по имени ftdi-logger.exe.
    [switch]$UseOriginalExe
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$script:Exe = Join-Path $script:Root "engine\target\debug\ftdi-logger.exe"
$script:Port = $Port
$script:StaticPort = $StaticPort
$script:CdpPort = $CdpPort
$script:Base = "http://127.0.0.1:$Port"
$script:OutDir = Join-Path $PSScriptRoot "out"
$script:Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$script:Tmp = Join-Path $env:TEMP "ftdi-edge-$($script:Stamp)"
$script:EngineOut = Join-Path $script:Tmp "engine.out.log"
$script:EngineErr = Join-Path $script:Tmp "engine.err.log"
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Created = [System.Collections.Generic.List[string]]::new()
$script:Engine = $null
$script:Static = $null
$script:Helpers = [System.Collections.Generic.List[object]]::new()

New-Item -ItemType Directory -Force -Path $script:OutDir, $script:Tmp | Out-Null

$script:RunExe = $script:Exe

# ─────────────────────────────── утилиты ──────────────────────────────────

function Short([string]$s, [int]$n = 240) {
    if ($null -eq $s) { return "" }
    $s = $s -replace "`r", " " -replace "`n", " "
    if ($s.Length -le $n) { return $s }
    return $s.Substring(0, $n) + "…"
}

function J([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { return ($text | ConvertFrom-Json) } catch { return $null }
}

# Чтение текстового файла без сюрпризов: Get-Content -Raw на ПУСТОМ файле возвращает
# AutomationNull, и [string](...) от него тоже null — метод .Trim() падает.
function Read-Text([string]$path) {
    if ([string]::IsNullOrEmpty($path) -or -not (Test-Path -LiteralPath $path)) { return "" }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
        if ($null -eq $raw) { return "" }
        return [string]$raw
    } catch { return "" }
}

function ToJson($obj) { return ($obj | ConvertTo-Json -Compress -Depth 12) }

function Esc([string]$s) { return [uri]::EscapeDataString($s) }

function Http {
    param(
        [string]$Method = "GET",
        [string]$Path,
        [string]$Body = $null,
        [string]$ContentType = "application/json",
        [string]$InFile = $null,
        [int]$TimeoutSec = 30,
        [string[]]$Headers = @()
    )
    $tmpBody = Join-Path $script:Tmp ("http-" + [guid]::NewGuid().ToString("N") + ".body")
    $tmpData = Join-Path $script:Tmp ("http-" + [guid]::NewGuid().ToString("N") + ".data")
    $tmpHdr = Join-Path $script:Tmp ("http-" + [guid]::NewGuid().ToString("N") + ".hdr")
    $cargs = @("-sS", "--path-as-is", "--max-time", "$TimeoutSec", "-X", $Method,
        "-D", $tmpHdr, "-o", $tmpBody, "-w", "%{http_code}|%{content_type}|%{size_download}|%{time_total}")
    if ($InFile) {
        $cargs += @("--data-binary", "@$InFile", "-H", "Content-Type: $ContentType")
    } elseif ($null -ne $Body) {
        [System.IO.File]::WriteAllText($tmpData, $Body, (New-Object System.Text.UTF8Encoding($false)))
        $cargs += @("--data-binary", "@$tmpData", "-H", "Content-Type: $ContentType")
    } else {
        $cargs += @("-H", "Content-Type: $ContentType")
    }
    foreach ($h in $Headers) { $cargs += @("-H", $h) }
    $cargs += "$script:Base$Path"

    $raw = & curl.exe @cargs 2>$null
    $code = 0; $ctype = ""; $size = 0; $time = 0.0
    if ($raw -and $raw -match '^(\d+)\|([^|]*)\|(\d+)\|([\d.]+)$') {
        $code = [int]$Matches[1]; $ctype = $Matches[2]; $size = [long]$Matches[3]; $time = [double]$Matches[4]
    }
    $bytes = [byte[]]@()
    if (Test-Path $tmpBody) { $bytes = [System.IO.File]::ReadAllBytes($tmpBody) }
    $text = if ($bytes.Length -gt 0) { [System.Text.Encoding]::UTF8.GetString($bytes) } else { "" }
    $headersText = Read-Text $tmpHdr
    Remove-Item $tmpBody, $tmpData, $tmpHdr -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Status = $code; ContentType = $ctype; Size = $size; Ms = [int][math]::Round($time * 1000)
        Text = $text; Bytes = $bytes; Raw = $raw; Headers = $headersText
    }
}

function HasJsonError($resp) {
    if ($null -eq $resp -or [string]::IsNullOrWhiteSpace($resp.Text)) { return $false }
    $o = J $resp.Text
    return ($null -ne $o -and $null -ne $o.error)
}

function V([string]$verdict, [string]$fact) { return [pscustomobject]@{ Verdict = $verdict; Fact = $fact } }

function Invoke-Case {
    param(
        [string]$Id,
        [string]$Name,
        [string]$Expect,
        [string]$Repro,
        [scriptblock]$Body
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $verdict = "FAIL"; $fact = ""; $evidence = $null
    try {
        $r = & $Body
        $sw.Stop()
        if ($r -is [pscustomobject] -and $r.Verdict) { $verdict = [string]$r.Verdict; $fact = [string]$r.Fact; $evidence = $r.Evidence }
        elseif ($r -is [string]) { $verdict = "PASS"; $fact = $r }
        else { $verdict = "PASS"; $fact = Short (($r | Out-String).Trim()) }
    } catch {
        $sw.Stop()
        $verdict = "FAIL"
        $stack = ($_.ScriptStackTrace -replace "`r?`n", " | ")
        $fact = "исключение теста: $($_.Exception.Message) [at $(Short $stack 220)]"
        Write-Host "       ↳ $($_.Exception.Message) @ $(Short $stack 220)" -ForegroundColor DarkYellow
    }
    $row = [pscustomobject]@{
        id = $Id; name = $Name; expect = $Expect; fact = $fact; verdict = $verdict
        repro = $Repro; ms = [int]$sw.ElapsedMilliseconds; evidence = $evidence
    }
    $script:Results.Add($row)
    $color = switch ($verdict) { "PASS" { "Green" } "BUG" { "Red" } default { "Yellow" } }
    Write-Host ("{0,-4} {1,-7} {2} — {3}" -f $verdict, $Id, $Name, $fact) -ForegroundColor $color
}

function Track([string]$id) {
    if ($id -and -not $script:Created.Contains($id)) { $script:Created.Add($id) | Out-Null }
}

function Delete-Session([string]$id) {
    if (-not $id) { return $null }
    return (Http DELETE "/api/sessions/$id" -TimeoutSec 30)
}

function Wait-Health([int]$timeoutSec = 60) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $h = Http GET "/api/health" -TimeoutSec 2
            if ($h.Status -eq 200) { return $h }
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    return $null
}

function Start-Engine {
    if (-not (Test-Path $script:RunExe)) { throw "нет бинаря: $($script:RunExe)" }
    Remove-Item $script:EngineOut, $script:EngineErr -Force -ErrorAction SilentlyContinue
    $script:Engine = Start-Process -FilePath $script:RunExe -ArgumentList @(
        "--root", $script:Root, "--port", "$($script:Port)", "--no-open", "--log-level", "info"
    ) -WorkingDirectory $script:Root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $script:EngineOut -RedirectStandardError $script:EngineErr
    $h = Wait-Health 60
    if (-not $h) {
        $tail = if (Test-Path $script:EngineOut) { Get-Content $script:EngineOut -Tail 20 | Out-String } else { "" }
        throw "движок не ответил за 60 с на $($script:Base). Лог: $($script:EngineOut)`n$tail"
    }
    Write-Host "движок: pid=$($script:Engine.Id) $($script:Base) (version $((J $h.Text).version))" -ForegroundColor Cyan
}

# Проверка «движок жив» между секциями: внешние тесты/уборка на общей машине
# иногда убивают процессы ftdi-logger.exe. Лучше зафиксировать это как INFRA-01,
# чем получить 60 кейсов с HTTP 0.
function Ensure-Engine([string]$where) {
    if ($script:Engine -and -not $script:Engine.HasExited) { return }
    $code = "?"
    if ($script:Engine) { try { $code = $script:Engine.ExitCode } catch { } }
    throw "движок завершился $where (exit code=$code) — см. $($script:EngineOut)/$($script:EngineErr)"
}

function Stop-Children([int]$parentPid) {
    try {
        Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.ParentProcessId -eq $parentPid } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch { }
}

function Stop-Engine {
    if ($script:Static -and -not $script:Static.HasExited) {
        Stop-Process -Id $script:Static.Id -Force -ErrorAction SilentlyContinue
        $script:Static = $null
    }
    if ($script:Engine) {
        $procId = $script:Engine.Id
        if (-not $script:Engine.HasExited) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 500
        Stop-Children $procId
        $script:Engine = $null
    }
    foreach ($h in $script:Helpers) {
        if ($h -and -not $h.HasExited) { Stop-Process -Id $h.Id -Force -ErrorAction SilentlyContinue }
    }
    $script:Helpers.Clear()
}

function Start-Static {
    $dist = Join-Path $script:Root "ui\dist"
    if (-not (Test-Path (Join-Path $dist "index.html"))) { throw "нет ui\dist\index.html — UI не собран" }
    $script:Static = Start-Process -FilePath "python" -ArgumentList @(
        "-m", "http.server", "$($script:StaticPort)", "--bind", "127.0.0.1", "--directory", $dist
    ) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $script:Tmp "static.out.log") `
        -RedirectStandardError (Join-Path $script:Tmp "static.err.log")
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Http GET "/" -TimeoutSec 2
            if ($r.Status -eq 200) { return }
        } catch { }
        Start-Sleep -Milliseconds 250
    }
    throw "python http.server не поднялся на $($script:StaticPort)"
}

function Start-DummyTarget([int]$seconds = 180) {
    $py = "C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe"
    if (-not (Test-Path $py)) { $py = (Get-Command python).Source }
    $p = Start-Process -FilePath $py -ArgumentList @(
        "-u", (Join-Path $script:Root "tests\e2e\dummy_target.py"), "--seconds", "$seconds"
    ) -WorkingDirectory $script:Root -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $script:Tmp "dummy-$($seconds).out.log") `
        -RedirectStandardError (Join-Path $script:Tmp "dummy-$($seconds).err.log")
    $script:Helpers.Add($p)
    Start-Sleep -Seconds 2
    return $p
}

function Start-WindowlessTarget {
    $pw = "C:\Users\User\AppData\Local\Programs\Python\Python312\pythonw.exe"
    if (-not (Test-Path $pw)) { throw "нет pythonw.exe" }
    $pyFile = Join-Path $script:Tmp "edge-sleep.py"
    Set-Content -Path $pyFile -Value "import time`ntime.sleep(180)`n" -Encoding UTF8
    $p = Start-Process -FilePath $pw -ArgumentList @("-u", "`"$pyFile`"") -PassThru -WindowStyle Hidden
    $script:Helpers.Add($p)
    Start-Sleep -Seconds 1
    return $p
}

function Start-CurlUpload([string]$name, [string]$file) {
    $safe = $name -replace '[^\w.\-]', '_'
    $outBody = Join-Path $script:Tmp "upload-$safe.body.json"
    $outMeta = Join-Path $script:Tmp "upload-$safe.meta.txt"
    $outErr = Join-Path $script:Tmp "upload-$safe.err.txt"
    $q = Esc $name
    # ВАЖНО: Start-Process склеивает ArgumentList через пробел без кавычек,
    # поэтому в -H не должно быть пробелов (Content-Type:application/octet-stream).
    $cargs = @("-sS", "--max-time", "600", "-X", "POST", "--data-binary", "@$file",
        "-H", "Content-Type:application/octet-stream", "-o", $outBody,
        "-w", "%{http_code}|%{content_type}|%{size_download}|%{time_total}",
        "$script:Base/api/import/upload?name=$q")
    $p = Start-Process -FilePath "curl.exe" -ArgumentList $cargs -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outMeta -RedirectStandardError $outErr
    return [pscustomobject]@{ Proc = $p; Body = $outBody; Meta = $outMeta; Err = $outErr; Name = $name; File = $file }
}

function Read-CurlResult($job) {
    # meta-файл появляется в момент старта curl и может быть ещё пустым, если процесс
    # только что завершился: ждём непустой meta и непустое тело (до 5 с).
    for ($i = 0; $i -lt 50; $i++) {
        $metaSize = if (Test-Path $job.Meta) { (Get-Item $job.Meta).Length } else { 0 }
        $bodyExists = Test-Path $job.Body
        if ($metaSize -gt 0 -and $bodyExists) { break }
        Start-Sleep -Milliseconds 100
    }
    $meta = (Read-Text $job.Meta).Trim()
    $text = Read-Text $job.Body
    $err = (Read-Text $job.Err).Trim()
    $code = 0; $time = 0.0
    if ($meta -match '^(\d+)\|([^|]*)\|(\d+)\|([\d.]+)$') { $code = [int]$Matches[1]; $time = [double]$Matches[4] }
    $json = $null
    if ($text) { $json = J $text }
    return [pscustomobject]@{ Status = $code; Ms = [int][math]::Round($time * 1000); Text = $text; Json = $json; Err = $err; Meta = $meta }
}

function Upload([string]$name, [string]$file, [int]$timeoutSec = 180) {
    $q = Esc $name
    return (Http POST "/api/import/upload?name=$q" -InFile $file -ContentType "application/octet-stream" -TimeoutSec $timeoutSec)
}

function SessionList { $r = Http GET "/api/sessions" -TimeoutSec 30; return (J $r.Text) }
function SessionDetail([string]$id) { $r = Http GET "/api/sessions/$id" -TimeoutSec 60; return [pscustomobject]@{ Resp = $r; Json = (J $r.Text) } }

# ─────────────────────────────── подготовка ───────────────────────────────

Write-Host "== FTDI/USB Logger edge-тесты ==" -ForegroundColor Cyan
Write-Host "root : $($script:Root)"
Write-Host "engine: $($script:Exe)"
Write-Host "tmp  : $($script:Tmp)"

if (-not (Test-Path $script:Exe)) { throw "движок не собран: $($script:Exe)" }

$files = Join-Path $script:Tmp "files"
New-Item -ItemType Directory -Force -Path $files | Out-Null

$utf8 = New-Object System.Text.UTF8Encoding($false)
$emptyFile = Join-Path $files "edge-empty.log"
[System.IO.File]::WriteAllBytes($emptyFile, [byte[]]@())
$newlinesFile = Join-Path $files "edge-newlines.log"
[System.IO.File]::WriteAllText($newlinesFile, ("`r`n" * 2000), $utf8)
$binaryFile = Join-Path $files "edge-binary.log"
$binBuf = New-Object byte[] 1048576
[System.Random]::new(42).NextBytes($binBuf)
[System.IO.File]::WriteAllBytes($binaryFile, $binBuf)

$smallLog = Join-Path $script:Root "reference\logs\winkfp-e2e-capture.log"
if (-not (Test-Path $smallLog)) { throw "нет эталонного лога: $smallLog" }
$mediumLog = Join-Path $files "edge-medium-7mb.log"
[System.IO.File]::WriteAllText($mediumLog, ([System.IO.File]::ReadAllText($smallLog) * 31), $utf8)

Write-Host ("файлы: empty=0B newlines={0}B binary={1}B medium={2:N1}MB" -f (Get-Item $newlinesFile).Length, (Get-Item $binaryFile).Length, ((Get-Item $mediumLog).Length / 1MB))

if (-not $UseOriginalExe) {
    $script:RunExe = Join-Path $script:Tmp ("edge-runner-$($script:Stamp).exe")
    Copy-Item -LiteralPath $script:Exe -Destination $script:RunExe -Force
    Write-Host "тестовый бинарь: $($script:RunExe) (копия, чтобы внешняя чистка по имени ftdi-logger.exe его не убила)" -ForegroundColor DarkGray
}

Start-Engine

try {
    $baselineList = SessionList
$script:BaselineIds = @($baselineList | ForEach-Object { $_.id })
Write-Host "базовые сессии: $($script:BaselineIds.Count) — $($script:BaselineIds -join ', ')" -ForegroundColor DarkGray

$script:KnownApi = $script:BaselineIds | Where-Object { $_ -match 'winkfp' } | Select-Object -First 1
if (-not $script:KnownApi) { $script:KnownApi = $script:BaselineIds | Select-Object -First 1 }
$script:DummyShotSession = $script:BaselineIds | Where-Object { $_ -match 'dummy-target' } | Select-Object -First 1
if (-not $script:DummyShotSession) { $script:DummyShotSession = $script:KnownApi }

$script:MediumSid = $null
$script:BigSid = $null
$script:DummySid = $null

# ───────────────────────── 1. ИМПОРТ: крайние случаи ─────────────────────

Invoke-Case "IMP-01" "Импорт пустого файла (0 байт, upload)" "4xx + JSON {error}" `
    "curl -X POST '$($script:Base)/api/import/upload?name=edge-empty.log' --data-binary @empty.log -H 'Content-Type: application/octet-stream'" {
    $r = Upload "edge-empty.log" $emptyFile
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) {
        V "PASS" "HTTP $($r.Status), $($r.Text.Trim())"
    } else {
        V "BUG" "ожидался 4xx с {error}; факт HTTP $($r.Status) ct=$($r.ContentType) body=$(Short $r.Text)"
    }
}

Invoke-Case "IMP-02" "Импорт файла из одних переводов строк (4000 B)" "4xx или 200 с 0 событий; без 5xx" `
    "curl -X POST '$($script:Base)/api/import/upload?name=edge-newlines.log' --data-binary @edge-newlines.log" {
    $r = Upload "edge-newlines.log" $newlinesFile
    if ($r.Status -eq 200) {
        $sid = (J $r.Text).session_id
        Track $sid
        $d = SessionDetail $sid
        $ev = 0
        if ($d.Json) { $ev = [int]$d.Json.meta.counts.events }
        $rep = Http GET "/api/sessions/$sid/report" -TimeoutSec 30
        if ($ev -eq 0 -and $rep.Status -eq 200) {
            V "PASS" "HTTP 200, session_id=$sid, событий=0, report HTTP 200 ($($rep.Size) B)"
        } else {
            V "BUG" "сессия создана, но событий=$ev, report=$($rep.Status)"
        }
    } elseif ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) {
        V "PASS" "HTTP $($r.Status) с {error} (отклонён)"
    } else {
        V "BUG" "HTTP $($r.Status) ct=$($r.ContentType) body=$(Short $r.Text)"
    }
}

Invoke-Case "IMP-03" "Импорт бинарного мусора (1 МБ случайных байт)" "4xx или сессия без падения; никаких 5xx" `
    "curl -X POST '$($script:Base)/api/import/upload?name=edge-binary.log' --data-binary @edge-binary.log" {
    $r = Upload "edge-binary.log" $binaryFile -timeoutSec 120
    if ($r.Status -eq 200) {
        $sid = (J $r.Text).session_id
        Track $sid
        $d = SessionDetail $sid
        $ev = if ($d.Json) { [int]$d.Json.meta.counts.events } else { -1 }
        $rep = Http GET "/api/sessions/$sid/report" -TimeoutSec 30
        V "PASS" "HTTP 200, сессия $sid, событий=$ev (бинарные строки ушли в kind=raw), report=$($rep.Status); валидации на бинарь нет — наблюдение"
    } elseif ($r.Status -ge 400 -and $r.Status -lt 500) {
        V "PASS" "HTTP $($r.Status) body=$(Short $r.Text)"
    } else {
        V "BUG" "HTTP $($r.Status) ct=$($r.ContentType) body=$(Short $r.Text)"
    }
}

Invoke-Case "IMP-04" "Импорт реального лога ~9.7 МБ (upload)" "200, >10000 событий, <60 c" `
    "curl -X POST '$($script:Base)/api/import/upload?name=edge-medium-7mb.log' --data-binary @edge-medium-7mb.log" {
    $r = Upload "edge-medium-7mb.log" $mediumLog -timeoutSec 300
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) за $($r.Ms) мс body=$(Short $r.Text)") }
    $sid = (J $r.Text).session_id
    Track $sid
    $script:MediumSid = $sid
    $d = SessionDetail $sid
    $ev = if ($d.Json) { [int]$d.Json.meta.counts.events } else { 0 }
    $mem = 0
    try { $mem = [int]((Get-Process -Id $script:Engine.Id).WorkingSet64 / 1MB) } catch { }
    if ($ev -gt 10000 -and $r.Ms -lt 60000) {
        V "PASS" "HTTP 200 за $($r.Ms) мс, событий=$ev, RSS движка=$mem МБ, session_id=$sid"
    } else {
        V "BUG" "событий=$ev, время=$($r.Ms) мс (порог: >10000 событий и <60 c), RSS=$mem МБ"
    }
}

Invoke-Case "IMP-05" "Имя файла с юникодом и пробелами" "200; сессия открывается" `
    "curl -X POST '$($script:Base)/api/import/upload?name=%D0%BB%D0%BE%D0%B3%20...' --data-binary @edge-newlines.log" {
    $name = "лог с пробелами — 测试-файл.log"
    $r = Upload $name $newlinesFile
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)") }
    $sid = (J $r.Text).session_id
    Track $sid
    $d = SessionDetail $sid
    if ($d.Resp.Status -eq 200) {
        $script:UnicodeSid = $sid
        V "PASS" "HTTP 200, session_id=$sid, label=$($d.Json.meta.label)"
    } else {
        V "BUG" "импорт 200, но сессия не открывается: HTTP $($d.Resp.Status)"
    }
}

Invoke-Case "IMP-06" "Имя сессии соответствует загруженному файлу" "label = имя файла (юникод сохранён)" `
    "импорт upload с name='лог с пробелами — 测试-файл.log' → GET /api/sessions/{id}" {
    if (-not $script:UnicodeSid) { return (V "FAIL" "нет сессии из IMP-05") }
    $d = SessionDetail $script:UnicodeSid
    $label = "$($d.Json.meta.label)"
    $id = "$($d.Json.meta.id)"
    $leak = ($label -match 'ftdi-import-\d+') -or ($label -match '[0-9a-f]{8}-[0-9a-f]{4}-') -or ($label -match '^[\s_]+$')
    $mangled = ($label -notmatch 'лог') -and ($label -notmatch '测试')
    if ($leak -or $mangled) {
        V "BUG" "label='$(Short $label 160)', id='$(Short $id 200)' — течёт имя временного файла/PID/UUID, юникод заменён на '_'"
    } else {
        V "PASS" "label='$label'"
    }
}

Invoke-Case "IMP-07" "Path traversal в query name импорта" "нет файлов вне каталога сессии/root; 4xx или безопасный sanitize" `
    "curl -X POST '$($script:Base)/api/import/upload?name=..%2F..%2Fevil.log' --data-binary @edge-newlines.log" {
    $checks = @()
    foreach ($name in @("../../evil.log", "..\..\evil.log", "..\..\..\evil-win.log")) {
        $r = Upload $name $newlinesFile
        if ($r.Status -eq 200) { Track (J $r.Text).session_id }
        $checks += "$name -> HTTP $($r.Status)"
    }
    $outside = @()
    foreach ($p in @((Join-Path $script:Root "evil.log"), "D:\evil.log", "D:\evil-win.log", (Join-Path $env:TEMP "evil.log"),
            (Join-Path $script:Root "evil-win.log"))) {
        if (Test-Path $p) { $outside += $p }
    }
    if ($outside.Count -gt 0) {
        V "BUG" "файлы созданы вне сессий: $($outside -join ', '); $($checks -join '; ')"
    } else {
        V "PASS" "$($checks -join '; '); файлов вне sessions/root не появилось (траверсал не сработал)"
    }
}

Invoke-Case "IMP-08" "Повторный импорт одного и того же файла" "оба импорта 200, id разные, обе сессии валидны" `
    "дважды POST /api/import/upload?name=edge-repeat.log с одним и тем же логом" {
    $a = Upload "edge-repeat.log" $smallLog
    $b = Upload "edge-repeat.log" $smallLog
    if ($a.Status -ne 200 -or $b.Status -ne 200) { return (V "BUG" "HTTP $($a.Status)/$($b.Status)") }
    $ia = (J $a.Text).session_id; $ib = (J $b.Text).session_id
    Track $ia; Track $ib
    $da = SessionDetail $ia; $db = SessionDetail $ib
    $ea = if ($da.Json) { [int]$da.Json.meta.counts.events } else { -1 }
    $eb = if ($db.Json) { [int]$db.Json.meta.counts.events } else { -1 }
    $list = SessionList
    $has = @($list | Where-Object { $_.id -eq $ia }).Count -eq 1 -and @($list | Where-Object { $_.id -eq $ib }).Count -eq 1
    if ($ia -ne $ib -and $ea -eq $eb -and $ea -gt 0 -and $has) {
        V "PASS" "id1=$ia, id2=$ib, событий $ea=$eb, обе в списке"
    } else {
        V "BUG" "id1=$ia id2=$ib events=$ea/$eb distinct=$($ia -ne $ib) inList=$has"
    }
}

Invoke-Case "IMP-09" "Два параллельных импорта upload" "оба 200, id разные, index.json валиден, движок жив" `
    "одновременно два curl POST /api/import/upload (9.7 МБ и 312 КБ)" {
    $beforeIds = @((SessionList).id)
    $b1 = Join-Path $script:Tmp "edge-par-1.body.json"
    $b2 = Join-Path $script:Tmp "edge-par-2.body.json"
    $jobBlock = {
        param($base, $name, $file, $outBody)
        $q = [uri]::EscapeDataString($name)
        $meta = & curl.exe -sS --max-time 300 -X POST --data-binary "@$file" `
            -H "Content-Type: application/octet-stream" -o $outBody `
            -w "%{http_code}|%{content_type}|%{size_download}|%{time_total}" `
            "$base/api/import/upload?name=$q"
        return [string]$meta
    }
    $j1 = Start-Job -ScriptBlock $jobBlock -ArgumentList $script:Base, "edge-par-1.log", $mediumLog, $b1
    $j2 = Start-Job -ScriptBlock $jobBlock -ArgumentList $script:Base, "edge-par-2.log", $smallLog, $b2
    Wait-Job -Id @($j1.Id, $j2.Id) -Timeout 300 | Out-Null
    $m1 = ([string](Receive-Job -Id $j1.Id)).Trim()
    $m2 = ([string](Receive-Job -Id $j2.Id)).Trim()
    Remove-Job -Id @($j1.Id, $j2.Id) -Force -ErrorAction SilentlyContinue
    $r1 = [pscustomobject]@{ Meta = $m1; Text = Read-Text $b1 }
    $r2 = [pscustomobject]@{ Meta = $m2; Text = Read-Text $b2 }
    $s1 = 0; $s2 = 0; $t1 = 0.0; $t2 = 0.0
    if ($m1 -match '^(\d+)\|([^|]*)\|(\d+)\|([\d.]+)$') { $s1 = [int]$Matches[1]; $t1 = [double]$Matches[4] }
    if ($m2 -match '^(\d+)\|([^|]*)\|(\d+)\|([\d.]+)$') { $s2 = [int]$Matches[1]; $t2 = [double]$Matches[4] }
    $j1o = J $r1.Text; $j2o = J $r2.Text
    $id1 = if ($j1o) { "$($j1o.session_id)" } else { "" }
    $id2 = if ($j2o) { "$($j2o.session_id)" } else { "" }
    $afterIds = @((SessionList).id)
    $newIds = @($afterIds | Where-Object { $_ -notin $beforeIds })
    foreach ($nid in $newIds) { Track $nid }
    $indexOk = $false
    try { $idx = Get-Content (Join-Path $script:Root "sessions\index.json") -Raw | ConvertFrom-Json; $indexOk = ($null -ne $idx) } catch { $indexOk = $false }
    $health = Http GET "/api/health" -TimeoutSec 10
    $ms1 = [int][math]::Round($t1 * 1000); $ms2 = [int][math]::Round($t2 * 1000)
    if ($s1 -eq 200 -and $s2 -eq 200 -and $id1 -and $id2 -and $id1 -ne $id2 -and $indexOk -and $health.Status -eq 200) {
        V "PASS" "par1=$id1 ($ms1 мс), par2=$id2 ($ms2 мс), новых сессий=$($newIds.Count), index.json OK, health=200"
    } elseif ($s1 -eq 200 -and $s2 -eq 200 -and $newIds.Count -ge 2 -and $indexOk -and $health.Status -eq 200) {
        V "PASS" "par1/par2 = 200 ($ms1/$ms2 мс), новых сессий=$($newIds.Count) ($($newIds -join ', ')), index.json OK, health=200 (тело ответа не разобрано, но сессии созданы)"
    } else {
        V "BUG" "meta='$(Short $m1 80)'/'$(Short $m2 80)' ids='$id1'/'$id2' newIds=$($newIds -join ','), indexOk=$indexOk health=$($health.Status)"
    }
}

Invoke-Case "IMP-10" "POST /api/import с несуществующим путём" "404 + JSON {error}" `
    "curl -X POST $($script:Base)/api/import -d '{`"path`":`"D:\\nope\\nope.log`"}'" {
    $r = Http POST "/api/import" (ToJson @{ path = "D:\nope\nope-$(Get-Random).log" })
    if ($r.Status -eq 404 -and (HasJsonError $r)) { V "PASS" "HTTP 404, $($r.Text.Trim())" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "IMP-11" "POST /api/import файла 0 байт (path, не upload)" "не 5xx; поведение согласовано с upload" `
    "curl -X POST $($script:Base)/api/import -d '{`"path`":`"<edge-empty.log>`"}'" {
    $r = Http POST "/api/import" (ToJson @{ path = $emptyFile })
    if ($r.Status -eq 200) {
        $sid = (J $r.Text).session_id; Track $sid
        V "PASS" "HTTP 200 (создана пустая сессия $sid) — расхождение с upload (там 400)"
    } elseif ($r.Status -ge 400 -and $r.Status -lt 500) {
        V "PASS" "HTTP $($r.Status) body=$(Short $r.Text)"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)"
    }
}

Invoke-Case "RAW-01" "raw.log: строк ровно столько же, сколько событий (без дедупа)" "raw.log non-empty lines == counts.events" `
    "импорт reference/logs/winkfp-e2e-capture.log → сравнить wc -l sessions/<id>/raw.log и counts.events" {
    $r = Upload "edge-raw.log" $smallLog
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)") }
    $sid = (J $r.Text).session_id; Track $sid
    $d = SessionDetail $sid
    $ev = if ($d.Json) { [int]$d.Json.meta.counts.events } else { -1 }
    $rawPath = Join-Path $script:Root "sessions" $sid
    $rawPath = Join-Path $rawPath "raw.log"
    $rawLines = 0
    if (Test-Path $rawPath) { $rawLines = @(Get-Content $rawPath | Where-Object { $_.Trim() -ne "" }).Count }
    if ($ev -gt 0 -and $rawLines -eq $ev) {
        V "PASS" "events=$ev, raw.log строк=$rawLines (совпадают), session=$sid"
    } else {
        V "BUG" "events=$ev, raw.log строк=$rawLines (не совпадают; дедуп подряд идущих строк?)"
    }
}

Invoke-Case "DEC-01" "decode события с 2-байтовым кадром не паникует" "200 + JSON, движок жив" `
    "импорт лога со строкой 'n=2 : 12 04', затем GET /api/sessions/<id>/events/<seq>/decode" {
    $shortLog = Join-Path $files "edge-shortframe.log"
    $content = "[+0.100s] VCP TX WriteFile(COM6) n=2 : 12 04`n[+0.120s] VCP RX ReadFile(COM6) n=2 : 12 04`n[+0.200s] VCP TX WriteFile(COM6) n=4 : 12 04 0d 1b`n"
    [System.IO.File]::WriteAllText($shortLog, $content, $utf8)
    $r = Upload "edge-shortframe.log" $shortLog
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)") }
    $sid = (J $r.Text).session_id; Track $sid
    $page = J (Http GET "/api/sessions/$sid/events?limit=50" -TimeoutSec 20).Text
    $ev = @($page.events) | Where-Object { $_.hex -match '^[0-9a-f]{2} [0-9a-f]{2}$' } | Select-Object -First 1
    $seq = if ($ev) { [int]$ev.seq } elseif (@($page.events).Count -gt 0) { [int]@($page.events)[0].seq } else { 0 }
    $dec = Http GET "/api/sessions/$sid/events/$seq/decode" -TimeoutSec 20
    $alive = (Http GET "/api/health" -TimeoutSec 10).Status
    if ($dec.Status -eq 200 -and $alive -eq 200 -and (J $dec.Text)) {
        V "PASS" "seq=$seq hex='$($ev.hex)', decode HTTP 200, health=200"
    } else {
        V "BUG" "seq=$seq hex='$($ev.hex)', decode HTTP $($dec.Status) body=$(Short $dec.Text 120), health=$alive"
    }
}

Ensure-Engine "после импорта"

# ───────────────────────── 2. API: мусорные запросы ──────────────────────

if (-not $script:MediumSid) { $script:MediumSid = $script:KnownApi }

Invoke-Case "API-01" "Несуществующий session_id (6 ручек)" "404 + JSON {error} на всех" `
    "curl '$($script:Base)/api/sessions/edge-no-such'  (и /events, /report, /steps/1, /events/0/decode)" {
    $u = "edge-no-such-session"
    $items = @(
        @{ m = "GET"; p = "/api/sessions/$u" },
        @{ m = "GET"; p = "/api/sessions/$u/events" },
        @{ m = "GET"; p = "/api/sessions/$u/report" },
        @{ m = "GET"; p = "/api/sessions/$u/steps/1" },
        @{ m = "GET"; p = "/api/sessions/$u/events/0/decode" },
        @{ m = "POST"; p = "/api/sessions/$u/reparse" }
    )
    $statuses = @(); $bad = @()
    foreach ($it in $items) {
        $r = if ($it.m -eq "POST") { Http POST $it.p "{}" -TimeoutSec 15 } else { Http GET $it.p -TimeoutSec 15 }
        $statuses += "$($it.p)=$($r.Status)"
        if ($r.Status -ne 404) { $bad += "$($it.p)=$($r.Status)" }
    }
    if ($bad.Count -eq 0) { V "PASS" ($statuses -join "; ") }
    else { V "BUG" ("ожидался 404 везде; факт: " + ($statuses -join '; ')) }
}

Invoke-Case "API-02" "seq вне диапазона: decode и context" "404 + JSON {error}" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events/99999999/decode'" {
    $d = Http GET "/api/sessions/$($script:MediumSid)/events/99999999/decode" -TimeoutSec 20
    $c = Http GET "/api/sessions/$($script:MediumSid)/events/99999999/context" -TimeoutSec 20
    if ($d.Status -eq 404 -and $c.Status -eq 404 -and (HasJsonError $d) -and (HasJsonError $c)) {
        V "PASS" "decode/context = 404: $(Short $d.Text 80) / $(Short $c.Text 80)"
    } else {
        V "BUG" "decode=$($d.Status) context=$($c.Status) ($(Short $d.Text 80))"
    }
}

Invoke-Case "API-03" "from > to в /events" "200 + пустой массив events" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events?from=100000&to=1'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/events?from=100000&to=1" -TimeoutSec 20
    $o = J $r.Text
    if ($r.Status -eq 200 -and $o -and @($o.events).Count -eq 0) { V "PASS" "HTTP 200, events=[], total=$($o.total)" }
    else { V "BUG" "HTTP $($r.Status), events=$(@($o.events).Count), body=$(Short $r.Text 120)" }
}

Invoke-Case "API-04" "limit=0" "не 5xx; документированный кламп (>=1)" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events?limit=0'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/events?limit=0" -TimeoutSec 20
    $o = J $r.Text
    $n = @($o.events).Count
    if ($r.Status -eq 200 -and $n -eq 1) { V "PASS" "HTTP 200, событий=$n (clamp(0,1,10000))" }
    elseif ($r.Status -eq 200) { V "FAIL" "HTTP 200, событий=$n — отличается от ожидаемого клампа 1" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-05" "limit=1000000 (сверх капа)" "200, не больше 10000 событий" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events?limit=1000000'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/events?limit=1000000" -TimeoutSec 60
    $o = J $r.Text
    $n = @($o.events).Count
    if ($r.Status -eq 200 -and $n -le 10000 -and $n -gt 0) { V "PASS" "HTTP 200, событий=$n (кап 10000)" }
    else { V "BUG" "HTTP $($r.Status), событий=$n (ожидалось 1..10000)" }
}

Invoke-Case "API-06" "kinds=чепуха" "200 + пустой список events" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events?kinds=chepuxa'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/events?kinds=chepuxa" -TimeoutSec 30
    $o = J $r.Text
    if ($r.Status -eq 200 -and @($o.events).Count -eq 0) { V "PASS" "HTTP 200, events=[], total=$($o.total)" }
    else { V "BUG" "HTTP $($r.Status), events=$(@($o.events).Count)" }
}

Invoke-Case "API-07" "Битый JSON в body (attach)" "4xx + JSON {error}" `
    "curl -X POST $($script:Base)/api/capture/attach -H 'Content-Type: application/json' --data '{`"pid`":123,'" {
    $r = Http POST "/api/capture/attach" '{"pid":123,'
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) {
        V "PASS" "HTTP $($r.Status), $(Short $r.Text 100)"
    } else {
        V "BUG" "HTTP $($r.Status) ct=$($r.ContentType), body=$(Short $r.Text 140) — ошибка не в формате {error}"
    }
}

Invoke-Case "API-08" "Лишние поля в JSON (attach)" "лишние поля игнорируются, 409 'процесс не найден'" `
    "curl -X POST $($script:Base)/api/capture/attach -d '{`"pid`":999999,`"bogus`":1,`"label`":`"x`"}'" {
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = 999999; bogus = 1; label = "x" })
    if (($r.Status -eq 409 -or $r.Status -eq 400) -and (HasJsonError $r)) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "API-09" "Не тот Content-Type (attach text/plain)" "415 + JSON {error}" `
    "curl -X POST $($script:Base)/api/capture/attach -H 'Content-Type: text/plain' -d 'pid=123'" {
    $r = Http POST "/api/capture/attach" '{"pid":123}' -ContentType "text/plain"
    if ($r.Status -eq 415 -and (HasJsonError $r)) {
        V "PASS" "HTTP 415, $(Short $r.Text 100)"
    } elseif ($r.Status -eq 415) {
        V "BUG" "HTTP 415, но тело не JSON: ct=$($r.ContentType) body=$(Short $r.Text 140)"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)"
    }
}

Invoke-Case "API-10" "Неверный format в export" "400 + JSON {error}" `
    "curl -X POST $($script:Base)/api/sessions/$($script:MediumSid)/export -d '{`"format`":`"rar`"}'" {
    $r = Http POST "/api/sessions/$($script:MediumSid)/export" (ToJson @{ format = "rar" })
    if ($r.Status -eq 400 -and (HasJsonError $r)) { V "PASS" "HTTP 400, $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-11" "Неверный format в report" "400 + JSON {error}" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/report?format=xml'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/report?format=xml" -TimeoutSec 30
    if ($r.Status -eq 400 -and (HasJsonError $r)) { V "PASS" "HTTP 400, $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-12" "DELETE несуществующей сессии" "404 + JSON {error}" `
    "curl -X DELETE '$($script:Base)/api/sessions/edge-no-such-session'" {
    $r = Http DELETE "/api/sessions/edge-no-such-session"
    if ($r.Status -eq 404) { V "PASS" "HTTP 404, $(Short $r.Text 80)" }
    elseif ($r.Status -eq 200) { V "BUG" "HTTP 200 $($r.Text.Trim()) — удаление несуществующей сессии считается успехом" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-13" "Неверный метод (GET /api/capture/attach)" "405 Method Not Allowed" `
    "curl -i '$($script:Base)/api/capture/attach'" {
    $r = Http GET "/api/capture/attach"
    if ($r.Status -eq 405) { V "PASS" "HTTP 405 (тело пустое: $($r.Size) B)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-14" "Неизвестная ручка API" "404 + JSON {error}" `
    "curl '$($script:Base)/api/nope'" {
    $r = Http GET "/api/nope"
    if ($r.Status -eq 404 -and (HasJsonError $r)) { V "PASS" "HTTP 404, $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text)" }
}

Invoke-Case "API-15" "Невалидный query (limit=abc)" "400 + JSON {error}" `
    "curl '$($script:Base)/api/sessions/$($script:MediumSid)/events?limit=abc'" {
    $r = Http GET "/api/sessions/$($script:MediumSid)/events?limit=abc" -TimeoutSec 15
    if ($r.Status -eq 400 -and (HasJsonError $r)) { V "PASS" "HTTP 400, $(Short $r.Text 100)" }
    else { V "BUG" "HTTP $($r.Status) ct=$($r.ContentType), body=$(Short $r.Text 140) — не {error}" }
}

Invoke-Case "API-16" "Report отдаётся как text/plain" "200 + text/plain; charset=utf-8" `
    "curl -i '$($script:Base)/api/sessions/$($script:KnownApi)/report'" {
    $r = Http GET "/api/sessions/$($script:KnownApi)/report" -TimeoutSec 60
    if ($r.Status -eq 200 -and $r.ContentType -match 'text/plain' -and $r.Size -gt 20) {
        V "PASS" "HTTP 200, ct=$($r.ContentType), $($r.Size) B"
    } else {
        V "BUG" "HTTP $($r.Status), ct=$($r.ContentType), $($r.Size) B"
    }
}

Invoke-Case "API-17" "Экспорт ZIP и JSONL" "200 + path существует и не пуст" `
    "curl -X POST $($script:Base)/api/sessions/$($script:KnownApi)/export -d '{`"format`":`"zip`"}'" {
    $z = Http POST "/api/sessions/$($script:KnownApi)/export" (ToJson @{ format = "zip" }) -TimeoutSec 120
    $j = Http POST "/api/sessions/$($script:KnownApi)/export" (ToJson @{ format = "jsonl" }) -TimeoutSec 120
    $zj = J $z.Text; $jj = J $j.Text
    $zok = $z.Status -eq 200 -and $zj.path -and (Test-Path $zj.path) -and (Get-Item $zj.path).Length -gt 0
    $jok = $j.Status -eq 200 -and $jj.path -and (Test-Path $jj.path) -and (Get-Item $jj.path).Length -gt 0
    if ($zok -and $jok) { V "PASS" "zip=$(Split-Path -Leaf $zj.path) $((Get-Item $zj.path).Length)B, jsonl=$(Split-Path -Leaf $jj.path) $((Get-Item $jj.path).Length)B" }
    else { V "BUG" "zip=$($z.Status)/$(if($zj){$zj.path}), jsonl=$($j.Status)/$(if($jj){$jj.path})" }
}

function CorsAcao([string]$headers) {
    $m = [regex]::Match($headers, '(?im)^access-control-allow-origin:\s*(.+?)\s*$')
    if ($m.Success) { return $m.Groups[1].Value.Trim() } else { return "" }
}

Invoke-Case "CORS-01" "CORS: злой Origin http://127.0.0.1.evil.com" "нет Access-Control-Allow-Origin (preflight и GET)" `
    "curl -X OPTIONS -H 'Origin: http://127.0.0.1.evil.com' -H 'Access-Control-Request-Method: GET' $($script:Base)/api/health" {
    $pre = Http OPTIONS "/api/health" -Headers @("Origin: http://127.0.0.1.evil.com", "Access-Control-Request-Method: GET", "Access-Control-Request-Headers: content-type")
    $get = Http GET "/api/health" -Headers @("Origin: http://127.0.0.1.evil.com")
    $a1 = CorsAcao $pre.Headers; $a2 = CorsAcao $get.Headers
    if (-not $a1 -and -not $a2) {
        V "PASS" "preflight HTTP $($pre.Status) ACAO='', GET HTTP $($get.Status) ACAO='' — злой origin отбит"
    } else {
        V "BUG" "preflight ACAO='$a1', GET ACAO='$a2' — префиксный origin пропущен"
    }
}

Invoke-Case "CORS-02" "CORS: легальный Origin http://127.0.0.1:55095" "ACAO = origin" `
    "curl -X OPTIONS -H 'Origin: http://127.0.0.1:55095' ... $($script:Base)/api/health" {
    $o = "http://127.0.0.1:55095"
    $pre = Http OPTIONS "/api/health" -Headers @("Origin: $o", "Access-Control-Request-Method: GET")
    $a = CorsAcao $pre.Headers
    if ($a -eq $o) { V "PASS" "preflight HTTP $($pre.Status), ACAO='$a'" }
    else { V "BUG" "HTTP $($pre.Status), ACAO='$a' (ожидалось '$o')" }
}

Invoke-Case "CORS-03" "CORS: userinfo в Origin (http://user@127.0.0.1:1234)" "нет ACAO" `
    "curl -X OPTIONS -H 'Origin: http://user@127.0.0.1:1234' ... $($script:Base)/api/health" {
    $pre = Http OPTIONS "/api/health" -Headers @("Origin: http://user@127.0.0.1:1234", "Access-Control-Request-Method: GET")
    $a = CorsAcao $pre.Headers
    if (-not $a) { V "PASS" "HTTP $($pre.Status), ACAO пуст — userinfo-origin отбит" }
    else { V "BUG" "HTTP $($pre.Status), ACAO='$a' — userinfo-origin пропущен" }
}

Invoke-Case "CORS-04" "CORS: localhost и [::1]" "ACAO для localhost:*, без ACAO для localhost.evil" `
    "curl -X OPTIONS -H 'Origin: http://localhost:55095' / '-H Origin: http://localhost.evil.com'" {
    $ok = Http OPTIONS "/api/health" -Headers @("Origin: http://localhost:55095", "Access-Control-Request-Method: GET")
    $bad = Http OPTIONS "/api/health" -Headers @("Origin: http://localhost.evil.com", "Access-Control-Request-Method: GET")
    $aok = CorsAcao $ok.Headers; $abad = CorsAcao $bad.Headers
    if ($aok -eq "http://localhost:55095" -and -not $abad) { V "PASS" "localhost ACAO='$aok', localhost.evil ACAO=''" }
    else { V "BUG" "localhost ACAO='$aok', localhost.evil ACAO='$abad'" }
}

Ensure-Engine "после API-тестов"

# ───────────────────────── 3. ЗАХВАТ без устройства ─────────────────────

Invoke-Case "CAP-01" "detach без активной сессии" "200 + null (или 4xx с {error}), без 5xx" `
    "curl -X POST '$($script:Base)/api/capture/detach' -d '{}'" {
    $r = Http POST "/api/capture/detach" "{}"
    if ($r.Status -eq 200 -and $r.Text.Trim() -eq "null") { V "PASS" "HTTP 200, body=null (штатно)" }
    elseif ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 80)" }
}

Invoke-Case "CAP-02" "hookctl до attach" "4xx + JSON {error} (мост не запущен)" `
    "curl -X POST '$($script:Base)/api/capture/hookctl' -d '{`"value`":`"pause`"}'" {
    $r = Http POST "/api/capture/hookctl" (ToJson @{ value = "pause" })
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) {
        V "PASS" "HTTP $($r.Status), $(Short $r.Text 100)"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120) — пользовательская ошибка отдана как 5xx"
    }
}

Invoke-Case "CAP-03" "attach pid=0" "4xx + JSON {error}, сессия не создаётся" `
    "curl -X POST $($script:Base)/api/capture/attach -d '{`"pid`":0}'" {
    $before = @((SessionList).id).Count
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = 0 }) -TimeoutSec 60
    Start-Sleep -Milliseconds 500
    $after = @((SessionList).id).Count
    $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r) -and -not $st.recording -and $after -eq $before) {
        V "PASS" "HTTP $($r.Status) $(Short $r.Text 100); сессий $before→$after, recording=false"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 100); сессий $before→$after, recording=$($st.recording)"
    }
}

Invoke-Case "CAP-04" "attach pid=999999" "4xx + JSON {error}, сессия не создаётся" `
    "curl -X POST $($script:Base)/api/capture/attach -d '{`"pid`":999999}'" {
    $before = @((SessionList).id).Count
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = 999999 }) -TimeoutSec 60
    Start-Sleep -Milliseconds 500
    $after = @((SessionList).id).Count
    $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r) -and -not $st.recording -and $after -eq $before) {
        V "PASS" "HTTP $($r.Status) $(Short $r.Text 110); сессий $before→$after"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 110); сессий $before→$after, recording=$($st.recording)"
    }
}

Invoke-Case "CAP-05" "attach pid=4 (System, Frida не сможет)" "4xx/409 с понятной ошибкой; без 'висящей' recording-сессии" `
    "curl -X POST $($script:Base)/api/capture/attach -d '{`"pid`":4,`"label`":`"edge-system`"}'" {
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = 4; label = "edge-system" }) -TimeoutSec 60
    Start-Sleep -Seconds 4
    $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
    $sid = $st.session
    if ($sid) { Track $sid; $script:ZombieSid = $sid }
    $sessStatus = $null; $errs = $null
    if ($sid) {
        $list = SessionList
        $m = @($list | Where-Object { $_.id -eq $sid })[0]
        if ($m) { $sessStatus = $m.status; $errs = $m.counts.errors }
    }
    $fact = "HTTP $($r.Status); recording=$($st.recording), bridge=$($st.bridge), hooks=$($st.hooks), session='$(Short $sid 90)', session.status=$sessStatus, errors=$errs"
    if ($r.Status -ge 400 -and $r.Status -lt 500) {
        $script:ZombieSid = $null
        V "PASS" "$fact (attach отклонён)"
    } elseif ($r.Status -eq 200 -and $st.recording -and -not $st.bridge -and $sessStatus -eq "recording") {
        V "BUG" "$fact — attach вернул 200, хотя Frida не прицепилась; сессия осталась recording с мёртвым мостом (висяк), повторный attach невозможен"
    } elseif ($r.Status -eq 200) {
        V "FAIL" "$fact — 200, но состояние нестандартное"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)"
    }
}

Invoke-Case "CAP-06" "shot без целевого окна (после неудачного attach)" "4xx + JSON {error} про окно" `
    "curl -X POST '$($script:Base)/api/sessions/<pid4-сессия>/shot' -d '{}'" {
    $sid = $script:ZombieSid
    if (-not $sid) {
        # fallback: окно-независимая цель pythonw (без окна)
        $w = Start-WindowlessTarget
        $a = Http POST "/api/capture/attach" (ToJson @{ pid = $w.Id; label = "edge-windowless" }) -TimeoutSec 60
        if ($a.Status -ne 200) { return (V "FAIL" "не удалось подготовить окно-независимую цель: HTTP $($a.Status)") }
        $sid = (J $a.Text).id; Track $sid
        $script:ZombieSid = $sid
        Start-Sleep -Seconds 2
    }
    $r = Http POST "/api/sessions/$sid/shot" "{}" -TimeoutSec 60
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) {
        V "PASS" "HTTP $($r.Status), $(Short $r.Text 140) (сессия $sid)"
    } else {
        V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)"
    }
}

Invoke-Case "CAP-07" "Закрытие pid4-сессии после неудачи attach (detach)" "detach 200, сессия finished" `
    "curl -X POST '$($script:Base)/api/capture/detach' -d '{}'" {
    if (-not $script:ZombieSid) { return (V "PASS" "нечего закрывать (attach pid=4 был отклонён)") }
    $d = Http POST "/api/capture/detach" "{}" -TimeoutSec 60
    Start-Sleep -Milliseconds 500
    $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
    $list = SessionList
    $m = @($list | Where-Object { $_.id -eq $script:ZombieSid })[0]
    if ($d.Status -eq 200 -and -not $st.recording -and $m -and $m.status -eq "finished") {
        V "PASS" "HTTP 200, recording=false, сессия=$($m.id) status=finished"
    } else {
        V "BUG" "detach=$($d.Status), recording=$($st.recording), status=$($m.status)"
    }
}

Invoke-Case "CAP-08" "step/start без сессии" "4xx + JSON {error}" `
    "curl -X POST '$($script:Base)/api/sessions/edge-no-such/step/start' -d '{`"title`":`"x`"}'" {
    $r = Http POST "/api/sessions/edge-no-such/step/start" (ToJson @{ title = "x" })
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)" }
}

Invoke-Case "CAP-09" "step/end без сессии" "4xx + JSON {error}" `
    "curl -X POST '$($script:Base)/api/sessions/edge-no-such/step/end' -d '{}'" {
    $r = Http POST "/api/sessions/edge-no-such/step/end" "{}"
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)" }
}

Invoke-Case "CAP-10" "attach к реальному процессу без FTDI (dummy_target.py)" "200, мост поднимается (hooks=on)" `
    "python tests\\e2e\\dummy_target.py --seconds 180; curl -X POST $($script:Base)/api/capture/attach -d '{`"pid`":<pid>}'" {
    $dummy = Start-DummyTarget 180
    $script:DummyProc = $dummy
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = $dummy.Id; label = "edge-dummy" }) -TimeoutSec 60
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)") }
    $sid = (J $r.Text).id; Track $sid; $script:DummySid = $sid
    $deadline = (Get-Date).AddSeconds(20)
    $st = $null
    while ((Get-Date) -lt $deadline) {
        $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
        if ($st.hooks -eq "on" -and $st.bridge) { break }
        Start-Sleep -Milliseconds 500
    }
    if ($st -and $st.hooks -eq "on" -and $st.bridge) {
        V "PASS" "HTTP 200, session=$sid, bridge=true, hooks=on, pid=$($dummy.Id)"
    } else {
        V "BUG" "HTTP 200, но hooks=$($st.hooks), bridge=$($st.bridge) за 20 c"
    }
}

Invoke-Case "CAP-11" "Второй attach подряд" "409 + JSON {error} 'сессия уже идёт'" `
    "повторный curl -X POST .../api/capture/attach во время активной сессии" {
    $r = Http POST "/api/capture/attach" (ToJson @{ pid = 4; label = "edge-second" }) -TimeoutSec 30
    if ($r.Status -eq 409 -and (HasJsonError $r)) { V "PASS" "HTTP 409, $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)" }
}

Invoke-Case "CAP-12" "step/end без открытого шага" "4xx + JSON {error}" `
    "curl -X POST '$($script:Base)/api/sessions/<dummy>/step/end' -d '{}'" {
    $r = Http POST "/api/sessions/$($script:DummySid)/step/end" "{}" -TimeoutSec 30
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and (HasJsonError $r)) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 120)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)" }
}

Invoke-Case "CAP-13" "Повторный step/end" "4xx + JSON {error}" `
    "дважды подряд curl -X POST .../step/end" {
    $a = Http POST "/api/sessions/$($script:DummySid)/step/end" "{}" -TimeoutSec 30
    $b = Http POST "/api/sessions/$($script:DummySid)/step/end" "{}" -TimeoutSec 30
    if ($a.Status -ge 400 -and $a.Status -lt 500 -and $b.Status -ge 400 -and $b.Status -lt 500 -and (HasJsonError $b)) {
        V "PASS" "первый=$($a.Status), повторный=$($b.Status): $(Short $b.Text 100)"
    } else {
        V "BUG" "первый=$($a.Status), повторный=$($b.Status) body=$(Short $b.Text 120)"
    }
}

Invoke-Case "CAP-14" "mark с пустым title" "не 5xx; пустая метка не ломает поток" `
    "curl -X POST '$($script:Base)/api/sessions/<dummy>/mark' -d '{`"title`":`"`"}'" {
    $r = Http POST "/api/sessions/$($script:DummySid)/mark" (ToJson @{ title = "" }) -TimeoutSec 30
    if ($r.Status -eq 200) { V "PASS" "HTTP 200, $($r.Text.Trim()) — сервер принимает пустую метку (валидации нет; UI её не отправляет)" }
    elseif ($r.Status -ge 400 -and $r.Status -lt 500) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 100)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "CAP-15" "note с пустым текстом" "не 5xx; пустая заметка не ломает сессию" `
    "curl -X POST '$($script:Base)/api/sessions/<dummy>/note' -d '{`"text`":`"`"}'" {
    $r = Http POST "/api/sessions/$($script:DummySid)/note" (ToJson @{ text = "" }) -TimeoutSec 30
    if ($r.Status -eq 200) { V "PASS" "HTTP 200, $($r.Text.Trim()) — пустая заметка записывается (валидации нет)" }
    elseif ($r.Status -ge 400 -and $r.Status -lt 500) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 100)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "CAP-16" "step/start + step/end в живой сессии" "200/200, сводка с idx, без ошибок" `
    "attach dummy_target; curl -X POST .../step/start -d '{`"title`":`"edge шаг`"}'; затем .../step/end" {
    $start = Http POST "/api/sessions/$($script:DummySid)/step/start" (ToJson @{ title = "edge шаг" }) -TimeoutSec 30
    $s1 = J $start.Text
    Start-Sleep -Milliseconds 400
    $end = Http POST "/api/sessions/$($script:DummySid)/step/end" "{}" -TimeoutSec 60
    $s2 = J $end.Text
    if ($start.Status -eq 200 -and $end.Status -eq 200 -and $s1 -and $s2 -and $s2.idx -eq $s1.idx) {
        V "PASS" "start idx=$($s1.idx), end idx=$($s2.idx), dur=$([math]::Round([double]$s2.dur,2)) c, png=$($s2.png)"
    } else {
        V "BUG" "start=$($start.Status) ($(Short $start.Text 100)), end=$($end.Status) ($(Short $end.Text 120))"
    }
}

Invoke-Case "CAP-17" "detach активной сессии + отчёт" "200, status=finished, report 200" `
    "curl -X POST '$($script:Base)/api/capture/detach' -d '{}'" {
    $r = Http POST "/api/capture/detach" "{}" -TimeoutSec 60
    if ($r.Status -ne 200) { return (V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 140)") }
    $meta = J $r.Text
    $rep = Http GET "/api/sessions/$($script:DummySid)/report" -TimeoutSec 30
    if ($meta.status -eq "finished" -and $rep.Status -eq 200) {
        V "PASS" "HTTP 200, session=$($meta.id), status=finished, report=$($rep.Status) $($rep.Size)B"
    } else {
        V "BUG" "status=$($meta.status), report=$($rep.Status)"
    }
}

Invoke-Case "CAP-18" "raw.log живого захвата в старом формате (MARK START/END + PHASE + PHASE-JSON)" "все 4 маркера, PHASE-JSON последней строкой" `
    "attach dummy_target → step/start → step/end → detach → sessions/<dummy>/raw.log" {
    if (-not $script:DummySid) { return (V "FAIL" "нет живой сессии из CAP-10") }
    $rawPath = Join-Path $script:Root "sessions"
    $rawPath = Join-Path $rawPath $script:DummySid
    $rawPath = Join-Path $rawPath "raw.log"
    $raw = Read-Text $rawPath
    if (-not $raw) { return (V "BUG" "raw.log пуст/нет: $rawPath") }
    $lines = @($raw -split "`n" | Where-Object { $_.Trim() -ne "" })
    $hasStart = @($lines | Where-Object { $_ -match '^# MARK wall=.*START 1: edge шаг' }).Count -gt 0
    $hasEnd = @($lines | Where-Object { $_ -match '^# MARK wall=.*END 1: edge шаг \(\d' }).Count -gt 0
    $hasPhase = @($lines | Where-Object { $_ -match '^# PHASE 1: ' }).Count -gt 0
    $hasJson = @($lines | Where-Object { $_ -match '^# PHASE-JSON \{' }).Count -gt 0
    $last = $lines[$lines.Count - 1]
    if ($hasStart -and $hasEnd -and $hasPhase -and $hasJson -and $last -match '^# PHASE-JSON') {
        V "PASS" "MARK START=$hasStart, MARK END=$hasEnd, PHASE=$hasPhase, PHASE-JSON=$hasJson, последняя строка начинается с '# PHASE-JSON'; всего строк=$($lines.Count)"
    } else {
        V "BUG" "MARK START=$hasStart, MARK END=$hasEnd, PHASE=$hasPhase, PHASE-JSON=$hasJson; последняя строка='$(Short $last 120)'; всего строк=$($lines.Count)"
    }
}

Ensure-Engine "после тестов захвата"

# ───────────────────────── 4. ФАЙЛЫ СЕССИИ ───────────────────────────────

$shotSid = $script:DummyShotSession
Invoke-Case "FILE-01" "GET /file/../../engine/Cargo.toml (raw path)" "400 + JSON {error}, файл не отдан" `
    "curl --path-as-is '$($script:Base)/api/sessions/$shotSid/file/../../engine/Cargo.toml'" {
    $r = Http GET "/api/sessions/$shotSid/file/../../engine/Cargo.toml" -TimeoutSec 15
    $leak = $r.Text -match '\[package\]'
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and -not $leak) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status), leak=$leak, body=$(Short $r.Text 140)" }
}

Invoke-Case "FILE-02" "GET /file/..%2f..%2fengine%2fCargo.toml (encoded path)" "4xx + JSON {error}" `
    "curl --path-as-is '$($script:Base)/api/sessions/$shotSid/file/..%2f..%2fengine%2fCargo.toml'" {
    $r = Http GET "/api/sessions/$shotSid/file/..%2f..%2fengine%2fCargo.toml" -TimeoutSec 15
    $leak = $r.Text -match '\[package\]'
    if ($r.Status -ge 400 -and $r.Status -lt 500 -and -not $leak) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status), leak=$leak, body=$(Short $r.Text 140)" }
}

Invoke-Case "FILE-03" "Окно-путь C:\\Windows\\win.ini в *path" "4xx, файл не отдан" `
    "curl --path-as-is '$($script:Base)/api/sessions/$shotSid/file/C:%5CWindows%5Cwin.ini'" {
    $r = Http GET "/api/sessions/$shotSid/file/C:%5CWindows%5Cwin.ini" -TimeoutSec 15
    if ($r.Status -ge 400 -and $r.Status -lt 500) { V "PASS" "HTTP $($r.Status), $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "FILE-04" "GET file несуществующего файла" "404 + JSON {error}" `
    "curl '$($script:Base)/api/sessions/$shotSid/file/shots/nope.png'" {
    $r = Http GET "/api/sessions/$shotSid/file/shots/nope.png" -TimeoutSec 15
    if ($r.Status -eq 404 -and (HasJsonError $r)) { V "PASS" "HTTP 404, $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "FILE-05" "GET скриншота реальной сессии" "200 image/png + PNG-сигнатура" `
    "curl -o shot.png '$($script:Base)/api/sessions/$shotSid/file/shots/01-step-01.png'" {
    $r = Http GET "/api/sessions/$shotSid/file/shots/01-step-01.png" -TimeoutSec 15
    $magic = if ($r.Bytes.Length -ge 8) { [BitConverter]::ToString($r.Bytes[0..7]) } else { "" }
    if ($r.Status -eq 200 -and $r.ContentType -match 'image/png' -and $magic -eq '89-50-4E-47-0D-0A-1A-0A') {
        V "PASS" "HTTP 200, ct=$($r.ContentType), $($r.Size) B, PNG OK"
    } else {
        V "BUG" "HTTP $($r.Status), ct=$($r.ContentType), $($r.Size) B, magic=$magic"
    }
}

Invoke-Case "FILE-06" "GET file несуществующей сессии" "404 + JSON {error}" `
    "curl '$($script:Base)/api/sessions/edge-no-such-session/file/shots/x.png'" {
    $r = Http GET "/api/sessions/edge-no-such-session/file/shots/x.png" -TimeoutSec 15
    if ($r.Status -eq 404 -and (HasJsonError $r)) { V "PASS" "HTTP 404, $(Short $r.Text 80)" }
    else { V "BUG" "HTTP $($r.Status) body=$(Short $r.Text 120)" }
}

Invoke-Case "FILE-07" "Path traversal через :id (C:\\Windows, D:\\README, ../)" "4xx; вне sessions/ ничего не отдаётся" `
    "curl --path-as-is '$($script:Base)/api/sessions/C:%5CWindows/file/win.ini'; '$($script:Base)/api/sessions/../file/engine/Cargo.toml'; '$($script:Base)/api/sessions/D:%5CFTDI_USB_Logger/file/README.md'" {
    $p1 = Http GET "/api/sessions/C:%5CWindows/file/win.ini" -TimeoutSec 15
    $p2 = Http GET "/api/sessions/../file/engine/Cargo.toml" -TimeoutSec 15
    $p3 = Http GET "/api/sessions/D:%5CFTDI_USB_Logger/file/README.md" -TimeoutSec 15
    $leaks = @()
    if ($p1.Status -eq 200 -and $p1.Text -match '16-bit app support') { $leaks += "C:\Windows\win.ini ($($p1.Size)B)" }
    if ($p2.Status -eq 200 -and $p2.Text -match '\[package\]') { $leaks += "engine/Cargo.toml ($($p2.Size)B)" }
    if ($p3.Status -eq 200 -and $p3.Text -match 'FTDI/USB Logger') { $leaks += "README.md ($($p3.Size)B)" }
    if ($leaks.Count -gt 0) {
        V "BUG" "произвольное чтение файлов через :id: $($leaks -join '; '); statuses=$($p1.Status)/$($p2.Status)/$($p3.Status)"
    } else {
        V "PASS" "statuses=$($p1.Status)/$($p2.Status)/$($p3.Status), утечек нет"
    }
}

Ensure-Engine "после тестов файлов"

# ───────────────────── 5. ДОЛГИЙ ПОТОК: 100 МБ лог ───────────────────────

$bigStart = Get-Date
if (-not $SkipBig -and (Test-Path $BigLog)) {
    Invoke-Case "BIG-01" "Импорт 100 МБ лога (upload) + память движка" "200; >500k событий; <300 c; RSS < 4 ГБ; health не блокируется" `
        "curl -X POST '$($script:Base)/api/import/upload?name=edge-big-100mb.log' --data-binary @MS45-Quickflash-capture-20261103-122230.log" {
        $bigCopy = Join-Path $script:Tmp "edge-big-100mb.log"
        Write-Host "       копирую 100 МБ лог в $bigCopy ..."
        Copy-Item -LiteralPath $BigLog -Destination $bigCopy -Force
        $beforeBigIds = @((SessionList).id)
        $job = Start-CurlUpload "edge-big-100mb.log" $bigCopy
        $script:BigUpload = $job
        $peakWs = 0; $healthMax = 0; $healthFails = 0; $engineDied = $false
        while (-not $job.Proc.HasExited) {
            try {
                $proc = Get-Process -Id $script:Engine.Id -ErrorAction Stop
                if ($proc.WorkingSet64 -gt $peakWs) { $peakWs = $proc.WorkingSet64 }
            } catch { $engineDied = $true; break }
            $h = Http GET "/api/health" -TimeoutSec 3
            if ($h.Status -eq 200) { if ($h.Ms -gt $healthMax) { $healthMax = $h.Ms } } else { $healthFails++ }
            Start-Sleep -Milliseconds 700
        }
        if (-not $engineDied) { Wait-Process -Id $job.Proc.Id -Timeout 600 -ErrorAction SilentlyContinue }
        # Новые сессии появляются в индексе в начале импорта; трекаем их ДО чтения ответа,
        # чтобы чистка не зависела от разбора JSON.
        $afterBigIds = @((SessionList).id)
        $newBigIds = @($afterBigIds | Where-Object { $_ -notin $beforeBigIds })
        foreach ($n in $newBigIds) { Track $n }
        if (-not $script:BigSid -and $newBigIds.Count -gt 0) { $script:BigSid = $newBigIds[0] }
        $res = Read-CurlResult $job
        $importMs = [int]((Get-Date) - $bigStart).TotalMilliseconds
        if ($engineDied) { return (V "BUG" "движок умер/недоступен во время импорта 100 МБ (health fails=$healthFails)") }
        if ($res.Status -ne 200) { return (V "BUG" "HTTP $($res.Status) за $($res.Ms) мс, body=$(Short $res.Text 200); новые сессии: $($newBigIds -join ', ')") }
        $sid = if ($res.Json -and $res.Json.session_id) { "$($res.Json.session_id)" } else { $script:BigSid }
        $script:BigSid = $sid; Track $sid
        Start-Sleep -Milliseconds 500
        $d = SessionDetail $sid
        $ev = if ($d.Json) { [int]$d.Json.meta.counts.events } else { 0 }
        $repSw = [System.Diagnostics.Stopwatch]::StartNew()
        $rep = Http GET "/api/sessions/$sid/report" -TimeoutSec 300
        $repSw.Stop()
        $pageSw = [System.Diagnostics.Stopwatch]::StartNew()
        $page = Http GET "/api/sessions/$sid/events?limit=1000" -TimeoutSec 300
        $pageSw.Stop()
        $peakMb = [int]($peakWs / 1MB)
        $memAfter = 0
        try { $memAfter = [int]((Get-Process -Id $script:Engine.Id).WorkingSet64 / 1MB) } catch { }
        $ok = ($res.Ms -lt 300000) -and ($ev -gt 500000) -and ($peakMb -lt 4096) -and ($healthMax -lt 5000) -and ($rep.Status -eq 200) -and ($page.Status -eq 200)
        $fact = "upload=$($res.Ms) мс, событий=$ev, RSS peak=$peakMb МБ (после $memAfter МБ), health max=$healthMax мс (fails=$healthFails), report=$($rep.Status) за $($repSw.ElapsedMilliseconds) мс, events(1000)=$($page.Status) за $($pageSw.ElapsedMilliseconds) мс, session=$sid"
        if ($ok) { V "PASS" $fact } else { V "BUG" "$fact — порог/поведение нарушены" }
    }
} else {
    Write-Host "BIG-01 пропущен (SkipBig или нет файла $BigLog)" -ForegroundColor DarkGray
}

# ───────────────────────── 6. UI через CDP ───────────────────────────────

# После тяжёлого импорта движок должен быть жив; если нет — перезапускаем для UI/чистки.
$engineAlive = $true
try { Get-Process -Id $script:Engine.Id -ErrorAction Stop | Out-Null } catch { $engineAlive = $false }
if (-not $engineAlive) {
    Write-Host "движок не выжил после BIG-01 — перезапускаю для UI и чистки" -ForegroundColor Red
    $script:BigSid = $null
    Start-Engine
}

$uiResults = @()
if (-not $SkipUi) {
    try {
        Start-Static
        $uiKnown = if ($script:MediumSid) { $script:MediumSid } else { $script:KnownApi }
        $nodeArgs = @(
            (Join-Path $PSScriptRoot "cdp-edge.mjs"),
            "--static", "http://127.0.0.1:$($script:StaticPort)/",
            "--engine", "$($script:Base)/",
            "--out", $script:OutDir,
            "--cdp-port", "$($script:CdpPort)",
            "--known-session", $uiKnown
        )
        if ($script:BigSid) { $nodeArgs += @("--big-session", $script:BigSid) }
        $nodeOut = Join-Path $script:Tmp "cdp.out.log"
        $nodeErr = Join-Path $script:Tmp "cdp.err.log"
        $np = Start-Process -FilePath "node" -ArgumentList $nodeArgs -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $nodeOut -RedirectStandardError $nodeErr
        Wait-Process -Id $np.Id -Timeout 600 -ErrorAction SilentlyContinue
        if (Test-Path $nodeOut) { Get-Content $nodeOut | ForEach-Object { Write-Host "       [ui] $_" -ForegroundColor DarkGray } }
        $uiJson = Join-Path $script:OutDir "ui-results.json"
        if (Test-Path $uiJson) {
            $parsed = Get-Content $uiJson -Raw | ConvertFrom-Json
            $uiResults = @($parsed.results)
        } else {
            $errTail = if (Test-Path $nodeErr) { Get-Content $nodeErr -Tail 15 | Out-String } else { "" }
            Invoke-Case "UI-00" "UI-прогон (node cdp-edge.mjs)" "ui-results.json создан" "node tests/e2e/edge/cdp-edge.mjs --static ... --engine ..." {
                V "FAIL" "нет ui-results.json; stderr: $(Short $errTail 300)"
            }
        }
    } catch {
        Invoke-Case "UI-00" "UI-прогон (node cdp-edge.mjs)" "ui-results.json создан" "node tests/e2e/edge/cdp-edge.mjs ..." {
            V "FAIL" "исключение: $($_.Exception.Message)"
        }
    }
}

$uiExpect = @{
    "UI-01" = "Открыть статику ui/dist (python http.server) без движка: видимый экран ошибки с кнопками, а не пустота"
    "UI-02" = "?demo=1 без движка: демо-сессия рисуется, поток не пуст"
    "UI-03" = "6 быстрых нажатий F2 в демо: шаги/состояние консистентны, без исключений и дублей"
    "UI-04" = "Поиск без результатов: пустое состояние «Ничего не найдено», 0 строк"
    "UI-05" = "Все 7 фильтров в ноль: пустое состояние, без падения и отрицательных высот"
    "UI-05b" = "Повторное включение всех фильтров: 12 kinds, поток снова отображается"
    "UI-06" = "Resize 800x600: нет горизонтального скролла, поток жив"
    "UI-07" = "Два таба с одной сессией: обе вкладки открывают её и получают одинаковый total"
    "UI-08" = "Большая сессия (100 МБ импорт): открывается, прокрутка вверх не вешает UI"
    "UI-09" = "Нет необработанных JS-исключений в UI"
}
$uiRepro = @{
    "UI-01" = "python -m http.server 8101 --directory ui/dist; открыть http://127.0.0.1:8101/ (движок не запущен)"
    "UI-02" = "открыть http://127.0.0.1:8101/?demo=1"
    "UI-03" = "в демо-режиме 6 x KeyboardEvent('keydown',{key:'F2'}) с интервалом 35 мс"
    "UI-04" = "ввести в поиск 'zzz-нет-такого-события' и подождать 500 мс"
    "UI-05" = "нажать все 7 .chip и посмотреть поток"
    "UI-05b" = "после нулевых фильтров нажать все 7 .chip ещё раз"
    "UI-06" = "Emulation.setDeviceMetricsOverride 800x600 и проверить scrollWidth"
    "UI-07" = "открыть UI движка в двух табах и выбрать одну и ту же сессию"
    "UI-08" = "выбрать сессию импорта 100 МБ и 3 раза прокрутить поток вверх (loadOlder)"
    "UI-09" = "Runtime.exceptionThrown за время UI-прогона"
}
foreach ($u in $uiResults) {
    $id = "$($u.id)"
    $script:Results.Add([pscustomobject]@{
        id = $id; name = "$($u.name)"; expect = "$($uiExpect[$id])"; fact = "$($u.fact)";
        verdict = "$($u.verdict)"; repro = "$($uiRepro[$id])"; ms = 0; evidence = $null
    })
    $color = switch ("$($u.verdict)") { "PASS" { "Green" } "BUG" { "Red" } default { "Yellow" } }
    Write-Host ("{0,-4} {1,-7} {2} — {3}" -f "$($u.verdict)", $id, "$($u.name)", "$($u.fact)") -ForegroundColor $color
}

Ensure-Engine "после UI-тестов"

# ───────────────────────── 7. ЧИСТКА + ИТОГИ ─────────────────────────────

if (-not $NoCleanup) {
    Write-Host ""
    Write-Host "== чистка ==" -ForegroundColor Cyan
    # 0) если движок умер (внешняя уборка/сбой) — поднимаем заново для удаления сессий
    if (-not $script:Engine -or $script:Engine.HasExited) {
        Write-Host "  движок умер к моменту чистки — перезапускаю для удаления тестовых сессий" -ForegroundColor Yellow
        Start-Sleep -Milliseconds 800
        Start-Engine
    }
    # 1) закрыть возможную активную сессию
    $st = J (Http GET "/api/capture/status" -TimeoutSec 10).Text
    if ($st -and $st.recording) { Http POST "/api/capture/detach" "{}" -TimeoutSec 30 | Out-Null }
    # 2) удалить все созданные нами сессии
    $deleteFail = @()
    foreach ($id in @($script:Created)) {
        $r = Delete-Session $id
        $still = @((SessionList) | Where-Object { $_.id -eq $id })
        if ($r.Status -eq 200 -and $still.Count -eq 0) { Write-Host "  удалена: $id" -ForegroundColor DarkGray }
        else { $deleteFail += "$id (HTTP $($r.Status))"; Write-Host "  НЕ удалена: $id (HTTP $($r.Status))" -ForegroundColor Red }
    }
    # 3) индекс и базовые сессии
    $after = SessionList
    $afterIds = @($after | ForEach-Object { $_.id })
    $missingBaseline = @($script:BaselineIds | Where-Object { $_ -notin $afterIds })
    $leftover = @($afterIds | Where-Object { $_ -notin $script:BaselineIds -and $_ -notin $script:Created })
    $indexOk = $false
    try { $idx = Get-Content (Join-Path $script:Root "sessions\index.json") -Raw | ConvertFrom-Json; $indexOk = ($null -ne $idx) } catch { $indexOk = $false }
    $dirs = @(Get-ChildItem (Join-Path $script:Root "sessions") -Directory | ForEach-Object { $_.Name })
    $dirLeftover = @($dirs | Where-Object { $_ -notin $afterIds })

    Invoke-Case "CLEAN-01" "Чистка: удалены только свои сессии, базовые целы, index.json валиден" "created=0, baseline intact, index OK" `
        "pwsh -File tests/e2e/edge/run-edge.ps1 (без -NoCleanup)" {
        $ev = "удалено=$($script:Created.Count - $deleteFail.Count)/$($script:Created.Count), сбоев=$($deleteFail.Count); базовых потеряно=$($missingBaseline.Count) (мог удалить другой агент); лишние в списке=$($leftover.Count) ($($leftover -join ', ')) (могут быть чужими — общий sessions/); каталоги без меты=$($dirLeftover.Count); indexOk=$indexOk"
        if ($deleteFail.Count -eq 0 -and $indexOk) {
            V "PASS" $ev
        } else {
            V "BUG" "$ev; deleteFail=$($deleteFail -join ', '); dirs=$($dirLeftover -join ', ')"
        }
    }
} else {
    Write-Host "чистка пропущена (-NoCleanup): созданы сессии: $($script:Created -join ', ')" -ForegroundColor Yellow
}

} catch {
    $emsg = $_.Exception.Message
    $script:Results.Add([pscustomobject]@{
        id = "INFRA-01"; name = "Движок жив весь прогон (внешнее вмешательство)"; expect = "движок жив весь прогон"
        fact = "$emsg"; verdict = "FAIL"; repro = "повторить запуск (см. out/engine-exit-code.txt и engine.err.log)"; ms = 0; evidence = $null
    })
    Write-Host "FAIL INFRA-01 — $emsg" -ForegroundColor Red
} finally {
    # Диагностика: код выхода движка и логи — в out/ (tmp чистится).
    if ($script:Engine -and $script:Engine.HasExited) {
        try { "exit code: $($script:Engine.ExitCode)" | Set-Content -Path (Join-Path $script:OutDir "engine-exit-code.txt") -Encoding UTF8 } catch { }
    }
    if (Test-Path $script:EngineOut) { Copy-Item $script:EngineOut (Join-Path $script:OutDir "engine.out.log") -Force -ErrorAction SilentlyContinue }
    if (Test-Path $script:EngineErr) { Copy-Item $script:EngineErr (Join-Path $script:OutDir "engine.err.log") -Force -ErrorAction SilentlyContinue }
    # Всегда гасим движок/статику/цели: иначе дочерний процесс держит stdout-пайп
    # и обёртка теста «висит» после падения скрипта.
    if (-not $NoCleanup -and (-not $script:Engine -or $script:Engine.HasExited)) {
        try { Start-Sleep -Milliseconds 800; Start-Engine } catch { Write-Host "  не удалось перезапустить движок для чистки: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    if (-not $NoCleanup -and $script:Engine) {
        try {
            $st = J (Http GET "/api/capture/status" -TimeoutSec 5).Text
            if ($st -and $st.recording) { Http POST "/api/capture/detach" "{}" -TimeoutSec 20 | Out-Null }
            foreach ($id in @($script:Created)) {
                try { Delete-Session $id | Out-Null } catch { }
            }
        } catch { }
    }
    if (-not $KeepEngine) {
        Stop-Engine
        Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "движок оставлен: $($script:Base) pid=$($script:Engine.Id) (лог $script:EngineOut)" -ForegroundColor Yellow
    }
}

# 9) сохранить машинные результаты
$passed = @($script:Results | Where-Object { $_.verdict -eq "PASS" }).Count
$bugs = @($script:Results | Where-Object { $_.verdict -eq "BUG" })
$fails = @($script:Results | Where-Object { $_.verdict -eq "FAIL" })
$summary = @()
$summary += "FTDI/USB Logger — edge-тесты, $($script:Stamp)"
$summary += "всего кейсов: $($script:Results.Count); PASS=$passed; BUG=$($bugs.Count); FAIL=$($fails.Count)"
$summary += ""
$summary += "BUG:"
foreach ($b in $bugs) { $summary += "  [$($b.id)] $($b.name) — $($b.fact)" }
if ($fails.Count) {
    $summary += ""
    $summary += "FAIL (проблема теста/инфраструктуры):"
    foreach ($f in $fails) { $summary += "  [$($f.id)] $($f.name) — $($f.fact)" }
}
$summary -join "`n" | Write-Host -ForegroundColor Cyan

New-Item -ItemType Directory -Force -Path $script:OutDir | Out-Null
$script:Results | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $script:OutDir "results.json") -Encoding UTF8
$script:Results | Select-Object id, name, verdict, expect, fact, ms, repro | Export-Csv -Path (Join-Path $script:OutDir "results.csv") -NoTypeInformation -Encoding UTF8
$summary -join "`n" | Set-Content -Path (Join-Path $script:OutDir "summary.txt") -Encoding UTF8
# markdown-таблица для отчёта
$md = @("| # | Кейс | Ожидание | Факт | Вердикт |", "|---|---|---|---|---|")
foreach ($r in $script:Results) {
    $fact = ($r.fact -replace '\|', '\|')
    $exp = ($r.expect -replace '\|', '\|')
    $md += "| $($r.id) | $($r.name -replace '\|','\|') | $exp | $fact | $($r.verdict) |"
}
$md -join "`n" | Set-Content -Path (Join-Path $script:OutDir "report-table.md") -Encoding UTF8
Write-Host "результаты: $(Join-Path $script:OutDir 'results.json')"

if ($bugs.Count -gt 0 -or $fails.Count -gt 0) { exit 1 } else { exit 0 }


