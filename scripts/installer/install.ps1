# Установка FTDI/USB Logger (per-user, без прав администратора).
# Запускается из распакованного SFX: рядом лежит папка FTDI_USB_Logger\.
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms

$src = Join-Path $PSScriptRoot "FTDI_USB_Logger"
if (-not (Test-Path (Join-Path $src "ftdi-logger.exe"))) {
    [System.Windows.Forms.MessageBox]::Show("Не найден каталог приложения рядом с установщиком.", "FTDI/USB Logger")
    exit 1
}

$dst = $env:FTDI_LOGGER_INSTALL_DIR
if (-not $dst) { $dst = Join-Path $env:LOCALAPPDATA "FTDI_USB_Logger" }
$silent = [bool]$env:FTDI_LOGGER_SILENT

Write-Host "[setup] установка в $dst"
Get-Process ftdi-logger -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $dst | Out-Null
& robocopy $src $dst /E /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "ошибка копирования (robocopy $LASTEXITCODE)" }
Copy-Item (Join-Path $dst "app.ico") (Join-Path $dst "ftdi-logger.ico") -Force -ErrorAction SilentlyContinue

if (-not $silent) {
    $ws = New-Object -ComObject WScript.Shell
    $icon = Join-Path $dst "ftdi-logger.ico"
    $target = Join-Path $dst "logger.cmd"
    $desktop = [Environment]::GetFolderPath("Desktop")
    $lnk = $ws.CreateShortcut((Join-Path $desktop "FTDI USB Logger.lnk"))
    $lnk.TargetPath = $target
    $lnk.WorkingDirectory = $dst
    $lnk.IconLocation = $icon
    $lnk.Description = "FTDI/USB Logger"
    $lnk.Save()

    $startMenu = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\FTDI USB Logger"
    New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
    $sl = $ws.CreateShortcut((Join-Path $startMenu "FTDI USB Logger.lnk"))
    $sl.TargetPath = $target
    $sl.WorkingDirectory = $dst
    $sl.IconLocation = $icon
    $sl.Save()
    $ul = $ws.CreateShortcut((Join-Path $startMenu "Удалить FTDI USB Logger.lnk"))
    $ul.TargetPath = Join-Path $dst "uninstall.cmd"
    $ul.WorkingDirectory = $dst
    $ul.IconLocation = $icon
    $ul.Save()

    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FTDI_USB_Logger"
    New-Item -Path $reg -Force | Out-Null
    $values = @{
        DisplayName = "FTDI/USB Logger"
        DisplayVersion = "0.1.0"
        Publisher = "DaVinci Cyber Engineering"
        InstallLocation = $dst
        DisplayIcon = $icon
        UninstallString = ('"' + (Join-Path $dst "uninstall.cmd") + '"')
        NoModify = 1
        NoRepair = 1
    }
    foreach ($key in $values.Keys) {
        $ptype = if ($key -in @("NoModify", "NoRepair")) { "DWord" } else { "String" }
        New-ItemProperty -Path $reg -Name $key -Value $values[$key] -PropertyType $ptype -Force | Out-Null
    }
}

Write-Host "[setup] готово"
if (-not $silent) {
    [System.Windows.Forms.MessageBox]::Show(
        "FTDI/USB Logger установлен." + [Environment]::NewLine + "Ярлык на рабочем столе и в меню Пуск.",
        "FTDI/USB Logger") | Out-Null
    Start-Process -FilePath (Join-Path $dst "logger.cmd") -WorkingDirectory $dst
}
exit 0


