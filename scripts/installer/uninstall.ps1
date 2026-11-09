# Удаление FTDI/USB Logger (per-user).
$ErrorActionPreference = "SilentlyContinue"
Add-Type -AssemblyName System.Windows.Forms
$dst = $PSScriptRoot
$silent = [bool]$env:FTDI_LOGGER_SILENT

Get-Process ftdi-logger -ErrorAction SilentlyContinue | Stop-Process -Force

$ws = New-Object -ComObject WScript.Shell
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath("Desktop")) "FTDI USB Logger.lnk")
$startMenu = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\FTDI USB Logger"
Remove-Item -Recurse -Force $startMenu
Remove-Item -Recurse -Force "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FTDI_USB_Logger"

$removeAll = $true   # по умолчанию удаляем всё; в GUI спросим и можем сохранить сессии
if (-not $silent) {
    $answer = [System.Windows.Forms.MessageBox]::Show(
        "Удалить также сессии и настройки?`n`nДа — удалить всё.`nНет — сохранить папку sessions рядом с рабочим столом.",
        "Удалить FTDI/USB Logger",
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Question)
    if ($answer -eq [System.Windows.Forms.DialogResult]::Cancel) { exit 0 }
    $removeAll = ($answer -eq [System.Windows.Forms.DialogResult]::Yes)
}

$sessions = Join-Path $dst "sessions"
if (-not $removeAll -and (Test-Path $sessions)) {
    $keep = Join-Path ([Environment]::GetFolderPath("Desktop")) ("FTDI_USB_Logger_sessions_" + (Get-Date -Format "yyyyMMdd-HHmmss"))
    Move-Item $sessions $keep -Force
    if (-not $silent) {
        [System.Windows.Forms.MessageBox]::Show("Сессии сохранены: $keep", "FTDI/USB Logger") | Out-Null
    }
}

# Удаляем каталог после выхода из скрипта (иначе файл uninstall.ps1 занят).
$cleanup = Join-Path $env:TEMP ("ftdi-uninstall-" + [Guid]::NewGuid().ToString("N") + ".cmd")
$lines = @(
    "@echo off",
    "timeout /t 2 /nobreak >nul",
    "rmdir /s /q `"$dst`" >nul 2>&1",
    "del /q `"%~f0`" >nul 2>&1"
)
Set-Content -Path $cleanup -Value ($lines -join "`r`n") -Encoding ASCII
Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $cleanup) -WindowStyle Hidden
exit 0

