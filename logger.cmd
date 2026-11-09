@echo off
rem ============================================================================
rem  FTDI/USB Logger — запуск продукта (двойной клик / ярлык на рабочем столе).
rem  Один и тот же файл работает в двух раскладках:
rem    * dist\FTDI_USB_Logger\logger.cmd  — рядом лежит ftdi-logger.exe,
rem      ROOT для движка = этот же каталог (там ui\dist, sidecar, sessions);
rem    * <репозиторий>\logger.cmd        — exe в dist\FTDI_USB_Logger\.
rem
rem  Поведение:
rem    1) если http://127.0.0.1:PORT/api/health уже отвечает — открывает окно
rem       работающего экземпляра и выходит 0 («уже запущено»);
rem    2) запускает exe скрыто, stdout/stderr — в logger.out.log / logger.err.log;
rem    3) ждёт health до ~8 с; если не поднялся — показывает хвост лога, кто занял
rem       порт (netstat), подсказку про смену порта и держит окно 15 с.
rem
rem  Для отладки/автотестов (необязательно):
rem    FTDI_LOGGER_PORT=7812   — другой порт
rem    FTDI_LOGGER_NO_OPEN=1   — не открывать окно UI
rem ============================================================================
chcp 65001 >nul 2>&1
setlocal EnableExtensions

set "PORT=7811"
if defined FTDI_LOGGER_PORT set "PORT=%FTDI_LOGGER_PORT%"
set "EXTRA="
if defined FTDI_LOGGER_NO_OPEN set "EXTRA=--no-open"

rem --- раскладка: dist (exe рядом с cmd) или репозиторий -----------------------
rem ROOT = каталог этого файла без завершающего обратного слэша.
for %%I in ("%~dp0.") do set "ROOT=%%~fI"
if exist "%~dp0ftdi-logger.exe" (
    set "DIST=%ROOT%"
) else (
    set "DIST=%ROOT%\dist\FTDI_USB_Logger"
)
set "EXE=%DIST%\ftdi-logger.exe"
set "OUTLOG=%DIST%\logger.out.log"
set "ERRLOG=%DIST%\logger.err.log"
set "HEALTH=http://127.0.0.1:%PORT%/api/health"

if not exist "%EXE%" goto :not_built

rem --- 1. Уже запущено? health отвечает -> показать существующее окно ----------
rem HttpClient без прокси: неудачный запрос не должен ждать системный прокси.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Net.Http; $handler=[System.Net.Http.HttpClientHandler]::new(); $handler.UseProxy=$false; $h=[System.Net.Http.HttpClient]::new($handler); $h.Timeout=[TimeSpan]::FromMilliseconds(900); try { $r=$h.GetAsync('%HEALTH%').GetAwaiter().GetResult(); if([int]$r.StatusCode -eq 200){ exit 0 } } catch {}; exit 1"
if not errorlevel 1 goto :already_running

rem --- 2. Старт: логи в файлы, иначе пользователь не увидит причину ошибки ----
del /q "%OUTLOG%" "%ERRLOG%" >nul 2>nul
if defined EXTRA goto :start_with_extra
powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%EXE%' -ArgumentList '--root','%ROOT%','--port','%PORT%' -WorkingDirectory '%ROOT%' -RedirectStandardOutput '%OUTLOG%' -RedirectStandardError '%ERRLOG%' -WindowStyle Hidden"
if errorlevel 1 goto :start_failed
goto :wait_health
:start_with_extra
powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%EXE%' -ArgumentList '--root','%ROOT%','--port','%PORT%','--no-open' -WorkingDirectory '%ROOT%' -RedirectStandardOutput '%OUTLOG%' -RedirectStandardError '%ERRLOG%' -WindowStyle Hidden"
if errorlevel 1 goto :start_failed
:wait_health

rem --- 3. Ждём, пока поднимется health (не дольше ~8 с) -------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Net.Http; $handler=[System.Net.Http.HttpClientHandler]::new(); $handler.UseProxy=$false; $h=[System.Net.Http.HttpClient]::new($handler); $h.Timeout=[TimeSpan]::FromMilliseconds(900); $u='%HEALTH%'; $deadline=[DateTime]::UtcNow.AddSeconds(8); while([DateTime]::UtcNow -lt $deadline){ try { $r=$h.GetAsync($u).GetAwaiter().GetResult(); if([int]$r.StatusCode -eq 200){ exit 0 } } catch {}; Start-Sleep -Milliseconds 250 }; exit 1"
if not errorlevel 1 goto :started
goto :start_failed

:already_running
echo [logger] FTDI/USB Logger уже запущен: http://127.0.0.1:%PORT%/
echo [logger] открываю окно работающего экземпляра.
start "" msedge --app=http://127.0.0.1:%PORT%/
exit /b 0

:started
echo [logger] FTDI/USB Logger запущен: http://127.0.0.1:%PORT%/
echo [logger] логи: "%OUTLOG%" / "%ERRLOG%"
exit /b 0

:start_failed
echo.
echo [logger] FTDI/USB Logger не поднялся за 8 секунд.
echo [logger] логи движка:
echo            "%ERRLOG%"
echo            "%OUTLOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '%ERRLOG%') { Get-Content -LiteralPath '%ERRLOG%' -Encoding UTF8 -Tail 12 }"
powershell -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path -LiteralPath '%OUTLOG%') { Get-Content -LiteralPath '%OUTLOG%' -Encoding UTF8 -Tail 12 }"
echo.
echo [logger] кто слушает порт %PORT% (netstat -ano ^| findstr LISTENING):
netstat -ano | findstr "LISTENING" | findstr ":%PORT%"
echo.
echo [logger] Если порт занят чужим процессом или нужен другой порт:
echo            "%EXE%" --root "%ROOT%" --port 7812
echo            (из репозитория также: powershell -ExecutionPolicy Bypass -File scripts\run.ps1 -Port 7812)
echo.
timeout /t 15 /nobreak >nul 2>nul
exit /b 1

:not_built
echo.
echo [logger] FTDI/USB Logger ещё не собран.
echo [logger] Нет файла: "%EXE%"
echo.
echo       Соберите продукт из корня репозитория:
echo         powershell -ExecutionPolicy Bypass -File scripts\build.ps1
echo       Только движок, без интерфейса:
echo         powershell -ExecutionPolicy Bypass -File scripts\build.ps1 -SkipUi
echo.
echo       Затем снова запустите logger.cmd.
echo.
timeout /t 12 /nobreak >nul 2>nul
exit /b 1
