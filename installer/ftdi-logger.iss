; FTDI/USB Logger — установщик Inno Setup 6.
;
; Собирается из scripts\build-installer.ps1:
;   ISCC.exe /Q /DAppVersion=0.1.0 installer\ftdi-logger.iss
;
; Payload — portable-сборка (движок + UI + лаунчер + встроенный Python с Frida),
; которую готовит build-installer.ps1 в build\installer\payload\FTDI_USB_Logger.
; Установка per-user (без прав администратора) в %LOCALAPPDATA%\FTDI_USB_Logger;
; сам лаунчер при запуске запросит UAC (движку нужны права для Frida-хуков).

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
; AppId стабилен между версиями — по нему Inno находит прежнюю установку.
AppId={{A7E3C2B1-6F4D-4A8E-9C1B-2D3E4F5A6B7C}
AppName=FTDI/USB Logger
AppVersion={#AppVersion}
AppVerName=FTDI/USB Logger {#AppVersion}
AppPublisher=DaVinci Cyber Engineering
AppPublisherURL=https://github.com/Ydjin1984/ftdi-usb-logger
AppSupportURL=https://github.com/Ydjin1984/ftdi-usb-logger/issues
AppUpdatesURL=https://github.com/Ydjin1984/ftdi-usb-logger/releases
DefaultDirName={localappdata}\FTDI_USB_Logger
DefaultGroupName=FTDI USB Logger
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=FTDI_USB_Logger_Setup
SetupIconFile=..\assets\app.ico
UninstallDisplayIcon={app}\FTDI_USB_Logger.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany=DaVinci Cyber Engineering
VersionInfoDescription=FTDI/USB Logger installer
VersionInfoProductName=FTDI/USB Logger
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=DaVinci Cyber Engineering

[Languages]
; Русский — язык по умолчанию; английский оставляем вторым.
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Ярлык на рабочем столе"; GroupDescription: "Дополнительно:"; Flags: checkedonce
Name: "startmenuicon"; Description: "Ярлык в меню «Пуск»"; GroupDescription: "Дополнительно:"; Flags: checkedonce

[Files]
Source: "..\build\installer\payload\FTDI_USB_Logger\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\build\installer\payload\README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
; На обычных профилях ярлык создаёт сам Inno. Если {autodesktop} не раскрывается
; (OneDrive-редирект), запись пропускается с предупреждением, а ярлык создаст
; лаунчер при первом запуске (Launcher.cs, EnsureDesktopShortcut).
Name: "{autodesktop}\FTDI USB Logger"; Filename: "{app}\FTDI_USB_Logger.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: desktopicon
Name: "{autoprograms}\FTDI USB Logger"; Filename: "{app}\FTDI_USB_Logger.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: startmenuicon
Name: "{autoprograms}\Удалить FTDI USB Logger"; Filename: "{uninstallexe}"; Tasks: startmenuicon

[Run]
Filename: "{app}\FTDI_USB_Logger.exe"; Description: "Запустить FTDI/USB Logger"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Логи запуска создаются уже после установки — Inno их не знает, убираем явно.
Type: files; Name: "{app}\logger.out.log"
Type: files; Name: "{app}\logger.err.log"
; Каталог sessions не удаляем: сессии пользователя должны пережить удаление программы.

[Code]
{ Перед установкой закрываем запущенные лаунчер и движок, иначе их exe заняты. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('taskkill.exe', '/F /IM FTDI_USB_Logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM ftdi-logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

{ Ярлык на рабочем столе мог создать лаунчер (если Inno не смог) — убираем его
  при удалении. Путь к рабочему столу берём из реестра: shell-константы на
  OneDrive-профилях в установщике не раскрываются. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Desk, Link, Pwsh, Cmd: String;
  ResultCode: Integer;
begin
  { Перед удалением закрываем лаунчер и движок: иначе Inno ждёт освобождения exe. }
  if CurUninstallStep = usUninstall then
  begin
    Exec('taskkill.exe', '/F /IM FTDI_USB_Logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM ftdi-logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  if CurUninstallStep = usPostUninstall then
  begin
    if not RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
        'Desktop', Desk) then
      Exit;
    Link := Desk + '\FTDI USB Logger.lnk';
    if not FileExists(Link) then
      Exit;
    { На OneDrive-профилях DeleteFile из установщика молча не срабатывает:
      удаляем 64-битным PowerShell (Sysnative) и проверяем результат. }
    Pwsh := ExpandConstant('{win}\Sysnative\WindowsPowerShell\v1.0\powershell.exe');
    if not FileExists(Pwsh) then
      Pwsh := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
    Cmd := '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Remove-Item -LiteralPath ' + #39 + Link + #39 + ' -Force -ErrorAction SilentlyContinue"';
    Exec(Pwsh, Cmd, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if FileExists(Link) then
      DeleteFile(Link);
    if FileExists(Link) then
      Log('uninstall: ярлык не удалён ' + Link)
    else
      Log('uninstall: ярлык удалён ' + Link);
  end;
end;
