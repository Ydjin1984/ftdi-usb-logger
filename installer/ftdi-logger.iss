; FTDI/USB Logger — установщик Inno Setup 6.
;
; Собирается из scripts\build-installer.ps1:
;   ISCC.exe /Q /DAppVersion=0.3.4 installer\ftdi-logger.iss
;
; Payload — portable-сборка (движок + UI + лаунчер + встроенный Python с Frida),
; которую готовит build-installer.ps1 в build\installer\payload\FTDI_USB_Logger.
; Установка per-user (без прав администратора) в %LOCALAPPDATA%\FTDI_USB_Logger;
; сам лаунчер при запуске запросит UAC (движку нужны права для Frida-хуков).

#ifndef AppVersion
  #define AppVersion "0.3.4"
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
; Язык мастера выбирается явно: иначе при нескольких [Languages] окно выбора
; может не показаться, и английский установщик остаётся русским.
ShowLanguageDialog=yes
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

[CustomMessages]
; Свои строки обязаны быть на обоих языках, иначе английский мастер показывает
; русский текст: встроенные .isl их не содержат.
russian.DesktopIcon=Ярлык на рабочем столе
english.DesktopIcon=Create a desktop shortcut
russian.StartMenuIcon=Ярлык в меню «Пуск»
english.StartMenuIcon=Create a Start menu shortcut
russian.AdditionalIcons=Дополнительно:
english.AdditionalIcons=Additional icons:
russian.UninstallShortcut=Удалить FTDI USB Logger
english.UninstallShortcut=Uninstall FTDI USB Logger
russian.LaunchApp=Запустить FTDI/USB Logger
english.LaunchApp=Launch FTDI/USB Logger
russian.ProxyGroup=J2534:
english.ProxyGroup=J2534:
russian.ProxyTask=Установить J2534-прокси (второй канал захвата)
english.ProxyTask=Install the J2534 proxy (second capture channel)
russian.ProxyOk=J2534-прокси зарегистрирован как отдельное устройство. Включить его позже: Настройки → J2534.
english.ProxyOk=The J2534 proxy is registered as a separate device. Enable it later in Settings → J2534.
russian.ProxyFail=Прокси не зарегистрирован: запрос прав администратора отменён или файлы не найдены. Включите его позже в Настройки → J2534 (там же объясняется, чего не хватает).
english.ProxyFail=The proxy was not registered: the administrator prompt was cancelled or files are missing. Enable it later in Settings → J2534.

[Tasks]
Name: "desktopicon"; Description: "{cm:DesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "startmenuicon"; Description: "{cm:StartMenuIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
; Регистрация J2534-прокси требует HKLM, поэтому идёт отдельным elevated-шагом
; (см. RegisterProxy). Отмена UAC не валит установку — прокси можно включить в
; настройках, движок к тому моменту уже работает с правами администратора.
Name: "j2534proxy"; Description: "{cm:ProxyTask}"; GroupDescription: "{cm:ProxyGroup}"; Flags: checkedonce

[Files]
Source: "..\build\installer\payload\FTDI_USB_Logger\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\build\installer\payload\README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
; На обычных профилях ярлык создаёт сам Inno. Если {autodesktop} не раскрывается
; (OneDrive-редирект), запись пропускается с предупреждением, а ярлык создаст
; лаунчер при первом запуске (Launcher.cs, EnsureDesktopShortcut).
Name: "{autodesktop}\FTDI USB Logger"; Filename: "{app}\FTDI_USB_Logger.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: desktopicon
Name: "{autoprograms}\FTDI USB Logger"; Filename: "{app}\FTDI_USB_Logger.exe"; WorkingDir: "{app}"; IconFilename: "{app}\app.ico"; Tasks: startmenuicon
Name: "{autoprograms}\{cm:UninstallShortcut}"; Filename: "{uninstallexe}"; Tasks: startmenuicon

[Run]
Filename: "{app}\FTDI_USB_Logger.exe"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Обычное удаление идёт без прав администратора, поэтому запись HKLM сама не
; уйдёт; основной путь — CurUninstallStepChanged ниже (ShellExec с UAC). Этот
; шаг остаётся страховкой для случая, когда установщик уже повышен.
Filename: "{app}\ftdi-j2534proxy-setup.exe"; Parameters: "remove --app ""{app}"""; Flags: runhidden skipifdoesntexist; RunOnceId: "RemoveJ2534Proxy"

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

{ Регистрация J2534-прокси. Установка per-user, поэтому HKLM-запись создаёт
  отдельный helper с повышением прав: Inno в режиме lowest сам повыситься не
  может. Отмена UAC не считается ошибкой установки — прокси включается позже
  из настроек (движок к тому моменту уже запускается с правами администратора). }
procedure RegisterProxy();
var
  Helper, Params: String;
  ResultCode: Integer;
begin
  Helper := ExpandConstant('{app}\ftdi-j2534proxy-setup.exe');
  if not FileExists(Helper) then
  begin
    Log('j2534proxy: нет ' + Helper + ' — регистрация пропущена');
    Exit;
  end;
  Params := 'install --app "' + ExpandConstant('{app}') + '"';
  if not ShellExec('runas', Helper, Params, ExpandConstant('{app}'), SW_HIDE,
                   ewWaitUntilTerminated, ResultCode) then
  begin
    Log('j2534proxy: ShellExec(runas) не запустился');
    if not WizardSilent then
      MsgBox(CustomMessage('ProxyFail'), mbInformation, MB_OK);
    Exit;
  end;
  if ResultCode = 0 then
  begin
    Log('j2534proxy: зарегистрирован');
    if not WizardSilent then
      MsgBox(CustomMessage('ProxyOk'), mbInformation, MB_OK);
  end
  else
  begin
    Log('j2534proxy: helper вернул ' + IntToStr(ResultCode));
    if not WizardSilent then
      MsgBox(CustomMessage('ProxyFail'), mbInformation, MB_OK);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('j2534proxy') then
    RegisterProxy();
end;

{ Ярлык на рабочем столе мог создать лаунчер (если Inno не смог) — убираем его
  при удалении. Путь к рабочему столу берём из реестра: shell-константы на
  OneDrive-профилях в установщике не раскрываются. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Desk, Link, Pwsh, Cmd, Helper, Params: String;
  ResultCode: Integer;
begin
  { Перед удалением закрываем лаунчер и движок: иначе Inno ждёт освобождения exe. }
  if CurUninstallStep = usUninstall then
  begin
    Exec('taskkill.exe', '/F /IM FTDI_USB_Logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('taskkill.exe', '/F /IM ftdi-logger.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    { Запись J2534-прокси лежит в HKLM, а удаление идёт без прав: снимаем её
      отдельным elevated-вызовом, пока helper ещё существует на диске. }
    Helper := ExpandConstant('{app}\ftdi-j2534proxy-setup.exe');
    if FileExists(Helper) then
    begin
      Params := 'remove --app "' + ExpandConstant('{app}') + '"';
      if ShellExec('runas', Helper, Params, ExpandConstant('{app}'), SW_HIDE,
                   ewWaitUntilTerminated, ResultCode) then
        Log('j2534proxy: remove вернул ' + IntToStr(ResultCode))
      else
        Log('j2534proxy: remove не запустился (UAC отменён) — запись осталась');
    end;
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

