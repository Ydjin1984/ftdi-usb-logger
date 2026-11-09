'use strict';
// Универсальный Frida-агент FTDI/USB Logger: FTDI D2XX + VCP/COM + файлы (всё из
// ftdi_capture.js, формат старых строк НЕ изменён) ПЛЮС универсальный транспорт:
//   * J2534 PassThru (Scanmatik, CHIPSOFT, Tactrix, VXDIAG, FC200, UCDS, Bosch MDI, …)
//     — динамический module observer по шаблонам + хуки PassThru*; строки `J2534 …`
//   * WinUSB (winusb.dll: ReadPipe/WritePipe/ControlTransfer) — строки `WINUSB …`
//   * HID (hid.dll + ReadFile/WriteFile по путям \\?\hid#…, DeviceIoControl) — строки `HID …`
//   * libusb-1.0 (bulk/interrupt/control_transfer) — строки `LIBUSB …`
//   * USB-пути \\?\hid#/usb#/winusb# (CreateFile/CloseHandle) — строки `USB open/close …`
// Формат новых строк — docs/02-architecture.md §11.3 (его разбирает engine/src/decode.rs).
// Каждый хук обёрнут в try/catch и не должен ронять целевую программу.
// Messages go through send() (console.log is NOT bridged to the host in frida-python 17).

const T0 = Date.now();
const MAXDUMP = 16384;
function ts() { return '+' + ((Date.now() - T0) / 1000).toFixed(3) + 's'; }
function log(msg) { send('[' + ts() + '] ' + msg); }

function hexDump(ptr, len) {
  try {
    if (!ptr || len <= 0) return '';
    const b = new Uint8Array(ptr.readByteArray(len));
    let s = '';
    for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16) + ' ';
    return s.trim();
  } catch (e) { return '<read-error ' + e + '>'; }
}

function safeStr(ptr) {
  try { return ptr.readUtf8String(); } catch (e) { return '?'; }
}

function globalExport(name) {
  try {
    if (typeof Module.getGlobalExportByName === 'function') return Module.getGlobalExportByName(name);
  } catch (e) { return null; }
  if (typeof Module.findGlobalExportByName === 'function') {
    const a = Module.findGlobalExportByName(name);
    if (a) return a;
  }
  if (typeof Module.findExportByName === 'function') {
    const a = Module.findExportByName(null, name);
    if (a) return a;
  }
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    try {
      const ex = mods[i].enumerateExports();
      for (let j = 0; j < ex.length; j++) {
        if (ex[j].name === name && ex[j].type === 'function') return ex[j].address;
      }
    } catch (e) {}
  }
  return null;
}

// ---------------- module load log ----------------
(function watchModules() {
  Process.enumerateModules().forEach(function (m) {
    if (/ftd2xx|ftdib|ftser|hook|quickflash|clrjit|FTD2XX_NET/i.test(m.name)) {
      log('MODULE(now) ' + m.name + '  ' + (m.path || '') + ' base=' + m.base);
    }
  });
  if (typeof Process.attachModuleObserver === 'function') {
    Process.attachModuleObserver({
      onAdded(mod) {
        if (/ftd2xx|ftdibus|ftdiport|ftser|hook|quickflash|\.net|clrjit/i.test(mod.name)) {
          log('MODULE + ' + mod.name + '  ' + (mod.path || '') + ' base=' + mod.base);
        }
      }
    });
  }
})();

// ---------------- D2XX (ftd2xx.dll) ----------------
const WANTED = ['FT_Open', 'FT_OpenEx', 'FT_Close', 'FT_Read', 'FT_Write', 'FT_SetBaudRate',
  'FT_SetDataCharacteristics', 'FT_SetFlowControl', 'FT_SetDtr', 'FT_ClrDtr', 'FT_SetRts', 'FT_ClrRts',
  'FT_SetLatencyTimer', 'FT_SetTimeouts', 'FT_SetBitMode', 'FT_Purge', 'FT_ResetDevice',
  'FT_GetQueueStatus', 'FT_SetChars', 'FT_SetDeadmanTimeout', 'FT_CyclePort', 'FT_ResetPort',
  'FT_CreateDeviceInfoList', 'FT_GetDeviceInfoDetail', 'FT_ListDevices', 'FT_GetDeviceInfoList',
  'FT_GetDeviceInfo', 'FT_EE_Read', 'FT_EE_UARead', 'FT_EE_UASize', 'FT_EE_Program',
  'FT_GetDriverVersion', 'FT_GetLibraryVersion', 'FT_GetVIDPID', 'FT_SetVIDPID',
  'FT_GetComPortNumber', 'FT_SetUSBParameters', 'FT_SetEventNotification'];

const hooked = {};
const listeners = [];      // наши InvocationListener-ы: пауза снимает только их (detachAll убивает recv)
let ftMod = null;          // модуль ftd2xx: нужен для повторной установки после паузы
let PAUSED = false;        // пауза хуков (логер может снять их на время критичной операции)

function attachHook(target, cbs) {
  const l = Interceptor.attach(target, cbs);
  listeners.push(l);
  return l;
}

function pauseHooks() {
  if (PAUSED) return;
  PAUSED = true;
  let n = 0;
  for (let i = 0; i < listeners.length; i++) {
    try { listeners[i].detach(); n++; } catch (e) {}
  }
  listeners.length = 0;
  vcpOn = false;
  log('hookctl: ПАУЗА — снято хуков ' + n + ' (байтовый поток и файлы не пишутся); resume — вернуть');
}

function resumeHooks() {
  if (!PAUSED) return;
  PAUSED = false;
  for (const k in hooked) delete hooked[k];
  installVcpHooks();
  const m = ftMod || Process.findModuleByName('ftd2xx.dll');
  if (m) hookFtModule(m);
  resumeUniversalHooks();
  ovlHooked = false;
  installOverlappedHooks();
  log('hookctl: возобновление — хуки поставлены заново');
}

function installFtHook(name, addr) {
  if (name === 'FT_Write') {
    attachHook(addr, {
      onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pwritten = args[3]; },
      onLeave(ret) {
        let n = 0; try { n = this.pwritten.readU32(); } catch (e) {}
        log('TX ftd2xx FT_Write rc=' + ret.toInt32() + ' len=' + this.len + ' n=' + n + ' : ' + hexDump(this.buf, Math.min(this.len, MAXDUMP)));
      }
    });
  } else if (name === 'FT_Read') {
    attachHook(addr, {
      onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pgot = args[3]; },
      onLeave(ret) {
        let n = 0; try { n = this.pgot.readU32(); } catch (e) {}
        if (n > 0) log('RX ftd2xx FT_Read rc=' + ret.toInt32() + ' want=' + this.len + ' n=' + n + ' : ' + hexDump(this.buf, Math.min(n, MAXDUMP)));
      }
    });
  } else if (name === 'FT_Open' || name === 'FT_OpenEx') {
    attachHook(addr, {
      onEnter(args) {
        this.isEx = (name === 'FT_OpenEx');
        this.idx = this.isEx ? 0 : args[0].toInt32();
        this.flags = this.isEx ? args[1].toInt32() : 0;
        this.name = this.isEx ? safeStr(args[0]) : '';
        this.ph = args[this.isEx ? 2 : 1];
      },
      onLeave(ret) {
        let hv = '?'; try { hv = this.ph.readPointer().toString(); } catch (e) {}
        log(name + (this.isEx ? "('" + this.name + "' flags=" + this.flags + ')' : '(idx=' + this.idx + ')') + ' rc=' + ret.toInt32() + ' handle=' + hv);
      }
    });
  } else if (name === 'FT_CreateDeviceInfoList') {
    attachHook(addr, {
      onEnter(args) { this.pn = args[0]; },
      onLeave(ret) { let n = '?'; try { n = this.pn.readU32(); } catch (e) {} log('FT_CreateDeviceInfoList rc=' + ret.toInt32() + ' devices=' + n); }
    });
  } else if (name === 'FT_GetDeviceInfoDetail') {
    attachHook(addr, {
      onEnter(args) { this.idx = args[0].toInt32(); this.flags = args[1]; this.type = args[2]; this.serial = args[5]; this.desc = args[6]; },
      onLeave(ret) {
        let fl = '?', ty = '?';
        try { fl = this.flags.readU32(); } catch (e) {}
        try { ty = this.type.readU32(); } catch (e) {}
        log('FT_GetDeviceInfoDetail idx=' + this.idx + ' rc=' + ret.toInt32() + ' flags=' + fl + ' type=' + ty + ' serial="' + safeStr(this.serial) + '" desc="' + safeStr(this.desc) + '"');
      }
    });
  } else if (name === 'FT_ListDevices') {
    attachHook(addr, {
      onLeave(ret) { log('FT_ListDevices rc=' + ret.toInt32()); }
    });
  } else if (name === 'FT_EE_UARead') {
    attachHook(addr, {
      onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pgot = args[3]; },
      onLeave(ret) {
        let n = 0; try { n = this.pgot.readU32(); } catch (e) {}
        log('FT_EE_UARead rc=' + ret.toInt32() + ' want=' + this.len + ' got=' + n + ' : ' + hexDump(this.buf, Math.min(n, 128)));
      }
    });
  } else if (name === 'FT_GetComPortNumber') {
    attachHook(addr, {
      onEnter(args) { this.pn = args[1]; },
      onLeave(ret) { let n = '?'; try { n = this.pn.readInt32(); } catch (e) {} log('FT_GetComPortNumber rc=' + ret.toInt32() + ' com=' + n); }
    });
  } else if (name === 'FT_SetBaudRate') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.b = args[1].toInt32(); }, onLeave(ret) { log('FT_SetBaudRate(handle=' + this.h + ', ' + this.b + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_SetLatencyTimer') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.ms = args[1].toInt32(); }, onLeave(ret) { log('FT_SetLatencyTimer(handle=' + this.h + ', ' + this.ms + 'ms) rc=' + ret.toInt32()); } });
  } else if (name === 'FT_SetTimeouts') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.r = args[1].toInt32(); this.w = args[2].toInt32(); }, onLeave(ret) { log('FT_SetTimeouts(handle=' + this.h + ', rd=' + this.r + ' wr=' + this.w + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_Purge') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.mask = args[1].toInt32(); }, onLeave(ret) { log('FT_Purge(handle=' + this.h + ', mask=' + this.mask + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_SetBitMode') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.mask = args[1].toInt32(); this.mode = args[2].toInt32(); }, onLeave(ret) { log('FT_SetBitMode(handle=' + this.h + ', mask=' + this.mask + ' mode=' + this.mode + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_SetDataCharacteristics') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.wl = args[1].toInt32(); this.sb = args[2].toInt32(); this.p = args[3].toInt32(); }, onLeave(ret) { log('FT_SetDataCharacteristics(handle=' + this.h + ', wl=' + this.wl + ' sb=' + this.sb + ' parity=' + this.p + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_SetFlowControl') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.f = args[1].toInt32(); }, onLeave(ret) { log('FT_SetFlowControl(handle=' + this.h + ', flags=' + this.f + ') rc=' + ret.toInt32()); } });
  } else if (name === 'FT_GetQueueStatus') {
    attachHook(addr, { onEnter(args) { this.h = args[0]; this.pq = args[1]; }, onLeave(ret) { let q = '?'; try { q = this.pq.readU32(); } catch (e) {} log('FT_GetQueueStatus(handle=' + this.h + ') q=' + q + ' rc=' + ret.toInt32()); } });
  } else if (name === 'FT_GetDeviceInfo') {
    attachHook(addr, {
      onEnter(args) { this.h = args[0]; this.serial = args[3]; this.desc = args[4]; },
      onLeave(ret) {
        let fl = 0, ty = 0; try { ty = args; } catch (e) {}
        log('FT_GetDeviceInfo(handle=' + this.h + ') rc=' + ret.toInt32() + ' serial="' + safeStr(this.serial) + '" desc="' + safeStr(this.desc) + '"');
      }
    });
  } else if (name === 'FT_Close' || name === 'FT_ResetDevice' || name === 'FT_ResetPort' || name === 'FT_CyclePort') {
    attachHook(addr, {
      onEnter(args) { this.h = args[0]; },
      onLeave(ret) { log(name + '(handle=' + this.h + ') rc=' + ret.toInt32()); }
    });
  } else {
    attachHook(addr, {
      onEnter(args) { this.h = args[0]; },
      onLeave(ret) { log(name + '(handle=' + this.h + ') rc=' + ret.toInt32()); }
    });
  }
}

function hookFtModule(mod) {
  ftMod = mod;
  if (PAUSED) { log('hookctl: ftd2xx загружен, но хуки на паузе — пропускаю'); return; }
  let n = 0;
  try {
    const ex = mod.enumerateExports();
    for (let i = 0; i < ex.length; i++) {
      const e = ex[i];
      if (e.type !== 'function') continue;
      if (WANTED.indexOf(e.name) < 0) continue;
      if (hooked[e.name]) continue;
      hooked[e.name] = true;
      try { installFtHook(e.name, e.address); n++; } catch (err) { log('hook fail ' + e.name + ': ' + err); }
    }
  } catch (err) { log('enumerateExports fail: ' + err); }
  log('ftd2xx.dll hooks installed (' + n + ') at ' + mod.base + ' ' + (mod.path || ''));
}

(function initFt() {
  let m = null;
  try { m = Process.findModuleByName('ftd2xx.dll'); } catch (e) {}
  if (m) { hookFtModule(m); return; }
  if (typeof Process.attachModuleObserver === 'function') {
    log('ftd2xx.dll not loaded yet — module observer armed');
    Process.attachModuleObserver({
      onAdded(mod) {
        if (/^ftd2xx\.dll$/i.test(mod.name)) hookFtModule(mod);
      }
    });
  } else {
    log('ftd2xx.dll not loaded — polling');
    const iv = setInterval(function () {
      const mm = Process.findModuleByName('ftd2xx.dll');
      if (mm) { clearInterval(iv); hookFtModule(mm); }
    }, 400);
  }
})();

// ---------------- VCP fallback (COM port via kernel32) + файловые операции ----------------
// Legacy-клиенты (EDIABAS/WinKFP — старый C, x86) могут открывать порт через CreateFileA
// и работать overlapped-I/O: тогда счётчик байт может быть 0, а данные — в буфере позже.
// Поэтому: ловим и CreateFileA, и помечаем overlapped посылки (ovl=1) вместо потери.
const comHandles = {};
const fileHandles = {};
// Quickflash: .bin/.csv/.cal/.hex. WinKFP/NFS: .0pa/.0da/.0ka — программы и датен-файлы,
// .ipo — скомпилированные PABD, .prg — SGBD (C:\EDIABAS\ECU), .dat/.his/.da2/.eng/.bsu —
// таблицы, история и инфо базы (что именно считано/приготовлено к прошивке).
const FILE_RE = /\.(bin|csv|cal|hex|0pa|0da|0ka|dat|his|prg|ipo|da2|eng|bsu)$/i;
let vcpOn = false;   // kernel32-хуки поставлены (после паузы ставим заново)
function installVcpHooks() {
  if (vcpOn) return;
  vcpOn = true;
  const pCreate = globalExport('CreateFileW');
  const pCreateA = globalExport('CreateFileA');
  const pRead = globalExport('ReadFile');
  const pWrite = globalExport('WriteFile');
  const pClose = globalExport('CloseHandle');

  function notePath(api, path, access, ret) {
    if (!path) return;
    if (/com\d+/i.test(path)) {
      const key = ret.toString();
      comHandles[key] = path;
      log('VCP ' + api + '(' + path + ') handle=' + key + ' invalid=' + (ret.toString() === '-1'));
      return;
    }
    if (FILE_RE.test(path) && ret.toString() !== '-1') {
      const key = ret.toString();
      fileHandles[key] = { path: path, access: access, bytes: 0, writes: 0 };
      log('FILE open ' + path + ' access=0x' + access.toString(16) + ' handle=' + key);
    }
  }

  if (pCreate) {
    attachHook(pCreate, {
      onEnter(args) { try { this.path = args[0].readUtf16String(); } catch (e) { this.path = null; } this.access = (function () { try { return args[1].toInt32(); } catch (e) { return 0; } })(); },
      onLeave(ret) { notePath('CreateFileW', this.path, this.access, ret); }
    });
  }
  if (pCreateA) {
    attachHook(pCreateA, {
      onEnter(args) { try { this.path = args[0].readCString(); } catch (e) { this.path = null; } this.access = (function () { try { return args[1].toInt32(); } catch (e) { return 0; } })(); },
      onLeave(ret) { notePath('CreateFileA', this.path, this.access, ret); }
    });
  }
  if (pWrite) {
    attachHook(pWrite, {
      onEnter(args) {
        this.hkey = args[0].toString();
        this.ovl = !args[4].isNull();
        try { classifyExistingHandle(this.hkey); } catch (e) {}
        this.plen = args[3];
        try { ovlRemember(args, false); } catch (e) {}
        try { this.ovlKey = this.ovl ? ovlKeyOf(this.hkey, args[4]) : null; } catch (e) { this.ovlKey = null; }
        if (comHandles[this.hkey]) { this.com = true; this.buf = args[1]; this.len = args[2].toInt32(); this.pw = args[3]; commStateOnce(this.hkey); }
        else if (fileHandles[this.hkey]) { this.fent = fileHandles[this.hkey]; this.len = args[2].toInt32(); this.pw = args[3]; }
        else { try { if (typeof usbHandles !== 'undefined' && usbHandles[this.hkey]) { this.usbEnt = usbHandles[this.hkey]; this.buf = args[1]; this.len = args[2].toInt32(); this.pw = args[3]; } } catch (e) {} }
      },
      onLeave(ret) {
        try { ovlOnIoLeave(this, ret); } catch (e) {}
        if (this.usbEnt) {
          let n = 0; try { n = this.pw.readU32(); } catch (e) {}
          const len = n > 0 ? n : this.len;
          this.usbEnt.bytes += len;
          this.usbEnt.writes += 1;
          if (len > 0) { try { emitUsbTransfer('TX', this.usbEnt.kind, this.buf, len, true); } catch (e) {} }
          return;
        }

        if (this.fent) {
          let n = 0; try { n = this.pw.readU32(); } catch (e) {}
          this.fent.bytes += n; this.fent.writes += 1;
          log('FILE write ' + this.fent.path + ' n=' + n + ' total=' + this.fent.bytes);
          return;
        }
        if (!this.com) return;
        if (this.ovl) return;   // TX overlapped уже записан на входе (полные байты)
        let n = 0; try { n = this.pw.readU32(); } catch (e) {}
        if (this.ovl && ret.toInt32() === 0) {
          // Pending TX: НЕ пишем строку (tx не удваиваем); полные байты - из
          // GetOverlappedResult/Ex или из sweep-fallback по OVERLAPPED.Internal.
          return;
        }
        log('VCP TX WriteFile(' + comHandles[this.hkey] + ') rc=' + ret.toInt32() + ' n=' + n + ' ovl=' + (this.ovl ? 1 : 0) + ' : ' + hexDump(this.buf, Math.min(this.len, MAXDUMP)));
      }
    });
  }
  if (pRead) {
    attachHook(pRead, {
      onEnter(args) {
        this.hkey = args[0].toString();
        this.ovl = !args[4].isNull();
        try { classifyExistingHandle(this.hkey); } catch (e) {}
        this.plen = args[3];
        try { ovlRemember(args, true); } catch (e) {}
        try { this.ovlKey = this.ovl ? ovlKeyOf(this.hkey, args[4]) : null; } catch (e) { this.ovlKey = null; }
        if (comHandles[this.hkey]) { this.com = true; this.buf = args[1]; this.len = args[2].toInt32(); this.pr = args[3]; commStateOnce(this.hkey); }
        else { try { if (typeof usbHandles !== 'undefined' && usbHandles[this.hkey]) { this.usbEnt = usbHandles[this.hkey]; this.buf = args[1]; this.len = args[2].toInt32(); this.pr = args[3]; } } catch (e) {} }
      },
      onLeave(ret) {
        if (this.usbEnt) {
          let n = 0; try { n = this.pr.readU32(); } catch (e) {}
          this.usbEnt.bytes += n;
          if (n > 0) { try { emitUsbTransfer('RX', this.usbEnt.kind, this.buf, n, true); } catch (e) {} }
          return;
        }
        let lerrEarly = 0;
        try { lerrEarly = (this.ovl && this.com) ? ovlLastError() : 0; } catch (e) { lerrEarly = 0; }
        try { ovlOnIoLeave(this, ret); } catch (e) {}
        if (!this.com) return;
        let n = 0; try { n = this.pr.readU32(); } catch (e) {}
        // overlapped-I/O: при pending (n=0) буфер ещё не заполнен — short-строка без hex,
        // реальные байты выдаст GetOverlappedResult(Ex).
        if (this.ovl && ret.toInt32() === 0) {
          // Pending: реальные байты придут через GetOverlappedResult(Ex); если не придут,
          // ovlSweep выдаст строку ovl=pending. Не плодим шум на каждый ReadFile.
          return;
        }
        const ln = n > 0 ? n : 0;
        if (ln > 0) log('VCP RX ReadFile(' + comHandles[this.hkey] + ') rc=' + ret.toInt32() + ' n=' + n + ' ovl=' + (this.ovl ? 1 : 0) + ' : ' + hexDump(this.buf, Math.min(ln, MAXDUMP)));
      }
    });
  }
  if (pClose) {
    attachHook(pClose, {
      onEnter(args) {
        const key = args[0].toString();
        if (comHandles[key]) { log('VCP CloseHandle(' + comHandles[key] + ')'); delete comHandles[key]; }
        if (fileHandles[key]) {
          const f = fileHandles[key];
          log('FILE close ' + f.path + ' bytes=' + f.bytes + ' writes=' + f.writes);
          delete fileHandles[key];
        }
      }
    });
  }
  installCommSettingsHooks();
}
installVcpHooks();

// ── Скорость и тайминги последовательного порта (SetCommState/SetCommTimeouts/…) ──
// .NET SerialPort и Delphi-клиенты меняют baud/таймауты через kernel32 и IOCTL-ы.
// Без этих хуков в лог попадали только байты, но не факт смены скорости/таймингов.
var commHooked = false;
const COMM_PARITY = { 0: 'NONE', 1: 'ODD', 2: 'EVEN', 3: 'MARK', 4: 'SPACE' };
const COMM_STOP = { 0: '1', 1: '1.5', 2: '2' };
const COMM_ESC = { 1: 'SETXOFF', 2: 'SETXON', 3: 'SETRTS', 4: 'CLRRTS', 5: 'SETDTR', 6: 'CLRDTR',
  7: 'RESETDEV', 8: 'SETBREAK', 9: 'CLRBREAK' };

const commStateSeen = {};
// Для порта, открытого ДО attach, SetCommState уже не сработает — спрашиваем
// текущие DCB/таймауты через GetCommState/GetCommTimeouts при первом I/O.
function commStateOnce(hkey) {
  if (commStateSeen[hkey]) return;
  commStateSeen[hkey] = true;
  try {
    const port = comHandles[hkey] || 'COM?';
    const gsAddr = globalExport('GetCommState');
    const gtAddr = globalExport('GetCommTimeouts');
    if (!gsAddr || !gtAddr) return;
    const hp = ptr(hkey);
    const dcb = Memory.alloc(64);
    const tmo = Memory.alloc(20);
    const gs = new NativeFunction(gsAddr, 'int', ['pointer', 'pointer']);
    const gt = new NativeFunction(gtAddr, 'int', ['pointer', 'pointer']);
    if (gs(hp, dcb) !== 0) {
      const flags = dcb.add(8).readU32();
      log('COM state(' + port + ') baud=' + dcb.add(4).readU32() +
        ' data=' + dcb.add(18).readU8() +
        ' parity=' + (COMM_PARITY[dcb.add(19).readU8()] || dcb.add(19).readU8()) +
        ' stop=' + (COMM_STOP[dcb.add(20).readU8()] || dcb.add(20).readU8()) +
        ' flow=' + commFlowName(flags) + ' (текущие на момент attach)');
    }
    if (gt(hp, tmo) !== 0) {
      log('COM timeouts(' + port + ') read_interval=' + tmo.add(0).readU32() +
        ' read_total_mul=' + tmo.add(4).readU32() + ' read_total_const=' + tmo.add(8).readU32() +
        ' write_total_mul=' + tmo.add(12).readU32() + ' write_total_const=' + tmo.add(16).readU32() +
        ' (текущие на момент attach)');
    }
  } catch (e) { try { log('commState error: ' + e); } catch (e2) {} }
}

function commPortOf(hkey) {
  try {
    if (comHandles[hkey]) return comHandles[hkey];
    if (classifyExistingHandle(hkey) === 'com') return comHandles[hkey] || 'COM?';
  } catch (e) {}
  return null;
}

function commFlowName(flags) {
  const parts = [];
  if (flags & 0x0004) parts.push('CTS');
  if (flags & 0x0008) parts.push('DSR');
  const dtr = (flags >> 4) & 0x3;
  const rts = (flags >> 12) & 0x3;
  if (dtr === 1) parts.push('DTR');
  else if (dtr === 2) parts.push('DTR_HS');
  if (rts === 1) parts.push('RTS');
  else if (rts === 2) parts.push('RTS_HS');
  else if (rts === 3) parts.push('RTS_TOGGLE');
  if (flags & 0x0100) parts.push('XON');
  if (flags & 0x0200) parts.push('XOFF');
  return parts.length ? parts.join('+') : 'NONE';
}

function installCommSettingsHooks() {
  if (commHooked) return;
  commHooked = true;
  const pSetState = globalExport('SetCommState');
  const pSetTimeouts = globalExport('SetCommTimeouts');
  const pSetup = globalExport('SetupComm');
  const pMask = globalExport('SetCommMask');
  const pEscape = globalExport('EscapeCommFunction');

  if (pSetState) attachHook(pSetState, {
    onEnter(args) { this.hkey = args[0].toString(); this.dcb = args[1]; },
    onLeave(ret) {
      try {
        const port = commPortOf(this.hkey);
        if (!port || !this.dcb || this.dcb.isNull()) return;
        const baud = this.dcb.add(4).readU32();
        const flags = this.dcb.add(8).readU32();
        const data = this.dcb.add(18).readU8();
        const parity = this.dcb.add(19).readU8();
        const stop = this.dcb.add(20).readU8();
        log('COM SetCommState(' + port + ') baud=' + baud + ' data=' + data +
          ' parity=' + (COMM_PARITY[parity] || parity) + ' stop=' + (COMM_STOP[stop] || stop) +
          ' flow=' + commFlowName(flags) + ' rc=' + ret.toInt32());
      } catch (e) {}
    }
  });

  if (pSetTimeouts) attachHook(pSetTimeouts, {
    onEnter(args) { this.hkey = args[0].toString(); this.t = args[1]; },
    onLeave(ret) {
      try {
        const port = commPortOf(this.hkey);
        if (!port || !this.t || this.t.isNull()) return;
        const p = this.t;
        log('COM SetCommTimeouts(' + port + ') read_interval=' + p.add(0).readU32() +
          ' read_total_mul=' + p.add(4).readU32() + ' read_total_const=' + p.add(8).readU32() +
          ' write_total_mul=' + p.add(12).readU32() + ' write_total_const=' + p.add(16).readU32() +
          ' rc=' + ret.toInt32());
      } catch (e) {}
    }
  });

  if (pSetup) attachHook(pSetup, {
    onEnter(args) { this.hkey = args[0].toString(); this.inb = args[1].toInt32(); this.outb = args[2].toInt32(); },
    onLeave(ret) {
      try {
        const port = commPortOf(this.hkey);
        if (!port) return;
        log('COM SetupComm(' + port + ') in=' + this.inb + ' out=' + this.outb + ' rc=' + ret.toInt32());
      } catch (e) {}
    }
  });

  if (pMask) attachHook(pMask, {
    onEnter(args) { this.hkey = args[0].toString(); this.mask = args[1].toInt32(); },
    onLeave(ret) {
      try {
        const port = commPortOf(this.hkey);
        if (!port) return;
        log('COM SetCommMask(' + port + ') mask=' + hex4(this.mask) + ' rc=' + ret.toInt32());
      } catch (e) {}
    }
  });

  if (pEscape) attachHook(pEscape, {
    onEnter(args) { this.hkey = args[0].toString(); this.func = args[1].toInt32(); },
    onLeave(ret) {
      try {
        const port = commPortOf(this.hkey);
        if (!port) return;
        log('COM EscapeCommFunction(' + port + ') func=' + (COMM_ESC[this.func] || this.func) +
          ' rc=' + ret.toInt32());
      } catch (e) {}
    }
  });
}


// ==================== ЛЕНИВАЯ КЛАССИФИКАЦИЯ УЖЕ ОТКРЫТЫХ ХЕНДЛОВ ============
// .NET-приложения (MS4x, SerialPort) открывают COM/HID/USB ДО attach: хука CreateFileW
// в этом случае не было, и старые ReadFile/WriteFile проверяют comHandles[handle] зря.
// Здесь по первому обращению к неизвестному хендлу мы спрашиваем у системы путь:
//   GetFinalPathNameByHandleW -> NtQueryObject(ObjectNameInformation=1) -> QueryDosDevice.
// Результат раскладывается в comHandles/fileHandles/usbHandles, чтобы работали старые хуки.
const clsCache = {};           // handle -> 'com'|'usb'|'file'|null
let clsComMap = null;          // "\device\serial0" -> "COM1"
let clsFailLogged = false;

function clsNormPath(p) {
  if (!p) return '';
  let s = String(p);
  s = s.replace(/^\\\\\?\\/, '');   // \\?\  -> остаётся путь/CON-имя
  s = s.replace(/^\\\?\?\\/, '');   // \??\  -> то же
  return s;
}

function clsBuildComMap() {
  if (clsComMap) return clsComMap;
  clsComMap = {};
  try {
    const fn = globalExport('QueryDosDeviceW');
    if (!fn) return clsComMap;
    const call = new NativeFunction(fn, 'uint32', ['pointer', 'pointer', 'uint32']);
    for (let i = 1; i <= 64; i++) {
      try {
        const name = Memory.allocUtf16String('COM' + i);
        const buf = Memory.alloc(1040);
        const n = call(name, buf, 520);
        if (n > 0) {
          const target = buf.readUtf16String();
          if (target) clsComMap[target.toLowerCase()] = 'COM' + i;
        }
      } catch (e) {}
    }
  } catch (e) {}
  return clsComMap;
}

function clsResolvePath(hkey) {
  const h = parseInt(hkey, 16);
  if (!h || isNaN(h)) return null;
  // 1) документированный путь (работает для файлов; для COM часто 0)
  try {
    const fn = globalExport('GetFinalPathNameByHandleW');
    if (fn) {
      const call = new NativeFunction(fn, 'uint32', ['uint32', 'pointer', 'uint32', 'uint32']);
      const buf = Memory.alloc(1040);
      const n = call(h, buf, 520, 0);
      if (n > 0 && n < 520) return buf.readUtf16String();
    }
  } catch (e) {}
  // 2) NtQueryObject(ObjectNameInformation=1): для устройств даёт \Device\Serial0 и т.п.
  try {
    const fn = globalExport('NtQueryObject');
    if (fn) {
      const call = new NativeFunction(fn, 'int', ['uint32', 'uint32', 'pointer', 'uint32', 'pointer']);
      const buf = Memory.alloc(0x2000);
      const ret = call(h, 1, buf, 0x2000, ptr(0));
      if (ret === 0) {
        const len = buf.readU16();
        const off = Process.pointerSize === 8 ? 8 : 4;
        const strPtr = buf.add(off).readPointer();
        if (len > 0 && !strPtr.isNull()) return strPtr.readUtf16String(len / 2);
      }
    }
  } catch (e) {}
  return null;
}

function classifyExistingHandle(hkey) {
  try {
    if (!hkey) return null;
    if (Object.prototype.hasOwnProperty.call(clsCache, hkey)) return clsCache[hkey];
    // уже классифицирован обычными хуками?
    try { if (comHandles[hkey]) { clsCache[hkey] = 'com'; return 'com'; } } catch (e) {}
    try { if (fileHandles[hkey]) { clsCache[hkey] = 'file'; return 'file'; } } catch (e) {}
    try { if (typeof usbHandles !== 'undefined' && usbHandles[hkey]) { clsCache[hkey] = 'usb'; return 'usb'; } } catch (e) {}

    const path = clsResolvePath(hkey);
    const norm = clsNormPath(path);
    const mCom = /com\d+/i.exec(norm);
    if (mCom) {
      const port = mCom[0].toUpperCase();
      try { comHandles[hkey] = port; } catch (e) {}
      log('VCP attach-existing ' + port + ' handle=' + hkey);
      clsCache[hkey] = 'com';
      return 'com';
    }
    if (norm) {
      const dev = clsBuildComMap()[norm.toLowerCase()];
      if (dev) {
        try { comHandles[hkey] = dev; } catch (e) {}
        log('VCP attach-existing ' + dev + ' handle=' + hkey);
        clsCache[hkey] = 'com';
        return 'com';
      }
    }
    if (/hid#|usb#vid_|winusb#/i.test(norm)) {
      let kind = 'usb';
      if (/hid#/i.test(norm)) kind = 'hid';
      else if (/winusb#/i.test(norm)) kind = 'winusb';
      try { usbHandles[hkey] = { path: norm, kind: kind, bytes: 0, writes: 0 }; } catch (e) {}
      log('USB open path="' + norm.replace(/"/g, "'") + '" kind=' + kind + ' handle=' + hkey);
      clsCache[hkey] = 'usb';
      return 'usb';
    }
    if (typeof FILE_RE !== 'undefined' && norm && FILE_RE.test(norm)) {
      try { fileHandles[hkey] = { path: norm, access: 0, bytes: 0, writes: 0 }; } catch (e) {}
      log('FILE open ' + norm + ' access=0x0 handle=' + hkey);
      clsCache[hkey] = 'file';
      return 'file';
    }
    clsCache[hkey] = null;
    if (!clsFailLogged) {
      clsFailLogged = true;
      log('hook: handle resolve fail handle=' + hkey + ' path="' + norm + '"');
    }
    return null;
  } catch (e) {
    try { log('hook: classify error handle=' + hkey + ': ' + e); } catch (e2) {}
    return null;
  }
}

// ==================== OVERLAPPED I/O (System.IO.Ports / .NET SerialPort) ==========
// .NET SerialPort (MS4x Flasher и др.) работает overlapped-I/O: ReadFile/WriteFile
// возвращают n=0 / ERROR_IO_PENDING, реальные счётчики и данные приходят позже в
// GetOverlappedResult/GetOverlappedResultEx. Секция восстанавливает потерянные байты
// и пишет их СТАРЫМ форматом (VCP RX/TX, FILE write); pending-RX не дампит мусор.
let ovlHooked = false;
const ovlPending = {};        // "handle|ovlPtr" -> {handle, ovl, buf, len, plen, isRead, kind, t, pendingLogged}
const ovlPathCache = {};      // handle -> path|null
let ovlSelfCall = 0;          //>0 — мы сами вызвали GetOverlappedResult из хука Wait
let ovlWrap = null;           // NativeFunction(kernel32!GetOverlappedResult)
let ovlGetLastErrFn = null;   // NativeFunction(kernel32!GetLastError)
let ovlMissLogged = false;
let ovlSweepTimer = null;
const OVL_PENDING_TTL_MS = 2000;

function ovlU32(ptr) { try { return ptr.readU32(); } catch (e) { return 0; } }
function ovlLastError() {
  try {
    if (!ovlGetLastErrFn) {
      const fn = globalExport('GetLastError');
      if (fn) ovlGetLastErrFn = new NativeFunction(fn, 'uint32', []);
    }
    return ovlGetLastErrFn ? ovlGetLastErrFn() : 0;
  } catch (e) { return 0; }
}
function ovlErr(where, err) {
  try {
    if (typeof HOOK_ERRORS === 'undefined') { log('overlapped hook error: ' + where + ': ' + err); return; }
    if (HOOK_ERRORS < 20) { HOOK_ERRORS++; log('overlapped hook error: ' + where + ': ' + err); }
  } catch (e) {}
}
function ovlSafeEnter(fn) { return function (args) { try { fn.call(this, args); } catch (e) { ovlErr('enter', e); } }; }
function ovlSafeLeave(fn) { return function (retval) { try { fn.call(this, retval); } catch (e) { ovlErr('leave', e); } }; }

function ovlPath(hkey) {
  if (Object.prototype.hasOwnProperty.call(ovlPathCache, hkey)) return ovlPathCache[hkey];
  let path = null;
  try { if (comHandles[hkey]) path = String(comHandles[hkey]); } catch (e) {}
  try { if (!path && fileHandles[hkey]) path = String(fileHandles[hkey].path); } catch (e) {}
  if (!path) {
    try {
      const fn = globalExport('GetFinalPathNameByHandleW');
      if (fn) {
        const call = new NativeFunction(fn, 'uint32', ['uint32', 'pointer', 'uint32', 'uint32']);
        const buf = Memory.alloc(1040);
        const n = call(parseInt(hkey, 16), buf, 520, 0);
        if (n > 0 && n < 520) path = buf.readUtf16String();
      }
    } catch (e) { path = null; }
  }
  ovlPathCache[hkey] = path;
  return path;
}

function ovlLabel(hkey) {
  try { classifyExistingHandle(hkey); } catch (e) {}
  const path = ovlPath(hkey);
  if (path) {
    const m = /com\d+/i.exec(path);
    return m ? m[0] : path;
  }
  return 'handle=' + hkey;
}

function ovlEmit(e, n) {
  try {
    if (!(n > 0)) return;
    if (e.kind !== 'com' && !(e.kind === 'file' && !e.isRead)) return;  // pipe/USB и прочее не шумим
    if (!e.isRead && e.kind === 'com') return;   // TX уже отдан на входе WriteFile
    const hkey = e.handle;
    let fileEnt = null;
    try { fileEnt = fileHandles[hkey] || null; } catch (err) {}
    if (e.isRead) {
      if (fileEnt) return;
      log('VCP RX ReadFile(' + ovlLabel(hkey) + ') rc=0 n=' + n + ' ovl=1 : ' + hexDump(e.buf, Math.min(n, MAXDUMP)));
    } else if (fileEnt) {
      fileEnt.bytes += n;
      fileEnt.writes += 1;
      log('FILE write ' + fileEnt.path + ' n=' + n + ' total=' + fileEnt.bytes);
    } else {
      log('VCP TX WriteFile(' + ovlLabel(hkey) + ') rc=0 n=' + n + ' ovl=1 : ' + hexDump(e.buf, Math.min(n, MAXDUMP)));
    }
  } catch (err) { ovlErr('ovlEmit', err); }
}

function ovlKeyOf(hkey, ovl) { return hkey + '|' + ovl.toString(); }

// hEvent в OVERLAPPED/NativeOverlapped: x64 — смещение 24, x86 — 16.
function ovlEventOf(ovl) {
  try {
    if (!ovl || ovl.isNull()) return null;
    const off = Process.pointerSize === 8 ? 24 : 16;
    const ev = ovl.add(off).readPointer();
    return ev && !ev.isNull() ? ev : null;
  } catch (e) { return null; }
}


const OVL_STATUS_PENDING = 0x103;
function ovlInternal(e) {
  try {
    if (!e || !e.ovl || e.ovl.isNull()) return OVL_STATUS_PENDING;
    return Process.pointerSize === 8 ? e.ovl.readU64().toNumber() : e.ovl.readU32();
  } catch (err) { return OVL_STATUS_PENDING; }
}
function ovlInternalHigh(e) {
  try {
    if (!e || !e.ovl || e.ovl.isNull()) return 0;
    return Process.pointerSize === 8 ? e.ovl.add(8).readU64().toNumber() : e.ovl.add(4).readU32();
  } catch (err) { return 0; }
}
// Ядро пишет статус/счётчик в ИСХОДНЫЙ OVERLAPPED (тот, что передан в ReadFile/WriteFile),
// поэтому завершённые операции ищем по Internal/InternalHigh, а не по указателю из
// GetOverlappedResult (.NET передаёт туда другую копию структуры).
function ovlCompletedKeys(hkey) {
  const out = [];
  try {
    for (const k in ovlPending) {
      const e = ovlPending[k];
      if (!e || e.handle !== hkey) continue;
      if (ovlInternal(e) !== OVL_STATUS_PENDING) out.push(k);
    }
    out.sort(function (a, b) { return (ovlPending[a].t || 0) - (ovlPending[b].t || 0); });
  } catch (err) { ovlErr('ovlCompletedKeys', err); }
  return out;
}

let ovlEventDbg = 0;
// Ключ pending по точному указателю, иначе — по handle + hEvent (главный путь для .NET),
// и лишь в крайнем случае FIFO по handle.
function ovlFindKey(hkey, ovlPtr) {
  try {
    const exact = ovlKeyOf(hkey, ovlPtr);
    if (ovlPending[exact]) return exact;
    const ev = ovlEventOf(ovlPtr);
    if (ev) {
      for (const k in ovlPending) {
        const e = ovlPending[k];
        if (!e || e.handle !== hkey) continue;
        if (e.event && e.event.equals(ev)) {
          if (ovlEventDbg < 120) { ovlEventDbg++; log('ovl: match by hEvent ' + ev + ' key=' + k); }
          return k;
        }
      }
    }
    for (const k in ovlPending) {
      const e = ovlPending[k];
      if (e && e.handle === hkey) {
        if (ovlEventDbg < 120) { ovlEventDbg++; log('ovl: FIFO fallback handle=' + hkey + ' key=' + k + ' (hEvent не совпал)'); }
        return k;
      }
    }
  } catch (err) { ovlErr('ovlFindKey', err); }
  return null;
}

function ovlTakePending(key) {
  if (!key) return null;
  const exact = ovlPending[key];
  if (exact) { delete ovlPending[key]; return exact; }
  // Фолбэк: .NET/.SerialPort передаёт в GetOverlappedResult указатель на поле
  // NativeOverlapped, а не на тот же OVERLAPPED, что был в ReadFile/WriteFile.
  // Поэтому при точном промахе берём самую старую (FIFO) запись этого хендла:
  // драйвер завершает операции в порядке выдачи.
  try {
    const hkey = key.split('|')[0];
    const cands = Object.keys(ovlPending).filter(function (k) { return k.indexOf(hkey + '|') === 0; });
    if (cands.length > 0) {
      cands.sort(function (a, b) { return (ovlPending[a].t || 0) - (ovlPending[b].t || 0); });
      const e = ovlPending[cands[0]];
      delete ovlPending[cands[0]];
      return e;
    }
  } catch (err) { ovlErr('ovlTakePending fallback', err); }
  if (!ovlMissLogged) {
    ovlMissLogged = true;
    log('ovl: pending miss key=' + key);
  }
  return null;
}

function ovlRemember(args, isRead) {
  try {
    const ovl = args[4];
    if (!ovl || ovl.isNull()) return;
    const hkey = args[0].toString();
    const key = ovlKeyOf(hkey, ovl);
    // .NET переиспользует NativeOverlapped: перед перезаписью забираем завершённую
    // операцию из OVERLAPPED.Internal/InternalHigh (иначе результат потеряется).
    const old = ovlPending[key];
    if (old) {
      try {
        if (ovlInternal(old) !== OVL_STATUS_PENDING) {
          const nOld = ovlInternalHigh(old);
          delete ovlPending[key];
          if (nOld > 0) ovlEmit(old, nOld);
        } else {
          delete ovlPending[key];   // переиспользование до завершения — запись битая
        }
      } catch (err) { ovlErr('ovlRemember reuse', err); }
    }
    ovlPending[key] = {
      handle: hkey, ovl: ovl, buf: args[1], len: args[2].toInt32(),
      plen: args[3], isRead: isRead, kind: classifyExistingHandle(hkey),
      t: Date.now(), pendingLogged: false,
      event: ovlEventOf(ovl)
    };
    const ent = ovlPending[key];
    if (!isRead && ent.kind === 'com' && ent.len > 0) {
      try {
        log('VCP TX WriteFile(' + ovlLabel(hkey) + ') rc=0 n=' + ent.len + ' ovl=1 : ' + hexDump(ent.buf, Math.min(ent.len, MAXDUMP)));
        ent.txLogged = true;
      } catch (err) { ovlErr('tx-enter', err); }
    }
    const keys = Object.keys(ovlPending);
    if (keys.length > 4096) delete ovlPending[keys[0]];
  } catch (err) { ovlErr('ovlRemember', err); }
}

// onLeave ReadFile/WriteFile: BOOL/счётчик -> pending или завершение; байты — в GetOverlappedResult.
function ovlOnIoLeave(self, retval) {
  try {
    if (!self) return;
    let key = self.ovlKey;
    if (!key && self.hkey && self.ovl) key = ovlKeyOf(self.hkey, self.ovl);
    const e = key ? ovlPending[key] : null;
    if (!e) return;
    let completed = true;
    try { completed = !!retval && retval.toInt32() !== 0; } catch (err) { completed = true; }
    const n = ovlU32(self.plen);
    if (completed && n > 0) {
      delete ovlPending[key];
      let known = false;
      try { known = !!(comHandles[self.hkey] || fileHandles[self.hkey]); } catch (err) {}
      if (!known) ovlEmit(e, n);   // старые хуки для неизвестных хендлов молчат
    } else {
      e.t = Date.now();
    }
  } catch (err) { ovlErr('ovlOnIoLeave', err); }
}

function ovlOnGetResult(hkey, ovlPtr, pBytes) {
  try {
    // 1) точное совпадение указателя (классические клиенты, не .NET)
    const exact = ovlKeyOf(hkey, ovlPtr);
    if (ovlPending[exact]) {
      const e = ovlPending[exact];
      const nCore = ovlInternalHigh(e);
      const n = nCore > 0 ? nCore : ovlU32(pBytes);
      delete ovlPending[exact];
      if (n > 0) { ovlEmit(e, n); return true; }
      return false;
    }
    // 2) уникальный hEvent, если события разные
    const ev = ovlEventOf(ovlPtr);
    if (ev) {
      for (const k in ovlPending) {
        const e = ovlPending[k];
        if (!e || e.handle !== hkey) continue;
        if (e.event && e.event.equals(ev)) {
          const nCore = ovlInternalHigh(e);
          const n = nCore > 0 ? nCore : ovlU32(pBytes);
          delete ovlPending[k];
          if (n > 0) { ovlEmit(e, n); return true; }
          return false;
        }
      }
    }
    // 3) .NET передаёт копию NativeOverlapped с общим hEvent — не угадываем:
    //    завершённые операции заберёт ovlSweep() по OVERLAPPED.Internal/InternalHigh.
  } catch (err) { ovlErr('ovlOnGetResult', err); }
  return false;
}

// Fallback: GetOverlappedResult так и не пришёл — для RX пишем один раз короткую
// строку без hex (буфер уже нельзя считать валидным), для TX просто забываем.
function ovlSweep() {
  try {
    const now = Date.now();
    const keys = Object.keys(ovlPending);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const e = ovlPending[key];
      if (!e) continue;
      // 1) завершилось, но GetOverlappedResult не пришёл/не связался — забираем из OVERLAPPED
      if (ovlInternal(e) !== OVL_STATUS_PENDING) {
        const n = ovlInternalHigh(e);
        delete ovlPending[key];
        if (n > 0) ovlEmit(e, n);
        continue;
      }
      const age = now - e.t;
      if (!e.pendingLogged && age >= OVL_PENDING_TTL_MS) {
        e.pendingLogged = true;
        if (e.isRead) {
          if (e.kind === 'com') log('VCP RX ReadFile(' + ovlLabel(e.handle) + ') rc=0 n=0 ovl=pending');
        } else if (e.kind === 'com') {
          delete ovlPending[key];   // TX уже отдан на входе WriteFile
        } else if (e.kind === 'file') {
          let fe = null;
          try { fe = fileHandles[e.handle] || null; } catch (err) {}
          if (fe) { fe.bytes += e.len; fe.writes += 1; log('FILE write ' + fe.path + ' n=' + e.len + ' total=' + fe.bytes); }
          delete ovlPending[key];
        }
      }
      if (age > 30000) delete ovlPending[key];
    }
  } catch (err) { ovlErr('ovlSweep', err); }
}

function installOverlappedHooks() {
  if (PAUSED || ovlHooked) return;
  ovlHooked = true;

  const pRead = globalExport('ReadFile');
  const pWrite = globalExport('WriteFile');
  const pReadEx = globalExport('ReadFileEx');
  const pWriteEx = globalExport('WriteFileEx');
  const pGet = globalExport('GetOverlappedResult');
  const pGetEx = globalExport('GetOverlappedResultEx');
  const pWait = globalExport('WaitForSingleObject');

  if (pGet && !ovlWrap) {
    try { ovlWrap = new NativeFunction(pGet, 'int', ['uint32', 'pointer', 'pointer', 'int']); } catch (e) { ovlWrap = null; }
  }
  if (!ovlSweepTimer) {
    try { ovlSweepTimer = setInterval(ovlSweep, 250); } catch (e) { ovlSweepTimer = null; }
  }

  function attachReadWrite(addr, isRead) {
    if (!addr) return;
    attachHook(addr, {
      onEnter: ovlSafeEnter(function (args) {
        ovlRemember(args, isRead);
        this.hkey = args[0].toString();
        this.plen = args[3];
        const ovl = args[4];
        this.ovl = ovl;
        this.ovlKey = (ovl && !ovl.isNull()) ? ovlKeyOf(this.hkey, ovl) : null;
      }),
      onLeave: ovlSafeLeave(function (ret) { ovlOnIoLeave(this); })
    });
  }
  // отдельные listener'ы ReadFile/WriteFile не нужны: pending собирают старые VCP-хуки,
  // иначе второй Interceptor-listener глушит первый (проверено на COM1).

  // ReadFileEx/WriteFileEx (APC): завершение через APC не хукаем — логируем запрос.
  if (pWriteEx) attachHook(pWriteEx, {
    onEnter: ovlSafeEnter(function (args) {
      const hkey = args[0].toString();
      const buf = args[1];
      const len = args[2].toInt32();
      if (len > 0) log('VCP TX WriteFileEx(' + ovlLabel(hkey) + ') len=' + len + ' ovl=1 : ' + hexDump(buf, Math.min(len, MAXDUMP)));
    })
  });
  if (pReadEx) attachHook(pReadEx, {
    onEnter: ovlSafeEnter(function (args) {
      const hkey = args[0].toString();
      const len = args[2].toInt32();
      if (len > 0) log('VCP RX ReadFileEx(' + ovlLabel(hkey) + ') len=' + len + ' ovl=1');
    })
  });

  function attachGet(addr) {
    if (!addr) return;
    attachHook(addr, {
      onEnter: ovlSafeEnter(function (args) {
        this.hkey = args[0].toString();
        this.ovl = args[1];
        this.pBytes = args[2];
        this.suppress = ovlSelfCall > 0;
      }),
      onLeave: ovlSafeLeave(function (ret) {
        if (this.suppress) return;
        if (ret.toInt32() !== 0) ovlOnGetResult(this.hkey, this.ovl, this.pBytes);
      })
    });
  }
  attachGet(pGet);
  attachGet(pGetEx);

  // Некоторые обёртки ждут на хендле файла: по WAIT_OBJECT_0 сами спрашиваем
  // GetOverlappedResult (без ожидания). Дублей нет — ovlTakePending удаляет запись.
  if (pWait) attachHook(pWait, {
    onEnter: ovlSafeEnter(function (args) {
      this.hkey = args[0].toString();
      this.relevant = false;
      if (!ovlWrap) return;
      for (const key in ovlPending) {
        const e = ovlPending[key];
        if (e && e.handle === this.hkey) { this.relevant = true; break; }
      }
    }),
    onLeave: ovlSafeLeave(function (ret) {
      if (!this.relevant || ret.toInt32() !== 0 || ovlSelfCall > 0 || !ovlWrap) return;  // WAIT_OBJECT_0 == 0
      const hkey = this.hkey;
      const h = parseInt(hkey, 16);
      const keys = Object.keys(ovlPending);
      for (let i = 0; i < keys.length; i++) {
        const e = ovlPending[keys[i]];
        if (!e || e.handle !== hkey) continue;
        const pBytes = Memory.alloc(4);
        pBytes.writeU32(0);
        ovlSelfCall++;
        let ok = 0;
        try { ok = ovlWrap(h, e.ovl, pBytes, 0); } catch (err) { ok = 0; }
        ovlSelfCall--;
        if (ok) ovlOnGetResult(hkey, e.ovl, pBytes);
      }
    })
  });

  log('overlapped: hooks read/write=' + (pRead ? 1 : 0) + '/' + (pWrite ? 1 : 0) +
      ' get=' + (pGet ? 1 : 0) + ' getEx=' + (pGetEx ? 1 : 0) +
      ' wait=' + (pWait ? 1 : 0) + ' ex=' + ((pReadEx || pWriteEx) ? 1 : 0) +
      ' listeners=' + listeners.length);
}
installOverlappedHooks();



// ==================== УНИВЕРСАЛЬНЫЙ ТРАНСПОРТ (docs/02 §11.3) ====================
// J2534 PassThru, WinUSB, HID, libusb-1.0 и USB-пути \\?\hid#/usb#/winusb#.
// Старые хуки и их строки не меняются: здесь только новые типы строк.
// Каждый колбэк обёрнут enterSafe/leaveSafe — ошибка хука не должна уронить цель.

let HOOK_ERRORS = 0;
function hookError(where, err) {
  try { if (HOOK_ERRORS < 20) { HOOK_ERRORS++; log('universal hook error: ' + where + ': ' + err); } } catch (e) {}
}
function enterSafe(fn) { return function (args) { try { fn.call(this, args); } catch (e) { hookError('enter', e); } }; }
function leaveSafe(fn) { return function (retval) { try { fn.call(this, retval); } catch (e) { hookError('leave', e); } }; }

function u32(ptr) { try { return ptr.readU32(); } catch (e) { return 0; } }
function u8(ptr) { try { return ptr.readU8(); } catch (e) { return 0; } }
function readBe32(ptr) { try { return ((u8(ptr) << 24) | (u8(ptr.add(1)) << 16) | (u8(ptr.add(2)) << 8) | u8(ptr.add(3))) >>> 0; } catch (e) { return 0; } }
function str8(ptr) { try { return ptr && !ptr.isNull() ? ptr.readUtf8String() : ''; } catch (e) { return ''; } }
function str16(ptr) { try { return ptr && !ptr.isNull() ? ptr.readUtf16String() : ''; } catch (e) { return ''; } }
function hx(ptr, len) { try { return len > 0 ? hexDump(ptr, Math.min(len, MAXDUMP)) : ''; } catch (e) { return ''; } }
function hex2(v) {
  var s = (v & 0xff).toString(16);
  return '0x' + (s.length < 2 ? '0' + s : s);
}
function hexLow(v) { return '0x' + (v >>> 0).toString(16); }
function hex4(v) { var s = (v >>> 0).toString(16); while (s.length < 4) s = '0' + s; return '0x' + s; }
function quote(s) { return String(s == null ? '' : s).replace(/"/g, "'"); }

function exportAddr(mod, name) {
  try {
    const ex = mod.enumerateExports();
    for (let i = 0; i < ex.length; i++) {
      if (ex[i].name === name && ex[i].type === 'function') return ex[i].address;
    }
  } catch (e) { hookError('enumerateExports ' + (mod && mod.name), e); }
  return null;
}

// ── состояние/счётчики для rpc.exports.status() ───────────────────────────
let j2534Hooked = {};          // "модуль|base" -> true
let j2534ModulesHooked = 0;
let winusbHooked = false, hidHooked = false, libusbHooked = false, usbPathHooked = false;
let winusbSeen = false, hidSeen = false, libusbSeen = false;
let univObserver = false;

// ── J2534 PassThru ─────────────────────────────────────────────────────────
const J2534_MODULE_RE = /(j2534|passthru|pass-thru|ptshim|op20pt|smj2534|vcxpt|evcucm|ucdsj2534|tactrix|scanmatik|chipsoft)/i;
const PT_MSG_SIZE = 4152;      // 6 * unsigned long (24) + Data[4128]; unsigned long = 4 байта и x86, и x64
const PT_PROTO = { 1: 'J1850VPW', 2: 'J1850PWM', 3: 'ISO9141', 4: 'ISO14230', 5: 'CAN', 6: 'ISO15765',
  7: 'SCI_A_ENGINE', 8: 'SCI_A_TRANS', 9: 'SCI_B_ENGINE', 10: 'SCI_B_TRANS' };
const J2534_EXPORTS = ['PassThruOpen', 'PassThruConnect', 'PassThruDisconnect', 'PassThruReadMsgs',
  'PassThruWriteMsgs', 'PassThruStartMsgFilter', 'PassThruIoctl', 'PassThruClose', 'PassThruGetLastError'];

function ptProtoName(id) { return PT_PROTO[id] || ('0x' + id.toString(16)); }

const PT_CFG_NAMES = {
  0x01: 'DATA_RATE', 0x03: 'LOOPBACK', 0x04: 'NODE_ADDRESS', 0x05: 'NETWORK_LINE',
  0x06: 'P1_MIN', 0x07: 'P1_MAX', 0x08: 'P2_MIN', 0x09: 'P2_MAX', 0x0A: 'P3_MIN', 0x0B: 'P3_MAX',
  0x0C: 'P4_MIN', 0x0D: 'P4_MAX', 0x0E: 'W1', 0x0F: 'W2', 0x10: 'W3', 0x11: 'W4', 0x12: 'W5',
  0x13: 'TIDLE', 0x14: 'TINIL', 0x15: 'TWUP', 0x16: 'PARITY', 0x17: 'BIT_SAMPLE_POINT',
  0x18: 'SYNC_JUMP_WIDTH', 0x19: 'W0', 0x1A: 'T1_MAX', 0x1B: 'T2_MAX', 0x1C: 'T4_MAX',
  0x1D: 'T5_MAX', 0x1E: 'ISO15765_BS', 0x1F: 'ISO15765_STMIN', 0x20: 'DATA_BITS',
  0x21: 'FIVE_BAUD_MOD', 0x22: 'BS_TX', 0x23: 'STMIN_TX', 0x24: 'ISO15765_WFT_MAX'
};

// SCONFIG_LIST { ulNumOfParams; SCONFIG* ConfigPtr } → "DATA_RATE=500000 W1=0 …"
function ptConfigList(p) {
  try {
    const n = p.readU32();
    if (!n || n > 64) return null;
    const off = Process.pointerSize === 8 ? 8 : 4;
    const arr = p.add(off).readPointer();
    if (arr.isNull()) return null;
    const parts = [];
    for (let i = 0; i < n; i++) {
      const ent = arr.add(i * 8);
      const par = ent.readU32();
      const val = ent.add(4).readU32();
      parts.push((PT_CFG_NAMES[par] || ('0x' + par.toString(16))) + '=' + val);
    }
    return parts.join(' ');
  } catch (e) { return null; }
}

function j2534Vendor(modName) {
  const n = (modName || '').toLowerCase();
  if (n.indexOf('smj2534') >= 0 || n.indexOf('scanmatik') >= 0) return 'Scanmatik';
  if (n.indexOf('j2534_interface') >= 0 || n.indexOf('chipsoft') >= 0) return 'CHIPSOFT';
  if (n.indexOf('op20pt') >= 0 || n.indexOf('openport') >= 0 || n.indexOf('tactrix') >= 0) return 'Tactrix';
  if (n.indexOf('vcxpt') >= 0 || n.indexOf('evcucm') >= 0 || n.indexOf('vcx') >= 0) return 'VXDIAG';
  if (n.indexOf('fc200') >= 0) return 'Changguang';
  if (n.indexOf('ucds') >= 0) return 'UCDS';
  if (n.indexOf('mdi') >= 0) return 'Bosch MDI';
  return '';
}

function readPtMsg(base, idx) {
  const p = base.add(idx * PT_MSG_SIZE);
  return {
    proto: u32(p),
    rxs: u32(p.add(4)),
    flags: u32(p.add(8)),
    size: u32(p.add(16)),
    dataPtr: p.add(24)
  };
}

// ISO15765/CAN: Data[0..3] = CAN ID (big-endian), дальше ISO-TP payload.
function emitPtMsg(dir, ch, m) {
  let size = m.size >>> 0;
  if (size > 4128) size = 4128;              // защита от мусорного DataSize
  let off = 0;
  let canId = -1;
  if (m.proto === 5 || m.proto === 6) {      // CAN / ISO15765
    if (size >= 4) { canId = readBe32(m.dataPtr); off = 4; }
  }
  const len = size - off;
  const hex = hx(m.dataPtr.add(off), len);
  const tail = dir === 'TX' ? (' flags=' + hexLow(m.flags)) : (' rxs=' + hexLow(m.rxs));
  const idPart = canId >= 0 ? (' id=0x' + canId.toString(16).toUpperCase()) : '';
  log('J2534 ' + dir + ' ch=' + ch + ' proto=' + ptProtoName(m.proto) + idPart + tail + ' len=' + len + ' : ' + hex);
}

function installJ2534Hook(name, addr, mod) {
  const dll = mod.name || '';
  const vendor = j2534Vendor(dll);
  if (name === 'PassThruOpen') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.pDev = args[1];
        this.name = args[0].isNull() ? '' : str8(args[0]);
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 open name="' + quote(this.name) + '" vendor="' + vendor + '" dll="' + dll + '" rc=' + ret.toInt32());
      })
    });
  } else if (name === 'PassThruConnect') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.dev = args[0].toInt32();
        this.proto = args[1].toInt32();
        this.flags = args[2].toInt32();
        this.baud = args[3].toInt32();
        this.pCh = args[4];
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 connect dev=' + this.dev + ' ch=' + u32(this.pCh) + ' proto=' + ptProtoName(this.proto) +
            ' flags=' + hexLow(this.flags) + ' baud=' + this.baud + ' rc=' + ret.toInt32());
      })
    });
  } else if (name === 'PassThruDisconnect') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) { this.ch = args[0].toInt32(); }),
      onLeave: leaveSafe(function (ret) { log('J2534 disconnect ch=' + this.ch + ' rc=' + ret.toInt32()); })
    });
  } else if (name === 'PassThruReadMsgs') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pMsg = args[1];
        this.pNum = args[2];
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const n = u32(this.pNum);
        if (rc === 0 && n > 0) {
          const cap = Math.min(n, 32);
          for (let i = 0; i < cap; i++) emitPtMsg('RX', this.ch, readPtMsg(this.pMsg, i));
        }
      })
    });
  } else if (name === 'PassThruWriteMsgs') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        const ch = args[0].toInt32();
        const n = u32(args[2]);           // pNumMsgs — указатель на число сообщений
        const pMsg = args[1];
        if (pMsg.isNull()) return;
        const cap = Math.min(n, 16);
        for (let i = 0; i < cap; i++) emitPtMsg('TX', ch, readPtMsg(pMsg, i));
      })
    });
  } else if (name === 'PassThruStartMsgFilter') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) { this.ch = args[0].toInt32(); this.type = args[1].toInt32(); }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 filter ch=' + this.ch + ' type=' + hex4(this.type) + ' rc=' + ret.toInt32());
      })
    });
  } else if (name === 'PassThruIoctl') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.id = args[1].toInt32();
        this.input = args[2];
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        log('J2534 ioctl ch=' + this.ch + ' id=' + hex4(this.id) + ' rc=' + rc);
        // SET_CONFIG (0x02): список параметров, включая DATA_RATE (битрейт CAN/ISO).
        if (this.id === 2 && this.input && !this.input.isNull()) {
          const cfg = ptConfigList(this.input);
          if (cfg) log('J2534 config ch=' + this.ch + ' ' + cfg + ' rc=' + rc);
        }
      })
    });
  } else if (name === 'PassThruClose') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) { this.dev = args[0].toInt32(); }),
      onLeave: leaveSafe(function (ret) { log('J2534 close dev=' + this.dev + ' rc=' + ret.toInt32()); })
    });
  } else if (name === 'PassThruGetLastError') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) { this.pText = args[0]; }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 error text="' + quote(str8(this.pText)) + '" rc=' + ret.toInt32());
      })
    });
  }
}

function hookJ2534Module(mod) {
  if (PAUSED || !mod) return;
  const key = mod.name + '|' + String(mod.base);
  if (j2534Hooked[key]) return;
  let installed = 0;
  for (let i = 0; i < J2534_EXPORTS.length; i++) {
    const name = J2534_EXPORTS[i];
    const addr = exportAddr(mod, name);
    if (!addr) continue;
    try { installJ2534Hook(name, addr, mod); installed++; } catch (e) { hookError('j2534 ' + name, e); }
  }
  j2534Hooked[key] = true;
  if (installed > 0) {
    j2534ModulesHooked++;
    log('J2534 module: ' + mod.name + ' ' + (mod.path || '') + ' base=' + mod.base + ' exports=' + installed);
  }
}

// ── WinUSB (winusb.dll) ────────────────────────────────────────────────────
function hookWinUsbModule(mod) {
  if (PAUSED || !mod || winusbHooked) return;
  winusbHooked = true;
  winusbSeen = true;
  const read = exportAddr(mod, 'WinUsb_ReadPipe');
  const write = exportAddr(mod, 'WinUsb_WritePipe');
  const ctl = exportAddr(mod, 'WinUsb_ControlTransfer');
  if (read) attachHook(read, {
    onEnter: enterSafe(function (args) {
      this.pipe = args[1].toInt32();
      this.buf = args[2];
      this.req = args[3].toInt32();
      this.plen = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      const n = ovlU32(this.plen);
      const len = n > 0 ? n : this.req;
      if (len > 0) log('WINUSB RX pipe=' + hex2(this.pipe) + ' len=' + len + ' : ' + hx(this.buf, len));
    })
  });
  if (write) attachHook(write, {
    onEnter: enterSafe(function (args) {
      this.pipe = args[1].toInt32();
      this.buf = args[2];
      this.req = args[3].toInt32();
      this.plen = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      const n = ovlU32(this.plen);
      const len = n > 0 ? n : this.req;
      if (len > 0) log('WINUSB TX pipe=' + hex2(this.pipe) + ' len=' + len + ' : ' + hx(this.buf, len));
    })
  });
  if (ctl) attachHook(ctl, {
    onEnter: enterSafe(function (args) {
      this.dirIn = (u8(args[1]) & 0x80) !== 0;   // SetupPacket.bmRequestType bit7
      this.buf = args[2];
      this.len = args[3].toInt32();
      this.plen = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      const n = ovlU32(this.plen);
      const len = n > 0 ? n : this.len;
      log('WINUSB CTL dir=' + (this.dirIn ? 'in' : 'out') + ' len=' + len + ' : ' + hx(this.buf, len));
    })
  });
  log('WINUSB module: ' + mod.name + ' read=' + (read ? 1 : 0) + ' write=' + (write ? 1 : 0) + ' ctl=' + (ctl ? 1 : 0));
}

// ── HID (hid.dll) ──────────────────────────────────────────────────────────
function hookHidExport(mod, name, dir) {
  const addr = exportAddr(mod, name);
  if (!addr) return;
  attachHook(addr, {
    onEnter: enterSafe(function (args) {
      this.buf = args[1];
      this.len = args[2].toInt32();
    }),
    onLeave: leaveSafe(function (ret) {
      if (ret.toInt32() === 0) return;           // BOOL: 0 = ошибка, данных нет
      const len = this.len;
      if (len <= 0) return;
      log('HID ' + dir + ' report=' + hex2(u8(this.buf)) + ' len=' + len + ' : ' + hx(this.buf, len));
    })
  });
}
function hookHidModule(mod) {
  if (PAUSED || !mod || hidHooked) return;
  hidHooked = true;
  hidSeen = true;
  hookHidExport(mod, 'HidD_GetFeature', 'RX');
  hookHidExport(mod, 'HidD_SetFeature', 'TX');
  hookHidExport(mod, 'HidD_GetInputReport', 'RX');
  hookHidExport(mod, 'HidD_SetOutputReport', 'TX');
  log('HID module: ' + mod.name);
}

// ── libusb-1.0 ─────────────────────────────────────────────────────────────
function hookLibusbTransfer(mod, name) {
  const addr = exportAddr(mod, name);
  if (!addr) return;
  attachHook(addr, {
    onEnter: enterSafe(function (args) {
      this.ep = args[1].toInt32();
      this.buf = args[2];
      this.len = args[3].toInt32();
      this.ptrans = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      if (ret.toInt32() < 0) return;             // отрицательный rc = ошибка
      const n = u32(this.ptrans);
      const len = n > 0 ? n : this.len;
      const dir = (this.ep & 0x80) ? 'RX' : 'TX';
      log('LIBUSB ' + dir + ' ep=' + hex2(this.ep) + ' len=' + len + ' : ' + hx(this.buf, len));
    })
  });
}
function hookLibusbModule(mod) {
  if (PAUSED || !mod || libusbHooked) return;
  libusbHooked = true;
  libusbSeen = true;
  hookLibusbTransfer(mod, 'libusb_bulk_transfer');
  hookLibusbTransfer(mod, 'libusb_interrupt_transfer');
  const ctl = exportAddr(mod, 'libusb_control_transfer');
  if (ctl) attachHook(ctl, {
    onEnter: enterSafe(function (args) {
      this.dirIn = (args[1].toInt32() & 0x80) !== 0;
      this.buf = args[5];
      this.len = args[6].toInt32();
    }),
    onLeave: leaveSafe(function (ret) {
      const n = ret.toInt32();
      if (n < 0) return;
      log('LIBUSB CTL dir=' + (this.dirIn ? 'in' : 'out') + ' len=' + n + ' : ' + hx(this.buf, n));
    })
  });
  log('LIBUSB module: ' + mod.name);
}

// ── USB-пути (\\.\?\\hid# | usb# | winusb#) + DeviceIoControl ────────────────
const usbHandles = {};
function usbPathKind(path) {
  if (!path) return null;
  const m = /^\\\\\?\\(hid|usb|winusb)#/i.exec(path);
  return m ? m[1].toLowerCase() : null;
}
function emitUsbTransfer(dir, kind, buf, len, reportFirst) {
  // Если приложение работает через FTDI D2XX, то же самое уже логируется как
  // TX/RX ftd2xx FT_Write/FT_Read. USB-события из DeviceIoControl в этом случае —
  // внутренняя реализация драйвера, и мы их не дублируем (иначе tx/rx байты ×2).
  if (ftMod && !PAUSED) return;
  if (!buf || len <= 0) return;
  const hex = hx(buf, len);
  if (kind === 'hid') log('HID ' + dir + ' report=' + hex2(reportFirst ? u8(buf) : 0) + ' len=' + len + ' : ' + hex);
  else if (kind === 'winusb') log('WINUSB ' + dir + ' len=' + len + ' : ' + hex);
  else log('USB ' + dir + ' len=' + len + ' : ' + hex);
}
function installUsbPathHooks() {
  if (PAUSED || usbPathHooked) return;
  usbPathHooked = true;

  const pCreateW = globalExport('CreateFileW');
  const pCreateA = globalExport('CreateFileA');
  const pRead = globalExport('ReadFile');
  const pWrite = globalExport('WriteFile');
  const pClose = globalExport('CloseHandle');
  const pIoctl = globalExport('DeviceIoControl');

  if (pCreateW) attachHook(pCreateW, {
    onEnter: enterSafe(function (args) { this.path = str16(args[0]); }),
    onLeave: leaveSafe(function (ret) {
      const kind = usbPathKind(this.path);
      if (!kind || ret.toString() === '-1') return;
      const key = ret.toString();
      usbHandles[key] = { path: this.path, kind: kind, bytes: 0, writes: 0 };
      log('USB open path="' + quote(this.path) + '" kind=' + kind + ' handle=' + key);
    })
  });
  if (pCreateA) attachHook(pCreateA, {
    onEnter: enterSafe(function (args) { this.path = str8(args[0]); }),
    onLeave: leaveSafe(function (ret) {
      const kind = usbPathKind(this.path);
      if (!kind || ret.toString() === '-1') return;
      const key = ret.toString();
      usbHandles[key] = { path: this.path, kind: kind, bytes: 0, writes: 0 };
      log('USB open path="' + quote(this.path) + '" kind=' + kind + ' handle=' + key);
    })
  });
  // ВАЖНО: отдельные хуки ReadFile/WriteFile здесь не ставим — второй Interceptor-listener
  // на ту же функцию глушит VCP-хук (перехват COM/overlapped перестаёт работать, проверено
  // на MS4x). USB-хендлы обрабатываются внутри общих хуков ReadFile/WriteFile (installVcpHooks).
  if (pClose) attachHook(pClose, {
    onEnter: enterSafe(function (args) {
      const key = args[0].toString();
      const ent = usbHandles[key];
      if (!ent) return;
      log('USB close path="' + quote(ent.path) + '" bytes=' + ent.bytes + ' writes=' + ent.writes);
      delete usbHandles[key];
    })
  });
  if (pIoctl) attachHook(pIoctl, {
    onEnter: enterSafe(function (args) {
      const hkey = args[0].toString();
      try { classifyExistingHandle(hkey); } catch (e) {}
      const ent = usbHandles[hkey];
      if (!ent) return;
      this.ent = ent;
      this.code = args[1].toInt32();
      this.inBuf = args[2];
      this.inLen = args[3].toInt32();
      this.outLen = args[5].toInt32();
      this.pBytes = args[6];
    }),
    onLeave: leaveSafe(function (ret) {
      if (!this.ent) return;
      const n = u32(this.pBytes);
      const outLen = n > 0 ? n : this.outLen;
      const prefix = this.ent.kind === 'hid' ? 'HID' : (this.ent.kind === 'winusb' ? 'WINUSB' : 'USB');
      log(prefix + ' ioctl code=' + hexLow(this.code) + ' rc=' + ret.toInt32() +
          ' in=' + this.inLen + ' out=' + outLen + ' : ' + hx(this.inBuf, this.inLen));
    })
  });
}

// ── установка/пауза ────────────────────────────────────────────────────────
function dispatchUniversalModule(mod) {
  if (!mod || !mod.name) return;
  try {
    if (J2534_MODULE_RE.test(mod.name)) hookJ2534Module(mod);
    else if (/^winusb\.dll$/i.test(mod.name)) hookWinUsbModule(mod);
    else if (/^hid\.dll$/i.test(mod.name)) hookHidModule(mod);
    else if (/^libusb-1\.0/i.test(mod.name)) hookLibusbModule(mod);
  } catch (e) { hookError('dispatch ' + mod.name, e); }
}

function installUniversalHooks() {
  if (PAUSED) return;
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) dispatchUniversalModule(mods[i]);
  } catch (e) { hookError('enumerateModules', e); }
  installUsbPathHooks();
  if (!univObserver) {
    univObserver = true;
    try {
      if (typeof Process.attachModuleObserver === 'function') {
        Process.attachModuleObserver({
          onAdded: function (mod) {
            try { if (!PAUSED) dispatchUniversalModule(mod); } catch (e) { hookError('observer', e); }
          }
        });
        log('universal: module observer armed (J2534/WinUSB/HID/libusb)');
      } else {
        log('universal: module observer НЕДОСТУПЕН (Frida без attachModuleObserver) — только уже загруженные модули');
      }
    } catch (e) { hookError('module observer', e); }
  }
  log('universal hooks: ftdi2xx=' + (ftMod ? 1 : 0) + ' j2534=' + j2534ModulesHooked +
      ' winusb=' + (winusbSeen ? 1 : 0) + ' hid=' + (hidSeen ? 1 : 0) + ' libusb=' + (libusbSeen ? 1 : 0) +
      ' usb_paths=' + Object.keys(usbHandles).length + ' listeners=' + listeners.length);
}

// После паузы все Interceptor-хуки сняты: сбрасываем флаги и ставим заново.
function resumeUniversalHooks() {
  j2534Hooked = {};
  j2534ModulesHooked = 0;
  winusbHooked = false; hidHooked = false; libusbHooked = false; usbPathHooked = false;
  installUniversalHooks();
}

function universalStatus() {
  let ftdi = false;
  try { ftdi = !!(ftMod || Object.keys(hooked).length > 0); } catch (e) { ftdi = false; }
  return {
    ftdi: ftdi,
    j2534: j2534ModulesHooked > 0,
    usb: !!(winusbSeen || hidSeen || libusbSeen || Object.keys(usbHandles).length > 0),
    hooks: listeners.length,
    paused: PAUSED,
    script: 'universal'
  };
}

installUniversalHooks();

// ---------------- канал управления от движка (sidecar/bridge.py): pause / resume / status ----------------
// Нужен, когда приложение под хуками не выполняет критичную операцию (например,
// запись): движок присылает {"cmd":"hookctl","value":"pause"}, bridge.py зовёт
// rpc.exports.hookctl(cmd), хуки снимаются и ставятся заново — A/B-проверка в одной сессии.
// (recv() в Frida 17 одноразовый — доставляет только первое сообщение типа,
//  поэтому управление идёт через RPC, а не через send/recv.)
// status — какие семейства хуков активны (для UI/диагностики моста).
// ping — проверка живости моста без устройства (bridge.py --self-test/смоук).
rpc.exports = {
  hookctl: function (cmd) {
    if (cmd === 'pause') { pauseHooks(); return 'paused'; }
    if (cmd === 'resume') { resumeHooks(); return 'resumed'; }
    return 'unknown';
  },
  status: function () {
    try { return universalStatus(); } catch (e) { return { error: String(e) }; }
  },
  ping: function () {
    return 'pong';
  }
};

log('capture script loaded: pid=' + Process.id + ' arch=' + Process.arch + ' modules=' + Process.enumerateModules().length + ' wall=' + new Date().toISOString());












