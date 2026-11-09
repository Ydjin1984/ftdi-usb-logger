'use strict';
// Quickflash family (BMW, Bimmer Tuning Tools) — K-line traffic capture. Универсальный хук для любого блока.
// Same hook set as work/orig-capture/ftdi_capture.js (proven on BMS46), plus:
//   * .bin/.csv файловые операции (какой файл загружен/сохранён, сколько записано)
//   * увеличенный кап дампа (16 KiB вместо 4 KiB) — fast read может вернуть крупный блок
// Primary: ftd2xx.dll D2XX exports (device enum, open, config, read/write, EEPROM).
// Fallback: kernel32 serial VCP I/O (CreateFileW/ReadFile/WriteFile on COM handles).
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
        if (comHandles[this.hkey]) { this.com = true; this.buf = args[1]; this.len = args[2].toInt32(); this.pw = args[3]; }
        else if (fileHandles[this.hkey]) { this.fent = fileHandles[this.hkey]; this.len = args[2].toInt32(); this.pw = args[3]; }
      },
      onLeave(ret) {
        if (this.fent) {
          let n = 0; try { n = this.pw.readU32(); } catch (e) {}
          this.fent.bytes += n; this.fent.writes += 1;
          log('FILE write ' + this.fent.path + ' n=' + n + ' total=' + this.fent.bytes);
          return;
        }
        if (!this.com) return;
        let n = 0; try { n = this.pw.readU32(); } catch (e) {}
        log('VCP TX WriteFile(' + comHandles[this.hkey] + ') rc=' + ret.toInt32() + ' n=' + n + ' ovl=' + (this.ovl ? 1 : 0) + ' : ' + hexDump(this.buf, Math.min(this.len, MAXDUMP)));
      }
    });
  }
  if (pRead) {
    attachHook(pRead, {
      onEnter(args) {
        this.hkey = args[0].toString();
        this.ovl = !args[4].isNull();
        if (comHandles[this.hkey]) { this.com = true; this.buf = args[1]; this.len = args[2].toInt32(); this.pr = args[3]; }
      },
      onLeave(ret) {
        if (!this.com) return;
        let n = 0; try { n = this.pr.readU32(); } catch (e) {}
        // overlapped-I/O: байт может быть 0 (операция ещё идёт) — выводим запрошенный размер, помечая ovl
        const ln = n > 0 ? n : (this.ovl ? this.len : 0);
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
}
installVcpHooks();

// ---------------- канал управления от движка (sidecar/bridge.py): 'pause' / 'resume' ----------------
// Нужен, когда приложение под хуками не выполняет критичную операцию (например,
// запись): движок присылает {"cmd":"hookctl","value":"pause"}, bridge.py зовёт
// rpc.exports.hookctl(cmd), хуки снимаются и ставятся заново — A/B-проверка в одной сессии.
// (recv() в Frida 17 одноразовый — доставляет только первое сообщение типа,
//  поэтому управление идёт через RPC, а не через send/recv.)
// ping — проверка живости моста без устройства (bridge.py --self-test/смоук).
rpc.exports = {
  hookctl: function (cmd) {
    if (cmd === 'pause') { pauseHooks(); return 'paused'; }
    if (cmd === 'resume') { resumeHooks(); return 'resumed'; }
    return 'unknown';
  },
  ping: function () {
    return 'pong';
  }
};

log('capture script loaded: pid=' + Process.id + ' arch=' + Process.arch + ' modules=' + Process.enumerateModules().length + ' wall=' + new Date().toISOString());
