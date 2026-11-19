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

// ── конфигурация attach: движок кладёт `var __FTDI_CONFIG__ = {…};` ────────
// перед исходником агента (sidecar/bridge.py), поэтому она доступна до
// installUniversalHooks() — режим сбора нельзя менять «после старта».
const CFG = (typeof __FTDI_CONFIG__ !== 'undefined' && __FTDI_CONFIG__) ? __FTDI_CONFIG__ : {};
const MODE = CFG.mode === 'compact' ? 'compact' : 'full';
const BITS = Process.arch === 'ia32' ? 32 : 64;
let CALL_SEQ = 0;
function threadId() { try { return Process.getCurrentThreadId(); } catch (e) { return 0; } }
// Счётчики полноты по стороне агента (docs/09 §4). `dropped_events` здесь —
// именно потери захвата (очередь/буфер), а не вытеснение из сводки шага:
// вытеснение считает движок отдельным `evicted_events`.
const counters = {
  calls: 0, rx_sof: 0, truncated_payloads: 0, decode_errors: 0, dropped_events: 0,
  file_reads: 0, partial_results: 0, contract_violations: 0, xdi_events: 0
};

// ── QPC: 6 знаков после точки и длительность вызова в микросекундах ───────
// Date.now() даёт миллисекунды — для `dur` этого мало. QueryPerformanceCounter
// читаем через NativeFunction: два вызова на запись, сама QPC — десятки нс.
// Если QPC недоступна, деградируем до прежних трёх знаков (старый формат).
let qpcFreq = 0, qpcT0 = 0, qpcBuf = null, qpcCount = null;
(function initQpc() {
  try {
    const pFreq = globalExport('QueryPerformanceFrequency');
    const pCnt = globalExport('QueryPerformanceCounter');
    if (!pFreq || !pCnt) return;
    qpcBuf = Memory.alloc(16);
    const freqFn = new NativeFunction(pFreq, 'int', ['pointer']);
    const cntFn = new NativeFunction(pCnt, 'int', ['pointer']);
    if (freqFn(qpcBuf) === 0) return;
    qpcFreq = qpcBuf.readU64().toNumber();
    if (!qpcFreq) return;
    if (cntFn(qpcBuf) === 0) { qpcFreq = 0; return; }
    qpcT0 = qpcBuf.readU64().toNumber();
    qpcCount = cntFn;
  } catch (e) { qpcCount = null; qpcFreq = 0; }
})();

function qpcNow() {
  if (!qpcCount) return 0;
  try { qpcCount(qpcBuf); return qpcBuf.readU64().toNumber(); } catch (e) { return 0; }
}
function qpcUs(from, to) {
  if (!qpcFreq || !from || !to || to < from) return 0;
  return Math.round((to - from) * 1e6 / qpcFreq);
}
function ts() {
  if (qpcCount && qpcFreq) return '+' + (qpcUs(qpcT0, qpcNow()) / 1e6).toFixed(6) + 's';
  return '+' + ((Date.now() - T0) / 1000).toFixed(3) + 's';
}
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
// Наши InvocationListener-ы: пауза снимает только их (detachAll убивает recv).
// Каждый помнит ещё адрес и «владельца» — модуль, в чьём коде стоит патч.
// Зачем: при FreeLibrary код DLL исчезает вместе с нашими байтами, а при
// повторной загрузке Windows часто кладёт её по ТОМУ ЖЕ base. Пока ключ
// `j2534Hooked[модуль|base]` не снят, повторный onAdded ранний выход — и второй
// проход писался в пустоту. Именно так у PCMflash логировался только первый
// шаг («Идентификация»), а «Чтение фулл флеш» после close давал 0 строк.
const listeners = [];      // [{ l, addr, owner }]
const hookedAddrs = new Set();  // адреса, на которых уже стоит наш listener
let currentOwner = '';     // чей код хукаем сейчас (ставится hook*Module)
let ftMod = null;          // модуль ftd2xx: нужен для повторной установки после паузы
let PAUSED = false;        // пауза хуков (логер может снять их на время критичной операции)

function setOwner(owner) { currentOwner = owner || ''; }
function modKey(mod) { return mod ? (mod.name + '|' + String(mod.base)) : ''; }

// Идемпотентно: повторная установка на тот же адрес (повторный dispatch модуля,
// повторный onAdded от наблюдателя) давала ВТОРОЙ listener — и каждая строка
// писалась дважды (`LAN CLOSE …` парами в логе PCMflash).
function attachHook(target, cbs) {
  const key = String(target);
  if (hookedAddrs.has(key)) return null;
  const l = Interceptor.attach(target, cbs);
  hookedAddrs.add(key);
  listeners.push({ l: l, addr: key, owner: currentOwner });
  return l;
}

// Снять хуки одного владельца (его DLL выгружается) и освободить адреса:
// иначе повторная загрузка по тому же base не поставит хуки заново.
function detachOwner(owner) {
  let n = 0;
  for (let i = listeners.length - 1; i >= 0; i--) {
    const e = listeners[i];
    if (owner && e.owner !== owner) continue;
    try { e.l.detach(); } catch (err) {}
    hookedAddrs.delete(e.addr);
    listeners.splice(i, 1);
    n++;
  }
  return n;
}

function pauseHooks() {
  if (PAUSED) return;
  PAUSED = true;
  let n = 0;
  for (let i = 0; i < listeners.length; i++) {
    try { listeners[i].l.detach(); n++; } catch (e) {}
  }
  listeners.length = 0;
  hookedAddrs.clear();  // после detach адреса свободны — resume поставит хуки заново
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
  // Каналы могли открыться, пока хуков не было: помечаем разрыв захвата, а не
  // «канал не открывался» (docs/09 D1, приёмка pause → открытие → resume).
  try { markChannelsPossiblyOpen('resume'); } catch (e) {}
  log('hookctl: возобновление — хуки поставлены заново');
}

function installFtHook(name, addr) {
  if (name === 'FT_Write') {
    attachHook(addr, {
      onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pwritten = args[3]; },
      onLeave(ret) {
        let n = 0; try { n = this.pwritten.readU32(); } catch (e) {}
        chunkedLog('TX ftd2xx FT_Write rc=' + ret.toInt32() + ' len=' + this.len + ' n=' + n,
          this.buf, this.len);
      }
    });
  } else if (name === 'FT_Read') {
    attachHook(addr, {
      onEnter(args) { this.buf = args[1]; this.len = args[2].toInt32(); this.pgot = args[3]; },
      onLeave(ret) {
        let n = 0; try { n = this.pgot.readU32(); } catch (e) {}
        if (n > 0) chunkedLog('RX ftd2xx FT_Read rc=' + ret.toInt32() + ' want=' + this.len + ' n=' + n,
          this.buf, n);
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
  setOwner(modKey(mod));
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
  setOwner('');
  if (vcpOn) return;
  vcpOn = true;
  const pCreate = globalExport('CreateFileW');
  const pCreateA = globalExport('CreateFileA');
  const pRead = globalExport('ReadFile');
  const pWrite = globalExport('WriteFile');
  const pClose = globalExport('CloseHandle');

  // D6: чтение входного файла. Раньше был виден только open/close, поэтому
  // «какими блоками PCMflash читает .bin» из лога не следовало. Не более
  // FILE_READ_LIMIT строк на сессию, дальше — только агрегат в # counters.
  const FILE_READ_LIMIT = 4096;
  let fileSizeFn = null;
  function fileSizeOf(handle) {
    try {
      if (fileSizeFn === null) {
        const p = globalExport('GetFileSizeEx');
        fileSizeFn = p ? new NativeFunction(p, 'int', ['pointer', 'pointer']) : false;
      }
      if (!fileSizeFn) return 0;
      const buf = Memory.alloc(8);
      if (fileSizeFn(handle, buf) === 0) return 0;
      return buf.readU64().toNumber();
    } catch (e) { return 0; }
  }
  function logFileRead(f, hkey, pN) {
    try {
      let n = 0;
      try { n = pN.readU32() >>> 0; } catch (e) { n = 0; }
      if (counters.file_reads >= FILE_READ_LIMIT) { f.readAgg = (f.readAgg || 0) + n; return; }
      counters.file_reads += 1;
      f.rpos = (f.rpos || 0) + n;
      const off = Math.max(0, f.rpos - n);
      log('FILE read h=' + hkey + ' off=0x' + off.toString(16) + ' len=' + n + ' total=' + (f.size || 0));
    } catch (e) { hookError('file read', e); }
  }

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
      // CreateFileA внутри вызывает CreateFileW — без этой проверки каждый файл
      // попадал в лог 2–3 раза (та же ручка, тот же путь), и счётчик files врал.
      if (fileHandles[key] && fileHandles[key].path === path) return;
      fileHandles[key] = { path: path, access: access, bytes: 0, writes: 0, reads: 0, rpos: 0, size: fileSizeOf(ret) };
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
        chunkedLog('VCP TX WriteFile(' + comHandles[this.hkey] + ') rc=' + ret.toInt32() + ' n=' + n + ' ovl=' + (this.ovl ? 1 : 0), this.buf, this.len);
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
        else if (fileHandles[this.hkey]) {
          // D6: чтение входного .bin — единственное место, где видно, какими
          // блоками PCMflash читает прошивку. Писали только open/close.
          this.fentR = fileHandles[this.hkey]; this.len = args[2].toInt32(); this.pr = args[3];
        }
        else { try { if (typeof usbHandles !== 'undefined' && usbHandles[this.hkey]) { this.usbEnt = usbHandles[this.hkey]; this.buf = args[1]; this.len = args[2].toInt32(); this.pr = args[3]; } } catch (e) {} }
      },
      onLeave(ret) {
        if (this.usbEnt) {
          let n = 0; try { n = this.pr.readU32(); } catch (e) {}
          // Синхронно завершившийся overlapped-запрос: снимаем pending, иначе
          // ovlSweep позже выдаст те же байты второй раз.
          if (this.ovlKey) { try { delete ovlPending[this.ovlKey]; } catch (e) {} }
          this.usbEnt.bytes += n;
          this.usbEnt.reads = (this.usbEnt.reads || 0) + 1;
          if (n > 0) { try { emitUsbTransfer('RX', this.usbEnt.kind, this.buf, n, true); } catch (e) {} }
          return;
        }
        let lerrEarly = 0;
        try { lerrEarly = (this.ovl && this.com) ? ovlLastError() : 0; } catch (e) { lerrEarly = 0; }
        try { ovlOnIoLeave(this, ret); } catch (e) {}
        if (this.fentR) { logFileRead(this.fentR, this.hkey, this.pr); return; }
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
        if (ln > 0) chunkedLog('VCP RX ReadFile(' + comHandles[this.hkey] + ') rc=' + ret.toInt32() + ' n=' + n + ' ovl=' + (this.ovl ? 1 : 0), this.buf, ln);
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
  setOwner('');
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
      try { fileHandles[hkey] = { path: norm, access: 0, bytes: 0, writes: 0, reads: 0, rpos: 0, size: 0 }; } catch (e) {}
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
    const hkey = e.handle;
    // USB-устройство с проприетарным драйвером (Scanmatik/PCMflash и подобные):
    // bulk-обмен идёт overlapped-ReadFile. При pending ReadFile возвращает 0, а
    // байты приходят позже в GetOverlappedResult. Раньше эта ветка USB просто
    // игнорировала — и в логе PCMflash 4 МБ чтения флеша не попадали вообще,
    // а `USB close` показывал bytes=0 при реальном трафике.
    if (e.kind === 'usb') {
      if (!e.isRead) return;                     // TX уже отдан на входе WriteFile
      const ent = usbHandles[hkey];
      if (ent) { ent.bytes += n; ent.reads = (ent.reads || 0) + 1; }
      emitUsbTransfer('RX', ent ? ent.kind : 'usb', e.buf, n, true);
      return;
    }
    if (e.kind !== 'com' && !(e.kind === 'file' && !e.isRead)) return;  // pipe и прочее не шумим
    if (!e.isRead && e.kind === 'com') return;   // TX уже отдан на входе WriteFile
    let fileEnt = null;
    try { fileEnt = fileHandles[hkey] || null; } catch (err) {}
    if (e.isRead) {
      if (fileEnt) return;
      chunkedLog('VCP RX ReadFile(' + ovlLabel(hkey) + ') rc=0 n=' + n + ' ovl=1', e.buf, n);
    } else if (fileEnt) {
      fileEnt.bytes += n;
      fileEnt.writes += 1;
      log('FILE write ' + fileEnt.path + ' n=' + n + ' total=' + fileEnt.bytes);
    } else {
      chunkedLog('VCP TX WriteFile(' + ovlLabel(hkey) + ') rc=0 n=' + n + ' ovl=1', e.buf, n);
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
        chunkedLog('VCP TX WriteFile(' + ovlLabel(hkey) + ') rc=0 n=' + ent.len + ' ovl=1', ent.buf, ent.len);
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
          // USB: операция не завершилась — честно говорим об этом, чтобы «дыра»
          // в логе была видна, а не выглядела как отсутствие обмена.
          else if (e.kind === 'usb') log('USB RX ovl=pending handle=' + e.handle + ' want=' + e.len);
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
  setOwner('');
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
      if (len > 0) chunkedLog('VCP TX WriteFileEx(' + ovlLabel(hkey) + ') len=' + len + ' ovl=1', buf, len);
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

// Одна строка лога — не больше MAXDUMP байт. Крупный буфер режем на части с
// `part=i/n`, чтобы хвост не терялся молча (16 КиБ FTDI/VCP — реальный кейс).
// Если частей больше 64, пишем явную отметку усечения с исходной длиной: лучше
// видимая потеря, чем тихая.
function chunkedLog(head, buf, len) {
  try {
    if (!len || len <= 0) { log(head); return; }
    const total = Math.ceil(len / MAXDUMP);
    const parts = Math.min(total, 64);
    for (let i = 0; i < parts; i++) {
      const off = i * MAXDUMP;
      const take = Math.min(len - off, MAXDUMP);
      if (take <= 0) break;
      let s = head;
      if (total > 1) s += ' part=' + (i + 1) + '/' + total;
      if (total > parts && i === parts - 1) {
        counters.truncated_payloads += 1;
        s += ' truncated=1 len=' + len + ' logged=' + (parts * MAXDUMP);
      }
      log(s + ' : ' + hx(buf.add(off), take));
    }
  } catch (e) { hookError('chunked log', e); }
}
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
// PassThruSetProgrammingVoltage добавлен 18.11.2026: без него в логе не было
// ни одной записи об управлении питанием — BitBox включает 12 В именно им,
// а хук его не перехватывал, и пять секунд между READ_VBATT и первым кадром
// выглядели пустыми. PassThruReadVersion — чтобы видеть версию API целиком.
// 18.11.2026: фиксированный список заменён обходом всех экспортов `PassThru*`
// (см. hookJ2534Module) — у вендоров разный набор функций, и всё, чего не было
// в списке, молча выпадало из лога (PassThruConnect у Scanmatik, StopMsgFilter,
// SetConfig у части драйверов).

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

// ISO15765/CAN: Data[0..3] = CAN ID (big-endian), дальше ISO-TP payload.
// Вендорные протоколы (PCMflash/Scanmatik 0x8003 и подобные) шлют 2-байтовый
// BE-префикс длины — его не срезаем (лог должен остаться байт-в-байт), но по нему
// находим сервисный байт и пишем `svc=0x27`, чтобы сводка шага показывала
// «0x27 SecurityAccess», а не «0x8003 ?».
function ptStripLength(ptr, size) {
  try {
    if (size < 3) return 0;
    const n = ((ptr.readU8() << 8) | ptr.add(1).readU8()) >>> 0;
    return n === size - 2 ? 2 : 0;
  } catch (e) { return 0; }
}
function ptServiceByte(proto, ptr, size, svcOff) {
  try {
    if (size <= svcOff) return null;
    if (proto === 5 || proto === 6) {
      const pci = ptr.add(svcOff).readU8();
      if ((pci & 0xF0) === 0x00 && size - svcOff >= 2) return ptr.add(svcOff + 1).readU8();
      return null;   // FF/CF/FC — сервиса в этом кадре нет
    }
    // Стандартные не-CAN протоколы (ISO9141/ISO14230/SAE) кодируют заголовок
    // (FMT/TGT/SRC), поэтому первый байт — не сервис. Их разбирает движок
    // (decode::j2534_service по ISO 14230-2), здесь не выдумываем.
    if (PT_PROTO[proto] !== undefined) return null;
    return ptr.add(svcOff).readU8();
  } catch (e) { return null; }
}
// ── J2534: полнота вызова, каналы, ABI (docs/09 §3, §5; docs/11) ─────────
// Ключ канала: pid | module_load_id | ch | gen. module_load_id — счётчик
// загрузок ИМЕНИ модуля, а не адрес базы: база повторяется после выгрузки,
// и без счётчика события двух сессий склеились бы (D1). gen растёт только
// после успешного Connect.
const chanState = {};   // "pid|load|ch" -> {ch, load, gen, open, missLogged}
const modLoadSeq = {};  // name.lower -> сколько раз имя загружалось (монотонно, не сбрасывается)
const modLoads = {};    // name.lower -> {base, id}: id растёт только при РЕАЛЬНОЙ перезагрузке

// `module_load_id` идентифицирует загрузку модуля, а не установку хуков:
// после pause → resume тот же модуль по тому же base остаётся той же загрузкой,
// иначе канал выглядел бы «не открывавшимся» и появлялся ложный chan-miss.
// При выгрузке вход из modLoads удаляется, но счётчик seq продолжает расти —
// иначе повторная загрузка снова получила бы id=1 и склеилась с прошлой сессией.
function loadIdFor(mod) {
  const name = String((mod && mod.name) || '').toLowerCase();
  const base = String((mod && mod.base) || '');
  const cur = modLoads[name];
  if (cur && cur.base === base) return cur.id;
  modLoadSeq[name] = (modLoadSeq[name] || 0) + 1;
  modLoads[name] = { base: base, id: modLoadSeq[name] };
  return modLoadSeq[name];
}

function chanKey(load, ch) { return Process.id + '|' + load + '|' + ch; }

function chanTouch(load, ch, op) {
  const k = chanKey(load, ch);
  let st = chanState[k];
  if (!st) st = chanState[k] = { ch: ch, load: load, gen: 0, open: false, missLogged: false };
  if (!st.open && !st.missLogged) {
    st.missLogged = true;
    // `mod=` — идентификатор загрузки DLL (как в rx-empty): без него нельзя
    // понять, канал «не открывался» или открылся при другой загрузке модуля.
    log('J2534 chan-miss ch=' + ch + ' gen=' + (st.gen + 1) + ' first_op=' + op +
        ' mod=' + load + ' th=' + threadId());
  }
  return st;
}

function chanOpen(load, ch) {
  const k = chanKey(load, ch);
  let st = chanState[k];
  if (!st) st = chanState[k] = { ch: ch, load: load, gen: 0, open: false, missLogged: false };
  st.gen += 1;
  st.open = true;
  st.missLogged = false;
  return st;
}

function chanClose(load, ch) {
  const st = chanState[chanKey(load, ch)];
  if (st) st.open = false;
}

// Пауза захвата: каналы могли открыться, пока хуков не было. Не выдаём их
// за открытые сейчас — помечаем разрыв, а не «канал не открывался» (D1).
function markChannelsPossiblyOpen(reason) {
  for (const k in chanState) {
    const st = chanState[k];
    if (!st.open) continue;
    log('J2534 chan-possibly-open ch=' + st.ch + ' gen=' + st.gen + ' reason=' + reason);
  }
}

// ── подавленные таймауты (D3) ────────────────────────────────────────────
// ERR_BUFFER_EMPTY (0x10) и ERR_TIMEOUT (0x11) — штатные ответы опроса.
// Построчно их писать нельзя (поток забивается), но и терять нельзя: считаем
// и печатаем агрегат раз в 5 с и на disconnect.
const emptyStat = {};   // load|ch|gen|rc|timeout_ms -> {n, ...}
const txErrStat = {};   // load|ch|gen|rc -> {n, ...}
let emptyTimer = null;

function chanGenOf(load, ch) {
  const st = chanState[chanKey(load, ch)];
  return st ? st.gen : 0;
}

// Ключ агрегата — по загрузке DLL, поколению канала, коду и таймауту: иначе
// разные результаты и таймауты сливаются в одну строку и «агрегат» врёт.
function emptyPoll(load, ch, rc, timeoutMs) {
  const gen = chanGenOf(load, ch);
  const k = load + '|' + ch + '|' + gen + '|' + (rc >>> 0) + '|' + (timeoutMs >>> 0);
  let st = emptyStat[k];
  if (!st) st = emptyStat[k] = { n: 0, load: load, ch: ch, gen: gen, rc: rc, timeout_ms: timeoutMs };
  st.n += 1;
}

function txErr(load, ch, rc) {
  const gen = chanGenOf(load, ch);
  const k = load + '|' + ch + '|' + gen + '|' + (rc >>> 0);
  let st = txErrStat[k];
  if (!st) st = txErrStat[k] = { n: 0, load: load, ch: ch, gen: gen, rc: rc };
  st.n += 1;
}

function flushIoStats() {
  for (const k in emptyStat) {
    const st = emptyStat[k];
    if (!st.n) continue;
    log('J2534 rx-empty ch=' + st.ch + ' gen=' + st.gen + ' mod=' + st.load + ' n=' + st.n +
        ' timeout_ms=' + st.timeout_ms + ' last_rc=0x' + (st.rc >>> 0).toString(16));
    st.n = 0;
  }
  for (const k in txErrStat) {
    const st = txErrStat[k];
    if (!st.n) continue;
    log('J2534 tx-err-stat ch=' + st.ch + ' gen=' + st.gen + ' mod=' + st.load + ' n=' + st.n +
        ' last_rc=0x' + (st.rc >>> 0).toString(16));
    st.n = 0;
  }
}

function startIoStatsTimer() {
  if (emptyTimer) return;
  try {
    emptyTimer = setInterval(function () { try { flushIoStats(); } catch (e) {} }, 5000);
  } catch (e) { emptyTimer = null; }
}

// ── ABI: 04.04 разбираем, 05.00 только регистрируем (docs/09 §5) ──────────
// Карта dll→api приходит от движка (он читает реестр PassThruSupport.04.04
// и .05.00). Если DLL в обеих ветках и версия не прочитана — dec=0.
const ABI_HINTS = (CFG.j2534_api && typeof CFG.j2534_api === 'object') ? CFG.j2534_api : {};
const ABI_KNOWN = Object.keys(ABI_HINTS).length > 0;
const modAbi = {};      // load -> {api, dec, ver, reason, dll, logged}

function abiFor(load, dll) {
  if (modAbi[load]) return modAbi[load];
  const hint = ABI_HINTS[String(dll || '').toLowerCase()];
  let api = '04.04', dec = 1, reason = '';
  if (hint === '05.00') { api = '05.00'; dec = 0; }
  else if (hint === 'ambiguous') { api = 'unknown'; dec = 0; reason = 'ambiguous'; }
  else if (hint === undefined && ABI_KNOWN) { api = 'unknown'; dec = 0; reason = 'unregistered'; }
  // Карты нет (реестр недоступен) — сохраняем прежнее поведение: 04.04.
  const st = modAbi[load] = { api: api, dec: dec, ver: '', reason: reason, dll: dll || '', logged: false };
  return st;
}

function emitApiLine(st, mod) {
  try {
    log('# api: ' + st.api + ' dll="' + ((mod && mod.name) || st.dll) + '" ver="' + (st.ver || '') +
        '" path="' + String((mod && mod.path) || '') + '" pid=' + Process.id + ' bits=' + BITS +
        ' dec=' + st.dec + (st.reason ? ' reason=' + st.reason : ''));
  } catch (e) { hookError('api line', e); }
}

// ── PASSTHRU_MSG 04.04: разбор и форматирование ──────────────────────────
const PT_DATA_MAX = 4128;      // Data[4128] в PASSTHRU_MSG; 05.00 — другая модель

const PT_IOCTL_NAMES = {
  0x01: 'GET_CONFIG', 0x02: 'SET_CONFIG', 0x03: 'READ_VBATT', 0x05: 'FAST_INIT',
  0x07: 'CLEAR_TX_BUFFER', 0x08: 'CLEAR_RX_BUFFER', 0x09: 'CLEAR_RX_MSGS',
  0x0A: 'CLEAR_MSG_FILTERS', 0x0B: 'CLEAR_PERIODIC_MSGS', 0x0C: 'CLEAR_EXTRA_MSGS',
  0x0D: 'CLEAR_ISO15765_FLOW_CONTROL', 0x0E: 'CLEAR_ISO15765_BUFFERS'
};
const PT_FILTER_NAMES = { 0x01: 'PASS_FILTER', 0x02: 'BLOCK_FILTER', 0x03: 'FLOW_CONTROL_FILTER' };

// Слитный hex (без пробелов) — для in=/out=/mask=/pattern=.
function hxc(ptr, len) {
  try {
    if (!ptr || len <= 0) return '-';
    const n = Math.min(len, MAXDUMP);
    const b = new Uint8Array(ptr.readByteArray(n));
    let s = '';
    for (let i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
    return s || '-';
  } catch (e) { return '-'; }
}

// Снимок сообщения в обычный объект: читаем ДО возврата из вызова, чтобы
// буфер, который драйвер меняет на месте, не исказил запись.
function ptRecord(base, idx) {
  const p = base.add(idx * PT_MSG_SIZE);
  const proto = u32(p);
  const rxs = u32(p.add(4));
  const flags = u32(p.add(8));
  const tsv = u32(p.add(12));
  const size = u32(p.add(16)) >>> 0;
  const xdiRaw = u32(p.add(20)) >>> 0;      // ExtraDataIndex: где начинаются extra-данные
  const dataPtr = p.add(24);
  let len = 0, canId = -1, idLen = 0, svc = null, hex = '', xdi = 0;
  if (size <= PT_DATA_MAX) {
    const isCan = (proto === 5 || proto === 6);
    // CAN: первые 4 байта Data — идентификатор кадра. Он декодируется в `id`,
    // но исходные байты остаются в hex целиком: раньше они выносились из hex и
    // терялись при обратной сборке кадра.
    if (isCan && size >= 4) { canId = readBe32(dataPtr); idLen = 4; }
    len = size;
    if (size > 0) {
      const svcOff = isCan ? idLen : ptStripLength(dataPtr, size);
      svc = ptServiceByte(proto, dataPtr, size, svcOff);
      // Горячий путь (§8): hexDump только для непустых буферов.
      hex = hx(dataPtr, size);
    }
    if (xdiRaw > 0 && xdiRaw < size) { xdi = xdiRaw; counters.xdi_events += 1; }
  }
  return { proto: proto, rxs: rxs, flags: flags, ts: tsv, size: size,
           len: len, canId: canId, idLen: idLen, svc: svc, hex: hex, xdi: xdi };
}

// c.common=1 — все общие поля на строке сообщения (одиночный вызов);
// иначе на строке только call и i, а общие поля — в строке J2534 call.
function ptLine(dir, ch, r, c) {
  const sof = dir === 'RX' && (r.rxs & 0x02) !== 0 ? 1 : 0;
  let s = 'J2534 ' + dir + ' ch=' + ch + ' call=' + c.call + ' i=' + c.i + '/' + c.n;
  if (c.common) s += ' n_in=' + c.nIn + ' n_out=' + c.nOut + ' th=' + c.th;
  s += ' ts=' + r.ts;
  s += dir === 'TX' ? ' flags=' + hexLow(r.flags) : ' rxs=' + hexLow(r.rxs);
  if (sof) s += ' sof=1';
  s += ' proto=' + ptProtoName(r.proto);
  if (r.canId >= 0) s += ' id=0x' + r.canId.toString(16).toUpperCase();
  if (r.idLen > 0) s += ' idlen=' + r.idLen;
  if (r.svc !== null) s += ' svc=' + hex2(r.svc);
  if (r.xdi > 0) s += ' xdi=' + r.xdi;
  s += ' len=' + r.len;
  if (c.common) s += ' dur=' + c.dur + ' rc=' + c.rc;
  // SOF без данных — короткая строка (D2); SOF с данными сохраняет и байты.
  if (sof && r.len === 0) return s;
  if (r.len > 0) s += ' : ' + r.hex;
  return s;
}

function filtMsg(p) {
  if (!p || p.isNull()) return null;
  try {
    const size = u32(p.add(16)) >>> 0;
    return {
      proto: u32(p),
      flags: u32(p.add(8)),
      size: size,
      hex: (size > 0 && size <= PT_DATA_MAX) ? hxc(p.add(24), size) : '-'
    };
  } catch (e) { return null; }
}

// PASSTHRU_MSG как аргумент ioctl: in=/out= (docs/09 D4: FAST_INIT — не 4 байта).
function ptMsgArg(prefix, p, st) {
  if (!p || p.isNull()) return prefix + '_ptr=0';
  if (st && st.dec === 0) return prefix + '_ptr=1 ' + prefix + '=none reason=abi';
  const size = u32(p.add(16)) >>> 0;
  if (size > PT_DATA_MAX) {
    return prefix + '_size=' + size + ' len_invalid=1 ' + prefix + '=none reason=len_invalid';
  }
  const data = p.add(24);
  return prefix + '_proto=' + hex4(u32(p)) +
    ' ' + prefix + '_rxs=' + hexLow(u32(p.add(4))) +
    ' ' + prefix + '_flags=' + hexLow(u32(p.add(8))) +
    ' ' + prefix + '_ts=' + (u32(p.add(12)) >>> 0) +
    ' ' + prefix + '_edi=' + (u32(p.add(20)) >>> 0) +
    ' ' + prefix + '_size=' + size +
    ' ' + prefix + '=' + hxc(data, size);
}

// SCONFIG_LIST { ulNumOfParams; SCONFIG* ConfigPtr } → слитный hex.
function sconfigHex(p, st) {
  if (!p || p.isNull()) return '';
  if (st && st.dec === 0) return '';
  try {
    const n = p.readU32();
    if (!n || n > 64) return '';
    const off = Process.pointerSize === 8 ? 8 : 4;
    const hdr = new Uint8Array(p.readByteArray(off));
    let s = '';
    for (let i = 0; i < hdr.length; i++) s += (hdr[i] < 16 ? '0' : '') + hdr[i].toString(16);
    const arr = p.add(off).readPointer();
    if (!arr.isNull()) {
      const cnt = Math.min(n, 16);
      const bytes = new Uint8Array(arr.readByteArray(cnt * 8));
      for (let i = 0; i < bytes.length; i++) s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return s;
  } catch (e) { return ''; }
}

function ioctlInput(id, p, st) {
  if (id >= 0x07 && id <= 0x0E) return 'in_ptr=0';      // CLEAR_*: буферов нет
  if (!p || p.isNull()) return 'in_ptr=0';
  if (id === 0x05) return ptMsgArg('in', p, st);
  if (id === 0x01 || id === 0x02) {
    const h = sconfigHex(p, st);
    return h ? ('in=' + h) : ('in_ptr=1' + (st && st.dec === 0 ? ' dec=0' : ''));
  }
  return 'in_ptr=1 dec=0';                               // неизвестный id: не читаем
}

function ioctlOutput(id, p, st) {
  if (!p || p.isNull()) return 'out_ptr=0';
  if (id === 0x03) {                                     // READ_VBATT: unsigned long
    return (st && st.dec === 0) ? 'out_ptr=1 out=none reason=abi' : ('out=' + hxc(p, 4));
  }
  if (id === 0x05) return ptMsgArg('out', p, st);
  if (id === 0x01) {
    const h = sconfigHex(p, st);
    return h ? ('out=' + h) : 'out_ptr=1';
  }
  return 'out_ptr=1';
}

// ── обработчики PassThru* ────────────────────────────────────────────────
function installJ2534Hook(name, addr, mod, load) {
  const dll = mod.name || '';
  const vendor = j2534Vendor(dll);
  const abi = abiFor(load, dll);

  if (name === 'PassThruOpen') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.pDev = args[1];
        this.name = args[0].isNull() ? '' : str8(args[0]);
        this.th = threadId();
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        // DeviceID валиден только при успехе; при ошибке пишем dev=-1.
        const dev = rc === 0 ? (u32(this.pDev) >>> 0) : -1;
        // `mod=` — идентификатор загрузки DLL: по нему видно, что второй Open
        // идёт БЕЗ выгрузки библиотеки (docs/12, приёмка Close → Open).
        log('J2534 open name="' + quote(this.name) + '" vendor="' + vendor + '" dll="' + dll +
            '" dev=' + dev + ' mod=' + load + ' rc=' + rc + ' th=' + this.th);
      })
    });
    return;
  }

  if (name === 'PassThruConnect') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.dev = args[0].toInt32();
        this.proto = args[1].toInt32();
        this.flags = args[2].toInt32();
        this.baud = args[3].toInt32();
        this.pCh = args[4];
        this.th = threadId();
        this.t0 = qpcNow();
        // Вход пишется ДО вызова: connect-enter без строки результата доказывает
        // только то, что выход в лог не попал (docs/09 D1), и это разные вещи.
        log('J2534 connect-enter dev=' + this.dev + ' proto=' + ptProtoName(this.proto) +
            ' flags=' + hexLow(this.flags) + ' baud=' + this.baud + ' th=' + this.th);
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const ch = u32(this.pCh) >>> 0;
        const dur = qpcUs(this.t0, qpcNow());
        let gen = 0;
        if (rc === 0) gen = chanOpen(load, ch).gen;
        log('J2534 connect dev=' + this.dev + ' ch=' + ch + ' proto=' + ptProtoName(this.proto) +
            ' flags=' + hexLow(this.flags) + ' baud=' + this.baud + ' rc=' + rc +
            ' gen=' + gen + ' th=' + this.th + ' dur=' + dur);
      })
    });
    return;
  }

  if (name === 'PassThruDisconnect') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.th = threadId();
        this.t0 = qpcNow();
      }),
      onLeave: leaveSafe(function (ret) {
        chanClose(load, this.ch);
        flushIoStats();          // D3: агрегат опросов при disconnect
        log('J2534 disconnect ch=' + this.ch + ' rc=' + ret.toInt32() +
            ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
      })
    });
    return;
  }

  if (name === 'PassThruReadMsgs') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pMsg = args[1];
        this.pNum = args[2];
        this.nIn = u32(args[2]) >>> 0;
        try { this.timeoutMs = args[3].toInt32(); } catch (e) { this.timeoutMs = 0; }
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'ReadMsgs');
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const dur = qpcUs(this.t0, qpcNow());
        const nOut = u32(this.pNum) >>> 0;
        counters.calls += 1;

        const to = this.timeoutMs;
        // rc=0 печатается как `0`, остальные — hex: так строка не меняет вид
        // для успешных вызовов и остаётся однозначной для ошибок.
        const rcHex = rc === 0 ? '0' : '0x' + (rc >>> 0).toString(16);
        // Предел чтения — ёмкость входного массива (n_in). n_out > n_in значит,
        // что драйвер записал больше, чем ему дали: читаем только n_in, но факт
        // нарушения контракта фиксируем отдельно, а не молча обрезаем.
        const capByInput = this.nIn > 0 ? this.nIn : 256;
        const overflow = nOut > capByInput;
        let cap = Math.min(nOut, capByInput, 256);

        if ((rc === 0x10 || rc === 0x11) && nOut === 0) {   // ERR_BUFFER_EMPTY / ERR_TIMEOUT
          emptyPoll(load, this.ch, rc, to);
          if (MODE === 'full') {
            log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=ReadMsgs n_in=' + this.nIn +
                ' n_out=0 timeout_ms=' + to + ' rc=' + rcHex + ' th=' + this.th + ' dur=' + dur);
          }
          return;
        }
        if (rc !== 0 && nOut === 0) {
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=ReadMsgs n_in=' + this.nIn +
              ' n_out=0 timeout_ms=' + to + ' rc=' + rcHex + ' th=' + this.th + ' dur=' + dur);
          log('J2534 rx-error ch=' + this.ch + ' rc=' + rcHex + ' op=ReadMsgs');
          return;
        }
        if (nOut === 0) {
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=ReadMsgs n_in=' + this.nIn +
              ' n_out=0 timeout_ms=' + to + ' rc=0 th=' + this.th + ' dur=' + dur);
          return;
        }

        // rc != 0 при непустом n_out — частичный результат: контракт PassThru
        // допускает сообщения, уже снятые с очереди, вместе с кодом ошибки.
        const partial = rc !== 0;
        const emptyWithMsgs = (rc === 0x10 || rc === 0x11) && nOut > 0;
        if (partial) counters.partial_results += 1;
        if (emptyWithMsgs) {
          // «Пусто» с сообщениями — тоже нарушение контракта драйвера.
          counters.contract_violations += 1;
          log('J2534 msgs-empty-with-data ch=' + this.ch + ' call=' + this.call +
              ' n_out=' + nOut + ' rc=' + rcHex);
        }
        if (overflow) {
          counters.contract_violations += 1;
          log('J2534 msgs-overflow ch=' + this.ch + ' call=' + this.call + ' n_in=' + this.nIn +
              ' n_out=' + nOut + ' read=' + cap + ' rc=' + rcHex);
        }
        const contractTag = overflow
          ? ' contract=n_out_gt_n_in'
          : (emptyWithMsgs ? ' contract=empty_with_msgs' : '');
        if (abi.dec === 0 || this.pMsg.isNull()) {
          // ABI не подтверждён (05.00 или ambiguous): раскладку PASSTHRU_MSG не
          // угадываем — фиксируем факт вызова и счётчики, структуру не читаем.
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=ReadMsgs n_in=' + this.nIn +
              ' n_out=' + nOut + ' timeout_ms=' + to + ' rc=' + rcHex +
              (partial ? ' partial=1' : '') + contractTag +
              ' th=' + this.th + ' dur=' + dur + ' dec=0');
          return;
        }

        const recs = [];
        for (let i = 0; i < cap; i++) recs.push(ptRecord(this.pMsg, i));
        if (nOut > cap) {
          // Усечение именно по нашему пределу 256. n_out > n_in — не усечение,
          // а нарушение контракта: оно посчитано выше и не должно раздувать
          // `truncated_payloads` (иначе «усечений нет» не докажешь).
          if (cap >= 256) counters.truncated_payloads += 1;
          log('J2534 rx-truncated ch=' + this.ch + ' call=' + this.call + ' returned=' + nOut +
              ' logged=' + cap);
        }
        const single = (recs.length === 1 && !partial && !overflow);
        if (!single) {
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=ReadMsgs n_in=' + this.nIn +
              ' n_out=' + nOut + ' timeout_ms=' + to + ' rc=' + rcHex +
              (partial ? ' partial=1' : '') + contractTag +
              ' th=' + this.th + ' dur=' + dur);
        }
        for (let i = 0; i < recs.length; i++) {
          const r = recs[i];
          const isSof = (r.rxs & 0x02) !== 0;
          if (isSof) counters.rx_sof += 1;
          // Компактный режим: SOF построчно не пишется, только счётчик (§4).
          // Полезные данные SOF (len > 0) сохраняются и в компактном режиме —
          // отбрасывается только пустой статус.
          if (MODE === 'compact' && isSof && r.len === 0) continue;
          log(ptLine('RX', this.ch, r, {
            call: this.call, i: i + 1, n: recs.length, common: single,
            nIn: this.nIn, nOut: nOut, th: this.th, dur: dur, rc: rc,
            partial: partial, overflow: overflow
          }));
        }
      })
    });
    return;
  }

  if (name === 'PassThruWriteMsgs') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pMsg = args[1];
        this.pNum = args[2];
        this.nIn = u32(args[2]) >>> 0;
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        try { this.timeoutMs = args[3].toInt32(); } catch (e) { this.timeoutMs = 0; }
        chanTouch(load, this.ch, 'WriteMsgs');
        // Снимок ДО вызова: драйвер правит массив и *pNumMsgs на месте.
        this.recs = [];
        this.cap = 0;
        if (!this.pMsg.isNull() && abi.dec !== 0) {
          this.cap = Math.min(this.nIn, 256);
          for (let i = 0; i < this.cap; i++) this.recs.push(ptRecord(this.pMsg, i));
        }
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const dur = qpcUs(this.t0, qpcNow());
        const nOut = u32(this.pNum) >>> 0;   // сколько драйвер реально принял
        counters.calls += 1;
        const to = this.timeoutMs;
        if (this.nIn > this.cap && this.cap > 0) {
          counters.truncated_payloads += 1;
          log('J2534 tx-truncated ch=' + this.ch + ' queued=' + this.nIn + ' logged=' + this.cap);
        }
        if (rc !== 0) {
          txErr(load, this.ch, rc);
          log('J2534 tx-error ch=' + this.ch + ' rc=0x' + (rc >>> 0).toString(16) + ' op=WriteMsgs');
        }
        if (!this.recs.length) {
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=WriteMsgs n_in=' + this.nIn +
              ' n_out=' + nOut + ' timeout_ms=' + to + ' rc=' + rc + ' th=' + this.th + ' dur=' + dur +
              (abi.dec === 0 ? ' dec=0' : ''));
          return;
        }
        const single = (this.recs.length === 1 && this.nIn === 1);
        if (!single) {
          log('J2534 call ch=' + this.ch + ' call=' + this.call + ' op=WriteMsgs n_in=' + this.nIn +
              ' n_out=' + nOut + ' timeout_ms=' + to + ' rc=' + rc + ' th=' + this.th + ' dur=' + dur);
        }
        // Полнота TX: сохраняются ВСЕ n_in входных сообщений, n_out — ответ драйвера.
        for (let i = 0; i < this.recs.length; i++) {
          log(ptLine('TX', this.ch, this.recs[i], {
            call: this.call, i: i + 1, n: this.recs.length, common: single,
            nIn: this.nIn, nOut: nOut, th: this.th, dur: dur, rc: rc
          }));
        }
      })
    });
    return;
  }

  if (name === 'PassThruStartMsgFilter') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.type = args[1].toInt32();
        this.pMask = args[2];
        this.pPattern = args[3];
        this.pFlow = args[4];
        this.pId = args[5];
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'filter');
        this.mask = abi.dec ? filtMsg(this.pMask) : null;
        this.pat = abi.dec ? filtMsg(this.pPattern) : null;
        this.flow = (this.pFlow && !this.pFlow.isNull() && abi.dec) ? filtMsg(this.pFlow) : null;
      }),
      onLeave: leaveSafe(function (ret) {
        let s = 'J2534 filter ch=' + this.ch + ' call=' + this.call + ' type=' + hex4(this.type);
        const nm = PT_FILTER_NAMES[this.type];
        if (nm) s += ' (' + nm + ')';
        s += ' mask=' + (this.mask ? this.mask.hex : '-');
        s += ' pattern=' + (this.pat ? this.pat.hex : '-');
        s += ' flow=' + (this.flow ? this.flow.hex : '-');
        if (this.mask) s += ' mask_proto=' + hex4(this.mask.proto) + ' mask_flags=' + hexLow(this.mask.flags);
        if (this.pat) s += ' pattern_proto=' + hex4(this.pat.proto) + ' pattern_flags=' + hexLow(this.pat.flags);
        if (this.pat) s += ' proto=' + ptProtoName(this.pat.proto) + ' flags=' + hexLow(this.pat.flags);
        if (abi.dec === 0) s += ' dec=0';
        s += ' id=' + hexLow(u32(this.pId)) +
             ' rc=' + ret.toInt32() + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow());
        log(s);
      })
    });
    return;
  }

  if (name === 'PassThruStopMsgFilter') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pId = args[1];
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'filter-stop');
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 filter-stop ch=' + this.ch + ' call=' + this.call + ' id=' + hexLow(u32(this.pId)) +
            ' rc=' + ret.toInt32() + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
      })
    });
    return;
  }

  if (name === 'PassThruStartPeriodicMsg') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pMsg = args[1];
        this.pId = args[2];
        try { this.ms = args[3].toInt32(); } catch (e) { this.ms = 0; }
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'periodic');
        this.rec = (this.pMsg && !this.pMsg.isNull() && abi.dec) ? ptRecord(this.pMsg, 0) : null;
      }),
      onLeave: leaveSafe(function (ret) {
        let s = 'J2534 periodic-start ch=' + this.ch + ' call=' + this.call +
                ' id=' + hexLow(u32(this.pId)) + ' ms=' + this.ms;
        if (this.rec) {
          s += ' proto=' + ptProtoName(this.rec.proto) + ' flags=' + hexLow(this.rec.flags) +
               ' len=' + this.rec.len;
        }
        s += ' rc=' + ret.toInt32() + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow());
        if (this.rec && this.rec.len > 0) s += ' : ' + this.rec.hex;
        log(s);
      })
    });
    return;
  }

  if (name === 'PassThruStopPeriodicMsg') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.pId = args[1];
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'periodic-stop');
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 periodic-stop ch=' + this.ch + ' call=' + this.call + ' id=' + hexLow(u32(this.pId)) +
            ' rc=' + ret.toInt32() + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
      })
    });
    return;
  }

  if (name === 'PassThruIoctl') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.ch = args[0].toInt32();
        this.id = args[1].toInt32();
        this.pIn = args[2];
        this.pOut = args[3];
        this.call = ++CALL_SEQ;
        this.th = threadId();
        this.t0 = qpcNow();
        chanTouch(load, this.ch, 'ioctl');
        // Вход копируется ДО вызова: ioctl может менять буфер на месте.
        this.inStr = ioctlInput(this.id, this.pIn, abi);
        this.cfg = (this.id === 0x02 && this.pIn && !this.pIn.isNull()) ? ptConfigList(this.pIn) : null;
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const dur = qpcUs(this.t0, qpcNow());
        let s = 'J2534 ioctl ch=' + this.ch + ' call=' + this.call + ' id=' + hex4(this.id);
        const nm = PT_IOCTL_NAMES[this.id];
        if (nm) s += ' (' + nm + ')';
        s += ' rc=' + rc + ' th=' + this.th + ' dur=' + dur + ' ' + this.inStr +
             ' ' + ioctlOutput(this.id, this.pOut, abi);
        log(s);
        // SET_CONFIG: параметры списком (DATA_RATE, тайминги W1..W5, BS/STMIN).
        if (this.cfg) log('J2534 config ch=' + this.ch + ' ' + this.cfg + ' rc=' + rc);
      })
    });
    return;
  }

  if (name === 'PassThruClose') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.dev = args[0].toInt32();
        this.th = threadId();
        this.t0 = qpcNow();
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 close dev=' + this.dev + ' rc=' + ret.toInt32() +
            ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
        // PassThruClose закрывает ЭКЗЕМПЛЯР устройства, DLL остаётся загруженной:
        // хуки НЕ снимаем, иначе после Close → Open теряется вся следующая сессия.
        // Проверяем только реальную выгрузку модуля.
        const modName = mod.name;
        try {
          setTimeout(function () {
            try {
              if (!Process.findModuleByName(modName)) invalidateModule(modName);
              rescanDue = true;
            } catch (e) {}
          }, 250);
        } catch (e) {}
      })
    });
    return;
  }

  if (name === 'PassThruGetLastError') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.pText = args[0];
        this.th = threadId();
        this.t0 = qpcNow();
      }),
      onLeave: leaveSafe(function (ret) {
        log('J2534 error text="' + quote(str8(this.pText)) + '" rc=' + ret.toInt32() +
            ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
      })
    });
    return;
  }

  if (name === 'PassThruSetProgrammingVoltage') {
    // PassThruSetProgrammingVoltage(DeviceID, Pin, Voltage)
    // Voltage — это не только милливольты: 0xFFFFFFFF = OFF,
    // 0xFFFFFFFE = SHORT_TO_GROUND, 0xFFFFFFFD = SHORT_TO_VBAT.
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.dev = args[0].toInt32();
        this.pin = args[1].toInt32();
        this.mv = args[2];
        this.th = threadId();
        this.t0 = qpcNow();
      }),
      onLeave: leaveSafe(function (ret) {
        const raw = this.mv.toUInt32();
        const val = raw === 0xFFFFFFFF ? 'OFF'
          : raw === 0xFFFFFFFE ? 'SHORT_TO_GROUND'
            : raw === 0xFFFFFFFD ? 'SHORT_TO_VBAT' : raw + ' mV';
        log('J2534 voltage dev=' + this.dev + ' pin=' + this.pin + ' ' + val +
            ' rc=' + ret.toInt32() + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
      })
    });
    return;
  }

  if (name === 'PassThruReadVersion') {
    attachHook(addr, {
      onEnter: enterSafe(function (args) {
        this.pFw = args[1];
        this.pDll = args[2];
        this.pApi = args[3];
        this.th = threadId();
        this.t0 = qpcNow();
      }),
      onLeave: leaveSafe(function (ret) {
        const rc = ret.toInt32();
        const apiStr = str8(this.pApi);
        const dllStr = str8(this.pDll);
        log('J2534 version fw="' + quote(str8(this.pFw)) + '" dll="' + quote(dllStr) +
            '" api="' + quote(apiStr) + '" rc=' + rc +
            ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
        // Версия API — подтверждение ABI. От неё зависит, можно ли вообще
        // разбирать PASSTHRU_MSG: для 05.00 раскладка другая (dec=0).
        let api = '';
        if (/^0?5\./.test(apiStr)) api = '05.00';
        else if (/^0?4\./.test(apiStr)) api = '04.04';
        if (api) {
          const changed = (abi.api !== api) || (abi.ver !== dllStr);
          abi.api = api;
          abi.dec = api === '05.00' ? 0 : 1;
          abi.reason = '';
          abi.ver = dllStr;
          if (changed || !abi.logged) { abi.logged = true; emitApiLine(abi, mod); }
        } else if (!abi.logged) {
          abi.logged = true;
          abi.ver = dllStr;
          emitApiLine(abi, mod);
        }
      })
    });
    return;
  }

  // Неизвестный PassThru*-экспорт (PassThruSetConfig, PassThruLogicalConnect,
  // PassThruQueuedWriteMsgs, вендорные расширения): generic-трасса, чтобы
  // вызов не выпадал из лога — именно так пропадал PassThruConnect.
  attachHook(addr, {
    onEnter: enterSafe(function (args) {
      const parts = [];
      for (let i = 0; i < 6; i++) {
        let v = '?';
        try { v = '0x' + args[i].toUInt32().toString(16); } catch (e) { v = '?'; }
        parts.push(v);
      }
      this.argdump = parts.join(',');
      this.call = ++CALL_SEQ;
      this.th = threadId();
      this.t0 = qpcNow();
    }),
    onLeave: leaveSafe(function (ret) {
      log('J2534 ' + name + ' args=[' + this.argdump + '] rc=' + ret.toInt32() +
          ' call=' + this.call + ' th=' + this.th + ' dur=' + qpcUs(this.t0, qpcNow()));
    })
  });
}

function hookJ2534Module(mod) {
  if (PAUSED || !mod) return;
  const key = modKey(mod);
  if (j2534Hooked[key]) return;
  setOwner(key);
  const load = loadIdFor(mod);
  let total = 0, attached = 0, dup = 0, failed = 0;
  const names = [];
  // Хукаем КАЖДЫЙ экспорт `PassThru*`, а не фиксированный список: набор функций
  // у вендоров разный (Scanmatik/CHIPSOFT/Tactrix/VXDIAG/MDI), и пропущенная
  // функция = дырка в логе.
  let exports = [];
  try { exports = mod.enumerateExports(); } catch (e) { hookError('j2534 enumerateExports', e); }
  // Ограничение, которое здесь не обойти: Frida отдаёт только поименованные
  // функции, а J2534-2 (LogicalConnect/Select/QueueMsgs) у Scanmatik
  // экспортируется БЕЗ имени (ординалы 1377-1379 в smj2534.dll). Если
  // приложение пойдёт через них, строки в логе не будет — docs/12 §11.
  for (let i = 0; i < exports.length; i++) {
    const ex = exports[i];
    if (!ex || ex.type !== 'function' || !/^PassThru/i.test(ex.name)) continue;
    if (!ex.address) continue;
    total += 1;
    names.push(ex.name);
    const before = listeners.length;
    try {
      installJ2534Hook(ex.name, ex.address, mod, load);
    } catch (e) {
      hookError('j2534 ' + ex.name, e);
      failed += 1;
      continue;
    }
    // attached растёт ТОЛЬКО при реально установленном хуке (D1): attachHook
    // возвращает null на уже занятый адрес, поэтому считаем по listeners.
    if (listeners.length > before) attached += 1; else dup += 1;
  }
  j2534Hooked[key] = true;
  if (attached > 0) {
    j2534ModulesHooked++;
    log('J2534 module: ' + mod.name + ' ' + (mod.path || '') + ' base=' + mod.base + ' exports=' + attached);
    startIoStatsTimer();
  }
  // Диагностика установки: одна строка на модуль + список имён.
  log('# hooks mod="' + mod.name + '" base=' + mod.base + ' load=' + load +
      ' exports=' + total + ' attached=' + attached + ' dup=' + dup + ' failed=' + failed);
  if (names.length) log('# hooks-names mod="' + mod.name + '" names="' + names.join(',') + '"');
  const st = abiFor(load, mod.name);
  st.logged = true;
  emitApiLine(st, mod);
}

// ── LAN: Winsock (ws2_32) ──────────────────────────────────────────────────
// Сетевые адаптеры диагностики и всё, что ходит не через USB/COM:
// J2534-по-IP, DoIP (ISO 13400), BMW ICOM/HSFZ (порт 6801), любые TCP/UDP-обёртки.
//
// Формат строк (разбор — engine/src/decode.rs `parse_lan_line`):
//   LAN CONNECT tcp fd=0x1a4 local=192.168.1.5:50123 remote=192.168.1.10:13400 rc=0
//   LAN TX tcp local=192.168.1.5:50123 remote=192.168.1.10:13400 len=32 : 02 fd 80 01 …
//   LAN RX tcp local=192.168.1.10:13400 remote=192.168.1.5:50123 len=40 : …
//   LAN CLOSE tcp fd=0x1a4 local=… remote=… bytes=1234 reads=9 writes=7
//
// Блокирующий обмен пишем на выходе из вызова (там известен результат и реальное
// число байт), overlapped — по WSAGetOverlappedResult либо подметанием
// WSAOVERLAPPED.Internal (клиенты на APC/completion-routine, как .NET Socket).
const LAN_MODULE_RE = /^ws2_32\.dll$/i;
const LAN_SWEEP_MS = 200;
let lanHooked = false, lanSeen = false, lanPeerFn = null, lanLocalFn = null, lanSweepTimer = null;
let lanIdleClosed = 0;   // сокеты, закрытые без обмена: считаем, но не логируем построчно
let lanBogusCounts = 0;  // счётчики байт, которым нельзя верить (см. lanEmitBufs)
const lanSocks = {};   // fd -> { key, fd, l4, local, remote, bytesIn, bytesOut, reads, writes }
const lanOvl = {};     // "fd|overlapped" -> { ent, bufs, t, ovl }

function lanSaString(ptr) {
  try {
    if (!ptr || ptr.isNull()) return '';
    const fam = ptr.readU16();
    const port = (ptr.add(2).readU8() << 8) | ptr.add(3).readU8();
    if (fam === 2) {                       // AF_INET
      const b = new Uint8Array(ptr.add(4).readByteArray(4));
      return b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3] + ':' + port;
    }
    if (fam === 23) {                      // AF_INET6
      const b = new Uint8Array(ptr.add(8).readByteArray(16));
      const g = [];
      for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
      return '[' + g.join(':') + ']:' + port;
    }
    return '';
  } catch (e) { return ''; }
}

function lanSock(fd, l4) {
  const key = String(fd);
  let ent = lanSocks[key];
  if (!ent) {
    ent = { key: key, fd: fd, l4: l4 || 'tcp', local: '', remote: '',
      bytesIn: 0, bytesOut: 0, reads: 0, writes: 0 };
    lanSocks[key] = ent;
  } else if (l4) {
    ent.l4 = l4;
  }
  return ent;
}

// Локальный и удалённый адрес спрашиваем у самой winsock один раз на сокет:
// у приложения под рукой может не быть своих структур sockaddr (например,
// после connect через хелпер). Неудача не мешает логировать обмен.
function lanResolve(ent) {
  if (!ent || (ent.local && ent.remote)) return;
  try {
    const buf = Memory.alloc(128);
    const lenp = Memory.alloc(4);
    if (!ent.local && lanLocalFn) {
      lenp.writeS32(128);
      if (lanLocalFn(ent.fd, buf, lenp) === 0) ent.local = lanSaString(buf);
    }
    if (!ent.remote && lanPeerFn) {
      lenp.writeS32(128);
      if (lanPeerFn(ent.fd, buf, lenp) === 0) ent.remote = lanSaString(buf);
    }
  } catch (e) { /* сокет уже закрыт — не страшно */ }
}

function lanEmit(dir, ent, buf, len) {
  try {
    if (!ent || !buf || buf.isNull() || len <= 0) return;
    lanResolve(ent);
    if (dir === 'TX') { ent.bytesOut += len; ent.writes += 1; }
    else { ent.bytesIn += len; ent.reads += 1; }
    log('LAN ' + dir + ' ' + ent.l4 + ' local=' + (ent.local || '?') + ' remote=' + (ent.remote || '?') +
      ' len=' + len + ' : ' + hx(buf, len));
  } catch (e) { hookError('lan emit', e); }
}

// WSABUF: { ULONG len; CHAR *buf; } — на x86 8 байт, на x64 16 (выравнивание).
function lanBufs(arr, count) {
  const out = [];
  try {
    if (!arr || arr.isNull()) return out;
    const stride = Process.pointerSize === 8 ? 16 : 8;
    const boff = Process.pointerSize === 8 ? 8 : 4;
    const n = Math.min(count, 64);
    for (let i = 0; i < n; i++) {
      const p = arr.add(i * stride);
      out.push({ len: p.readU32(), buf: p.add(boff).readPointer() });
    }
  } catch (e) { hookError('lan bufs', e); }
  return out;
}

function lanEmitBufs(dir, ent, bufs, total) {
  // Счётчик от драйвера больше самого буфера — это не «принятые байты», а мусор
  // в OVERLAPPED.InternalHigh (операция завершилась ошибкой/отменой, а поле
  // осталось от прошлой передачи). В логе 20261119-181253 так «принялось»
  // 841 B неинициализированной памяти, из которых полезных было 2 байта — и
  // эти 841 B ушли в RX сессии. Лучше не записать событие, чем записать чужую
  // память под видом данных с шины.
  const cap = sumBufs(bufs);
  if (cap > 0 && total > cap) {
    lanBogusCounts++;
    if (lanBogusCounts === 1 || lanBogusCounts % 32 === 0) {
      log('LAN WARN ' + (ent ? ent.l4 : '?') + ' ' + dir + ' len=' + total + ' > буфер ' + cap +
        ' — не принятые байты (операция без успешного статуса), событие пропущено; всего таких ' +
        lanBogusCounts);
    }
    return;
  }
  let left = total;
  for (let i = 0; i < bufs.length && left > 0; i++) {
    const take = Math.min(left, bufs[i].len);
    lanEmit(dir, ent, bufs[i].buf, take);
    left -= take;
  }
}

// WSARecv с completion-routine вообще не доходит до WSAGetOverlappedResult:
// забираем результат из WSAOVERLAPPED (Internal/InternalHigh), как ovlSweep для COM.
function lanSweep() {
  if (PAUSED) return;
  try {
    const now = Date.now();
    const keys = Object.keys(lanOvl);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const e = lanOvl[key];
      if (!e) continue;
      if (ovlInternal({ ovl: e.ovl }) !== OVL_STATUS_PENDING) {
        // InternalHigh — счётчик байт только при успешном статусе. У отменённой
        // или упавшей операции там остаётся значение прошлой передачи, и именно
        // оттуда в лог ушли 841 B «RX» из чужой памяти.
        const status = ovlInternal({ ovl: e.ovl });
        const n = ovlInternalHigh({ ovl: e.ovl });
        delete lanOvl[key];
        const ok = typeof status === 'number' && (status & 0xC0000000) === 0;
        if (ok && n > 0) lanEmitBufs('RX', e.ent, e.bufs, n);
        continue;
      }
      if (now - e.t > 30000) delete lanOvl[key];
    }
    // Сокеты, открытые и закрытые без обмена (пробы сети, внутренний резолвер
    // приложения): построчно их не пишем, но счётчик показываем — иначе в логе
    // появлялся десяток `LAN CLOSE … local=? bytes=0`, по которым нечего делать.
    if (lanIdleClosed > 0) {
      log('LAN: закрыто ' + lanIdleClosed + ' сокетов без обмена (проба/резолвер) — построчно не пишем');
      lanIdleClosed = 0;
    }
  } catch (err) { hookError('lan sweep', err); }
}

function lanAttach(mod, name, handlers) {
  const addr = exportAddr(mod, name);
  if (!addr) return false;
  try { attachHook(addr, handlers); return true; } catch (e) { hookError('lan ' + name, e); return false; }
}

function hookLanModule(mod) {
  if (PAUSED || !mod || lanHooked) return;
  lanHooked = true;
  setOwner(modKey(mod));
  lanSeen = true;
  if (!lanPeerFn) {
    const p = exportAddr(mod, 'getpeername');
    if (p) { try { lanPeerFn = new NativeFunction(p, 'int', ['pointer', 'pointer', 'pointer']); } catch (e) {} }
  }
  if (!lanLocalFn) {
    const p = exportAddr(mod, 'getsockname');
    if (p) { try { lanLocalFn = new NativeFunction(p, 'int', ['pointer', 'pointer', 'pointer']); } catch (e) {} }
  }
  if (!lanSweepTimer) {
    try { lanSweepTimer = setInterval(lanSweep, LAN_SWEEP_MS); } catch (e) { lanSweepTimer = null; }
  }
  let n = 0;

  if (lanAttach(mod, 'socket', {
    onEnter: enterSafe(function (args) { this.type = args[1].toInt32(); }),
    onLeave: leaveSafe(function (ret) {
      if (ret.toInt32() === -1) return;
      lanSock(ret, this.type === 2 ? 'udp' : 'tcp');
    })
  })) n++;

  if (lanAttach(mod, 'connect', {
    onEnter: enterSafe(function (args) { this.ent = lanSock(args[0]); this.name = args[1]; }),
    onLeave: leaveSafe(function (ret) {
      const rc = ret.toInt32();
      const addr = lanSaString(this.name);
      if (addr) this.ent.remote = addr;
      lanResolve(this.ent);
      log('LAN CONNECT ' + this.ent.l4 + ' fd=' + this.ent.key + ' local=' + (this.ent.local || '?') +
        ' remote=' + (this.ent.remote || '?') + ' rc=' + rc);
    })
  })) n++;

  // WSASocketW/A не проходят через `socket` (сразу к провайдеру), поэтому сокеты,
  // созданные ими, раньше попадали в лог как `local=? remote=?`.
  for (const wsName of ['WSASocketW', 'WSASocketA']) {
    if (lanAttach(mod, wsName, {
      onEnter: enterSafe(function (args) { this.type = args[1].toInt32(); }),
      onLeave: leaveSafe(function (ret) {
        if (ret.toInt32() === -1) return;
        lanSock(ret, this.type === 2 ? 'udp' : 'tcp');
      })
    })) n++;
  }

  // WSAConnect — второй путь установки соединения (Delphi/Indy, часть SDK).
  if (lanAttach(mod, 'WSAConnect', {
    onEnter: enterSafe(function (args) { this.ent = lanSock(args[0]); this.name = args[1]; }),
    onLeave: leaveSafe(function (ret) {
      const rc = ret.toInt32();
      const addr = lanSaString(this.name);
      if (addr) this.ent.remote = addr;
      lanResolve(this.ent);
      log('LAN CONNECT ' + this.ent.l4 + ' fd=' + this.ent.key + ' local=' + (this.ent.local || '?') +
        ' remote=' + (this.ent.remote || '?') + ' rc=' + rc);
    })
  })) n++;

  if (lanAttach(mod, 'closesocket', {
    onEnter: enterSafe(function (args) {
      const ent = lanSocks[String(args[0])] || null;
      this.ent = ent;
      // Адреса спрашиваем ДО закрытия: после возврата closesocket fd уже невалиден.
      if (ent) lanResolve(ent);
    }),
    onLeave: leaveSafe(function (ret) {
      const ent = this.ent;
      if (!ent) return;
      delete lanSocks[ent.key];
      for (const k in lanOvl) {
        if (lanOvl[k] && lanOvl[k].ent === ent) delete lanOvl[k];
      }
      // Сокет без обмена и без адреса — это проба/резолвер, а не диагностика:
      // в лог такие закрытия не пишем (иначе десяток строк `local=? bytes=0`).
      if (!ent.remote && ent.bytesIn + ent.bytesOut === 0) {
        lanIdleClosed++;
        return;
      }
      log('LAN CLOSE ' + ent.l4 + ' fd=' + ent.key + ' local=' + (ent.local || '?') +
        ' remote=' + (ent.remote || '?') + ' bytes=' + (ent.bytesIn + ent.bytesOut) +
        ' reads=' + ent.reads + ' writes=' + ent.writes + ' rc=' + ret.toInt32());
    })
  })) n++;

  if (lanAttach(mod, 'send', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0]); this.buf = args[1]; this.len = args[2].toInt32();
    }),
    onLeave: leaveSafe(function (ret) {
      const sent = ret.toInt32();
      if (sent > 0) lanEmit('TX', this.ent, this.buf, sent);
    })
  })) n++;

  if (lanAttach(mod, 'recv', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0]); this.buf = args[1]; this.len = args[2].toInt32();
    }),
    onLeave: leaveSafe(function (ret) {
      const got = ret.toInt32();
      if (got > 0) lanEmit('RX', this.ent, this.buf, got);
    })
  })) n++;

  if (lanAttach(mod, 'sendto', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0], 'udp'); this.buf = args[1]; this.len = args[2].toInt32(); this.to = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      const sent = ret.toInt32();
      if (sent <= 0) return;
      const addr = lanSaString(this.to);
      if (addr) this.ent.remote = addr;
      lanEmit('TX', this.ent, this.buf, sent);
    })
  })) n++;

  if (lanAttach(mod, 'recvfrom', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0], 'udp'); this.buf = args[1]; this.pFrom = args[4];
    }),
    onLeave: leaveSafe(function (ret) {
      const got = ret.toInt32();
      if (got <= 0) return;
      const addr = lanSaString(this.pFrom);
      if (addr) this.ent.remote = addr;
      lanEmit('RX', this.ent, this.buf, got);
    })
  })) n++;

  // WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
  if (lanAttach(mod, 'WSASend', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0]);
      this.bufs = lanBufs(args[1], args[2].toInt32());
      this.pLen = args[3];
      this.ovl = args[5];
    }),
    onLeave: leaveSafe(function (ret) {
      const rc = ret.toInt32();
      if (rc === 0) {
        const sent = u32(this.pLen) || sumBufs(this.bufs);
        lanEmitBufs('TX', this.ent, this.bufs, sent);
        return;
      }
      if (this.ovl && !this.ovl.isNull()) return;   // WSA_IO_PENDING — штатно
      log('LAN ERR ' + (this.ent ? this.ent.l4 : 'tcp') + ' fd=' + (this.ent ? this.ent.key : '?') +
        ' op=WSASend rc=' + rc);
    })
  })) n++;

  // WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)
  if (lanAttach(mod, 'WSARecv', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0]);
      this.bufs = lanBufs(args[1], args[2].toInt32());
      this.pLen = args[3];
      this.ovl = args[5];
    }),
    onLeave: leaveSafe(function (ret) {
      const rc = ret.toInt32();
      const key = this.ent.key + '|' + String(this.ovl);
      if (rc === 0) {
        const got = u32(this.pLen);
        if (got > 0) lanEmitBufs('RX', this.ent, this.bufs, got);
        return;
      }
      if (this.ovl && !this.ovl.isNull()) {
        lanOvl[key] = { ent: this.ent, bufs: this.bufs, ovl: this.ovl, t: Date.now() };
        return;
      }
      log('LAN ERR ' + this.ent.l4 + ' fd=' + this.ent.key + ' op=WSARecv rc=' + rc);
    })
  })) n++;

  // WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags,
  //             lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine)
  if (lanAttach(mod, 'WSARecvFrom', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0], 'udp');
      this.bufs = lanBufs(args[1], args[2].toInt32());
      this.pLen = args[3];
      this.pFrom = args[5];
      this.ovl = args[7];
    }),
    onLeave: leaveSafe(function (ret) {
      const rc = ret.toInt32();
      const key = this.ent.key + '|' + String(this.ovl);
      if (rc === 0) {
        const got = u32(this.pLen);
        const addr = lanSaString(this.pFrom);
        if (addr) this.ent.remote = addr;
        if (got > 0) lanEmitBufs('RX', this.ent, this.bufs, got);
        return;
      }
      if (this.ovl && !this.ovl.isNull()) {
        lanOvl[key] = { ent: this.ent, bufs: this.bufs, ovl: this.ovl, t: Date.now() };
        return;
      }
      log('LAN ERR ' + this.ent.l4 + ' fd=' + this.ent.key + ' op=WSARecvFrom rc=' + rc);
    })
  })) n++;

  // Завершение overlapped-приёма: WSAGetOverlappedResult(s, ovl, lpcbTransfer, fWait, lpdwFlags)
  if (lanAttach(mod, 'WSAGetOverlappedResult', {
    onEnter: enterSafe(function (args) {
      this.ent = lanSock(args[0]); this.ovl = args[1]; this.pLen = args[2];
    }),
    onLeave: leaveSafe(function (ret) {
      if (ret.toInt32() === 0) return;
      const key = this.ent.key + '|' + String(this.ovl);
      const e = lanOvl[key];
      if (!e) return;
      delete lanOvl[key];
      // Только `*lpcbTransfer`: winsock заполняет его при успехе. Фолбэк на
      // InternalHigh давал «байты» из старого OVERLAPPED (см. lanEmitBufs).
      const got = u32(this.pLen);
      if (got > 0) lanEmitBufs('RX', e.ent, e.bufs, got);
    })
  })) n++;

  log('LAN module: ' + mod.name + ' ' + (mod.path || '') + ' hooks=' + n);
}

function sumBufs(bufs) {
  let s = 0;
  for (let i = 0; i < bufs.length; i++) s += bufs[i].len;
  return s;
}

// ── WinUSB (winusb.dll) ────────────────────────────────────────────────────
function hookWinUsbModule(mod) {
  if (PAUSED || !mod || winusbHooked) return;
  winusbHooked = true;
  setOwner(modKey(mod));
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
  setOwner(modKey(mod));
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
  setOwner(modKey(mod));
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
  // Крупный bulk-пакет (4 МБ флеша читаются кусками по 64 КБ) режем на части:
  // одна строка = не больше MAXDUMP байт, иначе хвост молча терялся.
  let parts = Math.ceil(len / MAXDUMP);
  if (parts < 1) parts = 1;
  if (parts > 64) parts = 64;                 // предохранитель от мусорного len
  for (let i = 0; i < parts; i++) {
    const off = i * MAXDUMP;
    const take = Math.min(len - off, MAXDUMP);
    if (take <= 0) break;
    const hex = hx(buf.add(off), take);
    const suffix = parts > 1 ? (' part=' + (i + 1) + '/' + parts) : '';
    if (kind === 'hid') log('HID ' + dir + ' report=' + hex2(reportFirst ? u8(buf.add(off)) : 0) + ' len=' + take + suffix + ' : ' + hex);
    else if (kind === 'winusb') log('WINUSB ' + dir + ' len=' + take + suffix + ' : ' + hex);
    else log('USB ' + dir + ' len=' + take + suffix + ' : ' + hex);
  }
}
function installUsbPathHooks() {
  setOwner('');
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
      // CreateFileA вызывает CreateFileW: одну и ту же ручку логируем один раз.
      if (usbHandles[key] && usbHandles[key].path === this.path) return;
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
      if (usbHandles[key] && usbHandles[key].path === this.path) return;
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
      log('USB close path="' + quote(ent.path) + '" bytes=' + ent.bytes + ' writes=' + ent.writes +
        ' reads=' + (ent.reads || 0) + (ent.ioctls ? ' ioctls=' + ent.ioctls : ''));
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
      this.outBuf = args[4];
      this.outLen = args[5].toInt32();
      this.pBytes = args[6];
    }),
    onLeave: leaveSafe(function (ret) {
      if (!this.ent) return;
      const rc = ret.toInt32();
      const n = u32(this.pBytes);
      const outLen = n > 0 ? n : this.outLen;
      // Драйверный обмен идёт ЧЕРЕЗ DeviceIoControl, а не ReadFile/WriteFile:
      // без этого `USB close` показывал bytes=0 при реальном трафике (лог PCMflash).
      this.ent.bytes += this.inLen + (rc !== 0 ? outLen : 0);
      this.ent.ioctls = (this.ent.ioctls || 0) + 1;
      const prefix = this.ent.kind === 'hid' ? 'HID' : (this.ent.kind === 'winusb' ? 'WINUSB' : 'USB');
      log(prefix + ' ioctl code=' + hexLow(this.code) + ' rc=' + rc +
          ' in=' + this.inLen + ' out=' + outLen + ' : ' + hx(this.inBuf, this.inLen));
      // Ioctl совсем без входного буфера — это чистое чтение из драйвера: ответ
      // лежит в out, и без него такой обмен в логе выглядит пустым.
      if (this.inLen === 0 && outLen > 0 && rc !== 0) {
        log(prefix + ' RX ioctl code=' + hexLow(this.code) + ' len=' + outLen + ' : ' +
            hx(this.outBuf, outLen));
      }
    })
  });
}

// ── установка/пауза ────────────────────────────────────────────────────────
// ── перезагрузка модулей (FreeLibrary → LoadLibrary по тому же base) ───────
// PCMflash закрывает устройство после своей операции: PassThruClose →
// FreeLibrary(smj2534.dll), а для следующего действия загружает DLL заново —
// как правило по тому же base. Вместе с кодом DLL исчезают и наши патчи, а
// ключ `j2534Hooked["smj2534.dll|0x…"]` оставался, поэтому повторный dispatch
// ранне выходил: второй шаг («Чтение фулл флеш») писал в лог НОЛЬ строк.
// Теперь выгрузка снимает хуки и освобождает адреса, а загрузка — перевешивает.
const CAPTURE_MODULE_RE = /(j2534|passthru|pass-thru|ptshim|op20pt|smj2534|vcxpt|evcucm|ucdsj2534|tactrix|scanmatik|chipsoft|^winusb\.dll$|^hid\.dll$|^libusb-1\.0|^ftd2xx\.dll$)/i;

function moduleBaseName(path) {
  const s = String(path || '');
  const i = Math.max(s.lastIndexOf('\\'), s.lastIndexOf('/'));
  return (i >= 0 ? s.slice(i + 1) : s).toLowerCase();
}

// Забыть всё, что мы знали о модуле с таким именем (при любом base): и флаги
// «уже хукали», и сами listeners. Адреса освобождаются — иначе attachHook
// откажется ставить хуки на тот же адрес после перезагрузки.
function invalidateModule(name) {
  const lower = String(name || '').toLowerCase();
  if (!lower) return 0;
  let flags = 0;
  // Реальная выгрузка: следующая загрузка этого имени — новая (новый load id).
  try { delete modLoads[lower]; } catch (e) {}
  const keys = Object.keys(j2534Hooked);
  for (let i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase().indexOf(lower + '|') === 0) { delete j2534Hooked[keys[i]]; flags++; }
  }
  if (lower === 'ftd2xx.dll') {
    for (const k in hooked) delete hooked[k];
    ftMod = null;
  }
  if (lower === 'winusb.dll') { winusbHooked = false; winusbSeen = false; }
  if (lower === 'hid.dll') { hidHooked = false; hidSeen = false; }
  if (lower.indexOf('libusb-1.0') === 0) { libusbHooked = false; libusbSeen = false; }

  let n = 0;
  for (let i = listeners.length - 1; i >= 0; i--) {
    const own = String(listeners[i].owner || '').toLowerCase();
    if (own.indexOf(lower + '|') !== 0) continue;
    try { listeners[i].l.detach(); } catch (err) {}
    hookedAddrs.delete(listeners[i].addr);
    listeners.splice(i, 1);
    n++;
  }
  if (n > 0 || flags > 0) {
    log('MODULE ~ ' + name + ' выгружена/перезагружена — снято хуков ' + n +
        (flags ? ', флагов ' + flags : '') + '; перевесим при загрузке');
  }
  return n;
}

// onRemoved от Frida: чистим сразу, а перевесит обычный dispatch по onAdded.
function onModuleUnloaded(mod) {
  if (PAUSED || !mod || !mod.name) return;
  try { invalidateModule(mod.name); } catch (e) { hookError('module unload', e); }
}

// Страховка, если onRemoved не пришёл: слушаем сам загрузчик. Любая загрузка
// DLL с «нашим» именем → забыть старые хуки и пересканировать модули.
let dllLoadWatched = false;
let rescanDue = false;
let rescanTimer = null;

function univRescan() {
  if (PAUSED || !rescanDue) return;
  rescanDue = false;
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) dispatchUniversalModule(mods[i]);
  } catch (e) { hookError('rescan', e); }
}

function hookDllLoadWatch() {
  if (dllLoadWatched) return;
  const k32 = Process.findModuleByName('kernel32.dll');
  if (!k32) return;
  dllLoadWatched = true;
  setOwner('');
  const wide = ['LoadLibraryW', 'LoadLibraryExW'];
  const ansi = ['LoadLibraryA', 'LoadLibraryExA'];
  let n = 0;
  function wrap(name, isWide) {
    const addr = exportAddr(k32, name);
    if (!addr) return;
    try {
      attachHook(addr, {
        // Чистим ДО того, как модуль появится: наблюдатель Frida вызовет onAdded
        // прямо внутри LoadLibrary, повесит хуки, и снимать их уже нельзя.
        // Если же DLL сейчас нет в адресном пространстве — это и есть повторная
        // загрузка после выгрузки, и старый ключ «модуль|base» надо забыть.
        onEnter: enterSafe(function (args) {
          const path = isWide ? str16(args[0]) : str8(args[0]);
          const base = moduleBaseName(path);
          if (!base || !CAPTURE_MODULE_RE.test(base)) return;
          let loaded = null;
          try { loaded = Process.findModuleByName(base); } catch (e) {}
          if (!loaded) invalidateModule(base);
          rescanDue = true;
        })
      });
      n++;
    } catch (e) { hookError('loadwatch ' + name, e); }
  }
  for (let i = 0; i < wide.length; i++) wrap(wide[i], true);
  for (let i = 0; i < ansi.length; i++) wrap(ansi[i], false);
  if (!rescanTimer && n > 0) {
    try { rescanTimer = setInterval(univRescan, 200); } catch (e) { rescanTimer = null; }
  }
  if (n > 0) log('universal: сторож загрузки DLL активен (' + n + ' хуков) — перезагрузка адаптерных DLL не теряется');
}

// ── J2534-прокси: не хукать «внутренний» драйвер ───────────────────────────
// Когда приложение грузит наш j2534proxy.dll, прокси сама подгружает настоящий
// драйвер, и в процессе оказываются ДВА J2534-модуля. Хук на обоих писал бы
// каждый кадр дважды — TX на входе в прокси и ещё раз на входе в драйвер, —
// и счётчики сессии удваивались бы. Поэтому всё, что загружено «внутрь»
// прокси, не хукаем: эту полосу пишет сама DLL (docs/13-j2534-proxy.md §6).
const PROXY_MODULE_RE = /^j2534proxy\.dll$/i;
let proxySkipNoted = {};
let proxyActiveSeen = false;

function proxyModulePath() {
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      if (PROXY_MODULE_RE.test(mods[i].name)) return String(mods[i].path || mods[i].name);
    }
  } catch (e) { hookError('proxyModulePath', e); }
  return null;
}

// Прокси считается работающей, только если она реально начала форвардить:
// при инициализации (до LoadLibrary настоящего драйвера) она создаёт именованный
// мьютекс Local\FTDI_J2534_PROXY_<pid>. Просто «модуль загружен» — не признак:
// некоторые инструменты грузят все зарегистрированные J2534-DLL для перебора,
// и по одному лишь факту загрузки мы бы зря перестали хукать рабочий драйвер.
function proxyActiveInProcess() {
  if (proxyActiveSeen) return true;
  try {
    const k32 = Process.findModuleByName('kernel32.dll');
    const addr = k32 ? exportAddr(k32, 'OpenMutexA') : null;
    if (!addr) return false;
    const openMutex = new NativeFunction(addr, 'pointer', ['uint32', 'int', 'pointer']);
    const name = Memory.allocUtf8String('Local\\FTDI_J2534_PROXY_' + Process.id);
    const sync = 0x00100000; // SYNCHRONIZE
    const h = openMutex(sync, 0, name);
    if (!h.isNull()) { proxyActiveSeen = true; return true; }
  } catch (e) { hookError('proxyActiveInProcess', e); }
  return false;
}

function isProxyInner(mod) {
  if (!proxyActiveInProcess()) return false;
  const proxy = proxyModulePath();
  if (!proxy) return false;
  const path = String((mod && mod.path) || '');
  if (!path) return false;
  return path.toLowerCase() !== proxy.toLowerCase();
}

function dispatchUniversalModule(mod) {
  if (!mod || !mod.name) return;
  try {
    if (/^ftd2xx\.dll$/i.test(mod.name)) { if (!ftMod) hookFtModule(mod); }
    else if (J2534_MODULE_RE.test(mod.name)) {
      // Прокси в процессе? Значит настоящий драйвер загружен ею — см. выше.
      if (isProxyInner(mod)) {
        const key = String(mod.path || mod.name).toLowerCase();
        if (!proxySkipNoted[key]) {
          proxySkipNoted[key] = true;
          log('# hooks mod="' + mod.name + '" skip=proxy-inner path="' + (mod.path || '') + '"');
        }
      } else {
        hookJ2534Module(mod);
      }
    }
    else if (LAN_MODULE_RE.test(mod.name)) hookLanModule(mod);
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
          },
          onRemoved: function (mod) { onModuleUnloaded(mod); }
        });
        log('universal: module observer armed (J2534/WinUSB/HID/libusb)');
      } else {
        log('universal: module observer НЕДОСТУПЕН (Frida без attachModuleObserver) — только уже загруженные модули');
      }
    } catch (e) { hookError('module observer', e); }
  }
  hookDllLoadWatch();
  log('universal hooks: ftdi2xx=' + (ftMod ? 1 : 0) + ' j2534=' + j2534ModulesHooked +
      ' lan=' + (lanSeen ? 1 : 0) +
      ' winusb=' + (winusbSeen ? 1 : 0) + ' hid=' + (hidSeen ? 1 : 0) + ' libusb=' + (libusbSeen ? 1 : 0) +
      ' usb_paths=' + Object.keys(usbHandles).length + ' listeners=' + listeners.length);
}

// После паузы все Interceptor-хуки сняты: сбрасываем флаги и ставим заново.
function resumeUniversalHooks() {
  j2534Hooked = {};
  dllLoadWatched = false;   // после паузы сторож загрузки ставится заново
  rescanDue = true;
  j2534ModulesHooked = 0;
  lanHooked = false; lanPeerFn = null; lanLocalFn = null;
  winusbHooked = false; hidHooked = false; libusbHooked = false; usbPathHooked = false;
  installUniversalHooks();
}

function universalStatus() {
  let ftdi = false;
  try { ftdi = !!(ftMod || Object.keys(hooked).length > 0); } catch (e) { ftdi = false; }
  return {
    ftdi: ftdi,
    j2534: j2534ModulesHooked > 0,
    lan: lanSeen,
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
    try {
      const st = universalStatus();
      st.mode = MODE;
      return st;
    } catch (e) { return { error: String(e) }; }
  },
  // Счётчики потерь: движок дописывает их в `# counters` при остановке сессии
  // (docs/09 §4). Неполный лог нельзя выдавать за полный.
  counters: function () {
    try { flushIoStats(); } catch (e) {}
    return {
      mode: MODE,
      calls: counters.calls,
      rx_sof: counters.rx_sof,
      truncated_payloads: counters.truncated_payloads,
      decode_errors: counters.decode_errors,
      dropped_events: counters.dropped_events,
      file_reads: counters.file_reads,
      partial_results: counters.partial_results,
      contract_violations: counters.contract_violations,
      xdi_events: counters.xdi_events
    };
  },
  ping: function () {
    return 'pong';
  }
};

log('capture script loaded: pid=' + Process.id + ' arch=' + Process.arch + ' modules=' + Process.enumerateModules().length + ' wall=' + new Date().toISOString());












