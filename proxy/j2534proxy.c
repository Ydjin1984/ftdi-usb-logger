/*
 * j2534proxy.c -- J2534 (Pass-Thru 04.04) logging proxy for FTDI/USB Logger.
 *
 * Contract: docs/13-j2534-proxy.md (sections 3, 4, 6, 7, 11, 12).
 *
 * The proxy sits between a J2534 application (PCMflash etc.) and the real
 * driver (Scanmatik smj2534.dll, CHIPSOFT, OpenPort, VXDIAG, ...).  It is
 * registered as a *separate* PassThru device, forwards every call unchanged
 * and writes its own journal, so the capture lives outside the application
 * process and survives an agent crash.
 *
 * Journal: <LogDir>\proxy-YYYYMMDD-HHMMSS-pid<PID>.log, created on the first
 * call, appended, flushed after every line (FlushFileBuffers), so the file is
 * alive when the application dies.  The line grammar is the same as the Frida
 * agent's (docs/11), therefore the engine can merge both lanes and cross-check
 * frames with decode::parse_capture_line.
 *
 * Build: proxy\build.ps1 -- x86 for the product, x64 for the smoke test.
 *
 * Dependencies: kernel32 only.  The C runtime is linked statically (/MT), so
 * the import table of the delivered DLL contains KERNEL32.dll and nothing else.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <intrin.h>   /* _ReturnAddress(): кто вызвал вендорский ординал */

typedef unsigned long ulong;   /* J2534 04.04: 4 bytes on x86 and on x64 (LLP64) */
typedef unsigned char u8;
typedef unsigned int  u32;   /* 32-bit on x86 and x64: J2534 structures are LP64-agnostic */

/* ------------------------------------------------------------------ */
/* versions                                                            */
/* ------------------------------------------------------------------ */

/* Kept in sync with proxy\version.rc; the proxy reports it in the header
 * without pulling in version.dll (that would be a second dependency). */
#define PROXY_VERSION "1.0.0.123"
#define PROXY_API     "04.04"
#define PROXY_MAX_DATA 4128

/* ------------------------------------------------------------------ */
/* J2534 data types                                                    */
/* ------------------------------------------------------------------ */

typedef struct _PASSTHRU_MSG {
    ulong ProtocolID;
    ulong RxStatus;
    ulong TxFlags;
    ulong Timestamp;
    ulong DataSize;
    ulong ExtraDataIndex;
    u8    Data[PROXY_MAX_DATA];
} PASSTHRU_MSG;

typedef struct _SCONFIG {
    ulong Parameter;
    ulong Value;
} SCONFIG;

typedef struct _SCONFIG_LIST {
    ulong    NumOfParams;
    SCONFIG *ConfigPtr;
} SCONFIG_LIST;

#define STATUS_NOERROR            0x00UL
#define ERR_NOT_SUPPORTED         0x01UL
#define ERR_INVALID_CHANNEL_ID    0x02UL
#define ERR_INVALID_PROTOCOL_ID   0x03UL
#define ERR_NULL_PARAMETER        0x04UL
#define ERR_INVALID_IOCTL_VALUE   0x05UL
#define ERR_INVALID_FLAGS         0x06UL
#define ERR_FAILED                0x07UL
#define ERR_DEVICE_NOT_CONNECTED  0x08UL
#define ERR_TIMEOUT               0x09UL
#define ERR_BUFFER_EMPTY          0x10UL

/* ------------------------------------------------------------------ */
/* real driver entry points                                            */
/* ------------------------------------------------------------------ */

typedef ulong (WINAPI *PFN_OPEN)(void *, ulong *);
typedef ulong (WINAPI *PFN_CLOSE)(ulong);
typedef ulong (WINAPI *PFN_CONNECT)(ulong, ulong, ulong, ulong, ulong *);
typedef ulong (WINAPI *PFN_DISCONNECT)(ulong);
typedef ulong (WINAPI *PFN_READMSGS)(ulong, PASSTHRU_MSG *, ulong *, ulong);
typedef ulong (WINAPI *PFN_WRITEMSGS)(ulong, PASSTHRU_MSG *, ulong *, ulong);
typedef ulong (WINAPI *PFN_STARTPERIODIC)(ulong, PASSTHRU_MSG *, ulong *, ulong);
typedef ulong (WINAPI *PFN_STOPPERIODIC)(ulong, ulong);
typedef ulong (WINAPI *PFN_STARTFILTER)(ulong, ulong, PASSTHRU_MSG *, PASSTHRU_MSG *,
                                        PASSTHRU_MSG *, ulong *);
typedef ulong (WINAPI *PFN_STOPFILTER)(ulong, ulong);
typedef ulong (WINAPI *PFN_SETVOLTAGE)(ulong, ulong, ulong);
typedef ulong (WINAPI *PFN_READVERSION)(ulong, char *, char *, char *);
typedef ulong (WINAPI *PFN_GETLASTERROR)(char *);
typedef ulong (WINAPI *PFN_IOCTL)(ulong, ulong, void *, void *);

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

/* EnsureInit() is a three-state gate: 0 = fresh, 1 = initialising,
 * 2 = ready.  Only the winner initialises; everybody else waits for 2.
 * That keeps the single LoadLibraryA() of the real driver race-free without
 * touching an uninitialised CRITICAL_SECTION. */
#define INIT_NONE     0
#define INIT_BUSY     1
#define INIT_READY    2

static CRITICAL_SECTION g_cs;
static volatile LONG    g_state = INIT_NONE;

static HANDLE           g_hLog  = INVALID_HANDLE_VALUE;
static HANDLE           g_mutex = NULL;          /* Local\FTDI_J2534_PROXY_<pid> */
static HINSTANCE        g_hinst = NULL;
static HMODULE          g_real  = NULL;

static LONGLONG         g_qpf  = 1;
static LONGLONG         g_qpc0 = 0;

static volatile LONG    g_calls  = 0;            /* every API call, from 1 */
static volatile LONG    g_tx     = 0;            /* TX frames journalled */
static volatile LONG    g_rx     = 0;            /* RX frames journalled */
static volatile LONG    g_errors = 0;            /* calls that returned rc != 0 */
/* Security access (docs/16 §5): counts are written to the live state file so the
 * engine can tell from `proxy-live-<pid>.state` whether the session reached a
 * key, without parsing the journal.  g_key_pending is the key sent since the
 * last seed; ACCESS OK turns it into a confirmed pair. */
static volatile LONG    g_pairs  = 0;            /* seed→key pairs confirmed by 67 xx */
static volatile LONG    g_seed   = 0;            /* seeds received (67 7F / 67 01) */
static volatile LONG    g_key    = 0;            /* keys sent (27 80 / 27 02) */
static volatile LONG    g_denied = 0;            /* 7F 27 responses */
static volatile LONG    g_key_pending = 0;
static volatile LONG    g_gen    = 0;            /* successful Connect counter */

static int              g_enabled = 1;           /* [proxy] Enabled / FTDI_J2534_PROXY_OFF */
static int              g_fatal   = 0;           /* real driver unusable -> all calls 0x08 */
static int              g_bits    = 32;
static ulong            g_maxData = PROXY_MAX_DATA;

static char             g_dll[MAX_PATH];         /* full path of this DLL */
static char             g_dllName[MAX_PATH];     /* j2534proxy.dll */
static char             g_ini[MAX_PATH];         /* j2534proxy.ini next to the DLL */
static char             g_realPath[MAX_PATH];    /* the driver we forward to */
static char             g_logDir[MAX_PATH];      /* [proxy] LogDir */
static char             g_logExact[MAX_PATH];    /* FTDI_J2534_PROXY_LOG */
static char             g_devName[MAX_PATH];     /* [device] Name */
static char             g_devVendor[MAX_PATH];   /* [device] Vendor */

/* Live state for the GUI (docs/13 section 6).  The journal answers "what was
 * the exchange", this file answers "is the proxy loaded right now, in which
 * process, and how much has it seen" -- without the user reading logs or
 * running a single command.  It sits next to the journal, never instead of it. */
static char             g_logPath[MAX_PATH];     /* the journal we actually write */
static char             g_started[64];           /* wall(start), same value as the header */

static PFN_OPEN          pOpen;
static PFN_CLOSE         pClose;
static PFN_CONNECT       pConnect;
static PFN_DISCONNECT    pDisconnect;
static PFN_READMSGS      pReadMsgs;
static PFN_WRITEMSGS     pWriteMsgs;
static PFN_STARTPERIODIC pStartPeriodic;
static PFN_STOPPERIODIC  pStopPeriodic;
static PFN_STARTFILTER   pStartFilter;
static PFN_STOPFILTER    pStopFilter;
static PFN_SETVOLTAGE    pSetVoltage;
static PFN_READVERSION   pReadVersion;
static PFN_GETLASTERROR  pGetLastError;
static PFN_IOCTL         pIoctl;

/* Big scratch buffers: a full 4128-byte frame needs 12383 characters of hex.
 * All users run under g_cs, so a single instance is enough. */
static char g_hex[PROXY_MAX_DATA * 3 + 16];

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void SetStr(char *dst, DWORD cap, const char *src)
{
    if (!dst || cap == 0) return;
    if (!src) src = "";
    lstrcpynA(dst, src, (int)cap);
    dst[cap - 1] = 0;
}

static void TrimA(char *s)
{
    char  *p = s;
    size_t len;

    if (!s) return;
    while (*p == ' ' || *p == '\t') ++p;
    if (p != s) memmove(s, p, strlen(p) + 1);

    len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') s[--len] = 0;
        else break;
    }
}

/* Раскрыть %VAR% в пути из ini.
 *
 * GetPrivateProfileStringA переменные окружения НЕ раскрывает. Движок пишет
 * `LogDir=%LOCALAPPDATA%\FTDI_USB_Logger\j2534proxy`, и без этого шага прокси
 * создавала каталог с буквальным именем `%LOCALAPPDATA%` относительно рабочего
 * каталога приложения (у PCMflash это `C:\Users\User\Documents`), а движок искал
 * журнал в настоящем LogDir и писал «журналов нет», хотя прокси работала
 * (docs/13 §4). Поэтому любое значение пути из ini проходит через это. */
static void ExpandPath(char *path, DWORD cap)
{
    char  tmp[MAX_PATH];
    DWORD n;

    if (!path || !path[0]) return;
    if (!strchr(path, '%')) return;
    n = ExpandEnvironmentStringsA(path, tmp, MAX_PATH);
    if (n > 0 && n <= MAX_PATH) SetStr(path, cap, tmp);
}

/* ------------------------------------------------------------------ */
/* [log]: пределы дампов и разбор вендорских аргументов                */
/*                                                                     */
/* Живой разбор 1377 (BitBox, 20.11.2026): op=0x0B настраивает GPT,     */
/* op=0x00 — общий вызов; параметры лежат в блоке по *(arg+8) как      */
/* [count][ptr][tag,value]…, пара — два u32 ПО ЗНАЧЕНИЮ. Теги           */
/* 0x1AA8C7xx — непрозрачные константы, не указатели: разыменование    */
/* даёт ERROR_PARTIAL_COPY (299) даже в момент вызова.                 */
/* ------------------------------------------------------------------ */

static int  g_logArgs = 1;
static int  g_vendorArgBytes = 512;
static int  g_vendorBeforeBytes = 32;
static int  g_vendorParamPairs = 1;
static int  g_maxParamPairs = 16;
static int  g_maxDumpPerCall = 4096;
/* Белый список op для полного дампа: остальные — одной короткой строкой,
 * иначе сессия чтения (33 187 вызовов) распухает с 12 МБ до сотен. */
static int  g_vendorFullOp[8] = { 0x0b, 0x00 };
static int  g_vendorFullOpN = 2;
/* Какие ординалы вообще разбирать: остальные — короткой строкой. */
static int  g_vendorOrds[8] = { 1377, 1378, 1379 };
static int  g_vendorOrdN = 3;

static int ClampInt(int value, int lo, int hi)
{
    if (value < lo) return lo;
    if (value > hi) return hi;
    return value;
}

/* "0x0b,0x00" / "1377,1378" -> массив чисел. Пустая строка — не ошибка:
 * тогда остаётся значение по умолчанию. */
static void ParseNumList(const char *text, int *dst, int cap, int *count)
{
    const char *p = text;
    int n = 0;

    if (!text || !dst || !count) return;
    while (*p && n < cap) {
        char *end = NULL;
        unsigned long v;
        while (*p == ' ' || *p == '\t' || *p == ',') ++p;
        if (!*p) break;
        v = strtoul(p, &end, 0);
        if (end == p) break;
        dst[n++] = (int)v;
        p = end;
    }
    if (n > 0) *count = n;
}

static int AppendFmt(char *dst, int cap, int used, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (used < 0) used = 0;
    if (used >= cap - 1) return cap - 1;
    va_start(ap, fmt);
    n = _vsnprintf(dst + used, (size_t)(cap - used), fmt, ap);
    va_end(ap);
    if (n < 0) return cap - 1;
    used += n;
    if (used >= cap) used = cap - 1;
    dst[used] = 0;
    return used;
}

/* Чтение чужой/своей памяти — только после VirtualQuery: MEM_COMMIT, без
 * PAGE_NOACCESS и PAGE_GUARD, весь диапазон внутри одного региона. Ошибка
 * чтения не роняет процесс: вызывающий пишет <unreadable> (docs/13 §6.3). */
static int SafeRead(const void *p, void *dst, SIZE_T n)
{
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t start, end, region_end;

    if (!p || !dst || n == 0) return 0;
    start = (uintptr_t)p;
    end = start + n;
    if (end < start) return 0;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    if (end > region_end) return 0;
    return ReadProcessMemory(GetCurrentProcess(), p, dst, n, NULL) != 0;
}

/* hexdump в строку: `00112233` — без пробелов, чтобы не рвать длинную строку
 * и не тратить её длину (движок разбирает как одно значение). */
static void DumpHex(char *dst, int cap, const void *p, int n)
{
    static const char hx[] = "0123456789abcdef";
    u8  buf[8192];
    int i, k = 0;

    if (!dst || cap <= 1) return;
    dst[0] = 0;
    if (n <= 0) return;
    if (n > (int)sizeof(buf)) n = (int)sizeof(buf);
    if (!SafeRead(p, buf, (SIZE_T)n)) {
        SetStr(dst, (DWORD)cap, "<unreadable>");
        return;
    }
    for (i = 0; i < n && k + 3 < cap; ++i) {
        dst[k++] = hx[(buf[i] >> 4) & 0xF];
        dst[k++] = hx[buf[i] & 0xF];
    }
    dst[k] = 0;
}

/* Кто вызвал: `pcmflash.exe+0x837fd`. Без этого 11 пар конфигурации GPT и одна
 * пара питания неотличимы — обе идут через op=0x0b (docs/13 §6.3). */
static void NameOf(const char *path, char *dst, DWORD cap);

static void AddrToModule(const void *addr, char *dst, DWORD cap)
{
    HMODULE mod = NULL;
    char    path[MAX_PATH];
    char    base[MAX_PATH];

    if (!dst || cap == 0) return;
    dst[0] = 0;
    if (!addr) { SetStr(dst, cap, "0"); return; }
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)addr, &mod) || !mod) {
        _snprintf(dst, cap, "0x%p", addr);
        dst[cap - 1] = 0;
        return;
    }
    GetModuleFileNameA(mod, path, MAX_PATH);
    NameOf(path, base, MAX_PATH);
    _snprintf(dst, cap, "%s+0x%lx", base,
              (unsigned long)((uintptr_t)addr - (uintptr_t)mod));
    dst[cap - 1] = 0;
}

/* Имя параметра SET_CONFIG (J2534 04.04) — чтобы `cfg=` читался глазами. */
static const char *CfgName(ulong id)
{
    switch (id) {
    case 0x01: return "DATA_RATE";
    case 0x02: return "LOOPBACK";
    case 0x03: return "NODE_ADDRESS";
    case 0x04: return "NETWORK_LINE";
    case 0x05: return "P1_MIN";
    case 0x06: return "P1_MAX";
    case 0x07: return "P2_MIN";
    case 0x08: return "P2_MAX";
    case 0x09: return "P3_MIN";
    case 0x0A: return "P3_MAX";
    case 0x0B: return "P4_MIN";
    case 0x0C: return "P4_MAX";
    case 0x0D: return "W1";
    case 0x0E: return "W2";
    case 0x0F: return "W3";
    case 0x10: return "W4";
    case 0x11: return "W5";
    case 0x14: return "ISO15765_BS";
    case 0x15: return "ISO15765_STMIN";
    case 0x1A: return "BS_TX";
    case 0x1B: return "STMIN_TX";
    default:   return NULL;
    }
}

/* "C:\a\b.dll" -> "C:\a" */
static void DirOf(const char *path, char *dst, DWORD cap){
    size_t i, len;

    SetStr(dst, cap, path);
    len = strlen(dst);
    for (i = len; i > 0; --i) {
        if (dst[i - 1] == '\\' || dst[i - 1] == '/') {
            dst[i - 1] = 0;
            break;
        }
    }
    if (i == 0) dst[0] = 0;
}

/* "C:\a\b.dll" -> "b.dll" */
static void NameOf(const char *path, char *dst, DWORD cap)
{
    size_t i, len;

    SetStr(dst, cap, path);
    len = strlen(dst);
    for (i = len; i > 0; --i) {
        if (dst[i - 1] == '\\' || dst[i - 1] == '/') {
            SetStr(dst, cap, dst + i);
            return;
        }
    }
}

/* dst = dir + "\" + name */
static void JoinPath(char *dst, DWORD cap, const char *dir, const char *name)
{
    size_t len;

    SetStr(dst, cap, dir);
    len = strlen(dst);
    if (len > 0 && dst[len - 1] != '\\' && dst[len - 1] != '/') {
        if (len + 1 < cap) {
            dst[len] = '\\';
            dst[len + 1] = 0;
        }
    }
    if (strlen(dst) + strlen(name) + 1 < cap) lstrcatA(dst, name);
}

static void MakeDirs(const char *dir)
{
    char   tmp[MAX_PATH];
    size_t i, len;

    SetStr(tmp, MAX_PATH, dir);
    len = strlen(tmp);
    for (i = 0; i <= len; ++i) {
        if (tmp[i] == '\\' || tmp[i] == '/' || tmp[i] == 0) {
            char save = tmp[i];
            tmp[i] = 0;
            /* skip "C:" and empty components */
            if (tmp[0] && !(strlen(tmp) == 2 && tmp[1] == ':')) CreateDirectoryA(tmp, NULL);
            tmp[i] = save;
        }
    }
}

static int SamePath(const char *a, const char *b)
{
    char fa[MAX_PATH];
    char fb[MAX_PATH];

    if (!a || !a[0] || !b || !b[0]) return 0;
    if (!GetFullPathNameA(a, MAX_PATH, fa, NULL)) SetStr(fa, MAX_PATH, a);
    if (!GetFullPathNameA(b, MAX_PATH, fb, NULL)) SetStr(fb, MAX_PATH, b);
    return lstrcmpiA(fa, fb) == 0;
}

static ULONGLONG ElapsedUs(void)
{
    LARGE_INTEGER now;
    LONGLONG      d;

    QueryPerformanceCounter(&now);
    d = now.QuadPart - g_qpc0;
    if (d < 0) d = 0;
    return (ULONGLONG)(d * 1000000LL / g_qpf);
}

static LONGLONG QpcNow(void)
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return now.QuadPart;
}

static ULONGLONG UsSince(LONGLONG t0)
{
    LONGLONG d = QpcNow() - t0;
    if (d < 0) d = 0;
    return (ULONGLONG)(d * 1000000LL / g_qpf);
}

/* Lower-case, space separated, exactly n bytes (already clipped by the caller). */
static void HexBytes(char *dst, size_t cap, const u8 *d, ulong n)
{
    size_t used = 0;
    ulong  i;

    if (!dst || cap == 0) return;
    dst[0] = 0;
    if (!d || n == 0) return;
    for (i = 0; i < n; ++i) {
        int w;
        if (used + 4 >= cap) break;
        w = _snprintf(dst + used, cap - used, i ? " %02x" : "%02x", (unsigned)d[i]);
        if (w < 0) break;
        used += (size_t)w;
    }
}

/* ------------------------------------------------------------------ */
/* journal                                                             */
/* ------------------------------------------------------------------ */

/* Header/fatal/warn/stop lines carry no [+...] prefix. */
static void WriteFmt(const char *fmt, ...)
{
    char    buf[2048];
    int     n;
    DWORD   wrote = 0;
    va_list ap;

    if (g_hLog == INVALID_HANDLE_VALUE) return;

    va_start(ap, fmt);
    n = _vsnprintf(buf, sizeof(buf) - 3, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(buf) - 3;
    buf[n++] = '\r';
    buf[n++] = '\n';
    buf[n]   = 0;

    WriteFile(g_hLog, buf, (DWORD)n, &wrote, NULL);
    FlushFileBuffers(g_hLog);
}

/* Exchange lines: "[+<sec>.<usec>s] <body>", six decimals as in docs/11. */
static void WriteLiveFile(const char *state);   /* live state, defined below */
static void MaybeWriteLive(void);

static void LogLine(const char *fmt, ...)
{
    char      body[16384];
    char      line[16640];
    int       n, m;
    DWORD     wrote = 0;
    ULONGLONG us;
    va_list   ap;

    if (g_hLog == INVALID_HANDLE_VALUE) return;

    va_start(ap, fmt);
    n = _vsnprintf(body, sizeof(body) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) n = (int)sizeof(body) - 1;
    body[n] = 0;

    us = ElapsedUs();
    m  = _snprintf(line, sizeof(line) - 3, "[+%llu.%06llus] ",
                   us / 1000000ULL, us % 1000000ULL);
    if (m < 0) m = 0;
    if ((size_t)m + (size_t)n + 3 > sizeof(line)) {
        n = (int)(sizeof(line) - 3 - (size_t)m);
        if (n < 0) n = 0;
    }
    memcpy(line + m, body, (size_t)n);
    m += n;
    line[m++] = '\r';
    line[m++] = '\n';
    line[m]   = 0;

    WriteFile(g_hLog, line, (DWORD)m, &wrote, NULL);
    FlushFileBuffers(g_hLog);

    /* Every call ends here, so this is the one place that keeps the counters
     * in the live state file moving (throttled to once a second). */
    MaybeWriteLive();
}

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */

static void ReadIniStr(const char *sec, const char *key, const char *def,
                       char *dst, DWORD cap)
{
    DWORD n = GetPrivateProfileStringA(sec, key, def ? def : "", dst, cap, g_ini);
    if (n == 0 && def) SetStr(dst, cap, def);
    dst[cap - 1] = 0;
}

static void ReadFirstLine(const char *path, char *dst, DWORD cap)
{
    HANDLE h;
    DWORD  got = 0;
    char   raw[1024];
    DWORD  i;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    if (!ReadFile(h, raw, sizeof(raw) - 1, &got, NULL)) got = 0;
    CloseHandle(h);

    raw[got] = 0;
    for (i = 0; i < got; ++i) {
        if (raw[i] == '\r' || raw[i] == '\n') { raw[i] = 0; break; }
    }
    TrimA(raw);
    if (raw[0]) SetStr(dst, cap, raw);
}

/* Copies the variable only when it exists: an absent variable must not erase
 * the value that came from the ini (priority 2).  Returns 1 when copied. */
static int EnvStr(const char *name, char *dst, DWORD cap)
{
    DWORD n = GetEnvironmentVariableA(name, dst, cap);
    if (n == 0 || n >= cap) return 0;
    dst[cap - 1] = 0;
    TrimA(dst);
    return 1;
}

/* proxy-YYYYMMDD-HHMMSS-pid<PID>.log */
static void MakeLogName(char *dst, DWORD cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    _snprintf(dst, cap,
              "proxy-%04u%02u%02u-%02u%02u%02u-pid%lu.log",
              (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
              (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
              (ulong)GetCurrentProcessId());
    dst[cap - 1] = 0;
}

static HANDLE OpenLogAt(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return h;
    /* append: OPEN_ALWAYS keeps the existing content, seek to its end */
    SetFilePointer(h, 0, NULL, FILE_END);
    /* Remember where the journal really went: the live state file must sit in
     * the same directory the engine scans (LogDir, exact path or %TEMP%). */
    SetStr(g_logPath, MAX_PATH, path);
    return h;
}

static void OpenLog(void)
{
    char  name[MAX_PATH];
    char  dir[MAX_PATH];
    char  path[MAX_PATH];
    char  tmp[MAX_PATH];
    DWORD n;

    MakeLogName(name, MAX_PATH);

    /* priority 1: exact path from the environment */
    if (g_logExact[0]) {
        g_hLog = OpenLogAt(g_logExact);
        if (g_hLog != INVALID_HANDLE_VALUE) return;
    }

    /* priority 2: LogDir + generated name */
    dir[0] = 0;
    if (g_logDir[0]) {
        SetStr(dir, MAX_PATH, g_logDir);
    } else {
        /* priority 3: %LOCALAPPDATA%\FTDI_USB_Logger\j2534proxy */
        n = GetEnvironmentVariableA("LOCALAPPDATA", tmp, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            char base[MAX_PATH];
            JoinPath(base, MAX_PATH, tmp, "FTDI_USB_Logger");
            JoinPath(dir, MAX_PATH, base, "j2534proxy");
        }
    }

    if (dir[0]) {
        MakeDirs(dir);
        JoinPath(path, MAX_PATH, dir, name);
        g_hLog = OpenLogAt(path);
        if (g_hLog != INVALID_HANDLE_VALUE) return;
    }

    /* last resort: %TEMP% */
    n = GetTempPathA(MAX_PATH, tmp);
    if (n > 0 && n < MAX_PATH) {
        JoinPath(path, MAX_PATH, tmp, name);
        g_hLog = OpenLogAt(path);
    }
}

/* ------------------------------------------------------------------ */
/* live state (for the GUI)                                            */
/* ------------------------------------------------------------------ */

/* proxy-live-<pid>.state, next to the journal.  Extension is deliberately not
 * `.log`: the engine's lane collector takes every `proxy-*.log` as exchange
 * lines, and this file is not an exchange. */
static void LivePath(char *dst, DWORD cap)
{
    char  dir[MAX_PATH];
    char  name[64];

    dst[0] = 0;
    if (!g_logPath[0]) return;      /* no journal -> nothing to attribute it to */
    DirOf(g_logPath, dir, MAX_PATH);
    _snprintf(name, sizeof(name), "proxy-live-%lu.state", (ulong)GetCurrentProcessId());
    name[sizeof(name) - 1] = 0;
    JoinPath(dst, cap, dir, name);
}

/* Seconds since the Unix epoch (the engine compares them without parsing). */
static unsigned long long UnixNow(void)
{
    FILETIME      ft;
    ULARGE_INTEGER u;

    GetSystemTimeAsFileTime(&ft);
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

/* Replace the state file in one step: write `<path>.tmp`, then rename over.
 *
 * The engine polls this file while the tool works, so a half-written line would
 * be read as a broken state.  Rename is atomic on the same volume, hence the tmp
 * file next to the target and never in %TEMP%.
 *
 * No critical section: this also runs from DLL_PROCESS_DETACH, where another
 * thread may still hold g_cs.  Counters are read with InterlockedCompareExchange
 * so a torn 32-bit read is impossible in practice. */
static void WriteLiveFile(const char *state)
{
    char  path[MAX_PATH];
    char  tmp[MAX_PATH];
    char  exe[MAX_PATH];
    char  text[4096];
    HANDLE h;
    DWORD written = 0;
    int   len;
    size_t n;

    LivePath(path, MAX_PATH);
    if (!path[0]) return;

    SetStr(tmp, MAX_PATH, path);
    n = strlen(tmp);
    if (n + 5 >= MAX_PATH) return;
    lstrcpyA(tmp + n, ".tmp");

    exe[0] = 0;
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    exe[MAX_PATH - 1] = 0;

    len = _snprintf(text, sizeof(text),
        "# proxy live: pid=%lu state=%s\n"
        "pid=%lu\n"
        "state=%s\n"
        "exe=%s\n"
        "dll=%s\n"
        "real=%s\n"
        "log=%s\n"
        "device=%s\n"
        "started=%s\n"
        "updated=%llu\n"
        "calls=%ld\n"
        "tx=%ld\n"
        "rx=%ld\n"
        "errors=%ld\n"
        "pairs=%ld\n"
        "seed=%ld\n"
        "key=%ld\n"
        "denied=%ld\n"
        "gen=%ld\n"
        "bits=%d\n"
        "fatal=%d\n"
        "version=%s\n",
        (ulong)GetCurrentProcessId(), state,
        (ulong)GetCurrentProcessId(), state,
        exe, g_dll, g_realPath, g_logPath, g_devName,
        g_started, UnixNow(),
        (long)InterlockedCompareExchange(&g_calls, 0, 0),
        (long)InterlockedCompareExchange(&g_tx, 0, 0),
        (long)InterlockedCompareExchange(&g_rx, 0, 0),
        (long)InterlockedCompareExchange(&g_errors, 0, 0),
        (long)InterlockedCompareExchange(&g_pairs, 0, 0),
        (long)InterlockedCompareExchange(&g_seed, 0, 0),
        (long)InterlockedCompareExchange(&g_key, 0, 0),
        (long)InterlockedCompareExchange(&g_denied, 0, 0),
        (long)InterlockedCompareExchange(&g_gen, 0, 0),
        g_bits, g_fatal, PROXY_VERSION);
    if (len < 0) return;
    if ((size_t)len >= sizeof(text)) len = (int)sizeof(text) - 1;

    h = CreateFileA(tmp, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, text, (DWORD)len, &written, NULL);
    CloseHandle(h);
    MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING);
}

/* One write per second, driven by the exchange itself: every API call ends in
 * LogLine(), so an active tool refreshes the counters, and an idle tool keeps
 * the last numbers instead of rewriting the file 60 times a minute.  A thread
 * would do the same job but must then be joined before FreeLibrary() unmaps
 * this code -- a driver that crashes on unload is worse than slightly stale
 * counters, and "is it loaded" is answered by the process check in the engine. */
static void MaybeWriteLive(void)
{
    static volatile LONG last;
    LONG now  = (LONG)GetTickCount64();
    LONG prev = InterlockedCompareExchange(&last, 0, 0);

    if ((ULONG)(now - prev) < 1000) return;
    if (InterlockedCompareExchange(&last, now, prev) != prev) return;
    WriteLiveFile("live");
}

static void WriteHeader(void)
{
    SYSTEMTIME st;
    char       dir[MAX_PATH];
    char       live[MAX_PATH];

    GetLocalTime(&st);
    DirOf(g_dll, dir, MAX_PATH);

    g_started[0] = 0;
    _snprintf(g_started, sizeof(g_started), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
              (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
              (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
              (unsigned)st.wMilliseconds);
    g_started[sizeof(g_started) - 1] = 0;

    WriteFmt("# capture start: label=J2534 proxy");
    /* active=1 is the machine-readable proof (for the Frida agent) that the
     * proxy really forwards: a named mutex plus this marker. */
    WriteFmt("# proxy: dll=\"%s\" real=\"%s\" pid=%lu bits=%d active=%d",
             g_dll, g_realPath[0] ? g_realPath : "", (ulong)GetCurrentProcessId(),
             g_bits, g_mutex ? 1 : 0);
    WriteFmt("# wall(start)=%s", g_started);
    WriteFmt("# api: %s dll=\"%s\" ver=\"%s\" path=\"%s\" pid=%lu bits=%d dec=1",
             PROXY_API, g_dllName, PROXY_VERSION, g_dll,
             (ulong)GetCurrentProcessId(), g_bits);
    WriteFmt("# agent: %s mode=proxy", g_dllName);
    WriteFmt("# device: name=\"%s\" vendor=\"%s\"", g_devName, g_devVendor);
    LivePath(live, MAX_PATH);
    if (live[0]) WriteFmt("# proxy live: %s", live);
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static void LogFatal(const char *what)
{
    g_fatal = 1;
    WriteFmt("# proxy fatal: %s", what);
}

static void ResolveReal(void)
{
    if (g_realPath[0] == 0) {
        LogFatal("real library not found");
        return;
    }
    if (SamePath(g_realPath, g_dll)) {
        LogFatal("real == self");
        return;
    }

    g_real = LoadLibraryA(g_realPath);
    if (!g_real) {
        LogFatal("real library not found");
        return;
    }

    pOpen          = (PFN_OPEN)          GetProcAddress(g_real, "PassThruOpen");
    pClose         = (PFN_CLOSE)         GetProcAddress(g_real, "PassThruClose");
    pConnect       = (PFN_CONNECT)       GetProcAddress(g_real, "PassThruConnect");
    pDisconnect    = (PFN_DISCONNECT)    GetProcAddress(g_real, "PassThruDisconnect");
    pReadMsgs      = (PFN_READMSGS)      GetProcAddress(g_real, "PassThruReadMsgs");
    pWriteMsgs     = (PFN_WRITEMSGS)     GetProcAddress(g_real, "PassThruWriteMsgs");
    pStartPeriodic = (PFN_STARTPERIODIC) GetProcAddress(g_real, "PassThruStartPeriodicMsg");
    pStopPeriodic  = (PFN_STOPPERIODIC)  GetProcAddress(g_real, "PassThruStopPeriodicMsg");
    pStartFilter   = (PFN_STARTFILTER)   GetProcAddress(g_real, "PassThruStartMsgFilter");
    pStopFilter    = (PFN_STOPFILTER)    GetProcAddress(g_real, "PassThruStopMsgFilter");
    pSetVoltage    = (PFN_SETVOLTAGE)    GetProcAddress(g_real, "PassThruSetProgrammingVoltage");
    pReadVersion   = (PFN_READVERSION)   GetProcAddress(g_real, "PassThruReadVersion");
    pGetLastError  = (PFN_GETLASTERROR)  GetProcAddress(g_real, "PassThruGetLastError");
    pIoctl         = (PFN_IOCTL)         GetProcAddress(g_real, "PassThruIoctl");
}

static void InitOnce(void)
{
    char  dir[MAX_PATH];
    char  name[64];
    char  off[32];
    int   enabled;

    InitializeCriticalSection(&g_cs);

    g_qpf = 1;
    {
        LARGE_INTEGER f, c;
        QueryPerformanceFrequency(&f);
        if (f.QuadPart > 0) g_qpf = f.QuadPart;
        QueryPerformanceCounter(&c);
        g_qpc0 = c.QuadPart;
    }

    g_bits = (int)(sizeof(void *) * 8);

    GetModuleFileNameA(g_hinst, g_dll, MAX_PATH);
    g_dll[MAX_PATH - 1] = 0;
    NameOf(g_dll, g_dllName, MAX_PATH);
    DirOf(g_dll, dir, MAX_PATH);
    JoinPath(g_ini, MAX_PATH, dir, "j2534proxy.ini");

    /* ---- [proxy] --------------------------------------------------- */
    enabled = (int)GetPrivateProfileIntA("proxy", "Enabled", 1, g_ini);
    ReadIniStr("proxy", "RealLibrary", "", g_realPath, MAX_PATH);
    TrimA(g_realPath);
    ExpandPath(g_realPath, MAX_PATH);
    ReadIniStr("proxy", "LogDir", "", g_logDir, MAX_PATH);
    TrimA(g_logDir);
    /* %LOCALAPPDATA% и подобное: без раскрытия журнал уходил в каталог с
     * буквальным именем `%LOCALAPPDATA%` относительно CWD приложения. */
    ExpandPath(g_logDir, MAX_PATH);
    g_maxData = (ulong)GetPrivateProfileIntA("proxy", "MaxDataBytes", PROXY_MAX_DATA, g_ini);
    if (g_maxData == 0 || g_maxData > PROXY_MAX_DATA) g_maxData = PROXY_MAX_DATA;

    /* ---- [device] -------------------------------------------------- */
    ReadIniStr("device", "Name", "Scanmatik - SM2 Proxy", g_devName, MAX_PATH);
    TrimA(g_devName);
    ReadIniStr("device", "Vendor", "DaVinci Cyber Engineering", g_devVendor, MAX_PATH);
    TrimA(g_devVendor);

    /* ---- [log]: пределы дампов вендорских вызовов (docs/13 §6.3) ---- */
    g_logArgs = (int)GetPrivateProfileIntA("log", "LogArgs", 1, g_ini) ? 1 : 0;
    g_vendorArgBytes = ClampInt((int)GetPrivateProfileIntA("log", "VendorArgBytes", 512, g_ini), 0, 4096);
    g_vendorBeforeBytes = ClampInt((int)GetPrivateProfileIntA("log", "VendorBeforeBytes", 32, g_ini), 0, 256);
    g_vendorParamPairs = (int)GetPrivateProfileIntA("log", "VendorParamPairs", 1, g_ini) ? 1 : 0;
    g_maxParamPairs = ClampInt((int)GetPrivateProfileIntA("log", "MaxParamPairs", 16, g_ini), 1, 64);
    g_maxDumpPerCall = ClampInt((int)GetPrivateProfileIntA("log", "MaxDumpPerCall", 4096, g_ini), 64, 8192);
    {
        char list[128];
        ReadIniStr("log", "VendorFullOps", "0x0b,0x00", list, sizeof(list));
        ParseNumList(list, g_vendorFullOp, 8, &g_vendorFullOpN);
        ReadIniStr("log", "VendorOrds", "1377,1378,1379", list, sizeof(list));
        ParseNumList(list, g_vendorOrds, 8, &g_vendorOrdN);
    }

    /* ---- environment overrides (priority 1, docs/13 section 4) ----- */
    (void)EnvStr("FTDI_J2534_REAL_DLL", g_realPath, MAX_PATH);
    ExpandPath(g_realPath, MAX_PATH);
    (void)EnvStr("FTDI_J2534_PROXY_LOG", g_logExact, MAX_PATH);
    ExpandPath(g_logExact, MAX_PATH);
    off[0] = 0;
    if (EnvStr("FTDI_J2534_PROXY_OFF", off, sizeof(off)) &&
        off[0] && lstrcmpiA(off, "0") != 0) {
        enabled = 0;
    }

    /* ---- real_dll.txt (priority 3) --------------------------------- */
    if (g_realPath[0] == 0) {
        char txt[MAX_PATH];
        JoinPath(txt, MAX_PATH, dir, "real_dll.txt");
        ReadFirstLine(txt, g_realPath, MAX_PATH);
        ExpandPath(g_realPath, MAX_PATH);
    }

    g_enabled = enabled ? 1 : 0;

    /* Disabled: pure pass-through.  No journal, no mutex -- the Frida agent
     * keeps logging, as the user asked the proxy to stay out of the way. */
    if (!g_enabled) {
        ResolveReal();
        return;
    }

    /* Named mutex, created BEFORE the real driver is loaded: its presence in
     * the process is the Frida agent's proof that the proxy is forwarding and
     * the real driver must not be hooked a second time.  Name is fixed:
     *   Local\FTDI_J2534_PROXY_<pid>
     * The handle intentionally lives until DLL_PROCESS_DETACH. */
    _snprintf(name, sizeof(name), "Local\\FTDI_J2534_PROXY_%lu",
              (ulong)GetCurrentProcessId());
    name[sizeof(name) - 1] = 0;
    g_mutex = CreateMutexA(NULL, FALSE, name);

    OpenLog();
    WriteHeader();
    ResolveReal();

    /* "Loaded" is true from the moment the tool loaded us, not from the first
     * PassThru call: the whole point of the GUI indicator is to tell the user
     * whether the program picked our device at all.  Counters are refreshed by
     * MaybeWriteLive() from the exchange itself. */
    WriteLiveFile("live");
}

static void EnsureInit(void)
{
    LONG s = InterlockedCompareExchange(&g_state, INIT_BUSY, INIT_NONE);

    if (s == INIT_READY) return;
    if (s == INIT_BUSY) {
        while (InterlockedCompareExchange(&g_state, INIT_READY, INIT_READY) != INIT_READY) {
            Sleep(0);
        }
        return;
    }

    InitOnce();
    InterlockedExchange(&g_state, INIT_READY);
}

/* ------------------------------------------------------------------ */
/* journal helpers                                                     */
/* ------------------------------------------------------------------ */

static void CountError(void)
{
    InterlockedIncrement(&g_errors);
}

/* Forwarding failure: the contract asks for both the exchange line and the
 * duplicated "# proxy warn:" line (docs/13 section 6). */
static void EmitForwardError(const char *op, ulong rc)
{
    CountError();
    LogLine("J2534 err op=%s rc=0x%02lx", op, rc);
    WriteFmt("# proxy warn: J2534 err op=%s rc=0x%02lx", op, rc);
}

static const char *IoctlName(ulong id)
{
    switch (id) {
    case 0x01: return "GET_CONFIG";
    case 0x02: return "SET_CONFIG";
    case 0x03: return "READ_VBATT";
    case 0x04: return "FIVE_BAUD_INIT";
    case 0x05: return "FAST_INIT";
    case 0x06: return "CLEAR_TX_BUFFER";
    case 0x07: return "CLEAR_RX_BUFFER";
    case 0x08: return "CLEAR_PERIODIC_MSGS";
    case 0x09: return "CLEAR_MSG_FILTERS";
    case 0x0A: return "CLEAR_EXTRA_BYTES";
    case 0x0B: return "SET_BUS_PLUS";
    case 0x0C: return "SET_BUS_MINUS";
    case 0x0D: return "SET_PROG_VOLTAGE";
    case 0x0E: return "READ_PROG_VOLTAGE";
    default:   return "?";
    }
}

/* rc is written as "0" on success and as a hex code otherwise, the way the
 * agent does it (docs/11: rc=0, rc=0x11).  Called under g_cs. */
static const char *RcStr(ulong rc)
{
    static char buf[2][24];
    static int  slot = 0;

    char *b = buf[slot = (slot + 1) & 1];
    if (rc == 0) {
        b[0] = '0';
        b[1] = 0;
    } else {
        _snprintf(b, sizeof(buf[0]), "0x%02lx", rc);
        b[sizeof(buf[0]) - 1] = 0;
    }
    return b;
}

/* "J2534 call ch=.. call=.. op=..<extra> rc=.. th=.. dur=.." */
static void LogCall(LONG seq, const char *op, int hasCh, ulong ch,
                    ulong rc, DWORD th, ULONGLONG dur, const char *extra)
{
    if (!extra) extra = "";
    if (hasCh) {
        LogLine("J2534 call ch=%lu call=%ld op=%s%s rc=%s th=%lu dur=%llu",
                ch, seq, op, extra, RcStr(rc), (ulong)th, dur);
    } else {
        LogLine("J2534 call call=%ld op=%s%s rc=%s th=%lu dur=%llu",
                seq, op, extra, RcStr(rc), (ulong)th, dur);
    }
}

/* Service/sub-function offsets of a security-access frame.
 *
 * Vendor protocols (>= 0x8000, e.g. 0x8003) keep Data[0]=kind, Data[1]=length,
 * so the service is Data[2]; ISO 15765 single frames keep the PCI nibble in
 * Data[0], so the service is Data[1].  Other framing is not guessed. */
static int AuthSvcOff(const PASSTHRU_MSG *m, ulong *off)
{
    if (!m) return 0;
    if (m->ProtocolID >= 0x8000UL) {
        if (m->DataSize < 3) return 0;
        *off = 2;
        return 1;
    }
    if (m->ProtocolID == 0x06UL) {
        if (m->DataSize < 2 || (m->Data[0] & 0xF0) != 0x00) return 0;
        *off = 1;
        return 1;
    }
    return 0;
}

/* Append `mark=` tags to the exchange line.  They go into the key/value part
 * (before " : "), so the grammar in docs/11 and every existing parser keep
 * working; a human sees SEED?/SEED/KEY/ACCESS OK/ACCESS DENIED, and the engine
 * can read `mark=` without re-deriving the service.
 *
 * `27 01/02` (UDS) and `27 7F/80` (KWP2000) are both handled: an odd
 * sub-function requests a seed, an even one sends a key. */
static void AuthMark(int isTx, const PASSTHRU_MSG *m, char *mark, size_t cap)
{
    ulong  off, svc, sub, n, i;
    size_t pos = 0;
    int    w;

    if (!mark || cap < 8) return;
    mark[0] = 0;
    if (!AuthSvcOff(m, &off)) return;
    n = m->DataSize;
    if (n <= off + 1) return;
    svc = (ulong)m->Data[off];
    sub = (ulong)m->Data[off + 1];

    if (isTx) {
        if (svc != 0x27UL) return;
        if (sub & 1UL) {
            _snprintf(mark, cap, " mark=SEED?");
            return;
        }
        if (sub > 0 && n > off + 2) {
            InterlockedIncrement(&g_key);
            InterlockedExchange(&g_key_pending, 1);
            w = _snprintf(mark, cap, " mark=KEY key8=");
            if (w > 0) pos = (size_t)w;
            for (i = 0; i < 8 && off + 2 + i < n && pos + 3 < cap; i++) {
                w = _snprintf(mark + pos, cap - pos, "%02x",
                              (unsigned)m->Data[off + 2 + i]);
                if (w > 0) pos += (size_t)w;
            }
            if (off + 10 < n && pos + 3 < cap) {
                _snprintf(mark + pos, cap - pos, "..");
            }
        }
        return;
    }

    if (svc == 0x67UL && (sub & 1UL)) {
        InterlockedIncrement(&g_seed);
        w = _snprintf(mark, cap, " mark=SEED seed=");
        if (w > 0) pos = (size_t)w;
        for (i = 0; i < 16 && off + 2 + i < n && pos + 3 < cap; i++) {
            w = _snprintf(mark + pos, cap - pos, "%02x",
                          (unsigned)m->Data[off + 2 + i]);
            if (w > 0) pos += (size_t)w;
        }
        if (off + 18 < n && pos + 3 < cap) {
            _snprintf(mark + pos, cap - pos, "..");
        }
    } else if (svc == 0x67UL && sub > 0) {
        long pair;
        if (InterlockedExchange(&g_key_pending, 0)) {
            pair = InterlockedIncrement(&g_pairs);
            _snprintf(mark, cap, " mark=ACCESS_OK mark=PAIR#%ld", pair);
        } else {
            _snprintf(mark, cap, " mark=ACCESS_OK");
        }
    } else if (svc == 0x7FUL && sub == 0x27UL) {
        unsigned nrc = (n > off + 2) ? (unsigned)m->Data[off + 2] : 0U;
        InterlockedIncrement(&g_denied);
        InterlockedExchange(&g_key_pending, 0);
        _snprintf(mark, cap, " mark=ACCESS_DENIED nrc=0x%02x", nrc);
    }
    mark[cap - 1] = 0;
}

/* One TX/RX frame.  `total` is the denominator of i=k/n: the number of input
 * messages for TX, the number of returned messages for RX. */
static void LogMsg(int isTx, ulong ch, LONG seq, ulong idx, ulong total,
                   ulong n_in, ulong n_out, DWORD th,
                   const PASSTHRU_MSG *m, ULONGLONG dur, ulong rc)
{
    char  svc[32];
    char  trunc[32];
    char  mark[160];
    ulong size;
    ulong shown;

    if (!m) return;

    size = m->DataSize;
    if (size > PROXY_MAX_DATA) size = PROXY_MAX_DATA;

    shown = size;
    trunc[0] = 0;
    if (shown > g_maxData) {
        shown = g_maxData;
        SetStr(trunc, sizeof(trunc), " truncated=1");
    }
    HexBytes(g_hex, sizeof(g_hex), m->Data, shown);

    /* svc= only when it is unambiguous: vendor protocols keep it in Data[2]
     * (Data[0] is the frame kind, Data[1] the length), ISO15765 in Data[0]. */
    svc[0] = 0;
    if (m->ProtocolID >= 0x8000UL) {
        if (size > 2) _snprintf(svc, sizeof(svc), " svc=0x%02lx", (ulong)m->Data[2]);
    } else if (m->ProtocolID == 0x06UL) {
        if (size > 0) _snprintf(svc, sizeof(svc), " svc=0x%02lx", (ulong)m->Data[0]);
    }
    svc[sizeof(svc) - 1] = 0;
    AuthMark(isTx, m, mark, sizeof(mark));

    if (isTx) {
        InterlockedIncrement(&g_tx);
        LogLine("J2534 TX ch=%lu call=%ld i=%lu/%lu n_in=%lu n_out=%lu th=%lu ts=%lu "
                "flags=0x%lx proto=0x%02lx%s%s len=%lu%s dur=%llu rc=%s : %s",
                ch, seq, idx, total, n_in, n_out, (ulong)th, (ulong)m->Timestamp,
                (ulong)m->TxFlags, (ulong)m->ProtocolID, svc, mark, size, trunc,
                dur, RcStr(rc), g_hex);
    } else {
        InterlockedIncrement(&g_rx);
        LogLine("J2534 RX ch=%lu call=%ld i=%lu/%lu n_in=%lu n_out=%lu th=%lu ts=%lu "
                "rxs=0x%lx proto=0x%02lx%s%s len=%lu%s dur=%llu rc=%s : %s",
                ch, seq, idx, total, n_in, n_out, (ulong)th, (ulong)m->Timestamp,
                (ulong)m->RxStatus, (ulong)m->ProtocolID, svc, mark, size, trunc,
                dur, RcStr(rc), g_hex);
    }
}

/* ------------------------------------------------------------------ */
/* exported API (14 named entry points, Pass-Thru 04.04)               */
/* ------------------------------------------------------------------ */

ulong __stdcall PassThruOpen(void *pName, ulong *pDeviceID)
{
    ulong rc;
    LONG  seq;
    DWORD th;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();

    if (g_fatal || !pOpen) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruOpen", rc);
    } else {
        rc = pOpen(pName, pDeviceID);
        if (rc != STATUS_NOERROR) CountError();
    }

    LogLine("J2534 open name=\"%s\" dev=%lu rc=%s th=%lu",
            pName ? (const char *)pName : "",
            (ulong)(pDeviceID ? *pDeviceID : 0UL), RcStr(rc), (ulong)th);
    (void)seq;
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruClose(ulong DeviceID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pClose) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruClose", rc);
    } else {
        rc = pClose(DeviceID);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruClose", 0, 0, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruConnect(ulong DeviceID, ulong ProtocolID, ulong Flags,
                                ulong BaudRate, ulong *pChannelID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;
    ulong     ch = 0;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    LogLine("J2534 connect-enter dev=%lu proto=0x%02lx flags=0x%lx baud=%lu th=%lu",
            DeviceID, ProtocolID, Flags, BaudRate, (ulong)th);

    if (g_fatal || !pConnect) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruConnect", rc);
    } else {
        rc = pConnect(DeviceID, ProtocolID, Flags, BaudRate, pChannelID);
        if (rc != STATUS_NOERROR) CountError();
        else InterlockedIncrement(&g_gen);
    }

    dur = UsSince(t0);
    if (pChannelID) ch = *pChannelID;
    LogLine("J2534 connect dev=%lu ch=%lu proto=0x%02lx protocol=0x%02lx flags=0x%lx baud=%lu "
            "rc=%s gen=%ld th=%lu dur=%llu",
            DeviceID, ch, ProtocolID, ProtocolID, Flags, BaudRate, RcStr(rc),
            (long)g_gen, (ulong)th, dur);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruDisconnect(ulong ChannelID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pDisconnect) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruDisconnect", rc);
    } else {
        rc = pDisconnect(ChannelID);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruDisconnect", 1, ChannelID, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruReadMsgs(ulong ChannelID, PASSTHRU_MSG *pMsg,
                                 ulong *pNumMsgs, ulong Timeout)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;
    ulong     n_in, n_out, i;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq  = InterlockedIncrement(&g_calls);
    th   = GetCurrentThreadId();
    t0   = QpcNow();
    n_in = pNumMsgs ? *pNumMsgs : 0;

    if (g_fatal || !pReadMsgs) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruReadMsgs", rc);
        n_out = 0;
    } else {
        rc = pReadMsgs(ChannelID, pMsg, pNumMsgs, Timeout);
        if (rc != STATUS_NOERROR) CountError();
        n_out = pNumMsgs ? *pNumMsgs : 0;
        /* a driver must never report more messages than the buffer holds */
        if (n_out > n_in) n_out = n_in;
    }

    dur = UsSince(t0);
    for (i = 0; i < n_out; ++i) {
        LogMsg(0, ChannelID, seq, i + 1, n_out, n_in, n_out, th,
               &pMsg[i], dur, rc);
    }
    if (n_out == 0) {
        char extra[96];
        _snprintf(extra, sizeof(extra), " n_in=%lu n_out=%lu timeout_ms=%lu",
                  n_in, n_out, Timeout);
        extra[sizeof(extra) - 1] = 0;
        LogCall(seq, "PassThruReadMsgs", 1, ChannelID, rc, th, dur, extra);
    }

    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruWriteMsgs(ulong ChannelID, PASSTHRU_MSG *pMsg,
                                  ulong *pNumMsgs, ulong Timeout)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;
    ulong     n_in, n_out, i;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq  = InterlockedIncrement(&g_calls);
    th   = GetCurrentThreadId();
    t0   = QpcNow();
    n_in = pNumMsgs ? *pNumMsgs : 0;

    if (g_fatal || !pWriteMsgs) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruWriteMsgs", rc);
        n_out = 0;
    } else {
        rc = pWriteMsgs(ChannelID, pMsg, pNumMsgs, Timeout);
        if (rc != STATUS_NOERROR) CountError();
        n_out = pNumMsgs ? *pNumMsgs : 0;
        if (n_out > n_in) n_out = n_in;
    }

    dur = UsSince(t0);
    for (i = 0; i < n_in; ++i) {
        LogMsg(1, ChannelID, seq, i + 1, n_in, n_in, n_out, th,
               &pMsg[i], dur, rc);
    }
    if (n_in == 0) {
        char extra[96];
        _snprintf(extra, sizeof(extra), " n_in=%lu n_out=%lu timeout_ms=%lu",
                  n_in, n_out, Timeout);
        extra[sizeof(extra) - 1] = 0;
        LogCall(seq, "PassThruWriteMsgs", 1, ChannelID, rc, th, dur, extra);
    }

    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruStartPeriodicMsg(ulong ChannelID, PASSTHRU_MSG *pMsg,
                                         ulong *pMsgID, ulong TimeInterval)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pStartPeriodic) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruStartPeriodicMsg", rc);
    } else {
        rc = pStartPeriodic(ChannelID, pMsg, pMsgID, TimeInterval);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruStartPeriodicMsg", 1, ChannelID, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruStopPeriodicMsg(ulong ChannelID, ulong MsgID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pStopPeriodic) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruStopPeriodicMsg", rc);
    } else {
        rc = pStopPeriodic(ChannelID, MsgID);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruStopPeriodicMsg", 1, ChannelID, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruStartMsgFilter(ulong ChannelID, ulong FilterType,
                                       PASSTHRU_MSG *pMask, PASSTHRU_MSG *pPattern,
                                       PASSTHRU_MSG *pFlowControlMsg,
                                       ulong *pFilterID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pStartFilter) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruStartMsgFilter", rc);
    } else {
        rc = pStartFilter(ChannelID, FilterType, pMask, pPattern,
                          pFlowControlMsg, pFilterID);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruStartMsgFilter", 1, ChannelID, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruStopMsgFilter(ulong ChannelID, ulong FilterID)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pStopFilter) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruStopMsgFilter", rc);
    } else {
        rc = pStopFilter(ChannelID, FilterID);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruStopMsgFilter", 1, ChannelID, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruSetProgrammingVoltage(ulong DeviceID, ulong PinNumber,
                                              ulong Voltage)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pSetVoltage) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruSetProgrammingVoltage", rc);
    } else {
        rc = pSetVoltage(DeviceID, PinNumber, Voltage);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    {
        /* pin/voltage — единственное доказательство, что питание подаётся
         * ПОСЛЕ настройки GPT, а не до (docs/13 §6.3). */
        char extra[96];
        if (Voltage == 0) {
            _snprintf(extra, sizeof(extra), " pin=%lu voltage=0(OFF)", PinNumber);
        } else if (Voltage == 0xFFFFFFFEUL || Voltage == 0xFFFFFFFFUL) {
            _snprintf(extra, sizeof(extra), " pin=%lu voltage=0x%08lx(keep)",
                      PinNumber, Voltage);
        } else {
            _snprintf(extra, sizeof(extra), " pin=%lu voltage=%lu(0x%08lx)",
                      PinNumber, Voltage, Voltage);
        }
        extra[sizeof(extra) - 1] = 0;
        LogCall(seq, "PassThruSetProgrammingVoltage", 0, 0, rc, th, dur, extra);
    }
    LeaveCriticalSection(&g_cs);
    return rc;
}

/* 04.04 order: firmware first, API version last. */
ulong __stdcall PassThruReadVersion(ulong DeviceID, char *pFirmwareVersion,
                                    char *pDllVersion, char *pApiVersion)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pReadVersion) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruReadVersion", rc);
    } else {
        rc = pReadVersion(DeviceID, pFirmwareVersion, pDllVersion, pApiVersion);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    {
        /* Строки версий — то, по чему видно, что прокси форвардит в тот же
         * драйвер, что и раньше (docs/13 §6.3). */
        char fw[96], dll[128], api[64], extra[360];
        fw[0] = dll[0] = api[0] = 0;
        if (pFirmwareVersion) {
            if (SafeRead(pFirmwareVersion, fw, sizeof(fw) - 1)) fw[sizeof(fw) - 1] = 0;
            else fw[0] = 0;
        }
        if (pDllVersion) {
            if (SafeRead(pDllVersion, dll, sizeof(dll) - 1)) dll[sizeof(dll) - 1] = 0;
            else dll[0] = 0;
        }
        if (pApiVersion) {
            if (SafeRead(pApiVersion, api, sizeof(api) - 1)) api[sizeof(api) - 1] = 0;
            else api[0] = 0;
        }
        _snprintf(extra, sizeof(extra), " fw=\"%s\" dll=\"%s\" api=\"%s\"", fw, dll, api);
        extra[sizeof(extra) - 1] = 0;
        LogCall(seq, "PassThruReadVersion", 0, 0, rc, th, dur, extra);
    }
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruGetLastError(char *pErrorDescription)
{
    ulong     rc;
    LONG      seq;
    DWORD     th;
    LONGLONG  t0;
    ULONGLONG dur;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pGetLastError) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruGetLastError", rc);
    } else {
        rc = pGetLastError(pErrorDescription);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    LogCall(seq, "PassThruGetLastError", 0, 0, rc, th, dur, NULL);
    LeaveCriticalSection(&g_cs);
    return rc;
}

ulong __stdcall PassThruIoctl(ulong ChannelID, ulong IoctlID, void *pInput,
                              void *pOutput)
{
    ulong       rc;
    LONG        seq;
    DWORD       th;
    LONGLONG    t0;
    ULONGLONG   dur;
    char        extra[8192];
    int         used = 0;

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    used = AppendFmt(extra, sizeof(extra), 0, " ioctl=0x%02lx(%s)",
                     IoctlID, IoctlName(IoctlID));

    /* Входной буфер — ДО вызова: FAST_INIT перезаписывает его ответом. */
    if (g_logArgs && pInput) {
        if (IoctlID == 0x02) {
            u32 num = 0, ptr = 0;
            if (SafeRead(pInput, &num, sizeof(num)) &&
                SafeRead((const u8 *)pInput + 4, &ptr, sizeof(ptr))) {
                u32 i;
                if (num > 32) num = 32;
                used = AppendFmt(extra, sizeof(extra), used, " num=%lu",
                                 (unsigned long)num);
                for (i = 0; i < num; ++i) {
                    u32 pair[2];
                    const char *nm;
                    if (!ptr ||
                        !SafeRead((const u8 *)(uintptr_t)ptr + (size_t)i * 8,
                                  pair, sizeof(pair))) {
                        break;
                    }
                    nm = CfgName(pair[0]);
                    used = AppendFmt(extra, sizeof(extra), used, " %s=0x%lx",
                                     nm ? nm : "param", (unsigned long)pair[1]);
                }
            }
        } else if (IoctlID == 0x05) {
            PASSTHRU_MSG hdr;
            if (SafeRead(pInput, &hdr, 24)) {
                char data[700];
                int  n = (int)hdr.DataSize;
                if (n > (int)sizeof(data) / 2 - 1) n = (int)sizeof(data) / 2 - 1;
                DumpHex(data, sizeof(data), (const u8 *)pInput + 24, n);
                used = AppendFmt(extra, sizeof(extra), used,
                                 " proto=0x%lx in_len=%lu in=%s",
                                 (unsigned long)hdr.ProtocolID,
                                 (unsigned long)hdr.DataSize, data);
            }
        } else {
            char buf[160];
            DumpHex(buf, sizeof(buf), pInput, 64);
            used = AppendFmt(extra, sizeof(extra), used, " in=%s", buf);
        }
    }

    if (g_fatal || !pIoctl) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruIoctl", rc);
    } else {
        rc = pIoctl(ChannelID, IoctlID, pInput, pOutput);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);

    /* Выходной буфер — ПОСЛЕ вызова: ради него дамп и делается. */
    if (g_logArgs) {
        if (IoctlID == 0x03 && pOutput) {
            u32 v = 0;
            if (SafeRead(pOutput, &v, sizeof(v))) {
                used = AppendFmt(extra, sizeof(extra), used, " vbat=%lu",
                                 (unsigned long)v);
            }
        } else if (IoctlID == 0x05 && pInput) {
            PASSTHRU_MSG hdr;
            if (SafeRead(pInput, &hdr, 24)) {
                char data[700];
                int  n = (int)hdr.DataSize;
                if (n > (int)sizeof(data) / 2 - 1) n = (int)sizeof(data) / 2 - 1;
                DumpHex(data, sizeof(data), (const u8 *)pInput + 24, n);
                used = AppendFmt(extra, sizeof(extra), used, " ret_len=%lu out=%s",
                                 (unsigned long)hdr.DataSize, data);
            }
        } else if (pOutput) {
            char buf[160];
            DumpHex(buf, sizeof(buf), pOutput, 64);
            used = AppendFmt(extra, sizeof(extra), used, " out=%s", buf);
        }
    }
    (void)used;

    LogCall(seq, "PassThruIoctl", 1, ChannelID, rc, th, dur, extra);
    LeaveCriticalSection(&g_cs);
    return rc;
}

/* ------------------------------------------------------------------ */
/* vendor ordinals 1377-1379                                           */
/*                                                                     */
/* The real driver exports three undocumented entry points that         */
/* PCMflash uses for the Scanmatik K-line vendor protocol.  They must   */
/* stay transparent: x86 thunks log the call and tail-jump to the real  */
/* ordinal, so the stack is exactly the caller's (ported unchanged from */
/* the proven prototype, see docs/13 section 2).                        */
/*                                                                     */
/* rc is not observed here: the thunk leaves before the callee returns, */
/* so the vendor line reports rc=0 as the contract shape requires.      */
/* ------------------------------------------------------------------ */

/* Разобрать блок параметров вендорского вызова: `*(arg+8)` -> [count][ptr][tag,value]…
 *
 * Пара — два u32 ПО ЗНАЧЕНИЮ; теги 0x1AA8C7xx непрозрачны, их нельзя
 * разыменовывать (ReadProcessMemory даёт ERROR_PARTIAL_COPY 299 даже в момент
 * вызова). Поэтому читаем только блок и массив пар, всё остальное — как числа.
 */
static void VendorParamsText(const void *arg, char *dst, int cap)
{
    u32       block = 0, count = 0, ptr = 0;
    u32       pair[2];
    const u8 *pairs = NULL;
    int       i, used;

    if (!dst || cap <= 1) return;
    dst[0] = 0;
    if (!g_vendorParamPairs || !arg) return;
    if (!SafeRead((const u8 *)arg + 8, &block, sizeof(block)) || !block) {
        SetStr(dst, (DWORD)cap, "n/a");
        return;
    }
    if (!SafeRead((const void *)(uintptr_t)block, &count, sizeof(count))) {
        SetStr(dst, (DWORD)cap, "<unreadable>");
        return;
    }
    if (count > (u32)g_maxParamPairs) count = (u32)g_maxParamPairs;
    /* Пара может лежать по указателю из блока или сразу за ним: пробуем оба
     * варианта, чтобы не гадать по одной раскладке. */
    if (SafeRead((const u8 *)(uintptr_t)block + 4, &ptr, sizeof(ptr)) && ptr &&
        SafeRead((const void *)(uintptr_t)ptr, pair, sizeof(pair))) {
        pairs = (const u8 *)(uintptr_t)ptr;
    } else if (SafeRead((const u8 *)(uintptr_t)block + 8, pair, sizeof(pair))) {
        pairs = (const u8 *)(uintptr_t)block + 8;
    }
    used = AppendFmt(dst, cap, 0, "%lu:", (unsigned long)count);
    for (i = 0; i < (int)count; ++i) {
        if (!pairs || !SafeRead(pairs + (size_t)i * 8, pair, sizeof(pair))) break;
        used = AppendFmt(dst, cap, used, "%s0x%08lx=%lu",
                         i ? "," : "",
                         (unsigned long)pair[0], (unsigned long)pair[1]);
    }
}

static int VendorFullOp(ulong op)
{
    int i;
    for (i = 0; i < g_vendorFullOpN; ++i) {
        if ((ulong)g_vendorFullOp[i] == op) return 1;
    }
    return 0;
}

static int VendorOrdWanted(int ord)
{
    int i;
    for (i = 0; i < g_vendorOrdN; ++i) {
        if (g_vendorOrds[i] == ord) return 1;
    }
    return 0;
}

/* Одна строка на вендорский вызов (docs/13 §6.3): ord, op, arg, a2/a3, ret
 * (модуль+RVA вызывающего), rc, и для op из белого списка — mem/pre/params. */
static void LogVendor(int ord, ulong op, const void *arg, ulong a2, ulong a3,
                      const void *ret, ulong rc, DWORD th, ULONGLONG dur)
{
    char line[16384];
    char argtxt[32], rettxt[96], mem[2300], pre[220], params[1024];
    char a2mem[160], a3mem[160];
    int  full, used;

    full = g_logArgs && VendorOrdWanted(ord) && VendorFullOp(op);
    mem[0] = pre[0] = params[0] = a2mem[0] = a3mem[0] = 0;
    _snprintf(argtxt, sizeof(argtxt), "0x%p", arg);
    argtxt[sizeof(argtxt) - 1] = 0;
    AddrToModule(ret, rettxt, sizeof(rettxt));

    if (full) {
        int n = g_vendorArgBytes;
        int before = g_vendorBeforeBytes;
        if (n + before > g_maxDumpPerCall) {
            n = g_maxDumpPerCall;
            before = 0;
        }
        DumpHex(mem, sizeof(mem), arg, n);
        if (before > 0 && arg) {
            DumpHex(pre, sizeof(pre), (const u8 *)arg - before, before);
        }
        VendorParamsText(arg, params, sizeof(params));
        if (a2 && (const void *)(uintptr_t)a2 != arg) {
            DumpHex(a2mem, sizeof(a2mem), (const void *)(uintptr_t)a2, 64);
            if (!strcmp(a2mem, "<unreadable>")) a2mem[0] = 0;
        }
        if (a3 && (const void *)(uintptr_t)a3 != arg) {
            DumpHex(a3mem, sizeof(a3mem), (const void *)(uintptr_t)a3, 64);
            if (!strcmp(a3mem, "<unreadable>")) a3mem[0] = 0;
        }
    }

    used = AppendFmt(line, sizeof(line), 0,
                     "J2534 vendor ord=%d op=0x%lx arg=%s a2=0x%lx a3=0x%lx "
                     "ret=%s rc=%s th=%lu dur=%llu",
                     ord, op, argtxt, (unsigned long)a2, (unsigned long)a3,
                     rettxt, RcStr(rc), (ulong)th, dur);
    if (full) {
        used = AppendFmt(line, sizeof(line), used, " mem=%s pre=%s params=%s",
                         mem[0] ? mem : "-", pre[0] ? pre : "-",
                         params[0] ? params : "n/a");
        if (a2mem[0]) used = AppendFmt(line, sizeof(line), used, " a2mem=%s", a2mem);
        if (a3mem[0]) used = AppendFmt(line, sizeof(line), used, " a3mem=%s", a3mem);
    }
    (void)used;
    LogLine("%s", line);
}

#ifdef _M_IX86

static void *g_vendor[3];

/* a[-1] = return address, a[0] = first argument, a[1] = second argument */
static void LogVendorCall(int idx, const ulong *a)
{
    ulong      op = a ? a[0] : 0;
    ulong      arg = a ? a[1] : 0;
    LONGLONG   t0;

    EnsureInit();
    t0 = QpcNow();

    if (g_real) {
        if (!g_vendor[0]) g_vendor[0] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1377));
        if (!g_vendor[1]) g_vendor[1] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1378));
        if (!g_vendor[2]) g_vendor[2] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1379));
    }

    EnterCriticalSection(&g_cs);
    LogVendor(idx, op, (const void *)(uintptr_t)arg, 0, 0,
              (const void *)a[-1], 0, GetCurrentThreadId(), UsSince(t0));
    LeaveCriticalSection(&g_cs);
}

/* Fallback when the real driver has no such ordinal: return 7 (ERR_FAILED)
 * and pop the two arguments PCMflash passes, instead of jumping to NULL. */
__declspec(naked) static void VndMissing(void)
{
    __asm mov eax, 7
    __asm ret 8
}

__declspec(naked) void Vnd1377(void)
{
    __asm pushad
    __asm mov eax, esp
    __asm add eax, 36
    __asm push eax
    __asm push 1377
    __asm call LogVendorCall
    __asm add esp, 8
    __asm popad
    __asm cmp dword ptr [g_vendor], 0
    __asm je  fail
    __asm jmp dword ptr [g_vendor]
fail:
    __asm jmp VndMissing
}

__declspec(naked) void Vnd1378(void)
{
    __asm pushad
    __asm mov eax, esp
    __asm add eax, 36
    __asm push eax
    __asm push 1378
    __asm call LogVendorCall
    __asm add esp, 8
    __asm popad
    __asm cmp dword ptr [g_vendor+4], 0
    __asm je  fail2
    __asm jmp dword ptr [g_vendor+4]
fail2:
    __asm jmp VndMissing
}

__declspec(naked) void Vnd1379(void)
{
    __asm pushad
    __asm mov eax, esp
    __asm add eax, 36
    __asm push eax
    __asm push 1379
    __asm call LogVendorCall
    __asm add esp, 8
    __asm popad
    __asm cmp dword ptr [g_vendor+8], 0
    __asm je  fail3
    __asm jmp dword ptr [g_vendor+8]
fail3:
    __asm jmp VndMissing
}

#else /* x64: same ordinals, stubs only -- docs/13 section 7 */

/* На x64 трамплина к настоящему драйверу нет: ординалы только логируются,
 * вызов возвращает ERR_FAILED (как и раньше). Но аргументы читаются из
 * регистров по тому же __stdcall-соглашению, поэтому дамп и разбор параметров
 * работают одинаково на обеих разрядностях. */
static ulong VendorStub(int idx, ulong a0, ulong a1, ulong a2, ulong a3)
{
    EnsureInit();
    EnterCriticalSection(&g_cs);
    LogVendor(idx, a0, (const void *)(uintptr_t)a1, a2, a3,
              _ReturnAddress(), ERR_FAILED, GetCurrentThreadId(), 0);
    LeaveCriticalSection(&g_cs);
    return ERR_FAILED;
}

ulong Vnd1377(ulong a0, ulong a1, ulong a2, ulong a3) { return VendorStub(1377, a0, a1, a2, a3); }
ulong Vnd1378(ulong a0, ulong a1, ulong a2, ulong a3) { return VendorStub(1378, a0, a1, a2, a3); }
ulong Vnd1379(ulong a0, ulong a1, ulong a2, ulong a3) { return VendorStub(1379, a0, a1, a2, a3); }

#endif /* _M_IX86 */

/* ------------------------------------------------------------------ */

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
    } else if (reason == DLL_PROCESS_DETACH) {
        /* No critical section here: during process termination another thread
         * may still hold it.  The stop line is best effort by design. */
        if (g_hLog != INVALID_HANDLE_VALUE) {
            WriteFmt("# proxy stop: calls=%ld tx=%ld rx=%ld errors=%ld",
                     (long)g_calls, (long)g_tx, (long)g_rx, (long)g_errors);
            CloseHandle(g_hLog);
            g_hLog = INVALID_HANDLE_VALUE;
        }
        /* Keep the final state instead of deleting it: after the tool exits the
         * GUI shows "last run" with its counters right away, and the engine
         * prunes the file later. */
        WriteLiveFile("stopped");
        if (g_mutex) {
            CloseHandle(g_mutex);
            g_mutex = NULL;
        }
    }
    return TRUE;
}
