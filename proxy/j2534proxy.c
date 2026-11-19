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

typedef unsigned long ulong;   /* J2534 04.04: 4 bytes on x86 and on x64 (LLP64) */
typedef unsigned char u8;

/* ------------------------------------------------------------------ */
/* versions                                                            */
/* ------------------------------------------------------------------ */

/* Kept in sync with proxy\version.rc; the proxy reports it in the header
 * without pulling in version.dll (that would be a second dependency). */
#define PROXY_VERSION "1.0.0.120"
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

/* "C:\a\b.dll" -> "C:\a" */
static void DirOf(const char *path, char *dst, DWORD cap)
{
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

static void WriteHeader(void)
{
    SYSTEMTIME st;
    char       dir[MAX_PATH];

    GetLocalTime(&st);
    DirOf(g_dll, dir, MAX_PATH);

    WriteFmt("# capture start: label=J2534 proxy");
    /* active=1 is the machine-readable proof (for the Frida agent) that the
     * proxy really forwards: a named mutex plus this marker. */
    WriteFmt("# proxy: dll=\"%s\" real=\"%s\" pid=%lu bits=%d active=%d",
             g_dll, g_realPath[0] ? g_realPath : "", (ulong)GetCurrentProcessId(),
             g_bits, g_mutex ? 1 : 0);
    WriteFmt("# wall(start)=%04u-%02u-%02u %02u:%02u:%02u.%03u",
             (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
             (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
             (unsigned)st.wMilliseconds);
    WriteFmt("# api: %s dll=\"%s\" ver=\"%s\" path=\"%s\" pid=%lu bits=%d dec=1",
             PROXY_API, g_dllName, PROXY_VERSION, g_dll,
             (ulong)GetCurrentProcessId(), g_bits);
    WriteFmt("# agent: %s mode=proxy", g_dllName);
    WriteFmt("# device: name=\"%s\" vendor=\"%s\"", g_devName, g_devVendor);
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
    ReadIniStr("proxy", "LogDir", "", g_logDir, MAX_PATH);
    TrimA(g_logDir);
    g_maxData = (ulong)GetPrivateProfileIntA("proxy", "MaxDataBytes", PROXY_MAX_DATA, g_ini);
    if (g_maxData == 0 || g_maxData > PROXY_MAX_DATA) g_maxData = PROXY_MAX_DATA;

    /* ---- [device] -------------------------------------------------- */
    ReadIniStr("device", "Name", "Scanmatik - SM2 Proxy", g_devName, MAX_PATH);
    TrimA(g_devName);
    ReadIniStr("device", "Vendor", "DaVinci Cyber Engineering", g_devVendor, MAX_PATH);
    TrimA(g_devVendor);

    /* ---- environment overrides (priority 1, docs/13 section 4) ----- */
    (void)EnvStr("FTDI_J2534_REAL_DLL", g_realPath, MAX_PATH);
    (void)EnvStr("FTDI_J2534_PROXY_LOG", g_logExact, MAX_PATH);
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

/* One TX/RX frame.  `total` is the denominator of i=k/n: the number of input
 * messages for TX, the number of returned messages for RX. */
static void LogMsg(int isTx, ulong ch, LONG seq, ulong idx, ulong total,
                   ulong n_in, ulong n_out, DWORD th,
                   const PASSTHRU_MSG *m, ULONGLONG dur, ulong rc)
{
    char  svc[32];
    char  trunc[32];
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

    if (isTx) {
        InterlockedIncrement(&g_tx);
        LogLine("J2534 TX ch=%lu call=%ld i=%lu/%lu n_in=%lu n_out=%lu th=%lu ts=%lu "
                "flags=0x%lx proto=0x%02lx%s len=%lu%s dur=%llu rc=%s : %s",
                ch, seq, idx, total, n_in, n_out, (ulong)th, (ulong)m->Timestamp,
                (ulong)m->TxFlags, (ulong)m->ProtocolID, svc, size, trunc,
                dur, RcStr(rc), g_hex);
    } else {
        InterlockedIncrement(&g_rx);
        LogLine("J2534 RX ch=%lu call=%ld i=%lu/%lu n_in=%lu n_out=%lu th=%lu ts=%lu "
                "rxs=0x%lx proto=0x%02lx%s len=%lu%s dur=%llu rc=%s : %s",
                ch, seq, idx, total, n_in, n_out, (ulong)th, (ulong)m->Timestamp,
                (ulong)m->RxStatus, (ulong)m->ProtocolID, svc, size, trunc,
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
    LogLine("J2534 connect dev=%lu ch=%lu proto=0x%02lx flags=0x%lx baud=%lu "
            "rc=%s gen=%ld th=%lu dur=%llu",
            DeviceID, ch, ProtocolID, Flags, BaudRate, RcStr(rc),
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
    LogCall(seq, "PassThruSetProgrammingVoltage", 0, 0, rc, th, dur, NULL);
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
    LogCall(seq, "PassThruReadVersion", 0, 0, rc, th, dur, NULL);
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
    char        extra[96];

    EnsureInit();
    EnterCriticalSection(&g_cs);
    seq = InterlockedIncrement(&g_calls);
    th  = GetCurrentThreadId();
    t0  = QpcNow();

    if (g_fatal || !pIoctl) {
        rc = ERR_DEVICE_NOT_CONNECTED;
        EmitForwardError("PassThruIoctl", rc);
    } else {
        rc = pIoctl(ChannelID, IoctlID, pInput, pOutput);
        if (rc != STATUS_NOERROR) CountError();
    }

    dur = UsSince(t0);
    _snprintf(extra, sizeof(extra), " ioctl=0x%02lx(%s)", IoctlID, IoctlName(IoctlID));
    extra[sizeof(extra) - 1] = 0;
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

#ifdef _M_IX86

static void *g_vendor[3];

/* a[-1] = return address, a[0] = first argument, a[1] = second argument */
static void LogVendorCall(int idx, const ulong *a)
{
    ulong     op = a ? a[0] : 0;
    LONGLONG  t0;

    EnsureInit();
    t0 = QpcNow();

    if (g_real) {
        if (!g_vendor[0]) g_vendor[0] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1377));
        if (!g_vendor[1]) g_vendor[1] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1378));
        if (!g_vendor[2]) g_vendor[2] = (void *)GetProcAddress(g_real, (LPCSTR)MAKEINTRESOURCE(1379));
    }

    EnterCriticalSection(&g_cs);
    LogLine("J2534 vendor ord=%d op=0x%lx rc=0 th=%lu dur=%llu",
            idx, op, (ulong)GetCurrentThreadId(), UsSince(t0));
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

static ulong VendorStub(int idx, DWORD th)
{
    EnsureInit();
    EnterCriticalSection(&g_cs);
    LogLine("J2534 vendor ord=%d rc=%lu th=%lu dur=0", idx, ERR_FAILED, (ulong)th);
    LeaveCriticalSection(&g_cs);
    return ERR_FAILED;
}

ulong Vnd1377(void) { return VendorStub(1377, GetCurrentThreadId()); }
ulong Vnd1378(void) { return VendorStub(1378, GetCurrentThreadId()); }
ulong Vnd1379(void) { return VendorStub(1379, GetCurrentThreadId()); }

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
        if (g_mutex) {
            CloseHandle(g_mutex);
            g_mutex = NULL;
        }
    }
    return TRUE;
}
