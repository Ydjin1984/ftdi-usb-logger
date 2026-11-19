/*
 * smoke.c -- x64 smoke test of the FTDI/USB Logger J2534 proxy.
 *
 * Loads proxy\out\x64\j2534proxy.dll, points it at the test driver
 * tests\e2e\fake_j2534\target\release\fake_j2534.dll (through the documented
 * FTDI_J2534_REAL_DLL override), calls all 14 Pass-Thru entry points and then
 * checks the journal the proxy produced:
 *
 *   - the header of docs/13 section 6 (capture start / proxy: / wall(start)= /
 *     api: / agent:), including active=1 from the mutex marker;
 *   - "J2534 open", "J2534 connect" (and connect-enter), "J2534 TX",
 *     "J2534 RX", "J2534 call" and the final "# proxy stop:" line;
 *   - every exchange line uses the "[+<sec>.<6 digits>s]" prefix, the TX
 *     payload is exactly the lower-case hex we wrote, and svc= follows the
 *     vendor-protocol rule;
 *   - the journal is appended, not overwritten: a second load of the proxy in
 *     the same process adds a second header and a second stop line.
 *
 * Exit code 0 = all checks passed, 1 = failure (details on stdout).
 *
 * Usage: smoke.exe [log-path] [fake-dll-path] [proxy-dll-path]
 * All arguments are optional; defaults are derived from the location of this
 * executable (proxy\tests\out\x64\smoke.exe).
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long ulong;
typedef unsigned char u8;

typedef struct _PASSTHRU_MSG {
    ulong ProtocolID;
    ulong RxStatus;
    ulong TxFlags;
    ulong Timestamp;
    ulong DataSize;
    ulong ExtraDataIndex;
    u8    Data[4128];
} PASSTHRU_MSG;

#define STATUS_NOERROR 0x00UL
#define ERR_FAILED     0x07UL

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

static int g_failed = 0;
static int g_checks = 0;

static void Ok(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("  ok   ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    ++g_checks;
}

static void Fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    printf("  FAIL ");
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    g_failed = 1;
}

static void Check(int cond, const char *what)
{
    if (cond) Ok("%s", what);
    else      Fail("%s", what);
}

static void SetMsg(PASSTHRU_MSG *m, ulong proto, const u8 *data, ulong n)
{
    memset(m, 0, sizeof(*m));
    m->ProtocolID = proto;
    m->DataSize = n;
    if (n > 0) memcpy(m->Data, data, n);
}

/* path relative to the directory of this executable, normalized */
static void JoinExe(const char *rel, char *dst, DWORD cap)
{
    char full[MAX_PATH];
    char joined[MAX_PATH];

    GetModuleFileNameA(NULL, full, MAX_PATH);
    {
        char *p = strrchr(full, '\\');
        if (p) *p = 0;
    }
    _snprintf(joined, sizeof(joined), "%s\\%s", full, rel);
    joined[sizeof(joined) - 1] = 0;
    if (!GetFullPathNameA(joined, cap, dst, NULL)) lstrcpynA(dst, joined, (int)cap);
}

static int ReadWholeFile(const char *path, char **out, DWORD *sizeOut)
{
    HANDLE h;
    DWORD  size, got = 0;
    char  *buf;

    *out = NULL;
    *sizeOut = 0;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 4u * 1024u * 1024u) {
        CloseHandle(h);
        return 0;
    }
    buf = (char *)malloc(size + 1);
    if (!buf) { CloseHandle(h); return 0; }
    if (!ReadFile(h, buf, size, &got, NULL)) got = 0;
    CloseHandle(h);
    buf[got] = 0;
    *out = buf;
    *sizeOut = got;
    return got > 0;
}

static int Has(const char *log, const char *needle)
{
    return strstr(log, needle) != NULL;
}

static int CountOf(const char *log, const char *needle)
{
    int         n = 0;
    const char *p = log;
    size_t      len = strlen(needle);

    while ((p = strstr(p, needle)) != NULL) {
        ++n;
        p += len;
    }
    return n;
}

/* "[+<sec>.<6 digits>s] " */
static int PrefixOk(const char *p, size_t len)
{
    const char *dot;
    size_t      i;

    if (len < 10 || p[0] != '[' || p[1] != '+') return 0;
    dot = (const char *)memchr(p + 2, '.', len - 2);
    if (!dot || dot == p + 2) return 0;
    for (i = 2; p + i < dot; ++i) {
        if (p[i] < '0' || p[i] > '9') return 0;
    }
    if ((size_t)(dot - p) + 8 > len) return 0;
    for (i = 1; i <= 6; ++i) {
        if (dot[i] < '0' || dot[i] > '9') return 0;
    }
    return dot[7] == 's' && dot[8] == ']';
}

static int CheckLineShapes(const char *log, int *linesOut)
{
    const char *p = log;
    int         lines = 0;
    int         badTs = 0;
    int         badEmpty = 0;

    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t      len = eol ? (size_t)(eol - p) : strlen(p);

        if (len > 0 && p[len - 1] == '\r') --len;
        ++lines;

        if (len == 0) {
            ++badEmpty;
        } else if (p[0] == '[') {
            if (!PrefixOk(p, len)) ++badTs;
        }

        if (!eol) break;
        p = eol + 1;
    }

    *linesOut = lines;
    if (badTs) Fail("%d exchange line(s) do not use [+<sec>.<6 digits>s]", badTs);
    if (badEmpty) Fail("%d empty line(s) in the journal", badEmpty);
    return badTs == 0 && badEmpty == 0;
}

/* payload (after " : ") of the first line containing marker */
static int FirstPayload(const char *log, const char *marker, char *dst, size_t cap)
{
    const char *p = strstr(log, marker);
    size_t      i = 0;

    dst[0] = 0;
    if (!p) return 0;
    p = strstr(p, " : ");
    if (!p) return 0;
    p += 3;
    while (p[i] && p[i] != '\r' && p[i] != '\n' && i + 1 < cap) {
        dst[i] = p[i];
        ++i;
    }
    dst[i] = 0;
    while (i > 0 && dst[i - 1] == ' ') dst[--i] = 0;
    return 1;
}

/* one open/connect/write/read/close round against the fake driver */
static void RunSession(HMODULE hProxy, PFN_OPEN pOpen, PFN_CLOSE pClose,
                       PFN_CONNECT pConnect, PFN_DISCONNECT pDisconnect,
                       PFN_WRITEMSGS pWriteMsgs, PFN_READMSGS pReadMsgs)
{
    ulong       rc, dev = 0, ch = 0, num;
    PASSTHRU_MSG tx[2];
    PASSTHRU_MSG rx[4];
    const u8    tx0[] = { 0x00, 0x02, 0x27, 0x7f };
    const u8    tx1[] = { 0x00, 0x01, 0x3e };
    int         tries = 0;

    (void)hProxy;

    rc = pOpen("Scanmatik - SM2 Proxy", &dev);
    Check(rc == STATUS_NOERROR && dev == 1, "PassThruOpen -> rc=0 dev=1");

    rc = pConnect(dev, 0x8003, 0x1000, 57600, &ch);
    Check(rc == STATUS_NOERROR && ch == 1, "PassThruConnect -> rc=0 ch=1");

    SetMsg(&tx[0], 0x8003, tx0, 4);
    SetMsg(&tx[1], 0x8003, tx1, 3);
    num = 2;
    rc = pWriteMsgs(ch, tx, &num, 1000);
    Check(rc == STATUS_NOERROR && num == 2, "PassThruWriteMsgs -> rc=0 n=2/2");

    num = 0;
    do {
        num = 4;
        rc = pReadMsgs(ch, rx, &num, 0);
        ++tries;
    } while (num == 0 && tries < 6);
    Check(num > 0, "PassThruReadMsgs -> at least one frame");

    rc = pDisconnect(ch);
    Check(rc == STATUS_NOERROR, "PassThruDisconnect -> rc=0");

    rc = pClose(dev);
    Check(rc == STATUS_NOERROR, "PassThruClose -> rc=0");
}

int main(int argc, char **argv)
{
    char        proxyPath[MAX_PATH];
    char        fakePath[MAX_PATH];
    char        logPath[MAX_PATH];
    HMODULE     hProxy;
    FARPROC     f[14];
    const char *names[14];
    int         i, missing = 0;

    PFN_OPEN          pOpen;
    PFN_CLOSE         pClose;
    PFN_CONNECT       pConnect;
    PFN_DISCONNECT    pDisconnect;
    PFN_READMSGS      pReadMsgs;
    PFN_WRITEMSGS     pWriteMsgs;
    PFN_STARTPERIODIC pStartPeriodic;
    PFN_STOPPERIODIC  pStopPeriodic;
    PFN_STARTFILTER   pStartFilter;
    PFN_STOPFILTER    pStopFilter;
    PFN_SETVOLTAGE    pSetVoltage;
    PFN_READVERSION   pReadVersion;
    PFN_GETLASTERROR  pGetLastError;
    PFN_IOCTL         pIoctl;

    ulong       rc, dev = 0, ch = 0, filterId = 0, msgId = 0;
    PASSTHRU_MSG inMsg, outMsg;
    char        api[64], dllVer[64], fw[64], errText[256];
    const u8    tx0[] = { 0x00, 0x02, 0x27, 0x7f };
    char       *log = NULL;
    DWORD       logSize = 0, logSize2 = 0;
    int         lines = 0;
    char        payload[256];

    names[0]  = "PassThruOpen";
    names[1]  = "PassThruClose";
    names[2]  = "PassThruConnect";
    names[3]  = "PassThruDisconnect";
    names[4]  = "PassThruReadMsgs";
    names[5]  = "PassThruWriteMsgs";
    names[6]  = "PassThruStartPeriodicMsg";
    names[7]  = "PassThruStopPeriodicMsg";
    names[8]  = "PassThruStartMsgFilter";
    names[9]  = "PassThruStopMsgFilter";
    names[10] = "PassThruSetProgrammingVoltage";
    names[11] = "PassThruReadVersion";
    names[12] = "PassThruGetLastError";
    names[13] = "PassThruIoctl";

    /* ---- paths ------------------------------------------------------ */
    JoinExe("..\\..\\..\\out\\x64\\j2534proxy.dll", proxyPath, MAX_PATH);

    if (argc > 1 && argv[1][0]) lstrcpynA(logPath, argv[1], MAX_PATH);
    else JoinExe("..\\..\\smoke.log", logPath, MAX_PATH);

    if (argc > 2 && argv[2][0]) lstrcpynA(fakePath, argv[2], MAX_PATH);
    else JoinExe("..\\..\\..\\..\\tests\\e2e\\fake_j2534\\target\\release\\fake_j2534.dll",
                 fakePath, MAX_PATH);

    if (argc > 3 && argv[3][0]) lstrcpynA(proxyPath, argv[3], MAX_PATH);

    printf("== smoke: FTDI/USB Logger J2534 proxy (x64) ==\n");
    printf("proxy: %s\n", proxyPath);
    printf("real : %s\n", fakePath);
    printf("log  : %s\n", logPath);
    printf("\n");

    if (GetFileAttributesA(proxyPath) == INVALID_FILE_ATTRIBUTES) {
        printf("FAIL proxy DLL not found (build it with proxy\\build.ps1 first)\n");
        return 1;
    }
    if (GetFileAttributesA(fakePath) == INVALID_FILE_ATTRIBUTES) {
        printf("FAIL fake driver not found: %s\n", fakePath);
        return 1;
    }
    DeleteFileA(logPath);   /* deterministic start; append is checked below */

    /* documented priority 1 sources: no ini needed for the test */
    SetEnvironmentVariableA("FTDI_J2534_REAL_DLL", fakePath);
    SetEnvironmentVariableA("FTDI_J2534_PROXY_LOG", logPath);
    SetEnvironmentVariableA("FTDI_J2534_PROXY_OFF", NULL);

    /* ---- load the proxy and resolve all 14 entry points ------------- */
    hProxy = LoadLibraryA(proxyPath);
    if (!hProxy) {
        printf("FAIL LoadLibrary(proxy) err=%lu\n", (ulong)GetLastError());
        return 1;
    }
    for (i = 0; i < 14; ++i) {
        f[i] = GetProcAddress(hProxy, names[i]);
        if (!f[i]) { printf("  FAIL export missing: %s\n", names[i]); missing = 1; }
    }
    if (missing) return 1;
    Ok("all 14 Pass-Thru exports resolved");

    pOpen          = (PFN_OPEN)f[0];
    pClose         = (PFN_CLOSE)f[1];
    pConnect       = (PFN_CONNECT)f[2];
    pDisconnect    = (PFN_DISCONNECT)f[3];
    pReadMsgs      = (PFN_READMSGS)f[4];
    pWriteMsgs     = (PFN_WRITEMSGS)f[5];
    pStartPeriodic = (PFN_STARTPERIODIC)f[6];
    pStopPeriodic  = (PFN_STOPPERIODIC)f[7];
    pStartFilter   = (PFN_STARTFILTER)f[8];
    pStopFilter    = (PFN_STOPFILTER)f[9];
    pSetVoltage    = (PFN_SETVOLTAGE)f[10];
    pReadVersion   = (PFN_READVERSION)f[11];
    pGetLastError  = (PFN_GETLASTERROR)f[12];
    pIoctl         = (PFN_IOCTL)f[13];

    /* ---- exercise the API against the fake driver ------------------- */
    RunSession(hProxy, pOpen, pClose, pConnect, pDisconnect, pWriteMsgs, pReadMsgs);

    api[0] = dllVer[0] = fw[0] = 0;
    dev = 1;
    ch = 1;
    /* 04.04 order: firmware, DLL version, API version */
    rc = pReadVersion(dev, fw, dllVer, api);
    Check(rc == STATUS_NOERROR && strcmp(api, "04.04") == 0,
          "PassThruReadVersion -> rc=0 api=\"04.04\"");

    errText[0] = 0;
    rc = pGetLastError(errText);
    Check(rc == STATUS_NOERROR, "PassThruGetLastError -> rc=0");

    SetMsg(&inMsg, 0x8003, tx0, 4);
    memset(&outMsg, 0, sizeof(outMsg));
    rc = pIoctl(ch, 0x05, &inMsg, &outMsg);
    Check(rc == STATUS_NOERROR, "PassThruIoctl(FAST_INIT) -> rc=0");

    SetMsg(&inMsg, 0x8003, tx0, 4);
    rc = pStartFilter(ch, 1, &inMsg, &inMsg, NULL, &filterId);
    Check(rc == STATUS_NOERROR && filterId == 1, "PassThruStartMsgFilter -> rc=0 id=1");

    rc = pStopFilter(ch, filterId);
    Check(rc == STATUS_NOERROR, "PassThruStopMsgFilter -> rc=0");

    SetMsg(&inMsg, 0x8003, tx0, 4);
    rc = pStartPeriodic(ch, &inMsg, &msgId, 100);
    Check(rc == STATUS_NOERROR && msgId == 7, "PassThruStartPeriodicMsg -> rc=0 id=7");

    rc = pStopPeriodic(ch, msgId);
    Check(rc == STATUS_NOERROR, "PassThruStopPeriodicMsg -> rc=0");

    rc = pSetVoltage(dev, 15, 0);
    Check(rc == STATUS_NOERROR, "PassThruSetProgrammingVoltage -> rc=0");

#ifdef _WIN64
    {
        typedef ulong (*PFN_VENDOR)(void);
        PFN_VENDOR v = (PFN_VENDOR)GetProcAddress(hProxy, (LPCSTR)MAKEINTRESOURCEA(1377));
        if (!v) {
            Fail("ordinal 1377 is not exported");
        } else {
            ulong vrc = v();
            Check(vrc == ERR_FAILED, "ordinal 1377 stub -> 7 (ERR_FAILED, x64)");
        }
    }
#endif

    /* ---- unload: DllMain(DETACH) must write the stop line ----------- */
    FreeLibrary(hProxy);
    Ok("proxy unloaded (DllMain DLL_PROCESS_DETACH)");

    /* ---- journal ---------------------------------------------------- */
    if (!ReadWholeFile(logPath, &log, &logSize)) {
        printf("FAIL journal was not created: %s\n", logPath);
        return 1;
    }
    printf("\njournal: %s (%lu bytes)\n", logPath, (ulong)logSize);

    Check(Has(log, "# capture start: label=J2534 proxy"),        "header: # capture start");
    Check(Has(log, "# proxy: dll=\"") && Has(log, "active=1"),   "header: # proxy: ... active=1");
    Check(Has(log, "# wall(start)="),                            "header: # wall(start)=");
    Check(Has(log, "# api: 04.04 "),                             "header: # api: 04.04");
    Check(Has(log, "# agent: j2534proxy.dll mode=proxy"),        "header: # agent:");
    Check(Has(log, "J2534 open name=\"Scanmatik - SM2 Proxy\""), "J2534 open");
    Check(Has(log, "J2534 connect-enter "),                      "J2534 connect-enter");
    Check(Has(log, "J2534 connect dev=1 ch=1 "),                 "J2534 connect");
    Check(Has(log, "J2534 TX ch=1 call="),                       "J2534 TX");
    Check(Has(log, "J2534 RX ch=1 call="),                       "J2534 RX");
    Check(Has(log, "J2534 call ch=1 call="),                     "J2534 call");
    Check(Has(log, "svc=0x27"),                                  "svc=0x27 for proto 0x8003");
    Check(Has(log, "len=4 dur="),                                "len=/dur= on TX");
    Check(CheckLineShapes(log, &lines),                          "every line has [+<sec>.<6 digits>s]");
    Check(lines >= 20, "journal has enough lines");

    if (FirstPayload(log, "J2534 TX ch=1 call=", payload, sizeof(payload))) {
        Check(strcmp(payload, "00 02 27 7f") == 0, "TX payload is exact lower-case hex");
    } else {
        Fail("TX payload not found");
    }

    Check(Has(log, "# proxy stop: calls="), "final # proxy stop line");
    {
        const char *p = strstr(log, "# proxy stop:");
        if (p) {
            char   stop[128];
            size_t n = 0;
            while (p[n] && p[n] != '\r' && p[n] != '\n' && n + 1 < sizeof(stop)) {
                stop[n] = p[n];
                ++n;
            }
            stop[n] = 0;
            printf("       %s\n", stop);
        }
    }

    free(log);
    log = NULL;

    /* ---- append, not overwrite: load the proxy once more ------------ */
    hProxy = LoadLibraryA(proxyPath);
    if (!hProxy) {
        Fail("second LoadLibrary(proxy) err=%lu", (ulong)GetLastError());
    } else {
        (void)pOpen("Scanmatik - SM2 Proxy", &dev);
        (void)pClose(dev);
        FreeLibrary(hProxy);
        if (!ReadWholeFile(logPath, &log, &logSize2)) {
            Fail("journal disappeared after the second load");
        } else {
            int headers = CountOf(log, "# capture start:");
            int stops   = CountOf(log, "# proxy stop:");
            printf("\nappend check: %lu -> %lu bytes, headers=%d stops=%d\n",
                   (ulong)logSize, (ulong)logSize2, headers, stops);
            Check(logSize2 > logSize, "journal grew (file was not overwritten)");
            Check(headers == 2 && stops == 2, "second load appended its own header/stop");
            free(log);
        }
    }

    printf("\nchecks: %d passed, failed=%d\n", g_checks, g_failed ? 1 : 0);
    printf("%s\n", g_failed ? "SMOKE FAILED" : "SMOKE OK");
    return g_failed ? 1 : 0;
}
