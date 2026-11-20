/*
 * vendor_host.c -- 32-bit fixture that proves the proxy dumps vendor arguments.
 *
 * Loads the real x86 j2534proxy.dll over fakevendor.dll, calls the vendor
 * ordinal 1377 with the 11-pair GPT block that PCMflash builds, then checks
 * the journal: layer-independent parts of docs/13 §6.3 and the acceptance
 * values from the BitBox run (5000, 1, 1, 2, 64000, 32000, …).
 *
 * Usage: vendor_host.exe <proxy.dll> <fake.dll> <log path>
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long ulong;
typedef unsigned int  u32;

typedef struct PTMSG {
    ulong ProtocolID;
    ulong RxStatus;
    ulong TxFlags;
    ulong Timestamp;
    ulong DataSize;
    ulong ExtraDataIndex;
    unsigned char Data[4128];
} PTMSG;

static int g_checks = 0;
static int g_failed = 0;

static void Check(int ok, const char *what)
{
    printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
    ++g_checks;
    if (!ok) ++g_failed;
}

static int Has(const char *text, const char *needle)
{
    return strstr(text, needle) != NULL;
}

static char *ReadAll(const char *path)
{
    HANDLE h;
    DWORD  size, got = 0;
    char  *buf;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 4u * 1024u * 1024u) {
        CloseHandle(h);
        return NULL;
    }
    buf = (char *)malloc(size + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, buf, size, &got, NULL)) got = 0;
    CloseHandle(h);
    buf[got] = 0;
    return buf;
}

/* Одиннадцать пар конфигурации GPT — ровно те, что видел BitBox на живом
 * прогоне PCMflash (vendor-1377-decoded-2026-11-20.md). */
static const u32 kTags[11] = {
    0x1AA8C780, 0x1AA8C721, 0x1AA8C722, 0x1AA8C723, 0x1AA8C724, 0x1AA8C725,
    0x1AA8C751, 0x1AA8C752, 0x1AA8C753, 0x1AA8C754, 0x1AA8C755
};
static const u32 kVals[11] = {
    5000, 1, 1, 2, 64000, 32000, 1, 1, 1, 100000, 50000
};

int main(int argc, char **argv)
{
    HMODULE   proxy;
    ulong (__stdcall *pOpen)(void *, ulong *);
    ulong (__stdcall *pConnect)(ulong, ulong, ulong, ulong, ulong *);
    ulong (__stdcall *pVoltage)(ulong, ulong, ulong);
    ulong (__stdcall *pIoctl)(ulong, ulong, void *, void *);
    ulong (__stdcall *pClose)(ulong);
    ulong (__stdcall *pVendor)(ulong, ulong);
    ulong     dev = 0, ch = 0, rc;
    u32       i;
    PTMSG       PTMSG;
    char     *log;

    /* Блок параметров: [count][ptr][tag,value]… — пара два u32 по значению. */
    struct {
        u32 count;
        u32 ptr;
        u32 pairs[11][2];
    } block;
    /* Аргумент вызова: по смещению +8 лежит указатель на блок (x86, 4 байта). */
    struct {
        u32 pad0;
        u32 pad1;
        u32 blockAddr;
    } arg;

    if (argc < 4) {
        printf("usage: vendor_host.exe <proxy.dll> <fake.dll> <log>\n");
        return 2;
    }

    SetEnvironmentVariableA("FTDI_J2534_REAL_DLL", argv[2]);
    SetEnvironmentVariableA("FTDI_J2534_PROXY_LOG", argv[3]);
    DeleteFileA(argv[3]);

    proxy = LoadLibraryA(argv[1]);
    if (!proxy) {
        printf("FAIL LoadLibrary(proxy) err=%lu\n", (unsigned long)GetLastError());
        return 1;
    }

    pOpen    = (ulong (__stdcall *)(void *, ulong *))GetProcAddress(proxy, "PassThruOpen");
    pConnect = (ulong (__stdcall *)(ulong, ulong, ulong, ulong, ulong *))GetProcAddress(proxy, "PassThruConnect");
    pVoltage = (ulong (__stdcall *)(ulong, ulong, ulong))GetProcAddress(proxy, "PassThruSetProgrammingVoltage");
    pIoctl   = (ulong (__stdcall *)(ulong, ulong, void *, void *))GetProcAddress(proxy, "PassThruIoctl");
    pClose   = (ulong (__stdcall *)(ulong))GetProcAddress(proxy, "PassThruClose");
    pVendor  = (ulong (__stdcall *)(ulong, ulong))GetProcAddress(proxy, MAKEINTRESOURCEA(1377));
    if (!pOpen || !pConnect || !pVoltage || !pIoctl || !pClose || !pVendor) {
        printf("FAIL: not all entry points resolved (vendor=%p)\n", (void *)pVendor);
        return 1;
    }

    block.count = 11;
    block.ptr = (u32)(UINT_PTR)&block.pairs[0][0];
    for (i = 0; i < 11; ++i) {
        block.pairs[i][0] = kTags[i];
        block.pairs[i][1] = kVals[i];
    }
    arg.pad0 = 0;
    arg.pad1 = 0;
    arg.blockAddr = (u32)(UINT_PTR)&block;

    rc = pOpen(NULL, &dev);
    Check(rc == 0 && dev == 1, "PassThruOpen -> rc=0 dev=1");
    rc = pConnect(dev, 0x8003, 0x1000, 57600, &ch);
    Check(rc == 0 && ch == 1, "PassThruConnect -> rc=0 ch=1");

    rc = pVoltage(dev, 12, 5000);
    Check(rc == 0, "PassThruSetProgrammingVoltage(12, 5000) -> rc=0");

    memset(&PTMSG, 0, sizeof(PTMSG));
    PTMSG.ProtocolID = 0x8003;
    PTMSG.DataSize = 5;
    PTMSG.Data[0] = 0x00; PTMSG.Data[1] = 0x03; PTMSG.Data[2] = 0x80;
    PTMSG.Data[3] = 0xE1; PTMSG.Data[4] = 0x01;
    rc = pIoctl(ch, 0x05, &PTMSG, NULL);
    Check(rc == 0, "PassThruIoctl(FAST_INIT) -> rc=0");

    rc = pVendor(0x0B, (ulong)(UINT_PTR)&arg);
    Check(rc == 0, "vendor 1377 op=0x0b -> rc=0");

    pClose(dev);
    FreeLibrary(proxy);

    log = ReadAll(argv[3]);
    if (!log) {
        printf("FAIL journal was not created: %s\n", argv[3]);
        return 1;
    }

    Check(Has(log, "J2534 connect dev=1 ch=1 proto=0x8003 protocol=0x8003"),
          "connect: protocol/flags/baud");
    Check(Has(log, "pin=12 voltage=5000"),
          "SetProgrammingVoltage: pin=12 voltage=5000");
    Check(Has(log, "ioctl=0x05(FAST_INIT)") && Has(log, "in_len=5") &&
          Has(log, "in=000380e101"),
          "FAST_INIT: входной буфер");
    Check(Has(log, "ret_len=5") && Has(log, "out=0003677f34"),
          "FAST_INIT: ответ драйвера");
    Check(Has(log, "vendor ord=1377 op=0xb"), "vendor: строка вызова");
    Check(Has(log, "ret=vendor_host.exe+0x"), "vendor: ret = модуль+RVA");
    Check(Has(log, "mem=") && !Has(log, "mem=<unreadable>"), "vendor: hexdump arg");
    Check(Has(log, "pre=") && !Has(log, "pre=<unreadable>"), "vendor: дамп перед arg");

    /* params=11:tag=value,… — сверяем все одиннадцать пар по тегу. */
    for (i = 0; i < 11; ++i) {
        char pair[48];
        _snprintf(pair, sizeof(pair), "0x%08x=%lu", kTags[i], (unsigned long)kVals[i]);
        pair[sizeof(pair) - 1] = 0;
        {
            char what[80];
            _snprintf(what, sizeof(what), "params: %s", pair);
            what[sizeof(what) - 1] = 0;
            Check(Has(log, "params=11:") && Has(log, pair), what);
        }
    }

    free(log);
    printf("\nchecks: %d passed, failed=%d\n", g_checks - g_failed, g_failed);
    printf("%s\n", g_failed ? "VENDOR DUMP FAILED" : "VENDOR DUMP OK");
    return g_failed ? 1 : 0;
}
