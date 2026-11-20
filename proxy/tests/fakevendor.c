/*
 * fakevendor.c -- 32-bit fake J2534 driver for the vendor-argument fixture.
 *
 * Exports the PassThru entry points the fixture calls and the three unnamed
 * ordinals 1377/1378/1379 (exported by number, no name), exactly like
 * Scanmatik's smj2534.dll.  Nothing touches hardware: the goal is to let the
 * real x86 proxy thunks run so their journal lines can be verified.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef unsigned long ulong;

typedef struct PTMSG {
    ulong ProtocolID;
    ulong RxStatus;
    ulong TxFlags;
    ulong Timestamp;
    ulong DataSize;
    ulong ExtraDataIndex;
    unsigned char Data[4128];
} PTMSG;

__declspec(dllexport) ulong __stdcall PassThruOpen(void *name, ulong *dev)
{
    (void)name;
    if (dev) *dev = 1;
    return 0;
}

__declspec(dllexport) ulong __stdcall PassThruClose(ulong dev)
{
    (void)dev;
    return 0;
}

__declspec(dllexport) ulong __stdcall PassThruConnect(ulong dev, ulong proto,
                                                      ulong flags, ulong baud,
                                                      ulong *ch)
{
    (void)dev; (void)proto; (void)flags; (void)baud;
    if (ch) *ch = 1;
    return 0;
}

__declspec(dllexport) ulong __stdcall PassThruDisconnect(ulong ch)
{
    (void)ch;
    return 0;
}

__declspec(dllexport) ulong __stdcall PassThruSetProgrammingVoltage(ulong dev,
                                                                    ulong pin,
                                                                    ulong mv)
{
    (void)dev; (void)pin; (void)mv;
    return 0;
}

/* FAST_INIT: the driver answers with five bytes, like a real ECU would. */
__declspec(dllexport) ulong __stdcall PassThruIoctl(ulong ch, ulong id,
                                                    void *in, void *out)
{
    (void)ch; (void)out;
    if (id == 0x05 && in) {
        PTMSG *m = (PTMSG *)in;
        static const unsigned char reply[5] = { 0x00, 0x03, 0x67, 0x7f, 0x34 };
        unsigned i;
        for (i = 0; i < sizeof(reply); ++i) m->Data[i] = reply[i];
        m->DataSize = (ulong)sizeof(reply);
    }
    return 0;
}

/* Ordinal bodies: the proxy tail-jumps here and the caller sees rc=0. */
static ulong __stdcall VendorBody(ulong a, ulong b)
{
    (void)a; (void)b;
    return 0;
}

__declspec(dllexport) ulong __stdcall V1377(ulong a, ulong b) { return VendorBody(a, b); }
__declspec(dllexport) ulong __stdcall V1378(ulong a, ulong b) { return VendorBody(a, b); }
__declspec(dllexport) ulong __stdcall V1379(ulong a, ulong b) { return VendorBody(a, b); }

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)reason; (void)r;
    return TRUE;
}
