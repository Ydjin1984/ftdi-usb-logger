"""Фикстура «два слоя»: приложение → j2534proxy.dll → fake_j2534.dll.

Нужна, чтобы проверить связывание вызовов: каждая посылка видна дважды —
на входе в прокси и на входе в драйвер под ней. Запускается как обычный
процесс, к которому затем подключается движок (attach по pid).
"""
import ctypes
import sys
import time


class Msg(ctypes.Structure):
    _fields_ = [
        ("ProtocolID", ctypes.c_ulong),
        ("RxStatus", ctypes.c_ulong),
        ("TxFlags", ctypes.c_ulong),
        ("Timestamp", ctypes.c_ulong),
        ("DataSize", ctypes.c_ulong),
        ("ExtraDataIndex", ctypes.c_ulong),
        ("Data", ctypes.c_ubyte * 4128),
    ]


def main() -> int:
    dll = ctypes.WinDLL(sys.argv[1])
    pause = float(sys.argv[2]) if len(sys.argv) > 2 else 7.0

    dev = ctypes.c_ulong(0)
    rc = dll.PassThruOpen(None, ctypes.byref(dev))
    print("open rc=%s dev=%s" % (rc, dev.value), flush=True)

    ch = ctypes.c_ulong(0)
    rc = dll.PassThruConnect(dev, 0x8003, 0x1000, 57600, ctypes.byref(ch))
    print("connect rc=%s ch=%s" % (rc, ch.value), flush=True)

    # Пауза: движок успевает подключиться, и весь обмен попадает в захват.
    time.sleep(pause)

    for i in range(3):
        m = Msg()
        m.ProtocolID = 0x8003
        m.DataSize = 5
        m.Data[0], m.Data[1], m.Data[2] = 0x00, 0x03, 0x80
        m.Data[3], m.Data[4] = 0xE1, 0x01 + i
        n = ctypes.c_ulong(1)
        rc = dll.PassThruWriteMsgs(ch, ctypes.byref(m), ctypes.byref(n), 1000)
        print("write %d rc=%s n=%s" % (i, rc, n.value), flush=True)

        buf = (Msg * 8)()
        n2 = ctypes.c_ulong(8)
        rc = dll.PassThruReadMsgs(ch, buf, ctypes.byref(n2), 200)
        print("read %d rc=%s n=%s" % (i, rc, n2.value), flush=True)

    print("disconnect rc=%s" % dll.PassThruDisconnect(ch), flush=True)
    print("close rc=%s" % dll.PassThruClose(dev), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
