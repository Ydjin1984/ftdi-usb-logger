"""Цель для стенда полноты захвата J2534 (docs/09 §10).

Загружает `fake_j2534.dll`, проходит полный набор вызовов PassThru 04.04,
выгружает библиотеку и грузит заново — как PCMflash между своими действиями.
Второй проход проверяет, что после `Close → FreeLibrary → LoadLibrary` хуки
перевешены и сессия видна целиком.

Использование:
    python j2534_full_target.py <путь к fake_j2534.dll> <флаг-старт> [<флаг-второй-проход>]

Пока флага нет — процесс ждёт: логгер должен успеть attach до первого вызова.
"""

import ctypes as C
import os
import sys
import time

MSG_SIZE = 4152  # 6 * 4 байта заголовка + Data[4128]


class PassThruMsg(C.Structure):
    _fields_ = [
        ("ProtocolID", C.c_uint32),
        ("RxStatus", C.c_uint32),
        ("TxFlags", C.c_uint32),
        ("Timestamp", C.c_uint32),
        ("DataSize", C.c_uint32),
        ("ExtraDataIndex", C.c_uint32),
        ("Data", C.c_ubyte * 4128),
    ]


class SConfig(C.Structure):
    _fields_ = [("Parameter", C.c_uint32), ("Value", C.c_uint32)]


class SConfigList(C.Structure):
    _fields_ = [("NumOfParams", C.c_uint32), ("ConfigPtr", C.POINTER(SConfig))]


assert C.sizeof(PassThruMsg) == MSG_SIZE, C.sizeof(PassThruMsg)


def make_msg(proto, flags, payload):
    msg = PassThruMsg()
    msg.ProtocolID = proto
    msg.TxFlags = flags
    msg.DataSize = len(payload)
    for i, byte in enumerate(payload):
        msg.Data[i] = byte
    return msg


def wait_flag(path, timeout=30.0):
    deadline = time.time() + timeout
    while not os.path.exists(path) and time.time() < deadline:
        time.sleep(0.05)


def load(dll_path):
    k32 = C.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.argtypes = [C.c_wchar_p]
    k32.LoadLibraryW.restype = C.c_void_p
    k32.GetProcAddress.argtypes = [C.c_void_p, C.c_char_p]
    k32.GetProcAddress.restype = C.c_void_p
    k32.FreeLibrary.argtypes = [C.c_void_p]
    k32.FreeLibrary.restype = C.c_int

    handle = k32.LoadLibraryW(dll_path)
    if not handle:
        raise OSError("LoadLibraryW: %s" % C.get_last_error())

    def fn(name, restype, argtypes):
        addr = k32.GetProcAddress(C.c_void_p(handle), name.encode())
        if not addr:
            raise OSError("нет экспорта %s" % name)
        return C.WINFUNCTYPE(restype, *argtypes)(addr)

    api = {
        "Open": fn("PassThruOpen", C.c_int32, [C.c_char_p, C.POINTER(C.c_uint32)]),
        "Close": fn("PassThruClose", C.c_int32, [C.c_uint32]),
        "Connect": fn(
            "PassThruConnect",
            C.c_int32,
            [C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32, C.POINTER(C.c_uint32)],
        ),
        "Disconnect": fn("PassThruDisconnect", C.c_int32, [C.c_uint32]),
        "ReadMsgs": fn(
            "PassThruReadMsgs",
            C.c_int32,
            [C.c_uint32, C.POINTER(PassThruMsg), C.POINTER(C.c_uint32), C.c_uint32],
        ),
        "WriteMsgs": fn(
            "PassThruWriteMsgs",
            C.c_int32,
            [C.c_uint32, C.POINTER(PassThruMsg), C.POINTER(C.c_uint32), C.c_uint32],
        ),
        "StartMsgFilter": fn(
            "PassThruStartMsgFilter",
            C.c_int32,
            [
                C.c_uint32,
                C.c_uint32,
                C.POINTER(PassThruMsg),
                C.POINTER(PassThruMsg),
                C.POINTER(PassThruMsg),
                C.POINTER(C.c_uint32),
            ],
        ),
        "StopMsgFilter": fn("PassThruStopMsgFilter", C.c_int32, [C.c_uint32, C.c_uint32]),
        "StartPeriodic": fn(
            "PassThruStartPeriodicMsg",
            C.c_int32,
            [C.c_uint32, C.POINTER(PassThruMsg), C.POINTER(C.c_uint32), C.c_uint32],
        ),
        "StopPeriodic": fn("PassThruStopPeriodicMsg", C.c_int32, [C.c_uint32, C.c_uint32]),
        "Ioctl": fn(
            "PassThruIoctl",
            C.c_int32,
            [C.c_uint32, C.c_uint32, C.c_void_p, C.c_void_p],
        ),
        "ReadVersion": fn(
            "PassThruReadVersion",
            C.c_int32,
            [C.c_uint32, C.c_char_p, C.c_char_p, C.c_char_p],
        ),
        "SetProgrammingVoltage": fn(
            "PassThruSetProgrammingVoltage", C.c_int32, [C.c_uint32, C.c_uint32, C.c_uint32]
        ),
        "GetLastError": fn("PassThruGetLastError", C.c_int32, [C.c_char_p]),
    }
    return k32, handle, api


def pass_one(api, tag, hold_flag=None):
    dev = C.c_uint32(0)
    print("%s open rc=%d" % (tag, api["Open"](b"Fake J2534 Stand", C.byref(dev))), flush=True)
    print("%s dev=%d" % (tag, dev.value), flush=True)

    fw = C.create_string_buffer(120)
    dll = C.create_string_buffer(120)
    ver = C.create_string_buffer(120)
    rc = api["ReadVersion"](dev.value, fw, dll, ver)
    print("%s version rc=%d api=%s" % (tag, rc, ver.value.decode()), flush=True)

    api["SetProgrammingVoltage"](dev.value, 12, 12_000)

    ch = C.c_uint32(0)
    # 0x8003 — вендорный протокол Scanmatik/PCMflash: у него нет CAN-id.
    print(
        "%s connect rc=%d ch=%d" % (tag, api["Connect"](dev.value, 0x8003, 0, 250_000, C.byref(ch)), ch.value),
        flush=True,
    )

    # SET_CONFIG: DATA_RATE = 250000 (SCONFIG_LIST на входе).
    cfg = SConfig()
    cfg.Parameter = 0x01
    cfg.Value = 250_000
    cfg_list = SConfigList()
    cfg_list.NumOfParams = 1
    cfg_list.ConfigPtr = C.pointer(cfg)
    print("%s set_config rc=%d" % (tag, api["Ioctl"](ch.value, 0x02, C.byref(cfg_list), None)), flush=True)

    # FAST_INIT: оба аргумента — PASSTHRU_MSG (D4), не 4 байта.
    fast_in = make_msg(0x8003, 0, [0x00, 0x02, 0x27, 0x7F])
    fast_out = PassThruMsg()
    print(
        "%s fast_init rc=%d" % (tag, api["Ioctl"](ch.value, 0x05, C.byref(fast_in), C.byref(fast_out))),
        flush=True,
    )

    vbat = C.c_uint32(0)
    print("%s vbat rc=%d" % (tag, api["Ioctl"](ch.value, 0x03, None, C.byref(vbat))), flush=True)

    mask = make_msg(0x8003, 0, [0xFF, 0xFF, 0xFF, 0xFF])
    pattern = make_msg(0x8003, 0, [0x00, 0x00, 0x07, 0xE0])
    fid = C.c_uint32(0)
    print(
        "%s filter rc=%d id=%d"
        % (
            tag,
            api["StartMsgFilter"](
                ch.value, 0x01, C.byref(mask), C.byref(pattern), None, C.byref(fid)
            ),
            fid.value,
        ),
        flush=True,
    )

    # Точка паузы: канал открыт, а хуки сейчас снимут и поставят заново —
    # логгер обязан пометить канал `chan-possibly-open` (docs/09 D1).
    if hold_flag:
        print("%s hold" % tag, flush=True)
        wait_flag(hold_flag, timeout=60)

    # Пакетная запись: приложение отдаёт 5 сообщений, драйвер примет 2.
    tx = (PassThruMsg * 5)()
    for i in range(5):
        tx[i] = make_msg(0x8003, 0, [0x00, 0x02, 0x27, 0x7F + i])
    tx_n = C.c_uint32(5)
    rc = api["WriteMsgs"](ch.value, tx, C.byref(tx_n), 100)
    print("%s write5 rc=%d n=%d" % (tag, rc, tx_n.value), flush=True)
    print("%s write_n_out=%d" % (tag, tx_n.value), flush=True)

    pm = (PassThruMsg * 10)()
    for attempt in range(4):
        n = C.c_uint32(10)
        rc = api["ReadMsgs"](ch.value, pm, C.byref(n), 20)
        print("%s read%d rc=0x%x n=%d" % (tag, attempt + 1, rc & 0xFFFFFFFF, n.value), flush=True)
        if rc == 0 and n.value:
            break

    # Контрактные сценарии драйвера (docs/12 §9). Значение timeout — селектор
    # сценария в fake_j2534.dll: 777 — сообщения при rc!=0, 778 — n_out > n_in,
    # 779 — CAN с 4-байтным id и ExtraDataIndex.
    for sel, name in ((777, "partial"), (778, "overflow"), (779, "can")):
        buf = (PassThruMsg * 10)()
        cnt = C.c_uint32(10)
        rc = api["ReadMsgs"](ch.value, buf, C.byref(cnt), sel)
        print("%s %s rc=0x%x n=%d" % (tag, name, rc & 0xFFFFFFFF, cnt.value), flush=True)

    periodic_msg = make_msg(0x8003, 0, [0x00, 0x02, 0x3E, 0x00])
    pid = C.c_uint32(0)
    print("%s periodic rc=%d" % (tag, api["StartPeriodic"](ch.value, C.byref(periodic_msg), C.byref(pid), 1000)), flush=True)
    print("%s periodic_stop rc=%d" % (tag, api["StopPeriodic"](ch.value, pid.value)), flush=True)

    print("%s filter_stop rc=%d" % (tag, api["StopMsgFilter"](ch.value, fid.value)), flush=True)
    print("%s disconnect rc=%d" % (tag, api["Disconnect"](ch.value)), flush=True)
    print("%s close rc=%d" % (tag, api["Close"](dev.value)), flush=True)


def main():
    dll_path = os.path.abspath(sys.argv[1])
    start_flag = sys.argv[2]
    reload_flag = sys.argv[3] if len(sys.argv) > 3 else None
    hold_flag = sys.argv[4] if len(sys.argv) > 4 else None

    print("pid=%d dll=%s" % (os.getpid(), dll_path), flush=True)
    wait_flag(start_flag)
    print("go", flush=True)

    for attempt in (1, 2):
        k32, handle, api = load(dll_path)
        print("loaded%d base=0x%x" % (attempt, handle), flush=True)
        pass_one(api, "pass%d" % attempt, hold_flag if attempt == 1 else None)
        if attempt == 2:
            # Второй Open при ТОМ ЖЕ module_load_id: Close → Open без выгрузки
            # библиотеки. Отдельный проход нужен, чтобы приёмка «Close → Open»
            # опиралась на одинаковый `mod=` двух строк `J2534 open`, а не на
            # повторную загрузку DLL (docs/12 §12).
            pass_one(api, "reopen")
            print("reopen-done", flush=True)
        k32.FreeLibrary(C.c_void_p(handle))
        print("freed%d" % attempt, flush=True)
        if attempt == 1:
            if reload_flag:
                print("wait-reload", flush=True)
                wait_flag(reload_flag)
                print("reload-go", flush=True)
            else:
                time.sleep(1.0)

    print("done", flush=True)
    # Ждём, пока мост заберёт счётчики: сессия должна быть ещё жива.
    time.sleep(10.0)


if __name__ == "__main__":
    main()
