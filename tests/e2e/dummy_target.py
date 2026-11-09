"""Тестовая цель для e2e-смоука захвата: грузит FTD2XX.DLL и делает
безопасные read-only вызовы (перечисление устройств), затем спит.

Нужен, чтобы проверить всю цепочку без реального Quickflash/WinKFP:
engine -> sidecar (Frida) -> ftd2xx.dll -> события -> store.

    python tests/e2e/dummy_target.py --seconds 25
"""

from __future__ import annotations

import argparse
import ctypes
import sys
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=25.0)
    ap.add_argument("--bytes", action="store_true", help="дополнительно «пошуметь» FT_GetQueueStatus")
    args = ap.parse_args()

    try:
        dll = ctypes.WinDLL("FTD2XX.DLL")
    except OSError as exc:
        print(f"FTD2XX.DLL не загрузилась: {exc}", flush=True)
        return 2

    dll.FT_CreateDeviceInfoList.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
    dll.FT_CreateDeviceInfoList.restype = ctypes.c_uint32
    count = ctypes.c_uint32(0)
    status = dll.FT_CreateDeviceInfoList(ctypes.byref(count))
    print(f"FT_CreateDeviceInfoList status={status} devices={count.value}", flush=True)

    dll.FT_ListDevices.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
    dll.FT_ListDevices.restype = ctypes.c_uint32
    status = dll.FT_ListDevices(None, None, 0)
    print(f"FT_ListDevices status={status}", flush=True)

    if args.bytes and count.value:
        dll.FT_Open.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
        dll.FT_Open.restype = ctypes.c_uint32
        handle = ctypes.c_void_p()
        status = dll.FT_Open(0, ctypes.byref(handle))
        print(f"FT_Open status={status}", flush=True)
        if status == 0:
            q = ctypes.c_uint32(0)
            dll.FT_GetQueueStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
            dll.FT_GetQueueStatus.restype = ctypes.c_uint32
            for _ in range(3):
                st = dll.FT_GetQueueStatus(handle, ctypes.byref(q))
                print(f"FT_GetQueueStatus status={st} q={q.value}", flush=True)
                time.sleep(0.3)
            dll.FT_Close.argtypes = [ctypes.c_void_p]
            dll.FT_Close.restype = ctypes.c_uint32
            print(f"FT_Close status={dll.FT_Close(handle)}", flush=True)

    deadline = time.time() + args.seconds
    while time.time() < deadline:
        time.sleep(0.25)
    print("dummy target done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
