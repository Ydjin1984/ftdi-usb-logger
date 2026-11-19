"""Цель для E2E-регрессии «логируется только первый шаг».

Загружает J2534-DLL, вызывает PassThruOpen, выгружает её и повторяет всё ещё раз.
Ровно так ведёт себя PCMflash: идентификация заканчивается PassThruClose +
FreeLibrary, следующее действие снова грузит драйвер — часто по тому же base.
Без перевешивания хуков второй проход не попадает в лог.

Использование:
    python j2534_reload_target.py <путь к fake_j2534.dll> <файл-флаг>

Пока флага нет — процесс ждёт (чтобы логер успел attach).
"""

import ctypes as C
import os
import sys
import time

dll_path = sys.argv[1]
flag_path = sys.argv[2]

k32 = C.WinDLL("kernel32", use_last_error=True)
k32.LoadLibraryW.argtypes = [C.c_wchar_p]
k32.LoadLibraryW.restype = C.c_void_p
k32.GetProcAddress.argtypes = [C.c_void_p, C.c_char_p]
k32.GetProcAddress.restype = C.c_void_p
k32.FreeLibrary.argtypes = [C.c_void_p]
k32.FreeLibrary.restype = C.c_int

OPEN_PROTO = C.WINFUNCTYPE(C.c_int32, C.c_char_p, C.POINTER(C.c_uint32))

print("pid=%d" % os.getpid(), flush=True)

deadline = time.time() + 30
while not os.path.exists(flag_path) and time.time() < deadline:
    time.sleep(0.05)
print("go", flush=True)

for attempt in (1, 2):
    handle = k32.LoadLibraryW(dll_path)
    open_fn = OPEN_PROTO(k32.GetProcAddress(C.c_void_p(handle), b"PassThruOpen"))
    dev = C.c_uint32(0)
    rc = open_fn(None, C.byref(dev))
    print("load%d base=0x%x open_rc=%d dev=%d" % (attempt, handle, rc, dev.value), flush=True)
    time.sleep(1.5)
    k32.FreeLibrary(C.c_void_p(handle))
    print("free%d" % attempt, flush=True)
    time.sleep(1.5)

print("done", flush=True)
time.sleep(3)
