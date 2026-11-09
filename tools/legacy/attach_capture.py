#!/usr/bin/env python3
"""Универсальный захват обмена Quickflash-семейства (Frida -> канонический лог).

Заменяет прежний hardcoded-скрипт прошлой сессии BMS46: блок, exe, имя процесса,
хук-скрипт и сессионная папка задаются аргументами. Обычно запускается не руками,
а из logger.py (интерактивный логер).

    python attach_capture.py --exe "D:\\BMW_Flashers\\ME7.2 Quickflash\\ME72 Quickflash.exe" --launch
    python attach_capture.py --exe <exe> --find --wait 600
    python attach_capture.py --attach 1234 --exe <exe>
    python attach_capture.py --list --exe <exe>
    python attach_capture.py --script-check --exe <exe>

Лог: --out <файл> (по умолчанию sessions/<ts>-<label>/capture.log). Рядом с логом:
state.json (якорь t0 для mark.py) и stop.flag (грациозная остановка: файл -> эпилог -> выход).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCRIPT = os.path.join(HERE, "ftdi_capture_blocks.js")
SESSIONS_DIR = os.path.join(HERE, "sessions")

FILE_CLOSE_RE = re.compile(r"FILE close (.+?) bytes=(\d+) writes=(\d+)\s*$")
FILE_WRITE_RE = re.compile(r"^FILE write ")
TX_RE = re.compile(r"^\[[+][\d.]+s\] TX ")
RX_RE = re.compile(r"^\[[+][\d.]+s\] RX ")
HB_SECONDS = 15.0


def sha256_file(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        return "err:%s" % exc


def slug(text: str) -> str:
    s = re.sub(r"[^\w.-]+", "-", text.strip(), flags=re.UNICODE).strip("-")
    return (s or "session")[:40]


def ps_json(command: str):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except Exception:
        return None
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def find_processes(proc_name: str) -> list[dict]:
    data = ps_json(
        "Get-CimInstance Win32_Process -Filter \"Name='%s'\" | "
        "Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress" % proc_name
    )
    if data is None:
        return []
    if isinstance(data, dict):
        data = [data]
    return [d for d in data if isinstance(d, dict)]


def ps_file_version(path: str) -> str:
    out = ps_json(
        "(Get-Item -LiteralPath '%s' -ErrorAction Stop).VersionInfo | "
        "Select-Object FileVersion,ProductVersion,CompanyName,FileDescription | ConvertTo-Json -Compress"
        % path.replace("'", "''")
    )
    if not isinstance(out, dict):
        return "?"
    parts = [out.get("FileDescription"), out.get("CompanyName"), out.get("FileVersion"), out.get("ProductVersion")]
    return " | ".join(str(p) for p in parts if p) or "?"


class Session:
    def __init__(self, log_path: str, label: str, exe: str, adapter: str, ecu: str, note: str, script: str):
        self.log_path = log_path
        self.label = label
        self.exe = exe
        self.adapter = adapter
        self.ecu = ecu
        self.note = note
        self.script = script
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(log_path)) or ".", exist_ok=True)
        self.fh = open(log_path, "a", encoding="utf-8")
        self.t0 = time.time()
        self.counts = {"msgs": 0, "tx": 0, "rx": 0, "errors": 0, "files": 0}
        self.stop = threading.Event()
        self.hash_q: "queue.Queue[str]" = queue.Queue()

    def emit(self, line: str) -> None:
        with self.lock:
            self.fh.write(line + "\n")
            self.fh.flush()

    def rel(self) -> str:
        return "+%.3fs" % (time.time() - self.t0)

    def banner(self) -> None:
        exists = os.path.exists(self.exe)
        lines = [
            "=" * 74,
            "# capture start: label=%s" % self.label,
            "# tool: %s" % self.exe,
            "# exe: size=%d mtime=%s" % (
                os.path.getsize(self.exe) if exists else -1,
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(self.exe))) if exists else "?"),
            "# exe: sha256=%s" % (sha256_file(self.exe) if exists else "?"),
            "# exe: version=%s" % (ps_file_version(self.exe) if exists else "?"),
            "# ftd2xx: %s" % ps_file_version(r"C:\Windows\System32\FTD2XX.DLL"),
            "# app-dir: %s" % (os.path.dirname(self.exe) or "?"),
            "# wall(start)=%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
            "# host: user=%s computer=%s" % (os.environ.get("USERNAME", "?"), os.environ.get("COMPUTERNAME", "?")),
            "# adapter: %s" % (self.adapter or "(см. FT_GetDeviceInfoDetail/FT_GetDeviceInfo ниже)"),
            "# ecu: %s" % (self.ecu or "(см. ident-телеграмму ниже)"),
            "# note: %s" % (self.note or "-"),
            "# script: %s" % self.script,
            "# log: %s" % self.log_path,
            "=" * 74,
        ]
        for ln in lines:
            self.emit(ln)

    def epilogue(self, reason: str) -> None:
        self.emit("# capture stop: reason=%s wall=%s rel=%s" % (
            reason, time.strftime("%Y-%m-%d %H:%M:%S"), self.rel()))
        self.emit("# totals: lines=%d tx=%d rx=%d errors=%d file-closes=%d" % (
            self.counts["msgs"], self.counts["tx"], self.counts["rx"],
            self.counts["errors"], self.counts["files"]))
        self.emit("=" * 74)

    def heartbeat(self) -> None:
        while not self.stop.wait(HB_SECONDS):
            self.emit("# hb wall=%s rel=%s msgs=%d" % (
                time.strftime("%Y-%m-%d %H:%M:%S"), self.rel(), self.counts["msgs"]))

    def hasher(self) -> None:
        while True:
            try:
                path = self.hash_q.get(timeout=0.5)
            except queue.Empty:
                if self.stop.is_set():
                    return
                continue
            if path is None:
                return
            time.sleep(1.2)
            size = os.path.getsize(path) if os.path.exists(path) else -1
            digest = sha256_file(path) if size >= 0 else "missing"
            self.emit("# filehash %s size=%d sha256=%s" % (path, size, digest))

    def on_message(self, message, data) -> None:
        mtype = message.get("type")
        if mtype == "send":
            payload = str(message.get("payload"))
            self.counts["msgs"] += 1
            if TX_RE.match(payload):
                self.counts["tx"] += 1
            elif RX_RE.match(payload):
                self.counts["rx"] += 1
            self.emit(payload)
            m = FILE_CLOSE_RE.search(payload)
            if m and not FILE_WRITE_RE.match(payload):
                self.counts["files"] += 1
                self.hash_q.put(m.group(1))
        elif mtype == "error":
            self.counts["errors"] += 1
            self.emit("[script-error] " + str(message.get("description")))
            if message.get("stack"):
                self.emit(str(message.get("stack")))
        else:
            self.emit("[%s] %s" % (mtype, message))


def run_script_check(session: Session) -> int:
    """Dry-run пумбинга: загрузить хук в notepad.exe, убедиться, что поток сообщений жив."""
    target = r"C:\Windows\System32\notepad.exe"
    session.emit("# script-check: spawning %s" % target)
    device = frida.get_local_device()
    pid = device.spawn([target])
    fs = device.attach(pid)
    with open(session.script, "r", encoding="utf-8") as fh:
        script = fs.create_script(fh.read(), name="ftdi_capture_blocks")
    script.on("message", session.on_message)
    script.load()
    device.resume(pid)
    time.sleep(3.0)
    try:
        fs.detach()
    except Exception:
        pass
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    except Exception:
        pass
    ok = session.counts["msgs"] > 0 and session.counts["errors"] == 0
    session.emit("# script-check: result=%s msgs=%d errors=%d" % (
        "OK" if ok else "FAIL", session.counts["msgs"], session.counts["errors"]))
    return 0 if ok else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="Frida-захват обмена Quickflash-семейства")
    ap.add_argument("--exe", default="", help="путь к exe приложения (шапка/спавн/имя процесса)")
    ap.add_argument("--proc", default="", help="имя процесса (по умолчанию из --exe)")
    ap.add_argument("--script", default=DEFAULT_SCRIPT, help="Frida-скрипт хуков")
    ap.add_argument("--out", default="", help="файл лога (по умолчанию sessions/<ts>-<label>/capture.log)")
    ap.add_argument("--label", default="", help="метка сессии (по умолчанию имя exe без расширения)")
    ap.add_argument("--adapter", default="", help="описание/серийник шнурка (в шапку)")
    ap.add_argument("--ecu", default="", help="ЭБУ на стенде (в шапку)")
    ap.add_argument("--note", default="", help="произвольная заметка (в шапку)")
    ap.add_argument("--state-dir", default="", help="куда писать state.json/stop.flag (по умолчанию — рядом с логом)")
    ap.add_argument("--launch", action="store_true", help="запустить приложение и прицепиться (если уже запущено — просто attach)")
    ap.add_argument("--find", action="store_true", help="найти запущенный процесс и прицепиться")
    ap.add_argument("--wait", type=float, default=0.0, metavar="SEC", help="ждать появления процесса (с --find)")
    ap.add_argument("--attach", type=int, metavar="PID", help="прицепиться к PID")
    ap.add_argument("--attach-delay", type=float, default=0.0, metavar="SEC",
                    help="с --launch: подождать SEC после старта приложения и только потом ставить хуки "
                         "(приложение палит ранний attach и молча отключает прошивку: 07 0F→A2, E1)")
    ap.add_argument("--spawn", action="store_true", help="Frida-spawn приложения")
    ap.add_argument("--list", action="store_true", help="только показать процессы")
    ap.add_argument("--script-check", action="store_true", help="dry-run на notepad.exe")
    args = ap.parse_args()

    proc_name = args.proc or (os.path.basename(args.exe) if args.exe else "")
    if not proc_name:
        print("нужен --exe или --proc", file=sys.stderr)
        return 2

    if args.list:
        procs = find_processes(proc_name)
        if not procs:
            print("процесс '%s' не запущен" % proc_name)
        for p in procs:
            print("pid=%s path=%s cmd=%s" % (p.get("ProcessId"), p.get("ExecutablePath"), p.get("CommandLine")))
        return 0

    label = args.label or os.path.splitext(proc_name)[0]
    log_path = args.out
    if not log_path:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        log_path = os.path.join(SESSIONS_DIR, "%s-%s" % (stamp, slug(label)), "capture.log")
    session_dir = os.path.dirname(os.path.abspath(log_path))
    os.makedirs(session_dir, exist_ok=True)
    state_dir = args.state_dir or session_dir
    os.makedirs(state_dir, exist_ok=True)
    state_path = os.path.join(state_dir, "state.json")
    stop_flag = os.path.join(state_dir, "stop.flag")

    session = Session(log_path, label, args.exe, args.adapter, args.ecu, args.note, args.script)
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump({"t0_epoch": session.t0, "t0_wall": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "log": session.log_path, "label": label, "exe": args.exe, "proc": proc_name, "pid": None},
                  fh, ensure_ascii=False, indent=1)

    if args.script_check:
        rc = run_script_check(session)
        session.fh.close()
        return rc

    device = frida.get_local_device()
    pid = None
    spawned = False
    procs = find_processes(proc_name)

    if args.attach is not None:
        pid = args.attach
    elif args.spawn:
        if procs:
            print("Уже запущен pid=%s — закройте приложение перед --spawn." % procs[0].get("ProcessId"))
            return 2
        pid = device.spawn([args.exe], cwd=os.path.dirname(args.exe) or None)
        spawned = True
    elif args.launch:
        if procs:
            print("Уже запущен pid=%s — цепляюсь к нему." % procs[0].get("ProcessId"))
            pid = int(procs[0]["ProcessId"])
        else:
            print("Запускаю: %s" % args.exe)
            subprocess.Popen([args.exe], cwd=os.path.dirname(args.exe) or None)
            deadline = time.time() + 30.0
            while time.time() < deadline and pid is None:
                time.sleep(0.2)
                found = find_processes(proc_name)
                if found:
                    pid = int(found[0]["ProcessId"])
            if pid is not None and args.attach_delay > 0:
                print("жду %.0f с — даю приложению пройти стартовые проверки" % args.attach_delay)
                time.sleep(args.attach_delay)
    else:  # --find
        deadline = time.time() + max(args.wait, 0.0)
        while pid is None and time.time() <= deadline:
            if procs:
                pid = int(procs[0]["ProcessId"])
                break
            if not args.wait:
                print("Процесс '%s' не запущен (или укажите --wait/--launch)." % proc_name)
                return 1
            time.sleep(2.0)
            procs = find_processes(proc_name)
        if pid is None:
            print("Не дождался процесса '%s'." % proc_name)
            return 1

    state = {"t0_epoch": session.t0, "t0_wall": time.strftime("%Y-%m-%d %H:%M:%S"),
             "log": session.log_path, "label": label, "exe": args.exe, "proc": proc_name, "pid": pid}
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=1)

    print("attach pid=%d" % pid)
    fs = device.attach(pid)

    with open(args.script, "r", encoding="utf-8") as fh:
        source = fh.read()

    session.banner()
    session.emit("# attached pid=%d" % pid)
    for p in procs:
        if p.get("ProcessId") == pid:
            session.emit("# cmdline=%s" % p.get("CommandLine"))

    script = fs.create_script(source, name="ftdi_capture_blocks")
    script.on("message", session.on_message)
    script.load()
    session.emit("# hooks loaded")

    if spawned:
        device.resume(pid)
        session.emit("# resumed")

    threading.Thread(target=session.heartbeat, daemon=True).start()
    threading.Thread(target=session.hasher, daemon=True).start()

    reason = "target-exit"
    hooks_ctl = os.path.join(state_dir, "hooks.ctl")
    try:
        while True:
            time.sleep(1.0)
            if os.path.exists(hooks_ctl):
                cmd = ""
                try:
                    with open(hooks_ctl, "r", encoding="utf-8") as fh:
                        cmd = fh.read().strip().lower()
                    os.remove(hooks_ctl)
                except OSError:
                    cmd = ""
                if cmd in ("pause", "resume"):
                    try:
                        res = script.exports_sync.hookctl(cmd)
                        session.emit("# hookctl: %s по запросу логера %s -> %s" % (cmd, session.rel(), res))
                    except Exception as exc:
                        session.emit("# hookctl: не удалось послать %s: %s" % (cmd, exc))
            if os.path.exists(stop_flag):
                reason = "stop-flag"
                try:
                    os.remove(stop_flag)
                except OSError:
                    pass
                break
            if fs.is_detached:
                break
    except KeyboardInterrupt:
        reason = "user-stop"
    finally:
        session.stop.set()
        session.hash_q.put(None)
        session.epilogue(reason)
        try:
            fs.detach()
        except Exception:
            pass
        time.sleep(0.4)
        session.fh.close()
    print("Лог: %s" % session.log_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
