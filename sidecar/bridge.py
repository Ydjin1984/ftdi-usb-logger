#!/usr/bin/env python3
"""Мост «движок Rust ↔ Frida» для FTDI/USB Logger.

Запуск (как его делает движок, `engine/src/frida.rs`):

    python -u sidecar/bridge.py

Аргументов нет. Рабочий каталог — корень репозитория/установки. Обмен — JSON Lines
через stdin/stdout, UTF-8 без BOM, по одному объекту на строку (контракт:
docs/02-architecture.md §5, типы: engine/src/models.rs, enum BridgeMsg).

Движок → мост:  {"cmd":"attach",...} {"cmd":"hookctl",...} {"cmd":"mark",...}
                {"cmd":"note",...} {"cmd":"stop"}
Мост → движок:  hello, ready, event, rpc, log, error, bye (поля — как в BridgeMsg).

Смоук без устройства и без Frida:

    python sidecar/bridge.py --self-test

печатает hello, ready, 20 синтетических event-строк валидной грамматики старого
лога (TX/RX/VCP/FILE/MARK) и bye, затем выходит с кодом 0.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import threading
import time
from datetime import datetime, timezone

BRIDGE_VERSION = "0.1.0"

# Корень репозитория/установки: <root>/sidecar/bridge.py
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Строка-визитка агента (её печатает ftdi_capture.js при загрузке) — из неё
# берём arch/modules для сообщения ready.
PROBE_RE = re.compile(r"capture script loaded: pid=(\d+) arch=(\S+) modules=(\d+)")

# frida импортируем лениво: --self-test должен работать и без установленной Frida.
try:  # pragma: no cover - зависит от окружения
    import frida  # type: ignore

    FRIDA_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # noqa: BLE001 - нужна любая причина
    frida = None  # type: ignore[assignment]
    FRIDA_IMPORT_ERROR = _exc


class FatalError(Exception):
    """Ошибка, после которой мост обязан сказать error/fatal:true и выйти с кодом 2."""


class NonFatalError(Exception):
    """Ошибка одной команды: error/fatal:false, цикл продолжается."""


def rfc3339_now() -> str:
    """Текущее время UTC в RFC3339 с миллисекундами: 2026-11-09T12:00:13.123Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_line(obj) -> str:
    """Компактный JSON одной строкой (без BOM/переводов строк внутри)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def pid_from(obj):
    try:
        value = int(obj)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


class Bridge:
    """Состояние моста: одна Frida-сессия, один загруженный скрипт."""

    def __init__(self, out=None):
        self._out = out if out is not None else sys.stdout
        self._lock = threading.Lock()
        self.events = 0
        self.errors = 0
        self.session = None
        self.script = None
        self.pid: int | None = None
        self.script_path: str | None = None
        self.ready = False
        self._buffer: list[str] = []
        self._closing = False
        self._load_probe: dict = {}
        self._probe_evt = threading.Event()

    # ───────────────────────────── вывод ──────────────────────────────

    def emit(self, obj) -> None:
        line = json_line(obj)
        with self._lock:
            try:
                self._out.write(line + "\n")
                self._out.flush()
            except (BrokenPipeError, OSError, ValueError):
                # Родитель умер/закрыл пайп — молча выходим, это штатный сценарий.
                raise SystemExit(0)

    def log(self, level: str, msg: str) -> None:
        self.emit({"type": "log", "level": level, "msg": str(msg)})

    def _write_event_locked(self, line: str) -> None:
        self.events += 1
        try:
            self._out.write(json_line({"type": "event", "line": line, "wall": rfc3339_now()}) + "\n")
            self._out.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise SystemExit(0)

    def emit_event(self, line: str) -> None:
        with self._lock:
            if not self.ready:
                # До ready движок не ждёт event-ов: копим, чтобы не нарушить порядок.
                self._buffer.append(line)
                return
            self._write_event_locked(line)

    def flush_buffer(self) -> None:
        with self._lock:
            pending, self._buffer = self._buffer, []
            for line in pending:
                self._write_event_locked(line)

    # ────────────────────────── сообщения Frida ────────────────────────

    def on_message(self, message, data) -> None:
        """Колбэк script.on('message'): любой send() → строка события."""
        if self._closing:
            return
        mtype = message.get("type") if isinstance(message, dict) else None
        if mtype == "send":
            payload = message.get("payload")
            if isinstance(payload, str):
                line = payload
            elif isinstance(payload, (dict, list)):
                # JSON-объекты тоже поддержаны: line = компактный JSON-текст.
                line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
            else:
                line = str(payload)
            match = PROBE_RE.search(line)
            if match:
                self._load_probe = {
                    "pid": int(match.group(1)),
                    "arch": match.group(2),
                    "modules": int(match.group(3)),
                }
                self._probe_evt.set()
            self.emit_event(line)
        elif mtype == "error":
            # Ошибка внутри JS-агента: не фатальна для моста.
            self.errors += 1
            desc = str(message.get("description") or message.get("stack") or message)
            self.emit({"type": "error", "fatal": False, "msg": desc})
            stack = message.get("stack")
            if stack:
                self.emit({"type": "error", "fatal": False, "msg": str(stack)})
        elif mtype == "log":
            # console.log() (в Frida 17 в мост не транслируется, но пусть будет).
            payload = message.get("payload")
            text = str(payload) if payload is not None else ""
            self.log(str(message.get("level") or "info"), text)
        else:
            self.log("debug", "frida message type=%r: %r" % (mtype, message))

    # ──────────────────────────── команды ─────────────────────────────

    def resolve_script(self, value: str) -> str:
        """Путь к JS-агенту из команды attach: абсолютный или относительно корня."""
        if not value:
            return os.path.join(REPO_ROOT, "sidecar", "agents", "ftdi_capture.js")
        if os.path.isabs(value):
            return value
        candidates = [
            os.path.join(REPO_ROOT, value),
            os.path.join(os.getcwd(), value),
            os.path.join(REPO_ROOT, "sidecar", value),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        # Не нашли — вернём наиболее вероятный, ошибка будет внятной выше.
        return candidates[0]

    def cmd_attach(self, cmd: dict) -> None:
        if frida is None:
            raise FatalError(
                "frida не установлена (%s). Установите: %s -m pip install -r sidecar/requirements.txt"
                % (FRIDA_IMPORT_ERROR, sys.executable)
            )
        pid = pid_from(cmd.get("pid"))
        if pid is None:
            raise FatalError("attach: некорректный pid=%r" % (cmd.get("pid"),))
        script_path = self.resolve_script(str(cmd.get("script") or ""))
        if not os.path.isfile(script_path):
            raise FatalError("attach: скрипт не найден: %s" % script_path)
        label = str(cmd.get("label") or "")

        # Повторный attach = сначала аккуратно закрыть предыдущую сессию.
        self.stop_capture(emit_bye=False)
        with open(script_path, "r", encoding="utf-8") as handle:
            source = handle.read()

        with self._lock:
            self._buffer = []
            self._load_probe = {}
        self._probe_evt.clear()
        self.ready = False
        self._closing = False

        try:
            device = frida.get_local_device()
            session = device.attach(pid)
            script = session.create_script(
                source, name=os.path.basename(script_path).rsplit(".", 1)[0] or "ftdi_capture"
            )
            script.on("message", self.on_message)
            script.load()
        except Exception as exc:  # noqa: BLE001 - любая ошибка Frida фатальна для attach
            self.session = None
            self.script = None
            self.pid = None
            raise FatalError("attach pid=%s: %s: %s" % (pid, type(exc).__name__, exc))

        self.session = session
        self.script = script
        self.pid = pid
        self.script_path = script_path
        if label:
            self.log("info", "attach: pid=%s label=%s" % (pid, label))

        # Ждём строку-визитку агента, из неё arch/modules для ready.
        self._probe_evt.wait(1.0)
        probe = self._load_probe
        self.ready = True
        self.emit(
            {
                "type": "ready",
                "pid": probe.get("pid", pid),
                "arch": probe.get("arch", ""),
                "modules": probe.get("modules", 0),
                "script": os.path.basename(script_path),
            }
        )
        self.log("info", "скрипт загружен: %s" % script_path)
        self.flush_buffer()

    def cmd_hookctl(self, cmd: dict) -> None:
        value = str(cmd.get("value") or "")
        if value not in ("pause", "resume"):
            raise NonFatalError("hookctl: value должно быть pause|resume, получено %r" % (value,))
        if self.script is None:
            raise NonFatalError("hookctl(%s): мост не подключён" % value)
        try:
            exports = getattr(self.script, "exports_sync", None)
            if exports is None:
                exports = getattr(self.script, "exports")
            result = exports.hookctl(value)
        except Exception as exc:  # noqa: BLE001 - RPC-ошибка не должна ронять мост
            raise NonFatalError("hookctl(%s): %s: %s" % (value, type(exc).__name__, exc))
        self.emit({"type": "rpc", "name": "hookctl", "result": str(result)})

    def cmd_ping(self) -> None:
        if self.script is None:
            raise NonFatalError("ping: мост не подключён")
        try:
            exports = getattr(self.script, "exports_sync", None)
            if exports is None:
                exports = getattr(self.script, "exports")
            result = exports.ping()
        except Exception as exc:  # noqa: BLE001
            raise NonFatalError("ping: %s: %s" % (type(exc).__name__, exc))
        self.emit({"type": "rpc", "name": "ping", "result": str(result)})

    def cmd_mark(self, cmd: dict) -> None:
        """Разметку ведёт движок; мост только фиксирует факт команды в логе."""
        action = cmd.get("action")
        title = cmd.get("title") or ""
        if cmd.get("cmd") == "note":
            self.log("info", "note: %s" % (cmd.get("text") or ""))
        else:
            self.log("info", "mark %s: %s" % (action or "?", title))

    def stop_capture(self, emit_bye: bool = False) -> None:
        script, session = self.script, self.session
        self.script = None
        self.session = None
        self._closing = True
        self.ready = False
        with self._lock:
            self._buffer = []
        if script is not None:
            try:
                script.unload()
            except Exception:  # noqa: BLE001 - detach/unload best-effort
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001
                pass
        self.pid = None
        if emit_bye:
            self.emit({"type": "bye", "code": 0, "events": self.events})

    # ─────────────────────────── главный цикл ─────────────────────────

    def run(self) -> int:
        self.emit(
            {
                "type": "hello",
                "bridge": BRIDGE_VERSION,
                "frida": getattr(frida, "__version__", "") if frida is not None else "",
                "python": platform.python_version(),
            }
        )
        if frida is None:
            self.log("error", "frida недоступна: %s — режим только разбор/импорт" % (FRIDA_IMPORT_ERROR,))

        try:
            for raw in sys.stdin:
                line = raw.strip()
                if not line:
                    continue
                try:
                    cmd = json.loads(line)
                except json.JSONDecodeError as exc:
                    self.emit({"type": "error", "fatal": False, "msg": "не JSON: %s" % exc})
                    continue
                if not isinstance(cmd, dict):
                    self.emit({"type": "error", "fatal": False, "msg": "команда должна быть JSON-объектом"})
                    continue
                name = cmd.get("cmd")
                try:
                    if name == "attach":
                        self.cmd_attach(cmd)
                    elif name == "hookctl":
                        self.cmd_hookctl(cmd)
                    elif name == "stop":
                        self.stop_capture(emit_bye=True)
                        return 0
                    elif name in ("mark", "note"):
                        self.cmd_mark(cmd)
                    elif name == "ping":
                        self.cmd_ping()
                    else:
                        self.emit(
                            {"type": "error", "fatal": False, "msg": "неизвестная команда: %r" % (name,)}
                        )
                except FatalError as exc:
                    self.emit({"type": "error", "fatal": True, "msg": str(exc)})
                    self.stop_capture(emit_bye=False)
                    return 2
                except NonFatalError as exc:
                    self.emit({"type": "error", "fatal": False, "msg": str(exc)})
        except KeyboardInterrupt:
            self.stop_capture(emit_bye=True)
            return 0
        except SystemExit as exc:  # пайп закрыт — выходим тихо
            return int(exc.code or 0)

        # EOF на stdin = родитель закрыл нас: штатный грациозный выход.
        self.stop_capture(emit_bye=True)
        return 0


# ─────────────────────────── self-test ────────────────────────────────

# 20 строк валидной грамматики старого лога (parse_family.py / engine::decode):
# TX/RX ftd2xx, VCP TX/RX (с rc/ovl как в ftdi_capture_blocks.js), FILE open/write/close,
# MODULE, FT_*, MARK. Ни одна строка не выдумывает полей, которых не бывает в живом логе.
SELF_TEST_LINES = [
    "[+0.000s] MODULE(now) FTD2XX.DLL  C:\\windows\\SYSTEM32\\FTD2XX.DLL base=0x7ffb712c0000",
    "[+0.000s] MODULE + FTD2XX.DLL  C:\\windows\\SYSTEM32\\FTD2XX.DLL base=0x7ffb712c0000",
    "[+0.004s] ftd2xx.dll hooks installed (36) at 0x7ffb712c0000 C:\\windows\\SYSTEM32\\FTD2XX.DLL",
    "[+0.010s] FT_CreateDeviceInfoList rc=0 devices=1",
    "[+0.011s] FT_GetDeviceInfoDetail idx=0 rc=0 flags=0 type=5 serial=\"A50285BI\" desc=\"FT232R USB UART\"",
    "[+0.012s] FT_Open(idx=0) rc=0 handle=0x1f8312ba370",
    "[+0.013s] FT_SetBaudRate(handle=0x1f8312ba370, 10400) rc=0",
    "[+0.014s] FT_SetDataCharacteristics(handle=0x1f8312ba370, wl=8 sb=1 parity=0) rc=0",
    "[+0.015s] FT_SetTimeouts(handle=0x1f8312ba370, rd=500 wr=500) rc=0",
    "[+0.016s] FT_Purge(handle=0x1f8312ba370, mask=3) rc=0",
    "[+0.100s] TX ftd2xx FT_Write rc=0 len=4 n=4 : 12 04 0d 1b",
    "[+0.170s] RX ftd2xx FT_Read rc=0 want=64 n=4 : 12 04 4d 1b",
    "[+1.010s] VCP CreateFileW(COM6) handle=0x2b4 invalid=false",
    "[+2.100s] VCP TX WriteFile(COM6) rc=0 n=4 ovl=0 : 12 04 0d 1b",
    "[+2.170s] VCP RX ReadFile(COM6) rc=0 n=4 ovl=0 : 12 04 4d 1b",
    "[+3.000s] FILE open D:\\BMW_Flashers\\BMS46\\bms46ds0.bin access=0x80000000 handle=0x3b0",
    "[+3.100s] FILE write D:\\BMW_Flashers\\BMS46\\bms46ds0.bin n=65536 total=65536",
    "[+3.200s] FILE close D:\\BMW_Flashers\\BMS46\\bms46ds0.bin bytes=65536 writes=1",
    "[+3.250s] FT_GetComPortNumber rc=0 com=6",
    "# MARK wall=2026-11-09 12:00:00 rel=+3.300s START 1: читаю идентификаторы",
]


def self_test(out=None) -> int:
    out = out if out is not None else sys.stdout

    def write(obj) -> None:
        out.write(json_line(obj) + "\n")
        out.flush()

    write(
        {
            "type": "hello",
            "bridge": BRIDGE_VERSION,
            "frida": getattr(frida, "__version__", "") if frida is not None else "",
            "python": platform.python_version(),
        }
    )
    write({"type": "ready", "pid": 4321, "arch": "x64", "modules": 31, "script": "ftdi_capture.js"})
    for line in SELF_TEST_LINES:
        write({"type": "event", "line": line, "wall": rfc3339_now()})
    write({"type": "bye", "code": 0, "events": len(SELF_TEST_LINES)})
    return 0


def configure_stdio() -> None:
    """UTF-8 без BOM и '\n' — иначе на Windows протокол JSON Lines ломается."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", newline="\n")
    except Exception:  # noqa: BLE001 - старые/подменённые потоки
        pass
    try:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Frida-мост FTDI/USB Logger (JSON Lines через stdin/stdout)"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="напечатать hello/ready/20 event/bye и выйти (смоук без устройства и Frida)",
    )
    parser.add_argument("--version", action="version", version="bridge " + BRIDGE_VERSION)
    args = parser.parse_args(argv)

    configure_stdio()
    if args.self_test:
        return self_test()
    return Bridge().run()


if __name__ == "__main__":
    raise SystemExit(main())
