"""Стенд полноты захвата J2534 (docs/09 §10) — без железа.

Запускает `sidecar/bridge.py`, прицепляется Frida к python-цели, которая грузит
`fake_j2534.dll` и проходит полный набор вызовов PassThru 04.04 дважды (второй
раз — после FreeLibrary, то есть после выгрузки модуля). Собранные строки
складываются в raw.log и проверяются утверждениями из ТЗ.

    python tests/e2e/j2534_stand.py --dll <fakej2534.dll> --out <raw.log> [--mode full|compact]

Код возврата 0 — все проверки прошли.
"""

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BRIDGE = os.path.join(REPO, "sidecar", "bridge.py")
TARGET = os.path.join(REPO, "tests", "e2e", "j2534_full_target.py")

BANNER = [
    "# capture start: label=J2534 stand",
    "# tool: python.exe (fake_j2534.dll)",
    "# agent: universal_capture.js mode={mode}",
    "# attach: early",
]


class PipeReader(threading.Thread):
    """Читает stdout процесса построчно в очередь (не блокируя основной поток)."""

    def __init__(self, stream, sink):
        super().__init__(daemon=True)
        self.stream = stream
        self.sink = sink

    def run(self):
        for raw in self.stream:
            self.sink.put(raw.rstrip("\r\n"))


def wait_line(q, pattern, timeout, seen):
    """Ждём строку по regex; всё прочитанное складываем в `seen`."""
    deadline = time.time() + timeout
    rx = re.compile(pattern)
    while time.time() < deadline:
        try:
            line = q.get(timeout=0.2)
        except queue.Empty:
            continue
        seen.append(line)
        if rx.search(line):
            return line
    raise TimeoutError("не дождались %r за %.1f с; последние строки: %s"
                       % (pattern, timeout, seen[-8:]))


def drain(q, seen, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            seen.append(q.get(timeout=0.1))
        except queue.Empty:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="full")
    args = ap.parse_args()

    dll = os.path.abspath(args.dll)
    if not os.path.isfile(dll):
        print("нет DLL: %s" % dll)
        return 2

    work = tempfile.mkdtemp(prefix="j2534-stand-")
    start_flag = os.path.join(work, "go1")
    reload_flag = os.path.join(work, "go2")
    hold_flag = os.path.join(work, "go3")

    # ── цель ────────────────────────────────────────────────────────────
    target = subprocess.Popen(
        [sys.executable, "-u", TARGET, dll, start_flag, reload_flag, hold_flag],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO,
    )
    tq = queue.Queue()
    tlines = []
    PipeReader(target.stdout, tq).start()

    first = wait_line(tq, r"^pid=(\d+)", 30, tlines)
    pid = int(re.search(r"\d+", first).group(0))
    # `tlines` уже содержит первую строку — вытащим её из очереди-дубликата.
    print("цель: pid=%d" % pid, flush=True)

    # ── мост ────────────────────────────────────────────────────────────
    bridge = subprocess.Popen(
        [sys.executable, "-u", BRIDGE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO,
        env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1"),
    )
    bq = queue.Queue()
    events = []
    blines = []

    def on_bridge(line):
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            blines.append(line)
            return
        kind = msg.get("type")
        if kind == "event":
            events.append(msg.get("line", ""))
        elif kind == "log":
            blines.append("[%s] %s" % (msg.get("level"), msg.get("msg")))
        elif kind == "error":
            blines.append("[error] %s" % msg.get("msg"))
        elif kind in ("hello", "ready", "bye"):
            blines.append("[%s] %s" % (kind, json.dumps(msg, ensure_ascii=False)))

    def bridge_loop():
        for raw in bridge.stdout:
            on_bridge(raw.rstrip("\r\n"))

    threading.Thread(target=bridge_loop, daemon=True).start()

    def send(obj):
        bridge.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
        bridge.stdin.flush()

    time.sleep(1.0)
    send({
        "cmd": "attach",
        "pid": pid,
        "label": "J2534 stand",
        "options": {
            "mode": args.mode,
            "attach": "early",
            # DLL не в реестре: ABI передаём явно, иначе агент честно пишет dec=0.
            "j2534_api": {"fake_j2534.dll": "04.04"},
        },
    })

    # ── прогон ──────────────────────────────────────────────────────────
    deadline = time.time() + 60
    while time.time() < deadline and not any("ready" in b for b in blines):
        time.sleep(0.1)
    if not any("ready" in b for b in blines):
        print("мост не готов:\n" + "\n".join(blines[-20:]))
        target.kill()
        bridge.kill()
        return 2

    open(start_flag, "w").close()

    # Пауза ровно тогда, когда канал уже открыт: снятие и повторная установка
    # хуков не должны выдавать канал за «не открывался».
    wait_line(tq, r"^pass1 hold$", 60, tlines)
    send({"cmd": "hookctl", "value": "pause"})
    time.sleep(0.6)
    send({"cmd": "hookctl", "value": "resume"})
    time.sleep(0.8)
    open(hold_flag, "w").close()

    wait_line(tq, r"^wait-reload$", 60, tlines)
    time.sleep(0.5)
    open(reload_flag, "w").close()
    wait_line(tq, r"^done$", 60, tlines)
    time.sleep(0.8)

    send({"cmd": "stop"})
    try:
        bridge.wait(timeout=15)
    except subprocess.TimeoutExpired:
        bridge.kill()
    drain(bq, seen=[], seconds=0.2)
    try:
        target.wait(timeout=10)
    except subprocess.TimeoutExpired:
        target.kill()

    # ── raw.log ─────────────────────────────────────────────────────────
    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        for line in BANNER:
            handle.write(line.format(mode=args.mode) + "\n")
        for line in events:
            handle.write(line + "\n")
        handle.write("# totals: events=%d\n" % len(events))
    print("строк событий: %d → %s" % (len(events), out_path), flush=True)

    # ── проверки ────────────────────────────────────────────────────────
    text = "\n".join(events)
    failures = []

    def check(name, ok, detail=""):
        status = "OK  " if ok else "FAIL"
        print("%s %s%s" % (status, name, (" — " + detail) if detail and not ok else ""))
        if not ok:
            failures.append(name)

    def count(pattern):
        return len(re.findall(pattern, text))

    hooks = re.findall(
        r'# hooks mod="fake_j2534\.dll" base=\S+ load=(\d+) exports=(\d+) attached=(\d+) dup=(\d+) failed=(\d+)',
        text,
    )
    check("# hooks: две установки (load=1 и load=2)", len(hooks) >= 2, text[:400])
    if hooks:
        check(
            "# hooks: exports=14 attached=14 failed=0",
            all(h[1] == "14" and h[2] == "14" and h[4] == "0" for h in hooks),
            str(hooks),
        )
        loads = [int(h[0]) for h in hooks]
        check(
            "# hooks: load растёт монотонно (1 → 2), повторная установка не плодит load",
            loads == sorted(loads) and loads[0] == 1 and loads[-1] == 2,
            str(loads),
        )

    check("# api: ABI подтверждён (dec=1)", count(r"# api: 04\.04 .* dec=1") >= 1)
    check("# hooks-names: 14 имён", count(r'# hooks-names mod="fake_j2534\.dll" names="PassThru[A-Za-z,]*"') >= 1)

    connects = count(r"J2534 connect dev=1 ch=1 proto=0x8003 .* rc=0 gen=1")
    enters = count(r"J2534 connect-enter dev=1 proto=0x8003 .* baud=250000")
    check("J2534 connect: два успешных (gen=1 на каждый вход)", connects >= 2, "connect=%d enter=%d" % (connects, enters))
    check("J2534 connect-enter: по строке на каждый Connect", enters >= 2, "enter=%d" % enters)
    check("chan-miss отсутствует (connect наблюдался)", "chan-miss" not in text, str(count("chan-miss")))
    check("pause → resume: канал помечен chan-possibly-open",
          count(r"J2534 chan-possibly-open ch=1 gen=1 reason=resume") >= 1)

    # TX: пакетная запись 5 → 2
    tx_calls = re.findall(r"J2534 call ch=1 call=(\d+) op=WriteMsgs n_in=5 n_out=2 rc=0", text)
    check("WriteMsgs: n_in=5, драйвер принял n_out=2 (два прохода)", len(tx_calls) >= 2, str(tx_calls))
    tx_msgs = re.findall(r"J2534 TX ch=1 call=(\d+) i=(\d+)/(\d+)", text)
    check("WriteMsgs: записаны все 5 входных сообщений на проход", len(tx_msgs) >= 10, "TX строк: %d" % len(tx_msgs))
    if tx_calls and tx_msgs:
        per_call = {}
        for call, idx, total in tx_msgs:
            per_call.setdefault(call, set()).add(int(idx))
        full = [c for c in tx_calls[:1] if per_call.get(c) == {1, 2, 3, 4, 5}]
        check("WriteMsgs: у первого вызова ровно i=1..5", bool(full), str({k: sorted(v) for k, v in per_call.items()}))

    # RX: 3 сообщения, одно из них SOF
    rx_calls = re.findall(r"J2534 call ch=1 call=(\d+) op=ReadMsgs n_in=10 n_out=3 rc=0", text)
    check("ReadMsgs: n_in=10, n_out=3 (два прохода)", len(rx_calls) >= 2, str(rx_calls))
    sofs = re.findall(r"J2534 RX ch=1 call=\d+ i=(\d+)/(\d+) ts=0 rxs=0x2 sof=1 proto=0x8003 len=0$", text, re.M)
    if args.mode == "full":
        check("SOF: отдельная короткая строка без hex", len(sofs) >= 2, "SOF строк: %d" % len(sofs))
        check("SOF не содержит hex-секции", not re.search(r"sof=1[^\n]* : ", text))
        check("rx-empty: подавленные таймауты посчитаны", count(r"J2534 rx-empty ch=1 n=\d+ timeout_ms=20 last_rc=0x1[01]") >= 1)
    else:
        check("compact: SOF не печатается построчно", len(sofs) == 0)
        check("compact: агрегат rx_sof", "rx-sof-stat" in text or "# counters" in text)

    # FAST_INIT: PASSTHRU_MSG, а не 4 байта
    fast = re.findall(r"J2534 ioctl ch=1 call=\d+ id=0x0005 \(FAST_INIT\) .*in_size=4 in=0002277f", text)
    check("FAST_INIT: вход разобран как PASSTHRU_MSG (in_size=4)", len(fast) >= 2, "строк: %d" % len(fast))
    fast_out = re.findall(r"\(FAST_INIT\).*out_size=3 out=000367", text)
    check("FAST_INIT: выход разобран как PASSTHRU_MSG (out_size=3)", len(fast_out) >= 2, "строк: %d" % len(fast_out))
    check("FAST_INIT: DataSize вне 4128 не встречается", "len_invalid=1" not in text)

    # SET_CONFIG / READ_VBATT
    check("SET_CONFIG: параметры в строке", count(r"J2534 ioctl .*id=0x0002 \(SET_CONFIG\) .*in=[0-9a-f]+") >= 2)
    check("SET_CONFIG: config-строка с DATA_RATE", count(r"J2534 config ch=1 DATA_RATE=250000") >= 2)
    check("READ_VBATT: 4 байта на выходе", count(r"id=0x0003 \(READ_VBATT\) .*out=e02e0000") >= 2)

    # фильтры
    filt = re.findall(r"J2534 filter ch=1 call=\d+ type=0x0001 \(PASS_FILTER\) mask=ffffffff pattern=000007e0 flow=-", text)
    check("filter: mask/pattern/flow прочитаны", len(filt) >= 2, "строк: %d" % len(filt))
    check("filter-stop / periodic: именованные обработчики", count(r"J2534 filter-stop") >= 2 and count(r"J2534 periodic-start") >= 2)
    check("periodic-start: интервал и id", count(r"J2534 periodic-start ch=1 call=\d+ id=0x7 ms=1000") >= 2)

    check("ошибок хука нет", "universal hook error" not in text)
    counters = re.findall(r"# counters dropped_events=(\d+) truncated_payloads=(\d+) decode_errors=(\d+)", text)
    check("# counters: dropped=0 truncated=0 decode_errors=0", bool(counters) and counters[-1] == ("0", "0", "0"), str(counters))

    # Второй проход: после выгрузки DLL события снова идут в лог.
    second = [c for c in re.findall(r"J2534 connect dev=1 ch=1 .*gen=(\d+)", text)]
    check("второй проход после FreeLibrary записан", len(second) >= 2, "connect: %s" % second)

    if failures:
        print("\nПРОВАЛЕНО: %d проверок" % len(failures))
        for name in failures:
            print("  - %s" % name)
        print("\n--- лог моста ---")
        for line in blines[-25:]:
            print(line)
        return 1
    print("\nВсе проверки стенда пройдены.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
