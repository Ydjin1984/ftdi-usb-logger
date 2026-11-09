# -*- coding: utf-8 -*-
"""Генератор golden-артефактов для reference/expected.

Запускает СТАРЫЙ parse_family.py (CLI, --gap 2.0) на каждом ссылочном логе,
сохраняет stdout/stderr, переносит созданные парсером файлы в <лог>.files/,
и строит <лог>.summary.json через импорт того же модуля (parse_log/summarize).

Скрипт идемпотентен: reference/logs не должен содержать ничего, кроме исходных
логов; сгенерированные рядом с логами файлы немедленно переносятся.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PY = r"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe"
ORIG = Path(r"E:\Replica\work\orig-capture")
PARSER = ORIG / "parse_family.py"
LOGS = Path(r"D:\FTDI_USB_Logger\reference\logs")
EXP = Path(r"D:\FTDI_USB_Logger\reference\expected")
EXP.mkdir(parents=True, exist_ok=True)

ORDER = [
    "winkfp-e2e-capture.log",
    "winkfp-e2e-logger.out",
    "ftd2xx-bms46-session.log",
    "python-capture-empty.log",
    "bms46-no-traffic.log",
]
SIDE_FILES = ["tx-stream.bin", "rx-stream.bin", "stream-index.tsv"]
SIDE_DIRS = ["reads"]

HEADER_RE = re.compile(
    r"^СЕССИЯ (\S+)\s+start=(.*?)\s+обменов=(\d+)\s+mark=(\d+)\s+файлов=(\d+)\s+ошибок=(\d+)\s*$"
)
ITOGO_RE = re.compile(r"^  ИТОГО: посылок=(\d+)\s+TX=(\d+)B\s+RX=(\d+)B\s*$")
STREAM_RE = re.compile(
    r"^\s+0x([0-9A-Fa-f]{6})\.\.0x([0-9A-Fa-f]{6})\s+(\d+) B\s+блоков=(\d+)\s+sha256=([0-9a-f]{64})\s*$"
)


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_parser():
    spec = importlib.util.spec_from_file_location("old_parse_family", str(PARSER))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def move_side_files(logname: str) -> list[str]:
    dest = EXP / (logname + ".files")
    moved: list[str] = []
    for name in SIDE_FILES:
        src = LOGS / name
        if src.exists():
            dest.mkdir(parents=True, exist_ok=True)
            if (dest / name).exists():
                (dest / name).unlink()
            shutil.move(str(src), str(dest / name))
            moved.append(name)
    for name in SIDE_DIRS:
        src = LOGS / name
        if src.is_dir():
            if (dest / name).exists():
                shutil.rmtree(dest / name)
            dest.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest / name))
            moved.append(name + "/")
    return moved


def build_summary(pf, logp: Path, logname: str, command: str, moved: list[str]) -> dict:
    sessions, preamble = pf.parse_log(str(logp))
    out_sessions = []
    for i, ss in enumerate(sessions):
        s = pf.summarize(ss)
        out_sessions.append(
            {
                "index": i,
                "label": ss.label,
                "stamp": ss.stamp,
                "telegrams": s["exchanges"],
                "exchanges": s["exchanges"],
                "tx_bytes": s["tx_bytes"],
                "rx_bytes": s["rx_bytes"],
                "rx_chunks": sum(len(e.rx_chunks) for e in ss.exchanges),
                "cmd_hist": dict(sorted(s["cmd_hist"].items())),
                "resp_hist": dict(sorted(s["resp_hist"].items())),
                "reads": [
                    {"start": a, "len": ln, "blocks": n, "sha256": d}
                    for a, ln, n, d in s["reads"]
                ],
                "filehash": [{"path": p, "size": sz, "sha256": h} for p, sz, h in s["filehash"]],
                "marks": len(ss.marks),
                "files": len(ss.files),
                "errors": len(ss.errors),
                "ovl_zero": ss.ovl_zero,
            }
        )
    totals = {
        "sessions": len(out_sessions),
        "telegrams": sum(x["telegrams"] for x in out_sessions),
        "tx_bytes": sum(x["tx_bytes"] for x in out_sessions),
        "rx_bytes": sum(x["rx_bytes"] for x in out_sessions),
        "reads": sum(len(x["reads"]) for x in out_sessions),
        "filehash": sum(len(x["filehash"]) for x in out_sessions),
        "marks": sum(x["marks"] for x in out_sessions),
        "files": sum(x["files"] for x in out_sessions),
        "errors": sum(x["errors"] for x in out_sessions),
    }
    return {
        "schema": "old-parse-family-golden/v1",
        "log": {
            "file": logname,
            "path": str(logp),
            "bytes": logp.stat().st_size,
            "lines": len(logp.read_bytes().decode("utf-8", "replace").splitlines()),
            "sha256": sha256_file(logp),
        },
        "parser": {
            "path": str(PARSER),
            "sha256": sha256_file(PARSER),
            "command": command,
            "gap_seconds": 2.0,
        },
        "preamble_lines": len(preamble),
        "sessions": out_sessions,
        "totals": totals,
        "side_artifacts": moved,
    }


def crosscheck(stdout: str, summary: dict) -> dict:
    """Извлечь числа из stdout CLI и сверить с summary из импорта модуля."""
    parsed_sessions, itogo, streams = [], [], []
    for line in stdout.splitlines():
        m = HEADER_RE.match(line)
        if m:
            parsed_sessions.append(
                {
                    "label": m.group(1),
                    "start": m.group(2),
                    "exchanges": int(m.group(3)),
                    "marks": int(m.group(4)),
                    "files": int(m.group(5)),
                    "errors": int(m.group(6)),
                }
            )
            continue
        m = ITOGO_RE.match(line)
        if m:
            itogo.append({"exchanges": int(m.group(1)), "tx_bytes": int(m.group(2)), "rx_bytes": int(m.group(3))})
            continue
        m = STREAM_RE.match(line)
        if m:
            streams.append(
                {
                    "start": int(m.group(1), 16),
                    "end": int(m.group(2), 16),
                    "len": int(m.group(3)),
                    "blocks": int(m.group(4)),
                    "sha256": m.group(5),
                }
            )
    printed = [s for s in summary["sessions"] if s["exchanges"] or s["files"]]
    ok = True
    reasons: list[str] = []
    if len(parsed_sessions) != len(printed):
        ok = False
        reasons.append("число сессий в stdout (%d) != число печатаемых сессий (%d)" % (len(parsed_sessions), len(printed)))
    for hs, s in zip(parsed_sessions, printed):
        if hs["exchanges"] != s["exchanges"]:
            ok = False
            reasons.append("обмены: stdout %d != json %d" % (hs["exchanges"], s["exchanges"]))
        if hs["marks"] != s["marks"]:
            ok = False
            reasons.append("mark: stdout %d != json %d" % (hs["marks"], s["marks"]))
        if hs["files"] != s["files"]:
            ok = False
            reasons.append("files: stdout %d != json %d" % (hs["files"], s["files"]))
    for it, s in zip(itogo, printed):
        if (it["exchanges"], it["tx_bytes"], it["rx_bytes"]) != (s["exchanges"], s["tx_bytes"], s["rx_bytes"]):
            ok = False
            reasons.append("ИТОГО %s != json %s" % (it, (s["exchanges"], s["tx_bytes"], s["rx_bytes"])))
    json_reads = [r for s in printed for r in s["reads"]]
    if len(streams) != len(json_reads):
        ok = False
        reasons.append("потоки чтения: stdout %d != json %d" % (len(streams), len(json_reads)))
    else:
        for a, b in zip(streams, json_reads):
            if (a["start"], a["len"], a["blocks"], a["sha256"]) != (b["start"], b["len"], b["blocks"], b["sha256"]):
                ok = False
                reasons.append("поток %s != json %s" % (a, b))
                break
    return {
        "method": "regex over CLI stdout: СЕССИЯ/ИТОГО/ПОТОКИ ЧТЕНИЯ",
        "stdout_sessions": parsed_sessions,
        "stdout_itogo": itogo,
        "stdout_read_streams": len(streams),
        "match": ok,
        "mismatches": reasons,
    }


def main() -> int:
    pf = load_parser()
    for logname in ORDER:
        logp = LOGS / logname
        if not logp.exists():
            print("НЕТ ЛОГА:", logp)
            return 2
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUTF8"] = "1"
        cmd = [PY, str(PARSER), "--log", str(logp), "--gap", "2.0"]
        proc = subprocess.run(cmd, cwd=str(LOGS), capture_output=True, env=env)
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        (EXP / (logname + ".parse.out.txt")).write_bytes(proc.stdout)
        (EXP / (logname + ".parse.err.txt")).write_bytes(proc.stderr)
        moved = move_side_files(logname)
        command = "%s %s --log %s --gap 2.0" % (PY, str(PARSER), str(logp))
        summary = build_summary(pf, logp, logname, command, moved)
        summary["cli"] = {"exit_code": proc.returncode, "stdout_file": logname + ".parse.out.txt",
                          "stderr_file": logname + ".parse.err.txt"}
        summary["stdout_crosscheck"] = crosscheck(stdout, summary)
        (EXP / (logname + ".summary.json")).write_bytes(
            (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )
        print("%-28s rc=%d sessions=%d ex=%d tx=%d rx=%d reads=%d fh=%d marks=%d files=%d errors=%d side=%s cross=%s" % (
            logname, proc.returncode, summary["totals"]["sessions"], summary["totals"]["telegrams"],
            summary["totals"]["tx_bytes"], summary["totals"]["rx_bytes"], summary["totals"]["reads"],
            summary["totals"]["filehash"], summary["totals"]["marks"], summary["totals"]["files"],
            summary["totals"]["errors"], moved or "-", summary["stdout_crosscheck"]["match"]))
        if stderr.strip():
            print("  STDERR:", stderr.strip().splitlines()[:3])
    # контроль: в reference/logs не должно остаться мусора
    leftovers = [p.name for p in LOGS.iterdir() if p.name not in ORDER and p.name != "ediabas"]
    print("LEFTOVERS:", leftovers or "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
