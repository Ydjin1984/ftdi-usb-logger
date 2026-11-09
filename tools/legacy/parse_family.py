#!/usr/bin/env python3
"""Разбор сессионного лога Quickflash-семейства: телеграммы, тайминги, чтения.

Модуль и CLI. Как CLI: разбирает лог и печатает отчёт; по умолчанию пишет рядом с логом
    tx-stream.bin / rx-stream.bin / stream-index.tsv   — сырые потоки направлений (+ индекс)
    reads/AAAAAA-RRRRRR.bin                            — собранные потоки чтения памяти

Парсинг идёт ПО ПОРЯДКУ СТРОК лога (не по таймстемпам): приложение ставит следующую
посылку в лог одновременно с дочитыванием предыдущего ответа, поэтому склейка «RX между
двумя TX» по времени даёт сдвиг на один обмен.

Протокол блока заранее неизвестен, поэтому разбор описательный:
    * каждая TX-посылка -> строка «эхо / класс ответа / длина payload / пауза перед ней»;
    * семейная команда чтения `06 <addr32> <len8>` собирается в потоки чтения (проверено на BMS46);
    * всё прочее помечается как cmd=0xNN без домыслов.

    python parse_me72.py --log <путь/к/capture.log>
    python parse_me72.py --log <лог> --gap 2.0 --all

Из логера используется как модуль: parse_text(), parse_log(), summarize(), stream_ranges().
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = os.path.join(HERE, "capture.log")

TX_FT_RE = re.compile(r"^\[\+([\d.]+)s\] TX ftd2xx FT_Write rc=(-?\d+) len=(\d+) n=(\d+) : ([0-9a-f ]*)$")
RX_FT_RE = re.compile(r"^\[\+([\d.]+)s\] RX ftd2xx FT_Read rc=(-?\d+) want=(\d+) n=(\d+) : ([0-9a-f ]*)$")
TX_VCP_RE = re.compile(r"^\[\+([\d.]+)s\] VCP TX WriteFile\(([^)]+)\)(?: rc=-?\d+)? n=(\d+)(?: ovl=\d+)? : ([0-9a-f ]*)$")
RX_VCP_RE = re.compile(r"^\[\+([\d.]+)s\] VCP RX ReadFile\(([^)]+)\)(?: rc=-?\d+)? n=(\d+)(?: ovl=\d+)? : ([0-9a-f ]*)$")
MARK_RE = re.compile(r"^# MARK wall=(.+?) rel=\+([\d.]+)s\s+(.*)$")
FILE_OPEN_RE = re.compile(r"^\[\+([\d.]+)s\] FILE open (.+?) access=(0x[0-9a-f]+) handle=(.+)$")
FILE_CLOSE_RE = re.compile(r"^\[\+([\d.]+)s\] FILE close (.+?) bytes=(\d+) writes=(\d+)$")
FILEHASH_RE = re.compile(r"^# filehash (.+?) size=(-?\d+) sha256=(.+)$")
START_RE = re.compile(r"^# capture start(?::\s*label=(.*?))?\s*(\(attach\))?\s*$")
TIME_RE = re.compile(r"^# (wall\(start\)|time=)(.*)$")
PHASE_RE = re.compile(r"^#\s*(PHASE[^\n]*)$")
CFG_RE = re.compile(
    r"^\[\+([\d.]+)s\] ((?:FT_Set|FT_Purge|FT_Open|FT_Close|FT_Reset|FT_Cycle|FT_GetDeviceInfo|"
    r"FT_GetComPortNumber|FT_CreateDeviceInfoList|FT_ListDevices|FT_EE_|MODULE).*)$")
ERROR_RE = re.compile(r"script-error|<read-error")
PARITY_RE = re.compile(r"frame|parity|overrun", re.I)


def hexb(s: str) -> bytes:
    s = s.strip()
    return bytes(int(x, 16) for x in s.split()) if s else b""


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fmt(b: bytes, max_bytes: int = 16) -> str:
    s = " ".join("%02x" % x for x in b[:max_bytes])
    return s + (" … (%d B)" % len(b) if len(b) > max_bytes else "")


class Exchange:
    __slots__ = ("tx_t", "tx", "tx_trunc", "rx_chunks", "rx_t", "rx_trunc")

    def __init__(self, t: float, tx: bytes, trunc: bool):
        self.tx_t, self.tx, self.tx_trunc = t, tx, trunc
        self.rx_chunks: list[bytes] = []
        self.rx_t = t
        self.rx_trunc = False

    @property
    def rx(self) -> bytes:
        return b"".join(self.rx_chunks)


class Session:
    def __init__(self, label: str, attach: bool = False):
        self.label = label + (" (attach)" if attach else "")
        self.stamp = "?"
        self.exchanges: list[Exchange] = []
        self.marks: list[tuple[float, str, str]] = []
        self.cfg: list[tuple[float, str]] = []
        self.files: list[tuple[float, str, str]] = []
        self.filehash: list[tuple[str, int, str]] = []
        self.errors: list[str] = []
        self.modules: list[str] = []
        self.phases: list[str] = []
        self.ovl_zero = 0     # VCP-чтения с n=0 (overlapped): байты в логе недостоверны


def feed(sess: Session, lines) -> None:
    """Разобрать строки одного блока сессии в Session (порядок строк = порядок событий)."""
    ex: Exchange | None = None
    for raw in lines:
        line = raw.rstrip("\n")

        m = TX_FT_RE.match(line)
        if m:
            data = hexb(m.group(5))
            ex = Exchange(float(m.group(1)), data, len(data) < int(m.group(4)))
            sess.exchanges.append(ex)
            continue
        m = TX_VCP_RE.match(line)
        if m:
            data = hexb(m.group(4))
            ex = Exchange(float(m.group(1)), data, len(data) < int(m.group(3)))
            sess.exchanges.append(ex)
            continue
        m = RX_FT_RE.match(line)
        if m and ex is not None:
            data = hexb(m.group(5))
            ex.rx_chunks.append(data)
            ex.rx_t = float(m.group(1))
            ex.rx_trunc = ex.rx_trunc or len(data) < int(m.group(4))
            continue
        m = RX_VCP_RE.match(line)
        if m and ex is not None:
            n = int(m.group(3))
            data = hexb(m.group(4))
            if n == 0:
                # overlapped-чтение: на возврате из ReadFile счётчика байт ещё нет,
                # содержимое буфера недостоверно — в разбор его не берём
                data = b""
                ex.rx_trunc = True
                sess.ovl_zero += 1
            ex.rx_chunks.append(data)
            ex.rx_t = float(m.group(1))
            ex.rx_trunc = ex.rx_trunc or len(data) < n
            continue

        m = MARK_RE.match(line)
        if m:
            sess.marks.append((float(m.group(2)), m.group(1), m.group(3)))
            continue
        m = TIME_RE.match(line)
        if m and sess.stamp == "?":
            sess.stamp = m.group(2).strip()
            continue
        m = FILE_OPEN_RE.match(line)
        if m:
            sess.files.append((float(m.group(1)), "open", "%s access=%s" % (m.group(2), m.group(3))))
            continue
        m = FILE_CLOSE_RE.match(line)
        if m:
            sess.files.append((float(m.group(1)), "close", "%s bytes=%s writes=%s" % (
                m.group(2), m.group(3), m.group(4))))
            continue
        m = FILEHASH_RE.match(line)
        if m:
            sess.filehash.append((m.group(1), int(m.group(2)), m.group(3)))
            continue
        if line.startswith("# module "):
            sess.modules.append(line)
            continue
        m = PHASE_RE.match(line)
        if m:
            sess.phases.append(line)
            continue
        m = CFG_RE.match(line)
        if m:
            txt = m.group(2)
            if not txt.startswith("MODULE") and "ftd2xx.dll hooks installed" not in txt:
                sess.cfg.append((float(m.group(1)), txt))
            continue
        if ERROR_RE.search(line) or PARITY_RE.search(line):
            sess.errors.append(line)


def parse_text(text: str, label: str = "slice") -> Session:
    """Разобрать произвольный фрагмент лога (например, один шаг логера) в один Session."""
    sess = Session(label)
    feed(sess, text.splitlines())
    return sess


def parse_log(path: str) -> tuple[list[Session], list[str]]:
    """Разобрать файл лога: список сессий + преамбула."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    sessions: list[Session] = []
    preamble: list[str] = []
    cur: Session | None = None
    buf: list[str] = []
    for line in text.splitlines():
        m = START_RE.match(line)
        if m:
            if cur is not None:
                feed(cur, buf)
            cur = Session(m.group(1) or "?", bool(m.group(2)))
            sessions.append(cur)
            buf = []
            continue
        if cur is None:
            if line.strip():
                preamble.append(line)
            continue
        buf.append(line)
    if cur is not None:
        feed(cur, buf)
    return sessions, preamble


def split_echo_response(tx: bytes, rx: bytes) -> tuple[str, bytes]:
    """(есть ли эхо, остаток). Эхо — точный префикс RX, равный TX."""
    if tx and rx.startswith(tx):
        return "y", rx[len(tx):]
    return "n", rx


# коды отказа KWP2000 (вторая половина '7F <svc> <nrc>')
KWP_NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "badLength", 0x21: "busyRepeat", 0x22: "conditionsNotCorrect", 0x31: "requestOutOfRange",
    0x33: "securityAccessDenied", 0x35: "invalidKey", 0x78: "responsePending",
}
_KWP_SUB_SVC = (0x10, 0x27, 0x30, 0x31, 0x3E, 0x85)


def tx_summary(tx: bytes) -> str:
    """Короткая подпись TX-посылки: 'SVC(10,85)' для KWP-кадров ME7.2, иначе 'cmd=0xNN'."""
    if len(tx) >= 5 and tx[0] == 0xB8:
        svc = tx[4]
        if svc in _KWP_SUB_SVC and len(tx) > 5:
            return "SVC(%02X,%02X)" % (svc, tx[5])
        return "SVC(%02X)" % svc
    if len(tx) >= 3:
        return "cmd=0x%02X" % tx[2]
    return tx.hex(" ")


def parse_frame(tx: bytes, residual: bytes) -> tuple[str, bytes, bytes]:
    """(класс, payload, хвост). Класс: A0 / A2-denied / 0xNN / unparsed / no-answer.

    Кроме DS2-семейства разбираем кадры ME7.2 Quickflash (KWP2000 в обёртке `b8`):
    `b8 <dst> <src> <len> <data...> <cks>` — ответ '7F <svc> <nrc>' получает имя NRC.
    """
    if not residual:
        return "no-answer", b"", b""
    if tx and tx[0] == 0xB8 and residual[0] == 0xB8 and len(residual) >= 5:
        ln = residual[3]
        total = 4 + ln + 1
        if total <= len(residual):
            data, tail = residual[4:4 + ln], residual[total:]
            if not data:
                return "b8-empty", b"", tail
            if data[0] == 0x7F:
                if len(data) >= 3:
                    nrc = KWP_NRC.get(data[2], "")
                    return "7F(%02X,%02X%s)" % (data[1], data[2], "-" + nrc if nrc else ""), b"", tail
                return "7F-short", b"", tail
            if data[0] & 0xC0 == 0x40:      # положительный ответ = сервис + 0x40
                return "pos(%02X)" % (data[0] - 0x40), data[1:], tail
            return "b8(%02X)" % data[0], data[1:], tail
        return "b8-short(len=%d)" % ln, b"", b""
    if len(residual) >= 3 and residual[0] == tx[0]:
        ln = residual[1]
        if 2 <= ln <= len(residual):
            frame, tail = residual[:ln], residual[ln:]
            status = frame[2]
            if status == 0xA0:
                return "A0", frame[3:-1], tail
            if status == 0xA2:
                return "A2-denied", b"", tail
            return "0x%02X" % status, b"", tail
        return "short-frame(len=%d)" % ln, b"", b""
    return "unparsed(%s)" % fmt(residual, 8), b"", b""


def read_telegram(tx: bytes) -> tuple[int, int] | None:
    """Семейное чтение памяти: 12 <len> 06 <addr32> <blen> <cks> -> (addr, blen)."""
    if len(tx) >= 9 and tx[2] == 0x06:
        return int.from_bytes(tx[3:7], "big"), tx[7]
    return None


def stream_ranges(events: list[tuple[int, bytes, float]]) -> list[tuple[int, bytes, int]]:
    """Потоки чтения в порядке времени: последовательные адреса склеиваются.

    events: [(addr, payload, t)] -> [(start, bytes, blocks)]. Повторный проход тех же
    адресов позже даёт новый поток (сначала Read Tune, потом Read Full — разные проходы).
    """
    out: list[list] = []
    for addr, blob, t in events:
        if out and out[-1][0] + len(out[-1][1]) == addr:
            out[-1][1] += blob
            out[-1][2] += 1
        else:
            out.append([addr, bytearray(blob), 1])
    return [(a, bytes(b), n) for a, b, n in out]


def summarize(sess: Session) -> dict:
    """Машиночитаемая сводка по Session: счётчики, гистограммы, потоки чтения, файлы."""
    events: list[tuple[int, bytes, float]] = []
    cmd_hist: dict[str, int] = {}
    resp_hist: dict[str, int] = {}
    for e in sess.exchanges:
        echo, residual = split_echo_response(e.tx, e.rx)
        klass, payload, _tail = parse_frame(e.tx, residual)
        resp_hist[klass] = resp_hist.get(klass, 0) + 1
        rt = read_telegram(e.tx)
        if rt is not None and payload:
            events.append((rt[0], payload, e.tx_t))
            key = "READ(0x06)"
        else:
            key = tx_summary(e.tx)
        cmd_hist[key] = cmd_hist.get(key, 0) + 1
    return {
        "label": sess.label,
        "exchanges": len(sess.exchanges),
        "tx_bytes": sum(len(e.tx) for e in sess.exchanges),
        "rx_bytes": sum(len(e.rx) for e in sess.exchanges),
        "cmd_hist": cmd_hist,
        "resp_hist": resp_hist,
        "reads": [(a, len(b), n, sha(b)) for a, b, n in stream_ranges(events)],
        "files": sess.files,
        "filehash": sess.filehash,
        "marks": sess.marks,
        "errors": len(sess.errors),
    }


def dump_streams(sess: Session, outdir: str) -> None:
    tx_path = os.path.join(outdir, "tx-stream.bin")
    rx_path = os.path.join(outdir, "rx-stream.bin")
    idx_path = os.path.join(outdir, "stream-index.tsv")
    off = {"TX": 0, "RX": 0}
    with open(tx_path, "wb") as ftx, open(rx_path, "wb") as frx, open(idx_path, "w", encoding="utf-8") as fidx:
        fidx.write("dir\trel_time\tchunk_len\tstream_offset\ttruncated\n")
        for e in sess.exchanges:
            ftx.write(e.tx)
            fidx.write("TX\t+%.3f\t%d\t%d\t%s\n" % (e.tx_t, len(e.tx), off["TX"], "1" if e.tx_trunc else "0"))
            off["TX"] += len(e.tx)
            for chunk in e.rx_chunks:
                frx.write(chunk)
                fidx.write("RX\t+%.3f\t%d\t%d\t%s\n" % (e.rx_t, len(chunk), off["RX"], "1" if e.rx_trunc else "0"))
                off["RX"] += len(chunk)
    print("  сырые потоки: %s (%d B) | %s (%d B) | %s" % (
        os.path.basename(tx_path), off["TX"], os.path.basename(rx_path), off["RX"], os.path.basename(idx_path)))


def report(sess: Session, gap: float, reads_dir: str | None, show_all: bool) -> None:
    print("=" * 96)
    print("СЕССИЯ %-24s start=%s   обменов=%d   mark=%d   файлов=%d   ошибок=%d" % (
        sess.label, sess.stamp, len(sess.exchanges), len(sess.marks), len(sess.files), len(sess.errors)))

    for ln in sess.phases:
        print("  " + ln)

    if sess.modules:
        print("-" * 96)
        print("МОДУЛИ:")
        for ln in sess.modules:
            print("  " + ln)

    interesting_cfg = [c for c in sess.cfg
                       if not re.search(r"FT_Open|FT_CreateDeviceInfoList|FT_GetQueueStatus|FT_Close", c[1])]
    if interesting_cfg:
        print("-" * 96)
        print("КОНФИГУРАЦИЯ ПОРТА:")
        for t, txt in interesting_cfg:
            print("  +%9.3fs  %s" % (t, txt))

    if sess.files or sess.filehash:
        print("-" * 96)
        print("ФАЙЛЫ:")
        for t, kind, txt in sess.files:
            print("  +%9.3fs  %-5s %s" % (t, kind, txt))
        for path, size, digest in sess.filehash:
            print("  HASH   size=%-9d sha256=%s  %s" % (size, digest, path))

    if sess.errors:
        print("-" * 96)
        print("ОШИБКИ/АНОМАЛИИ В ЛОГЕ (%d):" % len(sess.errors))
        for e in sess.errors[:25]:
            print("  " + e)

    marks_sorted = sorted(sess.marks, key=lambda x: x[0])
    excl: list[tuple[float, str, str, int]] = []
    read_events: list[tuple[int, bytes, float]] = []
    read_mismatch: list[str] = []
    prev_t = None
    long_gaps: list[tuple[float, float]] = []
    pending_marks: list[str] = []
    mark_i = 0
    total_tx = total_rx = 0
    trunc_n = 0

    for e in sess.exchanges:
        while mark_i < len(marks_sorted) and marks_sorted[mark_i][0] <= e.tx_t:
            pending_marks.append(marks_sorted[mark_i][2])
            mark_i += 1
        if pending_marks:
            for mk in pending_marks:
                excl.append((e.tx_t, "~MARK~", mk, 0))
            pending_marks = []
        if prev_t is not None and (e.tx_t - prev_t) >= gap:
            long_gaps.append((prev_t, e.tx_t))
        if e.tx_trunc or e.rx_trunc:
            trunc_n += 1
        total_tx += len(e.tx)
        total_rx += len(e.rx)
        echo, residual = split_echo_response(e.tx, e.rx)
        klass, payload, tail = parse_frame(e.tx, residual)
        rt = read_telegram(e.tx)
        if rt is not None and payload:
            addr, blen = rt
            read_events.append((addr, payload, e.tx_t))
            if blen != len(payload):
                read_mismatch.append("+%.3fs addr=0x%06X заявлено %d байт, получено %d" % (
                    e.tx_t, addr, blen, len(payload)))
            shape = "READ 0x%06X +%d" % (addr, blen)
        else:
            off = 4 if (e.tx and e.tx[0] == 0xB8) else 2
            shape = "%s %s" % (tx_summary(e.tx), fmt(e.tx[off:], 10))
        resp_txt = klass
        if payload:
            resp_txt += " payload=%dB %s" % (len(payload), fmt(payload, 6))
        if tail:
            resp_txt += " tail=%s" % fmt(tail, 8)
        line = (e.tx_t, shape, "echo=%s -> %s" % (echo, resp_txt), 1)
        if (not show_all and rt is None and excl and excl[-1][1] == shape
                and excl[-1][2] == line[2] and excl[-1][3] > 0):
            p = excl[-1]
            excl[-1] = (p[0], p[1], p[2], p[3] + 1)
        else:
            excl.append(line)
        prev_t = e.tx_t

    print("-" * 96)
    print("ОБМЕН (по TX-посылкам; одинаковые подряд склеены xN):")
    if trunc_n:
        print("  ВНИМАНИЕ: усечённых дампов: %d (len > выведено)" % trunc_n)
    if sess.ovl_zero:
        print("  ВНИМАНИЕ: VCP-чтений без счётчика байт (overlapped, n=0): %d — в разбор не взяты"
              % sess.ovl_zero)
    for t, shape, resp_txt, cnt in excl:
        if shape == "~MARK~":
            print("  ~~~~ MARK: %s" % resp_txt)
            continue
        tail = "   x%d" % cnt if cnt > 1 else ""
        print("  +%10.3fs  %-32s %s%s" % (t, shape, resp_txt, tail))
    for mk in marks_sorted[mark_i:]:
        print("  ~~~~ MARK (после последней посылки): %s" % mk[2])
    print("  ИТОГО: посылок=%d  TX=%dB  RX=%dB" % (len(sess.exchanges), total_tx, total_rx))

    if long_gaps:
        print("-" * 96)
        print("ПАУЗЫ >= %.2fs (границы фаз — здесь обычно действия оператора):" % gap)
        for t0, t1 in long_gaps:
            who = [m[2] for m in marks_sorted if t0 <= m[0] <= t1]
            print("  +%9.3fs .. +%9.3fs  %6.2fs%s" % (
                t0, t1, t1 - t0, ("   MARK: " + "; ".join(who)) if who else ""))

    ranges = stream_ranges(read_events)
    if ranges:
        print("-" * 96)
        print("ПОТОКИ ЧТЕНИЯ (cmd 0x06; в порядке времени, повторные проходы — отдельно):")
        seen_names: dict[str, int] = {}
        for start, blob, blocks in ranges:
            print("  0x%06X..0x%06X  %7d B  блоков=%-5d  sha256=%s" % (
                start, start + len(blob), len(blob), blocks, sha(blob)))
            if reads_dir:
                os.makedirs(reads_dir, exist_ok=True)
                name = "%06X-%06X" % (start, start + len(blob))
                seen_names[name] = seen_names.get(name, 0) + 1
                suffix = "" if seen_names[name] == 1 else "-s%d" % seen_names[name]
                with open(os.path.join(reads_dir, name + suffix + ".bin"), "wb") as fh:
                    fh.write(blob)
        if len(read_events) > 2:
            ts = [t for _, _, t in read_events]
            deltas = [b - a for a, b in zip(ts, ts[1:]) if 0 < b - a < 5]
            if deltas:
                med = statistics.median(deltas)
                total_bytes = sum(len(p) for _, p, _ in read_events)
                span = ts[-1] - ts[0]
                print("  темп: медиана %.0f мс/блок, всего %.1f с, %.0f Б/с" % (
                    med * 1000, span, total_bytes / span if span else 0))
    if read_mismatch:
        print("-" * 96)
        print("НЕСООТВЕТСТВИЯ ДЛИНЫ В ЧТЕНИЯХ:")
        for x in read_mismatch[:20]:
            print("  " + x)
    print()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=DEFAULT_LOG)
    ap.add_argument("--gap", type=float, default=0.5, help="порог длинной паузы, с")
    ap.add_argument("--all", action="store_true", help="не склеивать повторяющиеся посылки")
    ap.add_argument("--no-dump", action="store_true", help="не писать сырые потоки")
    ap.add_argument("--no-reads", action="store_true", help="не сохранять собранные чтения")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print("нет лога: %s" % args.log, file=sys.stderr)
        return 1
    sessions, preamble = parse_log(args.log)
    print("Лог: %s" % args.log)
    if preamble:
        print("Преамбула (%d строк, первые 20):" % len(preamble))
        for ln in preamble[:20]:
            print("  " + ln)
    outdir = os.path.dirname(os.path.abspath(args.log))
    for sess in sessions:
        if not sess.exchanges and not sess.files:
            continue
        if not args.no_dump:
            dump_streams(sess, outdir)
        report(sess, args.gap, None if args.no_reads else os.path.join(outdir, "reads"), args.all)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
