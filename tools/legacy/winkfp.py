#!/usr/bin/env python3
"""WinKFP (NFS/EDIABAS) — распознавание блока, окружение EDIABAS и его трассы.

WinKFP общается с ЭБУ не через ftd2xx, а через EDIABAS (Interface=STD:OBD,
COM-порт VCP) — байтовый поток ловит обычный VCP-хук логера. Сверх байтового
потока EDIABAS пишет собственные трассы:

    <TracePath>\\api.trc   — вызовы job'ов SGBD и их результаты (семантический слой)
    <TracePath>\\IFH.trc   — обмен с интерфейсом (INPUT/OUTPUT на границе)

Модуль даёт логеру: алиасы блока (WinKFP → C:\\EC-APPS\\NFS\\BIN\\winkfpt.exe),
факты из ediabas.ini / Winkfpt.ini / obd.ini для шапки, разбор api.trc
(parse_api_trc) и снятие приращений трасс по шагам оператора (TraceWatcher).
"""

from __future__ import annotations

import os
import re

WINFKP_EXE = r"C:\EC-APPS\NFS\BIN\winkfpt.exe"
WINKFP_INI = r"C:\EC-APPS\NFS\BIN\Winkfpt.ini"
EDIABAS_INI = r"C:\EDIABAS\Bin\ediabas.ini"
OBD_INI = r"C:\EDIABAS\Bin\obd.ini"
DEFAULT_TRACE_DIR = r"C:\EDIABAS\TRACE"

BLOCK_LABEL = "WinKFP (NFS/EDIABAS)"
_ALIASES = {"winkfp", "winkfpt", "winkfpt.exe", "win-kfp", "win kfp", "nfs", "kfp"}
# прочие приложения EDIABAS (INPA/Tool32/NCS): трассы те же, job-уровень тоже полезен
_EDIABAS_PREFIXES = ("winkfp", "inpa", "tool32", "ncsexp", "ediabas", "nfs")


def _norm(name: str) -> str:
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def is_winkfp(name: str) -> bool:
    """Блок/путь относится к WinKFP? (алиас или basename winkfp*)"""
    n = _norm(name)
    if not n:
        return False
    if n in _ALIASES:
        return True
    return os.path.basename(n).startswith("winkfp")


def is_ediabas(name: str) -> bool:
    """Приложение ходит в ЭБУ через EDIABAS (WinKFP, INPA, Tool32, NCS)?
    Для таких сессий снимаем и трассы api.trc/IFH.trc."""
    n = _norm(name)
    if not n:
        return False
    base = os.path.basename(n)
    return any(base.startswith(p) for p in _EDIABAS_PREFIXES)


def known_blocks() -> list[tuple[str, str]]:
    """Известные логеру инструменты вне Quickflash-каталогов: [(имя, exe)]."""
    out: list[tuple[str, str]] = []
    if os.path.exists(WINFKP_EXE):
        out.append((BLOCK_LABEL, WINFKP_EXE))
    return out


# строки api.trc, которые не являются результатами job'а
_RESULT_SKIP = {"OBJECT", "JOBNAME", "VARIANTE", "JOBSTATUS", "SAETZE", "SETZE"}

_JOBARG_RE = re.compile(r'^\s*"(.*)"\s*$')
_RESULT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_ERROR_RE = re.compile(r"^\s*(?:Error|Fehler)\s*\(\s*(-?\d+)\s*\)\s*(.*)$")


def ini_get(path: str, key: str) -> str:
    """Первое значение key=... в ini (комментарии ';' игнорируем)."""
    try:
        with open(path, "r", encoding="latin-1", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s or s[0] in ";#":
                    continue
                if "=" not in s:
                    continue
                k, v = s.split("=", 1)
                if k.strip().lower() == key.lower():
                    return v.strip()
    except OSError:
        pass
    return ""


def ediabas_facts() -> dict:
    """Ключевые настройки окружения EDIABAS/WinKFP (для шапки лога и сообщений)."""
    return {
        "interface": ini_get(EDIABAS_INI, "Interface"),
        "trace_path": ini_get(EDIABAS_INI, "TracePath") or DEFAULT_TRACE_DIR,
        "trace_size_kb": ini_get(EDIABAS_INI, "TraceSize"),
        "api_trace": ini_get(EDIABAS_INI, "ApiTrace"),
        "ifh_trace": ini_get(EDIABAS_INI, "IfhTrace"),
        "obd_port": ini_get(OBD_INI, "Port"),
        "obd_hw": ini_get(OBD_INI, "Hardware"),
        "winkfp_api_trace": ini_get(WINKFP_INI, "API_TRACE"),
        "winkfp_ifh_trace": ini_get(WINKFP_INI, "IFH_TRACE"),
    }


def facts_line() -> str:
    """Однострочная сводка окружения (что и куда шьём/пишем)."""
    f = ediabas_facts()
    parts: list[str] = []
    if f["interface"]:
        parts.append("Interface=%s" % f["interface"])
    if f["obd_port"]:
        parts.append("obd.ini [OBD] Port=%s Hardware=%s" % (f["obd_port"], f["obd_hw"] or "?"))
    if f["trace_path"]:
        parts.append("трассы=%s" % f["trace_path"])
    return "; ".join(parts)


def tracing_problem() -> str:
    """Предупреждение, если трассы EDIABAS выключены (job-уровня не будет)."""
    f = ediabas_facts()
    off = [k for k, v in (("ApiTrace", f["api_trace"]), ("IfhTrace", f["ifh_trace"])) if v == "0"]
    if off:
        return "трассы EDIABAS выключены (%s=0 в %s) — job-уровень WinKFP не пишется" % (
            ", ".join(off), EDIABAS_INI)
    return ""


def parse_api_trc(text: str) -> list[dict]:
    """Разобрать текст api.trc в список job'ов.

    Запись: 'Job' -> sgbd, имя job'а, аргументы ('Results:' -> NAME = VALUE),
    ошибки ('Error (98) SYS-0008: JOB NOT FOUND') приходят внутри блока job'а.
    Служебные строки-маркеры ('#@N;P...;#') и коды игнорируются.
    """
    jobs: list[dict] = []
    cur: dict | None = None
    mode = ""
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s == "Job":
            cur = {"sgbd": "", "job": "", "args": [], "results": {}, "errors": []}
            jobs.append(cur)
            mode = "job"
            continue
        if s.startswith("Results") or s.startswith("Ergebnis"):
            mode = "results"
            continue
        if s == "Initialization" or s in ("End", "Ende"):
            mode = ""
            continue
        m = _ERROR_RE.match(s)
        if m:
            if cur is not None:
                err = "Error (%s) %s" % (m.group(1), m.group(2).strip())
                if not cur["errors"] or cur["errors"][-1] != err:   # api.trc повторяет ошибку
                    cur["errors"].append(err)
            mode = ""
            continue
        if cur is None:
            continue
        if mode == "job":
            m = _JOBARG_RE.match(s)
            if m:
                val = m.group(1)
                if not cur["sgbd"]:
                    cur["sgbd"] = val
                elif not cur["job"]:
                    cur["job"] = val
                elif val:
                    cur["args"].append(val)
            continue
        if mode == "results":
            m = _RESULT_RE.match(s)
            if m and m.group(1) not in _RESULT_SKIP:
                cur["results"].setdefault(m.group(1), m.group(2))
    return jobs


def format_job(j: dict) -> str:
    """Человекочитаемая строка job'а для лога шага."""
    head = 'job="%s" sgbd="%s"' % (j["job"] or "?", j["sgbd"] or "?")
    if j["args"]:
        head += " args=%s" % ",".join('"%s"' % a for a in j["args"][:3])
    parts = [head]
    if j["errors"]:
        parts.append("ОШИБКА: " + "; ".join(j["errors"]))
    if j["results"]:
        items = list(j["results"].items())
        shown = " ".join("%s=%s" % (k, v) for k, v in items[:10])
        more = "" if len(items) <= 10 else " …+%d" % (len(items) - 10)
        parts.append("результатов=%d %s%s" % (len(items), shown, more))
    return " | ".join(parts)


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _delta(path: str, off: int) -> bytes:
    """Приращение файла с off; при ротации (TraceSize) — всё с начала."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(0 if size < off else off)
            return fh.read()
    except OSError:
        return b""


class TraceWatcher:
    """Приращения EDIABAS-трасс по шагам оператора.

    mark() в начале шага, collect() в конце: job'ы из api.trc строчками в лог шага,
    сырые куски обеих трасс — файлами в папку сессии (api.trc ограничен TraceSize
    и ротируется, поэтому копия куска — единственный способ сохранить историю).
    """

    NAMES = ("api.trc", "IFH.trc")

    def __init__(self, trace_dir: str = ""):
        self.dir = trace_dir or ediabas_facts()["trace_path"] or DEFAULT_TRACE_DIR
        self.files = [os.path.join(self.dir, n) for n in self.NAMES]
        self.enabled = os.path.isdir(self.dir)
        self.marks: dict[str, int] = {}
        self.jobs_total = 0
        self.jobs_errors = 0

    def mark(self) -> None:
        """Запомнить позиции трасс (начало шага)."""
        self.marks = {p: _size(p) for p in self.files}

    def collect(self, idx: int, path_for) -> tuple[list[str], dict]:
        """(строки для лога шага, JSON-payload). path_for(имя) -> путь артефакта."""
        lines: list[str] = []
        blobs: dict[str, bytes] = {}
        for p in self.files:
            blob = _delta(p, self.marks.get(p, 0))
            if blob:
                blobs[p] = blob
        api_path = self.files[0]
        jobs = parse_api_trc(blobs[api_path].decode("latin-1", errors="replace")) if api_path in blobs else []
        self.jobs_total += len(jobs)
        self.jobs_errors += sum(1 for j in jobs if j["errors"])
        for j in jobs:
            lines.append("# PHASE %d   winkfp: %s" % (idx, format_job(j)))
        if not jobs and blobs:
            sizes = ", ".join("%s +%d Б" % (os.path.basename(p), len(b)) for p, b in blobs.items())
            lines.append("# PHASE %d   winkfp: новых job'ов нет (%s)" % (idx, sizes))
        for p, blob in blobs.items():
            try:
                with open(path_for("step-%02d-%s" % (idx, os.path.basename(p))), "wb") as fh:
                    fh.write(blob)
            except OSError:
                pass
        payload: dict = {}
        if jobs:
            payload["winkfp_jobs"] = [{
                "sgbd": j["sgbd"], "job": j["job"], "args": j["args"], "errors": j["errors"],
                "results": dict(list(j["results"].items())[:12]), "results_total": len(j["results"]),
            } for j in jobs]
        return lines, payload

    def final_copy(self, path_for) -> list[str]:
        """Сохранить текущие трассы целиком (хвост окна TraceSize) в папку сессии."""
        out: list[str] = []
        for p in self.files:
            if not os.path.exists(p):
                continue
            dest = path_for("ediabas-%s" % os.path.basename(p).lower())
            try:
                with open(p, "rb") as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                out.append(dest)
            except OSError:
                pass
        return out

    def summary_line(self) -> str:
        return "WinKFP/EDIABAS: job'ов за сессию %d, с ошибками %d" % (self.jobs_total, self.jobs_errors)
