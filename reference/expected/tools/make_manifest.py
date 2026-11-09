# -*- coding: utf-8 -*-
"""Манифест reference/expected: роли, размеры и sha256 всех golden-артефактов."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

EXP = Path(r"D:\FTDI_USB_Logger\reference\expected")
LOGS = Path(r"D:\FTDI_USB_Logger\reference\logs")
PARSER = Path(r"E:\Replica\work\orig-capture\parse_family.py")
LOG_ORDER = [
    "winkfp-e2e-capture.log",
    "winkfp-e2e-logger.out",
    "ftd2xx-bms46-session.log",
    "python-capture-empty.log",
    "bms46-no-traffic.log",
]


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def role(rel: str) -> str:
    if rel.endswith(".parse.out.txt"):
        return "cli-stdout"
    if rel.endswith(".parse.err.txt"):
        return "cli-stderr"
    if rel.endswith(".summary.json"):
        return "summary-json"
    if rel.endswith("tx-stream.bin"):
        return "side-tx-stream"
    if rel.endswith("rx-stream.bin"):
        return "side-rx-stream"
    if rel.endswith("stream-index.tsv"):
        return "side-stream-index"
    if "\\reads\\" in rel.replace("/", "\\"):
        return "side-reads-bin"
    return "other"


artifacts = []
for p in sorted(EXP.rglob("*")):
    if not p.is_file():
        continue
    rel = str(p.relative_to(EXP))
    if rel == "manifest.json" or rel == "README.md" or rel.startswith("tools" + "\\") or rel.startswith("tools/"):
        continue
    artifacts.append({"path": rel.replace("\\", "/"), "role": role(rel), "bytes": p.stat().st_size, "sha256": sha(p)})

manifest = {
    "schema": "reference-expected-manifest/v1",
    "purpose": "golden-эталоны старого parse_family.py для сверки нового Rust-разбора",
    "parser": {"path": str(PARSER), "sha256": sha(PARSER), "python": "3.12.4", "gap_seconds": 2.0},
    "logs": [
        {"file": n, "path": str(LOGS / n), "bytes": (LOGS / n).stat().st_size, "sha256": sha(LOGS / n)}
        for n in LOG_ORDER
    ],
    "summary_schema": "old-parse-family-golden/v1",
    "artifacts_count": len(artifacts),
    "artifacts": artifacts,
}
(EXP / "manifest.json").write_bytes((json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
print("artifacts:", len(artifacts))
