"""Разбор одной сессии осциллографа: каково качество записи и привязки.

Считает по scope/frames.jsonl:
  * распределение шага frame_id (сколько публикаций пропущено между кадрами);
  * линейную регрессию t сессии по номеру блока и остатки (медиана/p95/max, мс) —
    это джиттер доставки, а не «точность часов источника»;
  * проверку отсчётов: для кадра декодирует base64 i16 и сравнивает min/max по
    каждому каналу со stats.vmin/vmax (расхождение ≤ 1 мВ доказывает, что в файле
    настоящие вольты нужного канала, а не перепутанные столбцы);
  * сводку по каналам: сколько отсчётов, диапазон, представление.

Запуск:
  python build/analyze-scope.py sessions/<id>/scope/frames.jsonl
"""
import base64
import json
import struct
import sys
from statistics import median

import numpy as np


def percentile(values, p):
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return float("nan")
    return float(np.percentile(arr, p))


def main(path):
    frames = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                frames.append(json.loads(line))
            except json.JSONDecodeError:
                # Оборванная последняя строка после сбоя — читатель обязан её пропустить.
                continue
    if not frames:
        print("нет кадров")
        return 2

    print(f"кадров: {len(frames)}")
    first, last = frames[0], frames[-1]
    print(f"первый: frame_id={first['frame_id']} t={first['t']:.3f} "
          f"channels={first['channels']} width={first.get('width')} "
          f"window_samples={first.get('window_samples')} exact={first.get('exact')} "
          f"representation={first.get('representation')} unit={first.get('unit')}")
    print(f"последний: frame_id={last['frame_id']} t={last['t']:.3f}")

    ids = [f["frame_id"] for f in frames]
    steps = [b - a for a, b in zip(ids, ids[1:])]
    dup = sum(1 for s in steps if s == 0)
    gaps = [s for s in steps if s > 1]
    print(f"шагов frame_id: {len(steps)}, дублей: {dup}, разрывов: {len(gaps)}, "
          f"пропущено публикаций: {sum(s - 1 for s in gaps)}")

    ts = np.asarray([f["t"] for f in frames], dtype=float)
    fid = np.asarray(ids, dtype=float)
    # t = a + b * frame_id: b — средний период публикации.
    b, a = np.polyfit(fid, ts, 1)
    resid = (ts - (a + b * fid)) * 1000.0  # мс
    print(f"период публикации по регрессии: {b*1000:.2f} мс "
          f"(= {1/b:.2f} кадр/с)")
    print(f"остатки привязки, мс: медиана {median(abs(resid)):.1f}, "
          f"p95 {percentile(abs(resid), 95):.1f}, max {max(abs(resid)):.1f}")

    deltas = np.diff(ts) * 1000.0
    med = float(np.median(deltas)) if deltas.size else float("nan")
    dev = np.abs(deltas - med)
    print(f"интервал между кадрами, мс: медиана {med:.1f}, "
          f"p95 отклонения {percentile(dev, 95):.1f}, max отклонения {float(dev.max()) if dev.size else float('nan'):.1f}")

    # Целостность отсчётов: min/max кадра из columns_b64 против stats.
    checked = 0
    worst = 0.0
    for frame in frames[:20]:
        cols = frame.get("columns_b64") or ""
        if not cols:
            continue
        raw = base64.b64decode(cols)
        width = frame.get("width") or 0
        chans = frame.get("channels") or []
        if not width or not chans:
            continue
        need = width * len(chans) * 4
        if len(raw) < need:
            print(f"  кадр {frame['frame_id']}: base64 {len(raw)} < {need} — обрезан")
            continue
        stats = {s["ch"]: s for s in frame.get("stats") or []}
        for index, ch in enumerate(chans):
            lo = np.frombuffer(raw, dtype="<i2", count=width * 2, offset=index * width * 4)
            lo = lo.copy()
            lo[0::2] = np.minimum(lo[0::2], np.iinfo(np.int16).max)
            pairs = lo.reshape(-1, 2).astype(np.int32)
            empty = pairs[:, 0] > pairs[:, 1]
            vals_lo = pairs[~empty, 0]
            vals_hi = pairs[~empty, 1]
            if vals_lo.size == 0:
                continue
            vmin = vals_lo.min() / 1000.0
            vmax = vals_hi.max() / 1000.0
            st = stats.get(ch)
            if st and st.get("vmin") is not None:
                worst = max(worst, abs(vmin - st["vmin"]), abs(vmax - st["vmax"]))
            checked += 1
    print(f"сверено каналов кадра: {checked}, худшее расхождение с stats: "
          f"{worst*1000:.1f} мВ (ожидается ≤ 1 мВ)")

    by_ch = {}
    for frame in frames:
        for st in frame.get("stats") or []:
            slot = by_ch.setdefault(st["ch"], {"n": 0, "vmin": [], "vmax": []})
            slot["n"] += st.get("n") or 0
            if st.get("vmin") is not None:
                slot["vmin"].append(st["vmin"])
            if st.get("vmax") is not None:
                slot["vmax"].append(st["vmax"])
    for ch in sorted(by_ch):
        slot = by_ch[ch]
        lo = min(slot["vmin"]) if slot["vmin"] else float("nan")
        hi = max(slot["vmax"]) if slot["vmax"] else float("nan")
        print(f"  CH{ch}: отсчётов {slot['n']}, Vmin {lo:.3f} В, Vmax {hi:.3f} В")

    segs = sorted({f.get("segment", 0) for f in frames})
    print(f"сегментов: {len(segs)} {segs}")
    print(f"деградированных строк: {sum(1 for f in frames if f.get('degraded'))}")
    widths = {}
    for frame in frames:
        key = (frame.get("width"), frame.get("exact"), frame.get("representation"))
        widths[key] = widths.get(key, 0) + 1
    for key, count in sorted(widths.items(), key=lambda kv: -kv[1]):
        print(f"  ширина {key[0]} exact={key[1]} {key[2]}: {count} строк")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else ""))
