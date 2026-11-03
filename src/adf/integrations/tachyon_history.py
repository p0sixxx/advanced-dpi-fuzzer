"""Analysis of Tachyon DPI Fuzzer v2 history (``/etc/tachyon/fuzzer_history.json``).

Turns the stored runs into a table, flags patterns that indicate unreliable
selection (the same strategy winning with very different stability, winners
chosen on targets that were not blocked) and converts winners into ADF
strategies so the next ``adf run`` starts from them.
"""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..engines import StrategyError, TachyonDesync, Zapret, Zapret2, ByeDPI
from ..strategy import Strategy, from_text

_ENGINE_MAP = {"desync": TachyonDesync, "zapret2": Zapret2, "zapret": Zapret, "byedpi": ByeDPI}


def _date(ts: Any) -> str:
    try:
        return _dt.datetime.fromtimestamp(int(ts), _dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, OverflowError, OSError):
        return "?"


def to_strategy(engine: str, args: str, name: str = "") -> Tuple[Optional[Strategy], str]:
    cls = _ENGINE_MAP.get(engine)
    if cls is None:
        return None, f"unknown engine {engine}"
    try:
        return from_text(cls(), args, origin="tachyon_v2", name=name[:120]), ""
    except StrategyError as e:
        return None, str(e)


def analyze(data: Mapping[str, Any]) -> Dict[str, Any]:
    entries = list(data.get("entries", []))
    runs: List[Dict[str, Any]] = []
    stability: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    winners: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    findings: List[str] = []
    strategies: List[Strategy] = []
    seen = set()
    nested = 0
    for e in entries:
        best = e.get("best_strategy") or {}
        det = e.get("dpi_detection") or {}
        row = {
            "date": _date(e.get("timestamp")), "engine": e.get("engine", ""), "target": e.get("target", ""),
            "mode": e.get("mode", ""), "tested": e.get("total_tested", 0), "working": e.get("working_count", 0),
            "seconds": e.get("duration_sec", 0), "dpi": det.get("type", ""), "best": best.get("args", ""),
            "stability_pct": best.get("stability_pct"), "confidence": best.get("confidence", ""),
            "ttfb_ms": best.get("ttfb_ms"),
        }
        runs.append(row)
        if best.get("args"):
            stability[(row["engine"], best["args"])].append(float(best.get("stability_pct") or 0))
            winners[row["target"]][best["args"]] += 1
            if str(best.get("name", "")).count("Prior Winner") > 1:
                nested += 1
            if det.get("type") == "none":
                findings.append(f"{row['date']} {row['target']}: target was not blocked (\"{det.get('details', '')}\")"
                                f" but '{best['args']}' was still reported as the best strategy")
            key = (row["engine"], best["args"])
            if key not in seen:
                seen.add(key)
                s, err = to_strategy(row["engine"], best["args"], best.get("name", ""))
                if s is not None:
                    strategies.append(s)
                else:
                    findings.append(f"winner '{best['args']}' ({row['engine']}) cannot be represented: {err}")
        details = str(det.get("details", ""))
        perr = str((det.get("probe_metrics") or {}).get("error", ""))
        if "TCP connect timed out" in details and "after TCP connect" in perr:
            row["dpi_note"] = "details say TCP connect timed out, probe says TCP was established (TLS stalled)"
    for (eng, args), vals in stability.items():
        if len(vals) > 1 and max(vals) - min(vals) >= 50:
            findings.append(f"'{args}' won {len(vals)} times with stability {', '.join(f'{v:g}%' for v in vals)}: "
                            "3-repetition verification cannot tell stable from lucky")
    for target, wins in winners.items():
        if len(wins) > 1:
            findings.append(f"{target}: {len(wins)} different winners across runs: "
                            + "; ".join(f"{a} ×{n}" for a, n in sorted(wins.items(), key=lambda kv: -kv[1])))
    if nested:
        findings.append(f"{nested} winner names carry nested '⭐ Prior Winner' prefixes (name grows on every reuse)")
    inconsistent = sum(1 for r in runs if r.get("dpi_note"))
    if inconsistent:
        findings.append(f"{inconsistent} runs report 'TCP connect timed out' although the probe shows TCP was "
                        "established and the TLS handshake stalled (ClientHello dropped)")
    total_s = sum(int(r["seconds"] or 0) for r in runs)
    return {"runs": runs, "findings": findings, "strategies": strategies, "total_seconds": total_s}


def markdown(result: Mapping[str, Any]) -> str:
    lines = ["# Tachyon DPI Fuzzer v2: история прогонов", "",
             "| Дата (UTC) | Движок | Цель | Режим | Проверено | Рабочих | Время, с | DPI | Лучшая | Стаб. | Увер. |",
             "|---|---|---|---|---:|---:|---:|---|---|---:|---|"]
    for r in result["runs"]:
        lines.append(f"| {r['date']} | {r['engine']} | {r['target']} | {r['mode']} | {r['tested']} | {r['working']} "
                     f"| {r['seconds']} | {r['dpi']} | `{r['best'] or '—'}` | {r['stability_pct'] if r['stability_pct'] is not None else '—'} "
                     f"| {r['confidence'] or '—'} |")
    lines += ["", f"Суммарное время подбора: {result['total_seconds'] // 60} мин.", "", "## Наблюдения", ""]
    lines += [f"* {f}" for f in result["findings"]] or ["* —"]
    lines += ["", "## Стратегии-победители, добавленные в базу ADF как стартовые кандидаты", ""]
    lines += [f"* `{s.engine}` `{s.text}`" for s in result["strategies"]] or ["* —"]
    return "\n".join(lines) + "\n"
