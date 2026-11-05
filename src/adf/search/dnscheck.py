"""Tells a bad address from a bad strategy.

The search only sees addresses from the core's DNS. When one of them fails with every strategy, the
result looks like a strategy problem and no amount of searching helps. Where a second resolver returns
another network, the best strategy is measured on both sets of addresses.
"""

from __future__ import annotations

import dataclasses
import ipaddress
from typing import Any, Callable, Dict, List, Mapping, Sequence

from ..probe.backend import Backend
from ..probe.model import BatchResult, Target

CHECK_REPS = 3
MAX_ADDRESSES = 2
WORKS = 0.8
FAILS = 0.5
MEASURED_KINDS = ("https", "streaming", "tls_large")

Measure = Callable[[Sequence[Target], Mapping[str, Sequence[str]], int], BatchResult]


def _network(ip: str) -> str:
    return str(ipaddress.ip_network(f"{ip}/{24 if ':' not in ip else 48}", strict=False))


def other_networks(live: Sequence[str], other: Sequence[str]) -> List[str]:
    """Addresses of ``other`` outside the networks of ``live``: a CDN rotates within a network anyway."""
    known = {_network(ip) for ip in live}
    out: Dict[str, str] = {}
    for ip in other:
        if _network(ip) not in known:
            out.setdefault(_network(ip), ip)
    return list(out.values())[:MAX_ADDRESSES]


def verdict(live_rate: float, other_rate: float) -> str:
    if live_rate >= WORKS:
        return "ok"
    if other_rate >= WORKS and live_rate < FAILS:
        return "dns"
    if other_rate < FAILS and live_rate < FAILS:
        return "strategy"
    return "unclear"


def _tally(batch: BatchResult) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for r in batch.results:
        if r.verdict != "proxy_error":
            done = out.setdefault(r.target, [0, 0])
            done[0] += 1 if r.ok else 0
            done[1] += 1
    return out


def _rate(tally: Sequence[int]) -> float:
    return tally[0] / tally[1] if tally[1] else 0.0


def _in_families(t: Target, addresses: Sequence[str]) -> List[str]:
    return [ip for ip in addresses if ("ipv6" if ":" in ip else "ipv4") in t.families]


def run_check(backend: Backend, measure: Measure, targets: Sequence[Target], ips: Mapping[str, Sequence[str]],
              log: Callable[[str], None] = lambda m: None) -> Dict[str, Any]:
    result: Dict[str, Any] = dict(backend.dns_info(), rows=[], error="")
    pairs = []
    for t in targets:
        if t.kind in MEASURED_KINDS and t.host:
            live = _in_families(t, ips.get(t.id, ()))
            other = other_networks(live, _in_families(t, backend.other_addresses(t.host)))
            if other:
                pairs.append((t, live, other))
    if not pairs:
        return result
    widened = [dataclasses.replace(t, max_ips=max(len(live), len(other), 1)) for t, live, other in pairs]
    with_live = [t for t, (_, live, _) in zip(widened, pairs) if live]
    live_by_id = {t.id: live for t, (_, live, _) in zip(widened, pairs)}
    live_runs = measure(with_live, live_by_id, CHECK_REPS) if with_live else BatchResult(ok=True)
    other_runs = measure(widened, {t.id: other for t, (_, _, other) in zip(widened, pairs)}, CHECK_REPS)
    if live_runs.engine_failed or other_runs.engine_failed:
        result["error"] = live_runs.engine_error or other_runs.engine_error
        return result
    live_tally, other_tally = _tally(live_runs), _tally(other_runs)
    for t, live, other in pairs:
        on_live = live_tally.get(t.id, [0, 0])
        on_other = other_tally.get(t.id, [0, 0])
        row = {"target": t.id, "host": t.host, "live": live, "live_ok": on_live[0], "live_n": on_live[1],
               "other": other, "other_ok": on_other[0], "other_n": on_other[1],
               "verdict": verdict(_rate(on_live), _rate(on_other))}
        result["rows"].append(row)
        if row["verdict"] == "dns":
            log(f"{t.host}: {live} fails, {other} works: the DNS server is at fault, not the strategy")
    return result
