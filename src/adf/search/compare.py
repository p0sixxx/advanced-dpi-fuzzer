"""Side-by-side measurement of strategies under identical conditions.

Variants are measured round-robin (A, B, C, A, B, C, …) so that a change in the
network affects all of them equally; a round is discarded when the control
targets fail.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Sequence

from ..db import Store
from ..engines import Engine
from ..probe.backend import Backend, BackendError
from ..probe.model import BatchResult, Target
from ..safety import Guard
from ..scoring import StrategyScore, Thresholds
from ..strategy import Strategy
from .dnscheck import run_check


@dataclass
class Variant:
    label: str
    strategy: Optional[Strategy] = None
    outbound: Optional[Dict[str, Any]] = None   # raw tachyon-core outbound (Adaptive 2.0 etc.)

    @property
    def id(self) -> str:
        if self.strategy is not None:
            return self.strategy.id
        blob = json.dumps(self.outbound, sort_keys=True)
        return "raw-" + hashlib.sha1(blob.encode()).hexdigest()[:12]

    @property
    def text(self) -> str:
        return self.strategy.text if self.strategy else json.dumps(self.outbound, ensure_ascii=False)


def _dns_check(backend: Backend, engine: Engine, variants: Sequence[Variant], rows: Sequence[Mapping[str, Any]],
               targets: Sequence[Target], ips: Mapping[str, Sequence[str]], log: Callable[[str], None]) -> Dict[str, Any]:
    working = [(r, v) for r, v in zip(rows, variants) if not r["error"]]
    if not working:
        return dict(backend.dns_info(), rows=[], error="")
    best = max(working, key=lambda pair: (pair[0]["lb"], pair[0]["rate"]))[1]

    def measure(ts: Sequence[Target], addresses: Mapping[str, Sequence[str]], reps: int) -> BatchResult:
        if best.strategy is not None:
            return backend.run_batch(engine, best.strategy.params, ts, addresses, reps=reps)
        return backend.run_raw_outbound(best.outbound or {}, ts, addresses, reps=reps)
    try:
        return run_check(backend, measure, targets, ips, log)
    except BackendError as e:
        return dict(backend.dns_info(), rows=[], error=str(e))


def compare(store: Store, backend: Backend, engine: Engine, variants: Sequence[Variant], targets: Sequence[Target],
            controls: Sequence[Target], ips: Mapping[str, Sequence[str]], reps: int, network_id: str, guard: Guard,
            log: Callable[[str], None] = lambda m: None) -> Dict[str, Any]:
    guard.start()
    core = str(backend.env().get("core_version") or "")
    run_id = store.start_run(network_id, engine.name, core, getattr(backend, "name", "?"),
                             bool(getattr(backend, "simulated", False)),
                             {"compare": [v.label for v in variants], "reps": reps})
    epoch = store.current_epoch(network_id)
    sim = bool(getattr(backend, "simulated", False))
    req = {t.id: t.required for t in targets}
    scores = {v.id: StrategyScore(v.id, complexity=v.strategy.complexity if v.strategy else 0.0) for v in variants}
    for v in variants:
        if v.strategy:
            store.upsert_strategy(v.strategy)
        else:
            store.upsert_strategy(Strategy(engine="tachyon_raw", params_json=json.dumps(v.outbound, sort_keys=True),
                                           text=v.text, complexity=0.0, origin="compare", name=v.label, id=v.id))
    rejected: Dict[str, str] = {}
    discarded = 0
    status = "finished"
    rnd = 0
    try:
        while rnd < reps:
            guard.check()
            batch_results: Dict[str, BatchResult] = {}
            for v in variants:
                guard.before_batch()
                if v.strategy is not None:
                    b = backend.run_batch(engine, v.strategy.params, targets, ips, reps=1)
                else:
                    b = backend.run_raw_outbound(v.outbound or {}, targets, ips, reps=1)
                guard.after_batch(len(b.results))
                batch_results[v.id] = b
                if b.engine_failed and v.id not in rejected:
                    rejected[v.id] = b.engine_error
                    log(f"{v.label}: {b.engine_error}")
            ctrl_ok = True
            if controls:
                cb = backend.run_batch(engine, None, controls, ips, reps=1)
                store.add_trials(run_id, None, cb.results, network_id, epoch, sim, "control")
                ctrl_ok = sum(r.ok for r in cb.results) >= max(1, (len(cb.results) + 1) // 2)
            if not ctrl_ok:
                discarded += 1
                log(f"round {rnd + 1}: control failed, round discarded")
                if discarded > reps:
                    status = "aborted"
                    break
                guard.backoff()
                continue
            for v in variants:
                b = batch_results[v.id]
                store.add_trials(run_id, v.id, b.results, network_id, epoch, sim, "compare")
                for r in b.results:
                    if r.counts and r.target in req:
                        scores[v.id].stats(r.target, req[r.target]).add(r.ok, r.ttfb_ms, r.verdict)
            rnd += 1
            log(f"round {rnd}/{reps} done")
    except Exception as e:  # StopRequested or backend error: keep what was measured
        status = f"stopped: {e}"
    rows = []
    for v in variants:
        sc = scores[v.id]
        d = sc.to_dict()
        d.update({"label": v.label, "text": v.text, "class": sc.classify(Thresholds()), "error": rejected.get(v.id, "")})
        rows.append(d)
    summary = {"status": status, "simulated": sim, "rounds": rnd, "discarded_rounds": discarded, "rows": rows,
               "targets": [t.id for t in targets], "reps": reps, "network_id": network_id, "run_id": run_id,
               "engine_version": core}
    summary["dns_check"] = (_dns_check(backend, engine, variants, rows, targets, ips, log) if status == "finished"
                            else dict(backend.dns_info(), rows=[], error=""))
    store.finish_run(run_id, status, summary)
    return summary
