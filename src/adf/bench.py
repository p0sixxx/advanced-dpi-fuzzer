"""Offline comparison of search algorithms on the DPI simulator.

The simulator knows the *true* success probability of every strategy, so the
quality of what an algorithm picks can be measured exactly — something that is
impossible on a real network. Results are only as realistic as the
:class:`~adf.probe.backend.DPIModel`; they compare *search efficiency*, not
real-world bypass performance. Real comparisons use ``adf compare``.

``tachyon_v2`` re-implements the control flow of Tachyon DPI Fuzzer v2
(``diagnostics/fuzzer.uc`` run_fuzzer_worker, combinatorial mode for the
``desync`` engine): the same candidate list structure
(``generate_combinatorial_desync``), one probe per strategy with stop on the
first failed required target, top-5 re-probed 3 times, best composite score.
It is an emulation written from the audit, not Tachyon code.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .db import Store
from .engines import StrategyError, TachyonDesync
from .probe.backend import DPIModel, SimulatedBackend
from .probe.model import Target
from .probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS
from .safety import Budget, Guard, SafetyPolicy
from .search.orchestrator import Orchestrator, SearchConfig


# generate_combinatorial_desync() grids per Tachyon release (diagnostics/fuzzer/strategies.uc)
_V2_GRIDS = {
    "1.7": {"modes": ("fake_split", "tlsrec", "disorder", "split", "fake", "oob"),
            "splits": ("1", "2", "midsld", "sni"), "ttls": (3, 4, 5, 6, 8),
            "snis": ("www.google.com", "max.ru", "gosuslugi.ru", "sberbank.ru"), "udp_twin": False},
    "1.8.0": {"modes": ("fake_split", "fake_disorder", "multi_disorder", "multi_split", "tlsrec", "disorder",
                        "split", "fake", "oob"),
              "splits": ("midsld", "sni", "sniext+1", "host+1", "midsld-2", "endhost-1", "1", "2"),
              "ttls": (3, 4, 5, 6, 8),
              "snis": ("www.google.com", "max.ru", "vk.com", "gosuslugi.ru", "rzd.ru", "ozon.ru", "padencap",
                       "rndsni"),
              "udp_twin": True},
}
# Stage 1 runs until TACHYON_JOB_HARD_DEADLINE_SECONDS (2700 s). The user's history shows
# ~3.8 s per candidate (276 candidates in ~1050 s), i.e. about 710 candidates per job.
V2_DEADLINE_CANDIDATES = 710


def _v2_rerank_drop(items: List[Tuple[str, str, Dict[str, Any]]]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """Tachyon's rerank_strategies_by_dpi() for dpi type "drop": keyword score + its swap sort."""
    keys = ("syndata", "multisplit", "multidisorder", "paws", "seqovl", "fake", "badseq", "disorder")
    scored = [[sum(10 for k in keys if k in args.lower() or k in name.lower()), (name, args, p)]
              for name, args, p in items]
    n = len(scored)
    for i in range(n - 1):  # same O(n^2) exchange sort (not stable), to reproduce the order
        for j in range(i + 1, n):
            if scored[j][0] > scored[i][0]:
                scored[i], scored[j] = scored[j], scored[i]
    return [item for _, item in scored]


def tachyon_v2_candidates(engine: TachyonDesync, version: str = "1.8.0",
                          rerank_drop: bool = False) -> List[Tuple[str, Dict[str, Any]]]:
    """Candidate list with the structure of Tachyon's generate_combinatorial_desync().

    Entries that differ only in parameters a TCP probe cannot see (UDP twins in 1.8.0,
    TTL/SNI for disorder, split position for fake) are kept: Tachyon spends a probe on each.
    """
    g = _V2_GRIDS[version]
    items: List[Tuple[str, str, Dict[str, Any]]] = []
    seen_args = set()

    def add(name: str, args: str, tcp_args: Optional[str] = None) -> None:
        if args in seen_args:  # Tachyon dedups by argument *string* only
            return
        seen_args.add(args)
        try:
            params = engine.canonicalize(engine.parse(tcp_args or args))
        except StrategyError:
            return  # Tachyon's validator would drop it as well
        items.append((name, args, params))

    for name, p in engine.seeds():
        add(name, engine.render(p))
    for mode in g["modes"]:
        for pos in g["splits"]:
            if mode in ("multi_split", "multi_disorder") and "," not in pos:
                pos_eff = f"1,{pos}" if pos != "1" else "1,midsld"
            else:
                pos_eff = pos
            if "fake" in mode or mode == "disorder":
                for ttl in g["ttls"]:
                    for sni in g["snis"]:
                        base = f"mode={mode} split_pos={pos_eff} fake_ttl={ttl} fake_sni={sni} repeats=6"
                        add(f"{mode} (pos={pos}, TTL={ttl}, sni={sni})", base)
                        if g["udp_twin"]:
                            add(f"{mode} + UDP Fake (pos={pos}, TTL={ttl}, sni={sni}, udplen=64)",
                                base + f" udp_fake=true udp_repeats=6 udp_fake_ttl={ttl} udplen=64", base)
            else:
                add(f"{mode} (pos={pos})", f"mode={mode} split_pos={pos_eff}")
                add(f"{mode} (pos={pos}, delay=2ms)", f"mode={mode} split_pos={pos_eff} split_delay_ms=2")
    if rerank_drop:
        items = _v2_rerank_drop(items)
    return [(name, params) for name, _, params in items]


def _tachyon_score(results, ref: float = 0.0) -> float:
    ok = [r for r in results if r.ok]
    if not ok:
        return 0.0
    ttfb = statistics.median(r.ttfb_ms for r in ok)
    return 100 + max(0.0, 1000 - ttfb) + (50 if any(r.bytes >= 32768 for r in ok) else 20)


def run_tachyon_v2(backend: SimulatedBackend, engine: TachyonDesync, targets: Sequence[Target],
                   ips: Mapping[str, Sequence[str]], version: str = "1.8.0") -> Dict[str, Any]:
    all_cands = tachyon_v2_candidates(engine, version, rerank_drop=True)
    cands = all_cands[:V2_DEADLINE_CANDIDATES]
    required = [t for t in targets if t.required]
    probes0 = backend.probes
    stage1 = []
    for name, params in cands:
        b = backend.run_batch(engine, params, targets, ips, reps=1, stop_on_fail=True)
        req_ok = all(any(r.ok for r in b.results if r.target == t.id) for t in required)
        stage1.append((name, params, req_ok, _tachyon_score(b.results) if req_ok else 0.0))
    working = sorted([s for s in stage1 if s[2]], key=lambda s: -s[3])[:5]
    best = None
    best_score = -1.0
    for name, params, _, _ in working:
        reps_ok = 0
        res_all = []
        for _ in range(3):
            b = backend.run_batch(engine, params, targets, ips, reps=1, stop_on_fail=True)
            if all(any(r.ok for r in b.results if r.target == t.id) for t in required):
                reps_ok += 1
                res_all += b.results
        stability = reps_ok / 3 * 100
        score = stability * 4 + (max(0.0, 1000 - statistics.median([r.ttfb_ms for r in res_all if r.ok] or [1000]))
                                 * 0.3) + 50
        if reps_ok and score > best_score:
            best, best_score = (name, params), score
    return {"algorithm": "tachyon_v2_emulation", "version": version, "candidates": len(all_cands),
            "tested_before_deadline": len(cands),
            "unique_candidates": len({repr(sorted(p.items())) for _, p in all_cands}),
            "probes": backend.probes - probes0, "selected": best[1] if best else None}


def true_quality(model: DPIModel, targets: Sequence[Target], params: Optional[Mapping[str, Any]]) -> float:
    if params is None:
        return 0.0
    req = [t for t in targets if t.required] or list(targets)
    return round(min(model.p_success(t, params) for t in req), 4)


@dataclass
class BenchRow:
    seed: int
    algorithm: str
    probes: int
    true_quality: float
    complexity: float
    selected: str


def bench(seeds: Sequence[int] = (1, 2, 3, 4, 5), n_targets: int = 6, model_kw: Optional[Dict[str, Any]] = None
          ) -> List[BenchRow]:
    rows: List[BenchRow] = []
    targets = DEFAULT_TARGETS[:n_targets]
    for seed in seeds:
        model = DPIModel(seed=seed, **(model_kw or {}))
        eng = TachyonDesync()
        # --- Tachyon v2 emulation
        be = SimulatedBackend(model)
        ips = {t.id: be.resolve(t.host)[:1] for t in targets}
        tv2 = run_tachyon_v2(be, eng, targets, ips)
        sel = tv2["selected"]
        rows.append(BenchRow(seed, "tachyon_v2_emulation", tv2["probes"], true_quality(model, targets, sel),
                             eng.complexity(sel) if sel else 0.0, eng.render(sel) if sel else "-"))
        # --- ADF with the same probe budget, and with its default budget
        for label, budget in (("adf_equal_budget", Budget(max_batches=10 ** 6, max_probes=tv2["probes"])),
                              ("adf_default", Budget())):
            be2 = SimulatedBackend(DPIModel(seed=seed, **(model_kw or {})))
            guard = Guard(budget, SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0), sleeper=lambda s: None)
            orch = Orchestrator(Store(":memory:"), be2, eng, targets, DEFAULT_CONTROLS,
                                SearchConfig(seed=seed, use_history=False), guard)
            summary = orch.run()
            best = summary.get("best")
            params = best["params"] if best else None
            rows.append(BenchRow(seed, label, be2.probes, true_quality(model, targets, params),
                                 eng.complexity(params) if params else 0.0, best["text"] if best else "-"))
    return rows


def bench_table(rows: Sequence[BenchRow]) -> str:
    lines = ["| seed | algorithm | probes | true worst-target success | complexity | selected strategy |",
             "|---:|---|---:|---:|---:|---|"]
    for r in rows:
        lines.append(f"| {r.seed} | {r.algorithm} | {r.probes} | {r.true_quality:.3f} | {r.complexity} | `{r.selected}` |")
    algs = sorted({r.algorithm for r in rows})
    lines.append("")
    lines.append("| algorithm | mean probes | mean true quality | min true quality |")
    lines.append("|---|---:|---:|---:|")
    for a in algs:
        rs = [r for r in rows if r.algorithm == a]
        lines.append(f"| {a} | {statistics.mean(r.probes for r in rs):.0f} | "
                     f"{statistics.mean(r.true_quality for r in rs):.3f} | {min(r.true_quality for r in rs):.3f} |")
    return "\n".join(lines)
