"""Search orchestration.

Pipeline (each step persists to SQLite before the next one starts):

1. **Environment & baseline** – agent environment, CDN IPs per target, three
   rounds through a plain ``direct`` outbound on the same proxy path. Targets are
   classified ``open`` / ``blocked`` / ``partial`` / ``unreachable``; unreachable
   targets (IP block, routing, DNS) are excluded because no desync can fix them.
2. **Search** – sequential model-based optimisation:
   * candidate pool = seeds ∪ previous winners ∪ pairwise screening design;
   * every batch, a surrogate model (see :mod:`adf.learning`) is refitted and
     the next strategy is chosen by **Thompson sampling** on per-target Beta
     posteriors (prior from the surrogate, likelihood from trials) using the
     *worst* target – this balances screening new candidates against
     re-testing promising ones without a fixed "1 probe then 3 reps" schedule;
   * promising strategies spawn single-factor mutations over the full domain
     (local/evolutionary search); clearly dominated ones are eliminated;
   * a strategy is *settled* once every required target has ``confirm_n``
     trials.
3. **Simplification** – non-inferiority racing of strictly simpler variants of
   the winner (fewer fakes, simpler mode, no extra options).
4. **Final validation** – round-robin between finalists (same conditions) until
   ``final_n`` trials per target, with periodic control checks.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from statistics import median
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from ..db import Store
from ..engines import Capabilities, Engine, StrategyError
from ..generator import pairwise, random_valid
from ..learning import DecayPolicy, Surrogate, build_scores, detect_drift, observations_from_scores
from ..probe.backend import Backend, BackendError
from ..probe.model import PATH_VERDICTS, BatchResult, ProbeResult, Target, summarize_verdicts
from ..safety import Guard, StopRequested
from ..scoring import CLASS_ORDER, StrategyScore, Thresholds, non_inferior
from ..strategy import Strategy, make_strategy

BASELINE = "baseline"
SEARCH = "search"
SIMPLIFY = "simplify"
FINAL = "final"
CONTROL = "control"
REVALIDATE = "revalidate"


@dataclass
class SearchConfig:
    network_id: str = "default"
    seed: int = 0
    baseline_reps: int = 3
    confirm_n: int = 12
    final_n: int = 30
    top_k_final: int = 3
    extra_finalists: int = 5        # promising but under-tested strategies also enter the final race
    revalidate_top: int = 3         # previous winners re-tested at the start of a run
    revalidate_batches: int = 5
    prior_strength: float = 2.0
    default_prior: float = 0.25
    complexity_lambda: float = 0.01
    promising_rate: float = 0.6
    beam_width: int = 4             # only the best few strategies spawn mutations
    mutations_per_expand: int = 24
    max_pool: int = 1500
    search_until: float = 0.60      # fraction of budget for the search phase
    simplify_until: float = 0.75    # ... then simplification until this fraction
    simplify_margin: float = 0.05
    simplify_depth: int = 5
    use_history: bool = True
    stop_on_fail_screening: bool = True
    force_without_blocked: bool = False
    thresholds: Thresholds = field(default_factory=Thresholds)
    decay: DecayPolicy = field(default_factory=DecayPolicy)


@dataclass
class TargetStatus:
    target: Target
    status: str
    k: int
    n: int
    verdicts: Dict[str, int]
    ttfb_ms: float = 0.0


@dataclass
class Candidate:
    strategy: Strategy
    origin: str
    expanded: bool = False
    simplified: bool = False
    eliminated: bool = False
    invalid: str = ""

    @property
    def id(self) -> str:
        return self.strategy.id


class SearchAborted(RuntimeError):
    pass


class Orchestrator:
    def __init__(self, store: Store, backend: Backend, engine: Engine, targets: Sequence[Target],
                 controls: Sequence[Target], config: Optional[SearchConfig] = None, guard: Optional[Guard] = None,
                 caps: Optional[Capabilities] = None, extra: Sequence[Strategy] = (),
                 log: Optional[Callable[[str], None]] = None):
        self.store = store
        self.backend = backend
        self.engine = engine
        self.all_targets = list(targets)
        self.controls = list(controls)
        self.cfg = config or SearchConfig()
        self.guard = guard or Guard()
        self.caps = caps
        self.extra = list(extra)
        self.log = log or (lambda m: None)
        self.rng = random.Random(self.cfg.seed)
        self.pool: Dict[str, Candidate] = {}
        self.scores: Dict[str, StrategyScore] = {}
        self.run_scores: Dict[str, StrategyScore] = {}
        self.surrogate = Surrogate()
        self.ips: Dict[str, List[str]] = {}
        self.statuses: Dict[str, TargetStatus] = {}
        self.active: List[Target] = []
        self.run_id = 0
        self.epoch = 0
        self.engine_version = ""
        self.ref_ttfb = 0.0
        self.batches_since_control = 0
        self.last_good_trial_id = 0
        self.control_failures = 0
        self.events: List[Dict[str, Any]] = []
        self.verdicts: Dict[str, int] = {}
        self.finalists: List[Candidate] = []
        self.final_scores: Dict[str, StrategyScore] = {}
        self.drift: Dict[str, Any] = {}

    # ================================================================ helpers
    @property
    def simulated(self) -> bool:
        return bool(getattr(self.backend, "simulated", False))

    def _required(self) -> Dict[str, bool]:
        return {t.id: t.required for t in self.active}

    def _event(self, kind: str, **kw: Any) -> None:
        ev = {"t": round(self.guard.elapsed, 1), "event": kind, **kw}
        self.events.append(ev)

    def _add(self, params: Mapping[str, Any], origin: str, name: str = "") -> Optional[Candidate]:
        if len(self.pool) >= self.cfg.max_pool:
            return None
        try:
            s = make_strategy(self.engine, params, origin=origin, name=name, caps=self.caps)
        except StrategyError:
            return None
        if s.id in self.pool:
            return self.pool[s.id]
        c = Candidate(s, origin)
        self.pool[s.id] = c
        return c

    def _add_strategy(self, s: Strategy) -> Candidate:
        if s.id not in self.pool:
            self.pool[s.id] = Candidate(s, s.origin)
        return self.pool[s.id]

    def _score(self, sid: str) -> StrategyScore:
        sc = self.scores.get(sid)
        if sc is None:
            c = self.pool.get(sid)
            sc = self.scores[sid] = StrategyScore(sid, complexity=c.strategy.complexity if c else 0.0)
        return sc

    def _record(self, sid: Optional[str], results: Sequence[ProbeResult], phase: str) -> None:
        self.store.add_trials(self.run_id, sid, results, self.cfg.network_id, self.epoch, self.simulated, phase)
        for r in results:
            self.verdicts[r.verdict] = self.verdicts.get(r.verdict, 0) + 1
        if sid is None:
            return
        req = self._required()
        books = [self.scores, self.run_scores]
        if phase == FINAL and sid in self.final_scores:
            books.append(self.final_scores)
        for r in results:
            if not r.counts or r.target not in req:
                continue
            for book in books:
                sc = book.get(sid)
                if sc is None:
                    sc = book[sid] = StrategyScore(sid, complexity=self.pool[sid].strategy.complexity)
                sc.stats(r.target, req[r.target]).add(r.ok, r.ttfb_ms, r.verdict)

    def _rebuild_scores(self) -> None:
        """Recompute in-memory scores from the database (after invalidation)."""
        req = self._required()
        cx = {sid: c.strategy.complexity for sid, c in self.pool.items()}
        rows = self.store.trials(self.cfg.network_id, self.simulated, strategy_ids=list(self.pool))
        hist = [r for r in rows if r["run_id"] != self.run_id]
        cur = [r for r in rows if r["run_id"] == self.run_id]
        only = set(req)
        decayed = build_scores(hist, req, cx, self.cfg.decay, self.epoch, only_targets=only) \
            if self.cfg.use_history else {}
        self.run_scores = build_scores(cur, req, cx, only_targets=only)
        if self.final_scores:
            fresh = build_scores([r for r in cur if r["phase"] == FINAL], req, cx, only_targets=only)
            self.final_scores = {sid: fresh.get(sid, StrategyScore(sid, complexity=cx.get(sid, 0.0)))
                                 for sid in self.final_scores}
        self.scores = decayed
        for sid, sc in self.run_scores.items():
            base = self.scores.setdefault(sid, StrategyScore(sid, complexity=sc.complexity))
            for tid, ts in sc.targets.items():
                b = base.stats(tid, ts.required)
                b.n += ts.n
                b.k += ts.k
                b.ttfb_ok += ts.ttfb_ok
                for v, n in ts.verdicts.items():
                    b.verdicts[v] = b.verdicts.get(v, 0) + n

    def _batch(self, cand: Optional[Candidate], targets: Sequence[Target], reps: int, phase: str,
               stop_on_fail: bool = False) -> BatchResult:
        self.guard.before_batch()
        params = None if cand is None else cand.strategy.params
        try:
            batch = self.backend.run_batch(self.engine, params, targets, self.ips, reps=reps,
                                           stop_on_fail=stop_on_fail)
        except BackendError as e:
            self._event("backend_error", error=str(e))
            raise SearchAborted(f"backend failure: {e}") from e
        self.guard.after_batch(len(batch.results))
        if batch.mem_avail_kb and batch.mem_avail_kb < self.guard.policy.min_agent_mem_kb:
            self._event("low_memory", mem_avail_kb=batch.mem_avail_kb)
            self.guard.backoff()
        return batch

    # ============================================================== controls
    def _control_ok(self) -> bool:
        if not self.controls:
            return True
        batch = self._batch(None, self.controls, 1, CONTROL)
        self._record(None, batch.results, CONTROL)
        ok = sum(1 for r in batch.results if r.ok)
        return ok >= max(1, (len(batch.results) + 1) // 2)

    def _maybe_control(self, force: bool = False) -> None:
        self.batches_since_control += 1
        if not force and self.batches_since_control < self.guard.policy.control_every:
            return
        self.batches_since_control = 0
        while not self._control_ok():
            self.control_failures += 1
            n = self.store.invalidate_since(self.run_id, self.last_good_trial_id)
            self._event("network_down", invalidated=n, failures=self.control_failures)
            self.log(f"control check failed ({self.control_failures}); {n} trials invalidated, backing off")
            if self.control_failures >= self.guard.policy.max_control_failures:
                raise SearchAborted("network appears down: control targets keep failing")
            self._rebuild_scores()
            self.guard.backoff()
        self.control_failures = 0
        self.guard.reset_backoff()
        self.last_good_trial_id = self.store.max_trial_id(self.run_id)

    # =============================================================== phases
    def _environment(self) -> Dict[str, Any]:
        env = self.backend.env()
        self.engine_version = str(env.get("core_version") or env.get("agent") or "unknown")
        for t in self.all_targets + self.controls:
            if t.id in self.ips or not t.host:
                continue
            try:
                addrs = self.backend.resolve(t.host)
            except BackendError:
                addrs = []
            chosen: List[str] = []
            for fam in t.families:
                fam_addrs = [a for a in addrs if (":" in a) == (fam == "ipv6")]
                chosen += fam_addrs[: max(1, t.max_ips)]
            self.ips[t.id] = chosen
        return env

    def _baseline(self) -> None:
        targets = self.all_targets + self.controls
        batch = self._batch(None, targets, self.cfg.baseline_reps, BASELINE)
        if batch.engine_failed:
            raise SearchAborted(f"baseline engine failed: {batch.engine_error}")
        self._record(None, batch.results, BASELINE)
        by: Dict[str, List[ProbeResult]] = {}
        for r in batch.results:
            by.setdefault(r.target, []).append(r)
        for t in targets:
            rs = by.get(t.id, [])
            n = len(rs)
            k = sum(1 for r in rs if r.ok)
            path = sum(1 for r in rs if r.verdict in PATH_VERDICTS)
            ttfb = median([r.ttfb_ms for r in rs if r.ok]) if k else 0.0
            if n == 0:
                status = "unreachable"
            elif k / n >= 0.67:
                status = "open"
            elif path >= max(1, (n - k + 1) // 2):
                status = "unreachable"
            elif k == 0:
                status = "blocked"
            else:
                status = "partial"
            self.statuses[t.id] = TargetStatus(t, status, k, n, summarize_verdicts(rs), ttfb)
        ctrl_ok = [self.statuses[c.id] for c in self.controls if self.statuses[c.id].status == "open"]
        if self.controls and not ctrl_ok:
            raise SearchAborted("no control target is reachable without bypass: the probe path or network is broken")
        # blocked first (most discriminative, and stop-on-fail hits them early), then partial, then open
        order = {"blocked": 0, "partial": 1, "open": 2}
        self.active = sorted([t for t in self.all_targets if self.statuses[t.id].status in order],
                             key=lambda t: (order[self.statuses[t.id].status], not t.required))
        ref = [s.ttfb_ms for s in self.statuses.values() if s.status == "open" and s.ttfb_ms > 0]
        self.ref_ttfb = median(ref) if ref else 0.0
        blocked = [t.id for t in self.active if self.statuses[t.id].status in ("blocked", "partial")]
        self._event("baseline", statuses={k: v.status for k, v in self.statuses.items()})
        self.log("baseline: " + ", ".join(f"{k}={v.status}" for k, v in self.statuses.items()))
        if not blocked and not self.cfg.force_without_blocked:
            raise SearchAborted("no target is blocked without bypass: nothing to optimise "
                                "(use --force to search for non-breaking strategies anyway)")
        self.last_good_trial_id = self.store.max_trial_id(self.run_id)

    def _seed_pool(self) -> None:
        for s in self.extra:
            self._add_strategy(s)
        for name, params in self.engine.seeds(self.caps):
            self._add(params, "seed", name)
        invalid = self.store.invalid_ids(self.engine_version)
        if self.cfg.use_history:
            # previous strategies for this engine/network are re-validated (drift detection)
            known = {s.id: s for s in self.store.strategies(self.engine.name)}
            rows = self.store.trials(self.cfg.network_id, self.simulated, strategy_ids=list(known))
            req = self._required()
            hist = build_scores(rows, req, {k: v.complexity for k, v in known.items()}, self.cfg.decay, self.epoch,
                                only_targets=set(req))
            for sid, sc in sorted(hist.items(), key=lambda kv: -kv[1].utility())[:30]:
                if sc.rate > 0 and sid not in invalid:
                    self._add_strategy(Strategy(**{**known[sid].__dict__, "origin": "history"}))
        for params in pairwise(self.engine, self.caps, seed=self.cfg.seed):
            self._add(params, "pairwise")
        for sid, reason in invalid.items():
            if sid in self.pool:
                self.pool[sid].invalid = reason
        self._rebuild_scores()

    def _refit(self) -> None:
        params_of = {sid: c.strategy.params for sid, c in self.pool.items()}
        self.surrogate.fit(observations_from_scores(self.scores, params_of))

    def _theta(self, c: Candidate, targets: Sequence[Target]) -> float:
        sc = self.scores.get(c.id)
        p0 = self.surrogate.predict(c.strategy.params) if self.surrogate.observations >= 5 else self.cfg.default_prior
        s = self.cfg.prior_strength
        theta = 1.0
        for t in targets:
            st = sc.targets.get(t.id) if sc else None
            k = st.k if st else 0.0
            n = st.n if st else 0.0
            theta = min(theta, self.rng.betavariate(1 + s * p0 + k, 1 + s * (1 - p0) + max(0.0, n - k)))
        return theta - self.cfg.complexity_lambda * c.strategy.complexity

    def _settled(self, c: Candidate) -> bool:
        sc = self.scores.get(c.id)
        return bool(sc) and sc.min_n >= self.cfg.confirm_n and len(sc.required) >= len(
            [t for t in self.active if t.required])

    def _best_lb(self) -> float:
        return max((sc.lb for sid, sc in self.scores.items() if sid in self.pool and not self.pool[sid].invalid),
                   default=0.0)

    def _selectable(self) -> List[Candidate]:
        best_lb = self._best_lb()
        out = []
        for c in self.pool.values():
            if c.invalid or c.eliminated:
                continue
            sc = self.scores.get(c.id)
            if sc is not None and sc.min_n >= 3 and sc.ub < best_lb:
                c.eliminated = True
                continue
            if self._settled(c):
                continue
            out.append(c)
        return out

    @staticmethod
    def _posterior_mean(sc: StrategyScore) -> float:
        """Worst required target posterior mean under a uniform prior."""
        return min(((t.k + 1) / (t.n + 2) for t in sc.required), default=0.0)

    def _in_beam(self, c: Candidate) -> bool:
        ranked = sorted((self._posterior_mean(sc), sid) for sid, sc in self.scores.items()
                        if sid in self.pool and not self.pool[sid].invalid and sc.n_total > 0)
        top = {sid for _, sid in ranked[-self.cfg.beam_width:]}
        return c.id in top

    def _after(self, c: Candidate) -> None:
        sc = self.scores.get(c.id)
        if sc is None:
            return
        if (not c.expanded and sc.n_total >= 2 and self._posterior_mean(sc) >= self.cfg.promising_rate * 0.75
                and sc.mean_rate >= self.cfg.promising_rate and self._in_beam(c)):
            c.expanded = True
            muts = self.engine.mutations(c.strategy.params, self.caps)
            if self.surrogate.observations >= 5:
                muts.sort(key=lambda p: -self.surrogate.predict(p))
            added = sum(1 for p in muts[: self.cfg.mutations_per_expand] if self._add(p, "mutation"))
            self._event("expand", strategy=c.id, added=added)
        if not c.simplified and self._settled(c) and sc.lb >= self.cfg.thresholds.working_lb:
            c.simplified = True
            added = sum(1 for p in self.engine.simplifications(c.strategy.params, self.caps)
                        if self._add(p, "simplify"))
            self._event("simplify_seed", strategy=c.id, added=added)

    def _run_candidate(self, c: Candidate, phase: str, stop_on_fail: bool) -> BatchResult:
        batch = self._batch(c, self.active, 1, phase, stop_on_fail=stop_on_fail)
        if batch.engine_failed:
            c.invalid = batch.engine_error
            self.store.mark_invalid(c.id, self.engine_version, batch.engine_error)
            self._event("invalid", strategy=c.id, reason=batch.engine_error)
            return batch
        self.store.upsert_strategy(c.strategy)
        self._record(c.id, batch.results, phase)
        prev = self.scores.get(c.id)
        had_success_before = prev is not None and prev.mean_rate >= 0.5 and prev.n_total >= 3
        no_ok = not any(r.ok for r in batch.results)
        self._maybe_control(force=no_ok and had_success_before)
        return batch

    def _search(self) -> None:
        explore_round = 0
        while self.guard.fraction_used() < self.cfg.search_until:
            self.guard.check()
            self._refit()
            sel = self._selectable()
            if not sel:
                self._event("search_exhausted")
                break
            req_targets = [t for t in self.active if t.required] or self.active
            best = max(sel, key=lambda c: self._theta(c, req_targets))
            sc = self.scores.get(best.id)
            untested = sc is None or sc.n_total == 0
            self._run_candidate(best, SEARCH, stop_on_fail=self.cfg.stop_on_fail_screening and untested)
            self._after(best)
            # exploration when nothing works at all
            used = self.guard.fraction_used()
            if not any(s.k > 0 for sc in self.scores.values() for s in sc.targets.values()) and \
                    used > 0.15 * (explore_round + 1):
                explore_round += 1
                n = sum(1 for p in random_valid(self.engine, self.caps, 60, seed=self.cfg.seed + explore_round)
                        if self._add(p, "explore"))
                self._event("explore", added=n)

    def _race(self, c: Candidate, until_n: float, against: Optional[StrategyScore], limit: float) -> StrategyScore:
        while self.guard.fraction_used() < limit:
            sc = self.scores.get(c.id)
            if sc is not None and sc.min_n >= until_n:
                break
            if sc is not None and against is not None and sc.min_n >= 3 and sc.ub < against.lb - self.cfg.simplify_margin:
                break
            if c.invalid:
                break
            self._run_candidate(c, SIMPLIFY, stop_on_fail=False)
        return self._score(c.id)

    def ranking(self, settled_only: bool = False) -> List[Tuple[Candidate, StrategyScore]]:
        out = []
        for sid, sc in self.scores.items():
            c = self.pool.get(sid)
            if c is None or c.invalid or sc.n_total == 0:
                continue
            if settled_only and not self._settled(c):
                continue
            out.append((c, sc))
        out.sort(key=lambda cs: (-cs[1].utility(self.ref_ttfb), cs[0].strategy.complexity))
        return out

    def _simplify(self) -> Optional[Tuple[Candidate, List[str]]]:
        ranked = self.ranking(settled_only=True)
        if not ranked:
            return None
        winner, wsc = ranked[0]
        if wsc.lb < self.cfg.thresholds.working_lb:
            return None
        chain = [winner.id]
        current, csc = winner, wsc
        for _ in range(self.cfg.simplify_depth):
            accepted = None
            simpler = []
            for p in self.engine.simplifications(current.strategy.params, self.caps):
                cand = self._add(p, "simplify")
                if cand is not None and not cand.invalid and cand.strategy.complexity < current.strategy.complexity:
                    simpler.append(cand)
            simpler.sort(key=lambda c: c.strategy.complexity)
            for cand in simpler:
                if self.guard.fraction_used() >= self.cfg.simplify_until:
                    break
                # always compare against the original winner: margins must not accumulate along the chain
                sc = self._race(cand, wsc.min_n, wsc, self.cfg.simplify_until)
                if non_inferior(sc, wsc, self.cfg.simplify_margin):
                    accepted = (cand, sc)
                    break
            if accepted is None:
                break
            current, csc = accepted
            chain.append(current.id)
            self._event("simplified", to=current.id, complexity=current.strategy.complexity)
        return current, chain

    def _revalidate(self) -> None:
        """Re-test previous winners with a fixed number of trials and detect drift early."""
        hist = [c for c in self.pool.values() if c.origin == "history" and not c.invalid]
        hist.sort(key=lambda c: -self._score(c.id).utility())
        tested = 0
        for c in hist[: self.cfg.revalidate_top]:
            if self._score(c.id).rate < self.cfg.promising_rate:
                continue
            for _ in range(self.cfg.revalidate_batches):
                self._run_candidate(c, REVALIDATE, stop_on_fail=False)
            tested += 1
        if not tested:
            return
        drift = detect_drift(self.store, self.cfg.network_id, self.simulated, self.run_id, self._required())
        self.drift = {"checked": drift.checked, "drifted": drift.drifted}
        if drift.detected:
            self.epoch = self.store.new_epoch(self.cfg.network_id, f"drift in {len(drift.drifted)} strategies")
            self.store.retag_epoch(self.run_id, self.epoch)
            self._event("drift", drifted=drift.drifted, new_epoch=self.epoch)
            self.log(f"network behaviour changed: {len(drift.drifted)} former winners degraded, new epoch {self.epoch}")
            self._rebuild_scores()

    def _pick_finalists(self, optimized: Optional[Tuple[Candidate, List[str]]]) -> List[Candidate]:
        finalists: List[Candidate] = []
        if optimized:
            finalists.append(optimized[0])
        for c, _ in self.ranking(settled_only=True):
            if len(finalists) >= self.cfg.top_k_final:
                break
            if c not in finalists:
                finalists.append(c)
        promising = sorted((c for c in self.pool.values() if not c.invalid and c not in finalists
                            and c.id in self.scores and self.scores[c.id].n_total > 0),
                           key=lambda c: (-round(self._posterior_mean(self.scores[c.id]), 3),
                                          -self.surrogate.predict(c.strategy.params)))
        for c in promising[: self.cfg.extra_finalists]:
            if self._posterior_mean(self.scores[c.id]) >= self.cfg.promising_rate:
                finalists.append(c)
        if not finalists:
            finalists = [c for c, _ in self.ranking()[: self.cfg.top_k_final]]
        return finalists

    def _final(self, finalists: List[Candidate]) -> None:
        """Race finalists on *fresh* trials only (avoids the winner's curse of reusing selection data)."""
        self.finalists = finalists
        self.final_scores = {c.id: StrategyScore(c.id, complexity=c.strategy.complexity) for c in finalists}
        alive = list(finalists)
        while alive:
            for c in list(alive):
                fs = self.final_scores[c.id]
                if c.invalid or fs.min_n >= self.cfg.final_n:
                    alive.remove(c)
                    continue
                self.guard.check()
                batch = self._batch(c, self.active, 1, FINAL)
                if batch.engine_failed:
                    c.invalid = batch.engine_error
                    alive.remove(c)
                    continue
                self._record(c.id, batch.results, FINAL)
                self._maybe_control()
            ready = [fs for fs in self.final_scores.values() if fs.min_n >= 5]
            if ready:
                lead = max(fs.lb for fs in ready)
                for c in list(alive):
                    fs = self.final_scores[c.id]
                    if fs.min_n >= 5 and fs.ub < lead:
                        alive.remove(c)
                        self._event("final_eliminated", strategy=c.id)

    # ================================================================== run
    def run(self) -> Dict[str, Any]:
        self.guard.start()
        started = time.monotonic()
        status = "finished"
        error = ""
        optimized: Optional[Tuple[Candidate, List[str]]] = None
        env: Dict[str, Any] = {}
        try:
            env = self._environment()
            self.epoch = self.store.current_epoch(self.cfg.network_id)
            previous = self.store.last_engine_version(self.cfg.network_id, self.engine.name)
            if previous and previous != self.engine_version:
                # a strategy that worked on one core can fail outright on the next, with an identical config
                self.epoch = self.store.new_epoch(self.cfg.network_id, f"core {previous} -> {self.engine_version}")
                self.log(f"core changed ({previous} -> {self.engine_version}): earlier results carry less weight")
            self.run_id = self.store.start_run(self.cfg.network_id, self.engine.name, self.engine_version,
                                               getattr(self.backend, "name", "?"), self.simulated,
                                               {"targets": [t.id for t in self.all_targets],
                                                "controls": [t.id for t in self.controls],
                                                "budget": self.guard.budget.__dict__, "seed": self.cfg.seed})
            self.store.save_target_specs(t.to_dict() for t in self.all_targets + self.controls)
            self._baseline()
            self._seed_pool()
            self.log(f"candidate pool: {len(self.pool)} strategies")
            if self.cfg.use_history:
                self._revalidate()
            self._search()
            optimized = self._simplify()
            self._final(self._pick_finalists(optimized))
        except StopRequested as e:
            status = "stopped"
            error = str(e)
            if error == "budget exhausted":
                status = "finished"
                error = ""
        except SearchAborted as e:
            status = "aborted"
            error = str(e)
        summary = self.summary(env, optimized, status, error, time.monotonic() - started)
        if self.run_id:
            self.store.finish_run(self.run_id, status, summary)
        return summary

    # ============================================================== summary
    def summary(self, env: Mapping[str, Any], optimized: Optional[Tuple[Candidate, List[str]]], status: str,
                error: str, seconds: float) -> Dict[str, Any]:
        ranked = self.ranking()
        th = self.cfg.thresholds

        def row(c: Candidate, sc: StrategyScore) -> Dict[str, Any]:
            run_sc = self.run_scores.get(c.id)
            d = sc.to_dict(self.ref_ttfb)
            d.update({"text": c.strategy.text, "engine": c.strategy.engine, "origin": c.origin,
                      "name": c.strategy.name, "params": c.strategy.params,
                      "run_n": round(run_sc.n_total, 1) if run_sc else 0})
            d["class"] = sc.classify(th, self.ref_ttfb)
            return d

        classes: Dict[str, int] = {k: 0 for k in CLASS_ORDER}
        for _, sc in ranked:
            classes[sc.classify(th, self.ref_ttfb)] += 1
        tested_this_run = [sid for sid, sc in self.run_scores.items() if sc.n_total > 0]
        passed = [sid for sid in tested_this_run if any(t.k > 0 for t in self.run_scores[sid].targets.values())]
        by_family: Dict[str, List[float]] = {}
        for c, sc in ranked:
            fam = str(c.strategy.params.get("mode", c.strategy.params.get("split", c.strategy.params.get("method"))))
            by_family.setdefault(fam, [0.0, 0.0])
            by_family[fam][0] += sum(t.k for t in sc.targets.values())
            by_family[fam][1] += sum(t.n for t in sc.targets.values())
        # After final validation the finalists have comparable evidence: pick by utility
        # (reliability first, then latency and simplicity), not by the simplifier's guess.
        valid_final = [c for c in self.finalists if not c.invalid and self.final_scores.get(c.id)
                       and self.final_scores[c.id].n_total > 0]
        if valid_final:
            best = max(valid_final, key=lambda c: (self.final_scores[c.id].utility(self.ref_ttfb),
                                                   -c.strategy.complexity))
        else:
            best = ranked[0][0] if ranked else None
        return {
            "status": status,
            "error": error,
            "run_id": self.run_id,
            "network_id": self.cfg.network_id,
            "simulated": self.simulated,
            "engine": self.engine.name,
            "engine_version": self.engine_version,
            "env": dict(env),
            "seconds": round(seconds, 1),
            "batches": self.guard.batches,
            "probes": self.guard.probes,
            "pool_size": len(self.pool),
            "unique_tested": len(tested_this_run),
            "passed_screening": len(passed),
            "invalid": sum(1 for c in self.pool.values() if c.invalid),
            "classes": classes,
            "baseline": {k: {"status": v.status, "k": v.k, "n": v.n, "verdicts": v.verdicts}
                         for k, v in self.statuses.items()},
            "reference_ttfb_ms": round(self.ref_ttfb, 1),
            "verdicts": dict(sorted(self.verdicts.items(), key=lambda kv: -kv[1])),
            "families": {k: {"success_rate": round(v[0] / v[1], 3) if v[1] else 0.0, "trials": round(v[1], 1)}
                         for k, v in sorted(by_family.items(), key=lambda kv: -(kv[1][0] / kv[1][1] if kv[1][1] else 0))},
            "best": (dict(row(best, self.final_scores[best.id]), confirmation_sample=True)
                     if best and best.id in self.final_scores and self.final_scores[best.id].n_total > 0
                     else (row(best, self._score(best.id)) if best else None)),
            "finalists": [dict(row(c, self.final_scores[c.id]), confirmation_sample=True)
                          for c in self.finalists if c.id in self.final_scores and self.final_scores[c.id].n_total],
            "drift": self.drift,
            "simplification_chain": optimized[1] if optimized else [],
            "top": [row(c, sc) for c, sc in ranked[:15]],
            "events": self.events[-200:],
        }
