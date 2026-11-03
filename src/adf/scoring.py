"""Statistical scoring and classification of strategies.

Success is a Bernoulli outcome per trial. Decisions use the Wilson score
interval, which stays meaningful for small n and p near 0/1 (where the normal
approximation and "3/3 = 100 %" mislead). A strategy is judged by its *worst*
required target: a strategy that unblocks YouTube but breaks Discord is not
"stable".

Weights (time decay from :mod:`adf.learning`) are supported: ``n`` and ``k`` may
be fractional effective counts.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

Z95 = 1.959963984540054

UNTESTED = "Untested"
NOT_WORKING = "Not Working"
UNSTABLE = "Unstable"
PARTIAL = "Partially Working"
WORKING = "Working"
STABLE = "Stable"
EXCELLENT = "Excellent"
CLASS_ORDER = [UNTESTED, NOT_WORKING, UNSTABLE, PARTIAL, WORKING, STABLE, EXCELLENT]


@dataclass(frozen=True)
class Thresholds:
    # Wilson 95 % lower bounds. Examples: 5/5 -> 0.57, 12/12 -> 0.76, 23/24 -> 0.80,
    # 22/24 -> 0.74, 30/30 -> 0.89, 29/30 -> 0.83.
    working_lb: float = 0.50
    working_min_n: float = 5
    stable_lb: float = 0.75
    stable_min_n: float = 12
    excellent_lb: float = 0.85
    excellent_min_n: float = 30
    excellent_latency_factor: float = 1.5   # p90 TTFB vs baseline reference
    excellent_latency_slack_ms: float = 300.0
    partial_rate: float = 0.5


def wilson(k: float, n: float, z: float = Z95) -> tuple:
    """Wilson score interval (lower, upper) for k successes out of n."""
    if n <= 0:
        return (0.0, 1.0)
    p = min(1.0, max(0.0, k / n))
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (centre - margin) / denom), min(1.0, (centre + margin) / denom))


def percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = (len(s) - 1) * q
    lo, hi = math.floor(idx), math.ceil(idx)
    if lo == hi:
        return float(s[int(idx)])
    return float(s[lo] + (s[hi] - s[lo]) * (idx - lo))


@dataclass
class TargetStats:
    target: str
    required: bool = True
    n: float = 0.0
    k: float = 0.0
    ttfb_ok: List[float] = field(default_factory=list)
    verdicts: Dict[str, int] = field(default_factory=dict)

    def add(self, ok: bool, ttfb_ms: float = 0.0, verdict: str = "", weight: float = 1.0) -> None:
        self.n += weight
        if ok:
            self.k += weight
            if ttfb_ms > 0:
                self.ttfb_ok.append(ttfb_ms)
        if verdict:
            self.verdicts[verdict] = self.verdicts.get(verdict, 0) + 1

    @property
    def rate(self) -> float:
        return self.k / self.n if self.n else 0.0

    @property
    def lb(self) -> float:
        return wilson(self.k, self.n)[0]

    @property
    def ub(self) -> float:
        return wilson(self.k, self.n)[1]

    @property
    def p50(self) -> float:
        return percentile(self.ttfb_ok, 0.5)

    @property
    def p90(self) -> float:
        return percentile(self.ttfb_ok, 0.9)


@dataclass
class StrategyScore:
    strategy_id: str
    targets: Dict[str, TargetStats] = field(default_factory=dict)
    complexity: float = 0.0

    def stats(self, target: str, required: bool = True) -> TargetStats:
        if target not in self.targets:
            self.targets[target] = TargetStats(target, required)
        return self.targets[target]

    @property
    def required(self) -> List[TargetStats]:
        req = [t for t in self.targets.values() if t.required]
        return req or list(self.targets.values())

    @property
    def n_total(self) -> float:
        return sum(t.n for t in self.targets.values())

    @property
    def min_n(self) -> float:
        return min((t.n for t in self.required), default=0.0)

    @property
    def lb(self) -> float:
        """Worst-target Wilson lower bound: the headline reliability number."""
        return min((t.lb for t in self.required), default=0.0)

    @property
    def ub(self) -> float:
        return min((t.ub for t in self.required), default=1.0)

    @property
    def rate(self) -> float:
        return min((t.rate for t in self.required), default=0.0)

    @property
    def mean_rate(self) -> float:
        req = self.required
        return sum(t.rate for t in req) / len(req) if req else 0.0

    @property
    def p50(self) -> float:
        vals = [v for t in self.required for v in t.ttfb_ok]
        return percentile(vals, 0.5)

    @property
    def p90(self) -> float:
        vals = [v for t in self.required for v in t.ttfb_ok]
        return percentile(vals, 0.9)

    def utility(self, ref_ttfb_ms: float = 0.0) -> float:
        """Ranking objective: reliability first, then latency, then simplicity.

        lb ∈ [0,1] dominates. Latency costs up to 0.05 (1 s above reference)
        and each complexity point 0.01, so a simpler strategy wins only when
        reliability is statistically equivalent.
        """
        lat_pen = 0.0
        if ref_ttfb_ms > 0 and self.p50 > 0:
            lat_pen = 0.05 * min(1.0, max(0.0, (self.p50 - ref_ttfb_ms) / 1000.0))
        return round(self.lb - lat_pen - 0.01 * self.complexity, 6)

    def classify(self, th: Thresholds = Thresholds(), ref_ttfb_ms: float = 0.0) -> str:
        req = self.required
        if not req or self.n_total == 0:
            return UNTESTED
        if all(t.k == 0 for t in self.targets.values()):
            return NOT_WORKING
        lb, min_n = self.lb, self.min_n
        if lb >= th.excellent_lb and min_n >= th.excellent_min_n:
            if ref_ttfb_ms <= 0 or self.p90 <= max(ref_ttfb_ms * th.excellent_latency_factor,
                                                   ref_ttfb_ms + th.excellent_latency_slack_ms):
                return EXCELLENT
            return STABLE
        if lb >= th.stable_lb and min_n >= th.stable_min_n:
            return STABLE
        if lb >= th.working_lb and min_n >= th.working_min_n:
            return WORKING
        rates = [t.rate for t in req]
        if max(rates) >= th.partial_rate:
            return PARTIAL
        return UNSTABLE

    def to_dict(self, ref_ttfb_ms: float = 0.0) -> Dict[str, object]:
        return {
            "strategy_id": self.strategy_id,
            "class": self.classify(ref_ttfb_ms=ref_ttfb_ms),
            "lb": round(self.lb, 4),
            "ub": round(self.ub, 4),
            "rate": round(self.rate, 4),
            "mean_rate": round(self.mean_rate, 4),
            "n": round(self.n_total, 2),
            "min_n": round(self.min_n, 2),
            "p50_ttfb_ms": round(self.p50, 1),
            "p90_ttfb_ms": round(self.p90, 1),
            "complexity": self.complexity,
            "utility": self.utility(ref_ttfb_ms),
            "targets": {
                t.target: {"n": round(t.n, 2), "k": round(t.k, 2), "rate": round(t.rate, 3), "lb": round(t.lb, 3),
                           "required": t.required, "p50_ttfb_ms": round(t.p50, 1), "verdicts": t.verdicts}
                for t in self.targets.values()
            },
        }


def non_inferior(candidate: StrategyScore, incumbent: StrategyScore, margin: float = 0.05) -> bool:
    """True when ``candidate`` is not worse than ``incumbent`` by more than ``margin``.

    Used by the simplifier: a simpler variant replaces the incumbent if its
    worst-target Wilson lower bound is within ``margin`` of the incumbent's and it
    has at least as much evidence per target. Comparing lower bounds (not point
    estimates) keeps the test conservative for the candidate.
    """
    if candidate.min_n < max(1.0, incumbent.min_n):
        return False
    return candidate.lb >= incumbent.lb - margin


def two_proportion_drop(k_old: float, n_old: float, k_new: float, n_new: float, z: float = 2.326) -> bool:
    """One-sided two-proportion z-test: has the success rate dropped? (default α≈0.01)"""
    if n_old < 5 or n_new < 5:
        return False
    p1, p2 = k_old / n_old, k_new / n_new
    p = (k_old + k_new) / (n_old + n_new)
    se = math.sqrt(max(p * (1 - p) * (1 / n_old + 1 / n_new), 1e-12))
    return (p1 - p2) / se > z
