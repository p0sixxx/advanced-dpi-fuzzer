"""Learning from accumulated trials.

* **Decay**: each trial is weighted ``0.5 ** (age / half_life)``; trials from older
  *epochs* (see drift detection) get an extra factor. Old evidence therefore
  never dominates current decisions, but is still a useful prior.
* **Surrogate**: an additive logistic model over parameter features —
  ``(factor=value)`` and ``(mode, factor=value)`` — with empirical-Bayes
  shrinkage. It predicts the success probability of untested strategies and is
  used to order screening and to set weak Beta priors for racing. With
  categorical factors and a few hundred observations, this is far more sample
  efficient than a Gaussian process or reinforcement learning.
* **Drift**: if strategies that were reliable lose a statistically significant
  part of their success rate, a new epoch is started for the network.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .db import Store
from .scoring import StrategyScore, two_proportion_drop


@dataclass(frozen=True)
class DecayPolicy:
    half_life_days: float = 14.0
    epoch_factor: float = 0.25   # weight multiplier per epoch of age
    min_weight: float = 0.02     # below this a trial is ignored

    def weight(self, ts: float, epoch: int, current_epoch: int, now: Optional[float] = None) -> float:
        now = time.time() if now is None else now
        age_days = max(0.0, (now - ts) / 86400.0)
        w = 0.5 ** (age_days / self.half_life_days) * (self.epoch_factor ** max(0, current_epoch - epoch))
        return w if w >= self.min_weight else 0.0


def build_scores(rows: Iterable[Mapping[str, Any]], required: Mapping[str, bool], complexities: Mapping[str, float],
                 decay: Optional[DecayPolicy] = None, current_epoch: int = 0, now: Optional[float] = None,
                 only_targets: Optional[Set[str]] = None) -> Dict[str, StrategyScore]:
    """Aggregate trial rows into per-strategy scores (decayed if ``decay`` given)."""
    scores: Dict[str, StrategyScore] = {}
    for r in rows:
        if not r["counts"]:
            continue
        sid = r["strategy_id"]
        tid = r["target_id"]
        if sid is None or (only_targets is not None and tid not in only_targets):
            continue
        w = 1.0 if decay is None else decay.weight(r["ts"], r["epoch"], current_epoch, now)
        if w <= 0:
            continue
        sc = scores.get(sid)
        if sc is None:
            sc = scores[sid] = StrategyScore(sid, complexity=complexities.get(sid, 0.0))
        sc.stats(tid, required.get(tid, True)).add(bool(r["ok"]), r["ttfb_ms"], r["verdict"], w)
    return scores


# ----------------------------------------------------------------- surrogate
def features(params: Mapping[str, Any]) -> List[Tuple]:
    mode = params.get("mode", params.get("split", params.get("method", "")))
    out: List[Tuple] = []
    for k, v in params.items():
        out.append((k, _h(v)))
        if k not in ("mode",):
            out.append(("@" + str(mode), k, _h(v)))
    return out


def _h(v: Any) -> Any:
    return tuple(v) if isinstance(v, list) else v


def _logit(p: float) -> float:
    p = min(1 - 1e-4, max(1e-4, p))
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


@dataclass
class Surrogate:
    shrink: float = 4.0     # pseudo-trials pulling a feature towards the global mean
    base_k: float = 1.0
    base_n: float = 2.0
    feat: Dict[Tuple, List[float]] = field(default_factory=lambda: defaultdict(lambda: [0.0, 0.0]))
    observations: int = 0

    def fit(self, observations: Iterable[Tuple[Mapping[str, Any], float, float]]) -> "Surrogate":
        """``observations``: (params, k, n) per strategy (k/n = worst-target-weighted success)."""
        self.feat = defaultdict(lambda: [0.0, 0.0])
        self.base_k, self.base_n, self.observations = 1.0, 2.0, 0
        for params, k, n in observations:
            if n <= 0:
                continue
            # cap per-strategy evidence so one heavily raced strategy doesn't dominate
            scale = min(1.0, 8.0 / n)
            k, n = k * scale, n * scale
            self.base_k += k
            self.base_n += n
            self.observations += 1
            for f in features(params):
                acc = self.feat[f]
                acc[0] += k
                acc[1] += n
        return self

    @property
    def base(self) -> float:
        return self.base_k / self.base_n

    def predict(self, params: Mapping[str, Any]) -> float:
        b = _logit(self.base)
        x = b
        fs = features(params)
        if not fs:
            return self.base
        # average (not sum) of shrunk feature deviations: robust to correlated features
        dev = 0.0
        for f in fs:
            k, n = self.feat.get(f, (0.0, 0.0))
            p_f = (k + self.shrink * self.base) / (n + self.shrink)
            dev += _logit(p_f) - b
        x += dev * 2.0 / math.sqrt(len(fs))
        return _sigmoid(x)

    def uncertainty(self, params: Mapping[str, Any]) -> float:
        """0 (well known) .. 1 (unseen): mean shrinkage of the features."""
        fs = features(params)
        if not fs:
            return 1.0
        return sum(self.shrink / (self.feat.get(f, (0, 0))[1] + self.shrink) for f in fs) / len(fs)


def observations_from_scores(scores: Mapping[str, StrategyScore],
                             params_of: Mapping[str, Mapping[str, Any]]) -> List[Tuple[Mapping[str, Any], float, float]]:
    obs = []
    for sid, sc in scores.items():
        if sid not in params_of or sc.n_total <= 0:
            continue
        n = sum(t.n for t in sc.required)
        # worst-target rate × evidence: a strategy that works on one target only is not rewarded
        obs.append((params_of[sid], sc.rate * n, n))
    return obs


# --------------------------------------------------------------------- drift
@dataclass
class DriftReport:
    drifted: List[str]
    checked: int

    @property
    def detected(self) -> bool:
        return bool(self.drifted)


def detect_drift(store: Store, network_id: str, simulated: bool, recent_run_id: int,
                 required: Mapping[str, bool], min_old_rate: float = 0.8) -> DriftReport:
    """Compare the last run against older history for strategies tested in both."""
    rows = store.trials(network_id, simulated)
    old: Dict[str, List[float]] = defaultdict(lambda: [0.0, 0.0])
    new: Dict[str, List[float]] = defaultdict(lambda: [0.0, 0.0])
    for r in rows:
        if not r["counts"] or not required.get(r["target_id"], True):
            continue
        bucket = new if r["run_id"] == recent_run_id else old
        acc = bucket[r["strategy_id"]]
        acc[0] += r["ok"]
        acc[1] += 1
    drifted = []
    checked = 0
    for sid, (kn, nn) in new.items():
        if sid not in old:
            continue
        ko, no = old[sid]
        if no < 5 or ko / no < min_old_rate:
            continue
        checked += 1
        if two_proportion_drop(ko, no, kn, nn):
            drifted.append(sid)
    return DriftReport(drifted=drifted, checked=checked)
