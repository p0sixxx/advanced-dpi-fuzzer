import itertools
import time

import pytest

from adf.engines import ByeDPI, TachyonDesync
from adf.generator import _pairs, pairwise, random_valid, screening_factors
from adf.learning import DecayPolicy, Surrogate, build_scores
from adf.scoring import (EXCELLENT, NOT_WORKING, PARTIAL, STABLE, UNTESTED, WORKING, StrategyScore, non_inferior,
                         two_proportion_drop, wilson)


def test_wilson_known_values():
    assert wilson(0, 0) == (0.0, 1.0)
    lo, hi = wilson(3, 3)
    assert 0.43 < lo < 0.45 and hi == 1.0
    lo, _ = wilson(23, 24)
    assert 0.79 < lo < 0.80
    lo, hi = wilson(5, 10)
    assert lo < 0.5 < hi


def _score(per_target, ttfb=100.0, complexity=1.0):
    sc = StrategyScore("x", complexity=complexity)
    for tid, (k, n) in per_target.items():
        for i in range(n):
            sc.stats(tid).add(i < k, ttfb)
    return sc


def test_classification_uses_worst_target():
    assert StrategyScore("x").classify() == UNTESTED
    assert _score({"a": (0, 5)}).classify() == NOT_WORKING
    assert _score({"a": (30, 30), "b": (30, 30)}).classify(ref_ttfb_ms=90) == EXCELLENT
    assert _score({"a": (30, 30), "b": (12, 12)}).classify() == STABLE
    assert _score({"a": (6, 6), "b": (6, 6)}).classify() == WORKING
    # one target fine, the other broken -> only partially working
    assert _score({"a": (12, 12), "b": (1, 12)}).classify() == PARTIAL


def test_excellent_requires_latency():
    sc = _score({"a": (30, 30)}, ttfb=2000)
    assert sc.classify(ref_ttfb_ms=100) == STABLE


def test_utility_prefers_simpler_when_equal():
    a = _score({"a": (20, 20)}, complexity=1)
    b = _score({"a": (20, 20)}, complexity=4)
    assert a.utility() > b.utility()
    c = _score({"a": (12, 20)}, complexity=0)
    assert b.utility() > c.utility()  # reliability dominates simplicity


def test_non_inferiority():
    inc = _score({"a": (20, 20)})
    assert non_inferior(_score({"a": (20, 20)}), inc)
    assert not non_inferior(_score({"a": (14, 20)}), inc)
    assert not non_inferior(_score({"a": (5, 5)}), inc)  # not enough evidence


def test_two_proportion_drop():
    assert two_proportion_drop(48, 50, 5, 20)
    assert not two_proportion_drop(48, 50, 19, 20)


def test_pairwise_covers_all_feasible_pairs():
    eng = ByeDPI()
    design = pairwise(eng, seed=1)
    factors = screening_factors(eng, None)
    names = [f.name for f in factors]
    covered = set()
    for d in design:
        covered |= _pairs(d, names)
    # brute force over the screening grid: every pair occurring in some valid config must be covered
    feasible = set()
    for combo in itertools.product(*[f.values for f in factors]):
        cfg = dict(zip(names, combo))
        canon = eng.canonicalize(cfg)
        if eng.check(canon) is None:
            feasible |= _pairs(canon, names)
    assert feasible <= covered
    full = sum(1 for _ in itertools.product(*[f.values for f in factors]))
    assert len(design) < full / 3


def test_pairwise_tachyon_is_bounded_and_valid():
    eng = TachyonDesync()
    design = pairwise(eng, seed=0)
    assert 100 < len(design) < 400
    modes = {d["mode"] for d in design}
    assert {"fake_split", "multi_disorder", "tlsrec", "oob"} <= modes
    assert all(eng.check(d) is None for d in design)


def test_random_valid():
    eng = TachyonDesync()
    rs = random_valid(eng, None, 30, seed=2)
    assert len(rs) == 30 and all(eng.check(r) is None for r in rs)


def test_decay_weights():
    pol = DecayPolicy(half_life_days=10, epoch_factor=0.5)
    now = time.time()
    assert pol.weight(now, 0, 0, now) == pytest.approx(1.0)
    assert pol.weight(now - 10 * 86400, 0, 0, now) == pytest.approx(0.5)
    assert pol.weight(now, 0, 2, now) == pytest.approx(0.25)
    assert pol.weight(now - 1000 * 86400, 0, 0, now) == 0.0


def test_build_scores_with_decay():
    now = time.time()
    rows = [
        {"counts": 1, "strategy_id": "s", "target_id": "a", "ok": 1, "ttfb_ms": 10, "verdict": "ok", "ts": now,
         "epoch": 0},
        {"counts": 1, "strategy_id": "s", "target_id": "a", "ok": 0, "ttfb_ms": 0, "verdict": "tls_reset",
         "ts": now - 14 * 86400, "epoch": 0},
        {"counts": 0, "strategy_id": "s", "target_id": "a", "ok": 0, "ttfb_ms": 0, "verdict": "network_down",
         "ts": now, "epoch": 0},
    ]
    sc = build_scores(rows, {"a": True}, {"s": 1.0}, DecayPolicy(half_life_days=14), 0, now)["s"]
    assert sc.targets["a"].n == pytest.approx(1.5)
    assert sc.targets["a"].k == pytest.approx(1.0)


def test_surrogate_learns_feature_effects():
    obs = []
    for ttl in (3, 4, 5, 6):
        obs.append(({"mode": "fake_split", "fooling": "md5", "fake_ttl": ttl}, 9.0, 10.0))
        obs.append(({"mode": "split", "split_pos": "1"}, 0.0, 10.0))
    s = Surrogate().fit(obs)
    good = s.predict({"mode": "fake_split", "fooling": "md5", "fake_ttl": 8})
    bad = s.predict({"mode": "split", "split_pos": "2"})
    assert good > 0.6 > bad
    assert s.uncertainty({"mode": "oob"}) > s.uncertainty({"mode": "split"})
