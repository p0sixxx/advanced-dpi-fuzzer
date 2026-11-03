"""Candidate generation.

The generator never enumerates the full product space. It produces:

1. **Seeds** – upstream presets, previous winners, user strategies.
2. **Screening design** – a *pairwise covering array* (AETG greedy algorithm)
   over the engine's *primary* factors with a coarse value grid, built
   separately per partition value (mode / split function / method) because
   factor applicability depends on it. Every feasible pair of primary factor
   values appears in at least one candidate: interactions such as
   "fooling × split position" are covered with tens instead of thousands of
   candidates.
3. **Neighbourhood** – single-factor mutations over the *full* domain of all
   factors (including minor ones such as decoy SNI or seqovl) around
   promising strategies (local/evolutionary search).
4. **Simplifications** – strictly simpler variants of confirmed strategies.
5. **Exploration** – random valid samples when nothing works yet.
"""

from __future__ import annotations

import itertools
import random
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from .engines import Capabilities, Engine, StrategyError
from .engines.base import Factor, Params

# Primary factors and coarse screening grids per engine. Values outside the
# engine's (capability-filtered) domain are dropped automatically.
SCREENING: Dict[str, Dict[str, Tuple[Any, ...]]] = {
    "tachyon_desync": {
        "mode": ("split", "tlsrec", "disorder", "oob", "fake", "fake_split", "fake_disorder", "multi_split",
                 "multi_disorder"),
        "split_pos": ("1", "2", "midsld", "sni", "sniext+1", "host+1", "endhost-1", "1,midsld", "1,sniext+1,midsld",
                      "sniext+1,midsld"),
        "fooling": ("", "md5", "badsum", "badseq", "badack", "timestamp", "datanoack", "autottl", "md5_badack",
                    "badseq_badack_badsum", "hopbyhop"),
        "fake_ttl": (3, 4, 5, 6, 8),
        "repeats": (1, 4),
    },
    "zapret2": {
        "split": ("none", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"),
        "fake": (False, True),
        "fooling": ("none", "md5", "badsum", "badseq", "badack", "ts", "datanoack", "autottl", "hopbyhop2"),
        "fake_ttl": (0, 3, 5, 8),
        "pos": ("1", "2", "midsld", "sniext+1", "host+1", "1,midsld"),
    },
    "zapret": {
        "split": ("none", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit"),
        "fake": (False, True),
        "fooling": ("none", "md5sig", "ts", "badsum", "badseq", "datanoack", "hopbyhop2"),
        "ttl": (0, 3, 5, 8),
        "pos": ("1", "2", "midsld", "sniext+1", "host+1", "1,midsld"),
    },
    "byedpi": {
        "method": ("split", "disorder", "oob", "disoob", "fake"),
        "pos": ("1", "2", "0+s", "1+s", "0+sm", "1+h"),
        "ttl": (3, 5, 8),
        "md5sig": (False, True),
        "tlsrec": ("", "1+s"),
    },
}


def screening_factors(engine: Engine, caps: Optional[Capabilities]) -> List[Factor]:
    grid = SCREENING.get(engine.name, {})
    fmap = engine.factor_map(caps)
    out = []
    for name, values in grid.items():
        f = fmap.get(name)
        if f is None:
            continue
        allowed = [v for v in values if v in f.values]
        if allowed:
            out.append(Factor(f.name, tuple(allowed), f.neutral, f.description, f.applies, f.cost, f.ordered))
    return out


def _pairs(cfg: Mapping[str, Any], names: Sequence[str]) -> Set[Tuple]:
    present = [(n, cfg[n]) for n in names if n in cfg]
    return {(a, b) for a, b in itertools.combinations(present, 2)}


def pairwise(engine: Engine, caps: Optional[Capabilities] = None, seed: int = 0, candidates_per_step: int = 30,
             max_per_partition: int = 120, stall_limit: int = 4) -> List[Params]:
    """AETG-style pairwise covering design over the screening factors."""
    rng = random.Random(seed)
    factors = screening_factors(engine, caps)
    if not factors:
        return []
    part = factors[0]
    others = factors[1:]
    names = [f.name for f in factors]
    result: List[Params] = []
    seen: Set[str] = set()
    for pval in part.values:
        covered: Set[Tuple] = set()
        stall = 0
        produced = 0
        # values that are infeasible for this partition on their own are never chosen
        feasible = {f.name: [v for v in f.values if _feasible_alone(engine, caps, part.name, pval, f.name, v)]
                    for f in others}
        while produced < max_per_partition and stall < stall_limit:
            best: Optional[Params] = None
            best_gain = 0
            for _ in range(candidates_per_step):
                cfg: Dict[str, Any] = {part.name: pval}
                order = others[:]
                rng.shuffle(order)
                for f in order:
                    choices = list(feasible[f.name]) or list(f.values)
                    rng.shuffle(choices)
                    scored = []
                    for v in choices:
                        trial = dict(cfg)
                        trial[f.name] = v
                        gain = len(_pairs(trial, names) - covered)
                        scored.append((gain, v))
                    scored.sort(key=lambda gv: -gv[0])
                    cfg[f.name] = scored[0][1]
                try:
                    canon = engine.canonicalize(cfg, caps)
                except StrategyError:
                    continue
                if engine.check(canon, caps) is not None:
                    continue
                gain = len(_pairs(canon, names) - covered)
                if gain > best_gain:
                    best, best_gain = canon, gain
            if best is None:
                stall += 1
                continue
            key = repr(sorted(best.items()))
            covered |= _pairs(best, names)
            if key in seen:
                stall += 1
                continue
            seen.add(key)
            result.append(best)
            produced += 1
            stall = 0
    return result


def _valid(engine: Engine, caps: Optional[Capabilities], cfg: Mapping[str, Any]) -> bool:
    try:
        canon = engine.canonicalize(cfg, caps)
    except StrategyError:
        return False
    return engine.check(canon, caps) is None


def _feasible_alone(engine: Engine, caps: Optional[Capabilities], pname: str, pval: Any, fname: str,
                    value: Any) -> bool:
    """Is ``fname=value`` feasible with ``pname=pval``, allowing one other factor to be repaired?

    Neutral values can themselves be infeasible for a partition (a single split
    position under a multi mode, zapret fakes without fooling), so one other
    factor may take any value of its domain.
    """
    base = {pname: pval, fname: value}
    if _valid(engine, caps, base):
        return True
    for name, f in engine.factor_map(caps).items():
        if name in (pname, fname):
            continue
        if any(_valid(engine, caps, {**base, name: v}) for v in f.values):
            return True
    return False


def random_valid(engine: Engine, caps: Optional[Capabilities], n: int, seed: int = 0,
                 max_attempts: int = 50) -> List[Params]:
    """Uniform-ish random valid configurations over the full domain."""
    rng = random.Random(seed)
    fmap = engine.factor_map(caps)
    out: List[Params] = []
    seen: Set[str] = set()
    attempts = 0
    while len(out) < n and attempts < n * max_attempts:
        attempts += 1
        cfg = {name: rng.choice(f.values) for name, f in fmap.items()}
        try:
            canon = engine.canonicalize(cfg, caps)
        except StrategyError:
            continue
        if engine.check(canon, caps) is not None:
            continue
        key = repr(sorted(canon.items()))
        if key not in seen:
            seen.add(key)
            out.append(canon)
    return out
