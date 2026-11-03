"""Engine abstraction.

An engine is a DPI desynchronization implementation (tachyon-core Native Desync,
nfqws, nfqws2, ByeDPI). Each engine declares its parameter space as a list of
:class:`Factor` objects, the compatibility rules between parameters, how to bring
a parameter dict into canonical form (so that equivalent configurations share one
id) and how to render it in the engine's own syntax.

Engines never share syntax: rendering and parsing are engine specific, and the
validator of each engine encodes the grammar of the real implementation.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

Params = Dict[str, Any]


class StrategyError(ValueError):
    """Raised when a strategy cannot be parsed or is invalid for an engine."""


@dataclass(frozen=True)
class Factor:
    """One tunable parameter of an engine.

    ``values`` is the search domain used by the generator (not necessarily every
    value the engine accepts). ``neutral`` is the value meaning "feature off" —
    the generator uses it when simplifying a strategy. ``applies`` tells whether
    the factor has any effect for a given (partial) parameter set; factors that do
    not apply are removed during canonicalization.
    """

    name: str
    values: Tuple[Any, ...]
    neutral: Any
    description: str = ""
    applies: Callable[[Mapping[str, Any]], bool] = field(default=lambda p: True, compare=False)
    cost: Callable[[Any], float] = field(default=lambda v: 0.0, compare=False)
    ordered: bool = False  # numeric factor whose neighbours are adjacent values

    def neighbours(self, value: Any) -> List[Any]:
        """Values adjacent to ``value`` (ordered factors) or all other values."""
        vals = list(self.values)
        if value not in vals:
            return vals
        if not self.ordered:
            return [v for v in vals if v != value]
        i = vals.index(value)
        out = []
        if i > 0:
            out.append(vals[i - 1])
        if i + 1 < len(vals):
            out.append(vals[i + 1])
        return out


@dataclass
class Capabilities:
    """What a concrete installed engine binary accepts.

    ``allowed`` maps factor name -> set of accepted values. A factor missing from
    ``allowed`` is unrestricted (within its own domain). ``unsupported`` lists
    factors the binary rejects entirely. ``source`` documents where the data came
    from (``profile:<name>`` or ``probed:<host>``).
    """

    engine: str
    source: str
    allowed: Dict[str, set] = field(default_factory=dict)
    unsupported: set = field(default_factory=set)
    version: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def accepts(self, factor: str, value: Any) -> bool:
        if factor in self.unsupported:
            return False
        allowed = self.allowed.get(factor)
        if allowed is None:
            return True
        return _hashable(value) in allowed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": self.engine,
            "source": self.source,
            "version": self.version,
            "allowed": {k: sorted(map(str, v)) for k, v in self.allowed.items()},
            "unsupported": sorted(self.unsupported),
            "extra": self.extra,
        }


def _hashable(v: Any) -> Any:
    if isinstance(v, list):
        return tuple(v)
    return v


class Engine(abc.ABC):
    """Base class for all engines."""

    #: short engine id used in the database and on the CLI
    name: str = ""
    #: human readable title
    title: str = ""
    #: whether this release can measure the engine on a router
    probe_supported: bool = False

    # ------------------------------------------------------------------ space
    @abc.abstractmethod
    def factors(self, caps: Optional[Capabilities] = None) -> List[Factor]:
        """Search domain, already filtered by ``caps``."""

    def factor_map(self, caps: Optional[Capabilities] = None) -> Dict[str, Factor]:
        return {f.name: f for f in self.factors(caps)}

    @abc.abstractmethod
    def default_capabilities(self) -> Capabilities:
        """Conservative capabilities when the binary has not been probed."""

    # ----------------------------------------------------------- validation
    @abc.abstractmethod
    def check(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Optional[str]:
        """Return ``None`` if valid, otherwise a human readable reason."""

    def is_valid(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> bool:
        return self.check(params, caps) is None

    def canonicalize(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Params:
        """Drop factors that do not apply and normalise value types.

        Factors that are absent are filled with their ``neutral`` value first, so
        that ``{mode: split}`` and ``{mode: split, seqovl: 0}`` canonicalize to the
        same dict.
        """
        fmap = self.factor_map(None)
        out: Params = {}
        for name, value in params.items():
            if name not in fmap:
                raise StrategyError(f"{self.name}: unknown parameter '{name}'")
            out[name] = self.normalize_value(name, value)
        for name, factor in fmap.items():
            out.setdefault(name, factor.neutral)
        # iterate to a fixed point: removing one factor can disable another
        changed = True
        while changed:
            changed = False
            for name in list(out):
                f = fmap[name]
                if not f.applies(out):
                    del out[name]
                    changed = True
        return {k: out[k] for k in sorted(out)}

    def normalize_value(self, name: str, value: Any) -> Any:
        return value

    # -------------------------------------------------------------- syntax
    @abc.abstractmethod
    def render(self, params: Mapping[str, Any]) -> str:
        """Render canonical params into the engine's native strategy string."""

    @abc.abstractmethod
    def parse(self, text: str) -> Params:
        """Parse a native strategy string into params (inverse of :meth:`render`)."""

    # ----------------------------------------------------------- heuristics
    def complexity(self, params: Mapping[str, Any]) -> float:
        fmap = self.factor_map(None)
        total = 0.0
        for name, value in params.items():
            f = fmap.get(name)
            if f is not None:
                total += float(f.cost(value))
        return round(total, 3)

    def seeds(self, caps: Optional[Capabilities] = None) -> List[Tuple[str, Params]]:
        """Known strategies (name, params) from upstream presets."""
        return []

    def simplifications(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> List[Params]:
        """Strictly simpler variants of ``params`` (one change each).

        Generic rule: set one non-neutral factor back to neutral, or move an
        ordered factor one step towards lower cost.
        """
        fmap = self.factor_map(caps)
        out: List[Params] = []
        for name, value in params.items():
            f = fmap.get(name)
            if f is None:
                continue
            if (
                value != f.neutral
                and f.cost(f.neutral) < f.cost(value)
                and caps_ok(caps, name, f.neutral)
            ):
                cand = dict(params)
                cand[name] = f.neutral
                out.append(cand)
            if f.ordered and value in f.values:
                cheaper = [v for v in f.neighbours(value) if f.cost(v) < f.cost(value)]
                for v in cheaper:
                    cand = dict(params)
                    cand[name] = v
                    out.append(cand)
        return self._valid_unique(out, caps)

    def mutations(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> List[Params]:
        """All single-factor neighbours of ``params`` that are valid."""
        fmap = self.factor_map(caps)
        out: List[Params] = []
        for name, f in fmap.items():
            current = params.get(name, f.neutral)
            for v in f.neighbours(current):
                cand = dict(params)
                cand[name] = v
                out.append(cand)
        return self._valid_unique(out, caps)

    def _valid_unique(self, cands: Iterable[Mapping[str, Any]], caps: Optional[Capabilities]) -> List[Params]:
        seen = set()
        res: List[Params] = []
        for c in cands:
            try:
                canon = self.canonicalize(c, caps)
            except StrategyError:
                continue
            if self.check(canon, caps) is not None:
                continue
            key = repr(sorted(canon.items()))
            if key in seen:
                continue
            seen.add(key)
            res.append(canon)
        return res


def caps_ok(caps: Optional[Capabilities], factor: str, value: Any) -> bool:
    return caps is None or caps.accepts(factor, value)


def filter_values(values: Sequence[Any], caps: Optional[Capabilities], factor: str) -> Tuple[Any, ...]:
    if caps is None:
        return tuple(values)
    return tuple(v for v in values if caps.accepts(factor, v))
