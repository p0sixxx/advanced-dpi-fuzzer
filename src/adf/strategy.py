"""Canonical, reproducible strategy objects."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from .engines import Capabilities, Engine, StrategyError


def strategy_id(engine: str, params: Mapping[str, Any]) -> str:
    blob = json.dumps({"engine": engine, "params": dict(sorted(params.items()))}, sort_keys=True,
                      separators=(",", ":"), default=str)
    return engine[:2] + "-" + hashlib.sha1(blob.encode()).hexdigest()[:12]


@dataclass(frozen=True)
class Strategy:
    engine: str
    params_json: str
    text: str
    complexity: float
    origin: str = "generated"
    name: str = ""
    id: str = field(default="")

    @property
    def params(self) -> Dict[str, Any]:
        return json.loads(self.params_json)

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "engine": self.engine, "params": self.params, "text": self.text,
                "complexity": self.complexity, "origin": self.origin, "name": self.name}


def make_strategy(engine: Engine, params: Mapping[str, Any], origin: str = "generated", name: str = "",
                  caps: Optional[Capabilities] = None) -> Strategy:
    """Canonicalize + validate; raises :class:`StrategyError` when invalid."""
    canon = engine.canonicalize(params, caps)
    reason = engine.check(canon, caps)
    if reason is not None:
        raise StrategyError(reason)
    pj = json.dumps(canon, sort_keys=True, separators=(",", ":"))
    return Strategy(engine=engine.name, params_json=pj, text=engine.render(canon),
                    complexity=engine.complexity(canon), origin=origin, name=name,
                    id=strategy_id(engine.name, canon))


def from_text(engine: Engine, text: str, origin: str = "user", name: str = "",
              caps: Optional[Capabilities] = None) -> Strategy:
    return make_strategy(engine, engine.parse(text), origin=origin, name=name, caps=caps)
