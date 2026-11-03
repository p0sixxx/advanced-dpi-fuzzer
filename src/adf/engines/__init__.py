"""Engine registry."""

from __future__ import annotations

from typing import Dict, Sequence, Type

from .base import Capabilities, Engine, Factor, StrategyError
from .byedpi import ByeDPI
from .tachyon_desync import TachyonDesync
from .zapret import Zapret
from .zapret2 import Zapret2

ENGINES: Dict[str, Type[Engine]] = {
    TachyonDesync.name: TachyonDesync,
    Zapret.name: Zapret,
    Zapret2.name: Zapret2,
    ByeDPI.name: ByeDPI,
}


def get_engine(name: str, measure_udp: bool = False, families: Sequence[str] = ("ipv4",)) -> Engine:
    try:
        cls = ENGINES[name]
    except KeyError:
        raise StrategyError(f"unknown engine '{name}' (known: {', '.join(sorted(ENGINES))})") from None
    if cls is TachyonDesync:
        return TachyonDesync(measure_udp=measure_udp, families=families)
    if cls in (Zapret, Zapret2):
        return cls(families=families)
    return cls()


__all__ = ["Capabilities", "Engine", "Factor", "StrategyError", "ENGINES", "get_engine",
           "TachyonDesync", "Zapret", "Zapret2", "ByeDPI"]
