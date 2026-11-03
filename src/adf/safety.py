"""Budgets, rate limiting, back-off and graceful stop.

Every batch is committed to SQLite before the next one starts, so an
interruption (Ctrl+C, SIGTERM, stop file, power loss on the controller) never
loses more than the batch in flight, and the next run resumes from the stored
evidence.
"""

from __future__ import annotations

import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class Budget:
    max_batches: int = 400
    max_probes: int = 6000
    max_seconds: float = 3 * 3600.0


@dataclass
class SafetyPolicy:
    min_batch_interval_s: float = 1.0       # rate limit between engine batches
    control_every: int = 8                  # control check cadence (batches)
    max_control_failures: int = 6           # consecutive network-down detections before abort
    backoff_initial_s: float = 15.0
    backoff_max_s: float = 600.0
    stop_file: Optional[Path] = None
    min_agent_mem_kb: int = 24576


class StopRequested(Exception):
    pass


@dataclass
class Guard:
    budget: Budget = field(default_factory=Budget)
    policy: SafetyPolicy = field(default_factory=SafetyPolicy)
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], None] = time.sleep
    batches: int = 0
    probes: int = 0
    stop_reason: str = ""
    _started: float = 0.0
    _last_batch: float = 0.0
    _backoff: float = 0.0
    _signals_installed: bool = False

    def start(self) -> None:
        self._started = self.clock()
        self._last_batch = 0.0
        self._backoff = self.policy.backoff_initial_s

    def install_signal_handlers(self) -> None:
        def handler(signum, frame):  # noqa: ARG001
            self.stop_reason = f"signal {signum}"

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):  # not in main thread
                pass
        self._signals_installed = True

    @property
    def elapsed(self) -> float:
        return self.clock() - self._started

    def fraction_used(self) -> float:
        b = self.budget
        return max(self.batches / max(1, b.max_batches), self.probes / max(1, b.max_probes),
                   self.elapsed / max(1.0, b.max_seconds))

    def check(self) -> None:
        if self.stop_reason:
            raise StopRequested(self.stop_reason)
        if self.policy.stop_file is not None and Path(self.policy.stop_file).exists():
            self.stop_reason = f"stop file {self.policy.stop_file}"
            raise StopRequested(self.stop_reason)
        if self.fraction_used() >= 1.0:
            self.stop_reason = "budget exhausted"
            raise StopRequested(self.stop_reason)

    def before_batch(self) -> None:
        self.check()
        wait = self.policy.min_batch_interval_s - (self.clock() - self._last_batch)
        if self._last_batch and wait > 0:
            self.sleeper(wait)

    def after_batch(self, probes: int) -> None:
        self.batches += 1
        self.probes += probes
        self._last_batch = self.clock()

    def backoff(self) -> float:
        """Sleep after a network-down detection; returns the slept time."""
        t = self._backoff
        self.sleeper(t)
        self._backoff = min(self.policy.backoff_max_s, self._backoff * 2)
        return t

    def reset_backoff(self) -> None:
        self._backoff = self.policy.backoff_initial_s
