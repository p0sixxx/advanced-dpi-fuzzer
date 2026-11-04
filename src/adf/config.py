"""TOML configuration (see examples/config.toml). No secrets are stored here:
SSH authentication is delegated to ssh keys / ssh-agent."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_HOME = Path.home() / ".adf"


@dataclass
class RouterConfig:
    host: str = ""
    user: str = "root"
    port: int = 22
    identity: Optional[str] = None
    remote_agent: str = "/tmp/adf-agent.sh"
    local: bool = False             # the controller runs on the router itself


@dataclass
class ProbeConfig:
    port: int = 11290
    timeout_s: int = 8
    connect_timeout_s: int = 4
    engine_start_s: int = 10        # slow routers need longer to open the temporary engine's port
    interval_ms: int = 250
    routing_mark: Optional[int] = 0x08000000
    dns_server: str = "77.88.8.8"


@dataclass
class SearchSection:
    network_id: str = "default"
    engine: str = "tachyon_desync"
    max_batches: int = 400
    max_probes: int = 6000
    max_minutes: float = 180.0
    min_batch_interval_s: float = 1.0
    seed: int = 0
    categories: List[str] = field(default_factory=list)


@dataclass
class AppConfig:
    router: RouterConfig = field(default_factory=RouterConfig)
    probe: ProbeConfig = field(default_factory=ProbeConfig)
    search: SearchSection = field(default_factory=SearchSection)
    db: Path = DEFAULT_HOME / "adf.sqlite"
    targets_file: Optional[Path] = None
    stop_file: Path = DEFAULT_HOME / "STOP"


def _apply(obj: Any, data: Dict[str, Any], where: str) -> None:
    for k, v in data.items():
        if not hasattr(obj, k):
            raise ValueError(f"unknown option [{where}] {k}")
        setattr(obj, k, v)


def load_config(path: Optional[Path]) -> AppConfig:
    cfg = AppConfig()
    if path is None:
        return cfg
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("password", "secret", "token"):
        if any(key in str(k).lower() for k in _walk_keys(data)):
            raise ValueError("secrets must not be stored in the config file; use ssh keys / ssh-agent")
    _apply(cfg.router, data.get("router", {}), "router")
    _apply(cfg.probe, data.get("probe", {}), "probe")
    _apply(cfg.search, data.get("search", {}), "search")
    paths = data.get("paths", {})
    if "db" in paths:
        cfg.db = Path(paths["db"]).expanduser()
    if "targets" in paths:
        cfg.targets_file = (Path(path).parent / paths["targets"]).expanduser()
    if "stop_file" in paths:
        cfg.stop_file = Path(paths["stop_file"]).expanduser()
    return cfg


def _walk_keys(d: Any):
    if isinstance(d, dict):
        for k, v in d.items():
            yield k
            yield from _walk_keys(v)
