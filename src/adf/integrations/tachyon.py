"""Tachyon adapter: import current Native Desync settings, export/apply/rollback strategies.

Semantics mirror ``usr/lib/config/connections.uc`` (the UCI → tachyon-core
translator) of Tachyon ``af72053``:

* ``desync_opts`` is parsed **only** when ``desync_preset`` is ``custom`` or empty;
* explicit ``desync_*`` options override the preset defaults;
* unknown split positions are silently dropped by Tachyon, therefore the
  exporter only emits positions from its grammar.

The exporter writes *every* desync option explicitly (and deletes stale ones):
Tachyon's own ``fuzzer.uc apply`` leaves ``desync_fooling`` / ``desync_auto_tune``
from the previous configuration in place, so the applied strategy can differ
from the measured one.
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..engines import StrategyError, TachyonDesync
from ..engines.tachyon_desync import KEY_ORDER, preset_params
from ..strategy import Strategy

CONFIG = "tachyon"
OPTION_FOR_KEY = {k: "desync_" + k for k in KEY_ORDER}
ALL_DESYNC_OPTIONS = sorted(set(OPTION_FOR_KEY.values()) | {"desync_preset", "desync_auto_tune", "desync_opts"})
_LINE = re.compile(r"^([A-Za-z0-9_-]+)\.([A-Za-z0-9_@\[\]-]+)(?:\.([A-Za-z0-9_-]+))?=(.*)$")


def parse_uci_show(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse ``uci show <config>`` output into {section: {".type": t, option: value}}."""
    out: Dict[str, Dict[str, Any]] = {}
    for raw in text.splitlines():
        m = _LINE.match(raw.strip())
        if not m:
            continue
        _, sid, opt, value = m.groups()
        vals = shlex.split(value) if value else [""]
        if opt is None:
            out.setdefault(sid, {})[".type"] = vals[0] if vals else ""
        else:
            out.setdefault(sid, {})[opt] = vals[0] if len(vals) == 1 else vals
    return out


def desync_sections(cfg: Mapping[str, Mapping[str, Any]]) -> List[str]:
    res = []
    for sid, opts in cfg.items():
        t = opts.get(".type")
        if (t == "section" and opts.get("action") == "desync") or \
                (t == "outbound_source" and opts.get("source_type") == "desync"):
            res.append(sid)
    return res


@dataclass
class ImportedSection:
    section: str
    kind: str                       # "fixed" | "adaptive"
    params: Optional[Dict[str, Any]]
    auto_tune: Optional[bool]
    ignored_opts: str = ""          # desync_opts present but ignored by Tachyon
    notes: List[str] = field(default_factory=list)


def _bool(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def section_to_params(sid: str, opts: Mapping[str, Any], engine: Optional[TachyonDesync] = None) -> ImportedSection:
    engine = engine or TachyonDesync(measure_udp=True)
    raw_preset = str(opts.get("desync_preset", "")).strip().lower()
    is_custom = raw_preset in ("", "custom")
    auto_tune = _bool(opts["desync_auto_tune"]) if "desync_auto_tune" in opts else None
    notes: List[str] = []
    params: Dict[str, Any] = {}
    if not is_custom:
        try:
            params = preset_params(raw_preset)
        except StrategyError:
            res = ImportedSection(sid, "adaptive", None, auto_tune)
            if opts.get("desync_opts"):
                res.ignored_opts = str(opts["desync_opts"])
                res.notes.append("desync_opts is ignored by Tachyon because desync_preset is not 'custom'")
            return res
    elif opts.get("desync_mode"):
        params["mode"] = engine.normalize_value("mode", opts["desync_mode"])
    for key, opt in OPTION_FOR_KEY.items():
        if key == "mode" or opt not in opts:
            continue
        v = opts[opt]
        if key in ("seqovl", "wsize", "udplen") and str(v) in ("", "0"):
            continue
        try:
            params[key] = engine.normalize_value(key, v)
        except (StrategyError, ValueError):
            notes.append(f"{opt}={v!r} is not understood and was dropped (Tachyon drops it too)")
    ignored = ""
    if opts.get("desync_opts"):
        if is_custom:
            parsed, dropped = _parse_partial(engine, str(opts["desync_opts"]))
            params.update(parsed)
            notes += [f"desync_opts token {t!r} dropped (Tachyon ignores it too)" for t in dropped]
        else:
            ignored = str(opts["desync_opts"])
            notes.append("desync_opts is ignored by Tachyon because desync_preset is not 'custom'")
    if "mode" not in params:
        params["mode"] = "fake_split"
        notes.append("no mode set: Tachyon falls back to fake_split")
    if auto_tune:
        notes.append("auto_tune=1: tachyon-core may switch away from these parameters at runtime")
    return ImportedSection(sid, "fixed", params, auto_tune, ignored, notes)


def _parse_partial(engine: TachyonDesync, text: str) -> Tuple[Dict[str, Any], List[str]]:
    """Tolerant desync_opts parser with connections.uc key normalisation."""
    out: Dict[str, Any] = {}
    dropped: List[str] = []
    for tok in text.split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        k = k.strip().lower()
        if k.startswith("--"):
            k = k[2:].replace("-", "_")
        if k.startswith("dpi_desync_"):
            k = k[len("dpi_desync_"):]
        elif k == "dpi_desync":
            k = "mode"
        k = {"ttl": "fake_ttl", "split_seqovl": "seqovl"}.get(k, k)
        try:
            if k == "preset":
                out.update(preset_params(v))
            elif k in KEY_ORDER:
                out[k] = engine.normalize_value(k, v)
            elif k != "auto_tune":
                dropped.append(tok)
        except (StrategyError, ValueError):
            dropped.append(tok)
    return out, dropped


def export_options(strategy: Strategy, keep_udp: bool = True) -> Dict[str, Optional[str]]:
    """UCI option → value (``None`` = delete) for a measured strategy."""
    if strategy.engine != TachyonDesync.name:
        raise StrategyError("only tachyon_desync strategies can be exported to Tachyon Native Desync")
    p = strategy.params
    opts: Dict[str, Optional[str]] = {opt: None for opt in ALL_DESYNC_OPTIONS}
    opts["desync_preset"] = "custom"
    opts["desync_auto_tune"] = "0"
    for key, value in p.items():
        opt = OPTION_FOR_KEY[key]
        if isinstance(value, bool):
            opts[opt] = "1" if value else "0"
        elif key in ("fooling", "fake_sni") and not value:
            opts[opt] = None
        elif key in ("seqovl", "wsize", "udplen") and not value:
            opts[opt] = None
        else:
            opts[opt] = str(value)
    for flag in ("desync_syndata", "desync_ipfrag", "desync_tlsrec_first"):
        if opts.get(flag) == "0":
            opts[flag] = None
    if keep_udp and not any(k in p for k in ("udp_fake", "udp_repeats", "udp_fake_ttl", "udplen")):
        # UDP behaviour was not measured: leave the user's current UDP settings untouched
        for opt in ("desync_udp_fake", "desync_udp_repeats", "desync_udp_fake_ttl", "desync_udplen"):
            opts.pop(opt, None)
    opts["desync_opts"] = TachyonDesync(measure_udp=True).render(p) + " auto_tune=0"
    return opts


def uci_commands(section: str, options: Mapping[str, Optional[str]], config: str = CONFIG) -> List[str]:
    if not re.fullmatch(r"[A-Za-z0-9_@\[\]-]+", section):
        raise ValueError(f"invalid UCI section name {section!r}")
    cmds = []
    for opt in sorted(options):
        val = options[opt]
        if val is None:
            cmds.append(f"uci -q delete {config}.{section}.{opt}")
        else:
            cmds.append(f"uci set {config}.{section}.{opt}={shlex.quote(val)}")
    return cmds


def backup_options(cfg: Mapping[str, Mapping[str, Any]], section: str) -> Dict[str, Optional[str]]:
    opts = cfg.get(section, {})
    out: Dict[str, Optional[str]] = {}
    for opt in ALL_DESYNC_OPTIONS:
        v = opts.get(opt)
        out[opt] = None if v is None else (v if isinstance(v, str) else " ".join(v))
    return out


def shell_script(cmds: Sequence[str], reload: bool = True, config: str = CONFIG) -> str:
    lines = ["set -e"] + list(cmds) + [f"uci commit {config}"]
    if reload:
        lines.append("tachyon reload")
    return "\n".join(lines) + "\n"


@dataclass
class ApplyPlan:
    section: str
    strategy_id: str
    new_options: Dict[str, Optional[str]]
    backup: Dict[str, Optional[str]]
    script: str
    rollback_script: str

    def to_dict(self) -> Dict[str, Any]:
        return {"section": self.section, "strategy_id": self.strategy_id, "new_options": self.new_options,
                "backup": self.backup, "script": self.script, "rollback_script": self.rollback_script}


def plan_apply(current_uci_show: str, section: str, strategy: Strategy, reload: bool = True) -> ApplyPlan:
    cfg = parse_uci_show(current_uci_show)
    if section not in cfg:
        raise ValueError(f"section '{section}' not found in tachyon config")
    if section not in desync_sections(cfg):
        raise ValueError(f"section '{section}' is not a Native Desync section (action=desync / source_type=desync)")
    new = export_options(strategy)
    backup = {k: v for k, v in backup_options(cfg, section).items() if k in new}
    return ApplyPlan(section, strategy.id, new, backup, shell_script(uci_commands(section, new), reload),
                     shell_script(uci_commands(section, backup), reload))


class TachyonRemote:
    """Executes plans on the router through a transport that exposes ``shell``."""

    def __init__(self, transport: Any):
        if not hasattr(transport, "shell"):
            raise TypeError("transport must provide shell()")
        self.transport = transport

    def show(self) -> str:
        return self.transport.shell(f"uci -q show {CONFIG}")

    def save_full_backup(self) -> str:
        """Full ``uci export`` copy kept on the router (tmpfs is not used: survives reboot)."""
        path = f"/etc/tachyon/adf-backup-{int(time.time())}.uci"
        self.transport.shell(f"mkdir -p /etc/tachyon && uci export {CONFIG} > {shlex.quote(path)} && chmod 600 "
                             f"{shlex.quote(path)} && echo {shlex.quote(path)}")
        return path

    def run(self, script: str) -> str:
        return self.transport.shell("sh -s", stdin=script)
