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
from ..engines.tachyon_desync import CORE_DEFAULTS, KEY_ORDER, normalize_pos, preset_params
from ..strategy import Strategy

CONFIG = "tachyon"
OPTION_FOR_KEY = {k: "desync_" + k for k in KEY_ORDER}
ALL_DESYNC_OPTIONS = sorted(set(OPTION_FOR_KEY.values()) | {"desync_preset", "desync_auto_tune", "desync_opts"})
_LINE = re.compile(r"^([A-Za-z0-9_-]+)\.([A-Za-z0-9_@\[\]-]+)(?:\.([A-Za-z0-9_-]+))?=(.*)$")


# Only these lines are fetched from the router: section types, desync-related options, what
# ties a section to a service (list names) and references between sections (ids only).
# Subscription URLs, keys and other options never leave the router.
UCI_FILTER = (r"^tachyon\.[^.=]+=(section|outbound_source)$|"
              r"^tachyon\.[^.=]+\.(action|enabled|community_lists|condition_refs|source_type|outbound_source_refs|"
              r"source_refs|outbound_group_levels|desync_[a-z0-9_]+)=")
SHOW_DESYNC_CMD = f"uci -q show {CONFIG} | grep -E '{UCI_FILTER}'"


def _split_value(value: str) -> List[str]:
    try:
        return shlex.split(value) if value else [""]
    except ValueError:
        # unbalanced quoting that survived joining: keep the raw text without outer quotes
        return [value.strip().strip("'")]


def parse_uci_show(text: str) -> Dict[str, Dict[str, Any]]:
    """Parse ``uci show <config>`` output into {section: {".type": t, option: value}}.

    Values may span several lines (uci quotes embedded newlines); continuation
    lines are joined until the quoting balances.
    """
    out: Dict[str, Dict[str, Any]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i].strip()
        i += 1
        m = _LINE.match(raw)
        if not m:
            continue
        _, sid, opt, value = m.groups()
        while i < len(lines) and not _balanced(value):
            value += "\n" + lines[i]
            i += 1
        vals = _split_value(value)
        if opt is None:
            out.setdefault(sid, {})[".type"] = vals[0] if vals else ""
        else:
            out.setdefault(sid, {})[opt] = vals[0] if len(vals) == 1 else vals
    return out


def _balanced(value: str) -> bool:
    try:
        shlex.split(value)
        return True
    except ValueError:
        return False


def desync_sections(cfg: Mapping[str, Mapping[str, Any]]) -> List[str]:
    res = []
    for sid, opts in cfg.items():
        t = opts.get(".type")
        if (t == "section" and opts.get("action") == "desync") or \
                (t == "outbound_source" and opts.get("source_type") == "desync"):
            res.append(sid)
    return res


def _id_list(opts: Mapping[str, Any], key: str) -> List[str]:
    value = opts.get(key, [])
    return [value] if isinstance(value, str) else list(value)


def _uses_own_desync_options(opts: Mapping[str, Any]) -> bool:
    return opts.get("action") == "desync" and bool(opts.get("desync_preset") or opts.get("desync_opts"))


def inactive_desync_sources(cfg: Mapping[str, Mapping[str, Any]]) -> Dict[str, str]:
    """Desync outbound sources whose options never reach tachyon-core, with the reason.

    A section with action=desync builds its outbound from its own desync_* options: a source
    linked through outbound_source_refs adds nothing, not even options the section leaves
    unset (checked against the generated /etc/tachyon-core/config.json). Sources used by
    other sections, groups or balancers do reach the core.
    """
    shadowed_by: Dict[str, List[str]] = {}
    used = set()
    for sid, opts in cfg.items():
        for ref in _id_list(opts, "outbound_source_refs"):
            if _uses_own_desync_options(opts):
                shadowed_by.setdefault(ref, []).append(sid)
            else:
                used.add(ref)
        used.update(_id_list(opts, "source_refs"))
        used.update(_id_list(opts, "outbound_group_levels"))
    out = {}
    for sid in desync_sections(cfg):
        if cfg[sid].get(".type") != "outbound_source" or sid in used:
            continue
        if sid in shadowed_by:
            out[sid] = f"ignored: {', '.join(shadowed_by[sid])} uses its own desync_* options"
        else:
            out[sid] = "not referenced by any section"
    return out



# connections.uc norm_preset aliases
_PRESET_ALIASES = {
    "adaptive": "auto", "smart": "auto", "fakesplit": "fake_split", "fake+split": "fake_split",
    "fakedsplit": "fake_split", "faked_split": "fake_split", "fakedisorder": "fake_disorder",
    "fake+disorder": "fake_disorder", "multidisorder": "multi_disorder", "multi+disorder": "multi_disorder",
    "fakeddisorder": "multi_disorder", "faked_disorder": "multi_disorder", "multisplit": "multi_split",
    "multi+split": "multi_split", "tls_rec": "tlsrec", "youtube": "fake_split", "google_youtube": "fake_split",
    "discord": "fake_split", "general": "fake_split", "general_fake_tls": "fake_split", "general_alt": "tlsrec",
    "aggressive": "fake_disorder", "general_alt2": "fake_disorder", "general_multisplit": "multi_split",
    "light": "split", "general_simple_fake": "split",
}
_KNOWN_PRESETS = {"auto", "fake_split", "fake_disorder", "multi_disorder", "multi_split", "tlsrec", "split",
                  "disorder", "fake", "oob"}
TCP_KEYS = ("mode", "split_pos", "fooling", "fake_ttl", "fake_sni", "repeats", "split_delay_ms", "seqovl",
            "syndata", "wsize", "ipfrag", "tlsrec_first")


@dataclass
class ImportedSection:
    section: str
    kind: str                       # "fixed" | "adaptive"
    params: Optional[Dict[str, Any]]  # measurable TCP strategy (None: adaptive or not expressible)
    auto_tune: Optional[bool]
    outbound: Dict[str, Any] = field(default_factory=dict)  # exact object Tachyon passes to tachyon-core
    ignored_opts: str = ""          # desync_opts present but ignored by Tachyon
    notes: List[str] = field(default_factory=list)


def _bool(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _norm_preset(v: Any) -> str:
    v = str(v or "").strip().lower()
    if v in ("", "none", "custom"):
        return ""
    v = _PRESET_ALIASES.get(v, v)
    return v if v in _KNOWN_PRESETS else "auto"


def _pos_items(value: Any, notes: List[str]) -> Any:
    """Per-item tolerant split_pos normalisation (connections.uc drops invalid items silently)."""
    items = []
    for part in str(value).split(","):
        try:
            items.append(normalize_pos(part))
        except StrategyError:
            if part.strip():
                notes.append(f"split_pos item {part.strip()!r} is dropped by Tachyon")
    if not items:
        return None
    conv = [int(i) if i.isdigit() else i for i in items]
    return conv[0] if len(conv) == 1 else conv


def section_outbound(opts: Mapping[str, Any], engine: Optional[TachyonDesync] = None) -> Tuple[Dict[str, Any], List[str], str]:
    """The ``desync`` outbound Tachyon generates for a section (connections.uc semantics).

    Returns (outbound, notes, ignored desync_opts).
    """
    engine = engine or TachyonDesync(measure_udp=True)
    notes: List[str] = []
    raw_preset = str(opts.get("desync_preset", "")).strip().lower()
    is_custom = raw_preset in ("", "custom")
    ob: Dict[str, Any] = {"type": "desync"}
    preset = _norm_preset(raw_preset)
    if preset:
        ob["preset"] = preset
    if is_custom and opts.get("desync_mode"):
        ob["mode"] = engine.normalize_value("mode", opts["desync_mode"])
    fooling = engine.normalize_value("fooling", opts.get("desync_fooling", ""))
    if fooling:
        ob["fooling"] = fooling
    if str(opts.get("desync_auto_tune", "")).strip() != "":
        ob["auto_tune"] = _bool(opts["desync_auto_tune"])
    if _bool(opts.get("desync_tlsrec_first", "0")):
        ob["tlsrec_first"] = True
    if raw_preset == "discord" and not _bool(opts.get("desync_udp_fake", "0")):
        ob["udp_fake"] = True
    if "preset" not in ob and "mode" not in ob:
        ob["preset"] = "auto"
    if opts.get("desync_split_pos"):
        sp = _pos_items(opts["desync_split_pos"], notes)
        if sp is not None:
            ob["split_pos"] = sp
    for key in ("seqovl", "wsize", "udplen", "fake_ttl", "repeats", "udp_repeats", "udp_fake_ttl"):
        v = str(opts.get("desync_" + key, "")).strip()
        if v.isdigit() and int(v) > 0:
            ob[key] = int(v)
    for key in ("syndata", "ipfrag"):
        if _bool(opts.get("desync_" + key, "0")):
            ob[key] = True
    if str(opts.get("desync_fake_sni", "")).strip():
        ob["fake_sni"] = str(opts["desync_fake_sni"]).strip()
    sd = str(opts.get("desync_split_delay_ms", "")).strip()
    if sd.isdigit():
        ob["split_delay_ms"] = int(sd)
    if str(opts.get("desync_udp_fake", "")).strip() != "":
        ob["udp_fake"] = _bool(opts["desync_udp_fake"])
    ignored = ""
    if opts.get("desync_opts"):
        if is_custom:
            parsed, dropped = _parse_partial(engine, str(opts["desync_opts"]))
            for k, v in parsed.items():
                if k == "split_pos":
                    v = _pos_items(v, notes)
                    if v is None:
                        continue
                ob[k] = v
            notes += [f"desync_opts token {t!r} dropped (Tachyon ignores it too)" for t in dropped]
        else:
            ignored = str(opts["desync_opts"])
            notes.append("desync_opts is ignored by Tachyon because desync_preset is not 'custom'")
    return ob, notes, ignored


def section_to_params(sid: str, opts: Mapping[str, Any], engine: Optional[TachyonDesync] = None) -> ImportedSection:
    """Import a section: exact outbound + (when it is a fixed strategy) its measurable TCP params.

    Keys Tachyon leaves out get tachyon-core's defaults (CORE_DEFAULTS), so the
    imported strategy is what the core actually runs, not ADF's neutral values.
    """
    tcp_engine = TachyonDesync()
    ob, notes, ignored = section_outbound(opts, engine)
    if _uses_own_desync_options(opts) and _id_list(opts, "outbound_source_refs"):
        notes.append(f"linked outbound sources are ignored: {', '.join(_id_list(opts, 'outbound_source_refs'))}")
    auto_tune = ob.get("auto_tune")
    preset = ob.get("preset")
    if preset == "auto":
        notes.append("Adaptive 2.0 (preset=auto): tachyon-core chooses the strategy itself; "
                     "explicit options are passed as starting values")
        return ImportedSection(sid, "adaptive", None, auto_tune, ob, ignored, notes)
    params: Dict[str, Any] = preset_params(preset) if preset else {"mode": ob.get("mode", "fake_split")}
    if "mode" in ob:
        params["mode"] = ob["mode"]
    for k in TCP_KEYS[1:]:
        if k in ob:
            v = ob[k]
            params[k] = ",".join(str(x) for x in v) if isinstance(v, list) else v
    for k, v in CORE_DEFAULTS.items():
        params.setdefault(k, v)
    if auto_tune:
        notes.append("auto_tune=1: tachyon-core may switch away from these parameters at runtime")
    try:
        canon = tcp_engine.canonicalize(params)
        reason = tcp_engine.check(canon)
    except StrategyError as e:
        canon, reason = None, str(e)
    if reason is not None:
        notes.append(f"not expressible as a fixed ADF strategy ({reason}); measured as the raw outbound")
        canon = None
    return ImportedSection(sid, "fixed", canon, auto_tune, ob, ignored, notes)


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
            cmds.append(f"uci -q delete {config}.{section}.{opt} || true")  # absent option: non-zero exit under set -e
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
    inactive = inactive_desync_sources(cfg)
    if section in inactive:
        raise ValueError(f"outbound source '{section}' has no effect on tachyon-core ({inactive[section]}); "
                         "apply to the section that owns the options instead")
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
        return self.transport.shell(SHOW_DESYNC_CMD)

    def save_full_backup(self) -> str:
        """Full ``uci export`` copy kept on the router (tmpfs is not used: survives reboot)."""
        path = f"/etc/tachyon/adf-backup-{int(time.time())}.uci"
        self.transport.shell(f"mkdir -p /etc/tachyon && uci export {CONFIG} > {shlex.quote(path)} && chmod 600 "
                             f"{shlex.quote(path)} && echo {shlex.quote(path)}")
        return path

    def run(self, script: str) -> str:
        return self.transport.shell("sh -s", stdin=script)
