"""tachyon-core Native Desync (``"type": "desync"`` outbound).

Grammar sources (see docs/research/tachyon-fuzzer-audit.md):

* tachyon ``usr/lib/config/connections.uc`` – the UCI → core translator. This is
  what decides which values survive when a strategy is applied through Tachyon,
  so the export grammar here is restricted to what it understands.
* tachyon-core public source ``outbound/desync/config.rs`` – an older subset.
* tachyon-core CHANGELOG 0.2.2–0.3.0 – features of the shipped binary.

The real set of accepted values is detected on the router (``adf-agent caps``);
the profiles below are only the starting assumption.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .base import Capabilities, Engine, Factor, Params, StrategyError, filter_values

MODES = (
    "split",
    "tlsrec",
    "disorder",
    "oob",
    "fake",
    "fake_split",
    "fake_disorder",
    "multi_split",
    "multi_disorder",
)
FAKE_MODES = frozenset({"fake", "fake_split", "fake_disorder", "multi_disorder"})
SPLIT_MODES = frozenset(m for m in MODES if m != "fake")
MULTI_MODES = frozenset({"multi_split", "multi_disorder"})
SEQOVL_MODES = frozenset({"split", "disorder", "fake_split", "fake_disorder", "multi_split", "multi_disorder"})

MODE_COST = {
    "split": 1.0,
    "tlsrec": 1.0,
    "disorder": 1.5,
    "oob": 1.5,
    "fake": 2.0,
    "fake_split": 2.5,
    "fake_disorder": 3.0,
    "multi_split": 2.5,
    "multi_disorder": 3.5,
}

# Mode simplification graph: dropping one technique from a compound mode.
MODE_SIMPLER = {
    "fake_split": ("split", "fake"),
    "fake_disorder": ("disorder", "fake", "fake_split"),
    "multi_disorder": ("fake_disorder", "multi_split"),
    "multi_split": ("split", "tlsrec"),
    "disorder": ("split",),
    "oob": ("split",),
}

FOOLINGS = (
    "",
    "md5",
    "badsum",
    "badseq",
    "badack",
    "timestamp",
    "datanoack",
    "autottl",
    "md5_badack",
    "badseq_badack_badsum",
    "hopbyhop",
)
FOOLING_COST = {"": 0.0, "md5_badack": 2.0, "badseq_badack_badsum": 3.0}

# Position markers understood by connections.uc norm_single_split_pos (plus ints).
POS_MARKERS = ("midsld", "midsld-2", "midsld+2", "sni", "sniext+1", "host+1", "endhost-1", "extlen")
SINGLE_POSITIONS: Tuple[str, ...] = (
    "1", "2", "3", "5", "midsld", "midsld-2", "midsld+2", "sni", "sniext+1", "host+1", "endhost-1", "extlen",
)
MULTI_POSITIONS: Tuple[str, ...] = (
    "1,midsld",
    "1,sniext+1,midsld",
    "sniext+1,midsld",
    "2,midsld",
    "1,host+1",
    "host+1,endhost-1",
    "1,sni,midsld",
    "1,midsld,endhost-1",
)

WHITELIST_SNI = (
    "", "www.google.com", "ya.ru", "vk.com", "max.ru", "gosuslugi.ru", "sberbank.ru", "tbank.ru", "ozon.ru",
    "wildberries.ru", "rutube.ru", "dzen.ru", "avito.ru", "rzd.ru", "pochta.ru", "2gis.ru", "mail.ru", "rndsni",
)

# Aliases accepted by tachyon connections.uc (norm_mode / norm_fooling / norm_single_split_pos)
_MODE_ALIASES = {
    "fakesplit": "fake_split", "fake+split": "fake_split", "fakedsplit": "fake_split", "faked_split": "fake_split",
    "fakedisorder": "fake_disorder", "fake+disorder": "fake_disorder",
    "multidisorder": "multi_disorder", "multi+disorder": "multi_disorder", "fakeddisorder": "multi_disorder",
    "faked_disorder": "multi_disorder",
    "multisplit": "multi_split", "multi+split": "multi_split",
    "tls_rec": "tlsrec",
}
_FOOLING_ALIASES = {
    "none": "", "tcp_md5": "md5", "wrong-md5": "md5", "wrong_md5": "md5",
    "ts": "timestamp", "tcp_ts": "timestamp", "wrong-timestamp": "timestamp", "wrong_timestamp": "timestamp",
    "seq": "badseq", "wrong-sequence": "badseq", "wrong_sequence": "badseq",
    "ack": "badack", "tcp_ack": "badack", "wrong-ack": "badack", "wrong_ack": "badack",
    "sum": "badsum", "wrong-checksum": "badsum", "wrong_checksum": "badsum",
    "auto_ttl": "autottl", "ttl": "autottl", "low-ttl": "autottl", "low_ttl": "autottl",
    "ip6_hopbyhop": "hopbyhop", "hopbyhop2": "hopbyhop", "ip6_hopbyhop2": "hopbyhop", "destopt": "hopbyhop",
    "ip6_destopt": "hopbyhop",
    "combo": "badseq_badack_badsum", "badsum_combo": "badseq_badack_badsum",
    "tcp_md5_badack": "md5_badack", "md5+badack": "md5_badack",
    "data_no_ack": "datanoack", "noack": "datanoack",
}
_POS_ALIASES = {
    "sld": "midsld", "host": "midsld", "sld-2": "midsld-2", "sld+2": "midsld+2", "sniext": "sni",
    "sni+1": "sniext+1", "endsld-1": "endhost-1", "endhost": "endhost-1",
}

KEY_ORDER = (
    "mode", "split_pos", "fooling", "fake_ttl", "fake_sni", "repeats", "split_delay_ms", "seqovl", "syndata",
    "wsize", "ipfrag", "tlsrec_first", "udp_fake", "udp_repeats", "udp_fake_ttl", "udplen",
)
BOOL_KEYS = frozenset({"syndata", "ipfrag", "tlsrec_first", "udp_fake"})
INT_KEYS = frozenset({"fake_ttl", "repeats", "split_delay_ms", "seqovl", "wsize", "udp_repeats", "udp_fake_ttl", "udplen"})
UDP_KEYS = frozenset({"udp_fake", "udp_repeats", "udp_fake_ttl", "udplen"})
# Keys whose "off" value is the engine default and is left out of rendered output.
# fake_ttl / repeats / split_delay_ms are always explicit: core and UI defaults differ.
OMIT_WHEN_OFF = frozenset({"fooling", "fake_sni", "seqovl", "syndata", "wsize", "ipfrag", "tlsrec_first", "udplen"})

# tachyon-core values for keys a strategy string leaves out (public source config.rs ``Default``).
# A missing key is *not* "off": the core applies these. ADF's own strings always state them.
CORE_DEFAULTS = {"split_pos": "midsld", "fake_ttl": 6, "repeats": 1, "split_delay_ms": 1}

PROFILE_PUBLIC_SOURCE = "tachyon-core-public-source"
PROFILE_BINARY_03 = "tachyon-core-0.3"


def normalize_pos(value: Any) -> str:
    """Normalise a split position (single marker or comma list) to canonical text."""
    if isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        parts = str(value).split(",")
    out = []
    for part in parts:
        p = part.strip().lower()
        if not p:
            continue
        p = _POS_ALIASES.get(p, p)
        if p.isdigit():
            n = int(p)
            if not 1 <= n <= 1400:
                raise StrategyError(f"split_pos byte offset {n} outside 1..1400")
            p = str(n)
        elif p not in POS_MARKERS:
            raise StrategyError(f"split_pos marker '{part}' is not understood by Tachyon")
        out.append(p)
    if not out:
        raise StrategyError("empty split_pos")
    return ",".join(out)


def pos_count(pos: str) -> int:
    return len(pos.split(",")) if pos else 0


def _first_numeric_pos(pos: str) -> Optional[int]:
    first = pos.split(",")[0]
    return int(first) if first.isdigit() else None


class TachyonDesync(Engine):
    name = "tachyon_desync"
    title = "tachyon-core Native Desync"
    probe_supported = True

    def __init__(self, measure_udp: bool = False, families: Sequence[str] = ("ipv4",)):
        self.measure_udp = measure_udp
        self.families = tuple(families)

    # ------------------------------------------------------------- space
    def factors(self, caps: Optional[Capabilities] = None) -> List[Factor]:
        def fake(p: Mapping[str, Any]) -> bool:
            return p.get("mode") in FAKE_MODES

        def splits(p: Mapping[str, Any]) -> bool:
            return p.get("mode") in SPLIT_MODES

        foolings = [f for f in FOOLINGS if f != "hopbyhop" or self.families == ("ipv6",)]
        positions = list(SINGLE_POSITIONS) + list(MULTI_POSITIONS)
        fs = [
            Factor("mode", filter_values(MODES, caps, "mode"), "split", "desync technique",
                   cost=lambda v: MODE_COST.get(v, 3.0)),
            Factor("split_pos", filter_values(positions, caps, "split_pos"), "midsld", "split position(s)",
                   applies=splits, cost=lambda v: 0.75 * (pos_count(str(v)) - 1)),
            Factor("fooling", filter_values(foolings, caps, "fooling"), "", "fake packet fooling",
                   applies=fake, cost=lambda v: FOOLING_COST.get(v, 1.0)),
            Factor("fake_ttl", filter_values((2, 3, 4, 5, 6, 7, 8, 10, 12), caps, "fake_ttl"), 6, "fake TTL",
                   applies=fake, ordered=True),
            Factor("fake_sni", filter_values(WHITELIST_SNI, caps, "fake_sni"), "", "decoy SNI ('' = auto)",
                   applies=fake),
            Factor("repeats", filter_values((1, 2, 3, 4, 6, 8, 11), caps, "repeats"), 1, "fake repeats",
                   applies=fake, ordered=True, cost=lambda v: 0.15 * (int(v) - 1)),
            Factor("split_delay_ms", filter_values((0, 1, 2, 5, 10), caps, "split_delay_ms"), 0,
                   "delay between segments", applies=splits, ordered=True, cost=lambda v: 0.1 if int(v) else 0.0),
            Factor("seqovl", filter_values((0, 1, 2, 4), caps, "seqovl"), 0, "sequence overlap bytes",
                   applies=lambda p: p.get("mode") in SEQOVL_MODES, ordered=True,
                   cost=lambda v: 1.0 if int(v) else 0.0),
            Factor("syndata", (False, True), False, "payload in SYN", cost=lambda v: 1.0 if v else 0.0),
            Factor("wsize", filter_values((0, 1, 2), caps, "wsize"), 0, "TCP window clamp", ordered=True,
                   cost=lambda v: 1.0 if int(v) else 0.0),
            Factor("ipfrag", (False, True), False, "IP fragmentation", cost=lambda v: 1.0 if v else 0.0),
            Factor("tlsrec_first", (False, True), False, "TLS record split before mode",
                   applies=lambda p: p.get("mode") != "tlsrec", cost=lambda v: 1.0 if v else 0.0),
        ]
        if self.measure_udp:
            fs += [
                Factor("udp_fake", (False, True), False, "UDP fake burst", cost=lambda v: 0.5 if v else 0.0),
                Factor("udp_repeats", filter_values((1, 2, 3, 4, 6, 8), caps, "udp_repeats"), 3, "UDP fakes",
                       applies=lambda p: bool(p.get("udp_fake")), ordered=True,
                       cost=lambda v: 0.1 * (int(v) - 1)),
                Factor("udp_fake_ttl", filter_values((2, 3, 4, 5, 6, 8), caps, "udp_fake_ttl"), 6, "UDP fake TTL",
                       applies=lambda p: bool(p.get("udp_fake")), ordered=True),
                Factor("udplen", filter_values((0, 2, 4, 8, 25), caps, "udplen"), 0, "UDP length increment",
                       ordered=True, cost=lambda v: 1.0 if int(v) else 0.0),
            ]
        return [f for f in fs if caps is None or f.name not in caps.unsupported]

    def default_capabilities(self) -> Capabilities:
        return capability_profile(PROFILE_BINARY_03)

    def canonicalize(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Params:
        if not self.measure_udp:
            udp = sorted(k for k in params if k in UDP_KEYS)
            if udp:
                raise StrategyError(f"UDP parameters ({', '.join(udp)}) cannot be measured without QUIC targets")
        return super().canonicalize(params, caps)

    def normalize_value(self, name: str, value: Any) -> Any:
        if name == "mode":
            v = str(value).strip().lower()
            return _MODE_ALIASES.get(v, v)
        if name == "fooling":
            v = str(value or "").strip().lower()
            return _FOOLING_ALIASES.get(v, v)
        if name == "split_pos":
            return normalize_pos(value)
        if name in BOOL_KEYS:
            return _to_bool(value)
        if name in INT_KEYS:
            return int(value)
        if name == "fake_sni":
            return str(value or "").strip().lower()
        return value

    # -------------------------------------------------------- validation
    def check(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Optional[str]:
        mode = params.get("mode")
        if mode not in MODES:
            return f"unknown mode '{mode}'"
        for key in params:
            if key not in KEY_ORDER:
                return f"unknown key '{key}'"
            if key in UDP_KEYS and not self.measure_udp:
                return "UDP parameters cannot be measured without QUIC targets"
        if caps is not None:
            for key, value in params.items():
                if not caps.accepts(key, value):
                    return f"'{key}={value}' not accepted by {caps.source}"
        pos = params.get("split_pos")
        if pos is not None:
            try:
                pos = normalize_pos(pos)
            except StrategyError as e:
                return str(e)
            if pos_count(pos) > 1 and mode not in MULTI_MODES:
                return f"mode {mode} uses a single split position"
            if mode in MULTI_MODES and pos_count(pos) < 2:
                return f"mode {mode} needs at least two split positions"
        fooling = params.get("fooling", "")
        if fooling and fooling not in FOOLINGS:
            return f"unknown fooling '{fooling}'"
        if fooling == "hopbyhop" and self.families != ("ipv6",):
            return "hopbyhop fooling is IPv6-only"
        ttl = params.get("fake_ttl")
        if ttl is not None and not 1 <= int(ttl) <= 128:
            return "fake_ttl outside 1..128"
        reps = params.get("repeats")
        if reps is not None and not 1 <= int(reps) <= 20:
            return "repeats outside 1..20 (Tachyon UI range)"
        delay = params.get("split_delay_ms")
        if delay is not None and not 0 <= int(delay) <= 1000:
            return "split_delay_ms outside 0..1000"
        # Assumption (zapret semantics): disorder variants need seqovl < first split position.
        seqovl = int(params.get("seqovl", 0) or 0)
        if seqovl and pos is not None and "disorder" in str(mode):
            first = _first_numeric_pos(pos)
            if first is not None and seqovl >= first:
                return "disorder: seqovl must be smaller than the first split position"
        sni = params.get("fake_sni", "")
        if sni and sni != "rndsni" and not re.fullmatch(r"[a-z0-9.-]{1,253}", sni):
            return f"invalid fake_sni '{sni}'"
        return None

    # ------------------------------------------------------------ syntax
    def render(self, params: Mapping[str, Any]) -> str:
        """Render as a Tachyon ``desync_opts`` string (connections.uc grammar)."""
        parts = []
        for key in KEY_ORDER:
            if key not in params:
                continue
            value = params[key]
            if key in OMIT_WHEN_OFF and not value:
                continue
            if isinstance(value, bool):
                value = "1" if value else "0"
            parts.append(f"{key}={value}")
        return " ".join(parts)

    def parse(self, text: str) -> Params:
        params: Params = {}
        for token in text.split():
            if "=" not in token:
                raise StrategyError(f"token '{token}' is not key=value")
            key, value = token.split("=", 1)
            key = key.strip().lower()
            if key.startswith("--"):
                key = key[2:].replace("-", "_")
            if key.startswith("dpi_desync_"):
                key = key[len("dpi_desync_"):]
            elif key == "dpi_desync":
                key = "mode"
            if key == "ttl":
                key = "fake_ttl"
            if key == "split_seqovl":
                key = "seqovl"
            if key in ("auto_tune", "preset"):
                if key == "preset":
                    params.update(preset_params(value))
                continue
            if key not in KEY_ORDER:
                raise StrategyError(f"unknown key '{key}'")
            params[key] = self.normalize_value(key, value)
        if "mode" not in params:
            raise StrategyError("strategy has no mode")
        for key, value in CORE_DEFAULTS.items():
            params.setdefault(key, value)
        return params

    def outbound(self, params: Mapping[str, Any], tag: str = "adf-desync", routing_mark: Optional[int] = None,
                 explicit_auto_tune: bool = True) -> Dict[str, Any]:
        """tachyon-core JSON outbound object for this strategy."""
        ob: Dict[str, Any] = {"type": "desync", "tag": tag}
        for key in KEY_ORDER:
            if key not in params:
                continue
            value = params[key]
            if key in OMIT_WHEN_OFF and not value:
                continue
            if key == "split_pos":
                items = [int(p) if p.isdigit() else p for p in str(value).split(",")]
                value = items[0] if len(items) == 1 else items
            ob[key] = value
        if explicit_auto_tune:
            ob["auto_tune"] = False
        if routing_mark is not None:
            ob["routing_mark"] = routing_mark
        return ob

    # -------------------------------------------------------- heuristics
    def simplifications(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> List[Params]:
        out = list(super().simplifications(params, caps))
        mode = params.get("mode")
        for simpler in MODE_SIMPLER.get(mode, ()):
            cand = dict(params)
            cand["mode"] = simpler
            if simpler not in MULTI_MODES and pos_count(str(cand.get("split_pos", ""))) > 1:
                for p in str(cand["split_pos"]).split(","):
                    c2 = dict(cand)
                    c2["split_pos"] = p
                    out.append(c2)
            else:
                out.append(cand)
        pos = str(params.get("split_pos", ""))
        if pos_count(pos) > 2:
            items = pos.split(",")
            for i in range(len(items)):
                cand = dict(params)
                cand["split_pos"] = ",".join(items[:i] + items[i + 1:])
                out.append(cand)
        return self._valid_unique(out, caps)

    def seeds(self, caps: Optional[Capabilities] = None) -> List[Tuple[str, Params]]:
        raw = [
            # tachyon-core built-in presets expressed explicitly (config.rs preset defaults)
            ("core preset fake_split", "mode=fake_split split_pos=midsld fake_ttl=6 repeats=1 split_delay_ms=1"),
            ("core preset split", "mode=split split_pos=midsld split_delay_ms=1"),
            ("core preset disorder", "mode=disorder split_pos=1"),
            ("core preset tlsrec", "mode=tlsrec split_pos=sni split_delay_ms=1"),
            ("core preset fake", "mode=fake fake_ttl=6 repeats=1"),
            ("core preset oob", "mode=oob split_pos=1"),
            # Tachyon STRATEGIES_DESYNC (fuzzer/strategies.uc)
            ("tachyon fake_split midsld ttl4 max.ru", "mode=fake_split split_pos=midsld fake_ttl=4 fake_sni=max.ru repeats=6"),
            ("tachyon fake_split midsld ttl6 google", "mode=fake_split split_pos=midsld fake_ttl=6 fake_sni=www.google.com repeats=6"),
            ("tachyon fake_split sni ttl5 gosuslugi", "mode=fake_split split_pos=sni fake_ttl=5 fake_sni=gosuslugi.ru repeats=6"),
            ("tachyon fake_split 1 ttl4 sber", "mode=fake_split split_pos=1 fake_ttl=4 fake_sni=sberbank.ru repeats=6"),
            ("tachyon fake_split 2 ttl8 max.ru", "mode=fake_split split_pos=2 fake_ttl=8 fake_sni=max.ru repeats=8"),
            ("tachyon tlsrec midsld", "mode=tlsrec split_pos=midsld split_delay_ms=2"),
            ("tachyon tlsrec 2", "mode=tlsrec split_pos=2 split_delay_ms=1"),
            ("tachyon disorder midsld", "mode=disorder split_pos=midsld"),
            ("tachyon split sni 2ms", "mode=split split_pos=sni split_delay_ms=2"),
            ("tachyon oob midsld", "mode=oob split_pos=midsld"),
            # Tachyon UI defaults shown on the user's screenshots
            ("ui default fake_split", "mode=fake_split split_pos=1 fake_ttl=6 fake_sni=max.ru repeats=6 split_delay_ms=2"),
            ("ui multi_split 3-way", "mode=multi_split split_pos=1,sniext+1,midsld"),
            ("ui multi_disorder", "mode=multi_disorder split_pos=1,midsld fake_ttl=6 repeats=2"),
            ("ui fake_disorder md5", "mode=fake_disorder split_pos=midsld fooling=md5 fake_ttl=6 repeats=2"),
        ]
        out: List[Tuple[str, Params]] = []
        for name, text in raw:
            try:
                params = self.canonicalize(self.parse(text), caps)
            except StrategyError:
                continue
            if self.check(params, caps) is None:
                out.append((name, params))
        return out


def preset_params(preset: str) -> Params:
    """Explicit parameters of a tachyon-core preset (config.rs from_json)."""
    p = str(preset).strip().lower()
    p = {"fakesplit": "fake_split", "tls_rec": "tlsrec"}.get(p, p)
    table = {
        "fake_split": {"mode": "fake_split", "split_pos": "midsld", "fake_ttl": 6},
        "split": {"mode": "split", "split_pos": "midsld"},
        "disorder": {"mode": "disorder", "split_pos": "1"},
        "tlsrec": {"mode": "tlsrec", "split_pos": "sni"},
        "fake": {"mode": "fake", "fake_ttl": 6},
        "oob": {"mode": "oob", "split_pos": "1"},
        "fake_disorder": {"mode": "fake_disorder", "split_pos": "midsld"},
        "multi_split": {"mode": "multi_split", "split_pos": "1,sniext+1,midsld"},
        "multi_disorder": {"mode": "multi_disorder", "split_pos": "1,midsld"},
    }
    if p in ("auto", "adaptive", "smart"):
        raise StrategyError("preset=auto (Adaptive 2.0) is not a fixed strategy; it is measured as a baseline")
    if p not in table:
        raise StrategyError(f"unknown preset '{preset}'")
    return dict(table[p])


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    v = str(value).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off", ""):
        return False
    raise StrategyError(f"invalid boolean '{value}'")


def capability_profile(profile: str) -> Capabilities:
    if profile == PROFILE_PUBLIC_SOURCE:
        ints = {str(i) for i in range(1, 1401)}
        return Capabilities(
            engine=TachyonDesync.name,
            source=f"profile:{profile}",
            allowed={
                "mode": {"split", "tlsrec", "disorder", "oob", "fake", "fake_split"},
                "split_pos": ints | {"midsld", "sni"},
            },
            unsupported={"fooling", "seqovl", "syndata", "wsize", "ipfrag", "tlsrec_first", "udplen"},
            version="public-source",
        )
    if profile == PROFILE_BINARY_03:
        return Capabilities(engine=TachyonDesync.name, source=f"profile:{profile} (unverified)", version="0.3.x")
    raise ValueError(f"unknown capability profile {profile}")


def capabilities_from_probe(data: Mapping[str, Any]) -> Capabilities:
    """Build capabilities from ``adf-agent caps`` output.

    ``data`` = {"version": str, "results": [{"key": k, "value": v, "ok": bool}, ...]}
    A factor whose every tested value was rejected is marked unsupported.
    """
    allowed: Dict[str, set] = {}
    rejected: Dict[str, set] = {}
    for item in data.get("results", []):
        key, value, ok = item["key"], item["value"], bool(item["ok"])
        if key == "split_pos":
            try:
                value = normalize_pos(value)
            except StrategyError:
                continue
        (allowed if ok else rejected).setdefault(key, set()).add(_coerce(key, value))
    caps = Capabilities(engine=TachyonDesync.name, source=f"probed:{data.get('host', 'router')}",
                        version=str(data.get("version", "")))
    for key, bad in rejected.items():
        if key not in allowed:
            caps.unsupported.add(key)
    for key, good in allowed.items():
        if key in rejected:
            if key == "split_pos":
                # Keep positions accepted individually; lists accepted iff each item accepted.
                singles = {p for p in good if "," not in p}
                good = set(good)
                for lst in MULTI_POSITIONS:
                    if all(p in singles for p in lst.split(",")) and lst not in rejected.get(key, set()):
                        good.add(lst)
                good |= {str(i) for i in range(1, 1401)} if "1" in singles else set()
            caps.allowed[key] = good
    return caps


def _coerce(key: str, value: Any) -> Any:
    if key in INT_KEYS:
        return int(value)
    if key in BOOL_KEYS:
        return _to_bool(value)
    return value


def caps_test_matrix() -> List[Dict[str, Any]]:
    """Parameter/value pairs the agent feeds to ``tachyon-core check``.

    Each entry is a full outbound object differing from a known-good base in
    exactly one key, so a rejection is attributable to that key.
    """
    base = {"type": "desync", "tag": "caps", "mode": "split", "split_pos": "midsld"}
    tests: List[Dict[str, Any]] = []

    def add(key: str, value: Any, extra: Optional[Dict[str, Any]] = None) -> None:
        ob = dict(base)
        if extra:
            ob.update(extra)
        ob[key] = value
        tests.append({"key": key, "value": value, "outbound": ob})

    for m in MODES:
        add("mode", m, {"split_pos": [1, "midsld"]} if m in MULTI_MODES else None)
    for p in SINGLE_POSITIONS:
        add("split_pos", int(p) if p.isdigit() else p)
    add("split_pos", [1, "midsld"], {"mode": "multi_split"})
    for f in FOOLINGS[1:]:
        add("fooling", f, {"mode": "fake_split"})
    add("fake_sni", "rndsni", {"mode": "fake_split"})
    for key, value in (("seqovl", 1), ("syndata", True), ("wsize", 1), ("ipfrag", True),
                       ("tlsrec_first", True), ("udplen", 4), ("auto_tune", False)):
        add(key, value)
    return tests


def dumps_outbound(ob: Mapping[str, Any]) -> str:
    return json.dumps(ob, ensure_ascii=False, sort_keys=False)
