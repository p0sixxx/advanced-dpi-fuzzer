"""bol-van/zapret2 ``nfqws2`` strategy model (Lua desync functions).

Fooling in nfqws2 is passed as *direct* arguments of a desync function
(``:tcp_md5``, ``:badsum``, ``:tcp_seq=1000000``), read by ``apply_fooling()`` in
``lua/zapret-lib.lua``. A ``fooling=`` argument does not exist; Tachyon's presets
that use it send fakes without any fooling (see the audit).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .base import Capabilities, Engine, Factor, Params, StrategyError

SPLITS = ("none", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit")
FAKING_SPLITS = frozenset({"fakedsplit", "fakeddisorder", "hostfakesplit"})
SINGLE_POS_SPLITS = frozenset({"fakedsplit", "fakeddisorder"})

# fooling recipe id -> nfqws2 argument list
FOOLING_ARGS: Dict[str, Tuple[str, ...]] = {
    "none": (),
    "md5": ("tcp_md5",),
    "badsum": ("badsum",),
    "badseq": ("tcp_seq=1000000",),
    "badack": ("tcp_ack=-66000", "tcp_ts_up"),
    "ts": ("tcp_ts=-600000",),
    "ts_up": ("tcp_ts=-600000", "tcp_ts_up"),      # PAWS with timestamp moved first (Tachyon presets)
    "datanoack": ("tcp_flags_unset=ack",),
    "autottl": ("ip_autottl=-1,3-20",),
    "combo": ("tcp_seq=1000000", "tcp_ack=-66000", "tcp_ts_up", "badsum"),
    "hopbyhop2": ("ip6_hopbyhop", "ip6_hopbyhop2"),
}
FOOLING_COST = {"none": 0.0, "badack": 1.5, "ts_up": 1.5, "combo": 3.0, "hopbyhop2": 1.5}
POSITIONS = ("1", "2", "midsld", "sniext+1", "host+1", "endhost-1", "sld+1", "endsld-2", "1,midsld",
             "1,sniext+1,midsld", "1,sld+1,endsld-2")
# blob names: fake_default_tls is built into nfqws2; tls_* are installed by Tachyon (fuzzer.uc KNOWN_BLOB_FILES)
BLOBS = ("fake_default_tls", "tls_google", "tls_max", "tls_gosuslugi", "tls_sber")
_MARKER_RE = re.compile(r"^(-?\d+|(method|host|endhost|sld|endsld|midsld|sniext|extlen)([+-]\d+)?)$")


def _has_fake(p: Mapping[str, Any]) -> bool:
    return bool(p.get("fake")) or p.get("split") in FAKING_SPLITS


class Zapret2(Engine):
    name = "zapret2"
    title = "zapret2 nfqws2 (Lua)"
    probe_supported = True  # through Tachyon's own fuzzer probe (explicit permission required)

    def __init__(self, families=("ipv4",)):
        self.families = tuple(families)

    def factors(self, caps: Optional[Capabilities] = None) -> List[Factor]:
        foolings = [f for f in FOOLING_ARGS if f != "hopbyhop2" or self.families == ("ipv6",)]
        return [
            Factor("fake", (False, True), False, "separate fake packet", cost=lambda v: 1.0 if v else 0.0),
            Factor("fake_blob", BLOBS, "fake_default_tls", "fake payload blob", applies=lambda p: bool(p.get("fake"))),
            Factor("fake_repeats", (1, 2, 4, 6, 8, 11), 1, "fake repeats", applies=lambda p: bool(p.get("fake")),
                   ordered=True, cost=lambda v: 0.15 * (int(v) - 1)),
            Factor("fooling", tuple(foolings), "none", "fooling recipe", applies=_has_fake,
                   cost=lambda v: FOOLING_COST.get(v, 1.0)),
            Factor("fake_ttl", (0, 2, 3, 4, 5, 6, 8, 10), 0, "ip_ttl of fakes (0 = unchanged)", applies=_has_fake,
                   ordered=True, cost=lambda v: 0.5 if int(v) else 0.0),
            Factor("split", SPLITS, "none", "segmentation function",
                   cost=lambda v: {"none": 0, "multisplit": 1, "multidisorder": 1.5}.get(v, 2.5)),
            Factor("pos", POSITIONS, "midsld", "split markers",
                   applies=lambda p: p.get("split") not in ("none", "hostfakesplit"),
                   cost=lambda v: 0.75 * (len(str(v).split(",")) - 1)),
            Factor("seqovl", (0, 1, 2), 0, "seqovl", applies=lambda p: p.get("split") in ("multisplit", "multidisorder"),
                   ordered=True, cost=lambda v: 1.0 if int(v) else 0.0),
            Factor("seqovl_pattern", ("",) + BLOBS, "", "blob filling the seqovl part (default zeros)",
                   applies=lambda p: p.get("split") in ("multisplit", "multidisorder") and int(p.get("seqovl", 0) or 0) > 0),
        ]

    def default_capabilities(self) -> Capabilities:
        return Capabilities(engine=self.name, source="profile:zapret2-f924d79")

    def normalize_value(self, name: str, value: Any) -> Any:
        if name == "fake":
            return bool(value) if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
        if name in ("fake_repeats", "fake_ttl", "seqovl"):
            return int(value)
        return value

    def check(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Optional[str]:
        if not params.get("fake") and params.get("split", "none") == "none":
            return "strategy does nothing (no fake and no split)"
        if params.get("fooling", "none") not in FOOLING_ARGS:
            return f"unknown fooling recipe {params.get('fooling')}"
        if params.get("fooling") == "hopbyhop2" and self.families != ("ipv6",):
            return "ip6_hopbyhop is IPv6-only"
        if params.get("split", "none") not in SPLITS:
            return f"unknown split function {params.get('split')}"
        pos = params.get("pos")
        if pos is not None:
            items = str(pos).split(",")
            for item in items:
                if not _MARKER_RE.match(item):
                    return f"invalid marker '{item}'"
            if params.get("split") in SINGLE_POS_SPLITS and len(items) > 1:
                return f"{params.get('split')} uses a single split position"
            # multidisorder cancels seqovl >= first split pos (zapret-antidpi.lua multidisorder_send);
            # multisplit simply prepends seqovl bytes, any size.
            seqovl = int(params.get("seqovl", 0) or 0)
            if (seqovl and params.get("split") == "multidisorder" and items[0].isdigit()
                    and seqovl >= int(items[0])):
                return "multidisorder: seqovl must be smaller than the first split position"
        if _has_fake(params) and params.get("fooling", "none") == "none" and not int(params.get("fake_ttl", 0) or 0):
            return "fakes without fooling or TTL would reach the server"
        return None

    def render(self, params: Mapping[str, Any]) -> str:
        fool = list(FOOLING_ARGS[params.get("fooling", "none")]) if _has_fake(params) else []
        ttl = int(params.get("fake_ttl", 0) or 0)
        if ttl:
            fool.append(f"ip_ttl={ttl}")
        parts = ["--filter-tcp=443", "--filter-l7=tls", "--payload=tls_client_hello"]
        if params.get("fake"):
            args = [f"blob={params.get('fake_blob', 'fake_default_tls')}"]
            reps = int(params.get("fake_repeats", 1))
            if reps > 1:
                args.append(f"repeats={reps}")
            parts.append("--lua-desync=fake:" + ":".join(args + fool))
        split = params.get("split", "none")
        if split != "none":
            args = []
            if "pos" in params:
                args.append(f"pos={params['pos']}")
            seqovl = int(params.get("seqovl", 0) or 0)
            if seqovl:
                args.append(f"seqovl={seqovl}")
                if params.get("seqovl_pattern"):
                    args.append(f"seqovl_pattern={params['seqovl_pattern']}")
            if split in FAKING_SPLITS:
                args += fool
            parts.append(f"--lua-desync={split}" + ("".join(":" + a for a in args)))
        return " ".join(parts)

    def parse(self, text: str) -> Params:
        params: Params = {"fake": False, "split": "none"}
        fool_args: List[str] = []
        for token in text.split():
            if not token.startswith("--lua-desync="):
                continue
            body = token[len("--lua-desync="):]
            func, _, rest = body.partition(":")
            args = [a for a in rest.split(":") if a] if rest else []
            kv = {}
            for a in args:
                k, _, v = a.partition("=")
                kv[k] = v
                if k == "fooling":
                    raise StrategyError("'fooling=' is not an nfqws2 argument; pass fooling flags directly")
            if func == "fake":
                params["fake"] = True
                params["fake_blob"] = kv.get("blob", "fake_default_tls")
                params["fake_repeats"] = int(kv.get("repeats", 1))
            elif func in SPLITS:
                params["split"] = func
                if "pos" in kv:
                    params["pos"] = kv["pos"]
                if "seqovl" in kv:
                    params["seqovl"] = int(kv["seqovl"])
                if "seqovl_pattern" in kv:
                    params["seqovl_pattern"] = kv["seqovl_pattern"]
            else:
                raise StrategyError(f"function '{func}' is outside the modelled space")
            for a in args:
                k = a.partition("=")[0]
                if k in ("ip_ttl",):
                    params["fake_ttl"] = int(kv[k])
                elif k not in ("blob", "repeats", "pos", "seqovl", "seqovl_pattern"):
                    fool_args.append(a)
        if fool_args:
            uniq = tuple(dict.fromkeys(fool_args))
            for recipe, recipe_args in FOOLING_ARGS.items():
                if set(recipe_args) == set(uniq):
                    params["fooling"] = recipe
                    break
            else:
                raise StrategyError(f"fooling combination {uniq} is outside the modelled space")
        return params

    def seeds(self, caps: Optional[Capabilities] = None) -> List[Tuple[str, Params]]:
        raw = [
            ("z2 fake md5 + multisplit 1,midsld", {"fake": True, "fooling": "md5", "split": "multisplit", "pos": "1,midsld"}),
            ("z2 fake badsum + multidisorder 1,midsld", {"fake": True, "fooling": "badsum", "fake_repeats": 6,
                                                        "split": "multidisorder", "pos": "1,midsld"}),
            ("z2 fake ts + multisplit 1", {"fake": True, "fooling": "ts", "fake_repeats": 6, "split": "multisplit", "pos": "1"}),
            ("z2 fake badseq + multisplit 1,midsld seqovl=1", {"fake": True, "fooling": "badseq", "split": "multisplit",
                                                              "pos": "1,midsld", "seqovl": 0}),
            ("z2 hostfakesplit badsum", {"split": "hostfakesplit", "fooling": "badsum"}),
            ("z2 multisplit 1,sld+1,endsld-2", {"split": "multisplit", "pos": "1,sld+1,endsld-2"}),
        ]
        out = []
        for name, p in raw:
            c = self.canonicalize(p, caps)
            if self.check(c, caps) is None:
                out.append((name, c))
        return out
