"""bol-van/zapret v1 ``nfqws`` strategy model (classic --dpi-desync flags).

Fooling keywords are exactly those of ``parse_fooling()`` in ``nfq/nfqws.c``:
none md5sig ts badsum badseq datanoack hopbyhop hopbyhop2. ``badack`` is *not* a
v1 fooling keyword.
"""

from __future__ import annotations

import re
from typing import Any, List, Mapping, Optional, Tuple

from .base import Capabilities, Engine, Factor, Params, StrategyError

SPLITS = ("none", "multisplit", "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit")
FAKING = frozenset({"fakedsplit", "fakeddisorder", "hostfakesplit"})
V1_FOOLINGS = ("none", "md5sig", "ts", "badsum", "badseq", "datanoack", "hopbyhop", "hopbyhop2")
FOOLINGS = ("none", "md5sig", "ts", "badsum", "badseq", "datanoack", "md5sig,badsum", "badseq,badsum", "hopbyhop2")
POSITIONS = ("1", "2", "midsld", "sniext+1", "host+1", "endhost-1", "sld+1", "1,midsld", "1,sniext+1,midsld",
             "1,sld+1,endsld-2")
_MARKER_RE = re.compile(r"^(-?\d+|(method|host|endhost|sld|endsld|midsld|sniext)([+-]\d+)?)$")


def _has_fake(p: Mapping[str, Any]) -> bool:
    return bool(p.get("fake")) or p.get("split") in FAKING


class Zapret(Engine):
    name = "zapret"
    title = "zapret v1 nfqws"
    probe_supported = True  # through Tachyon's fuzzer probe (explicit permission required)

    def __init__(self, families=("ipv4",)):
        self.families = tuple(families)

    def factors(self, caps: Optional[Capabilities] = None) -> List[Factor]:
        foolings = [f for f in FOOLINGS if "hopbyhop" not in f or self.families == ("ipv6",)]
        return [
            Factor("fake", (False, True), False, "fake packet", cost=lambda v: 1.0 if v else 0.0),
            Factor("split", SPLITS, "none", "split mode",
                   cost=lambda v: {"none": 0, "multisplit": 1, "multidisorder": 1.5}.get(v, 2.5)),
            Factor("pos", POSITIONS, "midsld", "split positions",
                   applies=lambda p: p.get("split") != "none", cost=lambda v: 0.75 * (len(str(v).split(",")) - 1)),
            Factor("fooling", tuple(foolings), "none", "fooling", applies=_has_fake,
                   cost=lambda v: 0.0 if v == "none" else float(len(str(v).split(",")))),
            Factor("ttl", (0, 2, 3, 4, 5, 6, 8), 0, "--dpi-desync-ttl (0 = unset)", applies=_has_fake, ordered=True,
                   cost=lambda v: 0.5 if int(v) else 0.0),
            Factor("repeats", (1, 2, 4, 6, 8, 11), 1, "--dpi-desync-repeats", applies=_has_fake, ordered=True,
                   cost=lambda v: 0.15 * (int(v) - 1)),
            Factor("seqovl", (0, 1, 2), 0, "--dpi-desync-split-seqovl",
                   applies=lambda p: p.get("split") in ("multisplit", "multidisorder"), ordered=True,
                   cost=lambda v: 1.0 if int(v) else 0.0),
            Factor("fake_sni", ("", "www.google.com", "max.ru", "gosuslugi.ru", "fonts.google.com"), "",
                   "--dpi-desync-fake-tls-mod=sni=", applies=lambda p: bool(p.get("fake"))),
        ]

    def default_capabilities(self) -> Capabilities:
        return Capabilities(engine=self.name, source="profile:zapret-c4d0b19")

    def normalize_value(self, name: str, value: Any) -> Any:
        if name == "fake":
            return bool(value) if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
        if name in ("ttl", "repeats", "seqovl"):
            return int(value)
        return value

    def check(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Optional[str]:
        if not params.get("fake") and params.get("split", "none") == "none":
            return "strategy does nothing"
        for f in str(params.get("fooling", "none")).split(","):
            if f not in V1_FOOLINGS:
                return f"'{f}' is not an nfqws v1 fooling keyword"
        if "hopbyhop" in str(params.get("fooling", "")) and self.families != ("ipv6",):
            return "hopbyhop is IPv6-only"
        pos = params.get("pos")
        if pos is not None:
            items = str(pos).split(",")
            for item in items:
                if not _MARKER_RE.match(item):
                    return f"invalid marker '{item}' (v1 markers: method,host,endhost,sld,endsld,midsld,sniext)"
            seqovl = int(params.get("seqovl", 0) or 0)
            if seqovl and items[0].isdigit() and seqovl >= int(items[0]):
                return "seqovl must be smaller than the first split position"
        if _has_fake(params) and params.get("fooling", "none") == "none" and not int(params.get("ttl", 0) or 0):
            return "fakes need fooling or a TTL"
        return None

    def render(self, params: Mapping[str, Any]) -> str:
        modes = []
        if params.get("fake"):
            modes.append("fake")
        if params.get("split", "none") != "none":
            modes.append(params["split"])
        parts = ["--dpi-desync=" + ",".join(modes)]
        if "pos" in params:
            parts.append(f"--dpi-desync-split-pos={params['pos']}")
        if params.get("seqovl"):
            parts.append(f"--dpi-desync-split-seqovl={params['seqovl']}")
        if _has_fake(params):
            if params.get("fooling", "none") != "none":
                parts.append(f"--dpi-desync-fooling={params['fooling']}")
            if params.get("ttl"):
                parts.append(f"--dpi-desync-ttl={params['ttl']}")
            if int(params.get("repeats", 1)) > 1:
                parts.append(f"--dpi-desync-repeats={params['repeats']}")
        if params.get("fake_sni"):
            parts.append(f"--dpi-desync-fake-tls-mod=sni={params['fake_sni']}")
        return " ".join(parts)

    def parse(self, text: str) -> Params:
        params: Params = {"fake": False, "split": "none"}
        for token in text.split():
            key, _, value = token.partition("=")
            if key == "--dpi-desync":
                for m in value.split(","):
                    if m == "fake":
                        params["fake"] = True
                    elif m in SPLITS:
                        params["split"] = m
                    else:
                        raise StrategyError(f"desync mode '{m}' is outside the modelled space")
            elif key == "--dpi-desync-split-pos":
                params["pos"] = value
            elif key == "--dpi-desync-split-seqovl":
                params["seqovl"] = int(value)
            elif key == "--dpi-desync-fooling":
                params["fooling"] = value
            elif key == "--dpi-desync-ttl":
                params["ttl"] = int(value)
            elif key == "--dpi-desync-repeats":
                params["repeats"] = int(value)
            elif key == "--dpi-desync-fake-tls-mod" and value.startswith("sni="):
                params["fake_sni"] = value[4:]
            elif key.startswith("--filter-") or key in ("--new",):
                continue
            else:
                raise StrategyError(f"option '{key}' is outside the modelled space")
        return params

    def seeds(self, caps: Optional[Capabilities] = None) -> List[Tuple[str, Params]]:
        raw = [
            ("z1 fake,multisplit md5sig sld+1", {"fake": True, "split": "multisplit", "pos": "sld+1", "fooling": "md5sig"}),
            ("z1 fake ts repeats=6", {"fake": True, "fooling": "ts", "repeats": 6}),
            ("z1 fake,multidisorder badseq 1,midsld", {"fake": True, "split": "multidisorder", "pos": "1,midsld",
                                                      "fooling": "badseq"}),
            ("z1 multidisorder chain", {"split": "multidisorder", "pos": "1,sld+1,endsld-2"}),
            ("z1 fake,fakedsplit badsum 1", {"fake": True, "split": "fakedsplit", "pos": "1", "fooling": "badsum",
                                            "repeats": 6}),
        ]
        out = []
        for name, p in raw:
            c = self.canonicalize(p, caps)
            if self.check(c, caps) is None:
                out.append((name, c))
        return out
