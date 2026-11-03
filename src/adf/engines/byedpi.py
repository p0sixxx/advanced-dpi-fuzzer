"""hufrea/byedpi ``ciadpi`` strategy model.

Position syntax (``parse_offset`` in main.c): ``offset[:repeats[:skip]][+flag[mod]]``
with flag ``s`` (SNI), ``h`` (Host), ``n`` (none) and mod ``e`` (end), ``m`` (mid),
``r`` (rand), ``s`` (start). Marker names such as ``midsld`` are *not* accepted.
``--auto`` events are ``t r s c n`` plus ``p=<float>``.
"""

from __future__ import annotations

import re
import shlex
from typing import Any, List, Mapping, Optional, Tuple

from .base import Capabilities, Engine, Factor, Params, StrategyError

METHODS = ("split", "disorder", "oob", "disoob", "fake")
FLAG = {"split": "-s", "disorder": "-d", "oob": "-o", "disoob": "-q", "fake": "-f"}
REVERSE_FLAG = {v: k for k, v in FLAG.items()}
REVERSE_FLAG.update({"--split": "split", "--disorder": "disorder", "--oob": "oob", "--disoob": "disoob", "--fake": "fake"})
POSITIONS = ("1", "2", "3", "0+s", "1+s", "0+sm", "-1", "1+h", "0+hm")
POS_RE = re.compile(r"^-?\d+(:\d+(:\d+)?)?(\+[shn][emrs]?)?$")


class ByeDPI(Engine):
    name = "byedpi"
    title = "ByeDPI ciadpi"
    probe_supported = True  # isolated SOCKS proxy, measured by adf-agent directly

    def factors(self, caps: Optional[Capabilities] = None) -> List[Factor]:
        return [
            Factor("method", METHODS, "split", "desync method",
                   cost=lambda v: {"split": 1.0, "disorder": 1.5, "oob": 1.5, "disoob": 2.0, "fake": 2.5}[v]),
            Factor("pos", POSITIONS, "1", "position"),
            Factor("ttl", (3, 4, 5, 6, 8, 10), 8, "fake TTL (-t)", applies=lambda p: p.get("method") == "fake",
                   ordered=True),
            Factor("md5sig", (False, True), False, "-S", applies=lambda p: p.get("method") == "fake",
                   cost=lambda v: 1.0 if v else 0.0),
            Factor("fake_sni", ("", "www.google.com", "max.ru", "gosuslugi.ru"), "", "-n",
                   applies=lambda p: p.get("method") == "fake"),
            Factor("tlsrec", ("", "1+s", "0+sm", "3"), "", "-r", cost=lambda v: 1.0 if v else 0.0),
        ]

    def default_capabilities(self) -> Capabilities:
        return Capabilities(engine=self.name, source="profile:byedpi-9887576")

    def normalize_value(self, name: str, value: Any) -> Any:
        if name == "ttl":
            return int(value)
        if name == "md5sig":
            return bool(value) if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes")
        return value

    def check(self, params: Mapping[str, Any], caps: Optional[Capabilities] = None) -> Optional[str]:
        if params.get("method") not in METHODS:
            return f"unknown method {params.get('method')}"
        for key in ("pos", "tlsrec"):
            v = params.get(key)
            if v and not POS_RE.match(str(v)):
                return f"'{v}' is not a ByeDPI position (offset[:r[:s]][+s|h|n[e|m|r|s]])"
        sni = params.get("fake_sni")
        if sni and not re.fullmatch(r"[a-z0-9.-]+", sni):
            return "invalid fake SNI"
        return None

    def render(self, params: Mapping[str, Any]) -> str:
        parts = [FLAG[params["method"]], str(params.get("pos", "1"))]
        if params.get("method") == "fake":
            parts += ["-t", str(params.get("ttl", 8))]
            if params.get("md5sig"):
                parts.append("-S")
            if params.get("fake_sni"):
                parts += ["-n", params["fake_sni"]]
        if params.get("tlsrec"):
            parts += ["-r", params["tlsrec"]]
        return " ".join(parts)

    def parse(self, text: str) -> Params:
        tokens = shlex.split(text)
        params: Params = {}
        i = 0
        while i < len(tokens):
            t = tokens[i]
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            if t in REVERSE_FLAG:
                if "method" in params:
                    raise StrategyError("several desync methods are outside the modelled space")
                params["method"] = REVERSE_FLAG[t]
                params["pos"] = nxt
                i += 2
            elif t in ("-t", "--ttl"):
                params["ttl"] = int(nxt)
                i += 2
            elif t in ("-S", "--md5sig"):
                params["md5sig"] = True
                i += 1
            elif t in ("-n", "--fake-sni"):
                params["fake_sni"] = nxt
                i += 2
            elif t in ("-r", "--tlsrec"):
                params["tlsrec"] = nxt
                i += 2
            elif t.startswith("--auto") or t == "-A":
                events = t.split("=", 1)[1] if "=" in t else (nxt or "")
                bad = [e for e in events.split(",") if e and e[0] not in "trscn" and not e.startswith("p=")]
                if bad:
                    raise StrategyError(f"invalid --auto event(s) {','.join(bad)} (ByeDPI accepts t,r,s,c,n,p=<n>)")
                raise StrategyError("--auto makes ByeDPI switch groups at runtime; only fixed strategies are measured")
            else:
                raise StrategyError(f"option '{t}' is outside the modelled space")
        if "method" not in params:
            raise StrategyError("no desync method")
        return params

    def seeds(self, caps: Optional[Capabilities] = None) -> List[Tuple[str, Params]]:
        raw = [
            ("bd split 1 + tlsrec 1+s", {"method": "split", "pos": "1", "tlsrec": "1+s"}),
            ("bd disorder 1", {"method": "disorder", "pos": "1"}),
            ("bd fake -1 ttl 6", {"method": "fake", "pos": "-1", "ttl": 6}),
            ("bd split 1+s fake", {"method": "fake", "pos": "1+s", "ttl": 6}),
            ("bd oob 1", {"method": "oob", "pos": "1"}),
        ]
        out = []
        for name, p in raw:
            c = self.canonicalize(p, caps)
            if self.check(c, caps) is None:
                out.append((name, c))
        return out


def argv(params: Mapping[str, Any], port: int) -> List[str]:
    return ["-i", "127.0.0.1", "-p", str(port)] + shlex.split(ByeDPI().render(params))
