"""Targets and probe results.

A *trial* is one HTTP(S) request or one large ClientHello to one target through one strategy. The verdict
taxonomy separates DPI symptoms from problems that a desync strategy cannot fix
(DNS, TCP reachability, server errors), so they are never counted against a
strategy.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

DEFAULT_OK_CODES: Tuple[int, ...] = tuple(range(200, 400)) + (401, 403, 404, 405, 421)

# Verdicts
OK = "ok"
DPI_VERDICTS = frozenset({
    "tls_timeout",      # TCP up, no ServerHello before timeout
    "tls_reset",        # reset / alert during handshake (curl 35)
    "recv_reset",       # reset while receiving (curl 56)
    "cutoff_16k",       # stream cut after 10–30 KB (TSPU signature)
    "transfer_timeout", # data started but stalled
    "throttled",        # below min_speed_kbps
    "short_body",       # fewer bytes than required
    "empty_reply",      # curl 52
    "tls_cert",         # certificate mismatch: wrong server / stub (curl 60)
    "content_mismatch", # body does not match expected content
    "server_rejected",  # HTTP 400: the fake reached the server
    "http_status",      # unexpected status
    "curl_error",
})
PATH_VERDICTS = frozenset({"dns_fail", "connect_failed", "proxy_error"})
SERVER_VERDICTS = frozenset({"server_error"})
LARGE_HELLO = "tls_large"      # probed by the controller, see probe/hello.py


@dataclass(frozen=True)
class Target:
    id: str
    url: str
    category: str = "custom"
    name: str = ""
    required: bool = True
    kind: str = "https"            # https | streaming | quic | tls_large
    min_bytes: int = 0
    range: Optional[str] = None
    ok_codes: Tuple[int, ...] = DEFAULT_OK_CODES
    body_regex: Optional[str] = None
    min_speed_kbps: float = 0.0
    families: Tuple[str, ...] = ("ipv4",)
    max_ips: int = 2
    weight: float = 1.0

    @property
    def host(self) -> str:
        m = re.match(r"^[a-z]+://([^/:]+)", self.url)
        return m.group(1) if m else ""

    def validate(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", self.id):
            raise ValueError(f"target id '{self.id}' must match [A-Za-z0-9_.-]{{1,64}}")
        if not re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d+)?(/[^\s]*)?", self.url):
            raise ValueError(f"target {self.id}: invalid url '{self.url}'")
        if self.kind not in ("https", "streaming", "quic", LARGE_HELLO):
            raise ValueError(f"target {self.id}: unknown kind {self.kind}")
        if self.range and not re.fullmatch(r"\d+-\d*", self.range):
            raise ValueError(f"target {self.id}: invalid range {self.range}")
        if self.body_regex and re.search(r"\s", self.body_regex):
            raise ValueError(f"target {self.id}: body_regex must not contain whitespace (use [[:space:]])")
        for fam in self.families:
            if fam not in ("ipv4", "ipv6"):
                raise ValueError(f"target {self.id}: unknown family {fam}")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ok_codes"] = list(self.ok_codes)
        d["families"] = list(self.families)
        return d


@dataclass
class ProbeResult:
    target: str
    family: str
    ip: str
    verdict: str
    http_code: int = 0
    curl_exit: int = 0
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_ms: float = 0.0
    bytes: int = 0
    speed_kbps: float = 0.0
    content_ok: Optional[bool] = None
    error: str = ""
    rep: int = 1

    @property
    def ok(self) -> bool:
        return self.verdict == OK

    @property
    def counts(self) -> bool:
        """Whether the trial is evidence about the strategy."""
        return self.verdict == OK or self.verdict in DPI_VERDICTS

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classify(raw: Mapping[str, Any], target: Target) -> ProbeResult:
    """Turn one ``adf-agent`` probe line into a :class:`ProbeResult`."""
    code = int(raw.get("code", 0) or 0)
    rc = int(raw.get("exit", 0) or 0)
    size = int(float(raw.get("size", 0) or 0))
    tc = float(raw.get("tc", 0) or 0)
    ta = float(raw.get("ta", 0) or 0)
    tf = float(raw.get("tf", 0) or 0)
    tt = float(raw.get("tt", 0) or 0)
    speed = float(raw.get("speed", 0) or 0) / 1024.0
    content = raw.get("content")
    content_ok = None if content is None else bool(int(content))

    def res(verdict: str) -> ProbeResult:
        return ProbeResult(
            target=target.id, family=str(raw.get("family", "")), ip=str(raw.get("ip", "") or raw.get("rip", "")),
            verdict=verdict, http_code=code, curl_exit=rc, connect_ms=tc * 1000, tls_ms=ta * 1000,
            ttfb_ms=tf * 1000, total_ms=tt * 1000, bytes=size, speed_kbps=round(speed, 2), content_ok=content_ok,
            error=str(raw.get("error", ""))[:300], rep=int(raw.get("rep", 1) or 1),
        )

    if rc in (0, 63):  # 63 = max filesize reached: we got at least 4 MB, fine
        if code in target.ok_codes:
            if size < target.min_bytes and code == 200:
                return res("cutoff_16k" if 10240 <= size <= 30720 else "short_body")
            if content_ok is False:
                return res("content_mismatch")
            if target.min_speed_kbps and size >= 65536 and speed < target.min_speed_kbps:
                return res("throttled")
            return res(OK)
        if code == 400:
            return res("server_rejected")
        if code >= 500:
            return res("server_error")
        return res("http_status")
    if rc == 6:
        return res("dns_fail")
    if rc in (5, 97):
        return res("proxy_error")
    if rc == 7:
        return res("connect_failed")
    if rc == 28:
        if ta == 0:
            return res("tls_timeout")
        if 10240 <= size <= 30720:
            return res("cutoff_16k")
        return res("transfer_timeout")
    if rc == 35:
        return res("tls_reset")
    if rc in (56, 18):
        if 10240 <= size <= 30720:
            return res("cutoff_16k")
        return res("recv_reset")
    if rc == 52:
        return res("empty_reply")
    if rc == 60:
        return res("tls_cert")
    return res("curl_error")


@dataclass
class BatchResult:
    """Outcome of running one strategy (or the baseline) over a target list."""

    ok: bool
    results: List[ProbeResult] = field(default_factory=list)
    engine_error: str = ""
    mem_avail_kb: int = 0

    @property
    def engine_failed(self) -> bool:
        return not self.ok and bool(self.engine_error)


def target_from_dict(d: Mapping[str, Any]) -> Target:
    kw = dict(d)
    if "ok_codes" in kw:
        kw["ok_codes"] = tuple(int(c) for c in kw["ok_codes"])
    if "families" in kw:
        kw["families"] = tuple(kw["families"])
    t = Target(**kw)
    t.validate()
    return t


def summarize_verdicts(results: Iterable[ProbeResult]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for r in results:
        out[r.verdict] = out.get(r.verdict, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))
