"""Resolving the way the live engine does, and a second resolver to compare with.

Clients behind Tachyon get FakeIP answers, and the core then connects to whatever its own DNS server
returns. Another resolver can return another address of the same CDN, and a strategy can work on one
and fail on the other: on a Flint 2 AliDNS gave redirector.googlevideo.com 64.233.161.198, which failed
with every strategy tried, while Yandex and Google gave 142.251.127.198, which passed 20/20.

So a temporary engine is started with the live DNS server copied from the core's config, which covers
every server type the core knows, and with an independent server for the comparison. Queries reach it
over TCP on one connection per server.
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any, Dict, List, Mapping, Optional

from .hello import Stream, read_exact

A = 1
AAAA = 28
QUERY_TIMEOUT_S = 6.0
FALLBACK_SERVER = "77.88.8.8"   # same resolver Tachyon's fuzzer configures
AUTO = "auto"

LIVE_TAG = "adf-live"
CHECK_TAG = "adf-check"
BOOTSTRAP_TAG = "adf-bootstrap"

# By address, so the comparison depends on no other resolver; the first one the core does not use is taken.
CHECK_SERVERS = (("8.8.8.8", "dns.google"), ("77.88.8.8", "common.dot.dns.yandex.net"))
KINDS = {"https": "DoH", "h3": "DoH3", "tls": "DoT", "quic": "DoQ", "udp": "UDP", "tcp": "TCP"}


def query(host: str, qtype: int) -> bytes:
    name = b"".join(bytes([len(part)]) + part.encode("idna") for part in host.strip(".").split("."))
    return struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + name + b"\0" + struct.pack(">HH", qtype, 1)


def _skip_name(message: bytes, offset: int) -> int:
    while True:
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xc0 == 0xc0:
            return offset + 2
        offset += length + 1


def addresses(message: bytes) -> List[str]:
    """The A and AAAA records of an answer, in order. CNAME records are skipped."""
    out: List[str] = []
    try:
        if message[3] & 0x0f:
            return out
        questions, answers = struct.unpack(">HH", message[4:8])
        offset = 12
        for _ in range(questions):
            offset = _skip_name(message, offset) + 4
        for _ in range(answers):
            offset = _skip_name(message, offset)
            kind, _, _, length = struct.unpack(">HHIH", message[offset:offset + 10])
            offset += 10
            if kind in (A, AAAA):
                out.append(str(ipaddress.ip_address(message[offset:offset + length])))
            offset += length
    except (IndexError, ValueError, struct.error):
        return out
    return out


def ask(stream: Stream, host: str, qtype: int, timeout: float = QUERY_TIMEOUT_S) -> List[str]:
    message = query(host, qtype)
    stream.send(struct.pack(">H", len(message)) + message)
    head = read_exact(stream, 2, timeout)
    if len(head) < 2:
        raise ConnectionError("no DNS answer")
    return addresses(read_exact(stream, struct.unpack(">H", head)[0], timeout))


def _name(server: Mapping[str, Any]) -> str:
    return str((server.get("tls") or {}).get("server_name") or server.get("server") or "")


def describe(server: Optional[Mapping[str, Any]]) -> str:
    if not server:
        return ""
    return f"{KINDS.get(str(server.get('type')), server.get('type'))} {_name(server)}"


def check_server(live: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    used = {str(live.get("server")), _name(live)}
    for ip, name in CHECK_SERVERS:
        if ip not in used and name not in used:
            return {"type": "https", "tag": CHECK_TAG, "server": ip, "server_port": 443, "path": "/dns-query",
                    "tls": {"enabled": True, "server_name": name}}
    return None


def resolver_config(live: Mapping[str, Any], bootstrap: Optional[Mapping[str, Any]],
                    check: Optional[Mapping[str, Any]], port: int, routing_mark: Optional[int]) -> Dict[str, Any]:
    """A core that answers DNS on ``port`` from the live server, and on ``port + 1`` from the check server."""
    first = dict(bootstrap or {"type": "udp", "server": FALLBACK_SERVER}, tag=BOOTSTRAP_TAG)
    main = dict(live, tag=LIVE_TAG)
    first.pop("detour", None)       # the outbounds of the live config do not exist here
    main.pop("detour", None)
    if "domain_resolver" in main:
        main["domain_resolver"] = BOOTSTRAP_TAG
    servers = [first, main]
    inbounds = [{"type": "direct", "tag": "adf-live-in", "listen": "127.0.0.1", "listen_port": port}]
    rules = [{"inbound": "adf-live-in", "action": "route", "server": LIVE_TAG, "disable_cache": True}]
    if check:
        servers.append(dict(check))
        inbounds.append({"type": "direct", "tag": "adf-check-in", "listen": "127.0.0.1", "listen_port": port + 1})
        rules.append({"inbound": "adf-check-in", "action": "route", "server": CHECK_TAG, "disable_cache": True})
    outbound: Dict[str, Any] = {"type": "direct", "tag": "adf-out"}
    if routing_mark is not None:
        outbound["routing_mark"] = routing_mark
    tags = [i["tag"] for i in inbounds]
    return {
        "log": {"level": "error"},
        "dns": {"servers": servers, "rules": rules, "final": LIVE_TAG},
        "inbounds": inbounds,
        "outbounds": [outbound],
        "route": {"rules": [{"action": "sniff", "inbound": tags}, {"action": "hijack-dns", "inbound": tags}],
                  "final": "adf-out", "default_domain_resolver": BOOTSTRAP_TAG},
    }
