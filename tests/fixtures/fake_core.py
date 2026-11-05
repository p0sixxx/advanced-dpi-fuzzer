#!/usr/bin/env python3
"""Stand-in for the tachyon-core binary used by the agent integration tests.

Implements ``version``, ``check -c <cfg>`` and ``run -c <cfg>`` with a working
SOCKS5 "mixed" inbound. A scripted DPI drops connections whose first client
payload carries a hostname listed in FAKE_CORE_BLOCK, or is exactly
FAKE_CORE_DROP_WHOLE_HELLO bytes long, unless the configured desync mode is
listed in FAKE_CORE_WORKS. FAKE_CORE_REJECT lists outbound keys the "binary"
refuses in ``check`` (capability probing tests).
"""

import json
import os
import select
import socket
import socketserver
import struct
import sys
import threading

KNOWN_MODES = {"split", "tlsrec", "disorder", "oob", "fake", "fake_split", "fake_disorder", "multi_split",
               "multi_disorder", "none"}


def load(path):
    with open(path) as fh:
        return json.load(fh)


def check(cfg):
    reject = {k for k in os.environ.get("FAKE_CORE_REJECT", "").split(",") if k}
    inb = cfg.get("inbounds", [])
    if not inb or inb[0].get("type") != "mixed":
        return "need a mixed inbound"
    for ob in cfg.get("outbounds", []):
        if ob.get("type") not in ("direct", "desync"):
            return f"unknown outbound type {ob.get('type')}"
        if ob.get("type") == "desync":
            for k in ob:
                if k in reject:
                    return f"unknown field {k}"
            mode = ob.get("mode")
            if mode is not None and mode not in KNOWN_MODES:
                return f"unknown desync mode: {mode}"
            if ob.get("preset") not in (None, "auto", "fake_split", "split", "disorder", "tlsrec", "fake", "oob"):
                return f"unknown desync preset: {ob.get('preset')}"
    return None


class Handler(socketserver.BaseRequestHandler):
    outbound = {}

    def handle(self):
        c = self.request
        try:
            ver, n = c.recv(2)
            c.recv(n)
            c.sendall(b"\x05\x00")
            ver, cmd, _, atyp = c.recv(4)
            if atyp == 1:
                host = socket.inet_ntoa(c.recv(4))
            elif atyp == 3:
                ln = c.recv(1)[0]
                host = c.recv(ln).decode()
            else:
                host = socket.inet_ntop(socket.AF_INET6, c.recv(16))
            port = struct.unpack(">H", c.recv(2))[0]
            try:
                up = socket.create_connection((host, port), timeout=5)
            except OSError:
                c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return
            c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            first = c.recv(65536)
            blocked = [h.encode() for h in os.environ.get("FAKE_CORE_BLOCK", "").split(",") if h]
            works = set(os.environ.get("FAKE_CORE_WORKS", "").split(","))
            ob = self.outbound
            bypass = ob.get("type") == "desync" and ob.get("mode") in works
            whole = int(os.environ.get("FAKE_CORE_DROP_WHOLE_HELLO", 0))
            if (any(b in first for b in blocked) or (whole and len(first) == whole)) and not bypass:
                c.close()  # DPI reset
                up.close()
                return
            up.sendall(first)
            pump(c, up)
        except (OSError, ValueError):
            pass


def pump(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 10)
            if not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    finally:
        a.close()
        b.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "version":
        print("tachyon-core fake 0.3.4-test")
        return 0
    if len(sys.argv) < 4 or sys.argv[2] != "-c":
        print("usage: fake_core.py check|run -c cfg", file=sys.stderr)
        return 2
    cfg = load(sys.argv[3])
    err = check(cfg)
    if err:
        print(f"config error: {err}", file=sys.stderr)
        return 1
    if sys.argv[1] == "check":
        return 0
    if os.environ.get("FAKE_CORE_NO_LISTEN"):
        threading.Event().wait()
    inb = cfg["inbounds"][0]
    Handler.outbound = cfg["outbounds"][0]
    srv = Server((inb.get("listen", "127.0.0.1"), int(inb["listen_port"])), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
