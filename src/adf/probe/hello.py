"""A ClientHello of the size current Chrome sends.

curl on a router sends a few hundred bytes. Chrome offers a post-quantum key and sends about 2 KB
with its extensions shuffled. A strategy can pass every curl probe and still hang in Chrome: on a
Flint 2 ``split_pos=host+1`` passed 150/150 with curl and 0/16 with captured Chrome hellos.

The hello is written at once, because the engine has to get it whole, as it does from a LAN client.
Writing it in two parts with a pause hid that failure: the same hellos then passed 13/16.

No TLS library is involved: the handshake is not finished, and the verdict is whether the server's
first record gets back. The ML-KEM key is well-formed, so servers accept it and pick that group.
"""

from __future__ import annotations

import ipaddress
import random
import struct
import time
from typing import Optional, Protocol, Tuple

HELLO_BYTES = 1950              # record included; captured Chrome hellos were 1923-2019 bytes
PROXY_TIMEOUT_S = 15.0          # covers opening the SSH channel

X25519 = 0x001d
X25519_MLKEM768 = 0x11ec
MLKEM768_Q = 3329
MLKEM768_COEFFICIENTS = 768


class Stream(Protocol):
    def send(self, data: bytes) -> None: ...

    def recv(self, n: int, timeout: float) -> bytes:
        """Up to ``n`` bytes, b"" at end of stream; raises TimeoutError."""

    def close(self) -> None: ...


class ProxyFailure(Exception):
    """The engine's proxy did not open the connection: says nothing about the strategy."""


def _u16(v: int) -> bytes:
    return struct.pack(">H", v)


def _vec8(b: bytes) -> bytes:
    return bytes([len(b)]) + b


def _vec16(b: bytes) -> bytes:
    return _u16(len(b)) + b


def _ext(kind: int, body: bytes) -> bytes:
    return _u16(kind) + _vec16(body)


def _grease(rng: random.Random) -> int:
    return rng.randrange(16) * 0x1010 + 0x0a0a


def mlkem768_public_key(rng: random.Random) -> bytes:
    """A valid encapsulation key: 12-bit coefficients below q, then the 32-byte seed."""
    out = bytearray()
    for _ in range(MLKEM768_COEFFICIENTS // 2):
        pair = rng.randrange(MLKEM768_Q) | rng.randrange(MLKEM768_Q) << 12
        out += pair.to_bytes(3, "little")
    return bytes(out) + rng.randbytes(32)


def client_hello(host: str, rng: Optional[random.Random] = None, size: int = HELLO_BYTES) -> bytes:
    """A TLS record of exactly ``size`` bytes with Chrome's extensions in random order."""
    rng = rng or random.SystemRandom()
    group, version = _grease(rng), _grease(rng)
    name = host.encode("idna")
    key_shares = (_u16(group) + _vec16(b"\x00") +
                  _u16(X25519_MLKEM768) + _vec16(mlkem768_public_key(rng) + rng.randbytes(32)) +
                  _u16(X25519) + _vec16(rng.randbytes(32)))
    ech_grease = (b"\x00" + _u16(1) + _u16(1) + bytes([rng.randrange(256)]) + _vec16(rng.randbytes(32)) +
                  _vec16(rng.randbytes(rng.choice((144, 176, 208, 240)))))
    alpn = _vec16(_vec8(b"h2") + _vec8(b"http/1.1"))
    signature_algorithms = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)
    extensions = [
        _ext(0x0000, _vec16(b"\x00" + _vec16(name))),                                   # server_name
        _ext(0x0005, b"\x01" + _u16(0) + _u16(0)),                                      # status_request
        _ext(0x000a, _vec16(b"".join(map(_u16, (group, X25519_MLKEM768, X25519, 0x0017, 0x0018))))),
        _ext(0x000b, _vec8(b"\x00")),                                                   # ec_point_formats
        _ext(0x000d, _vec16(b"".join(map(_u16, signature_algorithms)))),
        _ext(0x0010, alpn),
        _ext(0x0012, b""),                                                              # signed_certificate_timestamp
        _ext(0x0017, b""),                                                              # extended_master_secret
        _ext(0x001b, _vec8(_u16(2))),                                                   # compress_certificate: brotli
        _ext(0x0023, b""),                                                              # session_ticket
        _ext(0x002b, _vec8(_u16(version) + _u16(0x0304) + _u16(0x0303))),               # supported_versions
        _ext(0x002d, _vec8(b"\x01")),                                                   # psk_key_exchange_modes
        _ext(0x0033, _vec16(key_shares)),
        _ext(0x44cd, _vec16(_vec8(b"h2"))),                                             # application_settings
        _ext(0xfe0d, ech_grease),
        _ext(0xff01, b"\x00"),                                                          # renegotiation_info
    ]
    rng.shuffle(extensions)
    ciphers = (_grease(rng), 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
               0x009c, 0x009d, 0x002f, 0x0035)
    before_extensions = (b"\x03\x03" + rng.randbytes(32) + _vec8(rng.randbytes(32)) +
                         _vec16(b"".join(map(_u16, ciphers))) + _vec8(b"\x00"))

    def record(exts: bytes) -> bytes:
        body = before_extensions + _vec16(exts)
        return b"\x16\x03\x01" + _vec16(b"\x01" + len(body).to_bytes(3, "big") + body)

    opening = _grease(rng)
    closing = _grease(rng)
    while closing == opening:       # a repeated extension is a fatal error for the server
        closing = _grease(rng)
    exts = _ext(opening, b"") + b"".join(extensions)
    filler = size - len(record(exts)) - 4 - 5       # padding extension header, closing GREASE extension
    if filler < 0:
        raise ValueError(f"hello cannot be smaller than {size - filler} bytes")
    return record(exts + _ext(0x0015, bytes(filler)) + _ext(closing, b"\x00"))


def read_exact(stream: Stream, n: int, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    data = b""
    while len(data) < n:
        chunk = stream.recv(n - len(data), max(0.0, deadline - time.monotonic()))
        if not chunk:
            break
        data += chunk
    return data


def socks5_open(stream: Stream, host: str, port: int, timeout: float = PROXY_TIMEOUT_S) -> None:
    """Open ``host:port`` through a SOCKS5 proxy: every engine ADF starts speaks it."""
    try:
        stream.send(b"\x05\x01\x00")
        if read_exact(stream, 2, timeout) != b"\x05\x00":
            raise ProxyFailure("the proxy did not answer the greeting")
        try:
            ip = ipaddress.ip_address(host)
            address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
        except ValueError:
            address = b"\x03" + _vec8(host.encode("idna"))
        stream.send(b"\x05\x01\x00" + address + _u16(port))
        head = read_exact(stream, 4, timeout)
        if len(head) < 4 or head[1] != 0:
            raise ProxyFailure(f"the proxy refused the connection: {head.hex()}")
        rest = {1: 4, 4: 16}.get(head[3])
        if rest is None:
            rest = read_exact(stream, 1, timeout)[0]
        read_exact(stream, rest + 2, timeout)
    except (OSError, IndexError) as e:      # TimeoutError is an OSError
        raise ProxyFailure(f"the proxy is unavailable: {e}") from e


def exchange(stream: Stream, hello: bytes, timeout: float) -> Tuple[str, float, str]:
    """Send the hello; returns (verdict, milliseconds to the first record, error)."""
    started = time.monotonic()
    try:
        stream.send(hello)
        reply = read_exact(stream, 6, timeout)
    except TimeoutError:
        return "tls_timeout", timeout * 1000, "no ServerHello"
    except OSError as e:
        return "tls_reset", (time.monotonic() - started) * 1000, str(e)
    ms = (time.monotonic() - started) * 1000
    if len(reply) == 6 and reply[0] == 0x16 and reply[5] == 0x02:
        return "ok", ms, ""
    if reply[:1] == b"\x15":
        return "server_rejected", ms, "TLS alert"
    if not reply:
        return "tls_reset", ms, "connection closed"
    return "content_mismatch", ms, f"not a ServerHello: {reply.hex()}"
