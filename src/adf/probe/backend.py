"""Probe backends.

* :class:`AgentBackend` drives ``agent/adf-agent.sh`` through a transport:
  :class:`LocalTransport` (agent runs on this machine, e.g. the controller runs on
  the router) or :class:`SSHTransport` (controller on a PC, agent on the router).
* :class:`SimulatedBackend` is a deterministic DPI model used by the test-suite
  and by ``adf bench`` to compare search algorithms offline. Its results are
  labelled ``simulated`` in the database and never mixed with real data.
"""

from __future__ import annotations

import ipaddress
import json
import os
import queue
import random
import re
import shlex
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from ..engines import ByeDPI, Engine, TachyonDesync
from ..engines.tachyon_desync import FAKE_MODES
from .dns import A, AAAA, AUTO, FALLBACK_SERVER, ask, check_server, describe, resolver_config
from .hello import PROXY_TIMEOUT_S, ProxyFailure, Stream, TargetUnreachable, client_hello, exchange, socks5_open
from .model import LARGE_HELLO, BatchResult, ProbeResult, Target, classify

AGENT_PATH = Path(os.environ.get("ADF_AGENT_PATH") or Path(__file__).resolve().parents[3] / "agent" / "adf-agent.sh")
TACHYON_BYPASS_MARK = 0x08000000  # NFT_OUTBOUND_MARK in Tachyon (service/lifecycle.uc)


class BackendError(RuntimeError):
    pass


def _run(cmd: Sequence[str], stdin: str, timeout: float, env: Optional[Dict[str, str]] = None):
    """Run with *binary* pipes: LF line endings and UTF-8 on every OS.

    Text-mode pipes on Windows translate "\n" to "\r\n", which would corrupt the
    agent script and the job protocol sent to the router.
    """
    p = subprocess.run(list(cmd), input=stdin.replace("\r\n", "\n").encode("utf-8"), capture_output=True,
                       timeout=timeout, env=env)
    return subprocess.CompletedProcess(p.args, p.returncode, p.stdout.decode("utf-8", "replace"),
                                       p.stderr.decode("utf-8", "replace"))


# ---------------------------------------------------------------- transports
class Transport:
    def call(self, args: Sequence[str], stdin: str = "", timeout: float = 600) -> str:
        raise NotImplementedError

    def connect(self, host: str, port: int, timeout: float) -> Stream:
        """A TCP connection opened from the agent's host."""
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


class SocketStream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv(self, n: int, timeout: float) -> bytes:
        self.sock.settimeout(timeout)
        return self.sock.recv(n)

    def close(self) -> None:
        self.sock.close()


class SSHStream:
    """A TCP connection opened by the router's sshd (``ssh -W``); pipes cannot be polled on Windows."""

    def __init__(self, cmd: Sequence[str]):
        self.proc = subprocess.Popen(list(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, bufsize=0)
        self.chunks: "queue.Queue[bytes]" = queue.Queue()
        self.pending = b""
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        while True:
            try:
                data = self.proc.stdout.read(65536)
            except (OSError, ValueError):
                data = b""
            self.chunks.put(data or b"")
            if not data:
                return

    def send(self, data: bytes) -> None:
        self.proc.stdin.write(data)

    def recv(self, n: int, timeout: float) -> bytes:
        if not self.pending:
            try:
                self.pending = self.chunks.get(timeout=max(timeout, 0.001))
            except queue.Empty:
                raise TimeoutError from None
            if not self.pending:
                self.chunks.put(b"")    # end of stream stays visible to later calls
                return b""
        data, self.pending = self.pending[:n], self.pending[n:]
        return data

    def close(self) -> None:
        self.proc.kill()
        self.proc.wait()
        for pipe in (self.proc.stdin, self.proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass


@dataclass
class LocalTransport(Transport):
    agent: str = str(AGENT_PATH)
    interpreter: str = "sh"
    env: Optional[Dict[str, str]] = None

    def call(self, args: Sequence[str], stdin: str = "", timeout: float = 600) -> str:
        env = dict(os.environ)
        if self.env:
            env.update(self.env)
        try:
            p = _run([*shlex.split(self.interpreter), self.agent, *args], stdin, timeout, env)
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"agent timed out after {timeout}s") from e
        if p.returncode not in (0,):
            raise BackendError(f"agent {' '.join(args)} failed (rc={p.returncode}): {p.stderr.strip()[:500]}"
                               f" {p.stdout.strip()[:300]}")
        return p.stdout

    def connect(self, host: str, port: int, timeout: float) -> Stream:
        return SocketStream(socket.create_connection((host, port), timeout=timeout))

    def shell(self, cmd: str, stdin: str = "", timeout: float = 120) -> str:
        p = _run(["sh", "-c", cmd], stdin, timeout)
        if p.returncode != 0:
            raise BackendError(f"command failed (rc={p.returncode}): {p.stderr.strip()[:500]}")
        return p.stdout

    def describe(self) -> str:
        return f"local:{self.agent}"


@dataclass
class SSHTransport(Transport):
    """Run the agent on the router over SSH.

    Authentication is left to ssh (keys / agent); the controller never handles
    passwords. ``BatchMode=yes`` makes ssh fail instead of prompting.
    """

    host: str
    user: str = "root"
    port: int = 22
    identity: Optional[str] = None
    remote_agent: str = "/tmp/adf-agent.sh"
    ssh: str = "ssh"
    extra_opts: Sequence[str] = ()
    core: str = ""

    def _base(self) -> List[str]:
        cmd = [self.ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p", str(self.port)]
        if self.identity:
            cmd += ["-i", str(Path(self.identity).expanduser())]
        cmd += list(self.extra_opts)
        cmd.append(f"{self.user}@{self.host}")
        return cmd

    def install(self, local_agent: Path = AGENT_PATH, timeout: float = 60) -> None:
        """Copy the agent to ``remote_agent`` (tmpfs by default: nothing persists)."""
        # strip CR: a Windows checkout may have converted the script to CRLF
        script = Path(local_agent).read_bytes().decode("utf-8").replace("\r\n", "\n")
        cmd = self._base() + [f"cat > {shlex.quote(self.remote_agent)} && chmod 700 {shlex.quote(self.remote_agent)}"]
        p = _run(cmd, script, timeout)
        if p.returncode != 0:
            raise BackendError(f"agent install failed: {p.stderr.strip()[:500]}")

    def call(self, args: Sequence[str], stdin: str = "", timeout: float = 600) -> str:
        remote = "sh " + shlex.quote(self.remote_agent) + " " + " ".join(shlex.quote(a) for a in args)
        if self.core:
            remote = f"ADF_CORE={shlex.quote(self.core)} {remote}"
        try:
            p = _run(self._base() + [remote], stdin, timeout)
        except subprocess.TimeoutExpired as e:
            raise BackendError(f"ssh agent call timed out after {timeout}s") from e
        if p.returncode != 0:
            raise BackendError(f"ssh agent {' '.join(args)} failed (rc={p.returncode}): {p.stderr.strip()[:500]}")
        return p.stdout

    def connect(self, host: str, port: int, timeout: float) -> Stream:
        cmd = self._base()
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        return SSHStream(cmd[:-1] + ["-q", "-W", address, cmd[-1]])

    def shell(self, cmd: str, stdin: str = "", timeout: float = 120) -> str:
        p = _run(self._base() + [cmd], stdin, timeout)
        if p.returncode != 0:
            raise BackendError(f"ssh command failed (rc={p.returncode}): {p.stderr.strip()[:500]}")
        return p.stdout

    def describe(self) -> str:
        return f"ssh:{self.user}@{self.host}:{self.port}"


# sing-box / tachyon-core default FakeIP pools; answers from them (or private/loopback
# addresses) mean the router's DNS was intercepted and cannot be used with --resolve.
_FAKEIP = (ipaddress.ip_network("198.18.0.0/15"), ipaddress.ip_network("fc00::/18"))


def usable_addresses(lines: Sequence[str]) -> List[str]:
    out = []
    for line in lines:
        try:
            ip = ipaddress.ip_address(line.strip())
        except ValueError:
            continue
        if any(ip in n for n in _FAKEIP if n.version == ip.version):
            continue
        if ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            continue
        out.append(str(ip))
    return out


def parse_lines(text: str) -> List[Dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ------------------------------------------------------------------ backends
class Backend:
    """Interface used by the search orchestrator."""

    name = "abstract"
    simulated = False

    def env(self) -> Dict[str, Any]:
        return {}

    def resolve(self, host: str) -> List[str]:
        return []

    def prepare_dns(self, hosts: Sequence[str]) -> None:
        """Called once before ``resolve``, with every host the run needs."""

    def other_addresses(self, host: str) -> List[str]:
        """Addresses from the independent resolver."""
        return []

    def dns_info(self) -> Dict[str, str]:
        return {"live": "", "check": "", "note": ""}

    def run_batch(self, engine: Engine, params: Optional[Mapping[str, Any]], targets: Sequence[Target],
                  ips: Mapping[str, Sequence[str]], reps: int = 1, stop_on_fail: bool = False) -> BatchResult:
        raise NotImplementedError

    def run_raw_outbound(self, outbound: Mapping[str, Any], targets: Sequence[Target],
                         ips: Mapping[str, Sequence[str]], reps: int = 1) -> BatchResult:
        """Measure an arbitrary tachyon-core outbound (e.g. preset=auto / Adaptive 2.0)."""
        raise NotImplementedError

    def capabilities(self, tests: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        return []


@dataclass
class ProbeSettings:
    port: int = 11290
    timeout_s: int = 8
    connect_timeout_s: int = 4
    engine_start_s: int = 10
    interval_ms: int = 250
    routing_mark: Optional[int] = TACHYON_BYPASS_MARK
    dns_server: str = AUTO           # AUTO: the DNS server of the live core; otherwise this resolver
    dns_check: bool = True           # compare with an independent resolver
    cacert: Optional[str] = None     # only for local test servers
    baseline_via_core: bool = True   # baseline through tachyon-core "direct" (same path as strategies)


class AgentBackend(Backend):
    name = "agent"

    def __init__(self, transport: Transport, settings: Optional[ProbeSettings] = None):
        self.transport = transport
        self.settings = settings or ProbeSettings()
        self._live: Dict[str, List[str]] = {}
        self._other: Dict[str, List[str]] = {}
        self._dns: Dict[str, str] = {"live": self.plain_dns, "check": "", "note": "configured"}

    @property
    def plain_dns(self) -> str:
        return FALLBACK_SERVER if self.settings.dns_server == AUTO else self.settings.dns_server

    # ---- helpers
    def core_config(self, engine: TachyonDesync, params: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        s = self.settings
        if params is None:
            outbound: Dict[str, Any] = {"type": "direct", "tag": "adf-out"}
            if s.routing_mark is not None:
                outbound["routing_mark"] = s.routing_mark
        else:
            outbound = engine.outbound(params, tag="adf-out", routing_mark=s.routing_mark)
        return {
            "log": {"level": "error"},
            "dns": {"servers": [{"type": "udp", "tag": "adf-dns", "server": self.plain_dns}], "final": "adf-dns"},
            "inbounds": [{"type": "mixed", "tag": "adf-in", "listen": "127.0.0.1", "listen_port": s.port}],
            "outbounds": [outbound],
            "route": {"final": "adf-out"},
        }

    def build_job(self, engine: Engine, params: Optional[Mapping[str, Any]], targets: Sequence[Target],
                  ips: Mapping[str, Sequence[str]], reps: int, stop_on_fail: bool = False,
                  raw_outbound: Optional[Mapping[str, Any]] = None) -> str:
        s = self.settings
        lines = ["ADF-JOB 1", f"port {s.port}", f"reps {int(reps)}", f"interval_ms {int(s.interval_ms)}",
                 f"timeout {int(s.timeout_s)}", f"connect_timeout {int(s.connect_timeout_s)}",
                 f"engine_start_s {int(s.engine_start_s)}", f"stop_on_fail {1 if stop_on_fail else 0}"]
        if s.cacert:
            lines.append(f"cacert {s.cacert}")
        if raw_outbound is not None:
            cfg = self.core_config(TachyonDesync(), None)
            ob = dict(raw_outbound, tag="adf-out")
            if s.routing_mark is not None:
                ob.setdefault("routing_mark", s.routing_mark)
            cfg["outbounds"] = [ob]
            lines += ["engine tachyon", "config-begin", json.dumps(cfg), "config-end"]
        elif params is None and not s.baseline_via_core:
            lines.append("engine none")
        elif isinstance(engine, TachyonDesync) or params is None:
            lines.append("engine tachyon")
            lines.append("config-begin")
            te = engine if isinstance(engine, TachyonDesync) else TachyonDesync()
            lines.append(json.dumps(self.core_config(te, params if isinstance(engine, TachyonDesync) else None)))
            lines.append("config-end")
        elif isinstance(engine, ByeDPI):
            lines.append("engine byedpi")
            lines.append("byedpi_args " + engine.render(params))
        else:
            raise BackendError(f"engine {engine.name} is measured through 'tachyon-probe', not adf-agent run")
        for t in targets:
            for fam in t.families:
                addrs = [a for a in ips.get(t.id, []) if (":" in a) == (fam == "ipv6")][: max(1, t.max_ips)] or ["-"]
                for ip in addrs:
                    lines.append(" ".join([
                        "target", t.id, fam, t.url, ip, str(int(t.min_bytes)), t.range or "-",
                        t.kind, t.body_regex or "-",
                    ]))
        lines.append("end")
        return "\n".join(lines) + "\n"

    # ---- interface
    def env(self) -> Dict[str, Any]:
        lines = parse_lines(self.transport.call(["env"], timeout=30))
        return lines[0] if lines else {}

    def resolve(self, host: str) -> List[str]:
        if self._live.get(host):
            return self._live[host]
        out = self.transport.call(["resolve", host, self.plain_dns], timeout=30)
        return usable_addresses(out.splitlines())

    def other_addresses(self, host: str) -> List[str]:
        return self._other.get(host, [])

    def dns_info(self) -> Dict[str, str]:
        return dict(self._dns)

    def _live_dns(self) -> Dict[str, Any]:
        try:
            lines = parse_lines(self.transport.call(["live-dns"], timeout=30))
        except BackendError:
            return {}
        return lines[0] if lines else {}

    def _ask_all(self, port: int, hosts: Sequence[str]) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        stream = None
        try:
            stream = self.transport.connect("127.0.0.1", port, PROXY_TIMEOUT_S)
            for host in hosts:
                out[host] = usable_addresses(ask(stream, host, A) + ask(stream, host, AAAA))
        except OSError:
            pass                    # the rest stays unanswered and falls back to plain DNS
        finally:
            if stream is not None:
                stream.close()
        return out

    def prepare_dns(self, hosts: Sequence[str]) -> None:
        s = self.settings
        if s.dns_server != AUTO or (hosts and all(self._live.get(host) for host in hosts)):
            return
        found = self._live_dns()
        server = found.get("server")
        self._dns = {"live": FALLBACK_SERVER, "check": "", "note": "no_live_dns"}
        if not isinstance(server, dict):
            return
        check = check_server(server) if s.dns_check else None
        cfg = resolver_config(server, found.get("bootstrap"), check, s.port, s.routing_mark)
        job = "\n".join(["ADF-JOB 1", f"port {s.port}", f"engine_start_s {int(s.engine_start_s)}", "engine tachyon",
                         "config-begin", json.dumps(cfg), "config-end"]) + "\n"
        try:
            items = parse_lines(self.transport.call(["hold", "120"], stdin=job, timeout=30 + s.engine_start_s))
        except BackendError:
            self._dns["note"] = "core_failed"
            return
        if any(i.get("t") == "error" or (i.get("t") == "engine" and not i.get("ok")) for i in items):
            self._dns["note"] = "core_failed"
            return
        try:
            self._live = self._ask_all(s.port, hosts)
            self._other = self._ask_all(s.port + 1, hosts) if check else {}
        finally:
            self.transport.call(["stop"], timeout=30)
        answered = len({host for host in hosts if self._live.get(host)})
        self._dns = {"live": describe(server) if answered else FALLBACK_SERVER,
                     "check": describe(check) if self._other else "",
                     "note": "" if answered == len(set(hosts)) else "partial" if answered else "no_answers"}
        if server.get("detour"):
            self._dns["note"] = "detour"

    def run_batch(self, engine: Engine, params: Optional[Mapping[str, Any]], targets: Sequence[Target],
                  ips: Mapping[str, Sequence[str]], reps: int = 1, stop_on_fail: bool = False) -> BatchResult:
        def job(ts: Sequence[Target]) -> str:
            return self.build_job(engine, params, ts, ips, reps, stop_on_fail)
        through_engine = params is not None or self.settings.baseline_via_core
        return self._measure(job, targets, ips, reps, stop_on_fail, through_engine)

    def run_raw_outbound(self, outbound: Mapping[str, Any], targets: Sequence[Target],
                         ips: Mapping[str, Sequence[str]], reps: int = 1) -> BatchResult:
        def job(ts: Sequence[Target]) -> str:
            return self.build_job(TachyonDesync(), None, ts, ips, reps, raw_outbound=outbound)
        return self._measure(job, targets, ips, reps, False, True)

    def _measure(self, job: Callable[[Sequence[Target]], str], targets: Sequence[Target],
                 ips: Mapping[str, Sequence[str]], reps: int, stop_on_fail: bool, through_engine: bool) -> BatchResult:
        large = [t for t in targets if t.kind == LARGE_HELLO]
        plain = [t for t in targets if t.kind != LARGE_HELLO]
        batch = self._run(job(plain), plain, ips, reps) if plain or not large else BatchResult(ok=True)
        if large and batch.ok and not (stop_on_fail and any(not r.ok for r in batch.results)):
            self._large_hellos(job([]) if through_engine else None, large, ips, reps, stop_on_fail, batch)
        return batch

    def _large_hellos(self, job: Optional[str], targets: Sequence[Target], ips: Mapping[str, Sequence[str]],
                      reps: int, stop_on_fail: bool, batch: BatchResult) -> None:
        s = self.settings
        addresses = [(t, fam, ip) for t in targets for fam in t.families
                     for ip in ([a for a in ips.get(t.id, []) if (":" in a) == (fam == "ipv6")][: max(1, t.max_ips)]
                                or ["-"])]
        if job is not None:
            per_probe = PROXY_TIMEOUT_S + s.connect_timeout_s + s.interval_ms / 1000 + 1
            hold_s = 30 + int(per_probe * reps * len(addresses))
            for item in parse_lines(self.transport.call(["hold", str(hold_s)], stdin=job,
                                                        timeout=30 + s.engine_start_s)):
                if item.get("t") == "engine" and not item.get("ok"):
                    batch.ok = False
                    batch.engine_error = str(item.get("error", "engine failed"))
                    return
                if item.get("t") == "error":
                    raise BackendError(f"agent error: {item.get('error')}")
        results: List[ProbeResult] = []
        try:
            for rep in range(1, reps + 1):
                for t, fam, ip in addresses:
                    r = self._large_hello(t, fam, ip, rep, job is not None)
                    results.append(r)
                    time.sleep(s.interval_ms / 1000)
                    if stop_on_fail and not r.ok:
                        return
        finally:
            batch.results.extend(results)
            if job is not None:
                self.transport.call(["stop"], timeout=30)
        if results and all(r.verdict == "proxy_error" for r in results):
            raise BackendError(f"large hellos cannot reach the temporary engine: {results[0].error}. "
                               "Allow TCP forwarding in the router's SSH server or set [probe] large_hello = false")

    def _large_hello(self, t: Target, fam: str, ip: str, rep: int, through_engine: bool) -> ProbeResult:
        s = self.settings
        address = t.host if ip == "-" else ip
        explicit = re.match(r"^https?://[^/:]+:(\d+)", t.url)
        port = int(explicit.group(1)) if explicit else 443
        result = ProbeResult(target=t.id, family=fam, ip="" if ip == "-" else ip, verdict="proxy_error", rep=rep)
        try:
            stream = (self.transport.connect("127.0.0.1", s.port, PROXY_TIMEOUT_S) if through_engine
                      else self.transport.connect(address, port, s.connect_timeout_s))
        except OSError as e:
            result.error = str(e)[:300]
            return result
        try:
            if through_engine:
                socks5_open(stream, address, port)
            result.verdict, result.tls_ms, result.error = exchange(stream, client_hello(t.host), s.connect_timeout_s)
            result.ttfb_ms = result.total_ms = result.tls_ms
            result.http_code = 200 if result.ok else 0
        except TargetUnreachable as e:
            result.verdict, result.error = "connect_failed", str(e)[:300]
        except ProxyFailure as e:
            result.error = str(e)[:300]
        finally:
            stream.close()
        return result

    def _run(self, job: str, targets: Sequence[Target], ips: Mapping[str, Sequence[str]], reps: int) -> BatchResult:
        per_probe = self.settings.timeout_s + self.settings.interval_ms / 1000 + 1
        n_probes = reps * sum(len(t.families) * max(1, t.max_ips) for t in targets)
        out = self.transport.call(["run"], stdin=job, timeout=30 + self.settings.engine_start_s + per_probe * n_probes)
        by_id = {t.id: t for t in targets}
        batch = BatchResult(ok=True)
        for item in parse_lines(out):
            kind = item.get("t")
            if kind == "engine" and not item.get("ok"):
                batch.ok = False
                batch.engine_error = str(item.get("error", "engine failed"))
            elif kind == "error":
                raise BackendError(f"agent error: {item.get('error')}")
            elif kind == "probe":
                t = by_id.get(item.get("target"))
                if t is not None:
                    batch.results.append(classify(item, t))
            elif kind == "done":
                batch.mem_avail_kb = int(item.get("mem_avail_kb", 0) or 0)
                if not item.get("ok") and not batch.engine_error:
                    batch.ok = False
                    batch.engine_error = "agent reported failure"
        return batch

    def capabilities(self, tests: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        te = TachyonDesync()
        lines = []
        for t in tests:
            cfg = self.core_config(te, None)
            cfg["outbounds"] = [dict(t["outbound"], tag="adf-out")]
            lines.append(f"{t['key']}\t{json.dumps(t['value'])}\t{json.dumps(cfg)}")
        out = self.transport.call(["caps"], stdin="\n".join(lines) + "\n", timeout=30 + 5 * len(lines))
        res = []
        for item, test in zip([i for i in parse_lines(out) if i.get("t") == "caps"], tests):
            try:
                item["value"] = json.loads(item["value"])
            except (TypeError, json.JSONDecodeError):
                pass
            item["control"] = bool(test.get("control"))
            res.append(item)
        return res

    def tachyon_probe(self, engine: str, args: str, url: str) -> Dict[str, Any]:
        out = self.transport.call(["tachyon-probe", engine, args, url], timeout=120)
        try:
            return json.loads(out.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as e:
            raise BackendError(f"unexpected tachyon-probe output: {out[:300]}") from e


# --------------------------------------------------------------- simulation
@dataclass
class DPIModel:
    """A synthetic censor used to benchmark search algorithms.

    Each target has a *rule*: a predicate over strategy params returning the
    success probability (noisy, like a real network). The default model mimics
    a TSPU-like stateful DPI: plain split is defeated by reassembly, fakes need a
    TTL between the DPI hop and the server, some fooling methods are stripped
    by NAT, and multi-segment disorder works best for video CDN.
    """

    dpi_hops: int = 4
    server_hops: int = 11
    seed: int = 1
    noise: float = 0.04
    network_down_prob: float = 0.0
    rules: Dict[str, Callable[[Mapping[str, Any]], float]] = field(default_factory=dict)

    def p_success(self, target: Target, params: Optional[Mapping[str, Any]]) -> float:
        rule = self.rules.get(target.category) or self.rules.get("*")
        if params is None:
            return 0.98 if target.category == "control" else (rule(None) if rule else 0.02)
        if rule is not None:
            return rule(params)
        return self.default_rule(target, params)

    def default_rule(self, target: Target, p: Mapping[str, Any]) -> float:
        if target.category == "control":
            return 0.98
        mode = p.get("mode")
        fooling = p.get("fooling", "")
        ttl = int(p.get("fake_ttl", 6) or 6)
        ttl_ok = self.dpi_hops <= ttl < self.server_hops
        fake_effective = mode in FAKE_MODES and (
            fooling in ("md5", "badseq", "md5_badack", "timestamp", "badseq_badack_badsum") or ttl_ok or
            fooling == "autottl")
        if fooling == "badsum":  # NAT recomputes checksums -> fake reaches server
            fake_effective = False
        fake_breaks = mode in FAKE_MODES and not fake_effective and ttl >= self.server_hops
        pos = str(p.get("split_pos", ""))
        hits_host = any(x in pos for x in ("midsld", "host+1", "sniext+1", "endhost-1"))
        base = 0.03
        if mode in ("split", "tlsrec", "oob"):
            base = 0.08 if not hits_host else 0.15  # reassembling DPI
            if mode == "tlsrec" and hits_host:
                base = 0.55
        elif mode == "disorder":
            base = 0.45 if hits_host else 0.25
        elif mode == "fake":
            base = 0.6 if fake_effective else 0.05
        elif mode in ("fake_split", "fake_disorder"):
            base = (0.9 if hits_host else 0.7) if fake_effective else 0.1
        elif mode == "multi_split":
            base = 0.6 if pos.count(",") >= 2 else 0.4
        elif mode == "multi_disorder":
            base = 0.97 if fake_effective else 0.5
        if target.category in ("youtube", "youtube_music") and mode not in ("multi_disorder", "fake_disorder"):
            base *= 0.8  # stricter rules for video CDN
        reps = int(p.get("repeats", 1) or 1)
        if mode in FAKE_MODES and fake_effective:
            base = min(0.995, base + 0.01 * min(reps, 6))
        if fake_breaks:
            base = 0.0
        if p.get("ipfrag"):
            base *= 0.5  # fragments dropped by CGNAT
        if p.get("syndata") and target.category == "cloudflare":
            base *= 0.3
        if target.kind == LARGE_HELLO and mode != "tlsrec" and "," not in pos and not pos.isdigit():
            base *= 0.05    # one split at the SNI: fails on a large hello (measured with Chrome hellos)
        return max(0.0, min(1.0, base))


class SimulatedBackend(Backend):
    name = "simulated"
    simulated = True

    def __init__(self, model: Optional[DPIModel] = None):
        self.model = model or DPIModel()
        self.rng = random.Random(self.model.seed)
        self.calls = 0
        self.probes = 0

    def env(self) -> Dict[str, Any]:
        return {"t": "env", "agent": "simulated", "core_version": "simulated", "http3": 0, "mem_avail_kb": 10 ** 6}

    def resolve(self, host: str) -> List[str]:
        h = sum(map(ord, host)) % 200
        return [f"192.0.2.{h + 1}", f"192.0.2.{h + 2}"]

    def run_raw_outbound(self, outbound: Mapping[str, Any], targets: Sequence[Target],
                         ips: Mapping[str, Sequence[str]], reps: int = 1) -> BatchResult:
        """Adaptive 2.0 is modelled as a fixed 'good but not best' strategy (labelled simulated)."""
        params = {"mode": "fake_split", "split_pos": "midsld", "fake_ttl": 6, "repeats": 1, "split_delay_ms": 1}
        return self.run_batch(TachyonDesync(), params, targets, ips, reps)

    def run_batch(self, engine: Engine, params: Optional[Mapping[str, Any]], targets: Sequence[Target],
                  ips: Mapping[str, Sequence[str]], reps: int = 1, stop_on_fail: bool = False) -> BatchResult:
        self.calls += 1
        if params is not None and engine.check(params) is not None:
            return BatchResult(ok=False, engine_error="config rejected: " + str(engine.check(params)))
        batch = BatchResult(ok=True, mem_avail_kb=10 ** 6)
        down = self.rng.random() < self.model.network_down_prob
        for rep in range(1, reps + 1):
            for t in targets:
                for fam in t.families:
                    addrs = list(ips.get(t.id, []))[: max(1, t.max_ips)] or [""]
                    for ip in addrs:
                        self.probes += 1
                        p = 0.0 if down else self.model.p_success(t, params)
                        p = min(1.0, max(0.0, p + self.rng.uniform(-self.model.noise, self.model.noise)))
                        ok = self.rng.random() < p
                        lat = 80 + self.rng.random() * 120 + (0 if params is None else 15 * len(params))
                        verdict = "ok" if ok else self.rng.choice(["tls_timeout", "tls_reset", "cutoff_16k"])
                        batch.results.append(ProbeResult(
                            target=t.id, family=fam, ip=ip, verdict=verdict, http_code=200 if ok else 0,
                            curl_exit=0 if ok else 28, connect_ms=lat * 0.3, tls_ms=lat * 0.7, ttfb_ms=lat,
                            total_ms=lat * 1.5, bytes=max(t.min_bytes, 70000) if ok else 0, rep=rep))
                        if stop_on_fail and not ok:
                            return batch
        return batch

    def capabilities(self, tests: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        return [{"t": "caps", "key": t["key"], "value": t["value"], "ok": not t.get("control"), "error": "",
                 "control": bool(t.get("control"))} for t in tests]
