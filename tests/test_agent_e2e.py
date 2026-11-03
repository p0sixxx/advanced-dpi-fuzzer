"""End-to-end test of agent/adf-agent.sh with a fake tachyon-core and a local HTTPS server.

Exercises the real shell agent (job protocol, engine start/stop, curl metrics,
content checks, caps probing) and the controller pipeline on top of it.
"""

import http.server
import os
import shutil
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from adf.db import Store
from adf.engines import TachyonDesync
from adf.engines.tachyon_desync import caps_test_matrix, capabilities_from_probe
from adf.probe.backend import AgentBackend, LocalTransport, ProbeSettings
from adf.probe.model import Target
from adf.safety import Budget, Guard, SafetyPolicy
from adf.search.orchestrator import Orchestrator, SearchConfig

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.skipif(not (shutil.which("curl") and shutil.which("openssl")), reason="needs curl+openssl")
BODY = b"<html>hello-adf " + b"x" * 100_000 + b"</html>"


@pytest.fixture(scope="module")
def https_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key, crt = d / "key.pem", d / "crt.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "2", "-subj", "/CN=open.test",
                    "-addext", "subjectAltName=DNS:open.test,DNS:blocked.test,DNS:localhost"],
                   check=True, capture_output=True)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1], str(crt)
    srv.shutdown()


def _busybox_path(tmp_path):
    """PATH with busybox applets first (like OpenWrt); curl stays the host's."""
    bb = shutil.which("busybox")
    d = tmp_path / "bb"
    d.mkdir()
    for applet in ("awk", "sed", "grep", "tr", "cut", "sort", "head", "cat", "sleep", "mkdir", "rm", "chmod", "kill",
                   "nslookup", "uname", "printf"):
        (d / applet).symlink_to(bb)
    return f"{d}:{os.environ['PATH']}"


SHELLS = ["sh"] + (["busybox ash"] if shutil.which("busybox") else [])


@pytest.fixture(params=SHELLS)
def backend(request, tmp_path, https_server):
    port, crt = https_server
    core = tmp_path / "tachyon-core"
    core.write_text(f"#!/bin/sh\nexec {sys.executable} {FIXTURES / 'fake_core.py'} \"$@\"\n")
    core.chmod(0o755)
    env = {"ADF_CORE": str(core), "ADF_STATE": str(tmp_path / "state"), "ADF_MIN_MEM_KB": "1",
           "FAKE_CORE_BLOCK": "blocked.test", "FAKE_CORE_WORKS": "multi_disorder,fake_disorder"}
    if request.param.startswith("busybox"):
        env["PATH"] = _busybox_path(tmp_path)
    sock_port = 20000 + (os.getpid() + len(request.param)) % 20000
    be = AgentBackend(LocalTransport(interpreter=request.param, env=env), ProbeSettings(port=sock_port, interval_ms=0, routing_mark=None,
                                                             cacert=crt, timeout_s=5, connect_timeout_s=3))
    return be, port, env


def targets(port):
    blocked = Target("blk", f"https://blocked.test:{port}/", "test", min_bytes=65536, body_regex="hello-adf")
    control = Target("ctl", f"https://open.test:{port}/", "control", min_bytes=1000)
    return blocked, control


IPS = {"blk": ["127.0.0.1"], "ctl": ["127.0.0.1"]}


def test_env(backend):
    be, _, _ = backend
    env = be.env()
    assert env["t"] == "env"
    assert "fake" in env["core_version"]


def test_baseline_blocked_and_strategy_passes(backend):
    be, port, _ = backend
    blk, ctl = targets(port)
    eng = TachyonDesync()
    base = be.run_batch(eng, None, [blk, ctl], IPS, reps=1)
    by = {r.target: r for r in base.results}
    assert by["ctl"].ok, by["ctl"]
    assert not by["blk"].ok and by["blk"].counts, by["blk"]
    good = be.run_batch(eng, {"mode": "multi_disorder", "split_pos": "1,midsld", "fake_ttl": 6, "repeats": 1}, [blk],
                        IPS, reps=2)
    assert good.ok and len(good.results) == 2
    assert all(r.ok and r.content_ok and r.bytes >= 65536 for r in good.results)
    bad = be.run_batch(eng, {"mode": "split", "split_pos": "midsld"}, [blk], IPS, reps=1)
    assert bad.ok and not bad.results[0].ok


def test_stop_on_fail(backend):
    be, port, _ = backend
    blk, ctl = targets(port)
    b = be.run_batch(TachyonDesync(), {"mode": "split", "split_pos": "1"}, [blk, ctl], IPS, reps=3, stop_on_fail=True)
    assert len(b.results) == 1


def test_engine_rejection_is_reported(backend):
    be, port, env = backend
    env["FAKE_CORE_REJECT"] = "fooling"
    blk, _ = targets(port)
    b = be.run_batch(TachyonDesync(), {"mode": "fake_split", "split_pos": "1", "fooling": "md5", "fake_ttl": 5,
                                       "repeats": 1}, [blk], IPS)
    assert b.engine_failed and "fooling" in b.engine_error
    env.pop("FAKE_CORE_REJECT")


def test_caps_probe(backend):
    be, _, env = backend
    env["FAKE_CORE_REJECT"] = "fooling,syndata"
    res = be.capabilities(caps_test_matrix())
    caps = capabilities_from_probe({"host": "t", "version": "x", "results": res})
    assert "fooling" in caps.unsupported and "syndata" in caps.unsupported
    assert "seqovl" not in caps.unsupported
    env.pop("FAKE_CORE_REJECT")


def test_orchestrator_on_agent(backend, tmp_path):
    be, port, _ = backend
    blk, ctl = targets(port)
    guard = Guard(Budget(max_batches=45), SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0, control_every=10),
                  sleeper=lambda s: None)
    store = Store(tmp_path / "e2e.sqlite")
    be.ips = IPS
    cfg = SearchConfig(seed=3, confirm_n=4, final_n=6, use_history=False, baseline_reps=2)
    orch = Orchestrator(store, be, TachyonDesync(), [blk], [ctl], cfg, guard)
    orch.ips = dict(IPS)
    orch._environment = lambda: {"core_version": "fake"}  # IPs are fixed for the local test
    summary = orch.run()
    assert summary["status"] == "finished", summary["error"]
    assert summary["baseline"]["blk"]["status"] == "blocked"
    best = summary["best"]
    assert best is not None and best["params"]["mode"] in ("multi_disorder", "fake_disorder"), best
    assert best["rate"] == 1.0
