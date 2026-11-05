"""The browser-size ClientHello probe: format, delivery in two parts, engine hold, SSH channel, search."""

import os
import random
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from adf.cli import main
from adf.config import load_config
from adf.db import Store
from adf.engines import TachyonDesync
from adf.probe.backend import AgentBackend, BackendError, LocalTransport, ProbeSettings, SimulatedBackend, SSHTransport
from adf.probe.hello import (HELLO_BYTES, MLKEM768_Q, ProxyFailure, X25519_MLKEM768, client_hello, exchange,
                             mlkem768_public_key, socks5_open)
from adf.probe.model import LARGE_HELLO, BatchResult, Target
from adf.probe.targets import DEFAULT_TARGETS, with_large_hello
from adf.report import compare_report
from adf.safety import Budget, Guard, SafetyPolicy
from adf.search.compare import Variant, compare
from adf.search.orchestrator import Orchestrator, SearchConfig
from adf.strategy import from_text

FIXTURES = Path(__file__).parent / "fixtures"
SERVER_HELLO = b"\x16\x03\x03\x00\x04\x02\x00\x00\x00"
MSS = 1460


def extensions(hello):
    """(type, body) pairs of a ClientHello record."""
    assert hello[:3] == b"\x16\x03\x01"
    assert struct.unpack(">H", hello[3:5])[0] == len(hello) - 5
    assert hello[5] == 1 and int.from_bytes(hello[6:9], "big") == len(hello) - 9
    i = 9 + 2 + 32
    i += 1 + hello[i]                                       # session id
    i += 2 + struct.unpack(">H", hello[i:i + 2])[0]         # ciphers
    i += 1 + hello[i]                                       # compression
    end = i + 2 + struct.unpack(">H", hello[i:i + 2])[0]
    assert end == len(hello)
    i += 2
    out = []
    while i < end:
        kind, size = struct.unpack(">HH", hello[i:i + 4])
        out.append((kind, hello[i + 4:i + 4 + size]))
        i += 4 + size
    assert i == end
    return out


def test_hello_is_browser_sized_and_spans_two_segments():
    hello = client_hello("www.youtube.com", random.Random(1))
    assert len(hello) == HELLO_BYTES > MSS
    ext = dict(extensions(hello))
    assert b"www.youtube.com" in ext[0]
    assert 0x0304 in struct.unpack(">3H", ext[0x2b][1:])


def test_hello_size_is_exact_for_any_shuffle():
    for seed in range(40):
        assert len(client_hello("a.example", random.Random(seed))) == HELLO_BYTES


def test_no_extension_is_repeated():
    for seed in range(300):
        kinds = [kind for kind, _ in extensions(client_hello("a.example", random.Random(seed)))]
        assert len(kinds) == len(set(kinds))


def test_hello_refuses_a_size_it_cannot_reach():
    with pytest.raises(ValueError):
        client_hello("a.example", random.Random(1), size=200)


def test_extension_order_moves_the_sni_between_segments():
    places = set()
    for seed in range(40):
        hello = client_hello("www.youtube.com", random.Random(seed))
        places.add(hello.index(b"www.youtube.com") < MSS)
    assert places == {True, False}


def test_post_quantum_share_is_a_valid_key():
    rng = random.Random(3)
    key = mlkem768_public_key(rng)
    assert len(key) == 1184
    for i in range(0, 1152, 3):
        pair = int.from_bytes(key[i:i + 3], "little")
        assert pair & 0xfff < MLKEM768_Q and pair >> 12 < MLKEM768_Q
    shares = dict(extensions(client_hello("a.example", rng)))[0x33]
    i, found = 2, {}
    while i < len(shares):
        group, size = struct.unpack(">HH", shares[i:i + 4])
        found[group] = size
        i += 4 + size
    assert found[X25519_MLKEM768] == 1216 and found[0x1d] == 32


class Scripted:
    def __init__(self, replies=(), error=None):
        self.replies = list(replies)
        self.error = error
        self.sent = []

    def send(self, data):
        self.sent.append(data)

    def recv(self, n, timeout):
        if self.error:
            raise self.error
        if not self.replies:
            return b""
        data, rest = self.replies[0][:n], self.replies[0][n:]
        self.replies[0:1] = [rest] if rest else []
        return data

    def close(self):
        pass


@pytest.mark.parametrize("replies,error,verdict", [
    ([SERVER_HELLO[:3], SERVER_HELLO[3:]], None, "ok"),
    ([b"\x15\x03\x03\x00\x02\x02\x28"], None, "server_rejected"),
    ([], None, "tls_reset"),
    ([b"HTTP/1.1 403 F\r\n"], None, "content_mismatch"),
    ([], TimeoutError(), "tls_timeout"),
    ([], ConnectionResetError("rst"), "tls_reset"),
])
def test_exchange_verdicts(replies, error, verdict):
    s = Scripted(replies, error)
    assert exchange(s, b"x" * HELLO_BYTES, 1)[0] == verdict
    assert [len(p) for p in s.sent] == [HELLO_BYTES]    # in two writes the engine hides the failure


def test_socks_failures_are_proxy_failures():
    for replies in ([], [b"\x05\xff"], [b"\x05\x00", b"\x05\x05\x00\x01"]):
        with pytest.raises(ProxyFailure):
            socks5_open(Scripted(replies), "192.0.2.1", 443, timeout=1)
    with pytest.raises(ProxyFailure):
        socks5_open(Scripted(error=TimeoutError()), "192.0.2.1", 443, timeout=1)


def test_socks_request_for_ip_and_name():
    s = Scripted([b"\x05\x00", b"\x05\x00\x00\x01", b"\x00" * 6])
    socks5_open(s, "192.0.2.1", 443, timeout=1)
    assert s.sent[1] == b"\x05\x01\x00\x01\xc0\x00\x02\x01\x01\xbb"
    s = Scripted([b"\x05\x00", b"\x05\x00\x00\x03", b"\x03", b"abc", b"\x00\x00"])
    socks5_open(s, "a.example", 443, timeout=1)
    assert s.sent[1] == b"\x05\x01\x00\x03\x09a.example\x01\xbb"


def test_large_variants_cover_required_https_targets():
    targets = with_large_hello(DEFAULT_TARGETS)
    large = {t.id: t for t in targets if t.kind == LARGE_HELLO}
    assert {"youtube-www-large", "youtube-video-large", "discord-www-large"} <= set(large)
    assert "youtube-img-large" not in large
    assert {"youtube-api-large", "discord-cdn-large", "instagram-api-large"} <= set(large)
    assert large["youtube-www-large"].required and large["youtube-www-large"].min_bytes == 0
    for t in targets:
        t.validate()


def test_large_hello_can_be_switched_off(tmp_path):
    path = tmp_path / "c.toml"
    assert load_config(None).probe.large_hello is True
    path.write_text("[probe]\nlarge_hello = false\n")
    assert load_config(path).probe.large_hello is False


class NoForwarding(LocalTransport):
    def call(self, args, stdin="", timeout=600):
        return '{"t":"done","ok":true}\n'

    def connect(self, host, port, timeout):
        raise OSError("channel open failed")


# ------------------------------------------------------------ through the real agent
@pytest.fixture
def tls_server():
    srv = socket.create_server(("127.0.0.1", 0))
    seen = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = b""
            c.settimeout(3)
            try:
                while len(data) < HELLO_BYTES:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                seen.append(len(data))
                c.sendall(SERVER_HELLO)
            except OSError:
                pass
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], seen
    srv.close()


@pytest.fixture
def agent(tmp_path):
    core = tmp_path / "tachyon-core"
    core.write_text(f"#!/bin/sh\nexec {sys.executable} {FIXTURES / 'fake_core.py'} \"$@\"\n")
    core.chmod(0o755)
    env = {"ADF_CORE": str(core), "ADF_STATE": str(tmp_path / "state"), "ADF_MIN_MEM_KB": "1",
           "FAKE_CORE_DROP_WHOLE_HELLO": str(HELLO_BYTES), "FAKE_CORE_WORKS": "multi_disorder"}
    port = 21000 + (os.getpid() + hash(str(tmp_path))) % 19000
    settings = ProbeSettings(port=port, interval_ms=0, routing_mark=None, timeout_s=3, connect_timeout_s=2)
    return AgentBackend(LocalTransport(env=env), settings), env


def _running(env):
    pid_file = Path(env["ADF_STATE"]) / "engine.pid"
    return pid_file.exists()


def test_whole_hello_separates_strategies(agent, tls_server):
    be, env = agent
    port, seen = tls_server
    t = Target("blk-large", f"https://blocked.test:{port}/", "test", kind=LARGE_HELLO)
    ips = {"blk-large": ["127.0.0.1"]}
    eng = TachyonDesync()
    good = be.run_batch(eng, {"mode": "multi_disorder", "split_pos": "1,midsld"}, [t], ips, reps=2)
    bad = be.run_batch(eng, {"mode": "fake_disorder", "split_pos": "host+1"}, [t], ips, reps=2)
    assert [r.verdict for r in good.results] == ["ok", "ok"]
    assert good.results[0].tls_ms > 0 and good.results[0].ttfb_ms == good.results[0].tls_ms
    assert [r.verdict for r in bad.results] == ["tls_reset", "tls_reset"]
    assert [n for n in seen if n] == [HELLO_BYTES, HELLO_BYTES]     # only the working strategy reached the server
    assert not _running(env)                        # the engine is stopped after the batch


def test_large_targets_do_not_reach_the_agent_job():
    jobs = []

    class Recording(NoForwarding):
        def call(self, args, stdin="", timeout=600):
            jobs.append((args[0], stdin))
            return '{"t":"done","ok":true}\n'

        def connect(self, host, port, timeout):
            return Scripted([b"\x05\x00", b"\x05\x00\x00\x01", b"\x00" * 6, SERVER_HELLO])

    be = AgentBackend(Recording(), ProbeSettings(interval_ms=0))
    plain = Target("a", "https://a.example/", "test")
    large = Target("a-large", "https://a.example/", "test", kind=LARGE_HELLO)
    batch = be.run_batch(TachyonDesync(), {"mode": "split"}, [plain, large], {}, reps=1)
    assert [name for name, _ in jobs] == ["run", "hold", "stop"]
    assert "target a ipv4" in jobs[0][1] and "a-large" not in jobs[0][1]
    assert "target" not in jobs[1][1]
    assert [r.target for r in batch.results] == ["a-large"]


def test_baseline_without_engine_connects_directly(agent, tls_server):
    be, env = agent
    be.settings.baseline_via_core = False
    port, _ = tls_server
    t = Target("x-large", f"https://open.test:{port}/", "test", kind=LARGE_HELLO)
    batch = be.run_batch(TachyonDesync(), None, [t], {"x-large": ["127.0.0.1"]}, reps=1)
    assert [r.verdict for r in batch.results] == ["ok"]


def test_hold_stops_by_itself_when_the_controller_disappears(agent):
    be, env = agent
    job = be.build_job(TachyonDesync(), {"mode": "split"}, [], {}, 1)
    be.transport.call(["hold", "1"], stdin=job, timeout=20)
    pid = int((Path(env["ADF_STATE"]) / "engine.pid").read_text())
    os.kill(pid, 0)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and _running(env):
        time.sleep(0.1)
    assert not _running(env)
    with pytest.raises(ProcessLookupError):
        for _ in range(30):
            os.kill(pid, 0)
            time.sleep(0.1)


def test_stop_ends_a_held_engine(agent):
    be, env = agent
    job = be.build_job(TachyonDesync(), {"mode": "split"}, [], {}, 1)
    be.transport.call(["hold", "60"], stdin=job, timeout=20)
    assert _running(env)
    be.transport.call(["stop"], timeout=20)
    assert not _running(env)
    assert not (Path(env["ADF_STATE"]) / "hold.pid").exists()


def test_rejected_config_is_reported_as_engine_failure(agent):
    be, env = agent
    be.transport.env["FAKE_CORE_REJECT"] = "mode"
    t = Target("x-large", "https://a.example/", "test", kind=LARGE_HELLO)
    batch = be.run_batch(TachyonDesync(), {"mode": "split"}, [t], {"x-large": ["127.0.0.1"]}, reps=1)
    assert batch.engine_failed and "rejected" in batch.engine_error


def test_unreachable_engine_stops_the_run_with_a_clear_message():
    be = AgentBackend(NoForwarding(), ProbeSettings(interval_ms=0))
    t = Target("x-large", "https://a.example/", "test", kind=LARGE_HELLO)
    with pytest.raises(BackendError, match="large_hello = false"):
        be.run_batch(TachyonDesync(), {"mode": "split"}, [t], {"x-large": ["192.0.2.1"]}, reps=1)


def test_ssh_stream_carries_a_hello_through_ssh_w(tmp_path, tls_server):
    port, seen = tls_server
    fake = tmp_path / "ssh"
    fake.write_text(f"""#!{sys.executable}
import os, socket, sys, threading
args = sys.argv[1:]
assert "BatchMode=yes" in args and "-q" in args
host, port = args[args.index("-W") + 1].rsplit(":", 1)
s = socket.create_connection((host, int(port)))
def down():
    while True:
        data = s.recv(65536)
        if not data:
            os._exit(0)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
threading.Thread(target=down, daemon=True).start()
while True:
    data = os.read(0, 65536)
    if not data:
        os._exit(0)
    s.sendall(data)
""")
    fake.chmod(0o755)
    stream = SSHTransport(host="192.0.2.1", ssh=str(fake)).connect("127.0.0.1", port, 5)
    try:
        verdict, ms, error = exchange(stream, client_hello("a.example"), 5)
    finally:
        stream.close()
    assert (verdict, error) == ("ok", "") and ms > 0
    assert seen == [HELLO_BYTES]


def test_ssh_stream_end_of_stream_stays_visible(tmp_path):
    fake = tmp_path / "ssh"
    fake.write_text("#!/bin/sh\nexit 255\n")
    fake.chmod(0o755)
    stream = SSHTransport(host="192.0.2.1", ssh=str(fake)).connect("127.0.0.1", 1, 5)
    try:
        assert stream.recv(4, 5) == b"" and stream.recv(4, 5) == b""
    finally:
        stream.close()


def test_ssh_stream_times_out(tmp_path):
    fake = tmp_path / "ssh"
    fake.write_text("#!/bin/sh\nexec sleep 30\n")
    fake.chmod(0o755)
    stream = SSHTransport(host="192.0.2.1", ssh=str(fake)).connect("127.0.0.1", 1, 5)
    try:
        with pytest.raises(TimeoutError):
            stream.recv(4, 0.05)
    finally:
        stream.close()


# ---------------------------------------------------------------------- search
def _guard():
    return Guard(Budget(max_batches=400, max_probes=4000, max_seconds=60), SafetyPolicy(min_batch_interval_s=0),
                 sleeper=lambda s: None)


def _targets():
    return with_large_hello([Target("yt", "https://yt.example/", "youtube", min_bytes=1000),
                             Target("ytv", "https://v.example/", "youtube")])


def test_search_rejects_a_strategy_that_only_passes_curl(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    controls = [Target("ctl", "https://ctl.example/", "control")]
    orch = Orchestrator(store, SimulatedBackend(), TachyonDesync(), _targets(), controls, guard=_guard(),
                        config=SearchConfig(network_id="net", seed=3, use_history=False))
    summary = orch.run()
    best = summary["best"]
    assert best is not None and "yt-large" in best["targets"]
    split_pos = dict(p.split("=") for p in best["text"].split()).get("split_pos", "")
    assert "," in split_pos or split_pos.isdigit() or "mode=tlsrec" in best["text"]


def test_core_change_starts_a_new_epoch(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    store.current_epoch("net-sim")
    store.start_run("net-sim", "tachyon_desync", "tachyon-core 0.3.4", "agent", True, {})
    before = store.current_epoch("net-sim")

    class NewCore(SimulatedBackend):
        def env(self):
            return dict(super().env(), core_version="tachyon-core 0.3.7")

    controls = [Target("ctl", "https://ctl.example/", "control")]
    logs = []
    Orchestrator(store, NewCore(), TachyonDesync(), _targets(), controls, guard=_guard(),
                 config=SearchConfig(network_id="net-sim", seed=3, use_history=False), log=logs.append).run()
    assert store.current_epoch("net-sim") == before + 1
    assert any("0.3.4 -> tachyon-core 0.3.7" in m or "core changed" in m for m in logs)
    assert store.last_engine_version("net-sim", "tachyon_desync") == "tachyon-core 0.3.7"


def test_same_core_keeps_the_epoch(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    controls = [Target("ctl", "https://ctl.example/", "control")]
    for _ in range(2):
        Orchestrator(store, SimulatedBackend(), TachyonDesync(), _targets(), controls, guard=_guard(),
                     config=SearchConfig(network_id="net", seed=3, use_history=False)).run()
    assert len(store.epochs("net")) == 1


def test_compare_records_the_core_version(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    v = [Variant("a", strategy=from_text(TachyonDesync(), "mode=fake_split split_pos=1 fake_ttl=6")),
         Variant("b", strategy=from_text(TachyonDesync(), "mode=split split_pos=1"))]
    summary = compare(store, SimulatedBackend(), TachyonDesync(), v, _targets(), [], {}, 2, "net", _guard())
    assert summary["engine_version"] == "simulated"
    assert store.runs(1)[0]["engine_version"] == "simulated"


def test_compare_reports_why_the_engine_refused_a_variant(tmp_path):
    class Refusing(SimulatedBackend):
        def run_batch(self, engine, params, targets, ips, reps=1, stop_on_fail=False):
            if params and params.get("mode") == "split":
                return BatchResult(ok=False, engine_error="config rejected: unknown field")
            return super().run_batch(engine, params, targets, ips, reps, stop_on_fail)

    store = Store(tmp_path / "a.sqlite")
    v = [Variant("good", strategy=from_text(TachyonDesync(), "mode=fake_split split_pos=1 fake_ttl=6")),
         Variant("bad", strategy=from_text(TachyonDesync(), "mode=split split_pos=1"))]
    logs = []
    summary = compare(store, Refusing(), TachyonDesync(), v, _targets(), [], {}, 2, "net", _guard(), log=logs.append)
    rows = {r["label"]: r for r in summary["rows"]}
    assert rows["bad"]["error"] == "config rejected: unknown field" and rows["good"]["error"] == ""
    assert sum("config rejected" in m for m in logs) == 1
    assert "* bad: config rejected: unknown field" in compare_report(summary["rows"], summary)


def test_cli_compare_measures_strategies_given_as_text(tmp_path, capsys):
    config = tmp_path / "c.toml"
    config.write_text(f'[paths]\ndb = "{(tmp_path / "a.sqlite").as_posix()}"\n')
    code = main(["-c", str(config), "compare", "--simulate", "--categories", "youtube", "--no-adaptive", "--reps", "3",
                 "--strategy", "mode=multi_disorder split_pos=1,sniext+1,midsld fake_ttl=10 repeats=4::multi",
                 "--strategy", "mode=fake_disorder split_pos=host+1 fake_ttl=10 repeats=4::host1"])
    assert code == 0
    report = capsys.readouterr().out
    assert "youtube-www-large" in report and "Untested" not in report


def test_failed_plain_probe_skips_large_hellos_on_stop_on_fail():
    calls = []

    class Failing(NoForwarding):
        def call(self, args, stdin="", timeout=600):
            calls.append(args[0])
            return ('{"t":"probe","target":"a","code":0,"exit":28,"ta":0}\n'
                    '{"t":"stopped_on_fail","target":"a"}\n{"t":"done","ok":true}\n')

    be = AgentBackend(Failing(), ProbeSettings(interval_ms=0))
    targets = [Target("a", "https://a.example/", "test"), Target("a-large", "https://a.example/", "test", kind=LARGE_HELLO)]
    batch = be.run_batch(TachyonDesync(), {"mode": "split"}, targets, {}, reps=1, stop_on_fail=True)
    assert calls == ["run"]
    assert [r.target for r in batch.results] == ["a"]


def test_large_targets_can_be_selected_by_id():
    from adf.cli import _targets
    from adf.config import AppConfig

    class Args:
        categories = None
        only = "youtube-www-large"
        targets = None

    targets, _ = _targets(AppConfig(), Args())
    assert [t.id for t in targets] == ["youtube-www-large"]
