import json
import os
import socket
import struct
import subprocess
from pathlib import Path

import pytest

from adf.db import Store
from adf.engines import TachyonDesync
from adf.probe.backend import AgentBackend, BackendError, DPIModel, ProbeSettings, SimulatedBackend, Transport
from adf.probe.dns import A, AAAA, addresses, check_server, describe, query, resolver_config
from adf.probe.model import BatchResult, ProbeResult, Target
from adf.probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS
from adf.report import compare_report, run_report
from adf.safety import Budget, Guard, SafetyPolicy
from adf.search.compare import Variant, compare
from adf.search.dnscheck import other_networks, run_check, verdict
from adf.search.orchestrator import Orchestrator, SearchConfig
from adf.strategy import from_text

AGENT = Path(__file__).resolve().parents[1] / "agent" / "adf-agent.sh"
BAD, GOOD = "64.233.161.198", "142.251.127.198"
HOST = "redirector.googlevideo.com"
ALIDNS = {"type": "https", "tag": "dns-server", "server": "dns.alidns.com", "server_port": 443, "path": "/dns-query",
          "tls": {"enabled": True, "server_name": "dns.alidns.com"}, "domain_resolver": "bootstrap-dns-server"}
BOOTSTRAP = {"type": "udp", "tag": "bootstrap-dns-server", "server": "1.0.0.1", "server_port": 53}


def answer(message, *ips):
    """An answer with a CNAME before the addresses, the way a CDN replies."""
    question = message[12:]
    out = message[:2] + struct.pack(">HHHHH", 0x8180, 1, len(ips) + 1, 0, 0) + question
    out += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
    for ip in ips:
        data = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        out += b"\xc0\x0c" + struct.pack(">HHIH", AAAA if ":" in ip else A, 1, 60, len(data)) + data
    return out


class DnsStream:
    def __init__(self, table):
        self.table = table
        self.reply = b""

    def send(self, data):
        message = data[2:]
        host = []
        i = 12
        while message[i]:
            host.append(message[i + 1:i + 1 + message[i]].decode())
            i += message[i] + 1
        qtype = struct.unpack(">H", message[i + 1:i + 3])[0]
        if ".".join(host) == "silent.test":
            raise TimeoutError("no answer")
        ips = [ip for ip in self.table.get(".".join(host), []) if (":" in ip) == (qtype == AAAA)]
        body = answer(message, *ips)
        self.reply += struct.pack(">H", len(body)) + body

    def recv(self, n, timeout):
        out, self.reply = self.reply[:n], self.reply[n:]
        return out

    def close(self):
        pass


class FakeTransport(Transport):
    def __init__(self, live=None, other=None, server=ALIDNS, hold='{"t":"engine","ok":true}'):
        self.tables = {11290: live or {}, 11291: other or {}}
        self.server = server
        self.hold = hold
        self.calls = []
        self.job = ""

    def call(self, args, stdin="", timeout=600):
        self.calls.append(args[0])
        if args[0] == "live-dns":
            return json.dumps({"t": "dns", "server": self.server, "bootstrap": BOOTSTRAP}) + "\n"
        if args[0] == "hold":
            self.job = stdin
            if self.hold is None:
                raise BackendError("agent failed")
            return self.hold + "\n"
        if args[0] == "resolve":
            return "77.88.8.9\n"
        return ""

    def connect(self, host, port, timeout):
        return DnsStream(self.tables[port])

    def describe(self):
        return "fake"


def test_answer_parsing_skips_cname_and_keeps_both_families():
    message = answer(query(HOST, A), GOOD, "2a00:1450:4010:c0f::c6")
    assert addresses(message) == [GOOD, "2a00:1450:4010:c0f::c6"]


def test_failed_or_truncated_answer_gives_nothing():
    message = answer(query(HOST, A), GOOD)
    assert addresses(message[:3] + bytes([message[3] | 3]) + message[4:]) == []
    assert addresses(message[:-2]) == []


def test_check_server_is_independent_from_the_live_one():
    assert check_server(ALIDNS)["tls"]["server_name"] == "dns.google"
    google = dict(ALIDNS, server="dns.google", tls={"enabled": True, "server_name": "dns.google"})
    assert check_server(google)["server"] == "77.88.8.8"
    assert check_server(dict(type="udp", server="8.8.8.8"))["server"] == "77.88.8.8"


def test_resolver_config_copies_the_live_server():
    cfg = resolver_config(dict(ALIDNS, detour="Main-out"), BOOTSTRAP, check_server(ALIDNS), 11290, 7)
    servers = {s["tag"]: s for s in cfg["dns"]["servers"]}
    assert servers["adf-live"]["server"] == "dns.alidns.com"
    assert servers["adf-live"]["domain_resolver"] == "adf-bootstrap"
    assert "detour" not in servers["adf-live"]
    assert cfg["route"]["default_domain_resolver"] == "adf-bootstrap"
    assert [i["listen_port"] for i in cfg["inbounds"]] == [11290, 11291]
    assert cfg["outbounds"][0]["routing_mark"] == 7


def test_any_server_type_is_described():
    assert describe(ALIDNS) == "DoH dns.alidns.com"
    assert describe({"type": "tls", "server": "1.1.1.1"}) == "DoT 1.1.1.1"
    assert describe({"type": "udp", "server": "8.8.8.8"}) == "UDP 8.8.8.8"


def test_addresses_come_from_the_live_dns_through_the_core():
    transport = FakeTransport({HOST: [BAD]}, {HOST: [GOOD]})
    be = AgentBackend(transport)
    be.prepare_dns([HOST])
    assert be.resolve(HOST) == [BAD]
    assert be.other_addresses(HOST) == [GOOD]
    assert be.dns_info() == {"live": "DoH dns.alidns.com", "check": "DoH dns.google", "note": ""}
    assert "resolve" not in transport.calls
    assert transport.calls[-1] == "stop"            # the temporary engine does not stay
    assert '"dns.alidns.com"' in transport.job


def test_fakeip_answers_are_not_used():
    be = AgentBackend(FakeTransport({HOST: ["198.18.3.167"]}))
    be.prepare_dns([HOST])
    assert be.resolve(HOST) == ["77.88.8.9"]        # plain DNS
    assert be.dns_info()["note"] == "no_answers"


def test_unanswered_host_falls_back_and_the_report_says_so():
    be = AgentBackend(FakeTransport({HOST: [GOOD]}))
    be.prepare_dns([HOST, "silent.test"])
    assert be.resolve(HOST) == [GOOD]
    assert be.resolve("silent.test") == ["77.88.8.9"]
    assert be.dns_info()["note"] == "partial"


@pytest.mark.parametrize("transport, note", [
    (FakeTransport(server=None), "no_live_dns"),
    (FakeTransport(hold=None), "core_failed"),
    (FakeTransport(hold='{"t":"engine","ok":false,"error":"config rejected"}'), "core_failed"),
])
def test_without_the_core_plain_dns_is_used(transport, note):
    be = AgentBackend(transport)
    be.prepare_dns([HOST])
    assert be.resolve(HOST) == ["77.88.8.9"]
    assert be.dns_info() == {"live": "77.88.8.8", "check": "", "note": note}
    assert be.other_addresses(HOST) == []


def test_configured_server_keeps_working_without_the_core():
    transport = FakeTransport()
    be = AgentBackend(transport, ProbeSettings(dns_server="9.9.9.9"))
    be.prepare_dns([HOST])
    assert be.resolve(HOST) == ["77.88.8.9"]
    assert transport.calls == ["resolve"]
    assert be.dns_info() == {"live": "9.9.9.9", "check": "", "note": "configured"}
    assert be.core_config(TachyonDesync(), None)["dns"]["servers"][0]["server"] == "9.9.9.9"


def test_check_can_be_switched_off():
    be = AgentBackend(FakeTransport({HOST: [BAD]}, {HOST: [GOOD]}), ProbeSettings(dns_check=False))
    be.prepare_dns([HOST])
    assert be.other_addresses(HOST) == []
    assert be.dns_info()["check"] == ""


def test_detour_is_reported():
    be = AgentBackend(FakeTransport({HOST: [GOOD]}, server=dict(ALIDNS, detour="Main-out")))
    be.prepare_dns([HOST])
    assert be.dns_info()["note"] == "detour"


def test_rotation_inside_a_network_is_not_a_difference():
    assert other_networks(["142.251.150.4"], ["142.251.150.9"]) == []
    assert other_networks([BAD], [GOOD, "142.251.127.200", "1.2.3.4", "5.6.7.8"]) == [GOOD, "1.2.3.4"]
    assert other_networks([], [GOOD]) == [GOOD]


@pytest.mark.parametrize("live, other, expected", [
    (1.0, 1.0, "ok"), (0.0, 1.0, "dns"), (0.0, 0.0, "strategy"), (0.67, 1.0, "unclear"), (0.34, 0.67, "unclear"),
])
def test_verdict(live, other, expected):
    assert verdict(live, other) == expected


class TwoAddresses(SimulatedBackend):
    """The strategy passes everywhere except on ``bad``, which the core's DNS returns."""

    bad = BAD

    def __init__(self, broken=(BAD,), other=(GOOD,)):
        super().__init__(DPIModel(seed=7))
        self.broken = broken
        self.other = other

    def other_addresses(self, host):
        return list(self.other)

    def dns_info(self):
        return {"live": "DoH dns.alidns.com", "check": "DoH dns.google", "note": ""}


def measure_with(broken):
    def measure(targets, ips, reps):
        batch = BatchResult(ok=True)
        for t in targets:
            for ip in ips[t.id][:t.max_ips]:
                for rep in range(reps):
                    batch.results.append(ProbeResult(t.id, "ipv4", ip, "tls_timeout" if ip in broken else "ok"))
        return batch
    return measure


def test_todays_failure_is_blamed_on_dns():
    t = Target("youtube-video", f"https://{HOST}/", "youtube", max_ips=1)
    done = run_check(TwoAddresses(), measure_with({BAD}), [t], {t.id: [BAD]})
    row = done["rows"][0]
    assert (row["live_ok"], row["live_n"], row["other_ok"], row["other_n"]) == (0, 3, 3, 3)
    assert row["verdict"] == "dns"


def test_failure_on_both_addresses_is_blamed_on_the_strategy():
    t = Target("youtube-video", f"https://{HOST}/", "youtube")
    done = run_check(TwoAddresses(), measure_with({BAD, GOOD}), [t], {t.id: [BAD]})
    assert done["rows"][0]["verdict"] == "strategy"


def test_every_other_address_is_measured_despite_max_ips():
    t = Target("youtube-video", f"https://{HOST}/", "youtube", max_ips=1)
    be = TwoAddresses(other=(GOOD, "1.2.3.4"))
    done = run_check(be, measure_with(set()), [t], {t.id: [BAD]})
    assert done["rows"][0]["other_n"] == 6


def test_addresses_outside_the_target_family_are_ignored():
    t = Target("youtube-video", f"https://{HOST}/", "youtube", max_ips=1)
    be = TwoAddresses(other=("2a00:1450:4001:c21::c6", GOOD, "1.2.3.4"))
    row = run_check(be, measure_with(set()), [t], {t.id: [BAD, "2a00:1450:4010:c01::c6"]})["rows"][0]
    assert row["live"] == [BAD]
    assert row["other"] == [GOOD, "1.2.3.4"]


def test_report_lists_only_the_targets_that_need_attention():
    ok = Target("youtube-www", "https://www.youtube.com/", "youtube")
    bad = Target("youtube-video", f"https://{HOST}/", "youtube")
    check = run_check(TwoAddresses(), measure_with({BAD}), [ok, bad], {ok.id: ["1.2.3.4"], bad.id: [BAD]})
    assert len(check["rows"]) == 2
    text = compare_report([], dict(dns_check=check))
    assert "| youtube-video |" in text and "| youtube-www |" not in text
    assert "разошлись на 2 целях" in text and "работает на 1 из них" in text


def test_target_without_live_address_is_still_checked():
    t = Target("youtube-video", f"https://{HOST}/", "youtube")
    done = run_check(TwoAddresses(), measure_with(set()), [t], {t.id: []})
    assert done["rows"][0]["live_n"] == 0
    assert done["rows"][0]["verdict"] == "dns"


def test_quic_targets_are_left_out():
    t = Target("q", f"https://{HOST}/", "youtube", kind="quic")
    assert run_check(TwoAddresses(), measure_with(set()), [t], {t.id: [BAD]})["rows"] == []


def test_engine_failure_is_reported_not_raised():
    t = Target("youtube-video", f"https://{HOST}/", "youtube")

    def measure(targets, ips, reps):
        return BatchResult(ok=False, engine_error="config rejected")
    done = run_check(TwoAddresses(), measure, [t], {t.id: [BAD]})
    assert done["rows"] == [] and done["error"] == "config rejected"


def guard():
    return Guard(Budget(max_batches=60, max_probes=10 ** 6), SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0),
                 sleeper=lambda s: None)


def test_search_report_names_the_dns_as_the_cause(monkeypatch):
    be = TwoAddresses()
    monkeypatch.setattr("adf.search.orchestrator.run_check", lambda b, m, targets, ips, log: run_check(
        b, measure_with({BAD}), targets[:1], {targets[0].id: [BAD]}, log))
    orch = Orchestrator(Store(":memory:"), be, TachyonDesync(), DEFAULT_TARGETS[:3], DEFAULT_CONTROLS,
                        SearchConfig(seed=7), guard())
    text = run_report(orch.run())
    assert "## Проверка DNS" in text
    assert "`DoH dns.alidns.com`" in text and "`DoH dns.google`" in text
    assert "виноват DNS" in text and "Смените основной DNS" in text


def test_compare_measures_the_best_variant_on_both_sets():
    be = TwoAddresses()
    engine = TachyonDesync()
    targets = DEFAULT_TARGETS[:2]
    ips = {t.id: [BAD] for t in targets}
    variants = [Variant("a", from_text(engine, "mode=multi_disorder split_pos=1,midsld fake_ttl=10")),
                Variant("b", from_text(engine, "mode=split split_pos=1"))]
    meta = compare(Store(":memory:"), be, engine, variants, targets, [], ips, 2, "n", guard())
    assert meta["dns_check"]["live"] == "DoH dns.alidns.com"
    assert meta["dns_check"]["rows"]
    assert "## Проверка DNS" in compare_report(meta["rows"], meta)


def test_simulated_run_has_no_dns_section():
    s = Orchestrator(Store(":memory:"), SimulatedBackend(DPIModel(seed=7)), TachyonDesync(), DEFAULT_TARGETS[:2],
                     DEFAULT_CONTROLS, SearchConfig(seed=7), guard()).run()
    assert "Проверка DNS" not in run_report(s)


def agent_live_dns(tmp_path, config):
    fake = tmp_path / "bin" / "jsonfilter"
    fake.parent.mkdir()
    fake.write_text(
        "#!/bin/sh\n"
        "# stands for OpenWrt's jsonfilter: prints the value this expression selects\n"
        'case "$4" in\n'
        "  '@.dns.final') echo dns-server ;;\n"
        f"  *'\"dns-server\"].domain_resolver') echo {BOOTSTRAP['tag']} ;;\n"
        f"  *'\"dns-server\"]') echo '{json.dumps(ALIDNS)}' ;;\n"
        f"  *'\"{BOOTSTRAP['tag']}\"]') echo '{json.dumps(BOOTSTRAP)}' ;;\n"
        "esac\n")
    fake.chmod(0o755)
    env = dict(os.environ, ADF_CORE_CONFIG=str(config), ADF_STATE=str(tmp_path / "state"),
               PATH=f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    return json.loads(subprocess.run(["sh", str(AGENT), "live-dns"], env=env, capture_output=True, text=True,
                                     check=True).stdout)


def test_agent_reads_only_the_dns_objects(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"outbounds": [{"password": "secret"}]}')
    out = agent_live_dns(tmp_path, config)
    assert out["server"] == ALIDNS
    assert out["bootstrap"] == BOOTSTRAP
    assert "secret" not in json.dumps(out)


def test_agent_without_a_live_config_says_so(tmp_path):
    assert agent_live_dns(tmp_path, tmp_path / "missing.json") == {"t": "dns", "server": None, "bootstrap": None}
