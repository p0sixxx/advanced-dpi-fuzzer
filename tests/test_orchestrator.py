import json

import pytest

from adf.bench import bench, tachyon_v2_candidates, true_quality
from adf.cli import main
from adf.db import Store
from adf.engines import TachyonDesync
from adf.probe.backend import DPIModel, SimulatedBackend
from adf.probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS
from adf.safety import Budget, Guard, SafetyPolicy, StopRequested
from adf.search.compare import Variant, compare
from adf.search.orchestrator import Orchestrator, SearchConfig
from adf.strategy import from_text


def guard(batches=150):
    return Guard(Budget(max_batches=batches, max_probes=10 ** 6),
                 SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0), sleeper=lambda s: None)


def test_search_finds_good_strategy():
    model = DPIModel(seed=7)
    targets = DEFAULT_TARGETS[:4]
    orch = Orchestrator(Store(":memory:"), SimulatedBackend(model), TachyonDesync(), targets, DEFAULT_CONTROLS,
                        SearchConfig(seed=7), guard(200))
    s = orch.run()
    assert s["status"] == "finished"
    assert s["best"] is not None
    assert true_quality(model, targets, s["best"]["params"]) >= 0.9
    assert s["unique_tested"] < s["pool_size"]  # no exhaustive enumeration


def test_named_strategy_is_measured_on_every_target():
    store = Store(":memory:")
    engine = TachyonDesync()
    named = from_text(engine, "mode=fake_disorder split_pos=1 fake_ttl=10 repeats=4", origin="user")
    orch = Orchestrator(store, SimulatedBackend(DPIModel(seed=7)), engine, DEFAULT_TARGETS[:4], DEFAULT_CONTROLS,
                        SearchConfig(seed=7, network_id="isp"), guard(40), extra=[named])
    orch.run()
    measured = store.trials("isp", True, strategy_ids=[named.id])
    assert {r["target_id"] for r in measured} >= {t.id for t in orch.active}


def test_aborts_when_nothing_blocked():
    model = DPIModel(seed=1, rules={"*": lambda p: 0.99})
    orch = Orchestrator(Store(":memory:"), SimulatedBackend(model), TachyonDesync(), DEFAULT_TARGETS[:2],
                        DEFAULT_CONTROLS, SearchConfig(), guard(20))
    s = orch.run()
    assert s["status"] == "aborted" and "nothing to optimise" in s["error"]


def test_unreachable_targets_excluded():
    class Unreach(SimulatedBackend):
        def run_batch(self, engine, params, targets, ips, reps=1, stop_on_fail=False):
            b = super().run_batch(engine, params, targets, ips, reps, stop_on_fail)
            for r in b.results:
                if r.target == "google-www":
                    r.verdict = "connect_failed"
            return b

    orch = Orchestrator(Store(":memory:"), Unreach(DPIModel(seed=2)), TachyonDesync(), DEFAULT_TARGETS[:3],
                        DEFAULT_CONTROLS, SearchConfig(seed=2), guard(40))
    s = orch.run()
    assert s["baseline"]["google-www"]["status"] == "unreachable"
    assert all("google-www" not in r["targets"] for r in s["top"])


def test_network_down_invalidates_and_aborts():
    class FlakyControls(SimulatedBackend):
        calls_after_baseline = 0

        def run_batch(self, engine, params, targets, ips, reps=1, stop_on_fail=False):
            b = super().run_batch(engine, params, targets, ips, reps, stop_on_fail)
            if params is None and reps == 1:  # control batches
                for r in b.results:
                    r.verdict = "tls_timeout"
            return b

    pol = SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0, control_every=3, max_control_failures=3)
    g = Guard(Budget(max_batches=100), pol, sleeper=lambda s: None)
    store = Store(":memory:")
    orch = Orchestrator(store, FlakyControls(DPIModel(seed=3)), TachyonDesync(), DEFAULT_TARGETS[:2],
                        DEFAULT_CONTROLS, SearchConfig(seed=3), g)
    s = orch.run()
    assert s["status"] == "aborted" and "network appears down" in s["error"]
    rows = store.run_trials(s["run_id"])
    assert any(r["verdict"] == "network_down" for r in rows)


def test_history_is_reused_and_drift_detected():
    store = Store(":memory:")
    targets = DEFAULT_TARGETS[:3]
    s1 = Orchestrator(store, SimulatedBackend(DPIModel(seed=4)), TachyonDesync(), targets, DEFAULT_CONTROLS,
                      SearchConfig(seed=4, network_id="isp"), guard(150)).run()
    best = s1["best"]["params"]
    # second run: the censor changed, the previous winner no longer works
    broken = DPIModel(seed=5)
    orig = broken.default_rule

    def rule(t, p):
        if p is not None and p == best:
            return 0.05
        return orig(t, p)

    broken.default_rule = rule
    o2 = Orchestrator(store, SimulatedBackend(broken), TachyonDesync(), targets, DEFAULT_CONTROLS,
                      SearchConfig(seed=5, network_id="isp"), guard(150))
    s2 = o2.run()
    assert any(c.origin == "history" for c in o2.pool.values())
    assert s2.get("drift", {}).get("drifted"), s2.get("drift")
    assert store.current_epoch("isp") == 1


def test_stop_file(tmp_path):
    stop = tmp_path / "STOP"
    stop.write_text("1")
    g = Guard(Budget(), SafetyPolicy(stop_file=stop, min_batch_interval_s=0), sleeper=lambda s: None)
    g.start()
    with pytest.raises(StopRequested):
        g.check()


def test_compare_round_robin():
    store = Store(":memory:")
    eng = TachyonDesync()
    good = from_text(eng, "mode=multi_disorder split_pos=1,midsld fake_ttl=6 repeats=2")
    bad = from_text(eng, "mode=split split_pos=1")
    be = SimulatedBackend(DPIModel(seed=1))
    out = compare(store, be, eng, [Variant("good", good), Variant("bad", bad),
                                   Variant("adaptive", outbound={"type": "desync", "preset": "auto"})],
                  DEFAULT_TARGETS[:2], DEFAULT_CONTROLS, {}, 8, "n", guard())
    rows = {r["label"]: r for r in out["rows"]}
    assert rows["good"]["rate"] > rows["bad"]["rate"]
    assert rows["good"]["min_n"] == 8


def test_tachyon_v2_emulation_has_redundant_candidates():
    c = tachyon_v2_candidates(TachyonDesync())
    unique = {repr(sorted(p.items())) for _, p in c}
    assert len(unique) < len(c) * 0.7  # disorder/fake ignore parameters Tachyon still iterates


def test_bench_smoke():
    rows = bench(seeds=[1], n_targets=3)
    algs = {r.algorithm for r in rows}
    assert algs == {"tachyon_v2_emulation", "adf_equal_budget", "adf_default"}


def test_cli_smoke(tmp_path, capsys):
    db = str(tmp_path / "c.sqlite")
    assert main(["validate", "mode=fake_split split_pos=1 fake_ttl=6"]) == 0
    assert main(["validate", "mode=split split_pos=1,midsld"]) == 1
    assert main(["generate", "--limit", "3"]) == 0
    capsys.readouterr()
    assert main(["--db", db, "run", "--simulate", "--max-batches", "60", "--only", "youtube-www,discord-www",
                 "--json"]) == 0
    out = capsys.readouterr().out
    summary = json.loads(out[out.index("{"):])
    assert summary["simulated"] and summary["best"]
    assert main(["--db", db, "best", "--simulated"]) == 0
    assert main(["export", "mode=fake_split split_pos=1 fake_ttl=6", "--section", "yt"]) == 0
    assert "uci set tachyon.yt.desync_preset=custom" in capsys.readouterr().out
    assert main(["methods", "--engine", "byedpi"]) == 0
    assert main(["--db", db, "db", "stats"]) == 0
