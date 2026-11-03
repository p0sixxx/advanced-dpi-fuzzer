import json

import pytest

from adf.db import Store
from adf.engines import TachyonDesync
from adf.integrations import tachyon as ti
from adf.probe.backend import AgentBackend, LocalTransport, ProbeSettings, parse_lines
from adf.probe.model import Target, classify
from adf.probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS, load_targets
from adf.strategy import from_text

T = Target("t", "https://example.org/", min_bytes=32768, body_regex="ex")


@pytest.mark.parametrize("raw,verdict", [
    ({"code": 200, "exit": 0, "size": 50000, "content": 1}, "ok"),
    ({"code": 200, "exit": 0, "size": 16000, "content": 1}, "cutoff_16k"),
    ({"code": 200, "exit": 0, "size": 500, "content": 1}, "short_body"),
    ({"code": 200, "exit": 0, "size": 50000, "content": 0}, "content_mismatch"),
    ({"code": 400, "exit": 0, "size": 100}, "server_rejected"),
    ({"code": 502, "exit": 0}, "server_error"),
    ({"code": 0, "exit": 28, "ta": 0}, "tls_timeout"),
    ({"code": 200, "exit": 28, "ta": 0.2, "size": 20000}, "cutoff_16k"),
    ({"code": 0, "exit": 35}, "tls_reset"),
    ({"code": 0, "exit": 56, "size": 12000}, "cutoff_16k"),
    ({"code": 0, "exit": 60}, "tls_cert"),
    ({"code": 0, "exit": 6}, "dns_fail"),
    ({"code": 0, "exit": 7}, "connect_failed"),
    ({"code": 0, "exit": 97}, "proxy_error"),
])
def test_classify(raw, verdict):
    r = classify(raw, T)
    assert r.verdict == verdict
    assert r.counts == (verdict == "ok" or verdict not in ("dns_fail", "connect_failed", "proxy_error",
                                                          "server_error"))


def test_target_validation():
    with pytest.raises(ValueError):
        Target("bad id!", "https://x.org/").validate()
    with pytest.raises(ValueError):
        Target("x", "https://x.org/", body_regex="a b").validate()
    for t in DEFAULT_TARGETS + DEFAULT_CONTROLS:
        t.validate()


def test_load_targets(tmp_path):
    p = tmp_path / "t.toml"
    p.write_text('[[target]]\nid="a"\nurl="https://a.org/"\ncategory="x"\nfamilies=["ipv4","ipv6"]\n'
                 '[[control]]\nid="c"\nurl="https://c.org/"\n')
    d = load_targets(p)
    assert d["targets"][0].families == ("ipv4", "ipv6") and d["controls"][0].id == "c"


def test_job_protocol():
    be = AgentBackend(LocalTransport(), ProbeSettings(port=1234, routing_mark=0x08000000))
    eng = TachyonDesync()
    s = from_text(eng, "mode=fake_split split_pos=1 fake_ttl=6 repeats=2")
    t6 = Target("v6", "https://x.org/", families=("ipv4", "ipv6"), max_ips=1)
    job = be.build_job(eng, s.params, [t6], {"v6": ["1.2.3.4", "2001:db8::1"]}, reps=2, stop_on_fail=True)
    lines = job.splitlines()
    assert lines[0] == "ADF-JOB 1" and lines[-1] == "end"
    assert "stop_on_fail 1" in lines and "engine tachyon" in lines
    cfg = json.loads(lines[lines.index("config-begin") + 1])
    assert cfg["outbounds"][0]["routing_mark"] == 0x08000000 and cfg["inbounds"][0]["listen"] == "127.0.0.1"
    targets = [l for l in lines if l.startswith("target ")]
    assert any("ipv4" in l and "1.2.3.4" in l for l in targets)
    assert any("ipv6" in l and "2001:db8::1" in l for l in targets)
    base = be.build_job(eng, None, [t6], {}, reps=1)
    assert '"type": "direct"' in base


def test_parse_lines_skips_garbage():
    assert parse_lines('noise\n{"t":"done"}\n{broken\n') == [{"t": "done"}]


def test_store_roundtrip(tmp_path):
    from adf.probe.model import ProbeResult
    st = Store(tmp_path / "a.sqlite")
    eng = TachyonDesync()
    s = from_text(eng, "mode=split split_pos=1")
    st.upsert_strategy(s)
    run = st.start_run("net", eng.name, "v", "agent", False, {})
    st.add_trials(run, s.id, [ProbeResult("t", "ipv4", "1.1.1.1", "ok", 200), ProbeResult("t", "ipv4", "", "tls_reset")],
                  "net", 0, False, "search")
    assert len(st.trials("net", False)) == 2
    mark = st.max_trial_id(run)
    st.add_trials(run, s.id, [ProbeResult("t", "ipv4", "", "tls_reset")], "net", 0, False, "search")
    assert st.invalidate_since(run, mark) == 1
    rows = st.trials("net", False)
    assert sum(r["counts"] for r in rows) == 2
    st.finish_run(run, "finished", {"x": 1})
    assert st.current_epoch("net") == 0 and st.new_epoch("net", "drift") == 1
    out = tmp_path / "e.jsonl"
    n = st.export_jsonl(out)
    st2 = Store(tmp_path / "b.sqlite")
    assert st2.import_jsonl(out) == n
    assert len(st2.trials("net", False)) == 3
    st.backup(tmp_path / "backup.sqlite")
    assert Store(tmp_path / "backup.sqlite").get_strategy(s.id).text == s.text


UCI_SHOW = """tachyon.settings=settings
tachyon.yt=section
tachyon.yt.action='desync'
tachyon.yt.desync_preset='auto'
tachyon.yt.desync_auto_tune='1'
tachyon.yt.desync_fooling='autottl'
tachyon.yt.desync_split_pos='1'
tachyon.yt.desync_opts='mode=fake_split split_pos=1 fake_ttl=6 fake_sni=max.ru repeats=6'
tachyon.dc=section
tachyon.dc.action='desync'
tachyon.dc.desync_preset='custom'
tachyon.dc.desync_mode='fake_split'
tachyon.dc.desync_split_pos='midsld+7'
tachyon.dc.desync_opts='fooling=md5 repeats=4 bogus=1'
tachyon.px=section
tachyon.px.action='connection'
"""


def test_import_reflects_tachyon_semantics():
    cfg = ti.parse_uci_show(UCI_SHOW)
    assert ti.desync_sections(cfg) == ["yt", "dc"]
    yt = ti.section_to_params("yt", cfg["yt"])
    assert yt.kind == "adaptive" and yt.ignored_opts.startswith("mode=fake_split")
    dc = ti.section_to_params("dc", cfg["dc"])
    assert dc.kind == "fixed"
    assert dc.params["mode"] == "fake_split" and dc.params["fooling"] == "md5" and dc.params["repeats"] == 4
    # midsld+7 is dropped by Tachyon, so the core runs its default position
    assert "split_pos" not in dc.outbound and dc.params["split_pos"] == "midsld"
    assert dc.params["split_delay_ms"] == 1  # absent option = core default, not "off"
    assert any("bogus" in n for n in dc.notes) and any("midsld+7" in n for n in dc.notes)


def test_import_real_router_layout():
    """Section layout reported from a GL.iNet Flint 2 (OpenWrt 25.12.6, tachyon-core 0.3.4)."""
    show = """tachyon.YouTube_desync=section
tachyon.YouTube_desync.action='desync'
tachyon.YouTube_desync.desync_preset='auto'
tachyon.YouTube_desync.desync_fake_sni='max.ru'
tachyon.YouTube_desync.desync_opts='mode=fake_split split_pos=1 fake_ttl=6 fake_sni=max.ru repeats=6'
tachyon.YouTube_desync.desync_split_pos='1'
tachyon.YouTube_desync.desync_fake_ttl='6'
tachyon.YouTube_desync.desync_repeats='6'
tachyon.YouTube_desync.desync_fooling='autottl'
tachyon.src_api=outbound_source
tachyon.src_api.source_type='desync'
tachyon.src_api.desync_preset='custom'
tachyon.src_api.desync_mode='fake_split'
tachyon.src_api.desync_split_pos='1'
tachyon.src_api.desync_fake_ttl='6'
tachyon.src_api.desync_fooling='autottl'
"""
    cfg = ti.parse_uci_show(show)
    assert ti.desync_sections(cfg) == ["YouTube_desync", "src_api"]
    yt = ti.section_to_params("YouTube_desync", cfg["YouTube_desync"])
    assert yt.kind == "adaptive" and yt.params is None
    assert yt.outbound == {"type": "desync", "preset": "auto", "fooling": "autottl", "split_pos": 1, "fake_ttl": 6,
                           "repeats": 6, "fake_sni": "max.ru"}
    api = ti.section_to_params("src_api", cfg["src_api"])
    assert api.outbound["mode"] == "fake_split" and "preset" not in api.outbound
    assert api.params["fooling"] == "autottl" and api.params["repeats"] == 1


def test_export_import_round_trip():
    eng = TachyonDesync(measure_udp=True)
    s = from_text(TachyonDesync(), "mode=multi_disorder split_pos=1,sniext+1,midsld fooling=md5_badack fake_ttl=5 "
                                   "fake_sni=max.ru repeats=2 split_delay_ms=1 seqovl=0 syndata=1")
    plan = ti.plan_apply(UCI_SHOW, "yt", s, reload=False)
    assert "uci set tachyon.yt.desync_preset=custom" in plan.script
    assert "uci set tachyon.yt.desync_auto_tune=0" in plan.script
    assert "tachyon reload" not in plan.script
    # simulate the resulting UCI state and import it back
    state = {".type": "section", "action": "desync"}
    for opt, val in plan.new_options.items():
        if val is not None:
            state[opt] = val
    back = ti.section_to_params("yt", state, eng)
    assert eng.canonicalize(back.params) == eng.canonicalize(s.params)
    assert back.auto_tune is False
    assert "uci set tachyon.yt.desync_preset=auto" in plan.rollback_script


def test_apply_refuses_non_desync_section():
    s = from_text(TachyonDesync(), "mode=split split_pos=1")
    with pytest.raises(ValueError):
        ti.plan_apply(UCI_SHOW, "px", s)
    with pytest.raises(ValueError):
        ti.uci_commands("bad;rm -rf /", {"a": "b"})


def test_example_configs_load(tmp_path):
    from pathlib import Path
    from adf.config import load_config
    root = Path(__file__).resolve().parents[1] / "examples"
    cfg = load_config(root / "config.toml")
    assert cfg.router.host and cfg.probe.routing_mark == 0x08000000
    assert cfg.targets_file.name == "targets.toml"
    loaded = load_targets(cfg.targets_file)
    assert loaded["targets"] and loaded["controls"]
    bad = tmp_path / "bad.toml"
    bad.write_text('[router]\nhost="x"\npassword="secret"\n')
    with pytest.raises(ValueError, match="secrets"):
        load_config(bad)


HISTORY = {"entries": [
    {"timestamp": 1793517713, "engine": "desync", "target": "youtube_suite", "mode": "presets",
     "best_strategy": {"name": "Fake + Split", "args": "mode=fake_split split_pos=1 fake_ttl=4 repeats=6",
                       "stability_pct": 33, "confidence": "low"}, "total_tested": 18, "working_count": 1,
     "dpi_detection": {"type": "drop", "details": "TCP connect timed out for x",
                       "probe_metrics": {"error": "TLS handshake stalled after TCP connect"}}, "duration_sec": 76},
    {"timestamp": 1793518096, "engine": "desync", "target": "youtube_suite", "mode": "adaptive",
     "best_strategy": {"name": "⭐ Prior Winner: ⭐ Prior Winner: Fake + Split",
                       "args": "mode=fake_split split_pos=1 fake_ttl=4 repeats=6", "stability_pct": 100},
     "total_tested": 18, "working_count": 1, "dpi_detection": {"type": "drop"}, "duration_sec": 50},
    {"timestamp": 1793517563, "engine": "desync", "target": "custom", "mode": "presets",
     "best_strategy": {"args": "preset=oob", "stability_pct": 100}, "total_tested": 18, "working_count": 18,
     "dpi_detection": {"type": "none", "details": "Target directly accessible"}, "duration_sec": 28},
    {"timestamp": 1793030633, "engine": "zapret2", "target": "youtube_suite", "mode": "presets",
     "best_strategy": {"args": "--lua-desync=fake:blob=tls_google:repeats=8:tcp_ts=-600000:tcp_ts_up "
                               "--lua-desync=multisplit:pos=1:seqovl=681:seqovl_pattern=tls_google"},
     "dpi_detection": {"type": "drop"}},
]}


def test_tachyon_history_analysis():
    from adf.integrations.tachyon_history import analyze, markdown
    res = analyze(HISTORY)
    text = " ".join(res["findings"])
    assert "not blocked" in text and "stability 33%, 100%" in text
    assert "nested" in text and "TCP connect timed out" in text
    engines = sorted(s.engine for s in res["strategies"])
    assert engines == ["tachyon_desync", "tachyon_desync", "zapret2"]
    # absent options = tachyon-core defaults, as the Tachyon fuzzer probe ran them
    fs = [s for s in res["strategies"] if "fake_ttl=4" in s.text][0]
    assert fs.params["split_delay_ms"] == 1
    assert "youtube_suite" in markdown(res)


def test_compare_current_section(tmp_path, capsys):
    from adf.cli import main
    uci = tmp_path / "uci.txt"
    uci.write_text(UCI_SHOW)
    db = str(tmp_path / "c.sqlite")
    assert main(["--db", db, "compare", "--simulate", "--current", "yt", "--current", "dc", "--uci-file", str(uci),
                 "--no-adaptive", "--reps", "3", "--only", "youtube-www"]) == 0
    out = capsys.readouterr().out
    assert "current: yt" in out and "current: dc" in out and "СИМУЛЯЦИЯ" in out
