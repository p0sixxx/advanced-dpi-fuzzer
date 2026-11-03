import pytest

from adf.engines import ByeDPI, StrategyError, TachyonDesync, Zapret, Zapret2, get_engine
from adf.engines.tachyon_desync import (PROFILE_PUBLIC_SOURCE, capabilities_from_probe, capability_profile,
                                        caps_test_matrix, normalize_pos)
from adf.strategy import from_text, make_strategy


@pytest.mark.parametrize("name", ["tachyon_desync", "zapret", "zapret2", "byedpi"])
def test_seeds_round_trip(name):
    eng = get_engine(name)
    seeds = eng.seeds()
    assert seeds
    for _, params in seeds:
        text = eng.render(params)
        assert eng.canonicalize(eng.parse(text)) == params
        assert eng.check(params) is None


@pytest.mark.parametrize("name", ["tachyon_desync", "zapret", "zapret2", "byedpi"])
def test_mutations_and_simplifications_are_valid(name):
    eng = get_engine(name)
    for _, params in eng.seeds()[:5]:
        for cand in eng.mutations(params) + eng.simplifications(params):
            assert eng.check(cand) is None
            assert eng.canonicalize(cand) == cand


def test_simplifications_are_strictly_simpler():
    eng = TachyonDesync()
    p = eng.canonicalize(eng.parse("mode=multi_disorder split_pos=1,sniext+1,midsld fooling=md5_badack fake_ttl=5 "
                                   "repeats=6 split_delay_ms=2 seqovl=0 syndata=1"))
    for s in eng.simplifications(p):
        assert eng.complexity(s) < eng.complexity(p)


def test_desync_canonical_equivalence():
    eng = TachyonDesync()
    # fooling/TTL/SNI do not apply to plain split: equivalent configurations share one id
    a = make_strategy(eng, {"mode": "split", "split_pos": "midsld", "fake_ttl": 4, "fake_sni": "max.ru"})
    b = make_strategy(eng, {"mode": "split", "split_pos": "sld"})
    assert a.id == b.id
    # split position does not apply to mode=fake
    c = make_strategy(eng, {"mode": "fake", "split_pos": "1", "fake_ttl": 6})
    d = make_strategy(eng, {"mode": "fake", "split_pos": "midsld", "fake_ttl": 6})
    assert c.id == d.id


@pytest.mark.parametrize("text,err", [
    ("mode=split split_pos=1,midsld", "single split position"),
    ("mode=multi_split split_pos=midsld", "at least two"),
    ("mode=fake_split split_pos=sld+3", "not understood"),
    ("mode=fake_split fooling=hopbyhop", "IPv6-only"),
    ("mode=split split_pos=2 seqovl=4", "seqovl must be smaller"),
    ("mode=bogus", "unknown mode"),
    ("mode=fake_split udp_fake=1", "UDP parameters"),
])
def test_desync_rejects(text, err):
    eng = TachyonDesync()
    with pytest.raises(StrategyError, match=err):
        from_text(eng, text)


def test_desync_aliases_follow_tachyon_translator():
    eng = TachyonDesync()
    p = eng.parse("dpi_desync=fakeddisorder --dpi-desync-split-pos=sni+1 fooling=tcp_md5 ttl=5")
    assert p["mode"] == "multi_disorder"
    assert p["split_pos"] == "sniext+1"
    assert p["fooling"] == "md5"
    assert p["fake_ttl"] == 5


def test_desync_outbound_json():
    eng = TachyonDesync()
    s = from_text(eng, "mode=multi_split split_pos=1,sniext+1,midsld split_delay_ms=2")
    ob = eng.outbound(s.params, routing_mark=0x08000000)
    assert ob["split_pos"] == [1, "sniext+1", "midsld"]
    assert ob["auto_tune"] is False and ob["routing_mark"] == 134217728
    assert "seqovl" not in ob and "fooling" not in ob


def test_hopbyhop_allowed_for_ipv6_only():
    eng6 = get_engine("tachyon_desync", families=("ipv6",))
    from_text(eng6, "mode=fake_split split_pos=1 fooling=hopbyhop fake_ttl=6 repeats=1")


def test_public_source_profile_limits_space():
    caps = capability_profile(PROFILE_PUBLIC_SOURCE)
    eng = TachyonDesync()
    names = {f.name for f in eng.factors(caps)}
    assert "fooling" not in names and "seqovl" not in names
    modes = eng.factor_map(caps)["mode"].values
    assert "multi_disorder" not in modes and "fake_split" in modes
    with pytest.raises(StrategyError):
        make_strategy(eng, {"mode": "split", "split_pos": "sniext+1"}, caps=caps)


def test_capabilities_from_probe():
    tests = caps_test_matrix()
    results = []
    for t in tests:
        ok = not (t["key"] == "fooling" or (t["key"] == "mode" and t["value"] == "multi_disorder"))
        results.append({"key": t["key"], "value": t["value"], "ok": ok})
    caps = capabilities_from_probe({"host": "r", "version": "0.3.4", "results": results})
    assert "fooling" in caps.unsupported
    assert not caps.accepts("mode", "multi_disorder")
    assert caps.accepts("mode", "fake_split")


def test_normalize_pos():
    assert normalize_pos("1, SNI+1 ,host") == "1,sniext+1,midsld"
    with pytest.raises(StrategyError):
        normalize_pos("0")


def test_zapret_v1_grammar():
    eng = Zapret()
    with pytest.raises(StrategyError, match="not an nfqws v1 fooling"):
        from_text(eng, "--dpi-desync=fake,multisplit --dpi-desync-fooling=badack --dpi-desync-split-pos=1")
    with pytest.raises(StrategyError):
        # nfqws2 syntax inside nfqws1 (found in Tachyon presets)
        from_text(eng, "--dpi-desync=hostfakesplit --dpi-desync-fooling=badsum,tcp_seq=1000000")
    s = from_text(eng, "--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=md5sig")
    assert "--dpi-desync-fooling=md5sig" in s.text


def test_zapret2_fooling_args_are_direct():
    eng = Zapret2()
    with pytest.raises(StrategyError, match="fooling="):
        eng.parse("--lua-desync=fake:blob=tls_google:repeats=6:fooling=badsum")
    s = from_text(eng, "--lua-desync=fake:blob=tls_google:repeats=6:badsum --lua-desync=multidisorder:pos=1,midsld")
    assert ":badsum" in s.text and "fooling" not in s.text
    with pytest.raises(StrategyError, match="reach the server"):
        make_strategy(eng, {"fake": True, "fooling": "none", "fake_ttl": 0})


def test_byedpi_grammar():
    eng = ByeDPI()
    with pytest.raises(StrategyError, match="invalid --auto"):
        eng.parse("-o 1 --auto=t,r,a,s -d 1")
    with pytest.raises(StrategyError):
        from_text(eng, "-s midsld")
    s = from_text(eng, "-f 1+s -t 6 -S -n max.ru")
    assert s.params["md5sig"] is True


def test_strategy_ids_are_stable():
    eng = TachyonDesync()
    a = from_text(eng, "mode=fake_split split_pos=1 fake_ttl=6 repeats=6")
    b = from_text(eng, "repeats=6 fake_ttl=6 split_pos=1 mode=fakesplit")
    assert a.id == b.id and a.text == b.text
