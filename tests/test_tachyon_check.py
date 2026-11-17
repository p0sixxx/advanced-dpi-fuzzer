from adf.integrations.tachyon_check import CHECK_CMD, UCI_FILTER, analyze, report

RAW = """== tachyon
1.8.0
== core
tachyon-core 0.5.9
== uci
tachyon.Main=section
tachyon.Main.action='connection'
tachyon.Main.balancer_refs='bal_main'
tachyon.Main.outbound_group_levels='grp_eu' 'srv:hschn'
tachyon.bal_main=balancer
tachyon.bal_main.name='Main balancer'
tachyon.bal_main.balancer_type='priority'
tachyon.grp_eu=outbound_group
tachyon.grp_eu.name='Europe'
tachyon.YT=section
tachyon.YT.action='desync'
tachyon.YT.desync_preset='custom'
tachyon.YT.desync_mode='fake_split'
tachyon.YT.desync_split_pos='1'
tachyon.YT2=section
tachyon.YT2.action='desync'
tachyon.YT2.desync_preset='auto'
tachyon.YT2.desync_opts='mode=fake_split'
== amnezia
Main\tamnezia_configs\t0\thschn
== end
"""


def test_priority_backup_ok_and_rename_impact():
    res = analyze(RAW, backup=["hschn"], rename=["hschn", "AmneziaWG 2.0 Amsterdam"])
    b = res.balancers[0]
    assert b.type == "priority" and b.levels == ["Europe", "hschn"] and b.used_by == ["Main"]
    texts = " ".join(f.text for f in res.findings)
    assert "OK" in texts and "srv:hschn" in texts and "имя Amnezia" in texts
    assert "desync_opts" in texts or "игнорируется" in texts          # YT2
    assert "auto_tune не задан" in texts                               # YT on core 0.5
    assert not any(f.level == "error" for f in res.findings)
    assert "Main balancer" in report(res)


def test_urltest_with_backup_is_error():
    raw = RAW.replace("balancer_type='priority'", "balancer_type='urltest'").replace(
        "tachyon.Main.outbound_group_levels='grp_eu' 'srv:hschn'\n", "").replace(
        "tachyon.bal_main.name='Main balancer'", "tachyon.bal_main.name='Main balancer'\n"
                                                 "tachyon.bal_main.source_refs='src_eu src_hschn'")
    raw = raw.replace("tachyon.grp_eu=outbound_group", "tachyon.src_hschn=outbound_source\n"
                      "tachyon.src_hschn.name='hschn'\ntachyon.grp_eu=outbound_group")
    res = analyze(raw, backup=["hschn"])
    assert any(f.level == "error" and "urltest" in f.text for f in res.findings)


def test_backup_not_last_is_error():
    raw = RAW.replace("'grp_eu' 'srv:hschn'", "'srv:hschn' 'grp_eu'")
    res = analyze(raw, backup=["hschn"])
    assert any(f.level == "error" and "ступени 1" in f.text for f in res.findings)


REFS_ONLY = """== tachyon
1.8.0
== core
tachyon-core 0.5.9
== uci
tachyon.Main=section
tachyon.Main.action='connection'
tachyon.Main.balancer_refs='Failover'
tachyon.Main.outbound_source_refs='upcloud_stockholm' 'amneziawg_2_0_amsterdam'
tachyon.Failover=balancer
tachyon.Failover.balancer_type='priority'
tachyon.Failover.name='Failover'
tachyon.upcloud_stockholm=outbound_source
tachyon.upcloud_stockholm.source_type='amnezia_config'
tachyon.upcloud_stockholm.name='AmneziaWG 3.1 Stockholm'
tachyon.amneziawg_2_0_amsterdam=outbound_source
tachyon.amneziawg_2_0_amsterdam.source_type='amnezia_config'
tachyon.amneziawg_2_0_amsterdam.name='AmneziaWG 2.0 Amsterdam'
tachyon.off=outbound_source
tachyon.off.enabled='0'
tachyon.off.name='Disabled'
== amnezia
upcloud_stockholm\tamnezia_configs\t0\tAmneziaWG 3.1 Stockholm
amneziawg_2_0_amsterdam\tamnezia_configs\t0\tAmneziaWG 2.0 Amsterdam
== end
"""


def test_priority_order_from_section_source_refs():
    # Tachyon 1.8.0 without outbound_group_levels: order = section's outbound_source_refs
    res = analyze(REFS_ONLY, backup=["Amsterdam"])
    b = res.balancers[0]
    assert b.levels == ["AmneziaWG 3.1 Stockholm", "AmneziaWG 2.0 Amsterdam"]
    assert "outbound_source_refs" in b.order_from and "Main" in b.order_from
    assert any(f.level == "info" and "OK" in f.text for f in res.findings)
    assert not any(f.level == "error" for f in res.findings)
    assert "(из источники секции Main" in report(res)


def test_priority_order_backup_first_is_error():
    raw = REFS_ONLY.replace("'upcloud_stockholm' 'amneziawg_2_0_amsterdam'",
                            "'amneziawg_2_0_amsterdam' 'upcloud_stockholm' 'off'")
    res = analyze(raw, backup=["Amsterdam"])
    assert res.balancers[0].levels == ["AmneziaWG 2.0 Amsterdam", "AmneziaWG 3.1 Stockholm"]  # disabled skipped
    assert any(f.level == "error" and "ступени 1" in f.text for f in res.findings)


def test_balancer_settings_levels_win():
    raw = REFS_ONLY.replace(
        "tachyon.Main.balancer_refs='Failover'",
        "tachyon.Main.balancer_refs='Failover'\n"
        "tachyon.Main.balancer_settings='{\"Failover\":{\"outbound_group_levels\":"
        "[\"amneziawg_2_0_amsterdam\",\"upcloud_stockholm\"]}}'")
    b = analyze(raw).balancers[0]
    assert b.levels == ["AmneziaWG 2.0 Amsterdam", "AmneziaWG 3.1 Stockholm"]
    assert b.order_from == "Main.balancer_settings"


def test_router_command_collects_no_secrets():
    for secret in ("private_key", "PrivateKey", "subscription_url", "password", "amnezia_conf_text"):
        assert secret not in UCI_FILTER
    assert "j.name" in CHECK_CMD and "config" not in CHECK_CMD.split("j.name")[1][:40]
