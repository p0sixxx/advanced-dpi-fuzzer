import builtins
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

from adf import check, cli, connect, console, live, ui
from adf.config import AppConfig, default_config
from adf.db import Store
from adf.engines import TachyonDesync
from adf.integrations import tachyon as tachyon_int
from adf.probe.backend import DPIModel, SimulatedBackend
from adf.probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS
from adf.safety import Budget, Guard, SafetyPolicy
from adf.search.compare import Variant, compare
from adf.search.orchestrator import Orchestrator, SearchConfig
from adf.strategy import from_text

PLAIN = console.Terminal(False)
COLOR = console.Terminal(True)


def test_width_counts_cyrillic_and_ignores_colors():
    assert console.visible_width(COLOR.style("Цель", "red")) == 4


def test_fit_keeps_escape_sequences_whole():
    text = COLOR.style("абвгдежзик", "green")
    short = console.fit(text, 5)
    assert console.visible_width(short) == 5
    assert short.startswith("\x1b[32m") and short.endswith("\x1b[0m")


def test_table_aligns_by_visible_width():
    lines = console.table(["Цель", "Успехов"], [[COLOR.style("a", "red"), "1/2"], ["длинная цель", "10/20"]], right=(1,))
    assert len({console.visible_width(line) for line in lines}) == 1


@pytest.mark.parametrize("seconds, text", [(None, "—"), (65, "01:05"), (3725, "1:02:05")])
def test_clock(seconds, text):
    assert console.clock(seconds) == text


def test_bar_stays_in_bounds():
    assert console.bar(2.0, 4) == "████" and console.bar(-1, 4) == "░░░░"


def test_plain_screen_prints_only_when_the_key_changes(capsys):
    screen = console.Screen(PLAIN)
    screen.draw(["a"], key="1")
    screen.draw(["b"], key="1")
    screen.draw(["c"], key="2")
    assert capsys.readouterr().out.split() == ["a", "c"]


def test_ansi_screen_clears_lines_left_by_a_taller_frame(capsys):
    screen = console.Screen(COLOR)
    screen.draw(["1", "2", "3"])
    capsys.readouterr()
    screen.draw(["1"])
    out = capsys.readouterr().out
    assert out.startswith("\x1b[3A") and out.count("\x1b[2K") == 3 and out.endswith("\x1b[2A")


def test_snapshot_round_trip(tmp_path):
    path = tmp_path / "x" / "check.json"
    live.write(path, {"status": live.RUNNING, "pid": os.getpid()})
    assert live.read(path)["pid"] == os.getpid()
    assert list(path.parent.iterdir()) == [path]
    assert live.active(live.read(path))


def test_missing_snapshot_is_none(tmp_path):
    assert live.read(tmp_path / "none.json") is None


def dead_pid():
    p = subprocess.Popen([sys.executable, "-c", ""])
    p.wait()
    return p.pid


def test_job_that_died_is_reported_as_failed():
    pid = dead_pid()
    assert not live.process_alive(pid)
    assert live.settled({"status": live.RUNNING, "pid": pid})["status"] == live.FAILED


def test_finished_snapshot_is_left_alone():
    assert live.settled({"status": live.FINISHED, "pid": 0})["status"] == live.FINISHED


WINDOWS_ROUTES = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.8.1   192.168.8.197     25
"""


@pytest.mark.parametrize("text, gateway", [
    (WINDOWS_ROUTES, "192.168.8.1"), ("default via 10.0.0.1 dev eth0 proto dhcp\n", "10.0.0.1"), ("nothing", ""),
])
def test_gateway(text, gateway):
    assert connect.parse_gateway(text) == gateway


def test_windows_key_path_survives_toml():
    text = connect.toml_router("192.168.8.1", "root", 22, Path(r"C:\Users\me\.ssh\adf_router"))
    assert tomllib.loads(text)["router"]["identity"].endswith("adf_router")
    assert "\\.ssh" in tomllib.loads(text)["router"]["identity"] or "/.ssh" in tomllib.loads(text)["router"]["identity"]


def test_setup_keeps_other_sections():
    old = "[search]\nnetwork_id = 'home'\n\n[router]\nhost = 'old'\n\n[probe]\nport = 1\n"
    merged = tomllib.loads(connect.merged_config(old, connect.toml_router("new", "root", 22, Path("k"))))
    assert merged["router"]["host"] == "new"
    assert merged["search"]["network_id"] == "home" and merged["probe"]["port"] == 1


def test_install_keeps_the_key_list_free_of_duplicates():
    assert "grep -qxF" in connect.INSTALL_KEY and "/etc/dropbear/authorized_keys" in connect.INSTALL_KEY


def test_config_from_setup_is_found(tmp_path, monkeypatch):
    monkeypatch.setenv("ADF_HOME", str(tmp_path))
    assert default_config() is None
    (tmp_path / "config.toml").write_text("[router]\nhost = 'r'\n", encoding="utf-8")
    assert default_config() == tmp_path / "config.toml"


# `uci show tachyon` as a Flint 2 prints it, reduced by the same filter as on the router
UCI_SHOW = """
tachyon.settings=settings
tachyon.settings.dns_server='https://common.dot.dns.yandex.net/dns-query'
tachyon.YouTube_desync=section
tachyon.YouTube_desync.enabled='1'
tachyon.YouTube_desync.action='desync'
tachyon.YouTube_desync.community_lists='youtube'
tachyon.YouTube_desync.condition_refs='cond_Youtube'
tachyon.YouTube_desync.desync_mode='fake_disorder'
tachyon.YouTube_desync.desync_preset='custom'
tachyon.YouTube_desync.desync_split_pos='endhost-1'
tachyon.Meta=section
tachyon.Meta.enabled='1'
tachyon.Meta.action='desync'
tachyon.Meta.condition_refs='cond_Meta'
tachyon.Meta.desync_preset='custom'
tachyon.cond_Meta=condition
tachyon.cond_Meta.community_lists='other' 'meta'
tachyon.Off=section
tachyon.Off.enabled='0'
tachyon.Off.action='desync'
tachyon.Off.community_lists='discord'
tachyon.Off.desync_preset='custom'
tachyon.Main=section
tachyon.Main.enabled='1'
tachyon.Main.action='connection'
tachyon.Main.community_lists='youtube' 'telegram'
"""


def as_fetched():
    keep = re.compile(tachyon_int.UCI_FILTER)
    return tachyon_int.parse_uci_show("\n".join(line for line in UCI_SHOW.splitlines() if keep.search(line)))


@pytest.mark.parametrize("service, section", [("youtube", "YouTube_desync"), ("instagram", "Meta"), ("discord", None),
                                              ("telegram", None)])
def test_section_of_a_service(service, section):
    assert check.find_section(as_fetched(), service) == section


def test_filter_still_leaves_urls_out():
    assert "settings" not in as_fetched() or "dns_server" not in as_fetched()["settings"]


def row(k, n=10, required=True):
    return {"label": "x", "k": k, "n": n, "required": required, "verdicts": {}}


@pytest.mark.parametrize("rows, dns, status", [
    ({"a": row(10), "b": row(10, required=False)}, None, "ok"),
    ({"a": row(10), "b": row(5, required=False)}, None, "warn"),
    ({"a": row(8)}, None, "warn"),
    ({"a": row(3, 5)}, None, "warn"),
    ({"a": row(0, 5)}, None, "fail"),
    ({"a": row(2)}, None, "fail"),
    ({"a": row(0)}, {"rows": [{"target": "a", "verdict": "dns"}]}, "dns"),
    ({}, None, "unknown"),
])
def test_verdict_of_a_service(rows, dns, status):
    assert check.judge(rows, dns)["status"] == status


def run_job(tmp_path, mode, services=("youtube",), stop=False):
    cfg = AppConfig(db=tmp_path / "adf.sqlite", stop_file=tmp_path / "STOP")
    cfg.search.max_batches = 25
    job = check.Job(cfg, check.Spec(mode, list(services), simulate=True), tmp_path / "check.json", tmp_path / "reports", cli)
    if stop:
        real = job.step

        def stopping(fraction, **fields):
            cfg.stop_file.write_text("x")
            real(fraction, **fields)
        job.step = stopping
    code = job.run()
    return code, live.read(tmp_path / "check.json")


def test_quick_check_reports_every_target(tmp_path):
    code, snapshot = run_job(tmp_path, check.CURRENT)
    assert code == 0 and snapshot["status"] == live.FINISHED and snapshot["fraction"] == 1.0
    result = snapshot["results"][0]
    assert result["status"] in ("ok", "no_bypass") and result["section"] is None
    assert any("как Chrome" in s["label"] for s in result["rows"].values())
    assert Path(snapshot["report"]).read_text(encoding="utf-8").startswith("# Проверка")


def test_each_service_gets_its_own_result(tmp_path):
    _, snapshot = run_job(tmp_path, check.CURRENT, ("youtube", "discord"))
    assert [r["service"] for r in snapshot["results"]] == ["youtube", "discord"]


def test_full_check_measures_the_candidate_next_to_the_current(tmp_path):
    _, snapshot = run_job(tmp_path, check.FULL)
    result = snapshot["results"][0]
    assert result["candidate"]["rows"] and result["search"]["tested"] > 0
    with Store(tmp_path / "adf.sqlite").tx() as c:
        labels = json.loads(c.execute("SELECT config FROM runs ORDER BY id DESC LIMIT 1").fetchone()[0])["compare"]
    assert labels == ["без обхода", "найдена"]


def test_stop_ends_the_check_and_keeps_the_report(tmp_path):
    code, snapshot = run_job(tmp_path, check.CURRENT, ("youtube", "discord"), stop=True)
    assert code == 0 and snapshot["status"] == live.STOPPED
    assert len(snapshot["results"]) == 1 and Path(snapshot["report"]).exists()


def test_router_failure_ends_with_a_readable_error(tmp_path, monkeypatch):
    def broken(cfg, args):
        raise cli.BackendError("ssh: connect to host port 22: Connection refused")
    monkeypatch.setattr(cli, "_backend", broken)
    code, snapshot = run_job(tmp_path, check.CURRENT)
    assert code == 1 and snapshot["status"] == live.FAILED
    assert "Connection refused" in "\n".join(ui.result_lines(snapshot, PLAIN))


def guard():
    return Guard(Budget(max_batches=30, max_probes=10 ** 6), SafetyPolicy(min_batch_interval_s=0, backoff_initial_s=0),
                 sleeper=lambda s: None)


def test_search_reports_progress_with_a_leader():
    seen = []
    Orchestrator(Store(":memory:"), SimulatedBackend(DPIModel(seed=7)), TachyonDesync(), DEFAULT_TARGETS[:3],
                 DEFAULT_CONTROLS, SearchConfig(seed=7), guard(), on_progress=seen.append).run()
    assert {"search", "final"} <= {p["phase"] for p in seen}
    leading = [p for p in seen if p["best"]]
    assert leading and leading[-1]["tested"] > 0 and leading[-1]["best"]["targets"]


def test_compare_reports_each_round():
    seen = []
    engine = TachyonDesync()
    targets = DEFAULT_TARGETS[:2]
    variant = Variant("a", from_text(engine, "mode=multi_disorder split_pos=1,midsld fake_ttl=10"))
    compare(Store(":memory:"), SimulatedBackend(DPIModel(seed=7)), engine, [variant], targets, [], {t.id: [] for t in targets},
            3, "n", guard(), on_progress=seen.append)
    assert [p["round"] for p in seen] == [1, 2, 3] and seen[-1]["fraction"] == 1


SNAPSHOT = {
    "mode": check.QUICK, "services": ["youtube", "discord"], "service": "youtube", "index": 0, "started": 1000.0,
    "fraction": 0.25, "phase": "search", "tested": 12, "pool": 296, "probes": 340, "detail": "mode=split",
    "best": {"text": "mode=fake_disorder", "lb": 0.9, "rate": 1.0, "targets": {}},
    "table": {"a": dict(row(9), label="www.youtube.com как Chrome")}, "verdicts": {"ok": 9, "tls_reset": 1}, "log": [],
}


def test_live_screen_shows_what_is_happening():
    text = "\n".join(ui.render(SNAPSHOT, PLAIN, now=1100.0))
    for part in ("быстрая проверка", "YouTube (1 из 2)", "25 %", "прошло 01:40", "≈ 05:00", "поиск стратегий",
                 "проверено 12 из 296", "Лучшая пока: mode=fake_disorder", "www.youtube.com как Chrome", "9/10",
                 "сброс 1", "adf watch"):
        assert part in text


def test_no_estimate_at_the_very_start():
    assert "оценивается" in "\n".join(ui.render(dict(SNAPSHOT, fraction=0.0), PLAIN, now=1001.0))


def result(**fields):
    return dict({"service": "youtube", "name": "YouTube", "section": "YouTube_desync", "current": "mode=split",
                 "status": "ok", "rows": {"a": dict(row(10), label="www.youtube.com")}, "lb": 0.5}, **fields)


def final(*results, **fields):
    return dict({"mode": check.CURRENT, "status": live.FINISHED, "results": list(results), "report": "r.md"}, **fields)


def test_result_says_when_dns_is_at_fault():
    dns = {"live": "DoH dns.alidns.com", "check": "DoH dns.google", "rows": [
        {"target": "youtube-video", "host": "redirector.googlevideo.com", "verdict": "dns", "live_ok": 0, "live_n": 3,
         "other_ok": 3, "other_n": 3}]}
    text = "\n".join(ui.result_lines(final(result(status="dns", dns=dns, dns_targets=["youtube-video"])), PLAIN))
    for part in ("YouTube: ВИНОВАТ DNS", "DoH dns.alidns.com", "адреса ядра 0/3, адреса сверки 3/3", "Смените основной DNS"):
        assert part in text


def test_no_bypass_is_not_called_a_failure():
    text = "\n".join(ui.result_lines(final(result(status="no_bypass", section=None)), PLAIN))
    assert "ОБХОД НЕ НАСТРОЕН" in text and "НЕ РАБОТАЕТ" not in text and "adf check --full" in text


def test_host_of_two_targets_is_listed_once():
    rows = [{"target": t, "host": "www.youtube.com", "verdict": "strategy", "live_ok": 0, "live_n": 3, "other_ok": 0,
             "other_n": 3} for t in ("youtube-www", "youtube-www-large")]
    text = "\n".join(ui.result_lines(final(result(dns={"live": "DoH x", "rows": rows})), PLAIN))
    assert text.count("www.youtube.com:") == 1 and "на 1 хостах" in text


def test_shaky_target_is_named_with_advice_to_repeat():
    rows = {"a": dict(row(3, 5), label="youtubei.googleapis.com как Chrome")}
    done = result(status="warn", rows=rows, shaky=["a"], optional=[])
    text = "\n".join(ui.result_lines(final(done), PLAIN))
    assert "ЕСТЬ ЗАМЕЧАНИЯ" in text and "youtubei.googleapis.com как Chrome" in text and "Повторите проверку" in text


def test_failing_service_points_to_the_full_check():
    text = "\n".join(ui.result_lines(final(result(status="fail")), PLAIN))
    assert "НЕ РАБОТАЕТ" in text and "adf check --full --services youtube" in text


BETTER = {"id": "ta-1", "text": "mode=x", "lb": 0.9, "rate": 1.0, "better": True}


def answers(monkeypatch, *replies):
    queue = list(replies)
    monkeypatch.setattr(builtins, "input", lambda prompt="": queue.pop(0))


def applied(monkeypatch):
    calls = []
    monkeypatch.setattr(check, "apply_candidate", lambda cli_, config, r: calls.append(r["section"]) or 0)
    return calls


def test_nothing_is_applied_without_a_typed_yes(monkeypatch, capsys):
    calls = applied(monkeypatch)
    answers(monkeypatch, "")
    ui.offer_apply(final(result(candidate=BETTER)), cli, None, PLAIN)
    assert calls == []


def test_typed_yes_applies_to_the_section_of_that_service(monkeypatch, capsys):
    calls = applied(monkeypatch)
    answers(monkeypatch, "да")
    ui.offer_apply(final(result(candidate=BETTER)), cli, None, PLAIN)
    assert calls == ["YouTube_desync"]
    assert "adf rollback --section YouTube_desync" in capsys.readouterr().out


@pytest.mark.parametrize("snapshot", [
    final(result(candidate=dict(BETTER, better=False))),
    final(result(candidate=BETTER, section=None)),
    final(result(candidate=BETTER), simulated=True),
])
def test_no_offer_when_there_is_nothing_to_apply(snapshot, monkeypatch):
    calls = applied(monkeypatch)
    answers(monkeypatch)
    ui.offer_apply(snapshot, cli, None, PLAIN)
    assert calls == []


def test_service_choice(monkeypatch, capsys):
    answers(monkeypatch, "2, 1,99")
    assert ui.choose_services(["youtube"]) == ["discord", "youtube"]
    answers(monkeypatch, "")
    assert ui.choose_services(["discord"]) == ["discord"]


def test_all_services_at_once(monkeypatch, capsys):
    answers(monkeypatch, str(len(check.SERVICES) + 1))
    assert ui.choose_services(["youtube"]) == list(check.SERVICES)


def test_going_back_picks_nothing(monkeypatch, capsys):
    answers(monkeypatch, "0")
    assert ui.choose_services(["youtube"]) == []


def test_sections_are_offered_by_their_names_on_the_router(monkeypatch, capsys):
    answers(monkeypatch, "1")
    assert ui.choose_sections(as_fetched(), ["youtube"]) == {"youtube": "YouTube_desync"}
    out = capsys.readouterr().out
    assert "YouTube_desync: YouTube" in out and "Meta: Instagram" in out and "Off" not in out


def test_all_sections_at_once(monkeypatch, capsys):
    answers(monkeypatch, "3")
    assert ui.choose_sections(as_fetched(), []) == {"youtube": "YouTube_desync", "instagram": "Meta"}


def test_section_without_a_known_service_is_matched_by_asking(monkeypatch, capsys):
    parsed = {"Mine": {".type": "section", "action": "desync", "community_lists": "custom"}}
    answers(monkeypatch, "1", "2")
    assert ui.choose_sections(parsed, []) == {"discord": "Mine"}
    assert "сервис не определён" in capsys.readouterr().out


def test_router_without_sections_says_so(capsys):
    assert ui.choose_sections({}, []) == {}
    assert "нет работающих секций" in capsys.readouterr().out


def test_search_budget_leaves_room_for_the_final_measurement():
    assert check.search_seconds(check.QUICK, check.QUICK_MINUTES) == 20 * 60 - 5 * 60 - 60
    assert check.search_seconds(check.FULL, 60) == 60 * 60 - 10 * 60 - 60
    assert check.search_seconds(check.QUICK, 1) == check.MIN_SEARCH_S


def test_time_is_planned_per_service():
    assert check.planned_minutes(check.Spec(check.QUICK, ["a", "b"], 15)) == 30
    assert ui._duration(90) == "1 ч 30 мин" and ui._duration(60) == "1 ч" and ui._duration(15) == "15 мин"


def test_chosen_section_is_measured(tmp_path):
    cfg = AppConfig(db=tmp_path / "adf.sqlite", stop_file=tmp_path / "STOP")
    spec = check.Spec(check.CURRENT, ["youtube"], simulate=True, sections={"youtube": "Mine"})
    job = check.Job(cfg, spec, tmp_path / "check.json", tmp_path / "reports", cli)
    parsed = {"Mine": {".type": "section", "action": "desync", "desync_preset": "custom", "desync_mode": "split",
                       "desync_split_pos": "1"}}
    section, variant, _ = job._current("youtube", parsed, TachyonDesync())
    assert section == "Mine" and variant.label == "сейчас: Mine"
    with pytest.raises(ValueError, match="Other"):
        job.spec.sections["youtube"] = "Other"
        job._current("youtube", parsed, TachyonDesync())


def test_job_gets_the_chosen_section(tmp_path, monkeypatch):
    seen = {}

    class Started:
        pid = 1

    def popen(command, **kw):
        seen["command"] = command
        return Started()
    monkeypatch.setenv("ADF_HOME", str(tmp_path))
    monkeypatch.setattr(subprocess, "Popen", popen)
    check.spawn(check.Spec(check.CURRENT, ["youtube"], sections={"youtube": "Mine"}))
    assert seen["command"][-2:] == ["--sections", "youtube=Mine"]


def test_explicit_section_reaches_the_job_spec(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setenv("ADF_HOME", str(tmp_path))
    monkeypatch.setattr(ui, "start_check", lambda spec, cli_, attach=True: seen.update(spec=spec) or 0)
    cli.main(["check", "--services", "youtube", "--sections", "youtube=Mine"])
    assert seen["spec"].mode == check.CURRENT and seen["spec"].sections == {"youtube": "Mine"}
    cli.main(["check", "--quick", "--services", "youtube"])
    assert seen["spec"].mode == check.QUICK and seen["spec"].minutes == check.QUICK_MINUTES
    cli.main(["check", "--full", "--services", "youtube"])
    assert seen["spec"].mode == check.FULL and seen["spec"].minutes == check.FULL_MINUTES


def test_menu_starts_the_chosen_check(monkeypatch, capsys):
    started = []
    monkeypatch.setattr(ui, "start_check", lambda spec, cli_: started.append(spec))
    monkeypatch.setattr(live, "read", lambda path: None)
    answers(monkeypatch, "1", "2", "", "", "2", "1", "90", "", "1", "0", "2", "1", "", "0", "0")
    cfg = AppConfig()
    cfg.router.host = "192.168.8.1"
    assert ui.menu(cli, None, cfg) == 0
    assert [(s.mode, s.services, s.minutes) for s in started] == [(check.QUICK, ["discord"], check.QUICK_MINUTES),
                                                                  (check.FULL, ["youtube"], 90.0)]
    assert "root@192.168.8.1" in capsys.readouterr().out


def test_menu_checks_the_section_picked_on_this_router(monkeypatch, capsys):
    started = []
    monkeypatch.setattr(ui, "start_check", lambda spec, cli_: started.append(spec))
    monkeypatch.setattr(live, "read", lambda path: None)
    monkeypatch.setattr(cli, "_uci_text", lambda cfg, args: "\n".join(
        line for line in UCI_SHOW.splitlines() if re.search(tachyon_int.UCI_FILTER, line)))
    answers(monkeypatch, "3", "1", "", "0")
    cfg = AppConfig()
    cfg.router.host = "r"
    ui.menu(cli, None, cfg)
    assert [(s.mode, s.sections) for s in started] == [(check.CURRENT, {"youtube": "YouTube_desync"})]


def test_menu_survives_a_router_that_does_not_answer(monkeypatch, capsys):
    def broken(cfg, args):
        raise cli.BackendError("no route to host")
    monkeypatch.setattr(cli, "_uci_text", broken)
    monkeypatch.setattr(live, "read", lambda path: None)
    answers(monkeypatch, "3", "0")
    cfg = AppConfig()
    cfg.router.host = "r"
    assert ui.menu(cli, None, cfg) == 0
    assert "Роутер не ответил" in capsys.readouterr().out


def test_menu_keeps_rollback_connection_and_exit_numbers(monkeypatch, capsys):
    monkeypatch.setattr(live, "read", lambda path: None)
    answers(monkeypatch, "0")
    cfg = AppConfig()
    cfg.router.host = "r"
    ui.menu(cli, None, cfg)
    out = capsys.readouterr().out
    assert "4  Откатить стратегию" in out and "5  Подключение к роутеру" in out and "0  Выход" in out


def test_menu_rolls_back_only_the_named_section(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "main", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(live, "read", lambda path: None)
    answers(monkeypatch, "4", "", "4", "YouTube_desync", "0")
    cfg = AppConfig()
    cfg.router.host = "r"
    ui.menu(cli, None, cfg)
    assert calls == [["rollback", "--section", "YouTube_desync"]]


def test_second_interrupt_leaves_the_check_running(monkeypatch, tmp_path, capsys):
    def interrupted(prompt=""):
        raise KeyboardInterrupt
    monkeypatch.setattr(builtins, "input", interrupted)
    cfg = AppConfig(stop_file=tmp_path / "STOP")
    assert ui._pause(cfg) is False
    assert not cfg.stop_file.exists()


@pytest.mark.parametrize("reply, stays, stops", [("", True, False), ("2", True, True), ("0", False, False)])
def test_pause_choices(reply, stays, stops, monkeypatch, tmp_path, capsys):
    answers(monkeypatch, reply)
    cfg = AppConfig(stop_file=tmp_path / "STOP")
    assert ui._pause(cfg) is stays
    assert cfg.stop_file.exists() is stops


def test_tables_of_current_and_found_are_labelled():
    candidate = dict(BETTER, rows={"a": dict(row(10), label="www.youtube.com")})
    text = "\n".join(ui.result_lines(final(result(candidate=candidate)), PLAIN))
    assert "Сейчас" in text and "Найденная" in text


def test_service_without_a_section_is_told_what_to_do():
    text = "\n".join(ui.result_lines(final(result(candidate=BETTER, section=None)), PLAIN))
    assert "Секции desync нет" in text and "создайте для сервиса секцию" in text


def test_interrupt_ends_without_a_traceback(monkeypatch, capsys):
    def interrupted(args):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "cmd_status", interrupted)
    assert cli.main(["status"]) == 130


def test_no_arguments_without_a_terminal_print_help(capsys):
    assert cli.main([]) == 2
    assert "check" in capsys.readouterr().out


def test_unknown_service_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("ADF_HOME", str(tmp_path))
    with pytest.raises(SystemExit, match="unknown service"):
        cli.main(["check", "--services", "tiktok"])


def test_check_outlives_the_command_that_started_it(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("ADF_HOME", str(tmp_path))
    spec = check.Spec(check.CURRENT, ["github"], simulate=True)
    assert ui.start_check(spec, cli, attach=False) == 0
    assert "adf watch" in capsys.readouterr().out
    deadline = time.monotonic() + 60
    snapshot = live.read(tmp_path / "check.json")
    while time.monotonic() < deadline and snapshot["status"] == live.RUNNING:
        time.sleep(0.2)
        snapshot = live.read(tmp_path / "check.json")
    assert snapshot["status"] == live.FINISHED, (tmp_path / "check.log").read_text(errors="replace")
    assert ui.status() == 0
    assert "GitHub:" in capsys.readouterr().out
