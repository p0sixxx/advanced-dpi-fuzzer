"""Command line interface: ``adf <command>`` (see ``adf --help``)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .bench import bench, bench_table
from .config import AppConfig, load_config
from .db import Store
from .engines import ENGINES, StrategyError, TachyonDesync, get_engine
from .engines.tachyon_desync import caps_test_matrix, capabilities_from_probe
from .generator import pairwise
from .integrations import tachyon as tachyon_int
from .integrations import tachyon_history
from .learning import DecayPolicy, build_scores
from .probe.backend import (AgentBackend, Backend, BackendError, DPIModel, LocalTransport, ProbeSettings,
                            SimulatedBackend, SSHTransport)
from .probe.targets import DEFAULT_CONTROLS, DEFAULT_TARGETS, load_targets, select
from .report import compare_report, run_report
from .safety import Budget, Guard, SafetyPolicy
from .search.compare import Variant, compare
from .search.orchestrator import Orchestrator, SearchConfig
from .strategy import from_text, make_strategy

DATA_DIR = Path(__file__).resolve().parent / "data"


def eprint(*a: Any) -> None:
    print(*a, file=sys.stderr)


# ------------------------------------------------------------------ plumbing
def _cfg(args: argparse.Namespace) -> AppConfig:
    cfg = load_config(Path(args.config) if args.config else None)
    if getattr(args, "db", None):
        cfg.db = Path(args.db)
    if getattr(args, "ssh", None):
        user, _, host = args.ssh.rpartition("@")
        cfg.router.host = host
        if user:
            cfg.router.user = user
    if getattr(args, "network_id", None):
        cfg.search.network_id = args.network_id
    return cfg


def _transport(cfg: AppConfig, args: argparse.Namespace):
    if getattr(args, "local", False):
        return LocalTransport()
    if not cfg.router.host:
        raise SystemExit("no router configured: use --ssh root@192.168.8.1, --local, --simulate or [router] in config")
    return SSHTransport(host=cfg.router.host, user=cfg.router.user, port=cfg.router.port,
                        identity=cfg.router.identity, remote_agent=cfg.router.remote_agent)


def _backend(cfg: AppConfig, args: argparse.Namespace) -> Backend:
    if getattr(args, "simulate", False):
        return SimulatedBackend(DPIModel(seed=getattr(args, "seed", 0) or 0))
    t = _transport(cfg, args)
    if isinstance(t, SSHTransport):
        t.install()
    p = cfg.probe
    return AgentBackend(t, ProbeSettings(port=p.port, timeout_s=p.timeout_s, connect_timeout_s=p.connect_timeout_s,
                                         interval_ms=p.interval_ms, routing_mark=p.routing_mark,
                                         dns_server=p.dns_server, cacert=getattr(args, "cacert", None)))


def _targets(cfg: AppConfig, args: argparse.Namespace) -> tuple:
    path = getattr(args, "targets", None) or cfg.targets_file
    if path:
        loaded = load_targets(Path(path))
        targets, controls = loaded["targets"], loaded["controls"] or list(DEFAULT_CONTROLS)
    else:
        targets, controls = list(DEFAULT_TARGETS), list(DEFAULT_CONTROLS)
    cats = (args.categories.split(",") if getattr(args, "categories", None) else cfg.search.categories) or None
    ids = args.only.split(",") if getattr(args, "only", None) else None
    targets = select(targets, cats, ids)
    if not targets:
        raise SystemExit("no targets selected")
    return targets, controls


def _confirm(prompt: str, expected: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        eprint("refusing: confirmation required (interactive terminal or --yes)")
        return False
    ans = input(f"{prompt}\nType '{expected}' to confirm: ").strip()
    return ans == expected


def _caps_for(store: Store, backend: Backend, engine_name: str, host: str):
    if engine_name != TachyonDesync.name:
        return None
    data = store.load_capabilities(engine_name, host)
    if data:
        return capabilities_from_probe(data)
    return None


# ------------------------------------------------------------------ commands
def cmd_env(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    print(json.dumps(_backend(cfg, args).env(), ensure_ascii=False, indent=2))
    return 0


def cmd_caps(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    backend = _backend(cfg, args)
    tests = caps_test_matrix()
    res = backend.capabilities(tests)
    env = backend.env()
    data = {"host": cfg.router.host or "local", "version": env.get("core_version", ""), "results": res}
    store = Store(cfg.db)
    store.save_capabilities(TachyonDesync.name, data["host"], data)
    caps = capabilities_from_probe(data)
    print(json.dumps({"version": data["version"], "accepted": sum(1 for r in res if r.get("ok")),
                      "rejected": [f"{r['key']}={r['value']}" for r in res if not r.get("ok")],
                      "capabilities": caps.to_dict()}, ensure_ascii=False, indent=2))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    eng = get_engine(args.engine, measure_udp=args.udp, families=args.families.split(","))
    try:
        s = from_text(eng, args.strategy)
    except StrategyError as e:
        print(json.dumps({"valid": False, "error": str(e)}, ensure_ascii=False))
        return 1
    out: Dict[str, Any] = {"valid": True, **s.to_dict()}
    if isinstance(eng, TachyonDesync):
        out["tachyon_core_outbound"] = eng.outbound(s.params)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    eng = get_engine(args.engine)
    seeds = [make_strategy(eng, p, "seed", n) for n, p in eng.seeds()]
    design = [make_strategy(eng, p, "pairwise") for p in pairwise(eng, seed=args.seed)]
    items = seeds + design
    if args.limit:
        items = items[: args.limit]
    for s in items:
        print(json.dumps(s.to_dict(), ensure_ascii=False) if args.json else f"{s.id}\t{s.origin}\t{s.text}")
    eprint(f"{len(seeds)} seeds + {len(design)} pairwise screening candidates")
    return 0


def cmd_targets(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    targets, controls = _targets(cfg, args)
    for t in targets + controls:
        print(f"{t.id:18} {t.category:14} {'req' if t.required else 'opt'} {t.kind:9} min={t.min_bytes:<7} {t.url}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    targets, controls = _targets(cfg, args)
    families = sorted({f for t in targets for f in t.families})
    engine = get_engine(args.engine or cfg.search.engine, measure_udp=any(t.kind == "quic" for t in targets),
                        families=families if len(families) == 1 else ("ipv4",))
    if not engine.probe_supported or engine.name in ("zapret", "zapret2"):
        raise SystemExit(f"engine {engine.name}: direct probing is not supported by adf-agent run; "
                         "generate/validate/export are available")
    backend = _backend(cfg, args)
    store = Store(cfg.db)
    if not args.simulate and cfg.db.exists():
        store.backup(cfg.db.with_suffix(".bak"))
    budget = Budget(max_batches=args.max_batches or cfg.search.max_batches,
                    max_probes=args.max_probes or cfg.search.max_probes,
                    max_seconds=60 * (args.max_minutes or cfg.search.max_minutes))
    policy = SafetyPolicy(min_batch_interval_s=0 if args.simulate else cfg.search.min_batch_interval_s,
                          stop_file=cfg.stop_file, backoff_initial_s=0 if args.simulate else 15)
    if not args.simulate:
        eprint(f"Real network probes via {getattr(backend, 'transport').describe()}: up to {budget.max_probes} HTTPS "
               f"requests to {len(targets) + len(controls)} targets, ≥{policy.min_batch_interval_s}s between batches. "
               f"Nothing on the router is changed. Stop at any time: Ctrl+C or `touch {cfg.stop_file}`.")
        if not _confirm("Start the search?", "yes", args.yes):
            return 2
    if cfg.stop_file.exists():
        cfg.stop_file.unlink()
    guard = Guard(budget, policy, sleeper=(lambda s: None) if args.simulate else time.sleep)
    guard.install_signal_handlers()
    caps = None if args.simulate else _caps_for(store, backend, engine.name, cfg.router.host or "local")
    extra = []
    for text in args.strategy or []:
        extra.append(from_text(engine, text, origin="user"))
    # current Tachyon strategies (adf import) and Fuzzer v2 winners (adf tachyon-history) are always candidates
    for s in store.strategies(engine.name):
        if s.origin in ("import", "tachyon_v2"):
            try:
                extra.append(make_strategy(engine, s.params, origin=s.origin, name=s.name, caps=caps))
            except StrategyError as e:
                eprint(f"skipping stored {s.origin} strategy {s.id}: {e}")
    sc = SearchConfig(network_id=cfg.search.network_id + ("-sim" if args.simulate else ""), seed=args.seed,
                      use_history=not args.fresh, force_without_blocked=args.force)
    orch = Orchestrator(store, backend, engine, targets, controls, sc, guard, caps, extra, log=eprint)
    summary = orch.run()
    report = run_report(summary)
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        eprint(f"report written to {args.report}")
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2, default=str))
    else:
        print(report)
    return 0 if summary["status"] == "finished" else 3


def _leaderboard(store: Store, network_id: str, engine: str, simulated: bool, limit: int) -> List[Dict[str, Any]]:
    strategies = {s.id: s for s in store.strategies(engine)}
    rows = store.trials(network_id, simulated, strategy_ids=list(strategies))
    req: Dict[str, bool] = {}
    for r in store.conn.execute("SELECT id, spec FROM targets"):
        req[r[0]] = bool(json.loads(r[1]).get("required", True))
    scores = build_scores(rows, req, {k: v.complexity for k, v in strategies.items()}, DecayPolicy(),
                          store.current_epoch(network_id))
    ranked = sorted(scores.values(), key=lambda sc: -sc.utility())[:limit]
    out = []
    for sc in ranked:
        d = sc.to_dict()
        d["text"] = strategies[sc.strategy_id].text
        out.append(d)
    return out


def cmd_best(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    store = Store(cfg.db)
    nid = cfg.search.network_id + ("-sim" if args.simulated else "")
    board = _leaderboard(store, nid, args.engine, args.simulated, args.limit)
    if args.json:
        print(json.dumps(board, ensure_ascii=False, indent=2))
    else:
        for i, d in enumerate(board, 1):
            print(f"{i:2}. {d['class']:18} LB={d['lb']:.3f} n/target={d['min_n']:<5g} cx={d['complexity']:<5} "
                  f"{d['strategy_id']}  {d['text']}")
    return 0


def _resolve_strategy(store: Store, ref: str, engine_name: str = TachyonDesync.name):
    s = store.get_strategy(ref)
    if s is not None:
        return s
    return from_text(get_engine(engine_name, measure_udp=True), ref, origin="user")


def cmd_export(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    store = Store(cfg.db)
    s = _resolve_strategy(store, args.strategy, args.engine)
    if args.format == "opts":
        print(s.text)
    elif args.format == "json":
        eng = get_engine(s.engine, measure_udp=True)
        if not isinstance(eng, TachyonDesync):
            raise SystemExit("json outbound export exists only for tachyon_desync")
        print(json.dumps(eng.outbound(s.params, tag=args.tag), ensure_ascii=False, indent=2))
    else:
        if not args.section:
            raise SystemExit("--section is required for uci export")
        opts = tachyon_int.export_options(s)
        print("\n".join(tachyon_int.uci_commands(args.section, opts)))
        print("uci commit tachyon\ntachyon reload")
    return 0


def _uci_text(cfg: AppConfig, args: argparse.Namespace) -> str:
    if getattr(args, "uci_file", None):
        return Path(args.uci_file).read_text(encoding="utf-8")
    return _transport(cfg, args).shell("uci -q show tachyon")


def cmd_import(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    parsed = tachyon_int.parse_uci_show(_uci_text(cfg, args))
    store = Store(cfg.db)
    out = []
    for sid in tachyon_int.desync_sections(parsed):
        imp = tachyon_int.section_to_params(sid, parsed[sid])
        item: Dict[str, Any] = {"section": sid, "kind": imp.kind, "auto_tune": imp.auto_tune,
                                "tachyon_core_outbound": imp.outbound, "notes": imp.notes}
        if imp.params:
            s = make_strategy(TachyonDesync(), imp.params, origin="import", name=f"tachyon:{sid}")
            item.update({"strategy_id": s.id, "text": s.text})
            store.upsert_strategy(s)
        if imp.ignored_opts:
            item["ignored_desync_opts"] = imp.ignored_opts
        out.append(item)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    store = Store(cfg.db)
    s = _resolve_strategy(store, args.strategy)
    transport = _transport(cfg, args)
    remote = tachyon_int.TachyonRemote(transport)
    plan = tachyon_int.plan_apply(remote.show(), args.section, s, reload=not args.no_reload)
    print(f"# Section tachyon.{args.section}: apply strategy {s.id}\n# {s.text}\n")
    print(plan.script)
    print("# Rollback script (stored in the database):\n" + plan.rollback_script)
    if args.dry_run:
        return 0
    if not _confirm("This changes the Tachyon configuration on the router and reloads Tachyon.", args.section,
                    args.yes):
        return 2
    full = remote.save_full_backup()
    remote.run(plan.script)
    eid = store.record_export(s.id, args.section, plan.to_dict(), backup=json.dumps(
        {"section": plan.backup, "full_backup_on_router": full}), applied=True)
    print(f"applied (export #{eid}); full backup on router: {full}; rollback: adf rollback --section {args.section}")
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    store = Store(cfg.db)
    row = store.last_applied_export(args.section)
    if row is None:
        raise SystemExit(f"no applied export recorded for section {args.section}")
    backup = json.loads(row["backup"])["section"]
    script = tachyon_int.shell_script(tachyon_int.uci_commands(args.section, backup), reload=not args.no_reload)
    print(script)
    if args.dry_run:
        return 0
    if not _confirm("Restore the previous Tachyon desync options?", args.section, args.yes):
        return 2
    tachyon_int.TachyonRemote(_transport(cfg, args)).run(script)
    store.mark_rolled_back(row["id"])
    print("rolled back")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    targets, controls = _targets(cfg, args)
    backend = _backend(cfg, args)
    store = Store(cfg.db)
    eng = TachyonDesync()
    variants: List[Variant] = []
    if not args.no_adaptive:
        variants.append(Variant("Tachyon Adaptive 2.0 (preset=auto)",
                                outbound={"type": "desync", "preset": "auto", "auto_tune": True}))
    if args.current:
        parsed = tachyon_int.parse_uci_show(_uci_text(cfg, args))
        for sid in args.current:
            if sid not in parsed:
                raise SystemExit(f"section {sid} not found in tachyon config")
            imp = tachyon_int.section_to_params(sid, parsed[sid])
            variants.append(Variant(f"current: {sid}", outbound=imp.outbound))
    for i, text in enumerate(args.strategy or [], 1):
        ref, _, label = text.partition("::")
        s = _resolve_strategy(store, ref)
        variants.append(Variant(label or f"strategy {i}", strategy=s))
    if args.best:
        nid = cfg.search.network_id + ("-sim" if args.simulate else "")
        board = _leaderboard(store, nid, eng.name, args.simulate, 1)
        if board:
            variants.append(Variant("Advanced DPI Fuzzer best", strategy=store.get_strategy(board[0]["strategy_id"])))
    if len(variants) < 2:
        raise SystemExit("need at least two variants (Adaptive 2.0, --strategy ..., --best)")
    ips = {t.id: backend.resolve(t.host)[: t.max_ips] for t in targets + controls}
    guard = Guard(Budget(max_batches=10 ** 6, max_probes=10 ** 7, max_seconds=86400),
                  SafetyPolicy(min_batch_interval_s=0 if args.simulate else cfg.search.min_batch_interval_s,
                               stop_file=cfg.stop_file, backoff_initial_s=0 if args.simulate else 15),
                  sleeper=(lambda s: None) if args.simulate else time.sleep)
    guard.install_signal_handlers()
    if not args.simulate and not _confirm(f"Measure {len(variants)} variants × {args.reps} rounds?", "yes", args.yes):
        return 2
    summary = compare(store, backend, eng, variants, targets, controls, ips, args.reps,
                      cfg.search.network_id + ("-sim" if args.simulate else ""), guard, log=eprint)
    rep = compare_report(summary["rows"], summary)
    if args.report:
        Path(args.report).write_text(rep, encoding="utf-8")
    print(rep)
    return 0


def cmd_tachyon_history(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    else:
        text = _transport(cfg, args).shell("cat /etc/tachyon/fuzzer_history.json")
    start = text.find("{")
    data = json.loads(text[start:]) if start >= 0 else {}
    result = tachyon_history.analyze(data)
    store = Store(cfg.db)
    for s in result["strategies"]:
        store.upsert_strategy(s)
    if args.json:
        out = dict(result, strategies=[s.to_dict() for s in result["strategies"]])
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(tachyon_history.markdown(result))
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    seeds = [int(x) for x in args.seeds.split(",")]
    print(bench_table(bench(seeds, n_targets=args.targets_n)))
    return 0


def cmd_methods(args: argparse.Namespace) -> int:
    data = json.loads((DATA_DIR / "methods.json").read_text(encoding="utf-8"))
    for m in data["methods"]:
        engines = m["engines"]
        if args.engine and engines.get(args.engine, {}).get("status", "absent") == "absent":
            continue
        print(f"{m['id']:22} {m['name']}")
        for e, info in engines.items():
            if info["status"] != "absent":
                print(f"    {e:15} [{info['status']:9}] {info['syntax']}")
    return 0


def cmd_db(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    store = Store(cfg.db)
    if args.action == "backup":
        print(store.backup(args.path or cfg.db.with_suffix(f".{int(time.time())}.bak")))
    elif args.action == "export":
        print(f"{store.export_jsonl(args.path)} rows exported")
    elif args.action == "import":
        print(f"{store.import_jsonl(args.path)} rows imported")
    else:
        c = store.conn
        stats = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                 for t in ("strategies", "runs", "trials", "invalid", "epochs", "exports")}
        stats["runs_recent"] = [dict(r) for r in store.runs(5)]
        for r in stats["runs_recent"]:
            r.pop("config", None)
            r.pop("summary", None)
        print(json.dumps(stats, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    cfg = _cfg(args)
    cfg.stop_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.stop_file.write_text(str(time.time()))
    print(f"stop requested ({cfg.stop_file}); the running search stops after the current batch")
    if getattr(args, "ssh", None) or getattr(args, "local", False):
        try:
            print(_transport(cfg, args).call(["stop"]).strip())
        except BackendError as e:
            eprint(f"agent stop failed: {e}")
    return 0


# -------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="adf", description="Advanced Adaptive DPI Fuzzer")
    p.add_argument("--version", action="version", version=f"adf {__version__}")
    p.add_argument("-c", "--config", help="TOML config (examples/config.toml)")
    p.add_argument("--db", help="SQLite database path (default ~/.adf/adf.sqlite)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def where(sp: argparse.ArgumentParser, simulate: bool = True) -> None:
        g = sp.add_mutually_exclusive_group()
        g.add_argument("--ssh", help="router as [user@]host (key-based SSH, BatchMode)")
        g.add_argument("--local", action="store_true", help="run adf-agent on this machine")
        if simulate:
            g.add_argument("--simulate", action="store_true", help="use the DPI simulator (no network)")
        sp.add_argument("--cacert", help=argparse.SUPPRESS)

    def tsel(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--targets", help="targets TOML (examples/targets.toml)")
        sp.add_argument("--categories", help="comma list: youtube,discord,…")
        sp.add_argument("--only", help="comma list of target ids")
        sp.add_argument("--network-id", help="label of the network/ISP the results belong to")

    sp = sub.add_parser("env", help="describe the agent host")
    where(sp)
    sp.set_defaults(func=cmd_env)

    sp = sub.add_parser("caps", help="probe which desync parameters the installed tachyon-core accepts")
    where(sp, simulate=False)
    sp.set_defaults(func=cmd_caps)

    sp = sub.add_parser("validate", help="validate and canonicalize a strategy string")
    sp.add_argument("strategy")
    sp.add_argument("--engine", default=TachyonDesync.name, choices=sorted(ENGINES))
    sp.add_argument("--udp", action="store_true", help="allow UDP parameters")
    sp.add_argument("--families", default="ipv4")
    sp.set_defaults(func=cmd_validate)

    sp = sub.add_parser("generate", help="print seeds and the pairwise screening design")
    sp.add_argument("--engine", default=TachyonDesync.name, choices=sorted(ENGINES))
    sp.add_argument("--seed", type=int, default=0)
    sp.add_argument("--limit", type=int, default=0)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_generate)

    sp = sub.add_parser("targets", help="list selected targets")
    tsel(sp)
    sp.set_defaults(func=cmd_targets)

    sp = sub.add_parser("run", help="search for the best strategy")
    where(sp)
    tsel(sp)
    sp.add_argument("--engine", choices=["tachyon_desync", "byedpi"])
    sp.add_argument("--max-batches", type=int)
    sp.add_argument("--max-probes", type=int)
    sp.add_argument("--max-minutes", type=float)
    sp.add_argument("--seed", type=int, default=0)
    sp.add_argument("--strategy", action="append", help="extra strategy to include (repeatable)")
    sp.add_argument("--fresh", action="store_true", help="ignore stored history")
    sp.add_argument("--force", action="store_true", help="search even if nothing is blocked")
    sp.add_argument("--report", help="write the Markdown report here")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("best", help="leaderboard from stored results (with time decay)")
    sp.add_argument("--engine", default=TachyonDesync.name)
    sp.add_argument("--network-id")
    sp.add_argument("--simulated", action="store_true")
    sp.add_argument("--limit", type=int, default=10)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_best)

    sp = sub.add_parser("export", help="export a strategy (uci commands / desync_opts / core JSON)")
    sp.add_argument("strategy", help="strategy id from the database or a strategy string")
    sp.add_argument("--engine", default=TachyonDesync.name)
    sp.add_argument("--format", choices=["uci", "opts", "json"], default="uci")
    sp.add_argument("--section")
    sp.add_argument("--tag", default="desync-out")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("import", help="read current Tachyon Native Desync sections")
    where(sp, simulate=False)
    sp.add_argument("--uci-file", "--file", dest="uci_file", help="saved `uci show tachyon` output instead of SSH")
    sp.set_defaults(func=cmd_import)

    for name, fn, hlp in (("apply", cmd_apply, "apply a strategy to a Tachyon section (asks for confirmation)"),
                          ("rollback", cmd_rollback, "restore the options saved by the last apply")):
        sp = sub.add_parser(name, help=hlp)
        where(sp, simulate=False)
        sp.add_argument("--section", required=True)
        if name == "apply":
            sp.add_argument("strategy")
        sp.add_argument("--dry-run", action="store_true")
        sp.add_argument("--no-reload", action="store_true")
        sp.add_argument("-y", "--yes", action="store_true")
        sp.set_defaults(func=fn)

    sp = sub.add_parser("compare", help="measure Adaptive 2.0 / current / best side by side")
    where(sp)
    tsel(sp)
    sp.add_argument("--strategy", action="append", help="id-or-string[::label] (repeatable)")
    sp.add_argument("--best", action="store_true", help="include the stored best strategy")
    sp.add_argument("--current", action="append", metavar="SECTION",
                    help="measure a Tachyon desync section exactly as configured (repeatable)")
    sp.add_argument("--uci-file", help="saved `uci show tachyon` output for --current")
    sp.add_argument("--no-adaptive", action="store_true")
    sp.add_argument("--reps", type=int, default=20)
    sp.add_argument("--report")
    sp.add_argument("-y", "--yes", action="store_true")
    sp.set_defaults(func=cmd_compare)

    sp = sub.add_parser("tachyon-history", help="analyse Tachyon Fuzzer v2 history and import its winners")
    where(sp, simulate=False)
    sp.add_argument("--file", help="local copy of /etc/tachyon/fuzzer_history.json (or adf-info.txt)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_tachyon_history)

    sp = sub.add_parser("bench", help="offline algorithm comparison on the DPI simulator")
    sp.add_argument("--seeds", default="1,2,3,4,5")
    sp.add_argument("--targets-n", type=int, default=6)
    sp.set_defaults(func=cmd_bench)

    sp = sub.add_parser("methods", help="list the desync methods knowledge base")
    sp.add_argument("--engine", choices=sorted(ENGINES))
    sp.set_defaults(func=cmd_methods)

    sp = sub.add_parser("db", help="database maintenance")
    sp.add_argument("action", choices=["stats", "backup", "export", "import"])
    sp.add_argument("path", nargs="?")
    sp.set_defaults(func=cmd_db)

    sp = sub.add_parser("stop", help="request a graceful stop of a running search")
    where(sp, simulate=False)
    sp.set_defaults(func=cmd_stop)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except (BackendError, StrategyError, ValueError) as e:
        eprint(f"error: {e}")
        return 1
    except BrokenPipeError:  # output piped into head & co.
        return 0


if __name__ == "__main__":
    sys.exit(main())
