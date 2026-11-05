"""The check started from a PC: of the current setup, or a short or long search for a better one.

Each service has its own Tachyon section, so each gets its own measurement and its own strategy; a single
search over several services would look for a strategy that fits all of them.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import live
from .config import AppConfig, adf_home
from .db import Store
from .engines import StrategyError, TachyonDesync, get_engine
from .integrations import tachyon as tachyon_int
from .probe.backend import BackendError
from .probe.model import LARGE_HELLO, Target
from .report import compare_report, dns_lines, run_report
from .safety import Budget, Guard, SafetyPolicy
from .scoring import wilson
from .search.compare import Variant, compare
from .search.dnscheck import run_check
from .search.orchestrator import Orchestrator, SearchConfig
from .strategy import Strategy, make_strategy

CURRENT = "current"
QUICK = "quick"
FULL = "full"
SERVICES = {"youtube": "YouTube", "discord": "Discord", "instagram": "Instagram", "telegram": "Telegram",
            "google": "Google", "github": "GitHub"}
COMMUNITY_LISTS = {"instagram": "meta"}     # Tachyon's list name when it differs from the service
CURRENT_ROUNDS = 5
QUICK_MINUTES = 20
FULL_MINUTES = 60
FINAL_ROUNDS = {QUICK: 5, FULL: 10}
ROUND_S = 60                # the current and the found strategy measured side by side, one round
DNS_CHECK_S = 60
MIN_SEARCH_S = 120
WORKS = 0.9
FAILS = 0.8
BETTER_BY = 0.05
DIRECT = {"type": "direct"}
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
CREATE_NO_WINDOW = 0x08000000
CREATE_NEW_PROCESS_GROUP = 0x00000200


@dataclasses.dataclass
class Spec:
    mode: str
    services: List[str]
    minutes: float = FULL_MINUTES       # for each service
    simulate: bool = False
    config: Optional[str] = None
    sections: Dict[str, str] = dataclasses.field(default_factory=dict)      # service -> section chosen by name


def label(t: Target) -> str:
    return f"{t.host} как Chrome" if t.kind == LARGE_HELLO else t.host


def _names(value: Any) -> List[str]:
    return value.split() if isinstance(value, str) else list(value or ())


def working_sections(parsed: Mapping[str, Mapping[str, Any]]) -> List[str]:
    """Desync sections under the names they have on this router, without those the core does not run."""
    inactive = tachyon_int.inactive_desync_sources(parsed)
    return [sid for sid in tachyon_int.desync_sections(parsed)
            if sid not in inactive and str(parsed[sid].get("enabled", "1")) != "0"]


def services_of(parsed: Mapping[str, Mapping[str, Any]], section: str) -> List[str]:
    opts = parsed[section]
    lists = _names(opts.get("community_lists"))
    for ref in _names(opts.get("condition_refs")):
        lists += _names(parsed.get(ref, {}).get("community_lists"))
    return [service for service in SERVICES if COMMUNITY_LISTS.get(service, service) in lists]


def find_section(parsed: Mapping[str, Mapping[str, Any]], service: str) -> Optional[str]:
    """The section that serves a service: by its own lists or those of its conditions."""
    for sid in working_sections(parsed):
        if service in services_of(parsed, sid):
            return sid
    return None


def search_seconds(mode: str, minutes: float) -> float:
    """The budget of a service covers the side-by-side measurement and the DNS check after the search."""
    return max(MIN_SEARCH_S, 60 * minutes - FINAL_ROUNDS[mode] * ROUND_S - DNS_CHECK_S)


def planned_minutes(spec: Spec) -> float:
    return (spec.minutes if spec.mode != CURRENT else 4) * len(spec.services)


def judge(rows: Mapping[str, Mapping[str, Any]], dns_check: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """The verdict for one service from per-target results of what is configured now."""
    # a few attempts prove little: 3 of 5 can be two timeouts on a target that passes 45 of 45 otherwise
    failing = [tid for tid, s in rows.items() if s["required"] and s["n"] and wilson(s["k"], s["n"])[1] < FAILS]
    shaky = [tid for tid, s in rows.items() if s["required"] and tid not in failing and s["n"]
             and s["k"] / s["n"] < WORKS]
    optional = [tid for tid, s in rows.items() if not s["required"] and s["n"] and s["k"] / s["n"] < FAILS]
    dns = [r["target"] for r in (dns_check or {}).get("rows", ()) if r["verdict"] == "dns"]
    if dns:
        status = "dns"
    elif failing:
        status = "fail"
    elif shaky or optional:
        status = "warn"
    elif rows:
        status = "ok"
    else:
        status = "unknown"
    return {"status": status, "failing": failing, "shaky": shaky, "optional": optional, "dns_targets": dns}


def _targets_view(row: Mapping[str, Any], targets: Sequence[Target]) -> Dict[str, Dict[str, Any]]:
    seen = row.get("targets", {})
    out = {}
    for t in targets:
        s = seen.get(t.id)
        if s:
            out[t.id] = {"label": label(t), "k": s["k"], "n": s["n"], "required": t.required,
                         "verdicts": s.get("verdicts", {})}
    return out


class Job:
    def __init__(self, cfg: AppConfig, spec: Spec, state: Path, reports: Path, helpers: Any):
        self.cfg = cfg
        self.spec = spec
        self.state = state
        self.reports = reports
        self.cli = helpers
        self.started = time.time()
        self.snapshot: Dict[str, Any] = {
            "pid": os.getpid(), "status": live.RUNNING, "mode": spec.mode, "services": spec.services,
            "simulated": spec.simulate, "started": self.started, "phase": "connect", "fraction": 0.0,
            "index": 0, "results": [], "error": "", "report": "", "log": [],
        }

    def emit(self, **fields: Any) -> None:
        self.snapshot.update(fields)
        live.write(self.state, self.snapshot)

    def note(self, text: str) -> None:
        self.emit(log=(self.snapshot["log"] + [text])[-4:])

    def step(self, fraction: float, **fields: Any) -> None:
        """Progress of the current service, turned into progress of the whole check."""
        total = len(self.spec.services)
        whole = (self.snapshot["index"] + max(0.0, min(1.0, fraction))) / total
        self.emit(fraction=whole, **fields)

    def _guard(self, seconds: float) -> Guard:
        policy = SafetyPolicy(min_batch_interval_s=0 if self.spec.simulate else self.cfg.search.min_batch_interval_s,
                              stop_file=self.cfg.stop_file, backoff_initial_s=0 if self.spec.simulate else 15)
        budget = Budget(max_batches=10 ** 6, max_probes=10 ** 7, max_seconds=seconds)
        return Guard(budget, policy, sleeper=(lambda s: None) if self.spec.simulate else time.sleep)

    def stopped(self) -> bool:
        return self.cfg.stop_file.exists()

    def _current(self, service: str, parsed: Mapping[str, Mapping[str, Any]], engine: TachyonDesync):
        section = self.spec.sections.get(service) or find_section(parsed, service)
        if section is None:
            return None, Variant("без обхода", outbound=dict(DIRECT)), None
        if section not in parsed:
            raise ValueError(f"section {section} not found on the router")
        imported = tachyon_int.section_to_params(section, parsed[section], engine)
        return section, Variant(f"сейчас: {section}", outbound=imported.outbound), imported.params

    def _measure(self, store: Store, backend: Any, variants: Sequence[Variant], targets: Sequence[Target],
                 controls: Sequence[Target], ips: Mapping[str, Sequence[str]], rounds: int,
                 span: Sequence[float]) -> Dict[str, Any]:
        """Variants alternate within one run: numbers taken at different times do not compare."""
        engine = get_engine(TachyonDesync.name, measure_udp=True)

        def progress(p: Mapping[str, Any]) -> None:
            self.step(span[0] + (span[1] - span[0]) * p["fraction"], phase="measure",
                      table=_targets_view(p["rows"][-1], targets), detail=f"круг {p['round']} из {p['rounds']}",
                      probes=p["probes"], verdicts=p["verdicts"], best=None)
        return compare(store, backend, engine, variants, targets, controls, ips, rounds,
                       self.cfg.search.network_id + ("-sim" if self.spec.simulate else ""),
                       self._guard(86400), log=self.note, on_progress=progress, dns_check=False)

    def _service(self, service: str, parsed: Mapping[str, Mapping[str, Any]], store: Store, backend: Any) -> Dict[str, Any]:
        args = argparse.Namespace(categories=service, only=None, targets=None)
        targets, controls = self.cli._targets(self.cfg, args)
        backend.prepare_dns([t.host for t in targets + controls if t.host])
        ips = {t.id: backend.resolve(t.host)[: t.max_ips] for t in targets + controls}
        engine = get_engine(TachyonDesync.name, measure_udp=False, families=("ipv4",))
        section, current, params = self._current(service, parsed, engine)
        opts = parsed.get(section, {}) if section else {}
        result: Dict[str, Any] = {"service": service, "name": SERVICES.get(service, service), "section": section,
                                  "current": opts.get("desync_opts") or current.text, "candidate": None,
                                  "dns": backend.dns_info()}
        reports: List[str] = []
        full = self.spec.mode != CURRENT
        found = None
        if full:
            found = self._search(engine, targets, controls, store, backend, params, reports, result)
            if self.stopped():
                return dict(result, report_text="\n".join(reports), status="stopped", rows={})
        variants = [current]
        if found is not None:
            variants.append(Variant("найдена", strategy=store.get_strategy(found["id"])))
        meta = self._measure(store, backend, variants, targets, controls, ips,
                             FINAL_ROUNDS[self.spec.mode] if full else CURRENT_ROUNDS,
                             (0.85, 0.95) if full else (0.0, 0.8))
        reports.append(compare_report(meta["rows"], meta))
        now = meta["rows"][0]
        result.update(rows=_targets_view(now, targets), lb=now["lb"], rate=now["rate"])
        if meta["status"] != "finished":
            return dict(result, report_text="\n".join(reports), status="stopped")
        if found is not None:
            other = meta["rows"][1]
            result["candidate"] = {"id": found["id"], "text": found["text"], "lb": other["lb"], "rate": other["rate"],
                                   "rows": _targets_view(other, targets),
                                   "better": other["lb"] > now["lb"] + BETTER_BY}
        self.step(0.97 if full else 0.85, phase="dns", detail="сверка адресов")
        winner = found if result["candidate"] and result["candidate"]["better"] else current
        dns_check = self._dns_check(backend, engine, winner, targets, ips)
        result["dns"] = dns_check
        result.update(judge(result["rows"], dns_check))
        if section is None and result["status"] in ("fail", "warn"):
            result["status"] = "no_bypass"      # blocked and nothing configured: not a failure of a strategy
        reports.append("\n".join(dns_lines(dns_check)))
        result["report_text"] = "\n".join(r for r in reports if r)
        return result

    def _dns_check(self, backend: Any, engine: Any, best: Any, targets: Sequence[Target],
                   ips: Mapping[str, Sequence[str]]) -> Dict[str, Any]:
        if isinstance(best, dict):
            measure = lambda ts, addresses, reps: backend.run_batch(engine, best["params"], ts, addresses, reps=reps)
        else:
            measure = lambda ts, addresses, reps: backend.run_raw_outbound(best.outbound, ts, addresses, reps=reps)
        try:
            return run_check(backend, measure, targets, ips, self.note)
        except BackendError as e:
            return dict(backend.dns_info(), rows=[], error=str(e))

    def _search(self, engine: Any, targets: Sequence[Target], controls: Sequence[Target], store: Store, backend: Any,
                params: Optional[Mapping[str, Any]], reports: List[str],
                result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        extra: List[Strategy] = []
        if params:
            try:
                extra.append(make_strategy(engine, params, origin="import", name=result["section"] or ""))
            except StrategyError as e:
                self.note(f"текущая стратегия не вошла в поиск: {e}")
        sc = SearchConfig(network_id=self.cfg.search.network_id + ("-sim" if self.spec.simulate else ""),
                          use_history=False, force_without_blocked=True)
        caps = None if self.spec.simulate else self.cli._caps_for(store, backend, engine.name,
                                                                   self.cfg.router.host or "local")
        guard = self._guard(search_seconds(self.spec.mode, self.spec.minutes))
        guard.budget.max_batches = self.cfg.search.max_batches
        guard.budget.max_probes = self.cfg.search.max_probes
        labels = {t.id: label(t) for t in targets}
        required = {t.id: t.required for t in targets}

        def progress(p: Mapping[str, Any]) -> None:
            view = {tid: {"label": labels.get(tid, tid), "k": k, "n": n, "required": required.get(tid, True), "verdicts": {}}
                    for tid, (k, n) in (p["best"] or {}).get("targets", {}).items()}
            self.step(min(0.8, 0.85 * p["fraction"]), phase=p["phase"], probes=p["probes"], verdicts=p["verdicts"],
                      tested=p["tested"], pool=p["pool"], best=p["best"], table=view, detail=p["current"])

        orch = Orchestrator(store, backend, engine, targets, controls, sc, guard, caps, extra, log=self.note,
                            on_progress=progress)
        summary = orch.run()
        reports.append(run_report(summary))
        best = summary.get("best")
        result["search"] = {"status": summary["status"], "tested": summary["unique_tested"], "pool": summary["pool_size"],
                            "error": summary.get("error", ""), "probes": summary["probes"]}
        if not best or any(s.id == best["strategy_id"] for s in extra):
            return None         # nothing found, or the search confirmed what is configured
        return {"id": best["strategy_id"], "text": best["text"], "params": best["params"]}

    def run(self) -> int:
        self.emit()
        if self.cfg.stop_file.exists():
            self.cfg.stop_file.unlink()
        simulate = self.spec.simulate
        args = argparse.Namespace(simulate=simulate, seed=0, local=False, uci_file=None)
        report: List[str] = [f"# Проверка {time.strftime('%Y-%m-%d %H:%M')}: {self.spec.mode}\n"]
        try:
            backend = self.cli._backend(self.cfg, args)
            store = Store(self.cfg.db)
            parsed = {} if simulate else tachyon_int.parse_uci_show(self.cli._uci_text(self.cfg, args))
            self.emit(core=str(backend.env().get("core_version") or ""))
            for i, service in enumerate(self.spec.services):
                self.emit(index=i, service=service, table={}, best=None, detail="", tested=0, pool=0)
                done = self._service(service, parsed, store, backend)
                report.append(done.pop("report_text", ""))
                self.snapshot["results"] = self.snapshot["results"] + [done]
                if self.stopped():
                    break
        except (BackendError, OSError, ValueError, StrategyError) as e:
            self.emit(status=live.FAILED, error=str(e)[:600])
            self._save(report)
            return 1
        self._save(report)
        self.emit(status=live.STOPPED if self.stopped() else live.FINISHED, fraction=1.0, phase="done", detail="")
        return 0

    def _save(self, report: Sequence[str]) -> None:
        self.reports.mkdir(parents=True, exist_ok=True)
        path = self.reports / f"check-{time.strftime('%Y%m%d-%H%M%S')}.md"
        path.write_text("\n".join(r for r in report if r), encoding="utf-8")
        self.snapshot["report"] = str(path)


def state_path() -> Path:
    return adf_home() / "check.json"


def log_path() -> Path:
    return adf_home() / "check.log"


def reports_path() -> Path:
    return adf_home() / "reports"


def spawn(spec: Spec) -> int:
    """Starts the job apart from this console, so that closing it does not stop the check."""
    command = [sys.executable, "-m", "adf"]
    if spec.config:
        command += ["-c", spec.config]
    command += ["check", "--job", "--mode", spec.mode, "--services", ",".join(spec.services),
                "--minutes", str(spec.minutes)]
    if spec.sections:
        command += ["--sections", ",".join(f"{service}={section}" for service, section in spec.sections.items())]
    if spec.simulate:
        command.append("--simulate")
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHONIOENCODING="utf-8")
    options: Dict[str, Any] = {}
    if os.name == "nt":
        # CREATE_NO_WINDOW and not DETACHED_PROCESS: every ssh.exe would then open a console window of its own
        options["creationflags"] = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    else:
        options["start_new_session"] = True
    path = log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as log:
        return subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env,
                                **options).pid


def keep_awake() -> None:
    """A PC that falls asleep would stop the check and look like a network failure."""
    if os.name == "nt":
        import ctypes

        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)


def apply_candidate(cli: Any, cfg_path: Optional[str], result: Mapping[str, Any]) -> int:
    argv = (["-c", cfg_path] if cfg_path else []) + ["apply", result["candidate"]["id"], "--section", result["section"], "--yes"]
    return cli.main(argv)
