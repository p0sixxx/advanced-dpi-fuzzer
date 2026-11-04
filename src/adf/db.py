"""SQLite persistence: strategies, runs, trials, epochs, capabilities, exports."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

from .probe.model import ProbeResult
from .strategy import Strategy

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS strategies (
    id TEXT PRIMARY KEY,
    engine TEXT NOT NULL,
    params TEXT NOT NULL,
    text TEXT NOT NULL,
    complexity REAL NOT NULL,
    origin TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    finished_at REAL,
    network_id TEXT NOT NULL,
    engine TEXT NOT NULL,
    engine_version TEXT NOT NULL DEFAULT '',
    agent TEXT NOT NULL DEFAULT '',
    simulated INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    config TEXT NOT NULL DEFAULT '{}',
    summary TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    spec TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS trials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    strategy_id TEXT REFERENCES strategies(id),
    target_id TEXT NOT NULL,
    ts REAL NOT NULL,
    network_id TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 0,
    simulated INTEGER NOT NULL DEFAULT 0,
    family TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    ok INTEGER NOT NULL,
    counts INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    http_code INTEGER NOT NULL DEFAULT 0,
    curl_exit INTEGER NOT NULL DEFAULT 0,
    connect_ms REAL NOT NULL DEFAULT 0,
    tls_ms REAL NOT NULL DEFAULT 0,
    ttfb_ms REAL NOT NULL DEFAULT 0,
    total_ms REAL NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    phase TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS trials_strategy ON trials(strategy_id, target_id);
CREATE INDEX IF NOT EXISTS trials_network ON trials(network_id, ts);
CREATE TABLE IF NOT EXISTS invalid (
    strategy_id TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    reason TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY (strategy_id, engine_version)
);
CREATE TABLE IF NOT EXISTS epochs (
    network_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    started_at REAL NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (network_id, epoch)
);
CREATE TABLE IF NOT EXISTS capabilities (
    engine TEXT NOT NULL,
    host TEXT NOT NULL,
    data TEXT NOT NULL,
    probed_at REAL NOT NULL,
    PRIMARY KEY (engine, host)
);
CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    strategy_id TEXT NOT NULL,
    section TEXT NOT NULL,
    payload TEXT NOT NULL,
    backup TEXT NOT NULL DEFAULT '',
    applied INTEGER NOT NULL DEFAULT 0,
    rolled_back INTEGER NOT NULL DEFAULT 0
);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        if self.path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        cur = self.conn.execute("SELECT value FROM meta WHERE key='schema_version'")
        row = cur.fetchone()
        if row is None:
            self.conn.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        elif int(row[0]) > SCHEMA_VERSION:
            raise RuntimeError(f"database schema {row[0]} is newer than this program ({SCHEMA_VERSION})")
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.conn
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------ strategies
    def upsert_strategy(self, s: Strategy) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO strategies(id, engine, params, text, complexity, origin, name, created_at) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=CASE WHEN strategies.name='' "
                "THEN excluded.name ELSE strategies.name END",
                (s.id, s.engine, s.params_json, s.text, s.complexity, s.origin, s.name, time.time()))

    def get_strategy(self, sid: str) -> Optional[Strategy]:
        r = self.conn.execute("SELECT * FROM strategies WHERE id=?", (sid,)).fetchone()
        if r is None:
            return None
        return Strategy(engine=r["engine"], params_json=r["params"], text=r["text"], complexity=r["complexity"],
                        origin=r["origin"], name=r["name"], id=r["id"])

    def strategies(self, engine: Optional[str] = None) -> List[Strategy]:
        q = "SELECT * FROM strategies" + (" WHERE engine=?" if engine else "")
        rows = self.conn.execute(q, (engine,) if engine else ()).fetchall()
        return [Strategy(engine=r["engine"], params_json=r["params"], text=r["text"], complexity=r["complexity"],
                         origin=r["origin"], name=r["name"], id=r["id"]) for r in rows]

    def mark_invalid(self, sid: str, engine_version: str, reason: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO invalid(strategy_id, engine_version, reason, ts) VALUES(?,?,?,?)",
                      (sid, engine_version, reason[:500], time.time()))

    def invalid_ids(self, engine_version: str) -> Dict[str, str]:
        rows = self.conn.execute("SELECT strategy_id, reason FROM invalid WHERE engine_version=?",
                                 (engine_version,)).fetchall()
        return {r[0]: r[1] for r in rows}

    # ------------------------------------------------------------------ runs
    def start_run(self, network_id: str, engine: str, engine_version: str, agent: str, simulated: bool,
                  config: Mapping[str, Any]) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO runs(started_at, network_id, engine, engine_version, agent, simulated, config) "
                "VALUES(?,?,?,?,?,?,?)",
                (time.time(), network_id, engine, engine_version, agent, int(simulated),
                 json.dumps(config, default=str)))
            return int(cur.lastrowid)

    def last_engine_version(self, network_id: str, engine: str) -> str:
        row = self.conn.execute("SELECT engine_version FROM runs WHERE network_id=? AND engine=? AND engine_version<>'' "
                                "ORDER BY id DESC LIMIT 1", (network_id, engine)).fetchone()
        return row[0] if row else ""

    def finish_run(self, run_id: int, status: str, summary: Mapping[str, Any]) -> None:
        with self.tx() as c:
            c.execute("UPDATE runs SET finished_at=?, status=?, summary=? WHERE id=?",
                      (time.time(), status, json.dumps(summary, default=str), run_id))

    def runs(self, limit: int = 20) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def save_target_specs(self, specs: Iterable[Mapping[str, Any]]) -> None:
        with self.tx() as c:
            for s in specs:
                c.execute("INSERT OR REPLACE INTO targets(id, spec) VALUES(?,?)", (s["id"], json.dumps(s)))

    # ---------------------------------------------------------------- trials
    def add_trials(self, run_id: int, strategy_id: Optional[str], results: Sequence[ProbeResult], network_id: str,
                   epoch: int, simulated: bool, phase: str, ts: Optional[float] = None) -> None:
        now = ts if ts is not None else time.time()
        with self.tx() as c:
            c.executemany(
                "INSERT INTO trials(run_id, strategy_id, target_id, ts, network_id, epoch, simulated, family, ip, ok, "
                "counts, verdict, http_code, curl_exit, connect_ms, tls_ms, ttfb_ms, total_ms, bytes, phase) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(run_id, strategy_id, r.target, now, network_id, epoch, int(simulated), r.family, r.ip, int(r.ok),
                  int(r.counts), r.verdict, r.http_code, r.curl_exit, r.connect_ms, r.tls_ms, r.ttfb_ms, r.total_ms,
                  r.bytes, phase) for r in results])

    def trials(self, network_id: str, simulated: bool, strategy_ids: Optional[Sequence[str]] = None,
               since: Optional[float] = None, include_baseline: bool = False) -> List[sqlite3.Row]:
        q = ["SELECT * FROM trials WHERE network_id=? AND simulated=?"]
        args: List[Any] = [network_id, int(simulated)]
        if not include_baseline:
            q.append("AND strategy_id IS NOT NULL")
        if since is not None:
            q.append("AND ts>=?")
            args.append(since)
        if strategy_ids is not None:
            ids = list(strategy_ids)
            if not ids:
                return []
            q.append(f"AND strategy_id IN ({','.join('?' * len(ids))})")
            args += ids
        return self.conn.execute(" ".join(q), args).fetchall()

    def max_trial_id(self, run_id: int) -> int:
        r = self.conn.execute("SELECT MAX(id) FROM trials WHERE run_id=?", (run_id,)).fetchone()
        return int(r[0] or 0)

    def invalidate_since(self, run_id: int, trial_id: int) -> int:
        """Mark strategy trials after ``trial_id`` as network-down (not evidence)."""
        with self.tx() as c:
            cur = c.execute("UPDATE trials SET counts=0, verdict='network_down' WHERE run_id=? AND id>? "
                            "AND strategy_id IS NOT NULL AND counts=1", (run_id, trial_id))
            return cur.rowcount

    def retag_epoch(self, run_id: int, epoch: int) -> None:
        """Move the trials of the current run into a newly started epoch."""
        with self.tx() as c:
            c.execute("UPDATE trials SET epoch=? WHERE run_id=?", (epoch, run_id))

    def baseline_trials(self, run_id: int) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM trials WHERE run_id=? AND strategy_id IS NULL", (run_id,)).fetchall()

    def run_trials(self, run_id: int) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM trials WHERE run_id=?", (run_id,)).fetchall()

    # ---------------------------------------------------------------- epochs
    def current_epoch(self, network_id: str) -> int:
        r = self.conn.execute("SELECT MAX(epoch) FROM epochs WHERE network_id=?", (network_id,)).fetchone()
        if r is None or r[0] is None:
            with self.tx() as c:
                c.execute("INSERT INTO epochs(network_id, epoch, started_at, reason) VALUES(?,?,?,?)",
                          (network_id, 0, time.time(), "initial"))
            return 0
        return int(r[0])

    def new_epoch(self, network_id: str, reason: str) -> int:
        e = self.current_epoch(network_id) + 1
        with self.tx() as c:
            c.execute("INSERT INTO epochs(network_id, epoch, started_at, reason) VALUES(?,?,?,?)",
                      (network_id, e, time.time(), reason))
        return e

    def epochs(self, network_id: str) -> List[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM epochs WHERE network_id=? ORDER BY epoch", (network_id,)).fetchall()

    # ---------------------------------------------------------- capabilities
    def save_capabilities(self, engine: str, host: str, data: Mapping[str, Any]) -> None:
        with self.tx() as c:
            c.execute("INSERT OR REPLACE INTO capabilities(engine, host, data, probed_at) VALUES(?,?,?,?)",
                      (engine, host, json.dumps(data), time.time()))

    def load_capabilities(self, engine: str, host: str) -> Optional[Dict[str, Any]]:
        r = self.conn.execute("SELECT data FROM capabilities WHERE engine=? AND host=?", (engine, host)).fetchone()
        return json.loads(r[0]) if r else None

    # --------------------------------------------------------------- exports
    def record_export(self, strategy_id: str, section: str, payload: Mapping[str, Any], backup: str = "",
                      applied: bool = False) -> int:
        with self.tx() as c:
            cur = c.execute("INSERT INTO exports(ts, strategy_id, section, payload, backup, applied) VALUES(?,?,?,?,?,?)",
                            (time.time(), strategy_id, section, json.dumps(payload), backup, int(applied)))
            return int(cur.lastrowid)

    def last_applied_export(self, section: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM exports WHERE section=? AND applied=1 AND rolled_back=0 ORDER BY id DESC LIMIT 1",
            (section,)).fetchone()

    def mark_rolled_back(self, export_id: int) -> None:
        with self.tx() as c:
            c.execute("UPDATE exports SET rolled_back=1 WHERE id=?", (export_id,))

    # ------------------------------------------------------ backup / migrate
    def backup(self, dest: str | Path) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        target = sqlite3.connect(str(dest))
        with target:
            self.conn.backup(target)
        target.close()
        return dest

    def export_jsonl(self, dest: str | Path) -> int:
        n = 0
        with open(dest, "w", encoding="utf-8") as fh:
            for table in ("strategies", "runs", "targets", "epochs", "trials", "invalid", "capabilities", "exports"):
                for row in self.conn.execute(f"SELECT * FROM {table}"):
                    fh.write(json.dumps({"table": table, "row": dict(row)}, ensure_ascii=False) + "\n")
                    n += 1
        return n

    def import_jsonl(self, src: str | Path) -> int:
        """Merge an export. Runs/trials get new ids; strategies dedupe by id."""
        run_map: Dict[int, int] = {}
        n = 0
        with open(src, encoding="utf-8") as fh, self.tx() as c:
            for line in fh:
                item = json.loads(line)
                table, row = item["table"], item["row"]
                if table == "runs":
                    old = row.pop("id")
                    cols = ",".join(row)
                    cur = c.execute(f"INSERT INTO runs({cols}) VALUES({','.join('?' * len(row))})", list(row.values()))
                    run_map[old] = int(cur.lastrowid)
                elif table == "trials":
                    row.pop("id")
                    row["run_id"] = run_map.get(row["run_id"], row["run_id"])
                    cols = ",".join(row)
                    c.execute(f"INSERT INTO trials({cols}) VALUES({','.join('?' * len(row))})", list(row.values()))
                elif table == "exports":
                    continue  # router-specific history is not portable
                else:
                    cols = ",".join(row)
                    c.execute(f"INSERT OR IGNORE INTO {table}({cols}) VALUES({','.join('?' * len(row))})",
                              list(row.values()))
                n += 1
        return n
