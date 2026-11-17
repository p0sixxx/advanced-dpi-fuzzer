"""Read-only health check of a Tachyon installation (``adf tachyon-check``).

One SSH call collects: Tachyon and tachyon-core versions, desync sections, balancers,
outbound groups/sources (names and references only) and the *names* of inline
Amnezia configurations. Keys, subscription URLs and configuration bodies are never
printed by the router-side command.

Semantics follow Tachyon 1.8.0 (``config/connections.uc``, ``views/balancers.ts``)
and the tachyon-core 0.5.9 reference (``docs/reference/outbounds/desync.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .tachyon import desync_sections, parse_uci_show, section_to_params

_KEYS = ("name", "label", "enabled", "action", "source_type", "balancer_type", "mode", "section",
         "outbound_group_levels", "group_refs", "source_refs", "include_outbounds", "exclude_outbounds",
         "include_regex", "exclude_regex", "include_prefixes", "balancer_refs", "outbound_group_refs",
         "outbound_source_refs", "testing_url", "active_check_interval", "urltest_active_check_interval",
         "tolerance")
_TYPES = ("section", "outbound_source", "outbound_group", "balancer", "priority_group", "priority_level")
UCI_FILTER = (r"^tachyon\.[^.=]+=(" + "|".join(_TYPES) + r")$|"
              r"^tachyon\.[^.=]+\.(" + "|".join(_KEYS) + r"|desync_[a-z0-9_]+)=")

# Prints only the "name" field of inline Amnezia configurations (never keys).
_AMNEZIA_NAMES = r"""ucode -e '
let c = require("uci").cursor();
function f(s) {
  for (let k in ["amnezia_configs", "selector_amnezia_configs"]) {
    let v = s[k];
    if (v == null) continue;
    if (type(v) != "array") v = [v];
    for (let i = 0; i < length(v); i++) {
      let j = null;
      try { j = json(v[i]); } catch (e) {}
      print(s[".name"] + "\t" + k + "\t" + i + "\t" + ((j && j.name) ? j.name : "") + "\n");
    }
  }
}
c.foreach("tachyon", "section", f);
c.foreach("tachyon", "outbound_source", f);
' 2>/dev/null"""

CHECK_CMD = "\n".join([
    "echo '== tachyon'; (tachyon show_version 2>/dev/null || apk list -I 2>/dev/null | grep -i '^tachyon' "
    "|| opkg list-installed 2>/dev/null | grep -i '^tachyon') | head -3",
    "echo '== core'; tachyon-core version 2>&1 | head -1",
    f"echo '== uci'; uci -q show tachyon | grep -E '{UCI_FILTER}'",
    "echo '== amnezia'; " + _AMNEZIA_NAMES,
    "echo '== end'",
])


@dataclass
class Finding:
    level: str      # "error" | "warning" | "info"
    topic: str
    text: str


@dataclass
class BalancerView:
    id: str
    name: str
    type: str
    levels: List[str]           # resolved display names, in priority order
    raw_levels: List[str]
    used_by: List[str]
    mode: str = ""


@dataclass
class CheckResult:
    tachyon_version: str
    core_version: str
    desync: List[Dict[str, Any]] = field(default_factory=list)
    balancers: List[BalancerView] = field(default_factory=list)
    amnezia_names: List[Dict[str, str]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


def split_sections(text: str) -> Dict[str, str]:
    parts: Dict[str, List[str]] = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r"^== (\w+)$", line.strip())
        if m:
            cur = m.group(1)
            parts.setdefault(cur, [])
            continue
        if cur:
            parts[cur].append(line)
    return {k: "\n".join(v).strip() for k, v in parts.items()}


def _list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        out: List[str] = []
        for x in v:
            out += _list(x)
        return out
    s = str(v).strip()
    if s.startswith("srv:"):
        return [s]  # a server name may contain spaces
    return [x for x in s.split() if x]


def _version_tuple(text: str) -> tuple:
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else ()


def _display(cfg: Mapping[str, Mapping[str, Any]], ref: str) -> str:
    if ref == "direct":
        return "Direct"
    if ref.startswith("srv:"):
        return ref[4:]
    sec = cfg.get(ref, {})
    return str(sec.get("name") or sec.get("label") or ref)


def analyze(text: str, backup: Sequence[str] = (), rename: Optional[Sequence[str]] = None) -> CheckResult:
    """``backup``: names (or substrings) that must only be a fallback tier.
    ``rename``: (old, new) — report every place the old name is used."""
    parts = split_sections(text)
    res = CheckResult(tachyon_version=parts.get("tachyon", "").splitlines()[0] if parts.get("tachyon") else "",
                      core_version=parts.get("core", ""))
    cfg = parse_uci_show(parts.get("uci", ""))
    core_v = _version_tuple(res.core_version)

    if not res.tachyon_version:
        res.findings.append(Finding("warning", "versions", "Tachyon version not reported"))
    if core_v and core_v < (0, 5, 0):
        res.findings.append(Finding("info", "versions", f"tachyon-core {res.core_version}: defaults differ from the "
                                    "0.5.x reference used by ADF (fooling/auto_tune); run `adf caps`"))

    # ---- desync sections
    for sid in desync_sections(cfg):
        imp = section_to_params(sid, cfg[sid])
        item = {"section": sid, "kind": imp.kind, "outbound": imp.outbound, "notes": imp.notes}
        res.desync.append(item)
        if imp.ignored_opts:
            res.findings.append(Finding("warning", sid, "«Строка стратегии» (desync_opts) игнорируется: пресет не "
                                        f"«custom» ({imp.outbound.get('preset')})"))
        if imp.kind == "fixed" and imp.auto_tune is None and core_v >= (0, 5, 0):
            res.findings.append(Finding("warning", sid, "auto_tune не задан → в tachyon-core 0.5+ он включён по "
                                        "умолчанию: параметры секции только стартовые, ядро может их менять"))
        if imp.kind == "fixed" and "fooling" not in imp.outbound and imp.outbound.get("mode") in (
                "fake", "fake_split", "fake_disorder", "multi_disorder"):
            res.findings.append(Finding("info", sid, "fooling не задан → ядро 0.5+ использует md5"))

    # ---- balancers
    sections_by_bal: Dict[str, List[str]] = {}
    for sid, opts in cfg.items():
        for b in _list(opts.get("balancer_refs")):
            sections_by_bal.setdefault(b, []).append(sid)
    for bid, opts in cfg.items():
        if opts.get(".type") != "balancer":
            continue
        btype = str(opts.get("balancer_type") or "urltest").lower()
        raw: List[str] = []
        for sid in sections_by_bal.get(bid, []):   # balancers.ts: levels stored on the using section first
            raw = _list(cfg[sid].get("outbound_group_levels"))
            if raw:
                break
        if not raw:
            raw = _list(opts.get("outbound_group_levels"))
        if not raw and btype != "priority":
            raw = _list(opts.get("group_refs")) or _list(opts.get("source_refs"))
        view = BalancerView(bid, str(opts.get("name") or bid), btype, [_display(cfg, r) for r in raw], raw,
                            sections_by_bal.get(bid, []), str(opts.get("mode") or ""))
        res.balancers.append(view)
        if str(opts.get("enabled", "1")) == "0":
            res.findings.append(Finding("info", bid, "балансировщик выключен"))
        for name in backup:
            hits = [i for i, lv in enumerate(view.levels) if name.lower() in lv.lower()]
            members = " ".join(view.levels).lower()
            if btype != "priority":
                if hits or name.lower() in members:
                    res.findings.append(Finding("error", bid, f"тип «{btype}»: «{name}» участвует наравне с "
                                                "остальными и может стать основным; для резерва нужен тип "
                                                "«priority» с ним на последней ступени"))
                continue
            if not hits:
                res.findings.append(Finding("warning", bid, f"«{name}» не найден среди ступеней: "
                                            f"{' → '.join(view.levels) or '(пусто)'}"))
            elif hits[-1] != len(view.levels) - 1 or hits[0] == 0:
                res.findings.append(Finding("error", bid, f"«{name}» стоит на ступени {hits[0] + 1} из "
                                            f"{len(view.levels)}; резерв должен быть последней ступенью"))
            else:
                res.findings.append(Finding("info", bid, f"OK: «{name}» — резервная (последняя) ступень "
                                            f"из {len(view.levels)}"))

    # ---- amnezia names and rename impact
    for line in parts.get("amnezia", "").splitlines():
        cols = line.split("\t")
        if len(cols) == 4:
            res.amnezia_names.append({"section": cols[0], "option": cols[1], "index": cols[2], "name": cols[3]})
    if rename:
        old = rename[0]
        places = [f"{a['section']}.{a['option']}[{a['index']}] (имя Amnezia-конфигурации)"
                  for a in res.amnezia_names if a["name"] == old]
        for sid, opts in cfg.items():
            for key in ("name", "label"):
                if str(opts.get(key, "")) == old:
                    places.append(f"{sid}.{key}")
            for key in ("outbound_group_levels", "include_outbounds", "exclude_outbounds"):
                for v in _list(opts.get(key)):
                    if v == old or v == f"srv:{old}":
                        places.append(f"{sid}.{key} → {v}")
            for key in ("include_regex", "exclude_regex"):
                for v in _list(opts.get(key)):
                    try:
                        if re.search(v, old):
                            places.append(f"{sid}.{key} → /{v}/ совпадает со старым именем")
                    except re.error:
                        pass
        if places:
            res.findings.append(Finding("info", "rename", f"«{old}» используется в: " + "; ".join(places)))
        else:
            res.findings.append(Finding("warning", "rename", f"«{old}» не найдено ни в именах, ни в ссылках"))
    return res


def report(res: CheckResult) -> str:
    lines = ["# Проверка Tachyon", "", f"* Tachyon: `{res.tachyon_version or '?'}`",
             f"* tachyon-core: `{res.core_version or '?'}`", "", "## Секции Native Desync", ""]
    for d in res.desync:
        lines.append(f"* **{d['section']}** ({d['kind']}): `{d['outbound']}`")
    lines += ["", "## Балансировщики", ""]
    for b in res.balancers:
        mode = f", алгоритм `{b.mode}`" if b.mode and b.type == "urltest" else ""
        lines.append(f"* **{b.name}** (`{b.id}`), тип `{b.type}`{mode}, используется: "
                     f"{', '.join(b.used_by) or '—'}")
        lines.append(f"  * порядок: {' → '.join(b.levels) or '(не задан)'}")
    if res.amnezia_names:
        lines += ["", "## Amnezia-конфигурации (только имена)", ""]
        lines += [f"* {a['section']}.{a['option']}[{a['index']}]: «{a['name']}»" for a in res.amnezia_names]
    lines += ["", "## Замечания", ""]
    icon = {"error": "❌", "warning": "⚠️", "info": "ℹ️"}
    lines += [f"* {icon[f.level]} **{f.topic}**: {f.text}" for f in res.findings] or ["* нет"]
    return "\n".join(lines) + "\n"
