"""Markdown reports for runs and comparisons."""

from __future__ import annotations

import json
from typing import Any, List, Mapping, Optional, Sequence


def _fmt_targets(t: Mapping[str, Any]) -> str:
    parts = []
    for tid, s in t.items():
        parts.append(f"{tid}: {s['k']:g}/{s['n']:g} (LB {s['lb']:.2f})")
    return "; ".join(parts)


DNS_NOTES = {
    "configured": "адрес задан в `[probe] dns_server`, DNS ядра и сверка не использовались",
    "no_live_dns": "DNS живого ядра не найден, адреса взяты у запасного сервера, сверки не было",
    "core_failed": "временное ядро не запустилось с DNS из живого конфига, адреса взяты у запасного сервера, "
                   "сверки не было",
    "no_answers": "DNS ядра не ответил, адреса взяты у запасного сервера",
    "partial": "DNS ядра ответил не на все имена, остальные адреса взяты у запасного сервера",
    "detour": "живой DNS идёт через секцию, а здесь запросы шли напрямую: ответы могут отличаться",
}
DNS_VERDICTS = {
    "ok": "адрес DNS ядра работает",
    "dns": "**виноват DNS**: стратегия работает на адресе сверки",
    "strategy": "не работают оба адреса: дело в стратегии",
    "unclear": "результат неоднозначен",
}


def dns_lines(check: Optional[Mapping[str, Any]]) -> List[str]:
    if not check or not check.get("live"):
        return []
    lines = ["", "## Проверка DNS", "", f"* DNS ядра: `{check['live']}`"]
    if check.get("check"):
        lines.append(f"* Сверка: `{check['check']}`")
    if check.get("note"):
        lines.append(f"* {DNS_NOTES.get(check['note'], check['note'])}")
    if check.get("error"):
        lines.append(f"* Сверка не завершена: {check['error']}")
    rows = check.get("rows") or []
    if check.get("check") and not check.get("error") and not rows:
        lines.append("* Сети адресов совпали, отдельная проверка не понадобилась.")
    problems = [r for r in rows if r["verdict"] != "ok"]
    if rows:
        lines.append(f"* Адреса разошлись на {len(rows)} целях, лучшая стратегия проверена на обоих наборах. "
                     f"На адресах DNS ядра она работает на {len(rows) - len(problems)} из них.")
    if problems:
        lines += ["", "| Цель | Адреса DNS ядра | Успехов | Адреса сверки | Успехов | Вывод |", "|---|---|---:|---|---:|---|"]
        for r in problems:
            lines.append(f"| {r['target']} | {', '.join(r['live']) or '—'} | {r['live_ok']}/{r['live_n']} | "
                         f"{', '.join(r['other'])} | {r['other_ok']}/{r['other_n']} | {DNS_VERDICTS[r['verdict']]} |")
    if any(r["verdict"] == "dns" for r in rows):
        lines += ["", "**Результат поиска занижен:** DNS ядра отдаёт адреса, на которых стратегия не работает, а "
                      "клиенты ходят именно на них. Смените основной DNS в Tachyon и повторите проверку."]
    return lines


def run_report(summary: Mapping[str, Any]) -> str:
    s = summary
    lines: List[str] = []
    title = "Advanced DPI Fuzzer — отчёт о прогоне"
    if s.get("simulated"):
        title += " (СИМУЛЯЦИЯ: результаты не относятся к реальной сети)"
    lines += [f"# {title}", ""]
    lines += [
        f"* Статус: **{s['status']}** {('— ' + s['error']) if s.get('error') else ''}",
        f"* Сеть: `{s['network_id']}`, движок `{s['engine']}` (`{s.get('engine_version', '')}`)",
        f"* Время: {s['seconds']} с, пакетов проб: {s['batches']}, запросов: {s['probes']}",
        f"* Пространство: пул {s['pool_size']} стратегий, проверено в этом прогоне {s['unique_tested']}, "
        f"прошли первичную проверку {s['passed_screening']}, отвергнуто движком {s['invalid']}",
        f"* Эталонный TTFB без обхода: {s.get('reference_ttfb_ms', 0)} мс",
        "",
        "## Классы стратегий",
        "",
        "| Класс | Кол-во |",
        "|---|---:|",
    ]
    for k, v in s["classes"].items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## Baseline (без обхода)", "", "| Цель | Статус | Успехов | Вердикты |", "|---|---|---:|---|"]
    for tid, b in s["baseline"].items():
        lines.append(f"| {tid} | {b['status']} | {b['k']}/{b['n']} | {json.dumps(b['verdicts'], ensure_ascii=False)} |")
    lines += dns_lines(s.get("dns_check"))
    best = s.get("best")
    lines += ["", "## Лучшая стратегия", ""]
    if best:
        lines += [
            f"* Класс: **{best['class']}**, нижняя граница 95 % (худшая цель): **{best['lb']:.3f}**, "
            f"наблюдений на цель ≥ {best['min_n']:g}",
            f"* TTFB p50/p90: {best['p50_ttfb_ms']} / {best['p90_ttfb_ms']} мс, сложность {best['complexity']}",
            f"* Строка (Tachyon `desync_opts`): `{best['text']}`" if best["engine"] == "tachyon_desync"
            else f"* Аргументы: `{best['text']}`",
            f"* По целям: {_fmt_targets(best['targets'])}",
        ]
        if s.get("simplification_chain") and len(s["simplification_chain"]) > 1:
            lines.append(f"* Упрощение: {' → '.join(s['simplification_chain'])}")
    else:
        lines.append("Рабочая стратегия не найдена.")
    lines += ["", "## Топ стратегий", "", "| # | Класс | LB | n/цель | TTFB p50 | Сложн. | Стратегия |",
              "|---:|---|---:|---:|---:|---:|---|"]
    for i, r in enumerate(s.get("top", []), 1):
        lines.append(f"| {i} | {r['class']} | {r['lb']:.3f} | {r['min_n']:g} | {r['p50_ttfb_ms']} | {r['complexity']} "
                     f"| `{r['text']}` |")
    lines += ["", "## Эффективность методов (семейств)", "", "| Семейство | Доля успехов | Испытаний |",
              "|---|---:|---:|"]
    for fam, v in s.get("families", {}).items():
        lines.append(f"| {fam} | {v['success_rate']:.3f} | {v['trials']:g} |")
    lines += ["", "## Вердикты проб", "", "| Вердикт | Кол-во |", "|---|---:|"]
    for k, v in s.get("verdicts", {}).items():
        lines.append(f"| {k} | {v} |")
    if s.get("drift"):
        lines += ["", f"Проверка дрейфа: проверено {s['drift']['checked']}, деградировали: "
                      f"{', '.join(s['drift']['drifted']) or 'нет'}"]
    lines += ["", "## Ограничения", "",
              "* Решения принимаются по нижней границе интервала Уилсона по худшей обязательной цели.",
              "* Цели, недоступные без обхода по L4/DNS, исключены — desync их не исправит.",
              "* UDP/QUIC-параметры оцениваются только при наличии HTTP/3-целей и curl с HTTP/3."]
    return "\n".join(lines) + "\n"


def compare_report(rows: Sequence[Mapping[str, Any]], meta: Mapping[str, Any]) -> str:
    title = "# Сравнение стратегий в одинаковых условиях"
    if meta.get("simulated"):
        title += " (СИМУЛЯЦИЯ)"
    lines = [title, "",
             f"* Сеть: `{meta.get('network_id')}`; повторов на цель: {meta.get('reps')}; "
             f"порядок: чередование по кругу (одинаковые условия сети)",
             f"* Ядро: `{meta.get('engine_version', '')}`",
             f"* Цели: {', '.join(meta.get('targets', []))}", "",
             "| Вариант | Класс | LB (худшая цель) | Успехов (мин. по целям) | TTFB p50 | Стратегия |",
             "|---|---|---:|---:|---:|---|"]
    for r in rows:
        lines.append(f"| {r['label']} | {r['class']} | {r['lb']:.3f} | {r['rate']:.3f} | {r['p50_ttfb_ms']} | "
                     f"`{r['text']}` |")
    failed = [f"* {r['label']}: {r['error']}" for r in rows if r.get("error")]
    if failed:
        lines += ["", "Движок не запустился:", *failed]
    lines += dns_lines(meta.get("dns_check"))
    lines += ["", "LB — нижняя граница 95 % доверительного интервала Уилсона. Разница считается значимой, "
                  "только если интервалы не перекрываются."]
    return "\n".join(lines) + "\n"
