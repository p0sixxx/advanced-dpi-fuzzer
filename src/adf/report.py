"""Markdown reports for runs and comparisons."""

from __future__ import annotations

import json
from typing import Any, List, Mapping, Sequence


def _fmt_targets(t: Mapping[str, Any]) -> str:
    parts = []
    for tid, s in t.items():
        parts.append(f"{tid}: {s['k']:g}/{s['n']:g} (LB {s['lb']:.2f})")
    return "; ".join(parts)


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
    lines += ["", "LB — нижняя граница 95 % доверительного интервала Уилсона. Разница считается значимой, "
                  "только если интервалы не перекрываются."]
    return "\n".join(lines) + "\n"
