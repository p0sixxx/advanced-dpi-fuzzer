"""What the person at the console sees: the menu, live progress and the result."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import check as job
from . import console, live
from .config import AppConfig
from .console import Terminal, bar, clock, table

PHASES = {
    "connect": "подключение к роутеру", "baseline": "проверка без обхода", "search": "поиск стратегий",
    "simplify": "упрощение лучшей стратегии", "final": "финальный замер кандидатов",
    "measure": "замер настройки", "dns": "сверка адресов DNS", "done": "готово",
}
MODES = {job.QUICK: "быстрая проверка", job.FULL: "полный подбор"}
VERDICTS = {"ok": "ok", "tls_timeout": "нет ответа", "tls_reset": "сброс", "server_rejected": "отказ сервера",
            "connect_failed": "нет соединения", "content_mismatch": "чужой ответ", "proxy_error": "ошибка прокси"}
STATUS = {
    "ok": ("РАБОТАЕТ", "green"), "warn": ("РАБОТАЕТ, ЕСТЬ ЗАМЕЧАНИЯ", "yellow"), "fail": ("НЕ РАБОТАЕТ", "red"),
    "dns": ("ВИНОВАТ DNS", "red"), "no_bypass": ("ОБХОД НЕ НАСТРОЕН", "yellow"), "stopped": ("ОСТАНОВЛЕНО", "yellow"), "unknown": ("НЕТ ДАННЫХ", "yellow"),
}
REFRESH_S = 1.0
OK_RATE = 0.9
BAD_RATE = 0.8


def _rate_style(k: float, n: float) -> str:
    rate = k / n if n else 0.0
    return "green" if rate >= OK_RATE else "yellow" if rate >= BAD_RATE else "red"


def _count(value: float) -> str:
    return f"{value:g}"


def _target_rows(term: Terminal, rows: Mapping[str, Mapping[str, Any]]) -> List[List[str]]:
    out = []
    for s in rows.values():
        n, k = s["n"], s["k"]
        tail = "" if s["required"] else term.style(" не обязательная", "dim")
        out.append([s["label"], term.style(f"{_count(k)}/{_count(n)}", _rate_style(k, n)),
                    term.style(bar(k / n if n else 0.0, 12), _rate_style(k, n)) + tail])
    return out


def eta(snapshot: Mapping[str, Any], now: float) -> Optional[float]:
    fraction = float(snapshot.get("fraction") or 0.0)
    spent = now - float(snapshot.get("started") or now)
    if fraction < 0.02 or spent <= 0:
        return None
    return spent * (1 - fraction) / fraction


def render(snapshot: Mapping[str, Any], term: Terminal, now: Optional[float] = None) -> List[str]:
    now = time.time() if now is None else now
    services = snapshot.get("services") or []
    service = snapshot.get("service")
    place = ""
    if service:
        place = f" · {job.SERVICES.get(service, service)} ({int(snapshot.get('index', 0)) + 1} из {len(services)})"
    title = f"Advanced DPI Fuzzer · {MODES.get(snapshot.get('mode'), '')}{place}"
    if snapshot.get("simulated"):
        title += term.style(" · СИМУЛЯЦИЯ", "yellow")
    fraction = float(snapshot.get("fraction") or 0.0)
    spent = now - float(snapshot.get("started") or now)
    left = eta(snapshot, now)
    lines = [
        term.style(title, "bold"),
        f"{term.style(bar(fraction), 'cyan')} {fraction * 100:3.0f} %   прошло {clock(spent)}, "
        f"осталось {'≈ ' + clock(left) if left is not None else 'оценивается'}",
    ]
    facts = [PHASES.get(str(snapshot.get("phase")), str(snapshot.get("phase")))]
    if snapshot.get("pool"):
        facts.append(f"проверено {snapshot.get('tested', 0)} из {snapshot['pool']} стратегий")
    if snapshot.get("probes"):
        facts.append(f"запросов {snapshot['probes']}")
    lines.append("Этап: " + " · ".join(facts))
    if snapshot.get("detail"):
        lines.append(term.style(f"Сейчас: {snapshot['detail']}", "dim"))
    leader = snapshot.get("best")
    if leader:
        lines += ["", f"Лучшая пока: {leader['text']}"]
    rows = snapshot.get("table") or {}
    if rows:
        lines += [""] + table(["Цель", "Успехов", ""], _target_rows(term, rows), right=(1,))
    verdicts = snapshot.get("verdicts") or {}
    if verdicts:
        parts = [f"{VERDICTS.get(k, k)} {v}" for k, v in sorted(verdicts.items(), key=lambda kv: -kv[1])]
        lines += ["", "Ответы: " + " · ".join(parts)]
    for line in (snapshot.get("log") or [])[-2:]:
        if "round" not in line:
            lines.append(term.style(line, "dim"))
    lines += ["", term.style("Ctrl+C: остановить или выйти. Если закрыть окно, проверка продолжится: adf watch", "dim")]
    return lines


def _advice(result: Mapping[str, Any]) -> List[str]:
    status = result.get("status")
    candidate = result.get("candidate") or {}
    out = []
    if status == "dns":
        names = ", ".join(result.get("dns_targets") or ())
        out.append(f"Смените основной DNS в Tachyon: на адресах DNS ядра не работает {names}, а на адресах сверки работает.")
    if candidate.get("better"):
        out.append("Найдена стратегия лучше текущей.")
    elif status == "fail" and result.get("search"):
        out.append("Подбор не нашёл стратегию заметно лучше текущей.")
    elif status in ("fail", "no_bypass"):
        out.append("Запустите полный подбор: adf check --full --services " + str(result.get("service")))
    elif status == "warn":
        names = [result["rows"][t]["label"] for t in [*(result.get("shaky") or ()), *(result.get("optional") or ())]
                 if t in result.get("rows", {})]
        out.append(f"Отдельные сбои: {', '.join(names)}. Повторите проверку; если они повторятся, запустите полный подбор.")
    if result.get("section") is None and candidate.get("better"):
        out.append("Применить автоматически некуда: создайте для сервиса секцию desync и задайте в ней эту стратегию.")
    return out


def _dns_lines(term: Terminal, dns: Mapping[str, Any]) -> List[str]:
    if not dns or not dns.get("live"):
        return []
    line = f"DNS ядра: {dns['live']}"
    if dns.get("check"):
        line += f", сверка: {dns['check']}"
    lines = [line]
    differ = dns.get("rows") or []
    if differ:
        bad = {r["host"]: r for r in reversed(differ) if r["verdict"] != "ok"}     # a host has two targets
        hosts = {r["host"] for r in differ}
        lines.append(f"Адреса разошлись на {len(hosts)} хостах, проблемных из них: {len(bad)}.")
        for host, r in bad.items():
            lines.append(term.style(f"  {host}: адреса ядра {r['live_ok']}/{r['live_n']}, "
                                    f"адреса сверки {r['other_ok']}/{r['other_n']}", "yellow"))
    if dns.get("error"):
        lines.append(term.style(f"Сверка не завершена: {dns['error']}", "yellow"))
    return lines


def result_lines(snapshot: Mapping[str, Any], term: Terminal) -> List[str]:
    lines = [term.style(f"Итог · {MODES.get(snapshot.get('mode'), '')}", "bold")]
    if snapshot.get("core"):
        lines[0] += f" · {snapshot['core']}"
    if snapshot.get("simulated"):
        lines.append(term.style("СИМУЛЯЦИЯ: результаты не относятся к реальной сети.", "yellow"))
    if snapshot.get("status") == live.STOPPED:
        lines.append(term.style("Проверка остановлена, собранные данные сохранены.", "yellow"))
    if snapshot.get("error"):
        lines += [term.style(f"Ошибка: {snapshot['error']}", "red"),
                  "Если роутер недоступен, проверьте подключение: adf setup"]
    for result in snapshot.get("results") or ():
        text, color = STATUS.get(str(result.get("status")), ("НЕТ ДАННЫХ", "yellow"))
        lines += ["", term.style(f"{result['name']}: {text}", color, "bold")]
        if result.get("section"):
            lines.append(f"Секция {result['section']}: {result.get('current', '')}")
        else:
            lines.append("Секции desync нет, показан результат без обхода.")
        rows = result.get("rows") or {}
        if rows:
            lines += [""] + table(["Сейчас", "Успехов", ""], _target_rows(term, rows), right=(1,)) + [""]
        candidate = result.get("candidate")
        if candidate:
            lines.append(f"Найдена: {candidate['text']}")
            if candidate.get("rows"):
                lines += [""] + table(["Найденная", "Успехов", ""], _target_rows(term, candidate["rows"]), right=(1,)) + [""]
            lines.append(f"Надёжность, нижняя граница: найденная {candidate['lb']:.2f}, текущая {result.get('lb', 0):.2f}")
        search = result.get("search")
        if search:
            lines.append(f"Подбор: проверено {search['tested']} из {search['pool']} стратегий, запросов {search['probes']}.")
        lines += _dns_lines(term, result.get("dns") or {})
        lines += [term.style("→ " + advice, "cyan") for advice in _advice(result)]
    if snapshot.get("report"):
        lines += ["", f"Отчёт: {snapshot['report']}"]
    return lines


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def offer_apply(snapshot: Mapping[str, Any], cli: Any, config: Optional[str], term: Terminal) -> None:
    """Nothing reaches the router without a typed answer, here and only here."""
    if snapshot.get("simulated"):
        return
    for result in snapshot.get("results") or ():
        candidate = result.get("candidate") or {}
        if not candidate.get("better") or not result.get("section"):
            continue
        print(f"\nПрименить найденную стратегию к секции {result['section']}?")
        if ask("Напишите «да», чтобы применить, или нажмите Enter, чтобы оставить как есть: ").lower() != "да":
            print("Оставлено как есть.")
            continue
        code = job.apply_candidate(cli, config, result)
        if code == 0:
            print(term.style(f"Применено. Проверьте сервис в браузере. Откат: adf rollback --section {result['section']}", "green"))
        else:
            print(term.style("Не удалось применить, настройки роутера не должны были измениться: проверьте adf watch", "red"))


def _pause(cfg: AppConfig) -> bool:
    """False when the viewer should leave."""
    print()
    print("Enter  смотреть дальше\n2      остановить проверку, собранное сохранится\n0      выйти, проверка продолжится")
    try:
        answer = input("> ").strip()
    except (EOFError, KeyboardInterrupt):       # a second Ctrl+C means leave
        print()
        return False
    if answer == "2":
        cfg.stop_file.parent.mkdir(parents=True, exist_ok=True)
        cfg.stop_file.write_text(str(time.time()))
        print("Остановка запрошена, проверка завершит текущий шаг.")
        return True
    return answer != "0"


def watch(cli: Any, config: Optional[str]) -> int:
    term = console.prepare()
    cfg = cli._cfg(_namespace(config))
    path = job.state_path()
    screen = console.Screen(term)
    while True:
        try:
            snapshot = live.read(path)
            if snapshot is None:
                print("Проверок ещё не было. Запустите: adf check")
                return 1
            snapshot = live.settled(snapshot)
            if snapshot.get("status") != live.RUNNING:
                screen.release()
                print()
                print("\n".join(result_lines(snapshot, term)))
                if _interactive():
                    offer_apply(snapshot, cli, config, term)
                return 0 if snapshot.get("status") == live.FINISHED else 3
            lines = render(snapshot, term)
            step = int(float(snapshot.get("fraction") or 0.0) * 20)
            screen.draw(lines, key=f"{snapshot.get('service')}:{snapshot.get('phase')}:{step}")
            time.sleep(REFRESH_S)
        except KeyboardInterrupt:
            screen.release()
            if not _interactive() or not _pause(cfg):
                print("Проверка продолжается. Посмотреть: adf watch, остановить: adf stop")
                return 0


def _namespace(config: Optional[str]) -> Any:
    import argparse

    return argparse.Namespace(config=config)


def _interactive() -> bool:
    import sys

    return sys.stdin.isatty() and sys.stdout.isatty()


def status() -> int:
    term = console.prepare()
    snapshot = live.read(job.state_path())
    if snapshot is None:
        print("Проверок ещё не было.")
        return 1
    snapshot = live.settled(snapshot)
    if snapshot.get("status") == live.RUNNING:
        print("\n".join(render(snapshot, term)))
    else:
        print("\n".join(result_lines(snapshot, term)))
    return 0


def start_check(spec: job.Spec, cli: Any, attach: bool = True) -> int:
    path = job.state_path()
    if live.active(live.read(path)):
        print("Проверка уже идёт, подключаюсь к ней.")
        return watch(cli, spec.config) if attach else 0
    pid = job.spawn(spec)
    live.write(path, {"pid": pid, "status": live.RUNNING, "mode": spec.mode, "services": spec.services,
                      "simulated": spec.simulate, "started": time.time(), "phase": "connect", "fraction": 0.0})
    if not attach:
        print("Проверка запущена. Посмотреть: adf watch, остановить: adf stop")
        return 0
    return watch(cli, spec.config)


def choose_services(default: Sequence[str]) -> List[str]:
    names = list(job.SERVICES)
    print("\nКакие сервисы проверить?")
    for i, name in enumerate(names, 1):
        print(f"{i}  {job.SERVICES[name]}")
    answer = ask(f"Номера через запятую [{','.join(str(names.index(s) + 1) for s in default)}]: ")
    if not answer:
        return list(default)
    picked = []
    for part in answer.replace(" ", "").split(","):
        if part.isdigit() and 1 <= int(part) <= len(names):
            picked.append(names[int(part) - 1])
    return list(dict.fromkeys(picked)) or list(default)


def _header(cfg: AppConfig, term: Terminal) -> List[str]:
    where = f"{cfg.router.user}@{cfg.router.host}" if cfg.router.host else "роутер не подключён"
    return ["", term.style("Advanced DPI Fuzzer", "bold") + f" · {where}"]


def menu(cli: Any, config: Optional[str], cfg: AppConfig) -> int:
    from . import connect

    term = console.prepare()
    services: List[str] = list(cfg.search.categories) or ["youtube"]
    if not cfg.router.host and not cfg.router.local:
        print("Роутер ещё не подключён, настроим подключение.")
        if connect.setup() != 0:
            return 1
        cfg = cli._cfg(_namespace(config))
    while True:
        print("\n".join(_header(cfg, term)))
        running = live.active(live.read(job.state_path()))
        if running:
            print(term.style("Идёт проверка.", "cyan"))
        print("1  Быстрая проверка: работает ли текущая настройка, несколько минут")
        print("2  Полный подбор: поиск стратегии лучше текущей")
        print("3  Смотреть проверку или последний результат")
        print("4  Откатить стратегию")
        print("5  Подключение к роутеру")
        print("0  Выход")
        answer = ask("> ")
        if answer == "1":
            services = choose_services(services)
            start_check(job.Spec(job.QUICK, services, config=config), cli)
        elif answer == "2":
            services = choose_services(services)
            typed = ask(f"Минут на всё [{job.FULL_MINUTES}]: ")
            minutes = float(typed) if typed.replace(".", "", 1).isdigit() and float(typed) > 0 else job.FULL_MINUTES
            start_check(job.Spec(job.FULL, services, minutes, config=config), cli)
        elif answer == "3":
            watch(cli, config)
        elif answer == "4":
            section = ask("Секция, например YouTube_desync: ")
            if section:
                argv = (["-c", config] if config else []) + ["rollback", "--section", section]
                cli.main(argv)
        elif answer == "5":
            connect.setup()
            cfg = cli._cfg(_namespace(config))
        elif answer in ("0", ""):
            return 0
