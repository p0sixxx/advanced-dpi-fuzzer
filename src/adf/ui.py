"""What the person at the console sees: the menu, live progress and the result."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping, Optional, Sequence

from . import check as job
from . import console, live
from .config import AppConfig
from .console import Terminal, bar, clock, table
from .integrations import tachyon as tachyon_int
from .probe.backend import BackendError

PHASES = {
    "connect": "подключение к роутеру", "baseline": "проверка без обхода", "search": "поиск стратегий",
    "simplify": "упрощение лучшей стратегии", "final": "финальный замер кандидатов",
    "measure": "замер настройки", "dns": "сверка адресов DNS", "done": "готово",
}
MODES = {job.CURRENT: "проверка текущей стратегии", job.QUICK: "быстрая проверка", job.FULL: "долгая проверка"}
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

    return argparse.Namespace(config=config, local=False, uci_file=None)


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


def _pick(names: Sequence[str], titles: Sequence[str], default: Sequence[int] = ()) -> List[str]:
    """One or several numbers, or the last number for all at once. Nothing picked means going back."""
    for i, title in enumerate(titles, 1):
        print(f"{i}  {title}")
    every = len(titles) + 1
    print(f"{every}  Все сразу, по очереди")
    print("0  Назад")
    hint = f" [{','.join(str(i + 1) for i in default)}]" if default else ""
    answer = ask(f"Номера через запятую{hint}: ")
    if answer == "0":
        return []
    if not answer:
        return [names[i] for i in default]
    numbers = [int(part) for part in answer.replace(" ", "").split(",") if part.isdigit()]
    if every in numbers:
        return list(names)
    return list(dict.fromkeys(names[n - 1] for n in numbers if 1 <= n <= len(names)))


def choose_services(default: Sequence[str]) -> List[str]:
    names = list(job.SERVICES)
    print("\nКакие сервисы проверить?")
    return _pick(names, [job.SERVICES[n] for n in names], [names.index(s) for s in default if s in names])


def choose_sections(parsed: Mapping[str, Mapping[str, Any]], default: Sequence[str]) -> Dict[str, str]:
    """Service -> section. A section whose lists name no known service is matched by asking."""
    sections = job.working_sections(parsed)
    if not sections:
        print("\nНа этом роутере нет работающих секций desync, проверять нечего.")
        return {}
    print("\nКакую секцию проверить? Названия взяты с этого роутера.")
    titles = []
    for sid in sections:
        services = [job.SERVICES[s] for s in job.services_of(parsed, sid)]
        titles.append(f"{sid}: {', '.join(services)}" if services else f"{sid}: сервис не определён")
    picked: Dict[str, str] = {}
    for sid in _pick(sections, titles):
        services = job.services_of(parsed, sid)
        if not services:
            print(f"\nЧем проверять секцию {sid}?")
            names = list(job.SERVICES)
            services = _pick(names, [job.SERVICES[n] for n in names], [names.index(s) for s in default if s in names])
        for service in services:
            picked.setdefault(service, sid)
    return picked


def _duration(minutes: float) -> str:
    hours, rest = divmod(int(round(minutes)), 60)
    if hours and rest:
        return f"{hours} ч {rest} мин"
    return f"{hours} ч" if hours else f"{rest} мин"


def _launch(spec: job.Spec, cli: Any) -> None:
    """The time is said before the start: all services one after another take hours."""
    count = len(spec.services)
    print(f"\nСервисов: {count}, по очереди: на роутере работает один временный движок. "
          f"Примерно {_duration(job.planned_minutes(spec))}.")
    if ask("Enter: начать, 0: отмена ") == "0":
        return
    start_check(spec, cli)


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
        print(f"1  Быстрая проверка: подбор, 15-{job.QUICK_MINUTES} минут на сервис")
        print(f"2  Долгая проверка: подбор, около {job.FULL_MINUTES} минут на сервис")
        print("3  Проверка текущей стратегии")
        print("4  Откатить стратегию")
        print("5  Подключение к роутеру")
        print("6  Смотреть проверку или последний результат")
        print("0  Выход")
        answer = ask("> ")
        if answer in ("1", "2"):
            mode, minutes = (job.QUICK, job.QUICK_MINUTES) if answer == "1" else (job.FULL, job.FULL_MINUTES)
            chosen = choose_services(services)
            if chosen:
                services = chosen
                typed = ask(f"Минут на сервис [{minutes}]: ")
                if typed.replace(".", "", 1).isdigit() and float(typed) > 0:
                    minutes = float(typed)
                _launch(job.Spec(mode, chosen, minutes, config=config), cli)
        elif answer == "3":
            try:
                parsed = tachyon_int.parse_uci_show(cli._uci_text(cfg, _namespace(config)))
            except BackendError as e:
                print(term.style(f"Роутер не ответил: {e}", "red"))
                continue
            sections = choose_sections(parsed, services)
            if sections:
                _launch(job.Spec(job.CURRENT, list(sections), config=config, sections=sections), cli)
        elif answer == "6":
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
