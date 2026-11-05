"""Connects a PC to the router once, so that every later command runs without a password."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence

from .config import adf_home

KEY = Path.home() / ".ssh" / "adf_router"
# OpenWrt's dropbear keeps root's keys apart from the usual place
INSTALL_KEY = ('if [ -d /etc/dropbear ]; then f=/etc/dropbear/authorized_keys; '
               'else mkdir -p ~/.ssh && chmod 700 ~/.ssh; f=~/.ssh/authorized_keys; fi; '
               'k=$(cat); touch "$f"; grep -qxF "$k" "$f" || printf "%s\\n" "$k" >> "$f"; chmod 600 "$f"')
ABOUT_ROUTER = 'cat /proc/sys/kernel/hostname; tachyon-core version 2>/dev/null | head -n1; true'


def parse_gateway(text: str) -> str:
    """The default gateway from `route print -4 0.0.0.0` or `ip route show default`."""
    found = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s", text, re.M)
    if not found:
        found = re.search(r"^default via (\d+\.\d+\.\d+\.\d+)", text, re.M)
    return found.group(1) if found else ""


def default_gateway() -> str:
    for command in (["route", "print", "-4", "0.0.0.0"], ["ip", "route", "show", "default"]):
        if shutil.which(command[0]):
            try:
                out = subprocess.run(command, capture_output=True, text=True, errors="replace", timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                continue
            gateway = parse_gateway(out.stdout)
            if gateway:
                return gateway
    return ""


def ssh_command(host: str, user: str, port: int, key: Optional[Path], batch: bool) -> List[str]:
    command = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", "-p", str(port)]
    if batch:
        command += ["-o", "BatchMode=yes"]
    if key:
        command += ["-i", str(key)]
    return command + [f"{user}@{host}"]


def login_works(host: str, user: str, port: int, key: Optional[Path]) -> Optional[str]:
    """What the router says about itself, or None when the key does not get in."""
    try:
        done = subprocess.run(ssh_command(host, user, port, key, True) + [ABOUT_ROUTER], capture_output=True, text=True,
                              errors="replace", timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout.strip().replace("\n", ", ") if done.returncode == 0 else None


def create_key(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "adf", "-f", str(path)], check=True)


def install_key(host: str, user: str, port: int, key: Path) -> bool:
    """ssh itself asks for the password in the console; ADF never sees it."""
    public = key.with_name(key.name + ".pub").read_text(encoding="utf-8").strip()
    done = subprocess.run(ssh_command(host, user, port, None, False) + [INSTALL_KEY], input=public, text=True)
    return done.returncode == 0


def toml_router(host: str, user: str, port: int, key: Path) -> str:
    # literal strings: a Windows path holds backslashes
    return f"[router]\nhost = '{host}'\nuser = '{user}'\nport = {port}\nidentity = '{key}'\n"


def merged_config(old: str, router: str) -> str:
    kept: List[str] = []
    skipping = False
    for line in old.splitlines():
        if line.strip().startswith("["):
            skipping = line.strip() == "[router]"
        if not skipping:
            kept.append(line)
    return router + ("\n" + "\n".join(kept).strip() + "\n" if any(line.strip() for line in kept) else "")


def save(host: str, user: str, port: int, key: Path) -> Path:
    path = adf_home() / "config.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    path.write_text(merged_config(old, toml_router(host, user, port, key)), encoding="utf-8")
    return path


def missing_tools(names: Sequence[str] = ("ssh", "ssh-keygen")) -> List[str]:
    return [name for name in names if not shutil.which(name)]


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    return input(f"{prompt}{suffix}: ").strip() or default


def setup(host: Optional[str] = None, user: str = "root", port: int = 22, key: Optional[str] = None) -> int:
    missing = missing_tools()
    if missing:
        print(f"Не найдено: {', '.join(missing)}. В Windows это компонент «Клиент OpenSSH» в разделе "
              "Параметры → Система → Дополнительные компоненты.")
        return 1
    host = host or _ask("Адрес роутера", default_gateway())
    if not host:
        print("Адрес роутера не указан.")
        return 1
    path = Path(key).expanduser() if key else KEY
    if not path.exists():
        print(f"Создаю SSH-ключ {path}")
        create_key(path)
    about = login_works(host, user, port, path)
    if about is None:
        print(f"Ключ ещё не установлен на {user}@{host}. Сейчас ssh спросит пароль роутера, "
              "ключ будет добавлен в его список разрешённых.")
        if _ask("Продолжить? (да/нет)", "да").lower() not in ("да", "yes", "y", "д"):
            return 2
        if not install_key(host, user, port, path):
            print("Не удалось установить ключ: проверьте адрес и пароль.")
            return 1
        about = login_works(host, user, port, path)
    if about is None:
        print("Ключ установлен, но вход по нему не работает. Проверьте, разрешён ли вход по ключу на роутере.")
        return 1
    print(f"Подключено: {user}@{host} ({about})")
    print(f"Настройки сохранены: {save(host, user, port, path)}")
    return 0
