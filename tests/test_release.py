"""The router build: self-extracting installer, `adf-router` and an install on a fake router."""

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a POSIX shell, run in WSL")
SHELLS = ["sh"] + (["busybox ash"] if shutil.which("busybox") else [])


def load_builder():
    spec = importlib.util.spec_from_file_location("build_release", ROOT / "packaging" / "build_release.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Router:
    """A directory tree standing in for the router; `python3` delegates to the test interpreter."""

    def __init__(self, tmp: Path, shell: str, python_installed: bool = True):
        self.tmp, self.shell = tmp, shell
        self.tools = tmp / "tools"
        self.bin = tmp / "usr-bin"
        self.prefix = tmp / "opt-adf"
        self.conf = tmp / "etc-adf"
        self.home = tmp / "root"
        self.apk_log = tmp / "apk.log"
        self.python_marker = tmp / "python-installed"
        for d in (self.tools, self.bin, self.home):
            d.mkdir()
        if python_installed:
            self.python_marker.touch()
        self._tool("python3", f'[ -f "{self.python_marker}" ] || exit 1\nexec "{sys.executable}" "$@"\n')
        self._tool("apk", f'echo "$*" >> "{self.apk_log}"\n[ "$1" != add ] || touch "{self.python_marker}"\n')
        self.env = {**os.environ, "HOME": str(self.home), "ADF_PREFIX": str(self.prefix),
                    "ADF_BIN_DIR": str(self.bin), "ADF_CONF_DIR": str(self.conf),
                    "PATH": f"{self.tools}:{self.bin}:{os.environ['PATH']}"}
        self.env.pop("PYTHONPATH", None)

    def _tool(self, name: str, body: str) -> None:
        path = self.tools / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)

    def sh(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run([*self.shell.split(), *args], capture_output=True, text=True, env=self.env,
                              timeout=timeout, stdin=subprocess.DEVNULL)

    def cmd(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run([*args], capture_output=True, text=True, env=self.env, timeout=timeout,
                              stdin=subprocess.DEVNULL)

    def wait_finished(self, timeout: float = 45) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            out = self.cmd("adf-router", "status").stdout
            if out.startswith("not running"):
                return out
            time.sleep(0.2)
        raise AssertionError("search did not finish: " + out)


@pytest.fixture(scope="module")
def installer(tmp_path_factory):
    return load_builder().build(tmp_path_factory.mktemp("dist"))


@pytest.fixture(scope="module")
def github_archive(tmp_path_factory):
    """What codeload.github.com serves for a branch: one top directory holding the repository."""
    path = tmp_path_factory.mktemp("github") / "repo.tgz"
    with tarfile.open(path, "w:gz") as tar:
        for name in ("src/adf", "agent", "packaging"):
            tar.add(ROOT / name, arcname=f"advanced-dpi-fuzzer-branch/{name}",
                    filter=lambda t: None if "__pycache__" in t.name else t)
    return path


def one_command(r, archive):
    r._tool("curl", f"""echo "$*" >> "{r.tmp}/curl.log"
while [ $# -gt 1 ]; do [ "$1" = -o ] && out=$2; shift; done
cp "{archive}" "$out"
""")
    return ROOT / "install.sh"


def test_build_is_reproducible_and_lf_only(installer, tmp_path):
    again = load_builder().build(tmp_path)
    assert again.read_bytes() == installer.read_bytes()
    head = installer.read_bytes().split(b"PAYLOAD_SHA256=", 1)[0]
    assert b"\r" not in head and head.startswith(b"#!/bin/sh\n")


@pytest.mark.parametrize("shell", SHELLS)
def test_install_run_and_uninstall(installer, tmp_path, shell):
    r = Router(tmp_path, shell)
    done = r.sh(str(installer))
    assert done.returncode == 0, done.stderr
    assert not r.apk_log.exists()  # Python was already there
    assert (r.prefix / "agent" / "adf-agent.sh").is_file() and (r.conf / "config.toml").is_file()
    assert "Advanced" in r.cmd("adf", "--help").stdout + r.cmd("adf-router", "help").stdout

    started = r.cmd("adf-router", "run", "--categories", "youtube", "--minutes", "1", "--",
                    "--simulate", "--max-batches", "6")
    assert started.returncode == 0, started.stderr
    status = r.wait_finished()
    assert "exit code 0" in status, status
    report = r.cmd("adf-router", "report")
    assert report.returncode == 0 and "отчёт о прогоне" in report.stdout
    assert r.cmd("adf-router", "best").returncode == 0

    (r.conf / "config.toml").write_text((r.conf / "config.toml").read_text() + "# user edit\n")
    assert r.sh(str(installer)).returncode == 0  # reinstall keeps the user's config
    assert "# user edit" in (r.conf / "config.toml").read_text()

    assert r.cmd("adf-router", "uninstall").returncode == 0
    assert not r.prefix.exists() and not (r.bin / "adf").exists() and not (r.bin / "adf-router").exists()
    assert (r.conf / "config.toml").exists() and (r.home / ".adf" / "reports").is_dir()


def test_installer_installs_python(installer, tmp_path):
    r = Router(tmp_path, "sh", python_installed=False)
    done = r.sh(str(installer))
    assert done.returncode == 0, done.stderr
    assert "python3-sqlite3" in r.apk_log.read_text()


def test_no_deps_never_calls_the_package_manager(installer, tmp_path):
    r = Router(tmp_path, "sh", python_installed=False)
    done = r.sh(str(installer), "--no-deps")
    assert done.returncode != 0 and "--no-deps" in done.stderr
    assert not r.apk_log.exists() and not r.prefix.exists()


SIMULATE = ("--", "--simulate", "--max-batches", "6")


@pytest.mark.parametrize("shell", SHELLS)
def test_one_command_installs_and_asks_for_the_service(github_archive, tmp_path, shell):
    r = Router(tmp_path, shell)
    script = one_command(r, github_archive)
    answers = tmp_path / "answers"
    answers.write_text("99\n")  # the menu appears, then an invalid answer ends it before any probe
    r.env["ADF_TTY"] = str(answers)
    done = r.cmd(*shell.split(), "-c", script.read_text(), timeout=90)
    assert "codeload.github.com/p0sixxx/advanced-dpi-fuzzer" in (tmp_path / "curl.log").read_text()
    assert (r.prefix / "VERSION").read_text().strip() and (r.bin / "adf-router").exists()
    assert "Which service to check?" in done.stdout, done.stdout + done.stderr


def test_one_command_without_terminal_only_installs(github_archive, tmp_path):
    r = Router(tmp_path, "sh")
    script = one_command(r, github_archive)
    r.env["ADF_TTY"] = str(tmp_path / "no-terminal")
    done = r.cmd("sh", str(script))
    assert done.returncode == 0, done.stderr
    assert "adf-router check" in done.stdout and (r.bin / "adf-router").exists()


def test_check_runs_the_chosen_service_and_shows_the_report(installer, tmp_path):
    r = Router(tmp_path, "sh")
    assert r.sh(str(installer)).returncode == 0
    done = r.cmd("adf-router", "check", "youtube", "--minutes", "1", *SIMULATE, timeout=60)
    assert done.returncode == 0, done.stderr
    assert "отчёт о прогоне" in done.stdout and "Nothing was changed in Tachyon" in done.stdout


def test_check_menu_picks_services_and_depth(installer, tmp_path):
    r = Router(tmp_path, "sh")
    assert r.sh(str(installer)).returncode == 0
    listed = [line.split()[1] for line in r.cmd("adf", "targets").stdout.splitlines()]
    services = list(dict.fromkeys(s for s in listed if s != "control"))
    answers = tmp_path / "answers"
    answers.write_text("1,3\n2\n")
    r.env["ADF_TTY"] = str(answers)
    done = r.cmd("adf-router", "check", *SIMULATE, timeout=60)
    assert done.returncode == 0, done.stderr
    assert f"{services[0]},{services[2]}, up to 20 min" in done.stdout


@pytest.mark.parametrize("answer,error", [("99\n", "no service number 99"), ("x\n", "not a number"),
                                          ("\n", "no service chosen")])
def test_check_rejects_bad_choice(installer, tmp_path, answer, error):
    r = Router(tmp_path, "sh")
    assert r.sh(str(installer)).returncode == 0
    answers = tmp_path / "answers"
    answers.write_text(answer)
    r.env["ADF_TTY"] = str(answers)
    done = r.cmd("adf-router", "check")
    assert done.returncode != 0 and error in done.stderr


def test_check_without_terminal_explains_itself(installer, tmp_path):
    r = Router(tmp_path, "sh")
    assert r.sh(str(installer)).returncode == 0
    r.env["ADF_TTY"] = str(tmp_path / "no-terminal")
    done = r.cmd("adf-router", "check")
    assert done.returncode != 0 and "no terminal" in done.stderr


def test_damaged_installer_is_refused(installer, tmp_path):
    bad = tmp_path / "bad.sh"
    data = bytearray(installer.read_bytes())
    data[-40] ^= 0xFF
    bad.write_bytes(bytes(data))
    r = Router(tmp_path, "sh")
    done = r.sh(str(bad))
    assert done.returncode != 0 and "damaged" in done.stderr
    assert not r.prefix.exists()


def test_second_search_is_refused_and_stop_works(installer, tmp_path):
    r = Router(tmp_path, "sh")
    assert r.sh(str(installer)).returncode == 0
    (r.home / ".adf").mkdir(exist_ok=True)
    sleeper = subprocess.Popen(["sleep", "30"])
    try:
        (r.home / ".adf" / "run.pid").write_text(str(sleeper.pid))
        again = r.cmd("adf-router", "run")
        assert again.returncode != 0 and "already running" in again.stderr
        refused = r.sh(str(installer))
        assert refused.returncode != 0 and "stop it first" in refused.stderr
    finally:
        sleeper.kill()
        sleeper.wait()
    assert r.cmd("adf-router", "status").stdout.startswith("not running")
