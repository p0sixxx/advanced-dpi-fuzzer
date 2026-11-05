"""State of a running check, shared between the job and whoever is watching it.

The job writes a snapshot after every batch. Any console, including one opened after a remote session
dropped, reads the same file, so closing a window neither stops the check nor loses its progress.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

RUNNING = "running"
FINISHED = "finished"
STOPPED = "stopped"
FAILED = "failed"
STILL_ACTIVE = 259
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    # os.kill(pid, 0) would terminate the process on Windows
    import ctypes

    kernel = ctypes.windll.kernel32
    handle = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    code = ctypes.c_ulong()
    try:
        return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == STILL_ACTIVE
    finally:
        kernel.CloseHandle(handle)


def write(path: Path, snapshot: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(dict(snapshot, updated=time.time()), f, ensure_ascii=False, default=str)
    for attempt in range(20):
        try:
            os.replace(name, path)
            return
        except PermissionError:     # on Windows a reader holding the file blocks the replace for a moment
            time.sleep(0.05)
    os.unlink(name)


def read(path: Path) -> Optional[Dict[str, Any]]:
    for attempt in range(5):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (PermissionError, ValueError):
            time.sleep(0.05)
    return None


def active(snapshot: Optional[Mapping[str, Any]]) -> bool:
    return bool(snapshot) and snapshot.get("status") == RUNNING and process_alive(int(snapshot.get("pid", 0)))


def settled(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """A snapshot left as running by a job that died is reported as failed."""
    if snapshot.get("status") == RUNNING and not process_alive(int(snapshot.get("pid", 0))):
        return dict(snapshot, status=FAILED, error="процесс проверки завершился неожиданно, см. журнал")
    return snapshot
