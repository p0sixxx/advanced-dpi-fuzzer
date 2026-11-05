"""Console output that works in a plain cmd or PowerShell window.

Windows starts them in an OEM code page without ANSI sequences, so Russian text and live updates both
need setting up. Where that is impossible, or the output is redirected, plain lines are written.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import unicodedata
from typing import List, Optional, Sequence

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
COLORS = {"red": "31", "green": "32", "yellow": "33", "cyan": "36", "dim": "2", "bold": "1"}
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
STD_OUTPUT_HANDLE = -11
CP_UTF8 = 65001


def _enable_windows_console() -> bool:
    import ctypes

    kernel = ctypes.windll.kernel32
    kernel.SetConsoleOutputCP(CP_UTF8)
    kernel.SetConsoleCP(CP_UTF8)
    handle = kernel.GetStdHandle(STD_OUTPUT_HANDLE)
    mode = ctypes.c_uint32()
    if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
        return False
    return bool(kernel.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))


class Terminal:
    def __init__(self, ansi: bool = False):
        self.ansi = ansi

    def style(self, text: str, *names: str) -> str:
        if not self.ansi or not names:
            return text
        return f"\x1b[{';'.join(COLORS[n] for n in names)}m{text}\x1b[0m"


def prepare() -> Terminal:
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    ansi = sys.stdout.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"
    if ansi and os.name == "nt":
        try:
            ansi = _enable_windows_console()
        except (OSError, AttributeError):
            ansi = False
    return Terminal(ansi)


def width() -> int:
    return min(shutil.get_terminal_size((100, 30)).columns, 140)


def visible_width(text: str) -> int:
    plain = ANSI.sub("", text)
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in plain)


def fit(text: str, limit: int) -> str:
    """Shortens a line without cutting an escape sequence in half."""
    if visible_width(text) <= limit:
        return text
    out = []
    used = 0
    pos = 0
    while pos < len(text) and used < limit - 1:
        escape = ANSI.match(text, pos)
        if escape:
            out.append(escape.group())
            pos = escape.end()
            continue
        out.append(text[pos])
        used += 1
        pos += 1
    return "".join(out) + "…" + ("\x1b[0m" if "\x1b[" in text else "")


def bar(fraction: float, size: int = 24) -> str:
    done = max(0, min(size, round(fraction * size)))
    return "█" * done + "░" * (size - done)


def table(headers: Sequence[str], rows: Sequence[Sequence[str]], right: Sequence[int] = ()) -> List[str]:
    sizes = [visible_width(h) for h in headers]
    for row in rows:
        sizes = [max(s, visible_width(c)) for s, c in zip(sizes, row)]

    def line(cells: Sequence[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            pad = " " * (sizes[i] - visible_width(cell))
            parts.append(pad + cell if i in right else cell + pad)
        return "  ".join(parts).rstrip()

    return [line(headers), line(["─" * s for s in sizes]), *map(line, rows)]


def clock(seconds: Optional[float]) -> str:
    if seconds is None or seconds < 0:
        return "—"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02}:{secs:02}" if hours else f"{minutes:02}:{secs:02}"


class Screen:
    """Redraws a block of lines in place. Without ANSI, prints the block only when ``key`` changes."""

    def __init__(self, term: Terminal):
        self.term = term
        self.height = 0
        self.last = ""

    def draw(self, lines: Sequence[str], key: str = "") -> None:
        limit = width() - 1
        lines = [fit(line, limit) for line in lines]
        if not self.term.ansi:
            if key != self.last:
                self.last = key
                print("\n".join(ANSI.sub("", line) for line in lines), flush=True)
            return
        out = [f"\x1b[{self.height}A"] if self.height else []
        out += [f"\r\x1b[2K{line}\n" for line in lines]
        out += ["\x1b[2K\n" * (self.height - len(lines)), f"\x1b[{self.height - len(lines)}A"] \
            if self.height > len(lines) else []
        sys.stdout.write("".join(out))
        sys.stdout.flush()
        self.height = len(lines)

    def release(self) -> None:
        """The block stays on screen and the next output goes below it."""
        self.height = 0
        self.last = ""
