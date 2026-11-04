#!/usr/bin/env python3
"""Build dist/adf-router-<version>.sh, the single-file installer for the router.

Standard library only, works on Linux and Windows. Text files are normalised to LF: a CRLF
checkout must not reach the router. The output is reproducible for a given source tree.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import sys
import tarfile
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "packaging" / "installer-header.sh"


def version() -> str:
    text = (ROOT / "src" / "adf" / "__init__.py").read_text(encoding="utf-8")
    found = re.search(r'__version__ = "([^"]+)"', text)
    if found is None:
        raise SystemExit("no __version__ in src/adf/__init__.py")
    return found.group(1)


def lf(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def collect(ver: str) -> Dict[str, bytes]:
    files = {"VERSION": ver.encode() + b"\n",
             "agent/adf-agent.sh": lf(ROOT / "agent" / "adf-agent.sh"),
             "bin/adf-router": lf(ROOT / "packaging" / "adf-router.sh")}
    src = ROOT / "src"
    for path in sorted((src / "adf").rglob("*")):
        if path.is_file() and path.suffix in (".py", ".json"):
            files["lib/" + path.relative_to(src).as_posix()] = lf(path)
    return files


def payload(files: Dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name in sorted(files):
            info = tarfile.TarInfo(name)
            info.size = len(files[name])
            info.mode = 0o755 if name.startswith("bin/") or name.endswith(".sh") else 0o644
            tar.addfile(info, io.BytesIO(files[name]))
    return gzip.compress(raw.getvalue(), compresslevel=9, mtime=0)


def build(out_dir: Path) -> Path:
    ver = version()
    blob = payload(collect(ver))
    header = lf(HEADER).decode("utf-8")
    line = header.count("\n") + 1
    header = (header.replace("@VERSION@", ver).replace("@PAYLOAD_LINE@", str(line))
              .replace("@PAYLOAD_SHA256@", hashlib.sha256(blob).hexdigest()))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"adf-router-{ver}.sh"
    out.write_bytes(header.encode("utf-8") + blob)
    return out


if __name__ == "__main__":
    target = build(Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist")
    print(f"{target} ({target.stat().st_size // 1024} KB)")
