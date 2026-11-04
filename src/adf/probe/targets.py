"""Default target catalogue (user-editable via TOML, see examples/targets.toml).

Large pages and sized downloads are used on purpose: TSPU cut-offs after
16–20 KB are only visible on responses larger than that, so most targets
require ``min_bytes`` of 32 KB or more.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .model import Target, target_from_dict

DEFAULT_TARGETS: List[Target] = [
    Target("google-www", "https://www.google.com/", "google", "Google Search", min_bytes=16384, body_regex="google"),
    Target("youtube-www", "https://www.youtube.com/", "youtube", "YouTube web", min_bytes=65536, body_regex="ytcfg"),
    Target("youtube-img", "https://i.ytimg.com/generate_204", "youtube", "YouTube static", required=False),
    # rr1.googlevideo.com (Tachyon's TARGET_SUITES.youtube_suite) is NXDOMAIN. The redirector shows
    # whether TLS with a googlevideo SNI passes, not video throughput: real nodes are per-session.
    Target("youtube-video", "https://redirector.googlevideo.com/", "youtube", "googlevideo redirector",
           ok_codes=(200, 204, 301, 302, 400, 403, 404, 405), required=False),
    Target("ytmusic-www", "https://music.youtube.com/", "youtube_music", "YouTube Music", min_bytes=32768),
    Target("discord-www", "https://discord.com/", "discord", "Discord web", min_bytes=32768, body_regex="discord"),
    Target("discord-gw", "https://gateway.discord.gg/", "discord", "Discord gateway", ok_codes=(200, 400, 404, 426)),
    Target("telegram-web", "https://web.telegram.org/", "telegram", "Telegram Web", body_regex="[Tt]elegram"),
    Target("telegram-api", "https://api.telegram.org/", "telegram", "Telegram Bot API", required=False),
    Target("instagram-www", "https://www.instagram.com/", "instagram", "Instagram web", min_bytes=16384,
           body_regex="[Ii]nstagram"),
    Target("instagram-cdn", "https://static.cdninstagram.com/", "instagram", "Instagram static CDN", required=False),
    Target("github-www", "https://github.com/", "github", "GitHub", min_bytes=65536, body_regex="github"),
    Target("cloudflare-100k", "https://speed.cloudflare.com/__down?bytes=102400", "cloudflare",
           "Cloudflare sized download", min_bytes=102400),
    Target("cloudflare-www", "https://www.cloudflare.com/", "cloudflare", "Cloudflare web", min_bytes=32768,
           required=False),
]

# Control resources: expected to be reachable *without* any bypass. A failing
# control means the network itself is down and the batch is discarded.
DEFAULT_CONTROLS: List[Target] = [
    Target("control-ya", "https://ya.ru/", "control", "Yandex", required=True),
    Target("control-vk", "https://vk.com/", "control", "VK", required=True),
]


def load_targets(path: Path) -> Dict[str, List[Target]]:
    """Load ``[[target]]`` and ``[[control]]`` tables from a TOML file."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    out = {
        "targets": [target_from_dict(t) for t in data.get("target", [])],
        "controls": [target_from_dict(t) for t in data.get("control", [])],
    }
    ids = [t.id for t in out["targets"] + out["controls"]]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise ValueError(f"duplicate target ids: {', '.join(sorted(dup))}")
    return out


def select(targets: Iterable[Target], categories: Optional[Sequence[str]] = None,
           ids: Optional[Sequence[str]] = None) -> List[Target]:
    res = []
    for t in targets:
        if categories and t.category not in categories:
            continue
        if ids and t.id not in ids:
            continue
        res.append(t)
    return res
