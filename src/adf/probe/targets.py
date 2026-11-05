"""Default target catalogue (user-editable via TOML, see examples/targets.toml).

Large pages and sized downloads are used on purpose: TSPU cut-offs after
16–20 KB are only visible on responses larger than that, so most targets
require ``min_bytes`` of 32 KB or more.
"""

from __future__ import annotations

import tomllib
from dataclasses import replace
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .model import DEFAULT_OK_CODES, LARGE_HELLO, Target, target_from_dict

# KiB/s over a whole large response. Far below normal lines (the slowest healthy response measured
# on a real router was 490), while throttled services crawl at a few dozen.
THROTTLED_KBPS = 128
# API and CDN roots answer 400: the host is judged by the TLS handshake, not by the page.
ROOT_400 = DEFAULT_OK_CODES + (400,)

DEFAULT_TARGETS: List[Target] = [
    Target("google-www", "https://www.google.com/", "google", "Google Search", min_bytes=16384, body_regex="google"),
    Target("google-accounts", "https://accounts.google.com/", "google", "Google sign-in", required=False, max_ips=1),
    Target("google-play", "https://play.googleapis.com/", "google", "Google Play API", required=False, max_ips=1),
    Target("google-fcm", "https://fcm.googleapis.com/", "google", "Firebase push", required=False, max_ips=1),
    Target("youtube-www", "https://www.youtube.com/", "youtube", "YouTube web", min_bytes=65536, body_regex="ytcfg",
           min_speed_kbps=THROTTLED_KBPS),
    Target("youtube-img", "https://i.ytimg.com/generate_204", "youtube", "YouTube static", required=False),
    # rr1.googlevideo.com (Tachyon's TARGET_SUITES.youtube_suite) is NXDOMAIN. The redirector shows
    # whether TLS with a googlevideo SNI passes, not video throughput: real nodes are per-session.
    # Required: a strategy that opens the page but not this host leaves videos spinning.
    Target("youtube-video", "https://redirector.googlevideo.com/", "youtube", "googlevideo redirector",
           ok_codes=(200, 204, 301, 302, 400, 403, 404, 405)),
    # The Android and iOS apps use this host for everything except the video itself.
    Target("youtube-api", "https://youtubei.googleapis.com/", "youtube", "YouTube mobile apps API", max_ips=1),
    Target("youtube-attest", "https://jnn-pa.googleapis.com/", "youtube", "YouTube player attestation",
           required=False, max_ips=1),
    # Depends on the host: yt4.ggpht.com passed while yt3.ggpht.com failed with the same strategy.
    Target("youtube-avatars", "https://yt3.ggpht.com/", "youtube", "YouTube avatars", required=False,
           ok_codes=ROOT_400, max_ips=1),
    Target("ytmusic-www", "https://music.youtube.com/", "youtube_music", "YouTube Music", min_bytes=32768),
    Target("discord-www", "https://discord.com/", "discord", "Discord web", min_bytes=32768, body_regex="discord",
           min_speed_kbps=THROTTLED_KBPS),
    Target("discord-gw", "https://gateway.discord.gg/", "discord", "Discord gateway", ok_codes=(200, 400, 404, 426)),
    Target("discord-cdn", "https://cdn.discordapp.com/", "discord", "Discord attachments and avatars", max_ips=1),
    Target("discord-media", "https://media.discordapp.net/", "discord", "Discord media proxy", required=False, max_ips=1),
    Target("discord-updates", "https://updates.discord.com/", "discord", "Discord desktop updates", required=False,
           max_ips=1),
    Target("telegram-web", "https://web.telegram.org/", "telegram", "Telegram Web", body_regex="[Tt]elegram"),
    Target("telegram-api", "https://api.telegram.org/", "telegram", "Telegram Bot API", required=False),
    Target("telegram-links", "https://t.me/", "telegram", "Telegram links", required=False, max_ips=1),
    Target("instagram-www", "https://www.instagram.com/", "instagram", "Instagram web", min_bytes=16384,
           body_regex="[Ii]nstagram"),
    Target("instagram-api", "https://i.instagram.com/", "instagram", "Instagram mobile apps API", max_ips=1),
    Target("instagram-cdn", "https://static.cdninstagram.com/", "instagram", "Instagram static CDN", required=False),
    Target("instagram-media", "https://scontent.cdninstagram.com/", "instagram", "Instagram photos and video",
           required=False, max_ips=1),
    Target("instagram-chat", "https://edge-chat.instagram.com/", "instagram", "Instagram messages", required=False,
           max_ips=1),
    Target("github-www", "https://github.com/", "github", "GitHub", min_bytes=65536, body_regex="github"),
    Target("github-api", "https://api.github.com/", "github", "GitHub API", required=False, max_ips=1),
    Target("github-raw", "https://raw.githubusercontent.com/", "github", "GitHub raw files", required=False, max_ips=1),
    Target("cloudflare-100k", "https://speed.cloudflare.com/__down?bytes=102400", "cloudflare",
           "Cloudflare sized download", min_bytes=102400, min_speed_kbps=THROTTLED_KBPS),
    Target("cloudflare-www", "https://www.cloudflare.com/", "cloudflare", "Cloudflare web", min_bytes=32768,
           required=False),
]

# Control resources: expected to be reachable *without* any bypass. A failing
# control means the network itself is down and the batch is discarded.
DEFAULT_CONTROLS: List[Target] = [
    Target("control-ya", "https://ya.ru/", "control", "Yandex", required=True),
    Target("control-vk", "https://vk.com/", "control", "VK", required=True),
]


def with_large_hello(targets: Iterable[Target]) -> List[Target]:
    """Add a browser-size ClientHello probe for each required target: curl's hello says nothing about Chrome."""
    res = list(targets)
    for t in list(res):
        if t.required and t.kind == "https":
            res.append(replace(t, id=f"{t.id}-large", name=f"{t.name or t.id}, large hello", kind=LARGE_HELLO,
                               min_bytes=0, range=None, body_regex=None, min_speed_kbps=0.0))
    return res


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
