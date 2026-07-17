# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: billets — emoji hashtag extraction

Authors write `#secu #waf` inline in the billet body; we lift those into real tag
rows and render them as emoji chips for quick-view filtering. Parsing the body
(rather than a separate tag picker) means tagging costs the author nothing and
applies retroactively to billets written before tags existed.
"""
from __future__ import annotations

import re
import unicodedata

# Curated tag -> emoji. Keys are already-normalised slugs. Unknown tags are NOT
# rejected — they get DEFAULT_EMOJI — so authors are never blocked by the map;
# entries here just make the common categories legible at a glance.
TAG_EMOJI: dict[str, str] = {
    # security
    "secu": "🛡️", "security": "🛡️", "waf": "🧱", "firewall": "🧱",
    "alerte": "🚨", "alert": "🚨", "incident": "🚨", "cve": "☢️",
    "ids": "👁️", "crowdsec": "🦅", "ban": "⛔", "attaque": "⚔️",
    # network
    "reseau": "🌐", "network": "🌐", "dns": "📡", "vpn": "🔐",
    "wireguard": "🔐", "tor": "🧅", "mesh": "🕸️", "p2p": "🕸️",
    "dpi": "🔍", "proxy": "🔀",
    # box / ops
    "box": "📦", "secubox": "📦", "debian": "🐧", "kernel": "🐧",
    "hardware": "🔌", "led": "💡", "boot": "🥾", "backup": "💾",
    "update": "⬆️", "deploy": "🚀", "build": "🏗️",
    # dev
    "bug": "🐛", "fix": "🔧", "feature": "✨", "refactor": "♻️",
    "test": "🧪", "doc": "📚", "docs": "📚", "api": "🔌",
    # editorial
    "news": "📰", "note": "📝", "billet": "📝", "communique": "📢",
    "annonce": "📢", "idee": "💡", "question": "❓", "wip": "🚧",
    # misc
    "perf": "⚡", "crypto": "🔑", "zkp": "🧮", "ia": "🤖", "ai": "🤖",
    "mail": "📧", "media": "🎬", "photo": "📸", "audio": "🎧",
    # media / broadcast — the tags this box's billets actually carry
    "podcast": "🎙️", "rtbf": "📻", "lapremierertbf": "📻", "radio": "📻",
    "tv": "📺", "video": "📹", "interview": "🎤", "musique": "🎵",
    # editorial topics seen in the archive. Descriptive of the SUBJECT only —
    # a tag emoji labels what a billet is about, it does not endorse it.
    "complot": "🕵️", "ovnis": "🛸", "chemtrails": "✈️", "matrix": "🕶️",
    "simulation": "🎮", "atlantis": "🌊", "bermuda": "🌀", "titanic": "🚢",
    "climate": "🌡️", "vaccine": "💉", "aids": "🧬", "sida": "🧬",
    "windsor": "👑", "marilynmonroe": "💋", "jfk": "🎯", "attentat": "💥",
    "worldtradecenter": "🏙️", "spirituality": "✨", "histoire": "📜",
    "science": "🔬", "sante": "🏥", "politique": "🏛️",
}

DEFAULT_EMOJI = "🏷️"

# `\w` is unicode-aware in Python 3, so #réseau matches; we fold the accents when
# normalising so #réseau and #reseau collapse to one tag. Bounded length keeps a
# wall of text from becoming a wall of chips.
_HASHTAG_RE = re.compile(r"(?<!\w)#(\w{2,32})\b", re.UNICODE)
MAX_TAGS = 8


def normalise(raw: str) -> str:
    """`#Réseau` -> `reseau`. Accent-folded + lowercased so visually-equal tags
    are actually equal. Returns '' if nothing usable survives."""
    s = unicodedata.normalize("NFKD", raw)
    s = "".join(c for c in s if not unicodedata.combining(c))
    s = s.lower().strip("_-")
    return s if re.fullmatch(r"[0-9a-z_-]{2,32}", s) else ""


def emoji_for(slug: str) -> str:
    return TAG_EMOJI.get(slug, DEFAULT_EMOJI)


def extract(body: str) -> list[tuple[str, str]]:
    """Body -> ordered, de-duplicated [(slug, emoji)], capped at MAX_TAGS.

    Order follows first appearance so the chip row reads like the author wrote it.
    A tag that normalises to nothing (e.g. `#__`) is dropped rather than stored.
    """
    seen: dict[str, str] = {}
    for m in _HASHTAG_RE.finditer(body or ""):
        slug = normalise(m.group(1))
        if not slug or slug in seen:
            continue
        seen[slug] = emoji_for(slug)
        if len(seen) >= MAX_TAGS:
            break
    return list(seen.items())
