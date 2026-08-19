# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ytsas :: extraction de l'identifiant vidéo YouTube.

Le join du tuyau souverain se fait par CET identifiant, jamais par le titre :
deux URL de la même vidéo (watch, youtu.be, shorts) doivent rendre le même id.
"""
import re
from urllib.parse import urlparse, parse_qs

_ID = re.compile(r"^[A-Za-z0-9_-]{11}$")


def video_id(url: str) -> str | None:
    try:
        u = urlparse(url)
    except (ValueError, AttributeError):
        return None
    host = (u.hostname or "").lower().removeprefix("www.")
    if host in ("youtube.com", "m.youtube.com"):
        if u.path == "/watch":
            v = parse_qs(u.query).get("v", [""])[0]
            return v if _ID.match(v) else None
        for pfx in ("/shorts/", "/embed/", "/v/"):
            if u.path.startswith(pfx):
                v = u.path[len(pfx):].split("/")[0]
                return v if _ID.match(v) else None
        return None
    if host == "youtu.be":
        v = u.path.lstrip("/").split("/")[0]
        return v if _ID.match(v) else None
    return None
