# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.exposure_read — derive a vhost's exposure from its snippet."""
from pathlib import Path

_SNIPPET_DIR = Path("/etc/nginx/snippets/exposure")
_LAN = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
_MESH = "10.10.0.0/24"


def read_exposure(vhost: str, snippet_dir=None) -> dict:
    d = Path(snippet_dir) if snippet_dir is not None else _SNIPPET_DIR
    try:
        content = (d / f"{vhost}.conf").read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = _MESH in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in _LAN):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}
