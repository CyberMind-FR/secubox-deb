# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: exposure.reach — per-vhost nginx reach snippet (pure + atomic)."""
import os
from pathlib import Path

REACH_LEVELS = ("localhost", "lan", "wan")
LAN_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
MESH_CIDR = "10.10.0.0/24"
SNIPPET_DIR = Path(os.environ.get("EXPOSURE_SNIPPET_DIR", "/etc/nginx/snippets/exposure"))


def reach_snippet(reach: str, mesh: bool) -> str:
    """Build the nginx allow/deny block for a reach level (+ mesh CIDR).

    Matches $remote_addr — only effective with the global real_ip rewrite.
    wan → "" (public). localhost/lan → allow-list + terminal `deny all;`.
    """
    if reach not in REACH_LEVELS:
        raise ValueError(f"invalid reach: {reach!r}")
    if reach == "wan":
        return ""  # public; mesh adds nothing to an already-open gate
    lines = ["allow 127.0.0.1;"]
    if reach == "lan":
        lines += [f"allow {c};" for c in LAN_CIDRS]
    if mesh:
        lines.append(f"allow {MESH_CIDR};")
    lines.append("deny all;")
    return "\n".join(lines) + "\n"


def snippet_path(vhost: str) -> Path:
    return SNIPPET_DIR / f"{vhost}.conf"
