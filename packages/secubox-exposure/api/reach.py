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


def write_snippet(vhost: str, reach: str, mesh: bool) -> None:
    """Atomically write the vhost's exposure snippet (temp + os.replace)."""
    content = reach_snippet(reach, mesh)
    SNIPPET_DIR.mkdir(parents=True, exist_ok=True)
    dst = SNIPPET_DIR / f"{vhost}.conf"
    tmp = SNIPPET_DIR / f"{vhost}.conf.tmp"
    tmp.write_text(content)
    os.replace(tmp, dst)


def read_snippet_reach(vhost: str) -> dict:
    """Derive {reach, mesh} from the on-disk snippet. Missing/empty → wan."""
    p = SNIPPET_DIR / f"{vhost}.conf"
    try:
        content = p.read_text()
    except OSError:
        return {"reach": "wan", "mesh": False}
    mesh = MESH_CIDR in content
    if content.strip() == "":
        reach = "wan"
    elif any(c in content for c in LAN_CIDRS):
        reach = "lan"
    else:
        reach = "localhost"
    return {"reach": reach, "mesh": mesh}


def load_record(vhost: str, is_public_now: bool) -> dict:
    """Current exposure record for a vhost.

    If a snippet exists, derive from it. Otherwise the DEFAULT is 'lan' — except
    a currently-public vhost defaults to 'wan' so first adoption never silently
    re-confines a live public service. tor is False here (the API overlays state).
    """
    p = SNIPPET_DIR / f"{vhost}.conf"
    if p.exists():
        rr = read_snippet_reach(vhost)
        return {"vhost": vhost, "reach": rr["reach"], "mesh": rr["mesh"], "tor": False}
    return {"vhost": vhost, "reach": "wan" if is_public_now else "lan",
            "mesh": False, "tor": False}
