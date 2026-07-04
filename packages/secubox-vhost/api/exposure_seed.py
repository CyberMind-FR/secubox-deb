# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: vhost.exposure_seed — secure-by-default lan snippet on vhost create.

Mirrors secubox-exposure's `reach.reach_snippet("lan", False)` block (the two
packages already duplicate the read logic by design). secubox-exposure is the
authoritative editor once a snippet exists — this module only seeds a lan
default so a freshly-created vhost is never left ungated, and never overwrites
an existing snippet.
"""
import os
from pathlib import Path

_LAN_BLOCK = (
    "allow 127.0.0.1;\n"
    "allow 10.0.0.0/8;\n"
    "allow 172.16.0.0/12;\n"
    "allow 192.168.0.0/16;\n"
    "deny all;\n"
)

_DEFAULT_SNIPPET_DIR = Path("/etc/nginx/snippets/exposure")


def ensure_snippet(vhost: str, snippet_dir=None) -> bool:
    """Seed the per-vhost lan snippet if absent. Returns True if the file exists
    afterward (freshly seeded or already present), False on any OSError writing
    it. Never overwrites an existing snippet."""
    d = Path(snippet_dir) if snippet_dir is not None else _DEFAULT_SNIPPET_DIR
    dst = d / f"{vhost}.conf"
    if dst.exists():
        return True
    tmp = d / f"{vhost}.conf.tmp"
    try:
        d.mkdir(parents=True, exist_ok=True)
        tmp.write_text(_LAN_BLOCK)
        os.replace(tmp, dst)
    except OSError:
        return False
    return dst.exists()
