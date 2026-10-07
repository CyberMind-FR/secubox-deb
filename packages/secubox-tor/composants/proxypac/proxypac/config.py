# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.config — lit proxypac.toml, résout le socks_endpoint."""
import subprocess

try:
    import tomllib
except ModuleNotFoundError:  # py<3.11
    import tomli as tomllib

DEFAULTS = {"role": "auto", "wpad_domain": "", "pac_url": "", "transparent": True}


def _detect_lan_ip():
    try:
        out = subprocess.run(["/usr/sbin/tor-lan-ip"], capture_output=True, text=True, timeout=5)
        ip = out.stdout.strip()
        return ip or "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def load(path="/etc/secubox/proxypac/proxypac.toml"):
    data = dict(DEFAULTS)
    try:
        with open(path, "rb") as f:
            data.update(tomllib.load(f))
    except (OSError, tomllib.TOMLDecodeError):
        pass
    ep = data.get("socks_endpoint")
    if not ep:
        ep = f"{_detect_lan_ip()}:9050"
    data["socks_endpoint"] = ep
    data.setdefault("transparent", True)
    return data
