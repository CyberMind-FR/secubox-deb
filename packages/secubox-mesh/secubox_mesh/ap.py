# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — AP Passpoint (hostapd) : génération conf + état clients.
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Any

import jinja2

from .models import APClient, Config

log = logging.getLogger("secubox.mesh")

HOSTAPD_CLI = "/usr/sbin/hostapd_cli"
TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "conf"

_RE_STA = re.compile(r"^([0-9a-f]{2}(?::[0-9a-f]{2}){5})$", re.IGNORECASE | re.MULTILINE)


def _env() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATE_DIR),
        autoescape=False,
        keep_trailing_newline=True,
    )


def render_hostapd(cfg: Config) -> str:
    """Rend conf/hostapd.conf.j2. Pas d'écriture disque ici."""
    return _env().get_template("hostapd.conf.j2").render(
        radio=cfg.radio.model_dump(),
        ap=cfg.ap.model_dump(),
        reg=cfg.reg.model_dump(),
    )


def clients(iface: str) -> list[APClient]:
    """`hostapd_cli -i <iface> all_sta` → liste de APClient."""
    try:
        out = subprocess.run(
            [HOSTAPD_CLI, "-i", iface, "all_sta"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    # Parser bloc-par-bloc, séparé par lignes vides
    blocks = re.split(r"\n\s*\n", out)
    out_list: list[APClient] = []
    for blk in blocks:
        mac_m = _RE_STA.search(blk)
        if not mac_m:
            continue
        kv: dict[str, str] = {}
        for line in blk.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                kv[k.strip()] = v.strip()

        def _i(key: str) -> int | None:
            try:
                return int(kv.get(key, ""))
            except (TypeError, ValueError):
                return None

        passpoint = "hs20" in kv or kv.get("interworking", "0") == "1"
        out_list.append(APClient(
            mac=mac_m.group(1).lower(),
            rx_bytes=_i("rx_bytes"),
            tx_bytes=_i("tx_bytes"),
            signal_dbm=_i("signal"),
            connected_time_s=_i("connected_time"),
            passpoint=passpoint,
        ))
    return out_list


def write_conf(cfg: Config, out_path: Path = Path("/run/secubox/mesh/hostapd.conf")) -> Path:
    """Écrit la conf rendue. Réservée au bring-up — pas appelée depuis l'API par défaut."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_hostapd(cfg)
    out_path.write_text(content)
    out_path.chmod(0o640)
    return out_path
