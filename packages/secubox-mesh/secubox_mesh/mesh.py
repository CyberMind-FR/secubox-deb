# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — 802.11s : énumération des pairs, rotation SAE.
HWMP est piloté côté mac80211 ; ici on lit l'état + on déclenche la rotation
de clé via wpa_cli (geste opérationnel, pas de PFS protocolaire ici).
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

from .models import Peer, Config

log = logging.getLogger("secubox.mesh")

IW = "/usr/sbin/iw"
WPA_CLI = "/usr/sbin/wpa_cli"

_RE_STATION = re.compile(r"^Station\s+([0-9a-f:]{17})", re.IGNORECASE | re.MULTILINE)


def list_peers(iface: str) -> list[Peer]:
    """`iw dev <iface> station dump` → liste de Peer (best-effort parsing)."""
    try:
        out = subprocess.run(
            [IW, "dev", iface, "station", "dump"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    peers: list[Peer] = []
    blocks = re.split(r"(?m)^(?=Station\s)", out)
    for blk in blocks:
        m = _RE_STATION.search(blk)
        if not m:
            continue
        kv: dict[str, str] = {}
        for line in blk.splitlines()[1:]:
            if ":" in line:
                k, _, v = line.strip().partition(":")
                kv[k.strip()] = v.strip()

        def _i(key: str) -> int | None:
            v = kv.get(key)
            if not v:
                return None
            tok = v.split()[0].replace(",", "")
            try:
                return int(tok)
            except ValueError:
                return None

        def _f(key: str) -> float | None:
            v = kv.get(key)
            if not v:
                return None
            tok = v.split()[0]
            try:
                return float(tok)
            except ValueError:
                return None

        peers.append(Peer(
            mac=m.group(1).lower(),
            inactive_ms=_i("inactive time"),
            rx_bytes=_i("rx bytes"),
            tx_bytes=_i("tx bytes"),
            signal_dbm=_i("signal"),
            tx_bitrate_mbps=_f("tx bitrate"),
            mesh_plink=kv.get("mesh plink"),
        ))
    return peers


def rotate_key(cfg: Config) -> dict[str, Any]:
    """
    Rotation SAE déclenchée via wpa_cli.
    NB : la maturité SAE-mesh dépend du chipset (cf. log WARN au démarrage).
    Pas de PFS protocolaire ici — on demande à wpa_supplicant de re-négocier.
    """
    iface = cfg.radio.iface
    log.warning("MESH SAE rotate requested (iface=%s, driver=%s)",
                iface, cfg.radio.driver)
    try:
        res = subprocess.run(
            [WPA_CLI, "-i", iface, "reauthenticate"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except FileNotFoundError:
        return {"status": "error", "reason": "wpa_cli not installed"}
    return {
        "status": "ok" if res.returncode == 0 else "error",
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
    }
