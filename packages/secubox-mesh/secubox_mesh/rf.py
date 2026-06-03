# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: MESH — wrappers iw (état radio + régulatoire).
Aucune logique métier ici : juste parser proprement la sortie de `iw`.
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

from .models import RFState, Config

log = logging.getLogger("secubox.mesh")

IW = "/usr/sbin/iw"

_RE_TYPE = re.compile(r"^\s*type\s+(\S+)", re.MULTILINE)
_RE_CHANNEL = re.compile(r"channel\s+(\d+)\s*\((\d+)\s*MHz\)")
_RE_WIDTH = re.compile(r"width:\s+(\d+)\s*MHz")
_RE_TXPOWER = re.compile(r"txpower\s+([\d.]+)\s*dBm")
_RE_COUNTRY = re.compile(r"country\s+([A-Z0-9]{2}):\s*(\S+)")


def _run(*argv: str, timeout: float = 5.0) -> str:
    """Run `iw ...` and return stdout. Raises CalledProcessError on non-zero."""
    res = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if res.returncode != 0:
        log.warning("iw call failed argv=%s rc=%d stderr=%s",
                    argv, res.returncode, res.stderr.strip())
        raise subprocess.CalledProcessError(res.returncode, argv, res.stdout, res.stderr)
    return res.stdout


def state(iface: str) -> RFState:
    """État radio courant pour <iface>. Sans I/O bloquante non-iw."""
    # iw dev <iface> info
    info = ""
    try:
        info = _run(IW, "dev", iface, "info")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    typ_m = _RE_TYPE.search(info)
    ch_m = _RE_CHANNEL.search(info)
    wd_m = _RE_WIDTH.search(info)
    tx_m = _RE_TXPOWER.search(info)

    # iw reg get
    reg = ""
    try:
        reg = _run(IW, "reg", "get")
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    country = "00"
    dfs = None
    rg = _RE_COUNTRY.search(reg)
    if rg:
        country, dfs = rg.group(1), rg.group(2)

    return RFState(
        iface=iface,
        type=typ_m.group(1) if typ_m else None,
        channel=int(ch_m.group(1)) if ch_m else None,
        freq_mhz=int(ch_m.group(2)) if ch_m else None,
        width_mhz=int(wd_m.group(1)) if wd_m else None,
        txpower_dbm=float(tx_m.group(1)) if tx_m else None,
        reg_country=country,
        reg_dfs_state=dfs,
    )


def set_domain(country: str, cfg: Config) -> dict[str, Any]:
    """
    Bascule le domaine régulatoire. Journalise (jamais silencieux).
    Garde-fou : code TOML reste autoritatif au reboot ; cette API est un override
    runtime, à utiliser de manière exceptionnelle.
    """
    cc = country.upper()
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise ValueError(f"country={country} invalide (attendu ISO-3166 alpha-2)")
    log.warning("REG override runtime: %s → %s (toml=%s)", cfg.reg.country, cc, cfg.reg.country)
    _run(IW, "reg", "set", cc)
    return {"applied": cc, "toml_default": cfg.reg.country}


def list_supported_modes(phy: str) -> list[str]:
    """Renvoie les modes d'interface supportés par le PHY (mesh point, AP, …)."""
    try:
        out = _run(IW, "phy", phy, "info")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    modes: list[str] = []
    in_section = False
    for ln in out.splitlines():
        if "Supported interface modes" in ln:
            in_section = True
            continue
        if in_section:
            s = ln.strip()
            if s.startswith("*"):
                modes.append(s.lstrip("* ").strip())
            elif s and not s.startswith("*") and not s.startswith("#"):
                break
    return modes
