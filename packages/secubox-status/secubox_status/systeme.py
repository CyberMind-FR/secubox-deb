# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Ressources du système, sans privilège ni sous-processus : /proc, /sys, statvfs.

Chaque mesure est un nombre fini ou None (sonde absente : une machine sans capteur thermique n'est pas en panne).
Même code sur arm64 et amd64.
"""
from __future__ import annotations

import math
import os
import platform
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

PROC = Path("/proc")
THERMAL = Path("/sys/class/thermal")


def _fini(v: Optional[float], chiffres: int = 1) -> Optional[float]:
    if v is None or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    return round(float(v), chiffres)


def _cpu_brut(proc: Path) -> Optional[Tuple[int, int]]:
    try:
        ligne = (proc / "stat").read_text(encoding="ascii").splitlines()[0].split()
    except (OSError, IndexError, UnicodeDecodeError):
        return None
    if ligne[0] != "cpu":
        return None
    try:
        v = [int(x) for x in ligne[1:]]
    except ValueError:
        return None
    repos = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), repos


def cpu_percent(proc: Path = PROC, intervalle: float = 0.25) -> Optional[float]:
    a = _cpu_brut(proc)
    time.sleep(intervalle)
    b = _cpu_brut(proc)
    if not a or not b or b[0] <= a[0]:
        return None
    total, repos = b[0] - a[0], b[1] - a[1]
    return _fini(100.0 * (total - repos) / total)


def memoire_percent(proc: Path = PROC) -> Optional[float]:
    vals: Dict[str, int] = {}
    try:
        for ligne in (proc / "meminfo").read_text(encoding="ascii").splitlines():
            k, _, reste = ligne.partition(":")
            parts = reste.split()
            if parts and parts[0].isdigit():
                vals[k] = int(parts[0])
    except (OSError, UnicodeDecodeError):
        return None
    total, dispo = vals.get("MemTotal"), vals.get("MemAvailable")
    if not total or dispo is None:
        return None
    return _fini(100.0 * (total - dispo) / total)


def disque_percent(point: str = "/") -> Optional[float]:
    try:
        s = os.statvfs(point)
    except OSError:
        return None
    total = s.f_blocks * s.f_frsize
    libre = s.f_bavail * s.f_frsize
    utilise = (s.f_blocks - s.f_bfree) * s.f_frsize
    if total <= 0 or utilise + libre <= 0:
        return None
    return _fini(100.0 * utilise / (utilise + libre))


def charge(proc: Path = PROC) -> Optional[list]:
    try:
        parts = (proc / "loadavg").read_text(encoding="ascii").split()[:3]
        return [_fini(float(x), 2) for x in parts]
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def uptime_s(proc: Path = PROC) -> Optional[int]:
    try:
        v = float((proc / "uptime").read_text(encoding="ascii").split()[0])
    except (OSError, ValueError, IndexError, UnicodeDecodeError):
        return None
    return int(v) if math.isfinite(v) else None


def temperature_c(thermal: Path = THERMAL) -> Optional[float]:
    """La plus haute des zones thermiques lisibles ; None s'il n'y en a aucune."""
    mesures = []
    try:
        zones = sorted(thermal.glob("thermal_zone*"))
    except OSError:
        return None
    for z in zones:
        try:
            v = int((z / "temp").read_text(encoding="ascii").strip())
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        c = v / 1000.0
        if -40.0 <= c <= 150.0:
            mesures.append(c)
    return _fini(max(mesures)) if mesures else None


def releve(proc: Path = PROC, thermal: Path = THERMAL, intervalle: float = 0.25) -> Dict:
    return {
        "cpu_percent": cpu_percent(proc, intervalle),
        "memory_percent": memoire_percent(proc),
        "disk_percent": disque_percent("/"),
        "load": charge(proc),
        "uptime_seconds": uptime_s(proc),
        "temperature_celsius": temperature_c(thermal),
    }


def plateforme() -> Dict[str, str]:
    u = platform.uname()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(u.machine, u.machine)
    return {"hostname": u.node, "architecture": arch, "kernel": u.release}
