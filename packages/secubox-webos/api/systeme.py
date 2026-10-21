# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: WebOS — relevé système léger pour le Hero du Hall (#2996).

Lecture directe de /proc (quelques Ko), aucun sous-processus : CPU par différence de deux
relevés de /proc/stat, mémoire par /proc/meminfo, réseau par /proc/net/dev (compteurs cumulés,
le client fait les différences), disque par statvfs. Appelé hors de la boucle d'événements.
"""
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

from secubox_core.system import disk_usage, load_average

PROC = Path("/proc")
_prec: dict = {"cpu": None}


def _cpu_total_idle(texte: str) -> tuple[int, int]:
    champs = texte.splitlines()[0].split()
    valeurs = [int(x) for x in champs[1:9]]
    idle = valeurs[3] + valeurs[4]
    return sum(valeurs), idle


def cpu_pct(stat: str, precedent: tuple[int, int] | None) -> tuple[float | None, tuple[int, int]]:
    """Pourcentage d'occupation entre deux relevés ; None au premier passage."""
    total, idle = _cpu_total_idle(stat)
    if precedent is None:
        return None, (total, idle)
    dt, di = total - precedent[0], idle - precedent[1]
    pct = round(100.0 * (dt - di) / dt, 1) if dt > 0 else 0.0
    return max(0.0, min(100.0, pct)), (total, idle)


def memoire(meminfo: str) -> dict:
    kv = {}
    for ligne in meminfo.splitlines():
        if ":" in ligne:
            k, v = ligne.split(":", 1)
            kv[k.strip()] = int(v.strip().split()[0])
    total = kv.get("MemTotal", 0)
    dispo = kv.get("MemAvailable", kv.get("MemFree", 0))
    utilise = max(0, total - dispo)
    return {"total_mb": total // 1024, "used_mb": utilise // 1024,
            "pct": round(100.0 * utilise / total, 1) if total else 0.0}


def reseau(netdev: str) -> dict:
    """Octets reçus/émis cumulés, toutes interfaces sauf lo."""
    rx = tx = 0
    for ligne in netdev.splitlines()[2:]:
        if ":" not in ligne:
            continue
        nom, reste = ligne.split(":", 1)
        if nom.strip() == "lo":
            continue
        champs = reste.split()
        if len(champs) >= 9:
            rx += int(champs[0])
            tx += int(champs[8])
    return {"rx_o": rx, "tx_o": tx}


_DISQUE_PHYSIQUE = re.compile(r"^(sd[a-z]+|vd[a-z]+|nvme\d+n\d+|mmcblk\d+)$")


def es_disque(diskstats: str) -> dict:
    """Octets lus/écrits cumulés sur les disques entiers (pas les partitions, ni loop/ram/zram)."""
    lus = ecrits = 0
    for ligne in diskstats.splitlines():
        champs = ligne.split()
        if len(champs) < 14 or not _DISQUE_PHYSIQUE.match(champs[2]):
            continue
        lus += int(champs[5]) * 512
        ecrits += int(champs[9]) * 512
    return {"lu_o": lus, "ecrit_o": ecrits}


def uptime_s(texte: str) -> int:
    return int(float(texte.split()[0]))


def releve(proc: Path = PROC, disque: str = "/") -> dict:
    """Un relevé complet ; conserve le dernier /proc/stat pour le CPU."""
    pct, _prec["cpu"] = cpu_pct((proc / "stat").read_text(), _prec["cpu"])
    d = disk_usage(disque)
    charge = load_average()
    return {
        "hote": socket.gethostname(),
        "releve": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu_pct": pct,
        "charge": [charge["load_1min"], charge["load_5min"], charge["load_15min"]],
        "coeurs": os.cpu_count() or 1,
        "mem": memoire((proc / "meminfo").read_text()),
        "disque": {"chemin": disque, "total_mb": d.get("total_mb", 0), "used_mb": d.get("used_mb", 0),
                   "pct": d.get("percent_used", 0.0)},
        "reseau": dict(reseau((proc / "net" / "dev").read_text()), t=time.time()),
        "es": dict(es_disque((proc / "diskstats").read_text()), t=time.time()),
        "uptime_s": uptime_s((proc / "uptime").read_text()),
    }
