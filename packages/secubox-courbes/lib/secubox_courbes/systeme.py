# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: courbes :: instantané système rapide pour la page « Système en direct » (#2767).

NON BLOQUANT : psutil calcule les pourcentages de CPU entre deux appels successifs (`interval=None`), au lieu de dormir 0,5 s à chaque requête
comme l'ancienne API de Glances. Le premier appel après le démarrage sert d'amorce.
Pour chaque processus : pid, nom, CPU, mémoire — JAMAIS la ligne de commande (elle peut contenir un secret) ni l'utilisateur."""
from __future__ import annotations

import threading
import time
from typing import Dict, List

import psutil

TOP_PROCESSUS = 8
MAX_NOM = 40
_VIRTUELS = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/lxcfs", "/var/lib/docker")
_EXCLUES = ("lo", "veth", "br", "lxcbr", "docker", "virbr")
_PROCS: Dict[int, psutil.Process] = {}
_VERROU = threading.Lock()          # deux requêtes simultanées ne doivent pas se disputer les compteurs de CPU


def _nom_propre(nom) -> str:
    if not nom:
        return "?"
    return "".join(c for c in str(nom) if c.isprintable())[:MAX_NOM] or "?"


def _processus() -> List[dict]:
    """Top des processus par CPU. Les objets Process sont gardés d'un appel à l'autre : c'est ce qui rend `cpu_percent()` exact."""
    vus = set()
    out = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.info["pid"]
            vus.add(pid)
            h = _PROCS.get(pid)
            if h is None:
                h = _PROCS[pid] = p
                h.cpu_percent(None)
                cpu = 0.0
            else:
                cpu = h.cpu_percent(None)
            mi = p.info.get("memory_info")
            out.append({"pid": pid, "nom": _nom_propre(p.info.get("name")), "cpu": round(cpu, 1), "memoire": int(mi.rss) if mi else 0})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    for pid in list(_PROCS):
        if pid not in vus:
            del _PROCS[pid]
    out.sort(key=lambda x: (-x["cpu"], -x["memoire"]))
    return out[:TOP_PROCESSUS]


def _disques() -> List[dict]:
    out, vus = [], set()
    for part in psutil.disk_partitions(all=False):
        pt = part.mountpoint
        if pt in vus or (pt.startswith(_VIRTUELS) and pt != "/"):
            continue
        try:
            u = psutil.disk_usage(pt)
        except OSError:
            continue
        if u.total <= 0:
            continue
        vus.add(pt)
        out.append({"point": pt, "pct": round(u.percent, 1), "utilise": u.used, "total": u.total})
    return out


def _reseau() -> dict:
    ifs, rx, tx = [], 0, 0
    for nom, c in psutil.net_io_counters(pernic=True).items():
        if nom.startswith(_EXCLUES):
            continue
        ifs.append({"nom": nom, "rx": c.bytes_recv, "tx": c.bytes_sent})
        rx += c.bytes_recv
        tx += c.bytes_sent
    return {"interfaces": ifs, "total": {"rx": rx, "tx": tx}}


def _temperatures() -> List[dict]:
    try:
        t = psutil.sensors_temperatures()
    except (AttributeError, OSError):
        return []
    out = []
    for nom, lst in (t or {}).items():
        for e in lst[:2]:
            if e.current is not None:
                out.append({"nom": _nom_propre(f"{nom} {e.label}".strip()), "c": round(e.current, 1)})
    return out[:8]


def instantane() -> dict:
    with _VERROU:
        return _instantane()


def _instantane() -> dict:
    coeurs = psutil.cpu_percent(interval=None, percpu=True)
    total = round(sum(coeurs) / len(coeurs), 1) if coeurs else 0.0
    m, s = psutil.virtual_memory(), psutil.swap_memory()
    try:
        charge = [round(x, 2) for x in psutil.getloadavg()]
    except OSError:
        charge = [0.0, 0.0, 0.0]
    return {
        "ts": time.time(),
        "cpu": {"total": total, "coeurs": [round(c, 1) for c in coeurs], "nb": psutil.cpu_count(logical=True)},
        "memoire": {"pct": round(m.percent, 1), "utilise": m.total - m.available, "total": m.total, "dispo": m.available},
        "swap": {"pct": round(s.percent, 1), "utilise": s.used, "total": s.total},
        "disques": _disques(),
        "reseau": _reseau(),
        "temperatures": _temperatures(),
        "charge": charge,
        "uptime_s": int(time.time() - psutil.boot_time()),
        "processus": _processus(),
    }
