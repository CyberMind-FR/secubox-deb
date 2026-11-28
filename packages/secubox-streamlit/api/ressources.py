# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Ressources des applis Streamlit, par cgroup de leur unité (#4050).

Chaque appli tourne dans SON unité `streamlit-app@<nom>.service`, dans le
conteneur LXC `streamlit`. Le cgroup de cette unité est visible depuis
l'hôte sous `/sys/fs/cgroup/lxc.payload.streamlit/…` : on y lit
`cpu.stat` (usage_usec, cumulé) et `memory.current`, en lecture seule, sans
lxc-attach, sans sudo, sans sous-processus. Une unité présente = une appli
éveillée ; absente = endormie.

Le CPU % se calcule entre DEUX relevés (différence d'usage_usec rapportée au
temps écoulé et au nombre de cœurs). Le relevé tourne en tâche de fond tant
que quelqu'un regarde le panneau (#1835 : personne ne regarde, rien ne
tourne) et s'écrit dans un fichier en double tampon : une passe dégradée
(cgroup illisible) ne remplace jamais le dernier relevé complet (#3011).
"""
from __future__ import annotations

import json
import os
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Racines candidates du cgroup du conteneur (lxc 5/6 sur cgroup v2).
RACINES_CGROUP = [
    Path(os.environ["SECUBOX_STREAMLIT_CGROUP"]) if os.environ.get("SECUBOX_STREAMLIT_CGROUP") else None,
    Path("/sys/fs/cgroup/lxc.payload.streamlit"),
    Path("/sys/fs/cgroup/lxc/streamlit"),
]
CACHE_RESSOURCES = Path(os.environ.get("SECUBOX_STREAMLIT_RESSOURCES_CACHE",
                                       "/var/lib/secubox/streamlit-ressources/ressources.json"))
IDLE_DIR = Path(os.environ.get("SECUBOX_STREAMLIT_IDLE_DIR", "/var/lib/secubox/streamlit/idle"))

PERIODE_S = 10          # un relevé toutes les 10 s, tant que le panneau est lu
REGARD_S = 120          # sans lecture depuis 2 min : le relevé s'arrête
HISTO_N = 30            # mini-histogramme : 30 relevés (5 min)

_UNITE = re.compile(r"^streamlit-app@(.+)\.service$")


def _desechapper(nom: str) -> str:
    """systemd échappe le nom d'instance (`-` → `\\x2d`) : on le rend lisible."""
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), nom)


def racine_cgroup() -> Optional[Path]:
    for r in RACINES_CGROUP:
        if r is not None and r.is_dir():
            return r
    return None


def _lire_cpu_usec(d: Path) -> Optional[int]:
    try:
        for ligne in (d / "cpu.stat").read_text().splitlines():
            k, _, v = ligne.partition(" ")
            if k == "usage_usec":
                return int(v)
    except (OSError, ValueError):
        pass
    return None


def _lire_memoire(d: Path) -> Optional[int]:
    try:
        return int((d / "memory.current").read_text().strip())
    except (OSError, ValueError):
        return None


def _dossiers_unites(racine: Path) -> Iterable[Path]:
    """Dossiers `streamlit-app@*.service` sous system.slice (et sa sous-tranche)."""
    sys_slice = racine / "system.slice"
    try:
        entrees = list(os.scandir(sys_slice))
    except OSError:
        return []
    out = []
    for e in entrees:
        if not e.is_dir(follow_symlinks=False):
            continue
        if _UNITE.match(e.name):
            out.append(Path(e.path))
        elif e.name.startswith("system-streamlit") and e.name.endswith(".slice"):
            try:
                out.extend(Path(s.path) for s in os.scandir(e.path)
                           if s.is_dir(follow_symlinks=False) and _UNITE.match(s.name))
            except OSError:
                pass
    return out


def relever(racine: Optional[Path] = None, maintenant: Optional[float] = None) -> Dict[str, Any]:
    """Un relevé brut : usage CPU cumulé et mémoire par appli éveillée.

    `complet=False` quand le cgroup du conteneur est introuvable : le relevé
    ne dit alors RIEN des applis (ce n'est pas « toutes endormies »).
    """
    t = time.time() if maintenant is None else maintenant
    racine = racine if racine is not None else racine_cgroup()
    if racine is None or not racine.is_dir():
        return {"ts": t, "complet": False, "applis": {}, "conteneur": {}}
    applis: Dict[str, Dict[str, Any]] = {}
    for d in _dossiers_unites(racine):
        nom = _desechapper(_UNITE.match(d.name).group(1))
        try:
            debut = d.stat().st_ctime
        except OSError:
            debut = None
        applis[nom] = {"cpu_usec": _lire_cpu_usec(d), "memoire": _lire_memoire(d), "debut": debut}
    return {"ts": t, "complet": True, "applis": applis,
            "conteneur": {"cpu_usec": _lire_cpu_usec(racine), "memoire": _lire_memoire(racine)}}


def cpu_pourcent(avant: Optional[int], apres: Optional[int], dt: float,
                 coeurs: Optional[int] = None) -> Optional[float]:
    """CPU en % de la BOX entière (100 % = tous les cœurs occupés).

    None si l'un des relevés manque, si le temps n'avance pas, ou si le
    compteur a reculé (unité redémarrée entre les deux relevés).
    """
    if avant is None or apres is None or dt <= 0 or apres < avant:
        return None
    n = coeurs or os.cpu_count() or 1
    pct = (apres - avant) / (dt * 1_000_000) / n * 100.0
    return round(min(max(pct, 0.0), 100.0), 1)


class Collecteur:
    """Relevés successifs → mesures (CPU %, mémoire, historique) + écriture du cache."""

    def __init__(self, cache: Path = CACHE_RESSOURCES, coeurs: Optional[int] = None):
        self.cache = cache
        self.coeurs = coeurs or os.cpu_count() or 1
        self.precedent: Optional[Dict[str, Any]] = None
        self.histo: Dict[str, deque] = {}
        self.histo_total: deque = deque(maxlen=HISTO_N)
        self.dernier_complet: Optional[Dict[str, Any]] = None

    def integrer(self, releve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Intègre un relevé ; rend les mesures si le relevé est complet, sinon None
        (le dernier relevé complet reste en place)."""
        if not releve.get("complet"):
            return None
        prev = self.precedent if (self.precedent and self.precedent.get("complet")) else None
        dt = releve["ts"] - prev["ts"] if prev else 0.0
        applis = {}
        for nom, m in releve["applis"].items():
            p = prev["applis"].get(nom) if prev else None
            cpu = cpu_pourcent(p.get("cpu_usec") if p else None, m.get("cpu_usec"), dt, self.coeurs)
            h = self.histo.setdefault(nom, deque(maxlen=HISTO_N))
            if cpu is not None:
                h.append(cpu)
            applis[nom] = {"cpu_pct": cpu, "memoire": m.get("memoire"), "debut": m.get("debut"),
                           "histo_cpu": list(h)}
        for nom in list(self.histo):            # appli endormie : son historique part
            if nom not in releve["applis"]:
                del self.histo[nom]
        c, pc = releve.get("conteneur") or {}, (prev or {}).get("conteneur") or {}
        cpu_c = cpu_pourcent(pc.get("cpu_usec"), c.get("cpu_usec"), dt, self.coeurs)
        if cpu_c is not None:
            self.histo_total.append(cpu_c)
        self.precedent = releve
        mesures = {"ts": releve["ts"], "intervalle_s": round(dt, 1) if prev else None,
                   "coeurs": self.coeurs, "applis": applis,
                   "conteneur": {"cpu_pct": cpu_c, "memoire": c.get("memoire"),
                                 "histo_cpu": list(self.histo_total)}}
        self.dernier_complet = mesures
        return mesures

    def ecrire(self, mesures: Dict[str, Any]) -> None:
        """Écriture atomique (tmp + rename) : un lecteur ne voit jamais un fichier à moitié écrit."""
        self.cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache.with_name("." + self.cache.name + ".tmp")
        tmp.write_text(json.dumps(mesures))
        os.replace(tmp, self.cache)

    def passe(self, racine: Optional[Path] = None, maintenant: Optional[float] = None) -> Optional[Dict[str, Any]]:
        m = self.integrer(relever(racine, maintenant))
        if m is not None:
            try:
                self.ecrire(m)
            except OSError:
                pass                             # le relevé en mémoire reste servi
        return m


def lire_cache(cache: Path = CACHE_RESSOURCES) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads(cache.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _dernier_acces(nom: str, inventaire: Dict[str, Any]) -> Optional[int]:
    la = inventaire.get("last_active")
    if isinstance(la, (int, float)) and la > 0:
        return int(la)
    try:
        return int((IDLE_DIR / f"{nom}.state").stat().st_mtime)
    except OSError:
        return None


def construire_vue(mesures: Optional[Dict[str, Any]], inventaire: List[Dict[str, Any]],
                   maintenant: Optional[float] = None) -> Dict[str, Any]:
    """Liste unique : éveillées EN HAUT (CPU décroissant), endormies en bas (mesures à zéro).

    `inventaire` = applis de /apps/audit (toutes, même endormies) ; les
    mesures disent qui est éveillé MAINTENANT (fraîcheur 10 s, plus récente
    que l'inventaire). Archivées : listées en dernier, comme endormies.
    """
    t = time.time() if maintenant is None else maintenant
    vues = (mesures or {}).get("applis") or {}
    connues = {a.get("name"): a for a in inventaire if a.get("name")}
    noms = set(connues) | set(vues)
    lignes = []
    for nom in noms:
        inv = connues.get(nom, {})
        m = vues.get(nom)
        eveillee = m is not None if mesures else (inv.get("state") == "running")
        debut = (m or {}).get("debut")
        acces = _dernier_acces(nom, inv)
        lignes.append({
            "name": nom,
            "eveillee": eveillee,
            "etat": "eveillee" if eveillee else ("archivee" if inv.get("state") == "archived" else "endormie"),
            "cpu_pct": ((m or {}).get("cpu_pct") if eveillee else 0.0),
            "memoire": ((m or {}).get("memoire") if eveillee else 0),
            "histo_cpu": ((m or {}).get("histo_cpu") or []) if eveillee else [],
            "age_s": int(t - debut) if (eveillee and debut) else None,
            "dernier_acces": acces,
            "port": inv.get("port"),
            "domain": inv.get("domain") or "",
        })
    rang = {"eveillee": 0, "endormie": 1, "archivee": 2}
    lignes.sort(key=lambda x: (rang[x["etat"]], -(x["cpu_pct"] or 0.0), -(x["memoire"] or 0), x["name"]))
    ev = [x for x in lignes if x["eveillee"]]
    cont = (mesures or {}).get("conteneur") or {}
    total = {
        "eveillees": len(ev),
        "applis": len(lignes),
        "cpu_pct": round(sum(x["cpu_pct"] or 0.0 for x in ev), 1),
        "memoire": sum(x["memoire"] or 0 for x in ev),
        "conteneur_cpu_pct": cont.get("cpu_pct"),
        "conteneur_memoire": cont.get("memoire"),
        "histo_cpu": cont.get("histo_cpu") or [],
    }
    return {
        "disponible": mesures is not None,
        "mesure_ts": (mesures or {}).get("ts"),
        "age_s": int(t - mesures["ts"]) if mesures and mesures.get("ts") else None,
        "intervalle_s": (mesures or {}).get("intervalle_s"),
        "coeurs": (mesures or {}).get("coeurs") or os.cpu_count(),
        "total": total,
        "applis": lignes,
    }
