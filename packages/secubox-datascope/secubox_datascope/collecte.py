# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Passe de collecte de DataScope : sources -> base -> caches overview.json et graph.json (#3853).

Garde-fous : moins de 512 Mo libres ou base >= 200 Mo => la passe s'abstient (rien n'est écrit) ; une passe
dégradée n'écrase jamais un cache COMPLET de moins de 15 min (double tampon, #3011) ; écriture atomique.
Lancé par l'unité oneshot : python3 -m secubox_datascope.collecte (une ligne JSON par passe, vers journald).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .config import Config, charger
from .connecteurs import network, status
from .store import (BASE_MAX_OCTETS, VOISINS_ARETES_MAX, VOISINS_NOEUDS_MAX, _taille, appliquer, etat_sources, ouvrir,
                    purger)

DISQUE_MIN_OCTETS = 512 * 1024 * 1024
COMPLET_VALIDE_S = 15 * 60
RAFRAICHIR_S = 10 * 60  # un cache identique n'est réécrit qu'au bout de ce délai (fraîcheur de genere_le)


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(s: Any) -> Optional[float]:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _ecrire_atomique(chemin: Path, contenu: Dict[str, Any]) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    tmp = chemin.with_name(chemin.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(contenu, f, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    finally:
        if tmp.exists():
            tmp.unlink()


def _actuel(chemin: Path) -> Optional[Dict[str, Any]]:
    try:
        d = json.loads(chemin.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _publier(chemin: Path, neuf: Dict[str, Any], complet: bool, maintenant: float) -> str:
    """Double tampon : une passe dégradée garde le dernier complet frais ; un contenu identique n'est pas réécrit."""
    ancien = _actuel(chemin)
    age: Optional[float] = None
    if ancien is not None:
        t = _epoch(ancien.get("genere_le"))
        age = None if t is None else maintenant - t
    if not complet and ancien and ancien.get("complet") is True and age is not None and age < COMPLET_VALIDE_S:
        return "conserve"
    if ancien and ancien.get("complet") == complet and age is not None and age < RAFRAICHIR_S:
        a = {k: v for k, v in ancien.items() if k != "genere_le"}
        n = {k: v for k, v in neuf.items() if k != "genere_le"}
        if a == n:
            return "inchange"
    _ecrire_atomique(chemin, neuf)
    return "ecrit"


def _vue_graphe(db, genere: str, complet: bool) -> Dict[str, Any]:
    n_tot = db.execute("SELECT count(*) FROM entities").fetchone()[0]
    noeuds = [dict(r) for r in db.execute(
        "SELECT id, type, label, source_module, first_seen, last_seen FROM entities ORDER BY id LIMIT ?",
        (VOISINS_NOEUDS_MAX,))]
    ids = {n["id"] for n in noeuds}
    aretes = []
    for r in db.execute("SELECT src, dst, type, evidence_type, confidence, source_module, last_seen "
                        "FROM relationships ORDER BY src, dst, type, source_module"):
        if r["src"] in ids and r["dst"] in ids:
            aretes.append(dict(r))
            if len(aretes) >= VOISINS_ARETES_MAX:
                break
    n_rel = db.execute("SELECT count(*) FROM relationships").fetchone()[0]
    tronque = n_tot > len(noeuds) or n_rel > len(aretes)
    return {"genere_le": genere, "complet": complet, "noeuds": noeuds, "aretes": aretes, "tronque": tronque}


def _vue_apercu(db, genere: str, complet: bool) -> Dict[str, Any]:
    entites = {r["type"]: r["n"] for r in db.execute("SELECT type, count(*) AS n FROM entities GROUP BY type")}
    return {"genere_le": genere, "complet": complet, "entites": entites,
            "relations": db.execute("SELECT count(*) FROM relationships").fetchone()[0],
            "sources": [{k: s[k] for k in ("source", "etat", "motif", "vu_le")} for s in etat_sources(db)]}


def _espace_libre(base: Path) -> int:
    p = base.parent
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(str(p)).free


def passe(cfg: Config, maintenant: float) -> Dict[str, Any]:
    debut = time.monotonic()

    def fin(res: Dict[str, Any]) -> Dict[str, Any]:
        res["duree_s"] = round(time.monotonic() - debut, 3)
        return res

    libre = _espace_libre(Path(cfg.base))
    if libre < DISQUE_MIN_OCTETS:
        return fin({"etat": "abstenu", "motif": f"disque : {libre // 2**20} Mo libres (< 512 Mo)", "sources": {}})
    hote = socket.gethostname().split(".")[0]
    db = ouvrir(Path(cfg.base))
    try:
        horodatage = _iso(maintenant)
        purger(db, horodatage)
        if _taille(db) >= BASE_MAX_OCTETS:
            return fin({"etat": "abstenu", "sources": {},
                        "motif": f"base : {_taille(db) // 2**20} Mo (>= {BASE_MAX_OCTETS // 2**20} Mo)"})
        sources: Dict[str, Any] = {}
        for releve in (network.lire(cfg.nac_db, cfg.netstats, hote, maintenant),
                       status.lire(cfg.modules, hote, maintenant, cfg.modules_perime_s)):
            res = appliquer(db, releve, horodatage)
            sources[releve.source] = {"etat": releve.etat, "motif": releve.motif, **res}
        complet = all(s["etat"] == "ok" and not s["refusees"] for s in sources.values())
        ecrit = {
            "overview.json": _publier(Path(cfg.cache) / "overview.json", _vue_apercu(db, horodatage, complet),
                                      complet, maintenant),
            "graph.json": _publier(Path(cfg.cache) / "graph.json", _vue_graphe(db, horodatage, complet),
                                   complet, maintenant),
        }
        return fin({"etat": "complet" if complet else "degrade", "sources": sources, "caches": ecrit})
    finally:
        db.close()


def main() -> int:
    try:
        res = passe(charger(), time.time())
    except Exception as e:  # noqa: BLE001 - erreur imprévue : une ligne pour journald, code non nul
        print(json.dumps({"etat": "erreur", "motif": type(e).__name__}), flush=True)
        return 1
    print(json.dumps(res, sort_keys=True, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
