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
import sqlite3
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


def _publier(chemin: Path, neuf: Dict[str, Any], complet: bool, maintenant: float, battement: bool = False) -> str:
    """Double tampon : une passe dégradée garde le dernier complet frais (sans battement : le collecteur vieillit).

    genere_le = date du contenu (inchangée si le contenu est identique). Avec battement, verifie_le = maintenant
    et le fichier est réécrit à chaque passe ; sans, un contenu identique n'est pas réécrit.
    """
    ancien = _actuel(chemin)
    age: Optional[float] = None
    if ancien is not None:
        t = _epoch(ancien.get("genere_le"))
        age = None if t is None else maintenant - t
    if not complet and ancien and ancien.get("complet") is True and age is not None and age < COMPLET_VALIDE_S:
        return "conserve"
    if ancien and ancien.get("complet") == complet:
        coeur = ("genere_le", "verifie_le")
        if {k: v for k, v in ancien.items() if k not in coeur} == {k: v for k, v in neuf.items() if k not in coeur}:
            if not battement:
                return "inchange"
            neuf["genere_le"] = ancien.get("genere_le", neuf["genere_le"])
    if battement:
        neuf["verifie_le"] = _iso(maintenant)
    _ecrire_atomique(chemin, neuf)
    return "ecrit"


MAX_PAR_IF = 60  # même plafond que la page (MAX_PAR_IF) : appareils dessinés par interface
TYPES_SOCLE = ("node", "interface", "network", "service")
_COLS = "id, type, label, source_module, first_seen, last_seen"


def _vue_graphe(db, genere: str, complet: bool) -> Dict[str, Any]:
    """Vue par défaut, priorisée : box, interfaces, zones et services d'abord ; puis, par interface (CONNECTS_TO le
    plus récent ; « sans interface » compte pour une), les MAX_PAR_IF appareils vus le plus récemment ; jamais
    d'adresse ip (dans l'inspecteur). 500 noeuds et 1 500 arêtes entre retenus au plus ; tronque si un noeud
    non-ip ou une arête entre retenus est écarté.
    """
    socle = [dict(r) for r in db.execute(
        f"SELECT {_COLS} FROM entities WHERE type IN ({','.join('?' * len(TYPES_SOCLE))}) "
        "ORDER BY CASE type WHEN 'node' THEN 0 WHEN 'interface' THEN 1 WHEN 'network' THEN 2 ELSE 3 END, id LIMIT ?",
        (*TYPES_SOCLE, VOISINS_NOEUDS_MAX))]
    reste = VOISINS_NOEUDS_MAX - len(socle)
    # Récence = date du NAC (attribut vu_nac, au jour près) : entities.last_seen n'est que la date de la passe.
    appareils = [] if reste <= 0 else [dict(r) for r in db.execute(
        f"WITH d AS (SELECT {_COLS}, CASE WHEN json_valid(attributes_json) THEN attributes_json ELSE '{{}}' END AS a,"
        "   (SELECT r.dst FROM relationships r WHERE r.src = e.id AND r.type = 'CONNECTS_TO'"
        "   AND r.dst LIKE 'interface:%' ORDER BY r.last_seen DESC, r.dst LIMIT 1) AS iface"
        "  FROM entities e WHERE e.type = 'device'),"
        " v AS (SELECT d.*, coalesce(json_extract(a, '$.vu_nac'), '') AS vu_nac, json_extract(a, '$.ip') AS ip"
        "  FROM d),"
        " r AS (SELECT v.*, ROW_NUMBER() OVER (PARTITION BY coalesce(iface, '') ORDER BY vu_nac DESC, id) AS rang"
        "  FROM v)"
        f" SELECT {_COLS}, vu_nac, ip FROM r WHERE rang <= ? ORDER BY rang, vu_nac DESC, id LIMIT ?",
        (MAX_PAR_IF, reste))]
    for n in appareils:  # seuls ip et vu_nac voyagent dans le graphe (liste d'appareils de la page)
        vu, ip = n.pop("vu_nac"), n.pop("ip")
        n["attributes"] = {k: v for k, v in (("vu_nac", vu), ("ip", ip)) if isinstance(v, str) and v}
    noeuds = sorted(socle + appareils, key=lambda n: n["id"])
    ids = [n["id"] for n in noeuds]
    db.execute("CREATE TEMP TABLE IF NOT EXISTS _vue(id TEXT PRIMARY KEY)")
    db.execute("DELETE FROM _vue")
    db.executemany("INSERT OR IGNORE INTO _vue(id) VALUES (?)", [(i,) for i in ids])
    # Arêtes du socle avant celles des appareils : la box et ses interfaces restent reliées même sous le plafond.
    aretes = [dict(r) for r in db.execute(
        "SELECT src, dst, type, evidence_type, confidence, source_module, last_seen FROM relationships "
        "WHERE src IN (SELECT id FROM _vue) AND dst IN (SELECT id FROM _vue) "
        "ORDER BY (src LIKE 'device:%' OR dst LIKE 'device:%'), src, dst, type, source_module LIMIT ?",
        (VOISINS_ARETES_MAX + 1,))]
    db.execute("DELETE FROM _vue")
    par_type = {r[0]: r[1] for r in db.execute("SELECT type, count(*) FROM entities GROUP BY type")}
    hors_ip = sum(n for t, n in par_type.items() if t != "ip")
    tronque = hors_ip > len(noeuds) or len(aretes) > VOISINS_ARETES_MAX
    return {"genere_le": genere, "complet": complet, "noeuds": noeuds, "aretes": aretes[:VOISINS_ARETES_MAX],
            "tronque": tronque, "ip_hors_vue": par_type.get("ip", 0)}


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
                                      complet, maintenant, battement=True),
            "graph.json": _publier(Path(cfg.cache) / "graph.json", _vue_graphe(db, horodatage, complet),
                                   complet, maintenant),
        }
        return fin({"etat": "complet" if complet else "degrade", "sources": sources, "caches": ecrit})
    finally:
        db.close()


def _temporaire(e: BaseException) -> bool:
    """Seuls un verrou ou une base occupée sont temporaires : la passe suivante réessaie (unité en succès).
    Droits, refus AppArmor, disque plein, schéma : vraie erreur, visible (unité en échec)."""
    if not isinstance(e, sqlite3.OperationalError):
        return False
    m = str(e).lower()
    return "locked" in m or "busy" in m


def main() -> int:
    try:
        res = passe(charger(), time.time())
    except Exception as e:  # noqa: BLE001 - une ligne pour journald ; code non nul sauf verrou temporaire
        if _temporaire(e):
            print(json.dumps({"etat": "erreur_temporaire", "motif": type(e).__name__}), flush=True)
            return 0
        print(json.dumps({"etat": "erreur", "motif": type(e).__name__}), flush=True)
        return 1
    print(json.dumps(res, sort_keys=True, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
