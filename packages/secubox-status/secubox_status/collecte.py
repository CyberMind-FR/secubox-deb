# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecte locale (oneshot, `secubox-status-collect.timer`, 60 s) : sources → relevé v2 → historique → projection.

Ordre et sûreté : le relevé local et la projection s'écrivent par renommage atomique ; l'historique est
transactionnel. Une source en échec ne fait jamais échouer la collecte : elle passe à `unknown`.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from . import SCHEMA_RELEVE, VERSION, config, historique, normalise, projection, systeme
from .sources import Lecture, lire_source

log = logging.getLogger("secubox-status")


def ecrire_atomique(chemin: Path, donnees: Any, mode: int = 0o640) -> None:
    texte = json.dumps(donnees, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=f".{chemin.name}.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _source(cfg: Dict[str, Any], nom: str, horodatage, maintenant: datetime) -> Lecture:
    s = cfg["sources"].get(nom) or {}
    if not s.get("enabled", True):
        return Lecture("absent", motif="source désactivée")
    return lire_source(Path(s["path"]), horodatage, float(s.get("stale_after_seconds", 300)), maintenant)


def collecter(cfg: Dict[str, Any], etat: Path, maintenant: Optional[datetime] = None,
              ressources: Optional[Dict[str, Any]] = None, plateforme: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    maintenant = maintenant or datetime.now(timezone.utc)
    quand = maintenant.isoformat(timespec="seconds")
    plat = plateforme or systeme.plateforme()
    noeud = config.nom_de_noeud(cfg, plat.get("hostname") or "")

    vh = _source(cfg, "vhosts", lambda d: d.get("timestamp"), maintenant)
    mo = _source(cfg, "modules", lambda d: d.get("timestamp"), maintenant)
    pr = _source(cfg, "profiles", lambda d: d.get("releve_ts") or d.get("releve_epoch"), maintenant)
    if ressources is None:
        ressources = systeme.releve() if cfg["sources"]["system"].get("enabled", True) else {}

    e_services, compteurs, detail = normalise.services(mo)
    e_validation, profil = normalise.validation(pr)
    composants = {
        "services": e_services,
        "web": normalise.web(vh),
        "system": normalise.systeme(ressources),
        "validation": e_validation,
    }
    critique_hs = any(d["critical"] and d["status"] == "outage" for d in detail)
    sources = {"modules": mo.etat, "vhosts": vh.etat, "profiles": pr.etat,
               "system": "fresh" if any(v is not None for v in ressources.values()) else "absent"}

    etat.mkdir(mode=0o750, exist_ok=True)
    base = etat / "status.db"
    cx = historique.ouvrir(base)
    try:
        releve = {
            "schema": SCHEMA_RELEVE, "version": VERSION,
            "node": {"id": noeud, "hostname": plat.get("hostname"), "architecture": plat.get("architecture"),
                     "did": None},
            "sequence": historique.sequence_suivante(cx, noeud),
            "collected_at": quand,
            "release": {"kernel": plat.get("kernel"), "profile": profil},
            "health": {"overall": normalise.global_(composants, critique_hs), **composants},
            "resources": {k: ressources.get(k) for k in
                          ("cpu_percent", "memory_percent", "disk_percent", "load", "uptime_seconds",
                           "temperature_celsius")},
            "counts": compteurs,
            "sources": sources,
            "source_notes": {k: v.motif for k, v in (("modules", mo), ("vhosts", vh), ("profiles", pr)) if v.motif},
        }
        ecrire_atomique(etat / "snapshot.json", releve)
        historique.inscrire(cx, releve, detail)
        historique.purger(cx, int(cfg["history"].get("retention_days", 90)), maintenant)
        public = projection.flotte(
            [projection.noeud_public(releve, cfg["public"], historique.heures(cx, noeud, 24, maintenant),
                                     historique.disponibilite(cx, noeud, 30, maintenant), detail,
                                     config.id_public(cfg))],
            quand)
    finally:
        cx.close()
    # Jalon 2 (#3626) : pairs vérifiés par l'Annuaire, sur l'agrégateur seulement.
    if cfg["status"].get("node_role") == "aggregator" and (cfg["sources"].get("pairs") or {}).get("enabled", True):
        sp = cfg["sources"]["pairs"]
        pairs = lire_source(Path(sp["path"]), lambda d: d.get("generated_at"),
                            float(sp.get("stale_after_seconds", 300)), maintenant)
        releve["sources"]["pairs"] = pairs.etat
        if pairs.etat in ("fresh", "stale") and isinstance(pairs.donnees, dict):
            frais = pairs.etat == "fresh"
            vus = {n["id"] for n in public["nodes"]}
            for rec in pairs.donnees.get("noeuds") or []:
                if isinstance(rec, dict) and rec.get("hostname") not in vus:
                    n = projection.noeud_pair(rec, frais and not rec.get("stale"))
                    public["nodes"].append(n)
                    vus.add(n["id"])
            for ind in pairs.donnees.get("indisponibles") or []:
                if isinstance(ind, dict) and ind.get("nom") not in vus:
                    public["nodes"].append(projection.noeud_absent(ind))
                    vus.add(str(ind.get("nom")))
            public = projection.flotte(public["nodes"], quand)
        ecrire_atomique(etat / "snapshot.json", releve)
    (etat / "public").mkdir(mode=0o750, exist_ok=True)
    ecrire_atomique(etat / "public" / "public-v2.json", public)
    return releve


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = config.charger()
    try:
        r = collecter(cfg, config.ETAT)
    except (OSError, sqlite3.Error) as e:
        log.exception("collecte impossible : %s", e)
        return 1
    log.info("relevé %s n°%d : %s (sources %s)", r["node"]["id"], r["sequence"], r["health"]["overall"],
             ", ".join(f"{k}={v}" for k, v in r["sources"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
