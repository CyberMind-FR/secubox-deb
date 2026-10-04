# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox WebFilter — API d'observation (#1962, phase 1).

Mode « observe » : ce que le filtrage de contenus AURAIT bloqué, par catégorie et par appareil. Aucune écriture dans Unbound, aucun blocage.
Lecture agrégée (`require_lecture`) ; tout ce qui détaille un appareil ou lance une action exige un administrateur (`require_jwt`).
"""
import json
import os
import sys
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query
from secubox_core.auth import require_jwt, require_lecture

for _p in ("/usr/lib/secubox/webfilter", str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from webfilter import catalogue, magasin  # noqa: E402

CATALOGUE = Path("/etc/secubox/webfilter.toml")
ETAT = Path("/var/lib/secubox/webfilter")
JOURS_MAX = 30
DEMANDE = "sync.demande"                                               # surveillé par secubox-webfilter-sync.path
DEMANDE_PERIMEE_S = 600

app = FastAPI(title="SecuBox WebFilter", version="0.1.0")


def _categories() -> list:
    try:
        return catalogue.charger(CATALOGUE)
    except catalogue.ErreurCatalogue as e:
        raise HTTPException(503, f"catalogue illisible : {e}") from None


def _depuis(jours: int) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(time.time() - (jours - 1) * 86400))


def _meta(cat_id: str, source_nom: str) -> dict:
    try:
        return json.loads((ETAT / "listes" / cat_id / f"{source_nom}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@app.get("/health")
def health():
    return {"status": "ok", "module": "webfilter", "version": app.version}


@app.get("/status", dependencies=[Depends(require_lecture)])
@app.get("/etat", dependencies=[Depends(require_lecture)])
def etat():
    """Catalogue, mode et ancienneté des listes ; nombre de requêtes classées sur 7 jours, sans aucun nom d'appareil ni chemin."""
    cats = _categories()
    mag = magasin.Magasin(ETAT / "webfilter.db")
    comptes = mag.par_categorie(_depuis(7))
    dernier = mag.dernier_evenement()
    sortie = []
    for c in cats:
        srcs = []
        for s in c.sources:
            m = _meta(c.id, s.nom)
            srcs.append({"nom": s.nom, "licence": s.licence, "n": m.get("n"), "ts": m.get("ts")})
        sortie.append({"id": c.id, "libelle": c.libelle, "mode": c.mode, "requetes_7j": comptes.get(c.id, 0), "sources": srcs})
    return {"mode_global": "observe", "categories": sortie,
            "dernier_evenement": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(dernier)) if dernier else None}


@app.get("/stats", dependencies=[Depends(require_jwt)])
def stats(jours: int = Query(7, ge=1, le=JOURS_MAX)):
    m = magasin.Magasin(ETAT / "webfilter.db")
    depuis = _depuis(jours)
    return {"jours": jours, "par_categorie": m.par_categorie(depuis), "par_client": m.par_client(depuis)}


@app.get("/categories/{cat_id}/domaines", dependencies=[Depends(require_jwt)])
def domaines(cat_id: str, jours: int = Query(7, ge=1, le=JOURS_MAX), n: int = Query(50, ge=1, le=500)):
    if cat_id not in {c.id for c in _categories()}:
        raise HTTPException(404, "catégorie inconnue")
    top = magasin.Magasin(ETAT / "webfilter.db").top_domaines(cat_id, _depuis(jours), n)
    return {"categorie": cat_id, "jours": jours, "domaines": [{"domaine": d, "n": c} for d, c in top]}


@app.post("/sync", status_code=202, dependencies=[Depends(require_jwt)])
def sync():
    """Dépose une DEMANDE de synchronisation ; le téléchargement est fait par l'unité systemd secubox-webfilter-sync (jamais dans ce processus,
    qui sert d'autres modules). Création exclusive : une demande déjà là, et récente, donne 409."""
    _categories()                                                       # 503 si le catalogue est illisible
    f = ETAT / DEMANDE
    ETAT.mkdir(parents=True, exist_ok=True)
    try:
        if time.time() - f.stat().st_mtime > DEMANDE_PERIMEE_S:         # demande oubliée (unité tombée) : on la remplace
            f.unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    try:
        os.close(os.open(f, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640))
    except FileExistsError:
        raise HTTPException(409, "une synchronisation est déjà demandée ou en cours") from None
    return {"statut": "demandee"}
