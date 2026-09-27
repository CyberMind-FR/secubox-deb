# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — API des faces (#1522)
CyberMind — https://cybermind.fr

Servie par l'agrégateur (utilisateur `secubox`, SANS privilège). Elle ne fait
que REMPLIR le profil et DEMANDER l'application (une unité .path root applique).
La logique vit dans premier_pas.remplir, partagée avec la console : cette API
n'ajoute que la garde.

QUI PEUT ÉCRIRE. Une box neuve n'a pas encore d'administrateur : pas de session
à exiger. L'adresse ne prouve rien — nginx fait confiance à X-Forwarded-For
venant du LAN. D'où un JETON de démarrage créé par root dans /run (0640
root:secubox), que le lanceur du kiosque passe à la page. Box configurée :
plus aucune écriture.
"""
from __future__ import annotations

import hmac
import os
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from premier_pas import moteur as M, profil as P, remplir as R  # noqa: E402

app = FastAPI(title="SecuBox Premier Pas", version="0.3.0")


def _jeton_path() -> Path:
    return Path(os.environ.get("PREMIER_PAS_JETON", "/run/secubox/premier-pas/jeton"))


def ecriture(x_premier_pas: Optional[str] = Header(default=None)) -> None:
    if M.MARQUEUR.exists():
        raise HTTPException(409, "Cette box est déjà configurée : l'assistant est fermé.")
    try:
        attendu = _jeton_path().read_text().strip()
    except OSError:
        raise HTTPException(503, "Assistant pas encore prêt : jeton de démarrage absent.")
    if not attendu or not x_premier_pas or not hmac.compare_digest(attendu, x_premier_pas.strip()):
        raise HTTPException(403, "L'assistant s'utilise depuis l'écran de la box.")


@app.get("/etat")
def etat():
    return R.etat()


@app.get("/choix")
def choix():
    """Ce que les étapes proposent : profils de services, fuseau et nom actuels."""
    try:
        fuseau = Path("/etc/timezone").read_text().strip()
    except OSError:
        fuseau = "Europe/Paris"
    try:
        nom = Path("/etc/hostname").read_text().strip()
    except OSError:
        nom = ""
    profils = []
    for p in sorted(P.PROFILS_DIR.glob("*.toml")) if P.PROFILS_DIR.is_dir() else []:
        try:
            d = tomllib.loads(p.read_text())
            profils.append({"id": p.stem, "libelle": d.get("label", p.stem), "modules": len(d.get("on", []))})
        except (OSError, ValueError):
            continue
    return {"fuseau": fuseau, "nom": nom, "profils": profils,
            "modes_reseau": list(P.MODES_RESEAU), "modes_maillage": list(P.MODES_MAILLAGE)}


@app.put("/etape/{etape}", dependencies=[Depends(ecriture)])
def enregistre(etape: str, valeurs: Dict[str, Any]):
    try:
        return R.enregistre(etape, valeurs)
    except R.Refus as e:
        raise HTTPException(404 if str(e) == "Étape inconnue." else 400, str(e))


@app.post("/appliquer", dependencies=[Depends(ecriture)])
def appliquer():
    try:
        R.demande_appliquer()
    except R.Refus as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "message": "Application demandée : la box se configure."}
