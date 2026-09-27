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
    return Path(os.environ.get("PREMIER_PAS_JETON", "/run/secubox-premier-pas/jeton"))


def _jeton_local_path() -> Path:
    return Path(os.environ.get("PREMIER_PAS_JETON_LOCAL", "/run/secubox-premier-pas/jeton-local"))


def _verifie(fourni: Optional[str], chemins) -> None:
    if M.MARQUEUR.exists():
        raise HTTPException(409, "Cette box est déjà configurée : l'assistant est fermé.")
    attendus = []
    for c in chemins:
        try:
            v = c.read_text().strip()
        except OSError:
            continue
        if v:
            attendus.append(v)
    if not attendus:
        raise HTTPException(503, "Assistant pas encore prêt : jeton de démarrage absent.")
    if not fourni or not any(hmac.compare_digest(a, fourni.strip()) for a in attendus):
        raise HTTPException(403, "L'assistant s'utilise depuis l'écran de la box.")


def ecriture(x_premier_pas: Optional[str] = Header(default=None)) -> None:
    """Remplir le profil : l'écran de la box (jeton local) OU la box maîtresse
    (le code d'appairage affiché à l'écran)."""
    _verifie(x_premier_pas, [_jeton_local_path(), _jeton_path()])


def locale(x_premier_pas: Optional[str] = Header(default=None)) -> None:
    """Décider (appliquer, accepter, refuser) : l'écran de la box SEUL. Le
    jeton local n'est jamais affiché ni transmis à la box maîtresse."""
    _verifie(x_premier_pas, [_jeton_local_path()])


@app.get("/etat")
def etat():
    return R.etat()


@app.get("/choix")
def choix():
    """Ce que les étapes proposent : profils de services, fuseau et nom actuels."""
    fuseau = P.fuseau_propose()
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
    return {"fuseau": fuseau, "fuseaux": P.fuseaux(), "nom": nom, "profils": profils,
            "modes_reseau": list(P.MODES_RESEAU), "modes_maillage": list(P.MODES_MAILLAGE)}


@app.put("/etape/{etape}", dependencies=[Depends(ecriture)])
def enregistre(etape: str, valeurs: Dict[str, Any]):
    try:
        return R.enregistre(etape, valeurs)
    except R.Refus as e:
        raise HTTPException(404 if str(e) == "Étape inconnue." else 400, str(e))


@app.post("/appliquer", dependencies=[Depends(locale)])
def appliquer():
    try:
        R.demande_appliquer()
    except R.Refus as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "message": "Application demandée : la box se configure."}


@app.get("/code", dependencies=[Depends(locale)])
def code():
    """Le code d'appairage, pour l'afficher à l'écran de la box (et seulement là)."""
    try:
        return {"code": _jeton_path().read_text().strip()}
    except OSError:
        raise HTTPException(503, "Code pas encore prêt.")


@app.post("/proposition", dependencies=[Depends(ecriture)])
def propose(demande: Dict[str, Any]):
    try:
        return R.propose(str(demande.get("par", "")), str(demande.get("mode", "proposer")))
    except R.Refus as e:
        raise HTTPException(409, str(e))


@app.post("/proposition/accepter", dependencies=[Depends(locale)])
def accepte():
    try:
        return R.accepte()
    except R.Refus as e:
        raise HTTPException(409, str(e))


@app.post("/proposition/refuser", dependencies=[Depends(locale)])
def refuse():
    try:
        return R.refuse()
    except R.Refus as e:
        raise HTTPException(409, str(e))


# ── Panneau maître (#1522, couche 4) : box en service, administrateur ──────
# Préparer le profil d'une future box, l'exporter, ou le pousser à distance.
from fastapi.responses import PlainTextResponse  # noqa: E402
from secubox_core.capacites import require_capability  # noqa: E402

from premier_pas import maitre as MA  # noqa: E402

_admin = [Depends(require_capability("admin.modules"))]


def _refus(f, *a, **k):
    try:
        return f(*a, **k)
    except R.Refus as e:
        raise HTTPException(400, str(e))


@app.get("/maitre/profils", dependencies=_admin)
def maitre_liste():
    return {"profils": MA.liste()}


@app.get("/maitre/profils/{nom}", dependencies=_admin)
def maitre_lit(nom: str):
    return {"nom": nom, "profil": R.vue(_refus(MA.lit, nom))}


@app.put("/maitre/profils/{nom}", dependencies=_admin)
def maitre_enregistre(nom: str, profil: Dict[str, Any]):
    return _refus(MA.enregistre, nom, profil)


@app.delete("/maitre/profils/{nom}", dependencies=_admin)
def maitre_supprime(nom: str):
    _refus(MA.supprime, nom)
    return {"ok": True}


@app.get("/maitre/profils/{nom}/export", dependencies=_admin, response_class=PlainTextResponse)
def maitre_export(nom: str):
    return PlainTextResponse(MA.texte(_refus(MA.lit, nom)),
                             headers={"Content-Disposition": f'attachment; filename="profil-{nom}.toml"'})


@app.post("/maitre/pousser", dependencies=_admin)
def maitre_pousse(demande: Dict[str, Any]):
    return _refus(MA.pousse, str(demande.get("nom", "")), str(demande.get("adresse", "")),
                  str(demande.get("code", "")), str(demande.get("mode", "proposer")))


@app.get("/maitre/distant", dependencies=_admin)
def maitre_distant(adresse: str):
    try:
        return _refus(MA.distant, adresse)
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001 — box injoignable
        raise HTTPException(502, f"Box injoignable : {e}")
