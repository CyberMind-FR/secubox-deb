# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes du lot 5b SBX TV PRIVACY (#3374) — assistant de détection en direct.

Gardes : tout en `require_jwt` (administrateur réel : données par appareil, choix différés, apprentissage guidé), SAUF le compteur
agrégé du kiosque `/protection/usager/appris` (`require_personne`, un nombre sans appareil ni domaine). Chaque écriture passe AVANT
par le verbe root `audit-protection` (gestes `assistant`, `assistant-annule`, `guide`) ; un audit impossible refuse le geste (502).
Les choix ne touchent jamais le DNS ici : le moteur `secubox-adguard-auto` consomme la file à son passage (`dnstv_assistant`).
"""
from __future__ import annotations

import json
import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

try:
    from . import dnstv, dnstv_assistant, dnstv_dpi, dnstv_regles, dnstv_taxonomie
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_assistant, dnstv_dpi, dnstv_regles, dnstv_taxonomie
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt, require_personne

router = APIRouter(prefix="/adblock-tv", tags=["adblock-tv-assistant"])

MAC_MOTIF = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
TYPES_ACTIONNABLES = ("repli", "repli-protege", "secours")      # découvertes qui portent un NOM de domaine
CANDIDATS_MAX = 50


class ChoixIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac: str = Field(pattern=MAC_MOTIF)
    domaine: str = Field(min_length=1, max_length=253)
    choix: Literal["bloquer", "legitime", "plus-tard"]
    force: bool = False
    decouverte: Optional[int] = Field(None, ge=1)


class AnnulerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[0-9a-f]{16}$")


class GuideIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mac: str = Field(pattern=MAC_MOTIF)
    actif: bool


def _etat() -> dict:
    etat, erreur = dnstv.lire_etat()
    if erreur:
        raise HTTPException(503, "état illisible")
    return etat


def _charger() -> dict:
    try:
        return dnstv_assistant.charger()
    except dnstv_assistant.ErreurAssistant as e:
        raise HTTPException(409, str(e)) from None


def _nom(etat: dict, mac: str) -> str:
    nom = next((c["nom"] for c in etat.get("clients", []) if c.get("mac") == mac), None)
    if nom is None:
        raise HTTPException(404, "appareil inconnu")
    return nom


def _audit(acteur: str, geste: str, nom: str, domaine: Optional[str], type_: str, force: bool = False) -> None:
    _r._ctl_entree("audit-protection", json.dumps({"acteur": acteur, "origine": "admin", "geste": geste, "cibles": [nom], "minutes": None,
                                                   "domaine": domaine, "type": type_, "force": bool(force)}))


def _action(x: Optional[dict]) -> Optional[dict]:
    return None if x is None else {k: x[k] for k in ("id", "choix", "etat", "applique", "raison", "force")}


@router.get("/protection/direct")
def direct(depuis: int = Query(0, ge=0), limite: int = Query(50, ge=1, le=200), _=Depends(require_jwt)):
    """Vue « En direct » : découvertes d'identifiant > `depuis` (curseur), avec nom d'appareil (« appareil inconnu » sans MAC déclarée,
    jamais une adresse), catégorie, confiance, raison, et l'action de l'assistant en cours ; la file entière (états à jour), les
    candidats en attente de validation et l'apprentissage guidé par appareil."""
    etat = _etat()
    c = _charger()
    noms = {x["mac"]: x["nom"] for x in etat.get("clients", []) if x.get("mac")}
    slugs = {dnstv._slug(x["nom"]): x for x in etat.get("clients", []) if x.get("mac")}
    file = dnstv_assistant.pour_page(c)
    par_couple: dict = {}
    for x in reversed(file):                                         # la plus récente gagne
        par_couple[(x["mac"], x["domaine"])] = x
    taxo = dnstv_taxonomie.Taxonomie.depuis_dossier()
    mag = dnstv_dpi.MagasinDPI(dnstv.DOSSIER_ETAT / "dpi-appareils.db", lecture_seule=True)
    out = []
    for d in mag.decouvertes(depuis, None, None, limite):
        nom_valide = dnstv.valider_domaine(d["domaine"]) == d["domaine"]
        cl = taxo.classer(d["domaine"]) if nom_valide else None
        out.append({"id": d["id"], "ts": d["ts"], "type": d["type"], "mac": d["mac"], "appareil": noms.get(d["mac"], "appareil inconnu"),
                    "domaine": d["domaine"], "categorie": d.get("categorie") or (cl["categorie"] if cl else "INCONNU"),
                    "protegee": bool(cl and cl["protegee"]), "confiance": d["confiance"], "raison": d["raison"],
                    "etat": "ecartee-protegee" if d["type"] == "repli-protege" else d["etat"],
                    "actionnable": nom_valide and d["type"] in TYPES_ACTIONNABLES and d["mac"] in noms,
                    "action": _action(par_couple.get((d["mac"], d["domaine"])))})
    try:
        regles = dnstv_regles.charger().liste()
    except dnstv_regles.ErreurRegle:
        regles = []
    candidats = []
    for r in sorted((r for r in regles if r["etat"] == "candidat" and r.get("origine") == "auto" and r["appareil"] in slugs),
                    key=lambda r: r["cree"], reverse=True)[:CANDIDATS_MAX]:
        cl = slugs[r["appareil"]]
        candidats.append({"mac": cl["mac"], "appareil": cl["nom"], "domaine": r["domaine"], "confiance": r["score"], "raison": r["motif"],
                          "categorie": taxo.classer(r["domaine"])["categorie"], "action": _action(par_couple.get((cl["mac"], r["domaine"])))})
    guides = set(c["guides"])
    return {"decouvertes": out, "dernier_id": max((d["id"] for d in out), default=depuis), "file": file, "candidats": candidats,
            "appareils": [{"mac": m, "nom": n, "guide": m in guides} for m, n in sorted(noms.items(), key=lambda kv: kv[1])],
            "genere": int(time.time())}


@router.post("/protection/assistant/choix")
def choix(corps: ChoixIn, jeton=Depends(require_jwt)):
    """Met un choix EN ATTENTE dans la file (aucun effet DNS ici). Bloquer une catégorie protégée (hors INCONNU) exige `force` (409),
    comme au lot 3 : `imasdk.googleapis.com` (STREAMING) n'est jamais bloquable sans elle."""
    d = dnstv.valider_domaine(corps.domaine)
    if not d or d != corps.domaine:
        raise HTTPException(422, "nom de domaine invalide")
    if corps.choix == "bloquer" and not corps.force:
        try:
            c = dnstv_taxonomie.Taxonomie.depuis_dossier().classer(d)
        except (OSError, ValueError) as e:
            raise HTTPException(503, f"taxonomie indisponible ({type(e).__name__}) : blocage refusé, réessayer") from None
        if c["protegee"] and c["categorie"] != "INCONNU":
            raise HTTPException(409, f"catégorie {c['categorie']} protégée (lecture des vidéos, DRM…) : confirmer le blocage (force)")
    with _r._verrou():
        nom = _nom(_etat(), corps.mac)
        c = _charger()
        acteur = _r._acteur(jeton)
        try:
            x = dnstv_assistant.ajouter(c, corps.mac, nom, d, corps.choix, corps.force, corps.decouverte, acteur, int(time.time()))
        except (dnstv_assistant.ErreurDoublon, dnstv_assistant.ErreurPlafond) as e:
            raise HTTPException(409, str(e)) from None
        except dnstv_assistant.ErreurAssistant as e:
            raise HTTPException(422, str(e)) from None
        _audit(acteur, "assistant", nom, d, corps.choix, corps.force)
        try:
            dnstv_assistant.ecrire(c)
        except (OSError, dnstv_assistant.ErreurAssistant) as e:
            raise HTTPException(503, f"file non écrite ({type(e).__name__})") from None
    return x


@router.post("/protection/assistant/annuler")
def annuler(corps: AnnulerIn, jeton=Depends(require_jwt)):
    """Retire une action tant qu'elle est EN ATTENTE (409 une fois traitée par le moteur)."""
    with _r._verrou():
        c = _charger()
        try:
            x = dnstv_assistant.annuler(c, corps.id)
        except dnstv_assistant.ErreurAssistant as e:
            raise HTTPException(404 if "inconnue" in str(e) else 409, str(e)) from None
        _audit(_r._acteur(jeton), "assistant-annule", x["appareil"], x["domaine"], x["choix"], x["force"])
        try:
            dnstv_assistant.ecrire(c)
        except (OSError, dnstv_assistant.ErreurAssistant) as e:
            raise HTTPException(503, f"file non écrite ({type(e).__name__})") from None
    return {"annule": x["id"]}


@router.post("/protection/assistant/guide")
def guide(corps: GuideIn, jeton=Depends(require_jwt)):
    """Apprentissage guidé d'un appareil : ses candidats attendent la validation au lieu de passer seuls en essai. Désactivé par défaut."""
    with _r._verrou():
        nom = _nom(_etat(), corps.mac)
        c = _charger()
        try:
            change = dnstv_assistant.basculer_guide(c, corps.mac, corps.actif)
        except dnstv_assistant.ErreurAssistant as e:
            raise HTTPException(409, str(e)) from None
        if change:
            _audit(_r._acteur(jeton), "guide", nom, None, "active" if corps.actif else "desactive")
            try:
                dnstv_assistant.ecrire(c)
            except (OSError, dnstv_assistant.ErreurAssistant) as e:
                raise HTTPException(503, f"apprentissage guidé non écrit ({type(e).__name__})") from None
    return {"mac": corps.mac, "guide": corps.actif}


@router.get("/protection/usager/appris")
def appris(_=Depends(require_personne)):
    """Kiosque (préparé, lot 5b) : « N nouveaux pisteurs appris » sur 7 jours, un nombre seulement (ni appareil, ni domaine)."""
    try:
        regles = dnstv_regles.charger()
    except dnstv_regles.ErreurRegle:
        raise HTTPException(503, "règles illisibles") from None
    return {"nouveaux_pisteurs": dnstv_assistant.nouveaux_pisteurs(regles, int(time.time())), "jours": dnstv_assistant.APPRIS_JOURS}
