# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API locale de secubox-garde (#3794) sur /run/secubox/garde.sock.

Lecture (`require_lecture`) : état par appareil, historique, réglages. Actions (`require_jwt`) : libérer, rouvrir,
débannir, réglages, clé SMS, envoi d'essai. L'API n'a ni sudo ni la clé du WAF ni accès aux secrets : chaque action
est une DEMANDE (table `demandes`, ou fichier déposé dans `/var/lib/secubox/garde/depot/` pour les réglages et la clé
SMS), exécutée par le passage suivant (≤ 60 s) ; l'interface l'affiche « en cours ». La clé SMS n'est jamais relue.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402
from secubox_core.compte_service import require_lecture_ou_compte  # noqa: E402

from garde import appareils, base, demandes  # noqa: E402

BASE = base.BASE
REGLAGES = base.REGLAGES
DEPOT = base.ETAT / "depot"
AUDIT = Path("/var/log/secubox/audit.log")
SEPT_JOURS = 7 * 86400
RE_COURRIEL = re.compile(r"[^@\s;,<>\"']{1,64}@[a-z0-9.-]{1,190}\.[a-z]{2,24}", re.I)
RE_CLE = re.compile(r"[A-Za-z0-9]{1,64}")
INTRUSIONS_MAX = 200

router = APIRouter(prefix="/api/v1/garde")
#: #3795 : la veille V2 (gk3) lit /etat et /historique avec le compte `ai-lecture` (jeton EdDSA lié à GET et au
#: chemin complet `/api/v1/garde/<route>` : nginx garde le préfixe). Sans porteur : `require_lecture` inchangé.
require_lecture_veille = require_lecture_ou_compte("ai-lecture")


# -- outils

def _db():
    return base.ouvrir(BASE)


def _audit(action: str, cible: str, par: Optional[str], resultat: str = "demande") -> None:
    ligne = json.dumps({"ts": int(time.time()), "module": "garde", "action": action, "cible": cible,
                        "motif": f"par {par or '?'}", "resultat": resultat}, ensure_ascii=False)
    try:
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError:
        pass


def _deposer_fichier(nom: str, contenu: str) -> None:
    """Écriture atomique 0600 dans le dépôt (lu puis effacé par l'aide root du passage)."""
    DEPOT.mkdir(mode=0o700, exist_ok=True)
    tmp = DEPOT / f".{nom}.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, contenu.encode("utf-8"))
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.replace(tmp, DEPOT / nom)


def _anonyme(payload: Any) -> bool:
    """Lecteur du tableau de bord (LAN, sans jeton) : chiffres seulement, jamais d'appareil, d'adresse ni de contact."""
    return not isinstance(payload, dict) or not payload.get("sub")


def _par(payload: Any) -> Optional[str]:
    return payload.get("sub") if isinstance(payload, dict) else None


# -- lecture

@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "module": "garde"}


def _carte(db, row, attente) -> Dict[str, Any]:
    did, menace, cible, mac, ip, motif, signe, debut, fin, etat = row
    adr = [r[0] for r in db.execute("SELECT ip FROM adresses WHERE decision_id=? ORDER BY ip", (did,))] or [ip]
    noms = db.execute("SELECT noms FROM decision_noms WHERE decision_id=?", (did,)).fetchone()
    action = "liberer" if menace == "infection" else "rouvrir"
    return {"id": did, "menace": menace, "cle": cible, "nom": appareils.nom_de(db, cible), "mac": mac,
            "adresses": adr, "motif": motif, "signe": signe, "noms": [n for n in (noms[0] if noms else "").split(",") if n],
            "debut": debut, "fin": fin, "etat": etat,
            "en_cours": etat == "levee_en_cours" or (action, did) in attente}


@router.get("/etat")
def etat(lecteur: Any = Depends(require_lecture_veille)) -> Dict[str, Any]:
    now = int(time.time())
    db = _db()
    try:
        attente = demandes.en_attente(db)
        rows = db.execute("SELECT id, menace, cible, mac, ip, motif, signe, debut, fin, etat FROM decisions "
                          "WHERE etat IN ('active','levee_en_cours') ORDER BY debut DESC").fetchall()
        cartes = [_carte(db, r, attente) for r in rows if r[1] in ("infection", "evasion")]
        bans = [r for r in rows if r[1] == "intrusion" and r[9] == "active"]
        recid = {ip for ip, n in db.execute(
            "SELECT ip, COUNT(*) FROM decisions WHERE menace='intrusion' AND etat IN ('active','echue','levee') "
            "AND debut>? GROUP BY ip", (now - SEPT_JOURS,)) if n >= 2}
        if bans:
            cartes.append({"menace": "intrusion", "n": len(bans),
                           "derniere": {"ip": bans[0][4], "debut": bans[0][7]},
                           "adresses": [{"ip": r[4], "fin": r[8], "motif": r[5], "recidive": r[4] in recid,
                                         "en_cours": ("debannir", r[4]) in attente} for r in bans[:INTRUSIONS_MAX]]})
        notifs = dict(db.execute("SELECT canal, COUNT(*) FROM file_notifs WHERE envoye=1 AND cree>? GROUP BY canal",
                                 (now - 86400,)).fetchall())
        tuiles = {
            "isoles": sum(1 for c in cartes if c["menace"] == "infection"),
            "evasions": sum(1 for c in cartes if c["menace"] == "evasion"),
            "bannis": len(bans),
            "recidivistes": len({r[4] for r in bans} & recid),
            "notifs_24h": {"sms": notifs.get("sms", 0), "courriel": notifs.get("courriel", 0)},
            "en_attente": db.execute("SELECT COUNT(*) FROM file_notifs WHERE envoye=0").fetchone()[0],
        }
        dem = [{"id": i, "action": a, "cible": c, "etat": e, "resultat": r, "cree": t} for i, a, c, e, r, t in db.execute(
            "SELECT id, action, cible, etat, resultat, cree FROM demandes WHERE etat='en_attente' OR traite>? "
            "ORDER BY id DESC LIMIT 20", (now - 3600,))]
    finally:
        db.close()
    reg = base.reglages(REGLAGES)
    anonyme = _anonyme(lecteur)
    if anonyme:
        cartes, dem = [], []
    return {"tuiles": tuiles, "actives": cartes, "automatique": reg["automatique"],
            "quarantaines_max": reg["quarantaines_max"], "demandes": dem, "releve": now, "session_requise": anonyme}


@router.get("/historique")
def historique(heures: int = Query(24, ge=1, le=720), lecteur: Any = Depends(require_lecture_veille)) -> Dict[str, Any]:
    if _anonyme(lecteur):
        return {"heures": heures, "lignes": [], "session_requise": True}
    now = int(time.time())
    depuis = now - heures * 3600
    db = _db()
    try:
        lignes: List[Dict[str, Any]] = []
        groupes: Dict[int, Dict[str, Any]] = {}
        for did, menace, cible, ip, motif, signe, debut, fin, et, par in db.execute(
                "SELECT id, menace, cible, ip, motif, signe, debut, fin, etat, leve_par FROM decisions "
                "WHERE debut>? ORDER BY debut DESC LIMIT 5000", (depuis,)):
            if menace == "intrusion":           # bans d'Internet : groupés par heure
                h = debut // 3600 * 3600
                g = groupes.get(h)
                if g is None:
                    g = groupes[h] = {"menace": "intrusion", "debut": h, "n": 0, "adresses": [], "etat": "active"}
                    lignes.append(g)
                g["n"] += 1
                if len(g["adresses"]) < 20:
                    g["adresses"].append(ip)
                continue
            lignes.append({"id": did, "menace": menace, "debut": debut, "fin": fin, "etat": et, "leve_par": par,
                           "nom": appareils.nom_de(db, cible), "motif": motif, "signe": signe})
        # Libérations par l'administrateur : visibles même si la décision est plus ancienne.
        for cle, signe, jusqua in db.execute("SELECT mac, signe, jusqua FROM liberations WHERE jusqua>?",
                                             (depuis + SEPT_JOURS,)):
            lignes.append({"menace": "libere", "debut": jusqua - SEPT_JOURS, "nom": appareils.nom_de(db, cle),
                           "signe": signe, "jusqua": jusqua})
    finally:
        db.close()
    lignes.sort(key=lambda x: x.get("debut") or 0, reverse=True)
    return {"heures": heures, "lignes": lignes[:500]}


# -- actions

class Cible(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


class Ip(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(max_length=64)

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))


def _demande_decision(action: str, corps: Cible, payload: Any) -> Dict[str, Any]:
    now = int(time.time())
    db = _db()
    try:
        r = db.execute("SELECT menace, cible, signe FROM decisions WHERE id=? AND etat IN ('active','levee_en_cours')",
                       (corps.id,)).fetchone()
        if not r or r[0] != demandes.MENACE[action]:
            raise HTTPException(404, "décision introuvable ou déjà levée")
        # Pas de nouvelle mesure 7 j pour ce signe sur cet appareil (enregistré dès la demande).
        db.execute("INSERT INTO liberations(mac, signe, jusqua) VALUES (?,?,?) ON CONFLICT(mac, signe) "
                   "DO UPDATE SET jusqua=excluded.jusqua", (r[1], r[2] or "", now + SEPT_JOURS))
        db.commit()
        did = demandes.deposer(db, action, corps.id, _par(payload), now)
    finally:
        db.close()
    _audit(f"{action}-demande", corps.id, _par(payload))
    return {"demande": did, "etat": "en_attente"}


@router.post("/liberer")
def liberer(corps: Cible, payload: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return _demande_decision("liberer", corps, payload)


@router.post("/rouvrir")
def rouvrir(corps: Cible, payload: Any = Depends(require_jwt)) -> Dict[str, Any]:
    return _demande_decision("rouvrir", corps, payload)


@router.post("/debannir")
def debannir(corps: Ip, payload: Any = Depends(require_jwt)) -> Dict[str, Any]:
    db = _db()
    try:
        if not db.execute("SELECT 1 FROM decisions WHERE menace='intrusion' AND etat='active' AND ip=?",
                          (corps.ip,)).fetchone():
            raise HTTPException(404, "aucun ban actif posé par la garde pour cette adresse")
        did = demandes.deposer(db, "debannir", corps.ip, _par(payload), int(time.time()))
    finally:
        db.close()
    _audit("debannir-demande", corps.ip, _par(payload))
    return {"demande": did, "etat": "en_attente"}


class Canal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    canal: Literal["sms", "courriel"]


@router.post("/tester")
def tester(corps: Canal, payload: Any = Depends(require_jwt)) -> Dict[str, Any]:
    db = _db()
    try:
        did = demandes.deposer(db, "tester", corps.canal, _par(payload), int(time.time()))
    finally:
        db.close()
    _audit("tester-demande", corps.canal, _par(payload))
    return {"demande": did, "etat": "en_attente"}


# -- réglages

class Reglages(BaseModel):
    model_config = ConfigDict(extra="forbid")
    automatique: Optional[bool] = None
    courriel: Optional[str] = Field(None, max_length=254)
    sms_utilisateur: Optional[str] = Field(None, max_length=16, pattern=r"^[0-9]{0,16}$")
    sms_bans: Optional[bool] = None

    @field_validator("courriel")
    @classmethod
    def _courriel(cls, v: Optional[str]) -> Optional[str]:
        if v and not RE_COURRIEL.fullmatch(v):
            raise ValueError("courriel invalide")
        return v


def _en_attente_reglages() -> Optional[Dict[str, Any]]:
    try:
        d = json.loads((DEPOT / "reglages.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


@router.get("/reglages")
def lire_reglages(lecteur: Any = Depends(require_lecture)) -> Dict[str, Any]:
    r = base.reglages(REGLAGES)
    if _anonyme(lecteur):
        return {"automatique": r["automatique"], "session_requise": True}
    db = _db()
    try:
        cle = db.execute("SELECT valeur FROM etat_moteur WHERE cle='cle_sms_presente'").fetchone()
    finally:
        db.close()
    return {"automatique": r["automatique"], "courriel": r["courriel"], "sms_utilisateur": r["sms_utilisateur"],
            "sms_bans": r["sms_bans"], "quarantaines_max": r["quarantaines_max"], "rafale_bans": r["rafale_bans"],
            "cle_sms_enregistree": bool(cle and cle[0]), "cle_sms_en_attente": (DEPOT / "cle-sms").exists(),
            "en_attente": _en_attente_reglages()}


@router.post("/reglages")
def ecrire_reglages(corps: Reglages, payload: Any = Depends(require_jwt)) -> Dict[str, Any]:
    nouveau = {k: v for k, v in corps.model_dump().items() if v is not None}
    if not nouveau:
        raise HTTPException(422, "aucun réglage")
    actuel = _en_attente_reglages() or {}
    actuel.update(nouveau)
    _deposer_fichier("reglages.json", json.dumps(actuel, ensure_ascii=False))
    _audit("reglages-demande", ",".join(sorted(nouveau)), _par(payload))
    return {"etat": "en_attente", "en_attente": actuel}


class CleSms(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cle: str = Field(max_length=64)

    @field_validator("cle")
    @classmethod
    def _cle(cls, v: str) -> str:
        if v and not RE_CLE.fullmatch(v):
            raise ValueError("clé : lettres et chiffres seulement")
        return v


@router.post("/cle-sms")
def cle_sms(corps: CleSms, payload: Any = Depends(require_jwt)) -> Dict[str, str]:
    """Dépôt 0600 ; l'aide root du passage la pose dans /etc/secubox/secrets/garde-sms (vide = retirée). Jamais relue."""
    _deposer_fichier("cle-sms", corps.cle)
    _audit("cle-sms-demande", "garde-sms", _par(payload))
    return {"etat": "en_attente"}


app = FastAPI(title="SecuBox Garde", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
