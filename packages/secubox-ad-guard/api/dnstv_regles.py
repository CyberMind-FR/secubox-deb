# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: règles du mode « auto » du POC DNS AdBlock TV (#1954).

Une règle = un domaine pour UN appareil. Cycle : candidat → essai (24 h) → confirmé ; sorties : rejeté, retiré.
Un essai non confirmé EXPIRE en « retiré » : l'automatisme ne fixe jamais rien seul.
Le fichier `regles.json` est écrit par un compte non privilégié et relu par le contrôleur root : tout est revalidé à la lecture,
les liens symboliques sont refusés.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

try:
    from . import dnstv
except ImportError:                                   # lancé hors paquet
    from api import dnstv

ETATS = ("candidat", "essai", "confirme", "rejete", "retire")
TRANSITIONS = {
    "candidat": {"essai", "rejete", "retire"},
    "essai": {"confirme", "retire"},
    "confirme": {"retire"},
    "rejete": {"candidat"},                            # l'administrateur peut rouvrir
    "retire": {"essai", "rejete"},
}
ESSAI_S = 24 * 3600                                    # durée de l'essai
CANDIDAT_S = 14 * 86400                                # un candidat ignoré 14 jours disparaît
HISTORIQUE_MAX = 10
REGLES_MAX = 2000
LECTURE_MAX = 8 * 1024 * 1024       # 2000 règles × (10 entrées d'historique) restent sous ce plafond
PURGE_RETIRE_S = 30 * 86400        # une règle retirée depuis plus de 30 jours est oubliée (les rejetées sont gardées : jamais reproposées)
RISQUES = ("faible", "partage", "variable")
ORIGINES = ("auto", "admin")
FICHIER = "regles.json"


class ErreurRegle(ValueError):
    pass


def slug(nom: str) -> str:
    """Identifiant de vue Unbound pour un appareil : minuscules, tirets ; jamais autre chose que [a-z0-9-]."""
    return dnstv._slug(nom)


def identifiant(appareil: str, domaine: str) -> str:
    return hashlib.sha1(f"{appareil}|{domaine}".encode()).hexdigest()[:12]


def _domaine(brut: str) -> str:
    d = dnstv.valider_domaine(brut) if isinstance(brut, str) and brut == brut.strip() and brut == brut.lower() else None
    if not d:
        raise ErreurRegle("domaine invalide")
    return d


def _appareil(brut: str) -> str:
    if not isinstance(brut, str) or slug(brut) != brut:
        raise ErreurRegle("appareil invalide (identifiant : minuscules, chiffres, tirets)")
    return brut


def valider_regle(b: dict) -> dict:
    if not isinstance(b, dict):
        raise ErreurRegle("règle invalide")
    appareil, domaine = _appareil(b.get("appareil")), _domaine(b.get("domaine"))
    if b.get("etat") not in ETATS:
        raise ErreurRegle("état de règle inconnu")
    risque = b.get("risque", "faible")
    origine = b.get("origine", "auto")
    if risque not in RISQUES or origine not in ORIGINES:
        raise ErreurRegle("risque ou origine inconnu")
    entiers = {}
    for k in ("cree", "maj", "fin_essai", "score"):
        v = b.get(k, 0)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ErreurRegle(f"champ {k} invalide")
        entiers[k] = v
    hist = b.get("historique", [])
    if not isinstance(hist, list):
        raise ErreurRegle("historique invalide")
    propre = []
    for h in hist[-HISTORIQUE_MAX:]:
        if not isinstance(h, dict) or h.get("vers") not in ETATS or not isinstance(h.get("ts"), int):
            raise ErreurRegle("historique invalide")
        propre.append({"ts": h["ts"], "de": h.get("de") if h.get("de") in ETATS else "", "vers": h["vers"],
                       "origine": h.get("origine") if h.get("origine") in ORIGINES else "auto", "motif": str(h.get("motif", ""))[:120]})
    return {"id": identifiant(appareil, domaine), "appareil": appareil, "domaine": domaine, "etat": b["etat"], "origine": origine,
            "risque": risque, "motif": str(b.get("motif", ""))[:120], "historique": propre, **entiers}


class Regles:
    def __init__(self, regles: Optional[List[dict]] = None):
        self._r: Dict[str, dict] = {}
        for x in regles or []:
            v = valider_regle(x)
            self._r[v["id"]] = v
        if len(self._r) > REGLES_MAX:
            raise ErreurRegle("trop de règles")

    @classmethod
    def depuis_dict(cls, brut) -> "Regles":
        if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("regles"), list):
            raise ErreurRegle("fichier de règles illisible")
        return cls(brut["regles"])

    def vers_dict(self) -> dict:
        return {"version": 1, "regles": sorted(self._r.values(), key=lambda x: (x["appareil"], x["domaine"]))}

    def liste(self) -> List[dict]:
        return [dict(x) for x in self.vers_dict()["regles"]]

    def get(self, rid: str) -> dict:
        if rid not in self._r:
            raise ErreurRegle("règle inconnue")
        return dict(self._r[rid])

    def proposer(self, appareil: str, domaine: str, score: int, risque: str, maintenant: int, origine: str = "auto") -> Optional[dict]:
        appareil, domaine = _appareil(appareil), _domaine(domaine)
        rid = identifiant(appareil, domaine)
        if rid in self._r:
            return None                                # déjà connue (y compris rejetée : jamais reproposée)
        if len(self._r) >= REGLES_MAX:
            raise ErreurRegle("trop de règles")
        regle = valider_regle({"appareil": appareil, "domaine": domaine, "etat": "candidat", "origine": origine, "risque": risque,
                               "score": max(0, int(score)), "cree": maintenant, "maj": maintenant, "fin_essai": 0,
                               "historique": [{"ts": maintenant, "de": "", "vers": "candidat", "origine": origine, "motif": "proposé"}]})
        self._r[rid] = regle
        return dict(regle)

    def transiter(self, rid: str, vers: str, origine: str, motif: str, maintenant: int) -> dict:
        r = self._r.get(rid)
        if r is None:
            raise ErreurRegle("règle inconnue")
        if vers not in TRANSITIONS.get(r["etat"], set()):
            raise ErreurRegle(f"transition interdite : {r['etat']} → {vers}")
        if origine not in ORIGINES:
            raise ErreurRegle("origine inconnue")
        r["historique"] = (r["historique"] + [{"ts": maintenant, "de": r["etat"], "vers": vers, "origine": origine, "motif": str(motif)[:120]}])[-HISTORIQUE_MAX:]
        r["etat"], r["maj"], r["motif"] = vers, maintenant, str(motif)[:120]
        r["fin_essai"] = maintenant + ESSAI_S if vers == "essai" else 0
        return dict(r)

    def expirer(self, maintenant: int) -> List[dict]:
        """Essais non confirmés → retirés ; candidats trop anciens → retirés ; règles retirées depuis longtemps → oubliées. Rend les règles changées."""
        out = []
        for rid, r in list(self._r.items()):
            if r["etat"] == "retire" and maintenant - r["maj"] > PURGE_RETIRE_S:
                del self._r[rid]
                continue
            if r["etat"] == "essai" and maintenant > r["fin_essai"]:
                out.append(self.transiter(rid, "retire", "auto", "essai expiré sans confirmation", maintenant))
            elif r["etat"] == "candidat" and maintenant - r["cree"] > CANDIDAT_S:
                out.append(self.transiter(rid, "retire", "auto", "candidat ignoré 14 jours", maintenant))
        return out

    def actives(self, appareil: str) -> List[str]:
        return sorted(r["domaine"] for r in self._r.values() if r["appareil"] == appareil and r["etat"] in ("essai", "confirme"))

    def par_appareil(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for r in self._r.values():
            if r["etat"] in ("essai", "confirme"):
                out.setdefault(r["appareil"], []).append(r["domaine"])
        return {k: sorted(v) for k, v in out.items()}


def charger(dossier: Optional[Path] = None) -> Regles:
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return Regles()
    except OSError as e:
        raise ErreurRegle(f"fichier de règles refusé ({type(e).__name__})") from e
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return Regles.depuis_dict(json.loads(h.read(LECTURE_MAX)))
    except (ValueError, OSError) as e:
        if isinstance(e, ErreurRegle):
            raise
        raise ErreurRegle("fichier de règles illisible") from e


def ecrire(regles: Regles, dossier: Optional[Path] = None) -> None:
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".regles.")
    with os.fdopen(fd, "w", encoding="utf-8") as h:
        json.dump(regles.vers_dict(), h, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, d / FICHIER)


@contextlib.contextmanager
def verrou(dossier: Optional[Path] = None, bloquant: bool = True):
    """Verrou exclusif commun à l'API et au moteur : lecture-modification-écriture de `regles.json` sans écrasement mutuel."""
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd = os.open(d / ".regles.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if bloquant else fcntl.LOCK_NB))
        except BlockingIOError as e:
            raise ErreurRegle("règles verrouillées par un autre traitement") from e
        yield
    finally:
        os.close(fd)
