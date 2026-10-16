# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: appstore.remote — installation à distance d'un paquet sur un autre nœud du maillage (#2808).

La demande voyage dans la boîte OpenPGP inter-box (#1736) : le démon openpgp vérifie l'expéditeur (clé liée au did dans l'annuaire), le destinataire,
la fraîcheur et le rejeu. Ce module ne signe ni ne vérifie rien lui-même.

RIEN NE S'INSTALLE À LA RÉCEPTION. La demande attend ; l'administrateur de la box CIBLE l'accepte en retapant le nom du paquet (comme le retrait),
puis secubox-appstorectl applique ses propres gardes (liste blanche, paquets protégés). Une réponse revient à l'expéditeur, et seule la cible
de la demande peut y répondre. Fonctions pures : le transport (boîte, envoi, installation) est injecté."""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

OBJET_DEMANDE = "appstore.install"
OBJET_REPONSE = "appstore.install.reponse"
MAX_EN_ATTENTE_PAR_PAIR = 10
MAX_RECUES = 200
MAX_ENVOYEES = 200
MAX_VUS = 2000
MAX_MESSAGE = 300
STATUTS_REPONSE = {"installee", "refusee", "echec"}
_PAQUET = re.compile(r"^secubox-[a-z0-9][a-z0-9.-]{0,62}$")
_ID = re.compile(r"^[0-9a-f]{32}$")


class Refus(Exception):
    def __init__(self, statut: int, detail: str):
        super().__init__(detail)
        self.statut, self.detail = statut, detail


def paquet_valide(p) -> bool:
    return isinstance(p, str) and bool(_PAQUET.match(p))


class Etat:
    """État persistant (JSON, écriture atomique) : messages déjà vus, demandes reçues, demandes envoyées."""

    def __init__(self, chemin: Path):
        self.chemin = Path(chemin)
        try:
            d = json.loads(self.chemin.read_text())
        except (OSError, ValueError):
            d = {}
        self.d = {"vus": list(d.get("vus", [])), "recues": dict(d.get("recues", {})), "envoyees": dict(d.get("envoyees", {}))}

    def sauver(self) -> None:
        self.d["vus"] = self.d["vus"][-MAX_VUS:]
        for cle, n in (("recues", MAX_RECUES), ("envoyees", MAX_ENVOYEES)):
            if len(self.d[cle]) > n:
                gardees = sorted(self.d[cle].values(), key=lambda x: x.get("emis", 0))[-n:]
                self.d[cle] = {x["id"]: x for x in gardees}
        self.chemin.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.chemin.parent, prefix=".remote-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(self.d, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.chemin)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def recues(self) -> List[dict]:
        return sorted(self.d["recues"].values(), key=lambda x: x.get("emis", 0), reverse=True)

    def envoyees(self) -> List[dict]:
        return sorted(self.d["envoyees"].values(), key=lambda x: x.get("emis", 0), reverse=True)


def _json(texte) -> Optional[dict]:
    try:
        v = json.loads(texte)
    except (TypeError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def synchroniser(etat: Etat, lister: Callable[[], List[dict]], lire: Callable[[str], dict]) -> None:
    """Lit (déchiffre) UNIQUEMENT les messages jamais vus ; range demandes et réponses ; le reste est marqué vu."""
    vus = set(etat.d["vus"])
    change = False
    for m in lister():
        ident = m.get("id")
        if not isinstance(ident, str) or ident in vus:
            continue
        msg = lire(ident)
        etat.d["vus"].append(ident); vus.add(ident); change = True
        objet, de, contenu = msg.get("objet"), msg.get("de"), _json(msg.get("contenu"))
        if contenu is None or contenu.get("v") != 1 or not _ID.match(str(contenu.get("id", ""))):
            continue
        if objet == OBJET_DEMANDE and paquet_valide(contenu.get("paquet")):
            en_attente = sum(1 for r in etat.d["recues"].values() if r["de"] == de and r["etat"] == "en_attente")
            if en_attente >= MAX_EN_ATTENTE_PAR_PAIR:
                continue
            etat.d["recues"][ident] = {"id": ident, "demande": contenu["id"], "de": de, "boxname": msg.get("boxname") or "",
                                       "paquet": contenu["paquet"], "emis": int(msg.get("emis") or 0), "etat": "en_attente", "message": ""}
        elif objet == OBJET_REPONSE and contenu.get("statut") in STATUTS_REPONSE:
            env = etat.d["envoyees"].get(contenu["id"])
            # Seule la CIBLE de la demande peut y répondre.
            if env and env["a"] == de and env["etat"] == "envoyee":
                env["etat"] = contenu["statut"]
                env["message"] = str(contenu.get("message", ""))[:MAX_MESSAGE]
    if change:
        etat.sauver()


def demander(etat: Etat, pair: str, paquet: str, envoyer: Callable[[str, str, str], dict]) -> dict:
    if not paquet_valide(paquet):
        raise Refus(400, "nom de paquet invalide")
    did = secrets.token_hex(16)
    r = envoyer(pair, OBJET_DEMANDE, json.dumps({"v": 1, "id": did, "paquet": paquet}))
    etat.d["envoyees"][did] = {"id": did, "a": r["a"], "boxname": r.get("boxname") or "", "paquet": paquet,
                               "emis": int(time.time()), "etat": "envoyee", "message": ""}
    etat.sauver()
    return {"id": did, "a": r["a"], "boxname": r.get("boxname") or ""}


def decider(etat: Etat, ident: str, accepter: bool, confirmer: Optional[str],
            installer: Callable[[str], tuple], repondre: Callable[[str, str, str], object]) -> dict:
    r = etat.d["recues"].get(ident)
    if r is None:
        raise Refus(404, "demande inconnue")
    if r["etat"] != "en_attente":
        raise Refus(409, "demande déjà traitée")
    if accepter:
        if confirmer != r["paquet"]:
            raise Refus(428, f"confirmation requise : retapez le nom du paquet ({r['paquet']})")
        ok, message = installer(r["paquet"])
        r["etat"], r["message"] = ("installee" if ok else "echec"), str(message)[:MAX_MESSAGE]
    else:
        r["etat"], r["message"] = "refusee", ""
    etat.sauver()
    try:
        repondre(r["de"], OBJET_REPONSE, json.dumps({"v": 1, "id": r["demande"], "statut": r["etat"], "message": r["message"]}))
    except Exception as e:  # noqa: BLE001 — la décision est prise ; la réponse est un courtoisie qui peut échouer (pair hors ligne)
        r["reponse_envoyee"] = False
        r["message"] = (r["message"] + f" (réponse non remise : {str(e)[:80]})").strip()
        etat.sauver()
    return r
