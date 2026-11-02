# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: mot de passe par défaut actif ? (#3401)

L'assistant premier-pas laisse choisir « Plus tard » : le compte `admin` garde alors le mot de passe du premier
démarrage. Il reste utilisable, mais ENCADRÉ tant qu'il est actif (connexion web limitée au LAN, SSH par mot de passe
refusé, aucune exposition externe, bandeau rouge). Ce module est l'INDICATEUR UNIQUE que tous ces gardes consultent.

On compare l'empreinte argon2 stockée au mot de passe connu du premier démarrage. Le clair n'est jamais stocké ni
journalisé : seul le verdict (booléen) sort d'ici. Le résultat est mis en cache par empreinte (argon2 coûte cher et le
bandeau interroge souvent) ; un changement de mot de passe change l'empreinte, donc invalide le cache de lui-même.

Bibliothèque stdlib + argon2 seulement : le ctl root la lance comme script (`python3 -I`), sans le paquet ni FastAPI.
État TERNAIRE (#3401, relecture) : « inconnu » compte comme « actif » pour toute garde (jamais fail-open).
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError

#: Le mot de passe livré au premier démarrage (images, users.json initial). Connu de tous : c'est tout le problème.
MOT_DE_PASSE_DEFAUT = "secubox"
COMPTE = "admin"
#: Où mener la personne pour changer le mot de passe (page Utilisateurs : changement du mot de passe admin).
LIEN_CHANGEMENT = "/users/"
MESSAGE = "Mot de passe par défaut actif : changez le mot de passe par défaut du compte admin."
MESSAGE_INCONNU = "État du mot de passe admin inconnu : accès encadré par prudence. Vérifiez le compte admin."

log = logging.getLogger("secubox.mot_de_passe_defaut")
_HASHER = PasswordHasher()
_cache: Dict[str, bool] = {}
_verrou = threading.Lock()


def _users_path() -> Path:
    return Path(os.environ.get("SECUBOX_USERS_JSON", "/etc/secubox/users.json"))


def _audit_path() -> Path:
    return Path(os.environ.get("SECUBOX_AUDIT_LOG", "/var/log/secubox/audit.log"))


ACTIF, INACTIF, INCONNU = "actif", "inactif", "inconnu"
#: Posé par premier-pas quand la personne choisit « Plus tard » (#3401). Seul ce marqueur ouvre une session directe
#: avec le défaut ; un compte « à changer » sans lui garde le changement obligatoire.
MARQUEUR_PLUS_TARD = Path("/etc/secubox/premier-pas-plus-tard")


def marqueur_plus_tard() -> Path:
    return Path(os.environ.get("SECUBOX_PLUS_TARD", str(MARQUEUR_PLUS_TARD)))


def plus_tard_choisi() -> bool:
    return marqueur_plus_tard().is_file()


class _Inconnu(Exception):
    pass


def _empreinte(compte: str, users: Optional[Path]) -> Optional[str]:
    """L'empreinte du compte, None s'il n'a aucun mot de passe. Lève _Inconnu si on ne sait pas lire."""
    try:
        doc = json.loads((users or _users_path()).read_text())
    except (OSError, ValueError) as e:
        raise _Inconnu(f"users.json illisible ({e.__class__.__name__})") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("users"), list):
        raise _Inconnu("users.json : forme inattendue")
    for u in doc["users"]:
        if isinstance(u, dict) and u.get("username") == compte:
            h = u.get("password_hash")
            return h if isinstance(h, str) and h else None
    raise _Inconnu(f"compte {compte} absent")


def est_le_defaut(mot_de_passe: str) -> bool:
    """Le clair saisi EST-il le mot de passe par défaut ? Comparaison à temps constant ; rien n'est conservé."""
    return hmac.compare_digest(str(mot_de_passe).encode(), MOT_DE_PASSE_DEFAUT.encode())


def _verdict_empreinte(empreinte: str) -> str:
    with _verrou:
        if empreinte in _cache:
            return _cache[empreinte]
    try:
        v = ACTIF if _HASHER.verify(empreinte, MOT_DE_PASSE_DEFAUT) else INACTIF
    except VerifyMismatchError:
        v = INACTIF
    except (VerificationError, InvalidHash):
        return INCONNU            # empreinte qu'on ne sait pas lire : pas mise en cache
    with _verrou:
        if len(_cache) > 64:
            _cache.clear()
        _cache[empreinte] = v
    return v


def verdict(compte: str = COMPTE, users: Optional[Path] = None) -> str:
    """TERNAIRE : « actif », « inactif » ou « inconnu » (fichier illisible, JSON corrompu, compte absent, erreur)."""
    try:
        h = _empreinte(compte, users)
        return INACTIF if h is None else _verdict_empreinte(h)
    except _Inconnu as e:
        log.warning("mot de passe par défaut : état inconnu (%s), garde maintenue", e)
        return INCONNU
    except Exception as e:  # noqa: BLE001 — toute surprise = inconnu, donc garde maintenue (jamais fail-open)
        log.warning("mot de passe par défaut : état inconnu (%s), garde maintenue", e.__class__.__name__)
        return INCONNU


def garde_requise(compte: str = COMPTE, users: Optional[Path] = None) -> bool:
    """Les gardes (SSH, exposition, connexion) s'appliquent tant que le défaut n'est pas PROUVÉ changé."""
    return verdict(compte, users) != INACTIF


def etat(compte: str = COMPTE, users: Optional[Path] = None) -> Dict[str, Any]:
    v = verdict(compte, users)
    msg = {ACTIF: MESSAGE, INCONNU: MESSAGE_INCONNU}.get(v, "")
    return {"etat": v, "actif": v == ACTIF, "inconnu": v == INCONNU, "compte": compte, "message": msg,
            "lien": LIEN_CHANGEMENT if msg else ""}


def refus_exposition(action: str, acteur: str = "?") -> Optional[str]:
    """Point de garde commun des chemins d'exposition : le message de refus (audité), ou None si permis."""
    if not garde_requise():
        return None
    audit("exposition_refusee", {"action": str(action)[:128], "acteur": str(acteur)[:64]})
    return "Exposition externe refusée : " + MESSAGE


def audit(evenement: str, details: Optional[Dict[str, Any]] = None, chemin: Optional[Path] = None) -> None:
    """Une ligne JSON en ajout seul dans /var/log/secubox/audit.log. Jamais de mot de passe dans `details`."""
    entree = {"ts": datetime.now(timezone.utc).isoformat(), "type": "mot_de_passe_defaut", "evenement": evenement,
              **(details or {})}
    ligne = json.dumps(entree, ensure_ascii=True)
    try:
        fd = os.open(chemin or _audit_path(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
        try:
            os.write(fd, (ligne + "\n").encode())
        finally:
            os.close(fd)
    except OSError as e:
        # Un audit qui ne s'écrit pas ne passe pas en silence : il reste au journal du service.
        log.warning("audit.log non écrit (%s) : %s", e.__class__.__name__, ligne)


#: Codes de sortie du point d'entrée CLI (le ctl root le lance en `cd / && python3 -I <ce fichier>`, sans importer
#: le paquet secubox_core ni FastAPI). Tout autre code (exception, argon2 absent…) = inconnu : garde maintenue.
SORTIE = {ACTIF: 0, INACTIF: 10, INCONNU: 2}

if __name__ == "__main__":
    raise SystemExit(SORTIE[verdict()])
