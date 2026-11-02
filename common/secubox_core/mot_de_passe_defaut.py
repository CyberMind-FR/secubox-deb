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

Bibliothèque stdlib + argon2 seulement : le ctl root (`secubox-sshctl`) l'importe sans FastAPI.
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

log = logging.getLogger("secubox.mot_de_passe_defaut")
_HASHER = PasswordHasher()
_cache: Dict[str, bool] = {}
_verrou = threading.Lock()


def _users_path() -> Path:
    return Path(os.environ.get("SECUBOX_USERS_JSON", "/etc/secubox/users.json"))


def _audit_path() -> Path:
    return Path(os.environ.get("SECUBOX_AUDIT_LOG", "/var/log/secubox/audit.log"))


def _empreinte(compte: str, users: Optional[Path]) -> Optional[str]:
    try:
        doc = json.loads((users or _users_path()).read_text())
    except (OSError, ValueError) as e:
        log.warning("users.json illisible (%s) : verdict « défaut inactif »", e.__class__.__name__)
        return None
    for u in doc.get("users", []) if isinstance(doc, dict) else []:
        if isinstance(u, dict) and u.get("username") == compte:
            h = u.get("password_hash")
            return h if isinstance(h, str) and h else None
    return None


def est_le_defaut(mot_de_passe: str) -> bool:
    """Le clair saisi EST-il le mot de passe par défaut ? Comparaison à temps constant ; rien n'est conservé."""
    return hmac.compare_digest(str(mot_de_passe).encode(), MOT_DE_PASSE_DEFAUT.encode())


def empreinte_est_le_defaut(empreinte: Optional[str]) -> bool:
    if not empreinte:
        return False
    with _verrou:
        if empreinte in _cache:
            return _cache[empreinte]
    try:
        verdict = bool(_HASHER.verify(empreinte, MOT_DE_PASSE_DEFAUT))
    except (VerifyMismatchError, VerificationError, InvalidHash):
        verdict = False
    with _verrou:
        if len(_cache) > 64:
            _cache.clear()
        _cache[empreinte] = verdict
    return verdict


def actif(compte: str = COMPTE, users: Optional[Path] = None) -> bool:
    """Vrai tant que l'empreinte du compte correspond au mot de passe par défaut."""
    return empreinte_est_le_defaut(_empreinte(compte, users))


def etat(compte: str = COMPTE, users: Optional[Path] = None) -> Dict[str, Any]:
    a = actif(compte, users)
    return {"actif": a, "compte": compte, "message": MESSAGE if a else "", "lien": LIEN_CHANGEMENT if a else ""}


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


if __name__ == "__main__":  # `python3 -m secubox_core.mot_de_passe_defaut` : code de sortie 0 = défaut actif
    raise SystemExit(0 if actif() else 1)
