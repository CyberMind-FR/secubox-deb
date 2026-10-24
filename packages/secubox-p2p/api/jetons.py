# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Jetons de jonction du maître (#3100) : cœur partagé par l'API et la CLI `sbx-mesh-invite`.

Le jeton (64 hexadécimaux, le format qu'exige automesh) n'est JAMAIS stocké : seule son empreinte SHA-256 l'est.
Un jeton `flash` ne vaut que pour `nom_prevu` : il autorise le remplacement de la clé d'un pair de ce nom (reflash)."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional

DEFAUT_DOSSIER = "/var/lib/secubox/p2p"
DEFAUT_TTL = 3600


def dossier_p2p() -> str:
    """Dossier d'état du module (surchargeable par SBX_P2P_DIR pour les tests)."""
    return os.environ.get("SBX_P2P_DIR") or DEFAUT_DOSSIER


def chemin_jetons() -> str:
    return os.path.join(dossier_p2p(), "master-link", "tokens.json")


def empreinte(jeton: str) -> str:
    return hashlib.sha256(jeton.encode()).hexdigest()


def lire(chemin: Optional[str] = None) -> List[Dict]:
    try:
        with open(chemin or chemin_jetons(), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return []
    return d if isinstance(d, list) else []


def ecrire(jetons: List[Dict], chemin: Optional[str] = None) -> None:
    """Écriture atomique (0600) ; le propriétaire reste à la charge de l'appelant."""
    chemin = str(chemin or chemin_jetons())
    dossier = os.path.dirname(chemin) or "."
    os.makedirs(dossier, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix=".tokens-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(jetons, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def generer(ttl: int, auto_approve: bool, nom_prevu: Optional[str] = None, flash: bool = False,
            token_type: str = "join", chemin: Optional[str] = None) -> Dict:
    """Fabrique et persiste un jeton ; rend le jeton en clair (une seule fois) et son empreinte."""
    jeton = secrets.token_hex(32)
    h = empreinte(jeton)
    maintenant = datetime.utcnow()
    expire = maintenant + timedelta(seconds=ttl)
    entree = {
        "hash": h, "type": token_type,
        "created": maintenant.isoformat(), "expires": expire.isoformat(),
        "expires_ts": int(expire.timestamp()), "ttl": ttl,
        "status": "active", "auto_approve": auto_approve,
        "peer_fp": None, "used_by": None,
        "nom_prevu": nom_prevu, "flash": bool(flash),
    }
    jetons = lire(chemin)
    jetons.append(entree)
    ecrire(jetons, chemin)
    return {"token": jeton, "token_hash": h, "expires": expire.isoformat(), "ttl": ttl,
            "auto_approve": auto_approve, "nom_prevu": nom_prevu, "flash": bool(flash)}
