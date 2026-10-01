# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox_core.coffre — le coffre des accès, par PERSONNE (#1562)
CyberMind — https://cybermind.fr

Le coffre des accès délégués (#1288, secubox-webos) était rangé par APPAREIL
(le `sub` du jeton : sbx-…, gk2) : une personne à deux appareils avait deux
coffres vides, alors que l'Identity Manager crée ses comptes par PERSONNE.
La clé devient `p-<user_uuid>` ; webos la calcule à chaque requête, sbxid y
écrit.

SANS MOT DE PASSE POUR LA PERSONNE : le mot de passe de services est tenu par
la machine. L'Identity Manager le pose ici au lieu de l'afficher ; la box s'en
sert pour agir AU NOM de la personne (aperçus, connexion automatique). Aucune
route ne le rend jamais (règle de secubox-webos/api/acces.py).
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Optional


def racine() -> Path:
    # Lu à l'appel : les tests (et un opérateur) déplacent le coffre.
    return Path(os.environ.get("SECUBOX_WEBOS_ACCES", "/etc/secubox/secrets/webos-acces"))


#: Service de l'Identity Manager → service du coffre. PeerTube et BBS n'ont
#: pas d'entrée : le BBS s'ouvre par la session du Hall, PeerTube attend sa
#: connexion automatique (#1562, étape 3).
SERVICE_DU_COMPTE = {"email": "mail", "nextcloud": "nextcloud"}

_UUID = re.compile(r"^[0-9a-f-]{8,40}$")


def cle_personne(user_uuid: str) -> Optional[str]:
    u = str(user_uuid or "").lower()
    return f"p-{u}" if _UUID.match(u) else None


def efface_personne(user_uuid: str) -> bool:
    """Supprime le coffre d'une personne SUPPRIMÉE (#1809) : ses secrets de
    services n'ont plus de porteur. Rien si le coffre n'existe pas."""
    import shutil
    cle = cle_personne(user_uuid)
    if not cle:
        return False
    d = racine() / cle
    if not d.is_dir() or d.is_symlink():
        return False
    shutil.rmtree(d)
    return True


def pose_machine(user_uuid: str, svc: str, compte: str, secret: str) -> bool:
    """Pose l'accès d'une personne à un service, avec le secret tenu par la
    machine. Même format que les accès délégués (svc, qui, compte, secret,
    cree, voie) ; 0700 / 0600, écriture atomique."""
    q = cle_personne(user_uuid)
    if not q or not compte or not secret or not re.fullmatch(r"[a-z0-9_-]{1,32}", svc):
        return False
    d = racine() / q
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    f = d / f"{svc}.json"
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"svc": svc, "qui": q, "compte": compte, "secret": secret,
                               "cree": int(time.time()), "voie": "machine"},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(f)
    return True


def reprend(depuis: str, vers: str) -> int:
    """Reprend dans le coffre d'une personne les accès d'un ancien coffre
    d'appareil (`depuis`), sans écraser ce qu'elle a déjà. Rend le nombre
    d'accès repris. Les fichiers repris sont DÉPLACÉS : un secret n'existe
    qu'à un endroit."""
    a, b = racine() / depuis, racine() / vers
    if depuis == vers or not a.is_dir():
        return 0
    b.mkdir(parents=True, exist_ok=True)
    os.chmod(b, 0o700)
    n = 0
    for f in a.glob("*.json"):
        if f.name.endswith((".flux.json", ".tmp")) or (b / f.name).exists():
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            d["qui"] = vers
            (b / f.name).write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
            os.chmod(b / f.name, 0o600)
            f.unlink()
            n += 1
        except (OSError, ValueError):
            continue
    return n
