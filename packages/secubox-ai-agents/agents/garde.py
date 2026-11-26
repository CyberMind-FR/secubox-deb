# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Garde des routes de secubox-ai-agents (#3986). N'importe PAS OpenJarvis.

Deux modes, choisis par `SECUBOX_AI_AGENTS_GARDE` :

- `secubox` (défaut, sûr) : `secubox_core.auth.require_jwt` — administrateur réel de la box. C'est le mode
  d'une box (gk3, tranche E) ;
- `jeton-local` : réservé au poste gk0 (POC), qui n'a pas de magasin d'utilisateurs SecuBox lisible par le
  service. Un jeton aléatoire dans un fichier 0600 du compte du service (`SECUBOX_AI_AGENTS_JETON`) ; seul le
  relais local du POC le lit et le pose. Le socket Unix reste 0600 : personne d'autre n'y parle.

Une valeur inconnue fait échouer le démarrage (jamais de repli silencieux vers « ouvert »).
"""
from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path
from typing import Any, Callable, Dict

from fastapi import Depends, HTTPException, Request, status

MODES = ("secubox", "jeton-local")


def mode() -> str:
    m = os.environ.get("SECUBOX_AI_AGENTS_GARDE", "secubox")
    if m not in MODES:
        raise RuntimeError(f"SECUBOX_AI_AGENTS_GARDE inconnu : {m!r} (attendu : {', '.join(MODES)})")
    return m


def lire_jeton(chemin: str | os.PathLike) -> str:
    """Lit le jeton local ; refuse un fichier lisible par d'autres, un lien, ou un jeton trop court."""
    p = Path(chemin)
    st = os.lstat(p)
    if not stat.S_ISREG(st.st_mode):
        raise RuntimeError("jeton local : fichier ordinaire requis")
    if st.st_mode & 0o077:
        raise RuntimeError("jeton local : droits trop larges (0600 requis)")
    if st.st_uid != os.getuid():
        raise RuntimeError("jeton local : propriétaire différent du service")
    jeton = p.read_text(encoding="utf-8").strip()
    if len(jeton) < 32:
        raise RuntimeError("jeton local : 32 caractères au moins")
    return jeton


def _garde_jeton_local() -> Callable[..., Dict[str, Any]]:
    chemin = os.environ.get("SECUBOX_AI_AGENTS_JETON", "")
    if not chemin:
        raise RuntimeError("mode jeton-local sans SECUBOX_AI_AGENTS_JETON")
    attendu = lire_jeton(chemin).encode()

    async def garde(request: Request) -> Dict[str, Any]:
        entete = request.headers.get("authorization", "")
        schema, _, jeton = entete.partition(" ")
        if schema.lower() != "bearer" or not hmac.compare_digest(jeton.strip().encode(), attendu):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "jeton requis",
                                headers={"WWW-Authenticate": "Bearer"})
        return {"sub": "proprietaire-gk0", "garde": "jeton-local"}

    return garde


def construire() -> Callable[..., Any]:
    """La dépendance FastAPI à poser sur chaque route (sauf /health)."""
    if mode() == "secubox":
        from secubox_core.auth import require_jwt  # importé seulement dans ce mode

        return require_jwt
    return _garde_jeton_local()


def dependance() -> Any:
    return Depends(construire())
