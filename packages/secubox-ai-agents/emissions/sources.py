# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Lecture SEULE des dossiers de gk2 (#4058, Task 6).

Deux GET, rien d'autre : `GET {base}/rapports` (liste des sujets) et `GET {base}/rapports/{genre}/{ident}` (dossier,
lecture par règles, lecture IA vérifiée). La base est le tunnel existant vers l'API WAF de gk2 ; le jeton de lecture
dédié vit dans `~/.config/secubox-ai-jeton/lecture-gk2` (0600). Aucune méthode d'écriture : la rédaction de gk2
(`POST …/rediger`) n'est jamais appelée d'ici.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

GENRES = ("campagne", "acteur")
_IDENT = re.compile(r"^[A-Za-z0-9_:.-]{1,80}$")           # même motif que `_RAPPORT_ID` côté gk2
JETON_DEFAUT = Path.home() / ".config/secubox-ai-jeton/lecture-gk2"
DELAI_S = 30.0


def jeton_fichier(chemin: Path = JETON_DEFAUT) -> Callable[[], str]:
    """Lecteur du jeton : relu à chaque appel (rotation sans redémarrage), refusé s'il est lisible par d'autres."""
    def lire() -> str:
        st = os.stat(chemin)
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise PermissionError(f"{chemin} doit être en 0600")
        return Path(chemin).read_text(encoding="ascii").strip()
    return lire


class Sources:
    def __init__(self, base: str, jeton: Callable[[], str], client: Optional[httpx.AsyncClient] = None) -> None:
        self.base = base.rstrip("/")
        self._jeton = jeton
        self._client = client

    async def _get(self, chemin: str) -> Dict[str, Any]:
        entetes = {"Authorization": f"Bearer {self._jeton()}", "Accept": "application/json"}
        if self._client is not None:
            r = await self._client.get(self.base + chemin, headers=entetes, timeout=DELAI_S)
        else:
            async with httpx.AsyncClient(trust_env=False) as c:
                r = await c.get(self.base + chemin, headers=entetes, timeout=DELAI_S)
        r.raise_for_status()
        d = r.json()
        if not isinstance(d, dict):
            raise ValueError("réponse de gk2 inattendue (objet JSON attendu)")
        return d

    async def lister(self) -> List[Dict[str, Any]]:
        """Les sujets qui ont un rapport (`sujets` de `GET /rapports`) ; vide si gk2 n'a pas encore de relevé."""
        d = await self._get("/rapports")
        return [s for s in d.get("sujets") or [] if isinstance(s, dict)] if d.get("disponible") else []

    async def dossier(self, genre: str, ident: str) -> Dict[str, Any]:
        if genre not in GENRES:
            raise ValueError(f"genre refusé : {genre!r}")
        if not isinstance(ident, str) or not _IDENT.match(ident) or ".." in ident:
            raise ValueError("identifiant refusé")
        return await self._get(f"/rapports/{genre}/{ident}")
