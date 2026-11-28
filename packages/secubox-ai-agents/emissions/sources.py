# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Lecture SEULE des dossiers de gk2 (#4058, Task 6).

Deux GET, rien d'autre : `GET {base}/rapports` (liste des sujets) et `GET {base}/rapports/{genre}/{ident}` (dossier,
lecture par règles, lecture IA vérifiée). Aucune méthode d'écriture : la rédaction de gk2 (`POST …/rediger`) n'est
jamais appelée d'ici.

Garde de gk2 (#4063) : `require_lecture_ou_compte("ai-lecture")`. Chaque GET porte donc un jeton NEUF du compte de
service `ai-lecture` (#3720), frappé par `secubox_core.compte_service.frapper_jeton` (le code de gk2, pas une copie) :
EdDSA, `kid` = SHA-256 du DER SPKI, `sub` ai-lecture, portée waf-lecture, `aud` = nom de la box gk2 (`gk2_aud`,
défaut « gk2 », comme `AUD_GK2` du relais), `jti` à usage unique, 30 s, `corps` = SHA-256 de b"", `methode` GET et
`chemin` = le chemin EXACT vu par la route du WAF (nginx retire `/api/v1/waf` : `/rapports`, `/rapports/<genre>/<id>`,
comme `ROUTES_DEFAUT` de secubox-ai/veille/client.py). Clé PRIVÉE Ed25519 propre à gk0 :
`~/.config/secubox-ai-jeton/ai-lecture.key`, 0600 et au compte courant, refusée sinon, relue à chaque requête
(rotation sans redémarrage). Clé publique déposée sur gk2 par root (`secubox-ai-emissions-cle`).
"""
from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from secubox_core.compte_service import frapper_jeton

GENRES = ("campagne", "acteur")
_IDENT = re.compile(r"^[A-Za-z0-9_:.-]{1,80}$")           # même motif que `_RAPPORT_ID` côté gk2
DELAI_S = 30.0
COMPTE = "ai-lecture"
CLE_DEFAUT = Path.home() / ".config/secubox-ai-jeton/ai-lecture.key"
AUD_DEFAUT = "gk2"
_TAILLE_MAX_CLE = 4096


def jeton_fichier(chemin: Path) -> Callable[[], str]:
    """Lecteur d'un jeton fixe (billets ; plus gk2 depuis #4063) : relu à chaque appel (rotation sans redémarrage), refusé s'il est lisible par d'autres."""
    def lire() -> str:
        st = os.stat(chemin)
        if stat.S_IMODE(st.st_mode) & 0o077:
            raise PermissionError(f"{chemin} doit être en 0600")
        return Path(chemin).read_text(encoding="ascii").strip()
    return lire


def lire_cle(chemin: Path = CLE_DEFAUT) -> bytes:
    """La clé privée PEM : fichier ordinaire (lien refusé), au compte courant, sans aucun droit pour le groupe ni les
    autres. Lève PermissionError sinon, OSError si absente."""
    fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise PermissionError(f"{chemin} : fichier ordinaire, au compte courant, en 0600 attendu")
        if st.st_size > _TAILLE_MAX_CLE:
            raise PermissionError(f"{chemin} : trop grande pour une clé Ed25519")
        return os.read(fd, _TAILLE_MAX_CLE)
    finally:
        os.close(fd)


def jeton_ai_lecture(aud: str = AUD_DEFAUT, cle: Callable[[], bytes] = lire_cle,
                     horloge: Callable[[], float] = time.time) -> Callable[[str], str]:
    """Frappeur : `chemin signé → jeton` d'UN GET (clé relue à chaque appel)."""
    if not isinstance(aud, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", aud):
        raise ValueError(f"audience refusée : {aud!r}")

    def frapper(chemin: str) -> str:
        return frapper_jeton(cle(), COMPTE, aud=aud, corps=b"", maintenant=horloge(), methode="GET", chemin=chemin)
    return frapper


class Sources:
    def __init__(self, base: str, jeton: Callable[[str], str], client: Optional[httpx.AsyncClient] = None) -> None:
        """`jeton(chemin)` frappe le jeton du GET de `base + chemin` ; `chemin` est celui que voit la route du WAF."""
        self.base = base.rstrip("/")
        self._jeton = jeton
        self._client = client

    async def _get(self, chemin: str) -> Dict[str, Any]:
        entetes = {"Authorization": f"Bearer {self._jeton(chemin)}", "Accept": "application/json"}
        if self._client is not None:
            r = await self._client.get(self.base + chemin, headers=entetes, timeout=DELAI_S)
        else:
            async with httpx.AsyncClient(trust_env=False, follow_redirects=False) as c:
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
