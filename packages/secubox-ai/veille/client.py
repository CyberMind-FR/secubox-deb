# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Client de lecture de gk2 pour la veille V2 (#3720) : GET seulement, signé par le compte `ai-lecture`.

Chaque requête porte un jeton neuf (`secubox_core.compte_service.frapper_jeton`) lié à GET et au chemin EXACT vu par
la route de gk2 (sans chaîne de requête) : le WAF voit `/menaces/flux` (nginx retire `/api/v1/waf`), la garde et
ad-guard voient leur chemin complet. La table nom → (URL relative à `menaces_url`, chemin signé) vient de
`[veille.routes]` d'ai.toml, défauts ci-dessous. `trust_env=False`, délai court (30 s pour `enforcement`, `[veille.delais]`), aucune redirection suivie.
"""
import time
from typing import Any, Callable, Optional

import httpx

from secubox_core.compte_service import frapper_jeton

COMPTE = "ai-lecture"
DELAI_S = 10.0
#: Délais propres à une route (nom de la table) : `enforcement` relit bans.jsonl sur gk2, plusieurs secondes.
#: Surchargeable par `[veille.delais] <nom> = <secondes>`, borné à DELAI_MIN_S..DELAI_MAX_S.
DELAIS_DEFAUT = {"enforcement": 30.0}
DELAI_MIN_S = 1.0
DELAI_MAX_S = 60.0
AGENT = {"User-Agent": "secubox-ai-veille/1", "Accept": "application/json"}
TAILLE_MAX = 8 * 2**20

#: nom → (URL relative à menaces_url, chemin signé).
ROUTES_DEFAUT = {
    "menaces_flux": ("/waf/menaces/flux", "/menaces/flux"),
    "enforcement": ("/waf/enforcement", "/enforcement"),
    "bans": ("/waf/bans", "/bans"),
    "campaigns": ("/waf/campaigns", "/campaigns"),
    "decisions": ("/waf/decisions", "/decisions"),
    "reevaluations": ("/waf/reevaluations", "/reevaluations"),
    "stats": ("/waf/stats", "/stats"),
    "ai_etat": ("/waf/ai/etat", "/ai/etat"),
    "mesures": ("/waf/mesures", "/mesures"),
    "actord": ("/waf/actord/propositions", "/actord/propositions"),
    "garde_etat": ("/garde/etat", "/api/v1/garde/etat"),
    "garde_historique": ("/garde/historique", "/api/v1/garde/historique"),
    # #3720 : security-posture a sa propre socket, nginx retire `/api/v1/security-posture` : la route voit `/overview`.
    "posture_overview": ("/security-posture/overview", "/overview"),
    "dns_alertes": ("/ad-guard/dnsguard/alertes", "/api/v1/ad-guard/dnsguard/alertes"),
}


class ErreurGk2(Exception):
    """Lecture impossible. `code` : statut HTTP (None : réseau, délai, réponse illisible)."""

    def __init__(self, code: Optional[int], motif: str):
        super().__init__(f"{code or 'reseau'} {motif}")
        self.code = code
        self.motif = motif


def routes(cfg: dict) -> dict:
    """Table des routes : défauts recouverts par `[veille.routes] <nom> = { url = "…", signe = "…" }`."""
    table = dict(ROUTES_DEFAUT)
    for nom, r in ((cfg.get("veille") or {}).get("routes") or {}).items():
        if isinstance(r, dict) and isinstance(r.get("url"), str) and isinstance(r.get("signe"), str):
            if r["url"].startswith("/") and r["signe"].startswith("/") and "?" not in r["signe"]:
                table[nom] = (r["url"], r["signe"])
    return table


def delais(cfg: dict) -> dict:
    """Délais par route : défauts recouverts par `[veille.delais]` ; valeur non numérique ignorée, bornée à 1..60 s."""
    table = dict(DELAIS_DEFAUT)
    for nom, v in ((cfg.get("veille") or {}).get("delais") or {}).items():
        if isinstance(v, (int, float)) and not isinstance(v, bool) and v == v:
            table[nom] = min(DELAI_MAX_S, max(DELAI_MIN_S, float(v)))
    return table


class ClientGk2:
    def __init__(self, base: str, aud: str, cle_pem: bytes, table: Optional[dict] = None,
                 transport: Optional[httpx.AsyncBaseTransport] = None, horloge: Callable[[], float] = time.time,
                 delai_s: float = DELAI_S, delais_routes: Optional[dict] = None):
        self.base = base.rstrip("/")
        self.aud = aud
        self._cle = cle_pem
        self.table = table or dict(ROUTES_DEFAUT)
        self._transport = transport
        self.horloge = horloge
        self.delai_s = delai_s
        self.delais_routes = dict(DELAIS_DEFAUT if delais_routes is None else delais_routes)

    async def get(self, nom: str, params: Optional[dict] = None) -> Any:
        url, signe = self.table[nom]
        jeton = frapper_jeton(self._cle, COMPTE, aud=self.aud, corps=b"", maintenant=self.horloge(),
                              methode="GET", chemin=signe)
        entetes = dict(AGENT, Authorization=f"Bearer {jeton}")
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=self.delais_routes.get(nom, self.delai_s), trust_env=False,
                                         follow_redirects=False, headers=entetes) as c:
                r = await c.get(self.base + url, params={k: v for k, v in (params or {}).items() if v is not None})
        except httpx.HTTPError as e:
            raise ErreurGk2(None, e.__class__.__name__) from None
        if r.status_code != 200:
            raise ErreurGk2(r.status_code, "refus" if r.status_code in (401, 403) else "statut")
        if len(r.content) > TAILLE_MAX:
            raise ErreurGk2(None, "trop_gros")
        try:
            return r.json()
        except ValueError:
            raise ErreurGk2(None, "json") from None
