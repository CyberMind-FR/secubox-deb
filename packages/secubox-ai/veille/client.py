# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Client de gk2 pour la veille V2 : lectures (#3720) signées `ai-lecture`, gestes (#3723) signés `ai-ban`.

Chaque requête porte un jeton neuf (`secubox_core.compte_service.frapper_jeton`) lié à GET et au chemin EXACT vu par
la route de gk2 (sans chaîne de requête) : le WAF voit `/menaces/flux` (nginx retire `/api/v1/waf`), la garde et
ad-guard voient leur chemin complet. La table nom → (URL relative à `menaces_url`, chemin signé) vient de
`[veille.routes]` d'ai.toml, défauts ci-dessous. `trust_env=False`, délai court (30 s pour `enforcement`, `[veille.delais]`), aucune redirection suivie.

Gestes (#3723, `post`) : SEULS les noms de `ROUTES_GESTES` (les routes `ai-ban` de gk2, `/api/v1/waf/ai/*`), seul
chemin d'écriture de gk3. Le corps est sérialisé UNE fois (octets exacts) et le jeton du compte `ai-ban` (clé remise
par LoadCredential=, jamais celle de lecture) lie son empreinte SHA-256, l'audience et un `jti` à usage unique ; le
compte `ai-ban` ne lie ni méthode ni chemin (contrainte P9 : chaque corps porte son `geste`). `avant_envoi(jti, kid)`
est attendu AVANT le premier octet envoyé : l'exécuteur y inscrit sa ligne `actions` en état `envoi` ; s'il lève, rien
ne part. TLS vérifié (défaut de httpx), pas de redirection, réponse bornée. Une réponse perdue (délai, coupure,
corps illisible) lève `ErreurGk2(None, …)` : le geste a PEUT-ÊTRE été fait, l'appelant rapproche, jamais ne rejoue.
"""
import json
import re
import time
from typing import Any, Awaitable, Callable, Optional

import httpx
import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secubox_core.compte_service import empreinte, frapper_jeton

COMPTE = "ai-lecture"
COMPTE_GESTES = "ai-ban"
#: Corps d'une réponse à un geste, au plus (gk2 rend quelques centaines d'octets).
TAILLE_MAX_GESTE = 64 * 1024
#: Délai d'un geste : gk2 attend wafctl / waf-blocs jusqu'à 30 s ; au-delà, l'issue est inconnue (rapprochement).
DELAI_GESTE_S = 45.0
_MOTIF = re.compile(r"^[a-z_]{1,32}$")
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
    # #3723 : gestes signés ai-ban (le chemin signé est ignoré : le compte ai-ban ne lie que le corps).
    "ai_ban": ("/waf/ai/ban", "/ai/ban"),
    "ai_unban": ("/waf/ai/unban", "/ai/unban"),
    "ai_prolonger": ("/waf/ai/prolonger", "/ai/prolonger"),
    "ai_limiter": ("/waf/ai/limiter", "/ai/limiter"),
    "ai_leurre": ("/waf/ai/leurre", "/ai/leurre"),
    "ai_partager": ("/waf/ai/partager", "/ai/partager"),
}
#: Les seuls noms que `post` accepte (catalogue fermé des gestes de gk2).
ROUTES_GESTES = frozenset({"ai_ban", "ai_unban", "ai_prolonger", "ai_limiter", "ai_leurre", "ai_partager"})


class ErreurGk2(Exception):
    """Lecture impossible. `code` : statut HTTP (None : réseau, délai, réponse illisible)."""

    def __init__(self, code: Optional[int], motif: str, reponse: Any = None):
        super().__init__(f"{code or 'reseau'} {motif}")
        self.code = code
        self.motif = motif
        self.reponse = reponse            # corps JSON de gk2 (geste refusé), donnée NON FIABLE


def routes(cfg: dict) -> dict:
    """Table des routes : défauts recouverts par `[veille.routes] <nom> = { url = "…", signe = "…" }`."""
    table = dict(ROUTES_DEFAUT)
    for nom, r in ((cfg.get("veille") or {}).get("routes") or {}).items():
        if isinstance(r, dict) and isinstance(r.get("url"), str) and isinstance(r.get("signe"), str):
            if nom in ROUTES_GESTES:
                continue                  # les routes d'écriture ne se redirigent pas par la configuration
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
                 delai_s: float = DELAI_S, delais_routes: Optional[dict] = None, cle_ban: Optional[bytes] = None):
        self.base = base.rstrip("/")
        self.aud = aud
        self._cle = cle_pem
        self._cle_ban = cle_ban
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

    @property
    def peut_agir(self) -> bool:
        """Vrai si la clé du compte `ai-ban` a été remise (sinon aucun geste n'est possible)."""
        return bool(self._cle_ban)

    @property
    def empreinte_ban(self) -> Optional[str]:
        """Empreinte (kid) de la clé ai-ban remise, ou None si elle n'est pas une clé privée Ed25519 lisible. Seule
        l'empreinte se journalise, jamais la clé."""
        if not self._cle_ban:
            return None
        try:
            cle = serialization.load_pem_private_key(self._cle_ban, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return None
        if not isinstance(cle, Ed25519PrivateKey):
            return None
        return empreinte(cle.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))

    async def post(self, nom: str, corps: dict,
                   avant_envoi: Optional[Callable[[str, str], Awaitable[None]]] = None) -> dict:
        """Geste signé `ai-ban` ; rend le corps JSON (objet) d'une réponse 200. Lève ValueError (route hors du
        catalogue, pas de clé), ErreurGk2(code, motif, reponse) pour un refus de gk2, ErreurGk2(None, …) pour une
        réponse perdue ou illisible (issue inconnue : à rapprocher)."""
        if nom not in ROUTES_GESTES:
            raise ValueError(f"route d'écriture inconnue : {nom!r}")
        if not self._cle_ban:
            raise ValueError("clé ai-ban absente")
        url, _ = self.table[nom]
        octets = json.dumps(corps, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        jeton = frapper_jeton(self._cle_ban, COMPTE_GESTES, aud=self.aud, corps=octets, maintenant=self.horloge())
        if avant_envoi is not None:
            jti = jwt.decode(jeton, options={"verify_signature": False})["jti"]
            await avant_envoi(jti, jwt.get_unverified_header(jeton)["kid"])
        entetes = dict(AGENT, Authorization=f"Bearer {jeton}")
        entetes["Content-Type"] = "application/json"
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=DELAI_GESTE_S, trust_env=False,
                                         follow_redirects=False, headers=entetes) as c:
                r = await c.post(self.base + url, content=octets)
        except httpx.HTTPError as e:
            raise ErreurGk2(None, e.__class__.__name__) from None
        if len(r.content) > TAILLE_MAX_GESTE:
            raise ErreurGk2(None if r.status_code == 200 else r.status_code, "trop_gros")
        try:
            reponse = r.json()
        except ValueError:
            reponse = None
        if r.status_code == 200:
            if not isinstance(reponse, dict):
                raise ErreurGk2(None, "reponse_illisible")
            return reponse
        detail = reponse.get("detail") if isinstance(reponse, dict) else None
        motif = detail.get("motif") if isinstance(detail, dict) else None
        if not isinstance(motif, str) or not _MOTIF.fullmatch(motif):
            motif = "refus" if r.status_code in (401, 403) else "statut"
        raise ErreurGk2(r.status_code, motif, reponse)
