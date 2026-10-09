# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload-agent :: le CLIENT de l'infrastructure (#2187, #2188, #2189)

  enroler()   HTTPS public (certificat VÉRIFIÉ, nom d'hôte seulement, jamais de redirection suivie) : POST /api/v1/autoload/enrol
  tunnel      HTTP dans WireGuard, vers le hub 10.64.0.1:8470 UNIQUEMENT : pré-rapport, progression, sondage du refus

Un refus de l'infrastructure (403, 429) est un EnrolementRefuse ; une panne (5xx, réseau, délai) est une OSError, réessayable : le parcours reprend.
Toute réponse est bornée (64 Kio) et validée avant d'être rendue.
"""
from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from typing import Dict, Optional

from .moteur import EnrolementRefuse

BASE_TUNNEL = "http://10.64.0.1:8470"
REPONSE_MAX = 64 * 1024
TIMEOUT_S = 20
_HOTE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMPREINTE = re.compile(r"^[0-9a-f]{64}$")


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def ouvreur_sans_redirection() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_SansRedirection)


class ClientInfra:
    def __init__(self, ouvrir=None, base_tunnel: str = BASE_TUNNEL, timeout: int = TIMEOUT_S):
        self._ouvrir = ouvrir or ouvreur_sans_redirection().open
        self.base_tunnel, self.timeout = base_tunnel, timeout

    def _appel(self, requete: urllib.request.Request, contexte: Optional[ssl.SSLContext] = None) -> Dict:
        try:
            kw = {"timeout": self.timeout}
            if contexte is not None:
                kw["context"] = contexte
            with self._ouvrir(requete, **kw) as r:
                brut = r.read(REPONSE_MAX + 1)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                raise EnrolementRefuse("refusé par l'infrastructure") from None
            raise OSError(f"infrastructure : HTTP {e.code}") from None
        except urllib.error.URLError as e:
            raise OSError(f"infrastructure injoignable : {e.reason}") from None
        if len(brut) > REPONSE_MAX:
            raise ValueError("réponse trop grosse")
        try:
            obj = json.loads(brut.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ValueError("réponse illisible") from None
        if not isinstance(obj, dict):
            raise ValueError("réponse inattendue")
        return obj

    # ── public : l'enrôlement ────────────────────────────────────────────────────────────────────────────────
    def enroler(self, jeton: Optional[str], serie: Optional[str], cle_pub: str, infra: str) -> Dict:
        if not isinstance(infra, str) or not _HOTE.match(infra):
            raise ValueError("infra : un nom de domaine seulement")
        corps = {"cle_pub": cle_pub}
        corps["jeton" if jeton is not None else "serie"] = jeton if jeton is not None else serie
        requete = urllib.request.Request(f"https://{infra}/api/v1/autoload/enrol", data=json.dumps(corps).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
        contexte = ssl.create_default_context()                                     # certificat et nom d'hôte vérifiés, jamais d'exception
        rep = self._appel(requete, contexte)
        if not isinstance(rep.get("tunnel"), dict) or not isinstance(rep.get("client"), str) or not isinstance(rep.get("profil"), str):
            raise ValueError("réponse d'enrôlement incomplète")
        return rep

    # ── tunnel : le hub, et lui seul ─────────────────────────────────────────────────────────────────────────
    def _tunnel(self, methode: str, chemin: str, corps: Optional[Dict] = None) -> Dict:
        data = json.dumps(corps).encode("utf-8") if corps is not None else None
        requete = urllib.request.Request(self.base_tunnel + chemin, data=data, headers={"Content-Type": "application/json"} if data else {}, method=methode)
        return self._appel(requete)

    def publier(self, pre_rapport: Dict) -> None:
        self._tunnel("POST", "/prerapport", pre_rapport)

    def progression(self, etape: str, faites: int, total: int, termine: bool = False) -> None:
        self._tunnel("POST", "/progression", {"etape": etape, "faites": faites, "total": total, "termine": termine})

    def refuse(self, empreinte: str) -> bool:
        if not isinstance(empreinte, str) or not _EMPREINTE.match(empreinte):
            raise ValueError("empreinte : 64 caractères hexadécimaux")
        return bool(self._tunnel("GET", f"/prerapport/{empreinte}/refus").get("refuse"))
