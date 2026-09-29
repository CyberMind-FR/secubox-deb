# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WebOS — manifeste de session de SBXOS (#1610).

Ce que la « Mine » décidait dans le navigateur (rôle, LAN, domaine, curation,
Espaces) est décidé ICI, par la box, selon l'appelant :
- rôle : admin seulement pour un administrateur réel (#1581) ; toute autre
  session reconnue = user ; sinon guest. Un appareil n'est jamais admin ;
- lan : verdict de nginx (X-SecuBox-LAN), jamais celui du client ;
- domaine : [global] domain, sinon [api] sso_cookie_domain, sinon l'hôte ;
- un invité ou un client hors LAN ne reçoit que les modules qu'il peut ouvrir,
  sans état : le manifeste public ne livre pas l'inventaire de la box.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional

ESPACES_TOML = Path("/usr/share/secubox/sbxos/espaces.toml")
CURATION = Path("/usr/share/secubox/www/sbxos/mine/curation.json")
# Entrée sans mot de passe des services qui en ont une (#1562).
ENTREE_SSO = {"nextcloud": "/sbx/entrer", "peertube": "/sbx/entrer"}
_HOTE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _lis(espaces: Path, curation: Path) -> tuple[dict, list]:
    with open(espaces, "rb") as f:
        e = tomllib.load(f)
    lieux = json.loads(curation.read_text(encoding="utf-8")).get("lieux", [])
    return e, lieux


def _url(lieu: dict, domaine: str) -> Optional[str]:
    """Réécrit l'hôte de la curation sur le domaine de CETTE box : seul le
    premier label est gardé, et seulement s'il est un nom d'hôte simple."""
    brut = str(lieu.get("url") or "")
    sous = brut.split("://")[-1].split("/")[0].split(".")[0].lower()
    if not domaine or not _HOTE.match(sous):
        return None
    base = f"https://{sous}.{domaine}"
    return base + ENTREE_SSO.get(lieu.get("id", ""), "/")


def construire(role: str, lan: bool, domaine: str,
               espaces: Path = ESPACES_TOML, curation: Path = CURATION) -> Dict[str, Any]:
    e, lieux = _lis(espaces, curation)
    par_id = {l["id"]: l for l in lieux if isinstance(l, dict) and l.get("id")}
    publics = set((e.get("public") or {}).get("modules", []))
    restreint = role == "guest" or not lan
    sortie_espaces = []
    for cle, esp in (e.get("espaces") or {}).items():
        modules = []
        for mid in esp.get("modules", []):
            l = par_id.get(mid)
            if not l:
                continue
            if l.get("lan") and not lan:
                continue                      # module LAN : invisible hors LAN
            if role == "guest" and mid not in publics:
                continue                      # un invité ne voit que le public
            m = {"id": mid, "label": str(l.get("label", mid))[:60],
                 "url": _url(l, domaine), "lan": bool(l.get("lan"))}
            if not restreint:
                m["etat"] = "inconnu"         # registre : voir #1624
            modules.append(m)
        sortie_espaces.append({"id": cle, "nom": esp.get("nom", cle),
                               "guide": esp.get("guide", ""), "modules": modules})
    return {
        "version": 1, "role": role, "lan": lan, "domaine": domaine,
        "espaces": sortie_espaces,
        "ecrans": dict(e.get("ecrans") or {}),
        "capacites": {"zigbee_commande": False, "voix": role != "guest", "diffuser": role != "guest"},
    }


def role_de(request) -> str:
    from secubox_core import auth
    jetons = []
    z = request.headers.get("authorization", "")
    if z.lower().startswith("bearer "):
        jetons.append(z[7:].strip())
    c = request.cookies.get(auth.SESSION_COOKIE)
    if c:
        jetons.append(c)
    for j in jetons:
        p = auth._validate_token(j)
        if p:
            return "admin" if auth.est_admin_reel(p) else "user"
    return "guest"
