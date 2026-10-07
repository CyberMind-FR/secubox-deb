# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WAF — les bans sont-ils APPLIQUÉS ? (#1693)
CyberMind — https://cybermind.fr

« 0 ban actif » ne distinguait pas un WAF calme d'un WAF dont les bans ne
s'appliquaient plus : table nft effacée par un rechargement du pare-feu (gk2,
six trous de 6 à 12 h en une semaine), ou sbxwaf en boucle de redémarrage
(gk3, aucun WAF depuis l'installation). Les deux s'affichaient « aucun
bannissement actif ». Ce module tranche, à partir de deux témoins
indépendants : ce que nft répond, et l'état que sbxwaf publie à chaque veille.
"""

import json
from pathlib import Path
from typing import Optional

# sbxwaf réécrit son état toutes les 30 s ; au-delà de ce délai, il ne tourne plus.
PERIME_APRES = 150


def lire_etat(chemin: Path) -> Optional[dict]:
    """État publié par sbxwaf (--nft-etat), ou None s'il est absent/illisible."""
    try:
        d = json.loads(chemin.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def application(etat: Optional[dict], table_absente: bool, maintenant: float) -> dict:
    """Verdict sur l'application des bans.

    etat :
      - « appliquee »     : sbxwaf veille et la table est en place ;
      - « table_absente » : nft ne connaît plus l'ensemble — rien n'est bloqué ;
      - « waf_arrete »    : sbxwaf ne publie plus son état (arrêté ou en boucle) ;
      - « desactive »     : sbxwaf tourne mais n'a pas pu poser son blocage ;
      - « inconnu »       : pas d'état publié (sbxwaf antérieur) et table présente.
    """
    v = {"etat": "inconnu", "ok": True, "detail": ""}
    if isinstance(etat, dict):
        for k in ("reparations", "derniere_reparation", "dernier_ban", "dernier_echec", "echec_a", "verifie"):
            if etat.get(k):
                v[k] = etat[k]
    if table_absente:
        v.update(etat="table_absente", ok=False,
                 detail="la table nft du WAF n'existe pas : aucune adresse n'est bloquée")
        return v
    if etat is None:
        return v
    age = maintenant - float(etat.get("verifie") or 0)
    if age > PERIME_APRES:
        v.update(etat="waf_arrete", ok=False,
                 detail=f"sbxwaf ne veille plus depuis {int(age // 60)} min (arrêté ou en boucle de redémarrage)")
    elif not etat.get("actif"):
        v.update(etat="desactive", ok=False,
                 detail="sbxwaf n'a pas pu poser son blocage nft : " + str(etat.get("dernier_echec") or "cause inconnue"))
    else:
        v.update(etat="appliquee", ok=True)
    return v
