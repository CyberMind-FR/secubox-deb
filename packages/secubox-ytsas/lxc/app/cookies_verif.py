# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Validation d'un cookies.txt déposé (#3837).

Un export de cookies fait HORS session (navigateur déconnecté) ou tronqué ne
contient aucun cookie de session Google/YouTube : yt-dlp n'authentifiera alors
rien et les téléchargements protégés échoueront en « auth requise ». On refuse un
tel dépôt au lieu de l'accepter en silence. Ce module ne lit QUE les noms des
cookies (champ 6 du format Netscape), jamais leurs valeurs.
"""

# Cookies de session Google/YouTube : la présence d'au moins un d'entre eux
# signale un export fait en étant connecté.
COOKIES_SESSION = (
    "SID", "HSID", "SSID", "APISID", "SAPISID",
    "__Secure-1PSID", "__Secure-3PSID", "__Secure-1PSIDTS", "__Secure-3PSIDTS",
    "__Secure-1PAPISID", "__Secure-3PAPISID", "LOGIN_INFO",
)


def _domaine_google(dom):
    """Le domaine du cookie est-il un domaine Google/YouTube ?
    (Les noms courts SID/APISID… existent ailleurs : on exige le bon domaine.)"""
    d = dom.lstrip("#").lstrip(".").lower()
    # « #HttpOnly_.youtube.com » → on a déjà retiré le préfixe côté nom ; ici le
    # champ domaine peut porter le préfixe HttpOnly_.
    if d.startswith("httponly_"):
        d = d[len("httponly_"):].lstrip(".")
    return (d == "google.com" or d.endswith(".google.com")
            or d == "youtube.com" or d.endswith(".youtube.com"))


def cookies_session_presents(text):
    """Le texte Netscape contient-il au moins un cookie de session Google/YouTube ?"""
    if not text:
        return False
    for ligne in text.splitlines():
        s = ligne.strip()
        if not s:
            continue
        # Les lignes « #HttpOnly_… » sont des données, pas des commentaires.
        if s.startswith("#") and not s.startswith("#HttpOnly_"):
            continue
        champs = ligne.split("\t")
        if len(champs) < 7:
            champs = ligne.split()
        if len(champs) >= 7 and champs[5] in COOKIES_SESSION and _domaine_google(champs[0]):
            return True
    return False
