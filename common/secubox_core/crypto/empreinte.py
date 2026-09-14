# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: empreintes courtes et identifiants dérivés.

POURQUOI CE MODULE EXISTE. Une vingtaine d'endroits du produit fabriquaient un
identifiant de la même façon :

    <hachage hérité>(quelque_chose.encode()).hexdigest()[:8]

Aucun n'était une faute de sécurité — ce sont des étiquettes, pas des preuves :
l'identifiant d'un webhook, d'une politique de cookies, d'un pair. MD5 n'y
protège rien, donc ses collisions n'y donnent rien.

Mais c'est un aveu qu'on ne peut pas se permettre. Un évaluateur CSPN qui
cherche le nom de ce hachage dans le dépôt en trouve vingt-trois, et doit alors examiner
vingt-trois cas pour conclure qu'aucun n'est grave. Ce temps-là, il ne le passe
pas sur ce qui compte vraiment, et notre crédit en souffre. Le coût du
remplacement est nul ; celui de l'explication, répété à chaque audit, ne l'est
pas.

D'où UNE fonction, relue une fois, employée partout :

    from secubox_core.crypto.empreinte import ident
    ident(webhook.url)                      # 12 hex, SHA-256 tronqué
    ident(domain, cookie_name, "tracker")   # parties séparées sans ambiguïté

SUR LA TRONCATURE. Tronquer SHA-256 est une pratique normalisée (FIPS 180-4
§7 ; c'est le principe même de SHA-224/384). Pour un identifiant, 48 bits
suffisent largement : il faudrait ~17 millions d'entrées pour avoir une chance
sur deux de collision, là où ces tables en comptent des dizaines.

SUR LA SÉPARATION DES PARTIES. ``ident("ab", "c")`` et ``ident("a", "bc")``
doivent différer. Les concaténer naïvement les rendrait identiques — une
confusion d'identifiants par simple choix de découpage. On insère donc un
séparateur qui ne peut pas apparaître dans une partie textuelle.

CE MODULE NE FAIT PAS DE SÉCURITÉ. Pour authentifier, il faut un HMAC et une
clé ; pour un mot de passe, Argon2id. Une empreinte publique et sans clé ne
prouve rien à personne, et ce module refuse de laisser croire le contraire :
son nom dit « empreinte », jamais « signature » ni « jeton ».
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Union

__all__ = ["ident", "empreinte", "jeton"]

# Octet de séparation. 0x1F est le « unit separator » d'ASCII : il n'apparaît
# ni dans une URL, ni dans un nom de domaine, ni dans un nom de politique.
_SEP = b"\x1f"

_LONGUEUR_MIN = 6          # 24 bits — en deçà, la collision cesse d'être rare
_LONGUEUR_MAX = 64         # SHA-256 complet en hexadécimal


def _octets(partie: Union[str, bytes, int, None]) -> bytes:
    if partie is None:
        return b""
    if isinstance(partie, bytes):
        return partie
    if isinstance(partie, int):
        return str(partie).encode("utf-8")
    return str(partie).encode("utf-8", "replace")


def empreinte(*parties: Union[str, bytes, int, None], domaine: str = "") -> str:
    """SHA-256 complet, en hexadécimal, des ``parties`` séparées sans ambiguïté.

    :param domaine: liaison de domaine facultative. Deux usages différents qui
        dérivent d'une même valeur devraient employer des domaines différents,
        pour que la même entrée ne donne pas le même identifiant partout.
    """
    h = hashlib.sha256()
    if domaine:
        h.update(_octets(domaine))
        h.update(_SEP)
    for i, p in enumerate(parties):
        if i:
            h.update(_SEP)
        h.update(_octets(p))
    return h.hexdigest()


def ident(*parties: Union[str, bytes, int, None], n: int = 12,
          domaine: str = "") -> str:
    """Identifiant court et STABLE, dérivé des ``parties`` — SHA-256 tronqué.

    Stable veut dire : les mêmes entrées donnent toujours le même identifiant,
    y compris après redémarrage ou sur une autre box. C'est ce qui distingue
    cette fonction de :func:`jeton`.

    :param n: longueur en caractères hexadécimaux (défaut 12, soit 48 bits).
    :raises ValueError: si ``n`` sort des bornes — un identifiant de 2
        caractères entrerait en collision presque immédiatement, et mieux vaut
        le refuser à l'appel que le découvrir en production.
    """
    if not _LONGUEUR_MIN <= n <= _LONGUEUR_MAX:
        raise ValueError(
            f"longueur d'identifiant hors bornes : {n} "
            f"(attendu entre {_LONGUEUR_MIN} et {_LONGUEUR_MAX})")
    return empreinte(*parties, domaine=domaine)[:n]


def jeton(n: int = 32) -> str:
    """Valeur IMPRÉVISIBLE, tirée du générateur du système.

    À employer partout où l'identifiant ne doit pas être devinable — une
    référence de session, un lien de partage. :func:`ident` ne convient pas là :
    elle est déterministe, donc reconstructible par qui connaît l'entrée.

    :param n: nombre d'octets d'entropie (défaut 32 = 256 bits).
    """
    if n < 16:
        raise ValueError("un jeton fait au moins 16 octets (128 bits)")
    return secrets.token_hex(n)
