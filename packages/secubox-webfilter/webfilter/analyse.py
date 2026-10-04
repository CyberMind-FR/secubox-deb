# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Lignes du journal d'Unbound (`reply:`) → événements ; classement d'un nom par catégorie. Toute valeur hostile est ignorée, jamais levée."""
import ipaddress
import re
import time
from dataclasses import dataclass

from . import domaines

LONGUEUR_MAX = 1000
TYPES = ("A", "AAAA", "HTTPS")
_REPLY = re.compile(r"\breply: (\S{1,45}) (\S{1,260}) (A|AAAA|HTTPS) IN ([A-Z]{1,12})\b")
_TS_DEBUT = re.compile(r"^(\d{9,11})(?:\.\d+)?\s")                  # `journalctl -o short-unix` : « 1791096961.220283 hôte unbound[pid]: … »
_TS_CROCHET = re.compile(r"\[(\d{9,11})\] unbound\[")               # sortie propre d'Unbound : « [epoch] unbound[pid:tid] reply: … »


@dataclass(frozen=True)
class Evenement:
    ts: int
    client: str
    qname: str
    qtype: str
    rcode: str


def ligne(texte: str, maintenant=time.time) -> Evenement | None:
    """Une ligne `reply:` d'Unbound. L'horodatage vient de la ligne (short-unix ou [epoch]) ; sans lui (`journalctl -o cat`), de `maintenant`."""
    if not isinstance(texte, str) or len(texte) > LONGUEUR_MAX:
        return None
    m = _REPLY.search(texte)
    if not m:
        return None
    client, qname, qtype, rcode = m.groups()
    t = _TS_DEBUT.match(texte) or _TS_CROCHET.search(texte)
    ts = t.group(1) if t else str(int(maintenant()))
    if "%" in client:
        return None
    try:
        client = str(ipaddress.ip_address(client))
    except ValueError:
        return None
    nom = domaines.valider(qname)
    if nom is None:
        return None
    return Evenement(int(ts), client, nom, qtype, rcode)


def classer(qname: str, indexes: dict) -> tuple | None:
    """(catégorie, entrée de liste) de la première catégorie (dans l'ordre du dictionnaire) dont l'index contient le nom ou l'un de ses parents."""
    for cat, index in indexes.items():
        entree = index.correspondance(qname)
        if entree:
            return cat, entree
    return None
