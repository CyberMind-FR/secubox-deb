# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Lignes du journal d'Unbound (`reply:`) → événements ; classement d'un nom par catégorie. Toute valeur hostile est ignorée, jamais levée."""
import ipaddress
import re
from dataclasses import dataclass

from . import domaines

LONGUEUR_MAX = 1000
TYPES = ("A", "AAAA", "HTTPS")
_REPLY = re.compile(r"\[(\d{9,11})\] unbound\[\d+:\d+\] reply: (\S{1,45}) (\S{1,260}) (A|AAAA|HTTPS) IN ([A-Z]{1,12})\b")


@dataclass(frozen=True)
class Evenement:
    ts: int
    client: str
    qname: str
    qtype: str
    rcode: str


def ligne(texte: str) -> Evenement | None:
    if not isinstance(texte, str) or len(texte) > LONGUEUR_MAX:
        return None
    m = _REPLY.search(texte)
    if not m:
        return None
    ts, client, qname, qtype, rcode = m.groups()
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


def classer(qname: str, indexes: dict) -> str | None:
    """Identifiant de la première catégorie (dans l'ordre du dictionnaire) dont l'index contient le nom ou l'un de ses parents."""
    for cat, index in indexes.items():
        if index.contient(qname):
            return cat
    return None
