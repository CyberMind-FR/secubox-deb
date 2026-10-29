# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: identité d'une box par son adresse dans le tunnel (#3126)

Une box n'a aucun secret à présenter : son identité EST son adresse source dans le tunnel WireGuard (nginx la transmet en `X-Real-IP`).
  - 10.10.0.0/24 (wg-mesh)     → `peers.json` du maillage, `mesh_ip` exacte ;
  - 10.64.0.0/16 (wg-autoload) → projection publique des pairs d'Auto-Load (abonnement `revoque` = inconnue) ;
  - toute autre adresse        → personne.
Fermé par défaut : fichier absent, trop gros, illisible ou de mauvaise forme → aucune box n'est identifiée.
Les fichiers sont relus seulement quand leur date, leur taille ou leur inode change (le résultat est mis en cache, tableau adresse → box).
"""
from __future__ import annotations

import ipaddress
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional

RESEAU_MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
RESEAU_AUTOLOAD = ipaddress.ip_network("10.64.0.0/16")
TAILLE_MAX = 1 << 20  # 1 Mio : au-delà, le fichier est refusé sans être lu
NOM_MAX = 64

PEERS_DEFAUT = Path("/var/lib/secubox/p2p/peers.json")
PAIRS_AUTOLOAD_DEFAUT = Path("/var/lib/secubox/autoload-public/pairs-publics.json")

_cache: dict = {}  # chemin -> (signature, {adresse: Box})


@dataclass(frozen=True)
class Box:
    nom: str
    adresse: str
    reseau: Literal["maillage", "autoload"]
    client: Optional[str]
    abonnement: Optional[str]

    @property
    def cle(self) -> str:
        """Clé unique d'une box : files et tables internes sont indexées par elle, jamais par le nom seul."""
        return f"{self.reseau}:{self.nom}"


def _lire_json(chemin: Path):
    """JSON du fichier, ou None (absent, lien, non régulier, trop gros, illisible). Bornée : jamais plus de TAILLE_MAX + 1 octets lus."""
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > TAILLE_MAX:
            return None
        brut = os.read(fd, TAILLE_MAX + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(brut) > TAILLE_MAX:
        return None
    try:
        return st, json.loads(brut)
    except (ValueError, RecursionError):
        return None


def _signature(chemin: Path):
    try:
        st = os.stat(chemin)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _table(chemin: Path, construire) -> dict:
    """Tableau adresse → Box du fichier, rechargé au changement ; {} (personne) si le fichier est inutilisable."""
    chemin = Path(chemin)
    sig = _signature(chemin)
    if sig is None:
        _cache.pop(chemin, None)
        return {}
    vu = _cache.get(chemin)
    if vu and vu[0] == sig:
        return vu[1]
    lu = _lire_json(chemin)
    table = {}
    if lu is not None:
        try:
            table = construire(lu[1])
        except (TypeError, ValueError, AttributeError):
            table = {}
    _cache[chemin] = (sig, table)
    return table


def _adresse_canonique(adresse) -> Optional[ipaddress.IPv4Address]:
    """Adresse IPv4 sous sa forme exacte (aucun espace, masque, zéro initial ni IPv6) ; sinon None."""
    if not isinstance(adresse, str) or len(adresse) > 15:
        return None
    try:
        ip = ipaddress.IPv4Address(adresse)
    except ValueError:
        return None
    return ip if str(ip) == adresse else None


def _nom_valide(nom) -> Optional[str]:
    if not isinstance(nom, str):
        return None
    nom = nom.strip()
    if not nom or len(nom) > NOM_MAX or not nom.isprintable():
        return None
    return nom


def _table_maillage(doc) -> dict:
    liste = doc.get("peers") if isinstance(doc, dict) else doc
    if not isinstance(liste, list):
        return {}
    out = {}
    for p in liste:
        if not isinstance(p, dict):
            continue
        ip, nom = _adresse_canonique(p.get("mesh_ip")), _nom_valide(p.get("name"))
        if ip is None or nom is None or ip not in RESEAU_MAILLAGE:
            continue
        out[str(ip)] = Box(nom, str(ip), "maillage", None, None)
    return out


def _table_autoload(doc) -> dict:
    liste = doc.get("pairs") if isinstance(doc, dict) else None
    if not isinstance(liste, list):
        return {}
    out = {}
    for p in liste:
        if not isinstance(p, dict):
            continue
        ip = _adresse_canonique(p.get("adresse"))
        client = _nom_valide(p.get("client"))
        abonnement = p.get("abonnement")
        if ip is None or client is None or ip not in RESEAU_AUTOLOAD or not isinstance(abonnement, str):
            continue
        if abonnement == "revoque":
            continue
        serie = _nom_valide(p.get("serie"))
        out[str(ip)] = Box(serie or f"{client}-{ip}", str(ip), "autoload", client, abonnement)
    return out


def box_par_adresse(adresse: str, peers: Path = PEERS_DEFAUT, pairs_autoload: Path = PAIRS_AUTOLOAD_DEFAUT) -> Optional[Box]:
    """La box qui parle depuis cette adresse du tunnel, ou None. Bloquante (petite lecture) : à appeler hors de la boucle (to_thread)."""
    ip = _adresse_canonique(adresse)
    if ip is None:
        return None
    if ip in RESEAU_MAILLAGE:
        return _table(peers, _table_maillage).get(str(ip))
    if ip in RESEAU_AUTOLOAD:
        return _table(pairs_autoload, _table_autoload).get(str(ip))
    return None
