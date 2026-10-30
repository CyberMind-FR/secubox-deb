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
import logging
import os
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Optional

RESEAU_MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
RESEAU_AUTOLOAD = ipaddress.ip_network("10.64.0.0/16")
TAILLE_MAX = 1 << 20  # 1 Mio : au-delà, le fichier est refusé sans être lu
NOM_MAX = 64
ABONNEMENTS = ("actif", "suspendu", "echu", "revoque")

PEERS_DEFAUT = Path("/var/lib/secubox/p2p/peers.json")
PAIRS_AUTOLOAD_DEFAUT = Path("/var/lib/secubox/autoload-public/pairs-publics.json")

log = logging.getLogger("pilotage.identite")
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


def _json_borne(fd: int, taille: int):
    """JSON du descripteur, ou None (trop gros, illisible). Jamais plus de TAILLE_MAX + 1 octets lus."""
    if taille > TAILLE_MAX:
        return None
    brut = os.read(fd, TAILLE_MAX + 1)
    if len(brut) > TAILLE_MAX:
        return None
    try:
        return json.loads(brut)
    except (ValueError, RecursionError):
        return None


def _table(chemin: Path, construire) -> dict:
    """Tableau adresse → Box du fichier, rechargé au changement ; {} (personne) si le fichier est inutilisable.
    La signature du cache vient du descripteur effectivement lu (fstat) ; lien et fichier non régulier sont refusés."""
    chemin = Path(chemin)
    try:
        fd = os.open(chemin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        _cache.pop(chemin, None)
        return {}
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            _cache.pop(chemin, None)
            return {}
        sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        vu = _cache.get(chemin)
        if vu and vu[0] == sig:
            return vu[1]
        doc = _json_borne(fd, st.st_size)
    except OSError:
        _cache.pop(chemin, None)
        return {}
    finally:
        os.close(fd)
    table = {}
    if doc is not None:
        try:
            table = _sans_ambiguite(construire(doc), chemin)
        except (TypeError, ValueError, AttributeError):
            table = {}
    _cache[chemin] = (sig, table)
    return table


def _sans_ambiguite(entrees: list, chemin: Path) -> dict:
    """R18, fermé par défaut : une adresse portée par des entrées divergentes, ou une clé de box portée par plusieurs adresses, est écartée
    (ces box ne sont pas identifiées). Les entrées révoquées ne sont jamais servies mais bloquent leur adresse. Une ligne de journal par rechargement."""
    par_adresse: dict = {}
    for ip, box in entrees:
        par_adresse.setdefault(ip, []).append(box)
    ecartees = {ip for ip, liste in par_adresse.items() if len(set(liste)) > 1}
    par_cle: dict = {}
    for ip, liste in par_adresse.items():
        if ip not in ecartees and liste[0].abonnement != "revoque":
            par_cle.setdefault(liste[0].cle, set()).add(ip)
    for ips in par_cle.values():
        if len(ips) > 1:
            ecartees |= ips
    if ecartees:
        log.warning("%s : %d adresse(s) écartée(s) (entrées divergentes ou nom en double) : %s",
                    chemin, len(ecartees), ", ".join(sorted(ecartees)[:20]))
    return {ip: liste[0] for ip, liste in par_adresse.items() if ip not in ecartees and liste[0].abonnement != "revoque"}


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


def _hote(ip, reseau) -> bool:
    """Adresse d'une box : dans le réseau, ni réseau, ni diffusion, ni première adresse (le maître)."""
    return ip in reseau and ip not in (reseau.network_address, reseau.broadcast_address, reseau.network_address + 1)


def _table_maillage(doc) -> list:
    """Entrées enrôlées seulement : peers.json reçoit aussi des découvertes mDNS non authentifiées (sans fingerprint ni joined_via)."""
    liste = doc.get("peers") if isinstance(doc, dict) else doc
    if not isinstance(liste, list):
        return []
    out = []
    for p in liste:
        if not isinstance(p, dict):
            continue
        ip, nom = _adresse_canonique(p.get("mesh_ip")), _nom_valide(p.get("name"))
        if ip is None or nom is None or not _hote(ip, RESEAU_MAILLAGE):
            continue
        if not all(isinstance(p.get(c), str) and p.get(c).strip() for c in ("fingerprint", "joined_via")):
            continue
        out.append((str(ip), Box(nom, str(ip), "maillage", None, None)))
    return out


def _table_autoload(doc) -> list:
    liste = doc.get("pairs") if isinstance(doc, dict) else None
    if not isinstance(liste, list):
        return []
    out = []
    for p in liste:
        if not isinstance(p, dict):
            continue
        ip = _adresse_canonique(p.get("adresse"))
        client = _nom_valide(p.get("client"))
        if ip is None or not _hote(ip, RESEAU_AUTOLOAD):
            continue
        if client is None:  # client illisible : jamais servie, mais l'adresse reste bloquée (une révocation ne se perd pas)
            out.append((str(ip), Box(f"?-{ip}", str(ip), "autoload", None, "revoque")))
            continue
        abonnement = p.get("abonnement")
        if abonnement not in ABONNEMENTS:  # inconnu : traité comme révoqué (bloque l'adresse)
            abonnement = "revoque"
        serie = _nom_valide(p.get("serie"))
        out.append((str(ip), Box(serie or f"{client}-{ip}", str(ip), "autoload", client, abonnement)))
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


def noms_du_maillage(peers: Path = PEERS_DEFAUT, hote: Callable[[], str] = socket.gethostname) -> set:
    """Noms portés au maillage, pour refuser un renommage vers un nom pris (L2 tâche 6) : pairs ENRÔLÉS de peers.json (même ceux que
    l'identité écarte pour ambiguïté : leur nom reste pris ; jamais une découverte mDNS non authentifiée, qui bloquerait un nom à
    distance) et le nom du maître. Fichier inutilisable → le nom du maître seul. Bloquante : hors de la boucle (to_thread)."""
    noms = set()
    try:
        fd = os.open(Path(peers), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fd = None
    if fd is not None:
        try:
            st = os.fstat(fd)
            doc = _json_borne(fd, st.st_size) if stat.S_ISREG(st.st_mode) else None
        except OSError:
            doc = None
        finally:
            os.close(fd)
        try:
            noms = {b.nom for _, b in _table_maillage(doc)} if doc is not None else set()
        except (TypeError, ValueError, AttributeError):
            noms = set()
    h = (hote() or "").split(".")[0].strip().lower()
    if h:
        noms.add(h)
    return noms
