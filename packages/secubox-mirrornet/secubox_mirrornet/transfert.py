# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Transfert des versions de jeux de données entre pairs (#3653, docs/MIRRORNET_DATA_EXCHANGE.md § 4).

Côté abonné : pour chaque abonnement Actif à un jeu de données, la dernière version non retirée est tirée du
fournisseur par l'écouteur maillé (`http://<ip-maillage>:8799/mirrornet/objets/<empreinte>`), une à la fois, puis
vérifiée (taille et BLAKE2b) avant d'être gardée ; les `garder` dernières versions restent, les retirées disparaissent.

Côté fournisseur : `autoriser` décide si un pair (adresse posée par nginx) reçoit un objet — abonnement Actif à un jeu de
CE nœud qui contient cette version non retirée, classe autre que « privé ».
"""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
import urllib.request
from typing import Any, Dict, Iterator, Optional

from . import config, objets

log = logging.getLogger("secubox-mirrornet")
MAILLAGE = ipaddress.ip_network("10.10.0.0/24")
DELAI = 30.0
MORCEAU = 256 * 1024


def autoriser(cx: sqlite3.Connection, ip: Optional[str], empreinte: str) -> Optional[str]:
    """Motif de refus, ou None si le pair à l'adresse `ip` peut recevoir l'objet `empreinte`."""
    try:
        if ip is None or ipaddress.ip_address(ip) not in MAILLAGE:
            return "adresse hors du maillage"
    except ValueError:
        return "adresse illisible"
    dids = [r[0] for r in cx.execute("SELECT did FROM node WHERE mesh_ip = ?", (ip,))]
    if len(dids) != 1:
        return "pair inconnu ou adresse revendiquée par plusieurs nœuds"
    soi = (cx.execute("SELECT soi FROM synchro WHERE id = 1").fetchone() or [None])[0]
    ligne = cx.execute(
        "SELECT 1 FROM dataset_version v JOIN offer o ON o.id = v.offer_id "
        "JOIN subscription s ON s.offer_id = o.id "
        "WHERE v.empreinte = ? AND v.retiree = 0 AND v.classe <> 'prive' AND o.fournisseur_did = ? AND o.etat = 'publiee' "
        "AND s.role = 'fournisseur' AND s.abonne_did = ? "
        "AND (SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) = 'Actif' "
        "LIMIT 1", (empreinte, soi, dids[0])).fetchone()
    return None if ligne else "aucun abonnement Actif de ce pair à une version non retirée contenant cet objet"


def a_tirer(cx: sqlite3.Connection) -> list:
    """Versions à recevoir : dernière version non retirée de chaque jeu auquel CE nœud est abonné (état Actif)."""
    return [dict(r) for r in cx.execute(
        "SELECT v.empreinte, v.taille, o.ref_annuaire AS service_id, n.mesh_ip, o.fournisseur_did "
        "FROM dataset_version v JOIN offer o ON o.id = v.offer_id JOIN node n ON n.did = o.fournisseur_did "
        "JOIN subscription s ON s.offer_id = o.id "
        "WHERE o.kind = 'dataset' AND s.role = 'abonne' AND v.retiree = 0 AND v.classe <> 'prive' "
        "AND (SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) = 'Actif' "
        "AND v.numero = (SELECT MAX(numero) FROM dataset_version w WHERE w.offer_id = o.id AND w.retiree = 0) "
        "AND NOT EXISTS (SELECT 1 FROM objet x WHERE x.empreinte = v.empreinte)")]


def _flux(url: str) -> Iterator[bytes]:
    req = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=DELAI) as r:  # noqa: S310 (maillage seulement, adresse vérifiée)
        while True:
            m = r.read(MORCEAU)
            if not m:
                return
            yield m


def tirer(cx: sqlite3.Connection, reglages: Dict[str, Any], flux=_flux) -> Dict[str, int]:
    """Une passe côté abonné : au plus UNE version reçue (débit modéré), puis rangement des versions gardées."""
    stats = {"recues": 0, "refusees": 0, "purgees": 0}
    for t in a_tirer(cx):
        ip = t.get("mesh_ip")
        try:
            if not ip or ipaddress.ip_address(ip) not in MAILLAGE:
                continue
        except ValueError:
            continue
        try:
            objets.verifier_espace(t["taille"], reglages["reserve_mo"])
            url = f"http://{ip}:{config.PORT_MAILLAGE}/mirrornet/objets/{t['empreinte']}"
            empreinte, taille = objets.ecrire(flux(url), min(t["taille"], reglages["taille_max_mo"] * 1024 * 1024),
                                              attendue=t["empreinte"], taille_attendue=t["taille"])
            objets.noter(cx, empreinte, taille, t["fournisseur_did"])
            stats["recues"] += 1
            log.info("mirrornet : version %s reçue (%s octets) du jeu %s", empreinte[:19], taille, t["service_id"][:12])
            break                                                   # une version reçue par passe (débit modéré)
        except objets.RefusObjet as e:
            stats["refusees"] += 1
            log.warning("mirrornet : version %s refusée : %s", t["empreinte"][:19], e)
        except OSError as e:                                        # fournisseur injoignable : on passe au jeu suivant
            log.info("mirrornet : fournisseur %s injoignable pour %s : %s", ip, t["empreinte"][:19], e.__class__.__name__)
    stats["purgees"] = ranger(cx, reglages["garder"])
    return stats


def ranger(cx: sqlite3.Connection, garder: int) -> int:
    """Supprime les objets retirés, et au-delà des `garder` dernières versions de chaque jeu ; jamais une version de
    CE nœud fournisseur (source = soi) encore publiée."""
    soi = (cx.execute("SELECT soi FROM synchro WHERE id = 1").fetchone() or [None])[0]
    a_supprimer = set()
    for (empreinte,) in cx.execute(
            "SELECT x.empreinte FROM objet x WHERE EXISTS (SELECT 1 FROM dataset_version v WHERE v.empreinte = x.empreinte "
            "AND v.retiree = 1) AND NOT EXISTS (SELECT 1 FROM dataset_version v WHERE v.empreinte = x.empreinte AND v.retiree = 0)"):
        a_supprimer.add(empreinte)
    for (offer_id,) in cx.execute("SELECT DISTINCT offer_id FROM dataset_version"):
        rangs = [r[0] for r in cx.execute(
            "SELECT v.empreinte FROM dataset_version v JOIN objet x ON x.empreinte = v.empreinte "
            "WHERE v.offer_id = ? AND v.retiree = 0 AND x.source <> ? ORDER BY v.numero DESC", (offer_id, soi or ""))]
        a_supprimer.update(rangs[garder:])
    for e in a_supprimer:
        objets.supprimer(cx, e)
    return len(a_supprimer)
