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
import json
import logging
import sqlite3
import time
import urllib.request
from datetime import datetime, timedelta, timezone
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
        "AND (v.classe IN ('public', 'communaute') OR o.approval_mode = 'pending') "
        "AND s.role = 'fournisseur' AND s.abonne_did = ? "
        "AND (SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) = 'Actif' "
        "LIMIT 1", (empreinte, soi, dids[0])).fetchone()
    if ligne is None:
        ligne = _espace_autorise(cx, soi, dids[0], empreinte)
    return None if ligne else "aucun abonnement Actif de ce pair à une version non retirée contenant cet objet"


def _espace_autorise(cx: sqlite3.Connection, soi: Optional[str], pair: str, empreinte: str):
    """Propagation (#3659) : CE nœud, producteur du jeu, est abonné (Actif) à une offre d'espace publiée par ce pair et
    a nommé ce jeu dans son abonnement signé. La version doit respecter À LA FOIS la compatibilité figée dans
    l'abonnement (ce que le producteur a accepté) et l'offre actuelle de l'espace (qui peut se restreindre) : classes,
    formats, licences, taille par objet, données personnelles. Jamais professionnel ni privé."""
    from . import espace  # noqa: PLC0415 (espace importe ce module)
    for r in cx.execute(
            "SELECT v.classe, v.format, v.licence, v.taille, v.donnees_personnelles, s.compat_acceptee, e.compat, e.quotas "
            "FROM dataset_version v JOIN offer o ON o.id = v.offer_id, subscription s JOIN offer e ON e.id = s.offer_id "
            "WHERE v.empreinte = ? AND v.retiree = 0 AND v.classe IN ('public', 'communaute', 'specialise') "
            "AND o.kind = 'dataset' AND o.etat = 'publiee' AND o.fournisseur_did = ? "
            "AND s.role = 'abonne' AND s.abonne_did = ? AND e.kind = 'espace' AND e.etat = 'publiee' AND e.fournisseur_did = ? "
            "AND EXISTS (SELECT 1 FROM json_each(s.jeux) WHERE value = o.ref_annuaire) "
            "AND (SELECT vers FROM subscription_event x WHERE x.subscription_id = s.id ORDER BY x.ts DESC, x.rowid DESC LIMIT 1) = 'Actif'",
            (empreinte, soi, soi, pair)):
        v = dict(r)
        try:
            figee = json.loads(v.pop("compat_acceptee"))
            actuelle = (json.loads(v.pop("compat")), json.loads(v.pop("quotas")))
        except (TypeError, ValueError):
            continue
        if not isinstance(figee, dict) or not figee:
            continue                                   # abonnement sans compatibilité figée : rien n'est servi
        if (espace.refus_version(espace.caracteristiques(figee.get("compat"), figee.get("quotas")), v) is None
                and espace.refus_version(espace.caracteristiques(*actuelle), v) is None):
            return (1,)
    return None


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


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # noqa: D401 — un fournisseur ne renvoie pas l'abonné ailleurs
        return None


# Ni proxy d'environnement, ni redirection : la requête va à l'adresse du maillage choisie, et nulle part ailleurs.
_OUVREUR = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SansRedirection())


class TropLent(OSError):
    pass


def _flux(url: str, delai_total: float = 600.0) -> Iterator[bytes]:
    """Lecture par morceaux, délai par lecture (DELAI) ET délai total : un fournisseur qui égrène un octet toutes les
    29 s ne retient pas la passe indéfiniment."""
    fin = time.monotonic() + delai_total
    req = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with _OUVREUR.open(req, timeout=DELAI) as r:  # noqa: S310 (maillage seulement, adresse vérifiée)
        if r.status != 200:
            raise OSError(f"HTTP {r.status}")
        while True:
            if time.monotonic() > fin:
                raise TropLent("délai total du transfert dépassé")
            m = r.read(MORCEAU)
            if not m:
                return
            yield m


# Refus et échecs mémorisés (empreinte -> (essais, prochain essai)) : une version falsifiée ou un fournisseur muet ne
# sont pas retéléchargés à chaque passe ; délai doublé à chaque échec, plafonné à un jour.
_REPRISE: Dict[str, tuple] = {}


def _differer(empreinte: str) -> None:
    n = _REPRISE.get(empreinte, (0, 0.0))[0] + 1
    _REPRISE[empreinte] = (n, time.monotonic() + min(86400.0, 60.0 * 2 ** n))


def _permis(empreinte: str) -> bool:
    return time.monotonic() >= _REPRISE.get(empreinte, (0, 0.0))[1]


def tirer(cx: sqlite3.Connection, reglages: Dict[str, Any], flux=_flux) -> Dict[str, int]:
    """Une passe côté abonné : au plus UNE version reçue (débit modéré), puis rangement des versions gardées."""
    stats = {"recues": 0, "refusees": 0, "purgees": 0}
    for t in a_tirer(cx):
        if not _permis(t["empreinte"]):
            continue
        ip = t.get("mesh_ip")
        try:
            if not ip or ipaddress.ip_address(ip) not in MAILLAGE:
                continue
        except ValueError:
            continue
        try:
            objets.verifier_espace(t["taille"], reglages["reserve_mo"])
            url = f"http://{ip}:{config.PORT_MAILLAGE}/mirrornet/objets/{t['empreinte']}"
            if t["taille"] > reglages["taille_max_mo"] * 1024 * 1024:
                raise objets.RefusObjet(f"version annoncée au-delà du plafond ({reglages['taille_max_mo']} Mio)")
            empreinte, taille = objets.ecrire(flux(url), t["taille"], attendue=t["empreinte"], taille_attendue=t["taille"])
            objets.noter(cx, empreinte, taille, t["fournisseur_did"])
            stats["recues"] += 1
            log.info("mirrornet : version %s reçue (%s octets) du jeu %s", empreinte[:19], taille, t["service_id"][:12])
            break                                                   # une version reçue par passe (débit modéré)
        except objets.RefusObjet as e:
            stats["refusees"] += 1
            _differer(t["empreinte"])
            log.warning("mirrornet : version %s refusée : %s", t["empreinte"][:19], e)
        except OSError as e:                                        # fournisseur injoignable ou trop lent : jeu suivant
            _differer(t["empreinte"])
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
    # Au-delà des `garder` dernières versions d'un jeu… sauf si la même empreinte est encore gardée par un AUTRE jeu ou
    # par une copie d'espace (#3659, relecture) : un tiers qui déclare l'empreinte d'un objet utile dans un vieux numéro
    # de son jeu ne le fait pas effacer.
    utiles, au_dela = set(), set()
    for (offer_id,) in cx.execute("SELECT DISTINCT offer_id FROM dataset_version"):
        rangs = [r[0] for r in cx.execute(
            "SELECT v.empreinte FROM dataset_version v JOIN objet x ON x.empreinte = v.empreinte "
            "WHERE v.offer_id = ? AND v.retiree = 0 AND x.source <> ? ORDER BY v.numero DESC", (offer_id, soi or ""))]
        utiles.update(rangs[:garder])
        au_dela.update(rangs[garder:])
    utiles.update(r[0] for r in cx.execute("SELECT empreinte FROM copie"))
    a_supprimer.update(au_dela - utiles)
    # Objets déposés ici que l'annuaire n'a jamais publiés (dépôt interrompu, réponse indéterminée) : effacés après un
    # jour, quand aucune version connue ne les cite.
    vieux = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    for (empreinte,) in cx.execute(
            "SELECT x.empreinte FROM objet x WHERE x.stocke_le < ? AND NOT EXISTS "
            "(SELECT 1 FROM dataset_version v WHERE v.empreinte = x.empreinte)", (vieux,)):
        a_supprimer.add(empreinte)
    return sum(1 for e in a_supprimer if objets.supprimer(cx, e))
