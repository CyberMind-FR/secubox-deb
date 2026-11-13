# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Présence certifiée des copies (#3661, phase 4c) : jamais auto-déclarée.

Preuve de possession : le producteur envoie à l'espace un défi aléatoire (32 octets) ; l'espace répond par
BLAKE2b-256 de l'objet, clé = défi. Seul qui détient les octets peut répondre ; le producteur recalcule sur SA copie et
compare à temps constant. Défi neuf à chaque fois : une réponse ancienne ne sert à rien. Côté espace, la preuve n'est
donnée qu'à l'origine de la copie, et au plus une fois par minute et par objet (calcul sur tout l'objet).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from . import config, objets, transfert

log = logging.getLogger("secubox-mirrornet")
DEFI = 32
MORCEAU = 1024 * 1024
PAR_PASSE = 4
RETRY_ECHEC_S = 180
_DERNIER = ("(SELECT vers FROM subscription_event x WHERE x.subscription_id = s.id "
            "ORDER BY x.ts DESC, x.rowid DESC LIMIT 1)")


# Un seul calcul de preuve à la fois sur ce nœud (jusqu'à 256 Mio relus) : une demande concurrente est refusée (503).
CALCUL = threading.Lock()


def preuve(empreinte: str, defi: bytes) -> str:
    """BLAKE2b-256 de l'objet, clé = défi (lecture par morceaux)."""
    h = hashlib.blake2b(digest_size=32, key=defi)
    with open(objets.chemin(empreinte), "rb") as f:
        while True:
            m = f.read(MORCEAU)
            if not m:
                break
            h.update(m)
    return h.hexdigest()


# --- côté espace : qui peut demander une preuve, et à quel rythme ------------------------------------------------------

_DERNIERES: Dict[tuple, float] = {}
_VERROU = threading.Lock()


def autoriser_preuve(cx: sqlite3.Connection, ip: Optional[str], empreinte: str) -> Optional[str]:
    """Motif de refus, ou None : le pair est l'ORIGINE d'une copie de cet objet gardée ici, et n'a pas demandé de
    preuve pour cet objet depuis 60 s."""
    try:
        if ip is None or ipaddress.ip_address(ip) not in transfert.MAILLAGE:
            return "adresse hors du maillage"
    except ValueError:
        return "adresse illisible"
    dids = [r[0] for r in cx.execute("SELECT did FROM node WHERE mesh_ip = ?", (ip,))]
    if len(dids) != 1:
        return "pair inconnu ou adresse revendiquée par plusieurs nœuds"
    if cx.execute(
            "SELECT 1 FROM copie c JOIN subscription s ON s.id = c.subscription_id JOIN dataset_version v ON v.id = c.version_id "
            f"WHERE c.empreinte = ? AND c.origine_did = ? AND c.parent_did = c.origine_did AND v.retiree = 0 AND {_DERNIER} = 'Actif' "
            "LIMIT 1", (empreinte, dids[0])).fetchone() is None:
        return "aucune copie de cet objet reçue de ce pair sous un abonnement d'espace Actif"
    with _VERROU:
        maintenant = time.monotonic()
        cle = (dids[0], empreinte)
        if maintenant - _DERNIERES.get(cle, -1e9) < 60:
            return "trop tôt"
        _DERNIERES[cle] = maintenant
        for k in [k for k, v in _DERNIERES.items() if maintenant - v > 3600]:
            _DERNIERES.pop(k, None)
    return None


# --- côté producteur : défier les espaces qui gardent mes jeux ---------------------------------------------------------

def a_certifier(cx: sqlite3.Connection, certif_s: int) -> List[Dict[str, Any]]:
    """(espace, version) à défier : abonnements Actif de CE nœud producteur à des espaces, jeux nommés, dernière
    version non retirée dont j'ai l'objet, sans preuve réussie ni échouée depuis `certif_s`."""
    soi = (cx.execute("SELECT soi FROM synchro WHERE id = 1").fetchone() or [None])[0]
    if not soi:
        return []
    limite = (datetime.now(timezone.utc) - timedelta(seconds=certif_s)).isoformat()
    # Après un ÉCHEC, nouvel essai plus tôt (#3661, banc) : le premier défi part souvent avant que l'espace ait tiré la
    # copie ; l'afficher « NON certifiée » pendant tout `certif_s` serait faux.
    limite_echec = (datetime.now(timezone.utc) - timedelta(seconds=min(certif_s, RETRY_ECHEC_S))).isoformat()
    return [dict(r) for r in cx.execute(
        "SELECT DISTINCT e.fournisseur_did AS gardien, n.mesh_ip, v.empreinte, o.ref_annuaire AS service_id "
        "FROM subscription s JOIN offer e ON e.id = s.offer_id JOIN node n ON n.did = e.fournisseur_did "
        "JOIN offer o ON o.kind = 'dataset' AND o.fournisseur_did = ? AND o.etat = 'publiee' "
        "AND o.ref_annuaire IN (SELECT value FROM json_each(s.jeux)) "
        "JOIN dataset_version v ON v.offer_id = o.id AND v.retiree = 0 "
        "AND v.numero = (SELECT MAX(numero) FROM dataset_version w WHERE w.offer_id = o.id AND w.retiree = 0) "
        "JOIN objet x ON x.empreinte = v.empreinte "
        f"WHERE s.role = 'abonne' AND s.abonne_did = ? AND e.kind = 'espace' AND e.etat = 'publiee' AND {_DERNIER} = 'Actif' "
        "AND NOT EXISTS (SELECT 1 FROM presence p WHERE p.gardien_did = e.fournisseur_did AND p.empreinte = v.empreinte "
        "AND p.mode = 'preuve' AND p.le > CASE p.statut WHEN 'ok' THEN ? ELSE ? END)", (soi, soi, limite, limite_echec))]


def _demander(url: str) -> Dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with transfert._OUVREUR.open(req, timeout=transfert.DELAI) as r:  # noqa: S310 (maillage seulement)
        if r.status != 200:
            raise OSError(f"HTTP {r.status}")
        return json.loads(r.read(4096))


def certifier(cx: sqlite3.Connection, reglages: Dict[str, Any],
              demander: Callable[[str], Dict[str, Any]] = _demander) -> Dict[str, int]:
    """Une passe : au plus PAR_PASSE défis. Le défi expiré ou sans réponse compte comme échec (la copie n'est pas
    présentée comme présente) ; le délai `certif_s` s'applique aussi après un échec (pas de rafale)."""
    stats = {"certifiees": 0, "echecs": 0}
    for t in a_certifier(cx, reglages["certif_s"])[:PAR_PASSE]:
        ip = t.get("mesh_ip")
        try:
            if not ip or ipaddress.ip_address(ip) not in transfert.MAILLAGE:
                continue
        except ValueError:
            continue
        defi = secrets.token_bytes(DEFI)
        try:
            attendue = preuve(t["empreinte"], defi)          # MA copie d'abord : son absence n'accuse pas l'espace
        except OSError as e:
            log.warning("mirrornet : objet %s illisible ici, preuve non demandée : %s", t["empreinte"][:19], e)
            continue
        try:
            rep = demander(f"http://{ip}:{config.PORT_MAILLAGE}/mirrornet/preuve/{t['empreinte']}?defi={defi.hex()}")
            recue = rep.get("preuve") if isinstance(rep, dict) else None
            ok = isinstance(recue, str) and hmac.compare_digest(recue.encode(), attendue.encode())
            motif = "" if ok else "preuve fausse : l'espace ne détient pas cet objet"
        except (OSError, ValueError) as e:
            ok, motif = False, f"espace injoignable ou refus ({e.__class__.__name__})"
        transfert.noter_presence(cx, t["gardien"], t["empreinte"], "preuve", ok, motif)
        stats["certifiees" if ok else "echecs"] += 1
        if not ok:
            log.warning("mirrornet : présence de %s chez %s non certifiée : %s", t["empreinte"][:19], t["gardien"][8:20], motif)
    return stats
