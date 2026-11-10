# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API de secubox-mirrornet (#3645) sur /run/secubox/mirrornet.sock — PHASE 2 : LECTURE SEULE.

Expose le modèle de données (docs/MIRRORNET_DATA_MODEL.md) : catalogue local, abonnements, règles de répartition
(`require_lecture`) ; soldes et ledger de CE nœud (`require_jwt` : le ledger est privé, MIRRORNET_ECONOMY.md § 8).
Aucune route d'écriture à ce stade. Routes `def` : les lectures SQLite tournent dans le pool, jamais sur la boucle.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from secubox_mirrornet import config, ledger, schema  # noqa: E402

log = logging.getLogger("secubox-mirrornet")
router = APIRouter(prefix="/api/v1/mirrornet")


def _base() -> sqlite3.Connection:
    if not config.BASE.exists():
        raise HTTPException(status_code=503, detail="base MirrorNet absente : le service ne l'a pas encore créée")
    try:
        return schema.ouvrir(config.BASE, lecture_seule=True)
    except sqlite3.Error as e:
        log.warning("base MirrorNet illisible : %s", e.__class__.__name__)
        raise HTTPException(status_code=500, detail="base MirrorNet illisible") from None


def _lignes(sql: str, args: tuple = ()) -> List[Dict[str, Any]]:
    cx = _base()
    try:
        return [dict(r) for r in cx.execute(sql, args)]
    except sqlite3.Error as e:
        log.warning("lecture MirrorNet en échec : %s", e.__class__.__name__)
        raise HTTPException(status_code=500, detail="lecture de la base en échec") from None
    finally:
        cx.close()


def _json(d: Dict[str, Any], *cles: str) -> Dict[str, Any]:
    for c in cles:
        try:
            d[c] = json.loads(d[c]) if isinstance(d.get(c), str) else d.get(c)
        except ValueError:
            d[c] = None
    return d


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "module": "mirrornet", "phase": 2}


@router.get("/schema", dependencies=[Depends(require_lecture)])
def schema_version() -> Dict[str, Any]:
    cx = _base()
    try:
        return {"version": schema.version(cx), "attendue": schema.VERSION}
    finally:
        cx.close()


@router.get("/services", dependencies=[Depends(require_lecture)])
def services() -> Dict[str, Any]:
    """Catalogue local des offres de service (hors jeux de données). Vide tant que la synchronisation n'existe pas."""
    rows = [_json(r, "tarif", "quotas") for r in _lignes(
        "SELECT id, ref_annuaire, fournisseur_did, kind, nom, version, classe, tarif, quotas, duree_s, grace_s, etat "
        "FROM offer WHERE kind <> 'dataset' ORDER BY nom")]
    return {"services": rows, "count": len(rows)}


@router.get("/datasets", dependencies=[Depends(require_lecture)])
def datasets() -> Dict[str, Any]:
    rows = [_json(r, "tarif") for r in _lignes(
        "SELECT o.id, o.ref_annuaire, o.fournisseur_did, o.nom, o.classe, o.tarif, o.etat, "
        "(SELECT MAX(numero) FROM dataset_version v WHERE v.offer_id = o.id AND v.retiree = 0) AS derniere_version "
        "FROM offer o WHERE o.kind = 'dataset' ORDER BY o.nom")]
    return {"datasets": rows, "count": len(rows)}


@router.get("/subscriptions", dependencies=[Depends(require_lecture)])
def subscriptions() -> Dict[str, Any]:
    """Abonnements connus de ce nœud et leur dernier état local (la vérité reste le journal de l'annuaire)."""
    rows = [_json(r, "tarif_accepte") for r in _lignes(
        "SELECT s.id, s.ref_annuaire, s.abonne_did, s.offer_id, s.version, s.tarif_accepte, s.renouvellement, "
        "s.expire_le, s.grace_s, (SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id "
        "ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS etat FROM subscription s ORDER BY s.id")]
    return {"subscriptions": rows, "count": len(rows)}


@router.get("/economy/distribution-rules", dependencies=[Depends(require_lecture)])
def regles() -> Dict[str, Any]:
    rows = [_json(r, "parts") for r in _lignes(
        "SELECT id, version, parts, sans_relais, valide_du, cree_le FROM distribution_rule ORDER BY version")]
    return {"rules": rows, "count": len(rows)}


@router.get("/economy/account", dependencies=[Depends(require_jwt)])
def compte() -> Dict[str, Any]:
    """Soldes de CE nœud. Crédits internes sans valeur monétaire ; comptes de règlement séparés (enregistrements)."""
    cx = _base()
    try:
        return {"comptes": ledger.soldes(cx), "unite": "centièmes de crédit", "valeur_monetaire": False}
    finally:
        cx.close()


@router.get("/economy/ledger", dependencies=[Depends(require_jwt)])
def journal(limite: int = Query(100, ge=1, le=1000), avant: int = Query(0, ge=0)) -> Dict[str, Any]:
    """Écritures (les plus récentes d'abord) et contrôle d'intégrité de la chaîne. Privé : administrateur seulement."""
    cx = _base()
    try:
        sql = ("SELECT e.rang, e.id, e.transaction_id, a.nature, a.titulaire, e.montant, t.libelle, t.ts "
               "FROM ledger_entry e JOIN account a ON a.id = e.account_id "
               "JOIN ledger_transaction t ON t.id = e.transaction_id ")
        args: tuple = ()
        if avant:
            sql += "WHERE e.rang < ? "
            args = (avant,)
        sql += "ORDER BY e.rang DESC LIMIT ?"
        ecritures = [dict(r) for r in cx.execute(sql, args + (limite,))]
        anomalies = ledger.verifier_integrite(cx)
        return {"ecritures": ecritures, "integre": not anomalies, "anomalies": anomalies[:50]}
    finally:
        cx.close()


app = FastAPI(title="SecuBox MirrorNet", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)
