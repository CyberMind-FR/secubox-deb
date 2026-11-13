# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""API de secubox-mirrornet sur /run/secubox/mirrornet.sock — PHASE 3 (#3647) : cycle de vie des abonnements.

Lecture (`require_lecture`) : catalogue local filtré, règles de répartition. Administrateur (`require_jwt`) : abonnements,
soldes, ledger, et les ÉCRITURES — publier, s'abonner, renouveler, résilier. MirrorNet ne signe rien : chaque geste est
relayé, avec le jeton de l'administrateur, aux routes /self/... de l'annuaire local qui signe par node.key et écrit
audit.log ; la base est ensuite resynchronisée depuis l'export de l'annuaire. Idempotence : en-tête `X-Idempotence`.
Synchronisation de fond : toutes les `intervalle_s` (60 s), dans un fil, jamais sur la boucle.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from secubox_mirrornet import abonnements as A  # noqa: E402
from secubox_mirrornet import annuaire, catalogue, config, espace, ledger, locaux, objets, presence, schema, transfert  # noqa: E402

log = logging.getLogger("secubox-mirrornet")
router = APIRouter(prefix="/api/v1/mirrornet")
PHASE = 4
RANG = config.RANG
_ID = re.compile(r"^[0-9a-f]{16,64}$")
_CLE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_VERROU_SYNCHRO = threading.Lock()


def _base(ecriture: bool = False) -> sqlite3.Connection:
    if not config.BASE.exists():
        raise HTTPException(status_code=503, detail="base MirrorNet absente : le service ne l'a pas encore créée")
    try:
        return schema.ouvrir(config.BASE, lecture_seule=not ecriture)
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


# --- synchronisation ------------------------------------------------------------------------------------------------

def synchroniser_maintenant() -> Dict[str, Any]:
    """Une passe export → base. Sérialisée (fond et routes). Erreur notée dans la table `synchro`, jamais levée."""
    with _VERROU_SYNCHRO:
        if not config.BASE.exists():
            return {"erreur": "base absente"}
        cx = schema.ouvrir(config.BASE)
        try:
            try:
                export = catalogue.lire_export(config.EXPORT)
            except catalogue.ExportIllisible as e:
                catalogue.noter_erreur(cx, str(e))
                return {"erreur": str(e)}
            res = catalogue.synchroniser(cx, export, grace_defaut=config.reglages()["grace_s"])
            # Clés d'idempotence : 24 h suffisent à une reprise ; une réservation en cours (statut 0) n'est pas touchée.
            limite = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            cx.execute("DELETE FROM requete WHERE statut <> 0 AND ts < ?", (limite,))
            orphelines = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            cx.execute("DELETE FROM requete WHERE statut = 0 AND ts < ?", (orphelines,))
            return res
        except sqlite3.Error as e:
            log.warning("synchronisation MirrorNet en échec : %s", e)
            return {"erreur": "base"}
        finally:
            cx.close()


_VERROU_TRANSFERT = threading.Lock()


def tirer_maintenant() -> Dict[str, Any]:
    """Une passe de réception des versions (#3653) : jamais deux à la fois, jamais d'exception vers la boucle."""
    if not _VERROU_TRANSFERT.acquire(blocking=False):
        return {"occupe": True}
    try:
        cx = schema.ouvrir(config.BASE)
        try:
            reg = config.reglages()
            try:
                res = transfert.tirer(cx, reg)
                res["espace"] = espace.propager(cx, reg)      # #3659 : copies gardées comme espace, même cadence
                res["presence"] = presence.certifier(cx, reg)  # #3661 : preuves de possession demandées aux espaces
            finally:
                # #3666 : indices TV déposés et livrés même si la réception a levé (ne lève jamais) ; l'erreur suit son cours.
                loc = locaux.passe(cx, reg)
            res["locaux"] = loc
            return res
        finally:
            cx.close()
    except (sqlite3.Error, OSError) as e:
        log.warning("mirrornet : passe de réception en échec : %s", e)
        return {"erreur": str(e)}
    finally:
        _VERROU_TRANSFERT.release()


async def _boucle_synchro() -> None:
    try:
        await asyncio.to_thread(objets.nettoyer_temporaires)
    except OSError as e:
        log.warning("mirrornet : dépôt des objets inaccessible : %s", e)
    while True:
        try:
            res = await asyncio.to_thread(synchroniser_maintenant)
            if res.get("transitions"):
                log.info("mirrornet : %s changement(s) d'état d'abonnement", res["transitions"])
        except Exception as e:  # noqa: BLE001 — la boucle ne meurt pas, mais elle le dit
            log.warning("mirrornet : passe de synchronisation en échec : %s", e)
        await asyncio.sleep(config.reglages()["intervalle_s"])


async def _boucle_reception() -> None:
    """Réception des versions dans SA tâche (#3653, relecture) : un fournisseur lent ne retarde jamais les transitions
    d'abonnement (échéance, grâce) de la boucle de synchronisation."""
    while True:
        await asyncio.sleep(config.reglages()["intervalle_s"])
        try:
            await asyncio.to_thread(tirer_maintenant)
        except Exception as e:  # noqa: BLE001
            log.warning("mirrornet : passe de réception en échec : %s", e)


@contextlib.asynccontextmanager
async def _vie(_app: FastAPI):
    taches = [asyncio.create_task(_boucle_synchro()), asyncio.create_task(_boucle_reception())]
    try:
        yield
    finally:
        for t in taches:
            t.cancel()


# --- lecture --------------------------------------------------------------------------------------------------------

def _presentable(o: Dict[str, Any], confiance_min: str) -> bool:
    """§ 3 : jamais d'offre d'un fournisseur OBSERVER ou REVOKED ; LIMITED : gratuit et public seulement."""
    niveau = o.get("fournisseur_niveau")
    if o.get("etat") != "publiee" or niveau not in RANG or RANG[niveau] < max(1, RANG[confiance_min]):
        return False
    if o.get("classe") == "prive":
        return False
    if niveau == "LIMITED":
        return (o.get("tarif") or {}).get("modele") == "gratuit" and o.get("classe") == "public"
    return True


_SQL_OFFRE = ("SELECT o.ref_annuaire AS id, o.fournisseur_did, n.nom AS fournisseur, n.niveau AS fournisseur_niveau, "
              "n.cause AS fournisseur_cause, n.ok_le AS fournisseur_ok_le, n.echec_depuis AS fournisseur_echec_depuis, "
              "o.kind, o.nom, o.version, o.classe, o.tarif, o.quotas, o.duree_s, o.grace_s, o.etat, o.endpoint, "
              "o.approval_mode, o.description, o.compat, o.sonde FROM offer o JOIN node n ON n.did = o.fournisseur_did")


def _soi() -> Optional[str]:
    r = _lignes("SELECT soi FROM synchro WHERE id = 1")
    return r[0]["soi"] if r else None


@router.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "module": "mirrornet", "phase": PHASE}


@router.get("/schema", dependencies=[Depends(require_lecture)])
def schema_version() -> Dict[str, Any]:
    cx = _base()
    try:
        return {"version": schema.version(cx), "attendue": schema.VERSION}
    finally:
        cx.close()


@router.get("/status", dependencies=[Depends(require_lecture)])
def status() -> Dict[str, Any]:
    """État du module : base, schéma, volumes, dernière synchronisation. Aucune donnée privée."""
    present = config.BASE.exists()
    res: Dict[str, Any] = {"module": "mirrornet", "phase": PHASE, "base": present, "ecriture": True}
    if present:
        cx = _base()
        try:
            res["schema"] = schema.version(cx)
            for t in ("offer", "subscription", "dataset_version", "distribution_rule"):
                res[f"n_{t}"] = cx.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            s = cx.execute("SELECT le, export_le, hauteur, offres, rejetees, erreur FROM synchro WHERE id = 1").fetchone()
            res["synchro"] = dict(s) if s else None
        finally:
            cx.close()
    return res


_TOPOLOGIE = ("endpoint", "sonde", "fournisseur_ok_le", "fournisseur_echec_depuis")


def _sans_topologie(r: Dict[str, Any], ident: Dict[str, Any]) -> Dict[str, Any]:
    """Lecteur anonyme (tableau de bord du LAN) : ni adresses du maillage ni joignabilité (MODULE-COMPLIANCE)."""
    if ident.get("tableau_de_bord") or not ident.get("sub"):
        for k in _TOPOLOGIE:
            r.pop(k, None)
    return r


@router.get("/services")
def services(ident: Dict[str, Any] = Depends(require_lecture)) -> Dict[str, Any]:
    """Catalogue local : offres présentables (§ 3) des autres nœuds, et celles de CE nœud (`mienne`)."""
    confiance_min = config.reglages()["confiance_min"]
    soi = _soi()
    rows = []
    for r in _lignes(_SQL_OFFRE + " WHERE o.kind NOT IN ('dataset', 'espace') ORDER BY o.nom"):
        r = _json(r, "tarif", "quotas", "compat")
        r["mienne"] = r["fournisseur_did"] == soi
        r["presentable"] = _presentable(r, confiance_min)
        if r["mienne"] or r["presentable"]:
            rows.append(_sans_topologie(r, ident))
    return {"services": rows, "count": len(rows), "confiance_min": confiance_min}


@router.get("/services/{service_id}")
def service(service_id: str, ident: Dict[str, Any] = Depends(require_lecture)) -> Dict[str, Any]:
    if not _ID.match(service_id):
        raise HTTPException(404, "offre inconnue")
    rows = _lignes(_SQL_OFFRE + " WHERE o.ref_annuaire = ?", (service_id,))
    if not rows:
        raise HTTPException(404, "offre inconnue")
    r = _json(rows[0], "tarif", "quotas", "compat")
    r["mienne"] = r["fournisseur_did"] == _soi()
    r["presentable"] = _presentable(r, config.reglages()["confiance_min"])
    if not (r["mienne"] or r["presentable"]):
        raise HTTPException(404, "offre inconnue")       # non présentable = invisible, comme au catalogue
    return _sans_topologie(r, ident)


@router.get("/datasets")
def datasets(ident: Dict[str, Any] = Depends(require_lecture)) -> Dict[str, Any]:
    """Jeux de données présentables (mêmes règles que le catalogue) et les miens, avec leur dernière version."""
    confiance_min, soi = config.reglages()["confiance_min"], _soi()
    rows = []
    for r in _lignes(_SQL_OFFRE + " WHERE o.kind = 'dataset' ORDER BY o.nom"):
        r = _json(r, "tarif", "quotas", "compat")
        r["mienne"] = r["fournisseur_did"] == soi
        r["presentable"] = _presentable(r, confiance_min)
        if not (r["mienne"] or r["presentable"]):
            continue
        d = _lignes("SELECT v.numero, v.empreinte, v.taille, v.format, v.licence, v.cree_le, v.fraicheur_s, "
                    "EXISTS (SELECT 1 FROM objet x WHERE x.empreinte = v.empreinte) AS present, "
                    "(SELECT n.nom FROM objet x JOIN node n ON n.did = x.source WHERE x.empreinte = v.empreinte) AS recue_de, "
                    "(SELECT COUNT(DISTINCT r.gardien_did) FROM replique r WHERE r.offer_id = o.id AND r.etat = 'Actif') AS repliques "
                    "FROM dataset_version v JOIN offer o ON o.id = v.offer_id WHERE o.ref_annuaire = ? AND v.retiree = 0 "
                    "ORDER BY v.numero DESC LIMIT 1", (r["id"],))
        r["derniere_version"] = d[0] if d else None
        if d and (ident.get("tableau_de_bord") or not ident.get("sub")):
            for k in ("recue_de", "repliques"):          # qui garde les jeux de qui : relation d'autrui (#3661)
                d[0].pop(k, None)
        rows.append(_sans_topologie(r, ident))
    return {"datasets": rows, "count": len(rows)}


@router.get("/datasets/{service_id}/versions")
def versions(service_id: str, ident: Dict[str, Any] = Depends(require_lecture)) -> Dict[str, Any]:
    """Manifestes d'un jeu (provenance, licence, classe, fraîcheur) et présence locale de chaque version."""
    if not _ID.match(service_id):
        raise HTTPException(404, "jeu inconnu")
    offre = _lignes(_SQL_OFFRE + " WHERE o.ref_annuaire = ? AND o.kind = 'dataset'", (service_id,))
    if not offre:
        raise HTTPException(404, "jeu inconnu")
    o = _json(offre[0], "tarif", "quotas", "compat")
    if not (o["fournisseur_did"] == _soi() or _presentable(o, config.reglages()["confiance_min"])):
        raise HTTPException(404, "jeu inconnu")
    rows = _lignes("SELECT v.numero, v.parent, v.empreinte, v.taille, v.format, v.licence, v.provenance, v.classe, "
                   "v.fraicheur_s, v.donnees_personnelles, v.cree_le, v.retiree, "
                   "EXISTS (SELECT 1 FROM objet x WHERE x.empreinte = v.empreinte) AS present "
                   "FROM dataset_version v JOIN offer o ON o.id = v.offer_id WHERE o.ref_annuaire = ? ORDER BY v.numero DESC",
                   (service_id,))
    return {"service_id": service_id, "nom": o["nom"], "versions": rows, "count": len(rows)}


_SQL_ABO = ("SELECT s.ref_annuaire AS id, s.role, s.abonne_did, na.nom AS abonne, o.ref_annuaire AS service_id, "
            "o.nom AS service, o.fournisseur_did, nf.nom AS fournisseur, s.version, s.tarif_accepte, s.renouvellement, "
            "s.demande_le, s.expire_le, s.echeance, s.grace_s, s.jeux, o.kind, "
            "(SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS etat, "
            "(SELECT motif FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS motif "
            "FROM subscription s JOIN offer o ON o.id = s.offer_id JOIN node na ON na.did = s.abonne_did "
            "JOIN node nf ON nf.did = o.fournisseur_did")


@router.get("/subscriptions", dependencies=[Depends(require_jwt)])
def subscriptions() -> Dict[str, Any]:
    """Abonnements de ce nœud (abonné ou fournisseur) et leur état dérivé. Administrateur : relation privée entre nœuds."""
    rows = [_json(r, "tarif_accepte", "jeux") for r in _lignes(_SQL_ABO + " ORDER BY s.demande_le DESC")]
    return {"subscriptions": rows, "count": len(rows)}


@router.get("/subscriptions/{subscription_id}", dependencies=[Depends(require_jwt)])
def subscription(subscription_id: str) -> Dict[str, Any]:
    if not _ID.match(subscription_id):
        raise HTTPException(404, "abonnement inconnu")
    rows = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (subscription_id,))
    if not rows:
        raise HTTPException(404, "abonnement inconnu")
    r = _json(rows[0], "tarif_accepte", "jeux")
    r["historique"] = _lignes("SELECT de, vers, motif, ts FROM subscription_event WHERE subscription_id = "
                              "(SELECT id FROM subscription WHERE ref_annuaire = ?) ORDER BY ts, rowid", (subscription_id,))
    return r


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
        anomalies = ledger.verifier_integrite(cx)      # phase 5 : contrôle en tâche de fond + cache (PERF-CACHE)
        return {"ecritures": ecritures, "integre": not anomalies, "anomalies": anomalies[:50], "tete": ledger.tete(cx)}
    finally:
        cx.close()


# --- écritures ------------------------------------------------------------------------------------------------------

def _jeton(request: Request) -> Optional[str]:
    """LE justificatif que la garde a accepté (Bearer, sinon cookie de session, dans son ordre) : jamais un autre, pour
    que l'annuaire agisse et audite au nom de l'appelant réel."""
    from secubox_core.auth import SESSION_COOKIE, _validate_token  # noqa: PLC0415
    a = request.headers.get("authorization", "")
    candidats = [a[7:].strip()] if a[:7].lower() == "bearer " and a[7:].strip() else []
    if request.cookies.get(SESSION_COOKIE):
        candidats.append(request.cookies[SESSION_COOKIE])
    for c in candidats:
        if _validate_token(c) is not None:
            return c
    return None


def _idempotent(cle: Optional[str], route: str, cible: str):
    """RÉSERVE la clé (None : à traiter) ou rend la réponse déjà donnée, rejouée telle quelle. Clé utilisée pour une
    autre requête, ou requête identique encore en cours : 409. Une réservation orpheline (> 5 min) est reprise."""
    if cle is None:
        return None
    if not _CLE.match(cle):
        raise HTTPException(422, "X-Idempotence : 8 à 64 caractères [A-Za-z0-9_-]")
    maintenant = datetime.now(timezone.utc)
    cx = _base(ecriture=True)
    try:
        cx.execute("BEGIN IMMEDIATE")
        try:
            r = cx.execute("SELECT route, cible, statut, resultat, ts FROM requete WHERE cle = ?", (cle,)).fetchone()
            if r is None or (r["statut"] == 0 and (r["route"], r["cible"]) == (route, cible)
                             and (maintenant - (A.instant(r["ts"]) or maintenant)).total_seconds() > 300):
                cx.execute("INSERT OR REPLACE INTO requete(cle, route, cible, statut, resultat, ts) VALUES (?,?,?,0,'null',?)",
                           (cle, route, cible, maintenant.isoformat()))
                cx.execute("COMMIT")
                return None
            cx.execute("COMMIT")
        except BaseException:
            cx.execute("ROLLBACK")
            raise
    finally:
        cx.close()
    if (r["route"], r["cible"]) != (route, cible):
        raise HTTPException(409, "X-Idempotence déjà utilisée pour une autre requête")
    if r["statut"] == 0:
        raise HTTPException(409, "requête identique en cours")
    return JSONResponse(status_code=r["statut"], content=json.loads(r["resultat"]))


def _memoriser(cle: Optional[str], statut: int, resultat: Any) -> None:
    if cle is None:
        return
    cx = _base(ecriture=True)
    try:
        cx.execute("UPDATE requete SET statut = ?, resultat = ? WHERE cle = ?",
                   (statut, json.dumps(resultat)[:65536], cle))
    finally:
        cx.close()


def _liberer(cle: Optional[str]) -> None:
    """Échec : la réservation disparaît, la même clé pourra être rejouée."""
    if cle is None:
        return
    cx = _base(ecriture=True)
    try:
        cx.execute("DELETE FROM requete WHERE cle = ? AND statut = 0", (cle,))
    finally:
        cx.close()


@contextlib.contextmanager
def _geste(cle: Optional[str], request: Request):
    """Échec AVANT signature : la réservation est libérée (la même clé pourra être rejouée). Après signature, jamais."""
    try:
        yield
    except BaseException:
        if not getattr(request.state, "signe", False):
            _liberer(cle)
        raise


def _relayer(request: Request, chemin: str, corps: Optional[Dict[str, Any]], cle: Optional[str]) -> Any:
    """Relaie le geste à l'annuaire. Dès qu'il est SIGNÉ (2xx) ou peut l'avoir été (504), la réponse est mémorisée sous
    la clé d'idempotence : une reprise ne le fait jamais signer une seconde fois, même si la suite échoue."""
    statut, rep = annuaire.appeler(chemin, corps, _jeton(request))
    if statut >= 500 and statut != 503:
        request.state.signe = True                     # indéterminé : rien ne sera libéré ni effacé
        # 504 (sans réponse) ou toute autre 5xx de l'annuaire : le geste a PU être signé. Seuls 503 (connexion
        # impossible) et les refus 4xx libèrent la clé ; ici la réponse est gardée, jamais rejouée vers l'annuaire.
        detail = (rep.get("detail") if isinstance(rep, dict) else None) or f"annuaire : HTTP {statut}"
        rep = {"detail": f"{detail} — résultat indéterminé, consulter /subscriptions avant de réessayer"}
        _memoriser(cle, 504, rep)
        raise HTTPException(504, rep["detail"])
    if statut >= 400:
        detail = rep.get("detail") if isinstance(rep, dict) else None
        raise HTTPException(statut if statut in (401, 403, 404, 409, 422, 503) else 502,
                            detail or f"annuaire : HTTP {statut}")
    try:
        _memoriser(cle, 200, rep)
    except sqlite3.Error as e:      # base occupée : la réservation (statut 0) reste, une reprise aura 409, pas 2 signatures
        log.warning("mirrornet : réponse signée non mémorisée (%s) ; la clé reste réservée", e)
        request.state.signe = True
    try:
        synchroniser_maintenant()      # l'annuaire a réécrit l'export avant de répondre : l'état est déjà visible
    except Exception as e:  # noqa: BLE001 — le geste est fait ; la boucle de fond rattrapera l'index
        log.warning("mirrornet : resynchronisation après geste en échec : %s", e)
    return rep


class Publication(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., min_length=1, max_length=80)
    kind: str = Field(..., pattern=r"^[a-z][a-z0-9_-]{1,23}$")
    endpoint: str = Field(..., min_length=1, max_length=256)
    approval_mode: str = Field("pending", pattern=r"^(auto|pending)$")
    # kind = « dataset » (#3653) : endpoint = mirrornet://<ce nœud> ; les versions se déposent par /datasets/{id}/versions.
    description: str = Field("", max_length=500)
    version: Optional[str] = Field(None, max_length=64)
    compat: Optional[Dict[str, Any]] = None
    tarif: Optional[Dict[str, Any]] = None
    quotas: Optional[Dict[str, int]] = None
    classe: Optional[str] = Field(None, pattern=r"^(public|communaute|specialise|professionnel|prive)$")
    duree_s: Optional[int] = Field(None, gt=0, le=10 * 365 * 86400)
    grace_s: Optional[int] = Field(None, ge=0, le=90 * 86400)
    sonde: Optional[str] = Field(None, max_length=256, pattern=r"^/[A-Za-z0-9._/~-]*$")


def _espace_valide(req: "Publication") -> None:
    """Offre d'espace (#3659) : capacité obligatoire, classes propageables seulement, listes bornées et typées."""
    q, c = req.quotas or {}, req.compat or {}
    if type(q.get("octets")) is not int or q["octets"] <= 0:
        raise HTTPException(422, "espace : quotas.octets (capacité offerte, en octets) obligatoire")
    if "octets_objet" in q and not (type(q["octets_objet"]) is int and 0 < q["octets_objet"] <= q["octets"]):
        raise HTTPException(422, "espace : quotas.octets_objet entre 1 et quotas.octets")
    if set(c) - {"classes", "formats", "licences", "agregees", "arch"}:
        raise HTTPException(422, "espace : compat admet classes, formats, licences, agregees, arch")
    classes = c.get("classes", ["public"])
    if not (isinstance(classes, list) and classes and all(x in espace.PROPAGEABLES for x in classes)):
        raise HTTPException(422, f"espace : compat.classes parmi {', '.join(espace.PROPAGEABLES)}")
    for cle, motif in (("formats", _FORMAT), ("licences", _LICENCE)):
        v = c.get(cle, [])
        if not (isinstance(v, list) and len(v) <= 16 and all(isinstance(x, str) and motif.match(x) for x in v)):
            raise HTTPException(422, f"espace : compat.{cle}, 16 valeurs au plus")
    if "agregees" in c and not isinstance(c["agregees"], bool):
        raise HTTPException(422, "espace : compat.agregees, vrai ou faux")
    if req.classe in ("professionnel", "prive"):
        raise HTTPException(422, "espace : une offre d'espace n'est ni professionnelle ni privée")


@router.post("/services/publish", dependencies=[Depends(require_jwt)])
def publier(req: Publication, request: Request, x_idempotence: Optional[str] = Header(None)):
    """Publie une offre de CE nœud (signée par l'annuaire) : service, jeu (`dataset`) ou espace (`espace`, #3659)."""
    if req.kind == "espace":
        _espace_valide(req)
    corps = req.model_dump(exclude_none=True)
    cible = hashlib.sha256(json.dumps(corps, sort_keys=True).encode()).hexdigest()[:32]
    deja = _idempotent(x_idempotence, "publier", cible)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        return _relayer(request, "/self/service/offer", corps, x_idempotence)


class Abonnement(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Optional[str] = Field(None, max_length=64)


_ARCH = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64", "armv7l": "armhf"}


def evaluer(offre: Dict[str, Any], soi: Optional[str], confiance_min: str) -> Optional[str]:
    """EVALUATE (§ 4) : motif de refus, ou None. Fonction pure (testée)."""
    if offre.get("etat") != "publiee":
        return "offre retirée"
    if soi and offre.get("fournisseur_did") == soi:
        return "un nœud ne s'abonne pas à sa propre offre"
    if not _presentable(offre, confiance_min):
        return (f"fournisseur au niveau {offre.get('fournisseur_niveau')} : offre non présentable "
                f"(seuil {confiance_min} ; LIMITED : gratuit et public seulement)")
    arch = (offre.get("compat") or {}).get("arch")
    if isinstance(arch, list) and arch and _ARCH.get(platform.machine(), platform.machine()) not in arch:
        return f"architecture {platform.machine()} hors de la compatibilité déclarée ({', '.join(map(str, arch))})"
    return None


@router.post("/services/{service_id}/subscribe", dependencies=[Depends(require_jwt)])
def s_abonner(service_id: str, request: Request, req: Optional[Abonnement] = None,
              x_idempotence: Optional[str] = Header(None)):
    """S'abonner : évaluation locale (niveau du fournisseur, classe, tarif, compatibilité), puis abonnement signé.
    Un abonnement déjà en cours à cette offre est rendu tel quel (`existant`), sans en créer un second."""
    if not _ID.match(service_id):
        raise HTTPException(404, "offre inconnue")
    deja = _idempotent(x_idempotence, "abonner", service_id)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        synchroniser_maintenant()
        rows = _lignes(_SQL_OFFRE + " WHERE o.ref_annuaire = ?", (service_id,))
        if not rows:
            raise HTTPException(404, "offre inconnue")
        offre = _json(rows[0], "tarif", "quotas", "compat")
        if offre.get("kind") == "espace":
            raise HTTPException(409, "offre d'espace : y confier des jeux par /espaces/{id}/propager")
        motif = evaluer(offre, _soi(), config.reglages()["confiance_min"])
        if motif:
            raise HTTPException(409, f"abonnement refusé : {motif}")
        en_cours = [r for r in _lignes(_SQL_ABO + " WHERE o.ref_annuaire = ? AND s.role = 'abonne'", (service_id,))
                    if r["etat"] in A.EN_COURS]
        if en_cours:
            res = dict(_json(en_cours[0], "tarif_accepte", "jeux"), existant=True)
        else:
            version = (req.version if req else None) or offre.get("version")
            corps = {"provider": offre["fournisseur_did"]}            # le fournisseur ÉVALUÉ, lié à l'abonnement
            if version:
                corps["version"] = version
            rep = _relayer(request, f"/self/service/{service_id}/subscribe", corps, x_idempotence)
            sub_id = rep.get("subscription_id") if isinstance(rep, dict) else None
            lignes = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (sub_id,)) if sub_id else []
            res = (dict(_json(lignes[0], "tarif_accepte", "jeux"), existant=False) if lignes
                   else {"id": sub_id, "existant": False})
        _memoriser(x_idempotence, 200, res)
    return res


def _abonnement_local(subscription_id: str) -> Dict[str, Any]:
    if not _ID.match(subscription_id):
        raise HTTPException(404, "abonnement inconnu")
    rows = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (subscription_id,))
    if not rows:
        raise HTTPException(404, "abonnement inconnu")
    return rows[0]


@router.post("/subscriptions/{subscription_id}/renew", dependencies=[Depends(require_jwt)])
def renouveler(subscription_id: str, request: Request, x_idempotence: Optional[str] = Header(None)):
    deja = _idempotent(x_idempotence, "renouveler", subscription_id)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        s = _abonnement_local(subscription_id)
        if s["role"] != "abonne":
            raise HTTPException(409, "seul l'abonné renouvelle")
        if s["etat"] not in ("Actif", "Grace"):
            raise HTTPException(409, f"abonnement {s['etat']} : renouvellement impossible")
        return _relayer(request, f"/self/subscription/{subscription_id}/renew", None, x_idempotence)


def _decision(subscription_id: str, request: Request, x_idempotence: Optional[str], verbe: str):
    """Approbation ou refus d'un abonné par CE nœud fournisseur (#3651), seulement tant que la demande est en attente."""
    deja = _idempotent(x_idempotence, verbe, subscription_id)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        s = _abonnement_local(subscription_id)
        if s["role"] != "fournisseur":
            raise HTTPException(409, "seul le fournisseur approuve ou refuse")
        if s["etat"] != "Demande":
            raise HTTPException(409, f"abonnement {s['etat']} : plus de décision à prendre")
        return _relayer(request, f"/self/subscription/{subscription_id}/{verbe}", None, x_idempotence)


@router.post("/subscriptions/{subscription_id}/approve", dependencies=[Depends(require_jwt)])
def approuver(subscription_id: str, request: Request, x_idempotence: Optional[str] = Header(None)):
    return _decision(subscription_id, request, x_idempotence, "approve")


@router.post("/subscriptions/{subscription_id}/reject", dependencies=[Depends(require_jwt)])
def refuser(subscription_id: str, request: Request, x_idempotence: Optional[str] = Header(None)):
    return _decision(subscription_id, request, x_idempotence, "reject")


@router.delete("/subscriptions/{subscription_id}", dependencies=[Depends(require_jwt)])
def resilier(subscription_id: str, request: Request, motif: str = Query("", max_length=200),
             x_idempotence: Optional[str] = Header(None)):
    """Résiliation (ce nœud est l'abonné) ou révocation de l'abonné (ce nœud est le fournisseur)."""
    deja = _idempotent(x_idempotence, "resilier", subscription_id)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        s = _abonnement_local(subscription_id)
        if s["etat"] in A.TERMINAUX:
            raise HTTPException(409, f"abonnement déjà clos ({s['etat']})")
        return _relayer(request, f"/self/subscription/{subscription_id}/cancel", {"motif": motif}, x_idempotence)


# --- espace offert et propagation (#3659) ----------------------------------------------------------------------------

@router.get("/espaces")
def espaces(ident: Dict[str, Any] = Depends(require_lecture)) -> Dict[str, Any]:
    """Offres d'espace présentables et les miennes : compatibilité et capacité déclarées (et occupée, pour les miennes)."""
    confiance_min, soi = config.reglages()["confiance_min"], _soi()
    rows = []
    cx = _base()
    try:
        for r in cx.execute(_SQL_OFFRE.replace("SELECT ", "SELECT o.id AS lid, ", 1)
                            + " WHERE o.kind = 'espace' ORDER BY o.nom"):
            r = _json(dict(r), "tarif", "quotas", "compat")
            r["mienne"] = r["fournisseur_did"] == soi
            r["presentable"] = _presentable(r, confiance_min)
            lid = r.pop("lid")
            if not (r["mienne"] or r["presentable"]):
                continue
            r["espace"] = espace.caracteristiques(r.get("compat"), r.get("quotas"))
            if r["mienne"] and ident.get("sub") and not ident.get("tableau_de_bord"):
                r["occupe"] = espace.occupe(cx, lid)
            rows.append(_sans_topologie(r, ident))
    except sqlite3.Error as e:
        log.warning("lecture MirrorNet en échec : %s", e.__class__.__name__)
        raise HTTPException(500, "lecture de la base en échec") from None
    finally:
        cx.close()
    return {"espaces": rows, "count": len(rows)}


@router.get("/espaces/gardees", dependencies=[Depends(require_jwt)])
def espaces_gardees() -> Dict[str, Any]:
    """Ce que CE nœud garde comme espace : producteurs, jeux nommés, copies (lignée), capacité, refus en cours."""
    cx = _base()
    try:
        rows = espace.gardees(cx)
    finally:
        cx.close()
    return {"gardees": rows, "count": len(rows)}


@router.get("/datasets/{service_id}/lignee", dependencies=[Depends(require_jwt)])
def lignee(service_id: str) -> Dict[str, Any]:
    """Où vit un jeu : versions (chaîne parent), espaces où ce nœud l'a confié, copies gardées ici."""
    if not _ID.match(service_id):
        raise HTTPException(404, "jeu inconnu")
    cx = _base()
    try:
        o = cx.execute("SELECT nom, fournisseur_did FROM offer WHERE ref_annuaire = ? AND kind = 'dataset'",
                       (service_id,)).fetchone()
        if o is None:
            raise HTTPException(404, "jeu inconnu")
        res = espace.lignee(cx, service_id)
        for e in res["espaces"]:
            p = cx.execute("SELECT statut, le, motif, empreinte FROM presence WHERE gardien_did = ? AND mode = 'preuve' "
                           "AND empreinte IN (SELECT v.empreinte FROM dataset_version v JOIN offer o ON o.id = v.offer_id "
                           "WHERE o.ref_annuaire = ?) ORDER BY le DESC LIMIT 1", (e["gardien_did"], service_id)).fetchone()
            e["presence"] = dict(p) if p else None
        res["repliques"] = [dict(r) for r in cx.execute(
            "SELECT n.nom AS gardien, r.gardien_did, r.etat, p.statut AS transfert, p.le AS transfert_le "
            "FROM replique r JOIN offer o ON o.id = r.offer_id JOIN node n ON n.did = r.gardien_did "
            "LEFT JOIN presence p ON p.gardien_did = r.gardien_did AND p.mode = 'transfert' AND p.empreinte = "
            "(SELECT v.empreinte FROM dataset_version v WHERE v.offer_id = o.id AND v.retiree = 0 ORDER BY v.numero DESC LIMIT 1) "
            "WHERE o.ref_annuaire = ? ORDER BY n.nom", (service_id,))]
    finally:
        cx.close()
    return dict(res, nom=o["nom"], producteur_did=o["fournisseur_did"], mien=o["fournisseur_did"] == _soi())


class Propagation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jeux: List[str] = Field(..., min_length=1, max_length=32)


@router.post("/espaces/{service_id}/propager", dependencies=[Depends(require_jwt)])
def propager(service_id: str, req: Propagation, request: Request, x_idempotence: Optional[str] = Header(None)):
    """Confier des jeux de CE nœud à l'espace d'un pair : évaluation (offre, niveau du pair), compatibilité de la
    dernière version de chaque jeu, puis abonnement signé qui NOMME les jeux. Un abonnement en cours à cet espace est
    rendu tel quel (`existant`) : pour changer de jeux, le résilier puis recommencer."""
    if not _ID.match(service_id) or len(set(req.jeux)) != len(req.jeux) or not all(_ID.match(j) for j in req.jeux):
        raise HTTPException(422, "espace ou jeux invalides")
    deja = _idempotent(x_idempotence, "propager", service_id + ",".join(sorted(req.jeux)))
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        synchroniser_maintenant()
        rows = _lignes(_SQL_OFFRE + " WHERE o.ref_annuaire = ? AND o.kind = 'espace'", (service_id,))
        if not rows:
            raise HTTPException(404, "espace inconnu")
        offre = _json(rows[0], "tarif", "quotas", "compat")
        motif = evaluer(offre, _soi(), config.reglages()["confiance_min"])
        if motif:
            raise HTTPException(409, f"propagation refusée : {motif}")
        car = espace.caracteristiques(offre.get("compat"), offre.get("quotas"))
        soi = _soi()
        for sid in req.jeux:
            jeu = _lignes("SELECT o.nom, o.classe, o.fournisseur_did, o.etat FROM offer o "
                          "WHERE o.ref_annuaire = ? AND o.kind = 'dataset'", (sid,))
            if not jeu or jeu[0]["fournisseur_did"] != soi or jeu[0]["etat"] != "publiee":
                raise HTTPException(409, f"jeu {sid[:16]} : aucun jeu publié par ce nœud")
            if jeu[0]["classe"] not in espace.PROPAGEABLES:
                raise HTTPException(409, f"jeu « {jeu[0]['nom']} » : classe {jeu[0]['classe']} jamais propagée")
            v = _lignes("SELECT v.classe, v.format, v.licence, v.taille, v.donnees_personnelles FROM dataset_version v "
                        "JOIN offer o ON o.id = v.offer_id WHERE o.ref_annuaire = ? AND v.retiree = 0 "
                        "ORDER BY v.numero DESC LIMIT 1", (sid,))
            refus = espace.refus_version(car, v[0]) if v else None
            if refus:
                raise HTTPException(409, f"jeu « {jeu[0]['nom']} » : {refus}")
        en_cours = [r for r in _lignes(_SQL_ABO + " WHERE o.ref_annuaire = ? AND s.role = 'abonne'", (service_id,))
                    if r["etat"] in A.EN_COURS]
        if en_cours:
            res = dict(_json(en_cours[0], "tarif_accepte", "jeux"), existant=True)
        else:
            rep = _relayer(request, f"/self/service/{service_id}/subscribe",
                           {"provider": offre["fournisseur_did"], "jeux": req.jeux}, x_idempotence)
            sub_id = rep.get("subscription_id") if isinstance(rep, dict) else None
            lignes = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (sub_id,)) if sub_id else []
            res = (dict(_json(lignes[0], "tarif_accepte", "jeux"), existant=False) if lignes
                   else {"id": sub_id, "existant": False})
        _memoriser(x_idempotence, 200, res)
    return res


# --- jeux de données : dépôt, retrait, service aux pairs (#3653) -----------------------------------------------------

_FORMAT = re.compile(r"^[A-Za-z0-9.+/_-]{1,80}$")
_LICENCE = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")
_DP = re.compile(r"^(non|agregees|base_legale:[A-Za-z0-9 ._:/-]{3,120})$")


@router.post("/datasets/{service_id}/versions", dependencies=[Depends(require_jwt)])
async def deposer(service_id: str, request: Request,
                  format: str = Query(..., max_length=80), licence: str = Query(..., max_length=64),
                  provenance: str = Query(..., min_length=1, max_length=160),
                  classe: str = Query(..., pattern=r"^(public|communaute|specialise|professionnel|prive)$"),
                  donnees_personnelles: str = Query("non", max_length=140),
                  fraicheur_s: Optional[int] = Query(None, gt=0, le=10 * 365 * 86400),
                  x_idempotence: Optional[str] = Header(None)):
    """Dépose une version d'un jeu de CE nœud : corps brut (application/octet-stream), empreinte calculée en flux,
    plafond `[donnees] taille_max_mo`, garde d'espace ; puis manifeste signé par l'annuaire. Échec : objet effacé."""
    if not _ID.match(service_id) or not _FORMAT.match(format) or not _LICENCE.match(licence) or not _DP.match(donnees_personnelles):
        raise HTTPException(422, "paramètres invalides (format, licence, données personnelles)")
    if any(ord(c) < 32 for c in provenance):
        raise HTTPException(422, "provenance : texte imprimable")
    if (classe == "public" and donnees_personnelles != "non") or (classe == "communaute" and donnees_personnelles not in ("non", "agregees")):
        raise HTTPException(422, "classe incompatible avec des données personnelles (MIRRORNET_DATA_EXCHANGE.md § 6)")
    offre = await asyncio.to_thread(_lignes, _SQL_OFFRE + " WHERE o.ref_annuaire = ?", (service_id,))
    if not offre or offre[0]["kind"] != "dataset" or offre[0]["fournisseur_did"] != await asyncio.to_thread(_soi):
        raise HTTPException(404, "jeu de données de ce nœud inconnu (offre kind=dataset publiée par ce nœud)")
    annoncee = request.headers.get("content-length")
    if annoncee is None or not annoncee.isdigit():
        raise HTTPException(411, "Content-Length requis (pas d'envoi par blocs) : la place disque est vérifiée d'avance")
    reg = config.reglages()
    taille_max = reg["taille_max_mo"] * 1024 * 1024
    if int(annoncee) > taille_max:
        raise HTTPException(413, f"objet trop volumineux (plafond {reg['taille_max_mo']} Mio)")
    cible = "|".join((service_id, format, licence, classe, donnees_personnelles, str(fraicheur_s), annoncee, provenance))
    deja = await asyncio.to_thread(_idempotent, x_idempotence, "deposer", hashlib.sha256(cible.encode()).hexdigest()[:32])
    if deja is not None:
        return deja
    try:
        await asyncio.to_thread(objets.verifier_espace, int(annoncee), reg["reserve_mo"])
        ecrivain = await asyncio.to_thread(objets.Ecrivain, taille_max)
        try:
            async for m in request.stream():              # écrit au fil de l'eau : jamais tout le corps en mémoire
                if m:
                    await asyncio.to_thread(ecrivain.ajouter, m)
        except BaseException:
            await asyncio.to_thread(ecrivain.abandonner)
            raise
        empreinte, taille = await asyncio.to_thread(ecrivain.terminer, None, int(annoncee))
    except objets.RefusObjet as e:
        await asyncio.to_thread(_liberer, x_idempotence)
        raise HTTPException(507 if "espace" in str(e) else 413, str(e)) from None
    except BaseException:
        await asyncio.to_thread(_liberer, x_idempotence)
        raise
    manifeste = {"empreinte": empreinte, "taille": taille, "format": format, "licence": licence,
                 "provenance": provenance, "classe": classe, "donnees_personnelles": donnees_personnelles}
    if fraicheur_s:
        manifeste["fraicheur_s"] = fraicheur_s
    try:
        rep = await asyncio.to_thread(_relayer, request, f"/self/dataset/{service_id}/version", manifeste, x_idempotence)
    except BaseException:
        # Réservation libérée et objet effacé SEULEMENT sur un refus certain (rien de signé). Indéterminé (5xx) : l'objet
        # reste (l'annuaire a peut-être publié la version) ; ranger() l'efface après un jour s'il n'est cité par rien.
        if not getattr(request.state, "signe", False):
            await asyncio.to_thread(_liberer, x_idempotence)
            await asyncio.to_thread(_effacer_si_orphelin, empreinte)
        raise
    await asyncio.to_thread(_noter_objet, empreinte, taille)
    return rep


def _noter_objet(empreinte: str, taille: int) -> None:
    cx = _base(ecriture=True)
    try:
        soi = _soi() or "soi"
        objets.noter(cx, empreinte, taille, soi)
        # Contenu identique à une copie déjà gardée : le dépôt local en reprend la propriété (#3659, relecture).
        cx.execute("UPDATE objet SET source = ? WHERE empreinte = ?", (soi, empreinte))
    finally:
        cx.close()


def _effacer_si_orphelin(empreinte: str) -> None:
    """Dépôt refusé par l'annuaire : l'objet n'est gardé que s'il sert déjà une autre version connue."""
    cx = _base(ecriture=True)
    try:
        if cx.execute("SELECT 1 FROM dataset_version WHERE empreinte = ?", (empreinte,)).fetchone() is None:
            objets.supprimer(cx, empreinte)
    finally:
        cx.close()


class Retrait(BaseModel):
    model_config = ConfigDict(extra="forbid")
    empreinte: str = Field(..., pattern=r"^b2:[0-9a-f]{64}$")
    motif: str = Field("", max_length=200)


@router.post("/datasets/{service_id}/retract", dependencies=[Depends(require_jwt)])
def retirer(service_id: str, req: Retrait, request: Request, x_idempotence: Optional[str] = Header(None)):
    if not _ID.match(service_id):
        raise HTTPException(404, "jeu inconnu")
    deja = _idempotent(x_idempotence, "retirer", service_id + req.empreinte)
    if deja is not None:
        return deja
    with _geste(x_idempotence, request):
        return _relayer(request, f"/self/dataset/{service_id}/retract", req.model_dump(), x_idempotence)


def _preuve_maillage() -> str:
    """Secret de l'écouteur maillé, remis par systemd (LoadCredential=pair-preuve) ; absent : route fermée."""
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    if not d:
        return ""
    try:
        v = Path(d, "pair-preuve").read_text(encoding="ascii").strip()
    except OSError:
        return ""
    return v if re.fullmatch(r"[0-9a-f]{64}", v) else ""


pair = APIRouter()


@pair.get("/pair/objets/{empreinte}")
def servir_objet(empreinte: str, request: Request):
    """Objet d'une version servi à un PAIR du maillage (#3653), joint seulement par l'écouteur :8799 qui pose
    X-SecuBox-Pair-IP ($remote_addr) — jamais par l'hôte d'administration (préfixe /api/v1/mirrornet/ seulement).
    Abonnement Actif du pair à une version non retirée de CE nœud, classe autre que « privé » ; sinon 404 sans détail."""
    if not objets.EMPREINTE.match(empreinte):
        raise HTTPException(404, "objet inconnu")
    preuve, attendue = request.headers.get("x-secubox-pair-preuve", ""), _preuve_maillage()
    if not attendue or not hmac.compare_digest(preuve.encode(), attendue.encode()):
        # Sans la preuve posée par nginx, l'adresse annoncée ne vaut rien (un appelant local de la socket la forgerait).
        raise HTTPException(404, "objet inconnu")
    ip = request.headers.get("x-secubox-pair-ip")
    cx = _base()
    try:
        refus = transfert.autoriser(cx, ip, empreinte)
    finally:
        cx.close()
    if refus is not None or not objets.present(empreinte):
        log.info("mirrornet : objet %s refusé à %s : %s", empreinte[:19], ip, refus or "absent du dépôt")
        raise HTTPException(404, "objet inconnu")
    try:
        f = open(objets.chemin(empreinte), "rb")       # ouvert AVANT de prendre un emplacement : rien à rendre si absent
    except (OSError, objets.RefusObjet):
        raise HTTPException(404, "objet inconnu") from None
    jeton = _prendre_service(ip or "")
    if jeton is None:
        f.close()
        # Le nœud qui sert décide (#3661) : saturé (globalement ou pour ce pair), il le dit ; l'abonné passe à la suite.
        raise HTTPException(503, "transferts simultanés au plafond", headers={"Retry-After": "60"})
    taille = os.fstat(f.fileno()).st_size

    def flux():
        try:
            while True:
                m = f.read(256 * 1024)
                if not m:
                    return
                yield m
        finally:
            f.close()
            _rendre_service(jeton)
    return StreamingResponse(flux(), media_type="application/octet-stream", headers={"Content-Length": str(taille)})


# Emplacements de transfert : jeton -> (pair, début). Plafond global `[espace] service_simultane`, au plus
# PAR_PAIR par pair ; un emplacement plus vieux que PERIME_S est réputé perdu (client parti sans que le flux soit
# refermé) et repris — le compteur ne peut pas rester bloqué au plafond.
_SERVICE: Dict[int, tuple] = {}
_VERROU_SERVICE = threading.Lock()
PAR_PAIR = 2
PERIME_S = 1800
_COMPTEUR = {"n": 0}


def _prendre_service(pair: str) -> Optional[int]:
    maintenant = time.monotonic()
    with _VERROU_SERVICE:
        for k in [k for k, (_p, t0) in _SERVICE.items() if maintenant - t0 > PERIME_S]:
            _SERVICE.pop(k, None)
        if len(_SERVICE) >= config.reglages()["service_simultane"]:
            return None
        if sum(1 for p, _t in _SERVICE.values() if p == pair) >= PAR_PAIR:
            return None
        _COMPTEUR["n"] += 1
        _SERVICE[_COMPTEUR["n"]] = (pair, maintenant)
        return _COMPTEUR["n"]


def _rendre_service(jeton: int) -> None:
    with _VERROU_SERVICE:
        _SERVICE.pop(jeton, None)


@pair.get("/pair/preuve/{empreinte}")
def servir_preuve(empreinte: str, request: Request, defi: str = Query("", max_length=64)):
    """Preuve de possession (#3661) : BLAKE2b-256 de l'objet, clé = défi du producteur. Seulement à l'ORIGINE d'une
    copie gardée ici, par l'écouteur maillé (preuve nginx), une fois par minute et par objet ; sinon 404 sans détail."""
    if not objets.EMPREINTE.match(empreinte) or not re.fullmatch(r"[0-9a-f]{64}", defi):
        raise HTTPException(404, "objet inconnu")
    jeton, attendue = request.headers.get("x-secubox-pair-preuve", ""), _preuve_maillage()
    if not attendue or not hmac.compare_digest(jeton.encode(), attendue.encode()):
        raise HTTPException(404, "objet inconnu")
    ip = request.headers.get("x-secubox-pair-ip")
    cx = _base()
    try:
        refus = presence.autoriser_preuve(cx, ip, empreinte)
    finally:
        cx.close()
    if refus is not None or not objets.present(empreinte):
        log.info("mirrornet : preuve de %s refusée à %s : %s", empreinte[:19], ip, refus or "absent du dépôt")
        raise HTTPException(404, "objet inconnu")
    if not presence.CALCUL.acquire(blocking=False):
        raise HTTPException(503, "preuve déjà en calcul", headers={"Retry-After": "60"})
    try:
        return {"empreinte": empreinte, "preuve": presence.preuve(empreinte, bytes.fromhex(defi))}
    except OSError:
        raise HTTPException(404, "objet inconnu") from None
    finally:
        presence.CALCUL.release()


app = FastAPI(title="SecuBox MirrorNet", version="0.5.0", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=_vie)
app.include_router(router)
app.include_router(pair)
