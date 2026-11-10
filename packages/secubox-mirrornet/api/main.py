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
import json
import logging
import platform
import re
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from secubox_core.auth import require_jwt, require_lecture  # noqa: E402

from secubox_mirrornet import abonnements as A  # noqa: E402
from secubox_mirrornet import annuaire, catalogue, config, ledger, schema  # noqa: E402

log = logging.getLogger("secubox-mirrornet")
router = APIRouter(prefix="/api/v1/mirrornet")
PHASE = 3
RANG = {"OBSERVER": 0, "LIMITED": 1, "PARTNER": 2, "TRUSTED": 3}
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


async def _boucle_synchro() -> None:
    while True:
        try:
            res = await asyncio.to_thread(synchroniser_maintenant)
            if res.get("transitions"):
                log.info("mirrornet : %s changement(s) d'état d'abonnement", res["transitions"])
        except Exception as e:  # noqa: BLE001 — la boucle ne meurt pas, mais elle le dit
            log.warning("mirrornet : passe de synchronisation en échec : %s", e)
        await asyncio.sleep(config.reglages()["intervalle_s"])


@contextlib.asynccontextmanager
async def _vie(_app: FastAPI):
    tache = asyncio.create_task(_boucle_synchro())
    try:
        yield
    finally:
        tache.cancel()


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
    for r in _lignes(_SQL_OFFRE + " WHERE o.kind <> 'dataset' ORDER BY o.nom"):
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


@router.get("/datasets", dependencies=[Depends(require_lecture)])
def datasets() -> Dict[str, Any]:
    rows = [_json(r, "tarif") for r in _lignes(
        "SELECT o.id, o.ref_annuaire, o.fournisseur_did, o.nom, o.classe, o.tarif, o.etat, "
        "(SELECT MAX(numero) FROM dataset_version v WHERE v.offer_id = o.id AND v.retiree = 0) AS derniere_version "
        "FROM offer o WHERE o.kind = 'dataset' ORDER BY o.nom")]
    return {"datasets": rows, "count": len(rows)}


_SQL_ABO = ("SELECT s.ref_annuaire AS id, s.role, s.abonne_did, na.nom AS abonne, o.ref_annuaire AS service_id, "
            "o.nom AS service, o.fournisseur_did, nf.nom AS fournisseur, s.version, s.tarif_accepte, s.renouvellement, "
            "s.demande_le, s.expire_le, s.echeance, s.grace_s, "
            "(SELECT vers FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS etat, "
            "(SELECT motif FROM subscription_event e WHERE e.subscription_id = s.id ORDER BY e.ts DESC, e.rowid DESC LIMIT 1) AS motif "
            "FROM subscription s JOIN offer o ON o.id = s.offer_id JOIN node na ON na.did = s.abonne_did "
            "JOIN node nf ON nf.did = o.fournisseur_did")


@router.get("/subscriptions", dependencies=[Depends(require_jwt)])
def subscriptions() -> Dict[str, Any]:
    """Abonnements de ce nœud (abonné ou fournisseur) et leur état dérivé. Administrateur : relation privée entre nœuds."""
    rows = [_json(r, "tarif_accepte") for r in _lignes(_SQL_ABO + " ORDER BY s.demande_le DESC")]
    return {"subscriptions": rows, "count": len(rows)}


@router.get("/subscriptions/{subscription_id}", dependencies=[Depends(require_jwt)])
def subscription(subscription_id: str) -> Dict[str, Any]:
    if not _ID.match(subscription_id):
        raise HTTPException(404, "abonnement inconnu")
    rows = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (subscription_id,))
    if not rows:
        raise HTTPException(404, "abonnement inconnu")
    r = _json(rows[0], "tarif_accepte")
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
    description: str = Field("", max_length=500)
    version: Optional[str] = Field(None, max_length=64)
    compat: Optional[Dict[str, Any]] = None
    tarif: Optional[Dict[str, Any]] = None
    quotas: Optional[Dict[str, int]] = None
    classe: Optional[str] = Field(None, pattern=r"^(public|communaute|prive)$")
    duree_s: Optional[int] = Field(None, gt=0, le=10 * 365 * 86400)
    grace_s: Optional[int] = Field(None, ge=0, le=90 * 86400)
    sonde: Optional[str] = Field(None, max_length=256, pattern=r"^/[A-Za-z0-9._/~-]*$")


@router.post("/services/publish", dependencies=[Depends(require_jwt)])
def publier(req: Publication, request: Request, x_idempotence: Optional[str] = Header(None)):
    """Publie une offre de CE nœud (signée par l'annuaire). `kind = dataset` attend la phase 4."""
    if req.kind == "dataset":
        raise HTTPException(422, "les jeux de données arrivent en phase 4")
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
        motif = evaluer(offre, _soi(), config.reglages()["confiance_min"])
        if motif:
            raise HTTPException(409, f"abonnement refusé : {motif}")
        en_cours = [r for r in _lignes(_SQL_ABO + " WHERE o.ref_annuaire = ? AND s.role = 'abonne'", (service_id,))
                    if r["etat"] in A.EN_COURS]
        if en_cours:
            res = dict(_json(en_cours[0], "tarif_accepte"), existant=True)
        else:
            version = (req.version if req else None) or offre.get("version")
            corps = {"provider": offre["fournisseur_did"]}            # le fournisseur ÉVALUÉ, lié à l'abonnement
            if version:
                corps["version"] = version
            rep = _relayer(request, f"/self/service/{service_id}/subscribe", corps, x_idempotence)
            sub_id = rep.get("subscription_id") if isinstance(rep, dict) else None
            lignes = _lignes(_SQL_ABO + " WHERE s.ref_annuaire = ?", (sub_id,)) if sub_id else []
            res = (dict(_json(lignes[0], "tarif_accepte"), existant=False) if lignes
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


app = FastAPI(title="SecuBox MirrorNet", version="0.2.0", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=_vie)
app.include_router(router)
