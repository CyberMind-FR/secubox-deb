# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: SBX Identity Manager — l'API (#1422, docs/AUTH_V3.md)
CyberMind — https://cybermind.fr

Un seul module pour l'identité SBX OS : qui je suis, mes appareils, mes
certificats (double signature réelle), l'administration SBX OS, le nœud du
maillage. KISS : il LIT ce qui existe (appareils admis de secubox-acces),
et pour révoquer il passe par l'instance d'acces chargée dans le même
processus — acces garde sa file en mémoire, l'écrire par derrière la
ferait écraser.

Qui appelle ? Une session SecuBox (cookie ou Bearer), vérifiée par
secubox_core. La session désigne un APPAREIL (par son jti, noté par acces à
l'ouverture), l'appareil désigne une PERSONNE. Les comptes système n'ont
pas d'identité SBX OS ; un administrateur système peut toutefois ouvrir
l'administration SBX OS (c'est l'exploitant).
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core import auth as _auth
from secubox_core import capacites as _cap
from secubox_core import sbxid as S
from secubox_core import user_store

from . import comptes, store

log = logging.getLogger("secubox.sbxid")
app = FastAPI(title="SBX Identity Manager", version="0.1.0")

DELEGATIONS = Path(os.environ.get("SECUBOX_WEBOS_ACCES", "/etc/secubox/secrets/webos-acces"))
_QUI_OK = "abcdefghijklmnopqrstuvwxyz0123456789._-"   # même règle que webos/acces.qui_sur
NODE_KEY = Path(os.environ.get("SBXID_NODE_KEY", "/etc/secubox/secrets/annuaire/node.key"))
_CERTS_EN_COURS: Dict[str, Dict[str, Any]] = {}      # serial → {payload, device, expire}


# ── Nœud ───────────────────────────────────────────────────────────────────
def _graine() -> Optional[str]:
    try:
        g = NODE_KEY.read_text().strip()
        return g if len(g) == 64 else None
    except OSError:
        return None


def _noeud() -> Optional[S.Node]:
    g = _graine()
    return S.Node.depuis_cle(S.pub_noeud(g)) if g else None


_DB = None


# UNE CONNEXION PAR THREAD (#1462). FastAPI sert les routes synchrones dans un
# pool de threads ; une connexion SQLite unique, créée par l'un, levait
# ProgrammingError dans les autres — invisible tant que les appels venaient un
# par un, 500 dès que l'admin Utilisateurs en a lancé trois ensemble.
# `_DB` est le jeton de GÉNÉRATION : None = (ré)ouvrir (et importer) ; les tests
# le remettent à None pour repartir d'une base neuve.
_LOCAL = threading.local()


def db():
    global _DB
    if _DB is None:
        _DB = object()
        c = store.ouvre()
        _LOCAL.c, _LOCAL.gen = c, _DB
        n = _noeud()
        try:
            r = store.importe_existant(c, n.did if n else "did:plc:" + "0" * 32)
            if r["appareils"]:
                log.info("sbxid : import %s", r)
        except Exception as e:                        # l'import ne doit jamais empêcher de servir
            log.error("sbxid : import impossible : %s", e)
        return c
    if getattr(_LOCAL, "gen", None) is not _DB:
        _LOCAL.c, _LOCAL.gen = store.ouvre(), _DB
    return _LOCAL.c


# ── Qui appelle ────────────────────────────────────────────────────────────
def _charge_session(request: Request) -> Dict[str, Any]:
    jetons = []
    a = request.headers.get("Authorization", "")
    if a.startswith("Bearer "):
        jetons.append(a[7:].strip())
    if request.cookies.get("secubox_session"):
        jetons.append(request.cookies["secubox_session"])
    for j in jetons:
        p = _auth._validate_token(j)
        if p:
            return p
    raise HTTPException(401, "Session requise — ouvrez le Hall depuis un appareil admis")


def _demandes() -> List[Dict[str, Any]]:
    try:
        b = json.loads(store.DEMANDES.read_text())
        return b.get("demandes", []) if isinstance(b, dict) else b
    except (OSError, ValueError):
        return []


def _appareil_de_session(p: Dict[str, Any]):
    """Le jti désigne l'appareil (acces le note à l'ouverture) ; à défaut le
    sub `sbx-<empreinte>` d'un appareil non rattaché."""
    jti, sub = p.get("jti", ""), p.get("sub", "")
    for d in _demandes():
        cle = d.get("cle_publique", "")
        if (jti and jti in (d.get("jtis") or [])) or (sub.startswith("sbx-") and cle
                                                      and "sbx-" + S.empreinte_cle(cle)[:12] == sub):
            try:
                return store.appareil_par_did(db(), S.did_appareil(cle))
            except S.Refus:
                return None
    return None


def _systeme_admin(sub: str) -> bool:
    u = user_store.get_user(sub) or {}
    return u.get("role") == "admin" and u.get("enabled", True)


def _rafraichit() -> None:
    """Un appareil admis entre-temps devient une personne (import idempotent)."""
    n = _noeud()
    try:
        store.importe_existant(db(), n.did if n else "did:plc:" + "0" * 32)
    except Exception as e:
        log.error("sbxid : rafraîchissement : %s", e)


def moi(request: Request) -> Dict[str, Any]:
    p = _charge_session(request)
    _rafraichit()
    dev = _appareil_de_session(p)
    ctx = {"sub": p.get("sub", ""), "device": dict(dev) if dev else None, "user": None,
           "systeme": _systeme_admin(p.get("sub", ""))}
    if dev and not dev["revoked_at"] and dev["user_uuid"]:
        ctx["user"] = store.personne(db(), dev["user_uuid"])
    elif dev is None:
        # SESSION DE COMPTE SANS APPAREIL (#1452, même règle que #1450) : ouverte
        # par mot de passe, elle désigne la personne unique propriétaire des
        # appareils acceptés pour ce compte (gk2 → gandalf). Sans appareil de
        # session, rien ne se signe : le certificat reste exigé DEPUIS l'appareil.
        per = _cap.personne_du_porteur(p)
        if per:
            ctx["user"] = store.personne(db(), per["user_uuid"])
            ctx["par_compte"] = True
    return ctx


def exige_admin(request: Request) -> Dict[str, Any]:
    ctx = moi(request)
    caps = (ctx["user"] or {}).get("capabilities", [])
    if not (ctx["systeme"] or "admin.users" in caps):
        raise HTTPException(403, "Capacité requise : admin.users")
    return ctx


def _acteur(ctx) -> str:
    return (ctx.get("user") or {}).get("pseudo") or ctx.get("sub") or "?"


# ── Routes ─────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    n = _noeud()
    return {"ok": True, "module": "sbxid", "version": app.version, "node": n.did if n else None}


def _connexions(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Les CONNEXIONS LIÉES (#1442) : sous quel compte la session est ouverte,
    à quel compte chaque appareil est rattaché, les liens d'application, les
    services délégués par le Hall. Des NOMS, jamais un secret."""
    sub = ctx.get("sub", "")
    uid = (ctx.get("user") or {}).get("user_uuid")
    par_did = {S.did_appareil(d["cle_publique"]): d for d in _demandes()
               if d.get("cle_publique") and d.get("etat") == "acceptee"}
    rattachements = []
    if uid:
        for a in db().execute("SELECT device_name, did FROM sbx_devices WHERE user_uuid=? AND revoked_at IS NULL", (uid,)):
            d = par_did.get(a["did"], {})
            rattachements.append({"appareil": a["device_name"], "compte": d.get("compte") or None,
                                  "courant": bool(ctx.get("device")) and ctx["device"]["did"] == a["did"]})
    qui = "".join(c for c in sub.lower() if c in _QUI_OK)[:64] or "_"
    try:
        services = sorted(f.stem for f in (DELEGATIONS / qui).glob("*.json"))
    except OSError:
        services = []
    liens = [dict(r) for r in db().execute("SELECT app, app_handle FROM sbx_app_links WHERE user_uuid=?", (uid,))] if uid else []
    return {"session_compte": sub, "compte_systeme": ctx.get("systeme", False),
            "appareil_courant": (ctx.get("device") or {}).get("device_name"),
            "rattachements": rattachements, "liens": liens, "services": services}


@app.get("/moi")
def route_moi(ctx=Depends(moi)):
    if not ctx["user"]:
        return {"identite": None, "systeme": ctx["systeme"], "sub": ctx["sub"], "connexions": _connexions(ctx),
                "motif": "Cette session n'est pas celle d'un appareil SBX OS "
                         + ("(compte système : administration seulement)" if ctx["systeme"] else "admis")}
    uid = ctx["user"]["user_uuid"]
    return {"identite": ctx["user"], "appareil_courant": (ctx["device"] or {}).get("device_uuid"),
            "par_compte": ctx["sub"] if ctx.get("par_compte") else None, "connexions": _connexions(ctx),
            "appareils": store.appareils_de(db(), uid), "systeme": ctx["systeme"],
            "liens": [dict(r) for r in db().execute("SELECT app, app_handle FROM sbx_app_links WHERE user_uuid=?", (uid,))]}


def _mon_appareil(ctx, device_uuid: str, admin_ok: bool = True):
    d = db().execute("SELECT * FROM sbx_devices WHERE device_uuid=?", (device_uuid,)).fetchone()
    if not d:
        raise HTTPException(404, "Appareil inconnu")
    a_moi = ctx["user"] and d["user_uuid"] == ctx["user"]["user_uuid"]
    admin = ctx["systeme"] or "admin.users" in (ctx["user"] or {}).get("capabilities", [])
    if not (a_moi or (admin_ok and admin)):
        raise HTTPException(403, "Cet appareil n'est pas le vôtre")
    return d


class Renomme(BaseModel):
    nom: str = Field(min_length=1, max_length=60)


@app.patch("/appareils/{device_uuid}")
def renomme(device_uuid: str, r: Renomme, ctx=Depends(moi)):
    d = _mon_appareil(ctx, device_uuid)
    db().execute("UPDATE sbx_devices SET device_name=? WHERE device_uuid=?", (r.nom.strip(), device_uuid))
    store.journal(db(), _acteur(ctx), "device.renamed", f"{d['device_name']} → {r.nom.strip()}")
    return {"ok": True}


def _module_acces():
    """L'instance d'acces chargée dans CE processus (l'agrégateur)."""
    for m in list(sys.modules.values()):
        if getattr(m, "__name__", "").endswith("main") and callable(getattr(m, "profileur", None)) \
                and hasattr(m, "_coupe_sessions"):
            return m
    return None


@app.post("/appareils/{device_uuid}/revoquer")
def revoque(device_uuid: str, ctx=Depends(moi)):
    d = _mon_appareil(ctx, device_uuid)
    if d["revoked_at"]:
        return {"ok": True, "deja": True}
    acc = _module_acces()
    if acc is None:
        raise HTTPException(503, "secubox-acces indisponible : révocation impossible sans lui")
    from secubox_core import appareils as _app
    avant = acc.profileur().demande_de(d["did"])
    jtis = list(avant.jtis) if avant else []
    compte = (avant.compte or ("sbx-" + S.empreinte_cle(d["public_key"])[:12])) if avant else ""
    if avant:
        acc.profileur().revoque(d["did"], par=_acteur(ctx))
    _app.revoque("sbx-" + S.empreinte_cle(d["public_key"])[:12])
    acc._coupe_sessions(compte, jtis)
    now = int(time.time())
    db().execute("UPDATE sbx_devices SET revoked_at=? WHERE device_uuid=?", (now, device_uuid))
    db().execute("UPDATE sbx_certificates SET revoked_at=? WHERE device_uuid=? AND revoked_at IS NULL", (now, device_uuid))
    store.journal(db(), _acteur(ctx), "device.revoked", f"{d['device_name']} · {len(jtis)} session(s) coupée(s)")
    return {"ok": True, "sessions_coupees": len(jtis)}


# ── Certificat à double signature ──────────────────────────────────────────
@app.post("/appareils/{device_uuid}/certificat/preparer")
def prepare(device_uuid: str, ctx=Depends(moi)):
    """Le serveur prépare la charge ; l'APPAREIL la signe (sa clé ne sort pas)."""
    d = _mon_appareil(ctx, device_uuid, admin_ok=False)
    if d["revoked_at"]:
        raise HTTPException(409, "Appareil révoqué")
    if not ctx["device"] or ctx["device"]["device_uuid"] != device_uuid:
        raise HTTPException(409, "Un certificat se signe depuis l'appareil concerné")
    n = _noeud()
    if not n:
        raise HTTPException(503, "Clé du nœud illisible")
    u = ctx["user"]
    user = S.User(u["user_uuid"], u["home_node"], u["pseudo"], epoch=u["epoch"],
                  roles=[r for r in u["roles"] if r != "subscriber"], tier=u["tier"])
    dev = S.Device(device_uuid, u["user_uuid"], d["public_key"])
    cert = S.nouveau_certificat("device", user, dev, node=n)
    _CERTS_EN_COURS[cert.payload["serial"]] = {"payload": cert.payload, "device": device_uuid,
                                               "expire": time.time() + 300}
    return {"serial": cert.payload["serial"], "message_hex": cert.message_user().hex(),
            "payload": cert.payload}


class Signature(BaseModel):
    serial: str
    sig_user: str = Field(pattern=r"^[0-9a-fA-F]{128}$")


@app.post("/appareils/{device_uuid}/certificat/signer")
def signe(device_uuid: str, s: Signature, ctx=Depends(moi)):
    d = _mon_appareil(ctx, device_uuid, admin_ok=False)
    en = _CERTS_EN_COURS.pop(s.serial, None)
    if not en or en["device"] != device_uuid or en["expire"] < time.time():
        raise HTTPException(410, "Préparation expirée : recommencer")
    dev = S.Device(device_uuid, ctx["user"]["user_uuid"], d["public_key"])
    cert = S.Certificate(payload=en["payload"], signer_device=device_uuid, sig_user=s.sig_user.lower())
    if not S.verifie_appareil(dev.public_key, cert.message_user(), cert.sig_user):
        raise HTTPException(422, "Signature de l'appareil invalide")
    S.contresigne_par_le_noeud(cert, _graine())
    v = S.verifie_certificat(cert, cle_noeud=_noeud().pubkey, appareils={device_uuid: dev})
    if not v.valide:
        raise HTTPException(500, f"certificat invalide après signature : {v.motif}")
    p = cert.payload
    db().execute("INSERT INTO sbx_certificates VALUES (?,?,?,?,?,?,?,?,NULL)",
                 (p["serial"], p["kind"], p["user_uuid"], device_uuid, p["epoch"], p["issued"], p["expires"],
                  json.dumps(cert.en_dict())))
    db().execute("UPDATE sbx_devices SET trust_level='trusted' WHERE device_uuid=?", (device_uuid,))
    store.journal(db(), _acteur(ctx), "certificate.issued", f"{d['device_name']} · {p['serial'][:8]}")
    return {"ok": True, "yaml": S.en_yaml(cert), "certificat": cert.en_dict()}


@app.get("/appareils/{device_uuid}/certificat")
def lit_certificat(device_uuid: str, ctx=Depends(moi)):
    _mon_appareil(ctx, device_uuid)
    r = db().execute("SELECT body FROM sbx_certificates WHERE device_uuid=? AND revoked_at IS NULL"
                     " ORDER BY issued DESC LIMIT 1", (device_uuid,)).fetchone()
    if not r:
        raise HTTPException(404, "Aucun certificat pour cet appareil")
    b = json.loads(r[0])
    return {"yaml": S.en_yaml(S.Certificate(**b)), "certificat": b}


# ── Administration SBX OS ──────────────────────────────────────────────────
@app.get("/roles")
def roles(ctx=Depends(moi)):
    lib = {r[0]: (r[1], bool(r[2])) for r in db().execute("SELECT role_id,label,derived FROM sbx_roles")}
    return {"capacites": list(S.CAPACITES), "roles": [
        {"id": k, "label": lib.get(k, (k, False))[0], "derive": lib.get(k, (k, False))[1], "capacites": v}
        for k, v in store.table_roles(db()).items()]}


@app.get("/admin/personnes")
def personnes(ctx=Depends(exige_admin)):
    _rafraichit()
    out = []
    for r in db().execute("SELECT user_uuid FROM sbx_users ORDER BY pseudo"):
        p = store.personne(db(), r[0])
        p["appareils"] = len([a for a in store.appareils_de(db(), r[0]) if not a["revoked_at"]])
        p["liens"] = comptes.liens(db(), r[0])
        out.append(p)
    return {"personnes": out}


@app.get("/admin/appareils")
def appareils(ctx=Depends(exige_admin)):
    """#1460 : chaque COMPTE D'APPAREIL (`sbx-<empreinte>`, le nom qu'on lit
    dans les sessions) → la personne, l'appareil, l'état de sa demande. Pour
    que l'admin Utilisateurs dise « gandalf · iPhone » et non une empreinte."""
    _rafraichit()
    out = {}
    for d in _demandes():
        cle = d.get("cle_publique")
        if not cle:
            continue
        try:
            compte, did = "sbx-" + S.empreinte_cle(cle)[:12], S.did_appareil(cle)
        except (S.Refus, ValueError):
            continue
        dev = store.appareil_par_did(db(), did)
        pseudo = None
        if dev and dev["user_uuid"]:
            r = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (dev["user_uuid"],)).fetchone()
            pseudo = r[0] if r else None
        out[compte] = {"pseudo": pseudo, "appareil": (dev["device_name"] if dev else None) or d.get("appareil") or d.get("nom"),
                       "etat": d.get("etat"), "revoque": bool(dev and dev["revoked_at"]),
                       "compte_rattache": d.get("compte") or None}
    return {"appareils": out}


class NouvellePersonne(BaseModel):
    pseudo: str = Field(min_length=2, max_length=32)
    role: str = "member"
    email: Optional[str] = Field(default=None, max_length=200)      # adresse de RÉCUPÉRATION, externe


@app.post("/admin/personnes")
def cree_personne(n: NouvellePersonne, ctx=Depends(exige_admin)):
    """Une personne SBX OS sans appareil encore (#1456) : ses comptes de services
    peuvent l'attendre ; son premier appareil lui sera RATTACHÉ à l'admission."""
    pseudo = n.pseudo.strip().lower()
    if not comptes.RE_NOM.match(pseudo) or pseudo in S.COMPTES_SYSTEME:
        raise HTTPException(400, "Pseudo : a-z 0-9 . _ - (2 à 32), jamais un compte système")
    if db().execute("SELECT 1 FROM sbx_users WHERE pseudo=?", (pseudo,)).fetchone():
        raise HTTPException(409, f"« {pseudo} » existe déjà")
    try:
        roles = S.roles_effectifs([n.role])
    except S.Refus as e:
        raise HTTPException(400, str(e))
    n_ = _noeud()
    uid = str(uuid.uuid4())
    db().execute("INSERT INTO sbx_users (user_uuid,pseudo,email,home_node,created_at) VALUES (?,?,?,?,?)",
                 (uid, pseudo, (n.email or "").strip() or None, n_.did if n_ else "did:plc:" + "0" * 32, int(time.time())))
    for x in roles:
        db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (uid, x, _acteur(ctx), int(time.time())))
    store.journal(db(), _acteur(ctx), "user.created", f"{pseudo} · {', '.join(roles)}")
    return store.personne(db(), uid)


def _comptes(f, *a):
    try:
        return f(db(), *a)
    except comptes.Refus as e:
        raise HTTPException(e.code, e.detail)


@app.get("/admin/personnes/{user_uuid}/comptes")
def comptes_de(user_uuid: str, ctx=Depends(exige_admin)):
    return _comptes(comptes.etat, user_uuid)


class Services(BaseModel):
    services: List[str]


# TRAVAIL EN ARRIÈRE-PLAN (#1458) : ouvrir un compte peut d'abord réveiller
# un module endormi (PeerTube : une minute et plus) ; HAProxy coupe une requête
# muette au bout de 30 s, et le mot de passe — rendu UNE fois — serait perdu
# avec elle. La route lance donc le travail et rend la main ; l'écran relit
# /comptes/travail jusqu'au résultat, qui n'est remis qu'une fois.
_TRAVAUX: Dict[str, Dict[str, Any]] = {}
_TRAVAUX_VERROU = threading.Lock()


def _travail(user_uuid: str, faire, evenement: str, acteur: str) -> Dict[str, Any]:
    with _TRAVAUX_VERROU:
        if (_TRAVAUX.get(user_uuid) or {}).get("etat") == "en_cours":
            raise HTTPException(409, "Un travail est déjà en cours pour cette personne")
        _TRAVAUX[user_uuid] = {"etat": "en_cours", "depuis": int(time.time())}

    def corps():
        c = store.ouvre()                        # SA connexion : autre thread
        try:
            r = faire(c)
            store.journal(c, acteur, evenement, f"{user_uuid[:8]} : " + ", ".join(
                f"{k}={'ok' if x is True else 'échec'}" for k, x in r["services"].items()))
            res = {"etat": "fini", **r}
        except comptes.Refus as e:
            res = {"etat": "echec", "code": e.code, "detail": e.detail}
        except Exception as e:                   # jamais un travail « en cours » éternel
            log.exception("sbxid : travail de comptes")
            res = {"etat": "echec", "code": 500, "detail": type(e).__name__}
        finally:
            c.close()
        with _TRAVAUX_VERROU:
            _TRAVAUX[user_uuid] = res
    threading.Thread(target=corps, daemon=True, name=f"comptes-{user_uuid[:8]}").start()
    return {"travail": "en_cours"}


@app.post("/admin/personnes/{user_uuid}/comptes")
def ouvre_comptes(user_uuid: str, v: Services, ctx=Depends(exige_admin)):
    _comptes(comptes._pseudo, user_uuid)          # 404/409 tout de suite, pas après le réveil
    return _travail(user_uuid, lambda c: comptes.cree(c, user_uuid, v.services), "services.created", _acteur(ctx))


@app.post("/admin/personnes/{user_uuid}/comptes/reinitialiser")
def reinitialise_comptes(user_uuid: str, ctx=Depends(exige_admin)):
    if not comptes.liens(db(), user_uuid).keys() & set(comptes.SERVICES):
        raise HTTPException(409, "Aucun compte de service lié à cette personne")
    return _travail(user_uuid, lambda c: comptes.reinitialise(c, user_uuid), "services.password_reset", _acteur(ctx))


@app.get("/admin/personnes/{user_uuid}/comptes/travail")
def travail(user_uuid: str, ctx=Depends(exige_admin)):
    """Le résultat, remis UNE fois (il porte le mot de passe)."""
    with _TRAVAUX_VERROU:
        t = _TRAVAUX.get(user_uuid)
        if not t:
            return {"etat": "aucun"}
        if t["etat"] != "en_cours":
            del _TRAVAUX[user_uuid]
        return t


class LienBbs(BaseModel):
    handle: str = Field(min_length=2, max_length=64)


@app.post("/admin/personnes/{user_uuid}/bbs")
def lie_bbs(user_uuid: str, v: LienBbs, ctx=Depends(exige_admin)):
    """Relier le compte BBS EXISTANT de la personne : ses messages et ses fils
    restent les siens, et la session du Hall l'ouvre sans mot de passe."""
    h = _comptes(comptes.lie_bbs, user_uuid, v.handle)
    store.journal(db(), _acteur(ctx), "link.bbs", f"{user_uuid[:8]} ↔ {h}")
    return {"ok": True, "handle": h}


@app.delete("/admin/personnes/{user_uuid}/liens/{app}/{ident}")
def delie(user_uuid: str, app: str, ident: str, ctx=Depends(exige_admin)):
    _comptes(comptes.delie, user_uuid, app, ident)
    store.journal(db(), _acteur(ctx), "link.removed", f"{user_uuid[:8]} ✕ {app}:{ident}")
    return {"ok": True}


class Roles(BaseModel):
    roles: List[str]


@app.put("/admin/personnes/{user_uuid}/roles")
def fixe_roles(user_uuid: str, r: Roles, ctx=Depends(exige_admin)):
    try:
        voulus = S.roles_effectifs(r.roles)           # refuse inconnus, retire les dérivés
    except S.Refus as e:
        raise HTTPException(400, str(e))
    if not db().execute("SELECT 1 FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone():
        raise HTTPException(404, "Personne inconnue")
    moi_uid = (ctx["user"] or {}).get("user_uuid")
    if user_uuid == moi_uid and "sbx_operator" not in voulus and not ctx["systeme"]:
        raise HTTPException(409, "Vous ne pouvez pas retirer votre propre rôle d'opérateur")
    avant = set(store.roles_de(db(), user_uuid))
    db().execute("DELETE FROM sbx_user_roles WHERE user_uuid=?", (user_uuid,))
    for x in voulus:
        db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (user_uuid, x, _acteur(ctx), int(time.time())))
    pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "roles.set", f"{pseudo} : +{sorted(set(voulus) - avant)} −{sorted(avant - set(voulus))}")
    return store.personne(db(), user_uuid)


class Statut(BaseModel):
    status: str = Field(pattern=r"^(active|suspended)$")


@app.post("/admin/personnes/{user_uuid}/statut")
def fixe_statut(user_uuid: str, s: Statut, ctx=Depends(exige_admin)):
    if user_uuid == (ctx["user"] or {}).get("user_uuid"):
        raise HTTPException(409, "Vous ne pouvez pas vous suspendre vous-même")
    r = db().execute("UPDATE sbx_users SET status=? WHERE user_uuid=?", (s.status, user_uuid))
    if not r.rowcount:
        raise HTTPException(404, "Personne inconnue")
    pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "user." + s.status, pseudo)
    return store.personne(db(), user_uuid)


@app.get("/admin/journal")
def journal(ctx=Depends(exige_admin), n: int = 100):
    return {"evenements": [dict(r) for r in db().execute(
        "SELECT at, actor, event, detail FROM sbx_audit ORDER BY at DESC LIMIT ?", (max(1, min(n, 500)),))]}


@app.get("/admin/demandes")
def demandes(ctx=Depends(exige_admin)):
    """Les demandes d'admission EN ATTENTE, tranchées ici (#1424)."""
    def emp(cle):
        h = S.empreinte_cle(cle)[:24]
        return " ".join(h[i:i + 4] for i in range(0, 24, 4))
    return {"en_attente": [{"did": d.get("did"), "nom": d.get("nom"), "appareil": d.get("appareil"),
                            "message": d.get("message") or "", "email": d.get("email") or "",
                            "demandee_le": d.get("demandee_le"), "empreinte": emp(d["cle_publique"])}
                           for d in _demandes() if d.get("etat") == "en_attente" and d.get("cle_publique")]}


class Decision(BaseModel):
    role: str = "member"
    motif: str = Field(default="", max_length=200)
    #: Rattacher l'appareil à une personne EXISTANTE (#1456) plutôt que d'en
    #: créer une d'après le nom déclaré.
    personne: Optional[str] = None


def _acces_ou_503():
    acc = _module_acces()
    if acc is None:
        raise HTTPException(503, "Module d'accès indisponible dans ce processus")
    return acc


@app.post("/admin/demandes/{did}/accepter")
async def accepte(did: str, dcn: Decision, request: Request, ctx=Depends(exige_admin)):
    """Admettre = 1) ouvrir la porte (acces : l'appareil pourra signer son
    défi), 2) donner une place dans SBX OS (le rôle choisi, ici)."""
    try:
        roles = S.roles_effectifs([dcn.role])
    except S.Refus as e:
        raise HTTPException(400, str(e))
    acc = _acces_ou_503()
    request.state.user = _acteur(ctx)
    out = await acc.accepter(acc.Verdict(did=did), request)
    _rafraichit()
    cle = next((d.get("cle_publique") for d in _demandes() if d.get("did") == did), None)
    dev = store.appareil_par_did(db(), S.did_appareil(cle)) if cle else None
    pseudo = None
    if dev and dcn.personne and dcn.personne != dev["user_uuid"]:
        if not db().execute("SELECT 1 FROM sbx_users WHERE user_uuid=?", (dcn.personne,)).fetchone():
            raise HTTPException(404, "Personne inconnue")
        ancien = dev["user_uuid"]
        db().execute("UPDATE sbx_devices SET user_uuid=? WHERE device_uuid=?", (dcn.personne, dev["device_uuid"]))
        # la personne née de la demande n'a plus rien : on ne laisse pas de fantôme
        if ancien and not db().execute("SELECT 1 FROM sbx_devices WHERE user_uuid=?", (ancien,)).fetchone():
            for t in ("sbx_user_roles", "sbx_app_links", "sbx_preferences"):
                db().execute(f"DELETE FROM {t} WHERE user_uuid=?", (ancien,))
            db().execute("DELETE FROM sbx_users WHERE user_uuid=?", (ancien,))
        dev = store.appareil_par_did(db(), S.did_appareil(cle))
        roles = []                                    # la personne garde SES rôles
    if dev and dev["user_uuid"] and roles:
        db().execute("DELETE FROM sbx_user_roles WHERE user_uuid=?", (dev["user_uuid"],))
        for x in roles:
            db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (dev["user_uuid"], x, _acteur(ctx), int(time.time())))
    if dev and dev["user_uuid"]:
        pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (dev["user_uuid"],)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "invite.validated",
                  f"{pseudo or did} · " + (', '.join(roles) if roles else "rattaché à sa personne"))
    return {"ok": True, "pseudo": pseudo, "roles": roles, "lien": out.get("lien", "")}


@app.post("/admin/demandes/{did}/refuser")
async def refuse(did: str, dcn: Decision, request: Request, ctx=Depends(exige_admin)):
    acc = _acces_ou_503()
    request.state.user = _acteur(ctx)
    await acc.refuser(acc.Verdict(did=did, motif=dcn.motif), request)
    nom = next((d.get("nom") for d in _demandes() if d.get("did") == did), did)
    store.journal(db(), _acteur(ctx), "invite.refused", f"{nom}" + (f" · {dcn.motif}" if dcn.motif else ""))
    return {"ok": True}


# ── Maillage ───────────────────────────────────────────────────────────────
@app.get("/mesh")
def mesh(ctx=Depends(moi)):
    n = _noeud()
    c = db()
    return {"node": {"did": n.did if n else None, "pubkey": n.pubkey if n else None},
            "personnes_hebergees": c.execute("SELECT count(*) FROM sbx_users WHERE status!='departed'").fetchone()[0],
            "migrations": [dict(r) for r in c.execute(
                "SELECT migration_uuid,user_uuid,from_node,to_node,state,updated_at FROM sbx_migrations"
                " ORDER BY updated_at DESC LIMIT 50")],
            "etat": "M5 : la demande et le transfert entre nœuds arrivent avec l'API de migration (AUTH v3 §5)"}
