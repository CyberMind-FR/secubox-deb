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

from . import comptes, invitations, store

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
    """Un appareil admis entre-temps devient une personne (import idempotent) ;
    la base suit la file pour les appareils connus, et un appareil admis absent
    du registre y est réinscrit (#1809)."""
    n = _noeud()
    try:
        store.importe_existant(db(), n.did if n else "did:plc:" + "0" * 32)
        store.reconcilie(db())
    except Exception as e:
        log.error("sbxid : rafraîchissement : %s", e)
    acc = _module_acces()
    if acc is not None and hasattr(acc, "reinscris_manquants"):
        try:
            acc.reinscris_manquants()
        except Exception as e:  # noqa: BLE001
            log.error("sbxid : réinscription des appareils : %s", e)


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
    appareils = store.appareils_de(db(), uid)
    sess = store.sessions_par_did(_demandes())
    for a in appareils:                           # #1472 : de quoi distinguer trois iPhone
        v = sess.get(a["did"]) or {}
        a.update(agent=v.get("agent"), ip=v.get("ip"))
        a["last_seen_at"] = a["last_seen_at"] or v.get("vu")
    return {"identite": ctx["user"], "appareil_courant": (ctx["device"] or {}).get("device_uuid"),
            "par_compte": ctx["sub"] if ctx.get("par_compte") else None, "connexions": _connexions(ctx),
            "appareils": appareils, "systeme": ctx["systeme"],
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


def _did_acces(d) -> str:
    """Le DID sous lequel la FILE D'ACCÈS range cet appareil (did:sbx: dérivé de
    la clé par le navigateur) — pas forcément celui de la base."""
    acc = _module_acces()
    if acc is None:
        return d["did"]
    for dem in list(acc.profileur()._demandes.values()):
        if dem.cle_publique.lower() == (d["public_key"] or "").lower():
            return dem.did
    return d["did"]


def _coupe_appareil(d, acteur: str, revoquer: bool) -> int:
    """Coupe les sessions d'un appareil ; le révoque aussi si demandé (#1809).
    Une seule voie pour la révocation, la suspension et la suppression."""
    acc = _module_acces()
    compte_app = "sbx-" + S.empreinte_cle(d["public_key"])[:12]
    if acc is None:
        if revoquer:
            raise HTTPException(503, "secubox-acces indisponible : révocation impossible sans lui")
        # Suspension sans la file : on coupe au moins les sessions du compte
        # d'appareil, directement dans le registre.
        from secubox_core import sessions as _reg
        cibles = set(_reg.jtis_du_compte(compte_app))
        if cibles:
            _reg.muter(lambda rows: [r for r in rows if r.get("id") not in cibles])
        return len(cibles)
    from secubox_core import appareils as _app
    did_a = _did_acces(d)
    avant = acc.profileur().demande_de(did_a)
    jtis = list(avant.jtis) if avant else []
    compte = (avant.compte or compte_app) if avant else compte_app
    if revoquer:
        if avant and avant.etat == "acceptee":
            acc.profileur().revoque(did_a, par=acteur)
        _app.revoque(compte_app)
        now = int(time.time())
        db().execute("UPDATE sbx_devices SET revoked_at=? WHERE device_uuid=? AND revoked_at IS NULL",
                     (now, d["device_uuid"]))
        db().execute("UPDATE sbx_certificates SET revoked_at=? WHERE device_uuid=? AND revoked_at IS NULL",
                     (now, d["device_uuid"]))
    # Les jti suivis, ET toutes les sessions du compte d'appareil (un compte
    # rattaché est celui d'un humain : on ne coupe alors que les jti suivis).
    from secubox_core import sessions as _reg
    if compte == compte_app:
        jtis = sorted(set(jtis) | set(_reg.jtis_du_compte(compte_app)))
    acc._coupe_sessions(compte, jtis)
    return len(jtis)


@app.post("/appareils/{device_uuid}/revoquer")
def revoque(device_uuid: str, ctx=Depends(moi)):
    d = _mon_appareil(ctx, device_uuid)
    if d["revoked_at"]:
        return {"ok": True, "deja": True}
    n = _coupe_appareil(d, _acteur(ctx), revoquer=True)
    store.journal(db(), _acteur(ctx), "device.revoked", f"{d['device_name']} · {n} session(s) coupée(s)")
    return {"ok": True, "sessions_coupees": n}


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
    sess = store.sessions_par_did(_demandes())
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
                       "compte_rattache": d.get("compte") or None,
                       **{k: (sess.get(did) or {}).get(k) for k in ("agent", "ip", "vu")}}
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
    S.emet_activite(db(), "user_joined", author=uid, visibility="node", origin_node=_origine(),
                    context={"via": "administration"})
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


class LienExistant(BaseModel):
    app: str = Field(min_length=2, max_length=20)
    ident: str = Field(min_length=2, max_length=120)


@app.post("/admin/personnes/{user_uuid}/lier")
def lie_existant(user_uuid: str, v: LienExistant, ctx=Depends(exige_admin)):
    """Relier un compte de service EXISTANT (#1468) — vérifié, jamais créé ; il
    garde son mot de passe."""
    if v.app == "bbs":
        return lie_bbs(user_uuid, LienBbs(handle=v.ident), ctx)
    ident = _comptes(comptes.lie_existant, user_uuid, v.app, v.ident)
    store.journal(db(), _acteur(ctx), "link." + v.app, f"{user_uuid[:8]} ↔ {ident} (mot de passe propre)")
    return {"ok": True, "app": v.app, "ident": ident}


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
    # SUSPENDRE COUPE (#1809) : avant, seul le drapeau changeait — sessions,
    # appareils et comptes de services continuaient de servir. Les appareils
    # ne sont PAS révoqués (la réactivation les rend) : la file d'accès refuse
    # d'ouvrir une session tant que la personne est suspendue.
    devs = db().execute("SELECT * FROM sbx_devices WHERE user_uuid=? AND revoked_at IS NULL",
                        (user_uuid,)).fetchall()
    coupees = 0
    if s.status == "suspended":
        for d in devs:
            coupees += _coupe_appareil(d, _acteur(ctx), revoquer=False)
        services = comptes.desactive_ouverts(db(), user_uuid)
    else:
        services = comptes.active_ouverts(db(), user_uuid)
    store.journal(db(), _acteur(ctx), "user." + s.status,
                  f"{pseudo} · {coupees} session(s) coupée(s) · services {sorted(services)}")
    return {**store.personne(db(), user_uuid), "sessions_coupees": coupees, "services": services}


@app.delete("/admin/personnes/{user_uuid}")
def supprime_personne(user_uuid: str, comptes_services: str = "garder", ctx=Depends(exige_admin)):
    """SUPPRIMER une personne (#1809) — seulement une fois SUSPENDUE : la
    suspension est la révocation ; la suppression, l'étape suivante, demandée.
    Appareils révoqués puis oubliés, rôles, liens, coffre et fiche effacés ;
    le journal garde une ligne. Les comptes de services ouverts pour elle
    restent DÉSACTIVÉS, sauf `comptes_services=supprimer` (données comprises)."""
    if comptes_services not in ("garder", "supprimer"):
        raise HTTPException(400, "comptes_services : garder | supprimer")
    if user_uuid == (ctx["user"] or {}).get("user_uuid"):
        raise HTTPException(409, "Vous ne pouvez pas vous supprimer vous-même")
    r = db().execute("SELECT pseudo, status FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone()
    if not r:
        raise HTTPException(404, "Personne inconnue")
    if r[1] != "suspended":
        raise HTTPException(409, "Suspendez d'abord cette personne : la suppression suit la révocation")
    acteur = _acteur(ctx)
    acc = _module_acces()
    devs = db().execute("SELECT * FROM sbx_devices WHERE user_uuid=?", (user_uuid,)).fetchall()
    coupees = 0
    for d in devs:
        coupees += _coupe_appareil(d, acteur, revoquer=True)
        if acc is not None:
            acc.profileur().oublie(_did_acces(d), force=True)
        from secubox_core import appareils as _app
        _app.oublie("sbx-" + S.empreinte_cle(d["public_key"])[:12])
    services = comptes.retire_ouverts(db(), user_uuid) if comptes_services == "supprimer" else {}
    from secubox_core import coffre as _coffre
    try:
        _coffre.efface_personne(user_uuid)
    except OSError as e:
        log.error("sbxid : coffre de %s : %s", user_uuid, e)
    pseudo = store.supprime_personne(db(), user_uuid)
    store.journal(db(), acteur, "user.deleted",
                  f"{pseudo} · {len(devs)} appareil(s) · {coupees} session(s) coupée(s) · "
                  f"comptes {comptes_services}{(' ' + str(sorted(services))) if services else ''}")
    return {"ok": True, "pseudo": pseudo, "appareils": len(devs), "sessions_coupees": coupees,
            "comptes_services": comptes_services, "services": services}


@app.post("/admin/appareils/{device_uuid}/oublier")
def oublie_appareil(device_uuid: str, ctx=Depends(exige_admin)):
    """Efface un appareil DÉJÀ RÉVOQUÉ (#1809) : sa ligne, ses certificats, sa
    demande dans la file et son entrée au registre."""
    d = db().execute("SELECT * FROM sbx_devices WHERE device_uuid=?", (device_uuid,)).fetchone()
    if not d:
        raise HTTPException(404, "Appareil inconnu")
    if not d["revoked_at"]:
        raise HTTPException(409, "Révoquez d'abord cet appareil")
    acc = _module_acces()
    if acc is not None:
        acc.profileur().oublie(_did_acces(d), force=True)
    from secubox_core import appareils as _app
    _app.oublie("sbx-" + S.empreinte_cle(d["public_key"])[:12])
    db().execute("DELETE FROM sbx_sessions WHERE device_uuid=?", (device_uuid,))
    db().execute("DELETE FROM sbx_certificates WHERE device_uuid=?", (device_uuid,))
    db().execute("DELETE FROM sbx_devices WHERE device_uuid=?", (device_uuid,))
    store.journal(db(), _acteur(ctx), "device.forgotten", d["device_name"])
    return {"ok": True}


# ── Communautés et autorisations (#1519, Community Refactor P2) ──────────────
# « Allow User » + « Allow Community » : une capacité (qui nomme son module)
# accordée à une personne ou à une communauté. Les règles vivent dans
# secubox_core.sbxid ; ici seulement la garde, le journal et les activités.

@app.get("/activite")
def activite(request: Request, n: int = 50, depuis: int = 0):
    """Le flux d'activités (#1560, P4), filtré pour CELUI qui regarde —
    visiteur compris (le public seulement). Règle unique :
    secubox_core.sbxid.activites_visibles."""
    try:
        per = (moi(request).get("user") or {})
    except HTTPException:
        per = {}
    return {"activites": S.activites_visibles(db(), per.get("user_uuid"), n, depuis)}


def _origine() -> str:
    n = _noeud()
    return n.did if n else "did:plc:" + "0" * 32


def _refus(f, *a, **k):
    try:
        return f(*a, **k)
    except S.Refus as e:
        raise HTTPException(400, str(e))


def _communaute(cid: str) -> Dict[str, Any]:
    r = db().execute("SELECT * FROM sbx_communities WHERE community_uuid=?", (cid,)).fetchone()
    if not r:
        raise HTTPException(404, "Communauté inconnue")
    d = dict(r)
    d["members"] = S.membres(db(), cid)
    d["grants"] = [dict(g) for g in db().execute(
        "SELECT grant_uuid, capability, granted_by, granted_at FROM sbx_grants "
        "WHERE subject_kind='community' AND subject_id=? AND revoked_at IS NULL ORDER BY capability", (cid,))]
    return d


@app.get("/admin/capacites")
def liste_capacites(ctx=Depends(exige_admin)):
    """Ce qui peut s'accorder : les capacités SBX OS, rangées par module."""
    par_module: Dict[str, List[str]] = {}
    for c in S.CAPACITES:
        par_module.setdefault(c.split(".", 1)[0], []).append(c)
    return {"capacites": list(S.CAPACITES), "modules": par_module}


@app.get("/admin/communautes")
def communautes(ctx=Depends(exige_admin), archivees: bool = False):
    q = ("SELECT c.*, (SELECT count(*) FROM sbx_community_members m WHERE m.community_uuid=c.community_uuid) AS n_members "
         "FROM sbx_communities c " + ("" if archivees else "WHERE c.archived_at IS NULL ") + "ORDER BY c.name")
    return {"communautes": [dict(r) for r in db().execute(q)]}


class NouvelleCommunaute(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    visibility: str = Field(default="private", pattern=r"^(private|invited|public)$")
    description: str = Field(default="", max_length=500)
    portrait: Optional[str] = Field(default=None, max_length=64)


@app.post("/admin/communautes")
def cree_communaute(n: NouvelleCommunaute, ctx=Depends(exige_admin)):
    cid = _refus(S.cree_communaute, db(), n.name, home_node=_origine(), created_by=_acteur(ctx),
                 visibility=n.visibility, description=n.description, portrait=n.portrait)
    store.journal(db(), _acteur(ctx), "community.created", f"{n.name.strip()} · {n.visibility}")
    return _communaute(cid)


@app.get("/admin/communautes/{cid}")
def communaute(cid: str, ctx=Depends(exige_admin)):
    return _communaute(cid)


@app.post("/admin/communautes/{cid}/archiver")
def archive_communaute(cid: str, ctx=Depends(exige_admin)):
    c = _communaute(cid)
    db().execute("UPDATE sbx_communities SET archived_at=? WHERE community_uuid=? AND archived_at IS NULL",
                 (int(time.time()), cid))
    store.journal(db(), _acteur(ctx), "community.archived", c["name"])
    return _communaute(cid)


class Appartenance(BaseModel):
    role: str = Field(default="member", pattern=r"^(owner|moderator|member)$")


@app.put("/admin/communautes/{cid}/membres/{user_uuid}")
def ajoute_membre(cid: str, user_uuid: str, a: Appartenance, ctx=Depends(exige_admin)):
    c = _communaute(cid)
    deja = any(m["user_uuid"] == user_uuid for m in c["members"])
    _refus(S.ajoute_membre, db(), cid, user_uuid, role=a.role, added_by=_acteur(ctx))
    pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "community.member", f"{c['name']} : {pseudo} ({a.role})")
    if not deja:
        S.emet_activite(db(), "community_joined", author=user_uuid, visibility="community",
                        community_uuid=cid, origin_node=_origine(), context={"role": a.role})
    return _communaute(cid)


@app.delete("/admin/communautes/{cid}/membres/{user_uuid}")
def retire_membre(cid: str, user_uuid: str, ctx=Depends(exige_admin)):
    c = _communaute(cid)
    if not S.retire_membre(db(), cid, user_uuid):
        raise HTTPException(404, "Cette personne n'est pas membre")
    pseudo = (db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone() or ["?"])[0]
    store.journal(db(), _acteur(ctx), "community.member.removed", f"{c['name']} : {pseudo}")
    return _communaute(cid)


# ── Salons BBS d'une communauté (#1548, D4) ────────────────────────────────
# La BBS tient les salons ; sbxid tient les communautés. On ne duplique rien :
# ces routes RELAIENT le jeton de l'administrateur aux routes d'admin de la BBS
# (#1523), qui le font valider par secubox-auth et journalisent le geste au nom
# de SON compte BBS — comme acces le fait déjà pour les comptes.
BBS_SOCK = os.environ.get("SBXID_BBS_SOCK", "/run/secubox/bbs.sock")


def _jeton(request: Request) -> str:
    a = request.headers.get("authorization", "")
    return a[7:] if a.startswith("Bearer ") else request.cookies.get("secubox_session", "")


def _bbs_http(methode: str, chemin: str, jeton: str, corps: Optional[dict] = None):
    import httpx  # noqa: PLC0415
    with httpx.Client(transport=httpx.HTTPTransport(uds=BBS_SOCK), base_url="http://bbs", timeout=8) as c:
        r = c.request(methode, chemin, json=corps, headers={"Authorization": "Bearer " + jeton})
    try:
        j = r.json()
    except ValueError:
        j = {}
    return r.status_code, j


# Injectable pour les tests.
bbs_appel = _bbs_http


def _bbs(request: Request, methode: str, chemin: str, corps: Optional[dict] = None) -> dict:
    try:
        code, j = bbs_appel(methode, "/api/v1/bbs/admin" + chemin, _jeton(request), corps)
    except Exception as e:  # socket absente, BBS arrêtée
        raise HTTPException(503, f"BBS injoignable ({type(e).__name__})")
    if code != 200:
        raise HTTPException(code if code in (400, 401, 403, 404, 409) else 502, j.get("error") or f"BBS : {code}")
    return j


@app.get("/admin/communautes/{cid}/salons")
def salons_de(cid: str, request: Request, ctx=Depends(exige_admin)):
    """Tous les salons, et pour chacun : privé ? ouvert à CETTE communauté ?"""
    _communaute(cid)
    j = _bbs(request, "GET", "/salons")
    return {"salons": [{"id": x["id"], "titre": x["titre"], "slug": x["slug"], "profondeur": x.get("profondeur", 0),
                        "prive": x.get("prive", False), "fils": x.get("fils", 0),
                        "ouvert": any(c.get("uuid") == cid for c in x.get("communautes") or [])}
                       for x in j.get("salons", [])]}


class SalonCommunaute(BaseModel):
    ouvrir: bool = True
    #: Un salon encore ouvert à tous est d'abord rendu privé : sans quoi
    #: « l'ouvrir à la communauté » ne restreindrait rien (#1548).
    reserver: bool = False


@app.post("/admin/communautes/{cid}/salons/{sid}")
def salon_communaute(cid: str, sid: int, v: SalonCommunaute, request: Request, ctx=Depends(exige_admin)):
    c = _communaute(cid)
    if c.get("archived_at"):
        raise HTTPException(409, "Communauté archivée")
    if v.ouvrir and v.reserver:
        _bbs(request, "POST", f"/salons/{sid}/prive", {"prive": True})
    _bbs(request, "POST", f"/salons/{sid}/communautes",
         {"communaute": cid, "action": "ajouter" if v.ouvrir else "retirer"})
    store.journal(db(), _acteur(ctx), "community.salon" if v.ouvrir else "community.salon.removed",
                  f"{c['name']} ↔ salon {sid}" + (" (réservé)" if v.reserver and v.ouvrir else ""))
    return salons_de(cid, request, ctx)


class Autorisation(BaseModel):
    subject_kind: str = Field(pattern=r"^(user|community)$")
    subject_id: str = Field(min_length=36, max_length=36)
    capability: str = Field(min_length=3, max_length=64)


def _sujet(kind: str, sid: str) -> str:
    t, col = ("sbx_users", "pseudo") if kind == "user" else ("sbx_communities", "name")
    k = "user_uuid" if kind == "user" else "community_uuid"
    r = db().execute(f"SELECT {col} FROM {t} WHERE {k}=?", (sid,)).fetchone()
    return r[0] if r else "?"


@app.post("/admin/autorisations")
def accorde(a: Autorisation, ctx=Depends(exige_admin)):
    gid = _refus(S.accorde, db(), a.subject_kind, a.subject_id, a.capability, granted_by=_acteur(ctx))
    nom = _sujet(a.subject_kind, a.subject_id)
    store.journal(db(), _acteur(ctx), "grant.issued", f"{a.capability} → {a.subject_kind} {nom}")
    S.emet_activite(db(), "permission_granted", author=_acteur(ctx), visibility="node",
                    origin_node=_origine(),
                    context={"capability": a.capability.strip().lower(), "subject_kind": a.subject_kind,
                             "subject": a.subject_id})
    return {"grant_uuid": gid}


@app.delete("/admin/autorisations/{grant_uuid}")
def revoque(grant_uuid: str, ctx=Depends(exige_admin)):
    g = db().execute("SELECT subject_kind, subject_id, capability FROM sbx_grants WHERE grant_uuid=?",
                     (grant_uuid,)).fetchone()
    if not g or not S.revoque_autorisation(db(), grant_uuid):
        raise HTTPException(404, "Autorisation inconnue ou déjà retirée")
    store.journal(db(), _acteur(ctx), "grant.revoked", f"{g[2]} ✕ {g[0]} {_sujet(g[0], g[1])}")
    return {"ok": True}


@app.get("/admin/personnes/{user_uuid}/autorisations")
def autorisations_de(user_uuid: str, ctx=Depends(exige_admin)):
    """D'où vient chaque capacité : directe, ou par quelle communauté."""
    if not db().execute("SELECT 1 FROM sbx_users WHERE user_uuid=?", (user_uuid,)).fetchone():
        raise HTTPException(404, "Personne inconnue")
    directes = [dict(r) for r in db().execute(
        "SELECT grant_uuid, capability, granted_by, granted_at FROM sbx_grants WHERE subject_kind='user' "
        "AND subject_id=? AND revoked_at IS NULL ORDER BY capability", (user_uuid,))]
    par_communaute = [dict(r) for r in db().execute(
        "SELECT g.grant_uuid, g.capability, c.community_uuid, c.name AS community FROM sbx_grants g "
        "JOIN sbx_community_members m ON g.subject_kind='community' AND g.subject_id=m.community_uuid "
        "JOIN sbx_communities c ON c.community_uuid=m.community_uuid "
        "WHERE g.revoked_at IS NULL AND c.archived_at IS NULL AND m.user_uuid=? ORDER BY g.capability",
        (user_uuid,))]
    return {"directes": directes, "par_communaute": par_communaute,
            "effectives": (store.personne(db(), user_uuid) or {}).get("capabilities", [])}


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
    # Une demande en attente depuis plus de 14 jours a EXPIRÉ (même règle que la
    # file) : elle passe dans les closes, qu'on peut oublier (#1809).
    limite = int(time.time()) - 14 * 24 * 3600
    def etat(d):
        e = d.get("etat")
        return "expiree" if e == "en_attente" and int(d.get("demandee_le") or 0) < limite else e
    lignes = [d for d in _demandes() if d.get("cle_publique")]
    revoques = [{"device_uuid": r["device_uuid"], "nom": r["device_name"], "pseudo": r["pseudo"],
                 "revoque_le": r["revoked_at"]}
                for r in db().execute("SELECT d.device_uuid, d.device_name, d.revoked_at, u.pseudo"
                                      " FROM sbx_devices d LEFT JOIN sbx_users u ON u.user_uuid=d.user_uuid"
                                      " WHERE d.revoked_at IS NOT NULL ORDER BY d.revoked_at DESC")]
    return {"en_attente": [{"did": d.get("did"), "nom": d.get("nom"), "appareil": d.get("appareil"),
                            "message": d.get("message") or "", "email": d.get("email") or "",
                            "demandee_le": d.get("demandee_le"), "empreinte": emp(d["cle_publique"])}
                           for d in lignes if etat(d) == "en_attente"],
            "closes": [{"did": d.get("did"), "nom": d.get("nom"), "appareil": d.get("appareil"),
                        "etat": etat(d), "le": d.get("traitee_le") or d.get("demandee_le"),
                        "renouvellements": d.get("renouvellements") or 0}
                       for d in lignes if etat(d) in ("refusee", "expiree")],
            "revoques": revoques}


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


def _rattache_a(dev, personne: str):
    """Rattache un appareil à une personne EXISTANTE ; la personne née de sa
    demande, restée sans rien, ne reste pas en fantôme. Rend l'appareil relu."""
    if not db().execute("SELECT 1 FROM sbx_users WHERE user_uuid=?", (personne,)).fetchone():
        raise HTTPException(404, "Personne inconnue")
    ancien = dev["user_uuid"]
    db().execute("UPDATE sbx_devices SET user_uuid=? WHERE device_uuid=?", (personne, dev["device_uuid"]))
    if ancien and ancien != personne and \
            not db().execute("SELECT 1 FROM sbx_devices WHERE user_uuid=?", (ancien,)).fetchone():
        for t in ("sbx_user_roles", "sbx_app_links", "sbx_preferences"):
            db().execute(f"DELETE FROM {t} WHERE user_uuid=?", (ancien,))
        db().execute("DELETE FROM sbx_users WHERE user_uuid=?", (ancien,))
    return db().execute("SELECT * FROM sbx_devices WHERE device_uuid=?", (dev["device_uuid"],)).fetchone()


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
        dev = _rattache_a(dev, dcn.personne)
        roles = []                                    # la personne garde SES rôles
    if dev and dev["user_uuid"] and roles:
        db().execute("DELETE FROM sbx_user_roles WHERE user_uuid=?", (dev["user_uuid"],))
        for x in roles:
            db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (dev["user_uuid"], x, _acteur(ctx), int(time.time())))
    if dev and dev["user_uuid"]:
        pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (dev["user_uuid"],)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "invite.validated",
                  f"{pseudo or did} · " + (', '.join(roles) if roles else "rattaché à sa personne"))
    services = []
    if dev and dev["user_uuid"] and roles:        # une ARRIVÉE ; un appareil rattaché n'en est pas une
        S.emet_activite(db(), "user_joined", author=dev["user_uuid"], visibility="node",
                        origin_node=_origine(), context={"via": "invitation"})
        # LES SERVICES DU RÔLE S'OUVRENT À L'ARRIVÉE (#1821), comme pour une
        # invitation : plus de second geste « ouvrir ses comptes ».
        uid = dev["user_uuid"]
        services = invitations.services_du_role(dcn.role)
        try:
            _travail(uid, lambda c: comptes.cree(c, uid, services), "services.created", _acteur(ctx))
        except HTTPException:
            services = []                          # un travail déjà en cours pour elle
    return {"ok": True, "pseudo": pseudo, "roles": roles, "lien": out.get("lien", ""),
            "services": services}


@app.post("/admin/demandes/{did}/oublier")
def oublie_demande(did: str, ctx=Depends(exige_admin)):
    """Efface une demande REFUSÉE ou EXPIRÉE de la file (#1809)."""
    acc = _module_acces()
    if acc is None:
        raise HTTPException(503, "secubox-acces indisponible")
    if not acc.profileur().oublie(did):
        raise HTTPException(409, "Seule une demande refusée ou expirée s'oublie")
    store.journal(db(), _acteur(ctx), "request.forgotten", did[:24])
    return {"ok": True}


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


# ── INVITATIONS (#1816, #1802 étape 4) ──────────────────────────────────────
# Une invitation VAUT APPROBATION : le lien fait entrer, sans demande à trancher.
# Les administrateurs invitent avec n'importe quel rôle, un membre seulement
# comme invité ; une personne ajoute elle-même un appareil (QR de 10 minutes).

_CADENCE_PUBLIQUE: Dict[str, list] = {}
CADENCE_PUBLIQUE_PAR_IP = 20


def _cadence_publique(request: Request) -> None:
    from secubox_core.auth import adresse_client
    ip = adresse_client(request) or "?"
    maintenant = time.monotonic()
    essais = [t for t in _CADENCE_PUBLIQUE.get(ip, []) if maintenant - t < 3600]
    if len(essais) >= CADENCE_PUBLIQUE_PAR_IP:
        raise HTTPException(429, "Trop d'essais. Réessayez plus tard.")
    essais.append(maintenant)
    _CADENCE_PUBLIQUE[ip] = essais


def _lien_invitation(code: str) -> str:
    from secubox_core.auth import hote_box
    hote = hote_box("hall")
    base = f"https://{hote}" if hote else ""
    return f"{base}/i/acces/?invitation={code}"


def _qr(url: str) -> str:
    """Le QR du lien, en data: URI — produit côté box, montré une fois."""
    try:
        import base64
        import io
        import qrcode
    except ImportError:
        return ""
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
    q.add_data(url)
    q.make(fit=True)
    t = io.BytesIO()
    q.make_image(fill_color="black", back_color="white").save(t, format="PNG")
    return "data:image/png;base64," + base64.b64encode(t.getvalue()).decode()


def _qui_invite(ctx) -> str:
    """L'identifiant gardé dans `created_by` : la personne, sinon le compte système."""
    return (ctx.get("user") or {}).get("user_uuid") or ("compte:" + (ctx.get("sub") or "?"))


def _pseudo_de(createur: str) -> str:
    if createur.startswith("compte:"):
        return createur.split(":", 1)[1]
    r = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (createur,)).fetchone()
    return r[0] if r else "?"


def _peut_inviter(ctx, role: str) -> None:
    caps = (ctx.get("user") or {}).get("capabilities", [])
    if ctx.get("systeme") or "admin.users" in caps:
        return                                              # administrateur : tout rôle
    u = ctx.get("user") or {}
    roles = set(u.get("roles") or [])
    if u.get("status") == "active" and roles - {"guest"} and role in invitations.ROLES_D_UN_MEMBRE:
        return                                              # membre : invité seulement
    raise HTTPException(403, "Un membre n'invite qu'en tant qu'invité ; inviter avec un autre rôle "
                             "est réservé à l'administration")


class Invitation(BaseModel):
    role: str = "member"
    pseudo: str = Field(default="", max_length=32)
    email: str = Field(default="", max_length=200)


@app.post("/invitations")
def cree_invitation(inv: Invitation, ctx=Depends(moi)):
    """Inviter quelqu'un : lien + QR à usage unique, ~72 h, révocable."""
    try:
        S.roles_effectifs([inv.role])
    except S.Refus as e:
        raise HTTPException(400, str(e))
    _peut_inviter(ctx, inv.role)
    pseudo = inv.pseudo.strip().lower()
    if pseudo:
        if not comptes.RE_NOM.match(pseudo) or pseudo in S.COMPTES_SYSTEME:
            raise HTTPException(400, "Pseudo : a-z 0-9 . _ - (2 à 32), hors comptes système")
        if db().execute("SELECT 1 FROM sbx_users WHERE pseudo=?", (pseudo,)).fetchone():
            raise HTTPException(409, f"« {pseudo} » existe déjà")
    out = invitations.cree(db(), createur=_qui_invite(ctx), role=inv.role, pseudo=pseudo,
                           email=inv.email.strip())
    lien = _lien_invitation(out.pop("code"))
    store.journal(db(), _acteur(ctx), "invite.created", f"{pseudo or '—'} · {inv.role}")
    return {**out, "lien": lien, "qr": _qr(lien)}


@app.post("/appareils/inviter")
def invite_un_appareil(ctx=Depends(moi)):
    """« Ajouter un appareil » : un QR de 10 minutes qui fait entrer un nouvel
    appareil de LA MÊME personne, sans passer par l'administration."""
    u = ctx.get("user")
    if not u or u.get("status") != "active" or ctx.get("device") is None:
        raise HTTPException(403, "Depuis un appareil déjà admis à votre nom")
    out = invitations.cree(db(), createur=u["user_uuid"], role=None)
    lien = _lien_invitation(out.pop("code"))
    store.journal(db(), _acteur(ctx), "invite.device", u.get("pseudo", ""))
    return {**out, "lien": lien, "qr": _qr(lien)}


@app.get("/invitations")
def liste_invitations(ctx=Depends(moi)):
    caps = (ctx.get("user") or {}).get("capabilities", [])
    tout = ctx.get("systeme") or "admin.users" in caps
    lst = invitations.en_cours(db(), None if tout else _qui_invite(ctx))
    for x in lst:
        x["par"] = _pseudo_de(x["par"] or "")
    return {"invitations": lst}


@app.delete("/invitations/{invite_uuid}")
def revoque_invitation(invite_uuid: str, ctx=Depends(moi)):
    caps = (ctx.get("user") or {}).get("capabilities", [])
    createur = invitations.createur_de(db(), invite_uuid)
    if createur is None:
        raise HTTPException(404, "Invitation inconnue")
    if not (ctx.get("systeme") or "admin.users" in caps or createur == _qui_invite(ctx)):
        raise HTTPException(403, "Seul qui l'a créée, ou l'administration, la révoque")
    if not invitations.revoque(db(), invite_uuid, _acteur(ctx)):
        raise HTTPException(409, "Déjà utilisée ou révoquée")
    store.journal(db(), _acteur(ctx), "invite.revoked", invite_uuid[:8])
    return {"ok": True}


@app.get("/invitation/apercu")
def apercu_invitation(code: str, request: Request):
    """Public : qui invite, en tant que quoi. Même réponse pour un code
    inconnu, servi, révoqué ou expiré."""
    _cadence_publique(request)
    try:
        return invitations.apercu(db(), code, _pseudo_de)
    except invitations.Refus as e:
        raise HTTPException(e.code, str(e))


class Rejoindre(BaseModel):
    code: str = Field(max_length=64)
    did: str = Field(max_length=160)
    cle_publique: str = Field(max_length=200)
    #: Le CODE signé par la clé de l'appareil : preuve qu'il la détient. Sans
    #: elle, on aurait pu présenter la clé publique d'un AUTRE appareil.
    signature: str = Field(max_length=200)
    nom: str = Field(default="", max_length=60)
    appareil: str = Field(default="", max_length=60)


@app.post("/invitation/rejoindre")
async def rejoint(r: Rejoindre, request: Request):
    """Public : l'invité REJOINT. Son appareil est admis d'emblée, sa personne
    créée (ou retrouvée, pour un appareil de plus), les services de son rôle
    s'ouvrent en arrière-plan ; il repart avec le jeton de suivi qui ouvre sa
    session par signature."""
    _cadence_publique(request)
    try:
        inv = invitations.valide(db(), r.code)
    except invitations.Refus as e:
        raise HTTPException(e.code, str(e))
    acc = _acces_ou_503()
    try:
        prouve = acc.verifie_signature(r.cle_publique, r.code.encode(), r.signature)
    except Exception:  # noqa: BLE001 — clé ou signature mal formée
        prouve = False
    if not prouve:
        raise HTTPException(403, "Preuve de la clé invalide")
    # Un appareil DÉJÀ admis ne change pas de personne par un lien — reconnu par
    # sa CLÉ, pas seulement par son DID (d'anciennes demandes portent un DID qui
    # ne dérive pas de la clé).
    cle = (r.cle_publique or "").strip().lower()
    try:
        dev_connu = store.appareil_par_did(db(), S.did_appareil(cle))
    except (S.Refus, ValueError):
        raise HTTPException(400, "Clé d'appareil invalide")
    deja = acc.profileur().demande_de(r.did)
    admise = any(d.etat == "acceptee" and d.cle_publique.lower() == cle
                 for d in list(acc.profileur()._demandes.values()))
    if admise or (deja is not None and deja.etat == "acceptee"):
        raise HTTPException(409, "Cet appareil a déjà un accès : ouvrez le lien depuis le nouvel appareil")
    if dev_connu is not None:
        # RÉVOQUÉ MAIS CONNU : il reste attaché à son ancienne personne, qu'un
        # lien « personne » renommerait. L'administration l'oublie d'abord (#1809).
        raise HTTPException(409, "Cet appareil a déjà été connu ici : demandez qu'il soit oublié, "
                                 "ou ouvrez le lien depuis un autre navigateur")
    sorte = "appareil" if inv["role_propose"] is None else "personne"
    cible = inv["created_by"] if sorte == "appareil" else None
    nom = (r.nom or inv["pseudo_propose"] or (_pseudo_de(cible) if cible else "") or "invité").strip()[:60]
    try:
        acc.profileur().demande({"did": r.did, "cle_publique": r.cle_publique, "nom": nom,
                                 "appareil": r.appareil, "message": "invitation",
                                 "email": inv["email"] or ""})
    except Exception as e:  # noqa: BLE001 — DemandeInvalide (400), DemandeTropTot (429)
        raise HTTPException(429 if type(e).__name__ == "DemandeTropTot" else 400, str(e))
    # Usage UNIQUE, atomiquement, AVANT d'admettre : deux appareils qui
    # présenteraient le même lien en même temps, un seul passe.
    if not invitations.consomme(db(), inv["invite_uuid"], device_uuid="(en cours)",
                                par=_pseudo_de(inv["created_by"])):
        raise HTTPException(404, "Invitation inconnue, déjà utilisée ou expirée")
    request.state.user = "invitation:" + _pseudo_de(inv["created_by"])
    try:
        await acc.accepter(acc.Verdict(did=r.did), request)
        _rafraichit()
        dev = store.appareil_par_did(db(), S.did_appareil(r.cle_publique))
        if dev is None:
            raise HTTPException(500, "Appareil admis mais introuvable — réessayez")
        if sorte == "appareil":
            dev = _rattache_a(dev, cible)
    except BaseException:
        # L'admission a échoué : l'invitation n'est pas perdue pour autant.
        db().execute("UPDATE sbx_invites SET validated_at=NULL, validated_by=NULL, device_uuid=NULL "
                     "WHERE invite_uuid=?", (inv["invite_uuid"],))
        raise
    uid = dev["user_uuid"]
    pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone()[0]
    if sorte == "personne":
        souhait = (inv["pseudo_propose"] or "").lower()
        if souhait and souhait != pseudo and \
                not db().execute("SELECT 1 FROM sbx_users WHERE pseudo=?", (souhait,)).fetchone():
            db().execute("UPDATE sbx_users SET pseudo=? WHERE user_uuid=?", (souhait, uid))
            pseudo = souhait
        if inv["email"]:
            db().execute("UPDATE sbx_users SET email=? WHERE user_uuid=?", (inv["email"], uid))
        db().execute("DELETE FROM sbx_user_roles WHERE user_uuid=?", (uid,))
        for x in S.roles_effectifs([inv["role_propose"]]):
            db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)",
                         (uid, x, request.state.user, int(time.time())))
    db().execute("UPDATE sbx_invites SET device_uuid=? WHERE invite_uuid=?",
                 (dev["device_uuid"], inv["invite_uuid"]))
    store.journal(db(), request.state.user, "invite.joined",
                  f"{pseudo} · {sorte}" + (f" · {inv['role_propose']}" if sorte == "personne" else ""))
    if sorte == "personne":
        S.emet_activite(db(), "user_joined", author=uid, visibility="node",
                        origin_node=_origine(), context={"via": "invitation"})
        svcs = invitations.services_du_role(inv["role_propose"])
        try:
            _travail(uid, lambda c: comptes.cree(c, uid, svcs), "services.created", request.state.user)
        except HTTPException:
            pass                                    # un travail déjà en cours : il suffira
    jeton = acc.profileur().demande_de(r.did).jeton
    return {"ok": True, "pseudo": pseudo, "sorte": sorte, "jeton": jeton}
