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
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from secubox_core import auth as _auth
from secubox_core import sbxid as S
from secubox_core import user_store

from . import store

log = logging.getLogger("secubox.sbxid")
app = FastAPI(title="SBX Identity Manager", version="0.1.0")

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


def db():
    global _DB
    if _DB is None:
        _DB = store.ouvre()
        n = _noeud()
        try:
            r = store.importe_existant(_DB, n.did if n else "did:plc:" + "0" * 32)
            if r["appareils"]:
                log.info("sbxid : import %s", r)
        except Exception as e:                        # l'import ne doit jamais empêcher de servir
            log.error("sbxid : import impossible : %s", e)
    return _DB


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


@app.get("/moi")
def route_moi(ctx=Depends(moi)):
    if not ctx["user"]:
        return {"identite": None, "systeme": ctx["systeme"], "sub": ctx["sub"],
                "motif": "Cette session n'est pas celle d'un appareil SBX OS "
                         + ("(compte système : administration seulement)" if ctx["systeme"] else "admis")}
    uid = ctx["user"]["user_uuid"]
    return {"identite": ctx["user"], "appareil_courant": ctx["device"]["device_uuid"],
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
        out.append(p)
    return {"personnes": out}


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
    if dev and dev["user_uuid"]:
        db().execute("DELETE FROM sbx_user_roles WHERE user_uuid=?", (dev["user_uuid"],))
        for x in roles:
            db().execute("INSERT INTO sbx_user_roles VALUES (?,?,?,?)", (dev["user_uuid"], x, _acteur(ctx), int(time.time())))
        pseudo = db().execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (dev["user_uuid"],)).fetchone()[0]
    store.journal(db(), _acteur(ctx), "invite.validated", f"{pseudo or did} · {', '.join(roles)}")
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
