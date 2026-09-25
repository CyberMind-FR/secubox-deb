# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Messagerie — la messagerie de la box (#1446)
CyberMind — https://cybermind.fr

Un mur public et des messages privés, pour les personnes (identité SBX OS)
comme pour les visiteurs (un pseudo). On écrit à une personne ou à tous ; on
répond en privé ou publiquement. Les conversations de la box y sont
CENTRALISÉES : le chat de la radio apparaît dans le mur, et y répondre le
republie dans la radio (surpostage local).

Visiteurs : publiés d'emblée (décision #1446), modération a posteriori par
qui détient bbs.moderate ; plafond par adresse ; un visiteur ne peut pas
prendre le pseudo d'une personne SBX OS.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import sqlite3
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

from secubox_core import auth as _auth
from secubox_core import capacites as _cap

app = FastAPI(title="SecuBox Messagerie", version="0.1.0")

DB = Path(os.environ.get("MESSAGERIE_DB", "/var/lib/secubox/messagerie/messages.db"))
RADIO_SOCK = os.environ.get("MESSAGERIE_RADIO_SOCK", "/run/secubox/radio.sock")
COOKIE_VISITEUR = "sbx_msg_v"
CORPS_MAX = 2000
PLAFOND = {"visiteur": 10, "sbx": 120}            # messages par heure et par adresse/personne
_RE_PSEUDO = re.compile(r"^[\w .'’-]{2,32}$", re.U)

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY, cree_le INTEGER NOT NULL,
  auteur_type TEXT NOT NULL CHECK (auteur_type IN ('sbx','visiteur')),
  auteur_ref TEXT NOT NULL, pseudo TEXT NOT NULL,
  prive INTEGER NOT NULL DEFAULT 0, destinataire TEXT, dest_pseudo TEXT,
  parent TEXT, corps TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'local', source_ref TEXT,
  supprime_le INTEGER, supprime_par TEXT);
CREATE INDEX IF NOT EXISTS idx_mur ON messages(prive, cree_le);
CREATE INDEX IF NOT EXISTS idx_prives ON messages(destinataire, auteur_ref, cree_le);
"""
_DB = None


def db() -> sqlite3.Connection:
    global _DB
    if _DB is None:
        DB.parent.mkdir(parents=True, exist_ok=True)
        _DB = sqlite3.connect(str(DB), timeout=5, isolation_level=None, check_same_thread=False)
        _DB.row_factory = sqlite3.Row
        _DB.executescript("PRAGMA journal_mode=WAL;" + SCHEMA)
    return _DB


def _ref_visiteur(cookie: str) -> str:
    """La référence d'un visiteur est une EMPREINTE de son cookie : elle se
    lit dans `destinataire`, le cookie lui-même vaut identité."""
    return "v:" + hashlib.sha256(cookie.encode()).hexdigest()[:24]


# ── Qui écrit ──────────────────────────────────────────────────────────────
def qui(request: Request) -> Dict[str, Any]:
    """Personne SBX OS si la session le dit, sinon visiteur (cookie), sinon anonyme."""
    for j in (request.cookies.get("secubox_session"),
              (request.headers.get("Authorization") or "")[7:] or None):
        p = _auth._validate_token(j) if j else None
        if p:
            per = _cap.personne_du_porteur(p)
            caps = _cap.capacites_du_porteur(p)
            if per:
                return {"type": "sbx", "ref": per["user_uuid"], "pseudo": per["pseudo"],
                        "moderateur": "bbs.moderate" in caps}
            if "bbs.moderate" in caps:                  # exploitant système sans identité SBX
                # le compte système reste invisible : on signe « modération »
                return {"type": "systeme", "ref": "sys:" + p.get("sub", ""), "pseudo": "modération",
                        "moderateur": True}
    v = request.cookies.get(COOKIE_VISITEUR) or ""
    if re.fullmatch(r"[0-9a-f]{32}", v):
        return {"type": "visiteur", "ref": _ref_visiteur(v), "pseudo": None, "moderateur": False}
    return {"type": "anonyme", "ref": None, "pseudo": None, "moderateur": False}


_FENETRES: Dict[str, deque] = {}


def _plafond(cle: str, limite: int) -> None:
    now = time.time()
    f = _FENETRES.setdefault(cle, deque())
    while f and now - f[0] > 3600:
        f.popleft()
    if len(f) >= limite:
        raise HTTPException(429, "Trop de messages : réessayez dans un moment")
    f.append(now)


def _pseudos_sbx(casse: bool = False) -> Dict[str, str]:
    """pseudo (minuscule, ou tel quel si casse) → user_uuid des personnes SBX OS actives."""
    try:
        c = sqlite3.connect(f"file:{_cap.SBX_DB}?mode=ro", uri=True, timeout=2)
        try:
            return {(r[1] if casse else r[1].lower()): r[0] for r in c.execute(
                "SELECT user_uuid, pseudo FROM sbx_users WHERE status='active'")}
        finally:
            c.close()
    except sqlite3.Error:
        return {}


# ── Radio : lecture et surpostage ──────────────────────────────────────────
def _radio_chat(n: int = 40) -> List[Dict[str, Any]]:
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=RADIO_SOCK), timeout=3) as cl:
            d = cl.get("http://radio/api/v1/radio/current",
                       headers={"X-Sbx-User-Id": str(_id_radio("messagerie")), "X-Sbx-User": "messagerie"}).json()
    except Exception:
        return []
    out = []
    for m in (d.get("chat") or [])[-n:]:
        out.append({"id": f"radio:{m.get('ID')}", "cree_le": m.get("DitLe") or 0, "auteur_type": "radio",
                    "pseudo": m.get("Pseudo") or "auditeur", "corps": m.get("Corps") or "", "prive": 0,
                    "source": "radio", "parent": None, "supprime": False})
    return out


def _id_radio(ref: str) -> int:
    """Un identifiant de chat radio stable pour une personne ou un visiteur."""
    return int(hashlib.sha256(ref.encode()).hexdigest()[:12], 16) or 1


def _surposte_radio(q: Dict[str, Any], pseudo: str, corps: str) -> bool:
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=RADIO_SOCK), timeout=3) as cl:
            r = cl.post("http://radio/api/v1/radio/chat", json={"corps": corps},
                        headers={"X-Sbx-Radio": "messagerie", "X-Sbx-User-Id": str(_id_radio(q["ref"])),
                                 "X-Sbx-User": pseudo})
            return r.status_code < 300
    except Exception:
        return False


# ── Vues ───────────────────────────────────────────────────────────────────
def _vue(r: sqlite3.Row, moi: Optional[str]) -> Dict[str, Any]:
    supprime = bool(r["supprime_le"])
    return {"id": r["id"], "cree_le": r["cree_le"], "auteur_type": r["auteur_type"], "pseudo": r["pseudo"],
            "prive": bool(r["prive"]), "destinataire": r["destinataire"], "dest_pseudo": r["dest_pseudo"],
            "parent": r["parent"],
            "corps": "" if supprime else r["corps"], "supprime": supprime, "source": r["source"],
            "de_moi": bool(moi) and r["auteur_ref"] == moi}


@app.get("/health")
def health():
    return {"ok": True, "module": "messagerie", "version": app.version}


@app.get("/qui")
def route_qui(request: Request):
    q = qui(request)
    return {k: q[k] for k in ("type", "pseudo", "moderateur")}


@app.get("/annuaire")
def annuaire():
    """À qui écrire : les personnes SBX OS (pseudos seulement)."""
    return {"personnes": sorted(({"pseudo": p, "ref": u} for p, u in _pseudos_sbx(casse=True).items()),
                                key=lambda x: x["pseudo"].lower())}


@app.get("/fil")
def fil(request: Request, n: int = 80):
    """Le mur public, CENTRALISÉ : messages de la box + chat de la radio."""
    q = qui(request)
    n = max(1, min(n, 300))
    locaux = [_vue(r, q["ref"]) for r in db().execute(
        "SELECT * FROM messages WHERE prive=0 ORDER BY cree_le DESC LIMIT ?", (n,))]
    tout = locaux + _radio_chat()
    tout.sort(key=lambda m: m["cree_le"])
    return {"messages": tout[-n:], "moi": {k: q[k] for k in ("type", "pseudo", "moderateur")}}


@app.get("/prives")
def prives(request: Request, n: int = 100):
    q = qui(request)
    if not q["ref"]:
        return {"messages": []}
    rows = db().execute("SELECT * FROM messages WHERE prive=1 AND (auteur_ref=? OR destinataire=?)"
                        " ORDER BY cree_le DESC LIMIT ?", (q["ref"], q["ref"], max(1, min(n, 500)))).fetchall()
    return {"messages": [_vue(r, q["ref"]) for r in reversed(rows)]}


class Nouveau(BaseModel):
    corps: str = Field(min_length=1, max_length=CORPS_MAX)
    destinataire: Optional[str] = None       # user_uuid, « v:<id> » (réponse à un visiteur) ; None = tous
    parent: Optional[str] = None             # id local ou « radio:<n> »
    public: Optional[bool] = None            # réponse : forcer public (None = comme le parent)
    pseudo: Optional[str] = None             # visiteurs seulement


def _intention(request: Request) -> None:
    """Un navigateur ne pose pas d'en-tête personnalisé inter-origines sans
    permission : l'exiger rend inopérante une écriture forgée par un tiers
    (même garde que la radio)."""
    if not request.headers.get("X-Sbx-Messagerie"):
        raise HTTPException(403, "En-tête d'intention manquant")


@app.post("/messages")
def ecrit(m: Nouveau, request: Request, response: Response):
    _intention(request)
    q = qui(request)
    # X-Real-IP : posé par le Hall depuis $remote_addr (déjà résolu par real_ip) ;
    # le premier élément de X-Forwarded-For, lui, se forge côté client.
    ip = request.headers.get("X-Real-IP") or (request.client.host if request.client else "?")
    if q["type"] in ("visiteur", "anonyme"):
        pseudo = (m.pseudo or "").strip()
        if not _RE_PSEUDO.match(pseudo):
            raise HTTPException(400, "Pseudo requis (2 à 32 lettres)")
        if pseudo.lower() in _pseudos_sbx():
            raise HTTPException(409, "Ce pseudo est celui d'une personne de la box : choisissez-en un autre")
        if q["type"] == "anonyme":                  # premier message : on remet un cookie de visiteur
            v = secrets.token_hex(16)
            response.set_cookie(COOKIE_VISITEUR, v, max_age=365 * 86400, httponly=True, samesite="lax",
                                secure=True, path="/")
            q = {"type": "visiteur", "ref": _ref_visiteur(v), "moderateur": False}
        _plafond("ip:" + ip, PLAFOND["visiteur"])
        auteur_type = "visiteur"
    else:
        pseudo = q["pseudo"]
        _plafond("p:" + q["ref"], PLAFOND["sbx"])
        auteur_type = "sbx"
    corps = m.corps.strip()
    parent = None
    prive, dest = (1, m.destinataire) if m.destinataire else (0, None)
    dest_pseudo = None
    if m.parent:
        if m.parent.startswith("radio:"):
            prive, dest = 0, None                   # une réponse au chat radio est publique
            _surposte_radio(q, pseudo, corps)       # … et republiée dans la radio
        else:
            p = db().execute("SELECT * FROM messages WHERE id=?", (m.parent,)).fetchone()
            if not p or p["supprime_le"]:
                raise HTTPException(404, "Message d'origine introuvable")
            if p["prive"] and q["ref"] not in (p["auteur_ref"], p["destinataire"]):
                raise HTTPException(403, "Ce message privé ne vous est pas adressé")
            if m.public is True:
                prive, dest = 0, None               # répondre publiquement : ne cite pas le privé
            elif m.public is False or p["prive"]:
                if p["auteur_ref"] != q["ref"]:
                    prive, dest, dest_pseudo = 1, p["auteur_ref"], p["pseudo"]
                else:
                    prive, dest, dest_pseudo = 1, p["destinataire"], p["dest_pseudo"]
        parent = m.parent
    if prive and not dest:
        raise HTTPException(400, "Destinataire requis pour un message privé")
    if prive and not dest.startswith("v:"):
        noms = {u: p for p, u in _pseudos_sbx(casse=True).items()}
        if dest not in noms:
            raise HTTPException(404, "Destinataire inconnu")
        dest_pseudo = noms[dest]
    elif prive and not parent:
        raise HTTPException(400, "On écrit à un visiteur en répondant à son message")
    mid = str(uuid.uuid4())
    db().execute("INSERT INTO messages (id,cree_le,auteur_type,auteur_ref,pseudo,prive,destinataire,dest_pseudo,"
                 "parent,corps,source) VALUES (?,?,?,?,?,?,?,?,?,?,'local')",
                 (mid, int(time.time()), auteur_type, q["ref"], pseudo, prive, dest, dest_pseudo, parent, corps))
    return {"ok": True, "id": mid, "prive": bool(prive)}


@app.delete("/messages/{mid}")
def supprime(mid: str, request: Request):
    _intention(request)
    q = qui(request)
    r = db().execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
    if not r:
        raise HTTPException(404, "Message introuvable")
    if not (q["ref"] and r["auteur_ref"] == q["ref"]) and not q["moderateur"]:
        raise HTTPException(403, "Seuls l'auteur et les modérateurs suppriment un message")
    db().execute("UPDATE messages SET supprime_le=?, supprime_par=? WHERE id=?",
                 (int(time.time()), q.get("pseudo") or q["ref"], mid))
    return {"ok": True}
