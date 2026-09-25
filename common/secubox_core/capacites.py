# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: capacites — le middleware unique des capacités (#1438, AUTH v3 M3)
CyberMind — https://cybermind.fr

    @router.post("/billet", dependencies=[Depends(require_capability("billets.publish"))])

Une session désigne un APPAREIL (par son jti, noté par l'accès à l'ouverture),
l'appareil une PERSONNE (sbx.db, SBX Identity Manager), la personne des rôles
et un abonnement, qui donnent des capacités. Un jeton ne suffit plus : il dit
QUI, la capacité dit CE QU'IL PEUT.

  - administrateur système (users.json, role admin, actif) : toutes les
    capacités SBX OS — c'est l'exploitant ; rien de ce qui marche ne se ferme ;
  - appareil révoqué, personne suspendue : aucune ;
  - pas de sbx.db (box sans l'Identity Manager) : repli sur le profil
    d'appareil (admin → tout, user → membre, guest → invité).

Lecture seule, en SQLite ; résultat gardé 30 s par session.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set

from fastapi import Depends, HTTPException

from . import sbxid as S
from . import user_store
from .auth import require_jwt

SBX_DB = Path("/var/lib/secubox/sbxid/sbx.db")
DEMANDES = Path("/var/lib/secubox/acces/demandes.json")
_CACHE: Dict[tuple, tuple] = {}
_TTL = 30.0


def _demandes() -> list:
    try:
        b = json.loads(DEMANDES.read_text())
        return b.get("demandes", []) if isinstance(b, dict) else b
    except (OSError, ValueError):
        return []


def _demande_de(sub: str, jti: str) -> Optional[Dict[str, Any]]:
    for d in _demandes():
        cle = d.get("cle_publique") or ""
        if (jti and jti in (d.get("jtis") or [])) or \
           (sub.startswith("sbx-") and cle and "sbx-" + S.empreinte_cle(cle)[:12] == sub):
            return d
    return None


def _depuis_sbxdb(did: str) -> Optional[Set[str]]:
    """None si sbx.db n'a rien à dire (absent, appareil inconnu) ; sinon l'ensemble."""
    if not SBX_DB.exists():
        return None
    try:
        c = sqlite3.connect(f"file:{SBX_DB}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return None
    try:
        dev = c.execute("SELECT user_uuid, revoked_at FROM sbx_devices WHERE did=?", (did,)).fetchone()
        if not dev:
            return None
        uid, revoque = dev
        if revoque or not uid:
            return set()
        u = c.execute("SELECT status FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone()
        if not u or u[0] != "active":
            return set()
        roles = [r[0] for r in c.execute("SELECT role_id FROM sbx_user_roles WHERE user_uuid=?", (uid,))]
        t = c.execute("SELECT tier FROM sbx_subscriptions WHERE user_uuid=? AND (expires_at IS NULL OR expires_at>?)"
                      " ORDER BY started_at DESC LIMIT 1", (uid, int(time.time()))).fetchone()
        table: Dict[str, list] = {}
        for rid, cap in c.execute("SELECT role_id, capability FROM sbx_role_capabilities"):
            table.setdefault(rid, []).append(cap)
        try:
            return set(S.capacites(roles, t[0] if t else "free", table or None))
        except S.Refus:
            return set()
    except sqlite3.Error:
        return None
    finally:
        c.close()


def _repli_profil(profil: str) -> Set[str]:
    return {"admin": set(S.ROLES["sbx_operator"]), "user": set(S.ROLES["member"]),
            "guest": set(S.ROLES["guest"])}.get(profil or "guest", set(S.ROLES["guest"]))


def capacites_du_porteur(payload: Dict[str, Any]) -> Set[str]:
    sub, jti = payload.get("sub", ""), payload.get("jti", "")
    cle = (sub, jti)
    hit = _CACHE.get(cle)
    if hit and time.time() - hit[0] < _TTL:
        return hit[1]
    u = user_store.get_user(sub) or {}
    if u.get("role") == "admin" and u.get("enabled", True):
        out = set(S.CAPACITES)                      # l'exploitant
    else:
        out = set()
        d = _demande_de(sub, jti)
        if d and d.get("etat") == "acceptee":
            try:
                did = S.did_appareil(d["cle_publique"])
            except (S.Refus, KeyError, ValueError):
                did = ""
            viaDb = _depuis_sbxdb(did) if did else None
            out = viaDb if viaDb is not None else _repli_profil(d.get("profil") or "guest")
    _CACHE[cle] = (time.time(), out)
    return out


def personne_du_porteur(payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """La PERSONNE SBX OS derrière une session (#1446) : {user_uuid, pseudo}
    si la session vient d'un appareil rattaché à une identité active ; None
    sinon (appareil inconnu, refusé, révoqué…).

    SESSION DE COMPTE SANS APPAREIL (#1450) : ouverte par mot de passe (+TOTP),
    elle ne porte aucune clé. Elle désigne alors la personne propriétaire des
    appareils ACCEPTÉS pour ce compte — gk2 → gandalf — à condition qu'il n'y
    en ait qu'UNE ; ambigu ou aucune → None. Une session qui vient d'un
    appareil ne retombe jamais sur son compte : un appareil refusé ou révoqué
    reste sans identité."""
    sub = payload.get("sub", "")
    d = _demande_de(sub, payload.get("jti", ""))
    if not SBX_DB.exists():
        return None
    if d is None and sub and not sub.startswith("sbx-"):
        dids = []
        for x in _demandes():
            if x.get("compte") == sub and x.get("etat") == "acceptee" and x.get("cle_publique"):
                try:
                    dids.append(S.did_appareil(x["cle_publique"]))
                except (S.Refus, ValueError):
                    pass
    elif d and d.get("etat") == "acceptee":
        try:
            dids = [S.did_appareil(d["cle_publique"])]
        except (S.Refus, KeyError, ValueError):
            return None
    else:
        return None
    if not dids:
        return None
    try:
        c = sqlite3.connect(f"file:{SBX_DB}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return None
    try:
        ph = ",".join("?" * len(dids))
        rows = c.execute("SELECT DISTINCT u.user_uuid, u.pseudo FROM sbx_devices d JOIN sbx_users u"
                         f" ON u.user_uuid=d.user_uuid WHERE d.did IN ({ph}) AND d.revoked_at IS NULL"
                         " AND u.status='active'", dids).fetchall()
        return {"user_uuid": rows[0][0], "pseudo": rows[0][1]} if len(rows) == 1 else None
    except sqlite3.Error:
        return None
    finally:
        c.close()


def require_capability(cap: str):
    """Dépendance FastAPI : session valide ET capacité `cap`."""
    S.valide_capacite(cap)                          # jamais une capacité système
    async def _garde(creds=Depends(require_jwt)):
        p = creds if isinstance(creds, dict) else {}
        if cap not in capacites_du_porteur(p):
            raise HTTPException(status_code=403, detail=f"Capacité requise : {cap}")
        return creds
    return _garde
