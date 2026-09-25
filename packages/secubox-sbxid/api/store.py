# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: sbxid.store — sbx.db et l'import de l'existant (#1422)
CyberMind — https://cybermind.fr

KISS : une base SQLite, un import IDEMPOTENT depuis ce qui existe déjà
(les appareils admis de secubox-acces et leurs rattachements), rien de
réécrit ailleurs. Les comptes système (admin, gk2, operator, root) ne
deviennent jamais des identités : un appareil rattaché à gk2 ou admin
appartient à la personne qui les exploite — « gandalf » (décision #1405).
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
import unicodedata
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from secubox_core import sbxid as S

DB = Path("/var/lib/secubox/sbxid/sbx.db")
DEMANDES = Path("/var/lib/secubox/acces/demandes.json")
BBS_DB = Path("/var/lib/secubox/bbs/index.db")

# Comptes système → identité SBX OS de leur exploitant (décision #1405).
EXPLOITANT = {"gk2": "gandalf", "admin": "gandalf"}
ROLES_EXPLOITANT = ["sbx_operator", "moderator"]
PROFIL_VERS_ROLE = {"admin": "sbx_operator", "user": "member", "guest": "guest"}


def ouvre(chemin: Optional[Path] = None) -> sqlite3.Connection:
    chemin = chemin or DB          # résolu à l'APPEL (surchargeable)
    chemin.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(chemin), timeout=5, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    S.initialise(c)
    return c


def journal(c: sqlite3.Connection, acteur: str, evenement: str, detail: str = "") -> None:
    c.execute("INSERT INTO sbx_audit VALUES (?,?,?,?)", (int(time.time()), acteur, evenement, detail))


def _genre(appareil: str) -> str:
    a = (appareil or "").lower()
    for motif, genre in (("iphone", "iphone"), ("ipad", "ipad"), ("mac", "mac"),
                         ("android", "android"), ("windows", "windows"), ("linux", "linux"), ("x11", "linux")):
        if motif in a:
            return genre
    return "autre"


def _pseudo_libre(c, voulu: str) -> str:
    # Les accents se DÉCOMPOSENT (Gérald → gerald), ils ne deviennent pas des tirets.
    sans = unicodedata.normalize("NFKD", voulu or "personne").encode("ascii", "ignore").decode()
    base = re.sub(r"[^a-z0-9_.-]+", "-", sans.strip().lower()).strip("-") or "personne"
    if base in S.COMPTES_SYSTEME:
        base = base + "-sbx"
    p, n = base, 2
    while c.execute("SELECT 1 FROM sbx_users WHERE pseudo=?", (p,)).fetchone():
        p, n = f"{base}-{n}", n + 1
    return p


def _personne(c, pseudo: str, home_node: str, roles: List[str]) -> str:
    r = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo=?", (pseudo,)).fetchone()
    if r:
        uid = r["user_uuid"]
    else:
        uid = str(uuid.uuid4())
        c.execute("INSERT INTO sbx_users (user_uuid,pseudo,home_node,created_at) VALUES (?,?,?,?)",
                  (uid, pseudo, home_node, int(time.time())))
    for role in roles:
        c.execute("INSERT OR IGNORE INTO sbx_user_roles VALUES (?,?,?,?)", (uid, role, "import", int(time.time())))
    return uid


def importe_existant(c: sqlite3.Connection, home_node: str, demandes: Optional[Path] = None) -> Dict[str, int]:
    """Appareils admis de secubox-acces → personnes + appareils. Idempotent."""
    demandes = demandes or DEMANDES
    try:
        brut = json.loads(demandes.read_text())
    except (OSError, ValueError):
        return {"personnes": 0, "appareils": 0}
    lignes = brut.get("demandes", []) if isinstance(brut, dict) else brut
    n_app, avant = 0, c.execute("SELECT count(*) FROM sbx_users").fetchone()[0]
    for d in lignes:
        if d.get("etat") not in ("acceptee", "refusee"):
            continue                                  # en attente : pas encore une personne
        if d.get("etat") == "refusee" and not (d.get("compte") or "").strip():
            # Un appareil refusé ou révoqué, jamais rattaché à personne, n'est
            # pas une personne : ne pas peupler SBX OS de fantômes (#1422).
            continue
        try:
            did = S.did_appareil(d["cle_publique"])
        except (S.Refus, KeyError, ValueError):
            continue
        if c.execute("SELECT 1 FROM sbx_devices WHERE did=?", (did,)).fetchone():
            continue
        compte = (d.get("compte") or "").strip().lower()
        if compte in EXPLOITANT:
            pseudo, roles = EXPLOITANT[compte], list(ROLES_EXPLOITANT)
        elif compte and compte not in S.COMPTES_SYSTEME:
            pseudo, roles = compte, [PROFIL_VERS_ROLE.get(d.get("profil") or "guest", "guest")]
        else:
            pseudo = _pseudo_libre(c, d.get("nom") or "personne")
            roles = [PROFIL_VERS_ROLE.get(d.get("profil") or "guest", "guest")]
        uid = _personne(c, pseudo, home_node, roles)
        revoque = int(d.get("traitee_le") or time.time()) if d.get("etat") == "refusee" else None
        c.execute("INSERT INTO sbx_devices (device_uuid,user_uuid,device_name,device_kind,did,public_key,"
                  "trust_level,last_seen_at,created_at,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (str(uuid.uuid4()), uid, (d.get("appareil") or d.get("nom") or "appareil")[:80],
                   _genre(d.get("appareil", "")), did, d["cle_publique"].lower(), "verified",
                   d.get("session_le"), int(d.get("demandee_le") or time.time()), revoque))
        n_app += 1
    if EXPLOITANT and c.execute("SELECT 1 FROM sbx_users WHERE pseudo='gandalf'").fetchone():
        uid = c.execute("SELECT user_uuid FROM sbx_users WHERE pseudo='gandalf'").fetchone()[0]
        c.execute("INSERT OR IGNORE INTO sbx_app_links VALUES (?,?,?,?)", (uid, "bbs", "gk2", "gk2"))
    lie_comptes_bbs_d_appareil(c)
    apres = c.execute("SELECT count(*) FROM sbx_users").fetchone()[0]
    if n_app:
        journal(c, "import", "import.acces", f"{apres - avant} personne(s), {n_app} appareil(s)")
    return {"personnes": apres - avant, "appareils": n_app}


def _handles_bbs(bbs_db: Optional[Path] = None) -> set:
    try:
        b = sqlite3.connect(f"file:{bbs_db or BBS_DB}?mode=ro", uri=True, timeout=2)
        try:
            return {r[0] for r in b.execute("SELECT handle FROM users WHERE handle LIKE 'sbx-%'")}
        finally:
            b.close()
    except sqlite3.Error:
        return set()


def lie_comptes_bbs_d_appareil(c: sqlite3.Connection, bbs_db: Optional[Path] = None) -> int:
    """#1454 : le BBS ouvre un compte `sbx-<empreinte>` à un appareil qui s'y
    présente avant d'être rattaché. Ce compte EST la personne propriétaire de
    l'appareil : on le lie (sbx_app_links), sans rien réécrire dans le BBS,
    lu en lecture seule. Seulement un compte qui existe, d'un appareil non
    révoqué, d'une personne active ; un lien déjà posé ne bouge pas."""
    handles = _handles_bbs(bbs_db)
    if not handles:
        return 0
    n = 0
    for uid, cle in c.execute("SELECT d.user_uuid, d.public_key FROM sbx_devices d JOIN sbx_users u"
                              " ON u.user_uuid=d.user_uuid WHERE d.revoked_at IS NULL AND u.status='active'").fetchall():
        try:
            h = "sbx-" + S.empreinte_cle(cle)[:12]
        except (S.Refus, ValueError):
            continue
        if h in handles:
            n += c.execute("INSERT OR IGNORE INTO sbx_app_links VALUES (?,?,?,?)", (uid, "bbs", h, h)).rowcount
    if n:
        journal(c, "import", "lien.bbs", f"{n} compte(s) BBS d'appareil lié(s)")
    return n


# ── Lectures ───────────────────────────────────────────────────────────────
def roles_de(c, uid: str) -> List[str]:
    return [r[0] for r in c.execute("SELECT role_id FROM sbx_user_roles WHERE user_uuid=? ORDER BY role_id", (uid,))]


def tier_de(c, uid: str) -> str:
    r = c.execute("SELECT tier FROM sbx_subscriptions WHERE user_uuid=? AND (expires_at IS NULL OR expires_at>?)"
                  " ORDER BY started_at DESC LIMIT 1", (uid, int(time.time()))).fetchone()
    return r[0] if r else "free"


def table_roles(c) -> Dict[str, List[str]]:
    t: Dict[str, List[str]] = {}
    for r in c.execute("SELECT role_id, capability FROM sbx_role_capabilities"):
        t.setdefault(r[0], []).append(r[1])
    return t


def personne(c, uid: str) -> Optional[Dict[str, Any]]:
    u = c.execute("SELECT * FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone()
    if not u:
        return None
    roles, tier = roles_de(c, uid), tier_de(c, uid)
    return {"user_uuid": uid, "pseudo": u["pseudo"], "email": u["email"] or "", "status": u["status"],
            "home_node": u["home_node"], "epoch": u["epoch"], "roles": S.roles_effectifs(roles, tier),
            "tier": tier,
            "capabilities": S.capacites(roles, tier, table_roles(c), suspendu=u["status"] == "suspended")}


def appareils_de(c, uid: str) -> List[Dict[str, Any]]:
    out = []
    for d in c.execute("SELECT * FROM sbx_devices WHERE user_uuid=? ORDER BY revoked_at IS NOT NULL, last_seen_at DESC",
                       (uid,)):
        cert = c.execute("SELECT serial, expires FROM sbx_certificates WHERE device_uuid=? AND revoked_at IS NULL"
                         " ORDER BY issued DESC LIMIT 1", (d["device_uuid"],)).fetchone()
        out.append({"device_uuid": d["device_uuid"], "name": d["device_name"], "kind": d["device_kind"],
                    "did": d["did"], "trust": d["trust_level"], "last_seen_at": d["last_seen_at"],
                    "revoked_at": d["revoked_at"], "certificate": dict(cert) if cert else None})
    return out


def appareil_par_did(c, did: str):
    return c.execute("SELECT * FROM sbx_devices WHERE did=?", (did,)).fetchone()
