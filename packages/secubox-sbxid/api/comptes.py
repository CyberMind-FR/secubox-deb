# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: SBX Identity — les comptes d'une PERSONNE dans les services (#1456)
CyberMind — https://cybermind.fr

Une personne SBX OS (user_uuid) a ses comptes Courriel, Nextcloud, PeerTube
— créés par le helper root de secubox-users, le même que pour les comptes
système — et son compte BBS, relié (jamais recréé). Tout est rangé dans
sbx_app_links : la personne est la clé, les comptes lui appartiennent.

COMPTE EXISTANT RELIÉ (#1468) : un compte qui existait avant (la boîte
gk2@secubox.in de l'exploitant, l'« admin » de Nextcloud) se RELIE à la
personne sans être recréé, et garde SON mot de passe — exclu du mot de passe
commun, jamais réinitialisé d'ici. Un nom système ne se relie qu'à la
personne de l'exploitant.

UN SEUL MOT DE PASSE DE SERVICES. Il n'est gardé nulle part : créé ou
réinitialisé, il est posé dans TOUS les services liés d'un coup et rendu une
fois à l'administration. Une réinitialisation rend donc l'accès à tout.
Le BBS n'en a pas besoin : il s'ouvre par la session du Hall (Remote-Sbx-Bbs).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

HELPER = ["sudo", "-n", "/usr/sbin/secubox-usersctl-services"]
BBS_DB = Path("/var/lib/secubox/bbs/index.db")
DOMAINE = os.environ.get("SBXID_DOMAINE_COURRIEL", "secubox.in")
SERVICES = ("email", "nextcloud", "peertube")
LIBELLES = {"email": "Courriel + webmail", "nextcloud": "Nextcloud", "peertube": "PeerTube", "bbs": "BBS"}
SYSTEME = {"root", "admin", "gk2", "operator"}
RE_NOM = re.compile(r"^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,30}[a-z0-9_-]$")      # celui du helper, sans point final


class Refus(Exception):
    def __init__(self, code: int, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


def mot_de_passe() -> str:
    """Provisoire, lisible à la dictée : 4 groupes de 4, sans 0/O/1/l."""
    a = "abcdefghjkmnpqrstuvwxyz23456789"
    return "-".join("".join(secrets.choice(a) for _ in range(4)) for _ in range(4))


def adresse(pseudo: str) -> str:
    return f"{pseudo}@{DOMAINE}"


def _helper(demande: Dict[str, Any], delai: int = 300) -> Dict[str, Any]:
    try:
        p = subprocess.run(HELPER, input=json.dumps(demande), capture_output=True, text=True, timeout=delai)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "erreur": f"helper injoignable ({type(e).__name__})"}
    try:
        return json.loads(p.stdout or "{}")
    except ValueError:
        return {"ok": False, "erreur": (p.stderr or p.stdout).strip()[-200:] or f"code {p.returncode}"}


# Injectable pour les tests.
helper: Callable[[Dict[str, Any]], Dict[str, Any]] = _helper


def _demande(pseudo: str, svc: str, action: str, password: str = "") -> Dict[str, Any]:
    """`pseudo` est le NOM DANS LE SERVICE : le pseudo SBX OS pour un compte
    ouvert d'ici, l'identifiant relié sinon (« gk2@secubox.in », « admin »)."""
    user, email = (pseudo.split("@", 1)[0], pseudo) if "@" in pseudo else (pseudo, adresse(pseudo))
    d = {"service": svc, "action": action, "user": user, "email": email, "nom": user}
    if password:
        d["password"] = password
    return d


def _pseudo(c: sqlite3.Connection, uid: str) -> str:
    r = c.execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone()
    if not r:
        raise Refus(404, "Personne inconnue")
    if not RE_NOM.match(r[0]):
        raise Refus(409, f"« {r[0]} » ne peut pas nommer un compte de service (a-z 0-9 . _ -)")
    return r[0]


def liens(c: sqlite3.Connection, uid: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for app, ident in c.execute("SELECT app, app_id FROM sbx_app_links WHERE user_uuid=? ORDER BY app, app_id", (uid,)):
        out.setdefault(app, []).append(ident)
    return out


def _lie(c, uid, app, ident):
    c.execute("INSERT OR REPLACE INTO sbx_app_links VALUES (?,?,?,?)", (uid, app, ident, ident))


def propres(c: sqlite3.Connection, uid: str) -> set:
    """Services dont le compte relié garde SON mot de passe (#1468)."""
    return {r[0].split(":", 1)[1] for r in c.execute(
        "SELECT cle FROM sbx_preferences WHERE user_uuid=? AND cle LIKE 'mdp_propre:%' AND valeur='1'", (uid,))}


def _nom_service(c, uid, svc, pseudo) -> str:
    """Le nom dans le service : celui qui est relié, sinon celui d'ici."""
    l = liens(c, uid).get(svc) or []
    return l[0] if l else (adresse(pseudo) if svc == "email" else pseudo)


def etat(c: sqlite3.Connection, uid: str) -> Dict[str, Any]:
    """Ce que chaque service sait de la personne, et ce qui est lié ici."""
    pseudo = _pseudo(c, uid)
    l = liens(c, uid)
    services = {}
    pr = propres(c, uid)
    for svc in SERVICES:
        nom = _nom_service(c, uid, svc, pseudo)
        r = helper(_demande(nom, svc, "etat"))
        services[svc] = {"libelle": LIBELLES[svc], "lie": svc in l, "identifiant": nom, "propre": svc in pr,
                         "existe": bool(r.get("ok") and (r.get("etat") or {}).get("existe")),
                         "disponible": r.get("disponible", True) is not False or bool(r.get("endormi")),
                         "endormi": bool(r.get("endormi")),
                         "erreur": None if r.get("ok") else r.get("erreur")}
    return {"pseudo": pseudo, "adresse": adresse(pseudo), "services": services, "bbs": l.get("bbs", [])}


def _pose_partout(c, uid, pseudo, pw, sauf: Optional[str] = None) -> Dict[str, Any]:
    """Le MÊME mot de passe dans chaque service lié — c'est la promesse."""
    out = {}
    pr = propres(c, uid)
    for svc in liens(c, uid):
        if svc in SERVICES and svc != sauf and svc not in pr:     # un compte relié garde SON mot de passe
            r = helper(_demande(_nom_service(c, uid, svc, pseudo), svc, "reinitialiser", pw))
            out[svc] = True if r.get("ok") else (r.get("erreur") or "échec")
    return out


def cree(c: sqlite3.Connection, uid: str, svcs: List[str]) -> Dict[str, Any]:
    """Ouvre les services demandés ; un nouveau mot de passe vaut alors pour
    TOUS les services de la personne (ceux d'avant compris)."""
    pseudo = _pseudo(c, uid)
    inconnus = [s for s in svcs if s not in SERVICES]
    if inconnus or not svcs:
        raise Refus(400, "Services : " + ", ".join(SERVICES))
    pw = mot_de_passe()
    resultats = _pose_partout(c, uid, pseudo, pw)
    deja = liens(c, uid)
    for svc in svcs:
        if svc in resultats or svc in deja:
            continue                                   # déjà lié : réinitialisé ci-dessus (ou mot de passe propre)
        r = helper(_demande(pseudo, svc, "creer", pw))
        ok = bool(r.get("ok"))
        if not ok and "exist" in str(r.get("erreur", "")).lower():      # « existe » / « already exists »
            # déjà là (créé à la main, ou par une tentative précédente) : on
            # le reprend, avec le mot de passe commun
            ok = bool(helper(_demande(pseudo, svc, "reinitialiser", pw)).get("ok"))
        if ok:
            _lie(c, uid, svc, adresse(pseudo) if svc == "email" else pseudo)
        resultats[svc] = True if ok else (r.get("erreur") or "échec")
    return {"mot_de_passe": pw if any(v is True for v in resultats.values()) else None,
            "adresse": adresse(pseudo), "services": resultats}


def reinitialise(c: sqlite3.Connection, uid: str) -> Dict[str, Any]:
    pseudo = _pseudo(c, uid)
    pw = mot_de_passe()
    res = _pose_partout(c, uid, pseudo, pw)
    if not res:
        raise Refus(409, "Aucun compte à mot de passe commun : les comptes reliés gardent le leur")
    return {"mot_de_passe": pw if any(v is True for v in res.values()) else None, "services": res}


def handle_bbs(nom: str, bbs_db: Optional[Path] = None) -> Optional[str]:
    """Le handle BBS tel qu'il existe (casse d'origine), ou None."""
    try:
        b = sqlite3.connect(f"file:{bbs_db or BBS_DB}?mode=ro", uri=True, timeout=2)
        try:
            r = b.execute("SELECT handle FROM users WHERE handle = ? COLLATE NOCASE AND disabled_at IS NULL",
                          (nom.strip(),)).fetchone()
        finally:
            b.close()
    except sqlite3.Error:
        return None
    return r[0] if r else None


def lie_bbs(c: sqlite3.Connection, uid: str, nom: str, bbs_db: Optional[Path] = None) -> str:
    if not c.execute("SELECT 1 FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone():
        raise Refus(404, "Personne inconnue")
    h = handle_bbs(nom, bbs_db)
    if not h:
        raise Refus(404, f"Aucun compte BBS actif nommé « {nom} »")
    if h.lower() in ("root", "admin", "gk2", "operator"):
        raise Refus(409, "Un compte système ne se lie pas à une personne")
    autre = c.execute("SELECT u.pseudo FROM sbx_app_links l JOIN sbx_users u USING(user_uuid)"
                      " WHERE l.app='bbs' AND lower(l.app_id)=lower(?) AND l.user_uuid!=?", (h, uid)).fetchone()
    if autre:
        raise Refus(409, f"« {h} » est déjà lié à {autre[0]}")
    _lie(c, uid, "bbs", h)
    return h


def lie_existant(c: sqlite3.Connection, uid: str, svc: str, ident: str) -> str:
    """Relier un compte EXISTANT (#1468) : vérifié dans le service, jamais créé,
    et qui garde son mot de passe."""
    from . import store
    r = c.execute("SELECT pseudo FROM sbx_users WHERE user_uuid=?", (uid,)).fetchone()
    if not r:
        raise Refus(404, "Personne inconnue")
    if svc not in SERVICES:
        raise Refus(400, "Services : " + ", ".join(SERVICES) + " (BBS : lien BBS)")
    ident = ident.strip()
    if svc == "email":
        ident = (ident if "@" in ident else adresse(ident)).lower()
    local = ident.split("@", 1)[0].lower()
    if not RE_NOM.match(local):
        raise Refus(400, "Identifiant invalide")
    if local in SYSTEME and r[0] not in set(store.EXPLOITANT.values()):
        raise Refus(409, "Un compte système ne se relie qu'à la personne de l'exploitant")
    autre = c.execute("SELECT u.pseudo FROM sbx_app_links l JOIN sbx_users u USING(user_uuid)"
                      " WHERE l.app=? AND lower(l.app_id)=lower(?) AND l.user_uuid!=?", (svc, ident, uid)).fetchone()
    if autre:
        raise Refus(409, f"« {ident} » est déjà relié à {autre[0]}")
    e = helper(_demande(ident, svc, "etat"))
    if not e.get("ok"):
        raise Refus(503, e.get("erreur") or "service injoignable")
    if not (e.get("etat") or {}).get("existe"):
        raise Refus(404, f"Aucun compte « {ident} » dans {LIBELLES[svc]}")
    c.execute("DELETE FROM sbx_app_links WHERE user_uuid=? AND app=?", (uid, svc))   # un compte par service
    _lie(c, uid, svc, ident)
    c.execute("INSERT OR REPLACE INTO sbx_preferences VALUES (?,?,?)", (uid, f"mdp_propre:{svc}", "1"))
    return ident


def delie(c: sqlite3.Connection, uid: str, app: str, ident: str) -> None:
    c.execute("DELETE FROM sbx_app_links WHERE user_uuid=? AND app=? AND app_id=?", (uid, app, ident))
    if not c.execute("SELECT 1 FROM sbx_app_links WHERE user_uuid=? AND app=?", (uid, app)).fetchone():
        c.execute("DELETE FROM sbx_preferences WHERE user_uuid=? AND cle=?", (uid, f"mdp_propre:{app}"))
