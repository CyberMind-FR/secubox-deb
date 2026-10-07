# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Auth API - OAuth2 + Vouchers + Sessions with Enhanced Monitoring"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException, BackgroundTasks
from secubox_core.auth import require_lecture
from pydantic import BaseModel, Field, field_validator
from secubox_core.auth import router as auth_router, require_jwt, create_token, set_session_callback
from secubox_core.config import get_config
import json
import os
import secrets
import time
import threading
import asyncio
import hashlib
import hmac
import httpx
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from api import ntp_health
from api import console as _console
from api import delegation as _deleg
from api import coffre_connexion as _coffre

app = FastAPI(title="secubox-auth", version="2.0.0", root_path="/api/v1/auth")

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

# ──────────────────────────────────────────────────────────────────────
# Task 13: branching login, MFA, TOTP enroll/confirm, set-password
# Inserted BEFORE the legacy auth_router mount so the overriding
# _login_router (mounted AFTER) takes precedence on /auth/login.
# ──────────────────────────────────────────────────────────────────────
from secubox_core import user_store
from secubox_core.auth import (
    set_session_validator,
    _emit_session_event,
    _decode_token as _jwt_decode,
)

# Make secubox-users engine importable (in-process path, no IPC).
# We cannot use `from api import engine` because Python resolves "api" to the
# secubox-auth api package (the one we're inside).  Instead we register the
# secubox-users api/ directory as a *separate* package named `_users_api` in
# sys.modules so that the relative imports inside engine.py (`from . import totp`)
# resolve correctly.
import importlib.util as _ilu
import sys as _sys
import types as _types


def _bootstrap_users_api_package() -> str:
    """Register secubox-users/api as '_users_api' package; return its root dir."""
    candidates = [
        Path("/usr/lib/secubox/users/api"),
        Path(__file__).resolve().parents[3] / "packages" / "secubox-users" / "api",
        Path(__file__).resolve().parents[3] / "packages" / "secubox-auth" / "composants" / "users" / "api",
    ]
    pkg_root = next((p for p in candidates if (p / "engine.py").exists()), None)
    if pkg_root is None:
        raise ImportError("secubox-users api/ not found in any candidate path")

    pkg_name = "_users_api"
    if pkg_name not in _sys.modules:
        # Create a package object pointing at the discovered directory.
        pkg = _types.ModuleType(pkg_name)
        pkg.__path__ = [str(pkg_root)]
        pkg.__package__ = pkg_name
        pkg.__spec__ = _ilu.spec_from_file_location(
            pkg_name, str(pkg_root / "__init__.py"),
            submodule_search_locations=[str(pkg_root)],
        )
        _sys.modules[pkg_name] = pkg
        # Execute __init__.py if it exists.
        init_py = pkg_root / "__init__.py"
        if init_py.exists():
            spec = _ilu.spec_from_file_location(pkg_name, str(init_py),
                                                submodule_search_locations=[str(pkg_root)])
            mod = _ilu.module_from_spec(spec)  # type: ignore[arg-type]
            _sys.modules[pkg_name] = mod
            spec.loader.exec_module(mod)       # type: ignore[union-attr]

    return pkg_name


def _load_users_submod(pkg_name: str, name: str) -> object:
    full_name = f"{pkg_name}.{name}"
    if full_name in _sys.modules:
        return _sys.modules[full_name]
    pkg_root = Path(_sys.modules[pkg_name].__path__[0])
    spec = _ilu.spec_from_file_location(full_name, str(pkg_root / f"{name}.py"),
                                        submodule_search_locations=[])
    mod = _ilu.module_from_spec(spec)           # type: ignore[arg-type]
    mod.__package__ = pkg_name
    _sys.modules[full_name] = mod
    spec.loader.exec_module(mod)                # type: ignore[union-attr]
    return mod


_users_api_pkg = _bootstrap_users_api_package()
_users_engine_mod = _load_users_submod(_users_api_pkg, "engine")
_users_totp_mod   = _load_users_submod(_users_api_pkg, "totp")
from api.totp_pending import PendingStore

_DATA_DIR = Path(os.environ.get("SECUBOX_AUTH_DATA_DIR", "/var/lib/secubox/auth"))
try:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
except PermissionError:
    # Running as non-root in dev/test — caller is responsible for env-overriding to a writable path.
    pass
__SESSIONS_FILE = Path(os.environ.get("SECUBOX_AUTH_SESSIONS", str(_DATA_DIR / "sessions.json")))
# Les routes /status, /sessions, /sessions/stats, /redeem_voucher et le
# nettoyage des sessions échues lisent `_SESSIONS_FILE` — un nom qui n'existait
# pas : NameError, donc 500, sur le panneau des sessions depuis #120 (#1695).
_SESSIONS_FILE = __SESSIONS_FILE
_AUDIT_FILE    = Path(os.environ.get("SECUBOX_AUTH_AUDIT",    str(_DATA_DIR / "audit.log")))
_TOTP_PENDING_FILE = Path(os.environ.get("SECUBOX_AUTH_TOTP_PENDING", str(_DATA_DIR / "totp-pending.json")))
_USERS_FILE    = Path(os.environ.get("USERS_FILE", "/etc/secubox/users.json"))

_pending      = PendingStore(_TOTP_PENDING_FILE, ttl_seconds=900)
_users_engine = _users_engine_mod.Engine(users_path=_USERS_FILE)


def _read_sessions() -> list:
    if not __SESSIONS_FILE.exists():
        return []
    try:
        return json.loads(__SESSIONS_FILE.read_text())
    except Exception:
        return []


def _muter_sessions(transforme) -> list:
    """Toute écriture du registre passe par le verrou et le renommage atomique
    de secubox_core (#1803) : deux processus auth l'écrivent (socket propre et
    agrégateur), plus users et system."""
    from secubox_core import sessions as _reg
    return _reg.muter(transforme)


def _append_audit(event: str, username: str, details: dict) -> None:
    # Créé en 0640, et ramené à 0640 s'il était plus large : le journal
    # d'authentification a été trouvé en 0666 sur gk2 — n'importe quel compte
    # pouvait y forger ou effacer une connexion (#1366).
    line = json.dumps({"ts": time.time(), "event": event, "user": username, **details}) + "\n"
    fd = os.open(_AUDIT_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
    try:
        if os.fstat(fd).st_mode & 0o037:
            os.fchmod(fd, 0o640)
        os.write(fd, line.encode())
    finally:
        os.close(fd)


def _session_validator(jti: str) -> bool:
    return any(s.get("id") == jti for s in _read_sessions())


def _on_session_event(event: str, username: str, details: dict) -> None:
    _append_audit(event, username, details)
    if event == "sessions_coupees":
        # Couper des sessions PRÉCISES (#1369). Un appareil rattaché à « gk2 »
        # ouvre ses sessions au nom de gk2 : le révoquer ne doit couper que les
        # siennes, pas gk2 sur tous ses autres appareils.
        cibles = set(details.get("jtis") or [])
        if cibles:
            _muter_sessions(lambda rows: [r for r in rows if r.get("id") not in cibles])
        return
    if event == "login_success":
        ligne = {
            "id": details.get("jti", secrets.token_hex(8)),
            "username": username,
            "ip": details.get("ip", ""),
            "user_agent": details.get("user_agent", ""),
            "created": datetime.utcnow().isoformat(),
            "expires": int(time.time()) + details.get("expires_in", 86400),
            "type": "jwt",
        }
        _muter_sessions(lambda rows: rows + [ligne])


def _revoke_sessions(username: str) -> int:
    compte = {"n": 0}

    def _sans_le_compte(rows):
        keep = [r for r in rows if r.get("username") != username]
        compte["n"] = len(rows) - len(keep)
        return keep
    _muter_sessions(_sans_le_compte)
    _append_audit("sessions_revoked", username, {"count": compte["n"]})
    return compte["n"]


set_session_validator(_session_validator)
# Module-load registration so secubox_core.auth fires our handler from the first request.
set_session_callback(_on_session_event)
_users_engine.set_revoke_callback(_revoke_sessions)
_users_engine.set_audit_callback(lambda evt, user, d: _append_audit(evt, user, d))


def _verify_totp_ntp_aware(username: str, code: str) -> bool:
    """Verify TOTP via the engine with a window scaled by NTP health."""
    window = ntp_health.recommended_totp_window()
    return _users_engine.verify_totp_for_user(username, code, window=window)


# ─── Second facteur selon le réseau (#1699) ────────────────────────────
# Modèle de Gandalf : administration depuis le WAN = OTP obligatoire ; depuis
# le LAN = OTP FACULTATIF (le mot de passe suffit, même pour un compte
# enrôlé) ; à la console locale = sans authentification (#1695).
#
# « LAN » EST LE VERDICT DE NGINX, jamais le nôtre : derrière HAProxy → sbxwaf
# → nginx, l'adresse vue d'ici est 127.0.0.1 pour tout le monde. nginx résout
# l'adresse réelle depuis la DROITE de X-Forwarded-For (real_ip_recursive) puis
# pose X-SecuBox-LAN avec proxy_set_header, qui ÉCRASE la valeur d'un client.
# Absent (requête hors nginx) = pas LAN = OTP exigé : l'échec ferme.
from secubox_core.auth import _requete_lan

OTP_LAN_VALEURS = ("facultatif", "obligatoire")
_REGLAGES = Path(os.environ.get("SECUBOX_AUTH_REGLAGES", str(_DATA_DIR / "reglages.json")))


def _otp_lan() -> str:
    """Réglage `otp_lan` : reglages.json (panneau Utilisateurs) > [auth] otp_lan
    (secubox.conf) > « facultatif ». Une valeur inconnue ne compte pas."""
    try:
        v = json.loads(_REGLAGES.read_text()).get("otp_lan")
        if v in OTP_LAN_VALEURS:
            return v
    except (OSError, ValueError, AttributeError):
        pass
    try:
        v = (get_config("auth") or {}).get("otp_lan")
    except Exception:  # noqa: BLE001 — config illisible : le défaut
        v = None
    return v if v in OTP_LAN_VALEURS else "facultatif"


def _otp_exige(request) -> bool:
    """Le second facteur est-il exigé pour cette connexion ?"""
    if not _requete_lan(request):
        return True
    return _otp_lan() == "obligatoire"


# ─── Branching login router ────────────────────────────────────────────
from fastapi import APIRouter as _APIRouter, Request as _Request, Response as _Response
from secubox_core.auth import set_session_cookie as _set_session_cookie
from secubox_core.crypto.empreinte import ident

_login_router = _APIRouter(tags=["auth-v2"])


class _LoginIn(BaseModel):
    username: str
    password: str


class _MfaIn(BaseModel):
    code: str


class _SetPasswordIn(BaseModel):
    new_password: str
    old_password: Optional[str] = None


def _check_scope(authorization: Optional[str], expected_scope: str) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token Bearer manquant")
    payload = _jwt_decode(authorization.split(" ", 1)[1])
    if payload.get("scope") != expected_scope:
        raise HTTPException(status_code=403, detail="Token hors scope")
    return payload


def _client_meta(request: _Request) -> tuple:
    """(adresse, agent) pour la trace de TOUTE connexion (59bb18392, #1753).

    Effacé par la fusion aff481735 : /login/mfa et /totp/confirm écrivaient
    depuis une adresse VIDE et sans agent — or depuis #1699 toute connexion WAN
    d'un compte à double facteur passe par /login/mfa : les connexions qu'il
    importe le plus de tracer ne l'étaient pas. Adresse lue depuis la droite
    (`adresse_client`), agent tronqué à 300 (#1474 : 100 coupait avant le
    navigateur)."""
    from secubox_core.auth import adresse_client
    return adresse_client(request), request.headers.get("User-Agent", "")[:300]


@_login_router.post("/login")
def _login_v2(req: _LoginIn, request: _Request, response: _Response):
    """Branching login: setup_token / mfa_token / enrollment_token / access_token."""
    ip, ua = _client_meta(request)
    user = user_store.get_user(req.username)

    # LE COMPTE DE LA CONSOLE N'ENTRE QUE PAR LE KIOSQUE (#1695) — jamais par
    # mot de passe. Vérifié AVANT la branche de première configuration : un
    # compte tout juste créé a encore un mot de passe vide à « définir », et
    # quiconque connaissant son nom en aurait fait un administrateur.
    # Un compte DÉLÉGUÉ par un autre nœud (#1720) n'entre que par délégation.
    if req.username in _deleg.lire_registre(_DELEGUES):
        _emit_session_event("login_failed", req.username, {
            "reason": "compte_delegue", "ip": ip, "user_agent": ua,
        })
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    try:
        _cfg_console = get_config("console")
    except Exception:  # noqa: BLE001 — config illisible : le nom par défaut, refus maintenu
        _cfg_console = {}
    if req.username == _console.reglages(_cfg_console)["compte"]:
        _emit_session_event("login_failed", req.username, {
            "reason": "console_hors_kiosque", "ip": ip, "user_agent": ua,
        })
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    if not user or not user.get("enabled"):
        _emit_session_event("login_failed", req.username, {
            "reason": "unknown_user" if not user else "disabled",
            "ip": ip, "user_agent": ua,
        })
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    # PREMIÈRE CONFIGURATION : UN ACTE LOCAL (#1707). Un compte « à changer »
    # sans mot de passe recevait un jeton « set-password » à quiconque donnait
    # son nom avec un mot de passe vide — depuis n'importe où. Le nom d'un compte
    # admin est souvent celui du nœud, donc celui du domaine : la prise du compte
    # tenait en deux requêtes. La première configuration ne se fait désormais
    # que depuis le réseau local (verdict nginx), et seulement pour un compte qui
    # n'a encore AUCUN mot de passe ; depuis le WAN, un compte « à changer » ne
    # s'ouvre pas du tout.
    lan = _requete_lan(request)
    a_changer = bool(user.get("must_change_password"))
    if a_changer and not lan:
        _emit_session_event("login_failed", req.username, {
            "reason": "premiere_configuration_hors_lan", "ip": ip, "user_agent": ua,
        })
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    if a_changer and req.password == "" and not user.get("password_hash"):
        setup_tok = create_token(req.username, scope="set-password", expires_in=900)
        _append_audit("setup_token_issued", req.username, {"ip": ip})
        return {"setup_required": True, "setup_token": setup_tok}

    if not user.get("password_hash"):
        _emit_session_event("login_failed", req.username, {"reason": "no_local_password", "ip": ip})
        raise HTTPException(status_code=401, detail="Aucun mot de passe local")

    if not user_store.verify_password(req.username, req.password):
        _emit_session_event("login_failed", req.username, {"reason": "invalid_credentials", "ip": ip})
        raise HTTPException(status_code=401, detail="Identifiants incorrects")

    # « À changer » avec un mot de passe (le admin/secubox du premier démarrage) :
    # le bon mot de passe ouvre le CHANGEMENT, jamais une session directe.
    if a_changer:
        setup_tok = create_token(req.username, scope="set-password", expires_in=900)
        _append_audit("setup_token_issued", req.username, {"ip": ip, "motif": "changement_impose"})
        return {"setup_required": True, "setup_token": setup_tok}

    # LE COFFRE S'OUVRE À LA CONNEXION (#1855) : mot de passe vérifié, on
    # PRÉPARE ; l'ouverture n'a lieu qu'une fois le second facteur réussi.
    ticket_coffre = _coffre.preparer(req.username, req.password)

    # Second facteur : exigé depuis le WAN, facultatif sur le LAN (#1699).
    otp = _otp_exige(request)
    totp_block = user.get("totp") or {}
    if otp and totp_block.get("enabled"):
        mfa_jti = secrets.token_hex(8)
        mfa_tok = create_token(req.username, scope="mfa-challenge", expires_in=300, jti=mfa_jti)
        _coffre.garder(mfa_jti, ticket_coffre, not lan, 300)
        _append_audit("mfa_challenge_issued", req.username, {"ip": ip})
        return {"mfa_required": True, "mfa_token": mfa_tok}

    # Admin without TOTP → force enrollment (depuis le WAN)
    if otp and user.get("role") == "admin":
        enroll_jti = secrets.token_hex(8)
        enroll_tok = create_token(req.username, scope="totp-enroll", expires_in=900, jti=enroll_jti)
        _coffre.garder(enroll_jti, ticket_coffre, not lan, 900)
        _append_audit("totp_enrollment_required", req.username, {"ip": ip})
        return {"enrollment_required": True, "enrollment_token": enroll_tok}

    # Second facteur exigé (WAN) mais absent pour ce compte (un utilisateur sans
    # TOTP) : un mot de passe seul n'ouvre rien — le ticket expirera de lui-même.
    _coffre.confirmer(None if otp else ticket_coffre, not lan)
    jti = secrets.token_hex(8)
    tok = create_token(req.username, jti=jti)
    _set_session_cookie(response, tok, request=request)  # SSO-lite (#400, #1723)
    _on_session_event("login_success", req.username, {
        "jti": jti, "expires_in": 86400, "ip": ip, "user_agent": ua,
        "otp": "exigé" if otp else "facultatif (LAN)",
    })
    _users_engine.touch_last_login(req.username)
    return {"access_token": tok, "token_type": "bearer", "expires_in": 86400}


# ─── Console locale du kiosque (#1695) ─────────────────────────────────
# Sans authentification, et au seul kiosque : les garanties sont dans
# api/console.py. Ici : le compte dédié, et une session ordinaire (jti inscrit,
# journalisée, visible et révocable dans la liste des sessions).
_console_lock = threading.Lock()
_console_session: Dict[str, Any] = {"jti": None, "jeton": None, "fin": 0}


def _console_compte(nom: str) -> None:
    """Crée le compte dédié s'il manque ; refuse s'il est désactivé ou n'est
    pas admin — le désactiver est la façon de couper la console."""
    u = _users_engine.get_user(nom)
    if u is None:
        _users_engine.create_user(nom, None, "admin")
        # Un mot de passe aléatoire, jeté : `create_user` laisse un mot de
        # passe vide « à définir », que /login ouvrirait à quiconque.
        _users_engine.set_password(nom, secrets.token_urlsafe(48))
        _append_audit("console_compte_cree", nom, {})
        u = _users_engine.get_user(nom) or {}
    if not u.get("enabled"):
        raise HTTPException(status_code=403, detail=f"compte « {nom} » désactivé : console coupée")
    if u.get("role") != "admin":
        raise HTTPException(status_code=409, detail=f"le compte « {nom} » n'est pas administrateur")


@_login_router.get("/console/jeton")
def _console_jeton(request: _Request):
    """Session d'administration de la console locale. Ne répond qu'à nginx, par
    le port console, pour une connexion du kiosque (voir api/console.py)."""
    cfg = get_config("console")
    motif = _console.refus(
        secret_fourni=request.headers.get("x-secubox-console", ""),
        paire=request.headers.get("x-secubox-console-paire", ""),
        # Posé par nginx (l'agrégateur réécrit Host quand il relaie vers auth.sock).
        hote=request.headers.get("x-secubox-console-hote", ""),
        origine=request.headers.get("origin"),
        cfg=cfg,
        uid=_console.uid_kiosque(),
    )
    if motif:
        _append_audit("console_refusee", "console", {"motif": motif})
        raise HTTPException(status_code=403, detail=motif)
    nom = _console.reglages(cfg)["compte"]
    _console_compte(nom)
    with _console_lock:
        s = _console_session
        maintenant = time.time()
        # Une session par demi-journée, pas une par page : le Hall et la page
        # de connexion la demandent tous deux au premier affichage.
        if (s["jeton"] and s.get("compte") == nom and s["fin"] - maintenant > 3600
                and _session_validator(s["jti"])):
            return {"access_token": s["jeton"], "token_type": "bearer",
                    "expires_in": int(s["fin"] - maintenant), "compte": nom}
        jti = secrets.token_hex(8)
        jeton = create_token(nom, expires_in=_console.DUREE, jti=jti)
        _on_session_event("login_success", nom, {
            "jti": jti, "expires_in": _console.DUREE, "ip": "127.0.0.1",
            "user_agent": "console locale (kiosque)", "source": "console",
        })
        _users_engine.touch_last_login(nom)
        _console_session.update(jti=jti, jeton=jeton, fin=maintenant + _console.DUREE, compte=nom)
    return {"access_token": jeton, "token_type": "bearer", "expires_in": _console.DUREE, "compte": nom}


# ─── Entrée déléguée d'un autre nœud (#1720) ───────────────────────────
_DELEGUES = Path(os.environ.get("SECUBOX_AUTH_DELEGUES", str(_DATA_DIR / "delegues.json")))


def _compte_delegue(nom: str) -> None:
    u = _users_engine.get_user(nom)
    if u is None:
        _users_engine.create_user(nom, None, "admin")
        # Mot de passe aléatoire jeté : le compte n'entre que par délégation.
        _users_engine.set_password(nom, secrets.token_urlsafe(48))
        _append_audit("delegation_compte_cree", nom, {})
        u = _users_engine.get_user(nom) or {}
    if not u.get("enabled"):
        raise HTTPException(status_code=403, detail=f"compte « {nom} » désactivé : délégation refusée")
    if u.get("role") != "admin":
        raise HTTPException(status_code=409, detail=f"le compte « {nom} » n'est pas administrateur")


@_login_router.get("/delegation/entrer")
def _delegation_entrer(a: str, request: _Request):
    """Entrée d'un compte d'aide d'un autre nœud, sur assertion signée par ce
    nœud, tant que CETTE box a autorisé l'administration à distance."""
    from fastapi.responses import HTMLResponse as _HTML  # noqa: PLC0415
    ip, _ua = _client_meta(request)   # depuis la droite : trace de délégation non forgeable
    try:
        self_did = _deleg.did_du_noeud()
        entries = _deleg.entrees()
        p = _deleg.verifier_entree(a, entries, self_did)
    except ValueError as exc:
        _append_audit("delegation_refusee", "?", {"motif": str(exc), "ip": ip})
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 — annuaire absent, clé illisible…
        _append_audit("delegation_refusee", "?", {"motif": f"indisponible : {exc}", "ip": ip})
        raise HTTPException(status_code=503, detail="délégation indisponible sur cette box")
    nom = _deleg.nom_compte(p["compte"], p["noeud"])
    _compte_delegue(nom)
    reg = _deleg.lire_registre(_DELEGUES)
    reg[nom] = {"centre": p["center_did"], "noeud": p["noeud"], "compte": p["compte"],
                "session": p["session_id"]}
    _deleg.ecrire_registre(_DELEGUES, reg)
    fin_ts = datetime.strptime(p["fin"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    duree = max(60, int(fin_ts - time.time()))
    jti = secrets.token_hex(8)
    jeton = create_token(nom, expires_in=duree, jti=jti, delegation={
        "centre": p["center_did"], "noeud": p["noeud"], "compte": p["compte"], "session": p["session_id"]})
    _on_session_event("login_success", nom, {
        "jti": jti, "expires_in": duree, "ip": ip,
        "user_agent": f"délégation {p['compte']}@{p['noeud']}", "source": "delegation",
        "centre": p["center_did"], "session_assistance": p["session_id"],
    })
    rep = _HTML(_deleg.PAGE.format(etiquette=f"{p['compte']}@{p['noeud']}", fin=p["fin"],
                                   jeton=json.dumps(jeton)))
    rep.headers["Cache-Control"] = "no-store"
    return rep


def _veille_delegations_une_fois() -> None:
    """Retire les sessions des comptes délégués dont l'autorisation a cessé."""
    reg = _deleg.lire_registre(_DELEGUES)
    if not reg:
        return
    try:
        a_fermer = set(_deleg.fermees(reg, _deleg.entrees(), _deleg.did_du_noeud()))
    except Exception:  # noqa: BLE001
        return
    if not a_fermer:
        return
    _muter_sessions(lambda rows: [r for r in rows if r.get("username") not in a_fermer])
    for nom in a_fermer:
        _append_audit("delegation_fermee", nom, {"session_assistance": reg[nom].get("session")})
        reg.pop(nom, None)
    _deleg.ecrire_registre(_DELEGUES, reg)


@app.on_event("startup")
async def _veille_delegations() -> None:
    async def boucle():
        while True:
            await asyncio.sleep(30)
            try:
                await asyncio.to_thread(_veille_delegations_une_fois)
            except Exception:  # noqa: BLE001
                pass
    asyncio.create_task(boucle())


@_login_router.post("/login/mfa")
async def _login_mfa(req: _MfaIn, request: _Request, response: _Response):
    payload = _check_scope(request.headers.get("Authorization"), "mfa-challenge")
    username = payload["sub"]
    if not user_store.is_enabled(username):
        raise HTTPException(status_code=401, detail="Compte désactivé")
    ok = (_verify_totp_ntp_aware(username, req.code)
          or _users_engine.consume_backup_code(username, req.code))
    if not ok:
        _append_audit("mfa_failed", username, {})
        raise HTTPException(status_code=401, detail="Code invalide")
    _coffre.confirmer_garde(payload.get("jti"))       # second facteur réussi : le Coffre s'ouvre (#1855)
    jti = secrets.token_hex(8)
    tok = create_token(username, jti=jti)
    _set_session_cookie(response, tok, request=request)  # SSO-lite (#400, #1723)
    ip, ua = _client_meta(request)
    _on_session_event("login_success", username, {"jti": jti, "expires_in": 86400,
                                                  "ip": ip, "user_agent": ua})
    _users_engine.touch_last_login(username)
    return {"access_token": tok, "token_type": "bearer", "expires_in": 86400}


@_login_router.post("/totp/enroll")
async def _totp_enroll(request: _Request):
    payload = _check_scope(request.headers.get("Authorization"), "totp-enroll")
    username = payload["sub"]
    existing = user_store.get_user(username) or {}
    if (existing.get("totp") or {}).get("enabled"):
        raise HTTPException(status_code=409, detail="Déjà enrôlé")
    secret = _users_totp_mod.generate_secret()
    _pending.put(payload["jti"], secret)
    import socket as _socket
    issuer = f"SecuBox · {_socket.gethostname()}"
    uri = _users_totp_mod.provisioning_uri(username, secret, issuer=issuer)
    qr_png = _users_totp_mod.qr_png_b64(uri)
    return {"secret": secret, "otpauth_uri": uri, "qr_png_b64": qr_png}


@_login_router.post("/totp/confirm")
def _totp_confirm(req: _MfaIn, request: _Request, response: _Response):
    payload = _check_scope(request.headers.get("Authorization"), "totp-enroll")
    username = payload["sub"]
    secret = _pending.get(payload["jti"])
    if not secret:
        raise HTTPException(status_code=410, detail="Enrôlement expiré")
    import pyotp as _pyotp
    if not _pyotp.TOTP(secret).verify(req.code, valid_window=1):
        raise HTTPException(status_code=401, detail="Code invalide")
    backup_plain = _users_engine.enroll_totp(username, secret)
    _pending.delete(payload["jti"])
    _coffre.confirmer_garde(payload.get("jti"))       # second facteur enrôlé et vérifié (#1855)
    jti = secrets.token_hex(8)
    tok = create_token(username, jti=jti)
    _set_session_cookie(response, tok, request=request)  # SSO-lite (#400, #1723)
    ip, ua = _client_meta(request)
    _on_session_event("login_success", username, {"jti": jti, "expires_in": 86400,
                                                  "ip": ip, "user_agent": ua})
    return {
        "access_token": tok, "token_type": "bearer", "expires_in": 86400,
        "backup_codes": backup_plain,
        "backup_codes_note": "Conservez ces codes. Affichés une seule fois.",
    }


@_login_router.post("/set-password")
def _set_password(req: _SetPasswordIn, request: _Request):
    auth_h = request.headers.get("Authorization", "")
    if not auth_h.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token Bearer manquant")
    payload = _jwt_decode(auth_h.split(" ", 1)[1])
    scope = payload.get("scope")
    username = payload["sub"]
    if scope == "set-password":
        _users_engine.set_password(username, req.new_password)
        _users_engine.revoke_sessions(username)
        return {"ok": True, "message": "Mot de passe défini, veuillez vous reconnecter"}
    if scope is None:
        # Change-my-password with full JWT
        if not req.old_password:
            raise HTTPException(status_code=400, detail="Ancien mot de passe requis")
        if not user_store.verify_password(username, req.old_password):
            raise HTTPException(status_code=401, detail="Ancien mot de passe incorrect")
        _users_engine.set_password(username, req.new_password)
        _coffre.changer(username, req.old_password, req.new_password)   # la serrure du Coffre suit (#1855)
        return {"ok": True, "message": "Mot de passe modifié"}
    raise HTTPException(status_code=403, detail="Token hors scope")


@_login_router.get("/preflight", dependencies=[Depends(require_lecture)])
async def _auth_preflight():
    """Public-readable preflight surface for the UI banner.

    Returns NTP-health + identity-store source. UI uses this to render warnings
    like "Identity store in fallback mode" or "Clock not synced — TOTP may fail".

    Distinct from the legacy `/health` liveness check (sidebar consumer):
    `/health` answers "is the service up?", `/preflight` answers "is auth healthy?".
    """
    src = user_store.load_with_fallback()
    return {
        "ntp": ntp_health.probe(),
        "totp_window": ntp_health.recommended_totp_window(),
        "identity_source": src.get("source"),
        "identity_fallback": src.get("source") == "auth.toml.fallback",
    }


# Mount v2 router FIRST so its /login overrides the legacy auth_router /login.
# FastAPI uses the first matching route, so _login_router must come before auth_router.
# Mounted under both prefixes: "" for the canonical URL (/api/v1/auth/login after nginx
# strips the /api/v1/auth/ prefix) and "/auth" for the legacy doubled URL
# (/api/v1/auth/auth/login), so existing frontend code keeps working during the cutover.
app.include_router(_login_router, prefix="")
app.include_router(_login_router, prefix="/auth")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()

# Configuration — all paths are env-overridable via _DATA_DIR (SECUBOX_AUTH_DATA_DIR)
VOUCHERS_FILE = _DATA_DIR / "vouchers.json"
HISTORY_FILE = _DATA_DIR / "history.json"
WEBHOOKS_FILE = _DATA_DIR / "webhooks.json"
STATS_FILE = _DATA_DIR / "stats.json"


class StatsCache:
    """Thread-safe stats cache with TTL."""

    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=30)


# Pydantic Models
class VoucherRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100)
    duration_hours: int = Field(default=24, ge=1, le=8760)
    bandwidth_mb: int = Field(default=0, ge=0)
    prefix: str = Field(default="SBX", max_length=10)


class ProviderRequest(BaseModel):
    provider_id: str
    client_id: str
    client_secret: str
    enabled: bool = True


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = Field(default=["login", "logout", "voucher_redeemed", "session_revoked"])
    secret: Optional[str] = None
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


# State
_cleanup_task: Optional[asyncio.Task] = None


def _load(p: Path, default=None):
    """Load JSON file safely."""
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return default if default is not None else []


def _save(p: Path, data):
    """Save JSON file safely."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    # Jamais modifiable par tous (#1366). La lecture reste telle quelle :
    # sessions.json est lu par d'autres modules (voir postinst).
    mode = p.stat().st_mode
    if mode & 0o002:
        os.chmod(p, mode & 0o775)


def _load_history() -> List[Dict[str, Any]]:
    return _load(HISTORY_FILE, [])


def _save_history(history: List[Dict[str, Any]]):
    history = history[-2000:]
    _save(HISTORY_FILE, history)


def _load_webhooks() -> List[Dict[str, Any]]:
    return _load(WEBHOOKS_FILE, [])


def _save_webhooks(webhooks: List[Dict[str, Any]]):
    _save(WEBHOOKS_FILE, webhooks)


def _record_event(event: str, details: Optional[Dict] = None):
    """Record an event in history."""
    history = _load_history()
    entry = {
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "details": details or {}
    }
    history.append(entry)
    _save_history(history)


async def _send_webhook(url: str, payload: Dict[str, Any], secret: Optional[str] = None):
    """Send webhook notification."""
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload)

        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers["X-SecuBox-Signature"] = f"sha256={signature}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, content=body, headers=headers)
    except Exception:
        pass


async def _notify_webhooks(event: str, data: Dict[str, Any]):
    """Send notifications to all webhooks for event."""
    webhooks = _load_webhooks()
    for webhook in webhooks:
        if webhook.get("enabled", True) and event in webhook.get("events", []):
            await _send_webhook(
                webhook["url"],
                {"event": event, "data": data, "timestamp": datetime.now().isoformat()},
                webhook.get("secret")
            )


def _cleanup_expired():
    """Remove expired sessions and update stats."""
    now = int(time.time())
    sessions = _load(_SESSIONS_FILE, [])
    active = [s for s in sessions if s.get("expires", 0) > now]
    expired_count = len(sessions) - len(active)

    if expired_count > 0:
        _save(_SESSIONS_FILE, active)
        _record_event("sessions_expired", {"count": expired_count})

    return expired_count


async def _periodic_cleanup():
    """Background task to clean up expired sessions."""
    while True:
        try:
            _cleanup_expired()
        except Exception:
            pass
        await asyncio.sleep(300)  # Every 5 minutes



@app.on_event("startup")
async def startup():
    """Start background cleanup task."""
    global _cleanup_task
    _cleanup_task = asyncio.create_task(_periodic_cleanup())


@app.on_event("shutdown")
async def shutdown():
    """Stop background cleanup."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()


# Public endpoints
@router.get("/health")
async def health():
    return {"status": "ok", "module": "auth", "version": "2.0.0"}


# Le bouton « 2FA » du panneau Utilisateurs appelle /settings — une route
# disparue du code (404) depuis juillet. Elle revient pour la seule politique
# qui reste réglable : l'OTP sur le LAN. Depuis le WAN, il est toujours exigé.
class _ReglagesIn(BaseModel):
    otp_lan: Optional[str] = None
    # Ancien contrat du bouton : vrai = « 2FA des admins exigée ».
    require_admin_totp: Optional[bool] = None


def _reglages_vue() -> Dict[str, Any]:
    v = _otp_lan()
    return {"otp_lan": v, "otp_wan": "obligatoire", "require_admin_totp": v == "obligatoire"}


@router.get("/settings")
async def reglages_lire(user=Depends(require_jwt)):
    return _reglages_vue()


@router.post("/settings")
async def reglages_ecrire(body: _ReglagesIn, user=Depends(require_jwt)):
    v = body.otp_lan
    if v is None and body.require_admin_totp is not None:
        v = "obligatoire" if body.require_admin_totp else "facultatif"
    if v not in OTP_LAN_VALEURS:
        raise HTTPException(status_code=400, detail="otp_lan : « facultatif » ou « obligatoire »")
    tmp = _REGLAGES.with_suffix(".tmp")
    tmp.write_text(json.dumps({"otp_lan": v}))
    tmp.replace(_REGLAGES)
    _append_audit("reglage_otp_lan", user.get("sub", ""), {"otp_lan": v})
    return _reglages_vue()


@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Get auth module status."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    cfg = get_config("oauth")
    now = int(time.time())
    sessions = _load(_SESSIONS_FILE, [])
    active_sessions = [s for s in sessions if s.get("expires", 0) > now]
    vouchers = _load(VOUCHERS_FILE, [])

    result = {
        "sessions": {
            "active": len(active_sessions),
            "total": len(sessions)
        },
        "vouchers": {
            "total": len(vouchers),
            "unused": sum(1 for v in vouchers if not v.get("used")),
            "used": sum(1 for v in vouchers if v.get("used"))
        },
        "oauth_providers": list(cfg.keys()) if cfg else [],
        "timestamp": datetime.now().isoformat()
    }

    stats_cache.set("status", result)
    return result


@router.get("/sessions")
async def sessions(user=Depends(require_jwt)):
    """Get active sessions."""
    now = int(time.time())
    all_sessions = _load(_SESSIONS_FILE, [])
    active = []

    for s in all_sessions:
        if s.get("expires", 0) > now:
            session = s.copy()
            session["remaining_seconds"] = s.get("expires", 0) - now
            session["remaining_human"] = str(timedelta(seconds=session["remaining_seconds"]))
            active.append(session)

    return {
        "sessions": active,
        "count": len(active)
    }


@router.get("/sessions/stats")
async def session_stats(user=Depends(require_jwt)):
    """Get session statistics."""
    now = int(time.time())
    sessions = _load(_SESSIONS_FILE, [])
    active = [s for s in sessions if s.get("expires", 0) > now]

    # Group by type
    by_type: Dict[str, int] = {}
    for s in active:
        stype = s.get("type", "unknown")
        by_type[stype] = by_type.get(stype, 0) + 1

    return {
        "total": len(sessions),
        "active": len(active),
        "expired": len(sessions) - len(active),
        "by_type": by_type,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/vouchers")
async def vouchers(user=Depends(require_jwt)):
    """Get all vouchers."""
    all_vouchers = _load(VOUCHERS_FILE, [])
    return {
        "vouchers": all_vouchers,
        "total": len(all_vouchers),
        "unused": sum(1 for v in all_vouchers if not v.get("used")),
        "used": sum(1 for v in all_vouchers if v.get("used"))
    }


@router.get("/vouchers/stats")
async def voucher_stats(user=Depends(require_jwt)):
    """Get voucher statistics."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    now = int(time.time())

    # Recent usage (last 24h)
    cutoff = now - 86400
    recent_used = sum(
        1 for v in vouchers_list
        if v.get("used") and v.get("used_at", 0) > cutoff
    )

    # By prefix
    by_prefix: Dict[str, Dict[str, int]] = {}
    for v in vouchers_list:
        code = v.get("code", "")
        prefix = code.split("-")[0] if "-" in code else "UNKNOWN"
        if prefix not in by_prefix:
            by_prefix[prefix] = {"total": 0, "used": 0}
        by_prefix[prefix]["total"] += 1
        if v.get("used"):
            by_prefix[prefix]["used"] += 1

    return {
        "total": len(vouchers_list),
        "unused": sum(1 for v in vouchers_list if not v.get("used")),
        "used": sum(1 for v in vouchers_list if v.get("used")),
        "used_last_24h": recent_used,
        "by_prefix": by_prefix,
        "timestamp": datetime.now().isoformat()
    }


@router.get("/oauth_providers")
async def oauth_providers(user=Depends(require_jwt)):
    """List OAuth providers."""
    cfg = get_config("oauth")
    providers = []
    for k, v in (cfg or {}).items():
        providers.append({
            "id": k,
            "configured": bool(v.get("client_id")),
            "enabled": v.get("enabled", True)
        })
    return {"providers": providers}


@router.get("/splash_config")
async def splash_config(user=Depends(require_jwt)):
    """Get captive portal splash config."""
    cfg = get_config("auth") or {}
    return {
        "title": cfg.get("splash_title", "SecuBox Guest Access"),
        "logo": cfg.get("splash_logo", "/logo.png"),
        "methods": cfg.get("splash_methods", ["voucher", "oauth"]),
        "welcome_message": cfg.get("welcome_message", "Welcome to SecuBox Network")
    }


@router.get("/bypass_rules")
async def bypass_rules(user=Depends(require_jwt)):
    """Get auth bypass rules."""
    rules_file = Path("/etc/secubox/auth-bypass.json")
    return {"rules": _load(rules_file, [])}


@router.post("/generate_vouchers")
async def generate_vouchers(req: VoucherRequest, user=Depends(require_jwt)):
    """Generate new vouchers."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    new_vouchers = []

    for _ in range(req.count):
        code = f"{req.prefix}-{secrets.token_hex(4).upper()}"
        v = {
            "code": code,
            "duration_hours": req.duration_hours,
            "bandwidth_mb": req.bandwidth_mb,
            "created": int(time.time()),
            "created_at": datetime.now().isoformat(),
            "used": False,
            "created_by": user.get("sub", "unknown")
        }
        vouchers_list.append(v)
        new_vouchers.append(v)

    _save(VOUCHERS_FILE, vouchers_list)
    _record_event("vouchers_generated", {
        "count": len(new_vouchers),
        "prefix": req.prefix,
        "by": user.get("sub")
    })
    stats_cache.clear()

    return {
        "created": len(new_vouchers),
        "vouchers": new_vouchers
    }


@router.post("/redeem_voucher")
async def redeem_voucher(code: str, client_ip: Optional[str] = None):
    """Redeem a voucher (public endpoint)."""
    vouchers_list = _load(VOUCHERS_FILE, [])

    for v in vouchers_list:
        if v["code"] == code and not v.get("used"):
            v["used"] = True
            v["used_at"] = int(time.time())
            v["used_at_iso"] = datetime.now().isoformat()
            v["client_ip"] = client_ip

            _save(VOUCHERS_FILE, vouchers_list)

            # Create session
            sessions = _load(_SESSIONS_FILE, [])
            session = {
                "id": secrets.token_hex(8),
                "type": "voucher",
                "voucher_code": code,
                "created": int(time.time()),
                "expires": int(time.time()) + v["duration_hours"] * 3600,
                "client_ip": client_ip,
                "bandwidth_mb": v.get("bandwidth_mb", 0)
            }
            sessions.append(session)
            _save(_SESSIONS_FILE, sessions)

            token = create_token(f"voucher:{code}", expires_in=v["duration_hours"] * 3600)

            _record_event("voucher_redeemed", {
                "code": code,
                "client_ip": client_ip,
                "duration_hours": v["duration_hours"]
            })
            await _notify_webhooks("voucher_redeemed", {
                "code": code,
                "client_ip": client_ip
            })
            stats_cache.clear()

            return {
                "success": True,
                "token": token,
                "session_id": session["id"],
                "expires_in": v["duration_hours"] * 3600
            }

    raise HTTPException(400, "Voucher invalide ou déjà utilisé")


@router.get("/validate_voucher")
async def validate_voucher(code: str, user=Depends(require_jwt)):
    """Validate a voucher without consuming it."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    for v in vouchers_list:
        if v["code"] == code:
            return {
                "valid": not v.get("used", False),
                "voucher": v
            }
    return {"valid": False, "error": "Voucher not found"}


@router.post("/delete_voucher")
async def delete_voucher(code: str, user=Depends(require_jwt)):
    """Delete a voucher."""
    vouchers_list = _load(VOUCHERS_FILE, [])
    original_count = len(vouchers_list)
    vouchers_list = [v for v in vouchers_list if v.get("code") != code]

    if len(vouchers_list) < original_count:
        _save(VOUCHERS_FILE, vouchers_list)
        _record_event("voucher_deleted", {"code": code, "by": user.get("sub")})
        stats_cache.clear()
        return {"success": True, "deleted": code}

    return {"success": False, "error": "Voucher not found"}


@router.post("/revoke_session")
async def revoke_session(session_id: str, user=Depends(require_jwt)):
    """Revoke a session."""
    sessions = _load(_SESSIONS_FILE, [])
    original_count = len(sessions)
    revoked_session = next((s for s in sessions if s.get("id") == session_id), None)
    sessions = [s for s in sessions if s.get("id") != session_id]

    if len(sessions) < original_count:
        _save(_SESSIONS_FILE, sessions)
        _record_event("session_revoked", {
            "session_id": session_id,
            "by": user.get("sub"),
            "session_type": revoked_session.get("type") if revoked_session else "unknown"
        })
        await _notify_webhooks("session_revoked", {"session_id": session_id})
        stats_cache.clear()
        return {"success": True, "revoked": session_id}

    return {"success": False, "error": "Session not found"}


@router.post("/set_provider")
async def set_provider(req: ProviderRequest, user=Depends(require_jwt)):
    """Configure an OAuth provider."""
    _record_event("provider_configured", {
        "provider_id": req.provider_id,
        "by": user.get("sub")
    })
    return {"success": True, "provider": req.provider_id}


@router.post("/delete_provider")
async def delete_provider(provider_id: str, user=Depends(require_jwt)):
    """Delete an OAuth provider."""
    _record_event("provider_deleted", {
        "provider_id": provider_id,
        "by": user.get("sub")
    })
    return {"success": True, "deleted": provider_id}


@router.get("/history")
async def get_history(limit: int = 100, event: Optional[str] = None, user=Depends(require_jwt)):
    """Get event history."""
    history = _load_history()

    if event:
        history = [h for h in history if h.get("event") == event]

    return {
        "events": history[-limit:],
        "total": len(history)
    }


@router.get("/logs")
def get_logs(lines: int = 100, user=Depends(require_jwt)):
    """Get auth service logs."""
    try:
        r = subprocess.run(
            ["journalctl", "-u", "secubox-auth", "-n", str(min(lines, 500)), "--no-pager"],
            capture_output=True, text=True, timeout=10
        )
        return {"lines": r.stdout.splitlines(), "count": len(r.stdout.splitlines())}
    except Exception as e:
        return {"lines": [], "error": str(e)}


@router.get("/webhooks")
async def list_webhooks(user=Depends(require_jwt)):
    """List configured webhooks."""
    return {"webhooks": _load_webhooks()}


@router.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user=Depends(require_jwt)):
    """Add a new webhook."""
    webhooks = _load_webhooks()
    webhook_data = webhook.model_dump()
    webhook_data["id"] = ident(webhook.url, n=8)
    webhook_data["created_at"] = datetime.now().isoformat()
    webhooks.append(webhook_data)
    _save_webhooks(webhooks)
    return {"success": True, "webhook": webhook_data}


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, user=Depends(require_jwt)):
    """Delete a webhook."""
    webhooks = _load_webhooks()
    webhooks = [w for w in webhooks if w.get("id") != webhook_id]
    _save_webhooks(webhooks)
    return {"success": True}


@router.get("/summary")
async def summary(user=Depends(require_jwt)):
    """Get auth module summary."""
    now = int(time.time())
    sessions = _load(_SESSIONS_FILE, [])
    vouchers_list = _load(VOUCHERS_FILE, [])
    cfg = get_config("oauth")

    active_sessions = [s for s in sessions if s.get("expires", 0) > now]

    # Recent activity (last 24h)
    history = _load_history()
    cutoff = datetime.now() - timedelta(hours=24)
    recent = [
        h for h in history
        if datetime.fromisoformat(h.get("timestamp", "2000-01-01")) > cutoff
    ]

    return {
        "sessions": {
            "active": len(active_sessions),
            "total": len(sessions)
        },
        "vouchers": {
            "total": len(vouchers_list),
            "unused": sum(1 for v in vouchers_list if not v.get("used")),
            "used": sum(1 for v in vouchers_list if v.get("used"))
        },
        "oauth_providers": len(cfg) if cfg else 0,
        "activity_24h": len(recent),
        "recent_events": history[-5:],
        "webhooks_configured": len(_load_webhooks()),
        "timestamp": datetime.now().isoformat()
    }


# Aliases for compatibility
@router.get("/list_providers")
async def list_providers(user=Depends(require_jwt)):
    return await oauth_providers(user)


@router.get("/list_vouchers")
async def list_vouchers(user=Depends(require_jwt)):
    return await vouchers(user)


@router.post("/create_voucher")
async def create_voucher(
    duration_hours: int = 24,
    bandwidth_mb: int = 0,
    prefix: str = "SBX",
    user=Depends(require_jwt)
):
    req = VoucherRequest(count=1, duration_hours=duration_hours, bandwidth_mb=bandwidth_mb, prefix=prefix)
    result = await generate_vouchers(req, user)
    return result["vouchers"][0] if result["vouchers"] else {}


@router.get("/list_sessions")
async def list_sessions(user=Depends(require_jwt)):
    return await sessions(user)


app.include_router(router)
