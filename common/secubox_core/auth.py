# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox core auth — JWT HS256 over a `user_store`-backed identity.

Compared to v1 (plaintext `auth.toml` lookup), this module:
- delegates password verification to `secubox_core.user_store`
- adds a `jti` claim to every issued token
- validates the `jti` against an externally-injected session validator
- carries an optional `scope` claim for short-lived setup / mfa / enroll tokens
- defensively re-checks `is_enabled` on every authenticated request
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# PyJWT ET NON python-jose (#1294). python3-jose a ete RETIRE de Debian 13 :
# il n'existe plus que dans oldstable, et un debootstrap trixie echoue net sur
# « Couldn't find these debs: python3-jose ». Comme secubox-core en dependait,
# TOUTE la pile devenait ininstallable sur trixie.
#
# python3-jwt existe dans les DEUX suites (2.6.0 en bookworm, 2.10.1 en
# trixie), l'API encode/decode est identique, et ExpiredSignatureError derive
# de PyJWTError comme elle derivait de JWTError — la clause `except` garde donc
# exactement la meme portee. secubox-portal utilisait deja PyJWT : cette
# migration supprime aussi une seconde bibliotheque JWT pour le meme besoin.
import jwt
from jwt import PyJWTError as JWTError
from pydantic import BaseModel

from . import sessions as _sessions
from . import appareils, user_store
from . import origine as _origine
from .config import get_config
from .logger import get_logger

log = get_logger("auth")
_bearer = HTTPBearer(auto_error=False)

# Session callbacks ─────────────────────────────────────────────────────
_session_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None

# Default validator — FAIL-CLOSED since #942.
#
# It used to be `lambda jti: True`. Only `secubox-auth` ever calls
# `set_session_validator()`, so every module served on its own socket (44 of
# them on gk2) accepted revoked sessions forever, and the 116 mounted in the
# aggregator were covered only by the side effect of `auth` being imported
# into the same interpreter — a protection that silently vanished whenever
# that import failed.
#
# The shared read-only store answers the same question without an IPC hop.
# `secubox-auth` still overrides this with its own writer-side validator.
_session_validator: Callable[[str], bool] = _sessions.is_valid



def _samesite(secure: bool) -> str:
    """Politique SameSite d'un cookie SecuBox (commit dfc315826, « Les cookies
    SecuBox survivent au cadre » ; docs/MODULE-GUIDELINES.md §8bis).

    None sous TLS : un module encadré par le Hall servi sur un AUTRE site
    (hall.gk2.net) est un contexte tiers, où un cookie Lax n'est pas joint.
    Le cookie étant alors joint à toute requête vers *.<domaine>, les
    écritures qui s'authentifient par lui passent par la garde d'origine
    (secubox_core.origine, #1607)."""
    force = os.environ.get("SECUBOX_COOKIE_SAMESITE", "").strip().lower()
    if force in ("lax", "strict", "none"):
        return force
    return "none" if secure else "lax"

def set_session_callback(cb: Callable[[str, str, Dict[str, Any]], None]) -> None:
    """Set callback fired on login_success / login_failed / etc."""
    global _session_callback
    _session_callback = cb


def set_session_validator(fn: Callable[[str], bool]) -> None:
    """Inject the jti → bool checker used by require_jwt."""
    global _session_validator
    _session_validator = fn


def _emit_session_event(event: str, username: str, details: Optional[Dict[str, Any]] = None) -> None:
    if _session_callback:
        try:
            _session_callback(event, username, details or {})
        except Exception as exc:
            log.warning("session callback error: %s", exc)


# JWT helpers ────────────────────────────────────────────────────────────
def _secret() -> str:
    """The HS256 signing secret. Raises when unset — never signs with a default.

    Until #942 this fell back to a hard-coded placeholder, so a node whose
    config had not been provisioned would boot happily and sign every token
    in the fleet with a string published in the source tree. A missing secret
    is a provisioning failure and must stop the service, not degrade it.
    """
    try:
        cfg = get_config("api")
    except OSError as exc:
        # Unreadable config is not a reason to fall back to a weaker secret;
        # try the environment, then fail.
        log.warning("config unreadable while reading jwt_secret: %s", exc)
        cfg = {}
    s = cfg.get("jwt_secret", "") or os.environ.get("SECUBOX_JWT_SECRET", "")
    if not s:
        raise RuntimeError(
            "jwt_secret is not configured: set api.jwt_secret in "
            "/etc/secubox/secubox.conf or SECUBOX_JWT_SECRET in the unit. "
            "Refusing to sign tokens with a default."
        )
    return s


# SSO-lite (#400) ────────────────────────────────────────────────────────
# A session cookie + /verify endpoint let nginx `auth_request` gate vhosts
# against SecuBox users directly — replacing the ex-SSO IdP (retired) while reusing the same
# argon2 user_store. The cookie is set parent-domain-scoped so one login
# covers every *.<domain> vhost (SSO-lite). Configure the parent domain via
# api.sso_cookie_domain in secubox.conf (e.g. ".gk2.secubox.in"); empty =
# host-only cookie (still works, but not shared across subdomains).
SESSION_COOKIE = "secubox_session"


def _cookie_domain(request: Optional[Request] = None) -> Optional[str]:
    cfg = get_config("api")
    dom = cfg.get("sso_cookie_domain", "") or os.environ.get("SECUBOX_SSO_COOKIE_DOMAIN", "")
    if request is None:
        return dom or None
    # SANS RÉGLAGE, LE DOMAINE DE LA BOX (#1723). gk2 tient `.gk2.secubox.in`
    # d'une ligne posée à la main ; gk3 ne l'avait pas : la session ouverte sur
    # admin.gk3 restait à admin.gk3, et le Hall ne voyait personne.
    if not dom:
        try:
            g = str(get_config("global").get("domain", "") or "").strip().lstrip(".").lower()
        except (OSError, ValueError, AttributeError):
            g = ""
        dom = "." + g if g and re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", g) else ""
    if not dom:
        return None
    # Un Domain que l'hôte du navigateur ne couvre pas est REJETÉ par celui-ci :
    # plus de cookie du tout (kiosque sur hall.localhost, accès par IP). L'hôte
    # vient de l'Origin — Host est réécrit en « localhost » par l'agrégateur.
    from . import origine as _o
    hote = _o.hote_origine(request.headers.get("origin") or "") or \
        _o.hote_de(request.headers.get("host"))
    racine = dom.lstrip(".").lower()
    if hote and hote != "localhost" and not (hote == racine or hote.endswith("." + racine)):
        return None
    return dom


def set_session_cookie(response: Response, token: str, expires_in: int = 86400,
                       request: Optional[Request] = None) -> None:
    """Public helper so override modules (secubox-auth) emit the same SSO-lite
    session cookie on their own login-success paths. `request` lets the cookie
    take the box's domain when none is configured (#1723)."""
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=expires_in,
        httponly=True,
        secure=True,
        # Encadre par le Hall, un service est un contexte TIERS : le
        # navigateur rejette un cookie Lax ou Strict pose la, et le service
        # ne reconnait plus le visiteur (dfc315826). None exige Secure ; en clair
        # on retombe sur Lax plutot que de poser un cookie que le navigateur
        # jettera. SECUBOX_COOKIE_SAMESITE ferme la porte si l'operateur le
        # veut, au prix de l'affichage encadre.
        samesite=_samesite(True),   # secure=True juste au-dessus
        domain=_cookie_domain(request),
        path="/",
    )


#: Revendication qui BORNE le profil d'une session, quelle que soit l'identité
#: qu'elle porte (#1607). Posée à l'émission par une voie d'entrée moins forte
#: que la signature : le lien d'entrée à usage unique plafonne à `guest`.
#: Signée avec le reste du jeton ; qui refrappe un jeton pour la même session
#: la recopie.
PLAFOND = "plafond"

#: Revendication d'une session DÉLÉGUÉE par un autre nœud (#1720).
DELEGATION = "delegation"
TRACE_DELEGATION_DEFAUT = "/var/log/secubox/delegation.log"


def _trace_delegation(request: Request, payload: Dict[str, Any]) -> None:
    """Une ligne par appel fait sous délégation (#1720) — jamais bloquant (une
    trace impossible ne doit pas couper l'assistance), JAMAIS SILENCIEUX : si
    le fichier est inaccessible — unité durcie (ProtectSystem=strict), compte
    hors du groupe secubox —, la ligne part au journal système (LOG_AUTH).
    Vécu : en fichier seul, les appels servis par un module durci se perdaient."""
    d = (payload or {}).get(DELEGATION)
    if not isinstance(d, dict):
        return
    ligne = ""
    try:
        ligne = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "compte": payload.get("sub"), "centre": d.get("centre"),
            "noeud": d.get("noeud"), "aidant": d.get("compte"),
            "session": d.get("session"),
            "methode": request.method, "chemin": request.url.path,
        }, ensure_ascii=False)
        chemin = Path(os.environ.get("SECUBOX_TRACE_DELEGATION", TRACE_DELEGATION_DEFAUT))
        with open(chemin, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        import syslog  # noqa: PLC0415
        syslog.openlog("secubox-delegation", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, ligne or "trace de délégation illisible")
    except Exception:  # noqa: BLE001 — même le journal système refuse : rien de plus à faire
        pass


#: Profils d'une PERSONNE : ce que `require_personne` admet.
PROFILS_PERSONNE = ("user", "admin")


def create_token(
    username: str,
    expires_in: int = 86400,
    scope: Optional[str] = None,
    jti: Optional[str] = None,
    plafond: Optional[str] = None,
    delegation: Optional[Dict[str, Any]] = None,
) -> str:
    """Mint a JWT. `scope` carries a short-lived intent ("set-password", "mfa-challenge", …).

    `plafond` ("guest", "user", "admin") borne le profil de la session : une
    session plafonnée à `guest` n'est jamais une personne, ni un administrateur,
    quel que soit le profil inscrit du porteur."""
    payload: Dict[str, Any] = {
        "sub": username,
        "iat": int(time.time()),
        "exp": int(time.time()) + expires_in,
        "jti": jti or secrets.token_hex(8),
    }
    if scope:
        payload["scope"] = scope
    if plafond:
        payload[PLAFOND] = plafond
    if delegation:
        # Session ouverte par délégation d'un autre nœud (#1720) : qui, d'où,
        # au titre de quelle assistance. Chaque appel l'emporte dans la trace.
        payload[DELEGATION] = {k: str(v) for k, v in delegation.items()}
    return jwt.encode(payload, _secret(), algorithm="HS256")


def _decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
        if not payload.get("sub"):
            raise ValueError("missing sub")
        return payload
    except (JWTError, ValueError) as exc:
        log.warning("JWT invalide: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _is_scope_token(payload: Dict[str, Any]) -> bool:
    """A `scope` claim marks an INTENT token, never an access token (#942).

    `create_token(scope=...)` mints three of them: `mfa-challenge` (issued
    after the password check but BEFORE the TOTP check), `set-password`
    (issued against an EMPTY password when must_change_password is set) and
    `totp-enroll`. `_validate_token` never looked at the claim, so any of
    them opened a full session on every module keeping the permissive
    validator — a 2FA bypass with the password alone, and a passwordless
    entry for a freshly provisioned account.

    They are redeemed by `secubox-auth`'s own `_check_scope()`, which
    verifies the exact expected scope. They must never reach `require_jwt`.
    """
    return bool(payload.get("scope"))


def porteur_reconnu(sub: str) -> bool:
    """Ce porteur existe-t-il, et est-il encore admis ?

    UN SEUL PRÉDICAT, PARCE QUE DEUX ONT DÉJÀ DIVERGÉ. `_validate_token` et
    `verify` portaient chacun leur copie du contrôle ; en ajoutant le registre
    des appareils (#1351) je n'ai corrigé que la première. Résultat : un
    appareil passait `require_jwt` et se faisait refuser par `/auth/verify` —
    donc entrait dans SecuBox et restait à la porte des services protégés par
    `auth_request`. Le genre d'incohérence qu'on ne trouve qu'en la subissant.

    DEUX REGISTRES, ESPACES DE NOMS DISJOINTS : `appareils` ne répond que pour
    le préfixe `sbx-`, les utilisateurs pour le reste.
    """
    return bool(user_store.is_enabled(sub) or appareils.est_admis(sub))


def _validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode + scope/session/enabled checks. Returns the payload if the token
    is fully valid, else None — never raises. Used to try multiple credential
    sources (Bearer, cookie) without the first failure aborting the request."""
    try:
        payload = jwt.decode(token, _secret(), algorithms=["HS256"])
    except JWTError:
        return None
    if not payload.get("sub"):
        return None
    if _is_scope_token(payload):
        log.warning(
            "rejected scope token (scope=%s, sub=%s) presented as an access token",
            payload.get("scope"), payload.get("sub"),
        )
        return None
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        return None
    # DEUX SORTES DE PORTEURS, DEUX REGISTRES (#1351).
    #
    # Un UTILISATEUR a un nom choisi, un mot de passe, des droits attribués.
    # Un APPAREIL est une CLÉ : son nom en dérive, il n'a pas de mot de passe —
    # il entre en signant — et il vit dans son propre registre.
    #
    # Les loger ensemble faisait apparaître des entrées `sbx-…` dans le panneau
    # « Users », où aucun geste de gestion d'utilisateurs n'a de sens pour elles.
    # Le registre des appareils ne répond QU'À la question posée ici : ce
    # porteur existe-t-il, et est-il encore admis ?
    #
    # L'ordre compte peu — les espaces de noms sont disjoints, `appareils` ne
    # répond que pour le préfixe `sbx-` — mais on interroge les utilisateurs
    # d'abord : c'est le cas courant, et le registre des appareils reste vide
    # sur une box qui n'a admis personne.
    if not porteur_reconnu(payload["sub"]):
        return None
    return payload


def est_admin_reel(payload: Dict[str, Any]) -> bool:
    """Ce porteur est-il un ADMINISTRATEUR RÉEL (#1581) ?

    Un compte UTILISATEUR de rôle « admin », actif. Jamais une session
    d'appareil (sbx-…), quel que soit le profil qu'on lui a donné à
    l'admission : un appareil entre en signant, sans mot de passe ni second
    facteur — ce n'est pas une preuve suffisante pour administrer la box."""
    sub = str((payload or {}).get("sub") or "")
    if not sub or sub.startswith(appareils.PREFIXE):
        return False
    # Un plafond borne tout : sous `admin`, pas d'administration (#1607).
    if PLAFOND in (payload or {}) and (payload or {}).get(PLAFOND) != "admin":
        return False
    try:
        u = user_store.get_user(sub) or {}
        return u.get("role") == "admin" and bool(user_store.is_enabled(sub))
    except Exception:  # noqa: BLE001 — dans le doute, pas d'administration
        return False


def est_personne(payload: Dict[str, Any]) -> bool:
    """Ce porteur est-il une PERSONNE admise, de profil `user` ou plus (#1607) ?

    OUI pour :
      - un compte utilisateur (users.json) actif, de rôle autre que `guest` —
        y compris un appareil rattaché, qui entre au nom de son compte ;
      - un appareil admis (sbx-…) dont le profil est `user` ou `admin`.
    NON pour :
      - un appareil au profil `guest`, révoqué ou inconnu ;
      - une session plafonnée sous `user` (claim `plafond`, lien d'entrée) ;
      - un jeton à portée restreinte (`scope`, #942) ;
      - toute erreur de lecture des registres — dans le doute, non."""
    p = payload or {}
    sub = str(p.get("sub") or "")
    if not sub or _is_scope_token(p):
        return False
    if PLAFOND in p and p.get(PLAFOND) not in PROFILS_PERSONNE:
        return False
    try:
        if sub.startswith(appareils.PREFIXE):
            return appareils.est_admis(sub) and appareils.profil_de(sub) in PROFILS_PERSONNE
        u = user_store.get_user(sub) or {}
        return bool(u) and u.get("role") != "guest" and bool(user_store.is_enabled(sub))
    except Exception:  # noqa: BLE001 — dans le doute, pas une personne
        return False


# Garde d'origine ─────────────────────────────────────────────────────────
def domaine_box() -> str:
    """Le domaine de la box, sans point initial, en minuscules ; "" si aucun.

    `[global] domain`, sinon le domaine du cookie de session
    (`[api] sso_cookie_domain`, « .gk2.secubox.in » sur gk2)."""
    try:
        dom = get_config("global").get("domain", "")
    except (OSError, ValueError, AttributeError):
        dom = ""
    if not dom:
        try:
            dom = _cookie_domain() or ""
        except (OSError, ValueError, AttributeError):
            dom = ""
    return dom.strip().lstrip(".").lower() if isinstance(dom, str) else ""


def hote_box(prefixe: str) -> str:
    """`<prefixe>.<domaine de la box>` ; "" si le domaine est inconnu (#1723).

    Un nom de service se DÉRIVE du domaine de la box, il ne s'écrit pas :
    `peertube.gk2.secubox.in` codé en dur envoyait gk3 chez gk2."""
    dom = domaine_box()
    return f"{prefixe}.{dom}" if dom and prefixe else dom


# Le nœud de référence du maillage : celui qui sert un service qu'une box n'a
# pas elle-même (même valeur que REFERENCE dans webos/www/hall/domaine.js).
REFERENCE = "gk2.secubox.in"
_DPKG_INFO = Path("/var/lib/dpkg/info")


def hote_parc(prefixe: str, paquet: str) -> str:
    """Le service `prefixe` qu'on CONSOMME : celui de cette box si `paquet` y
    est installé, sinon celui du nœud de référence (#1723).

    C'est la règle du Hall — le local s'il existe, le maillage en repli —
    appliquée côté serveur (zia → peertube, billets → peertube…)."""
    if (_DPKG_INFO / f"{paquet}.list").exists():
        local = hote_box(prefixe)
        if local and local != prefixe:
            return local
    return f"{prefixe}.{REFERENCE}"


def garde_origine(request: Request, payload: Optional[Dict[str, Any]] = None) -> None:
    """La garde d'origine pour une session lue dans le COOKIE (#1607).

    `require_session` (donc `require_jwt`, `require_personne`,
    `require_capability`) l'applique d'elle-même. Un module qui lit le cookie
    lui-même avant d'ÉCRIRE l'appelle avec la requête et le payload retenu.
    Règle et modes : secubox_core.origine."""
    _origine.garde(request, (payload or {}).get("sub"), domaine_box())


async def require_session(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    """N'IMPORTE QUELLE session reconnue — utilisateur OU appareil admis.

    C'était `require_jwt` jusqu'à #1581 : une session d'invité (l'appareil de
    gek) ouvrait ainsi toute la webui d'administration et ses API. À poser
    EXPLICITEMENT, et seulement sur une route d'usager (le Hall, ses accès,
    réveiller un module) ; tout le reste passe par `require_jwt`, réservé aux
    administrateurs réels.

    GARDE D'ORIGINE (#1607) : quand la session retenue vient du COOKIE et que
    la méthode écrit (ni GET, ni HEAD, ni OPTIONS), la requête doit venir
    d'une page de la box — voir secubox_core.origine. Un jeton porteur n'y
    est pas soumis : le navigateur ne le joint jamais de lui-même."""
    # SSO-lite (#400): accept the Bearer token OR the parent-domain session
    # cookie. The cookie lets one SecuBox login cover every module without
    # re-auth. It is SameSite=None under TLS (see _samesite): a write
    # authenticated by it goes through the origin guard below.
    #
    # Shadowing fix: try BOTH sources, Bearer first then cookie, and accept the
    # first that fully validates. Previously a present-but-STALE Bearer (an old
    # localStorage sbx_token the webui still sent) was used exclusively and its
    # failure 401'd the request even when the session cookie was perfectly
    # valid — which hard-redirected the panel to /login.html in a loop. A stale
    # token must never shadow a live session.
    candidates = []
    if creds is not None and creds.credentials:
        candidates.append(("porteur", creds.credentials))
    cookie_tok = request.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidates.append(("cookie", cookie_tok))
    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token Bearer ou session manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for source, token in candidates:
        payload = _validate_token(token)
        if payload is not None:
            if source == "cookie":
                garde_origine(request, payload)
            _trace_delegation(request, payload)
            return payload
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalide ou expiré",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_jwt(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    """ADMINISTRATION : une session valide ET un administrateur réel (#1581).

    SÛR PAR DÉFAUT. 124 modules gardent leurs routes par `require_jwt` ; elles
    deviennent toutes réservées aux administrateurs d'un seul geste. Une route
    qu'un usager doit pouvoir appeler le dit en passant à `require_session`."""
    payload = await require_session(request, creds)
    if not est_admin_reel(payload):
        log.warning("administration refusée à %s (ni compte, ni rôle admin)", payload.get("sub"))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Réservé aux administrateurs de la box")
    return payload


async def require_personne(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    """PLANCHER DES USAGERS : la session d'une PERSONNE, profil `user` ou plus
    (#1607).

    Entre `require_session` (n'importe quelle session, invités compris) et
    `require_jwt` (administrateurs réels). À poser sur une écriture d'usager
    visible par d'autres ou coûteuse : diffuser, parler, piloter un appareil.
    Admet un compte actif (appareil rattaché compris) ou un appareil admis au
    profil `user`/`admin` ; refuse (403) un appareil `guest`, une session
    plafonnée sous `user` (lien d'entrée) et tout jeton à portée restreinte.
    Passe par `require_session`, donc par la garde d'origine."""
    payload = await require_session(request, creds)
    if not est_personne(payload):
        log.warning("plancher personne : refusé à %s", payload.get("sub"))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Réservé aux personnes admises (profil user ou plus)")
    return payload


# Lecture gardée + mode tableau de bord ─────────────────────────────────
#
# LE MOTIF « THREE-FOLD » ETAIT UNE LECTURE PUBLIQUE (#1256). Environ 140
# routes du parc — `status`, `components`, `access`, `stats` — etaient
# documentees « public » pour que les tableaux de bord s'affichent sans
# session. Ce n'etait pas une negligence, c'etait un choix. Mais une lecture
# publique reste de la reconnaissance offerte : inventaire de paquets, pairs
# WireGuard, topologie du frontal, journaux.
#
# LE PARC PASSE DONC EN LECTURE GARDEE. `require_lecture` remplace l'absence
# de garde sur ces routes :
#
#   1. porteur ou cookie de session valide  -> autorise, identite connue ;
#   2. sinon, SI le mode tableau de bord est actif ET que nginx a marque la
#      requete comme LAN  -> autorise en lecteur anonyme ;
#   3. sinon  -> 401.
#
# LE DEFAUT EST FERME. Le mode est opt-in, declaratif, auditable et versionne
# — la meme doctrine que `waf_bypass` dans haproxy.toml, et pour la meme
# raison : un defaut silencieux ne protege plus personne.
#
# POURQUOI NGINX DECIDE DU « LAN », ET PAS NOUS. Juger l'origine depuis
# Python est un piege : derriere HAProxy -> sbxwaf -> nginx, `$remote_addr`
# vaut 127.0.0.1 pour TOUT LE MONDE, et un test naif verrait le WAN entier
# comme local. Le depot resout deja ce probleme dans
# conf.d/secubox-lan-geo.conf (`set_real_ip_from` + `real_ip_header
# X-Forwarded-For` + `real_ip_recursive on`, puis un bloc `geo $lan_client`).
# On consomme ce verdict, on ne le refait pas.
#
# L'EN-TETE N'EST PAS FORGEABLE PAR LE CLIENT : le snippet
# secubox-proxy.conf le pose avec `proxy_set_header`, qui REMPLACE toute
# valeur presentee par l'appelant. Et si la requete n'est pas passee par
# nginx, l'en-tete est absent : on retombe sur l'exigence du jeton. Les deux
# chemins d'echec ferment.
ENTETE_LAN = "X-SecuBox-LAN"


def mode_tableau_de_bord_actif() -> bool:
    """Le mode est-il arme sur cette board ?

    `[tableau_de_bord] actif = true` dans /etc/secubox/secubox.conf. Absent ou
    invalide vaut FALSE : on ne s'ouvre jamais par defaut d'ecriture.
    `SECUBOX_TABLEAU_DE_BORD` (1/0) surcharge, pour les tests et la mise au
    point — jamais pour la production.
    """
    forcage = os.environ.get("SECUBOX_TABLEAU_DE_BORD", "").strip()
    if forcage in ("1", "0"):
        return forcage == "1"
    try:
        valeur = get_config("tableau_de_bord").get("actif", False)
    except Exception:  # config illisible -> ferme
        return False
    # STRICTEMENT LE BOOLEEN TOML, et rien d'autre. `bool("false")` vaut True
    # en Python : accepter la chaine ouvrirait la lecture du parc sur un
    # `actif = "true"` mal type — ou pire, sur un `actif = "false"`.
    return valeur is True


def _requete_lan(request: Request) -> bool:
    """Verdict LAN de nginx, tel quel. Absent = non-LAN."""
    return request.headers.get(ENTETE_LAN, "").strip() == "1"


async def require_lecture(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Dict[str, Any]:
    """Garde de LECTURE : jeton, ou mode tableau de bord depuis le LAN.

    Rend le payload du jeton quand il y en a un, sinon un pseudo-payload
    `{"sub": None, "tableau_de_bord": True}` — pour qu'une route puisse savoir
    qu'elle sert un lecteur anonyme et taire ce qui ne le regarde pas.
    """
    candidats = []
    if creds is not None and creds.credentials:
        candidats.append(creds.credentials)
    cookie_tok = request.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidats.append(cookie_tok)
    for token in candidats:
        payload = _validate_token(token)
        if payload is not None:
            return payload

    if mode_tableau_de_bord_actif() and _requete_lan(request):
        return {"sub": None, "tableau_de_bord": True}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Lecture gardee : jeton requis. Le mode tableau de bord "
            "(/etc/secubox/secubox.conf, [tableau_de_bord] actif) autorise le "
            "LAN sans jeton ; il est inactif ou la requete n'est pas LAN."
        ),
        headers={"WWW-Authenticate": "Bearer"},
    )


# Password verification ─────────────────────────────────────────────────
def _check_password(username: str, password: str) -> bool:
    """Delegate to user_store. Replaces the old plaintext auth.toml lookup."""
    return user_store.verify_password(username, password)


def _second_facteur_requis(username: str) -> str:
    """Motif pour lequel ce compte ne peut PAS ouvrir de session sur mot de
    passe seul, ou "" s'il le peut (#1406)."""
    u = user_store.get_user(username) or {}
    if (u.get("totp") or {}).get("enabled"):
        return "totp"
    if u.get("must_change_password"):
        return "mot de passe a changer"
    if u.get("role") == "admin":
        return "admin (TOTP obligatoire)"
    return ""


# Legacy /auth/login endpoint kept for backwards compat ────────────────
router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, request: Request, response: Response):
    """Plain login endpoint — secubox-auth overrides this with the full branching flow."""
    client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() \
        or request.headers.get("X-Real-IP", "") \
        or (request.client.host if request.client else "")
    user_agent = request.headers.get("User-Agent", "")
    if not _check_password(req.username, req.password):
        _emit_session_event("login_failed", req.username, {
            "reason": "invalid_credentials",
            "ip": client_ip,
            "user_agent": user_agent[:300] if user_agent else "",
        })
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects",
        )
    # UN SEUL FACTEUR NE SUFFIT PAS PARTOUT (#1406). Cette route est montee
    # par 47 modules (/api/v1/<module>/auth/login) et, dans l'agregateur qui
    # monte aussi secubox-auth, sa session est ENREGISTREE : elle ouvrait une
    # session complete sur mot de passe seul, TOTP des admins contourne.
    # Elle applique desormais la politique du vrai login : un compte a
    # second facteur, a mot de passe a changer, ou admin (TOTP obligatoire)
    # passe par /api/v1/auth/login. Verifie APRES le mot de passe : qui ne
    # l'a pas n'apprend rien de l'etat du compte.
    motif = _second_facteur_requis(req.username)
    if motif:
        _emit_session_event("login_failed", req.username, {
            "reason": "second_factor_required", "detail": motif,
            "ip": client_ip,
            "user_agent": user_agent[:300] if user_agent else "",
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ce compte exige la connexion complete (second facteur) — "
                   "se connecter par /api/v1/auth/login",
        )
    jti = secrets.token_hex(8)
    tok = create_token(req.username, jti=jti)
    # SSO-lite: also drop a parent-domain session cookie so nginx auth_request
    # (GET /auth/verify) gates sibling vhosts with this one login.
    set_session_cookie(response, tok, request=request)
    _emit_session_event("login_success", req.username, {
        "jti": jti,
        "expires_in": 86400,
        "ip": client_ip,
        "user_agent": user_agent[:300] if user_agent else "",
    })
    return TokenResponse(access_token=tok)


@router.get("/verify")
async def verify(request: Request):
    """nginx `auth_request` target (SSO-lite, #400).

    Validates the SecuBox session cookie (or a Bearer token for API clients)
    against the same checks as require_jwt, and echoes the identity back as
    `Remote-User` / `Remote-Groups` headers for the proxied app. 200 = allow,
    401 = deny (nginx then 302s to the SecuBox login page)."""
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            tok = auth[7:]
    if not tok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="no session")
    # _decode_token raises 401 on invalid/expired.
    payload = _decode_token(tok)
    # Same rule as require_jwt (#942): an intent token is not a session.
    if _is_scope_token(payload):
        log.warning(
            "rejected scope token (scope=%s) at the nginx auth_request target",
            payload.get("scope"),
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="jeton hors scope")
    jti = payload.get("jti")
    if not jti or not _session_validator(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session révoquée")
    sub = payload["sub"]
    # LE MÊME PRÉDICAT QUE `_validate_token`, et c'est le point : en avoir deux
    # les a fait diverger dès le premier ajout (#1351).
    if not porteur_reconnu(sub):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="compte désactivé")
    # LE RÔLE SUIT LE MÊME REGLE QUE LE PORTEUR : deux registres, et celui qui
    # connaît ce nom répond. Sans cela un appareil recevait un `Remote-Groups`
    # VIDE, et tout service qui décide d'après ce champ le traitait comme
    # n'ayant aucun droit — après l'avoir laissé entrer. Pire qu'un refus : une
    # entrée qui ne mène à rien.
    role = ""
    try:
        getter = getattr(user_store, "get_user", None)
        if callable(getter):
            u = getter(sub) or {}
            role = u.get("role", "") if isinstance(u, dict) else ""
        if not role:
            role = appareils.profil_de(sub) if appareils.get(sub) else ""
    except Exception:
        role = ""
    # COMPTE BBS LIÉ (#1456) : la personne SBX OS derrière la session peut
    # avoir un compte BBS à elle (« cedre83 ») ; le BBS l'ouvre alors au lieu
    # du compte d'appareil. Import tardif : capacites importe ce module.
    headers = {"Remote-User": sub, "Remote-Groups": role}
    try:
        from secubox_core import capacites as _cap
        lie = _cap.compte_lie(payload, "bbs")
        if lie:
            headers["Remote-Sbx-Bbs"] = lie
        # BOÎTE LIÉE (#1562) : le webmail (greffon secubox_sso) ouvre CETTE boîte
        # sans mot de passe — seulement si la personne en a une, et une adresse.
        boite = _cap.compte_lie(payload, "email")
        if boite and "@" in boite:
            headers["Remote-Sbx-Mail"] = boite
        # COMPTE NEXTCLOUD LIÉ (#1562) : le Cloud l'ouvre sans mot de passe
        # (nginx /sbx/entrer → user_saml en mode variable d'environnement).
        # Seuls les caractères d'un uid Nextcloud : l'en-tête devient $_SERVER.
        nc = _cap.compte_lie(payload, "nextcloud")
        if nc and re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", nc):
            headers["Remote-Sbx-Nextcloud"] = nc
        # COMPTE PEERTUBE LIÉ (#1562) : le greffon secubox-sso l'ouvre.
        pt = _cap.compte_lie(payload, "peertube")
        if pt and re.fullmatch(r"[a-z0-9._]{1,50}", pt):
            headers["Remote-Sbx-Peertube"] = pt
    except Exception:
        pass
    return JSONResponse({"ok": True, "user": sub}, headers=headers)


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Clear the SSO-lite session cookie."""
    response.delete_cookie(SESSION_COOKIE, domain=_cookie_domain(request), path="/")
    return {"ok": True}
