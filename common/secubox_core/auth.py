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
import inspect
import re
import secrets
import socket
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional
from urllib.parse import unquote

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
from .config import get_config, reload_config
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
        return
    # SANS secubox-auth DANS CE PROCESSUS (#1817) : l'agrégateur d'une box
    # installée par image ne le charge pas toujours. Une session ouverte ici
    # (signature d'appareil, lien d'entrée) n'était alors JAMAIS enregistrée —
    # cookie rendu, puis refusé partout. Le cœur tient lui-même le registre,
    # par l'écrivain verrouillé et atomique (#1803).
    d = details or {}
    try:
        if event == "login_success" and d.get("jti"):
            from datetime import datetime as _dt
            ligne = {"id": d["jti"], "username": username, "ip": d.get("ip", ""),
                     "user_agent": d.get("user_agent", ""), "created": _dt.utcnow().isoformat(),
                     "expires": int(time.time()) + int(d.get("expires_in", 86400)), "type": "jwt"}
            _sessions.muter(lambda rows: rows + [ligne])
        elif event == "sessions_coupees" and d.get("jtis"):
            cibles = set(d["jtis"])
            _sessions.muter(lambda rows: [r for r in rows if r.get("id") not in cibles])
    except OSError as exc:
        log.warning("registre des sessions : %s", exc)


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
        # La config est en cache par processus : un service lance avant que le
        # secret n'entre dans secubox.conf le croirait absent jusqu'au
        # redemarrage (#2554). On relit le fichier une fois avant de refuser.
        try:
            reload_config()
            s = get_config("api").get("jwt_secret", "")
        except OSError as exc:
            log.warning("config unreadable while re-reading jwt_secret: %s", exc)
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


def _ecrire_trace(ligne: str, ident: str = "secubox-delegation") -> None:
    """Une ligne en ajout dans le fichier de trace des délégations ; à défaut (ou ligne vide : trace illisible),
    au journal système (LOG_AUTH)."""
    try:
        if not ligne:
            raise ValueError("trace illisible")
        chemin = Path(os.environ.get("SECUBOX_TRACE_DELEGATION", TRACE_DELEGATION_DEFAUT))
        with open(chemin, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
        return
    except Exception:  # noqa: BLE001
        pass
    try:
        import syslog  # noqa: PLC0415
        syslog.openlog(ident, 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, ligne or "trace de délégation illisible")
    except Exception:  # noqa: BLE001 — même le journal système refuse : rien de plus à faire
        pass


def _trace_delegation(request: Request, payload: Dict[str, Any], verdict: str = "accepte", motif: str = "") -> None:
    """Une ligne par appel fait sous délégation (#1720) — jamais bloquant (une
    trace impossible ne doit pas couper l'assistance), JAMAIS SILENCIEUX : si
    le fichier est inaccessible — unité durcie (ProtectSystem=strict), compte
    hors du groupe secubox —, la ligne part au journal système (LOG_AUTH).
    Vécu : en fichier seul, les appels servis par un module durci se perdaient.

    Deux délégations : la session d'assistance d'un autre nœud (#1720, réclamation `delegation`) et le porteur
    délégué du pilotage (#3126 L5, réclamation `pilotage`, voir `_trace_pilotage`). JAMAIS le jeton. Lignes en ASCII
    (`ensure_ascii`) : le chemin vient du client."""
    p = payload or {}
    d = p.get(DELEGATION)
    if not isinstance(d, dict):
        if _est_porteur_pilotage(p) and isinstance(p.get(PILOTAGE), dict):
            _trace_pilotage(request, verdict, motif, p)
        return
    ligne = ""
    try:
        ligne = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "compte": p.get("sub"), "centre": d.get("centre"),
            "noeud": d.get("noeud"), "aidant": d.get("compte"),
            "session": d.get("session"),
            "methode": request.method, "chemin": request.url.path,
        }, ensure_ascii=True)
    except Exception:  # noqa: BLE001
        pass
    _ecrire_trace(ligne)


# Porteur délégué du pilotage (#3126, L5 « Box légère ») ─────────────────
#
# Les pages d'administration d'une box légère sont servies par le MAÎTRE. Leurs
# appels `/api/v1/…` arrivent par le canal agent ↔ contrôleur, puis le relais
# local `sbx-pilotage-relais` frappe un jeton DÉLÉGUÉ et appelle la socket du
# module en posant `X-SecuBox-Pilotage-Relais`. Ce jeton :
#   - EdDSA (Ed25519), signé par la clé PRIVÉE du seul relais, durée ≤ 60 s.
#     R-L5-9 DÉROGE aux Global Constraints du plan (« HS256 + jwt_secret ») : les
#     sockets de modules sont souvent en 0666 et `jwt_secret` est lu par tous les
#     modules ; un module compromis frapperait un jeton administrateur. Les
#     modules ne lisent que la clé PUBLIQUE, `DOSSIER_CLE_RELAIS/NOM_CLE_RELAIS` ;
#   - `aud` = nom de la box (nom court de l'hôte), `sub` = `pilotage:<acteur>@<maître>` ;
#   - `cible` = le module visé, comparé à l'identité du module qui sert la route ;
#   - réclamation `pilotage = {acteur, maitre, portee}`, portée `lecture` ou `admin`.
#
# CONTRAT DES CLÉS (créées par la tâche 2, à l'installation du relais ; R-L5-13) :
#   /etc/secubox-pilotage/            dossier root:root 0755, HORS de /etc/secubox
#                                     (qui appartient au compte secubox, ~110 unités) ;
#   /etc/secubox-pilotage/relais.pub  PEM SubjectPublicKeyInfo Ed25519, root:root
#                                     0644, lisible par les modules ;
#   clé privée                        PEM PKCS#8 Ed25519, 0600, au compte du relais
#                                     (secubox-pilotage), hors de ce dossier public —
#                                     jamais lue ici.
# Le dossier est ouvert O_DIRECTORY|O_NOFOLLOW, le fichier par dir_fd O_NOFOLLOW ;
# l'un et l'autre doivent appartenir à root, sans écriture pour le groupe ni les
# autres. Sinon, comme si la clé était absente : AUCUN jeton délégué n'est
# reconnu. Le chemin est fixe : jamais lu d'un en-tête ni d'une réclamation
# (`kid`, `jku`, `jwk` ignorés).
#
# ACTEUR : le relais (tâche 2) le NORMALISE en minuscules avant de frapper le
# jeton ; ici, un acteur hors `[a-z0-9._-]{1,64}` est refusé, jamais converti.
#
# ÉCRITURE FERMÉE PAR DÉFAUT (R-L5-12, #3279 en version minimale) : en portée
# `admin`, une méthode d'écriture n'est permise que sur une route que le PAQUET
# du module déclare ouverte, dans
# `/usr/share/secubox/pilotage/routes-ouvertes.d/<module>.toml` (même règle de
# propriété que la clé ; fichier invalide = rien d'ouvert). La lecture reste
# soumise à la seule liste de refus (secrets).
#
# CE N'EST PAS UNE SESSION : aucun `jti` du registre, jamais dans la liste des
# sessions. Il n'est lu qu'en Bearer, jamais dans le cookie, et seulement avec
# l'en-tête du relais — que nginx (secubox-proxy.conf), HAProxy (verdicts
# effacés à l'entrée) et l'agrégateur (intermédiaire ASGI) effacent. Il n'ouvre
# JAMAIS une route qui crée ou modifie des comptes, des secrets ou des sessions
# (listes ci-dessous ; une liste d'ouverture déclarée par module la remplacera, #3279).
ENTETE_PILOTAGE_RELAIS = "X-SecuBox-Pilotage-Relais"
PILOTAGE = "pilotage"
PREFIXE_PILOTAGE = "pilotage:"
DUREE_MAX_PILOTAGE_S = 60
#: Avance d'horloge tolérée sur `iat` : le relais frappe sur la même machine.
DERIVE_PILOTAGE_S = 5
PORTEES_PILOTAGE = ("lecture", "admin")
METHODES_LECTURE = ("GET", "HEAD")
ALGORITHME_PILOTAGE = "EdDSA"
DOSSIER_CLE_RELAIS = "/etc/secubox-pilotage"
NOM_CLE_RELAIS = "relais.pub"
_TAILLE_MAX_CLE = 4096
#: Déclarations d'écriture ouverte livrées par les paquets des modules.
DOSSIER_ROUTES_OUVERTES = "/usr/share/secubox/pilotage/routes-ouvertes.d"
_TAILLE_MAX_DECLARATION = 64 * 1024
METHODES_ECRITURE = ("POST", "PUT", "PATCH", "DELETE")
#: Propriétaire exigé des fichiers de confiance (clé, déclarations).
UID_ROOT = 0
DOSSIER_SOCKETS = "/run/secubox"
#: Racine d'installation des modules : une route servie depuis
#: `/usr/lib/secubox/<module>/…` appartient au module `<module>`.
RACINE_MODULES = "/usr/lib/secubox"
#: Journal d'audit central (ajout seul) : chaque REFUS d'un porteur délégué.
AUDIT_PILOTAGE = "/var/log/secubox/audit.log"
#: Modules qui ne reconnaissent JAMAIS le porteur délégué : comptes, sessions,
#: secrets, assistance (sessions déléguées), premier pas (création du premier
#: administrateur), le pilotage lui-même (consentement, mains liées, support :
#: une délégation ne s'élargit pas elle-même) et l'agrégateur (qui efface
#: l'en-tête). Tout module `pilotage*` l'est aussi, par préfixe.
MODULES_EXCLUS_PILOTAGE = frozenset({
    "auth", "vault", "portal", "assist", "premier-pas", "users", "aggregator",
    "pilotage", "pilotage-agent", "pilotage-canal", "pilotage-relais",
})
#: Mots qui désignent des comptes, des sessions, des secrets ou leur
#: restauration, dans N'IMPORTE QUEL module : le porteur délégué y est refusé
#: (403), quelle que soit la méthode. Comparés en minuscules, après décodage-%,
#: au segment entier ET à chacun de ses morceaux découpés sur `[-_.]` et tout
#: autre caractère hors `[a-z0-9]` (`reset-password` → `password`, `api_key` →
#: `key`, `users\nx` → `users`).
SEGMENTS_EXCLUS_PILOTAGE = frozenset({
    "auth", "login", "logout", "users", "user", "utilisateurs", "utilisateur",
    "comptes", "compte", "accounts", "account", "sessions", "session",
    "secrets", "secret", "password", "passwords", "passwd", "mot-de-passe",
    "mots-de-passe", "reset-password", "set-password", "totp", "mfa", "2fa",
    "otp", "second-facteur", "jeton", "jetons", "token", "tokens", "api-key",
    "api_key", "api-keys", "apikeys", "cle", "cles", "key", "keys", "passkey",
    "passkeys", "webauthn", "vault", "coffre", "delegation", "delegations",
    "sudoers", "credential", "credentials", "identifiants", "private",
    "privkey", "psk", "restore",
})
#: Routes de secrets nommées explicitement, par module (chemin sans le préfixe
#: `/api/v1/<module>`) : configuration et QR d'un pair WireGuard (clé privée du
#: pair), export des pairs.
ROUTES_EXCLUES_PILOTAGE = {
    "wireguard": (re.compile(r"/peer/[^/]+/(config|qr)/?"), re.compile(r"/export(/.*)?")),
}
_RE_DECOUPE = re.compile(r"[^a-z0-9]+")   # `[-_.]` et tout autre séparateur (espace, saut de ligne, `;`…)
_RE_NOM_BOX = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_RE_MODULE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_RE_ACTEUR = re.compile(r"[a-z0-9._-]{1,64}")
_RE_MAITRE = re.compile(r"[a-z0-9-]{1,63}")
_RE_SUB_PILOTAGE = re.compile(r"pilotage:[a-z0-9._-]{1,64}@[a-z0-9-]{1,63}")


class _PayloadPilotage(dict):
    """Payload d'un porteur délégué RENDU PAR LA GARDE (`_porteur_pilotage`).

    C'est la marque que `est_admin_reel` exige : un dict décodé ailleurs (un module qui lirait le jeton lui-même),
    ou une copie (`dict(p)`), ne l'a pas. Reste un dict : sérialisable par une route qui rend `user`. La même instance
    est posée sur `request.state.pilotage`."""


def nom_box_locale() -> str:
    """Le nom de cette box, tel que le maître le connaît : le nom COURT de
    l'hôte, en minuscules (même règle que `noms_du_maillage` du pilotage, et
    que `secubox-renommer`, qui change l'hôte). "" si illisible ou invalide :
    aucun jeton délégué n'est alors reconnu."""
    try:
        nom = (socket.gethostname() or "").split(".")[0].strip().lower()
    except OSError:
        return ""
    return nom if _RE_NOM_BOX.fullmatch(nom) else ""


def _methode(request) -> str:
    try:
        return str(request.scope.get("method") or request.method).upper()
    except Exception:  # noqa: BLE001 — requête incomplète : méthode inconnue
        return ""


def _chemin_requete(request) -> str:
    try:
        return str(request.scope.get("path") or "")
    except Exception:  # noqa: BLE001
        return ""


def module_courant(request) -> str:
    """L'IDENTITÉ du module qui sert cette requête : `<m>` quand la fonction de
    la route résolue (`scope["endpoint"]`) a son source sous
    `RACINE_MODULES/<m>/` ; "" sinon (aucune route, route de secubox_core,
    chemin relatif, nom invalide).

    POURQUOI LE SOURCE DE LA ROUTE. Il est fixé par l'installation du paquet
    (dpkg), jamais par la requête ; il vaut aussi dans un processus de groupe
    (`secubox-groupd`, plusieurs modules dans un interpréteur), où une variable
    d'environnement posée par l'unité serait commune à tous les modules ; et il
    ne dépend pas du nom de la socket. Une route de secubox_core (`/auth/…`)
    n'appartient à aucun module : le porteur délégué y est refusé."""
    try:
        fn = inspect.unwrap(request.scope.get("endpoint"))
        fichier = fn.__code__.co_filename
    except Exception:  # noqa: BLE001 — pas de route, ou pas une fonction
        return ""
    if not isinstance(fichier, str) or not os.path.isabs(fichier):
        return ""
    cle = (RACINE_MODULES, fichier)
    if cle in _cache_modules:   # M3 : deux realpath par requête, sinon
        return _cache_modules[cle]
    racine = os.path.realpath(RACINE_MODULES)
    relatif = os.path.relpath(os.path.realpath(fichier), racine)
    nom = "" if relatif.startswith("..") or os.path.isabs(relatif) else relatif.split(os.sep)[0]
    nom = nom if _RE_MODULE.fullmatch(nom) else ""
    if len(_cache_modules) > 4096:
        _cache_modules.clear()
    _cache_modules[cle] = nom
    return nom


_cache_modules: Dict[Any, str] = {}


def _preuve_socket(request, module: str) -> bool:
    """Contrôle SUPPLÉMENTAIRE par `scope["server"]` (le porteur tient d'abord par la signature et `cible`).

    - absent (`None`) : uvicorn 0.32 (Debian trixie) n'y met rien pour une socket Unix (`get_local_addr` ne rend
      qu'un couple hôte/port) — accepté ;
    - `(chemin, None)` (uvicorn ≥ 0.33 sur `--uds`) : doit être `DOSSIER_SOCKETS/<module>.sock` ;
    - `(hôte, port)` : TCP — refusé, quelle que soit la version.
    `server` vient de `getsockname()` : le client ne le choisit pas (à la différence de `client`)."""
    try:
        serveur = request.scope.get("server")
    except Exception:  # noqa: BLE001
        return False
    if serveur is None:
        return True
    if not isinstance(serveur, (tuple, list)) or len(serveur) != 2 or serveur[1] is not None:
        return False
    chemin = serveur[0]
    if isinstance(chemin, bytes):
        chemin = chemin.decode("utf-8", "replace")
    if not isinstance(chemin, str):
        return False
    return chemin == f"{DOSSIER_SOCKETS.rstrip('/')}/{module}.sock"


_avertis: set = set()


def _avertir_une_fois(cle: Any, message: str, *args: Any) -> None:
    """M2 : un `log.warning` motivé, une seule fois par `cle` (empreinte d'un fichier, motif) : un fichier refusé
    ne remplit pas le journal à chaque requête, et un changement de fichier est de nouveau signalé."""
    if cle in _avertis:
        return
    if len(_avertis) > 1024:
        _avertis.clear()
    _avertis.add(cle)
    log.warning(message, *args)


def _proprietaire_attendu(chemin: str) -> int:
    return UID_ROOT


def _lire_fichier_root(dossier: str, nom: str, taille_max: int):
    """(contenu, empreinte) d'un fichier de CONFIANCE : dossier ouvert `O_DIRECTORY|O_NOFOLLOW`, fichier par `dir_fd`
    `O_NOFOLLOW` ; l'un et l'autre à root, sans écriture pour le groupe ni les autres ; fichier ordinaire, taille
    bornée. Lève OSError ou ValueError (motif) sinon."""
    dfd = os.open(dossier, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        sd = os.fstat(dfd)
        if sd.st_uid != _proprietaire_attendu(dossier) or sd.st_mode & 0o022:
            raise ValueError(f"dossier {dossier!r} : pas à root, ou inscriptible par le groupe ou les autres")
        fd = os.open(nom, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        try:
            sf = os.fstat(fd)
            chemin = os.path.join(dossier, nom)
            if not stat.S_ISREG(sf.st_mode):
                raise ValueError(f"{chemin!r} : pas un fichier ordinaire")
            if sf.st_uid != _proprietaire_attendu(chemin) or sf.st_mode & 0o022:
                raise ValueError(f"{chemin!r} : pas à root, ou inscriptible par le groupe ou les autres")
            if not 0 < sf.st_size <= taille_max:
                raise ValueError(f"{chemin!r} : taille {sf.st_size} hors de ]0, {taille_max}]")
            donnees = os.read(fd, taille_max + 1)
            return donnees, (dossier, nom, sd.st_ino, sf.st_ino, sf.st_size, sf.st_mtime_ns)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)


_cache_cle: Dict[str, Any] = {"empreinte": None, "cle": None}


def _cle_publique_relais():
    """La clé publique Ed25519 du relais, `DOSSIER_CLE_RELAIS/NOM_CLE_RELAIS` (arbre root, R-L5-13) ; None si
    absente, douteuse (propriétaire, droits, lien), illisible, trop grosse ou d'un autre type — avec un avertissement
    par empreinte (M2). Relue quand le fichier change."""
    try:
        donnees, empreinte = _lire_fichier_root(DOSSIER_CLE_RELAIS, NOM_CLE_RELAIS, _TAILLE_MAX_CLE)
    except (OSError, ValueError) as e:
        _avertir_une_fois(("cle", DOSSIER_CLE_RELAIS, str(e)), "cle publique du relais refusee : %r", str(e))
        return None
    if _cache_cle["empreinte"] == empreinte:
        return _cache_cle["cle"]
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415
        from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415
        cle = load_pem_public_key(donnees)
    except Exception as e:  # noqa: BLE001 — PEM illisible
        _avertir_une_fois(("cle", empreinte), "cle publique du relais illisible : %r", type(e).__name__)
        return None
    if not isinstance(cle, Ed25519PublicKey):
        _avertir_une_fois(("cle", empreinte), "cle publique du relais refusee : %r n'est pas Ed25519",
                          type(cle).__name__)
        return None
    _cache_cle.update(empreinte=empreinte, cle=cle)
    return cle


# Motifs de chemin des déclarations : ancrés `^/…$`, littéraux, `\.` `\-`, classes bornées (une classe niée doit
# exclure `/`, une classe positive ne contient pas `/`), groupes d'alternatives LITTÉRALES `(a|b)`, quantificateurs
# `+` et `{n}`/`{n,m}`. Ni `.` nu, ni `*`, ni `?`, ni `|` hors groupe, ni groupe spécial, ni échappement de classe.
_RE_GROUPE_LITTERAL = re.compile(r"\((?:[A-Za-z0-9_-]+\|)*[A-Za-z0-9_-]+\)")
_RE_CLASSE_MOTIF = re.compile(r"\[(\^?)([^\]\\]*)\]")
_RE_RESTE_PERMIS = re.compile(r"[A-Za-z0-9_/:+-]*")
# Premier segment LITTÉRAL (R-L5-16) : `^/[^/]+$` ouvrirait toutes les routes d'un segment du module.
_RE_PREMIER_SEGMENT = re.compile(r"\^/(?:[A-Za-z0-9_:-]|\\[.\-])+(?:/|\$$)")


def _valider_motif(motif: Any) -> "re.Pattern":
    if not isinstance(motif, str) or not 3 <= len(motif) <= 256 or not motif.startswith("^/") \
            or not motif.endswith("$") or motif.endswith("\\$"):
        raise ValueError(f"motif {motif!r} : ancré `^/…$` attendu (256 caractères au plus)")
    if not _RE_PREMIER_SEGMENT.match(motif):
        raise ValueError(f"motif {motif!r} : le premier segment doit être littéral")
    corps = _RE_GROUPE_LITTERAL.sub("g", motif[1:-1])

    def _classe(m):
        nie, contenu = m.groups()
        # La classe telle que `re` l'entend (intervalles compris : `[!-~]`, `[.-0]` contiennent `/`) ne doit pas
        # accepter `/` (R-L5-16).
        try:
            franchit = not contenu or re.fullmatch("[" + nie + contenu + "]", "/") is not None
        except re.error:
            franchit = True
        if franchit:
            raise ValueError(f"motif {motif!r} : classe {m.group(0)!r} qui peut franchir `/`")
        return "c"

    corps = _RE_CLASSE_MOTIF.sub(_classe, corps)
    corps = re.sub(r"\\[.\-]", "l", corps)
    corps = re.sub(r"\{\d{1,3}(,\d{1,3})?\}", "q", corps)
    if not _RE_RESTE_PERMIS.fullmatch(corps):
        raise ValueError(f"motif {motif!r} : caractère ou construction interdits (motif ouvert)")
    try:
        return re.compile(motif)
    except re.error as e:
        raise ValueError(f"motif {motif!r} : {e}") from None


def valider_routes_ouvertes(texte: str) -> list:
    """Valide une déclaration `routes-ouvertes.d/<module>.toml` et rend `[(frozenset(méthodes), [motifs])]`.

    Format : `[[routes]]` avec exactement `methodes = ["POST", …]` (parmi POST, PUT, PATCH, DELETE) et
    `chemins = ["^/…$", …]` (motifs bornés, voir `_valider_motif`), chemins relatifs au module (sans
    `/api/v1/<module>`). Lève ValueError à la moindre anomalie : un fichier invalide n'ouvre RIEN."""
    try:
        import tomllib  # noqa: PLC0415
    except ImportError:  # pragma: no cover — Python < 3.11
        import tomli as tomllib  # type: ignore  # noqa: PLC0415
    doc = tomllib.loads(texte)   # TOMLDecodeError dérive de ValueError
    if set(doc) != {"routes"} or not isinstance(doc["routes"], list) or not 1 <= len(doc["routes"]) <= 100:
        raise ValueError("une seule clé `routes`, liste de 1 à 100 tables `[[routes]]`")
    sortie = []
    for entree in doc["routes"]:
        if not isinstance(entree, dict) or set(entree) != {"methodes", "chemins"}:
            raise ValueError("chaque `[[routes]]` porte exactement `methodes` et `chemins`")
        methodes, chemins = entree["methodes"], entree["chemins"]
        if not isinstance(methodes, list) or not methodes or any(m not in METHODES_ECRITURE for m in methodes):
            raise ValueError(f"methodes {methodes!r} : liste non vide parmi {METHODES_ECRITURE}")
        if not isinstance(chemins, list) or not 1 <= len(chemins) <= 100:
            raise ValueError("chemins : liste de 1 à 100 motifs")
        sortie.append((frozenset(methodes), [_valider_motif(c) for c in chemins]))
    return sortie


_cache_routes: Dict[str, Any] = {}


def routes_ouvertes(module: str) -> list:
    """Les écritures que le paquet de `module` déclare ouvertes au porteur délégué ; [] si aucune déclaration, ou
    si elle est douteuse (propriétaire, droits, lien) ou invalide — avec un avertissement par empreinte (M2)."""
    if not _RE_MODULE.fullmatch(module or ""):
        return []
    try:
        donnees, empreinte = _lire_fichier_root(DOSSIER_ROUTES_OUVERTES, f"{module}.toml", _TAILLE_MAX_DECLARATION)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as e:
        _avertir_une_fois(("routes", module, str(e)), "pilotage : declaration de %r ignoree : %r", module, str(e))
        return []
    deja = _cache_routes.get(module)
    if deja and deja[0] == empreinte:
        return deja[1]
    try:
        routes = valider_routes_ouvertes(donnees.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        _avertir_une_fois(("routes", empreinte), "pilotage : declaration de %r invalide : %r", module, str(e))
        routes = []
    _cache_routes[module] = (empreinte, routes)
    return routes


def _chemin_du_module(request, module: str) -> str:
    """Le chemin décodé (casse d'origine), sans le préfixe `/api/v1/<module>` s'il est présent."""
    chemin = _chemin_requete(request)
    for _ in range(3):
        decode = unquote(chemin)
        if decode == chemin:
            break
        chemin = decode
    segments = chemin.split("/")
    if len(segments) >= 4 and segments[0] == "" and segments[1].lower() == "api" and segments[2].lower() == "v1" \
            and segments[3].lower() == module:
        chemin = "/" + "/".join(segments[4:])
    return chemin


def ecriture_ouverte(request, module: str) -> bool:
    """Cette écriture (méthode, chemin) est-elle déclarée ouverte par le paquet de `module` ?"""
    methode = _methode(request)
    chemin = _chemin_du_module(request, module)
    return any(methode in methodes and any(m.fullmatch(chemin) for m in motifs)
               for methodes, motifs in routes_ouvertes(module))


def _module_exclu(nom: str) -> bool:
    return nom in MODULES_EXCLUS_PILOTAGE or nom.startswith("pilotage")


def route_exclue_du_pilotage(request, module: Optional[str] = None) -> bool:
    """Le porteur délégué est-il INTERDIT sur cette route ? Vrai pour un module
    exclu (par son identité, ou par le préfixe `/api/v1/<m>/` du chemin), pour
    une route de secrets nommée (`ROUTES_EXCLUES_PILOTAGE`), pour un chemin dont
    un segment, ou un morceau de segment, est dans `SEGMENTS_EXCLUS_PILOTAGE`,
    et dans le doute (module inconnu)."""
    module = module_courant(request) if module is None else module
    if not module or _module_exclu(module):
        return True
    chemin = _chemin_requete(request)
    for _ in range(3):   # `%2575sers` → `%75sers` → `users`
        decode = unquote(chemin)
        if decode == chemin:
            break
        chemin = decode
    chemin = chemin.lower()
    segments = [s for s in chemin.split("/") if s]
    if len(segments) >= 3 and segments[0] == "api" and segments[1] == "v1":
        if _module_exclu(segments[2]):
            return True
        if segments[2] == module:
            chemin = "/" + "/".join(segments[3:])
    for motif in ROUTES_EXCLUES_PILOTAGE.get(module, ()):
        if motif.fullmatch(chemin):
            return True
    for s in segments:
        if s in SEGMENTS_EXCLUS_PILOTAGE or any(m in SEGMENTS_EXCLUS_PILOTAGE for m in _RE_DECOUPE.split(s) if m):
            return True
    return False


def _forme_pilotage(payload: Any) -> Optional[Dict[str, Any]]:
    """La réclamation `pilotage` si `payload` a la forme d'un jeton délégué
    valide MAINTENANT pour cette box ; None sinon. Ne lit ni le registre des
    sessions ni celui des comptes. Ne lève jamais."""
    try:
        p = payload if isinstance(payload, dict) else {}
        sub = p.get("sub")
        if not isinstance(sub, str) or not _RE_SUB_PILOTAGE.fullmatch(sub):
            return None
        box = nom_box_locale()
        if not box or p.get("aud") != box:
            return None
        cible = p.get("cible")
        if not isinstance(cible, str) or not _RE_MODULE.fullmatch(cible):
            return None
        iat, exp = p.get("iat"), p.get("exp")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (iat, exp)):
            return None
        maintenant = time.time()
        if not (iat < exp <= iat + DUREE_MAX_PILOTAGE_S) or exp <= maintenant or iat > maintenant + DERIVE_PILOTAGE_S:
            return None
        # Un jeton délégué ne porte rien d'autre : ni intention, ni plafond, ni session d'assistance.
        if p.get("scope") or PLAFOND in p or DELEGATION in p:
            return None
        r = p.get(PILOTAGE)
        if not isinstance(r, dict):
            return None
        acteur, maitre, portee = r.get("acteur"), r.get("maitre"), r.get("portee")
        if not isinstance(acteur, str) or not _RE_ACTEUR.fullmatch(acteur):
            return None
        if not isinstance(maitre, str) or not _RE_MAITRE.fullmatch(maitre):
            return None
        if sub != f"{PREFIXE_PILOTAGE}{acteur}@{maitre}":
            return None
        if not isinstance(portee, str) or portee not in PORTEES_PILOTAGE:
            return None
        return r
    except Exception:  # noqa: BLE001 — dans le doute, pas un porteur délégué
        return None


def _est_porteur_pilotage(payload: Any) -> bool:
    """Le `sub` dit « jeton délégué » : un tel payload ne passe JAMAIS par le chemin des sessions ou des comptes."""
    return isinstance(payload, dict) and str(payload.get("sub") or "").startswith(PREFIXE_PILOTAGE)


def _ecrire_audit(entree: Dict[str, Any]) -> None:
    ligne = json.dumps(entree, ensure_ascii=True)
    try:
        with open(AUDIT_PILOTAGE, "a", encoding="utf-8") as f:
            f.write(ligne + "\n")
    except OSError as e:
        # Un audit qui ne s'écrit pas ne passe pas en silence (#3258 R13) : il reste au journal du service.
        log.warning("audit.log non écrit (%s) : %s", e.__class__.__name__, ligne)


_invalides: Dict[str, Any] = {"nombre": 0, "depuis": 0.0}
#: Les gardes `def` tournent dans le pool de threads de FastAPI : le compteur est partagé (R-L5-16).
_verrou_invalides = threading.Lock()


def _horloge() -> float:
    return time.monotonic()


def _compter_invalide(request, motif: str) -> None:
    """M1 : un jeton dont la signature n'a PAS été vérifiée (n'importe qui peut en présenter) n'est pas audité ; il
    est compté, et le compte part à la trace et au journal au plus une fois par minute."""
    maintenant = _horloge()
    with _verrou_invalides:
        _invalides["nombre"] += 1
        if _invalides["depuis"] and maintenant - _invalides["depuis"] < 60:
            return
        nombre = _invalides["nombre"]
        _invalides.update(nombre=0, depuis=maintenant)
    try:
        _ecrire_trace(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "type": "pilotage",
                                  "verdict": "refuse", "motif": motif, "nombre": nombre,
                                  "methode": _methode(request)[:16], "chemin": _chemin_requete(request)[:512],
                                  "module": module_courant(request)}, ensure_ascii=True))
    except (TypeError, ValueError) as e:
        log.warning("pilotage : trace des jetons invalides impossible : %r", str(e))
    log.warning("pilotage : %d jeton(s) delegue(s) non verifie(s) en une minute (dernier motif : %r)", nombre, motif)


def _trace_pilotage(request, verdict: str, motif: str = "", payload: Optional[Dict[str, Any]] = None) -> None:
    """Une ligne par usage du porteur délégué dans la trace des délégations, et, pour un REFUS, aussi dans
    `audit.log`. Acteur, maître, portée seulement quand le jeton a été VÉRIFIÉ (`payload`) ; jamais le jeton.
    ASCII seulement : le chemin vient du client."""
    try:
        r = (payload or {}).get(PILOTAGE) if payload else None
        r = r if isinstance(r, dict) else {}
        champs = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "type": "pilotage",
                  "compte": str(payload.get("sub"))[:200] if payload else None,
                  "acteur": str(r["acteur"])[:64] if "acteur" in r else None,
                  "maitre": str(r["maitre"])[:63] if "maitre" in r else None,
                  "portee": str(r["portee"])[:16] if "portee" in r else None,
                  "verdict": verdict, "methode": _methode(request)[:16], "chemin": _chemin_requete(request)[:512],
                  "module": module_courant(request)}
        if motif:
            champs["motif"] = motif
        _ecrire_trace(json.dumps(champs, ensure_ascii=True))
        if verdict != "accepte":
            _ecrire_audit({"ts": champs["ts"], "module": champs["module"], "evenement": "pilotage_delegue",
                           "verdict": verdict, "motif": motif, "compte": champs["compte"], "acteur": champs["acteur"],
                           "maitre": champs["maitre"], "portee": champs["portee"], "methode": champs["methode"],
                           "chemin": champs["chemin"]})
    except Exception as e:  # noqa: BLE001 — une trace impossible ne coupe pas la requête, mais se dit
        _avertir_une_fois(("trace", type(e).__name__), "pilotage : trace impossible : %r", str(e))


def jeton_pilotage_valide(payload: Dict[str, Any], request: Request) -> bool:
    """Vrai SEULEMENT si : l'en-tête du relais est présent et non vide ; le
    payload a la forme du jeton délégué (`aud` = cette box, `exp - iat ≤ 60`,
    non échu, `sub` = `pilotage:<acteur>@<maître>`, réclamation complète) ; sa
    `cible` est le module qui sert la route (`module_courant`) ; la preuve par
    la socket ne contredit pas (absente, ou la socket de ce module) ; la route
    n'est pas exclue. La signature Ed25519 est vérifiée AVANT, au décodage
    (`_porteur_pilotage`) ; la portée (lecture : GET/HEAD) par les gardes."""
    try:
        if not (request.headers.get(ENTETE_PILOTAGE_RELAIS) or "").strip():
            return False
        if _forme_pilotage(payload) is None:
            return False
        module = module_courant(request)
        if not module or payload.get("cible") != module or not _preuve_socket(request, module):
            return False
        return not route_exclue_du_pilotage(request, module)
    except Exception:  # noqa: BLE001
        return False


def _porteur_pilotage(request: Request, token: str) -> Optional[Dict[str, Any]]:
    """Le payload du porteur délégué (marqué `_PayloadPilotage`, posé sur
    `request.state.pilotage`), ou None : la garde continue, puis 401. Tout
    jeton présenté AVEC l'en-tête du relais et refusé est tracé (motif, jamais
    le jeton). Lève 403, tracé, quand le jeton est valide mais que la route est
    exclue, ou qu'une portée `lecture` tente une autre méthode que GET/HEAD."""
    try:
        if not (request.headers.get(ENTETE_PILOTAGE_RELAIS) or "").strip():
            return None
    except Exception:  # noqa: BLE001 — requête sans en-têtes lisibles
        return None
    cle = _cle_publique_relais()
    box = nom_box_locale()
    if cle is None or not box or not token:
        _compter_invalide(request, "cle publique du relais ou nom de box indisponible")
        return None
    try:
        # La SIGNATURE seule ici ; audience, échéance et forme sont vérifiées par `_forme_pilotage`, une fois la
        # signature acquise : un refus après ce point est celui d'un jeton frappé par le relais, donc audité.
        payload = jwt.decode(token, cle, algorithms=[ALGORITHME_PILOTAGE],
                             options={"verify_exp": False, "verify_aud": False, "verify_iat": False,
                                      "verify_nbf": False})
    except (JWTError, ValueError, TypeError):
        _compter_invalide(request, "signature non verifiee ou jeton illisible")
        return None
    if not isinstance(payload, dict) or _forme_pilotage(payload) is None:
        _trace_pilotage(request, "refuse", "jeton invalide (forme, audience, duree ou reclamation)",
                        payload if isinstance(payload, dict) else None)
        return None
    module = module_courant(request)
    if not module or payload.get("cible") != module:
        _trace_pilotage(request, "refuse", "cible differente du module servi", payload)
        return None
    if not _preuve_socket(request, module):
        _trace_pilotage(request, "refuse", "socket : ni absente ni celle du module", payload)
        return None
    if route_exclue_du_pilotage(request, module):
        _trace_pilotage(request, "refuse", "route exclue du pilotage", payload)
        log.warning("pilotage : route exclue %r pour %r", _chemin_requete(request), payload.get("sub"))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Route exclue du pilotage délégué (comptes, sessions, secrets)")
    lecture = _methode(request) in METHODES_LECTURE
    if payload[PILOTAGE]["portee"] != "admin" and not lecture:
        _trace_pilotage(request, "refuse", "portee lecture", payload)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Pilotage en lecture seule : écriture refusée")
    if not lecture and not ecriture_ouverte(request, module):
        _trace_pilotage(request, "refuse", "ecriture non declaree par le module", payload)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Écriture non ouverte au pilotage délégué par ce module")
    if not jeton_pilotage_valide(payload, request):   # le prédicat public fait foi
        _trace_pilotage(request, "refuse", "predicat jeton_pilotage_valide", payload)
        return None
    marque = _PayloadPilotage(payload)
    try:
        request.state.pilotage = marque
    except AttributeError as e:   # requête sans état : la marque du payload suffit
        _avertir_une_fois(("etat", type(request).__name__), "pilotage : marque non posee sur la requete : %r", str(e))
    return marque


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
        if _est_porteur_pilotage(payload):
            # Le porteur délégué (#3126 L5) n'est pas une session : jamais par `/verify` (auth_request de nginx).
            raise ValueError("porteur délégué du pilotage")
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
    if _est_porteur_pilotage(payload):
        # Le porteur délégué (#3126 L5) n'est JAMAIS une session : reconnu par sa forme, au seul chemin du relais
        # (`_porteur_pilotage`). PyJWT le refuse déjà ici (réclamation `aud` sans audience attendue) ; on le dit.
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
    if sub.startswith(PREFIXE_PILOTAGE):
        # PORTEUR DÉLÉGUÉ DU PILOTAGE (#3126 L5) : administrateur de la box, sous les exclusions de la route, tant
        # que son jeton est valide et que sa portée est `admin`. En `lecture`, jamais (GET/HEAD par `require_jwt`).
        # SEULEMENT le payload RENDU PAR LA GARDE (`_PayloadPilotage`, aussi posé sur `request.state.pilotage`) :
        # le même contenu décodé ailleurs, ou copié, n'est pas un administrateur.
        if not isinstance(payload, _PayloadPilotage):
            return False
        r = _forme_pilotage(payload)
        return r is not None and r.get("portee") == "admin"
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


def session_toujours_admin(payload: Dict[str, Any]) -> bool:
    """Un administrateur dont on a déjà accepté le jeton l'est-il TOUJOURS ? (#3126, connexions longues : flux SSE)

    Regroupe ce que `require_jwt` a vérifié à l'ouverture et qui peut changer ensuite : le jeton n'est pas échu (`exp`), sa session
    est vivante (`jti`, déconnexion ou révocation), le porteur est encore un administrateur réel et actif (`est_admin_reel`).
    Bloquante (lectures de registres) : à appeler hors de la boucle. Ne lève jamais ; dans le doute, faux."""
    try:
        exp = (payload or {}).get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not exp > time.time():   # NaN : faux
            return False
        if _est_porteur_pilotage(payload):
            # Pas de session derrière un porteur délégué (#3126 L5) : sa forme et son échéance (≤ 60 s) font foi.
            return bool(est_admin_reel(payload))
        jti = payload.get("jti")
        if not jti or not _session_validator(jti):
            return False
        return bool(est_admin_reel(payload))
    except Exception:  # noqa: BLE001 — dans le doute, on coupe
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
    if not sub or _is_scope_token(p) or sub.startswith(PREFIXE_PILOTAGE):
        # Le porteur délégué du pilotage (#3126 L5) administre ; il n'agit pas en personne sous son nom.
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
        if payload is None and source == "porteur":
            # PORTEUR DÉLÉGUÉ DU PILOTAGE (#3126 L5) : Bearer seulement, socket du module + en-tête du relais.
            # 403 (tracé) sur une route exclue ou une écriture en portée `lecture`.
            payload = _porteur_pilotage(request, token)
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
    if _est_porteur_pilotage(payload):
        # Porteur délégué (#3126 L5), déjà borné par `require_session` (signature, cible, en-tête, exclusions). Portée
        # `admin` : administrateur ; portée `lecture` : GET et HEAD seulement — revérifié ici, l'écriture est l'enjeu.
        r = _forme_pilotage(payload) if isinstance(payload, _PayloadPilotage) else None
        if r is None or (r.get("portee") != "admin" and _methode(request) not in METHODES_LECTURE):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Pilotage en lecture seule : écriture refusée")
        return payload
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


def adresse_client(request) -> str:
    """Adresse du client pour la TRACE (sessions, audit, délégation) — #1753.

    Lue depuis la DROITE de X-Forwarded-For, en sautant les sauts locaux
    (sbxwaf, nginx) : HAProxy AJOUTE l'adresse réelle en fin de chaîne, alors
    que tout ce qui la précède vient du client. Lire la gauche, comme le
    faisaient /login et la délégation, laissait un appelant écrire l'adresse de
    son choix dans le journal d'audit (même piège que sbxwaf, #1697).
    X-Real-IP n'est PAS consulté : sur les locations qui posent leurs propres
    `proxy_set_header`, nginx ne le réécrit pas et il arrive tel que le client
    l'a envoyé. Ne sert jamais à décider du LAN : c'est le rôle d'ENTETE_LAN.

    TOUTES LES LIGNES, PAS LA PREMIÈRE : `option forwardfor` d'HAProxy ajoute
    une LIGNE X-Forwarded-For à la suite de celle du client au lieu de
    compléter la sienne, et `headers.get()` ne rend que la première — la
    forgée. Mesuré sur gk3 : le journal retenait l'adresse fournie par le
    client. Là où nginx est en frontal, c'est lui qui ajoute l'adresse qu'il a
    résolue (`$proxy_add_x_forwarded_for` sur les locations d'auth).
    """
    h = request.headers
    lignes = h.getlist("X-Forwarded-For") if hasattr(h, "getlist") else [h.get("X-Forwarded-For", "")]
    chaine = [a.strip() for ligne in lignes for a in (ligne or "").split(",") if a.strip()]
    for a in reversed(chaine):
        if not (a.startswith("127.") or a in ("::1", "localhost")):
            return a[:64]
    hote = request.client.host if request.client else ""
    return hote or ""


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
        candidats.append(("porteur", creds.credentials))
    cookie_tok = request.cookies.get(SESSION_COOKIE)
    if cookie_tok:
        candidats.append(("cookie", cookie_tok))
    for source, token in candidats:
        payload = _validate_token(token)
        if payload is not None:
            return payload
        if source == "porteur":
            # Porteur délégué du pilotage (#3126 L5) : mêmes conditions que dans `require_session`, tracé.
            payload = _porteur_pilotage(request, token)
            if payload is not None:
                _trace_delegation(request, payload)
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
    client_ip = adresse_client(request)   # depuis la droite (#1753)
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
    # `?exige=admin` (#1783) : pour les services qui ne peuvent pas lire le
    # secret JWT eux-mêmes (toolbox tourne sous son propre compte), nginx
    # délègue ici la garde d'administration entière — le même prédicat que
    # require_jwt, pas un simple rôle recopié dans un en-tête.
    if request.query_params.get("exige") == "admin" and not est_admin_reel(payload):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="administrateur requis")
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
async def logout(request: Request, response: Response,
                 creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)):
    """Termine la session côté serveur, puis efface le cookie (#1803).

    Effacer le cookie seul laissait le jti vivant (24 h après un mot de passe,
    7 jours pour un appareil) : un jeton copié ailleurs restait valable. Le jti
    du cookie ET celui du Bearer sont retirés du registre — par l'événement que
    secubox-auth applique déjà pour couper des sessions précises. Un jeton
    illisible ou expiré n'empêche pas d'effacer le cookie."""
    jetons = [request.cookies.get(SESSION_COOKIE)]
    if creds is not None:
        jetons.append(creds.credentials)
    for jeton in filter(None, jetons):
        try:
            payload = jwt.decode(jeton, _secret(), algorithms=["HS256"])
        except (JWTError, ValueError, RuntimeError):
            continue
        jti, sub = payload.get("jti"), payload.get("sub")
        if jti and sub and not _is_scope_token(payload):
            _emit_session_event("sessions_coupees", str(sub),
                                {"jtis": [jti], "motif": "deconnexion"})
    response.delete_cookie(SESSION_COOKIE, domain=_cookie_domain(request), path="/")
    response.delete_cookie(SESSION_COOKIE, path="/")   # variante limitée à l'hôte
    return {"ok": True}
