# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""SecuBox API gateway — master ASGI app mounting per-module FastAPIs.

Each SecuBox module ships a `secubox_<name>.api.main` module exporting a
`FastAPI` instance named `app`. This aggregator imports each one and mounts
it under `/api/v1/<name>` so the single uvicorn process handles all routes.

Design constraints:

* **Isolation per module** — each `app.mount()` is wrapped in try/except so a
  broken module doesn't poison startup. Failures recorded in `_LOAD_ERRORS`
  visible at `/health`.
* **No code in modules changes** — sub-apps work as standalone uvicorn AND
  as mounted sub-apps. Starlette does NOT fire a mounted sub-app's
  startup/lifespan events: a module needing a background loop runs on its
  own socket.
* **Path layout matches nginx convention** — nginx already routes
  `/api/v1/<name>/...` to the per-module unix socket. After migration, the
  same routes hit aggregator socket; the path-prefix mount preserves URLs.
* **Graceful degradation** — modules that fail to import don't take down
  the gateway (their routes fall through to the socket relay, 404).
* **Progressive mount (#3216)** — the gateway serves `/health` and the relay
  as soon as uvicorn listens; modules are mounted afterwards, one by one,
  essentials first. A module not mounted yet answers 503 + Retry-After.

Modules to mount are listed in /etc/secubox/aggregator.toml so the package
postinst can manage the migration set without code edits.
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import os
import sys
import time
import tomllib
from pathlib import Path
from typing import Dict, List

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials
from starlette.routing import Mount

log = logging.getLogger("secubox.aggregator")

CONFIG_FILE = Path("/etc/secubox/aggregator.toml")

# Path prefix preserved across all sub-app mounts. Matches existing nginx
# routes : `/api/v1/<module>/...`.
API_PREFIX = "/api/v1"

# Répertoire des sockets dédiés. Lu à chaque requête, et non figé à la
# construction de l'app, pour que les tests puissent le déplacer.
RUN_DIR = "/run/secubox"

# ── Sockets dédiés réservés à l'administration (#1608) ───────────────────────
# Un module servi sur son propre socket SANS garde propre, et que seule la
# console d'administration lit par ce chemin, n'est relayé ici qu'à un
# ADMINISTRATEUR RÉEL (#1581) : session utilisateur de rôle admin, par cookie
# SSO ou Bearer — jamais une session d'appareil, quel que soit son profil.
# 401 sans session, 403 pour tout autre porteur ; le socket n'est pas contacté.
#
# actor : sbx-actord (Renseignement). Son API ne vérifie aucune session : elle
# sert la vue complète (services visés, preuves, feedback) à la seule route qui
# la demande par `X-Sbx-Vue: complete`. Cette route, c'est ce relais, et il ne
# pose l'en-tête qu'APRÈS la garde.
#
# radio : secubox-radio sert la vue sysop à toute requête SANS le préfixe
# /api/v1/radio — c'est-à-dire à ce relais, qui le retire. Elle compte sur la
# porte de l'administration ; cette porte, c'est cette garde (#1800).
#
# vault : le Coffre (#1367) vit dans son propre processus, jamais monté ici ;
# son API vérifie elle-même le jeton, ce relais la ferme d'abord à tout autre
# qu'un administrateur réel.
_SOCKETS_ADMIN = frozenset({"actor", "radio", "vault"})

# L'en-tête de vue est une décision de la ROUTE, pas du visiteur : celui que le
# client envoie n'est jamais recopié, vers aucun module.
_ENTETE_VUE = "X-Sbx-Vue"
# OUVRIR LE COFFRE HORS LAN (Coffre P4, #1367). Le second facteur se vérifie
# ICI : le plancher anti-rejeu des TOTP n'est inscriptible que par `secubox`, et
# le Coffre tourne sous un utilisateur à lui. L'en-tête est une décision de la
# ROUTE, posée après le code valide — celui d'un client est toujours retiré.
_ENTETE_SECOND_FACTEUR = "X-SecuBox-Second-Facteur"
# LA CONNEXION OUVRE LE COFFRE (#1855) : `vault/compte/*` et `vault/personne/*` ne servent que
# secubox-auth, par la socket. Le relais web ne le sert JAMAIS, et marque ce
# qu'il porte au Coffre pour qu'il puisse le refuser lui-même.
_ENTETE_RELAIS = "X-SecuBox-Relais"
_ECHECS_OTP_MAX = 5
_ECHECS_OTP_FENETRE_S = 3600
_echecs_otp: Dict[str, List[float]] = {}
_VUE_COMPLETE = "complete"


def _garde_administration(personnelle: bool = False):
    """`require_jwt` de secubox-core (session valide + administrateur réel) ;
    `require_session` pour le compartiment d'une personne (`vault/moi…`, P5) : une
    session reconnue, invités compris (#1855) — la personne vient du jeton.

    Importé à l'usage : si secubox-core est illisible, seuls les sockets
    réservés tombent (503), le reste de la passerelle continue de servir."""
    try:
        from secubox_core.auth import require_jwt, require_session
    except Exception as e:  # noqa: BLE001 — sans garde, on ne relaie pas
        log.error("[proxy] garde d'administration indisponible : %s", e)
        return None
    return require_session if personnelle else require_jwt


def _chemin_personnel(name: str, path: str) -> bool:
    """`/api/v1/vault/moi…` : le compartiment de la personne de la session (P5).
    Le Coffre la reconnaît lui-même depuis le jeton et exige SA serrure à
    chaque valeur ; ici, on n'admet qu'une session reconnue, invités compris
    (#1855) : sans personne SBX OS derrière elle, le Coffre répond 403."""
    return name == "vault" and (path == "moi" or path.startswith("moi/"))


async def _second_facteur_coffre(request: Request, body: bytes, porteur, fwd: dict):
    """Hors LAN (ou politique « obligatoire »), un TOTP valide et inédit du
    compte de la session, sinon 401. Rend None quand la requête peut passer."""
    import asyncio
    import json as _json
    import time as _time
    try:
        from secubox_core import second_facteur
    except Exception:  # noqa: BLE001 — sans vérificateur, on n'ouvre pas
        return Response(status_code=503)
    if not second_facteur.otp_exige(request):
        return None
    qui = str((porteur or {}).get("sub") or "")
    maintenant = _time.monotonic()
    recents = [t for t in _echecs_otp.get(qui, []) if maintenant - t < _ECHECS_OTP_FENETRE_S]
    _echecs_otp[qui] = recents
    if len(recents) >= _ECHECS_OTP_MAX:
        return JSONResponse({"detail": "trop d'essais — réessayer plus tard"}, status_code=429)
    try:
        code = str((_json.loads(body or b"{}") or {}).get("otp") or "").strip()
    except (ValueError, AttributeError):
        code = ""
    if not (code and qui and await asyncio.to_thread(second_facteur.verifie_totp, qui, code)):
        recents.append(maintenant)
        return JSONResponse({"detail": "second facteur exigé (code TOTP)"}, status_code=401)
    _echecs_otp.pop(qui, None)
    fwd[_ENTETE_SECOND_FACTEUR] = "verifie"
    return None


def _porteur(request: Request) -> HTTPAuthorizationCredentials | None:
    """Le jeton Bearer de la requête, comme HTTPBearer(auto_error=False)."""
    schema, _, jeton = request.headers.get("authorization", "").partition(" ")
    jeton = jeton.strip()
    if schema.lower() != "bearer" or not jeton:
        return None
    return HTTPAuthorizationCredentials(scheme=schema, credentials=jeton)


# Track which modules were successfully mounted and which failed.
_MOUNTED: List[str] = []
_LOAD_ERRORS: Dict[str, str] = {}

# ── Montage progressif (#3216) ───────────────────────────────────────────────
# Monter ~80 modules AVANT qu'uvicorn n'écoute coûtait 4 à 8 minutes de 502 sur le Hall, l'authentification et
# l'administration à chaque redémarrage (gk2, sous swap). La passerelle sert donc tout de suite ; une tâche lancée au
# démarrage monte ensuite les modules un par un, sur le fil de la boucle (`_load_app_from_path` permute `sys.modules['api*']`
# et `sys.path` : jamais en parallèle), en lui rendant la main entre deux. Ceux qui restent à monter répondent 503.
#
# D'abord : auth (la porte d'authentification de nginx passe par /api/v1/auth/auth/verify), hub (menu du Hall), sbxid
# (« Mes comptes »), portal, users.
ESSENTIELS = ("auth", "hub", "sbxid", "portal", "users")
# Entre deux imports, la boucle sert les requêtes en attente au moins aussi longtemps que l'import l'a occupée
# (plancher PAUSE_MONTAGE_S, plafond PAUSE_MAX_S) : sous swap, un import prend 3 à 6 s.
PAUSE_MONTAGE_S = 0.05
PAUSE_MAX_S = 2.0
RETRY_AFTER_S = 5
_A_MONTER: List[str] = []
_MONTAGE: Dict[str, object] = {"pret": False, "duree_s": None, "interrompu": None}
_TACHE_MONTAGE: asyncio.Task | None = None


def _ordre_montage(modules: List[str]) -> List[str]:
    """Les essentiels présents d'abord, dans l'ordre d'ESSENTIELS ; le reste dans l'ordre de la configuration."""
    return [m for m in ESSENTIELS if m in modules] + [m for m in modules if m not in ESSENTIELS]


def _pause_apres(duree_import: float) -> float:
    return max(PAUSE_MONTAGE_S, min(duree_import, PAUSE_MAX_S))


# Modules RETIRÉS du dépôt : encore cités dans /etc/secubox/aggregator.toml d'une box mise à jour
# (hexo, ollama, gotosocial, redroid, simplex, newsbin, voip, frigate : docker/podman, #1743).
# Les ignorer en silence évite une erreur de chargement par module disparu dans la santé.
RETIRED_MODULES = frozenset({
    "hexo", "ollama", "gotosocial", "redroid", "simplex", "newsbin", "voip", "frigate",
    "reality", "ai-insights",   # #3017 : façades sans données, retirées
    "zkp",                      # #3019 : tableau de bord ZKP hors arbre, retiré
})

# Modules À SOCKET DÉDIÉE, jamais montés en processus même si un aggregator.toml les cite (#3013) :
# le relais transparent (`_dedicated_socket_proxy`) les atteint sur /run/secubox/<m>.sock.
# lyrion : E/S bloquantes vers LMS (#763). exposure : écrit /etc/nginx et torrc, recharge nginx
# et tor — son service root existe pour ça ; monté ici (secubox, ProtectSystem=full), il rendait 500.
# nettweak : écrit /proc/sys (sysctl -w) — monté ici, « sysctl: permission denied on key … » pour chaque clé (#3065).
# traffic, qos : `tc qdisc add|del` sans sudo — monté ici, « RTNETLINK answers: Operation not permitted » (#3065).
# #3077 : audit du 2026-10-23 — admin (systemctl, reboot), cloner (tar de /etc et /var/lib), netdiag (ping, ss -p), certs
# (certbot, /etc/letsencrypt), cookies (/etc/secubox/cookies.json, clé Fernet), mail (mailctl, lxc-attach) ont tous une unité
# root active et leur socket ; montés ici, sous `secubox`, leurs actions échouaient (mailctl : « Not installed »).
# #3178 : nac tournait deux fois, ici ET dans secubox-nac.service — deux collecteurs sur la même base, et la page lisait l'instantané en
# mémoire de l'agrégateur (« 0 connecté » sur gk2 pendant que la Vigie voyait 13 appareils). Un seul collecteur : celui de son service.
# #3189 : netmodes appelle netmodesctl par sudo, impossible sous l'utilisateur de l'agrégateur (secubox, pas de sudo) — son service root le fait.
DEDICATED_MODULES = frozenset({"lyrion", "exposure", "nettweak", "traffic", "qos",
                               "admin", "cloner", "netdiag", "certs", "cookies", "mail", "nac", "netmodes", "pilotage"})

# Délai du relais vers une socket dédiée : DELAI_RELAIS, sauf pour un module dont une action dure davantage.
# #3189 : netmodes — une application du mode routeur (Unbound, nginx -t, networkd, DHCP vérifié actif) peut prendre
# jusqu'au délai de son API (DELAI_CTL = 150 s) ; à 60 s le relais rendait 502 pendant que la bascule continuait.
DELAI_RELAIS = 60.0
DELAIS_RELAIS_MODULE: Dict[str, float] = {"netmodes": 200.0}


def _load_config() -> dict:
    """Read the TOML config. Returns a dict with at least 'modules' key.

    Default config (when file missing): empty module list — aggregator runs
    but mounts nothing. Lets the package install before modules are wired in.
    """
    cfg = {"modules": [], "version": __import__("aggregator").__version__}
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("rb") as f:
                data = tomllib.load(f)
            # Les sockets réservées (#3216, relecture) : montées ici, elles échapperaient à la garde et aux marques du relais
            # (Coffre : compte/*, personne/*, second facteur) — jamais, même citées à la main dans le TOML.
            ecartes = RETIRED_MODULES | DEDICATED_MODULES | _SOCKETS_ADMIN
            cfg["modules"] = [m for m in data.get("modules", []) if m not in ecartes]
            ignores = [m for m in data.get("modules", []) if m in ecartes]
            if ignores:
                log.info("modules retirés ou à socket dédiée ignorés : %s", ", ".join(ignores))
            log.info("loaded %d modules from %s", len(cfg["modules"]), CONFIG_FILE)
        else:
            log.warning("no config at %s — aggregator runs with no mounts", CONFIG_FILE)
    except Exception as e:
        log.error("config load failed: %s", e)
    return cfg


SECUBOX_LIB = Path("/usr/lib/secubox")


def _load_app_from_path(name: str) -> FastAPI | None:
    """Locate the module's FastAPI by walking /usr/lib/secubox/<name>/.

    SecuBox modules ship their FastAPI as `api/main.py`. They are not
    installed as Python packages — the per-module systemd unit runs
    `uvicorn api.main:app` from cwd=/usr/lib/secubox/<name>, so module
    code typically uses one of these import styles :

        from .deps import X         # relative — needs __package__ set
        from api.deps import X      # absolute — needs cwd on sys.path
        from api import deps        # mixed
        import api.deps             # bare absolute

    To make all four work for many modules in the SAME interpreter we :

    1. Synthesise a per-module parent package `sbx_pkg_<safe>` whose
       __path__ is `<name>/api`. Loading api/main.py as `<pkg>.main`
       inside that synthetic package makes `from .deps` resolve to
       `sbx_pkg_<safe>.deps`, served from the right `api/` directory.
    2. Pop any cached `sys.modules["api"]` / `sys.modules["api.*"]` left
       behind by previously-loaded modules and put <name> on sys.path —
       so absolute `from api.X` resolves freshly to THIS module's `api/`.
    3. After exec, drop the freshly-loaded `api*` entries again so the
       next module starts with a clean slate (and remove the sys.path
       entry to prevent cross-module bleed).

    Both styles now work per-module without one module's `api/`
    shadowing another's — the bug that hit haproxy after auth had loaded.
    """
    import importlib.util as _util

    candidates = [
        SECUBOX_LIB / name / "api" / "main.py",
        SECUBOX_LIB / name.replace("-", "_") / "api" / "main.py",
    ]
    target = next((p for p in candidates if p.exists()), None)
    if target is None:
        _LOAD_ERRORS[name] = (
            f"main.py not found under "
            f"{SECUBOX_LIB}/{{{name},{name.replace('-', '_')}}}/api/"
        )
        return None

    api_dir = target.parent           # /usr/lib/secubox/<name>/api
    mod_dir = str(api_dir.parent)     # /usr/lib/secubox/<name>
    safe = name.replace("-", "_")
    pkg_name = f"sbx_pkg_{safe}"
    main_name = f"{pkg_name}.main"

    # ── (1) Synthetic parent package so `from .deps import X` works ──
    pkg_init = api_dir / "__init__.py"
    if pkg_init.exists():
        pkg_spec = _util.spec_from_file_location(
            pkg_name, pkg_init,
            submodule_search_locations=[str(api_dir)],
        )
    else:
        pkg_spec = _util.spec_from_loader(pkg_name, loader=None, is_package=True)
        pkg_spec.submodule_search_locations = [str(api_dir)]
    if pkg_spec is None:
        _LOAD_ERRORS[name] = "could not build synthetic parent package spec"
        return None
    pkg_mod = _util.module_from_spec(pkg_spec)
    pkg_mod.__path__ = [str(api_dir)]

    # ── (2) Isolate the `api` namespace from prior module loads ──
    for k in list(sys.modules):
        if k == "api" or k.startswith("api."):
            del sys.modules[k]
    sys.path.insert(0, mod_dir)
    sys.modules[pkg_name] = pkg_mod
    if pkg_init.exists() and pkg_spec.loader is not None:
        try:
            pkg_spec.loader.exec_module(pkg_mod)
        except Exception as e:
            _LOAD_ERRORS[name] = f"exec_module(parent): {type(e).__name__}: {e}"
            sys.modules.pop(pkg_name, None)
            try:
                sys.path.remove(mod_dir)
            except ValueError:
                pass
            return None

    # ── (3) Load api/main.py as `<pkg>.main` so it inherits __package__ ──
    spec = _util.spec_from_file_location(main_name, target)
    if spec is None or spec.loader is None:
        _LOAD_ERRORS[name] = f"spec_from_file_location returned None for {target}"
        return None
    mod = _util.module_from_spec(spec)
    mod.__package__ = pkg_name
    sys.modules[main_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        _LOAD_ERRORS[name] = f"exec_module: {type(e).__name__}: {e}"
        return None
    finally:
        try:
            sys.path.remove(mod_dir)
        except ValueError:
            pass
        # Drop any `api*` cache this load produced so the next module gets
        # its own fresh `api` namespace.
        for k in list(sys.modules):
            if k == "api" or k.startswith("api."):
                del sys.modules[k]

    sub_app = getattr(mod, "app", None)
    if not isinstance(sub_app, FastAPI):
        _LOAD_ERRORS[name] = "no FastAPI 'app' attribute at module level"
        return None
    return sub_app


def _mount_module(parent: FastAPI, name: str) -> None:
    """Resolve and mount a SecuBox module's FastAPI under /api/v1/<name>.

    Le montage est inséré AVANT la route du relais `/api/v1/{name}/{path}` : monté après coup, un `app.mount()`
    finirait derrière elle et le relais répondrait à sa place (#3216)."""
    sub_app = _load_app_from_path(name)
    if sub_app is None:
        log.warning("[mount] %s SKIPPED — %s", name, _LOAD_ERRORS.get(name, "?"))
        return
    try:
        routes = parent.router.routes
        relais = next((i for i, r in enumerate(routes) if getattr(r, "name", None) == "_dedicated_socket_proxy"),
                      len(routes))
        routes.insert(relais, Mount(f"{API_PREFIX}/{name}", app=sub_app, name=name))
        _MOUNTED.append(name)
        log.info("[mount] %s OK at %s/%s", name, API_PREFIX, name)
    except Exception as e:
        _LOAD_ERRORS[name] = f"mount: {type(e).__name__}: {e}"
        log.error("[mount] %s FAILED on mount: %s", name, e)


async def _monter_progressivement(app: FastAPI, chemin_origine: List[str]) -> None:
    """Monte les modules de `_A_MONTER` un par un. Un module reste « à monter » (503) jusqu'à la fin de son montage.

    Après chaque module, le chemin Python reprend son ordre d'origine (#1680) : les ajouts d'un module passent derrière,
    pour que les imports différés des requêtes servies entre deux montages ne prennent pas le websockets de Debian."""
    debut = time.monotonic()
    while _A_MONTER:
        name = _A_MONTER[0]
        t0 = time.monotonic()
        try:
            _mount_module(app, name)
        except (Exception, SystemExit) as e:  # noqa: BLE001 — un module (même un sys.exit à l'import) n'arrête ni les suivants ni la passerelle
            _LOAD_ERRORS[name] = f"mount: {type(e).__name__}: {e}"
            log.error("[mount] %s FAILED: %s", name, e)
        finally:
            _A_MONTER.pop(0)
            ajouts = [p for p in sys.path if p not in chemin_origine]
            sys.path[:] = chemin_origine + ajouts
        await asyncio.sleep(_pause_apres(time.monotonic() - t0))
    _MONTAGE["duree_s"] = round(time.monotonic() - debut, 1)
    _MONTAGE["pret"] = True
    log.info("montage terminé : %d montés, %d échecs en %s s", len(_MOUNTED), len(_LOAD_ERRORS), _MONTAGE["duree_s"])


def _fin_du_montage(tache: asyncio.Task) -> None:
    """Une tâche sortie sur une exception laisserait les modules restants en 503 pour toujours, sans un mot : on le dit
    (journal et /health `interrompu`). Une annulation à l'arrêt n'est pas une interruption."""
    if tache.cancelled() or tache.exception() is None:
        return
    e = tache.exception()
    _MONTAGE["interrompu"] = f"{type(e).__name__}: {e}"
    log.error("montage interrompu : %s — modules restants : %s", _MONTAGE["interrompu"], ", ".join(_A_MONTER) or "aucun")


def _build_app() -> FastAPI:
    cfg = _load_config()
    app = FastAPI(
        title="SecuBox API gateway",
        version=cfg.get("version", "0.1.0"),
        # Disable docs at root to avoid clashes — each sub-app keeps its own
        # /docs and /openapi.json under its mount path.
        docs_url=None,
        redoc_url=None,
    )

    # LE CHEMIN PYTHON DU SERVEUR NE DOIT PAS DÉPENDRE DES MODULES (#1680).
    # Huit modules font `sys.path.insert(0, "/usr/lib/python3/dist-packages")`
    # à leur import : une fois montés ici, le websockets 10.4 de Debian passait
    # DEVANT celui qu'attend uvicorn (≥ 13, /usr/local), et uvicorn mourait au
    # démarrage (« cannot import name ServerProtocol ») — agrégateur en boucle,
    # registre du Hall vide (gk3). On charge d'abord ce dont le serveur a besoin,
    # puis on rend au chemin son ordre d'origine après les montages.
    try:
        import websockets.server  # noqa: F401 — la bonne version, mise en cache
    except Exception:  # noqa: BLE001 — sans websockets, uvicorn s'en passe
        pass
    chemin_origine = list(sys.path)

    # Rien n'est monté ici (#3216) : la tâche de démarrage s'en charge, une fois la socket à l'écoute.
    _MOUNTED.clear()
    _LOAD_ERRORS.clear()
    _A_MONTER[:] = _ordre_montage(cfg.get("modules", []))
    _MONTAGE.update(pret=False, duree_s=None, interrompu=None)

    @app.on_event("startup")
    async def _lancer_montage() -> None:
        global _TACHE_MONTAGE
        _TACHE_MONTAGE = asyncio.create_task(_monter_progressivement(app, chemin_origine))
        _TACHE_MONTAGE.add_done_callback(_fin_du_montage)

    @app.on_event("shutdown")
    async def _arreter_montage() -> None:
        tache = _TACHE_MONTAGE
        if tache is not None and not tache.done():
            tache.cancel()
            await asyncio.gather(tache, return_exceptions=True)

    @app.on_event("startup")
    async def _raise_threadpool() -> None:
        """Sync (`def`) route handlers — including the blocking ones converted
        by the #738 async-sweep — run in AnyIO's default threadpool (40 tokens).
        With ~110 modules sharing one process, raise the cap so concurrent
        blocking calls don't queue head-of-line behind a full pool."""
        try:
            import anyio
            anyio.to_thread.current_default_thread_limiter().total_tokens = 80
            log.info("threadpool limiter raised to 80 tokens")
        except Exception as e:  # never let this break startup
            log.warning("could not raise threadpool limiter: %s", e)

    @app.get("/health")
    async def health() -> dict:
        """Aggregator health. Reports per-module load state.

        Répondre, c'est « passerelle prête » ; `pret` dit « tous les modules traités » (#3216). Servie sur la boucle,
        comme le montage : l'instantané est cohérent (un module n'est jamais à la fois monté et à monter)."""
        return {
            "status": "ok",
            "mounted": list(_MOUNTED),
            "failed": dict(_LOAD_ERRORS),
            "total_mounted": len(_MOUNTED),
            "total_failed": len(_LOAD_ERRORS),
            "pret": _MONTAGE["pret"],
            "a_monter": list(_A_MONTER),
            "duree_montage_s": _MONTAGE["duree_s"],
            "interrompu": _MONTAGE["interrompu"],
        }

    @app.get("/")
    def root() -> dict:
        """Aggregator landing — minimal JSON for liveness probes."""
        return {
            "service": "secubox-aggregator",
            "version": cfg.get("version", "?"),
            "mounted": len(_MOUNTED),
            "failed": len(_LOAD_ERRORS),
        }

    # ── Selective concentrator ───────────────────────────────────────────────
    # A module NOT mounted in-process but running on its own
    # /run/secubox/<name>.sock is reached transparently here, so EVERY module is
    # addressable at /api/v1/<name>/… through the gateway — no per-vhost nginx
    # location and no HAProxy drift needed. Mounted modules never reach this
    # route (their Mount matches first). The sub-app serves its routes at the
    # STRIPPED path (root_path is cosmetic), so /api/v1/jellyfin/partners is
    # forwarded to the socket as /partners.
    #
    # Un module de _SOCKETS_ADMIN n'est relayé qu'à un administrateur réel
    # (#1581). La garde passe AVANT la recherche du socket : la réponse ne
    # dépend pas de ce que le module tourne ou non.
    @app.api_route(
        f"{API_PREFIX}/{{name}}/{{path:path}}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    )
    async def _dedicated_socket_proxy(name: str, path: str, request: Request) -> Response:
        if name in _MOUNTED:
            return Response(status_code=404)
        if name == "vault" and path.split("/", 1)[0] in ("compte", "personne"):
            return Response(status_code=404)
        reserve = name in _SOCKETS_ADMIN
        if reserve:
            garde = _garde_administration(_chemin_personnel(name, path))
            if garde is None:
                return Response(status_code=503)
            # 401 sans session, 403 pour un appareil ou un non-admin :
            # l'HTTPException remonte telle quelle.
            porteur = await garde(request, _porteur(request))
        else:
            porteur = None
        if name in _A_MONTER:
            # Pas encore monté (#3216) : jamais un relais vers une socket absente ou périmée.
            return JSONResponse({"detail": "module en cours de montage", "module": name}, status_code=503,
                                headers={"Retry-After": str(RETRY_AFTER_S)})
        sock = f"{RUN_DIR}/{name}.sock"
        if not os.path.exists(sock):
            return Response(status_code=404)
        url = f"http://localhost/{path}"
        if request.url.query:
            url += f"?{request.url.query}"
        body = await request.body()
        fwd = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", _ENTETE_VUE.lower(),
                                    _ENTETE_SECOND_FACTEUR.lower(), _ENTETE_RELAIS.lower())}
        if reserve:
            fwd[_ENTETE_VUE] = _VUE_COMPLETE
        if name == "vault":
            fwd[_ENTETE_RELAIS] = "agregateur"
        if name == "vault" and path == "ouvrir" and request.method == "POST":
            refus = await _second_facteur_coffre(request, body, porteur, fwd)
            if refus is not None:
                return refus
        try:
            async with httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(uds=sock),
                timeout=DELAIS_RELAIS_MODULE.get(name, DELAI_RELAIS),
            ) as client:
                r = await client.request(request.method, url, content=body, headers=fwd)
        except Exception as e:  # socket gone / module down
            log.warning("[proxy] %s%s/%s -> %s failed: %s", API_PREFIX, "/" + name, path, sock, e)
            return Response(status_code=502)
        drop = {"content-length", "transfer-encoding", "connection"}
        out = {k: v for k, v in r.headers.items() if k.lower() not in drop}
        return Response(content=r.content, status_code=r.status_code, headers=out,
                        media_type=r.headers.get("content-type"))

    return app


# uvicorn imports `secubox_aggregator.main:app` so this stays at module level
app = _build_app()
