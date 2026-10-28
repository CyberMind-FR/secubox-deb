# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""secubox-streamlit — Streamlit Platform API (Three-Fold Architecture)"""
import os
import re
import json
import subprocess
import shutil
import tempfile
import zipfile
import asyncio
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, BackgroundTasks
from fastapi.responses import FileResponse
from secubox_core.auth import require_lecture
from secubox_core.auth import domaine_box, hote_box
from pydantic import BaseModel
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
# secubox_core.screenshots ne fait QUE lire/servir un PNG déjà produit
# (voir app_screenshot ci-dessous) — jamais de capture in-process : celle-
# ci vit exclusivement dans le processus détaché `streamlit-shotter`
# (api/shots.py), lancé via `_spawn_shotter`, jamais importé ici. C'est ce
# qui garantit qu'un chromium enlisé ne peut jamais affecter la boucle
# d'événements partagée par l'agrégateur (#958).
from secubox_core import screenshots as _screenshots
# Validation des noms publics et lecture des publications (#3247) : le MÊME module que streamlitctl exécute en root
# pour écrire — une seule règle, appliquée avant sudo ici, et de nouveau par le ctl.
from . import publication as _pub

app = FastAPI(title="secubox-streamlit", version="1.0.0", root_path="/api/v1/streamlit")

# ════════════════════════��════════════════════════���════════════════
# DOUBLE PRE-CACHE BUFFERING (instant + details)
# ═══════════════════════════════��═════════════════════���════════════

class DoubleBufferCache:
    """Thread-safe double-buffer cache for instant and detailed stats.

    - instant: Quick stats for dashboard cards, refreshed every 5s
    - details: Full detailed data, refreshed every 30s
    """

    def __init__(self):
        self._instant: Dict[str, Any] = {}
        self._details: Dict[str, Any] = {}
        self._instant_ts: float = 0
        self._details_ts: float = 0
        self._lock = threading.Lock()
        self.INSTANT_TTL = 5  # seconds
        self.DETAILS_TTL = 30  # seconds

    def get_instant(self) -> Dict[str, Any]:
        """Get instant cache (quick stats)."""
        with self._lock:
            return self._instant.copy()

    def get_details(self) -> Dict[str, Any]:
        """Get details cache (full data)."""
        with self._lock:
            return self._details.copy()

    def set_instant(self, data: Dict[str, Any]):
        """Update instant cache."""
        with self._lock:
            self._instant = data
            self._instant_ts = time.time()

    def set_details(self, data: Dict[str, Any]):
        """Update details cache."""
        with self._lock:
            self._details = data
            self._details_ts = time.time()

    def instant_stale(self) -> bool:
        """Check if instant cache is stale."""
        return time.time() - self._instant_ts > self.INSTANT_TTL

    def details_stale(self) -> bool:
        """Check if details cache is stale."""
        return time.time() - self._details_ts > self.DETAILS_TTL

    def age(self) -> Dict[str, float]:
        """Get cache ages."""
        now = time.time()
        return {
            "instant_age": round(now - self._instant_ts, 1) if self._instant_ts else None,
            "details_age": round(now - self._details_ts, 1) if self._details_ts else None,
        }


_cache = DoubleBufferCache()
_cache_task: Optional[asyncio.Task] = None

# ══════════════════════════════════════════════════════════════════
# Health Check Endpoint (public, no auth)
# ══════════════════════════════════════════════════════════════════

@app.get("/health")
async def health_check():
    """Public health check endpoint for sidebar status."""
    return {"status": "ok", "module": "deb"}

app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("streamlit")

APPS_DIR = "/srv/streamlit/apps"
LXC_NAME = "streamlit"
CTL = "/usr/sbin/streamlitctl"
# Réglages du module (#3247 : [publication], [ports]) et déclarations ([apps.*], [instances.*]). Lisible par le
# compte secubox (root:secubox 0640) ; seul streamlitctl (root) l'écrit.
STREAMLIT_CONF = Path(os.environ.get("SECUBOX_STREAMLIT_CONF", "/etc/secubox/streamlit.toml"))
# Réveil implicite du conteneur (dépôt, démarrage, publication) : `streamlitctl start` borné. HAProxy coupe une
# requête à 30 s ; le reste de la requête (port, démarrage, publication) doit tenir dans la marge.
CONTENEUR_REVEIL_DELAI_S = 20
# Publication : nginx -t + rechargement, route sbxwaf, génération HAProxy (le plus long).
PUBLICATION_DELAI_S = 90

# Vignettes capturées (#958) — répertoire de cache DÉDIÉ, jamais à
# l'intérieur de APPS_PATH : la moitié du parc est constituée de scripts
# .py à plat (#959), qui n'ont aucun répertoire où poser "une image à côté
# de l'appli", et pour les applis-répertoire ça polluerait potentiellement
# un dépôt git source. Même schéma de stockage que secubox-metablogizer
# (secubox_core.screenshots), sous sa propre clé de module.
SHOTS_CACHE_DIR = Path(os.environ.get("SECUBOX_STREAMLIT_SHOTS_CACHE",
                                       "/var/cache/secubox/streamlit/shots"))
# Le binaire qui pilote réellement chromium (api/shots.py). Toujours lancé
# en process DÉTACHÉ (voir _spawn_shotter) — jamais importé/appelé
# in-process ici, précisément pour que la capture (jusqu'à ~240s,
# secubox_core.shotter) ne puisse jamais geler la boucle d'événements
# partagée par tous les modules quand l'agrégateur les sert en process
# unique (#958 — incident récurrent de ce projet, cf. mémoire "aggregator
# wedge SPOF").
SHOTTER_BIN = os.environ.get("SECUBOX_STREAMLIT_SHOTTER_BIN",
                              "/usr/sbin/streamlit-shotter")

# Plafond (s) de tout appel à streamlitctl fait DANS une requête de réveil
# ou de recapture (#1776). HAProxy coupe une connexion inactive à 30 s :
# la réponse doit partir avant 25 s quoi qu'il arrive sur la board — le
# réveil lui-même, lui, tourne en tâche de fond sans plafond ici (voir
# `_do_wake_in_background`).
WAKE_CHECK_TIMEOUT_S = 15

# Nom d'appli (ou d'instance) admis avant TOUT passage à `sudo streamlitctl`
# (#1776). streamlitctl tourne en root et range ces noms dans des chemins
# ($APPS_PATH/<nom>, `rm -rf` compris pour `app remove`), des noms d'unités
# systemd (streamlit-app@<nom>.service) et des sections TOML : rien ne les
# validait jusqu'ici. Le jeu de caractères est celui des noms réellement
# présents sur la board (répertoires et scripts .py à plat : lettres,
# chiffres, « _ », « - », « . » — ex. yijing-360,
# yijing.bak.rolledback.20260101) ; jamais de « / », et jamais de « . » ni
# de « - » en tête : ni « .. », ni fichier caché, ni nom lu comme une option
# par streamlitctl, systemctl ou pkill.
_NOM_APPLI_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def _exiger_nom_appli(name: str) -> str:
    """Refuse (400) un nom d'appli hors de `_NOM_APPLI_RE`.

    Appelée en tête de chaque route qui transmet un nom à streamlitctl — un
    nom refusé ici n'atteint jamais sudo.
    """
    if not isinstance(name, str) or not _NOM_APPLI_RE.fullmatch(name):
        raise HTTPException(400, "nom d'appli invalide")
    return name


def _cfg():
    cfg = get_config("streamlit")
    power_cfg = cfg.get("power", {}) if cfg else {}
    return {
        "apps_dir": cfg.get("apps_dir", APPS_DIR) if cfg else APPS_DIR,
        "default_port": cfg.get("default_port", 8501) if cfg else 8501,
        "use_lxc": cfg.get("use_lxc", True) if cfg else True,
        "auto_pause": power_cfg.get("auto_pause", False),
        "auto_pause_minutes": power_cfg.get("auto_pause_minutes", 30),
        "presence_events": power_cfg.get("presence_events", True),
    }


# Horodatage et préfixe que `log`/`error` de streamlitctl ajoutent à chaque ligne : retirés du message rendu.
_PREFIXE_JOURNAL = re.compile(r"^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\]\s*(?:ERROR:\s*)?")
# Ce qui ressemble à un secret n'atteint jamais une réponse HTTP : identifiants dans une URL, clé=valeur sensible.
_SECRET_URL = re.compile(r"(://)[^/@\s:]+:[^/@\s]+@")
_SECRET_CLE = re.compile(r"(?i)\b(token|password|passwd|secret|mot_de_passe|api_key|apikey)\b(\s*[=:]\s*)\S+")


def _message_ctl(stdout: str, stderr: str, code) -> str:
    """La cause réelle d'un échec du ctl, JAMAIS vide (#3247 : « Deploy failed: » puis un 500 sans message).

    stderr d'abord (c'est là qu'`error` écrit), sinon la fin de stdout, sinon le code ; trois lignes au plus,
    horodatage retiré, secrets masqués."""
    for flux in (stderr, stdout):
        lignes = [_PREFIXE_JOURNAL.sub("", x).strip() for x in (flux or "").splitlines()]
        lignes = [x for x in lignes if x]
        uniques = list(dict.fromkeys(lignes[-6:]))[-3:]
        if uniques:
            msg = " ; ".join(uniques)
            msg = _SECRET_CLE.sub(r"\1\2***", _SECRET_URL.sub(r"\1***@", msg))
            return msg[:400]
    return f"streamlitctl a échoué (code {code}) sans message"


def _json_de_sortie(stdout: str) -> Optional[dict]:
    """Le JSON rendu par le ctl : toute la sortie, ou sa DERNIÈRE ligne JSON. `log` écrit sur stdout AVANT le JSON
    (`app deploy`) : lire seulement une sortie qui commence par « { » faisait d'un dépôt réussi un échec."""
    brut = (stdout or "").strip()
    if brut.startswith("{"):
        try:
            d = json.loads(brut)
            return d if isinstance(d, dict) else None
        except ValueError:
            pass
    for ligne in reversed(brut.splitlines()):
        ligne = ligne.strip()
        if ligne.startswith("{") and ligne.endswith("}"):
            try:
                d = json.loads(ligne)
            except ValueError:
                continue
            if isinstance(d, dict):
                return d
    return None


def _run_ctl(*args, timeout: int = 30, entree: Optional[str] = None, brut: bool = False) -> dict:
    """Lance `sudo -n streamlitctl <args>` ; rend son JSON (ou {"output": …}) avec "code", et "error" — jamais vide —
    dès que le code n'est pas 0. `entree` passe par l'entrée standard (valeurs d'environnement : jamais en argv).
    `brut` : sortie rendue telle quelle (journaux d'une appli, dont une ligne peut être du JSON)."""
    argv = ["sudo", "-n", CTL, *args]
    try:
        if entree is None:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True,
                               stdin=subprocess.DEVNULL)
        else:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True, input=entree)
        code, stdout, stderr = 0, p.stdout, p.stderr
    except subprocess.CalledProcessError as e:
        code, stdout, stderr = e.returncode, e.stdout or "", e.stderr or ""
    except subprocess.TimeoutExpired:
        return {"error": f"streamlitctl {' '.join(args[:2])} : délai de {timeout} s dépassé", "success": False,
                "timeout": True, "code": None}
    except OSError as e:
        return {"error": f"streamlitctl injoignable : {e.strerror or e}", "success": False, "code": None}
    donnees = None if brut else _json_de_sortie(stdout)
    res = dict(donnees) if donnees is not None else {"output": stdout}
    res["code"] = code
    if code != 0 and not res.get("error"):
        res["error"] = _message_ctl(stdout, stderr, code)
    elif code != 0:
        res["error"] = _SECRET_CLE.sub(r"\1\2***", _SECRET_URL.sub(r"\1***@", str(res["error"])))[:400]
    return res


# Codes de streamlitctl (et d'api/publication.py) → statut HTTP. Un échec non classé reste un 500, mais lisible.
_STATUTS_CTL = {2: 404, 3: 409, 4: 409, 5: 409, 64: 400, 75: 503}


def _ctl_ok(*args, timeout: int = 30, entree: Optional[str] = None) -> dict:
    """`_run_ctl` qui lève l'HTTPException adaptée (cause réelle en détail) au lieu de rendre l'échec."""
    r = _run_ctl(*args, timeout=timeout, entree=entree)
    if r.get("timeout"):
        raise HTTPException(504, r["error"])
    code = r.get("code")
    if code == 0:
        return r
    raise HTTPException(_STATUTS_CTL.get(code, 500) if code is not None else 502,
                        r.get("error") or f"streamlitctl a échoué (code {code})")


def _spawn_shotter(name: str, *, force: bool) -> None:
    """Lance `streamlit-shotter` en tâche DÉTACHÉE et rend la main
    immédiatement (#958).

    `subprocess.Popen(...)` retourne dès le fork+exec (millisecondes) — il
    n'attend JAMAIS l'issue du processus fils. Toute la résolution de
    cible (l'appli tourne-t-elle ? sur quel port ? IP du conteneur ?) et la
    capture elle-même (jusqu'à ~240s, chromium piloté par CDP) se déroulent
    dans ce processus fils, entièrement hors de ce service et de sa boucle
    d'événements : même un chromium qui s'enliserait ne peut affecter que
    ce processus détaché, jamais l'agrégateur qui sert ce module (et ~110
    autres) en process unique.

    Ne lève jamais : appelée après un réveil déjà réussi ou un clic
    "recapturer" déjà validé, un échec de lancement ne doit dégrader ni
    l'un ni l'autre — seulement finir au journal.
    """
    args = [SHOTTER_BIN, name] + (["--force"] if force else [])
    try:
        subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          start_new_session=True)
    except OSError as exc:
        log.warning("shotter spawn failed for %s: %s", name, exc)


def _lxc_running() -> bool:
    """Check if LXC container is running.

    Uses sudo -n for non-interactive sudo (requires sudoers config). Borné (#3247) : un lxc-info qui ne répond
    pas vaut « arrêté » plutôt qu'une requête suspendue.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "/usr/sbin/secubox-lxcctl", "lxc-info", "-n", LXC_NAME, "-s"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("lxc-info %s : %s", LXC_NAME, exc)
        return False
    return "RUNNING" in result.stdout


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    return Path(f"/var/lib/lxc/{LXC_NAME}").exists()


APPS_PATH = "/srv/streamlit/apps"


def _read_deploy_metadata(app_name: str) -> dict:
    """Read .deploy.json for an app; return empty dict if absent or invalid."""
    path = Path(APPS_PATH) / app_name / ".deploy.json"
    try:
        with path.open() as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError, OSError):
        return {}


def _git_describe_tag(app_name: str) -> str | None:
    """Fallback: read the current tag via `git describe --tags --exact-match`."""
    app_dir = Path(APPS_PATH) / app_name
    if not (app_dir / ".git").exists():
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(app_dir), "describe", "--tags", "--exact-match"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _get_apps(*, enrichir: bool = True, timeout: int = 30,
              strict: bool = False) -> List[dict]:
    """Get list of apps from streamlitctl, enriched with current_tag + deployed_at.

    `enrichir=False` saute le `git describe` par appli (un sous-processus par
    dépôt, jusqu'à 5 s chacun) — inutile à une simple vérification de
    vivacité, et c'est lui qui rendrait sa durée imprévisible. `strict=True`
    lève `RuntimeError` quand streamlitctl n'a pas rendu de liste (délai
    dépassé, sudo refusé, sortie illisible) au lieu de la confondre avec
    « aucune appli » : sur le chemin du réveil, ce serait un faux 404.
    """
    result = _run_ctl("app", "list", timeout=timeout)
    if strict and not isinstance(result.get("apps"), list):
        raise RuntimeError(str(result.get("error") or "streamlitctl app list sans liste"))
    apps = result.get("apps", [])
    if not enrichir:
        return apps
    for app in apps:
        name = app.get("name")
        if not name:
            continue
        meta = _read_deploy_metadata(name)
        app["current_tag"] = meta.get("tag") or _git_describe_tag(name)
        app["deployed_at"] = meta.get("deployed_at")
    return apps


def _get_instances() -> List[dict]:
    """Get list of instances from streamlitctl."""
    result = _run_ctl("instance", "list")
    return result.get("instances", [])


def _refresh_instant_cache():
    """Refresh instant cache with quick stats."""
    cfg = _cfg()
    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    _cache.set_instant({
        "container_status": container_status,
        "lxc_exists": _lxc_exists(),
        "lxc_running": _lxc_running() if cfg["use_lxc"] else False,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
        "ts": time.time(),
    })


def _refresh_details_cache():
    """Refresh details cache with full data."""
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    _cache.set_details({
        "apps": apps,
        "instances": instances,
        "app_count": len(apps),
        "running_apps": sum(1 for a in apps if a.get("running")),
        "instance_count": len(instances),
        "running_instances": sum(1 for i in instances if i.get("running")),
        "container_status": container_status,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
        "ts": time.time(),
    })


# RAFRAÎCHIR À LA DEMANDE, PAS EN BOUCLE (#1835).
#
# Une boucle permanente relançait toutes les 30 s `streamlitctl app list` et
# `instance list` (~400 processus chacun : le script lit son TOML champ par
# champ, entrée par entrée), un `git describe` par appli, et sondait le
# conteneur toutes les 5 s — que quelqu'un regarde ou non. Mesuré sur gk2 le
# 2026-10-01 : ~14 000 lancements en dix minutes, près de la moitié de la box,
# pour AUCUNE lecture de ces routes de la journée. Et ces appels synchrones
# tournaient DANS la boucle d'événements : l'API se figeait le temps de chacun.
#
# Désormais une route qui lit une donnée périmée la rafraîchit elle-même, hors
# de la boucle (thread), une seule fois même si plusieurs requêtes arrivent
# ensemble. Personne ne regarde : rien ne tourne. C'est la règle de #1028.
#
# PÉRIMÉ MAIS PRÉSENT : ON RÉPOND TOUT DE SUITE. Une liste fraîche coûte ~9 s
# sur gk2 (mesuré) ; la faire attendre au visiteur à chaque expiration serait
# pire que la boucle. Si une valeur existe, on la rend et le rafraîchissement
# part en tâche de fond ; on n'attend que lorsqu'il n'y a encore RIEN.
_VERROU_CACHE: Optional[asyncio.Lock] = None
_EN_FOND: Dict[str, asyncio.Task] = {}


async def _rafraichit(quoi: str, perime) -> None:
    global _VERROU_CACHE
    if _VERROU_CACHE is None:
        _VERROU_CACHE = asyncio.Lock()
    async with _VERROU_CACHE:
        if not perime():                       # rafraîchi pendant l'attente
            return
        fn = _refresh_instant_cache if quoi == "instant" else _refresh_details_cache
        try:
            await asyncio.to_thread(fn)
        except Exception as e:  # noqa: BLE001 — une donnée périmée vaut mieux qu'un 500
            log.warning("cache refresh error (%s): %s", quoi, e)


async def _cache_frais(quoi: str) -> None:
    perime = _cache.instant_stale if quoi == "instant" else _cache.details_stale
    if not perime():
        return
    present = bool(_cache.get_instant() if quoi == "instant" else _cache.get_details())
    if not present:
        await _rafraichit(quoi, perime)
        return
    t = _EN_FOND.get(quoi)
    if t is None or t.done():
        _EN_FOND[quoi] = asyncio.create_task(_rafraichit(quoi, perime))


@app.on_event("startup")
async def startup_cache():
    """Un seul pré-remplissage, en tâche de fond : le premier visiteur ne paie
    pas l'attente, et le démarrage n'est pas retardé. Pas de boucle."""
    global _cache_task
    _cache_task = asyncio.create_task(_cache_frais("details"))


@app.on_event("shutdown")
async def shutdown_cache():
    """Annule le pré-remplissage s'il court encore."""
    global _cache_task
    if _cache_task:
        _cache_task.cancel()


# ═══════════════════════════════════════════════════════════════════════
# THREE-FOLD ARCHITECTURE
# ═══════════════════════════════════════════════════════════════════════

# ── COMPONENTS ─────────────────────────────────────────────────────────
# What makes up the system

@router.get("/components", dependencies=[Depends(require_lecture)])
async def components():
    """List system components (public)."""
    cfg = _cfg()
    lxc_installed = _lxc_exists()

    return {
        "components": [
            {
                "name": "Streamlit LXC Container",
                "type": "container",
                "description": "Alpine-based LXC container running Streamlit",
                "installed": lxc_installed,
                "config_path": "/etc/secubox/streamlit.toml"
            },
            {
                "name": "Application Directory",
                "type": "storage",
                "description": "Directory containing deployed apps",
                "path": cfg["apps_dir"],
                "exists": Path(cfg["apps_dir"]).exists()
            },
            {
                "name": "streamlitctl",
                "type": "cli",
                "description": "Control script for container and app management",
                "path": CTL,
                "installed": Path(CTL).exists()
            }
        ],
        "use_lxc": cfg["use_lxc"]
    }


# ── STATUS ─────────────────────────────────────────────────────────────
# Health and runtime state

@router.get("/instant", dependencies=[Depends(require_lecture)])
async def instant():
    """Get instant stats from pre-cache (public, fast)."""
    await _cache_frais("instant")
    data = _cache.get_instant()
    data["cache_age"] = _cache.age()
    return data


@router.get("/details", dependencies=[Depends(require_lecture)])
async def details():
    """Get detailed stats from pre-cache (public)."""
    await _cache_frais("details")
    data = _cache.get_details()
    data["cache_age"] = _cache.age()
    return data


@router.get("/status", dependencies=[Depends(require_lecture)])
async def status():
    """Get platform status from cache (public)."""
    # Use cached details for fast response
    await _cache_frais("details")
    cached = _cache.get_details()
    if cached and cached.get("app_count") is not None:
        return {
            "app_count": cached.get("app_count", 0),
            "running_apps": cached.get("running_apps", 0),
            "instance_count": cached.get("instance_count", 0),
            "running_instances": cached.get("running_instances", 0),
            "container_status": cached.get("container_status", "unknown"),
            "use_lxc": cached.get("use_lxc", True),
            "default_port": cached.get("default_port", 8501),
            "cached": True,
            "cache_age": _cache.age(),
        }

    # Fallback to direct fetch if cache not ready
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    container_status = "not_configured"
    if cfg["use_lxc"]:
        if _lxc_exists():
            container_status = "running" if _lxc_running() else "stopped"
        else:
            container_status = "not_installed"

    running_apps = sum(1 for a in apps if a.get("running"))
    running_instances = sum(1 for i in instances if i.get("running"))

    return {
        "app_count": len(apps),
        "running_apps": running_apps,
        "instance_count": len(instances),
        "running_instances": running_instances,
        "container_status": container_status,
        "use_lxc": cfg["use_lxc"],
        "default_port": cfg["default_port"],
        "cached": False,
    }


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    checks = {
        "api": "ok",
        "streamlitctl": "ok" if Path(CTL).exists() else "missing",
        "apps_dir": "ok" if Path(_cfg()["apps_dir"]).exists() else "missing"
    }

    if _cfg()["use_lxc"]:
        if _lxc_exists():
            checks["container"] = "running" if _lxc_running() else "stopped"
        else:
            checks["container"] = "not_installed"

    overall = "healthy" if all(v in ["ok", "running"] for v in checks.values()) else "degraded"

    return {
        "status": overall,
        "module": "streamlit",
        "checks": checks
    }


# ── ACCESS ─────────────────────────────────────────────────────────────
# How to connect to services

@router.get("/access", dependencies=[Depends(require_lecture)])
async def access():
    """Get access information for running apps (public)."""
    apps = _get_apps()
    instances = _get_instances()
    cfg = _cfg()

    access_points = []

    # Add running apps
    for app in apps:
        if app.get("running") and app.get("port"):
            access_points.append({
                "name": app["name"],
                "type": "app",
                "port": app["port"],
                "url": f"http://{{{{hostname}}}}:{app['port']}",
                "status": "running"
            })

    # Add running instances
    for inst in instances:
        if inst.get("running") and inst.get("port"):
            access_points.append({
                "name": inst.get("id", inst.get("name", "unknown")),
                "type": "instance",
                "app": inst.get("app"),
                "port": inst["port"],
                "url": f"http://{{{{hostname}}}}:{inst['port']}",
                "domain": inst.get("domain"),
                "status": "running"
            })

    return {
        "access": access_points,
        "default_port": cfg["default_port"]
    }


# ═══════════════════════════════════════════════════════════════════════
# APPS
# ═══════════════════════════════════════════════════════════════════════

@router.get("/apps", dependencies=[Depends(require_lecture)])
async def list_apps():
    """List all apps (public)."""
    return {"apps": _get_apps()}


APPS_AUDIT_CACHE = Path("/var/cache/secubox/streamlit/audit.json")


@router.get("/apps/audit", dependencies=[Depends(require_lecture)])
async def apps_audit():
    """Inventaire croisé disque / déclarations / processus (lecture seule).

    Lecture GARDÉE (#1256) comme les autres routes d'affichage du module :
    jeton, cookie de session, ou mode tableau de bord depuis le LAN. C'est
    elle qui alimente le mur Mosaïque (effacée par une fusion du 2026-08-17,
    restaurée par #1776).

    Servi depuis le cache écrit par streamlit-audit.timer (root, disque +
    TOML + lxc-attach ps, ~11s en direct / ~31s à travers l'agrégateur). Le
    chemin de requête est une lecture de fichier : ne JAMAIS retomber sur
    `streamlitctl app audit` en direct ici, ce serait réintroduire le délai
    que ce cache existe pour supprimer (#956).
    """
    try:
        raw = json.loads(APPS_AUDIT_CACHE.read_text())
        if not isinstance(raw, dict):
            raise ValueError("cache content is not a JSON object")
    except FileNotFoundError:
        return {"available": False, "reason": "cache not written yet",
                "apps": [], "summary": {}}
    except (OSError, ValueError) as exc:
        log.warning("apps audit cache unreadable: %s", exc)
        return {"available": False, "reason": "cache unreadable",
                "apps": [], "summary": {}}

    age = None
    try:
        age = int(time.time() - APPS_AUDIT_CACHE.stat().st_mtime)
    except OSError:
        pass

    return {
        "available": True,
        "apps": raw.get("apps", []),
        "summary": raw.get("summary", {}),
        "cache_age_seconds": age,
    }


# ═══════════════════════════════════════════════════════════════════════
# SCREENSHOTS — Mosaic tile thumbnails (#958)
# ═══════════════════════════════════════════════════════════════════════

@router.get("/apps/vitrine", dependencies=[Depends(require_lecture)])
def apps_vitrine():
    """La VITRINE des applis pour le Hall (#2996, phase 4) : une ligne par appli — nom, en ligne ou non, domaine public
    (celui de sa première instance active, sinon aucun), vignette conservée et sa date. Lecture gardée comme `/apps`
    et `/apps/{name}/screenshot` (décision #1776 : une vignette photographie l'appli). Jamais de capture déclenchée ici."""
    cfg = _load_streamlit_config() or {}
    domaines: Dict[str, str] = {}
    for ident, inst in (cfg.get("instances") or {}).items():
        appli = inst.get("app", ident)
        if inst.get("enabled", True) and appli not in domaines:
            domaines[appli] = inst.get("domain") or hote_box(ident)
    lignes = []
    for a in _get_apps(enrichir=False, timeout=10):
        nom = a.get("name")
        if not nom or not _NOM_APPLI_RE.fullmatch(str(nom)):
            continue
        meta = _screenshots.read_meta(SHOTS_CACHE_DIR, nom)
        lignes.append({
            "name": nom,
            "running": bool(a.get("running")),
            "archived": bool(a.get("archived")),
            "domain": domaines.get(nom),
            "screenshot_available": _screenshots.png_path(SHOTS_CACHE_DIR, nom).exists(),
            "screenshot_captured_at": meta.get("captured_at"),
        })
    lignes.sort(key=lambda x: (not x["running"], x["name"].lower()))
    return {"apps": lignes, "vhost_suffix": domaine_box()}


@router.get("/apps/{name}/screenshot", dependencies=[Depends(require_lecture)])
def app_screenshot(name: str):
    """Sert la vignette conservée — lecture GARDÉE (#1256, décision #1776).

    Publique à l'origine (#958) au motif qu'un `<img src>` ne porte pas
    d'en-tête Authorization. Mais une vignette est une photographie de
    l'appli elle-même — tableaux de bord, photos, données saisies — et le
    parc est passé en lecture gardée : la route équivalente de
    secubox-metablogizer, invoquée à l'époque comme précédent, est elle-même
    sous `require_lecture` depuis. Le `<img>` du mur reste servi : il est
    émis depuis la même origine et emporte le cookie de session, et le mode
    tableau de bord depuis le LAN l'ouvre sans jeton. Un visiteur anonyme
    hors LAN reçoit 401, jamais l'image.

    Route de LECTURE SEULE : ne déclenche jamais de capture, quel que soit
    le nombre de requêtes reçues — la vignette est déjà là ou elle ne l'est
    pas (`sync def` : FastAPI la sert depuis le threadpool, un simple accès
    fichier, jamais de subprocess ici).

    `Cache-Control: private, max-age=604800, immutable` — délibérément PAS
    `no-cache` : le panneau ajoute déjà `?t=<captured_at>` à l'URL (voir
    `www/streamlit/index.html`), donc l'URL elle-même change quand le
    contenu change. Tant que `captured_at` ne bouge pas, c'est
    STRICTEMENT le même contenu — laisser le navigateur servir sa copie
    locale sans même revalider est exactement ce qui évite de retélécharger
    56 PNG à chaque rafraîchissement de 60s (#958 point 5). `private` et non
    plus `public` : la réponse est désormais soumise à une garde, aucun
    cache partagé ne doit la resservir à un autre client.
    """
    _exiger_nom_appli(name)
    try:
        p = _screenshots.png_path(SHOTS_CACHE_DIR, name)
    except ValueError:
        raise HTTPException(404, "unknown app")
    if not p.exists():
        raise HTTPException(404, "no screenshot yet")
    meta = _screenshots.read_meta(SHOTS_CACHE_DIR, name)
    return FileResponse(p, media_type="image/png", headers={
        "Cache-Control": "private, max-age=604800, immutable",
        "X-Captured-At": str(meta.get("captured_at", "")),
    })


@router.post("/apps/{name}/recapture")
def app_recapture(name: str, user=Depends(require_jwt)):
    """Déclencheur MANUEL (spec §3.1) — le bouton "recapturer" d'une tuile.

    Valide la cible ICI (rapide : entrypoint + port + `lxc-info`, pas de
    chromium) pour donner un retour immédiat et exact au bouton — 404 si
    l'appli est inconnue, 409 si elle est endormie ou sans cible
    exploitable. Ce pré-check n'est PAS fait sur le chemin de réveil (voir
    `wake_app`) : là, l'appli vient déjà de se réveiller avec succès, le
    coût d'une seconde résolution serait payé pour rien.

    Rend la main dès le lancement du processus détaché — jamais après la
    capture elle-même (~240s), voir `_spawn_shotter`. La résolution de cible
    est bornée à WAKE_CHECK_TIMEOUT_S : la réponse doit partir avant la
    coupure d'inactivité d'HAProxy (30 s) ; au-delà, 409 plutôt qu'un 504.
    """
    _exiger_nom_appli(name)
    target = _run_ctl("app", "shot-target", name, timeout=WAKE_CHECK_TIMEOUT_S)
    if not target.get("ok"):
        reason = str(target.get("error") or "capture impossible")
        raise HTTPException(404 if "not found" in reason else 409, reason)
    _spawn_shotter(name, force=True)
    return {"ok": True, "triggered": True, "name": name}


@router.get("/app/{name}")
async def get_app(name: str, user=Depends(require_jwt)):
    """Get app details."""
    apps = _get_apps()
    for a in apps:
        if a.get("name") == name:
            # Add extra details
            app_dir = Path(_cfg()["apps_dir"]) / name
            a["path"] = str(app_dir)
            a["has_requirements"] = (app_dir / "requirements.txt").exists()
            return a
    raise HTTPException(404, f"App not found: {name}")


# ── DÉPÔT, PORT, PUBLICATION (#3247) ──────────────────────────────────
# Constaté sur gk2 le 2026-10-28 : dépôt et démarrage en 500 SANS MESSAGE quand le conteneur dormait, port 8501
# imposé, aucune publication, nom public figé. Chaque route ci-dessous : réveille le conteneur s'il dort (même chemin
# que /power/wake), demande le port au ctl (seul à voir ce qui écoute dans le conteneur), publie par le chemin
# déclaratif (api/publication.py, exécuté en root par streamlitctl), et rend la cause réelle d'un échec.

ZIP_MAX_ENTREES = 10000
ZIP_MAX_OCTETS = 1 << 30          # 1 Gio une fois décompressée


class NomPublic(BaseModel):
    public_name: str = ""


class EnvAppli(BaseModel):
    vars: Dict[str, str] = {}
    unset: List[str] = []


def _exiger_port(port: int) -> int:
    """0 = port automatique ; sinon 1024..65535 (l'appli tourne sans privilège dans le conteneur)."""
    if port == 0:
        return 0
    if not 1024 <= port <= 65535:
        raise HTTPException(400, f"port {port} hors limites : 1024 à 65535, ou vide pour un port automatique")
    return port


def _exiger_label(label: str) -> str:
    """Nom public : libellé DNS strict (400), jamais un nom de service de la box (409). Avant tout sudo."""
    err = _pub.erreur_label(label)
    if err:
        raise HTTPException(400, err)
    if _pub.label_reserve(label):
        raise HTTPException(409, f"nom public « {label} » réservé aux services de la box")
    return label


def _acteur(user) -> str:
    sub = str((user or {}).get("sub") or "")
    return sub if _pub.ACTEUR_RE.fullmatch(sub) else "inconnu"


def _conf_texte() -> str:
    try:
        return STREAMLIT_CONF.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("streamlit.toml illisible : %s", exc)
        return ""


def _publications_de(name: str, texte: Optional[str] = None) -> List[dict]:
    return _pub.publications(_conf_texte() if texte is None else texte, "").get(name, [])


def _verifier_nom_libre(label: str, name: str) -> None:
    """Réponse rapide AVANT tout geste (rien n'est déposé si le nom est pris) ; le ctl revérifie en root."""
    dom = domaine_box()
    if not dom:
        raise HTTPException(409, "domaine de la box inconnu ([global] domain dans secubox.conf) : publication "
                                 "impossible")
    texte = _conf_texte()
    if any(p["nom_public"] == label for p in _publications_de(name, texte)):
        return
    conflit = _pub.conflit_nom(label, f"{label}.{dom}", name, texte, _pub.routes_lisibles())
    if conflit:
        raise HTTPException(409, conflit)


def _verifier_zip(chemin: Path) -> None:
    """Refuse une archive dont une entrée sortirait du dossier de l'appli (chemin absolu, « .. »), un lien
    symbolique, ou une archive démesurée — avant que le ctl root ne l'extraie (RULES-CODE § 1)."""
    try:
        with zipfile.ZipFile(chemin) as z:
            infos = z.infolist()
    except (zipfile.BadZipFile, OSError) as exc:
        raise HTTPException(400, f"archive ZIP illisible ({exc})")
    if len(infos) > ZIP_MAX_ENTREES:
        raise HTTPException(400, f"archive refusée : plus de {ZIP_MAX_ENTREES} entrées")
    total = 0
    for info in infos:
        nom = info.filename.replace("\\", "/")
        if nom.startswith("/") or re.match(r"^[A-Za-z]:", nom) or ".." in nom.split("/"):
            raise HTTPException(400, f"archive refusée : chemin hors du dossier de l'appli ({nom[:120]})")
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            raise HTTPException(400, f"archive refusée : lien symbolique ({nom[:120]})")
        total += info.file_size
        if total > ZIP_MAX_OCTETS:
            raise HTTPException(400, "archive refusée : plus de 1 Gio une fois décompressée")


def _attribuer_port(name: str, port: int) -> dict:
    """Port libre choisi PAR LE CTL : lui seul voit ce qui écoute dans le conteneur (lxc-attach, root), et il
    tient les déclarations ; persisté et appli déclarée ([apps.<name>]) avec --apply."""
    args = ["app", "port", name] + ([str(port)] if port else []) + ["--apply"]
    return _ctl_ok(*args, timeout=WAKE_CHECK_TIMEOUT_S)


def _publication_apres(name: str, user, nom_public: str = "") -> dict:
    """Publication après un dépôt ou un démarrage. Nom public fourni → publié sous ce nom ; déjà publiée → la
    chaîne suit le port ; sinon publiée sous un nom dérivé du dossier SEULEMENT si `[publication] auto = true`.
    Jamais d'exception : un refus (nom pris…) est rapporté, le dépôt ou le démarrage reste acquis."""
    texte = _conf_texte()
    actuelles = _publications_de(name, texte)
    if nom_public:
        args = ["app", "publish", name, nom_public]
    elif len(actuelles) == 1 and actuelles[0].get("geree"):
        args = ["app", "publish", name]
    elif len(actuelles) == 1:
        return {"publiee": True, "synchronisee": False, "domaine": actuelles[0].get("domaine"),
                "raison": "publication posée hors de streamlitctl : laissée telle quelle ; « Renommer » sous le même "
                          "nom la reprend dans la chaîne gérée"}
    elif actuelles:
        return {"publiee": True, "synchronisee": False,
                "raison": "plusieurs instances publient cette appli : rien n'est resynchronisé"}
    elif _pub.reglages(texte)["auto"]:
        label = _pub.label_par_defaut(name)
        if not label or _pub.label_reserve(label):
            return {"publiee": False, "erreur": "aucun nom public utilisable dérivé du dossier : publiez-la "
                                                "avec un nom"}
        args = ["app", "publish", name, label]
    else:
        return {"publiee": False,
                "raison": "publication sur demande ([publication] auto = false) : action « Publier »"}
    r = _run_ctl(*args, "--par", _acteur(user), "--apply", timeout=PUBLICATION_DELAI_S)
    if r.get("code") != 0:
        return {"publiee": bool(actuelles), "erreur": r.get("error") or "publication impossible"}
    return {"publiee": True, "nom_public": r.get("nom_public"), "domaine": r.get("domaine"),
            "evenement": r.get("evenement"), "avertissements": r.get("avertissements") or []}


@router.post("/deploy")
def deploy(
    file: UploadFile = File(...),
    name: str = Form(""),
    port: str = Form(""),
    public_name: str = Form(""),
    name_q: str = Query("", alias="name"),
    port_q: int = Query(0, alias="port"),
    public_q: str = Query("", alias="public_name"),
    user=Depends(require_jwt),
):
    """Déploie une appli depuis un ZIP (#3247).

    Champs de formulaire (ceux qu'envoie la page ; les anciens paramètres de requête restent admis) : `name`
    (nom du dossier), `port` (vide = automatique), `public_name` (nom public : publie l'appli sous
    `<nom>.<domaine de la box>`). Réveille le conteneur s'il dort ; attribue et persiste le port ; déclare
    l'appli ; publie si un nom public est donné (ou si `[publication] auto = true`), puis la démarre.
    `def` : servie dans le pool de fils, jamais sur la boucle partagée de l'agrégateur."""
    name = (name or name_q).strip()
    if not name:
        if not file.filename:
            raise HTTPException(400, "Filename required")
        name = Path(file.filename).name.replace(".zip", "").replace(" ", "_").lower()
    # Le nom finit dans l'argv de streamlitctl.
    _exiger_nom_appli(name)
    port_txt = (port or "").strip()
    if port_txt and not port_txt.isdigit():
        raise HTTPException(400, "port invalide : un nombre, ou vide pour un port automatique")
    port_n = _exiger_port(int(port_txt) if port_txt else port_q)
    nom_public = (public_name or public_q).strip()
    if nom_public:
        _exiger_label(nom_public)
        _verifier_nom_libre(nom_public, name)

    # Fichier temporaire NON prévisible (l'ancien /tmp/streamlit_upload_<nom>.zip l'était), lu par le ctl root.
    fd, tmp = tempfile.mkstemp(prefix="streamlit-depot-", suffix=".zip")
    try:
        with os.fdopen(fd, "wb") as fh:
            shutil.copyfileobj(file.file, fh)
        _verifier_zip(Path(tmp))
        reveille = _reveiller_conteneur(f"le dépôt de « {name} »")
        result = _ctl_ok("app", "deploy", tmp, name, timeout=120)
    finally:
        Path(tmp).unlink(missing_ok=True)
    attrib = _attribuer_port(name, port_n)
    publication = _publication_apres(name, user, nom_public)
    demarrage = None
    if publication.get("publiee") and publication.get("synchronisee") is not False:
        # Publiée = servie : (re)démarrée sur le nouveau code.
        r = _run_ctl("app", "restart", name, timeout=60)
        demarrage = {"ok": r.get("code") == 0, **({"erreur": r["error"]} if r.get("code") else {})}
    log.info("Deployed app: %s (port %s, publication %s)", name, attrib.get("port"), publication)
    reponse = {k: v for k, v in result.items() if k not in ("code", "output")}
    reponse.update({"success": True, "name": name, "port": attrib.get("port"),
                    "port_source": attrib.get("source"), "conteneur_reveille": reveille,
                    "publication": publication, "demarrage": demarrage})
    return reponse


@router.post("/app/{name}/start")
def start_app(name: str, port: int = 0, user=Depends(require_jwt)):
    """Démarre une appli. Sans port : le sien, sinon un port libre (plus jamais `default_port`). Réveille le
    conteneur s'il dort ; une appli publiée voit sa chaîne suivre le port. `def` : hors de la boucle partagée."""
    _exiger_nom_appli(name)
    _exiger_port(port)
    reveille = _reveiller_conteneur(f"le démarrage de « {name} »")
    attrib = _attribuer_port(name, port)
    p = int(attrib["port"])
    _ctl_ok("app", "start", name, str(p), timeout=30)
    log.info("Started app: %s on port %d", name, p)
    return {"success": True, "name": name, "port": p, "port_source": attrib.get("source"),
            "conteneur_reveille": reveille, "publication": _publication_apres(name, user)}


@router.post("/app/{name}/stop")
def stop_app(name: str, user=Depends(require_jwt)):
    """Stop an app."""
    _exiger_nom_appli(name)
    _run_ctl("app", "stop", name)
    log.info("Stopped app: %s", name)
    return {"success": True, "name": name}


@router.delete("/app/{name}")
def delete_app(name: str, user=Depends(require_jwt)):
    """Supprime une appli — après avoir retiré sa publication : jamais un vhost qui pointerait vers une appli
    absente (ou, plus tard, vers celle qui récupérerait son port). Retrait impossible = suppression annulée."""
    _exiger_nom_appli(name)
    retrait = _run_ctl("app", "unpublish", name, "--par", _acteur(user), "--apply", timeout=PUBLICATION_DELAI_S)
    if retrait.get("code") != 0:
        raise HTTPException(_STATUTS_CTL.get(retrait.get("code"), 500),
                            f"suppression annulée, la publication n'a pas pu être retirée : {retrait.get('error')}")
    _ctl_ok("app", "remove", name)
    log.info("Removed app: %s", name)
    return {"success": True, "name": name, "publication_retiree": retrait.get("retires", [])}


@router.get("/publications", dependencies=[Depends(require_lecture)])
def publications_liste():
    """Noms publics et domaines de chaque appli (déclarations `[instances.*]`), et les réglages de publication.
    Lecture gardée comme /apps/vitrine (les domaines publiés y figurent déjà)."""
    texte = _conf_texte()
    dom = domaine_box()
    r = _pub.reglages(texte)
    return {"auto": r["auto"], "autostart": r["autostart"], "domaine": dom,
            "ports": [r["port_min"], r["port_max"]], "apps": _pub.publications(texte, dom)}


@router.post("/app/{name}/publish")
def publish_app(name: str, req: Optional[NomPublic] = None, user=Depends(require_jwt)):
    """Publie l'appli sous `<nom public>.<domaine de la box>` (nom dérivé du dossier si absent), par la chaîne
    déclarative : vhost nginx :9080, route sbxwaf (secubox-waf-route), vhost HAProxy, `[instances.<nom>]`.
    Jamais de contournement du WAF. Réveille le conteneur, attribue un port s'il en faut un, puis la démarre."""
    _exiger_nom_appli(name)
    nom = ((req.public_name if req else "") or "").strip()
    actuelles = _publications_de(name)
    if not nom and not actuelles:
        nom = _pub.label_par_defaut(name)
        if not nom:
            raise HTTPException(400, "nom public requis : le nom du dossier n'en donne aucun de valide")
    if nom:
        _exiger_label(nom)
        if not any(p["nom_public"] == nom for p in actuelles):
            _verifier_nom_libre(nom, name)
    reveille = _reveiller_conteneur(f"la publication de « {name} »")
    attrib = _attribuer_port(name, 0)
    args = ["app", "publish", name] + ([nom] if nom else []) + ["--par", _acteur(user), "--apply"]
    r = _ctl_ok(*args, timeout=PUBLICATION_DELAI_S)
    d = _run_ctl("app", "start", name, str(attrib["port"]), timeout=30)
    return {"success": True, "name": name, "nom_public": r.get("nom_public"), "domaine": r.get("domaine"),
            "evenement": r.get("evenement"), "port": attrib.get("port"), "conteneur_reveille": reveille,
            "avertissements": r.get("avertissements") or [],
            "demarrage": {"ok": d.get("code") == 0, **({"erreur": d["error"]} if d.get("code") else {})}}


@router.post("/app/{name}/rename")
def rename_app(name: str, req: NomPublic, user=Depends(require_jwt)):
    """Change le nom public : le nouveau est posé et l'ancien retiré par le même chemin (nginx, route sbxwaf,
    HAProxy, TOML), chaque changement audité dans /var/log/secubox/audit.log par le ctl."""
    _exiger_nom_appli(name)
    nom = (req.public_name or "").strip()
    _exiger_label(nom)
    actuelles = _publications_de(name)
    if not actuelles:
        raise HTTPException(409, f"« {name} » n'est pas publiée : publiez-la d'abord (action « Publier »)")
    if len(actuelles) > 1:
        raise HTTPException(409, "plusieurs instances publient cette appli : retirez la publication puis "
                                 "republiez-la sous un seul nom")
    if actuelles[0]["nom_public"] != nom:
        _verifier_nom_libre(nom, name)
    reveille = _reveiller_conteneur(f"le renommage de « {name} »")
    r = _ctl_ok("app", "publish", name, nom, "--par", _acteur(user), "--apply", timeout=PUBLICATION_DELAI_S)
    return {"success": True, "name": name, "nom_public": r.get("nom_public"), "domaine": r.get("domaine"),
            "evenement": r.get("evenement"), "ancien": r.get("ancien"), "conteneur_reveille": reveille,
            "avertissements": r.get("avertissements") or []}


@router.post("/app/{name}/unpublish")
def unpublish_app(name: str, user=Depends(require_jwt)):
    """Retire la publication (les quatre maillons) ; l'appli reste déposée et retrouve la mise en veille."""
    _exiger_nom_appli(name)
    r = _ctl_ok("app", "unpublish", name, "--par", _acteur(user), "--apply", timeout=PUBLICATION_DELAI_S)
    return {"success": True, "name": name, "retires": r.get("retires", []),
            "avertissements": r.get("avertissements") or []}


@router.get("/app/{name}/env")
def get_env(name: str, user=Depends(require_jwt)):
    """Les NOMS des variables de l'appli — jamais leurs valeurs."""
    _exiger_nom_appli(name)
    _reveiller_conteneur(f"la lecture de l'environnement de « {name} »")
    r = _ctl_ok("app", "env", name, "list")
    return {"name": name, "cles": r.get("cles", []), "fichier": r.get("fichier")}


@router.put("/app/{name}/env")
def put_env(name: str, req: EnvAppli, user=Depends(require_jwt)):
    """Définit (`vars`) ou retire (`unset`) des variables de l'appli : fichier root 0600 dans le conteneur, lu par
    son unité au prochain démarrage. Les valeurs passent par l'entrée standard du ctl, jamais par son argv."""
    _exiger_nom_appli(name)
    for cle, valeur in req.vars.items():
        err = _pub.erreur_cle_env(cle) or _pub.erreur_valeur_env(valeur)
        if err:
            raise HTTPException(400, err)
    for cle in req.unset:
        err = _pub.erreur_cle_env(cle)
        if err:
            raise HTTPException(400, err)
    _reveiller_conteneur(f"la modification de l'environnement de « {name} »")
    args = (["app", "env", name, "set"] + [x for cle in req.unset for x in ("--unset", cle)]
            + ["--par", _acteur(user), "--apply"])
    r = _ctl_ok(*args, entree="".join(f"{k}={v}\n" for k, v in req.vars.items()))
    return {"success": True, "name": name, "cles": r.get("cles", []),
            "redemarrage_requis": bool(r.get("redemarrage_requis"))}


@router.get("/app/{name}/logs")
async def get_logs(name: str, lines: int = 100, user=Depends(require_jwt)):
    """Get app logs."""
    _exiger_nom_appli(name)
    result = _run_ctl("app", "logs", name, str(lines), brut=True)
    return {"logs": result.get("output", "").splitlines()}


# ── WAKE ───────────────────────────────────────────────────────────────
# Lazy restart an idle-stopped streamlit app (ref #331, budget/blocking
# fix ref #958, restauré après la fusion du 2026-08-17 par #1776).

class WakeResult(BaseModel):
    name: str
    status: str  # "running" (already up) | "waking" (just triggered, or
                 # already in flight — poll POST .../wake again, or the
                 # live GET /apps / GET /app/{name} the wall already
                 # consumes, until "running")
    duration_ms: int  # cost of resolving THIS response (the fast liveness
                       # check below) — never the wake itself, which may
                       # still be running long after this response ships.


# Réveils actuellement en vol, par nom d'appli (#958 follow-up). Même
# motif que le verrou par-module de secubox-waker
# (packages/secubox-profiles/api/waker.py::_locks/_lock) : dédier UN
# réveil à la fois par nom, jamais une seconde tentative concurrente tant
# que la première n'a pas fini — la libération se fait dans le `finally`
# de `_do_wake_in_background`, jamais par le handler HTTP lui-même (qui
# rend la main bien avant que le réveil ne se termine). Un vrai
# `threading.Lock`, pas seulement l'atomicité du GIL sur `set` : la prise
# se fait sur le thread qui sert la requête, la libération sur celui de la
# tâche de fond — deux threads différents touchent le même ensemble.
_wake_claim_mutex = threading.Lock()
_WAKE_IN_PROGRESS: set = set()

# Issue d'un réveil de fond terminé en ÉCHEC, par nom d'appli (#1776) :
# (instant monotone, code HTTP, détail). Rendue UNE fois, au sondage
# suivant du mur — sans elle, le sondage qui suit un échec relancerait
# aussitôt un nouveau réveil voué au même sort, toutes les 5 s jusqu'à la
# limite du mur, et un code 2 de `streamlitctl app wake` (appli inconnue)
# arrivé en fond serait perdu au lieu de devenir le 404 qu'il est. Au-delà
# de WAKE_ECHEC_TTL_S, l'échec est oublié : un clic ultérieur retente.
_WAKE_ECHECS: Dict[str, tuple] = {}
WAKE_ECHEC_TTL_S = 120


def _wake_try_claim(name: str) -> bool:
    """Réclame `name` pour un nouveau réveil en fond, ou refuse si un
    réveil est déjà en vol pour cette appli."""
    with _wake_claim_mutex:
        if name in _WAKE_IN_PROGRESS:
            return False
        _WAKE_IN_PROGRESS.add(name)
        return True


def _wake_release(name: str) -> None:
    with _wake_claim_mutex:
        _WAKE_IN_PROGRESS.discard(name)


def _wake_noter_echec(name: str, code: int, detail: str) -> None:
    with _wake_claim_mutex:
        _WAKE_ECHECS[name] = (time.monotonic(), code, detail)


def _wake_oublier_echec(name: str) -> None:
    with _wake_claim_mutex:
        _WAKE_ECHECS.pop(name, None)


def _wake_prendre_echec(name: str) -> Optional[tuple]:
    """Retire et rend (code, détail) du dernier échec de fond pour `name`
    s'il date de moins de WAKE_ECHEC_TTL_S, sinon None."""
    with _wake_claim_mutex:
        rec = _WAKE_ECHECS.pop(name, None)
    if rec is None or time.monotonic() - rec[0] > WAKE_ECHEC_TTL_S:
        return None
    return rec[1], rec[2]


def _do_wake_in_background(name: str) -> None:
    """Exécute le réveil RÉEL (`streamlitctl app wake <name>`) — jusqu'à
    [wake].budget_seconds (300s par défaut, /etc/secubox/streamlit.toml,
    cf. `cmd_app_wake`) sur une board chargée, mesuré 26 à 78s, parfois
    plus.

    Tourne dans le threadpool que Starlette utilise pour toute
    `BackgroundTasks.add_task` d'une fonction SYNCHRONE (voir son appel
    dans `wake_app` ci-dessous) — jamais sur la boucle d'événements que
    l'agrégateur partage avec ~110 autres modules. C'est la même
    discipline déjà appliquée à `container_install` ci-dessus (`install`,
    jusqu'à 600s, même mécanisme) : un `subprocess.run` synchrone est sans
    risque ICI précisément parce qu'il tourne hors de la boucle
    d'événements.

    AUCUN argument de secondes n'est passé à `streamlitctl app wake` ici :
    le budget vit dans un seul endroit, [wake].budget_seconds, résolu par
    `cmd_app_wake` lui-même. Dupliquer ce nombre ici — même comme timeout
    Python — recréerait exactement le défaut que ce correctif referme :
    deux constantes qui finissent par diverger.

    L'existence reste tranchée par streamlitctl (#959) : son code 2
    (« appli inconnue ») est noté comme un 404, rendu au sondage suivant ;
    tout autre échec comme un 504. L'échec est noté AVANT la libération du
    verrou (`finally`), pour qu'aucun sondage ne se glisse entre les deux et
    ne relance un réveil.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", CTL, "app", "wake", name],
            capture_output=True, check=False,
        )
        if result.returncode == 0:
            log.info("wake: %s woke successfully (background)", name)
            _wake_oublier_echec(name)
            # Capture paresseuse (#958, spec §3.1/§3.5) : SI la vignette
            # est périmée. On n'arrive ici qu'APRÈS un réveil qui vient de
            # réussir pour sa propre raison — jamais un réveil déclenché
            # pour photographier. `_spawn_shotter` rend la main tout de
            # suite : ce thread de fond n'attend jamais les ~240s d'une
            # capture en plus des ~300s déjà passées à réveiller.
            _spawn_shotter(name, force=False)
        elif result.returncode == 2:
            log.warning("wake: %s unknown to streamlitctl (rc=2)", name)
            _wake_noter_echec(name, 404, f"app not found: {name}")
        elif result.returncode == 75:
            # Conteneur endormi que `app wake` n'a pas pu lever (#3247) : un 503 qui dit pourquoi.
            cause = _message_ctl((result.stdout or b"").decode(errors="replace"),
                                 (result.stderr or b"").decode(errors="replace"), 75)
            log.warning("wake: %s — conteneur indisponible : %s", name, cause)
            _wake_noter_echec(name, 503, f"conteneur streamlit indisponible : {cause}")
        else:
            stderr_snippet = (result.stderr or b"").decode(errors="replace")[:200]
            log.warning("wake: %s failed rc=%d stderr=%s", name, result.returncode, stderr_snippet)
            _wake_noter_echec(name, 504, f"wake failed: {stderr_snippet}".strip())
    except OSError as exc:
        log.warning("wake: %s failed to launch: %s", name, exc)
        _wake_noter_echec(name, 502, "streamlitctl injoignable")
    finally:
        _wake_release(name)


@router.post("/apps/{name}/wake", response_model=WakeResult)
def wake_app(name: str, background_tasks: BackgroundTasks, user=Depends(require_jwt)) -> WakeResult:
    """Wake an idle-stopped streamlit app — never blocks on the wake itself.

    `def`, pas `async def` (#1776) : la vérification de vivacité ci-dessous
    lance `sudo streamlitctl app list` (un `lxc-attach ps` pour tout le
    parc). La version perdue le 2026-08-17 l'appelait depuis un handler
    `async def`, donc SUR la boucle d'événements que l'agrégateur partage
    avec ~110 modules — le gel même que #738 avait retiré. En `def`,
    Starlette sert la requête depuis son threadpool.

    The actual wake (`streamlitctl app wake <name>`) can take up to
    [wake].budget_seconds on a loaded board (300s default, measured 26 to
    78s, sometimes more) — this handler never awaits it. It only:

      1. Runs a FAST, BOUNDED liveness check (`streamlitctl app list`
         without the per-app `git describe` enrichment, capped at
         WAKE_CHECK_TIMEOUT_S so the answer always leaves well before
         HAProxy's 30 s idle cut). If the app is already running, returns
         immediately with status="running" — no background task needed.
      2. Otherwise, claims the per-app in-flight lock (`_wake_try_claim`)
         and hands the real wake off to `_do_wake_in_background` via
         `BackgroundTasks` — which Starlette runs in its threadpool, off
         the shared event loop (see that function's docstring) — and
         returns status="waking" immediately.

    A caller polling this same route again for an app still waking gets
    status="waking" again (the lock refuses a second background task);
    once the wake completes, the very next fast liveness check reports
    "running" — or, if the background wake failed, the recorded failure
    is returned once (404 or 504) instead of silently re-triggering.

    Existence is delegated to streamlitctl, never re-derived here (#959 —
    the old `APPS_PATH/{name}` is_dir check 404'd every flat-script app):
    synchronously through `app list` (same `_app_entrypoint`/
    `_scan_running_apps` helpers as `app wake` since #958), and, when that
    list cannot be obtained in time, through `app wake` itself, whose rc=2
    becomes the 404 of the next poll.

    Status codes:
      - 200: status="running" (already up) or "waking" (just triggered, or
        a wake for this app was already in flight)
      - 400: malformed app name (never reaches sudo)
      - 404: app does not exist (per `app list`, or rc=2 of a background
        `app wake`)
      - 502: streamlitctl binary missing / could not be launched
      - 504: the previous background wake failed (returned once)

    Concurrency with `secubox-waker`/`secubox-wakectl` (packages/
    secubox-profiles): that pair wakes a whole MODULE (the secubox-streamlit
    LXC/service itself) on external vhost access, a coarser granularity
    than this route (one app process inside an already-running module).
    """
    _exiger_nom_appli(name)
    if not Path(CTL).exists():
        raise HTTPException(502, "streamlitctl missing")

    start = time.monotonic()
    try:
        apps = _get_apps(enrichir=False, timeout=WAKE_CHECK_TIMEOUT_S, strict=True)
    except RuntimeError as exc:
        # Vivacité inconnue (ctl trop lent ou en échec) : ni 404 ni
        # "running" inventés — l'existence est laissée à `app wake`.
        apps = None
        log.warning("wake: %s liveness check unavailable (%s) — delegating to app wake", name, exc)
    duration_ms = int((time.monotonic() - start) * 1000)

    if apps is not None:
        app_row = next((a for a in apps if isinstance(a, dict) and a.get("name") == name), None)
        if app_row is None:
            _wake_oublier_echec(name)
            raise HTTPException(404, f"app not found: {name}")
        if app_row.get("running"):
            _wake_oublier_echec(name)
            _spawn_shotter(name, force=False)
            return WakeResult(name=name, status="running", duration_ms=duration_ms)

    echec = _wake_prendre_echec(name)
    if echec is not None:
        code, detail = echec
        raise HTTPException(code, detail)

    if not _wake_try_claim(name):
        log.info("wake: %s already in flight, not triggering a second one", name)
        return WakeResult(name=name, status="waking", duration_ms=duration_ms)

    background_tasks.add_task(_do_wake_in_background, name)
    log.info("wake: %s triggered in background, duration_ms=%d (liveness check only)", name, duration_ms)
    return WakeResult(name=name, status="waking", duration_ms=duration_ms)


# ═══════════════════════════════════════════════════════════════════════
# INSTANCES
# ═══════════════════════════════════════════════════════════════════════

@router.get("/instances")
async def list_instances(user=Depends(require_jwt)):
    """List all instances."""
    return {"instances": _get_instances()}


@router.post("/instance/{id}/start")
def start_instance(id: str, user=Depends(require_jwt)):
    """Start an instance — réveille le conteneur s'il dort (#3247) ; l'échec du ctl est rendu, plus masqué."""
    _exiger_nom_appli(id)
    _reveiller_conteneur(f"le démarrage de l'instance « {id} »")
    _ctl_ok("instance", "start", id)
    return {"success": True, "id": id}


@router.post("/instance/{id}/stop")
def stop_instance(id: str, user=Depends(require_jwt)):
    """Stop an instance."""
    _exiger_nom_appli(id)
    _run_ctl("instance", "stop", id)
    return {"success": True, "id": id}


# ═══════════════════════════════════════════════════════════════════════
# CONTAINER CONTROL
# ═══════════════════════════════════════════════════════════════════════

@router.get("/container/status")
async def container_status(user=Depends(require_jwt)):
    """Get LXC container status."""
    if not _cfg()["use_lxc"]:
        return {"enabled": False}

    return {
        "enabled": True,
        "exists": _lxc_exists(),
        "running": _lxc_running()
    }


@router.post("/container/install")
async def container_install(background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Install LXC container (background)."""
    def do_install():
        subprocess.run([CTL, "install"], timeout=600)

    background_tasks.add_task(do_install)
    return {"success": True, "message": "Installation started in background"}


@router.post("/container/start")
async def container_start(user=Depends(require_jwt)):
    """Start LXC container."""
    result = _run_ctl("start", timeout=60)
    return {"success": "error" not in result}


@router.post("/container/stop")
async def container_stop(user=Depends(require_jwt)):
    """Stop LXC container."""
    result = _run_ctl("stop", timeout=60)
    return {"success": "error" not in result}


# ═══════════════════════════════════════════════════════════════════════
# POWER MANAGEMENT (Sleep/Wake)
# ═══════════════════════════════════════════════════════════════════════

POWER_STATE_FILE = Path("/var/lib/secubox/streamlit-power.json")
_last_activity: float = time.time()

def _load_power_state() -> dict:
    """Load power state from file."""
    if POWER_STATE_FILE.exists():
        try:
            return json.loads(POWER_STATE_FILE.read_text())
        except (OSError, ValueError) as exc:
            log.warning("état d'alimentation illisible (%s) : valeurs par défaut", exc)
    return {"state": "running", "paused_at": None, "last_activity": time.time()}

def _save_power_state(state: dict):
    """Save power state to file."""
    POWER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    POWER_STATE_FILE.write_text(json.dumps(state, indent=2))

def _update_activity():
    """Update last activity timestamp."""
    global _last_activity
    _last_activity = time.time()
    state = _load_power_state()
    state["last_activity"] = _last_activity
    _save_power_state(state)

def _get_idle_seconds() -> float:
    """Get seconds since last activity."""
    state = _load_power_state()
    last = state.get("last_activity", time.time())
    return time.time() - last

def _emit_presence_event(event: str, details: Optional[Dict[str, Any]] = None):
    """Emit presence event for banner injection.

    Events: 'wake', 'sleep', 'activity'
    """
    cfg = _cfg()
    event_data = {
        "timestamp": datetime.now().isoformat(),
        "module": "streamlit",
        "event": event,
        "details": details if details is not None else {},
    }

    # Log presence event for banner system
    if cfg.get("presence_events"):
        presence_file = Path("/var/lib/secubox/presence/streamlit.json")
        presence_file.parent.mkdir(parents=True, exist_ok=True)
        presence_file.write_text(json.dumps(event_data, indent=2))
        log.info("Presence event: %s", event)


def _load_streamlit_config() -> dict:
    """Load streamlit config from TOML file."""
    config_path = STREAMLIT_CONF
    if config_path.exists():
        try:
            import tomllib
            with open(config_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            log.warning("Failed to load config: %s", e)
    return {}


def _start_autostart_instances():
    """Start all instances with autostart=true."""
    cfg = _load_streamlit_config()
    if not cfg:
        return []

    started = []
    instances = cfg.get("instances", {})
    for name, inst in instances.items():
        if inst.get("autostart") and inst.get("enabled"):
            port = inst.get("port", 0)
            app = inst.get("app", name)
            if port:
                result = _run_ctl("instance", "start", name, str(port), timeout=30)
                if result.get("success") or "running" in str(result.get("output", "")).lower():
                    started.append({"name": name, "app": app, "port": port})
                    log.info("Autostarted instance: %s on port %s", name, port)
    return started

@router.get("/power/status", dependencies=[Depends(require_lecture)])
async def power_status():
    """Get power state and idle time (public endpoint for dashboard)."""
    state = _load_power_state()
    running = _lxc_running()
    idle_secs = _get_idle_seconds()

    # Determine effective state
    if state.get("state") == "paused" and not running:
        effective_state = "paused"
    elif running:
        effective_state = "running"
    else:
        effective_state = "stopped"

    return {
        "state": effective_state,
        "container_running": running,
        "idle_seconds": int(idle_secs),
        "idle_formatted": _format_duration(int(idle_secs)),
        "paused_at": state.get("paused_at"),
        "auto_pause_enabled": _cfg().get("auto_pause", False),
        "auto_pause_minutes": _cfg().get("auto_pause_minutes", 30)
    }

def _format_duration(seconds: int) -> str:
    """Format seconds to human readable."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"

@router.post("/power/pause")
async def power_pause(user=Depends(require_jwt)):
    """Pause (sleep) the Streamlit container to save resources.

    Container is stopped but state is preserved. Use /power/wake to resume.
    """
    if not _lxc_running():
        return {"success": True, "message": "Already paused/stopped"}

    # Stop the container
    result = _run_ctl("stop", timeout=60)
    if "error" in result:
        raise HTTPException(500, f"Failed to pause: {result.get('error')}")

    # Save paused state
    state = _load_power_state()
    state["state"] = "paused"
    state["paused_at"] = datetime.now().isoformat()
    _save_power_state(state)

    # Emit presence event for banner injection
    _emit_presence_event("sleep", {"idle_seconds": int(_get_idle_seconds())})

    log.info("Streamlit container paused (sleep mode)")
    return {"success": True, "state": "paused"}

def _noter_reveil() -> None:
    """Effets de bord d'un réveil : état d'alimentation + évènement de présence. Ne lève jamais : un fichier
    d'état non inscriptible ne doit pas faire échouer un réveil réussi."""
    try:
        state = _load_power_state()
        paused_duration = None
        if state.get("paused_at"):
            try:
                paused_at = datetime.fromisoformat(state["paused_at"])
                maintenant = datetime.now(paused_at.tzinfo or timezone.utc)
                if paused_at.tzinfo is None:
                    maintenant = maintenant.replace(tzinfo=None)
                paused_duration = int((maintenant - paused_at).total_seconds())
            except (TypeError, ValueError):
                paused_duration = None
        state["state"] = "running"
        state["paused_at"] = None
        _update_activity()
        _save_power_state(state)
        _emit_presence_event("wake", {"paused_duration": paused_duration})
    except OSError as exc:
        log.warning("réveil : état d'alimentation non enregistré (%s)", exc)


def _reveiller_conteneur(motif: str) -> bool:
    """Réveille le conteneur s'il dort — MÊME CHEMIN que POST /power/wake (`streamlitctl start`), borné à
    CONTENEUR_REVEIL_DELAI_S (#3247). Rend True s'il dormait.

    Le dépôt et le démarrage d'une appli échouaient en 500 SANS MESSAGE quand le conteneur était arrêté (gk2,
    2026-10-28 : arrêté après un redémarrage). Désormais : réveil, et s'il échoue, 503 avec la cause réelle ;
    409 si le conteneur n'est même pas installé. Le balayage des instances `autostart` de /power/wake n'est PAS
    rejoué ici : un dépôt ne démarre pas tout le parc (#982)."""
    if not _cfg()["use_lxc"]:
        return False
    if _lxc_running():
        return False
    if not _lxc_exists():
        raise HTTPException(409, f"Conteneur streamlit non installé : installez-le (onglet État → Installer) "
                                 f"avant {motif}.")
    r = _run_ctl("start", timeout=CONTENEUR_REVEIL_DELAI_S)
    if not _lxc_running():
        cause = r.get("error") or "le conteneur ne passe pas en état RUNNING"
        raise HTTPException(503, f"Conteneur streamlit endormi : réveil impossible avant {motif} ({cause}).")
    _noter_reveil()
    log.info("conteneur streamlit réveillé (%s)", motif)
    return True


def _power_wake_sync() -> dict:
    if _lxc_running():
        _update_activity()
        return {"success": True, "message": "Already running"}
    _reveiller_conteneur("le réveil demandé")
    # Start autostart instances (réveil EXPLICITE du module : les instances déclarées `autostart` reviennent).
    autostarted = _start_autostart_instances()
    log.info("Streamlit container woken from sleep, autostarted %d instances", len(autostarted))
    return {"success": True, "state": "running", "autostarted": autostarted}


@router.post("/power/wake")
async def power_wake(user=Depends(require_jwt)):
    """Wake (resume) the Streamlit container from sleep.

    Restarts the container and all previously running apps. Même chemin que le réveil implicite du dépôt et du
    démarrage (`_reveiller_conteneur`) ; 503 avec la cause si le conteneur ne se lève pas (avant : un 500 vide,
    toujours, la sortie non-JSON de `streamlitctl start` portant une clé "error").
    """
    return await asyncio.to_thread(_power_wake_sync)

@router.post("/power/toggle")
async def power_toggle(user=Depends(require_jwt)):
    """Toggle between pause and running states."""
    if _lxc_running():
        return await power_pause(user)
    else:
        return await power_wake(user)


@router.get("/autostart", dependencies=[Depends(require_lecture)])
async def list_autostart():
    """List instances configured for autostart (public)."""
    cfg = _load_streamlit_config()
    if not cfg:
        return {"autostart": [], "vhost_suffix": domaine_box()}

    autostart_list = []
    instances = cfg.get("instances", {})
    for name, inst in instances.items():
        if inst.get("autostart") and inst.get("enabled"):
            autostart_list.append({
                "name": name,
                "app": inst.get("app", name),
                "port": inst.get("port"),
                "domain": inst.get("domain") or hote_box(name),
                "emancipated": inst.get("emancipated", False),
            })

    return {
        "autostart": autostart_list,
        "count": len(autostart_list),
        "vhost_suffix": domaine_box(),  # celui de CETTE box (#1723)
    }


@router.post("/autostart/run")
def run_autostart(user=Depends(require_jwt)):
    """Manually trigger autostart for all configured instances (réveille le conteneur s'il dort, #3247)."""
    _reveiller_conteneur("le démarrage des instances autostart")
    started = _start_autostart_instances()
    return {
        "success": True,
        "started": started,
        "count": len(started),
    }


# ═══════════════════════════════════════════════════════════════════════
# MIGRATION
# ═══════════════════════════════════════════════════════════════════════

class MigrateRequest(BaseModel):
    source: str = "192.168.255.1"


@router.post("/migrate")
async def migrate(req: MigrateRequest, background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Migrate apps from OpenWrt SecuBox."""
    def do_migrate():
        subprocess.run([CTL, "migrate", req.source], timeout=600)

    background_tasks.add_task(do_migrate)
    log.info("Migration started from %s", req.source)
    return {"success": True, "message": f"Migration from {req.source} started"}


# ═══════════════════════════════════════════════════════════════════════
# GITEA INTEGRATION
# ═══════════════════════════════════════════════════════════════════════

@router.post("/gitea/push/{name}")
async def gitea_push(name: str, user=Depends(require_jwt)):
    """Push app to Gitea repository."""
    _exiger_nom_appli(name)
    result = _run_ctl("gitea", "push", name, timeout=60)
    return {"success": "error" not in result, "name": name}


class GiteaCloneRequest(BaseModel):
    repo: str


@router.post("/gitea/clone/{name}")
async def gitea_clone(name: str, req: GiteaCloneRequest, user=Depends(require_jwt)):
    """Clone app from Gitea repository."""
    _exiger_nom_appli(name)
    result = _run_ctl("gitea", "clone", name, req.repo, timeout=120)
    return {"success": "error" not in result, "name": name}


app.include_router(router)
