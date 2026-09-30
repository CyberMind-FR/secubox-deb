# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox Nextcloud API - File Sync & Cloud Storage with LXC"""
import subprocess
import os
import re
import signal
import fcntl
import json
import socket
import time
import threading
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config
from secubox_core.auth import require_lecture
from secubox_core.auth import hote_box

app = FastAPI(title="SecuBox Nextcloud")
config = get_config("nextcloud")


def _public_base_url(ssl_domain: str, domain: str, http_port: int) -> str:
    """Return the URL a client/device uses to reach Nextcloud.

    HAProxy terminates TLS 1.3 in front of every SecuBox vhost, so a real
    public domain is always reachable over https. Precedence: an explicit
    ssl_domain wins; otherwise the configured public ``domain`` (skipping the
    ``cloud.local`` placeholder); only a bare host with no real domain falls
    back to the container port. Never emit ``localhost`` when a domain exists —
    that is unreachable from a phone/desktop client (the bug this fixes).
    """
    if ssl_domain:
        return f"https://{ssl_domain}"
    if "." in domain and domain != "cloud.local":
        return f"https://{domain}"
    return f"http://localhost:{http_port}"


LXC_NAME = config.get("container_name", "nextcloud")
LXC_PATH = Path(config.get("lxc_path", "/data/lxc"))
DATA_PATH = Path(config.get("data_path", "/data/volumes/nextcloud"))
LXC_ROOTFS = LXC_PATH / LXC_NAME / "rootfs"
NC_IP = config.get("lxc_ip", "10.100.0.21")
NC_INTERNAL_PORT = 80

# This API runs UNPRIVILEGED (user `secubox`). Its ONLY privileged surface is
# `sudo nextcloudctl` (see /etc/sudoers.d/secubox-nextcloud) — direct lxc-info /
# lxc-attach / du on /data/lxc all fail with permission errors. So: probe the
# container's port for liveness (privilege-free) and route every container op
# through nextcloudctl (which has an `occ` passthrough and runs as root).
NCTL = ["sudo", "-n", "/usr/sbin/nextcloudctl"]

# Ce que `run_cmd` rend sur stderr quand il a dû tuer le groupe à l'expiration.
EXPIRE = "Command timed out"


def run_cmd(cmd: list, timeout: int = 30, stdin: Optional[str] = None) -> tuple:
    """Run command and return (success, stdout, stderr).

    Le sous-processus tourne dans sa PROPRE session, et l'expiration tue tout
    le groupe.

    Sans cela, `subprocess.run` ne tuait que l'enfant direct — ici `sudo` —
    tandis que la chaine qu'il avait ouverte derriere lui
    (`nextcloudctl` -> `lxc-attach` -> `php occ`) survivait, reparentee a
    l'init du conteneur. Le rafraichisseur de cache lance deux `occ` toutes
    les 60 s : chaque expiration abandonnait donc deux processus PHP, qui
    ralentissaient le conteneur, ce qui provoquait de nouvelles expirations.
    Il s'en est accumule 460, pour une charge machine de 300.

    `stdin` porte ce qui ne doit JAMAIS passer par argv : un mot de passe
    (visible de `ps`, journalisé par sudo) ou la confirmation « yes » d'un
    verbe destructeur (sans elle, le helper lit EOF et abandonne). #1756.
    """
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                text=True, start_new_session=True)
        out, err = proc.communicate(input=stdin, timeout=timeout)
        return proc.returncode == 0, out.strip(), err.strip()
    except subprocess.TimeoutExpired:
        if proc is not None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
        try:
            if proc is not None:
                proc.communicate(timeout=5)
        except Exception:
            pass
        return False, "", EXPIRE
    except Exception as e:
        return False, "", str(e)


def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def lxc_running() -> bool:
    """Privilege-free liveness: the container's web server answers on its port."""
    return _port_open(NC_IP, NC_INTERNAL_PORT)


def lxc_installed() -> bool:
    """Container dir present. As `secubox` we can't traverse /data/lxc, so a
    PermissionError means the path IS there (installed); FileNotFound = not."""
    try:
        return (LXC_PATH / LXC_NAME / "config").exists()
    except PermissionError:
        return True


def nctl(*args, timeout: int = 60, stdin: Optional[str] = None) -> tuple:
    """Run `sudo nextcloudctl <args>` — the only privileged container surface."""
    return run_cmd(NCTL + [str(a) for a in args], timeout, stdin=stdin)


def ctl(subcmd: list, timeout: int = 60, stdin: Optional[str] = None) -> tuple:
    """`nctl` sous forme de liste : le point d'entrée des routes (#1757).

    Même chemin privilégié (`sudo -n nextcloudctl`, groupe tué à
    l'expiration) ; la forme liste est celle des routes de e2f71a500, et
    l'unique point que les tests remplacent."""
    return nctl(*subcmd, timeout=timeout, stdin=stdin)


# Une opération de compte tourne sur le chemin de la requête : HAProxy coupe à
# 30 s d'inactivité, elle doit donc rendre la main avant.
DELAI_REQUETE = 25

# `occ` est à vol unique dans nextcloudctl (flock, a15b71bf4) : quand le
# rafraîchisseur de cache en tient un, le helper sort en 75 (EX_TEMPFAIL) avec
# ce mot sur stderr. C'est « réessayer dans un instant », pas une panne.
OCC_OCCUPE = "single-flight"


def _echec_helper(action: str, err: str, out: str = ""):
    """Traduit l'échec d'un verbe du helper en réponse HTTP (#1757).

    503 : `occ` occupé par un autre appelant — rien n'a été fait, réessayer.
    504 : délai dépassé — le groupe est tué, mais `occ` a pu aboutir dans le
          conteneur : la page recharge la liste pour le savoir.
    500 : le reste, avec le message du helper."""
    if OCC_OCCUPE in (err or "") or OCC_OCCUPE in (out or ""):
        raise HTTPException(503, f"{action}: Nextcloud busy (occ single-flight), retry in a few seconds",
                            headers={"Retry-After": "10"})
    if err == EXPIRE:
        raise HTTPException(504, f"{action}: timed out — it may still complete, reload to check")
    raise HTTPException(500, f"{action} failed: {err or out}")


def _require_running():
    if not lxc_running():
        raise HTTPException(409, "Nextcloud container is not running")


def _json_de_sortie(out: str):
    """Le JSON d'une sortie du helper : toute la sortie, sinon sa dernière ligne
    (un `log` ou un avertissement PHP peut la précéder). None si illisible."""
    texte = (out or "").strip()
    lignes = texte.splitlines()
    for candidat in (texte, lignes[-1] if lignes else ""):
        try:
            return json.loads(candidat)
        except ValueError:
            continue
    return None


# GARDES DE SAISIE (#429, effacées par la fusion aff481735, #1756, #1757) : un
# uid, un quota ou un nom de sauvegarde est validé sur un jeu de caractères sûr
# AVANT d'atteindre argv, un chemin ou le helper root (qui revalide : défense
# en profondeur, cf. _valid_uid / _valid_quota / _valid_backup_name).
# `fullmatch` et non `match` : `$` tolère un saut de ligne final.
_UID_RE = re.compile(r"[A-Za-z0-9._@-]+")
_QUOTA_RE = re.compile(r"(none|default|[0-9]+(\.[0-9]+)?[KMGT]?B?)", re.I)
_BACKUP_RE = re.compile(r"[A-Za-z0-9._-]+")


def _valid_uid(uid: str) -> bool:
    return bool(uid) and bool(_UID_RE.fullmatch(uid))


def _valid_backup_name(name: str) -> bool:
    return bool(name) and bool(_BACKUP_RE.fullmatch(name))


def _mot_de_passe_valide(pwd: str) -> bool:
    # une ligne = un mot de passe : le helper en lit une seule (`read -r`)
    return bool(pwd) and not any(c in pwd for c in "\r\n\0")


def _nom_affiche_valide(nom: str) -> bool:
    # passe dans argv (jamais dans une chaîne de shell) : pas de caractère de
    # contrôle, qui ferait échouer l'appel ou brouillerait le journal de sudo
    return not any(ord(c) < 32 or ord(c) == 127 for c in nom)


def occ_cmd(command: str, timeout: int = 60) -> tuple:
    """OCC passthrough via nextcloudctl (runs as root inside the container)."""
    return nctl("occ", *command.split(), timeout=timeout)


def lxc_attach(command: str, timeout: int = 30) -> tuple:
    """Legacy shim: the only in-container ops the API needs are OCC commands, so
    route them through the nextcloudctl occ passthrough. Non-occ callers were
    already broken under the unprivileged user."""
    return nctl("occ", *command.split(), timeout=timeout)


# Background-refreshed cache for the slow, root-only fields (occ --version,
# occ user:list, container-side du). /status is polled every ~30s by the webui,
# so it must NOT run these inline (each occ call is ~5s and blocks the loop);
# it reads this cache, filled every 60s by _refresh_cache() below.
# `storage` : la dernière mesure servie par /storage (#1757), vide avant la
# première.
_nc_cache = {"version": "", "user_count": 0, "disk_used": "0", "storage": {}, "ts": 0}

# Le stockage se mesure par un `du` sur tout le volume de données : lourd, et
# il bouge lentement. Toutes les 10 min, pas à chaque tour du rafraîchisseur.
INTERVALLE_STOCKAGE = 600


def _mesurer_stockage() -> Optional[dict]:
    """/storage, mesuré DANS le conteneur (`nextcloudctl storage --json` : df
    et du). L'API, non privilégiée, ne voit pas le volume : ses du/df côté
    hôte rendaient 0 (#429). Appelé par le seul rafraîchisseur de fond —
    jamais sur le chemin d'une requête (#1757). None si la mesure échoue."""
    # quatre lxc_attach bornés à 45 s chacun côté conteneur
    ok, out, _ = ctl(["storage", "--json"], timeout=240)
    if not ok:
        return None
    s = _json_de_sortie(out)
    if not isinstance(s, dict):
        return None
    try:
        pct = int(float(s.get("used_pct") or 0))
    except (TypeError, ValueError):
        pct = 0
    return {
        "used": str(s.get("used") or ""),
        "total": str(s.get("total") or ""),
        "used_pct": max(0, min(100, pct)),
        "data": str(s.get("data") or ""),
        "ts": time.time(),
    }


def _compute_nc_cache(precedent: Optional[dict] = None) -> dict:
    prec = precedent or {}
    stockage = prec.get("storage") or {}
    # Le stockage survit à un tour sans mesure (conteneur arrêté, occ en
    # échec) : l'espace occupé ne disparaît pas avec le conteneur.
    out_cache = {"version": "", "user_count": 0, "disk_used": prec.get("disk_used") or "0",
                 "storage": stockage, "ts": time.time()}
    if not lxc_running():
        return out_cache
    ok, out, _ = occ_cmd("--version", timeout=30)
    if ok:
        m = re.search(r'(\d+\.\d+\.\d+)', out)
        if m:
            out_cache["version"] = m.group(1)
    ok, out, _ = occ_cmd("user:list --output=json", timeout=30)
    if ok and out.strip():
        try:
            out_cache["user_count"] = len(json.loads(out.strip().splitlines()[-1]))
        except Exception:
            pass
    # Stockage ET disk_used de /status, d'une seule mesure dans le conteneur.
    # Elle remplace `nextcloudctl status`, qui refaisait un `occ user:list` et
    # un du côté hôte à chaque tour. Pas de mesure si `occ` vient d'échouer :
    # le conteneur est engorgé, le disjoncteur vaut aussi pour elle. Un ÉCHEC
    # compte comme un essai (`essai`) : sinon un du qui expire à 240 s
    # repartirait à chaque tour.
    derniere = max(float(stockage.get("ts") or 0), float(stockage.get("essai") or 0))
    if out_cache["version"] and time.time() - derniere >= INTERVALLE_STOCKAGE:
        mesure = _mesurer_stockage()
        if mesure:
            out_cache["storage"] = mesure
            out_cache["disk_used"] = mesure["data"] or "0"
        else:
            out_cache["storage"] = dict(stockage, essai=time.time())
    return out_cache


INTERVALLE = 60
PLAFOND_ATTENTE = 1800
FICHIER_CACHE = Path("/var/cache/secubox/nextcloud/status.json")
VERROU = Path("/run/secubox/nextcloud-cache.lock")


def _lire_cache_partage() -> Optional[dict]:
    try:
        d = json.loads(FICHIER_CACHE.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _ecrire_cache_partage(d: dict) -> None:
    try:
        FICHIER_CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = FICHIER_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(d))
        os.replace(tmp, FICHIER_CACHE)
    except OSError:
        pass


def _cache_worker():
    """Rafraichit le cache toutes les 60 s, dans un thread demon.

    Deliberement pas une tache de demarrage asyncio : le lifespan d'uvicorn ne
    se declenchait pas de facon fiable ici, et le cache restait vide. Un thread
    demon lance a l'import tourne toujours, et fait son travail bloquant hors
    de la boucle.

    UN SEUL processus rafraichit, garde par un verrou de fichier. Ce module est
    importe par le demon autonome, par l'agregateur ET par le groupe : chacun
    demarrait son propre rafraichisseur, et sept `occ` concurrents partaient
    ainsi toutes les minutes sur une machine qui met plus d'une minute a en
    executer un. Les autres processus se contentent de relire le fichier que le
    detenteur du verrou ecrit — c'est la meme donnee, elle n'a pas a etre
    calculee sept fois.
    """
    global _nc_cache
    verrou = None
    try:
        VERROU.parent.mkdir(parents=True, exist_ok=True)
        verrou = open(VERROU, "w")
        fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
        maitre = True
    except (OSError, BlockingIOError):
        maitre = False

    # Disjoncteur. Un sondeur de fond qui reinterroge sans fin un service
    # engorge l'engorge davantage : chaque cycle ajoutait trois `occ` a un
    # conteneur qui ne finissait deja plus les precedents. On espace donc les
    # tentatives apres chaque echec, jusqu'a une demi-heure, et on revient au
    # rythme normal des que la mesure reussit.
    attente = INTERVALLE
    echecs = 0

    while True:
        try:
            if maitre:
                mesure = _compute_nc_cache(_nc_cache)
                # Une version vide alors que le conteneur repond signale un
                # `occ` qui n'aboutit pas : c'est un echec, pas une mesure.
                rate = mesure.get("version") == "" and lxc_running()
                if rate:
                    echecs += 1
                    attente = min(INTERVALLE * (2 ** echecs), PLAFOND_ATTENTE)
                    mesure["indisponible"] = True
                    mesure["prochain_essai_dans"] = attente
                else:
                    echecs = 0
                    attente = INTERVALLE
                _nc_cache = mesure
                _ecrire_cache_partage(_nc_cache)
            else:
                partage = _lire_cache_partage()
                if partage:
                    _nc_cache = partage
                elif verrou is not None:
                    # Le detenteur a disparu : on tente de reprendre la main,
                    # sinon plus personne ne mesurerait rien.
                    try:
                        fcntl.flock(verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        maitre = True
                    except (OSError, BlockingIOError):
                        pass
        except Exception:
            pass
        time.sleep(attente if maitre else INTERVALLE)


threading.Thread(target=_cache_worker, daemon=True, name="nc-cache").start()


# Public endpoints
#
# `def` et non `async def` pour tout gestionnaire qui touche une socket, un
# sous-processus ou le disque (f703692b7, #1757) : FastAPI le passe alors au
# pool de threads. En `async def`, la sonde de port (jusqu'à 1,5 s) ou un
# `sudo nextcloudctl` gelait la boucle de l'agrégateur entier, donc tous les
# modules qu'il sert. Seuls les gestionnaires purs restent `async`.
@app.get("/status", dependencies=[Depends(require_lecture)])
def status():
    """Get Nextcloud service status (fast: live port probe + cached occ fields)."""
    running = lxc_running()
    installed = lxc_installed()

    c = _nc_cache
    version = c.get("version", "") if running else ""
    user_count = c.get("user_count", 0) if running else 0
    disk_used = c.get("disk_used") or "0"

    http_port = config.get("http_port", 8080)
    domain = config.get("domain") or hote_box("nc") or "cloud.local"  # #1723

    return {
        "module": "nextcloud",
        "enabled": config.get("enabled", True),
        "running": running,
        # La page n'affiche « running » qu'avec `reachable` ; sans lui, c'était
        # « running (unreachable) » à vie (#1757). L'API, non privilégiée, juge
        # la marche du conteneur PAR la réponse de son port : les deux
        # coïncident.
        "reachable": running,
        "installed": installed,
        "version": version,
        "http_port": http_port,
        "data_path": str(DATA_PATH),
        "domain": domain,
        "user_count": user_count,
        "disk_used": disk_used,
        # Public URL from the real domain (not localhost) so the dashboard links
        # somewhere reachable; falls back to the container port for a bare host.
        "web_url": _public_base_url(config.get("ssl_domain", ""), domain, http_port),
        "ssl_enabled": config.get("ssl_enabled", False),
        "container_name": LXC_NAME,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "module": "nextcloud"}


# Protected endpoints
@app.get("/config", dependencies=[Depends(require_jwt)])
def get_config_endpoint():
    """Get Nextcloud configuration"""
    return {
        "enabled": config.get("enabled", True),
        "http_port": config.get("http_port", 8080),
        "data_path": str(DATA_PATH),
        "domain": config.get("domain") or hote_box("nc") or "cloud.local",
        "admin_user": config.get("admin_user", "admin"),
        "memory_limit": config.get("memory_limit", "1G"),
        "upload_max": config.get("upload_max", "512M"),
        "redis_enabled": config.get("redis_enabled", True),
        "ssl_enabled": config.get("ssl_enabled", False),
        "ssl_domain": config.get("ssl_domain", ""),
        "backup_enabled": config.get("backup_enabled", True),
        "backup_keep": config.get("backup_keep", 7),
    }


class ConfigUpdate(BaseModel):
    http_port: Optional[int] = None
    domain: Optional[str] = None
    memory_limit: Optional[str] = None
    upload_max: Optional[str] = None


@app.post("/config", dependencies=[Depends(require_jwt)])
async def save_config(update: ConfigUpdate):
    """Save Nextcloud configuration"""
    return {"success": True, "message": "Configuration saved"}


@app.post("/start", dependencies=[Depends(require_jwt)])
def start_service():
    """Start Nextcloud container"""
    if lxc_running():
        raise HTTPException(400, "Service is already running")
    if not lxc_installed():
        raise HTTPException(400, "Container not installed")

    success, _, err = ctl(["start"])
    if success:
        return {"success": True, "message": "Service started"}
    raise HTTPException(500, f"Failed to start: {err}")


@app.post("/stop", dependencies=[Depends(require_jwt)])
def stop_service():
    """Stop Nextcloud container"""
    if not lxc_running():
        raise HTTPException(400, "Service is not running")

    success, _, err = ctl(["stop"])
    if success:
        return {"success": True, "message": "Service stopped"}
    raise HTTPException(500, f"Failed to stop: {err}")


@app.post("/restart", dependencies=[Depends(require_jwt)])
def restart_service():
    """Restart Nextcloud container"""
    success, _, err = ctl(["restart"])
    if success:
        return {"success": True, "message": "Service restarted"}
    raise HTTPException(500, f"Restart failed: {err}")


@app.post("/install", dependencies=[Depends(require_jwt)])
def install():
    """Install Nextcloud (background)"""
    if lxc_installed():
        raise HTTPException(400, "Already installed")

    subprocess.Popen(
        [*NCTL, "install"],
        stdout=open("/var/log/nextcloud-install.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {
        "success": True,
        "message": "Installation started in background",
        "log_file": "/var/log/nextcloud-install.log"
    }


@app.post("/uninstall", dependencies=[Depends(require_jwt)])
def uninstall():
    """Uninstall Nextcloud (preserves data). `nextcloudctl uninstall` demande
    « yes » sur stdin : sans réponse il lisait EOF et abandonnait, et la route
    rendait toujours 500 (2632596b6, #1756)."""
    success, out, err = ctl(["uninstall"], timeout=120, stdin="yes\n")
    if success:
        return {"success": True, "message": "Uninstalled (data preserved)"}
    raise HTTPException(500, f"Uninstall failed: {err or out}")


@app.post("/update", dependencies=[Depends(require_jwt)])
def update():
    """Update Nextcloud"""
    subprocess.Popen(
        [*NCTL, "update"],
        stdout=open("/var/log/nextcloud-update.log", "w"),
        stderr=subprocess.STDOUT
    )
    return {"success": True, "message": "Update started in background"}


# ---------------------------------------------------------------------------
# Comptes (e2f71a500, 79aac6487 — effacés par la fusion aff481735, #1757)
# ---------------------------------------------------------------------------
# Tout passe par `nextcloudctl user …` : jamais d'`occ` construit ici, jamais
# de mot de passe dans argv (stdin seulement), uid et quota validés avant
# d'atteindre le helper, 409 si le conteneur est arrêté.

def _normaliser_comptes(data) -> list:
    """Ramène la sortie de `nextcloudctl user list` aux lignes de la page.

    `occ user:list --info` rend {uid: {display_name, enabled, quota,
    last_seen, email, …}} ; le repli sans --info rend {uid: nom affiché}."""
    if isinstance(data, dict):
        comptes = []
        for uid, v in data.items():
            if isinstance(v, dict):
                comptes.append({
                    "uid": str(uid),
                    "displayname": v.get("display_name") or v.get("displayname") or str(uid),
                    "enabled": bool(v.get("enabled", True)),
                    "quota": v.get("quota") or "",
                    "last_seen": v.get("last_seen") or "",
                    "email": v.get("email") or "",
                })
            else:
                comptes.append({"uid": str(uid), "displayname": v or str(uid),
                                "enabled": True, "quota": ""})
        return comptes
    if isinstance(data, list):
        return [u for u in data if isinstance(u, dict)]
    return []


@app.get("/users", dependencies=[Depends(require_jwt)])
def list_users():
    """Comptes Nextcloud détaillés : uid, nom affiché, actif, quota (79aac6487)."""
    if not lxc_running():
        return {"users": []}
    ok, out, err = ctl(["user", "list"], timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("user list", err, out)
    return {"users": _normaliser_comptes(_json_de_sortie(out))}


class NewUser(BaseModel):
    uid: str
    display_name: str = ""
    password: str


class QuotaReq(BaseModel):
    quota: str


class ResetPassword(BaseModel):
    uid: str
    password: str


@app.post("/user", dependencies=[Depends(require_jwt)])
def create_user(req: NewUser):
    """Crée un compte. Le mot de passe va sur l'entrée standard de
    `nextcloudctl user add` — jamais dans argv (visible de `ps`, journalisé
    par sudo)."""
    if not _valid_uid(req.uid):
        raise HTTPException(400, "invalid uid")
    if not _mot_de_passe_valide(req.password):
        raise HTTPException(400, "invalid password")
    if not _nom_affiche_valide(req.display_name):
        raise HTTPException(400, "invalid display name")
    _require_running()
    ok, out, err = ctl(["user", "add", req.uid, req.display_name or req.uid],
                       stdin=req.password + "\n", timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("create", err, out)
    return {"success": True, "message": f"User {req.uid} created"}


@app.post("/user/password", dependencies=[Depends(require_jwt)])
def reset_password(req: ResetPassword):
    """Réinitialise le mot de passe d'un compte Nextcloud (09e1884fb, #1756).

    Le mot de passe ne voyage QUE par stdin (`nextcloudctl user setpass`).
    La version écrasée par la fusion aff481735 le collait dans
    `OC_PASS='…'` d'une chaîne passée à `sh -c` root du conteneur : visible de
    `ps` et du journal de sudo, et une apostrophe dans le mot de passe ou l'uid
    y faisait exécuter du code. Elle échouait de toute façon (`occ su`
    n'existe pas) — chaque nouvel essai refuitait le mot de passe."""
    if not lxc_running():
        raise HTTPException(409, "Nextcloud container is not running")
    if not _valid_uid(req.uid):
        raise HTTPException(400, "invalid uid")
    if not _mot_de_passe_valide(req.password):
        raise HTTPException(400, "invalid password")
    ok, out, err = ctl(["user", "setpass", req.uid], stdin=req.password + "\n",
                       timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("password reset", err, out)
    return {"success": True, "message": f"Password reset for {req.uid}"}


@app.delete("/user/{uid}", dependencies=[Depends(require_jwt)])
def delete_user(uid: str):
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    _require_running()
    ok, out, err = ctl(["user", "del", uid], timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("delete", err, out)
    return {"success": True}


def _basculer_compte(uid: str, verbe: str) -> dict:
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    _require_running()
    ok, out, err = ctl(["user", verbe, uid], timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper(verbe, err, out)
    return {"success": True}


@app.post("/user/{uid}/enable", dependencies=[Depends(require_jwt)])
def enable_user(uid: str):
    return _basculer_compte(uid, "enable")


@app.post("/user/{uid}/disable", dependencies=[Depends(require_jwt)])
def disable_user(uid: str):
    return _basculer_compte(uid, "disable")


@app.post("/user/{uid}/quota", dependencies=[Depends(require_jwt)])
def set_quota(uid: str, req: QuotaReq):
    if not _valid_uid(uid):
        raise HTTPException(400, "invalid uid")
    if not _QUOTA_RE.fullmatch(req.quota or ""):
        raise HTTPException(400, "invalid quota")
    _require_running()
    ok, out, err = ctl(["user", "quota", uid, req.quota], timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("quota", err, out)
    return {"success": True}


@app.get("/storage", dependencies=[Depends(require_jwt)])
def get_storage():
    """Stockage du conteneur, dans le schéma de la page (used, total,
    used_pct, data). Sert la DERNIÈRE MESURE du rafraîchisseur de fond
    (`_mesurer_stockage`, toutes les 10 min) : un du sur le volume à chaque
    requête, c'était l'orage que le cache a éteint (#1757). `ts` = 0 tant
    qu'aucune mesure n'a abouti."""
    s = _nc_cache.get("storage") or {}
    return {
        "used": s.get("used", ""),
        "total": s.get("total", ""),
        "used_pct": s.get("used_pct", 0),
        "data": s.get("data", ""),
        "ts": s.get("ts", 0),
    }


# ---------------------------------------------------------------------------
# Sauvegardes : ce que nextcloudctl écrit, c'est backups/nextcloud_<nom>.tar.gz
# (cmd_backup). La liste, la suppression et la restauration parlent du même
# fichier, par son nom (#1757).
# ---------------------------------------------------------------------------
PREFIXE_SAUVEGARDE = "nextcloud_"
SUFFIXE_SAUVEGARDE = ".tar.gz"


def _fichier_sauvegarde(name: str) -> Path:
    return DATA_PATH / "backups" / f"{PREFIXE_SAUVEGARDE}{name}{SUFFIXE_SAUVEGARDE}"


@app.get("/backups", dependencies=[Depends(require_jwt)])
def list_backups():
    """List available backups"""
    backups = []
    try:
        fichiers = list((DATA_PATH / "backups").glob(f"{PREFIXE_SAUVEGARDE}*{SUFFIXE_SAUVEGARDE}"))
    except OSError:
        fichiers = []
    for f in fichiers:
        name = f.name[len(PREFIXE_SAUVEGARDE):-len(SUFFIXE_SAUVEGARDE)]
        if not _valid_backup_name(name):
            continue  # ni supprimable ni restaurable par l'API : on ne le propose pas
        try:
            st = f.stat()
        except OSError:
            continue
        backups.append({
            "name": name,
            "size": f"{st.st_size // 1024 // 1024}M",
            "timestamp": int(st.st_mtime),
        })

    return {"backups": sorted(backups, key=lambda x: x["timestamp"], reverse=True)}


class BackupRequest(BaseModel):
    name: Optional[str] = None


@app.post("/backup", dependencies=[Depends(require_jwt)])
def create_backup(req: Optional[BackupRequest] = None):
    """Create a backup. Corps facultatif : la page poste sans corps, et un
    modèle obligatoire lui rendait 422 (#1757)."""
    name = req.name if req else None
    if name and not _valid_backup_name(name):
        raise HTTPException(400, "invalid backup name")
    sub = ["backup"]
    if name:
        sub.append(name)

    success, out, err = ctl(sub, timeout=300)
    if success:
        return {"success": True, "message": "Backup created"}
    raise HTTPException(500, f"Backup failed: {err or out}")


@app.delete("/backup/{name}", dependencies=[Depends(require_jwt)])
def delete_backup(name: str):
    """Supprime une sauvegarde par `nextcloudctl backup-delete <nom>` (#1757).

    L'ancienne route déliait `<nom>-db.sql` / `<nom>-data.tar.gz`, que le
    helper n'écrit pas — et l'API, en `secubox`, ne peut de toute façon rien
    délier dans le répertoire de root."""
    if not _valid_backup_name(name):
        raise HTTPException(400, "invalid backup name")
    try:
        if not _fichier_sauvegarde(name).exists():
            raise HTTPException(404, f"Backup {name} not found")
    except PermissionError:
        pass  # répertoire illisible pour nous : le helper tranchera
    ok, out, err = ctl(["backup-delete", name], timeout=DELAI_REQUETE)
    if not ok:
        _echec_helper("backup delete", err, out)
    return {"success": True, "message": f"Backup {name} deleted"}


@app.post("/restore/{name}", dependencies=[Depends(require_jwt)])
def restore_backup(name: str):
    """Restore from backup (en arrière-plan). Nom validé, et le « yes » de
    confirmation fourni : sans lui le helper abandonnait en silence (#1756)."""
    if not _valid_backup_name(name):
        raise HTTPException(400, "invalid backup name")
    proc = subprocess.Popen(
        [*NCTL, "restore", name],
        stdin=subprocess.PIPE,
        stdout=open("/var/log/nextcloud-restore.log", "w"),
        stderr=subprocess.STDOUT,
        text=True, start_new_session=True,
    )
    try:
        proc.stdin.write("yes\n")
        proc.stdin.close()
    except OSError:
        pass
    return {"success": True, "message": "Restore started in background"}


@app.get("/connections", dependencies=[Depends(require_jwt)])
def get_connections():
    """Get connection URLs (CalDAV, CardDAV, WebDAV)"""
    http_port = config.get("http_port", 8080)
    domain = config.get("domain") or hote_box("nc") or "cloud.local"  # #1723
    ssl_domain = config.get("ssl_domain", "")

    base_url = _public_base_url(ssl_domain, domain, http_port)

    return {
        "base_url": base_url,
        "caldav": f"{base_url}/remote.php/dav/calendars/<username>/",
        "carddav": f"{base_url}/remote.php/dav/addressbooks/users/<username>/contacts/",
        "webdav": f"{base_url}/remote.php/dav/files/<username>/",
        "davx5_url": f"{base_url}/remote.php/dav",
        "desktop_url": base_url,
        "ios_app": "https://apps.apple.com/app/nextcloud/id1125420102",
        "android_app": "https://play.google.com/store/apps/details?id=com.nextcloud.client"
    }


class OccCommand(BaseModel):
    command: str


@app.post("/occ", dependencies=[Depends(require_jwt)])
def run_occ(req: OccCommand):
    """Run OCC command"""
    if not lxc_running():
        raise HTTPException(400, "Container not running")

    success, out, err = occ_cmd(req.command, timeout=120)
    if success:
        return {"success": True, "output": out}
    raise HTTPException(500, f"Command failed: {err}")


@app.get("/logs", dependencies=[Depends(require_jwt)])
def get_logs(lines: int = 100):
    """Get Nextcloud logs"""
    logs = []

    # Installation log
    install_log = Path("/var/log/nextcloud-install.log")
    if install_log.exists():
        success, out, _ = run_cmd(["tail", f"-n{lines}", str(install_log)])
        if success:
            logs.extend(out.split("\n"))

    return {"logs": logs}


class SSLEnable(BaseModel):
    domain: str


@app.post("/ssl/enable", dependencies=[Depends(require_jwt)])
def ssl_enable(req: SSLEnable):
    """Enable SSL for domain"""
    success, _, err = ctl(["ssl-enable", req.domain])
    if success:
        return {"success": True, "message": f"SSL enabled for {req.domain}"}
    raise HTTPException(500, f"SSL enable failed: {err}")


@app.post("/ssl/disable", dependencies=[Depends(require_jwt)])
def ssl_disable():
    """Disable SSL"""
    success, _, err = ctl(["ssl-disable"])
    if success:
        return {"success": True, "message": "SSL disabled"}
    raise HTTPException(500, f"SSL disable failed: {err}")
