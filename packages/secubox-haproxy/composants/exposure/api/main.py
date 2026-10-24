# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Exposure Manager API
Service exposure management - Tor, SSL, DNS, Mesh

Enhanced features:
- Multi-channel exposure tracking with status sync
- Health checking for exposed services
- Automatic SSL certificate management (ACME integration)
- Mesh publishing with peer sync
- Exposure history and audit logging
- QoS policies for exposed services
- Scheduled health checks with alerts
"""

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from pathlib import Path
from datetime import datetime, timedelta, timezone
from enum import Enum
import subprocess
import os
import json
import re
import asyncio
import threading
import httpx

# Import shared auth
import sys
sys.path.insert(0, '/usr/lib/secubox/core')
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "dev"}

from api import reach as _reach
from api import exclusion as _excl
# Top-level (not lazy, unlike the other mesh_egress call sites below) so
# emancipate_webui's federation call resolves the module-global at call time
# and tests can monkeypatch it directly as `main._publish`.
from api.mesh_egress import _publish
from secubox_core.auth import require_lecture

app = FastAPI(title="SecuBox Exposure Manager API", version="2.0.0")

# Configuration
TOR_DATA = Path("/var/lib/tor/hidden_services")
TOR_CONFIG = Path("/etc/tor/torrc")
# Un fichier par service onion, dans le répertoire que le torrc de Debian inclut (`%include /etc/tor/torrc.d/*.conf`).
# Le torrc lui-même n'est plus réécrit (#2050) ; les services posés avant ce changement y restent lisibles.
TOR_DROPIN_DIR = Path("/etc/tor/torrc.d")
# ONIONS (#3112, #3123). Tout service onion livre au frontal HAProxy `onion-in` (127.0.0.1:9180, généré par
# haproxyctl), jamais directement à nginx :9080 ni au frontal public http-in :80 : là, chaque visiteur Tor
# arrivait de 127.0.0.1 et nginx le classait LAN. Le frontal refuse tout Host qui n'est pas en .onion, efface
# l'adresse annoncée par le client, pose le marqueur NON LAN 192.0.2.80 (« client onion ») et passe par sbxwaf,
# qui route le Host <onion>.onion — la route de l'onion du webui (vers nginx :9080) est posée ici.
HAPROXY_TOML = Path("/etc/secubox/haproxy.toml")
ONION_IN_PORT_DEFAUT = 9180
WEBUI_NGINX_PORT = 9080
# Entrées HTTP directes de la box, jamais cibles d'un onion : nginx (9080) et le frontal public http-in (80).
PORTS_HTTP_DIRECTS = (80, WEBUI_NGINX_PORT)
# Répertoire de repli de metablogizerctl pour ses services onion (quand l'API d'exposition est absente).
TOR_METABLOG_DIR = Path("/etc/tor/secubox-metablogizer.d")
WAF_ROUTE_CMD = "secubox-waf-route"
CONFIG_FILE = Path("/etc/secubox/exposure.json")
DATA_DIR = Path("/var/lib/secubox/exposure")
HISTORY_FILE = DATA_DIR / "history.json"
HEALTH_FILE = DATA_DIR / "health_status.json"
WEBHOOKS_FILE = DATA_DIR / "webhooks.json"

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Health check interval (seconds)
HEALTH_CHECK_INTERVAL = 300


class ExposureChannel(str, Enum):
    TOR = "tor"
    DNS = "dns"
    MESH = "mesh"
    SSL = "ssl"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ExposureHistoryEntry(BaseModel):
    timestamp: str
    action: str  # emancipate, revoke, update, health_change
    service: str
    channels: List[str]
    user: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class ServiceHealth(BaseModel):
    service: str
    status: HealthStatus
    last_check: str
    response_time_ms: Optional[float] = None
    error: Optional[str] = None
    channels: Dict[str, HealthStatus] = {}


class WebhookConfig(BaseModel):
    url: str
    events: List[str] = ["health_change", "exposure_change"]
    enabled: bool = True
    secret: Optional[str] = None


DEFAULT_CONFIG = {
    "known_services": [],
    "emancipated": [],
    "health_check_enabled": True,
    "health_check_interval": 300
}


# ============================================================================
# Per-vhost exposure switch (localhost / lan / wan) — ref #793
# ============================================================================

class ExposureSet(BaseModel):
    reach: Literal["localhost", "lan", "wan"]
    mesh: bool = False
    tor: bool = False


_VHOST_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_vhost(vhost: str) -> None:
    """Reject anything that isn't a plausible hostname. Defense-in-depth: Starlette
    already blocks '/' in a single path segment; this additionally rejects
    whitespace, empty strings, '..' traversal markers, and over-long names, so a
    crafted {vhost} can't be used to write a snippet outside intent."""
    if (not vhost or len(vhost) > 253 or ".." in vhost
            or not _VHOST_RE.match(vhost)):
        raise HTTPException(status_code=400, detail="invalid vhost")


def _reload_nginx() -> bool:
    """nginx -t then reload. Returns True on success (fail-safe: no raise)."""
    try:
        if subprocess.run(["nginx", "-t"], capture_output=True, timeout=10).returncode != 0:
            return False
        subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, timeout=15)
        return True
    except Exception:
        return False


_AUDIT_LOG = Path("/var/log/secubox/audit.log")


def _audit_write(line: str) -> None:
    """Append-only CSPN audit trail. Shared by every exposure audit call site
    so the log format/location stays single-sourced. Best-effort: an audit
    write failure must never fail the (already-applied) exposure change."""
    try:
        _AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _AUDIT_LOG.open("a") as f:
            f.write(line)
    except OSError:
        pass


def _audit_exposure(vhost: str, rec: dict, user: str) -> None:
    _audit_write(f"{datetime.now(timezone.utc).isoformat()} exposure {vhost} "
                 f"reach={rec['reach']} mesh={rec['mesh']} tor={rec['tor']} by={user}\n")


def _audit_exposure_action(action: str, detail: str, user: str) -> None:
    """Generic audit entry for exposure actions that aren't a per-vhost reach
    change (e.g. emancipating the admin webui itself as a hidden service)."""
    _audit_write(f"{datetime.now(timezone.utc).isoformat()} exposure action={action} "
                 f"{detail} by={user}\n")


@app.get("/exposure/{vhost}")
async def get_exposure(vhost: str, user: dict = Depends(require_jwt)):
    _validate_vhost(vhost)
    # is_public_now no longer affects the missing-snippet result (see reach.load_record):
    # ungated == effectively public → 'wan'. Kept for API compatibility.
    return _reach.load_record(vhost, is_public_now=False)


@app.post("/exposure/{vhost}")
async def set_exposure(vhost: str, body: ExposureSet, user: dict = Depends(require_jwt)):
    _validate_vhost(vhost)
    p = _reach.snippet_path(vhost)
    try:
        prev = p.read_text()                    # last-good content (may not exist)
    except OSError:
        prev = None
    _reach.write_snippet(vhost, body.reach, body.mesh)
    if not await asyncio.to_thread(_reload_nginx):   # nginx -t failed → roll back
        try:
            if prev is not None:
                p.write_text(prev)
            else:
                p.unlink(missing_ok=True)
        finally:
            await asyncio.to_thread(_reload_nginx)   # best-effort restore of last-good
        raise HTTPException(status_code=500,
                             detail="nginx validation failed; exposure unchanged")
    # nginx reloaded OK — reach is applied. Tor is HARD-REFUSED for cert-pinned /
    # MITM-bypassed hosts (shared toolbox exclusion list — Filtres MITM + splice +
    # autolearn): never anonymously re-expose an endpoint that clients pin.
    if body.tor:
        excluded, why = _excl.exclusion_reason(vhost)
        if excluded:
            rec = {"vhost": vhost, "reach": body.reach, "mesh": body.mesh, "tor": False}
            _audit_exposure(vhost, rec, user.get("sub", "?"))
            raise HTTPException(
                status_code=400,
                detail=f"Tor refusé pour {vhost} : domaine exclu — {why}. "
                       f"Reach '{body.reach}' appliqué.")
    # not excluded — now apply Tor, then audit the confirmed change.
    await _apply_tor(vhost, body.tor, user)
    rec = {"vhost": vhost, "reach": body.reach, "mesh": body.mesh, "tor": body.tor}
    _audit_exposure(vhost, rec, user.get("sub", "?"))
    return rec


# ============================================================================
# History Management
# ============================================================================

def load_history() -> List[Dict]:
    """Load exposure history."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_history(history: List[Dict]):
    """Save exposure history."""
    # Keep last 1000 entries
    history = history[-1000:]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def add_history_entry(entry: ExposureHistoryEntry):
    """Add entry to exposure history."""
    history = load_history()
    history.append(entry.dict())
    save_history(history)


# ============================================================================
# Health Status Management
# ============================================================================

_health_status: Dict[str, ServiceHealth] = {}
_health_lock = threading.Lock()


def load_health_status() -> Dict[str, ServiceHealth]:
    """Load health status from file."""
    global _health_status
    if HEALTH_FILE.exists():
        try:
            with open(HEALTH_FILE) as f:
                data = json.load(f)
                _health_status = {k: ServiceHealth(**v) for k, v in data.items()}
        except Exception:
            pass
    return _health_status


def save_health_status():
    """Save health status to file."""
    with _health_lock:
        try:
            with open(HEALTH_FILE, 'w') as f:
                json.dump({k: v.dict() for k, v in _health_status.items()}, f, indent=2)
        except Exception:
            pass


def update_health(service: str, health: ServiceHealth):
    """Update service health status."""
    global _health_status
    with _health_lock:
        old_status = _health_status.get(service)
        _health_status[service] = health

        # Check for status change
        if old_status and old_status.status != health.status:
            return True  # Status changed
    return False


# ============================================================================
# Webhook Notifications
# ============================================================================

def load_webhooks() -> List[WebhookConfig]:
    """Load webhook configurations."""
    if WEBHOOKS_FILE.exists():
        try:
            with open(WEBHOOKS_FILE) as f:
                return [WebhookConfig(**wh) for wh in json.load(f)]
        except Exception:
            pass
    return []


def save_webhooks(webhooks: List[WebhookConfig]):
    """Save webhook configurations."""
    try:
        with open(WEBHOOKS_FILE, 'w') as f:
            json.dump([wh.dict() for wh in webhooks], f, indent=2)
    except Exception:
        pass


async def send_webhook(event: str, data: Dict[str, Any]):
    """Send webhook notification."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if not wh.enabled or event not in wh.events:
            continue

        payload = {
            "event": event,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "data": data
        }

        try:
            headers = {"Content-Type": "application/json"}
            if wh.secret:
                import hashlib, hmac
                sig = hmac.new(wh.secret.encode(), json.dumps(payload).encode(), hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = sig

            async with httpx.AsyncClient() as client:
                await client.post(wh.url, json=payload, headers=headers, timeout=5.0)
        except Exception:
            pass


# ============================================================================
# Health Checking
# ============================================================================

async def check_service_health(service: str, port: int, channels: List[str]) -> ServiceHealth:
    """Check health of an exposed service."""
    health = ServiceHealth(
        service=service,
        status=HealthStatus.UNKNOWN,
        last_check=datetime.utcnow().isoformat() + "Z"
    )

    channel_health = {}

    # Check local port
    start_time = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection('127.0.0.1', port),
            timeout=5.0
        )
        writer.close()
        await writer.wait_closed()
        health.response_time_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        channel_health["local"] = HealthStatus.HEALTHY
    except Exception as e:
        health.error = str(e)
        channel_health["local"] = HealthStatus.UNHEALTHY

    # Check Tor if enabled
    if "tor" in channels:
        config = load_config()
        for svc in config.get("emancipated", []):
            if svc.get("name") == service and svc.get("onion"):
                # Just check if Tor service is running for now
                try:
                    result = subprocess.run(["pgrep", "tor"], capture_output=True, timeout=5)
                    if result.returncode == 0:
                        channel_health["tor"] = HealthStatus.HEALTHY
                    else:
                        channel_health["tor"] = HealthStatus.UNHEALTHY
                except Exception:
                    channel_health["tor"] = HealthStatus.UNKNOWN

    # Determine overall status
    if all(s == HealthStatus.HEALTHY for s in channel_health.values()):
        health.status = HealthStatus.HEALTHY
    elif all(s == HealthStatus.UNHEALTHY for s in channel_health.values()):
        health.status = HealthStatus.UNHEALTHY
    elif any(s == HealthStatus.HEALTHY for s in channel_health.values()):
        health.status = HealthStatus.DEGRADED
    else:
        health.status = HealthStatus.UNKNOWN

    health.channels = channel_health
    return health


# Models
class TorAddRequest(BaseModel):
    service: str
    # #3112 : None ⇒ le frontal onion-in ; toute autre valeur que son port est refusée par /tor/add.
    local_port: Optional[int] = None
    onion_port: int = 80


class TorRemoveRequest(BaseModel):
    service: str


class SslAddRequest(BaseModel):
    service: str
    domain: str
    local_port: int = 80


class SslRemoveRequest(BaseModel):
    service: str


class EmancipateRequest(BaseModel):
    service: str
    port: int
    domain: Optional[str] = None
    tor: bool = False
    dns: bool = False
    mesh: bool = False


class RevokeRequest(BaseModel):
    service: str
    tor: bool = False
    dns: bool = False
    mesh: bool = False


class FixPortRequest(BaseModel):
    service: str
    port: int


# Helpers
def run_cmd(cmd: list, timeout: int = 30) -> tuple:
    """Run command and return (success, stdout, stderr)"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)


def load_config() -> dict:
    """Load exposure configuration"""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    """Save exposure configuration"""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def scan_services() -> list:
    """Scan listening services"""
    services = []

    # Use ss to get listening ports
    success, out, _ = run_cmd(["ss", "-tlnp"])
    if not success:
        return services

    seen_ports = set()
    for line in out.split('\n'):
        if 'LISTEN' not in line:
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # Parse address:port
        addr = parts[3]
        if ':' in addr:
            addr_parts = addr.rsplit(':', 1)
            port = addr_parts[-1]
            address = addr_parts[0] if len(addr_parts) > 1 else "0.0.0.0"
        else:
            continue

        if port in seen_ports:
            continue
        seen_ports.add(port)

        # Determine if external
        external = "0.0.0.0" in address or "::" in address or "*" in address

        # Get process name
        proc = "unknown"
        if 'users:' in line:
            match = re.search(r'users:\(\("([^"]+)"', line)
            if match:
                proc = match.group(1)

        # Map process to friendly name
        name_map = {
            "sshd": "SSH",
            "nginx": "Nginx",
            "haproxy": "HAProxy",
            "tor": "Tor",
            "python3": "Python App",
            "uvicorn": "Uvicorn API",
            "dnsmasq": "DNS",
        }
        name = name_map.get(proc, proc)

        services.append({
            "port": int(port),
            "address": address,
            "process": proc,
            "name": name,
            "external": external
        })

    return sorted(services, key=lambda x: x["port"])


def _hs_dropin(name: str) -> Path:
    return TOR_DROPIN_DIR / f"70-secubox-hs-{name}.conf"


def _ecrit_atomique(f: Path, texte: str) -> None:
    """Écriture atomique (fichier temporaire du même répertoire puis rename), mode d'origine conservé :
    Tor, rechargé à tout moment, ne lit jamais un fichier à moitié écrit."""
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.tmp")
    tmp.write_text(texte)
    try:
        os.chmod(tmp, f.stat().st_mode & 0o7777)
    except OSError:
        pass
    tmp.replace(f)


def _torrc_inclut_dropins() -> bool:
    """Le torrc lit-il torrc.d ? Le torrc de Debian ne l'inclut PAS par défaut (#3112, I1)."""
    try:
        texte = TOR_CONFIG.read_text()
    except OSError:
        return False
    for chemin in re.findall(r"^\s*%include\s+(\S+)", texte, re.M):
        if chemin.startswith((str(TOR_DROPIN_DIR), "/etc/tor/torrc.d")):
            return True
    return False


def _assure_include_torrc() -> bool:
    """Ajoute `%include <torrc.d>/*.conf` au torrc s'il manque (idempotent, atomique). Jamais de service écrit
    dans un fichier que Tor ne lit pas. Rend True si le torrc inclut torrc.d à la sortie."""
    if _torrc_inclut_dropins():
        return True
    try:
        texte = TOR_CONFIG.read_text()
        if texte and not texte.endswith("\n"):
            texte += "\n"
        _ecrit_atomique(TOR_CONFIG, texte + f"%include {TOR_DROPIN_DIR}/*.conf\n")
    except OSError:
        return False
    return True


def _hs_ecrit_dropin(name: str, hs_dir: Path, onion_port: int, local_port: int) -> None:
    """Écrit le fichier du service, atomiquement (un fichier par service : rien à relire ni à réécrire d'autre).
    S'assure d'abord que le torrc inclut torrc.d : sinon le service serait écrit pour rien (#3112, I1)."""
    _assure_include_torrc()
    _ecrit_atomique(_hs_dropin(name),
                    f"# SecuBox — service onion {name} (#2050)\n"
                    f"HiddenServiceDir {hs_dir}\n"
                    f"HiddenServicePort {onion_port} 127.0.0.1:{local_port}\n")


_RE_HS_DIR = re.compile(r"^\s*HiddenServiceDir\s+(.+?)\s*$")
_RE_HS_PORT = re.compile(r"^(\s*HiddenServicePort\s+)(\d+)(?:[ \t]+([^\s#]+))?([ \t]*(?:#.*)?)$")


def _norm_dir(valeur: str) -> str:
    """HiddenServiceDir comparable : sans commentaire de fin, sans blancs, sans « / » final."""
    v = valeur.split("#", 1)[0].strip()
    return v.rstrip("/") or v


def _hs_stanza_texte(name: str, hs_dir: Path) -> str:
    """Texte du service : son fichier, sinon l'ancien bloc du torrc ; '' si absent."""
    for src in (_hs_dropin(name), TOR_CONFIG):
        try:
            texte = src.read_text()
        except OSError:
            continue
        if src == TOR_CONFIG:
            blocs = _hs_blocs_torrc(texte)
            return next((b for d, b in blocs if d == _norm_dir(str(hs_dir))), "")
        return texte
    return ""


def _hs_blocs_torrc(texte: str) -> list:
    """[(HiddenServiceDir normalisé, texte du bloc)] : un bloc commence à sa ligne HiddenServiceDir (et son
    éventuel commentaire « # Hidden service: » juste avant) et court jusqu'à la ligne suivante qui n'est pas
    HiddenService*."""
    lignes = texte.splitlines(keepends=True)
    out, i = [], 0
    while i < len(lignes):
        md = _RE_HS_DIR.match(lignes[i])
        if md:
            deb = i
            if deb > 0 and lignes[deb - 1].startswith("# Hidden service:"):
                deb -= 1
            fin = i + 1
            while fin < len(lignes) and lignes[fin].lstrip().startswith("HiddenService") \
                    and not _RE_HS_DIR.match(lignes[fin]):
                fin += 1
            out.append((_norm_dir(md.group(1)), "".join(lignes[deb:fin])))
            i = fin
        else:
            i += 1
    return out


def _hs_retire_bloc_torrc(hs_dir: Path) -> bool:
    """Retire du torrc de Debian le seul ancien bloc de ce service (ligne à ligne, jamais un autre service),
    atomiquement. Ne touche NI à la clé NI au répertoire du service. Rend True si un bloc a été retiré."""
    try:
        texte = TOR_CONFIG.read_text()
    except OSError:
        return False
    for d, bloc in _hs_blocs_torrc(texte):
        if d == _norm_dir(str(hs_dir)):
            _ecrit_atomique(TOR_CONFIG, texte.replace(bloc, "", 1))
            return True
    return False


def _port_onion_in() -> int:
    """Port du frontal HAProxy `onion-in` : clé `onion_in_port` de haproxy.toml (la même que lit
    haproxyctl generate), sinon 9180. Jamais 9080 ni 80 : ce serait de nouveau nginx ou http-in en direct."""
    try:
        m = re.search(r"^onion_in_port\s*=\s*(\d+)\s*$", HAPROXY_TOML.read_text(), re.M)
        if m and 1 <= int(m.group(1)) <= 65535 and int(m.group(1)) not in PORTS_HTTP_DIRECTS:
            return int(m.group(1))
    except OSError:
        pass
    return ONION_IN_PORT_DEFAUT


def _route_waf_onion(onion: str) -> bool:
    """Route sbxwaf `<onion>.onion` → webui (nginx :9080), posée par l'outil commun `secubox-waf-route`
    (idempotent, écriture atomique, adresse des voisins du port). Sans elle sbxwaf rend 421 à l'onion.
    Au mieux : un échec n'ouvre rien, l'onion reste simplement fermé. Ne lève jamais."""
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", onion or ""):
        return False
    res = run_cmd([WAF_ROUTE_CMD, onion, str(WEBUI_NGINX_PORT)])
    return bool(isinstance(res, tuple) and res and res[0])


def _fichiers_tor() -> list:
    """Tous les fichiers où peut vivre un service onion : le torrc, torrc.d, et le répertoire de repli de
    metablogizerctl."""
    fichiers = [TOR_CONFIG]
    for d in (TOR_DROPIN_DIR, TOR_METABLOG_DIR):
        try:
            fichiers += sorted(p for p in d.glob("*.conf") if p.is_file())
        except OSError:
            pass
    return fichiers


def _cible_normalisee(cible: Optional[str], port_virtuel: str) -> str:
    """Cible d'un HiddenServicePort ramenée à « hôte:port » (absente ⇒ 127.0.0.1:<port virtuel>)."""
    if not cible:
        return f"127.0.0.1:{port_virtuel}"
    if cible.isdigit():
        return f"127.0.0.1:{cible}"
    for boucle in ("localhost:", "[::1]:"):
        if cible.startswith(boucle):
            return "127.0.0.1:" + cible[len(boucle):]
    return cible


def _hs_lignes(texte: str):
    """Itère (index, HiddenServiceDir courant normalisé, match HiddenServicePort) sur un fichier Tor."""
    courant = ""
    for i, ligne in enumerate(texte.splitlines()):
        md = _RE_HS_DIR.match(ligne)
        if md:
            courant = _norm_dir(md.group(1))
            continue
        mp = _RE_HS_PORT.match(ligne)
        if mp:
            yield i, courant, mp


def migrer_onions(user: str = "reconcile") -> dict:
    """Migration #3112/#3123, idempotente : TOUT service onion qui livrait en clair à une entrée HTTP directe de
    la box — nginx (127.0.0.1:9080) ou le frontal public http-in (127.0.0.1:80) — vise désormais le frontal
    HAProxy `onion-in`. Réécriture SUR PLACE de la seule ligne HiddenServicePort (torrc, torrc.d, répertoire de
    metablogizer), atomique : rien n'est déplacé dans un fichier que Tor ne lirait pas, HiddenServiceDir est
    inchangé (même clé, même adresse .onion). Recharge Tor une fois si quelque chose a changé ; une ligne
    d'audit par service migré."""
    port = _port_onion_in()
    a_migrer = {f"127.0.0.1:{p}" for p in PORTS_HTTP_DIRECTS}
    if port != ONION_IN_PORT_DEFAUT:
        a_migrer.add(f"127.0.0.1:{ONION_IN_PORT_DEFAUT}")
    migres = []
    for f in _fichiers_tor():
        try:
            texte = f.read_text()
        except OSError:
            continue
        lignes = texte.splitlines(keepends=True)
        change = False
        for i, hs_dir, mp in _hs_lignes(texte):
            ancienne = _cible_normalisee(mp.group(3), mp.group(2))
            if ancienne in a_migrer:
                fin = "\n" if lignes[i].endswith("\n") else ""
                lignes[i] = f"{mp.group(1)}{mp.group(2)} 127.0.0.1:{port}{mp.group(4)}{fin}"
                migres.append({"fichier": str(f), "dir": hs_dir, "ancienne_cible": ancienne})
                change = True
        if change:
            _ecrit_atomique(f, "".join(lignes))

    services = _load_emancipated()
    entrees = False
    for svc in services:
        if svc.get("local_port") in PORTS_HTTP_DIRECTS:
            svc["local_port"] = port
            entrees = True
    if entrees:
        _save_emancipated(services)
    if migres:
        run_cmd(["systemctl", "reload", "tor"])
    for mg in migres:
        _audit_exposure_action(
            action="migrate_onion",
            detail=f"dir={mg['dir'] or '(inconnu)'} ancienne_cible={mg['ancienne_cible']} "
                   f"cible=127.0.0.1:{port} ref=#3112",
            user=user,
        )
    return {"success": True, "migrated": bool(migres or entrees), "services": migres, "local_port": port}


def signaler_onions_non_migres(user: str = "reconcile") -> list:
    """Après migration, tout HiddenServicePort qui ne vise pas le frontal onion-in est signalé BRUYAMMENT :
    stderr et ligne d'audit `onion_non_migre` (avec son HiddenServiceDir). Jamais en silence (#3112, I2)."""
    port = _port_onion_in()
    restes = []
    for f in _fichiers_tor():
        try:
            texte = f.read_text()
        except OSError:
            continue
        for _, hs_dir, mp in _hs_lignes(texte):
            cible = _cible_normalisee(mp.group(3), mp.group(2))
            if cible != f"127.0.0.1:{port}":
                restes.append({"fichier": str(f), "dir": hs_dir, "cible": cible})
    for r in restes:
        print(f"ERREUR #3112 : service onion NON migré — {r['dir'] or '(HiddenServiceDir inconnu)'} "
              f"vise {r['cible']} au lieu de 127.0.0.1:{port} ({r['fichier']}). Ses visiteurs ne passent "
              f"pas par le frontal onion-in.", file=sys.stderr)
        _audit_exposure_action(action="onion_non_migre",
                               detail=f"dir={r['dir'] or '(inconnu)'} cible={r['cible']} fichier={r['fichier']}",
                               user=user)
    return restes


def _onion_webui_hostname() -> str:
    try:
        return (TOR_DATA / "webui" / "hostname").read_text().strip()
    except OSError:
        return ""


def get_tor_services() -> list:
    """Get Tor hidden services.

    Degrades gracefully when the caller (e.g. the web-serving `secubox` user in
    the aggregator) cannot read Tor's 0700 hidden-service dir — that dir holds
    onion PRIVATE KEYS and must NOT be world-readable, so a PermissionError is
    expected and correct. Return an empty list rather than 500 the /status page.
    """
    services = []

    try:
        if not TOR_DATA.exists():
            return services
        entries = list(TOR_DATA.iterdir())
    except OSError:
        return services

    for dir_path in entries:
        if not dir_path.is_dir():
            continue

        svc_name = dir_path.name
        hostname_file = dir_path / "hostname"
        onion = ""

        if hostname_file.exists():
            onion = hostname_file.read_text().strip()

        # Get port from torrc
        port = "80"
        backend = "127.0.0.1:80"

        stanza = _hs_stanza_texte(svc_name, dir_path)
        match = re.search(r'HiddenServicePort\s+(\d+)\s+(\S+)', stanza)
        if match:
            port = match.group(1)
            backend = match.group(2)

        if onion:
            services.append({
                "service": svc_name,
                "onion": onion,
                "port": port,
                "backend": backend
            })

    return services


def get_ssl_backends() -> list:
    """Get SSL backends from HAProxy/nginx config"""
    backends = []

    # Check HAProxy backends
    haproxy_cfg = Path("/etc/haproxy/haproxy.cfg")
    if haproxy_cfg.exists():
        # Parse haproxy config for backends with SSL
        cfg = haproxy_cfg.read_text()
        # Simplified parsing - real implementation would be more sophisticated

    # Check nginx vhosts
    nginx_dir = Path("/etc/nginx/sites-enabled")
    if nginx_dir.exists():
        for vhost in nginx_dir.iterdir():
            if vhost.is_file():
                content = vhost.read_text()
                # Check for SSL cert
                if "ssl_certificate" in content:
                    # Extract server_name
                    match = re.search(r'server_name\s+([^;]+);', content)
                    if match:
                        domain = match.group(1).strip().split()[0]
                        backends.append({
                            "service": vhost.name,
                            "domain": domain,
                            "backend": "nginx"
                        })

    return backends


# Public endpoints
@app.get("/status", dependencies=[Depends(require_lecture)])
async def get_status():
    """Get exposure status overview"""
    services = scan_services()
    tor_services = get_tor_services()
    ssl_backends = get_ssl_backends()

    external_count = sum(1 for s in services if s["external"])

    return {
        "services": {
            "total": len(services),
            "external": external_count
        },
        "tor": {
            "count": len(tor_services),
            "services": tor_services
        },
        "ssl": {
            "count": len(ssl_backends),
            "backends": ssl_backends
        }
    }


@app.get("/scan", dependencies=[Depends(require_lecture)])
async def scan():
    """Scan listening services"""
    return {"services": scan_services()}


@app.get("/tor_list", dependencies=[Depends(require_lecture)])
async def tor_list():
    """List Tor hidden services"""
    return {"services": get_tor_services()}


@app.get("/ssl_list", dependencies=[Depends(require_lecture)])
async def ssl_list():
    """List SSL backends"""
    return {"backends": get_ssl_backends()}


@app.get("/emancipated", dependencies=[Depends(require_lecture)])
async def get_emancipated():
    """Get list of emancipated services"""
    config = load_config()
    return {"services": config.get("emancipated", [])}


# Protected endpoints
def _tor_add_sync(name: str, local_port: int, onion_port: int) -> dict:
    """Blocking torrc-edit + reload + poll-for-onion mechanics (up to 10s).
    Plain sync function — callers on an event loop MUST offload via
    asyncio.to_thread (see _apply_tor). Does not check hs existence; that's
    the caller's responsibility (tor_add's 400, _apply_tor's `not hs.exists()`)."""
    hs_dir = TOR_DATA / name

    # Un fichier par service dans torrc.d (le torrc de Debian n'est plus réécrit, #2050).
    _hs_ecrit_dropin(name, hs_dir, onion_port, local_port)

    # Reload Tor
    run_cmd(["systemctl", "reload", "tor"])

    # Wait for onion address (Tor generates it on reload) — bounded, blocking.
    import time
    for _ in range(10):
        time.sleep(1)
        hostname_file = hs_dir / "hostname"
        if hostname_file.exists():
            onion = hostname_file.read_text().strip()
            return {
                "success": True,
                "message": "Hidden service created",
                "onion": onion
            }

    return {
        "success": True,
        "message": "Hidden service created, onion address pending"
    }


def _tor_remove_sync(name: str) -> dict:
    """Blocking torrc-edit + directory removal + reload mechanics. Plain sync
    function — callers on an event loop MUST offload via asyncio.to_thread.
    Does not check hs existence; that's the caller's responsibility."""
    hs_dir = TOR_DATA / name

    # Son fichier de torrc.d, puis l'ancien bloc du torrc s'il y en a un (ligne à ligne : jamais d'autre service).
    try:
        _hs_dropin(name).unlink()
    except FileNotFoundError:
        pass
    _hs_retire_bloc_torrc(hs_dir)

    # Remove directory
    import shutil
    shutil.rmtree(hs_dir, ignore_errors=True)

    # Reload Tor
    run_cmd(["systemctl", "reload", "tor"])

    return {"success": True, "message": "Hidden service removed"}


async def _apply_tor(vhost: str, want: bool, user: dict) -> None:
    """Apply/remove a Tor hidden service for this vhost. Thread-offloaded so the
    blocking torrc reload/poll never stalls the shared event loop. Best-effort:
    a Tor hiccup must not fail the reach change (which already succeeded)."""
    name = "".join(c for c in vhost if c.isalnum() or c in "_-")

    def _work():
        hs = TOR_DATA / name
        try:
            if want and not hs.exists():
                # #3112/#3123 : par le frontal onion-in, jamais http-in (:80) en direct.
                _tor_add_sync(name, local_port=_port_onion_in(), onion_port=80)
            elif not want and hs.exists():
                _tor_remove_sync(name)
        except Exception:
            pass

    await asyncio.to_thread(_work)


# ----------------------------------------------------------------------------
# Task 5 (tor-enhancement-phase1): emancipate the webui itself, standalone +
# persist-on-boot. Mirrors the _tor_add_sync mechanic above; annuaire
# federation (mesh_egress._publish) is opt-in via `federate=True` and always
# best-effort — a mesh/annuaire hiccup must never fail a plain, single-node
# webui emancipation.
# ----------------------------------------------------------------------------

def _hs_dir_exists(name: str) -> bool:
    """Whether the Tor HS key/hostname dir already exists for `name`."""
    return (TOR_DATA / name).exists()


def _torrc_has_stanza(name: str) -> bool:
    """Whether torrc still contains the HiddenServiceDir stanza for `name`.

    `_tor_add_sync` appends `HiddenServiceDir`/`HiddenServicePort` lines into
    TOR_CONFIG; those lines are what actually keeps the hidden service alive
    after a `systemctl reload tor`. If torrc gets reset/regenerated while the
    key dir under TOR_DATA survives, the stanza is gone but the HS dir check
    alone would report "already provisioned" — leaving the .onion dark with
    no repair path. Never raises."""
    try:
        hs_dir = TOR_DATA / name
        return _hs_dropin(name).exists() or bool(_hs_stanza_texte(name, hs_dir))
    except OSError:
        return False


def _load_emancipated() -> list:
    return load_config().get("emancipated", [])


def _save_emancipated(services: list) -> None:
    config = load_config()
    config["emancipated"] = services
    save_config(config)


def _mesh_present() -> bool:
    """Best-effort mesh detection for the federation gate — never raises."""
    try:
        from api.mesh_egress import mesh_ip  # noqa: PLC0415
        return mesh_ip() is not None
    except Exception:  # noqa: BLE001
        return False


def emancipate_webui(federate: bool = False, user: Optional[dict] = None) -> dict:
    """Emancipate the SecuBox webui itself as a Tor hidden service.

    Standalone by default: creates HS `name="webui"`, `onion_port=80`, whose
    target is the dedicated HAProxy frontend `onion-in` (127.0.0.1:9180 by
    default) — NEVER nginx :9080 directly (#3112: every Tor visitor came from
    127.0.0.1 and nginx classed it LAN). Records it `active` in the exposure
    config so `tor_reconcile_persist()` can restore it on reboot, and registers
    the sbxwaf route `<onion>` -> webui so the WAF inspects and serves it.

    `federate=True` additionally publishes a signed annuaire offer — but ONLY
    when a mesh is actually present, and always wrapped so a federation
    failure can never raise out of (or block) this call; the HS itself has
    already been created by that point.

    `user` is the JWT principal from the calling endpoint — recorded in the
    CSPN audit trail (FINAL-REVIEW: publishing the admin webui as a hidden
    service is at least as security-relevant as an exit-country/VPN/bridge
    change, which are already audited via `_audit_exposure`).
    """
    port = _port_onion_in()
    tor_result = _tor_add_sync(name="webui", local_port=port, onion_port=80)

    entry = {"name": "webui", "local_port": port, "onion_port": 80, "active": True}
    if tor_result.get("onion"):
        entry["onion"] = tor_result["onion"]
        entry["waf_route"] = _route_waf_onion(tor_result["onion"])

    services = [s for s in _load_emancipated() if s.get("name") != "webui"]
    services.append(entry)
    _save_emancipated(services)

    _audit_exposure_action(
        action="emancipate_webui",
        detail=f"onion={entry.get('onion', '(pending)')} local_port={port} federate={federate}",
        user=(user or {}).get("sub", "?"),
    )

    if federate and tor_result.get("onion"):
        try:
            if _mesh_present():
                endpoint = f"http://{tor_result['onion']}/"
                _publish("webui", endpoint,
                         {"channel": "tor", "onion": tor_result["onion"], "port": port})
        except Exception:  # noqa: BLE001 — federation is best-effort, never fatal
            pass

    return {"success": True, "message": "webui emancipated", "output": entry, "tor": tor_result}


def tor_reconcile_persist(user: str = "reconcile") -> dict:
    """Boot-time reconcile: re-apply the torrc HiddenService* stanza for every
    `active` emancipated service that is missing EITHER its HS key dir OR its
    torrc stanza (e.g. after a fresh provisioning, an image flash, an
    operator wipe of /var/lib/tor, OR a torrc reset that left the key dir
    untouched). A service is skipped only when BOTH the key dir exists AND
    torrc already contains its HiddenServiceDir stanza — the only state in
    which the .onion is actually being served. When the key dir survives but
    the stanza is missing, `_tor_add_sync` re-appends it and reloads Tor;
    since the private key is unchanged, the `.onion` address is preserved.

    #3112/#3123 : d'abord la migration de TOUS les onions vers le frontal
    HAProxy onion-in (idempotente) ; aucun service n'est réappliqué vers nginx
    :9080 ni http-in :80, quelle que soit la valeur enregistrée ; la route
    sbxwaf de l'onion du webui est assurée ; enfin tout onion qui ne vise pas
    le frontal est signalé bruyamment. `user` : qui lance (audit).
    """
    try:
        migration = migrer_onions(user=user)
    except Exception as e:  # noqa: BLE001 — la migration ne doit pas empêcher la persistance des autres
        migration = {"success": False, "error": str(e)}
    applied = []
    for svc in _load_emancipated():
        if not svc.get("active"):
            continue
        name = svc.get("name")
        local_port = svc.get("local_port")
        onion_port = svc.get("onion_port")
        if not name or local_port is None or onion_port is None:
            continue
        if local_port in PORTS_HTTP_DIRECTS or name == "webui":
            local_port = _port_onion_in()
        if _hs_dir_exists(name) and _torrc_has_stanza(name):
            continue
        try:
            _tor_add_sync(name=name, local_port=local_port, onion_port=onion_port)
            applied.append(name)
        except Exception:  # noqa: BLE001 — one bad entry must not abort the rest
            continue

    route = False
    if any(s.get("name") == "webui" and s.get("active") for s in _load_emancipated()):
        route = _route_waf_onion(_onion_webui_hostname())

    try:
        restes = signaler_onions_non_migres(user=user)
    except Exception as e:  # noqa: BLE001
        print(f"ERREUR #3112 : contrôle des onions impossible ({e})", file=sys.stderr)
        restes = None

    return {"success": True, "applied": applied, "migration": migration, "waf_route": route,
            "non_migres": restes}


@app.post("/tor/add")
async def tor_add(req: TorAddRequest, user: dict = Depends(require_jwt)):
    """Add Tor hidden service"""
    # Cert-pin / MITM-bypass gate — check the ORIGINAL host before sanitisation
    # strips its dots. Covers /emancipate too (it calls this). Never anonymously
    # re-expose an endpoint clients pin.
    excluded, why = _excl.exclusion_reason(req.service)
    if excluded:
        raise HTTPException(status_code=400,
                            detail=f"Tor refusé pour {req.service} : domaine exclu — {why}.")
    # #3112/#3123 : LISTE BLANCHE, une seule cible — le frontal onion-in. Un onion vers nginx :9080 ou http-in
    # :80 en direct contourne le nettoyage des en-têtes, et nginx prend chaque visiteur Tor (127.0.0.1) pour un
    # poste du LAN. sbxwaf route ensuite le Host <onion>.onion.
    port = _port_onion_in()
    if req.local_port not in (None, port):
        raise HTTPException(status_code=400,
                            detail=f"Tor refusé vers 127.0.0.1:{req.local_port} : un service onion ne vise que "
                                   f"le frontal HAProxy onion-in (127.0.0.1:{port}) (#3112).")
    # Sanitize service name
    name = "".join(c for c in req.service if c.isalnum() or c in "_-")

    hs_dir = TOR_DATA / name
    if hs_dir.exists():
        raise HTTPException(status_code=400, detail="Hidden service already exists")

    return _tor_add_sync(name, port, req.onion_port)


@app.post("/tor/remove")
async def tor_remove(req: TorRemoveRequest, user: dict = Depends(require_jwt)):
    """Remove Tor hidden service"""
    name = "".join(c for c in req.service if c.isalnum() or c in "_-")
    hs_dir = TOR_DATA / name

    if not hs_dir.exists():
        raise HTTPException(status_code=404, detail="Hidden service not found")

    return _tor_remove_sync(name)


@app.post("/tor/emancipate_webui")
async def tor_emancipate_webui(federate: bool = False, user: dict = Depends(require_jwt)):
    """Emancipate the SecuBox webui itself as a standalone Tor hidden service
    (opt-in `?federate=true` to also publish an annuaire offer, best-effort).
    Offloaded to a thread — emancipate_webui blocks for up to 10s (torrc
    reload + onion poll) via _tor_add_sync, and this runs on the shared
    aggregator event loop."""
    return await asyncio.to_thread(emancipate_webui, federate, user)


@app.post("/ssl/add")
async def ssl_add(req: SslAddRequest, user: dict = Depends(require_jwt)):
    """Add SSL backend"""
    # This would integrate with HAProxy or nginx
    # Simplified implementation

    config = load_config()
    if "ssl_backends" not in config:
        config["ssl_backends"] = []

    config["ssl_backends"].append({
        "service": req.service,
        "domain": req.domain,
        "local_port": req.local_port
    })

    save_config(config)

    return {"success": True, "message": "SSL backend configured"}


@app.post("/ssl/remove")
async def ssl_remove(req: SslRemoveRequest, user: dict = Depends(require_jwt)):
    """Remove SSL backend"""
    config = load_config()

    if "ssl_backends" in config:
        config["ssl_backends"] = [
            b for b in config["ssl_backends"]
            if b["service"] != req.service
        ]
        save_config(config)

    return {"success": True, "message": "SSL backend removed"}


@app.post("/emancipate")
async def emancipate(req: EmancipateRequest, user: dict = Depends(require_jwt)):
    """Emancipate a service (expose via Tor/DNS/Mesh)"""
    config = load_config()

    if "emancipated" not in config:
        config["emancipated"] = []

    # Check if already emancipated
    for svc in config["emancipated"]:
        if svc["name"] == req.service:
            raise HTTPException(status_code=400, detail="Service already emancipated")

    result = {
        "name": req.service,
        "port": req.port,
        "domain": req.domain,
        "tor": req.tor,
        "dns": req.dns,
        "mesh": req.mesh
    }

    # If Tor requested, create hidden service + register the onion in the
    # directory so the anonymous egress endpoint federates (gondwana #768 P3).
    if req.tor:
        # Tor passe par le frontal onion-in (#3112) : le port du service ne sert qu'au maillage et au DNS.
        tor_req = TorAddRequest(service=req.service)
        tor_result = await tor_add(tor_req, user)
        if tor_result.get("onion"):
            result["onion"] = tor_result["onion"]
            try:
                from api.mesh_egress import apply_tor  # noqa: PLC0415
                tr = apply_tor(req.service, req.port, tor_result["onion"])
                result["tor_registered"] = bool(tr.get("ok"))
                if not tr.get("ok"):
                    result["tor_error"] = tr.get("error")
            except Exception as e:  # noqa: BLE001
                result["tor_registered"] = False
                result["tor_error"] = str(e)

    # If Mesh requested, make it real (gondwana #768): open the port over the
    # wg-mesh + register a signed emancipated offer into the annuaire directory
    # so it federates into every node's mesh-wide catalog.
    if req.mesh:
        try:
            from api.mesh_egress import apply_mesh  # noqa: PLC0415
            mesh_result = apply_mesh(req.service, req.port)
            result["mesh_endpoint"] = mesh_result.get("endpoint")
            result["mesh_registered"] = bool(mesh_result.get("ok"))
            result["mesh_nft"] = mesh_result.get("nft")
            if not mesh_result.get("ok"):
                result["mesh_error"] = mesh_result.get("error")
        except Exception as e:  # noqa: BLE001 — a mesh hiccup must not fail emancipate
            result["mesh_registered"] = False
            result["mesh_error"] = str(e)

    # Public channel (gondwana #768 P4): federate a public offer + emit the WAF
    # vhost recipe. Real reach is completed by the operator (DNS + cert); we do
    # not auto-mutate the live HAProxy/sbxwaf chain.
    if req.dns and req.domain:
        try:
            from api.mesh_egress import apply_public  # noqa: PLC0415
            pub = apply_public(req.service, req.port, req.domain)
            result["public_registered"] = bool(pub.get("ok"))
            result["public_recipe"] = pub.get("recipe")
            if not pub.get("ok"):
                result["public_error"] = pub.get("error")
        except Exception as e:  # noqa: BLE001
            result["public_registered"] = False
            result["public_error"] = str(e)

    config["emancipated"].append(result)
    save_config(config)

    return {"success": True, "message": "Service emancipated", "output": result}


@app.post("/revoke")
async def revoke(req: RevokeRequest, user: dict = Depends(require_jwt)):
    """Revoke service exposure"""
    config = load_config()

    if "emancipated" not in config:
        return {"success": True, "message": "No emancipated services"}

    # Find and remove
    found = None
    for svc in config["emancipated"]:
        if svc["name"] == req.service:
            found = svc
            break

    if not found:
        raise HTTPException(status_code=404, detail="Service not found")

    # If Tor was enabled, remove hidden service
    if found.get("tor") and req.tor:
        tor_req = TorRemoveRequest(service=req.service)
        await tor_remove(tor_req, user)

    config["emancipated"] = [
        s for s in config["emancipated"]
        if s["name"] != req.service
    ]
    save_config(config)

    return {"success": True, "message": "Service revoked"}


@app.get("/info", dependencies=[Depends(require_lecture)])
async def get_info():
    """Get module info"""
    return {
        "module": "secubox-exposure",
        "version": "2.0.0",
        "description": "Service exposure management - Tor, SSL, DNS, Mesh",
        "features": [
            "multi_channel", "health_checks", "audit_history",
            "webhook_alerts", "scheduled_monitoring"
        ]
    }


@app.get("/health")
async def health_endpoint():
    """Health check endpoint."""
    return {"status": "healthy", "service": "secubox-exposure", "version": "2.0.0"}


# ============================================================================
# History Endpoints
# ============================================================================

@app.get("/history", dependencies=[Depends(require_lecture)])
async def get_history(
    limit: int = 50,
    service: str = None,
    action: str = None
):
    """Get exposure history."""
    history = load_history()

    # Filter by service
    if service:
        history = [h for h in history if h.get("service") == service]

    # Filter by action
    if action:
        history = [h for h in history if h.get("action") == action]

    # Return most recent first
    history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {"history": history[:limit], "total": len(history)}


@app.delete("/history")
async def clear_history(user: dict = Depends(require_jwt)):
    """Clear exposure history."""
    save_history([])
    return {"status": "cleared"}


# ============================================================================
# Health Check Endpoints
# ============================================================================

@app.get("/health/services", dependencies=[Depends(require_lecture)])
async def get_services_health():
    """Get health status of all exposed services."""
    health_status = load_health_status()
    return {"services": {k: v.dict() for k, v in health_status.items()}}


@app.get("/health/services/{service}", dependencies=[Depends(require_lecture)])
async def get_service_health(service: str):
    """Get health status of a specific service."""
    health_status = load_health_status()
    if service not in health_status:
        raise HTTPException(status_code=404, detail="Service not found")
    return health_status[service].dict()


@app.post("/health/check/{service}")
async def check_service(service: str, background_tasks: BackgroundTasks, user: dict = Depends(require_jwt)):
    """Trigger health check for a service."""
    config = load_config()

    # Find service
    svc = None
    for s in config.get("emancipated", []):
        if s.get("name") == service:
            svc = s
            break

    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")

    # Get channels
    channels = []
    if svc.get("tor"):
        channels.append("tor")
    if svc.get("dns"):
        channels.append("dns")
    if svc.get("mesh"):
        channels.append("mesh")

    # Run health check
    health = await check_service_health(service, svc.get("port", 80), channels)

    # Update status
    status_changed = update_health(service, health)
    save_health_status()

    # Send webhook if status changed
    if status_changed:
        background_tasks.add_task(send_webhook, "health_change", {
            "service": service,
            "status": health.status.value,
            "previous_status": _health_status.get(service, {}).status if service in _health_status else "unknown"
        })

    return health.dict()


@app.post("/health/check_all")
async def check_all_services(background_tasks: BackgroundTasks, user: dict = Depends(require_jwt)):
    """Trigger health check for all exposed services."""
    config = load_config()
    results = {}

    for svc in config.get("emancipated", []):
        service = svc.get("name")
        channels = []
        if svc.get("tor"):
            channels.append("tor")
        if svc.get("dns"):
            channels.append("dns")
        if svc.get("mesh"):
            channels.append("mesh")

        health = await check_service_health(service, svc.get("port", 80), channels)
        status_changed = update_health(service, health)
        results[service] = health.dict()

        if status_changed:
            background_tasks.add_task(send_webhook, "health_change", {
                "service": service,
                "status": health.status.value
            })

    save_health_status()
    return {"results": results, "checked": len(results)}


# ============================================================================
# Webhook Endpoints
# ============================================================================

@app.get("/webhooks")
async def list_webhooks(user: dict = Depends(require_jwt)):
    """List configured webhooks."""
    webhooks = load_webhooks()
    return {"webhooks": [wh.dict() for wh in webhooks]}


@app.post("/webhooks")
async def add_webhook(webhook: WebhookConfig, user: dict = Depends(require_jwt)):
    """Add a webhook."""
    webhooks = load_webhooks()

    for wh in webhooks:
        if wh.url == webhook.url:
            raise HTTPException(status_code=409, detail="Webhook URL already exists")

    webhooks.append(webhook)
    save_webhooks(webhooks)
    return {"status": "added"}


@app.delete("/webhooks")
async def delete_webhook(url: str, user: dict = Depends(require_jwt)):
    """Delete a webhook by URL."""
    webhooks = load_webhooks()
    original_len = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.url != url]

    if len(webhooks) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    save_webhooks(webhooks)
    return {"status": "deleted"}


# ============================================================================
# Statistics Endpoints
# ============================================================================

@app.get("/stats", dependencies=[Depends(require_lecture)])
async def get_exposure_stats():
    """Get exposure statistics."""
    config = load_config()
    history = load_history()
    health_status = load_health_status()

    emancipated = config.get("emancipated", [])

    # Count by channel
    channel_counts = {"tor": 0, "dns": 0, "mesh": 0, "ssl": 0}
    for svc in emancipated:
        if svc.get("tor"):
            channel_counts["tor"] += 1
        if svc.get("dns"):
            channel_counts["dns"] += 1
        if svc.get("mesh"):
            channel_counts["mesh"] += 1

    # Health summary
    health_summary = {"healthy": 0, "degraded": 0, "unhealthy": 0, "unknown": 0}
    for h in health_status.values():
        health_summary[h.status.value] = health_summary.get(h.status.value, 0) + 1

    # Recent activity
    recent_history = sorted(history, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]

    return {
        "total_exposed": len(emancipated),
        "by_channel": channel_counts,
        "health_summary": health_summary,
        "recent_activity": recent_history
    }


# ============================================================================
# Enhanced Emancipate/Revoke with History
# ============================================================================

# Override emancipate to add history
_original_emancipate = emancipate


@app.post("/emancipate")
async def emancipate_with_history(
    req: EmancipateRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Emancipate a service with history tracking."""
    result = await _original_emancipate(req, user)

    # Add history entry
    channels = []
    if req.tor:
        channels.append("tor")
    if req.dns:
        channels.append("dns")
    if req.mesh:
        channels.append("mesh")

    add_history_entry(ExposureHistoryEntry(
        timestamp=datetime.utcnow().isoformat() + "Z",
        action="emancipate",
        service=req.service,
        channels=channels,
        user=user.get("sub"),
        details={"port": req.port, "domain": req.domain}
    ))

    # Send webhook
    background_tasks.add_task(send_webhook, "exposure_change", {
        "action": "emancipate",
        "service": req.service,
        "channels": channels
    })

    return result


# Override revoke to add history
_original_revoke = revoke


@app.post("/revoke")
async def revoke_with_history(
    req: RevokeRequest,
    background_tasks: BackgroundTasks,
    user: dict = Depends(require_jwt)
):
    """Revoke service exposure with history tracking."""
    result = await _original_revoke(req, user)

    # Add history entry
    channels = []
    if req.tor:
        channels.append("tor")
    if req.dns:
        channels.append("dns")
    if req.mesh:
        channels.append("mesh")

    add_history_entry(ExposureHistoryEntry(
        timestamp=datetime.utcnow().isoformat() + "Z",
        action="revoke",
        service=req.service,
        channels=channels,
        user=user.get("sub")
    ))

    # Send webhook
    background_tasks.add_task(send_webhook, "exposure_change", {
        "action": "revoke",
        "service": req.service,
        "channels": channels
    })

    # Remove from health status
    with _health_lock:
        _health_status.pop(req.service, None)
    save_health_status()

    return result


# ============================================================================
# Background Health Monitoring
# ============================================================================

_health_task: Optional[asyncio.Task] = None


async def periodic_health_check():
    """Background task for periodic health checks."""
    while True:
        try:
            config = load_config()
            if not config.get("health_check_enabled", True):
                await asyncio.sleep(60)
                continue

            interval = config.get("health_check_interval", HEALTH_CHECK_INTERVAL)
            await asyncio.sleep(interval)

            for svc in config.get("emancipated", []):
                service = svc.get("name")
                channels = []
                if svc.get("tor"):
                    channels.append("tor")
                if svc.get("dns"):
                    channels.append("dns")
                if svc.get("mesh"):
                    channels.append("mesh")

                try:
                    health = await check_service_health(service, svc.get("port", 80), channels)
                    status_changed = update_health(service, health)

                    if status_changed:
                        await send_webhook("health_change", {
                            "service": service,
                            "status": health.status.value
                        })
                except Exception:
                    pass

            save_health_status()

        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    global _health_task
    load_health_status()
    _health_task = asyncio.create_task(periodic_health_check())


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    global _health_task
    if _health_task:
        _health_task.cancel()
        try:
            await _health_task
        except asyncio.CancelledError:
            pass
    save_health_status()
