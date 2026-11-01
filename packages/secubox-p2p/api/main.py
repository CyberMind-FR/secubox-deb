#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox P2P API — Peer-to-Peer Network Hub
Manages peer discovery, mesh networking, service federation, and master-link enrollment
"""
from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import contextvars
import functools
import threading
import logging
import subprocess
import asyncio
import ipaddress
import json
import os
import re
import socket
import time
import hashlib
import secrets
from pathlib import Path
from urllib.parse import quote
from datetime import datetime, timedelta

log = logging.getLogger("secubox.p2p")

import sys
# En QUEUE, jamais en tête : devant /usr/local, le websockets 10.4 de Debian
# masquait celui qu'attend uvicorn ≥ 0.54 → service en boucle (#1796).
if "/usr/lib/python3/dist-packages" not in sys.path:
    sys.path.append("/usr/lib/python3/dist-packages")
try:
    from secubox_core.auth import require_jwt
except ImportError:
    async def require_jwt():
        return {"sub": "admin"}

from . import mesh, registry, annuaire_client, dht, federation, masterlink, automesh, jetons, ancre, pairs_directs, pairs_enroles, oubli
from secubox_core.auth import require_lecture, SESSION_COOKIE, _bearer
from secubox_core.crypto.empreinte import ident

app = FastAPI(
    title="SecuBox P2P API",
    description="P2P network hub with peer discovery and master-link enrollment",
    version="1.3.0",
    docs_url="/docs",
    redoc_url=None
)


# ── jeton de l'appelant relayé à l'annuaire local (#3136) ────────────────────
_RE_JETON = re.compile(r"[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{0,2048}")


def _jetons_de_l_appelant(scope) -> tuple:
    """Candidats de la requête dans l'ordre de la garde de lecture — Bearer, puis cookie de session —, de forme JWT
    seulement, sans doublon. La position des en-têtes ne compte pas."""
    from http.cookies import SimpleCookie
    bearer, cookie = [], []
    for nom, valeur in scope.get("headers") or []:
        if nom == b"authorization" and valeur[:7].lower() == b"bearer ":
            bearer.append(valeur[7:].decode("latin-1").strip())
        elif nom == b"cookie":
            try:
                c = SimpleCookie(valeur.decode("latin-1"))
            except Exception:  # noqa: BLE001
                continue
            if SESSION_COOKIE in c:
                cookie.append(c[SESSION_COOKIE].value)
    return tuple(dict.fromkeys(j for j in bearer + cookie if _RE_JETON.fullmatch(j)))


class _RelaieJeton:
    """ASGI : pose le jeton de l'appelant pour annuaire_client le temps de la requête, puis le retire."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        marque = annuaire_client.JETON_APPELANT.set(_jetons_de_l_appelant(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            annuaire_client.JETON_APPELANT.reset(marque)


app.add_middleware(_RelaieJeton)

# Paths
P2P_DIR = Path("/var/lib/secubox/p2p")
PEERS_FILE = P2P_DIR / "peers.json"
# Projection lisible des pairs enrôlés pour le pilotage (#3126) : P2P_DIR est 0700, secubox-pilotage ne lit que cette projection.
PAIRS_ENROLES_DIR = pairs_enroles.DOSSIER_DEFAUT
SERVICES_FILE = P2P_DIR / "services.json"
PROFILES_FILE = P2P_DIR / "profiles.json"
THREATS_FILE = P2P_DIR / "threats.json"
NODE_ID_FILE = P2P_DIR / "node.id"
ACTIVATION_FILE = P2P_DIR / "activation.json"
CONFIG_FILE = Path("/etc/secubox/p2p.toml")

# Master-Link paths
ML_DIR = P2P_DIR / "master-link"
ML_TOKENS_FILE = ML_DIR / "tokens.json"
ML_REQUESTS_FILE = ML_DIR / "requests.json"
ML_CONFIG_FILE = ML_DIR / "config.json"

# mDNS service type for SecuBox discovery
MDNS_SERVICE_TYPE = "_secubox._tcp"
API_PORT = 7331

# Master-Link defaults
ML_DEFAULT_TOKEN_TTL = 3600  # 1 hour
ML_DEFAULT_MAX_DEPTH = 3


def init_dirs():
    P2P_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any = None) -> Any:
    if default is None:
        default = []
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except:
            pass
    return default


def save_json(path: Path, data: Any):
    init_dirs()
    if Path(path) in (PEERS_FILE, WG_MESH_CONFIG, ML_REQUESTS_FILE, ML_TOKENS_FILE):
        # #3335 (relecture #3341), #3362 : mêmes fichiers que « Oublier ce nœud » (jonctions comprises) : écriture atomique
        # sous son verrou. Déjà dans une section critique de ce fil : variante « déjà sous verrou », sans reprendre le flock.
        if oubli.tenu(P2P_DIR):
            _ecrire_sous_verrou(path, data)
        else:
            with oubli.verrou(P2P_DIR):
                _ecrire_sous_verrou(path, data)
    else:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    if Path(path) == PEERS_FILE:
        # #3126 : chaque écriture du registre republie la projection du pilotage ; un échec ne bloque jamais le registre.
        try:
            pairs_enroles.publier(data, PAIRS_ENROLES_DIR)
        except (pairs_enroles.ProjectionErreur, OSError) as e:
            log.warning("projection des pairs enrôlés non publiée : %s", e)


def _ecrire_sous_verrou(path: Path, data: Any) -> None:
    """Écriture atomique d'un fichier d'état du maillage ; l'appelant TIENT `oubli.verrou(P2P_DIR)` (#3362)."""
    oubli.ecrire_atomique(path, data, 0o644 if Path(path) == PEERS_FILE else 0o600)


def _ml_lire(path: Path) -> List[Dict]:
    """#3362 (passe 2) : demandes ou jetons, lus STRICTEMENT dans une section critique ; illisibles → 503, rien n'est
    réécrit (load_json rendait [] et le fichier était remplacé par une liste vide)."""
    try:
        return oubli.lire_strict_liste(path)
    except oubli.EtatIllisible:
        raise HTTPException(status_code=503, detail="jonctions du maillage illisibles : rien n'est modifié") from None


def get_node_id() -> str:
    """Get or generate unique node ID."""
    init_dirs()
    if NODE_ID_FILE.exists():
        return NODE_ID_FILE.read_text().strip()

    # Generate from MAC address or random
    node_id = None
    try:
        # Try to get MAC from first non-loopback interface
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=5
        )
        mac_match = re.search(r'link/ether ([0-9a-f:]{17})', result.stdout)
        if mac_match:
            mac = mac_match.group(1).replace(':', '')
            node_id = f"sb-{mac}"
    except:
        pass

    if not node_id:
        import uuid
        node_id = f"sb-{uuid.uuid4().hex[:12]}"

    NODE_ID_FILE.write_text(node_id)
    return node_id


def get_hostname() -> str:
    """Get system hostname."""
    try:
        return socket.gethostname()
    except:
        return "secubox"


# La règle vit dans secubox_core.reseau (#1556) — p2p, l'annonce Bonjour et
# les noms <box>.lan.<zone> la partagent. Copie locale seulement le temps
# qu'un secubox-core plus ancien soit encore installé.
try:
    from secubox_core.reseau import choisit_lan_ip  # noqa: E402
except ImportError:  # pragma: no cover — secubox-core < 1.5.24
    _IFACES_HORS_LAN = ("lo", "veth", "docker", "lxcbr", "br-lxc", "wg", "tun", "tap", "virbr", "eye-br")

    def choisit_lan_ip(adresses, source_defaut: Optional[str]) -> Optional[str]:
        import ipaddress  # noqa: PLC0415
        reelles = [(i, ip) for i, ip in adresses
                   if not i.startswith(_IFACES_HORS_LAN) and not ip.startswith("127.")]
        for _, ip in reelles:
            if ip.startswith("192.168.255."):
                return ip
        if source_defaut and any(ip == source_defaut for _, ip in reelles):
            return source_defaut
        for _, ip in reelles:
            try:
                if ipaddress.ip_address(ip).is_private:
                    return ip
            except ValueError:
                continue
        return reelles[0][1] if reelles else source_defaut


def get_lan_ip() -> Optional[str]:
    """Adresse LAN annoncée (invitations, join-script, statut) — voir choisit_lan_ip."""
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        adresses = [(m.group(1), m.group(2)) for m in re.finditer(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)]
        r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", r)
        return choisit_lan_ip(adresses, m.group(1) if m else None) or "127.0.0.1"
    except Exception:  # noqa: BLE001 — jamais une exception pour une adresse d'affichage
        return "127.0.0.1"


def get_wan_ip() -> Optional[str]:
    """Get WAN/public IP address."""
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "3", "https://api.ipify.org"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    return None


def get_wireguard_ips() -> List[str]:
    """Get WireGuard interface IPs."""
    wg_ips = []
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", "type", "wireguard"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for iface in data:
                for addr in iface.get('addr_info', []):
                    if addr.get('family') == 'inet':
                        wg_ips.append(addr.get('local'))
    except:
        pass
    return wg_ips


def get_node_addresses() -> List[Dict]:
    """Get all node addresses."""
    addresses = []

    lan_ip = get_lan_ip()
    if lan_ip:
        addresses.append({"type": "lan", "address": lan_ip, "port": API_PORT})

    wan_ip = get_wan_ip()
    if wan_ip:
        addresses.append({"type": "wan", "address": wan_ip, "port": API_PORT})

    for wg_ip in get_wireguard_ips():
        addresses.append({"type": "wireguard", "address": wg_ip, "port": API_PORT})

    return addresses


# ============== Master-Link Helpers ==============

def ml_init():
    """Initialize master-link directories and config."""
    ML_DIR.mkdir(parents=True, exist_ok=True)
    if not ML_CONFIG_FILE.exists():
        ml_config = {
            "enabled": True,
            "role": "master",
            "upstream": None,
            "depth": 0,
            "max_depth": ML_DEFAULT_MAX_DEPTH,
            "token_ttl": ML_DEFAULT_TOKEN_TTL,
            "auto_approve": False,
            "fingerprint": get_node_id()
        }
        save_json(ML_CONFIG_FILE, ml_config)


def get_ml_config() -> Dict:
    """Get master-link configuration."""
    ml_init()
    default = {
        "enabled": True,
        "role": "master",
        "upstream": None,
        "depth": 0,
        "max_depth": ML_DEFAULT_MAX_DEPTH,
        "token_ttl": ML_DEFAULT_TOKEN_TTL,
        "auto_approve": False,
        "fingerprint": get_node_id()
    }
    return load_json(ML_CONFIG_FILE, default)


def save_ml_config(config: Dict):
    """Save master-link configuration."""
    ml_init()
    save_json(ML_CONFIG_FILE, config)


def get_ml_tokens() -> List[Dict]:
    """Get all master-link tokens. Dans une section critique (#3362) : lecture STRICTE (503 si illisible) ; hors section
    (lectures seules) : tolérante."""
    ml_init()
    if oubli.tenu(P2P_DIR):
        return _ml_lire(ML_TOKENS_FILE)
    return load_json(ML_TOKENS_FILE, [])


def save_ml_tokens(tokens: List[Dict]):
    """Save master-link tokens."""
    ml_init()
    save_json(ML_TOKENS_FILE, tokens)


def get_ml_requests() -> List[Dict]:
    """Get all join requests. Dans une section critique (#3362) : lecture STRICTE (503 si illisible) ; hors section
    (lectures seules) : tolérante."""
    ml_init()
    if oubli.tenu(P2P_DIR):
        return _ml_lire(ML_REQUESTS_FILE)
    return load_json(ML_REQUESTS_FILE, [])


def save_ml_requests(requests: List[Dict]):
    """Save join requests."""
    ml_init()
    save_json(ML_REQUESTS_FILE, requests)


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_hex(32)


def hash_token(token: str) -> str:
    """Hash a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def ml_token_generate(ttl: int = None, token_type: str = "join", auto_approve: bool = False,
                      nom_prevu: Optional[str] = None, flash: bool = False) -> Dict:
    """Generate a new join token (le cœur vit dans jetons.py, partagé avec sbx-mesh-invite)."""
    config = get_ml_config()

    if ttl is None:
        ttl = config.get("token_ttl", ML_DEFAULT_TOKEN_TTL)

    ml_init()
    try:
        emis = jetons.generer(ttl, auto_approve, nom_prevu=nom_prevu, flash=flash,
                              token_type=token_type, chemin=ML_TOKENS_FILE)
    except oubli.EtatIllisible:                 # #3362 : tokens.json illisible n'est jamais remplacé
        raise HTTPException(status_code=503, detail="jetons de jonction illisibles : aucun jeton émis") from None
    token, token_hash, expires = emis["token"], emis["token_hash"], emis["expires"]

    # Build join URL
    lan_ip = get_lan_ip()

    return {
        "token": token,
        "token_hash": token_hash,
        "expires": expires,
        "ttl": ttl,
        "auto_approve": auto_approve,
        "url": f"http://{lan_ip}:{API_PORT}/master-link/?token={token}"
    }


def ml_token_validate(token: str, attente: Optional[float] = None) -> Dict:
    """Validate a token. `attente` : verrou pris sans bloquer, réessayé au plus `attente` s (route publique), sinon
    oubli.VerrouOccupe."""
    if not token:
        return {"valid": False, "error": "missing_token"}

    token_hash = hash_token(token)
    init_dirs()
    with oubli.verrou(P2P_DIR, attente=attente):  # #3362 : lire, marquer « expiré », écrire : une section critique
        return _ml_token_validate(get_ml_tokens(), token_hash)


def _ml_token_validate(tokens: List[Dict], token_hash: str) -> Dict:
    now = datetime.utcnow()

    for t in tokens:
        if t.get("hash") == token_hash:
            # Check status
            if t.get("status") == "used":
                return {"valid": False, "error": "token_already_used"}
            if t.get("status") == "expired":
                return {"valid": False, "error": "token_expired"}
            if t.get("status") == "revoked":
                return {"valid": False, "error": "token_revoked"}

            # Check expiry
            expires_ts = t.get("expires_ts", 0)
            if now.timestamp() > expires_ts:
                # Mark as expired
                t["status"] = "expired"
                save_ml_tokens(tokens)
                return {"valid": False, "error": "token_expired"}

            return {
                "valid": True,
                "token_hash": token_hash,
                "expires": t.get("expires"),
                "auto_approve": t.get("auto_approve", False),
                "flash": bool(t.get("flash")),
                "nom_prevu": t.get("nom_prevu"),
            }

    return {"valid": False, "error": "unknown_token"}


def ml_token_mark_used(token_hash: str, peer_fp: str):
    """Mark a token as used (section critique, #3362)."""
    init_dirs()
    with oubli.verrou(P2P_DIR):
        tokens = get_ml_tokens()
        _marquer_utilise(tokens, token_hash, peer_fp)
        save_ml_tokens(tokens)


def _marquer_utilise(tokens: List[Dict], token_hash: str, peer_fp: str) -> None:
    for t in tokens:
        if t.get("hash") == token_hash:
            t["status"] = "used"
            t["peer_fp"] = peer_fp
            t["used_by"] = peer_fp
            t["used_at"] = datetime.utcnow().isoformat()
            break


def ml_cleanup_tokens():
    """Remove expired tokens (section critique, lecture stricte : #3362)."""
    init_dirs()
    with oubli.verrou(P2P_DIR):
        return _ml_cleanup_tokens(get_ml_tokens())


def _ml_cleanup_tokens(tokens: List[Dict]) -> Dict:
    now = datetime.utcnow().timestamp()
    cleaned = 0

    active_tokens = []
    for t in tokens:
        expires_ts = t.get("expires_ts", 0)
        if now > expires_ts or t.get("status") in ["used", "expired", "revoked"]:
            cleaned += 1
        else:
            active_tokens.append(t)

    if cleaned > 0:
        save_ml_tokens(active_tokens)

    return {"cleaned": cleaned}


async def discover_mdns(timeout: int = 5) -> List[Dict]:
    """Discover SecuBox peers via mDNS/Avahi."""
    peers = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "avahi-browse", "-t", "-r", "-p", MDNS_SERVICE_TYPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 2)

        # Parse avahi-browse -p output
        # Format: +;iface;protocol;name;type;domain
        # =;iface;protocol;name;type;domain;hostname;address;port;txt
        current_service = {}
        for line in stdout.decode().split('\n'):
            parts = line.split(';')
            if len(parts) >= 8 and parts[0] == '=':
                name = parts[3]
                hostname = parts[6]
                address = parts[7]
                port = int(parts[8]) if parts[8].isdigit() else API_PORT
                # TXT publié par secubox-annuaire-noms (#1556) : « "boxname=gk3" "node_id=…" »
                txt = dict(re.findall(r'"([a-z_]+)=([^"]*)"', parts[9])) if len(parts) > 9 else {}

                peer_id = txt.get("node_id") or f"sb-{ident(address, n=12)}"
                peers.append({
                    "id": peer_id,
                    "boxname": txt.get("boxname"),
                    "mesh_ip": txt.get("mesh_ip"),
                    "name": txt.get("boxname") or name or hostname,
                    "address": address,
                    "port": port,
                    "hostname": hostname,
                    "discovered_via": "mdns",
                    "discovered_at": datetime.utcnow().isoformat(),
                    "status": "online"
                })
    except FileNotFoundError:
        pass  # avahi-browse not installed
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"mDNS discovery error: {e}")

    return peers


async def discover_network_scan(subnet: str = None, timeout: int = 5) -> List[Dict]:
    """Discover SecuBox peers via network scanning."""
    peers = []

    # Get subnet from LAN IP if not provided
    if not subnet:
        lan_ip = get_lan_ip()
        if lan_ip and lan_ip != "127.0.0.1":
            # Convert to /24 subnet
            subnet = '.'.join(lan_ip.split('.')[:3]) + '.0/24'
        else:
            return peers

    # Get ARP table
    arp_hosts = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+', line)
            # Parenthèses : « a and b or c » arrêtait le scan sur une ligne
            # STALE sans adresse (AttributeError avalé par le except) (#1556).
            if match and ('REACHABLE' in line or 'STALE' in line):
                arp_hosts.append(match.group(1))
    except:
        pass

    # Probe hosts for SecuBox
    async def probe_debian(ip: str) -> Optional[Dict]:
        """Une box SecuBox-Deb : /api/v1/p2p/status répond en JSON — le statut
        (node_id, hostname) si la lecture est ouverte, sinon le refus
        « jeton requis » propre à SecuBox. Le /cgi-bin/luci ci-dessous ne
        trouvait que des OpenWrt (#1556)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "2", "-k", f"https://{ip}/api/v1/p2p/status",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            j = json.loads(stdout.decode() or "{}")
        except Exception:  # noqa: BLE001
            return None
        if not (j.get("node_id") or "jeton" in str(j.get("detail", "")).lower()):
            return None
        return {"id": j.get("node_id") or f"sb-{ident(ip, n=12)}", "name": j.get("hostname") or "SecuBox",
                "address": ip, "port": 443, "is_secubox": True, "is_openwrt": False,
                "discovered_via": "network_scan", "discovered_at": datetime.utcnow().isoformat(), "status": "online"}

    async def probe_host(ip: str) -> Optional[Dict]:
        """Probe a single host for SecuBox."""
        d = await probe_debian(ip)
        if d:
            return d
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "2", "-k",
                f"https://{ip}/cgi-bin/luci",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            body = stdout.decode().lower()

            is_secubox = any(m in body for m in [
                'data-secubox-theme', 'luci-static/secubox',
                'secubox-portal', 'luci-app-secubox'
            ])
            is_openwrt = 'luci' in body

            if is_secubox or is_openwrt:
                # Extract name from title
                name = "SecuBox" if is_secubox else "OpenWRT"
                title_match = re.search(r'<title>([^<]+)</title>', stdout.decode(), re.I)
                if title_match:
                    name = title_match.group(1).split(' - ')[0].strip()

                peer_id = f"sb-{ident(ip, n=12)}"
                return {
                    "id": peer_id,
                    "name": name,
                    "address": ip,
                    "port": 443,
                    "is_secubox": is_secubox,
                    "is_openwrt": is_openwrt,
                    "discovered_via": "network_scan",
                    "discovered_at": datetime.utcnow().isoformat(),
                    "status": "online"
                }
        except:
            pass
        return None

    # Probe all ARP hosts concurrently
    if arp_hosts:
        tasks = [probe_host(ip) for ip in arp_hosts[:50]]  # Limit to 50 hosts
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, dict):
                peers.append(result)

    return peers


async def discover_peers(method: str = "all", timeout: int = 5) -> Dict:
    """Discover peers using specified method."""
    all_peers = []

    if method in ["all", "mdns"]:
        mdns_peers = await discover_mdns(timeout)
        all_peers.extend(mdns_peers)

    if method in ["all", "scan"]:
        scan_peers = await discover_network_scan(timeout=timeout)
        # Add only peers not already found via mDNS
        existing_addrs = {p["address"] for p in all_peers}
        for peer in scan_peers:
            if peer["address"] not in existing_addrs:
                all_peers.append(peer)

    # Deduplicate by address
    seen = set()
    unique_peers = []
    for peer in all_peers:
        if peer["address"] not in seen:
            seen.add(peer["address"])
            unique_peers.append(peer)

    return {
        "discovered": unique_peers,
        "count": len(unique_peers),
        "method": method,
        "timestamp": datetime.utcnow().isoformat()
    }


def get_self_peer() -> Dict:
    """Get local node as peer entry."""
    return {
        "id": get_node_id(),
        "name": f"{get_hostname()} (local)",
        "address": get_lan_ip(),
        "wan_address": get_wan_ip(),
        "wg_addresses": get_wireguard_ips(),
        "addresses": get_node_addresses(),
        "status": "online",
        "is_local": True,
        "added": datetime.utcnow().isoformat()
    }


# ============== Pydantic Models ==============

class PeerRequest(BaseModel):
    address: str
    name: Optional[str] = None
    wan_address: Optional[str] = None
    wg_address: Optional[str] = None


class ServiceRequest(BaseModel):
    name: str
    port: int
    protocol: str = "tcp"
    description: Optional[str] = None


class ProfileRequest(BaseModel):
    name: str
    settings: Dict[str, Any] = {}


class ThreatRequest(BaseModel):
    ip: str
    reason: str
    severity: str = "medium"


class DiscoverRequest(BaseModel):
    method: str = "all"  # all, mdns, scan
    timeout: int = 5


class JoinRequest(BaseModel):
    token: str
    fingerprint: str
    hostname: Optional[str] = None
    address: Optional[str] = None
    # LA CLÉ WIREGUARD DU PAIR (#1360). Sans elle, la jonction inscrivait le
    # pair au registre et s'arrêtait là : aucun tunnel ne pouvait se former.
    # Optionnelle pour rester compatible avec les anciens scripts et les
    # maîtres OpenWrt ; un pair qui ne l'envoie pas est inscrit sans transport.
    wg_public_key: Optional[str] = None
    wg_port: Optional[int] = None


class ApproveRequest(BaseModel):
    fingerprint: str
    action: str  # approve, reject, promote
    reason: Optional[str] = None


class TokenGenerateRequest(BaseModel):
    ttl: Optional[int] = None
    token_type: str = "join"
    auto_approve: bool = False


# ============== Status ==============

@app.get("/status", dependencies=[Depends(require_lecture)])
def get_status():
    """Get P2P network status (public)."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    services = load_json(SERVICES_FILE, [])
    threats = load_json(THREATS_FILE, {})

    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data
    # A node is not its own peer — exclude the local entry from the counts
    # (older versions persisted get_self_peer() into PEERS_FILE, inflating these).
    local_id = get_node_id()
    peers = [p for p in peers if not p.get("is_local") and p.get("id") != local_id]

    # Mesh view is driven by the wg-mesh transport (wg_mesh.json), which p2p
    # now owns (Gondwana Phase 1). The web UI reads total_peers/active_peers.
    # CONFIGURÉS ET VIVANTS NE SONT PAS LA MÊME CHOSE (#1360). `online_peers`
    # valait le nombre de pairs configurés : gk2 annonçait deux pairs en ligne
    # qui n'avaient jamais établi de poignée de main. On compte désormais ceux
    # dont la dernière poignée de main est récente — et, si la mesure manque,
    # on le DIT (`liveness: unavailable`) au lieu de supposer.
    handshakes = mesh.load_handshakes()
    wg_state = get_wg_mesh_config()
    wg_nodes = mesh.peer_nodes(wg_state, handshakes)
    # #3362 : le registre hérité aussi est MESURÉ (poignée de main du pair wg-mesh de même adresse), jamais son « online » écrit.
    online_peers = [p for p in mesh.statut_registre(peers, wg_state, handshakes) if p.get("status") == "online"]
    wg_peer_count = len(wg_nodes)
    wg_online = sum(1 for n in wg_nodes if n["status"] == "online")

    # Get master-link status
    ml_config = get_ml_config()

    return {
        "online": True,
        "node_id": get_node_id(),
        "hostname": get_hostname(),
        "lan_ip": get_lan_ip(),
        "wan_ip": get_wan_ip(),
        "peer_count": wg_peer_count or len(peers),
        "online_peers": wg_online if wg_peer_count else len(online_peers),
        "total_peers": wg_peer_count or len(peers),
        "active_peers": wg_online if wg_peer_count else len(online_peers),
        "liveness": "measured" if handshakes is not None else "unavailable",
        "service_count": len(services) if isinstance(services, list) else 0,
        "threat_count": len(threats) if isinstance(threats, dict) else 0,
        "master_link": {
            "role": ml_config.get("role", "master"),
            "depth": ml_config.get("depth", 0),
            "upstream": ml_config.get("upstream")
        },
        "version": "1.3.0"
    }


# ============== Peer Discovery ==============

@app.get("/discover", dependencies=[Depends(require_lecture)])
async def discover_get(method: str = "all", timeout: int = 5):
    """Discover peers (public read)."""
    return await discover_peers(method, timeout)


@app.post("/discover")
async def discover_post(req: DiscoverRequest, user: dict = Depends(require_jwt)):
    """Discover and optionally add peers."""
    result = await discover_peers(req.method, req.timeout)

    # Optionally auto-add discovered peers
    if result["discovered"]:
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_ids = {p.get("id") for p in peers}

        added = 0
        for peer in result["discovered"]:
            if peer["id"] not in existing_ids and not peer.get("is_local"):
                peers.append(peer)
                added += 1

        if added > 0:
            await asyncio.to_thread(save_json, PEERS_FILE, {"peers": peers})  # #3362 : verrou hors de la boucle
            result["added"] = added

    return result


@app.get("/discover/self", dependencies=[Depends(require_lecture)])
async def get_self():
    """Get local node info for announcement."""
    return get_self_peer()


# ============== Peers ==============

@app.get("/peers", dependencies=[Depends(require_lecture)])
async def list_peers():
    """List all known peers (public read).

    The wg-mesh transport (wg_mesh.json) is the source of truth for the mesh
    view (Gondwana Phase 1); fall back to the legacy peers.json registry only
    when there are no wg-mesh peers configured.
    """
    init_dirs()
    wg_state, handshakes = get_wg_mesh_config(), mesh.load_handshakes()
    nodes = mesh.peer_nodes(wg_state, handshakes)
    if nodes:
        return {"peers": nodes, "count": len(nodes)}

    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data
    # A node is not its own peer: never insert/persist the local node here.
    local_id = get_node_id()
    peers = [p for p in peers if not p.get("is_local") and p.get("id") != local_id]
    peers = mesh.statut_registre(peers, wg_state, handshakes)          # #3362 : statut mesuré, jamais la valeur écrite
    return {"peers": peers, "count": len(peers)}


@app.post("/peers")
def add_peer(req: PeerRequest, user: dict = Depends(require_jwt)):
    """Add a new peer manually."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer_id = f"sb-{ident(req.address, n=12)}"

    # Check if already exists
    if any(p.get("id") == peer_id or p.get("address") == req.address for p in peers):
        raise HTTPException(status_code=400, detail="Peer already exists")

    # Build addresses
    addresses = [{"type": "lan", "address": req.address, "port": API_PORT}]
    if req.wan_address:
        addresses.append({"type": "wan", "address": req.wan_address, "port": API_PORT})
    if req.wg_address:
        addresses.append({"type": "wireguard", "address": req.wg_address, "port": API_PORT})

    peer = {
        "id": peer_id,
        "name": req.name or f"Peer@{req.address}",
        "address": req.address,
        "wan_address": req.wan_address,
        "wg_address": req.wg_address,
        "addresses": addresses,
        "added": datetime.utcnow().isoformat(),
        "status": "pending"
    }
    peers.append(peer)
    save_json(PEERS_FILE, {"peers": peers})
    return {"status": "ok", "peer": peer}


@app.delete("/peers/{peer_id}")
def remove_peer(peer_id: str, user: dict = Depends(require_jwt)):
    """Remove a peer."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    # Don't allow removing local node
    local_id = get_node_id()
    if peer_id == local_id:
        raise HTTPException(status_code=400, detail="Cannot remove local node")

    original_count = len(peers)
    peers = [p for p in peers if p.get('id') != peer_id]

    if len(peers) == original_count:
        raise HTTPException(status_code=404, detail="Peer not found")

    save_json(PEERS_FILE, {"peers": peers})
    return {"status": "ok", "removed": peer_id}


@app.post("/peers/{peer_id}/probe")
async def probe_peer(peer_id: str, user: dict = Depends(require_jwt)):
    """Probe a peer to check if it's online."""
    init_dirs()
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer = next((p for p in peers if p.get("id") == peer_id), None)
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found")

    address = peer.get("address")
    if not address:
        raise HTTPException(status_code=400, detail="Peer has no address")

    # Probe the peer
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "3", "-k",
            f"https://{address}/api/v1/p2p/status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)

        if proc.returncode == 0:
            try:
                data = json.loads(stdout.decode())
                peer["status"] = "online"
                peer["last_seen"] = datetime.utcnow().isoformat()
                peer["remote_info"] = data
            except:
                peer["status"] = "online"
                peer["last_seen"] = datetime.utcnow().isoformat()
        else:
            peer["status"] = "offline"
    except:
        peer["status"] = "offline"

    await asyncio.to_thread(save_json, PEERS_FILE, {"peers": peers})  # #3362 : verrou hors de la boucle
    return {"status": "ok", "peer": peer}


# ============== Services ==============

@app.get("/services", dependencies=[Depends(require_lecture)])
async def list_services():
    """Live view: annuaire catalog ⨝ my subscriptions ⨝ activation overlay ⨝ legacy."""
    init_dirs()
    local_did, _ = annuaire_client.node_identity()
    catalog, cat_err = annuaire_client.get_catalog()
    subs, _ = annuaire_client.get_subscriptions(local_did)
    overlay = registry.load_overlay(str(ACTIVATION_FILE))
    legacy = load_json(SERVICES_FILE, [])
    legacy = legacy if isinstance(legacy, list) else []
    rows = registry.merge_services(catalog, subs, overlay, legacy, local_did)
    out = {"services": rows}
    if cat_err:
        out["catalog_unavailable"] = True
        out["catalog_error"] = cat_err
    return out


@app.post("/services")
def register_service(req: ServiceRequest, user: dict = Depends(require_jwt)):
    """Register a P2P service."""
    init_dirs()
    services = load_json(SERVICES_FILE, [])
    if not isinstance(services, list):
        services = []

    service = {
        "name": req.name,
        "port": req.port,
        "protocol": req.protocol,
        "description": req.description,
        "registered": datetime.utcnow().isoformat(),
        "active": True
    }
    services.append(service)
    save_json(SERVICES_FILE, services)
    return {"status": "ok", "service": service}


@app.delete("/services/{name}")
def unregister_service(name: str, user: dict = Depends(require_jwt)):
    """Unregister a service."""
    init_dirs()
    services = load_json(SERVICES_FILE, [])
    if isinstance(services, list):
        services = [s for s in services if s.get('name') != name]
        save_json(SERVICES_FILE, services)
    return {"status": "ok"}


@app.post("/services/auto-register")
async def auto_register(user: dict = Depends(require_jwt)):
    """Activate local catalog services + subscribe to remote ones (per approval mode)."""
    init_dirs()
    local_did, priv = annuaire_client.node_identity()
    catalog, cat_err = annuaire_client.get_catalog()
    if cat_err:
        return {"activated": 0, "requested": 0, "pending": 0, "already": 0,
                "errors": [cat_err]}
    subs, _ = annuaire_client.get_subscriptions(local_did)
    subscribed = {s.get("service_id") for s in subs}
    overlay = registry.load_overlay(str(ACTIVATION_FILE))
    activated = requested = pending = already = 0
    errors = []
    for offer in catalog:
        sid = offer.get("service_id")
        if not sid:
            continue
        if offer.get("provider") == local_did:
            registry.set_active(str(ACTIVATION_FILE), sid,
                                registry.port_from_endpoint(offer.get("endpoint", "")))
            activated += 1
            continue
        if sid in subscribed or (overlay.get(sid, {}).get("subscription_id")):
            already += 1
            continue
        if not priv or not local_did:
            errors.append(f"{sid}: node has no annuaire identity (run annuairectl init)")
            continue
        res, err = annuaire_client.subscribe(sid, local_did, priv)
        if err:
            errors.append(f"{sid}: {err}")
            continue
        registry.set_subscription(str(ACTIVATION_FILE), sid, res.get("subscription_id", ""))
        requested += 1
        if res.get("state") == "pending":
            pending += 1
    return {"activated": activated, "requested": requested, "pending": pending,
            "already": already, "errors": errors}


@app.post("/services/{service_id}/request")
async def request_access(service_id: str, user: dict = Depends(require_jwt)):
    """Subscribe to a single remote service offer."""
    init_dirs()
    local_did, priv = annuaire_client.node_identity()
    if not priv or not local_did:
        return {"status": "error", "error": "node has no annuaire identity (run annuairectl init)"}
    res, err = annuaire_client.subscribe(service_id, local_did, priv)
    if err:
        return {"status": "error", "error": err}
    registry.set_subscription(str(ACTIVATION_FILE), service_id, res.get("subscription_id", ""))
    return {"status": "ok", "subscription": res}


def _get_our_mesh_ip() -> Optional[str]:
    """Return the local wg-mesh IP (10.10.0.x), or None if not configured."""
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", mesh.MESH_INTERFACE],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", result.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    # Fall back to wg_mesh.json address field
    cfg = get_wg_mesh_config()
    addr = (cfg.get("address") or "").split("/")[0]
    return addr if addr and addr.startswith("10.") else None


def _provider_mesh_ip_from_offer(offer: Dict) -> Optional[str]:
    """Derive the provider's mesh IP from the offer endpoint or the wg_mesh peers list.

    Priority:
    1. If the offer endpoint host is already 10.10.0.x use it directly.
    2. Otherwise scan wg_mesh.json peers for one whose mesh_ip matches the
       endpoint host (LAN/WAN IP).  Not implemented here — provider mesh IP
       resolution via offer endpoint host is the canonical path for M2.
    """
    endpoint = offer.get("endpoint", "")
    # Strip scheme
    host = endpoint
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]
    if re.match(r"^10\.10\.0\.\d+$", host):
        return host
    # Try wg_mesh peers: find a peer whose allowed_ips /32 host matches endpoint host
    try:
        cfg = get_wg_mesh_config()
        for p in cfg.get("peers", []):
            peer_ip = p.get("mesh_ip") or ""
            if peer_ip and peer_ip == host:
                return peer_ip
            # Try /32 host from allowed_ips
            aips = p.get("allowed_ips", "")
            if aips:
                h = aips.split(",")[0].strip()
                if h.endswith("/32") and h.split("/")[0] == host:
                    return h.split("/")[0]
    except Exception:
        pass
    return None


def _pull_grant(offer: Dict) -> tuple:
    """Pull a macro grant credential from the provider over the mesh.

    Builds a self-signed Subscription and POSTs it to the provider's mesh
    endpoint at :8798/api/v1/p2p-macro/grant/<service_id>.

    The Subscription signing exactly mirrors annuaire/verbs.py::subscribe():
      payload = sub.model_dump() minus {"sig","signer_did"}
      sig_hex = ed25519_sign(priv, canonical_bytes(payload))
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",",":")).encode("utf-8")

    subscriber_pubkey is added to the POST body but NOT included in the signed
    payload (it is not part of the Subscription model — mirrors _verify_subscription_sig).

    Returns:
        (cred_dict, None) on success, or (None, error_string) on any failure.
        Never raises.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        service_id = offer.get("service_id", "")

        # 1. Get our node identity.
        did, priv_hex = annuaire_client.node_identity()
        if not did or not priv_hex:
            return None, "node has no annuaire identity (run annuairectl init)"

        # 2. Derive the provider mesh IP.
        provider_ip = _provider_mesh_ip_from_offer(offer)
        if not provider_ip:
            return None, f"cannot resolve provider mesh IP from offer endpoint: {offer.get('endpoint')!r}"

        # 3. Build the Subscription payload (mirrors Subscription model fields).
        now_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        subscription_id = secrets.token_hex(32)
        payload: Dict = {
            "subscription_id": subscription_id,
            "subscriber": did,
            "service_id": service_id,
            "requested_at": now_utc,
            "sig": None,
            "signer_did": None,
        }
        # Strip sig/signer_did for signing (mirrors verbs.py subscribe()).
        to_sign = {k: v for k, v in payload.items() if k not in ("sig", "signer_did")}
        canonical = json.dumps(to_sign, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # 4. Sign with ed25519.
        priv_bytes = bytes.fromhex(priv_hex)
        priv_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig_bytes = priv_key.sign(canonical)
        sig_hex = sig_bytes.hex()
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pub_hex = pub_bytes.hex()

        # 5. POST to provider mesh grant endpoint (TCP HTTP, 5s timeout).
        body_dict = {
            **to_sign,
            "sig": sig_hex,
            "signer_did": did,
            "subscriber_pubkey": pub_hex,
        }
        body_bytes = json.dumps(body_dict).encode("utf-8")
        import http.client as _http
        conn = _http.HTTPConnection(provider_ip, 8798, timeout=5)
        conn.request(
            "POST",
            f"/api/v1/p2p-macro/grant/{service_id}",
            body=body_bytes,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        if resp.status >= 400:
            try:
                err_body = json.loads(raw)
                return None, f"provider returned HTTP {resp.status}: {err_body.get('error', raw.decode()[:200])}"
            except Exception:
                return None, f"provider returned HTTP {resp.status}"
        cred = json.loads(raw)
        return cred, None
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _macroctl_activate(kind: str, cred: Dict) -> tuple:
    """Run ``sudo -n secubox-macroctl <kind> activate --cred <json>``.

    Mirrors macro_grant.run_grant() pattern.

    Returns:
        (True, None) on success, or (False, error_string) on failure.
        Never raises.
    """
    cmd = [
        "sudo", "-n", "/usr/sbin/secubox-macroctl",
        kind, "activate",
        "--cred", json.dumps(cred),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "macroctl activate failed").strip()
    return True, None


def _macroctl_revoke(kind: str, sub_did: str, src_ip: str) -> tuple:
    """Run ``sudo -n secubox-macroctl <kind> revoke --sub <did> --src-ip <ip>``.

    Returns:
        (True, None) on success, or (False, error_string) on failure.
        Never raises.
    """
    cmd = [
        "sudo", "-n", "/usr/sbin/secubox-macroctl",
        kind, "revoke",
        "--sub", sub_did,
        "--src-ip", src_ip,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "macroctl revoke failed").strip()
    return True, None


@app.post("/services/{service_id}/activate")
async def activate_service(service_id: str, user: dict = Depends(require_jwt)):
    """Mark a catalog service locally active (binds the derived local port).

    M1 path (local own service, or non-macro remote approved): sets overlay active.
    M2 path (remote macro offer, approved): pulls grant credential from provider
    over the mesh, runs macroctl activate, stores endpoint in overlay.
    """
    init_dirs()
    catalog, _ = annuaire_client.get_catalog()
    offer = next((o for o in catalog if o.get("service_id") == service_id), None)
    if offer is None:
        return {"status": "error", "error": "service not in catalog"}
    local_did, _ = annuaire_client.node_identity()

    is_remote = offer.get("provider") != local_did
    has_macro = bool(offer.get("macro"))

    if is_remote:
        subs, _ = annuaire_client.get_subscriptions(local_did)
        st = next((s.get("state") for s in subs if s.get("service_id") == service_id), None)
        if st != "approved":
            return {"status": "error", "error": f"remote service not approved (state={st})"}

        # M2: remote macro offer with approved subscription → pull credential + activate.
        if has_macro:
            cred, err = _pull_grant(offer)
            if err:
                return {"status": "error", "error": f"pull grant failed: {err}"}
            kind = offer["macro"].get("kind", "")
            ok, aerr = _macroctl_activate(kind, cred)
            if not ok:
                return {"status": "error", "error": f"macroctl activate failed: {aerr}"}
            endpoint = cred.get("endpoint", offer.get("endpoint", ""))
            registry.set_active(str(ACTIVATION_FILE), service_id,
                                registry.port_from_endpoint(endpoint),
                                endpoint=endpoint or None)
            return {"status": "ok", "endpoint": endpoint}

    # M1 path: local service or non-macro remote approved service.
    registry.set_active(str(ACTIVATION_FILE), service_id,
                        registry.port_from_endpoint(offer.get("endpoint", "")))
    return {"status": "ok"}


@app.post("/services/{service_id}/revoke-access")
async def revoke_access(service_id: str, user: dict = Depends(require_jwt)):
    """Revoke consumer access to a macro service (consumer-side).

    Runs ``sudo macroctl <kind> revoke --sub <our-did> --src-ip <our-mesh-ip>``
    and clears the local active state in the overlay.
    """
    init_dirs()
    catalog, _ = annuaire_client.get_catalog()
    offer = next((o for o in catalog if o.get("service_id") == service_id), None)
    if offer is None:
        return {"status": "error", "error": "service not in catalog"}

    macro = offer.get("macro")
    if not macro:
        return {"status": "error", "error": "service has no macro descriptor"}

    kind = macro.get("kind", "")
    local_did, _ = annuaire_client.node_identity()
    our_mesh_ip = _get_our_mesh_ip()

    if not (our_mesh_ip and our_mesh_ip.startswith("10.10.0.")):
        return JSONResponse({"error": "node has no wg-mesh IP; cannot revoke"}, status_code=409)

    ok, err = _macroctl_revoke(kind, local_did or "", our_mesh_ip)
    if not ok:
        log.warning("macroctl revoke failed for %s: %s", service_id, err)
        return {"status": "error", "error": f"macroctl revoke failed: {err}"}

    # Clear the active state in the overlay.
    overlay = registry.load_overlay(str(ACTIVATION_FILE))
    entry = overlay.get(service_id, {})
    entry["active"] = False
    overlay[service_id] = entry
    registry.save_overlay(str(ACTIVATION_FILE), overlay)

    return {"status": "ok"}


# ============== Mesh Network ==============

@app.get("/mesh", dependencies=[Depends(require_lecture)])
async def get_mesh_status():
    """Get mesh network topology (public read).

    Derived from the wg-mesh transport (wg_mesh.json) that p2p owns
    (Gondwana Phase 1): the local node is the center, each wg peer is a node,
    links go from local to each peer (hub-and-spoke). Falls back to the
    legacy peers.json registry when no wg-mesh peers are configured.
    """
    init_dirs()
    wg = get_wg_mesh_config()
    peer_views = mesh.peer_nodes(wg, mesh.load_handshakes())
    local_id = get_node_id()

    if peer_views:
        local_addr = (wg.get("address") or "").split("/")[0]
        local_node = {
            "id": local_id,
            "name": get_hostname(),
            "address": local_addr,
            "status": "online",
            "is_local": True,
        }
        nodes = [local_node]
        links = []
        for pv in peer_views:
            nodes.append({**pv, "is_local": False})
            links.append({"source": local_id, "target": pv["id"], "status": pv.get("status", "online")})
        return {"nodes": nodes, "links": links, "total_nodes": len(nodes), "local_node": local_id}

    # Legacy fallback (peers.json registry)
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else peers_data
    nodes = []
    links = []
    for peer in peers:
        node = {
            "id": peer.get('id', ''),
            "name": peer.get('name', 'Unknown'),
            "address": peer.get('address', ''),
            "status": peer.get('status', 'unknown'),
            "is_local": peer.get('is_local', False) or peer.get('id') == local_id
        }
        nodes.append(node)
        if not node["is_local"]:
            links.append({"source": local_id, "target": peer.get('id'), "status": peer.get('status', 'unknown')})
    return {"nodes": nodes, "links": links, "total_nodes": len(nodes), "local_node": local_id}


# ============== Profiles ==============

@app.get("/profiles", dependencies=[Depends(require_lecture)])
async def list_profiles():
    """List P2P profiles."""
    init_dirs()
    profiles = load_json(PROFILES_FILE, {})
    return {"profiles": profiles if isinstance(profiles, dict) else {}}


@app.post("/profiles")
def create_profile(req: ProfileRequest, user: dict = Depends(require_jwt)):
    """Create a P2P profile."""
    init_dirs()
    profiles = load_json(PROFILES_FILE, {})
    if not isinstance(profiles, dict):
        profiles = {}

    profiles[req.name] = {
        "name": req.name,
        "settings": req.settings,
        "created": datetime.utcnow().isoformat()
    }
    save_json(PROFILES_FILE, profiles)
    return {"status": "ok", "profile": profiles[req.name]}


@app.delete("/profiles/{name}")
def delete_profile(name: str, user: dict = Depends(require_jwt)):
    """Delete a profile."""
    init_dirs()
    profiles = load_json(PROFILES_FILE, {})
    if isinstance(profiles, dict) and name in profiles:
        del profiles[name]
        save_json(PROFILES_FILE, profiles)
    return {"status": "ok"}


# ============== Threat Intelligence ==============

@app.get("/threats", dependencies=[Depends(require_lecture)])
async def list_threats():
    """List threat intelligence entries (public read)."""
    init_dirs()
    threats = load_json(THREATS_FILE, {})
    return {"threats": threats if isinstance(threats, dict) else {}}


@app.post("/threats")
def report_threat(req: ThreatRequest, user: dict = Depends(require_jwt)):
    """Report a threat."""
    init_dirs()
    threats = load_json(THREATS_FILE, {})
    if not isinstance(threats, dict):
        threats = {}

    threats[req.ip] = {
        "ip": req.ip,
        "reason": req.reason,
        "severity": req.severity,
        "reported": datetime.utcnow().isoformat(),
        "reporter": user.get('sub', 'anonymous')
    }
    save_json(THREATS_FILE, threats)
    return {"status": "ok", "threat": threats[req.ip]}


@app.delete("/threats/{ip}")
def remove_threat(ip: str, user: dict = Depends(require_jwt)):
    """Remove a threat entry."""
    init_dirs()
    threats = load_json(THREATS_FILE, {})
    if isinstance(threats, dict) and ip in threats:
        del threats[ip]
        save_json(THREATS_FILE, threats)
    return {"status": "ok"}


# ============== WireGuard Mesh ==============

WG_MESH_CONFIG = P2P_DIR / "wg_mesh.json"
WG_INTERFACE = mesh.MESH_INTERFACE
WG_PORT = mesh.MESH_PORT
WG_NETWORK = mesh.MESH_NETWORK


def get_wg_mesh_config() -> Dict:
    """Get WireGuard mesh configuration."""
    default = {
        "enabled": False,
        "interface": WG_INTERFACE,
        "listen_port": WG_PORT,
        "network": WG_NETWORK,
        "private_key": None,
        "public_key": None,
        "peers": []
    }
    return load_json(WG_MESH_CONFIG, default)


def generate_wg_keypair() -> tuple:
    """Generate WireGuard keypair."""
    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, timeout=5)
        private_key = priv.stdout.strip()

        pub = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True, timeout=5)
        public_key = pub.stdout.strip()

        return private_key, public_key
    except:
        return None, None


@app.get("/wireguard", dependencies=[Depends(require_lecture)])
def get_wireguard_status():
    """Get WireGuard mesh status (public read)."""
    config = get_wg_mesh_config()

    # Get actual interface status
    wg_status = {"running": False, "peers": []}
    try:
        result = subprocess.run(
            ["wg", "show", WG_INTERFACE],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            wg_status["running"] = True
            # Parse peers
            for line in result.stdout.split('\n'):
                if line.startswith('peer:'):
                    wg_status["peers"].append({"public_key": line.split(':')[1].strip()})
    except:
        pass

    return {
        "config": {
            "enabled": config.get("enabled", False),
            "interface": config.get("interface", WG_INTERFACE),
            "listen_port": config.get("listen_port", WG_PORT),
            "network": config.get("network", WG_NETWORK),
            "public_key": config.get("public_key"),
            "peer_count": len(config.get("peers", []))
        },
        "status": wg_status
    }


@app.post("/wireguard/init")
def init_wireguard(user: dict = Depends(require_jwt)):
    """Initialize WireGuard mesh interface."""
    config = get_wg_mesh_config()

    # Generate keypair if not exists
    if not config.get("private_key"):
        private_key, public_key = generate_wg_keypair()
        if not private_key:
            raise HTTPException(status_code=500, detail="Failed to generate WireGuard keys")
        config["private_key"] = private_key
        config["public_key"] = public_key

    # Assign mesh IP: .1 for the master role, else allocate from the pool.
    p2p_cfg = mesh.load_p2p_config(CONFIG_FILE)
    if p2p_cfg["role"] == "master":
        addr = "10.10.0.1"
    else:
        taken = [p.get("allowed_ips", "") for p in config.get("peers", [])]
        addr = mesh.allocate_mesh_ip(WG_NETWORK, taken)
    config["address"] = f"{addr}/24"
    config["role"] = p2p_cfg["role"]
    config["ddns"] = mesh.ddns_name(get_hostname())

    save_json(WG_MESH_CONFIG, config)

    return {
        "status": "ok",
        "public_key": config["public_key"],
        "address": config["address"],
        "listen_port": config.get("listen_port", WG_PORT)
    }


@app.post("/wireguard/peer")
def add_wireguard_peer(
    public_key: str,
    endpoint: str,
    allowed_ips: str = "10.10.0.0/24",
    user: dict = Depends(require_jwt)
):
    """Add a WireGuard mesh peer."""
    config = get_wg_mesh_config()
    peers = config.get("peers", [])

    # Check if already exists
    if any(p.get("public_key") == public_key for p in peers):
        raise HTTPException(status_code=400, detail="Peer already exists")

    peer = {
        "public_key": public_key,
        "endpoint": endpoint,
        "allowed_ips": allowed_ips,
        "added": datetime.utcnow().isoformat()
    }
    peers.append(peer)
    config["peers"] = peers
    save_json(WG_MESH_CONFIG, config)

    return {"status": "ok", "peer": peer}


@app.post("/wireguard/enable")
def enable_wireguard(user: dict = Depends(require_jwt)):
    """Enable and start WireGuard mesh interface."""
    config = get_wg_mesh_config()

    if not config.get("private_key"):
        raise HTTPException(status_code=400, detail="WireGuard not initialized")

    bad = mesh.subnet_overlap(config.get("network", WG_NETWORK))
    if bad:
        raise HTTPException(status_code=409,
            detail=f"mesh network overlaps reserved subnet {bad!r}; refusing")

    if not config.get("address"):
        raise HTTPException(status_code=400,
            detail="WireGuard not initialized (no address); run /wireguard/init first")

    # Provisioning (wg-quick, /etc/wireguard write) is delegated to the root
    # CLI sbx-mesh-up; this unprivileged endpoint only marks the intent.
    config["enabled"] = True
    save_json(WG_MESH_CONFIG, config)

    return {"status": "ok", "message": "mesh marked enabled; run 'sbx-mesh-up' as root to provision the interface"}


# ============== Remote Announcers ==============

ANNOUNCERS_FILE = P2P_DIR / "announcers.json"


def get_announcers() -> List[Dict]:
    """Get list of remote announcer servers."""
    return load_json(ANNOUNCERS_FILE, [])


@app.get("/announcers", dependencies=[Depends(require_lecture)])
async def list_announcers():
    """List remote announcer servers (public read)."""
    announcers = get_announcers()
    return {"announcers": announcers, "count": len(announcers)}


@app.post("/announcers")
def add_announcer(
    url: str,
    name: Optional[str] = None,
    user: dict = Depends(require_jwt)
):
    """Add a remote announcer server."""
    announcers = get_announcers()

    if any(a.get("url") == url for a in announcers):
        raise HTTPException(status_code=400, detail="Announcer already exists")

    announcer = {
        "id": ident(url, n=12),
        "url": url,
        "name": name or url,
        "added": datetime.utcnow().isoformat(),
        "status": "unknown",
        "last_sync": None
    }
    announcers.append(announcer)
    save_json(ANNOUNCERS_FILE, announcers)

    return {"status": "ok", "announcer": announcer}


@app.delete("/announcers/{announcer_id}")
def remove_announcer(announcer_id: str, user: dict = Depends(require_jwt)):
    """Remove an announcer server."""
    announcers = get_announcers()
    announcers = [a for a in announcers if a.get("id") != announcer_id]
    save_json(ANNOUNCERS_FILE, announcers)
    return {"status": "ok"}


@app.post("/announcers/sync")
async def sync_with_announcers(user: dict = Depends(require_jwt)):
    """Sync peer list with all remote announcers."""
    announcers = get_announcers()
    results = []
    all_remote_peers = []

    for announcer in announcers:
        url = announcer.get("url", "").rstrip('/')
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "5", "-k",
                f"{url}/api/v1/p2p/peers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            if proc.returncode == 0:
                data = json.loads(stdout.decode())
                peers = data.get("peers", [])
                announcer["status"] = "online"
                announcer["last_sync"] = datetime.utcnow().isoformat()
                announcer["peer_count"] = len(peers)

                # Add remote peers (exclude local nodes)
                for peer in peers:
                    if not peer.get("is_local"):
                        peer["discovered_via"] = f"announcer:{announcer['id']}"
                        peer["announcer_url"] = url
                        all_remote_peers.append(peer)

                results.append({"announcer": announcer["url"], "status": "ok", "peers": len(peers)})
            else:
                announcer["status"] = "error"
                results.append({"announcer": announcer["url"], "status": "error"})
        except Exception as e:
            announcer["status"] = "error"
            results.append({"announcer": announcer["url"], "status": "error", "error": str(e)})

    await asyncio.to_thread(save_json, ANNOUNCERS_FILE, announcers)  # #3362 : verrou hors de la boucle

    # Merge remote peers with local peers
    if all_remote_peers:
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_addrs = {p.get("address") for p in peers}

        added = 0
        for peer in all_remote_peers:
            if peer.get("address") and peer["address"] not in existing_addrs:
                peers.append(peer)
                existing_addrs.add(peer["address"])
                added += 1

        if added > 0:
            await asyncio.to_thread(save_json, PEERS_FILE, {"peers": peers})  # #3362 : verrou hors de la boucle

        results.append({"merged": added, "total_remote_peers": len(all_remote_peers)})

    return {"status": "ok", "results": results}


@app.post("/announce")
async def announce_self(user: dict = Depends(require_jwt)):
    """Announce local node to all remote announcers."""
    announcers = get_announcers()
    self_peer = get_self_peer()
    results = []

    for announcer in announcers:
        url = announcer.get("url", "").rstrip('/')
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--connect-timeout", "5", "-k",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({
                    "address": self_peer["address"],
                    "name": self_peer["name"],
                    "wan_address": self_peer.get("wan_address"),
                    "wg_address": self_peer.get("wg_addresses", [None])[0] if self_peer.get("wg_addresses") else None
                }),
                f"{url}/api/v1/p2p/peers",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            if proc.returncode == 0:
                results.append({"announcer": url, "status": "ok"})
            else:
                results.append({"announcer": url, "status": "error"})
        except Exception as e:
            results.append({"announcer": url, "status": "error", "error": str(e)})

    return {"status": "ok", "results": results}


# ============== Bridge Discovery ==============

@app.post("/discover/bridge")
async def discover_via_bridge(
    bridge_peer: str,
    user: dict = Depends(require_jwt)
):
    """Discover peers through a bridge peer (multi-hop discovery)."""
    # Query the bridge peer for its known peers
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "5", "-k",
            f"https://{bridge_peer}/api/v1/p2p/peers",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

        if proc.returncode != 0:
            raise HTTPException(status_code=502, detail="Failed to reach bridge peer")

        data = json.loads(stdout.decode())
        remote_peers = data.get("peers", [])

        # Mark as discovered via bridge
        for peer in remote_peers:
            peer["discovered_via"] = f"bridge:{bridge_peer}"
            peer["bridge_peer"] = bridge_peer

        # Optionally add to local peer list
        peers_data = load_json(PEERS_FILE, {"peers": []})
        peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []
        existing_addrs = {p.get("address") for p in peers}

        added = 0
        for peer in remote_peers:
            if peer.get("address") and peer["address"] not in existing_addrs and not peer.get("is_local"):
                peers.append(peer)
                existing_addrs.add(peer["address"])
                added += 1

        if added > 0:
            await asyncio.to_thread(save_json, PEERS_FILE, {"peers": peers})  # #3362 : verrou hors de la boucle

        return {
            "status": "ok",
            "bridge_peer": bridge_peer,
            "discovered": len(remote_peers),
            "added": added,
            "peers": remote_peers
        }
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Invalid response from bridge peer")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Bridge peer timeout")


# ============== Master-Link ==============

@app.get("/master-link/status", dependencies=[Depends(require_lecture)])
def ml_status():
    """Get master-link status (public read)."""
    config = get_ml_config()
    requests = get_ml_requests()
    tokens = get_ml_tokens()

    # Count by status
    pending = sum(1 for r in requests if r.get("status") == "pending")
    approved = sum(1 for r in requests if r.get("status") == "approved")
    rejected = sum(1 for r in requests if r.get("status") == "rejected")

    # Count active tokens
    now = datetime.utcnow().timestamp()
    active_tokens = sum(1 for t in tokens
                       if t.get("status") == "active" and t.get("expires_ts", 0) > now)

    return {
        "enabled": config.get("enabled", True),
        "role": config.get("role", "master"),
        "depth": config.get("depth", 0),
        "max_depth": config.get("max_depth", ML_DEFAULT_MAX_DEPTH),
        "upstream": config.get("upstream"),
        "fingerprint": config.get("fingerprint", get_node_id()),
        "hostname": get_hostname(),
        "auto_approve": config.get("auto_approve", False),
        "peers": {
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "total": len(requests)
        },
        "active_tokens": active_tokens
    }


@app.post("/master-link/token")
def ml_generate_token(req: TokenGenerateRequest, user: dict = Depends(require_jwt)):
    """Generate a join token (auth required)."""
    config = get_ml_config()

    # Only master or sub-master can generate tokens
    role = config.get("role", "master")
    if role not in ["master", "sub-master"]:
        raise HTTPException(status_code=403, detail="Only master or sub-master nodes can generate tokens")

    result = ml_token_generate(
        ttl=req.ttl,
        token_type=req.token_type,
        auto_approve=req.auto_approve
    )
    return result


@app.post("/master-link/invite")
def ml_generate_invite(
    ttl: int = 3600,
    auto_approve: bool = True,
    user: dict = Depends(require_jwt)
):
    """Generate a shareable invite URL (simplified flow)."""
    config = get_ml_config()
    role = config.get("role", "master")
    if role not in ["master", "sub-master"]:
        raise HTTPException(status_code=403, detail="Only master or sub-master can invite")

    # Generate token
    result = ml_token_generate(ttl=ttl, auto_approve=auto_approve)
    token = result["token"]

    # Build URLs
    lan_ip = get_lan_ip()
    wan_ip = get_wan_ip()
    hostname = get_hostname()
    fingerprint = config.get("fingerprint", get_node_id())

    # Web URL for browser
    web_url = f"https://{lan_ip}/master-link/?token={token}"

    # CLI one-liner for OpenWRT/Linux
    cli_cmd = f"wget -qO- 'http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join-script?token={token}' | sh"

    code = _code_invitation(lan_ip, token)
    return {
        "token": token,
        "code": code,
        "expires": result["expires"],
        "auto_approve": auto_approve,
        "master": {
            "fingerprint": fingerprint,
            "hostname": hostname,
            "lan_ip": lan_ip,
            "wan_ip": wan_ip,
            "role": role,
            "depth": config.get("depth", 0)
        },
        "urls": {
            "web": web_url,
            "web_wan": f"https://{wan_ip}/master-link/?token={token}" if wan_ip else None,
            "api": f"http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join"
        },
        "cli": {
            "command": cli_cmd,
            "curl": f"curl -s 'http://{lan_ip}:{API_PORT}/api/v1/p2p/master-link/join-script?token={token}' | sh"
        },
        "copy_paste": f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SecuBox Mesh Invite - {hostname}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Option 1 - Web Browser:
  {web_url}

Option 2 - Command Line (OpenWRT/Linux):
  {cli_cmd}

Code (une seule saisie sur la box qui rejoint) :
  {code or token}

Token: {token}
Expires: {result['expires']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    }


@app.post("/master-link/invite-local")
def ml_generate_invite_local(
    ttl: int = 3600,
    auto_approve: bool = True,
    user: dict = Depends(require_jwt)
):
    """Generate an invite for the admin dashboard (JWT required).

    SÉCURITÉ (#2476) : cette route s'appelait « locale » et se fiait à la provenance de la requête. Or un client sans adresse (socket unix, le chemin de nginx)
    comptait comme local, et X-Real-IP / X-Forwarded-For ne prouvent rien : n'importe qui fabriquait un jeton de jonction auto-approuvé. Elle exige maintenant le
    JWT d'un administrateur, comme /master-link/invite.
    """

    config = get_ml_config()
    role = config.get("role", "master")
    if role not in ["master", "sub-master"]:
        raise HTTPException(status_code=403, detail="Only master or sub-master can invite")

    # Generate token
    result = ml_token_generate(ttl=ttl, auto_approve=auto_approve)
    token = result["token"]

    # Build URLs
    lan_ip = get_lan_ip()
    wan_ip = get_wan_ip()
    hostname = get_hostname()
    fingerprint = config.get("fingerprint", get_node_id())

    # Web URL for browser
    web_url = f"https://{lan_ip}/master-link/?token={token}"

    # CLI for OpenWRT
    cli_cmd = f"sbx-mesh-join {lan_ip} {token}"

    return {
        "token": token,
        "code": _code_invitation(lan_ip, token),
        "hash": result["token_hash"],
        "expires": result["expires"],
        "expires_ts": result.get("ttl", 3600) + int(datetime.utcnow().timestamp()),
        "ttl": ttl,
        "auto_approve": auto_approve,
        "url": web_url,
        "master": {
            "fingerprint": fingerprint,
            "hostname": hostname,
            "lan_ip": lan_ip,
            "wan_ip": wan_ip
        },
        "cli": cli_cmd
    }


@app.get("/master-link/join-script", dependencies=[Depends(require_lecture)])
def ml_join_script(token: str, request: Request):
    """Return a shell script for joining (OpenWRT compatible)."""
    from fastapi.responses import PlainTextResponse

    # Get master info
    config = get_ml_config()
    master_ip = get_lan_ip()
    master_fp = config.get("fingerprint", get_node_id())
    master_hostname = get_hostname()

    script = f'''#!/bin/sh
# SecuBox Mesh Join Script
# Master: {master_hostname} ({master_fp})
# Generated: {datetime.utcnow().isoformat()}

set -e

MASTER_IP="{master_ip}"
MASTER_PORT="{API_PORT}"
TOKEN="{token}"

# Detect system type
if [ -f /etc/openwrt_release ]; then
    SYSTEM="openwrt"
    # Get fingerprint from OpenWRT
    if [ -f /etc/secubox/node.id ]; then
        FINGERPRINT=$(cat /etc/secubox/node.id)
    else
        FINGERPRINT="owrt-$(cat /sys/class/net/br-lan/address 2>/dev/null | tr -d ':' || echo $RANDOM)"
        mkdir -p /etc/secubox
        echo "$FINGERPRINT" > /etc/secubox/node.id
    fi
    HOSTNAME=$(uci get system.@system[0].hostname 2>/dev/null || hostname)
    ADDRESS=$(ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \\K[\\d.]+' | head -1)
    [ -z "$ADDRESS" ] && ADDRESS=$(ip route get 1 | grep -oP 'src \\K[\\d.]+')
else
    SYSTEM="linux"
    if [ -f /var/lib/secubox/p2p/node.id ]; then
        FINGERPRINT=$(cat /var/lib/secubox/p2p/node.id)
    else
        FINGERPRINT="sbx-$(cat /sys/class/net/eth0/address 2>/dev/null | tr -d ':' || hostname | md5sum | cut -c1-12)"
    fi
    HOSTNAME=$(hostname)
    ADDRESS=$(ip route get 1 2>/dev/null | grep -oP 'src \\K[\\d.]+' || echo "unknown")
fi

echo "╔══════════════════════════════════════════╗"
echo "║     SecuBox Mesh - Joining Network       ║"
echo "╠══════════════════════════════════════════╣"
echo "║ System:      $SYSTEM"
echo "║ Fingerprint: $FINGERPRINT"
echo "║ Hostname:    $HOSTNAME"
echo "║ Address:     $ADDRESS"
echo "║ Master:      $MASTER_IP"
echo "╚══════════════════════════════════════════╝"
echo ""

# Use wget (OpenWRT) or curl (Debian)
if command -v curl >/dev/null 2>&1; then
    RESPONSE=$(curl -s -X POST \\
        -H "Content-Type: application/json" \\
        -d "{{\\"token\\":\\"$TOKEN\\",\\"fingerprint\\":\\"$FINGERPRINT\\",\\"hostname\\":\\"$HOSTNAME\\",\\"address\\":\\"$ADDRESS\\"}}" \\
        "http://$MASTER_IP:$MASTER_PORT/api/v1/p2p/master-link/join")
elif command -v wget >/dev/null 2>&1; then
    RESPONSE=$(wget -qO- --post-data="{{\\"token\\":\\"$TOKEN\\",\\"fingerprint\\":\\"$FINGERPRINT\\",\\"hostname\\":\\"$HOSTNAME\\",\\"address\\":\\"$ADDRESS\\"}}" \\
        --header="Content-Type: application/json" \\
        "http://$MASTER_IP:$MASTER_PORT/api/v1/p2p/master-link/join" 2>/dev/null)
else
    echo "ERROR: Neither curl nor wget available"
    exit 1
fi

# Parse response
STATUS=$(echo "$RESPONSE" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

if [ "$STATUS" = "approved" ]; then
    echo "✓ SUCCESS: Joined mesh network!"
    echo "  Status: APPROVED"
    DEPTH=$(echo "$RESPONSE" | grep -o '"depth":[0-9]*' | cut -d':' -f2)
    [ -n "$DEPTH" ] && echo "  Depth: $DEPTH"

    # Save master info for OpenWRT
    if [ "$SYSTEM" = "openwrt" ]; then
        mkdir -p /etc/secubox
        echo "$MASTER_IP" > /etc/secubox/master.ip
        echo "$FINGERPRINT" > /etc/secubox/node.id
    fi
elif [ "$STATUS" = "pending" ]; then
    echo "⏳ PENDING: Waiting for master approval"
    echo "  Your fingerprint: $FINGERPRINT"
    echo "  Check back later or ask the master admin to approve."
else
    echo "✗ FAILED: $RESPONSE"
    exit 1
fi
'''
    return PlainTextResponse(content=script, media_type="text/plain")


ATTENTE_VERROU_PUBLIC_S = 2.0


@app.post("/master-link/token/validate")
def ml_validate_token(token: str):
    """Validate a token (public). #3362 passe 3 : `def` (pool, jamais la boucle) et verrou non bloquant, réessayé ~2 s,
    puis 503 : un appelant anonyme ne peut ni figer l'API ni occuper un fil indéfiniment."""
    try:
        return ml_token_validate(token, attente=ATTENTE_VERROU_PUBLIC_S)
    except oubli.VerrouOccupe:
        raise HTTPException(status_code=503, detail="état du maillage occupé : réessayer") from None


@app.post("/master-link/token/revoke")
def ml_revoke_token(token: str, user: dict = Depends(require_jwt)):
    """Revoke a token."""
    token_hash = hash_token(token)
    init_dirs()
    with oubli.verrou(P2P_DIR):                  # #3362 : section critique, lecture stricte
        tokens = get_ml_tokens()
        for t in tokens:
            if t.get("hash") == token_hash:
                t["status"] = "revoked"
                save_ml_tokens(tokens)
                return {"status": "ok", "revoked": token_hash}

    raise HTTPException(status_code=404, detail="Token not found")


@app.post("/master-link/token/cleanup")
def ml_cleanup(user: dict = Depends(require_jwt)):
    """Cleanup expired tokens."""
    return ml_cleanup_tokens()


@app.post("/master-link/cleanup-local")
def ml_cleanup_local(user: dict = Depends(require_jwt)):
    """Cleanup expired tokens (JWT required — plus de confiance dans la provenance, #2476)."""
    return ml_cleanup_tokens()


@app.post("/master-link/join")
def ml_join(req: JoinRequest, request: Request):
    """Handle join request from new node (token validated).

    #3362 (passe 2) : validation du jeton, lecture des demandes, inscription et écritures dans UNE section critique
    (`oubli.verrou`) : une jonction qui a lu avant un oubli concurrent ne réécrit plus sa copie périmée."""
    init_dirs()
    with oubli.verrou(P2P_DIR):
        return _ml_join(req, request)


def _ml_join(req: JoinRequest, request: Request):
    # Validate token
    validation = ml_token_validate(req.token)
    if not validation.get("valid"):
        raise HTTPException(status_code=403, detail=validation.get("error", "Invalid token"))

    token_hash = validation.get("token_hash")
    auto_approve = validation.get("auto_approve", False)

    # Get peer address from request if not provided
    peer_address = req.address
    if not peer_address:
        peer_address = request.client.host if request.client else "unknown"

    # Get config
    config = get_ml_config()
    my_depth = config.get("depth", 0)
    peer_depth = my_depth + 1

    # Store join request
    requests = get_ml_requests()
    now = datetime.utcnow()

    # Check if already exists
    existing = next((r for r in requests if r.get("fingerprint") == req.fingerprint), None)
    if existing:
        # UN PAIR DÉJÀ APPROUVÉ PEUT REVENIR AVEC SA CLÉ (#1360) : c'est le cas
        # de tout nœud enrôlé avant l'échange de clés, et d'un nœud réinstallé.
        # On met sa clé à jour et on le (ré)inscrit au transport, au lieu de lui
        # répondre « déjà approuvé » sans rien lui donner pour monter le tunnel.
        existing["address"] = peer_address or existing.get("address")
        _record_wg_identity(existing, req)
        if existing.get("status") == "approved":
            _renommer_au_retour(existing, req, requests)
            _provision(existing)
            save_ml_requests(requests)
            return {
                "status": "approved",
                "fingerprint": req.fingerprint,
                "message": "Already approved",
                "mesh_ip": existing.get("mesh_ip"),
                "wg": _wg_offer(existing),
            }
        elif existing.get("status") == "pending":
            save_ml_requests(requests)
            return {
                "status": "pending",
                "fingerprint": req.fingerprint,
                "message": "Join request already pending"
            }

    # REFLASH (#3100) : un jeton `flash` ne vaut que pour le nom prévu, et ne remplace
    # que le pair de CE nom ; hors flash, un nom déjà pris reste refusé.
    flash = bool(validation.get("flash"))
    nom = (req.hostname or "").strip()
    if flash and nom != (validation.get("nom_prevu") or ""):
        _audit_jonction("jonction_refusee", raison="jeton flash pour un autre nom", nom=nom)
        raise HTTPException(status_code=403, detail="flash_token_other_name")
    homonyme = None
    if nom and nom.lower() not in NOMS_PAR_DEFAUT:
        homonyme = next((r for r in requests if r.get("hostname") == nom
                         and r.get("status") == "approved"
                         and r.get("fingerprint") != req.fingerprint), None)
    if homonyme and not (flash and (auto_approve or config.get("auto_approve", False))):
        _audit_jonction("jonction_refusee", raison="nom deja pris", nom=nom)
        raise HTTPException(status_code=409, detail="nom déjà pris : préparer un flash sur le maître "
                                                    "(page Netboot) ou retirer l'ancien pair")

    join_request = {
        "fingerprint": req.fingerprint,
        "address": peer_address,
        "hostname": req.hostname or "unknown",
        "token_hash": token_hash,
        "timestamp": now.isoformat(),
        "status": "pending"
    }
    _record_wg_identity(join_request, req)

    # Check global auto-approve or token auto-approve
    global_auto = config.get("auto_approve", False)
    if auto_approve or global_auto:
        # Auto-approve
        join_request["status"] = "approved"
        join_request["approved_at"] = now.isoformat()
        join_request["approved_by"] = config.get("fingerprint", get_node_id())
        join_request["depth"] = peer_depth
        if homonyme:
            _remplacer_homonyme(join_request, homonyme, requests)
        else:
            _assign_mesh_ip(join_request)

        # Mark token as used
        ml_token_mark_used(token_hash, req.fingerprint)

        # Add to peers
        _add_approved_peer(join_request)
        _provision(join_request)
        for k in ("remplace_cle", "remplace_ip", "remplace_nom"):
            join_request.pop(k, None)          # usage unique : l'ancienne clé est partie

        requests.append(join_request)
        save_ml_requests(requests)

        return {
            "success": True,
            "status": "approved",
            "fingerprint": req.fingerprint,
            "depth": peer_depth,
            "message": "Auto-approved",
            "mesh_ip": join_request.get("mesh_ip"),
            "wg": _wg_offer(join_request),
        }

    # Manual approval required
    requests.append(join_request)
    save_ml_requests(requests)

    return {
        "success": True,
        "status": "pending",
        "fingerprint": req.fingerprint,
        "message": "Join request queued for approval"
    }


NOMS_PAR_DEFAUT = {"", "unknown", "localhost", "secubox", "secubox-mochabin", "secubox-espressobin"}


def _audit_jonction(evenement: str, **champs) -> None:
    """Décision de sécurité de la jonction, dans l'audit (jamais de jeton ni de code)."""
    try:
        ancre.audit(evenement, chemin=os.environ.get("SBX_AUDIT", "/var/log/secubox/audit.log"), **champs)
    except OSError as e:
        log.warning("audit jonction non écrit: %s", e)


def _renommer_au_retour(existing: Dict, req: "JoinRequest", requests: List[Dict]) -> None:
    """#3213 : un pair approuvé qui revient sous un autre nom d'hôte est renommé (demande, registre hérité ; le
    transport suit par `_provision`). gk3 restait « secubox-live », son nom d'installation, chez le maître.

    Jamais un nom par défaut, jamais un nom que `pairs_directs.valider_pair` écarterait, jamais celui d'un autre
    pair approuvé : la jonction continue alors sous l'ancien nom."""
    nom = (req.hostname or "").strip()
    ancien = existing.get("hostname") or ""
    if nom == ancien or nom.lower() in NOMS_PAR_DEFAUT or not pairs_directs._NOM.fullmatch(nom):
        return
    if any(r.get("hostname") == nom and r.get("status") == "approved"
           and r.get("fingerprint") != existing.get("fingerprint") for r in requests):
        _audit_jonction("renommage_refuse", raison="nom deja pris", nom=nom, ancien_nom=ancien)
        return
    existing["hostname"] = nom
    legacy = load_json(PEERS_FILE, {"peers": []})
    for lp in legacy.get("peers", []):
        if lp.get("fingerprint") == existing.get("fingerprint"):
            lp["name"] = nom
    save_json(PEERS_FILE, legacy)
    _audit_jonction("pair_renomme", nom=nom, ancien_nom=ancien, mesh_ip=existing.get("mesh_ip"))


def _remplacer_homonyme(join_request: Dict, ancien: Dict, requests: List[Dict]) -> None:
    """Reflash (#3100) : le nouveau pair prend l'adresse du maillage de l'ancien de même nom.

    L'ancienne demande disparaît du registre, l'ancienne entrée du registre hérité aussi,
    et l'ancienne clé est retirée du transport par `_add_mesh_peer` (champ `remplace_cle`).
    """
    join_request["mesh_ip"] = ancien.get("mesh_ip")
    if ancien.get("wg_public_key"):
        join_request["remplace_cle"] = ancien["wg_public_key"]
    # Même sans clé connue dans la demande : le transport est purgé par adresse et par nom.
    join_request["remplace_ip"] = ancien.get("mesh_ip")
    join_request["remplace_nom"] = ancien.get("hostname")
    _audit_jonction("pair_remplace_reflash", nom=ancien.get("hostname"),
                    ancienne_empreinte=ancien.get("fingerprint"),
                    nouvelle_empreinte=join_request.get("fingerprint"), mesh_ip=ancien.get("mesh_ip"))
    requests[:] = [r for r in requests if r is not ancien]
    legacy = load_json(PEERS_FILE, {"peers": []})
    if isinstance(legacy, dict):
        legacy["peers"] = [p for p in legacy.get("peers", [])
                           if p.get("fingerprint") != ancien.get("fingerprint")]
        save_json(PEERS_FILE, legacy)
    if not join_request.get("mesh_ip"):
        _assign_mesh_ip(join_request)


def _assign_mesh_ip(join_request: Dict) -> None:
    """Allocate the next free mesh IP, deduping against EVERY source.

    Ne regardait que `peers.json`, et ignorait donc les pairs WireGuard réels :
    la VM de test a reçu 10.10.0.2, l'adresse de c3box (#1360).
    """
    legacy = load_json(PEERS_FILE, {"peers": []}).get("peers", [])
    taken = mesh.taken_mesh_ips(get_wg_mesh_config(), legacy, get_ml_requests())
    join_request["mesh_ip"] = mesh.allocate_mesh_ip(mesh.MESH_NETWORK, taken)


def _master_wg_pubkey(state: Dict) -> Optional[str]:
    """La clé publique du maître — stockée, ou dérivée de la privée.

    Sur gk2, l'état porte la clé privée ADOPTÉE du fichier wg-quick, mais pas la
    publique. `wg pubkey` est un pur calcul : il ne touche pas l'interface et
    ne demande aucun privilège.
    """
    if mesh.valid_wg_key(state.get("public_key")):
        return state["public_key"]
    priv = state.get("private_key")
    if not priv:
        return None
    try:
        r = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                           text=True, timeout=5)
        pk = r.stdout.strip()
        return pk if r.returncode == 0 and mesh.valid_wg_key(pk) else None
    except Exception:
        return None


def _add_mesh_peer(join_request: Dict) -> bool:
    """Inscrit le pair dans `wg_mesh.json` — le TRANSPORT, pas le registre.

    L'écriture de l'état suffit : l'unité `secubox-p2p-mesh.path` (root) voit
    le fichier changer et applique la configuration par `sbx-mesh-up`. Le
    service reste sans privilège, et aucune nouvelle surface sudo n'est ouverte.
    """
    pk = join_request.get("wg_public_key")
    ip = join_request.get("mesh_ip")
    if not (pk and ip):
        return False
    state = get_wg_mesh_config()
    ancienne = join_request.get("remplace_cle")
    if ancienne and ancienne != pk:                 # reflash (#3100) : l'ancienne clé quitte le transport
        state["peers"] = [p for p in state.get("peers", []) if p.get("public_key") != ancienne]
    r_ip, r_nom = join_request.get("remplace_ip"), join_request.get("remplace_nom")
    if r_ip or r_nom:                               # ... et tout pair qui tenait l'adresse ou le nom
        state["peers"] = [p for p in state.get("peers", []) if p.get("public_key") == pk or not (
            (r_ip and (p.get("mesh_ip") == r_ip or p.get("allowed_ips") == f"{r_ip}/32"))
            or (r_nom and p.get("name") == r_nom))]
    peer = {
        "public_key": pk,
        "allowed_ips": f"{ip}/32",
        "mesh_ip": ip,
        "name": join_request.get("hostname") or ip,
        "fingerprint": join_request.get("fingerprint"),
        "added": datetime.utcnow().isoformat(),
    }
    ep = join_request.get("wg_endpoint")
    if ep:
        peer["endpoint"] = ep
    mesh.upsert_mesh_peer(state, peer)
    save_json(WG_MESH_CONFIG, state)
    return True


def _wg_offer(join_request: Dict) -> Optional[Dict]:
    """Ce que le pair doit savoir pour monter SON côté du tunnel.

    L'endpoint du maître n'est PAS renvoyé : le pair le compose avec l'adresse
    qu'il vient lui-même de joindre. Le deviner ici (derrière nginx, l'adresse
    vue est 127.0.0.1) serait moins fiable que ce que le pair sait déjà.
    """
    if not (join_request.get("wg_public_key") and join_request.get("mesh_ip")):
        return None
    state = get_wg_mesh_config()
    master_pk = _master_wg_pubkey(state)
    if not master_pk:
        return None
    return {
        "master_public_key": master_pk,
        "master_port": state.get("listen_port", WG_PORT),
        "master_mesh_ip": (state.get("address") or "10.10.0.1/24").split("/")[0],
        "address": f"{join_request['mesh_ip']}/24",
        "network": state.get("network", WG_NETWORK),
    }


def _provision(join_request: Dict) -> None:
    """Inscrit le pair au transport ; réattribue son adresse si elle est prise.

    CAS RÉEL : la VM de test avait été approuvée avec 10.10.0.2, l'adresse de
    c3box — l'ancien allocateur ignorait les pairs WireGuard. Reconduire cette
    adresse au réenrôlement aurait détourné la route de c3box. On la libère et
    on en prend une vraiment libre.
    """
    if not join_request.get("wg_public_key"):
        return
    try:
        _add_mesh_peer(join_request)
    except ValueError:
        join_request.pop("mesh_ip", None)
        _assign_mesh_ip(join_request)
        _add_mesh_peer(join_request)
    # Le registre hérité suit, sinon l'interface afficherait l'ancienne adresse.
    legacy = load_json(PEERS_FILE, {"peers": []})
    for lp in legacy.get("peers", []):
        if lp.get("fingerprint") == join_request.get("fingerprint"):
            lp["mesh_ip"] = join_request["mesh_ip"]
    save_json(PEERS_FILE, legacy)


def _record_wg_identity(join_request: Dict, req: "JoinRequest") -> None:
    """Valide et consigne la clé et l'endpoint annoncés par le pair.

    L'endpoint n'est construit qu'à partir d'une adresse IP VALIDE : il finit
    dans un fichier de configuration rendu, et un nom arbitraire y ferait
    entrer n'importe quoi.
    """
    if req.wg_public_key is None:
        return
    if not mesh.valid_wg_key(req.wg_public_key):
        raise HTTPException(status_code=400, detail="invalid WireGuard public key")
    join_request["wg_public_key"] = req.wg_public_key
    port = req.wg_port or WG_PORT
    if not (1 <= int(port) <= 65535):
        raise HTTPException(status_code=400, detail="invalid WireGuard port")
    try:
        adresse = ipaddress.ip_address(join_request.get("address") or "")
        hote = f"[{adresse}]" if adresse.version == 6 else str(adresse)     # IPv6 entre crochets (#2936)
        join_request["wg_endpoint"] = f"{hote}:{int(port)}"
    except ValueError:
        join_request.pop("wg_endpoint", None)


def _add_approved_peer(join_request: Dict):
    """Add approved peer to peer list."""
    peers_data = load_json(PEERS_FILE, {"peers": []})
    peers = peers_data.get("peers", []) if isinstance(peers_data, dict) else []

    peer_id = f"sb-{ident(join_request['fingerprint'], n=12)}"

    # Check if already exists
    if any(p.get("id") == peer_id for p in peers):
        return

    peer = {
        "id": peer_id,
        "fingerprint": join_request["fingerprint"],
        "name": join_request.get("hostname", "Peer"),
        "address": join_request.get("address"),
        "mesh_ip": join_request.get("mesh_ip"),
        "depth": join_request.get("depth", 1),
        "role": join_request.get("role", "peer"),
        "added": datetime.utcnow().isoformat(),
        "joined_via": "master-link",
        # #3362 : jamais « online » écrit (il restait figé, même sans poignée de main) ; lu, il est mesuré (statut_registre)
        "status": "unknown"
    }
    peers.append(peer)
    save_json(PEERS_FILE, {"peers": peers})


OUBLI_PAIR_CTL = "/usr/sbin/secubox-oubli-pair"
PILOTAGE_SOCK = "/run/secubox/pilotage.sock"
RE_ACTEUR = re.compile(r"[A-Za-z0-9._@-]{1,64}")
RE_NOM_PAIR_31 = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")      # nom de pair de l'autoload et de l'assistant root
OPERATIONS_OUBLI: Dict[str, Dict] = {}                        # #3362 : opérations d'oubli (mémoire du service, 50 au plus)
_OPERATIONS_MAX = 50
_operations_verrou = threading.Lock()


def _oubli_suites_root(cibles: Dict, nom: Optional[str], force: bool = False, acteur: str = "?") -> Dict:
    """#3362 : les nettoyages qui exigent root (pair retiré de l'interface wg-mesh par sa clé EXACTE, noms relayés vers son
    adresse, noms Unbound, abonnement de l'autoload) par `sudo -n secubox-oubli-pair`, argv fixe, sans shell. L'assistant
    revérifie chaque cible contre l'état déjà écrit et contre l'interface (poignée de main récente refusée sans --force).
    Rend {étape: {ok, detail}} ; jamais d'exception : un échec devient une étape « racine » en échec."""
    acteur = acteur if RE_ACTEUR.fullmatch(acteur or "") else "inconnu"
    argv = ["sudo", "-n", OUBLI_PAIR_CTL, "--acteur", acteur]
    for c in cibles.get("cles") or []:
        argv += ["--cle", c]
    for ip in cibles.get("ips") or []:
        argv += ["--ip", ip]
    if nom:
        argv += ["--nom", nom]
    if force:
        argv += ["--force"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=900, check=False)
        doc = json.loads(r.stdout or "{}") if (r.stdout or "").strip() else {}
        etapes = doc.get("etapes") if r.returncode == 0 else None
        if isinstance(etapes, dict) and etapes:
            out = {str(k): {"ok": bool(v.get("ok")), "detail": str(v.get("detail") or "")[:300]}
                   for k, v in etapes.items() if isinstance(v, dict)}
            if doc.get("audit_ok") is False:
                out["audit_racine"] = {"ok": False, "detail": f"journal d'audit non écrit : {(r.stderr or '').strip()[:200]}"}
            return out
        detail = f"code {r.returncode} : {str(doc.get('erreur') or r.stderr or r.stdout or '').strip()[:300]}"
    except (OSError, subprocess.SubprocessError, ValueError, AttributeError) as e:
        detail = f"{type(e).__name__} : {str(e)[:200]}"
    return {"racine": {"ok": False, "detail": detail}}


def _oubli_pilotage(nom: str, force: bool) -> Dict:
    """#3362 : la box quitte la Flotte du pilotage (boites, inventaire, événements) par sa route d'administration
    (`POST /boxes/{nom}/oublier`), sur sa socket locale, avec le jeton de l'administrateur qui oublie. 404 : rien à oublier."""
    _, err = annuaire_client._requete_avec_essais("POST", f"/boxes/{quote(nom, safe='')}/oublier", PILOTAGE_SOCK,
                                                  body={"confirmation": nom, "force": bool(force)})
    if err is None:
        return {"ok": True, "detail": "box oubliée de la Flotte"}
    if "HTTP 404" in err:
        return {"ok": True, "detail": "box inconnue du pilotage"}
    if "FileNotFoundError" in err or "ConnectionRefusedError" in err:
        return {"ok": True, "detail": "pilotage absent"}
    return {"ok": False, "detail": err.replace("annuaire ", "pilotage ")[:300]}


_TACHES: set = set()      # #3362 : référence forte des tâches asyncio lancées sans attente (sinon le GC peut les couper)


def _garder_tache(tache):
    _TACHES.add(tache)
    tache.add_done_callback(_TACHES.discard)
    return tache


def _lancer_operation(fonction) -> None:
    """Étapes longues en tâche de fond, dans le contexte de la requête (jeton de l'administrateur pour le pilotage)."""
    ctx = contextvars.copy_context()
    threading.Thread(target=ctx.run, args=(fonction,), daemon=True, name="oubli-noeud").start()


def _operation_maj(op: str, **champs) -> None:
    with _operations_verrou:
        OPERATIONS_OUBLI[op].update(champs)


def _finir_oubli(op: str, nom: str, retires: Dict, force: bool, acteur: str, etapes_initiales: Dict) -> None:
    """Fin de l'oubli (tâche de fond) : étapes root, puis Flotte du pilotage ; chaque échec journalisé et audité.
    L'état initial arrive en argument : le dict partagé n'est jamais relu hors de son verrou."""
    etapes = {k: dict(v) for k, v in etapes_initiales.items()}
    try:
        nom_libre = bool(retires.get("nom_libre"))
        nom_root = nom if nom_libre and RE_NOM_PAIR_31.fullmatch(nom) else None
        etapes.update(_oubli_suites_root(retires, nom_root, force=force, acteur=acteur))
        if nom_libre:
            etapes["pilotage"] = _oubli_pilotage(nom, force)
        else:
            etapes["pilotage"] = {"ok": True, "detail": "nom encore porté par un autre pair : Flotte gardée"}
            etapes.setdefault("autoload", {"ok": True, "detail": "nom encore porté par un autre pair : abonnement gardé"})
    except Exception as e:  # noqa: BLE001 — l'opération doit toujours se terminer, et dire pourquoi
        etapes["interne"] = {"ok": False, "detail": f"{type(e).__name__} : {str(e)[:200]}"}
    restes = [k for k, v in etapes.items() if not v.get("ok")]
    for k in restes:
        log.warning("oubli de %s : étape %s en échec : %s", nom, k, etapes[k].get("detail"))
        _audit_jonction("p2p_noeud_oubli_partiel", noeud=nom, etape=k, motif=etapes[k].get("detail"), acteur=acteur)
    _audit_jonction("p2p_noeud_oublie", noeud=nom, force=force, acteur=acteur, registre=retires["registre"],
                    wg=retires["wg"], cles=retires["cles"], ips=retires["ips"], restes=restes, operation=op)
    _operation_maj(op, etat="termine", etapes=etapes, restes=restes, status="partiel" if restes else "ok",
                   termine_le=time.time())


class OublierRequest(BaseModel):
    model_config = {"extra": "forbid"}
    nom: str = Field(..., min_length=1, max_length=63)
    confirmation: str = Field(..., min_length=1, max_length=63)
    public_key: Optional[str] = Field(None, max_length=44)
    fingerprint: Optional[str] = Field(None, max_length=64)
    force: bool = False


@app.post("/master-link/oublier", status_code=202)
def ml_oublier(req: OublierRequest, user: dict = Depends(require_jwt)):
    """« Oublier ce nœud » (#3335, #3362) : LE point d'entrée du maître. Il retire le pair de TOUS les états où il est
    référencé :
      1. SYNCHRONE, sous le verrou des écrivains (`.etat.lock`), lecture stricte (illisible : 503, rien n'est modifié) puis
         écritures atomiques : registre (peers.json), transport (wg_mesh.json → sbx-mesh-up rend wg-mesh.conf), jonctions
         (demande approuvée, jetons consommés : fichiers réécrits seulement si une entrée du pair en part) ; projection.
      2. EN TÂCHE DE FOND (202, opération suivie par GET /master-link/oublier/{operation}) : root par secubox-oubli-pair
         (interface wg-mesh par clé exacte, noms relayés, noms Unbound, abonnement autoload), puis Flotte du pilotage.
    Un nom encore porté par un autre pair garde son abonnement et sa Flotte. Chaque échec est journalisé, audité et rendu
    dans `restes` ; `status` vaut « partiel » tant qu'il reste quelque chose."""
    if req.confirmation != req.nom:
        raise HTTPException(status_code=400, detail="confirmation : retapez exactement le nom du nœud")
    acteur = str(user.get("sub", "?"))
    local = socket.gethostname().split(".")[0].lower()
    a = ancre.lire()
    cle_maitre = a.get("cle_publique") if isinstance(a, dict) else None
    op = secrets.token_hex(16)
    with _operations_verrou:                     # #3362 : contrôle 429 ET réservation de la place dans la MÊME section
        # seules les opérations TERMINÉES sont purgées (une opération en cours reste suivable)
        terminees = [k for k, v in OPERATIONS_OUBLI.items() if v.get("etat") == "termine"]
        while len(OPERATIONS_OUBLI) >= _OPERATIONS_MAX and terminees:
            OPERATIONS_OUBLI.pop(terminees.pop(0))
        if len(OPERATIONS_OUBLI) >= _OPERATIONS_MAX:
            raise HTTPException(status_code=429, detail="trop d'oublis en cours : réessayer quand l'un d'eux est terminé")
        OPERATIONS_OUBLI[op] = {"operation": op, "oublie": req.nom, "etat": "reservee", "status": "en_cours",
                                "etapes": {}, "restes": [], "debut": time.time()}
    try:
        return _ml_oublier_reserve(op, req, acteur, local, cle_maitre)
    except BaseException:
        with _operations_verrou:                 # refus (409, 503…) : la place réservée est rendue
            OPERATIONS_OUBLI.pop(op, None)
        raise


def _ml_oublier_reserve(op: str, req: "OublierRequest", acteur: str, local: str, cle_maitre: Optional[str]) -> Dict:
    """Suite de ml_oublier, la place de l'opération `op` étant réservée."""
    init_dirs()
    ml_init()
    try:
        with oubli.verrou(P2P_DIR):
            peers_doc = oubli.lire_strict(PEERS_FILE, {"peers": []})
            wg_state = oubli.lire_strict(WG_MESH_CONFIG, {"peers": []})
            demandes = oubli.lire_strict_liste(ML_REQUESTS_FILE)
            jetons_ml = oubli.lire_strict_liste(ML_TOKENS_FILE)
            peers, wg, retires = oubli.oublier(peers_doc, wg_state, req.nom, handshakes=mesh.load_handshakes(),
                                               now=time.time(), local=local, force=req.force, cle=req.public_key,
                                               empreinte=req.fingerprint, cle_maitre=cle_maitre)
            demandes, jetons_ml, n_jonctions = oubli.oublier_jonctions(demandes, jetons_ml, req.nom, retires)
            oubli.ecrire_atomique(WG_MESH_CONFIG, wg, 0o600)   # secubox-p2p-mesh.path → sbx-mesh-up rend la conf persistée
            oubli.ecrire_atomique(PEERS_FILE, peers, 0o644)
            if n_jonctions["demandes"]:
                oubli.ecrire_atomique(ML_REQUESTS_FILE, demandes, 0o600)
            if n_jonctions["jetons"]:
                oubli.ecrire_atomique(ML_TOKENS_FILE, jetons_ml, 0o600)
    except oubli.EtatIllisible as e:
        _audit_jonction("p2p_noeud_oubli_refuse", noeud=req.nom, motif=str(e), acteur=acteur)
        raise HTTPException(status_code=503, detail="état du maillage illisible : rien n'est modifié") from None
    except oubli.Refus as e:
        _audit_jonction("p2p_noeud_oubli_refuse", noeud=req.nom, motif=str(e), acteur=acteur)
        raise HTTPException(status_code=409, detail=str(e)) from None
    etapes: Dict[str, Dict] = {
        "registre": {"ok": True, "detail": f"{retires['registre']} entrée(s) du registre, {retires['wg']} pair(s) wg-mesh"},
        "jonctions": {"ok": True, "detail": f"{n_jonctions['demandes']} demande(s), {n_jonctions['jetons']} jeton(s) révoqué(s)"},
    }
    try:
        pairs_enroles.publier(peers, PAIRS_ENROLES_DIR)
        etapes["projection"] = {"ok": True, "detail": "pairs-enroles.json republié"}
    except (pairs_enroles.ProjectionErreur, OSError) as e:
        etapes["projection"] = {"ok": False, "detail": str(e)[:300]}
    with _operations_verrou:
        OPERATIONS_OUBLI[op] = {"operation": op, "oublie": req.nom, "etat": "en_cours", "status": "en_cours",
                                "retires": {"registre": retires["registre"], "wg": retires["wg"], **n_jonctions},
                                "etapes": {k: dict(v) for k, v in etapes.items()}, "restes": [], "debut": time.time()}
    _lancer_operation(lambda: _finir_oubli(op, req.nom, retires, req.force, acteur, etapes))
    return {"operation": op, "etat": "en_cours", "oublie": req.nom, "suivi": f"/api/v1/p2p/master-link/oublier/{op}"}


@app.get("/master-link/oublier/{operation}")
def ml_oublier_suivi(operation: str, user: dict = Depends(require_jwt)):
    """#3362 : état d'une opération d'oubli (étapes faites, restes, « termine »). Inconnue (ou service redémarré) : 404."""
    if not re.fullmatch(r"[0-9a-f]{32}", operation):
        raise HTTPException(status_code=404, detail="opération inconnue")
    with _operations_verrou:
        d = OPERATIONS_OUBLI.get(operation)
        if d is None:
            raise HTTPException(status_code=404, detail="opération inconnue")
        return json.loads(json.dumps(d))


@app.post("/master-link/approve")
async def ml_approve(req: ApproveRequest, user: dict = Depends(require_jwt)):
    """Approve, reject, or promote a peer (auth required).

    #3362 (passe 2) : lecture, décision et écritures dans UNE section critique : une approbation concurrente d'un oubli ne
    ramène pas le pair oublié."""
    # #3362 passe 3 : le verrou se prend dans un fil du pool, jamais dans la boucle ; la notification d'une promotion
    # (tâche asyncio) est lancée ici, APRÈS le retour du fil.
    reponse, promotion = await asyncio.to_thread(_ml_approve_verrouille, req)
    if promotion:
        _garder_tache(asyncio.create_task(_notify_peer_promotion(*promotion)))
    return reponse


def _ml_approve_verrouille(req: ApproveRequest):
    """(réponse, (adresse, profondeur) d'une promotion à notifier ou None), sous le verrou."""
    init_dirs()
    with oubli.verrou(P2P_DIR):
        promotion: List = []
        reponse = _ml_approve(req, promotion)
        return reponse, (tuple(promotion[0]) if promotion else None)


def _ml_approve(req: ApproveRequest, promotion: List):
    requests = get_ml_requests()
    config = get_ml_config()
    now = datetime.utcnow()

    # Find the request
    join_request = next((r for r in requests if r.get("fingerprint") == req.fingerprint), None)
    if not join_request:
        raise HTTPException(status_code=404, detail="No pending request for this fingerprint")

    my_fp = config.get("fingerprint", get_node_id())
    my_depth = config.get("depth", 0)

    if req.action == "approve":
        if join_request.get("status") == "approved":
            return {"status": "already_approved", "fingerprint": req.fingerprint}

        peer_depth = my_depth + 1
        join_request["status"] = "approved"
        join_request["approved_at"] = now.isoformat()
        join_request["approved_by"] = my_fp
        join_request["depth"] = peer_depth

        # Mark token as used
        token_hash = join_request.get("token_hash")
        if token_hash:
            ml_token_mark_used(token_hash, req.fingerprint)

        # Allocate mesh IP if not already set (handles manual-approve path)
        if not join_request.get("mesh_ip"):
            _assign_mesh_ip(join_request)

        # Add to peers
        _add_approved_peer(join_request)
        _provision(join_request)

        save_ml_requests(requests)

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "address": join_request.get("address"),
            "hostname": join_request.get("hostname"),
            "depth": peer_depth,
            "status": "approved"
        }

    elif req.action == "reject":
        join_request["status"] = "rejected"
        join_request["rejected_at"] = now.isoformat()
        join_request["rejected_by"] = my_fp
        join_request["reason"] = req.reason or "Rejected by admin"

        save_ml_requests(requests)

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "status": "rejected"
        }

    elif req.action == "promote":
        if join_request.get("status") != "approved":
            raise HTTPException(status_code=400, detail="Can only promote approved peers")

        # Check depth limit
        max_depth = config.get("max_depth", ML_DEFAULT_MAX_DEPTH)
        current_depth = join_request.get("depth", my_depth + 1)
        if current_depth >= max_depth:
            raise HTTPException(status_code=400, detail=f"Max depth ({max_depth}) reached")

        join_request["role"] = "sub-master"
        join_request["promoted_at"] = now.isoformat()
        join_request["promoted_by"] = my_fp

        save_ml_requests(requests)

        # Notify peer of promotion (background)
        peer_addr = join_request.get("address")
        if peer_addr:
            promotion.append((peer_addr, current_depth))          # notifiée par la coroutine, après le fil

        return {
            "success": True,
            "fingerprint": req.fingerprint,
            "new_role": "sub-master",
            "depth": current_depth
        }

    else:
        raise HTTPException(status_code=400, detail=f"Invalid action: {req.action}")


async def _notify_peer_promotion(peer_addr: str, depth: int):
    """Notify a peer that they've been promoted."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "5", "-k",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", json.dumps({"action": "promote", "role": "sub-master", "depth": depth}),
            f"https://{peer_addr}/api/v1/p2p/master-link/status",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.communicate(), timeout=10)
    except:
        pass  # Best effort


async def garde_pair_ou_lecture(request: Request, creds=Depends(_bearer)):
    """#3133 : X-SecuBox-Pair = jeton secret posé par nginx (listener 7331, source 10.10.0.0/24) ou garde de lecture."""
    if pairs_directs.en_tete_pair_valide(request.headers.get("X-SecuBox-Pair")):
        return {"pair": True}
    return await require_lecture(request, creds)


@app.get("/master-link/pairs", dependencies=[Depends(garde_pair_ou_lecture)])
async def ml_pairs():
    """Liste des pairs vivants du maillage, pour les liens directs (#3133). Aucun secret.

    Sans mesure des poignées de main (fichier absent, illisible ou de plus de 120 s) : 503, JAMAIS une liste vide
    valide — chaque pair retirerait alors tous ses liens directs ; sur une erreur HTTP, le pair ne change rien."""
    poignees = mesh.load_handshakes()
    if poignees is None:
        raise HTTPException(status_code=503, detail="mesure des poignées indisponible")
    return {"version": 1, "pairs": pairs_directs.pairs_vivants(get_wg_mesh_config(), poignees)}


@app.get("/master-link/peers", dependencies=[Depends(require_lecture)])
def ml_list_peers():
    """List all join requests and their status (public read)."""
    requests = get_ml_requests()
    return {"peers": requests, "count": len(requests)}


@app.get("/master-link/tree", dependencies=[Depends(require_lecture)])
def ml_tree():
    """Get mesh hierarchy tree (public read)."""
    config = get_ml_config()
    requests = get_ml_requests()

    # Build tree starting from self
    my_fp = config.get("fingerprint", get_node_id())

    root = {
        "fingerprint": my_fp,
        "hostname": get_hostname(),
        "role": config.get("role", "master"),
        "depth": config.get("depth", 0),
        "address": get_lan_ip(),
        "children": []
    }

    # Add approved peers as children
    for req in requests:
        if req.get("status") == "approved":
            child = {
                "fingerprint": req.get("fingerprint"),
                "hostname": req.get("hostname", "unknown"),
                "address": req.get("address"),
                "role": req.get("role", "peer"),
                "depth": req.get("depth", root["depth"] + 1),
                "approved_at": req.get("approved_at"),
                "children": []  # Would need recursive fetch for sub-master children
            }
            root["children"].append(child)

    return {"tree": root}


@app.get("/master-link/config")
def ml_get_config(user: dict = Depends(require_jwt)):
    """Get full master-link configuration (auth required)."""
    return get_ml_config()


@app.post("/master-link/config")
def ml_set_config(
    role: Optional[str] = None,
    upstream: Optional[str] = None,
    depth: Optional[int] = None,
    max_depth: Optional[int] = None,
    auto_approve: Optional[bool] = None,
    token_ttl: Optional[int] = None,
    user: dict = Depends(require_jwt)
):
    """Update master-link configuration (auth required)."""
    config = get_ml_config()

    if role is not None:
        if role not in ["master", "sub-master", "peer"]:
            raise HTTPException(status_code=400, detail="Invalid role")
        config["role"] = role

    if upstream is not None:
        config["upstream"] = upstream

    if depth is not None:
        config["depth"] = depth

    if max_depth is not None:
        config["max_depth"] = max_depth

    if auto_approve is not None:
        config["auto_approve"] = auto_approve

    if token_ttl is not None:
        config["token_ttl"] = token_ttl

    save_ml_config(config)
    return {"status": "ok", "config": config}


def _code_invitation(adresse, token: str):
    """Code d'invitation (adresse du parent + jeton) ; None si l'adresse n'est pas exploitable (pas d'IP locale connue)."""
    try:
        return automesh.encoder(str(adresse or ""), token)
    except ValueError:
        return None


def _url_jonction(master_addr: str) -> str:
    """URL de /master-link/join du parent. Une adresse du réseau local (IP privée) reste en HTTP sur le port du module, comme avant ; toute autre adresse passe par HTTPS
    (nginx du parent), certificat VÉRIFIÉ : le jeton ne voyage jamais en clair sur Internet."""
    hote = f"[{master_addr}]" if ":" in master_addr else master_addr          # un littéral IPv6 s'écrit entre crochets dans une URL
    try:
        if ipaddress.ip_address(master_addr).is_private:
            return f"http://{hote}:{API_PORT}/api/v1/p2p/master-link/join"
    except ValueError:
        pass
    return f"https://{hote}/api/v1/p2p/master-link/join"


def _wg_cles():
    """(genkey, pubkey) reels : `wg genkey` / `wg pubkey`, purs calculs sans privilege."""
    def genkey():
        return subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()

    def pubkey(priv):
        return subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    return genkey, pubkey


def _ecrire_etat_wg(etat: Dict) -> None:
    """Ecriture atomique en 0600 : l'unite .path (root) applique le changement."""
    init_dirs()
    with oubli.verrou(P2P_DIR):            # #3335 : verrou commun des écrivains de wg_mesh.json
        oubli.ecrire_atomique(WG_MESH_CONFIG, etat, 0o600)


async def _rejoindre_maitre(master_addr: str, token: str) -> Dict:
    """Côté box qui REJOINT : envoie la demande de jonction au parent (appel SORTANT) et, si le parent approuve, enregistre son rôle de pair."""
    if not automesh.adresse_valide(master_addr):
        raise HTTPException(status_code=400, detail="Adresse du parent invalide")
    my_fp = get_node_id()
    my_hostname = get_hostname()
    my_addr = get_lan_ip()
    url = _url_jonction(master_addr)
    # #2885 : la cle du pair part avec la demande, sinon le maitre l'inscrit sans tunnel.
    corps = {"token": token, "fingerprint": my_fp, "hostname": my_hostname, "address": my_addr}
    try:
        genkey, pubkey = _wg_cles()
        etat_wg, pub = mesh.preparer_pair(get_wg_mesh_config(), genkey, pubkey)
        await asyncio.to_thread(_ecrire_etat_wg, etat_wg)
        corps.update({"wg_public_key": pub, "wg_port": int(etat_wg.get("listen_port", WG_PORT))})
    except (OSError, subprocess.SubprocessError, ValueError) as e:
        log.warning("tunnel du pair non prepare : %s", e)     # l'inscription reste possible sans tunnel
    try:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--connect-timeout", "10",
            *(["-k"] if url.startswith("http://") else []),
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-d", json.dumps(corps),
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)

        if proc.returncode != 0:
            raise HTTPException(status_code=502, detail="Failed to reach master")

        result = json.loads(stdout.decode())

        # If approved, update local config
        if result.get("status") == "approved":
            config = await asyncio.to_thread(get_ml_config)
            config["role"] = "peer"
            config["upstream"] = master_addr
            config["depth"] = result.get("depth", 1)
            await asyncio.to_thread(save_ml_config, config)
            if isinstance(result.get("wg"), dict) and corps.get("wg_public_key"):
                try:
                    await asyncio.to_thread(_ecrire_etat_wg, mesh.appliquer_offre(get_wg_mesh_config(), result["wg"], master_addr))
                except (OSError, ValueError) as e:
                    log.warning("offre de tunnel du maitre refusee : %s", e)

        return result

    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Invalid response from master")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Master timeout")


@app.post("/master-link/join-with-token")
async def ml_join_upstream(
    master_addr: str,
    token: str,
    user: dict = Depends(require_jwt)
):
    """Join a mesh as peer using a token (peer-side operation)."""
    return await _rejoindre_maitre(master_addr, token)


class CodeRequest(BaseModel):
    code: str


@app.post("/master-link/join-with-code")
async def ml_join_with_code(req: CodeRequest, user: dict = Depends(require_jwt)):
    """Rejoindre le maillage avec UN code (adresse du parent + jeton) au lieu de deux saisies (#2475). La box appelle le parent ; c'est le parent qui décide."""
    try:
        adresse, jeton = automesh.decoder(req.code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return await _rejoindre_maitre(adresse, jeton)


# ============== Health ==============

@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-p2p", "version": "1.9.0"}


# ============== DHT (Kademlia, feature-flagged) — Issue #774 Task 9 ==============
#
# Backward compatible by construction: with [dht].enabled = false (the
# default when the section is absent from p2p.toml), _dht_startup sets
# app.state.dht = None and nothing new is started. Every endpoint below
# checks app.state.dht is not None before touching the DHT.

DHT_AUDIT_LOG = Path("/var/log/secubox/p2p/p2p-audit.log")


def _dht_audit(event: str, **fields):
    """Best-effort append-only audit line; never raises."""
    try:
        DHT_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": datetime.utcnow().isoformat(), "event": event, **fields})
        with open(DHT_AUDIT_LOG, "a") as f:
            f.write(line + "\n")
    except Exception as exc:  # noqa: BLE001
        log.warning("dht audit log write failed: %s", exc)


@app.on_event("startup")
async def _dht_startup():
    """Start the Kademlia DHT iff [dht].enabled — never break app startup."""
    app.state.dht = None
    try:
        cfg = mesh.load_p2p_config(CONFIG_FILE)
        if not cfg["dht"]["enabled"]:
            return

        did, priv_hex = annuaire_client.node_identity()
        if not did or not priv_hex:
            log.warning("dht enabled but node has no annuaire identity; not starting")
            return

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        id_pubkey = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        wg_pubkey = ""
        try:
            wg_pubkey = get_wg_mesh_config().get("public_key") or ""
        except Exception:  # noqa: BLE001
            wg_pubkey = ""

        advertise_host = cfg["dht"].get("advertise_host", "") or "0.0.0.0"
        endpoint = f'{advertise_host}:{cfg["dht"]["port"]}'

        net = dht.DHTNetwork(did, id_pubkey, wg_pubkey, endpoint)
        await net.start(host="0.0.0.0", port=cfg["dht"]["port"])
        net.load_routing()
        _garder_tache(asyncio.create_task(net.bootstrap(seeds=cfg["dht"]["bootstrap"], annuaire_nodes=[])))
        app.state.dht = net
        log.info("DHT started did=%s port=%s", did, cfg["dht"]["port"])
    except Exception as exc:  # noqa: BLE001
        log.warning("dht startup failed (continuing without DHT): %s", exc)
        app.state.dht = None


@app.on_event("shutdown")
async def _dht_shutdown():
    """Persist the routing table and close the DHT transport, best-effort."""
    net = getattr(app.state, "dht", None)
    if not net:
        return
    try:
        net.save_routing()
    except Exception as exc:  # noqa: BLE001
        log.warning("dht save_routing failed: %s", exc)
    try:
        await net.stop()
    except Exception as exc:  # noqa: BLE001
        log.warning("dht stop failed: %s", exc)


@app.get("/dht/peers", dependencies=[Depends(require_lecture)])
async def dht_peers():
    """Routing table snapshot (public read). Disabled -> empty/zeroed shape."""
    net = getattr(app.state, "dht", None)
    if net is None:
        return {"enabled": False, "peers": [], "buckets": 0}
    return {
        "enabled": True,
        "peers": [
            {"node_id_hex": n.node_id.hex(), "did": n.did,
             "endpoint": f"{n.endpoint[0]}:{n.endpoint[1]}"}
            for n in net.routing.all_nodes()
        ],
        "buckets": len([b for b in net.routing.buckets if b.nodes]),
    }


@app.post("/dht/announce")
async def dht_announce(user: dict = Depends(require_jwt)):
    """Sign + publish our own reachability record to the DHT (auth required)."""
    net = getattr(app.state, "dht", None)
    if net is None:
        raise HTTPException(status_code=400, detail="dht disabled")
    await net.announce()
    _dht_audit("dht_announce", did=net.did)
    return {"ok": True, "key": net.self_id.hex()}


@app.get("/dht/find/{did}", dependencies=[Depends(require_lecture)])
async def dht_find(did: str):
    """Resolve a DID to its verified reachability record via the DHT (public read)."""
    net = getattr(app.state, "dht", None)
    if net is None:
        raise HTTPException(status_code=400, detail="dht disabled")
    rec = await net.find_peer(did)
    if rec is None:
        raise HTTPException(status_code=404, detail="not found")
    return rec


# ============== Federation health-checks (feature-flagged) — Issue #774 Task 13 ==============
#
# Backward compatible by construction: with [federation].health_checks = false
# (the default when the section is absent from p2p.toml), _federation_startup
# sets app.state.health_store = app.state.health_checker = None and nothing
# new is started. Every endpoint below checks app.state.health_checker is not
# None before touching it.

@app.on_event("startup")
async def _federation_startup():
    """Start the federation health-checker iff [federation].health_checks —
    never break app startup. When app.state.dht is set (DHT enabled), each
    sweep also publishes the store snapshot into the DHT's advisory
    health_store (make_dht_publisher)."""
    app.state.health_store = None
    app.state.health_checker = None
    try:
        cfg = mesh.load_p2p_config(CONFIG_FILE)
        if not cfg["federation"]["health_checks"]:
            return

        store = federation.HealthStore(fail_threshold=cfg["federation"]["fail_threshold"])

        publish_fn = None
        if getattr(app.state, "dht", None):
            publish_fn = federation.make_dht_publisher(app.state.dht)

        probe_fn = functools.partial(
            federation.default_probe, timeout=cfg["federation"]["probe_timeout"]
        )
        checker = federation.HealthChecker(
            federation.services_from_registry,
            probe_fn,
            store,
            interval=cfg["federation"]["interval"],
            max_concurrency=cfg["federation"]["max_concurrency"],
            enabled=True,
            publish_fn=publish_fn,
        )
        checker.start()

        app.state.health_store = store
        app.state.health_checker = checker
        log.info("federation health-checker started interval=%s", cfg["federation"]["interval"])
    except Exception as exc:  # noqa: BLE001
        log.warning("federation startup failed (continuing without health-checks): %s", exc)
        app.state.health_store = None
        app.state.health_checker = None


@app.on_event("shutdown")
async def _federation_shutdown():
    """Stop the federation health-checker's background sweep loop, best-effort."""
    checker = getattr(app.state, "health_checker", None)
    if not checker:
        return
    try:
        await checker.stop()
    except Exception as exc:  # noqa: BLE001
        log.warning("federation checker stop failed: %s", exc)


@app.get("/federation/services", dependencies=[Depends(require_lecture)])
async def federation_services():
    """Federated services + their current health status (public read).
    Disabled -> enabled: false, but the service list is still returned
    (health reported as 'unknown' for each)."""
    store = getattr(app.state, "health_store", None)
    checker = getattr(app.state, "health_checker", None)
    return {
        "enabled": checker is not None,
        "services": [
            {
                **svc,
                "health": store.status_of(svc["id"]) if store else {"status": "unknown"},
            }
            for svc in federation.services_from_registry()
        ],
    }


@app.post("/federation/healthcheck")
async def federation_healthcheck(user: dict = Depends(require_jwt)):
    """Force an immediate health-check sweep (auth required)."""
    checker = getattr(app.state, "health_checker", None)
    if checker is None:
        raise HTTPException(status_code=400, detail="health checks disabled")
    n = await checker.sweep_once()
    return {"ok": True, "probed": n}


# ============== Master-Link election/heartbeat (feature-flagged) — Issue #774 Task 16b ====
#
# Backward compatible by construction: with [masterlink].enabled = false (the
# default when the section is absent from p2p.toml), _masterlink_startup sets
# app.state.masterlink = None and nothing new is started. Every endpoint below
# checks app.state.masterlink is not None before touching it.

def _masterlink_peers_fn() -> list:
    """Real peers_fn for MasterLink: derive election candidates from the
    live wg-mesh state (wg_mesh.json), via masterlink.peers_from_mesh().
    Never raises — any error (missing/malformed wg_mesh.json, etc.) yields
    an empty candidate list, so a broken mesh state degrades to
    self-election rather than crashing the tick loop."""
    try:
        return masterlink.peers_from_mesh(get_wg_mesh_config())
    except Exception as exc:  # noqa: BLE001
        log.warning("masterlink peers_fn failed (mesh state unavailable): %s", exc)
        return []


@app.on_event("startup")
async def _masterlink_startup():
    """Start the master-link election/heartbeat state machine iff
    [masterlink].enabled — never break app startup."""
    app.state.masterlink = None
    try:
        cfg = mesh.load_p2p_config(CONFIG_FILE)
        if not cfg["masterlink"]["enabled"]:
            return

        did, priv_hex = annuaire_client.node_identity()
        if not did or not priv_hex:
            log.warning("masterlink enabled but node has no annuaire identity; not starting")
            return

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        priv_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        id_pubkey = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

        self_id_hex = dht.node_id_for(did).hex()

        peer_addrs = []
        for a in cfg["masterlink"]["peer_addrs"]:
            try:
                host, port_s = a.rsplit(":", 1)
                peer_addrs.append((host, int(port_s)))
            except (ValueError, AttributeError):
                log.warning("masterlink: skipping malformed peer_addrs entry %r", a)

        term_store = masterlink.TermStore()
        ml = masterlink.MasterLink(
            self_id_hex, cfg["masterlink"]["priority"], _masterlink_peers_fn, lambda msg: None,
            term_store, id_pubkey=id_pubkey,
            heartbeat_interval=cfg["masterlink"]["heartbeat_interval"],
            election_timeout=cfg["masterlink"]["election_timeout"],
            peer_addrs=peer_addrs,
        )
        await ml.start(host="0.0.0.0", port=cfg["masterlink"]["port"])
        ml.start_ticking()
        app.state.masterlink = ml
        log.info("masterlink started self_id=%s port=%s", self_id_hex, cfg["masterlink"]["port"])
    except Exception as exc:  # noqa: BLE001
        log.warning("masterlink startup failed (continuing without masterlink): %s", exc)
        app.state.masterlink = None


@app.on_event("shutdown")
async def _masterlink_shutdown():
    """Stop the master-link tick loop and close its UDP transport, best-effort."""
    ml = getattr(app.state, "masterlink", None)
    if not ml:
        return
    try:
        await ml.stop()
    except Exception as exc:  # noqa: BLE001
        log.warning("masterlink stop failed: %s", exc)


@app.get("/masterlink/topology", dependencies=[Depends(require_lecture)])
async def masterlink_topology():
    """Snapshot of this node's master-link topology (public read).
    Disabled -> {"enabled": false}."""
    ml = getattr(app.state, "masterlink", None)
    if ml is None:
        return {"enabled": False}
    return {"enabled": True, **ml.topology()}


@app.post("/masterlink/promote")
async def masterlink_promote(user: dict = Depends(require_jwt)):
    """Force an on-demand promotion attempt (auth required)."""
    ml = getattr(app.state, "masterlink", None)
    if ml is None:
        raise HTTPException(status_code=400, detail="masterlink disabled")
    result = ml.request_promotion()
    _dht_audit("masterlink_promote", **result)
    return result


# ============== Macro Grant (M2) ==============
#
# POST /api/v1/p2p-macro/grant/{service_id}
#
# Body (JSON): full self-signed Subscription dict + subscriber_pubkey field:
#   {subscription_id, subscriber, service_id, requested_at,
#    sig, signer_did, subscriber_pubkey}
#
# The endpoint authorizes self-certifyingly:
#   (a) subscriber_pubkey hashes to subscriber DID (did_from_pubkey_hex)
#   (b) ed25519 sig verifies over the canonical Subscription payload
#       (model_dump minus sig/signer_did/subscriber_pubkey, sort_keys)
#   (c) service_id matches the URL slug
#   (d) the local offer has approval_mode=="auto" and carries a macro descriptor
#
# On success → 200 {<credential from macroctl>, service_id}
# On auth failure → 403 {error: ...}
# On macroctl failure → 502 {error: ...}
# Unknown service → 404 {error: ...}


def _verify_subscription_sig(sub: Dict[str, Any], pub_hex: str) -> bool:
    """Verify an Ed25519 self-signature on a Subscription dict.

    Mirrors the signing logic in packages/secubox-annuaire/annuaire/verbs.py::subscribe():

        full = sub.model_dump()
        payload = {k: v for k, v in full.items() if k not in ("sig", "signer_did")}
        sig_hex = sign(subscriber_priv, canonical_bytes(payload))

    canonical_bytes (from annuaire/crypto.py):
        json.dumps(obj, sort_keys=True, separators=(",",":")).encode("utf-8")

    The ``subscriber_pubkey`` field is NOT part of the Subscription model so it
    is absent from ``model_dump()`` and therefore NOT included in the signed
    payload — we explicitly exclude it here too.

    Args:
        sub:     Full Subscription dict including sig, signer_did, subscriber_pubkey.
        pub_hex: Hex-encoded raw 32-byte Ed25519 public key to verify against.

    Returns:
        True if the sig verifies, False on any failure.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        # Reconstruct the exact payload that was signed: strip sig, signer_did,
        # and subscriber_pubkey (not part of the Subscription model).
        _STRIP = frozenset(("sig", "signer_did", "subscriber_pubkey"))
        payload = {k: v for k, v in sub.items() if k not in _STRIP}

        # canonical_bytes — identical to annuaire/crypto.py::canonical_bytes.
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        sig_hex: str = sub.get("sig", "") or ""
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)

        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, msg)
        return True
    except Exception:  # noqa: BLE001
        return False


@app.post("/api/v1/p2p-macro/grant/{service_id}")
async def macro_grant_endpoint(service_id: str, req: Request):
    """Provider-side macro grant endpoint.

    The consumer (subscriber) POSTs its self-signed Subscription; we verify
    self-certifyingly and, on success, invoke macroctl to provision the macro.
    """
    from api import macro_grant, annuaire_client  # noqa: PLC0415

    try:
        body = await req.json()
    except json.JSONDecodeError:
        return JSONResponse({"error": "request body must be valid JSON"}, status_code=400)

    if not isinstance(body, dict):
        return JSONResponse({"error": "body must be a JSON object"}, status_code=400)

    # Look up the service offer in the annuaire catalog.
    catalog, _err = annuaire_client.get_catalog()
    offer = next((o for o in catalog if o.get("service_id") == service_id), None)
    if offer is None:
        return JSONResponse({"error": "unknown service"}, status_code=404)

    def _verify(sub: Dict[str, Any]) -> bool:
        pub = sub.get("subscriber_pubkey", "") or ""
        if not pub:
            return False
        # (a) pubkey must hash to subscriber DID.
        if annuaire_client.did_from_pubkey_hex(pub) != sub.get("subscriber"):
            return False
        # (b) Ed25519 sig over canonical payload.
        return _verify_subscription_sig(sub, pub)

    ok, why = macro_grant.authorize_grant(offer, body, _verify)
    if not ok:
        return JSONResponse({"error": why}, status_code=403)

    src_ip = (req.client.host if req.client else "") or req.headers.get("x-real-ip", "")
    macro = offer.get("macro", {})
    cred, err = macro_grant.run_grant(
        macro.get("kind", ""),
        body.get("subscriber", ""),
        src_ip,
        macro.get("params", {}),
    )
    if err:
        log.warning("macro grant failed for %s: %s", service_id, err)  # server-side detail
        return JSONResponse({"error": "macro grant failed"}, status_code=502)

    cred = cred or {}
    cred["service_id"] = service_id
    return cred


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
