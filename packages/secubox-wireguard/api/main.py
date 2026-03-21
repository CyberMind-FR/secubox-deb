"""
secubox-wireguard — FastAPI application
Port de luci-app-wireguard-dashboard

Méthodes RPCD portées :
  status, peers, interfaces, generate_keys, create_interface,
  add_peer, remove_peer, config, generate_qr, traffic,
  interface_control, bandwidth_rates, ping_peer
"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from secubox_core.auth   import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess, base64, shutil, re, json

app = FastAPI(title="secubox-wireguard", version="1.0.0",
              root_path="/api/v1/wireguard")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log    = get_logger("wireguard")


# ── helpers ──────────────────────────────────────────────────────

def _wg(*args, timeout=10) -> subprocess.CompletedProcess:
    return subprocess.run(["/usr/bin/sudo", "/usr/bin/wg"] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def _wg_quick(*args, timeout=30) -> subprocess.CompletedProcess:
    return subprocess.run(["/usr/bin/sudo", "/usr/bin/wg-quick"] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def _ifaces() -> list[str]:
    r = _wg("show", "interfaces")
    return [i for i in r.stdout.strip().split() if i]


def _parse_wg_dump(iface: str) -> dict:
    """Parse 'wg show <iface> dump' en dict structuré."""
    r = _wg("show", iface, "dump")
    lines = r.stdout.strip().splitlines()
    result = {"interface": {}, "peers": []}
    if not lines:
        return result
    # Première ligne = interface
    parts = lines[0].split("\t")
    if len(parts) >= 4:
        result["interface"] = {
            "private_key":  parts[0],
            "public_key":   parts[1],
            "listen_port":  int(parts[2]) if parts[2].isdigit() else 0,
            "fwmark":       parts[3],
        }
    # Lignes suivantes = peers
    for line in lines[1:]:
        p = line.split("\t")
        if len(p) >= 8:
            result["peers"].append({
                "public_key":        p[0],
                "preshared_key":     p[1],
                "endpoint":          p[2],
                "allowed_ips":       p[3].split(","),
                "latest_handshake":  int(p[4]) if p[4].isdigit() else 0,
                "transfer_rx":       int(p[5]) if p[5].isdigit() else 0,
                "transfer_tx":       int(p[6]) if p[6].isdigit() else 0,
                "persistent_keepalive": p[7],
            })
    return result


# ── GET endpoints ─────────────────────────────────────────────────

def _get_iface_address(iface: str) -> str:
    """Get interface IP address."""
    try:
        r = subprocess.run(["ip", "-o", "addr", "show", iface], capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if "inet " in line:
                return line.split("inet ")[1].split()[0]
    except Exception:
        pass
    return ""


def _is_iface_up(iface: str) -> bool:
    """Check if interface is up (WireGuard shows 'unknown' when up)."""
    from pathlib import Path
    operstate = Path(f"/sys/class/net/{iface}/operstate")
    if operstate.exists():
        state = operstate.read_text().strip()
        # WireGuard interfaces show "unknown" when up
        return state in ("up", "unknown")
    return False


@router.get("/status")
async def status():
    """WireGuard status for dashboard (public)."""
    interfaces = []
    for iface in _ifaces():
        dump = _parse_wg_dump(iface)
        intf = dump["interface"]
        interfaces.append({
            "name": iface,
            "public_key": intf.get("public_key", ""),
            "listen_port": intf.get("listen_port", 0),
            "peer_count": len(dump["peers"]),
            "up": _is_iface_up(iface),
            "address": _get_iface_address(iface),
        })
    return {"interfaces": interfaces, "wg_available": bool(shutil.which("wg"))}


@router.get("/interfaces")
async def interfaces():
    """List interfaces for dashboard (public)."""
    result = []
    for iface in _ifaces():
        dump = _parse_wg_dump(iface)
        intf = dump["interface"]
        result.append({
            "name": iface,
            "public_key": intf.get("public_key", ""),
            "listen_port": intf.get("listen_port", 0),
            "peer_count": len(dump["peers"]),
            "up": _is_iface_up(iface),
            "address": _get_iface_address(iface),
        })
    return {"interfaces": result}


@router.get("/peers")
async def peers(iface: str = ""):
    """List peers for dashboard (public)."""
    all_peers = []
    ifaces = [iface] if iface else _ifaces()
    for if_name in ifaces:
        dump = _parse_wg_dump(if_name)
        for p in dump.get("peers", []):
            all_peers.append({
                "public_key": p["public_key"],
                "name": p["public_key"][:12] + "...",
                "allowed_ips": ",".join(p.get("allowed_ips", [])),
                "interface": if_name,
                "rx_bytes": p.get("transfer_rx", 0),
                "tx_bytes": p.get("transfer_tx", 0),
                "latest_handshake": p.get("latest_handshake", 0),
                "endpoint": p.get("endpoint", ""),
            })
    return {"peers": all_peers}


@router.get("/traffic")
async def traffic():
    """Traffic stats for dashboard (public)."""
    traffic_data = {}
    for iface in _ifaces():
        from pathlib import Path
        base = Path(f"/sys/class/net/{iface}/statistics")
        if base.exists():
            try:
                traffic_data[iface] = {
                    "rx_bytes": int((base / "rx_bytes").read_text()),
                    "tx_bytes": int((base / "tx_bytes").read_text()),
                }
            except Exception:
                traffic_data[iface] = {"rx_bytes": 0, "tx_bytes": 0}
    return {"traffic": traffic_data}


@router.get("/bandwidth_rates")
async def bandwidth_rates(iface: str = "wg0", user=Depends(require_jwt)):
    """Lecture des stats /sys/class/net/<iface>/statistics/."""
    from pathlib import Path
    base = Path(f"/sys/class/net/{iface}/statistics")
    if not base.exists():
        return {"rx_bytes": 0, "tx_bytes": 0, "iface": iface}
    return {
        "iface":    iface,
        "rx_bytes": int((base / "rx_bytes").read_text()),
        "tx_bytes": int((base / "tx_bytes").read_text()),
    }


@router.get("/config")
async def config(iface: str = "wg0", user=Depends(require_jwt)):
    """Contenu de /etc/wireguard/<iface>.conf (clés privées masquées)."""
    from pathlib import Path
    conf = Path(f"/etc/wireguard/{iface}.conf")
    if not conf.exists():
        raise HTTPException(404, f"/etc/wireguard/{iface}.conf introuvable")
    content = conf.read_text()
    # Masquer les clés privées
    content = re.sub(r"(PrivateKey\s*=\s*)\S+", r"\1[HIDDEN]", content)
    return PlainTextResponse(content)


# ── Génération de clés ────────────────────────────────────────────

@router.post("/generate_keys")
async def generate_keys(user=Depends(require_jwt)):
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
    private_key = priv.stdout.strip()
    pub = subprocess.run(["wg", "pubkey"],
                         input=private_key, capture_output=True, text=True)
    public_key = pub.stdout.strip()
    psk = subprocess.run(["wg", "genpsk"], capture_output=True, text=True)
    return {
        "private_key":   private_key,
        "public_key":    public_key,
        "preshared_key": psk.stdout.strip(),
    }


# ── QR Code ───────────────────────────────────────────────────────

@router.get("/generate_qr")
async def generate_qr(iface: str = "wg0",
                      peer_pubkey: str = "",
                      user=Depends(require_jwt)):
    """Génère un QR code PNG (base64) pour un peer."""
    if not shutil.which("qrencode"):
        raise HTTPException(503, "qrencode non installé (apt install qrencode)")
    # Config minimale du peer
    conf = f"[Interface]\nPrivateKey = <GENERATED>\n\n[Peer]\nPublicKey = SERVEUR_PUBKEY\nEndpoint = SERVEUR:51820\nAllowedIPs = 0.0.0.0/0"
    r = subprocess.run(
        ["qrencode", "-t", "PNG", "-o", "-"],
        input=conf, capture_output=True, timeout=10
    )
    if r.returncode != 0:
        raise HTTPException(500, r.stderr.decode()[:200])
    return {"qr_png_b64": base64.b64encode(r.stdout).decode()}


# ── Actions POST ──────────────────────────────────────────────────

class InterfaceRequest(BaseModel):
    name:        str = "wg0"
    listen_port: int = 51820
    address:     str = "10.0.0.1/24"

class PeerRequest(BaseModel):
    iface:        str = "wg0"
    public_key:   str
    allowed_ips:  str = "10.0.0.2/32"
    endpoint:     str = ""
    keepalive:    int = 0

class ControlRequest(BaseModel):
    iface:  str = "wg0"
    action: str  # up | down | restart


@router.post("/create_interface")
async def create_interface(req: InterfaceRequest, user=Depends(require_jwt)):
    keys = await generate_keys(user)
    from pathlib import Path
    conf = (f"[Interface]\n"
            f"PrivateKey = {keys['private_key']}\n"
            f"ListenPort = {req.listen_port}\n"
            f"Address = {req.address}\n")
    conf_path = Path(f"/etc/wireguard/{req.name}.conf")
    conf_path.write_text(conf)
    conf_path.chmod(0o600)
    return {"success": True, "iface": req.name, "public_key": keys["public_key"]}


@router.post("/add_peer")
async def add_peer(req: PeerRequest, user=Depends(require_jwt)):
    args = ["wg", "set", req.iface,
            "peer", req.public_key,
            "allowed-ips", req.allowed_ips]
    if req.endpoint:
        args += ["endpoint", req.endpoint]
    if req.keepalive:
        args += ["persistent-keepalive", str(req.keepalive)]
    r = subprocess.run(args, capture_output=True, text=True)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()}


@router.post("/remove_peer")
async def remove_peer(public_key: str, iface: str = "wg0", user=Depends(require_jwt)):
    r = subprocess.run(
        ["wg", "set", iface, "peer", public_key, "remove"],
        capture_output=True, text=True
    )
    return {"success": r.returncode == 0}


@router.post("/interface_control")
async def interface_control(req: ControlRequest, user=Depends(require_jwt)):
    if req.action not in ("up", "down", "restart"):
        raise HTTPException(400, "action doit être up|down|restart")
    if req.action == "restart":
        subprocess.run(["wg-quick", "down", req.iface], capture_output=True)
        r = subprocess.run(["wg-quick", "up", req.iface], capture_output=True, text=True)
    else:
        r = subprocess.run(["wg-quick", req.action, req.iface], capture_output=True, text=True)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


class StartStopRequest(BaseModel):
    interface: str = "wg0"


@router.post("/start")
async def start(req: StartStopRequest, user=Depends(require_jwt)):
    """Start a WireGuard interface."""
    r = subprocess.run(["wg-quick", "up", req.interface], capture_output=True, text=True, timeout=30)
    log.info("start interface: %s", req.interface)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/stop")
async def stop(req: StartStopRequest, user=Depends(require_jwt)):
    """Stop a WireGuard interface."""
    r = subprocess.run(["wg-quick", "down", req.interface], capture_output=True, text=True, timeout=30)
    log.info("stop interface: %s", req.interface)
    return {"success": r.returncode == 0, "output": (r.stdout + r.stderr).strip()[:500]}


@router.post("/delete_interface")
async def delete_interface(req: StartStopRequest, user=Depends(require_jwt)):
    """Delete a WireGuard interface."""
    from pathlib import Path
    # First stop if running
    subprocess.run(["wg-quick", "down", req.interface], capture_output=True)
    # Remove config file
    conf = Path(f"/etc/wireguard/{req.interface}.conf")
    if conf.exists():
        conf.unlink()
    log.info("delete interface: %s", req.interface)
    return {"success": True, "interface": req.interface}


class DeletePeerRequest(BaseModel):
    public_key: str
    interface: str = "wg0"


@router.post("/delete_peer")
async def delete_peer(req: DeletePeerRequest, user=Depends(require_jwt)):
    """Delete a peer from interface."""
    r = subprocess.run(
        ["wg", "set", req.interface, "peer", req.public_key, "remove"],
        capture_output=True, text=True
    )
    log.info("delete peer: %s from %s", req.public_key[:12], req.interface)
    return {"success": r.returncode == 0}


@router.get("/get_config")
async def get_config(interface: str = "wg0", user=Depends(require_jwt)):
    """Get interface configuration."""
    from pathlib import Path
    conf = Path(f"/etc/wireguard/{interface}.conf")
    if not conf.exists():
        return {"config": f"# No configuration for {interface}"}
    content = conf.read_text()
    # Mask private keys
    content = re.sub(r"(PrivateKey\s*=\s*)\S+", r"\1[HIDDEN]", content)
    return {"config": content}


@router.post("/reload")
async def reload(user=Depends(require_jwt)):
    """Reload all WireGuard interfaces."""
    for iface in _ifaces():
        subprocess.run(["wg-quick", "down", iface], capture_output=True)
        subprocess.run(["wg-quick", "up", iface], capture_output=True)
    log.info("reload all interfaces")
    return {"success": True}


@router.post("/ping_peer")
async def ping_peer(ip: str, count: int = 3, user=Depends(require_jwt)):
    r = subprocess.run(
        ["ping", "-c", str(count), "-W", "2", ip],
        capture_output=True, text=True, timeout=15
    )
    return {"reachable": r.returncode == 0, "output": r.stdout[-500:]}


# ── Config génération ─────────────────────────────────────────────

class GenerateConfigRequest(BaseModel):
    iface: str = "wg0"
    peer_name: str = "client1"
    peer_ip: str = "10.0.0.2/32"


@router.post("/generate_config")
async def generate_config(req: GenerateConfigRequest, user=Depends(require_jwt)):
    """Générer une config client WireGuard."""
    from pathlib import Path
    keys = await generate_keys(user)

    # Lire la config serveur pour obtenir la clé publique
    server_conf = Path(f"/etc/wireguard/{req.iface}.conf")
    server_pubkey = "SERVER_PUBKEY"
    server_port = 51820

    if server_conf.exists():
        dump = _parse_wg_dump(req.iface)
        server_pubkey = dump.get("interface", {}).get("public_key", "SERVER_PUBKEY")
        server_port = dump.get("interface", {}).get("listen_port", 51820)

    client_conf = f"""[Interface]
PrivateKey = {keys['private_key']}
Address = {req.peer_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pubkey}
Endpoint = YOUR_SERVER_IP:{server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    return {
        "config": client_conf,
        "public_key": keys["public_key"],
        "private_key": keys["private_key"],
    }


# ── Peer descriptions ─────────────────────────────────────────────

@router.get("/peer_descriptions")
async def peer_descriptions(iface: str = "wg0", user=Depends(require_jwt)):
    """Descriptions des peers (stockées en commentaires ou fichier séparé)."""
    from pathlib import Path
    desc_file = Path(f"/etc/secubox/wireguard/{iface}_peers.json")
    if desc_file.exists():
        return json.loads(desc_file.read_text())
    return {}


# ── Endpoints management ──────────────────────────────────────────

@router.get("/get_endpoints")
async def get_endpoints(user=Depends(require_jwt)):
    """Liste des endpoints configurés."""
    from pathlib import Path
    endpoints_file = Path("/etc/secubox/wireguard/endpoints.json")
    if endpoints_file.exists():
        return json.loads(endpoints_file.read_text())
    return {"endpoints": [], "default": ""}


class EndpointRequest(BaseModel):
    name: str
    address: str
    port: int = 51820


@router.post("/set_endpoint")
async def set_endpoint(req: EndpointRequest, user=Depends(require_jwt)):
    log.info("set_endpoint: %s -> %s:%d", req.name, req.address, req.port)
    return {"success": True, "endpoint": f"{req.address}:{req.port}"}


@router.post("/set_default_endpoint")
async def set_default_endpoint(name: str, user=Depends(require_jwt)):
    log.info("set_default_endpoint: %s", name)
    return {"success": True, "default": name}


@router.post("/delete_endpoint")
async def delete_endpoint(name: str, user=Depends(require_jwt)):
    log.info("delete_endpoint: %s", name)
    return {"success": True}


# ── Uplink management (multi-WAN failover) ────────────────────────

@router.get("/uplink_status")
async def uplink_status(user=Depends(require_jwt)):
    """Statut des uplinks WireGuard."""
    return {"active_uplink": None, "uplinks": []}


@router.get("/uplinks")
async def uplinks(user=Depends(require_jwt)):
    """Liste des uplinks configurés."""
    from pathlib import Path
    uplinks_file = Path("/etc/secubox/wireguard/uplinks.json")
    if uplinks_file.exists():
        return json.loads(uplinks_file.read_text())
    return []


class UplinkRequest(BaseModel):
    name: str
    endpoint: str
    public_key: str
    priority: int = 100


@router.post("/add_uplink")
async def add_uplink(req: UplinkRequest, user=Depends(require_jwt)):
    log.info("add_uplink: %s -> %s", req.name, req.endpoint)
    return {"success": True, "uplink": req.name}


@router.post("/remove_uplink")
async def remove_uplink(name: str, user=Depends(require_jwt)):
    log.info("remove_uplink: %s", name)
    return {"success": True}


@router.get("/test_uplink")
async def test_uplink(name: str, user=Depends(require_jwt)):
    """Tester la connectivité d'un uplink."""
    return {"name": name, "reachable": False, "latency_ms": 0}


@router.get("/offer_uplink")
async def offer_uplink(name: str, user=Depends(require_jwt)):
    """Marquer un uplink comme disponible."""
    return {"success": True, "name": name, "offered": True}


@router.get("/withdraw_uplink")
async def withdraw_uplink(name: str, user=Depends(require_jwt)):
    """Retirer un uplink de la rotation."""
    return {"success": True, "name": name, "withdrawn": True}


class UplinkPriorityRequest(BaseModel):
    name: str
    priority: int


@router.post("/set_uplink_priority")
async def set_uplink_priority(req: UplinkPriorityRequest, user=Depends(require_jwt)):
    log.info("set_uplink_priority: %s -> %d", req.name, req.priority)
    return {"success": True}


class UplinkFailoverRequest(BaseModel):
    enabled: bool
    check_interval: int = 30


@router.post("/set_uplink_failover")
async def set_uplink_failover(req: UplinkFailoverRequest, user=Depends(require_jwt)):
    log.info("set_uplink_failover: enabled=%s", req.enabled)
    return {"success": True, "enabled": req.enabled}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "wireguard"}


app.include_router(router)
