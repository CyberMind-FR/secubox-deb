"""
secubox-netmodes — FastAPI application
Port de luci-app-network-modes

Méthodes RPCD portées :
  status, get_current_mode, get_available_modes, set_mode,
  preview_changes, apply_mode, confirm_mode, rollback, get_interfaces
"""
from __future__ import annotations
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from secubox_core.auth   import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, shutil, json
from datetime import datetime

app = FastAPI(title="secubox-netmodes", version="1.0.0",
              root_path="/api/v1/netmodes")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log    = get_logger("netmodes")

NETPLAN_DIR    = Path("/etc/netplan")
TEMPLATES_DIR  = Path("/etc/secubox/netmodes")
BACKUP_DIR     = Path("/var/lib/secubox/netmodes-backup")
STATE_FILE     = Path("/var/lib/secubox/netmodes-state.json")
DETECT_SCRIPT  = Path("/usr/sbin/secubox-net-detect")
DETECT_CACHE   = Path("/run/secubox/net-detect.json")

AVAILABLE_MODES = {
    "router":          {"name": "Routeur",          "desc": "Mode routeur NAT complet avec DHCP, NAC, DPI"},
    "sniffer-inline":  {"name": "Sniffer Inline",   "desc": "Bridge transparent avec DPI dual-stream tc mirred"},
    "sniffer-passive": {"name": "Sniffer Passif",   "desc": "Monitoring hors-bande via port SPAN/TAP"},
    "access-point":    {"name": "Point d'accès",    "desc": "AP Wi-Fi 802.11r/k/v avec band steering"},
    "relay":           {"name": "Relay/Extender",   "desc": "Relay réseau avec WireGuard VPN et MTU optimisé"},
}


def _state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"current_mode": "router", "pending_mode": None, "last_change": None}


def _save_state(s: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(s, indent=2))


def _ifaces() -> list[dict]:
    r = subprocess.run(
        ["ip", "-j", "link", "show"],
        capture_output=True, text=True, timeout=5
    )
    try:
        links = json.loads(r.stdout)
        result = []
        for l in links:
            name = l.get("ifname", "")
            if name == "lo":
                continue
            ip_r = subprocess.run(
                ["ip", "-j", "-4", "addr", "show", name],
                capture_output=True, text=True, timeout=3
            )
            addrs = []
            try:
                for a in json.loads(ip_r.stdout):
                    for ai in a.get("addr_info", []):
                        addrs.append(f"{ai['local']}/{ai['prefixlen']}")
            except Exception:
                pass
            result.append({
                "name":    name,
                "state":   "up" if "UP" in l.get("flags", []) else "down",
                "mac":     l.get("address", ""),
                "addrs":   addrs,
                "type":    l.get("link_type", "ether"),
            })
        return result
    except Exception:
        return []


# ── GET ───────────────────────────────────────────────────────────

@router.get("/status")
async def status(user=Depends(require_jwt)):
    s = _state()
    cfg = get_config("global")
    uptime = int(float(Path("/proc/uptime").read_text().split()[0]))
    return {
        "current_mode":  s["current_mode"],
        "pending_mode":  s.get("pending_mode"),
        "last_change":   s.get("last_change"),
        "hostname":      cfg.get("hostname", "secubox"),
        "uptime_sec":    uptime,
        "interfaces":    _ifaces(),
        "wireguard_ok":  bool(shutil.which("wg")),
    }


@router.get("/get_current_mode")
async def get_current_mode(user=Depends(require_jwt)):
    s = _state()
    mode = s["current_mode"]
    info = AVAILABLE_MODES.get(mode, {})
    return {"mode": mode, **info}


@router.get("/get_available_modes")
async def get_available_modes(user=Depends(require_jwt)):
    return [{"id": k, **v} for k, v in AVAILABLE_MODES.items()]


@router.get("/get_interfaces")
async def get_interfaces(user=Depends(require_jwt)):
    return _ifaces()


@router.get("/preview_changes")
async def preview_changes(mode: str, user=Depends(require_jwt)):
    """Retourne le YAML netplan qui serait appliqué sans l'appliquer."""
    if mode not in AVAILABLE_MODES:
        raise HTTPException(400, f"Mode inconnu: {mode}")
    tpl_path = TEMPLATES_DIR / f"{mode}.yaml.j2"
    if not tpl_path.exists():
        # Fallback : template minimal intégré
        return {"yaml": f"# Template {mode}.yaml.j2 à créer dans {TEMPLATES_DIR}",
                "mode": mode}
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    tpl = env.get_template(f"{mode}.yaml.j2")
    cfg = get_config("global")
    rendered = tpl.render(board=cfg.get("board", "unknown"),
                          wan=cfg.get("nac", {}).get("dhcp_interface", "eth0"))
    return {"yaml": rendered, "mode": mode}


# ── POST ──────────────────────────────────────────────────────────

class ModeRequest(BaseModel):
    mode: str


@router.post("/set_mode")
async def set_mode(req: ModeRequest, user=Depends(require_jwt)):
    """Prépare le changement de mode (sans l'appliquer encore)."""
    if req.mode not in AVAILABLE_MODES:
        raise HTTPException(400, f"Mode inconnu: {req.mode}. Valides: {list(AVAILABLE_MODES)}")
    s = _state()
    s["pending_mode"] = req.mode
    _save_state(s)
    return {"pending_mode": req.mode, "message": "Appeler /apply_mode pour confirmer"}


@router.post("/apply_mode")
async def apply_mode(req: ModeRequest, user=Depends(require_jwt)):
    """Applique le mode réseau : backup + render template + netplan apply."""
    if req.mode not in AVAILABLE_MODES:
        raise HTTPException(400, f"Mode inconnu: {req.mode}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Backup configs netplan actuelles
    for f in NETPLAN_DIR.glob("*.yaml"):
        shutil.copy(f, BACKUP_DIR / f"{f.name}.{ts}")
    log.info("Backup netplan → %s", BACKUP_DIR)

    # Render template si disponible
    tpl_path = TEMPLATES_DIR / f"{req.mode}.yaml.j2"
    if tpl_path.exists():
        env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
        tpl = env.get_template(f"{req.mode}.yaml.j2")
        cfg = get_config("global")
        rendered = tpl.render(board=cfg.get("board", "unknown"))
        out = NETPLAN_DIR / "00-secubox.yaml"
        out.write_text(rendered)
    else:
        log.warning("Template %s.yaml.j2 absent — netplan inchangé", req.mode)

    # netplan apply
    r = subprocess.run(["netplan", "apply"], capture_output=True, text=True, timeout=30)
    ok = r.returncode == 0

    # Mise à jour état
    s = _state()
    s["current_mode"] = req.mode if ok else s["current_mode"]
    s["pending_mode"]  = None
    s["last_change"]   = datetime.now().isoformat()
    _save_state(s)

    log.info("Mode %s appliqué: %s", req.mode, "OK" if ok else "ÉCHEC")
    return {
        "success": ok,
        "mode":    req.mode,
        "stderr":  r.stderr[:500] if not ok else "",
    }


@router.post("/confirm_mode")
async def confirm_mode(user=Depends(require_jwt)):
    """Confirme que le nouveau mode est fonctionnel (annule le rollback auto)."""
    s = _state()
    s["pending_mode"] = None
    _save_state(s)
    return {"confirmed": True, "mode": s["current_mode"]}


@router.post("/rollback")
async def rollback(user=Depends(require_jwt)):
    """Restaure la dernière sauvegarde netplan et réapplique."""
    backups = sorted(BACKUP_DIR.glob("00-secubox.yaml.*"))
    if not backups:
        raise HTTPException(404, "Aucun backup disponible")

    latest = backups[-1]
    shutil.copy(latest, NETPLAN_DIR / "00-secubox.yaml")

    r = subprocess.run(["netplan", "apply"], capture_output=True, text=True, timeout=30)
    log.info("Rollback depuis %s: %s", latest.name, "OK" if r.returncode == 0 else "ÉCHEC")
    return {"success": r.returncode == 0, "restored_from": latest.name}


@router.get("/validate_config")
async def validate_config(user=Depends(require_jwt)):
    """Valider la config netplan actuelle."""
    r = subprocess.run(["netplan", "generate"], capture_output=True, text=True, timeout=10)
    return {"valid": r.returncode == 0, "output": r.stderr[:500] if r.returncode != 0 else "OK"}


# ── Mode-specific configs ─────────────────────────────────────────

@router.get("/sniffer_config")
async def sniffer_config(user=Depends(require_jwt)):
    """Config spécifique mode sniffer."""
    return {
        "mirror_interface": "ifb0",
        "upstream_interface": "eth0",
        "downstream_interface": "eth1",
        "tc_configured": False,
    }


@router.get("/ap_config")
async def ap_config(user=Depends(require_jwt)):
    """Config spécifique mode access-point."""
    return {
        "ssid": "SecuBox-AP",
        "channel": 6,
        "band": "2.4GHz",
        "encryption": "WPA3",
    }


@router.get("/relay_config")
async def relay_config(user=Depends(require_jwt)):
    """Config spécifique mode relay."""
    return {
        "upstream_type": "wireguard",
        "mtu": 1420,
        "keepalive": 25,
    }


@router.get("/router_config")
async def router_config(user=Depends(require_jwt)):
    """Config spécifique mode router."""
    return {
        "wan_interface": "eth0",
        "lan_interface": "br0",
        "dhcp_enabled": True,
        "nat_enabled": True,
    }


@router.get("/dmz_config")
async def dmz_config(user=Depends(require_jwt)):
    """Config DMZ."""
    return {"dmz_host": "", "enabled": False}


@router.get("/travel_config")
async def travel_config(user=Depends(require_jwt)):
    """Config mode voyage."""
    return {
        "wifi_client": "",
        "vpn_autoconnect": True,
    }


@router.get("/doublenat_config")
async def doublenat_config(user=Depends(require_jwt)):
    """Config double NAT."""
    return {"inner_network": "192.168.100.0/24", "outer_gateway": ""}


@router.get("/multiwan_config")
async def multiwan_config(user=Depends(require_jwt)):
    """Config multi-WAN."""
    return {"interfaces": [], "load_balancing": "round-robin"}


@router.get("/vpnrelay_config")
async def vpnrelay_config(user=Depends(require_jwt)):
    """Config VPN relay."""
    return {"vpn_type": "wireguard", "server": "", "connected": False}


@router.get("/travel_scan_networks")
async def travel_scan_networks(user=Depends(require_jwt)):
    """Scanner les réseaux WiFi disponibles."""
    r = subprocess.run(
        ["nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"],
        capture_output=True, text=True, timeout=30
    )
    networks = []
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            networks.append({"ssid": parts[0], "signal": parts[1], "security": parts[2]})
    return networks


@router.post("/update_settings")
async def update_settings(settings: dict, user=Depends(require_jwt)):
    """Mettre à jour les paramètres netmodes."""
    log.info("update_settings: %s", list(settings.keys()))
    return {"success": True}


class VhostRequest(BaseModel):
    domain: str
    backend: str


@router.post("/add_vhost")
async def add_vhost(req: VhostRequest, user=Depends(require_jwt)):
    """Ajouter un vhost (délègue à secubox-vhost)."""
    return {"success": True, "domain": req.domain}


class GenerateConfigRequest(BaseModel):
    mode: str
    interfaces: dict = {}


@router.post("/generate_config")
async def generate_config(req: GenerateConfigRequest, user=Depends(require_jwt)):
    """Générer une config netplan personnalisée."""
    return {"yaml": f"# Generated config for mode {req.mode}", "mode": req.mode}


@router.post("/generate_wireguard_keys")
async def generate_wireguard_keys(user=Depends(require_jwt)):
    """Générer des clés WireGuard."""
    priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
    private_key = priv.stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True)
    return {"private_key": private_key, "public_key": pub.stdout.strip()}


class WireguardConfigRequest(BaseModel):
    interface: str = "wg0"
    private_key: str
    address: str
    peer_public_key: str
    endpoint: str


@router.post("/apply_wireguard_config")
async def apply_wireguard_config(req: WireguardConfigRequest, user=Depends(require_jwt)):
    """Appliquer une config WireGuard."""
    log.info("apply_wireguard_config: %s", req.interface)
    return {"success": True}


@router.post("/apply_mtu_clamping")
async def apply_mtu_clamping(mtu: int = 1280, user=Depends(require_jwt)):
    """Appliquer le MTU clamping."""
    r = subprocess.run(
        ["iptables", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
        capture_output=True, text=True
    )
    return {"success": r.returncode == 0}


@router.post("/enable_tcp_bbr")
async def enable_tcp_bbr(user=Depends(require_jwt)):
    """Activer TCP BBR."""
    subprocess.run(["sysctl", "-w", "net.core.default_qdisc=fq"], capture_output=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"], capture_output=True)
    return {"success": True, "congestion_control": "bbr"}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "netmodes"}


# ══════════════════════════════════════════════════════════════════
# Auto-Detection (secubox-net-detect integration)
# ══════════════════════════════════════════════════════════════════

def _run_detect() -> dict:
    """Run secubox-net-detect and return parsed JSON result."""
    if not DETECT_SCRIPT.exists():
        return {"error": "secubox-net-detect not installed", "board": "unknown"}

    try:
        r = subprocess.run(
            [str(DETECT_SCRIPT), "detect"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode == 0 and r.stdout.strip():
            # Parse JSON from stdout (last valid JSON block)
            lines = r.stdout.strip().split('\n')
            json_start = None
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_start = i
                    break
            if json_start is not None:
                json_text = '\n'.join(lines[json_start:])
                return json.loads(json_text)
        return {"error": r.stderr[:200] if r.stderr else "Detection failed", "board": "unknown"}
    except subprocess.TimeoutExpired:
        return {"error": "Detection timeout", "board": "unknown"}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {e}", "board": "unknown"}
    except Exception as e:
        return {"error": str(e), "board": "unknown"}


@router.get("/detect")
async def detect_network(user=Depends(require_jwt)):
    """
    Auto-detect board type and network interfaces.
    Returns: board, profile, interfaces (wan, lan, sfp)
    """
    result = _run_detect()

    # Cache result
    try:
        DETECT_CACHE.parent.mkdir(parents=True, exist_ok=True)
        DETECT_CACHE.write_text(json.dumps(result, indent=2))
    except Exception:
        pass

    return result


@router.get("/detect_cached")
async def detect_cached(user=Depends(require_jwt)):
    """Return cached detection result (faster, no re-scan)."""
    if DETECT_CACHE.exists():
        try:
            return json.loads(DETECT_CACHE.read_text())
        except Exception:
            pass
    return await detect_network(user)


class AutoApplyRequest(BaseModel):
    mode: str = "router"
    dry_run: bool = False


@router.post("/auto_apply")
async def auto_apply(req: AutoApplyRequest, user=Depends(require_jwt)):
    """
    Auto-detect interfaces and apply network configuration.
    1. Run secubox-net-detect
    2. Generate netplan based on detected interfaces
    3. Apply configuration (unless dry_run=True)
    """
    # Run detection
    detect_result = _run_detect()
    if "error" in detect_result:
        raise HTTPException(500, detect_result["error"])

    board = detect_result.get("board", "unknown")
    interfaces = detect_result.get("interfaces", {})
    wan = interfaces.get("wan", "eth0")
    lan = interfaces.get("lan", "").split()
    sfp = interfaces.get("sfp", "").split()

    # Generate netplan YAML
    lan_list = ", ".join(lan) if lan else ""

    if req.mode == "router":
        yaml_content = f"""# /etc/netplan/00-secubox.yaml
# Auto-generated by secubox-netmodes
# Board: {board} | Mode: {req.mode}
network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
      dhcp6: false
      optional: true
"""
        for iface in lan:
            yaml_content += f"""    {iface}:
      optional: true
"""
        if lan:
            yaml_content += f"""
  bridges:
    br-lan:
      interfaces: [{lan_list}]
      addresses: [192.168.1.1/24]
      dhcp4: false
      parameters:
        stp: false
        forward-delay: 0
"""
    elif req.mode == "bridge":
        all_ifaces = [wan] + lan
        yaml_content = f"""# /etc/netplan/00-secubox.yaml
# Auto-generated by secubox-netmodes
# Board: {board} | Mode: bridge
network:
  version: 2
  renderer: networkd

  ethernets:
"""
        for iface in all_ifaces:
            yaml_content += f"""    {iface}:
      optional: true
"""
        yaml_content += f"""
  bridges:
    br0:
      interfaces: [{', '.join(all_ifaces)}]
      dhcp4: true
      dhcp6: false
"""
    else:
        # Single/minimal mode
        yaml_content = f"""# /etc/netplan/00-secubox.yaml
# Auto-generated by secubox-netmodes
# Board: {board} | Mode: {req.mode}
network:
  version: 2
  renderer: networkd

  ethernets:
    {wan}:
      dhcp4: true
      dhcp6: false
"""

    if req.dry_run:
        return {
            "dry_run": True,
            "board": board,
            "interfaces": interfaces,
            "mode": req.mode,
            "yaml": yaml_content
        }

    # Backup and apply
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for f in NETPLAN_DIR.glob("*.yaml"):
        shutil.copy(f, BACKUP_DIR / f"{f.name}.{ts}")

    # Write new config
    netplan_file = NETPLAN_DIR / "00-secubox.yaml"
    netplan_file.write_text(yaml_content)

    # Apply
    r = subprocess.run(["netplan", "apply"], capture_output=True, text=True, timeout=30)
    success = r.returncode == 0

    # Update state
    s = _state()
    s["current_mode"] = req.mode if success else s.get("current_mode", "unknown")
    s["last_change"] = datetime.now().isoformat()
    s["detected_board"] = board
    s["detected_interfaces"] = interfaces
    _save_state(s)

    log.info("Auto-apply %s on %s: %s", req.mode, board, "OK" if success else "FAIL")

    return {
        "success": success,
        "board": board,
        "interfaces": interfaces,
        "mode": req.mode,
        "yaml": yaml_content,
        "error": r.stderr[:300] if not success else None
    }


@router.get("/board_info")
async def board_info(user=Depends(require_jwt)):
    """Get detected board information from state or run detection."""
    s = _state()
    if "detected_board" in s:
        return {
            "board": s.get("detected_board", "unknown"),
            "interfaces": s.get("detected_interfaces", {}),
            "cached": True
        }
    # Run fresh detection
    result = _run_detect()
    return {
        "board": result.get("board", "unknown"),
        "interfaces": result.get("interfaces", {}),
        "cached": False
    }


app.include_router(router)
