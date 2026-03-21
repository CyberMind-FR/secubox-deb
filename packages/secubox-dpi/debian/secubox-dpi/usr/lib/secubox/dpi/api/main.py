"""secubox-dpi — netifyd socket + tc mirred DPI dual-stream"""
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, json, socket
from pathlib import Path

app = FastAPI(title="secubox-dpi", version="1.0.0", root_path="/api/v1/dpi")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("dpi")

NETIFYD_SOCK = Path("/run/netifyd/netifyd.sock")

def _netifyd_query(cmd: dict) -> dict:
    """Envoi JSON command sur socket netifyd."""
    if not NETIFYD_SOCK.exists():
        return {"error": "netifyd socket unavailable"}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(NETIFYD_SOCK))
            s.sendall((json.dumps(cmd) + "\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                data += chunk
                if data.endswith(b"\n"): break
        return json.loads(data.decode())
    except Exception as e:
        log.warning("netifyd query error: %s", e)
        return {"error": str(e)}

def _setup_mirred(iface: str, mirror_if: str = "ifb0") -> dict:
    """Configure tc mirred + ifb0 pour DPI dual-stream."""
    cmds = [
        ["ip", "link", "add", mirror_if, "type", "ifb"],
        ["ip", "link", "set", mirror_if, "up"],
        ["tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress"],
        ["tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect",
         "dev", mirror_if],
        ["tc", "qdisc", "add", "dev", iface, "handle", "1:", "prio"],
        ["tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "all",
         "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "mirror",
         "dev", mirror_if],
    ]
    results = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd[-3:]), "ok": r.returncode == 0,
                        "err": r.stderr.strip()[:100] if r.returncode != 0 else ""})
    return {"steps": results, "interface": iface, "mirror": mirror_if}

@router.get("/status")
async def status(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    netifyd_up = subprocess.run(["pgrep", "netifyd"], capture_output=True).returncode == 0
    iface = cfg.get("interface", "eth0")
    mirred_active = subprocess.run(
        ["tc", "filter", "show", "dev", iface, "parent", "ffff:"],
        capture_output=True, text=True
    ).stdout.strip() != ""
    return {"running": netifyd_up, "mode": cfg.get("mode","inline"),
            "engine": cfg.get("engine","netifyd"),
            "interface": iface, "mirred_active": mirred_active}

@router.get("/flows")
async def flows(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_flows"})

@router.get("/applications")
async def applications(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_applications"})

@router.get("/devices")
async def devices(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_devices"})

@router.get("/risks")
async def risks(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_risks"})

@router.get("/talkers")
async def talkers(user=Depends(require_jwt)):
    return _netifyd_query({"type":"get_top_talkers"})

@router.post("/setup_mirred")
async def setup_mirred(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return _setup_mirred(cfg.get("interface","eth0"), cfg.get("mirror_if","ifb0"))


@router.get("/apps")
async def apps(user=Depends(require_jwt)):
    """Liste des applications détectées."""
    return _netifyd_query({"type": "get_applications"})


@router.get("/protocols")
async def protocols(user=Depends(require_jwt)):
    """Protocoles détectés."""
    return _netifyd_query({"type": "get_protocols"})


@router.get("/categories")
async def categories(user=Depends(require_jwt)):
    """Catégories d'applications."""
    return [
        {"id": "streaming", "name": "Streaming", "apps": ["netflix", "youtube", "twitch"]},
        {"id": "social", "name": "Réseaux sociaux", "apps": ["facebook", "instagram", "tiktok"]},
        {"id": "gaming", "name": "Jeux", "apps": ["steam", "xbox", "playstation"]},
        {"id": "productivity", "name": "Productivité", "apps": ["office365", "google_drive", "zoom"]},
        {"id": "p2p", "name": "P2P/Torrent", "apps": ["bittorrent", "emule"]},
    ]


@router.get("/top_apps")
async def top_apps(limit: int = 10, user=Depends(require_jwt)):
    """Top applications par trafic."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    # Aggregate by app
    app_traffic = {}
    for f in flows.get("flows", []):
        app = f.get("detected_application_name", "unknown")
        app_traffic[app] = app_traffic.get(app, 0) + f.get("bytes", 0)
    sorted_apps = sorted(app_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"app": a, "bytes": b} for a, b in sorted_apps]


@router.get("/top_protocols")
async def top_protocols(limit: int = 10, user=Depends(require_jwt)):
    """Top protocoles par trafic."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    proto_traffic = {}
    for f in flows.get("flows", []):
        proto = f.get("detected_protocol_name", "unknown")
        proto_traffic[proto] = proto_traffic.get(proto, 0) + f.get("bytes", 0)
    sorted_protos = sorted(proto_traffic.items(), key=lambda x: -x[1])[:limit]
    return [{"protocol": p, "bytes": b} for p, b in sorted_protos]


@router.get("/bandwidth_by_app")
async def bandwidth_by_app(user=Depends(require_jwt)):
    """Bande passante par application."""
    return await top_apps(20, user)


@router.get("/bandwidth_by_device")
async def bandwidth_by_device(user=Depends(require_jwt)):
    """Bande passante par appareil."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    device_traffic = {}
    for f in flows.get("flows", []):
        mac = f.get("local_mac", "unknown")
        device_traffic[mac] = device_traffic.get(mac, 0) + f.get("bytes", 0)
    sorted_devs = sorted(device_traffic.items(), key=lambda x: -x[1])[:20]
    return [{"mac": d, "bytes": b} for d, b in sorted_devs]


@router.get("/active_flows")
async def active_flows(user=Depends(require_jwt)):
    """Flux actifs."""
    return _netifyd_query({"type": "get_flows"})


@router.get("/flow_details")
async def flow_details(flow_id: str, user=Depends(require_jwt)):
    """Détails d'un flux."""
    return _netifyd_query({"type": "get_flow", "flow_id": flow_id})


@router.get("/device_flows")
async def device_flows(mac: str, user=Depends(require_jwt)):
    """Flux d'un appareil."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("local_mac") == mac]


@router.get("/realtime")
async def realtime(user=Depends(require_jwt)):
    """Statistiques temps réel."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    stats_path = Path(f"/sys/class/net/{iface}/statistics")
    if not stats_path.exists():
        return {"error": "Interface not found"}
    return {
        "rx_bytes": int((stats_path / "rx_bytes").read_text().strip()),
        "tx_bytes": int((stats_path / "tx_bytes").read_text().strip()),
        "rx_packets": int((stats_path / "rx_packets").read_text().strip()),
        "tx_packets": int((stats_path / "tx_packets").read_text().strip()),
    }


@router.get("/stats")
async def stats(user=Depends(require_jwt)):
    """Statistiques DPI."""
    return _netifyd_query({"type": "get_stats"})


from pydantic import BaseModel


class BlockRuleRequest(BaseModel):
    app_or_category: str
    action: str = "block"  # block, limit, mark
    limit_kbps: int = 0


@router.get("/block_rules")
async def block_rules(user=Depends(require_jwt)):
    """Règles de blocage."""
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        return json.loads(rules_file.read_text())
    return []


@router.post("/add_block_rule")
async def add_block_rule(req: BlockRuleRequest, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    rules = json.loads(rules_file.read_text()) if rules_file.exists() else []
    rules.append(req.model_dump())
    rules_file.write_text(json.dumps(rules, indent=2))
    log.info("DPI rule added: %s", req.app_or_category)
    return {"success": True}


@router.post("/delete_block_rule")
async def delete_block_rule(app_or_category: str, user=Depends(require_jwt)):
    rules_file = Path("/etc/secubox/dpi-rules.json")
    if rules_file.exists():
        rules = json.loads(rules_file.read_text())
        rules = [r for r in rules if r.get("app_or_category") != app_or_category]
        rules_file.write_text(json.dumps(rules, indent=2))
    return {"success": True}


@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    """Alertes DPI."""
    return _netifyd_query({"type": "get_alerts"})


@router.get("/dns_queries")
async def dns_queries(limit: int = 100, user=Depends(require_jwt)):
    """Requêtes DNS interceptées."""
    return _netifyd_query({"type": "get_dns_queries", "limit": limit})


@router.get("/ssl_flows")
async def ssl_flows(user=Depends(require_jwt)):
    """Flux SSL/TLS."""
    flows = _netifyd_query({"type": "get_flows"})
    if "error" in flows:
        return []
    return [f for f in flows.get("flows", []) if f.get("ssl", {}).get("enabled")]


@router.get("/ssl_fingerprints")
async def ssl_fingerprints(user=Depends(require_jwt)):
    """Empreintes JA3/JA3S."""
    return _netifyd_query({"type": "get_ssl_fingerprints"})


class DpiSettingsRequest(BaseModel):
    interface: str = "eth0"
    mirror_if: str = "ifb0"
    mode: str = "inline"  # inline, passive, mirror
    enabled: bool = True


@router.get("/settings")
async def settings(user=Depends(require_jwt)):
    cfg = get_config("dpi")
    return {
        "interface": cfg.get("interface", "eth0"),
        "mirror_if": cfg.get("mirror_if", "ifb0"),
        "mode": cfg.get("mode", "inline"),
        "enabled": cfg.get("enabled", True),
    }


@router.post("/save_settings")
async def save_settings(req: DpiSettingsRequest, user=Depends(require_jwt)):
    settings_file = Path("/etc/secubox/dpi.json")
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    settings_file.write_text(json.dumps(req.model_dump(), indent=2))
    log.info("DPI settings saved")
    return {"success": True}


@router.post("/restart")
async def restart(user=Depends(require_jwt)):
    """Redémarrer netifyd."""
    r = subprocess.run(["systemctl", "restart", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/start")
async def start(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "start", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.post("/stop")
async def stop(user=Depends(require_jwt)):
    r = subprocess.run(["systemctl", "stop", "netifyd"], capture_output=True, text=True)
    return {"success": r.returncode == 0}


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    r = subprocess.run(
        ["journalctl", "-u", "netifyd", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.get("/interface_list")
async def interface_list(user=Depends(require_jwt)):
    """Liste des interfaces."""
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        return [l.get("ifname") for l in links if l.get("ifname") != "lo"]
    except Exception:
        return []


@router.get("/tc_status")
async def tc_status(user=Depends(require_jwt)):
    """État tc mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    qdisc = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                           capture_output=True, text=True)
    filters = subprocess.run(["tc", "filter", "show", "dev", iface, "parent", "ffff:"],
                             capture_output=True, text=True)
    return {
        "qdisc": qdisc.stdout,
        "filters": filters.stdout,
        "active": "mirred" in filters.stdout,
    }


@router.post("/remove_mirred")
async def remove_mirred(user=Depends(require_jwt)):
    """Supprimer la configuration mirred."""
    cfg = get_config("dpi")
    iface = cfg.get("interface", "eth0")
    mirror_if = cfg.get("mirror_if", "ifb0")
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "ingress"], capture_output=True)
    subprocess.run(["tc", "qdisc", "del", "dev", iface, "root"], capture_output=True)
    subprocess.run(["ip", "link", "del", mirror_if], capture_output=True)
    return {"success": True}


@router.get("/export_flows")
async def export_flows(format: str = "json", user=Depends(require_jwt)):
    """Exporter les flux."""
    flows = _netifyd_query({"type": "get_flows"})
    if format == "csv":
        lines = ["timestamp,src_ip,dst_ip,app,protocol,bytes"]
        for f in flows.get("flows", []):
            lines.append(f"{f.get('timestamp')},{f.get('local_ip')},{f.get('other_ip')},"
                        f"{f.get('detected_application_name')},{f.get('detected_protocol_name')},"
                        f"{f.get('bytes')}")
        return {"format": "csv", "data": "\n".join(lines)}
    return flows


@router.get("/health")
async def health():
    return {"status": "ok", "module": "dpi"}


app.include_router(router)
