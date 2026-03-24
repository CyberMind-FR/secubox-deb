"""
secubox-qos — FastAPI application
Port de luci-app-bandwidth-manager

Méthodes RPCD portées :
  status, classes, rules, schedules, clients, usage, quotas, apply_qos

v1.1.0: Per-VLAN QoS support
  - Multi-interface support (eth0, eth0.100, eth0.200, etc.)
  - Per-VLAN bandwidth policies
  - 802.1p PCP priority mapping
  - VLAN-aware traffic classification
  - VLAN discovery and management
"""
from __future__ import annotations
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth   import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, json, re
from pathlib import Path
from typing import Optional

app = FastAPI(title="secubox-qos", version="1.1.0", root_path="/api/v1/qos")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log    = get_logger("qos")

QOS_CONF = Path("/etc/secubox/qos.json")

# 802.1p Priority Code Point (PCP) mapping
# Maps tc class priority to VLAN PCP values (0-7)
PCP_MAPPING = {
    "realtime":   7,  # Network Control
    "voice":      6,  # Voice (VoIP)
    "video":      5,  # Video
    "controlled": 4,  # Controlled Load
    "excellent":  3,  # Excellent Effort (Business Critical)
    "best_effort": 0, # Best Effort (Default)
    "background": 1,  # Background
    "bulk":       2,  # Spare/Bulk
}

# Default VLAN policies template
DEFAULT_VLAN_POLICY = {
    "enabled": True,
    "upload_mbps": 100,
    "download_mbps": 200,
    "priority": 0,  # PCP value
    "description": "",
    "classes": [],
}


def _load_conf() -> dict:
    if QOS_CONF.exists():
        conf = json.loads(QOS_CONF.read_text())
        # Migration: ensure new fields exist
        if "vlan_policies" not in conf:
            conf["vlan_policies"] = {}
        if "interfaces" not in conf:
            # Migrate single interface to list
            conf["interfaces"] = [conf.get("interface", "eth0")]
        return conf
    return {
        "enabled": False,
        "interface": "eth0",         # Primary interface (legacy)
        "interfaces": ["eth0"],      # All managed interfaces
        "upload_mbps": 100,
        "download_mbps": 200,
        "classes": [],
        "rules": [],
        "quotas": [],
        "vlan_policies": {},         # Per-VLAN policies: {"eth0.100": {...}, ...}
        "pcp_enabled": False,        # 802.1p marking enabled
        "pcp_mappings": {},          # Custom PCP mappings
    }


def _save_conf(conf: dict):
    QOS_CONF.parent.mkdir(parents=True, exist_ok=True)
    QOS_CONF.write_text(json.dumps(conf, indent=2))


def _discover_vlans() -> list[dict]:
    """Discover all VLAN interfaces on the system."""
    vlans = []
    r = subprocess.run(["ip", "-j", "link", "show", "type", "vlan"],
                       capture_output=True, text=True)
    try:
        links = json.loads(r.stdout) if r.stdout.strip() else []
        for link in links:
            ifname = link.get("ifname", "")
            # Parse VLAN ID from interface name or linkinfo
            vlan_id = None
            if "." in ifname:
                try:
                    vlan_id = int(ifname.split(".")[-1])
                except ValueError:
                    pass
            linkinfo = link.get("linkinfo", {}).get("info_data", {})
            if not vlan_id:
                vlan_id = linkinfo.get("id")

            parent = link.get("link", "")
            vlans.append({
                "interface": ifname,
                "vlan_id": vlan_id,
                "parent": parent,
                "state": link.get("operstate", "unknown"),
                "mtu": link.get("mtu", 1500),
            })
    except Exception:
        pass
    return vlans


def _get_parent_interface(vlan_iface: str) -> str:
    """Get parent interface for a VLAN interface."""
    if "." in vlan_iface:
        return vlan_iface.split(".")[0]
    return vlan_iface


def _is_vlan_interface(iface: str) -> bool:
    """Check if interface is a VLAN interface."""
    if "." in iface:
        return True
    # Check via ip link
    r = subprocess.run(["ip", "-d", "link", "show", iface],
                       capture_output=True, text=True)
    return "vlan" in r.stdout.lower()


def _get_vlan_id(iface: str) -> Optional[int]:
    """Extract VLAN ID from interface."""
    if "." in iface:
        try:
            return int(iface.split(".")[-1])
        except ValueError:
            pass
    return None


def _create_vlan_interface(parent: str, vlan_id: int) -> dict:
    """Create a VLAN interface."""
    iface = f"{parent}.{vlan_id}"
    r = subprocess.run(
        ["ip", "link", "add", "link", parent, "name", iface,
         "type", "vlan", "id", str(vlan_id)],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        return {"success": False, "error": r.stderr}

    # Bring interface up
    subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    return {"success": True, "interface": iface}


def _delete_vlan_interface(iface: str) -> dict:
    """Delete a VLAN interface."""
    r = subprocess.run(["ip", "link", "delete", iface],
                       capture_output=True, text=True)
    return {"success": r.returncode == 0, "error": r.stderr if r.returncode != 0 else None}


def _iface_stats(iface: str) -> dict:
    base = Path(f"/sys/class/net/{iface}/statistics")
    if not base.exists():
        return {"rx_bytes": 0, "tx_bytes": 0, "rx_packets": 0, "tx_packets": 0}
    return {
        k: int((base / k).read_text().strip())
        for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
    }


def _tc_show(iface: str) -> dict:
    r = subprocess.run(
        ["tc", "-j", "qdisc", "show", "dev", iface],
        capture_output=True, text=True, timeout=5
    )
    try:
        return {"qdiscs": json.loads(r.stdout)}
    except Exception:
        return {"qdiscs": [], "raw": r.stdout[:500]}


def _apply_htb(conf: dict, iface: str = None) -> dict:
    """
    Applique la configuration HTB via tc CLI.
    Supports per-interface and per-VLAN configuration.
    """
    if iface is None:
        iface = conf.get("interface", "eth0")

    # Check for VLAN-specific policy
    vlan_policy = conf.get("vlan_policies", {}).get(iface, {})
    if vlan_policy:
        up_kbps = int(vlan_policy.get("upload_mbps", 100)) * 1000
        down_kbps = int(vlan_policy.get("download_mbps", 200)) * 1000
        prio_offset = vlan_policy.get("priority", 0)
    else:
        up_kbps = int(conf.get("upload_mbps", 100)) * 1000
        down_kbps = int(conf.get("download_mbps", 200)) * 1000
        prio_offset = 0

    cmds = [
        # Reset
        ["tc", "qdisc", "del", "dev", iface, "root"],
        # Root HTB
        ["tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb",
         "default", "30"],
        # Classe root
        ["tc", "class", "add", "dev", iface, "parent", "1:", "classid", "1:1",
         "htb", "rate", f"{up_kbps}kbit", "burst", "15k"],
        # Classe haute priorité (voip, gaming)
        ["tc", "class", "add", "dev", iface, "parent", "1:1", "classid", "1:10",
         "htb", "rate", f"{up_kbps//4}kbit", "ceil", f"{up_kbps}kbit", "prio", "1"],
        # Classe standard
        ["tc", "class", "add", "dev", iface, "parent", "1:1", "classid", "1:30",
         "htb", "rate", f"{up_kbps//2}kbit", "ceil", f"{up_kbps}kbit", "prio", "2"],
        # Classe basse priorité (bulk)
        ["tc", "class", "add", "dev", iface, "parent", "1:1", "classid", "1:50",
         "htb", "rate", f"{up_kbps//8}kbit", "ceil", f"{up_kbps}kbit", "prio", "3"],
        # fq_codel sur chaque classe
        ["tc", "qdisc", "add", "dev", iface, "parent", "1:10", "handle", "10:", "fq_codel"],
        ["tc", "qdisc", "add", "dev", iface, "parent", "1:30", "handle", "30:", "fq_codel"],
        ["tc", "qdisc", "add", "dev", iface, "parent", "1:50", "handle", "50:", "fq_codel"],
    ]

    results = []
    for cmd in cmds:
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": " ".join(cmd[-4:]), "ok": r.returncode == 0})

    # Apply VLAN-specific filters if this is a VLAN interface
    vlan_id = _get_vlan_id(iface)
    if vlan_id and conf.get("pcp_enabled"):
        pcp_results = _apply_pcp_marking(iface, vlan_policy)
        results.extend(pcp_results)

    return {"steps": results, "interface": iface, "vlan_id": vlan_id}


def _apply_htb_all(conf: dict) -> dict:
    """Apply HTB to all configured interfaces."""
    results = {}
    interfaces = conf.get("interfaces", [conf.get("interface", "eth0")])

    for iface in interfaces:
        results[iface] = _apply_htb(conf, iface)

    return {"interfaces": results, "count": len(interfaces)}


def _apply_pcp_marking(iface: str, policy: dict) -> list:
    """Apply 802.1p PCP marking for VLAN interface."""
    results = []
    pcp = policy.get("priority", 0)

    # Use tc to set skb priority which maps to VLAN PCP
    # Class 1:10 (high) → PCP 6 (voice)
    # Class 1:30 (standard) → PCP 0 (best effort)
    # Class 1:50 (bulk) → PCP 1 (background)
    pcp_map = {
        "1:10": min(pcp + 6, 7),
        "1:30": pcp,
        "1:50": max(pcp - 1, 0) if pcp > 0 else 1,
    }

    for classid, pcp_val in pcp_map.items():
        # Set skb->priority via tc filter action
        cmd = [
            "tc", "filter", "add", "dev", iface, "parent", "1:",
            "protocol", "all", "prio", "1",
            "handle", classid.replace(":", ""),
            "fw", "flowid", classid,
            "action", "skbedit", "priority", str(pcp_val)
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        results.append({"cmd": f"pcp {classid}→{pcp_val}", "ok": r.returncode == 0})

    return results


def _apply_vlan_filter(parent_iface: str, vlan_id: int, class_id: str) -> dict:
    """Apply tc filter to classify traffic by VLAN ID."""
    # Use u32 filter to match VLAN ID in 802.1Q header
    # VLAN ID is in bytes 14-15 of ethernet frame (offset 12 from IP)
    cmd = [
        "tc", "filter", "add", "dev", parent_iface, "parent", "1:",
        "protocol", "802.1Q", "prio", "1",
        "u32", "match", "u16", f"0x{vlan_id:04x}", "0x0fff", "at", "-4",
        "flowid", class_id
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return {"cmd": f"vlan {vlan_id}→{class_id}", "ok": r.returncode == 0, "error": r.stderr}


# ── GET ───────────────────────────────────────────────────────────

@router.get("/status")
async def status(user=Depends(require_jwt)):
    conf  = _load_conf()
    iface = conf.get("interface", "eth0")
    stats = _iface_stats(iface)
    tc    = _tc_show(iface)
    qos_active = any(q.get("kind") == "htb" for q in tc.get("qdiscs", []))
    return {
        "enabled":       conf.get("enabled", False),
        "qos_active":    qos_active,
        "interface":     iface,
        "upload_mbps":   conf.get("upload_mbps", 0),
        "download_mbps": conf.get("download_mbps", 0),
        "stats":         stats,
    }


@router.get("/classes")
async def classes(user=Depends(require_jwt)):
    return _load_conf().get("classes", [])


@router.get("/rules")
async def rules(user=Depends(require_jwt)):
    return _load_conf().get("rules", [])


@router.get("/quotas")
async def quotas(user=Depends(require_jwt)):
    return _load_conf().get("quotas", [])


@router.get("/usage")
async def usage(user=Depends(require_jwt)):
    conf  = _load_conf()
    iface = conf.get("interface", "eth0")
    return {"interface": iface, **_iface_stats(iface)}


@router.get("/clients")
async def clients(user=Depends(require_jwt)):
    """Statistiques par client via nftables accounting (si configuré)."""
    r = subprocess.run(
        ["nft", "-j", "list", "table", "inet", "secubox_qos"],
        capture_output=True, text=True, timeout=5
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return []


@router.get("/schedules")
async def schedules(user=Depends(require_jwt)):
    return _load_conf().get("schedules", [])


# ── POST ──────────────────────────────────────────────────────────

class QosConfig(BaseModel):
    interface:      str   = "eth0"
    upload_mbps:    int   = 100
    download_mbps:  int   = 200
    enabled:        bool  = True


@router.post("/apply_qos")
async def apply_qos(req: QosConfig, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.update(req.dict())
    _save_conf(conf)

    if req.enabled:
        result = _apply_htb(conf)
        log.info("QoS appliqué: %sMbps↑ %sMbps↓ sur %s",
                 req.upload_mbps, req.download_mbps, req.interface)
    else:
        # Supprimer la config tc
        subprocess.run(["tc", "qdisc", "del", "dev", req.interface, "root"],
                       capture_output=True)
        result = {"removed": True}
        log.info("QoS désactivé sur %s", req.interface)

    return {"success": True, **result}


class QuotaRequest(BaseModel):
    mac:       str
    daily_mb:  int  = 0
    monthly_mb: int = 0


@router.post("/set_quota")
async def set_quota(req: QuotaRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    quotas = [q for q in conf.get("quotas", []) if q.get("mac") != req.mac]
    quotas.append(req.dict())
    conf["quotas"] = quotas
    _save_conf(conf)
    return {"success": True, "quota": req.dict()}


@router.get("/list_rules")
async def list_rules(user=Depends(require_jwt)):
    """Liste des règles QoS."""
    return _load_conf().get("rules", [])


class RuleRequest(BaseModel):
    name: str
    match_type: str = "ip"  # ip, mac, port, dscp, app
    match_value: str = ""
    class_id: str = "1:30"
    priority: int = 10
    enabled: bool = True


@router.post("/add_rule")
async def add_rule(req: RuleRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    rules = conf.get("rules", [])
    rules.append(req.model_dump())
    conf["rules"] = rules
    _save_conf(conf)
    log.info("Règle QoS ajoutée: %s", req.name)
    return {"success": True, "rule": req.model_dump()}


@router.post("/update_rule")
async def update_rule(name: str, req: RuleRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["rules"] = [r for r in conf.get("rules", []) if r.get("name") != name]
    conf["rules"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True, "rule": req.model_dump()}


@router.post("/delete_rule")
async def delete_rule(name: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["rules"] = [r for r in conf.get("rules", []) if r.get("name") != name]
    _save_conf(conf)
    return {"success": True, "deleted": name}


# ── Classes ────────────────────────────────────────────────────────

@router.get("/list_classes")
async def list_classes(user=Depends(require_jwt)):
    return _load_conf().get("classes", [])


class ClassRequest(BaseModel):
    classid: str
    name: str
    rate_kbps: int
    ceil_kbps: int = 0
    priority: int = 2
    parent: str = "1:1"


@router.post("/add_class")
async def add_class(req: ClassRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    classes = conf.get("classes", [])
    classes.append(req.model_dump())
    conf["classes"] = classes
    _save_conf(conf)
    return {"success": True, "class": req.model_dump()}


@router.post("/update_class")
async def update_class(classid: str, req: ClassRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["classes"] = [c for c in conf.get("classes", []) if c.get("classid") != classid]
    conf["classes"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_class")
async def delete_class(classid: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["classes"] = [c for c in conf.get("classes", []) if c.get("classid") != classid]
    _save_conf(conf)
    return {"success": True, "deleted": classid}


# ── Groups ─────────────────────────────────────────────────────────

@router.get("/groups")
async def groups(user=Depends(require_jwt)):
    return _load_conf().get("groups", [])


class GroupRequest(BaseModel):
    name: str
    members: list[str] = []
    class_id: str = "1:30"
    quota_daily_mb: int = 0


@router.post("/add_group")
async def add_group(req: GroupRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("groups", [])
    conf["groups"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True, "group": req.model_dump()}


@router.post("/update_group")
async def update_group(name: str, req: GroupRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["groups"] = [g for g in conf.get("groups", []) if g.get("name") != name]
    conf["groups"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_group")
async def delete_group(name: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["groups"] = [g for g in conf.get("groups", []) if g.get("name") != name]
    _save_conf(conf)
    return {"success": True}


@router.post("/add_to_group")
async def add_to_group(group: str, mac: str, user=Depends(require_jwt)):
    conf = _load_conf()
    for g in conf.get("groups", []):
        if g.get("name") == group:
            if mac not in g.get("members", []):
                g["members"].append(mac)
    _save_conf(conf)
    return {"success": True}


@router.post("/remove_from_group")
async def remove_from_group(group: str, mac: str, user=Depends(require_jwt)):
    conf = _load_conf()
    for g in conf.get("groups", []):
        if g.get("name") == group:
            g["members"] = [m for m in g.get("members", []) if m != mac]
    _save_conf(conf)
    return {"success": True}


# ── Profiles ───────────────────────────────────────────────────────

@router.get("/profiles")
async def profiles(user=Depends(require_jwt)):
    return _load_conf().get("profiles", [
        {"id": "gaming", "name": "Gaming", "priority": 1, "class": "1:10"},
        {"id": "streaming", "name": "Streaming", "priority": 2, "class": "1:20"},
        {"id": "standard", "name": "Standard", "priority": 3, "class": "1:30"},
        {"id": "bulk", "name": "Bulk/P2P", "priority": 4, "class": "1:50"},
    ])


class ProfileRequest(BaseModel):
    id: str
    name: str
    priority: int
    class_id: str
    apps: list[str] = []


@router.post("/add_profile")
async def add_profile(req: ProfileRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("profiles", [])
    conf["profiles"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_profile")
async def delete_profile(profile_id: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["profiles"] = [p for p in conf.get("profiles", []) if p.get("id") != profile_id]
    _save_conf(conf)
    return {"success": True}


@router.post("/assign_profile")
async def assign_profile(mac: str, profile_id: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("client_profiles", {})
    conf["client_profiles"][mac] = profile_id
    _save_conf(conf)
    return {"success": True}


# ── Schedules ──────────────────────────────────────────────────────

@router.get("/list_schedules")
async def list_schedules(user=Depends(require_jwt)):
    return _load_conf().get("schedules", [])


class ScheduleRequest(BaseModel):
    name: str
    days: list[str] = ["mon", "tue", "wed", "thu", "fri"]
    start_time: str = "08:00"
    end_time: str = "18:00"
    action: str = "apply_profile"
    profile_id: str = ""
    enabled: bool = True


@router.post("/add_schedule")
async def add_schedule(req: ScheduleRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("schedules", [])
    conf["schedules"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/update_schedule")
async def update_schedule(name: str, req: ScheduleRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["schedules"] = [s for s in conf.get("schedules", []) if s.get("name") != name]
    conf["schedules"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_schedule")
async def delete_schedule(name: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["schedules"] = [s for s in conf.get("schedules", []) if s.get("name") != name]
    _save_conf(conf)
    return {"success": True}


# ── Parental ───────────────────────────────────────────────────────

@router.get("/parental")
async def parental(user=Depends(require_jwt)):
    return _load_conf().get("parental", [])


class ParentalRequest(BaseModel):
    mac: str
    block_schedule: dict = {}
    blocked_categories: list[str] = []
    daily_limit_hours: float = 0


@router.post("/set_parental")
async def set_parental(req: ParentalRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("parental", [])
    conf["parental"] = [p for p in conf["parental"] if p.get("mac") != req.mac]
    conf["parental"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_parental")
async def delete_parental(mac: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["parental"] = [p for p in conf.get("parental", []) if p.get("mac") != mac]
    _save_conf(conf)
    return {"success": True}


# ── Analytics / Realtime ───────────────────────────────────────────

@router.get("/realtime")
async def realtime(user=Depends(require_jwt)):
    """Bande passante en temps réel."""
    conf = _load_conf()
    iface = conf.get("interface", "eth0")
    stats1 = _iface_stats(iface)
    import time
    time.sleep(0.5)
    stats2 = _iface_stats(iface)
    return {
        "rx_bps": (stats2["rx_bytes"] - stats1["rx_bytes"]) * 2,
        "tx_bps": (stats2["tx_bytes"] - stats1["tx_bytes"]) * 2,
        "rx_pps": (stats2["rx_packets"] - stats1["rx_packets"]) * 2,
        "tx_pps": (stats2["tx_packets"] - stats1["tx_packets"]) * 2,
        "interface": iface,
    }


@router.get("/bandwidth_history")
async def bandwidth_history(hours: int = 24, user=Depends(require_jwt)):
    """Historique de bande passante (via vnstat si disponible)."""
    r = subprocess.run(
        ["vnstat", "--json", "-h", str(hours)],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"hours": [], "error": "vnstat not available"}


@router.get("/top_talkers")
async def top_talkers(user=Depends(require_jwt)):
    """Top consommateurs de bande passante (via nftables accounting)."""
    r = subprocess.run(
        ["nft", "-j", "list", "set", "inet", "secubox_qos", "client_bytes"],
        capture_output=True, text=True
    )
    try:
        data = json.loads(r.stdout)
        return data
    except Exception:
        return []


@router.get("/per_client_usage")
async def per_client_usage(user=Depends(require_jwt)):
    """Usage par client."""
    return _load_conf().get("client_usage", {})


@router.get("/alerts")
async def alerts(user=Depends(require_jwt)):
    """Alertes QoS (quotas dépassés, etc.)."""
    conf = _load_conf()
    alerts_list = []
    for q in conf.get("quotas", []):
        usage = conf.get("client_usage", {}).get(q.get("mac"), {})
        if q.get("daily_mb") and usage.get("today_mb", 0) > q.get("daily_mb"):
            alerts_list.append({
                "type": "quota_exceeded",
                "mac": q.get("mac"),
                "limit_mb": q.get("daily_mb"),
                "used_mb": usage.get("today_mb"),
            })
    return alerts_list


@router.get("/quota_status")
async def quota_status(mac: str, user=Depends(require_jwt)):
    """Statut quota d'un client."""
    conf = _load_conf()
    quota = next((q for q in conf.get("quotas", []) if q.get("mac") == mac), None)
    usage = conf.get("client_usage", {}).get(mac, {})
    return {"quota": quota, "usage": usage}


@router.post("/reset_quota")
async def reset_quota(mac: str, user=Depends(require_jwt)):
    """Réinitialiser le quota d'un client."""
    conf = _load_conf()
    conf.setdefault("client_usage", {})
    if mac in conf["client_usage"]:
        conf["client_usage"][mac] = {"today_mb": 0, "month_mb": 0}
    _save_conf(conf)
    return {"success": True}


# ── DPI Integration ────────────────────────────────────────────────

@router.get("/dpi_apps")
async def dpi_apps(user=Depends(require_jwt)):
    """Applications détectées par DPI."""
    r = subprocess.run(
        ["curl", "-s", "--unix-socket", "/run/secubox/dpi.sock",
         "http://localhost/api/v1/dpi/apps"],
        capture_output=True, text=True
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return []


@router.get("/dpi_rules")
async def dpi_rules(user=Depends(require_jwt)):
    """Règles QoS basées sur DPI."""
    return _load_conf().get("dpi_rules", [])


class DpiRuleRequest(BaseModel):
    app_id: str
    class_id: str = "1:30"
    action: str = "mark"  # mark, drop, limit
    limit_kbps: int = 0


@router.post("/add_dpi_rule")
async def add_dpi_rule(req: DpiRuleRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.setdefault("dpi_rules", [])
    conf["dpi_rules"].append(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.post("/delete_dpi_rule")
async def delete_dpi_rule(app_id: str, user=Depends(require_jwt)):
    conf = _load_conf()
    conf["dpi_rules"] = [r for r in conf.get("dpi_rules", []) if r.get("app_id") != app_id]
    _save_conf(conf)
    return {"success": True}


# ── Advanced ───────────────────────────────────────────────────────

@router.get("/tc_raw")
async def tc_raw(user=Depends(require_jwt)):
    """Configuration tc brute."""
    conf = _load_conf()
    iface = conf.get("interface", "eth0")
    qdisc = subprocess.run(["tc", "qdisc", "show", "dev", iface],
                           capture_output=True, text=True)
    classes = subprocess.run(["tc", "class", "show", "dev", iface],
                             capture_output=True, text=True)
    filters = subprocess.run(["tc", "filter", "show", "dev", iface],
                             capture_output=True, text=True)
    return {
        "qdisc": qdisc.stdout,
        "classes": classes.stdout,
        "filters": filters.stdout,
    }


@router.post("/tc_command")
async def tc_command(command: str, user=Depends(require_jwt)):
    """Exécuter une commande tc (admin only)."""
    if not command.startswith("tc "):
        return {"error": "Must start with 'tc '"}
    r = subprocess.run(command.split(), capture_output=True, text=True, timeout=10)
    return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}


@router.get("/interface_list")
async def interface_list(user=Depends(require_jwt)):
    """Liste des interfaces réseau."""
    r = subprocess.run(["ip", "-j", "link", "show"], capture_output=True, text=True)
    try:
        links = json.loads(r.stdout)
        return [l.get("ifname") for l in links if l.get("ifname") != "lo"]
    except Exception:
        return []


class SettingsRequest(BaseModel):
    interface: str = "eth0"
    upload_mbps: int = 100
    download_mbps: int = 200
    enabled: bool = True
    fq_codel: bool = True


@router.post("/save_settings")
async def save_settings(req: SettingsRequest, user=Depends(require_jwt)):
    conf = _load_conf()
    conf.update(req.model_dump())
    _save_conf(conf)
    return {"success": True}


@router.get("/get_settings")
async def get_settings(user=Depends(require_jwt)):
    return _load_conf()


@router.post("/reset_config")
async def reset_config(user=Depends(require_jwt)):
    """Réinitialiser la configuration QoS."""
    conf = {
        "enabled": False,
        "interface": "eth0",
        "upload_mbps": 100,
        "download_mbps": 200,
        "classes": [],
        "rules": [],
        "quotas": [],
    }
    _save_conf(conf)
    return {"success": True}


@router.get("/export_config")
async def export_config(user=Depends(require_jwt)):
    """Exporter la configuration."""
    return _load_conf()


class ImportRequest(BaseModel):
    config: dict


@router.post("/import_config")
async def import_config(req: ImportRequest, user=Depends(require_jwt)):
    _save_conf(req.config)
    return {"success": True}


@router.get("/logs")
async def logs(lines: int = 100, user=Depends(require_jwt)):
    """Logs QoS."""
    r = subprocess.run(
        ["journalctl", "-u", "secubox-qos", "-n", str(lines), "--no-pager"],
        capture_output=True, text=True, timeout=10
    )
    return {"lines": r.stdout.splitlines()}


@router.post("/reload")
async def reload(user=Depends(require_jwt)):
    """Recharger la configuration et réappliquer tc."""
    conf = _load_conf()
    if conf.get("enabled"):
        result = _apply_htb(conf)
        return {"success": True, **result}
    return {"success": True, "message": "QoS disabled"}


# ══════════════════════════════════════════════════════════════════
# ══ VLAN QoS Management ═══════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════

@router.get("/vlans")
async def list_vlans(user=Depends(require_jwt)):
    """List all VLAN interfaces with their QoS policies."""
    vlans = _discover_vlans()
    conf = _load_conf()
    policies = conf.get("vlan_policies", {})

    for vlan in vlans:
        iface = vlan["interface"]
        vlan["policy"] = policies.get(iface, None)
        vlan["qos_enabled"] = iface in conf.get("interfaces", [])

    return {"vlans": vlans, "count": len(vlans)}


@router.get("/vlan/{interface}")
async def get_vlan_policy(interface: str, user=Depends(require_jwt)):
    """Get QoS policy for a specific VLAN interface."""
    conf = _load_conf()
    policy = conf.get("vlan_policies", {}).get(interface, None)
    stats = _iface_stats(interface)
    tc = _tc_show(interface)
    vlan_id = _get_vlan_id(interface)

    return {
        "interface": interface,
        "vlan_id": vlan_id,
        "policy": policy,
        "stats": stats,
        "tc": tc,
        "qos_active": any(q.get("kind") == "htb" for q in tc.get("qdiscs", [])),
    }


class VlanPolicyRequest(BaseModel):
    upload_mbps: int = 100
    download_mbps: int = 200
    priority: int = 0  # 802.1p PCP base value (0-7)
    description: str = ""
    enabled: bool = True
    classes: list[dict] = []


@router.post("/vlan/{interface}/policy")
async def set_vlan_policy(interface: str, req: VlanPolicyRequest, user=Depends(require_jwt)):
    """Set QoS policy for a VLAN interface."""
    conf = _load_conf()

    # Validate interface exists
    if not Path(f"/sys/class/net/{interface}").exists():
        raise HTTPException(status_code=404, detail=f"Interface {interface} not found")

    # Validate PCP value
    if not 0 <= req.priority <= 7:
        raise HTTPException(status_code=400, detail="Priority must be 0-7 (802.1p PCP)")

    # Store policy
    conf.setdefault("vlan_policies", {})
    conf["vlan_policies"][interface] = req.model_dump()

    # Add to managed interfaces if enabled
    if req.enabled and interface not in conf.get("interfaces", []):
        conf.setdefault("interfaces", [])
        conf["interfaces"].append(interface)
    elif not req.enabled and interface in conf.get("interfaces", []):
        conf["interfaces"].remove(interface)

    _save_conf(conf)

    # Apply if QoS is globally enabled
    result = {}
    if conf.get("enabled") and req.enabled:
        result = _apply_htb(conf, interface)
        log.info("VLAN QoS applied: %s - %sMbps↑ %sMbps↓ PCP=%d",
                 interface, req.upload_mbps, req.download_mbps, req.priority)

    return {"success": True, "interface": interface, **result}


@router.delete("/vlan/{interface}/policy")
async def delete_vlan_policy(interface: str, user=Depends(require_jwt)):
    """Remove QoS policy from a VLAN interface."""
    conf = _load_conf()

    # Remove policy
    if interface in conf.get("vlan_policies", {}):
        del conf["vlan_policies"][interface]

    # Remove from managed interfaces
    if interface in conf.get("interfaces", []):
        conf["interfaces"].remove(interface)

    _save_conf(conf)

    # Clear tc rules
    subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                   capture_output=True)

    log.info("VLAN QoS policy removed: %s", interface)
    return {"success": True, "interface": interface}


class CreateVlanRequest(BaseModel):
    parent: str = "eth0"
    vlan_id: int
    upload_mbps: int = 100
    download_mbps: int = 200
    priority: int = 0
    description: str = ""


@router.post("/vlan/create")
async def create_vlan(req: CreateVlanRequest, user=Depends(require_jwt)):
    """Create a new VLAN interface with QoS policy."""
    # Validate VLAN ID
    if not 1 <= req.vlan_id <= 4094:
        raise HTTPException(status_code=400, detail="VLAN ID must be 1-4094")

    # Validate parent interface exists
    if not Path(f"/sys/class/net/{req.parent}").exists():
        raise HTTPException(status_code=404, detail=f"Parent interface {req.parent} not found")

    # Create VLAN interface
    result = _create_vlan_interface(req.parent, req.vlan_id)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to create VLAN"))

    interface = result["interface"]

    # Set QoS policy
    conf = _load_conf()
    conf.setdefault("vlan_policies", {})
    conf["vlan_policies"][interface] = {
        "enabled": True,
        "upload_mbps": req.upload_mbps,
        "download_mbps": req.download_mbps,
        "priority": req.priority,
        "description": req.description,
        "classes": [],
    }

    conf.setdefault("interfaces", [])
    if interface not in conf["interfaces"]:
        conf["interfaces"].append(interface)

    _save_conf(conf)

    log.info("VLAN created: %s (ID: %d) on %s", interface, req.vlan_id, req.parent)
    return {"success": True, "interface": interface, "vlan_id": req.vlan_id}


@router.delete("/vlan/{interface}")
async def delete_vlan(interface: str, user=Depends(require_jwt)):
    """Delete a VLAN interface and its QoS policy."""
    if not _is_vlan_interface(interface):
        raise HTTPException(status_code=400, detail="Not a VLAN interface")

    # Remove QoS first
    conf = _load_conf()
    if interface in conf.get("vlan_policies", {}):
        del conf["vlan_policies"][interface]
    if interface in conf.get("interfaces", []):
        conf["interfaces"].remove(interface)
    _save_conf(conf)

    # Delete interface
    result = _delete_vlan_interface(interface)
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Failed to delete VLAN"))

    log.info("VLAN deleted: %s", interface)
    return {"success": True, "interface": interface}


@router.get("/vlan/policies")
async def list_vlan_policies(user=Depends(require_jwt)):
    """List all VLAN QoS policies."""
    conf = _load_conf()
    policies = conf.get("vlan_policies", {})
    return {
        "policies": [
            {"interface": iface, **policy}
            for iface, policy in policies.items()
        ],
        "count": len(policies),
    }


@router.post("/vlan/apply_all")
async def apply_all_vlan_qos(user=Depends(require_jwt)):
    """Apply QoS to all configured VLAN interfaces."""
    conf = _load_conf()
    if not conf.get("enabled"):
        return {"success": False, "error": "QoS is globally disabled"}

    result = _apply_htb_all(conf)
    log.info("QoS applied to %d interfaces", result["count"])
    return {"success": True, **result}


# ── 802.1p PCP Management ─────────────────────────────────────────

@router.get("/pcp/mappings")
async def get_pcp_mappings(user=Depends(require_jwt)):
    """Get 802.1p PCP priority mappings."""
    conf = _load_conf()
    return {
        "default_mappings": PCP_MAPPING,
        "custom_mappings": conf.get("pcp_mappings", {}),
        "pcp_enabled": conf.get("pcp_enabled", False),
    }


class PcpMappingRequest(BaseModel):
    class_id: str  # e.g., "1:10"
    pcp_value: int  # 0-7


@router.post("/pcp/mapping")
async def set_pcp_mapping(req: PcpMappingRequest, user=Depends(require_jwt)):
    """Set custom PCP mapping for a traffic class."""
    if not 0 <= req.pcp_value <= 7:
        raise HTTPException(status_code=400, detail="PCP value must be 0-7")

    conf = _load_conf()
    conf.setdefault("pcp_mappings", {})
    conf["pcp_mappings"][req.class_id] = req.pcp_value
    _save_conf(conf)
    return {"success": True, "mapping": {req.class_id: req.pcp_value}}


@router.post("/pcp/enable")
async def enable_pcp(enabled: bool = True, user=Depends(require_jwt)):
    """Enable or disable 802.1p PCP marking."""
    conf = _load_conf()
    conf["pcp_enabled"] = enabled
    _save_conf(conf)
    log.info("802.1p PCP marking %s", "enabled" if enabled else "disabled")
    return {"success": True, "pcp_enabled": enabled}


# ── Per-Interface Management ──────────────────────────────────────

@router.get("/interfaces")
async def list_managed_interfaces(user=Depends(require_jwt)):
    """List all managed interfaces with their QoS status."""
    conf = _load_conf()
    managed = conf.get("interfaces", [])
    vlan_policies = conf.get("vlan_policies", {})

    interfaces = []
    for iface in managed:
        stats = _iface_stats(iface)
        tc = _tc_show(iface)
        policy = vlan_policies.get(iface, {
            "upload_mbps": conf.get("upload_mbps", 100),
            "download_mbps": conf.get("download_mbps", 200),
        })

        interfaces.append({
            "interface": iface,
            "is_vlan": _is_vlan_interface(iface),
            "vlan_id": _get_vlan_id(iface),
            "policy": policy,
            "stats": stats,
            "qos_active": any(q.get("kind") == "htb" for q in tc.get("qdiscs", [])),
        })

    return {"interfaces": interfaces, "count": len(interfaces)}


class AddInterfaceRequest(BaseModel):
    interface: str
    upload_mbps: int = 100
    download_mbps: int = 200
    priority: int = 0
    apply_now: bool = True


@router.post("/interface/add")
async def add_managed_interface(req: AddInterfaceRequest, user=Depends(require_jwt)):
    """Add an interface to QoS management."""
    if not Path(f"/sys/class/net/{req.interface}").exists():
        raise HTTPException(status_code=404, detail=f"Interface {req.interface} not found")

    conf = _load_conf()
    conf.setdefault("interfaces", [])

    if req.interface not in conf["interfaces"]:
        conf["interfaces"].append(req.interface)

    # If it's a VLAN, store policy
    if _is_vlan_interface(req.interface):
        conf.setdefault("vlan_policies", {})
        conf["vlan_policies"][req.interface] = {
            "enabled": True,
            "upload_mbps": req.upload_mbps,
            "download_mbps": req.download_mbps,
            "priority": req.priority,
            "description": "",
            "classes": [],
        }

    _save_conf(conf)

    result = {}
    if req.apply_now and conf.get("enabled"):
        result = _apply_htb(conf, req.interface)

    log.info("Interface added to QoS: %s", req.interface)
    return {"success": True, "interface": req.interface, **result}


@router.delete("/interface/{interface}")
async def remove_managed_interface(interface: str, user=Depends(require_jwt)):
    """Remove an interface from QoS management."""
    conf = _load_conf()

    if interface in conf.get("interfaces", []):
        conf["interfaces"].remove(interface)

    if interface in conf.get("vlan_policies", {}):
        del conf["vlan_policies"][interface]

    _save_conf(conf)

    # Clear tc rules
    subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                   capture_output=True)

    log.info("Interface removed from QoS: %s", interface)
    return {"success": True, "interface": interface}


@router.get("/interface/{interface}/stats")
async def get_interface_stats(interface: str, user=Depends(require_jwt)):
    """Get detailed stats for a specific interface."""
    if not Path(f"/sys/class/net/{interface}").exists():
        raise HTTPException(status_code=404, detail=f"Interface {interface} not found")

    stats = _iface_stats(interface)
    tc = _tc_show(interface)
    conf = _load_conf()
    policy = conf.get("vlan_policies", {}).get(interface, {})

    # Get tc class stats
    r = subprocess.run(["tc", "-s", "-j", "class", "show", "dev", interface],
                       capture_output=True, text=True)
    try:
        class_stats = json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        class_stats = []

    return {
        "interface": interface,
        "is_vlan": _is_vlan_interface(interface),
        "vlan_id": _get_vlan_id(interface),
        "policy": policy,
        "stats": stats,
        "tc": tc,
        "class_stats": class_stats,
    }


# ── VLAN-aware Rules ──────────────────────────────────────────────

class VlanRuleRequest(BaseModel):
    name: str
    vlan_id: int
    class_id: str = "1:30"
    priority: int = 10
    enabled: bool = True


@router.post("/vlan/rule")
async def add_vlan_rule(req: VlanRuleRequest, user=Depends(require_jwt)):
    """Add a VLAN-based classification rule."""
    conf = _load_conf()
    conf.setdefault("vlan_rules", [])
    conf["vlan_rules"].append(req.model_dump())
    _save_conf(conf)

    # Apply filter on parent interface
    # Find interfaces that might carry this VLAN
    result = None
    for iface in conf.get("interfaces", []):
        parent = _get_parent_interface(iface)
        if parent != iface:  # This is a VLAN interface
            continue
        # Apply to parent interfaces
        result = _apply_vlan_filter(iface, req.vlan_id, req.class_id)

    log.info("VLAN rule added: VLAN %d → %s", req.vlan_id, req.class_id)
    return {"success": True, "rule": req.model_dump(), "filter_result": result}


@router.get("/vlan/rules")
async def list_vlan_rules(user=Depends(require_jwt)):
    """List all VLAN classification rules."""
    conf = _load_conf()
    return {"rules": conf.get("vlan_rules", [])}


@router.delete("/vlan/rule/{name}")
async def delete_vlan_rule(name: str, user=Depends(require_jwt)):
    """Delete a VLAN classification rule."""
    conf = _load_conf()
    conf["vlan_rules"] = [r for r in conf.get("vlan_rules", []) if r.get("name") != name]
    _save_conf(conf)
    return {"success": True, "deleted": name}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "qos", "version": "1.1.0"}


app.include_router(router)
