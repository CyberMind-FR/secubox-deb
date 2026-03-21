"""
secubox-qos — FastAPI application
Port de luci-app-bandwidth-manager

Méthodes RPCD portées :
  status, classes, rules, schedules, clients, usage, quotas, apply_qos
"""
from __future__ import annotations
from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth   import router as auth_router, require_jwt
from secubox_core.config import get_config
from secubox_core.logger import get_logger
import subprocess, json
from pathlib import Path

app = FastAPI(title="secubox-qos", version="1.0.0", root_path="/api/v1/qos")
app.include_router(auth_router, prefix="/auth")

router = APIRouter()
log    = get_logger("qos")

QOS_CONF = Path("/etc/secubox/qos.json")


def _load_conf() -> dict:
    if QOS_CONF.exists():
        return json.loads(QOS_CONF.read_text())
    return {
        "enabled": False,
        "interface": "eth0",
        "upload_mbps": 100,
        "download_mbps": 200,
        "classes": [],
        "rules": [],
        "quotas": [],
    }


def _save_conf(conf: dict):
    QOS_CONF.parent.mkdir(parents=True, exist_ok=True)
    QOS_CONF.write_text(json.dumps(conf, indent=2))


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


def _apply_htb(conf: dict) -> dict:
    """
    Applique la configuration HTB via pyroute2 ou tc CLI.
    Utilise tc CLI pour la compatibilité maximale.
    """
    iface      = conf.get("interface", "eth0")
    up_kbps    = int(conf.get("upload_mbps", 100)) * 1000
    down_kbps  = int(conf.get("download_mbps", 200)) * 1000

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

    return {"steps": results, "interface": iface}


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


@router.get("/health")
async def health():
    return {"status": "ok", "module": "qos"}


app.include_router(router)
