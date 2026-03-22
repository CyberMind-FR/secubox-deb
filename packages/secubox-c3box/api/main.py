"""SecuBox C3box API - Services Portal"""
import subprocess
from fastapi import FastAPI, Depends
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox C3Box Services Portal")
config = get_config("c3box")

SERVICES = [
    {"name": "crowdsec", "category": "security", "icon": "🛡️", "desc": "IDS/IPS Protection"},
    {"name": "wireguard", "category": "security", "icon": "🔒", "desc": "VPN Server"},
    {"name": "waf", "category": "security", "icon": "🔥", "desc": "Web Application Firewall"},
    {"name": "nac", "category": "security", "icon": "👁️", "desc": "Network Access Control"},
    {"name": "auth", "category": "security", "icon": "🎫", "desc": "OAuth2 & Captive Portal"},
    {"name": "haproxy", "category": "network", "icon": "⚡", "desc": "Load Balancer"},
    {"name": "vhost", "category": "network", "icon": "🌐", "desc": "Virtual Hosts"},
    {"name": "netmodes", "category": "network", "icon": "🔀", "desc": "Network Modes"},
    {"name": "dpi", "category": "network", "icon": "🔍", "desc": "Deep Packet Inspection"},
    {"name": "qos", "category": "network", "icon": "📶", "desc": "Bandwidth Manager"},
    {"name": "droplet", "category": "apps", "icon": "📁", "desc": "File Publisher"},
    {"name": "streamlit", "category": "apps", "icon": "📊", "desc": "Python Apps"},
    {"name": "streamforge", "category": "apps", "icon": "🔨", "desc": "App Manager"},
    {"name": "metablogizer", "category": "apps", "icon": "📝", "desc": "Static Sites"},
    {"name": "publish", "category": "apps", "icon": "🚀", "desc": "Publishing Hub"},
    {"name": "dns", "category": "comm", "icon": "🌍", "desc": "DNS Server"},
    {"name": "mail", "category": "comm", "icon": "📧", "desc": "Email Server"},
    {"name": "webmail", "category": "comm", "icon": "💌", "desc": "Roundcube/SOGo"},
    {"name": "users", "category": "comm", "icon": "👥", "desc": "Identity Manager"},
    {"name": "netdata", "category": "monitoring", "icon": "📈", "desc": "Real-time Monitoring"},
    {"name": "cdn", "category": "network", "icon": "🌐", "desc": "Cache Server"},
    {"name": "mediaflow", "category": "apps", "icon": "🎬", "desc": "Media Streaming"},
]


def check_service(name: str) -> bool:
    """Check if a secubox service is running"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", f"secubox-{name}"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() == "active"
    except:
        return False


@app.get("/status")
async def status():
    """Public status endpoint"""
    return {
        "module": "c3box",
        "status": "ok",
        "version": "1.0.0",
        "description": "Services Portal"
    }


@app.get("/services")
async def list_services():
    """List all available services with status"""
    services_with_status = []
    for svc in SERVICES:
        svc_copy = svc.copy()
        svc_copy["running"] = check_service(svc["name"])
        svc_copy["url"] = f"/{svc['name']}/"
        services_with_status.append(svc_copy)

    return {
        "services": services_with_status,
        "total": len(services_with_status),
        "running": sum(1 for s in services_with_status if s["running"])
    }


@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint"""
    return {"config": dict(config)}
