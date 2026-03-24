#!/usr/bin/env python3
"""
SecuBox Roadmap API - Migration Roadmap: OpenWRT → Debian
Tracks migration progress from OpenWRT to Debian packages

NOTE: All endpoints are public (no authentication required)
This module provides read-only migration status information.
"""
from fastapi import FastAPI
from pathlib import Path

app = FastAPI(
    title="SecuBox Roadmap API",
    description="Migration Roadmap: OpenWRT → Debian tracking (Public API)",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

# NOTE: No authentication required - this is a public read-only API

# OpenWRT source modules to port
OPENWRT_MODULES = {
    # Portés et complets (Core)
    "luci-app-secubox": {"deb": "secubox-hub", "status": "complete", "category": "core"},

    # Security
    "luci-app-crowdsec-dashboard": {"deb": "secubox-crowdsec", "status": "complete", "category": "security"},
    "luci-app-wireguard-dashboard": {"deb": "secubox-wireguard", "status": "complete", "category": "security"},
    "luci-app-auth-guardian": {"deb": "secubox-auth", "status": "complete", "category": "security"},
    "luci-app-client-guardian": {"deb": "secubox-nac", "status": "complete", "category": "security"},
    "secubox-waf": {"deb": "secubox-waf", "status": "complete", "category": "security", "new": True},
    "secubox-portal": {"deb": "secubox-portal", "status": "complete", "category": "security", "new": True},
    "secubox-hardening": {"deb": "secubox-hardening", "status": "complete", "category": "security", "new": True},

    # Network
    "luci-app-network-modes": {"deb": "secubox-netmodes", "status": "complete", "category": "network"},
    "luci-app-netifyd-dashboard": {"deb": "secubox-dpi", "status": "complete", "category": "network"},
    "luci-app-bandwidth-manager": {"deb": "secubox-qos", "status": "complete", "category": "network"},
    "luci-app-vhost-manager": {"deb": "secubox-vhost", "status": "complete", "category": "network"},
    "luci-app-cdn-cache": {"deb": "secubox-cdn", "status": "complete", "category": "network"},
    "luci-app-haproxy": {"deb": "secubox-haproxy", "status": "complete", "category": "network"},
    "secubox-dns": {"deb": "secubox-dns", "status": "complete", "category": "network", "new": True},

    # Monitoring
    "luci-app-netdata-dashboard": {"deb": "secubox-netdata", "status": "complete", "category": "monitoring"},
    "luci-app-media-flow": {"deb": "secubox-mediaflow", "status": "complete", "category": "monitoring"},
    "secubox-traffic": {"deb": "secubox-traffic", "status": "complete", "category": "monitoring", "new": True},
    "secubox-watchdog": {"deb": "secubox-watchdog", "status": "complete", "category": "monitoring", "new": True},

    # System
    "luci-app-system-hub": {"deb": "secubox-system", "status": "complete", "category": "system"},
    "secubox-backup": {"deb": "secubox-backup", "status": "complete", "category": "system", "new": True},

    # Admin
    "secubox-mail": {"deb": "secubox-mail", "status": "complete", "category": "admin", "new": True},
    "secubox-webmail": {"deb": "secubox-webmail", "status": "complete", "category": "admin", "new": True},
    "secubox-users": {"deb": "secubox-users", "status": "complete", "category": "admin", "new": True},
    "secubox-mail-lxc": {"deb": "secubox-mail-lxc", "status": "complete", "category": "admin", "new": True},
    "secubox-webmail-lxc": {"deb": "secubox-webmail-lxc", "status": "complete", "category": "admin", "new": True},

    # Publishing
    "luci-app-droplet": {"deb": "secubox-droplet", "status": "complete", "category": "publishing"},
    "luci-app-metablogizer": {"deb": "secubox-metablogizer", "status": "complete", "category": "publishing"},
    "secubox-publish": {"deb": "secubox-publish", "status": "complete", "category": "publishing", "new": True},

    # Apps
    "luci-app-streamlit": {"deb": "secubox-streamlit", "status": "complete", "category": "apps"},
    "luci-app-streamlit-forge": {"deb": "secubox-streamforge", "status": "complete", "category": "apps"},
    "secubox-nextcloud": {"deb": "secubox-nextcloud", "status": "complete", "category": "apps", "new": True},
    "secubox-gitea": {"deb": "secubox-gitea", "status": "complete", "category": "apps", "new": True},
    "secubox-c3box": {"deb": "secubox-c3box", "status": "complete", "category": "apps", "new": True},

    # Privacy
    "secubox-tor": {"deb": "secubox-tor", "status": "complete", "category": "privacy", "new": True},
    "secubox-mitmproxy": {"deb": "secubox-mitmproxy", "status": "complete", "category": "privacy", "new": True},
    "secubox-exposure": {"deb": "secubox-exposure", "status": "complete", "category": "privacy", "new": True},

    # Crypto/Mesh
    "secubox-zkp": {"deb": "secubox-zkp", "status": "complete", "category": "crypto", "new": True},
    "secubox-mesh": {"deb": "secubox-mesh", "status": "complete", "category": "network", "new": True},
    "secubox-p2p": {"deb": "secubox-p2p", "status": "complete", "category": "network", "new": True},

    # Vortex Security Suite (Complete)
    "luci-app-device-intel": {"deb": "secubox-device-intel", "status": "complete", "category": "monitoring"},
    "luci-app-vortex-dns": {"deb": "secubox-vortex-dns", "status": "complete", "category": "network"},
    "luci-app-vortex-firewall": {"deb": "secubox-vortex-firewall", "status": "complete", "category": "security"},
    "luci-app-meshname-dns": {"deb": "secubox-meshname", "status": "complete", "category": "network"},

    # Dashboard/SOC (New Debian modules)
    "secubox-soc": {"deb": "secubox-soc", "status": "complete", "category": "dashboard", "new": True},
    "secubox-roadmap": {"deb": "secubox-roadmap", "status": "complete", "category": "dashboard", "new": True},
    "secubox-repo": {"deb": "secubox-repo", "status": "complete", "category": "system", "new": True},
}

CATEGORIES = {
    "dashboard": {"icon": "🛡️", "name": "Dashboard"},
    "core": {"icon": "🏠", "name": "Core"},
    "security": {"icon": "🔒", "name": "Security"},
    "network": {"icon": "🌐", "name": "Network"},
    "monitoring": {"icon": "📊", "name": "Monitoring"},
    "publishing": {"icon": "📝", "name": "Publishing"},
    "apps": {"icon": "📦", "name": "Applications"},
    "admin": {"icon": "⚙️", "name": "Administration"},
    "system": {"icon": "🖥️", "name": "System"},
    "privacy": {"icon": "🕵️", "name": "Privacy"},
    "crypto": {"icon": "🔐", "name": "Cryptography"},
}


@app.get("/status")
async def get_status():
    """Get roadmap overview status."""
    total = len(OPENWRT_MODULES)
    complete = len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"])
    planned = len([m for m in OPENWRT_MODULES.values() if m["status"] == "planned"])
    new_deb = len([m for m in OPENWRT_MODULES.values() if m.get("new", False)])

    return {
        "total_modules": total,
        "complete": complete,
        "in_progress": total - complete - planned,
        "planned": planned,
        "new_debian_only": new_deb,
        "progress_percent": round(complete / total * 100) if total else 0
    }


@app.get("/roadmap")
async def get_roadmap():
    """Get full migration roadmap with module details."""
    complete = []
    in_progress = []
    planned = []
    new_modules = []

    for openwrt, info in OPENWRT_MODULES.items():
        deb = info["deb"]
        sock = Path(f"/run/secubox/{deb.replace('secubox-','')}.sock")
        installed = sock.exists()

        entry = {
            "source": openwrt,
            "target": deb,
            "category": info["category"],
            "category_info": CATEGORIES.get(info["category"], {"icon": "📋", "name": info["category"]}),
            "status": info["status"],
            "installed": installed,
            "new": info.get("new", False),
        }

        if info.get("new"):
            new_modules.append(entry)
        elif info["status"] == "complete":
            complete.append(entry)
        elif info["status"] == "in_progress":
            in_progress.append(entry)
        else:
            planned.append(entry)

    total = len(OPENWRT_MODULES)
    done = len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"])

    return {
        "summary": {
            "total": total,
            "complete": done,
            "in_progress": len(in_progress),
            "planned": len(planned),
            "new_debian": len(new_modules),
            "progress_percent": round(done / total * 100) if total else 0,
        },
        "by_category": {
            cat: {
                "info": CATEGORIES.get(cat, {"icon": "📋", "name": cat}),
                "total": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat]),
                "complete": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat and m["status"] == "complete"]),
            }
            for cat in set(m["category"] for m in OPENWRT_MODULES.values())
        },
        "complete": complete,
        "in_progress": in_progress,
        "planned": planned,
        "new_modules": new_modules,
    }


@app.get("/modules")
async def list_modules(category: str = None, status: str = None):
    """List modules with optional filtering."""
    modules = []

    for openwrt, info in OPENWRT_MODULES.items():
        if category and info["category"] != category:
            continue
        if status and info["status"] != status:
            continue

        deb = info["deb"]
        sock = Path(f"/run/secubox/{deb.replace('secubox-','')}.sock")

        modules.append({
            "source": openwrt,
            "target": deb,
            "category": info["category"],
            "status": info["status"],
            "installed": sock.exists(),
            "new": info.get("new", False),
        })

    return {"modules": modules, "count": len(modules)}


@app.get("/categories")
async def list_categories():
    """List all categories with stats."""
    return {
        "categories": [
            {
                "id": cat,
                "icon": info["icon"],
                "name": info["name"],
                "total": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat]),
                "complete": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat and m["status"] == "complete"]),
            }
            for cat, info in CATEGORIES.items()
            if any(m["category"] == cat for m in OPENWRT_MODULES.values())
        ]
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-roadmap"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
