#!/usr/bin/env python3
"""
SecuBox Roadmap API - Migration Roadmap: OpenWRT → Debian
Tracks migration progress from OpenWRT to Debian packages

NOTE: All endpoints are public (no authentication required)
This module provides read-only migration status information.

Updated: 2026-03-26
OpenWRT: 103 luci-app modules
Debian: 52 packages (49 UI + 3 backend)
"""
from fastapi import FastAPI
from pathlib import Path

app = FastAPI(
    title="SecuBox Roadmap API",
    description="Migration Roadmap: OpenWRT → Debian tracking (Public API)",
    version="1.1.0",
    docs_url="/docs",
    redoc_url=None
)

# NOTE: No authentication required - this is a public read-only API

# Complete mapping of all OpenWRT modules to Debian packages
# Status: complete, planned
OPENWRT_MODULES = {
    # ═══════════════════════════════════════════════════════════════
    # CORE INFRASTRUCTURE (3 OpenWRT → 7 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-secubox": {"deb": "secubox-hub", "status": "complete", "category": "core"},
    "luci-app-secubox-portal": {"deb": "secubox-portal", "status": "complete", "category": "core"},
    "luci-app-system-hub": {"deb": "secubox-system", "status": "complete", "category": "core"},

    # ═══════════════════════════════════════════════════════════════
    # SECURITY (18 OpenWRT → 14 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-crowdsec-dashboard": {"deb": "secubox-crowdsec", "status": "complete", "category": "security"},
    "luci-app-auth-guardian": {"deb": "secubox-auth", "status": "complete", "category": "security"},
    "luci-app-client-guardian": {"deb": "secubox-nac", "status": "complete", "category": "security"},
    "luci-app-wireguard-dashboard": {"deb": "secubox-wireguard", "status": "complete", "category": "security"},
    "luci-app-tor-shield": {"deb": "secubox-tor", "status": "complete", "category": "security"},
    "luci-app-vortex-dns": {"deb": "secubox-vortex-dns", "status": "complete", "category": "security"},
    "luci-app-vortex-firewall": {"deb": "secubox-vortex-firewall", "status": "complete", "category": "security"},
    "luci-app-mitmproxy": {"deb": "secubox-mitmproxy", "status": "complete", "category": "security"},
    "luci-app-secubox-users": {"deb": "secubox-users", "status": "complete", "category": "security"},
    "luci-app-zkp": {"deb": "secubox-zkp", "status": "complete", "category": "security"},
    # Planned
    "luci-app-wazuh": {"deb": "secubox-wazuh", "status": "planned", "category": "security"},
    "luci-app-ipblocklist": {"deb": "secubox-ipblocklist", "status": "planned", "category": "security"},
    "luci-app-cve-triage": {"deb": "secubox-cve", "status": "planned", "category": "security"},
    "luci-app-threat-analyst": {"deb": "secubox-threat", "status": "planned", "category": "security"},
    "luci-app-mac-guardian": {"deb": "secubox-mac-guardian", "status": "planned", "category": "security"},
    "luci-app-cookie-tracker": {"deb": "secubox-cookie-tracker", "status": "planned", "category": "security"},
    "luci-app-interceptor": {"deb": "secubox-interceptor", "status": "planned", "category": "security"},
    "luci-app-secubox-security-threats": {"deb": "secubox-threats", "status": "planned", "category": "security"},

    # ═══════════════════════════════════════════════════════════════
    # NETWORK (20 OpenWRT → 14 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-network-modes": {"deb": "secubox-netmodes", "status": "complete", "category": "network"},
    "luci-app-bandwidth-manager": {"deb": "secubox-qos", "status": "complete", "category": "network"},
    "luci-app-traffic-shaper": {"deb": "secubox-traffic", "status": "complete", "category": "network"},
    "luci-app-haproxy": {"deb": "secubox-haproxy", "status": "complete", "category": "network"},
    "luci-app-cdn-cache": {"deb": "secubox-cdn", "status": "complete", "category": "network"},
    "luci-app-vhost-manager": {"deb": "secubox-vhost", "status": "complete", "category": "network"},
    "luci-app-exposure": {"deb": "secubox-exposure", "status": "complete", "category": "network"},
    "luci-app-meshname-dns": {"deb": "secubox-meshname", "status": "complete", "category": "network"},
    "luci-app-dns-master": {"deb": "secubox-dns", "status": "complete", "category": "network"},
    "luci-app-dpi-dual": {"deb": "secubox-dpi", "status": "complete", "category": "network"},
    "luci-app-secubox-mesh": {"deb": "secubox-mesh", "status": "complete", "category": "network"},
    "luci-app-secubox-p2p": {"deb": "secubox-p2p", "status": "complete", "category": "network"},
    # Planned
    "luci-app-secubox-netifyd": {"deb": "secubox-netifyd", "status": "planned", "category": "network"},
    "luci-app-network-tweaks": {"deb": "secubox-net-tweaks", "status": "planned", "category": "network"},
    "luci-app-network-anomaly": {"deb": "secubox-anomaly", "status": "planned", "category": "network"},
    "luci-app-dns-provider": {"deb": "secubox-dns-provider", "status": "planned", "category": "network"},
    "luci-app-dnsguard": {"deb": "secubox-dnsguard", "status": "planned", "category": "network"},
    "luci-app-routes-status": {"deb": "secubox-routes", "status": "planned", "category": "network"},
    "luci-app-ksm-manager": {"deb": "secubox-ksm", "status": "planned", "category": "network"},
    "luci-app-mqtt-bridge": {"deb": "secubox-mqtt", "status": "planned", "category": "network"},

    # ═══════════════════════════════════════════════════════════════
    # MONITORING (9 OpenWRT → 6 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-netdata-dashboard": {"deb": "secubox-netdata", "status": "complete", "category": "monitoring"},
    "luci-app-media-flow": {"deb": "secubox-mediaflow", "status": "complete", "category": "monitoring"},
    "luci-app-device-intel": {"deb": "secubox-device-intel", "status": "complete", "category": "monitoring"},
    "luci-app-metrics-dashboard": {"deb": "secubox-metrics", "status": "complete", "category": "monitoring"},
    # Planned
    "luci-app-glances": {"deb": "secubox-glances", "status": "planned", "category": "monitoring"},
    "luci-app-ndpid": {"deb": "secubox-ndpid", "status": "planned", "category": "monitoring"},
    "luci-app-service-registry": {"deb": "secubox-registry", "status": "planned", "category": "monitoring"},
    "luci-app-cyberfeed": {"deb": "secubox-cyberfeed", "status": "planned", "category": "monitoring"},
    "luci-app-media-hub": {"deb": "secubox-media-hub", "status": "planned", "category": "monitoring"},

    # ═══════════════════════════════════════════════════════════════
    # APPLICATIONS (28 OpenWRT → 9 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-mailserver": {"deb": "secubox-mail", "status": "complete", "category": "apps"},
    "luci-app-gitea": {"deb": "secubox-gitea", "status": "complete", "category": "apps"},
    "luci-app-nextcloud": {"deb": "secubox-nextcloud", "status": "complete", "category": "apps"},
    "luci-app-streamlit": {"deb": "secubox-streamlit", "status": "complete", "category": "apps"},
    "luci-app-streamlit-forge": {"deb": "secubox-streamforge", "status": "complete", "category": "apps"},
    # Planned
    "luci-app-ollama": {"deb": "secubox-ollama", "status": "planned", "category": "apps"},
    "luci-app-localai": {"deb": "secubox-localai", "status": "planned", "category": "apps"},
    "luci-app-ai-gateway": {"deb": "secubox-ai-gateway", "status": "planned", "category": "apps"},
    "luci-app-ai-insights": {"deb": "secubox-ai-insights", "status": "planned", "category": "apps"},
    "luci-app-jellyfin": {"deb": "secubox-jellyfin", "status": "planned", "category": "apps"},
    "luci-app-lyrion": {"deb": "secubox-lyrion", "status": "planned", "category": "apps"},
    "luci-app-jitsi": {"deb": "secubox-jitsi", "status": "planned", "category": "apps"},
    "luci-app-matrix": {"deb": "secubox-matrix", "status": "planned", "category": "apps"},
    "luci-app-simplex": {"deb": "secubox-simplex", "status": "planned", "category": "apps"},
    "luci-app-jabber": {"deb": "secubox-jabber", "status": "planned", "category": "apps"},
    "luci-app-gotosocial": {"deb": "secubox-gotosocial", "status": "planned", "category": "apps"},
    "luci-app-peertube": {"deb": "secubox-peertube", "status": "planned", "category": "apps"},
    "luci-app-magicmirror2": {"deb": "secubox-magicmirror", "status": "planned", "category": "apps"},
    "luci-app-zigbee2mqtt": {"deb": "secubox-zigbee", "status": "planned", "category": "apps"},
    "luci-app-domoticz": {"deb": "secubox-domoticz", "status": "planned", "category": "apps"},
    "luci-app-picobrew": {"deb": "secubox-picobrew", "status": "planned", "category": "apps"},
    "luci-app-webradio": {"deb": "secubox-webradio", "status": "planned", "category": "apps"},
    "luci-app-photoprism": {"deb": "secubox-photoprism", "status": "planned", "category": "apps"},
    "luci-app-turn": {"deb": "secubox-turn", "status": "planned", "category": "apps"},
    "luci-app-voip": {"deb": "secubox-voip", "status": "planned", "category": "apps"},

    # ═══════════════════════════════════════════════════════════════
    # PUBLISHING (9 OpenWRT → 3 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-droplet": {"deb": "secubox-droplet", "status": "complete", "category": "publishing"},
    "luci-app-metablogizer": {"deb": "secubox-metablogizer", "status": "complete", "category": "publishing"},
    # Planned
    "luci-app-hexojs": {"deb": "secubox-hexo", "status": "planned", "category": "publishing"},
    "luci-app-metabolizer": {"deb": "secubox-metabolizer", "status": "planned", "category": "publishing"},
    "luci-app-metacatalog": {"deb": "secubox-metacatalog", "status": "planned", "category": "publishing"},
    "luci-app-reporter": {"deb": "secubox-reporter", "status": "planned", "category": "publishing"},
    "luci-app-newsbin": {"deb": "secubox-newsbin", "status": "planned", "category": "publishing"},
    "luci-app-torrent": {"deb": "secubox-torrent", "status": "planned", "category": "publishing"},

    # ═══════════════════════════════════════════════════════════════
    # SYSTEM (24 OpenWRT → 3 Debian)
    # ═══════════════════════════════════════════════════════════════
    "luci-app-backup": {"deb": "secubox-backup", "status": "complete", "category": "system"},
    "luci-app-repo": {"deb": "secubox-repo", "status": "complete", "category": "system"},
    # Planned
    "luci-app-config-vault": {"deb": "secubox-vault", "status": "planned", "category": "system"},
    "luci-app-config-advisor": {"deb": "secubox-advisor", "status": "planned", "category": "system"},
    "luci-app-cloner": {"deb": "secubox-cloner", "status": "planned", "category": "system"},
    "luci-app-vm": {"deb": "secubox-vm", "status": "planned", "category": "system"},
    "luci-app-secubox-netdiag": {"deb": "secubox-netdiag", "status": "planned", "category": "system"},
    "luci-app-secubox-mirror": {"deb": "secubox-mirror", "status": "planned", "category": "system"},
    "luci-app-secubox-admin": {"deb": "secubox-admin", "status": "planned", "category": "system"},
    "luci-app-master-link": {"deb": "secubox-master-link", "status": "planned", "category": "system"},
    "luci-app-rtty-remote": {"deb": "secubox-rtty", "status": "planned", "category": "system"},
    "luci-app-mmpm": {"deb": "secubox-mmpm", "status": "planned", "category": "system"},
    "luci-app-saas-relay": {"deb": "secubox-saas-relay", "status": "planned", "category": "system"},
    "luci-app-openclaw": {"deb": "secubox-openclaw", "status": "planned", "category": "system"},
    "luci-app-rezapp": {"deb": "secubox-rezapp", "status": "planned", "category": "system"},
    "luci-app-localrecall": {"deb": "secubox-localrecall", "status": "planned", "category": "system"},
    "luci-app-avatar-tap": {"deb": "secubox-avatar-tap", "status": "planned", "category": "system"},
    "luci-app-iot-guard": {"deb": "secubox-iot-guard", "status": "planned", "category": "system"},
    "luci-app-smtp-relay": {"deb": "secubox-smtp-relay", "status": "planned", "category": "system"},
}

# Debian-only modules (no OpenWRT equivalent)
DEBIAN_ONLY_MODULES = {
    "secubox-core": {"category": "core", "description": "Shared Python library"},
    "secubox-daemon": {"category": "core", "description": "Go mesh daemon (secuboxd, secuboxctl)"},
    "secubox-full": {"category": "core", "description": "Metapackage (all modules)"},
    "secubox-lite": {"category": "core", "description": "Metapackage (essential modules)"},
    "secubox-waf": {"category": "security", "description": "Web Application Firewall (CrowdSec)"},
    "secubox-hardening": {"category": "security", "description": "Kernel sysctl + module blacklist"},
    "secubox-soc": {"category": "monitoring", "description": "Security Operations Center dashboard"},
    "secubox-watchdog": {"category": "monitoring", "description": "Container/service health monitoring"},
    "secubox-publish": {"category": "publishing", "description": "Unified publishing platform"},
    "secubox-c3box": {"category": "apps", "description": "Services portal with topology"},
    "secubox-roadmap": {"category": "system", "description": "Migration roadmap tracker"},
    "secubox-webmail": {"category": "apps", "description": "Roundcube/SOGo webmail"},
    "secubox-mail-lxc": {"category": "apps", "description": "Mail server LXC backend"},
    "secubox-webmail-lxc": {"category": "apps", "description": "Webmail LXC backend"},
}

CATEGORIES = {
    "core": {"icon": "🏠", "name": "Core", "order": 0},
    "security": {"icon": "🛡️", "name": "Security", "order": 1},
    "network": {"icon": "🌐", "name": "Network", "order": 2},
    "monitoring": {"icon": "📈", "name": "Monitoring", "order": 3},
    "publishing": {"icon": "📤", "name": "Publishing", "order": 4},
    "apps": {"icon": "🎯", "name": "Applications", "order": 5},
    "system": {"icon": "📦", "name": "System", "order": 6},
}


@app.get("/status")
async def get_status():
    """Get roadmap overview status."""
    total_openwrt = len(OPENWRT_MODULES)
    complete = len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"])
    planned = len([m for m in OPENWRT_MODULES.values() if m["status"] == "planned"])
    debian_only = len(DEBIAN_ONLY_MODULES)

    return {
        "openwrt_modules": total_openwrt,
        "debian_packages": complete + debian_only,
        "migrated": complete,
        "pending": planned,
        "debian_only": debian_only,
        "progress_percent": round(complete / total_openwrt * 100) if total_openwrt else 0,
        "total_endpoints": "~1000+"
    }


@app.get("/roadmap")
async def get_roadmap():
    """Get full migration roadmap with module details."""
    complete = []
    planned = []
    debian_only = []

    for openwrt, info in OPENWRT_MODULES.items():
        deb = info["deb"]
        sock = Path(f"/run/secubox/{deb.replace('secubox-','')}.sock")
        installed = sock.exists()

        entry = {
            "source": openwrt,
            "target": deb,
            "category": info["category"],
            "category_info": CATEGORIES.get(info["category"], {"icon": "📋", "name": info["category"], "order": 99}),
            "status": info["status"],
            "installed": installed,
        }

        if info["status"] == "complete":
            complete.append(entry)
        else:
            planned.append(entry)

    for deb, info in DEBIAN_ONLY_MODULES.items():
        sock = Path(f"/run/secubox/{deb.replace('secubox-','')}.sock")
        debian_only.append({
            "source": "(Debian only)",
            "target": deb,
            "category": info["category"],
            "category_info": CATEGORIES.get(info["category"], {"icon": "📋", "name": info["category"], "order": 99}),
            "status": "complete",
            "installed": sock.exists(),
            "description": info["description"],
            "new": True,
        })

    total_openwrt = len(OPENWRT_MODULES)
    migrated = len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"])

    return {
        "summary": {
            "openwrt_total": total_openwrt,
            "migrated": migrated,
            "pending": total_openwrt - migrated,
            "debian_only": len(DEBIAN_ONLY_MODULES),
            "total_debian_packages": migrated + len(DEBIAN_ONLY_MODULES),
            "progress_percent": round(migrated / total_openwrt * 100) if total_openwrt else 0,
        },
        "by_category": {
            cat: {
                "info": CATEGORIES.get(cat, {"icon": "📋", "name": cat, "order": 99}),
                "openwrt_total": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat]),
                "migrated": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat and m["status"] == "complete"]),
                "debian_only": len([m for m in DEBIAN_ONLY_MODULES.values() if m["category"] == cat]),
            }
            for cat in CATEGORIES.keys()
        },
        "complete": sorted(complete, key=lambda x: (CATEGORIES.get(x["category"], {}).get("order", 99), x["target"])),
        "planned": sorted(planned, key=lambda x: (CATEGORIES.get(x["category"], {}).get("order", 99), x["target"])),
        "debian_only": sorted(debian_only, key=lambda x: (CATEGORIES.get(x["category"], {}).get("order", 99), x["target"])),
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
        })

    return {"modules": modules, "count": len(modules)}


@app.get("/categories")
async def list_categories():
    """List all categories with stats."""
    return {
        "categories": sorted([
            {
                "id": cat,
                "icon": info["icon"],
                "name": info["name"],
                "order": info["order"],
                "openwrt_total": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat]),
                "migrated": len([m for m in OPENWRT_MODULES.values() if m["category"] == cat and m["status"] == "complete"]),
                "debian_only": len([m for m in DEBIAN_ONLY_MODULES.values() if m["category"] == cat]),
            }
            for cat, info in CATEGORIES.items()
        ], key=lambda x: x["order"])
    }


@app.get("/comparison")
async def get_comparison():
    """Get OpenWRT vs Debian comparison summary."""
    return {
        "openwrt": {
            "total_modules": len(OPENWRT_MODULES),
            "platform": "OpenWRT 23.05",
            "arch": "MIPS/ARM",
            "backend": "Shell + RPCD",
            "api_style": "ubus JSON-RPC",
            "config": "UCI (/etc/config)",
            "firewall": "fw3 (iptables)",
        },
        "debian": {
            "total_packages": len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"]) + len(DEBIAN_ONLY_MODULES),
            "platform": "Debian Bookworm 12",
            "arch": "ARM64/AMD64",
            "backend": "FastAPI + Python",
            "api_style": "REST API",
            "config": "TOML/YAML",
            "firewall": "nftables",
            "endpoints": "~1000+",
        },
        "migration": {
            "migrated": len([m for m in OPENWRT_MODULES.values() if m["status"] == "complete"]),
            "pending": len([m for m in OPENWRT_MODULES.values() if m["status"] == "planned"]),
            "debian_only": len(DEBIAN_ONLY_MODULES),
        }
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "secubox-roadmap", "version": "1.1.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
