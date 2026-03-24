#!/usr/bin/env python3
"""
SecuBox Screenshot & Documentation Tool
Captures screenshots from SecuBox instances and generates comparison documentation.

Usage:
    python3 screenshot-tool.py --host vm        # VM at localhost:9443
    python3 screenshot-tool.py --host device    # Device at 192.168.255.1
    python3 screenshot-tool.py --compare        # Compare both and generate wiki docs
    python3 screenshot-tool.py --all            # Capture all and generate everything

Requirements:
    pip install playwright aiohttp Pillow
    playwright install chromium
"""

from __future__ import annotations
import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.async_api import Page, Browser

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None
    print("Warning: playwright not installed. Run: pip install playwright && playwright install chromium")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Configuration
HOSTS = {
    "vm": {
        "name": "SecuBox VM (VirtualBox)",
        "url": "https://localhost:9443",
        "description": "Development/testing virtual machine",
    },
    "device": {
        "name": "SecuBox Device (Debian)",
        "url": "https://192.168.255.1",
        "description": "Production Debian device",
    },
}

# Module definitions with paths and descriptions
MODULES = {
    # Dashboard
    "hub": {"path": "/", "name": "Dashboard", "category": "Dashboard", "icon": "🏠"},
    "soc": {"path": "/soc/", "name": "Security Operations Center", "category": "Dashboard", "icon": "🛡️"},
    "roadmap": {"path": "/roadmap/", "name": "Migration Roadmap", "category": "Dashboard", "icon": "📋"},

    # Security
    "crowdsec": {"path": "/crowdsec/", "name": "CrowdSec", "category": "Security", "icon": "🛡️"},
    "waf": {"path": "/waf/", "name": "Web Application Firewall", "category": "Security", "icon": "🔥"},
    "vortex-firewall": {"path": "/vortex-firewall/", "name": "Vortex Firewall", "category": "Security", "icon": "🔥"},
    "hardening": {"path": "/hardening/", "name": "System Hardening", "category": "Security", "icon": "🔒"},
    "mitmproxy": {"path": "/mitmproxy/", "name": "MITM Proxy", "category": "Security", "icon": "🔍"},

    # Network
    "netmodes": {"path": "/netmodes/", "name": "Network Modes", "category": "Network", "icon": "🌐"},
    "qos": {"path": "/qos/", "name": "QoS Manager", "category": "Network", "icon": "📊"},
    "traffic": {"path": "/traffic/", "name": "Traffic Shaping", "category": "Network", "icon": "📈"},
    "haproxy": {"path": "/haproxy/", "name": "HAProxy", "category": "Network", "icon": "⚡"},
    "cdn": {"path": "/cdn/", "name": "CDN Cache", "category": "Network", "icon": "🚀"},
    "vhost": {"path": "/vhost/", "name": "Virtual Hosts", "category": "Network", "icon": "🏗️"},

    # DNS
    "dns": {"path": "/dns/", "name": "DNS Server", "category": "DNS", "icon": "🌍"},
    "vortex-dns": {"path": "/vortex-dns/", "name": "Vortex DNS", "category": "DNS", "icon": "🛡️"},
    "meshname": {"path": "/meshname/", "name": "Mesh DNS", "category": "DNS", "icon": "📡"},

    # VPN & Privacy
    "wireguard": {"path": "/wireguard/", "name": "WireGuard VPN", "category": "VPN", "icon": "🔗"},
    "mesh": {"path": "/mesh/", "name": "Mesh Network", "category": "VPN", "icon": "🕸️"},
    "p2p": {"path": "/p2p/", "name": "P2P Network", "category": "VPN", "icon": "🔗"},
    "tor": {"path": "/tor/", "name": "Tor Network", "category": "Privacy", "icon": "🧅"},
    "exposure": {"path": "/exposure/", "name": "Exposure Settings", "category": "Privacy", "icon": "🌐"},
    "zkp": {"path": "/zkp/", "name": "Zero-Knowledge Proofs", "category": "Privacy", "icon": "🔐"},

    # Monitoring
    "netdata": {"path": "/netdata/", "name": "Netdata", "category": "Monitoring", "icon": "📊"},
    "dpi": {"path": "/dpi/", "name": "Deep Packet Inspection", "category": "Monitoring", "icon": "🔬"},
    "device-intel": {"path": "/device-intel/", "name": "Device Intelligence", "category": "Monitoring", "icon": "📱"},
    "watchdog": {"path": "/watchdog/", "name": "Watchdog", "category": "Monitoring", "icon": "👁️"},
    "mediaflow": {"path": "/mediaflow/", "name": "Media Flow", "category": "Monitoring", "icon": "🎬"},

    # Access Control
    "auth": {"path": "/auth/", "name": "Authentication", "category": "Access", "icon": "🔐"},
    "nac": {"path": "/nac/", "name": "Network Access Control", "category": "Access", "icon": "🛡️"},
    "users": {"path": "/users/", "name": "User Management", "category": "Access", "icon": "👥"},
    "portal": {"path": "/portal/", "name": "Login Portal", "category": "Access", "icon": "🔐"},

    # Services
    "c3box": {"path": "/c3box/", "name": "Services Portal", "category": "Services", "icon": "📦"},
    "gitea": {"path": "/gitea/", "name": "Gitea", "category": "Services", "icon": "🦊"},
    "nextcloud": {"path": "/nextcloud/", "name": "Nextcloud", "category": "Services", "icon": "☁️"},

    # Email
    "mail": {"path": "/mail/", "name": "Mail Server", "category": "Email", "icon": "📧"},
    "webmail": {"path": "/webmail/", "name": "Webmail", "category": "Email", "icon": "💌"},

    # Publishing
    "publish": {"path": "/publish/", "name": "Publishing", "category": "Publishing", "icon": "📰"},
    "droplet": {"path": "/droplet/", "name": "Droplet", "category": "Publishing", "icon": "💧"},
    "metablogizer": {"path": "/metablogizer/", "name": "Metablogizer", "category": "Publishing", "icon": "📝"},

    # Apps
    "streamlit": {"path": "/streamlit/", "name": "Streamlit", "category": "Apps", "icon": "🎨"},
    "streamforge": {"path": "/streamforge/", "name": "StreamForge", "category": "Apps", "icon": "⚡"},
    "repo": {"path": "/repo/", "name": "Repository", "category": "Apps", "icon": "📦"},

    # System
    "system": {"path": "/system/", "name": "System", "category": "System", "icon": "⚙️"},
    "backup": {"path": "/backup/", "name": "Backup", "category": "System", "icon": "💾"},
}


class ScreenshotTool:
    def __init__(self, output_dir: str = "docs/screenshots"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results = {"vm": {}, "device": {}}
        self.token = None

    async def login(self, page: Page, base_url: str, username: str = "admin", password: str = "secubox") -> bool:
        """Login to SecuBox and get JWT token."""
        try:
            # Go to login page
            await page.goto(f"{base_url}/portal/login.html", wait_until="networkidle", timeout=10000)
            await asyncio.sleep(1)

            # Fill credentials
            await page.fill('input[name="username"], input[type="text"]', username)
            await page.fill('input[name="password"], input[type="password"]', password)

            # Click login button
            await page.click('button[type="submit"], .btn-login, button:has-text("Login")')
            await asyncio.sleep(2)

            # Check if login succeeded by looking for token
            self.token = await page.evaluate("localStorage.getItem('sbx_token')")
            return self.token is not None
        except Exception as e:
            print(f"  Login failed: {e}")
            return False

    async def capture_module(self, page: Page, base_url: str, module_id: str, module_info: dict, host_key: str) -> dict:
        """Capture screenshot of a single module."""
        result = {
            "module": module_id,
            "name": module_info["name"],
            "category": module_info["category"],
            "success": False,
            "screenshot": None,
            "error": None,
        }

        try:
            url = f"{base_url}{module_info['path']}"
            print(f"  Capturing {module_info['icon']} {module_info['name']}...", end=" ", flush=True)

            # Navigate to module
            response = await page.goto(url, wait_until="networkidle", timeout=15000)
            await asyncio.sleep(1)  # Wait for animations

            # Check for redirect to login
            if "/login" in page.url or "/portal" in page.url:
                print("(needs login)", end=" ")
                result["error"] = "requires_auth"

            # Take screenshot
            screenshot_path = self.output_dir / host_key / f"{module_id}.png"
            screenshot_path.parent.mkdir(parents=True, exist_ok=True)

            await page.screenshot(path=str(screenshot_path), full_page=True)

            result["success"] = True
            result["screenshot"] = str(screenshot_path)
            result["status_code"] = response.status if response else None
            print("OK")

        except Exception as e:
            result["error"] = str(e)
            print(f"FAILED: {e}")

        return result

    async def capture_host(self, host_key: str) -> dict:
        """Capture all module screenshots for a host."""
        host = HOSTS[host_key]
        results = {"host": host, "modules": [], "timestamp": datetime.now().isoformat()}

        print(f"\n{'='*60}")
        print(f"Capturing screenshots from: {host['name']}")
        print(f"URL: {host['url']}")
        print(f"{'='*60}")

        if not PLAYWRIGHT_AVAILABLE:
            print("ERROR: Playwright not available. Install with: pip install playwright && playwright install chromium")
            return results

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=['--ignore-certificate-errors', '--no-sandbox']
            )

            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )

            page = await context.new_page()

            # Login first
            print("\nLogging in...")
            logged_in = await self.login(page, host['url'])
            if logged_in:
                print("  Login successful!")
                # Set token for subsequent requests
                await page.evaluate(f"localStorage.setItem('sbx_token', '{self.token}')")
            else:
                print("  Login failed, some pages may not be accessible")

            # Capture each module
            print(f"\nCapturing {len(MODULES)} modules...")
            for module_id, module_info in MODULES.items():
                result = await self.capture_module(page, host['url'], module_id, module_info, host_key)
                results["modules"].append(result)

            await browser.close()

        # Summary
        success = sum(1 for m in results["modules"] if m["success"])
        print(f"\nCompleted: {success}/{len(MODULES)} screenshots captured")

        self.results[host_key] = results
        return results

    def generate_module_docs(self, host_key: str) -> str:
        """Generate markdown documentation for a host's modules."""
        results = self.results.get(host_key, {})
        host = HOSTS[host_key]

        md = f"""# SecuBox Module Screenshots - {host['name']}

*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

**Host:** {host['url']}
**Description:** {host['description']}

---

## Module Gallery

"""
        # Group by category
        categories = {}
        for module in results.get("modules", []):
            cat = module.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(module)

        for category, modules in sorted(categories.items()):
            md += f"### {category}\n\n"
            md += "| Module | Screenshot | Status |\n"
            md += "|--------|------------|--------|\n"

            for module in modules:
                module_id = module["module"]
                info = MODULES.get(module_id, {})
                icon = info.get("icon", "📋")
                name = module["name"]

                if module["success"]:
                    screenshot_rel = f"screenshots/{host_key}/{module_id}.png"
                    status = "✅ Captured"
                    img = f"![{name}]({screenshot_rel})"
                else:
                    status = f"❌ {module.get('error', 'Failed')}"
                    img = "*Not available*"

                md += f"| {icon} **{name}** | {img} | {status} |\n"

            md += "\n"

        return md

    def generate_comparison_doc(self) -> str:
        """Generate comparison document between VM and Device."""
        md = """# SecuBox UI Comparison: VM vs Device

*Generated: {timestamp}*

This document compares the SecuBox user interface between:
- **VM (VirtualBox):** Development/testing environment at localhost:9443
- **Device (Debian):** Production Debian device at 192.168.255.1

---

## Overview

| Metric | VM | Device |
|--------|----|----- --|
| Total Modules | {vm_total} | {device_total} |
| Captured | {vm_success} | {device_success} |
| Failed | {vm_failed} | {device_failed} |

---

## Side-by-Side Comparison

""".format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            vm_total=len(self.results.get("vm", {}).get("modules", [])),
            vm_success=sum(1 for m in self.results.get("vm", {}).get("modules", []) if m.get("success")),
            vm_failed=sum(1 for m in self.results.get("vm", {}).get("modules", []) if not m.get("success")),
            device_total=len(self.results.get("device", {}).get("modules", [])),
            device_success=sum(1 for m in self.results.get("device", {}).get("modules", []) if m.get("success")),
            device_failed=sum(1 for m in self.results.get("device", {}).get("modules", []) if not m.get("success")),
        )

        # Compare each module
        categories = {}
        for module_id, info in MODULES.items():
            cat = info.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append((module_id, info))

        for category, modules in sorted(categories.items()):
            md += f"### {category}\n\n"

            for module_id, info in modules:
                icon = info.get("icon", "📋")
                name = info.get("name", module_id)

                md += f"#### {icon} {name}\n\n"
                md += "| VM | Device |\n"
                md += "|----|----- --|\n"

                # VM screenshot
                vm_path = f"screenshots/vm/{module_id}.png"
                vm_cell = f"![VM {name}]({vm_path})" if (self.output_dir / "vm" / f"{module_id}.png").exists() else "*Not captured*"

                # Device screenshot
                device_path = f"screenshots/device/{module_id}.png"
                device_cell = f"![Device {name}]({device_path})" if (self.output_dir / "device" / f"{module_id}.png").exists() else "*Not captured*"

                md += f"| {vm_cell} | {device_cell} |\n\n"

        return md

    def generate_wiki_openwrt(self) -> str:
        """Generate wiki page for secubox-openwrt repository."""
        return """# SecuBox OpenWRT - UI Documentation

*This documentation shows the original OpenWRT LuCI interface.*

## About SecuBox OpenWRT

SecuBox OpenWRT is the original security appliance firmware based on OpenWRT with LuCI web interface.

**Repository:** [secubox-openwrt](https://github.com/gkerma/secubox-openwrt)

## UI Theme

The OpenWRT version uses the standard LuCI theme with SecuBox customizations:
- Dark theme with blue accents
- Responsive sidebar navigation
- Module-based organization

## Module Screenshots

See the [Module Gallery](Module-Gallery) for screenshots of each module.

## Migration to Debian

SecuBox is being migrated from OpenWRT to Debian. See [secubox-deb](https://github.com/CyberMind-FR/secubox-deb) for the Debian version.

### Key Differences

| Aspect | OpenWRT | Debian |
|--------|---------|--------|
| Base OS | OpenWRT | Debian Bookworm |
| Web Framework | LuCI (Lua) | FastAPI (Python) |
| Theme | LuCI Dark | CRT P31 Phosphor |
| Config | UCI | TOML |
| Init System | procd | systemd |

---

*Generated by SecuBox Screenshot Tool*
"""

    def generate_wiki_debian(self) -> str:
        """Generate wiki page for secubox-deb repository."""
        return """# SecuBox Debian - UI Documentation

*This documentation shows the Debian version with CRT P31 phosphor theme.*

## About SecuBox Debian

SecuBox Debian is the next-generation security appliance running on Debian Bookworm with a modern FastAPI backend.

**Repository:** [secubox-deb](https://github.com/CyberMind-FR/secubox-deb)

## UI Theme: CRT P31 Phosphor

The Debian version features a retro CRT terminal aesthetic inspired by P31 phosphor green monitors:

```css
:root {
    --p31-peak: #33ff66;    /* Bright phosphor green */
    --p31-hot: #66ffaa;     /* Hot phosphor glow */
    --p31-mid: #22cc44;     /* Standard text */
    --p31-dim: #0f8822;     /* Dim text */
    --p31-ghost: #052210;   /* Ghost/borders */
    --p31-decay: #ffb347;   /* Decay/warnings (amber) */
    --tube-black: #050803;  /* CRT black */
    --tube-deep: #080d05;   /* Deep background */
}
```

### Theme Features

- **Phosphor glow effects** on text and borders
- **Scanline overlay** for authentic CRT look
- **Monospace fonts** (Courier Prime)
- **Amber warnings** for alerts and errors
- **Responsive design** with collapsible sidebar

## Architecture

### Backend Stack
- **FastAPI** - Modern async Python web framework
- **Uvicorn** - ASGI server on Unix sockets
- **Nginx** - Reverse proxy and static files
- **JWT** - Authentication tokens
- **TOML** - Configuration format

### Frontend Stack
- **Vanilla JS** - No framework dependencies
- **CSS Variables** - Themeable design system
- **WebSocket** - Real-time updates (SOC module)
- **Shared Components** - sidebar.js, crt-system.css

## Module Count

| Category | Count |
|----------|-------|
| Dashboard | 3 |
| Security | 5 |
| Network | 6 |
| DNS | 3 |
| VPN/Privacy | 6 |
| Monitoring | 5 |
| Access Control | 4 |
| Services | 3 |
| Email | 2 |
| Publishing | 3 |
| Apps | 3 |
| System | 2 |
| **Total** | **47** |

## Module Screenshots

See the [Module Gallery](Module-Gallery) for screenshots of each module.

## API Documentation

Each module exposes a REST API at `/api/v1/<module>/`:

```bash
# Example: Get SOC status
curl -H "Authorization: Bearer $TOKEN" https://secubox/api/v1/soc/status

# Example: List CrowdSec decisions
curl -H "Authorization: Bearer $TOKEN" https://secubox/api/v1/crowdsec/decisions
```

---

*Generated by SecuBox Screenshot Tool*
"""

    def save_results(self):
        """Save all results and documentation."""
        # Save raw results as JSON
        results_file = self.output_dir / "capture_results.json"
        with open(results_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\nResults saved to: {results_file}")

        # Generate documentation for each host
        for host_key in ["vm", "device"]:
            if self.results.get(host_key, {}).get("modules"):
                doc_file = self.output_dir.parent / f"SCREENSHOTS-{host_key.upper()}.md"
                with open(doc_file, "w") as f:
                    f.write(self.generate_module_docs(host_key))
                print(f"Documentation saved to: {doc_file}")

        # Generate comparison document
        if self.results.get("vm") and self.results.get("device"):
            comparison_file = self.output_dir.parent / "UI-COMPARISON.md"
            with open(comparison_file, "w") as f:
                f.write(self.generate_comparison_doc())
            print(f"Comparison saved to: {comparison_file}")

        # Generate wiki pages
        wiki_dir = self.output_dir.parent / "wiki"
        wiki_dir.mkdir(exist_ok=True)

        with open(wiki_dir / "secubox-openwrt-ui.md", "w") as f:
            f.write(self.generate_wiki_openwrt())
        print(f"OpenWRT wiki saved to: {wiki_dir / 'secubox-openwrt-ui.md'}")

        with open(wiki_dir / "secubox-debian-ui.md", "w") as f:
            f.write(self.generate_wiki_debian())
        print(f"Debian wiki saved to: {wiki_dir / 'secubox-debian-ui.md'}")


async def main():
    parser = argparse.ArgumentParser(description="SecuBox Screenshot & Documentation Tool")
    parser.add_argument("--host", choices=["vm", "device", "both"], default="vm",
                       help="Which host to capture (default: vm)")
    parser.add_argument("--compare", action="store_true",
                       help="Generate comparison documentation")
    parser.add_argument("--all", action="store_true",
                       help="Capture all hosts and generate all documentation")
    parser.add_argument("--output", default="docs/screenshots",
                       help="Output directory for screenshots")
    parser.add_argument("--username", default="admin",
                       help="Login username")
    parser.add_argument("--password", default="secubox",
                       help="Login password")
    parser.add_argument("--module", help="Capture only a specific module")
    parser.add_argument("--list-modules", action="store_true",
                       help="List all available modules")

    args = parser.parse_args()

    if args.list_modules:
        print("\nAvailable modules:")
        print("-" * 60)
        for cat in sorted(set(m["category"] for m in MODULES.values())):
            print(f"\n{cat}:")
            for mid, info in MODULES.items():
                if info["category"] == cat:
                    print(f"  {info['icon']} {mid}: {info['name']}")
        return

    tool = ScreenshotTool(args.output)

    if args.all:
        await tool.capture_host("vm")
        await tool.capture_host("device")
        tool.save_results()
    elif args.host == "both":
        await tool.capture_host("vm")
        await tool.capture_host("device")
        tool.save_results()
    else:
        await tool.capture_host(args.host)
        tool.save_results()

    print("\n" + "=" * 60)
    print("Screenshot capture complete!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
