#!/usr/bin/env python3
"""
SecuBox UI Screenshot Capture & Guideline Checker
==================================================
Captures screenshots from all SecuBox modules and verifies UI compliance.

Usage:
    pip install playwright
    playwright install chromium
    python scripts/ui-screenshot-capture.py [--base-url URL] [--output-dir DIR]

Requirements:
    - Running SecuBox instance at https://localhost:9443/
    - playwright package installed
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

try:
    from playwright.async_api import async_playwright, Page
except ImportError:
    print("ERROR: playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)


# UI Guidelines - Expected elements per the design docs
UI_GUIDELINES = {
    "required_elements": {
        "sidebar": "nav.sidebar, #sidebar",
        "main_content": ".main-content, main",
        "theme_css": "link[href*='crt-light'], link[href*='crt-system']",
    },
    "color_palette_light": {
        "tube_light": "#e8f5e9",
        "tube_pale": "#c8e6c9",
        "p31_peak": "#00dd44",
        "p31_mid": "#009933",
    },
    "color_palette_dark": {
        "tube_black": "#0a0e14",
        "tube_deep": "#1a1f2e",
        "p31_peak": "#33ff66",
    },
    "module_colors": {
        "boot": "#803018",
        "wall": "#9A6010",
        "mind": "#3D35A0",
        "root": "#0A5840",
        "mesh": "#104A88",
        "auth": "#C04E24",
    }
}

# All modules from UI-GUIDE.md
MODULES = [
    # Dashboard
    {"name": "Dashboard", "path": "/", "category": "dashboard"},
    {"name": "Portal", "path": "/portal/", "category": "dashboard"},
    {"name": "System Hub", "path": "/system/", "category": "dashboard"},
    {"name": "SOC", "path": "/soc/", "category": "dashboard"},

    # Security
    {"name": "Users", "path": "/users/", "category": "security"},
    {"name": "WireGuard VPN", "path": "/wireguard/", "category": "security"},
    {"name": "CrowdSec", "path": "/crowdsec/", "category": "security"},
    {"name": "WAF", "path": "/waf/", "category": "security"},
    {"name": "MITM Proxy", "path": "/mitmproxy/", "category": "security"},
    {"name": "Hardening", "path": "/hardening/", "category": "security"},
    {"name": "Auth Guardian", "path": "/auth/", "category": "security"},
    {"name": "Vortex Firewall", "path": "/vortex-firewall/", "category": "security"},
    {"name": "NAC", "path": "/nac/", "category": "security"},
    {"name": "Tor", "path": "/tor/", "category": "security"},
    {"name": "ZKP", "path": "/zkp/", "category": "security"},

    # Network
    {"name": "DNS", "path": "/dns/", "category": "network"},
    {"name": "Vortex DNS", "path": "/vortex-dns/", "category": "network"},
    {"name": "Traffic Shaping", "path": "/traffic/", "category": "network"},
    {"name": "Network Modes", "path": "/netmodes/", "category": "network"},
    {"name": "DPI", "path": "/dpi/", "category": "network"},
    {"name": "QoS", "path": "/qos/", "category": "network"},
    {"name": "Virtual Hosts", "path": "/vhost/", "category": "network"},
    {"name": "CDN Cache", "path": "/cdn/", "category": "network"},
    {"name": "HAProxy", "path": "/haproxy/", "category": "network"},
    {"name": "Exposure", "path": "/exposure/", "category": "network"},
    {"name": "Mesh DNS", "path": "/meshname/", "category": "network"},

    # Monitoring
    {"name": "Metrics", "path": "/metrics/", "category": "monitoring"},
    {"name": "Netdata", "path": "/netdata/", "category": "monitoring"},
    {"name": "Media Flow", "path": "/mediaflow/", "category": "monitoring"},
    {"name": "Device Intel", "path": "/device-intel/", "category": "monitoring"},

    # Publishing
    {"name": "Droplet", "path": "/droplet/", "category": "publishing"},
    {"name": "MetaBlogizer", "path": "/metablogizer/", "category": "publishing"},
    {"name": "Publish", "path": "/publish/", "category": "publishing"},

    # Applications
    {"name": "Mail", "path": "/mail/", "category": "applications"},
    {"name": "Webmail", "path": "/webmail/", "category": "applications"},
    {"name": "Streamlit", "path": "/streamlit/", "category": "applications"},
    {"name": "C3Box", "path": "/c3box/", "category": "applications"},
    {"name": "Gitea", "path": "/gitea/", "category": "applications"},
    {"name": "Nextcloud", "path": "/nextcloud/", "category": "applications"},
    {"name": "StreamForge", "path": "/streamforge/", "category": "applications"},
    {"name": "Ollama", "path": "/ollama/", "category": "applications"},
    {"name": "Jellyfin", "path": "/jellyfin/", "category": "applications"},
    {"name": "Lyrion", "path": "/lyrion/", "category": "applications"},
    {"name": "Hexo", "path": "/hexo/", "category": "applications"},
    {"name": "Webradio", "path": "/webradio/", "category": "applications"},
    {"name": "Torrent", "path": "/torrent/", "category": "applications"},
    {"name": "Newsbin", "path": "/newsbin/", "category": "applications"},
    {"name": "Domoticz", "path": "/domoticz/", "category": "applications"},
    {"name": "GoToSocial", "path": "/gotosocial/", "category": "applications"},
    {"name": "Simplex", "path": "/simplex/", "category": "applications"},
    {"name": "PhotoPrism", "path": "/photoprism/", "category": "applications"},
    {"name": "HomeAssistant", "path": "/homeassistant/", "category": "applications"},
    {"name": "Matrix", "path": "/matrix/", "category": "applications"},
    {"name": "Jitsi", "path": "/jitsi/", "category": "applications"},
    {"name": "PeerTube", "path": "/peertube/", "category": "applications"},
    {"name": "VoIP", "path": "/voip/", "category": "applications"},

    # System
    {"name": "APT Repo", "path": "/repo/", "category": "system"},
    {"name": "Backup", "path": "/backup/", "category": "system"},
    {"name": "Watchdog", "path": "/watchdog/", "category": "system"},
    {"name": "Roadmap", "path": "/roadmap/", "category": "system"},
    {"name": "Admin", "path": "/admin/", "category": "system"},
    {"name": "Console", "path": "/console/", "category": "system"},
]


@dataclass
class UICheckResult:
    """Result of a UI guideline check"""
    module: str
    path: str
    screenshot_path: str
    has_sidebar: bool = False
    has_main_content: bool = False
    has_theme_css: bool = False
    page_title: str = ""
    status_code: int = 0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.has_sidebar and self.has_main_content and self.status_code == 200


class UIScreenshotCapture:
    """Captures screenshots and validates UI guidelines"""

    def __init__(self, base_url: str = "https://localhost:9443", output_dir: str = "docs/screenshots/audit"):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: list[UICheckResult] = []

    async def capture_all(self, headless: bool = True):
        """Capture screenshots from all modules"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,  # For self-signed certs
            )
            page = await context.new_page()

            print(f"SecuBox UI Screenshot Capture")
            print(f"==============================")
            print(f"Base URL: {self.base_url}")
            print(f"Output: {self.output_dir}")
            print(f"Modules: {len(MODULES)}")
            print()

            for i, module in enumerate(MODULES, 1):
                result = await self._capture_module(page, module, i, len(MODULES))
                self.results.append(result)

            await browser.close()

        self._generate_report()

    async def _capture_module(self, page: Page, module: dict, index: int, total: int) -> UICheckResult:
        """Capture screenshot and check guidelines for a single module"""
        name = module["name"]
        path = module["path"]
        url = f"{self.base_url}{path}"

        # Sanitize filename
        filename = path.strip("/").replace("/", "-") or "index"
        screenshot_path = self.output_dir / f"{filename}.png"

        result = UICheckResult(
            module=name,
            path=path,
            screenshot_path=str(screenshot_path),
        )

        print(f"[{index}/{total}] {name} ({path})...", end=" ", flush=True)

        try:
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            result.status_code = response.status if response else 0

            # Wait for dynamic content
            await page.wait_for_timeout(1000)

            # Check required elements
            result.has_sidebar = await self._element_exists(page, UI_GUIDELINES["required_elements"]["sidebar"])
            result.has_main_content = await self._element_exists(page, UI_GUIDELINES["required_elements"]["main_content"])
            result.has_theme_css = await self._element_exists(page, UI_GUIDELINES["required_elements"]["theme_css"])

            # Get page title
            result.page_title = await page.title()

            # Capture screenshot
            await page.screenshot(path=screenshot_path, full_page=False)

            # Check for specific issues
            if not result.has_sidebar:
                result.errors.append("Missing sidebar navigation")
            if not result.has_main_content:
                result.errors.append("Missing main content container")
            if not result.has_theme_css:
                result.warnings.append("Missing CRT theme CSS")

            status = "OK" if result.passed else "FAIL"
            print(f"{status}")

        except Exception as e:
            result.errors.append(f"Error: {str(e)}")
            print(f"ERROR: {e}")

        return result

    async def _element_exists(self, page: Page, selector: str) -> bool:
        """Check if element exists using CSS selector"""
        try:
            element = await page.query_selector(selector)
            return element is not None
        except:
            return False

    def _generate_report(self):
        """Generate markdown report of results"""
        report_path = self.output_dir / "UI-AUDIT-REPORT.md"

        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        with open(report_path, "w") as f:
            f.write(f"# SecuBox UI Audit Report\n\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n")
            f.write(f"**Base URL:** {self.base_url}\n")
            f.write(f"**Total Modules:** {len(self.results)}\n")
            f.write(f"**Passed:** {passed}\n")
            f.write(f"**Failed:** {failed}\n\n")

            f.write("---\n\n")
            f.write("## Summary\n\n")
            f.write("| Module | Path | Sidebar | Content | Theme | Status |\n")
            f.write("|--------|------|---------|---------|-------|--------|\n")

            for r in self.results:
                sidebar = "OK" if r.has_sidebar else "MISS"
                content = "OK" if r.has_main_content else "MISS"
                theme = "OK" if r.has_theme_css else "WARN"
                status = "PASS" if r.passed else "**FAIL**"
                f.write(f"| {r.module} | `{r.path}` | {sidebar} | {content} | {theme} | {status} |\n")

            f.write("\n---\n\n")
            f.write("## Issues Found\n\n")

            issues_found = False
            for r in self.results:
                if r.errors or r.warnings:
                    issues_found = True
                    f.write(f"### {r.module} (`{r.path}`)\n\n")
                    for error in r.errors:
                        f.write(f"- **ERROR:** {error}\n")
                    for warning in r.warnings:
                        f.write(f"- **WARNING:** {warning}\n")
                    f.write("\n")

            if not issues_found:
                f.write("No issues found.\n\n")

            f.write("---\n\n")
            f.write("## Screenshots\n\n")

            by_category = {}
            for r in self.results:
                module = next((m for m in MODULES if m["path"] == r.path), {})
                cat = module.get("category", "other")
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(r)

            for category, results in by_category.items():
                f.write(f"### {category.title()}\n\n")
                for r in results:
                    filename = Path(r.screenshot_path).name
                    f.write(f"#### {r.module}\n")
                    f.write(f"![{r.module}]({filename})\n\n")

        print(f"\nReport saved to: {report_path}")

        # Also save JSON for programmatic use
        json_path = self.output_dir / "ui-audit-results.json"
        with open(json_path, "w") as f:
            json.dump([{
                "module": r.module,
                "path": r.path,
                "screenshot": r.screenshot_path,
                "passed": r.passed,
                "has_sidebar": r.has_sidebar,
                "has_main_content": r.has_main_content,
                "has_theme_css": r.has_theme_css,
                "status_code": r.status_code,
                "errors": r.errors,
                "warnings": r.warnings,
            } for r in self.results], f, indent=2)

        print(f"JSON data saved to: {json_path}")


async def main():
    import argparse

    parser = argparse.ArgumentParser(description="Capture SecuBox UI screenshots")
    parser.add_argument("--base-url", default="https://localhost:9443", help="Base URL")
    parser.add_argument("--output-dir", default="docs/screenshots/audit", help="Output directory")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed mode")
    args = parser.parse_args()

    capture = UIScreenshotCapture(base_url=args.base_url, output_dir=args.output_dir)
    await capture.capture_all(headless=not args.headed)


if __name__ == "__main__":
    asyncio.run(main())
