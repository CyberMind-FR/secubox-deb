#!/usr/bin/env python3
"""
SecuBox Module Screenshots Capture
===================================
Captures screenshots of all SecuBox modules for wiki documentation.

Features:
- Auto-discovers all 120+ modules from packages/
- Creates screenshots in docs/screenshots/vm/
- Generates thumbnails for wiki index
- Outputs JSON manifest for generate-docs.py integration

Usage:
    pip install -r scripts/requirements-screenshot.txt
    playwright install chromium

    # Capture all modules
    python scripts/capture-screenshots.py --base-url https://192.168.1.200

    # Capture specific modules
    python scripts/capture-screenshots.py --modules hub,soc,crowdsec

    # Generate thumbnails only (from existing screenshots)
    python scripts/capture-screenshots.py --thumbnails-only

Requirements:
    - Running SecuBox instance
    - playwright package with chromium
    - Pillow for thumbnail generation
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
import argparse

try:
    from playwright.async_api import async_playwright, Page, Browser
except ImportError:
    print("ERROR: playwright not installed.")
    print("Run: pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    from PIL import Image as _PIL_Image  # noqa: F401
    PILLOW_AVAILABLE = True
    del _PIL_Image
except ImportError:
    print("WARNING: Pillow not installed. Thumbnails will be skipped.")
    print("Run: pip install Pillow")
    PILLOW_AVAILABLE = False


# ============================================================================
# Module Discovery
# ============================================================================

def discover_modules(packages_dir: Path) -> list[dict]:
    """
    Auto-discover all modules from packages/secubox-*/www/*/index.html
    Returns list of module metadata.
    """
    modules = []
    seen = set()

    for index_html in sorted(packages_dir.glob("secubox-*/www/*/index.html")):
        # Extract: packages/secubox-hub/www/hub/index.html -> hub
        parts = index_html.parts
        package_name = None
        www_name = None

        for i, part in enumerate(parts):
            if part.startswith("secubox-"):
                package_name = part.replace("secubox-", "")
            if part == "www" and i + 1 < len(parts):
                www_name = parts[i + 1]

        if www_name and www_name not in seen:
            seen.add(www_name)
            modules.append({
                "id": www_name,
                "package": package_name,
                "path": f"/{www_name}/",
                "name": www_name.replace("-", " ").title(),
                "category": categorize_module(www_name),
            })

    return modules


def categorize_module(module_id: str) -> str:
    """Categorize module based on its ID."""
    categories = {
        # Dashboard
        "hub": "Dashboard", "soc": "Dashboard", "roadmap": "Dashboard",
        "metrics": "Dashboard", "admin": "Dashboard",

        # Security
        "crowdsec": "Security", "waf": "Security", "nac": "Security",
        "auth": "Security", "hardening": "Security", "mitmproxy": "Security",
        "vortex-firewall": "Security", "ipblock": "Security", "mac-guard": "Security",
        "interceptor": "Security", "cookies": "Security", "threats": "Security",
        "threat-analyst": "Security", "cve-triage": "Security", "wazuh": "Security",
        "ossec": "Security", "openclaw": "Security", "iot-guard": "Security",

        # Network
        "netmodes": "Network", "qos": "Network", "traffic": "Network",
        "haproxy": "Network", "cdn": "Network", "vhost": "Network",
        "routes": "Network", "nettweak": "Network", "netdiag": "Network",
        "network-anomaly": "Network", "modem": "Network",

        # DNS
        "dns": "DNS", "vortex-dns": "DNS", "meshname": "DNS",
        "dns-guard": "DNS", "dns-provider": "DNS", "ad-guard": "DNS",

        # VPN & Privacy
        "wireguard": "VPN", "mesh": "VPN", "p2p": "VPN", "master-link": "VPN",
        "tor": "Privacy", "exposure": "Privacy", "zkp": "Privacy",
        "simplex": "Privacy", "vault": "Privacy",

        # Monitoring
        "netdata": "Monitoring", "dpi": "Monitoring", "netifyd": "Monitoring",
        "ndpid": "Monitoring", "device-intel": "Monitoring", "watchdog": "Monitoring",
        "mediaflow": "Monitoring", "glances": "Monitoring",

        # Access
        "portal": "Access", "users": "Access", "identity": "Access",

        # Services
        "c3box": "Services", "gitea": "Services", "nextcloud": "Services",
        "ollama": "AI", "localai": "AI", "ai-gateway": "AI",
        "ai-insights": "AI", "localrecall": "AI", "mcp-server": "AI",

        # Email
        "mail": "Email", "webmail": "Email", "mail-lxc": "Email",
        "webmail-lxc": "Email", "smtp-relay": "Email", "jabber": "Email",

        # Media
        "jellyfin": "Media", "lyrion": "Media", "webradio": "Media",
        "photoprism": "Media", "peertube": "Media", "torrent": "Media",
        "newsbin": "Media",

        # Publishing
        "publish": "Publishing", "droplet": "Publishing", "metablogizer": "Publishing",
        "hexo": "Publishing", "gotosocial": "Publishing", "cyberfeed": "Publishing",
        "metacatalog": "Publishing", "metabolizer": "Publishing",

        # Apps
        "streamlit": "Apps", "streamforge": "Apps", "repo": "Apps",
        "domoticz": "IoT", "homeassistant": "IoT", "zigbee": "IoT",
        "mqtt": "IoT", "matrix": "Communication", "jitsi": "Communication",
        "voip": "Communication", "turn": "Communication",

        # System
        "system": "System", "backup": "System", "config-advisor": "System",
        "reporter": "System", "mirror": "System", "cloner": "System",
        "ksm": "System", "avatar": "System", "rtty": "System",
        "vm": "System", "redroid": "System", "rezapp": "System",
        "picobrew": "System", "saas-relay": "System", "magicmirror": "System",
        "mmpm": "System", "eye-remote": "System",
    }
    return categories.get(module_id, "Other")


# ============================================================================
# Screenshot Capture
# ============================================================================

@dataclass
class CaptureResult:
    """Result of a screenshot capture."""
    module_id: str
    module_name: str
    category: str
    path: str
    screenshot_path: str
    thumbnail_path: str = ""
    success: bool = False
    status_code: int = 0
    error: Optional[str] = None
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ScreenshotCapture:
    """Captures screenshots from SecuBox modules."""

    def __init__(
        self,
        base_url: str = "https://localhost:9443",
        output_dir: str = "docs/screenshots/vm",
        thumb_dir: str = "docs/screenshots/thumbnails",
        username: str = "admin",
        password: Optional[str] = None,
        page_delay: int = 30,  # seconds to wait for cache refresh
        token: Optional[str] = None,  # pre-minted JWT (bypass password login)
    ):
        self.base_url = base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.thumb_dir = Path(thumb_dir)
        self.username = username
        self.password = password or os.environ.get("SECUBOX_PASSWORD", "secubox")
        self.page_delay = page_delay
        self.token = token or os.environ.get("SECUBOX_TOKEN") or None

        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.thumb_dir.mkdir(parents=True, exist_ok=True)

        self.results: list[CaptureResult] = []

    async def login(self, page: Page) -> bool:
        """Authenticate the capture session. With a pre-minted JWT (--token), the
        token is injected into localStorage by an init-script on the context (set
        in capture_all) BEFORE any page script runs, so every dashboard sees an
        authenticated session on first paint — no password flow needed. Otherwise
        fall back to the API password login."""
        if self.token:
            print("Auth: pre-minted JWT (injected via init-script)")
            return True
        try:
            print(f"Logging in to {self.base_url}...")

            # Go to login page first
            await page.goto(f"{self.base_url}/login.html", wait_until="networkidle", timeout=30000)

            # Use API login directly via page.evaluate
            login_result = await page.evaluate(f"""
                async () => {{
                    try {{
                        const res = await fetch('/api/v1/auth/auth/login', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ username: '{self.username}', password: '{self.password}' }})
                        }});

                        if (!res.ok) {{
                            return {{ success: false, error: 'HTTP ' + res.status }};
                        }}

                        const data = await res.json();
                        if (data.access_token) {{
                            localStorage.setItem('sbx_token', data.access_token);
                            localStorage.setItem('sbx_user', '{self.username}');
                            return {{ success: true, token: data.access_token }};
                        }}
                        return {{ success: false, error: 'No token returned' }};
                    }} catch (e) {{
                        return {{ success: false, error: e.message }};
                    }}
                }}
            """)

            if login_result.get("success"):
                print(f"  Login successful (token received)")
                # Reload to apply token
                await page.reload(wait_until="networkidle")
                return True
            else:
                print(f"  Login failed: {login_result.get('error', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"  Login error: {e}")
            return False

    async def capture_module(self, page: Page, module: dict, index: int, total: int) -> CaptureResult:
        """Capture screenshot for a single module."""
        module_id = module["id"]
        module_name = module["name"]
        category = module["category"]
        path = module["path"]
        url = f"{self.base_url}{path}"

        screenshot_path = self.output_dir / f"{module_id}.png"
        thumb_path = self.thumb_dir / f"{module_id}-thumb.png"

        result = CaptureResult(
            module_id=module_id,
            module_name=module_name,
            category=category,
            path=path,
            screenshot_path=str(screenshot_path),
            thumbnail_path=str(thumb_path),
            timestamp=datetime.now().isoformat(),
        )

        print(f"[{index:3d}/{total}] {module_name:30s} {path:25s}", end=" ", flush=True)

        try:
            # "domcontentloaded" (NOT "networkidle"): live dashboards poll/websocket
            # forever and never reach network-idle, so networkidle would burn the full
            # 30s timeout on every one. We gate readiness deterministically afterwards
            # with _wait_content_ready (loading sentinels clear + a real network lull).
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            result.status_code = response.status if response else 0

            if result.status_code != 200:
                result.error = f"HTTP {result.status_code}"
                print(f"SKIP ({result.error})")
                return result

            # Wait for dynamic content to FINISH rendering (deterministic, not a
            # blind sleep): loading sentinels clear + network settles, capped by
            # page_delay as an upper bound. Reports how it resolved.
            waited = await self._wait_content_ready(page, self.page_delay)
            print(f"[{waited}]", end=" ", flush=True)

            # Capture screenshot
            await page.screenshot(path=screenshot_path, full_page=False)
            result.success = True

            # Generate thumbnail
            if PILLOW_AVAILABLE:
                self._create_thumbnail(screenshot_path, thumb_path)

            print("OK")

        except Exception as e:
            result.error = str(e)
            print(f"ERROR: {e}")

        return result

    async def _wait_content_ready(self, page: Page, max_wait: int) -> str:
        """Wait until a dashboard has FINISHED rendering its async content, rather
        than sleeping a fixed delay. SecuBox panels fetch data after load (cache
        refresh, tab-switch fetches) and paint placeholders meanwhile, so a blind
        timeout captures half-loaded pages or wastes time.

        Resolution = first of:
          • content-ready: no loading sentinels remain ("loading…", spinners,
            empty placeholders, "—"/"..." KPI stubs) AND the DOM has been stable
            (no mutations) for a short quiet window;
          • network-idle settle: no in-flight requests for the quiet window;
          • cap: max_wait seconds elapsed (hard upper bound — never hangs).

        Returns a short tag describing how it resolved (for the per-line log).
        """
        quiet_ms = 1200          # DOM/network must be still this long to count as "done"
        poll_ms = 300
        deadline = max_wait * 1000
        # Track in-flight requests so we can detect a genuine network lull.
        inflight = {"n": 0, "last_active_ms": 0}
        clock = {"ms": 0}

        def _req(_):
            inflight["n"] += 1
            inflight["last_active_ms"] = clock["ms"]

        def _done(_):
            inflight["n"] = max(0, inflight["n"] - 1)
            inflight["last_active_ms"] = clock["ms"]

        page.on("request", _req)
        page.on("requestfinished", _done)
        page.on("requestfailed", _done)

        # JS probe: count loading sentinels still on the page. Mirrors the dashboard
        # idioms (class "empty"/"loading"/"skeleton"/"spinner", literal "loading…",
        # bare "—"/"..." stubs) so "content arrived" is observable, not guessed.
        sentinel_js = r"""() => {
            const sel = '.empty,.loading,.skeleton,.spinner,[aria-busy="true"]';
            let n = document.querySelectorAll(sel).length;
            const txt = (document.body && document.body.innerText) || '';
            // count visible loading words (cheap; bounded)
            const m = txt.match(/loading[…\.]*|chargement/gi);
            if (m) n += m.length;
            return n;
        }"""

        last_html_len = -1
        stable_since = None
        prev_sentinels = None
        try:
            while clock["ms"] < deadline:
                await page.wait_for_timeout(poll_ms)
                clock["ms"] += poll_ms

                try:
                    sentinels = await page.evaluate(sentinel_js)
                    html_len = await page.evaluate("() => document.body ? document.body.innerHTML.length : 0")
                except Exception:
                    sentinels, html_len = 0, last_html_len

                net_quiet = (inflight["n"] == 0 and
                             clock["ms"] - inflight["last_active_ms"] >= quiet_ms)
                dom_stable = (html_len == last_html_len and sentinels == prev_sentinels)

                if dom_stable and net_quiet:
                    if stable_since is None:
                        stable_since = clock["ms"]
                    elif clock["ms"] - stable_since >= quiet_ms:
                        # Settled. content-ready if no sentinels remain.
                        return f"ready {clock['ms']//1000}s" if sentinels == 0 else f"settled {clock['ms']//1000}s"
                else:
                    stable_since = None

                last_html_len = html_len
                prev_sentinels = sentinels

            return f"cap {max_wait}s"
        finally:
            page.remove_listener("request", _req)
            page.remove_listener("requestfinished", _done)
            page.remove_listener("requestfailed", _done)

    def _create_thumbnail(self, src_path: Path, thumb_path: Path, size: tuple = (400, 225)):
        """Create thumbnail from screenshot."""
        if not PILLOW_AVAILABLE:
            return
        try:
            from PIL import Image as PILImage
            img = PILImage.open(src_path)
            img.thumbnail(size, PILImage.Resampling.LANCZOS)
            img.save(thumb_path, "PNG", optimize=True)
        except Exception as e:
            print(f"    Thumbnail error: {e}")

    async def capture_all(self, modules: list[dict], headless: bool = True):
        """Capture screenshots from all modules."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=headless)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )

            # With a pre-minted JWT, seed localStorage on EVERY document before its
            # own scripts run (init-script fires pre-load on each navigation), so the
            # dashboard boots already-authenticated on first paint — more robust than
            # a one-shot setItem that a redirect/clear could drop. Keys mirror the
            # frontend (sbx_token primary, secubox_token legacy, sbx_user).
            if self.token:
                await context.add_init_script(
                    "try{localStorage.setItem('sbx_token',%r);"
                    "localStorage.setItem('secubox_token',%r);"
                    "localStorage.setItem('sbx_user',%r);}catch(e){}"
                    % (self.token, self.token, self.username)
                )

            page = await context.new_page()

            print("=" * 80)
            print("SecuBox Module Screenshots Capture")
            print("=" * 80)
            print(f"Base URL:    {self.base_url}")
            print(f"Output:      {self.output_dir}")
            print(f"Thumbnails:  {self.thumb_dir}")
            print(f"Modules:     {len(modules)}")
            print("=" * 80)
            print()

            # Login first
            await self.login(page)
            print()

            # Capture each module
            for i, module in enumerate(modules, 1):
                result = await self.capture_module(page, module, i, len(modules))
                self.results.append(result)
                # Small delay to prevent navigation conflicts
                await page.wait_for_timeout(200)

            await browser.close()

        # Generate manifest
        self._save_manifest()
        self._print_summary()

    def _save_manifest(self):
        """Save JSON manifest of captured screenshots."""
        manifest_path = self.output_dir / "capture-manifest.json"

        manifest = {
            "generated": datetime.now().isoformat(),
            "base_url": self.base_url,
            "total_modules": len(self.results),
            "successful": sum(1 for r in self.results if r.success),
            "failed": sum(1 for r in self.results if not r.success),
            "modules": [r.to_dict() for r in self.results],
        }

        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)

        print(f"\nManifest saved to: {manifest_path}")

    def _print_summary(self):
        """Print capture summary."""
        successful = sum(1 for r in self.results if r.success)
        failed = sum(1 for r in self.results if not r.success)

        print()
        print("=" * 80)
        print("Summary")
        print("=" * 80)
        print(f"Total:      {len(self.results)}")
        print(f"Successful: {successful}")
        print(f"Failed:     {failed}")

        if failed > 0:
            print()
            print("Failed modules:")
            for r in self.results:
                if not r.success:
                    print(f"  - {r.module_id}: {r.error}")

        # Group by category
        print()
        print("By category:")
        categories = {}
        for r in self.results:
            if r.category not in categories:
                categories[r.category] = {"success": 0, "failed": 0}
            if r.success:
                categories[r.category]["success"] += 1
            else:
                categories[r.category]["failed"] += 1

        for cat, counts in sorted(categories.items()):
            print(f"  {cat:20s}: {counts['success']:3d} OK, {counts['failed']:3d} failed")


def generate_thumbnails_only(screenshots_dir: Path, thumb_dir: Path, size: tuple = (400, 225)):
    """Generate thumbnails from existing screenshots."""
    if not PILLOW_AVAILABLE:
        print("ERROR: Pillow not installed. Run: pip install Pillow")
        return

    from PIL import Image as PILImage

    thumb_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating thumbnails from {screenshots_dir}")

    count = 0
    for png in screenshots_dir.glob("*.png"):
        if png.name == "capture-manifest.json":
            continue

        thumb_path = thumb_dir / f"{png.stem}-thumb.png"
        try:
            img = PILImage.open(png)
            img.thumbnail(size, PILImage.Resampling.LANCZOS)
            img.save(thumb_path, "PNG", optimize=True)
            print(f"  {png.name} -> {thumb_path.name}")
            count += 1
        except Exception as e:
            print(f"  {png.name}: ERROR {e}")

    print(f"\nGenerated {count} thumbnails")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Capture screenshots of SecuBox modules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Capture all modules
    python scripts/capture-screenshots.py --base-url https://192.168.1.200

    # Capture specific modules
    python scripts/capture-screenshots.py --modules hub,soc,crowdsec

    # Generate thumbnails only
    python scripts/capture-screenshots.py --thumbnails-only

    # Use custom credentials
    SECUBOX_PASSWORD=mypassword python scripts/capture-screenshots.py
        """,
    )

    parser.add_argument(
        "--base-url",
        default="https://localhost:9443",
        help="SecuBox base URL (default: https://localhost:9443)",
    )
    parser.add_argument(
        "--output-dir",
        default="docs/screenshots/vm",
        help="Screenshot output directory (default: docs/screenshots/vm)",
    )
    parser.add_argument(
        "--thumb-dir",
        default="docs/screenshots/thumbnails",
        help="Thumbnail output directory (default: docs/screenshots/thumbnails)",
    )
    parser.add_argument(
        "--modules",
        help="Comma-separated list of module IDs to capture (default: all)",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="Login username (default: admin)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Pre-minted JWT (bypass password login); injected into localStorage. "
             "Falls back to $SECUBOX_TOKEN.",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run browser in headed mode (visible)",
    )
    parser.add_argument(
        "--thumbnails-only",
        action="store_true",
        help="Generate thumbnails from existing screenshots only",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=30,
        help="UPPER BOUND (seconds) per page; capture fires as soon as content is "
             "rendered + network settles, this is just the cap (default: 30)",
    )

    args = parser.parse_args()

    # Thumbnails only mode
    if args.thumbnails_only:
        generate_thumbnails_only(
            Path(args.output_dir),
            Path(args.thumb_dir),
        )
        return

    # Discover modules
    base_dir = Path(__file__).parent.parent
    packages_dir = base_dir / "packages"

    all_modules = discover_modules(packages_dir)
    print(f"Discovered {len(all_modules)} modules from packages/")

    # Filter modules if specified
    if args.modules:
        requested = set(args.modules.split(","))
        modules = [m for m in all_modules if m["id"] in requested]
        print(f"Filtering to {len(modules)} requested modules")
    else:
        modules = all_modules

    if not modules:
        print("No modules to capture")
        return

    # Capture screenshots
    capture = ScreenshotCapture(
        base_url=args.base_url,
        output_dir=args.output_dir,
        thumb_dir=args.thumb_dir,
        username=args.username,
        page_delay=args.delay,
        token=args.token,
    )

    asyncio.run(capture.capture_all(modules, headless=not args.headed))


if __name__ == "__main__":
    main()
