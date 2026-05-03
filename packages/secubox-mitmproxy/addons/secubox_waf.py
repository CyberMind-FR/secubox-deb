"""SecuBox WAF — Mitmproxy Threat Detection Addon

Inspects HTTP traffic for attack patterns and logs threats to JSONL
for CrowdSec consumption.

Install: Copy to /srv/mitmproxy-waf/addons/
Run: mitmdump -s /addons/secubox_waf.py
"""
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from mitmproxy import http, ctx

# File paths (bind-mounted from host)
DATA_DIR = Path("/data")
THREATS_LOG = DATA_DIR / "threats.log"
ROUTES_FILE = DATA_DIR / "routes.json"
RULES_FILE = DATA_DIR / "waf-rules.json"
STATS_FILE = DATA_DIR / "stats.json"


class SecuBoxWAF:
    """Mitmproxy addon for WAF threat detection and routing."""

    def __init__(self):
        self.routes: Dict[str, tuple] = {}
        self.rules: Dict[str, Any] = {}
        self.stats: Dict[str, int] = {}
        self._load_config()

    def _load_config(self):
        """Load routes and rules from data files."""
        # Load routes
        if ROUTES_FILE.exists():
            try:
                self.routes = json.loads(ROUTES_FILE.read_text())
                ctx.log.info(f"Loaded {len(self.routes)} routes")
            except Exception as e:
                ctx.log.error(f"Failed to load routes: {e}")

        # Load rules
        if RULES_FILE.exists():
            try:
                self.rules = json.loads(RULES_FILE.read_text())
                self.stats = {cat: 0 for cat in self.rules}
                ctx.log.info(f"Loaded {len(self.rules)} rule categories")
            except Exception as e:
                ctx.log.error(f"Failed to load rules: {e}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Process incoming request: detect threats and route to backend."""
        # 1. Check for threats
        threats = self._check_request(flow)

        # 2. Log any detected threats
        for threat in threats:
            self._log_threat(flow, threat)

        # 3. Route to real backend based on Host header
        host = flow.request.host_header
        if host and host in self.routes:
            backend = self.routes[host]
            if isinstance(backend, list) and len(backend) >= 2:
                flow.request.host = backend[0]
                flow.request.port = backend[1]

    def _check_request(self, flow: http.HTTPFlow) -> List[Dict]:
        """Check request against all enabled rule categories."""
        threats = []

        # Build target string from path and query
        path = flow.request.path or ""
        query = flow.request.query.decode("utf-8", errors="ignore") if flow.request.query else ""
        target = f"{path}?{query}" if query else path

        # Also check headers and body for some patterns
        user_agent = flow.request.headers.get("User-Agent", "")

        for category, config in self.rules.items():
            if not config.get("enabled", True):
                continue

            patterns = config.get("patterns", [])
            severity = config.get("severity", "medium")

            for pattern in patterns:
                regex = pattern.get("regex", "")
                name = pattern.get("name", "unknown")

                try:
                    # Check URL path/query
                    match = re.search(regex, target, re.IGNORECASE)

                    # For scanner detection, also check User-Agent
                    if not match and category == "scanners":
                        match = re.search(regex, user_agent, re.IGNORECASE)

                    if match:
                        threats.append({
                            "category": category,
                            "severity": severity,
                            "pattern": name,
                            "matched": match.group(0)[:100]  # Limit matched text
                        })
                        self.stats[category] = self.stats.get(category, 0) + 1
                        break  # One match per category is enough

                except re.error as e:
                    ctx.log.warn(f"Invalid regex in {category}/{name}: {e}")

        return threats

    def _log_threat(self, flow: http.HTTPFlow, threat: Dict) -> None:
        """Write threat to JSONL log for CrowdSec consumption."""
        try:
            # Get client IP
            client_ip = "unknown"
            if flow.client_conn and flow.client_conn.peername:
                client_ip = flow.client_conn.peername[0]

            entry = {
                "ts": time.time(),
                "ip": client_ip,
                "host": flow.request.host_header or "unknown",
                "path": flow.request.path or "/",
                "method": flow.request.method,
                "category": threat["category"],
                "severity": threat["severity"],
                "pattern": threat["pattern"],
                "matched": threat["matched"]
            }

            with THREATS_LOG.open("a") as f:
                f.write(json.dumps(entry) + "\n")

            ctx.log.warn(f"THREAT: {threat['category']} from {client_ip} - {threat['pattern']}")

        except Exception as e:
            ctx.log.error(f"Failed to log threat: {e}")

    def done(self):
        """Called when mitmproxy shuts down — save stats."""
        try:
            STATS_FILE.write_text(json.dumps(self.stats, indent=2))
        except Exception as e:
            ctx.log.error(f"Failed to save stats: {e}")


# Register addon
addons = [SecuBoxWAF()]
