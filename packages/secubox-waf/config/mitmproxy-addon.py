# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox WAF Addon for mitmproxy - Graduated Response Mode

Progressive threat response:
1. First detection -> Warning page (not block)
2. Multiple attempts (3+) -> Auto-ban via CrowdSec

Features:
- Pattern-based threat detection (SQLi, XSS, LFI, RCE, etc.)
- Warning page on initial detection
- Threat logging to /data/mitmproxy/logs/waf-threats.log
- Auto-ban after threshold reached
"""
import json
import re
import subprocess
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from mitmproxy import http, ctx

ROUTES_FILE = Path("/data/mitmproxy/haproxy-routes.json")
RULES_FILE = Path("/data/mitmproxy/waf-rules.json")
THREATS_LOG = Path("/data/mitmproxy/logs/waf-threats.log")
WHITELIST = {"127.0.0.1", "192.168.255.1", "10.100.0.1"}

# Graduated response thresholds
BAN_THRESHOLD = 3  # Number of threats before ban
BAN_WINDOW = 300   # Window in seconds (5 min)

WARNING_PAGE = b"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox WAF - Security Alert</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a0a0f 100%);
            color: #e8e6d9;
            font-family: "JetBrains Mono", monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            text-align: center;
            padding: 2rem;
            max-width: 800px;
        }
        .alert-icon {
            font-size: 6rem;
            margin-bottom: 1.5rem;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
        }
        h1 {
            color: #e63946;
            font-size: 2.5rem;
            margin-bottom: 1rem;
            text-shadow: 0 0 20px rgba(230, 57, 70, 0.5);
        }
        .warning-box {
            background: rgba(230, 57, 70, 0.1);
            border: 2px solid #e63946;
            border-radius: 12px;
            padding: 2rem;
            margin: 2rem 0;
        }
        .warning-text {
            color: #e63946;
            font-size: 1.2rem;
            margin-bottom: 1rem;
        }
        .details {
            color: #6b6b7a;
            font-size: 0.9rem;
            margin-top: 1rem;
        }
        .license-box {
            background: rgba(201, 168, 76, 0.1);
            border: 1px solid #c9a84c;
            border-radius: 8px;
            padding: 1.5rem;
            margin-top: 2rem;
            text-align: left;
        }
        .license-title {
            color: #c9a84c;
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }
        .license-text {
            color: #6b6b7a;
            font-size: 0.75rem;
            line-height: 1.5;
        }
        .counter {
            color: #00ff41;
            font-size: 1.5rem;
            margin-top: 1rem;
        }
        .footer {
            margin-top: 2rem;
            color: #6b6b7a;
            font-size: 0.8rem;
        }
        .footer a { color: #c9a84c; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="alert-icon">&#x26A0;&#xFE0F;</div>
        <h1>SECURITY ALERT</h1>
        <div class="warning-box">
            <p class="warning-text">&#x1F6A8; Suspicious Activity Detected</p>
            <p>Your request contains patterns that match known attack signatures.</p>
            <p class="details">This incident has been logged and your IP address recorded.</p>
            <p class="counter">Warnings: <span id="count">{count}</span> / {threshold}</p>
        </div>
        <div class="license-box">
            <p class="license-title">&#x1F4DC; SecuBox Security Notice</p>
            <p class="license-text">
                This system is protected by SecuBox WAF (Web Application Firewall).<br>
                All access attempts are monitored, logged, and may be reported to authorities.<br>
                Continued malicious activity will result in automatic IP ban.<br><br>
                &copy; 2024-2026 CyberMind Security Platform<br>
                ANSSI CSPN Candidate | https://secubox.in
            </p>
        </div>
        <p class="footer">
            Protected by <a href="https://cybermind.fr">CyberMind</a> |
            <a href="https://secubox.in">SecuBox</a>
        </p>
    </div>
</body>
</html>"""

class SecuBoxWAF:
    def __init__(self):
        self.routes = {}
        self.compiled_patterns = {}
        self.stats = {"requests": 0, "warnings": 0, "blocked": 0}
        self.threat_counts = defaultdict(list)  # IP -> list of timestamps
        self.load_routes()
        self.load_rules()
        THREATS_LOG.parent.mkdir(parents=True, exist_ok=True)

    def load_routes(self):
        if ROUTES_FILE.exists():
            try:
                self.routes = json.loads(ROUTES_FILE.read_text())
                ctx.log.info(f"Loaded {len(self.routes)} routes")
            except Exception as e:
                ctx.log.error(f"Failed to load routes: {e}")

    def load_rules(self):
        if RULES_FILE.exists():
            try:
                data = json.loads(RULES_FILE.read_text())
                categories = data.get("categories", {})
                total = 0
                for cat_id, cat_data in categories.items():
                    if not cat_data.get("enabled", True):
                        continue
                    patterns = []
                    for rule in cat_data.get("patterns", []):
                        try:
                            compiled = re.compile(rule["pattern"], re.IGNORECASE)
                            patterns.append({
                                "id": rule["id"],
                                "regex": compiled,
                                "desc": rule.get("desc", ""),
                                "severity": cat_data.get("severity", "medium")
                            })
                            total += 1
                        except re.error:
                            pass
                    self.compiled_patterns[cat_id] = {
                        "name": cat_data.get("name", cat_id),
                        "severity": cat_data.get("severity", "medium"),
                        "patterns": patterns
                    }
                ctx.log.info(f"Loaded {total} WAF rules in {len(self.compiled_patterns)} categories")
            except Exception as e:
                ctx.log.error(f"Failed to load WAF rules: {e}")

    def check_request(self, flow: http.HTTPFlow):
        """Check request against WAF rules."""
        raw_query = flow.request.query.to_dict() if flow.request.query else {}
        query_str = " ".join(f"{k}={v}" for k, v in raw_query.items())

        path = urllib.parse.unquote_plus(flow.request.path)
        query = urllib.parse.unquote_plus(query_str)
        body = flow.request.get_text() or ""
        ua = flow.request.headers.get("User-Agent", "")

        scan_text = f"{path} {query} {body} {ua}".lower()

        for cat_id, cat_data in self.compiled_patterns.items():
            for pattern in cat_data["patterns"]:
                if pattern["regex"].search(scan_text):
                    return {
                        "category": cat_id,
                        "rule_id": pattern["id"],
                        "description": pattern["desc"],
                        "severity": pattern["severity"]
                    }
        return None

    def get_threat_count(self, ip: str) -> int:
        """Get threat count for IP within window."""
        now = datetime.now()
        cutoff = now - timedelta(seconds=BAN_WINDOW)
        self.threat_counts[ip] = [t for t in self.threat_counts[ip] if t > cutoff]
        return len(self.threat_counts[ip])

    def add_threat(self, ip: str):
        """Record threat for IP."""
        self.threat_counts[ip].append(datetime.now())

    def log_threat(self, flow: http.HTTPFlow, threat: dict, action: str):
        """Log threat to file."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else "unknown",
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "path": flow.request.path,
            "category": threat["category"],
            "rule_id": threat["rule_id"],
            "severity": threat["severity"],
            "description": threat["description"],
            "action": action
        }
        try:
            with open(THREATS_LOG, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            ctx.log.error(f"Failed to log threat: {e}")

    def ban_ip(self, ip: str, reason: str):
        """Ban IP via CrowdSec."""
        try:
            subprocess.run([
                "cscli", "decisions", "add",
                "--ip", ip,
                "--type", "ban",
                "--duration", "4h",
                "--reason", f"secubox/waf-{reason}"
            ], capture_output=True, timeout=5)
            ctx.log.warn(f"BANNED {ip} for {reason}")
        except Exception:
            pass

    def request(self, flow: http.HTTPFlow):
        self.stats["requests"] += 1
        host = flow.request.pretty_host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

        # Skip whitelist
        if client_ip in WHITELIST:
            if host in self.routes:
                backend_ip, backend_port = self.routes[host]
                flow.request.host = backend_ip
                flow.request.port = backend_port
            return

        # Check for threats
        threat = self.check_request(flow)
        if threat:
            self.add_threat(client_ip)
            count = self.get_threat_count(client_ip)

            sev = threat["severity"]
            cat = threat["category"]
            rid = threat["rule_id"]
            ctx.log.warn(f"THREAT [{sev}] {client_ip} ({count}/{BAN_THRESHOLD}): {cat} {rid}")

            if count >= BAN_THRESHOLD:
                # Ban and block
                self.stats["blocked"] += 1
                self.log_threat(flow, threat, "banned")
                self.ban_ip(client_ip, threat["category"])
                flow.response = http.Response.make(
                    403,
                    b"<h1>403 Forbidden</h1><p>Your IP has been banned.</p>",
                    {"Content-Type": "text/html", "X-SecuBox-WAF": "banned"}
                )
            else:
                # Warning page
                self.stats["warnings"] += 1
                self.log_threat(flow, threat, "warning")
                warning = WARNING_PAGE.replace(b"{count}", str(count).encode())
                warning = warning.replace(b"{threshold}", str(BAN_THRESHOLD).encode())
                flow.response = http.Response.make(
                    403,
                    warning,
                    {"Content-Type": "text/html", "X-SecuBox-WAF": "warning"}
                )
            return

        # Route to backend
        if host in self.routes:
            backend_ip, backend_port = self.routes[host]
            flow.request.host = backend_ip
            flow.request.port = backend_port

    def response(self, flow: http.HTTPFlow):
        if flow.response:
            flow.response.headers["X-SecuBox-WAF"] = "inspected"

addons = [SecuBoxWAF()]
