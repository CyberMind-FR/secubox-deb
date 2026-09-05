# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""SecuBox WAF Addon for mitmproxy - Graduated Response Mode

Progressive threat response:
1. First detection → Warning page (not block)
2. Multiple attempts (3+) → Auto-ban (inline 403 block)

Features:
- Pattern-based threat detection (SQLi, XSS, LFI, RCE, etc.)
- Warning page on initial detection
- Threat logging to /data/mitmproxy/logs/waf-threats.log
- Auto-ban after threshold reached
- Styled error pages for backend failures (502/503)
"""
import json
import re
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from mitmproxy import http, ctx

ROUTES_FILE = Path("/data/mitmproxy/haproxy-routes.json")
RULES_FILE = Path("/data/mitmproxy/waf-rules.json")
THREATS_LOG = Path("/data/mitmproxy/logs/waf-threats.log")
STATS_FILE = Path("/data/mitmproxy/logs/waf-stats.json")
CDN_CONFIG_FILE = Path("/data/mitmproxy/cdn-config.json")
WHITELIST = {"127.0.0.1", "192.168.255.1"}
# Trusted networks bypass the WAF entirely: loopback + RFC1918 (the LAN and the
# internal LXC bridge). The WAF protects against EXTERNAL probes; LAN operators
# must never be banned (e.g. a logout request matching a rule). CIDR-aware.
import ipaddress as _ipaddr
_WL_NETS = []
for _c in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"):
    try:
        _WL_NETS.append(_ipaddr.ip_network(_c))
    except ValueError:
        pass

def _is_whitelisted(ip):
    if ip in WHITELIST:
        return True
    try:
        addr = _ipaddr.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _WL_NETS)

STATS_SAVE_INTERVAL = 100  # Save stats every N requests

# CDN Options (loaded from cdn-config.json)
CDN_OPTIONS = {
    "banner_injection": True,
    "banner_url": "https://admin.gk2.secubox.in/shared/health-banner.js",
    "banner_api_url": "https://admin.gk2.secubox.in/api/v1/metrics/health/summary",
    "inject_domains": ["*"],  # ["*"] = all, or list specific domains
    "exclude_domains": [],    # Domains to exclude from injection
}

def load_cdn_config():
    """Load CDN configuration from file."""
    global CDN_OPTIONS
    if CDN_CONFIG_FILE.exists():
        try:
            with open(CDN_CONFIG_FILE) as f:
                loaded = json.load(f)
                CDN_OPTIONS.update(loaded)
        except Exception as e:
            pass  # Use defaults
    return CDN_OPTIONS

def save_cdn_config():
    """Save CDN configuration to file."""
    try:
        CDN_CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CDN_CONFIG_FILE, "w") as f:
            json.dump(CDN_OPTIONS, f, indent=2)
    except Exception:
        pass

# Graduated response thresholds
BAN_THRESHOLD = 3  # Number of threats before ban
BAN_WINDOW = 300   # Window in seconds (5 min)

# Trusted proxy IPs (HAProxy, Docker bridge)
TRUSTED_PROXIES = {"10.100.0.1", "127.0.0.1", "172.17.0.1", "192.168.255.1"}

# Hosts that resolve to the box itself. When a client targets one of
# these by literal IP and the Host is NOT in haproxy-routes.json, the
# request would loop forever through HAProxy default_backend ->
# mitmproxy -> HAProxy. The pre-route guard in request() rewrites such
# requests to host nginx (9080) so a sensible vhost answers instead of
# the WAF's 508 loop-detected page. Update this set if a new gk2-side
# interface gets a routable IP that a browser could reach by literal.
SELF_HOSTS = {
    "127.0.0.1",
    "192.168.1.200",   # lan0 — main LAN
    "192.168.255.1",   # lan3 / lo — admin VLAN
    "10.100.0.1",      # br-lxc — LXC bridge gateway
    "10.55.0.1",       # eye-br0 — Eye Remote bridge
}

def get_real_client_ip(flow: http.HTTPFlow) -> str:
    """Extract real client IP from X-Forwarded-For or X-Real-IP headers.

    Falls back to direct connection IP if no proxy headers found.
    """
    peer_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"

    # Check X-Forwarded-For first (may contain chain: client, proxy1, proxy2)
    xff = flow.request.headers.get("X-Forwarded-For", "")
    if xff:
        # Take the first IP in the chain (original client)
        ips = [ip.strip() for ip in xff.split(",")]
        for ip in ips:
            if ip and ip not in TRUSTED_PROXIES:
                ctx.log.info(f"[IP] XFF={xff} -> real={ip} (peer={peer_ip})")
                return ip

    # Check X-Real-IP
    xri = flow.request.headers.get("X-Real-IP", "")
    if xri and xri not in TRUSTED_PROXIES:
        ctx.log.info(f"[IP] XRI={xri} -> real={xri} (peer={peer_ip})")
        return xri.strip()

    # Fallback to direct connection - log ALL headers for debugging
    all_headers = dict(flow.request.headers)
    ctx.log.warn(f"[IP-DEBUG] peer={peer_ip} headers={all_headers}")
    return peer_ip

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

ERROR_502_PAGE = b"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>502 - Service Unavailable | SecuBox</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0f 0%, #0f0a1a 100%);
            color: #e8e6d9;
            font-family: "JetBrains Mono", "Courier New", monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1rem;
        }
        .container {
            text-align: center;
            max-width: 700px;
            width: 100%;
        }
        .ascii-art {
            font-size: clamp(6px, 1.2vw, 10px);
            line-height: 1.15;
            color: #6e40c9;
            text-shadow: 0 0 15px rgba(110, 64, 201, 0.5);
            white-space: pre;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        .error-code {
            font-size: clamp(4rem, 12vw, 7rem);
            font-weight: bold;
            color: #6e40c9;
            text-shadow: 0 0 30px rgba(110, 64, 201, 0.6);
            line-height: 1;
            margin-bottom: 0.5rem;
            animation: flicker 3s infinite;
        }
        @keyframes flicker {
            0%, 100% { opacity: 1; }
            92% { opacity: 1; }
            93% { opacity: 0.8; }
            94% { opacity: 1; }
            96% { opacity: 0.9; }
            97% { opacity: 1; }
        }
        .error-title {
            font-size: clamp(1.2rem, 3vw, 1.6rem);
            color: #c9a84c;
            margin-bottom: 1.5rem;
        }
        .error-box {
            background: rgba(110, 64, 201, 0.1);
            border: 1px solid rgba(110, 64, 201, 0.3);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1.5rem 0;
        }
        .error-message {
            color: #8b949e;
            font-size: 1rem;
            line-height: 1.6;
        }
        .error-message code {
            background: rgba(110, 64, 201, 0.2);
            padding: 2px 8px;
            border-radius: 4px;
            color: #c9a84c;
            font-size: 0.9em;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .status-item {
            background: rgba(30, 30, 40, 0.5);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem;
        }
        .status-label {
            font-size: 0.75rem;
            color: #6b6b7a;
            text-transform: uppercase;
            letter-spacing: 0.1em;
        }
        .status-value {
            font-size: 1rem;
            color: #e8e6d9;
            margin-top: 0.3rem;
        }
        .status-value.down { color: #e63946; }
        .status-value.checking { color: #c9a84c; }
        .actions {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 2rem;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #6e40c9;
            color: white;
            border: none;
        }
        .btn-primary:hover { background: #8250df; }
        .btn-secondary {
            background: transparent;
            color: #8b949e;
            border: 1px solid #30363d;
        }
        .btn-secondary:hover {
            border-color: #6e40c9;
            color: #c9a84c;
        }
        .footer {
            margin-top: 3rem;
            font-size: 0.75rem;
            color: #6b6b7a;
        }
        .footer a { color: #c9a84c; text-decoration: none; }
        .retry-timer {
            color: #00ff41;
            font-size: 0.9rem;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="ascii-art">
 _____ _____ _____    _____         _               
|   __|  |  |___  |  |   __|___ ___|_|___ ___       
|__   |  |  |  _  |  |__   | -_|  _| | . |   |      
|_____|_____|_____|  |_____|___|_|  |_|___|_|_|     
                                                    
    +-----------------------------------------------+
    |  The backend service is temporarily offline  |
    |                                               |
    |     [ Retrying connection... ]               |
    |                                               |
    +-----------------------------------------------+
        </div>

        <div class="error-code">502</div>
        <h1 class="error-title">Bad Gateway</h1>

        <div class="error-box">
            <p class="error-message">
                The upstream server <code>{host}</code> is not responding.<br>
                This could be due to maintenance, high load, or a service restart.
            </p>
        </div>

        <div class="status-grid">
            <div class="status-item">
                <div class="status-label">Backend</div>
                <div class="status-value down">{host}</div>
            </div>
            <div class="status-item">
                <div class="status-label">WAF Status</div>
                <div class="status-value" style="color: #00ff41;">Active</div>
            </div>
            <div class="status-item">
                <div class="status-label">Time</div>
                <div class="status-value">{time}</div>
            </div>
        </div>

        <p class="retry-timer">Auto-retry in <span id="countdown">10</span>s...</p>

        <div class="actions">
            <a href="javascript:location.reload()" class="btn btn-primary">Retry Now</a>
            <a href="/" class="btn btn-secondary">Go Home</a>
        </div>

        <p class="footer">
            SecuBox WAF | <a href="https://secubox.in">secubox.in</a> | 
            <a href="https://cybermind.fr">CyberMind</a>
        </p>
    </div>

    <script>
    (function() {
        let seconds = 10;
        const el = document.getElementById('countdown');
        const timer = setInterval(() => {
            seconds--;
            el.textContent = seconds;
            if (seconds <= 0) {
                clearInterval(timer);
                location.reload();
            }
        }, 1000);
    })();
    </script>
</body>
</html>"""

ERROR_503_PAGE = b"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>503 - Service Unavailable | SecuBox</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a0f0a 100%);
            color: #e8e6d9;
            font-family: "JetBrains Mono", "Courier New", monospace;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1rem;
        }
        .container {
            text-align: center;
            max-width: 700px;
            width: 100%;
        }
        .ascii-art {
            font-size: clamp(6px, 1.2vw, 10px);
            line-height: 1.15;
            color: #c9a84c;
            text-shadow: 0 0 15px rgba(201, 168, 76, 0.5);
            white-space: pre;
            margin-bottom: 2rem;
            overflow: hidden;
        }
        .error-code {
            font-size: clamp(4rem, 12vw, 7rem);
            font-weight: bold;
            color: #c9a84c;
            text-shadow: 0 0 30px rgba(201, 168, 76, 0.6);
            line-height: 1;
            margin-bottom: 0.5rem;
        }
        .error-title {
            font-size: clamp(1.2rem, 3vw, 1.6rem);
            color: #e63946;
            margin-bottom: 1.5rem;
        }
        .maintenance-box {
            background: rgba(201, 168, 76, 0.1);
            border: 1px solid rgba(201, 168, 76, 0.3);
            border-radius: 12px;
            padding: 2rem;
            margin: 1.5rem 0;
        }
        .maintenance-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            animation: spin 3s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .error-message {
            color: #8b949e;
            font-size: 1rem;
            line-height: 1.6;
        }
        .actions {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 2rem;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.9rem;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #c9a84c;
            color: #0a0a0f;
            border: none;
        }
        .btn-primary:hover { background: #d4b85c; }
        .btn-secondary {
            background: transparent;
            color: #8b949e;
            border: 1px solid #30363d;
        }
        .btn-secondary:hover {
            border-color: #c9a84c;
            color: #c9a84c;
        }
        .footer {
            margin-top: 3rem;
            font-size: 0.75rem;
            color: #6b6b7a;
        }
        .footer a { color: #c9a84c; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="ascii-art">
 _____ _____ _____    _____     _     _                         
|   __|  |  |___  |  |     |___|_|___| |_ ___ ___ ___ ___ ___ ___ 
|__   |  |  |  _  |  | | | | .'| |   |  _| -_|   | .'|   |  _| -_|
|_____|_____|_____|  |_|_|_|__,|_|_|_|_| |___|_|_|__,|_|_|___|___|
                                                                  
    +-----------------------------------------------+
    |       Service temporarily unavailable        |
    |                                               |
    |  The hamsters powering this service need     |
    |  a quick coffee break. Back soon!            |
    +-----------------------------------------------+
        </div>

        <div class="error-code">503</div>
        <h1 class="error-title">Service Unavailable</h1>

        <div class="maintenance-box">
            <div class="maintenance-icon">&#x2699;&#xFE0F;</div>
            <p class="error-message">
                We're currently performing maintenance or experiencing high load.<br>
                Please try again in a few moments.
            </p>
        </div>

        <div class="actions">
            <a href="javascript:location.reload()" class="btn btn-primary">Try Again</a>
            <a href="/" class="btn btn-secondary">Go Home</a>
        </div>

        <p class="footer">
            SecuBox WAF | <a href="https://secubox.in">secubox.in</a> | 
            <a href="https://cybermind.fr">CyberMind</a>
        </p>
    </div>
</body>
</html>"""

class SecuBoxWAF:
    def __init__(self):
        self.routes = {}
        self._routes_mtime = 0.0
        self._last_route_check = 0.0
        self.compiled_patterns = {}
        self.stats = {"requests": 0, "warnings": 0, "blocked": 0, "errors": 0}
        self.threat_counts = defaultdict(list)  # IP -> list of timestamps
        self.load_routes()
        self.load_rules()
        THREATS_LOG.parent.mkdir(parents=True, exist_ok=True)
    
    def save_stats(self):
        """Save stats to file for external access."""
        try:
            stats_data = {
                **self.stats,
                "passed": self.stats["requests"] - self.stats["blocked"] - self.stats["warnings"],
                "updated_at": datetime.now().isoformat(),
                "routes_count": len(self.routes)
            }
            STATS_FILE.write_text(json.dumps(stats_data, indent=2))
        except Exception as e:
            ctx.log.warn(f"Failed to save stats: {e}")

    def load_routes(self):
        if ROUTES_FILE.exists():
            try:
                self.routes = json.loads(ROUTES_FILE.read_text())
                sfx = set()
                for _h in self.routes:
                    _p = _h.split('.')
                    if len(_p) >= 2 and not _p[-1].isdigit():
                        sfx.add('.'.join(_p[-2:]))
                self.local_suffixes = sfx
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
    
    def check_request(self, flow: http.HTTPFlow) -> dict | None:
        """Check request against WAF rules."""
        # Skip trusted internal services
        host = flow.request.pretty_host
        if host in ("git.gk2.secubox.in", "git.secubox.in", "10.100.0.1:9080", "admin.gk2.secubox.in"):
            return None
        # Fast path: skip static assets and health checks (no WAF check needed)
        path_lower = flow.request.path.lower()
        if any(path_lower.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map")):
            return None
        if "/health" in path_lower or "/status" in path_lower or "system_health" in path_lower:
            return None
        raw_query = dict(flow.request.query) if flow.request.query else {}
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
        # Debug: log raw header values
        xff = flow.request.headers.get("X-Forwarded-For", "")
        xri = flow.request.headers.get("X-Real-IP", "")
        entry = {
            "timestamp": datetime.now().isoformat(),
            "client_ip": get_real_client_ip(flow),
            "_debug_xff": xff,
            "_debug_xri": xri,
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
        """Record a WAF ban decision.

        The offending request is already blocked in-line with a 403 response
        (handled in the request hook). No external ban backend is configured,
        so this only records the event in the WAF log and stats counters.
        """
        self.stats["bans"] = self.stats.get("bans", 0) + 1
        ctx.log.warn(f"BANNED {ip} for {reason} (WAF 403 inline block)")
    
    def _maybe_reload_routes(self):
        # #609 — live-reload haproxy-routes.json when it changes (throttled
        # 10 s) so haproxyctl route edits take effect with NO restart. Pairs
        # with the directory bind-mount that makes mv-replaced files visible.
        import os as _o, time as _t
        now = _t.time()
        if now - getattr(self, "_last_route_check", 0) < 10:
            return
        self._last_route_check = now
        try:
            m = _o.path.getmtime(str(ROUTES_FILE))
        except OSError:
            return
        if m != getattr(self, "_routes_mtime", 0):
            self._routes_mtime = m
            self.load_routes()
            try:
                ctx.log.info(f"[routes] live-reloaded {len(self.routes)} routes")
            except Exception:
                pass

    def requestheaders(self, flow: http.HTTPFlow):
        self._maybe_reload_routes()
        # #605 — mitmproxy 11 opens the upstream connection before request(),
        # so routing must happen here. ALSO: in --mode regular mitmproxy is a
        # forward proxy that would relay ANY Host, so internet scanners abused
        # it as an open proxy (~70% error churn + self-loops). Serve ONLY our
        # own vhosts: mapped (routes), our domains (-> nginx catch-all), or our
        # own IPs; refuse everything else with 421 and never open an upstream.
        try:
            host = flow.request.pretty_host
            if host in self.routes:
                bip, bport = self.routes[host]
                orig = flow.request.headers.get('Host', host)
                flow.request.host = bip
                flow.request.port = bport
                try:
                    flow.server_conn.address = (bip, bport)
                except Exception:
                    pass
                flow.request.headers['Host'] = orig
                return
            if host in SELF_HOSTS or self._is_local_host(host):
                flow.request.host = '192.168.1.200'
                flow.request.port = 9080
                try:
                    flow.server_conn.address = ('192.168.1.200', 9080)
                except Exception:
                    pass
                return
            self.stats['blocked'] = self.stats.get('blocked', 0) + 1
            flow.response = http.Response.make(
                421,
                b'<h1>421 Misdirected Request</h1><p>SecuBox WAF does not proxy this host.</p>',
                {'Content-Type': 'text/html', 'X-SecuBox-WAF': 'unmapped-host'},
            )
        except Exception as e:
            ctx.log.warn(f'[requestheaders-route] {e}')

    def _is_local_host(self, host: str) -> bool:
        # #605 — is `host` one of our own (registrable) domains? Derived from
        # the routed hosts in load_routes (self.local_suffixes).
        sfx = getattr(self, 'local_suffixes', None)
        if not sfx:
            return False
        return any(host == s or host.endswith('.' + s) for s in sfx)

    def request(self, flow: http.HTTPFlow):
        # Connection close (Phase 6.J leak fix, ref #496) — prevents mitmproxy
        # from accumulating idle keep-alive sockets to upstream backends.
        # Without this, the per-server connection pool grows ~1 entry per
        # unique upstream host and never shrinks; after a few hours we
        # observed 1500+ FDs, 800+ ESTAB sockets, worker queue saturation,
        # HAProxy timeouts → HTTP 504 on every WAF-routed vhost.
        # Cost : 1 TCP handshake per request to upstream (~1ms loopback).
        flow.request.headers["Connection"] = "close"

        # Pre-route guard: a Host header that is one of this box's own
        # listening IPs and is not explicitly mapped in haproxy-routes
        # would loop (HAProxy default_backend mitmproxy_inspector ->
        # mitmproxy -> Host header IP = HAProxy again). Rewrite to host
        # nginx (9080) which has the canonical hub vhost and a sensible
        # default catch-all. Avoids the 508 page the user would
        # otherwise see.
        host_pre = flow.request.pretty_host
        if host_pre in SELF_HOSTS and host_pre not in self.routes:
            ctx.log.info(f"[self-host] rewriting {host_pre} -> nginx 9080 (was unmapped)")
            flow.request.host = "192.168.1.200"
            flow.request.port = 9080
            # Leave Host header intact so nginx can pick a vhost
        # Self-loop guard (last resort): if our own LXC IP appears
        # repeatedly in XFF, we are bouncing through HAProxy
        # default_backend mitmproxy_inspector. Short-circuit with 508
        # so a misrouted Host cannot peg CPU by ping-ponging forever.
        if flow.request.headers.get("X-Forwarded-For", "").count("10.100.0.60") > 2:
            ctx.log.warn(f"[loop] 508 host={host_pre} xff_self_refs="
                         f"{flow.request.headers.get('X-Forwarded-For', '').count('10.100.0.60')} "
                         f"— add {host_pre!r} to haproxy-routes.json or SELF_HOSTS")
            self.stats["blocked"] = self.stats.get("blocked", 0) + 1
            flow.response = http.Response.make(
                508,
                b"<h1>508 Loop Detected</h1><p>SecuBox WAF refused to forward a self-looping request.</p>",
                {"Content-Type": "text/html", "X-SecuBox-WAF": "loop-detected"},
            )
            return
        self.stats["requests"] += 1
        # Periodically save stats
        if self.stats["requests"] % STATS_SAVE_INTERVAL == 0:
            self.save_stats()
        host = flow.request.pretty_host
        client_ip = get_real_client_ip(flow)
        
        # Skip whitelist
        if _is_whitelisted(client_ip):
            if host in self.routes:
                backend_ip, backend_port = self.routes[host]
                original_host = flow.request.headers.get("Host", host)
                flow.request.host = backend_ip
                flow.request.port = backend_port
                flow.request.headers["Host"] = original_host
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
        
        # Route to backend - preserve original Host header for nginx vhost matching
        if host in self.routes:
            backend_ip, backend_port = self.routes[host]
            # Store original host for nginx to match server_name
            original_host = flow.request.headers.get("Host", host)
            flow.request.host = backend_ip
            flow.request.port = backend_port
            # Restore the original Host header so nginx can match the correct server_name
            flow.request.headers["Host"] = original_host
    
    def error(self, flow: http.HTTPFlow):
        """Handle connection errors with styled error pages."""
        self.stats["errors"] += 1
        host = flow.request.pretty_host if flow.request else "unknown"
        now = datetime.now().strftime("%H:%M:%S")
        
        error_msg = str(flow.error) if flow.error else "Unknown error"
        ctx.log.warn(f"Backend error for {host}: {error_msg}")
        
        # Determine error type
        if "Connection refused" in error_msg or "Errno 111" in error_msg:
            # 502 Bad Gateway - backend not responding
            page = ERROR_502_PAGE.replace(b"{host}", host.encode())
            page = page.replace(b"{time}", now.encode())
            flow.response = http.Response.make(
                502,
                page,
                {"Content-Type": "text/html", "X-SecuBox-WAF": "error-502"}
            )
        elif "timed out" in error_msg.lower():
            # 504 Gateway Timeout
            page = ERROR_502_PAGE.replace(b"{host}", host.encode())
            page = page.replace(b"{time}", now.encode())
            page = page.replace(b"502", b"504")
            page = page.replace(b"Bad Gateway", b"Gateway Timeout")
            flow.response = http.Response.make(
                504,
                page,
                {"Content-Type": "text/html", "X-SecuBox-WAF": "error-504"}
            )
        else:
            # 503 Service Unavailable - general error
            flow.response = http.Response.make(
                503,
                ERROR_503_PAGE,
                {"Content-Type": "text/html", "X-SecuBox-WAF": "error-503"}
            )
    
    def response(self, flow: http.HTTPFlow):
        if flow.response:
            flow.response.headers["X-SecuBox-WAF"] = "inspected"

            # CDN Banner Injection - inject health banner into all HTML responses
            cfg = load_cdn_config()
            if cfg.get("banner_injection", True):
                content_type = flow.response.headers.get("Content-Type", "")
                host = flow.request.host or ""

                # Check domain filters
                inject_domains = cfg.get("inject_domains", ["*"])
                exclude_domains = cfg.get("exclude_domains", [])

                should_inject = ("*" in inject_domains or host in inject_domains)
                should_inject = should_inject and (host not in exclude_domains)

                if "text/html" in content_type and flow.response.content and should_inject:
                    try:
                        html = flow.response.content.decode("utf-8", errors="ignore")
                        if "</body>" in html.lower() and "health-banner.js" not in html:
                            # Inject health banner + cookie inventory before </body>
                            banner_url = cfg.get("banner_url", "https://admin.gk2.secubox.in/shared/health-banner.js")
                            api_url = cfg.get("banner_api_url", "https://admin.gk2.secubox.in/api/v1/metrics/health/summary")
                            inventory_url = cfg.get("cookie_inventory_url", "https://admin.gk2.secubox.in/shared/cookie-inventory.js")
                            ingest_url = cfg.get("cookie_audit_ingest_url", "https://admin.gk2.secubox.in/api/v1/cookie-audit/ingest")
                            cookie_summary_url = cfg.get("cookie_audit_summary_url", "https://admin.gk2.secubox.in/api/v1/cookie-audit/summary")
                            banner_script = f'''
<script>
(function(){{
    if(document.getElementById('health-banner'))return;
    window.SECUBOX_HEALTH_API='{api_url}';
    window.SECUBOX_COOKIE_AUDIT_INGEST='{ingest_url}';
    window.SECUBOX_COOKIE_AUDIT_SUMMARY='{cookie_summary_url}';
    var s=document.createElement('script');
    s.src='{banner_url}';
    s.crossOrigin='anonymous';
    s.onerror=function(){{console.warn('[SecuBox] Banner load failed')}};
    document.body.appendChild(s);
    var c=document.createElement('script');
    c.src='{inventory_url}';
    c.crossOrigin='anonymous';
    c.onerror=function(){{console.warn('[SecuBox] Cookie inventory load failed')}};
    document.body.appendChild(c);
}})();
</script>
'''
                            # Case-insensitive replacement
                            html = re.sub(r'(</body>)', banner_script + r'\1', html, flags=re.IGNORECASE)
                            flow.response.content = html.encode("utf-8")
                            flow.response.headers["X-SecuBox-Banner"] = "injected"
                    except Exception as e:
                        ctx.log.warn(f"Banner injection failed: {e}")

    def done(self):
        """Called when mitmproxy shuts down - save final stats."""
        self.save_stats()
        ctx.log.info(f"WAF shutdown - stats: {self.stats}")

addons = [SecuBoxWAF()]
