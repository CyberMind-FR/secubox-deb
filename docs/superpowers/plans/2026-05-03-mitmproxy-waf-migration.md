<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mitmproxy WAF Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the mitmproxy WAF module from SecuBox-OpenWrt to SecuBox-DEB, providing HTTP traffic inspection for HAProxy with threat detection and CrowdSec integration.

**Architecture:** LXC container running mitmproxy with custom threat detection addon. FastAPI manages container lifecycle and serves WebUI. HAProxy routes traffic through the WAF container. Threats logged to JSONL for CrowdSec consumption.

**Tech Stack:** Python 3.11+, FastAPI, LXC, mitmproxy, TOML config, CrowdSec

---

## File Structure

```
packages/secubox-mitmproxy/
├── api/
│   ├── __init__.py              # Package init
│   ├── main.py                  # FastAPI app + health endpoint
│   └── routers/
│       ├── __init__.py          # Router exports
│       ├── status.py            # Container status, start/stop/restart
│       ├── settings.py          # Configuration CRUD
│       ├── alerts.py            # Threat log, stats, bans
│       ├── haproxy.py           # Enable/disable WAF, route sync
│       └── waf.py               # Rule category toggles
├── addons/
│   └── secubox_waf.py           # Mitmproxy threat detection addon
├── bin/
│   └── mitmproxyctl             # Python CLI for LXC management
├── data/
│   └── waf-rules.json           # Default rule definitions
├── www/
│   └── mitmproxy/
│       ├── index.html           # Redirect to status
│       ├── status.html          # Dashboard
│       ├── settings.html        # Configuration form
│       └── filters.html         # WAF rule toggles
├── menu.d/
│   └── 500-mitmproxy.json       # Sidebar menu entry
├── crowdsec/
│   └── secubox-waf.yaml         # CrowdSec acquisition config
├── debian/
│   ├── control                  # Package metadata
│   ├── rules                    # Build rules
│   ├── postinst                 # Post-install script
│   ├── prerm                    # Pre-remove script
│   ├── secubox-mitmproxy.service # Systemd unit
│   └── mitmproxy.toml           # Default config
└── README.md                    # Module documentation
```

---

### Task 1: Package Scaffold and Debian Files

**Files:**
- Create: `packages/secubox-mitmproxy/debian/control`
- Create: `packages/secubox-mitmproxy/debian/rules`
- Create: `packages/secubox-mitmproxy/debian/postinst`
- Create: `packages/secubox-mitmproxy/debian/prerm`
- Create: `packages/secubox-mitmproxy/debian/secubox-mitmproxy.service`
- Create: `packages/secubox-mitmproxy/api/__init__.py`
- Create: `packages/secubox-mitmproxy/api/routers/__init__.py`

- [ ] **Step 1: Create package directory structure**

```bash
mkdir -p packages/secubox-mitmproxy/{api/routers,addons,bin,data,www/mitmproxy,menu.d,crowdsec,debian}
```

- [ ] **Step 2: Create debian/control**

```
Source: secubox-mitmproxy
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox
Rules-Requires-Root: no

Package: secubox-mitmproxy
Architecture: all
Depends: ${misc:Depends},
         secubox-core (>= 1.0),
         secubox-haproxy,
         lxc,
         lxc-templates,
         python3-uvicorn,
         python3-toml
Recommends: secubox-crowdsec
Description: SecuBox Mitmproxy WAF — Web Application Firewall
 HTTP traffic inspection for HAProxy-hosted services with threat
 detection and CrowdSec integration for automatic IP banning.
 .
 Features:
  - LXC-isolated mitmproxy instance
  - 90+ threat detection patterns (SQLi, XSS, RCE, etc.)
  - HAProxy integration for vhost inspection
  - CrowdSec JSONL output for auto-banning
  - WebUI dashboard with real-time stats
 .
 Port Debian bookworm de luci-app-mitmproxy (SecuBox OpenWrt / CyberMind.fr).
```

- [ ] **Step 3: Create debian/rules**

```makefile
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/lib/secubox/mitmproxy
	cp -r api $(CURDIR)/debian/secubox-mitmproxy/usr/lib/secubox/mitmproxy/
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/www
	cp -r www/mitmproxy $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/www/
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/menu.d
	cp menu.d/*.json $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/menu.d/
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/mitmproxy
	cp -r addons $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/mitmproxy/
	cp -r data $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/mitmproxy/
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/sbin
	install -m 755 bin/mitmproxyctl $(CURDIR)/debian/secubox-mitmproxy/usr/sbin/
	install -d $(CURDIR)/debian/secubox-mitmproxy/etc/secubox
	install -m 644 debian/mitmproxy.toml $(CURDIR)/debian/secubox-mitmproxy/etc/secubox/
	install -d $(CURDIR)/debian/secubox-mitmproxy/lib/systemd/system
	install -m 644 debian/secubox-mitmproxy.service $(CURDIR)/debian/secubox-mitmproxy/lib/systemd/system/
```

- [ ] **Step 4: Create debian/postinst**

```bash
#!/bin/bash
set -e

case "$1" in
  configure)
    # Create data directories
    install -d -o secubox -g secubox -m 750 /srv/mitmproxy-waf/data
    install -d -o secubox -g secubox -m 750 /srv/mitmproxy-waf/addons
    install -d -o secubox -g secubox -m 750 /srv/mitmproxy-waf/config

    # Copy addon to data directory
    cp /usr/share/secubox/mitmproxy/addons/secubox_waf.py /srv/mitmproxy-waf/addons/

    # Copy default rules if not exists
    if [ ! -f /srv/mitmproxy-waf/data/waf-rules.json ]; then
      cp /usr/share/secubox/mitmproxy/data/waf-rules.json /srv/mitmproxy-waf/data/
    fi

    # Install CrowdSec acquisition if CrowdSec is installed
    if [ -d /etc/crowdsec/acquis.d ]; then
      install -m 644 /usr/share/secubox/mitmproxy/crowdsec/secubox-waf.yaml \
        /etc/crowdsec/acquis.d/ 2>/dev/null || true
    fi

    # Symlink for uvicorn workdir
    ln -sf /usr/lib/secubox/secubox-mitmproxy /usr/lib/secubox/mitmproxy 2>/dev/null || true

    # Enable and start service
    systemctl daemon-reload
    systemctl enable secubox-mitmproxy.service
    systemctl start secubox-mitmproxy.service || true

    # Reload nginx if installed
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
```

- [ ] **Step 5: Create debian/prerm**

```bash
#!/bin/bash
set -e

case "$1" in
  remove|purge)
    systemctl stop secubox-mitmproxy.service || true
    systemctl disable secubox-mitmproxy.service || true
    ;;
esac
#DEBHELPER#
```

- [ ] **Step 6: Create debian/secubox-mitmproxy.service**

```ini
[Unit]
Description=SecuBox Mitmproxy WAF API
After=network.target secubox-core.service lxc.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/mitmproxy
ExecStart=/usr/bin/uvicorn api.main:app \
    --uds /run/secubox/mitmproxy.sock \
    --log-level warning
ExecStartPost=/bin/chmod 660 /run/secubox/mitmproxy.sock
Restart=on-failure
RestartSec=5

PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/secubox /srv/mitmproxy-waf /var/lib/lxc /etc/secubox

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 7: Create api/__init__.py**

```python
"""SecuBox Mitmproxy WAF API"""
```

- [ ] **Step 8: Create api/routers/__init__.py**

```python
"""SecuBox Mitmproxy WAF API Routers"""
from .status import router as status_router
from .settings import router as settings_router
from .alerts import router as alerts_router
from .haproxy import router as haproxy_router
from .waf import router as waf_router

__all__ = ["status_router", "settings_router", "alerts_router", "haproxy_router", "waf_router"]
```

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-mitmproxy/
git commit -m "feat(mitmproxy): Add package scaffold and debian files"
```

---

### Task 2: Configuration Files

**Files:**
- Create: `packages/secubox-mitmproxy/debian/mitmproxy.toml`
- Create: `packages/secubox-mitmproxy/data/waf-rules.json`
- Create: `packages/secubox-mitmproxy/crowdsec/secubox-waf.yaml`
- Create: `packages/secubox-mitmproxy/menu.d/500-mitmproxy.json`

- [ ] **Step 1: Create debian/mitmproxy.toml (default config)**

```toml
# SecuBox Mitmproxy WAF Configuration

[container]
name = "mitmproxy-waf"
memory_limit = "256M"
autostart = true

[proxy]
listen_port = 8890
web_port = 8091
web_host = "127.0.0.1"
data_path = "/srv/mitmproxy-waf"

[haproxy]
enabled = false
config_path = "/etc/haproxy/haproxy.cfg"
backend_name = "mitmproxy_waf"

[crowdsec]
enabled = true
threats_log = "/srv/mitmproxy-waf/data/threats.log"

[autoban]
enabled = true
sensitivity = "moderate"
ban_duration = "4h"
min_severity = "high"

[autoban.categories]
sqli = true
xss = true
cmdi = true
traversal = true
ssrf = true
log4shell = true
cve_exploits = true
scanners = false
path_scan = false

[autoban.thresholds]
moderate_count = 3
moderate_window = 300
permissive_count = 5
permissive_window = 3600

[whitelist]
ips = ["127.0.0.1"]

[waf_rules]
sqli = true
xss = true
cmdi = true
traversal = true
ssrf = true
xxe = true
ldap = true
log4shell = true
scanners = true
path_scan = true
cve_exploits = true
rce = true
voip = false
xmpp = false
```

- [ ] **Step 2: Create data/waf-rules.json**

```json
{
  "sqli": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "union_select", "regex": "(?i)union\\s+(all\\s+)?select"},
      {"name": "or_injection", "regex": "(?i)\\bor\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+"},
      {"name": "and_injection", "regex": "(?i)\\band\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+"},
      {"name": "sleep_injection", "regex": "(?i)sleep\\s*\\(\\s*\\d+\\s*\\)"},
      {"name": "benchmark", "regex": "(?i)benchmark\\s*\\("},
      {"name": "comment_injection", "regex": "(?i)(--|#|/\\*).*$"},
      {"name": "hex_encoding", "regex": "(?i)0x[0-9a-f]+"},
      {"name": "char_function", "regex": "(?i)char\\s*\\(\\s*\\d+"}
    ]
  },
  "xss": {
    "enabled": true,
    "severity": "high",
    "patterns": [
      {"name": "script_tag", "regex": "(?i)<\\s*script[^>]*>"},
      {"name": "event_handler", "regex": "(?i)\\bon\\w+\\s*="},
      {"name": "javascript_uri", "regex": "(?i)javascript\\s*:"},
      {"name": "data_uri", "regex": "(?i)data\\s*:[^,]*;base64"},
      {"name": "svg_onload", "regex": "(?i)<\\s*svg[^>]*onload"},
      {"name": "img_onerror", "regex": "(?i)<\\s*img[^>]*onerror"}
    ]
  },
  "cmdi": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "semicolon_cmd", "regex": ";\\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\\b"},
      {"name": "pipe_cmd", "regex": "\\|\\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\\b"},
      {"name": "backtick", "regex": "`[^`]+`"},
      {"name": "subshell", "regex": "\\$\\([^)]+\\)"},
      {"name": "and_cmd", "regex": "&&\\s*(cat|ls|id|whoami|wget|curl)\\b"}
    ]
  },
  "traversal": {
    "enabled": true,
    "severity": "high",
    "patterns": [
      {"name": "dot_dot_slash", "regex": "\\.\\.[\\\\/]"},
      {"name": "encoded_traversal", "regex": "(?i)(%2e%2e|%252e%252e)[\\\\/(%2f|%252f)]"},
      {"name": "nullbyte", "regex": "%00"},
      {"name": "etc_passwd", "regex": "(?i)etc[\\\\/]passwd"}
    ]
  },
  "ssrf": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "localhost", "regex": "(?i)(localhost|127\\.0\\.0\\.1)"},
      {"name": "internal_10", "regex": "\\b10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"},
      {"name": "internal_172", "regex": "\\b172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}\\b"},
      {"name": "internal_192", "regex": "\\b192\\.168\\.\\d{1,3}\\.\\d{1,3}\\b"},
      {"name": "metadata_aws", "regex": "169\\.254\\.169\\.254"}
    ]
  },
  "xxe": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "doctype", "regex": "(?i)<!DOCTYPE"},
      {"name": "entity", "regex": "(?i)<!ENTITY"},
      {"name": "system", "regex": "(?i)SYSTEM\\s+['\"]"}
    ]
  },
  "ldap": {
    "enabled": true,
    "severity": "high",
    "patterns": [
      {"name": "ldap_filter", "regex": "\\)\\(|\\(\\||\\(&"},
      {"name": "ldap_wildcard", "regex": "\\*\\)"}
    ]
  },
  "log4shell": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "jndi_lookup", "regex": "(?i)\\$\\{jndi:"},
      {"name": "jndi_ldap", "regex": "(?i)jndi:(ldap|rmi|dns|iiop)://"},
      {"name": "nested_lookup", "regex": "(?i)\\$\\{[^}]*\\$\\{"}
    ]
  },
  "scanners": {
    "enabled": true,
    "severity": "medium",
    "patterns": [
      {"name": "sqlmap", "regex": "(?i)sqlmap"},
      {"name": "nikto", "regex": "(?i)nikto"},
      {"name": "nuclei", "regex": "(?i)nuclei"},
      {"name": "burpsuite", "regex": "(?i)burp"},
      {"name": "nmap", "regex": "(?i)nmap"},
      {"name": "dirbuster", "regex": "(?i)dirbuster"}
    ]
  },
  "path_scan": {
    "enabled": true,
    "severity": "medium",
    "patterns": [
      {"name": "dotenv", "regex": "\\.env$"},
      {"name": "git_dir", "regex": "\\.git/"},
      {"name": "wp_admin", "regex": "(?i)/wp-admin"},
      {"name": "phpmyadmin", "regex": "(?i)phpmyadmin"},
      {"name": "config_php", "regex": "(?i)config\\.php$"},
      {"name": "backup_files", "regex": "\\.(bak|backup|old|orig)$"}
    ]
  },
  "cve_exploits": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "spring4shell", "regex": "(?i)class\\.module\\.classLoader"},
      {"name": "moveit", "regex": "(?i)moveitisapi"},
      {"name": "struts_ognl", "regex": "(?i)%\\{.*\\}"}
    ]
  },
  "rce": {
    "enabled": true,
    "severity": "critical",
    "patterns": [
      {"name": "eval_function", "regex": "(?i)\\beval\\s*\\("},
      {"name": "exec_function", "regex": "(?i)\\bexec\\s*\\("},
      {"name": "system_function", "regex": "(?i)\\bsystem\\s*\\("},
      {"name": "passthru", "regex": "(?i)\\bpassthru\\s*\\("}
    ]
  },
  "voip": {
    "enabled": false,
    "severity": "medium",
    "patterns": [
      {"name": "sip_invite", "regex": "(?i)INVITE\\s+sip:"}
    ]
  },
  "xmpp": {
    "enabled": false,
    "severity": "medium",
    "patterns": [
      {"name": "xmpp_stanza", "regex": "<(message|presence|iq)\\s"}
    ]
  }
}
```

- [ ] **Step 3: Create crowdsec/secubox-waf.yaml**

```yaml
# CrowdSec acquisition for SecuBox WAF threats
source: file
filenames:
  - /srv/mitmproxy-waf/data/threats.log
labels:
  type: secubox-waf
```

- [ ] **Step 4: Create menu.d/500-mitmproxy.json**

```json
{
  "id": "mitmproxy",
  "name": "WAF",
  "icon": "🛡️",
  "path": "/mitmproxy/",
  "category": "security",
  "order": 500,
  "description": "Web Application Firewall"
}
```

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mitmproxy/
git commit -m "feat(mitmproxy): Add configuration files and WAF rules"
```

---

### Task 3: mitmproxyctl CLI

**Files:**
- Create: `packages/secubox-mitmproxy/bin/mitmproxyctl`

- [ ] **Step 1: Create bin/mitmproxyctl**

```python
#!/usr/bin/env python3
"""mitmproxyctl — LXC container management for SecuBox WAF

Usage:
    mitmproxyctl install   Create and configure LXC container
    mitmproxyctl start     Start container and mitmproxy
    mitmproxyctl stop      Stop container
    mitmproxyctl restart   Restart container
    mitmproxyctl status    Show container and process status
    mitmproxyctl destroy   Remove container (requires --force)
    mitmproxyctl logs      Show mitmproxy logs
"""
import sys
import os
import subprocess
import json
import time
import argparse
from pathlib import Path

try:
    import toml
except ImportError:
    toml = None

CONTAINER_NAME = "mitmproxy-waf"
CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")
DATA_PATH = Path("/srv/mitmproxy-waf")
LXC_PATH = Path("/var/lib/lxc") / CONTAINER_NAME


def load_config() -> dict:
    """Load configuration from TOML file."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {
        "container": {"name": CONTAINER_NAME, "memory_limit": "256M"},
        "proxy": {"listen_port": 8890, "web_port": 8091, "data_path": str(DATA_PATH)},
    }


def run(cmd: list, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command with error handling."""
    print(f"  → {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)


def lxc_exists() -> bool:
    """Check if LXC container exists."""
    result = run(["lxc-ls"], capture=True, check=False)
    return CONTAINER_NAME in result.stdout.split()


def lxc_running() -> bool:
    """Check if LXC container is running."""
    result = run(["lxc-info", "-n", CONTAINER_NAME, "-s"], capture=True, check=False)
    return "RUNNING" in result.stdout


def lxc_exec(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Execute command inside LXC container."""
    return run(["lxc-attach", "-n", CONTAINER_NAME, "--"] + cmd, check=check)


def cmd_install():
    """Create and configure LXC container."""
    print(f"Installing LXC container: {CONTAINER_NAME}")

    if lxc_exists():
        print(f"  Container {CONTAINER_NAME} already exists")
        return 1

    config = load_config()

    # Create data directories
    print("Creating data directories...")
    DATA_PATH.mkdir(parents=True, exist_ok=True)
    (DATA_PATH / "data").mkdir(exist_ok=True)
    (DATA_PATH / "addons").mkdir(exist_ok=True)
    (DATA_PATH / "config").mkdir(exist_ok=True)

    # Create LXC container
    print("Creating LXC container...")
    run([
        "lxc-create", "-n", CONTAINER_NAME,
        "-t", "download",
        "--",
        "-d", "debian",
        "-r", "bookworm",
        "-a", "amd64"
    ])

    # Configure container
    print("Configuring container...")
    lxc_config = LXC_PATH / "config"
    with open(lxc_config, "a") as f:
        f.write(f"\n# SecuBox WAF configuration\n")
        f.write(f"lxc.mount.entry = {DATA_PATH}/data data none bind,create=dir 0 0\n")
        f.write(f"lxc.mount.entry = {DATA_PATH}/addons addons none bind,create=dir 0 0\n")
        memory_bytes = int(config["container"].get("memory_limit", "256M").rstrip("M")) * 1024 * 1024
        f.write(f"lxc.cgroup2.memory.max = {memory_bytes}\n")

    # Start container for setup
    print("Starting container for initial setup...")
    run(["lxc-start", "-n", CONTAINER_NAME])
    time.sleep(5)  # Wait for container to boot

    # Install mitmproxy inside container
    print("Installing mitmproxy in container...")
    lxc_exec(["apt-get", "update"])
    lxc_exec(["apt-get", "install", "-y", "python3", "python3-pip"])
    lxc_exec(["pip3", "install", "--break-system-packages", "mitmproxy"])

    # Stop container
    run(["lxc-stop", "-n", CONTAINER_NAME])

    print(f"Container {CONTAINER_NAME} installed successfully")
    return 0


def cmd_start():
    """Start container and mitmproxy."""
    print(f"Starting {CONTAINER_NAME}...")

    if not lxc_exists():
        print(f"  Container does not exist. Run: mitmproxyctl install")
        return 1

    if lxc_running():
        print(f"  Container already running")
        return 0

    config = load_config()
    proxy_port = config["proxy"].get("listen_port", 8890)
    web_port = config["proxy"].get("web_port", 8091)

    # Start container
    run(["lxc-start", "-n", CONTAINER_NAME])
    time.sleep(3)

    # Start mitmproxy inside container (backgrounded)
    print("Starting mitmproxy...")
    lxc_exec([
        "sh", "-c",
        f"nohup mitmdump --mode upstream:http://127.0.0.1:80 "
        f"--listen-port {proxy_port} "
        f"--set web_open_browser=false "
        f"-s /addons/secubox_waf.py "
        f"> /var/log/mitmproxy.log 2>&1 &"
    ])

    print(f"Container {CONTAINER_NAME} started")
    print(f"  Proxy port: {proxy_port}")
    print(f"  Web port: {web_port}")
    return 0


def cmd_stop():
    """Stop container."""
    print(f"Stopping {CONTAINER_NAME}...")

    if not lxc_exists():
        print(f"  Container does not exist")
        return 1

    if not lxc_running():
        print(f"  Container not running")
        return 0

    run(["lxc-stop", "-n", CONTAINER_NAME])
    print(f"Container {CONTAINER_NAME} stopped")
    return 0


def cmd_restart():
    """Restart container."""
    cmd_stop()
    time.sleep(2)
    return cmd_start()


def cmd_status():
    """Show container and process status."""
    print(f"Status: {CONTAINER_NAME}")

    if not lxc_exists():
        print("  Container: NOT INSTALLED")
        return 1

    if lxc_running():
        print("  Container: RUNNING")

        # Check mitmproxy process
        result = lxc_exec(["pgrep", "-f", "mitmdump"], check=False)
        if result.returncode == 0:
            print("  Mitmproxy: RUNNING")
        else:
            print("  Mitmproxy: STOPPED")

        # Get container IP
        result = run(["lxc-info", "-n", CONTAINER_NAME, "-iH"], capture=True, check=False)
        if result.stdout.strip():
            print(f"  IP: {result.stdout.strip().split()[0]}")
    else:
        print("  Container: STOPPED")

    # Check threat log
    threats_log = DATA_PATH / "data" / "threats.log"
    if threats_log.exists():
        lines = threats_log.read_text().strip().split("\n")
        print(f"  Threats logged: {len([l for l in lines if l])}")

    return 0


def cmd_destroy(force: bool = False):
    """Remove container."""
    if not force:
        print("Use --force to destroy container")
        return 1

    print(f"Destroying {CONTAINER_NAME}...")

    if not lxc_exists():
        print(f"  Container does not exist")
        return 0

    if lxc_running():
        run(["lxc-stop", "-n", CONTAINER_NAME])

    run(["lxc-destroy", "-n", CONTAINER_NAME])
    print(f"Container {CONTAINER_NAME} destroyed")
    return 0


def cmd_logs():
    """Show mitmproxy logs."""
    if not lxc_running():
        print("Container not running")
        return 1

    lxc_exec(["tail", "-100", "/var/log/mitmproxy.log"], check=False)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SecuBox WAF container management")
    parser.add_argument("command", choices=["install", "start", "stop", "restart", "status", "destroy", "logs"])
    parser.add_argument("--force", action="store_true", help="Force operation")
    args = parser.parse_args()

    commands = {
        "install": cmd_install,
        "start": cmd_start,
        "stop": cmd_stop,
        "restart": cmd_restart,
        "status": cmd_status,
        "destroy": lambda: cmd_destroy(args.force),
        "logs": cmd_logs,
    }

    return commands[args.command]()


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Make executable and commit**

```bash
chmod +x packages/secubox-mitmproxy/bin/mitmproxyctl
git add packages/secubox-mitmproxy/bin/
git commit -m "feat(mitmproxy): Add mitmproxyctl CLI for LXC management"
```

---

### Task 4: Threat Detection Addon

**Files:**
- Create: `packages/secubox-mitmproxy/addons/secubox_waf.py`

- [ ] **Step 1: Create addons/secubox_waf.py**

```python
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
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/addons/
git commit -m "feat(mitmproxy): Add secubox_waf.py threat detection addon"
```

---

### Task 5: FastAPI Main App and Status Router

**Files:**
- Create: `packages/secubox-mitmproxy/api/main.py`
- Create: `packages/secubox-mitmproxy/api/routers/status.py`

- [ ] **Step 1: Create api/main.py**

```python
"""SecuBox Mitmproxy WAF API

Manages LXC container lifecycle and provides threat monitoring endpoints.
"""
import asyncio
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

from .routers import status_router, settings_router, alerts_router, haproxy_router, waf_router

app = FastAPI(
    title="secubox-mitmproxy",
    version="1.0.0",
    root_path="/api/v1/mitmproxy"
)

# Include auth router
app.include_router(auth_router, prefix="/auth")

# Include module routers
app.include_router(status_router, tags=["status"])
app.include_router(settings_router, tags=["settings"])
app.include_router(alerts_router, tags=["alerts"])
app.include_router(haproxy_router, prefix="/haproxy", tags=["haproxy"])
app.include_router(waf_router, prefix="/waf", tags=["waf"])

log = get_logger("mitmproxy")

# Constants
DATA_PATH = Path("/srv/mitmproxy-waf/data")
STATS_CACHE_FILE = DATA_PATH / "stats.json"
THREATS_LOG = DATA_PATH / "threats.log"

# In-memory cache
_stats_cache: dict = {}


async def _refresh_stats_cache():
    """Background task to refresh stats cache every 60s."""
    global _stats_cache
    while True:
        try:
            stats = {"threats_today": 0, "by_category": {}, "by_severity": {}}

            if THREATS_LOG.exists():
                today_start = __import__("time").time() - 86400

                for line in THREATS_LOG.read_text().strip().split("\n"):
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("ts", 0) >= today_start:
                            stats["threats_today"] += 1
                            cat = entry.get("category", "unknown")
                            sev = entry.get("severity", "unknown")
                            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                    except json.JSONDecodeError:
                        continue

            _stats_cache = stats
            STATS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATS_CACHE_FILE.write_text(json.dumps(stats))
            log.debug("Stats cache refreshed")

        except Exception as e:
            log.error(f"Stats cache refresh failed: {e}")

        await asyncio.sleep(60)


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    # Load existing cache
    if STATS_CACHE_FILE.exists():
        try:
            global _stats_cache
            _stats_cache = json.loads(STATS_CACHE_FILE.read_text())
        except Exception:
            pass

    asyncio.create_task(_refresh_stats_cache())
    log.info("SecuBox Mitmproxy WAF API started")


@app.get("/health")
async def health():
    """Health check endpoint (no auth required)."""
    return {"status": "ok", "module": "mitmproxy"}


def get_stats_cache() -> dict:
    """Get current stats cache."""
    return _stats_cache
```

- [ ] **Step 2: Create api/routers/status.py**

```python
"""Status router — Container status and control endpoints."""
import subprocess
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.status")

CONTAINER_NAME = "mitmproxy-waf"


class StatusResponse(BaseModel):
    container_exists: bool
    container_running: bool
    mitmproxy_running: bool
    threats_today: int = 0
    by_category: dict = {}
    by_severity: dict = {}


class ActionResponse(BaseModel):
    success: bool
    message: str


def _lxc_exists() -> bool:
    """Check if LXC container exists."""
    result = subprocess.run(["lxc-ls"], capture_output=True, text=True)
    return CONTAINER_NAME in result.stdout.split()


def _lxc_running() -> bool:
    """Check if LXC container is running."""
    result = subprocess.run(
        ["lxc-info", "-n", CONTAINER_NAME, "-s"],
        capture_output=True, text=True
    )
    return "RUNNING" in result.stdout


def _mitmproxy_running() -> bool:
    """Check if mitmproxy is running inside container."""
    if not _lxc_running():
        return False
    result = subprocess.run(
        ["lxc-attach", "-n", CONTAINER_NAME, "--", "pgrep", "-f", "mitmdump"],
        capture_output=True
    )
    return result.returncode == 0


@router.get("/status", response_model=StatusResponse)
async def get_status(user=Depends(require_jwt)):
    """Get container and WAF status."""
    from ..main import get_stats_cache

    stats = get_stats_cache()

    return StatusResponse(
        container_exists=_lxc_exists(),
        container_running=_lxc_running(),
        mitmproxy_running=_mitmproxy_running(),
        threats_today=stats.get("threats_today", 0),
        by_category=stats.get("by_category", {}),
        by_severity=stats.get("by_severity", {})
    )


@router.post("/start", response_model=ActionResponse)
async def start_container(user=Depends(require_jwt)):
    """Start the WAF container."""
    if not _lxc_exists():
        raise HTTPException(400, "Container not installed. Run: mitmproxyctl install")

    if _lxc_running():
        return ActionResponse(success=True, message="Container already running")

    result = subprocess.run(["mitmproxyctl", "start"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container started")
    else:
        raise HTTPException(500, f"Failed to start: {result.stderr}")


@router.post("/stop", response_model=ActionResponse)
async def stop_container(user=Depends(require_jwt)):
    """Stop the WAF container."""
    if not _lxc_running():
        return ActionResponse(success=True, message="Container not running")

    result = subprocess.run(["mitmproxyctl", "stop"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container stopped")
    else:
        raise HTTPException(500, f"Failed to stop: {result.stderr}")


@router.post("/restart", response_model=ActionResponse)
async def restart_container(user=Depends(require_jwt)):
    """Restart the WAF container."""
    result = subprocess.run(["mitmproxyctl", "restart"], capture_output=True, text=True)

    if result.returncode == 0:
        return ActionResponse(success=True, message="Container restarted")
    else:
        raise HTTPException(500, f"Failed to restart: {result.stderr}")
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mitmproxy/api/
git commit -m "feat(mitmproxy): Add FastAPI main app and status router"
```

---

### Task 6: Settings Router

**Files:**
- Create: `packages/secubox-mitmproxy/api/routers/settings.py`

- [ ] **Step 1: Create api/routers/settings.py**

```python
"""Settings router — Configuration CRUD endpoints."""
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

try:
    import toml
except ImportError:
    toml = None

router = APIRouter()
log = get_logger("mitmproxy.settings")

CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")


class ContainerSettings(BaseModel):
    name: str = "mitmproxy-waf"
    memory_limit: str = "256M"
    autostart: bool = True


class ProxySettings(BaseModel):
    listen_port: int = 8890
    web_port: int = 8091
    web_host: str = "127.0.0.1"
    data_path: str = "/srv/mitmproxy-waf"


class HAProxySettings(BaseModel):
    enabled: bool = False
    config_path: str = "/etc/haproxy/haproxy.cfg"
    backend_name: str = "mitmproxy_waf"


class AutobanSettings(BaseModel):
    enabled: bool = True
    sensitivity: str = "moderate"
    ban_duration: str = "4h"
    min_severity: str = "high"


class WhitelistSettings(BaseModel):
    ips: List[str] = ["127.0.0.1"]


class SettingsResponse(BaseModel):
    container: ContainerSettings
    proxy: ProxySettings
    haproxy: HAProxySettings
    autoban: AutobanSettings
    whitelist: WhitelistSettings


class SettingsUpdate(BaseModel):
    container: Optional[ContainerSettings] = None
    proxy: Optional[ProxySettings] = None
    haproxy: Optional[HAProxySettings] = None
    autoban: Optional[AutobanSettings] = None
    whitelist: Optional[WhitelistSettings] = None


def _load_config() -> dict:
    """Load configuration from TOML file."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {}


def _save_config(config: dict) -> None:
    """Save configuration to TOML file."""
    if not toml:
        raise HTTPException(500, "TOML library not available")

    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        toml.dump(config, f)


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(user=Depends(require_jwt)):
    """Get current configuration."""
    config = _load_config()

    return SettingsResponse(
        container=ContainerSettings(**config.get("container", {})),
        proxy=ProxySettings(**config.get("proxy", {})),
        haproxy=HAProxySettings(**config.get("haproxy", {})),
        autoban=AutobanSettings(**config.get("autoban", {})),
        whitelist=WhitelistSettings(**config.get("whitelist", {}))
    )


@router.post("/settings", response_model=SettingsResponse)
async def update_settings(update: SettingsUpdate, user=Depends(require_jwt)):
    """Update configuration."""
    config = _load_config()

    if update.container:
        config["container"] = update.container.dict()
    if update.proxy:
        config["proxy"] = update.proxy.dict()
    if update.haproxy:
        config["haproxy"] = update.haproxy.dict()
    if update.autoban:
        config["autoban"] = update.autoban.dict()
    if update.whitelist:
        config["whitelist"] = update.whitelist.dict()

    _save_config(config)
    log.info("Configuration updated")

    return await get_settings(user)
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/api/routers/settings.py
git commit -m "feat(mitmproxy): Add settings router"
```

---

### Task 7: Alerts Router

**Files:**
- Create: `packages/secubox-mitmproxy/api/routers/alerts.py`

- [ ] **Step 1: Create api/routers/alerts.py**

```python
"""Alerts router — Threat log, stats, and ban management."""
import json
import subprocess
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.alerts")

DATA_PATH = Path("/srv/mitmproxy-waf/data")
THREATS_LOG = DATA_PATH / "threats.log"


class ThreatEntry(BaseModel):
    ts: float
    ip: str
    host: str
    path: str
    method: str
    category: str
    severity: str
    pattern: str
    matched: str


class AlertsResponse(BaseModel):
    total: int
    alerts: List[ThreatEntry]


class StatsResponse(BaseModel):
    total: int
    by_category: dict
    by_severity: dict
    by_ip: dict
    top_paths: List[dict]


class BanEntry(BaseModel):
    ip: str
    reason: str
    duration: str
    source: str


class BansResponse(BaseModel):
    total: int
    bans: List[BanEntry]


class UnbanRequest(BaseModel):
    ip: str


class ActionResponse(BaseModel):
    success: bool
    message: str


@router.get("/alerts", response_model=AlertsResponse)
async def get_alerts(
    user=Depends(require_jwt),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    category: Optional[str] = None,
    severity: Optional[str] = None
):
    """Get threat alerts with pagination and filtering."""
    alerts = []

    if THREATS_LOG.exists():
        lines = THREATS_LOG.read_text().strip().split("\n")
        lines = [l for l in lines if l]  # Remove empty
        lines.reverse()  # Most recent first

        for line in lines:
            try:
                entry = json.loads(line)

                # Apply filters
                if category and entry.get("category") != category:
                    continue
                if severity and entry.get("severity") != severity:
                    continue

                alerts.append(ThreatEntry(**entry))
            except (json.JSONDecodeError, TypeError):
                continue

    total = len(alerts)
    alerts = alerts[offset:offset + limit]

    return AlertsResponse(total=total, alerts=alerts)


@router.get("/alerts/stats", response_model=StatsResponse)
async def get_alert_stats(user=Depends(require_jwt)):
    """Get aggregated threat statistics."""
    stats = {
        "total": 0,
        "by_category": {},
        "by_severity": {},
        "by_ip": {},
        "top_paths": []
    }

    path_counts = {}

    if THREATS_LOG.exists():
        for line in THREATS_LOG.read_text().strip().split("\n"):
            if not line:
                continue
            try:
                entry = json.loads(line)
                stats["total"] += 1

                cat = entry.get("category", "unknown")
                sev = entry.get("severity", "unknown")
                ip = entry.get("ip", "unknown")
                path = entry.get("path", "/")

                stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
                stats["by_ip"][ip] = stats["by_ip"].get(ip, 0) + 1
                path_counts[path] = path_counts.get(path, 0) + 1

            except json.JSONDecodeError:
                continue

    # Top 10 paths
    sorted_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    stats["top_paths"] = [{"path": p, "count": c} for p, c in sorted_paths]

    return StatsResponse(**stats)


@router.post("/alerts/clear", response_model=ActionResponse)
async def clear_alerts(user=Depends(require_jwt)):
    """Clear the threat log."""
    if THREATS_LOG.exists():
        THREATS_LOG.write_text("")
        log.info("Threat log cleared")

    return ActionResponse(success=True, message="Threat log cleared")


@router.get("/bans", response_model=BansResponse)
async def get_bans(user=Depends(require_jwt)):
    """Get active bans from CrowdSec."""
    bans = []

    try:
        result = subprocess.run(
            ["cscli", "decisions", "list", "-o", "json"],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0 and result.stdout:
            decisions = json.loads(result.stdout) or []
            for d in decisions:
                if d.get("type") == "ban":
                    bans.append(BanEntry(
                        ip=d.get("value", "unknown"),
                        reason=d.get("scenario", "unknown"),
                        duration=d.get("duration", "unknown"),
                        source=d.get("origin", "unknown")
                    ))
    except Exception as e:
        log.error(f"Failed to get bans: {e}")

    return BansResponse(total=len(bans), bans=bans)


@router.post("/unban", response_model=ActionResponse)
async def unban_ip(req: UnbanRequest, user=Depends(require_jwt)):
    """Remove IP from ban list."""
    try:
        result = subprocess.run(
            ["cscli", "decisions", "delete", "--ip", req.ip],
            capture_output=True, text=True, timeout=10
        )

        if result.returncode == 0:
            log.info(f"Unbanned IP: {req.ip}")
            return ActionResponse(success=True, message=f"IP {req.ip} unbanned")
        else:
            raise HTTPException(500, f"Failed to unban: {result.stderr}")

    except subprocess.TimeoutExpired:
        raise HTTPException(500, "CrowdSec command timed out")
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/api/routers/alerts.py
git commit -m "feat(mitmproxy): Add alerts router with threat log and bans"
```

---

### Task 8: HAProxy Integration Router

**Files:**
- Create: `packages/secubox-mitmproxy/api/routers/haproxy.py`

- [ ] **Step 1: Create api/routers/haproxy.py**

```python
"""HAProxy router — WAF enable/disable and route sync."""
import json
import re
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

try:
    import toml
except ImportError:
    toml = None

router = APIRouter()
log = get_logger("mitmproxy.haproxy")

CONFIG_FILE = Path("/etc/secubox/mitmproxy.toml")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")
HAPROXY_BACKUP = Path("/etc/haproxy/haproxy.cfg.waf-backup")
ROUTES_FILE = Path("/srv/mitmproxy-waf/data/routes.json")


class HAProxyStatus(BaseModel):
    waf_enabled: bool
    backend_exists: bool
    routes_count: int


class RoutesResponse(BaseModel):
    routes: Dict[str, List]


class ActionResponse(BaseModel):
    success: bool
    message: str


def _load_config() -> dict:
    """Load mitmproxy config."""
    if toml and CONFIG_FILE.exists():
        return toml.load(CONFIG_FILE)
    return {}


def _save_config(config: dict) -> None:
    """Save mitmproxy config."""
    if toml:
        with open(CONFIG_FILE, "w") as f:
            toml.dump(config, f)


def _haproxy_has_waf_backend() -> bool:
    """Check if HAProxy config has mitmproxy_waf backend."""
    if not HAPROXY_CFG.exists():
        return False
    content = HAPROXY_CFG.read_text()
    return "backend mitmproxy_waf" in content


def _parse_haproxy_backends() -> Dict[str, tuple]:
    """Parse HAProxy config to extract vhost → backend mappings."""
    routes = {}

    if not HAPROXY_CFG.exists():
        return routes

    content = HAPROXY_CFG.read_text()

    # Find backend definitions and their servers
    backends = {}
    current_backend = None

    for line in content.split("\n"):
        line = line.strip()

        # Backend definition
        if line.startswith("backend "):
            current_backend = line.split()[1]
            backends[current_backend] = None

        # Server definition inside backend
        elif current_backend and line.startswith("server "):
            # server name ip:port ...
            parts = line.split()
            if len(parts) >= 3:
                addr = parts[2]
                if ":" in addr:
                    ip, port = addr.rsplit(":", 1)
                    try:
                        backends[current_backend] = (ip, int(port))
                    except ValueError:
                        pass

    # Find use_backend rules to map hosts to backends
    for line in content.split("\n"):
        # use_backend backend_name if { hdr(host) -i hostname }
        match = re.search(r'use_backend\s+(\S+)\s+if\s+\{\s*hdr\(host\)\s+-i\s+(\S+)', line)
        if match:
            backend_name, hostname = match.groups()
            if backend_name in backends and backends[backend_name]:
                routes[hostname] = list(backends[backend_name])

    return routes


@router.get("/status", response_model=HAProxyStatus)
async def get_haproxy_status(user=Depends(require_jwt)):
    """Get HAProxy WAF integration status."""
    config = _load_config()

    routes_count = 0
    if ROUTES_FILE.exists():
        try:
            routes = json.loads(ROUTES_FILE.read_text())
            routes_count = len(routes)
        except Exception:
            pass

    return HAProxyStatus(
        waf_enabled=config.get("haproxy", {}).get("enabled", False),
        backend_exists=_haproxy_has_waf_backend(),
        routes_count=routes_count
    )


@router.post("/enable", response_model=ActionResponse)
async def enable_waf(user=Depends(require_jwt)):
    """Enable WAF inspection for HAProxy traffic."""
    if not HAPROXY_CFG.exists():
        raise HTTPException(400, "HAProxy config not found")

    config = _load_config()
    proxy_port = config.get("proxy", {}).get("listen_port", 8890)

    # Backup current config
    shutil.copy(HAPROXY_CFG, HAPROXY_BACKUP)

    content = HAPROXY_CFG.read_text()

    # Add mitmproxy_waf backend if not exists
    if "backend mitmproxy_waf" not in content:
        waf_backend = f"""
# SecuBox WAF Backend
backend mitmproxy_waf
    mode http
    server waf 127.0.0.1:{proxy_port} check
"""
        # Add before first backend or at end
        if "backend " in content:
            idx = content.index("backend ")
            content = content[:idx] + waf_backend + "\n" + content[idx:]
        else:
            content += waf_backend

        HAPROXY_CFG.write_text(content)

    # Sync routes
    await sync_routes(user)

    # Update config
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["enabled"] = True
    _save_config(config)

    # Reload HAProxy
    result = subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)
    if result.returncode != 0:
        log.error(f"Failed to reload HAProxy: {result.stderr}")

    log.info("WAF enabled for HAProxy")
    return ActionResponse(success=True, message="WAF enabled")


@router.post("/disable", response_model=ActionResponse)
async def disable_waf(user=Depends(require_jwt)):
    """Disable WAF inspection (restore original routing)."""
    config = _load_config()

    # Restore backup if exists
    if HAPROXY_BACKUP.exists():
        shutil.copy(HAPROXY_BACKUP, HAPROXY_CFG)

        # Reload HAProxy
        subprocess.run(["systemctl", "reload", "haproxy"], capture_output=True)

    # Update config
    if "haproxy" not in config:
        config["haproxy"] = {}
    config["haproxy"]["enabled"] = False
    _save_config(config)

    log.info("WAF disabled for HAProxy")
    return ActionResponse(success=True, message="WAF disabled")


@router.post("/sync", response_model=ActionResponse)
async def sync_routes(user=Depends(require_jwt)):
    """Sync HAProxy vhosts to mitmproxy routes."""
    routes = _parse_haproxy_backends()

    ROUTES_FILE.parent.mkdir(parents=True, exist_ok=True)
    ROUTES_FILE.write_text(json.dumps(routes, indent=2))

    log.info(f"Synced {len(routes)} routes to mitmproxy")
    return ActionResponse(success=True, message=f"Synced {len(routes)} routes")


@router.get("/routes", response_model=RoutesResponse)
async def get_routes(user=Depends(require_jwt)):
    """Get current route mappings."""
    routes = {}

    if ROUTES_FILE.exists():
        try:
            routes = json.loads(ROUTES_FILE.read_text())
        except Exception:
            pass

    return RoutesResponse(routes=routes)
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/api/routers/haproxy.py
git commit -m "feat(mitmproxy): Add HAProxy integration router"
```

---

### Task 9: WAF Rules Router

**Files:**
- Create: `packages/secubox-mitmproxy/api/routers/waf.py`

- [ ] **Step 1: Create api/routers/waf.py**

```python
"""WAF router — Rule category management."""
import json
from pathlib import Path
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("mitmproxy.waf")

RULES_FILE = Path("/srv/mitmproxy-waf/data/waf-rules.json")
DEFAULT_RULES = Path("/usr/share/secubox/mitmproxy/data/waf-rules.json")


class RuleCategory(BaseModel):
    name: str
    enabled: bool
    severity: str
    pattern_count: int
    hits: int = 0


class RulesResponse(BaseModel):
    categories: List[RuleCategory]


class RuleStatsResponse(BaseModel):
    stats: Dict[str, int]


class ToggleRequest(BaseModel):
    category: str
    enabled: bool


class ActionResponse(BaseModel):
    success: bool
    message: str


def _load_rules() -> dict:
    """Load WAF rules from file."""
    if RULES_FILE.exists():
        return json.loads(RULES_FILE.read_text())
    elif DEFAULT_RULES.exists():
        return json.loads(DEFAULT_RULES.read_text())
    return {}


def _save_rules(rules: dict) -> None:
    """Save WAF rules to file."""
    RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    RULES_FILE.write_text(json.dumps(rules, indent=2))


def _load_stats() -> dict:
    """Load detection stats."""
    stats_file = RULES_FILE.parent / "stats.json"
    if stats_file.exists():
        try:
            return json.loads(stats_file.read_text())
        except Exception:
            pass
    return {}


@router.get("/rules", response_model=RulesResponse)
async def get_rules(user=Depends(require_jwt)):
    """Get all WAF rule categories."""
    rules = _load_rules()
    stats = _load_stats()

    categories = []
    for name, config in rules.items():
        categories.append(RuleCategory(
            name=name,
            enabled=config.get("enabled", True),
            severity=config.get("severity", "medium"),
            pattern_count=len(config.get("patterns", [])),
            hits=stats.get(name, 0)
        ))

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    categories.sort(key=lambda x: severity_order.get(x.severity, 99))

    return RulesResponse(categories=categories)


@router.post("/rules/toggle", response_model=ActionResponse)
async def toggle_rule(req: ToggleRequest, user=Depends(require_jwt)):
    """Enable or disable a rule category."""
    rules = _load_rules()

    if req.category not in rules:
        raise HTTPException(404, f"Category not found: {req.category}")

    rules[req.category]["enabled"] = req.enabled
    _save_rules(rules)

    action = "enabled" if req.enabled else "disabled"
    log.info(f"WAF category {req.category} {action}")

    return ActionResponse(success=True, message=f"Category {req.category} {action}")


@router.get("/rules/stats", response_model=RuleStatsResponse)
async def get_rule_stats(user=Depends(require_jwt)):
    """Get per-category detection statistics."""
    return RuleStatsResponse(stats=_load_stats())
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/api/routers/waf.py
git commit -m "feat(mitmproxy): Add WAF rules router"
```

---

### Task 10: WebUI Status Page

**Files:**
- Create: `packages/secubox-mitmproxy/www/mitmproxy/index.html`
- Create: `packages/secubox-mitmproxy/www/mitmproxy/status.html`

- [ ] **Step 1: Create www/mitmproxy/index.html**

```html
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url=status.html">
    <title>SecuBox WAF</title>
</head>
<body>
    <p>Redirecting to <a href="status.html">status</a>...</p>
</body>
</html>
```

- [ ] **Step 2: Create www/mitmproxy/status.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Status - SecuBox</title>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
    <style>
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card-bg, #fff);
            border: 2px solid var(--border, #a5d6a7);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }
        .stat-card.critical { border-color: #e63946; }
        .stat-card.warning { border-color: #f4a261; }
        .stat-card.success { border-color: #2a9d8f; }
        .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary, #00aa44);
        }
        .stat-label {
            font-size: 0.8rem;
            color: var(--text-muted, #666);
            text-transform: uppercase;
        }
        .controls {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn-primary { background: var(--primary, #00aa44); color: white; }
        .btn-danger { background: #e63946; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        .status-running { background: #2a9d8f; }
        .status-stopped { background: #e63946; }
        .threats-table {
            width: 100%;
            border-collapse: collapse;
        }
        .threats-table th, .threats-table td {
            padding: 0.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border, #ddd);
        }
        .threats-table th { background: var(--card-bg, #f5f5f5); }
        .severity-critical { color: #e63946; font-weight: bold; }
        .severity-high { color: #f4a261; }
        .severity-medium { color: #e9c46a; }
    </style>
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <div class="container">
            <h1>🛡️ WAF Status</h1>

            <div class="stats-grid">
                <div class="stat-card" id="status-card">
                    <div class="stat-value" id="container-status">--</div>
                    <div class="stat-label">Container</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="threats-today">0</div>
                    <div class="stat-label">Threats Today</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" id="bans-count">0</div>
                    <div class="stat-label">Active Bans</div>
                </div>
                <div class="stat-card" id="haproxy-card">
                    <div class="stat-value" id="haproxy-status">--</div>
                    <div class="stat-label">HAProxy WAF</div>
                </div>
            </div>

            <div class="controls">
                <button class="btn btn-primary" id="btn-start" onclick="startContainer()">Start</button>
                <button class="btn btn-danger" id="btn-stop" onclick="stopContainer()">Stop</button>
                <button class="btn btn-secondary" id="btn-restart" onclick="restartContainer()">Restart</button>
                <button class="btn btn-primary" id="btn-enable-waf" onclick="enableWAF()">Enable WAF</button>
                <button class="btn btn-danger" id="btn-disable-waf" onclick="disableWAF()">Disable WAF</button>
            </div>

            <h2>Recent Threats</h2>
            <table class="threats-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>Path</th>
                    </tr>
                </thead>
                <tbody id="threats-body">
                    <tr><td colspan="5">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </main>
    <script src="/shared/sidebar.js"></script>
    <script>
        const API = '/api/v1/mitmproxy';
        const token = localStorage.getItem('sbx_token') || localStorage.getItem('secubox_token');
        const headers = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };

        async function loadStatus() {
            try {
                const res = await fetch(API + '/status', { headers });
                const data = await res.json();

                const statusCard = document.getElementById('status-card');
                const statusEl = document.getElementById('container-status');

                if (data.container_running && data.mitmproxy_running) {
                    statusEl.innerHTML = '<span class="status-indicator status-running"></span>Running';
                    statusCard.className = 'stat-card success';
                } else if (data.container_exists) {
                    statusEl.innerHTML = '<span class="status-indicator status-stopped"></span>Stopped';
                    statusCard.className = 'stat-card warning';
                } else {
                    statusEl.innerHTML = 'Not Installed';
                    statusCard.className = 'stat-card critical';
                }

                document.getElementById('threats-today').textContent = data.threats_today || 0;
            } catch (e) {
                console.error('Failed to load status:', e);
            }
        }

        async function loadHAProxyStatus() {
            try {
                const res = await fetch(API + '/haproxy/status', { headers });
                const data = await res.json();

                const el = document.getElementById('haproxy-status');
                const card = document.getElementById('haproxy-card');

                if (data.waf_enabled) {
                    el.textContent = 'Enabled';
                    card.className = 'stat-card success';
                } else {
                    el.textContent = 'Disabled';
                    card.className = 'stat-card';
                }
            } catch (e) {
                console.error('Failed to load HAProxy status:', e);
            }
        }

        async function loadBans() {
            try {
                const res = await fetch(API + '/bans', { headers });
                const data = await res.json();
                document.getElementById('bans-count').textContent = data.total || 0;
            } catch (e) {
                console.error('Failed to load bans:', e);
            }
        }

        async function loadThreats() {
            try {
                const res = await fetch(API + '/alerts?limit=20', { headers });
                const data = await res.json();

                const tbody = document.getElementById('threats-body');
                if (!data.alerts || data.alerts.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5">No threats detected</td></tr>';
                    return;
                }

                tbody.innerHTML = data.alerts.map(t => `
                    <tr>
                        <td>${new Date(t.ts * 1000).toLocaleTimeString()}</td>
                        <td>${t.ip}</td>
                        <td>${t.category}</td>
                        <td class="severity-${t.severity}">${t.severity}</td>
                        <td title="${t.path}">${t.path.substring(0, 50)}${t.path.length > 50 ? '...' : ''}</td>
                    </tr>
                `).join('');
            } catch (e) {
                console.error('Failed to load threats:', e);
            }
        }

        async function startContainer() {
            await fetch(API + '/start', { method: 'POST', headers });
            loadStatus();
        }

        async function stopContainer() {
            await fetch(API + '/stop', { method: 'POST', headers });
            loadStatus();
        }

        async function restartContainer() {
            await fetch(API + '/restart', { method: 'POST', headers });
            loadStatus();
        }

        async function enableWAF() {
            await fetch(API + '/haproxy/enable', { method: 'POST', headers });
            loadHAProxyStatus();
        }

        async function disableWAF() {
            await fetch(API + '/haproxy/disable', { method: 'POST', headers });
            loadHAProxyStatus();
        }

        // Initial load
        loadStatus();
        loadHAProxyStatus();
        loadBans();
        loadThreats();

        // Auto-refresh every 30s
        setInterval(() => {
            loadStatus();
            loadBans();
            loadThreats();
        }, 30000);
    </script>
</body>
</html>
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mitmproxy/www/
git commit -m "feat(mitmproxy): Add WebUI status page"
```

---

### Task 11: WebUI Settings Page

**Files:**
- Create: `packages/secubox-mitmproxy/www/mitmproxy/settings.html`

- [ ] **Step 1: Create www/mitmproxy/settings.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Settings - SecuBox</title>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
    <style>
        .form-section {
            background: var(--card-bg, #fff);
            border: 2px solid var(--border, #a5d6a7);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .form-section h3 {
            margin-top: 0;
            color: var(--primary, #00aa44);
            border-bottom: 1px solid var(--border, #ddd);
            padding-bottom: 0.5rem;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.25rem;
            font-weight: 600;
        }
        .form-group input, .form-group select {
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border, #ccc);
            border-radius: 4px;
            font-size: 1rem;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--primary, #00aa44);
        }
        .form-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            font-size: 1rem;
        }
        .btn-primary { background: var(--primary, #00aa44); color: white; }
        .btn-primary:hover { opacity: 0.9; }
        .message {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        .message.success { background: #d4edda; color: #155724; display: block; }
        .message.error { background: #f8d7da; color: #721c24; display: block; }
        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .checkbox-label input { width: auto; }
    </style>
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <div class="container">
            <h1>⚙️ WAF Settings</h1>

            <div id="message" class="message"></div>

            <form id="settings-form">
                <div class="form-section">
                    <h3>Container</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Memory Limit</label>
                            <select id="memory_limit" name="memory_limit">
                                <option value="128M">128 MB</option>
                                <option value="256M" selected>256 MB</option>
                                <option value="512M">512 MB</option>
                                <option value="1G">1 GB</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" id="autostart" name="autostart" checked>
                                Autostart on boot
                            </label>
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <h3>Proxy</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Listen Port</label>
                            <input type="number" id="listen_port" name="listen_port" value="8890">
                        </div>
                        <div class="form-group">
                            <label>Web UI Port</label>
                            <input type="number" id="web_port" name="web_port" value="8091">
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <h3>Auto-Ban</h3>
                    <div class="form-row">
                        <div class="form-group">
                            <label class="checkbox-label">
                                <input type="checkbox" id="autoban_enabled" name="autoban_enabled" checked>
                                Enable Auto-Ban
                            </label>
                        </div>
                        <div class="form-group">
                            <label>Sensitivity</label>
                            <select id="sensitivity" name="sensitivity">
                                <option value="aggressive">Aggressive (ban immediately)</option>
                                <option value="moderate" selected>Moderate (3 hits / 5 min)</option>
                                <option value="permissive">Permissive (5 hits / 1 hour)</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Ban Duration</label>
                            <select id="ban_duration" name="ban_duration">
                                <option value="1h">1 hour</option>
                                <option value="4h" selected>4 hours</option>
                                <option value="24h">24 hours</option>
                                <option value="7d">7 days</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Minimum Severity</label>
                            <select id="min_severity" name="min_severity">
                                <option value="critical">Critical only</option>
                                <option value="high" selected>High and above</option>
                                <option value="medium">Medium and above</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div class="form-section">
                    <h3>Whitelist</h3>
                    <div class="form-group">
                        <label>Whitelisted IPs (comma-separated)</label>
                        <input type="text" id="whitelist_ips" name="whitelist_ips" value="127.0.0.1" placeholder="127.0.0.1, 192.168.1.0/24">
                    </div>
                </div>

                <button type="submit" class="btn btn-primary">Save Settings</button>
            </form>
        </div>
    </main>
    <script src="/shared/sidebar.js"></script>
    <script>
        const API = '/api/v1/mitmproxy';
        const token = localStorage.getItem('sbx_token') || localStorage.getItem('secubox_token');
        const headers = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };

        async function loadSettings() {
            try {
                const res = await fetch(API + '/settings', { headers });
                const data = await res.json();

                document.getElementById('memory_limit').value = data.container?.memory_limit || '256M';
                document.getElementById('autostart').checked = data.container?.autostart !== false;
                document.getElementById('listen_port').value = data.proxy?.listen_port || 8890;
                document.getElementById('web_port').value = data.proxy?.web_port || 8091;
                document.getElementById('autoban_enabled').checked = data.autoban?.enabled !== false;
                document.getElementById('sensitivity').value = data.autoban?.sensitivity || 'moderate';
                document.getElementById('ban_duration').value = data.autoban?.ban_duration || '4h';
                document.getElementById('min_severity').value = data.autoban?.min_severity || 'high';
                document.getElementById('whitelist_ips').value = (data.whitelist?.ips || ['127.0.0.1']).join(', ');
            } catch (e) {
                showMessage('Failed to load settings', 'error');
            }
        }

        async function saveSettings(e) {
            e.preventDefault();

            const data = {
                container: {
                    name: 'mitmproxy-waf',
                    memory_limit: document.getElementById('memory_limit').value,
                    autostart: document.getElementById('autostart').checked
                },
                proxy: {
                    listen_port: parseInt(document.getElementById('listen_port').value),
                    web_port: parseInt(document.getElementById('web_port').value),
                    web_host: '127.0.0.1',
                    data_path: '/srv/mitmproxy-waf'
                },
                autoban: {
                    enabled: document.getElementById('autoban_enabled').checked,
                    sensitivity: document.getElementById('sensitivity').value,
                    ban_duration: document.getElementById('ban_duration').value,
                    min_severity: document.getElementById('min_severity').value
                },
                whitelist: {
                    ips: document.getElementById('whitelist_ips').value.split(',').map(s => s.trim()).filter(s => s)
                }
            };

            try {
                const res = await fetch(API + '/settings', {
                    method: 'POST',
                    headers,
                    body: JSON.stringify(data)
                });

                if (res.ok) {
                    showMessage('Settings saved successfully', 'success');
                } else {
                    const err = await res.json();
                    showMessage(err.detail || 'Failed to save', 'error');
                }
            } catch (e) {
                showMessage('Failed to save settings', 'error');
            }
        }

        function showMessage(text, type) {
            const el = document.getElementById('message');
            el.textContent = text;
            el.className = 'message ' + type;
            setTimeout(() => { el.className = 'message'; }, 5000);
        }

        document.getElementById('settings-form').addEventListener('submit', saveSettings);
        loadSettings();
    </script>
</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/www/mitmproxy/settings.html
git commit -m "feat(mitmproxy): Add WebUI settings page"
```

---

### Task 12: WebUI Filters Page

**Files:**
- Create: `packages/secubox-mitmproxy/www/mitmproxy/filters.html`

- [ ] **Step 1: Create www/mitmproxy/filters.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Filters - SecuBox</title>
    <link rel="stylesheet" href="/shared/crt-light.css">
    <link rel="stylesheet" href="/shared/sidebar-light.css">
    <style>
        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }
        .filter-card {
            background: var(--card-bg, #fff);
            border: 2px solid var(--border, #a5d6a7);
            border-radius: 8px;
            padding: 1rem;
        }
        .filter-card.critical { border-left: 4px solid #e63946; }
        .filter-card.high { border-left: 4px solid #f4a261; }
        .filter-card.medium { border-left: 4px solid #e9c46a; }
        .filter-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .filter-name {
            font-weight: bold;
            font-size: 1.1rem;
        }
        .filter-toggle {
            position: relative;
            width: 50px;
            height: 26px;
        }
        .filter-toggle input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .filter-toggle .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .3s;
            border-radius: 26px;
        }
        .filter-toggle .slider:before {
            position: absolute;
            content: "";
            height: 20px;
            width: 20px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }
        .filter-toggle input:checked + .slider {
            background-color: var(--primary, #00aa44);
        }
        .filter-toggle input:checked + .slider:before {
            transform: translateX(24px);
        }
        .filter-meta {
            display: flex;
            gap: 1rem;
            font-size: 0.85rem;
            color: var(--text-muted, #666);
        }
        .filter-severity {
            text-transform: uppercase;
            font-weight: bold;
        }
        .filter-severity.critical { color: #e63946; }
        .filter-severity.high { color: #f4a261; }
        .filter-severity.medium { color: #e9c46a; }
        .filter-hits {
            margin-left: auto;
        }
        .message {
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        .message.success { background: #d4edda; color: #155724; display: block; }
        .message.error { background: #f8d7da; color: #721c24; display: block; }
    </style>
</head>
<body class="crt-light">
    <nav class="sidebar" id="sidebar"></nav>
    <main class="main-content">
        <div class="container">
            <h1>🔍 WAF Filters</h1>
            <p>Enable or disable threat detection categories. Changes take effect immediately.</p>

            <div id="message" class="message"></div>

            <div class="filters-grid" id="filters-grid">
                <div class="filter-card">Loading...</div>
            </div>
        </div>
    </main>
    <script src="/shared/sidebar.js"></script>
    <script>
        const API = '/api/v1/mitmproxy';
        const token = localStorage.getItem('sbx_token') || localStorage.getItem('secubox_token');
        const headers = { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' };

        const categoryDescriptions = {
            sqli: 'SQL Injection attacks',
            xss: 'Cross-Site Scripting',
            cmdi: 'Command Injection',
            traversal: 'Path Traversal',
            ssrf: 'Server-Side Request Forgery',
            xxe: 'XML External Entity',
            ldap: 'LDAP Injection',
            log4shell: 'Log4Shell / JNDI',
            scanners: 'Security Scanners',
            path_scan: 'Sensitive Path Scans',
            cve_exploits: 'Known CVE Exploits',
            rce: 'Remote Code Execution',
            voip: 'VoIP/SIP Attacks',
            xmpp: 'XMPP Injection'
        };

        async function loadFilters() {
            try {
                const res = await fetch(API + '/waf/rules', { headers });
                const data = await res.json();

                const grid = document.getElementById('filters-grid');
                grid.innerHTML = data.categories.map(cat => `
                    <div class="filter-card ${cat.severity}">
                        <div class="filter-header">
                            <span class="filter-name">${cat.name}</span>
                            <label class="filter-toggle">
                                <input type="checkbox" ${cat.enabled ? 'checked' : ''}
                                       onchange="toggleCategory('${cat.name}', this.checked)">
                                <span class="slider"></span>
                            </label>
                        </div>
                        <p style="margin: 0.5rem 0; font-size: 0.9rem;">
                            ${categoryDescriptions[cat.name] || 'Threat detection patterns'}
                        </p>
                        <div class="filter-meta">
                            <span class="filter-severity ${cat.severity}">${cat.severity}</span>
                            <span>${cat.pattern_count} patterns</span>
                            <span class="filter-hits">Hits: ${cat.hits}</span>
                        </div>
                    </div>
                `).join('');
            } catch (e) {
                showMessage('Failed to load filters', 'error');
            }
        }

        async function toggleCategory(category, enabled) {
            try {
                const res = await fetch(API + '/waf/rules/toggle', {
                    method: 'POST',
                    headers,
                    body: JSON.stringify({ category, enabled })
                });

                if (res.ok) {
                    showMessage(`${category} ${enabled ? 'enabled' : 'disabled'}`, 'success');
                } else {
                    const err = await res.json();
                    showMessage(err.detail || 'Failed to toggle', 'error');
                    loadFilters(); // Reload to reset checkbox
                }
            } catch (e) {
                showMessage('Failed to toggle filter', 'error');
                loadFilters();
            }
        }

        function showMessage(text, type) {
            const el = document.getElementById('message');
            el.textContent = text;
            el.className = 'message ' + type;
            setTimeout(() => { el.className = 'message'; }, 3000);
        }

        loadFilters();
    </script>
</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/www/mitmproxy/filters.html
git commit -m "feat(mitmproxy): Add WebUI filters page"
```

---

### Task 13: README Documentation

**Files:**
- Create: `packages/secubox-mitmproxy/README.md`

- [ ] **Step 1: Create README.md**

```markdown
# secubox-mitmproxy

Web Application Firewall (WAF) for SecuBox using mitmproxy in an LXC container.

## Features

- HTTP traffic inspection for HAProxy-hosted services
- 90+ threat detection patterns (SQLi, XSS, RCE, etc.)
- CrowdSec integration for automatic IP banning
- LXC-isolated mitmproxy instance
- WebUI dashboard with real-time stats

## Architecture

```
Internet → HAProxy → mitmproxy-waf (LXC) → Real Backends
                          ↓
                    threats.log → CrowdSec → Ban
```

## Installation

```bash
apt install secubox-mitmproxy
mitmproxyctl install  # Create LXC container
mitmproxyctl start    # Start WAF
```

## API Endpoints

Base: `/api/v1/mitmproxy`

### Status & Control
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/status` | Container & threat stats |
| POST | `/start` | Start container |
| POST | `/stop` | Stop container |
| POST | `/restart` | Restart container |

### Settings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/settings` | Get configuration |
| POST | `/settings` | Update configuration |

### Threats
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/alerts` | List threats (paginated) |
| GET | `/alerts/stats` | Aggregated statistics |
| POST | `/alerts/clear` | Clear threat log |
| GET | `/bans` | Active CrowdSec bans |
| POST | `/unban` | Remove IP ban |

### HAProxy Integration
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/haproxy/status` | WAF enabled status |
| POST | `/haproxy/enable` | Enable WAF inspection |
| POST | `/haproxy/disable` | Disable WAF |
| POST | `/haproxy/sync` | Sync routes from HAProxy |
| GET | `/routes` | Current route mappings |

### WAF Rules
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/waf/rules` | List rule categories |
| POST | `/waf/rules/toggle` | Enable/disable category |
| GET | `/waf/rules/stats` | Per-category stats |

## Configuration

File: `/etc/secubox/mitmproxy.toml`

```toml
[container]
name = "mitmproxy-waf"
memory_limit = "256M"

[proxy]
listen_port = 8890
web_port = 8091

[haproxy]
enabled = true

[autoban]
enabled = true
sensitivity = "moderate"
ban_duration = "4h"
```

## Detection Categories

| Category | Severity | Description |
|----------|----------|-------------|
| sqli | critical | SQL Injection |
| xss | high | Cross-Site Scripting |
| cmdi | critical | Command Injection |
| traversal | high | Path Traversal |
| ssrf | critical | Server-Side Request Forgery |
| log4shell | critical | Log4Shell / JNDI |
| scanners | medium | Security Scanner Detection |

## CLI Commands

```bash
mitmproxyctl install   # Create LXC container
mitmproxyctl start     # Start container
mitmproxyctl stop      # Stop container
mitmproxyctl status    # Show status
mitmproxyctl logs      # View logs
mitmproxyctl destroy --force  # Remove container
```

## File Locations

| File | Purpose |
|------|---------|
| `/etc/secubox/mitmproxy.toml` | Configuration |
| `/srv/mitmproxy-waf/data/threats.log` | Threat log (JSONL) |
| `/srv/mitmproxy-waf/data/routes.json` | HAProxy routes |
| `/srv/mitmproxy-waf/data/waf-rules.json` | Rule definitions |

## WebUI

- Status: `/mitmproxy/status.html`
- Settings: `/mitmproxy/settings.html`
- Filters: `/mitmproxy/filters.html`

## Dependencies

- secubox-core
- secubox-haproxy
- lxc, lxc-templates
- python3-uvicorn, python3-toml

## License

Proprietary - CyberMind.fr
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mitmproxy/README.md
git commit -m "docs(mitmproxy): Add README documentation"
```

---

### Task 14: Nginx Configuration

**Files:**
- Create: `packages/secubox-mitmproxy/nginx/mitmproxy.conf`

- [ ] **Step 1: Create nginx/mitmproxy.conf**

```nginx
# SecuBox Mitmproxy WAF - Nginx configuration
# Include in /etc/nginx/secubox.d/

location /api/v1/mitmproxy/ {
    proxy_pass http://unix:/run/secubox/mitmproxy.sock;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /mitmproxy/ {
    alias /usr/share/secubox/www/mitmproxy/;
    index index.html;
    try_files $uri $uri/ =404;
}
```

- [ ] **Step 2: Update debian/rules to install nginx config**

Add to `override_dh_auto_install`:
```makefile
	install -d $(CURDIR)/debian/secubox-mitmproxy/etc/nginx/secubox.d
	install -m 644 nginx/mitmproxy.conf $(CURDIR)/debian/secubox-mitmproxy/etc/nginx/secubox.d/
```

- [ ] **Step 3: Create nginx directory and commit**

```bash
mkdir -p packages/secubox-mitmproxy/nginx
git add packages/secubox-mitmproxy/nginx/
git add packages/secubox-mitmproxy/debian/rules
git commit -m "feat(mitmproxy): Add nginx configuration"
```

---

### Task 15: Final Integration and Testing

**Files:**
- Modify: `packages/secubox-mitmproxy/crowdsec/secubox-waf.yaml` (copy to correct location in postinst)

- [ ] **Step 1: Verify all files exist**

```bash
ls -la packages/secubox-mitmproxy/
ls -la packages/secubox-mitmproxy/api/
ls -la packages/secubox-mitmproxy/api/routers/
ls -la packages/secubox-mitmproxy/www/mitmproxy/
ls -la packages/secubox-mitmproxy/debian/
```

- [ ] **Step 2: Create crowdsec directory and copy yaml**

```bash
mkdir -p packages/secubox-mitmproxy/crowdsec
# crowdsec/secubox-waf.yaml already created in Task 2
```

- [ ] **Step 3: Update debian/rules for crowdsec**

Add to `override_dh_auto_install`:
```makefile
	install -d $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/mitmproxy/crowdsec
	install -m 644 crowdsec/secubox-waf.yaml $(CURDIR)/debian/secubox-mitmproxy/usr/share/secubox/mitmproxy/crowdsec/
```

- [ ] **Step 4: Final commit**

```bash
git add packages/secubox-mitmproxy/
git commit -m "feat(mitmproxy): Complete package integration"
```

- [ ] **Step 5: Build package**

```bash
cd packages/secubox-mitmproxy
dpkg-buildpackage -us -uc -b
```

Expected: `.deb` file created without errors

- [ ] **Step 6: Update HISTORY.md**

Add Session 90 entry documenting the mitmproxy WAF migration.

```bash
git add .claude/HISTORY.md
git commit -m "docs(history): Document Session 90 mitmproxy WAF migration"
```

---

## Testing Checklist

After implementation:

- [ ] Package builds without errors
- [ ] `mitmproxyctl install` creates LXC container
- [ ] `mitmproxyctl start` starts container and mitmproxy
- [ ] API `/health` endpoint responds
- [ ] API `/status` shows container state
- [ ] WebUI status page loads with sidebar
- [ ] WebUI settings page saves configuration
- [ ] WebUI filters page toggles categories
- [ ] HAProxy enable routes traffic through WAF
- [ ] Threat detection logs to threats.log
- [ ] CrowdSec acquisition reads threat log
