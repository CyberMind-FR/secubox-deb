<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

## Testing Notes

- **Virtualization testing**: Use VirtualBox only (not QEMU)

---

## Wiki Sync Workflow

GitHub wiki is a **separate repository** from the main project. Files in `wiki/` folder must be synced manually.

### Quick Command
```bash
# Sync and push wiki to GitHub
bash scripts/sync-wiki.sh -p -m "Add Eye-Remote docs"

# Dry run (preview changes)
bash scripts/sync-wiki.sh -n
```

### Manual Workflow
```bash
# 1. Clone wiki repo
git clone git@github.com:CyberMind-FR/secubox-deb.wiki.git /tmp/wiki

# 2. Copy files
cp wiki/*.md /tmp/wiki/

# 3. Commit and push
cd /tmp/wiki
git add -A && git commit -m "Update wiki" && git push
```

### When to Sync
- After adding/editing any `wiki/*.md` file
- After bumping version in `wiki/_Sidebar.md`
- Before release (ensure docs match release)

### Red Links
If wiki links show as red on GitHub:
1. Verify file exists in `wiki/` folder
2. Run `scripts/sync-wiki.sh -p` to push to wiki repo
3. Check case sensitivity (GitHub wiki is case-sensitive)

---

## DSA Switch Loop Fix (ESPRESSObin)

**Problem:** mv88e6xxx driver infinite loop during boot
**Root Cause:** Live kernel has mv88e6xxx built-in (not module)
**Solution:** Use BOTH blacklists:
```bash
modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init
```

**Where to apply:**
- `boot.scr` — U-Boot boot script
- `extlinux/extlinux.conf` — fallback config
- `board/*/boot*.cmd` — source files

---

## OpenWrt SecuBox Analysis (2026-05-02)

**Source device:** C3BOX @ 192.168.255.1

### System Info

| Component | Details |
|-----------|---------|
| **OS** | OpenWrt 24.10.5 (r29087-d9c5716d1d) |
| **Kernel** | 6.6.119 aarch64 |
| **Board** | mvebu/cortexa72 (MOCHAbin Armada 7040) |
| **Hostname** | C3BOX |
| **RAM** | 8GB (3GB used, 5GB available) |
| **Swap** | 4GB (unused) |
| **Storage** | 14.6GB overlay (73%), 915GB /srv (97%), 1.8TB /mnt/MUSIC (96%) |

### Installed Packages

| Category | Count | Examples |
|----------|-------|----------|
| **luci-app-*** | ~55 | secubox, crowdsec-dashboard, network-modes, vhost-manager |
| **secubox-app-*** | ~45 | haproxy, mitmproxy, localai, streamlit, gitea |
| **RPCD backends** | ~100 | /usr/libexec/rpcd/luci.* shell scripts |

### LXC Containers (30 total)

**Running (14):**
- domoticz, gitea, jabber, lyrion, mailserver, matrix
- mitmproxy-in, nextcloud, peertube, roundcube, streamlit, voip

**Stopped (16):**
- glances, gotosocial, **haproxy** (was broken), hexojs, jellyfin
- jitsi, magicmirror2, maltego, nextcloud-talk, nzbhydra
- photoprism, picobrew, qbittorrent, sabnzbd, sherlock, simplex, webtorrent, zigbee2mqtt

### Network Configuration

```
br-lan:  192.168.255.1/24 (lan0-lan3 bridged)
br-wan:  DHCP (eth0+eth2 bridged)
wg0/1/2: WireGuard VPN (10.10.0.1/24)
yggdrasil: Overlay mesh network
docker0: Docker bridge (disabled)
```

### Security Stack

| Layer | Component | Status |
|-------|-----------|--------|
| **Firewall** | nftables (fw4) | DEFAULT DROP, input/forward chains |
| **IDS** | CrowdSec | Running (PID 18930), enrolled |
| **Bouncer** | crowdsec-firewall-bouncer | Enabled, 10s update freq |
| **WAF** | mitmproxy-in (LXC) | HAProxy backend, autoban enabled |
| **DPI** | Dual-stream (nDPId + netifyd) | LAN + TAP correlation |
| **DNS** | AdGuardHome + BIND | Running |

### Key UCI Configs

**Main SecuBox config** (`/etc/config/secubox`):
- Device ID: `1caea1be3aa2b79d`
- Base domain: `gk2.secubox.in`
- Local domain: `sb.local`
- Mesh: enabled (edge role, 10.42.0.0/16)
- AI: disabled
- Containers: haproxy, mitmproxy-in, streamlit
- Streamlit apps: 12 instances (ports 8501-8520)
- Metablogizer blogs: 14 sites (ports 8900-8947)

**DPI Dual config** (`/etc/config/dpi-dual`):
- Mode: dual (MITM + TAP)
- Correlation: enabled (60s window)
- Auto-ban: disabled (threshold 80)
- LAN tracking: clients, destinations, protocols

**Mitmproxy config** (`/etc/config/mitmproxy`):
- Instance "in": WAF/Reverse Proxy (port 8890)
- HAProxy router: enabled
- Autoban: 4h duration, high severity
- WAF rules: SQLi, XSS, LFI, RCE, CVE-2024, scanners

### RPCD Backend Pattern

Example from `luci.glances`:
```sh
#!/bin/sh
. /lib/functions.sh
. /usr/share/libubox/jshn.sh

get_status() {
    # Check LXC container status
    lxc_state=$(lxc-info -n "$LXC_NAME" -s 2>/dev/null | grep -oE 'RUNNING|STOPPED')
    # Read UCI config
    local enabled=$(uci -q get glances.main.enabled || echo "0")
    # Output JSON
    cat <<EOF
    { "running": true, "enabled": true, ... }
EOF
}

case "$1" in
    list) method_list ;;
    call) case "$2" in
        status) method_status ;;
        get_config) method_get_config ;;
    esac ;;
esac
```

**Key patterns for migration:**
- Shell scripts using `jshn.sh` for JSON output
- UCI config reads via `uci -q get`
- LXC container management via `lxc-info`, `lxc-start`
- Service checks via `pgrep`
- Caching to `/tmp/secubox/*.json`

### HAProxy Fix (2026-05-02)

**Problem:** HAProxy container wouldn't start
**Root cause:** Invalid certificate references in `/srv/haproxy/certs/certs.list`
```
/opt/haproxy/certs/cyberzine.maegia.tv.fullchain.pem  # FILE MISSING
/opt/haproxy/certs/devel.maegia.tv.fullchain.pem     # FILE MISSING
```

**Fix:**
```bash
sed -i "/\.fullchain\.pem/d" /srv/haproxy/certs/certs.list
lxc-start -n haproxy
```

### Services for Debian Migration Priority

Based on this analysis, the running services to prioritize:

1. **secubox-core** — orchestration daemon
2. **crowdsec** + bouncer — IDS/IPS
3. **haproxy** (LXC) — TLS termination, routing
4. **mitmproxy-in** (LXC) — WAF inspection
5. **dpi-dual** (nDPId + netifyd) — traffic analysis
6. **uhttpd** — LuCI web server
7. **streamlit** (LXC) — dashboard apps
8. **metablogizer** — static site generator

### Frontend Structure

LuCI views in `/www/luci-static/resources/view/secubox/`:
- `hub.js` (51KB) — main dashboard
- `apps.js` (149KB) — app store
- `dashboard.js` (15KB) — status overview
- `services.js` (23KB) — service management
- `mesh.js` (17KB) — P2P mesh

Static assets in `/www/luci-static/secubox/`:
- `cascade.css` (28KB) — main stylesheet
- `index.html` (82KB) — standalone dashboard
- `crt-engine.js` — CRT terminal effects

---

## Double-Buffer Pre-Cache Pattern with Lock File Protection (2026-05-09)

### Problem
Background cache refresh tasks in FastAPI can create **phantom processes** when:
1. Service restarts while a refresh is running
2. Multiple uvicorn workers spawn concurrent refreshes
3. No timeout on blocking operations causes task to hang indefinitely

### Solution: Lock File + Guards + Timeout

```python
import asyncio
import concurrent.futures
from pathlib import Path

LOCK_FILE = Path("/run/secubox/<module>-cache.lock")
_refresh_running = False  # In-process guard

def _acquire_lock() -> bool:
    """Try to acquire the lock file. Returns True if acquired."""
    try:
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        if LOCK_FILE.exists():
            try:
                pid = int(LOCK_FILE.read_text().strip())
                import os
                os.kill(pid, 0)  # Check if process alive
                return False  # Another process holds lock
            except (ValueError, ProcessLookupError, OSError):
                LOCK_FILE.unlink(missing_ok=True)  # Stale lock
        import os
        LOCK_FILE.write_text(str(os.getpid()))
        return True
    except Exception:
        return False

def _release_lock():
    """Release the lock file."""
    LOCK_FILE.unlink(missing_ok=True)

async def _refresh_all_caches():
    """Background task with triple protection."""
    global _refresh_running

    while True:
        # Guard 1: In-process concurrency check
        if _refresh_running:
            await asyncio.sleep(30)
            continue

        _refresh_running = True
        try:
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                futures = [
                    loop.run_in_executor(pool, _compute_status_sync),
                    loop.run_in_executor(pool, _compute_metrics_sync),
                ]
                # Guard 2: Timeout prevents infinite hang
                results = await asyncio.wait_for(
                    asyncio.gather(*futures, return_exceptions=True),
                    timeout=25  # Must complete before next 30s cycle
                )
            # Update caches...
        except asyncio.TimeoutError:
            log.warning("Cache refresh timed out - skipping cycle")
        except Exception as e:
            log.error("Cache refresh failed: %s", e)
        finally:
            _refresh_running = False

        await asyncio.sleep(30)

async def start_cache_refresh():
    """Start with lock file protection."""
    # Guard 3: Cross-process lock file
    if not _acquire_lock():
        log.warning("Another process holds cache lock - using file cache only")
        # Load from disk cache for instant responses
        return

    # Load file caches for instant startup
    _status_cache = _load_cache_from_file(STATUS_CACHE_FILE)

    asyncio.create_task(_refresh_all_caches())

async def stop_cache_refresh():
    """Cleanup on shutdown."""
    _release_lock()
```

### Key Points

| Protection | Purpose | Location |
|------------|---------|----------|
| `_refresh_running` | Prevents in-process overlap | `_refresh_all_caches()` |
| `wait_for(timeout=25)` | Kills hung operations | `_refresh_all_caches()` |
| Lock file (`/run/...`) | Prevents cross-process overlap | `start_cache_refresh()` |
| PID check | Detects stale locks from crashed processes | `_acquire_lock()` |

### When to Use

- **Always** for stats-heavy endpoints (CPU, memory, disk, network)
- **Always** when subprocess calls may hang (cscli, nft, ss)
- **Always** when data can be 30-60s stale without impact
- **Never** for real-time actions (start/stop/restart/ban)

### Implementation in SecuBox

Applied to:
- `secubox-crowdsec/api/routers/status.py` — CrowdSec status/metrics/hub
- `secubox-system/api/main.py` — System stats (planned)
