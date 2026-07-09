# OpenClaw Dedicated-LXC Scanner — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secubox-openclaw` a working OSINT + active-scan module whose toolchain runs in a dedicated sandboxed LXC container, driven by a privileged `openclawctl` helper and an aggregator-safe (plain-`def`, cached, async-job) API with a wired, hardened dashboard.

**Architecture:** A persistent `openclaw` LXC (debootstrap minbase bookworm, `br-lxc`, `10.100.0.41`) is a **stateless tool-runner** holding `nmap`/NSE + `dig`/`whois`/`curl`. The host module (mounted in-process by `secubox-aggregator`) validates + enforces policy, spawns **detached** scan workers that `lxc-attach` the tools and write results to host-side JSON, and serves a nextcloud-style dashboard. No handler blocks the shared aggregator loop.

**Tech Stack:** bash (`openclawctl`), Python 3.11 / FastAPI (`api/main.py`), pytest, LXC + debootstrap, vanilla HTML/JS dashboard, Debian packaging (debhelper 13).

## Global Constraints

- **LXC path:** `/data/lxc` (canonical on SecuBox boards). Container dir `/data/lxc/openclaw/`, rootfs `/data/lxc/openclaw/rootfs`.
- **Container:** name `openclaw`, IP `10.100.0.41/24`, gateway `10.100.0.1`, bridge `br-lxc`. `.41` is verified free (`.30` is matrix).
- **Toolchain in container:** `nmap` (+ NSE), `dnsutils`, `whois`, `curl`, `ca-certificates`. Host adds `debootstrap`, `lxc` deps only — scan tools live in the container, never on the host.
- **Privilege:** API runs as `secubox` under the aggregator (`NoNewPrivileges=no`). The ONLY privileged surface is `sudo -n /usr/sbin/openclawctl`, granted by `/etc/sudoers.d/secubox-openclaw`: `secubox ALL=(root) NOPASSWD: /usr/sbin/openclawctl` (`0440 root:root`).
- **Aggregator safety:** every FastAPI route handler is plain `def` (threadpooled) — never `async def`. No handler runs a scan inline; scans are detached workers. `/status` and `/scans`-heavy reads use the single-flight + stale-while-revalidate cache.
- **Injection:** targets validated `^[A-Za-z0-9._:@/-]+$` and scan_id `^[a-f0-9]{8}$` **before** any shell/`lxc-attach`; inner `sh -c '…"$1"'` takes positional args, never string interpolation. Same rule in bash (`openclawctl`) and Python (`api/main.py`).
- **Target policy:** passive OSINT unrestricted; active `nmap` allowed for RFC1918/LAN + box-owned domains, else requires `authorized: true` (409 otherwise) and every active scan is appended to `/var/log/secubox/audit.log`.
- **Paths that must NOT be re-chowned/loosened:** `/run/secubox` (1777 root:root), `/etc/secubox` (0755), `/var/log/secubox` (0755) parents. Scan store `/var/lib/secubox/openclaw/scans/` owned `secubox`, created with `mkdir(parents=True, exist_ok=True)`.
- **Copy/naming:** module id `openclaw`; API base `/api/v1/openclaw`; dashboard at `/openclaw/`.
- **Reference implementation (verbatim-portable pieces):** `/home/reepost/CyberMindStudio/secubox-deb-worktrees/429-secubox-nextcloud-dashboard-api-renvoie/packages/secubox-nextcloud/` — `sbin/nextcloudctl` (lxc helpers, debootstrap), `api/main.py` (`ctl()`, `_cached`), `tests/conftest.py`, `debian/{secubox-nextcloud.sudoers,postinst,rules}`.
- **Board access:** `ssh root@192.168.1.200`. Do NOT restart the aggregator repeatedly; one restart picks up new in-process code.

---

## File Structure

- `packages/secubox-openclaw/sbin/openclawctl` — **new** privileged bash helper (install/start/stop/status/scan/selftest + guards).
- `packages/secubox-openclaw/api/main.py` — **rewrite**: `ctl()`, plain-`def` handlers, validators, target policy + audit, async-job scan model, single-flight/stale-while-revalidate `/status` cache; delete the async/asyncio subprocess machinery.
- `packages/secubox-openclaw/tests/{conftest.py,test_policy.py,test_scans.py,test_status_cache.py}` — **new** pytest suite (stub `ctl`).
- `packages/secubox-openclaw/debian/secubox-openclaw.sudoers` — **new**.
- `packages/secubox-openclaw/debian/{postinst,rules,control}` — **modify** (visudo check, install sbin+sudoers+conf, Depends).
- `packages/secubox-openclaw/conf/openclaw.toml.example` — **new**.
- `packages/secubox-openclaw/www/openclaw/index.html` — **rewrite/wire + harden**.

---

### Task 1: `openclawctl` — control plane core (guards, lxc helpers, status, start/stop, selftest, dispatch)

**Files:**
- Create: `packages/secubox-openclaw/sbin/openclawctl`
- Test: `packages/secubox-openclaw/tests/test_openclawctl_guards.sh`

**Interfaces:**
- Produces (consumed by Tasks 2, 3, 4): `openclawctl status --json` → `{"running":bool,"installed":bool,"ip":"10.100.0.41","tools":{"nmap":bool,"dig":bool,"whois":bool,"curl":bool}}`; exit-code-0 helpers `openclawctl start|stop|selftest`; bash guards `_valid_target`, `_valid_scanid`, `_valid_type`.

- [ ] **Step 1: Write the failing guard test**

Create `packages/secubox-openclaw/tests/test_openclawctl_guards.sh`:
```bash
#!/bin/bash
# Exercises openclawctl's injection guards via the hidden __guard entrypoint.
set -u
CTL="$(dirname "$0")/../sbin/openclawctl"
fail=0
ok()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && echo "PASS accept $1 '$2'" || { echo "FAIL should-accept $1 '$2'"; fail=1; }; }
no()  { "$CTL" __guard "$1" "$2" >/dev/null 2>&1 && { echo "FAIL should-reject $1 '$2'"; fail=1; } || echo "PASS reject $1 '$2'"; }
ok target "example.com";        ok target "192.168.1.10"; ok target "10.0.0.0/24"; ok target "a@b.com"
no target 'a;rm -rf /';         no target 'a b';          no target "$(printf 'a\nb')"
ok scanid "a1b2c3d4";           no scanid "XYZ";          no scanid "a1b2c3d4e5"
ok type domain; ok type ip; ok type email; ok type dns; ok type whois; ok type certs; ok type ports; no type pwn
exit $fail
```

- [ ] **Step 2: Run it — expect failure (script missing)**

Run: `bash packages/secubox-openclaw/tests/test_openclawctl_guards.sh`
Expected: FAIL / not found (openclawctl doesn't exist yet).

- [ ] **Step 3: Implement `openclawctl` core**

Create `packages/secubox-openclaw/sbin/openclawctl` (mode 755):
```bash
#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox OpenClaw controller — privileged LXC tool-runner control plane.
# The ONLY privileged surface for the openclaw module (invoked via sudo).
set -uo pipefail

CONFIG_FILE="/etc/secubox/openclaw.toml"
LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
CONTAINER="${SECUBOX_LXC_NAME:-openclaw}"
LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
LXC_IP="${SECUBOX_LXC_IP:-10.100.0.41}"
LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
SCANS_DIR="${SECUBOX_OPENCLAW_SCANS:-/var/lib/secubox/openclaw/scans}"

err() { echo "[ERROR] $*" >&2; }

# ---- injection guards (defense in depth; API validates too) ----
_valid_target() { [[ "$1" =~ ^[A-Za-z0-9._:@/-]+$ ]]; }
_valid_scanid() { [[ "$1" =~ ^[a-f0-9]{8}$ ]]; }
_valid_type()   { case "$1" in domain|ip|email|dns|whois|certs|ports) return 0;; *) return 1;; esac; }

# ---- lxc helpers (mirror nextcloudctl) ----
lxc_running() { lxc-info -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null | grep -q "State:.*RUNNING"; }
lxc_exists()  { [ -d "$LXC_PATH/$CONTAINER/rootfs" ]; }
# Run a command in the container. Extra args after the command string are
# passed as positional $1.. to `sh -c` — NEVER interpolate targets into the
# command string.
lxc_attach()  { local cmd="$1"; shift; lxc-attach -n "$CONTAINER" -P "$LXC_PATH" -- sh -c "$cmd" _ "$@"; }

has_tool() { lxc_running && lxc_attach 'command -v "$1" >/dev/null' "$1"; }

cmd_status() {
    local running=false installed=false
    lxc_exists && installed=true
    lxc_running && running=true
    local nmap=false dig=false whois=false curl=false
    if [ "$running" = true ]; then
        has_tool nmap  && nmap=true
        has_tool dig   && dig=true
        has_tool whois && whois=true
        has_tool curl  && curl=true
    fi
    printf '{"running":%s,"installed":%s,"ip":"%s","tools":{"nmap":%s,"dig":%s,"whois":%s,"curl":%s}}\n' \
        "$running" "$installed" "$LXC_IP" "$nmap" "$dig" "$whois" "$curl"
}

cmd_start() { lxc_exists || { err "not installed"; return 1; }; lxc-start -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null; sleep 1; lxc_running; }
cmd_stop()  { lxc-stop -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null; ! lxc_running; }
cmd_selftest() { lxc_running || { err "container not running"; return 1; }; lxc_attach 'nmap --version && dig -v 2>&1 | head -1 && whois --version 2>&1 | head -1'; }

usage() { echo "usage: openclawctl {install|start|stop|status [--json]|scan <type> <target> <id>|selftest}" >&2; }

case "${1:-}" in
    __guard) # hidden: validate a value, exit 0/1 (for tests)
        case "${2:-}" in
            target) _valid_target "${3:-}";;
            scanid) _valid_scanid "${3:-}";;
            type)   _valid_type "${3:-}";;
            *) exit 2;;
        esac ;;
    status)   shift; cmd_status ;;
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    selftest) cmd_selftest ;;
    install)  cmd_install ;;          # Task 2
    scan)     shift; cmd_scan "$@" ;; # Task 3
    *) usage; exit 2 ;;
esac
```
(`cmd_install`/`cmd_scan` are added in Tasks 2/3; the dispatch references them now so the file's shape is stable — running `install`/`scan` before those tasks errors with "command not found", which is fine for this task's tests.)

- [ ] **Step 4: Run guard test + syntax — expect PASS**

Run: `bash -n packages/secubox-openclaw/sbin/openclawctl && chmod +x packages/secubox-openclaw/sbin/openclawctl && bash packages/secubox-openclaw/tests/test_openclawctl_guards.sh`
Expected: `bash -n` clean; every guard line `PASS`.

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-openclaw/sbin/openclawctl packages/secubox-openclaw/tests/test_openclawctl_guards.sh
git commit -m "feat(openclaw): openclawctl control-plane core (guards, status --json, start/stop, selftest)"
```

---

### Task 2: `openclawctl install` — debootstrap the sandboxed container

**Files:**
- Modify: `packages/secubox-openclaw/sbin/openclawctl` (add `cmd_install`)

**Interfaces:**
- Consumes: Task 1 vars/helpers. Produces: `openclawctl install` builds `/data/lxc/openclaw/rootfs`, writes LXC config, installs the toolchain, starts the container. Idempotent (re-run is a no-op if `lxc_exists` && tools present).

- [ ] **Step 1: Implement `cmd_install`** (insert above the `usage()` line)
```bash
_write_lxc_config() {
    cat > "$LXC_PATH/$CONTAINER/config" <<EOF
lxc.uts.name = $CONTAINER
lxc.rootfs.path = dir:$LXC_PATH/$CONTAINER/rootfs
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.include = /usr/share/lxc/config/common.conf
lxc.apparmor.profile = generated
lxc.apparmor.allow_nesting = 0
EOF
}

cmd_install() {
    [ "$(id -u)" -eq 0 ] || { err "root required"; return 1; }
    mkdir -p "$LXC_PATH/$CONTAINER" "$SCANS_DIR"
    if [ ! -x "$LXC_PATH/$CONTAINER/rootfs/bin/bash" ]; then
        echo "[openclaw] debootstrapping bookworm rootfs…"
        debootstrap --variant=minbase \
            --include=systemd,systemd-sysv,dbus,ca-certificates,iproute2 \
            bookworm "$LXC_PATH/$CONTAINER/rootfs" http://deb.debian.org/debian || { err "debootstrap failed"; return 1; }
    fi
    echo "$CONTAINER" > "$LXC_PATH/$CONTAINER/rootfs/etc/hostname"
    printf 'nameserver %s\nnameserver 1.1.1.1\n' "$LXC_GW" > "$LXC_PATH/$CONTAINER/rootfs/etc/resolv.conf"
    _write_lxc_config
    lxc_running || lxc-start -n "$CONTAINER" -P "$LXC_PATH" 2>/dev/null
    sleep 2
    echo "[openclaw] installing toolchain…"
    lxc_attach 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y --no-install-recommends nmap ndiff dnsutils whois curl ca-certificates >/dev/null 2>&1'
    lxc_attach 'command -v nmap >/dev/null && command -v dig >/dev/null && command -v whois >/dev/null' \
        && echo "[openclaw] install complete" || { err "toolchain missing after install"; return 1; }
}
```

- [ ] **Step 2: Syntax check**

Run: `bash -n packages/secubox-openclaw/sbin/openclawctl`
Expected: clean.

- [ ] **Step 3: Live install on gk2** (integration — needs the board)

Run:
```bash
scp packages/secubox-openclaw/sbin/openclawctl root@192.168.1.200:/usr/sbin/openclawctl
ssh root@192.168.1.200 'chmod +x /usr/sbin/openclawctl && /usr/sbin/openclawctl install && /usr/sbin/openclawctl status --json && /usr/sbin/openclawctl selftest'
```
Expected: `status --json` shows `"running":true,"installed":true` and all four tools `true`; `selftest` prints nmap/dig/whois versions.

- [ ] **Step 4: Commit**
```bash
git add packages/secubox-openclaw/sbin/openclawctl
git commit -m "feat(openclaw): openclawctl install (debootstrap sandbox + nmap/dig/whois/curl toolchain)"
```

---

### Task 3: `openclawctl scan` — run tools in-container, write host-side result JSON

**Files:**
- Modify: `packages/secubox-openclaw/sbin/openclawctl` (add `cmd_scan` + helpers)

**Interfaces:**
- Consumes: Task 1 guards/`lxc_attach`, Task 2 container. Produces: `openclawctl scan <type> <target> <id>` writes `"$SCANS_DIR/<id>.json"` with `{"id","type","target","status":"completed|failed","started_at","finished_at","results":{...},"error":null}`; exit 0 on success.

- [ ] **Step 1: Implement `cmd_scan`** (insert above `usage()`)
```bash
# jq is available on the HOST (SecuBox base). Build the record on the host from
# captured container stdout; never let the target reach a shell unquoted.
_scan_write() { # $1=id $2=json-object-of-record
    local f="$SCANS_DIR/$1.json"; mkdir -p "$SCANS_DIR"; printf '%s\n' "$2" > "$f"; chmod 640 "$f"
}

cmd_scan() {
    local type="${1:-}" target="${2:-}" id="${3:-}"
    _valid_type "$type"    || { err "bad type"; return 2; }
    _valid_target "$target"|| { err "bad target"; return 2; }
    _valid_scanid "$id"    || { err "bad id"; return 2; }
    lxc_running || { _scan_write "$id" "$(jq -nc --arg i "$id" --arg t "$type" --arg g "$target" '{id:$i,type:$t,target:$g,status:"failed",error:"container not running",results:null}')"; return 1; }
    local started; started="$(date -u +%FT%TZ)"
    local raw rc
    case "$type" in
        dns)    raw="$(lxc_attach 'dig +noall +answer ANY "$1"' "$target" 2>&1)"; rc=$? ;;
        whois)  raw="$(lxc_attach 'whois -- "$1"' "$target" 2>&1)"; rc=$? ;;
        certs)  raw="$(lxc_attach 'curl -s --max-time 20 "https://crt.sh/?q=$1&output=json"' "$target" 2>&1)"; rc=$? ;;
        ports)  raw="$(lxc_attach 'nmap -Pn -T4 --top-ports 100 -oG - "$1"' "$target" 2>&1)"; rc=$? ;;
        ip)     raw="$(lxc_attach 'nmap -Pn -T4 -sV --top-ports 200 "$1"' "$target" 2>&1)"; rc=$? ;;
        domain) raw="$(lxc_attach 'echo "== DNS =="; dig +noall +answer ANY "$1"; echo "== WHOIS =="; whois -- "$1" 2>/dev/null | head -40; echo "== CERTS =="; curl -s --max-time 20 "https://crt.sh/?q=$1&output=json" | head -c 20000' "$target" 2>&1)"; rc=$? ;;
        email)  raw="$(lxc_attach 'd="${1#*@}"; echo "== MX =="; dig +short MX "$d"; echo "== SPF =="; dig +short TXT "$d" | grep -i spf' "$target" 2>&1)"; rc=$? ;;
        *) err "unhandled type"; return 2 ;;
    esac
    local status="completed"; [ "$rc" -ne 0 ] && status="failed"
    _scan_write "$id" "$(jq -nc --arg i "$id" --arg t "$type" --arg g "$target" --arg s "$status" \
        --arg st "$started" --arg fi "$(date -u +%FT%TZ)" --arg raw "$raw" \
        '{id:$i,type:$t,target:$g,status:$s,started_at:$st,finished_at:$fi,results:{raw:$raw},error:(if $s=="failed" then "tool exit non-zero" else null end)}')"
    [ "$status" = completed ]
}
```

- [ ] **Step 2: Syntax check** — `bash -n packages/secubox-openclaw/sbin/openclawctl` → clean.

- [ ] **Step 3: Live scan round-trip on gk2**
```bash
scp packages/secubox-openclaw/sbin/openclawctl root@192.168.1.200:/usr/sbin/openclawctl
ssh root@192.168.1.200 'chmod +x /usr/sbin/openclawctl; /usr/sbin/openclawctl scan dns example.com aaaa1111; cat /var/lib/secubox/openclaw/scans/aaaa1111.json; echo; /usr/sbin/openclawctl scan ports 127.0.0.1 bbbb2222; jq .status /var/lib/secubox/openclaw/scans/bbbb2222.json'
```
Expected: `aaaa1111.json` is valid JSON `"status":"completed"` with `results.raw` containing DNS answers; ports scan completes. Injection: `openclawctl scan dns 'a;id' cccc3333` → `bad target`, no file written.

- [ ] **Step 4: Commit**
```bash
git add packages/secubox-openclaw/sbin/openclawctl
git commit -m "feat(openclaw): openclawctl scan — run tools in-container, write host-side result JSON"
```

---

### Task 4: API core — `ctl()`, validators, target classification, cached `def` status/health/config

**Files:**
- Rewrite (part 1): `packages/secubox-openclaw/api/main.py`
- Create: `packages/secubox-openclaw/tests/conftest.py`, `packages/secubox-openclaw/tests/test_status_cache.py`, `packages/secubox-openclaw/tests/test_policy.py`

**Interfaces:**
- Produces (consumed by Task 5): `ctl(subcmd:list, timeout=60, stdin=None) -> (ok,out,err)`; `_valid_target(str)->bool`, `_valid_scanid(str)->bool`; `_is_local_or_owned(target:str)->bool`; `_cached(key,ttl,producer)`, `_invalidate_stats()`; `lxc_running()->bool`; `_require_installed()`. Endpoints `GET /status`, `GET /health`, `GET/POST /config`.

- [ ] **Step 1: Write conftest + failing tests**

`tests/conftest.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Seed secubox_core config so `api.main` imports without reading /etc."""
import secubox_core.config as _cfgmod
_cfgmod._CONFIG = {
    "openclaw": {
        "enabled": True,
        "container_name": "openclaw",
        "lxc_ip": "10.100.0.41",
        "owned_domains": ["gk2.secubox.in"],
    },
}
```
`tests/test_policy.py`:
```python
import importlib
def _load(monkeypatch):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m

def test_local_targets_are_owned(monkeypatch):
    m = _load(monkeypatch)
    assert m._is_local_or_owned("192.168.1.10") is True
    assert m._is_local_or_owned("10.0.0.5") is True
    assert m._is_local_or_owned("nc.gk2.secubox.in") is True   # box-owned suffix

def test_external_targets_not_owned(monkeypatch):
    m = _load(monkeypatch)
    assert m._is_local_or_owned("scanme.nmap.org") is False
    assert m._is_local_or_owned("8.8.8.8") is False
```
`tests/test_status_cache.py`:
```python
import importlib
from fastapi.testclient import TestClient
def _load(monkeypatch):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    return m

def test_status_single_flight(monkeypatch):
    m = _load(monkeypatch); calls = {"n": 0}
    def counting(sub, *a, **k):
        if list(sub[:1]) == ["status"]: calls["n"] += 1
        return (True, '{"running":true,"installed":true,"ip":"10.100.0.41","tools":{"nmap":true,"dig":true,"whois":true,"curl":true}}', "")
    monkeypatch.setattr(m, "ctl", counting)
    c = TestClient(m.app)
    c.get("/status"); c.get("/status")
    assert calls["n"] == 1                      # 2nd served from cache
    m._invalidate_stats(); c.get("/status")
    assert calls["n"] == 2
```

- [ ] **Step 2: Run — expect failure** (`ModuleNotFoundError`/attr missing after rewrite start)

Run: `cd packages/secubox-openclaw && PYTHONPATH=../../common:. python3 -m pytest tests/ -q`
Expected: FAIL.

- [ ] **Step 3: Implement `api/main.py` core** (replace the file's top through the status/health/config section; scan endpoints come in Task 5)
```python
"""SecuBox OpenClaw API — OSINT + active scanner driven through a sandboxed LXC.

Every handler is plain `def` (FastAPI threadpools it) — the module is mounted
in-process by the aggregator, so an async handler running subprocess would
freeze the shared loop. Container ops go through `sudo -n openclawctl`.
"""
import re as _re
import os
import json
import time
import ipaddress
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox OpenClaw", version="2.0.0")
config = get_config("openclaw")

CTL = "/usr/sbin/openclawctl"
CONTAINER_IP = config.get("lxc_ip", "10.100.0.41")
DATA_DIR = Path("/var/lib/secubox/openclaw")
SCANS_DIR = DATA_DIR / "scans"
AUDIT_LOG = Path("/var/log/secubox/audit.log")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

_UID_RE = _re.compile(r"^[A-Za-z0-9._:@/-]+$")
_ID_RE = _re.compile(r"^[a-f0-9]{8}$")
OWNED = [d.lower().lstrip(".") for d in config.get("owned_domains", ["gk2.secubox.in"])]


def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "timed out"
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def ctl(subcmd, timeout=60, stdin=None):
    """`sudo -n openclawctl <subcmd...>` — the only privileged path. Fail-safe."""
    cmd = ["sudo", "-n", CTL, *subcmd]
    if stdin is None:
        return run_cmd(cmd, timeout)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin)
        return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # pragma: no cover
        return False, "", str(e)


def _valid_target(t): return bool(t) and bool(_UID_RE.fullmatch(t))
def _valid_scanid(i): return bool(i) and bool(_ID_RE.fullmatch(i))


def _is_local_or_owned(target: str) -> bool:
    """True if target is RFC1918/loopback/link-local (IP or CIDR) or a box-owned
    domain suffix. Used to gate active scans without an explicit authorization."""
    t = target.strip().lower()
    host = t.split("/")[0].split("@")[-1]
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(t, strict=False)
        return net.is_private or net.is_loopback
    except ValueError:
        pass
    return any(host == d or host.endswith("." + d) for d in OWNED)


# ---- single-flight, stale-while-revalidate cache (ported from nextcloud) ----
_STATS_CACHE: dict = {}
_CACHE_LOCKS: dict = {}
_CACHE_LOCKS_GUARD = threading.Lock()

def _cache_lock(key):
    with _CACHE_LOCKS_GUARD:
        return _CACHE_LOCKS.setdefault(key, threading.Lock())

def _cached(key, ttl, producer):
    now = time.monotonic(); hit = _STATS_CACHE.get(key)
    if hit and (now - hit[0]) < ttl:
        return hit[1]
    lock = _cache_lock(key)
    if hit is not None:
        if lock.acquire(blocking=False):
            def _bg():
                try: _STATS_CACHE[key] = (time.monotonic(), producer())
                except Exception: pass
                finally: lock.release()
            threading.Thread(target=_bg, name=f"oc-cache-{key}", daemon=True).start()
        return hit[1]
    with lock:
        hit = _STATS_CACHE.get(key)
        if hit and (time.monotonic() - hit[0]) < ttl:
            return hit[1]
        val = producer(); _STATS_CACHE[key] = (time.monotonic(), val); return val

def _invalidate_stats(): _STATS_CACHE.clear()


def _ctl_status():
    ok, out, _ = ctl(["status", "--json"], timeout=25)
    if not ok:
        return {"running": False, "installed": False, "ip": CONTAINER_IP,
                "tools": {"nmap": False, "dig": False, "whois": False, "curl": False}}
    try:
        return json.loads(out)
    except Exception:
        return {"running": False, "installed": False, "ip": CONTAINER_IP, "tools": {}}

def lxc_running() -> bool:
    return bool(_ctl_status().get("running"))

def _require_installed():
    if not _ctl_status().get("installed"):
        raise HTTPException(409, "OpenClaw container is not installed")


@app.get("/health")
def health():
    return {"status": "ok", "module": "openclaw"}

@app.get("/status")
def status():
    return _cached("status", 15.0, _compute_status)

def _compute_status():
    s = _ctl_status()
    return {"module": "openclaw", "enabled": config.get("enabled", True),
            "running": s.get("running", False), "installed": s.get("installed", False),
            "ip": s.get("ip", CONTAINER_IP), "tools": s.get("tools", {}),
            "total_scans": len(list(SCANS_DIR.glob("*.json")))}

@app.get("/config", dependencies=[Depends(require_jwt)])
def get_config_endpoint():
    return {"enabled": config.get("enabled", True), "owned_domains": OWNED,
            "integrations": {k: bool(config.get(k)) for k in
                             ("shodan_api_key", "censys_api_id", "virustotal_api_key")}}
```

- [ ] **Step 4: Run — expect PASS**

Run: `cd packages/secubox-openclaw && PYTHONPATH=../../common:. python3 -m pytest tests/test_policy.py tests/test_status_cache.py -q`
Expected: PASS (policy + cache). (Scan tests come in Task 5.)

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-openclaw/api/main.py packages/secubox-openclaw/tests/conftest.py packages/secubox-openclaw/tests/test_policy.py packages/secubox-openclaw/tests/test_status_cache.py
git commit -m "feat(openclaw): API core — ctl routing, def+cached status, target classification"
```

---

### Task 5: API scan endpoints — async-job model, target policy + audit, quick lookups

**Files:**
- Modify: `packages/secubox-openclaw/api/main.py` (append scan/lookup endpoints; delete leftover async machinery)
- Create: `packages/secubox-openclaw/tests/test_scans.py`

**Interfaces:**
- Consumes: Task 4 `ctl`, `_valid_target`, `_valid_scanid`, `_is_local_or_owned`, `_require_installed`, `SCANS_DIR`, `AUDIT_LOG`. Produces endpoints: `POST /scan/{domain|ip|email}`, `GET /scans`, `GET /scan/{id}`, `DELETE /scan/{id}`, `GET /dns/{domain}`, `GET /whois/{target}`, `GET /certs/{domain}`, `GET /ports/{ip}`.

- [ ] **Step 1: Write failing scan tests** — `tests/test_scans.py`:
```python
import importlib, json
from fastapi.testclient import TestClient
def _load(monkeypatch, installed=True):
    import api.main as m; importlib.reload(m)
    from secubox_core.auth import require_jwt
    m.app.dependency_overrides[require_jwt] = lambda: {"sub": "admin"}
    monkeypatch.setattr(m, "_ctl_status", lambda: {"running": True, "installed": installed, "ip": "10.100.0.41", "tools": {}})
    return m

def test_external_active_scan_refused_without_authorization(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    r = c.post("/scan/ip", json={"target": "scanme.nmap.org"})
    assert r.status_code == 409

def test_external_active_scan_allowed_when_authorized(monkeypatch):
    m = _load(monkeypatch); spawned = {}
    monkeypatch.setattr(m, "_spawn_worker", lambda t, tgt, i: spawned.update(type=t, target=tgt, id=i))
    c = TestClient(m.app)
    r = c.post("/scan/ip", json={"target": "scanme.nmap.org", "authorized": True})
    assert r.status_code == 200 and r.json()["status"] == "started"
    assert spawned["type"] == "ip"

def test_lan_active_scan_allowed_without_authorization(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/ip", json={"target": "192.168.1.5"}).status_code == 200

def test_passive_domain_scan_always_allowed(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/domain", json={"target": "scanme.nmap.org"}).status_code == 200

def test_bad_target_rejected_400(monkeypatch):
    m = _load(monkeypatch)
    monkeypatch.setattr(m, "_spawn_worker", lambda *a, **k: None)
    c = TestClient(m.app)
    assert c.post("/scan/domain", json={"target": "a;rm -rf /"}).status_code == 400

def test_scan_get_and_delete_id_validated(monkeypatch):
    m = _load(monkeypatch)
    c = TestClient(m.app)
    assert c.get("/scan/NOTHEX99").status_code == 400
    assert c.delete("/scan/../etc").status_code in (400, 404)
```

- [ ] **Step 2: Run — expect failure** — `PYTHONPATH=../../common:. python3 -m pytest tests/test_scans.py -q` → FAIL.

- [ ] **Step 3: Implement scan endpoints** (append to `api/main.py`; also delete any residual `async def`/`asyncio`/`create_subprocess_exec`/`httpx` code from the old file)
```python
class ScanReq(BaseModel):
    target: str
    authorized: bool = False

# domain/email = passive (unrestricted); ip = active (policy-gated)
_ACTIVE_TYPES = {"ip", "ports"}

def _new_id():
    return os.urandom(4).hex()

def _spawn_worker(scan_type: str, target: str, scan_id: str):
    """Detached — runs entirely off the aggregator. openclawctl does the work
    and writes scans/<id>.json. We only record 'pending' first."""
    rec = {"id": scan_id, "type": scan_type, "target": target, "status": "pending",
           "started_at": datetime.now(timezone.utc).isoformat(), "results": None, "error": None}
    (SCANS_DIR / f"{scan_id}.json").write_text(json.dumps(rec))
    subprocess.Popen(["sudo", "-n", CTL, "scan", scan_type, target, scan_id],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)

def _audit(op, scan_type, target, authorized, scan_id):
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT_LOG.open("a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                                "module": "openclaw", "op": op, "operator": op,
                                "type": scan_type, "target": target,
                                "authorized": authorized, "scan_id": scan_id}) + "\n")
    except Exception:  # pragma: no cover - audit must never break a scan
        pass

def _start_scan(scan_type, req: ScanReq, operator: str):
    _require_installed()
    if not _valid_target(req.target):
        raise HTTPException(400, "invalid target")
    if scan_type in _ACTIVE_TYPES and not _is_local_or_owned(req.target) and not req.authorized:
        raise HTTPException(409, "external active scan requires authorized=true")
    scan_id = _new_id()
    if scan_type in _ACTIVE_TYPES:
        _audit(operator, scan_type, req.target, req.authorized, scan_id)
    _spawn_worker(scan_type, req.target, scan_id)
    return {"status": "started", "scan_id": scan_id, "type": scan_type, "target": req.target}

@app.post("/scan/domain", dependencies=[Depends(require_jwt)])
def scan_domain(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("domain", req, claims.get("sub", "?"))

@app.post("/scan/ip", dependencies=[Depends(require_jwt)])
def scan_ip(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("ip", req, claims.get("sub", "?"))

@app.post("/scan/email", dependencies=[Depends(require_jwt)])
def scan_email(req: ScanReq, claims: dict = Depends(require_jwt)):
    return _start_scan("email", req, claims.get("sub", "?"))

@app.get("/scans", dependencies=[Depends(require_jwt)])
def list_scans():
    out = []
    for f in sorted(SCANS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:200]:
        try: out.append(json.loads(f.read_text()))
        except Exception: pass
    return {"scans": out}

@app.get("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
def get_scan(scan_id: str):
    if not _valid_scanid(scan_id):
        raise HTTPException(400, "invalid scan id")
    f = SCANS_DIR / f"{scan_id}.json"
    if not f.exists():
        raise HTTPException(404, "not found")
    return json.loads(f.read_text())

@app.delete("/scan/{scan_id}", dependencies=[Depends(require_jwt)])
def delete_scan(scan_id: str):
    if not _valid_scanid(scan_id):
        raise HTTPException(400, "invalid scan id")
    f = SCANS_DIR / f"{scan_id}.json"
    if f.exists(): f.unlink()
    return {"status": "deleted", "scan_id": scan_id}

def _sync_lookup(scan_type, target):
    _require_installed()
    if not _valid_target(target):
        raise HTTPException(400, "invalid target")
    ok, out, err = ctl(["scan", scan_type, target, "00000000"], timeout=45)
    # the sync path reuses the same helper but we read the record it wrote
    f = SCANS_DIR / "00000000.json"
    if f.exists():
        try: return json.loads(f.read_text())
        except Exception: pass
    return {"status": "failed" if not ok else "completed", "results": {"raw": out or err}}

@app.get("/dns/{domain}", dependencies=[Depends(require_jwt)])
def dns_lookup(domain: str): return _sync_lookup("dns", domain)

@app.get("/whois/{target}", dependencies=[Depends(require_jwt)])
def whois_lookup(target: str): return _sync_lookup("whois", target)

@app.get("/certs/{domain}", dependencies=[Depends(require_jwt)])
def certs_lookup(domain: str): return _sync_lookup("certs", domain)

@app.get("/ports/{ip}", dependencies=[Depends(require_jwt)])
def ports_lookup(ip: str): return _sync_lookup("ports", ip)

@app.post("/install", dependencies=[Depends(require_jwt)])
def install():
    """Build the sandbox container (debootstrap + toolchain) in the background.
    Detached like a scan worker — never runs on the request path."""
    if _ctl_status().get("installed"):
        raise HTTPException(400, "already installed")
    subprocess.Popen(["sudo", "-n", CTL, "install"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     stdin=subprocess.DEVNULL, start_new_session=True)
    _invalidate_stats()
    return {"status": "installing"}
```
Add a test to `tests/test_scans.py`:
```python
def test_install_detached_when_absent(monkeypatch):
    m = _load(monkeypatch, installed=False)
    called = {}
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: called.setdefault("argv", a[0]))
    c = TestClient(m.app)
    r = c.post("/install")
    assert r.status_code == 200 and r.json()["status"] == "installing"
    assert called["argv"][:4] == ["sudo", "-n", m.CTL, "install"]

def test_install_refused_when_present(monkeypatch):
    m = _load(monkeypatch, installed=True)
    assert TestClient(m.app).post("/install").status_code == 400
```
Then remove any remaining old code below/around these (search the file for `async def`, `asyncio`, `create_subprocess_exec`, `httpx`, `BackgroundTasks`, `_run_scan`, `_whois_lookup`, `_port_check` and delete those definitions/imports). Verify: `grep -nE "async def|asyncio|create_subprocess_exec|httpx|BackgroundTasks" api/main.py` → no matches.

- [ ] **Step 4: Run — expect PASS**

Run: `cd packages/secubox-openclaw && PYTHONPATH=../../common:. python3 -m pytest tests/ -q`
Expected: all tests pass; the grep above returns nothing.

- [ ] **Step 5: Commit**
```bash
git add packages/secubox-openclaw/api/main.py packages/secubox-openclaw/tests/test_scans.py
git commit -m "feat(openclaw): async-job scan endpoints + target policy/audit + sync lookups; drop async machinery"
```

---

### Task 6: Packaging — sudoers, postinst visudo, rules install lines, control Depends, toml

**Files:**
- Create: `packages/secubox-openclaw/debian/secubox-openclaw.sudoers`, `packages/secubox-openclaw/conf/openclaw.toml.example`
- Modify: `packages/secubox-openclaw/debian/{postinst,rules,control}`

**Interfaces:** Produces the installed `/usr/sbin/openclawctl`, `/etc/sudoers.d/secubox-openclaw`, `/etc/secubox/openclaw.toml.example`; makes the deb build.

- [ ] **Step 1: sudoers** — `debian/secubox-openclaw.sudoers`:
```
# The aggregator (user secubox) drives the OpenClaw LXC through openclawctl.
# This is the ONLY privileged surface for the module.
secubox ALL=(root) NOPASSWD: /usr/sbin/openclawctl
```

- [ ] **Step 2: toml.example** — `conf/openclaw.toml.example`:
```toml
# /etc/secubox/openclaw.toml — cp from this example.
enabled = true
container_name = "openclaw"
lxc_ip = "10.100.0.41"
# Active nmap scans are auto-allowed for RFC1918/LAN + these owned suffixes;
# any other external active target needs an explicit authorized=true per scan.
owned_domains = ["gk2.secubox.in"]
# Optional OSINT integrations (leave blank to disable). Put real keys in
# /etc/secubox/secrets/ (chmod 600) if you prefer them off the TOML.
# shodan_api_key = ""
# censys_api_id = ""
# virustotal_api_key = ""
```

- [ ] **Step 3: rules** — add to `override_dh_auto_install` (mirror nextcloud rules): install `sbin/*` → `/usr/sbin`, the sudoers → `/etc/sudoers.d/secubox-openclaw` (0440), and `conf/openclaw.toml.example` → `/etc/secubox`:
```make
	install -d $(CURDIR)/debian/secubox-openclaw/usr/sbin
	install -m 755 sbin/openclawctl $(CURDIR)/debian/secubox-openclaw/usr/sbin/openclawctl
	install -d $(CURDIR)/debian/secubox-openclaw/etc/sudoers.d
	install -m 440 debian/secubox-openclaw.sudoers $(CURDIR)/debian/secubox-openclaw/etc/sudoers.d/secubox-openclaw
	install -d $(CURDIR)/debian/secubox-openclaw/etc/secubox
	install -m 644 conf/openclaw.toml.example $(CURDIR)/debian/secubox-openclaw/etc/secubox/openclaw.toml.example
```
(If the existing rules already `cp -r api`/`www`, keep those lines. Ensure this runs in the same install override.)

- [ ] **Step 4: postinst visudo** — add near the top of the `configure` case (mirror nextcloud), and do NOT enable the dedicated service (aggregator serves it):
```sh
    if [ -f /etc/sudoers.d/secubox-openclaw ]; then
        visudo -cf /etc/sudoers.d/secubox-openclaw >/dev/null || {
            echo "secubox-openclaw: invalid sudoers, removing" >&2
            rm -f /etc/sudoers.d/secubox-openclaw
        }
    fi
```

- [ ] **Step 5: control Depends** — set `Depends: ${misc:Depends}, secubox-core (>= 1.0.0), debootstrap, lxc, jq` (host needs debootstrap+lxc to build/run the container and jq for openclawctl's record writing; the scan tools live in the container, not here).

- [ ] **Step 6: Build + verify the deb ships everything**

Run:
```bash
cd packages/secubox-openclaw && dpkg-buildpackage -us -uc -b 2>&1 | tail -3
dpkg-deb -c ../secubox-openclaw_*_all.deb | grep -E "sudoers.d/secubox-openclaw|sbin/openclawctl|openclaw.toml.example|api/main.py"
```
Expected: build succeeds; all four paths listed. `visudo -cf debian/secubox-openclaw.sudoers` → clean.

- [ ] **Step 7: Commit**
```bash
git add packages/secubox-openclaw/debian/secubox-openclaw.sudoers packages/secubox-openclaw/conf/openclaw.toml.example packages/secubox-openclaw/debian/postinst packages/secubox-openclaw/debian/rules packages/secubox-openclaw/debian/control
git commit -m "feat(openclaw): packaging — sudoers+visudo, install openclawctl+toml, deps debootstrap/lxc/jq"
```

---

### Task 7: Frontend — wire the dashboard to the API + XSS-harden

**Files:**
- Rewrite: `packages/secubox-openclaw/www/openclaw/index.html`

**Interfaces:** Consumes all Task 4/5 endpoints. Produces the working dashboard.

- [ ] **Step 1: Implement** — keep the existing skin/markup shell; wire the JS with the nextcloud dashboard's helpers:
  - `esc(s)` on EVERY backend string rendered into innerHTML (targets, tool `results.raw`, hostnames).
  - fail-safe `api(path, opts)` → `fetch` with `Authorization: Bearer ${localStorage.sbx_token}`; on 401 → redirect `login.html?redirect=`.
  - **Status pill** from `GET /status` (installed/running + tools); when `installed:false`, show an **Install** button → `POST /install`… (Note: `/install` endpoint — add a thin `@app.post("/install")` in Task 5 style that `subprocess.Popen(["sudo","-n",CTL,"install"], start_new_session=True)` + returns `{status:"started"}`; if you add it, also add a test. If out of scope for v1, hide the Install button and document that `openclawctl install` is run once by the operator — pick ONE and reflect it in the code, no dangling button.)
  - **Scan launcher**: target input + type auto-detect (`@`→email; `/` or IPv4→ip; else domain); if type∈{ip,ports} and target not LAN/owned (reuse a JS `isLocalOrOwned`) → typed "I am authorized" confirm before POST with `authorized:true`.
  - **Scan history** from `GET /scans`: table (id,type,target,status,started_at) with per-row **View** (`GET /scan/{id}` → render `results.raw` in a `<pre>` via `esc`) and **Delete** (typed confirm → `DELETE`). Poll every 5s while any row is `pending`/`running`.
  - **Quick lookups**: DNS/whois/certs/ports inputs → the sync GETs → render escaped.
  - All row actions via `data-*` attributes + delegated `addEventListener` — NEVER `onclick="fn('${x}')"`.

- [ ] **Step 2: Validate** — extract the inline `<script>` and `node --check`; grep confirms no `onclick="` with interpolated data and `esc(` wraps rendered values.

Run: `node --check <(sed -n '/<script>/,/<\/script>/p' packages/secubox-openclaw/www/openclaw/index.html | sed '1d;$d')`
Expected: OK.

- [ ] **Step 3: Commit**
```bash
git add packages/secubox-openclaw/www/openclaw/index.html
git commit -m "feat(openclaw): wire + XSS-harden the scanner dashboard"
```

---

### Task 8: Live end-to-end on gk2

**Files:** none (integration/verification).

- [ ] **Step 1: Build + deploy the deb**
```bash
cd packages/secubox-openclaw && dpkg-buildpackage -us -uc -b
scp ../secubox-openclaw_*_all.deb root@192.168.1.200:/root/
ssh root@192.168.1.200 'dpkg -i --force-confdef --force-confold /root/secubox-openclaw_*_all.deb && sudo -u secubox sudo -n /usr/sbin/openclawctl status --json'
```
Expected: install rc=0; secubox can `sudo openclawctl` (JSON, not a sudo error).

- [ ] **Step 2: Build the container + restart the aggregator once**
```bash
ssh root@192.168.1.200 'openclawctl install && systemctl restart secubox-aggregator'
```
Expected: container builds; aggregator active.

- [ ] **Step 3: Verify via the vhost + concurrency**
```bash
ssh root@192.168.1.200 'S=/run/secubox/aggregator.sock
  curl -s --unix-socket $S http://localhost/api/v1/openclaw/status | jq "{installed,running,tools}"
  # start a LAN active scan; while it runs, another module must stay fast
  # (auth-gated scan needs a token — trigger openclawctl directly to prove the pipeline)
  openclawctl scan ip 127.0.0.1 dddd4444 & sleep 1
  time curl -s -o /dev/null -w "%{http_code}" --unix-socket $S http://localhost/api/v1/cookies/status; echo
  wait; jq .status /var/lib/secubox/openclaw/scans/dddd4444.json'
```
Expected: status shows installed/running + tools true; the concurrent `cookies/status` returns fast (loop not blocked); the scan record reaches `completed`.

- [ ] **Step 4: Verify the dashboard** — `curl -k https://admin.gk2.secubox.in/openclaw/` returns 200 and the wired markup; a manual browser pass (operator) scans a LAN IP + a domain and sees results render, external-active confirm gate fires.

- [ ] **Step 5: Record + commit tracking**
```bash
# HISTORY.md + MIGRATION-MAP.md entry for openclaw
git add .claude/HISTORY.md .claude/MIGRATION-MAP.md
git commit -m "docs(openclaw): mark module implemented (LXC scanner live on gk2)"
```

---

## Notes for the executor

- **Do the async→def and delete-old-machinery in Task 5 completely** — a single leftover `async def` handler that shells out reintroduces the board-wide SPOF.
- **One aggregator restart** (Task 8 Step 2) is enough to load the new in-process code; do not restart repeatedly (each re-imports ~110 modules and spikes load).
- **`/install` decision** (Task 7 Step 1): pick add-endpoint-or-operator-run and make the UI consistent — no dangling button.
- **Sync-lookup `00000000` scan-id** collides if two lookups run at once; if that races in practice, switch `_sync_lookup` to a per-request temp id and read that file. Flagged, not pre-optimized.
