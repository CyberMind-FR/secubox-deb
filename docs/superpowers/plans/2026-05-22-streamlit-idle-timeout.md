<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Streamlit Per-App Idle Timeout + Wake-on-Demand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop streamlit apps that haven't served traffic in N minutes; lazily restart them on the next user visit. Reclaims ~80–150 MB resident per dormant app on gk2.

**Architecture:**
A systemd timer in the host runs `streamlitctl app idle-check` every 5 min. The check uses `lxc-attach … ss -tn` to count ESTABLISHED connections to each app's port; an app with **zero ESTABLISHED connections for `idle_timeout_minutes`** is stopped. A new FastAPI endpoint `POST /api/v1/streamlit/apps/{name}/wake` re-spawns the app on demand (and waits for the port to come up). The control-plane FastAPI service stays always-on; only individual app processes are paused.

**Tech Stack:**
- `streamlitctl` (bash) — adds two subcommands: `app idle-check`, `app wake`
- `secubox-streamlit-idle.{service,timer}` (new) — periodic sweep
- FastAPI `/apps/{name}/wake` endpoint (Python) — shell-out to `streamlitctl app wake`
- `/etc/secubox/streamlit.toml` — new `[idle]` section with `timeout_minutes`, `check_interval_minutes`, `enabled`
- Per-app state in `/var/lib/secubox/streamlit/idle/<name>.state` (host side; cheap text file)
- Tests in `packages/secubox-streamlit/api/tests/` using pytest + the existing test scaffolding

**Out of scope (deferred):**
- Auto-relaunch via nginx `error_page` (operator-triggered or UI-triggered wake is enough for v1)
- HTML "app is asleep" stub page (follow-up)
- Wake-from-mitmproxy-route fallback (follow-up)

---

## File Structure

- **Create:**
  - `packages/secubox-streamlit/debian/secubox-streamlit-idle.service` — oneshot, runs `streamlitctl app idle-check`
  - `packages/secubox-streamlit/debian/secubox-streamlit-idle.timer` — every 5 min
  - `packages/secubox-streamlit/api/tests/test_idle.py` — unit tests for the wake endpoint
- **Modify:**
  - `packages/secubox-streamlit/sbin/streamlitctl` — add `_app_running()`, `_app_idle_seconds()`, `cmd_app_idle_check()`, `cmd_app_wake()`; extend `cmd_app_start` to clear the idle marker
  - `packages/secubox-streamlit/api/main.py` — new `POST /apps/{name}/wake` route
  - `packages/secubox-streamlit/streamlit.toml` (or wherever the default config lives) — add `[idle]` section
  - `packages/secubox-streamlit/debian/secubox-streamlit.install` — ship the new unit + timer
  - `packages/secubox-streamlit/debian/postinst` — `systemctl enable --now secubox-streamlit-idle.timer`
  - `packages/secubox-streamlit/debian/prerm` — `systemctl disable --now secubox-streamlit-idle.timer`
  - `packages/secubox-streamlit/debian/changelog` — bump to next version with `[idle]` summary

---

## Task 1: streamlitctl helpers — running detection + idle accounting

**Files:**
- Modify: `packages/secubox-streamlit/sbin/streamlitctl` (top of file, near other helpers)

The current `_app_running` check (`ss -tln sport = :$port`) only works for ports bound *on the host*, but streamlit listens inside the LXC. The new helper runs `ss` via `lxc-attach`. The "last activity" timestamp is tracked in a state file under `/var/lib/secubox/streamlit/idle/<name>.state` — written every time idle-check sees ≥1 ESTABLISHED connection, and read to decide stop-or-not.

- [ ] **Step 1: Read existing helper block (above cmd_app_start) for context**

```bash
sed -n '1,80p' packages/secubox-streamlit/sbin/streamlitctl
```

- [ ] **Step 2: Add idle-state helpers near the top of the file**

Insert after the existing constants block (around the `CONF_PATH=` line):

```bash
IDLE_STATE_DIR="/var/lib/secubox/streamlit/idle"

# Read [idle] settings from /etc/secubox/streamlit.toml with safe defaults.
_idle_config() {
    local key="$1" default="$2"
    grep -E "^\s*${key}\s*=" "$CONF_PATH" 2>/dev/null \
        | head -1 | cut -d'=' -f2- | tr -d ' "' \
        || echo "$default"
}

# Returns 0 if the app is listening on its port INSIDE the LXC, else 1.
_app_running() {
    local name="$1"
    local port; port=$(grep -E "^port\s*=" "$APPS_PATH/$name/.streamlit.toml" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    [ -z "$port" ] && return 1
    lxc_running || return 1
    lxc-attach -n "$LXC_NAME" -- ss -tln "sport = :$port" 2>/dev/null \
        | awk -v p="$port" 'NR>1 && $4 ~ ":"p"$" {found=1} END {exit found?0:1}'
}

# Returns the count of ESTABLISHED connections to the app's port (inside LXC).
_app_active_conns() {
    local name="$1"
    local port; port=$(grep -E "^port\s*=" "$APPS_PATH/$name/.streamlit.toml" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    [ -z "$port" ] && { echo 0; return; }
    lxc_running || { echo 0; return; }
    lxc-attach -n "$LXC_NAME" -- ss -tn state established "sport = :$port" 2>/dev/null \
        | awk 'NR>1' | wc -l
}

# Last-activity epoch for the app (file mtime). Touched by cmd_app_idle_check
# when ESTABLISHED>0; created at start time by cmd_app_start.
_app_last_active() {
    local name="$1"
    local f="$IDLE_STATE_DIR/$name.state"
    [ -f "$f" ] || { echo 0; return; }
    stat -c %Y "$f"
}

_app_touch_active() {
    local name="$1"
    mkdir -p "$IDLE_STATE_DIR"
    touch "$IDLE_STATE_DIR/$name.state"
}
```

- [ ] **Step 3: Wire the new state into cmd_app_start (touch on start, clear nothing)**

Add right after `log "App $name started"` in `cmd_app_start`:

```bash
    _app_touch_active "$name"
```

- [ ] **Step 4: Lint the script — no shellcheck regressions on the new helpers**

```bash
shellcheck -S warning -e SC1091 -e SC2086 packages/secubox-streamlit/sbin/streamlitctl 2>&1 | head -30
```

Expected: no new warnings about the inserted block (pre-existing warnings on legacy code are out of scope).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-streamlit/sbin/streamlitctl
git commit -m "feat(streamlit): add idle-tracking helpers to streamlitctl (#119-followup)"
```

---

## Task 2: streamlitctl — `app idle-check` subcommand

**Files:**
- Modify: `packages/secubox-streamlit/sbin/streamlitctl`

Decision logic per app: if `_app_active_conns > 0` → `_app_touch_active`; else if `(now - _app_last_active) > timeout` → `cmd_app_stop`.

- [ ] **Step 1: Add cmd_app_idle_check below cmd_app_stop**

```bash
cmd_app_idle_check() {
    local enabled; enabled=$(_idle_config "enabled" "true")
    [ "$enabled" = "true" ] || { log "idle-check disabled in $CONF_PATH"; return 0; }

    local timeout_min; timeout_min=$(_idle_config "timeout_minutes" "30")
    local timeout_sec=$(( timeout_min * 60 ))
    local now; now=$(date +%s)

    local stopped=0 active=0 idle=0
    for app_dir in "$APPS_PATH"/*/; do
        [ -d "$app_dir" ] || continue
        local name; name=$(basename "$app_dir")
        [ "$name" = "*" ] && continue

        _app_running "$name" || continue

        local conns; conns=$(_app_active_conns "$name")
        if [ "$conns" -gt 0 ]; then
            _app_touch_active "$name"
            active=$(( active + 1 ))
            continue
        fi

        local last; last=$(_app_last_active "$name")
        [ "$last" -eq 0 ] && { _app_touch_active "$name"; continue; }
        local idle_sec=$(( now - last ))

        if [ "$idle_sec" -ge "$timeout_sec" ]; then
            log "idle-stop: $name (idle ${idle_sec}s >= ${timeout_sec}s)"
            cmd_app_stop "$name" >/dev/null 2>&1 || true
            stopped=$(( stopped + 1 ))
        else
            idle=$(( idle + 1 ))
        fi
    done

    log "idle-check: active=$active idle=$idle stopped=$stopped"
}
```

- [ ] **Step 2: Register the subcommand in the case-block at the bottom of the file**

Find the `app)` dispatcher (around line 736):

```bash
            list)       cmd_app_list ;;
```

Add right after:

```bash
            idle-check) cmd_app_idle_check ;;
            wake)       cmd_app_wake "$@" ;;
```

Also update the usage line in the `*)` branch to include both.

- [ ] **Step 3: Hand-test the new subcommand on the local sandbox**

```bash
sudo bash -c 'CONF_PATH=/tmp/empty.toml APPS_PATH=/tmp/no-apps packages/secubox-streamlit/sbin/streamlitctl app idle-check'
```

Expected: `idle-check: active=0 idle=0 stopped=0` (no apps to iterate). Confirms the new code path is wired.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-streamlit/sbin/streamlitctl
git commit -m "feat(streamlit): streamlitctl app idle-check — stop idle apps past timeout"
```

---

## Task 3: streamlitctl — `app wake` subcommand

**Files:**
- Modify: `packages/secubox-streamlit/sbin/streamlitctl`

`cmd_app_wake <name> [timeout_seconds]` starts the app if not running, then polls until the port is listening or timeout (default 30 s). Exits 0 on success, 1 on timeout, 2 on misuse.

- [ ] **Step 1: Add cmd_app_wake right after cmd_app_idle_check**

```bash
cmd_app_wake() {
    local name="$1"
    local wait_sec="${2:-30}"
    [ -z "$name" ] && { error "Usage: streamlitctl app wake <name> [wait_seconds]"; return 2; }
    [ -d "$APPS_PATH/$name" ] || { error "App not found: $name"; return 2; }

    if _app_running "$name"; then
        _app_touch_active "$name"
        log "wake: $name already running"
        return 0
    fi

    log "wake: starting $name (will wait up to ${wait_sec}s)"
    cmd_app_start "$name" >/dev/null 2>&1 || { error "wake: failed to start $name"; return 1; }

    local elapsed=0
    while [ "$elapsed" -lt "$wait_sec" ]; do
        if _app_running "$name"; then
            _app_touch_active "$name"
            log "wake: $name listening after ${elapsed}s"
            return 0
        fi
        sleep 1
        elapsed=$(( elapsed + 1 ))
    done

    error "wake: $name did not come up within ${wait_sec}s"
    return 1
}
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-streamlit/sbin/streamlitctl
git commit -m "feat(streamlit): streamlitctl app wake — lazy start + poll for port"
```

---

## Task 4: systemd timer + service unit

**Files:**
- Create: `packages/secubox-streamlit/debian/secubox-streamlit-idle.service`
- Create: `packages/secubox-streamlit/debian/secubox-streamlit-idle.timer`
- Modify: `packages/secubox-streamlit/debian/secubox-streamlit.install`
- Modify: `packages/secubox-streamlit/debian/postinst`
- Modify: `packages/secubox-streamlit/debian/prerm`

- [ ] **Step 1: Create the service unit**

```ini
[Unit]
Description=SecuBox Streamlit — idle-app sweep
After=secubox-streamlit.service
Requires=secubox-streamlit.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/streamlitctl app idle-check
# Best-effort — a failed sweep should not page anyone
SuccessExitStatus=0 1
```

- [ ] **Step 2: Create the timer unit**

```ini
[Unit]
Description=Run secubox-streamlit-idle.service every 5 minutes
After=secubox-streamlit.service

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Unit=secubox-streamlit-idle.service

[Install]
WantedBy=timers.target
```

- [ ] **Step 3: Update `debian/secubox-streamlit.install`**

Append:

```
debian/secubox-streamlit-idle.service /lib/systemd/system/
debian/secubox-streamlit-idle.timer   /lib/systemd/system/
```

- [ ] **Step 4: Enable in postinst, disable in prerm**

Add to `postinst` after the existing `systemctl enable --now secubox-streamlit.service`:

```bash
systemctl enable --now secubox-streamlit-idle.timer || true
```

Add to `prerm` before `systemctl stop secubox-streamlit.service`:

```bash
systemctl disable --now secubox-streamlit-idle.timer || true
```

- [ ] **Step 5: Build + lint the .deb**

```bash
cd packages/secubox-streamlit
dpkg-buildpackage -us -uc -b 2>&1 | tail -20
```

Expected: a `secubox-streamlit_*.deb` in the parent dir. Lintian warnings about the new unit-file names are OK if there's no policy violation. **Stop and ask** if a lintian *error* appears.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-streamlit/debian/secubox-streamlit-idle.service \
        packages/secubox-streamlit/debian/secubox-streamlit-idle.timer \
        packages/secubox-streamlit/debian/secubox-streamlit.install \
        packages/secubox-streamlit/debian/postinst \
        packages/secubox-streamlit/debian/prerm
git commit -m "feat(streamlit): systemd idle-sweep timer (every 5 min)"
```

---

## Task 5: FastAPI `/apps/{name}/wake` endpoint

**Files:**
- Modify: `packages/secubox-streamlit/api/main.py`
- Modify: `packages/secubox-streamlit/api/tests/test_idle.py` (create if absent)

The endpoint shells out to `streamlitctl app wake <name> 30`. Returns 200 on success, 504 on wake timeout, 404 if the app doesn't exist, 502 if `streamlitctl` is missing.

- [ ] **Step 1: Find the existing route style + JWT dep**

```bash
grep -nE "^@app\.(get|post)|require_jwt|Depends\(" packages/secubox-streamlit/api/main.py | head -20
```

This is to ensure the new route matches existing auth + response patterns. Existing routes use `dependencies=[Depends(require_jwt)]`.

- [ ] **Step 2: Add a Pydantic response model (top of api/main.py near other models)**

```python
class WakeResult(BaseModel):
    name: str
    status: str  # "running" | "started" | "timeout"
    duration_ms: int
```

- [ ] **Step 3: Add the route (place it near the other `/apps/...` handlers)**

```python
@app.post("/apps/{name}/wake", dependencies=[Depends(require_jwt)])
async def wake_app(name: str) -> WakeResult:
    """Wake an idle-stopped streamlit app. Blocks until the port comes up
    or 30 s elapse. Idempotent — returns immediately if already running."""
    if not Path(CTL).exists():
        raise HTTPException(502, "streamlitctl missing")
    app_dir = Path("/srv/streamlit/apps") / name
    if not app_dir.is_dir():
        raise HTTPException(404, f"app not found: {name}")

    start = time.monotonic()
    try:
        result = subprocess.run(
            [CTL, "app", "wake", name, "30"],
            capture_output=True, timeout=35, check=False,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "wake exceeded 35s wall-clock")

    duration_ms = int((time.monotonic() - start) * 1000)
    if result.returncode == 0:
        status = "running" if b"already running" in result.stderr else "started"
        return WakeResult(name=name, status=status, duration_ms=duration_ms)
    raise HTTPException(504, f"wake failed: {result.stderr.decode(errors='replace')[:200]}")
```

- [ ] **Step 4: Write the failing test**

```python
# packages/secubox-streamlit/api/tests/test_idle.py
from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from api.main import app

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SECUBOX_DISABLE_JWT", "1")  # follow existing test pattern
    return TestClient(app)

def test_wake_missing_app_returns_404(client, tmp_path, monkeypatch):
    monkeypatch.setattr("api.main.CTL", "/usr/sbin/streamlitctl")
    with patch("api.main.Path") as mock_path:
        mock_path.return_value.is_dir.return_value = False
        mock_path.return_value.exists.return_value = True
        r = client.post("/apps/nope/wake")
    assert r.status_code == 404

def test_wake_running_returns_200_running(client, monkeypatch):
    monkeypatch.setattr("api.main.CTL", "/usr/sbin/streamlitctl")
    fake = MagicMock(returncode=0, stderr=b"wake: foo already running\n")
    with patch("api.main.Path") as mock_path, \
         patch("api.main.subprocess.run", return_value=fake):
        mock_path.return_value.is_dir.return_value = True
        mock_path.return_value.exists.return_value = True
        r = client.post("/apps/foo/wake")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "running"
    assert body["name"] == "foo"

def test_wake_timeout_returns_504(client, monkeypatch):
    monkeypatch.setattr("api.main.CTL", "/usr/sbin/streamlitctl")
    fake = MagicMock(returncode=1, stderr=b"wake: foo did not come up within 30s\n")
    with patch("api.main.Path") as mock_path, \
         patch("api.main.subprocess.run", return_value=fake):
        mock_path.return_value.is_dir.return_value = True
        mock_path.return_value.exists.return_value = True
        r = client.post("/apps/foo/wake")
    assert r.status_code == 504
```

- [ ] **Step 5: Run the tests**

```bash
cd packages/secubox-streamlit
python3 -m pytest api/tests/test_idle.py -v
```

Expected: 3 tests pass. If `SECUBOX_DISABLE_JWT` is not the right knob, inspect `api/tests/conftest.py` for the actual override pattern.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-streamlit/api/main.py packages/secubox-streamlit/api/tests/test_idle.py
git commit -m "feat(streamlit): POST /apps/{name}/wake — lazy start API endpoint"
```

---

## Task 6: Default config — `[idle]` section in `/etc/secubox/streamlit.toml`

**Files:**
- Modify: the default `streamlit.toml` shipped by the package (likely `packages/secubox-streamlit/streamlit.toml` or under `debian/`)

- [ ] **Step 1: Find the file**

```bash
find packages/secubox-streamlit -name 'streamlit.toml' -not -path '*/debian/secubox-streamlit/*'
```

If it doesn't exist yet, the .deb writes one in `postinst`; in that case create `packages/secubox-streamlit/streamlit.toml` and ship it via `.install`.

- [ ] **Step 2: Add the `[idle]` block at the end of the file**

```toml
[idle]
# Stop streamlit apps that haven't served any ESTABLISHED connection
# for this many minutes. Set to 0 to disable. Default 30.
timeout_minutes = 30

# How often the systemd timer runs the sweep. Informational — the
# actual timer is in secubox-streamlit-idle.timer; keep them in sync
# if you change either.
check_interval_minutes = 5

# Master switch. false = streamlitctl app idle-check exits 0 without
# touching anything.
enabled = true
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-streamlit/streamlit.toml
git commit -m "feat(streamlit): default [idle] config block (timeout 30 min)"
```

---

## Task 7: Changelog + version bump

**Files:**
- Modify: `packages/secubox-streamlit/debian/changelog`

- [ ] **Step 1: Read the current version**

```bash
head -1 packages/secubox-streamlit/debian/changelog
```

- [ ] **Step 2: Prepend the new entry**

```text
secubox-streamlit (NEXT_VERSION) bookworm; urgency=medium

  * streamlitctl: new `app idle-check` + `app wake` subcommands.
    idle-check stops apps with zero ESTABLISHED connections for the
    configured timeout (default 30 min). wake lazily restarts a
    stopped app and polls until its port is listening.
  * systemd: new secubox-streamlit-idle.timer fires the sweep every
    5 minutes. Enabled by postinst, disabled by prerm.
  * api: new POST /api/v1/streamlit/apps/{name}/wake endpoint that
    shells to `streamlitctl app wake`. Returns 200 (running/started),
    404 (no such app), 504 (wake timeout).
  * config: new [idle] section in /etc/secubox/streamlit.toml
    (timeout_minutes, check_interval_minutes, enabled).
  * Memory win on gk2: ~80–150 MB freed per dormant app. Closes #331.
    

 -- Gerald Kerma <devel@cybermind.fr>  Fri, 22 May 2026 06:30:00 +0000
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-streamlit/debian/changelog
git commit -m "chore(streamlit): bump to NEXT_VERSION with idle-timeout summary"
```

---

## Task 8: End-to-end test on gk2

**Manual — operator runs after PR merges.**

- [ ] **Step 1: Build + deploy the .deb**

```bash
cd packages/secubox-streamlit
dpkg-buildpackage -us -uc -b
scp ../secubox-streamlit_*_all.deb root@192.168.1.200:/tmp/
ssh root@192.168.1.200 'dpkg -i /tmp/secubox-streamlit_*_all.deb'
```

- [ ] **Step 2: Verify the timer is armed**

```bash
ssh root@192.168.1.200 'systemctl list-timers secubox-streamlit-idle.timer'
```

Expected: a row with NEXT timestamp within 5 min.

- [ ] **Step 3: Confirm an idle app gets stopped**

Deploy or pick an existing streamlit app that has zero traffic. Run:

```bash
ssh root@192.168.1.200 'streamlitctl app idle-check'
```

Wait 30 min + 5 min (one timer cycle). Re-run:

```bash
ssh root@192.168.1.200 'streamlitctl app list'
```

Expected: the app's `running` field flipped to `false`. `free -m` shows ~100 MB more available.

- [ ] **Step 4: Confirm the wake endpoint relaunches it**

```bash
ssh root@192.168.1.200 'curl -sS -X POST -H "Cookie: $JWT" http://127.0.0.1/api/v1/streamlit/apps/<name>/wake | jq'
```

Expected: `{"name":"<name>","status":"started","duration_ms":<some-ms>}` in under 10 s.

- [ ] **Step 5: File the GitHub issue + close it via this PR**

Use `gh issue create` with a body that summarises the design + links this plan, then reference `Closes #331` in the PR.
