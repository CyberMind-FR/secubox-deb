<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Frigate NVR Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up Frigate NVR in a dedicated LXC on the amd64 node (official image via podman), with a JWT'd `/api/v1/frigate/*` shim, cross-node WAF exposure from gk2, storage + disk-pressure guard, and sidebar/menu integration — validated with a go2rtc demo source, no real camera.

**Architecture:** A new `secubox-frigate` Debian package (Architecture: all) that mirrors `secubox-photoprism` **exactly** in shape (podman container inside a dedicated Debian LXC, a host-side FastAPI shim daemon on a Unix socket, an nginx vhost, a `menu.d` entry, an `frigatectl` lifecycle tool). It installs on **amd64**; gk2's HAProxy→mitmproxy→mesh fronts the Frigate UI (no `waf_bypass`), and gk2's Hub polls the shim over the mesh.

**Tech Stack:** LXC (`lxc-create` download template), podman (`--network=host` inside the LXC), Frigate official OCI image (OpenVINO CPU detector + bundled go2rtc/ffmpeg), FastAPI/uvicorn (host shim), pytest, HAProxy + mitmproxy, nginx.

## Global Constraints

- **Reference module = `packages/secubox-photoprism`** — copy its idioms verbatim (control, rules, `debian/*.service`, `lib/photoprism/install-lxc.sh`, `sbin/photoprismctl`, `postinst`, `nginx/*.conf`, `menu.d/*.json`). Frigate deltas are spelled out per task; everything unspecified follows photoprism.
- **Host node = amd64** (`secubox-live`, mesh `10.10.0.3`, LAN `192.168.1.9`). The package installs there.
- **Podman runs INSIDE the LXC** via a systemd unit in the LXC — **never** driven by the `.deb`/postinst. The `.deb` only provisions the LXC + config; the LXC's own systemd runs Frigate. (`--network=host`, mirror photoprism.)
- **Detector = OpenVINO on CPU**; Frigate image pinned (no `:latest`) — `ghcr.io/blakeblackshear/frigate:0.14.1` (override via `SECUBOX_FRIGATE_IMAGE`).
- **NO `waf_bypass`** — the Frigate UI is fronted by gk2 HAProxy → `mitmproxy_inspector` → mesh → amd64. Update **both** `/srv/mitmproxy/haproxy-routes.json` and `/srv/mitmproxy-in/haproxy-routes.json`, then restart mitmproxy. (This is the one place Frigate differs from photoprism, which bypasses the WAF — do NOT copy photoprism's bypass here.)
- **All shim handlers plain `def`** (aggregator SPOF discipline, even though it runs standalone on amd64). Stats-heavy endpoints **double-cached** (background refresh + JSON cache file). Fail-safe: Frigate down → `status` reports it, others serve empty/last-cache, **never a 5xx storm**.
- **`/api/v1/frigate/stats` returns TOP-LEVEL keys** `cameras`, `events`, `fps` (the sidebar reads them directly — same contract as nac `/stats`).
- **Shim service** sets `RuntimeDirectoryPreserve=yes` (avoid the `/run/secubox` socket-wipe on the satellites).
- **Secrets** (camera RTSP creds) in `/etc/secubox/secrets/` chmod 600 owner `secubox` — never in the repo/config-in-git.
- **Perms:** do not touch `/run` (1777), `/etc/secubox` (0755), `/var/log/secubox` (0755) parents. Media on `/data/frigate`.
- **License header** `LicenseRef-CMSD-1.0` on every new file (Python + bash), via the codebase convention.
- Tests run: `cd packages/secubox-frigate && PYTHONPATH=../../common:. python3 -m pytest tests -q`.

---

## File Structure

```
packages/secubox-frigate/
├── api/
│   ├── __init__.py
│   └── main.py                     # FastAPI shim: status/cameras/events/storage/stats (JWT, plain def, double-cache)
├── conf/
│   ├── frigate.config.yml.example  # OpenVINO detector + go2rtc demo source + retention + commented camera
│   └── frigate.nginx.conf          # /api/v1/frigate/ → shim socket ; /frigate/ static (placeholder)
├── lib/frigate/
│   ├── install-lxc.sh              # idempotent: create LXC, install podman, drop in-LXC frigate.container unit, bind mounts
│   └── frigate.container           # systemd unit (in the LXC) that `podman run`s the pinned Frigate image
├── sbin/
│   ├── frigatectl                  # install/status/start/stop/restart lifecycle (mirror photoprismctl)
│   └── secubox-frigate-diskguard   # /data disk-pressure check (called by a timer)
├── menu.d/
│   └── 618-frigate.json            # navbar entry
├── nginx/
│   └── frigate.conf                # gk2-side route entry (proxy /api/v1/frigate over mesh to amd64) — Task 6
├── tests/
│   ├── test_shim.py                # endpoint shapes, JWT gate, plain-def, fail-safe
│   ├── test_stats_contract.py      # /stats top-level {cameras,events,fps}
│   └── test_diskguard.py           # disk-pressure guard fires on low df (mocked)
├── www/frigate/index.html          # minimal placeholder (dashboard = sub-project 2)
├── debian/
│   ├── changelog control rules postinst prerm
│   ├── secubox-frigate.service     # host shim daemon (uvicorn on /run/secubox/frigate.sock)
│   ├── secubox-frigate-diskguard.service + .timer
│   └── secubox.yaml
└── README.md
```

---

## Task 1: Package scaffold

**Files:**
- Create: `packages/secubox-frigate/debian/control`, `debian/rules`, `debian/changelog`, `debian/compat` (via compat-13), `debian/secubox.yaml`, `README.md`, `api/__init__.py`, `www/frigate/index.html`
- Reference: `packages/secubox-photoprism/debian/{control,rules,changelog,secubox.yaml}`

**Interfaces:**
- Produces: an installable (empty-behaviour) `secubox-frigate` `.deb` at version `0.1.0-1~bookworm1`; package name `secubox-frigate`, Architecture: all.

- [ ] **Step 1: Copy photoprism's debian scaffold, rename to frigate.** Read `packages/secubox-photoprism/debian/control` and create `packages/secubox-frigate/debian/control` with:
```
Source: secubox-frigate
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-frigate
Architecture: all
Depends: ${misc:Depends}, secubox-core (>= 1.0), python3-uvicorn | python3-pip,
 lxc, lxc-templates, podman, nftables, openssl
Description: Frigate NVR for SecuBox (native LXC, podman)
 SecuBox module for the Frigate NVR (frigate.video) running as the official
 podman container inside a dedicated Debian LXC on the amd64 node. `frigatectl
 install` provisions the LXC + container on demand; the host shim daemon stays
 lightweight and always reachable on /run/secubox/frigate.sock.
 .
 Foundation scope: OpenVINO CPU detector, go2rtc demo source (no camera yet),
 storage + retention on /data/frigate, /api/v1/frigate/* shim, and cross-node
 exposure through gk2's WAF (mitmproxy — no bypass). The C3BOX dashboard, MQTT,
 and 4R config double-buffer are deferred (sub-project 2 / follow-ups).
 .
 Provides FastAPI backend on /api/v1/frigate/ via a Unix socket.
```
- [ ] **Step 2: rules + changelog + secubox.yaml.** Copy `packages/secubox-photoprism/debian/rules` verbatim to `packages/secubox-frigate/debian/rules` (dh sequence; it installs `lib/`, `sbin/`, `conf/`, `www/`, `menu.d/`, `api/` — verify the install stanzas reference the frigate paths, adjust any `photoprism`→`frigate` literal). Create `debian/changelog`:
```
secubox-frigate (0.1.0-1~bookworm1) bookworm; urgency=medium

  * Foundation (#821): Frigate NVR in a podman-in-LXC on amd64; /api/v1/frigate
    shim (status/cameras/events/storage/stats); go2rtc demo source; OpenVINO CPU
    detector; storage + disk-pressure guard; cross-node WAF exposure (no bypass);
    menu.d + sidebar /stats. Dashboard/MQTT/4R deferred.

 -- Gerald KERMA <devel@cybermind.fr>  Mon, 06 Jul 2026 00:00:00 +0000
```
Copy `debian/secubox.yaml` from photoprism, changing `name`/`socket`/paths to `frigate`.
- [ ] **Step 3: minimal api + placeholder www.** Create `api/__init__.py` (SPDX header + empty). Create `www/frigate/index.html` — a minimal placeholder carrying the SPDX header and one line: `<h1>Frigate — dashboard coming in sub-project 2. API at /api/v1/frigate/</h1>` (the full dashboard is a separate spec; do NOT build it here).
- [ ] **Step 4: build the .deb (arch:all).**
Run: `cd packages/secubox-frigate && dpkg-buildpackage -us -uc -b 2>&1 | tail -3`
Expected: `dpkg-deb: building package 'secubox-frigate' in '../secubox-frigate_0.1.0-1~bookworm1_all.deb'`.
- [ ] **Step 5: verify contents + parseable changelog.**
Run: `dpkg-deb -c ../secubox-frigate_0.1.0-1~bookworm1_all.deb | grep -E "www/frigate|api/__init__"` and `dpkg-parsechangelog -l debian/changelog -S Version`
Expected: files present; Version `0.1.0-1~bookworm1`.
- [ ] **Step 6: Commit.**
```bash
git add packages/secubox-frigate/debian packages/secubox-frigate/api/__init__.py packages/secubox-frigate/www packages/secubox-frigate/README.md
git commit -m "feat(frigate): package scaffold — control/rules/changelog + placeholder (ref #821)"
```

---

## Task 2: LXC + podman provisioning (`install-lxc.sh` + in-LXC unit)

**Files:**
- Create: `packages/secubox-frigate/lib/frigate/install-lxc.sh`, `packages/secubox-frigate/lib/frigate/frigate.container`
- Reference: `packages/secubox-photoprism/lib/photoprism/install-lxc.sh` (copy structure verbatim; change the deltas below)

**Interfaces:**
- Produces: `install-lxc.sh` idempotently creates an LXC named `frigate` (override `SECUBOX_LXC_NAME`) on `br-lxc` at `10.100.0.140` (override `SECUBOX_LXC_IP`), installs podman inside it, drops the `frigate.container`/`podman run` unit, bind-mounts `/etc/secubox/frigate`→`/config` and `/data/frigate`→`/media/frigate`, and starts Frigate. Sentinel `/var/lib/secubox/frigate/.lxc-provisioned`.

- [ ] **Step 1: copy photoprism's install-lxc.sh, retarget the readonly vars.** Change the header block to frigate; set:
```bash
readonly LXC_NAME="${SECUBOX_LXC_NAME:-frigate}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.140}"
readonly DATA_DIR="${SECUBOX_DATA_DIR:-/data/frigate}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/var/lib/secubox/frigate}"
readonly CONFIG_DIR="${SECUBOX_FRIGATE_CONFIG:-/etc/secubox/frigate}"
readonly IMAGE="${SECUBOX_FRIGATE_IMAGE:-ghcr.io/blakeblackshear/frigate:0.14.1}"
readonly HTTP_PORT="${SECUBOX_FRIGATE_PORT:-5000}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
```
Keep photoprism's `require_cmds`, `ensure_bridge`, `ensure_masquerade`, `lxc_state`, `create_lxc`, `write_lxc_config`, `la()` helpers verbatim (they are generic). Add `podman` to `require_cmds` list check inside the LXC step.
- [ ] **Step 2: ensure_dirs for frigate.** Replace photoprism's `ensure_dirs` body with:
```bash
ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 "$STATE_DIR" 2>/dev/null || true
    install -d -m 0755 "$CONFIG_DIR"
    install -d -m 0750 "$DATA_DIR/db" "$DATA_DIR/recordings" "$DATA_DIR/clips" "$DATA_DIR/exports"
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DATA_DIR"
    chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$CONFIG_DIR"
}
```
- [ ] **Step 3: lay down the config into CONFIG_DIR if absent.** After `ensure_dirs`, add a step that copies the `.example` to the live path only when missing (never clobber operator edits):
```bash
install_config() {
    if [ ! -f "$CONFIG_DIR/config.yml" ]; then
        log "Seeding $CONFIG_DIR/config.yml from example"
        install -m 0640 /usr/share/secubox/frigate/frigate.config.yml.example "$CONFIG_DIR/config.yml"
        chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$CONFIG_DIR/config.yml"
    fi
}
```
- [ ] **Step 4: the in-LXC podman unit `frigate.container`.** Frigate runs `--network=host` (mirror photoprism's reason: unprivileged LXC podman CNI). Create `lib/frigate/frigate.container` as a plain systemd unit (podman run, not quadlet — match photoprism's approach of a unit that execs podman):
```ini
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Installed INTO the frigate LXC by install-lxc.sh; runs the official Frigate
# image. --network=host (unprivileged LXC podman has no CNI bridge). Config +
# media are bind-mounted from the host through the LXC.
[Unit]
Description=Frigate NVR (podman)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=on-failure
RestartSec=10
ExecStartPre=-/usr/bin/podman rm -f frigate
ExecStart=/usr/bin/podman run --rm --name frigate --network=host \
  --shm-size=128m \
  -e FRIGATE_RTSP_PASSWORD_FILE=/run/secrets/frigate-rtsp \
  -v /config:/config \
  -v /media/frigate:/media/frigate \
  --tmpfs /tmp/cache:size=256000000 \
  ghcr.io/blakeblackshear/frigate:0.14.1
ExecStop=/usr/bin/podman stop -t 10 frigate

[Install]
WantedBy=multi-user.target
```
In `install-lxc.sh`, add a step that (a) `la() apt-get install -y podman` inside the LXC, (b) copies `frigate.container` to `$LXC_PATH/$LXC_NAME/rootfs/etc/systemd/system/frigate.service`, (c) bind-mounts (via the LXC config `lxc.mount.entry`) the host `$CONFIG_DIR`→`/config` and `$DATA_DIR`→`/media/frigate`, (d) `la() systemctl enable --now frigate`.
- [ ] **Step 5: idempotency sentinel + main().** Mirror photoprism's `main()` order: `require_cmds; ensure_dirs; install_config; ensure_bridge; ensure_masquerade; create_lxc; write_lxc_config; <podman step>; touch "$SENTINEL"`. Re-run short-circuits the debootstrap (`create_lxc` already guards on the rootfs dir) and `podman pull` only runs on image change.
- [ ] **Step 6: syntax check.**
Run: `bash -n packages/secubox-frigate/lib/frigate/install-lxc.sh && echo OK`
Expected: `OK`.
- [ ] **Step 7: Commit.**
```bash
git add packages/secubox-frigate/lib
git commit -m "feat(frigate): idempotent LXC + podman provisioning (mirror photoprism) (ref #821)"
```

---

## Task 3: Frigate config example (OpenVINO + go2rtc demo source)

**Files:**
- Create: `packages/secubox-frigate/conf/frigate.config.yml.example`

**Interfaces:**
- Produces: a valid Frigate `config.yml` that boots with the OpenVINO CPU detector and a **go2rtc demo source** (no real camera), so the pipeline runs end-to-end for validation.

- [ ] **Step 1: write the example config.** Frigate config schema (docs.frigate.video). Create `conf/frigate.config.yml.example`:
```yaml
# SecuBox Frigate config (Foundation). Copied to /etc/secubox/frigate/config.yml
# on first install (never clobbered). OpenVINO CPU detector; a go2rtc demo source
# validates the pipeline with no real camera. Add real cameras under `cameras:`.
mqtt:
  enabled: false            # deferred (sub-project follow-up)

detectors:
  ov:
    type: openvino
    device: CPU

model:
  path: /openvino-model/ssdlite_mobilenet_v2.xml
  input_tensor: nhwc
  input_pixel_format: bgr
  width: 300
  height: 300

# go2rtc restream — a bundled demo/test source so Frigate runs with no camera.
go2rtc:
  streams:
    demo:
      # Frigate/go2rtc ships an ffmpeg test-pattern generator; replace with rtsp://... for a real camera.
      - "ffmpeg:device?video=testsrc#video=h264"

record:
  enabled: true
  retain:
    days: 3
    mode: motion

snapshots:
  enabled: true
  retain:
    default: 5

cameras:
  demo:
    enabled: true
    ffmpeg:
      inputs:
        - path: rtsp://127.0.0.1:8554/demo
          input_args: preset-rtsp-restream
          roles: [detect, record]
    detect:
      width: 1280
      height: 720
      fps: 5

# ── Add real cameras later, e.g.:
# cameras:
#   frontdoor:
#     ffmpeg:
#       inputs:
#         - path: rtsp://USER:PASS@192.168.1.50:554/stream
#           roles: [detect, record]
```
- [ ] **Step 2: lint it parses as YAML.**
Run: `python3 -c "import yaml,sys; yaml.safe_load(open('packages/secubox-frigate/conf/frigate.config.yml.example')); print('yaml ok')"`
Expected: `yaml ok`.
- [ ] **Step 3: assert the required Foundation keys are present (guards against a broken example).**
Run:
```bash
python3 -c "
import yaml
c=yaml.safe_load(open('packages/secubox-frigate/conf/frigate.config.yml.example'))
assert c['detectors']['ov']['type']=='openvino', 'detector must be openvino'
assert 'demo' in c['go2rtc']['streams'], 'demo go2rtc source required'
assert c['record']['enabled'] is True, 'record must be enabled'
assert c['mqtt']['enabled'] is False, 'mqtt deferred → disabled'
print('config contract ok')"
```
Expected: `config contract ok`.
- [ ] **Step 4: Commit.**
```bash
git add packages/secubox-frigate/conf/frigate.config.yml.example
git commit -m "feat(frigate): config example — OpenVINO detector + go2rtc demo source (ref #821)"
```

---

## Task 4: API shim (`api/main.py`) — status/cameras/events/storage/stats

**Files:**
- Create: `packages/secubox-frigate/api/main.py`, `packages/secubox-frigate/tests/test_shim.py`, `packages/secubox-frigate/tests/test_stats_contract.py`, `packages/secubox-frigate/tests/__init__.py`, `packages/secubox-frigate/pytest.ini`
- Reference: `packages/secubox-photoprism/api/main.py` (FastAPI app + JWT dep + socket idioms)

**Interfaces:**
- Consumes: `secubox_core.auth.require_jwt` (JWT dependency, from `common/secubox_core`), Frigate HTTP API at `FRIGATE_URL` (default `http://10.100.0.140:5000`).
- Produces: a FastAPI `app` with a `router` prefixed `/api/v1/frigate`, 5 GET handlers (all plain `def`), a module-level `_cache` dict + `refresh_cache()` background task started on `@app.on_event("startup")`, and a `_frigate_get(path)` helper that returns `(json_or_None, ok_bool)` fail-safe.

- [ ] **Step 1: write failing tests for the endpoint shapes + fail-safe.** Create `tests/test_shim.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib, inspect
from fastapi.testclient import TestClient

def _app(monkeypatch, frigate_stats=None, frigate_events=None, up=True):
    import api.main as m
    importlib.reload(m)
    # bypass JWT
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "test"}
    def fake_get(path):
        if not up:
            return None, False
        if path == "/api/stats":
            return frigate_stats or {"cameras": {"demo": {"camera_fps": 5, "detection_fps": 4.9, "process_fps": 5}},
                                     "detectors": {"ov": {"inference_speed": 12.3}},
                                     "service": {"version": "0.14.1", "uptime": 3600}}, True
        if path == "/api/events":
            return frigate_events or [{"id": "1", "label": "person", "camera": "demo", "start_time": 1, "zones": []}], True
        return {}, True
    monkeypatch.setattr(m, "_frigate_get", fake_get)
    return TestClient(m.app), m

def test_status_up(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/status")
    assert r.status_code == 200
    b = r.json()
    assert b["up"] is True and b["version"] == "0.14.1"

def test_status_down_is_failsafe(monkeypatch):
    c, _ = _app(monkeypatch, up=False)
    r = c.get("/api/v1/frigate/status")
    assert r.status_code == 200          # never 5xx
    assert r.json()["up"] is False

def test_cameras_shape(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/cameras")
    assert r.status_code == 200
    cams = r.json()["cameras"]
    assert cams[0]["name"] == "demo" and cams[0]["online"] is True

def test_events_bounded(monkeypatch):
    c, _ = _app(monkeypatch)
    r = c.get("/api/v1/frigate/events")
    assert r.status_code == 200
    assert r.json()["events"][0]["label"] == "person"

def test_all_handlers_plain_def(monkeypatch):
    _, m = _app(monkeypatch)
    for name in ("status", "cameras", "events", "storage", "stats"):
        fn = getattr(m, name)
        assert not inspect.iscoroutinefunction(fn), f"{name} must be plain def (aggregator SPOF rule)"
```
- [ ] **Step 2: run — fails (no module).**
Run: `cd packages/secubox-frigate && PYTHONPATH=../../common:. python3 -m pytest tests/test_shim.py -q`
Expected: FAIL (`ModuleNotFoundError: api.main` / import error).
- [ ] **Step 3: implement `api/main.py`.**
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""SecuBox-Deb :: secubox-frigate :: /api/v1/frigate/* shim (Foundation, #821)."""
import json, os, shutil, threading, time, urllib.request
from pathlib import Path
from fastapi import APIRouter, Depends, FastAPI

try:
    from secubox_core.auth import require_jwt
except Exception:  # test/offline fallback
    def require_jwt():  # noqa: D401
        return {"sub": "anon"}

FRIGATE_URL = os.environ.get("SECUBOX_FRIGATE_URL", "http://10.100.0.140:5000")
DATA_DIR = os.environ.get("SECUBOX_FRIGATE_DATA", "/data/frigate")
CACHE_FILE = Path("/var/cache/secubox/frigate/stats.json")
EVENTS_LIMIT = 50

app = FastAPI(title="secubox-frigate")
router = APIRouter(prefix="/api/v1/frigate")
_cache: dict = {}
_lock = threading.Lock()


def _frigate_get(path: str):
    """GET Frigate's HTTP API. Returns (json, True) or (None, False). Never raises."""
    try:
        with urllib.request.urlopen(FRIGATE_URL + path, timeout=3) as r:
            return json.loads(r.read().decode("utf-8")), True
    except Exception:
        return None, False


def _compute_status() -> dict:
    data, ok = _frigate_get("/api/stats")
    if not ok or not data:
        return {"up": False, "version": None, "uptime": None, "detector_fps": None}
    svc = data.get("service", {})
    det = next(iter(data.get("detectors", {}).values()), {})
    return {"up": True, "version": svc.get("version"), "uptime": svc.get("uptime"),
            "detector_fps": det.get("inference_speed")}


def _compute_cameras() -> list:
    data, ok = _frigate_get("/api/stats")
    if not ok or not data:
        return []
    out = []
    for name, c in (data.get("cameras") or {}).items():
        out.append({"name": name, "online": (c.get("camera_fps", 0) or 0) > 0,
                    "camera_fps": c.get("camera_fps"), "detection_fps": c.get("detection_fps"),
                    "process_fps": c.get("process_fps")})
    return out


def _compute_events() -> list:
    data, ok = _frigate_get("/api/events")
    if not ok or not data:
        return []
    out = []
    for e in data[:EVENTS_LIMIT]:
        eid = e.get("id")
        out.append({"id": eid, "label": e.get("label"), "camera": e.get("camera"),
                    "start_time": e.get("start_time"), "zones": e.get("zones", []),
                    "snapshot": f"/api/v1/frigate/media/events/{eid}/snapshot.jpg" if eid else None})
    return out


def _compute_storage() -> dict:
    try:
        du = shutil.disk_usage(DATA_DIR)
        rec = Path(DATA_DIR) / "recordings"
        oldest = None
        if rec.is_dir():
            files = sorted(rec.rglob("*.mp4"))
            if files:
                oldest = int(files[0].stat().st_mtime)
        return {"path": DATA_DIR, "total": du.total, "used": du.used, "free": du.free,
                "pct_used": round(du.used / du.total * 100, 1) if du.total else 0, "oldest_recording": oldest}
    except Exception:
        return {"path": DATA_DIR, "total": None, "used": None, "free": None, "pct_used": None, "oldest_recording": None}


def _compute_stats() -> dict:
    cams = _compute_cameras()
    evs = _compute_events()
    det = _compute_status().get("detector_fps")
    # TOP-LEVEL keys the sidebar reads directly (nac /stats contract).
    return {"cameras": len(cams), "events": len(evs), "fps": det,
            "by_camera": {c["name"]: c.get("detection_fps") for c in cams}}


def refresh_cache():
    while True:
        try:
            data = _compute_stats()
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(data))
            with _lock:
                _cache.update(data)
        except Exception:
            pass
        time.sleep(60)


@app.on_event("startup")
def _startup():
    threading.Thread(target=refresh_cache, daemon=True).start()


@router.get("/status")
def status(user=Depends(require_jwt)):
    return _compute_status()


@router.get("/cameras")
def cameras(user=Depends(require_jwt)):
    return {"cameras": _compute_cameras()}


@router.get("/events")
def events(user=Depends(require_jwt)):
    return {"events": _compute_events()}


@router.get("/storage")
def storage(user=Depends(require_jwt)):
    return _compute_storage()


@router.get("/stats")
def stats(user=Depends(require_jwt)):
    with _lock:
        if _cache:
            return dict(_cache)
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return _compute_stats()


app.include_router(router)
```
NOTE for the implementer: keep `status/cameras/events/storage/stats` as **module-level** `def`s (decorated with `@router.get`). Do not nest them inside another function — the tests read `m.status` etc. directly and assert `not iscoroutinefunction`.
- [ ] **Step 4: create `tests/__init__.py` (empty) and `pytest.ini`** with `[pytest]\ntestpaths = tests`.
- [ ] **Step 5: run — passes.**
Run: `cd packages/secubox-frigate && PYTHONPATH=../../common:. python3 -m pytest tests/test_shim.py -q`
Expected: PASS (5 tests).
- [ ] **Step 6: /stats contract test.** Create `tests/test_stats_contract.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import importlib
from fastapi.testclient import TestClient

def test_stats_top_level_keys(monkeypatch):
    import api.main as m
    importlib.reload(m)
    m.app.dependency_overrides[m.require_jwt] = lambda: {"sub": "t"}
    monkeypatch.setattr(m, "_frigate_get", lambda p: (
        ({"cameras": {"demo": {"camera_fps": 5, "detection_fps": 4.5, "process_fps": 5}},
          "detectors": {"ov": {"inference_speed": 10.0}}, "service": {"version": "0.14.1"}}, True)
        if p == "/api/stats" else ([{"id": "1", "label": "car", "camera": "demo"}], True)))
    m._cache.clear()
    b = TestClient(m.app).get("/api/v1/frigate/stats").json()
    assert set(["cameras", "events", "fps"]).issubset(b), "sidebar reads top-level cameras/events/fps"
    assert b["cameras"] == 1 and b["events"] == 1 and b["fps"] == 10.0
```
Run: `PYTHONPATH=../../common:. python3 -m pytest tests/test_stats_contract.py -q`
Expected: PASS.
- [ ] **Step 7: Commit.**
```bash
git add packages/secubox-frigate/api/main.py packages/secubox-frigate/tests packages/secubox-frigate/pytest.ini
git commit -m "feat(frigate): /api/v1/frigate shim — status/cameras/events/storage/stats, JWT, double-cached, fail-safe (ref #821)"
```

---

## Task 5: Host shim service + disk-pressure guard + `frigatectl`

**Files:**
- Create: `packages/secubox-frigate/debian/secubox-frigate.service`, `debian/secubox-frigate-diskguard.service`, `debian/secubox-frigate-diskguard.timer`, `sbin/secubox-frigate-diskguard`, `sbin/frigatectl`, `tests/test_diskguard.py`
- Reference: `packages/secubox-photoprism/debian/secubox-photoprism.service`, `packages/secubox-photoprism/sbin/photoprismctl`

**Interfaces:**
- Consumes: `api/main.py` (`app`).
- Produces: `secubox-frigate.service` (uvicorn on `/run/secubox/frigate.sock`, `User=secubox`, `RuntimeDirectoryPreserve=yes`), a `secubox-frigate-diskguard` oneshot+timer, `frigatectl {install,status,start,stop,restart}` delegating to `install-lxc.sh` + `lxc-attach`.

- [ ] **Step 1: shim service (copy photoprism's, retarget paths).** Create `debian/secubox-frigate.service`:
```ini
[Unit]
Description=SecuBox Frigate API shim
After=network.target secubox-core.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/frigate
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/frigate.sock --log-level warning
Restart=on-failure
RestartSec=5
UMask=0000
NoNewPrivileges=true
RuntimeDirectory=secubox
RuntimeDirectoryPreserve=yes
RuntimeDirectoryMode=0775
ReadWritePaths=/run/secubox /var/lib/secubox /etc/secubox /var/log/secubox /var/cache/secubox /data/frigate

[Install]
WantedBy=multi-user.target
```
- [ ] **Step 2: failing test for the disk guard.** Create `tests/test_diskguard.py`:
```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import subprocess, sys, os
GUARD = os.path.join(os.path.dirname(__file__), "..", "sbin", "secubox-frigate-diskguard")

def test_guard_fires_below_threshold(tmp_path):
    # DF override: guard reads SECUBOX_FRIGATE_DF_PCT for testability
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "95", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 2, "guard must exit 2 when over the limit"
    assert "disk pressure" in (r.stdout + r.stderr).lower()

def test_guard_ok_below_limit():
    env = {**os.environ, "SECUBOX_FRIGATE_DF_PCT": "40", "SECUBOX_FRIGATE_DISK_LIMIT": "90"}
    r = subprocess.run(["bash", GUARD], capture_output=True, text=True, env=env)
    assert r.returncode == 0
```
- [ ] **Step 3: run — fails (no guard script).**
Run: `cd packages/secubox-frigate && python3 -m pytest tests/test_diskguard.py -q`
Expected: FAIL.
- [ ] **Step 4: implement `sbin/secubox-frigate-diskguard`.**
```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: secubox-frigate :: /data disk-pressure guard.
set -euo pipefail
readonly DATA_DIR="${SECUBOX_FRIGATE_DATA:-/data/frigate}"
readonly LIMIT="${SECUBOX_FRIGATE_DISK_LIMIT:-90}"     # percent
# Testable: SECUBOX_FRIGATE_DF_PCT overrides the measured value.
if [ -n "${SECUBOX_FRIGATE_DF_PCT:-}" ]; then
    pct="$SECUBOX_FRIGATE_DF_PCT"
else
    pct="$(df --output=pcent "$DATA_DIR" 2>/dev/null | tail -1 | tr -dc '0-9')"
    pct="${pct:-0}"
fi
if [ "$pct" -ge "$LIMIT" ]; then
    logger -t secubox-frigate "disk pressure: ${pct}% >= ${LIMIT}% on ${DATA_DIR} — reduce retention"
    echo "disk pressure: ${pct}% >= ${LIMIT}%" >&2
    exit 2
fi
echo "disk ok: ${pct}% < ${LIMIT}%"
exit 0
```
- [ ] **Step 5: run — passes.**
Run: `python3 -m pytest tests/test_diskguard.py -q`
Expected: PASS (2).
- [ ] **Step 6: guard unit + timer.** Create `debian/secubox-frigate-diskguard.service` (`Type=oneshot`, `ExecStart=/usr/sbin/secubox-frigate-diskguard`, `User=secubox`) and `debian/secubox-frigate-diskguard.timer` (`OnCalendar=*:0/15`, `Persistent=true`, `WantedBy=timers.target`).
- [ ] **Step 7: `frigatectl` (copy photoprismctl, retarget).** Create `sbin/frigatectl` mirroring `sbin/photoprismctl`: subcommands `install` (runs `/usr/share/secubox/lib/frigate/install-lxc.sh`), `status`/`start`/`stop`/`restart` (`lxc-info`/`lxc-attach -n frigate ... systemctl <verb> frigate`). `bash -n` clean.
Run: `bash -n packages/secubox-frigate/sbin/frigatectl && bash -n packages/secubox-frigate/sbin/secubox-frigate-diskguard && echo OK`
Expected: `OK`.
- [ ] **Step 8: Commit.**
```bash
git add packages/secubox-frigate/debian/secubox-frigate.service packages/secubox-frigate/debian/secubox-frigate-diskguard.* packages/secubox-frigate/sbin packages/secubox-frigate/tests/test_diskguard.py
git commit -m "feat(frigate): host shim service + disk-pressure guard + frigatectl (ref #821)"
```

---

## Task 6: Cross-node exposure (WAF) + nginx route + menu.d + sidebar stats

**Files:**
- Create: `packages/secubox-frigate/conf/frigate.nginx.conf`, `packages/secubox-frigate/menu.d/618-frigate.json`
- Reference: `packages/secubox-photoprism/conf/photoprism.nginx.conf`, `packages/secubox-photoprism/menu.d/617-photoprism.json`, and the sidebar contract at `packages/secubox-hub/www/shared/sidebar.js:203-218`

**Interfaces:**
- Produces: an nginx location routing `/api/v1/frigate/` → the shim socket; a `menu.d` entry; documentation of the gk2 HAProxy + both mitmproxy route-file edits (applied at deploy, not in the package).

- [ ] **Step 1: nginx route.** Create `conf/frigate.nginx.conf` mirroring photoprism's, but the API location proxies to the shim socket and the UI location routes through the WAF (documented), NOT a bypass:
```nginx
# secubox-frigate — API shim (local socket) + placeholder UI.
# NOTE: the Frigate UI itself is fronted by gk2 HAProxy→mitmproxy→mesh→amd64
# (no waf_bypass). This file only serves the shim API + the placeholder page.
location /api/v1/frigate/ {
    proxy_pass http://unix:/run/secubox/frigate.sock:/api/v1/frigate/;
    include /etc/nginx/snippets/secubox-proxy.conf;
    proxy_intercept_errors on;
}
location /frigate/ {
    alias /usr/share/secubox/www/frigate/;
    index index.html;
    try_files $uri $uri/ /frigate/index.html;
}
```
- [ ] **Step 2: menu.d entry.** Create `menu.d/618-frigate.json` mirroring `617-photoprism.json` shape — title "Frigate", path `/frigate/`, an appropriate icon, category security/media. Verify JSON parses:
Run: `python3 -c "import json; json.load(open('packages/secubox-frigate/menu.d/618-frigate.json')); print('ok')"`
Expected: `ok`.
- [ ] **Step 3: document the sidebar stats wiring.** In `README.md`, record the exact line to add to `packages/secubox-hub/www/shared/sidebar.js` PAGE_METRICS map (the shared navbar; a hub change, applied separately):
```
'/frigate/': { metrics: ['cameras','events','fps'], api: '/api/v1/frigate/stats' },
```
(Do NOT edit sidebar.js in this package — it belongs to secubox-hub; note it for the deploy step. The `/stats` endpoint already returns those top-level keys — Task 4.)
- [ ] **Step 4: document the gk2 WAF exposure (deploy-time, both route files).** In `README.md`, record the exact deploy steps (run on gk2, not in the package):
```
# gk2: front the amd64 Frigate UI through the WAF (NO bypass)
haproxyctl vhost add frigate.gk2.secubox.in          # backend defaults to mitmproxy_inspector
# add to BOTH /srv/mitmproxy/haproxy-routes.json AND /srv/mitmproxy-in/haproxy-routes.json:
#   "frigate.gk2.secubox.in": ["10.100.0.140", 5000]   # amd64 frigate LXC over the mesh
systemctl restart mitmproxy
```
- [ ] **Step 5: Commit.**
```bash
git add packages/secubox-frigate/conf/frigate.nginx.conf packages/secubox-frigate/menu.d packages/secubox-frigate/README.md
git commit -m "feat(frigate): nginx shim route + menu.d + documented WAF exposure & sidebar stats (ref #821)"
```

---

## Task 7: postinst / prerm + build & install verification

**Files:**
- Create/modify: `packages/secubox-frigate/debian/postinst`, `debian/prerm`, `debian/rules` (install stanzas)
- Reference: `packages/secubox-photoprism/debian/{postinst,prerm,rules}`

**Interfaces:**
- Produces: postinst that creates the `secubox` interaction dirs, enables the shim + diskguard timer (NOT the in-LXC frigate unit), and runs `frigatectl install` (provision the LXC) — guarded so a build host without LXC doesn't fail; prerm stops the shim + timer, leaves `/data/frigate` + `/etc/secubox/frigate` intact.

- [ ] **Step 1: postinst (mirror photoprism, adapt).** Create `debian/postinst`:
```bash
#!/bin/bash
set -e
case "$1" in
  configure)
    install -d -m 0755 -o secubox -g secubox /var/cache/secubox/frigate 2>/dev/null || true
    systemctl daemon-reload || true
    deb-systemd-helper enable secubox-frigate.service >/dev/null 2>&1 || true
    deb-systemd-invoke restart secubox-frigate.service >/dev/null 2>&1 || true
    systemctl enable --now secubox-frigate-diskguard.timer >/dev/null 2>&1 || true
    # Provision the LXC only where LXC is available (the amd64 host). Never fail install.
    if command -v lxc-create >/dev/null 2>&1; then
        /usr/sbin/frigatectl install || echo "frigatectl install deferred — run manually on the frigate host" >&2
    fi
    ;;
esac
#DEBHELPER#
exit 0
```
- [ ] **Step 2: prerm.** Create `debian/prerm`:
```bash
#!/bin/bash
set -e
case "$1" in
  remove|deconfigure)
    systemctl stop secubox-frigate-diskguard.timer >/dev/null 2>&1 || true
    deb-systemd-invoke stop secubox-frigate.service >/dev/null 2>&1 || true
    # Leave the frigate LXC, /data/frigate, and /etc/secubox/frigate intact (data-preserving).
    ;;
esac
#DEBHELPER#
exit 0
```
- [ ] **Step 3: rules install stanzas + no dh_installsystemd auto-manage of the in-LXC unit.** In `debian/rules`, ensure `lib/frigate/frigate.container` is installed to `/usr/share/secubox/lib/frigate/` (NOT to `/lib/systemd`), the `.example` to `/usr/share/secubox/frigate/`, `sbin/*` to `/usr/sbin/`, `www/frigate/` to `/usr/share/secubox/www/frigate/`, `conf/frigate.nginx.conf` to the module nginx dir, `menu.d/*` to `/usr/share/secubox/menu.d/`, `api/` to `/usr/lib/secubox/frigate/`. Mirror photoprism's `rules` exactly for placement.
- [ ] **Step 4: build the full package.**
Run: `cd packages/secubox-frigate && dpkg-buildpackage -us -uc -b 2>&1 | tail -3`
Expected: builds `secubox-frigate_0.1.0-1~bookworm1_all.deb`.
- [ ] **Step 5: verify the .deb ships everything + scripts parse.**
Run:
```bash
dpkg-deb -c ../secubox-frigate_0.1.0-1~bookworm1_all.deb | grep -E "install-lxc.sh|frigate.container|frigate.config.yml.example|usr/sbin/frigatectl|secubox-frigate-diskguard|api/main.py|www/frigate|618-frigate.json"
dpkg-deb -e ../secubox-frigate_0.1.0-1~bookworm1_all.deb /tmp/frig-ctl && bash -n /tmp/frig-ctl/postinst && bash -n /tmp/frig-ctl/prerm && echo "maintainer scripts OK"
```
Expected: all paths present; `maintainer scripts OK`.
- [ ] **Step 6: full test suite green.**
Run: `PYTHONPATH=../../common:. python3 -m pytest tests -q`
Expected: all pass (shim + stats-contract + diskguard).
- [ ] **Step 7: Commit.**
```bash
git add packages/secubox-frigate/debian/postinst packages/secubox-frigate/debian/prerm packages/secubox-frigate/debian/rules
git commit -m "feat(frigate): postinst/prerm (provision LXC, data-preserving) + build verification (ref #821)"
```

---

## Deployment (post-merge, human-run — NOT part of the plan's tasks)

Documented in `README.md` (Task 6). On amd64: install the `.deb` → postinst runs `frigatectl install` → LXC boots Frigate with the demo source. On gk2: `haproxyctl vhost add frigate.gk2.secubox.in`, add the route to **both** mitmproxy files, `systemctl restart mitmproxy`, and add the sidebar PAGE_METRICS line to secubox-hub. Verify `/api/v1/frigate/status` `up:true`, the sidebar badge populates, and Frigate's UI loads through the WAF chain.

---

## Self-Review Notes

- **Spec coverage:** §4.2 LXC/podman → Task 2; §4.3 config → Task 3; §4.4 shim (5 endpoints, plain def, double-cache, fail-safe) → Task 4; §4.5 cross-node WAF (both route files, no bypass) → Task 6; §4.6 security (JWT, secrets, RuntimeDirectoryPreserve) → Tasks 4/5/6; storage + disk guard → Task 5; menu.d + /stats → Task 6; packaging/postinst → Tasks 1/7. All covered.
- **Deferred (per spec §2):** C3BOX dashboard (sub-project 2), MQTT (config `enabled:false`), 4R double-buffer — none appear as tasks. Correct.
