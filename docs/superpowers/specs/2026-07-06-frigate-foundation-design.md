# Design — Frigate NVR Foundation (Sub-project 1 of #821)

- **Issue**: [#821](https://github.com/CyberMind-FR/secubox-deb/issues/821)
- **Date**: 2026-07-06
- **Licence**: LicenseRef-CMSD-1.0
- **Module**: new `packages/secubox-frigate/`
- **Scope**: Foundation only. The full custom C3BOX dashboard is **Sub-project 2** (separate spec).

## 1. Problème

SecuBox has no NVR / camera-analytics capability. Frigate (frigate.video) is a local-only NVR with
real-time AI object detection (person/car/…), event clips, and a mature API — a natural fit beside
DPI/WAF/SOC. It must land as a first-class SecuBox module, **LXC-native** (own systemd inside a dedicated
LXC, not driven by the `.deb`), reachable through the existing WAF/Hub conventions — without a working
camera yet (framework-first).

## 2. Objectif (Foundation)

Frigate running in a dedicated LXC on the **amd64** node, validated against a **go2rtc demo source** (no real
camera), with a `secubox-frigate` `.deb` that provisions the LXC + config + storage, a JWT'd `/api/v1/frigate/*`
API shim (status/cameras/events/storage/stats), cross-node exposure through gk2's WAF, and the sidebar
`/stats` + `menu.d` integration. **Non-goals (deferred):** the custom C3BOX dashboard (Sub-project 2),
MQTT/Home-Assistant wiring, and full 4R double-buffer on the Frigate config.

## 3. Décisions (brainstorm 2026-07-06)

| Axe | Décision |
|-----|----------|
| Host | **amd64** (x86-64, `secubox-live`, mesh 10.10.0.3 / LAN 192.168.1.9) — most CPU/RAM headroom; detection-bound workload |
| Detector | **OpenVINO on CPU** (x86) — no extra hardware; model bundled in the Frigate image |
| Install | **Official Frigate OCI image via podman**, run by a **systemd quadlet INSIDE the LXC** (not by the `.deb`). Upstream is Docker-only; bare-metal is unsupported. The guideline's intent (the *package* doesn't drive containers) holds — the LXC's own systemd does |
| Cameras | **Framework-first** — a go2rtc demo/test source validates the pipeline; real cameras added to config later |
| WebUI | **Full custom C3BOX dashboard = Sub-project 2**; Foundation ships the API + a minimal placeholder page only |
| Shim placement | **amd64**, standalone `secubox-frigate.service` (mirrors how nac is served on amd64); gk2's Hub aggregates over the mesh |
| Exposure | gk2 **HAProxy → `mitmproxy_inspector` → (mesh) → amd64** — **no `waf_bypass`**; both mitmproxy route files updated |
| Storage/DB | Recordings + Frigate **SQLite** DB on amd64 `/data/frigate` (bind host→LXC→container); retention via Frigate config + a disk-pressure guard |
| Config | `/etc/secubox/frigate/config.yml` (+ `.example`); camera creds in `/etc/secubox/secrets/` chmod 600 |

## 4. Architecture

### 4.1 Runtime topology
```
amd64 host (192.168.1.9 / mesh 10.10.0.3)
  ├── /etc/secubox/frigate/config.yml         (operator config; bind-mounted in)
  ├── /data/frigate/{db,recordings,clips}     (media + SQLite; bind-mounted in)
  ├── LXC "frigate" (dedicated, idmap per fleet pattern)
  │     └── systemd quadlet → podman: ghcr.io/blakeblackshear/frigate:<pin>
  │           ├── frigate app (:5000 HTTP API + UI)
  │           ├── go2rtc      (:1984 / RTSP restream → WebRTC/MSE)
  │           └── OpenVINO detector (CPU)  + ffmpeg
  └── secubox-frigate.service  → /api/v1/frigate/*  (FastAPI shim, JWT, plain def)
        └── queries http://<lxc-ip>:5000 (Frigate API) + go2rtc

gk2 (WAF/Hub front)
  └── HAProxy(frigate vhost) → mitmproxy_inspector → nginx/route → (mesh) → amd64 frigate UI/API
  └── Hub polls amd64 /api/v1/frigate/stats over the mesh for cross-node aggregation
```

### 4.2 LXC provisioning — `lib/frigate/install-lxc.sh` (idempotent)
- Create the `frigate` LXC on amd64 if absent (Debian rootfs, idmap consistent with the fleet's shared
  pattern — mirror `secubox-photoprism`/`secubox-peertube` `install-lxc.sh`).
- Install podman in the LXC; drop the **quadlet** unit (`frigate.container`) that runs the official image
  with the bind mounts (`/etc/secubox/frigate` → container `/config`, `/data/frigate` → `/media/frigate`)
  and the OpenVINO device access needed on x86 CPU.
- `systemctl --machine` / `lxc-attach` enable+start the quadlet inside the LXC.
- Re-run = no-op (guarded creation, `podman pull` only past an image-tag change).
- The image tag is **pinned** (reproducible), overridable via config.

### 4.3 Frigate config (`/etc/secubox/frigate/config.yml`)
- Ships a validated **`.example`** with: the OpenVINO detector + bundled model, the go2rtc **demo source**
  (a test-pattern / sample RTSP so the pipeline runs with zero cameras), `record` + `snapshots` retention
  defaults, and a commented camera block operators fill in later.
- Frigate validates config on start and via its config API; a bad edit fails Frigate startup loudly (surfaced
  by the shim's `status`). Full 4R double-buffer is deferred.

### 4.4 API shim — `api/main.py` (`secubox-frigate`, FastAPI, JWT, **plain `def`**)
All handlers plain `def` (FastAPI threadpools them); stats-heavy ones **double-cached** (background refresh
task + JSON cache file, per the perf pattern) so a request never blocks on Frigate/go2rtc.
- `GET /api/v1/frigate/status` — Frigate reachable? version, uptime, detector inference speed/fps, config-valid.
- `GET /api/v1/frigate/cameras` — cameras + per-camera state (online, detect/record fps, last-seen) from Frigate `/api/stats`.
- `GET /api/v1/frigate/events` — recent detections (label, camera, ts, zone) + snapshot/clip URLs, from Frigate `/api/events` (bounded).
- `GET /api/v1/frigate/storage` — `/data/frigate` usage, retention days, oldest recording, free space.
- `GET /api/v1/frigate/stats` — **top-level** `{cameras, events, fps}` for the sidebar badge (matches the nac `/stats` contract the sidebar polls).
- Fail-safe: Frigate down → `status` reports it, other endpoints return empty/last-cache, never 5xx-storm.

### 4.5 Cross-node exposure (gk2 fronts amd64)
- Add a frigate vhost on gk2's HAProxy routed to `mitmproxy_inspector` (no `waf_bypass`); mitmproxy forwards
  over the mesh to amd64's Frigate UI/API. Update **both** `/srv/mitmproxy/haproxy-routes.json` and
  `/srv/mitmproxy-in/haproxy-routes.json` + restart mitmproxy (CLAUDE.md rule).
- nginx route `/api/v1/frigate/` on the serving node → the amd64 shim socket (local on amd64; over-mesh proxy
  entry on gk2 for the Hub).
- Frigate's UI is **never** exposed directly to the LAN/WAN — only via the WAF chain.

### 4.6 Security
- Frigate's built-in auth (0.14+) enabled; SecuBox **JWT** required on every shim endpoint (`Depends(require_jwt)`).
- Camera RTSP creds in `/etc/secubox/secrets/frigate-*` chmod 600 owner `secubox`; referenced from config, never in the repo.
- nftables on amd64: allow the frigate LXC → camera RTSP (LAN) only; no inbound to Frigate except via the WAF chain.
- `/run`/`/etc/secubox`/`/var/log/secubox`/`/data` parent perms untouched; media dir owned appropriately for the LXC idmap.

## 5. Data flow
```
go2rtc demo source ─▶ Frigate (detect via OpenVINO) ─▶ SQLite events + /data recordings
                                       │
        shim (amd64) ◀── Frigate /api/stats,/api/events ──┘
             │
   /api/v1/frigate/* (JWT, cached) ──▶ gk2 Hub (mesh) ──▶ sidebar badge / (later) C3BOX dashboard
   Frigate UI ──▶ HAProxy(gk2) ─ mitmproxy ─ mesh ─▶ amd64  (no waf_bypass)
```

## 6. Error handling / constraints
- **Fail-safe shim**: Frigate/LXC down → `status` says so; cached/empty elsewhere; never a 5xx storm (WAF would amplify).
- **Aggregator SPOF rule** applies IF the shim is ever aggregator-mounted: all handlers plain `def`, no blocking on the loop. On amd64 it's a standalone service, but keep the discipline for portability.
- **Idempotent provisioning**: `install-lxc.sh` re-run = no-op; a partial LXC create is repaired, never bricks the host.
- **Disk-pressure guard**: a small timer checks `/data` free space; below threshold → log + (config) reduce retention / alert. Recording never fills the disk unbounded.
- **Socket hygiene**: the shim service uses `RuntimeDirectoryPreserve=yes` (avoid the `/run/secubox` wipe that bit nac on the satellites).
- **Image pin**: reproducible Frigate version; upgrades are a deliberate tag bump, not silent `:latest`.

## 7. Tests
- `install-lxc.sh`: idempotent create (mock/dry-run), quadlet laid down, bind mounts correct, re-run no-op.
- Config `.example`: validates against Frigate's schema (or a lint) — demo source present, detector = openvino.
- Shim: each endpoint with a mocked Frigate `/api/stats`,`/api/events` fixture → correct shape; `/stats` top-level `{cameras,events,fps}`; JWT-gated (401 without token); plain `def`; Frigate-down → `status` down + others fail-safe (no 5xx).
- Storage guard: fixture `/data` low → guard fires (mocked df).
- Cross-node: route entries present in both mitmproxy files; HAProxy backend = `mitmproxy_inspector` (no bypass) — structural check.
- Manual: on amd64, LXC up, Frigate UI reachable through the WAF chain, demo source produces an event.

## 8. Séquencement (pour le plan)
1. Package scaffold (`secubox-frigate`: debian/, control, structure mirroring an LXC module).
2. `lib/frigate/install-lxc.sh` + the quadlet unit (create LXC, podman, bind mounts, OpenVINO) — idempotent.
3. Frigate `config.yml.example` (OpenVINO detector + go2rtc demo source + retention + commented camera).
4. API shim `api/main.py` (status/cameras/events/storage/stats, JWT, plain def, double-cache) + tests.
5. `secubox-frigate.service` (amd64 standalone) + storage/disk-pressure guard timer.
6. Cross-node exposure (HAProxy vhost + both mitmproxy route files + nginx `/api/v1/frigate/` route) + menu.d + sidebar `/stats` wiring.
7. postinst/prerm (provision LXC on install, stop cleanly; keep `/data` + config on remove) + changelog.

## 9. Risques
- **Frigate is Docker-first** — podman-in-LXC is the pragmatic path; watch cgroup/nesting quirks for podman inside LXC (may need `security.nesting=true` on the LXC).
- **OpenVINO on CPU** — modest fps; fine for framework validation + a few cameras. Coral/iGPU is a later upgrade, config-only.
- **Cross-node latency** — the shim runs local on amd64 (fast); only the UI proxy + Hub poll cross the mesh. Keep shim cached so the mesh hop never blocks a handler.
- **amd64 lacks the `RuntimeDirectoryPreserve` fix** — the shim ships its own drop-in; note the fleet-wide backport (separate).
- **Storage growth** — retention + disk guard mandatory before any real camera; unbounded recording would fill `/data`.
- **Scope creep toward the dashboard** — live view / event UI / config editing are explicitly Sub-project 2.
