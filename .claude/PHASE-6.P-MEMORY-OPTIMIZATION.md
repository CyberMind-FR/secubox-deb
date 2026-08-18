<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Phase 6.P — Memory handler analysis + optimization proposal

*Drafted 2026-06-06 after live profiling on gk2 (Marvell 7040, 8 GB RAM)*

---

## Current state

`MemAvailable 2.98 GB` ; not pressured, but **4.32 GB AnonPages = active app memory** with `3.4 GB swap used` even at idle — system has been touching swap historically.

### Top consumers (by RSS, host)

| RSS | Process | Notes |
|---:|---------|-------|
| 297 MB | java | peertube indexer |
| 283 MB | peertube node | media server |
| **174 MB** | **uvicorn secubox_toolbox** | ⚠ heaviest SecuBox FastAPI |
| 201 MB | crowdsec | LAPI + scenario engine |
| 189 MB | systemd-journal | retention queue |
| 164 MB | grafana | dashboard |
| 161 MB | python3 (mitm WAF) | LXC mitmproxy |
| 132 MB | systemd-journal #2 | second instance |
| ~60 MB × 15 | **uvicorn FastAPI per module** | secubox-auth, hub, mesh, threats, mitmproxy, toolbox, … |

### Hidden cost — duplicated Python interpreters

Each `secubox-<module>` ships its own systemd unit running `uvicorn api.main:app`. Each loads :

- Python 3.11 interpreter (~30 MB)
- FastAPI + Pydantic + Starlette (~15 MB)
- module-specific deps (~10-15 MB)

15 modules × ~60 MB = **~900 MB of duplicated Python overhead** — most of it identical code in different address spaces.

---

## Proposals (ordered by ROI)

### P1 — ASGI consolidation : 1 master uvicorn, N mounted sub-apps  ★★★★★

**Idea** : a new mini-package `secubox-aggregator` mounts each module's FastAPI under a path prefix and serves all via a single uvicorn process.

```python
# /usr/lib/secubox/aggregator/main.py
from fastapi import FastAPI
import importlib

app = FastAPI(title="SecuBox API gateway", version="1.0.0")

MODULES = ["auth", "hub", "mesh", "threats", "toolbox",
           "mitmproxy", "nac", "auth-guardian", "system",
           "vortex-firewall", "ad-guard", "cookies", "dpi", "soc"]

for name in MODULES:
    try:
        m = importlib.import_module(f"secubox_{name.replace('-','_')}.api.main")
        app.mount(f"/api/v1/{name}", m.app, name=name)
    except ImportError:
        continue  # module not installed
```

**Gain** : 14 × 60 MB = **~840 MB freed**. Plus shared connection pools, shared Pydantic schemas, faster startup.

**Risk** : a misbehaving module can take down the gateway. Mitigations :

- `try/except` around each `app.mount()` so one broken module doesn't poison startup
- Per-module ASGI middleware for circuit-breaker on exception spikes
- Keep nginx `/api/v1/<module>/` route mappings unchanged (nginx → unix socket of aggregator) so module path conventions stay

**Effort** : 1 week for the aggregator + per-module migration (each module loses its own systemd unit, gains a mount line).

### P2 — secubox_toolbox memory diet  ★★★★

The toolbox FastAPI is the heaviest single process. Quick wins :

- **Lazy load Jinja2 templates** : currently all 6 templates pre-loaded at startup. Switch to `env.get_template()` on first hit (saves ~10-15 MB cold start).
- **Lazy-import dpi_class** : 147 compiled regexes eat ~5 MB. Defer until first banner injection.
- **Tune uvicorn** : currently 9 threads detected. `--workers 1 --backlog 200 --limit-concurrency 100` on 4-core ARM is enough — no need for 9 threads. Saves ~30 MB.
- **PYTHONDONTWRITEBYTECODE=1** in the systemd unit Env : skip writing `.pyc` files (no benefit on small immutable lib code, just I/O noise).

Combined gain : **~50 MB** on toolbox alone.

### P3 — mitm WAF nightly restart + HTTP/2 disable  ★★★

mitmproxy has [known](https://github.com/mitmproxy/mitmproxy/issues/4631) memory growth with long-running HTTP/2 sessions (multiplexed streams retain state). Even with Phase 6.J `Connection: close`, the WAF process drifts up over days.

- `--set http2=false` on mitm WAF and mitm-wg : drops HTTP/2 multiplex retention.
- Add `RuntimeMaxSec=21600` (6h) to both mitm services. systemd auto-restarts cleanly. With Phase 7.A backend persistence, no operational impact.

Gain : **~50 MB** per mitm process recovered every 6h.

### P4 — Per-LXC `memory.max` enforcement  ★★★

Currently 0 of 16 LXCs have memory limits. A misbehaving app can balloon to consume all 8 GB. Pre-allocate sane budgets :

| LXC | Proposed `memory.max` | Reason |
|-----|----------------------:|--------|
| mitmproxy (WAF) | 512 MB | mitmproxy + addons |
| peertube | 1024 MB | media transcode is heavy |
| photoprism | 512 MB | indexer + Go binary |
| nextcloud | 512 MB | PHP + apache |
| mail | 384 MB | postfix + dovecot |
| matrix | 384 MB | synapse |
| gitea | 256 MB | go binary, minimal |
| grafana | 256 MB | go binary |
| authelia | 128 MB | go binary, light |
| roundcube | 256 MB | PHP webmail |
| horde | 256 MB | PHP groupware |
| yacy | 256 MB | java search engine |
| rustdesk | 128 MB | rust binary, light |
| mqtt | 128 MB | mosquitto |
| zigbee | 128 MB | zigbee2mqtt |
| lyrion | 384 MB | perl LMS |

Total budgeted : **5.5 GB** out of 8 GB. Leaves 2.5 GB for host (kernel, journal, FastAPI host services).

Implementation : `/etc/lxc/lxc-<name>.conf` lines :

```
lxc.cgroup2.memory.max = 512M
lxc.cgroup2.memory.swap.max = 0
```

`memory.swap.max = 0` prevents the LXC from touching swap — under pressure it gets OOM-killed cleanly instead of grinding swap.

### P5 — systemd-journal aggressive rotation  ★★

189 MB + 132 MB = 321 MB in journal queues. Currently using default settings.

In `/etc/systemd/journald.conf` :

```
SystemMaxUse=200M     # was unlimited
SystemMaxFileSize=20M # smaller rotation units
MaxRetentionSec=2week
```

`systemctl restart systemd-journald` after applying. Gain : ~200 MB stable.

### P6 — Disable unused LXCs  ★★

Operator decision — but `yacy`, `horde`, `rustdesk` look like dev/personal experiments. Stopping each frees ~100-150 MB.

```bash
sudo lxc-stop -n yacy
sudo lxc-stop -n horde
sudo lxc-stop -n rustdesk
# To prevent auto-restart at boot :
sudo sed -i 's/^lxc.start.auto = 1/lxc.start.auto = 0/' /var/lib/lxc/yacy/config
# … repeat for horde, rustdesk
```

---

## Aggregate impact estimate

| Proposal | Estimated gain | Risk | Effort |
|----------|--------------:|------|--------|
| P1 ASGI consolidation | **~840 MB** | medium (modules share fate) | 1 week |
| P2 toolbox diet | ~50 MB | low | 1 day |
| P3 mitm restart + http2=false | ~100 MB | low | 1 hour |
| P4 LXC memory.max | bounded blast radius | low | 1 hour |
| P5 journal rotation | ~200 MB | none | 5 min |
| P6 stop unused LXCs | ~300 MB | none | 5 min |
| **Total realistic** | **~1.5 GB** | | |

After P3+P4+P5+P6 (zero-risk, < 1 day) : **~600 MB freed**, swap pressure should disappear entirely.

After P1 + P2 (architectural, 1-2 weeks) : **~890 MB freed** on top — system would have 2.5 GB easy headroom even with all services running.

---

## Order recommended

1. **P5 + P6** today (5 min each, no risk) — immediate ~500 MB win
2. **P3** today (1h) — mitm nightly restart, http2=false
3. **P4** tomorrow (1h with testing) — LXC memory caps
4. **P2** this week (1 day) — toolbox diet
5. **P1** later (1 week) — biggest gain but most invasive ; do after Phase 7.C
   lands so the WAF stack is stable first

---

## Quick-win deployment now ?

P5 + P6 are 100% safe and immediate. If approved, I apply them and report
back with `free -h` before/after.

## Side note — lyrion HS

LXC `lyrion` runs OK (squeezeboxserver active, listens 9000/9090/3483).
HAProxy routes `lyrion.gk2.secubox.in` → `mitmproxy_inspector` backend.
503 means mitm WAF either doesn't have the route mapped, or the LXC IP
in `/srv/mitmproxy/haproxy-routes.json` is stale. Worth investigating
once memory optimization lands (some LXC bridge weirdness may be
memory-pressure-induced).
