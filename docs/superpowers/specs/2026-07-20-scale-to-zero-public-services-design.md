<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# Scale-to-Zero for SecuBox Public Services — Design

**Date:** 2026-07-20
**Owner module:** `secubox-profiles` (extends it) + two companion services it ships
**Status:** approved design → implementation plan next
**Builds on:** secubox-profiles 0.7.0 observed-state actuator (#893), the streamlit-sleeper pattern, the sbxwaf/nginx front, the cellule-in-a-box direction.

---

## Goal

Let rarely-accessed public services **sleep when idle** (container stopped → RAM
freed) and **wake on access** (first request starts them, behind a branded
"starting…" splash), governed by a **per-module lifecycle policy**. The payoff
is RAM on a single box (many services, few concurrently used) — the enabling
condition for cellule-in-a-box (per-client cells that mostly sleep).

## Non-goals

- Not a load balancer / autoscaler / HA — single box by design (mesh ≠ HA).
- Not freeze/suspend — sleep is a **full stop** (RAM must actually be freed).
  Freeze (keep RAM, instant wake) was explicitly rejected: no RAM gain.
- Never sleeps the gateway path (HAProxy/sbxwaf/nginx), auth, aggregator, or any
  `always-on`/`protected` module.
- No change to the 0.7.0 actuator's start/stop/observed-state internals — this
  feature *drives* it, it does not reimplement it.

## Global Constraints

- Python 3.11 (`from __future__ import annotations`, SPDX header block); Go where
  a component must sit on the hot request path only if justified (the waker is
  Python on its own socket unless profiling says otherwise).
- **webui→ctl guideline:** any privileged/system-driving action (start/stop a
  module, edit nginx/route config) goes through a confined, audited root `ctl`
  over scoped exact-command sudoers; unprivileged services never actuate
  in-process.
- **Reuse the 0.7.0 actuator** for all start/stop (observed-state arbiter,
  4R snapshot, audit, per-module derived timeout). `wakectl`/`sleeper` call the
  same `profilectl`-class path, never raw `lxc-start`/`systemctl`.
- Single uvicorn worker per service (process-local locks are valid, as in
  secubox-profiles' `_apply_lock`); each service on its own Unix socket under
  `/run/secubox/`.
- Audit every lifecycle decision (wake, sleep, refusal) to
  `/var/log/secubox/audit.log`.
- Sequential actuation, one module at a time (inherited from the actuator).
- Commit trailer `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, no Claude
  references.

---

## Per-module lifecycle policy (manifest)

Two new optional fields on each module manifest (`/etc/secubox/modules.d/<id>.toml`),
parsed by the existing `secubox-profiles` manifest loader:

| Field | Values | Default | Meaning |
|-------|--------|---------|---------|
| `lifecycle` | `always-on` \| `eager` \| `on-demand` \| `manual` | `eager` | see below |
| `wake_class` | `normal` \| `urgent` | `normal` | wake priority / idle grace |

- **`always-on`** — never sleeps; excluded from the sleeper. Core/gateway/auth/
  aggregator/WAF, and anything `protected`. (A `protected` module is treated as
  `always-on` regardless of its declared `lifecycle`.)
- **`eager`** — started at boot (warm first access), but idle-sleeps when unused
  and wakes on access. Default for normal apps.
- **`on-demand`** — boot-cold (off at boot), wakes on first access, idle-sleeps.
  Maximum RAM savings; the cellule-in-a-box default.
- **`manual`** — stays off until an operator explicitly starts it; never
  auto-started (no wake-on-access) and never auto-slept.
- **`wake_class=urgent`** — the sleeper uses a **longer idle threshold** (sleeps
  it more reluctantly) and the splash shows a **lower expected budget**. No
  pre-warm / predictive wake in this spec (deferred).

Only `eager` and `on-demand` participate in sleep/wake. `always-on` and `manual`
are inert to this feature (but their fields are still validated).

---

## Architecture & components

Front topology is unchanged: `HAProxy → sbxwaf :8085 → nginx :9080 → container`.
The feature adds an **activator** on the wake path and a **sleeper** on a timer,
both delegating actuation to the 0.7.0 actuator via a root ctl.

### 1. Manifest schema (secubox-profiles)
Add `lifecycle` + `wake_class` to the `Manifest` model and loader, with the
defaults and validation above. `scan` (manifest derivation) sets `lifecycle`
to a safe default (`always-on` for anything currently protected/core; `eager`
otherwise) — never silently makes a running service sleepable without an
explicit manifest. Status/diff/export gain read-only visibility of the fields.

### 2. `secubox-wakectl` (root ctl)
`secubox-wakectl wake <module> [--json]` — starts the module through the 0.7.0
actuator path (the same `apply --only <module>` machinery: observed-state wait,
4R snapshot, audit, derived timeout). Refuses `manual` (no auto-wake) and
unknown modules; idempotent if already up. Emits a `--json` report the waker
consumes. Scoped sudoers grants exactly the waker's fixed argv (systemd-run
wrapper if the caller service is `ProtectSystem=strict`, per the 0.7.0 lesson).

### 3. `secubox-waker` (activator service — own socket `/run/secubox/waker.sock`)
The HTTP service nginx routes a down on-demand vhost to. Per request for a
sleeping module `m`:
1. Resolve vhost → module via the route map (the WAF `haproxy-routes.json` /
   an nginx-generated vhost→module table).
2. Acquire the **per-module wake lock** (async lock keyed by module) so N
   concurrent requests trigger exactly **one** wake.
3. If not already waking: fire `sudo -n … secubox-wakectl wake <m> --json`
   **non-blocking** (background task), record wake-start time.
4. Return **HTTP 503 + `Retry-After`** with a branded splash page that
   auto-refreshes (meta-refresh + JS poll) and shows the **wake budget**
   (estimated seconds, derived from `wake_class` + a rolling median of past wake
   durations for `m`).
5. On a later poll, if the module is observed UP → 200 signalling nginx to
   proxy (or a redirect so the client re-hits the now-live backend); if the
   wake **failed** (wakectl reported failure / observed-state never reached
   within the actuator's derived timeout) → a branded **error** page (not an
   infinite splash), release the lock, audit.
The splash never blocks a worker on the wake — the wake runs in the background;
each poll is a fast state check.

### 4. nginx integration
For each `on-demand`/`eager` vhost, a generated snippet routes upstream failure
to the waker instead of a bare 502:
```
location / {
    proxy_pass http://<container-upstream>;
    proxy_next_upstream error timeout http_502 http_504;
    error_page 502 504 = @waker;
}
location @waker { proxy_pass http://unix:/run/secubox/waker.sock; }
```
Generated by a `ctl` (root), not hand-edited; regenerated when a module's
`lifecycle` changes. Always-on vhosts get no `@waker` (a real 502 stays a 502).

### 5. `secubox-sleeper` (daemon + timer)
Periodically (e.g. every 60 s), for each `eager`/`on-demand` module currently UP:
- **idle** iff `last_request_age > idle_threshold(m)` **AND** `active_conns(m) == 0`
  **AND** (module exposes `/idle` → it reports idle, else ignored).
- `idle_threshold(m)` derives from `wake_class` (urgent → longer).
- On idle → STOP via the actuator (`profilectl apply --only <m>` → stop path:
  4R snapshot, observed-state, audit). Coordinates with the wake lock: never
  stops a module that is mid-wake or was accessed within the last poll.
- Never touches `always-on`/`manual`/`protected`. Excludes the streamlit
  sleepers already handled by the watchdog (no double-management).

**Front signals (hybrid idle):**
- `last_request` + `active_conns` per vhost come from the front — sbxwaf stats
  and/or nginx `stub_status`/access-log tailing (exact source picked in the
  plan; both are read-only observations).
- Optional per-module `GET /idle` hint (JSON `{"idle": bool, "reason": …}`) —
  a module with long-lived sessions/websockets (matrix, peertube-live) can veto
  a sleep the front would otherwise trigger. Absence of the endpoint = front
  decision stands.

### 6. webui (profiles panel)
Read + light control: per module show `lifecycle`, `wake_class`, live sleep
state (up/asleep/waking), and the wake budget; **manual sleep/wake** buttons
(delegate to `wakectl`/`profilectl` via the webui→ctl path). Editing a module's
`lifecycle`/`wake_class` writes the manifest (through a ctl) and regenerates the
nginx snippet.

---

## Data flow

**Sleep:** `secubox-sleeper` timer → per-module idle check (front + hint) →
actuator STOP (snapshot + audit) → nginx now sees the upstream down.

**Wake:** request → sbxwaf → nginx → upstream down → `@waker` → waker acquires
lock → `wakectl wake <m>` (background) → 503 splash (auto-refresh + budget) →
client polls → module observed UP → nginx proxies the live backend.

---

## Concurrency, error handling, safety

- **One wake per module:** the waker's per-module async lock collapses a burst
  of concurrent first-requests into a single `wakectl` call.
- **Sleep/wake race:** the sleeper checks the wake lock and the last-request
  timestamp immediately before stopping; a module accessed or waking in the
  current window is skipped. The actuator's own observed-state arbiter prevents
  a half-stopped/half-started module from being mis-reported.
- **Wake failure:** surfaced as a branded error page + audit; the module stays
  down; the lock is released so a later request can retry.
- **Wake storm / DoS:** an unauthenticated request to a sleeping vhost triggers
  a container start — a cost. Mitigations: the wake lock (one start per module
  regardless of request volume), a per-module wake-rate cap (min interval
  between wake attempts), and `on-demand` reserved for services whose wake cost
  is acceptable. Auth-gated vhosts wake only after the auth layer (which is
  `always-on`) — so anonymous callers can't wake an auth-walled app's backend.
- **Boot:** `on-demand` modules are NOT started at boot; `eager` are; the boot
  reconciler must respect `lifecycle` (does not force-start `on-demand`, does
  not fight the sleeper).
- **Watchdog coexistence:** `secubox-watchdog` auto-revives stopped
  `lxc.start.auto=1` containers — an `on-demand`/asleep module must be excluded
  from watchdog revival (else it fights the sleeper), exactly as streamlit
  sleepers are today.

## Testing

- Manifest: `lifecycle`/`wake_class` parse + defaults + validation; `protected`
  ⇒ treated always-on; scan defaults are safe.
- wakectl: wakes via the actuator; refuses `manual`/unknown; idempotent if up;
  `--json` shape; sudoers argv exact.
- waker: vhost→module resolve; **one** wake under N concurrent requests (lock);
  503 splash + Retry-After + budget; up → proxy signal; wake-failure → error
  page + lock released; wake-rate cap.
- sleeper: idle = last-request AND 0-conns AND hint; never stops
  always-on/manual/protected; skips mid-wake; STOP goes through the actuator;
  urgent → longer threshold.
- nginx snippet generation: on-demand gets `@waker`, always-on does not;
  regenerated on lifecycle change.
- Integration (board pilot): pick one low-risk on-demand service, drive
  full sleep → wake-on-access → serve, verify RAM freed while asleep, splash
  shown, service live after wake, gateway/other vhosts unaffected.

## Rollout

Source-first. Ship behind an explicit per-module opt-in (`lifecycle=on-demand`
must be set deliberately; nothing sleeps by default beyond `eager`'s idle-sleep,
which itself only applies once a module declares it). Validate on **one pilot
service** end-to-end before widening. Bump secubox-profiles minor; document the
policy in the module README + wiki + WEBUI-PANEL-GUIDELINES.

## Risks / open tuning (for the plan)

- Exact front source for `last_request`/`active_conns` (sbxwaf stats vs nginx
  stub_status vs access-log tail) — pick the lowest-overhead reliable one.
- Idle-threshold defaults per `wake_class` — start conservative (long), tune.
- Wake-budget estimation (rolling median vs static per class) — start static
  per class, refine with history.
- Splash UX must not itself be cached by sbxwaf's media cache (Content-Encoding
  / cache-key lessons) — mark it no-store.
