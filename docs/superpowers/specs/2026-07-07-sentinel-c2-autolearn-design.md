<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Sentinel C2/Botnet Auto-Learning — Design

**Date:** 2026-07-07
**Related:** #823 (Sentinel engine), builds on the live activation (#825)
**Status:** Design — pending user review

---

## Goal

Automatically learn C2/botnet indicators from observed traffic and grow a
learned indicator overlay, with **high-precision false-positive suppression** so
legitimate periodic traffic (mail/webmail polling, admin WebUI dashboards,
monitoring/health checks, NTP, update-checkers) is never learned as C2.

**Report-only.** Learned indicators carry `action=report`; `FinalizeAction`
keeps behavioral/learned classes report-only forever — never auto-block.

Non-goal: new *detection* of beaconing (the `Behavioral` engine already fires
`ClassBotnetC2` beacon verdicts). This adds a **promotion layer + FP gate** that
turns sustained, corroborated beaconing into persistent learned indicators.

---

## Background — what already exists

- `internal/sentinel/behavioral.go`: the beaconing detector. Per
  `(MacHash, Host)` it tracks inter-arrival times; once `beaconMinHits=6` hits
  with coefficient-of-variation `≤ beaconJitterCV=0.20`, it fires one
  `ClassBotnetC2` verdict (`sev/conf 70`, `ActionReport`, evidence
  `{pattern:beaconing, host, interval_s}`), latched once per key.
- `internal/sentinel/pack.go`: `Loader` globs an overlay directory of `*.json`
  packs, `MergePacks` merges base + overlays (overlay entry overrides base on
  same `(Type,Value)`), hot-reload with a throttle, fail-closed on base-dir
  disappearance. Overlay dir on gk2 = `/var/lib/secubox/sentinel/overlay`.
- IOC pack entry shape (`botnet.json`): `{type, value, class, severity, source,
  action}`. `type ∈ {domain, ip, ja3, ...}`.
- `FlowMeta` carries: `Host, URL, ClientIP, JA3, JA4, CertSHA1, FileSHA256,
  MacHash`. (No Referer — signals are computed from these fields only.)
- `cmd/sbxmitm/adcand*.go`: the existing autolearn candidate→confirm pattern
  (records a candidate host with a hits count, an allowlist, and first-party
  suppression) — the model this mirrors.
- The live-feed fetcher `secubox-sentinel-feeds` writes overlay packs atomically
  (write-temp + validate non-empty JSON + rename) — the atomic-write model this
  reuses.

---

## Architecture

A new package unit `internal/sentinel/c2learn.go` (`C2Learner`) sits downstream
of `Behavioral`. It is an `Analyzer` wrapper / post-step in the daemon: it never
blocks the analyze path, is fully fail-safe, and bounded in memory.

```
mirror → Behavioral(beacon verdict) ─┐
                                     ├─▶ C2Learner.Observe(flow, beaconVerdict)
FlowMeta ────────────────────────────┘        │
   FP-gate (c2allow) ──drop──▶ (suppressed)    │
   signals (rare / non-browser JA4 / DGA) ─────┤
   candidate store (c2cand) ───────────────────┤
   sustained + corroborated? ──▶ promote ───▶ learned-c2.json (overlay)
                                                   │
                                    Loader hot-reload → Gate match (report)
                                                   │
                                        /stats · /verdicts · 3 surfaces
```

### Component 1 — FP gate (`c2allow.go`)

`Allowed(host) bool` — the host is **allowlisted (never learned)** if it matches
ANY of:
- **box's own vhosts / admin domains** — read from a box-domains source at
  startup + on reload. Source: the HAProxy routes file
  (`/etc/secubox/waf/haproxy-routes.json`) keys and/or a seeded
  `box-domains.txt`; both optional/fail-safe. This is the primary "admin WebUI"
  suppressor.
- **first-party / LAN** — `Host` whose registrable domain equals the box's own
  registrable domain, or a `Host` that is an RFC1918 / loopback / link-local IP
  literal.
- **seeded operator allowlist** `c2-allow.txt` — one host/suffix per line,
  pre-seeded with: mail/webmail providers, monitoring/health endpoints, NTP,
  OS/browser update + telemetry, and major CDNs. Operator-editable; hot-reloaded.
- (optional, bundled) a high-reputation top-domains list — suffix match.

Matching is suffix-aware (`sub.example.com` matches an `example.com` entry).
All sources are fail-safe: a missing/corrupt file contributes no entries (logs
once), never errors the learner.

### Component 2 — corroborating signals (`c2signal.go`)

Computed from `FlowMeta` for the beaconing host. Promotion requires **≥1**:
- **rare/unknown destination** — `Host` global first-seen recently / very low
  cumulative hit-frequency across the daemon's observation window (a bounded
  frequency map). A long-established destination is not "rare".
- **non-browser JA3/JA4** — `JA4` (fallback `JA3`) not in a bundled
  known-browser fingerprint set. An admin dashboard polled by a real browser has
  a browser JA4 → this signal does NOT fire → suppressed. Empty JA4 (non-TLS or
  unknown) is treated as *unknown*, not automatically "non-browser" (avoid FP on
  missing data) — configurable.
- **DGA-ish / high-entropy domain** — Shannon entropy of the registrable label
  above a threshold, or long random-looking label. Reuses the entropy helper
  style from `behavioral.go`'s one-time-link check.

### Component 3 — candidate store + confirm (`c2cand.go`)

Bounded (LRU-capped) map keyed by `Host`:
`{host, firstSeen, lastSeen, windows, distinctDevices set, signals set,
meanInterval}`. A beacon that passes the gate AND has ≥1 signal
records/updates a candidate. **Promotion criteria (all required):**
- **sustained**: observed across `≥ c2MinWindows` (e.g. 3) separate beacon
  windows spanning `≥ c2MinSpan` (e.g. 30 min) — not one burst;
- **corroborated**: `≥1` corroborating signal present (see Component 2);
- distinct-device count raises the recorded confidence (more devices → higher),
  but a single device still promotes (targeted implant).

Persisted to `/var/lib/secubox/sentinel/c2-candidates.json` (atomic write) so
candidates survive daemon restarts. LRU + TTL bounded.

### Component 4 — promotion to learned overlay

On confirm, upsert the host into
`/var/lib/secubox/sentinel/overlay/learned-c2.json`:
`{type:"domain", value:<host>, class:"botnet_c2", severity:75, action:"report",
source:"autolearn", evidence:{signals, interval_s, devices}}`.
- **Atomic** write-temp-rename; validated non-empty JSON before rename (reuse
  the feeds fetcher's fail-safe model).
- **Deduped** by host; **size-capped** (e.g. ≤ 2000 entries, evict oldest).
- **TTL decay**: an entry not re-confirmed within `c2LearnedTTL` (e.g. 30 days)
  is aged out on the next write — the list self-cleans when a host goes quiet.
- The existing `Loader` hot-reloads the overlay → the `Gate` matches the host
  (report-only) → verdicts flow to `/stats`, `/verdicts`, and all three surfaces
  with `class=botnet_c2, source=autolearn`.

### Component 5 — surfaces + safety valve

- The daemon status HTTP gains read endpoints:
  `GET /c2/learned` and `GET /c2/candidates` (bounded, read-only, localhost).
- The portal proxies them (`/admin/sentinel/c2`), and the WebUI Sentinelle tab
  gains a **"C2 appris"** sub-view listing learned + candidate hosts with their
  signals/interval/devices.
- Each entry has **"Ignorer (allowlist)"** → `POST /admin/sentinel/c2/allow`
  (host) → the daemon appends the host to `c2-allow.txt` and removes it from the
  learned overlay + candidate store. One click corrects a rare FP; the allowlist
  addition prevents re-promotion.

---

## Error handling

- Fully fail-safe: the learner never blocks or panics on the analyze path;
  malformed `FlowMeta` fields make a signal a no-op.
- All file reads (allowlist, box-domains, candidates, overlay) fail to
  empty/no-op on missing/corrupt input, logged once — never fatal.
- All file writes atomic (temp + rename); a write failure is logged and dropped,
  never corrupts the live overlay.
- Bounded memory: LRU caps on the candidate map and the frequency map.
- Report-only invariant enforced at the source (`action:report` on every learned
  entry) AND by `FinalizeAction` (`ClassBotnetC2` is heuristic → report).

---

## Testing

- **FP gate**: box-vhost host suppressed; first-party (box registrable) host
  suppressed; RFC1918 IP host suppressed; a `c2-allow.txt` entry (and its
  subdomains) suppressed; a browser-JA4 beacon to a known domain not learned.
- **Multi-signal**: a sustained beacon to an *unknown-but-browser-JA4* host with
  no other signal → NOT promoted (periodicity alone insufficient); the same host
  with a non-browser JA4 → candidate.
- **Lifecycle**: one burst (single window) → candidate, not promoted; sustained
  across `≥ c2MinWindows` over `≥ c2MinSpan` + ≥1 signal → promoted; distinct
  devices raise recorded confidence.
- **Promotion**: learned-c2.json written atomically, deduped, capped; a
  never-re-confirmed entry past TTL is evicted on next write; overlay hot-reload
  makes the Gate match the host (report-only).
- **Safety valve**: allow-add removes the learned entry + candidate and prevents
  re-promotion; `c2-allow.txt` gets the host.
- **Report-only**: no learned/behavioral path ever yields `action=block`.
- **Fail-safe**: missing/corrupt allowlist, box-domains, candidates, overlay →
  learner still runs, no panic, no false promotion from garbage.
- **Surfaces**: `/c2/learned` + `/c2/candidates` shapes; portal proxy fail-safe
  (daemon dark → empty, HTTP 200); WebUI sub-view renders learned/candidate/empty
  states; escaping on all daemon-supplied host strings.

---

## Files

- `packages/secubox-toolbox-ng/internal/sentinel/c2learn.go` — **create**
  (orchestrator: Observe + promote).
- `packages/secubox-toolbox-ng/internal/sentinel/c2allow.go` — **create** (FP gate).
- `packages/secubox-toolbox-ng/internal/sentinel/c2signal.go` — **create**
  (rare / non-browser-JA4 / DGA signals + bounded frequency map).
- `packages/secubox-toolbox-ng/internal/sentinel/c2cand.go` — **create**
  (candidate store + confirm + persistence).
- `packages/secubox-toolbox-ng/internal/sentinel/*_test.go` — **create**.
- `packages/secubox-toolbox-ng/cmd/sbx-sentinel/main.go` — **modify** (wire the
  learner after Behavioral; pass overlay/allowlist/candidate paths from env).
- `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go` — **modify**
  (`/c2/learned`, `/c2/candidates`, `POST /c2/allow`).
- `packages/secubox-toolbox-ng/debian/` — **modify** (ship a seeded
  `c2-allow.txt` + known-browser-JA4 set; env vars in `sentinel.env`).
- `packages/secubox-toolbox/secubox_toolbox/sentinel_link.py` +
  `api.py` — **modify** (proxy `/admin/sentinel/c2*` + allow POST, fail-safe).
- `packages/secubox-toolbox/www/toolbox/index.html` — **modify** (C2 appris
  sub-view + Ignorer button).

---

## Config (env, defaults tuned for precision)

- `SENTINEL_C2_ALLOW_FILE=/etc/secubox/sentinel/c2-allow.txt`
- `SENTINEL_C2_BOX_DOMAINS=/etc/secubox/waf/haproxy-routes.json` (+ optional
  `box-domains.txt`)
- `SENTINEL_C2_CANDIDATES=/var/lib/secubox/sentinel/c2-candidates.json`
- `SENTINEL_C2_LEARNED=/var/lib/secubox/sentinel/overlay/learned-c2.json`
- thresholds: `c2MinWindows=3`, `c2MinSpan=30m`, `c2LearnedTTL=720h`, learned
  `severity=75`, candidate/learned caps `2000`. Constants, tunable in one place.

---

## Out of scope (deferred)

- Auto-*blocking* of learned C2 (stays report-only; a future operator opt-in).
- IP-literal C2 beyond the RFC1918 suppression (mirror is mostly HTTP host-based).
- Cross-device fleet correlation via the mesh (single-node learner for now).
- Payload-size / cert-chain signals (not reliably available from the async
  mirror today).
