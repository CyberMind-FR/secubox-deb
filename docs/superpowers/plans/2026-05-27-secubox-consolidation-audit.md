# SecuBox Modules Consolidation — Phase 1 Audit Findings

> **Status:** Phase 1 (audit only) complete. No code touched.
> Decision input for the consolidation plan stub
> [[2026-05-26-secubox-modules-consolidation]]. Each Tier in the
> "Proposed merges" section needs operator sign-off before any work
> in Phase 2.

## How this was produced

Run `python3 scripts/audit-packages.py` from repo root. Artifacts:

| File | Purpose |
|---|---|
| `out/packages.json` | Full structured inventory (one entry per `packages/secubox-*/`). |
| `out/packages.dot` | Graphviz dependency graph (Depends/Recommends edges between secubox-* binaries). |
| `out/empty-packages.txt` | Packages with no service, no route, no api, no www, no frontend build, not flagged as metapackage. |
| `out/clusters-by-prefix.txt` | Naive prefix grouping (catches `dns-*`, `soc-*`, etc. — misses `streamforge/streamlit` because no shared hyphen prefix). |
| `out/clusters-fuzzy.txt` | Hand-curated semantic clusters with per-member evidence (deps, routes, services). The primary input to merge decisions. |

Re-run the script after any packaging change to refresh the data.

## Headline numbers

| Metric | Count |
|---|---|
| `packages/secubox-*/` directories | 141 |
| Real metapackages (Section=metapackages) | 2 (`secubox-full`, `secubox-lite`) |
| Empty / broken packages | 1 truly empty + 1 broken (see below) |
| Packages depending on `secubox-core` | 131 / 141 (93%) |
| Packages with no nginx route | 38 (CLI/daemon-only or content-only) |
| Packages with no systemd service | 8 (frontends, defaults, broken) |
| Already-transitional packages (already mid-merge) | 3 (`mail-lxc`, `webmail`, `webmail-lxc` → `secubox-mail`) |

`secubox-core` is the universal substrate. `secubox-haproxy` is the
next-most-depended-on (7 dependents).

## Broken / needs immediate cleanup (independent of consolidation)

After widening the audit heuristic to recognise `etc/`, `kiosk/`,
`helper/`, etc., only two genuine issues remain.

1. **`secubox-c3box` binary name collision (CONFIRMED BUG)** — two
   source packages produce a `.deb` named `secubox-c3box`:
   - `packages/secubox-c3box/` — Architecture: all, Python FastAPI
     dashboard. Ships to `/usr/lib/secubox/c3box/`,
     `/usr/share/secubox/www/c3box/`, `/etc/nginx/secubox.d/c3box.conf`,
     `secubox-c3box.service` → `Depends: secubox-core`.
   - `packages/secubox-daemon/debian/control` — also declares
     `Package: secubox-c3box` (Architecture: any), built from
     `../../daemon/build/c3box` Go binary. Ships to `/usr/bin/c3box`,
     `/usr/share/c3box/www/`, `c3box.service` → `Depends: secubox-daemon`.

   File paths don't overlap, but **dpkg can only have one
   `secubox-c3box` package installed at a time** — whichever is
   installed second wins. Operators get whichever c3box happens to be
   built last by the build matrix.

   **Recommended fix**: rename the Go variant in the daemon source.
   `secubox-daemon-c3box` matches Debian's "Source-binary disambiguation"
   convention (cf. `linux` → `linux-image-*`, `linux-headers-*`). Patch
   sites: `packages/secubox-daemon/debian/control` (Package: stanza +
   `secubox-c3box.*` filenames → `secubox-daemon-c3box.*`),
   `packages/secubox-daemon/debian/rules` (`debian/secubox-c3box/...`
   paths), `packages/secubox-daemon/debian/secubox-c3box.{postinst,prerm}`
   filenames. Add `Conflicts: secubox-c3box (<< 1.1)` and
   `Provides:`/`Replaces:` boilerplate if needed for upgrade safety.
   Estimated effort: 30 min in a worktree, plus build verification.

2. **`secubox-smart-strip` packaging incomplete (deferred)** — real
   hardware module (SBX-STR-01: `firmware/` has MCU C code; `host/` has
   `secubox_smart_strip.py` + mockup HTML) that was scaffolded in
   commit `32fecbf0 feat(hardware): Add Smart-Strip HMI module
   (SBX-STR-01) + fix lite profile build` but never got a `debian/`
   directory. Currently un-buildable.

   **Recommended action**: file as separate hardware-track issue. The
   fix requires understanding the SBX-STR-01 hardware spec (UART
   protocol between host daemon and MCU firmware, systemd unit shape,
   AppArmor profile, udev rules for the serial device), which is out
   of scope for the consolidation track. Estimated effort: 1-2 days.

**False positives** (audit heuristic before fix v2; now resolved):

- `secubox-eye-square` ships `helper/` + `kiosk/` (Pi 4B framebuffer
  kiosk). Legit.
- `secubox-defaults` ships `/etc/default/secubox` via `etc/` + a
  `triggers` file. Legit content-only package; no service expected.
- `secubox-daemon` itself only declared in its 2-binary stanza — its
  ExecStart lives in `../../daemon/systemd/secuboxd.service` (out of
  tree) and is installed by `debian/rules`. Legit Go-cross-build layout.

## Proposed merges (by tier — needs per-cluster sign-off)

Marks below: **-N** = net reduction in package count after merge.
Evidence lives in `out/clusters-fuzzy.txt`.

### Tier 1 — Finish what's already started (recommend: do first)

**`secubox-mail` cluster: 5 → 1 or 2  (-3 to -4)**
- Members: `secubox-mail`, `secubox-mail-lxc`, `secubox-webmail`,
  `secubox-webmail-lxc`, `secubox-smtp-relay`
- `mail-lxc`, `webmail`, `webmail-lxc` already self-identify as
  "Transitional package — moved to secubox-mail" in their Description.
  They just need `Provides:`/`Replaces:`/`Conflicts:` plumbing
  finished and removal from the build matrix.
- `smtp-relay` is debatable — distinct purpose (outbound relay vs
  inbound mailserver) but same operator concern. Recommend: **keep
  `smtp-relay` separate**, finish the other 3 transitions.
- Effort: 1 day. Risk: low (transition already declared).

### Tier 2 — Strong evidence, small surface (good first real merges)

**~~`secubox-streamlit` cluster: 2 → 1 (-1)~~ SKIPPED on closer inspection (2026-05-27)**
- Members: `secubox-streamlit`, `secubox-streamforge`
- `secubox-streamlit` already ships two services (`secubox-streamlit.service`
  and `secubox-streamlit-idle.service`) — the idle variant the plan
  stub flagged as a separate package is already an in-package
  `ExecStart` variant.
- However, the two packages serve **distinct operator workflows**:
  `secubox-streamlit` is the runtime that **runs** Streamlit apps in
  an LXC container (depends on `lxc`, `debootstrap`, sudoers for LXC,
  955-line FastAPI, 934-line CLI). `secubox-streamforge` is the
  template/author tool for **building** apps (no LXC, 660-line
  FastAPI, 143-line CLI). They appear as separate menu entries
  (🎯 "Streamlit app platform" vs 🔨 "Streamlit app development")
  and map back to two distinct LuCI apps in the OpenWrt source
  (`luci-app-streamlit` and `luci-app-streamlit-forge`).
- Merging would force every `streamforge` operator to install
  `lxc`/`debootstrap` (or require a complicated Recommends-vs-Depends
  split). Net reduction = -1 package; cost = dependency bloat or
  packaging complexity for marginal user-facing benefit.
- **Decision: keep both packages separate.**

**`secubox-magicmirror` cluster: 2 → 1  (-1)**
- Members: `secubox-magicmirror`, `secubox-mmpm`
- `mmpm` is the MagicMirror package manager — pure tooling around the
  same daemon.

**~~`secubox-dpi` cluster: 4 → 2 (-2)~~ REVISED 2026-05-27: naming-fix only, no merge**
- Members: `secubox-dpi`, `secubox-netifyd`, `secubox-ndpid`,
  `secubox-mediaflow`
- On closer inspection the four packages have **distinct** operator
  roles, not duplicated ones:
  - `secubox-netifyd` is the netifyd daemon lifecycle dashboard
    (start/stop/config/alerts/restart/interfaces).
  - `secubox-dpi` is the analytics layer on top of netifyd (top apps,
    top protocols, bandwidth-by-app/device, talkers, risks, tc mirred
    setup). Same daemon, different operator workflow.
  - `secubox-ndpid` is the dashboard for the nDPId engine — different
    backend daemon, JA3/JA4 TLS fingerprinting.
  - `secubox-mediaflow` is a downstream consumer of DPI for
    streaming/VoIP classification.
- The audit's original "dual-stream netifyd/nDPId" framing for
  `secubox-dpi` was aspirational — the code is netifyd-only, and
  nDPId-engine analysis is already owned by `secubox-ndpid`.
- Real bug surfaced: `secubox-dpi`'s Description headline ("netifyd
  Dashboard") collided with `secubox-netifyd`'s. Fixed in #382 by
  rewriting the Description + Recommends to make the layered model
  explicit. No package merges.
- **Decision: keep all four packages. Net reduction = 0.**

### Tier 3 — Plan-stub clusters confirmed by data

**`secubox-dns` cluster: 5 → 1  (-4)**
- Members: `secubox-dns`, `secubox-dns-guard`, `secubox-dns-provider`,
  `secubox-vortex-dns`, `secubox-ad-guard`
- All five depend only on `secubox-core`. All overlap on
  `/etc/resolv.conf` and/or unbound. `vortex-dns` is the
  CyberMind-branded variant. `ad-guard` is a DNS-sinkhole — same
  resolver-layer concern.
- Proposal: one `secubox-dns` source package with sub-features toggled
  via `debconf` or feature flags in `/etc/secubox/dns.toml`.
- Risk: medium (operators may pin specific variants — needs
  `Provides:`/`Replaces:` per old name).

**`secubox-threats` cluster: 7 → 1  (-6)**
- Members: `secubox-threats`, `secubox-threat-analyst`,
  `secubox-cve-triage`, `secubox-network-anomaly`,
  `secubox-cyberfeed`, `secubox-ipblock`, `secubox-openclaw`
- All depend only on `secubox-core`. Each ships exactly one service +
  optional nginx route. The 7 services subscribe to the same
  CrowdSec/Suricata event bus.
- Proposal: one source `secubox-threats` building 7 binary packages
  with a shared `secubox-threats-common` dependency, OR one binary
  with feature toggles.
- Risk: medium-high (largest surface change; 7 services to coordinate).

**`secubox-mesh` cluster: 6 → 2  (-4)**
- Members: `secubox-mesh`, `secubox-meshname`, `secubox-master-link`,
  `secubox-mirror`, `secubox-p2p`, `secubox-daemon`
- `secubox-p2p` already serves `/master-link/` — overlap with
  `secubox-master-link`.
- `secubox-daemon` is the Go-built mesh daemon; should stay separate
  from the Python dashboard layer.
- Proposal: `secubox-daemon` (Go binary, unchanged) +
  `secubox-mesh` (dashboard: absorbs meshname, master-link, mirror,
  p2p dashboards).

### Tier 4 — Architecturally borderline (defer until Tier 1-3 lands)

| Cluster | Current → Proposed | Net |
|---|---|---|
| `secubox-soc` (soc + soc-agent + soc-gateway + soc-web) | 4 → 2 (backend + React web) | -2 |
| `secubox-system` (system + system-hub + admin + hub) | 4 → 2 (hub frontend + system backend) | -2 |
| `secubox-waf` (waf + mitmproxy + haproxy + interceptor) | 4 → 2 (waf incl. mitmproxy + haproxy separate) | -2 |
| `secubox-traffic` (traffic + qos + nettweak) | 3 → 1 | -2 |
| `secubox-monitoring` (netdata + glances + metrics + health-doctor + watchdog + device-intel) | 6 → 2-3 | -3 to -4 |
| `secubox-identity` (identity + users + avatar + auth + portal + authelia) | 6 → 3 | -3 |
| `secubox-publishing` (droplet + cloner + publish + backup + reporter) | 5 → 3 | -2 |
| `secubox-ai` (ai-gateway + ai-insights + localai + ollama + mcp-server) | 5 → 3 (ollama → localai) | -2 |
| `secubox-meta-services` (metablogizer + metabolizer + metacatalog + metoblizer) | 4 → 4 (KEEP — see below) | 0 |

**Note on `meta*` cluster** — the plan-stub flagged this as
"typo proliferation". The audit disagrees: each of the four ships a
distinct service with a distinct nginx route. Names are confusing but
they're real separate features (static-site publisher, log processor,
service catalog, log aggregator). Recommend: **keep separate, but
rename one or more for clarity**:
- `metoblizer` → maybe `log-aggregator` (the description literally says "centralized log aggregator")
- `metabolizer` → maybe `log-processor`
- `metablogizer` is the real name (static site publisher)
- `metacatalog` is fine

## Realistic total reduction

| Tier | Net reduction | Cumulative |
|---|---|---|
| Tier 0 (cleanup broken pkgs) | -1 to -2 | 139-140 |
| Tier 1 (mail) | -3 | 136-137 |
| Tier 2 (magicmirror only — streamlit + dpi dropped 2026-05-27) | -1 | 135-136 |
| Tier 3 (dns, threats, mesh) | -14 | 118-119 |
| Tier 4 (if all approved) | -18 | ~100-101 |

So the realistic floor is **~100 packages**, a 28% reduction. The
plan-stub's framing of "100+ packages" → consolidation is correct in
the destination but understates the start (141, not 100+).

## Don't-merge confirmation

The plan-stub's don't-merge list is correct as-is. Audit data
specifically confirms:

- **LXC service backers** (`gitea`, `nextcloud`, `matrix`, `jitsi`,
  `jellyfin`, `peertube`, `gotosocial`, `simplex`, `jabber`,
  `photoprism`, `nextcloud`, `newsbin`, `voip`, `turn`, `domoticz`,
  `homeassistant`, `rustdesk`, `yacy`, `lyrion`, `authelia`,
  `redroid`, `webradio`, `torrent`, `hexo`) — 24 distinct LXC apps,
  each backs a different container. Operators install per-container.

- **Hardware-gated** (`sentinelle-gsm`, `rbs-sensor`, `modem`,
  `zigbee`, `picobrew`) — install gated on physical SDR/modem/USB.

- **Security primitives** (`zkp`, `vault`, `hardening`,
  `secubox-cipher` — last is in plan-stub but doesn't exist yet in
  packages/) — isolation matters for ANSSI CSPN scope.

- **UI modes** (`console`, `eye-remote`, `c3box`) —
  `kiosk` from plan-stub doesn't exist as a package.

## Phase 2 readiness checklist

Before starting any merge work:

- [ ] Operator approves Tier 0 cleanup (smart-strip + c3box/daemon
      collision + eye-square).
- [ ] Operator approves Tier 1 (mail transition completion).
- [ ] `staging.secubox.in` repo + at least one canary box exist for
      apt full-upgrade rehearsal (called out as a risk in plan-stub).
- [ ] Build-scripts refactor [[2026-05-26-build-scripts-refactor]] has
      landed (plan-stub pre-req).
- [ ] CI matrix updated to build both the old single-packages and the
      new merged packages in parallel during transition, per the
      "v2.12.x builds" caveat in plan-stub.

Phase 2 itself = per-cluster one-pager → sign-off → implement →
canary apt full-upgrade test. Recommend Tier 0 + Tier 1 + one Tier 2
cluster (streamlit, smallest blast radius) as the recipe-finding pass.
