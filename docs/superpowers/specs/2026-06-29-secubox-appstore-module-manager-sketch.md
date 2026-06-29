# SecuBox App Store / Module Manager — Architecture Sketch

**Date:** 2026-06-29 · **Status:** brainstorm sketch (pre-spec) · **Author intent:** "appstore categorized + live prefs/components care; lyrion/peertube/nextcloud/webmail/kbin are modules of this toolbox system; implement shortly."

---

## 1. Core idea

A single web UI to **discover → install → enable/disable → configure → monitor** every SecuBox module, like an app store but fused with a live "components care" panel (prefs + health + restart/repair). It is a *front-end + lifecycle layer over manifests that already exist* — not a new packaging system.

**Foundation already present (don't reinvent):**
- **128 modules** each ship `debian/secubox.yaml` = `{name, category, tier, description, depends, api:{socket,health}, ui:{path}}` — this IS the catalog entry.
- Categories in use: `media, email, ai, iot, communication, publishing, network, security, system, vpn, dashboard, misc`. Tiers: `lite | standard | pro | all`.
- Module anatomy: `api/main.py` (FastAPI control-plane), `nginx/*.conf`, `sbin/<mod>ctl` (29), `lib/<mod>/install-lxc.sh` (9 LXC-backed: lyrion, peertube, photoprism, jellyfin-ish, grafana, mqtt, yacy, rustdesk, zigbee), `conf/<mod>.toml.example`, `menu.d/NNN-<mod>.json` (129), `www/<mod>/` (150).
- The **aggregator** mounts each module API at `/api/v1/<name>/`; the **hub** is the central dashboard; **menu.d** drives the menu.
- apt repo `apt.secubox.in` is the package source; `dpkg` is installed-state truth.

## 2. State model (per module)

`available` (in apt, not installed) → `installed` → `enabled` (service on + menu/nginx wired) → `running` (healthy). Plus `update-available`, `error`, and `tier-locked` (board tier < module tier). Health = {service active?, LXC state (for LXC apps), socket up?, last /health, mem/disk}.

## 3. Backend — `secubox-appstore` module (FastAPI, on the aggregator, runs as `secubox`)

Read/aggregate endpoints (safe, no privilege):
- `GET /catalog?category=&tier=&q=` — merged list: apt-available ∪ dpkg-installed, each with manifest + state + version + update flag.
- `GET /module/{name}` — manifest + live state + health + prefs schema + screenshots.
- `GET /module/{name}/health` — proxy module `/health` + LXC/service/socket/resources.
- `GET /jobs/{id}` — async job status (install/uninstall progress).

Mutating endpoints (delegate to a root helper — see §4):
- `POST /module/{name}/install` · `/uninstall`
- `POST /module/{name}/enable` · `/disable`
- `POST /module/{name}/restart`
- `GET/PUT /module/{name}/prefs` — read/write the module TOML (schema-validated; sensitive configs go through the CSPN double-buffer/4R: shadow → validate → atomic swap → rollback).
- `POST /module/{name}/expose` — toggle public exposure (HAProxy ACL + mitmproxy route, **never waf_bypass**) — later phase.

## 4. Privilege & async model (the hard part)

The FastAPI runs as `secubox` and **cannot** apt-install, run `install-lxc.sh`, `lxc-*`, `systemctl`, or edit `/etc/nginx`. Mirror the proven `sbx-mesh-up`/`<mod>ctl` pattern:
- A **root helper `secubox-appstorectl`** does the privileged verbs (`install <name>` = apt-get install + run the module's `install-lxc.sh` if LXC-backed; `enable/disable` = systemctl + menu.d toggle + nginx reload; `uninstall` = apt purge [+ optional LXC destroy]).
- FastAPI invokes it via a **narrow sudoers rule** (only `secubox-appstorectl <verb> <name>`), or hands jobs to a **privileged oneshot/queue** (a root `secubox-appstore-worker` consuming a job dir).
- Installs take **minutes** (apt + debootstrap LXC) → **async job model**: enqueue → return job id → UI polls `/jobs/{id}` with a progress stream (stage: download → install → provision-lxc → enable → health-check).
- Every action → append-only **audit log** (`/var/log/secubox/audit.log`), CSPN requirement.

## 5. Manifest schema extension (`secubox.yaml` v2 — additive, back-compatible)

Add optional appstore fields, defaulted so the 128 existing manifests still parse:
```yaml
appstore:
  icon: "lyrion.svg"            # or emoji/glyph
  summary: "Squeezebox / LMS music server"
  long_description: |            # markdown
  screenshots: ["1.png","2.png"]
  lxc: true                      # LXC-backed (drives install-lxc.sh step)
  exposure: optional             # none | optional | required (HAProxy/mitmproxy)
  default_ports: [9000, 3483]
  resources: { ram_mb: 512, disk_mb: 2048 }
  conflicts: []                  # mutually-exclusive modules
  homepage: "https://lyrion.org"
```

## 6. Web UI — components

- **CatalogGrid** + **AppCard** (icon, name, summary, category/tier badge, state pill, primary action toggle).
- **CategoryFilter** (chips from `category`), **TierFilter**, **SearchBox** (name/desc), **State filter** (installed/enabled/available/updates).
- **AppDetailDrawer**: description + screenshots; **ActionBar** (Install/Enable/Disable/Restart/Uninstall, tier-locked → upsell); **PrefsForm** (schema-driven from `conf/*.toml.example`); **HealthPanel** (service/LXC/socket/resources, live); **LogViewer** (journalctl tail); **JobProgress** (install spinner with stages).
- **Live Care view**: cross-module health board (what's down / degraded), bulk restart/repair, update-all.
- Style: SecuBox C3BOX palette (cosmos-black/gold-hermetic/cyber-cyan, Cinzel/JetBrains Mono).

## 6b. Granular control + Profile system (requested 2026-06-29)

The store doesn't just install/remove whole modules — it **composes the appliance** at four granularity levels, and **Profiles** bundle a whole composition you can switch atomically.

**Granularity levels (each independently toggleable):**
- **L0 — Module:** install / enable / disable the whole `secubox-<name>` (service + LXC).
- **L1 — Component:** sub-features *within* a running module (e.g. lyrion: streaming on / plugins off; nextcloud: files on / calendar off; a security module: detection on / active-response off). Driven by a `components:` list the module declares in its manifest, mapped to the module's own config flags / sub-services.
- **L2 — Navbar / menu:** show/hide and reorder individual `menu.d` entries — UI surface independent of whether the module runs (hide an app from the menu without disabling it, or vice-versa).
- **L3 — Appearance:** theme / palette / layout / branding (the C3BOX themes), per-board or per-profile.

**Profiles** = a named, versioned bundle of `{enabled modules, per-module component flags, navbar layout+order, appearance/theme, exposure settings}`.
- **Built-in presets:** *Minimal*, *Media Center* (lyrion/peertube/jellyfin/photoprism + lean navbar), *Security Ops* (waf/crowdsec/dpi/soc forward), *Home/Family* (nextcloud/mail/homeassistant), *Headless/Kiosk*. Presets can align with the board **tier**.
- **Custom profiles:** create / clone / edit / export / import.
- **Switch = one atomic transaction** via the CSPN double-buffer/4R (shadow → validate → swap → rollback) — flipping a profile reconfigures modules+navbar+appearance together, with one-click rollback if it breaks.
- **Scope:** a per-board *active profile* (the appliance's persona) and optionally **per-user** profiles (master users `gk2`/`admin` see different navbars/apps) — ties into identity.
- **Storage:** `/etc/secubox/profiles/<name>.toml` + an `active` pointer + 4R snapshots; API: `GET /profiles`, `GET/PUT /profiles/{name}`, `POST /profiles/{name}/apply` (atomic), `POST /profiles/{name}/rollback`, `GET /profiles/active`.

## 6c. P2P distribution + multi-service agents (requested 2026-06-29)

The app store rides the **gondwana mesh** — both its *package source* and its *running services* are federated across nodes, so the fleet is redundant and clients are served from the nearest node.

**P2P-mirrored apt repo + federated catalog:**
- `apt.secubox.in` (today only on gk2) becomes **P2P-mirrored**: each mesh node holds a signed mirror, synced over the wg-mesh (`10.10.0.0/24`) with rsync/content-addressed deltas. A node/client installs from the **nearest reachable mirror** (local → mesh peer → upstream gk2/public), so installs are fast and **survive gk2 being offline** (access redundancy). Mirrors stay trustworthy via GPG (verify `InRelease`); never trust an unsigned peer mirror.
- The **catalog is federated**: each node advertises which package versions it holds and which services it runs; the store shows a **mesh-wide view** ("install here" vs "already running on c3box"). This is exactly the gondwana **distributed directory** (peers/services/name records) — the app store is its first big consumer.

**Multi-service agents (serve all network clients):**
- Each node runs its module services as **agents** that serve its LAN clients; the mesh makes any service reachable from any node (hub-routed today, direct later), so a client on c3box's LAN can use a service hosted on gk2 and vice-versa — **service mirroring + redundancy of access** (gondwana Phase 4).
- A thin **agent/orchestration layer** gossips health + "who-runs-what", does **failover** (a dead service → route clients to a mesh replica), and advises **placement** (install a module on the best-suited node). Clients reach services by the per-node name `<service>.<boxname>.secubox.in`, routed over the mesh.
- This makes the app store the *control plane* and the mesh agents the *data plane* of one distributed appliance, not 3 separate boxes.

## 7. Implementation plan (incremental, each shippable)

- **A — Catalog (read-only, safe):** manifest aggregator (parse 128 `secubox.yaml` + dpkg + apt state) → `GET /catalog` + `/module/{name}`. UI: CatalogGrid + filters + AppDetailDrawer (read-only). No privilege. *Delivers the store view immediately.*
- **B — Health & prefs (read + careful write):** `/health` aggregation + `/prefs` GET; PUT prefs via the CSPN double-buffer path. UI: HealthPanel + PrefsForm + Live Care board.
- **C — Lifecycle (privileged):** `secubox-appstorectl` root helper + sudoers + async job model; enable/disable first (low risk), then install/uninstall (LXC). UI: ActionBar + JobProgress + audit.
- **D — Exposure & mesh (later):** per-app public exposure toggle (HAProxy+mitmproxy, no waf_bypass); gondwana mesh mirroring/redundancy (install once, run-anywhere) tying into the Phase-2/4 mesh work.
- **E — Manifest v2 rollout:** add `appstore:` block to the headline apps first (lyrion, peertube, nextcloud, webmail/mail, kbin/gotosocial, jellyfin, photoprism), generators backfill the rest.

## 8. Open questions (to resolve in the spec / by GPT)

1. New `secubox-appstore` package vs. extend `secubox-hub`?
2. Privilege bridge: narrow sudoers vs. a root job-queue worker? (CSPN favors the auditable queue.)
3. Job/progress transport: poll `/jobs/{id}` vs. SSE/WebSocket.
4. Prefs schema source: parse `*.toml.example` comments vs. a declared JSON-schema per module.
5. Tier enforcement: hard block vs. show-and-upsell.
6. Uninstall semantics for LXC apps: keep data volume vs. purge.

---

## 9. GPT architecture-design prompt (copy-paste)

> You are a senior systems architect. Design the **"SecuBox App Store / Module Manager"** for an existing Debian-based security-appliance platform. Output a concrete architecture: data model, REST API surface, UI component tree, the manifest schema, and the install/enable/prefs/health/async-job flows — with a privilege/security model. Be specific and implementable; prefer extending what exists over inventing new systems.
>
> **Platform context (ground truth — design WITH this, not around it):**
> - SecuBox-DEB: Debian bookworm appliance. ~128 "modules", each a Debian package `secubox-<name>` from a signed apt repo (`apt.secubox.in`). `dpkg` = installed-state truth.
> - Every module already ships a manifest `debian/secubox.yaml`: `{name, category, tier, description, depends, api:{socket,health}, ui:{path}}`. Categories: media, email, ai, iot, communication, publishing, network, security, system, vpn, dashboard, misc. Tiers: lite|standard|pro|all (the board has a tier; modules above it are locked).
> - Module anatomy: a FastAPI control-plane `api/main.py` (mounted by a central **aggregator** at `/api/v1/<name>/`, served over a unix socket, running as unprivileged user `secubox`), an nginx vhost fragment, an optional `sbin/<name>ctl` CLI, an optional `lib/<name>/install-lxc.sh` that provisions the app inside an **LXC container** (9 apps today: lyrion, peertube, photoprism, jellyfin, grafana, mqtt, yacy, rustdesk, zigbee), a `conf/<name>.toml.example`, a hub menu entry `menu.d/NNN-<name>.json`, and a static dashboard `www/<name>/`. A central **hub** dashboard aggregates everything.
> - Hard constraints: the API process is unprivileged (`secubox` user, NoNewPrivileges) — it CANNOT apt-install, run lxc/systemctl, or edit /etc/nginx; privileged actions must go through a separate root path. Security model is CSPN/ANSSI-oriented: append-only audit log, double-buffer/4R for sensitive config writes (shadow→validate→atomic-swap→rollback), AppArmor, no `waf_bypass` (all public exposure routes through an HAProxy→mitmproxy WAF chain). Installs take minutes (apt + LXC debootstrap) so lifecycle ops must be asynchronous with progress.
>
> **Design deliverables:**
> 1. **Catalog/data model:** how to merge apt-available ∪ dpkg-installed into a categorized, tiered, searchable catalog; the per-module state machine (available→installed→enabled→running, plus update-available/error/tier-locked) and health model (service/LXC/socket/resources).
> 2. **Manifest schema v2:** an additive `appstore:` block (icon, summary, long_description, screenshots, lxc:bool, exposure: none|optional|required, default_ports, resources, conflicts, homepage) that keeps the 128 existing manifests valid.
> 3. **REST API:** read endpoints (`/catalog`, `/module/{name}`, `/health`, `/jobs/{id}`) and mutating endpoints (install, uninstall, enable, disable, restart, prefs GET/PUT, expose) — request/response shapes.
> 4. **Privilege bridge + async jobs:** compare (a) a narrow sudoers rule to a root `secubox-appstorectl <verb> <name>` vs (b) a root job-queue worker consuming a spool dir; pick one for CSPN auditability; define the job/progress model and the install pipeline stages (download→install→provision-lxc→enable→health-check).
> 5. **Web UI component tree:** CatalogGrid/AppCard, Category/Tier/Search/State filters, AppDetailDrawer (description, screenshots, ActionBar, schema-driven PrefsForm, HealthPanel, LogViewer, JobProgress), and a cross-module "Live Care" health board with bulk restart/repair/update-all.
> 6. **Prefs editing:** how to render a schema-driven form from `conf/<name>.toml.example` (or a declared JSON-schema), validate, and write via the double-buffer/4R path.
> 7. **Decisions:** new `secubox-appstore` package vs extend the hub; poll vs SSE for job progress; tier hard-block vs upsell; LXC uninstall data-retention.
>
> Produce: an architecture diagram (ASCII), the manifest v2 schema, the full API table, the privilege/async design, the UI component tree, and a 4–5 step incremental build plan where each step ships something usable. Headline apps to use as worked examples: lyrion (LXC music), peertube (LXC video), nextcloud (cloud), webmail/mail, kbin/gotosocial (fediverse).

---

## 10. GPT prompt — COMPLETE (architectural research notes) · copy-paste

> **Role.** You are a distributed-systems architect. Write **architectural research notes / a design sketch** (not production code) for the **"SecuBox App Store + Module Composer"** — a web UI and control plane to discover, install, enable/disable (at multiple granularities), configure, profile, monitor, and **federate over a P2P mesh** every module of a Debian security appliance. Prefer extending what already exists over inventing new systems. Be concrete, opinionated, and implementable; call out trade-offs and pick.
>
> **Platform ground truth (design WITH this):**
> - SecuBox-DEB: Debian bookworm appliance. ~128 "modules"; each is a Debian package `secubox-<name>` from a signed apt repo (`apt.secubox.in`); `dpkg` = installed truth.
> - Each module already ships a manifest `debian/secubox.yaml` = `{name, category, tier, description, depends, api:{socket,health}, ui:{path}}`. Categories: media, email, ai, iot, communication, publishing, network, security, system, vpn, dashboard, misc. Tiers: lite|standard|pro|all (the board has a tier; higher-tier modules are locked).
> - Module anatomy: a FastAPI control-plane `api/main.py` (mounted by a central **aggregator** at `/api/v1/<name>/` over a unix socket, running as **unprivileged user `secubox`, NoNewPrivileges**), an nginx vhost fragment, an optional `sbin/<name>ctl` CLI, an optional `lib/<name>/install-lxc.sh` that provisions the app in an **LXC** (9 LXC apps today: lyrion, peertube, photoprism, jellyfin, grafana, mqtt, yacy, rustdesk, zigbee), a `conf/<name>.toml.example`, a hub menu entry `menu.d/NNN-<name>.json`, and a static dashboard `www/<name>/`. A central **hub** aggregates everything.
> - **Hard constraints:** the API process is unprivileged — it CANNOT apt-install, run lxc/systemctl, or edit /etc/nginx; privileged actions go through a separate root path. CSPN/ANSSI security: append-only audit log; **double-buffer/4R** for sensitive config writes (shadow→validate→atomic-swap→rollback); AppArmor; **no `waf_bypass`** (all public exposure routes through an HAProxy→mitmproxy WAF chain). Installs take minutes (apt + LXC debootstrap) → lifecycle ops must be **asynchronous with progress**.
> - **Mesh ("gondwana"):** the appliance is one of several nodes (today: gk2=master/`10.10.0.1`, c3box=`.2`, amd64=`.3`) on a WireGuard mesh `10.10.0.0/24:51822` owned by module `secubox-p2p`. The mesh has node identity (wg pubkey + node-id + DDNS name `<boxname>.secubox.in`) and a planned **distributed directory** (replicated peers/services/name records, DNS-like) plus per-node service naming `<service>.<boxname>.secubox.in` routed via the hub.
>
> **Design the following (produce research notes for each):**
> 1. **Catalog & state.** Merge apt-available ∪ dpkg-installed into a categorized, tiered, searchable catalog. Per-module state machine: available→installed→enabled→running, plus update-available/error/tier-locked. Health model: service active / LXC state / socket up / last `/health` / mem-disk.
> 2. **Manifest schema v2 (additive, keeps 128 manifests valid):** an `appstore:` block (icon, summary, long_description, screenshots, `lxc:bool`, `exposure: none|optional|required`, default_ports, resources, conflicts, homepage) **and a `components:` list** declaring toggleable sub-features (mapped to the module's own config flags / sub-services).
> 3. **Granular control — four levels, each independently toggleable:** L0 module (install/enable/disable whole package+LXC); L1 component (sub-features within a running module); L2 navbar/menu (show/hide/reorder `menu.d` entries, independent of whether the module runs); L3 appearance (theme/palette/layout/branding). Define the data model + API for each.
> 4. **Profiles.** A named, versioned bundle of `{enabled modules, per-module component flags, navbar layout+order, appearance, exposure}`. Built-in presets (Minimal, Media Center, Security Ops, Home/Family, Headless/Kiosk) that can align to tier; custom create/clone/edit/export/import. **Apply = one atomic transaction via double-buffer/4R** with one-click rollback. Scope: a per-board active profile AND optional per-user profiles (master users see different navbars/apps — ties to identity). Storage + API (`/profiles`, `apply`, `rollback`, `active`).
> 5. **Lifecycle API + privilege bridge + async jobs.** REST read endpoints (`/catalog`, `/module/{name}`, `/health`, `/jobs/{id}`) and mutating ones (install, uninstall, enable, disable, restart, prefs GET/PUT, expose). The unprivileged API must reach root work: compare (a) a narrow sudoers rule to a root `secubox-appstorectl <verb> <name>` vs (b) a root **job-queue worker** consuming a spool dir; pick one for CSPN auditability. Define the job/progress model and install pipeline stages (download→install→provision-lxc→enable→health-check).
> 6. **Prefs editing.** Render a schema-driven form from `conf/<name>.toml.example` (or a declared JSON-schema); validate; write via the 4R double-buffer path.
> 7. **P2P distribution (rides the mesh).** Make `apt.secubox.in` **P2P-mirrored**: each node holds a GPG-signed mirror synced over the wg-mesh (rsync/content-addressed deltas); install source preference local→mesh-peer→upstream; **survives the master being offline**; never trust an unsigned peer mirror (verify `InRelease`). Make the **catalog federated**: each node advertises held package versions + running services (this is the distributed directory's first consumer); the UI shows a mesh-wide view ("install here" vs "running on c3box").
> 8. **Multi-service agents (serve all network clients).** Each node runs its modules as agents serving its LAN clients; the mesh makes any service reachable from any node so clients are served from the nearest node (service mirroring + access redundancy). Design a thin agent/orchestration layer: health/who-runs-what gossip, failover (dead service → route to a mesh replica), placement advice (install on the best-suited node), client access via `<service>.<boxname>.secubox.in`. App store = control plane; mesh agents = data plane of one distributed appliance.
> 9. **Web UI component tree.** CatalogGrid/AppCard; Category/Tier/Search/State filters; AppDetailDrawer (description, screenshots, ActionBar, schema-driven PrefsForm, component toggles, HealthPanel, LogViewer, JobProgress); a Profiles manager; a cross-module **Live Care** board (what's down/degraded, bulk restart/repair/update-all, mesh-wide). Palette: C3BOX (cosmos-black/gold-hermetic/cyber-cyan; Cinzel + JetBrains Mono).
> 10. **Key decisions to resolve:** new `secubox-appstore` package vs extend the hub; job progress transport (poll vs SSE/WebSocket); tier hard-block vs upsell; LXC uninstall data-retention; mesh-sync protocol for the repo and the directory.
>
> **Output format (research notes):** an ASCII architecture diagram (UI ↔ appstore API ↔ root worker ↔ apt/lxc/systemd, plus the mesh: mirror sync + federated catalog + agents); the manifest v2 + `components:` schema; the full REST API table; the profile/4R model; the P2P mirror + federated-catalog + agent protocol; the privilege/async-job design; the UI component tree; and a phased, each-step-shippable build plan. Use these as worked examples throughout: **lyrion** (LXC music), **peertube** (LXC video), **nextcloud** (cloud), **webmail/mail**, **kbin/gotosocial** (fediverse).
