<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Modules Consolidation Plan

> **Status:** STUB / TODO for later. Audit + decision phase first;
> no code touched until each merge is approved per package.

**Goal:** Reduce the 100+ `secubox-*` package count by merging
redundant siblings and grouping tightly-coupled ones, without
losing dpkg-level granularity for what operators legitimately want
to enable/disable independently.

## Audit phase

```bash
ls packages/secubox-* -d | wc -l            # current package count
# group by likely consolidation cluster
```

### Candidate clusters (initial sketch — needs grep/audit)

| Cluster | Current packages | Rationale |
|---|---|---|
| **secubox-dns** | secubox-dns, secubox-dns-guard, secubox-dns-provider, secubox-vortex-dns | All touch /etc/resolv.conf or unbound. Operator usually wants ONE DNS subsystem active, not four overlapping ones. |
| **secubox-threats** | secubox-threats, secubox-threat-analyst, secubox-cve-triage, secubox-network-anomaly | Distinct *features* but they all subscribe to the same CrowdSec/Suricata event bus. Bundle as `secubox-threats` with sub-modules. |
| **secubox-mesh** | secubox-mesh, secubox-meshname, secubox-master-link, secubox-mirror | All P2P/mesh-adjacent. master-link + mirror probably absorb into mesh. |
| **secubox-streamforge** | secubox-streamforge, secubox-streamlit, secubox-streamlit-idle | Same Streamlit runtime. Three packages for what should be ExecStart variants of one service. |
| **secubox-metablogizer/-bolizer/-acatalog** | secubox-metablogizer, secubox-metabolizer, secubox-metacatalog, secubox-metoblizer | Names alone suggest typo proliferation. Audit + pick one canonical. |
| **secubox-ai-*** | secubox-ai-gateway, secubox-ai-insights, secubox-ai-* (others) | Likely fine as separate but worth a pass. |
| **secubox-droplet** | secubox-droplet, secubox-cloner, secubox-publish | "Export-this-box" tooling. Probably one package. |

(List is illustrative — first task in plan is the actual audit.)

## Phases

1. **Inventory + dependency graph.** Generate
   `out/packages.dot` showing Depends/Recommends edges + ExecStart
   targets + nginx route owners. Visualise clusters that already
   talk to each other.
2. **Cluster approval round-trip.** For each proposed cluster: write
   a one-pager (what disappears, what fields move to debconf, what
   the new postinst does), get operator sign-off, then implement.
3. **Implementation order: bottom-up.** Merge the smallest /
   most-disposable clusters first (e.g. streamlit variants). Build
   confidence + recipe before touching big ones (DNS, threats).
4. **Per-merge regression gate:** apt full-upgrade on a snapshot of
   an installed box must succeed without operator intervention
   (Provides:/Replaces:/Conflicts: declared correctly so the new
   bundle takes over the old single packages).

## Don't-merge list (preserve operator choice)

* `secubox-kiosk`, `secubox-console`, `secubox-eye-remote` — UI
  modes are intentionally separate.
* `secubox-authelia`, `secubox-grafana`, `secubox-yacy`,
  `secubox-rustdesk`, `secubox-lyrion`, `secubox-mail`,
  `secubox-gitea`, etc. — each backs a distinct LXC container that
  operators decide to run or not.
* `secubox-sentinelle-gsm`, `secubox-fmrelay` — hardware-gated, op
  installs only with matching SDR + modem.
* `secubox-zkp`, `secubox-vault`, `secubox-cipher` — security
  primitives, isolation matters.

## Risks

* **dpkg upgrade choreography is painful.** A bad
  Replaces:/Conflicts: line bricks operators' apt state on next
  `apt full-upgrade`. Need staging.secubox.in repo + canary boxes.
* **Service unit renames break operator playbooks.** Some operators
  may have local `systemctl is-enabled secubox-streamlit-idle`
  monitors. Provide alias unit files for one release cycle.
* **CI build-packages.yml matrix grows in parallel with refactor**
  — keep all old package names buildable from the merged source
  until the consolidation actually ships, so partial work doesn't
  break v2.12.x builds.

## Estimate

* Audit + clusters: 1 week of careful reading.
* Per-cluster merge: 1-3 days depending on size.
* Total realistic: **1-2 months calendar** if interleaved with
  feature work.

## Pre-requisites

* Build-scripts refactor [[2026-05-26-build-scripts-refactor]]
  ideally landed first — smaller diff surface when touching
  packaging too.
