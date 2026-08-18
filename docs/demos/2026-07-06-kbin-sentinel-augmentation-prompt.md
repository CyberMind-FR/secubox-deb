<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Demo Prompt — kbin ToolBoX × Sentinel Augmentation (#823)

## What changed
The SecuBox kbin (ToolBoX) gained an on-network **compromise-detection**
capability group ("Sentinelle"): the `sbx-sentinel` daemon inspects mirrored
tunnel traffic against commercial-spyware / exploit / botnet IOC packs (Pegasus,
Predator/Intellexa, plus live abuse.ch + MVT/Citizen-Lab feeds) and records
per-device verdicts. Findings now surface in three places:
- **Admin WebUI** — a fleet "🛡️ Sentinelle" tab (all recent detections +
  compromise evaluation).
- **kbin "mon rapport"** — a per-device Compromission tab.
- **PDF report** — a per-device Sentinelle section.

All findings are report-only and carry an anonymous `mac_hash` only. Heuristic
and zero-click signals are shown as "suspect", never as a confirmed compromise.

## GPT prompt (paste into a model)

> You are presenting SecuBox, a Debian-based home/SMB security gateway. It just
> shipped a new capability group called **Sentinelle**: while a device browses
> through the SecuBox tunnel, the box inspects the traffic against threat-intel
> indicators for commercial spyware (Pegasus, Predator/Intellexa), exploits, and
> botnets, and produces a per-device **compromise assessment** (clean / suspect /
> compromised) plus a detection list. It surfaces this to the admin as a fleet
> dashboard tab, to each user in their personal "mon rapport", and in a printable
> PDF — all keyed on an anonymous session hash, no personal data.
>
> Write a short, punchy narrative (max 250 words) for a security-savvy audience
> that (a) explains why on-network compromise detection at the gateway is a
> meaningful augmentation over endpoint-only tools, (b) walks through what a user
> sees when their phone contacts a known Pegasus C2, and (c) is honest that the
> system is detection/reporting, not blocking, and that heuristic signals are
> flagged as suspicion rather than proof. Avoid hype; be technically credible.
