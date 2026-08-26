<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# sbxwaf — the standalone WAF 🛡️

**[EN](WAF)** | [FR](WAF-FR) | **🟡 WALL** | sovereign application firewall

> Pattern matched, ban applied in the kernel. No third-party service sits in the
> decision path.

## What changed

Until August 2026 the blocking chain went through CrowdSec: local detection,
community reputation, then a bouncer translating the decision into a rule.
`sbxwaf` now decides and enforces on its own.

This is not a technical rejection. CrowdSec carried months of production and
community detection did real work. Three things tipped the balance:

- **a third party in the decision path** — if it stops, nothing bans any more,
  and that happened silently;
- **load cost** on a constrained ARM board — the reference box went from a load
  of 15–22 down to 5–7 once it was stopped;
- **reciprocity** of the shared intelligence, which no longer held over time.

## How it bans

```
request → sbxwaf → pattern → nft set (waf_ban / waf_ban6)
                              ↑
                       chain waf_drop, hook input, priority -100
                       ip saddr @waf_ban counter drop
```

The chain is the part that matters. A populated nft set that no rule references
blocks nothing — it is a list with no doorman. `sbxwaf` therefore creates the
chain and both rules at startup, preceded by a `flush chain`: `add rule` is not
idempotent, and without the flush every restart stacked a duplicate.

Measured on the reference box:

| Metric | Value |
|---|---|
| Banned addresses | 115 IPv4 + 2 IPv6 |
| Packets dropped by the kernel | 12,545 |
| Traffic turned away | 878 KB |
| Rule categories | 25 |
| Behavioural detections | 4 |

## Per-vhost anti-robots

48 named robots (search engines, AI harvesters, SEO tools) plus generic
patterns. Three paths are **always** served, even to a banned robot:
`/robots.txt`, `/favicon.ico` and `/.well-known/`. Blocking `robots.txt` would
stop the robot from ever learning it is unwelcome.

The Vhost panel checkbox is labelled **Anti-robots**: ticked means blocked.

## Beyond HTTP: sbx-authwatch

A WAF only sees the web. `sbx-authwatch` reads SSH, SMTP and IMAP — both the
systemd journal and plain files — and writes into **the same ban set and the
same threat log**. This is the correlation CrowdSec used to provide, rebuilt
locally.

- Patterns written from real production log lines, not from upstream docs.
- **Campaign** detection (keyed on the targeted account) and **non-existent
  account** detection — an attempt against a domain nobody uses is an attack,
  not a typo.
- **10 decoy ports**. A decoy records and stays quiet; it never imitates the
  protocol, because imitating means offering a surface.
- Declarative per-service filters in `/etc/secubox/authwatch/services.json` — a
  service without a verified pattern stays `"actif": false` with the reason
  written down, rather than shipping a guessed pattern.

## Watching it work

`https://waf.<box>/` — LAN only. Attackers, countries, names not resolved by any
existing vhost, behavioural detections, targeted accounts, decoys hit, and
per-category effectiveness. Charts are inline SVG, no external library.

## Notes

- The `crowdsec` package may stay installed; it is simply stopped and disabled
  at boot.
- `secubox-blacklist-sync` and `secubox-threatmesh-bridge` depend on it through
  `Requisite=`: without CrowdSec they do not start, instead of failing in a loop.
