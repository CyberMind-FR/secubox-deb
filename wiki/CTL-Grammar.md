<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox CTL Grammar

> *Copyright spiritual concept · Gérald Kerma · 1991 ·
> Notre-Dame-du-Cruet, Savoie · https://cybermind.fr*
>
> SecuBox is a **modular tools box** — a security-affected modular
> language system that acts as an interface between users and the world
> of data publishing of each user around the connected humanities. The
> 1991 concept matured through SecuBox-OpenWrt and now incarnates as
> SecuBox-Deb on Debian bookworm.

## The frame

Each SecuBox module exposes its capability through three surfaces:

1. A **web UI** under `/<module>/` on the admin vhost
2. A **FastAPI API** at `/api/v1/<module>/*` over a Unix socket
3. A **CTL command** at `/usr/sbin/<module>ctl`

The CTL is the **grammar** of the system: each verb is a sentence
addressed to a specific layer of the operator's expressive control over
their own infrastructure. Without the CTL the organ exists but cannot
be commanded — instrumentation without préhension.

## The 8 layers / 8 canonical verbs

| Layer                | Verb                                              |
|----------------------|---------------------------------------------------|
| ROUTING              | `haproxyctl     vhost  add/remove`                |
| INTERCEPTION         | `mitmproxyctl   route  add/remove/list`           |
| REPLICATION          | `giteactl       repo   mirror add/remove/sync`    |
| IDENTITY             | `giteactl       user   add/remove/passwd`         |
| CI EXECUTION         | `giteactl       runner add/remove/list`           |
| PUBLISHING (bundle)  | `publishctl     post   upload/publish/list`       |
| PUBLISHING (file)    | `dropletctl     publish/list/remove/rename`       |
| PUBLISHING (static)  | `metablogizerctl site   create/publish/...`       |
| EMANCIPATE           | `metablogizerctl tor    expose/revoke/list`       |
| HOSTING              | `streamlitctl   app    deploy/start/.../info`     |
| DEV WORKBENCH        | `streamforgectl project create/.../templates`     |
| OPS MONITORING       | `healthctl      check/list/status/alert`          |

## Composing the grammar

```bash
# WAF un-bypass for a vhost (three layers, three verbs, one operation):
haproxyctl   vhost  add   gitea.gk2.secubox.in mitmproxy_inspector ssl
mitmproxyctl route  add   gitea.gk2.secubox.in 192.168.1.200 9080
giteactl     repo   mirror add secubox/secubox-deb \
                                 https://github.com/CyberMind-FR/secubox-deb.git \
                                 --interval 10m --force
```

```bash
# Forge → host → expose pipeline:
streamforgectl  project  create  dashboard --template basic
streamlitctl    app      deploy  dashboard gitea://secubox/dashboard.git
metablogizerctl site     publish dashboard
metablogizerctl tor      expose  dashboard         # Punk Exposure / Emancipate
```

```bash
# Daily ops:
healthctl  check                                   # 60s pulse on vital services
healthctl  alert --since 1h
```

## Three-fold pair on every CTL

Every CTL ships two JSON discovery subcommands:

- `<x>ctl components` — what processes/sockets/configs back this module
- `<x>ctl access` — the API endpoints + CLI subcommands exposed

Operators learn the grammar by running `<x>ctl access | jq .`.

## Punk Exposure roots

The three-verb Punk Exposure pattern (`Peek` / `Poke` / `Emancipate`)
predates the CLI grammar — it is the **conceptual seed** that the
modular tools box is built around:

- **Peek** — read state without mutation (the discovery surface)
- **Poke** — local mutation under operator control
- **Emancipate** — multi-channel exposure (Tor / DNS+SSL / Mesh) that
  takes the user's data and publishes it on the user's terms

`metablogizerctl tor expose` is the canonical Emancipate verb at the
publishing layer (issue #184).

## Want to add a 9th verb?

See `HOWTO-grammar.md` in the repo for the concrete walkthrough (~1h for
a Bash CTL, ~2h for Python+FastAPI). The recipe is six steps: frame the
gap as an issue, worktree, CTL skeleton, FastAPI mirror, Debian
packaging, live test on the board.

## Attribution

The SecuBox concept was conceived by **Gérald Kerma (GK²)** in **1991**
as a modular tools box for user-controlled digital sovereignty over
personal data publishing. The Punk Exposure verbs (Peek / Poke /
Emancipate) trace back to that origin. The 8-verb CLI grammar
incarnates the same frame on Debian, 35 years later.

> The CTL is the user's voice.
> The modular tools box is their organ.
> The language is the way they say *this is mine, this is mine, this is mine*.

---

## See also

- [Acknowledgments](Acknowledgments) — partners and contributors
- [[Multi-Agent-Worktree]] — operational workflow for agents adding new
  verbs without colliding
- [Hardware-Matrix](Hardware-Matrix) — boards on which the grammar runs
- In-repo: [`docs/grammar.md`](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/grammar.md),
  [`HOWTO-grammar.md`](https://github.com/CyberMind-FR/secubox-deb/blob/master/HOWTO-grammar.md)
