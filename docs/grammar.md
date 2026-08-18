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
> SecuBox is a **modular tools box** — a security-affected modular language
> system that acts as an interface between users and the world of data
> publishing of each user around the connected humanities. The 1991 concept
> matured through SecuBox-OpenWrt and incarnates here as SecuBox-Deb on
> Debian bookworm arm64/amd64. This document codifies the CLI grammar that
> makes the modular concept expressible from the shell.
>
> Sister documents:
>
> - [`MODULE-GUIDELINES.md`](MODULE-GUIDELINES.md) — package/LXC/WebUI/API scaffolding around a verb
> - [`../HOWTO-grammar.md`](../HOWTO-grammar.md) — recipe for adding a new verb
> - [`UI-GUIDE.md`](UI-GUIDE.md) — theme and sidebar conventions

---

## The frame

Each SecuBox module exposes its capability through three surfaces:

1. **A web UI** (under `/<module>/` on the admin vhost)
2. **A FastAPI API** (`/api/v1/<module>/*` over a Unix socket)
3. **A CTL command** (`/usr/sbin/<module>ctl`)

The CTL is the **grammar** of the system: each verb is a sentence in the
modular language, addressed to a specific layer of the operator's
expressive control over their own infrastructure.

Without the CTL the organ exists but cannot be commanded —
**instrumentation without préhension**. The CTL gives the operator
*préhension* (grasping power) over what the module already instruments.

---

## The 8 layers / 8 canonical verbs

| Layer                | Verb                                              | Forged in |
|----------------------|---------------------------------------------------|-----------|
| ROUTING              | `haproxyctl   vhost  add/remove`                  | pre-2026  |
| INTERCEPTION         | `mitmproxyctl route  add/remove/list`             | #173      |
| REPLICATION          | `giteactl     repo   mirror add/remove/sync/list` | #176      |
| IDENTITY             | `giteactl     user   add/remove/passwd/list`      | pre-2026  |
| CI EXECUTION         | `giteactl     runner add/remove/list/token`       | #190      |
| PUBLISHING (bundle)  | `publishctl   post   upload/publish/...`          | #180      |
| PUBLISHING (file)    | `dropletctl   publish/list/remove/rename`         | #181, #196 |
| PUBLISHING (static)  | `metablogizerctl site create/publish/...`         | pre-2026  |
| EMANCIPATE           | `metablogizerctl tor  expose/revoke/list/status`  | #184      |
| HOSTING              | `streamlitctl app    deploy/start/.../info/restart` | #182    |
| DEV WORKBENCH        | `streamforgectl project create/.../templates`     | #183      |
| OPS MONITORING       | `healthctl    check/list/status/alert`            | #212      |

Each verb closes a previously implicit operation. Composing them
expresses end-to-end workflows in three lines of shell:

```bash
# WAF un-bypass for a vhost (the cookie-audit cascade fix, today's grammar):
haproxyctl   vhost  add   gitea.gk2.secubox.in mitmproxy_inspector ssl
mitmproxyctl route  add   gitea.gk2.secubox.in 192.168.1.200 9080
giteactl     repo   mirror add secubox/secubox-deb \
                                 https://github.com/CyberMind-FR/secubox-deb.git \
                                 --interval 10m --force
```

```bash
# Forge → host → expose pipeline (apps + static):
streamforgectl  project  create   dashboard --template basic
streamlitctl    app      deploy   dashboard gitea://secubox/dashboard.git
metablogizerctl site     publish  dashboard
metablogizerctl tor      expose   dashboard           # Punk Exposure
```

```bash
# Daily ops dance:
healthctl  check                    # 60s pulse on vital services
healthctl  alert --since 1h         # what failed or recovered
```

---

## Pattern recipe — adding the 9th verb

A new `<module>ctl <noun> <verb>` follows the same six-step recipe every
time:

### 1. Open an issue framing the gap

State the **layer**, the **noun**, and the **operator workflow** that
currently has no expressible form. Quote any sibling-grammar tickets (e.g.
"parallel to #173 on the interception layer"). The issue is the design
document; subsequent PRs reference it.

### 2. Worktree per issue

```bash
scripts/agent-worktree.sh start --issue <N>
```

This enforces the multi-agent worktree workflow (`.claude/CLAUDE.md`):
the primary checkout stays on master, every non-trivial feature lives in
its own worktree, each commit references `(ref #N)` or `(closes #N)`.

### 3. CTL skeleton

Bash for shell-shaped tools (giteactl, metablogizerctl), Python with
`argparse` for tools with rich subcommands and JSON I/O (mitmproxyctl,
healthctl). Both styles co-exist; pick the one closest to the existing
ctls in the same package.

Three subsections in every CTL:

```text
Lifecycle (top-level)      install start stop restart status logs
Three-fold (JSON)          components access
<noun> <verb>(s)           the new grammar
```

The Three-fold pair (`components` and `access`) is the discovery contract
— operators run `<x>ctl access` to learn what the module exposes without
reading source. See `giteactl` and `healthctl` for the canonical shape.

### 4. FastAPI mirror

Every verb is a function. Every function gets a route under
`/api/v1/<module>/*`. The CTL becomes a thin wrapper over the API when
running on the box, and the same routes are consumed by the web UI from
the browser. CTL ↔ API parity is mechanical (one engine, two call sites).

See `packages/secubox-users/api/engine.py` ↔ `sbin/usersctl` for the
reference pattern.

### 5. systemd integration

If the verb daemonizes anything, ship the unit:

```text
debian/<service>.service       Type=simple, User=secubox, ExecStart=python3 -m uvicorn ...
debian/<service>-runner.timer  for periodic actions (health-doctor, geoipupdate)
```

The Debian `postinst` enables units; the `prerm` disables them. Both are
idempotent. Use `AmbientCapabilities=` rather than running as root — we
discovered (#194) that missing CAP_NET_ADMIN silently breaks aggregators
that need to read `nft` sets.

### 6. Live test on the prod board

The grammar is empirical — a verb is only forged when it survives a live
deploy on `gk2` (192.168.1.200). The PR body documents the verification:
the exact command, the observable side-effect, the API endpoint check.

---

## Naming conventions

- `<module>ctl` (single binary name, no separator). `metactl` was renamed
  `publishctl` in #180 to align.
- Verbs are imperative present tense: `add` / `remove` / `list` / `status`,
  not `creating` / `deletion` / `listed`.
- Nouns are singular: `route`, `repo`, `app`, `project`, `vhost`, `user`.
- Aliases are accepted but not advertised in `--help`: `rm`/`del` for
  `remove`, `ls` for `list`.
- Three-fold output is always JSON (machine-readable). Other commands
  human-friendly by default; `--json` flag opt-in.

---

## Layered architecture map

```text
┌─────────────────────────────────────────────────────────────────────┐
│  EMANCIPATE   metablogizerctl tor (#184)        Punk Exposure       │
├─────────────────────────────────────────────────────────────────────┤
│  PUBLISHING   metablogizerctl site, publishctl post (#180),         │
│               dropletctl publish (#181/#196)                        │
│  HOSTING      streamlitctl app (#182), streamforgectl project (#183)│
├─────────────────────────────────────────────────────────────────────┤
│  IDENTITY     giteactl user                                         │
│  REPLICATION  giteactl repo mirror (#176)                           │
│  CI EXECUTION giteactl runner (#190)                                │
├─────────────────────────────────────────────────────────────────────┤
│  INTERCEPTION mitmproxyctl route (#173)                             │
│  ROUTING      haproxyctl vhost                                      │
├─────────────────────────────────────────────────────────────────────┤
│  OPS MONITORING healthctl (#212)                                    │
│                 surveille les 9 couches ci-dessus                    │
└─────────────────────────────────────────────────────────────────────┘
```

The monitoring layer at the bottom is meta — `healthctl` watches the
state of the other nine and surfaces transitions via journal events.

---

## Philosophical roots

The SecuBox concept was conceived by **Gérald Kerma (GK²)** in **1991**
as a modular tools box for user-controlled digital sovereignty over
personal data publishing. The Punk Exposure verbs (`Peek`/`Poke`/
`Emancipate`) trace back to that origin: three modes of expression
through which the user occupies their own infrastructure rather than
delegate it. The 8-verb CLI grammar is the operational incarnation of
that frame on Debian, 35 years later.

The CTL is the user's voice. The modular tools box is their organ. The
language is the way they say *this is mine, this is mine, this is mine*.

---

## See also

- `HOWTO-grammar.md` — concrete walkthrough for adding a 9th verb
- `wiki/CTL-Grammar.md` — public-facing summary on the GitHub wiki
- `.claude/CLAUDE.md` — operational rules for agents (worktree workflow,
  per-package conventions, hard rules)
- Issues #173, #176, #180-#184, #190, #212 — the forging history
