<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# HOWTO — forge a new CTL verb

> *Copyright spiritual concept · Gérald Kerma · 1991*
>
> This is the concrete walkthrough. See `docs/grammar.md` for the
> conceptual frame and the 8 canonical verbs already in place.

You want to add `xctl widget add/remove/list` (or any 9th verb). Follow
these steps in order. Time budget: ~1 hour for a Bash-style verb,
~2 hours for a Python+FastAPI one.

---

## 1. Frame the gap

Write the issue body following this template (adapt verbs/nouns):

```markdown
## Context

The X module already exposes <capability> via the web UI and FastAPI, but
operators have no CLI grammar for it. Closing the gap parallel to:

- `mitmproxyctl route add` (#173) — INTERCEPTION
- `giteactl repo mirror add` (#176) — REPLICATION

## Gap

Forge `xctl widget` with subcommands:

  xctl widget add NAME [--option ...]
  xctl widget remove NAME
  xctl widget list
  xctl widget status NAME

## Out of scope

(Anything you defer to a followup ticket.)
```

Submit, capture the issue number. Reference it as `#<N>` in everything
that follows.

---

## 2. Worktree

```bash
scripts/agent-worktree.sh start --issue <N>
cd ~/CyberMindStudio/secubox-deb-worktrees/<N>-<slug>
```

You're now on a branch named `feature/<N>-<slug>` (or `fix/...` if the
issue is labeled `bug`). Every commit message ends with `(ref #<N>)` or
`(closes #<N>)` on the final commit.

---

## 3. Pick the language

| When | Use |
|---|---|
| The verb is mostly shell-orchestration (lxc-attach, systemctl, file ops) | Bash |
| The verb needs rich subparsers, JSON I/O, or a registry pattern | Python |

Both styles exist in-tree. Reference implementations:

- **Bash** — `packages/secubox-gitea/sbin/giteactl`, `packages/secubox-metablogizer/sbin/metablogizerctl`
- **Python** — `packages/secubox-mitmproxy/bin/mitmproxyctl`, `packages/secubox-health-doctor/sbin/healthctl`

---

## 4. Skeleton

### Bash skeleton

```bash
#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# xctl — SecuBox X control (issue #<N>).

set -euo pipefail
VERSION="0.1.0"
CONFIG_FILE="/etc/secubox/x.toml"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()   { printf "${GREEN}[X]${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }

# Lifecycle
cmd_start()    { systemctl start   secubox-x.service && log started; }
cmd_stop()     { systemctl stop    secubox-x.service && log stopped; }
cmd_restart()  { systemctl restart secubox-x.service && log restarted; }
cmd_status()   { systemctl is-active secubox-x.service; }
cmd_logs()     { journalctl -u secubox-x.service -n "${1:-50}" --no-pager; }

# Three-fold (JSON discovery)
cmd_components() {
  cat <<EOF
{"service":"secubox-x.service","api_base":"/api/v1/x","ctl_version":"$VERSION"}
EOF
}
cmd_access() {
  cat <<EOF
{"api":{"list":"GET /widgets","add":"POST /widget","remove":"DELETE /widget/{name}"}}
EOF
}

# Widget noun
cmd_widget() {
  local act="${1:-}"; shift || true
  case "$act" in
    add)     widget_add "$@" ;;
    remove|rm|delete) widget_remove "$@" ;;
    list|ls) widget_list "$@" ;;
    status)  widget_status "$@" ;;
    *) echo "Usage: xctl widget {add|remove|list|status} [args]" ;;
  esac
}

widget_add()    { :; }   # implement: name validation, side effect, idempotent
widget_remove() { :; }
widget_list()   { :; }
widget_status() { :; }

case "${1:-}" in
  start|stop|restart|status) c="$1"; shift; cmd_$c "$@" ;;
  logs)       shift; cmd_logs "$@" ;;
  components) cmd_components ;;
  access)     cmd_access ;;
  widget)     shift; cmd_widget "$@" ;;
  *) echo "Usage: xctl <command>"; exit 1 ;;
esac
```

### Python skeleton

```python
#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""xctl — SecuBox X control (#<N>)."""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, "/usr/lib/secubox/x")
from api import engine  # canonical writer used by FastAPI too

def cmd_widget_add(args): engine.widget_add(args.name); return 0
def cmd_widget_remove(args): engine.widget_remove(args.name); return 0
def cmd_widget_list(args): print(json.dumps(engine.widget_list(), indent=2)); return 0

def build_parser():
    p = argparse.ArgumentParser(prog="xctl")
    sub = p.add_subparsers(dest="cmd", required=True)
    for n in ("start", "stop", "restart", "status", "components", "access", "logs"):
        sub.add_parser(n)
    w = sub.add_parser("widget"); ws = w.add_subparsers(dest="wc", required=True)
    add = ws.add_parser("add"); add.add_argument("name"); add.set_defaults(func=cmd_widget_add)
    rm  = ws.add_parser("remove"); rm.add_argument("name"); rm.set_defaults(func=cmd_widget_remove)
    ls  = ws.add_parser("list"); ls.set_defaults(func=cmd_widget_list)
    return p

def main():
    args = build_parser().parse_args()
    return args.func(args) if hasattr(args, "func") else 0

if __name__ == "__main__":
    sys.exit(main())
```

---

## 5. FastAPI mirror

Every verb has a route. Same engine, two callers (CTL and API).

```python
# packages/secubox-x/api/main.py
from fastapi import FastAPI
from . import engine

app = FastAPI(root_path="/api/v1/x")

@app.get("/widgets")
def widget_list(): return engine.widget_list()

@app.post("/widget")
def widget_add(name: str): return engine.widget_add(name)

@app.delete("/widget/{name}")
def widget_remove(name: str): return engine.widget_remove(name)
```

The CTL and the web UI both call into `engine.widget_*`. **Don't
duplicate business logic** between CTL and API — they're two surfaces
on the same engine.

---

## 6. Debian packaging

`packages/secubox-x/debian/`:

- `control` — Depends on `secubox-core`, `python3-uvicorn`, etc.
- `changelog` — bump version, include `Closes: #<N>`.
- `rules` — install the CTL to `/usr/sbin/xctl`, the API to
  `/usr/lib/secubox/x/`, the systemd unit to `/lib/systemd/system/`.
- `postinst` — `systemctl enable --now secubox-x.service` (idempotent).
- `prerm` — `systemctl disable --now secubox-x.service`.

systemd unit boilerplate:

```ini
[Unit]
Description=SecuBox X
After=network.target secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/x
ExecStart=/usr/bin/python3 -m uvicorn api.main:app \
    --uds /run/secubox/x.sock --log-level warning
Restart=on-failure
ReadWritePaths=/run/secubox /var/cache/secubox

[Install]
WantedBy=multi-user.target
```

If your CTL needs to read nft sets, add
`AmbientCapabilities=CAP_NET_ADMIN` (see #194 — without it,
`subprocess.run(["nft", ...])` silently returns empty).

---

## 7. Nginx route (so the API is reachable via admin.gk2)

Add `/etc/nginx/secubox-routes.d/x.conf`:

```nginx
location /api/v1/x/ {
    proxy_pass http://unix:/run/secubox/x.sock:/api/v1/x/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_read_timeout 60s;
}
```

This goes in `secubox-routes.d/`, **not** `secubox.d/` — the admin.gk2
server block includes the former (lesson learned from #163).

---

## 8. Live test on the board

The verb is only forged when it survives prod. From your worktree:

```bash
# Copy the CTL onto the board first
scp packages/secubox-x/sbin/xctl root@192.168.1.200:/usr/sbin/

ssh root@192.168.1.200 'xctl access | jq .'        # discovery
ssh root@192.168.1.200 'xctl widget add demo'      # the new verb
ssh root@192.168.1.200 'xctl widget list'          # observe side-effect
```

If anything is wrong, the operator's CLI tells them so. That's the
whole point of the grammar.

---

## 9. Commit + PR

Commit messages stay terse. Don't include AI attribution footers — the
project's global reference is enough. Example:

```text
feat(xctl): forge widget noun verbs (closes #<N>)

Ninth verb of the SecuBox grammar, layer = <layer>. Parallel to
mitmproxyctl route (#173), giteactl repo mirror (#176).

Subcommands:
  xctl widget add NAME [--option ...]
  xctl widget remove NAME
  xctl widget list
  xctl widget status NAME

Live-tested on gk2 board: <one-line observation>.
```

Push the branch, open the PR with a one-paragraph summary + a test plan
checklist. Don't add `🤖 Generated with Claude Code` style footers.

---

## 10. Update grammar.md

After merge, add a row to the canonical table in `docs/grammar.md` and
the wiki version. The grammar is a living document; new verbs extend it.

---

## Common pitfalls

- **Naming**: it's `<module>ctl`, not `<module>-ctl` or `<module>_ctl`.
  Renaming after the fact (e.g. `metactl` → `publishctl` in #180) is
  user-hostile; pick right from the start.
- **Nounlessness**: don't ship a flat verb set without a noun. `xctl
  upload` invites future verb collisions; `xctl widget upload` does not.
- **AmbientCapabilities** vs `NoNewPrivileges`: they coexist when caps
  are set in the unit (#194).
- **Filesystem fetches don't trigger Gitea hooks** (#176): for verbs
  that pull data into Gitea-managed repos, use Gitea's API, not
  `git fetch` on the bare repo from the host.
- **Default LXC paths**: board reality is `/data/lxc/`, not
  `/var/lib/lxc/` (#173). Auto-detect or read from config.
- **The grammar surfaces real bugs**: when `healthctl check` flags 4/11
  failing on first run, those are real anomalies, not check bugs.
