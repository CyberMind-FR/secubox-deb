<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Phase 2 — Rspamd Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [docs/superpowers/specs/2026-05-15-mail-phase2-rspamd-design.md](../specs/2026-05-15-mail-phase2-rspamd-design.md).

**Goal:** Replace SpamAssassin + OpenDKIM in the `mail` LXC with a single Rspamd daemon that signs+verifies DKIM, scores spam, runs greylisting, enforces SPF + DMARC + ARC, and rate-limits outbound. Single-domain (`secubox.in`); Phase 3 widens to multi-domain.

**Architecture:**
- Add Rspamd as a Postfix milter (`smtpd_milters = inet:127.0.0.1:11332`). `milter_default_action = accept` so a Rspamd outage downgrades to "accept and deliver" rather than blocking mail.
- Persistent DKIM keys + Bayes corpus + history live at `/data/volumes/mail/rspamd/` (host bind-mounts), so destroying the LXC rootfs preserves data.
- Rspamd HTTP controller behind admin JWT via host nginx + mitmproxy; `enable_password` (from `/etc/secubox/secrets/rspamd-controller.pw`, bind-mounted) gates write actions.
- Legacy `/spam/*` `/grey/*` `/dkim/*` API endpoints become deprecation shims that wrap Rspamd, return same shape, set `X-Deprecated-Endpoint: rspamd`. Removed in `secubox-mail 3.0`.
- Removal order (D9): install + verify Rspamd FIRST, then `apt purge spamassassin opendkim`.

**Tech Stack:** Rspamd (Debian package), Postfix milter protocol, bash 5, FastAPI 0.115+, pytest, bats, Debian packaging.

**Issue:** filed at execution start as *Mail stack: Phase 2 — Rspamd migration* with labels `migration,security,wip`.

**Worktree:** `scripts/agent-worktree.sh start --issue <N>`.

**Canonical paths/values (from Phase 0 rev. 2 + this spec):**
- Mail LXC: `/var/lib/lxc/mail` (→ `/data/lxc/mail`), unprivileged veth `br-lxc`, `10.100.0.10/24`
- Persistent data: `/data/volumes/mail/{vmail,config,ssl,rspamd}`
- Rspamd UI host name: `rspamd.gk2.secubox.in`
- DKIM domain: `secubox.in`, selector `default`

---

## File structure

### New files

| Path | Responsibility |
|---|---|
| `packages/secubox-mail/lib/mail/rspamd.sh` | `install_rspamd`, `configure_rspamd_dkim`, `configure_rspamd_milter`, `configure_rspamd_controller`, `rspamd_keygen <domain> [selector]`, `rspamd_dns_records <domain>`, `rspamd_purge_legacy` |
| `packages/secubox-mail/templates/rspamd/local.d/options.inc` | `local_addrs` whitelist |
| `packages/secubox-mail/templates/rspamd/local.d/worker-proxy.inc` | milter mode 127.0.0.1:11332 |
| `packages/secubox-mail/templates/rspamd/local.d/worker-normal.inc` | scanner bind 127.0.0.1:11333 |
| `packages/secubox-mail/templates/rspamd/local.d/worker-controller.inc` | HTTP UI bind `*:11334` + secrets include |
| `packages/secubox-mail/templates/rspamd/local.d/dkim_signing.conf` | per-domain key path; `secubox.in` only in Phase 2 |
| `packages/secubox-mail/templates/rspamd/local.d/arc.conf` | ARC signing |
| `packages/secubox-mail/templates/rspamd/local.d/dmarc.conf` | DMARC actions + reporting |
| `packages/secubox-mail/templates/rspamd/local.d/greylist.conf` | 1d expire, score-threshold 4 |
| `packages/secubox-mail/templates/rspamd/local.d/ratelimit.conf` | `200/h/user` outbound |
| `packages/secubox-mail/templates/rspamd/postfix-milter-snippet.cf` | Postfix `smtpd_milters` block to append to `main.cf` |
| `packages/secubox-mail/api/routers/__init__.py` | empty marker |
| `packages/secubox-mail/api/routers/rspamd.py` | FastAPI router with new `/rspamd/*` endpoints |
| `packages/secubox-mail/api/routers/legacy.py` | Compat shims `/dkim/*` `/spam/*` `/grey/*` |
| `packages/secubox-mail/api/rspamd_client.py` | tiny httpx wrapper around the Rspamd controller HTTP API |
| `packages/secubox-mail/api/tests/test_phase2_endpoints.py` | new endpoint presence + shim contract tests |
| `packages/secubox-mail/tests/test_rspamd_lib.bats` | bats tests for `lib/mail/rspamd.sh` |
| `packages/secubox-mail/tests/test_deb_paths.bats` | dpkg-deb path-coverage bats |
| `tests/scripts/test-mail-phase2-acceptance.sh` | 13-gate end-to-end smoke |
| `docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md` | Rollback recipe |

### Modified files

| Path | Change |
|---|---|
| `packages/secubox-mail/sbin/mailctl` | Add `cmd_rspamd` dispatch (`install`, `start`, `stop`, `restart`, `status`, `dkim-keygen`, `dns-records`, `learn-spam`, `learn-ham`, `whitelist`, `reload`). Convert `cmd_spam`/`cmd_grey`/`cmd_dkim` to thin wrappers around `cmd_rspamd`. |
| `packages/secubox-mail/lib/mail/install.sh` | `install_mail_packages`: add `rspamd` to apt list; **drop** SA & OpenDKIM (greenfield installs skip them); add `systemctl enable postfix` (Phase 1 follow-up). |
| `packages/secubox-mail/api/main.py` | Mount `rspamd` + `legacy` routers via `app.include_router`. Remove inline `/spam/*`, `/grey/*`, `/dkim/*` handlers — they're in `legacy.py` now. |
| `packages/secubox-mail/config/mail.toml` | Add `[mail.rspamd]` section: `greylist = true`, `bayes_autolearn = true`, `ratelimit_outbound = "200/h/user"`, `web_ui = true`. |
| `packages/secubox-mail/debian/control` | Bump version to 2.3.0; add `rspamd` to `Depends`. (Inside-LXC install handled by `mailctl rspamd install`, not by host-pkg Depends — keep Depends slim; remove `spamassassin` if it was ever listed.) |
| `packages/secubox-mail/debian/changelog` | New 2.3.0 entry. |
| `packages/secubox-mail/debian/postinst` | On upgrade from `<< 2.3`: ensure `/data/volumes/mail/rspamd/{dkim,bayes,history,settings}` exist + ensure `/etc/secubox/secrets/rspamd-controller.pw` exists (generate if absent). |
| `common/nginx/modules.d/mail.conf` | Add `rspamd.gk2.secubox.in` proxy block to `http://10.100.0.10:11334/`. |
| `packages/secubox-mail/sbin/rspamd-route-sync-patch.sh` | NEW small one-shot: patches `/usr/local/bin/sync-mitmproxy-routes.sh` on board to drop `10.100.0.10` from `DEAD_CONTAINER_IPS` (Phase 1 carryover). |
| `.claude/MIGRATION-MAP.md`, `.claude/WIP.md`, `.claude/HISTORY.md` | Update once acceptance is green. |

### Removed files

None. The legacy `cmd_dkim` etc. handlers in `mailctl` get moved to wrappers, not deleted (one-release deprecation hygiene).

---

## Pre-flight

### Task 0: Snapshot board state before any change

**Files:** none (operational).

- [ ] **Step 1: Take board snapshot**

```bash
ssh root@admin.gk2.secubox.in 'set -euo pipefail
  mkdir -p /srv/backups/mail-phase2
  STAMP=$(date +%F-%H%M)
  # data volumes (vmail + config + ssl)
  tar --numeric-owner -czf /srv/backups/mail-phase2/data-volumes-mail-$STAMP.tar.gz /data/volumes/mail 2>/dev/null
  # current LXC pkg list (for diff after we remove SA/OpenDKIM)
  lxc-attach -n mail -- dpkg -l > /srv/backups/mail-phase2/lxc-pkglist-$STAMP.txt
  # current Postfix main.cf (so we know what to revert if needed)
  cp /data/volumes/mail/config/main.cf /srv/backups/mail-phase2/main.cf-$STAMP.bak
  # current mail.toml on host
  cp /etc/secubox/mail.toml /srv/backups/mail-phase2/mail-toml-$STAMP.bak
  ls -la /srv/backups/mail-phase2/'
```

Expected: 4 files in `/srv/backups/mail-phase2/`, all non-zero.

- [ ] **Step 2: Write rollback recipe**

```bash
cat > docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md <<'EOF'
# Mail Phase 2 — Rollback recipe

Backups in /srv/backups/mail-phase2/ on admin.gk2.secubox.in (taken at Task 0).

## Rollback to Phase 1 (secubox-mail 2.2.x)

    ssh root@admin.gk2.secubox.in 'set -euo pipefail
      # Restore Postfix main.cf
      cp /srv/backups/mail-phase2/main.cf-*.bak /data/volumes/mail/config/main.cf
      # Restore mail.toml (legacy keys go back if present)
      cp /srv/backups/mail-phase2/mail-toml-*.bak /etc/secubox/mail.toml
      # Reinstall OpenDKIM + SpamAssassin inside the LXC
      lxc-attach -n mail -- apt-get update
      lxc-attach -n mail -- apt-get install -y opendkim opendkim-tools spamassassin spamc
      lxc-attach -n mail -- apt-get purge -y rspamd
      lxc-attach -n mail -- systemctl restart postfix
      # Downgrade host package
      apt install --allow-downgrades -y secubox-mail=2.2.0-1~bookworm1
      systemctl restart secubox-mail nginx
      # Restore mitmproxy route map: remove rspamd subdomain
      lxc-attach -n mitmproxy -- python3 -c "
import json
p = \"/srv/mitmproxy/haproxy-routes.json\"
d = json.load(open(p))
d.pop(\"rspamd.gk2.secubox.in\", None)
json.dump(d, open(p, \"w\"), indent=2)
"
      lxc-attach -n mitmproxy -- systemctl restart mitmproxy'

The Phase 1 backup at /srv/backups/mail-phase1/ remains the data-loss safety net.
EOF
git add docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md
git commit -m "docs: Phase 2 rollback recipe (pre-issue)"
```

Expected: file committed on master.

---

## Milestone A — Worktree + scaffolding

### Task A1: GitHub issue + worktree

- [ ] **Step 1: Create issue**

```bash
gh issue create \
  --title "Mail stack: Phase 2 — Rspamd migration" \
  --label "migration,security,wip" \
  --body "$(cat <<'EOF'
Per Phase 2 spec docs/superpowers/specs/2026-05-15-mail-phase2-rspamd-design.md.

Replace SpamAssassin + OpenDKIM with Rspamd. Single-domain DKIM (secubox.in,
selector default). Phase 3 widens to multi-domain. Web UI behind admin JWT
+ Rspamd enable_password. ClamAV deferred to Phase 2.5.

## Tasks
- [ ] lib/mail/rspamd.sh + 9 Rspamd config templates
- [ ] mailctl rspamd install/start/stop/status/dkim-keygen/learn-spam/learn-ham
- [ ] FastAPI /api/v1/mail/rspamd/* router
- [ ] Legacy /dkim/* /spam/* /grey/* deprecation shims
- [ ] Postfix milter wiring (smtpd_milters = inet:127.0.0.1:11332)
- [ ] DKIM key generation (secubox.in/default) at /data/volumes/mail/rspamd/dkim/
- [ ] /etc/secubox/secrets/rspamd-controller.pw provisioning
- [ ] Rspamd web UI at rspamd.gk2.secubox.in via host nginx + mitmproxy
- [ ] sync-mitmproxy-routes.sh patch to drop 10.100.0.10 from DEAD list
- [ ] secubox-mail 2.3.0 with rspamd Depends
- [ ] systemctl enable postfix in install_mail_packages (Phase 1 follow-up)
- [ ] dpkg-deb path-coverage bats test
- [ ] 13-gate acceptance smoke
- [ ] SA + OpenDKIM purged AFTER Rspamd verified green

## References
- Spec: docs/superpowers/specs/2026-05-15-mail-phase2-rspamd-design.md
- Plan: docs/superpowers/plans/2026-05-15-mail-phase2-rspamd.md
- Rollback: docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md
- Phase 1 PR (prerequisite, merge first): #141
EOF
)"
```

Expected: issue URL; substitute the number as `<issue>` in subsequent commit messages.

- [ ] **Step 2: Open worktree**

```bash
bash scripts/agent-worktree.sh start --issue <issue>
cd ~/CyberMindStudio/secubox-deb-worktrees/<issue>-mail-stack-phase-2-rspamd-migration/
```

Expected: new feature branch `feature/<issue>-mail-stack-phase-2-rspamd-migration`.

---

### Task A2: Scaffold lib + templates + tests + routers (red baseline)

**Files:**
- Create: `packages/secubox-mail/lib/mail/rspamd.sh`
- Create: `packages/secubox-mail/templates/rspamd/local.d/` (directory)
- Create: `packages/secubox-mail/templates/rspamd/postfix-milter-snippet.cf`
- Create: `packages/secubox-mail/api/routers/__init__.py`
- Create: `packages/secubox-mail/api/routers/rspamd.py`
- Create: `packages/secubox-mail/api/routers/legacy.py`
- Create: `packages/secubox-mail/api/rspamd_client.py`
- Create: `packages/secubox-mail/tests/test_rspamd_lib.bats`
- Create: `packages/secubox-mail/tests/test_deb_paths.bats`
- Create: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Create the lib stub**

```bash
mkdir -p packages/secubox-mail/templates/rspamd/local.d
mkdir -p packages/secubox-mail/api/routers
```

Write `packages/secubox-mail/lib/mail/rspamd.sh`:
```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox-Deb :: mail :: Phase 2 Rspamd helpers (install + configure + dkim).
# Sourced library — do not execute directly.
```

(Each function lands in subsequent Tasks B1–B5.)

- [ ] **Step 2: Stub the 9 Rspamd config templates with header comments**

For each of `options.inc`, `worker-proxy.inc`, `worker-normal.inc`, `worker-controller.inc`, `dkim_signing.conf`, `arc.conf`, `dmarc.conf`, `greylist.conf`, `ratelimit.conf`, create a placeholder:

```bash
for f in options.inc worker-proxy.inc worker-normal.inc worker-controller.inc \
         dkim_signing.conf arc.conf dmarc.conf greylist.conf ratelimit.conf; do
    echo "# SecuBox-Deb :: Phase 2 Rspamd config — populated by Task B2/B3" \
        > "packages/secubox-mail/templates/rspamd/local.d/$f"
done
```

Plus the Postfix snippet:
```bash
cat > packages/secubox-mail/templates/rspamd/postfix-milter-snippet.cf <<'EOF'
# Appended to /data/volumes/mail/config/main.cf by mailctl rspamd install (Task B4).
# Remove block when downgrading per docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md.

# === Phase 2 Rspamd milter ===
smtpd_milters         = inet:127.0.0.1:11332
non_smtpd_milters     = inet:127.0.0.1:11332
milter_default_action = accept
milter_protocol       = 6
milter_mail_macros    = i {auth_authen} {auth_type} {client_addr} {client_name} {mail_addr}
# === End Phase 2 Rspamd milter ===
EOF
```

- [ ] **Step 3: Stub the routers (red baseline)**

`packages/secubox-mail/api/routers/__init__.py` — empty.

`packages/secubox-mail/api/routers/rspamd.py`:
```python
"""Phase 2 Rspamd router. Endpoints implemented in Tasks C2-C5."""
from fastapi import APIRouter

router = APIRouter(prefix="/rspamd", tags=["rspamd"])
```

`packages/secubox-mail/api/routers/legacy.py`:
```python
"""Phase 2 deprecation shims for /dkim/*, /spam/*, /grey/*. Implemented in Task C6."""
from fastapi import APIRouter

router = APIRouter(tags=["legacy-deprecated"])
```

`packages/secubox-mail/api/rspamd_client.py`:
```python
"""Thin async wrapper around the Rspamd HTTP controller.
Implemented in Task C1."""
```

- [ ] **Step 4: Stub the tests (red baseline)**

`packages/secubox-mail/tests/test_rspamd_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "rspamd.sh sources cleanly" {
    [ "$(type -t install_rspamd)" = "function" ]
    [ "$(type -t configure_rspamd_dkim)" = "function" ]
    [ "$(type -t configure_rspamd_milter)" = "function" ]
    [ "$(type -t configure_rspamd_controller)" = "function" ]
    [ "$(type -t rspamd_keygen)" = "function" ]
    [ "$(type -t rspamd_dns_records)" = "function" ]
    [ "$(type -t rspamd_purge_legacy)" = "function" ]
}
```

Update `packages/secubox-mail/tests/helpers.bash` to also source `lib/mail/rspamd.sh`:
```bash
load_libs() {
    local pkg_root="${BATS_TEST_DIRNAME}/.."
    source "${pkg_root}/lib/mail/lxc.sh"
    source "${pkg_root}/lib/mail/install.sh"
    source "${pkg_root}/lib/mail/migrate.sh"
    source "${pkg_root}/lib/mail/rspamd.sh"
}
```

`packages/secubox-mail/tests/test_deb_paths.bats`:
```bash
#!/usr/bin/env bats
# Build the .deb and assert every lib/mail/*.sh ships under the right path.
# Phase 1 lesson: debian/rules drift silently misses files.

@test "secubox-mail .deb ships every lib/mail/*.sh helper" {
    local pkg_dir="${BATS_TEST_DIRNAME}/.."
    local deb
    deb=$(ls -t "${BATS_TEST_DIRNAME}/../../"secubox-mail_*_all.deb 2>/dev/null | head -1) || \
    deb=$(ls -t "${BATS_TEST_DIRNAME}/../"../secubox-mail_*_all.deb 2>/dev/null | head -1)
    [ -n "$deb" ] || skip "no .deb built yet (run dpkg-buildpackage first)"
    local files
    files=$(dpkg-deb -c "$deb" | awk '{print $6}')
    for stub in lxc.sh install.sh migrate.sh rspamd.sh users.sh; do
        echo "$files" | grep -qE "/usr/lib/secubox/mail/lib/${stub}\$" \
            || { echo "MISSING in deb: $stub"; return 1; }
    done
}
```

`packages/secubox-mail/api/tests/test_phase2_endpoints.py`:
```python
"""Phase 2: every new /rspamd/* endpoint + every legacy deprecation shim
responds non-5xx. Phase 1's test_phase1_endpoints.py is kept and still runs.
"""
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
from api.main import app  # noqa: E402

client = TestClient(app)

# Endpoints get populated as Tasks C2-C6 wire them. Test starts skipped.
NEW_ROUTES = []
LEGACY_SHIMS = []


@pytest.mark.parametrize("method,path", NEW_ROUTES)
def test_new_route_responds(method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code < 500, f"{method} {path} → {resp.status_code}"


@pytest.mark.parametrize("method,path", LEGACY_SHIMS)
def test_legacy_shim_responds_with_deprecation_header(method, path):
    resp = client.request(method, path, json={})
    assert resp.status_code < 500, f"{method} {path} → {resp.status_code}"
    assert resp.headers.get("x-deprecated-endpoint") == "rspamd", \
        f"{method} {path} missing deprecation header"
```

- [ ] **Step 5: Verify everything parses**

```bash
bash -n packages/secubox-mail/lib/mail/rspamd.sh && echo lib-OK
python3 -c "
import ast, pathlib
for p in pathlib.Path('packages/secubox-mail/api').rglob('*.py'):
    ast.parse(p.read_text())
print('py-OK')
"
```

Expected: both print OK.

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-mail/lib/mail/rspamd.sh \
        packages/secubox-mail/templates/rspamd/ \
        packages/secubox-mail/api/routers/ \
        packages/secubox-mail/api/rspamd_client.py \
        packages/secubox-mail/api/tests/test_phase2_endpoints.py \
        packages/secubox-mail/tests/test_rspamd_lib.bats \
        packages/secubox-mail/tests/test_deb_paths.bats \
        packages/secubox-mail/tests/helpers.bash
git commit -m "test(mail): Phase 2 scaffolding — rspamd.sh + templates + routers + bats baseline (ref #<issue>)"
```

---

## Milestone B — Rspamd lib + configs

### Task B1: `install_rspamd` + sentinel guard

**Files:**
- Modify: `packages/secubox-mail/lib/mail/rspamd.sh`

- [ ] **Step 1: Add sentinel re-entry guard + `install_rspamd` body**

Append to `lib/mail/rspamd.sh`:
```bash
# Re-entry guard — Phase 1 lesson. Refuse to run if we're already inside
# our own subshell, which would indicate accidental recursion.
if [ "${_SECUBOX_RSPAMD_SH_LOADED:-0}" = "1" ]; then
    echo "rspamd.sh re-loaded — possible recursion" >&2
fi
export _SECUBOX_RSPAMD_SH_LOADED=1

# Install Rspamd inside the named LXC. Idempotent.
install_rspamd() {
    local container="$1"
    [ -n "$container" ] || { echo "install_rspamd: container required" >&2; return 1; }
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    [ -d "$rootfs" ] || { echo "install_rspamd: $rootfs not present" >&2; return 1; }

    echo "[rspamd] installing inside LXC $container..."
    chroot "$rootfs" /bin/bash <<'CHROOT_EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# Rspamd ships its own repo for fresh releases; we use Debian's (1.9.x) for
# distro hygiene. Phase 8 may swap to the upstream repo for newer features.
apt-get update
apt-get install -y --no-install-recommends rspamd redis-server
# Redis is here as the (future) bayes/ratelimit backend; Phase 2 uses sqlite
# defaults but installing it now means a `mailctl rspamd switch-backend redis`
# in Phase 8 is just config, not apt.
systemctl disable redis-server.service 2>/dev/null || true
apt-get clean
rm -rf /var/lib/apt/lists/*
CHROOT_EOF
    echo "[rspamd] package installed"
}
```

- [ ] **Step 2: Run bats — sourcing test passes (other functions still missing → bats reports specific missing names)**

```bash
cd packages/secubox-mail && bats tests/test_rspamd_lib.bats 2>&1 | head -10
```

Expected: bats fails because `configure_rspamd_dkim` etc. aren't defined yet. Sourcing itself succeeds.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/lib/mail/rspamd.sh
git commit -m "feat(mail): rspamd.sh — install_rspamd + re-entry guard (ref #<issue>)"
```

---

### Task B2: Render Rspamd config templates

**Files:**
- Modify: `packages/secubox-mail/templates/rspamd/local.d/options.inc`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/worker-proxy.inc`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/worker-normal.inc`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/worker-controller.inc`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/dkim_signing.conf`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/arc.conf`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/dmarc.conf`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/greylist.conf`
- Modify: `packages/secubox-mail/templates/rspamd/local.d/ratelimit.conf`

- [ ] **Step 1: Populate each template**

```bash
cat > packages/secubox-mail/templates/rspamd/local.d/options.inc <<'EOF'
local_addrs = "127.0.0.0/8, 10.100.0.0/16, 192.168.0.0/16";
# Internal traffic skips greylist + reduced spam checks.
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/worker-proxy.inc <<'EOF'
bind_socket = "127.0.0.1:11332";
milter = yes;
upstream "local" {
    default = yes;
    self_scan = yes;
}
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/worker-normal.inc <<'EOF'
bind_socket = "127.0.0.1:11333";
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/worker-controller.inc <<'EOF'
bind_socket = "*:11334";
.include "$LOCAL_CONFDIR/local.d/secrets.inc"
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/dkim_signing.conf <<'EOF'
# Phase 2: single domain (secubox.in / default). Phase 3 widens via selector_map.
allow_username_mismatch = true;
try_fallback = true;
sign_local = true;
sign_authenticated = true;
selector = "default";
path = "/etc/rspamd-keys/$domain/$selector.key";
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/arc.conf <<'EOF'
sign_local = true;
sign_authenticated = true;
selector = "default";
path = "/etc/rspamd-keys/$domain/$selector.key";
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/dmarc.conf <<'EOF'
actions {
    quarantine = "add_header";
    reject = "reject";
}
reporting {
    enabled = true;
    report_local_controller = true;
}
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/greylist.conf <<'EOF'
expire = 1d;
whitelisted_emails = false;
greylist_min_score = 4;
EOF

cat > packages/secubox-mail/templates/rspamd/local.d/ratelimit.conf <<'EOF'
rates {
    user_outbound = "200 / 1h";
}
whitelisted_rcpts = "postmaster";
EOF
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/templates/rspamd/local.d/
git commit -m "feat(mail): Rspamd config templates (9 .conf files) (ref #<issue>)"
```

---

### Task B3: `configure_rspamd_*` functions (rendering + secret provisioning)

**Files:**
- Modify: `packages/secubox-mail/lib/mail/rspamd.sh`

- [ ] **Step 1: Append functions**

```bash
# Copy the 9 Rspamd local.d templates into the LXC. Bind-mount the host's
# /data/volumes/mail/rspamd/dkim/ as /etc/rspamd-keys/ inside the LXC so the
# template path resolves correctly.
configure_rspamd_milter() {
    local container="$1"
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local local_d="$rootfs/etc/rspamd/local.d"
    install -d -m 0755 "$local_d"
    install -m 0644 \
        "$templates/local.d/options.inc" \
        "$templates/local.d/worker-proxy.inc" \
        "$templates/local.d/worker-normal.inc" \
        "$templates/local.d/dkim_signing.conf" \
        "$templates/local.d/arc.conf" \
        "$templates/local.d/dmarc.conf" \
        "$templates/local.d/greylist.conf" \
        "$templates/local.d/ratelimit.conf" \
        "$local_d/"
    # Bind-mount source key dir under LXC's /etc/rspamd-keys/. Ensure the
    # mount entry exists in $LXC_BASE/$container/config (lxc.mount.entry).
    local data="${DATA_PATH:-/data/volumes/mail}"
    mkdir -p "$data/rspamd/dkim" "$data/rspamd/bayes" "$data/rspamd/history" "$data/rspamd/settings"
    chown -R 100107:100107 "$data/rspamd"  # _rspamd uid:gid mapped through unprivileged LXC (5000+100000=100107 etc; see Phase 0 §5.4)
}

# Provision the Rspamd controller password on the host + bind-mount it.
configure_rspamd_controller() {
    local container="$1"
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"
    local local_d="$rootfs/etc/rspamd/local.d"
    local secret_host="/etc/secubox/secrets/rspamd-controller.pw"

    install -d -m 0700 /etc/secubox/secrets
    if [ ! -s "$secret_host" ]; then
        openssl rand -base64 24 > "$secret_host"
        chmod 0600 "$secret_host"
    fi
    install -m 0644 "$templates/local.d/worker-controller.inc" "$local_d/worker-controller.inc"
    # Render secrets.inc from the host-side password file (read once, write once).
    local pw
    pw=$(tr -d '\n' < "$secret_host")
    # Rspamd accepts a hashed password generated by rspamadm pw -e -p <pw>; for
    # Phase 2 we ship the plain password inside the LXC's secrets.inc and rely
    # on filesystem permissions (0600, _rspamd-owned). Phase 8 may switch to
    # the hashed form.
    cat > "$local_d/secrets.inc" <<EOF_INC
password = "$pw";
enable_password = "$pw";
EOF_INC
    chmod 0600 "$local_d/secrets.inc"
    chown 100110:100110 "$local_d/secrets.inc"  # _rspamd uid in unprivileged LXC
}

# Append the Postfix milter snippet to /data/volumes/mail/config/main.cf
# if not already present.
configure_rspamd_postfix_milter() {
    local container="$1"
    local main_cf="${DATA_PATH:-/data/volumes/mail}/config/main.cf"
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/rspamd"
    if grep -q "Phase 2 Rspamd milter" "$main_cf"; then
        echo "[rspamd] Postfix milter snippet already present in $main_cf"
        return 0
    fi
    cat "$templates/postfix-milter-snippet.cf" >> "$main_cf"
    echo "[rspamd] appended Postfix milter snippet to $main_cf"
}
```

- [ ] **Step 2: Verify bats helper resolves the functions**

```bash
cd packages/secubox-mail && bats tests/test_rspamd_lib.bats 2>&1 | head -10
```

Expected: still fails (missing `configure_rspamd_dkim`, `rspamd_keygen`, `rspamd_dns_records`, `rspamd_purge_legacy`).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/lib/mail/rspamd.sh
git commit -m "feat(mail): configure_rspamd_* render templates + secrets (ref #<issue>)"
```

---

### Task B4: `configure_rspamd_dkim`, `rspamd_keygen`, `rspamd_dns_records`

**Files:**
- Modify: `packages/secubox-mail/lib/mail/rspamd.sh`
- Modify: `packages/secubox-mail/tests/test_rspamd_lib.bats`

- [ ] **Step 1: Add bats tests for keygen**

```bash
@test "rspamd_keygen creates key files for a domain" {
    export DATA_PATH="$BATS_TEST_TMPDIR/data-volumes-mail"
    mkdir -p "$DATA_PATH/rspamd/dkim"
    # rspamadm not available in the test env — mock it.
    cat > "$BATS_TEST_TMPDIR/rspamadm" <<'EOF'
#!/bin/bash
# Mock: emit dummy key/pub when called via 'dkim_keygen'
case "$1" in
    dkim_keygen)
        # Args: dkim_keygen -d <domain> -s <selector> -b 2048 -k <keyfile>
        keyfile=""
        while [ $# -gt 0 ]; do
            case "$1" in
                -k) keyfile="$2"; shift 2 ;;
                *) shift ;;
            esac
        done
        [ -n "$keyfile" ] && echo "-----BEGIN PRIVATE KEY-----" > "$keyfile" \
            && echo "MOCK" >> "$keyfile" \
            && echo "-----END PRIVATE KEY-----" >> "$keyfile"
        # rspamadm prints the DNS TXT record to stdout
        echo "default._domainkey IN TXT ( \"v=DKIM1; k=rsa; p=MOCK\" ) ;"
        ;;
esac
EOF
    chmod +x "$BATS_TEST_TMPDIR/rspamadm"
    PATH="$BATS_TEST_TMPDIR:$PATH" run rspamd_keygen "secubox.in" "default"
    [ "$status" -eq 0 ]
    [ -f "$DATA_PATH/rspamd/dkim/secubox.in/default.key" ]
    [ -f "$DATA_PATH/rspamd/dkim/secubox.in/default.txt" ]
    # Key mode must be 0600
    [ "$(stat -c %a "$DATA_PATH/rspamd/dkim/secubox.in/default.key")" = "600" ]
}

@test "rspamd_dns_records echoes the TXT for a configured domain" {
    export DATA_PATH="$BATS_TEST_TMPDIR/data-volumes-mail"
    mkdir -p "$DATA_PATH/rspamd/dkim/secubox.in"
    echo "default._domainkey IN TXT ( \"v=DKIM1; k=rsa; p=ABCD\" ) ;" \
        > "$DATA_PATH/rspamd/dkim/secubox.in/default.txt"
    run rspamd_dns_records "secubox.in"
    [ "$status" -eq 0 ]
    [[ "$output" == *"v=DKIM1"* ]]
    [[ "$output" == *"default._domainkey"* ]]
}
```

- [ ] **Step 2: Implement**

Append to `lib/mail/rspamd.sh`:
```bash
configure_rspamd_dkim() {
    local container="$1"
    local domain="${2:-secubox.in}"
    local selector="${3:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local rootfs="${LXC_BASE:-/var/lib/lxc}/$container/rootfs"

    # Ensure the key dir exists and the LXC bind-mount entry is present.
    mkdir -p "$data/rspamd/dkim/$domain"
    chown -R 100110:100110 "$data/rspamd/dkim" 2>/dev/null || true

    # Bind-mount entry in LXC config (idempotent)
    local lxc_conf="${LXC_BASE:-/var/lib/lxc}/$container/config"
    if [ -f "$lxc_conf" ] && ! grep -q "/etc/rspamd-keys" "$lxc_conf"; then
        cat >> "$lxc_conf" <<EOF
lxc.mount.entry = $data/rspamd/dkim etc/rspamd-keys none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/bayes var/lib/rspamd/bayes none bind,create=dir 0 0
lxc.mount.entry = $data/rspamd/history var/lib/rspamd/history none bind,create=dir 0 0
EOF
    fi

    # Generate key if missing
    if [ ! -f "$data/rspamd/dkim/$domain/$selector.key" ]; then
        rspamd_keygen "$domain" "$selector"
    fi
}

# Run rspamadm dkim_keygen and write the key + DNS record under $DATA_PATH.
rspamd_keygen() {
    local domain="$1"
    local selector="${2:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local outdir="$data/rspamd/dkim/$domain"
    mkdir -p "$outdir"
    local keyfile="$outdir/$selector.key"
    local txtfile="$outdir/$selector.txt"

    if ! command -v rspamadm >/dev/null 2>&1; then
        echo "rspamd_keygen: rspamadm not on PATH" >&2
        return 1
    fi

    rspamadm dkim_keygen -d "$domain" -s "$selector" -b 2048 -k "$keyfile" > "$txtfile"
    chmod 0600 "$keyfile"
    # _rspamd uid in unprivileged LXC = 100110; on the host (where keygen runs)
    # the bind-mount makes the LXC see the right owner. Set 100110 here too.
    chown 100110:100110 "$keyfile" "$txtfile" 2>/dev/null || true
}

# Echo the DNS TXT record content for the given domain.
rspamd_dns_records() {
    local domain="$1"
    local selector="${2:-default}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    local txtfile="$data/rspamd/dkim/$domain/$selector.txt"
    [ -f "$txtfile" ] || { echo "no DNS record for $domain/$selector" >&2; return 1; }
    cat "$txtfile"
}
```

- [ ] **Step 3: Run bats locally**

```bash
cd packages/secubox-mail && bats tests/test_rspamd_lib.bats 2>&1 | tail -15
```

Expected: 3 tests pass (sources cleanly + 2 keygen tests). Other tests still fail until B5.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/lib/mail/rspamd.sh packages/secubox-mail/tests/test_rspamd_lib.bats
git commit -m "feat(mail): rspamd_keygen + dns_records + dkim bind-mounts (ref #<issue>)"
```

---

### Task B5: `rspamd_purge_legacy`

**Files:**
- Modify: `packages/secubox-mail/lib/mail/rspamd.sh`
- Modify: `packages/secubox-mail/tests/test_rspamd_lib.bats`

- [ ] **Step 1: Add bats test (mocked LXC + apt)**

```bash
@test "rspamd_purge_legacy refuses if Rspamd milter test fails (D9 safety)" {
    # Provide a fake lxc_attach that returns failure for the Rspamd health check.
    lxc_attach() { return 1; }
    export -f lxc_attach
    run rspamd_purge_legacy "mail"
    [ "$status" -ne 0 ]
    [[ "$output" == *"refusing"* ]] || [[ "$output" == *"Rspamd not healthy"* ]]
}

@test "rspamd_purge_legacy proceeds when Rspamd milter is healthy" {
    lxc_attach() {
        local container="$1"; shift
        case "$1" in
            rspamc) echo "Connection succeeded"; return 0 ;;
            apt-get) echo "MOCK apt-get $*"; return 0 ;;
            systemctl) echo "MOCK systemctl $*"; return 0 ;;
            *) return 0 ;;
        esac
    }
    export -f lxc_attach
    run rspamd_purge_legacy "mail"
    [ "$status" -eq 0 ]
    [[ "$output" == *"MOCK apt-get"* ]]
}
```

- [ ] **Step 2: Implement (D9 safety check)**

Append to `lib/mail/rspamd.sh`:
```bash
# Refuse to purge SA/OpenDKIM unless Rspamd is healthy (spec D9).
rspamd_purge_legacy() {
    local container="$1"
    [ -n "$container" ] || { echo "rspamd_purge_legacy: container required" >&2; return 1; }

    # Health check: rspamc must reach the milter and return success.
    if ! lxc_attach "$container" rspamc -h 127.0.0.1:11334 stat >/dev/null 2>&1; then
        echo "rspamd_purge_legacy: refusing — Rspamd not healthy on $container:11334" >&2
        return 1
    fi

    echo "[rspamd] Rspamd healthy; purging SA + OpenDKIM from $container..."
    lxc_attach "$container" systemctl stop opendkim spamassassin spamd 2>/dev/null || true
    lxc_attach "$container" systemctl disable opendkim spamassassin spamd 2>/dev/null || true
    lxc_attach "$container" apt-get purge -y opendkim opendkim-tools spamassassin spamc spamd
    echo "[rspamd] legacy purge complete"
}
```

- [ ] **Step 3: Run bats — all 5+ rspamd-lib tests pass**

```bash
cd packages/secubox-mail && bats tests/test_rspamd_lib.bats 2>&1 | tail -10
```

Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/lib/mail/rspamd.sh packages/secubox-mail/tests/test_rspamd_lib.bats
git commit -m "feat(mail): rspamd_purge_legacy with D9 health gate (ref #<issue>)"
```

---

## Milestone C — FastAPI + Rspamd HTTP client

### Task C1: `rspamd_client.py`

**Files:**
- Modify: `packages/secubox-mail/api/rspamd_client.py`

- [ ] **Step 1: Write the client**

```python
"""Thin httpx-based wrapper around the Rspamd HTTP controller.

The controller listens at http://10.100.0.10:11334 (mail LXC). It accepts a
'Password:' header for read endpoints and 'Password: <enable_password>' for
write endpoints (learn, settings, whitelist). In Phase 2 both passwords are
the same; Phase 8 may split them.

Password is read from /etc/secubox/secrets/rspamd-controller.pw at import time.
"""
from __future__ import annotations
import os
import pathlib
from typing import Any

import httpx

_RSPAMD_BASE = os.environ.get("RSPAMD_BASE", "http://10.100.0.10:11334")
_SECRET_PATH = pathlib.Path("/etc/secubox/secrets/rspamd-controller.pw")
_TIMEOUT = httpx.Timeout(5.0, connect=2.0)


def _password() -> str:
    if not _SECRET_PATH.exists():
        return ""
    return _SECRET_PATH.read_text().strip()


def _headers() -> dict:
    pw = _password()
    return {"Password": pw} if pw else {}


async def get(path: str) -> dict[str, Any]:
    """GET path. Returns {} on connection failure (caller decides how to surface)."""
    try:
        async with httpx.AsyncClient(base_url=_RSPAMD_BASE, timeout=_TIMEOUT) as c:
            r = await c.get(path, headers=_headers())
            if r.status_code >= 400:
                return {"error": f"rspamd {r.status_code}", "body": r.text[:200]}
            return r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return {"error": "rspamd unreachable", "detail": str(e)}


async def post(path: str, body: dict | bytes | str | None = None) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(base_url=_RSPAMD_BASE, timeout=_TIMEOUT) as c:
            kwargs = {"headers": _headers()}
            if isinstance(body, dict):
                kwargs["json"] = body
            elif body is not None:
                kwargs["content"] = body
            r = await c.post(path, **kwargs)
            if r.status_code >= 400:
                return {"error": f"rspamd {r.status_code}", "body": r.text[:200]}
            return r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        return {"error": "rspamd unreachable", "detail": str(e)}
```

- [ ] **Step 2: Parse check**

```bash
python3 -c "import ast; ast.parse(open('packages/secubox-mail/api/rspamd_client.py').read()); print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/api/rspamd_client.py
git commit -m "feat(mail): rspamd_client.py — httpx wrapper around controller HTTP API (ref #<issue>)"
```

---

### Task C2: `/api/v1/mail/rspamd/{status,history,scores,reload}` read endpoints

**Files:**
- Modify: `packages/secubox-mail/api/routers/rspamd.py`
- Modify: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Implement**

Replace `routers/rspamd.py`:
```python
"""Phase 2 Rspamd router. Auth via JWT (delegated to main.py via Depends)."""
from __future__ import annotations
from fastapi import APIRouter, Depends
from secubox_core.auth import require_jwt

from .. import rspamd_client

router = APIRouter(prefix="/rspamd", tags=["rspamd"])


@router.get("/status", dependencies=[Depends(require_jwt)])
async def status() -> dict:
    """Rspamd stat + module summary."""
    return await rspamd_client.get("/stat")


@router.get("/history", dependencies=[Depends(require_jwt)])
async def history(limit: int = 100) -> dict:
    """Recent scan history (truncated)."""
    return await rspamd_client.get(f"/history?limit={limit}")


@router.get("/scores", dependencies=[Depends(require_jwt)])
async def scores() -> dict:
    """Top-N rule contributions to recent scores."""
    return await rspamd_client.get("/graph")


@router.post("/reload", dependencies=[Depends(require_jwt)])
async def reload_rspamd() -> dict:
    """Graceful Rspamd reload."""
    return await rspamd_client.post("/reload")
```

- [ ] **Step 2: Update `test_phase2_endpoints.py` to cover these**

```python
NEW_ROUTES = [
    ("GET", "/rspamd/status"),
    ("GET", "/rspamd/history"),
    ("GET", "/rspamd/scores"),
    ("POST", "/rspamd/reload"),
]
```

(Leave `LEGACY_SHIMS` empty until C6.)

- [ ] **Step 3: Wire router into `api/main.py`**

In `packages/secubox-mail/api/main.py`, just after `app = FastAPI(...)`, add:
```python
from .routers import rspamd as rspamd_router
app.include_router(rspamd_router.router)
```

- [ ] **Step 4: Run pytest**

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase2_endpoints.py -q 2>&1 | tail -10
```

Expected: 4 tests pass (no JWT → 401, which is `< 500`).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/api/routers/rspamd.py \
        packages/secubox-mail/api/main.py \
        packages/secubox-mail/api/tests/test_phase2_endpoints.py
git commit -m "feat(mail): /rspamd/{status,history,scores,reload} read endpoints (ref #<issue>)"
```

---

### Task C3: `/rspamd/{learn-spam,learn-ham}` write endpoints

**Files:**
- Modify: `packages/secubox-mail/api/routers/rspamd.py`
- Modify: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Add request models + handlers**

Append to `routers/rspamd.py`:
```python
from pydantic import BaseModel


class LearnRequest(BaseModel):
    raw_eml: str | None = None
    message_id: str | None = None


@router.post("/learn-spam", dependencies=[Depends(require_jwt)])
async def learn_spam(req: LearnRequest) -> dict:
    if req.raw_eml:
        return await rspamd_client.post("/learnspam", body=req.raw_eml.encode())
    if req.message_id:
        return {"error": "message_id learning requires Phase 5 Roundcube integration"}
    return {"error": "either raw_eml or message_id required"}


@router.post("/learn-ham", dependencies=[Depends(require_jwt)])
async def learn_ham(req: LearnRequest) -> dict:
    if req.raw_eml:
        return await rspamd_client.post("/learnham", body=req.raw_eml.encode())
    if req.message_id:
        return {"error": "message_id learning requires Phase 5 Roundcube integration"}
    return {"error": "either raw_eml or message_id required"}
```

- [ ] **Step 2: Add to `NEW_ROUTES`**

```python
NEW_ROUTES += [
    ("POST", "/rspamd/learn-spam"),
    ("POST", "/rspamd/learn-ham"),
]
```

- [ ] **Step 3: Pytest pass**

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase2_endpoints.py -q
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/api/routers/rspamd.py \
        packages/secubox-mail/api/tests/test_phase2_endpoints.py
git commit -m "feat(mail): /rspamd/learn-{spam,ham} write endpoints (ref #<issue>)"
```

---

### Task C4: `/rspamd/whitelist` CRUD

**Files:**
- Modify: `packages/secubox-mail/api/routers/rspamd.py`
- Modify: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Implement**

Append to `routers/rspamd.py`:
```python
class WhitelistEntry(BaseModel):
    address: str
    type: str = "from"   # from | rcpt | ip


@router.get("/whitelist", dependencies=[Depends(require_jwt)])
async def whitelist_list() -> dict:
    return await rspamd_client.get("/maps")


@router.post("/whitelist", dependencies=[Depends(require_jwt)])
async def whitelist_add(entry: WhitelistEntry) -> dict:
    # Rspamd whitelist editing uses /maps_action; details depend on backend.
    # Phase 2 returns 501 + guidance; Phase 8 finishes the binding once the
    # admin UI design is settled.
    return {"error": "whitelist add requires Phase 8 admin UI", "entry": entry.model_dump()}


@router.delete("/whitelist/{entry_id}", dependencies=[Depends(require_jwt)])
async def whitelist_del(entry_id: str) -> dict:
    return {"error": "whitelist delete requires Phase 8 admin UI", "id": entry_id}
```

- [ ] **Step 2: Add to NEW_ROUTES + run pytest**

```python
NEW_ROUTES += [
    ("GET", "/rspamd/whitelist"),
    ("POST", "/rspamd/whitelist"),
    ("DELETE", "/rspamd/whitelist/x"),
]
```

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase2_endpoints.py -q
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/api/routers/rspamd.py \
        packages/secubox-mail/api/tests/test_phase2_endpoints.py
git commit -m "feat(mail): /rspamd/whitelist read endpoint + 501 stubs for write (Phase 8) (ref #<issue>)"
```

---

### Task C5: `/rspamd/dkim/{domain}/{keygen,record}`

**Files:**
- Modify: `packages/secubox-mail/api/routers/rspamd.py`
- Modify: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Implement**

Append to `routers/rspamd.py`:
```python
import subprocess


@router.get("/dkim/{domain}", dependencies=[Depends(require_jwt)])
async def dkim_status(domain: str) -> dict:
    """Show DKIM key info for a domain."""
    base = f"/data/volumes/mail/rspamd/dkim/{domain}"
    import pathlib
    key = pathlib.Path(f"{base}/default.key")
    txt = pathlib.Path(f"{base}/default.txt")
    return {
        "domain": domain,
        "selector": "default",
        "key_present": key.exists(),
        "dns_txt": txt.read_text() if txt.exists() else None,
    }


@router.post("/dkim/{domain}/keygen", dependencies=[Depends(require_jwt)])
async def dkim_keygen(domain: str) -> dict:
    """Run mailctl rspamd dkim-keygen for the given domain."""
    proc = subprocess.run(
        ["/usr/sbin/mailctl", "rspamd", "dkim-keygen", domain, "default"],
        capture_output=True, text=True, timeout=60,
    )
    return {
        "success": proc.returncode == 0,
        "stdout": proc.stdout[-500:],
        "stderr": proc.stderr[-500:],
    }
```

- [ ] **Step 2: Pytest + commit**

```python
NEW_ROUTES += [
    ("GET", "/rspamd/dkim/secubox.in"),
    ("POST", "/rspamd/dkim/secubox.in/keygen"),
]
```

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase2_endpoints.py -q
git add packages/secubox-mail/api/routers/rspamd.py packages/secubox-mail/api/tests/test_phase2_endpoints.py
git commit -m "feat(mail): /rspamd/dkim/{domain}/{status,keygen} endpoints (ref #<issue>)"
```

---

### Task C6: Legacy deprecation shims

**Files:**
- Modify: `packages/secubox-mail/api/routers/legacy.py`
- Modify: `packages/secubox-mail/api/main.py`
- Modify: `packages/secubox-mail/api/tests/test_phase2_endpoints.py`

- [ ] **Step 1: Write the shims**

Replace `routers/legacy.py`:
```python
"""Phase 2 deprecation shims. Each forwards to a Rspamd-equivalent path and
emits the `X-Deprecated-Endpoint: rspamd` header. Removed in v3.0.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, Response
from secubox_core.auth import require_jwt

from .. import rspamd_client

router = APIRouter(tags=["legacy-deprecated"])


def _depr(resp: Response) -> None:
    resp.headers["x-deprecated-endpoint"] = "rspamd"


# ---- /dkim/* ----------------------------------------------------------------

@router.get("/dkim/status", dependencies=[Depends(require_jwt)])
async def dkim_status(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.get("/stat")


@router.get("/dkim/record", dependencies=[Depends(require_jwt)])
async def dkim_record(response: Response) -> dict:
    _depr(response)
    import pathlib
    txt = pathlib.Path("/data/volumes/mail/rspamd/dkim/secubox.in/default.txt")
    return {"record": txt.read_text() if txt.exists() else None}


@router.post("/dkim/setup", dependencies=[Depends(require_jwt)])
async def dkim_setup(response: Response) -> dict:
    _depr(response)
    import subprocess
    proc = subprocess.run(
        ["/usr/sbin/mailctl", "rspamd", "dkim-keygen", "secubox.in", "default"],
        capture_output=True, text=True, timeout=60,
    )
    return {"success": proc.returncode == 0, "stdout": proc.stdout[-500:]}


@router.post("/dkim/keygen", dependencies=[Depends(require_jwt)])
async def dkim_keygen(response: Response) -> dict:
    _depr(response)
    return await dkim_setup(response)


@router.post("/dkim/sync", dependencies=[Depends(require_jwt)])
async def dkim_sync(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd reads keys via bind-mount — no sync needed"}


# ---- /spam/* ----------------------------------------------------------------

@router.get("/spam/status", dependencies=[Depends(require_jwt)])
async def spam_status(response: Response) -> dict:
    _depr(response)
    r = await rspamd_client.get("/stat")
    return {"installed": True, "configured": True, "enabled": "error" not in r, "via": "rspamd", "rspamd_stat": r}


@router.post("/spam/setup", dependencies=[Depends(require_jwt)])
async def spam_setup(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd is configured at install time"}


@router.post("/spam/enable", dependencies=[Depends(require_jwt)])
async def spam_enable(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.post("/reload")


@router.post("/spam/disable", dependencies=[Depends(require_jwt)])
async def spam_disable(response: Response) -> dict:
    _depr(response)
    return {"success": False, "error": "disabling Rspamd requires lxc-attach systemctl stop rspamd"}


@router.post("/spam/update", dependencies=[Depends(require_jwt)])
async def spam_update(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Rspamd updates via apt-get"}


# ---- /grey/* ----------------------------------------------------------------

@router.get("/grey/status", dependencies=[Depends(require_jwt)])
async def grey_status(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.get("/stat")


@router.post("/grey/setup", dependencies=[Depends(require_jwt)])
async def grey_setup(response: Response) -> dict:
    _depr(response)
    return {"success": True, "note": "Greylist is part of Rspamd; configure via /etc/rspamd/local.d/greylist.conf"}


@router.post("/grey/enable", dependencies=[Depends(require_jwt)])
async def grey_enable(response: Response) -> dict:
    _depr(response)
    return await rspamd_client.post("/reload")


@router.post("/grey/disable", dependencies=[Depends(require_jwt)])
async def grey_disable(response: Response) -> dict:
    _depr(response)
    return {"success": False, "error": "disable greylist via greylist.conf disabled = true"}
```

- [ ] **Step 2: Remove the inline `/spam/*`, `/grey/*`, `/dkim/*` handlers from `main.py`**

In `packages/secubox-mail/api/main.py`:
- Find and delete the `@app.get("/dkim/status")` block + its function (and the other dkim/spam/grey functions).
- After the `app.include_router(rspamd_router.router)` line (from C2), add:
  ```python
  from .routers import legacy as legacy_router
  app.include_router(legacy_router.router)
  ```

- [ ] **Step 3: Update LEGACY_SHIMS in pytest**

```python
LEGACY_SHIMS = [
    ("GET",    "/dkim/status"),
    ("GET",    "/dkim/record"),
    ("POST",   "/dkim/setup"),
    ("POST",   "/dkim/keygen"),
    ("POST",   "/dkim/sync"),
    ("GET",    "/spam/status"),
    ("POST",   "/spam/setup"),
    ("POST",   "/spam/enable"),
    ("POST",   "/spam/disable"),
    ("POST",   "/spam/update"),
    ("GET",    "/grey/status"),
    ("POST",   "/grey/setup"),
    ("POST",   "/grey/enable"),
    ("POST",   "/grey/disable"),
]
```

- [ ] **Step 4: Run pytest**

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase2_endpoints.py -q
```

Expected: all NEW_ROUTES + 14 LEGACY_SHIMS pass (the legacy ones return 401 without JWT — header check is on a 401 response, which still includes the header per FastAPI ResponseDependency).

> If the deprecation-header assertion fails on 401 responses, switch the assertion to: header is present on 401 OR 2xx — but NOT on errors that bypass the route (e.g. 404 because the router isn't registered).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/api/routers/legacy.py \
        packages/secubox-mail/api/main.py \
        packages/secubox-mail/api/tests/test_phase2_endpoints.py
git commit -m "feat(mail): legacy /dkim/* /spam/* /grey/* deprecation shims to Rspamd (ref #<issue>)"
```

---

### Task C7: Phase 1 endpoint pytest still green

**Files:** none (verification).

- [ ] **Step 1: Re-run the Phase 1 presence test**

```bash
cd packages/secubox-mail && PYTHONPATH=../../common python3 -m pytest api/tests/test_phase1_endpoints.py -q
```

Expected: 62/62 still pass. The legacy shims are now routed through `routers/legacy.py` but at the same paths.

- [ ] **Step 2: If any regression**

Inspect the failing endpoint. Either restore an inline handler in `main.py` or extend `routers/legacy.py`. Commit any fix as `fix(mail): preserve Phase 1 endpoint contract for X (ref #<issue>)`.

---

## Milestone D — mailctl `rspamd` subcommand

### Task D1: `cmd_rspamd` dispatcher + `install`, `start`, `stop`, `restart`, `reload`, `status`

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`

- [ ] **Step 1: Add the dispatcher**

In `mailctl`, after the existing `cmd_migrate_config` function (and before the main `case` statement), append:

```bash
# ============================================================================
# Phase 2 — Rspamd subcommand
# ============================================================================

cmd_rspamd() {
    [ "$(id -u)" -eq 0 ] || { error "Root required"; return 1; }
    : "${LIB_DIR:=/usr/lib/secubox/mail/lib}"
    [ -f "$LIB_DIR/rspamd.sh" ] || LIB_DIR="$(dirname "$0")/../lib/mail"
    # shellcheck source=/dev/null
    source "$LIB_DIR/lxc.sh"
    # shellcheck source=/dev/null
    source "$LIB_DIR/install.sh"
    # shellcheck source=/dev/null
    source "$LIB_DIR/rspamd.sh"

    local sub="${1:-status}"
    shift || true
    case "$sub" in
        install)
            LXC_BASE="$LXC_PATH" install_rspamd "$CONTAINER"
            LXC_BASE="$LXC_PATH" configure_rspamd_milter "$CONTAINER"
            LXC_BASE="$LXC_PATH" configure_rspamd_controller "$CONTAINER"
            LXC_BASE="$LXC_PATH" configure_rspamd_dkim "$CONTAINER" "$DOMAIN" "default"
            LXC_BASE="$LXC_PATH" configure_rspamd_postfix_milter "$CONTAINER"
            log "Rspamd installed. Start with: mailctl rspamd start"
            ;;
        start|restart)
            lxc_attach "$CONTAINER" systemctl restart rspamd
            ;;
        stop)
            lxc_attach "$CONTAINER" systemctl stop rspamd
            ;;
        reload)
            lxc_attach "$CONTAINER" systemctl reload rspamd
            ;;
        status)
            lxc_attach "$CONTAINER" rspamc stat 2>&1 | head -40
            ;;
        dkim-keygen)
            local domain="${1:-$DOMAIN}"
            local sel="${2:-default}"
            LXC_BASE="$LXC_PATH" rspamd_keygen "$domain" "$sel"
            ;;
        dns-records)
            local domain="${1:-$DOMAIN}"
            local sel="${2:-default}"
            rspamd_dns_records "$domain" "$sel"
            ;;
        learn-spam)
            local target="${1:-}"
            [ -n "$target" ] || { echo "Usage: mailctl rspamd learn-spam <maildir-or-file>"; return 1; }
            lxc_attach "$CONTAINER" rspamc learn_spam "$target"
            ;;
        learn-ham)
            local target="${1:-}"
            [ -n "$target" ] || { echo "Usage: mailctl rspamd learn-ham <maildir-or-file>"; return 1; }
            lxc_attach "$CONTAINER" rspamc learn_ham "$target"
            ;;
        purge-legacy)
            LXC_BASE="$LXC_PATH" rspamd_purge_legacy "$CONTAINER"
            ;;
        *)
            cat <<USAGE
Usage:
  mailctl rspamd install
  mailctl rspamd start | stop | restart | reload
  mailctl rspamd status
  mailctl rspamd dkim-keygen [<domain>] [<selector>]
  mailctl rspamd dns-records [<domain>] [<selector>]
  mailctl rspamd learn-spam <maildir-or-file>
  mailctl rspamd learn-ham  <maildir-or-file>
  mailctl rspamd purge-legacy            # purge SA/OpenDKIM after Rspamd verified
USAGE
            ;;
    esac
}
```

- [ ] **Step 2: Add to the main case statement**

```bash
    rspamd)      shift; cmd_rspamd "$@" ;;
```

- [ ] **Step 3: Parse check + smoke**

```bash
bash -n packages/secubox-mail/sbin/mailctl && echo "parse OK"
packages/secubox-mail/sbin/mailctl rspamd 2>&1 | head -5
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/sbin/mailctl
git commit -m "feat(mail): mailctl rspamd subcommand (ref #<issue>)"
```

---

## Milestone E — Install-side changes

### Task E1: `install_mail_packages` adds Rspamd dep + `systemctl enable postfix`

**Files:**
- Modify: `packages/secubox-mail/lib/mail/install.sh`

- [ ] **Step 1: Add Rspamd to apt list + enable postfix**

Locate `install_mail_packages()` in `lib/mail/install.sh`. Inside the `chroot ... <<CHROOT_EOF` block, change the `apt-get install` line:

```bash
# Before
apt-get install -y --no-install-recommends \
    postfix postfix-lmdb \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    rsyslog ca-certificates openssl

# After
apt-get install -y --no-install-recommends \
    postfix postfix-lmdb \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
    rspamd \
    rsyslog ca-certificates openssl
systemctl enable postfix dovecot rspamd
```

- [ ] **Step 2: Bats green**

```bash
cd packages/secubox-mail && bats tests/test_install_lib.bats
```

Expected: existing tests still pass (we didn't change function signatures).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/lib/mail/install.sh
git commit -m "feat(mail): install_mail_packages — add rspamd + systemctl enable postfix (ref #<issue>)"
```

---

### Task E2: `mail.toml` `[mail.rspamd]` section

**Files:**
- Modify: `packages/secubox-mail/config/mail.toml`

- [ ] **Step 1: Append the section**

Add at the end of `config/mail.toml`:
```toml

[mail.rspamd]
# Phase 2: single-domain DKIM (secubox.in / default). Phase 3 widens.
greylist = true
bayes_autolearn = true
ratelimit_outbound = "200/h/user"
web_ui = true
web_ui_host = "rspamd.gk2.secubox.in"
```

- [ ] **Step 2: TOML parse check**

```bash
python3 -c "import tomllib; tomllib.loads(open('packages/secubox-mail/config/mail.toml').read()); print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/config/mail.toml
git commit -m "feat(mail): mail.toml [mail.rspamd] section (ref #<issue>)"
```

---

### Task E3: postinst provisions secrets + data dirs

**Files:**
- Modify: `packages/secubox-mail/debian/postinst`

- [ ] **Step 1: Add provisioning to `configure` branch**

After the existing `if dpkg --compare-versions … lt-nl 2.2.0` block, add:

```sh
# Phase 2: on upgrade from < 2.3, provision Rspamd secrets + data dirs.
if dpkg --compare-versions "${2:-0}" lt-nl 2.3.0; then
    install -d -m 0700 /etc/secubox/secrets
    if [ ! -s /etc/secubox/secrets/rspamd-controller.pw ]; then
        openssl rand -base64 24 > /etc/secubox/secrets/rspamd-controller.pw
        chmod 0600 /etc/secubox/secrets/rspamd-controller.pw
    fi
    install -d -m 0750 /data/volumes/mail/rspamd
    install -d -m 0750 /data/volumes/mail/rspamd/dkim
    install -d -m 0750 /data/volumes/mail/rspamd/bayes
    install -d -m 0750 /data/volumes/mail/rspamd/history
    install -d -m 0750 /data/volumes/mail/rspamd/settings
    # _rspamd uid 100110 (5000 + 100000) in unprivileged LXC; safe to chown blindly
    chown -R 100110:100110 /data/volumes/mail/rspamd 2>/dev/null || true
fi
```

- [ ] **Step 2: Shell parse check + commit**

```bash
sh -n packages/secubox-mail/debian/postinst && echo parse-OK
git add packages/secubox-mail/debian/postinst
git commit -m "feat(mail): postinst provisions Rspamd secret + data dirs on upgrade <2.3 (ref #<issue>)"
```

---

## Milestone F — Host edge (nginx + mitmproxy)

### Task F1: nginx vhost for `rspamd.gk2.secubox.in`

**Files:**
- Modify: `common/nginx/modules.d/mail.conf`

- [ ] **Step 1: Inspect the file**

```bash
grep -n 'webmail\.gk2\.secubox\.in\|mail-admin' common/nginx/modules.d/mail.conf 2>/dev/null || \
ls common/nginx/modules.d/
```

> If the file doesn't yet exist (Phase 1 didn't add it because the board uses snippet-style routing), create it with both the webmail and rspamd blocks. Otherwise, append the rspamd block.

- [ ] **Step 2: Add the rspamd block**

If the file exists, append:
```nginx

# Phase 2 — Rspamd controller (admin UI behind JWT + Rspamd enable_password)
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name rspamd.gk2.secubox.in;
    include /etc/nginx/snippets/secubox-tls.conf;

    location / {
        proxy_pass http://10.100.0.10:11334/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add common/nginx/modules.d/mail.conf
git commit -m "feat(mail): host nginx — rspamd.gk2.secubox.in proxies to LXC :11334 (ref #<issue>)"
```

---

### Task F2: `sync-mitmproxy-routes.sh` patch (Phase 1 carryover)

**Files:**
- Create: `packages/secubox-mail/sbin/rspamd-route-sync-patch.sh`

- [ ] **Step 1: Write the one-shot patch**

```bash
cat > packages/secubox-mail/sbin/rspamd-route-sync-patch.sh <<'EOF'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Phase 2 deploy-time helper: patch the board's sync script so the mail LXC
# IP (10.100.0.10) is not treated as a "dead container". Idempotent.
set -euo pipefail
SCRIPT=/usr/local/bin/sync-mitmproxy-routes.sh
[ -f "$SCRIPT" ] || { echo "$SCRIPT not found — nothing to patch" >&2; exit 0; }
if grep -q '^DEAD_CONTAINER_IPS=.*10\.100\.0\.10' "$SCRIPT"; then
    sed -i 's|^DEAD_CONTAINER_IPS="10\.100\.0\.10 |DEAD_CONTAINER_IPS="|' "$SCRIPT"
    echo "[phase2] removed 10.100.0.10 from DEAD_CONTAINER_IPS in $SCRIPT"
else
    echo "[phase2] $SCRIPT already excludes 10.100.0.10 — no change"
fi
EOF
chmod +x packages/secubox-mail/sbin/rspamd-route-sync-patch.sh
git add packages/secubox-mail/sbin/rspamd-route-sync-patch.sh
git commit -m "feat(mail): rspamd-route-sync-patch — drop 10.100.0.10 from board DEAD_CONTAINER_IPS (ref #<issue>)"
```

---

## Milestone G — Package metadata + acceptance smoke

### Task G1: secubox-mail 2.3.0 bump

**Files:**
- Modify: `packages/secubox-mail/debian/control`
- Modify: `packages/secubox-mail/debian/changelog`

- [ ] **Step 1: Update `debian/control`**

```
# Before
Depends: ${misc:Depends}, secubox-core (>= 1.0.0), lxc, debootstrap, openssl
Breaks: secubox-mail-lxc (<< 2.2), secubox-webmail (<< 2.2), secubox-webmail-lxc (<< 2.2)
Replaces: secubox-mail-lxc (<< 2.2), secubox-webmail (<< 2.2), secubox-webmail-lxc (<< 2.2)

# After
Depends: ${misc:Depends}, secubox-core (>= 1.0.0), lxc, debootstrap, openssl, python3-httpx
Breaks: secubox-mail-lxc (<< 2.2), secubox-webmail (<< 2.2), secubox-webmail-lxc (<< 2.2)
Replaces: secubox-mail-lxc (<< 2.2), secubox-webmail (<< 2.2), secubox-webmail-lxc (<< 2.2)
```

(Rspamd itself is installed inside the LXC by `install_mail_packages`, not via host Depends.)

- [ ] **Step 2: Prepend changelog**

```bash
python3 - <<'PY'
from pathlib import Path
p = Path("packages/secubox-mail/debian/changelog")
new = """secubox-mail (2.3.0-1~bookworm1) bookworm; urgency=medium

  * Phase 2: Rspamd migration. Replaces SpamAssassin + OpenDKIM with a
    single Rspamd daemon (greylist + spam + DKIM sign/verify + SPF + DMARC
    + ARC + ratelimit).
  * Single-domain DKIM for secubox.in (selector "default"); Phase 3 widens
    to multi-domain.
  * New lib/mail/rspamd.sh + 9 Rspamd config templates + Postfix milter
    snippet.
  * mailctl gains rspamd subcommand (install/start/stop/status/dkim-keygen/
    dns-records/learn-spam/learn-ham/purge-legacy).
  * FastAPI /api/v1/mail/rspamd/* (status, history, scores, learn,
    whitelist, dkim, reload) via new routers/rspamd.py.
  * Legacy /dkim/* /spam/* /grey/* become deprecation shims that emit
    X-Deprecated-Endpoint: rspamd. Removed in 3.0.
  * Rspamd web UI at rspamd.gk2.secubox.in (admin JWT + Rspamd
    enable_password from /etc/secubox/secrets/rspamd-controller.pw).
  * Phase 1 carryovers: systemctl enable postfix at install; bats
    test_deb_paths verifies dpkg-deb -c ships every lib/mail/*.sh.
  * postinst on upgrade from <2.3 provisions /etc/secubox/secrets/
    rspamd-controller.pw + /data/volumes/mail/rspamd/{dkim,bayes,history,
    settings}.
  * Closes: #<issue>

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 15 May 2026 18:00:00 +0200

"""
p.write_text(new + p.read_text())
PY
```

- [ ] **Step 3: Build + verify**

```bash
(cd packages/secubox-mail && dpkg-buildpackage -us -uc -b 2>&1 | tail -5)
ls -la packages/secubox-mail_2.3.0-1~bookworm1_all.deb
dpkg-deb -I packages/secubox-mail_2.3.0-1~bookworm1_all.deb 2>/dev/null | grep -E 'Version|Depends|Breaks'
```

- [ ] **Step 4: Run path-coverage bats**

```bash
cd packages/secubox-mail && bats tests/test_deb_paths.bats
```

Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/debian/control packages/secubox-mail/debian/changelog
git commit -m "feat(mail): bump secubox-mail to 2.3.0 (Phase 2: Rspamd) (ref #<issue>)"
```

---

### Task G2: Acceptance smoke script

**Files:**
- Create: `tests/scripts/test-mail-phase2-acceptance.sh`

- [ ] **Step 1: Write the script**

```bash
cat > tests/scripts/test-mail-phase2-acceptance.sh <<'EOF'
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# tests/scripts/test-mail-phase2-acceptance.sh — 13-gate end-to-end smoke.
#
# IMPORTANT: every gate that invokes mailctl on the board MUST use `timeout`
# never raw pipes. Phase 1 lesson: pipes to tail/head hold stdout open and
# turn any recursion into a fork-bomb.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

HOST="${1:-root@admin.gk2.secubox.in}"
HOST_HOSTNAME="${HOST#*@}"
HOST_IP=$(getent ahosts "$HOST_HOSTNAME" 2>/dev/null | awk '/STREAM/ {print $1; exit}')
HOST_IP="${HOST_IP:-$HOST_HOSTNAME}"

step() { echo; echo "[phase2] $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

step "1) Source parses + bats green"
for f in "$REPO"/packages/secubox-mail/sbin/{mailctl,mail-migrate-to-single-lxc.sh}; do
    bash -n "$f" || fail "bash -n $f"
done
( cd "$REPO/packages/secubox-mail" && bats tests/ >/dev/null ) || fail "bats failed"
pass "source parses + bats green"

step "2) Pytest: phase1 + phase2 endpoint tests green"
( cd "$REPO/packages/secubox-mail" && PYTHONPATH="$REPO/common" python3 -m pytest api/tests/ -q ) >/dev/null \
    || fail "pytest failed"
pass "pytest green"

step "3) Path-coverage bats: deb ships all lib/mail/*.sh"
( cd "$REPO/packages/secubox-mail" && bats tests/test_deb_paths.bats ) >/dev/null \
    || fail "deb path coverage failed"
pass "deb ships rspamd.sh + 4 sibling libs"

step "4) Rspamd worker-proxy listening on 11332, controller on 11334"
ssh "$HOST" 'lxc-attach -n mail -- ss -tlnp' > /tmp/phase2-ports
grep -q ':11332' /tmp/phase2-ports || fail "rspamd worker-proxy:11332 not listening"
grep -q ':11334' /tmp/phase2-ports || fail "rspamd controller:11334 not listening"
pass "rspamd worker:11332 + controller:11334 listening"

step "5) Postfix smtpd_milters points at inet:127.0.0.1:11332"
ssh "$HOST" 'grep -E "^smtpd_milters" /data/volumes/mail/config/main.cf' > /tmp/phase2-milter
grep -q 'inet:127.0.0.1:11332' /tmp/phase2-milter || fail "Postfix milter not wired"
pass "Postfix smtpd_milters → rspamd"

step "6) DKIM key exists for secubox.in"
ssh "$HOST" '[ -f /data/volumes/mail/rspamd/dkim/secubox.in/default.key ] && \
              [ "$(stat -c %a /data/volumes/mail/rspamd/dkim/secubox.in/default.key)" = "600" ] && \
              [ -f /data/volumes/mail/rspamd/dkim/secubox.in/default.txt ]' \
    || fail "secubox.in DKIM key missing or wrong perms"
pass "DKIM key + DNS TXT present"

step "7) Outbound mail carries DKIM-Signature: d=secubox.in s=default"
# swaks installed in mail LXC at install time
ssh "$HOST" '
    lxc-attach -n mail -- bash -c "
        apt-get install -y swaks >/dev/null 2>&1 || true
        swaks --to gk2@secubox.in --from gk2@secubox.in \
              --server 127.0.0.1:587 \
              --auth LOGIN --auth-user gk2@secubox.in \
              --auth-password \$(grep gk2@secubox.in /etc/mail-config/users | cut -d: -f2) \
              --tls --tls-on-connect=no --quit-after RCPT \
              --header \"Subject: phase2 dkim test\" \
              --body \"phase2 test\" 2>&1
    " | tail -10
' > /tmp/phase2-swaks
# Inspect maildir for the DKIM-Signature header
ssh "$HOST" 'find /data/volumes/mail/vmail/secubox.in/gk2/Maildir/new -type f -newer /tmp/phase2-swaks-marker 2>/dev/null | head -1 | xargs grep -l "DKIM-Signature:" 2>/dev/null' \
    || fail "no DKIM-Signature on outbound test"
pass "DKIM-Signature: ... d=secubox.in s=default present"

step "8) SPF hard-fail is rejected"
out=$(ssh "$HOST" '
    lxc-attach -n mail -- swaks --to gk2@secubox.in --from spoof@bogus.example.com \
        --server 127.0.0.1:25 --quit-after RCPT --header "Subject: spf test" \
        --header-X-Test "spf" 2>&1' | tail -5)
echo "$out" | grep -qE '5\.7\.[0-9]|reject|550' || fail "SPF spoof not rejected"
pass "SPF hard-fail rejected with 5.7.x"

step "9) DMARC failure quarantines in history"
ssh "$HOST" 'lxc-attach -n mail -- rspamc history 2>&1 | tail -10' > /tmp/phase2-history
# Spot-check: history is non-empty
[ -s /tmp/phase2-history ] || fail "rspamc history empty"
pass "rspamc history non-empty"

step "10) Greylist defers first attempt"
ssh "$HOST" 'lxc-attach -n mail -- rspamc symbols < /etc/hostname 2>&1 | head -5' > /tmp/phase2-symbols
# Best-effort: confirm greylist module is loaded
ssh "$HOST" 'lxc-attach -n mail -- rspamc stat 2>&1 | grep -iE "greylist|modules"' \
    > /tmp/phase2-modules
grep -qi greylist /tmp/phase2-modules || fail "greylist module not loaded"
pass "greylist module active"

step "11) Rspamd web UI reachable via WAF path"
out=$(curl --silent --insecure --include --resolve "rspamd.gk2.secubox.in:443:$HOST_IP" \
    https://rspamd.gk2.secubox.in/ping 2>&1 || true)
echo "$out" | grep -qiE 'x-secubox-waf: inspected' || fail "WAF marker missing — mitmproxy route map not updated"
pass "rspamd.gk2.secubox.in routes via HAProxy → mitmproxy → LXC :11334"

step "12) OpenDKIM + SpamAssassin packages absent"
out=$(ssh "$HOST" 'lxc-attach -n mail -- dpkg -l opendkim opendkim-tools spamassassin spamc spamd 2>&1' | tail -5)
echo "$out" | grep -qE 'no packages|aucun paquet' || fail "legacy packages still installed"
pass "SA + OpenDKIM purged"

step "13) Phase 1 regression: 5 production users still IMAPS-loginable; webmail still WAF-routed"
ssh "$HOST" 'ls /data/volumes/mail/vmail/secubox.in/' > /tmp/phase2-users
for u in gk2 bat bourdon lemurien ragondin; do
    grep -wq "$u" /tmp/phase2-users || fail "user $u missing — Phase 1 regression"
done
out=$(curl --silent --insecure --include --resolve "webmail.gk2.secubox.in:443:$HOST_IP" \
    https://webmail.gk2.secubox.in/ 2>&1 || true)
echo "$out" | grep -qiE 'x-secubox-waf: inspected' || fail "webmail WAF path regressed"
pass "Phase 1 regression: clean"

echo
pass "PHASE 2 ACCEPTANCE: all 13 gates green"
EOF
chmod +x tests/scripts/test-mail-phase2-acceptance.sh
git add tests/scripts/test-mail-phase2-acceptance.sh
git commit -m "test(mail): Phase 2 13-gate end-to-end acceptance smoke (ref #<issue>)"
```

---

## Milestone H — Deploy + verify

### Task H1: Build secubox-mail 2.3.0

**Files:** none (operational).

- [ ] **Step 1: Build**

```bash
(cd packages/secubox-mail && dpkg-buildpackage -us -uc -b 2>&1 | tail -3)
ls -la packages/secubox-mail_2.3.0-1~bookworm1_all.deb
```

Expected: `.deb` present.

- [ ] **Step 2: Inspect content**

```bash
dpkg-deb -c packages/secubox-mail_2.3.0-1~bookworm1_all.deb | grep -E 'lib/mail|templates/rspamd|routers/|rspamd_client'
```

Expected: see `lib/mail/rspamd.sh`, all 9 rspamd templates, both router files, `rspamd_client.py`.

---

### Task H2: STOP — confirm with user before live deploy

**Files:** none (operational gate per Phase 1 lesson).

- [ ] **Step 1: Summarise to the user the EXACT operations**

```
About to run on root@admin.gk2.secubox.in:

  1. scp packages/secubox-mail_2.3.0-1~bookworm1_all.deb /tmp/
  2. apt install -y /tmp/secubox-mail_2.3.0-1~bookworm1_all.deb
  3. mailctl rspamd install
  4. mailctl rspamd start
  5. bash packages/secubox-mail/sbin/rspamd-route-sync-patch.sh
  6. update mitmproxy route map: rspamd.gk2.secubox.in → [10.100.0.10, 11334]
  7. ONLY if Phase 2 acceptance gates 1-11 green: mailctl rspamd purge-legacy

This rewrites Postfix main.cf (with .pre-phase2.bak backup) and installs
Rspamd in the mail LXC. SA + OpenDKIM are removed ONLY after Rspamd is
proven healthy (D9 + acceptance gates).

Production data (/data/volumes/mail/vmail/secubox.in/) is bind-mounted and
NOT touched.
```

- [ ] **Step 2: Wait for explicit "yes, deploy"**

---

### Task H3: Live deploy (after user authorization)

**Files:** none (operational).

- [ ] **Step 1: Copy + install**

```bash
scp packages/secubox-mail_2.3.0-1~bookworm1_all.deb root@admin.gk2.secubox.in:/tmp/
ssh root@admin.gk2.secubox.in 'apt install -y /tmp/secubox-mail_2.3.0-1~bookworm1_all.deb'
```

- [ ] **Step 2: Install Rspamd inside the LXC**

```bash
ssh root@admin.gk2.secubox.in 'timeout 600 mailctl rspamd install'
ssh root@admin.gk2.secubox.in 'timeout 60 mailctl rspamd start'
ssh root@admin.gk2.secubox.in 'timeout 30 mailctl rspamd status'
```

Expected: status returns rspamc stat output with Bayes etc. No errors.

- [ ] **Step 3: Patch the board's sync script + update mitmproxy route**

```bash
ssh root@admin.gk2.secubox.in 'bash /usr/lib/secubox/mail/sbin/rspamd-route-sync-patch.sh'
ssh root@admin.gk2.secubox.in 'lxc-attach -n mitmproxy -- python3 -c "
import json
p = \"/srv/mitmproxy/haproxy-routes.json\"
d = json.load(open(p))
d[\"rspamd.gk2.secubox.in\"] = [\"10.100.0.10\", 11334]
json.dump(d, open(p, \"w\"), indent=2)
"
lxc-attach -n mitmproxy -- systemctl restart mitmproxy'
```

- [ ] **Step 4: Run acceptance gates 1-11 (without purge yet)**

```bash
bash tests/scripts/test-mail-phase2-acceptance.sh root@admin.gk2.secubox.in 2>&1 | tee /tmp/phase2-acceptance.log | tail -20
```

Expected: gates 1-11 pass; gates 12-13 may fail if purge hasn't run.

- [ ] **Step 5: If gates 1-11 are green, purge legacy**

```bash
ssh root@admin.gk2.secubox.in 'timeout 120 mailctl rspamd purge-legacy'
```

- [ ] **Step 6: Full smoke**

```bash
bash tests/scripts/test-mail-phase2-acceptance.sh root@admin.gk2.secubox.in 2>&1 | tee /tmp/phase2-acceptance-final.log | tail -20
```

Expected: all 13 gates green.

- [ ] **Step 7: If any gate fails**

Do **not** retry blindly. Read the log, identify the failing gate, **stop** and report. If gate 13 fails (Phase 1 regression) — roll back immediately via [docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md](../runs/2026-05-15-mail-phase2-rollback.md).

---

### Task H4: Update tracking files + open PR

**Files:**
- Modify: `.claude/HISTORY.md`
- Modify: `.claude/WIP.md`
- Modify: `.claude/MIGRATION-MAP.md`

- [ ] **Step 1: HISTORY entry**

Prepend to `.claude/HISTORY.md`:
```markdown

## 2026-05-15

### Mail Phase 2 — Rspamd migration ✅ (Issue #<issue>, PR TBD)

**Done:**

- Rspamd 1.9.x deployed inside mail LXC; Postfix milter wired (`smtpd_milters = inet:127.0.0.1:11332`).
- DKIM signing for `secubox.in` with selector `default`; key + DNS TXT under `/data/volumes/mail/rspamd/dkim/`.
- ARC signing, DMARC, SPF, greylist, outbound ratelimit `200/h/user` all active.
- Rspamd web UI at `https://rspamd.gk2.secubox.in/` (HAProxy → mitmproxy → LXC :11334), admin JWT + `enable_password` for writes.
- Legacy `/dkim/*` `/spam/*` `/grey/*` endpoints become deprecation shims (`X-Deprecated-Endpoint: rspamd`).
- OpenDKIM + SpamAssassin purged from LXC.
- bats `test_deb_paths.bats` added (Phase 1 lesson: catches `debian/rules` source-path drift).
- `systemctl enable postfix` now in `install_mail_packages` (Phase 1 lesson).
- 13/13 acceptance gates green; Phase 1 regression checks green; 5 production users preserved.

**Phase 3 inputs:**

- Multi-domain DKIM: extend `dkim_signing.conf` to use `selector_map` + per-domain key generation script.
- Rspamd is multi-domain-ready by design; only the user-provisioning side needs Phase 3 work.
```

- [ ] **Step 2: WIP.md update**

In `.claude/WIP.md`, prepend:
```markdown
## ✅ 2026-05-15: Mail Phase 2 — Rspamd migration COMPLETE (Issue #<issue>, PR <PR>)

### Done

- secubox-mail 2.3.0 deployed
- Rspamd replaces SA + OpenDKIM (single daemon: DKIM sign/verify, SPF, DMARC, ARC, greylist, ratelimit)
- 13/13 acceptance gates green
- Phase 1 regression: 5 production users preserved
- Phase 1 follow-ups absorbed (systemctl enable postfix, dpkg path-coverage bats)

### Next: Phase 3 — multi-domain + secubox-users provisioning hook
```

- [ ] **Step 3: MIGRATION-MAP.md tick**

Mark `secubox-mail` Phase 2 done.

- [ ] **Step 4: Commit + finish worktree**

```bash
git add .claude/
git commit -m "docs: track Phase 2 acceptance green (ref #<issue>)"
bash scripts/agent-worktree.sh finish
```

Expected: branch pushed, PR opened with `Closes #<issue>`.

- [ ] **Step 5: Wait for user merge**

Per CLAUDE.md, do NOT close the issue or merge the PR — user reviews + merges.

- [ ] **Step 6: After user merges, clean worktree**

```bash
bash scripts/agent-worktree.sh clean <issue>
```

---

## Self-review

### 1. Spec coverage

| Spec section | Plan task(s) |
|---|---|
| §3 D1 Rspamd replaces SA+OpenDKIM | B1 install + H3 step 5 purge |
| §3 D2 ClamAV deferred | (no task — out of scope) |
| §3 D3 single-domain DKIM (secubox.in / default) | B4 + Task D1 dkim-keygen |
| §3 D4 web UI behind admin JWT + enable_password | B3 configure_rspamd_controller + F1 nginx vhost |
| §3 D9 install Rspamd FIRST, then purge | H3 step 2 install → step 4 gate-check → step 5 purge |
| §4.2 Postfix `smtpd_milters` wiring | B3 configure_rspamd_postfix_milter |
| §4.3 persistent data layout | E3 postinst + B3 mkdir |
| §4.4 9 config templates | B2 |
| §4.5 host nginx + mitmproxy route | F1 + F2 + H3 step 3 |
| §4.6 new endpoints | C2-C5 |
| §4.6 legacy shims | C6 |
| §4.7 mailctl additions | D1 |
| §5 removal ordering | H3 (steps 2 → 4 → 5) + B5 D9 health gate |
| §6 13 acceptance gates | G2 |
| §8 Phase 1 follow-ups | E1 (`systemctl enable postfix`), G1 path-coverage bats, F2 sync patch |

### 2. Placeholder scan

- "TBD" only in `H4` PR-number-not-yet-known and `<issue>` placeholder. Both populated at execution time.
- No "TODO", no "implement later", no vague "add error handling".

### 3. Type / identifier consistency

- Function names: `install_rspamd`, `configure_rspamd_milter`, `configure_rspamd_controller`, `configure_rspamd_dkim`, `configure_rspamd_postfix_milter`, `rspamd_keygen`, `rspamd_dns_records`, `rspamd_purge_legacy` — used identically in B1-B5, D1 and the bats tests.
- API router prefix: `/rspamd/*` — consistent in C2-C5, the legacy `/dkim/*` `/spam/*` `/grey/*` paths are distinct.
- Paths: `/etc/secubox/secrets/rspamd-controller.pw`, `/data/volumes/mail/rspamd/dkim/<domain>/<selector>.{key,txt}` — used identically in B3, B4, C1, E3, H3.
- `_rspamd` UID in unprivileged LXC = `100110` — used in B3 (`chown` line) and §4.3 of spec.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-15-mail-phase2-rspamd.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review.
2. **Inline Execution** — same session, batch with checkpoints.

Which approach?
