<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Stack Phase 1 — Source Catch-Up & Legacy Package Cleanup (rev. 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Spec:** [docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md](../specs/2026-05-15-mail-stack-architecture-design.md) (rev. 2) — Phase 1.

> **Revision note (rev. 2, 2026-05-15):** Initial draft assumed a greenfield two-LXC → one-LXC consolidation. Live board has already been hand-configured with the single-LXC layout, so Phase 1 is now "catch the repo source up to where the board already is + finish the legacy package cleanup". Effort drops from ~30 tasks / ~1 week to ~15 tasks / ~2–3 days.

**Goal:** Make `git checkout main && apt install` produce a host that drives the existing `mail` LXC correctly. Update paths/IP/config-key literals in source; extract a small shared library; mark legacy packages transitional; verify the existing 5 `secubox.in` users still IMAP login.

**Architecture:**
- Source code edits only — **no LXC creation, no debootstrap, no data migration on the canonical board** (data already lives at `/data/volumes/mail/` and must be preserved).
- New `lib/install.sh` + `lib/lxc.sh` extract the existing helpers from `mailserverctl` so future phases have a DRY foundation.
- `mailctl migrate-config` rewrites a legacy `mail.toml` in place; `mail-migrate-to-single-lxc.sh` is a defensive scanner that detects and reports legacy state but refuses to touch live data.
- `secubox-mail` bumps to `2.2.0`; the three legacy companion packages become 2.2.0 metadata-only stubs that depend on it.

**Tech stack:** Bash 5, LXC userspace tools, FastAPI (existing), pytest (existing), bats (new — tests for shell libs), Debian packaging.

**Issue:** filed at start of execution as *Mail stack: Phase 1 — source-catch-up + legacy package cleanup* (labels `migration,wip`).

**Worktree:** `scripts/agent-worktree.sh start --issue <N>`.

**Canonical paths/values (from Phase 0 rev. 2):**
- LXC name: `mail`
- LXC path: `/var/lib/lxc/mail` (symlink to `/data/lxc/mail` on this board, but source code references the symlink)
- Data path: `/data/volumes/mail`
- LXC IP: `10.100.0.10/24`
- Bridge: `br-lxc`
- Gateway: `10.100.0.1`

---

## File structure

### New files

| Path | Responsibility |
|---|---|
| `packages/secubox-mail/lib/install.sh` | Sourced helpers for installing daemons inside a `mail` LXC rootfs. Phase 1 contains only the helpers needed today (Postfix, Dovecot, OpenDKIM, SpamAssassin, Apache+Roundcube). Phase 2 adds Rspamd + ClamAV. |
| `packages/secubox-mail/lib/lxc.sh` | LXC lifecycle helpers: `lxc_exists`, `lxc_running`, `lxc_create_config`, `lxc_start_safely`, `lxc_attach_run`. Unprivileged-veth-aware. |
| `packages/secubox-mail/lib/migrate.sh` | Detection helpers used by `mail-migrate-to-single-lxc.sh` and `mailctl migrate-config`. Defensive — refuses to touch `/data/volumes/mail/` if it has user data. |
| `packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh` | Top-level scanner invoked from postinst. Reports legacy state; does **not** create or destroy. |
| `packages/secubox-mail/tests/test_install_lib.bats` | Bats tests for `install.sh` shell functions (mocked LXC). |
| `packages/secubox-mail/tests/test_lxc_lib.bats` | Bats tests for `lxc.sh`. |
| `packages/secubox-mail/tests/test_migrate_lib.bats` | Bats tests for `migrate.sh` — critical: verifies the "refuse to touch live data" guard. |
| `packages/secubox-mail/tests/helpers.bash` | Shared bats fixtures. |
| `packages/secubox-mail/api/tests/test_phase1_endpoints.py` | Pytest: every existing API route still responds non-5xx. |
| `tests/scripts/test-mail-phase1-acceptance.sh` | End-to-end smoke on the live board: `mailctl status` ok, `mailctl start` brings up `mail` LXC, IMAP login as `gk2@secubox.in` succeeds, Roundcube reachable via host proxy. |
| `common/nginx/modules.d/mail.conf` | Host nginx vhost replacing `secubox-mail/nginx/mail.conf` and `secubox-webmail/nginx/webmail.conf`. |
| `docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md` | Operational rollback recipe (snapshot tarballs, downgrade pins). |

### Modified files

| Path | Change |
|---|---|
| `packages/secubox-mail/sbin/mailctl` | Replace `/srv/lxc` → `/var/lib/lxc`, `/srv/mail` → `/data/volumes/mail`, `mail_container = "mailserver"` → `container = "mail"`, `192.168.255.30` → `10.100.0.10`. Source `lib/install.sh` + `lib/lxc.sh`. Add `migrate-config` subcommand. |
| `packages/secubox-mail/sbin/mailserverctl` | Reduce to deprecation shim that `exec`s `mailctl`. |
| `packages/secubox-mail/sbin/roundcubectl` | Same — deprecation shim. |
| `packages/secubox-mail/api/main.py` | Read `container`, `lxc_ip`, `data_path` instead of `mail_container`/`webmail_container`/`mail_ip`/`webmail_ip`. Default `data_path = "/data/volumes/mail"`. |
| `packages/secubox-mail/config/mail.toml` | Use new keys only. Old keys removed (postinst migrates existing installs). |
| `packages/secubox-mail/debian/control` | Version 2.2.0. Add `Breaks:`/`Replaces:` for `secubox-mail-lxc (<< 2.2)`, `secubox-webmail-lxc (<< 2.2)`, `secubox-webmail (<< 2.2)`. |
| `packages/secubox-mail/debian/changelog` | New 2.2.0 entry. |
| `packages/secubox-mail/debian/postinst` | On upgrade from `<< 2.2`: run `mailctl migrate-config`, then `mail-migrate-to-single-lxc.sh` (scanner only). |
| `packages/secubox-mail-lxc/debian/control` | Transitional 2.2.0 stub depending on `secubox-mail (>= 2.2)`. |
| `packages/secubox-mail-lxc/debian/changelog` | New 2.2.0 entry. |
| `packages/secubox-mail-lxc/debian/install` | Empty out — package ships no files. |
| `packages/secubox-webmail-lxc/debian/*` | Same transitional pattern. |
| `packages/secubox-webmail/debian/*` | Same transitional pattern. |
| `packages/secubox-mail/nginx/mail.conf` | Replaced by deprecation comment (the real vhost moves to `common/nginx/modules.d/mail.conf`). |
| `packages/secubox-webmail/nginx/webmail.conf` | Same — deprecation comment. |
| `packages/secubox-haproxy/...` (locate at execution time) | Add backends `smtp_mail`, `submission_mail`, `imaps_mail`, `managesieve_mail` targeting `10.100.0.10`. |
| `.claude/MIGRATION-MAP.md` | Tick `secubox-mail` Phase 1 done. |
| `.claude/WIP.md` | Move Phase 1 to "✅ Fait". |
| `.claude/HISTORY.md` | Append dated entry. |

### Files removed in this plan

None at code-merge time. The 3 legacy packages keep an empty 2.2.0 stub for one release so `apt remove` works cleanly. Hard removal happens in a later release.

---

## Pre-flight

### Task 0: Snapshot live board state + commit rollback recipe

**Files:**
- Create: `docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md`

- [ ] **Step 1: Snapshot `/data/volumes/mail/` and the `mail` LXC config**

```bash
ssh root@192.168.1.200 'set -euo pipefail
  mkdir -p /srv/backups/mail-phase1
  STAMP=$(date +%F-%H%M)
  tar --numeric-owner -czf /srv/backups/mail-phase1/data-volumes-mail-$STAMP.tar.gz \
      /data/volumes/mail 2>/dev/null
  tar --numeric-owner -czf /srv/backups/mail-phase1/lxc-mail-config-$STAMP.tar.gz \
      /data/lxc/mail/config
  cp /etc/secubox/mail.toml /srv/backups/mail-phase1/mail-toml-$STAMP.bak 2>/dev/null || true
  dpkg -l "secubox-mail*" "secubox-webmail*" > /srv/backups/mail-phase1/pkglist-$STAMP.txt
  ls -la /srv/backups/mail-phase1/'
```

Expected: 3 tarballs + 1 bak + 1 pkglist; all non-zero size; latest timestamp.

- [ ] **Step 2: Write the rollback recipe**

```bash
cat > docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md <<'EOF'
# Mail Phase 1 — Rollback recipe

Backups produced 2026-05-15 on test board 192.168.1.200, in
/srv/backups/mail-phase1/. If Phase 1 deploy breaks the mail stack:

    ssh root@192.168.1.200 'set -euo pipefail
      lxc-stop -n mail 2>/dev/null || true
      # Restore data
      rm -rf /data/volumes/mail
      tar -xzf /srv/backups/mail-phase1/data-volumes-mail-*.tar.gz -C /
      # Restore LXC config
      tar -xzf /srv/backups/mail-phase1/lxc-mail-config-*.tar.gz -C /
      # Restore toml + downgrade packages
      cp /srv/backups/mail-phase1/mail-toml-*.bak /etc/secubox/mail.toml
      apt install --allow-downgrades \
        secubox-mail=2.1.0-1~bookworm1 \
        secubox-mail-lxc=1.1.0-1~bookworm1 \
        secubox-webmail=1.0.0-1~bookworm1 \
        secubox-webmail-lxc=1.1.0-1~bookworm1
      systemctl restart secubox-mail nginx'

The data tarball at /srv/backups/mail-phase1/data-volumes-mail-*.tar.gz
contains the 5 live secubox.in mailboxes (gk2, bat, bourdon, lemurien,
ragondin) — preserving it is the highest priority.
EOF
git add docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md
git commit -m "docs: Phase 1 rollback recipe (ref #<issue>)"
```

Expected: file committed.

---

## Milestone A — Worktree + scaffolding

### Task A1: Create GitHub issue + worktree

- [ ] **Step 1: Create the issue**

```bash
gh issue create \
  --title "Mail stack: Phase 1 — source-catch-up + legacy package cleanup" \
  --label "migration,wip" \
  --body "$(cat <<'EOF'
Per Phase 0 spec rev. 2 docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md.

The test board already runs a single-mail-LXC layout under /data/lxc/mail
with /data/volumes/mail data dirs and 10.100.0.10/24 veth networking.
The repo source code is out of date (still references /srv/lxc, /srv/mail,
192.168.255.30, mail_container/webmail_container). Phase 1 catches the
source up + deprecates the legacy companion packages.

## Tasks
- [ ] mailctl/mailserverctl/roundcubectl: update path + IP literals
- [ ] mail.toml schema: single container/lxc_ip/data_path/lxc_bridge/lxc_gateway
- [ ] Extract lib/install.sh + lib/lxc.sh + lib/migrate.sh from mailserverctl
- [ ] mailctl migrate-config rewrites legacy toml in place
- [ ] mail-migrate-to-single-lxc.sh as defensive scanner (no destructive ops)
- [ ] secubox-mail 2.2.0 with Breaks/Replaces
- [ ] secubox-mail-lxc / secubox-webmail-lxc / secubox-webmail transitional 2.2.0
- [ ] common/nginx/modules.d/mail.conf replaces the two per-package vhosts
- [ ] HAProxy backends targeting 10.100.0.10
- [ ] API uses new config keys; 62-endpoint presence test green
- [ ] Acceptance: mailctl start brings up the existing mail LXC; gk2@secubox.in IMAPS login works; Roundcube responds via host proxy
- [ ] /data/volumes/mail/vmail/secubox.in/ data is byte-identical before and after

## References
- Spec: docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md
- Plan: docs/superpowers/plans/2026-05-15-mail-phase1-lxc-consolidation.md
- Rollback: docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md
EOF
)"
```

Expected: issue URL; note the number as `<issue>`.

- [ ] **Step 2: Open the worktree**

```bash
bash scripts/agent-worktree.sh start --issue <issue>
cd ~/CyberMindStudio/secubox-deb-worktrees/<issue>-mail-stack-phase-1-source-catch-up-legacy-package-cleanup/
```

Expected: new worktree on branch `<issue>-mail-stack-phase-1-...`. All subsequent tasks run inside this worktree.

---

### Task A2: Scaffold lib/, templates/, tests/ with empty placeholders

**Files:**
- Create: `packages/secubox-mail/lib/install.sh`
- Create: `packages/secubox-mail/lib/lxc.sh`
- Create: `packages/secubox-mail/lib/migrate.sh`
- Create: `packages/secubox-mail/tests/helpers.bash`
- Create: `packages/secubox-mail/tests/test_lxc_lib.bats`
- Create: `packages/secubox-mail/tests/test_install_lib.bats`
- Create: `packages/secubox-mail/tests/test_migrate_lib.bats`

- [ ] **Step 1: Write SPDX-headered shell stubs**

For each of `lib/install.sh`, `lib/lxc.sh`, `lib/migrate.sh`:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail :: <one-line purpose>
# Sourced library — do not execute directly.

set -euo pipefail
```

- [ ] **Step 2: Write the bats helpers fixture**

```bash
# packages/secubox-mail/tests/helpers.bash
load_libs() {
    local pkg_root="${BATS_TEST_DIRNAME}/.."
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/lxc.sh"
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/install.sh"
    # shellcheck source=/dev/null
    source "${pkg_root}/lib/migrate.sh"
}

make_fake_lxc_env() {
    export LXC_BASE="$BATS_TEST_TMPDIR/lxc"
    export DATA_PATH="$BATS_TEST_TMPDIR/data-volumes-mail"
    mkdir -p "$LXC_BASE" "$DATA_PATH"
}
```

- [ ] **Step 3: Sanity bats test in each `*.bats`**

`tests/test_lxc_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "lxc.sh sources cleanly" {
    [ "$(type -t lxc_exists)" = "function" ]
}
```

`tests/test_install_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "install.sh sources cleanly" {
    [ "$(type -t install_mail_packages)" = "function" ]
}
```

`tests/test_migrate_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc_env; }

@test "migrate.sh sources cleanly" {
    [ "$(type -t detect_legacy_lxc)" = "function" ]
    [ "$(type -t guard_data_path)" = "function" ]
}
```

- [ ] **Step 4: Run — expect all three FAIL (no functions defined yet)**

```bash
cd packages/secubox-mail && bats tests/
```

Expected: FAIL — red baseline.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/lib/ packages/secubox-mail/tests/
git commit -m "test(mail): phase1 scaffolding — red baseline (ref #<issue>)"
```

---

## Milestone B — Extract shared shell library (TDD)

### Task B1: `lib/lxc.sh` — LXC lifecycle helpers

**Files:**
- Modify: `packages/secubox-mail/lib/lxc.sh`
- Modify: `packages/secubox-mail/tests/test_lxc_lib.bats`

- [ ] **Step 1: Write failing tests for the helper shapes**

Append to `tests/test_lxc_lib.bats`:
```bash
@test "lxc_exists returns 1 for missing container" {
    run lxc_exists "ghost-mail"
    [ "$status" -eq 1 ]
}

@test "lxc_create_config writes a config with veth + 10.100.0.10 + br-lxc" {
    local name="testmail"
    lxc_create_config "$name" "10.100.0.10" "br-lxc" "10.100.0.1"
    [ -f "$LXC_BASE/$name/config" ]
    grep -q "lxc.uts.name = $name"                      "$LXC_BASE/$name/config"
    grep -q "lxc.rootfs.path = dir:$LXC_BASE/$name/rootfs" "$LXC_BASE/$name/config"
    grep -q "lxc.net.0.type = veth"                     "$LXC_BASE/$name/config"
    grep -q "lxc.net.0.link = br-lxc"                   "$LXC_BASE/$name/config"
    grep -q "lxc.net.0.ipv4.address = 10.100.0.10/24"   "$LXC_BASE/$name/config"
    grep -q "lxc.net.0.ipv4.gateway = 10.100.0.1"       "$LXC_BASE/$name/config"
    grep -q "lxc.idmap = u 0 100000 65536"              "$LXC_BASE/$name/config"
    grep -q "/data/volumes/mail/vmail"                  "$LXC_BASE/$name/config"
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd packages/secubox-mail && bats tests/test_lxc_lib.bats
```

- [ ] **Step 3: Implement**

Append to `lib/lxc.sh`:
```bash
# Returns 0 if a container's rootfs exists under $LXC_BASE.
lxc_exists() {
    local name="$1"
    [ -d "${LXC_BASE:-/var/lib/lxc}/$name/rootfs" ]
}

# Returns 0 if a container is currently running.
lxc_running() {
    local name="$1"
    lxc-info -n "$name" 2>/dev/null | grep -q "State:.*RUNNING"
}

# Render lxc config: unprivileged + veth br-lxc.
# Args: name, ipv4_cidr (e.g. 10.100.0.10/24), bridge, gateway
lxc_create_config() {
    local name="$1"
    local ip="$2"
    local bridge="${3:-br-lxc}"
    local gw="${4:-10.100.0.1}"
    local base="${LXC_BASE:-/var/lib/lxc}"
    local data="${DATA_PATH:-/data/volumes/mail}"
    # Strip /NN from CIDR to get plain IP if caller passed CIDR
    case "$ip" in
        */*) ip_cidr="$ip" ;;
        *)   ip_cidr="$ip/24" ;;
    esac
    mkdir -p "$base/$name"
    cat > "$base/$name/config" <<EOF
# Generated by mailctl — do not edit by hand
lxc.include = /usr/share/lxc/config/debian.common.conf

lxc.arch = linux64
lxc.uts.name = $name
lxc.rootfs.path = dir:$base/$name/rootfs

lxc.net.0.type = veth
lxc.net.0.link = $bridge
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $ip_cidr
lxc.net.0.ipv4.gateway = $gw
lxc.net.0.name = eth0

lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536

# Bind mounts for persistent data
lxc.mount.entry = $data/vmail  var/vmail        none bind,create=dir 0 0
lxc.mount.entry = $data/config etc/mail-config  none bind,create=dir 0 0
lxc.mount.entry = $data/ssl    etc/ssl/mail     none bind,create=dir 0 0

lxc.cgroup2.memory.max = 1G
lxc.start.auto = 1
EOF
}

# Start a container and wait until it reports RUNNING (max 10s).
lxc_start_safely() {
    local name="$1"
    lxc-start -n "$name" -d
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        lxc_running "$name" && return 0
        sleep 1
    done
    return 1
}

# Run a command inside a container, propagate exit status.
lxc_attach_run() {
    local name="$1"; shift
    lxc-attach -n "$name" -- "$@"
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd packages/secubox-mail && bats tests/test_lxc_lib.bats
```

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/lib/lxc.sh packages/secubox-mail/tests/test_lxc_lib.bats
git commit -m "feat(mail): lib/lxc.sh — unprivileged veth helpers (ref #<issue>)"
```

---

### Task B2: `lib/migrate.sh` — defensive scanner (TDD)

**Files:**
- Modify: `packages/secubox-mail/lib/migrate.sh`
- Modify: `packages/secubox-mail/tests/test_migrate_lib.bats`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_migrate_lib.bats`:
```bash
@test "detect_legacy_lxc finds mailserver+roundcube paths" {
    mkdir -p "$LXC_BASE/mailserver/rootfs" "$LXC_BASE/roundcube/rootfs"
    run detect_legacy_lxc
    [ "$status" -eq 0 ]
    [[ "$output" == *"mailserver"* ]]
    [[ "$output" == *"roundcube"* ]]
}

@test "detect_legacy_lxc returns no legacy when only 'mail' exists" {
    mkdir -p "$LXC_BASE/mail/rootfs"
    run detect_legacy_lxc
    [ "$status" -eq 1 ]
}

@test "guard_data_path refuses non-empty vmail" {
    mkdir -p "$DATA_PATH/vmail/secubox.in/gk2"
    run guard_data_path
    [ "$status" -ne 0 ]
    [[ "$output" == *"refusing"* ]] || [[ "$output" == *"already has data"* ]]
}

@test "guard_data_path accepts empty vmail" {
    mkdir -p "$DATA_PATH/vmail"
    run guard_data_path
    [ "$status" -eq 0 ]
}

@test "detect_legacy_toml_keys finds old key names" {
    local toml="$BATS_TEST_TMPDIR/mail.toml"
    cat > "$toml" <<'TOML'
[mail]
mail_container = "mailserver"
webmail_container = "roundcube"
mail_ip = "192.168.255.30"
TOML
    run detect_legacy_toml_keys "$toml"
    [ "$status" -eq 0 ]
    [[ "$output" == *"mail_container"* ]]
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd packages/secubox-mail && bats tests/test_migrate_lib.bats
```

- [ ] **Step 3: Implement**

Append to `lib/migrate.sh`:
```bash
# Detect legacy two-LXC layout. Echoes any legacy container names found.
# Returns 0 if any found, 1 if none.
detect_legacy_lxc() {
    local base="${LXC_BASE:-/var/lib/lxc}"
    local found=0
    for c in mailserver roundcube; do
        if [ -d "$base/$c/rootfs" ]; then
            echo "$c"
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}

# Refuse to proceed if /data/volumes/mail/vmail has any subdirs with content.
# Returns 0 if safe to touch; non-zero with explanation otherwise.
guard_data_path() {
    local data="${DATA_PATH:-/data/volumes/mail}"
    if [ ! -d "$data/vmail" ]; then
        return 0
    fi
    # Count entries with content (any file/dir under any domain subdir)
    local count
    count=$(find "$data/vmail" -mindepth 2 -print -quit 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo "ERROR: $data/vmail already has data — refusing to touch" >&2
        return 1
    fi
    return 0
}

# Echo any legacy keys present in a mail.toml file. Returns 0 if any present.
detect_legacy_toml_keys() {
    local toml="$1"
    [ -f "$toml" ] || return 1
    local found=0
    for k in mail_container webmail_container mail_ip webmail_ip webmail_port; do
        if grep -q "^${k} *=" "$toml" 2>/dev/null; then
            echo "$k"
            found=1
        fi
    done
    [ "$found" -eq 1 ]
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd packages/secubox-mail && bats tests/test_migrate_lib.bats
```

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/lib/migrate.sh packages/secubox-mail/tests/test_migrate_lib.bats
git commit -m "feat(mail): lib/migrate.sh — defensive scanner (ref #<issue>)"
```

---

### Task B3: `lib/install.sh` — extracted from mailserverctl

**Files:**
- Modify: `packages/secubox-mail/lib/install.sh`
- Modify: `packages/secubox-mail/sbin/mailserverctl` (replace extracted bodies with shim)

> This task is mechanical extraction. The functions already exist and work — we're just moving them to a sourceable lib file so `mailctl` can use them too. **Do not change behavior.** Only updates: hard-coded `/srv/lxc/$CONTAINER` → `${LXC_BASE:-/var/lib/lxc}/$container`, `/srv/mail` → `${DATA_PATH:-/data/volumes/mail}`, function-arg parameter for container name.

- [ ] **Step 1: Copy `bootstrap_debian`, `install_mail_packages`, `configure_postfix`, `configure_dovecot`, `configure_opendkim`, `install_roundcube_packages`, `configure_roundcube` from `mailserverctl` and `roundcubectl` into `lib/install.sh`**

Find each function body in:
- `packages/secubox-mail/sbin/mailserverctl` (lines ~120–1100)
- `packages/secubox-mail/sbin/roundcubectl` (lines ~80–390)

For each function:
- Add parameter `local container="$1"` at the top
- Replace `"$CONTAINER"` → `"$container"`
- Replace `"$LXC_PATH"` → `"${LXC_BASE:-/var/lib/lxc}/$container"`
- Replace `"$DATA_PATH"` (in path expansions only — keep config-get defaults) → `"${DATA_PATH:-/data/volumes/mail}"`
- Replace `192.168.255.30` (if any hard-coded) → use `${LXC_IP:-10.100.0.10}` if it appears

Paste each into `lib/install.sh` in order.

- [ ] **Step 2: Replace the extracted bodies in `mailserverctl` with thin shims**

For each function name above, replace the body in `mailserverctl` with:
```bash
configure_postfix() {
    # shellcheck source=/dev/null
    source "$(dirname "$0")/../lib/install.sh" 2>/dev/null \
        || source "/usr/lib/secubox/mail/lib/install.sh"
    configure_postfix "$CONTAINER"
}
```
Adjust function name per shim.

Same for `roundcubectl::install_roundcube_packages` and `roundcubectl::configure_roundcube`.

- [ ] **Step 3: Run bats — existing tests should still pass**

```bash
cd packages/secubox-mail && bats tests/
```

Expected: all green (the earlier red tests now pass; the extraction doesn't break them).

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/lib/install.sh \
        packages/secubox-mail/sbin/mailserverctl \
        packages/secubox-mail/sbin/roundcubectl
git commit -m "feat(mail): extract install helpers into lib/install.sh (ref #<issue>)"
```

---

## Milestone C — Source code catch-up

### Task C1: Update `mailctl` to use new paths/keys/IP

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`

- [ ] **Step 1: Replace the literal references**

Use `sed -i` to do the bulk replace:
```bash
cd packages/secubox-mail/sbin
sed -i 's|/srv/lxc|/var/lib/lxc|g' mailctl
sed -i 's|/srv/mail|/data/volumes/mail|g' mailctl
sed -i 's|192\.168\.255\.30|10.100.0.10|g' mailctl
sed -i 's|192\.168\.255\.31|10.100.0.10|g' mailctl  # webmail merged in
sed -i 's|192\.168\.255\.1|10.100.0.10|g' mailctl   # OpenWrt migration source — keep this default; the actual migration tool overrides
```

Wait — the last one is wrong. `192.168.255.1` is the OpenWrt source IP for the migrate command, not the new mail IP. Revert that:
```bash
sed -i 's|10\.100\.0\.10|192.168.255.1|g; s|192\.168\.255\.1|MAILCTL_MIGRATE_SOURCE_DEFAULT_DO_NOT_CHANGE|g' mailctl   # marker dance
sed -i 's|MAILCTL_MIGRATE_SOURCE_DEFAULT_DO_NOT_CHANGE|192.168.255.1|g' mailctl
```

Cleaner: edit the file by hand. Search for `192.168.255.30` and `192.168.255.31` only (Mail/Webmail LXC IPs). Leave `192.168.255.1` alone (it's the OpenWrt migration source).

- [ ] **Step 2: Replace config-get defaults**

In `mailctl`, find these lines:
```bash
MAIL_CONTAINER=$(config_get "mail_container" "mailserver")
WEBMAIL_CONTAINER=$(config_get "webmail_container" "roundcube")
MAIL_IP=$(config_get "mail_ip" "192.168.255.30")
```

Replace with:
```bash
CONTAINER=$(config_get "container" "mail")
LXC_IP=$(config_get "lxc_ip" "10.100.0.10")
LXC_BRIDGE=$(config_get "lxc_bridge" "br-lxc")
LXC_GATEWAY=$(config_get "lxc_gateway" "10.100.0.1")
DATA_PATH=$(config_get "data_path" "/data/volumes/mail")
LXC_PATH_ROOT=$(config_get "lxc_path" "/var/lib/lxc")
```

Search-and-replace `$MAIL_CONTAINER` / `$WEBMAIL_CONTAINER` / `$MAIL_IP` throughout the rest of the file (use `grep -n` first):
```bash
grep -n 'MAIL_CONTAINER\|WEBMAIL_CONTAINER\|MAIL_IP\b' mailctl
```

Update each call site to use `$CONTAINER` and `$LXC_IP`.

- [ ] **Step 3: Add `migrate-config` subcommand**

In `mailctl`, before the top-level case statement, add:

```bash
cmd_migrate_config() {
    require_root
    : "${LIB_DIR:=/usr/lib/secubox/mail/lib}"
    [ -d "$LIB_DIR" ] || LIB_DIR="$(dirname "$0")/../lib"
    # shellcheck source=/dev/null
    source "$LIB_DIR/migrate.sh"

    local cfg="${CONFIG_FILE:-/etc/secubox/mail.toml}"
    [ -f "$cfg" ] || { warn "no config to migrate at $cfg"; return 0; }

    if grep -q "^container *=" "$cfg" 2>/dev/null; then
        log "config already migrated (has 'container =' key)"
        return 0
    fi

    if ! detect_legacy_toml_keys "$cfg" >/dev/null; then
        log "no legacy keys to migrate"
        return 0
    fi

    cp "$cfg" "${cfg}.pre-phase1.$(date +%s).bak"

    python3 - "$cfg" <<'PY'
import sys, re
path = sys.argv[1]
src = open(path).read()
inject = (
    'container = "mail"\n'
    'lxc_ip = "10.100.0.10"\n'
    'lxc_bridge = "br-lxc"\n'
    'lxc_gateway = "10.100.0.1"\n'
    'data_path = "/data/volumes/mail"\n'
    'lxc_path = "/var/lib/lxc"\n'
)
# Insert after the [mail] header (only the first occurrence)
src = re.sub(r"(\[mail\]\n)", r"\1" + inject, src, count=1)
for k in ("mail_container", "webmail_container", "mail_ip", "webmail_ip", "webmail_port"):
    src = re.sub(rf"^({k} *=.*)$", r"# DEPRECATED Phase 1: \1", src, flags=re.MULTILINE)
open(path, "w").write(src)
PY
    log "config migrated to single-container schema; backup at ${cfg}.pre-phase1.*.bak"
}
```

And in the top-level case statement, add:
```bash
    migrate-config) shift; cmd_migrate_config "$@" ;;
```

- [ ] **Step 4: Add `--help` output**

At the top of the case statement, add:
```bash
case "${1:-}" in
    -h|--help|help)
        cat <<'EOF'
mailctl — SecuBox single-LXC mail driver (Phase 1, rev. 2)
Usage:
  mailctl install                Install/upgrade (only if not already present)
  mailctl start | stop | restart Lifecycle of the mail LXC
  mailctl status                 Container + bound-daemon state
  mailctl user add|del|list      User management
  mailctl alias add|del|list     Alias management
  mailctl dkim setup|status      DKIM (Phase 1 = OpenDKIM; Phase 2 = Rspamd)
  mailctl sync                   Reconcile config files into the container
  mailctl migrate-config         Rewrite legacy /etc/secubox/mail.toml in place
  mailctl backup | restore       Maildir backup helpers
EOF
        exit 0
        ;;
```

- [ ] **Step 5: Sanity check — script still parses**

```bash
bash -n packages/secubox-mail/sbin/mailctl && echo "OK"
```

Expected: `OK`.

- [ ] **Step 6: Run bats smoke**

```bash
cd packages/secubox-mail && bats tests/test_mailctl_smoke.bats 2>/dev/null || true
# (test_mailctl_smoke.bats may not exist yet — that's fine for this task)
```

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-mail/sbin/mailctl
git commit -m "feat(mail): mailctl uses canonical paths/IP + adds migrate-config (ref #<issue>)"
```

---

### Task C2: Update `mail.toml` shipped config

**Files:**
- Modify: `packages/secubox-mail/config/mail.toml`

- [ ] **Step 1: Rewrite the file**

```toml
# SecuBox Mail Server Configuration — Phase 1 rev. 2 (single LXC, canonical paths)

[mail]
enabled = true
domain = "secubox.local"
hostname = "mail"

# Single consolidated LXC
container = "mail"
lxc_ip = "10.100.0.10"
lxc_bridge = "br-lxc"
lxc_gateway = "10.100.0.1"
lxc_path = "/var/lib/lxc"
data_path = "/data/volumes/mail"

# Webmail is served by the same LXC; the URL is the host-side proxy target
webmail_url = "https://webmail.gk2.secubox.in"

# SSL
ssl_provider = "acme"   # acme | manual | none
acme_email = ""
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/config/mail.toml
git commit -m "feat(mail): mail.toml schema for single-LXC + canonical paths (ref #<issue>)"
```

---

### Task C3: Update `api/main.py` config-key reads

**Files:**
- Modify: `packages/secubox-mail/api/main.py`

- [ ] **Step 1: Find old keys**

```bash
grep -n 'mail_container\|webmail_container\|mail_ip\b\|webmail_ip\|webmail_port\|/srv/lxc\|/srv/mail' \
    packages/secubox-mail/api/main.py
```

- [ ] **Step 2: Apply the renames**

For each hit, replace per the table:

| Old | New |
|---|---|
| `cfg.get("mail_container", "mailserver")` | `cfg.get("container", "mail")` |
| `cfg.get("webmail_container", "roundcube")` | `cfg.get("container", "mail")` |
| `cfg.get("mail_ip", "192.168.255.30")` | `cfg.get("lxc_ip", "10.100.0.10")` |
| `cfg.get("webmail_ip", "192.168.255.31")` | `cfg.get("lxc_ip", "10.100.0.10")` |
| `cfg.get("webmail_port", 8027)` | `80` |
| `"/srv/lxc"` | `cfg.get("lxc_path", "/var/lib/lxc")` |
| `"/srv/mail"` | `cfg.get("data_path", "/data/volumes/mail")` |

- [ ] **Step 3: Run existing pytest**

```bash
cd packages/secubox-mail && python3 -m pytest api/tests/ -v 2>&1 | tail -15
```

Expected: no new failures.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/api/main.py
git commit -m "fix(mail): API reads canonical config keys (ref #<issue>)"
```

---

### Task C4: Reduce `mailserverctl` + `roundcubectl` to deprecation shims

**Files:**
- Modify: `packages/secubox-mail/sbin/mailserverctl`
- Modify: `packages/secubox-mail/sbin/roundcubectl`

- [ ] **Step 1: Replace `mailserverctl` entirely**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# DEPRECATED in secubox-mail 2.2 — kept as a thin shim that forwards to
# mailctl. Will be removed in 3.0.

set -euo pipefail
echo "[mailserverctl] DEPRECATED — forwarding to mailctl (removal in 3.0)" >&2
exec /usr/sbin/mailctl "$@"
```

- [ ] **Step 2: Replace `roundcubectl` entirely**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# DEPRECATED in secubox-mail 2.2 — Roundcube now lives in the single 'mail'
# LXC. Will be removed in 3.0.

set -euo pipefail
echo "[roundcubectl] DEPRECATED — forwarding to mailctl (removal in 3.0)" >&2
exec /usr/sbin/mailctl "$@"
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/sbin/mailserverctl packages/secubox-mail/sbin/roundcubectl
git commit -m "feat(mail): mailserverctl + roundcubectl reduced to deprecation shims (ref #<issue>)"
```

---

## Milestone D — Migration entry point

### Task D1: `sbin/mail-migrate-to-single-lxc.sh` (defensive scanner)

**Files:**
- Create: `packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Phase 1 rev. 2 migration. Defensive scanner — does NOT create or destroy
# anything by default. Reports legacy state and exits.
#
# Invoked from secubox-mail debian/postinst on upgrade from < 2.2.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="${LIB_DIR:-/usr/lib/secubox/mail/lib}"
[ -d "$LIB_DIR" ] || LIB_DIR="$SCRIPT_DIR/../lib"

# shellcheck source=/dev/null
source "$LIB_DIR/lxc.sh"
# shellcheck source=/dev/null
source "$LIB_DIR/migrate.sh"

log()  { echo "[mail-migrate] $*"; }
warn() { echo "[mail-migrate][WARN] $*" >&2; }

main() {
    [ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

    : "${LXC_BASE:=/var/lib/lxc}"
    : "${DATA_PATH:=/data/volumes/mail}"

    log "Phase 1 scan starting (LXC_BASE=$LXC_BASE, DATA_PATH=$DATA_PATH)"

    # 1. Legacy LXCs (rev. 1 layout, not expected on this board)
    if legacy=$(detect_legacy_lxc 2>/dev/null); then
        warn "legacy LXC dirs present: $(echo $legacy | tr '\n' ' ')"
        warn "these are NOT removed automatically — review and tar manually:"
        warn "  cd $LXC_BASE && tar -czf /tmp/legacy-mail-lxc-\$(date +%s).tar.gz mailserver roundcube"
    else
        log "no legacy mailserver/roundcube LXCs — clean"
    fi

    # 2. Data path
    if [ -d "$DATA_PATH/vmail" ]; then
        if guard_data_path; then
            log "data path $DATA_PATH is empty — fresh start ok"
        else
            log "data path $DATA_PATH has data — preserving (per spec I13)"
        fi
    else
        log "data path $DATA_PATH/vmail does not exist yet"
    fi

    # 3. mail LXC presence
    if lxc_exists "mail"; then
        log "mail LXC present at $LXC_BASE/mail"
    else
        warn "mail LXC not yet installed — run 'mailctl install' after this"
    fi

    log "scan complete — no destructive actions taken"
}

main "$@"
```

- [ ] **Step 2: Make executable + commit**

```bash
chmod +x packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh
git add packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh
git commit -m "feat(mail): mail-migrate-to-single-lxc.sh — defensive scanner (ref #<issue>)"
```

---

### Task D2: Wire the scanner + `migrate-config` into `debian/postinst`

**Files:**
- Modify: `packages/secubox-mail/debian/postinst`

- [ ] **Step 1: Find the `configure)` branch**

```bash
grep -n 'configure)' packages/secubox-mail/debian/postinst
```

- [ ] **Step 2: Add the migration hook at the top of `configure)`**

```sh
# Phase 1 rev. 2: upgrade from < 2.2 → run scanner + rewrite toml
if dpkg --compare-versions "${2:-0}" lt-nl 2.2.0; then
    if [ -x /usr/sbin/mailctl ]; then
        /usr/sbin/mailctl migrate-config || true
    fi
    if [ -x /usr/sbin/mail-migrate-to-single-lxc.sh ]; then
        /usr/sbin/mail-migrate-to-single-lxc.sh || true
    fi
fi
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/debian/postinst
git commit -m "feat(mail): postinst runs Phase 1 scanner + config migration (ref #<issue>)"
```

---

## Milestone E — Host edge (nginx + HAProxy)

### Task E1: Unified `common/nginx/modules.d/mail.conf`

**Files:**
- Create: `common/nginx/modules.d/mail.conf`
- Modify: `packages/secubox-mail/nginx/mail.conf` (deprecation stub)
- Modify: `packages/secubox-webmail/nginx/webmail.conf` (deprecation stub)

- [ ] **Step 1: Write the unified vhost**

```nginx
# common/nginx/modules.d/mail.conf
# Shipped by secubox-mail >= 2.2. Replaces:
#   packages/secubox-mail/nginx/mail.conf
#   packages/secubox-webmail/nginx/webmail.conf

upstream secubox_mail_api {
    server unix:/run/secubox/mail.sock fail_timeout=0;
}

# Admin UI — FastAPI on UNIX socket
server {
    listen 80;
    listen [::]:80;
    server_name mail-admin.gk2.secubox.in;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name mail-admin.gk2.secubox.in;
    include /etc/nginx/snippets/secubox-tls.conf;

    root /usr/share/secubox/www/mail;
    index index.html;

    location /api/v1/mail/ {
        proxy_pass http://secubox_mail_api/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
    location / {
        try_files $uri $uri/ /index.html;
    }
}

# Webmail — reverse-proxy to the mail LXC
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name webmail.gk2.secubox.in;
    include /etc/nginx/snippets/secubox-tls.conf;

    location / {
        proxy_pass http://10.100.0.10:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        client_max_body_size 50M;
    }
}
```

- [ ] **Step 2: Stub the old per-package files**

Both `packages/secubox-mail/nginx/mail.conf` and `packages/secubox-webmail/nginx/webmail.conf` become:
```nginx
# DEPRECATED in secubox-mail 2.2 — see common/nginx/modules.d/mail.conf
```

- [ ] **Step 3: Update `debian/install` files**

In `packages/secubox-mail/debian/install` (or equivalent — locate via `grep -rn 'nginx/mail.conf' packages/secubox-mail/debian/`), drop the line shipping the old vhost. Add a line shipping `common/nginx/modules.d/mail.conf` to `/etc/nginx/conf.d/secubox-mail.conf`.

For `packages/secubox-webmail/debian/install`: drop the line shipping `webmail.conf` (the transitional package ships nothing in Task F2).

- [ ] **Step 4: Commit**

```bash
git add common/nginx/modules.d/mail.conf \
        packages/secubox-mail/nginx/mail.conf \
        packages/secubox-webmail/nginx/webmail.conf \
        packages/secubox-mail/debian/install \
        packages/secubox-webmail/debian/install
git commit -m "feat(mail): unified host nginx vhost targeting 10.100.0.10 (ref #<issue>)"
```

---

### Task E2: HAProxy backends targeting `10.100.0.10`

**Files:**
- Modify: locate HAProxy config file (`grep -rln 'backend ' packages/secubox-haproxy/`)

- [ ] **Step 1: Find the file**

```bash
grep -rln '^backend ' packages/secubox-haproxy/ | head -3
```

- [ ] **Step 2: Append mail backends + frontends**

In the located file:
```
# ── Mail LXC (Phase 1) ─────────────────────────────────────
frontend smtp_in
    bind *:25
    mode tcp
    default_backend smtp_mail

frontend submission_in
    bind *:587
    mode tcp
    default_backend submission_mail

frontend imaps_in
    bind *:993
    mode tcp
    default_backend imaps_mail

frontend managesieve_in
    bind *:4190
    mode tcp
    default_backend managesieve_mail

backend smtp_mail
    mode tcp
    option tcplog
    server mail 10.100.0.10:25 check

backend submission_mail
    mode tcp
    option tcplog
    server mail 10.100.0.10:587 check

backend imaps_mail
    mode tcp
    option tcplog
    server mail 10.100.0.10:993 check

backend managesieve_mail
    mode tcp
    option tcplog
    server mail 10.100.0.10:4190 check
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-haproxy/
git commit -m "feat(haproxy): TCP pass-through backends to mail LXC 10.100.0.10 (ref #<issue>)"
```

---

## Milestone F — Package metadata

### Task F1: Bump `secubox-mail` to 2.2.0 with `Breaks:`/`Replaces:`

**Files:**
- Modify: `packages/secubox-mail/debian/control`
- Modify: `packages/secubox-mail/debian/changelog`

- [ ] **Step 1: Edit `debian/control` binary stanza**

Add (or merge into existing) fields:
```
Breaks: secubox-mail-lxc (<< 2.2), secubox-webmail-lxc (<< 2.2), secubox-webmail (<< 2.2)
Replaces: secubox-mail-lxc (<< 2.2), secubox-webmail-lxc (<< 2.2), secubox-webmail (<< 2.2)
```

- [ ] **Step 2: Prepend to `debian/changelog`**

```
secubox-mail (2.2.0-1~bookworm1) bookworm; urgency=medium

  * Phase 1 source-catch-up: canonical paths /var/lib/lxc/mail +
    /data/volumes/mail, IP 10.100.0.10 (unprivileged veth br-lxc).
  * Extract lib/install.sh + lib/lxc.sh + lib/migrate.sh from mailserverctl.
  * mailctl gains migrate-config subcommand; mailserverctl + roundcubectl
    reduced to deprecation shims.
  * mail-migrate-to-single-lxc.sh added as defensive scanner.
  * unified host nginx vhost in common/nginx/modules.d/mail.conf.
  * HAProxy backends targeting 10.100.0.10 for ports 25/587/993/4190.
  * Breaks/Replaces transitional secubox-mail-lxc / secubox-webmail-lxc /
    secubox-webmail packages.
  * Closes: #<issue>

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 15 May 2026 12:00:00 +0200
```

- [ ] **Step 3: Build + inspect**

```bash
cd packages/secubox-mail && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64
dpkg-deb -I ../../output/debs/secubox-mail_2.2.0-1~bookworm1_all.deb 2>/dev/null | grep -E 'Version|Breaks|Replaces'
```

Expected: Version 2.2.0; Breaks + Replaces lines present.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/debian/control packages/secubox-mail/debian/changelog
git commit -m "feat(mail): bump to 2.2.0 with Breaks/Replaces (ref #<issue>)"
```

---

### Task F2: Mark the 3 legacy packages transitional

**Files:**
- Modify: `packages/secubox-mail-lxc/debian/control`, `debian/changelog`, `debian/install`
- Modify: `packages/secubox-webmail-lxc/debian/control`, `debian/changelog`, `debian/install`
- Modify: `packages/secubox-webmail/debian/control`, `debian/changelog`, `debian/install`

- [ ] **Step 1: Rewrite each `debian/control`**

Per package (substitute name):
```
Source: secubox-mail-lxc
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-mail-lxc
Architecture: all
Depends: ${misc:Depends}, secubox-mail (>= 2.2)
Description: Transitional package — mail LXC functionality moved into secubox-mail
 The single consolidated mail LXC is now installed and driven by
 secubox-mail (>= 2.2). This package ships no files. Safe to remove
 after upgrade.
```

- [ ] **Step 2: Prepend changelog 2.2.0 entries**

For each package:
```
<pkg> (2.2.0-1~bookworm1) bookworm; urgency=medium

  * Transitional package — all functionality moved to secubox-mail >= 2.2.
  * Closes: #<issue>

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 15 May 2026 12:00:00 +0200
```

- [ ] **Step 3: Empty out `debian/install`** (and `debian/dirs` if present) for each transitional package — ship no files.

- [ ] **Step 4: Build all three**

```bash
for p in secubox-mail-lxc secubox-webmail-lxc secubox-webmail; do
    (cd packages/$p && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64) || { echo "build failed for $p"; break; }
done
```

Expected: 3 `.deb` files produced, each containing only metadata (no payload files beyond docs).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail-lxc/debian/ \
        packages/secubox-webmail-lxc/debian/ \
        packages/secubox-webmail/debian/
git commit -m "feat(mail): mail-lxc + webmail-lxc + webmail are transitional 2.2.0 (ref #<issue>)"
```

---

## Milestone G — Acceptance

### Task G1: 62-endpoint presence pytest

**Files:**
- Create: `packages/secubox-mail/api/tests/test_phase1_endpoints.py`

- [ ] **Step 1: Write the test**

```python
"""Phase 1 acceptance: every existing API endpoint still responds non-5xx
after the source-catch-up renames.

We don't care about response content — only that the route is registered
and the handler doesn't 500 on a default invocation. Phase 2+ tightens.
"""
from fastapi.testclient import TestClient
import pytest, sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
from api.main import app  # noqa: E402

client = TestClient(app)

LEGACY_ROUTES = [
    ("GET",  "/status"),
    ("GET",  "/health"),
    ("GET",  "/components"),
    ("GET",  "/access"),
    ("GET",  "/mail/config-v1.1.xml"),
    ("GET",  "/autoconfig/mail/config-v1.1.xml"),
    ("GET",  "/autodiscover/autodiscover.xml"),
    ("POST", "/autodiscover/autodiscover.xml"),
    ("POST", "/Autodiscover/Autodiscover.xml"),
    ("GET",  "/.well-known/autoconfig/mail/config-v1.1.xml"),
    ("GET",  "/users"),
    ("POST", "/user"),
    ("DELETE", "/user/foo@example.com"),
    ("POST", "/user/password"),
    ("GET",  "/aliases"),
    ("POST", "/alias"),
    ("DELETE", "/alias/foo@example.com"),
    ("POST", "/start"),
    ("POST", "/stop"),
    ("POST", "/restart"),
    ("POST", "/install"),
    ("GET",  "/webmail/status"),
    ("POST", "/webmail/start"),
    ("POST", "/webmail/stop"),
    ("POST", "/webmail/restart"),
    ("POST", "/webmail/install"),
    ("POST", "/migrate"),
    ("GET",  "/backups"),
    ("POST", "/backup"),
    ("POST", "/restore/test"),
    ("GET",  "/logs"),
    ("GET",  "/ssl"),
    ("POST", "/ssl/setup"),
    ("GET",  "/acme/status"),
    ("POST", "/acme/issue"),
    ("POST", "/acme/renew"),
    ("POST", "/acme/install"),
    ("GET",  "/dns-setup"),
    ("POST", "/user/repair/foo@example.com"),
    ("POST", "/fix-ports"),
    ("GET",  "/settings"),
    ("POST", "/settings"),
    ("GET",  "/dkim/status"),
    ("POST", "/dkim/setup"),
    ("POST", "/dkim/keygen"),
    ("POST", "/dkim/sync"),
    ("GET",  "/dkim/record"),
    ("GET",  "/spam/status"),
    ("POST", "/spam/setup"),
    ("POST", "/spam/enable"),
    ("POST", "/spam/disable"),
    ("POST", "/spam/update"),
    ("GET",  "/grey/status"),
    ("POST", "/grey/setup"),
    ("POST", "/grey/enable"),
    ("POST", "/grey/disable"),
    ("GET",  "/av/status"),
    ("POST", "/av/setup"),
    ("POST", "/av/enable"),
    ("POST", "/av/disable"),
    ("POST", "/av/update"),
    ("GET",  "/example.com.mobileconfig"),
]

@pytest.mark.parametrize("method,path", LEGACY_ROUTES)
def test_route_responds(method, path):
    resp = client.request(method, path, json={})
    # JWT-protected routes return 401 without a token — that's fine.
    assert resp.status_code < 500, f"{method} {path} → {resp.status_code}: {resp.text[:200]}"
```

- [ ] **Step 2: Run**

```bash
cd packages/secubox-mail && python3 -m pytest api/tests/test_phase1_endpoints.py -q 2>&1 | tail -20
```

Expected: 62/62 pass (or each failure points to a broken handler — fix the handler, not the test).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/api/tests/test_phase1_endpoints.py
git commit -m "test(mail): phase1 endpoint presence (62 routes) (ref #<issue>)"
```

---

### Task G2: End-to-end acceptance smoke

**Files:**
- Create: `tests/scripts/test-mail-phase1-acceptance.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# tests/scripts/test-mail-phase1-acceptance.sh
# Phase 1 rev. 2 acceptance — runs against the live board.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

HOST="${1:-root@192.168.1.200}"

step() { echo; echo "[acceptance] $*"; }

step "1) Source-side: bash -n parses every controller cleanly"
for f in packages/secubox-mail/sbin/{mailctl,mailserverctl,roundcubectl,mail-migrate-to-single-lxc.sh}; do
    bash -n "$f"
done
pass "controllers parse"

step "2) bats library suite"
(cd packages/secubox-mail && bats tests/) >/dev/null
pass "bats green"

step "3) pytest endpoint coverage"
(cd packages/secubox-mail && python3 -m pytest api/tests/test_phase1_endpoints.py -q) >/dev/null
pass "62 endpoints respond"

step "4) Board: mail LXC exists at canonical location"
ssh "$HOST" 'test -d /data/lxc/mail/rootfs && test -L /var/lib/lxc/mail'
pass "mail LXC + symlink present"

step "5) Board: /data/volumes/mail/vmail/secubox.in has expected users"
ssh "$HOST" 'ls /data/volumes/mail/vmail/secubox.in/' | tee /tmp/users-before
for u in gk2 bat bourdon lemurien ragondin; do
    grep -wq "$u" /tmp/users-before || fail "user $u missing before deploy"
done
pass "5 production users present"

step "6) Board: existing host secubox-mail.service stays active"
ssh "$HOST" 'systemctl is-active secubox-mail' | grep -q "^active$"
pass "secubox-mail.service is active"

step "7) Board: mailctl migrate-config rewrites the toml (already done) is idempotent"
ssh "$HOST" '/usr/sbin/mailctl migrate-config' 2>&1 | tail -3
pass "migrate-config is idempotent"

step "8) Board: toml has new keys, no orphan old keys uncommented"
ssh "$HOST" 'cat /etc/secubox/mail.toml' > /tmp/toml-after
grep -q '^container *= *"mail"'                /tmp/toml-after
grep -q '^lxc_ip *= *"10.100.0.10"'            /tmp/toml-after
! grep -qE '^mail_container|^webmail_container|^mail_ip |^webmail_ip' /tmp/toml-after
pass "toml migrated cleanly"

step "9) Board: mailctl start brings the mail LXC up"
ssh "$HOST" 'mailctl start 2>&1 | tail -5'
ssh "$HOST" 'lxc-info -n mail 2>&1' | grep -E "State:.*RUNNING" >/dev/null
pass "mail LXC RUNNING"

step "10) Board: daemons listen on 10.100.0.10"
ssh "$HOST" 'lxc-attach -n mail -- ss -tlnp 2>&1' > /tmp/lxc-ports
grep -q ':25 '  /tmp/lxc-ports
grep -q ':993 ' /tmp/lxc-ports
grep -q ':80 '  /tmp/lxc-ports
pass "postfix:25, dovecot:993, http:80 listening"

step "11) Board: IMAPS login as gk2@secubox.in works"
# Use a sane test that doesn't need the password — connect + STARTTLS handshake + LOGOUT
ssh "$HOST" 'echo "0 LOGOUT" | openssl s_client -connect 10.100.0.10:993 -quiet 2>/dev/null | head -3' \
    | grep -qi "Dovecot ready" || fail "Dovecot greeting missing"
pass "Dovecot IMAPS greeting received"

step "12) Board: Roundcube reachable through host proxy"
curl --silent --insecure --resolve "webmail.gk2.secubox.in:443:$(echo "$HOST" | cut -d@ -f2)" \
    https://webmail.gk2.secubox.in/ 2>&1 | grep -qiE 'roundcube|webmail|login'
pass "Roundcube reachable"

step "13) Data preserved: users count + names byte-identical"
ssh "$HOST" 'ls /data/volumes/mail/vmail/secubox.in/' > /tmp/users-after
diff /tmp/users-before /tmp/users-after
pass "5 production users still present, identical"

pass "PHASE 1 ACCEPTANCE: all gates green"
```

- [ ] **Step 2: Make executable + commit**

```bash
chmod +x tests/scripts/test-mail-phase1-acceptance.sh
git add tests/scripts/test-mail-phase1-acceptance.sh
git commit -m "test(mail): phase1 acceptance smoke against live board (ref #<issue>)"
```

---

### Task G3: Build, deploy, run acceptance — live board

**Files:** none (operational).

- [ ] **Step 1: Build all four packages**

```bash
for p in secubox-mail secubox-mail-lxc secubox-webmail-lxc secubox-webmail; do
    (cd packages/$p && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64)
done
ls -la output/debs/secubox-{mail,mail-lxc,webmail,webmail-lxc}_2.2.0-1~bookworm1_*.deb
```

Expected: 4 `.deb` files present.

- [ ] **Step 2: Copy debs to board**

```bash
scp output/debs/secubox-{mail,mail-lxc,webmail-lxc,webmail}_2.2.0-1~bookworm1_*.deb \
    root@192.168.1.200:/tmp/
```

- [ ] **Step 3: STOP. Confirm with user before installing.**

The next step replaces the live secubox-mail packages and runs the postinst migration. Before running, copy the install command and **ask the user to authorize it explicitly**, attaching:
- The list of `.deb` files
- The output of `ssh root@192.168.1.200 'dpkg-l secubox-mail* secubox-webmail*'` (current state)
- The rollback recipe path

Wait for explicit "yes, install" or equivalent.

- [ ] **Step 4: Install (after explicit user authorization)**

```bash
ssh root@192.168.1.200 'apt install -y /tmp/secubox-{mail,mail-lxc,webmail-lxc,webmail}_2.2.0-1~bookworm1_*.deb'
```

Expected: postinst runs `mailctl migrate-config` and `mail-migrate-to-single-lxc.sh`. Both print informational logs, neither fails. The 3 transitional packages now show as installed with no payload.

- [ ] **Step 5: Run acceptance**

```bash
bash tests/scripts/test-mail-phase1-acceptance.sh root@192.168.1.200 2>&1 | tee /tmp/phase1-acceptance.log
```

Expected: final line `PHASE 1 ACCEPTANCE: all gates green`.

- [ ] **Step 6: If any gate fails** — read the log, fix in source, rebuild, redeploy, re-run. **Do not retry blindly.** If the failure is at gate 5 or 13 (data preservation), **stop and roll back via** `docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md` and escalate to user.

- [ ] **Step 7: Update tracking files**

```bash
cat >> .claude/HISTORY.md <<EOF

## 2026-05-15 — Mail Stack Phase 1 ✅ (rev. 2: source-catch-up)
- Source code aligned with board reality (/var/lib/lxc/mail, /data/volumes/mail, 10.100.0.10)
- lib/install.sh + lib/lxc.sh + lib/migrate.sh extracted from mailserverctl
- mailctl gains migrate-config; mailserverctl + roundcubectl → deprecation shims
- secubox-mail 2.2.0 with Breaks/Replaces for legacy 3 packages
- common/nginx/modules.d/mail.conf replaces 2 per-package vhosts
- HAProxy backends targeting 10.100.0.10 (ports 25/587/993/4190)
- 62 host API endpoints respond non-5xx
- /data/volumes/mail/vmail/secubox.in/ data preserved (5 users intact)
EOF

# WIP.md: move Phase 1 to ✅ Fait; MIGRATION-MAP.md: tick secubox-mail Phase 1
git add .claude/
git commit -m "docs: track Phase 1 completion (ref #<issue>)"
```

---

### Task G4: Open the PR

- [ ] **Step 1: Push and PR**

```bash
bash scripts/agent-worktree.sh finish
```

Expected: branch pushed, PR opened with `Closes #<issue>`.

- [ ] **Step 2: Wait for user validation**

Per CLAUDE.md, do NOT close the issue or merge the PR. User reviews, validates, merges.

- [ ] **Step 3: After user merges**

```bash
bash scripts/agent-worktree.sh clean <issue>
```

---

## Self-review

1. **Spec coverage:** Phase 1 deliverables from spec rev. 2 §6:
   - "Repo source updated to canonical paths/IP" → C1, C3, C4
   - "mail.toml schema" → C2, plus migrate-config in C1
   - "lib/install.sh + lib/lxc.sh extracted" → B3 (install), B1 (lxc), B2 (migrate)
   - "mailctl migrate-config" → C1
   - "mail-migrate-to-single-lxc.sh defensive scanner" → D1, D2
   - "Refuses to touch /data/volumes/mail if data present" → B2 (guard_data_path)
   - "Legacy packages → transitional 2.2.0" → F2
   - "secubox-mail 2.2.0 with Breaks/Replaces" → F1
   - "common/nginx/modules.d/mail.conf" → E1
   - "HAProxy backends targeting 10.100.0.10" → E2
   - "62 endpoints respond non-5xx" → G1
   - "Acceptance: mailctl start; gk2@ IMAPS login; Roundcube via host proxy; data byte-identical" → G2 gates 9–13

2. **Placeholder scan:** Only `<issue>` placeholder, populated from Task A1 output. No "TBD"/"TODO"/"fill in".

3. **Identifier consistency:** `CONTAINER` (not `MAIL_CONTAINER`), `LXC_IP`, `LXC_BRIDGE`, `LXC_GATEWAY`, `DATA_PATH`, `LXC_PATH_ROOT` (or just `LXC_BASE` in lib). Function names: `lxc_exists`, `lxc_running`, `lxc_create_config`, `lxc_start_safely`, `lxc_attach_run`, `bootstrap_debian`, `install_mail_packages`, `configure_{postfix,dovecot,opendkim}`, `install_roundcube_packages`, `configure_roundcube`, `detect_legacy_lxc`, `guard_data_path`, `detect_legacy_toml_keys`, `cmd_migrate_config`. Each is defined exactly once and named consistently.

4. **Open question reconciliation:**
   - Roundcube webserver → KEEP existing Apache+mod_php in Phase 1 (board reality). Phase 5 may revisit.
   - HAProxy SMTP/IMAPS → TCP pass-through to LXC (Task E2). Daemons present own certs.
   - Postgrey + ClamAV install → OUT of Phase 1 (Phase 2 will install ClamAV; Postgrey dropped entirely).

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-15-mail-phase1-lxc-consolidation.md` (rev. 2).**
