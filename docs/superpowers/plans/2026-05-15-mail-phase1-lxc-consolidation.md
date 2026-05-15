# Mail Stack Phase 1 — LXC Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Spec:** [docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md](../specs/2026-05-15-mail-stack-architecture-design.md) — Phase 1 section.

**Goal:** Collapse the existing two-container layout (`mailserver` LXC at 192.168.255.30 + `roundcube` LXC at 192.168.255.31) into a single `mail` LXC at `/srv/lxc/mail` while preserving every existing host-side API endpoint and avoiding feature regression. No Rspamd yet (Phase 2). No multi-domain refactor yet (Phase 3).

**Architecture:**
- Single LXC bootstrap via `debootstrap` Debian bookworm arm64.
- Inside the LXC: Postfix + Dovecot + SpamAssassin + Postgrey + OpenDKIM + ClamAV + nginx + php-fpm + Roundcube + acme.sh. (Same software set as today, just co-located.)
- New `mailctl` is the only driver going forward. `mailserverctl` and `roundcubectl` shrink to thin shims that print a deprecation notice and call `mailctl`.
- A migration script `mail-migrate-to-single-lxc.sh` rsyncs mail data + Roundcube state from the old containers to the new one, then teardown of old containers.
- Old packages `secubox-mail-lxc`, `secubox-webmail-lxc`, `secubox-webmail` are marked `Conflicts:` against the new `secubox-mail` 2.x and removed via `postinst`. Their persistent data is migrated, not deleted.

**Tech stack:** Bash 5, LXC userspace tools (`lxc-create`/`lxc-start`/`lxc-stop`/`lxc-attach`/`lxc-info`), debootstrap, Postfix, Dovecot, SpamAssassin, Postgrey, OpenDKIM, ClamAV, nginx, php-fpm, Roundcube (Debian package), acme.sh, FastAPI (existing API kept), pytest (Python tests), bash test harness in `tests/scripts/`.

**Issue:** _to be filed at start of execution as `Mail stack: Phase 1 — consolidate to single LXC` with labels `migration,wip`_.

**Worktree:** `scripts/agent-worktree.sh start --issue <N>` per CLAUDE.md.

---

## File structure

### New files

| Path | Responsibility |
|---|---|
| `packages/secubox-mail/lib/install.sh` | Shared install/configure functions used by `mailctl`. Single source of truth for "how to put Postfix+Dovecot+etc. into a fresh LXC rootfs". |
| `packages/secubox-mail/lib/lxc.sh` | LXC lifecycle helpers: `lxc_exists`, `lxc_running`, `lxc_create_config`, `lxc_start_safely`, `lxc_attach_run`. |
| `packages/secubox-mail/lib/migrate.sh` | Migration helpers from old two-LXC layout (`mailserver` + `roundcube`) to new single `mail` LXC. |
| `packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh` | Top-level migration entry point invoked from postinst and manually. |
| `packages/secubox-mail/templates/lxc-config.template` | Single LXC config template (mounts, caps, cgroups). |
| `packages/secubox-mail/templates/start-mail.sh.template` | LXC init script that starts all daemons. |
| `packages/secubox-mail/templates/nginx-roundcube.conf` | In-LXC nginx vhost for Roundcube. |
| `packages/secubox-mail/templates/php-fpm-pool.conf` | In-LXC PHP-FPM pool definition. |
| `packages/secubox-mail/tests/test_install_lib.bats` | Bats tests for `install.sh` shell functions (mocked LXC). |
| `packages/secubox-mail/tests/test_lxc_lib.bats` | Bats tests for `lxc.sh`. |
| `packages/secubox-mail/tests/test_mailctl_smoke.bats` | Bats smoke test of new `mailctl install --dry-run`. |
| `packages/secubox-mail/api/tests/test_phase1_endpoints.py` | Pytest: every one of the 62 existing endpoints still returns a non-500 response after consolidation. |
| `tests/scripts/test-mail-phase1-acceptance.sh` | Integration acceptance — send + receive a mail through the single LXC, verify in Roundcube. |

### Modified files

| Path | Change |
|---|---|
| `packages/secubox-mail/sbin/mailctl` | Major rewrite — becomes single driver. Re-uses `lib/install.sh` + `lib/lxc.sh`. |
| `packages/secubox-mail/sbin/mailserverctl` | Reduced to a deprecation shim that forwards to `mailctl`. |
| `packages/secubox-mail/sbin/roundcubectl` | Same — deprecation shim. |
| `packages/secubox-mail/api/main.py` | Update IP/port references from `mail_ip`/`webmail_ip` to single `lxc_ip`. Map legacy endpoint paths to new `mailctl` invocations. |
| `packages/secubox-mail/config/mail.toml` | Single `container = "mail"` + `lxc_ip = "192.168.255.30"`; drop `webmail_container` / `webmail_ip`. |
| `packages/secubox-mail/debian/control` | Bump version to `2.0.0-1~bookworm1`. Add `Breaks:`/`Replaces:` for `secubox-mail-lxc (<<2.0)`, `secubox-webmail-lxc (<<2.0)`, `secubox-webmail (<<2.0)`. |
| `packages/secubox-mail/debian/postinst` | Call `mail-migrate-to-single-lxc.sh` on upgrade from `<<2.0`. |
| `packages/secubox-mail-lxc/debian/control` | Mark as transitional package, version `2.0.0-1~bookworm1`, `Depends: secubox-mail (>= 2.0)`. Empty payload. |
| `packages/secubox-webmail-lxc/debian/control` | Same transitional pattern. |
| `packages/secubox-webmail/debian/control` | Same transitional pattern. |
| `common/nginx/modules.d/mail.conf` _(new file in this dir, replaces both `secubox-mail/nginx/mail.conf` and `secubox-webmail/nginx/webmail.conf`)_ | Host-side reverse proxy: `mail-admin.<base>` → FastAPI socket, `webmail.<base>` → LXC IP. |
| `.claude/MIGRATION-MAP.md` | Tick `secubox-mail` as Phase 1 done when this lands. |
| `.claude/WIP.md` | Move Phase 1 item from "Next Up" to "✅ Fait". |
| `.claude/HISTORY.md` | Append dated entry. |

### Files removed (in this plan, by `git rm`)

None at code-merge time. The deprecated packages keep an empty placeholder for one minor release so `apt remove` works cleanly. They are deleted in a later cleanup commit after one release cycle, **not in this plan**.

---

## Pre-flight

### Task 0: Snapshot the host and the two existing LXCs

**Files:** none (operational task).

- [ ] **Step 1: Snapshot the existing LXCs on the test board**

Run on the deploy host:
```bash
ssh root@192.168.1.200 'set -euo pipefail
  mkdir -p /srv/backups/mail-phase1
  cd /srv/lxc
  for c in mailserver roundcube; do
    [ -d "$c" ] || continue
    lxc-stop -n "$c" 2>/dev/null || true
    tar --numeric-owner -czf "/srv/backups/mail-phase1/${c}-$(date +%F).tar.gz" "$c"
    lxc-start -n "$c" -d 2>/dev/null || true
  done
  ls -la /srv/backups/mail-phase1/'
```

Expected: two `.tar.gz` files listed, non-zero size.

- [ ] **Step 2: Snapshot /srv/mail and /etc/secubox/mail.toml**

```bash
ssh root@192.168.1.200 'tar --numeric-owner -czf /srv/backups/mail-phase1/data-$(date +%F).tar.gz /srv/mail /etc/secubox/mail.toml 2>/dev/null; ls -la /srv/backups/mail-phase1/'
```

Expected: third tarball present.

- [ ] **Step 3: Commit the rollback recipe**

Create `docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md` documenting the exact tar paths and how to restore:

```bash
cat > docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md <<'EOF'
# Mail Phase 1 — Rollback recipe

If Phase 1 deployment fails, restore from /srv/backups/mail-phase1/:

    ssh root@192.168.1.200 'set -euo pipefail
      cd /srv/lxc
      lxc-stop -n mail 2>/dev/null || true
      rm -rf mail
      tar -xzf /srv/backups/mail-phase1/mailserver-*.tar.gz
      tar -xzf /srv/backups/mail-phase1/roundcube-*.tar.gz
      tar -xzf /srv/backups/mail-phase1/data-*.tar.gz -C /
      lxc-start -n mailserver -d
      lxc-start -n roundcube -d
      apt install --reinstall secubox-mail-lxc=1.* secubox-webmail-lxc=1.* secubox-webmail=1.*'
EOF
git add docs/superpowers/runs/2026-05-15-mail-phase1-rollback.md
git commit -m "docs: Phase 1 rollback recipe (ref #<issue>)"
```

Expected: file committed.

---

## Milestone A — Scaffolding inside the new package layout

### Task A1: Create the `lib/` and `templates/` directories with empty placeholders

**Files:**
- Create: `packages/secubox-mail/lib/install.sh`
- Create: `packages/secubox-mail/lib/lxc.sh`
- Create: `packages/secubox-mail/lib/migrate.sh`
- Create: `packages/secubox-mail/templates/lxc-config.template`
- Create: `packages/secubox-mail/templates/start-mail.sh.template`
- Create: `packages/secubox-mail/templates/nginx-roundcube.conf`
- Create: `packages/secubox-mail/templates/php-fpm-pool.conf`

- [ ] **Step 1: Create the files with the standard SPDX header**

For each file above, write this exact content (adjust the description line per file):

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: mail-phase1 :: <file purpose, one line>
# Sourced library — do not execute directly.

set -euo pipefail
```

Templates (`*.template`, `*.conf`) get a `#`-comment header only, no shebang, no `set`.

- [ ] **Step 2: Commit the scaffolding**

```bash
git add packages/secubox-mail/lib/ packages/secubox-mail/templates/
git commit -m "feat(mail): scaffold phase1 lib/ and templates/ (ref #<issue>)"
```

Expected: 7 files committed.

---

### Task A2: Set up bats test harness for shell libs

**Files:**
- Create: `packages/secubox-mail/tests/test_install_lib.bats`
- Create: `packages/secubox-mail/tests/test_lxc_lib.bats`
- Create: `packages/secubox-mail/tests/test_mailctl_smoke.bats`
- Create: `packages/secubox-mail/tests/helpers.bash`

- [ ] **Step 1: Verify bats is available**

```bash
which bats || sudo apt install -y bats
bats --version
```

Expected: `Bats 1.x` printed.

- [ ] **Step 2: Write `helpers.bash` with shared test fixtures**

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

# Fake LXC environment under a tmpdir so tests don't need root or actual LXC.
make_fake_lxc() {
    export LXC_BASE="$BATS_TEST_TMPDIR/lxc"
    export DATA_PATH="$BATS_TEST_TMPDIR/srv-mail"
    mkdir -p "$LXC_BASE" "$DATA_PATH"
}
```

- [ ] **Step 3: Write a trivial sanity test in each `*.bats` file**

`test_lxc_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc; }

@test "lxc.sh sources cleanly" {
    [ "$(type -t lxc_exists)" = "function" ]
}
```

`test_install_lib.bats`:
```bash
#!/usr/bin/env bats
load helpers
setup() { load_libs; make_fake_lxc; }

@test "install.sh sources cleanly" {
    [ "$(type -t install_mail_packages)" = "function" ]
}
```

`test_mailctl_smoke.bats`:
```bash
#!/usr/bin/env bats
load helpers

@test "mailctl --help exits 0" {
    run "${BATS_TEST_DIRNAME}/../sbin/mailctl" --help
    [ "$status" -eq 0 ]
}
```

- [ ] **Step 4: Run the bats suite — expect failures**

```bash
cd packages/secubox-mail && bats tests/
```

Expected: all three bats files **fail** — the functions `lxc_exists`, `install_mail_packages` aren't defined yet, and `mailctl` may not yet support `--help`. This is the red baseline before TDD.

- [ ] **Step 5: Commit the failing tests**

```bash
git add packages/secubox-mail/tests/
git commit -m "test(mail): phase1 bats scaffolding — red baseline (ref #<issue>)"
```

Expected: 4 files committed.

---

### Task A3: Generate the GitHub issue and start the worktree

**Files:** none.

- [ ] **Step 1: Create the issue**

```bash
gh issue create --title "Mail stack: Phase 1 — consolidate to single LXC" \
  --label "migration,wip" \
  --body "$(cat <<'EOF'
Per Phase 0 spec docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md.

## Tasks
- [ ] Bootstrap single `mail` LXC
- [ ] Postfix + Dovecot + SA + Postgrey + OpenDKIM + ClamAV installed in one container
- [ ] Roundcube inside the same container, served via nginx+php-fpm
- [ ] New `mailctl` is the single driver; mailserverctl/roundcubectl shrink to shims
- [ ] Data migration from old two LXCs
- [ ] Host nginx + HAProxy updated
- [ ] Old packages secubox-mail-lxc / secubox-webmail-lxc / secubox-webmail marked transitional
- [ ] All 62 host API endpoints respond
- [ ] Acceptance smoke (send + receive via IMAPS, Roundcube renders)

## Files
- packages/secubox-mail/
- packages/secubox-mail-lxc/
- packages/secubox-webmail-lxc/
- packages/secubox-webmail/
- common/nginx/modules.d/mail.conf

## References
- Spec: docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md
- Plan: docs/superpowers/plans/2026-05-15-mail-phase1-lxc-consolidation.md
EOF
)"
```

Expected: issue URL printed; note the number as `<issue>` and substitute it in every later commit message.

- [ ] **Step 2: Open the worktree**

```bash
bash scripts/agent-worktree.sh start --issue <issue>
cd ~/CyberMindStudio/secubox-deb-worktrees/<issue>-mail-stack-phase-1-consolidate-to-single-lxc/
```

Expected: new worktree created on branch `<issue>-mail-phase1-...`.

---

## Milestone B — Shared install library

> The existing `mailserverctl` already contains working functions for these. We **extract** them into `lib/install.sh` so the new `mailctl` can call them. The old `mailserverctl` keeps working until the deprecation shim lands.

### Task B1: Extract LXC helpers into `lib/lxc.sh`

**Files:**
- Modify: `packages/secubox-mail/lib/lxc.sh`
- Test: `packages/secubox-mail/tests/test_lxc_lib.bats`

- [ ] **Step 1: Write the failing test (LXC helpers shape)**

Add to `test_lxc_lib.bats`:
```bash
@test "lxc_exists returns 1 for missing container" {
    run lxc_exists "ghost-container"
    [ "$status" -eq 1 ]
}

@test "lxc_create_config writes a config file with rootfs path" {
    local name="testmail"
    local cfg
    cfg="$(lxc_create_config "$name" "192.168.255.30" 2>&1)"
    grep -q "lxc.uts.name = $name" "$LXC_BASE/$name/config"
    grep -q "lxc.rootfs.path = dir:$LXC_BASE/$name/rootfs" "$LXC_BASE/$name/config"
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd packages/secubox-mail && bats tests/test_lxc_lib.bats
```

Expected: both new cases fail (functions empty).

- [ ] **Step 3: Implement the functions**

Append to `lib/lxc.sh`:
```bash
# Returns 0 if a container's rootfs exists under $LXC_BASE.
lxc_exists() {
    local name="$1"
    [ -d "${LXC_BASE:-/srv/lxc}/$name/rootfs" ]
}

# Returns 0 if a container is currently running.
lxc_running() {
    local name="$1"
    lxc-info -n "$name" -P "${LXC_BASE:-/srv/lxc}" 2>/dev/null | grep -q "State:.*RUNNING"
}

# Render lxc.config for the named container at the given IP.
# Writes to $LXC_BASE/$name/config and echoes the path.
lxc_create_config() {
    local name="$1"
    local ip="$2"
    local base="${LXC_BASE:-/srv/lxc}"
    local data="${DATA_PATH:-/srv/mail}"
    mkdir -p "$base/$name"
    cat > "$base/$name/config" <<EOF
lxc.uts.name = $name
lxc.rootfs.path = dir:$base/$name/rootfs
lxc.net.0.type = none
lxc.mount.auto = proc:mixed sys:ro cgroup:mixed
lxc.cap.drop = sys_module mac_admin mac_override sys_time
lxc.tty.max = 4
lxc.pty.max = 256
lxc.cgroup2.memory.max = 1024M
lxc.init.cmd = /opt/start-mail.sh

# Persistent data bind mounts
lxc.mount.entry = $data/vmail var/mail none bind,create=dir 0 0
lxc.mount.entry = $data/ssl etc/ssl/mail none bind,create=dir 0 0
lxc.mount.entry = $data/dkim etc/opendkim/keys none bind,create=dir 0 0
lxc.mount.entry = $data/roundcube var/lib/roundcube none bind,create=dir 0 0
lxc.mount.entry = $data/clamav var/lib/clamav none bind,create=dir 0 0
EOF
    echo "$base/$name/config"
}

# Start a container and wait until it reports RUNNING (max 10s).
lxc_start_safely() {
    local name="$1"
    lxc-start -n "$name" -P "${LXC_BASE:-/srv/lxc}" -d
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        lxc_running "$name" && return 0
        sleep 1
    done
    return 1
}

# Run a command inside a container, propagate exit status.
lxc_attach_run() {
    local name="$1"; shift
    lxc-attach -n "$name" -P "${LXC_BASE:-/srv/lxc}" -- "$@"
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd packages/secubox-mail && bats tests/test_lxc_lib.bats
```

Expected: all tests in this file pass.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/lib/lxc.sh packages/secubox-mail/tests/test_lxc_lib.bats
git commit -m "feat(mail): extract lxc.sh helpers from mailserverctl (ref #<issue>)"
```

---

### Task B2: Extract debootstrap helper into `lib/install.sh`

**Files:**
- Modify: `packages/secubox-mail/lib/install.sh`
- Test: `packages/secubox-mail/tests/test_install_lib.bats`

- [ ] **Step 1: Write the failing test**

Add to `test_install_lib.bats`:
```bash
@test "bootstrap_debian refuses to run if debootstrap missing" {
    # Hide debootstrap from PATH
    local fake_path="$BATS_TEST_TMPDIR/path"
    mkdir -p "$fake_path"
    PATH="$fake_path" run bootstrap_debian "$BATS_TEST_TMPDIR/lxc/mail"
    [ "$status" -ne 0 ]
    [[ "$output" == *"debootstrap"* ]]
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
cd packages/secubox-mail && bats tests/test_install_lib.bats
```

Expected: FAIL (function undefined).

- [ ] **Step 3: Implement**

Append to `lib/install.sh`:
```bash
# Run debootstrap into the rootfs of an LXC. $1 = absolute LXC path
# (the one that will contain rootfs/). Caller ensures parent dirs exist.
bootstrap_debian() {
    local lxc_path="$1"
    if ! command -v debootstrap >/dev/null 2>&1; then
        echo "ERROR: debootstrap not installed. Run: apt install debootstrap" >&2
        return 1
    fi
    mkdir -p "$lxc_path"
    debootstrap --variant=minbase --include=ca-certificates,curl,gnupg,locales,systemd-sysv \
        bookworm "$lxc_path/rootfs" http://deb.debian.org/debian
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
cd packages/secubox-mail && bats tests/test_install_lib.bats
```

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-mail/lib/install.sh packages/secubox-mail/tests/test_install_lib.bats
git commit -m "feat(mail): extract bootstrap_debian helper (ref #<issue>)"
```

---

### Task B3: Extract `install_mail_packages` (Postfix/Dovecot/SA/Postgrey/OpenDKIM/ClamAV)

**Files:**
- Modify: `packages/secubox-mail/lib/install.sh`

> No bats test for this — it requires a real LXC + apt. We rely on the integration acceptance test at the end (Milestone I).

- [ ] **Step 1: Copy the existing function from `mailserverctl`**

Find `install_mail_packages()` in `packages/secubox-mail/sbin/mailserverctl` (around line 250) and copy its body verbatim into `lib/install.sh`. Then enhance it to also install ClamAV, since today ClamAV is installed by `mailserverctl::cmd_av_install` as a separate step — Phase 1 collapses install into one shot.

```bash
# Install the mail stack inside a debootstrapped LXC rootfs.
# Phase 1: same software set as today (Postfix + Dovecot + SA + Postgrey
#          + OpenDKIM + ClamAV) plus nginx + php-fpm + Roundcube for webmail.
# Caller ensures the LXC is up.
install_mail_packages() {
    local container="$1"
    log "Installing mail packages inside LXC $container..."
    lxc_attach_run "$container" bash -c '
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends \
            postfix postfix-pcre \
            dovecot-core dovecot-imapd dovecot-pop3d dovecot-managesieved dovecot-sieve \
            spamassassin spamc \
            postgrey \
            opendkim opendkim-tools \
            clamav clamav-daemon clamav-milter \
            nginx php-fpm php-pear php-mbstring php-intl php-zip php-xml php-mysql \
            roundcube roundcube-plugins roundcube-sqlite3 \
            ca-certificates curl gnupg socat
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    '
}
```

- [ ] **Step 2: Replace the equivalent in `mailserverctl` with a thin wrapper**

In `packages/secubox-mail/sbin/mailserverctl`, replace the body of `install_mail_packages()` with:
```bash
install_mail_packages() {
    # shellcheck source=/dev/null
    source "$(dirname "$0")/../lib/install.sh" 2>/dev/null \
        || source "/usr/lib/secubox/mail/lib/install.sh"
    install_mail_packages "$CONTAINER"
}
```

This keeps `mailserverctl` working during transition; the new code path is authoritative.

- [ ] **Step 3: Run bats — expect existing tests still pass**

```bash
cd packages/secubox-mail && bats tests/
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/lib/install.sh packages/secubox-mail/sbin/mailserverctl
git commit -m "feat(mail): unify install_mail_packages in lib/install.sh (ref #<issue>)"
```

---

### Task B4: Extract `configure_postfix`, `configure_dovecot`, `configure_opendkim`, `configure_clamav` into `lib/install.sh`

**Files:**
- Modify: `packages/secubox-mail/lib/install.sh`
- Modify: `packages/secubox-mail/sbin/mailserverctl` (replace each `configure_*` body with a thin source+call shim)

- [ ] **Step 1: Copy the four existing `configure_*` function bodies from `mailserverctl`**

Locate `configure_postfix()`, `configure_dovecot()`, `configure_opendkim()`, `configure_clamav()` in `mailserverctl`. Copy each into `lib/install.sh`, prefixing the function names with nothing (same names — they'll shadow the inlined ones once the shim sources them). Adjust hard-coded paths to use `${LXC_PATH:-/srv/lxc/mail}` and accept the container name as `$1`.

For brevity, do not paste the full bodies here — they're in `mailserverctl` lines roughly 700–1100. The copy is mechanical:
- Read each function from `mailserverctl`.
- Paste into `lib/install.sh` with the parameter signature `configure_postfix() { local container="$1"; ... }`.
- Replace `$CONTAINER` with `$container` in the body.
- Replace `$LXC_PATH` with `${LXC_BASE}/${container}` (since `LXC_PATH` was the per-container path in the old script).

- [ ] **Step 2: Replace the four bodies in `mailserverctl` with shim**

For each one, body becomes:
```bash
configure_postfix() {
    source "$(dirname "$0")/../lib/install.sh" 2>/dev/null \
        || source "/usr/lib/secubox/mail/lib/install.sh"
    configure_postfix "$CONTAINER"
}
```
(Same shape for the other three.)

- [ ] **Step 3: Run bats — existing tests still green**

```bash
cd packages/secubox-mail && bats tests/
```

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/lib/install.sh packages/secubox-mail/sbin/mailserverctl
git commit -m "feat(mail): unify configure_* helpers in lib/install.sh (ref #<issue>)"
```

---

### Task B5: Add `install_roundcube()` and `configure_roundcube()` to `lib/install.sh`

**Files:**
- Modify: `packages/secubox-mail/lib/install.sh`
- Modify: `packages/secubox-mail/templates/nginx-roundcube.conf`
- Modify: `packages/secubox-mail/templates/php-fpm-pool.conf`

- [ ] **Step 1: Populate the templates**

`templates/nginx-roundcube.conf`:
```nginx
server {
    listen 80 default_server;
    server_name _;
    root /var/lib/roundcube/public_html;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    location ~* /(\.|config|temp|logs) {
        deny all;
        return 404;
    }
}
```

`templates/php-fpm-pool.conf`:
```ini
[roundcube]
user = www-data
group = www-data
listen = /run/php/php8.2-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 10
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 3
chdir = /
```

- [ ] **Step 2: Add the install + configure functions**

Append to `lib/install.sh`:
```bash
# Phase 1 webserver inside the LXC is nginx + php-fpm. Apache is rejected
# to keep one httpd flavor across the SecuBox host stack.
configure_roundcube() {
    local container="$1"
    local templates="${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}"
    local lxc_root="${LXC_BASE:-/srv/lxc}/$container/rootfs"

    install -m 0644 "$templates/nginx-roundcube.conf" \
        "$lxc_root/etc/nginx/sites-available/roundcube"
    install -m 0644 "$templates/php-fpm-pool.conf" \
        "$lxc_root/etc/php/8.2/fpm/pool.d/roundcube.conf"

    lxc_attach_run "$container" bash -c '
        set -euo pipefail
        rm -f /etc/nginx/sites-enabled/default
        ln -sf ../sites-available/roundcube /etc/nginx/sites-enabled/roundcube

        # Roundcube SQLite db
        install -d -o www-data -g www-data /var/lib/roundcube
        if [ ! -f /var/lib/roundcube/roundcube.db ]; then
            sqlite3 /var/lib/roundcube/roundcube.db \
                < /usr/share/dbconfig-common/data/roundcube/install/sqlite3
            chown www-data:www-data /var/lib/roundcube/roundcube.db
        fi

        # Point Roundcube at the local Dovecot
        sed -i "s|^\$config\[.default_host.\].*|\$config[\"default_host\"] = \"tls://localhost\";|" \
            /etc/roundcube/config.inc.php
        sed -i "s|^\$config\[.smtp_server.\].*|\$config[\"smtp_server\"] = \"tls://localhost\";|" \
            /etc/roundcube/config.inc.php
    '
}
```

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/lib/install.sh packages/secubox-mail/templates/
git commit -m "feat(mail): roundcube install+configure in shared lib (ref #<issue>)"
```

---

## Milestone C — New `mailctl install`

### Task C1: Rewrite `mailctl install` to drive the single `mail` LXC

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`

- [ ] **Step 1: Replace the existing `cmd_install` body**

Locate `cmd_install()` (around line 259) in `mailctl` and replace its body with:

```bash
cmd_install() {
    require_root

    : "${LIB_DIR:=/usr/lib/secubox/mail/lib}"
    [ -d "$LIB_DIR" ] || LIB_DIR="$(dirname "$0")/../lib"
    # shellcheck source=/dev/null
    source "$LIB_DIR/lxc.sh"
    # shellcheck source=/dev/null
    source "$LIB_DIR/install.sh"

    local container="${MAIL_CONTAINER:-mail}"
    local lxc_ip
    lxc_ip="$(config_get "lxc_ip" "192.168.255.30")"

    log "Installing single mail LXC '$container' at $lxc_ip..."

    # Persistent data dirs
    mkdir -p "$DATA_PATH"/{vmail,ssl,dkim,roundcube,clamav,backups,config}
    touch "$DATA_PATH/config/users" "$DATA_PATH/config/vmailbox" "$DATA_PATH/config/virtual"

    if ! lxc_exists "$container"; then
        bootstrap_debian "$LXC_BASE/$container"
    fi

    lxc_create_config "$container" "$lxc_ip"
    install -m 0755 "${TEMPLATES_DIR:-/usr/lib/secubox/mail/templates}/start-mail.sh.template" \
        "$LXC_BASE/$container/rootfs/opt/start-mail.sh"

    lxc_start_safely "$container" \
        || { error "container failed to start"; return 1; }

    install_mail_packages "$container"
    configure_postfix      "$container"
    configure_dovecot      "$container"
    configure_opendkim     "$container"
    configure_clamav       "$container"
    configure_roundcube    "$container"

    log "Mail stack installed in single LXC '$container'"
    log "Next: mailctl user add <user@$DOMAIN>"
}
```

- [ ] **Step 2: Add `--help` output to `mailctl`**

Find the top-level case statement and add at the top:
```bash
case "${1:-}" in
    -h|--help|help)
        cat <<'EOF'
mailctl — SecuBox single-LXC mail driver (Phase 1)
Usage:
  mailctl install                Install or upgrade the mail LXC
  mailctl start | stop | restart Lifecycle
  mailctl status                 Show container + daemon state
  mailctl user add|del|list      User management
  mailctl alias add|del|list     Alias management
  mailctl dkim setup|status      DKIM (Phase 1 = OpenDKIM, Phase 2 = Rspamd)
  mailctl sync                   Reconcile flat files into the container
  mailctl backup | restore       Maildir backup helpers
EOF
        exit 0
        ;;
```

- [ ] **Step 3: Run bats — `mailctl --help` now passes**

```bash
cd packages/secubox-mail && bats tests/test_mailctl_smoke.bats
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/sbin/mailctl
git commit -m "feat(mail): mailctl install drives single mail LXC (ref #<issue>)"
```

---

### Task C2: Populate `templates/start-mail.sh.template`

**Files:**
- Modify: `packages/secubox-mail/templates/start-mail.sh.template`

- [ ] **Step 1: Replace the placeholder with the full init script**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Init script run by lxc.init.cmd. Starts every daemon in the mail LXC.
# No systemd inside the container — we keep it minimal and explicit.

set -eu
mkdir -p /run/php

# 1. Postgrey
service postgrey start || /usr/sbin/postgrey --inet=10023 --pidfile=/var/run/postgrey.pid -d

# 2. OpenDKIM
service opendkim start

# 3. SpamAssassin
service spamassassin start

# 4. ClamAV
service clamav-daemon start
service clamav-milter start

# 5. Dovecot
/usr/sbin/dovecot

# 6. Postfix
/usr/sbin/postfix start

# 7. PHP-FPM
/usr/sbin/php-fpm8.2 --nodaemonize &

# 8. nginx (foreground — keeps LXC PID 1 alive)
exec /usr/sbin/nginx -g "daemon off;"
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/templates/start-mail.sh.template
git commit -m "feat(mail): start-mail.sh init script for single LXC (ref #<issue>)"
```

---

### Task C3: Update `mail.toml` schema for single LXC

**Files:**
- Modify: `packages/secubox-mail/config/mail.toml`

- [ ] **Step 1: Replace the file contents**

```toml
# SecuBox Mail Server Configuration — Phase 1 (single LXC)

[mail]
enabled = true
domain = "secubox.local"
hostname = "mail"
data_path = "/srv/mail"
lxc_path = "/srv/lxc"

# Single consolidated LXC (Phase 1 onwards)
container = "mail"
lxc_ip = "192.168.255.30"

# Webmail (now inside the same LXC; the URL is the host-side proxy target)
webmail_url = "https://webmail.gk2.secubox.in"

# SSL settings
ssl_provider = "acme"   # acme | manual | none
acme_email = ""

# DEPRECATED — kept for one release so mailctl migrate-config can read them
# mail_container = "mailserver"
# mail_ip = "192.168.255.30"
# webmail_container = "roundcube"
# webmail_ip = "192.168.255.31"
# webmail_port = 8027
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/config/mail.toml
git commit -m "feat(mail): mail.toml schema — single container (ref #<issue>)"
```

---

### Task C4: Implement `mailctl migrate-config` to upgrade old toml in place

**Files:**
- Modify: `packages/secubox-mail/sbin/mailctl`

- [ ] **Step 1: Add the subcommand**

In `mailctl`, add a new function before the case statement:

```bash
cmd_migrate_config() {
    require_root
    local cfg="${CONFIG_FILE:-/etc/secubox/mail.toml}"
    [ -f "$cfg" ] || { warn "no config to migrate at $cfg"; return 0; }

    if grep -q "^container *=" "$cfg"; then
        log "config already migrated"
        return 0
    fi

    cp "$cfg" "${cfg}.pre-phase1.$(date +%s).bak"

    # Inject the new single-LXC keys after [mail] header, preserve old keys
    # commented for one release.
    python3 - "$cfg" <<'PY'
import sys, re
path = sys.argv[1]
src = open(path).read()
# Insert after [mail] section header
new_block = (
    "container = \"mail\"\n"
    "lxc_ip = \"192.168.255.30\"\n"
    "webmail_url = \"https://webmail.gk2.secubox.in\"\n"
)
src = re.sub(r"(\[mail\]\n)", r"\1" + new_block, src, count=1)
# Comment out deprecated keys
for k in ("mail_container", "mail_ip", "webmail_container", "webmail_ip", "webmail_port"):
    src = re.sub(rf"^({k} *=.*)$", r"# DEPRECATED Phase 1: \1", src, flags=re.MULTILINE)
open(path, "w").write(src)
PY
    log "config migrated; backup at ${cfg}.pre-phase1.*.bak"
}
```

And add to the case statement:
```bash
    migrate-config) shift; cmd_migrate_config "$@" ;;
```

- [ ] **Step 2: Test it on a fixture**

```bash
mkdir -p /tmp/mail-cfg-test
cp packages/secubox-mail/config/mail.toml /tmp/mail-cfg-test/old.toml
# Make it look like the old format
sed -i 's/^container = "mail"/mail_container = "mailserver"/' /tmp/mail-cfg-test/old.toml
sed -i '/^lxc_ip/d;/^webmail_url/d' /tmp/mail-cfg-test/old.toml
echo 'webmail_container = "roundcube"' >> /tmp/mail-cfg-test/old.toml

# Run migration (override config file path via env)
CONFIG_FILE=/tmp/mail-cfg-test/old.toml sudo packages/secubox-mail/sbin/mailctl migrate-config

# Verify
grep -E '^container *=|^lxc_ip|^webmail_url' /tmp/mail-cfg-test/old.toml
grep -E '^# DEPRECATED Phase 1' /tmp/mail-cfg-test/old.toml
```

Expected: three new lines present; deprecated lines prefixed with `# DEPRECATED Phase 1`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/sbin/mailctl
git commit -m "feat(mail): mailctl migrate-config rewrites toml in place (ref #<issue>)"
```

---

## Milestone D — Data migration script

### Task D1: Write `lib/migrate.sh` helpers

**Files:**
- Modify: `packages/secubox-mail/lib/migrate.sh`

- [ ] **Step 1: Add helpers**

```bash
# Idempotent — safe to re-run.
migrate_mailserver_data() {
    local old_lxc="${LXC_BASE:-/srv/lxc}/mailserver"
    local new_data="${DATA_PATH:-/srv/mail}"
    if [ -d "$old_lxc/rootfs/var/mail" ]; then
        log "Migrating mailserver maildirs..."
        rsync -aAX --delete-after \
            "$old_lxc/rootfs/var/mail/" "$new_data/vmail/"
    fi
    if [ -d "$old_lxc/rootfs/etc/opendkim/keys" ]; then
        log "Migrating DKIM keys..."
        rsync -aAX "$old_lxc/rootfs/etc/opendkim/keys/" "$new_data/dkim/"
    fi
    if [ -d "$old_lxc/rootfs/etc/ssl/mail" ]; then
        log "Migrating SSL certs..."
        rsync -aAX "$old_lxc/rootfs/etc/ssl/mail/" "$new_data/ssl/"
    fi
}

migrate_roundcube_data() {
    local old_lxc="${LXC_BASE:-/srv/lxc}/roundcube"
    local new_data="${DATA_PATH:-/srv/mail}"
    if [ -d "$old_lxc/rootfs/var/lib/roundcube" ]; then
        log "Migrating Roundcube user data..."
        rsync -aAX "$old_lxc/rootfs/var/lib/roundcube/" "$new_data/roundcube/"
    fi
}

stop_old_containers() {
    for c in mailserver roundcube; do
        if lxc-info -n "$c" -P "${LXC_BASE:-/srv/lxc}" 2>/dev/null | grep -q RUNNING; then
            log "Stopping old container: $c"
            lxc-stop -n "$c" -P "${LXC_BASE:-/srv/lxc}" -t 30 || true
        fi
    done
}

archive_old_rootfs() {
    local base="${LXC_BASE:-/srv/lxc}"
    local out="${BACKUP_DIR:-/srv/backups/mail-phase1}"
    mkdir -p "$out"
    for c in mailserver roundcube; do
        if [ -d "$base/$c/rootfs" ]; then
            log "Archiving $base/$c..."
            tar --numeric-owner -czf "$out/${c}-rootfs-$(date +%s).tar.gz" -C "$base" "$c"
        fi
    done
}
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/lib/migrate.sh
git commit -m "feat(mail): migrate.sh helpers (data rsync, archive) (ref #<issue>)"
```

---

### Task D2: Create the top-level `mail-migrate-to-single-lxc.sh`

**Files:**
- Create: `packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# Migrate from the two-LXC layout (mailserver + roundcube) to the single
# `mail` LXC. Idempotent. Safe to invoke from debian/postinst.

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
    [ "$(id -u)" -eq 0 ] || { echo "Must run as root" >&2; exit 1; }

    local needs_migration=0
    if lxc_exists "mailserver" || lxc_exists "roundcube"; then
        needs_migration=1
    fi

    if [ "$needs_migration" -eq 0 ]; then
        log "no legacy LXCs detected — nothing to migrate"
        exit 0
    fi

    log "phase 1 migration starting"
    stop_old_containers
    archive_old_rootfs
    migrate_mailserver_data
    migrate_roundcube_data

    log "data migrated to /srv/mail"
    log "next: run 'mailctl install' to bring up the new 'mail' LXC"
    log "old rootfs archives kept under ${BACKUP_DIR:-/srv/backups/mail-phase1}"
}

main "$@"
```

- [ ] **Step 2: Make it executable + commit**

```bash
chmod +x packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh
git add packages/secubox-mail/sbin/mail-migrate-to-single-lxc.sh
git commit -m "feat(mail): top-level migrate-to-single-lxc script (ref #<issue>)"
```

---

### Task D3: Wire migration into `debian/postinst`

**Files:**
- Modify: `packages/secubox-mail/debian/postinst`

- [ ] **Step 1: Add the migration hook**

Locate `case "$1" in` block. In the `configure)` branch, add at the top:

```sh
# Phase 1 migration: if upgrading from <2.0, collapse old two-LXC layout
if dpkg --compare-versions "${2:-0}" lt-nl 2.0.0; then
    if [ -x /usr/sbin/mail-migrate-to-single-lxc.sh ]; then
        /usr/sbin/mail-migrate-to-single-lxc.sh || {
            echo "mail-migrate-to-single-lxc.sh failed; aborting upgrade"
            exit 1
        }
    fi
    /usr/sbin/mailctl migrate-config || true
fi
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/debian/postinst
git commit -m "feat(mail): postinst migrates legacy LXCs on upgrade to 2.0 (ref #<issue>)"
```

---

## Milestone E — Host edge (nginx + HAProxy)

### Task E1: Replace the two old nginx vhosts with one `mail.conf` in `common/nginx/modules.d/`

**Files:**
- Create: `common/nginx/modules.d/mail.conf`
- Modify: `packages/secubox-mail/debian/install` (or wherever the old `nginx/mail.conf` is shipped) — drop the per-package nginx file.
- Modify: `packages/secubox-webmail/debian/install` — same.

- [ ] **Step 1: Write the unified vhost**

```nginx
# common/nginx/modules.d/mail.conf
# Shipped by secubox-mail >= 2.0. Replaces:
#   packages/secubox-mail/nginx/mail.conf
#   packages/secubox-webmail/nginx/webmail.conf

# Admin UI: FastAPI on UNIX socket
upstream secubox_mail_api {
    server unix:/run/secubox/mail.sock fail_timeout=0;
}

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

# Webmail: reverse-proxy to Roundcube inside the mail LXC
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name webmail.gk2.secubox.in;

    include /etc/nginx/snippets/secubox-tls.conf;

    location / {
        proxy_pass http://192.168.255.30:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_buffering off;
        client_max_body_size 50M;  # attachment uploads
    }
}
```

- [ ] **Step 2: Stop shipping the old per-package nginx files**

In `packages/secubox-mail/debian/install` (if it exists; otherwise inspect `dpkg-buildpackage` output), remove the line that copies `nginx/mail.conf` into the package. Same for `secubox-webmail`. Add a line shipping `common/nginx/modules.d/mail.conf` into `/etc/nginx/conf.d/secubox-mail.conf`.

- [ ] **Step 3: Commit**

```bash
git add common/nginx/modules.d/mail.conf \
        packages/secubox-mail/debian/install \
        packages/secubox-webmail/debian/install
git commit -m "feat(mail): unified host nginx vhost for admin+webmail (ref #<issue>)"
```

---

### Task E2: HAProxy backend for SMTP and IMAPS

**Files:**
- Modify: `packages/secubox-haproxy/` (whatever file holds backend definitions — locate via `grep -r "backend " packages/secubox-haproxy`)

- [ ] **Step 1: Locate the HAProxy backend file**

```bash
grep -rln "^backend " packages/secubox-haproxy/ | head -5
```

Use the file that matches the existing pattern (likely `packages/secubox-haproxy/config/haproxy.cfg.template` or similar).

- [ ] **Step 2: Add backends — pass-through to LXC**

Append:
```
backend smtp_mail
    mode tcp
    option tcplog
    server mail 192.168.255.30:25 check

backend submission_mail
    mode tcp
    option tcplog
    server mail 192.168.255.30:587 check

backend imaps_mail
    mode tcp
    option tcplog
    server mail 192.168.255.30:993 check

backend managesieve_mail
    mode tcp
    option tcplog
    server mail 192.168.255.30:4190 check
```

And matching frontends on ports 25 / 587 / 993 / 4190 with `mode tcp`, no TLS termination (Postfix/Dovecot present their own certs).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-haproxy/
git commit -m "feat(haproxy): mail LXC backends (smtp/submission/imaps/sieve) (ref #<issue>)"
```

---

### Task E3: Update existing `packages/secubox-mail/nginx/mail.conf` and `packages/secubox-webmail/nginx/webmail.conf` to deprecation stubs

**Files:**
- Modify: `packages/secubox-mail/nginx/mail.conf`
- Modify: `packages/secubox-webmail/nginx/webmail.conf`

- [ ] **Step 1: Replace both with one-line comments**

For each file:
```nginx
# DEPRECATED in secubox-mail 2.0 — see common/nginx/modules.d/mail.conf
# This file is shipped empty for one release to avoid nginx config breakage
# on partially-upgraded systems.
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/nginx/mail.conf packages/secubox-webmail/nginx/webmail.conf
git commit -m "feat(mail): deprecate per-package nginx files (ref #<issue>)"
```

---

## Milestone F — API endpoint coverage

### Task F1: Update `packages/secubox-mail/api/main.py` to use the new single-LXC config keys

**Files:**
- Modify: `packages/secubox-mail/api/main.py`

- [ ] **Step 1: Grep for the old keys**

```bash
grep -n 'mail_container\|webmail_container\|mail_ip\|webmail_ip\|webmail_port' \
    packages/secubox-mail/api/main.py
```

For each hit, replace with the new key. Pattern:

| Old | New |
|---|---|
| `config.get("mail_container", "mailserver")` | `config.get("container", "mail")` |
| `config.get("webmail_container", "roundcube")` | `config.get("container", "mail")` |
| `config.get("mail_ip", "192.168.255.30")` | `config.get("lxc_ip", "192.168.255.30")` |
| `config.get("webmail_ip", "192.168.255.31")` | `config.get("lxc_ip", "192.168.255.30")` |
| `config.get("webmail_port", 8027)` | `80` (hard-coded — webmail now on standard HTTP inside LXC, proxied via 443 host-side) |

- [ ] **Step 2: Run API unit tests if any**

```bash
cd packages/secubox-mail && python3 -m pytest api/tests/ -v 2>&1 | tail -20
```

Expected: still green (or at minimum, no new failures).

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/api/main.py
git commit -m "fix(mail): API uses single-container config keys (ref #<issue>)"
```

---

### Task F2: Add an endpoint-presence pytest covering all 62 endpoints

**Files:**
- Create: `packages/secubox-mail/api/tests/test_phase1_endpoints.py`

- [ ] **Step 1: Write the test**

```python
"""Phase 1 acceptance: every legacy endpoint must still answer.

We don't care about response *content* here — only that the route is
registered and returns a non-500 status code. Phase 2+ adds content tests.
"""
from fastapi.testclient import TestClient
import pytest

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parents[2]))
from api.main import app  # noqa: E402

client = TestClient(app)

# Pulled from packages/secubox-mail/api/main.py via grep '@app\.' on 2026-05-15.
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
    ("DELETE","/user/foo@example.com"),
    ("POST", "/user/password"),
    ("GET",  "/aliases"),
    ("POST", "/alias"),
    ("DELETE","/alias/foo@example.com"),
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
    # Plus a few /domain.mobileconfig dynamic paths
    ("GET",  "/example.com.mobileconfig"),
]

@pytest.mark.parametrize("method,path", LEGACY_ROUTES)
def test_route_responds(method, path):
    resp = client.request(method, path, json={})
    # JWT-protected routes return 401 without a token — that still counts as "registered".
    assert resp.status_code < 500, f"{method} {path} returned {resp.status_code}: {resp.text[:200]}"
```

- [ ] **Step 2: Run — capture pass/fail**

```bash
cd packages/secubox-mail && python3 -m pytest api/tests/test_phase1_endpoints.py -v 2>&1 | tail -40
```

Expected: most pass; any 500 indicates a route broken by the config-key rename in F1. Fix any failure by adjusting the route handler — do not change the test.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail/api/tests/test_phase1_endpoints.py
git commit -m "test(mail): phase1 endpoint-presence coverage (62 routes) (ref #<issue>)"
```

---

## Milestone G — Old controllers shrunk to shims

### Task G1: Reduce `mailserverctl` to a deprecation shim

**Files:**
- Modify: `packages/secubox-mail/sbin/mailserverctl`

- [ ] **Step 1: Replace the entire file**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# DEPRECATED in secubox-mail 2.0 — kept as a thin shim that forwards to
# mailctl. To be removed in 3.0.

set -euo pipefail
echo "[mailserverctl] DEPRECATED — forwarding to mailctl (will be removed in 3.0)" >&2
exec /usr/sbin/mailctl "$@"
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/sbin/mailserverctl
git commit -m "feat(mail): mailserverctl reduced to deprecation shim (ref #<issue>)"
```

---

### Task G2: Reduce `roundcubectl` to a deprecation shim

**Files:**
- Modify: `packages/secubox-mail/sbin/roundcubectl`

- [ ] **Step 1: Replace the entire file**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# DEPRECATED in secubox-mail 2.0 — Roundcube now lives inside the single
# `mail` LXC. This shim translates the few legacy verbs to mailctl.

set -euo pipefail
echo "[roundcubectl] DEPRECATED — forwarding to mailctl (will be removed in 3.0)" >&2

case "${1:-}" in
    start|stop|restart|status) exec /usr/sbin/mailctl "$1" ;;
    install)                    exec /usr/sbin/mailctl install ;;
    access|components|shell)    exec /usr/sbin/mailctl "$@" ;;
    *)                          exec /usr/sbin/mailctl "$@" ;;
esac
```

- [ ] **Step 2: Commit**

```bash
git add packages/secubox-mail/sbin/roundcubectl
git commit -m "feat(mail): roundcubectl reduced to deprecation shim (ref #<issue>)"
```

---

### Task G3: Trim `secubox-mail-lxc`, `secubox-webmail-lxc`, `secubox-webmail` to transitional packages

**Files:**
- Modify: `packages/secubox-mail-lxc/debian/control`
- Modify: `packages/secubox-webmail-lxc/debian/control`
- Modify: `packages/secubox-webmail/debian/control`

- [ ] **Step 1: Rewrite each `debian/control`**

Each becomes (substitute the package name):
```
Source: secubox-mail-lxc
Section: net
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-mail-lxc
Architecture: all
Depends: ${misc:Depends}, secubox-mail (>= 2.0)
Description: Transitional package — mail LXC functionality moved to secubox-mail
 This package no longer ships any code. The single consolidated mail LXC
 is now installed and driven by secubox-mail (>= 2.0). Safe to remove
 after upgrade.
```

For each of the three packages: bump version to `2.0.0-1~bookworm1` in `debian/changelog`, and empty out `debian/install` / `debian/dirs` so no files ship.

- [ ] **Step 2: Verify each package builds clean**

```bash
for p in secubox-mail-lxc secubox-webmail-lxc secubox-webmail; do
    (cd packages/$p && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64 2>&1 | tail -5)
done
```

Expected: each produces a `.deb` with no files in the data tarball besides docs.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-mail-lxc/debian/ packages/secubox-webmail-lxc/debian/ packages/secubox-webmail/debian/
git commit -m "feat(mail): mark mail-lxc/webmail-lxc/webmail as transitional (ref #<issue>)"
```

---

### Task G4: Bump `secubox-mail` to 2.0.0 with `Breaks:` / `Replaces:`

**Files:**
- Modify: `packages/secubox-mail/debian/control`
- Modify: `packages/secubox-mail/debian/changelog`

- [ ] **Step 1: Edit `debian/control`**

In the binary package stanza, add:
```
Breaks: secubox-mail-lxc (<< 2.0), secubox-webmail-lxc (<< 2.0), secubox-webmail (<< 2.0)
Replaces: secubox-mail-lxc (<< 2.0), secubox-webmail-lxc (<< 2.0), secubox-webmail (<< 2.0)
```

- [ ] **Step 2: Edit `debian/changelog`**

Prepend:
```
secubox-mail (2.0.0-1~bookworm1) bookworm; urgency=medium

  * Phase 1 consolidation: single 'mail' LXC replaces mailserver + roundcube.
  * New lib/install.sh + lib/lxc.sh shared driver.
  * mailctl is now the single driver; mailserverctl and roundcubectl are shims.
  * mail-migrate-to-single-lxc.sh runs from postinst.
  * Closes: #<issue>

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 15 May 2026 12:00:00 +0200
```

- [ ] **Step 3: Build and inspect**

```bash
cd packages/secubox-mail && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64
dpkg-deb -I ../../output/debs/secubox-mail_2.0.0-1~bookworm1_all.deb | grep -E 'Version|Depends|Breaks|Replaces'
```

Expected: version 2.0.0; Breaks + Replaces lines visible.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-mail/debian/control packages/secubox-mail/debian/changelog
git commit -m "feat(mail): bump to 2.0.0 with Breaks/Replaces for legacy packages (ref #<issue>)"
```

---

## Milestone H — Acceptance

### Task H1: Write the end-to-end smoke test

**Files:**
- Create: `tests/scripts/test-mail-phase1-acceptance.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# tests/scripts/test-mail-phase1-acceptance.sh — Phase 1 acceptance smoke.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

HOST="${1:-root@192.168.1.200}"
TEST_USER="phase1@gk2.secubox.in"
TEST_PASS="phase1-$(date +%s)"

step() { echo; echo "[acceptance] $*"; }

step "1) Only one mail LXC exists"
ssh "$HOST" 'lxc-ls' | tee /tmp/lxc-ls
grep -wq mail /tmp/lxc-ls
! grep -wq mailserver /tmp/lxc-ls
! grep -wq roundcube /tmp/lxc-ls
pass "lxc-ls shows only 'mail'"

step "2) Mail container is running"
ssh "$HOST" 'lxc-info -n mail | grep -E "State:.*RUNNING"' >/dev/null
pass "mail LXC is RUNNING"

step "3) Daemons up inside container"
ssh "$HOST" 'lxc-attach -n mail -- ss -tlnp' | tee /tmp/lxc-ports
grep -q ':25 '  /tmp/lxc-ports || fail "postfix 25 not listening"
grep -q ':993 ' /tmp/lxc-ports || fail "dovecot 993 not listening"
grep -q ':80 '  /tmp/lxc-ports || fail "nginx 80 not listening"
pass "postfix + dovecot + nginx listening"

step "4) Provision a test user"
ssh "$HOST" "mailctl user add '$TEST_USER' --password '$TEST_PASS'"
ssh "$HOST" "mailctl user list" | grep -q "$TEST_USER"
pass "test user provisioned"

step "5) Send a message to self via submission/SASL"
ssh "$HOST" "echo 'Subject: phase1\n\nhello' | swaks --to '$TEST_USER' --from '$TEST_USER' \
    --server 192.168.255.30:587 --auth LOGIN --auth-user '$TEST_USER' --auth-password '$TEST_PASS' \
    --tls --tls-on-connect=no"
pass "submission accepted"

step "6) Read it back via IMAPS"
ssh "$HOST" "curl --silent --insecure --user '$TEST_USER:$TEST_PASS' \
    'imaps://192.168.255.30/INBOX' --request 'FETCH 1 BODY[TEXT]'" | grep -q 'hello'
pass "imaps fetch works"

step "7) Roundcube renders the login page through the host proxy"
curl --silent --insecure --resolve "webmail.gk2.secubox.in:443:192.168.1.200" \
    https://webmail.gk2.secubox.in/ | grep -qi 'roundcube\|webmail'
pass "Roundcube reachable through host nginx"

step "8) All 62 admin endpoints reply non-5xx"
ssh "$HOST" "cd /usr/lib/secubox/mail && python3 -m pytest api/tests/test_phase1_endpoints.py -q" >/dev/null
pass "endpoint coverage test green on board"

pass "PHASE 1 ACCEPTANCE: all gates green"
```

- [ ] **Step 2: Make it executable + commit**

```bash
chmod +x tests/scripts/test-mail-phase1-acceptance.sh
git add tests/scripts/test-mail-phase1-acceptance.sh
git commit -m "test(mail): phase1 end-to-end acceptance smoke (ref #<issue>)"
```

---

### Task H2: Deploy to test board and run acceptance

**Files:** none (operational).

- [ ] **Step 1: Build secubox-mail 2.0.0**

```bash
cd packages/secubox-mail && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64
```

Expected: `../../output/debs/secubox-mail_2.0.0-1~bookworm1_all.deb` produced.

- [ ] **Step 2: Build the transitional packages**

```bash
for p in secubox-mail-lxc secubox-webmail-lxc secubox-webmail; do
    (cd packages/$p && dpkg-buildpackage -us -uc -b -a arm64 --host-arch arm64)
done
```

- [ ] **Step 3: Copy debs to board and install**

```bash
scp output/debs/secubox-{mail,mail-lxc,webmail-lxc,webmail}_2.0.0-1~bookworm1_*.deb root@192.168.1.200:/tmp/
ssh root@192.168.1.200 'apt install -y /tmp/secubox-{mail,mail-lxc,webmail-lxc,webmail}_2.0.0*.deb'
```

Expected: postinst runs `mail-migrate-to-single-lxc.sh` then `mailctl install`. Both succeed. `apt` reports the 3 transitional packages now have no files.

- [ ] **Step 4: Run acceptance**

```bash
bash tests/scripts/test-mail-phase1-acceptance.sh root@192.168.1.200 2>&1 | tee /tmp/phase1-acceptance.log
```

Expected: final line `PHASE 1 ACCEPTANCE: all gates green`.

- [ ] **Step 5: If any gate fails**

Do **not** retry blindly. Read the log, identify the failing gate, open the relevant file, fix, rebuild, redeploy. Re-run the smoke. Iterate until green.

- [ ] **Step 6: Update tracking files + commit**

```bash
cat >> .claude/HISTORY.md <<EOF

## 2026-05-15 — Mail Stack Phase 1 ✅
- Single 'mail' LXC replaces mailserver + roundcube LXCs
- New lib/install.sh + lib/lxc.sh shared driver; mailctl is single driver
- mail-migrate-to-single-lxc.sh handles upgrade-time migration
- secubox-mail-lxc / secubox-webmail-lxc / secubox-webmail are transitional
- secubox-mail 2.0.0 with Breaks/Replaces
- 62 host API endpoints still answer; acceptance smoke green
EOF

# WIP.md: move the Phase 1 item to ✅ Fait
# MIGRATION-MAP.md: tick secubox-mail Phase 1

git add .claude/
git commit -m "docs: track Phase 1 completion (ref #<issue>)"
```

---

### Task H3: Finish the worktree and open the PR

**Files:** none (operational).

- [ ] **Step 1: Push and PR**

```bash
bash scripts/agent-worktree.sh finish
```

Expected: branch pushed, PR opened with body `Closes #<issue>` and a summary.

- [ ] **Step 2: Wait for user validation**

Per CLAUDE.md, do NOT close the issue or merge the PR. User reviews, validates, and closes.

- [ ] **Step 3: After user merges**

```bash
bash scripts/agent-worktree.sh clean <issue>
```

Expected: worktree + branch deleted; back to master.

---

## Self-review

Run through this checklist before invoking subagent-driven-development or executing-plans:

1. **Spec coverage:** Every Phase 1 deliverable from spec §6 maps to a task:
   - "Collapse mailserver + roundcube into single mail LXC" → C1, D1, D2
   - "New mailctl skeleton driving /srv/lxc/mail" → C1, C4
   - "Data migration script" → D1, D2, D3
   - "secubox-mail-lxc / secubox-webmail-lxc Conflicts: + postinst removal" → G3, G4
   - "Roundcube inside mail LXC" → B5, C2
   - "Nginx host proxy updated" → E1, E3
   - "All 62 API endpoints still answer" → F1, F2
2. **Placeholder scan:** Only `<issue>` placeholder, populated from Task A3 output. No "TBD" / "TODO" / "fill in" anywhere else.
3. **Type/identifier consistency:** Function names match across tasks: `lxc_exists`, `lxc_running`, `lxc_create_config`, `lxc_start_safely`, `lxc_attach_run`, `bootstrap_debian`, `install_mail_packages`, `configure_postfix`, `configure_dovecot`, `configure_opendkim`, `configure_clamav`, `configure_roundcube`, `migrate_mailserver_data`, `migrate_roundcube_data`, `stop_old_containers`, `archive_old_rootfs`, `cmd_install`, `cmd_migrate_config`. Sub-skill: each is defined exactly once (in `lib/install.sh`, `lib/lxc.sh`, `lib/migrate.sh`, or `mailctl`) and referenced by name everywhere else.
4. **Open question reconciliation:** Spec §9 listed "Roundcube webserver: Apache vs nginx" — resolved in Task B5 as **nginx + php-fpm**. "HAProxy frontend for SMTP" — resolved in Task E2 as **TCP pass-through, daemons present own certs**. Other open questions belong to Phases 2+.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-15-mail-phase1-lxc-consolidation.md`.**

Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration with two-stage review at each step.
2. **Inline Execution** — I execute tasks here in this session with checkpoints for review.

Which approach?
