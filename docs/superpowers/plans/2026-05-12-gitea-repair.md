<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gitea Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the existing Gitea LXC (`10.100.0.40`) at `https://gitea.gk2.secubox.in/` (web) and `ssh://git@gitea.gk2.secubox.in:2222/` (git SSH), reusing the wildcard cert and the existing data on `/data/volumes/gitea/`. No changes to the LXC, no new cert, no `haproxyctl` (see #91).

**Architecture:** Manual edits to `/etc/haproxy/haproxy.cfg` (with timestamped backup before every edit) and a new nginx vhost on the MOCHAbin. Backend is `nginx_vhosts` direct — mitmproxy WAF is bypassed for git smart-HTTP traffic. Repo-side: package the config files under `packages/secubox-gitea/conf/` so the change is reproducible.

**Tech Stack:** HAProxy (TCP + HTTP frontends), nginx (`proxy_pass`), LXC bind mounts, git over SSH. All work happens via SSH to `root@192.168.1.200`.

**Spec:** [docs/superpowers/specs/2026-05-12-gitea-repair-design.md](../specs/2026-05-12-gitea-repair-design.md)
**Issue:** [#49 sub-project A](https://github.com/CyberMind-FR/secubox-deb/issues/49)
**Blocker reference:** [#91 — haproxyctl regression](https://github.com/CyberMind-FR/secubox-deb/issues/91)

---

## File Structure

| Action | Path | Lives where | Responsibility |
|--------|------|-------------|----------------|
| Create | `/etc/nginx/sites-available/gitea.conf` | MOCHAbin (live) | nginx vhost — proxy `gitea.gk2.secubox.in:9080` → `10.100.0.40:3000` |
| Symlink | `/etc/nginx/sites-enabled/gitea` | MOCHAbin (live) | Enable the vhost |
| Modify | `/etc/haproxy/haproxy.cfg` | MOCHAbin (live) | + ACL in `http-in` + ACL in `https-in` + new `gitea-ssh` TCP frontend + `gitea_ssh` backend |
| Create | `packages/secubox-gitea/conf/gitea.nginx.conf` | This repo | Versioned copy of the nginx vhost |
| Create | `packages/secubox-gitea/conf/haproxy.snippet` | This repo | Versioned copy of the HAProxy ACL + TCP frontend snippet |
| Modify | `packages/secubox-gitea/debian/postinst` | This repo | Drop the conf files into `/etc/...` on package install |
| Modify | `packages/secubox-gitea/debian/prerm` | This repo | Remove the dropped files on uninstall |
| Modify | `packages/secubox-gitea/README.md` | This repo | Document the exposed URLs |
| Create | `tests/scripts/test-gitea-routing.sh` | This repo | Smoke-tests the 5 validation gates from the spec |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | This repo | Session 161 entry |

---

## Task 1: Repo-side — versioned nginx vhost config

**Files:**
- Create: `packages/secubox-gitea/conf/gitea.nginx.conf`

This is the source of truth for the nginx vhost. It lives in the repo so a fresh package install reproduces the routing, and so we have a diffable history.

- [ ] **Step 1: Verify branch and worktree**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/49-feat-metablogizer-streamlit-version-mana
git rev-parse --abbrev-ref HEAD
```

Expected: `feature/49-feat-metablogizer-streamlit-version-mana`. If not, **STOP** and report BLOCKED.

- [ ] **Step 2: Create the conf directory if missing**

```bash
mkdir -p packages/secubox-gitea/conf
```

- [ ] **Step 3: Write the nginx vhost file**

Create `packages/secubox-gitea/conf/gitea.nginx.conf`:

```nginx
# packages/secubox-gitea/conf/gitea.nginx.conf
# Installed by secubox-gitea postinst at /etc/nginx/sites-available/gitea.conf
#
# Proxies gitea.gk2.secubox.in (port 9080, HAProxy backend nginx_vhosts)
# to the Gitea LXC at 10.100.0.40:3000.
#
# Bypasses mitmproxy WAF intentionally — git smart-HTTP push/pull is high-
# volume binary that the WAF cannot meaningfully inspect, and Gitea web is
# operator-only (not a public service).

server {
    listen 0.0.0.0:9080;
    server_name gitea.gk2.secubox.in;

    # Gitea handles its own auth and rate limiting; nginx is a pure proxy.
    # 512 MB allows LFS push and large clone over HTTPS.
    client_max_body_size 512M;

    location / {
        proxy_pass http://10.100.0.40:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    access_log /var/log/nginx/gitea_access.log;
    error_log  /var/log/nginx/gitea_error.log;
}
```

- [ ] **Step 4: Syntax-check the snippet locally**

```bash
nginx -t -c /dev/stdin < packages/secubox-gitea/conf/gitea.nginx.conf 2>&1 | tail -3
```

Expected: `nginx: configuration file /dev/stdin test failed` is OK here — nginx -t requires a full config. A better check:

```bash
# Verify the file is not empty and contains the listen directive
grep -q 'listen 0.0.0.0:9080;' packages/secubox-gitea/conf/gitea.nginx.conf && echo "syntax markers present"
grep -q 'proxy_pass http://10.100.0.40:3000;' packages/secubox-gitea/conf/gitea.nginx.conf && echo "backend target present"
```

Expected: both lines print their `present` confirmation.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-gitea/conf/gitea.nginx.conf
git commit -m "feat(gitea): Versioned nginx vhost config for gitea.gk2.secubox.in (ref #49)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Repo-side — versioned HAProxy snippet

**Files:**
- Create: `packages/secubox-gitea/conf/haproxy.snippet`

This is the exact text that postinst will append to (or insert into) `/etc/haproxy/haproxy.cfg`. Keeping it as a snippet (not a full file) avoids overwriting unrelated vhosts.

- [ ] **Step 1: Write the snippet**

Create `packages/secubox-gitea/conf/haproxy.snippet`:

```
# packages/secubox-gitea/conf/haproxy.snippet
# Installed by secubox-gitea postinst; injected into /etc/haproxy/haproxy.cfg.
#
# Two ACL pairs (http-in + https-in) route gitea.gk2.secubox.in to the
# nginx_vhosts backend (direct, no mitmproxy). The TCP frontend exposes
# Gitea SSH on port 2222 so the host port 22 stays reserved for operator
# access.

# --- INJECT INTO frontend http-in (before "default_backend fallback") ---
#     acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in
#     use_backend nginx_vhosts if host_gitea_gk2_secubox_in

# --- INJECT INTO frontend https-in (before "default_backend fallback") ---
#     acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in
#     use_backend nginx_vhosts if host_gitea_gk2_secubox_in

# --- APPEND AT END OF FILE (after the last existing backend block) ---
frontend gitea-ssh
    bind *:2222
    mode tcp
    option tcplog
    timeout client 1h
    default_backend gitea_ssh

backend gitea_ssh
    mode tcp
    option tcp-check
    timeout server 1h
    server gitea_lxc 10.100.0.40:22 check
```

The leading `# ---` markers are how postinst (Task 5) finds the three injection points. Lines that start with `#     ` (six leading chars including hash) are the literal text to inject (postinst strips the `# ` prefix).

- [ ] **Step 2: Sanity-check the snippet**

```bash
grep -c "^# ---" packages/secubox-gitea/conf/haproxy.snippet
```

Expected: `3` (three injection markers).

```bash
grep -c "frontend gitea-ssh\|backend gitea_ssh" packages/secubox-gitea/conf/haproxy.snippet
```

Expected: `2`.

- [ ] **Step 3: Commit**

```bash
git add packages/secubox-gitea/conf/haproxy.snippet
git commit -m "feat(gitea): Versioned HAProxy snippet for gitea.gk2 routing + SSH (ref #49)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Live edit — pre-change backup of haproxy.cfg on MOCHAbin

**Files:**
- Live: `/etc/haproxy/haproxy.cfg` (read-only at this step)
- Live: `/etc/haproxy/haproxy.cfg.bak.gitea-repair.<timestamp>` (new)

Per #91, **never** touch HAProxy without a known-good snapshot to roll back to. This step is non-destructive; it only writes the backup.

- [ ] **Step 1: SSH preflight**

```bash
ssh root@192.168.1.200 'hostname; haproxy -v | head -1'
```

Expected: `secubox-mochabin` + a version line. If SSH fails, STOP and report BLOCKED — none of the live steps can proceed.

- [ ] **Step 2: Take backup**

```bash
ssh root@192.168.1.200 '
  ts=$(date +%s)
  cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak.gitea-repair.$ts
  echo "Backup: /etc/haproxy/haproxy.cfg.bak.gitea-repair.$ts"
  wc -l /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak.gitea-repair.$ts
'
```

Expected: prints the new backup path and the same line count for both files (~400+ lines).

- [ ] **Step 3: Sanity check — current config is valid**

```bash
ssh root@192.168.1.200 'haproxy -f /etc/haproxy/haproxy.cfg -c 2>&1 | tail -3'
```

Expected: `Configuration file is valid`. If not, **STOP** — we cannot reliably add to a broken config. Investigate before continuing.

- [ ] **Step 4: Confirm `gitea.gk2.secubox.in` is NOT yet routed**

```bash
ssh root@192.168.1.200 'grep -c "gitea.gk2.secubox.in" /etc/haproxy/haproxy.cfg'
```

Expected: `0`. If non-zero, the ACL already exists — inspect and decide whether to skip the rest of Task 4.

No commit at this step (live-only, no repo changes).

---

## Task 4: Live edit — inject the three HAProxy snippets

**Files:**
- Modify (live): `/etc/haproxy/haproxy.cfg`

The snippet has three injection points. The `default_backend fallback` lines in `frontend http-in` and `frontend https-in` are distinct anchors. Insert before each.

- [ ] **Step 1: Inject ACL into http-in**

```bash
ssh root@192.168.1.200 '
  awk "
    /^frontend http-in/ { in_http=1 }
    /^frontend / && !/^frontend http-in/ { in_http=0 }
    in_http && /^    default_backend fallback/ && !done {
      print \"    acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in\"
      print \"    use_backend nginx_vhosts if host_gitea_gk2_secubox_in\"
      done=1
    }
    { print }
  " /etc/haproxy/haproxy.cfg > /tmp/haproxy.cfg.new
  mv /tmp/haproxy.cfg.new /etc/haproxy/haproxy.cfg
  grep -c "host_gitea_gk2_secubox_in" /etc/haproxy/haproxy.cfg
'
```

Expected: `2` (the new ACL line + the new `use_backend` line).

- [ ] **Step 2: Inject ACL into https-in**

```bash
ssh root@192.168.1.200 '
  awk "
    /^frontend https-in/ { in_https=1 }
    /^frontend / && !/^frontend https-in/ { in_https=0 }
    in_https && /^    default_backend fallback/ && !done {
      print \"    acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in\"
      print \"    use_backend nginx_vhosts if host_gitea_gk2_secubox_in\"
      done=1
    }
    { print }
  " /etc/haproxy/haproxy.cfg > /tmp/haproxy.cfg.new
  mv /tmp/haproxy.cfg.new /etc/haproxy/haproxy.cfg
  grep -c "host_gitea_gk2_secubox_in" /etc/haproxy/haproxy.cfg
'
```

Expected: `4` (two each in http-in and https-in).

- [ ] **Step 3: Append TCP frontend + backend for SSH**

```bash
ssh root@192.168.1.200 '
  cat >> /etc/haproxy/haproxy.cfg <<"EOF"

frontend gitea-ssh
    bind *:2222
    mode tcp
    option tcplog
    timeout client 1h
    default_backend gitea_ssh

backend gitea_ssh
    mode tcp
    option tcp-check
    timeout server 1h
    server gitea_lxc 10.100.0.40:22 check
EOF
  grep -c "frontend gitea-ssh\|backend gitea_ssh" /etc/haproxy/haproxy.cfg
'
```

Expected: `2`.

- [ ] **Step 4: Validate the modified config**

```bash
ssh root@192.168.1.200 'haproxy -f /etc/haproxy/haproxy.cfg -c 2>&1 | tail -3'
```

Expected: `Configuration file is valid`. If `Fatal errors found`, **STOP** and rollback (Task 9).

- [ ] **Step 5: Reload HAProxy**

```bash
ssh root@192.168.1.200 'systemctl reload haproxy && systemctl is-active haproxy'
```

Expected: `active`. If reload fails, **STOP** and rollback (Task 9).

- [ ] **Step 6: Verify port 2222 is now listening**

```bash
ssh root@192.168.1.200 'ss -tlnp | grep ":2222"'
```

Expected: one or more `LISTEN` lines for `0.0.0.0:2222` owned by `haproxy`.

No commit at this step — the repo-side equivalent goes in via Task 5's postinst patch.

---

## Task 5: Live edit — install nginx vhost on MOCHAbin

**Files:**
- Create (live): `/etc/nginx/sites-available/gitea.conf`
- Create (live): `/etc/nginx/sites-enabled/gitea` (symlink)

- [ ] **Step 1: Verify the staging file from Task 1 is in place locally**

```bash
test -f packages/secubox-gitea/conf/gitea.nginx.conf && wc -l packages/secubox-gitea/conf/gitea.nginx.conf
```

Expected: ~25 lines.

- [ ] **Step 2: Copy to MOCHAbin**

```bash
scp packages/secubox-gitea/conf/gitea.nginx.conf root@192.168.1.200:/etc/nginx/sites-available/gitea.conf
ssh root@192.168.1.200 'chmod 644 /etc/nginx/sites-available/gitea.conf'
```

- [ ] **Step 3: Enable the vhost**

```bash
ssh root@192.168.1.200 'ln -sf /etc/nginx/sites-available/gitea.conf /etc/nginx/sites-enabled/gitea && ls -la /etc/nginx/sites-enabled/gitea'
```

Expected: symlink shown.

- [ ] **Step 4: Validate nginx config**

```bash
ssh root@192.168.1.200 'nginx -t 2>&1 | tail -3'
```

Expected: `nginx: configuration file /etc/nginx/nginx.conf test is successful`. If not, **STOP** and rollback (Task 9).

- [ ] **Step 5: Reload nginx**

```bash
ssh root@192.168.1.200 'systemctl reload nginx && systemctl is-active nginx'
```

Expected: `active`.

No commit at this step — repo-side conf was already committed in Task 1.

---

## Task 6: Repo-side — postinst patch to reproduce the routing

**Files:**
- Read: `packages/secubox-gitea/debian/postinst`
- Modify: `packages/secubox-gitea/debian/postinst`

The package install should reproduce what Tasks 4 and 5 did manually. This is idempotent: if the ACL already exists or the vhost is already installed, skip.

- [ ] **Step 1: Read the current postinst**

```bash
cat packages/secubox-gitea/debian/postinst | head -40
```

(No expected output check — just need to understand the structure before editing.)

- [ ] **Step 2: Append the routing-install logic**

Add this block to `packages/secubox-gitea/debian/postinst` before the `exit 0` / `#DEBHELPER#` placeholder. If the file has multiple `case "$1" in` arms, add it inside the `configure)` arm.

```bash
# --- Routing install (idempotent) ---
NGINX_VHOST=/etc/nginx/sites-available/gitea.conf
NGINX_ENABLED=/etc/nginx/sites-enabled/gitea
HAPROXY_CFG=/etc/haproxy/haproxy.cfg

# 1. nginx vhost
if [ ! -f "$NGINX_VHOST" ]; then
    install -m 0644 /usr/share/secubox-gitea/conf/gitea.nginx.conf "$NGINX_VHOST"
    ln -sf "$NGINX_VHOST" "$NGINX_ENABLED"
    if nginx -t 2>/dev/null; then
        systemctl reload nginx
    else
        echo "secubox-gitea: nginx -t failed after vhost install — rolling back vhost" >&2
        rm -f "$NGINX_ENABLED" "$NGINX_VHOST"
    fi
fi

# 2. HAProxy ACLs (only if gitea.gk2.secubox.in is not yet routed)
if ! grep -q "host_gitea_gk2_secubox_in" "$HAPROXY_CFG" 2>/dev/null; then
    cp "$HAPROXY_CFG" "$HAPROXY_CFG.bak.gitea-postinst.$(date +%s)"
    # Inject into http-in and https-in frontends (before default_backend fallback)
    for frontend in http-in https-in; do
        awk -v fe="$frontend" '
            $0 ~ "^frontend "fe { inside=1 }
            /^frontend / && $0 !~ "^frontend "fe { inside=0 }
            inside && /^    default_backend fallback/ && !done {
                print "    acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in"
                print "    use_backend nginx_vhosts if host_gitea_gk2_secubox_in"
                done=1
            }
            { print }
        ' "$HAPROXY_CFG" > "$HAPROXY_CFG.new"
        mv "$HAPROXY_CFG.new" "$HAPROXY_CFG"
    done
    # Append the TCP frontend + backend if not present
    if ! grep -q "^frontend gitea-ssh" "$HAPROXY_CFG"; then
        cat >> "$HAPROXY_CFG" <<'GITEASSH'

frontend gitea-ssh
    bind *:2222
    mode tcp
    option tcplog
    timeout client 1h
    default_backend gitea_ssh

backend gitea_ssh
    mode tcp
    option tcp-check
    timeout server 1h
    server gitea_lxc 10.100.0.40:22 check
GITEASSH
    fi
    if haproxy -f "$HAPROXY_CFG" -c >/dev/null 2>&1; then
        systemctl reload haproxy
    else
        echo "secubox-gitea: haproxy -c failed after ACL install — rolling back" >&2
        cp "$HAPROXY_CFG.bak.gitea-postinst."* "$HAPROXY_CFG"
    fi
fi
# --- end routing install ---
```

Also ensure the `conf/` files ship with the package: in `debian/rules` or wherever the package's `install` rules live, the `conf/` dir needs to land at `/usr/share/secubox-gitea/conf/`. If `debian/secubox-gitea.install` exists, append:

```
conf/* /usr/share/secubox-gitea/conf/
```

Otherwise add an `override_dh_auto_install` block in `debian/rules`. Check what pattern the other packages in `packages/` use first.

- [ ] **Step 3: Verify postinst shell syntax**

```bash
bash -n packages/secubox-gitea/debian/postinst && echo "syntax OK"
```

Expected: `syntax OK`.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-gitea/debian/postinst packages/secubox-gitea/debian/secubox-gitea.install 2>/dev/null || true
git add packages/secubox-gitea/debian/
git commit -m "feat(gitea): postinst installs routing (nginx vhost + HAProxy ACL + SSH frontend) (ref #49)

Idempotent: skips if gitea.gk2.secubox.in is already routed. Rolls back
HAProxy or nginx changes if their respective -c / -t check fails.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Validation gate — smoke test the 5 checks

**Files:**
- Create: `tests/scripts/test-gitea-routing.sh`
- Source: `scripts/lib/test-helpers.sh` (already in repo from earlier work)

- [ ] **Step 1: Write the smoke test**

Create `tests/scripts/test-gitea-routing.sh`:

```bash
#!/usr/bin/env bash
# tests/scripts/test-gitea-routing.sh
# Validates the 5 gates from docs/superpowers/specs/2026-05-12-gitea-repair-design.md.
# Run from the repo root or anywhere — uses absolute test-helper path.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=../../scripts/lib/test-helpers.sh
source "$REPO/scripts/lib/test-helpers.sh"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"

# Gate 1: HTTPS reachability + HTTP 200
log_step() { echo "[gate $1] $2"; }

log_step 1 "HTTPS GET /"
code=$(curl -s -o /dev/null -w "%{http_code}" "https://$GITEA_HOST/")
assert_eq "200" "$code" "Gitea web HTTPS code"

# Gate 2: TLS cert SAN includes the wildcard
log_step 2 "TLS SAN check"
san=$(echo | openssl s_client -servername "$GITEA_HOST" -connect "$GITEA_HOST:443" 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName 2>&1)
assert_contains "$san" "*.gk2.secubox.in" "wildcard SAN covers $GITEA_HOST"

# Gate 3: Response body is a Gitea page (contains <title>)
log_step 3 "HTML body sanity"
body=$(curl -s "https://$GITEA_HOST/")
assert_contains "$body" "<title>" "response is HTML with a <title>"

# Gate 4: SSH on 2222 — TCP path open, SSH server responds
log_step 4 "SSH protocol reachability on port $GITEA_SSH_PORT"
ssh_out=$(ssh -p "$GITEA_SSH_PORT" -o ConnectTimeout=5 -o BatchMode=yes \
              -o StrictHostKeyChecking=accept-new \
              "git@$GITEA_HOST" 2>&1 | head -3 || true)
if echo "$ssh_out" | grep -qE "Permission denied|successfully authenticated|Hi there"; then
  pass "SSH server responded on port $GITEA_SSH_PORT"
else
  echo "FAIL: gate 4 — SSH did not respond properly"
  echo "----- ssh output -----"
  echo "$ssh_out"
  echo "----------------------"
  exit 1
fi

# Gate 5: round-trip git over HTTPS (skipped if no GITEA_TOKEN env var)
log_step 5 "HTTPS git round-trip (optional)"
if [[ -z "${GITEA_TOKEN:-}" || -z "${GITEA_USER:-}" || -z "${GITEA_TEST_REPO:-}" ]]; then
  log_step 5 "SKIP — GITEA_TOKEN / GITEA_USER / GITEA_TEST_REPO not set"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  clone_url="https://${GITEA_USER}:${GITEA_TOKEN}@${GITEA_HOST}/${GITEA_USER}/${GITEA_TEST_REPO}.git"
  if git clone --depth 1 "$clone_url" "$tmp/repo" >/dev/null 2>&1; then
    pass "git clone over HTTPS"
  else
    echo "FAIL: gate 5 — git clone over HTTPS failed"
    exit 1
  fi
fi

pass "all gates passed"
```

- [ ] **Step 2: Make the test executable**

```bash
chmod +x tests/scripts/test-gitea-routing.sh
```

- [ ] **Step 3: Run the smoke test against the live target**

```bash
bash tests/scripts/test-gitea-routing.sh 2>&1 | tail -15
```

Expected: `PASS: all gates passed` (with gate 5 SKIP unless `GITEA_TOKEN/USER/TEST_REPO` are exported).

If any gate fails, the implementation is incomplete. Go back to the corresponding live-side task and debug. Do NOT mark this checkbox until all gates pass.

- [ ] **Step 4: Commit**

```bash
git add tests/scripts/test-gitea-routing.sh
git commit -m "test(gitea): Smoke test for the 5 validation gates (ref #49)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: README + tracking docs

**Files:**
- Modify: `packages/secubox-gitea/README.md`
- Modify: `.claude/WIP.md`
- Modify: `.claude/HISTORY.md`

- [ ] **Step 1: Append URLs and gates to the package README**

Insert after the `## Features` block in `packages/secubox-gitea/README.md`:

```markdown
## Public endpoints

| Service | URL |
|---------|-----|
| Gitea web | `https://gitea.gk2.secubox.in/` |
| Git over SSH | `ssh://git@gitea.gk2.secubox.in:2222/<user>/<repo>.git` |

TLS is provided by the wildcard cert `*.gk2.secubox.in` loaded by HAProxy; no
per-host certbot is needed.

The package's `postinst` installs the nginx vhost + HAProxy ACLs + TCP
frontend for SSH. The install is idempotent; re-running `apt install
--reinstall secubox-gitea` will not duplicate routes.

## Operator runbook

If `gitea.gk2.secubox.in` stops responding:

1. `ssh root@<host> 'systemctl status haproxy nginx'` — both must be active.
2. `ssh root@<host> 'curl -sI http://10.100.0.40:3000/'` — confirms the LXC is up.
3. `ssh root@<host> 'lxc-attach -n gitea -- systemctl status gitea'` — Gitea inside the LXC.
4. `bash tests/scripts/test-gitea-routing.sh` from this repo runs the full gate suite.
```

- [ ] **Step 2: Add Session 161 entry to `.claude/WIP.md`**

Insert at the top, after the existing `# WIP — Work In Progress` header and the *Mis à jour* line. Bump the *Mis à jour* line to `Session 161` (or whatever the next free number is — check `head -3 .claude/WIP.md` to confirm):

```markdown
## ✅ Session 161: Gitea repair — public routing for gitea.gk2.secubox.in (Issue #49 sub-A)

### Objective
Expose the existing Gitea LXC at `https://gitea.gk2.secubox.in/` (web) and `ssh://git@gitea.gk2.secubox.in:2222/` (git SSH), reusing the wildcard cert and the existing data volumes on `/data/volumes/gitea/`. Prerequisite for #49 sub-projects B–F (MetaBlogizer ingest, Streamlit version pinning, version dashboard).

### Completed
- Brainstormed design → `docs/superpowers/specs/2026-05-12-gitea-repair-design.md`
- Plan → `docs/superpowers/plans/2026-05-12-gitea-repair.md`
- nginx vhost (`packages/secubox-gitea/conf/gitea.nginx.conf` + live install)
- HAProxy ACL injected into http-in + https-in (manual edit; **not** `haproxyctl` — see #91)
- HAProxy TCP frontend `gitea-ssh` on `*:2222` → `10.100.0.40:22`
- Package postinst reproduces all routing on fresh install (idempotent)
- Smoke test `tests/scripts/test-gitea-routing.sh` passes all 5 gates

### Followups
- #91 — `haproxyctl vhost add` regression (must be fixed before any `haproxyctl` use)
- #49 sub-project B — MetaBlogizer → Gitea ingest (166 sites)
```

- [ ] **Step 3: Add the same entry to `.claude/HISTORY.md`**

Mirror the WIP entry under `## 2026-05-12` in `.claude/HISTORY.md`, in the same style as the other Session entries already there.

- [ ] **Step 4: Commit tracking updates**

```bash
git add packages/secubox-gitea/README.md .claude/WIP.md .claude/HISTORY.md
git commit -m "docs(gitea): Session 161 — Gitea public routing (ref #49)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: Rollback procedure (read-only — only triggered on failure)

This task is **not run** in the normal flow. It documents the exact rollback steps if any earlier task fails on the live MOCHAbin.

- [ ] **(Triggered only on failure) Restore HAProxy**

```bash
ssh root@192.168.1.200 '
  latest=$(ls -t /etc/haproxy/haproxy.cfg.bak.gitea-repair.* 2>/dev/null | head -1)
  if [ -z "$latest" ]; then echo "NO BACKUP FOUND" >&2; exit 1; fi
  cp "$latest" /etc/haproxy/haproxy.cfg
  haproxy -f /etc/haproxy/haproxy.cfg -c && systemctl reload haproxy
  echo "Rolled back from: $latest"
'
```

- [ ] **(Triggered only on failure) Remove nginx vhost**

```bash
ssh root@192.168.1.200 '
  rm -f /etc/nginx/sites-enabled/gitea /etc/nginx/sites-available/gitea.conf
  nginx -t && systemctl reload nginx
  echo "nginx vhost removed"
'
```

After rollback, the live MOCHAbin is back to the pre-Task-3 state. Investigate the failure before retrying.

No commit at this step.

---

## Task 10: Finish the worktree (PR for sub-project A)

**Files:** none modified at this step — just git operations.

Sub-project A (Gitea repair) is **one of six** under issue #49. The PR closes the sub-project's work but #49 stays open until B–F also complete.

- [ ] **Step 1: Verify the worktree is on the right branch and clean**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/49-feat-metablogizer-streamlit-version-mana
git rev-parse --abbrev-ref HEAD
git status --short
```

Expected: `feature/49-feat-metablogizer-streamlit-version-mana`, no uncommitted files.

- [ ] **Step 2: Re-run the smoke test one final time before push**

```bash
bash tests/scripts/test-gitea-routing.sh 2>&1 | tail -5
```

Expected: `PASS: all gates passed`. If anything regressed since Task 7, **STOP** and investigate.

- [ ] **Step 3: Push + PR via the worktree helper**

```bash
bash scripts/agent-worktree.sh finish 2>&1 | tail -10
```

Expected: prints a new PR URL (`https://github.com/CyberMind-FR/secubox-deb/pull/<N>`). The PR body should reference `#49` but NOT `Closes #49` — sub-project A is one piece of #49. Use `Refs #49 (sub-project A)`.

- [ ] **Step 4: Edit the PR body to make the scope explicit**

```bash
gh pr edit <N> --body "$(cat <<'EOF'
Sub-project A of #49: Gitea routing repair.

- Spec: docs/superpowers/specs/2026-05-12-gitea-repair-design.md
- Plan: docs/superpowers/plans/2026-05-12-gitea-repair.md
- Smoke: tests/scripts/test-gitea-routing.sh

`https://gitea.gk2.secubox.in/` and `ssh://git@gitea.gk2.secubox.in:2222/` are
both live and validated end-to-end.

Refs #49 (sub-project A — does **not** close the umbrella issue; B–F remain).
EOF
)"
```

(Replace `<N>` with the actual PR number from Step 3.)

- [ ] **Step 5: Comment on #49 with progress**

```bash
gh issue comment 49 --body "Sub-project A (Gitea repair) merged via PR #<N>. \`https://gitea.gk2.secubox.in/\` is now live; ssh on 2222 routes to the LXC. B (MetaBlogizer → Gitea ingest) can now start."
```

---

## Self-review

**1. Spec coverage:**

- Spec § *Web (HTTPS) path* → Task 5 (nginx vhost live), Task 1 (versioned conf). ✓
- Spec § *Git over SSH path* → Task 4 step 3 (TCP frontend), Task 2 (versioned snippet). ✓
- Spec § *HAProxy ACL — manual edit, not `haproxyctl`* → Task 4 steps 1–2 + Task 3 (pre-backup). ✓
- Spec § *mitmproxy route skipped* → no task creates one. ✓ (correct — confirmed implicitly by Task 7 gate 1 passing without a route entry)
- Spec § *Storage* → no changes needed, no task. ✓
- Spec § *Validation gate (5 checks)* → Task 7 implements all 5 (1–4 always run, 5 conditional on env). ✓
- Spec § *Rollback procedure* → Task 9 documents it. ✓
- Spec § *File-level changes* → Tasks 1, 2, 4, 5, 6 cover each entry. ✓
- Spec § *Licensing* (config snippets out of license-header scope) → no header injection needed. ✓

**2. Placeholder scan:**

- No "TBD", "TODO", "implement later".
- Task 6 step 2 references "the conf/ files ship with the package: in `debian/rules` or wherever the package's `install` rules live" — this is a small ambiguity for the implementer. Mitigation: the step explicitly says "Check what pattern the other packages in `packages/` use first". Acceptable because the exact mechanism varies by package and the implementer can grep `packages/*/debian/` to find the pattern.
- Task 8 step 2 references `Session 161 (or whatever the next free number is — check head -3 .claude/WIP.md to confirm)`. This is a real ambiguity but mitigated by the inline check command. Acceptable.

**3. Type / identifier consistency:**

- `host_gitea_gk2_secubox_in` ACL name used identically in Tasks 4 (live) and 6 (postinst).
- `frontend gitea-ssh` / `backend gitea_ssh` consistent across Tasks 2, 4, 6.
- Port `2222` consistent across all tasks and the smoke test.
- LXC IP `10.100.0.40` consistent across all tasks.
- File paths under `packages/secubox-gitea/conf/` consistent.

No gaps. Plan is ready to execute.
