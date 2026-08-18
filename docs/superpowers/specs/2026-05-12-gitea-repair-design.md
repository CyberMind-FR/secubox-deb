<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Gitea Repair — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49) — sub-project A (Gitea repair, prerequisite for ingest/dashboard)
**Branch:** `feature/49-feat-metablogizer-streamlit-version-mana`

## Context

The Gitea LXC at `10.100.0.40` is running fine and responds with HTTP 200 to a
direct probe on port 3000. The hostname `gitea.gk2.secubox.in` resolves to the
public IP `82.67.100.75` (the MOCHAbin) but returns **502 Bad Gateway** from
mitmproxy because no HAProxy ACL nor mitmproxy route exists for that hostname.
The related `git.gk2.secubox.in` returns 200 but currently serves a static
MetaBlogizer landing page, not the actual Gitea instance.

This is the first sub-project from issue #49. Without a reachable Gitea, the
later sub-projects (ingest of 166 MetaBlogizer sites, deploy webhooks,
Streamlit version pinning) cannot proceed.

## Goal

Expose the existing Gitea LXC at `https://gitea.gk2.secubox.in/` (web) and
`ssh://git@gitea.gk2.secubox.in:2222/` (git over SSH), using the existing
wildcard TLS cert `*.gk2.secubox.in`, without touching the LXC itself or its
data on `/data/volumes/gitea/`.

## Non-goals

- Reconfiguring Gitea (admin account, OAuth, themes — already provisioned)
- Migrating data (it's already on `/data/volumes/gitea/`)
- Replacing the landing page at `git.gk2.secubox.in` (separate decision)
- Issuing a new TLS certificate (wildcard already covers the hostname)
- Routing through mitmproxy WAF (skipped intentionally — see *Architecture* §)

## Current state (verified 2026-05-12)

| Layer | State |
|-------|-------|
| Gitea LXC | RUNNING, IP `10.100.0.40`, web on `:3000`, SSH on `:22`, 60 GB used / 910 GB free |
| LXC bind mounts | `/data/volumes/gitea/repos` → `/var/lib/gitea/repositories`, `/data/volumes/gitea/data` → `/var/lib/gitea` |
| DNS | `gitea.gk2.secubox.in` → `82.67.100.75` (correct) |
| HAProxy ACL | **MISSING** for `gitea.gk2.secubox.in` |
| nginx vhost | **MISSING** for Gitea proxy |
| mitmproxy route | **NULL** for `gitea.gk2.secubox.in` |
| TLS cert | `*.gk2.secubox.in.pem` already loaded by HAProxy — covers this hostname |

## Architecture

### Web (HTTPS) path

```
Client → https://gitea.gk2.secubox.in (TCP 443)
       → HAProxy https-in frontend (TLS termination, wildcard cert)
       → ACL host_gitea_gk2_secubox_in → backend nginx_vhosts → 127.0.0.1:9080
       → nginx vhost `gitea.conf`
       → proxy_pass http://10.100.0.40:3000 (Gitea LXC web)
```

Backend is `nginx_vhosts` (direct), **not** `mitmproxy_inspector`.
Justification:

- Gitea web is for the operator only (internal tooling, not public service).
- Git smart-HTTP traffic is high-volume binary that mitmproxy WAF cannot
  meaningfully inspect.
- The existing `admin.gk2.secubox.in` and most operator vhosts already use
  `nginx_vhosts` in `haproxy.cfg` despite the CLAUDE.md policy line. This
  design follows the actual deployment pattern, not the aspirational one.

### Git over SSH path

```
Client → ssh://git@gitea.gk2.secubox.in:2222
       → HAProxy new TCP frontend `gitea-ssh` on *:2222 mode tcp
       → backend gitea_ssh → 10.100.0.40:22 (Gitea LXC sshd)
```

Port 2222 is chosen because:

- Port 22 is the MOCHAbin host SSHD (reserved for operator access).
- 2222 is the well-known alternate, easy to remember (`-p 2222`).
- HAProxy can do raw TCP proxying without TLS overhead (git wraps its own
  encryption via SSH).

### Storage

No changes. Existing bind mounts continue to provide persistence:

- `/data/volumes/gitea/repos` (repositories, 50 GB+ headroom)
- `/data/volumes/gitea/data` (config, gitea.db, indexers, avatars)

## Components

### 1. nginx vhost — `/etc/nginx/sites-available/gitea.conf`

```nginx
server {
    listen 0.0.0.0:9080;
    server_name gitea.gk2.secubox.in;

    # Gitea handles its own auth and rate limiting; nginx is a pure proxy.
    client_max_body_size 512M;  # allow LFS push, large repo clones over HTTPS

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

Symlink into `sites-enabled/`, `nginx -T`, `systemctl reload nginx`.

### 2. HAProxy ACL — manual edit, not `haproxyctl`

A previous attempt with `haproxyctl vhost add` regenerated `haproxy.cfg`
incorrectly (rewrote 185 vhosts to a non-existent `waf_inspector` backend).
Tracked separately as bug
[#91](https://github.com/CyberMind-FR/secubox-deb/issues/91) — must be fixed
before we trust `haproxyctl vhost add` again. Until then, every HAProxy
vhost change for this repo is a manual edit with a pre-change backup.

For this change we will manually insert four lines:

In `frontend http-in` (before `default_backend fallback`):
```
    acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in
    use_backend nginx_vhosts if host_gitea_gk2_secubox_in
```

In `frontend https-in` (before `default_backend fallback`):
```
    acl host_gitea_gk2_secubox_in hdr(host) -i gitea.gk2.secubox.in
    use_backend nginx_vhosts if host_gitea_gk2_secubox_in
```

### 3. HAProxy TCP frontend (new) — `gitea-ssh`

Appended after the existing `frontend webui-lan` block:

```
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

`timeout client/server 1h` covers long-running git pushes/clones.

### 4. mitmproxy route

Skipped. With backend `nginx_vhosts`, HAProxy bypasses mitmproxy entirely for
this hostname. No entry in `/srv/mitmproxy/haproxy-routes.json` is needed.

### 5. TLS cert

No change. `*.gk2.secubox.in.pem` is loaded by `frontend https-in` via
`bind *:443 ssl crt /data/haproxy/certs/` and matches `gitea.gk2.secubox.in`
via the wildcard.

## Validation gate

The change is "done" when **all five** checks pass:

1. `curl -sI https://gitea.gk2.secubox.in/` → `HTTP/1.1 200 OK`, `server: nginx/1.22.1`
2. TLS SAN check: `openssl s_client -servername gitea.gk2.secubox.in ...` lists `DNS:*.gk2.secubox.in`
3. Web reachability: `curl -s https://gitea.gk2.secubox.in/ | grep -q "<title>"` returns 0
4. SSH protocol reachability: `ssh -p 2222 -o ConnectTimeout=5 -o BatchMode=yes git@gitea.gk2.secubox.in 2>&1 | head -1` must print `Permission denied (publickey)` or a Gitea welcome banner — anything that proves the TCP path is open and an SSH server answered, not "Connection refused" or "Connection timed out". (Authenticated git over SSH is tested in step 5 once a key is enrolled in Gitea.)
5. Round-trip git (optional, runs only if an SSH key is already enrolled in Gitea for some test user): create a test repo via Gitea web, clone it over both HTTPS and SSH, push a commit, pull it back, verify SHA matches. Cleanup repo after. If no test user is enrolled, do the round-trip over HTTPS only with a token.

If any check fails: revert HAProxy from the backup we took, reload, and
investigate before re-applying.

## Rollback procedure

Before any HAProxy change:

```bash
cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak.gitea-repair.$(date +%s)
```

If a reload fails or a vhost breaks:

```bash
cp /etc/haproxy/haproxy.cfg.bak.gitea-repair.<timestamp> /etc/haproxy/haproxy.cfg
systemctl reload haproxy
```

Same for nginx (`/etc/nginx/sites-available/gitea.conf` is new — just `rm` the
symlink and reload).

## Error handling

| Failure | Detection | Response |
|---------|-----------|----------|
| HAProxy reload rejects new ACL | `haproxy -c -f /etc/haproxy/haproxy.cfg` before reload | Roll back, fix syntax, retry |
| nginx -t fails | Stderr from `nginx -t` | Roll back, fix syntax, retry |
| HTTPS test returns non-200 | Step 1 of validation gate | Check nginx access log, then LXC reachability |
| SSH on 2222 refused | Step 4 fails | Verify HAProxy `gitea-ssh` frontend listens, then LXC sshd is up |
| Wildcard cert SAN does not match | Step 2 fails | Unexpected; check actual loaded `*.gk2.secubox.in.pem` against hostname |

## Testing

This is operational infrastructure work. The validation gate (5 checks) is the
test. No unit tests are added.

## File-level changes

| Action | File | Purpose |
|--------|------|---------|
| Create | `/etc/nginx/sites-available/gitea.conf` (MOCHAbin) | Proxy `gitea.gk2.secubox.in` → `10.100.0.40:3000` |
| Symlink | `/etc/nginx/sites-enabled/gitea` → `gitea.conf` | Enable vhost |
| Patch | `/etc/haproxy/haproxy.cfg` (MOCHAbin) | Add 2× 2-line ACL block (http-in + https-in) + new TCP frontend `gitea-ssh` and backend `gitea_ssh` |
| Create (repo) | `packages/secubox-gitea/conf/gitea.nginx.conf` | Versioned copy of the nginx vhost so the package ships it |
| Create (repo) | `packages/secubox-gitea/conf/haproxy.snippet` | Versioned copy of the HAProxy ACL + TCP frontend snippet |
| Patch (repo) | `packages/secubox-gitea/debian/postinst` | Install the conf files into `/etc/...` on package install |

The repo-side files (under `packages/secubox-gitea/`) ensure the change is
reproducible: a fresh deployment of the SecuBox stack will get the same routing
without manual steps.

## Open questions

None blocking. The choice of port 2222 vs 22 was decided in brainstorming; the
choice of `nginx_vhosts` vs `mitmproxy_inspector` is documented in
*Architecture* §.

## Licensing

Per [`.claude/CLAUDE.md`](../../../.claude/CLAUDE.md), all first-party
artifacts in this design ship under CMSD-1.0 (CyberMind Source-Disclosed
License). The HAProxy/nginx config snippets are operational config — no header
required by the license-headers tool (config files are out of scope per the
Phase A allowlist).
