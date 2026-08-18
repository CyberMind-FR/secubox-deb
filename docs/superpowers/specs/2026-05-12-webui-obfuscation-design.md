---
title: WebUI Obfuscation — `admin.<HOSTNAME>.secubox.in` Only
issue: 44
date: 2026-05-12
status: design
---
<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->


## Context

GitHub issue: [#44 — WebUI Obfuscation - admin.HOSTNAME.secubox.in Only](https://github.com/CyberMind-FR/secubox-deb/issues/44).

The SecuBox WebUI currently answers on a permissive set of `server_name` values (`localhost`, `secubox.local`, `192.168.255.1`, `admin.gk2.secubox.in`, `gk2.secubox.in`, `secubox.maegia.tv`, `c3box.maegia.tv`). For ANSSI CSPN compliance, the WebUI must be served **only** on a single, well-defined canonical host: `admin.<HOSTNAME>.<DOMAIN_SUFFIX>` where `HOSTNAME` and `DOMAIN_SUFFIX` are board-identity values.

This design hardens HAProxy + nginx to enforce that constraint, while keeping LAN-direct emergency access on port `9443` untouched.

## Goals

1. **Single canonical URL** — only `https://admin.<HOSTNAME>.<DOMAIN_SUFFIX>/` returns the WebUI from the HAProxy-fronted path (port 443).
2. **Single source of truth** — `/etc/default/secubox` defines `SECUBOX_HOSTNAME` and `SECUBOX_DOMAIN_SUFFIX`. Both HAProxy and nginx derive their regex from this file.
3. **Defense in depth** — strict regex at HAProxy (first filter) AND at nginx (second filter). No reliance on a single point of enforcement.
4. **Idempotent rollout** — render scripts safe to run repeatedly; nginx and HAProxy validate before reload, rollback on failure.
5. **LAN escape hatch preserved** — `https://192.168.1.200:9443/` continues to serve the WebUI for emergency access without going through the obfuscation layer.

## Non-goals

- Changing the `:9443` LAN-direct listener (out of scope; remains permissive).
- Reworking the existing `mitmproxy_inspector` routing for non-WebUI vhosts (metablog, streamlit).
- Re-issuing TLS certificates for the new canonical name (`admin.gk2.secubox.in` already has a valid cert).
- Auto-detecting `SECUBOX_HOSTNAME` from network identity beyond a one-shot postinst fallback (`hostname -s` minus the `secubox-` prefix).

## Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│ /etc/default/secubox        ← single source of truth             │
│   SECUBOX_HOSTNAME=gk2                                           │
│   SECUBOX_DOMAIN_SUFFIX=secubox.in                               │
└──────────────────────────────────────────────────────────────────┘
                            │ read at API startup
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│ secubox-haproxy FastAPI (existing service, new endpoints)        │
│   GET  /api/v1/haproxy/webui/admin-domain                        │
│        → {hostname, domain_suffix, admin_domain, regex}          │
│   GET  /api/v1/haproxy/webui/nginx-config                        │
│        → text/plain (rendered nginx vhost)                       │
│   POST /api/v1/haproxy/webui/refresh                             │
│        → invalidate cached identity (after /etc/default edit)    │
└──────────────────────────────────────────────────────────────────┘
        │                                          │
        │ called by haproxyctl                     │ called by render script
        ▼                                          ▼
┌────────────────────────────────┐    ┌────────────────────────────┐
│ /etc/haproxy/haproxy.cfg       │    │ /etc/nginx/sites-available │
│   acl is_webui_admin           │    │     /secubox-local         │
│     hdr(host) -m reg           │    │   server_name              │
│     ^admin\.gk2\.secubox\.in$  │    │     ~^admin\.gk2\.secubox  │
│   use_backend webui_direct     │    │     \.in$;                 │
│     if is_webui_admin          │    │                            │
└────────────────────────────────┘    └────────────────────────────┘
```

All three strict checks must agree on the same regex. The API is the canonical computation point. `haproxyctl` and `secubox-render-nginx-webui` consume it. The API itself reads `/etc/default/secubox` directly.

## Components

### 1. New package `secubox-defaults`

A minimal Debian package whose only job is to ship the source-of-truth env file.

```text
packages/secubox-defaults/
├── debian/
│   ├── control          # Source + Binary, Architecture: all, no deps
│   ├── rules            # dh $@
│   ├── compat           # 13
│   ├── changelog
│   ├── copyright
│   ├── install          # etc/default/secubox → /etc/default/secubox
│   ├── secubox-defaults.postinst
│   └── secubox-defaults.conffiles  # /etc/default/secubox (preserve on upgrade)
├── etc/default/secubox  # template
└── README.md
```

**`/etc/default/secubox` content (template):**

```sh
# SecuBox board identity — single source of truth.
# Read by secubox-haproxy FastAPI at startup and by render scripts.
# After editing, run:
#   curl -fsS -X POST --unix-socket /run/secubox/haproxy.sock \
#        http://localhost/webui/refresh
#   /usr/local/bin/secubox-render-nginx-webui
#   /usr/local/bin/secubox-haproxy-regen-safe
SECUBOX_HOSTNAME="gk2"
SECUBOX_DOMAIN_SUFFIX="secubox.in"
```

**Postinst behavior** (idempotent):

- If `/etc/default/secubox` is missing (purge + reinstall case), copy the template.
- If `SECUBOX_HOSTNAME` is unset or empty, attempt autodetect: `hostname -s` stripped of any `secubox-` prefix. If still empty, leave unset and emit a warning (admin must edit).
- Trigger downstream regen via `dpkg-trigger secubox-haproxy-refresh` (other packages declare `interest secubox-haproxy-refresh` in their `triggers` files).

**Dependencies:** none. `secubox-haproxy`, `secubox-hub`, `secubox-core` add `Depends: secubox-defaults` going forward.

### 2. `secubox-haproxy` API extension

New helper module + three endpoints in `packages/secubox-haproxy/api/`.

**`packages/secubox-haproxy/api/webui_identity.py`** — parse and cache the defaults file:

```python
import re, shlex
from pathlib import Path
from functools import lru_cache

DEFAULTS_FILE = Path("/etc/default/secubox")

@lru_cache(maxsize=1)
def _parse_defaults() -> dict:
    out = {}
    if DEFAULTS_FILE.exists():
        for line in DEFAULTS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = shlex.split(v)[0] if v else ""
    return out

def get_identity() -> dict:
    cfg = _parse_defaults()
    host = cfg.get("SECUBOX_HOSTNAME", "")
    suffix = cfg.get("SECUBOX_DOMAIN_SUFFIX", "secubox.in")
    if not host:
        raise ValueError("SECUBOX_HOSTNAME not set in /etc/default/secubox")
    admin = f"admin.{host}.{suffix}"
    regex = "^" + re.escape(admin) + "$"
    return {"hostname": host, "domain_suffix": suffix,
            "admin_domain": admin, "regex": regex}

def invalidate_cache() -> None:
    _parse_defaults.cache_clear()
```

**Endpoints** added to the existing FastAPI app in `packages/secubox-haproxy/api/main.py`:

| Method | Path | Auth | Body / Response |
| --- | --- | --- | --- |
| GET | `/webui/admin-domain` | none (info, not secret) | JSON `{hostname, domain_suffix, admin_domain, regex}` |
| GET | `/webui/nginx-config` | `Depends(require_jwt)` | `text/plain` — rendered nginx vhost |
| POST | `/webui/refresh` | `Depends(require_jwt)` | invalidate LRU cache; returns 204 |

If `get_identity()` raises (HOSTNAME unset), endpoints return `503` with `{"error": "SECUBOX_HOSTNAME not configured"}`.

**Rendered nginx vhost template (returned by `/webui/nginx-config`):**

```nginx
# SecuBox WebUI — strict-regex obfuscation (issue #44)
# Generated by /api/v1/haproxy/webui/nginx-config — do not edit by hand.
server {
    listen 0.0.0.0:9080;
    server_name ~^admin\.{HOSTNAME_ESCAPED}\.{SUFFIX_ESCAPED}$;
    root /usr/share/secubox/www;
    index index.html;
    location / { try_files $uri $uri/ /index.html; }
    include /etc/nginx/secubox.d/*.conf;
    include /etc/nginx/snippets/api-error.conf;
    location /health {
        return 200 '{"status":"ok"}';
        add_header Content-Type application/json;
    }
}
```

`{HOSTNAME_ESCAPED}` and `{SUFFIX_ESCAPED}` are the values with literal dots escaped (nginx regex syntax).

### 3. nginx renderer script

New file: `packages/secubox-haproxy/sbin/secubox-render-nginx-webui` (installs to `/usr/local/bin/`).

Snapshot → fetch from API → atomic stage → `nginx -t` → reload, with rollback at any failure point.

```bash
#!/bin/bash
# secubox-render-nginx-webui — render strict-regex WebUI vhost from API
set -euo pipefail
TARGET=/etc/nginx/sites-available/secubox-local
TMP=$(mktemp /tmp/secubox-local.XXXXXX)
SNAP="$TARGET.bak.$(date +%s)"
SOCK=/run/secubox/haproxy.sock

log() { echo "[$(date '+%F %T')] $*" >&2; }

[[ -S "$SOCK" ]] || { log "FATAL: $SOCK missing — is secubox-haproxy.service running?"; exit 2; }

log "Fetch /webui/nginx-config from API"
if ! curl -sf --unix-socket "$SOCK" http://localhost/webui/nginx-config -o "$TMP"; then
    log "API call failed"
    rm -f "$TMP"; exit 3
fi
[[ -s "$TMP" ]] || { log "API returned empty body"; rm -f "$TMP"; exit 3; }

log "Snapshot $TARGET → $SNAP"
[[ -f "$TARGET" ]] && cp -p "$TARGET" "$SNAP"
mv "$TMP" "$TARGET"

if ! nginx -t 2>&1 | grep -q "syntax is ok"; then
    log "nginx -t FAILED — rolling back"
    [[ -f "$SNAP" ]] && cp -p "$SNAP" "$TARGET"
    exit 5
fi

log "Reload nginx"
systemctl reload nginx && log "render OK (snapshot kept: $SNAP)"
```

**Triggers:**

- Postinst of `secubox-defaults`: best-effort — calls the renderer and treats exit code 2 (API socket missing) as non-fatal, since on first install `secubox-haproxy.service` may not be up yet. Other exit codes propagate.
- Postinst of `secubox-haproxy`: always renders to ensure sync; exit code is fatal here (service is starting in this transaction).
- Manual: admin after editing `/etc/default/secubox`.
- No timer: HOSTNAME changes are rare and the renderer is invoked explicitly.

### 4. `haproxyctl` regex injection

Modify `packages/secubox-haproxy/sbin/haproxyctl` `generate` command to:

1. Fetch the regex via API (with fallback to direct read of `/etc/default/secubox` if API socket unreachable).
2. Inject the strict-regex ACL/use_backend pair at the **top** of both `frontend http-in` and `frontend https-in` rule blocks.
3. Skip the original `admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX}` per-vhost ACL inside the existing loop (avoid double-match).

Inserted snippet (after `mode http` of each frontend):

```haproxy
    # WebUI Obfuscation (issue #44) — strict regex from /etc/default/secubox
    acl is_webui_admin hdr(host) -m reg <REGEX_FROM_API>
    use_backend webui_direct if is_webui_admin
```

**Symmetry:** apply the same logic in `packages/secubox-haproxy/api/main.py` `generate_config()` (Python branch) so `POST /api/v1/haproxy/generate` produces a coherent cfg.

**Why `webui_direct` not `mitmproxy_inspector`:**

- Issue #44 explicitly proposes `webui_direct`.
- `webui_direct` → `server webui 127.0.0.1:9080 check` — direct nginx, skips mitmproxy WAF.
- WebUI admin is protected by JWT on `/api/v1/*` endpoints; the WAF bypass is acceptable because the surface is bounded by the strict regex.
- Avoids a routing loop (mitmproxy → 9080 → mitmproxy).

### 5. Tests

**Unit tests** (pytest, run in CI):

| File | Coverage |
| --- | --- |
| `packages/secubox-haproxy/tests/test_webui_identity.py` | parse empty file; missing HOSTNAME → ValueError; custom suffix; regex escapes literal dots; cache invalidation works |
| `packages/secubox-haproxy/tests/test_webui_endpoints.py` | `/webui/admin-domain` returns expected JSON shape; `/webui/nginx-config` 401 without JWT, 200 + text/plain with JWT; `/webui/refresh` invalidates and returns 204 |
| `packages/secubox-defaults/tests/test_postinst.sh` | postinst detects hostname when SECUBOX_HOSTNAME empty; preserves admin-set value |

**Integration test** (`tests/integration/test_44_webui_obfuscation.sh`) run on board or VM:

```text
1. Snapshot haproxy.cfg + secubox-local
2. Set SECUBOX_HOSTNAME=gk2
3. /usr/local/bin/secubox-render-nginx-webui
4. /usr/local/bin/secubox-haproxy-regen-safe --no-reload
5. nginx -t && haproxy -c -f /etc/haproxy/haproxy.cfg
6. systemctl reload nginx haproxy
7. Probe positive: curl -ski https://admin.gk2.secubox.in/  → 200 + "SecuBox Control Center"
8. Probe negative: curl -ski -H "Host: gk2.secubox.in" https://192.168.1.200/  → NOT the WebUI
9. Probe LAN direct: curl -ski https://192.168.1.200:9443/  → 200 + WebUI (unchanged path)
10. Probe random admin.*: curl -ski -H "Host: admin.fake.secubox.in" https://192.168.1.200/  → reject (regex strict)
11. Regression spot-check: cpf.gk2, arm.gk2, lldh.ganimed.fr, pub.gk2, werdl.gk2, 3d.gk2  → all still HTTP 200 with expected titles
12. Restore snapshots if any probe failed
```

### 6. Rollback plan

Layered by cost / reversibility:

| Layer | Mechanism | Trigger |
| --- | --- | --- |
| `haproxy.cfg` | `secubox-haproxy-regen-safe` validates + auto-restores | regen validation fails |
| `secubox-local` nginx | `secubox-render-nginx-webui` keeps `.bak.<ts>` | `nginx -t` fails |
| `/etc/default/secubox` | `dpkg --purge secubox-defaults` reverts to legacy permissive vhost | full rollback request |
| Packages | `dpkg -i <previous_version>.deb` from APT repo | major regression |

## Acceptance criteria

1. `https://admin.gk2.secubox.in/` → HTTP 200, body contains `SecuBox Control Center`.
2. `https://gk2.secubox.in/` (no `admin.` prefix) → does NOT serve the WebUI (HAProxy + nginx both refuse).
3. `https://192.168.1.200:9443/` → still HTTP 200 with WebUI markup (LAN escape hatch intact).
4. `haproxy -c -f /etc/haproxy/haproxy.cfg` → exit 0 (config valid).
5. `nginx -t` → `syntax is ok`.
6. All sites verified in Sessions 153–156 (cpf, arm, zkp, lldh, pub, werdl, 3d, 42, c3box, gandalf, live) remain HTTP 200 with expected titles.
7. pytest unit tests pass.
8. `systemctl restart secubox-haproxy.service` does not corrupt `haproxy.cfg` (uses the patched generators).

## Residual risks

- **Drift if admin edits `/etc/default/secubox` without re-rendering.** Mitigation: README and the comment block inside the defaults file both prescribe the refresh + render commands. Long-term, a systemd path-unit could watch the file and trigger rerender automatically (out of scope here).
- **`haproxyctl generate` still has the pre-existing TOML cert path bug** (`/srv/haproxy/certs/` vs real `/data/haproxy/certs/`) — Session 156 noted this. `secubox-haproxy-regen-safe` catches it via `haproxy -c -f` and rolls back, but the cert path mismatch should be fixed in the TOML before we expect `regen-safe` to succeed end-to-end. Tracked as a follow-up out of this issue.
- **Order-sensitive HAProxy ACL placement.** The strict-regex ACL must be emitted **before** any per-vhost ACL that could match the same hostname. The generator-side change guarantees this by emitting the regex block immediately after `mode http` of each frontend, but a future generator refactor must not break that ordering.

## Out of scope (follow-up issues)

- Fix `/etc/secubox/haproxy.toml` cert path (`/srv/haproxy/certs` → `/data/haproxy/certs`).
- systemd path-unit auto-rerender on `/etc/default/secubox` change.
- Extend WebUI dashboard to display the configured `SECUBOX_HOSTNAME` and the resulting canonical URL.
