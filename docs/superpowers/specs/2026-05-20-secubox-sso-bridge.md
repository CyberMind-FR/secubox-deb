<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# `secubox-sso-bridge` — Single Sign-On across SecuBox + 3rd-party admin UIs

**Réf.**     CyberMind / SecuBox-Deb · SSO doctrine
**Date**     2026-05-20
**Statut**   spec captured from operator drop, not yet scoped against existing AUTH stack
**Layer**    AUTH (extends `secubox-zkp-auth` / `secubox-users`)

---

## Operator intent

> "sso yacy admin with secubox authentication"
> "sso nextcloud admin likely..."
> "idem gitea admin access"
> "sso must be health banner percolated"

The user wants a SecuBox-side identity provider (IdP) such that when an
admin authenticates against SecuBox (via the canonical hub login at
`/login.html` + JWT), the same session grants admin access to:

- **YaCy** (`yacy.maegia.tv` or LAN)
- **Nextcloud** (URL TBD)
- **Gitea** (`gitea.gk2.secubox.in`)
- (likely: Grafana, RustDesk web admin, mitmproxy web ⨯ any other module
  with its own native admin UI)

Plus: every SSO login page (whether SecuBox-native or upstream-served)
must include the SecuBox **health-banner.js** injection so the operator
sees the system-wide health bar even on the auth screens.

---

## Prerequisites — open questions for the operator

1. **IdP choice**: SecuBox doesn't yet ship an IdP. Three viable paths:
   - **Authelia** (small, OIDC + 2FA, suitable for self-hosted) — recommended starter
   - **Authentik** (fuller-featured, heavier)
   - **Keycloak** (mature but JVM-heavy on arm64 MOCHAbin)

   The `secubox-zkp-auth` module mentioned in earlier specs may be the
   intended IdP — but it's not yet in the repo. Operator must arbitrate
   between adopting an upstream IdP or finishing the in-house ZKP-auth.

2. **Protocol per backend**:
   | Backend | Native SSO support | Path of least resistance |
   |---|---|---|
   | Grafana | OAuth2 / OIDC / LDAP / SAML | OIDC against SecuBox IdP |
   | YaCy | local users only, no OAuth | nginx `auth_request` to SecuBox `/api/v1/portal/verify` |
   | Nextcloud | OAuth2 / OIDC / SAML (via app) | OIDC via `user_oidc` app |
   | Gitea | OAuth2 / OIDC / LDAP / SAML | OIDC against SecuBox IdP |
   | RustDesk web admin | none (OSS), pro only | nginx `auth_request` |
   | mitmproxy web | none | nginx `auth_request` |

   YaCy + RustDesk + mitmproxy = no native SSO → use nginx `auth_request`
   sub-request to a SecuBox `/api/v1/portal/verify` endpoint that checks
   the JWT cookie and returns 200/401.

3. **Session sharing**: SecuBox JWT lives in `localStorage` and as
   `Authorization: Bearer …` header. For nginx `auth_request` we also
   need it in a cookie (e.g. `sbx_token`) — needs a small SecuBox-portal
   change to set the cookie at login time.

4. **Health banner on the IdP login page**: `sub_filter` injection of
   `/shared/health-banner.js` in nginx, identical to how the canonical hub
   vhost does it on `admin.gk2.secubox.in`. The IdP login page must be
   served by nginx (not by Authelia's built-in static asset) for the
   sub_filter to land — typically via a reverse-proxy wrapper.

---

## Proposed implementation outline (to validate)

### Phase A — Verify endpoint in `secubox-portal`

Add `POST /api/v1/portal/verify` that:

- Reads `sbx_token` cookie OR `Authorization: Bearer …` header
- Validates JWT signature + expiry against the secret in `/etc/secubox/secubox.conf`
- Returns 200 + `X-Sbx-User: <name>` / `X-Sbx-Role: <admin|operator|viewer>` headers if valid
- Returns 401 otherwise

This is the building block for nginx `auth_request` integration.

### Phase B — nginx `auth_request` for SSO-less backends

For YaCy / RustDesk web / mitmproxy:

```nginx
location /yacy/ {
    auth_request /__sbx_verify;
    auth_request_set $sbx_user $upstream_http_x_sbx_user;
    error_page 401 = /login.html?redirect=/yacy/;
    proxy_pass http://10.100.0.80:8090/;
    proxy_set_header X-Forwarded-User $sbx_user;
    # sub_filter for health-banner.js — same as the canonical vhost
    sub_filter_types text/html;
    sub_filter_once on;
    sub_filter "</body>" '<script src="/shared/health-banner.js"></script></body>';
}

location = /__sbx_verify {
    internal;
    proxy_pass http://unix:/run/secubox/portal.sock:/api/v1/portal/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Cookie $http_cookie;
    proxy_set_header Authorization $http_authorization;
}
```

### Phase C — OIDC IdP for SSO-capable backends

Pick **Authelia** in an LXC at `10.100.0.20` on `br-lxc`:

- New module `secubox-authelia` (same LXC pattern as grafana/yacy/rustdesk)
- Mounts under `/auth/` on the canonical hub vhost
- Configured to use SecuBox's `users.json` as the authentication backend
  (file backend with argon2 — matches the existing `secubox-users` schema)
- OIDC clients pre-provisioned for grafana, gitea, nextcloud

Each backend then enables OIDC:

- Grafana → `auth.generic_oauth` against `https://auth.maegia.tv/.well-known/openid-configuration`
- Gitea → `Site Administration` → `Authentication Sources` → OAuth2
- Nextcloud → `user_oidc` app → add provider

### Phase D — Health-banner percolation everywhere

For every SSO-touched vhost (Authelia login page, every backend's `/login`
or equivalent), add the `sub_filter` injection of `/shared/health-banner.js`.
For backends that minify/CSP-restrict, may need a small upstream patch or
inject via the post-login dashboard instead.

---

## Out of scope (separate efforts)

- Full ZKP-auth implementation per the GK-HAM-2025 doctrine in CLAUDE.md
  (that's a v3.x track)
- 2FA / TOTP enrollment UX (Authelia covers this out-of-the-box)
- Audit trail of cross-app SSO logins (deferred to a `secubox-audit` module)

---

## Decision points

Before scaffolding any code, the operator needs to arbitrate:

1. **IdP**: Authelia LXC vs in-house ZKP-auth vs Authentik vs Keycloak?
2. **Cookie name + scope**: `sbx_token` global, or per-app `sbx_<app>_token`?
3. **Health banner on IdP login**: do we proxy the IdP through nginx
   (where sub_filter works) or accept that the IdP login page lacks the banner?
4. **Per-backend role mapping**: SecuBox roles (admin/operator/viewer) → each
   backend's role model (grafana Admin/Editor/Viewer, gitea admin/user, etc.)
