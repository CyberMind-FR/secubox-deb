# secubox-authelia

[Authelia](https://www.authelia.com/) SSO IdP for SecuBox, hosted in a Debian
LXC at `10.100.0.20` on the SecuBox `br-lxc` bridge.

Follows [`docs/MODULE-GUIDELINES.md`](../../docs/MODULE-GUIDELINES.md); opens
the **AUTH-BRIDGE** sub-layer of the AUTH layer of the SecuBox CTL grammar.

## Quickstart

```bash
apt install secubox-authelia
autheliactl install       # provisions LXC + Authelia binary + secrets
autheliactl status        # green when LXC + daemon + host-API all up
```

Then point a browser at `https://auth.maegia.tv/` (DNS + HAProxy vhost must
be operator-configured first — see `nginx/authelia-vhost.conf` for the
exact incantation).

## File backend = SecuBox single source of truth

Authelia is configured with the **file backend** reading
`/etc/secubox/users.json` (the same argon2id store managed by `secubox-users`).
No LDAP, no SQL — SecuBox's canonical identity store is authoritative.
A user enabled in `secubox-users` is enabled in Authelia.

## OIDC clients (pre-provisioned, secrets filled by wizard)

| Client | Application | Redirect URI |
|---|---|---|
| `secubox-grafana` | Grafana | `https://grafana.maegia.tv/login/generic_oauth` |
| `secubox-gitea` | Gitea | `https://gitea.gk2.secubox.in/user/oauth2/secubox/callback` |
| `secubox-nextcloud` | Nextcloud (opt-in) | `https://nextcloud.maegia.tv/apps/user_oidc/code` |

## nginx `auth_request` for SSO-less backends

YaCy, RustDesk-web, mitmproxy-web don't speak OIDC. Their nginx vhosts can
gate access via `auth_request /__sbx_auth_verify;` (the snippet in
`/etc/nginx/secubox.d/authelia.conf` defines `/__sbx_auth_verify` as a
proxy to the host FastAPI `/verify` endpoint). v1.0.0 ships the snippet but
`/verify` is a 501 stub — full JWT validation is the v1.1.0 follow-up.

## CTL — `autheliactl`

```text
autheliactl components       # LXC + authelia daemon + host-API states
autheliactl status           # overall green/yellow/red
autheliactl access list      # public URL(s) + auth method

autheliactl install          # idempotent LXC + Authelia bootstrap
autheliactl reload           # restart host FastAPI + authelia daemon
autheliactl repair           # (v1.1.0)
autheliactl wizard           # (v1.1.0) — interactive seed + install
autheliactl uninstall        # (v1.1.0)

autheliactl provider     list|add|remove|test       # (v1.1.0)
autheliactl oidc-client  list|add|remove|rotate-secret  # (v1.1.0)
autheliactl user         list|enable|disable|enrol-totp  # (v1.1.0)
autheliactl session      list|kill|killall            # (v1.1.0)
autheliactl totp         list|reset|verify             # (v1.1.0)
```

## Operator prerequisites for public exposure

For `https://auth.maegia.tv/` to be reachable from outside the LAN:

1. DNS `A auth.maegia.tv → <public-ip>`
2. TLS cert at `/data/haproxy/certs/auth.maegia.tv.pem` (Let's Encrypt or manual)
3. `haproxyctl vhost add auth.maegia.tv nginx_vhosts ssl`
4. **Inside** the mitmproxy LXC: add `auth.maegia.tv → 192.168.1.200:9080` in
   `/srv/mitmproxy/haproxy-routes.json` then `systemctl restart mitmproxy`

Steps 3 and 4 mirror what was done for `yacy.maegia.tv` on 2026-05-20.

## Files

```text
/etc/secubox/authelia.toml                  # operator config (rendered by autheliactl reload)
/etc/secubox/secrets/authelia-jwt           # JWT signing secret (32 bytes hex)
/etc/secubox/secrets/authelia-store         # storage encryption key
/etc/nginx/secubox.d/authelia.conf          # /auth/ + /api/v1/authelia/ + /__sbx_auth_verify
/etc/nginx/secubox-routes.d/authelia.conf   # idem (canonical hub vhost include)
/etc/nginx/sites-available/authelia.conf    # auth.maegia.tv public vhost (symlink to enable)
/usr/lib/secubox/authelia/api/              # host FastAPI
/usr/share/secubox/lib/authelia/install-lxc.sh
/usr/share/secubox/www/authelia/            # SecuBox-themed iframe wrapper
/usr/share/secubox/menu.d/40-authelia.json
/data/lxc/authelia/                         # LXC rootfs (created by autheliactl install)
```
