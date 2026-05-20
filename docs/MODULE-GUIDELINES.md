# SecuBox Module Guidelines

> Canonical reference for authoring a new `secubox-<module>` Debian package.
> Read alongside [`docs/grammar.md`](grammar.md) (CTL grammar) and
> [`docs/UI-GUIDE.md`](UI-GUIDE.md) (theme + sidebar conventions).
>
> The HOWTO that walks through adding a new CTL verb is at
> [`HOWTO-grammar.md`](../HOWTO-grammar.md). This document covers the
> module-level scaffolding around a verb (packaging, LXC, FastAPI host
> control plane, web UI, nginx wiring).

---

## 1. When to create a new module

A new `secubox-<module>` package is justified when **all** of these hold:

- It introduces a new noun in the CTL grammar (not a verb on an existing noun).
- It owns at least one of: a long-running daemon, a web UI route under `/<module>/`, a public-facing endpoint under `/api/v1/<module>/`, or a Debian-distributable bundle of templates/config.
- It is independently uninstallable (`apt remove secubox-<module>` must leave the rest of SecuBox functional).

Examples:

| Add a module | Don't add a module |
|---|---|
| Grafana dashboards backed by a Grafana LXC | A new dashboard JSON for the existing `secubox-metrics` module |
| YaCy peer search engine | A YaCy crawl-result viewer that lives in `secubox-hub` |
| RustDesk relay | A `wireguard add peer rustdesk-relay` verb on the existing VPN module |

---

## 2. Module shape (file structure)

The canonical layout. Every directory below is optional except `debian/`, but most modules grow into the full shape.

```text
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   ├── main.py                       # FastAPI on /run/secubox/<module>.sock
│   ├── models.py                     # Pydantic schemas
│   └── lxc_helpers.py                # LXC modules only
├── conf/
│   └── <module>.toml.example         # installed to /etc/secubox/
├── debian/
│   ├── changelog
│   ├── control                       # see §6
│   ├── rules                         # see §6
│   ├── install                       # or use rules override_dh_auto_install
│   ├── postinst                      # idempotent — see §6
│   ├── prerm
│   ├── postrm
│   └── secubox-<module>.service      # systemd unit — see §6
├── lib/
│   └── <module>/                     # LXC modules only — see §3
│       ├── install-lxc.sh
│       ├── update-lxc.sh
│       └── provision/
├── menu.d/
│   └── 50-<module>.json              # SecuBox sidebar entry — see §4
├── nginx/
│   └── <module>.conf                 # /etc/nginx/secubox.d/ snippet — see §5
├── README.md                         # operator-facing
├── sbin/
│   └── <module>ctl                   # bash CLI — see §7 + grammar.md
├── tests/
│   ├── helpers.bash                  # bats helpers
│   └── test-*.bats                   # CLI tests
└── www/
    ├── <module>/
    │   ├── index.html                # SecuBox-themed landing — see UI-GUIDE.md
    │   ├── settings.html
    │   └── logs.html
    └── shared/                       # rarely needed — most JS/CSS lives in secubox-hub
```

Mirror an existing module of similar shape rather than starting from scratch:

| Pattern | Reference module |
|---|---|
| LXC-hosted daemon | `packages/secubox-gitea/`, `packages/secubox-mail/` |
| Host-only daemon | `packages/secubox-metrics/`, `packages/secubox-crowdsec/` |
| WAF / proxy add-on | `packages/secubox-mitmproxy/` |
| Pure web UI on existing service | `packages/secubox-soc-web/` |
| Pure CLI / no daemon | `packages/secubox-droplet/` |

---

## 3. LXC layout (modules that run their daemon in a Debian LXC)

### When LXC is the right choice

- Daemon needs a different runtime (JVM, Alpine, custom apt repo) than the host.
- Daemon is high-risk and should run in an isolated rootfs (RustDesk, mitmproxy).
- Daemon needs root-level setup that would conflict with another module's daemon if run on the host.

### IP allocation

The SecuBox LXC bridge is `br-secubox` on `10.100.0.0/24`. Allocations:

| IP | Module |
|---|---|
| `.1` | bridge gateway (host side) |
| `.10` | mail |
| `.11`/`.12` | mail-related (rspamd, sieve) |
| `.30` | (reserved) |
| `.40` | gitea |
| `.70` | grafana (planned, #229) |
| `.80` | yacy (planned, #230) |
| `.90` | rustdesk (planned, #231) |

Pick the next free `.X` above the current high-water mark. Reserve the IP in
`docs/grammar.md` or this doc on submission of the module PR.

### Bootstrap script: `lib/<module>/install-lxc.sh`

Idempotent shell script that creates the LXC if absent, debootstraps it,
installs the daemon, provisions defaults, and exits 0. Must be safely
re-runnable (the operator may run it from `<module>ctl install` repeatedly).

Anatomy:

```bash
#!/usr/bin/env bash
set -euo pipefail
readonly LXC_NAME="${SECUBOX_LXC_NAME:-<module>}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.XX}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly DEBIAN_SUITE="bookworm"

# 1. Idempotency short-circuit
lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null | grep -q '^State: *RUNNING' && exit 0

# 2. Create if missing
[ -d "$LXC_PATH/$LXC_NAME" ] || lxc-create -n "$LXC_NAME" -t debian -P "$LXC_PATH" -- -r "$DEBIAN_SUITE"

# 3. Pin static IP, AppArmor profile, autostart
cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
lxc.uts.name = $LXC_NAME
lxc.net.0.type = veth
lxc.net.0.link = br-secubox
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.apparmor.profile = generated
lxc.start.auto = 1
EOF

# 4. Start + wait for network
lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
for i in $(seq 1 30); do
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && break
    sleep 1
done

# 5. Install daemon + dependencies
lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -c '
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends <packages>
'

# 6. Provision (dashboards / peer lists / keys)
"$(dirname "$0")/provision/run.sh"

# 7. Sentinel
touch /var/lib/secubox/<module>/.lxc-provisioned
```

### Provisioning (`lib/<module>/provision/`)

Ship configuration that the operator expects out-of-the-box:

- Grafana dashboards (`.json`), datasource yaml.
- YaCy peer seed list, blacklist, default crawl profile.
- RustDesk key material is generated, not shipped — but a `key generate` wrapper goes here.

Provisioned content is read-only after install; user customisation lives in
`/etc/secubox/<module>.toml` and overrides the provisioned defaults.

### Not in the image — installed on demand

Modules whose LXC rootfs is >100 MB should **not** be pre-built into the
SecuBox system image. The package ships only the install script; the
operator runs `<module>ctl install` post-firstboot.

This keeps the v2.10.x image at ~8 GB. Modules requiring large daemons
(grafana, yacy, rustdesk) follow this rule. Compact LXCs (mitmproxy ~50 MB)
can pre-build during image construction.

---

## 4. WebUI conventions

### Theme

Mandatory. See [`docs/UI-GUIDE.md`](UI-GUIDE.md):

- CRT P31 phosphor palette via `/shared/crt-{light,dark}.css`
- Sidebar via `/shared/sidebar-{light,dark}.css` populated by `/shared/sidebar.js`
- Theme toggle persists to `localStorage.sbx_theme`

### Auth wrapper

Every page (except `/login.html`) must redirect to `/login.html?redirect=<current-path>`
when no `localStorage.sbx_token` is present. The hub's `index.html` shows the
canonical `checkAuth()` implementation:

```js
function checkAuth() {
    if (!localStorage.getItem('sbx_token')) {
        window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
        return false;
    }
    return true;
}
if (!checkAuth()) {
    document.body.innerHTML = '<div style="padding:2rem;color:var(--root-main);">Redirecting to login...</div>';
}
```

Path is `/login.html`, **never** `/portal/login.html` — see #222.

### Menu integration (`menu.d/<module>.json`)

```json
{
  "title": "Module Name",
  "subtitle": "One-line purpose",
  "icon": "fa-icon-name",
  "url": "/<module>/",
  "section": "monitoring|security|network|publishing|hosting|search|admin",
  "order": 50,
  "module": "<module>"
}
```

`section` slots into the existing sidebar grouping. `order` controls
position inside the section (10/20/30/.../90).

### Three-fold landing

The module's `index.html` should surface the same three sections the CTL
exposes — components / status / access — at the top of the page:

```html
<section class="threefold">
  <article id="components">...</article>  <!-- LXC state, daemon state, host API state -->
  <article id="status">...</article>       <!-- overall green/yellow/red + the last event -->
  <article id="access">...</article>       <!-- public hostname + auth method -->
</section>
```

Pulls live data from `/api/v1/<module>/components`, `/status`, `/access`.

### Iframe pattern for LXC web UIs

When the LXC daemon ships its own admin UI (Grafana, YaCy, RustDesk web
console), embed it inside a SecuBox-themed iframe under `/<module>/`. The
iframe target proxies through nginx to the LXC IP (see §5). Operator
navigates dashboards via the SecuBox sidebar (`menu.d`), not the native
chrome.

---

## 5. nginx wiring (`nginx/<module>.conf`)

Installed to `/etc/nginx/secubox.d/<module>.conf` and auto-included by
`/etc/nginx/sites-available/secubox`.

### Standard pattern (host FastAPI only)

```nginx
# /etc/nginx/secubox.d/<module>.conf
location /api/v1/<module>/ {
    proxy_pass http://unix:/run/secubox/<module>.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
```

### LXC daemon iframe target

```nginx
location /api/v1/<module>/ {
    proxy_pass http://unix:/run/secubox/<module>.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}

# Native admin UI of the LXC daemon (iframe target)
location /<module>/ {
    proxy_pass http://10.100.0.XX:PORT/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Daemon must be configured to serve from the `/<module>/` subpath
(e.g. Grafana `serve_from_sub_path=true`).

### Non-HTTP daemons (rustdesk, raw TCP/UDP)

Don't proxy through nginx — proxy through HAProxy stream mode. See
`packages/secubox-haproxy/conf/` for the stream-backend pattern.

---

## 6. Debian packaging conventions

### `debian/control`

```text
Source: secubox-<module>
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13), dh-python, python3-all
Standards-Version: 4.6.2
Homepage: https://cybermind.fr/secubox

Package: secubox-<module>
Architecture: all
Depends: ${misc:Depends},
         secubox-core (>= 1.0),
         <module-specific deps>
Recommends: <optional companions>
Description: SecuBox <Module> — <one-line purpose>
 <Longer description, 3-5 lines.>
```

**Do not** ship a `debian/compat` file. The `Build-Depends: debhelper-compat (= 13)` is the single source of truth (see #220).

### `debian/rules`

```makefile
#!/usr/bin/make -f
%:
	dh $@ --with python3

override_dh_auto_install:
	install -d debian/secubox-<module>/usr/lib/secubox/<module>
	cp -r api debian/secubox-<module>/usr/lib/secubox/<module>/
	install -d debian/secubox-<module>/usr/sbin
	install -m 755 sbin/<module>ctl debian/secubox-<module>/usr/sbin/<module>ctl
	install -d debian/secubox-<module>/usr/share/secubox/www
	[ -d www ] && cp -r www/. debian/secubox-<module>/usr/share/secubox/www/ || true
	install -d debian/secubox-<module>/usr/share/secubox/menu.d
	[ -d menu.d ] && cp -r menu.d/. debian/secubox-<module>/usr/share/secubox/menu.d/ || true
	install -d debian/secubox-<module>/etc/nginx/secubox.d
	[ -f nginx/<module>.conf ] && cp nginx/<module>.conf debian/secubox-<module>/etc/nginx/secubox.d/ || true
	# LXC modules only:
	install -d debian/secubox-<module>/usr/share/secubox/lib/<module>
	[ -d lib/<module> ] && cp -r lib/<module>/. debian/secubox-<module>/usr/share/secubox/lib/<module>/ || true
```

### `debian/postinst`

Idempotent system-user creation, directory provisioning, conditional
nginx reload, service enable. **Never start the FastAPI before its
prerequisites are present** — for LXC modules, defer the first start
to `<module>ctl install` (which fires after the LXC is up).

```sh
#!/bin/sh
set -e
case "$1" in
    configure)
        getent group secubox >/dev/null || groupadd --system secubox
        getent passwd secubox >/dev/null || useradd --system --gid secubox \
            --home /var/lib/secubox --no-create-home --shell /usr/sbin/nologin secubox
        install -d -m 0770 -o root -g secubox /etc/secubox
        install -d -m 0755 -o secubox -g secubox /var/lib/secubox/<module>

        if [ ! -f /etc/secubox/<module>.toml ] && [ -f /etc/secubox/<module>.toml.example ]; then
            cp /etc/secubox/<module>.toml.example /etc/secubox/<module>.toml
            chmod 640 /etc/secubox/<module>.toml
            chown root:secubox /etc/secubox/<module>.toml
        fi

        if systemctl is-active --quiet nginx 2>/dev/null; then
            nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
        fi

        systemctl daemon-reload 2>/dev/null || true
        systemctl enable secubox-<module>.service 2>/dev/null || true
        # LXC modules: do not start yet; ctl install will start after LXC up.
        # Host-only modules: uncomment the next line:
        # systemctl start secubox-<module>.service 2>/dev/null || true
        ;;
esac
#DEBHELPER#
exit 0
```

### `debian/secubox-<module>.service`

```ini
[Unit]
Description=SecuBox <Module> API
After=network.target secubox-core.service
Wants=secubox-core.service

[Service]
UMask=0007
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/<module>
RuntimeDirectory=secubox
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStartPre=/bin/mkdir -p /etc/secubox
ExecStartPre=/bin/chown secubox:secubox /etc/secubox
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/<module>.sock --log-level warning
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
LogsDirectory=secubox
LogsDirectoryMode=0755
ReadWritePaths=/run/secubox /var/lib/secubox /etc/secubox /var/log/secubox

[Install]
WantedBy=multi-user.target
```

Board-specific units (Pi/MOCHAbin I2C/LED) **must** gate on `ConditionArchitecture=arm64` to skip silently on x86_64 (see #226).

### Slipstream into the system image

The `build-packages.yml` workflow auto-discovers any new `packages/secubox-*/debian/control` on the next push. No workflow edit is required.

The `build-image.sh` slipstream loop (`cp /tmp/secubox-debs/secubox-*.deb`) picks up the new `_all.deb` automatically. New module appears in `dpkg -l 'secubox-*'` on the next image build.

`apt-get install -f -y` after the slipstream `dpkg -i --force-depends` step (since #218) pulls any new declared Debian deps — no need to add them to the debootstrap `INCLUDE_PKGS`.

---

## 7. CTL conventions

Read first: [`docs/grammar.md`](grammar.md) (canonical verbs table) +
[`HOWTO-grammar.md`](../HOWTO-grammar.md) (recipe for adding a verb).

### Mandatory three-fold

Every `<module>ctl` exposes:

| Noun | Verb | Output |
|---|---|---|
| `components` | (no verb) `list` `status` | one line per managed component (LXC, daemon, host-API, sub-units) |
| `status` | (no verb) | overall green/yellow/red + last event line |
| `access` | `list` `show <name>` | every URL/socket the module exposes + the auth method |

Plain stdout for humans, `--json` for machines. Schema:

```json
{
  "module": "<module>",
  "version": "<semver>",
  "components": [
    {"name": "lxc",      "state": "running|stopped|absent", "detail": "..."},
    {"name": "daemon",   "state": "running|stopped|absent", "detail": "..."},
    {"name": "host-api", "state": "running|stopped|absent", "detail": "..."}
  ]
}
```

### Module-specific noun-verb pairs

Per the grammar table — one verb closes one previously-implicit operation.
Examples in flight:

```text
grafanactl   dashboard list/add/remove/export        # OPS MONITORING (#229)
yacyctl      index     status/build/clear/optimize   # SEARCH (#230)
rustdeskctl  peer      add/remove/list               # REMOTE-ACCESS (#231)
```

### Style

- Imperative present tense: `add`, `remove`, `list`, `status`. Not `creating`, `deletion`, `listed`.
- Singular nouns: `route`, `repo`, `app`, `peer`, `dashboard`, `vhost`.
- Aliases accepted but not advertised in `--help`: `rm`/`del` for `remove`, `ls` for `list`.
- Exit codes: `0` success, `1` user error, `2` runtime error, `3` lxc/daemon down.

### Help

`<module>ctl --help` prints the noun-verb table; `<module>ctl <noun>` prints
the verbs for that noun; `<module>ctl <noun> <verb> --help` prints flags.

---

## 8. API conventions

### Transport

FastAPI + Uvicorn on a Unix socket at `/run/secubox/<module>.sock`. **Never** a TCP port (avoids LAN-side enumeration).

### Routing

nginx proxies `/api/v1/<module>/*` → the Unix socket. The FastAPI app
mounts its routes at the root (no `/api/v1/<module>` prefix in the app
code — nginx strips it).

### Mandatory endpoints

| Endpoint | Purpose |
|---|---|
| `GET /status` | Same JSON as `<module>ctl status --json` |
| `GET /components` | Same JSON as `<module>ctl components --json` |
| `GET /access` | Same JSON as `<module>ctl access --json` |
| `GET /healthz` | `{"ok": true}` if the API process is alive — no shelling out |
| `GET /version` | `{"version": "<semver>", "build": "<git-sha>"}` |

These five let `healthctl` watch the module without module-specific code.

### Module-specific endpoints

One endpoint per noun-verb pair the CTL exposes. The API can either
re-implement the logic in Python (fast) or shell out to `<module>ctl <noun> <verb> --json`
(simple, single source of truth). The latter is the SecuBox default.

### Auth

All non-trivial endpoints (anything mutating state, or returning data
beyond status/components/access/healthz/version) require JWT via
`Depends(auth.require_jwt)`. The JWT secret is generated at firstboot
into `/etc/secubox/secubox.conf`.

### Pydantic models

Define in `api/models.py`. Re-use shared models from `secubox-core` when
they fit (`secubox_core.models.JobStatus`, etc.).

---

## 9. Tests

### CTL tests

Use [bats-core](https://github.com/bats-core/bats-core). One file per noun,
or one file per coherent flow (`test-<module>ctl-install.bats`,
`test-<module>ctl-dashboards.bats`).

PATH-shim external commands (`lxc-create`, `lxc-attach`, `systemctl`,
`curl`) in `tests/helpers.bash` so the suite runs offline:

```bash
# tests/helpers.bash
setup() {
    export PATH="$BATS_TEST_DIRNAME/stubs:$PATH"
    # Each stub is a shell script that echoes a canned response.
}
```

### API tests

pytest + httpx async client. Spin up uvicorn on a tempfile socket per
test session; assert JSON schema.

### CI

Both run automatically as part of `Build SecuBox .deb packages` when
`debian/rules` includes them via `dh_auto_test` or `debian/tests/`.

---

## 10. Validation checklist (run before opening the PR)

- [ ] Package builds locally: `cd packages/secubox-<module> && dpkg-buildpackage -us -uc -b` succeeds with no warnings other than the standard `dpkg-source: warning: source format` line.
- [ ] `lintian --no-tag-display-limit ../secubox-<module>_*.deb` reports zero `E:` and zero `W:` (info lines OK).
- [ ] `<module>ctl --help` lists every noun.
- [ ] `<module>ctl <noun> --help` lists every verb on that noun.
- [ ] Three-fold JSON schemas match §7 and §8.
- [ ] `bats tests/` runs green offline (no internet, no LXC).
- [ ] WebUI page loads with `localStorage.sbx_token` set; redirects to `/login.html` when not.
- [ ] nginx vhost includes both `/api/v1/<module>/` and `/<module>/` (if iframe target).
- [ ] No `debian/compat` file (compat 13 declared via `Build-Depends` only).
- [ ] No Pi-only services without `ConditionArchitecture=arm64` (see #226).
- [ ] No reference to `/portal/login.html` (use `/login.html` — see #222).
- [ ] `apt-get install -y ../secubox-<module>_*.deb` on a fresh VM completes; `systemctl status secubox-<module>` is `loaded` (host modules: also `active`); LXC modules: `<module>ctl install` then `<module>ctl status` returns green.
- [ ] Module added to `docs/MODULES.md` catalog.
- [ ] CTL verbs added to `docs/grammar.md` canonical table.
- [ ] `.claude/MIGRATION-MAP.md` row added.

---

## References

- [`docs/grammar.md`](grammar.md) — canonical CTL grammar
- [`HOWTO-grammar.md`](../HOWTO-grammar.md) — recipe for adding a verb
- [`docs/UI-GUIDE.md`](UI-GUIDE.md) — UI theme and sidebar
- [`docs/MODULES.md`](MODULES.md) — module catalog
- [`docs/SECUBOX-DEV-METHODOLOGY.md`](SECUBOX-DEV-METHODOLOGY.md) — overall development workflow
- [`.claude/PATTERNS.md`](../.claude/PATTERNS.md) — RPCD → FastAPI porting patterns
- Plan example: [`docs/superpowers/plans/2026-05-20-grafana-yacy-rustdesk-lxc-modules.md`](superpowers/plans/2026-05-20-grafana-yacy-rustdesk-lxc-modules.md) — three modules following this guideline end-to-end.
