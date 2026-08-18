<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Three new LXC SecuBox modules: secubox-grafana, secubox-yacy, secubox-rustdesk

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add three new LXC-hosted SecuBox modules — Grafana (security metrics dashboards), YaCy (peer-to-peer search engine), RustDesk (self-hosted remote-desktop relay) — each shipped as a `secubox-<name>` Debian package with the standard SecuBox layout (CTL tool, FastAPI control plane, web UI, nginx vhost, menu integration, LXC bootstrap, three-fold introspection). All three slipstreamed into the next release artifact.

**Architecture:** One LXC container per module, debootstrap-based, IP-allocated on the existing `10.100.0.0/24` SecuBox LXC bridge. The host runs only the FastAPI control plane (Unix socket → nginx `/api/v1/<module>/`), the WebUI shell, the CTL tool, and the bootstrap/management scripts. The LXC runs the actual service daemon. Public exposure goes through `haproxyctl vhost add` → `mitmproxyctl route add` for HTTP/HTTPS modules (grafana, yacy); RustDesk uses HAProxy stream-mode (TCP+UDP) directly because mitmproxy doesn't inspect non-HTTP traffic.

**Tech stack:**
- Debian 12 bookworm LXC (consistent with mail, gitea, mitmproxy LXCs already in production)
- FastAPI + Uvicorn on `/run/secubox/<module>.sock` for the host control plane
- Bash CTL tool following the canonical SecuBox grammar (`<module>ctl <noun> <verb>`, three-fold `components|status|access`)
- Vanilla HTML/CSS/JS web UI under the SecuBox 6-module palette (DESIGN-CHARTER.md)
- nginx reverse proxy snippet in `/etc/nginx/secubox.d/<module>.conf` (auto-included by sites-available/secubox)

---

## 0. Pre-flight: IP and port allocations

| Module | LXC IP | LXC name | Internal ports | Public hostname (HAProxy vhost) |
|---|---|---|---|---|
| grafana | `10.100.0.70` | `grafana` | 3000/tcp (HTTP) | `grafana.gk2.secubox.in` |
| yacy | `10.100.0.80` | `yacy` | 8090/tcp (HTTP, admin), 8443/tcp (HTTPS) | `yacy.gk2.secubox.in` |
| rustdesk | `10.100.0.90` | `rustdesk` | 21114/tcp (web), 21115/tcp (NAT test), 21116/tcp+udp (hbbs signal), 21117/tcp (hbbr relay), 21118/tcp (web client), 21119/tcp (legacy) | `rustdesk.gk2.secubox.in` (web) + raw `21115-21119` TCP/UDP on bare host IP |

Confirm against `grep -rohE '10\.100\.0\.[0-9]+' packages/ image/ | sort -u` before T0; current high-water mark observed is `.60`. If `.70/.80/.90` collide, bump to the next free `.7X` range.

---

## 1. File structure (identical skeleton for all three)

Mirrored from `packages/secubox-gitea` + `packages/secubox-mail` (the two closest LXC references).

```text
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   ├── main.py                     # FastAPI: status, restart, logs, module-specific endpoints
│   ├── models.py                   # Pydantic schemas
│   └── lxc_helpers.py              # shared lxc-attach / lxc-info wrappers (consider moving to secubox-core)
├── conf/
│   └── <module>.toml.example       # written to /etc/secubox/<module>.toml.example
├── debian/
│   ├── changelog                   # 1.0.0-1~bookworm1
│   ├── control                     # Depends below
│   ├── install                     # path -> rootfs mapping (or use rules override_dh_auto_install)
│   ├── postinst                    # idempotent user/dir/service setup, NO LXC creation (defer to ctl)
│   ├── prerm                       # stop service, do not destroy LXC
│   ├── postrm                      # purge: rm /etc/secubox/<module>.toml, /var/lib/secubox/<module>
│   ├── rules                       # %: dh $@ --with python3   ; override_dh_auto_install
│   └── secubox-<module>.service    # systemd unit for the host FastAPI
├── lib/
│   └── <module>/
│       ├── install-lxc.sh          # idempotent: create LXC if missing, debootstrap, install daemon
│       ├── update-lxc.sh           # in-place upgrade
│       ├── provision/              # per-module provisioning (grafana dashboards, yacy peer seeds, rustdesk keys)
│       └── README.md
├── menu.d/
│   └── 50-<module>.json            # SecuBox web UI menu entry, see existing menu.d schema
├── nginx/
│   └── <module>.conf               # location /api/v1/<module>/ + /<module>/  (proxy_pass unix socket / LXC IP)
├── README.md                       # operator-facing: install/upgrade/ctl reference/troubleshooting
├── sbin/
│   └── <module>ctl                 # bash CLI, three-fold + module-specific verbs
├── tests/
│   ├── helpers.bash                # bats helpers (mock lxc-attach, PATH shims)
│   └── test-<module>ctl.bats       # bats-core integration tests
└── www/
    ├── <module>/
    │   ├── index.html              # SecuBox-wrapped landing page (iframe to LXC web UI for grafana/yacy)
    │   ├── settings.html
    │   └── logs.html
    └── shared/                     # if any module-specific shared JS/CSS
```

### `debian/control` template

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
         secubox-haproxy,
         lxc,
         lxc-templates,
         debootstrap,
         python3-uvicorn,
         python3-fastapi,
         python3-toml,
         openssl,
         curl,
         <module-specific runtime deps below>
Recommends: secubox-mitmproxy
Description: SecuBox <Module> — <short purpose>
 <Longer description, 3-5 lines, includes the three-fold verbs.>
```

Module-specific deps:

- **grafana**: nothing extra on host (the grafana daemon lives in LXC; the host only needs `curl` for health probes and `jq` for dashboard JSON munging — already pulled by other modules).
- **yacy**: same; the JVM lives in the LXC.
- **rustdesk**: `iproute2` (for `ss` to inspect UDP listeners during health probe).

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

### `debian/postinst` template

```bash
#!/bin/sh
set -e
case "$1" in
    configure)
        getent group secubox >/dev/null || groupadd --system secubox
        getent passwd secubox >/dev/null || useradd --system --gid secubox \
            --home /var/lib/secubox --no-create-home --shell /usr/sbin/nologin secubox

        install -d -m 0770 -o root -g secubox /etc/secubox
        install -d -m 0755 -o secubox -g secubox /var/lib/secubox/<module>
        install -d -m 0755 -o secubox -g secubox /var/log/secubox

        # Copy example config if no live config exists
        if [ ! -f /etc/secubox/<module>.toml ] && [ -f /etc/secubox/<module>.toml.example ]; then
            cp /etc/secubox/<module>.toml.example /etc/secubox/<module>.toml
            chmod 640 /etc/secubox/<module>.toml
            chown root:secubox /etc/secubox/<module>.toml
        fi

        # Reload nginx if running (vhost snippet was just installed)
        if systemctl is-active --quiet nginx 2>/dev/null; then
            nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
        fi

        systemctl daemon-reload 2>/dev/null || true
        systemctl enable secubox-<module>.service 2>/dev/null || true
        # Do not start the FastAPI before the LXC is provisioned; ctl will start it
        # at the end of `<module>ctl install`.
        ;;
esac
#DEBHELPER#
exit 0
```

### `lib/<module>/install-lxc.sh` template

Idempotent: safe to re-run. Mirrors the structure of `packages/secubox-mail/lib/mail/install-mail-lxc.sh` (existing reference).

```bash
#!/usr/bin/env bash
set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-<module>}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.XX}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly DEBIAN_SUITE="bookworm"

# 1. Bail out if LXC already exists and is healthy
if lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null | grep -q '^State: *RUNNING'; then
    echo "[install-lxc] $LXC_NAME already running — nothing to do"
    exit 0
fi

# 2. Create the LXC if missing
if [ ! -d "$LXC_PATH/$LXC_NAME" ]; then
    lxc-create -n "$LXC_NAME" -t debian -P "$LXC_PATH" -- -r "$DEBIAN_SUITE"
fi

# 3. Wire static IP into LXC config (10.100.0.X on br-lxc)
cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
lxc.uts.name = $LXC_NAME
lxc.net.0.type = veth
lxc.net.0.link = br-lxc
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = 10.100.0.1
lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.apparmor.profile = generated
lxc.start.auto = 1
EOF

# 4. Start, wait for network
lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
for i in $(seq 1 30); do
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 10.100.0.1 >/dev/null 2>&1 && break
    sleep 1
done

# 5. Install the daemon (module-specific section — see per-module sections below)
lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -c '
    apt-get update -q
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        <module-specific packages>
'

# 6. Provision (dashboards / peer lists / keys)
"$(dirname "$0")/provision/run.sh"

# 7. Mark provisioned
touch /var/lib/secubox/<module>/.lxc-provisioned
```

---

## 2. CTL grammar fit

Per `docs/grammar.md`, all three modules get a new entry in the verbs table. Each CTL exposes the three-fold introspection (`components`, `status`, `access`) **plus** module-specific noun/verb pairs.

### `grafanactl` — OPS MONITORING layer (sister to `healthctl`)

| Noun | Verb |
|---|---|
| `components` | `status`, `list` |
| `status` | (no verb — prints overall state) |
| `access` | `list`, `show <name>` |
| `dashboard` | `list`, `add <file.json>`, `remove <uid>`, `export <uid>` |
| `datasource` | `list`, `add <toml>`, `remove <name>`, `test <name>` |
| `alert` | `list`, `mute <id>`, `unmute <id>` |
| `user` | `list`, `add <name> <role>`, `remove <name>`, `passwd <name>` |
| `api-key` | `list`, `create <name> <role>`, `revoke <id>` |

Help line for the grammar table addition:

```text
| OPS MONITORING       | `grafanactl   dashboard list/add/remove/export`   | #229 (this) |
```

### `yacyctl` — new layer: SEARCH (independent search-engine sovereignty, fits Punk Exposure ethos)

| Noun | Verb |
|---|---|
| `components` | `status`, `list` |
| `status` | (no verb) |
| `access` | `list`, `show` |
| `peer` | `list`, `add <url>`, `remove <hash>`, `status <hash>` |
| `index` | `status`, `build <urls.txt>`, `clear`, `optimize` |
| `query` | `test <terms>`, `count <terms>` |
| `blacklist` | `list`, `add <pattern>`, `remove <pattern>` |
| `crawler` | `list`, `start <profile>`, `stop <id>`, `schedule <profile> <cron>` |

Help line:

```text
| SEARCH               | `yacyctl      index  status/build/clear/optimize` | #230 (this) |
```

### `rustdeskctl` — new layer: REMOTE-ACCESS (peer-mediated remote desktop, also Punk Exposure)

| Noun | Verb |
|---|---|
| `components` | `status`, `list` |
| `status` | (no verb) |
| `access` | `list`, `show` |
| `peer` | `list`, `add <id> <pubkey>`, `remove <id>` |
| `relay` | `status`, `restart`, `log tail` |
| `key` | `show`, `rotate` (generates a new keypair, broadcasts to peers) |
| `session` | `list`, `kill <id>` |

Help line:

```text
| REMOTE-ACCESS        | `rustdeskctl  peer   add/remove/list`             | #231 (this) |
```

### Three-fold output (all modules)

Each `<module>ctl components`, `status`, and `access` returns JSON to stdout when `--json` is passed, formatted text otherwise. Schema mirrors existing `giteactl`/`healthctl`:

```json
{
  "module": "grafana",
  "version": "1.0.0",
  "components": [
    {"name": "lxc", "state": "running", "detail": "10.100.0.70 — uptime 3d12h"},
    {"name": "daemon", "state": "running", "detail": "grafana-server 10.4.2, port 3000"},
    {"name": "host-api", "state": "running", "detail": "uvicorn on /run/secubox/grafana.sock"}
  ]
}
```

---

## 3. Per-module specifics

### 3a. secubox-grafana

**LXC daemon install (inside LXC):**

```bash
apt-get install -y --no-install-recommends \
    apt-transport-https software-properties-common wget gnupg ca-certificates
wget -qO - https://apt.grafana.com/gpg.key | apt-key add -
echo "deb https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
apt-get update -q
apt-get install -y --no-install-recommends grafana
systemctl enable grafana-server
```

**Provisioning (from `lib/grafana/provision/`):**

- Datasources: `secubox-metrics` (prometheus on `127.0.0.1:9090` exposed to LXC via host bridge), `crowdsec-metrics`, `journald-loki` (if loki later).
- Dashboards (JSON, ship in package):
  - `nftables.json` — drops/accepts per chain/rule, geo overlay
  - `crowdsec.json` — alerts per scenario, decisions over time
  - `suricata.json` — alerts by severity, top src IPs
  - `cookie-audit.json` — RGPD/ePrivacy violations from cookie-audit ledger
  - `mitmproxy-waf.json` — Set-Cookie inspections + block decisions
  - `secubox-services.json` — secubox-* systemd unit health (vital + non-vital)

**Web UI (`www/grafana/index.html`):**

SecuBox-themed wrapper page that opens the grafana UI inside an iframe sandbox (no chrome). Top bar: SecuBox logo, links back to `/`, mode switcher. Below: full-bleed iframe at `https://<host>/grafana/d/...`. Native Grafana is hidden under the SecuBox menu so the user navigates dashboards via SecuBox menu.d.

**nginx vhost (`nginx/grafana.conf`):**

```nginx
# /etc/nginx/secubox.d/grafana.conf
location /api/v1/grafana/ {
    proxy_pass http://unix:/run/secubox/grafana.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}

# Grafana native UI (iframe target)
location /grafana/ {
    proxy_pass http://10.100.0.70:3000/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    # Grafana live websocket
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

Grafana `serve_from_sub_path` must be set true in `/etc/grafana/grafana.ini`:

```ini
[server]
domain = <vhost>
root_url = https://<vhost>/grafana/
serve_from_sub_path = true
```

### 3b. secubox-yacy

**LXC daemon install:**

```bash
apt-get install -y --no-install-recommends \
    default-jre-headless wget ca-certificates unzip
mkdir -p /opt/yacy && cd /opt/yacy
wget -q https://release.yacy.net/yacy_v1.940_20240319_10001.tar.gz
tar xzf yacy_v1.940_*.tar.gz --strip-components=1
useradd -r -s /bin/false yacy
chown -R yacy:yacy /opt/yacy
cat > /etc/systemd/system/yacy.service <<'EOF'
[Unit]
Description=YaCy P2P Search
After=network.target
[Service]
Type=simple
User=yacy
WorkingDirectory=/opt/yacy
ExecStart=/opt/yacy/startYACY.sh -d
ExecStop=/opt/yacy/stopYACY.sh
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl enable yacy
```

**Provisioning:**

- Pre-seed peer list from `lib/yacy/provision/peers.seed.txt`
- Default crawl profile: `secubox-*.in` domains, depth 2
- Blacklist seed: `lib/yacy/provision/blacklist.txt` (CrowdSec banlist excerpt)
- Admin password generated by `<module>ctl install` (firstboot-style argon2-hash to `/etc/secubox/yacy.toml`)

**WebUI wrapper:** same iframe pattern as grafana.

**nginx vhost:**

```nginx
location /api/v1/yacy/ {
    proxy_pass http://unix:/run/secubox/yacy.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
location /yacy/ {
    proxy_pass http://10.100.0.80:8090/;
    proxy_set_header Host $host;
    proxy_http_version 1.1;
}
```

### 3c. secubox-rustdesk

**LXC daemon install:**

```bash
apt-get install -y --no-install-recommends wget ca-certificates
cd /opt
wget -q https://github.com/rustdesk/rustdesk-server/releases/download/1.1.11/rustdesk-server-linux-amd64.zip
unzip rustdesk-server-linux-amd64.zip
useradd -r -s /bin/false rustdesk
mkdir /var/lib/rustdesk
chown rustdesk:rustdesk /var/lib/rustdesk /opt/amd64
# Two systemd units:
cat > /etc/systemd/system/rustdesk-hbbs.service <<'EOF'
[Unit]
Description=RustDesk Signal Server (hbbs)
After=network.target
[Service]
Type=simple
User=rustdesk
WorkingDirectory=/var/lib/rustdesk
ExecStart=/opt/amd64/hbbs
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/rustdesk-hbbr.service <<'EOF'
[Unit]
Description=RustDesk Relay Server (hbbr)
After=network.target rustdesk-hbbs.service
[Service]
Type=simple
User=rustdesk
WorkingDirectory=/var/lib/rustdesk
ExecStart=/opt/amd64/hbbr
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl enable rustdesk-hbbs rustdesk-hbbr
```

**Exposure** — *deviates from grafana/yacy*: RustDesk uses UDP (21116/udp) which mitmproxy can't inspect. Use HAProxy stream-mode TCP+UDP on the host edge:

```text
frontend rustdesk-stream
    mode tcp
    bind :21115
    bind :21116
    bind :21117
    bind :21118
    bind :21119
    default_backend rustdesk-lxc

backend rustdesk-lxc
    mode tcp
    server rustdesk 10.100.0.90 check
```

Plus a separate UDP socket forwarded via `socat` or `iptables -t nat -A PREROUTING ... -p udp --dport 21116 -j DNAT --to 10.100.0.90:21116` (use whichever is already idiomatic in `secubox-haproxy`; check `packages/secubox-haproxy/lib/` first).

Web admin UI (port 21118) still routes through nginx like the others:

```nginx
location /api/v1/rustdesk/ {
    proxy_pass http://unix:/run/secubox/rustdesk.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
location /rustdesk/ {
    proxy_pass http://10.100.0.90:21114/;
    proxy_http_version 1.1;
}
```

---

## 4. Slipstream into the next release

Once each package's `debian/control` is present and `dpkg-buildpackage -us -uc -b` succeeds locally:

- `.github/workflows/build-packages.yml` auto-discovers via `find packages/secubox-*/debian/control` and adds the new packages to the matrix on next push. No workflow edit required.
- `image/build-image.sh` slipstream loop (`cp /tmp/secubox-debs/secubox-*.deb`) picks up the new `_all.deb` files automatically.
- Verify: after the next `gh workflow run build-packages.yml --ref master`, the run summary should show three new `build (secubox-{grafana,yacy,rustdesk}, amd64)` jobs ending in `success`.
- Next image build (`build-image.yml`) then includes the three new packages in `dpkg -l 'secubox-*'`.

The new modules **do not need their LXC pre-built** in the image. Operator installs them post-firstboot via:

```bash
grafanactl install   # idempotent — runs lib/grafana/install-lxc.sh
yacyctl install
rustdeskctl install
```

This avoids inflating the image with three LXC rootfs trees (~600 MB total) when most operators won't need all three.

---

## 5. Tasks (TDD, frequent commits, one PR per module)

Each module gets its own issue + worktree + PR (per `feedback_no_unprompted_prs` memory — opening PRs unprompted needs per-PR approval; this plan is the prompt). Strongly recommended order:

1. **#229 — secubox-grafana** (most directly useful, drives operator adoption of the SecuBox stack)
2. **#230 — secubox-yacy** (independent of any other module)
3. **#231 — secubox-rustdesk** (most divergent due to UDP/HAProxy-stream — leave for last so the grafana+yacy patterns are settled)

Per-module task breakdown follows. Each `[ ]` is a single 2-5 minute action.

---

### Module 1: secubox-grafana

#### Task G1: package skeleton + debian/control

**Files:**
- Create: `packages/secubox-grafana/debian/{changelog,control,rules,install,postinst,prerm,secubox-grafana.service}`
- Create: `packages/secubox-grafana/conf/grafana.toml.example`
- Create: `packages/secubox-grafana/README.md`

- [ ] **Step 1: Write `debian/changelog`**

```text
secubox-grafana (1.0.0-1~bookworm1) bookworm; urgency=medium

  * Initial release: Grafana OSS in LXC for SecuBox security dashboards.
  * Three-fold CTL grammar (grafanactl: components, status, access).
  * Dashboard verbs: list/add/remove/export.
  * Datasource verbs: list/add/remove/test.
  * Pre-provisioned dashboards: nftables, crowdsec, suricata, cookie-audit,
    mitmproxy-waf, secubox-services.
  * Closes: #229

 -- Gerald KERMA <devel@cybermind.fr>  Wed, 20 May 2026 10:00:00 +0200
```

- [ ] **Step 2: Write `debian/control`** — use the template from §1, module-specific `Depends` from §1.
- [ ] **Step 3: Write `debian/rules`**:

```makefile
#!/usr/bin/make -f
%:
	dh $@ --with python3

override_dh_auto_install:
	install -d debian/secubox-grafana/usr/lib/secubox/grafana
	cp -r api debian/secubox-grafana/usr/lib/secubox/grafana/
	install -d debian/secubox-grafana/usr/share/secubox/grafana/provision
	[ -d lib/grafana/provision ] && cp -r lib/grafana/provision/. debian/secubox-grafana/usr/share/secubox/grafana/provision/ || true
	install -d debian/secubox-grafana/usr/sbin
	install -m 755 sbin/grafanactl debian/secubox-grafana/usr/sbin/grafanactl
	install -d debian/secubox-grafana/usr/share/secubox/www
	[ -d www ] && cp -r www/. debian/secubox-grafana/usr/share/secubox/www/ || true
	install -d debian/secubox-grafana/usr/share/secubox/menu.d
	[ -d menu.d ] && cp -r menu.d/. debian/secubox-grafana/usr/share/secubox/menu.d/ || true
	install -d debian/secubox-grafana/etc/nginx/secubox.d
	[ -f nginx/grafana.conf ] && cp nginx/grafana.conf debian/secubox-grafana/etc/nginx/secubox.d/ || true
	install -d debian/secubox-grafana/etc/secubox
	[ -f conf/grafana.toml.example ] && cp conf/grafana.toml.example debian/secubox-grafana/etc/secubox/grafana.toml.example || true
	install -d debian/secubox-grafana/usr/share/secubox/lib/grafana
	[ -d lib/grafana ] && cp -r lib/grafana/. debian/secubox-grafana/usr/share/secubox/lib/grafana/ || true
```

- [ ] **Step 4: Write `debian/postinst`** — copy from §1 template, substitute `<module>=grafana`.
- [ ] **Step 5: Write `debian/prerm`**:

```sh
#!/bin/sh
set -e
case "$1" in
    remove|deconfigure|upgrade)
        systemctl stop secubox-grafana.service 2>/dev/null || true
        systemctl disable secubox-grafana.service 2>/dev/null || true
        ;;
esac
#DEBHELPER#
exit 0
```

- [ ] **Step 6: Write `debian/secubox-grafana.service`** — use the template from §1.
- [ ] **Step 7: Local build smoke test**

Run: `cd packages/secubox-grafana && dpkg-buildpackage -us -uc -b`
Expected: `secubox-grafana_1.0.0-1~bookworm1_all.deb` produced under `..` (the parent dir), no errors.

- [ ] **Step 8: Commit**

```bash
git add packages/secubox-grafana/{debian,conf,README.md}
git commit -m "feat(secubox-grafana): package skeleton (ref #229)"
```

#### Task G2: CTL tool with three-fold introspection

**Files:**
- Create: `packages/secubox-grafana/sbin/grafanactl`
- Create: `packages/secubox-grafana/tests/helpers.bash`
- Create: `packages/secubox-grafana/tests/test-grafanactl-threefold.bats`

- [ ] **Step 1: Write the failing test**

```bats
@test "grafanactl components prints lxc/daemon/host-api with JSON output" {
    run grafanactl components --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.components | map(.name) | contains(["lxc","daemon","host-api"])'
}

@test "grafanactl status returns module=grafana and version" {
    run grafanactl status --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.module == "grafana"'
    echo "$output" | jq -e '.version != ""'
}

@test "grafanactl access list shows the public hostname when configured" {
    HOSTNAME=grafana.gk2.secubox.in
    echo 'public_hostname = "grafana.gk2.secubox.in"' > /etc/secubox/grafana.toml
    run grafanactl access list --json
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.access[] | select(.url | contains("grafana.gk2.secubox.in"))'
}
```

- [ ] **Step 2: Run the test, expect failure with `command not found: grafanactl`**.
- [ ] **Step 3: Write the minimal `sbin/grafanactl`** with `components`, `status`, `access` verbs only. Pattern: mirror `packages/secubox-gitea/sbin/giteactl`'s three-fold section.
- [ ] **Step 4: Re-run test, expect PASS**.
- [ ] **Step 5: Commit**.

#### Task G3: `grafanactl install` — provision the LXC

**Files:**
- Modify: `packages/secubox-grafana/sbin/grafanactl` (add `install` verb)
- Create: `packages/secubox-grafana/lib/grafana/install-lxc.sh`
- Create: `packages/secubox-grafana/tests/test-grafanactl-install.bats` (with stubbed `lxc-create`/`lxc-attach` via PATH shims)

- [ ] **Step 1: Write the failing test** — `grafanactl install` should call `lxc-create` and `lxc-attach` with the right args, and write `/var/lib/secubox/grafana/.lxc-provisioned` on success.
- [ ] **Step 2: Implement `install-lxc.sh`** using the §1 template with `<module>=grafana`, `IP=10.100.0.70`, `PORTS=3000`.
- [ ] **Step 3: Add `cmd_install()` to `grafanactl`** that just execs the script with sensible env.
- [ ] **Step 4: Run test, expect PASS**.
- [ ] **Step 5: Commit**.

#### Task G4: FastAPI host control plane

**Files:**
- Create: `packages/secubox-grafana/api/{__init__.py,main.py,models.py}`
- Create: `packages/secubox-grafana/tests/test-api.py` (pytest)

- [ ] **Step 1: Write the failing test** — pytest fixture spawns uvicorn on a temp socket, asserts `GET /status` returns `{"module": "grafana", "version": ..., "components": [...]}`.
- [ ] **Step 2: Write minimal `api/main.py`** — three endpoints: `GET /status`, `GET /components`, `GET /access`. Each shells out to `grafanactl <verb> --json` and returns the parsed JSON. (Same trick as `secubox-mail`'s API.)
- [ ] **Step 3: Run test, expect PASS**.
- [ ] **Step 4: Commit**.

#### Task G5: dashboard / datasource verbs

- [ ] **Step 1: Write failing bats** for `grafanactl dashboard list/add/remove/export`.
- [ ] **Step 2: Implement against the Grafana HTTP API** (`http://10.100.0.70:3000/api/dashboards/db` etc.) inside `grafanactl`. Use a stored API key from `/etc/secubox/grafana.toml` (created by `install` step).
- [ ] **Step 3: Same for `datasource list/add/remove/test`**.
- [ ] **Step 4: Pass tests, commit per noun**.

#### Task G6: pre-provisioned dashboards

**Files:**
- Create: `packages/secubox-grafana/lib/grafana/provision/dashboards/{nftables,crowdsec,suricata,cookie-audit,mitmproxy-waf,secubox-services}.json`
- Create: `packages/secubox-grafana/lib/grafana/provision/datasources/secubox-metrics.yaml`
- Modify: `lib/grafana/install-lxc.sh` to copy provisioning into `/etc/grafana/provisioning/`

- [ ] **Step 1**: write a minimal `secubox-services.json` dashboard JSON (single time-series panel: `systemd_unit_state{name=~"secubox-.*"}`).
- [ ] **Step 2**: provisioning yaml for the secubox-metrics datasource (prometheus on `http://10.100.0.X:9090` — verify port from `secubox-metrics.service`).
- [ ] **Step 3**: wire provisioning into `install-lxc.sh` (copies during step 5 of the template).
- [ ] **Step 4**: end-to-end manual test on a dev VM — `grafanactl install`, then `curl https://localhost/grafana/login` → grafana page; `grafanactl dashboard list` → shows the provisioned ones.
- [ ] **Step 5: Commit**.

#### Task G7: web UI + nginx + menu

**Files:**
- Create: `packages/secubox-grafana/www/grafana/{index.html,settings.html}`
- Create: `packages/secubox-grafana/nginx/grafana.conf`
- Create: `packages/secubox-grafana/menu.d/50-grafana.json`

- [ ] **Step 1**: `www/grafana/index.html` — SecuBox-wrapped iframe per the DESIGN-CHARTER palette. Loads `/grafana/d/secubox-services/secubox-services-overview` in iframe.
- [ ] **Step 2**: `nginx/grafana.conf` — see §3a snippet.
- [ ] **Step 3**: `menu.d/50-grafana.json`:

```json
{
  "title": "Grafana",
  "subtitle": "Security metrics",
  "icon": "fa-chart-line",
  "url": "/grafana/",
  "section": "monitoring",
  "order": 50,
  "module": "grafana"
}
```

- [ ] **Step 4**: install on dev VM, click through SecuBox menu → Grafana iframe loads.
- [ ] **Step 5: Commit**.

#### Task G8: PR + CI

- [ ] **Step 1**: open PR `feat(secubox-grafana): security-metrics dashboard module (closes #229)`.
- [ ] **Step 2**: build-packages.yml auto-runs on PR open; verify `build (secubox-grafana, amd64)` passes.
- [ ] **Step 3**: request user review.

---

### Module 2: secubox-yacy

Same structure as Grafana with the YaCy-specific deltas from §3b. Tasks mirror G1–G8 with `<module>=yacy`, `IP=10.100.0.80`, daemon=YaCy + JVM, provisioning = peer list + crawl profile + blacklist.

**Key deviation from Grafana:** YaCy doesn't expose a Prometheus-friendly metrics endpoint by default; the `grafanactl datasource add` integration with YaCy is OUT-OF-SCOPE for this plan (would require a YaCy → Prometheus exporter, separate issue).

---

### Module 3: secubox-rustdesk

Same structure with the RustDesk-specific deltas from §3c. Major deviations:

- **HAProxy stream-mode config** instead of mitmproxy route. Add to `packages/secubox-haproxy/conf/streams/rustdesk.cfg` (or wherever `haproxyctl vhost add` writes — verify). Use `haproxyctl stream add rustdesk-stream` if such a verb exists; else extend `haproxyctl` first in a separate prereq PR.
- **UDP forwarding:** decide between `nftables` (preferred, matches the project's stack) or `socat`. Add to the rustdesk `install-lxc.sh`.
- **Two systemd units** in the LXC (`rustdesk-hbbs`, `rustdesk-hbbr`) — `rustdeskctl components` must list both as separate components, not aggregated.

---

## 6. Documentation updates after merge

- [ ] `docs/grammar.md` — append three new rows to the canonical verbs table:
  - `OPS MONITORING / grafanactl dashboard list/add/remove/export / #229`
  - `SEARCH / yacyctl index status/build/clear/optimize / #230`
  - `REMOTE-ACCESS / rustdeskctl peer add/remove/list / #231`
- [ ] `HOWTO-grammar.md` — no change (recipe is unchanged; the three new modules just demonstrate it).
- [ ] `wiki/CTL-Grammar.md` — sync with `docs/grammar.md`.
- [ ] `.claude/MIGRATION-MAP.md` — add three new rows (✅ when delivered).
- [ ] `.claude/HISTORY.md` — dated entry summarising all three.

## 7. Self-review checklist (run before declaring the plan ready to execute)

- [ ] **Spec coverage:** every requirement in the user prompt (Grafana for security metrics, YaCy search, both in LXC, web UI, CTL tool, API, deps, slipstream in next release) is addressed by at least one task.
- [ ] **Rustdesk addition (mid-flight scope add):** all rustdesk-specific deltas (UDP, HAProxy stream mode, two daemons) are explicitly called out in §3c and Module 3 task list.
- [ ] **No placeholders:** every CTL noun/verb has a real spec (no "TODO" or "to be decided").
- [ ] **Type consistency:** the JSON schema in §2 ("three-fold output") matches what `grafanactl`, `yacyctl`, `rustdeskctl` will produce.
- [ ] **IP allocation:** `.70`, `.80`, `.90` confirmed free against current `grep -rohE '10\.100\.0\.[0-9]+' packages/ image/` output (verified at plan-write time; re-verify at T0 of each module).

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-20-grafana-yacy-rustdesk-lxc-modules.md`.

Two execution options:

1. **Subagent-driven** (recommended) — dispatch a fresh subagent per task, two-stage review (spec compliance + code quality) per task, three independent PRs in sequence.
2. **Inline execution** — drive each task in the main session via `superpowers:executing-plans`, batch the trivial tasks (skeleton scaffolding) with checkpoints between modules.

Strongly recommend **(1)** because each module is ~8 TDD tasks × 5 commits and benefits from independent reviewer-style checks per task. Total estimated cycle: ~3 working days end-to-end, with build-packages + build-image CI runs gating each merge.

Awaiting user decision on:
- File three separate issues (#229, #230, #231) now, or just #229 first?
- Subagent-driven vs inline execution?
- LXC IP scheme — `10.100.0.{70,80,90}` confirmed, or different range preferred?
