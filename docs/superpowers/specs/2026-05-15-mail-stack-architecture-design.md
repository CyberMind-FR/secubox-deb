<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Stack Architecture — Phase 0 Design (rev. 3)

**Date:** 2026-05-16 (rev. 3 — three-LXC topology: mail / roundcube / horde)
**Status:** Approved direction; rev. 3 reflects live-board topology after the 2026-05-16 split
**Author:** Gérald Kerma <devel@cybermind.fr>
**Scope:** Architecture-only. Each implementation phase below gets its own spec → plan → PR cycle.

> **Revision note (rev. 3, 2026-05-16):** Roundcube webmail and the new Horde Groupware Webmail are each extracted into their own LXC; the `mail` LXC keeps only Postfix + Dovecot (+ Rspamd + ClamAV after Phase 2). Invariant **I1** is rewritten from "exactly ONE LXC" to "three webmail-stack LXCs with clear single responsibilities". This change was driven by user request 2026-05-16 to add Horde as a second webmail option without conflating it with the SMTP/IMAP server.
>
> **Revision note (rev. 2, 2026-05-15):** Initial draft assumed a `/srv/lxc/` + `192.168.255.x` + `lxc.net.0.type = none` greenfield layout. Live board inspection on 2026-05-15 showed the actual single-`mail` LXC has already been hand-built on the test board with a modern unprivileged-veth layout under `/data/lxc/` + `/data/volumes/`. Invariants were corrected; Phase 1 reduced to "catch the repo source up to where the board already is, then deprecate the legacy package frame".

---

## 1. Goal

Deliver a "full-featured" multi-domain mail + collaboration stack inside a single LXC container, integrated with the existing SecuBox-Deb identity (`secubox-users`), DNS (`secubox-dns`) and storage (`secubox-nextcloud`) services.

**Definition of full-featured for this project:**
- Standards-compliant SMTP/IMAP with TLS, SPF, DKIM, DMARC, ARC
- Per-user features: ManageSieve filters, quotas, vacation, app passwords
- Multi-domain virtual hosting with per-domain DKIM keys
- Roundcube webmail with PGP (Enigma), 2FA, ManageSieve UI, CardDAV/CalDAV bridged to Nextcloud
- Mailing lists (mlmmj) and shared mailboxes
- imapsync-based migration from OpenWrt SecuBox or any external IMAP
- End-user self-service portal (password, vacation, aliases, app-passwords, sieve)
- Observability + outbound abuse policies

## 2. Non-goals

- ActiveSync / EAS protocol (Z-Push, grommunio) — not in scope this round
- JMAP (Cyrus pivot) — not in scope
- Mail archival / legal hold — not in scope
- Independent CardDAV/CalDAV server inside the mail LXC — delegated to `secubox-nextcloud`

## 3. Locked invariants

Each phase below MUST respect these. Changing one requires a new Phase 0 revision.

| # | Invariant |
|---|---|
| **I1** | Three webmail-stack LXCs, each with a single responsibility: `mail` (Postfix+Dovecot+Rspamd+ClamAV — MTA/MDA/spam), `roundcube` (Roundcube webmail), `horde` (Horde Groupware Webmail). No daemon overlap between containers. |
| **I2** | All three LXCs are **unprivileged** (`lxc.idmap = u 0 100000 65536`), veth on bridge `br-lxc`, IPv4 in `10.100.0.0/24` with gateway `10.100.0.1`: `mail` = `.10`, `horde` = `.11`, `roundcube` = `.12`. AppArmor + `debian.common.conf` includes. |
| **I3** | Antispam stack is **Rspamd** (single daemon on the `mail` LXC: greylisting + spam scoring + DKIM sign+verify + SPF + DMARC + ARC). ClamAV remains as separate AV milter on the `mail` LXC. SpamAssassin, Postgrey, OpenDKIM, opendmarc removed in Phase 2. |
| **I4** | CardDAV + CalDAV are **not** served from any mail-stack LXC. Roundcube + Horde plugins point at `https://nextcloud.gk2.secubox.in/remote.php/dav/`. |
| **I5** | Mail accounts are provisioned **by** `secubox-users`. The mail stack is a downstream consumer. Local Dovecot is the materialized projection. |
| **I6** | Outbound delivery is **direct on port 25** from the `mail` LXC. No smarthost relay. |
| **I7** | Multi-domain virtual users. Mailbox path: `/data/volumes/mail/vmail/<domain>/<user>/` (Maildir layout `cur/new/tmp` directly, no `Maildir/` subdir). Per-domain DKIM key (or Rspamd selector after Phase 2). |
| **I8** | Existing data is migrated from OpenWrt SecuBox via **imapsync** (Phase 7). |
| **I9** | Two webmails coexist: **Roundcube** (light, primary at `webmail.gk2.secubox.in`) and **Horde** (groupware, at `horde.gk2.secubox.in`). Both authenticate against the `mail` LXC's IMAP (`tls://10.100.0.10:143`). SOGo / Cyrus / grommunio remain rejected. |
| **I10** | The `mail` LXC daemons listen on `10.100.0.10`. Webmail LXCs listen on their respective `10.100.0.11` (horde) / `10.100.0.12` (roundcube), port 80. Exposure: HAProxy TCP pass-through for SMTP/IMAPS to `.10`; HAProxy → mitmproxy → LXC for HTTPS webmail traffic. |
| **I11** | Configuration source of truth: `/etc/secubox/mail.toml` on the host (mail-server side). Webmail-LXC configs (`/data/lxc/<webmail-name>/rootfs/etc/...`, one of `roundcube` or `horde`) are rendered by Phase-5-era `mailctl webmail …` subcommands. No editing config inside the LXC. |
| **I12** | **Persistent data lives on the host under `/data/volumes/mail/{vmail,config,ssl}`** (mail-server) and inside each webmail LXC's filesystem (Roundcube SQLite, Horde MariaDB). Mail-server data is bind-mounted into the `mail` LXC. Destroying any LXC rootfs MUST NOT destroy mail data (the webmail rootfs may lose session state, which is acceptable). |
| **I13** | **Existing mail data on the test board MUST be preserved.** As of 2026-05-15 the board hosts the `secubox.in` domain with five live mailboxes (`gk2`, `bat`, `bourdon`, `lemurien`, `ragondin`) under `/data/volumes/mail/vmail/secubox.in/`. Any upgrade path that touches the data directory MUST refuse to proceed if it cannot guarantee preservation. |
| **I14** | Password policy is **disabled by admin opt-out** (rev. 3, 2026-05-16). `secubox-users` password validation rejects only empty/non-string values. Restoring the policy is a one-line revert in `password_policy.py`. |

## 4. Current state (test board 192.168.1.200, surveyed 2026-05-15)

| Element | Reality |
|---|---|
| LXCs on board | `gitea`, `mail`, `matrix`, `mitmproxy`, `nextcloud`, `streamlit` |
| `mail` LXC location | `/data/lxc/mail/` (symlinked from `/var/lib/lxc/mail`) |
| `mail` LXC state | STOPPED (last touched 2026-05-08) |
| `mail` LXC networking | unprivileged, veth `br-lxc`, `10.100.0.10/24`, gw `10.100.0.1` |
| `mail` LXC bind mounts | `/data/volumes/mail/vmail` → `var/vmail`, `/data/volumes/mail/config` → `etc/mail-config`, `/data/volumes/mail/ssl` → `etc/ssl/mail` |
| Inside-LXC software | Postfix, Dovecot (core+imapd+lmtpd+pop3d), Apache2+mod_php, nginx, OpenDKIM, SpamAssassin, Roundcube (core+plugins+classic+larry skins, mysql backend), php-net-sieve |
| **NOT yet inside LXC** | Postgrey, ClamAV (planned by spec rev. 1 — never installed; rev. 2 drops Postgrey entirely and defers ClamAV to Phase 2) |
| Persistent data | `/data/volumes/mail/vmail/{secubox.in/{gk2,bat,bourdon,lemurien,ragondin},gk2}`, `/data/volumes/mail/config/{main.cf,master.cf,vmailbox,virtual,vdomains,users,aliases,...}`, `/data/volumes/mail/ssl/{fullchain.pem,privkey.pem}` (Feb 2026 ACME issue) |
| Host packages | `secubox-mail 2.1.0-1`, `secubox-mail-lxc 1.1.0-1`, `secubox-webmail 1.0.0-1`, `secubox-webmail-lxc 1.1.0-1` |
| Host service | `secubox-mail.service` is `active` (FastAPI listens, but mail LXC isn't running) |
| Postfix `main.cf` (in `/data/volumes/mail/config/`) | hostname `mail.secubox.in`, virtual mailbox domains via `/etc/postfix/vdomains`, SASL via Dovecot, TLS via `/etc/ssl/mail/`, Maildir layout |
| Roundcube webserver | Apache2 + libapache2-mod-php8.2 (BOTH nginx and apache2 packages installed inside LXC; only one needed) |
| Repo source layout (this tree) | Out of date: `mailctl` still references `/srv/lxc`, `/srv/mail`, `mail_container = "mailserver"`, `webmail_container = "roundcube"`, `192.168.255.30`. The single `mail` LXC was hand-built outside the repo. |
| Host `mail.toml` | Out of date: still has `mail_container`, `webmail_container`, `mail_ip = "192.168.255.30"`, `webmail_ip = "192.168.255.31"` |

## 5. Target architecture

### 5.1 LXC layout (canonical, rev. 3)

Three LXCs on `br-lxc` / `10.100.0.0/24`. Each has a single responsibility.

```
/var/lib/lxc/mail      -> /data/lxc/mail        (10.100.0.10)
/var/lib/lxc/horde     -> /data/lxc/horde       (10.100.0.11)
/var/lib/lxc/roundcube -> /data/lxc/roundcube   (10.100.0.12)

/data/lxc/mail/                       # MTA / MDA / spam / DKIM
    config                            # unprivileged, veth br-lxc, 10.100.0.10/24
    rootfs/
        etc/postfix/                  # rendered by mailctl
        etc/dovecot/
        etc/rspamd/                   # Phase 2+
        etc/clamav/                   # Phase 2+
        etc/mlmmj/                    # Phase 6+
        opt/start-mail.sh             # init script run by lxc.init.cmd
        var/vmail/                    # bind-mounted from /data/volumes/mail/vmail/

/data/lxc/roundcube/                  # Roundcube webmail (Apache + PHP + SQLite)
    config                            # 10.100.0.12/24
    rootfs/
        etc/apache2/sites-available/roundcube.conf
        etc/roundcube/{config.inc.php,config.inc.php.local}
        var/lib/roundcube/db/sqlite.db   # local SQLite (sessions, prefs, cache)
        var/lib/roundcube/public_html/   # docroot

/data/lxc/horde/                      # Horde Groupware Webmail (Apache + PHP + MariaDB)
    config                            # 10.100.0.11/24
    rootfs/
        etc/horde/horde/conf.php      # IMAP backend = tls://10.100.0.10:143
        etc/apache2/sites-available/horde.conf
        var/lib/mysql/                # local MariaDB (Horde tables)
        usr/share/horde/              # the Horde tree (Debian packages)

/data/volumes/mail/                   # Mail-server persistent data (bind into mail LXC)
    vmail/                            # Maildirs at <domain>/<user>/{cur,new,tmp}
        secubox.in/{bat,bourdon,gk2,lemurien,ragondin}/
        <future-domain>/<user>/
    config/                           # Postfix/Dovecot lookup tables, owned by host
        main.cf, master.cf
        users, vmailbox, virtual, valias, vdomains, aliases
        *.lmdb (rebuilt by postmap)
    ssl/                              # ACME-issued certs (host renews, container reads)
    dkim/                             # per-domain keys (Phase 2 owned by Rspamd)
    rspamd/                           # Phase 2 — bayes corpus, history
    clamav/                           # Phase 2 — virus signature DB
    sieve/                            # Phase 4 — per-user sieve scripts
    mlmmj/                            # Phase 6 — mailing list spools
```

Webmail LXCs do **not** bind-mount mail data — they reach Dovecot via IMAP over `tls://10.100.0.10:143`. Each webmail LXC owns its own user-prefs / session store (SQLite for Roundcube, MariaDB for Horde).

### 5.2 Network and ports

| LXC | IP | Listener | Port | Protocol | Exposed how |
|---|---|---|---|---|---|
| mail | 10.100.0.10 | Postfix smtpd | 25 | SMTP | HAProxy TCP pass-through, WAN |
| mail | 10.100.0.10 | Postfix submission | 587 | SMTP+STARTTLS+SASL | HAProxy TCP pass-through, WAN |
| mail | 10.100.0.10 | Postfix submissions | 465 | SMTPS+SASL | HAProxy TCP pass-through, WAN |
| mail | 10.100.0.10 | Dovecot imap | 143 | IMAP+STARTTLS | LAN-internal (both webmail LXCs + host) |
| mail | 10.100.0.10 | Dovecot imaps | 993 | IMAPS | HAProxy TCP pass-through, WAN |
| mail | 10.100.0.10 | Dovecot ManageSieve | 4190 | sieve+STARTTLS | HAProxy TCP pass-through, WAN |
| mail | 10.100.0.10 | Rspamd controller | 11334 | HTTP | host nginx admin auth (Phase 2+) |
| mail | 10.100.0.10 | Rspamd worker-proxy | 11332 | milter | localhost-in-LXC only (Phase 2+) |
| mail | 10.100.0.10 | ClamAV milter | 8894 | milter | localhost-in-LXC only (Phase 2+) |
| horde | 10.100.0.11 | Apache (Horde) | 80 | HTTP | HAProxy → mitmproxy → LXC :80 |
| roundcube | 10.100.0.12 | Apache (Roundcube) | 80 | HTTP | HAProxy → mitmproxy → LXC :80 |

Host nginx + HAProxy publish:

- `https://mail-admin.gk2.secubox.in/` → FastAPI on UNIX socket `/run/secubox/mail.sock`
- `https://webmail.gk2.secubox.in/` → `http://10.100.0.12:80/` (Roundcube LXC)
- `https://horde.gk2.secubox.in/` → `http://10.100.0.11:80/` (Horde LXC)
- `https://mail.gk2.secubox.in/.well-known/autoconfig/...` → FastAPI autoconfig
- `https://rspamd.gk2.secubox.in/` → `http://10.100.0.10:11334/` (Phase 2+, admin-auth gated)

The mitmproxy route map (`/srv/mitmproxy/haproxy-routes.json`, both host copy and LXC copy) MUST have entries for `webmail.gk2.secubox.in`, `horde.gk2.secubox.in`, and `rspamd.gk2.secubox.in` after Phase 2. The `sync-mitmproxy-routes.sh` `DEAD_CONTAINER_IPS` list MUST NOT include `10.100.0.10`, `.11`, or `.12`.

### 5.3 Daemon inventory (end of Phase 8)

**Inside `mail` LXC:**

| Daemon | Source | Role | Phase added |
|---|---|---|---|
| Postfix | Debian | MTA | already on board |
| Dovecot | Debian | IMAP + LMTP + ManageSieve + SASL auth | already on board |
| Rspamd | Debian | Greylist + spam + DKIM + SPF + DMARC + ARC + ratelimit | Phase 2 |
| ClamAV (clamd + clamav-milter) | Debian | Virus scan | Phase 2 |
| mlmmj | Debian | Mailing lists | Phase 6 |
| acme.sh | upstream | TLS cert renewal | host-side, already wired |
| imapsync | upstream | One-shot per migration job | Phase 7 |

**Inside `roundcube` LXC:**

| Daemon | Source | Role |
|---|---|---|
| Apache2 + libapache2-mod-php8.2 | Debian | Roundcube webserver |
| Roundcube (1.6.x) | Debian | Webmail (classic/larry skins, plugins, SQLite backend) |

**Inside `horde` LXC:**

| Daemon | Source | Role |
|---|---|---|
| Apache2 + libapache2-mod-php8.2 | Debian | Horde webserver |
| Horde Groupware Webmail (5.x) | Debian (`php-horde-webmail`) | IMP webmail + Kronolith cal + Turba contacts + Ingo filters + Nag tasks + Mnemo notes |
| MariaDB | Debian | Horde tables (users prefs, sessions, calendars) |

**Daemons removed by Phase 2** (from the `mail` LXC): SpamAssassin, OpenDKIM. Apache + Roundcube were already removed from `mail` LXC by the rev. 3 split (moved to `roundcube` LXC). (Postgrey was planned by rev. 1 but never installed; dropped from scope.)

### 5.4 Identity / provisioning flow (Phase 3)

```
secubox-users API ──"user.created"──▶ mail provisioning webhook
                                       │
                                       ▼
                                 mailctl provision <user@domain>
                                       │
                                       ├──▶ /data/volumes/mail/vmail/<domain>/<user>/Maildir (mkdir + perms)
                                       ├──▶ append /data/volumes/mail/config/users (Dovecot passwd-file, SHA512-CRYPT)
                                       ├──▶ append /data/volumes/mail/config/vmailbox (Postfix virtual_mailbox_maps)
                                       └──▶ postmap if needed; notify Rspamd
```

Password sync: `secubox-users` POSTs `/internal/password` over UNIX socket on every change. No password ever leaves the host except as the SHA512-CRYPT hash already stored in Dovecot's `users` file.

### 5.5 DNS records owned by the mail stack

For each managed domain, `mailctl dns-records <domain>` emits records `secubox-dns` must publish:

```
mail.<domain>           A      <public IP>
<domain>                MX 10  mail.<domain>.
<domain>                TXT    "v=spf1 mx -all"
default._domainkey.<domain>   TXT  "v=DKIM1; k=rsa; p=<pubkey>"
_dmarc.<domain>         TXT    "v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>; ruf=mailto:postmaster@<domain>; adkim=s; aspf=s"
_imaps._tcp.<domain>    SRV    "0 1 993 mail.<domain>."
_submission._tcp.<domain> SRV  "0 1 587 mail.<domain>."
autoconfig.<domain>     CNAME  mail.<domain>.
autodiscover.<domain>   CNAME  mail.<domain>.
```

Phase 3 wires this to `secubox-dns` via API.

### 5.6 `mail.toml` schema (target — end of Phase 3)

```toml
[mail]
enabled = true
hostname = "mail.gk2.secubox.in"
container = "mail"
lxc_path = "/var/lib/lxc"          # symlink to /data/lxc on this board
data_path = "/data/volumes/mail"
lxc_ip = "10.100.0.10"
lxc_bridge = "br-lxc"
lxc_gateway = "10.100.0.1"

[[mail.domain]]
name = "secubox.in"
primary = true
dkim_selector = "default"
dmarc_policy = "quarantine"
catchall = ""

[mail.tls]
provider = "acme"
acme_email = "postmaster@secubox.in"

[mail.rspamd]                        # Phase 2+
greylist = true
bayes_autolearn = true
ratelimit_outbound = "100/h/user"

[mail.identity]                      # Phase 3+
source = "secubox-users"
provisioning_url = "http://127.0.0.1:8093/api/v1/users"

[mail.dav]                           # Phase 5+
provider = "secubox-nextcloud"
url = "https://nextcloud.gk2.secubox.in/remote.php/dav/"

[mail.webmail]                       # Phase 5+
enabled = true
url = "https://webmail.gk2.secubox.in/"
plugins = ["managesieve", "carddav", "calendar", "enigma", "twofactor"]

[mail.lists]                         # Phase 6+
enabled = false
default_domain = "lists.gk2.secubox.in"
```

## 6. Phase plan (revised)

Phase 1 is now substantially smaller: most of the architectural bones are already on the board; the repo source just doesn't reflect them yet.

| # | Phase | Effort | Critical-path? |
|---|---|---|---|
| **0** | Architecture spec (this doc, rev. 2) | done | — |
| **1** | **Reconcile source ↔ board, deprecate legacy packages, lock the data contract** | 2–3 days | yes |
| **2** | Rspamd migration (drops SA + OpenDKIM, adds ClamAV) | 1 wk | yes |
| **3** | Multi-domain + `secubox-users` provisioning hook | 1.5 wk | yes |
| **4** | ManageSieve + quotas + vacation | 1 wk | yes |
| **5** | Roundcube polish + Nextcloud DAV bridge + (optional) Apache→nginx+php-fpm | 1 wk | no |
| **6** | mlmmj mailing lists + shared mailboxes | 1 wk | no |
| **7** | imapsync migration tooling | 1 wk | no |
| **8** | Self-service portal + observability + outbound abuse policies | 1.5 wk | no |

**Total:** ~8 weeks. Phase 5–8 can interleave once Phase 3 is in.

### Phase 1 — revised goal: "source-catch-up + legacy package cleanup"

**Deliverables**
- Repo source updated to canonical paths/IP: `/var/lib/lxc/mail`, `/data/volumes/mail`, `10.100.0.10`, unprivileged veth br-lxc. (`mailctl`, `mailserverctl`, `roundcubectl`, `api/main.py`.)
- `mail.toml` schema: single `container`, `lxc_ip`, `lxc_bridge`, `lxc_gateway`, `data_path`. Drop `mail_container`/`webmail_container`/`mail_ip`/`webmail_ip`/`webmail_port`.
- `lib/install.sh` + `lib/lxc.sh` extracted from `mailserverctl` for re-use.
- `mailctl migrate-config` rewrites a legacy `mail.toml` in place. Idempotent.
- `mail-migrate-to-single-lxc.sh` becomes a defensive **scanner** that detects old `mailserver`/`roundcube` LXC directories (none expected on this board) and old toml keys, and applies safe migration. **Refuses to touch `/data/volumes/mail/` if data is present** (per I13).
- Legacy `secubox-mail-lxc`, `secubox-webmail-lxc`, `secubox-webmail` packages → transitional metadata-only `2.2.0` packages that just `Depends: secubox-mail (>= 2.2)`.
- `secubox-mail` bumps to `2.2.0` (one minor higher than current `2.1.0`) with `Breaks:`/`Replaces:` against the transitional packages.
- Host nginx vhost: `mail-admin.<base>` → FastAPI socket; `webmail.<base>` → `http://10.100.0.10:80/`. Replaces both `packages/secubox-mail/nginx/mail.conf` and `packages/secubox-webmail/nginx/webmail.conf` with one `common/nginx/modules.d/mail.conf`.
- HAProxy SMTP/submission/IMAPS/sieve backends targeting `10.100.0.10`.
- API `main.py` updated to read new keys; all 62 endpoints respond non-5xx (presence test).
- Acceptance: from clean checkout + deploy, `mailctl status` correctly reports the existing `mail` LXC; `mailctl start` brings it up; existing 5 `secubox.in` users can IMAP login; Roundcube responds via host proxy.

**Explicitly out of Phase 1:**
- Installing Postgrey / ClamAV inside the LXC — Phase 2 handles ClamAV; Postgrey is dropped entirely.
- Multi-domain refactor — Phase 3.
- Apache → nginx+php-fpm migration — Phase 5 if desired.
- Roundcube CardDAV/CalDAV plugin wiring — Phase 5.

## 7. Deprecations and breaking changes

| Item | Phase | Migration |
|---|---|---|
| `secubox-mail-lxc` package | 1 | Transitional 2.2.0 stub depending on `secubox-mail (>= 2.2)`. Removed entirely in 3.0. |
| `secubox-webmail-lxc` package | 1 | Same |
| `secubox-webmail` package | 1 | Same — its API surface folded into `secubox-mail` API. |
| `mail_container`, `webmail_container`, `mail_ip`, `webmail_ip`, `webmail_port` in `mail.toml` | 1 | `mailctl migrate-config` rewrites to single `container`/`lxc_ip` + comments the old keys for one release. |
| `/srv/lxc/`, `/srv/mail/` paths in source | 1 | Replaced by `/var/lib/lxc/` and `/data/volumes/mail/` everywhere. |
| `192.168.255.30/31` IP literals in source | 1 | Replaced by `10.100.0.10` (and `lxc_ip` lookup from toml). |
| OpenDKIM (`/dkim/*` API) | 2 | Rspamd DKIM module; old endpoints proxy for one minor version, removed in 3.0. |
| SpamAssassin (`/spam/*`) | 2 | Rspamd spam scoring; same pattern. |
| Postgrey (`/grey/*`) | 2 | Rspamd greylist module; the `/grey/*` endpoints were stubbed but Postgrey was never installed — endpoints return informative deprecation responses. |
| `domain` scalar in `mail.toml` | 3 | Migrated to `[[mail.domain]]` array. |

## 8. GitHub issue plan

| # | Title | Label | Phase |
|---|---|---|---|
| TBD | Mail stack: Phase 1 — source-catch-up + legacy package cleanup | `migration,wip` | 1 |
| TBD | Mail stack: Phase 2 — Rspamd migration | `migration,security` | 2 |
| TBD | Mail stack: Phase 3 — multi-domain + secubox-users integration | `migration,api` | 3 |
| TBD | Mail stack: Phase 4 — ManageSieve + quotas + vacation | `api,frontend` | 4 |
| TBD | Mail stack: Phase 5 — Roundcube polish + Nextcloud DAV bridge | `frontend` | 5 |
| TBD | Mail stack: Phase 6 — mailing lists + shared mailboxes | `api,frontend` | 6 |
| TBD | Mail stack: Phase 7 — imapsync migration tooling | `migration` | 7 |
| TBD | Mail stack: Phase 8 — self-service portal + metrics + abuse | `frontend,infra` | 8 |

Issues filed at start of each phase.

## 9. Open questions (deferred to per-phase specs)

- **Roundcube webserver (Phase 5):** Keep Apache+mod_php (current) or migrate to nginx+php-fpm? Decided in Phase 5 spec. Phase 1 does **not** touch this.
- **PGP key escrow (Phase 5/8):** read-only after import vs. user-managed in self-service portal?
- **HAProxy SMTP cert handling:** TCP pass-through (current direction) vs. terminate at HAProxy with shared cert. Phase 1 stays pass-through; revisit only if cert renewal proves painful.
- **Mailing list tool (Phase 6):** mlmmj vs. Mailman 3?

## 10. ANSSI / CSPN posture

- **Privilege separation:** every daemon under its own user. LXC unprivileged adds a second layer (root inside LXC = uid 100000 outside).
- **Audit logging:** all admin actions (provision, delete, password reset, sieve edit) appended to `/data/volumes/mail/audit.log` and to `secubox-users` audit stream.
- **Double-buffer config:** `mailctl` writes Postfix/Dovecot/Rspamd config under `/data/volumes/mail/config/shadow/`, validates with `postfix check` / `doveconf -n`, atomic-swap to `active/`. Keeps R1..R4.
- **AppArmor profiles:** one per daemon, shipped by `secubox-mail` debian/, enforced via `postinst`.
- **Secrets:** Dovecot SHA512-CRYPT only; DKIM private keys 0600 owned by `_rspamd` (post-Phase-2); ACME private keys 0600 owned by root. Nothing leaves the host.

---

**End of Phase 0 spec rev. 2.** Next: revised Phase 1 plan, then user re-confirmation, then execution.
