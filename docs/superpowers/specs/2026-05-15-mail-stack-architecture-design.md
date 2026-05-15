# Mail Stack Architecture — Phase 0 Design

**Date:** 2026-05-15
**Status:** Approved (brainstorm complete, awaiting user review of this written spec)
**Author:** Gérald Kerma <devel@cybermind.fr>
**Scope:** Architecture-only. Each implementation phase below gets its own spec → plan → PR cycle.

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

These are the architectural decisions ratified during brainstorming on 2026-05-15. Each phase below MUST respect them. Changing one requires a new Phase 0 spec.

| # | Invariant |
|---|---|
| I1 | Exactly ONE LXC container named `mail` at `/srv/lxc/mail`. No separate `mailserver` and `roundcube` LXCs. |
| I2 | Antispam stack is **Rspamd** (sole daemon for greylisting, spam scoring, DKIM signing+verify, SPF, DMARC, ARC). ClamAV remains as separate AV milter. SpamAssassin, Postgrey, OpenDKIM, opendmarc are removed. |
| I3 | CardDAV + CalDAV are **not** served from the mail LXC. Roundcube plugins point at `https://nextcloud.gk2.secubox.in/remote.php/dav/`. |
| I4 | Mail accounts are provisioned **by** `secubox-users`. The mail stack is a downstream consumer, not the authority. Local Dovecot user db is the materialized projection. |
| I5 | Outbound delivery is **direct on port 25**. No smarthost relay. PTR/rDNS must be correct. |
| I6 | Multi-domain virtual users. Mailbox path: `/srv/mail/<domain>/<user>/`. Per-domain DKIM key. |
| I7 | Existing data is migrated from OpenWrt SecuBox via **imapsync** (Phase 7). Greenfield is acceptable for early phases. |
| I8 | Webmail = Roundcube. SOGo / Cyrus / grommunio are explicitly rejected for this round. |
| I9 | All container daemons listen on the LXC's IP only (`192.168.255.30`), exposed to the LAN/WAN via the host's HAProxy (TLS) and nginx (HTTP admin). |
| I10 | Configuration source of truth: `/etc/secubox/mail.toml` on the host, rendered into the LXC by `mailctl`. No editing config inside the LXC. |

## 4. Current state — what already exists

### 4.1 Packages (host-side)

| Package | Lines | Role | Action |
|---|---|---|---|
| `secubox-mail` | ~3,200 (sbin) + 62 API endpoints | Admin UI + mailctl/mailserverctl/roundcubectl | **Refactor heavily** in phases 1–4 |
| `secubox-webmail` | API + UI | Webmail admin (start/stop/config) | **Merge** into `secubox-mail` in Phase 1 |
| `secubox-mail-lxc` | thin LXC wrapper | Standalone mail LXC controls | **Deprecate** in Phase 1 |
| `secubox-webmail-lxc` | thin LXC wrapper | Standalone webmail LXC controls | **Deprecate** in Phase 1 |
| `secubox-smtp-relay` | placeholder | SMTP relay/smarthost | Out of scope (invariant I5) |
| `secubox-users` | full | Identity authority | **Integrate** in Phase 3 (provisioning hook) |
| `secubox-dns` | full | DNS zone master | **Integrate** in Phase 3 (export MX/SPF/DKIM/DMARC records) |
| `secubox-nextcloud` | full | CardDAV/CalDAV authority | **Integrate** in Phase 5 (Roundcube plugin target) |

### 4.2 mailserverctl v2.6.0 capabilities (to be replaced/folded in)

- LXC create/start/stop/restart/destroy
- Postfix + Dovecot install via debootstrap
- DKIM (OpenDKIM) — keygen, install, configure, sync ← **replaced by Rspamd in Phase 2**
- SpamAssassin — setup, enable, disable, update ← **removed in Phase 2**
- Postgrey — setup, enable, disable ← **removed in Phase 2**
- ClamAV — setup, enable, disable, update ← **kept**
- ACME — issue, renew, install ← **kept**
- SSL — selfsigned, status ← **kept**

### 4.3 Existing 62 API endpoints

Inventory in `packages/secubox-mail/api/main.py`. Phase 1 keeps all paths stable; phases 2–8 add new ones. Removals (DKIM-via-OpenDKIM, spam-via-SA, grey-via-postgrey) are replaced by `/rspamd/*` in Phase 2 — the old paths become thin shims for one minor version, then disappear in v3.0.

## 5. Target architecture

### 5.1 LXC layout

```
/srv/lxc/mail/                     # Single LXC root
  rootfs/                          # Debian bookworm arm64
    etc/postfix/
    etc/dovecot/
    etc/rspamd/
    etc/clamav/
    etc/apache2/  or  etc/nginx/   # Roundcube webserver
    etc/roundcube/
    etc/mlmmj/
    opt/
      start-mail.sh                # systemd-less init for the LXC
      rspamd-hook.sh
  config                           # LXC config (mounts, caps, cgroups)

/srv/mail/                         # Persistent data, bind-mounted into LXC
  vmail/<domain>/<user>/           # Maildir per virtual user
  dkim/<domain>/                   # Per-domain RSA 2048 keys
  ssl/                             # ACME-issued certs
  rspamd/                          # Bayes corpus + history
  clamav/                          # Virus signature DB
  mlmmj/<list>/                    # Mailing list spools
  sieve/<domain>/<user>/           # Per-user sieve scripts
  roundcube/                       # Roundcube user data (logs, plugins state)
```

### 5.2 Network and ports

LXC IP: `192.168.255.30` (LAN bridge). No NAT, no veth — uses host network namespace bridge.

| Listener | Port | Protocol | Exposed how |
|---|---|---|---|
| Postfix smtpd | 25 | SMTP | LAN + WAN (DNAT from host) |
| Postfix submission | 587 | SMTP+STARTTLS+SASL | LAN + WAN |
| Postfix submissions | 465 | SMTPS+SASL | LAN + WAN |
| Dovecot imap | 143 | IMAP+STARTTLS | LAN only |
| Dovecot imaps | 993 | IMAPS | LAN + WAN |
| Dovecot ManageSieve | 4190 | sieve+STARTTLS | LAN + WAN |
| Rspamd controller | 11334 | HTTP | LAN admin only, behind host nginx |
| Rspamd worker | 11332 | milter | localhost-in-LXC only |
| ClamAV milter | 8894 | milter | localhost-in-LXC only |
| Roundcube HTTP | 80 / 443 | HTTP | Behind host HAProxy on `webmail.<domain>` |
| mlmmj-receive | n/a | local pipe via Postfix transport | — |

Host nginx publishes:
- `https://mail-admin.gk2.secubox.in/` → SecuBox admin UI (this packages's `www/mail/`)
- `https://webmail.gk2.secubox.in/` → Roundcube in LXC
- `https://mail.gk2.secubox.in/.well-known/autoconfig/...` → autoconfig responses from FastAPI
- `https://rspamd.gk2.secubox.in/` → Rspamd UI (admin auth)

### 5.3 Daemon inventory (final state, end of Phase 8)

Inside `mail` LXC:

| Daemon | Source | Role |
|---|---|---|
| Postfix | Debian | MTA |
| Dovecot | Debian | IMAP + LMTP + ManageSieve + SASL auth backend |
| Rspamd | Debian | Greylist + spam + DKIM + SPF + DMARC + ARC + ratelimit |
| ClamAV (clamd + clamav-milter) | Debian | Virus scan |
| Roundcube | Debian | Webmail (PHP-FPM + Apache or nginx) |
| mlmmj | Debian | Mailing lists |
| acme.sh | upstream | TLS cert renewal |
| imapsync | upstream | One-shot per migration job, not a long-running daemon |

No SpamAssassin, no Postgrey, no OpenDKIM, no opendmarc.

### 5.4 Identity / provisioning flow

```
secubox-users API  ──"user.created"──▶  mail provisioning webhook
                                         │
                                         ▼
                                   mailctl provision <user@domain>
                                         │
                                         ├──▶ /srv/mail/vmail/<domain>/<user>/  (mkdir + perms)
                                         ├──▶ Dovecot passwd-file: append entry (hashed password)
                                         ├──▶ Postfix virtual_mailbox_maps: append
                                         └──▶ Notify Rspamd (no-op for now, hook for per-user policies)
```

Password sync: `secubox-users` POSTs `/internal/password` (mTLS or shared-secret over UNIX socket) on every password change. No password is stored in the mail LXC outside Dovecot's auth-passdb.

### 5.5 DNS records owned by the mail stack

For each managed domain, `mailctl dns-records <domain>` emits the records that `secubox-dns` must publish:

```
mail.<domain>           A      <public IP>
<domain>                MX 10  mail.<domain>.
<domain>                TXT    "v=spf1 mx -all"
default._domainkey.<domain>  TXT  "v=DKIM1; k=rsa; p=<pubkey>"
_dmarc.<domain>         TXT    "v=DMARC1; p=quarantine; rua=mailto:postmaster@<domain>; ruf=mailto:postmaster@<domain>; adkim=s; aspf=s"
_imaps._tcp.<domain>    SRV    "0 1 993 mail.<domain>."
_submission._tcp.<domain> SRV  "0 1 587 mail.<domain>."
autoconfig.<domain>     CNAME  mail.<domain>.
autodiscover.<domain>   CNAME  mail.<domain>.
```

Phase 3 wires this to `secubox-dns` via API call instead of manual paste.

### 5.6 `mail.toml` schema (target — end of Phase 3)

```toml
[mail]
enabled = true
hostname = "mail.gk2.secubox.in"           # host of the mail LXC (used in HELO, certs)
data_path = "/srv/mail"
lxc_path = "/srv/lxc"
container = "mail"                          # single LXC name
lxc_ip = "192.168.255.30"

[[mail.domain]]
name = "gk2.secubox.in"
primary = true                              # one domain MUST be primary (postmaster, ACME)
dkim_selector = "default"                   # selector for DKIM TXT record
dmarc_policy = "quarantine"                 # none | quarantine | reject
catchall = ""                               # optional catchall recipient

[[mail.domain]]
name = "cybermind.fr"
primary = false
dkim_selector = "default"
dmarc_policy = "quarantine"

[mail.tls]
provider = "acme"                           # acme | manual | selfsigned
acme_email = "postmaster@gk2.secubox.in"

[mail.rspamd]
greylist = true
bayes_autolearn = true
ratelimit_outbound = "100/h/user"           # postfix-policyd-style rate limits

[mail.identity]
source = "secubox-users"                    # secubox-users | local
provisioning_url = "http://127.0.0.1:8093/api/v1/users"  # for pull-on-startup reconciliation

[mail.dav]
provider = "secubox-nextcloud"              # secubox-nextcloud | radicale | none
url = "https://nextcloud.gk2.secubox.in/remote.php/dav/"

[mail.webmail]
enabled = true
url = "https://webmail.gk2.secubox.in/"
plugins = ["managesieve", "carddav", "calendar", "enigma", "twofactor"]

[mail.lists]
enabled = true
default_domain = "lists.gk2.secubox.in"     # mlmmj base
```

## 6. Phase plan

Each phase below produces its own design spec, plan, and PR. Phases 5–8 can interleave once Phase 3 is merged; phases 1→2→3→4 are strictly sequential.

### Phase 1 — LXC consolidation
- **Goal:** Collapse `mailserver` + `roundcube` LXCs into single `mail` LXC.
- **Deliverables:**
  - New `mailctl` skeleton driving `/srv/lxc/mail`
  - Data migration script: `/srv/lxc/mailserver/rootfs/var/mail/*` → `/srv/mail/vmail/`, similar for Roundcube state
  - `secubox-mail-lxc` and `secubox-webmail-lxc` marked `Conflicts:` and removed via `postinst`
  - Roundcube installed inside `mail` LXC (Apache or nginx; one webserver chosen here)
  - Nginx host proxy updated: `webmail.<domain>` → LXC, `mail-admin.<domain>` → secubox-mail FastAPI
  - All existing 62 API endpoints still answer (no contract break this phase)
- **Acceptance:** old endpoints respond; one LXC running; `lxc-ls` shows only `mail`; smoke test sends + reads a message via IMAPS.

### Phase 2 — Rspamd migration
- **Goal:** Replace SA + Postgrey + OpenDKIM + opendmarc with Rspamd.
- **Deliverables:**
  - Rspamd installed inside LXC, milter on `127.0.0.1:11332`
  - `smtpd_milters = inet:127.0.0.1:11332` in Postfix
  - Per-domain DKIM keys moved from `/etc/opendkim/keys/<domain>/` to `/srv/mail/dkim/<domain>/`; Rspamd `dkim_signing` module reads them
  - SA / Postgrey / OpenDKIM / opendmarc removed (apt purge) inside LXC
  - Rspamd web UI behind host nginx with admin JWT
  - New endpoints: `/rspamd/{status,history,learn-spam,learn-ham,scores}`
  - Old endpoints `/spam/*`, `/grey/*`, `/dkim/*` proxied to Rspamd-equivalent for one release, then dropped in v3.0
- **Acceptance:** Postfix logs show milter wins through Rspamd; DKIM-Signature header present on outbound; spam test (GTUBE) blocked; greylist visible in Rspamd UI.

### Phase 3 — Multi-domain + identity wiring
- **Goal:** Make the stack truly multi-domain and driven by `secubox-users`.
- **Deliverables:**
  - Dovecot vmail with `mail_location = maildir:/srv/mail/vmail/%d/%n`
  - Postfix `virtual_mailbox_domains/maps/alias_maps` as flat files synced by `mailctl reconcile`
  - Per-domain DKIM keygen + publish via `secubox-dns` API
  - `secubox-users` provisioning hook: webhook handler in secubox-mail API that consumes user-lifecycle events
  - `mailctl reconcile` command: pull full user list from `secubox-users`, diff against local state, apply
  - `[[mail.domain]]` array in `mail.toml`; old single `domain=` value migrated automatically
  - Autoconfig/autodiscover/mobileconfig respond per-domain
- **Acceptance:** create user in secubox-users UI → mailbox auto-provisioned within 5s; second domain added via `mailctl domain add` produces DKIM record visible in DNS UI.

### Phase 4 — ManageSieve + quotas + vacation
- **Goal:** Per-user features expected by any modern mail client.
- **Deliverables:**
  - Dovecot ManageSieve listener on 4190
  - Dovecot quota plugin (per-user, configurable default in `mail.toml`)
  - Vacation/auto-reply via Sieve (`vacation` extension)
  - Roundcube ManageSieve plugin enabled
  - API: `/user/{email}/quota`, `/user/{email}/sieve`, `/user/{email}/vacation`
- **Acceptance:** Roundcube Filters tab works; over-quota mail is rejected with 5.2.2; vacation reply throttle-once-per-day verified.

### Phase 5 — Roundcube polish + groupware delegation
- **Goal:** Make Roundcube feel like part of SecuBox and surface contacts/calendars from Nextcloud.
- **Deliverables:**
  - Roundcube CardDAV plugin (`kolab/carddav` or `larsneo/carddav`) pointed at `https://nextcloud.<domain>/remote.php/dav/addressbooks/users/<user>/contacts/`
  - Roundcube CalDAV plugin similarly
  - Enigma (PGP) plugin enabled with per-user keyrings under `/srv/mail/roundcube/pgp/<user>/`
  - 2FA plugin (TOTP) enabled, sharing secret store with `secubox-users` if possible
  - SecuBox CRT-light theme ported to Roundcube skin format
- **Acceptance:** Roundcube address book lists Nextcloud contacts; calendar view shows Nextcloud events; PGP-signed test message verified end-to-end.

### Phase 6 — Mailing lists + shared mailboxes
- **Goal:** Collaboration features.
- **Deliverables:**
  - mlmmj installed in LXC
  - Postfix transport map: `<list>@lists.<domain>` → `mlmmj:/srv/mail/mlmmj/<list>`
  - Dovecot `acl` plugin for shared mailbox grants
  - List admin UI under `/api/v1/mail/list/*`
- **Acceptance:** create list, subscribe two users, post a message, both receive; share a folder from user A to user B, B sees it in Roundcube.

### Phase 7 — Migration tooling (imapsync)
- **Goal:** Import existing mail from OpenWrt SecuBox or any external IMAP.
- **Deliverables:**
  - `imapsync` packaged inside LXC (or invoked from host via lxc-attach)
  - UI: add source credentials, map source-user → target-user@domain, schedule sync
  - Progress tracker in API (`/migrate/job/{id}`)
  - Bulk-import helper for OpenWrt SecuBox dump format
- **Acceptance:** sync a 500-message mailbox from external IMAP, target receives all messages with flags preserved, UI shows job complete.

### Phase 8 — Self-service portal + observability + abuse handling
- **Goal:** End-user UX + ops hygiene.
- **Deliverables:**
  - Self-service portal (separate nginx vhost or sub-path under webmail): change password, vacation, aliases, app-passwords, sieve editor, quota gauge
  - Postfix/Dovecot/Rspamd metrics exported to `secubox-metrics`
  - Outbound rate-limit policy (Rspamd `ratelimit` module + Postfix policy delegation)
  - Bounce/NDR parsing dashboard
- **Acceptance:** end user logs in to portal with their normal mail credentials, changes password, sees change reflected next login; outbound burst above policy is throttled with 4xx; bounce summary visible in admin UI.

## 7. Deprecations and breaking changes

| Item | Phase | Migration |
|---|---|---|
| `secubox-mail-lxc` package | 1 | `apt purge` on upgrade; postinst checks for old LXC and migrates data |
| `secubox-webmail-lxc` package | 1 | Same |
| `secubox-webmail` package | 1 | Folded into `secubox-mail`; postinst migrates `/etc/secubox/webmail.toml` keys into `[mail.webmail]` table |
| `mail_container` + `webmail_container` in `mail.toml` | 1 | Replaced by single `container` key |
| `mail_ip` + `webmail_ip` | 1 | Replaced by single `lxc_ip` |
| OpenDKIM (and `/dkim/*` API surface) | 2 | Rspamd DKIM module; old endpoints proxy for one minor version, removed in v3.0 |
| SpamAssassin (`/spam/*`) | 2 | Same pattern |
| Postgrey (`/grey/*`) | 2 | Same pattern |
| opendmarc | 2 | Rspamd DMARC module |
| `domain` (scalar) in `mail.toml` | 3 | Migrated to `[[mail.domain]]` array by `mailctl migrate-config` |

## 8. GitHub issue plan

| # | Title | Label | Phase |
|---|---|---|---|
| TBD | Mail stack: Phase 1 — consolidate to single LXC | `migration,wip` | 1 |
| TBD | Mail stack: Phase 2 — Rspamd migration | `migration,security` | 2 |
| TBD | Mail stack: Phase 3 — multi-domain + secubox-users integration | `migration,api` | 3 |
| TBD | Mail stack: Phase 4 — ManageSieve + quotas + vacation | `api,frontend` | 4 |
| TBD | Mail stack: Phase 5 — Roundcube polish + Nextcloud DAV bridge | `frontend` | 5 |
| TBD | Mail stack: Phase 6 — mailing lists + shared mailboxes | `api,frontend` | 6 |
| TBD | Mail stack: Phase 7 — imapsync migration tooling | `migration` | 7 |
| TBD | Mail stack: Phase 8 — self-service portal + metrics + abuse | `frontend,infra` | 8 |

Issues are filed when each phase begins, not all at once. Each phase ref's its issue in commits per CLAUDE.md workflow.

## 9. Open questions (deferred to per-phase specs)

- **Roundcube webserver:** Apache+mod_php vs nginx+php-fpm inside LXC — picked in Phase 1 spec.
- **mlmmj vs Mailman 3:** Phase 6 picks. mlmmj is far lighter; Mailman 3 has a much richer UI.
- **PGP key escrow:** does the self-service portal allow end users to upload/replace PGP keys, or read-only after import?
- **Secret material in `secubox-users`:** can the mail provisioning hook receive plain passwords (forwarded to Dovecot SHA512-CRYPT), or only hash-on-arrival?
- **HAProxy frontend for SMTP:** terminate TLS at HAProxy and forward to Postfix on plain socket, or pass-through to Postfix with its own cert? Phase 1 decides.

## 10. ANSSI / CSPN posture (CLAUDE.md §🛡️)

- **Privilege separation:** every daemon under its dedicated user (`postfix`, `dovecot`, `rspamd`, `clamav`, `roundcube`, `mlmmj`). LXC adds a second layer.
- **Audit logging:** all admin actions (provision, delete, password reset, sieve edit) appended to `/srv/mail/audit.log` and to `secubox-users` audit stream.
- **Double-buffer config:** `mailctl` writes Postfix/Dovecot/Rspamd config under `/srv/mail/config/shadow/`, validates with `postfix check` / `doveconf -n`, then atomic-swap to `active/`. Rollback keeps R1..R4 snapshots.
- **AppArmor profiles:** one per daemon, shipped by `secubox-mail` debian/, enforced in `postinst`.
- **Secrets:** Dovecot SHA512-CRYPT only; DKIM private keys chmod 600 owned by `_rspamd`; ACME private keys chmod 600 owned by `root`. None ever leave the host.

---

**End of Phase 0 spec.** Next step: brainstorm Phase 1 (LXC consolidation) in its own session.
