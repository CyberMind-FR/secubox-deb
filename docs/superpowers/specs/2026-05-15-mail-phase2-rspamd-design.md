<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Mail Phase 2 — Rspamd migration

**Date:** 2026-05-15
**Status:** Approved (this brainstorm complete, awaiting written-spec user review)
**Spec depends on:** Phase 0 rev. 2 `docs/superpowers/specs/2026-05-15-mail-stack-architecture-design.md`
**Phase 1 outcome:** 12/12 acceptance gates green (PR #141, 2026-05-15). Mail LXC running with Postfix + Dovecot + Apache+Roundcube + OpenDKIM (no DKIM keys) + SpamAssassin (installed but inactive).

---

## 1. Goal

Replace SpamAssassin + OpenDKIM with a single Rspamd daemon inside the mail LXC. Rspamd handles greylisting, spam scoring, DKIM signing + verify, SPF, DMARC, ARC, and outbound ratelimit. Single-domain DKIM (`secubox.in`); Phase 3 widens to per-domain. Web UI behind admin JWT, read-only by default. Old `/spam/*`, `/grey/*`, `/dkim/*` HTTP endpoints become deprecation shims that return the Rspamd-equivalent data with `X-Deprecated-Endpoint: rspamd` header until v3.0.

## 2. Non-goals

- ClamAV / antivirus — split into a follow-up Phase 2.5 with its own spec.
- Per-domain DKIM keys (Phase 3).
- Bayes corpus seeding from external sources (start empty, learn via Roundcube plugins in Phase 5).
- ActiveSync, ARC chain debugging UI, header anonymization, mlmmj — all out of scope.

## 3. Locked decisions

| # | Decision | Source |
|---|---|---|
| D1 | Rspamd is the only spam/DKIM daemon. SA + OpenDKIM are removed at end of phase. | Phase 0 §3 I3, this brainstorm |
| D2 | ClamAV deferred to Phase 2.5 | This brainstorm |
| D3 | DKIM scope = `secubox.in` only, selector `default` | This brainstorm |
| D4 | Rspamd web UI behind admin JWT (host nginx → mitmproxy → LXC `:11334`); Rspamd `enable_password` (in `/etc/secubox/secrets/`) gates write actions | This brainstorm |
| D5 | Bayes corpus starts empty; Phase 5 wires Roundcube "Mark as spam" plugins | Implicit (Phase 5 deliverable) |
| D6 | ARC signing enabled by default; helps forwarded mail authenticate | Best practice |
| D7 | Outbound rate limit default = 200 messages/hour/user (configurable in `mail.toml`) | Best practice |
| D8 | Legacy `/spam/*` `/grey/*` `/dkim/*` endpoints kept as deprecation shims until v3.0 | Backward-compat hygiene |
| D9 | Removal order: install + verify Rspamd FIRST, only then purge SA/OpenDKIM | Risk reduction |

## 4. Architecture

### 4.1 Daemon set inside the `mail` LXC (end-of-phase)

| Daemon | Port | Owner | Comes from |
|---|---|---|---|
| Postfix | 25, 465, 587 | `postfix` | already running, milter wiring added |
| Dovecot | 143, 993, 4190 | `dovecot` | already running, unchanged |
| Apache + mod_php + Roundcube | 80 | `www-data` | already running, unchanged |
| **Rspamd worker-proxy** | `127.0.0.1:11332` | `_rspamd` | NEW — Postfix milter target |
| **Rspamd worker-normal** | `127.0.0.1:11333` | `_rspamd` | NEW — internal scan worker |
| **Rspamd controller** | `0.0.0.0:11334` | `_rspamd` | NEW — HTTP UI + API |
| OpenDKIM | — | (gone) | apt purge |
| SpamAssassin | — | (gone) | apt purge |

### 4.2 Postfix integration

`mailctl rspamd install` patches `/data/volumes/mail/config/main.cf` to add:

```
smtpd_milters         = inet:127.0.0.1:11332
non_smtpd_milters     = inet:127.0.0.1:11332
milter_default_action = accept
milter_protocol       = 6
milter_mail_macros    = i {auth_authen} {auth_type} {client_addr} {client_name} {mail_addr} {mail_host} {mail_mailer}
```

`milter_default_action = accept` means a Rspamd outage downgrades to "accept and deliver" rather than blocking mail flow. Phase 2.5 / Phase 8 can tighten this once observability is in place.

### 4.3 Persistent data layout

```
/data/volumes/mail/
  rspamd/
    dkim/
      secubox.in/
        default.key           # 2048-bit RSA private, 0600, _rspamd:_rspamd
        default.txt           # DNS TXT record content (Phase 3 publishes via secubox-dns)
        default.pub           # public component (informational)
    bayes/                    # bind-mounted → /var/lib/rspamd/bayes
    history/                  # bind-mounted → /var/lib/rspamd/history
    settings/                 # bind-mounted → /var/lib/rspamd/settings (per-user score overrides)
```

The bind-mount approach means `lxc-destroy mail; mailctl install` keeps the Bayes corpus + per-user settings intact.

### 4.4 Rspamd config (rendered by `mailctl rspamd install`)

| File | Purpose |
|---|---|
| `/etc/rspamd/local.d/options.inc` | `local_addrs = "127.0.0.0/8, 10.100.0.0/16";` (so internal traffic skips greylist) |
| `/etc/rspamd/local.d/worker-proxy.inc` | milter mode, bind `127.0.0.1:11332`, backend `127.0.0.1:11333` |
| `/etc/rspamd/local.d/worker-normal.inc` | bind `127.0.0.1:11333` |
| `/etc/rspamd/local.d/worker-controller.inc` | bind `*:11334`; `password` + `enable_password` from `/etc/secubox/secrets/rspamd-controller.pw` (bind-mounted into LXC) |
| `/etc/rspamd/local.d/dkim_signing.conf` | `selector = "default"; path = "/etc/rspamd-keys/$domain/$selector.key"; try_fallback = true;` (`/etc/rspamd-keys/` is bind-mounted from `/data/volumes/mail/rspamd/dkim/`) |
| `/etc/rspamd/local.d/arc.conf` | `sign_authenticated = true; sign_local = true;` |
| `/etc/rspamd/local.d/dmarc.conf` | `actions { quarantine = "add_header"; reject = "reject"; }; reporting { enabled = true; report_local_controller = true; }` |
| `/etc/rspamd/local.d/greylist.conf` | `expire = 1d; whitelisted_emails = false; greylist_min_score = 4;` |
| `/etc/rspamd/local.d/ratelimit.conf` | `rates { user_outbound = "200 / 1h"; }; whitelisted_rcpts = "postmaster"; ` |
| `/etc/rspamd/local.d/classifier-bayes.conf` | `cache { backend = "redis"; }; servers = "127.0.0.1:6379";` — actually deferred; Phase 2 uses default sqlite backend at `/var/lib/rspamd/bayes` |

Secrets handling: `/etc/secubox/secrets/rspamd-controller.pw` is a 32-byte random string generated at install time on the host. It's bind-mounted into the LXC as `/etc/rspamd/local.d/secrets.inc`. Both reads + writes (e.g. learn-spam) require this password. The host-side FastAPI uses the secret transparently when calling the Rspamd controller; admins logging into the web UI use it directly.

### 4.5 Host edge

| Item | Change |
|---|---|
| `common/nginx/modules.d/mail.conf` | Add `server { server_name rspamd.gk2.secubox.in; location / { proxy_pass http://10.100.0.10:11334/; } }` |
| HAProxy | No change — `*.gk2.secubox.in` already routes through `mitmproxy_inspector` |
| mitmproxy route map | Add `rspamd.gk2.secubox.in: ["10.100.0.10", 11334]` at deploy time (same pattern as Phase 1 webmail) |
| `sync-mitmproxy-routes.sh` on board | Already patched in Phase 1 to remove `10.100.0.10` from DEAD list |

### 4.6 API surface

#### New endpoints (`packages/secubox-mail/api/main.py`)

```
GET    /api/v1/mail/rspamd/status        → {enabled, version, dkim_domains, greylist, ratelimit, bayes_learned}
GET    /api/v1/mail/rspamd/history       → recent scans (last 1000 messages, scored)
GET    /api/v1/mail/rspamd/scores        → score histogram + top-rule contributions
POST   /api/v1/mail/rspamd/learn-spam    → body = {message_id} | {raw_eml}; calls rspamc learn_spam
POST   /api/v1/mail/rspamd/learn-ham     → mirror
GET    /api/v1/mail/rspamd/whitelist     → list whitelist entries
POST   /api/v1/mail/rspamd/whitelist     → body = {address, type=from|rcpt|ip}
DELETE /api/v1/mail/rspamd/whitelist/{id}
GET    /api/v1/mail/rspamd/dkim/{domain} → {selector, dns_txt, key_path, last_rotated}
POST   /api/v1/mail/rspamd/dkim/{domain}/keygen → generate key + emit DNS record
POST   /api/v1/mail/rspamd/reload        → graceful reload
```

#### Compat shims (kept until v3.0)

| Legacy path | Returns | Header |
|---|---|---|
| `GET /dkim/status` | `{enabled, domain, selector, dns_record_present}` from Rspamd | `X-Deprecated-Endpoint: rspamd` |
| `POST /dkim/setup` | Calls `/rspamd/dkim/secubox.in/keygen` | same |
| `POST /dkim/keygen` | Same | same |
| `POST /dkim/sync` | No-op (Rspamd reads from bind-mount); returns 200 with deprecation header | same |
| `GET /dkim/record` | Returns content of `/data/volumes/mail/rspamd/dkim/secubox.in/default.txt` | same |
| `GET /spam/{status,...}` | `{installed: true, configured: true, enabled: <rspamd-enabled>}` derived from Rspamd status | same |
| `POST /spam/{setup,enable,disable,update}` | 200 + deprecation header; enable/disable toggle the multimap `spam.map` | same |
| `GET /grey/{status,...}` | Maps to Rspamd greylist module status | same |
| `POST /grey/{setup,enable,disable}` | Toggles `greylist.conf.disabled` | same |

`mailctl spam {setup,enable,…}`, `mailctl grey …`, `mailctl dkim …` similarly become thin wrappers around the new `mailctl rspamd …` subcommands.

### 4.7 mailctl additions

```bash
mailctl rspamd install                    # install + render config + start
mailctl rspamd start | stop | restart | reload
mailctl rspamd status                     # JSON: see /rspamd/status
mailctl rspamd dkim-keygen <domain> [selector=default]
mailctl rspamd dns-records <domain>       # echo DNS TXT records to publish (used by secubox-dns)
mailctl rspamd learn-spam <maildir-or-message>
mailctl rspamd learn-ham <maildir-or-message>
mailctl rspamd whitelist add|del|list
```

The actual `rspamadm` / `rspamc` commands run via `lxc_attach mail -- rspamc ...`.

## 5. Removal ordering

Per locked decision **D9**:

1. **Add Rspamd** (install in LXC, render config, start), without touching Postfix yet.
2. **Sanity smoke**: Rspamd controller responds on `:11334`; rspamc → "milter test" passes.
3. **Wire Postfix milter**: `smtpd_milters = inet:127.0.0.1:11332`, reload Postfix.
4. **Full Phase 2 smoke** (gates 1–11). Must be green.
5. **Decommission OpenDKIM**: `systemctl disable --now opendkim`, remove `Milter` directive from `/etc/postfix/main.cf` if present, `apt purge opendkim opendkim-tools`.
6. **Decommission SpamAssassin**: `systemctl disable --now spamassassin spamd 2>/dev/null || true`, `apt purge spamassassin spamc spamd`.
7. **Re-run Phase 1 + Phase 2 smokes** to confirm no regression.

## 6. Phase 2 acceptance smoke (`tests/scripts/test-mail-phase2-acceptance.sh`)

| # | Gate | How |
|---|---|---|
| 1 | Source-side parse clean | `bash -n` on `mailctl`, `lib/mail/rspamd.sh`, `mail-migrate-to-single-lxc.sh` |
| 2 | Pytest: new `/rspamd/*` endpoints + legacy compat shims respond non-5xx | TestClient |
| 3 | bats: `dpkg-deb -c <built deb>` ships `lib/mail/rspamd.sh` | bats path-coverage test |
| 4 | Rspamd worker-proxy listening on 11332, controller on 11334 | `lxc-attach -- ss -tlnp` |
| 5 | Postfix `smtpd_milters` points at `inet:127.0.0.1:11332` | grep main.cf |
| 6 | DKIM keygen produces `/data/volumes/mail/rspamd/dkim/secubox.in/default.key` (0600) + `default.txt` | stat + content check |
| 7 | Outbound mail carries `DKIM-Signature: ... d=secubox.in s=default` | submit via `swaks`, fetch via curl IMAPS, grep header |
| 8 | SPF hard-fail rejected | submit forged sender, expect `550 5.7.1` |
| 9 | DMARC quarantine action visible in history | submit DMARC-failing mail; `rspamc history` shows it |
| 10 | Greylist defers first attempt; retry succeeds | submit from never-before-seen IP, expect `451`, retry within window, expect `2.0.0` |
| 11 | Rspamd web UI at `https://rspamd.gk2.secubox.in/` responds 200 with admin JWT | curl with JWT |
| 12 | OpenDKIM + SpamAssassin packages absent | `dpkg -l opendkim spamassassin 2>&1 \| grep -q 'no packages'` |
| 13 | Phase 1 regression: 5 production users still IMAPS-loginable; webmail still WAF-routed | re-run Phase 1 gates 4 + 10 + 11 + 12 |

## 7. Files in this phase

### New

| Path | Responsibility |
|---|---|
| `packages/secubox-mail/lib/mail/rspamd.sh` | `install_rspamd`, `configure_rspamd_dkim`, `configure_rspamd_milter`, `configure_rspamd_controller`, `rspamd_keygen <domain> [selector]` |
| `packages/secubox-mail/templates/rspamd/local.d/*.conf` | All Rspamd config snippets (one file per module) |
| `packages/secubox-mail/templates/rspamd/secrets.inc.template` | Password template, expanded at install time |
| `packages/secubox-mail/api/routers/rspamd.py` | FastAPI router with new `/rspamd/*` endpoints (extract from main.py to keep main.py tractable) |
| `packages/secubox-mail/api/routers/legacy.py` | Compat shims for `/dkim/*` `/spam/*` `/grey/*` |
| `packages/secubox-mail/api/tests/test_phase2_endpoints.py` | New endpoint presence + shim contract tests |
| `packages/secubox-mail/tests/test_rspamd_lib.bats` | bats tests for `lib/mail/rspamd.sh` |
| `packages/secubox-mail/tests/test_deb_paths.bats` | NEW path-coverage bats: builds the deb, runs `dpkg-deb -c`, asserts every `lib/mail/*.sh` ships |
| `tests/scripts/test-mail-phase2-acceptance.sh` | 13-gate end-to-end smoke |
| `docs/superpowers/runs/2026-05-15-mail-phase2-rollback.md` | Rollback recipe (downgrade to 2.2.x, restore SA+OpenDKIM if needed) |

### Modified

| Path | Change |
|---|---|
| `packages/secubox-mail/sbin/mailctl` | Add `cmd_rspamd` subcommand dispatch; legacy `cmd_dkim`/`cmd_spam`/`cmd_grey` become Rspamd wrappers |
| `packages/secubox-mail/api/main.py` | Mount `rspamd` + `legacy` routers; remove inline `/dkim/*` `/spam/*` `/grey/*` handlers |
| `packages/secubox-mail/lib/mail/install.sh` | Drop SA/OpenDKIM from `install_mail_packages`; add `systemctl enable postfix` (Phase 1 follow-up); install `rspamd` package |
| `packages/secubox-mail/config/mail.toml` | Add `[mail.rspamd]` section (greylist, ratelimit_outbound, bayes_autolearn defaults) |
| `packages/secubox-mail/debian/control` | Version 2.3.0; `Depends: ... rspamd` |
| `packages/secubox-mail/debian/changelog` | New 2.3.0 entry |
| `packages/secubox-mail/debian/postinst` | If upgrade from `<< 2.3`: bind-mount setup + Rspamd install runs once |

## 8. Phase 2 follow-ups carried over from Phase 1 deploy

| Item | Where addressed |
|---|---|
| Sentinel env-var guard in shims | `mailctl rspamd` doesn't shim anything that re-enters itself; the existing `mailserverctl`/`roundcubectl` shims keep their Phase 1 implementation. No new guard needed in Phase 2. |
| `dpkg-deb -c` path-coverage bats test | `packages/secubox-mail/tests/test_deb_paths.bats` (new file above) |
| `systemctl enable postfix` in install_mail_packages | Added in `install.sh` modification above |
| Document host/LXC mitmproxy route file split in CLAUDE.md | Out of Phase 2 (one-line doc patch — can land separately) |
| `sync-mitmproxy-routes.sh` mail-LXC awareness | Patch the script to keep `10.100.0.10` out of DEAD_CONTAINER_IPS by default, then commit + deploy in Phase 2 |

## 9. Effort + risk

- **Effort:** ~1 week focused work (~15–20 tasks in the plan).
- **Risk:**
  - Rspamd milter integration is well-trodden; the main hazard is the Postfix `smtpd_milters` cutover. Mitigated by D9 ordering + `milter_default_action = accept` (fail-open).
  - DKIM key generation can produce keys that `rspamd-dkim` can't read if file ownership is wrong. Mitigated by explicit `chown _rspamd:_rspamd` in `rspamd_keygen` and a verify step that re-reads the key before claiming success.
  - mitmproxy route map drift (Phase 1 lesson): the script patch + the route entry are now both in Phase 2's deploy steps.
  - SA/OpenDKIM removal could break mail flow if Postfix still references them. Mitigated by removing the `Milter` directive BEFORE `apt purge`.

## 10. Deferred to Phase 2.5+

- ClamAV: separate spec.
- Tighten `milter_default_action` from `accept` to `tempfail`.
- Bayes corpus seeding from public datasets.
- Rspamd Redis backend for shared bayes across (future) multi-instance setups.
- Per-user Rspamd settings via Sieve hooks.

---

**End of Phase 2 spec.** Next: write implementation plan via `writing-plans`, then execute.
