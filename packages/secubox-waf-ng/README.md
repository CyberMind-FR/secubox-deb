<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🛡️ secubox-waf-ng — Go WAF engine (`sbxwaf`)

> **WIP / not yet cut over.** This package ships the new host-native Go WAF
> engine that replaces the Python `mitmproxy` inspection layer. The binary and
> package are built and parity-tested; production cutover is **gated** — follow
> [`docs/CUTOVER.md`](docs/CUTOVER.md). See issue #744.

**Category:** Security

## What it is

`sbxwaf` is a single host-native Go binary that reverse-proxies the HAProxy
`mitmproxy_inspector` backend to the internal vhosts while inspecting, blocking,
and banning — a drop-in, perf-first replacement for the `mitmproxy 11` + Python
addons WAF. It shares an extracted core (`internal/forge`, `internal/httpcodec`,
`internal/relay`, `internal/reload`) with the toolbox R3 engine `sbxmitm`.

## Features

- **Vhost routing** — `haproxy-routes.json`, hot-reloaded (mtime); unmapped host → 421
- **Regex WAF engine** — `waf-rules.json` (SQLi/XSS/LFI/RCE/CVE…), case-insensitive, hot-reload
- **PHP2Shell (`php2shell`, rules 1.7.0)** — multipart bodies sent to a PHP vhost are captured as a stream and checked by structural signatures (`php2shell-001` to `-008`), `detect` mode only: logged, never blocked or banned. A vhost is PHP when its service is listed in `php_services` (`vhost_profiles.json`: nextcloud, roundcube) **or** its normalised host matches a `php_hotes` pattern (shipped: `^(nc|nextcloud|cloud)\.`, `^(webmail|roundcube)\.`; an invalid pattern is rejected alone). Every client is analysed, LAN and 127.0.0.1 included (logged as `local`, never sent to actord). The body is read the way PHP 8.2 reads it: `main/rfc1867.c` transcribed (not `mime/multipart`), sticky `skip_upload` included, and checked against a C oracle built from `rfc1867.c` (reviewer probes, 300 000 random bodies and differential fuzzing, no divergence). Assumed PHP settings: defaults (`max_file_uploads=20`, `file_uploads=On`, `upload_max_filesize` ≥ 1 MiB, no mbstring encoding translation). The capture window is **min(`--max-body-inspect`, 1 MiB)**, whatever the text-inspection cap; up to 16 concurrent multipart captures plus 8 urlencoded ones, so at worst 24 MiB. Log statuses: `multipart-tronque`, `multipart-malforme`, `multipart-limite`, `capture-concurrence` (#3273: full semaphore, 16 multipart or 8 urlencoded captures, signal `genre` 1 or 2; written after the response, at most one line per second per `genre`, the next one carrying `supprimees`, the number of lines dropped meanwhile) (severity `audit` = 10, counted as *states*, not threats, by the panel); every multipart line carries `ja4` and `tool`. `vhost_profiles.json` is read at start only: after editing `php_services` or `php_hotes`, restart `secubox-waf-ng` and check the line `sbxwaf: vhosts PHP armés : N explicites, M motifs`. **Rollback**: set `"enabled": false` on the `php2shell` category of `/etc/secubox/waf/waf-rules.json` (hot reload): no category with a structural signature means no capture at all, and a body kind (XML prologue, start of a WebDAV `PUT`, urlencoded) is captured only while an enabled category reads it. `waf-rules-sync` keeps an operator's `"enabled": false` across upgrades (audited when the shipped copy enables the category); a `true` follows the shipped copy, so a package can still disable a category, and `waf-profils-fusion` never re-adds a `php_services`/`php_hotes` entry the operator removed. Or install the previous package.
- **Equivalent PHP signatures (`roundcube`, `nextcloud`, `php_requete`, rules 1.7.0, #3273)** — three more categories, `"mode": "detect"` and `"enabled": true`, inserted before `php2shell` (which stays last). Same guarantee as PHP2Shell: logged with the real severity of the signature, never blocked, banned or escalated, and the relayed request is untouched. Each signature carries `cve`, `confidence`, `desc` and `source`; thresholds without a primary source carry `"seuil": "provisoire, non sourcé (2026-10-29)"` (`php2shell-002`, `-003`, `-006`, `-007`).
  - `roundcube` (`"services": ["roundcube"]`): `rc-001` `_from` outside the characters the fix accepts (CVE-2025-49113, CVE-2026-114724; critical); `rc-002` session-serialisation markers in a multipart `filename` (high); `rc-003` CR/LF/NUL in IMAP parameters (`_uid`, `_flag`, `_q`, `_filter`, …) or an invalid `_flag` (high); `rc-004` CR/LF/NUL in mail header fields on send (medium; `_to`, `_cc`, `_bcc`, `_message` are deliberately not read); `rc-005` markasjunk `POST` with `_uid` in the query string (low); `rc-006` non-raster image (SVG, EPS, PS, PDF, MVG magic bytes) uploaded as a contact photo or settings image (high).
  - `nextcloud` (`"services": ["nextcloud"]`): `nc-001` anonymous `POST` on a federated-share path while federation is unused (medium); `nc-002` more than 5 such calls per 1 200 s and per IP (high); `nc-003` `PROPPATCH` on `calendar-proxy-read|write` (medium); `nc-004` same, with a Basic user different from the `<uid>` of the path (high); `nc-005` WebDAV `PUT` of a raster name whose first 64 bytes are a non-raster format (medium).
  - `php_requete` (every PHP vhost, no service): `php-001` more than 1 020 parts, `php-002` `DOCTYPE`/`ENTITY` in an XML prologue, `php-003` cookie name that PHP normalises into `__Host-`/`__Secure-`, `php-004` and `php-005` multipart boundary above 70 / 5 120 characters (the status becomes `malforme` above 70 while the PHP counters are kept), `php-006` `PHP_SESSION_UPLOAD_PROGRESS` present, `php-007` PHP-CGI `-d` option probe. `php2shell-005` to `-008` complete PHP2Shell: body without usable length, parts with 9 headers or more, 21 empty file fields or more, more than 1 000 urlencoded variables.
  - Services: a signature with `services` only fires on vhosts of that service; a host recognised only by a `php_hotes` pattern (service empty) gets every family. `federation_vhosts` (in `vhost_profiles.json`, shipped empty, read at start only) lists the Nextcloud hosts whose operator uses federation: absent, every anonymous federated share is a medium signal.
  - What is read per check: the query string and the capture window (`min(--max-body-inspect, 1 MiB)`) already captured by #3257, for each retained name its first and last occurrence plus at most one suspicious middle one (CR, LF, NUL or an invalid IMAP flag character), so a `_uid[]` array cannot hide a CRLF between two clean values, 64 bytes of magic number per file, the XML prologue (4 096 bytes) and the start of a WebDAV `PUT` (64 bytes) captured without a token, the `Cookie` lines, and headers only for the rest. Never a body, file name or parameter value in the log. Tool labels (`behavior_traits` `outil:<label>`, and the `tool` field when empty) aggravate a line but never raise its severity.
  - Rollback: `"enabled": false` per category in `/etc/secubox/waf/waf-rules.json` (hot reload); with no active structural category nothing is captured. `waf-rules-sync` keeps that `false` across upgrades. The panel (`/php/signaux`, cached, flagged `perime` after 10 minutes) shows counts per family, rule, vhost and public address.
  - Known limits: IPv6 addresses are not grouped by /64 for the `nc-002` counter (4 096 IPs at most, so a /64 can fill it); Nextcloud chunking v1 (`/remote.php/dav/uploads/…` v1 layout) is not covered; `nc-004` is a false positive when a client logs in with its e-mail address (identifier different from the `<uid>`), accepted in `detect` and to be measured; `/php/signaux` reads only the current threat log and its `.1` rotation, not older `.N.gz` files. Roundcube `1.6.5+dfsg-1+deb12u12` stays vulnerable to 113386, 114720, 114724, 114725 and 114727: these signatures spot attacks, they do not fix them.
- **Graduated ban** — sliding window (300 s / threshold 3) → WARNING then BAN, append-only threat log
- **sbx-actord load (#3320, 1.33.0)** — in-memory actor graph pruned at the event retention; consolidation incremental through the index every 10 min; proposals recomputed every 90 s (file rewritten only when changed, at least every 5 min for sbxwaf freshness), measures kept at 30 s (event cache 25 s); `--workers` defaults to 1; a rejected batch is replayed event by event; ingestion and evidence ledger written in batches (≤ 256 events / 200 ms per transaction); prune in batches of 5 000 keys; bbolt `NoFreelistSync` + map freelist; unit: `--workers 1`, `GOMEMLIMIT=180MiB GOGC=50`, `MemoryHigh=200M` under `MemoryMax=256M`. The evidence ledger still has no retention (it is a proof): follow-up.
- **Native nftables bans** — `inet secubox` sets `waf_ban`/`waf_ban6` (4 h), decisions emitted to `sbx-actord` (campaigns, decoys); external blocking bridge removed (#1218)
- **RGPD cookie-audit** — per `Set-Cookie` JSONL, values SHA-256-hashed (raw value never stored)
- **Media-cache** — 16 MB/obj, 2 GB total, per-vhost keyed, `Flusher` passthrough for progressive media
- **Themed error pages** — 502/503/504 (Host HTML-escaped — no reflected XSS)
- **Hardened** — dedicated `secubox-waf` user, `NoNewPrivileges`, `ProtectSystem=strict`, seccomp, AppArmor enforce, `RuntimeDirectoryPreserve=yes`

## Architecture

```
Internet ──TLS1.3──▶ HAProxy :443 ──▶ backend mitmproxy_inspector
                                         │  (cutover: server → host sbxwaf)
                                         ▼
                       sbxwaf workers (secubox-waf-ng-worker@1..2, 127.0.0.1:808x)
                       ├─ routes → rules → ban (nft) → sbx-actord
                       ├─ cookie-audit · media-cache · error pages
                       ▼
                       backends 10.100.0.0/24
```

## Installation

```bash
sudo apt install secubox-waf-ng
# provision the WAF CA at /etc/secubox/waf/ca/ and the rules at
# /etc/secubox/waf/waf-rules.json (COMPLETE corpus — must contain log4shell),
# then: systemctl enable --now secubox-waf-ng-worker@1 secubox-waf-ng-worker@2
```

## Configuration

- `/etc/secubox/waf/haproxy-routes.json` — vhost → backend map (hot-reload)
- `/etc/secubox/waf/waf-rules.json` — WAF regex rules (hot-reload)
- `/etc/secubox/waf/vhost_profiles.json` — per-vhost adaptive rules (#1080, read at start only):
  `services.<name>.legit_paths`, optional `services.<name>.suppress_categories` (applied to that
  service's legit paths only, #3193 — e.g. `livekit`: `credential_harvest` on `/rtc/v1`), `vhosts`
  (host → service), global `suppress_categories`, `anti_robots`. Conffile edited at runtime: on
  upgrade `waf-profils-fusion` adds the shipped services/vhosts that are missing
  (reference copy `/usr/share/secubox/waf/vhost_profiles.json`), never an operator value.
- `/etc/secubox/waf/ca/` — forge CA (cert + key)
- Logs: `/var/log/secubox/waf/waf-threats.log`, `/var/log/secubox/cookie-audit/server.jsonl`
- Cache: `/var/cache/secubox/waf/media`

## Migration / cutover

Shadow → parity → **go/no-go gate** (bench `>5×` req/s·core, `p99 < ⅓`, `RSS < ¼`;
`TestWAFParity` 0-fail) → HAProxy `server` re-point → rollback = re-point back.
Pre-cutover **BLOCKING gates** (see `docs/CUTOVER.md`): complete rules WITH
log4shell, `\u0000→\x00` null-byte fix, goform false-positive fix,
`--max-body-inspect` sized for upload routes.

## Known limitations (documented gaps)

- Body inspection is prefix-bounded (`--max-body-inspect`, default 1 MiB) vs Python full-body scan — truncation is audit-logged; raise the cap or route large-upload vhosts around the WAF.
- 5 null-byte CVE patterns need `\u0000→\x00` in the rules file to compile under RE2.
- **WebUI not yet wired:** `sbxwaf` writes the threat log but not the aggregate `waf-stats.json` the WAF dashboard reads — the `/api/v1/waf` metrics feed needs porting before cutover (issue #747).

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
