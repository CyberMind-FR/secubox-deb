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
- **PHP2Shell (`php2shell`, rules 1.6.0)** — multipart bodies sent to a PHP vhost are captured as a stream and checked by structural signatures (`php2shell-001` to `-004`), `detect` mode only: logged, never blocked or banned. A vhost is PHP when its service is listed in `php_services` (`vhost_profiles.json`: nextcloud, roundcube) **or** its normalised host matches a `php_hotes` pattern (shipped: `^(nc|nextcloud|cloud)\.`, `^(webmail|roundcube)\.`; an invalid pattern is rejected alone). Every client is analysed, LAN and 127.0.0.1 included (logged as `local`, never sent to actord). The body is read the way PHP 8.2 reads it (`main/rfc1867.c` transcribed, not `mime/multipart`). The capture window is **min(`--max-body-inspect`, 1 MiB)**, whatever the text-inspection cap; up to 16 concurrent captures, so at worst 16 MiB. Log statuses: `multipart-tronque`, `multipart-malforme`, `multipart-limite`, `multipart-concurrence` (severity `audit` = 10, counted as *states*, not threats, by the panel); every multipart line carries `ja4` and `tool`. `vhost_profiles.json` is read at start only: after editing `php_services` or `php_hotes`, restart `secubox-waf-ng` and check the line `sbxwaf: vhosts PHP armés : N explicites, M motifs`. **Rollback**: set `"enabled": false` on the `php2shell` category of `/etc/secubox/waf/waf-rules.json` (hot reload): no category with a structural signature means no capture at all. `waf-rules-sync` keeps that choice across upgrades (audited), and `waf-profils-fusion` never re-adds a `php_services`/`php_hotes` entry the operator removed. Or install the previous package.
- **Graduated ban** — sliding window (300 s / threshold 3) → WARNING then BAN, append-only threat log
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
