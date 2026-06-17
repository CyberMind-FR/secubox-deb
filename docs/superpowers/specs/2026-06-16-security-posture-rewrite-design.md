<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# Spec — secubox-security-posture v2 (honest posture scorecard)

*2026-06-16 · issue #617 · supersedes the broken v1 and folds the sidebar entry of PR #616*

## Problem

The v1 module (~6,100 lines) is broken and largely fake:

- `/overview` raises `NameError` — `self._get_combined_recommendations(...)` is
  called at module scope and the method is defined as dead code after `return`
  (`api/main.py:584`).
- TPN compliance is ~95% stub (proxies CSPN), performance service latencies are
  hardcoded (`waf_latency = 25.0  # simulated`), and 7 of 16 DEFCON indicators
  are hardcoded to perfect ("assume good for now").
- A `zip()/gather()` alignment bug misassigns CSPN results to requirement IDs.
- The UI does not use the shared hybrid-skin tokens the rest of the WebUI uses.

## Principle

**Every indicator carries provenance.** A value is only counted if it was
actually measured. If a source is unreachable or a check is inherently
human-judged, it renders as `UNKNOWN` or `MANUAL` and is *excluded* from the
score denominator — never silently counted as a pass. Each domain reports a
**coverage %** (`known / total`) so the operator sees how much of the score is
real signal.

## Minimal-privilege collection (CSPN attack-surface requirement)

Collectors read from, in order of preference:

1. **Sibling module sockets** `/run/secubox/<mod>.sock` (those modules already
   hold their own privilege grants).
2. **CrowdSec Prometheus** `http://127.0.0.1:6060/metrics` (reachable as `secubox`).
3. **Unprivileged `/proc`, `/sys`, config-file reads.**

No new `sudo` grants are introduced. Anything obtainable only via root that no
sibling exposes is reported `MANUAL`. This keeps the module low-surface and
avoids the "aggregator runs module code as `secubox`" privilege trap
(see project memory: aggregator in-process serving).

## Architecture

```
api/
  __init__.py
  main.py                 # thin FastAPI: lifespan, 60s cache refresh, routes
  posture/
    __init__.py
    model.py              # Status enum; Indicator, DomainScore, Finding, Provenance dataclasses
    scoring.py            # PURE: indicators -> domain scores -> overall -> DEFCON  (TDD)
    sources.py            # socket_get(sock, path), crowdsec_prom(), read_proc(), run() helpers
    collectors.py         # async real probes -> Indicator(value, status, provenance | unknown)
    cspn.py               # CSPN requirement matrix + repaired real checks; manual flagged
    tpn.py                # TPN media overlay — real signals only, rest MANUAL
tests/
  test_scoring.py         # DEFCON thresholds, weighting, unknown exclusion, coverage
  test_cspn_parse.py      # TLS / audit-log / nft parsing on fixture strings
  test_collectors.py      # normalization with faked socket responses
```

### model.py

- `Status(Enum)`: `OK`, `WARN`, `CRIT`, `UNKNOWN`, `MANUAL`.
- `Indicator`: `id, domain, label, value(0..1|None), weight, status, provenance,
  detail, remediation(str|None), link(str|None)`.
- `DomainScore`: `domain, score(0..100|None), coverage(0..1), status, indicators[]`.
- `Finding`: `severity, domain, title, detail, remediation, link`.
- `Provenance`: `source` (e.g. `socket:waf.sock /stats`), `ok: bool`, `note`.

### scoring.py (pure, no I/O — TDD target)

- `domain_score(indicators)`: weighted mean of indicators whose status is one of
  {OK,WARN,CRIT} (i.e. has a numeric `value`); `UNKNOWN/MANUAL` excluded.
  Returns `(score|None, coverage)`. `None` when coverage == 0.
- `overall_score(domain_scores)`: weighted mean over domains that have a score.
  Domain weights: WALL .22, AUTH .18, ROOT .18, MESH .16, MIND .14, BOOT .12.
- `defcon(score)`: 5→1 mapping with name/color/emoji:
  - ≥90 DEFCON 5 (Normal, `--root-main` green)
  - 75–89 DEFCON 4 (Elevated, `--mesh-main` blue)
  - 55–74 DEFCON 3 (Guarded, `--wall-main` amber)
  - 35–54 DEFCON 2 (High, `--boot-light` orange/red)
  - <35 DEFCON 1 (Critical, `--boot-main` red, blink)
- `status_of(value)`: value≥.8 OK, ≥.5 WARN, else CRIT (per-indicator default;
  some indicators override thresholds).

### collectors.py (async, real)

One coroutine per domain returning `list[Indicator]`; every probe wrapped so a
failure yields an `UNKNOWN` indicator with provenance `ok=False`, not an
exception. Signal map (domain → indicator → source):

- **AUTH** auth.sock: `mfa_coverage` (`/status` sessions+totp), `failed_login_rate`
  (`/history`), `oauth_configured` (`/oauth_providers`), `session_hygiene` (`/sessions`).
- **WALL** waf.sock `/stats`, crowdsec.sock `/decisions`+`/bouncers`, prom
  `cs_active_decisions`: `nft_default_drop` (metrics.sock `/firewall_stats`),
  `active_bans`, `waf_rule_coverage`, `bouncer_health`.
- **BOOT** hardening.sock `/benchmark/score`, backup.sock `/history`+`/retention`:
  `hardening_pct`, `backup_freshness`, `backup_success`, `audit_framework`.
- **MIND** network-anomaly.sock `/alerts`, ndpid.sock `/risks`+`/status`,
  dns-guard.sock `/stats`: `anomaly_pressure`, `flow_risk`, `dga_detection`, `dpi_coverage`.
- **ROOT** system.sock `/metrics`+`/services`, `/proc`: `cpu_headroom`,
  `mem_headroom`, `disk_headroom`, `failed_units`, `audit_log_fresh`.
- **MESH** wireguard.sock `/status`, certs.sock `/metrics`, vhost.sock `/status`,
  vortex-dns.sock `/stats`: `wg_peer_health`, `cert_min_days`, `tls13_enforced`,
  `dns_blocklist`, `vhost_ratio`.

### cspn.py

Reuse the v1 requirement matrix (CWE/NIST/ISO mappings) but repair execution:
each requirement holds its own check coroutine; results are gathered into a
`{req_id: result}` dict (no positional `zip`). Real checks kept/repaired: TLS in
HAProxy (CRY-01/02), key-file perms (CRY-04), AppArmor enforce (ACL-02), service
users (ACL-01), nft default-drop (NET-01), listening-port surface (NET-02),
audit-log freshness+format (LOG-01/02). Requirements without an automatable
check are `MANUAL` (documented, not faked).

### tpn.py — media overlay (real only)

- Real: `torrent_p2p_absent` (ndpid `/applications` — BitTorrent/eMule volume),
  `piracy_domains_blocked` (dns-guard `/alerts` + vortex RPZ), `media_tls13`
  (certs `/details` for media vhosts), `streaming_classified` (ndpid streaming apps).
- Manual (badged): HSTS on media vhosts, DRM/content-protection headers, cert
  pinning policy, geo-blocking.

### API (api/main.py)

- `GET /overview` (cached) — overall score, DEFCON, 6 domain scores+coverage,
  TPN summary, top findings.
- `GET /defcon` — gauge payload + per-indicator detail.
- `GET /domains/{domain}` — indicators for one domain.
- `GET /cspn` — full CSPN report. `GET /tpn` — media overlay report.
- `GET /findings` — actionable findings sorted by severity.
- `GET /health`. `POST /refresh` — force recompute.
- Lifespan (not deprecated `on_event`); background task refreshes every 60 s to
  `/var/cache/secubox/security-posture/posture.json` (project double-cache pattern).
- No auth (socket-only, like siblings); mounted at `/api/v1/security-posture`.

### Frontend (www/security-posture/)

`index.html` + `posture.js` + `posture.css`, following the threat-analyst
skeleton: Space Grotesk / JetBrains Mono, `/shared/design-tokens.css` +
`/shared/sidebar.css`; `sidebar.js` injects the dark hybrid-skin + global bars.
Layout:

1. **DEFCON gauge hero** — SVG arc, overall score, level name, coverage note.
2. **6 domain cards** — color-coded per module (`--<domain>-main`), score ring,
   coverage %, top 1–2 findings, deep-link to the owning module page.
3. **CSPN audit table** — collapsible: req id, title, status badge, detail.
4. **TPN media panel** — real signals + `MANUAL` badges.
5. **Findings list** — severity, text, copyable remediation command, module link.

Honest `UNKNOWN`/`MANUAL` badges everywhere; live refresh against `/overview`.

## Packaging

- `debian/rules`: install `api/posture/` submodule + www + `menu.d/` (self-contained
  sidebar entry, folding PR #616). Tests not shipped.
- `menu.d/security-posture.json`: category `wall`, icon 🎚️, path `/security-posture/`.
- `debian/changelog`: `1.0.1-1` → **`2.0.0-1`** (breaking API).

## Testing

- `scoring.py` and parsers built test-first (pure functions, fixture strings).
- Target the CSPN parse logic and the scoring math; collectors tested with faked
  socket JSON via monkeypatched `sources`.

## Out of scope

- New `sudo` grants. DRM/HSTS/geo-block auto-probing (remain MANUAL).
- Changing sibling module APIs.
