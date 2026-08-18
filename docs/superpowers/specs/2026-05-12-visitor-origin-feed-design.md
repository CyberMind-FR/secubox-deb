<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — Health Banner Live Panel

*Issue: [#92](https://github.com/CyberMind-FR/secubox-deb/issues/92)*
*Date: 2026-05-12*
*Author: Gérald Kerma (via Claude, Session 160)*

> **Scope note.** Originally filed as "visitor-origin feed only". User expanded
> the scope mid-brainstorm to also include live-hosts and cert-status sections.
> All three are designed together because they share the banner module, polling
> pattern, design tokens, and CORS/cache plumbing. Splitting them later is
> always possible, but each section is small enough that combining them is
> cheaper than three round-trips of design + PR + review.

---

## 1. Goal

Add a public "live panel" to the SecuBox health banner — the floating widget
injected on every SecuBox vhost — with three independent sections:

1. **VisitorOrigin** — top source ASNs hitting the box (anonymized, last 60 min).
2. **LiveHosts** — top vhosts being served (by request rate, last 60 min).
3. **CertStatus** — Let's Encrypt / ACME state rollup across vhosts.

All three sections are visible to anonymous viewers. Hostnames and cert
metadata are already discoverable via DNS and the TLS handshake; exposing them
in the banner adds no recon surface beyond what is already public. Raw client
IPs are never exposed.

## 2. Non-goals

- Per-vhost rollup of visitor ASNs (single global rollup for v1).
- Historical charts or sparklines (current 60 min snapshot only).
- Country/city geolocation (ASN only).
- Bot/scraper classification or threat scoring.
- IPv6 source coverage for VisitorOrigin (follow-up).
- Admin-gated views (everything in v1 is public; nothing exposes IPs).
- Manual cert renewal trigger UI (CertStatus is read-only).

## 3. User-facing surface

The health banner gains one new panel containing three stacked sections, placed
after the existing SSL/health indicators:

```text
┌─ VisitorOrigin ──────────────────────────────────┐
│ AS13335 Cloudflare         ████████ 142          │
│ AS16276 OVH SAS            ████      78          │
│ AS3320  Deutsche Telekom   ███       54          │
│ AS3215  Orange S.A.        ██        31          │
│ AS5089  Virgin Media       █         12          │
└─ last 60 min · top 5 ────────────────────────────┘

┌─ LiveHosts ──────────────────────────────────────┐
│ secubox.in                 ████████ 412 req      │
│ apt.secubox.in             █████    214 req      │
│ hub.secubox.in             ███      138 req      │
│ auth.secubox.in            ██        67 req      │
│ p2p.secubox.in             █         22 req      │
└─ last 60 min · top 5 ────────────────────────────┘

┌─ CertStatus ─────────────────────────────────────┐
│ ✅ 11 valid    ⚠ 2 expiring <30d    ✗ 0 failed   │
│ next renewal: auth.secubox.in · 14d              │
└──────────────────────────────────────────────────┘
```

Each section is hidden independently when:

- Its data source is unavailable (e.g. `mmdb` missing for VisitorOrigin,
  HAProxy socket missing for LiveHosts, no certs found for CertStatus).
- Its `entries` list is empty after filtering.
- Its fetch fails for any reason.

The whole panel collapses gracefully — a single failing section never breaks
the others.

## 4. Architecture overview

All three sections follow the same shape: a 60 s background asyncio task in
`secubox-metrics` reads raw data, computes a sanitized rollup, persists it to
`/var/cache/secubox/metrics/<section>.json`, and exposes it via a public,
CORS-open, 5-minute-cached endpoint. The banner polls each endpoint on its
own 30 s cycle.

```text
┌──────────────────────────────────────────────────────────────────────┐
│                         secubox-metrics                              │
│                                                                      │
│   VisitorOriginAggregator ──▶ visitor-origin.json ──▶ /visitor-origin│
│   LiveHostsAggregator     ──▶ live-hosts.json     ──▶ /live-hosts    │
│   CertStatusAggregator    ──▶ cert-status.json    ──▶ /cert-status   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
        │                            │                          │
        ▼                            ▼                          ▼
   nft set seen_src           HAProxy stats socket     /etc/letsencrypt/live
   (kernel TTL'd)             show stat -1 6 -1        + cryptography parse

Banner polls each endpoint independently every 30 s.
```

## 5. Components in detail

### 5.1 nftables ruleset (`/etc/nftables.d/secubox-metrics.nft`)

Idempotent include shipped by the `secubox-metrics` package. Lives in its own
table to stay clear of `secubox-firewall`'s ruleset.

```nft
table inet secubox_metrics {
    set seen_src {
        type ipv4_addr
        flags timeout
        timeout 1h
        size 65536
    }

    chain ingress_tap {
        type filter hook prerouting priority -300; policy accept;
        tcp dport { 80, 443 } add @seen_src { ip saddr }
    }
}
```

- Separate table → no entanglement with `secubox-firewall`.
- `priority -300` runs before standard filter; set additions happen even if a
  later rule drops the packet.
- `size 65536` caps memory; on overflow the kernel evicts oldest entries.
- Per-packet cost on Armada 3720/7040: ~hundreds of nanoseconds. Negligible.

### 5.2 Config blocks (`/etc/secubox/secubox.conf`)

The codebase uses a single TOML config file `/etc/secubox/secubox.conf` read by
`secubox_core.config.get_config(section)`. Three new sections are added:

```toml
[visitor_origin]
enabled        = true
window_minutes = 60
min_count      = 5
top_n          = 5
asn_db_path    = "/var/lib/GeoIP/GeoLite2-ASN.mmdb"
nft_table      = "secubox_metrics"
nft_set        = "seen_src"
nft_family     = "inet"

[live_hosts]
enabled         = true
window_minutes  = 60
top_n           = 5
haproxy_socket  = "/run/haproxy/admin.sock"
# Frontends to count; "*" means all that show vhost-style names.
frontend_filter = "*"

[cert_status]
enabled        = true
letsencrypt_live_dir = "/etc/letsencrypt/live"
warn_days      = 30        # "expiring soon" threshold
critical_days  = 7         # surfaced as ⚠ vs ✗ tightening
```

Parsed by `common/secubox_core/config.py` with sensible defaults when blocks
are absent (each section defaults to `enabled=False`).

### 5.3 VisitorOrigin aggregator (`packages/secubox-metrics/api/visitor_origin.py`)

```python
class VisitorOriginAggregator:
    def __init__(self, cfg: VisitorOriginConfig): ...
    async def run_forever(self) -> None: ...
    async def refresh_once(self) -> dict: ...
    def _read_nft_set(self) -> list[IPv4Address]: ...        # subprocess nft -j
    def _lookup_asn(self, ip) -> tuple[int, str] | None: ... # maxminddb
    def _aggregate(self, ips) -> list[dict]: ...             # threshold + sort
    def _persist(self, payload) -> None: ...                 # atomic write
    def current(self) -> dict: ...                           # sync read
```

**Guarantees.** Raw IPs never leave the aggregator's local scope. The threshold
gate (`count >= min_count`) runs *before* cache write, so the on-disk file
cannot contain an ASN attributable to fewer than `min_count` distinct sources.

### 5.4 LiveHosts aggregator (`packages/secubox-metrics/api/live_hosts.py`)

Data source: HAProxy admin socket. The socket exposes per-frontend request
counters (`req_tot`) that are monotonic since HAProxy start, so we sample at
fixed intervals and ring-buffer 1 min deltas over 60 slots.

```python
class LiveHostsAggregator:
    def __init__(self, cfg: LiveHostsConfig):
        self._buckets = collections.deque(maxlen=60)  # 60 × 1 min
        self._prev_totals: dict[str, int] = {}
    async def run_forever(self) -> None: ...
    async def refresh_once(self) -> dict: ...
    def _read_haproxy_stats(self) -> dict[str, int]: ...  # frontend → req_tot
    def _delta_and_buffer(self, totals: dict[str, int]) -> dict[str, int]: ...
    def _aggregate(self) -> list[dict]: ...                # sum buckets, top_n
    def _persist(self, payload) -> None: ...
    def current(self) -> dict: ...
```

**Why HAProxy socket, not log parsing?** The socket is structured CSV that
HAProxy guarantees stable per major version; log parsing has to track format
changes, sampling, rotation, and is heavier on the box. The socket is also
already used by `haproxyctl`.

**Frontend filtering.** Only frontends whose name looks like a hostname (or
matches `frontend_filter` when not `"*"`) are counted. Internal frontends like
`stats-https` are filtered out to avoid noise. Heuristic: contains a `.`,
doesn't start with `_`, isn't in a blocklist.

**Schema.**

```json
{
  "enabled": true,
  "window_minutes": 60,
  "generated_at": "2026-05-12T14:23:00Z",
  "entries": [
    {"host": "secubox.in",     "count": 412},
    {"host": "apt.secubox.in", "count": 214}
  ]
}
```

### 5.5 CertStatus aggregator (`packages/secubox-metrics/api/cert_status.py`)

Reads every `*/cert.pem` under `/etc/letsencrypt/live/`, parses with
`cryptography.x509.load_pem_x509_certificate`, extracts `not_valid_after`.

```python
class CertStatusAggregator:
    def __init__(self, cfg: CertStatusConfig): ...
    async def run_forever(self) -> None: ...
    async def refresh_once(self) -> dict: ...
    def _scan_certs(self) -> list[CertInfo]: ...
    def _classify(self, cert: CertInfo, now: datetime) -> str: ...
        # → "valid" | "expiring_soon" | "expiring_critical" | "expired"
    def _summarize(self, infos) -> dict: ...
    def _persist(self, payload) -> None: ...
    def current(self) -> dict: ...
```

**Schema.**

```json
{
  "enabled": true,
  "generated_at": "2026-05-12T14:23:00Z",
  "summary": {
    "total": 13,
    "valid": 11,
    "expiring_soon": 2,
    "expiring_critical": 0,
    "expired": 0,
    "failed_renewal": 0
  },
  "next_renewal": {"host": "auth.secubox.in", "days": 14},
  "warnings": [
    {"host": "auth.secubox.in", "days": 14, "state": "expiring_soon"}
  ]
}
```

**Failed-renewal detection.** Optional v1 enhancement: tail
`/var/log/letsencrypt/letsencrypt.log` for the last 7 days, count failures by
host. If the log is unreadable, `failed_renewal=0` (degrade gracefully). This
can ship as a follow-up if it complicates v1.

**Permissions.** `cert.pem` is world-readable by default on Debian; the
aggregator runs as `secubox-metrics` and only reads. Private keys are never
touched.

### 5.6 FastAPI endpoints

Three GET endpoints, all unauthenticated, all CORS-open, all `Cache-Control: public, max-age=300`:

```http
GET /api/v1/metrics/visitor-origin
GET /api/v1/metrics/live-hosts
GET /api/v1/metrics/cert-status
```

Each endpoint returns its aggregator's `current()` payload or
`{"enabled": false, ...}` when the aggregator is disabled or has no data.

### 5.7 GeoIP database lifecycle (VisitorOrigin only)

- `apt install geoipupdate python3-maxminddb` (added to `debian/control`
  Depends).
- License key in `/etc/secubox/secrets/maxmind.conf` (mode `0600`, owner
  `secubox`). Operator-supplied; absent ⇒ updater no-op (logged once).
- `secubox-geoipupdate.timer` runs weekly, calling
  `secubox-geoipupdate.service` which exec's `geoipupdate -f /etc/secubox/secrets/maxmind.conf`.
- Aggregator opens the mmdb read-only via `maxminddb.open_database(path, MODE_MMAP)`
  and reopens on mtime change.

### 5.8 Health-banner integration (`packages/secubox-hub/www/shared/health-banner.js`)

Bump `VERSION` to `'1.3.0'`. Add three independent fetch loops mirroring the
existing `HealthCache` pattern. Each section:

- Has its own 30 s timer.
- Has its own cache + last-error tracker.
- Renders only when `enabled === true` and `entries.length > 0`
  (or, for cert-status, `summary.total > 0`).
- A section's failure never affects the others.

```js
const VISITOR_ORIGIN_API = window.SECUBOX_VISITOR_ORIGIN_API
    || '/api/v1/metrics/visitor-origin';
const LIVE_HOSTS_API     = window.SECUBOX_LIVE_HOSTS_API
    || '/api/v1/metrics/live-hosts';
const CERT_STATUS_API    = window.SECUBOX_CERT_STATUS_API
    || '/api/v1/metrics/cert-status';

const LIVE_REFRESH_INTERVAL = 30000; // 30s, shared across the three
```

Section rendering uses the existing design tokens (`design-tokens.css`)
— no new colours, no new fonts. Bars use the `--gold-hermetic` accent for
VisitorOrigin, `--cyber-cyan` for LiveHosts, `--matrix-green`/`--cinnabar`
for CertStatus pass/fail icons.

## 6. Failure modes (catalogue)

| Trigger                                  | Affected      | Effect                                       | UI                       |
|------------------------------------------|---------------|----------------------------------------------|--------------------------|
| `mmdb` missing                           | VisitorOrigin | `enabled=false`                              | Section hidden           |
| `mmdb` lookup raises                     | VisitorOrigin | IP skipped, others continue                  | Logged                   |
| `nft` set missing                        | VisitorOrigin | `enabled=false`, logged once                 | Section hidden           |
| `nft -j` returns malformed JSON          | VisitorOrigin | Refresh skipped, prior payload kept          | Logged warning           |
| All ASNs below `min_count`               | VisitorOrigin | `entries=[]`                                 | Section hidden           |
| HAProxy socket missing/unreadable        | LiveHosts     | `enabled=false`, logged once                 | Section hidden           |
| HAProxy `show stat` parse fail           | LiveHosts     | Refresh skipped, prior payload kept          | Logged warning           |
| All frontends below 1 req in 60 min      | LiveHosts     | `entries=[]`                                 | Section hidden           |
| `/etc/letsencrypt/live` missing or empty | CertStatus    | `enabled=false`                              | Section hidden           |
| Cert parse error on one host             | CertStatus    | That host skipped, others continue           | Logged                   |
| Endpoint 5xx                             | Any           | Banner caches prior payload 5 min then hides | Section hidden           |
| Aggregator task dies                     | Any           | Watchdog logs, asyncio restart               | Stale data until restart |

## 7. Testing strategy

### 7.1 Unit tests

`packages/secubox-metrics/tests/test_visitor_origin.py`

- `_aggregate`: synthetic IPs → expected counts.
- `_aggregate`: threshold edge — `min_count` kept, `min_count - 1` dropped.
- `_aggregate`: top-N sort, ASN-numeric tiebreak.
- `_lookup_asn`: private addresses → `None`; mmdb mock for known IPs.
- `refresh_once`: missing mmdb / empty set / subprocess raise.
- `_persist`: atomic write, `0644`, parent dir created.

`packages/secubox-metrics/tests/test_live_hosts.py`

- Ring-buffer accumulates 60 buckets, oldest evicted.
- Delta computation handles HAProxy restart (counter reset) without negatives.
- Frontend filter excludes internal names.
- Top-N + tiebreak.
- Missing socket / malformed CSV → `enabled=false` or prior payload.

`packages/secubox-metrics/tests/test_cert_status.py`

- Classifier: `now < not_valid_after - warn_days` → valid.
- Classifier: critical/expired/expiring_soon boundaries.
- Summary counts match fixtures.
- Missing live dir → `enabled=false`.
- Parse failure on one cert doesn't kill the scan.

### 7.2 Integration tests

- VisitorOrigin: populate `inet secubox_metrics seen_src` with `nft add element`
  for known public IPs, run `refresh_once()` against a fixture mmdb, assert
  endpoint schema.
- LiveHosts: spawn a `socat` listener mimicking the HAProxy socket reply,
  drive two refreshes, assert deltas + top-N.
- CertStatus: fixture directory with hand-crafted PEMs (valid / 5d / -1d),
  assert summary + `next_renewal`.

### 7.3 Manual verification

- Curl each endpoint on a live box, observe sane payloads.
- Open a public vhost in a browser, confirm all three sections render with
  current data.
- Stop nft / HAProxy / move the live dir — confirm each section disappears
  independently within 60 s while the others stay up.

## 8. Open questions resolved before code

1. **MaxMind license key**: operator-supplied at install. Postinst creates
   `/etc/secubox/secrets/` with right perms and adds a `README.md` note
   pointing at the free GeoLite2 signup. Feature ships disabled if absent —
   no install breakage.
2. **nftables conflict with `secubox-firewall`**: avoided by living in a
   separate table `inet secubox_metrics`, separate chain, priority `-300`.
3. **HAProxy socket reachability from `secubox-metrics`**: the `secubox`
   system user (already used by the service) is added to the `haproxy` group in
   postinst, matching the socket's group ownership (mode `0660`). No new
   sudoers exceptions.

## 9. Acceptance criteria

- [ ] `apt install secubox-metrics` configures the nft table, deploys the
  timer, joins the haproxy group, and starts the service without manual
  steps.
- [ ] All three endpoints (`/visitor-origin`, `/live-hosts`, `/cert-status`)
  respond 200 with documented schemas, in both enabled and disabled states.
- [ ] No raw IP appears in any cache file, the systemd journal, or any HTTP
  response.
- [ ] An ASN with fewer than `min_count` distinct sources is absent from all
  observable surfaces.
- [ ] Each banner section appears within 90 s of first applicable data and
  disappears within 60 s of its data source being removed.
- [ ] Unit test suite passes at ≥ 80 % coverage for the three aggregator
  modules.
- [ ] Integration tests pass against fixtures (mmdb, mock HAProxy socket,
  fixture cert dir).
- [ ] No regression on the existing `/api/v1/metrics/health/summary` payload
  or the banner's SSL section.

## 10. Out of scope (candidate follow-ups)

- IPv6 source coverage in VisitorOrigin (`type ipv6_addr` set + mmdb v6).
- Per-vhost rollup of visitor ASNs (admin-only).
- 24 h trend sparklines for any section.
- Operator-configurable port list for the ingress_tap chain.
- ASN reputation hint (flag known scraper ASNs).
- Manual cert renewal trigger UI.
- CertStatus failed-renewal log scanner (if it complicates v1).
