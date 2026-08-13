# Design — Cross-plane Presence Guardian (Project B / B1)

- **Issue** : [#820](https://github.com/CyberMind-FR/secubox-deb/issues/820)
- **Date** : 2026-07-05
- **Licence** : LicenseRef-CMSD-1.0
- **Module** : `packages/secubox-nac/` (Client Guardian), stacked on Project A (#817/PR #818)

## 1. Problème

Project A unified the **LAN device** plane into one store. But "who is on my network" spans more planes with no shared view: **WAN** visitors/bots (seen by sbxwaf + crowdsec), **WireGuard** peers + **kbin personas** (the R3 toolbox tunnel — a phone testing the kbin), and **Tor** — each observed by a different subsystem, none correlated, none geo-tagged in one place, and with no threshold alerting or scheduled reporting. The user wants a **gare de triage / presence guardian**: one place that observes every plane, tags origin (geo when possible, provenance otherwise), raises tiered alerts on thresholds, and emits scheduled/triggered reports — with a phone hitting the kbin surfacing as a tracked presence linked to its kbin profile.

## 2. Objectif (B1)

A cross-plane **presence** layer in `secubox-nac`: a `presences` table + per-plane collectors (WAN, LAN, WG, kbin) with geo/provenance enrichment, a tiered alert engine that emails on thresholds (via smtp-relay), scheduled reports (wiring reporter's dormant scheduler + email), and a unified presence view in the Client Guardian webui — including kbin-persona linkage. **Tor is deferred** (no per-visitor data today). The triage/emancipation verbs (VLAN/Tor/mesh) are **Project C**.

## 3. Décisions (brainstorm 2026-07-05)

| Axe | Décision |
|-----|----------|
| Model | NEW `presences` table keyed by `(plane, identity)`; A's `devices` rows LINK to a presence (a LAN/WG device is also a presence). No forcing IPs into the MAC-keyed devices table. |
| Planes B1 | WAN, LAN, WG, kbin. **Tor deferred**. |
| Geo | Existing mmdb infra (`waf/geoip`, metrics `visitor_origin`) → `geo_cc`/`geo_asn`; **provenance tags** when geo unavailable (private/LAN/mesh/tunnel). |
| Alerts | Tiered (`info/notice/warn/critical`), per-plane thresholds; email via **smtp-relay `sendmail`**. |
| Reports | Wire **reporter**'s stub scheduler to actually run (cron→timer) + email delivery of the HTML/PDF. |
| kbin | A phone on the R3 tunnel (mac_hash persona) → a presence + link to its kbin profile report + shown in the Client Guardian webui. |
| Home | `secubox-nac` (extends A); guardian webui gains a cross-plane presence view. |

**Non-objectifs**: Tor per-visitor (new collection) → later phase. VLAN/Tor/mesh emancipation → Project C.

## 4. Architecture

### 4.1 `presences` table (extends A's SQLite `devices.db`)

```
presences(
  id TEXT PRIMARY KEY,            -- "<plane>:<identity>" (e.g. wan:1.2.3.4, wg:<mac_hash>, lan:<mac>, kbin:<mac_hash>)
  plane TEXT,                     -- wan | lan | wg | kbin   (tor later)
  identity TEXT,                  -- ip | mac_hash | mac
  device_mac TEXT,               -- FK-ish link to devices.mac when this presence IS a known device (lan/wg), else NULL
  geo_cc TEXT, geo_asn TEXT, geo_org TEXT,
  provenance TEXT,               -- geo | private | lan | mesh | tunnel | bot | crawler | tor(later)
  client_type TEXT,              -- browser | mobile-app | bot | crawler | peer | persona (from sbxwaf classifyUA / plane)
  first_seen INTEGER, last_seen INTEGER, hits INTEGER DEFAULT 0,
  tier TEXT DEFAULT 'info',      -- current alert tier for this presence
  extra TEXT                     -- json: host/UA/kbin-report-token/etc (bounded)
);
CREATE INDEX idx_pres_plane ON presences(plane);
CREATE INDEX idx_pres_last ON presences(last_seen);
```
Accessed via a `PresenceStore` (mirrors A's `DeviceStore`: WAL, `threading.Lock`, best-value upsert, `list(plane=,tier=,limit=)`). A LAN/WG presence carries `device_mac` linking to A's `devices` row (so the webui can show device details + presence stats together).

### 4.2 Per-plane collectors (all off-loop, fail-safe, double-cached — A's rules)

- **WAN** (`presence/wan.py`): tail sbxwaf `threat-log` JSONL (`/var/log/secubox/waf-threats.log`) for per-request `{client_ip, host, user_agent, category}`, and read sbxwaf `visitstats` snapshot for aggregate client-type; upsert a `wan:<ip>` presence per source IP, `client_type` from the UA classifier, `hits`++. (Bounded tail-read like A/media-catch.)
- **LAN/WG** (`presence/local.py`): mirror A's `devices` (LAN + WG source) into `lan:<mac>` / `wg:<mac_hash>` presences with `device_mac` set — a thin projection so the presence view is unified; no new discovery.
- **kbin** (`presence/kbin.py`): read the toolbox persona identities (`mac_hash` — the R3 tunnel), upsert `kbin:<mac_hash>` presences; when a persona has a kbin report token, store it in `extra` so the webui can deep-link to the kbin profile report.
- Collectors run in the existing nac collector loop (add plane-collector steps) — off-loop via `run_in_executor`, each fail-safe (a missing source contributes nothing).

### 4.3 Geo / provenance (`presence/geo.py`)

Reuse the existing mmdb (`/var/lib/secubox/geoip/GeoLite2-Country.mmdb` + `GeoLite2-ASN.mmdb`) exactly as `waf/api` + `metrics/visitor_origin` do (`geoip2`/`maxminddb`, in-memory cache). For a public WAN IP → `geo_cc`/`geo_asn`/`geo_org`, `provenance="geo"`. For private/LAN/WG/mesh/tunnel identities → skip geo, set `provenance` accordingly (`private`/`lan`/`tunnel`/`mesh`). Bots/crawlers tagged from the UA classifier. Fail-safe: mmdb missing → `provenance` still set, geo empty.

### 4.4 Alert engine (`presence/alerts.py`)

Tiered thresholds evaluated each collector cycle over the presences + counts:
- Tiers: `info` (normal), `notice` (e.g. a new WAN country, a new WG persona), `warn` (e.g. bot surge > N/min, a new-unknown-router presence — reuses A's rogue-AP signal), `critical` (operator-defined, e.g. a burst of new WAN IPs, a flagged ASN).
- Config in `/etc/secubox/presence-alerts.toml` (thresholds per plane/tier). A fired alert → an alert record (SQLite, like A's history) + an **email** via a small `presence/mailer.py` that shells `smtp-relay`'s working path (`/usr/sbin/sendmail -t -oi`) with a rate-limit/dedup (don't spam: coalesce per tier per window). Fail-safe: no mailer → alert still recorded.

### 4.5 Reports (`presence/reports.py`)

Wire the **reporter** module's dormant scheduler: a systemd timer (`secubox-presence-report.timer`) reads `/etc/secubox/reporter-schedule.json` (daily/weekly) and generates a presence report (reuse reporter's HTML/PDF templates fed with the presences/geo/alert data), then **emails** it (same mailer). Also a `POST /presence/report/now` for on-demand. (This finally makes reporter's stub scheduler execute — a documented gap.)

### 4.6 API + WebUI

- API (nac, plain `def`, JWT): `GET /presence` (list, filter by plane/tier), `GET /presence/{id}`, `GET /presence/geo` (aggregate by country/ASN), `GET /presence/alerts`, `POST /presence/report/now`, `POST /presence/sync` (force a collect).
- WebUI: a new **"Présence"** view in Client Guardian — cross-plane table (plane badge, identity, geo flag/ASN or provenance tag, client-type, hits, tier), a geo/ASN aggregate panel, an alerts panel; a LAN/WG/kbin row links to the device (A) and, for kbin, deep-links the kbin report. All fields escaped (attacker-influenceable host/UA/geo).

## 5. Data flow

```
sbxwaf threat-log + visitstats + crowdsec ──▶ wan collector ──┐
A devices (lan/wg source) ────────────────▶ local collector ──┤
toolbox mac_hash personas ────────────────▶ kbin collector  ──┤─▶ PresenceStore (upsert, geo/provenance enrich)
                                                               │        │
                                        alert engine (tiers) ◀─┘        ├─▶ /presence API ─▶ webui Présence view
                                            │                           └─▶ report timer ─▶ HTML/PDF ─▶ email
                                            └─▶ threshold hit ─▶ alert record + email (smtp-relay sendmail, deduped)
```

## 6. Error handling / constraints (inherit A)

- Every handler plain `def`; all collection/geo/subprocess off-loop (A's #808 rule) — critical since nac is aggregator-mounted.
- `PresenceStore` WAL + `threading.Lock`; collector is the writer, handlers read.
- Fail-safe collectors + mailer + geo (a missing source/mmdb/sendmail degrades, never crashes the loop or a handler).
- Email rate-limited/deduped (coalesce per tier per window) — never a mail storm.
- Bounded tail-reads for the WAN log; bounded presence list queries (indexed).
- No PII beyond what the sources already expose (sbxwaf threat-log is IP+UA+host; kbin is mac_hash, not raw identity). Perms: reuse A's `devices.db` file (add the `presences` table there) `0640 secubox:secubox`.
- Lazy-init (A's middleware) covers the new tables/collectors under in-aggregator mount.

## 7. Tests

- `PresenceStore`: schema, best-value upsert, plane/tier filters, device_mac link.
- WAN collector: threat-log fixture → `wan:<ip>` presences with client_type; bounded tail; fail-safe on missing log.
- local/kbin collectors: A devices → lan/wg presences with device_mac; personas → kbin presences with report token.
- geo: public IP → cc/asn/provenance=geo; private/tunnel → provenance set, geo empty; mmdb-missing fail-safe.
- alerts: threshold config → tier transitions; email fired once per window (mailer mocked); dedup/rate-limit; no-mailer fail-safe.
- reports: schedule read → report generated + emailed (mailer + template mocked); `/report/now`.
- API: filters, geo aggregate, alerts; all JWT-gated, plain `def`.
- webui: presence view renders escaped fields; kbin deep-link; manual.

## 8. Séquencement (pour le plan)

1. `PresenceStore` + `presences` table + migration-free init (extends A's db).
2. Geo/provenance enricher (reuse mmdb).
3. WAN collector (sbxwaf threat-log + visitstats + crowdsec).
4. local + kbin collectors (project A devices + toolbox personas + kbin report link).
5. Wire collectors into nac's off-loop collector loop; `/presence*` API (def).
6. Alert engine + mailer (smtp-relay sendmail, tiered, deduped).
7. Report scheduler (timer + reporter templates + email) + `/report/now`.
8. WebUI Présence view (cross-plane table + geo/ASN panel + alerts + kbin deep-link).
9. Packaging (alert/report config, timer unit, changelog).

## 9. Risques

- **Depends on Project A** (the store, lazy-init, collector loop). B stacks on #818; ideally A merges + validates on the board first.
- **Email storms**: strict per-tier/window dedup + rate-limit; a misconfigured threshold must not flood. Off by default until thresholds set.
- **WAN cardinality**: many WAN IPs → bound the presences table (LRU/age-out old low-hit WAN presences; keep counts). The threat-log is already the bounded source.
- **kbin persona identity**: `mac_hash` is privacy-preserving (no raw identity) — the linkage is to the kbin report token, not PII.
- **Geo accuracy / mmdb freshness**: reuse the existing updater; geo is best-effort, provenance always set.
- **Scope**: Tor + emancipation explicitly out (later phase / Project C).
