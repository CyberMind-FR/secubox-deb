# Cross-plane Presence Guardian Implementation Plan (Project B / B1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a cross-plane presence layer to `secubox-nac` (Client Guardian): a `presences` table fed by WAN/LAN/WG/kbin collectors with geo/provenance enrichment, tiered alerts that email on thresholds, wired scheduled reports, and a unified "Présence" webui view — stacked on Project A (#818).

**Architecture:** New focused modules under `packages/secubox-nac/api/presence/` — `store.py` (`PresenceStore`, mirrors A's `DeviceStore`), `geo.py` (mmdb enrich), `wan.py`/`local.py`/`kbin.py` (plane collectors), `alerts.py` + `mailer.py` (tiered alert engine + sendmail), `reports.py` (scheduler + email). Wired into A's existing off-loop collector loop; new `/presence*` handlers (plain `def`) in `api/main.py`. Presences live in A's `devices.db` (a new table). Tor deferred; emancipation → Project C.

**Tech Stack:** Python stdlib `sqlite3` (WAL + Lock), `geoip2`/`maxminddb` (existing mmdb), `/usr/sbin/sendmail -t -oi` (smtp-relay path), FastAPI (aggregator-mounted → plain `def`), vanilla-JS webui.

## Global Constraints

- **Inherit ALL Project A constraints**: every handler plain `def`; ALL collection/geo/subprocess/log-tail work OFF the shared aggregator loop (`run_in_executor` in the collector; #808) — nac is aggregator-mounted, so a blocking call board-wide-blocks. Lazy-init (A's middleware) must cover the new store/collectors.
- **PresenceStore**: WAL + `threading.Lock` around every SQL op (mirror `DeviceStore`); the collector is the only writer; handlers read short indexed queries.
- **Fail-safe everywhere**: a missing source (no threat-log, no mmdb, no sendmail, no crowdsec) contributes nothing and NEVER raises or crashes the loop/handler.
- **No mail storms**: alert email is rate-limited + deduped (coalesce per `(tier, plane)` per window); the feature is OFF until thresholds are configured (`/etc/secubox/presence-alerts.toml` absent → no alerts).
- **Geo best-effort**: `provenance` is ALWAYS set (geo/private/lan/tunnel/mesh/bot); `geo_cc`/`geo_asn` only for public IPs when mmdb present.
- **Privacy**: no new PII — WAN uses IP+UA+host (already in the threat-log), kbin uses `mac_hash` (not raw identity); the kbin link is a report token, not PII.
- **Perms**: reuse A's `devices.db` (`0640 secubox:secubox`) for the `presences` table; no `/run`/`/etc/secubox` parent perm changes.
- **SPDX** `LicenseRef-CMSD-1.0` (full 4-line block) on every new file. `git add` only the files a task changes.
- **Reserved**: no Tor collection, no VLAN/Tor/mesh emancipation (Project C).

---

## File Structure

- Create `packages/secubox-nac/api/presence/__init__.py`, `store.py`, `geo.py`, `wan.py`, `local.py`, `kbin.py`, `alerts.py`, `mailer.py`, `reports.py`.
- Modify `packages/secubox-nac/api/collector.py` (add plane-collector steps to the off-loop cycle) and `api/main.py` (`/presence*` handlers + wire alert/report).
- Modify `packages/secubox-nac/www/luci-static/resources/view/client-guardian/` — add `presence.js` + register in `nav.js`.
- Create `packages/secubox-nac/tests/presence/` — `test_presence_store.py`, `test_geo.py`, `test_wan.py`, `test_local_kbin.py`, `test_alerts.py`, `test_reports.py`, `test_presence_api.py`.
- Packaging: `debian/` alert/report config + `secubox-presence-report.timer/service` + changelog.

---

### Task 1: `PresenceStore` + `presences` table

**Files:** Create `packages/secubox-nac/api/presence/__init__.py`, `packages/secubox-nac/api/presence/store.py`; Test `packages/secubox-nac/tests/presence/test_presence_store.py`.

**Interfaces (consumed by all later tasks):**
- `class PresenceStore:` `__init__(db_path)` opens the SAME `devices.db` (a new `presences` table + `presence_alerts` table; `CREATE TABLE IF NOT EXISTS`; WAL; `threading.Lock`).
- `pid(plane, identity) -> str` = `f"{plane}:{identity}"`.
- `upsert(pres: dict)` — best-value merge keyed by `id`; always update `last_seen`, increment `hits`; never null-clobber `geo_*`/`device_mac`.
- `get(id)`, `list(*, plane=None, tier=None, limit=1000)` (newest last_seen), `count(plane=None)`.
- `record_alert(plane, tier, detail)` / `alerts(limit=200)`.
Schema exactly per the spec §4.1 (`presences` cols + indexes `plane`,`last_seen`; `presence_alerts(id,ts,plane,tier,detail)`).

- [ ] **Step 1: Failing test** — upsert a `wan:1.2.3.4` presence (geo set), re-upsert with no geo → geo preserved, `hits` incremented, `last_seen` updated; `list(plane="wan")` returns it; `count()`.
- [ ] **Step 2: Run — FAIL.** `cd packages/secubox-nac && PYTHONPATH=../../common:. python3 -m pytest tests/presence/test_presence_store.py -q`
- [ ] **Step 3: Implement** `store.py` mirroring `api/store.py`'s `DeviceStore` (WAL, Lock, best-value upsert with `COALESCE(excluded,existing)` for enrichment cols, always-set `last_seen`, `hits = devices.hits + 1`). Import-safe (no I/O at import). SPDX.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(nac): PresenceStore + presences table (Project B, ref #820)`

---

### Task 2: Geo/provenance enricher (`presence/geo.py`)

**Files:** Create `packages/secubox-nac/api/presence/geo.py`; Test `tests/presence/test_geo.py`.

**Interfaces:** `enrich_origin(ip_or_identity, plane) -> dict` → `{geo_cc, geo_asn, geo_org, provenance}`. Public IP + mmdb present → geo + `provenance="geo"`. Private/loopback/link-local IP → `provenance="private"`. Non-IP identity by plane → `provenance` in `{lan, wg:"tunnel", kbin:"tunnel", mesh}`. mmdb missing → geo empty, provenance still set. Reuse the `geoip2.database.Reader(GEOIP_DB_PATH="/var/lib/secubox/geoip/GeoLite2-Country.mmdb")` + `maxminddb` ASN pattern from `packages/secubox-waf/api/main.py` (in-memory cached readers; `AddressNotFoundError`→empty).

- [ ] **Step 1: Failing tests** — a public IP (mock reader) → `provenance=="geo"` + `geo_cc`; `10.0.0.5` → `provenance=="private"`, no geo; a `wg`/`kbin` identity → `provenance=="tunnel"`; reader-missing → no raise, provenance set.
- [ ] **Step 2: Run — FAIL.** → **Step 3: Implement** (mmdb readers lazily opened + cached; fully fail-safe). → **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(nac): presence geo/provenance enricher (reuse mmdb) (ref #820)`

---

### Task 3: WAN collector (`presence/wan.py`)

**Files:** Create `packages/secubox-nac/api/presence/wan.py`; Test `tests/presence/test_wan.py`.

**Interfaces:** `collect_wan(store, geo_enrich, *, threat_log="/var/log/secubox/waf-threats.log", visitstats_path=…, max_bytes=8MiB) -> int` — bounded tail-read the threat-log JSONL (`{client_ip, host, user_agent, category, timestamp}`), classify client-type from the UA (bot/crawler/mobile-app/browser — mirror sbxwaf's `classifyUA` keywords), `geo_enrich(client_ip,"wan")`, `store.upsert({id:pid("wan",ip), plane:"wan", identity:ip, client_type, provenance/geo…, extra:{host,ua,category}})`; returns count. Optionally fold sbxwaf `visitstats` aggregate client-type counts into a summary (out of the per-IP rows). Fail-safe: missing log → 0.

- [ ] **Step 1: Failing test** — a threat-log fixture with 2 IPs (one bot UA, one browser UA) → 2 `wan:` presences with the right `client_type` + geo (mocked); bounded tail; missing log → 0 (no raise).
- [ ] **Step 2–4: FAIL → implement → PASS.**
- [ ] **Step 5: Commit** `feat(nac): WAN presence collector (sbxwaf threat-log + UA classify) (ref #820)`

---

### Task 4: local + kbin collectors (`presence/local.py`, `presence/kbin.py`)

**Files:** Create `presence/local.py`, `presence/kbin.py`; Test `tests/presence/test_local_kbin.py`.

**Interfaces:**
- `collect_local(store, device_store) -> int` — project A's `devices` (LAN + WG source) into `lan:<mac>` / `wg:<mac_hash-or-mac>` presences with `device_mac` set + `provenance` `lan`/`tunnel`; no new discovery, just a mirror.
- `collect_kbin(store, *, personas_source) -> int` — read toolbox `mac_hash` personas (the R3 tunnel identities; the source is the toolbox persona/media-catch/report registry — read whatever exists, e.g. `/run/secubox/media-catch.jsonl` client hashes or a persona list) → `kbin:<mac_hash>` presences, `provenance="tunnel"`, and when a persona has a kbin report token, store it in `extra.report_token` for the webui deep-link. Fail-safe on a missing source.

- [ ] **Step 1: Failing tests** — a fake DeviceStore with a lan + a wg device → 2 presences with `device_mac` linked; a personas fixture → `kbin:` presences with `report_token` in extra; missing source → 0.
- [ ] **Step 2–4: FAIL → implement → PASS.**
- [ ] **Step 5: Commit** `feat(nac): local + kbin presence collectors (ref #820)`

---

### Task 5: Wire collectors into the loop + `/presence*` API

**Files:** Modify `packages/secubox-nac/api/collector.py` + `api/main.py`; Test `tests/presence/test_presence_api.py`.

- Add a `PresenceCollector` (or extend A's `Collector`): each off-loop cycle also runs `collect_wan`/`collect_local`/`collect_kbin` (each fail-safe, wrapped) into the shared `PresenceStore`. Init the `PresenceStore` in A's `_do_init()` (idempotent, lazy-init-covered).
- API (plain `def`, `Depends(require_jwt)`): `GET /presence` (filter `?plane=&tier=`), `GET /presence/{id}`, `GET /presence/geo` (aggregate count by `geo_cc`/`geo_asn`), `GET /presence/alerts`, `POST /presence/sync` (force one collect, threadpooled).

- [ ] **Step 1: Failing tests** — seed the PresenceStore; `/presence?plane=wan` filters; `/presence/geo` aggregates by country; all JWT-gated + plain `def`. (Monkeypatch DATA_DIR / temp ACL for import.)
- [ ] **Step 2–4: FAIL → implement → PASS.**
- [ ] **Step 5: Commit** `feat(nac): wire presence collectors off-loop + /presence API (ref #820)`

---

### Task 6: Alert engine + mailer (`presence/alerts.py`, `presence/mailer.py`)

**Files:** Create `presence/alerts.py`, `presence/mailer.py`; Test `tests/presence/test_alerts.py`.

**Interfaces:**
- `mailer.send_alert(subject, body, *, to, sendmail="/usr/sbin/sendmail") -> bool` — shell `["/usr/sbin/sendmail","-t","-oi"]` feeding an RFC822 message (mirror `packages/secubox-smtp-relay/api/main.py`'s send path); fail-safe (returns False on any error, never raises). Factored so tests mock the subprocess.
- `alerts.evaluate(store, config, mailer, *, now, state) -> list[dict]` — read thresholds from `config` (parsed `/etc/secubox/presence-alerts.toml`: per-plane/tier counts + a window + a recipient); compute tier for presences/counts (reuse A's rogue-AP HIGH for a new-unknown-router WG/LAN presence; a new WAN country → notice; bot surge > N/window → warn; operator criticals); on a tier transition record `store.record_alert(...)` and `mailer.send_alert(...)` — **deduped/rate-limited**: coalesce per `(tier, plane)` per window via `state` (an in-memory last-sent map). No config → no alerts.

- [ ] **Step 1: Failing tests** — a config with a WAN-bot threshold; feed presences crossing it → one alert recorded + `mailer.send_alert` called ONCE; a second eval in the same window → NOT re-sent (dedup); no config → no alerts; mailer raising → alert still recorded (fail-safe).
- [ ] **Step 2–4: FAIL → implement → PASS.**
- [ ] **Step 5: Commit** `feat(nac): tiered presence alert engine + sendmail mailer (deduped) (ref #820)`

---

### Task 7: Report scheduler + `/presence/report/now`

**Files:** Create `presence/reports.py`; Modify `api/main.py`; Create `debian/secubox-presence-report.{service,timer}`; Test `tests/presence/test_reports.py`.

**Interfaces:** `reports.build_report(store, *, fmt="html") -> bytes` (a presence report: per-plane counts, geo/ASN top-N, recent alerts — reuse `packages/secubox-reporter`'s HTML/PDF template helpers if importable, else a self-contained HTML). `reports.run_scheduled(store, schedule_path, mailer, recipient)` reads `/etc/secubox/reporter-schedule.json` (daily/weekly) and emails the report. A systemd `secubox-presence-report.timer` → `.service` runs `run_scheduled`. `POST /presence/report/now` (def) generates + returns/download.

- [ ] **Step 1: Failing tests** — `build_report` returns non-empty HTML with the plane counts; `run_scheduled` (mocked mailer + schedule) emails once; `/report/now` returns a report. 
- [ ] **Step 2–4: FAIL → implement → PASS.**
- [ ] **Step 5: Commit** `feat(nac): presence report scheduler + email + /report/now (ref #820)`

---

### Task 8: WebUI "Présence" view

**Files:** Create `packages/secubox-nac/www/luci-static/resources/view/client-guardian/presence.js`; Modify `nav.js`.

- [ ] **Step 1** Cross-plane table: plane badge, identity, geo flag/`geo_cc`+ASN OR `provenance` tag, `client_type`, `hits`, `tier` (colored). Fetch `/presence` (sbx_token auth like other views). ALL fields via `E()`/`textContent` (host/UA/geo are attacker-influenceable — escape).
- [ ] **Step 2** A geo/ASN aggregate panel (`/presence/geo`) + an alerts panel (`/presence/alerts`). A LAN/WG row links to the device (A's client view); a kbin row deep-links the kbin report via `extra.report_token`.
- [ ] **Step 3** Register "Présence" in `nav.js` (mirror the Task-A-8 `groups.js` registration). C3BOX palette.
- [ ] **Step 4** Verify no `innerHTML` of untrusted fields (grep); `node --check` on a stubbed copy.
- [ ] **Step 5: Commit** `feat(nac): webui — cross-plane Présence view + geo/alerts + kbin deep-link (ref #820)`

---

### Task 9: Packaging

**Files:** Modify `packages/secubox-nac/debian/{control,postinst,changelog}`; add the timer/service + a default `presence-alerts.toml.example`.

- [ ] **Step 1** Ship `secubox-presence-report.{service,timer}` (root oneshot generating+emailing; timer daily) + a commented `presence-alerts.toml.example` (thresholds OFF by default). postinst installs them but does NOT enable alerts (config absent = off).
- [ ] **Step 2** `debian/control`: no new hard dep (geoip2/maxminddb already pulled by waf/metrics; sendmail via smtp-relay is a runtime path, `Recommends` at most).
- [ ] **Step 3** Bump `secubox-nac` changelog (e.g. `3.1.0`) referencing #820; `dpkg-parsechangelog` parses.
- [ ] **Step 4: Commit** `chore(nac): packaging — presence report timer + alert config example + changelog (ref #820)`

---

## Done-Definition (B1)

`/presence` shows WAN visitors/bots (geo-tagged), LAN+WG devices (linked to A), and kbin personas (deep-linked to their kbin report) in one view; tiered alerts email (deduped) on configured thresholds; a scheduled presence report emails daily; all collectors run off the shared loop (no board-wide stall); everything plain `def` + fail-safe. Full pytest green. **Tor + emancipation NOT built** (later phase / Project C).

## Notes for Project C
The `presences` table + `tier` + the alert engine are the seam Project C's triage/emancipation verbs (VLAN/Tor/mesh) act on — a presence/device at a tier can be routed into a channel.
