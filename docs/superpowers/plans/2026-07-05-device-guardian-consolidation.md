# Device Guardian Consolidation Implementation Plan (Project A)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secubox-nac` (Client Guardian) the single canonical Device Guardian — a normalized SQLite store fed by one discovery pipeline with absorbed vendor/fingerprint/classifier logic — and retire `secubox-mac-guard`/`secubox-device-intel`/`secubox-iot-guard`, preserving every device and capability.

**Architecture:** New focused libs under `packages/secubox-nac/api/` — `store.py` (SQLite + idempotent legacy migration), `discovery.py` (dnsmasq+ISC+ARP merge), `enrich.py` (OUI vendor + device-type/risk classify + OpenWrt fingerprint), `collector.py` (background passive loop + double-cache). `api/main.py` handlers become plain `def` reading the cache/store (never scanning inline — the aggregator is a shared single-process loop). Actions keep nac's `inet secubox_nac` nft sets; mac-guard's allow/deny folds into `allow_state`. Retired modules' API paths redirect to nac; their packages are removed in a gated follow-up.

**Tech Stack:** Python 3.11 stdlib `sqlite3` (WAL, no ORM), FastAPI (aggregator-mounted), existing `secubox_core` auth, nftables, vanilla-JS LuCI-style webui.

## Global Constraints

- **Aggregator SPOF (#808):** every FastAPI handler is a plain `def` (FastAPI threadpools it); ALL discovery/scan/probe/subprocess/`ip neigh`/nft work happens in the background collector task or a threadpool, NEVER inline in a handler. Handlers read the double-cached snapshot or the SQLite store (short indexed queries only).
- **MAC canonicalization:** one function `canon_mac(s) -> str` (lowercase, colon-separated); applied on EVERY ingest so the four legacy casings (nac lower, mac-guard upper, device-intel upper, iot-guard lower) converge.
- **Migration is idempotent + additive + reversible:** importing the 3 legacy stores upserts by `mac`, re-run is a no-op, a corrupt legacy file is skipped (logged) and never aborts boot; legacy files are left untouched until the retired packages are removed.
- **Data preservation:** mac-guard's 277 devices + device-intel's 3 + iot-guard's DB migrate losslessly (per-column best non-null value; nac + iot history preserved).
- **Perms:** `/var/lib/secubox/nac/devices.db` is `0640 secubox:secubox`; no `/run/secubox` (1777) or `/etc/secubox` (0755) parent perm changes; nft calls are nac's existing ones.
- **SQLite:** WAL mode; the collector task is the ONLY writer; handlers read. Keep handler queries short + indexed (`last_seen`, `zone`, `device_type`).
- **Reserved for Project B:** the schema carries nullable `plane`, `provenance`, `geo_cc`, `geo_asn` columns — created but UNUSED in Project A (no code sets them). Do not build cross-plane/geo/alert/report features (Project B) or VLAN/Tor/mesh verbs (Project C).
- **SPDX header** (`LicenseRef-CMSD-1.0`) on every new file.
- **`git add` only the files a task changes** — never `.superpowers/` or `-A`.

---

## File Structure

- Create `packages/secubox-nac/api/store.py` — `DeviceStore` (SQLite), schema, `canon_mac`, `migrate_legacy`.
- Create `packages/secubox-nac/api/discovery.py` — `discover()` merging dnsmasq + ISC + ARP into canonical device dicts.
- Create `packages/secubox-nac/api/enrich.py` — `oui_vendor`, `classify_device_type`, `risk_score`, `openwrt_fingerprint`.
- Create `packages/secubox-nac/api/collector.py` — `Collector` (background passive loop, double-cache, event/webhook fire).
- Modify `packages/secubox-nac/api/main.py` — handlers → plain `def` reading store/cache; wire collector at startup; add absorbed endpoints; fold allow/deny into zones.
- Modify `packages/secubox-nac/www/luci-static/resources/view/client-guardian/clients.js` (+ a groups view) — vendor/type/risk columns, export.
- Create `packages/secubox-nac/tests/` — `test_store.py`, `test_discovery.py`, `test_enrich.py`, `test_collector.py`, `test_actions.py`, `test_redirects.py`.
- Modify `packages/secubox-nac/debian/{control,postinst,changelog}` — migration, deps (`ieee-data`), version bump.
- Modify retired modules' packaging + `aggregator.toml`/nginx for redirects (Task 9).

---

### Task 1: SQLite device store + idempotent legacy migration (`store.py`)

**Files:**
- Create: `packages/secubox-nac/api/store.py`
- Test: `packages/secubox-nac/tests/test_store.py`

**Interfaces (consumed by Tasks 2–9):**
- `canon_mac(s: str) -> str` — lowercase, `:`-separated, or `""` if not a MAC.
- `class DeviceStore:`
  - `__init__(self, db_path: str)` — opens SQLite, WAL, `CREATE TABLE IF NOT EXISTS` (schema below), creates indexes.
  - `upsert(self, dev: dict) -> None` — dev keyed by `mac` (already canon); per-column best-value merge (never overwrite a non-null stored value with a null incoming one; update `last_seen`, `ip`, `source` always).
  - `get(self, mac: str) -> dict | None`
  - `list(self, *, zone=None, device_type=None, risk_min=None, limit=1000) -> list[dict]` — indexed, newest `last_seen` first.
  - `count(self) -> int`
  - `record_event(self, mac, event, detail="")` / `history(mac=None, limit=200)`
- `migrate_legacy(store: DeviceStore, *, macguard_json, deviceintel_json, iot_db) -> dict` — idempotent import; returns `{"imported": n, "skipped": n}`; a missing/corrupt source is skipped (logged), never raises.

Schema (create exactly these columns; the last four are Project-B reserved, always nullable/unused here):
```sql
CREATE TABLE IF NOT EXISTS devices(
  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
  oui_vendor TEXT,
  is_router INTEGER DEFAULT 0, is_openwrt INTEGER DEFAULT 0, is_secubox INTEGER DEFAULT 0,
  model TEXT, luci_version TEXT,
  device_type TEXT DEFAULT 'unknown', risk_level TEXT DEFAULT 'unknown', risk_score INTEGER DEFAULT 50,
  zone TEXT, allow_state TEXT DEFAULT 'unknown', quarantined INTEGER DEFAULT 0, parental_profile TEXT,
  first_seen INTEGER, last_seen INTEGER, source TEXT,
  tags TEXT, notes TEXT, group_id TEXT,
  plane TEXT, provenance TEXT, geo_cc TEXT, geo_asn TEXT   -- RESERVED (Project B), unused here
);
CREATE INDEX IF NOT EXISTS idx_dev_last ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_dev_zone ON devices(zone);
CREATE INDEX IF NOT EXISTS idx_dev_type ON devices(device_type);
CREATE TABLE IF NOT EXISTS device_history(id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ts INTEGER, event TEXT, detail TEXT);
```

- [ ] **Step 1: Failing test — canon_mac + schema + upsert best-value**
```python
def test_canon_mac():
    from api.store import canon_mac
    assert canon_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert canon_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert canon_mac("not-a-mac") == ""

def test_upsert_best_value(tmp_path):
    from api.store import DeviceStore, canon_mac
    s = DeviceStore(str(tmp_path/"d.db"))
    s.upsert({"mac": canon_mac("AA:BB:CC:00:00:01"), "ip":"10.0.0.5","hostname":"h","oui_vendor":"Acme","first_seen":1,"last_seen":1,"source":"arp"})
    # a later sighting with no vendor must NOT wipe the stored vendor, but must update last_seen/ip
    s.upsert({"mac": "aa:bb:cc:00:00:01", "ip":"10.0.0.6","last_seen":2,"source":"dnsmasq"})
    d = s.get("aa:bb:cc:00:00:01")
    assert d["oui_vendor"] == "Acme" and d["ip"] == "10.0.0.6" and d["last_seen"] == 2
    assert s.count() == 1
```
- [ ] **Step 2: Run — FAIL.** `cd packages/secubox-nac && PYTHONPATH=../../common:. python3 -m pytest tests/test_store.py -q`
- [ ] **Step 3: Failing test — idempotent migration**
```python
def test_migrate_idempotent(tmp_path):
    import json, sqlite3
    from api.store import DeviceStore, migrate_legacy
    mg = tmp_path/"mg.json"; mg.write_text(json.dumps({"AA:BB:CC:00:00:02":{"ip":"10.0.0.7","vendor":"V","hostname":"m","first_seen":10,"last_seen":11}}))
    di = tmp_path/"di.json"; di.write_text(json.dumps({"AA:BB:CC:00:00:03":{"ip":"10.0.0.8","is_openwrt":True,"model":"X"}}))
    iot = tmp_path/"iot.db"; c=sqlite3.connect(iot); c.execute("CREATE TABLE devices(mac_address TEXT, ip TEXT, device_type TEXT, risk_score INT)"); c.execute("INSERT INTO devices VALUES('aa:bb:cc:00:00:02','10.0.0.7','phone',30)"); c.commit(); c.close()
    s = DeviceStore(str(tmp_path/"d.db"))
    r1 = migrate_legacy(s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot))
    assert s.count() == 2  # :02 (merged mg+iot) and :03
    d = s.get("aa:bb:cc:00:00:02")
    assert d["oui_vendor"] == "V" and d["device_type"] == "phone"  # cross-source merge
    r2 = migrate_legacy(s, macguard_json=str(mg), deviceintel_json=str(di), iot_db=str(iot))
    assert s.count() == 2  # re-run no-op
```
- [ ] **Step 4: Run — FAIL.**
- [ ] **Step 5: Implement `store.py`** — SPDX header; `canon_mac` (strip separators, hexen, regroup, validate 12 hex); `DeviceStore` (sqlite3 `PRAGMA journal_mode=WAL`, row_factory=dict, the schema above, `upsert` via `INSERT … ON CONFLICT(mac) DO UPDATE SET` with `COALESCE(excluded.x, devices.x)` for best-value on enrichment columns and always-set for `ip/last_seen/source`); `migrate_legacy` reads each legacy shape (mac-guard dict keyed by MAC with `vendor`; device-intel dict with `is_openwrt/model`; iot `devices` table `mac_address/device_type/risk_score`), canon-MACs, upserts, swallows per-source errors.
- [ ] **Step 6: Run — PASS** (both tests). `python3 -m pytest tests/test_store.py -q`
- [ ] **Step 7: Commit** `feat(nac): SQLite device store + idempotent legacy migration (ref #817)`

---

### Task 2: Unified discovery merge (`discovery.py`)

**Files:**
- Create: `packages/secubox-nac/api/discovery.py`
- Test: `packages/secubox-nac/tests/test_discovery.py`

**Interfaces:**
- Consumes: `store.canon_mac`.
- Produces: `discover(*, dnsmasq_leases, isc_leases, arp_cmd=default) -> list[dict]` — parses all three sources (paths injectable for tests; `arp_cmd` a callable returning `ip neigh` text), merges by canon MAC into one dict per device with `{mac, ip, hostname, source}` where `source` is the highest-confidence origin seen (`dnsmasq`|`isc`|`arp`). LAN-iface filter for ARP reuses nac's `LAN_INTERFACES`. Fail-safe: a missing/garbage source contributes nothing, never raises.

- [ ] **Step 1: Failing test — three sources merge/dedup by MAC**
```python
def test_discover_merges(tmp_path):
    from api.discovery import discover
    dns = tmp_path/"dnsmasq.leases"; dns.write_text("1700000000 aa:bb:cc:00:00:10 10.0.0.10 host-a *\n")
    isc = tmp_path/"dhcpd.leases"; isc.write_text('lease 10.0.0.11 {\n hardware ethernet AA:BB:CC:00:00:11;\n client-hostname "host-b";\n}\n')
    arp = lambda: "10.0.0.10 dev br0 lladdr aa:bb:cc:00:00:10 REACHABLE\n10.0.0.12 dev br0 lladdr aa:bb:cc:00:00:12 STALE\n"
    out = {d["mac"]: d for d in discover(dnsmasq_leases=str(dns), isc_leases=str(isc), arp_cmd=arp)}
    assert set(out) == {"aa:bb:cc:00:00:10","aa:bb:cc:00:00:11","aa:bb:cc:00:00:12"}
    assert out["aa:bb:cc:00:00:10"]["hostname"] == "host-a"   # dnsmasq wins over bare arp
    assert out["aa:bb:cc:00:00:11"]["source"] == "isc"
    assert out["aa:bb:cc:00:00:12"]["source"] == "arp"

def test_discover_failsafe(tmp_path):
    from api.discovery import discover
    out = discover(dnsmasq_leases=str(tmp_path/"missing"), isc_leases=str(tmp_path/"missing2"), arp_cmd=lambda: (_ for _ in ()).throw(OSError()))
    assert out == []
```
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement `discovery.py`** — reuse nac's `_parse_leases` (dnsmasq) logic + device-intel's ISC block-regex parser (`_get_dhcp_leases`, `DHCP_LEASES=/var/lib/dhcp/dhcpd.leases`) + nac's `_parse_arp` (LAN_INTERFACES filter). Merge preferring a source with a hostname; `source` records the winning origin. All wrapped so any source failure yields empty for that source.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(nac): unified dnsmasq+ISC+ARP discovery merge (ref #817)`

---

### Task 3: Enrichers — OUI vendor, device-type/risk, OpenWrt fingerprint (`enrich.py`)

**Files:**
- Create: `packages/secubox-nac/api/enrich.py`
- Test: `packages/secubox-nac/tests/test_enrich.py`

**Interfaces:**
- `load_oui(path="/usr/share/ieee-data/oui.txt") -> dict[str,str]` (prefix→vendor; missing file → `{}`) and `oui_vendor(mac, oui_map) -> str` — from mac-guard's `_load_oui_db`.
- `classify_device_type(hostname, vendor) -> str` and `risk_score(device_type, is_router, open_ports=None) -> tuple[int,str]` — from iot-guard's keyword map (camera/smart_tv/smart_speaker/smart_home/printer/router/phone/…) + score→level (`low/medium/high`).
- `openwrt_fingerprint(hostname) -> dict` — `{is_openwrt, is_router, router_vendor}` from device-intel's `ROUTER_VENDORS`/`OPENWRT_HOSTNAMES`/`_is_openwrt_hostname`. (Active HTTP LuCI probe is a separate on-demand endpoint in Task 6, not here.)

- [ ] **Step 1: Failing tests**
```python
def test_classify_and_risk():
    from api.enrich import classify_device_type, risk_score
    assert classify_device_type("living-room-camera", "Hikvision") == "camera"
    assert classify_device_type("Johns-iPhone", "Apple") == "phone"
    lvl = risk_score("camera", is_router=False)[1]
    assert lvl in {"low","medium","high"}

def test_oui_and_openwrt(tmp_path):
    from api.enrich import load_oui, oui_vendor, openwrt_fingerprint
    ouif = tmp_path/"oui.txt"; ouif.write_text("AA-BB-CC   (hex)\t\tAcme Corp\n")
    m = load_oui(str(ouif))
    assert oui_vendor("aa:bb:cc:00:00:20", m) == "Acme Corp"
    fp = openwrt_fingerprint("OpenWrt")
    assert fp["is_openwrt"] is True
```
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement `enrich.py`** — lift the three modules' pure functions verbatim (attribute the source in a comment), stdlib only.
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(nac): absorbed enrichers — OUI vendor + device-type/risk + OpenWrt fingerprint (ref #817)`

---

### Task 4: Background collector + double-cache; handlers → plain `def`

**Files:**
- Create: `packages/secubox-nac/api/collector.py`
- Modify: `packages/secubox-nac/api/main.py` (startup wiring; `status`/`clients`/`client` handlers → `def` reading the store; keep `_notify_webhooks`/`_record_event`)
- Test: `packages/secubox-nac/tests/test_collector.py`

**Interfaces:**
- Consumes: `discovery.discover`, `enrich.*`, `store.DeviceStore`.
- Produces: `class Collector: __init__(store, oui_map, interval=30)`, `async run_forever(self)` (passive discover → enrich → `store.upsert`; on a MAC not previously in the store, `record_event("client_joined")` + fire webhooks; update an in-memory `snapshot` list for handlers), `snapshot(self) -> list[dict]`.

- [ ] **Step 1: Failing test — one cycle populates store + fires join event; Write never scans**
```python
def test_collector_cycle(tmp_path, monkeypatch):
    from api.store import DeviceStore
    from api.collector import Collector
    s = DeviceStore(str(tmp_path/"d.db"))
    import api.collector as C
    monkeypatch.setattr(C, "discover", lambda **k: [{"mac":"aa:bb:cc:00:00:30","ip":"10.0.0.30","hostname":"cam","source":"arp"}])
    events=[]; col = Collector(s, oui_map={}, interval=0); col._emit = lambda ev,d: events.append(ev)
    col.cycle_once()
    assert s.count()==1 and "client_joined" in events
    d = s.get("aa:bb:cc:00:00:30"); assert d["device_type"] in {"camera","unknown"}  # classified during enrich
    assert col.snapshot()[0]["mac"]=="aa:bb:cc:00:00:30"
```
(Expose a synchronous `cycle_once()` that `run_forever` calls each interval, so the test drives one cycle deterministically.)
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement `collector.py`** + rewire `main.py`: at `startup`, build `DeviceStore`, run `migrate_legacy` once, `load_oui`, start `Collector.run_forever` as the task (replacing `_monitor_clients`). Convert `status`/`clients`/`client/{mac}` handlers from `async def` to **`def`** returning `collector.snapshot()` / `store.get()` (NO `_discover_clients()` inline — that was the loop-block). Keep webhook firing inside the collector.
- [ ] **Step 4: Run — PASS** + full nac suite green.
- [ ] **Step 5: Commit** `feat(nac): background collector + double-cache; handlers def, no inline scan (ref #817)`

---

### Task 5: Fold mac-guard allow/deny into nac zones/nft

**Files:**
- Modify: `packages/secubox-nac/api/main.py` (allow/deny endpoints + `allow_state` → nft)
- Test: `packages/secubox-nac/tests/test_actions.py`

**Interfaces:** `POST /allow/{mac}` / `POST /deny/{mac}` set `allow_state` in the store and drive nft: deny → add to `blocked` set + remove from `lan_allowed`; allow → reverse. Reuse nac's `_nft_add_element`/`_nft_delete_element` on `inet secubox_nac`. (mac-guard's separate `inet secubox_mac_guard` table is retired; its members are migrated into `secubox_nac` at cutover — Task 9.)

- [ ] **Step 1: Failing test (nft mocked)** — `deny` adds MAC to `blocked` and sets `allow_state="deny"`; `allow` reverses. Assert against a fake `_nft_*` capturing set membership.
- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Commit** `feat(nac): fold allow/deny into zones (mac-guard absorbed) (ref #817)`

---

### Task 6: Absorbed endpoints (vendors, scan, probe, mDNS, groups, export)

**Files:** Modify `packages/secubox-nac/api/main.py`; Test `packages/secubox-nac/tests/test_endpoints.py`

**Interfaces (all plain `def`; heavy ops via `run_in_threadpool` / background, never inline-blocking):**
- `GET /vendors` (OUI map size + lookup), `GET /clients?device_type=&risk_min=` (store filters), `POST /scan` (on-demand nmap/arping → threadpool → upsert), `POST /probe/openwrt[/{ip}]` (device-intel `_probe_luci`, bounded concurrency, updates fingerprint columns), `GET /mdns` (avahi-browse, threadpool), `GET /groups` + CRUD (device_groups table), `GET /export/{json,csv}` (dump the store).

- [ ] **Step 1: Failing tests** — `/clients?device_type=camera` filters to camera rows; `/export/csv` returns a header + one row per device; `/groups` CRUD round-trips. (Scan/probe/mDNS: test the store-update path with the subprocess mocked.)
- [ ] **Step 2: Run — FAIL.** → **Step 3: Implement.** → **Step 4: PASS.**
- [ ] **Step 5: Commit** `feat(nac): absorbed endpoints — vendors/scan/probe/mdns/groups/export (ref #817)`

---

### Task 7: Retirement redirects + auth-gate the open `/status`

**Files:** Modify `packages/secubox-{mac-guard,device-intel,iot-guard}/api/main.py` (redirect stubs), `packages/secubox-network-anomaly/api/main.py` (auth-gate); Test `packages/secubox-nac/tests/test_redirects.py`

**Interfaces:** each retired module's `api/main.py` is reduced to a thin app whose routes `RedirectResponse(status_code=308, url="/api/v1/nac/…")` map to the nac equivalent (`/devices`→`/clients`, `/whitelist`→`/allow`, etc.); a deprecation header `X-SecuBox-Deprecated: use /api/v1/nac`. `network-anomaly` stays but its `/status` (and any open route) now `Depends(require_jwt)` like nac (security fix; device-intel/iot-guard become redirects so their open-status is moot).

- [ ] **Step 1: Failing test** — a request to a retired path returns 308 to the nac equivalent; `network-anomaly /status` without a token now 401.
- [ ] **Step 2–4: implement + pass.**
- [ ] **Step 5: Commit** `feat(nac): retire mac-guard/device-intel/iot-guard via redirects; auth-gate network-anomaly (ref #817)`

---

### Task 8: WebUI — vendor/type/risk columns + groups + export

**Files:** Modify `packages/secubox-nac/www/luci-static/resources/view/client-guardian/clients.js` (+ add `groups.js`, register in the view menu); remove retired modules' `www/<name>/`.

- [ ] **Step 1** Add `oui_vendor` / `device_type` / `risk_level` columns + OpenWrt/SecuBox fingerprint badges to the clients table; wire the existing fetch to the enriched `/clients` fields.
- [ ] **Step 2** Add a groups view (list/create/assign) hitting `/groups*`, and an Export button (→ `/export/csv`).
- [ ] **Step 3** Remove `packages/secubox-{mac-guard,device-intel,iot-guard}/www/`.
- [ ] **Step 4** Manual load check (stub fetch) + confirm C3BOX palette + no console errors; escape all rendered device fields (hostname/vendor are attacker-influenceable) via `textContent`.
- [ ] **Step 5: Commit** `feat(nac): webui — vendor/type/risk columns, groups, export; drop retired webuis (ref #817)`

---

### Task 9: Packaging — migration wiring, deps, redirects config, changelog

**Files:** Modify `packages/secubox-nac/debian/{control,postinst,changelog}`; the retired packages' `debian/` (mark transitional / drop www); `aggregator.toml` example + nginx route confs.

- [ ] **Step 1** `nac` `debian/control`: add `Depends: ieee-data` (OUI) + `python3` sqlite (stdlib, no dep). postinst: create `devices.db` dir `0640 secubox:secubox`; the idempotent `migrate_legacy` runs lazily at first collector start (no heavy postinst work) — document it.
- [ ] **Step 2** nft migration: at cutover, copy `inet secubox_mac_guard` `mac_blacklist`/`mac_whitelist` elements into `secubox_nac` `blocked`/`lan_allowed` (a one-shot in postinst, idempotent, best-effort).
- [ ] **Step 3** aggregator.toml + nginx: keep nac; the 3 retired module routes point at their redirect stubs (Task 7). Bump `secubox-nac` changelog (e.g. 3.0.0 — major: SQLite + consolidation), reference #817.
- [ ] **Step 4** Verify `dpkg-parsechangelog` parses; note the retired-package REMOVAL is a **separate gated follow-up** (after the redirect window proves clean live) — do NOT remove the packages in this plan.
- [ ] **Step 5: Commit** `chore(nac): packaging — migration wiring, ieee-data dep, retirement redirects, changelog (ref #817)`

---

## Done-Definition (Project A)

On the board, `secubox-nac` serves the unified SQLite inventory (mac-guard's 277 + device-intel's 3 merged, MAC-canonical, vendor/type/risk enriched), one discovery loop replaces four, handlers are non-blocking `def`, existing actions (zones/ban/quarantine/allow-deny) work through `secubox_nac` nft, the 3 retired modules' paths 308-redirect to nac, network-anomaly is auth-gated, and the webui shows the enriched columns. Full pytest suite green. Retired-package removal is deferred to a gated follow-up. **No** cross-plane/geo/alert/report (Project B) or VLAN/Tor/mesh (Project C) code.

## Notes for Project B (do not build here)
The reserved `plane`/`provenance`/`geo_cc`/`geo_asn` columns + the `DeviceStore` API are the seam Project B extends: WAN visitors, WG/kbin personas, and Tor visitors become rows (or a sibling `presences` table) with `plane` set, geo-enriched via the existing `waf/geoip` + metrics `visitor_origin` infra, feeding alert tiers + email/reports.
