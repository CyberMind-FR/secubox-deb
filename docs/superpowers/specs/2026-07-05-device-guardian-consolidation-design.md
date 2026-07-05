# Design — Device Guardian consolidation (Project A)

- **Issue** : [#817](https://github.com/CyberMind-FR/secubox-deb/issues/817)
- **Date** : 2026-07-05
- **Licence** : LicenseRef-CMSD-1.0
- **Module** : `packages/secubox-nac/` (Client Guardian) ; retires `secubox-mac-guard`, `secubox-device-intel`, `secubox-iot-guard`

## 1. Problème

Cinq modules se recouvrent sur la découverte/inventaire des appareils LAN, chacun avec sa propre boucle de scan et son propre store MAC-clé :

| module | store | valeur distincte | état board |
|--------|-------|------------------|-----------|
| **nac** (client-guardian) | JSON, MAC bas-de-casse | zones nft + parental + webhooks + **webui la plus riche** (8 vues, ~2285 lignes JS) + history/policy | live, **1** device |
| **mac-guard** | JSON, MAC HAUT-de-casse | whitelist/blacklist + **OUI vendor** (`ieee-data`) + auto-block | live, **277** devices |
| **device-intel** | JSON, MAC HAUT | **fingerprint OpenWrt/SecuBox/LuCI** + mDNS + groupes + export CSV/JSON + **parser ISC dhcpd.leases** | live, 3 devices |
| **iot-guard** | **SQLite** (meilleur schéma) | **classifieur device-type + risk-score** + sync mesh P2P + diag Chromecast | live, on-demand |
| **network-anomaly** | JSONL par métrique | détection d'anomalie statistique (z-score, port-scan) — **PAS un store d'appareils** | live |

Quatre lancent la **même** boucle ARP/DHCP indépendamment (code copié-collé), chacun un store MAC divergent (casse incohérente). Résultat : données fragmentées (l'inventaire réel = mac-guard 277 ; nac quasi-vide mais UI/policy riches), quadruple scan redondant, et device-intel/iot-guard/network-anomaly exposent `/status` **sans auth**.

## 2. Objectif

**Un seul** module d'appareils : `secubox-nac` (marque *Client Guardian*) devient le **Device Guardian** canonique — store SQLite normalisé, une boucle de découverte unifiée, toute la logique distincte absorbée, les 3 modules doublons retirés, `network-anomaly` gardé à part. Actions **existantes uniquement** (zones/ban/quarantine/allow-deny). Aucune régression de données ni d'UI.

## 3. Décisions (brainstorm 2026-07-05)

| Axe | Décision |
|-----|----------|
| Home canonique | **`secubox-nac`** (live, UI+policy les plus riches) ; garde le paquet, `/api/v1/nac/`, la socket, la webui |
| Store | Migration flat-JSON → **SQLite** (base = schéma iot-guard), MAC **bas-de-casse** canonique |
| Absorption | OUI vendor (mac-guard) ; fingerprint OpenWrt/mDNS/groupes/export/ISC-parser (device-intel) ; classifieur device-type + risk + mesh-sync + schéma SQLite (iot-guard) — en **libs internes**, pas en modules |
| Retrait | mac-guard, device-intel, iot-guard : logique absorbée → routes `/api/v1/<name>/*` en **redirections** → suppression paquet après fenêtre |
| network-anomaly | **reste autonome** ; gagne « attacher une anomalie à un MAC/IP » depuis le store nac |
| Cast diag (iot-guard) | **scindé** en petit outil séparé (ou abandonné) — hors cœur |
| Actions | **existantes seulement** : zones nft (lan/iot/guest/quarantine/blocked) + ban + quarantine + parental + allow/deny (mac-guard replié) |
| Réservé Project B | colonnes **nullable** `plane`/`provenance`/`geo_*` dans le schéma (WAN/WG/Tor/kbin plus tard) |

**Non-objectifs (différés)** : observation cross-plan WAN/WG/Tor/kbin + geo + alertes + email/rapports → **Project B**. Verbes d'émancipation VLAN/Tor/mesh → **Project C**.

## 4. Architecture

### 4.1 Store canonique — SQLite

`/var/lib/secubox/nac/devices.db` (owner `secubox`, 0640). Table `devices`, une ligne/appareil, `mac` **bas-de-casse** PK. Schéma = iot-guard étendu :

```
devices(
  mac TEXT PRIMARY KEY,               -- lowercase canonical
  ip TEXT, hostname TEXT,
  oui_vendor TEXT,                    -- mac-guard: ieee-data lookup
  is_router INT, is_openwrt INT, is_secubox INT, model TEXT, luci_version TEXT,  -- device-intel fingerprint
  device_type TEXT, risk_level TEXT, risk_score INT,  -- iot-guard classifier
  zone TEXT,                          -- nac: lan_allowed|iot_zone|guest_zone|quarantine_zone|blocked
  allow_state TEXT,                   -- allow|deny|unknown (mac-guard folded)
  quarantined INT, parental_profile TEXT,
  first_seen INT, last_seen INT, source TEXT,  -- source: dnsmasq|isc|arp|nmap|mdns|mesh|manual
  tags TEXT, notes TEXT, group_id TEXT,
  -- RESERVED for Project B (nullable, unused in A):
  plane TEXT, provenance TEXT, geo_cc TEXT, geo_asn TEXT
)
device_history(id, mac, ts, event, detail)   -- from nac history + iot device_history
device_groups(id, name, ...)                 -- device-intel groups
```

Access via a small `secubox_core.device_store` module (or `nac/store.py`) — plain stdlib `sqlite3`, WAL mode, one connection per request (aggregator is single-process; keep queries short, indexed on `last_seen`/`zone`/`device_type`). **No ORM.**

### 4.2 Migration (idempotente, first-boot)

`nac`'s postinst (or a lazy first-request init) imports the 3 legacy stores into `devices.db` **once**, MAC-keyed merge (lowercase-normalise), preferring the richest non-null field per column. Re-run = no-op (upsert on `mac`, skip if `last_seen` unchanged). Legacy files (`mac-guard/devices.json` 277, `device-intel/devices.json` 3, `iot-guard/devices.db`) are **read-only, left in place** until the retired packages are removed — fully reversible.

### 4.3 One discovery pipeline

Replaces the 4 duplicate loops with a single `nac` background task (double-cached; the aggregator's `def` handlers read the cache, never scan inline — #808 rule):

1. **Passive** each interval (default 30s): dnsmasq leases + **ISC `dhcpd.leases`** (device-intel parser) + ARP `ip neigh` (LAN-iface allowlist, nac's filter) → merge by MAC.
2. **Enrich**: OUI vendor (`ieee-data`); device-type + risk classify (iot-guard keyword engine).
3. **On-demand** (endpoint-triggered, bounded concurrency): `nmap -sn`, `arping` sweep, mDNS `avahi-browse`, OpenWrt/SecuBox HTTP fingerprint probe, mesh-peer sync (`/run/secubox/p2p.sock`).
4. New-MAC → `client_joined` event → nac history + existing HMAC webhooks. Default-quarantine policy preserved.

### 4.4 Actions — unify existing

`nac` keeps `inet secubox_nac` sets (lan_allowed/iot_zone/guest_zone/quarantine_zone/blocked). mac-guard's whitelist/blacklist fold into `allow_state` → driving `blocked` (deny) / `lan_allowed` (allow); the separate `inet secubox_mac_guard` table is **retired** (its elements migrated into `secubox_nac` sets at cutover). Ban, quarantine, parental unchanged. No VLAN/Tor/mesh (Project C).

### 4.5 API + retirement redirects

- `nac` gains the absorbed endpoints: `/vendors`, `/scan`, `/probe/openwrt[/{ip}]`, `/mdns`, `/groups*`, `/export/{json,csv}`, `/mesh/peers`+`/mesh/sync`, device-type/risk filters on `/clients`.
- Retired modules' `/api/v1/{mac-guard,device-intel,iot-guard}/*` → **thin redirect** to the nac equivalent (301 or in-aggregator proxy) during the deprecation window, then removed with the packages.
- **Auth-gate** the currently-open `/status` on device-intel/iot-guard/network-anomaly (they must require the same JWT/session as nac) — security fix folded in.
- All handlers plain `def` (aggregator in-process rule); scans/probes run in the background task or a threadpool, never inline.

### 4.6 WebUI

`nac`'s existing 8-view LuCI-style webui is the home. Extend the clients view with `oui_vendor` / `device_type` / `risk_level` columns + fingerprint badges (OpenWrt/SecuBox), add a groups view and an export button. Retired modules' `www/<name>/` removed. Keep the Client Guardian brand + C3BOX palette.

## 5. Live-board migration / retirement (delicate)

All 5 are aggregator-mounted (in-process). Sequence, data-preserving + reversible:

1. Ship new `secubox-nac` (SQLite store + absorbed libs + discovery). postinst runs idempotent import of the 3 legacy stores.
2. Restart the aggregator once → nac serves the unified store; verify (277+3 merged, webui, actions).
3. Flip `aggregator.toml` + nginx: the 3 retired module paths redirect to nac; keep the retired modules mounted only long enough to serve redirects (or drop them and let nginx 301).
4. After the redirect window proves clean, remove `secubox-mac-guard`/`secubox-device-intel`/`secubox-iot-guard` packages (a follow-up), archiving their legacy stores.

Rollback at any step: legacy stores untouched; re-enable the old modules in aggregator.toml.

## 6. Error handling / constraints

- **Fail-safe discovery**: a failing source (missing ISC leases, no nmap) degrades to the others; never crashes the loop or the handler.
- **Migration safety**: import is idempotent + additive; a corrupt legacy file is skipped (logged), never aborts boot.
- **SQLite concurrency**: single-process aggregator; WAL + short transactions; the discovery background task is the only writer, handlers read.
- **Aggregator SPOF**: every handler plain `def`, all scanning off the request path (#808).
- **Perms**: `devices.db` `0640 secubox:secubox`; nft calls unchanged (nac already does them); no `/run`/`/etc/secubox` parent perm changes.
- **MAC canonicalisation**: one function, lowercase, colon-separated — applied on every ingest so the 4 casings converge.

## 7. Tests

- **Store/migration**: 277+3 legacy rows → merged `devices.db` with per-column best-value; re-run = no-op; corrupt legacy file skipped; MAC casing normalised.
- **Discovery merge**: dnsmasq + ISC + ARP fixtures dedup by MAC into one row with correct `source`.
- **Enrichment**: OUI vendor lookup, device-type/risk classify, OpenWrt-fingerprint parse — unit tests with fixtures.
- **Actions**: zone assign / ban / allow-deny → correct nft set membership (nft mocked); quarantine round-trip.
- **API**: absorbed endpoints; retired-path redirects resolve to nac; `/status` now auth-gated (401 without token) on the 3 formerly-open modules.
- **WebUI**: manual (vendor/type/risk columns, groups, export) + a structural check that retired webuis are gone.

## 8. Séquencement (pour le plan)

1. **SQLite store + migration lib** (schema, `device_store`, idempotent import, MAC canonicalise) — standalone, testable.
2. **Unified discovery pipeline** (dnsmasq+ISC+ARP merge + enrich, background task, double-cache) writing the store.
3. **Absorbed enrichers** (OUI vendor, OpenWrt/mDNS fingerprint, device-type+risk classify, groups/export, mesh-sync) as libs + endpoints.
4. **Actions unify** (fold mac-guard allow/deny into nac zones/nft; migrate its set elements).
5. **API redirects + auth-gate** (retired paths → nac; close the open `/status`).
6. **WebUI** (extend nac views; remove retired webuis).
7. **Packaging/retirement** (aggregator.toml + nginx flip; changelog; retired-package removal as a gated follow-up).

## 9. Risques

- **Retiring 3 live in-process modules**: mitigated by redirect window + reversible aggregator.toml flip + legacy stores kept until package removal.
- **mac-guard 277-device migration**: the real inventory; migration must be lossless (per-column best-value + history preserved). Tested.
- **SQLite in a single-process aggregator**: fine with WAL + one writer; must keep handler queries short (indexed) so no handler stalls the shared loop.
- **Scope creep toward triage**: VLAN/Tor/mesh explicitly out (Project C); the zone/policy seam is left ready but unbuilt.
- **Cast diagnostics orphaning**: splitting it out must not silently drop a feature someone uses — ship it as a tiny standalone tool or explicitly confirm removal.
