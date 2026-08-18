<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Tracking v2 — Layered Block / Poison / Anonymize

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox` (+ small wires into `secubox-dns-guard`)
- **Status:** Design approved, pending implementation plan
- **Related:** `social_graph`/`social.py` cartography, `escalate.py` (#527),
  `autolearn`, `protective_mode.py`, `ad_ghost.py`

---

## 1. Goal

Give LAN clients behind the SecuBox transparent WAF a privacy layer that:

1. **Minimises external attack surface** — blocks pure trackers at three depths
   (DNS refuse → exclusive-IP nft-drop → HTTP 204).
2. **Defeats profiling without breaking sites** — trackers that are load-bearing
   (or whose blocking would reveal us as a blocker) are *poisoned*: the client
   presents a **stable fabricated identity** the target accepts, so the tracker
   builds a coherent profile of a person who does not exist.
3. **Anonymises the residue** — always-on header hygiene (DNT/GPC, strip
   operator/carrier headers) on every flow.

Derived from operator intent: *"supprimer tous les accès externes d'une page
pour n'avoir que les accès au site demandé… utiliser les domaines des cookies
traceurs pour blacklister… corréler les IPs banned"* (the block/surface side)
and *"cookies rémanents… contenu fake mais accepté par la cible… faire du bruit…
anonymiser et rendre silencieux la pertinence de mes traces"* (the poison side).

### Decisions locked during brainstorming

| Question | Decision |
|---|---|
| Scope | One combined spec, both block+poison |
| Default posture | Layered: **block pure, poison load-bearing, anonymize residue** |
| Poison identity | **Stable fake per (client, tracker)** — coherent fiction, no rotation |
| Noise | **Passive signal degradation only** — no new traffic (board-constrained) |
| IP correlation | **Exclusive-tracker IPs only**, CDN/cloud allowlisted |
| First-party-only | **Opt-in "Fort Knox" mode, per-site** (off by default) |

---

## 2. Architecture (Approach C)

A new pure-Python **brain** (`privacy.py`) holds all policy and the fake-identity
jar. One new thin **mitm addon** (`privacy_guard.py`) applies the brain's verdict
in the hot path. The **offline pipeline** reuses the existing hourly `autolearn`
timer and proven nft/DNS machinery — no new daemon.

```
┌── HOT PATH (mitm worker, per flow) ──────────────────────────────┐
│  privacy_guard.py  (NEW thin addon)                              │
│    request hook  → privacy.verdict(flow, client) → one of:       │
│        allow | block(204) | poison | anonymize | fortknox-block  │
│    response hook → rewrite Set-Cookie per the chosen fake jar    │
│         └─→ privacy.py  (NEW brain, pure Python, unit-tested)    │
│               • classify(host)      tracker? pure vs load-bearing│
│               • fake_jar(client,trk) stable fabricated identity  │
│               • verdict(...)        the layered policy           │
│               • fortknox(site,host) same-registrable-domain?     │
│               • reads: learned-trackers.txt, exclusive-ip set,   │
│                        cdn-allowlist, filters.json toggles       │
└──────────────────────────────────────────────────────────────────┘
            ▲ reads lists                       │ records observations
            │                                   ▼
┌── OFFLINE PATH (hourly autolearn timer / existing store) ────────┐
│  social_graph + store.py   → observe 3rd-party tracking cookies  │
│  autolearn (EXTENDED)       → learned-trackers.txt               │
│                               + cookie-derived blacklist (NEW)    │
│                               + exclusive-tracker-IP set (NEW)    │
│  escalate.py (EXTENDED)     → nft-drop exclusive-tracker IPs      │
│  dns-guard feed (NEW wire)  → refuse blacklisted domains at DNS   │
└──────────────────────────────────────────────────────────────────┘
```

### Files

**New**
- `mitmproxy_addons/privacy_guard.py` — request/response hooks, applies verdict only.
- `secubox_toolbox/privacy.py` — brain: classify, jar, verdict, fortknox, list loaders.
- `tests/test_privacy.py`, `tests/test_privacy_autolearn.py` — unit + offline tests.
- `www/privacy/` (or a tab in the existing toolbox webui) — Privacy / Anti-Track panel.
- `data/cdn-allowlist.txt` — Cloudflare/Fastly/Akamai/Google/AWS published ranges.

**Extended**
- `sbin/secubox-toolbox-autolearn` — two new outputs (blacklist signal, exclusive-IP set).
- `secubox_toolbox/escalate.py` — consume `exclusive-tracker-ips.txt` → nft sets with TTL.
- `secubox_toolbox/social.py` / `social_graph.py` — flag cross-site tracking-cookie setters.
- `secubox_toolbox/filters.py` — new toggle defaults (Section 5).
- small `dns-guard` sync hook (write blacklist into its blocklist input + reload).
- `systemd/secubox-toolbox-mitm.service` — add `-s …/privacy_guard.py`.

**Untouched / still authoritative**
- `social.py` cartography schema, `store.py` core tables, nft `secubox_blacklist`
  `blacklist_v4/v6` sets, consent tiers r0/r1/r2.

### Boundary

`privacy_guard.py` performs **no** classification or state math — it only applies
`privacy.verdict()`. All subtle logic (fake-id jar, layered verdict, fortknox) lives
in `privacy.py`, testable without mitmproxy. The hot path does only in-memory
dict/regex lookups; all resolve/correlate work is offline in `autolearn`.

---

## 3. Layered verdict (`privacy.verdict(flow, client)`)

Evaluated per request; first match wins.

```
1. FORT KNOX armed for this site?  (site ∈ fortknox_sites)
   ├─ host NOT same-registrable-domain as the page's site → BLOCK (any 3rd-party)
   └─ else (first-party)                                   → ALLOW

2. Is host a tracker?  classify(host)
   ├─ NOT a tracker        → ALLOW (+ anonymize headers if privacy_anonymize)
   ├─ PURE tracker         → BLOCK  (204 at HTTP; also DNS-refused / maybe nft-dropped)
   └─ LOAD-BEARING tracker → POISON
```

### Classification — pure vs load-bearing

A host is a **tracker** if it matches the static `_TRACKER` patterns **or**
`learned-trackers.txt`.

- **PURE** (safe to block): no first-party role — never observed serving
  non-tracking content, request looks like a beacon (analytics/collect/pixel path,
  or no page-critical `Accept: text/html|script` dependency). `autolearn` promotes
  a host to PURE only after it is confirmed beacon-only across ≥2 sites.
- **LOAD-BEARING** (poison, never block): also serves needed content (tag managers,
  CDN-hosted JS), or blocking it has broken pages before.
- **Default-unknown tracker → POISON.** Fail-safe: when in doubt, poison (never
  breaks a page), never block.

### POISON action

- **Request hook:** replace outbound `Cookie` values for that tracker with the
  client's stable fake identity from the jar (forge, not drop → request accepted).
- **Passive signal degradation:** referer → site root; fake-but-consistent
  `Sec-CH-UA`/locale/screen hints; pin `DNT:1`, `Sec-GPC:1`.
- **Response hook:** rewrite the tracker's `Set-Cookie` so the *next* request keeps
  presenting the same fake id (jar persists it); drop re-identification cookies that
  don't match the jar.

### ANONYMIZE (always-on hygiene, all flows incl. allowed first-party)

Strip operator/carrier headers (existing `protective_mode` list: MSISDN, x-acr,
x-wap-*, forwarded, etc.), pin DNT/Sec-GPC. Active whenever `privacy_anonymize`.

### Relationship to `protective_mode.py`

`protective_mode`'s `spoof` (drop-cookie) becomes the **anonymize** primitive; the
new **poison** verdict supersedes drop for load-bearing trackers. `protective_mode`
is refactored to call `privacy.py` rather than carry its own host list — one source
of truth for tracker patterns.

---

## 4. Stable-fake-identity jar

One persistent fabricated identity per `(client, tracker)` that looks real, never
rotates, and never derives from the client's real data.

### Generation — deterministic, no stored secret in clear

```
fake_id(client, tracker, cookie_name) =
    HMAC( server_seed , client_mac_hash || registrable(tracker) || cookie_name )
    → shaped to the cookie's observed format
```

- `server_seed`: `/etc/secubox/secrets/privacy-jar.key`, mode 0600, owner
  `secubox-toolbox`, generated once in postinst. Not in TOML, not in git (CSPN
  secrets rule).
- **Deterministic ⇒ stateless to compute.** Same inputs always yield the same id,
  so the identity is "rémanent" across worker restarts and identical across all 4
  R3 workers with **no shared state**.
- `client_mac_hash` is the already-hashed client id from `store.py` (never raw MAC).
- Different `client_mac_hash` in the HMAC ⇒ no cross-client leakage.

### Format shaping — so the target accepts it

`privacy.py` carries a **format-profile table** keyed by cookie name/pattern
(`_ga` → `GA1.2.<int>.<int>`, UUID, base64 blob, `<ts>.<rand>`, …). It renders the
HMAC output into the right shape so the value is syntactically valid. Unknown
cookie → generic opaque token matching the observed length/charset. Observed shapes
come from `social_graph`'s existing passive cookie observation (names + formats
only, never real values).

### Persistence & overrides

The deterministic path needs no storage. A small new `privacy_jar` table in the
existing `toolbox.db` is used **only** for exceptions: a server-assigned id we must
echo back verbatim (we store *our* fake mapping, never the real one), or an operator
pin/reset. TTL-purged like other tables; `reset_client()` (RGPD) also wipes that
client's jar rows.

### Failure mode

If `privacy-jar.key` is missing/unreadable, fall back to **anonymize-drop** (old
spoof) rather than emit a guessable/zero id — fail toward privacy, never toward a
weak fake.

---

## 5. Offline pipeline (in the hourly `autolearn` timer)

Produces three files the hot path / DNS layer read. No new daemon, no hot-path cost.
All writes atomic (temp + rename).

### 5.1 Cookie-derived blacklist signal (NEW)

Extend `social_graph` observation to flag a domain as a **tracking-cookie setter**
when, across `social_edges`/`social_nodes`, it:

- sets a third-party cookie (domain ≠ page registrable domain), **and**
- the cookie id is reused across **≥2 distinct sites** (cross-site correlation =
  the definition of a tracking cookie), **and**
- is set **pre-consent** (`pre_consent_hits` column already exists).

`autolearn` folds these into `learned-trackers.txt` tagged reason `cookie-xsite`.
This realises *"utiliser les domaines des cookies traceurs pour blacklister."*

### 5.2 Exclusive-tracker IP set (NEW)

For each learned tracker domain, resolve it (reuse `escalate._resolve_ips`) and
accumulate a `domain→IPs` map in `toolbox.db`. An IP qualifies for nft-drop **only
if**:

- every domain ever seen resolving to it is a known tracker (no first-party
  co-resident), **and**
- it is **not** in the CDN/cloud allowlist (`data/cdn-allowlist.txt`:
  Cloudflare/Fastly/Akamai/Google/AWS published ranges, refreshable).

Qualifying IPs → `exclusive-tracker-ips.txt`. `escalate.py` (extended) adds them to
the existing `inet secubox_blacklist blacklist_v4/v6` sets **with a TTL** (default
4h, auto-renewed while still qualifying) so a reassigned IP ages out. Every
add/remove is appended to `/var/log/secubox/audit.log` (reason + TTL) — auditable
and reversible per CSPN.

### 5.3 DNS-guard wiring (NEW, defense-in-depth)

A small sync step writes the learned blacklist into `secubox-dns-guard`'s blocklist
input and reloads it, so pure trackers are **refused at DNS** before a connection is
attempted — covers flows that bypass the proxy. Domains remain HTTP-204'd by
`privacy_guard` too (belt and suspenders).

### Layered block, three depths

DNS refuse → exclusive-IP nft-drop → HTTP 204. A pure tracker hits whichever fires
first; **load-bearing trackers hit none** (poisoned, not blocked).

### Guardrails (CSPN / board safety)

- CDN allowlist is the hard gate against collateral on shared IPs.
- Every list write atomic; every nft/DNS mutation audit-logged with reason + TTL.
- Master `privacy_enforce` toggle disables **all** active blocking/dropping
  (observe-only) without a restart.

---

## 6. Config, UI, error handling, tests

### 6.1 Config (`/etc/secubox/toolbox/filters.json`, hot-reloaded, default-safe)

| Key | Default | Effect |
|---|---|---|
| `privacy_enforce` | `false` | master switch; off = observe-only |
| `privacy_poison` | `true` | forge stable fake id for load-bearing trackers vs anonymize-drop |
| `privacy_anonymize` | `true` | always-on header hygiene (DNT/GPC, strip operator headers) |
| `privacy_ip_drop` | `false` | enable exclusive-tracker IP nft-drop |
| `privacy_dns_feed` | `true` | sync learned blacklist into dns-guard |
| `fortknox_sites` | `[]` | per-site first-party-only opt-in list |

`privacy_enforce` ships **off** → feature deploys dark, soaks in observe-only, then
is armed. `privacy_ip_drop` separately gated (highest-collateral action).

### 6.2 UI — "Privacy / Anti-Track" panel (toolbox webui)

Per-client tracker cartography (already collected); learned blacklist with reasons
(`cookie-xsite`, `opgrade`, `threat-intel`); exclusive-IP drop list with TTLs;
poison counters (fake identities served); Fort-Knox per-site arm/disarm. Reads route
through the aggregator like every other module; write/toggle actions POST to the
toolbox API. No new socket.

### 6.3 Error handling — fail toward privacy, never toward breakage

- Missing `privacy-jar.key` → anonymize-drop fallback.
- `learned-trackers.txt` / IP set / CDN allowlist unreadable → treat as empty (no
  false blocks), log once.
- Any exception in `verdict()` → `allow` + anonymize (never 500 a client's page);
  counter incremented.
- DNS-guard / nft sync failure → audit-log, leave previous list in place (atomic
  writes ⇒ no partial state).
- `privacy_guard` never blocks the worker loop — in-memory lookups only; resolve/
  correlate is offline.

### 6.4 Tests

- `privacy.py` units (no mitmproxy): classify pure vs load-bearing; `verdict()` each
  branch incl. Fort-Knox; jar determinism (same inputs→same id; different client→
  different id; format shaping per cookie pattern); fail-safe paths.
- `autolearn`: cookie-xsite detection (id reused ≥2 sites, pre-consent); exclusive-IP
  gate (first-party co-resident → excluded, CDN range → excluded); atomic writes.
- Integration: synthetic flow through `privacy_guard` hooks — cookie forged not
  dropped, headers anonymized, 204 on pure tracker.
- CSPN: audit entry for every nft/DNS mutation with reason + TTL; `reset_client`
  wipes jar rows.

---

## 7. Rollout

1. Ship with `privacy_enforce=false` (observe-only). Verify cartography + learned
   lists populate; no client impact.
2. Soak window; review the learned blacklist and would-be exclusive-IP set in the UI
   for false positives.
3. Arm `privacy_enforce=true` (poison + anonymize + DNS feed + HTTP block).
4. Separately arm `privacy_ip_drop=true` after the exclusive-IP set looks clean.
5. Fort-Knox is per-site opt-in throughout — never auto-armed.

Deploy respects the board rules: no mass daemon restart (only
`secubox-toolbox-mitm.service` reload for the new addon), shared `/…/secubox`
parents stay 0755, secret in `/etc/secubox/secrets/` 0600.

---

## 8. Out of scope (future specs)

- Active decoy traffic generation (bandwidth/CPU cost, IP-reputation risk).
- Rotating / pooled-k-anonymity identities (chose stable-per-client).
- Default-on first-party isolation with auto-grown allowlist.
