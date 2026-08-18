<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2b: Enforcement depth (DNS-refuse + exclusive-IP nft-drop)

- **Date:** 2026-06-17
- **Package:** `secubox-toolbox` (+ `secubox-dns-guard` blocklist file)
- **Issue:** #633
- **Status:** Design approved, pending implementation plan
- **Parent spec:** `docs/superpowers/specs/2026-06-17-anti-tracking-v2-design.md` (§5.2, §5.3)
- **Builds on:** Plan 1 (filter toggles, the block/poison split) and Plan 2a
  (which produces `pure-trackers.txt`, the hard-block allowlist this plan enforces).

---

## 1. Goal

Add the two deeper hard-block layers below the HTTP-204 layer, both driven by the
**pure-trackers** list so they stay consistent with Plan 1's block-vs-poison split:

1. **DNS-refuse** — feed the pure-tracker domains into `secubox-dns-guard` so they
   never resolve (cheapest block; also covers flows that bypass the proxy).
2. **Exclusive-IP nft-drop** — resolve pure-tracker domains to IPs and drop the IP
   in the existing `inet secubox_blacklist` set, but **only** when the IP is not in
   a curated CDN/cloud allowlist (so we never blackhole shared infrastructure).

Load-bearing trackers are never touched here — they are poisoned at HTTP by Plan 1.
A domain is hard-blocked at any depth only if it is confirmed **pure**.

### Decisions locked during brainstorming

| Question | Decision |
|---|---|
| Feed source | **DNS = pure-trackers; IP = pure + exclusivity + CDN gate** (not the full learned list) |
| CDN allowlist | **Static shipped `cdn-allowlist.txt`**, manual refresh on release (no runtime fetch) |
| Dark gating | All enforcement requires **`privacy_enforce=true` AND** its specific toggle |
| Where it lives | IP-drop extends `escalate.py`; DNS feed is a step in `autolearn` |

### Dark-gating correction (important)

Plan 1 ships `privacy_dns_feed=true` but `privacy_enforce=false`. To keep the
"deploys dark, arm later" guarantee, **both** new enforcement paths additionally
require the master switch:

- DNS feed runs iff `privacy_enforce && privacy_dns_feed`.
- IP-drop runs iff `privacy_enforce && privacy_ip_drop` (already `false` by default
  — double-gated).

No new toggles are added; Plan 1's `filters.json` keys are reused.

---

## 2. Architecture

```
sbin/secubox-toolbox-autolearn   (hourly — Plan 2a, EXTENDED)
   └─ after writing pure-trackers.txt:
        if privacy_enforce and privacy_dns_feed:
            ip_dns.feed_dns_guard(pure_hosts)   → write dns-guard blocklist + reload

secubox_toolbox/ip_dns.py        (NEW pure helpers, unit-tested)
   • load_cdn_allowlist(path) -> list[ipaddress network]
   • ip_in_allowlist(ip, networks) -> bool
   • exclusive_tracker_ips(pure_hosts, resolve, allow_nets) -> set[str]
   • dns_guard_lines(pure_hosts) -> list[str]   (blocklist.txt format)

secubox_toolbox/escalate.py      (timer — Phase 13.D, EXTENDED)
   └─ if privacy_enforce and privacy_ip_drop:
        ips = ip_dns.exclusive_tracker_ips(pure_hosts, _resolve_ips, allow_nets)
        for ip in ips: _nft_add_blacklist(ip)   (existing fn, TTL + audit)

data/cdn-allowlist.txt           (NEW shipped data)
   • curated CIDR ranges: Cloudflare / Fastly / Akamai / Google / AWS / Azure
```

**Files**
- **New:** `secubox_toolbox/ip_dns.py`, `tests/test_ip_dns.py`, `data/cdn-allowlist.txt`.
- **Extended:** `secubox_toolbox/escalate.py` (consume pure list → exclusive-IP drop),
  `sbin/secubox-toolbox-autolearn` (DNS feed step), `debian/rules` (ship the data
  file), `debian/changelog`.
- **Reused:** Plan 1 toggles; the existing nft `blacklist_v4/v6` sets + TTL;
  `escalate._resolve_ips`/`_nft_add_blacklist`; `secubox-dns-guard`'s blocklist file.

**Boundary.** `ip_dns.py` is pure (no nft, no DNS, no file writes): exclusivity takes
a `resolve` callable and pre-loaded allow-networks; the DNS-feed formatter returns
lines. `escalate.py` injects the real `_resolve_ips` and does the nft writes;
`autolearn` does the dns-guard file write + reload. This keeps the risky network/nft
work in the existing audited scripts and the logic unit-testable.

---

## 3. CDN/cloud allowlist (`data/cdn-allowlist.txt`)

- One CIDR per line (`#` comments), covering the major shared providers:
  Cloudflare, Fastly, Akamai, Google, Amazon AWS/CloudFront, Microsoft Azure.
- Parsed with the stdlib `ipaddress` module into a list of `ip_network` objects;
  membership is a linear scan (the list is small — hundreds of CIDRs — and runs in
  the hourly/timer job, not the hot path).
- **Refresh:** manual, on package release (providers publish range JSONs; the
  maintainer regenerates the file). Documented in the file header. No runtime fetch.
- Shipped via `debian/rules` to `/usr/lib/secubox/toolbox/data/cdn-allowlist.txt`
  (alongside the package); `ip_dns.load_cdn_allowlist` reads that path, env-overridable
  for tests.

---

## 4. Exclusive-IP nft-drop (`escalate.py` extension)

`exclusive_tracker_ips(pure_hosts, resolve, allow_nets)`:
- For each host in `pure_hosts`, call `resolve(host)` → list of IPs.
- An IP qualifies iff it is **not** in any allow-network (`ip_in_allowlist` False).
- Return the set of qualifying IPs.

In `escalate.py`, gated by `privacy_enforce && privacy_ip_drop`:
- Read `pure-trackers.txt` (env-overridable path), load the CDN allowlist once,
  call `exclusive_tracker_ips` with the existing `_resolve_ips`, and `_nft_add_blacklist`
  each qualifying IP (existing function: `inet secubox_blacklist`, `blacklist_v4/v6`,
  `ESCALATE_TTL` default 4h, auto-renews each run while the host stays pure).
- Every add is audit-logged via the existing escalate audit path
  (`/var/log/secubox/audit.log`), reason `pure-tracker-ip`.

**Safety:** pure-only source means we never IP-drop a poisoned/load-bearing tracker;
the CDN allowlist means we never drop a shared-infra IP even if a pure tracker happens
to resolve there. TTL means a reassigned IP ages out automatically.

---

## 5. DNS-refuse feed (`autolearn` step)

`dns_guard_lines(pure_hosts)` returns the blocklist lines in `secubox-dns-guard`'s
documented format (one domain per line). In `autolearn`, immediately after the
`pure-trackers.txt` write, gated by `privacy_enforce && privacy_dns_feed`:
- Write the pure-tracker domains into `/var/lib/secubox/dns-guard/blocklist.txt`
  (env-overridable path) **atomically** (temp + `os.replace`), preserving any
  non-secubox entries is out of scope — the feed owns a dedicated section/file per
  the dns-guard integration (confirm during implementation whether dns-guard reads a
  single blocklist or a drop-in; write to the secubox-owned input it documents).
- Trigger dns-guard's reload (its documented mechanism — file-watch or a reload
  call; confirm during implementation). Reload failure is logged, non-fatal.

**Fail-safe:** any error (file unwritable, reload fails) logs and leaves the previous
dns-guard list intact (atomic write guarantees no partial state). Never abort the
autolearn run.

---

## 6. Config, error handling, tests

- **Config:** reuse Plan 1 `filters.json` toggles. The offline scripts read them via
  `secubox_toolbox.filters.get_filters()`. Master gate `privacy_enforce` checked in
  both paths. No new keys.
- **Error handling:** `ip_dns` functions catch nothing internally beyond input
  parsing (pure logic); the scripts wrap the new steps in try/except so a failure
  never aborts the existing escalate/autolearn behavior. A missing `pure-trackers.txt`
  → empty set → no drops / empty feed (fail toward fewer blocks). A malformed CDN
  allowlist line is skipped (logged once).
- **Tests (`tests/test_ip_dns.py`, no network/nft):**
  - `load_cdn_allowlist` parses CIDRs, skips comments/blank/malformed lines.
  - `ip_in_allowlist`: an IP inside a shipped range → True; outside → False; IPv6.
  - `exclusive_tracker_ips` with a stub `resolve`: pure host → IP not in CDN → in
    result; pure host → IP in CDN range → excluded; multiple hosts/IPs deduped.
  - `dns_guard_lines`: returns sorted unique domains in the expected format.
  - gating: a small test (or escalate/autolearn integration) asserting that with
    `privacy_enforce=false` no nft/DNS action is taken (the helper is pure, so this
    is asserted at the script-integration level the way Plan 2a's subprocess test does).

---

## 7. Rollout

Ships dark with Plan 1/2a: nothing enforces until `privacy_enforce=true`. Arm order
recommended: soak observe-only → arm `privacy_enforce` (poison + anonymize + DNS
feed of pure trackers) → separately arm `privacy_ip_drop` once the exclusive-IP set
looks clean in review. Deploy respects board rules: no shared-`/…/secubox`-parent
mode changes; nft adds are TTL'd + audited; the CDN allowlist is the collateral gate.

---

## 8. Out of scope

- Runtime auto-refresh of the CDN allowlist (manual refresh chosen).
- `#social` top-5 UI + `#filtres` bypass panel + ignore_hosts seed → Plan 2c/2d.
- Any change to the learning signals (Plan 2a) or the hot-path engine (Plan 1).
