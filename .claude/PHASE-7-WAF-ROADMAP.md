<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Phase 7 — WAF Active Enforcement + Threat Reduction

*Created 2026-06-05 · ref to be filed as issue #498*

---

## Why

Currently the mitm WAF (`secubox_waf.py` in mitmproxy LXC) **detects**
threats (regex pattern match → category/severity, threat_counts dict per
IP, BAN_THRESHOLD / BAN_WINDOW logic) but its only enforcement is :

* warn pages served back to the offender (HTML 200 with severity HTML)
* stats counter increments
* 508 page for self-loop guard

**Nothing drops the offender at the network layer.** The result :

* `threat_counts` dict accumulates entries per unique attacker IP forever
  (until they age out of BAN_WINDOW, then prune in Phase 6.J)
* Attackers keep flooding HTTPS — every probe costs WAF a TLS handshake +
  regex run + log write
* CrowdSec catches SSH brute-force + log-parseable HTTP attacks but
  doesn't see what only mitm WAF sees (per-route signature match)
* Live observation 2026-06-05 : mitm WAF saturated 800+ idle connections
  while serving real and bot traffic indistinguishably

We need : **WAF detection → kernel drop**.

---

## Quick enhancement (2-3 days, low risk)

### Bridge mitm WAF → CrowdSec local API

```
[mitm WAF detects threat for IP X over BAN_THRESHOLD]
        ↓
[POST http://localhost:8080/v1/decisions]
        ↓
[CrowdSec adds decision : ban X for Y hours, reason "waf-pattern-match:cat"]
        ↓
[crowdsec-firewall-bouncer reads + adds nft drop element]
        ↓
[Subsequent connection attempts from X → DROP in netdev ingress, no TCP handshake]
```

### Implementation

* New helper in secubox_waf.py :

  ```python
  def _ban_via_crowdsec(ip: str, reason: str, hours: int = 4):
      try:
          httpx.post(
              "http://127.0.0.1:8081/v1/decisions",  # CrowdSec local API
              json={
                  "type": "ban", "scope": "Ip", "value": ip,
                  "duration": f"{hours}h", "reason": f"waf:{reason}",
                  "origin": "secubox-waf",
              },
              headers={"X-Api-Key": _CROWDSEC_API_KEY},
              timeout=1.0,
          )
      except Exception as e:
          ctx.log.warn(f"cs-bridge fail for {ip}: {e}")
  ```

* In `request` hook after threat detected and `count >= BAN_THRESHOLD` :
  call `_ban_via_crowdsec(client_ip, cat, hours=4)`.

* CrowdSec config : add `secubox-waf` as a valid origin in
  `/etc/crowdsec/local_api_credentials.yaml`, generate API key with
  `cscli bouncers add secubox-waf`.

* nft already has the bouncer chain (`table ip crowdsec`) — no work needed.

### Telemetry side-effect

* mitm WAF stats grow a `bans_pushed` counter
* CrowdSec dashboard at `/api/v1/crowdsec/decisions` lists who's banned
* Decisions appear in admin webui (already wired through `/admin/clients/rich`
  via mac_hash, can add an IP-bans card)

---

## Mid-term enhancement (1-2 weeks)

### Active rate-limiting at nft layer (pre-mitm)

Add a `meter` rule in `inet filter input` before the WAF backend chain :

```nft
table inet filter {
    set rate_limit_4 {
        type ipv4_addr
        flags dynamic
        timeout 5m
        size 65535
    }
    chain input {
        # Pre-filter : drop IPs that exceed 30 conn/s for 30s
        tcp dport { 80, 443 } meter rate_limit { ip saddr limit rate 30/second burst 50 packets } accept
        tcp dport { 80, 443 } add @rate_limit_4 { ip saddr timeout 5m } counter drop
        # ... existing rules ...
    }
}
```

* Cheap : kernel-side, no Python overhead
* Catches the slowloris/TCP-only scanners that bypass CrowdSec log parsing
* Doesn't trigger on legitimate browsers (TCP from real browsers stays
  well under 30 conn/s per IP)

### WAF dashboard — live threat map

Card in admin webui (`/admin/` Threats tab) showing :

* Top 20 attacker IPs (last 24h) with country + ASN + first/last seen
* Top 10 attack patterns matched (XSS, SQLi, LFI, ...)
* Geo map (ASCII or SVG) of attacker origins
* Live counter : decisions added in last hour
* Manual ban button (sysadmin can ban an IP for N hours via webui)
* Backed by SQLite : new `threats` table with (ts, ip, category, severity, host, path)

### Honeypot routing for known bot signatures

Specific paths frequently hit by scanners :

* `/wp-admin`, `/.env`, `/phpmyadmin`, `/.git/config`, `/server-status`
* Route them to a sinkhole `127.0.0.1:9999` that :
  * Returns 200 OK with a large fake JSON (slowloris bait, 60s response)
  * Logs the attempt + auto-bans

---

## Long-term proper (1-2 months)

### eBPF-based filtering at kernel level

mitm WAF in Python = 30%+ CPU at scale + connection pool issues. Replace
the hot-path with eBPF :

* `tc ingress` filter on lan0/wan0 that runs an XDP/eBPF program
* Program checks source IP against a BPF map (the ban list, ~10k entries)
* Drop in the kernel before tcp/443 even hits HAProxy
* Python WAF kept for deep inspection (Layer 7 pattern matching) ; eBPF
  takes care of Layer 3/4 enforcement

Tooling : Cilium / bpftrace / falco-style detector → BPF map writes.

### Replace mitm WAF with ModSecurity in HAProxy

mitmproxy is NOT a WAF tool — it's a debugging proxy with WAF-ish addons.
A real WAF :

* HAProxy → modsecurity-nginx → OWASP CRS rules → backend
* CRS catches OWASP top-10 by default
* SecuBox can ship custom rules in `/etc/modsecurity/secubox-rules.conf`
* Real benchmarks : ModSec ~5x throughput of Python mitm at same CPU

### Global threat intel federation

* Push our local bans to CrowdSec Hub (community blocklist)
* Pull AlienVault OTX + Spamhaus DROP + tor exit nodes into nft sets
* Daily cron `cscli decisions import` from public feeds

---

## Acceptance criteria for Phase 7 (minimum viable)

1. Attacker IP that triggers BAN_THRESHOLD is dropped at nft level within
   30s of the offending request.
2. mitm WAF `threat_counts` dict stays under 200 entries during a sustained
   scanner attack (was 1500+ before).
3. `cscli decisions list` shows new entries with `origin=secubox-waf`.
4. Admin webui Threats tab shows live attacker top-20 + manual ban button.
5. Documented in wiki page `WAF-active-enforcement`.

---

## Dependencies / known issues

* CrowdSec local API needs HTTP listener (currently exposed on
  127.0.0.1:8081 by default — fine for in-LXC mitm)
* nft bouncer chain `table ip crowdsec` already exists — verified live
* No new dependencies (httpx already in mitm Python env)

---

## File this as

GitHub issue with title :
`Phase 7 — WAF active enforcement (mitm → CrowdSec bridge + nft drop)`
Label : `security` `migration` `wip`
Initial assignee : Gérald Kerma
