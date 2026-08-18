<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WAF engine migration — feasibility analysis (#662 follow-on)

> Status: ANALYSIS ONLY. No code, no plan, nothing touched on the live WAF.
> Question asked: *"can the #662 Go-engine technique be adapted to the WAF?"*
> Date: 2026-06-18. Sibling of `2026-06-18-mitm-engine-migration-analysis.md`.

## TL;DR

Technically yes — and the hardest part of #662 (cert forging / transport / CA
trust) **does not exist** for the WAF, because HAProxy already terminates TLS and
hands mitmproxy cleartext. But the right move is **NOT** to hand-roll a Go WAF the
way we hand-rolled the R3 engine. The WAF's decision logic is security-critical and
synchronous (block-before-forward), which is exactly where bespoke code is most
dangerous. The recommendation is to **ADOPT** a vetted engine (OWASP Coraza + CRS v4)
rather than port our bespoke regex rules, and — if the non-WAF addons can be
relocated — to **retire the in-path mitmproxy entirely** via HAProxy's SPOA, which
also eliminates the WAF's worst failure mode (the single-backend SPOF that "downs all
inspected vhosts").

Crucially, **the perf premise is weaker than #662's.** #662 had a measured CPU/latency
ceiling on the R3 tunnel. The WAF is *not* currently throughput-bound. So the
justification here is **resilience + security coverage + fewer band-aids**, not raw
speed. Be honest about that when deciding whether it's worth the risk.

---

## 1. What the WAF actually is (grounded, repo + live board)

- **Reverse-proxy inspector**, not a transparent/forward MITM like R3. Path:
  external client → **HAProxy `*:443 ssl` (TLS 1.3 termination)** → cleartext HTTP →
  **mitmproxy `--mode regular` in the `mitmproxy` LXC (`10.100.0.60:8080`)** →
  backend vhosts. HAProxy rewrites to absolute-form (`set-uri http://Host/path`) so
  the forward-proxy accepts it.
- **No TLS / no cert machinery on the WAF side.** mitmproxy never decrypts, never
  forges, holds no CA. (This removes the entire hard half of the #662 port.)
- **Hot path (every request), deterministic:** host→backend dict lookup
  (live-reloaded from `/srv/mitmproxy/haproxy-routes.json`, 255 entries, 187 routed
  through inspection), then a single linear **regex scan** over
  `path+query+body+UA` against `waf-rules.json` (~90+ patterns: sqli/xss/cmdi/
  traversal/ssrf/xxe/log4shell/scanners/cve…), first-match-wins. Block = set
  `flow.response` to short-circuit → **synchronous, decide-before-forward**.
- **Enforcement is graduated and mostly soft:** 1st/2nd hit → 403 *warning page*;
  3rd hit in 300 s (`BAN_THRESHOLD=3`) → ban via **CrowdSec LAPI** (`POST /v1/alerts`,
  JWT watcher) → `crowdsec-firewall-bouncer` drops at nft. The CrowdSec POST is a
  **synchronous `urllib` call (~up to 4 s) inside the request hook** — the clearest
  GIL/latency smell, trivially a goroutine in Go.
- **Stateful bits are small:** per-IP sliding-window dict (in-memory, lost on
  restart; hit 1500+ entries under attack). Everything else is stateless.
- **Three NON-WAF addons ride the same proxy:** `media_cache.py` (#607 disk cache for
  owned-vhost media), `cookie_audit.py` (RGPD Set-Cookie ledger, observational),
  and CDN **banner injection** (`response` hook, injects `<script>` before `</body>`
  on owned vhosts). These do **traffic transformation / caching** — a verdict-only
  WAF (SPOA) would not cover them; their fate must be decided (relocate, drop, or
  keep a thin in-path component).
- **Two synced package copies:** `packages/secubox-mitmproxy/` (canonical, 1193-line
  addon, CrowdSec bridge + watchdog + FastAPI control) and the legacy
  `packages/secubox-waf/` (968-line, ships `wafctl` + the LXC unit). Sync-lag is a
  known liability (`.claude/TODO.md`).

## 2. Live performance — the decisive datum

| Metric (gk2, read-only) | Value |
|---|---|
| mitmproxy | 11.0.2 / Py 3.11 / **single process, single asyncio loop** (no multi-core) |
| Request volume | **~3.6 req/s** sustained (mostly internet scanner probing) |
| WAF CPU | **~17–53% of ONE core** (clean Δ ≈ 17%); ~5050 CPU-s over 12 d, niced |
| Board load avg | ~3.5 on 4 cores — board near-saturated overall, WAF a minority |
| Inspected vhosts | 187 of 255 routes, **one `mitmproxy_inspector` backend** |
| Hardening band-aids | `MemoryMax=512M`, `RuntimeMaxSec=21600` (6 h forced restart), `http2=false`, loop-guard, `Connection: close` (FD-leak fix), nft pre-rate-limit, watchdog (lxc-restart on 3 probe fails) |

**Conclusion:** at today's load a rewrite is **not justified by throughput** — the
WAF isn't pegging its core. The real motivations are: (1) the **single-threaded
ceiling under attack/burst** (saturates ~7–10 req/s on the inspected path; a scan
flood serializes through one loop), (2) the **single-backend SPOF** — with
`waf_enabled`, *all* vhosts + the default route funnel through one inspector, so its
death = board-wide 503 (the watchdog only turns a multi-hour outage into a ~3-min
one), (3) the **resource pathologies** (FD/conn-pool leak, HTTP/2 memory drift)
papered over by restarts. The project's own `.claude/PHASE-7-WAF-ROADMAP.md` already
says it: *"mitmproxy is NOT a WAF tool… ModSec ~5× throughput of Python mitm."*

## 3. Why the #662 playbook only half-applies

| #662 (R3 anti-track) | WAF |
|---|---|
| Forward/transparent MITM, forges certs, CA trust, SO_ORIGINAL_DST — **hard** | Reverse proxy, **HAProxy already terminates TLS**, cleartext in — **easy** |
| Decisions can be **async** (poison cookies fire-and-forget) | Decisions are **synchronous** (block before forward) — can't sidecar the verdict |
| Feature-set was **bespoke** → hand-port justified | Detection is **generic WAF rules** → a vetted CRS exists → **adopt, don't port** |
| Bug = degraded browsing (annoying) | Bug = **outage of all vhosts OR a security bypass** — far higher bar |
| Clear measured perf ceiling drove it | **Not throughput-bound today** — weaker perf case |

So: transport is easier, but the part #662 deliberately kept in Python (the "risky
brain") **is** the WAF's core and is on the synchronous critical path. The lesson is
inverted: for R3 we built; for the WAF we should **adopt the engine** and only write
thin glue.

## 4. Options (build-vs-adopt)

**Option A — HAProxy + `coraza-spoa` + CRS v4 (RECOMMENDED, if addons relocatable).**
Keep HAProxy as-is; attach OWASP **Coraza** (CRS v4) as a **SPOA/SPOE agent**.
HAProxy sends each request to the agent, **blocks for the verdict**, applies
`http-request deny 403 if {var(txn.coraza.action) -m str deny}`. Pure-Go, clean
arm64 (`CGO_ENABLED=0`). **Retires the in-path mitmproxy → eliminates the SPOF**
(traffic no longer flows *through* the inspector; the agent is out-of-band, in-line
only for the verdict). Adopts a community-vetted ruleset instead of our bespoke
regex. *Gaps:* SPOA returns a **verdict only — no traffic transformation**, so
banner-injection / media-cache / cookie-audit must move elsewhere or be dropped.
*Risks:* `coraza-spoa` is **0.x (v0.7.2, 2026-05)**, no named prod adopters → pin +
benchmark on arm64; **HAProxy 3.1+ requires `mode spop`** for the SPOA backend →
check the board's HAProxy version before wiring.

**Option B — Go reverse-proxy embedding Coraza (`coraza/v3` `http.WrapHandler`).**
A single Go binary replaces mitmproxy *in-path* (`net/http/httputil.ReverseProxy` +
Coraza). Keeps the in-path model → can still do banner/cache/transformation, and
gets multi-core + bounded memory + no FD leak. Still **adopts** the engine + CRS;
only the proxy glue is bespoke. *Cost:* ReverseProxy footguns (bounded body
buffering, Content-Length resync, error/upgrade handling) need a real PoC test
suite; still an in-path component (SPOF remains, but a robust Go one).

**Option C — CrowdSec AppSec component (Coraza inline).** CrowdSec's AppSec
component *is* Coraza inline; since we already integrate CrowdSec (LAPI bridge), this
could deliver the inline WAF as a CrowdSec component and unify the stack. Worth
scoping against A.

**Option D — REJECT: hand-roll a Go WAF engine / port the bespoke regex rules.** The
"don't roll your own crypto" rule applies to WAF rulesets. Bespoke signatures miss
generic/0-day-class detection that CRS anomaly-scoring is built for, and carry a
permanent FP-tuning + CVE-tracking burden. Also reject the dead `spoa-modsecurity`
(ModSecurity v2, EOL 2024).

## 5. CSPN angle

The project targets ANSSI CSPN. Adopting **OWASP CRS v4** (a flagship, test-suite-
covered ruleset) is far more defensible for certification than bespoke regex, and a
formal SPOA verdict + an explicit **fail-open vs fail-close** SPOE policy is a clean,
auditable security-decision boundary. (Current bespoke WAF = warn-pages + 3-strike
CrowdSec ban; CRS gives graduated anomaly scoring with documented paranoia levels.)

## 6. Recommendation + gated next steps (NOT started)

**Recommendation:** ADOPT Coraza + CRS v4. Prefer **Option A (SPOA, retire mitmproxy,
kill the SPOF)** if banner/cache/cookie-audit can be relocated; fall back to
**Option B (in-path Go + embedded Coraza)** if traffic transformation must stay
in-path. Do **not** hand-roll the engine or port the regex rules.

Proposed gated plan, more conservative than #662 (security-critical + SPOF):
1. **Decide the addon fate** (banner / media-cache / cookie-audit): relocate, drop,
   or keep a thin in-path component → this picks A vs B.
2. **Check the board's HAProxy version** (SPOE 2.x vs 3.1 `mode spop`).
3. **PoC, detect-only, SHADOW:** run coraza-spoa (or the Go+Coraza proxy) in
   **detection-only** mode against a mirror/copy of real traffic; **compare its
   verdicts to the current regex WAF** on the same requests (false-pos / false-neg
   delta). Serve no clients.
4. **arm64 benchmark** (latency added per request, body-size cost, burst behaviour).
5. **CRS tuning pass** on real traffic in detect-only (FP elimination, paranoia
   level) before any blocking.
6. **Canary ONE low-risk vhost** through the new path with the old WAF as instant
   fallback; watch; widen; then retire the mitmproxy inspector.

**Honest framing for the go/no-go:** if the goal is "the WAF is slow," the data says
it isn't (yet) — don't take the risk. If the goal is **resilience (kill the SPOF,
end the FD-leak/memory restarts, multi-core burst headroom) + better/auditable
detection coverage (CRS) for CSPN**, then Coraza+CRS via SPOA is a strong, mostly-
*adopt* move with a contained bespoke surface — a very different risk profile from
the #662 hand-roll.

## Sources
Repo: `packages/secubox-mitmproxy/addons/secubox_waf.py`, `data/waf-rules.json`,
`packages/secubox-haproxy/sbin/haproxyctl`, `packages/secubox-waf/systemd/
mitmproxy.service`, `.claude/PHASE-7-WAF-ROADMAP.md`. Live: gk2 read-only
(mitmproxy 11.0.2, 3.6 req/s, ~17–53% one core, 255 routes/187 inspected, HAProxy
TLS-term → cleartext). External (2025-26): OWASP Coraza v3.7 / coraza-spoa v0.7.2 /
coraza-coreruleset (CRS v4.25 LTS), HAProxy SPOE + 3.1 `mode spop`, CrowdSec AppSec
in-band/out-of-band, ngrok in-process Coraza.
