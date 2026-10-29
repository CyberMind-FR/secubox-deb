<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox WAF-NG — Shadow-Run, Bench & Cutover/Rollback Runbook

**Issue**: [#744](https://github.com/CyberMind-FR/secubox-deb/issues/744) — Replace mitmproxy/mitmdump with sbxwaf (Go)
**Author**: CyberMind — Gérald Kerma
**Status**: Operator-gated — do NOT execute cutover until all go/no-go gates pass

---

## Worker topology

Production decision: **HAProxy does NOT load-balance the two worker ports directly**.

Instead, an nftables DNAT rule spreads new TCP connections across
`127.0.0.1:8081` and `127.0.0.1:8082` at the kernel level
(`numgen inc mod 2`, sticky per-connection via conntrack).  HAProxy's backend
`mitmproxy_inspector` is re-pointed to a single loopback address
(`127.0.0.1:8080` — the nftables DNAT VIP), which transparently fans out to
the two workers.  This keeps the HAProxy config minimal (one `server` line to
edit at cutover/rollback) while the kernel absorbs the dispatch overhead.

```
HAProxy backend mitmproxy_inspector
  └─ server srv0 127.0.0.1:8080 check      ← nftables DNAT VIP (cutover)
         ↕ nftables DNAT (numgen inc mod 2)
  ├─ secubox-waf-ng-worker@1  127.0.0.1:8081
  └─ secubox-waf-ng-worker@2  127.0.0.1:8082
```

Legacy (mitmproxy LXC) topology for reference:

```
HAProxy backend mitmproxy_inspector
  └─ server srv0 10.100.0.60:8080 check    ← mitmproxy LXC (legacy / rollback target)
```

---

## 1. Pre-cutover checklist

Run every item from top to bottom before touching HAProxy.  Any FAIL = stop.

### 1.1 CA provisioned

```bash
# CA key pair must exist at the paths sbxwaf reads at startup.
test -f /etc/secubox/waf/ca/ca-cert.pem && echo "OK: ca-cert.pem" || echo "MISSING: ca-cert.pem"
test -f /etc/secubox/waf/ca/ca.pem      && echo "OK: ca.pem (key)" || echo "MISSING: ca.pem (key)"

# Permissions: root:secubox-waf, 0640
ls -la /etc/secubox/waf/ca/
```

If missing, generate a self-signed CA (or copy from the existing mitmproxy LXC):

```bash
# On the mitmproxy LXC (10.100.0.60) — copy the existing CA so clients already trust it:
scp root@10.100.0.60:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem \
    /etc/secubox/waf/ca/ca-cert.pem
scp root@10.100.0.60:/home/mitmproxy/.mitmproxy/mitmproxy-ca.pem \
    /etc/secubox/waf/ca/ca.pem
chown root:secubox-waf /etc/secubox/waf/ca/*.pem
chmod 0640 /etc/secubox/waf/ca/*.pem
```

### 1.2 Native nftables bans verified (external blocking bridge removed, #1218)

sbxwaf enforces its own bans: `nftban.go` maintains the sets `waf_ban` /
`waf_ban6` of the table `inet secubox` (4 h timeout), and the graduated
response (warning, then ban) feeds `sbx-actord` for campaigns and decoys.  The
external blocking bridge and its URL / token flags were removed (#1218): the
unit carries no such flag and no secret is needed.

```bash
# The ban sets exist:
nft list set inet secubox waf_ban
nft list set inet secubox waf_ban6
```

### 1.3 COMPLETE rule corpus deployed with log4shell — BLOCKING

**The deployed rule file MUST be the COMPLETE corpus** — i.e.
`packages/secubox-mitmproxy/data/waf-rules.json` (has the `log4shell`
category with `${jndi:` patterns), **NOT**
`packages/secubox-waf/config/waf-rules.json` (missing log4shell — this was
the 150-pattern file used during development).

Verify on the board:

```bash
# MUST return at least one line (jndi patterns present)
grep -qi jndi /etc/secubox/waf/waf-rules.json && echo "OK: log4shell present" \
    || echo "FAIL: log4shell MISSING — deploy complete corpus before proceeding"
```

If the check fails, copy the complete corpus:

```bash
# From the source tree:
install -m 0644 packages/secubox-mitmproxy/data/waf-rules.json \
    /etc/secubox/waf/waf-rules.json
chown root:secubox-waf /etc/secubox/waf/waf-rules.json
chmod 0640 /etc/secubox/waf/waf-rules.json
```

### 1.4 Null-byte CVE patterns fixed (RE2-compatible) — BLOCKING

Five CVE patterns use `\u0000` (Unicode escape) which RE2 rejects, causing
them to be silently dropped at rule load time:

- `cve-ast-2022-42706`
- `cve-ast-2023-37457`
- `cve-opensips-2023-49323`
- `cve-prosody-2022-0217`
- `cve-strophe-2022-29168`

Before cutover, replace every occurrence of `\u0000` with `\x00`
(RE2-compatible raw null byte escape) in the deployed rules file:

```bash
# In-place fix (GNU sed):
sed -i 's/\\u0000/\\x00/g' /etc/secubox/waf/waf-rules.json

# Verify no \u0000 remain:
grep -c '\\u0000' /etc/secubox/waf/waf-rules.json && echo "STILL PRESENT — fix failed" \
    || echo "OK: no null-byte escapes remain"

# Re-run the parity harness to confirm patterns now load cleanly:
cd /path/to/secubox-deb
go test ./packages/secubox-toolbox-ng/cmd/sbxwaf/ -run TestWAFParity -v 2>&1 \
    | grep -E 'PASS|FAIL|KNOWN GAP'
```

The parity harness must report 0 FAIL and the null-byte known_gap fixture
should transition from `known_gap` to a real pass once the patterns load.

### 1.5 goform false-positive fixed (rule hygiene) — BLOCKING

The pattern `/goform/.*\$\(|\`|;` has an unanchored `;` alternative at the
top level of the RE2 alternation.  This fires on ANY request whose combined
scan text (path + query + body + UA) contains a semicolon — including benign
`Mozilla/5.0 (X11; Linux x86_64)` User-Agent strings.

Fix: scope all alternatives inside the path context by anchoring the
alternation to the goform path prefix:

```json
"pattern": "/goform/.*?(\\$\\(|`|;)"
```

Apply to the deployed rules file:

```bash
# Review the current pattern:
grep -A2 'router-goform' /etc/secubox/waf/waf-rules.json

# After manual edit or script-based fix, verify:
grep 'router-goform' /etc/secubox/waf/waf-rules.json
```

Then re-run the parity harness.  The `known_gap_router_goform_fp_ua_semicolon`
known-gap fixture should now FAIL (it expects `warn` for the gap behaviour;
after the fix it will be `allow` and the fixture will need updating) — this is
expected: update the fixture to `expect: "allow"` and remove `known_gap: true`
once you confirm benign UA no longer triggers the rule.

### 1.6 Body inspection cap — documented detection gap (CUTOVER GATE)

**Operator acknowledgement required before cutover.**

sbxwaf inspects only the first `--max-body-inspect` bytes (default **1 MiB**) of
each request body.  The remaining bytes are streamed to the upstream uninspected.

**Python WAF difference**: the Python mitmproxy addon called `get_text()` which
buffers the **entire** body (no cap) — a request whose body is 1 MiB of benign
padding followed by the attack payload was caught by Python but is NOT caught by
sbxwaf at the default cap.

**Risk mitigation**:
- Path, query string, and User-Agent are inspected in full (no cap) — only
  body-only payloads beyond the cap evade.
- Truncation events are **always audit-logged** (action=`body-inspect-truncated`
  in the WAF threat log) so operators can observe evasion attempts.
- The local sliding-window ban counter still enforces on repeated scan attempts.

**Actions before cutover (choose one)**:

Option A — Raise the cap for stricter coverage:
```bash
# Edit ExecStart in the worker unit to add:
#   --max-body-inspect 8388608    # 8 MiB — covers typical API POST bodies
# Then reload:
systemctl daemon-reload && systemctl restart secubox-waf-ng-worker@{1,2}.service
```

Option B — Route large-upload vhosts around inspection (PeerTube, Nextcloud uploads):
Configure HAProxy to bypass the WAF backend for known large-upload paths and keep
the default 1 MiB cap for all other traffic.

Option C — Accept the gap (minimum): document the arbitrated decision here and
confirm audit-logging is active so evasion attempts are visible in the threat log:
```bash
# Confirm body-inspect-truncated events appear in the threat log:
tail -f /var/log/secubox/waf/waf-threats.log | jq 'select(.category=="body-inspect-truncated")'
```

Operator sign-off: `[ ] body-inspect gap reviewed and mitigated / accepted`

### 1.6bis Corps multipart des vhosts PHP — capture en flux (#3257)

Sur les vhosts PHP, sbxwaf capture en flux le début d'un envoi
`multipart/form-data` et l'analyse (PHP2Shell, CVE-2026-109618 et
CVE-2026-109619). Un vhost est PHP si son service figure dans `php_services`
(`vhost_profiles.json` : `nextcloud`, `roundcube`) **ou** si son nom d'hôte
normalisé correspond à un motif de `php_hotes` (livrés : `^(nc|nextcloud|cloud)\.`
et `^(webmail|roundcube)\.` ; un motif invalide est rejeté seul, journalisé).
La catégorie `php2shell` du corpus livré (`_meta` 1.6.0) est en mode `detect` :
les détections sont journalisées, **jamais bloquées** ni bannies. Le corps
relayé au backend n'est pas modifié. Le corps est lu comme PHP 8.2 le lit
(`main/rfc1867.c` transcrit, `skip_upload` collant compris) : fins de ligne
mélangées, apostrophes, en-têtes tolérés et parties placées après
`--frontière--` sont vus. La lecture a été confrontée à un oracle C bâti sur
`rfc1867.c` (sondes de relecture, 300 000 corps aléatoires, fuzz
différentiel) sans divergence. Réglages PHP supposés : valeurs par défaut
(`max_file_uploads=20`, `file_uploads=On`, `upload_max_filesize` ≥ 1 Mio,
pas de traduction d'encodage mbstring).

- **Tous les clients** sont analysés, réseau local et 127.0.0.1 compris (Tor
  arrive en 127.0.0.1) : une adresse privée est journalisée `local` et n'est
  jamais émise vers actord.
- **Mémoire** : la fenêtre de capture vaut **min(`--max-body-inspect`, 1 Mio)**.
  Relever l'inspection texte (option A ci-dessus, 8 Mio) ne la relève pas.
  Jusqu'à 16 captures simultanées : au pire **16 Mio** en mémoire.
- **Statuts de journal** (compteurs et booléens seulement, jamais le corps ni un
  nom de fichier ; `ja4` et `tool` comme une ligne detect) :
  `multipart-tronque` (fenêtre atteinte), `multipart-malforme`,
  `multipart-limite` (plafond de 2000 parties) et `capture-concurrence`
  (#3273 : sémaphore plein, 16 captures multipart ou 8 urlencoded, signal
  `genre` 1 ou 2 : le corps n'est pas analysé).
- **Gravité `audit`** : ces statuts portent la gravité `audit`, de valeur 10 (au
  lieu de 40) : ce sont des observations, pas des attaques. Le panneau les
  compte à part, en « états » (`etats`, `etats_today`), hors menaces.
- **Avant le canari, sur chaque box** : déclarer ses vhosts PHP (`php_services`,
  ou un motif `php_hotes`), puis `systemctl restart secubox-waf-ng` —
  `vhost_profiles.json` n'est lu qu'au démarrage — et vérifier au journal la
  ligne `sbxwaf: vhosts PHP armés : N explicites, M motifs`. Avec 0 et 0, la
  box est aveugle : zéro ligne `php2shell` ne prouve alors rien.
- **Retour arrière** : passer `"enabled": false` sur la catégorie `php2shell`
  dans `/etc/secubox/waf/waf-rules.json` (rechargement à chaud) : sans
  signature structurelle active, aucune capture n'est posée et aucune ligne
  `multipart-*` n'est écrite. Ce choix survit aux mises à jour : `waf-rules-sync`
  garde le `"enabled": false` de la box (ligne d'audit quand la copie livrée
  active la catégorie) ; un `true` suit la copie livrée, pour qu'un paquet
  puisse encore désactiver une catégorie. `waf-profils-fusion` ne remet jamais un nom de
  `php_services` ou de `php_hotes` retiré par l'opérateur. Ou réinstaller le
  paquet précédent (1.30.7).

### 1.7 Parity harness green — BLOCKING

After applying the corpus and rule fixes above, the full parity test suite
must pass with zero non-known-gap failures:

```bash
cd packages/secubox-toolbox-ng
go test ./cmd/sbxwaf/ -run TestWAFParity -v 2>&1 | tail -10
# Must end with: PASS
```

### 1.8 nftables DNAT rule in place for VIP fan-out

The nftables DNAT rule must be loaded so that `127.0.0.1:8080` is forwarded
to the two workers:

```nftables
# /etc/secubox/waf/nft-waf-dnat.nft  (load via: nft -f /etc/secubox/waf/nft-waf-dnat.nft)
table ip secubox_waf_dnat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr 127.0.0.1 tcp dport 8080 \
            dnat to 127.0.0.1 : 8081-8082 numgen inc mod 2 offset 8081
    }
    chain output {
        type nat hook output priority -100; policy accept;
        ip daddr 127.0.0.1 tcp dport 8080 \
            dnat to 127.0.0.1 : 8081-8082 numgen inc mod 2 offset 8081
    }
}
```

```bash
# Verify workers are listening:
ss -tlnp | grep -E '808[12]' && echo "OK: workers listening" || echo "FAIL: workers not up"
# Verify DNAT table loaded:
nft list table ip secubox_waf_dnat 2>/dev/null && echo "OK" || echo "FAIL: DNAT table not loaded"
```

### 1.9 Workers healthy

```bash
systemctl is-active secubox-waf-ng-worker@1.service && echo "OK @1" || echo "FAIL @1"
systemctl is-active secubox-waf-ng-worker@2.service && echo "OK @2" || echo "FAIL @2"

# Quick smoke test through the VIP — expect a proxy response (not 502):
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ -H "Host: ${BENCH_HOST:-secubox.local}"
# Anything other than 502/503/504 = worker reachable
```

---

## 2. Shadow-run

Shadow-run means running both stacks simultaneously and comparing decisions
WITHOUT redirecting production traffic to sbxwaf.

### 2.1 Start workers on shadow ports (8081/8082)

If the workers are not already running (they listen on 8081/8082 by default
from the systemd template unit):

```bash
systemctl enable --now secubox-waf-ng-worker@1.service
systemctl enable --now secubox-waf-ng-worker@2.service
journalctl -u secubox-waf-ng-worker@1 -n 20 --no-pager
journalctl -u secubox-waf-ng-worker@2 -n 20 --no-pager
```

### 2.2 Mirror/replay traffic for parity comparison

Option A — Manual replay with curl (low effort):

```bash
# Pick a sample URL from nginx/HAProxy access logs:
tail -100 /var/log/haproxy.log \
    | awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# Replay against both:
curl -s -v http://10.100.0.60:8080/api/v1/hub/status -H "Host: secubox.local" 2>&1 | head -5
curl -s -v http://127.0.0.1:8081/api/v1/hub/status  -H "Host: secubox.local" 2>&1 | head -5
```

Option B — HAProxy `mode tcp` traffic tee (advanced, zero-risk):

Add a second backend in haproxy.cfg that mirrors the inspect traffic to the
shadow without affecting the live path.  This is a read-only copy; HAProxy
discards the shadow responses.

```haproxy
backend shadow_sbxwaf
    mode tcp
    server shadow 127.0.0.1:8081

# In the frontend:
#   use_backend shadow_sbxwaf if TRUE   # or a sampling ACL
```

This is operator-discretion; Option A is sufficient for shadow validation
before a planned maintenance-window cutover.

### 2.3 Run the bench harness

```bash
# Ensure both stacks are serving (legacy on 10.100.0.60:8080, shadow on 127.0.0.1:8081)
bash scripts/sbxwaf-bench.sh

# Custom parameters example:
DURATION=60 CONNECTIONS=100 \
LEGACY_ADDR=10.100.0.60:8080 SHADOW_ADDR=127.0.0.1:8081 \
bash scripts/sbxwaf-bench.sh
```

Review the comparison table.  All three gates must print PASS.

### 2.4 Re-run the parity harness against live rules

```bash
cd packages/secubox-toolbox-ng
go test ./cmd/sbxwaf/ -run TestWAFParity -count=1 -v 2>&1 | tail -15
```

Zero parity divergences (non-known-gap FAILs) required.

---

## 3. Go/No-Go gate

All of the following must be true before proceeding to §4:

| Gate | Criterion | Tool |
|------|-----------|------|
| G1: Throughput | sbxwaf req/s·core > 5× mitmproxy req/s·core | `sbxwaf-bench.sh` |
| G2: Latency | sbxwaf avg p99 < 1/3 mitmproxy avg p99 | `sbxwaf-bench.sh` |
| G3: Memory | sbxwaf RSS < 1/4 mitmproxy fleet RSS | `sbxwaf-bench.sh` |
| G4: Parity | `TestWAFParity` 0 FAIL, 0 new parity divergences | `go test ./cmd/sbxwaf/` |
| G5: Rules | log4shell present + null-byte fixed + goform fixed | checklist §1.3–1.5 |

If any gate fails, stop.  Diagnose and iterate; do not cut over under pressure.

---

## 4. Cutover

Maintenance window recommended (impact: ~1 second HAProxy reload downtime).

### 4.1 Confirm workers are running and healthy

```bash
ss -tlnp | grep -E '808[12]'
systemctl is-active secubox-waf-ng-worker@{1,2}.service
```

### 4.2 Edit HAProxy backend — re-point server from LXC to host VIP

Find the current `mitmproxy_inspector` backend in `/etc/haproxy/haproxy.cfg`
(or the appropriate drop-in file managed by `haproxyctl`):

```
backend mitmproxy_inspector
    ...
    server srv0 10.100.0.60:8080 check    ← BEFORE (mitmproxy LXC)
```

Change to:

```
backend mitmproxy_inspector
    ...
    server srv0 127.0.0.1:8080 check      ← AFTER (nftables DNAT VIP → sbxwaf workers)
```

### 4.3 Validate and reload

```bash
# Syntax check (BLOCKING — never skip):
haproxy -c -f /etc/haproxy/haproxy.cfg && echo "OK: config valid" || { echo "SYNTAX ERROR — abort"; exit 1; }

# Graceful reload (zero dropped connections in most cases):
systemctl reload haproxy

# Confirm the reload succeeded:
systemctl is-active haproxy && echo "HAProxy running" || echo "FAIL: HAProxy not running"
```

### 4.4 Smoke test

```bash
# Via HAProxy — confirm traffic flows through sbxwaf workers:
curl -s -o /dev/null -w '%{http_code}\n' \
    "https://<your-vhost>/api/v1/hub/status" \
    -H "Host: <your-vhost>"
# Expect 200 or any non-502/503 response.

# Check X-SecuBox-WAF header is present (stamped by sbxwaf on every response):
curl -sI "https://<your-vhost>/api/v1/hub/status" | grep -i "x-secubox-waf"
# Must return: x-secubox-waf: inspected
```

---

## 5. Rollback

Rollback is a single HAProxy edit + reload.  The mitmproxy LXC stays deployed
and listening until the operator explicitly validates the sbxwaf cutover (do
NOT stop the LXC).

### 5.1 Re-point server back to mitmproxy LXC

In `/etc/haproxy/haproxy.cfg` (or the managed drop-in):

```
backend mitmproxy_inspector
    ...
    server srv0 10.100.0.60:8080 check    ← ROLLBACK (restore mitmproxy LXC)
```

### 5.2 Validate and reload

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg && echo "OK" || { echo "SYNTAX ERROR"; exit 1; }
systemctl reload haproxy
```

### 5.3 Verify mitmproxy LXC is serving

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
    http://10.100.0.60:8080/ -H "Host: <your-vhost>"
```

### 5.4 Keep sbxwaf workers running (do not disable yet)

Leave workers running so logs are preserved for post-incident analysis.
Disable them only after root-cause investigation is complete:

```bash
# Only after analysis:
systemctl disable --now secubox-waf-ng-worker@{1,2}.service
```

---

## 6. Post-cutover monitoring

### 6.1 Threat log

```bash
# Live WAF decisions:
tail -f /var/log/secubox/waf/waf-threats.log | jq .

# Block count in last hour:
journalctl -u secubox-waf-ng-worker@1 --since "1 hour ago" --no-pager \
    | grep -c '"verdict":"ban"' || true
```

### 6.2 Cookie-audit ledger

```bash
tail -f /var/log/secubox/cookie-audit/server.jsonl | jq .
```

### 6.3 Socket health (/run/secubox)

The workers do NOT expose a Unix socket (they use TCP on 8081/8082), but
other modules share `/run/secubox`.  Verify the RuntimeDirectoryPreserve=yes
guarantee is in place so worker restarts do not wipe sibling sockets:

```bash
# Must show Preserve=yes for all workers:
systemctl show secubox-waf-ng-worker@1 -p RuntimeDirectoryPreserve
systemctl show secubox-waf-ng-worker@2 -p RuntimeDirectoryPreserve
# Expected: RuntimeDirectoryPreserve=yes

# Confirm /run/secubox is not empty after any worker restart:
ls /run/secubox/ | wc -l    # must be > 0 (other modules' sockets)
```

Background: 95 units share `RuntimeDirectory=secubox`.  Without
`RuntimeDirectoryPreserve=yes`, ANY unit restart wipes `/run/secubox` and
kills every other module's socket → board-wide 502 cascade (lesson from #741,
board-applied 2026-06-25).  The secubox-waf-ng-worker@.service unit ships
with `RuntimeDirectoryPreserve=yes` to prevent this.

### 6.4 Ban propagation

sbxwaf bans natively in nftables (sets `waf_ban` / `waf_ban6`, table
`inet secubox`, 4 h) and reports decisions to `sbx-actord`.  Verify bans are
flowing:

```bash
nft list set inet secubox waf_ban
# Watch threat log for bans:
tail -f /var/log/secubox/waf/waf-threats.log | jq 'select(.verdict=="ban")'
```

### 6.5 Known operational constraints

**Python WAF unescaped-Host XSS (backport candidate)**: The legacy Python WAF
(`mitmproxy-addon.py`) has an unescaped `Host` header in its HTML error pages
(the `host` variable is interpolated directly into the error page HTML without
HTML-escaping).  This XSS exists in the Python path; sbxwaf's error pages use
Go `text/template` with HTML auto-escaping so the Go path is not affected.
Track as a backport-to-Python candidate if the legacy Python path is ever
re-enabled.

**Body URL-decoding asymmetry (known limitation)**: sbxwaf scans the raw
request body bytes without URL-decoding form-encoded bodies.  A
percent-encoded SQLi payload in a POST body (e.g.
`admin%27%20OR%20%271%27%3D%271`) will not be detected.  The Python engine
has the same limitation (mitmproxy `get_text()` is charset-decode only, not
form-decode).  Both engines behave identically here.  Document for future
improvement (add form-body URL-decoding in the handler's body preprocessing
step before calling `rules.Match`).

---

## Appendix: useful one-liners

```bash
# Workers listening?
ss -tlnp | grep -E '808[12]'

# nftables DNAT active?
nft list table ip secubox_waf_dnat 2>/dev/null | grep dnat

# What does HAProxy currently point at?
grep -A5 'backend mitmproxy_inspector' /etc/haproxy/haproxy.cfg | grep server

# Reload HAProxy safely:
haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy

# Worker memory:
systemctl show secubox-waf-ng-worker@{1,2} -p MemoryCurrent

# Log4shell check (deploy gate):
grep -qi jndi /etc/secubox/waf/waf-rules.json && echo "OK" || echo "MISSING"

# Null-byte check (deploy gate):
grep -c '\\u0000' /etc/secubox/waf/waf-rules.json && echo "NEEDS FIX" || echo "OK"
```
