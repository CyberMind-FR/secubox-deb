# ToolBoX cert-mismatch → warn-and-allow (no 502) — Design

*2026-07-02 · CyberMind / SecuBox-Deb · module `secubox-toolbox` (R3 Go mitm `sbxmitm`)*

## Problem

When a client behind wg-toolbox reaches an HTTPS site whose **upstream certificate
does not validate** (hostname mismatch, expired, self-signed, or a genuinely
foreign issuer), the R3 mitm (`packages/secubox-toolbox-ng/cmd/sbxmitm`) currently
**fails the upstream TLS dial → the client gets a 502 Bad Gateway** and cannot
reach the site at all. This is both a usability wall (a self-hosted domain with a
not-yet-issued cert is unreachable through the toolbox while fine directly) and a
missed security-UX opportunity: a cert anomaly is exactly when the user should be
*informed*, not silently hard-blocked.

## Goal

Replace the hard 502 with **warn-and-allow**: the toolbox keeps the site
accessible (served to the client under the toolbox's own trusted CA, so no
browser block), **injects a prominent "identity not verified / possible
impersonation" banner**, records a **SOC event**, and **notifies** only for the
high-risk (active third-party impersonation) class. Non-blocking by default.

## Decisions (from brainstorming)

- **Behaviour:** accessible + banner under the toolbox CA. Soft, never blocking. No interstitial.
- **Alerting:** SOC log for every anomaly + in-page banner + push/portal notification **only** for the `third_party` class (active impersonation), not for benign mismatches.
- **Banner persistence:** dismissible **per-site**, keyed on the leaf cert **fingerprint**. Once dismissed for a host at a given fingerprint it stays hidden; if the fingerprint later **changes**, the banner re-appears (re-alert).

## Global Constraints

- Language: Go. Lives entirely in `packages/secubox-toolbox-ng/cmd/sbxmitm/`. Rebuild `secubox-toolbox-ng`; restart `secubox-toolbox-ng-worker@1..4` to deploy.
- License header `LicenseRef-CMSD-1.0` on new files.
- Must NOT hard-fail on cert anomalies (that is the bug being removed). A genuine **network/connection** failure (not a cert issue) remains a real failure — no misleading banner.
- The client-facing leg is already re-signed under the R3 CA (`/etc/secubox/toolbox/ca-wg/`); nothing about client trust changes.
- Splice/passthrough hosts (`tls-splice-seed.conf`) are out of scope — they are never TLS-intercepted, so there is no upstream cert to classify.
- SOC log format is the existing `waf-threats.log` JSON-lines shape (one object per line).
- Reuse the existing banner injection (`policy.Inject` / `injectIntoBody`) and reload plumbing; do not add a second injection path.

## Architecture

One new classifier at the upstream-dial boundary + reuse of the existing banner,
SOC-log and (new, thin) notify sinks. Data rides the per-flow context from dial
to response.

```
client ──TLS(R3 CA)──▶ sbxmitm ──TLS──▶ upstream
                          │  VerifyConnection (never fatal) → {class, issuer, subject, fp}
                          │  stored on the flow
                          ▼
             response HTML ──▶ inject banner (if class≠ok) + SOC log + notify(if third_party)
```

## Components

### 1. Upstream cert classifier — `certcheck.go` (new)
- A `tls.Config.VerifyConnection` callback used for the **upstream** dial that
  **never returns an error** (so the dial always proceeds). It computes:
  - `class ∈ {ok, expired, self_signed, hostname_mismatch, third_party}`
  - `issuer` (leaf `Issuer.String()`), `subject` (leaf `Subject.String()`)
  - `fp` = hex SHA-256 of the leaf `Raw` DER.
- Classification rules (first match wins), given the connecting SNI `host`:
  - Build a roots-only verify (`x509.VerifyOptions{DNSName: host, Roots: system}`).
    - verify **ok** → `ok`.
    - error is `x509.CertificateInvalidError{Reason: Expired}` → `expired`.
    - chain is self-signed (leaf issuer == subject and not in roots) → `self_signed`.
    - `x509.HostnameError` (chain builds to a trusted root but the name doesn't match) → `hostname_mismatch`.
    - otherwise (untrusted issuer / unknown authority presenting a different identity) → `third_party` (active-impersonation class).
- Output type `CertVerdict{Class, Issuer, Subject, FP, Host}` stashed on the flow/proxy request context. `ok` ⇒ no downstream action.

### 2. Banner (reuse `policy.Inject` / `injectIntoBody`)
- On a 2xx `text/html` response whose flow carries a non-`ok` verdict, inject,
  before `</body>`, a self-contained banner element carrying `data-sbx-certwarn`,
  `data-host`, `data-fp`, and human text:
  `⚠️ Identité non vérifiée — <host> : <raison lisible>. Émetteur présenté : <issuer>. Possible usurpation.`
- The banner ships a tiny inline script (nonce-borrow like the existing banner,
  reuses `csp.go` relax path) that:
  - reads `localStorage['sbx_certwarn_<host>']`; if it equals the current `data-fp`, removes the banner (dismissed-and-unchanged);
  - wires the ✕ button to write the current `fp` into that key and hide the banner;
  - if the stored value differs from `data-fp` (cert changed) the banner stays → re-alert.
- Colour/severity: `third_party` renders in the danger palette (cinnabar); the
  benign classes in the warning palette (gold). Purely cosmetic; both non-blocking.

### 3. SOC log
- Append one line to `/var/log/secubox/waf-threats.log`:
  `{"timestamp": <RFC3339>, "client_ip": <peer>, "host": <host>, "category": "cert_anomaly", "class": <class>, "issuer": <issuer>, "subject": <subject>, "fingerprint": <fp>, "action": "warning"}`.
- Fire-and-forget, best-effort (a slow/broken log file never affects the proxy),
  matching the existing relay discipline. Emitted once per (flow) anomaly,
  including for non-HTML responses (where no banner is injected).

### 4. Notify (thin, `third_party` only)
- When `class == third_party`, POST a compact event to the portal ingest the
  existing relays already use (`/__toolbox/social-event`-style fire-and-forget)
  or the notification sink used by other high-severity toolbox events —
  `{type:"cert_impersonation", host, issuer, fingerprint, client_ip, ts}`.
- Deduplicate per `(host, fp)` within a process-lifetime set so a page with many
  subresources from the same impersonated host notifies once.

## Data flow

`dial upstream → VerifyConnection sets CertVerdict on ctx (never fatal) → TLS
proceeds → response path: if verdict.Class≠ok → (a) SOC log always, (b) inject
banner iff 2xx text/html, (c) notify iff third_party → response returned to
client under the R3 CA`.

## Error handling / edges

- **Real network failure** (connection refused, timeout, TLS protocol error that
  is not a cert-validity issue): unchanged — remains a genuine failure, no banner,
  no `cert_anomaly` log (avoid crying wolf).
- **Non-HTML responses** (JSON/binary/downloads): no injection, but the SOC log
  and notify still fire so the anomaly is recorded.
- **Compressed HTML** (br/zstd/gzip): injection goes through the existing
  decode→inject→re-encode path (same as the current banner; covered by
  `compress_test`).
- **Strict-CSP pages:** reuse the existing consented CSP-relax loader path
  (`csp.go`, `--csp-bypass-demo`); if relax is off, the banner may not render —
  acceptable, the SOC log still records it.
- **Splice hosts:** never reach the classifier (no interception) — unaffected.
- **Fingerprint churn on multi-cert hosts** (load-balanced differing leaves):
  keyed dismissal may re-show if a host legitimately serves multiple leaves; the
  per-`(host,fp)` notify dedup and the benign colouring keep this low-noise.

## Testing

Go table tests in `cmd/sbxmitm/` (mirroring existing `main_test.go` / `bench_test.go` cert fixtures):
- `certcheck_test.go`: for fixtures {valid-chain, expired, self-signed, hostname-mismatch, foreign-issuer} assert the returned `class` and that `VerifyConnection` **never returns an error**, and `fp` is the SHA-256 of the leaf DER.
- Banner: given a flow verdict ≠ `ok`, assert the banner is injected before `</body>` with correct `data-host`/`data-fp`; given `ok`, assert **no** injection. Extend `compress_test` to confirm injection survives br/zstd round-trip.
- SOC log: assert exactly one `cert_anomaly` line with the right fields per anomalous flow, including a non-HTML response case.
- Notify: assert a `third_party` verdict triggers one notify per `(host,fp)` and other classes trigger none.
- Dismissal JS: assert (via a small DOM/GoQuery or string check on the emitted script) it compares `localStorage['sbx_certwarn_<host>']` to `data-fp` and hides only on equality.

## Out of scope (YAGNI)

- Interstitial / click-through blocking mode.
- Per-host allow-list of accepted anomalies (splice already covers "trust this host entirely").
- Automatic cert issuance / remediation (that is the operator DNS-01 / autosetup flow, separate).
- Two-way / reverse-proxy cert handling beyond the client→mitm→upstream leg.
