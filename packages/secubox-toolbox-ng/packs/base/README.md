# Sentinel base IOC packs

This directory holds the **shipped base content pack** for the sbxmitm
Sentinel threat-detection engine (`internal/sentinel`, `packages/secubox-toolbox-ng`).
It is loaded at startup by `sentinel.NewLoader(baseDir, overlayDir)` and
merged with whatever live-feed overlay pack(s) are configured on the box
(Task 12 — live feed overlay ingestion, not part of this pack).

## Files

| File | Threat classes | Provenance |
|------|-----------------|------------|
| `spyware.json` | `spyware_pegasus`, `spyware_predator`, `spyware_intellexa`, `zero_click` | Amnesty International **Mobile Verification Toolkit (MVT)** indicator methodology (`pegasus.stix2`-style domain/cert indicators) and **Citizen Lab** Predator/Intellexa research (e.g. *The Great iPwn*, *Predator in the Wires*, *The Predator Files*) |
| `malware.json` | `malware`, `trojan` | **abuse.ch** ThreatFox/Feodo Tracker export shape |
| `botnet.json` | `botnet_c2` | **abuse.ch** ThreatFox export shape |

## IMPORTANT — these are representative, not the live current indicator set

Commercial-spyware C2 infrastructure (Pegasus/Predator/Intellexa) rotates
domains, certificates and hosting on a timescale of weeks, and the exact
live values are not something a package should hardcode and let go stale in
a Debian archive. The entries in `spyware.json`, `malware.json` and
`botnet.json` are therefore:

- **Structurally representative** of the indicator *shapes* documented by
  Amnesty MVT / Citizen Lab / abuse.ch — e.g. disposable
  notification/news-portal-themed domains and one-time SMS/iMessage
  delivery-link path patterns for Pegasus/Predator, and standard
  domain/IP/hash C2 indicators for the abuse.ch-shaped entries.
- **Not live-verified current infrastructure.** Every domain/IP value uses
  an RFC 2606 / RFC 5737 reserved, non-resolvable placeholder range
  (`*.example`, `203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) so
  nothing in this base pack can ever collide with, block, or misattribute a
  real third-party domain or address. JA3/JA4/cert-SHA1/file-SHA256 values
  are similarly illustrative placeholders, not fingerprints lifted from a
  real report.
- **Small and seed-only by design.** The base pack exists so the engine has
  *something* to match against and so its safety invariants (see below) have
  real content to exercise in CI, before any live feed is configured. It is
  intentionally NOT an attempt to replicate the full current Amnesty
  MVT / Citizen Lab / abuse.ch indicator corpus.

**The live feed overlay (Task 12) is authoritative for indicator volume and
currency.** Operators should point `sentinel.NewLoader`'s `overlayDir` at a
directory kept in sync with the actual current MVT STIX2 bundle, Citizen
Lab's published IOC lists, and abuse.ch's ThreatFox/Feodo Tracker exports.
Overlay entries override base entries with the same `(type, value)` pair
(see `pack.go`'s `MergePacks`), so a live feed naturally supersedes any
placeholder here once configured.

## Safety invariant: heuristic/zero-click entries are report-only

Per the Sentinel plan's Global Constraints, only a **confirmed known-infra**
IOC hit (`spyware_pegasus`/`spyware_predator`/`spyware_intellexa`, high
severity) may carry `"action": "block"`. Every `zero_click` entry — a
heuristic match on a *delivery-link shape*, not a confirmed compromise —
MUST carry `"action": "report"` and must NEVER be shipped as `"block"`.

This is enforced as a hard test, not just a convention:
`internal/sentinel/spyware_test.go`'s `TestBasePackZeroClickIsReportOnly`
loads every `*.json` file in this directory and fails the build if any
IOC whose class is heuristic (`sentinel.IsHeuristicClass`) declares any
action other than `report`. `internal/sentinel/spyware.go`'s
`Spyware.Analyze` additionally forces `zero_click` verdicts to
`ActionReport` at the code level regardless of what a pack (base or
overlay) declares, as defense in depth on top of this content invariant.
