<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Design — sbxmitm Sentinel: exploit/malware/spyware detection engine

- **Issue**: [#823](https://github.com/CyberMind-FR/secubox-deb/issues/823)
- **Date**: 2026-07-06
- **Licence**: LicenseRef-CMSD-1.0
- **Module**: `packages/secubox-toolbox-ng` (Go), integrated with `cmd/sbxmitm`; content overlaid via `blacklist-sync`
- **Posture**: **defensive** — protects the operator's own R3-consented tunnel; no offensive capability.

## 1. Problème

The R3 toolbox MITM (`sbxmitm`) already decrypts consented tunnel traffic (forge/204/inject/splice/JA4) but does **no threat inspection**. Meanwhile the network's users face the full spectrum of web-delivered threats — malware/trojan downloads, botnet C2, phishing — and, for high-risk targets, **commercial/nation-state spyware** (Pegasus, Predator/Cytrox, Intellexa) delivered via zero-click links. SecuBox has the decrypted flow and the threat-intel feeds (ThreatFox/Feodo/SSLBL) but nothing that turns them into detection + mitigation on the live flow.

## 2. Objectif

A **defensive** detection engine — **sbxmitm Sentinel** — that, on every R3-decrypted flow: matches high-confidence IOCs inline and **neutralizes** the threat (block/strip/sinkhole), mirrors suspicious flows to an **async Go analyzer** (YARA + behavioral + commercial-spyware indicators), records verdicts (SQLite), and emits **proposal/solution reports**. Threat content is a **bundled base pack** overlaid with **live MVT/Citizen Lab + existing feeds**. It stays within the R3-consent + `mac_hash` privacy boundary and uses **no `waf_bypass`**.

**Non-goals:** any offensive/exploitation capability; decrypting non-consented traffic; endpoint/host forensics (this is network-delivery detection, not on-device MVT); auto-blocking heuristic/zero-click hits (report only — see §6).

## 3. Décisions (brainstorm 2026-07-06)

| Axe | Décision |
|-----|----------|
| Posture | **Hybrid** — inline block on high-confidence; async deep-analysis + report otherwise |
| Placement | Whole engine in **Go / `secubox-toolbox-ng`** (single language with sbxmitm) |
| Inline gate | Hooks sbxmitm's per-flow Request/Response; **O(1) IOC matching only** (hot path), reuses sbxmitm neutralize primitives |
| Async analyzer | Go daemon in toolbox-ng — **YARA** (libyara/cgo), behavioral, spyware indicators, report gen |
| Spyware IOCs | **Both** — bundled base pack (offline) ∪ live **Amnesty MVT + Citizen Lab** feeds |
| Feeds | Reuse `blacklist-sync`/threat-intel timer for MVT/CitizenLab + existing ThreatFox/Feodo/SSLBL |
| Block vs report | **Known-infra IOC hits block inline**; heuristic/zero-click **report only** (no false-blocking legit messaging) |
| Store | SQLite verdict store → toolbox WebUI/API + reports |
| Privacy | R3-consent boundary; `mac_hash` identity; no new PII |
| Scope | **One combined spec** (gate + analyzer + packs) |

## 4. Architecture

### 4.1 Components (all Go, in `packages/secubox-toolbox-ng`)
```
cmd/sbxmitm (existing)
  └── sentinel inline gate (new: cmd/sbxmitm/sentinel*.go or internal/sentinel)
        per R3-decrypted flow (Request + Response headers/first bytes):
          match IOC sets: domain | url | ip | ja3/ja4 | cert-sha1 | file-hash
          high-confidence  → NEUTRALIZE inline (204/block-page/strip/sinkhole,
                              reusing swneuter/poison_gate/forge) + record verdict
          suspicious       → tag + MIRROR (flow meta + bounded payload) to analyzer
        HOT-PATH BUDGET: matching only; NEVER YARA/heavy work inline.

cmd/sbx-sentinel (new async daemon)  ── receives mirrored flows over a local socket
  ├── yara engine (libyara/cgo)      → file/payload malware rules
  ├── behavioral engine              → C2 beaconing cadence, one-time-link / redirect-chain,
  │                                     zero-click delivery patterns (iMessage/WhatsApp URL shapes)
  ├── spyware indicator engine       → MVT/CitizenLab IOC correlation (domain/C2/JA/cert/URL)
  ├── verdict scorer                 → class + severity + confidence + action
  └── reporter                       → per-verdict proposal/solution report (Go templates)

internal/sentinel/packs               ── IOC/YARA loader
  base pack (shipped, offline)  ∪  live overlay (MVT + CitizenLab + ThreatFox/Feodo/SSLBL)

store: /var/lib/secubox/sentinel/sentinel.db (SQLite)  ── verdicts, evidence, actions, mac_hash
```

### 4.2 IOC model + pack format
A pack is a set of typed indicators: `{type, value, class, severity, source, action}` where
`type ∈ {domain, url_regex, ip, ja3, ja4, cert_sha1, file_sha256, yara_rule}`,
`class ∈ {malware, trojan, botnet_c2, phishing, spyware_pegasus, spyware_predator, spyware_intellexa, zero_click}`,
`action ∈ {block, strip, sinkhole, report}`. The inline gate loads the cheap types into hash-sets/tries; YARA rules load only into the analyzer. Base pack ships in the package (versioned); the live overlay is fetched by `blacklist-sync` into a merge dir and hot-reloaded.

### 4.3 Verdict → action → report
- **Neutralize (inline, high-confidence, `action=block/strip/sinkhole`)**: reuse sbxmitm primitives — serve a Sentinel block page (like the WAF 421 page), strip the offending response body, or sinkhole the C2 host. Record `action_taken`.
- **Report (async / heuristic / `action=report`)**: the analyzer writes a verdict + a human-readable **proposal/solution report** — *what* was detected (class, evidence: matched IOC/rule, JA4, URL), *why* (source/confidence), and the *recommended mitigation* (e.g. "isolate device `mac_hash`", "rotate credentials", "the delivery URL was reported, not blocked, to avoid breaking messaging — advise the user"). Surfaced per `mac_hash` in the toolbox WebUI + report links.

## 5. Data flow
```
R3 flow (TLS-decrypted, consented)
  ├─ inline gate: IOC match (O(1))
  │     block/strip/sinkhole ◀─ high-confidence ─▶ verdict store ─▶ WebUI/API
  │     suspicious ─mirror(meta+bounded payload)─┐
  └───────────────────────────────────────────── ▼
                                    sbx-sentinel analyzer (Go, async)
                                      YARA + behavioral + spyware indicators
                                      → verdict + proposal/solution report ─▶ store ─▶ WebUI/report
packs: base (shipped) ∪ live MVT+CitizenLab+ThreatFox/Feodo/SSLBL (blacklist-sync, hot-reload)
```

## 6. Error handling / constraints
- **Hot-path budget (critical):** the inline gate does IOC hash/trie lookups only; a slow gate degrades *all* R3 browsing. YARA/behavioral/deep analysis is **async only**. Benchmarked against a per-flow budget; the gate fail-opens (a matcher error lets the flow pass, logs) — never blocks browsing on its own bug.
- **False positives:** only **high-confidence known-infra** hits block inline; heuristic + zero-click + low-confidence are **report-only** with tunable thresholds. A blocklist entry can be per-class allow-listed (operator override).
- **Mirror bounded:** mirrored payloads are size-capped and rate-limited; the analyzer is fail-safe (down/slow analyzer never stalls sbxmitm — mirror is fire-and-forget over a local socket with a bounded queue; drop-with-count on overflow).
- **YARA/libyara** is a new CGO dependency for toolbox-ng (which already cross-compiles CGO for dpi/toolbox-ng) — pin libyara, guard the build.
- **Feed trust:** MVT/CitizenLab/abuse.ch are trusted sources fetched over TLS; the base pack is the offline fallback; a corrupt//empty live overlay is ignored (keep base) — never wipes detection.
- **Privacy:** inspection stays within the R3-consent boundary the tunnel already establishes; identity is `mac_hash` only; reports carry no raw PII; retention bounded (verdict store TTL).
- **No `waf_bypass`;** integrates with the existing sbxmitm/WAF chain; block pages route through the same inspected path.
- **Defensive-only:** the engine detects + neutralizes delivery to protect the operator's users; it never exploits, attacks, or exfiltrates.

## 7. Tests
- **Inline gate:** fixture flows with a known-bad domain/JA4/cert/hash → neutralized + verdict recorded; benign flow → passes untouched; matcher error → fail-open (flow passes, logged); **perf bench** within the hot-path budget.
- **Pack loader:** base pack loads offline; live overlay merges + hot-reloads; each IOC type parses; corrupt overlay ignored (base retained).
- **Analyzer:** YARA rule hit on a malware payload fixture → malware verdict; beaconing fixture → botnet_c2; a bundled Pegasus/Predator IOC (from the base pack) matched in a flow fixture → spyware verdict + report; zero-click heuristic fixture → **report, not block**.
- **Verdict store + report:** a verdict persists with class/severity/evidence/action; a report renders the detection + recommended mitigation; per-`mac_hash` query.
- **Fail-safe:** analyzer down → sbxmitm unaffected (mirror drops with count); overflow drop counted.
- **Security posture:** assert heuristic/zero-click classes are `action=report` (never auto-block) in the shipped base pack.

## 8. Séquencement (pour le plan)
1. IOC pack model + loader (types, base-pack format, hash-set/trie build) + base pack skeleton.
2. Inline gate in sbxmitm (IOC match on the per-flow hook; neutralize primitives; fail-open; verdict emit) + perf bench.
3. Mirror channel (bounded fire-and-forget local socket, drop-with-count).
4. `sbx-sentinel` async daemon scaffold + verdict store (SQLite) + scorer.
5. YARA engine (libyara/cgo) + malware/file rules.
6. Behavioral engine (beaconing, one-time-link/redirect-chain, zero-click heuristics).
7. Spyware indicator engine + the commercial-spyware base pack (Pegasus/Predator/Cytrox/Intellexa) + zero-click report-only enforcement.
8. Live feed overlay via `blacklist-sync` (MVT + CitizenLab + ThreatFox/Feodo/SSLBL) + hot-reload.
9. Reporter (proposal/solution report templates) + toolbox WebUI/API surface for verdicts/reports.
10. Packaging (units, config, retention/TTL, changelog) + deploy recipe (ng-workers + sentinel daemon).

## 9. Risques
- **Hot-path performance** — the single biggest risk; mitigated by IOC-only inline + async everything-else + benchmarks + fail-open.
- **False-positive blocking** — high-confidence-only inline; heuristic/zero-click report-only; operator allow-list.
- **Zero-click detection is hard** — inherently heuristic; framed as alert/report + recommended mitigation, not a guarantee; honest confidence scoring.
- **libyara/CGO build** — new cross-compile dep; pin + guard (parity with existing dpi/toolbox-ng CGO).
- **IOC feed drift/poisoning** — trusted sources + offline base + ignore-corrupt-overlay.
- **Scope/perception** — strictly defensive; the spec + issue state detection/mitigation/report for the operator's own consented network only.
