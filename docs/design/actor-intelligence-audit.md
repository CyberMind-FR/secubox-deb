<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Actor Intelligence — Audit préalable (RFC-0013 §0)

> Audit en lecture seule du dépôt `secubox-deb`. Objet : inventorier l'existant
> avant d'implémenter `cmd/sbx-actord` + `internal/actor` (*extend before create*).
> Répertoires `vendor/`, `*.gopath/`, `debian/secubox*/` exclus. Design :
> [`actor-intelligence-rfc-pack.md`](actor-intelligence-rfc-pack.md) · prompt :
> [`actor-intelligence-rfc13-prompt.md`](actor-intelligence-rfc13-prompt.md) · issue #1240.

## Tableau récapitulatif

| # | Thème RFC-0013 | Statut | Brique de réutilisation principale (chemin:symbole) |
|---|----------------|--------|------------------------------------------------------|
| 1 | Émission d'événements hot path / event socket / verdict store | **PARTIEL** | `internal/relay/relay.go:Emit`/`EmitSync` (bus POST unix) · `internal/sentinel/mirror.go:MirrorMsg` · `internal/sentinel/store.go:Store` (bbolt) · `cmd/sbxwaf/threatlog.go:ThreatLog.Record` (NDJSON) |
| 2 | Event Envelope normalisé | **PARTIEL** | `cmd/sbxwaf/threatlog.go:logEntry` · `cmd/sbx-authwatch/menaces.go:entreeMenace` · `internal/sentinel/gate.go:FlowMeta` — pas d'enveloppe v1 unifiée |
| 3 | Fingerprinting JA3/JA4 / HTTP / UA-family | **PARTIEL** | JA4: `cmd/sbxmitm/relay.go:emitJA4`, `internal/sentinel/ja4capture.go`, `internal/sentinel/ioc.go:MatchJA4` · UA: `cmd/sbxwaf/toolprint.go:identifierOutil`, `cmd/sbxwaf/visitstats.go:classifyUA` · **HTTP fp = MANQUANT** |
| 4 | ASN / GeoIP / reverse DNS | **PARTIEL** | ASN: `secubox-dpi/collector/main.go:asnOrg`/`cloudByASN` (maxminddb-golang) · Geo: `secubox-waf/api/main.py` geoip2 · **reverse DNS = MANQUANT** |
| 5 | Corrélation / clustering / scoring / similarité | **PARTIEL** | `cmd/sbxwaf/profiler.go` (AttackerProfile/Campaign/clusteriser) · `cmd/sbx-authwatch/campagne.go:Campagnes` · `internal/sentinel/behavioral.go` + `c2learn.go` · **similarité pondérée / graphe / union-find = MANQUANT** |
| 6 | Honeypot / leurres / canaris | **PARTIEL** | `cmd/sbx-authwatch/leurre.go:Leurre`/`EcouteLeurre` · `cmd/sbxwaf/negativespace.go` · **honey-identities / MicroCanary = MANQUANT** |
| 7 | Bannissement / ratelimit / verdicts | **EXISTANT — À NE PAS DUPLIQUER** | `cmd/sbxwaf/nftban.go:NftBanner` · `banstore.go:BanStore` · `ban.go:Ban` · `antirobots.go` · `cmd/sbx-authwatch/nft.go:Banneur` · `internal/sentinel/scorer.go:FinalizeAction` |
| 8 | Stockage local (bbolt / SQLite / ledger) | **EXISTANT (partiel)** | bbolt: `internal/sentinel/store.go` (go.etcd.io/bbolt v1.3.11) · NDJSON: `banstore.go`, `threatlog.go` · **Evidence Ledger inviolable (hash-chain) = MANQUANT** |
| 9 | WebUI / API intelligence | **PARTIEL** | `secubox-threat-analyst/api/main.py` · `secubox-threatmesh/api/main.py` · `secubox-soc-gateway/lib/alert_correlator.py` · **endpoints /actors /campaigns /evidence = MANQUANT** |
| 10 | Références CrowdSec résiduelles | **DETTE DOC uniquement** | Aucune dans le code ; seulement changelog/README. Purge déjà actée. |

## Détail par thème

### 1. Émission d'événements — event socket & verdict store
Trois voies coexistent, **pas de bus normalisé unique** :
- **sbxwaf → NDJSON** : `cmd/sbxwaf/threatlog.go:91 ThreatLog.Record` (`waf-threats.log`) ; `banstore.go:50 BanStore.Append` (`bans.jsonl`) ; `visitstats.go:106`, `vhostsignals.go:78`. Câblage `cmd/sbxwaf/main.go:1083,1113`.
- **sbxmitm → sockets unix (POST fire-and-forget)** — vrai transport existant : `internal/relay/relay.go:41 Emit` / `:49 EmitSync` (`EmitTimeout=2s`, jamais bloquant), mapping `relay.go:13-18` (`cookies.sock`, `dpi.sock`, `avatar.sock`, `threat-analyst.sock/ja4`, `soc.sock/event`). `cmd/sbxmitm/relay.go:289 emitJA4`.
- **sbx-sentinel → socket unix + verdict store bbolt** : écoute `cmd/sbx-sentinel/main.go:144` (`/run/secubox/sentinel-mirror.sock`), reçoit `internal/sentinel/mirror.go:26 MirrorMsg`, store `internal/sentinel/store.go:27 Store`.
- **sbxdpi** : API read-only `/run/secubox/dpi-live.sock` (`cmd/sbxdpi/main.go:174`).

→ `sbx-actord` fournit un socket d'ingestion (`/run/secubox/actord.sock`) et réutilise le pattern `relay.Emit` côté producteurs.

### 2. Event Envelope
Pas d'enveloppe v1. Structures partielles/redondantes : `threatlog.go:69 logEntry` (& jumeau `ThreatRecord:38`), `authwatch/menaces.go:35 entreeMenace` (**reproduit `logEntry`** pour partager le journal WAF), `sentinel/gate.go:21 FlowMeta`, `banstore.go:24 BanRecord`.
Couverts : `src_ip, vhost, action, rule_id, severity, tls_fingerprint(ja4), path`. **Absents** : `event_id, sensor, src_port, transport, protocol, credential_token_hash(HMAC), path_shape normalisé, user_agent_family, http_fingerprint, behavior_tags, asn, geo_country, reverse_dns_class, request_rate_bucket, session_duration_bucket, evidence_refs`.

### 3. Fingerprinting
- **JA4** EXISTANT : capture `cmd/sbxmitm/relay.go:254 ja4Event`/`:289 emitJA4`, stockage `internal/sentinel/ja4capture.go:26`, matching `ioc.go:172 MatchJA3`/`:178 MatchJA4`. Clé de corrélation dans `profiler.go` (repli IP), champ `logEntry.JA4`.
- **UA-family/outil** EXISTANT : `toolprint.go:58 identifierOutil`, `antirobots.go:131 identifierRobot`, `visitstats.go:174 classifyUA`.
- **HTTP fp (JA4H/HTTP2)** — **MANQUANT**.

### 4. ASN / GeoIP / reverse DNS
- **ASN** EXISTANT (Go) : `secubox-dpi/collector/main.go:75 asnOrg`/`:93 cloudByASN` via `oschwald/maxminddb-golang v1.13.1` (`GeoLite2-ASN.mmdb`).
- **GeoIP pays** EXISTANT (Python) : `secubox-waf/api/main.py:1849` (geoip2).
- **reverse DNS / `reverse_dns_class`** — **MANQUANT** (aucune classification PTR cloud/isp/hosting/tor). → créer côté Go, réutiliser `maxminddb-golang`.

### 5. Corrélation / clustering / scoring / similarité
Moteurs partiels, **aucun = similarité multi-signal pondérée** :
- `cmd/sbxwaf/profiler.go` (le plus proche) : `construireProfils:87` (clé JA4→IP + séquence chemins), `signatureWorkflow:147` (SHA1 de l'ensemble des chemins normalisés + outil), `clusteriser:163` (**égalité stricte de signature**), `normaliserChemin:35` = **path_shape réutilisable**.
- `authwatch/campagne.go:38 Campagnes` (pivot compte-cible → sources, détection botnet SASL).
- `sentinel/behavioral.go` (`checkBeaconing:130` CV intervalles, `shannonEntropy:379`), `c2learn.go`, `c2signal.go:isDGA`.
- `sentinel/scorer.go` (`HighConfidenceThreshold=85`, `FinalizeAction:37`).
**MANQUANT** : similarité pondérée explicable, graphe/union-find, versionnage des poids.

### 6. Honeypot / leurres / canaris
- **Leurres réseau** EXISTANT : `authwatch/leurre.go:36 Leurre`, `EcouteLeurre:98` (ban 1er contact).
- **Negative-space HTTP** EXISTANT : `cmd/sbxwaf/negativespace.go` (`classifyPath`, `"honeypot"`, `estHauteValeur`).
- **honey-identities / MicroCanary (identifiants/jetons canari pour mesurer la CONNAISSANCE)** — **MANQUANT**.

### 7. Bannissement / verdicts — À NE PAS DUPLIQUER
`sbxwaf` : `ban.go:32 Ban`, `banstore.go:34 BanStore`, `nftban.go:44 NftBanner` (sets `waf_ban`/`waf_ban6` table `secubox`, TTL nft), `antirobots.go:172 refuserRobot`. `authwatch` : `nft.go:34 Banneur` (**même set nft**), `compteur.go`, `blanche.go:24 ListeBlanche`, `comptes.go:32 Comptes`. `sentinel` : `ioc.go:47 Action`, `scorer.go:37 FinalizeAction`.
→ `sbx-actord` **recommande** ; l'application passe par ces briques.

### 8. Stockage local
- **bbolt** v1.3.11 (`go.mod:9`) : `sentinel/store.go`, `c2cand.go:163`, `c2learn.go:385`, `ja4capture.go`.
- **modernc.org/sqlite** v1.29.10 : radio/socialrelay/metanews/bbs (dispo si relationnel).
- **NDJSON** : `banstore.go`, `threatlog.go`, `mediacatch.go`.
- **Evidence Ledger inviolable (chaînage de hash)** — **MANQUANT** (`BanStore.Append` append-only mais non infalsifiable).

### 9. WebUI / API d'intelligence
Adjacent : `secubox-threat-analyst/api/main.py` (`/run/secubox/threat-analyst.sock`, `collect_waf_alerts:241`, `analyze_with_ai:280`, `approve/apply/rollback_rule:402-524`), `secubox-threatmesh/api/main.py` (IOC sqlite, gossip), `secubox-soc*` (`AlertCorrelator`, `/event`). Aucun cardlet acteurs/menaces dans `secubox-webos`. → API `/stats /actors /campaigns /evidence` à créer.

### 10. CrowdSec résiduel
**Aucune référence code**. Dette doc uniquement (changelog `secubox-waf-ng`, README de threatmesh/threat-analyst/soc/vortex-firewall/security-posture/wazuh/threats/profiles). Conforme à la contrainte : ne rien réactiver ; purge doc séparée. (Cohérent avec la purge box+dépôt déjà faite.)

## Briques RFC-0013 MANQUANTES à construire (`cmd/sbx-actord` + `internal/actor`)

Réutiliser : `bbolt`, `internal/relay`, `maxminddb-golang`, `profiler.normaliserChemin`, `toolprint`, `visitstats.classifyUA`, `sentinel.behavioral`, `nftban`/`Banneur`, `sentinel.Store`, `FinalizeAction`, `leurre.go`, `negativespace.go`, `ListeBlanche`.

1. **`envelope`** — Event Envelope v1 (§2) : `event_id, sensor, transport/protocol, credential_token_hash` (**HMAC-SHA256 à secret local rotatable**), `path_shape, user_agent_family, http_fingerprint, behavior_tags, asn, geo_country, reverse_dns_class, *_bucket, evidence_refs`. Instrumenter sbxwaf/sbxdpi/authwatch/sentinel.
2. **Socket d'ingestion actord** (`/run/secubox/actord.sock`) + collecteur asynchrone non bloquant (pattern `relay.Emit`).
3. **`features`** — extraction (path_shape, ua_family, tls_fp).
4. **`similarity`** — similarité multi-signal **pondérée + versionnée** (poids credential 30 / séquence 18 / outil 12 / TLS 12 / cadence 8 / IP-decay 10 / ASN 5 / pays 1).
5. **`graph`** — ActorGraph / campagnes (union-find/graphe, décroissance IP).
6. **`knowledge`** — KnowledgeScore + **honey-identities / MicroCanary** (réutiliser `authwatch/comptes.go:Inexistant`).
7. **`intent`** — IntentScore + AutomationScore + PersistenceScore (entrées : `sentinel.behavioral`, `campagne.go`).
8. **`evidence`** — Evidence Ledger append-only **inviolable** (hash-chain).
9. **`response`** — recommandations graduées TTL + rollback (s'inspirer de `threat-analyst.rollback_rule`).
10. **`api`** — `/stats /actors /campaigns /evidence`.
11. **Résolveur `reverse_dns_class`** + enrichissement ASN/Geo côté Go toolbox-ng.

**Vigilance** : `logEntry` (threatlog.go) et `entreeMenace` (authwatch) sont **volontairement dupliqués** pour partager le journal WAF lu par le panneau WAF/PDF — l'enveloppe v1 ne doit pas casser ce format.
