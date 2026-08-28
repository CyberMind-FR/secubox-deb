# IMPLEMENTATION-AUDIT.md — Cyber Senses / Intelligence

**Objet :** audit Phase 0 du brief « Cyber Senses · Fingerprinting · MicroCanary · Auth Observer · Signal Intelligence ».
**Règle du brief :** *extend before create* — ne pas reconstruire ce que `sbxwaf`, `sentinel`, `sbxmitm`, HAProxy, nftables ou CrowdSec savent déjà faire.
**Statut :** audit seul, **aucun code écrit**. Méthode : lecture du dépôt réel + des specs `docs/superpowers/specs/` (10 specs), 4 sondes de code parallèles.
**Date :** 2026-08-28.

---

## 0. Verdict d'ensemble

**Le brief est déjà réalisé à ~80 %.** L'essentiel des « organes » décrits existe en production, mais **dispersé** entre trois foyers :

1. **`secubox-toolbox-ng`** (Go) — le vrai moteur : `cmd/sbxwaf`, `cmd/sbx-authwatch`, `cmd/sbxmitm`, `cmd/sbx-sentinel`, `internal/sentinel`.
2. **Python legacy / WebUI** — `secubox-waf` (addon mitmproxy + dashboard FastAPI + **données de règles**), `secubox-soc` (dashboard SOC complet), `secubox-mitmproxy` (WAF Python + honeypot nginx).
3. **Périphérie** — `secubox-auth` (événements de session), `secubox-crowdsec` (LAPI/bouncer), `secubox-cyberfeed` (feeds), GeoIP.

Le travail réel n'est **pas** un second stack de sécurité. C'est :
- **consolider** des capacités déjà écrites (aujourd'hui sous `cmd/`) en paquets `internal/` réutilisables ;
- **combler quelques vrais trous** (coherence engine, producteur JA4 HAProxy + strip, couche greeting du MicroCanary, consommateur Auth-Observer, cardlet Hall, namespace de config `intelligence`) ;
- **corriger 4 points de sécurité/robustesse** identifiés ci-dessous.

### Topologie live (à retenir)

- **Moteur WAF live = Go**, source `packages/secubox-toolbox-ng/cmd/sbxwaf/*.go`, **livré compilé** par `secubox-waf-ng` (`systemd/secubox-waf-ng.service`, `ExecStart=/usr/sbin/sbxwaf --listen 127.0.0.1:8085`, backend HAProxy `mitmproxy_inspector`).
- **`secubox-waf` (Python) = legacy** : ne reste que **config/données** (`config/waf-rules.json`, `config/vhost_profiles.json`) + **WebUI** (`api/main.py`, `www/waf/tableau.html`).
- **Substrat de convergence = 2 canaux partagés**, pas un bus applicatif :
  1. **nft sets partagés** `inet secubox waf_ban{,6}` — écrits par `sbxwaf` **et** `sbx-authwatch` ;
  2. **journal NDJSON partagé** `waf-threats.log` — **même format** écrit par `sbxwaf` (`cmd/sbxwaf/threatlog.go`) et `sbx-authwatch` (`cmd/sbx-authwatch/menaces.go`).
- **Ligne sbxmitm/sentinel** : un **Mirror** socket-unix borné (`internal/sentinel/mirror.go`, file 1024, cap 8 KiB, drop-with-count) → `cmd/sbx-sentinel` (analyseurs IOC async).

> **Conséquence directive :** le « Signal Bus » du brief doit **formaliser ce substrat existant** (NDJSON + nft + Mirror), pas introduire un nouveau transport. **Pas de Kafka/RabbitMQ/Elastic** — confirmé par les specs comme par le code.

---

## 1. Tableau de synthèse (composant du brief → réalité)

| # | Composant brief | Verdict | Où (preuve) |
|---|---|---|---|
| §3 | **Signal** (représentation/bus/spool) | **PARTIEL** | NDJSON `waf-threats.log` (`threatlog.go`) + Mirror socket (`internal/sentinel/mirror.go`) + `type Signal` auth (`cmd/sbx-authwatch/motifs.go:31`). Pas de `internal/signal` unifié ni de struct versionnée générique. |
| §4 P0-A | **Negative-space** | **PARTIEL** | Chemins-appâts en données `waf-rules.json` (`honeypot`, `recon_crawler`, `credential_harvest`, `product_absent_probes`). **Pas de classifieur 4-états** ; un 404 générique n'est pas distingué. |
| §5 P0-B | **Fingerprint engine** | **PARTIEL / éclaté** | JA4 ad-hoc `ja4stack` (`cmd/sbxmitm/main.go:98`, **pas FoxIO**), capture `ja4capture.go`, `toolprint.go`, `machash.go`. Consommateur JA4 WAF OK (`--ja4-header`, `main.go:805`). **Producteur HAProxy + strip absents.** JA4S/JA4H/traits TCP **absents**. |
| §6 P0-C | **Coherence engine** | **ABSENT** | Aucun score de cohérence inter-couches. Plus proche : corroboration ≥2 traits de `toolprint.go`. **Vrai trou.** |
| §7 P1-A | **Toolprint / tools.json** | **IMPLÉMENTÉ** | `cmd/sbxwaf/toolprint.go` (`outilsConnus` L30-51 : nuclei/sqlmap/nikto/wpscan/gobuster/ffuf/masscan/nmap/zap…), nommage prudent (`certain=false`→famille). **Écart :** table **compilée en Go**, pas de `tools.json` hot-reload externe. |
| §8 P1-B | **Behavior engine** (stats glissantes/acteur) | **PARTIEL** | Sentinel `behavioral.go` (beaconing/one-time-link/zero-click) **fait**. Côté WAF : seulement 2 compteurs fenêtre glissante (`ban`, `escalateBan`) + `profiler.go` **offline**. Les stats riches (req/min, unique_paths, 404_ratio, variance inter-arrivées…) **manquent au niveau HTTP**. |
| §9 P1-C | **MicroCanary** | **PARTIEL** | Ports-leurres réels `cmd/sbx-authwatch/leurre.go` (`Leurre`, `EcouteLeurre`, RDP/VNC/telnet/SMB/mysql, ban 1er contact) + honeypot HTTP nginx (`secubox-mitmproxy/nginx/honeypot.conf`). **Manque** la couche greeting→observe→classify du brief (leurre **n'émet aucun banner**). |
| §10 P1-D | **Auth Observer** | **PARTIEL** | `sbx-authwatch` couvre l'auth **non-HTTP par logs** (SSH/SMTP/IMAP). Les **événements de session propres à la box** existent (`secubox-auth/api/main.py` `_emit_session_event` login_failed/success/MFA) mais **aucun consommateur comportemental** ne les lit. |
| §11 P2 | **Actor Memory** (`actor_hash=HMAC`) | **PARTIEL** | Clé acteur = **JA4 sinon IP** (`profiler.go:89`, offline). Store bbolt sentinel par `MacHash` (`store.go`). HMAC-identité existe mais pour le **jar anti-track** (`privacy-jar.key`, non rotatif, clé=client). `actor_hash=HMAC(rotating_secret, fingerprint)` **absent**. TTL en morceaux. |
| §12 P2 | **Campaign correlation** (`workflow_hash`) | **IMPLÉMENTÉ** | `profiler.go` `signatureWorkflow` (SHA1 chemins normalisés+outils) → `clusteriser`→`Campaign`→`CorrelationSummary`, via `--correlate`. **Batch/offline** (pas live). |
| §13 P2 | **OSINT enrichment** | **PARTIEL** | Feeds overlay (ThreatFox/MVT/CitizenLab via sentinel-feeds + `secubox-cyberfeed` + SOC intel CRUD) **fait/planifié**. **GeoIP fait** (`secubox-waf/api/main.py:380`). **ASN réservé-mais-vide** (`:419-420`). rDNS/whois/cert & OSINT **par-acteur absents**. |
| §14 | **Dashboard cardlets** | **IMPLÉMENTÉ (données+UI) / cardlet Hall ABSENT** | WAF `tableau.html:132` « Attaquants persistants » + API `/campaigns`,`/stats`,`/bans`,`/detections`. `secubox-soc` (SOC complet). Hub `soc/nac`. **Aucun cardlet WAF/SOC/menace dans le Hall webos** (`api/cardlets.py`). |
| §17 | **Config `intelligence`** | **ABSENT** | Config = flags CLI (`sbxwaf/main.go:942-1028`) + JSON données + EnvironmentFile (`SENTINEL_ENABLED=0`, conffile). **Aucun namespace `intelligence`.** |
| §15 | **Resistance Lab** | **ABSENT** | Hors périmètre initial (à créer isolé, plus tard). |

---

## 2. Détail par composant (avec recommandation *extend*)

### §3 Signal — **PARTIEL → formaliser l'existant**
- **Existe :** journal NDJSON `waf-threats.log` (spool de facto ; champs `timestamp,client_ip,host,method,path,category,severity,rule_id,action,user_agent,tool?,ja4?` — `threatlog.go:69-82`, IP privée→`"local"`). Mirror socket borné (`mirror.go`, `MirrorMsg{Meta,Body,TS}`). `type Signal{IP,Service,Categorie,Severite,Detail,Cible}` + `chan Signal` (authwatch).
- **Manque :** un `internal/signal` partagé, une struct **versionnée** générique (`Version,Sensor,Event,Actor,Confidence,Severity,Tags,Facts`), des subscribers in-mem.
- **Recommandation :** créer `internal/signal` qui **enveloppe** le NDJSON + le Mirror existants (adapteurs), sans nouveau transport. Le NDJSON reste la source de vérité disque ; le Mirror reste le canal live. Versionner le record.

### §4 P0-A Negative-space — **PARTIEL → classifieur au-dessus des règles**
- **Existe :** appâts en données (`waf-rules.json` : `/.git/config` L230, `/.env` L235, `/actuator/env` L245, `/adminer.php` L797, `/.aws/credentials` L812, `/server-status` L822 ; `product_absent_probes` L949 = sondes CVE de produits **absents**, « signal pur zéro FP »). Match first-win regex `rules.go`.
- **Manque :** taxonomie `KNOWN_REAL / UNKNOWN / KNOWN_NEGATIVE / HIGH_VALUE_PROBE`. Un 404 **non couvert par une règle** est simplement reverse-proxifié — aucun signal « ressource inexistante ». `escalate` implémenté mais **non activé** dans le corpus livré ; `recon_crawler` en `detect` seulement.
- **Recommandation :** ajouter une **couche de classification** au-dessus de `rules.go` (ne pas réécrire le moteur de règles). Le brief l'exige : « ne pas considérer naïvement toute 404 comme attaque ». Activer `escalate` + `recon_crawler(detect)`, ajouter les signatures manquantes (`/config.json`, `/phpmyadmin` génériques, `/.git/HEAD`) — Phase F de la spec `2026-08-20`.

### §5 P0-B Fingerprint — **PARTIEL → producteur HAProxy + strip (aussi correctif sécu)**
- **Existe (consommateur) :** `main.go:805 lireJA4()` lit `--ja4-header` ; JA4 → clé profiler + champ threatlog.
- **Manque (producteur + garde-fou) :** **HAProxy n'injecte aucun `X-Sbx-JA4`** (`secubox-haproxy` ne génère que `X-Real-IP`/`X-Forwarded-Proto`), et **rien ne strippe** les `X-Sbx-*`/XFF entrants (grep `Header.Del` = 0 dans `cmd/sbxwaf`). JA4 est un `ja4stack` ad-hoc (**pas compatible bases JA4 publiques**) ; JA4S/JA4H/traits TCP absents.
- **Recommandation :** (1) **producteur** `set-header X-Sbx-JA4` côté HAProxy (lua/patch selon version, point ouvert spec §5) ; (2) **strip inbound** `X-Sbx-*` au bord — voir §Sécurité #1 (à faire **indépendamment** des features). Consolider en `internal/fingerprint`.

### §6 P0-C Coherence — **ABSENT → nouveau, mais nourri par l'existant**
- Aucun « les couches racontent-elles la même histoire ? ». **Recommandation :** `coherence.go` **consommant** les faits déjà produits (UA vs JA4, ordre d'en-têtes, Accept-Language, cadence, navigation) ; sortir `identity_coherence_low` comme **indice** (jamais ban seul). Réutiliser la logique de corroboration de `toolprint.go`.

### §7 P1-A Toolprint — **IMPLÉMENTÉ** (option : externaliser `tools.json`)
- `toolprint.go` : `identifierOutil` (UA→nommé+certain ; chemin→famille+incertain), `étiquetteOutil` (`family?` si incertain) — **respecte** la règle « jamais de faux nom ».
- **Recommandation :** rien de nouveau, sauf **externaliser** la table en `tools.json` hot-reload (comme `waf-rules.json`) si l'on veut l'éditer sans recompiler (conforme spec §C).

### §8 P1-B Behavior — **PARTIEL → étendre le profiler en moteur live**
- Sentinel `behavioral.go` (beaconing CV≤0.20, hits≥6) **fait**. WAF : `profiler.go` **offline** + 2 compteurs ban.
- **Recommandation :** promouvoir `profiler.go` vers un **état glissant par acteur live** (req/min, unique_paths/min, 404_ratio, negative_space_ratio, variance inter-arrivées, séquence) émettant `class/confidence/evidence[]`. Réutiliser le pattern `behavioral.go`. **Pas de ML en P1.**

### §9 P1-C MicroCanary — **PARTIEL → couche greeting sur `leurre.go`**
- `leurre.go` ouvre des ports morts et **ban au 1er contact, sans banner ni observation**. Le brief veut : accept → greeting minimal → réponse **bornée** → classifier → close → signal, pour SSH/Redis/SMTP/MySQL.
- **Recommandation :** **étendre `leurre.go`** (ou nouveau `secubox-microcanary` isolé) avec un émetteur de greeting borné + lecteur borné + classifieur, **sans jamais** offrir de shell/exécuter/télécharger. Reprendre le **hardening systemd** déjà démontré (`sbx-sentinel.service`/`secubox-authwatch.service` : `NoNewPrivileges`, `ProtectSystem=strict`, `CapabilityBoundingSet`, `MemoryMax`). Prototype **SSH+Redis** d'abord (spec Phase 5).

### §10 P1-D Auth Observer — **PARTIEL → consommateur des événements de session**
- `sbx-authwatch` = auth non-HTTP **par logs**. Les événements **applicatifs** de la box existent : `secubox-auth/api/main.py` `_emit_session_event("login_failed"/"login_success")` (`:228,:263`), MFA (`mfa_failed:279`), audit `_append_audit` → `audit.log`, callbacks `set_session_callback`/`set_audit_callback`.
- **Recommandation :** ajouter un **consommateur comportemental** qui s'abonne à ces événements (séquence fail×N → fingerprint change → success ⇒ `auth_suspicious_sequence`), **métadonnées uniquement** (jamais mot de passe/cookie/token/secret MFA), émis vers le Signal/threatlog. **Ne pas** créer un nouveau proxy d'auth.

### §11 P2 Actor Memory — **PARTIEL → actor_hash + rétention à paliers**
- Clé actuelle = JA4-sinon-IP (offline). HMAC-identité existe (jar anti-track `privacy-jar.key`, `common/secubox_core/...`, 0600, owner `secubox-toolbox`) mais **clé=client, non rotatif**.
- **Recommandation :** introduire `actor_hash = HMAC(rotating_secret, normalized_fingerprint_material)` — **réutiliser la convention de secret** (`/etc/secubox/secrets/…`) mais **secret rotatif** dédié. Paliers TTL (short/medium/aggregated) configurables ; stocker profils, **pas** le trafic brut. Attention **RGPD/CSPN** (point ouvert spec §5).

### §12 P2 Campaign — **IMPLÉMENTÉ** (option : rendre live)
- `signatureWorkflow`+`clusteriser`+`CorrelationSummary` **fait** (batch). **Recommandation :** conserver ; envisager corrélation **incrémentale** (n-grammes de chemins comme le suggère la spec §D, vs hash d'ensemble actuel) et surface `/api/v1/metrics/waf/attackers`.

### §13 P2 OSINT — **PARTIEL → enrichisseurs locaux async par-acteur**
- **Fait :** feeds overlay (local-first, hot-reload, « overlay vide ⇒ garder base »), GeoIP.
- **Manque :** ASN (schéma réservé, vide), rDNS/cert/réputation locale par-acteur.
- **Recommandation :** enrichisseurs **async locaux** (ASN, rDNS, réputation) alimentant l'Actor Memory **hors chemin réseau** (jamais bloquant). APIs externes = plugins **facultatifs**.

### §14 Dashboard — **IMPLÉMENTÉ (données+UI) → ajouter cardlet(s) Hall**
- **Fait :** WAF `tableau.html` « Attaquants persistants », API `/campaigns` (`campaigns.json`), `/stats`, `/bans` (pays), `/detections` ; **`secubox-soc`** (summary/map/live/tickets/intel/webhooks) ; Hub `soc`,`nac` ; CrowdSec UI.
- **Manque :** cardlet dans le **Hall webos** (`api/cardlets.py` n'a aucun adaptateur WAF/SOC).
- **Recommandation :** ajouter cardlets Hall (« Qui frappe ? / Comment ? / Campagnes / Acteur ») **au-dessus des endpoints existants** ; ne **pas** construire un nouveau dashboard.

### §17 Config `intelligence` — **ABSENT → surface unifiée disable-able**
- **Recommandation :** introduire un namespace `intelligence.{fingerprint,coherence,behavior,actor_memory,microcanary,osint}` qui **mappe** sur les flags/env existants. Toute feature **désactivable**, suivant le pattern `SENTINEL_ENABLED=0` (conffile qui survit à l'upgrade).

---

## 3. Constats sécurité / robustesse (à traiter en priorité, indépendamment des features)

1. **`sbxwaf` fait confiance à JA4/XFF entrants sans strip** (`cmd/sbxwaf`, aucun `Header.Del`). Si un chemin atteint `sbxwaf` **sans** réécriture HAProxy, un client peut **forger** `X-Sbx-JA4`/`X-Forwarded-For` → empoisonne clé de corrélation et bans. **À corriger** (strip au bord + producteur HAProxy) — c'est aussi le plus gros trou fonctionnel du corridor JA4.
2. **Sentinel livré « dark »** : `sbx-sentinel.service` désactivé par design, `SENTINEL_ENABLED` non positionné, aucun analyseur câblé par défaut. Moteur présent mais **inerte** (cutover humain).
3. **`escalate` non activé** dans le corpus de règles livré (implémenté mais dormant).
4. **Hardening systemd inégal** : fort sur `sbx-sentinel`/`secubox-authwatch`/`sentinelle-gsm` ; **faible** sur `secubox-mitmproxy` (pas de caps/mem/syscall) et **quasi nul** sur `secubox-device-intel` (`NoNewPrivileges` seul). Aligner sur le template existant.

---

## 4. Roadmap révisée (au vu de l'existant)

Le brief prévoit Phase 1 = negative-space + host-anomaly + tool-signatures + JA4 transport. **Or host-anomaly et tool-signatures sont DÉJÀ FAITS.** Phase 1 se réduit donc à :

- **Phase 1a (quick wins, petit code) :** activer `escalate`+`recon_crawler`, ajouter signatures manquantes, poser le **classifieur negative-space** au-dessus de `rules.go`.
- **Phase 1b (corridor JA4, = correctif sécu #1) :** **producteur** `X-Sbx-JA4` HAProxy + **strip** inbound `X-Sbx-*` dans `sbxwaf`.
- **Phase 2 (Signal) :** extraire `internal/signal` (adapteurs NDJSON+Mirror, record versionné) — brancher `sbxwaf` d'abord, valider, puis les autres producteurs.
- **Phase 3 (compréhension) :** `coherence.go` (nouveau) + promotion `profiler.go` en behavior engine live + `actor_hash` HMAC + rétention à paliers. **Mode observe-only** d'abord.
- **Phase 4 (Auth) :** consommateur comportemental des événements `secubox-auth` (metrics → signal → réponse adaptative, par paliers).
- **Phase 5 (MicroCanary) :** étendre `leurre.go` avec greeting/observe borné (SSH+Redis d'abord).
- **Phase 6 (OSINT) :** enrichisseurs locaux async (ASN/rDNS/réputation) ; plugins externes facultatifs.
- **Transverse :** namespace config `intelligence` (tout désactivable) ; cardlets Hall au-dessus des endpoints existants ; aligner le hardening systemd de `secubox-mitmproxy`/`device-intel`.

**Definition of Done (brief §21) :** transformer `185.x GET /.env` en une fiche acteur expliquée (classe, confiance, evidence, campagne, première vue, action suggérée) **sans conserver le contenu** — la matière (`profiler.go`, campagnes, JA4, threatlog) existe déjà ; il reste à **relier et exposer**.

---

## 5. Où va le nouveau code (foyer confirmé)

`packages/secubox-toolbox-ng/` — module `github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng` (go 1.22), déjà `cmd/{sbxwaf,sbx-authwatch,sbxmitm,sbx-sentinel}` + `internal/{sentinel,relay,forge,reload,httpcodec}`. Les paquets proposés `signal/fingerprint/profiler/authobserver/microcanary` existent **en substance sous `cmd/`** ; le geste est **extraction/consolidation en `internal/`**, pas du greenfield. MicroCanary peut rester dans `authwatch` (extension `leurre`) ou devenir un service isolé `secubox-microcanary`.

**Aucune modification effectuée. Rien à builder. En attente de validation avant Phase 1.**
