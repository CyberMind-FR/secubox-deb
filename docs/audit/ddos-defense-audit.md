<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit de l'existant : défense DDoS distribuée et « MirrorNet Collective Defense »

Issue : #3417, phase 1 (audit en lecture seule).
Date : 2026-11-03. Base : `master` au commit `47acf97fb`.
Méthode : lecture du dépôt uniquement (`grep` et lectures ciblées). Aucune box n'a été consultée, donc rien de
ce qui est écrit ici ne décrit l'état réel d'un déploiement : ce sont les sources, les unités et les configurations
livrées par les paquets.

Statuts :

- **EXISTANT** : la capacité est dans le code, avec sa référence.
- **PARTIEL** : elle existe, mais avec une limite qui compte pour un DDoS.
- **ABSENT** : on l'a cherchée sans la trouver (motifs de recherche indiqués).
- **NON VÉRIFIÉ** : le code ne suffit pas à trancher ; il faut une mesure au banc.

Les chemins sont relatifs à `packages/`, sauf mention contraire. `tng/` désigne `secubox-toolbox-ng/`.

---

## 1.1 ActorD / Actor Intelligence

Composants : `tng/cmd/sbx-actord/` (démon), `tng/internal/actor/{envelope,store,evidence,similarity,graph,knowledge,intent,score,response,analysis,mesure,emit,features}`.
Les capteurs qui émettent des enveloppes sont `tng/cmd/sbxwaf`, `tng/cmd/sbxdpi/actorsensor.go`, `tng/cmd/sbx-authwatch/acteur.go`
et le capteur de balayage `tng/cmd/sbxwaf/scansensor.go`. L'unité est `secubox-waf-ng/systemd/secubox-actord.service:33-41`.
Activation documentée dans `docs/ACTOR-INTELLIGENCE-ACTIVATION.md` (racine du dépôt).

| Capacité | Statut | Référence |
|---|---|---|
| Architecture : démon séparé, ingestion par socket Unix non bloquante, stockage bbolt append-only, ledger de preuves | EXISTANT | `tng/cmd/sbx-actord/main.go:7-16,39-56` ; `server.go:148-216` (ingestion) ; sockets `/run/secubox/actord.sock` (ingestion) et `/run/secubox/actor.sock` (API) |
| Collecte multi-capteurs (WAF, DPI, authwatch, balayage de ports) | EXISTANT | `tng/cmd/sbxwaf/main.go:1259` (`--actor-socket`) ; `tng/cmd/sbxdpi/actorsensor.go` ; `tng/cmd/sbx-authwatch/acteur.go` ; `tng/cmd/sbxwaf/main.go:1333-1334` (`--scan-sensor`, seuil de 8 ports) |
| Émission sans blocage : si actord tombe, les capteurs continuent | EXISTANT | `main.go:14-15` ; `tng/internal/actor/emit/emit.go` ; file `--queue 4096` (`main.go:51`) |
| Identification d'un acteur par signature multi-signal (identifiant, chemins, UA, JA4, cadence, IP qui décroît, ASN, pays) | EXISTANT | `tng/cmd/sbx-actord/correlate.go:33-46` (`signatureDe`) ; poids dans `tng/internal/actor/similarity/similarity.go:20-33` (l'IP a une demi-vie de 6 h, le pays pèse 1) |
| Corrélation multi-IP (un acteur regroupe plusieurs adresses) | EXISTANT | `tng/internal/actor/graph/graph.go` (610 lignes) ; `correlate.go:88-139` (`observe`, `correlate`) |
| Agrégation temporelle (fenêtres, réapparitions, consolidation) | EXISTANT | `correlate.go:25-30` (`windows`, `days`), `correlate.go:261-289` (`consolidationLoop`, `purgerMemoire`) ; rétention 15 j (`--retention 360h` dans l'unité) ; rejeu plafonné à 50 000 événements (`correlate.go:47-50`) |
| Détection de campagnes (même mode opératoire, dictionnaires de sous-domaines regroupés) | EXISTANT | `tng/cmd/sbx-actord/api.go:191-283` (`signatureCampagne`, `suffixeDictionnaire`), `api.go:298-376` (`campagnes`) ; corrélateur hors ligne `secubox-waf-ng/systemd/secubox-waf-campaigns.service:30` (`sbxwaf --correlate`) |
| Scoring explicable et versionné | EXISTANT | `tng/internal/actor/score/score.go:6-47` |
| Échelle de réponse graduée OBSERVE → DELAY → CHALLENGE → TARPIT → DENY → QUARANTINE, avec TTL | EXISTANT | `tng/internal/actor/response/response.go:6-60` ; aucune escalade sous le plancher de confiance (`response.go:31-33`) |
| API (lecture seule, sauf le retour d'opérateur) | EXISTANT | `server.go:264-305` : `/stats`, `/actors`, `/actors/{id}`, `/campaigns`, `/robots`, `/mesures`, `/radar`, `/overview`, `/proposals`, `/evidence/{id}`, `/actors/{id}/{timeline,graph,risk}`, `/events`, `POST /feedback/{id}` ; vue réduite sans adresses (`horsVueReduite`) |
| Décisions : actord ne bloque jamais lui-même ; il publie des propositions et des mesures | EXISTANT | `main.go:60-66` (`--shadow=false` refusé) ; `propositions.go:13-16,94` ; fichiers `/run/secubox/actord-propositions.json` et `/run/secubox/actord-mesures.json` (unité, l. 39-40) |
| Lien avec sbxwaf : application par le WAF, avec ses propres garde-fous | EXISTANT | `tng/cmd/sbxwaf/actorban.go:5-17` : il faut une preuve locale (≥ `--actor-ban-min` 2 sanctions), les adresses privées et protégées sont exclues, plafond de 20 bans/h, un fichier périmé ne produit rien. Échelle appliquée par `tng/cmd/sbxwaf/mesures.go:100-208` (plafond `--mesures-max-bans-heure` 20) |
| Temps réel | PARTIEL | L'ingestion est continue, mais les propositions sont republiées périodiquement (`propositions.go:94` `publierPropositions(chemin, pas)`) et relues par le WAF à chaque `Tick` (`actorban.go:160,239`). La latence entre la détection et le drop vaut au moins la période des deux boucles, de l'ordre de la seconde à la minute. NON VÉRIFIÉ au banc |
| Détection volumétrique propre à un DDoS (débit global, nombre de sources, pics de SYN) | ABSENT | Recherche `ddos`, `syn.?flood` sur `*.go`/`*.py` : aucun résultat dans actord ni dans sbxwaf. Le modèle d'actord est comportemental (qui fait quoi), pas volumétrique |

---

## 1.2 SBX WAF (`sbxwaf`, Go)

Sources : `tng/cmd/sbxwaf/*.go`. Unité : `secubox-waf-ng/systemd/secubox-waf-ng.service`. API d'administration : `secubox-waf-ng/composants/waf/api/main.py`.

| Capacité | Statut | Référence |
|---|---|---|
| Détection HTTP (règles, inspection, profils de vhost, anomalies d'hôte, leurres) | EXISTANT | `inspect.go`, `rules.go`, `vhostprofiles.go`, `hostanomaly.go`, `leurrehttp.go`, `toolprint.go`, `antirobots.go`, `crawlers.go` |
| Adresse cliente réelle derrière HAProxy | EXISTANT | `inspect.go:155-175` (`clientIP`) : le XFF n'est cru que si le pair immédiat fait partie de `trustedProxies` (`inspect.go:31-40`) |
| Fenêtre glissante par IP (3 hits en 300 s), table plafonnée à 100 000 IP | EXISTANT | `ban.go:4-43` |
| Ban individuel natif nft : `inet secubox` sets `waf_ban`/`waf_ban6`, timeout par élément, chaîne d'entrée de priorité -100 | EXISTANT | `nftban.go:20-40,126-141` ; `--nft-ban` actif dans l'unité (l. 141) ; durée par défaut 4 h (`main.go:1275`) |
| IPv4 et IPv6 | EXISTANT | `nftban.go:126-127,139-140` (deux sets) ; `setPour` (`nftban.go:153`) |
| Expiration | EXISTANT | timeout nft par élément (`nftban.go:217`) ; réévaluation à l'échéance avec RELEASE ou EXTEND gradué, plafond 30 j (`main.go:1341`, `reevaluation.go:45-180`, `--reevaluation auto` dans l'unité l. 145) |
| Persistance des bans (`bans.jsonl`) et réinjection au démarrage | EXISTANT | `banstore.go:17-23,52,75` ; `nftban.go:247-280` (`Reload`) ; `/var/lib/secubox/waf/bans.jsonl` (`main.go:1273`) |
| Auto-réparation si `flush ruleset` efface la table | EXISTANT | `nftban.go:285-345` (`Presente`, `Reparer`, `Veiller`) |
| Bans de campagne (sondes de haute valeur, durée 4 h / 24 h / 7 j, plafond 30/h) | EXISTANT | `campagneban.go:4-35` ; `--campagne-ban auto` (unité l. 144) |
| Ban sur leurre | EXISTANT (optionnel) | `leurreban.go` ; `--leurre-ban` seulement dans `secubox-waf-ng/conf/honeypot.conf` |
| Autoban « propose » | EXISTANT | Modes `off\|propose\|auto` pour `--actor-ban`, `--campagne-ban`, `--mesures`, `--reevaluation` (`main.go:1336-1345`). **Dans l'unité livrée, ils sont tous à `auto`** (`secubox-waf-ng.service:143-146`) ; `propose` est un réglage, pas le défaut |
| Exceptions / liste blanche | PARTIEL | Exclusion en dur des adresses privées, de boucle locale, lien-local et multicast, plus `--actor-ban-protegees` (`actorban.go:86-121`). **Dans le paquet générique, l'unité fige une plage propre à une box** : `--actor-ban-protegees 82.67.100.75/32,2a01:e0a:dec:c4e0::/60` (`secubox-waf-ng.service:147`). Il n'y a pas de liste blanche administrateur déclarative (TOML) partagée par tous les chemins de ban |
| Bans manuels et levée de ban par l'API | EXISTANT | `secubox-waf-ng/composants/waf/api/main.py:1660` (`GET /bans`), `:1752` (`/bans/history`), `:1779` (`POST /ban`), `:1915` (`POST /unban/{ip}`), `:1986` (`/autoban/config`) ; toutes sous `require_jwt` ou `require_lecture` |
| Rate limiting HTTP par IP ou par vhost dans sbxwaf | ABSENT | Recherche `rate.?limit\|ratelimit\|token.?bucket` dans `tng/cmd/sbxwaf` : seul un commentaire sur Nextcloud (`nextcloud.go:36`) |
| Gestion des robots | EXISTANT | `antirobots.go`, `crawlers.go` ; compteurs par famille dans actord (`/robots`, `server.go:293`) |
| Ban par préfixe (/24, /48) ou par ASN | ABSENT | Recherche `CIDRMask(24`, `prefix.*ban`, `asn.*ban` : rien. Le ban se fait adresse par adresse |
| Capacité des sets nft du WAF | NON VÉRIFIÉ | Pas de `size` explicite dans `nftban.go:126-127`. Le comportement sous un grand nombre d'éléments, sur une carte de 1 à 4 Go, reste à mesurer |

---

## 1.3 Réseau

| Capacité | Statut | Référence |
|---|---|---|
| nftables en DEFAULT DROP (entrée) | EXISTANT | `secubox-hardening/nft/nftables.conf:22-24` (`policy drop`) ; installé par le `postinst` (l. 33-62, avec validation `nft -c` avant bascule) |
| Drop-ins `/etc/nftables.d/*.nft` et inclusions de site et de confiance | EXISTANT | `nftables.conf:36,70,72` ; `secubox-hardening/debian/rules:39` |
| Réinitialisation globale : `flush ruleset` en tête de la base | EXISTANT (risque) | `nftables.conf:20`. Toutes les tables créées dynamiquement (WAF, rate-limit) disparaissent à chaque rechargement. Le WAF se répare seul (`nftban.go:285-345`) ; le rate-limit ne se recharge pas (voir plus bas) |
| Garde WAN : ports de backend et de leurre fermés sur `eth2` et `br-lan`, jonction du maillage 7331 réservée au LAN | EXISTANT | `secubox-hardening/nft/secubox-wan-guard.nft:21-40`. Le nom d'interface `eth2` est figé en dur |
| Rate limit SYN avant le WAF (`inet secubox_waf_ratelimit`) | PARTIEL | `secubox-waf-ng/config/secubox-waf-ratelimit.nft:31-70`, chargé par `secubox-waf-ng/systemd/secubox-waf-ratelimit.service` (oneshot, `RemainAfterExit`). Trois limites : (a) `limit rate over 30/second burst 50` **sans compteur par source** (l. 66-69), donc un seuil global : en cas de pic, toute source dont le SYN tombe au-delà du seuil part 5 min dans `offenders_v4`, y compris un client légitime ; (b) la règle n'alimente que `offenders_v4` (`ip saddr`), donc **le SYN IPv6 n'est pas limité**, et la liste blanche n'existe qu'en v4 (l. 48-52) ; (c) la table n'est pas dans `/etc/nftables.d`, donc un `flush ruleset` l'efface sans qu'aucune réparation la recharge. Les trois points sont NON VÉRIFIÉS au banc |
| SYN cookies | EXISTANT | `secubox-hardening/conf/99-secubox-hardening.conf:81` (`tcp_syncookies = 1`) ; profil « security » de nettweak (`secubox-qos/composants/nettweak/api/main.py:348-349`, `tcp_max_syn_backlog 4096`) |
| rp_filter (anti-usurpation) | EXISTANT | `99-secubox-hardening.conf:67-68` |
| Réglage de conntrack (`nf_conntrack_max`, timeouts) | ABSENT | Recherche `nf_conntrack_max` dans `packages/` : aucun résultat. La table conntrack garde la taille par défaut du noyau, ce qui est critique sur une carte de 1 Go en cas de flood |
| UDP : limitation de débit | ABSENT | Ports UDP ouverts sans limite (`nftables.conf:42,44` : 3483 et WireGuard 51820-51825) |
| ICMP : limitation de débit | ABSENT | `nftables.conf:29-30,51` : `ip protocol icmp accept` sans `limit` ; pas de `icmp_ratelimit` dans le sysctl de durcissement |
| Capteur de balayage de ports | EXISTANT | `secubox-hub/nftables.d/zz-secubox-scan-tap.nft:10-15` (sets v4/v6, timeout 10 min, taille 65 536), lu par `tng/cmd/sbxwaf/scansensor.go` |
| Liste noire agrégée (flux de menaces) | PARTIEL | `secubox-toolbox/nftables.d/secubox-blacklist.nft:32-79` ; alimentée par `secubox-toolbox/sbin/secubox-blacklist-sync` (consensus de 2 sources ou poids ≥ 80, l. 45-50 ; plafond de 50 000, l. 21 ; TTL 2 h, l. 18 ; rien de plus large qu'un /8 en v4 ou un /32 en v6, l. 116). **La chaîne est en `hook forward`** (`secubox-blacklist.nft:68`) : elle protège le LAN routé, **pas la box elle-même** (HAProxy, SSH) |
| HAProxy frontal TLS | EXISTANT | `secubox-haproxy/sbin/haproxyctl:1060` (`maxconn 4096`), `:1066-1068` (`timeout connect 5s`, `client 30s`, `server 30s`) |
| HAProxy : limitation par source (stick-table, `sc_http_req_rate`, `tcp-request connection reject`) | ABSENT | Recherche `stick-table\|sc_http_req_rate\|tcp-request` dans `secubox-haproxy` : aucun résultat |
| HAProxy : anti-slowloris (`timeout http-request`) | ABSENT | 0 occurrence de `timeout http-request` ou `http-keep-alive` dans `haproxyctl`. Seul `timeout client 30s` borne la connexion |
| Garde-fous administrateur (ne jamais couper l'admin) | PARTIEL | SSH limité au LAN et à 10/8 (`nftables.conf:33,38-39`) ; adresses privées jamais bannies par le WAF (`actorban.go:109-121`, `campagneban.go`) ; liste blanche v4 privée du rate-limit (l. 48-52). Il n'y a pas de liste d'administrateurs publics commune à tous les mécanismes (WAF, rate-limit, meshban, blacklist), et la seule plage publique protégée est figée dans l'unité (voir 1.2) |
| Interfaces WAN et LAN | PARTIEL | Noms figés en dur (`eth2`, `br-lan`, `wg-mesh`) dans `secubox-wan-guard.nft` et `nftables.conf:46-48` ; pas de résolution déclarative du WAN dans les règles DDoS |

---

## 1.4 MirrorNet / maillage

Le code contient **trois sous-systèmes distincts**. Les confondre fausserait la conception.

### A. Fédération signée des bans (annuaire) : le seul partage de bans réellement signé

| Capacité | Statut | Référence |
|---|---|---|
| Modèle `BanRecord` signé en Ed25519, auto-certifié (auteur = éditeur), TTL `expires_at` | EXISTANT | `secubox-annuaire/annuaire/model.py:723-744` |
| Publication et révocation (une box ne lève que ses propres bans) | EXISTANT | `secubox-annuaire/annuaire/verbs.py:1937-1974` (`publish_ban`, `revoke_ban`) |
| Journal chaîné BLAKE2b, signature vérifiée à l'ajout | EXISTANT | `secubox-annuaire/annuaire/log.py:112-140` (`append` vérifie la signature), `:224` (`verify_chain`) ; synchronisation `annuaire/mesh_sync.py:13` |
| Union fédérée et application nft (`inet secubox_meshban`, set `banned`, hook input priorité -5) | PARTIEL | `annuaire/threatmesh.py:27-56` : **IPv4 seulement** (`is_ipv4`, l. 20-24 et 29) ; table entière reconstruite à chaque passage ; minuterie toutes les 60 s (`systemd/secubox-annuaire-bans-apply.timer:8`, `annuairectl:401-411`) |
| Droit d'abonnement « bans-waf » (sinon seules les bans locales s'appliquent) | EXISTANT | `annuaire/droits.py:172-190` (`bans_a_appliquer`, validité de 48 h, audité) |
| Consensus (N box d'accord avant d'appliquer) | ABSENT | `verbs.py:1977-2014` : l'union est un simple OU, et un seul membre suffit à bannir une IP pour tout le maillage |
| Plages protégées et liste blanche admin côté meshban | ABSENT | `threatmesh.py:27-41` ne filtre que le type d'adresse ; aucune exclusion des plages privées, du maître ou des administrateurs |
| TTL obligatoire | ABSENT | `annuairectl:471` : `--ttl` vaut `None` par défaut, ce qui donne `expires_at = None`, donc un ban **permanent** (`model.py:741`) |
| Alimentation automatique par sbxwaf ou actord | ABSENT | Aucune occurrence de `annuaire` ni de `publish_ban` dans `tng/cmd/sbxwaf` ou `sbx-actord`. Le seul appelant de `publish_ban` est `annuairectl` (l. 374-377, manuel). L'ancien pont `sbx-threatmesh-bridge` est cité dans `secubox-annuaire/debian/changelog:543` mais **sa source n'est pas dans le dépôt** ; il lisait l'ancien moteur de décisions externe retiré (#1218) |
| API de lecture | EXISTANT | `secubox-annuaire/api/main.py:774` (`GET /bans`, `require_lecture`) |
| Profils MirrorNet (révisions de profil réseau) | EXISTANT (hors sujet ban) | `annuaire/mirrornet/__init__.py` : génération de profils réseau portés par `ConfigBlob`. Rien sur la défense collective |

### B. `secubox-threatmesh` (démon :8780) : un échange de bans non signé

| Capacité | Statut | Référence |
|---|---|---|
| Diffusion des décisions locales aux pairs (`secubox-p2p/peers.json`) | EXISTANT | `secubox-threatmesh/api/main.py:165-179` (`mesh_gossip_once`), boucle `:182` |
| Ingestion des pairs | PARTIEL, non conforme | `api/main.py:236-251` : `POST /mesh/ingest` **sans garde, sans signature, `node` auto-déclaré**. Le docstring dit lui-même « Trust boundary = the WireGuard mesh transport ». IPv4 seulement (`IPV4`, l. 43) ; jusqu'à 20 000 IP par appel ; pas de TTL (upsert en base `toolbox.db`, `threat_intel`) |
| Exposition | Non conforme à AGENTS.md | `systemd/secubox-threatmesh.service:13` : `uvicorn --host 0.0.0.0 --port 8780`, donc un port TCP au lieu d'une socket Unix ; filtré par `nftables.d/secubox-threatmesh.nft:3-10` (accepté seulement depuis `lo` et `wg*`) |
| Effet réel | PARTIEL | Les IP reçues deviennent des lignes `threat_intel` de poids 70 (`api/main.py:249`). `secubox-blacklist-sync` ne les arme que si 2 sources concordent ou si le poids atteint 80 (l. 45-50), et dans une chaîne **forward** seulement. Une IP du maillage ne bloque donc pas un flood dirigé vers la box |
| Flux publics de menaces | EXISTANT | `secubox-threatmesh/sbin/secubox-threatfeed:32-53` (abuse.ch, firehol, Spamhaus DROP v4/v6, etc.) |

### C. `secubox-p2p` : identité, ancre du maître, élection, DHT

| Capacité | Statut | Référence |
|---|---|---|
| Ancre du maître (la box refuse tout autre maître) | EXISTANT | `secubox-p2p/api/ancre.py:5-8,62-66` (`accepte`), audit `:67` |
| Heartbeat signé du maître et élection | EXISTANT | `secubox-p2p/api/masterlink.py:24-59` (`sign_heartbeat`, `verify_heartbeat`), `:90` (`elect`) |
| Découverte DHT avec enregistrements signés en Ed25519 | EXISTANT | `secubox-p2p/api/dht.py:127-190` (`canonical_record`, `sign_record`, `verify_record`) |
| WireGuard du maillage, état des pairs (handshakes, vivacité) | EXISTANT | `secubox-p2p/api/mesh.py:164,354-410` (`render_wg_conf`, `load_handshakes`, `peer_liveness`, `statut_registre`) |
| Nœuds indisponibles | PARTIEL | Vivacité calculée (`mesh.py:377`) ; pour les bans, les droits restent valables 48 h quand le maître est injoignable (`droits.py:174-175`). Il n'existe pas de file de rattrapage dédiée aux bans hors de la convergence du journal annuaire |
| Relais | EXISTANT (hors sujet DDoS) | `secubox-p2p/sbin/secubox-relais-maillage` ; test `secubox-p2p/tests/test_relais_policy_drop_3130.py` |
| Score de confiance par pair pour les bans reçus | ABSENT | Aucune pondération par éditeur dans `verbs.py:_get_bans` ni dans `threatmesh/api/main.py:upsert_iocs` (poids fixe 70) |

---

## 1.5 SBXOS / Hall / tableaux de bord sécurité

| Capacité | Statut | Référence |
|---|---|---|
| Console Actor Intelligence | EXISTANT | `secubox-waf-ng/www/actor/index.html` ; `secubox-webos/www/actor-intelligence/index.html` |
| Vigie SOC (statut, carte des menaces et attaques, alertes, pairs, arbre du maillage) | EXISTANT | `secubox-soc/api/main.py:232-815` (`/status`, `/summary`, `/map/threats`, `/map/attacks`, `/alerts`, `/mesh/peers`, `/mesh/status`, `/mesh/tree`…) ; pages `secubox-soc/www/soc/{index,guardian,reseau}.html` |
| État du réseau en direct (menaces et bans de sbxwaf par jour) | EXISTANT | `secubox-live/live/collecte.py:9-13,53-56` (lit `waf-threats.log` et `bans.jsonl`) ; `secubox-live/www/live/` |
| Tableau ThreatMesh | EXISTANT | `secubox-threatmesh/www/threatmesh/index.html`. Il reflète le démon B, **pas** l'union fédérée A |
| Panneaux d'état des bans automatiques | EXISTANT | fichiers d'état `/var/lib/secubox/waf/{actor,campagne}-ban-etat.json` (`main.go:1337,1347`) |
| SBXOS (Hall) | NON VÉRIFIÉ | `secubox-sbxos/` n'est livré qu'en bundle (`dist/assets/*.js`) ; aucun widget DDoS ou meshban n'a été identifié dans les sources lisibles |
| Vue DDoS dédiée (débit SYN, conntrack, sources par seconde, état du mode d'urgence) | ABSENT | Aucune page ni route trouvée (recherche `ddos`, `conntrack` dans `www/` et `api/`) |

---

## Composants réutilisables

1. **actord** : signature multi-signal, graphe d'acteurs, campagnes, échelle de réponse graduée et explicable, mode shadow. C'est la base naturelle pour qualifier une attaque distribuée (`correlate.go`, `api.go:campagnes`, `response.go`).
2. **Garde-fous de ban du WAF** : preuve locale, plafond horaire, exclusion des plages privées et protégées, fichier périmé ignoré, modes `off|propose|auto`, journal annulable (`actorban.go`, `campagneban.go`, `mesures.go`). Ils sont à généraliser.
3. **Ban nft natif du WAF** : sets v4/v6 à timeout, chaîne de priorité -100, persistance JSONL, auto-réparation après `flush ruleset` (`nftban.go`, `banstore.go`). C'est le modèle à suivre pour toute nouvelle table DDoS.
4. **BanRecord de l'annuaire** : Ed25519, journal chaîné, révocation par l'éditeur, TTL, droit d'abonnement (`model.py:723`, `verbs.py:1937`, `droits.py:172`). C'est le bon support pour une défense collective signée.
5. **Identité p2p** : ancre du maître, heartbeat signé, DHT signée (`ancre.py`, `masterlink.py`, `dht.py`).
6. **Capteur de balayage** (`zz-secubox-scan-tap.nft` et `scansensor.go`) : c'est le modèle d'un capteur nft vers actord.

## Écarts majeurs

1. Aucune détection volumétrique : ni débit SYN, ni sources par seconde, ni saturation de conntrack. actord et sbxwaf sont comportementaux.
2. Le rate-limit SYN est global, IPv4 seulement, et n'est pas réparé après `flush ruleset` (`secubox-waf-ratelimit.nft:66-69`).
3. Rien n'est limité par source avant TLS : pas de stick-table HAProxy, pas de `timeout http-request`, pas de meter nft par source. Pas de limite UDP ni ICMP, et pas de réglage de conntrack.
4. Le partage de bans entre box n'est pas alimenté par le WAF ni par actord. La fédération signée (annuaire) ne reçoit que des bans manuels ; le démon threatmesh échange sans signature, et ses IP finissent dans une chaîne forward.
5. La fédération n'a ni consensus, ni plages protégées, ni TTL obligatoire, ni IPv6 ; un seul membre compromis peut bannir n'importe quelle IP sur tout le maillage, y compris un administrateur.
6. Les listes blanches sont dispersées (WAF : flag de l'unité ; rate-limit : v4 privé ; meshban : rien ; blacklist : `nft-input-trust.d`). Il n'existe pas de source unique pour les administrateurs.
7. Une IP propre à une box est figée dans l'unité générique (`secubox-waf-ng.service:147`), et les noms d'interface (`eth2`) sont codés en dur.

## Risques de régression

- **Coupure de l'administrateur** : un rate-limit global ou une union fédérée sans exclusion peut bannir l'IP publique de l'administrateur (4G, réseau d'hôtel). Il faut une liste blanche administrateur commune, consultée **avant** toute règle de drop, et un retour arrière automatique (TTL court, puis confirmation).
- **Faux positifs NAT / CGNAT / IPv6 /64** : des centaines d'usagers partagent une adresse v4 (opérateurs mobiles, CGNAT Free). Un seuil par IP les traite comme un seul acteur. En IPv6, bannir une /128 ne sert à rien face à un attaquant qui tourne dans sa /64. Il faut des seuils par préfixe, avec prudence.
- **CDN, proxies et robots légitimes** : les adresses de CDN ou de proxies d'entreprise, et les robots connus, dépassent facilement les seuils. Il faut réutiliser `crawlers.go` et l'action « robot », et ne jamais bannir au pays seul (`similarity.go:30`).
- **Mémoire ARM 1-4 Go** : conntrack par défaut, sets nft sans `size` (`nftban.go:126`), table de 100 000 IP du WAF (`ban.go:12-16`, environ 8 Mo), graphe actord rejoué jusqu'à 50 000 événements, et un ingest threatmesh qui accepte 20 000 IP par appel. Chaque nouveau set doit avoir un `size` et une politique d'éviction, et le flood doit être absorbé par le noyau (nft, conntrack), pas par Python ou Go.
- **`flush ruleset`** : toute nouvelle table hors de `/etc/nftables.d` disparaît au rechargement (constat déjà documenté pour le WAF, `nftban.go:285-296`).
- **WAN mvpp2** : ne jamais toucher au MTU ni faire de down/up sur l'interface WAN à distance. Les mesures DDoS doivent rester purement nft et sysctl.

## Proposition d'architecture cible (NON implémentée, à valider)

```
              Internet
                 │
   [N0] noyau : sysctl (syncookies, conntrack dimensionné, icmp_ratelimit)
                 │
   [N1] nft inet secubox_ddos (drop-in /etc/nftables.d, priorité -150)
        ├─ allow_admin{4,6}  (source unique /etc/secubox/ddos.toml) → accept
        ├─ meter SYN/UDP/ICMP par source (v4 /32, v6 /64), size borné
        ├─ sets ddos_ban{4,6} timeout   ← sbxwaf / actord / maillage
        └─ compteurs globaux → capteur ddos (comme scan-tap)
                 │
   [N2] HAProxy : stick-table par source, timeout http-request, maxconn par frontal
                 │
   [N3] sbxwaf : comportement, bans gradués existants (inchangés)
                 │
   actord : nouvelle famille d'événements « volumétrique » + campagne DDoS
                 │ propositions (shadow → propose → auto)
   [MirrorNet] BanRecord annuaire signé, TTL OBLIGATOIRE, IPv4+IPv6,
               consensus ≥ k éditeurs OU confiance de l'éditeur,
               exclusion allow_admin + privé + maître, plafond par éditeur
```

Principes : le noyau absorbe le flood, actord qualifie, sbxwaf applique, et le maillage partage seulement des bans
signés, à TTL, en mode propose par défaut. La décision de sécurité reste locale à la box cible (vision headless).
Chaque décision passe par `/var/log/secubox/audit.log`.

### Plan proposé

- **Plan A, durcissement local, sans maillage** (risque faible) : TOML `ddos.toml` avec une liste blanche administrateur unique ;
  table `secubox_ddos` en drop-in (meters par source v4 et v6/64, bornés) ; correction ou remplacement de
  `secubox-waf-ratelimit.nft` (par source, IPv6, inclus dans `nftables.d`) ; sysctl conntrack et ICMP ; HAProxy
  `timeout http-request` et stick-table. Déploiement d'abord en compteurs seuls (shadow), puis en drop après mesure au banc
  (gk4/gk5/gk6), jamais directement sur gk2.
- **Plan B, qualification par actord** : un capteur DDoS nft vers actord (sur le modèle de scan-tap), une détection de campagne
  volumétrique et une proposition vers sbxwaf avec les garde-fous existants (`propose` par défaut).
- **Plan C, défense collective MirrorNet** : sbxwaf ou actord publient des `BanRecord` (TTL obligatoire, IPv6), avec consensus k-sur-n ou
  confiance par éditeur, exclusions communes et plafond par éditeur ; meshban en v4 et v6 ; mise en conformité ou retrait de
  l'ingest non signé de `secubox-threatmesh` (port 0.0.0.0:8780) ; un tableau de bord SOC dédié.

Ordre recommandé : A, puis B, puis C. Chaque étape est validée au banc avant l'étape suivante.
