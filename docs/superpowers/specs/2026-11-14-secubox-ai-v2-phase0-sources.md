<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox AI V2 — phase 0 : audit des sources de sécurité de gk2 (#3718)

Annexe de [`2026-11-14-secubox-ai-v2-design.md`](2026-11-14-secubox-ai-v2-design.md) (§ 4, 6, 7, 14, 15).
Relevé du **2026-11-14 vers 12 h (CET)** sur gk2 (`192.168.1.200`, secubox-waf-ng 1.35.2, secubox-core 1.8.32,
secubox-toolbox-ng 0.14.0, secubox-security-posture 2.6.0) et gk3 (`192.168.1.9`, secubox-ai 0.1.2).

Méthode : **lecture seule**. `ls`, `stat`, `getfacl`, `head`/`tail`, `wc`, `nft -j list`, `systemctl cat/show`,
`journalctl`, statistiques calculées **sur gk2** par `python3` en flux (rien de copié hors de la box, racine à 77 %),
GET depuis gk3 sur `https://admin.gk2.secubox.in/api/v1/…` sans jeton (comme `menaces.py`). Rien n'a été écrit,
relancé ni installé. Un seul effet de bord : le GET de sonde sur `/waf/ai/etat` sans jeton a produit, comme prévu par
`compte_service.py`, une ligne `compte-service refus motif=absent ip=192.168.1.9` dans `/var/log/secubox/audit.log`
(11:09:43Z) — c'est la sonde de cet audit, pas un incident.

Les adresses des exemples ci-dessous sont **remplacées par des plages de documentation** ; les autres champs sont réels.

## 1. Synthèse

| Source | Où (gk2) | Volume / jour | Id stable | Horodatage | Route de lecture actuelle (garde) | Collecte V2 recommandée |
|---|---|---|---|---|---|---|
| Journal des menaces (sbxwaf + sbx-authwatch) | `/var/log/secubox/waf/waf-threats.log` | 13 400 – 19 800 lignes, 6 – 7,6 Mo | **aucun** | ISO 8601 à la seconde, **heure locale** `+01:00` | `/waf/alerts` (`require_lecture`) : 500 dernières lignes au plus, sans curseur | **route à ajouter** : flux par position `inode:octet` ; d'ici là `/waf/alerts?limit=500` toutes les 30 s |
| Journal des bans | `/var/lib/secubox/waf/bans.jsonl` | ≈ 2 100 lignes, 235 Ko | `id` dérivé (ip, at) par `/waf/enforcement` | époque (s) `at`, `exp` | `/waf/enforcement` (`require_lecture`), 30 j relus à chaque appel (2,5 – 4,7 s) | **paramètre `depuis` à ajouter** ; d'ici là `/waf/enforcement?limite=1000` toutes les 5 min |
| Bans actifs (nft) | `inet secubox waf_ban` (2 508), `waf_ban6` (0) | instantané | adresse | `expires` relatif (s) | `/waf/bans` (`require_lecture`), 586 Ko | instantané toutes les 5 min, différence d'ensembles |
| Blocs /24 | `inet secubox_waf_blocs blocs4` (0) + `ai-ban.jsonl` | 0 – 2 | `id` (32 hex) | ISO UTC + époque | `/waf/ai/etat` (**`require_ai_ban`** seulement) | route du compte de lecture (§ 4) |
| Ban du maillage | `inet secubox_meshban banned` (0), `secubox_threatmesh` (aucun ensemble) | 0 | — | — | aucune | hors V2 (Q10) |
| sbx-authwatch | dans le journal des menaces (`tool = authwatch`) + `waf_ban` + journald | 660 – 1 280 lignes, **toutes** `auth_smtp:sasl_failed` | aucun | idem menaces | `/waf/alerts` | avec le journal des menaces |
| Leurres HTTP / honeypot | journal des menaces : `category = honeypot` ; champs `leurre`, `filigrane` | 36 – 55 `honeypot` ; 355 – 786 lignes avec `leurre` | `filigrane` (16 hex) | idem menaces | `/waf/alerts` | avec le journal des menaces |
| Leurres de service (ports) | sbx-authwatch écoute 9 ports | **0** (fermés côté WAN par nft) | — | — | — | aucune (voir § 3.6) |
| Campagnes du WAF | `/var/cache/secubox/waf/campaigns.json` (minuterie 5 min) | 249 campagnes, 1 552 attaquants | `signature` (16 hex) | aucun dans le fichier | `/waf/campaigns` (`require_lecture`), **20 premières** seulement | instantané toutes les 5 min |
| Réévaluations à l'échéance | `/var/lib/secubox/waf/reevaluations.jsonl` | ≈ 1 250 lignes, 310 Ko | aucun | époque `ts` | `/waf/reevaluations?limite=N` (`require_lecture`), 5 000 dernières lignes | toutes les 5 min, `limite=1000` |
| Décisions de ban (acteurs, campagnes) | `actor-ban-etat.json`, `campagne-ban-etat.json` | instantané | — | époque `genere_le` | `/waf/decisions` (`require_lecture`) | instantané toutes les 5 min |
| Mesures Actor Intelligence | `/var/lib/secubox/waf/mesures.jsonl` | ≈ 9 000 lignes, 2,5 Mo | `actor` (ACT-nnnn) | époque `ts` | **aucune** | route à ajouter (phase 2, facultatif) |
| security-posture | API `secubox-security-posture` | instantané (cache 5 min) | — | ISO UTC | `/security-posture/overview` (`require_lecture`) | toutes les 15 min, contexte |
| Journal d'audit | `/var/log/secubox/audit.log` ; `/var/log/secubox/waf/audit.log` | ≈ 4 400 ; ≈ 1 160 lignes | aucun | ISO UTC `Z` | **aucune** générale | pas en V2 ; l'état `ai-ban` suffit |
| DNS (dns-guard) | `/var/lib/secubox/dns-guard/alerts.jsonl` | ≈ 100 lignes | `id` (`dns-…`) | ISO UTC `Z` | `/dns-guard/alerts` (`require_jwt`) | hors V2 (Q10) |
| DNS (Unbound) | journald, `log-queries/replies/local-actions: yes` | ≈ 2,5 M lignes | — | journald | aucune | **non** (volume, vie privée) |
| nDPI | `secubox-ndpid-engine` (sockets `/run/secubox/ndpi/`) | — | — | — | `/ndpid/flows` (`require_jwt`) | hors V2 (Q10) |

Chiffres des 24 h : 15 604 lignes de menaces le 13/11 (1 472 `high`, 13 358 `medium`, 771 `info`, 1 `critical`),
10 071 le 14/11 à 12 h ; `/waf/stats` donne 1 461 menaces « bloquées » et 8 620 « observées » le 14/11, 2 790 sur
24 h glissantes ; 2 113 lignes de `bans.jsonl` sur 24 h ; 2 508 bans actifs.

## 2. Chemin gk3 → gk2

- gk3 résout `admin.gk2.secubox.in` en `192.168.1.200` (Unbound de gk2). Le vhost a `waf_bypass = false` : la requête
  suit HAProxy TLS 1.3 → sbxwaf → nginx → `location /api/v1/waf/` → `/run/secubox/aggregator.sock` (les modules sont
  servis par l'agrégateur). nginx marque `192.168.1.0/24` comme LAN (`secubox-lan-geo.conf`, `geo $lan_client`).
- `secubox-ai.service` sur gk3 : `IPAddressDeny` des plages privées, puis `IPAddressAllow=127.0.0.1/32 192.168.1.200/32
  192.168.1.3/32 10.100.0.85/32` par le drop-in que `secubox-aictl preparer` écrit depuis `ai.toml`
  (`menaces_url = "https://admin.gk2.secubox.in/api/v1"`). **La future unité `secubox-ai-veille` devra recevoir le même
  drop-in** (au moins `192.168.1.200/32`), sinon elle ne joint pas gk2.
- Mode tableau de bord **actif** sur gk2 (`/etc/secubox/secubox.conf`, `[tableau_de_bord] actif = true`) : toutes les
  routes `require_lecture` répondent 200 à gk3 sans jeton. Temps mesurés depuis gk3 : `/waf/alerts` 35 ms, `/waf/stats`
  50 ms, `/waf/campaigns` 73 ms, `/waf/bans` 0,46 s (586 Ko), `/waf/bans/history` 0,47 s, `/waf/history` **10,4 s**
  (agrégat de tous les journaux tournés, cache 1 h), `/waf/enforcement` **2,5 – 4,7 s**, `/security-posture/overview`
  92 ms. `require_jwt` (`/waf/info`, `/dns-guard/alerts`, `/ndpid/flows`) → 401 ; `/waf/ai/etat` → 401.

**Ce que tait le lecteur anonyme : rien.** Aucune route du WAF ni de security-posture ne consulte le marqueur
`tableau_de_bord` du pseudo-payload (seuls `ad-guard` et `mirrornet` le font). Le lecteur anonyme du LAN reçoit donc
adresses, agents utilisateurs, chemins, comptes visés (`/waf/stats` → `comptes_vises`), pays, empreintes HTTP. Pour la
V2 ce n'est pas un manque ; c'est une **exposition** à signaler : tout poste du LAN lit l'intégralité de la veille de
gk2. La décision Q2 (compte de service de lecture) est confirmée ; resserrer le lecteur anonyme du WAF est une issue à
part (propriétaire : `secubox-waf-ng`), à ne faire **qu'après** le passage de `menaces.py` au compte de lecture, sinon
le Radar 0.1.x perd ses données.

## 3. Sources, une par une

### 3.1 Journal des menaces — `waf-threats.log` (sbxwaf + sbx-authwatch)

- **Chemin** : `/var/log/secubox/waf/waf-threats.log`, `secubox-waf:secubox-waf 0660` + ACL `user:secubox-live:r`,
  `user:secubox-cve-leurres:r` ; dossier `secubox-waf:secubox 2750` + ACL. Écrivains : sbxwaf (ouvre, écrit, referme à
  chaque ligne) et sbx-authwatch (groupe `secubox-waf`, `ReadWritePaths=/var/log/secubox/waf`).
- **Rotation** : `/etc/logrotate.d/secubox-waf`, quotidienne vers 00 h 30 **et** `maxsize 20M`, `rotate 7`, `compress`,
  `delaycompress`, `create 0660`, par **renommage** (l'inode change : 262286 → `.1`, nouveau 262213). Le `.1` reste en
  clair un jour. Rétention 7 j + le jour courant.
- **Volume** (7 jours) : 13 420 – 19 840 lignes/jour, ≈ 6 – 7,6 Mo/jour en clair (≈ 480 o/ligne).
- **Format** : JSON par ligne. Champs toujours présents (chaînes) : `timestamp`, `client_ip`, `host`, `method`, `path`,
  `category`, `severity`, `rule_id`, `action`, `user_agent`. Facultatifs : `tool` (chaîne, suffixe `?` = supposé),
  `http_fingerprint` (16 hex), `behavior_traits` (liste de chaînes), `negative_space` (`known_negative`),
  `leurre` (`racine`…), `filigrane` (16 hex). `client_ip` vaut **`local`** pour le LAN (718 – 1 534 lignes/jour, en
  grande partie `identity.gk3.secubox.in` interrogé par un client aiohttp de gk3).
- **Valeurs** : `severity` ∈ {`info`, `medium`, `high`, `critical`, `audit`} ; `action` ∈ {`detect`, `banned`, `robot`,
  `warning`, `body-inspect-skipped`}. Familles du 13/11 : `host_anomaly:unrouted` 13 032, `auth_smtp:sasl_failed`
  1 282, `recon_crawler` 474, `scanners` 326, `robots` 297, `host_anomaly:ip_literal` 143, `honeypot` 36,
  `host_anomaly:dga` 8, `webmail` 2, `sqli` 1, `host_anomaly:empty` 1 ; le 14/11 apparaît `waf_fingerprint`.
  Outils : `moissonneur-secrets?`, `client-automatise?`, `authwatch`, `sondeur-console?`, `scanner-cms?`,
  `fuzzer-repertoire?`, `robot`, `zgrab`, `masscan`, `httpx`…
- **Horodatage** : seconde, **décalage local** (`+01:00` aujourd'hui, `+02:00` l'été). À convertir en UTC à l'ingestion.
- **Identifiant** : aucun. **Doublons exacts réels** : 60 à 105 clés (horodatage, adresse, famille, hôte, chemin)
  répétées par jour, jusqu'à 8 fois — des requêtes distinctes dans la même seconde. Une empreinte du seul contenu
  (§ 6 de la conception) **fusionnerait des événements réels** : l'identité doit inclure la position dans le fichier.
- **Exemples** :

  ```json
  {"timestamp":"2026-11-14T00:36:03+01:00","client_ip":"203.0.113.21","host":"smtp","method":"","path":"gege","category":"auth_smtp:sasl_failed","severity":"high","rule_id":"authentification SASL refusee — compte inexistant « gege »/1","action":"banned","user_agent":"","tool":"authwatch"}
  {"timestamp":"2026-11-14T00:41:08+01:00","client_ip":"198.51.100.40","host":"anibal-amiot.net","method":"GET","path":"/","category":"host_anomaly:unrouted","severity":"medium","rule_id":"","action":"banned","user_agent":"Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)","tool":"client-automatise?","http_fingerprint":"f07dd2a8327ce472","behavior_traits":["entetes:pauvres","entetes:accept-generique","nav:sans-cookie"],"leurre":"racine","filigrane":"f63a9dd23387f73b"}
  ```

- **Route actuelle** : `GET /waf/alerts?limit=N&aggregate=false` (`require_lecture`). Sert un cache chaud rafraîchi
  toutes les **30 s** (`WAF_WARM_INTERVAL`) depuis les **512 Ko** de fin du fichier, plafonné à **500 lignes**, plus
  récentes d'abord, plus `country` (GeoIP). Au rythme du 14/11, 500 lignes = **≈ 44 min** (11:25 → 12:09) ; une rafale
  (campagne `d9f3227654369a11` : 277 sondes en 32 s) la ramène à quelques minutes. Pas de paramètre `depuis`, pas de
  position. `/waf/history` (tendances par jour, 10 s, cache 1 h) et `/waf/bans/history?hours=&limit=` (agrégat par
  adresse) sont des **agrégats**, pas un flux.
- **Bruit à écarter à l'ingestion** : `client_ip = local` (marqué, pas jeté : il sert à voir le LAN) ; le banc
  d'autotest écrit **ailleurs** (`waf-selftest.log`), le journal des menaces en est propre.

### 3.2 Journal des bans — `bans.jsonl`

- **Chemin** : `/var/lib/secubox/waf/bans.jsonl`, `secubox-waf:secubox-waf 0640` + ACL `user:secubox-live:r`.
  Écrivain : sbxwaf. **Aucune rotation** : 96 324 lignes, 10,4 Mo depuis le 20/08 ; inode stable.
- **Volume** : 2 113 lignes, 235 Ko sur 24 h.
- **Format** : `{"ip": str, "cat": str, "sev": str, "at": int, "exp": int, "action": "ban"|"unban"}` ; `cat` porte la
  famille et le suffixe `|prolonge` (réarmement) ; préfixes `leurre:`, `mesure:ACT-nnnn`, `campagne:<signature>`.
  Exemple : `{"ip":"198.51.100.56","cat":"host_anomaly:ip_literal|prolonge","sev":"high","at":1794654410,"exp":1795259210,"action":"ban"}`.
- **Répartition 24 h** : `leurre` 837, `mesure` 541, `host_anomaly` 199, `scanners` 121, `campagne` 84, `honeypot` 48 ;
  **`lfi` 244, `xss` 37, `sqli` 1 : tous sur `198.51.100.77`, l'autotest du WAF** (`SecuBox-WAF-SelfTest/1`). Ils
  sont aussi présents dans `waf_ban`. Durées : 1 h, 4 h, 24 h, 7 j.
- **Absents** : les bans de **sbx-authwatch** (82 sur 24 h selon son journal) ne sont **pas** écrits dans
  `bans.jsonl` — seulement dans `waf_ban` et dans la ligne `action = banned` du journal des menaces.
- **Horodatage** : époque en secondes (UTC). **Identifiant** : aucun dans le fichier ; `/waf/enforcement` dérive
  `id` = 12 hex de (ip, at) (`enforcement.identifiant`).
- **Route** : `GET /waf/enforcement?statut=&limite=` (`require_lecture`) relit les 30 derniers jours **en entier** à
  chaque appel (64 330 actions, 2,5 – 4,7 s), plafond 1 000. Champs : `id`, `type`, `target`, `reason`,
  `source_decision`, `severity`, `duration_s`, `created_at`, `expires_at`, `status`, `rollback`.

### 3.3 Bans actifs — ensembles nft

- `inet secubox waf_ban` (`ipv4_addr`, `flags timeout`, compteurs par élément) : **2 508** éléments ; `waf_ban6` : 0.
  `inet secubox_waf_blocs blocs4` (`interval, timeout`) : 0 ; `inet secubox_meshban banned` : 0 ;
  `inet secubox_threatmesh` : aucun ensemble. Lecture : root (ou `sudo -n nft` pour le compte `secubox`).
- **Route** : `GET /waf/bans` (`require_lecture`), cache chaud 30 s : `{bans: [{ip, value, scenario, reason, famille,
  duration, expires_in, type, origin, id: null, created_at: "", country, asn, asn_org}], total, application:{etat, ok,
  detail, dernier_ban, verifie}}` — 586 Ko. `origin` vaut toujours `sbxwaf`, même pour les bans d'authwatch.
  `application` vient de `/var/cache/secubox/waf/nft-etat.json` (sbxwaf, toutes les 30 s) : distingue « 0 ban » de
  « table effacée ».
- Blocs /24 et gestes IA : `/var/lib/secubox/waf/ai-ban.jsonl` (`{ts, at, type: ban|annule, id, cible, fin, mode,
  conseil, motif, jti, cle, duree_s, cause}`, 2 lignes, essai du 14/11 sur `203.0.113.0/24`), servis par
  `GET /waf/ai/etat` gardé **par `require_ai_ban` seul** (401 sans jeton, et le refus est audité).

### 3.4 sbx-authwatch

- Unité `secubox-authwatch.service` (`/usr/sbin/sbx-authwatch`) : journaux de l'hôte et du LXC `mail`
  (`/data/lxc/mail/rootfs/var/log/journal`), comptes de `/data/volumes/mail/config/users`, filtres
  `/etc/secubox/authwatch/services.json` (gitea SSH et web, nextcloud ; peertube inactif), seuil 6 / 10 min, ban 4 h.
- **Sorties** : (1) le journal des menaces (`tool = "authwatch"`), (2) `waf_ban` directement (CAP_NET_ADMIN), (3) son
  journal systemd (`BAN <ip> ← <famille> (<détail>, total n)`). Aucun fichier propre.
- **Réalité sur 7 jours** : **une seule famille**, `auth_smtp:sasl_failed` (660 – 1 280 lignes/jour, 82 bans/jour au
  journal). Zéro SSH de l'hôte (SSH root limité au LAN), zéro IMAP, zéro gitea, zéro nextcloud.

### 3.5 Leurres HTTP et honeypot (sbxwaf)

- `category = "honeypot"`, `rule_id = honey-0nn`, `action` `warning` ou `banned` : 36 – 55 lignes/jour (chemins
  `/phpinfo.php`, `/wp-admin/install.php`…). Champs `leurre` (`racine`) et `filigrane` (16 hex) sur 355 – 786 lignes/jour
  de `host_anomaly:unrouted` : la page leurre servie et sa marque, ce qui permet de reconnaître un retour.
- `secubox-cve-leurres.timer` (10 min, `secubox-cvectl leurre compter --json`) : `{"leurres": 0}` — aucune touche des
  leurres CVE à ce jour. Route : celle du module CVE (non relevée, 0 donnée).

### 3.6 Leurres de service (ports)

sbx-authwatch écoute 3389, 3306, 27017, 6379, 5432, 1433, 5900, 23, 9200 ; la règle nft
`iifname "eth2" tcp dport { 23, 1433, 3306, 3389, … } drop` (#1306) les ferme **côté WAN** (97 709 paquets écartés au
compteur) et `br-lan` aussi (#3206). **Ils ne peuvent rien produire** : source morte par conception, à ne pas compter
comme couverture. Le compteur nft est le seul signal (sans adresse).

### 3.7 Campagnes du WAF

- `secubox-waf-campaigns.timer` (5 min) → `/var/cache/secubox/waf/campaigns.json` (`secubox-waf 0644`, 120 Ko) :
  `{attaquants: 1552, campagnes: [249 × {signature, outil, attaquants: [ip…], sondes, exemple_sequence: [chemins],
  haute_valeur}]}`. Pas d'horodatage par campagne ; instantané.
- **Route** : `GET /waf/campaigns` (`require_lecture`) : **20 premières campagnes** sur 249, séquence tronquée à 12,
  `nb_attaquants` ajouté. Les bans qui en découlent : `campagne-ban-etat.json` (`/waf/decisions`) et
  `cat = campagne:<signature>` dans `bans.jsonl`.

### 3.8 Réévaluations, décisions, mesures

- `reevaluations.jsonl` (`secubox-waf 0640`, sans rotation, 33 297 lignes depuis le 10/10, 1 251/jour) :
  `{ts, ip, categorie, paquets, compteur, recidives, decision: RELEASE|EXTEND, duree_s, raison, mode, applique,
  version}`. Route `GET /waf/reevaluations?limite=` (5 000 dernières lignes, totaux). Doublon : chaque décision est
  aussi écrite dans `/var/log/secubox/waf/audit.log` (`action = reevaluation`, ≈ 1 160/jour, sans rotation, 5 Mo).
- `actor-ban-etat.json`, `campagne-ban-etat.json` : décisions du tour courant (`candidats`, `decision`
  `ecarte:deja_banni`…, plafond horaire) → `GET /waf/decisions`.
- `mesures.jsonl` (Actor Intelligence, `secubox-waf 0640`, **74 Mo sans rotation**, ≈ 9 000 lignes et 2,5 Mo/jour) :
  `{ts, actor: "ACT-nnnn", ip, niveau: TARPIT|DENY|DELAY|CHALLENGE, risque, confiance, decision, expire, raison, mode,
  applique, version}`. **Aucune route** ne l'expose.

### 3.9 security-posture

`GET /security-posture/overview` (`require_lecture`, cache 5 min) : `{timestamp (UTC, µs), overall{level, name, color,
emoji, blink, score}, coverage, domains[6], findings[], cspn{…}, tpn{…}}`. Aussi `/defcon`, `/findings`,
`/domains/{d}`. Contexte de la box, pas d'événement d'attaque ; 15 min suffisent.

### 3.10 Journal d'audit

- `/var/log/secubox/audit.log` : `secubox:secubox 0660` + ACL `secubox-pilotage:rw`, règle générale
  `/etc/logrotate.d/secubox` (quotidien + `maxsize 20M`, 14, renommage). Formes JSON hétérogènes (`{ts, module, action,
  result, detail}`, `{ts, module, acteur, appelant, evenement, …}`), ≈ 4 400 lignes/jour, dominé par `antirootkit` et
  `pilotage`. Les gestes IA y sont (`module = waf`, `action = ai-ban-demande | ai-ban | ai-unban`, `by = ai-ban`) ainsi
  que les refus du compte de service (`module = compte-service`). **Aucune route de lecture générale.**
- Pour la V2 : l'état des gestes se relit par `/waf/ai/etat` ; une route d'audit n'est **pas** nécessaire en phase 2.

### 3.11 DNS et nDPI (hors premier périmètre, Q10)

- Unbound journalise requêtes, réponses et actions locales dans journald : ≈ 105 000 lignes/heure. Inutilisable tel
  quel (volume, vie privée du LAN) ; à ne pas collecter.
- dns-guard : `/var/lib/secubox/dns-guard/alerts.jsonl` (`secubox 0640`, 104 lignes/24 h, `id` stable `dns-…`, ISO
  UTC) ; `type` `malicious` (98 %), `tunneling`, `high_rate`, `dga`, `exfiltration` ; `client_ip` = poste du LAN
  (`10.100.0.10` = LXC mail). Route `GET /dns-guard/alerts?hours=` (`require_jwt`).
- nDPI : `secubox-ndpid-engine` actif (sockets `/run/secubox/ndpi/`), API `secubox-ndpid` : `/ndpid/flows`, `/top/*`
  (`require_jwt`). Pas d'événements de sécurité prêts à consommer.

## 4. Compte de service de lecture (Q2) — ce qu'il doit couvrir

Mécanisme repris de `common/secubox_core/compte_service.py` (branche #3716) : clé Ed25519 privée sur gk3, publique
sous `/etc/secubox-comptes-service/<compte>/` (aujourd'hui `ai-ban/` contient une clé, celle du POC gk0), jeton par
requête (`jti` unique, ≤ 60 s, `aud` = gk2, `corps` = SHA-256 du corps — `b""` pour un GET).

Points relevés pour la phase 2 :

1. **Liste fermée** : ajouter `"ai-lecture": "waf-lecture"` à `COMPTES_SERVICE` (et son dossier de clés, posé par
   `wafctl` root comme `ai-ban`).
2. **Contrainte P9** : le jeton lie le corps, pas le chemin. Pour un GET le corps est vide : un jeton `ai-lecture` vaut
   pour **toutes** les routes que ce compte ouvre. Acceptable si le compte n'ouvre que des GET sans effet ; plus propre :
   ajouter les réclamations `methode` et `chemin` (prévu par le docstring) avant d'ouvrir le compte.
3. **Composition de gardes** : les routes sont aujourd'hui `require_lecture` ; `require_lecture` refuse un jeton EdDSA
   puis, sur le LAN, **retombe en lecteur anonyme** (mode tableau de bord actif) — un jeton de compte mal formé passerait
   donc silencieusement en anonyme. Il faut une garde `require_lecture_ou_compte("ai-lecture")` qui, **si un porteur
   EdDSA est présent**, le vérifie ou refuse (jamais de repli anonyme).
4. **Mémoire de rejeu** : un processus unique (agrégateur `--workers 1`) ; ≈ 4 GET/min de la veille (§ 5) = ≈ 6 000 `jti`/jour,
   chacun gardé ≈ 65 s : moins de 10 en mémoire, loin de `REJEU_MAX`.
5. **Audit des refus** : chaque refus écrit dans `audit.log` (une ligne par motif toutes les 10 s) ; une veille mal
   réglée qui boucle sur 401 le remplirait lentement — la veille doit espacer après un refus.

**Routes que le compte `ai-lecture` doit ouvrir (GET seulement)** :

| Route | Module propriétaire | Garde actuelle | Usage V2 |
|---|---|---|---|
| `/waf/alerts` | secubox-waf-ng | `require_lecture` | flux des menaces (en attendant la route à curseur) |
| `/waf/menaces/flux` *(à créer)* | secubox-waf-ng | — | flux à curseur `inode:octet` (§ 5) |
| `/waf/enforcement` (+ `depuis` *à créer*) | secubox-waf-ng | `require_lecture` | journal des bans avec `id` |
| `/waf/bans` | secubox-waf-ng | `require_lecture` | bans actifs + état d'application |
| `/waf/campaigns` (+ `limite` *à créer*) | secubox-waf-ng | `require_lecture` | campagnes (toutes, pas 20) |
| `/waf/decisions` | secubox-waf-ng | `require_lecture` | décisions acteurs / campagnes |
| `/waf/reevaluations` | secubox-waf-ng | `require_lecture` | RELEASE / EXTEND |
| `/waf/stats` | secubox-waf-ng | `require_lecture` | compteurs de rapprochement (±1 %, critère phase 2) |
| `/waf/ai/etat` | secubox-waf-ng | `require_ai_ban` | blocs /24 et gestes IA (lecture) |
| `/waf/geoip/{ip}` | secubox-waf-ng | `require_lecture` | pays d'une adresse hors fenêtre |
| `/security-posture/overview` | secubox-security-posture | `require_lecture` | contexte |
| `/waf/mesures` *(à créer, facultatif)* | secubox-waf-ng | — | mesures Actor Intelligence |

À **ne pas** ouvrir : `/waf/history` (10 s par appel, agrégat), `/waf/bans/history` (agrégat), `/waf/info`,
`/waf/rules`, toute route POST. `/dns-guard/alerts` et `/ndpid/*` attendront Q10.

## 5. Collecte recommandée par source

| Source | Curseur | Intervalle | Identité d'un événement |
|---|---|---|---|
| Menaces (route à créer) | `inode:octet` de la dernière ligne lue ; à l'inode changé, finir `waf-threats.log.1` (en clair grâce à `delaycompress`) puis repartir à 0 | 30 s (cache chaud du WAF) | `inode:octet` de la ligne (unique, conserve les doublons réels) |
| Menaces (repli actuel) | dernier `timestamp` + compte des lignes de cette seconde déjà vues | 30 s, `limit=500` | (horodatage, rang dans la seconde, empreinte du contenu) ; trou signalé si la plus ancienne ligne reçue est plus récente que le curseur |
| Bans | `at` maximal vu (route `depuis`) ; repli : `limite=1000` | 5 min | `id` de `/waf/enforcement` |
| Bans actifs | instantané | 5 min | adresse ; apparition / disparition par différence |
| Blocs /24, gestes IA | instantané | 5 min | `id` |
| Campagnes | instantané | 5 min | `signature` |
| Décisions | instantané (`genere_le`) | 5 min | (`source`, `target`, `genere_le`) |
| Réévaluations | `ts` maximal vu | 5 min, `limite=1000` | (ts, ip, decision) |
| Posture | instantané (`timestamp`) | 15 min | `timestamp` |

Normalisation : convertir les horodatages locaux en UTC ; `famille` = partie avant `:` de `category`/`cat`,
`sous_famille` = après, suffixe `|prolonge` → attribut ; marquer `client_ip = local` ; **écarter les plages de
documentation** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) des bans et des corrélations (autotest du WAF,
essais `ai-ban`), sans les supprimer de la base.

## 6. Manques et points bloquants

1. **Bloquant pour le critère « 24 h sans trou » de la phase 2** : pas de flux à curseur pour le journal des menaces.
   `/waf/alerts` n'offre que 500 lignes (≈ 44 min, quelques minutes en rafale) et l'identité par contenu fusionne des
   doublons réels (jusqu'à 8 par seconde). → Route `GET /waf/menaces/flux?depuis=<inode>:<octet>&max=N` dans
   **secubox-waf-ng** (lecture, bornée, avec la position de chaque ligne et le passage par `.1`).
2. **`/waf/enforcement` coûte 2,5 – 4,7 s** (relit 30 j de `bans.jsonl` à chaque appel) et n'a pas de `depuis`.
   → paramètre `depuis=<époque>` (et lecture depuis la fin) dans secubox-waf-ng.
3. **Bans de sbx-authwatch absents de `bans.jsonl`** : la famille la plus fréquente (`auth_smtp:sasl_failed`) n'a
   d'historique de ban que par la ligne `action = banned` du journal des menaces. → soit authwatch écrit aussi dans
   `bans.jsonl` (secubox-toolbox-ng), soit la V2 le documente comme tel.
4. **`/waf/campaigns` tronque à 20 campagnes sur 249** → paramètre `limite` (secubox-waf-ng).
5. **Le lecteur anonyme ne tait rien** sur le WAF : exposition à traiter à part, après le passage au compte de lecture
   (§ 2).
6. **Compte `ai-lecture`** : garde composée sans repli anonyme et réclamations `methode`/`chemin` (§ 4) avant ouverture.
7. **Journaux sans rotation sur gk2** (racine à 77 %) : `mesures.jsonl` 74 Mo (+2,5 Mo/j), `waf-selftest.log` 27 Mo
   (104 562 lignes), `bans.jsonl` 10 Mo, `reevaluations.jsonl` 8 Mo, `waf/audit.log` 5 Mo. Hors V2 mais à ouvrir en
   issue (secubox-waf-ng / toolbox-ng) : la V2 ne doit pas compter sur leur profondeur.
8. **Sources mortes ou muettes** : leurres de service fermés côté WAN, filtres SSH / IMAP / gitea / nextcloud à zéro
   sur 7 jours, `secubox_meshban` et `secubox_waf_blocs` vides. Le corrélateur (règles multi-sources, phase 3) n'aura,
   à ce jour, que **web (sbxwaf)** et **SMTP (authwatch)** : un incident multi-sources réel sera rare.
9. **Bruit LAN** : `client_ip = local` vers `identity.gk3.secubox.in` (client aiohttp de gk3) ≈ 700 – 1 500 lignes/jour
   classées `host_anomaly:unrouted` — à comprendre côté gk3 (hors V2).

## 7. gk3 (Q9)

Mesuré le 14/11 vers 12 h, LXC `mail` en marche, `secubox-kiosk` actif : racine NVMe 453 Go, **345 Go libres** (20 %
occupés) ; `/var/lib/secubox/ai` = 771 Mo ; mémoire 7,6 Gio, **3,5 Gio disponibles**, échange 2,7 / 11,8 Gio utilisés ;
4 cœurs. Estimation de `veille.db` : ≈ 18 000 événements/jour × ≈ 1 Ko (ligne + index) ≈ 18 Mo/jour, **≈ 550 Mo pour
30 jours** : Q9 tient largement ; le seuil de garde de 1 Gio libre est sans risque.

## 8. Reste à faire en phase 0

- ≥ 200 événements de référence anonymisés dans `packages/secubox-ai/tests/donnees/` (familles vues : les 13 de § 3.1,
  bans `leurre`/`mesure`/`campagne`/`|prolonge`, réévaluations RELEASE/EXTEND, une campagne, un état `ai-ban`).
- Ouvrir les issues des routes manquantes (§ 6, points 1 à 4 et 6) dans les paquets propriétaires.
