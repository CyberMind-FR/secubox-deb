<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🛡️ secubox-waf-ng — Go WAF engine (`sbxwaf`)

> **WIP / not yet cut over.** This package ships the new host-native Go WAF
> engine that replaces the Python `mitmproxy` inspection layer. The binary and
> package are built and parity-tested; production cutover is **gated** — follow
> [`docs/CUTOVER.md`](docs/CUTOVER.md). See issue #744.

**Category:** Security

## What it is

`sbxwaf` is a single host-native Go binary that reverse-proxies the HAProxy
`mitmproxy_inspector` backend to the internal vhosts while inspecting, blocking,
and banning — a drop-in, perf-first replacement for the `mitmproxy 11` + Python
addons WAF. It shares an extracted core (`internal/forge`, `internal/httpcodec`,
`internal/relay`, `internal/reload`) with the toolbox R3 engine `sbxmitm`.

## Features

- **Vhost routing** — `haproxy-routes.json`, hot-reloaded (mtime); unmapped host → 421 ; adresse isolée par secubox-garde (`/run/secubox/garde/isoles.json`, `--garde-isoles` ; cru seulement si sûr — pas de lien, à secubox-garde ou root, non inscriptible par d'autres — et frais, < 600 s ; adresses publiques jamais exemptées) → page d'explication 200 `no-store`, sans anomalie ni ban, une ligne `isolé-servi` par adresse et par minute (#3800)
- **Regex WAF engine** — `waf-rules.json` (SQLi/XSS/LFI/RCE/CVE…), case-insensitive, hot-reload
- **PHP2Shell (`php2shell`, rules 1.7.0)** — multipart bodies sent to a PHP vhost are captured as a stream and checked by structural signatures (`php2shell-001` to `-008`), `detect` mode only: logged, never blocked or banned. A vhost is PHP when its service is listed in `php_services` (`vhost_profiles.json`: nextcloud, roundcube) **or** its normalised host matches a `php_hotes` pattern (shipped: `^(nc|nextcloud|cloud)\.`, `^(webmail|roundcube)\.`; an invalid pattern is rejected alone). Every client is analysed, LAN and 127.0.0.1 included (logged as `local`, never sent to actord). The body is read the way PHP 8.2 reads it: `main/rfc1867.c` transcribed (not `mime/multipart`), sticky `skip_upload` included, and checked against a C oracle built from `rfc1867.c` (reviewer probes, 300 000 random bodies and differential fuzzing, no divergence). Assumed PHP settings: defaults (`max_file_uploads=20`, `file_uploads=On`, `upload_max_filesize` ≥ 1 MiB, no mbstring encoding translation). The capture window is **min(`--max-body-inspect`, 1 MiB)**, whatever the text-inspection cap; up to 16 concurrent multipart captures plus 8 urlencoded ones, so at worst 24 MiB. Log statuses: `multipart-tronque`, `multipart-malforme`, `multipart-limite`, `capture-concurrence` (#3273: full semaphore, 16 multipart or 8 urlencoded captures, signal `genre` 1 or 2; written after the response, at most one line per second per `genre`, the next one carrying `supprimees`, the number of lines dropped meanwhile) (severity `audit` = 10, counted as *states*, not threats, by the panel); every multipart line carries `ja4` and `tool`. `vhost_profiles.json` is read at start only: after editing `php_services` or `php_hotes`, restart `secubox-waf-ng` and check the line `sbxwaf: vhosts PHP armés : N explicites, M motifs`. **Rollback**: set `"enabled": false` on the `php2shell` category of `/etc/secubox/waf/waf-rules.json` (hot reload): no category with a structural signature means no capture at all, and a body kind (XML prologue, start of a WebDAV `PUT`, urlencoded) is captured only while an enabled category reads it. `waf-rules-sync` keeps an operator's `"enabled": false` across upgrades (audited when the shipped copy enables the category); a `true` follows the shipped copy, so a package can still disable a category, and `waf-profils-fusion` never re-adds a `php_services`/`php_hotes` entry the operator removed. Or install the previous package.
- **Equivalent PHP signatures (`roundcube`, `nextcloud`, `php_requete`, rules 1.7.0, #3273)** — three more categories, `"mode": "detect"` and `"enabled": true`, inserted before `php2shell` (which stays last). Same guarantee as PHP2Shell: logged with the real severity of the signature, never blocked, banned or escalated, and the relayed request is untouched. Each signature carries `cve`, `confidence`, `desc` and `source`; thresholds without a primary source carry `"seuil": "provisoire, non sourcé (2026-10-29)"` (`php2shell-002`, `-003`, `-006`, `-007`).
  - `roundcube` (`"services": ["roundcube"]`): `rc-001` `_from` outside the characters the fix accepts (CVE-2025-49113, CVE-2026-114724; critical); `rc-002` session-serialisation markers in a multipart `filename` (high); `rc-003` CR/LF/NUL in IMAP parameters (`_uid`, `_flag`, `_q`, `_filter`, …) or an invalid `_flag` (high); `rc-004` CR/LF/NUL in mail header fields on send (medium; `_to`, `_cc`, `_bcc`, `_message` are deliberately not read); `rc-005` markasjunk `POST` with `_uid` in the query string (low); `rc-006` non-raster image (SVG, EPS, PS, PDF, MVG magic bytes) uploaded as a contact photo or settings image (high).
  - `nextcloud` (`"services": ["nextcloud"]`): `nc-001` anonymous `POST` on a federated-share path while federation is unused (medium); `nc-002` more than 5 such calls per 1 200 s and per IP (high); `nc-003` `PROPPATCH` on `calendar-proxy-read|write` (medium); `nc-004` same, with a Basic user different from the `<uid>` of the path (high); `nc-005` WebDAV `PUT` of a raster name whose first 64 bytes are a non-raster format (medium).
  - `php_requete` (every PHP vhost, no service): `php-001` more than 1 020 parts, `php-002` `DOCTYPE`/`ENTITY` in an XML prologue, `php-003` cookie name that PHP normalises into `__Host-`/`__Secure-`, `php-004` and `php-005` multipart boundary above 70 / 5 120 characters (the status becomes `malforme` above 70 while the PHP counters are kept), `php-006` `PHP_SESSION_UPLOAD_PROGRESS` present, `php-007` PHP-CGI `-d` option probe. `php2shell-005` to `-008` complete PHP2Shell: body without usable length, parts with 9 headers or more, 21 empty file fields or more, more than 1 000 urlencoded variables.
  - Services: a signature with `services` only fires on vhosts of that service; a host recognised only by a `php_hotes` pattern (service empty) gets every family. `federation_vhosts` (in `vhost_profiles.json`, shipped empty, read at start only) lists the Nextcloud hosts whose operator uses federation: absent, every anonymous federated share is a medium signal.
  - What is read per check: the query string and the capture window (`min(--max-body-inspect, 1 MiB)`) already captured by #3257, for each retained name its first and last occurrence plus at most one suspicious middle one (CR, LF, NUL or an invalid IMAP flag character), so a `_uid[]` array cannot hide a CRLF between two clean values, 64 bytes of magic number per file, the XML prologue (4 096 bytes) and the start of a WebDAV `PUT` (64 bytes) captured without a token, the `Cookie` lines, and headers only for the rest. Never a body, file name or parameter value in the log. Tool labels (`behavior_traits` `outil:<label>`, and the `tool` field when empty) aggravate a line but never raise its severity.
  - Rollback: `"enabled": false` per category in `/etc/secubox/waf/waf-rules.json` (hot reload); with no active structural category nothing is captured. `waf-rules-sync` keeps that `false` across upgrades. The panel (`/php/signaux`, cached, flagged `perime` after 10 minutes) shows counts per family, rule, vhost and public address.
  - Known limits: IPv6 addresses are not grouped by /64 for the `nc-002` counter (4 096 IPs at most, so a /64 can fill it); Nextcloud chunking v1 (`/remote.php/dav/uploads/…` v1 layout) is not covered; `nc-004` is a false positive when a client logs in with its e-mail address (identifier different from the `<uid>`), accepted in `detect` and to be measured; `/php/signaux` reads only the current threat log and its `.1` rotation, not older `.N.gz` files. Roundcube `1.6.5+dfsg-1+deb12u12` stays vulnerable to 113386, 114720, 114724, 114725 and 114727: these signatures spot attacks, they do not fix them.
- **Graduated ban** — sliding window (300 s / threshold 3) → WARNING then BAN, append-only threat log
- **sbx-actord load (#3320, 1.33.0)** — in-memory actor graph pruned at the event retention; consolidation incremental through the index every 10 min; proposals recomputed every 90 s (file rewritten only when changed, at least every 5 min for sbxwaf freshness), measures kept at 30 s (event cache 25 s); `--workers` defaults to 1; a rejected batch is replayed event by event; ingestion and evidence ledger written in batches (≤ 256 events / 200 ms per transaction); prune in batches of 5 000 keys; bbolt `NoFreelistSync` + map freelist; unit: `--workers 1`, `GOMEMLIMIT=180MiB GOGC=50`, `MemoryHigh=200M` under `MemoryMax=256M`. The evidence ledger still has no retention (it is a proof): follow-up.
- **Native nftables bans** — `inet secubox` sets `waf_ban`/`waf_ban6` (4 h), decisions emitted to `sbx-actord` (campaigns, decoys); external blocking bridge removed (#1218)
- **RGPD cookie-audit** — per `Set-Cookie` JSONL, values SHA-256-hashed (raw value never stored)
- **Media-cache** — 16 MB/obj, 2 GB total, per-vhost keyed, `Flusher` passthrough for progressive media
- **Themed error pages** — 502/503/504 (Host HTML-escaped — no reflected XSS)
- **Hardened** — dedicated `secubox-waf` user, `NoNewPrivileges`, `ProtectSystem=strict`, seccomp, AppArmor enforce, `RuntimeDirectoryPreserve=yes`

## Architecture

```
Internet ──TLS1.3──▶ HAProxy :443 ──▶ backend mitmproxy_inspector
                                         │  (cutover: server → host sbxwaf)
                                         ▼
                       sbxwaf workers (secubox-waf-ng-worker@1..2, 127.0.0.1:808x)
                       ├─ routes → rules → ban (nft) → sbx-actord
                       ├─ cookie-audit · media-cache · error pages
                       ▼
                       backends 10.100.0.0/24
```

## Installation

```bash
sudo apt install secubox-waf-ng
# provision the WAF CA at /etc/secubox/waf/ca/ and the rules at
# /etc/secubox/waf/waf-rules.json (COMPLETE corpus — must contain log4shell),
# then: systemctl enable --now secubox-waf-ng-worker@1 secubox-waf-ng-worker@2
```

## Configuration

- `/etc/secubox/waf/haproxy-routes.json` — vhost → backend map (hot-reload)
- `/etc/secubox/waf/waf-rules.json` — WAF regex rules (hot-reload)
- `/etc/secubox/waf/vhost_profiles.json` — per-vhost adaptive rules (#1080, read at start only):
  `services.<name>.legit_paths`, optional `services.<name>.suppress_categories` (applied to that
  service's legit paths only, #3193 — e.g. `livekit`: `credential_harvest` on `/rtc/v1`), `vhosts`
  (host → service), global `suppress_categories`, `anti_robots`. Conffile edited at runtime: on
  upgrade `waf-profils-fusion` adds the shipped services/vhosts that are missing
  (reference copy `/usr/share/secubox/waf/vhost_profiles.json`), never an operator value.
- `/etc/secubox/waf/ca/` — forge CA (cert + key)
- Logs: `/var/log/secubox/waf/waf-threats.log`, `/var/log/secubox/cookie-audit/server.jsonl`
- Cache: `/var/cache/secubox/waf/media`

## Bans de bloc /24 et compte de service `ai-ban` (#3716, 1.35.0)

Une box d'IA (POC sur gk0) propose des bans à partir des alertes ; elle n'écrit dans le pare-feu de la box que par
trois routes gardées, et un bloc /24 ne se bannit que par `waf-blocs`, en root.

**Table `inet secubox_waf_blocs`** (à part de `inet secubox`, que sbxwaf vide et recrée) : ensemble `blocs4`
(`ipv4_addr`, `interval, timeout`, compteur), chaîne `entree` (crochet `input`, priorité -101, juste avant `waf_drop`),
règle `ct direction original ip saddr @blocs4 counter drop` : seuls les flux ouverts par le bloc sont coupés, les
réponses aux connexions que la box ouvre (DNS, apt, ACME) passent. Fichier livré : `/usr/share/secubox/waf/blocs.nft`.
État root : `/var/lib/secubox-waf-blocs/blocs.json` (dossier root 0700, fichier 0600), fin de chaque bloc. L'unité
`secubox-waf-blocs` rejoue la table et ses blocs (temps **restant**) au démarrage et à chaque rechargement de
`nftables.service` ; la minuterie `secubox-waf-blocs-veille` (60 s, `waf-blocs reparer`) remet ce qui manque après
un `nft -f` direct. IPv4 seulement.

**Gardes de `waf-blocs`** (pour tout ban, adresse ou bloc) : jamais le privé, une plage de
`/etc/secubox/waf/protegees.env` (`SECUBOX_WAF_PROTEGEES=…`, une ligne, virgules), une adresse d'une interface de la
box, ni un point de terminaison WireGuard. Une source illisible refuse (`garde_illisible`). **Un bloc est refusé tant
que `protegees.env` n'a aucune ligne `SECUBOX_WAF_PROTEGEES`** : derrière un NAT l'adresse publique n'est sur aucune
interface, et le paquet ne la devine pas. Le postinst sème un fichier **commenté** s'il est absent (jamais écrasé) ;
l'administrateur y écrit l'IPv4 publique en /32 et le préfixe IPv6 de la box (ou la ligne vide
`SECUBOX_WAF_PROTEGEES=` s'il n'y a rien de plus à protéger), puis redémarre `secubox-waf-ng` pour sbxwaf.

**Verbes `wafctl`** (le compte `secubox` les a par sudo ; `ban-bloc` et `unban-bloc` passent par `systemd-run`) :

| Verbe | Effet |
|---|---|
| `wafctl ban-bloc <a.b.c.0/24> <durée>` | bannit un /24 canonique, 1 h à 7 j ; un rebannissement ne raccourcit jamais |
| `wafctl unban-bloc <a.b.c.0/24>` | retire le bloc (table et état) |
| `wafctl blocs` | liste JSON des blocs non échus, temps restant, présence dans nft |
| `wafctl ban <ip> <durée> --exiger-protegees` | ban d'adresse d'office du compte `ai-ban` (#3723) : la garde exige `protegees.env` et sa ligne `SECUBOX_WAF_PROTEGEES`, comme pour un bloc |
| `wafctl leurre <ip> <N>s` / `wafctl leurre-lever <ip>` | #3723 : redirection d'une adresse publique IPv4 ou IPv6 vers le théâtre de sbxwaf (1 h à 7 j, sinon `refus:duree`) : remplacement atomique de `/var/lib/secubox/waf/leurres-ip.json` sous verrou ; sortie `{"fin": <epoch>}` ou `refus:<motif>` (`plein` au-delà de 2 048) ; garde d'office ; sudoers `SBX_WAF_LEURRE` |
| `wafctl limiter <ip> <N>s` / `wafctl limiter-lever <ip>` | #3723 : limite de débit d'une adresse publique IPv4 ou IPv6 (1 h à 24 h, sinon `refus:duree`) dans `limite_ia_v4`/`limite_ia_v6` ; ajout et nouveau délai en UNE transaction nft ; sortie `{"fin": <epoch>}` ou `refus:<motif>` ; garde d'office ; sudoers `SBX_WAF_LIMITER` |
| `wafctl prolonger <ip> <N>s` | #3723 : prolonge une adresse DÉJÀ dans `waf_ban` par UNE transaction `nft -f` (`delete element` puis `add element … timeout`), jamais un simple `add` dont le délai ne serait pas rafraîchi ; absente : `refus:absent` ; garde d'office ; IPv4 ; sudoers `SBX_WAF_PROLONGER` |
| `wafctl cle-ai-ban ajouter <fichier.pub>` | **root seul**, hors sudoers : pose une clé publique Ed25519 sous `/etc/secubox-comptes-service/ai-ban/<empreinte>.pub` (root 0644 ; empreinte = SHA-256 hex du DER, le `kid` des jetons) ; deux clés au plus |
| `wafctl cle-ai-ban retirer <empreinte>` / `retirer --toutes` | **root seul** : révoque une clé, ou toutes (effet à la requête suivante) |
| `wafctl cle-ai-ban lister` | empreintes posées, et si le nom de fichier est la vraie empreinte |
| `wafctl cle-ai-filtres ajouter\|retirer\|lister` | **root seul**, même code pour le compte `ai-filtres` (#3732, 1.37.0) : `/etc/secubox-comptes-service/ai-filtres/` |

Réponse : une ligne JSON `{"ok", "motif", …}` ; codes de sortie `invalide` 1, `privee` 2, `protegee` 3, `box` 4,
`pair` 5, `garde_illisible` 6, `nft` 7, `duree` 8, `etat` 9, `audit` 10, `incoherent` 11, `usage` 64. Chaque geste
est une ligne de `/var/log/secubox/audit.log`.

**Rotation de la clé** : générer la nouvelle paire **sur la box de l'IA** (la privée ne la quitte jamais), copier la
`.pub` sur la box, `sudo wafctl cle-ai-ban ajouter /tmp/nouvelle.pub` (deux clés valent le temps de la bascule),
basculer le relais sur la nouvelle privée, puis `sudo wafctl cle-ai-ban retirer <ancienne empreinte>`. Une troisième
clé est refusée. **Révocation d'urgence** : `sudo wafctl cle-ai-ban retirer --toutes` — plus aucun jeton `ai-ban`
n'est accepté. Une mise à jour du paquet ne vide jamais ce dossier.

**Routes `/api/v1/waf/ai/*`** — garde `require_ai_ban` (`secubox_core.compte_service`), exception écrite à
`RULES-CODE` § 3 : en-tête `Authorization: Bearer <jeton EdDSA>` (`kid`, `sub="ai-ban"`, `aud` = nom court de la box,
`portee="waf-ban"`, `exp - iat` ≤ 60 s, `jti` à usage unique, `corps` = SHA-256 hex du corps brut, `b""` pour un GET).
Jeton absent, invalide, échu ou rejoué : 401 ; audience d'une autre box, sujet ou portée : 403 ; corps de plus de
16 Kio : 413.

| Route | Corps | Réponse |
|---|---|---|
| `POST /ai/ban` | `{"geste": "ban", "cible": "198.51.100.7" ou "203.0.113.0/24", "duree_s": 3600…604800, "mode": "clic"\|"auto", "conseil": "<id>", "motif": "<200 car.>"}` | 200 `{id, cible, fin, duree_s, audit}` |
| `POST /ai/prolonger` | `{"geste": "prolonger", "id": "<32 hex>", "duree_s": <s>, "conseil": "<id>", "motif": "<200 car.>"}` (#3723, 1.43.0) | 200 `{id, cible, fin, audit}` |
| `POST /ai/limiter` | `{"geste": "limiter", "cible": "<IPv4 ou IPv6 publique>", "duree_s": 3600…86400, "conseil": "<id>", "motif": "<200 car.>"}` (#3723) | 200 `{id, cible, fin, audit}` |
| `POST /ai/leurre` | `{"geste": "leurre", "cible": "<IPv4 ou IPv6 publique>", "duree_s": 3600…604800, "conseil": "<id>", "motif": "<200 car.>"}` (#3723) | 200 `{id, cible, fin, audit}` |
| `POST /ai/partager` | `{"geste": "partager", "cible": "<IPv4 ou IPv6 publique BANNIE>", "duree_s": 3600…604800, "conseil": "<id>", "famille": "<[a-z0-9_-], 64 car.>"}` (#3723) | 200 `{id, cible, fin, audit}` |
| `POST /ai/unban` | `{"geste": "unban", "id": "<32 hex>"}` (un id du journal, jamais une adresse) | 200 `{id, etat}`, `etat` ∈ `annule`, `echu`, `deja_annule`, `couvert` ; 404 `inconnu` |
| `GET /ai/etat` | aucun | 200 `{actifs, compteurs, plafonds, plafonds_par_geste, sade_mode}` |

**Gestes d'office du compte `ai-ban` (#3723, 1.43.0).** Le journal `/var/lib/secubox/waf/ai-ban.jsonl` porte un champ
`geste` par ligne (`ban`, `ban_bloc`, `prolonger`, `unban`) ; une ligne d'avant 1.43.0 sans lui est classée par la
forme de sa cible.

- **Porte du mode SADE**, avant tout autre contrôle d'un geste d'office (`mode = "auto"`, et `prolonger`) : gk2 lit
  `/run/secubox/sade-mode.json`, publié par secubox-soc (`{"mode", "depuis", "liste_blanche"}`), jamais la base du SOC.
  Fichier absent : aucune porte. `observe` : 409 `sade_observe` ; `reactive` : seul `limiter` passe, 409
  `sade_reactive` sinon ; `active` / `aggressive` : ouverte. `depuis` est l'instant de la PUBLICATION (l'API SOC
  republie toutes les 60 s) : un fichier illisible, d'un mode inconnu ou dont `depuis` date de plus de 15 min vaut
  `observe`. `/run/secubox` étant 1777, le fichier n'est cru que s'il appartient à root ou au compte `secubox` et
  n'est modifiable ni par le groupe ni par les autres ; sinon `observe` et liste vide (journal en erreur, une fois).
  Limite : tout processus qui tourne sous le compte `secubox` peut l'écrire. La `liste_blanche` publiée est une liste de cibles protégées pour TOUT geste,
  clic compris (409 `protegee`) ; illisible : 503 `etat`.
- **Ban d'adresse d'office** : admis seulement si l'adresse a une ligne de menace (`client_ip` ou `ip` exact) de moins
  de 24 h dans la fin de `/var/log/secubox/waf/waf-threats.log` (16 Mio lus au plus), 409 `non_vue` sinon. **La durée
  est calculée par gk2 et le `duree_s` du client est ignoré** : 24 h, × 4 par ban ai-ban précédent de la même adresse
  dans le journal (hors bans annulés pour `audit` ou `unban`), 7 j au plus (24 h, 96 h, puis 7 j) ; la réponse la
  rend (`duree_s`). « Vue » se lit au champ `timestamp` des lignes de sbxwaf (RFC 3339 avec décalage ; sbxwaf
  n'écrit pas de champ `at`). Cibles jamais visées d'office (409 `protegee`) : pair du maillage
  (`/var/lib/secubox/p2p/wg_mesh.json` et threatmesh `GET /peers`, mêmes sources que `sade_auto` de secubox-soc),
  robot d'indexation vérifié (DNS inverse confirmé par le direct, mêmes domaines que sbxwaf `crawlers.go`, 4 s au
  plus), liste blanche SADE ; une source muette, illisible, ou un DNS en doute ⇒ 409 `protegee_inconnue` (jamais un
  geste à l'aveugle ; la socket threatmesh absente compte comme muette). `wafctl ban … --exiger-protegees` : la garde
  root exige `protegees.env` (Freebox, adresse publique) ; privé, box et pairs WireGuard : leur motif.
- **`prolonger`** : un `id` d'un ban ai-ban ACTIF du journal seulement (409 `inconnu` sinon : jamais un ban d'une autre
  source ni un ban levé ou échu) ; nouvelle fin = maintenant + `duree_s`, 409 `duree` au-delà de 7 j, 409
  `raccourcit` si elle tombe avant la fin actuelle ; mêmes cibles protégées que le ban d'office. `wafctl prolonger
  <ip> <N>s` pour une adresse (une transaction nft ; 409 `absent` si elle n'est plus dans `waf_ban`), `wafctl
  ban-bloc <cidr> <N>s` pour un bloc (waf-blocs ne raccourcit jamais : sa fin enregistrée fait foi). Audit `ai-prolonger-demande`
  (sans elle, rien n'est fait) puis `ai-prolonger` ; une ligne `prolonge` au journal, qui fait foi pour la fin.
- **Plafonds par geste** (fenêtres glissantes, sommés sur tous les niveaux) :

  | Geste | Plafond | Refus |
  |---|---|---|
  | `ban` d'adresse (d'office et clic) | 60/h, 400/j | `plafond_heure`, `plafond_jour` |
  | `ban_bloc` d'office | 5/h, 20/j | `plafond_auto` |
  | tout `ban_bloc` (d'office et clic) | 30/h, 100/j | `plafond_compte` |
  | `prolonger` | 30/h, 100/j | `plafond_heure`, `plafond_jour` |
  | `limiter` | 60/h, 400/j | `plafond_heure`, `plafond_jour` |
  | `leurre` | 30/h, 200/j | `plafond_heure`, `plafond_jour` |
  | `partager` | 30/h, 200/j | `plafond_heure`, `plafond_jour` |

- **`limiter`** (geste d'office, le seul admis en SADE `reactive`) : une adresse publique IPv4 ou IPv6 en forme
  canonique (jamais un bloc, ni une IPv6 porteuse d'IPv4) ; 1 h à 24 h (409 `duree`) ; 409 `deja_actif` si elle est
  déjà limitée (un ban reste possible) ; mêmes cibles protégées que le ban d'office (liste blanche SADE, pairs du
  maillage, robots vérifiés, gardes root avec `protegees.env` exigé). Audit `ai-limiter-demande` puis `ai-limiter`
  (limite levée si ce dernier échoue). Table `inet secubox_waf_ratelimit` (`/etc/secubox/secubox-waf-ratelimit.nft`) :
  ensembles `limite_ia_v4`/`limite_ia_v6` (`flags timeout`, 4096 éléments) et, après l'acceptation du LAN
  (`whitelist_v4`, jamais limité), `ip saddr @limite_ia_v4 tcp dport { 80, 443 } update @debit_ia_v4 { ip saddr limit
  rate over 5/second burst 20 packets } counter drop` (et l'équivalent IPv6) : un seau PAR adresse, les paquets au-delà
  sont **jetés**, jamais `reject` ni redirection. **Un rechargement du fichier** (`systemctl restart
  secubox-waf-ratelimit`, ou la mise à jour du paquet, qui redémarre l'unité) recrée la table : **les limites en cours
  sont perdues** (choix assumé : gestes courts) ; le journal ai-ban les montre encore jusqu'à leur fin. `/ai/unban` de
  l'id d'une limite la lève (`wafctl limiter-lever`) ; `/ai/prolonger` la refuse (`inconnu`).

- **`leurre`** (geste d'office, refusé en SADE `observe` et `reactive`) : une adresse publique IPv4 ou IPv6 en forme
  canonique est redirigée vers le théâtre de sbxwaf (#1290) ; 1 h à 7 j (409 `duree`) ; 409 `deja_actif` si elle est
  déjà leurrée ; mêmes cibles protégées que le ban d'office ; **409 `deja_banni`** si elle est déjà bannie (ban ai-ban
  actif, bloc ai-ban ou de l'administrateur, `waf_ban`/`waf_ban6`) : un attaquant banni n'atteint pas le leurre, et ce
  geste ne lève jamais un ban ; état illisible : 503 `etat`. Audit `ai-leurre-demande` puis `ai-leurre` (leurre levé
  si ce dernier échoue). `wafctl leurre <ip> <N>s` remplace atomiquement `/var/lib/secubox/waf/leurres-ip.json`
  (`{"format": 1, "entrees": {ip: {fin, motif}}}`, root, 0644, entrées échues purgées, 2 048 au plus : `refus:plein`).
  sbxwaf (`--leurres-ip`) relit ce fichier au plus toutes les 5 s, ne le croit qu'à root (ordinaire, un seul lien,
  sans écriture de groupe ni d'autres) et ignore le LAN : chaque requête d'une adresse listée reçoit une scène du
  théâtre, jamais le vhost réel (une méthode autre que GET, HEAD ou POST : 405), et une ligne `leurre_redirige`
  (gravité `audit`) au journal des menaces, sans émission vers sbx-actord : ni ban, ni escalade, ni anomalie d'hôte.
  L'unité `secubox-waf-ng` ne rend plus ce fichier à `secubox-waf` au démarrage. `/ai/unban` de l'id d'un leurre le
  lève (`wafctl leurre-lever`) ; `/ai/prolonger` le refuse (`inconnu`).

- **`partager`** (geste d'office, refusé en SADE `observe` et `reactive`) : publie au maillage une adresse publique
  IPv4 ou IPv6 **bannie sur gk2 à cet instant** selon le pare-feu (`waf_ban`, `waf_ban6`, ou un bloc actif de
  waf-blocs qui la couvre ; le journal ai-ban seul ne suffit pas) : sinon **409 `non_bannie`**, rien de non vérifié ne
  part ; état illisible : 503 `etat`. `famille` (`[a-z0-9_-]`, 64 au plus, pas de `motif` libre) ; 1 h à 7 j (409
  `duree`) ; 409 `deja_actif` si elle est déjà partagée ; mêmes cibles protégées que le ban d'office. Audit
  `ai-partager-demande` puis `ai-partager` (indicateur retiré si ce dernier échoue). `wafctl indice-partager <ip> <N>s
  <famille>` remplace atomiquement `/var/lib/secubox/waf/ip-indices-publication.json` : contenu exact `{"format": 1,
  "jeu": "ip-indices", "indicateurs": [{ip, famille, expire}], "revus": [ip]}`, root, 0644, échus purgés, 500
  indicateurs (`refus:plein`) et 500 revus au plus ; secubox-mirrornet (0.7.0) ne le croit qu'à root et le publie
  comme jeu `ip-indices`. `/ai/unban` de l'id le retire (`wafctl indice-retirer`, le ban reste).

- **Pairs : `secubox-waf-indices`** (oneshot, minuterie de 5 min, compte `secubox`, profil AppArmor enforce, exception
  § 10 écrite) : lit `/var/lib/secubox-mirrornet-partage/livraisons/ip-indices/` (64 producteurs, 2 Mio et 500
  indicateurs chacun, schéma exact). Une adresse reçue est notée avec l'instant de sa réception ; elle n'est bannie
  24 h (`sudo -n wafctl ban <ip> 86400s --exiger-protegees`, motif d'audit `indice-maillage:<famille>`) **que si le
  journal des menaces local la montre hostile APRÈS cette réception** (famille hors des neutres, ni `leurre_redirige`,
  ni gravité `audit`) ; jamais une cible protégée (privé, box, LAN, pairs `wg_mesh.json` et threatmesh si sa socket
  existe, robots vérifiés, liste blanche SADE, `protegees.env` exigé par la garde root), porte SADE `ban` si le mode
  est publié ; 30 bans par heure glissante ; un indicateur échu est oublié. Déjà dans `waf_ban`/`waf_ban6` de la
  box (lecture `sudo -n nft -j list set …`, droit SBX_WAF_NFTLIST) : rien n'est posé, l'adresse est seulement revue
  (`waf-indice-deja-bannie`), et aucun retour arrière ne retire le ban du WAF local ; ensemble illisible : elle attend. Audit `waf-indice-demande` puis
  `waf-indice` (ban retiré si ce dernier échoue), `waf-indice-refus`. L'adresse bannie entre dans les `revus` de la
  publication de la box (`wafctl indice-revu`). État : `/var/lib/secubox-waf-indices/etat.json` (0700). Mesure pour
  SADE : `/run/secubox/waf-indices-etat.json` (0644, `{maj, partages, revus_chez_pairs, contenus_chez_pairs, recus}`),
  lue par `indices_ip.indices_etat()` (None si absente, d'un autre compte que root/secubox, modifiable par d'autres
  ou de plus de 30 min). `partages` : indicateurs non échus de la publication locale ; `revus_chez_pairs` : adresses
  partagées ici qu'au moins un pair a revues ; `contenus_chez_pairs` : couples pair × adresse partagée et revue.
  Jamais un zéro inventé : publication locale absente ou illisible ⇒ relevé indisponible (None) ; index des
  livraisons illisible ⇒ comptes des pairs None. Réception bornée : échéance reçue ramenée à 7 j au plus, 500
  adresses retenues au plus par producteur, une adresse qu'aucune livraison actuelle ne porte plus est oubliée (index
  illisible : rien n'est oublié). Le dossier `/var/log/sudo-io` est créé par le postinst (log_output sous
  ProtectSystem=strict).
  Limite connue : un indicateur publié vit jusqu'à son échéance (7 j au plus) même si le ban de l'adresse sur gk2
  prend fin plus tôt ou est levé ; seul `/ai/unban` de l'id du partage le retire de la publication.

  `GET /ai/etat` rend `plafonds_par_geste` (`{geste: {heure, jour, restant_heure, restant_jour}}`) et `sade_mode`
  (`null` si le fichier est absent), `limites` et `leurres` (`[{id, cible, fin}]`), `partages` (`[{id, cible, fin,
  famille}]`) ; `compteurs` et `plafonds` ne portent plus
  que les blocs.

**Compte de service `ai-filtres` (#3732, 1.37.0)** — garde `require_ai_filtres` : même jeton que ci-dessus avec
`sub="ai-filtres"` et `portee="waf-filtres"`, clés à part (un jeton `ai-ban` y est refusé, et inversement), même
processus désigné. Écriture par `sudo -n /usr/sbin/secubox-cvectl filtres-ia appliquer|retirer --apply --json`
(entrée sur STDIN, acteur `ai-filtres:<kid>`), lecture par `filtres-ia lister --json` ; délai de 60 s. Chaque appel
est audité (`ai-filtres-appliquer`, `ai-filtres-retirer`, `ai-filtres-lister`) ; un changement fait dont l'audit ne
s'écrit pas rend 500.
Code 5 de cvectl (erreur interne) → 503 `ctl` (le relais le retente après 24 h ; 3 → 409 est un refus définitif).
Les catégories `ia_filtres_*` (mode `escalate`, `ban_seuil`/`ban_duree` propres) ne bannissent que si le compteur
escalate global de sbxwaf existe : `-escalate-threshold`/`-escalate-window` actifs (défauts 3 et 24 h) ; sans lui,
elles observent seulement, comme `detect`.

| Route | Corps | Réponse |
|---|---|---|
| `POST /ai/filtres` | `{"filtres": [1 à 50 objets]}` (tri et bornes par cvectl) | 200 `{appliques, rejets, inchanges, …}` ; 409 `rejete` si rien n'est appliqué ni inchangé |
| `DELETE /ai/filtres/{id}` | aucun ; `id` = `ia-…` | 200 bilan de cvectl ; 404 id inconnu |
| `GET /ai/filtres` | aucun | 200 `{filtres}` |

Codes de cvectl : 2 → 422, 3 → 409, 4 → 404 ; autre code, délai dépassé ou binaire absent → 503 `ctl`.

### Ban de secubox-garde (#3794)

Compte de service `garde` (portée `garde-ban`, mêmes règles de jeton que `ai-ban`) ; clé privée
`/etc/secubox/secrets/garde-ban.pem` (root:secubox-garde 0640), créée par `wafctl cle-garde-ban generer`.

| Route | Corps | Réponse |
|---|---|---|
| `POST /garde/ban` | `{"geste": "ban", "cible": "<IPv4 ou IPv6 publique>", "duree_s": 3600…2592000, "motif": "<200 car.>"}` | 200 `{id, cible, fin, audit}` ; 409 `{"detail": {"motif"}}` : `forme`, `privee`, `deja_actif`, `plafond`, ou motif de `wafctl` |
| `POST /garde/unban` | `{"geste": "unban", "cible": "<ip>"}` (champs en trop : 422) | 200 `{cible, ids, etat: "annule"}` ; 200 `etat: "deja_leve"` si l'élément n'est plus dans `waf_ban`/`waf_ban6` (journal `note: déjà levé`, sans wafctl) ; 409 `etranger` si l'échéance restante de l'élément (ou un élément permanent) dépasse la `fin` notée par la garde de plus de 120 s — ban repris par un autre, jamais levé ; 503 `etat` si l'ensemble ou une échéance est illisible ; 409 `pas_garde` (aucun ban de la garde actif pour cette adresse dans `garde-ban.jsonl` : ban étranger, inconnu, échu ou déjà levé — jamais de wafctl), `plafond` (60/h), ou motif de `wafctl` |

Plafonds 120/h et 1000/j (journal `/var/lib/secubox/waf/garde-ban.jsonl`) ; application par `wafctl ban`
(`waf_ban`/`waf_ban6` avec timeout), audit `garde-ban-demande` puis `garde-ban`. Le champ `audit` de la réponse
vaut l'`id` de l'entrée du journal. Une cible déjà présente dans l'ensemble vivant (`waf_ban`/`waf_ban6`, lu avant
`wafctl`) est refusée en 409 `deja_actif`, et un ensemble illisible donne 503 `etat` : un ban posé par quelqu'un d'autre
n'est jamais touché. `unban` : même garde (compte `garde`, portée `garde-ban`), audit `garde-unban` avant
`wafctl unban` (chemin du retour arrière de l'ai-ban), puis ligne `{"type": "annule", "geste": "unban"}` au journal. Les plages IPv4 de documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) sont
acceptées, comme pour l'ai-ban (banc et essais).

Bornes vérifiées sur la box : IPv4 publique ou /24 exact (422 sinon) ; `mode: "auto"` = bloc seulement, 24 h au plus,
**cas sûr recontrôlé** (≥ 20 adresses du bloc dans `waf_ban`, toutes de familles sûres : `scanners`,
`recon_crawler`, `host_anomaly`, `leurre`, `product_absent_probes`, `honeypot`, `waf_fingerprint` ; les attaques — `xss`,
`lfi`, `sqli`, `rce`, `api_abuse`, `campagne`, `mesure`, toute autre, et `waf` inconnue — restent en un clic). Famille
d'une adresse : celle de son **dernier** enregistrement `ban` de `/var/lib/secubox/waf/bans.jsonl` (`cat` coupé au
premier `|` puis au premier `:` : `host_anomaly:unrouted` → `host_anomaly`, `scanners|prolonge` → `scanners`), lu par
sa fin (16 Mio au plus : au-delà, les plus anciens ne sont plus lus ; depuis #3816 le journal ne garde que 31 jours
plus les bans actifs, voir « Journal des bans ») ; à défaut, le motif du journal des menaces
(≈ 6 h), puis `waf`. `bans.jsonl` illisible : 503 `etat`, jamais « sans catégorie ». `GET /bans` porte la même
`famille` par ban (lue par le relais du POC, qui applique le même ensemble) ;
plafonds glissants d'office 5/h et 20/j, du compte 30/h et 100/j. Refus 409 `{"detail": {"motif"}}` : `deja_actif`,
`duree`, `plafond_compte`, `plafond_auto`, `pas_sur`, et les gardes `privee`, `protegee`, `box`, `pair`,
`garde_illisible`, `nft` ; 503 `etat`, `journal`, `audit`, `wafctl`, `processus` ; 500 `incoherent`. Un débannissement
ne lève jamais un ban qu'une autre source couvre (sbxwaf, administrateur) : état `couvert`. Journal des gestes :
`/var/lib/secubox/waf/ai-ban.jsonl`. La `fin` d'un ban de bloc (réponse et journal) est celle que `waf-blocs` a
enregistrée.

**Journal des bans** (`/var/lib/secubox/waf/bans.jsonl`, #3816). sbxwaf y ajoute une ligne par ban/unban et le relit au
démarrage. Il le **compacte** au démarrage puis chaque heure (`--ban-store-compactage 1h`) : restent les lignes de moins
de `--ban-store-fenetre` (31 j d'office, jamais moins de 30 j : récidive leurre et campagne, plafond de chaîne de la
réévaluation, vue `/enforcement`), le dernier état de chaque ban actif et toute chaîne de bans qui atteint la fenêtre ; le
reste est ajouté à `bans-AAAAMM.jsonl.gz` (mois de `at`, gzip multi-membres, `zcat` le lit), archives purgées au-delà de
`--ban-store-archives` mois (6). Réécriture atomique (temporaire dans le dossier, fsync, rename, mode et ACL recopiés) ;
rien n'est réécrit sous `--ban-store-seuil` octets archivables (256 Kio). Un lecteur incrémental identifie le fichier
par le descripteur ouvert (`fstat`) : un nouvel inode veut dire « relire depuis le début ».

**Journaux de preuves** (`mesures.jsonl`, `reevaluations.jsonl`, #3820). Une ligne par décision de l'échelle de réponse
et par réévaluation ; seuls lecteurs : `/mesures` (8 Mio de fin au plus) et `/reevaluations` (5 000 dernières lignes).
sbxwaf les compacte au même rythme que `bans.jsonl` : il garde un **suffixe** du fichier (octets et ordre inchangés)
qui commence à la première ligne de moins de `--preuves-fenetre` (8 j d'office, 24 h au moins), reculé pour toujours
garder plus de 8 Mio de `mesures.jsonl` et au moins 5 000 lignes de `reevaluations.jsonl` : les deux routes rendent
exactement la même chose qu'avant. Le reste va dans `mesures-AAAAMM.jsonl.gz` / `reevaluations-AAAAMM.jsonl.gz`
(mois de `ts`, `zcat` les lit), purgées au-delà de `--preuves-archives` mois (6) ; rien n'est réécrit sous
`--preuves-seuil` octets archivables (1 Mio). Mêmes garanties de réécriture que `bans.jsonl` ; les écrivains de sbxwaf
prennent un verrou d'ajout par chemin que le compactage tient pour recopier la fin et renommer.

**Le cas sûr, deux contrôles** : la règle effective est **relais ∧ gk2**. Le relais vérifie chaque adresse du bloc
dans ses propres relevés ; le recontrôle de la box ne regarde, pour chaque adresse de `waf_ban`, que la **dernière**
catégorie de ban de cette adresse (journal des menaces), pas son historique. Ni l'un ni l'autre ne connaît les pairs
hors site ou itinérants (box en déplacement, postes nomades, adresse publique d'un pair derrière un autre FAI) : leurs
adresses ou blocs **doivent** être écrits dans `protegees.env`, sinon rien n'empêche leur /24 d'être banni.

**Un seul processus sert `/ai/*`** : la mémoire des jetons vus, le verrou et les plafonds sont par processus. C'est
`secubox-waf.service` : uvicorn mono-processus (sans `--workers`, `User=secubox`) sur `/run/secubox/waf.sock`, où le
serveur d'administration (`webui.conf` de secubox-hub) envoie déjà `/api/v1/waf/` — aucune route nginx à part. Le
paquet y pose `SECUBOX_WAF_GESTES_IA=1` (drop-in `/usr/lib/systemd/system/secubox-waf.service.d/secubox-waf-gestes-ia.conf`),
pris au redémarrage de `secubox-waf.service` que le postinst fait à chaque mise à jour ; l'agrégateur n'est jamais
relancé. Tout autre importateur du module (un agrégateur qui monterait `waf`) rend 503 `processus` avant de lire le
jeton. L'unité livrée porte `NoNewPrivileges=false` : les gestes passent par `sudo -n` (droits exacts de
`/etc/sudoers.d/secubox-waf`, compte `secubox`). Les premières 1.35.0 livraient une route
`/etc/nginx/secubox-routes.d/waf-ai.conf` et un drop-in de l'agrégateur : la mise à niveau les retire
(`debian/maintscript`, `rm_conffile`).

**AppArmor** : `/etc/apparmor.d/usr.sbin.waf-blocs` est livré en **complain** ; il passe en enforce après relecture
des journaux au banc gk6.

## Lectures de la veille V2 et compte `ai-lecture` (#3720, 1.41.0)

Garde `require_lecture_ou_compte("ai-lecture")` (secubox-core ≥ 1.8.35) : **sans porteur**, `require_lecture`
inchangé (session, tableau de bord LAN) ; **porteur EdDSA** ⇒ jeton du compte `ai-lecture` (portée `waf-lecture`,
clé publique posée par `wafctl cle-ai-lecture ajouter`), lié à `GET` et au **chemin exact vu par l'application**, ou
401 (jamais de repli anonyme). Les paramètres de requête ne sont pas liés : chaque route les borne (hors bornes ⇒ 422).

**Chemin à signer (réclamation `chemin`)** : le serveur d'administration (`location /api/v1/waf/ { proxy_pass
http://unix:/run/secubox/waf.sock:/; }`) retire le préfixe ; uvicorn (`api.main:app`, sans `root_path`) voit le
chemin SANS `/api/v1/waf`. gk3 appelle `https://<gk2>/api/v1/waf/menaces/flux?…` et signe `chemin = "/menaces/flux"`.

| Appel (gk3) | Chemin signé | Paramètres (bornes) |
|---|---|---|
| `GET /api/v1/waf/menaces/flux` | `/menaces/flux` | `depuis=<inode>:<octet>` (début de ligne, sinon 422), `max` 1–2000 (500) |
| `GET /api/v1/waf/enforcement` | `/enforcement` | `depuis` époque 0–4102444800, `limite` 1–1000 (200), `statut` ∈ {`active`,`expired`,`released`} |
| `GET /api/v1/waf/campaigns` | `/campaigns` | `limite` 1–1000 (20) |
| `GET /api/v1/waf/mesures` | `/mesures` | `depuis` époque (0), `limite` 1–2000 (500) |
| `GET /api/v1/waf/actord/propositions` | `/actord/propositions` | — |
| `GET /api/v1/waf/alerts` | `/alerts` | `limit` 1–500 (50), `aggregate` |
| `GET /api/v1/waf/bans` | `/bans` | — |
| `GET /api/v1/waf/decisions` | `/decisions` | — |
| `GET /api/v1/waf/reevaluations` | `/reevaluations` | `limite` 1–1000 (100) |
| `GET /api/v1/waf/stats` | `/stats` | — |
| `GET /api/v1/waf/geoip/<ip>` | `/geoip/<ip>` (l'adresse comprise) | `ip` 2–45 car. `[0-9A-Fa-f:.]` |
| `GET /api/v1/waf/ai/etat` | `/ai/etat` | — (ouvert à `ai-ban` et `ai-lecture` ; aiguillage par `kid`) |

`/menaces/flux` rend `{"lignes": [{"position": "<inode>:<octet>", "ligne": {…}|null, ["motif"]}], "suivant",
"rotation", "trou"}` : lecture par `seek`, 1 Mio au plus par réponse, jamais de ligne partielle (la dernière ligne
en cours d'écriture attend l'appel suivant) ; ligne illisible ⇒ `ligne: null, motif: illisible`, ligne > 64 Kio ⇒
`motif: trop_longue` (sautée). Leurres de service (#3728, lignes `tool: authwatch` de sbx-authwatch, #3795) : contacts
(`client_ip`, `agent`, `user_agent`, `host`, `path`) rendus tels quels, mais chaque `essais[]` sans le mot de passe en
clair — `{compte, mot_de_passe_hmac, mot_de_passe_longueur}` : HMAC-SHA256 à clé locale de gk2
(`/etc/secubox/secrets/leurres-hmac.key`, 32 octets, root:secubox 0640, LUE DIRECTEMENT par l'API, jamais tournée
automatiquement ; créée si absente par l'oneshot root `secubox-waf-leurres-cle.service` — `Wants=`/`After=` du drop-in,
jamais `Requires=` ni `LoadCredential=` : la clé ne bloque jamais l'API — et par le postinst, qui remet une clé 0600
d'une installation antérieure en root:secubox 0640 sans la régénérer et signale une clé absente sur stderr et dans
`audit.log`) ; clé absente, illisible ou courte (journalisé au plus toutes les 10 min),
`mot_de_passe_hmac: null` (jamais le clair ni un SHA-256 nu). Sur ces lignes, les champs bruts (`message`, `ligne`,
`payload`…) sont retirés et toute chaîne qui contient un mot de passe tenté devient `[masqué]`. Le journal de gk2 garde
le clair (décision du propriétaire). À inode changé : fin de `waf-threats.log.1` (en clair, `delaycompress`) puis le courant
depuis 0 (`rotation: true`) ; inode inconnu ou fichier raccourci ⇒ reprise au début de `.1` puis du courant,
`trou: true`. `/enforcement?depuis=` relit `bans.jsonl` par la **fin** (16 Mio au plus, arrêt 10 min avant
`depuis`), plus anciens d'abord, `complet` faux si coupé. `/mesures` lit `mesures.jsonl` par la fin (8 Mio au plus).
`/actord/propositions` : `{"available": false, "motif": "absent"|"illisible"|"invalide"}` si le fichier manque, est
refusé (droits) ou n'est pas du JSON (> 2 Mio compris) ; une ligne de journal par motif toutes les 10 min.
**Droits** : sbx-actord (`secubox-actord.service`, `SupplementaryGroups=actord-lecture`) publie
`actord-propositions.json` et `actord-mesures.json` en 0640 au groupe `actord-lecture` (repli `actord-ingest` si le
groupe manque). `actord-lecture` est un groupe en **lecture seule** (créé par le postinst, membres `secubox` et
`secubox-waf`, aucun fichier inscriptible par lui) : sbxwaf et l'API du WAF lisent ; sbx-actord n'entre jamais dans
`secubox-waf` (écriture de `waf-threats.log`) et `secubox` jamais dans `actord-ingest`.
Non ouvertes au compte : `/history`, `/bans/history`, `/info`, `/rules`, toute route POST.

## Migration / cutover

Shadow → parity → **go/no-go gate** (bench `>5×` req/s·core, `p99 < ⅓`, `RSS < ¼`;
`TestWAFParity` 0-fail) → HAProxy `server` re-point → rollback = re-point back.
Pre-cutover **BLOCKING gates** (see `docs/CUTOVER.md`): complete rules WITH
log4shell, `\u0000→\x00` null-byte fix, goform false-positive fix,
`--max-body-inspect` sized for upload routes.

## Known limitations (documented gaps)

- Body inspection is prefix-bounded (`--max-body-inspect`, default 1 MiB) vs Python full-body scan — truncation is audit-logged; raise the cap or route large-upload vhosts around the WAF.
- 5 null-byte CVE patterns need `\u0000→\x00` in the rules file to compile under RE2.
- **WebUI not yet wired:** `sbxwaf` writes the threat log but not the aggregate `waf-stats.json` the WAF dashboard reads — the `/api/v1/waf` metrics feed needs porting before cutover (issue #747).

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).

## Mémoire des leurres de service (#3734)

`sbx-authwatch` écrit une ligne `leurre:<service>` par connexion à un leurre (#3728). L'API du WAF les range dans
`/var/lib/secubox-waf-leurres/leurres.db` (SQLite, répertoire 0700 `secubox`, 30 jours, ingestion à curseur toutes les 60 s et avant chaque lecture).
Toutes les routes sont en `require_jwt` : les mots de passe tentés par les robots y sont **en clair**.

| Route | Rend |
|---|---|
| `GET /api/v1/waf/leurres/resume` | `attaquants`, `couples`, `rejeux`, `touches`, `bans_actifs`, `par_leurre`, `premiere` |
| `GET /api/v1/waf/leurres/attaquants?filtre=&profil=&limite=` | une ligne par adresse : `services`, `profil`, `client`, `essais` (5 premiers), `nb_essais`, `rejeu`, `visites`, `premiere`, `derniere`, `ban` |
| `GET /api/v1/waf/leurres/attaquant/<ip>` | chaque visite de l'adresse et ses couples |
| `GET /api/v1/waf/leurres/dictionnaire` | `mots_de_passe` (essais, comptes, adresses), `comptes`, `couples` |
| `GET /api/v1/waf/leurres/rejeux` | `mot_de_passe_plusieurs_comptes`, `couple_plusieurs_adresses`, `client_plusieurs_leurres` |
| `POST /api/v1/waf/leurres/ban` | `{"ip", "duree": "4h"\|"24h"\|"7d"}` — adresse vue par un leurre seulement, jamais interne ; audit `leurre-ban` |
| `POST /api/v1/waf/leurres/unban` | `{"ip"}` ; audit `leurre-unban` |

Page : `/waf/leurres.html` (onglet « Leurres » de `/waf/`).

## Onglet Filtres IA (#3748)

Filtres de l'IA en vigueur sur la box (catégories `ia_filtres_critique|haute|moyenne`), leurs touches, les bans et
le recoupement avec la mémoire des leurres. Une tâche de fond (toutes les 5 min) lit `secubox-cvectl filtres-ia
lister --json`, le journal des menaces (7 j), les bans nft, la mémoire des leurres et les rejets audités de cvectl,
puis écrit `/var/lib/secubox/waf/filtres-ia.json` par remplacement atomique ; les routes ne lisent que ce cache.
Ce que la box ne sait pas (vulnérabilités connues, candidats du relais gk0, KEV quand il n'est pas gardé) vaut `null`.

| Route | Garde | Rend |
|---|---|---|
| `GET /api/v1/waf/filtres-ia/resume` | `require_lecture` | `resume` (`actifs`, `par_gravite`, `kev`, `ecartes`, `touches_24h`, `filtres_touches_24h`, `faux_positifs_24h`, `bans_actifs`, `bans_aussi_leurre`, `vulnerabilites_connues`, `candidats_relais`), `leurres_communs`, `genere_le`, `etat` |
| `GET /api/v1/waf/filtres-ia/touches` | `require_lecture` | `filtres` : `id`, `cve`, `produit`, `famille`, `gravite`, `motif`, `kev`, `epss`, `touches_24h`, `touches_7j`, `adresses_24h`, `bannies`, `faux_positifs`, `leurres`, `derniere` |
| `GET /api/v1/waf/filtres-ia/radar` | `require_lecture` | `points` : `ip`, `ia`, `touches`, `filtres`, `leurres`, `banni` (300 au plus) |
| `POST /api/v1/waf/filtres-ia/{id}/retirer` | `require_jwt` | bilan de `cvectl filtres-ia retirer --apply` (acteur = l'administrateur) ; audit `waf-filtres-ia-retirer` intention puis issue ; 404 id inconnu, 422 id invalide |

Page : `/waf/filtres-ia.html` (onglet « Filtres IA » de `/waf/`), `?demo=1` : adresses de documentation, aucune écriture.
