<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit de l'existant : hébergement distribué de sites sur le maillage (#3420, phase 1)

Objectif visé : un site (statique, blog, microblog, CMS, dynamique, API, média) a une **source
maître** (une SecuBox, une clé USB ou un support autorisé), des **répliques** tenues par les pairs,
une répartition de charge **sans point central**, un basculement, puis une **réconciliation** au
retour du maître sans écrasement aveugle. Principe : « un site appartient à son propriétaire, pas à
son serveur ».

Audit en **lecture seule** du dépôt (master `bcae465d6`). Aucune box interrogée : tout ce qui dépend
de l'état réel d'une box est marqué NON VÉRIFIÉ.

Statuts : **EXISTANT** (dans le code, référencé) · **PARTIEL** (existe, avec une limite qui compte
ici) · **ABSENT** (cherché, non trouvé ; motif indiqué) · **NON VÉRIFIÉ** (dépend du terrain ou
non lu en détail).

Le maillage (identité Ed25519, ancre du maître, heartbeat, DHT, wg-mesh, vivacité, relais) est déjà
inventorié dans `docs/audit/ddos-defense-audit.md` § 1.4 C : on y renvoie sans le refaire.
Rectification de chemin pour ce même audit : le code de `sbxwaf` est sous
`packages/secubox-toolbox-ng/cmd/sbxwaf/` (et non `tng/cmd/sbxwaf/`).

---

## 1. Hébergement sur une box

| Capacité | Statut | Références |
|---|---|---|
| nginx sert les sites locaux (vhosts par module, `server_name` exact prioritaire sur le joker) | EXISTANT | `packages/*/nginx/` ; résolution des vhosts `packages/secubox-haproxy/composants/exposure/api/reach.py:64` |
| HAProxy TLS 1.3 frontal, généré depuis `/etc/secubox/haproxy.toml` par `haproxyctl generate` | EXISTANT | `packages/secubox-haproxy/sbin/haproxyctl:1016` (`cmd_generate`), lecture des `[vhosts.*]` `:137-200` (champs nom, domain, backend, enabled, waf_bypass, ssl, ssl_redirect, cadrable, cookies_tiers) |
| `haproxyctl vhost add/remove`, réparation de config | EXISTANT | `haproxyctl:619` (`cmd_vhost_add`), `:730`, `:667` |
| Backends multi-serveurs avec `balance` et `check` (`[backends.X] servers = [...]`) | EXISTANT | `haproxyctl:1500-1520` |
| … mais le chemin public passe par `sbxwaf_inspector` (un seul serveur `waf`) | PARTIEL | `haproxyctl:1477` (`server waf …:… check`). La répartition HAProxy multi-serveurs n'est utilisable qu'avec `waf_bypass`, ce qui est interdit hors exception déclarative |
| Table de routes `sbxwaf` : **un hôte → une seule cible (IP, port)** | PARTIEL | `packages/secubox-toolbox-ng/cmd/sbxwaf/routes.go:106` (`loadRoutesJSON` → `map[string][2]string`), `:285` (`Lookup` rend une IP et un port). Pas de liste de cibles, pas de santé, pas de repli : c'est **le verrou** de la répartition vers des répliques |
| Rechargement à chaud des routes | EXISTANT | `routes.go:31` (Load/Apply atomique), `:279` (`Maybe`) |
| Déclaration de route par paquet (`secubox-waf-route`) | EXISTANT | `packages/secubox-core/usr/sbin/secubox-waf-route` |
| Bypass WAF déclaratif par vhost | EXISTANT | `haproxyctl:190` ; règle `.claude/reference/SECURITE-WAF.md` |
| Certificats ACME (certbot, bundle HAProxy `/data/haproxy/certs/`) | EXISTANT | `packages/secubox-certs/` (`sbin/secubox-certbot:7-14`), `haproxyctl:773-862` (`cert list/add/delete/renew/sync`) |
| Joker DNS d'un nœud (DNS-01 via le registraire, jamais d'écrasement d'un enregistrement étranger) | EXISTANT | `packages/secubox-dns/composants/dns-provider/api/joker.py:1-25` ; appelé par le relais `secubox-relais-maillage:331` (`dns_joker_assure`), `:356` |
| Registraires (OVH, Gandi, Cloudflare, Route53) | EXISTANT (Gandi seul éprouvé) | `dns-provider/api/main.py:9,64-67,94-95` ; « Gandi sur gk2 » `joker.py:6`. Les autres adaptateurs : NON VÉRIFIÉ |
| Exposeur (Peek/Poke/Emancipate, Tor + DNS + maillage) | PARTIEL | `packages/secubox-haproxy/composants/exposure/` ; le canal « Mesh » est noté « à porter » dans `.claude/reference/EXPOSITION-PUNK.md` |
| Vhost (composant) | EXISTANT | `packages/secubox-haproxy/composants/vhost/sbin/vhostctl` |
| Plusieurs enregistrements A/AAAA par nom (DNS round-robin) ou retrait sur santé | ABSENT | `joker.py` crée un enregistrement et refuse d'en écraser un autre ; aucun motif `round.?robin`, `health.*dns` dans `dns-provider/` |

## 2. Modules de publication

| Module | Statut | Stockage, source, réplication | Références |
|---|---|---|---|
| **metablogizer** (sites statiques) | EXISTANT | Sites sous `/srv/metablogizer/sites` → lien vers `/data/metablogizer` ; manifeste **`site.json`** (JSON Schema : name, domain, published, version `vX.Y.Z`, source_url, gitea_repo, aliases, last_updated) ; publication = vhost HAProxy derrière `sbxwaf_inspector` + synchro des routes ; Tor par site | `secubox-metablogizer/schema/site.json.schema.json` ; `api/site_schema.py:24-99` ; `sbin/metablogizerctl:134` (`site_publish`), `:302` (`site_wire_public_vhost`), `:317`, `:393` (`tor_expose`) |
| metablogizer : synchro depuis un amont git | EXISTANT | `metablog-sync` : `git reset --hard` sur l'amont **déclaré source de vérité**, rien si l'amont n'a pas bougé. C'est déjà le modèle « maître externe, réplique alignée » pour un site, mais en écrasement (pas de détection de divergence) | `sbin/metablog-sync:7-23,39` |
| metablogizer : versions immuables, bascule atomique d'une version | ABSENT | `version` est un champ déclaratif ; aucun répertoire de versions ni lien `current` (motifs `releases/`, `current ->`) |
| droplet (dépôt de fichiers, liens de partage, expiration) | EXISTANT | `secubox-metablogizer/composants/droplet/` |
| publish (plateforme multi-cibles) | EXISTANT, NON VÉRIFIÉ en détail | `secubox-metablogizer/composants/publish/api/main.py` (1365 l.) ; suppose un DNS joker `*.gk2.secubox.in` (l. 848-850 de la copie empaquetée) |
| **billets** (microblog) | EXISTANT | SQLite (`aiosqlite`) + **journal d'événements chaîné SHA-256** (`billet.published/edited/deleted`, commentaires) ; miroir vers le BBS | `secubox-billets/api/db.py:5,24` ; `api/services/eventlog.py` ; `api/services/miroir_bbs.py` |
| **bbs** (forums, bibliothèque, publication vers billets) | EXISTANT | Go, SQLite `bbs.db` | `secubox-bbs/internal/store/` ; `internal/billets/` |
| **streamlit** (applis Python dynamiques) | EXISTANT | LXC dédié, une unité par appli | `secubox-streamlit/lxc`, `sbin/streamlitctl` ; état réel : NON VÉRIFIÉ |
| **podcaster** (flux RSS republié) | EXISTANT | médias locaux, public via HAProxy/exposure | `secubox-podcaster/debian/control` (Description) |
| **peertube** (vidéo fédérée) | EXISTANT | LXC natif, **PostgreSQL** `peertube_prod`, sauvegarde par `pg_dump` | `secubox-peertube/sbin/*:309,392` |
| metanews (agrégateur, pas un site d'auteur) | EXISTANT (hors cible) | `secubox-metanews/` |
| hexo, gotosocial, mastodon | ABSENT comme module source | `packages/secubox-hexo/`, `secubox-gotosocial/` ne contiennent que `debian/` (reliquats de build) ; seul un connecteur `secubox-bbs/internal/mastodon` existe |
| CMS PHP (WordPress ou autre), php-fpm | ABSENT | motifs `wordpress`, `php-fpm`, `php8` : aucun module ; seules des mentions en tests ou dans `secubox-mail/lib/mail/install.sh` |
| Gitea (dépôts git, miroir des sites) | EXISTANT | `secubox-gitea/sbin/giteactl` ; référencé par `site.json:gitea_repo` |

## 3. Exécution, conteneurs, volumes, bases

| Capacité | Statut | Références |
|---|---|---|
| Python/FastAPI par module sur socket Unix | EXISTANT | règle AGENTS.md ; tous les `api/` |
| PHP | ABSENT | voir § 2 |
| LXC (jamais Docker), `lxcpath` connus `/data/lxc` puis `/var/lib/lxc` | EXISTANT | `packages/secubox-core/usr/sbin/secubox-lxcctl:17,24,43-45` ; attente du volume `systemd/lxc.service.d/wait-for-data.conf:15` |
| Volume `/data` (SSD) | EXISTANT, disposition propre à chaque box | idem ; état réel des box : NON VÉRIFIÉ |
| SQLite (billets, bbs, nombreux modules) | EXISTANT | § 2 |
| PostgreSQL (peertube, dans le LXC) | EXISTANT | § 2 |
| Réplication de base entre box (log shipping, réplica en lecture) | ABSENT | motifs `streaming replication`, `litestream`, `wal`, `replica` : rien côté sites |

## 4. Maillage (complément à `ddos-defense-audit.md` § 1.4 C)

| Capacité | Statut | Références |
|---|---|---|
| Identité, ancre du maître, heartbeat signé, élection, DHT signée, wg-mesh, vivacité | EXISTANT | inventorié dans `ddos-defense-audit.md` § 1.4 C (`secubox-p2p/api/ancre.py`, `masterlink.py`, `dht.py`, `mesh.py`) |
| **Relais d'un nœud sans WAN par la box qui a le WAN** : TLS terminé et WAF sur le relais, HTTP vers le pair sur wg-mesh ; vérifie appartenance au maillage, DNS public, certificat, vhost | EXISTANT | `secubox-p2p/sbin/secubox-relais-maillage:7-30`, `:244` (`cmd_relayer`), `:296` (`relais_poser`), `:159` (`routes_ecrire`), `:442` (`domaine_tenu_par_autre`), `:856` (`cmd_synchroniser`, minuteur horaire) |
| Relais : un nom → **un seul** pair | PARTIEL | `routes_ecrire <nom> <ip> <port>` (`:159`) et `route_etrangere` (`:472`) refusent un second titulaire : pas de groupe de pairs pour un même nom |
| Ports média relayés (UDP/TCP) | EXISTANT | `:824` (`cmd_relayer_port`), `:736` |
| Liens WireGuard directs entre pairs (hors étoile) | EXISTANT | `secubox-p2p/api/pairs_directs.py:1-25` (32 pairs max, fraîcheur 600 s) |
| Pairs éphémères (session) | EXISTANT | `secubox-p2p/api/ephemeral.py` |
| Santé des services fédérés (up/down avec anti-rebond, persistée) | EXISTANT | `secubox-p2p/api/federation.py:17-30` (`HealthStore`) |
| **Synchronisation signée de contenu** : `ConfigBlob` (version monotone, **un seul écrivain par scope**, `payload` en ligne ou `payload_uri` + `content_hash` BLAKE2b), réplication par `mesh_sync` (pull, vérification de chaque signature), application CSPN 4R (shadow → validation → swap → rollback) idempotente par version, sur liste d'inclusion | EXISTANT | `secubox-annuaire/annuaire/model.py:538-575` ; `annuaire/mesh_sync.py:1-20` ; `annuaire/config_apply.py:1-25` ; verbes `annuaire/verbs.py:1744-1806` |
| Offres de service signées (`ServiceOffer`, kind `mirror`…), abonnements | EXISTANT | `model.py:453-485` |
| Artefacts versionnés et signés promus par anneaux (`Evolution`, `Artifact` kind `www`) | EXISTANT | `model.py:888-921` ; `annuaire/releases.py` |
| Transfert de fichiers volumineux entre pairs (contenu d'un site) | ABSENT comme service générique | `rsync` n'apparaît que dans des ctl locaux (`metablogizerctl`, `streamlitctl`, `giteactl`, `mediactl`…) ; `payload_uri` existe dans `ConfigBlob` mais aucun service de récupération dédié aux sites |
| Nœuds indisponibles : file de rattrapage | PARTIEL | convergence par le journal annuaire (pull) ; rien de propre aux sites |
| Répartition de charge sans point central | ABSENT | ni DNS multi-cibles (§ 1), ni multi-cibles `sbxwaf` (§ 1), ni anycast. Le relais fait du nœud WAN un **point de passage** obligatoire |
| VRRP / keepalived | ABSENT (volontaire) | aucun paquet ni règle ; décision du 2026-07-13 (pas de HA de passerelle) |

## 5. Sauvegarde, restauration, supports

| Capacité | Statut | Références |
|---|---|---|
| Sauvegarde configs + données + conteneurs LXC, chiffrée `age` | EXISTANT | `secubox-backup/sbin/backupctl:68` (`init_key`), `:236` (`archiver`), `:152` (`restaurer`), `:177` (`restaurer_conteneur` : conteneur arrêté, non relancé) |
| Clonage | EXISTANT, NON VÉRIFIÉ | `secubox-backup/composants/cloner` |
| PeerTube : `pg_dump` | EXISTANT | `secubox-peertube/sbin/*:309` |
| Clé USB reconnue **par étiquette** (`SBXPROFIL`), montée en lecture seule le temps de la lecture | EXISTANT (premier pas seulement) | `secubox-premier-pas/systemd/secubox-premier-pas.service:16-19` ; sources `premier_pas/moteur.py:53-57` |
| Fichier USB **signé** : signature détachée OpenPGP vérifiée par `gpgv` contre un trousseau fourni, schéma strict, aucun secret en clair | EXISTANT (mode provision) | `secubox-premier-pas/premier_pas/provision.py:12-20,60-61,128-129` |
| Identité d'un support USB (numéro de série, empreinte), révocation d'un support perdu | ABSENT | motifs `ID_SERIAL`, `revoqu.*support`, `udisks` : rien hors règles udev série/zigbee |
| Auto-Load | EXISTANT, **hors sujet USB** | c'est un provisionnement **réseau** (jetons, tunnel `wg-autoload` 10.64.0.0/16) : `secubox-autoload/README.md` |
| Eye Remote (gadget USB : réseau ECM, médias de démarrage) | EXISTANT | `secubox-eye-remote/core/boot_media.py`, `udev/90-secubox-eye-remote.rules` ; usage comme support de site : ABSENT |
| Netboot (live, overlay U-Boot signé FIT) | EXISTANT, hors sujet sites | `secubox-netboot/` |

## 6. Signature et identité

| Capacité | Statut | Références |
|---|---|---|
| Identité de box `did:plc:` = empreinte de la clé Ed25519 ; journal chaîné BLAKE2b | EXISTANT | `secubox-annuaire/annuaire/crypto.py`, `log.py` ; `model.py:194` (`Identity`) |
| Snapshots de flotte : quatre champs concordants avant de croire la signature | EXISTANT | `annuaire/fleet.py:15-17,66` |
| Clé OpenPGP de box liée au `did` (auteur vérifié = did nommé), révocation | EXISTANT | `model.py:979-1015` ; `annuaire/openpgp.py` ; composant `secubox-annuaire/composants/openpgp/` |
| Délégation, droits signés à durée de validité (48 h) | EXISTANT | `annuaire/delegation.py`, `annuaire/droits.py:172-190` |
| Identité d'un **propriétaire de site** distincte de la box | ABSENT | aucun objet « site » ni « propriétaire » dans `model.py` ; le propriétaire n'existe que comme compte local (auth) |
| Fédération SBX v2 (CA GK2, certificat Ed25519 de box) | EXISTANT | `packages/secubox-federation/` (Go) |

---

## 7. Composants réutilisables

1. **`ConfigBlob` + `mesh_sync` + `config_apply`** : un écrivain par scope, version monotone,
   contenu adressé par empreinte, application 4R. C'est déjà le squelette d'un « manifeste de site
   répliqué » et d'un pointeur de version publiée.
2. **`site.json` de metablogizer** et `metablog-sync` : manifeste local et synchro depuis une source
   amont déclarée.
3. **`secubox-relais-maillage`** : chaîne DNS → certificat → vhost → route sbxwaf vers un pair,
   avec audit et refus d'écraser une route étrangère.
4. **`joker.py`** : DNS-01, jamais d'écrasement, création relue.
5. **`provision.py`** + unité premier-pas : lecture USB par étiquette en lecture seule, signature
   détachée `gpgv` contre un trousseau explicite, schéma strict.
6. **Journal chaîné de billets** : base naturelle d'une réplication par événements (microblog).
7. **`backupctl`** (age) et `pg_dump` : instantanés pour CMS et bases.
8. **`HealthStore`** (anti-rebond up/down) et vivacité wg-mesh.
9. **Clé OpenPGP de box** et identités Ed25519 : signature de versions sans nouvelle PKI.

## 8. Écarts

- E1. `sbxwaf` ne connaît qu'**une cible par hôte** : ni répliques, ni santé, ni repli.
- E2. Le relais ne sait servir un nom que depuis **un** pair.
- E3. Aucun DNS multi-cibles ni retrait sur santé : la répartition sans point central n'a pas de
  mécanisme.
- E4. Pas d'objet « site » ni de « propriétaire » dans l'annuaire ; pas de versions immuables de
  site ni de bascule atomique.
- E5. Pas de transfert de contenu volumineux entre pairs (au-delà d'un `payload_uri` non exploité).
- E6. Pas d'identité ni de révocation de **support** USB ; la lecture USB n'existe que pour le
  premier pas.
- E7. Pas de réplication de base (SQLite, PostgreSQL) entre box ; pas de CMS PHP.
- E8. Le canal « Mesh » de l'exposeur reste « à porter ».

## 9. Risques

- R1. **Écrasement aveugle** : `metablog-sync` fait `git reset --hard`, et `ConfigBlob` est en
  dernier-écrivain-gagne. Réutilisés tels quels pour un maître qui revient, ils écraseraient les
  écritures faites pendant son absence.
- R2. **Point central de fait** : seul gk2 est exposé à Internet ; tout site relayé dépend de lui
  (TLS, WAF, DNS). Une répartition « sans point central » exige plusieurs nœuds exposés, donc
  plusieurs WAF et certificats à tenir, ce qui va contre l'état actuel du parc.
- R3. **Cohérence des bases** : un CMS en écriture sur deux box diverge ; sans réplication de base
  il faut un unique écrivain.
- R4. **Confiance dans un support branché** : la tentation de lire une clé par simple étiquette
  (modèle SBXPROFIL) ouvrirait l'injection de contenu publié.
- R5. **Certificats** : servir un même nom depuis plusieurs box suppose une clé privée partagée
  (secret à répliquer) ou un certificat par box (DNS-01 sur chacune).
- R6. **Contournement du WAF** : la répartition HAProxy multi-serveurs existe déjà mais n'est
  atteignable qu'en `waf_bypass` ; ne pas s'en servir pour aller vite.
- R7. **Espace disque** : gk2 à plus de 90 % sur la racine ; des répliques complètes doivent vivre
  sur `/data`, avec quota.
