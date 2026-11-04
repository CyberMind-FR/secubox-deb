<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MirrorNet — architecture (#3429, phase B, conception)

Statut du document : **CONCEPTION**, rien n'est implémenté. Fondé sur l'audit consolidé
`docs/audit/mirrornet-infrastructure-audit.md` (désigné ci-dessous « audit ») et sur les arbitrages du propriétaire
du 2026-11-03 (commentaires de #3429, #3420, #3417).

Marquage obligatoire de chaque élément :

- **EXISTANT** : dans le code de `master`, avec sa référence `fichier:ligne` ;
- **À ÉTENDRE** : existant à modifier, l'extension est une proposition ;
- **NOUVEAU** : n'existe pas, proposition.

Chemins relatifs à `packages/` sauf mention contraire. `tng/` n'est jamais employé : `sbxwaf` vit sous
`secubox-toolbox-ng/cmd/sbxwaf/`.

## 0. Arbitrages du 2026-11-03

Décisions du propriétaire, **validées le 2026-11-03** ; elles priment sur toute formulation antérieure des documents
de la phase B. Les sous-sections « Vision du propriétaire » et « Conflit de nom court » ci-dessous font foi et
remplacent ce qui les contredit (notamment la décision 3, reportée).

**Décision 1 — chaque module reste maître de ses services ; `secubox-mirrornet` est le plan de contrôle (validé
2026-11-03).**

- Le module qui sert un service en reste le maître : metablogizer pour les vhosts statiques, streamlit pour ses
  applis, chaque service sur mesure chez son module. Lui seul sait empaqueter, vérifier, installer, redémarrer.
- Chaque module **déclare** son comportement P2P par un manifeste empaqueté, sur le modèle EXISTANT de
  `capabilities.d` : fichiers `/usr/share/secubox/capabilities.d/*.json` posés par le `debian/rules` du module
  (`secubox-radio/debian/rules:56-57`), lus et fusionnés par ZIA (`secubox-zia/api/capabilities.py:35` `CAP_DIR`,
  `:162-174` lecture, un manifeste cassé n'abat pas le registre). NOUVEAU : `/usr/share/secubox/mirrornet.d/<module>.toml`
  (format : `distributed-hosting.md` § 3 ; manifeste de service généré § 9) — quoi répliquer (fichiers, base, rien), réplique en lecture ou en écriture,
  basculement automatique ou promotion manuelle, sonde de santé, hooks « exporter » / « installer la version X ».
- `secubox-mirrornet` devient le **panneau de master control** multi-services : il lit les manifestes, affiche quel
  service tourne sur quel nœud, applique la politique (source/copies, noms courts, basculement, réputation, défense) et pilote
  les routes sbxwaf. Il **ne touche jamais au contenu** d'un module : il demande à l'adaptateur du module d'exporter
  ou d'installer une version (`distributed-hosting.md` § 4), transporte et vérifie des objets opaques (empreinte,
  identité du nœud source), et n'ouvre jamais une archive. Il **détecte** les publications des modules et les diffuse
  sans geste (vision ci-dessous).

**Décision 2 — `ConfigBlob` par version, généralisé en « version de service » (validé 2026-11-03).** Un scope par
version (`service.<nom>.v.<empreinte16>`), quel que soit le module (`replication.md` § 2).

**Décision 3 — propriétaire = clé OpenPGP d'une personne : REPORTÉE (2026-11-03, après la maquette).** Aucune
signature de site en Alpha 21 ; authenticité par l'identité du nœud (`distributed-hosting.md` § 2) ; signature locale
des sites = chantier ultérieur.

**Décision 4 — format de route sbxwaf étendu (validé 2026-11-03)**, rétrocompatible (`load-balancing.md` § 2) ; les
cibles sont les points de service **déclarés par le module**, plus un port mirrornet.

**Décision 5 — `defense.toml` OBSERVE / ASSISTED / AUTONOMOUS (validé 2026-11-03)** : ASSISTED sur une installation
neuve, AUTONOMOUS conservé sur une box en service ; consensus des bans fédérés k = 2 éditeurs PARTNER ou 1 TRUSTED
(`collective-defense.md` § 2, § 4).

**Plan** : le lot « sites statiques » est découpé en (a) socle mirrornet + format du manifeste + API adaptateur +
registre des noms courts, (b) adaptateur metablogizer avec détection des publications, en Alpha 21 ; streamlit et
Voice Studio en Alpha 22 ; le panneau de contrôle est la page admin de `secubox-mirrornet` (`plan-alpha21.md`).

### Vision du propriétaire (2026-11-03, après la maquette)

- MirrorNet = automatique : tout site ou service publié sur un nœud (`toto.gk9.secubox.in`, y compris depuis une clé USB locale) devient disponible sous son nom court `toto.secubox.in`, sans geste.
- Un site est miroité d'office sur un autre nœud et les visites sont réparties entre les copies.
- Un service local (ex. Voice Studio sur gk3) est distribué sur le maillage ; des services équivalents se partagent les ressources.
- Signature des sites : importante mais NON IMPLÉMENTÉE (metablogizer ne signe rien ; seul HMAC du webhook Gitea, `packages/secubox-metablogizer/api/webhook.py:41`). La crypto actuelle est propre au maître (Hall, mail, APT). Alpha 21 : pas de signature de contenu ; l'authenticité repose sur l'identité du nœud dans le maillage (annuaire + WireGuard). Signature locale des sites : chantier ultérieur (décision 3 reportée).
- gk2 reste la seule entrée Internet : il sert sa copie ou relaie par wg-mesh.

### Conflit de nom court (validé 2026-11-03)

- Le premier nœud qui publie `toto` obtient `toto.secubox.in` ; un contenu DIFFÉRENT publié ensuite sous le même nom reste sur son nom de nœud (`toto.<nœud>.secubox.in`).
- Si l'antériorité n'est pas établie (publications simultanées, annuaire non convergé), le conflit bloque : aucun nom court, chaque copie reste sur son nom de nœud jusqu'à arbitrage administrateur.
- Le même contenu (même propriétaire) publié sur plusieurs nœuds n'est pas un conflit : il rejoint le miroir et la répartition.

### Antériorité et nœud source disparu (conception, détail `distributed-hosting.md` § 6)

- Chaque publication écrit une annonce de nom signée par la box (`ConfigBlob` scope `nom.<nom>.<nœud>`, `annonce_le`).
  A est antérieure à B si `annonce_le(A) + marge_horloge < annonce_le(B)` ; une annonce antidatée au-delà de la marge
  est datée à sa réception. Sous la marge : simultanées → bloqué.
- Titularité acquise après `fenetre_convergence` sans concurrente antérieure ou simultanée ; avant : nom de nœud seul.
  Concurrente plus ancienne découverte après coup (partition) : « contesté », titulaire toujours servi, arbitrage.
- Calcul pur depuis le journal, identique sur chaque nœud ; l'arbitrage administrateur (`nom.<nom>.arbitrage`, maître
  ancré) prime.
- En A21, « même propriétaire » = même contenu (empreinte ou racine de chaîne) ; seul le titulaire prolonge sa chaîne.
- Nœud source absent : les copies servent la dernière version, nom conservé, pas de nouvelle version ; réattribution
  seulement par arbitrage. Nœud source révoqué : nom court suspendu, routes retirées.

## 1. Documents de la phase B

| Document | Brique(s) |
|---|---|
| `architecture.md` (ce document) | vue d'ensemble, nommage, composants N1..N13 |
| `distributed-hosting.md` | Distributed Hosting : publication automatique, nom court (conflit, antériorité), placement des miroirs, manifeste P2P de module, API adaptateur, services équivalents, types |
| `replication.md` | Peer Replication : versions, transfert vérifié, réconciliation |
| `load-balancing.md` | Load Balancing : sbxwaf multi-cibles, santé, nommage DNS |
| `failover.md` | Failover : scénario gk2/gk6/gk4, anti split-brain, keepalived |
| `usb-master-source.md` | USB Master : publication locale par clé USB |
| `federated-trust.md` | Federated Trust : identités, niveaux, révocation, rotation |
| `node-reputation.md` | Node Reputation |
| `collective-defense.md` | ActorD, SBX WAF, nftables, bans fédérés (MCD) |
| `testing.md` | plan de tests, mesures ARM64 / x86_64 |
| `plan-alpha21.md` | découpage de l'Alpha 21 en lots (une PR par lot) |

## 2. Briques et responsabilités

| Brique | Responsabilité | Socle existant principal | Nature du travail |
|---|---|---|---|
| MirrorNet | réseau de pairs chiffré, annuaire signé | wg-mesh `secubox-p2p/api/mesh.py:164` ; journal `secubox-annuaire/annuaire/log.py:112-140` ; `mesh_sync.py:146` (`sync_once`) | EXISTANT, réutilisé |
| Distributed Hosting | publication automatique, registre des noms courts, placement des miroirs, manifeste P2P déclaré par chaque module | modèle `capabilities.d` (`secubox-zia/api/capabilities.py:35,162`) ; `site.json` metablogizer (`secubox-metablogizer/api/site_schema.py:24-99`) ; `ConfigBlob` (`secubox-annuaire/annuaire/model.py:538-575`) | NOUVEAU (manifeste `mirrornet.d`, service), À ÉTENDRE (ConfigBlob réutilisé) |
| Adaptateurs de module | exporter / installer / activer / sonder une version du service, **dans** le module | metablogizer : sites `/srv/metablogizer/sites` (`sbin/metablogizerctl:8`), vhost (`:134-206`), extraction confinée (`composants/publish/api/main.py:812`) | NOUVEAU (A21 metablogizer, A22 streamlit) |
| Peer Replication | versions de service immuables (objets opaques), transfert vérifié (empreinte + nœud source), réconciliation ; installation déléguée à l'adaptateur | `ConfigBlob.payload_uri` (`model.py:564`) jamais exploité ; `config_apply.py` (4R) | NOUVEAU |
| Load Balancing | plusieurs cibles par nom derrière le WAF | `routes.go:106` (`loadRoutesJSON` → `map[string][2]string`), `:285` (`Lookup`) | À ÉTENDRE (verrou E1) |
| Failover | lecture servie malgré la perte d'une réplique ou du contenu maître | `HealthStore` (`secubox-p2p/api/federation.py:17-40`), vivacité (`mesh.py:244,377`) | NOUVEAU (logique), EXISTANT (sondes) |
| USB Master | publication locale depuis une clé (sans signature en A21) | étiquette `SBXPROFIL` (`secubox-premier-pas/systemd/secubox-premier-pas.service:16-17`) | NOUVEAU (support `SBXSITE`), modèle EXISTANT |
| ActorD | détecter, corréler (campagnes multi-IP, par site) | `secubox-toolbox-ng/cmd/sbx-actord/api.go:191,298` (campagnes) ; `Envelope.Vhost` (`internal/actor/envelope/envelope.go:108`) | À ÉTENDRE (`site_id`, volumétrie) |
| SBX WAF | décider | `secubox-toolbox-ng/cmd/sbxwaf/actorban.go`, `nftban.go` | À ÉTENDRE |
| Federated Trust | identités liées (base de l'authenticité A21), niveaux, révocation effective | `MemberState` (`model.py:40-49`), `NodeRecord` (`model.py:505-532`, porte déjà `pubkey_wg`), OpenPGP lié (`model.py:979-1015`) | À ÉTENDRE + NOUVEAU (projection de niveau) |
| Node Reputation | fiabilité explicable et réversible | signaux seulement (audit § 3.1) | NOUVEAU (Alpha 22) |
| SBXOS | vue MIRRORNET > DISTRIBUTED INFRASTRUCTURE | page Flotte `secubox-annuaire/www/fleet/` ; pilotage | NOUVEAU (vue), EXISTANT (surfaces) |

## 3. Vue d'ensemble

```
                         Internet
                            │  (seul gk2 est exposé jusqu'à la bêta)
                 ┌──────────▼───────────┐
                 │ gk2  HAProxy TLS 1.3 │ EXISTANT  haproxyctl:1477 (server waf … check)
                 │      *.secubox.in    │ À ÉTENDRE certificat joker (joker.py)
                 └──────────┬───────────┘
                 ┌──────────▼───────────┐
                 │ sbxwaf (WAF unique)  │ À ÉTENDRE routes multi-cibles + site_id
                 │  décide, bannit nft  │ EXISTANT  nftban.go
                 └───┬───────┬───────┬──┘
           local     │       │ wg-mesh 10.10.0.0/24 (EXISTANT)
        ┌────────────▼┐  ┌───▼────────┐ ┌▼───────────┐
        │ gk2 module  │  │ gk6 module │ │ gk4 module │  service servi PAR SON MODULE (metablogizer…),
        │ copie       │  │ nœud source│ │ copie      │  point de service déclaré dans mirrornet.d
        └──────▲──────┘  └─────┬──────┘ └─────▲──────┘  version installée par l'adaptateur du module
               │ annonces de nom et de version signées par la box source (ConfigBlob, pull) EXISTANT transport
               └─────────────────┴──────────────┘ objets par empreinte (pull HTTP sur wg-mesh) NOUVEAU

   Plan de contrôle : secubox-mirrornet (manifestes, politique, routes)   NOUVEAU
                      sur secubox-annuaire (journal signé, mesh_sync pull) EXISTANT
   Plan de gestion  : pilotage (agent sortant, admin.<nœud>.secubox.in)   EXISTANT
   Vue             : Flotte « Distributed Infrastructure » sur gk2         NOUVEAU
```

Trois plans, comme la feuille de route Gondwana
(`docs/superpowers/plans/2026-06-30-gondwana-p2p-clone-distribute-emancipate.md`, § 2) :

- **contrôle** : `secubox-mirrornet` (détecte les publications, tient le registre des noms courts, place les miroirs,
  pilote sbxwaf), appuyé sur l'annuaire (identités, annonces de nom et de version, révocations, bans, niveaux) ; tout y est signé et
  rejoué par pull ; aucun secret (`ConfigBlob`, docstring `model.py:538-548`) ;
- **données** : wg-mesh (trafic HTTP vers les répliques, transfert des objets) ;
- **gestion** : pilotage (relevés, actions du catalogue fermé, vhost `admin.<nœud>.secubox.in`,
  `secubox-pilotage/README.md:278-343`).

Invariants hérités de Gondwana (§ 0) et maintenus : fédération de nœuds souverains, **pas d'élection du maître du
maillage** (masterlink reste désactivé, `secubox-p2p/api/main.py:3384-3414`), un seul écrivain par site (le nœud
source titulaire), secrets
jamais répliqués, API sans privilège + ctl root étroit, 4R et audit, **aucun `waf_bypass`**.

## 4. Nommage (arbitrage du 2026-11-03)

| Nom | Rôle | Servi par (Alpha 21) | Statut |
|---|---|---|---|
| `<service>.secubox.in` | **nom court** distribué, attribué automatiquement au premier publieur (§ 0) | sbxwaf de gk2 → toutes les copies saines du titulaire (copie locale de gk2 ou relais wg-mesh) | NOUVEAU |
| `<service>.<nœud>.secubox.in` | **nom de nœud**, posé dès la publication, toujours publié (diagnostic, conflit, bascule) | sbxwaf de gk2 → une seule cible : la copie de `<nœud>` | À ÉTENDRE (modèle du relais `secubox-p2p/sbin/secubox-relais-maillage:159`) |
| `admin.<nœud>.secubox.in` | administration d'un nœud | vhost de pilotage, route vers l'IP maillée du pair | EXISTANT (`secubox-pilotage/README.md:278-330`) |
| `admin.secubox.in` | administration **agrégée** multi-pairs (vue lourde sur le maître, actions relayées par le pilotage, décision sur la box cible) | gk2 ; Alpha 21 : lecture seule (vue Flotte) | NOUVEAU |

Règles :

- Le manifeste de service généré porte les équivalences (`[equivalences]`, `distributed-hosting.md` § 9) ; elles sont
  **dérivées** des copies placées automatiquement, jamais saisies, et toujours publiées.
- DNS de `secubox.in` tenu sur gk2 tant qu'aucun second nœud n'est exposé : tous les noms ci-dessus pointent vers gk2.
- Certificats : `*.secubox.in` et `*.<nœud>.secubox.in` obtenus **par gk2** en DNS-01 (`secubox-dns/composants/
  dns-provider/api/joker.py:1-25`, EXISTANT pour le joker par nœud ; À ÉTENDRE pour `*.secubox.in`). Aucune clé privée
  ne quitte gk2. Après la bêta, chaque nœud exposé obtient les siens (N12).
- `<service>` ne peut pas valoir un nom de nœud (`gk2`, `gk6`…), `admin`, `apt`, `live` ni une classe de services
  équivalents (`distributed-hosting.md` § 8). Un nom déjà tenu suit la règle de conflit (§ 0), sans refus de publier :
  la publication reste servie sur son nom de nœud.

## 5. Flux principaux

**Publication automatique (statique, Alpha 21)**

```mermaid
sequenceDiagram
  participant U as Propriétaire (webui du module ou clé USB, sur gk6)
  participant S as gk6 (nœud source)
  participant A as Annuaire (journal signé)
  participant C as gk4 / gk2 (copies élues)
  participant W as sbxwaf gk2
  U->>S: publication locale (aucun autre geste)
  S->>S: adaptateur metablogizer « exporter » → objet opaque BLAKE2b
  S->>A: annonces signées par la box : nom.<nom>.gk6, service.<nom>.v.<empreinte>, copies.<nom>
  W->>W: <nom>.gk6.secubox.in → gk6 (relais wg-mesh)
  C->>A: mesh_sync (pull) ; registre des noms : titulaire après convergence
  C->>S: GET objet par empreinte (wg-mesh)
  C->>C: empreinte vérifiée, adaptateur « installer » + « activer » ; sonde du module
  W->>W: <nom>.secubox.in → copies saines (répartition)
```

**Requête publique** : client → HAProxy gk2 → sbxwaf (inspection, ban éventuel, `site_id` dans l'événement ActorD) →
choix d'une cible saine (copie locale de gk2, ou relais wg-mesh) → point de service du module (lecture seule).

**Révocation** : `RevocationNotice` (EXISTANT, `model.py:361-391`) → projection REVOKED → retrait du pair de wg-mesh et
de la projection `pairs-enroles.json` lue par le pilotage (`secubox-pilotage/README.md:21`) → retrait de la cible dans
sbxwaf, suspension des noms courts dont il est source. NOUVEAU (N4).

## 6. Composants N1..N13 (repris de l'audit § 9, précisés)

| N° | Composant | Précision de conception | Où | Calendrier | Document |
|---|---|---|---|---|---|
| N1 | Manifeste P2P de module (`mirrornet.d`) + API adaptateur + publication automatique + registre des noms courts + placement des miroirs | manifeste de module empaqueté (modèle `capabilities.d`) ; détection des publications (`publications` de l'adaptateur) ; annonces `nom.<nom>.<nœud>` signées par la box, antériorité calculée, arbitrage ; manifeste de service **généré** ; copies `copies.<nom>` ; aucune signature de personne (décision 3 reportée) | NOUVEAU paquet `secubox-mirrornet` | A21 | distributed-hosting |
| N2 | Liaison signée des identités | `NodeRecord` porte déjà `did` + `pubkey_wg` (`model.py:516-519`) : À ÉTENDRE avec `openpgp_empreinte` et `cert_sbx_serie` (optionnel) ; vérifié par `mesh.py` avant de rendre un pair | `secubox-annuaire`, `secubox-p2p` | A21 | federated-trust |
| N3 | Niveaux TRUSTED…REVOKED | projection calculée du journal, jamais stockée ; A21 affichée sans effet ; A22 effets (capacités) | `secubox-annuaire` (module NOUVEAU `confiance.py`) | A21 / A22 | federated-trust |
| N4 | Révocation effective | REVOKED → retrait wg + projection pilotage + routes sbxwaf, < 60 s, audité | `secubox-p2p` (À ÉTENDRE, chemin root existant) | A21 | federated-trust |
| N5 | sbxwaf multi-cibles | format de route objet rétrocompatible ; santé hors du chemin de requête ; repli passif ; `site_id` | `secubox-toolbox-ng/cmd/sbxwaf/routes.go`, `secubox-core/usr/sbin/secubox-waf-route` | A21 (statique) | load-balancing |
| N6 | Transfert de version vérifié | objets opaques adressés BLAKE2b, annonce signée par la box source, pull HTTP sur wg-mesh par mirrornet ; installation, bascule atomique et service **par l'adaptateur du module** | `secubox-mirrornet` + adaptateur metablogizer | A21 | replication |
| N7 | Réputation | deux axes (disponibilité, fiabilité), locale, décroissante, explicable ; résumé anonyme sur live | `secubox-annuaire` ou `secubox-mirrornet` | A22 | node-reputation |
| N8 | Écrivain par site + quorum + fencing | bail d'écriture signé (site, terme, écrivain), quorum = majorité stricte des répliques ; CMS : promotion manuelle | `secubox-mirrornet` | A22 | failover, replication |
| N9 | Bans fédérés MCD | `BanRecord` (`model.py:723-744`) : TTL obligatoire, IPv6, exclusions, consensus/niveau ; threatmesh retiré | `secubox-annuaire`, `sbxwaf`, `sbx-actord` | A21 (retrait threatmesh, étape A locale) / A22 (MCD) | collective-defense |
| N10 | `KeySuccession` | ancienne + nouvelle clé, chevauchement borné | `secubox-annuaire` | A22 (A21 : ré-adhésion) | federated-trust |
| N11 | keepalived | IP virtuelle d'un **site** sur un même LAN, jamais la passerelle, optionnel | NOUVEAU paquet optionnel | A22 | failover |
| N12 | DNS multi-cibles, plusieurs nœuds exposés | retrait sur santé, certificats par nœud | `secubox-dns` | après bêta | load-balancing |
| N13 | Vue Flotte « Distributed Infrastructure » + carte Hall + arbitrage des conflits | A21 lecture (`require_lecture`) + arbitrage d'un nom bloqué (`require_jwt`, gk2), A22 gestes relayés par le pilotage | `secubox-annuaire/www/fleet/`, `secubox-mirrornet` API | A21 / A22 | architecture § 7 |

## 7. Paquet NOUVEAU `secubox-mirrornet` : plan de contrôle (décision 1, validé 2026-11-03)

`secubox-mirrornet` porte la **politique** et le **transport**, jamais le contenu ni le service. Le contenu, son
installation et son service restent dans le module (metablogizer, streamlit…), derrière son adaptateur.

| Élément | Valeur proposée |
|---|---|
| Rôle | lit `/usr/share/secubox/mirrornet.d/*.toml` (manifestes de module) ; détecte les publications locales ; génère `/etc/secubox/services/<nom>@<nœud>.toml` ; tient le registre des noms courts ; place les copies ; décide l'éligibilité ; pilote les routes sbxwaf ; demande aux adaptateurs `exporter` / `installer` / `activer` |
| API | FastAPI, socket `/run/secubox/mirrornet.sock` (0660, groupe `secubox`) ; `GET /api/v1/mirrornet/{modules,services,service/{nom},noms,versions/{nom},sante,usb,flotte}` (`require_lecture`), `POST /api/v1/mirrornet/nom/arbitrer` (`require_jwt`, maître ancré) ; A22 : `service/promouvoir` |
| Compte | `secubox-mirrornet` (jamais root), AppArmor enforce, socle § 10 de `.claude/RULES-CODE.md` |
| ctl root | `mirrornetctl` à verbes exacts (sudoers argv exact) : `vhost-poser <nom>`, `route-poser <nom>`, `route-retirer <nom>`, `usb-lire` ; aucune écriture dans l'arbre d'un module |
| Données | `/data/mirrornet/objets/<blake2b>` (archives **opaques**, jamais extraites par mirrornet), état des versions par service et par nœud ; quota par service |
| Configuration | `/etc/secubox/mirrornet.toml` (0640 : `marge_horloge`, `fenetre_convergence`, `delai_abandon`, `minimum_copies`, `[hebergement]`, `[usb]`) ; manifestes de service générés `/etc/secubox/services/<nom>@<nœud>.toml` |
| Objets pour les pairs | nginx `:8471` sur l'IP wg-mesh, `/objets/<empreinte>`, accès limité aux pairs de `pairs-enroles.json` |
| Service local | **aucun** : chaque module sert ses répliques sur le point de service déclaré dans son manifeste |
| Minuteries | synchro (annonces + objets) toutes les 60 s ; sondes (celles déclarées par les modules) toutes les 10 s |
| Audit | `/var/log/secubox/audit.log` : publication détectée, annonce de nom, titularité, conflit (refusé, bloqué, contesté), arbitrage, placement et refus de copie, installation demandée/refusée par l'adaptateur, bascule, lecture USB |

L'alternative « étendre metablogizer » et l'alternative « mirrornet sert le contenu » sont **écartées** (décision 1).

## 8. SBXOS, Flotte, Hall

- **Panneau de master control** : page admin NOUVELLE de `secubox-mirrornet` (`www/mirrornet/`, charte
  `.claude/WEBUI-PANEL-GUIDELINES.md`) : modules déclarés (`mirrornet.d`), services, quel service tourne sur quel nœud
  (source, copies, version installée), état du nom court (titulaire, refusé, bloqué, contesté, suspendu), routes
  sbxwaf. A21 : lecture + arbitrage d'un conflit ; A22 : promotion, réglage de politique.
- Vue « MIRRORNET > DISTRIBUTED INFRASTRUCTURE » : onglet de la page Flotte (`secubox-annuaire/www/fleet/`, EXISTANT)
  qui renvoie au panneau, sur gk2. Contenu A21 : services, noms courts et conflits, version attendue et version servie par copie, santé, équivalences,
  niveau de confiance **affiché** des pairs (mention « sans effet »), révocations récentes. Lecture `require_lecture`.
- Carte Hall/SBXOS : synthèse (sites servis, répliques saines / totales), lue par la même route.
- `admin.secubox.in` : A21 = cette vue en lecture ; A22 = gestes (arbitrage, promotion CMS, niveau TRUSTED, révocation) postés au
  maître, relayés par le pilotage, **décidés par le ctl de la box cible** (vision remote controller).
- Petites box : aucune vue lourde locale ; elles publient leurs relevés (modèle de l'agent pilotage, EXISTANT).

## 9. Ce que l'architecture ne fait pas (Alpha 21)

Pas de signature de contenu (décision 3 reportée) ; pas de partage de charge entre services équivalents ni
d'adaptateur Voice Studio (A22) ; pas de second nœud exposé ; pas d'élection ; pas d'écriture répliquée (blog, microblog, CMS en Alpha 22) ; pas de
niveau de confiance à effet ; pas de réputation ; pas de keepalived ; pas de DNS multi-cibles. La disponibilité gagnée
est celle du **contenu** derrière gk2 (copies réparties automatiquement), pas celle de l'**entrée** (gk2 reste point unique, audit § 11).
