<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Audit de l'existant : MirrorNet, infrastructure distribuée (#3429, phase A)

Date : 2026-11-03. Base : `master` au commit `554f83041`. Audit en **lecture seule** du dépôt : aucune box
consultée, rien n'est modifié. Tout ce qui dépend de l'état réel d'une box est **NON VÉRIFIÉ**.

Statuts : **EXISTANT** (dans le code, référencé) · **PARTIEL** (existe, avec une limite qui compte ici) ·
**ABSENT** (cherché, non trouvé ; motif indiqué) · **NON VÉRIFIÉ** (le code ne suffit pas à trancher).
Chemins relatifs à `packages/`, sauf mention contraire.

Ce document **ne refait pas** deux audits qui font foi pour leur périmètre ; il les cite et les complète :

- `docs/audit/ddos-defense-audit.md` (#3417) : ActorD, sbxwaf, nftables, les trois sous-systèmes de partage
  de bans (annuaire signé, threatmesh non signé, p2p), tableaux de bord sécurité.
- `docs/audit/distributed-hosting-audit.md` et `docs/hosting/site-characterization.md` (#3420) : hébergement,
  publication, relais, ConfigBlob, sauvegarde, USB signée, certificats et DNS.

**Rectification de chemin** : `ddos-defense-audit.md` écrit `tng/` pour `secubox-toolbox-ng/` ; sa mention
`tng/cmd/sbxwaf/` désigne `packages/secubox-toolbox-ng/cmd/sbxwaf/` (déjà relevé dans
`distributed-hosting-audit.md`, en-tête). Toutes les références `sbxwaf` ci-dessous utilisent le chemin réel.

Cible de conception et arbitrages déjà pris : `wiki/MirrorNet-Infrastructure-Distribuee.md` (manifeste
`/etc/secubox/sites/<nom>.toml` ; écriture par type ; basculement automatique en lecture, promotion d'un CMS
manuelle ; keepalived seulement pour l'IP virtuelle d'un site sur un même LAN, jamais pour la passerelle ;
signature OpenPGP ; propriétaire = une personne ; LAN et maillage = zones de confiance). Les sections
« proposition » ci-dessous sont **des propositions**, jamais un état existant.

---

## 1. Tableau de synthèse par brique

| Brique | Statut | Où c'est établi |
|---|---|---|
| MirrorNet : wg-mesh, vivacité, registre des pairs | EXISTANT | `ddos-defense-audit.md` § 1.4 C ; `secubox-p2p/api/mesh.py:164,244,354,377,387` |
| MirrorNet : jonction (jetons, automesh), oubli de pair | EXISTANT | § 2.1 ci-dessous |
| MirrorNet : liens directs, relais, pairs éphémères | EXISTANT (relais : un nom → un pair) | `distributed-hosting-audit.md` § 4 |
| MirrorNet : découverte DHT signée | EXISTANT | `secubox-p2p/api/dht.py:127-190` |
| MirrorNet : ancre du maître | EXISTANT | `secubox-p2p/api/ancre.py:22-67` |
| MirrorNet : élection masterlink | PARTIEL (désactivée par défaut, sans quorum) | § 4 ci-dessous |
| Annuaire : identités, adhésion, révocation, propositions et votes, témoins, ConfigBlob signé | EXISTANT | § 2.2 ci-dessous ; `distributed-hosting-audit.md` § 4 et 6 |
| Fédération SBX v2 (CA GK2, certificats Ed25519, CRL) | EXISTANT, déploiement NON VÉRIFIÉ | § 2.3 ci-dessous |
| WireGuard (wg-mesh 10.10.0.0/24, wg-autoload 10.64.0.0/16) | EXISTANT ; rotation des clés ABSENTE | § 2.1 |
| ActorD | EXISTANT (comportemental, pas volumétrique) | `ddos-defense-audit.md` § 1.1 |
| SBX WAF (`secubox-toolbox-ng/cmd/sbxwaf/`) | EXISTANT ; une cible par hôte | `ddos-defense-audit.md` § 1.2 ; `distributed-hosting-audit.md` § 1 (`routes.go:106,285`) |
| nftables | EXISTANT (DEFAULT DROP) ; limites DDoS listées | `ddos-defense-audit.md` § 1.3 |
| nginx | EXISTANT | `distributed-hosting-audit.md` § 1 |
| HAProxy | EXISTANT ; multi-serveurs seulement hors WAF | § 5 ci-dessous |
| Keepalived / VRRP | ABSENT (volontaire jusqu'ici) | § 5 ci-dessous |
| FastAPI / agrégateur, sockets Unix | EXISTANT (threatmesh hors règle : TCP 0.0.0.0:8780) | `ddos-defense-audit.md` § 1.4 B |
| LXC | EXISTANT | `distributed-hosting-audit.md` § 3 |
| DNS : registraires, joker DNS-01 | EXISTANT (Gandi seul éprouvé) | `distributed-hosting-audit.md` § 1 |
| DNS dynamique | PARTIEL (route API, pas de multi-cibles) | § 5 ci-dessous |
| DNS multi-cibles / retrait sur santé | ABSENT | `distributed-hosting-audit.md` § 1, E3 |
| Certificats (certbot, bundle HAProxy) | EXISTANT ; un certificat par box | `distributed-hosting-audit.md` § 1, R5 |
| Domaines | EXISTANT (par box) | idem |
| Synchronisation (ConfigBlob, mesh_sync pull, application 4R) | EXISTANT ; dernier-écrivain-gagne | `distributed-hosting-audit.md` § 4, R1 |
| Stockage `/data`, sauvegardes `age` | EXISTANT | `distributed-hosting-audit.md` § 3 et 5 |
| SBXOS / Hall / Flotte / pilotage | PARTIEL (pas de vue « infrastructure distribuée ») | § 7 ci-dessous |
| Federated trust (niveaux TRUSTED…REVOKED) | PARTIEL (briques présentes, pas de niveaux) | § 2 |
| Node reputation | ABSENT (signaux présents, aucun score) | § 3 |
| Élection / quorum / anti split-brain du plan de données | PARTIEL / ABSENT | § 4 |
| Répartition de charge multi-maillage | ABSENT | § 5 |

---

## 2. Federated trust (nouveau)

### 2.1 Identités cryptographiques d'un nœud aujourd'hui

Un nœud porte **plusieurs identités indépendantes**, sans lien formel entre elles :

| Identité | Statut | Référence | Remarque |
|---|---|---|---|
| Clé WireGuard wg-mesh (transport) | EXISTANT | `secubox-p2p/api/mesh.py:164` (`render_wg_conf`) | Identité de fait du plan de données : le pilotage identifie une box par son **adresse source dans le tunnel** (`secubox-pilotage/README.md`, ligne « Identité ») |
| Clé WireGuard wg-autoload | EXISTANT | `secubox-autoload/README.md` ; `secubox-pilotage/README.md` (10.64.0.0/16 → `pairs-publics.json`) | Même modèle : identité = adresse tunnel |
| Identité annuaire `did:plc:` (Ed25519, auto-certifiante) | EXISTANT | `secubox-annuaire/annuaire/model.py:194-215` (`Identity`, `self_cert_digest`) | Signe journal, bans, ConfigBlob, offres |
| Clé OpenPGP de box liée au `did` | EXISTANT | `model.py:979-1015` ; `verbs.py:2441` (`openpgp_bind`), `:2453` (`openpgp_revoke`) | Support naturel de la signature OpenPGP retenue par le wiki |
| Ancre du maître (empreinte de la clé du maître, refus de tout autre maître) | EXISTANT | `secubox-p2p/api/ancre.py:22` (`empreinte`), `:62` (`accepte`), `:67` (audit) | Une seule ancre : un seul maître de confiance par box |
| Heartbeat signé masterlink | EXISTANT, désactivé par défaut | `secubox-p2p/api/masterlink.py:32` (`sign_heartbeat`), `:50` (`verify_heartbeat`) ; `api/main.py:3384-3414` (`[masterlink].enabled = false` si la section manque) | Un heartbeat **sans** champ `sig` est accepté sans vérification (`masterlink.py`, `on_heartbeat`, docstring « backward compatibility ») |
| Enregistrements DHT signés | EXISTANT | `secubox-p2p/api/dht.py:127-190` | |
| Jetons de jonction du maître | EXISTANT | `secubox-p2p/api/jetons.py:5-8` (seule l'empreinte SHA-256 est stockée), `:22` (TTL 3600 s), `:97` (`generer`, `flash` lié à `nom_prevu`) | Jeton = autorisation d'**entrer**, pas identité durable |
| Certificat SBX v2 (CA GK2) | EXISTANT | `secubox-federation/README.md` ; `internal/ca/renew.go:15-33` (renouvellement avec preuve de clé), `internal/ca/revoke.go:29-87` (CRL signée) | Sujet = identité annuaire. Paquet encore en `~bookworm1` (README) : déploiement NON VÉRIFIÉ |
| Identité de **propriétaire** (personne) | ABSENT | `distributed-hosting-audit.md` § 6 | Exigé par l'arbitrage « propriétaire = personne » |

### 2.2 Autorisations interbox, révocation, gouvernance

| Capacité | Statut | Référence |
|---|---|---|
| Machine d'état d'adhésion OBSERVED → MEMBER → REVOKED (pas de promotion silencieuse, révocation jamais effacée) | EXISTANT | `secubox-annuaire/annuaire/model.py:40-49` |
| Révocation signée, portée SELF / CASCADE (profondeur ≤ 8) / NAME_ONLY, append-only | EXISTANT | `model.py:132-136,361-391` ; `verbs.py:901` (`revoke`), `:100` (`_authorized_revoked_dids`) |
| Propositions et votes, règle ONE_NODE_ONE_VOICE par défaut (anti-ploutocratie) | EXISTANT | `model.py:114-130` ; `verbs.py:677` (`propose`), `:733` (`vote`), `:793` (`tally`) ; API `secubox-annuaire/api/main.py:273` |
| Témoins co-signant la racine Merkle (anti-équivocation) | EXISTANT | `model.py:393-420` (`WitnessAttest`) ; `verbs.py:176` |
| Droits signés (`Grant`) émis et révoqués | EXISTANT | `model.py:580` ; `verbs.py:1114` (`grant_issue`), `:1186` (`grant_revoke`) |
| Droits de service d'un pair (`bans-waf`…), validité 48 h, audités | EXISTANT | `secubox-annuaire/annuaire/droits.py:36,91,172-190` |
| Niveaux d'abonnement fédération (community / standard / pro / premium) | EXISTANT | `secubox-federation/internal/federation/config.go:60-87` |
| CRL de la CA fédération | EXISTANT | `secubox-federation/internal/ca/revoke.go:29-87` |
| Oubli d'un pair (registre + wg-mesh, refus si maître ou en ligne) | EXISTANT | `secubox-p2p/api/oubli.py` (docstring), `:186` (`oublier`), `:249` (`oublier_jonctions`) |
| **Rotation des clés** (WireGuard, Ed25519 annuaire, ancre, OpenPGP) | ABSENT | Recherche `rotat`, `rekey` dans `secubox-annuaire/annuaire`, `secubox-p2p/api`, `secubox-p2p/sbin` : rien. Seul un conseil d'interface dans `secubox-wireguard/www/luci-static/.../settings.js:266`. Un `did` étant l'empreinte de la clé (`model.py:194`), changer la clé **change l'identité** : il n'y a pas d'objet « succession de clé » |
| Révocation d'un pair propagée au transport (retrait wg automatique quand le `did` est REVOKED) | ABSENT | `oubli.py` est manuel ; aucun lien `REVOKED` → `wg_mesh.json` trouvé |
| Niveaux de confiance d'un pair TRUSTED / PARTNER / LIMITED / OBSERVER / REVOKED | ABSENT comme tel | Les niveaux de `federation` sont **commerciaux** (canaux, synchro), pas de confiance ; `MemberState` n'a que trois états |

### 2.3 Écart et proposition (non existante)

Il manque un **lien signé unique** entre les identités d'un nœud (`did` ↔ clé WG mesh ↔ clé OpenPGP ↔ certificat
SBX), et un **niveau de confiance** par pair dérivé du journal. Proposition :

- **Niveau = projection calculée**, jamais stockée (comme `SubscriptionState`, `model.py:144`) :
  `REVOKED` si une `RevocationNotice` valide vise le `did` ; `OBSERVER` = `MemberState.OBSERVED` ;
  `LIMITED` / `PARTNER` / `TRUSTED` = `MEMBER` + `Grant` signé de portée croissante, à durée de validité.
- **Capacités par niveau** (exemple à arbitrer) : OBSERVER reçoit les listes publiques ; LIMITED sert des
  répliques statiques en lecture ; PARTNER réplique blogs/microblogs et publie des bans soumis à quorum ;
  TRUSTED peut être maître de site et voter. Un ban fédéré n'est jamais accepté d'un niveau < PARTNER.
- **Liaison d'identités** : un enregistrement signé par le `did` qui déclare la clé WG et l'empreinte OpenPGP
  (extension de `NodeRecord`, `model.py:505`), vérifié par `mesh.py` avant de rendre un pair.
- **Rotation** : objet `KeySuccession` signé par l'ancienne **et** la nouvelle clé, avec chevauchement borné ;
  sans lui, toute rotation est une ré-adhésion.
- **Révocation effective** : `REVOKED` → retrait wg et refus du canal pilotage dans la minute, audité.

---

## 3. Node reputation (nouveau)

### 3.1 Signaux déjà mesurés

| Signal | Statut | Référence | Utilisable pour |
|---|---|---|---|
| Poignée de main WireGuard, vivacité (seuil 180 s) | EXISTANT | `secubox-p2p/api/mesh.py:244` (`LIVENESS_MAX_AGE = 180`), `:377` | disponibilité |
| Santé des services fédérés avec anti-rebond (3 échecs) | EXISTANT | `secubox-p2p/api/federation.py:17-40` (`HealthStore`) | disponibilité par service |
| Liens directs frais (600 s, 32 pairs max) | EXISTANT | `secubox-p2p/api/pairs_directs.py:23-24,77` | joignabilité |
| Relevés pilotage TR-181 (services, paquets, mémoire basse, boucles de relance) | EXISTANT | `secubox-pilotage/README.md` ; `secubox-pilotage-agent/README.md` (Notify) | santé, conformité de version |
| Instantanés de flotte signés (quatre champs concordants) | EXISTANT | `secubox-annuaire/annuaire/fleet.py:15-17,66` | intégrité de déclaration |
| Page publique `live.secubox.in` (nœuds, CPU, mémoire, durée de marche par classe) | EXISTANT | `secubox-live/README.md` (sources : `pilotage.db`, `waf-threats.log`, `bans.jsonl`) | vitrine agrégée, pas un score |
| Bans publiés par un éditeur (annuaire) | EXISTANT | `secubox-annuaire/annuaire/verbs.py:1937-2014` | qualité des bans d'un pair (à mesurer) |
| Retour opérateur sur un acteur | EXISTANT | ActorD `POST /feedback/{id}` (`ddos-defense-audit.md` § 1.1) | modèle d'annulation explicable |

### 3.2 Ce qui manque (tout ABSENT)

Recherche `reputation`, `score.*pair`, `trust.*score` dans `secubox-p2p`, `secubox-annuaire` : rien. Le poids
des IoC reçus est fixe (70) dans threatmesh (`ddos-defense-audit.md` § 1.4 B), sans pondération par éditeur.

Exigences pour une réputation conforme à la demande (proposition) :

- **Deux axes séparés** : *disponibilité* (vivacité, santé) et *fiabilité* (bans contestés, signatures
  invalides, équivocation détectée par un témoin). **L'indisponibilité ne dégrade jamais la fiabilité** :
  un pair hors ligne perd seulement son rôle de réplique servie.
- **Transparente et explicable** : chaque variation journalisée avec sa cause (même principe que
  `secubox-toolbox-ng/internal/actor/score/score.go`, score versionné).
- **Non permanente, réversible** : décroissance temporelle vers la valeur neutre ; un opérateur peut annuler
  un fait, comme le `feedback` d'ActorD.
- **Anti-manipulation** : un pair ne note pas un autre seul ; seuls les faits **vérifiables localement**
  (signature invalide, ban contredit par une preuve locale, équivocation co-signée par un témoin) comptent ;
  un vote ONE_NODE_ONE_VOICE (`QuorumRule`) pour toute sanction qui change un niveau de confiance.
- **Calcul local** à chaque box (pas de score global imposé par gk2).

---

## 4. Élection d'un maître, quorum, anti split-brain (nouveau)

| Capacité | Statut | Référence |
|---|---|---|
| Élection déterministe (priorité puis `node_id`, plus petit gagne) | EXISTANT | `secubox-p2p/api/masterlink.py:90-106` (`elect`) |
| Termes monotones persistés (0600), heartbeat de terme inférieur ignoré | EXISTANT | `masterlink.py` (`TermStore`, `on_heartbeat`) |
| Départage de deux maîtres au même terme | EXISTANT | `masterlink.py`, `on_heartbeat` (égalité de terme : un seul survit) |
| Activation par défaut | ABSENT | `secubox-p2p/api/main.py:3384-3414` : désactivé si `[masterlink]` manque dans `p2p.toml`. Pilotage et agent supposent un maître **fixe** `10.10.0.1` / `10.64.0.1` (`secubox-pilotage-agent/README.md`) ; l'ancre n'accepte qu'**un** maître (`ancre.py:62`) |
| **Quorum** (majorité des membres pour devenir maître) | ABSENT | `tick` élit dès que `election_timeout` expire, sur les seuls candidats **visibles** (`_candidates()`) : deux partitions élisent chacune un maître. La docstring parle d'« évitement de split-brain », mais elle ne couvre que le retour d'un ancien maître (terme inférieur), pas une partition |
| Heartbeat non signé accepté | PARTIEL (risque) | `on_heartbeat` : un message sans `sig` n'est pas vérifié |
| Quorum de gouvernance (votes annuaire) | EXISTANT | § 2.2 (`tally`) ; c'est un quorum **de décision**, lent, pas un consensus de service |
| Fencing (jeton de maître écrivain par site, refus d'écriture d'un ancien maître) | ABSENT | aucun motif `fenc`, `epoch` côté sites ; `ConfigBlob` a « un écrivain par scope » + version monotone (`distributed-hosting-audit.md` § 4), base possible |

Contraintes : **seul gk2 est exposé à Internet** et porte CA fédération, apt, pilotage, Hall ; une élection
automatique du *maître du maillage* déplacerait des fonctions non répliquées. Proposition cohérente avec les
arbitrages : **ne pas élire le maître du maillage** en Alpha 21 ; élire seulement un **écrivain par site**, et
seulement pour les types qui l'admettent (microblog multi-écriture avec quorum) ; promotion CMS manuelle ;
quorum = majorité stricte des répliques déclarées dans le manifeste, sinon lecture seule. Une partition sans
majorité continue de **servir en lecture** et refuse les écritures.

---

## 5. Répartition de charge multi-maillage (nouveau)

| Capacité | Statut | Référence |
|---|---|---|
| HAProxy `[backends.X] servers = [...]` avec `balance` et `check` | EXISTANT | `secubox-haproxy/sbin/haproxyctl:1500-1520` |
| Chemin public : un seul serveur `waf` (`sbxwaf_inspector`), avec `check` | EXISTANT | `haproxyctl:1477` ; le multi-serveurs n'est atteignable qu'en `waf_bypass` (interdit hors exception, `.claude/reference/SECURITE-WAF.md`) |
| sbxwaf : **une cible (IP, port) par hôte**, sans santé ni repli | PARTIEL — **verrou principal** | `secubox-toolbox-ng/cmd/sbxwaf/routes.go:106,285` (`distributed-hosting-audit.md` E1) |
| Relais maillage : un nom → un pair | PARTIEL | `secubox-p2p/sbin/secubox-relais-maillage:159,472` (`distributed-hosting-audit.md` E2) |
| Health checks existants réutilisables | EXISTANT | `HealthStore` (`federation.py:17`), vivacité wg (`mesh.py:377`), `check` HAProxy |
| DNS dynamique | PARTIEL | `secubox-dns/composants/dns-provider/api/main.py:1393` (`POST /ddns/update`, audité `:1428`, `ddns_check_interval` 300 s `:1089`) ; `secubox-p2p/api/mesh.py:206` (`ddns_name`). Un enregistrement par nom |
| DNS multi-cibles (plusieurs A/AAAA) et retrait sur santé | ABSENT | `distributed-hosting-audit.md` E3 ; `joker.py` refuse d'écraser un enregistrement étranger |
| Keepalived / VRRP | ABSENT | aucun paquet ni configuration (`grep -ri keepalived\|vrrp` hors `debian/`) ; décision 2026-07-13 « pas de HA de passerelle », assouplie par le wiki pour l'IP virtuelle d'un site sur un même LAN |
| Anycast | ABSENT | — |

Conséquence : tant que seul gk2 est exposé, la « répartition » possible est **derrière** gk2 : HAProxy → sbxwaf →
*plusieurs* répliques sur wg-mesh. Cela exige d'étendre `routes.go` à une **liste de cibles avec santé** (le
WAF reste unique et en tête, la règle « tout passe par sbxwaf » est respectée). La répartition sans point
central (DNS multi-cibles vers plusieurs nœuds exposés, chacun avec son WAF et son certificat DNS-01) relève de
l'après-bêta tant que le parc n'a qu'un nœud exposé.

---

## 6. Autres briques (renvois)

- **ActorD, sbxwaf, nftables, partage de bans** : `ddos-defense-audit.md` § 1.1-1.4. Constat repris : la
  fédération signée des bans (annuaire) n'a ni consensus, ni TTL obligatoire, ni plages protégées, ni IPv6, et
  n'est alimentée ni par sbxwaf ni par ActorD ; threatmesh échange **sans signature** sur un port TCP.
- **Hébergement, relais, ConfigBlob, certificats, DNS, sauvegardes `age`, USB signée** :
  `distributed-hosting-audit.md` § 1-6 et `docs/hosting/site-characterization.md`.
- **LXC** : `secubox-core/usr/sbin/secubox-lxcctl` (`distributed-hosting-audit.md` § 3).

---

## 7. SBXOS, Hall, Flotte, pilotage : où loger « MIRRORNET > DISTRIBUTED INFRASTRUCTURE »

| Surface | Statut | Référence |
|---|---|---|
| Page Flotte (annuaire), qui porte le panneau Pilotage | EXISTANT | `secubox-annuaire/www/fleet/index.html` ; `secubox-pilotage/README.md` (« Menu : panneau Pilotage dans la page Flotte ») |
| Pilotage L1/L2 (inventaire SQLite, actions du catalogue fermé, agent sortant, Go sans CGO) | EXISTANT | `secubox-pilotage/README.md`, `secubox-pilotage-agent/README.md` |
| Vigie SOC (pairs, arbre du maillage) | EXISTANT | `ddos-defense-audit.md` § 1.5 (`secubox-soc/api/main.py`) |
| Topologie masterlink | EXISTANT (vide si désactivé) | `secubox-p2p/api/main.py` route `GET /masterlink/topology` (`require_lecture`) |
| SBXOS (PWA Hall) | NON VÉRIFIÉ | `secubox-sbxos/README.md` : V1 sans backend, manifeste servi en fichier ; sources livrées en bundle (`ddos-defense-audit.md` § 1.5) |
| Vue « infrastructure distribuée » (sites, répliques, santé, niveaux de confiance, réputation) | ABSENT | — |

Proposition : le **tableau de bord** vit dans **Flotte** (annuaire), sur le maître (vision « headless =
remote controller ») ; le Hall/SBXOS n'en affiche qu'une **carte** de synthèse lue en `require_lecture`. Les
gestes (promotion CMS, révocation, changement de niveau) passent par l'API du maître et sont **décidés sur la
box cible** (ctl confiné). Sur petites machines : aucune vue lourde locale, calcul côté maître, la box ne
publie que ses relevés (déjà le modèle de l'agent pilotage).

---

## 8. Composants réutilisables

1. **Annuaire** : `MemberState`, `RevocationNotice` (cascade bornée), `propose`/`vote`/`tally`
   (ONE_NODE_ONE_VOICE), `WitnessAttest`, `Grant`, `droits.py` (validité 48 h) : base des niveaux de confiance.
2. **`ConfigBlob` + `mesh_sync` + `config_apply`** : manifeste de site répliqué, un écrivain par scope
   (`distributed-hosting-audit.md` § 7).
3. **`masterlink.py`** : termes monotones et heartbeat signé, réutilisables pour l'écrivain d'un site, à
   condition d'ajouter le quorum.
4. **`HealthStore`**, vivacité wg, `check` HAProxy : santé des répliques.
5. **CA fédération** : certificats Ed25519 avec renouvellement par preuve de clé et CRL signée.
6. **Clé OpenPGP de box** + `provision.py` (`gpgv`) : signatures de versions et de supports USB.
7. **Pilotage** : relevés, canal sortant, Flotte ; **live** : vitrine agrégée sans adresse.
8. Garde-fous de ban de sbxwaf (`ddos-defense-audit.md`, « Composants réutilisables » 2-4).

## 9. Nouveaux composants nécessaires (propositions)

| N° | Composant | Lot proposé |
|---|---|---|
| N1 | Objet `Site` + propriétaire (personne) dans l'annuaire, manifeste `/etc/secubox/sites/<nom>.toml` | Alpha 21 |
| N2 | Liaison signée des identités d'un nœud (`did` ↔ WG ↔ OpenPGP ↔ certificat SBX) | Alpha 21 |
| N3 | Niveaux de confiance calculés (TRUSTED…REVOKED) et capacités par niveau | Alpha 21 (lecture), Alpha 22 (effets) |
| N4 | Révocation → retrait wg + refus pilotage, auditée | Alpha 21 |
| N5 | `routes.go` multi-cibles avec santé et repli (WAF unique en tête) | Alpha 21 (statique, lecture) |
| N6 | Transfert de contenu signé entre pairs (`payload_uri` exploité, versions immuables + bascule atomique) | Alpha 21 |
| N7 | Réputation à deux axes, locale, décroissante, explicable | Alpha 22 |
| N8 | Écrivain par site avec quorum et fencing (microblog) ; promotion CMS manuelle | Alpha 22 |
| N9 | Fédération des bans : alimentation par sbxwaf/ActorD, TTL obligatoire, IPv6, plages protégées, seuil par niveau de confiance ; threatmesh signé ou retiré | Alpha 22 (cf. #3417) |
| N10 | `KeySuccession` (rotation des clés) | Alpha 22 |
| N11 | keepalived pour l'IP virtuelle d'un site sur un même LAN | Alpha 22, optionnel |
| N12 | DNS multi-cibles avec retrait sur santé, plusieurs nœuds exposés | après bêta |
| N13 | Vue Flotte « Distributed Infrastructure » + carte Hall | Alpha 21 (lecture), Alpha 22 (gestes) |

## 10. Dépendances

- N5 dépend de N1 (liste des répliques d'un site) et de la santé (`HealthStore`).
- N3 dépend de N2 ; N7, N8 et N9 dépendent de N3.
- N8 dépend de N6 (versions) et du quorum ; N9 dépend aussi des correctifs DDoS locaux de #3417.
- N12 dépend d'un second nœud exposé (décision d'exploitation), de N5 et de certificats par nœud (DNS-01).
- Toute la chaîne suppose la règle « tout passe par sbxwaf » : aucune répartition HAProxy en `waf_bypass`.

## 11. Risques

- **Sécurité du maillage** : la confiance actuelle est « être dans wg-mesh » (threatmesh l'écrit en toutes
  lettres ; pilotage identifie par adresse tunnel). Une clé WG volée vaut une box entière ; sans rotation ni
  lien `REVOKED` → transport, une révocation n'est pas effective. Heartbeat non signé accepté.
- **Faux bans** : union OU sans consensus, sans TTL obligatoire ni plages protégées (`ddos-defense-audit.md`
  § 1.4 A) ; avec la réputation, risque inverse de « punir » un pair indisponible. Règle : indisponibilité ≠
  malveillance, seuils par niveau, TTL court, annulation explicable.
- **Split-brain** : masterlink élit sans quorum ; activé tel quel, deux partitions auraient deux maîtres. Les
  écritures d'un site (CMS, base) ne doivent jamais dépendre de cette élection.
- **Mémoire ARM 1-4 Go** : journal annuaire rejoué, ConfigBlob et répliques, ActorD (50 000 événements),
  sets nft sans `size`. Tout calcul de réputation et de niveaux doit être incrémental, borné, et absent des
  petites box (relevés seulement).
- **gk2 point unique** : TLS, WAF, DNS, CA, apt, pilotage, live sur la seule box exposée, racine à plus de
  90 %. Une réplique derrière gk2 améliore la disponibilité du *contenu*, pas de l'*entrée*.
- **Régression du parc** : `secubox-federation` encore étiqueté bookworm ; activer masterlink ou la CA
  changerait le comportement de box déjà en service.

## 12. Impacts performances

- sbxwaf multi-cibles : un choix de cible et une table de santé par hôte, coût négligeable si la santé est
  mise à jour hors du chemin de requête (même modèle que le rechargement à chaud de `routes.go:31,279`).
- Réplication : bande passante wg-mesh et disque `/data` (quota par site) ; transferts par différence.
- Réputation et niveaux : calcul périodique sur le maître ; une box ne fait que vérifier des signatures.
- Vérifications de signature Ed25519 : peu coûteuses ; le journal annuaire complet, lui, croît sans fin
  (prévoir des points de contrôle).
- Santé : réutiliser les sondes existantes (handshakes, `HealthStore`, pilotage) plutôt qu'en ajouter.

## 13. Découpage en lots (proposition, cohérente avec le wiki)

- **Alpha 21 — fondations** : N1, N2, N3 en lecture seule (niveaux affichés, sans effet), N4, N5 pour les
  sites statiques (lecture, basculement automatique), N6, N13 en lecture ; correctifs locaux #3417 ;
  `masterlink` **reste désactivé**.
- **Alpha 22** : N3 avec effets, N7, N8 (microblog avec quorum ; CMS : promotion manuelle), N9, N10, N11
  optionnel, gestes N13.
- **Après bêta** : N12 (plusieurs nœuds exposés, DNS multi-cibles), élection éventuelle du maître du
  maillage avec quorum, anycast.

## 14. Plan de tests

Scénario obligatoire **GK2 / GK3 / GK4** : gk2 = maître exposé ; gk3 et gk4 = répliques. *Attention :* la
mémoire du projet classe gk3 (voicestudio) comme **intouchable** et réserve le banc à gk4/gk5/gk6/gk7 ; le
rôle de gk3 dans ce scénario est donc à arbitrer (voir questions), à défaut gk5 ou gk6 le remplace.

1. **Confiance** : enrôler gk4 (jeton, automesh), vérifier OBSERVED → MEMBER, niveau calculé affiché ;
   révoquer gk4 → retrait wg et refus pilotage en moins d'une minute, audit présent.
2. **Site statique** : manifeste sur gk2, répliques sur gk3/gk4, sbxwaf de gk2 sert depuis les deux ; arrêter
   gk3 → bascule sans erreur 5xx ; arrêter gk2 côté contenu (WAF actif) → service depuis gk4.
3. **Retour du maître** : modifier le site pendant l'absence, rétablir → réconciliation sans écrasement.
4. **Partition** : couper gk3–gk4 du maillage ; vérifier qu'aucune partition minoritaire n'accepte
   d'écriture (microblog), que la lecture continue, et qu'aucun second maître n'apparaît.
5. **Faux ban** : publier depuis gk4 un ban visant l'IP d'administration → refusé (plage protégée / niveau).
6. **Réputation** : gk4 hors ligne 1 h → disponibilité basse, fiabilité inchangée ; signature invalide
   injectée → fiabilité baisse, explication lisible, retour à la normale par décroissance ou annulation.
7. **Mémoire** : mesurer RSS et sets nft sur une box 1 Go pendant la synchro et un flood simulé.
8. **WAF** : vérifier qu'aucun chemin public ne contourne sbxwaf (`haproxyctl` généré, aucun `waf_bypass` ajouté).

## 15. Questions d'arbitrage

1. Le rôle de gk3 dans le scénario de test obligatoire (gk3 est noté intouchable) : le maintenir ou le
   remplacer par gk5/gk6 ?
2. Les niveaux de confiance : projection du journal annuaire (proposé) ou extension des tiers de
   `secubox-federation` ? Qui peut promouvoir un pair en TRUSTED : l'administrateur seul, ou un vote ?
3. Rotation des clés : accepter qu'une rotation soit une ré-adhésion en Alpha 21, ou exiger `KeySuccession`
   dès les fondations ?
4. masterlink : le garder désactivé jusqu'à l'après-bêta (proposé), ou lui ajouter un quorum en Alpha 22 ?
5. threatmesh (non signé, TCP) : le retirer au profit de la fédération annuaire, ou le signer ?
6. Un second nœud exposé à Internet est-il envisagé avant la bêta ? Sans lui, la répartition reste derrière gk2.
7. La réputation est-elle publiée (live.secubox.in, agrégée) ou strictement locale à chaque box ?
