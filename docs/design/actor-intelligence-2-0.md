<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# Actor Intelligence 2.0 — audit de l'existant et plan (#2240)

Brief du propriétaire du 2026-10-11. **Règle : étendre l'Actor Intelligence existante (RFC-0013), ne rien réinventer.** Ce document est l'étape « inspecter avant de modifier » du brief ; il ne change aucun code. Il complète `actor-intelligence-audit.md` (audit initial de la RFC-0013) et `actor-intelligence-rfc-pack.md`.

## 1. Ce qui existe déjà

| Brique | Où | État |
|---|---|---|
| Enveloppe d'événement normalisée | `internal/actor/envelope` | livrée (v1) |
| Extraction de traits, similarité pondérée et versionnée | `internal/actor/{features,similarity}` | livrée |
| Graphe d'acteurs et campagnes | `internal/actor/graph`, `cmd/sbx-actord/correlate.go` | livré |
| Scores explicables (contributions pondérées, version d'algorithme figée) | `internal/actor/{score,knowledge,intent}` | livrés |
| Recommandation graduée avec TTL et `Rollbackable` | `internal/actor/response` : OBSERVE, DELAY, CHALLENGE, TARPIT, DENY, QUARANTINE | livrée |
| Registre de preuves chaîné par hachage, `Verify()` | `internal/actor/evidence` | livré |
| Store local, émission non bloquante | `internal/actor/{store,emit}` | livrés |
| Démon, API en lecture, propositions, retour d'expérience | `cmd/sbx-actord` : `/stats /actors /actors/{id} /campaigns /robots /overview /proposals /evidence/{id}`, `POST /feedback/{id}` | livré, **shadow** |
| Robots connus classés à part | `cmd/sbx-actord/robots.go` | livré (#2201) |
| Bans appliqués | `cmd/sbxwaf` : `--nft-ban`, `--actor-ban`, `--campagne-ban`, `--leurre-ban` (#2238), journal de bans append-only, annulables | livré, déployé |
| Page web Actor | `packages/secubox-waf-ng/www/actor` | livrée |

## 2. Correspondance avec les 19 points du brief

| # | Point du brief | Statut | Écart à combler |
|---|---|---|---|
| 1 | Capteurs → schéma commun | **partiel** | seuls **sbxwaf** et **sbx-authwatch** émettent vers actord. Manquent : DNS (ad-guard), DPI (sbxdpi), pare-feu (nftables), IDS local, sentinelle |
| 2 | Actor Intelligence, identité comportementale | fait | habitudes/horaires par acteur à enrichir |
| 3 | Empreinte comportementale explicable | fait pour le HTTP | familles DNS (tunneling, balises), exfiltration, latéral : dépendent des capteurs du point 1 |
| 4 | Graphe acteur → événement → cible… | **partiel** | graphe d'acteurs et campagnes ; pas d'exposition par acteur (`/graph`), pas de nœuds cible/service/appareil |
| 5 | Corrélation en scénarios | **partiel** | campagnes par signature ; pas de scénario ordonné (DNS → scan → HTTP → WAF) en fenêtres configurables |
| 6 | Risque ≠ confiance, facteurs visibles | **partiel** | `Vector` porte sévérité, intention, connaissance, confiance ; pas de « risque » unique exposé avec ses facteurs |
| 7 | Décision OBSERVE / MITIGATE / BLOCK | **partiel** | six modes de réponse existent ; à regrouper en trois niveaux de politique, avec raison, événements sources, durée, rollback |
| 8 | Abstraction `EnforcementAction` | **manque** | les bans vivent dans le journal de bans de sbxwaf, sans objet commun (type, cible, expiration, `source_decision`) ni pour DNS, quarantaine, segmentation |
| 9 | Kill switch logique (ré-évaluation) | **manque** | le ban expire par timeout nft ; aucune ré-évaluation « libérer ou prolonger » |
| 10 | Evidence engine | fait | à relier à chaque décision et à chaque action (résultat, rollback) |
| 11 | Mode PASSIVE_ONLY | **partiel** | `--shadow` seulement ; sbxwaf a `off\|propose\|auto` à part : deux interrupteurs sans vocabulaire commun |
| 12 | Mode SIMULATION (`WOULD_BLOCK`) | **partiel** | `propose` écrit des candidats ; pas de journal `WOULD_BLOCK` rejouable |
| 13 | API | **partiel** | existent `/actors`, `/actors/{id}`. Manquent `/actors/{id}/{timeline,graph,risk}`, `/events`, `/decisions`, `/enforcement`, `POST /enforcement/{id}/rollback` |
| 14 | Vue SENTINEL dans le Hall | **partiel** | page Actor existante ; pas de vue Hall, ni quarantaine, ni radar. **Collision de nom** : « Sentinel/sentinelle » désigne déjà d'autres modules |
| 15 | Fiche acteur (exemple A184) | partiel | données présentes, présentation à composer |
| 16 | Principes (local first, réversible…) | respectés | règle à garder : aucune décision sur un seul capteur |
| 17 | Compatibilité | à respecter | ne pas casser `logEntry` (WAF) ni `entreeMenace` (authwatch), volontairement dupliqués |
| 18 | Tests | partiels | Go : paquets `internal/actor/*` testés ; scénarios d'intégration multi-capteurs et panne de capteur à écrire |
| 19 | Livrables | — | ce document ouvre le chantier |

## 3. Garde-fous qui s'appliquent déjà (à conserver)

- Un acteur « bruit non relié » comme ACT-0001 (3 307 adresses) ne se bannit jamais en bloc : la preuve est par adresse (#2238).
- Robots connus, auto-test de santé, clients du LAN, domaines de première partie : jamais bannis (#1266, #2200, #2201).
- Aucun ban ne se nourrit d'un autre ban automatique ; coupe-circuit horaire ; plages protégées déclarées.
- Pas de brouillage radio ni d'interférence physique : hors périmètre.

## 4. Plan par phases

Chaque phase est livrable seule, testée, et laisse le système fonctionnel.

1. **Modes et enforcement commun.** *(API livrée, #2240 : `/enforcement`, `/enforcement/mode`, `/decisions`, rollback ; reste le vocabulaire de mode lu par actord lui-même.)* Un seul vocabulaire `PASSIVE_ONLY | SIMULATION | ACTIVE` lu par actord *et* sbxwaf ; objet `EnforcementAction` (`type, target, reason, duration, created_at, expires_at, rollback, source_decision`) écrit dans un registre local append-only, alimenté par les bans existants (leurre, campagne, acteur) ; journal `WOULD_BLOCK` en simulation ; API `GET /decisions`, `GET /enforcement`, `POST /enforcement/{id}/rollback` (garde `require_jwt`, rollback = ligne `unban` du journal de bans, déjà supporté). *Risque faible : on habille ce qui existe.*
2. **Capteurs.** *(pare-feu livré : sonde nftables + `--scan-sensor` ; DNS livré : `secubox-adguard-dnssensor`, seuls les domaines malveillants ou anormaux, dérive des domaines connus comprise ; détournement d'un domaine normal livré (réponses du cache d'Unbound, référence de 3 jours) ; DPI livré : risques nDPI hostiles cumulés par adresse publique (`DPI_ACTOR_SOCK`). Les quatre capteurs (WAF, pare-feu, DNS, DPI) émettent désormais vers actord. Ordre modifié : le DNS d'ad-guard décrit des appareils du LAN, pas des acteurs extérieurs, alors que le pare-feu voit les scans qui sont le signal central du brief.)* Émetteurs DNS (ad-guard, déjà par appareil et par domaine), DPI (sbxdpi, paires de flux), pare-feu (compteurs de `waf_drop` et de la chaîne d'entrée). Chaque capteur est facultatif : sa panne dégrade la confiance, jamais le moteur. *Prérequis de la corrélation multi-capteurs.*
3. **Scénarios, risque et confiance.** *(livré, toolbox-ng 0.9.0 : `internal/actor/analysis`, routes `/actors/{id}/{timeline,graph,risk}` et `/events`, politique `v2` ; reste l'affichage dans la vue Hall, phase 5.)* Fenêtres temporelles configurables ; scénario ordonné par acteur (reconnaissance → scan → tentative → répétition) ; `risk` et `confidence` exposés séparément avec leurs facteurs (`+20 scan`, `+15 répétition`…, la somme est le score) ; `GET /actors/{id}/{timeline,graph,risk}` et `GET /events`.
4. **Kill switch logique.** À l'échéance d'un ban ou d'une quarantaine : ré-évaluation, puis `RELEASE` ou `EXTEND` (durée graduée existante), jamais de permanent accidentel ; chaque transition est une ligne de preuve.
5. **Vue SENTINEL dans le Hall.** Réutilise la page Actor (`waf-ng/www/actor`) et le registre du Hall ; ajoute décisions, actions défensives et état de quarantaine. **Nom à décider** : « Sentinel » existe déjà (module sentinelle, `sbx-sentinel`).
6. **Documentation et activation.** Politique de scoring par défaut, exemple de configuration, procédure `PASSIVE_ONLY → SIMULATION → ACTIVE`.

## 5. Politique de scoring par défaut (proposée, versionnée `v2`)

Facteurs additifs, plafonnés à 100, chacun traçable à une preuve : scan de ports +20 ; répétition +15 ; service sensible ciblé +20 ; corrélation multi-capteurs +15 ; comportement automatisé +10 ; historique +7 ; sonde de haute valeur (secrets, exécution, administration) +20 ; robot connu −40 ; client LAN ou première partie : plafonné à OBSERVE.

Niveaux de décision : **OBSERVE** sous 42 de risque ou 60 de confiance ; **MITIGATE** (délai, défi, tarpit, limitation) de 42 à 74 ; **BLOCK** (deny, quarantaine) à partir de 75 avec confiance ≥ 80 et au moins **deux capteurs distincts** — une décision de BLOCK sur un seul capteur est refusée par construction. Une panne de capteur retire sa contribution et abaisse la confiance.

## 6. Activation progressive

1. `PASSIVE_ONLY` (déjà le cas pour actord) : observer, scorer, afficher.
2. `SIMULATION` : journal `WOULD_BLOCK` relu par l'administrateur pendant au moins une semaine ; mesurer les faux positifs (CGNAT, robots).
3. `ACTIVE` par type d'action, du plus réversible au plus dur : limitation, puis délai, puis blocage temporaire. Les bans automatiques actuels (#2238) sont l'étape ACTIVE du seul périmètre HTTP et leurre.

## 7. Décisions à prendre par le propriétaire

- Nom de la vue : « SENTINEL » entre en collision avec le module sentinelle existant. Proposition : **Radar des acteurs** dans le Hall, « Actor Intelligence » dans le menu.
- Ordre des phases : proposé 1 → 2 → 3 → 4 → 5 → 6. La phase 1 se fait sans nouveau capteur ; la 2 est la plus lourde (quatre capteurs, quatre paquets touchés).
- Seuil BLOCK : deux capteurs distincts au minimum, confirmé ?
