<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->

# SADE — SecuBox Active Defense Engine (conception)

Date : 2026-11-20. Statut : conception, à valider par le propriétaire. **Prolonge, ne remplace pas**
`docs/superpowers/specs/2026-11-19-secubox-ai-v2-riposte-graduee-design.md` (#3827) et les deux specs V2
(`2026-11-14-secubox-ai-v2-design.md`, `2026-11-18-...-correlation-outils-auto-design.md`). Ce qui n'est pas
dit ici reste comme dans ces specs.

## Intention

Faire passer SecuBox d'une posture « je détecte » à « j'ai reconnu ce comportement, identifié les services
ciblés, appliqué une contre-mesure **locale**, vérifié son efficacité et conservé les preuves ». Décision du
propriétaire (20/11) : **SADE = chapeau unifiant** (pas un moteur neuf), **mode ACTIVE par défaut**.

## Principe directeur : chapeau, pas doublon

SecuBox possède déjà détection, scoring, réponse graduée, expiration, rollback et maillage. SADE **n'ajoute
aucun détecteur, corrélateur ni scoring** : il **orchestre**, **applique une politique** (modes/seuils) et
**présente** (console unique). Construire un détecteur/corrélateur neuf dupliquerait Actor Intelligence + V2
et fragmenterait l'audit CSPN — exclu (AGENTS « ne pas dupliquer », méthode §15 du prompt propriétaire).

| Brique SADE (prompt) | Composant SecuBox réutilisé | Écart réel à combler par SADE |
|---|---|---|
| Détection (WAF/DPI/logs/réseau) | `secubox-waf-ng` (sbxwaf), DPI/nDPI, leurres, Actor Intelligence 2.0, bans auto WAF (#2238) | aucun — SADE **lit** |
| Scoring 0-100, récurrence | Actor Intelligence (score acteur), dossiers V2 + signaux de persistance (#3827) | **mapper** score→échelle, pas le recalculer |
| Réponse graduée (5 niveaux) | Échelle observer/contenir/usager (#3827), catalogue de gestes fermé V2 (waf-ng `gestes_ia`) | **bande REACTIVE** (ralentir seul) + **garde humaine 95-100** à ajouter à l'échelle |
| Confinement d'appareil / quarantaine | `secubox-garde` (`demandes.py` : l'IA propose, garde applique) | aucun — SADE **route** vers garde |
| Mesh Defense (indicateurs GK2/GK3/C3Box) | threatmesh / `secubox-p2p`, `propager_maillage` (#3827) | aucun — SADE **expose/contrôle** |
| Console Cyber Defense Live | SOC (`secubox-hub/www/soc`), cardlet actor, Radar/Chaîne V2 (#3811) | **vue unifiée** DÉTECTION→ANALYSE→DÉCISION→ACTION→VÉRIF + commutateur de mode |
| nftables / WAF / DNS adapters | chemins audités ctl+sudoers de gk2 (`wafctl`, `ai-ban`, nft drop-ins) | aucun — **jamais** de règle écrite à la main depuis SADE |
| Expiration / rollback / audit | bans à TTL, double-tampon + rollback 4R, `audit.log` append-only | aucun — SADE **s'appuie dessus** |

**Composant** : `secubox-active-defense` — indépendant mais **mince** : console + politique/modes + orchestration
+ API de façade (statut/menaces/actions/approbation/rollback). Il **propose** depuis gk3 et **applique par le
chemin audité de gk2** (comme V2) ; il n'a aucun privilège d'écriture réseau propre.

## Réconciliation « ACTIVE d'emblée » ↔ « l'IA propose, n'agit pas »

Le propriétaire veut ACTIVE (blocage/confinement automatiques). Les règles permanentes disent « l'IA propose »
([[feedback_ia_jamais_inventer]], [[project_actor_autoban_propose]]) et « ne rien casser en prod ». On concilie
par la **source de la décision**, pas par le mode :

- **Auto (même en ACTIVE)** uniquement les gestes **déterministes à haute confiance** déjà auto aujourd'hui :
  le « cas sûr décidé par le code » de #3827 (cible publique réellement vue, catalogue fermé, sous plafond) et
  la classe de bans auto WAF existante (ex. sonde `/.env` → ban). **Le code décide sur des chiffres, jamais le
  modèle de langue.**
- **Proposé** (toujours, quel que soit le mode) : toute décision **inférée par l'IA/V2** ou de confiance
  moyenne → carte d'action à valider dans la console.
- **Validation humaine obligatoire** : tout geste **irréversible**, tout **confinement d'appareil interne**
  (via garde), et tout score **95-100** (incident critique). ACTIVE ne lève jamais cette garde.

Donc : ACTIVE = « les gestes sûrs et réversibles s'appliquent seuls, le reste se propose, l'exceptionnel se
valide ». Jamais un faux positif inféré par l'IA auto-appliqué sur gk2.

## Non-objectifs / Anti-objectifs (repris de #3827, non négociables)

- **Aucune action offensive / hack-back** : pas d'intrusion, pas d'exploitation d'un tiers, pas de DoS vers une
  source externe, pas de « trafic inversé ». La box n'émet rien vers l'attaquant au-delà de sa réponse normale.
- Pas de nouveau capteur/IDS ; pas de geste hors catalogue audité ; pas de règle nft/nginx/WG écrite à la main.
- Pas de scoring/corrélation réimplémentés : SADE lit Actor Intelligence + dossiers V2.
- SADE ne se bloque jamais lui-même ni son canal d'administration (voir garde-fous).

## Échelle unifiée : score → niveau → mode

Le score 0-100 **est celui d'Actor Intelligence** (pas recalculé). SADE le projette sur l'échelle #3827 étendue :

| Score | Niveau | Geste(s) | Application en mode ACTIVE |
|---|---|---|---|
| 0-19 | **observer** (N1) | enrichissement du dossier | auto (aucune action réseau) |
| 20-59 | **reactive** (N2a, nouveau) | `limite_debit`, délais, protection d'endpoint | auto si cas sûr |
| 60-79 | **contenir** (N2) | `ban` TTL, `quarantaine_dns`, `isoler_zone`, `rejet_doh_dot` | auto si cas sûr ; sinon proposé |
| 80-94 | **usager** (N3) | `ban` long, `ban_bloc` /24, `propager_maillage`, `rediriger_leurre` | auto si récidive/campagne confirmée par le code ; sinon proposé |
| 95-100 | **incident** | confinement renforcé, mesures exceptionnelles | **proposé + validation humaine obligatoire** |

Les **plafonds de gk2** (complément V2 : `ban` 60/h, 400/j…) valent pour la **somme** des gestes, pas par
niveau. La montée est pilotée par les **signaux de persistance** de #3827 (tentatives, couches, fenêtre,
campagne, récidive) ; la redescente ne défait pas les bans actifs (ils expirent seuls).

## Modes de fonctionnement (commutateur global)

- **OBSERVE** : détection + analyse + console, zéro action (kill-switch de facto).
- **REACTIVE** : + gestes de faible impact auto (ralentissement, enrichissement) ; blocage/confinement proposés.
- **ACTIVE** (défaut) : + blocage/confinement auto **selon la réconciliation ci-dessus** ; exceptionnel validé.
- **AGGRESSIVE** : seuils abaissés + surveillance renforcée + **validation humaine élargie** ; **jamais** une
  action offensive ni hors périmètre. Réservé au banc/pic d'attaque.

Changement de mode : audité, réservé à un administrateur réel (`require_jwt`), avec **retour immédiat à OBSERVE**
en cas d'anomalie (boucle de blocage, plafond, perte du canal admin).

## Garde-fous obligatoires (prompt §12, en grande partie déjà présents)

- **Dry-run** par politique (simuler une décision sans l'appliquer) — nouveau côté SADE.
- **Liste blanche prioritaire** : adresses de gestion (SSH/admin LAN+mesh), services critiques, pairs du
  maillage, passerelle. SADE **ne bloque jamais** ces cibles ni une IP privée ([[feedback_lan_mesh_zone_de_confiance]]).
- **Ne jamais couper son propre canal d'administration** (garde dure, testée).
- **Expiration automatique** (TTL) + **rollback** (double-tampon 4R existant) + **retour arrière** par geste.
- **Plafond de décisions auto** par fenêtre + **anti-boucle** (une même cible n'enchaîne pas des bans en rafale).
- **Détection de faux positifs** : un geste qui frappe une cible légitime récurrente abaisse la confiance et
  repasse en proposé.
- **Résistance au redémarrage** (état en SQLite + nft drop-ins persistants existants).
- **Audit inviolable autant que possible** : chaque décision écrite dans `audit.log` append-only avec ses
  facteurs (score, signaux, geste, motif, TTL, résultat, opérateur si validation).

## Console « Cyber Defense Live »

Prolonge la page SOC (`secubox-hub/www/soc`) + cardlet actor + Radar/Chaîne V2, en Aurora (maquette avant code,
comme Radar/Chaîne validés 14/11) :

- Frise **DÉTECTION → ANALYSE → DÉCISION → ACTION → VÉRIFICATION** par incident.
- Menaces (24 h), sources actives, services ciblés, score, blocages actifs, quarantaines, incidents.
- Panneau de contrôle : mode (OBSERVE/REACTIVE/ACTIVE/AGGRESSIVE), seuils, exceptions, **file d'approbation**
  des mesures proposées, déblocage manuel, **retour arrière**. Le modèle **résume** (« monté en N3 après
  récidive sur le /24 ») ; il **ne décide ni du niveau ni de la montée**.

## API de façade (`/api/v1/active-defense/…`)

Façade **unifiante** ; sous le capot, chaque route délègue au module réel. `require_jwt` sur toute
administration ; lecture `require_lecture` ; socket Unix `/run/secubox/active-defense.sock`, jamais de port TCP.

- `GET status|threats|threats/{id}|events|actions|policies` → agrège Actor Intelligence + dossiers V2 + bans WAF.
- `POST analyze` → relit un dossier (pas de nouveau scoring).
- `POST respond|approve|unblock|rollback|quarantine|allowlist` → **propose** et, après garde/validation,
  **applique par le chemin audité** (`ai-ban`/`wafctl` côté gk2, garde côté appareil). Aucune écriture directe.

## Mesh Defense

Réutilise threatmesh/`propager_maillage` : une menace **qualifiée** sur un nœud produit une **alerte partagée**
et une politique sur les autres nœuds ; **jamais** un blocage non vérifié propagé en aveugle
([[project_mesh_bans_vs_threatmesh_widget]]). Périmètre GK2/GK3/C3Box.

## Périmètre et déploiement progressif

- **Internet → gk2** pour les attaquants externes ; **appareils internes** restent à `secubox-garde` (SADE
  propose, garde applique) — frontière #3827 scénario 4.
- **Seuils et montée affinés au banc gk4-gk7 d'abord, jamais sur gk2 en premier** ([[feedback_pilotage_pas_de_deploiement_avant_l5]]).
- Déploiement par étapes : (1) console + API lecture seule (OBSERVE) ; (2) REACTIVE sur banc ; (3) ACTIVE sur
  banc, mesure des faux positifs ; (4) ACTIVE sur gk2 une fois la confiance établie ; (5) mesh + AGGRESSIVE.

## Laissé au constructeur

- Les seuils exacts (bandes de score, `n2/n3_tentatives`, fenêtres, plafonds de décisions auto) : départ
  raisonnable + affinage au banc.
- Schéma SQLite de SADE : il ne **duplique pas** threats/events/scores (ils vivent dans Actor Intelligence/V2) ;
  il tient **ses** tables — `policies`, `mode`, `decisions` (file d'approbation + applied), `allowlist`,
  `rollbacks`, `incidents` — et **référence** les dossiers V2 par id.
- `/etc/secubox/active-defense/` : `default.yaml`/`aggressive.yaml`/`custom.yaml` (modes, seuils, exceptions) ;
  schéma validé, double-tampon pour les changements sensibles.
- Le point d'application exact de chaque geste (déjà tracé par #3827 + catalogue V2).

## Décisions prises par l'assistant (à vérifier)

- **SADE = chapeau mince, pas un moteur de détection/scoring neuf** (choix propriétaire « chapeau unifiant »).
- **ACTIVE par défaut, concilié** : auto seulement pour le déterministe réversible ; IA-inféré proposé ;
  irréversible/interne/95-100 validé humainement. Si le propriétaire veut vraiment l'auto-application des
  décisions IA, c'est un changement explicite de la règle « l'IA propose », à rediscuter, pas à présumer.
- **Zéro offensif** (repris de #3827). Toute capacité active reste défensive et locale.
- **Rien de nouveau écrit à la main** : SADE applique par `ai-ban`/`wafctl`/garde, jamais en direct.

Liens : [[project_secubox_ai_v2]] · [[project_actor_autoban_propose]] · [[feedback_ia_jamais_inventer]] ·
[[project_waf_auto_bans_2238]] · [[project_mesh_bans_vs_threatmesh_widget]] ·
[[feedback_pilotage_pas_de_deploiement_avant_l5]] · [[project_headless_remote_controller_vision]].
