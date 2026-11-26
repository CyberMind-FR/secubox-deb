<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CyberMind AI V3 — architecture cible et plan (#3981, phase 2)

Suite de `docs/CYBERMIND-AI-V3-AUDIT.md`. **Proposition à arbitrer**, pas une décision. Tout ce qui touche à
OpenJarvis est **conditionnel** à la phase 1 bis (clone et lecture, impossibles hors ligne le 2026-11-26).

## 1. Principe directeur

OpenJarvis (s'il passe l'audit) est un **moteur de raisonnement sans mains** : il lit, cherche, résume,
planifie et **propose**. CyberMind garde tout ce qui touche au monde : comptes, réseau, maillage,
déploiement, et le seul chemin d'action existant (`ai-ban`, gk2 fait foi). La règle de la spec V2 § 12 est
étendue à tout agent : **le modèle reçoit un texte, rend un JSON validé par du code ; aucune décision de
sécurité réseau n'est prise par un LLM.**

## 2. Ce qui va sur quelle machine (adapté aux faits)

| Machine | Profil | Rôle IA | Ne fait pas |
|---|---|---|---|
| gk0 (PC, RTX 3050 4 Go, Vulkan) | FULL (modeste) | **moteur** principal : llama.cpp (modèles ≤ ~9B Q4/Q5), runtime d'agents pour Deep Research / Digest ; POC public (relais) | ni vLLM ni SGLang réalistes (4 Go) ; jamais d'action sur gk2 |
| gk3 (secubox-ai V2) | MESH, contrôle | **plan de contrôle** : API `/api/v1/ai/*`, routeur, mémoire, veille, exécuteur `ai-ban`, journal | pas d'inférence lourde |
| gk2 (prod, exposé) | MESH, cible | fait foi : bornes, plafonds, SADE, audit ; lu par gk3 | **aucun runtime d'agents**, aucun moteur |
| MOCHAbin / C3Box (arm64 8 Go) | EDGE | client léger : relais vers le meilleur moteur du maillage, ZIA heuristique, tout au plus un 0,5B pour un tri trivial | pas d'agent, pas de modèle > 1B (essai 25/11) |

## 3. ADR

**ADR-1 — Pas de nouveau routeur : étendre `secubox-ai/api/moteurs.py`.**
Pourquoi : deux routeurs existent déjà (audit § 5.1). Alternatives : routeur d'OpenJarvis (couplage au
runtime tiers) ; nouveau paquet `-ai-router` (troisième copie). Conséquences : découverte par le maillage,
latence mesurée, quotas et repli s'ajoutent à `moteurs.py` ; la gateway reste la frontière de souveraineté
(classes de données) et devient un **moteur parmi d'autres** pour le routeur.

**ADR-2 — Une seule mémoire : `memoire.db` (FTS5) derrière l'API.**
Pourquoi : interdiction de dupliquer ; FTS5 marche (`memoire.py:62-67`). Alternatives : mémoire native
d'OpenJarvis ; localrecall. Conséquences : OpenJarvis reçoit un outil « chercher en mémoire » (lecture
API), pas d'accès fichier ; vecteurs en table annexe optionnelle (sqlite-vec si empaquetable en arm64,
sinon absent) ; localrecall migré plus tard ou laissé en l'état (décision séparée).

**ADR-3 — OpenJarvis en environnement Python dédié, livré tout construit.**
Pourquoi : isoler ses dépendances de `python3-fastapi` Debian. Alternatives : paquets Debian un à un (coût
prohibitif) ; `pip` au postinst (réseau en install, non reproductible — précédent billets à ne pas
copier). Conséquences : venv `/usr/lib/secubox/ai-agents/venv` construit en CI avec roues épinglées par
empreinte, `Architecture: amd64` d'abord (gk0) ; arm64 seulement si un besoin EDGE réel apparaît.

**ADR-4 — Le runtime d'agents tourne en service confiné, LXC en option.**
Pourquoi : le confinement systemd + AppArmor du module est déjà fort (`secubox-ai-moteur` : `AF_UNIX`
seul, `IPAddressDeny=any`). Alternatives : LXC non privilégié d'emblée (demandé) — retenu **si** l'audit
montre des outils d'exécution impossibles à retirer (Q8) ; Docker : exclu. Conséquences : unité
`secubox-ai-agents.service`, compte `secubox-ai-agents`, `ProtectHome`, réseau limité au socket du
routeur et à l'outil de recherche (lui-même derrière la garde SSRF R13 de `recherche.py`).

**ADR-5 — Outils des agents = liste blanche en lecture ; actions = propositions.**
Pourquoi : « l'IA propose, le code décide ». Conséquences : un agent peut créer une **proposition** dans
`veille.db` (même table que la V2) ; elle suit le circuit existant (approbation humaine ou cas sûr codé,
plafonds, SADE, revalidation, audit). Aucun outil shell, fichier, `sudo`, `systemd-run`, MCP d'écriture.

**ADR-6 — AI Mesh = annuaire existant + capacité « moteur IA ».**
Pourquoi : maillage WireGuard et annuaire existent. Conséquences : chaque nœud publie `{moteurs, modèles,
contexte, j/s mesurés, charge}` ; heartbeat par l'annuaire ; authentification mutuelle = clé WireGuard +
JWT de service ; reprise = repli du routeur.

## 4. Découpage en paquets (moins que proposé)

| Proposé | Recommandé | Raison |
|---|---|---|
| `secubox-ai` | **garder**, porte API V3, routeur, mémoire, sécurité, évaluation | tout y existe ; le fragmenter casse la V2 en production |
| `secubox-ai-openjarvis` | **`secubox-ai-agents`** (nouveau, seul ajout) | isole le venv tiers et sa licence ; désinstallable sans toucher la veille |
| `-ai-router`, `-ai-memory`, `-ai-security` | **non** (modules Python de `secubox-ai`) | un paquet de plus = une unité, un compte, un AppArmor, une version à synchroniser, pour aucune frontière de privilège nouvelle |
| `-ai-mesh` | **non** : capacité publiée par `secubox-annuaire` | le maillage existe |
| `-ai-eval` | **non** : `secubox-ai` + script de banc | outil de banc, pas un service |
| `secubox-zia` | **garder** ; ajoute la vue « moteurs et agents » | existe |

Bilan : **un seul nouveau paquet**. `secubox-ai-gateway` et `secubox-zia-llm` inchangés.

## 5. API

Nouvelles routes sous `/api/v1/ai/` (socket `ai.sock`), toutes `require_jwt` sauf mention ; les anciennes
(`/essai/flux`, `/memoire*`, `/moteur*`, `/modeles*`, `/propositions*`, …) restent telles quelles.

| Route | Méthode | Note |
|---|---|---|
| `/chat` | POST | alias versionné de `/essai/flux` (même code) |
| `/engines`, `/models` | GET | vue du routeur (locaux + maillage) |
| `/agents`, `/agents/{id}` | GET | agents **déclarés** (fichier TOML signé par paquet, pas créés par l'API) |
| `/agents/{id}/run` | POST | lance une exécution bornée (durée, jetons, outils) ; rend un identifiant de tâche |
| `/tasks`, `/tasks/{id}` | GET / POST `…/arreter` | réutilise `taches.py` |
| `/skills`, `/tools` | GET | liste blanche effective |
| `/memory`, `/knowledge` | GET/POST | façade de `memoire.py` |
| `/scheduler` | GET | lecture des minuteries ; modification = admin + audit |
| `/mesh/nodes` | GET `require_lecture` | capacités IA des pairs |
| `/security` | GET | politiques, plafonds, journal (lecture) |
| `/evaluation` | GET / POST `…/lancer` | banc de requêtes reproductible |

Seules `/chat`, `/memory`, `/knowledge` peuvent recevoir `require_session` pour un usage d'usager, **posé
explicitement** et sur accord.

## 6. Sécurité

- Invariant : aucune route, aucun outil d'agent n'atteint `wafctl`, nftables, `haproxyctl` ou l'exécuteur
  autrement que par une **proposition** ; testé par un test d'architecture (import interdit + liste des
  outils figée).
- Injection de prompt : tout contenu lu (pages, documents, journaux) est **donnée** ; les sorties des
  agents sont validées par Pydantic `extra="forbid"` ; une proposition issue d'un agent n'est jamais un
  « cas sûr » d'office (approbation humaine requise au début).
- SSRF : la recherche passe par la garde R13 existante ; l'unité des agents n'a pas d'autre réseau.
- Journal : chaque exécution d'agent (agent, outils appelés, durée, jetons ; ni question ni réponse, règle
  0.1.x) dans `audit.log` par le relais existant.
- Comptes : `secubox-ai-agents` dédié ; corriger au passage `User=secubox` de `secubox-zia*` (issue à part).
- Préalable : garde de `secubox-ai-gateway` `POST /v1/chat/completions` (audit § 2.6) avant de faire de la
  gateway un moteur du routeur.

## 7. Migration

Rien n'est déplacé : `memoire.db` et `veille.db` restent où elles sont ; nouvelles tables par le mécanisme de
migration versionné avec sauvegarde (`veille/base.py`). Conversations : `historique` existant. Configs :
nouvelles sections dans `ai.toml`, anciennes clés lues telles quelles. Rollback : `apt install secubox-ai=<version
précédente>` + la sauvegarde `.avant-NNNN` ; `secubox-ai-agents` se retire sans effet sur la veille.
Scripts de postinst idempotents (règle `postinst` préserve l'état).

## 8. Plan phasé

| Phase | Contenu | Critère de sortie | Accord du propriétaire |
|---|---|---|---|
| 1 bis | clone OpenJarvis, réponses Q1-Q12 | audit § 3 réécrit avec fichiers et lignes | **licence** |
| 3 | garde de la gateway ; comptes ZIA dédiés | tests, déployé gk3 | non (correctifs) |
| 4 | routeur étendu (ADR-1) + `/engines`, `/models`, `/mesh/nodes` + capacité annuaire | gk3 choisit gk0 quand il est là, se replie sinon ; mesuré | non |
| 5 | `secubox-ai-agents` sur **gk0**, un agent lecture seule (Digest du matin à partir de `veille.db`), outils : mémoire + recherche | 7 jours sans appel hors liste, sorties validées | **oui** (nouveau paquet, venv tiers) |
| 6 | agents qui proposent (table des propositions), approbation humaine seule | aucune proposition d'agent exécutée sans clic | **oui** |
| 7 | Deep Research, vue ZIA du Hall, banc d'évaluation | banc reproductible publié | exposition publique : **oui** |

Demandent toujours l'accord : tout ce qui est destructif (bases, retrait de routes), toute API incompatible,
toute licence tierce, toute exposition publique, et toute extension des gestes d'action.
