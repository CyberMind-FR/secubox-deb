<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai-agents — plan par tranches (#3986, suite de #3981)

Paquet validé par le propriétaire le 2026-11-26, avec cette demande : « il me faudra le reste de Jarvis :
chatbot, mémoire, apprentissage… ». Base : `docs/CYBERMIND-AI-V3-AUDIT.md` (§ 3, § 8) et
`docs/CYBERMIND-AI-V3-ARCHITECTURE.md` (PR #3983).

## Invariants (toutes tranches, chacun couvert par un test)

1. OpenJarvis est une **bibliothèque** derrière NOTRE API FastAPI. Jamais son serveur ni sa CLI : ils
   importent le minage (audit § 8.5).
2. **Aucun outil** shell, code, fichier de l'hôte, navigateur, Docker ni réseau direct : les modules sont
   supprimés du venv livré (`outils-retires.txt`, `sandbox/`). La politique de capacités refuse par défaut
   (`CapabilityPolicy(default_deny=True)`).
3. Minage « Pearl » absent du venv et jamais importé (`mining/`, `cli/mine_cmd.py`, `cli/pearl_cmd.py`).
4. Aucune télémétrie : `OPENJARVIS_NO_UPDATE_CHECK=1`, hôte d'analytique neutralisé, et surtout **réseau
   fermé** au niveau de l'unité (`RestrictAddressFamilies=AF_UNIX` en tranche A). Ce sont la configuration
   ET le confinement, pas la configuration seule.
5. Garde sur chaque route sauf `/health` : `require_jwt` sur une box ; jeton local 0600 sur gk0 seulement.
   Socket Unix, jamais de port TCP.
6. Toute action sur une box = **proposition** par le circuit existant (`ai-ban` / gestes, gk2 fait foi).
7. Aucun root à l'exécution ; root seulement pour construire le venv (comme un postinst).
8. Une seule base par usage : conversations (SessionStore d'OpenJarvis), mémoire documentaire par agent
   (SQLiteMemory, extension Rust). `memoire.db` de secubox-ai n'est ni copiée ni lue en tranche A ; leur
   rapprochement se tranche en tranche E (voir accord 4).
9. Preuves : tests sur le vrai moteur et la vraie extension Rust. Un faux moteur ne prouve rien ; un test qui
   ne peut pas tourner est sauté **en le disant**.

## Tranche A — gk0 : conversation, flux, sessions, mémoire

| # | Tâche | Fait quand |
|---|---|---|
| A1 | `sbin/secubox-ai-agents-construire` : venv `/opt/secubox-ai-agents/venv-<date>`, lien `venv` basculé atomiquement (`venv.avant` gardé), `requirements.txt` épinglé par empreinte (17 paquets, ni python-telegram-bot, ni posthog, ni datasets), OpenJarvis `556ddf32` sans dépendances, extension Rust par `maturin build`, minage, bac à sable et outils interdits supprimés, venv root en lecture seule | `/opt/secubox-ai-agents/venv` actif, `import openjarvis.mining` échoue |
| A2 | `agents/` : garde (`garde.py`, sans OpenJarvis), moteur (`LlamaCppEngine` sur socket Unix), conversations et mémoire (`stockage.py`), API (`app.py`) : `/health`, `/status`, `POST /chat` (SSE), `/conversations[/{id}]` (GET, DELETE), `/memoire/{agent}` (POST, GET ?q=) | tests verts dans le venv livré |
| A3 | Unité utilisateur durcie `secubox-ai-agents-gk0.service` (pas de réseau, `PrivateUsers`, `ProtectSystem=strict`, filtre d'appels système, `MemoryMax=1G`) | service actif, socket 0600 |
| A4 | Relais POC : `agents_relais.py` + `agents.html`, deux lignes en fin de `relais.py`, préfixe `/api/v1/ai/jarvis/` (le POC a déjà `POST /api/v1/ai/agents/{nom}`), page `/jarvis`, local seulement | relais redémarré une fois, ses routes existantes répondent, `/jarvis` converse |
| A5 | Mesures sur le vrai moteur (Gemma 3 4B, Vulkan) : premier mot, durée, débit, mémoire du service | chiffres dans la PR |

Sortie de A : un échange en flux depuis `/jarvis`, l'historique repris au tour suivant, la mémoire citée ;
tests verts dans `/opt` ; aucune route existante du relais cassée ; rien n'est exposé publiquement.

## Tranche B — apprentissage et évaluation

Ce qu'OpenJarvis fournit **réellement** (à relire avant d'écrire : `learning/`, `evals/`, `skills/`,
`telemetry/`) : banc d'évaluation (jeux locaux seulement, aucun téléchargement Hugging Face en service),
compétences déclaratives (`skills/`) sans outil interdit, apprentissage de prompts (dspy/gepa en extras :
**accord** avant tout ajout de dépendance). Sortie : un banc reproductible sur gk0 (questions SecuBox,
réponses attendues), score publié, comparaison de modèles du POC.

## Tranche C — Deep Research, Morning Digest, scheduler (#3990, livrée sur gk0)

Fait : recherche par `NativeReActAgent` (et non `DeepResearchAgent` : Gemma 3 4B ne produit pas d'appel
d'outil natif sur ce llama-server, essai du 2026-11-26), digest par `MorningDigestAgent` avec notre
`digest_collect`, planificateur `TaskScheduler`, pont SearXNG sur socket Unix. Reste : `IPAddressDeny` du pont
non appliqué en unité utilisateur (tranche E : unité système).


`DeepResearchAgent`, `MorningDigestAgent`, `scheduler/` d'OpenJarvis. Recherche web : un outil À NOUS qui
n'appelle que la SearXNG locale du POC (`127.0.0.1:8888`), derrière la garde SSRF de secubox-ai (R13) ;
l'unité s'ouvre à cette seule adresse (`IPAddressAllow=127.0.0.1/32` en unité système, ou socket Unix).
Digest à partir de `veille.db` (lecture). Le scheduler d'OpenJarvis ne lance que des agents sans outil
d'action. Sortie : digest quotidien généré sur gk0 ; recherche citant ses sources ; aucun appel hors SearXNG
(vérifié par l'unité, pas par le code).

## Tranche D — ZIA du Hall

Vue « moteurs et agents » dans `secubox-zia` (lecture), conversation depuis le Hall par l'agrégateur,
`require_session` posé **explicitement** sur les seules routes d'usager : **accord** (accès d'usagers).

## Tranche E — gk3 et maillage

Paquet Debian `secubox-ai-agents` (`debian/`, `Architecture: amd64` d'abord, venv construit en CI avec ses
roues), compte système dédié, AppArmor `enforce`, unité système, route nginx `/api/v1/ai/agents/` derrière
`require_jwt`, routeur de moteurs (ADR-1) qui choisit gk0 par le maillage et se replie. Propositions d'agents
dans la table des propositions de la veille V2, approbation humaine seule. Sortie : gk3 converse par gk0 ;
une proposition d'agent n'est jamais exécutée sans clic.

## Ce qui demande l'accord du propriétaire

1. Toute **exposition publique** (nom public du relais, `ai.gk0`, Hall pour les usagers).
2. Toute nouvelle **dépendance** au-delà de `requirements.txt` (dspy, gepa, faiss, sentence-transformers…).
3. Toute **action** d'agent, même proposée (tranche E), et toute extension des gestes.
4. Fusion ou migration de **mémoires** (`memoire.db` de secubox-ai, POC, OpenJarvis) : destructif possible.
5. Déploiement sur une **box** (gk3) et publication sur `apt.secubox.in`.
6. Montée de commit d'OpenJarvis (projet Alpha, API instable) : relecture de `security/` à chaque montée.
