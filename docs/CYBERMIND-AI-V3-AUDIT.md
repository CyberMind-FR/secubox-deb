<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# CyberMind AI V3 — audit de l'existant et d'OpenJarvis (#3981, phase 1)

Document de travail, **non destructif** : aucun code IA modifié, rien installé, aucune connexion aux box.
Base : `master` au commit `6f4e5f855` (2026-11-26). Les numéros de ligne renvoient à cette révision.

## 0. Limites de cet audit (à lire d'abord)

- **OpenJarvis n'a PAS pu être cloné.** Au moment de l'audit, le poste n'avait aucun accès réseau
  (`gh` et `git ls-remote` : *network is unreachable*, `ssh github.com` idem). Aucune copie locale n'existe
  (recherche `*jarvis*` sur le disque : rien). Ni le fork `gkerma` ni l'amont n'ont été lus.
- Tout ce qui est dit d'OpenJarvis en § 3 est donc **non vérifié** : c'est une grille de questions et des
  souvenirs publics de l'auteur du document, marqués comme tels. **Aucune décision d'intégration ne doit
  s'appuyer sur § 3 avant la phase 1 bis** (§ 7) : clone en lecture seule, lecture des fichiers cités.
- L'issue #3981 n'a pas pu être relue (`gh issue view` hors ligne) : le cadrage vient du texte du
  propriétaire transmis à l'agent. Le worktree a été créé à la main (`git worktree add`, même convention
  que `scripts/agent-worktree.sh`, qui exige `gh`).
- L'état **déployé** des box (gk0, gk2, gk3) n'a pas été relevé (consigne : pas de SSH). L'inventaire
  ci-dessous est celui des **sources** ; seul le POC de gk0 (ce poste) a été listé, sans lire ses secrets.

## 1. Faits d'entrée (vérifiés par le propriétaire)

| Fait | Conséquence |
|---|---|
| gk0 = RTX 3050 **4 Go** + Iris Xe (pas de 3060 12 Go) ; llama.cpp du POC construit en Vulkan (`~/poc-secubox-ai/build-vk/CMakeCache.txt`, `GGML_CUDA=OFF`) | modèles ≤ ~7-9B quantifiés, contexte modeste ; vLLM/SGLang (CUDA, mémoire GPU large) hors de portée réaliste |
| Essai arm64 25/11 (Cortex-A72, llama.cpp) : Qwen 0,5B 8,4 j/s, Llama 1B 4,6, Qwen 1,5B 2,0 ; classement 0 à 1 sur 4 | **aucune inférence utile sur MOCHAbin** ; une box arm64 route, elle ne pense pas |
| Modèle partagé gk6+gk1 par RPC : 1,1-2,0 j/s | pas de modèle découpé entre box (déjà acté) |
| POC public sur gk0 (`~/poc-secubox-ai`, relais) ; secubox-ai V2 sur gk3 lit gk2 et agit par `ai-ban` | deux lieux d'exécution existent déjà, avec un contrat « l'IA propose, le code décide » |

## 2. Inventaire de l'existant (sources)

### 2.1 Paquets

| Paquet | Version | Rôle | Taille utile |
|---|---|---|---|
| `secubox-ai` | 2.3.3 (`packages/secubox-ai/debian/changelog:1`) | module IA de gk3 porté du POC : dialogue, mémoire, documents, moteurs, veille V2, radar, Nuclei | API ~5 000 l., veille ~8 000 l., page 2 239 l. |
| `secubox-ai-gateway` | 1.6.0 | proxy OpenAI-compatible à 3 classes (LOCAL_ONLY / SANITIZED / CLOUD_DIRECT), contient `localrecall` et `mcp-server` (`debian/control` : `Replaces`/`Breaks`) | `api/main.py` 1 038 l., MCP 1 022 l., localrecall 683 l. |
| `secubox-zia` | 0.4.4 | ZIA du Hall : interface humaine du bus d'objets, heuristique + LLM local, délégation niveau 2/3 | `api/` ~2 100 l. |
| `secubox-zia-llm` | 0.3.0 | fournit `llama-server` (`/usr/lib/secubox/zia-llm/llama-server`) et `secubox-zia-getmodel` | unité + script |

`secubox-ai` dépend de `secubox-zia-llm (>= 0.3.0~)` (`packages/secubox-ai/debian/control:22`) : le binaire
llama.cpp est **déjà** empaqueté et partagé.

### 2.2 API de `secubox-ai` (socket `/run/secubox/ai.sock`, préfixe public `/api/v1/ai/` retiré par nginx)

Montage : `packages/secubox-ai/api/main.py:53-66`. Pas d'OpenAPI servie (`main.py:51`).

| Domaine | Routes (fichier:ligne) | Garde |
|---|---|---|
| santé / état | `GET /health` (`main.py:28`), `GET /status` (`main.py:33`) | aucune / `require_jwt` |
| dialogue (flux) | `POST /essai/flux` (`dialogue.py:83`) | routeur `require_jwt` (`dialogue.py:80`) |
| moteur | `GET /moteur`, `POST /moteur/{choix}` (`moteurs.py:387,392`) | `require_jwt` par route |
| mémoire | `/historique*`, `/memoire*`, `/memoire-export`, `/memoire-import`, `/memoire-reglage` (`memoire.py:165-357`) | routeur `require_jwt` (`memoire.py:161`) |
| documents | `POST /documents`, `/documents/fichier`, `/documents/{id}/analyser`, `/memoire/documents/{doc}` (`documents.py:207-323`) | routeur `require_jwt` (`documents.py:204`) |
| modèles | `/modeles*`, `/medias/gguf*`, `/depots*` (`modeles.py:335-529`) | `require_jwt` par route |
| tâches | `/taches/{t}`, `/travaux*`, `/tout-arreter` (`taches.py:246-302`) | routeur `require_jwt` |
| menaces / radar | `/menaces/releve|resumer|demander` (`menaces.py:551-584`), `/menaces/pays|chaine|series`, `/dossiers*` (`radar.py:347-585`) | routeur `require_jwt` |
| réponses V2 | `/propositions*`, `/actions*`, `/veille/etat|suspendre|reprendre`, `/filtres*`, `/dossiers/{id}/redescendre|analyser` (`reponses.py:125-337`) | routeur `require_jwt` (`reponses.py:30`) |
| code, médias, journal, réglages | `code.py:76`, `medias.py:172-195`, `journal.py:88`, `reglages.py:226-231` | `require_jwt` |

Constat : **toutes les routes sauf `/health` sont gardées**, mais par deux styles (garde au routeur ou à la
route) ; une V3 doit garder ce style et le tester (`tests/test_socle_3583.py` existe).

### 2.3 Unités systemd et confinement (`packages/secubox-ai/systemd/`)

| Unité | Compte | Réseau | Mémoire | AppArmor |
|---|---|---|---|---|
| `secubox-ai.service` (API) | `secubox-ai` (l.17) | `IPAddressDeny` LAN, `Allow 127.0.0.1` (l.89-90) + drop-in LAN posé par postinst (`postinst:147`) | 768M | `secubox-ai-api` |
| `secubox-ai-moteur.service` (llama-server) | `secubox-ai-moteur` | **`AF_UNIX` seul, `IPAddressDeny=any`** (l.60-61), socket `/run/secubox-ai/moteur.sock` | 512M | `secubox-ai-moteur` |
| `secubox-ai-veille.service` | `secubox-ai` | `IPAddressDeny=any` + `Allow 127.0.0.1` (l.91-92) | 256M | `secubox-ai-veille` |
| `secubox-ai-nuclei.service` + `.timer` | `secubox-ai-nuclei` | Internet public seul, LAN refusé (l.68-69), `CPUQuota=50%` | 512M | `secubox-ai-nuclei` |
| `secubox-ai-demandes.service`, `secubox-ai-preparer.service` | root (ctl `secubox-aictl`, 1 288 l.) | `AF_UNIX` / préparation | — | — (exception de ctl root) |

Le module ne lance jamais `systemctl` : il dépose `$SECUBOX_AI_RUN/demandes/<action>.demande`
(`api/moteurs.py`, docstring l.1-8), un ctl root les exécute. **C'est déjà la « passerelle de sécurité »
demandée**, pour le pilotage du moteur.

### 2.4 Bases et état

- `memoire.db` : SQLite WAL, **FTS5** sans accents (`api/memoire.py:7`, tables l.62-67 : `souvenirs`,
  `passages` fts5, `historique`). Export/import versionnés (`memoire.py:306,340`). → la « mémoire SQLite
  FTS5/BM25 » demandée **existe** ; il manque seulement les vecteurs (optionnels).
- `veille.db` : SQLite WAL, migrations versionnées avec sauvegarde `veille.db.avant-NNNN`, jamais supprimée
  (`veille/base.py:5-9,76,117`). → patron de migration à réutiliser pour la V3.
- POC gk0 : `~/poc-secubox-ai/memoire/memoire.db`, journaux `relais/audit.jsonl`, `relais/gestes.jsonl`
  (fichiers listés, contenu non lu ; `relais/cles.json` volontairement non ouvert).

### 2.5 Comptes de service, garde-fous, actions

- Comptes : `secubox-ai`, `secubox-ai-moteur`, `secubox-ai-nuclei` (gk3) ; clé `ai-filtres` pour les filtres WAF
  construits par le code, jamais par le texte du modèle (`veille/apprentissage.py:5-9`) ; `ai-ban` = clé de signature
  côté gk3, vérifiée par gk2 (`packages/secubox-ai/veille/executeur.py:5-40`, spec V2 § 5.3).
- **Seul chemin d'écriture gk3 → gk2** : l'exécuteur (`executeur.py:5`). Rapprochement avant tout envoi,
  revalidation (catalogue de gestes, cible publique hors plages protégées, durées dans les bornes de gk2),
  plafonds gk3 ≤ gk2 (`executeur.py:74-75,501-525`), auto-suspension après 3 refus `plafond_*` en 10 min,
  un 503 ou un 401/403 (`executeur.py:37`), mode `observation` / `hybride`, respect du mode SADE de gk2.
- Côté gk2 : gestes exécutables `ban, limiter, leurre, prolonger` (`packages/secubox-soc/api/defense.py:628`),
  mêmes verbes que le compte `ai-ban`.
- Spec V2 § 12 (`docs/superpowers/specs/2026-11-14-secubox-ai-v2-design.md:487-501`) : « le modèle n'a ni
  shell, ni fichier, ni réseau : il reçoit un texte et rend un JSON que le code valide » (Pydantic strict,
  `extra="forbid"`, § 9.2). **C'est exactement la règle « aucune action réseau décidée par le LLM ».**

### 2.6 Passerelle et MCP (`secubox-ai-gateway`)

- Classification de données et repli de fournisseurs (`api/main.py:1-16`, 3 classes) : un **routeur de
  moteurs** existe déjà, orienté souveraineté, pas latence/quotas fins.
- **Constat de sécurité** : `POST /v1/chat/completions` (`api/main.py:705`) ne porte **aucune** garde
  FastAPI, et l'application n'a pas de dépendance globale (`main.py:62`). Le limiteur s'appuie sur
  `x-api-key` ou l'adresse du client (`main.py:726`). À vérifier : protection éventuelle par nginx/WAF.
  Écart possible à `RULES-CODE.md` § 3 → **issue séparée à ouvrir**, hors périmètre de ce document.
- MCP : outils `secubox.waf.status`, `secubox.waf.threats`, … (`composants/mcp-server/api/main.py:241+`),
  `POST /tools/{tool}/call` gardé `require_jwt` (l.982), appels `subprocess.run` (l.582, 704, 714) : un
  **serveur MCP existe déjà** ; ses sous-processus doivent être relus avant de l'ouvrir à un runtime d'agents.

### 2.7 ZIA (`secubox-zia`)

- `api/main.py:1-12` : la ZIA « ne possède pas les données », elle interprète le bus d'objets du Hall, qui
  applique l'ACL ; niveaux 1 (local) / 2 (VHOST) / 3 (remote, `remote_enabled=false`, budget 20/h,
  `conf/zia.toml`).
- Routes : `POST /v1/chat` (`main.py:350`, rôle dérivé, cf. `tests/test_role_derive.py`), admin
  `/securite/*`, `/config`, `/llm/*` sous `exige_admin`.
- `secubox-zia.service` et `secubox-zia-llm.service` tournent en `User=secubox` (compte partagé), pas en
  compte dédié : écart à AGENTS.md (« utilisateur dédié par service ») à noter pour la V3.

### 2.8 LXC

Aucun conteneur LXC IA dans les sources : tout tourne en services systemd confinés sur l'hôte (gk3) ou en
processus utilisateur (POC gk0). La demande « LXC non privilégié » est donc **nouvelle**.

### 2.9 Pages

`packages/secubox-ai/www/ai/index.html` (2 239 l., menu `130-ai.json`), `secubox-zia/www/zia/{index,admin,
securite,micro}.html`, `secubox-ai-gateway/www/ai-gateway/{index,multimodal}.html`, pages localrecall et
mcp-server. Le « tableau ZIA dans le Hall » a une base (`zia/index.html`, Aurora #2646).

## 3. OpenJarvis — grille d'audit (NON VÉRIFIÉE)

Ce que l'auteur croit savoir, **à confirmer ligne à ligne** au clone : projet public d'un laboratoire
universitaire (Stanford) présenté début 2026 comme cadre d'agents personnels « local-first », organisé en
primitives (moteur d'inférence, agents, outils et mémoire, apprentissage, évaluation/mesure d'énergie),
capable de parler à Ollama, vLLM, SGLang, llama.cpp et à des API compatibles OpenAI ; licence supposée
permissive (Apache-2.0 ?). **Rien de cela n'a été lu dans le code.** Le fork `gkerma` est inconnu.

Questions à trancher au clone (chaque réponse avec fichier et ligne) :

| # | Question | Pourquoi c'est bloquant |
|---|---|---|
| Q1 | Licence exacte de l'amont et du fork, licences des dépendances (`pyproject`, `Cargo.toml`) | compatibilité avec CMSD-1.0 et la livraison en `.deb` ; **accord du propriétaire** |
| Q2 | Différences fork ↔ amont (`git log upstream/main..`) | qui maintient quoi ; dette de rebase |
| Q3 | Langages ; part Rust ; Rust facultatif ou obligatoire ; roues arm64 disponibles | build arm64 sous Debian 13 sans réseau au postinst |
| Q4 | Dépendances Python : nombre, épinglage, torch/CUDA obligatoires ou non | taille sur une box 8 Go ; conflit avec `python3-fastapi` Debian |
| Q5 | Ce qui marche sans GPU (moteur llama.cpp/Ollama CPU) | profils EDGE et MESH |
| Q6 | Ce qui exige Docker (bacs à sable d'outils, services annexes) | **Docker interdit** : tout composant qui l'exige est écarté |
| Q7 | Télémétrie, appels sortants par défaut, téléchargements de modèles implicites | CSPN, souveraineté, `IPAddressDeny` |
| Q8 | Exécution d'outils : shell, code Python arbitraire, navigateur, fichiers | **aucun shell sur l'hôte** ; à désactiver ou confiner |
| Q9 | Modèle de permissions réel (liste blanche d'outils, approbation humaine), ou seulement des conventions de prompt | la sécurité doit être du code, pas une consigne |
| Q10 | MCP client/serveur, A2A : implémentés ou annoncés ; tests | ne rien simuler |
| Q11 | Stockage (mémoire, traces) : SQLite ? emplacements codés en dur (`~/.…`) ? | pas de base dupliquée ; `ProtectHome` |
| Q12 | Maturité : version, fréquence des versions, tests, CI, ruptures d'API | risque de régression |

## 4. Matrice existant ↔ OpenJarvis ↔ manque

Colonne OpenJarvis = **annoncé, non vérifié**.

| Brique demandée | Existe chez SecuBox | OpenJarvis (à vérifier) | Manque réel |
|---|---|---|---|
| Runtime d'agents, ReAct | non (prompts fixes de l'analyste, `veille/analyste.py`) | oui, annoncé | boucle d'agent bornée, **sans** outil d'action |
| Deep Research | partiel : `api/recherche.py` (584 l., recherche + lecture de pages, **garde SSRF R13** l.7-8 ; SearXNG au POC) | annoncé | orchestration multi-étapes |
| Morning Digest | partiel : résumé des menaces (`menaces.py:569`), rapports metrics | annoncé | digest planifié |
| Skills / tools | MCP `secubox-ai-gateway` ; outils du bus ZIA (`secubox-zia/api/tools.py`) | annoncé | registre unique, liste blanche |
| Scheduler | `secubox-ai-veille` (boucles), timer Nuclei, `taches.py` | annoncé | — (garder systemd) |
| Mémoire | `memoire.db` FTS5 (`memoire.py:62-67`) | annoncé | vecteurs optionnels |
| Routeur de moteurs | `moteurs.py` (local/distant, sonde, repli), gateway (classes) | annoncé | découverte par le maillage, latence, quotas |
| Passerelle de sécurité | ctl + demandes, exécuteur `ai-ban`, Pydantic strict, gk2 fait foi | à vérifier (Q8, Q9) | relecture des outils MCP ; garde de la gateway |
| AI Mesh | maillage WireGuard + annuaire (`secubox-annuaire`, specs maillage 2026-10-24) | non (hors périmètre supposé) | annonce de capacités IA, heartbeat |
| Évaluation | tests unitaires ; essai arm64 manuel du 25/11 | annoncé (mesures) | banc de requêtes reproductible |
| Learning | `veille/apprentissage.py` (668 l., filtres) | annoncé | — (à ne pas brancher sur l'action) |
| Tableau ZIA du Hall | `secubox-zia/www/zia/index.html` | non | vue des moteurs et agents |

## 5. Conflits

1. **Deux routeurs de moteurs** déjà (`secubox-ai/api/moteurs.py`, `secubox-ai-gateway`) ; un troisième
   (OpenJarvis) aggraverait la fragmentation. Il faut **un** routeur, l'existant étendu.
2. **Deux mémoires** déjà (`memoire.db` de secubox-ai, `localrecall` de la gateway) + celle d'OpenJarvis :
   interdiction de dupliquer → OpenJarvis doit lire/écrire par l'API mémoire, ou ne pas avoir de mémoire.
3. **Python Debian vs environnement isolé** : RULES-CODE § 11 interdit `| python3-pip` en dépendance ; un
   venv épinglé existe en précédent (`packages/secubox-billets/debian/postinst:25-31`) mais télécharge au
   postinst → pour OpenJarvis, **roues construites en CI et livrées dans le `.deb`**, jamais `pip` en ligne.
4. **Outils d'exécution** d'un runtime d'agents (shell, code) contre « aucun shell sur l'hôte », `ai-ban`
   unique chemin d'écriture et spec V2 § 12.
5. **Nommage d'API** : `/api/v1/ai/` est déjà le préfixe de `secubox-ai` (`nginx/ai.conf:20`) ; les routes
   V3 demandées (`/chat`, `/agents`, …) s'ajoutent sans conflit de chemin, à condition de garder
   `/essai/flux`, `/memoire*`, `/moteur*` (page et POC les appellent).

## 6. Risques

**arm64** : roues Rust/Python absentes pour aarch64 (Q3, Q4) ; torch impossible en 8 Go avec le reste de la
box ; Python 3.13 de trixie vs versions exigées ; temps de build sur MOCHAbin. Et surtout : l'inférence
arm64 est inutilisable (§ 1) — un runtime d'agents sur EDGE n'apporte rien s'il n'a pas de moteur distant.

**Régression** : la page `ai/index.html` et le POC gk0 appellent les routes actuelles ; la veille V2 est en
production sur gk3 avec un chemin d'écriture vers gk2 ; `memoire.db` et `veille.db` portent des données
réelles ; `secubox-ai` dépend de `secubox-zia-llm`. Toute V3 qui remplace au lieu d'ajouter casse un de ces
points. Le plus grave : un agent qui obtiendrait un accès, même indirect, à l'exécuteur `ai-ban`.

## 7. Phase 1 bis (à faire dès que le réseau revient)

1. `git clone --depth 50` amont et fork dans le scratchpad, **sans** installer ni exécuter (`python3 -I`
   pour toute lecture scriptée) ; 2. répondre Q1-Q12 avec fichiers et lignes ; 3. corriger § 3 et § 4 ;
4. relire `gh issue view 3981` et aligner. Aucune décision de phase 3 avant ce point.
