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

- OpenJarvis a été cloné **en lecture seule** (rien installé, rien exécuté) dans le scratchpad de la session :
  amont `open-jarvis/OpenJarvis` au commit `556ddf32` (2026-11-26), fork `gkerma/OpenJarvis` au `86f75ef7`.
  Le réseau était coupé au début de la session ; il est revenu avant la rédaction de § 3.
- Lecture **ciblée** (≈ 181 000 lignes Python, 691 fichiers ; 27 700 lignes Rust) : `pyproject.toml`,
  `rust/Cargo.toml`, `_rust_bridge.py`, `core/config.py`, `core/paths.py`, `security/`, `tools/`,
  `sandbox/`, `server/auth_middleware.py`, `agents/`, workflows CI. Le reste n'est pas relu : les
  affirmations hors de ces fichiers sont marquées « non vérifié ». Aucun test d'OpenJarvis n'a été lancé.
- L'issue #3981 a été relue tardivement (`gh` revenu) ; le worktree a été créé à la main
  (`git worktree add`, convention de `scripts/agent-worktree.sh`, qui exigeait `gh` hors ligne).
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

## 3. OpenJarvis — audit du code (lecture seule)

Chemins relatifs à la racine du dépôt amont (`556ddf32`).

| # | Question | Constat | Preuve |
|---|---|---|---|
| Q1 | Licence | **Apache-2.0** (compatible avec une livraison séparée ; NOTICE et licence à conserver dans le `.deb`). Licences des ~25 dépendances directes non relues une à une | `LICENSE:1-3`, `pyproject.toml` `license` |
| Q2 | Fork ↔ amont | le fork `gkerma` n'a **aucun** commit propre ; il est **en retard de 14** commits. C'est un miroir | `git log up/main..HEAD` vide, `HEAD..up/main` = 14 |
| Q3 | Langages, Rust | Python ≥ 3.11 **< 3.14** (trixie : 3.13, compatible), Rust (17 crates, PyO3), TypeScript (frontend, desktop Tauri). Rust **exige 1.89** (`rust/Cargo.toml` `rust-version`). Le paquet PyPI est construit par `uv build` (hatchling) **sans** l'extension Rust (`.github/workflows/pypi-publish.yml:109`) ; l'extension se compile à part par `maturin develop` (`Makefile:9`). Rust n'est **pas facultatif** pour la mémoire : `tools/storage/bm25.py:13` appelle `get_rust_module()` à l'import, `tools/storage/sqlite.py:49-54` lève une erreur sans Rust ; sécurité (`security/ssrf.py:102-105`, `injection_scanner.py:137-144`, `capabilities.py:89-93`) a un repli Python | fichiers cités |
| Q4 | Dépendances | dépendances **de base** lourdes et hors sujet pour une box : `datasets` (Hugging Face, tire pandas/numpy/pyarrow), `nvidia-ml-py`, `posthog`, `python-telegram-bot`, `ddgs`, `aiohttp`, `openai` ; ~60 extras (vLLM, torch, faiss, canaux de messagerie, minage). Aucun torch en base | `pyproject.toml` `dependencies` |
| Q5 | Sans GPU | moteurs par HTTP OpenAI-compatible : `llamacpp` (`localhost:8080`), `vllm`, `sglang`, `lmstudio` (`engine/openai_compat_engines.py:9-13`), `ollama.py`, `cloud.py`, `litellm.py`. Le runtime lui-même n'exige pas de GPU ; il délègue l'inférence | `engine/` |
| Q6 | Docker | **le bac à sable d'agents est Docker/Podman** (`sandbox/runner.py:1-5,43,56,105-111`) ; outils `docker_shell_exec.py`, `code_interpreter_docker.py` ; extra `sandbox-docker`, minage `mining/_docker.py`. Alternative interne : `sandbox/wasm_runner.py` (wasmtime) et `security/subprocess_sandbox.py` (environnement filtré, pas d'isolation noyau). → **à écarter entièrement** chez nous | fichiers cités |
| Q7 | Télémétrie | analytique PostHog **désactivée par défaut** (`enabled=False`) mais hôte et clé **codés en dur** (`core/config.py:1211-1231`), et `posthog` est une dépendance de base ; contrôle de version vers `pypi.org` (`cli/_version_check.py:18`) ; traces locales SQLite activées par défaut (`core/config.py:1234-1238`). → à neutraliser par configuration **et** par `IPAddressDeny` | fichiers cités |
| Q8 | Outils d'exécution | `tools/shell_exec.py:94-97` : `subprocess.Popen(command, shell=True)` (« confirmed shell commands ») ; `code_interpreter.py:128-217` (Python après validation AST, sous-processus) ; `file_write.py`, `apply_patch.py`, `git_tool.py`, `browser.py` (playwright), `http_request.py`, `db_query.py`. → **aucun de ces outils ne doit être chargé** | fichiers cités |
| Q9 | Permissions | un vrai mécanisme en code : RBAC de capacités (`security/capabilities.py:1`, motifs `*`), `approval_store.py`, `server/approval_routes.py`, `security/guardrails.py`, `taint.py`, `audit.py`, `signing.py`. Leur solidité **n'a pas été éprouvée** ici | fichiers cités |
| Q10 | MCP, A2A | implémentés : `mcp/{client,server,transport,protocol,loader}.py`, `a2a/{client,server,protocol,tool}.py`, crates `openjarvis-mcp`, `openjarvis-a2a`. Conformité au protocole non testée | `src/openjarvis/mcp`, `a2a` |
| Q11 | Stockage | racine unique `$OPENJARVIS_HOME` > `$XDG_DATA_HOME/openjarvis` > `~/.openjarvis` (`core/paths.py:82-90`) : **déplaçable** sous `/var/lib/…`, compatible `ProtectHome` ; bases propres (traces, mémoire SQLite par Rust) — **seconde mémoire** si on les garde | fichiers cités |
| Q12 | Maturité | « Development Status :: 3 - Alpha » (`pyproject.toml`), versions `v1.0.5.devNNNN` (une étiquette par commit, 1 396 commits depuis le 2026-03-12), 732 fichiers de tests, CI de sécurité (`security-sast.yml`). Rythme très rapide → API instable | `git tag`, `.github/workflows/` |

Autres constats :

- **Serveur** : `127.0.0.1:8000` par défaut (`core/config.py:1165-1166`) ; authentification par clé
  `Bearer` **seulement si une clé est définie** (`server/auth_middleware.py:39,49`) : sans
  `OPENJARVIS_API_KEY`, l'API n'est pas protégée. Chez nous : socket Unix ou clé obligatoire, jamais exposé.
- Agents présents : `NativeReActAgent`, `DeepResearchAgent`, `MorningDigestAgent`, `OrchestratorAgent`,
  `ProactiveAgent`, `MonitorOperativeAgent`, `RLMAgent`, et des enveloppes d'agents tiers
  (`ClaudeCodeAgent`, `OpenHandsAgent`, `OpenCodeAgent`) (`agents/*.py`). ReAct, Deep Research et Morning
  Digest **existent réellement** ; leur qualité avec un modèle ≤ 9B n'a pas été mesurée.
- **Sous-système de minage de crypto-monnaie** « Pearl » (`src/openjarvis/mining/`, extras
  `mining-pearl-*`, `mining/_docker.py`) dans le même paquet. Il ne s'active pas tout seul (extras), mais il
  est livré dans les sources : **à exclure du venv et à signaler au propriétaire**.
- Chemins sans Rust à vérifier : sans l'extension, la mémoire BM25/SQLite ne fonctionne pas ; avec
  l'extension, il faut une chaîne Rust ≥ 1.89, plus récente que le `rustc` de Debian 13 (1.85 d'après la
  connaissance de l'auteur, **non vérifié sur le poste**) → `rustup` en CI ou rétroportage.

## 4. Matrice existant ↔ OpenJarvis ↔ manque

Colonne OpenJarvis = présent dans le code (§ 3) ; qualité non mesurée.

| Brique demandée | Existe chez SecuBox | OpenJarvis (à vérifier) | Manque réel |
|---|---|---|---|
| Runtime d'agents, ReAct | non (prompts fixes de l'analyste, `veille/analyste.py`) | `agents/native_react.py:132` | boucle d'agent bornée, **sans** outil d'action |
| Deep Research | partiel : `api/recherche.py` (584 l., recherche + lecture de pages, **garde SSRF R13** l.7-8 ; SearXNG au POC) | `agents/deep_research.py:159` (outils utilisés non relus) | orchestration multi-étapes |
| Morning Digest | partiel : résumé des menaces (`menaces.py:569`), rapports metrics | `agents/morning_digest.py:42` | digest planifié |
| Skills / tools | MCP `secubox-ai-gateway` ; outils du bus ZIA (`secubox-zia/api/tools.py`) | `skills/`, `tools/` (dont shell, code, fichiers : **à exclure**) | registre unique, liste blanche |
| Scheduler | `secubox-ai-veille` (boucles), timer Nuclei, `taches.py` | `scheduler/` (croniter) | — (garder systemd) |
| Mémoire | `memoire.db` FTS5 (`memoire.py:62-67`) | `tools/storage/` (BM25/SQLite **Rust obligatoire**), faiss/colbert en extras | vecteurs optionnels |
| Routeur de moteurs | `moteurs.py` (local/distant, sonde, repli), gateway (classes) | `engine/multi.py`, `_discovery.py`, `cloud_router.py` | découverte par le maillage, latence, quotas |
| Passerelle de sécurité | ctl + demandes, exécuteur `ai-ban`, Pydantic strict, gk2 fait foi | RBAC, approbations, garde SSRF, scanner d'injection (Q9) — mais outils shell et Docker livrés | relecture des outils MCP ; garde de la gateway |
| AI Mesh | maillage WireGuard + annuaire (`secubox-annuaire`, specs maillage 2026-10-24) | A2A (`a2a/`) entre instances ; pas de découverte maillée | annonce de capacités IA, heartbeat |
| Évaluation | tests unitaires ; essai arm64 manuel du 25/11 | `evals/`, `bench/`, `telemetry/` (énergie, FLOPs) | banc de requêtes reproductible |
| Learning | `veille/apprentissage.py` (668 l., filtres) | `learning/` (dspy, gepa en extras) | — (à ne pas brancher sur l'action) |
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
5. **Bac à sable Docker** : l'isolation d'agents d'OpenJarvis est Docker/Podman (§ 3, Q6), interdits ;
   l'isolation doit venir de nous (unité systemd + AppArmor, ou LXC), avec les outils d'exécution non chargés.
6. **Base de traces et mémoire Rust** d'OpenJarvis : troisième lieu de données conversationnelles ; à
   désactiver (traces) ou rediriger vers l'API mémoire.
7. **Nommage d'API** : `/api/v1/ai/` est déjà le préfixe de `secubox-ai` (`nginx/ai.conf:20`) ; les routes
   V3 demandées (`/chat`, `/agents`, …) s'ajoutent sans conflit de chemin, à condition de garder
   `/essai/flux`, `/memoire*`, `/moteur*` (page et POC les appellent).

## 6. Risques

**arm64** : aucune CI Linux arm64 en amont (seul `desktop.yml` teste Windows ARM64) ; extension Rust à
compiler soi-même (Rust ≥ 1.89) ; `datasets`/pyarrow lourds en 8 Go ; Python 3.13 de trixie dans la plage
admise (< 3.14). Et surtout : l'inférence
arm64 est inutilisable (§ 1) — un runtime d'agents sur EDGE n'apporte rien s'il n'a pas de moteur distant.

**Régression** : la page `ai/index.html` et le POC gk0 appellent les routes actuelles ; la veille V2 est en
production sur gk3 avec un chemin d'écriture vers gk2 ; `memoire.db` et `veille.db` portent des données
réelles ; `secubox-ai` dépend de `secubox-zia-llm`. Toute V3 qui remplace au lieu d'ajouter casse un de ces
points. Le plus grave : un agent qui obtiendrait un accès, même indirect, à l'exécuteur `ai-ban`.

## 7. Suites de l'audit

1. Lancer la suite de tests d'OpenJarvis dans un venv jetable **sur gk0** (pas sur une box), avec et sans
   l'extension Rust, pour mesurer ce qui marche réellement sans Rust ni GPU ;
2. relire `security/capabilities.py`, `approval_store.py`, `guardrails.py` en entier avant de s'y fier ;
3. dresser la licence de chaque dépendance du venv retenu ;
4. décision du propriétaire sur le sous-système de minage (exclusion) et sur la dépendance à un projet Alpha.

Points 1 à 4 traités en § 8.

## 8. Qualification gk0 (2026-11-26)

Décisions du propriétaire reçues avant cette étape : dépendance à un projet Alpha **acceptée** ; sous-système
de minage « Pearl » **exclu** (jamais installé ni importé).

### 8.1 Conditions

- Poste gk0, Python 3.12.3, **aucun** sudo, apt ni Docker ; services du POC non touchés.
- Environnement jetable : `uv venv` dans le scratchpad (`…/scratchpad/oj/venv`), OpenJarvis amont `556ddf32`
  installé en mode éditable avec les extras `dev,server` seulement (ni vLLM, torch, faiss, canaux,
  navigateur, minage). Venv : 503 Mo.
- Extension Rust : `rustc 1.95.0` (paquet système, sans rustup ; `rust-toolchain.toml` demande 1.89, ignoré
  faute de rustup), `maturin develop --release` réussi en 2 min 14 s ; `RUST_AVAILABLE = True`.
- Réseau : ouvert **seulement** pour `uv pip install` et `cargo` (téléchargements). Imports et tests lancés
  sous `unshare -rn` (espace réseau vide, **boucle locale comprise**).
- Télémétrie coupée : `OPENJARVIS_HOME` et `HOME` dans le scratchpad, `OPENJARVIS_NO_UPDATE_CHECK=1`
  (`cli/_version_check.py:53-65`), `OPENJARVIS_ANALYTICS_HOST=http://127.0.0.1:9` (en plus de
  `analytics.enabled=False` par défaut), `CUDA_VISIBLE_DEVICES=` (pas de GPU). `posthog` n'est pas importé
  par les paquets de base.

### 8.2 Suite de tests (sans GPU, hors réseau, 8 processus, 23 min 34 s)

**10 006 réussis, 32 échecs, 0 erreur, 118 sautés.**

| Module | Réussis | Échecs | Cause des échecs |
|---|---|---|---|
| tools | 1 054 | 1 | message de `git` en français (locale du poste), pas un défaut |
| channels | 806 | 1 | `npm install` (whatsapp_baileys) : pas de réseau |
| agents | 797 | 4 | 2 × opencode : réseau ; 2 × `test_rust_agent_ctors` (hôte d'engin personnalisé ollama/vllm) : **à analyser** (boucle locale coupée probable) |
| engine | 663 | 4 | gemma.cpp « live » : pas de poids de modèle |
| evals | 628 | 10 | jeux de données Hugging Face à télécharger |
| server | 510 | 2 | Granola injoignable ; démon : connexion locale refusée (boucle coupée par `unshare`) |
| connectors | 464 | 5 | 4 « live » (Oura, Strava, Spotify, Google Tasks) ; 1 × IMAP `logout` non appelé : **à analyser** |
| skills | 309 | 4 | tests « live » : aucun moteur lancé |
| deployment | 62 | 1 | `uv build` d'un sdist : réseau |
| autres modules | tous | 0 | — |

Aucun échec ne touche `security/`, `memory/`, `scheduler/`, `mcp/`, `a2a/`. Trois échecs restent à expliquer
(2 agents Rust, 1 IMAP) : à relancer avec la boucle locale active avant de conclure.

### 8.3 Relecture complète des trois fichiers de sécurité

- `security/capabilities.py` (370 l.) : **ouvert par défaut** — sans politique pour un agent, tout est
  permis (`default_deny=False`, l.71-73, 146, 163). L'inventaire des outils internes est bien conçu : un
  outil interne non inventorié exige `system:admin` (l.352-353), un outil MCP exige `tool:invoke` quel que
  soit son nom (l.327-331), une usurpation de `calculator`/`think` est refusée (l.335-350). Avec Rust, la
  vérification passe par l'implémentation native (l.137-138) : équivalence avec le repli Python non
  vérifiée. **Chez nous : `default_deny=True` obligatoire et politique fichier explicite.**
- `tools/approval_store.py` (406 l.) : simple SQLite (`approvals.db` sous `OPENJARVIS_HOME`, l.150-158),
  sans identité de l'approbateur, sans signature ni journal d'audit ; `update_status` accepte n'importe quel
  passage d'état (l.265-284) ; `INSERT OR REPLACE` (l.212) ; palier `trivial` = exécution sans demander
  (l.39) et mémoire « toujours approuver » (l.28, 307-349). **Ne remplace pas** notre circuit de
  propositions (plafonds, revalidation, audit, gk2 fait foi) : à ne pas utiliser pour des actions.
- `security/guardrails.py` (330 l.) : enveloppe d'engin qui cherche **secrets et données personnelles**
  (`SecretScanner`, `PIIScanner`, l.56-59), **pas** l'injection de prompt ; mode par défaut `WARN` = texte
  transmis tel quel (l.47, 126-136) ; en flux, la sortie n'est contrôlée **qu'après** envoi au client
  (l.248-269, 294-315). Utile pour la souveraineté des données, sans valeur de barrière.

### 8.4 Licences des dépendances

- Python (87 distributions du venv, métadonnées `importlib.metadata`) : MIT, BSD, Apache-2.0, PSF pour
  l'essentiel. À signaler : **`python-telegram-bot` 22.8 en LGPL-3.0-only** (dépendance de **base**,
  inutile pour nous : à retirer du venv livré, ou accepter la LGPL en bibliothèque), `certifi` et `tqdm` en
  MPL-2.0 (copyleft par fichier, acceptables sans modification), `openjarvis-rust` sans métadonnée de
  licence (Apache-2.0 du dépôt). Aucune GPL, AGPL, SSPL ni BUSL.
- Rust (312 crates du registre téléchargé) : MIT / Apache-2.0 / Unicode-3.0 / BSD / ISC / Zlib /
  CDLA-Permissive-2.0 ; `r-efi` propose LGPL-2.1 **en option** parmi MIT/Apache. Aucune incompatible.

### 8.5 « Pearl » à l'import

- `import openjarvis` et `openjarvis.{agents,tools,engine,memory,security}` : **aucun** module `mining`.
- `import openjarvis.server.app` ou `openjarvis.cli` : **13 modules de minage chargés**
  (`openjarvis.mining.{cpu_pearl,vllm_pearl,_docker,_install,_pearl_subprocess,…}`, `cli.pearl_cmd`).
  Liens : `core/config.py:42,2051` (`MiningConfig`), `engine/_discovery.py:84-85` (import dans une fonction),
  `cli/mine_cmd.py:20-42`. Le code de minage n'est pas lancé, mais il est importé.
- Exclusion : ne **jamais** utiliser le serveur ni la CLI d'OpenJarvis (ADR-4) ; dans le venv livré,
  supprimer `openjarvis/mining/`, `cli/pearl_cmd.py`, `cli/mine_cmd.py`, et vérifier par un test que
  `openjarvis.agents`, `.tools`, `.engine`, `.memory`, `.security` s'importent sans eux et qu'aucun module
  `mining` n'apparaît dans `sys.modules`.

### 8.6 Espace disque

Venv 503 Mo, registre cargo 641 Mo, compilation Rust 660 Mo : 1,8 Go au total dans le scratchpad, sous le
seuil de 5 Go, conservés. Espace libre du poste : 32 Go.
