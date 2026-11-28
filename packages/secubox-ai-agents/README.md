<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai-agents

OpenJarvis (amont `open-jarvis/OpenJarvis`, commit `556ddf32`, Apache-2.0) utilisé comme **bibliothèque**,
derrière l'API FastAPI de SecuBox, sur socket Unix (#3986). Plan : `docs/superpowers/plans/2026-11-26-secubox-ai-agents.md`.

État : **tranches A, C, B et D, sur gk0 seulement** (poste du propriétaire, POC). Pas encore de paquet Debian (tranche E).

## API (socket `$XDG_RUNTIME_DIR/secubox-ai-agents/agents.sock` sur gk0)

Toutes les routes sauf `/health` exigent la garde : `require_jwt` (mode `secubox`, défaut) ou le jeton local
0600 (mode `jeton-local`, gk0). Le relais du POC les sert sous `/api/v1/ai/jarvis/` (local seulement) et la
page sous `/jarvis`.

| Route | Rôle |
|---|---|
| `GET /health` | vivant |
| `GET /status` | version, moteur, outils (aucun), politique (refus par défaut), mode de garde |
| `POST /chat` | `{message, conversation?, agent="assistant", memoire=true, max_tokens<=2048, temperature}` → flux SSE : `{conversation, sources}`, `{morceau}`…, `{fin, morceaux, caracteres, premier_s, duree_s}` |
| `GET /conversations`, `GET|DELETE /conversations/{id}` | historique (SessionStore d'OpenJarvis) |
| `POST /memoire/{agent}` `{titre, texte, source}`, `GET /memoire/{agent}?q=` | mémoire documentaire par agent (SQLiteMemory, FTS5/BM25 en Rust) |

Tranche C (#3990) :

| Route | Rôle |
|---|---|
| `POST /recherche` `{question}` | recherche approfondie (`NativeReActAgent` d'OpenJarvis, outils `web_search` + `memory_search`) en tâche de fond → `{travail}` ; 409 si un travail tourne déjà |
| `GET /travaux`, `GET /travaux/{id}`, `POST /travaux/{id}/annuler` | travaux visibles, résultat, sources `[n]`, `verifie` ; annulation coopérative |
| `GET|PUT /digest` `{actif, heure, themes}`, `POST /digest/maintenant` | digest du matin (`MorningDigestAgent`, notre `digest_collect`), lecture seule, historique (`DigestStore`) |
| `GET|POST /planificateur`, `POST /planificateur/{id}/pause|reprendre`, `DELETE /planificateur/{id}` | `TaskScheduler` + `SchedulerStore` d'OpenJarvis : 10 tâches actives au plus, 1 h au moins entre deux passages |

Recherche web : UNIQUEMENT par `sbin/secubox-ai-pont-searxng` (socket Unix → `127.0.0.1:8888`, destination codée en
dur) ; le service des agents reste en `RestrictAddressFamilies=AF_UNIX`. En unité utilisateur, `IPAddressDeny`
du pont N'EST PAS appliqué (essai du 2026-11-26) : sa seule garde est la destination fixe ; une unité système
(tranche E) l'appliquera.

Tranche B (#3992) :

| Route | Rôle |
|---|---|
| `POST /chat` (suite) | l'événement `fin` porte `trace` (Trace d'OpenJarvis) ; le premier événement dit combien de `corrections` ont été reprises |
| `POST /retour` `{trace, note: plus|moins, correction?}` | `TraceStore.update_feedback` (1,0 / 0,0) ; la correction d'un 👎 va en mémoire (agent `corrections`) et prévaut ensuite sur une question voisine |
| `GET /evaluation`, `POST /evaluation` `{moteur: actif|second, echantillons?}` | `EvalRunner` d'OpenJarvis sur le jeu `agents/jeux/jeu-secubox-fr.jsonl` (12 questions, notation par mots attendus) : exactitude, latence, premier mot, j/s, historique ; routage appris (`LearnedRouterPolicy`) en recommandation |

Second moteur d'évaluation : unité utilisateur `secubox-ai-eval-moteur` (CPU, une heure au plus, aucun lien avec
`poc-llama`), démarrée et arrêtée par le relais (`/api/v1/ai/jarvis-moteur2/*`) avec une garde de mémoire
(taille du modèle + 1,5 Go). Non fourni ici : `LLMOptimizer` (modèle infonuagique), dspy/gepa (absents), LoRA/SFT/GRPO
(entraînement de poids : accord du propriétaire).

Tranche D (#3995) :

| Route | Rôle |
|---|---|
| `GET /vision`, `POST /image` `{image (base64), action: decrire|lire|question, question?}` | l'image (PNG, JPEG, WebP reconnus par leurs octets, 6 Mo au plus) est gardée dans l'état du service (0600) et lue par le moteur actif et son projecteur ; flux SSE |
| `POST /creations` `{prompt, negatif?, modele: sd15|sdxl-turbo, taille: 512|1024, graine?}`, `GET /creations`, `GET /creations/{id}.png`, `DELETE /creations/{id}` | création d'images : filtre de contenu par défaut, file (20 au plus), journal sans le texte des demandes ; générée par le travailleur `secubox-ai-images` |

- Projecteur vision : téléchargé par le relais (`/api/v1/ai/jarvis-medias/projecteur`, `mmproj-…` d'un modèle installé, SHA-256 de Hugging Face vérifié par la fonction `telecharger` du relais).
- Création : `sbin/secubox-ai-images` (bibliothèque standard), unité `secubox-ai-images` (sans réseau, sans lien avec `poc-llama`), stable-diffusion.cpp `52491bd` (MIT) compilé en Vulkan dans `~/poc-secubox-ai/sdcpp` ; une image à la fois ; carte NVIDIA si sa mémoire libre suffit (sinon CPU) ; arrêt propre = demande remise en file. Modèles par `sbin/secubox-ai-images-modeles` (empreintes figées) : SD 1.5 (CreativeML OpenRAIL-M), SDXL Turbo (**Stability AI Non-Commercial Community : pas d'usage commercial**).

### Comparaison des modèles (gk0, 2026-11-26, 21 questions, `EvalRunner`)

| Modèle | Justes | Latence moy. | Premier mot | j/s | GPU | RAM du moteur |
|---|---|---|---|---|---|---|
| Gemma 3 4B Q4_K_M | 19/21 | 1,35 s | 0,43 s | 12,4 | 2,7 Go | 1,9 Go |
| Qwen3.5-9B non censuré Q5_K_M | 18/21 | 56,6 s | 43,0 s | 2,7 | 2,5 Go | 10,6 Go |
| DeepSeek-Coder-V2-Lite Q4_K_M | 12/21 (dont 4 erreurs « serveur déconnecté ») | 14,4 s | 5,7 s | 4,0 | 2,7 Go | 11,6 Go |

Moteur du POC en mode mixte (`--fit`) sur la RTX 3050 4 Go : ce qui ne tient pas sur la carte reste sur le CPU. Qwen3.5 raisonne
avant de répondre (premier mot visible tardif).

## Environnement

- `sbin/secubox-ai-agents-construire <paquet>` (root) : venv `/opt/secubox-ai-agents/venv-<date>`, lien `venv`
  basculé, `venv.avant` gardé pour revenir en arrière ; `requirements.txt` épinglé par empreinte ; OpenJarvis
  sans ses dépendances ; extension Rust compilée ; supprimés : `mining/`, `cli/mine_cmd.py`,
  `cli/pearl_cmd.py`, `sandbox/`, et les outils de `outils-retires.txt`.
- Unité gk0 : `systemd/secubox-ai-agents-gk0.service` (unité utilisateur, aucun réseau :
  `RestrictAddressFamilies=AF_UNIX`).
- Variables : `SECUBOX_AI_AGENTS_GARDE`, `SECUBOX_AI_AGENTS_JETON`, `SECUBOX_AI_AGENTS_MOTEUR` (socket de
  llama-server), `SECUBOX_AI_AGENTS_ETAT` ; `OPENJARVIS_HOME`, `OPENJARVIS_NO_UPDATE_CHECK=1`.

## Tests

Sur le vrai moteur et la vraie extension Rust, avec l'interpréteur du venv livré :

    PYTHONPATH=<dossier où pytest est installé> /opt/secubox-ai-agents/venv/bin/python -m pytest packages/secubox-ai-agents/tests

## Atelier des émissions (#4058, gk0)

Service utilisateur `secubox-ai-emissions` (`emissions/app.py`, FastAPI sur `%t/secubox-ai-emissions/emissions.sock`),
relayé par le relais du POC (`relais/emissions_relais.py`) sous `/api/v1/ai/emissions/*`, Host local seulement, jeton
local posé par le relais. Panneau : onglet « Émissions » du relais (`/emissions`).

- Chaîne en sept étapes (`emissions/production.py`) : faits (gk2, lecture seule) → évolutions → consigne → dialogue
  (Gemma) → vérification (✓/⚠/✗) → voix (Voice Studio LOCAL `http://127.0.0.1:3910`) → montage (MP3 + chronologie).
  Brouillon : `~/.local/state/secubox-ai-emissions/brouillons/<id>/etat.json` ; reprise à la première étape non faite.
  Une production à la fois, la synthèse d'abord.
- Routes (après `/api/v1/ai/emissions`) : `GET sources|evolutions|brouillons|reglages|etat`, `POST produire`
  `{"sources": ["campagne/<id>"|"acteur/<id>"], "format": "synthese"|"sujet"}`, `POST reglages`, `GET {id}`,
  `POST {id}/entete`, `POST {id}/replique/{rang}` (texte → revérifiée, seule sa voix refaite),
  `POST {id}/replique/{rang}/reecrire` (proposition vérifiée, jamais appliquée d'office), `POST {id}/capture`,
  `POST {id}/capture/{cid}/valider`, `POST {id}/mp4`, `POST {id}/publier`, `POST {id}/reprendre`, `DELETE {id}`,
  `GET {id}/fichier/<emission.mp3|emission.mp4|diapos/…png|captures/…png>`.
- Réglages : `~/.config/secubox-ai-emissions/reglages.toml` (adresses : `voix_url`, `gk2_base`, `gk2_aud`, `billets_base`) puis
  `<état>/reglages.json` écrit par le panneau (`voix_gpu`, `voix1`, `voix2`, `seuil`, `ecart`, `mp4_jours`).
  `voix_gpu = false` par défaut (CUDA en panne) : Gemma n'est pas suspendu ; `true` : verrou GPU + relais en 503.
- Lecture de gk2 (#4063) : `GET {gk2_base}/rapports` et `/rapports/{genre}/{id}`, gardées sur gk2 par
  `require_lecture_ou_compte("ai-lecture")`. Chaque GET porte un jeton EdDSA NEUF du compte de service `ai-lecture`
  (`secubox_core.compte_service.frapper_jeton` : portée `waf-lecture`, `aud` = `gk2_aud` du TOML, défaut `gk2`,
  `methode` GET, `chemin` = `/rapports…` tel que le voit le WAF, `jti` unique, 30 s). Clé privée de gk0 :
  `~/.config/secubox-ai-jeton/ai-lecture.key` (0600, au compte courant, refusée sinon). Plus de jeton fixe.
- Clé : `sbin/secubox-ai-emissions-cle` (installé dans `~/.local/lib/secubox-ai-emissions/`, sans root) crée la paire
  si elle manque, jamais écrasée, puis affiche la clé publique, son `kid` et la commande à lancer EN ROOT sur gk2 :
  `wafctl cle-ai-lecture ajouter <fichier.pub>` (→ `/etc/secubox-comptes-service/ai-lecture/<kid>.pub`, root 0644 ;
  deux clés au plus, celle de gk3 comprise).
- Installation sans root : `sbin/installer-emissions.sh <paquet> [python]` (idempotent, ne redémarre rien ; copie
  aussi `common/secubox_core/` à côté de `emissions/`).
