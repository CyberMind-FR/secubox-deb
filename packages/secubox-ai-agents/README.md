<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai-agents

OpenJarvis (amont `open-jarvis/OpenJarvis`, commit `556ddf32`, Apache-2.0) utilisé comme **bibliothèque**,
derrière l'API FastAPI de SecuBox, sur socket Unix (#3986). Plan : `docs/superpowers/plans/2026-11-26-secubox-ai-agents.md`.

État : **tranche A, sur gk0 seulement** (poste du propriétaire, POC). Pas encore de paquet Debian (tranche E).

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
