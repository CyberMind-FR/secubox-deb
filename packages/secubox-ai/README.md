<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ai

Module IA de SecuBox (#3583), porté du POC gk0. API FastAPI sur le socket `/run/secubox/ai.sock`,
publiée sous `/api/v1/ai` (nginx retire le préfixe, comme secubox-ai-gateway).

| Route | Garde | Rôle |
|---|---|---|
| `GET /health` | aucune | vivacité `{"status": "ok", "module": "ai"}` |
| `GET /status` | `require_jwt` | `{"module", "version", "moteur"}` |

Toute route ajoutée doit porter `require_jwt` (test `test_toute_route_est_gardee`).

Tests : `python -m pytest packages/secubox-ai/tests -q` depuis la racine du dépôt, ce paquet seul.
