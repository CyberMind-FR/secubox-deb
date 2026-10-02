<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🌿 Multi-Agent Worktree Workflow — Obligatoire

Chaque travail non-trivial doit s'exécuter dans un worktree dédié, créé via
`scripts/agent-worktree.sh start --issue <#>`. Le checkout principal
(`~/CyberMindStudio/secubox-deb/secubox-deb/`) est réservé au `master`
housekeeping et au travail humain — pas aux agents.

### Quand créer un worktree

- Toute issue GitHub avec label `bug`, `enhancement`, `documentation`,
  `eye-remote`, ou tout label métier (migration, hardware, api, frontend,
  security, infra)
- Toute tâche estimée > 30 min ou touchant ≥ 3 fichiers
- Toute feature/fix qui finira en PR

### Quand NE PAS en créer

- Édition triviale d'un seul fichier de suivi (`HISTORY.md`, `WIP.md`,
  `TODO.md`)
- Exploration read-only, réponse à une question
- Commits administratifs sur master (tags, bumps de version)

### Cycle obligatoire

```text
gh issue create
  → scripts/agent-worktree.sh start --issue <#>
  → cd ~/CyberMindStudio/secubox-deb-worktrees/<#>-<slug>
  → code + commits (chaque message: "(ref #<#>)")
  → scripts/agent-worktree.sh finish     # push + PR avec "Closes #<#>"
  → [user valide et merge la PR]
  → scripts/agent-worktree.sh clean <#>  # supprime worktree + branche
```

### Parallélisme

`start` refuse de créer un second worktree pour la même issue. Deux sessions
Claude (deux terminaux) peuvent travailler simultanément sur deux issues
distinctes sans collision.

### Source de vérité opérationnelle

`scripts/agent-worktree.sh --help`

---

