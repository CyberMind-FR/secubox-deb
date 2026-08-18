<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Multi-Agent Worktree Workflow

**Un agent · une issue · une branche · un worktree.**

Le helper `scripts/agent-worktree.sh` (livré dans SecuBox-Deb depuis [PR #85](https://github.com/CyberMind-FR/secubox-deb/pull/85)) lie chaque tâche non-triviale à une issue GitHub, une branche dédiée, et un git worktree isolé sous `~/CyberMindStudio/secubox-deb-worktrees/`. Cela permet à plusieurs agents (Claude Code, GPT, Gemini, Copilot, ou un humain) de travailler simultanément sur le même dépôt sans collision d'état git.

---

## 🟢 ROOT — Vue d'ensemble

### Pourquoi

Sans isolation, deux sessions d'agent qui partagent le même checkout doivent jongler avec `git stash` / `git checkout` à chaque changement de contexte. Les worktrees git résolvent ce problème : un seul `.git/` partagé, plusieurs dossiers de travail indépendants chacun sur sa propre branche.

Ce workflow ajoute par-dessus :

- **traçabilité** : chaque branche est nommée d'après une issue GitHub (`feature/<#>-<slug>`)
- **discipline de cycle** : `start → code → finish → clean`, refusée à chaque étape si l'état est mauvais
- **dogfooding multi-agent** : la doctrine est codifiée dans `CLAUDE.md`, le script fonctionne pareil pour tout agent qui sait exécuter du shell

### Layout sur disque

```text
~/CyberMindStudio/
├── secubox-deb/secubox-deb/              ← checkout principal (master / travail humain)
└── secubox-deb-worktrees/                ← racine des worktrees agents
    ├── 80-apt-tier-manifest-helper/      ← worktree pour issue #80
    ├── 83-multi-agent-worktree-workflow/
    └── 92-eye-remote-led-fix/
```

### Branche → préfixe (dérivé du label issue)

| Label GitHub | Préfixe |
|---|---|
| `bug`, `fix` | `fix/` |
| `documentation` | `docs/` |
| `infra`, `chore` | `chore/` |
| tout autre / défaut | `feature/` |

Le slug est dérivé du titre de l'issue : minuscules, ASCII-folded (`iconv //TRANSLIT`), tirets, 40 caractères max.

---

## 🔴 BOOT — Quick start

```bash
# 1. Créer une issue GitHub (label déterminera le préfixe de branche)
gh issue create --title "Fix HyperPixel init on cold boot" --label "bug"
# → returns #92

# 2. Démarrer le worktree
bash scripts/agent-worktree.sh start --issue 92
# → branch:   fix/92-fix-hyperpixel-init-on-cold-boot
# → worktree: ~/CyberMindStudio/secubox-deb-worktrees/92-fix-hyperpixel-init-on-cold-boot
# → next:     cd <path>

# 3. Travailler dans le worktree
cd ~/CyberMindStudio/secubox-deb-worktrees/92-fix-hyperpixel-init-on-cold-boot
# ... edit, test, commit (avec "(ref #92)" dans chaque message)

# 4. Pousser et ouvrir la PR
bash scripts/agent-worktree.sh finish
# → git push -u origin <branch>
# → gh pr create avec titre = titre de l'issue, body = "Closes #92"

# 5. Après que la PR est mergée par un humain
bash scripts/agent-worktree.sh clean 92
# → git worktree remove + git branch -d
```

---

## 🔵 MESH — Référence des sous-commandes

### `start --issue <N>`

Crée la branche et le worktree associés à l'issue `<N>`.

| Précondition | Sortie si violée |
|---|---|
| `gh auth status` OK | 2 |
| Working tree propre dans le checkout courant | 3 |
| Pas déjà dans un worktree sous `WORKTREE_ROOT` | 3 |
| Issue existe sur GitHub | 2 |
| Branche n'existe pas déjà localement | 3 |
| Path de worktree libre | 3 |

Options : `--dry-run` (affiche sans agir), `--verbose`.

Effet de bord : commentaire automatique sur l'issue (`Worktree created at <path>, branch <branch>`).

### `list`

Affiche tous les worktrees enregistrés, décorés ainsi :

```text
[primary] master  /home/.../secubox-deb  ahead:0 behind:20 clean
fix/92-fix-hyperpixel-init   /home/.../92-fix-hyperpixel-init   ahead:3 behind:0 dirty
```

Tag `[primary]` pour le checkout principal (hors `WORKTREE_ROOT`). `ahead/behind` calculé contre `origin/master`. État `clean`/`dirty` selon `git diff HEAD`.

### `sync [<N>]`

Rebase le worktree courant (ou celui de l'issue `<N>`) sur `origin/master`.

```bash
sync         # depuis le worktree courant
sync 92      # résolution par numéro d'issue depuis n'importe où
```

Conflit de rebase → `git rebase --abort`, code de sortie 3, résolution manuelle laissée à l'humain.

### `finish`

À exécuter **depuis l'intérieur d'un worktree**. Pousse la branche et ouvre la PR.

| Précondition | Sortie |
|---|---|
| Working tree propre | 3 |
| Branche d'agent valide (`feature/`, `fix/`, `docs/`, `chore/`) | 1 |
| Au moins 1 commit ahead de `origin/master` | 3 |

Le titre de la PR est récupéré via `gh issue view <N> --json title`. Le body contient `Closes #<N>`. Le worktree **n'est pas supprimé** — laissé en place pour d'éventuelles corrections de review.

### `clean <N>`

Après que la PR a été mergée, supprime worktree et branche locale.

| Précondition | Sortie |
|---|---|
| Worktree existe pour l'issue | 2 |
| Working tree du worktree propre | 3 |
| PR mergée (sauf `--force`) | 3 |

### Codes de sortie

| Code | Sens |
|---|---|
| 0 | Succès |
| 1 | Erreur générique / usage |
| 2 | Précondition (issue manquante, gh non auth) |
| 3 | Mauvais état (dirty, conflit, PR non mergée) |
| 4 | Réseau (gh API, git push) |

---

## 🟣 MIND — Prompt pour agents GPT / Gemini / Copilot

Le bloc ci-dessous est conçu pour être collé tel quel comme **system prompt** (ou première instruction utilisateur) à un agent non-Claude (GPT-5, Gemini, Copilot, agents OpenAI Codex…) afin qu'il suive correctement la doctrine multi-agent de SecuBox-Deb.

> ℹ️ Pour Claude Code : la doctrine est déjà chargée via `CLAUDE.md`, aucun prompt à coller. Pour Anthropic API en standalone, utiliser ce prompt aussi.

---

````text
You are an autonomous coding agent working on the SecuBox-Deb repository
(https://github.com/CyberMind-FR/secubox-deb). It is a Debian-based
cybersecurity appliance, ARM64-first, targeting ANSSI CSPN certification.

This repository enforces a strict multi-agent workflow. You MUST follow it
for any non-trivial task — that means: any feature, any bug fix, any
documentation work that will become a pull request, any task touching
3 or more files, or any task expected to take more than 30 minutes.

You may SKIP this workflow only for:
  - Single-file edits to .claude/HISTORY.md, .claude/WIP.md, .claude/TODO.md
  - Read-only exploration or answering questions
  - Administrative master commits (tags, version bumps)

============================================================
THE MANDATORY CYCLE
============================================================

For every qualifying task:

1. ENSURE A GITHUB ISSUE EXISTS
   - If one already exists for the work, note the issue number <N>.
   - If not, create one BEFORE writing any code:
       gh issue create --title "<concise task title>" \
                       --body "<context, tasks, files>" \
                       --label "<bug|enhancement|documentation>"
     The label determines the branch prefix:
       bug / fix         -> fix/
       documentation     -> docs/
       infra / chore     -> chore/
       anything else     -> feature/

2. CREATE THE WORKTREE
   From the primary checkout (~/CyberMindStudio/secubox-deb/secubox-deb):
       bash scripts/agent-worktree.sh start --issue <N>
   This creates a branch named "<prefix>/<N>-<slug>" and a worktree at
   ~/CyberMindStudio/secubox-deb-worktrees/<N>-<slug>/.
   The script will refuse if:
     - the working tree is dirty (exit 3)
     - gh is not authenticated (exit 2)
     - the issue does not exist (exit 2)
     - the same issue already has a worktree (exit 3)
   In any of these cases, DO NOT retry blindly. Read the error and fix
   the underlying state (commit, stash, authenticate, or pick a different
   issue number).

3. WORK IN THE WORKTREE
       cd ~/CyberMindStudio/secubox-deb-worktrees/<N>-<slug>
   All edits, builds, tests, and commits happen here. Every commit MUST
   include "(ref #<N>)" in its message and end with the project
   Co-Authored-By line found in CLAUDE.md.

4. SYNC IF MASTER MOVES (optional)
   If origin/master advances while you are working:
       bash scripts/agent-worktree.sh sync
   On rebase conflict the script aborts cleanly (exit 3) — resolve the
   conflict manually before re-running.

5. FINISH — OPEN THE PR
       bash scripts/agent-worktree.sh finish
   This pushes the branch, fetches the issue title from GitHub, and opens
   a PR with body "Closes #<N>". The worktree is intentionally NOT
   deleted at this stage — leave it in place for review feedback fixes.

6. WAIT FOR HUMAN VALIDATION
   You do not merge your own PR. A human reviews and merges.

7. CLEAN UP AFTER MERGE
       bash scripts/agent-worktree.sh clean <N>
   This removes the worktree and deletes the local branch. The script
   refuses if the PR is not merged (exit 3, use --force only if you know
   what you are doing).

============================================================
PARALLELISM
============================================================

Two agents (or two sessions of the same agent) may run in parallel on
two different issues — each has its own worktree, its own branch, its
own working tree. The script will refuse to create a second worktree
for an issue that already has one, so collisions are impossible by
construction.

============================================================
EXIT CODE CONTRACT
============================================================

The script communicates errors through exit codes — use them to decide
how to recover:

  0  success
  1  generic / usage error (your CLI invocation was wrong)
  2  precondition failed (auth, issue lookup) — fix and retry
  3  bad state (dirty, conflict, non-merged PR) — fix the state
  4  network or remote error (gh API down, push refused) — retry later

============================================================
COMMANDS REFERENCE
============================================================

  bash scripts/agent-worktree.sh --help
  bash scripts/agent-worktree.sh start  --issue <N> [--dry-run] [-v]
  bash scripts/agent-worktree.sh list   [--verbose]
  bash scripts/agent-worktree.sh sync   [<N>]
  bash scripts/agent-worktree.sh finish [--dry-run]
  bash scripts/agent-worktree.sh clean  <N> [--force]

============================================================
WHEN IN DOUBT
============================================================

  - Read the wiki: https://github.com/CyberMind-FR/secubox-deb/wiki/Multi-Agent-Worktree
  - Read the spec: docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md
  - Read the doctrine section "🌿 Multi-Agent Worktree Workflow — Obligatoire" in CLAUDE.md

Never delete a worktree, branch, or PR you did not create. Never force-push
master. Never bypass the script for a task that qualifies for the cycle.
````

---

## 🟠 WALL — Pièges courants

| Symptôme | Cause probable | Remède |
|---|---|---|
| `start: working tree is dirty` (exit 3) | Modifications non commitées dans le checkout principal | `git stash` ou commit avant `start` |
| `start: gh not authenticated` (exit 2) | Token expiré | `gh auth login` |
| `start: issue #X not found` (exit 2) | Numéro d'issue erroné, ou repo wrong | Vérifier `gh issue list` |
| `finish: branch has no commits ahead` (exit 3) | Tu n'as rien committé dans le worktree | Faire au moins un commit |
| `finish: not on an agent branch` (exit 1) | Tu n'es pas dans un worktree créé par `start` | `cd` dans le bon dossier |
| `clean: PR is 'OPEN', refusing` (exit 3) | PR pas encore mergée | Attendre le merge, ou `--force` à tes risques |
| Slug trop court (titre 100% non-ASCII) | iconv ne peut pas translit | Fallback automatique `<prefix>/<N>-issue` |
| Deux issues avec slugs identiques | Préfixe `<N>-` les distingue | Aucune action requise |

---

## 🟢 ROOT — Sources de vérité

- **Script** : [`scripts/agent-worktree.sh`](https://github.com/CyberMind-FR/secubox-deb/blob/master/scripts/agent-worktree.sh)
- **Bibliothèque** : [`scripts/lib/agent-worktree-lib.sh`](https://github.com/CyberMind-FR/secubox-deb/blob/master/scripts/lib/agent-worktree-lib.sh)
- **Tests** : [`scripts/tests/test-agent-worktree.sh`](https://github.com/CyberMind-FR/secubox-deb/blob/master/scripts/tests/test-agent-worktree.sh) (26 cas)
- **Spec** : [`docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md`](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/superpowers/specs/2026-05-12-multi-agent-worktree-workflow-design.md)
- **Doctrine CLAUDE.md** : section `## 🌿 Multi-Agent Worktree Workflow — Obligatoire`
- **Help opérationnel** : `bash scripts/agent-worktree.sh --help`

---

*Page maintenue par CyberMind · Gérald Kerma · 2026-05-12*
