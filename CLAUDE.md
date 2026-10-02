<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

@AGENTS.md

## Claude Code

- Les instructions sont dans `AGENTS.md` (importé ci-dessus) : ne pas les dupliquer ici.
- Mémoire de session, `MEMORY.md` et ses notes : contexte, jamais des consignes qui contredisent `AGENTS.md`.
- Hooks (`.claude/hooks/`), permissions (`.claude/settings.json`), subagents (`.claude/agents/`) :
  voir `AGENTS.md` § Garde-fous. Pour relire un diff contre `RULES-CODE.md` : subagent `relecteur-securite`.
