<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.

  Extrait À L'IDENTIQUE de l'ancien CLAUDE.md racine (master 8af868a51), #1863.
  Lu sur demande seulement : AGENTS.md renvoie ici.
-->

## 🧭 Session Startup — Lire d'abord

### Fichiers de référence obligatoires

| Priorité | Fichier | Description | Quand lire |
|----------|---------|-------------|------------|
| 1 | `.claude/WIP.md` | Travail en cours, prochain item | **Toujours en premier** |
| 2 | `.claude/TODO.md` | Backlog priorisé par phase | Pour planifier |
| 3 | `.claude/HISTORY.md` | Historique des changements | Pour contexte |
| 4 | `.claude/MIGRATION-MAP.md` | État modules (✅/🔄/⬜) | Pour status |
| 5 | `.claude/PATTERNS.md` | Patterns RPCD→FastAPI | Pour coder |
| 6 | `.claude/MODULE-COMPLIANCE.md` | Règles conformité | **Obligatoire avant code** |

### Fichiers de référence techniques

| Fichier | Description | Quand lire |
|---------|-------------|------------|
| `docs/TOOLS.md` | Référence outils build/génération | Pour builder |
| `.claude/QUICKSHEET-REFERENCE.md` | Quick ref commandes | Pour commandes |
| `.claude/DESIGN-CHARTER.md` | Charte UI/UX (C3BOX hermétique) | Pour frontend |
| `.claude/WEBUI-PANEL-GUIDELINES.md` | **Look & feel DÉFAUT des webui de gestion des modules** (cyan hybrid-dark, Courier Prime, emoji ; réf. `/certs/`) | Avant tout panel/admin webui |
| `.claude/WIKI-STYLE-GUIDE.md` | Style documentation | Pour docs |
| `.claude/NOTES.md` | Notes de session | Pour contexte additionnel |

### Workflow "continue" / "suivant" / "next"

1. Lire `WIP.md` → identifier le premier item "⬜ Next Up"
2. Implémenter selon `PATTERNS.md` et `MODULE-COMPLIANCE.md`
3. Mettre à jour les fichiers `.claude/` :
   - Cocher ✅ dans `MIGRATION-MAP.md` si module terminé
   - Déplacer dans "✅ Fait" dans `WIP.md`
   - Ajouter entrée datée dans `HISTORY.md`
   - Mettre à jour `TODO.md` si nécessaire

### Liens GitHub Issues

Pour les bugs et features : `https://github.com/CyberMind-FR/secubox-deb/issues`

Quand créer une issue :
- Bug non trivial nécessitant investigation
- Feature request de l'utilisateur
- Tâche à reporter pour plus tard

### Synchronisation GitHub Issues — Workflow Obligatoire

**Principe fondamental** : Transparence maximale. Chaque plan/feature majeure doit être synchronisée avec une GitHub Issue pour traçabilité publique.

#### Workflow complet (Open by Default)

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. CRÉATION DU PLAN                                                │
│     ├─ Identifier la feature/bug dans WIP.md ou TODO.md             │
│     ├─ Créer GitHub Issue avec label approprié                      │
│     │   gh issue create --title "..." --body "..." --label "..."    │
│     └─ Référencer l'issue # dans WIP.md/TODO.md                     │
├─────────────────────────────────────────────────────────────────────┤
│  2. IMPLÉMENTATION                                                  │
│     ├─ Mettre à jour WIP.md avec progression                        │
│     ├─ Commenter l'issue avec avancement significatif               │
│     │   gh issue comment <#> --body "Progress: ..."                 │
│     └─ Cocher les sous-tâches dans l'issue si applicable            │
├─────────────────────────────────────────────────────────────────────┤
│  3. COMPLÉTION (NE PAS FERMER)                                      │
│     ├─ Créer commit avec référence issue : "feat: X (ref #42)"      │
│     ├─ Mettre à jour HISTORY.md avec entrée datée                   │
│     ├─ Déplacer vers "✅ Fait" dans WIP.md                          │
│     ├─ Commenter l'issue : "Implementation complete, pending review"│
│     └─ NE JAMAIS fermer automatiquement                             │
├─────────────────────────────────────────────────────────────────────┤
│  4. VALIDATION MANUELLE (User uniquement)                           │
│     ├─ User teste/valide la feature                                 │
│     ├─ User confirme : "Validated, closing"                         │
│     └─ User ferme l'issue OU demande corrections                    │
└─────────────────────────────────────────────────────────────────────┘
```

#### Labels GitHub recommandés

| Label | Usage |
|-------|-------|
| `migration` | Portage OpenWrt → Debian |
| `hardware` | LED, GPIO, I2C, board-specific |
| `api` | FastAPI endpoints |
| `frontend` | Dashboard, UI, CSS |
| `security` | CSPN, nftables, WAF |
| `infra` | HAProxy, nginx, systemd |
| `documentation` | README, CLAUDE.md |
| `wip` | Travail en cours |
| `blocked` | Bloqué par dépendance |

#### Commandes rapides

```bash
# Créer une issue depuis la ligne de commande
gh issue create --title "Port LED heartbeat from OpenWrt" \
  --body "$(cat <<'EOF'
## Context
Description du problème ou de la feature.

## Tasks
- [ ] Task 1
- [ ] Task 2
- [ ] Task 3

## Files
- `path/to/file.py`

## References
- Related: #XX
EOF
)" --label "migration,hardware"

# Lister les issues ouvertes
gh issue list --state open

# Commenter une issue
gh issue comment 42 --body "Progress: Backend completed, testing frontend"

# Voir une issue
gh issue view 42

# Fermer (USER UNIQUEMENT après validation)
gh issue close 42 --comment "Validated and deployed"
```

#### Règles strictes

1. **Fermeture pilotée par marqueur** — une issue se ferme quand elle est
   **terminée ET déployée**, enregistrée par un marqueur MACHINE-LISIBLE dans
   `.claude/HISTORY.md` ou `.claude/WIP.md` : `closes #N` / `fixes #N` /
   `FERMÉ #N` / `RÉSOLU #N`. Ne PAS écrire ces marqueurs pour des issues
   « filed for later » ou « ouvertes » (HISTORY en journalise aussi). Le
   nettoyage se fait avec `scripts/sync-issues.sh` (`--dry-run` puis `--apply`),
   qui ferme les `#N` marquées encore ouvertes. Le texte libre ne ferme jamais.
2. **Référencer dans les commits** — `feat: X (ref #42)` en cours ; `closes #42`
   seulement une fois déployé.
3. **Synchroniser WIP.md** — Chaque issue ouverte doit apparaître dans WIP.md
4. **Snapshot avant clôture** — Commit + tag si feature majeure
5. **Issues publiques** — Workflow open source, traçabilité maximale

---

