<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Divergences entre l'ancien CLAUDE.md et l'ancien AGENTS.md (#1863)

Relevées au `diff` le 2026-10-02 (master `8af868a51`). Les deux contradictions de règle ont été
**arbitrées par l'exploitant le 2026-10-02** : c'est la version de l'ancien CLAUDE.md qui fait loi
(`AGENTS.md` la porte désormais, sans mention provisoire). Ce fichier ne garde que la trace.

## Arbitré — contradictions de règle (« Règles strictes », n° 1 et 2)

| Règle | Ancien CLAUDE.md (RETENU) | Ancien AGENTS.md (écarté) |
|---|---|---|
| Fermeture des issues | Par marqueur machine-lisible (`closes #N` dans HISTORY/WIP) quand c'est **terminé ET déployé**, puis `scripts/sync-issues.sh` ; le texte libre ne ferme jamais | Jamais de fermeture automatique : seul le user valide et ferme |
| `closes #N` dans les commits | `(ref #N)` en cours ; `closes #N` seulement une fois déployé | `(closes #N)` si le user a pré-validé |

## Écarts de fond, tranchés d'office (sans contradiction de règle)

| Point | CLAUDE.md | AGENTS.md | Retenu |
|---|---|---|---|
| Frontal TLS | « HAProxy TLS 1.3 » listé | absent | présent (règle de sécurité, simple omission) |
| Paquet `secubox-crowdsec` | absent | cité (arbre, exemples) | absent : CrowdSec est sorti de la box |
| DPI | `nDPId`, `secubox-dpi` | `netifyd`, `luci-app-netifyd-dashboard` | nDPId |
| Dossier de suivi | `.claude/` | `.Codex/` (n'existe pas) | `.claude/` |
| Cache stats | « Toujours pour les dashboards stats (WAF, bandwidth, DPI…) » | ligne absente | présent |
| Table de priorité | 14 lignes dont `secubox-dpi` | ligne `secubox-dpi` absente | complète |
| Nom de l'agent | « Claude Code » | « Codex » | neutre (« les agents ») |
