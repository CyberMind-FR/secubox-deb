<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Divergences entre l'ancien CLAUDE.md et l'ancien AGENTS.md (#1863)

Relevées au `diff` le 2026-10-02 (master `8af868a51`). **Les deux premières sont des règles qui
se contredisent : elles attendent l'arbitrage de l'exploitant.** En attendant, `AGENTS.md`
porte la version de l'ancien CLAUDE.md (celle qui reflète la pratique courante), marquée
« PROVISOIRE ». Supprimer ce fichier une fois arbitré.

## À arbitrer (contradictions de règle)

### 1. Fermeture des issues (« Règles strictes », n° 1)

- **Ancien CLAUDE.md** — *Fermeture pilotée par marqueur* : une issue se ferme quand elle est
  **terminée ET déployée**, enregistrée par un marqueur machine-lisible dans `.claude/HISTORY.md`
  ou `.claude/WIP.md` (`closes #N` / `fixes #N` / `FERMÉ #N` / `RÉSOLU #N`) ; pas de marqueur pour
  les issues « filed for later » ; nettoyage par `scripts/sync-issues.sh` (`--dry-run` puis
  `--apply`) ; le texte libre ne ferme jamais.
- **Ancien AGENTS.md** — *Jamais de fermeture automatique* : seul le user peut valider et fermer.

### 2. Référence d'issue dans les commits (« Règles strictes », n° 2)

- **Ancien CLAUDE.md** — `feat: X (ref #42)` en cours ; `closes #42` seulement une fois déployé.
- **Ancien AGENTS.md** — `feat: Add X (ref #42)` ou `fix: Y (closes #42)` si le user a pré-validé.

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
