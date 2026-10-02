<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# AGENTS.md — SecuBox-DEB

Source unique des instructions pour les agents (Claude Code, Codex, …). `CLAUDE.md` l'importe ;
il n'existe pas d'autre copie. Garder ce fichier sous 150 lignes : le détail vit dans
`.claude/reference/` et se lit **sur demande**, jamais au démarrage.

## Le projet

SecuBox-DEB : portage Debian bookworm arm64 de SecuBox OpenWrt (GlobalScale Marvell Armada),
cible certification ANSSI CSPN. Un module = un paquet `packages/secubox-<module>/` (`api/`, `www/`,
`debian/`). FastAPI + Uvicorn sur **socket Unix** par module ; nginx ; HAProxy TLS 1.3 → `sbxwaf`
(Go, WAF) → nginx ; nftables ; LXC (jamais Docker ni Podman) ; config TOML dans `/etc/secubox/`.
Code partagé : `common/secubox_core/`. Suivi de projet : `.claude/`.

## Démarrage — lecture ciblée

- **Rien à lire d'office.** Sur « continue / suivant / next » : `.claude/WIP.md` (< 200 lignes),
  premier item « ⬜ Next Up », puis seulement les fichiers de la table ci-dessous.
- **Avant de coder** : `.claude/MODULE-COMPLIANCE.md` (conformité d'un module) et
  `.claude/RULES-CODE.md` (règles permanentes de code). Patterns : `grep` dans `.claude/PATTERNS.md`.
- `.claude/archive/**` et les mois passés de `HISTORY.md` : **uniquement sur demande**, par `grep`
  ciblé puis lecture d'un seul fichier de mois (`archive/INDEX.md` dit où).
- Ne jamais lire en entier un fichier de plus de ~300 lignes sans nécessité : `grep -n`, puis `Read` avec plage.

## Règles non négociables

**Réseau / sécurité**
- nftables en `DEFAULT DROP` ; ouvrir explicitement le strict nécessaire. Jamais iptables.
- Exposition externe : HAProxy TLS 1.3 en frontal. Jamais d'auto-exposition de `127.0.0.1`.
- Tout le trafic passe par `sbxwaf` (127.0.0.1:8085, unité `secubox-waf-ng`). **Jamais** de bypass
  hand-édité ; seule exception : `waf_bypass = true` déclaratif par vhost dans
  `/etc/secubox/haproxy.toml` (honoré par `haproxyctl`). Un paquet déclare sa route WAF
  (`secubox-waf-route`), pas à la main. Détail : `.claude/reference/SECURITE-WAF.md`.
- AppArmor `enforce` et utilisateur dédié `secubox-<module>` (jamais root) pour chaque service.
- Aucun secret dans le code ni dans un TOML versionné : `/etc/secubox/secrets/`.
- Config sensible : double-buffer (shadow → validation → swap atomique) + rollback 4R ; chaque
  décision de sécurité écrite dans `/var/log/secubox/audit.log` (append-only).
- Conteneurs : **LXC uniquement** (`PATTERNS.md`, Pattern 11).

**API**
- RPCD `luci.<m>/<méthode>` → `GET|POST /api/v1/<m>/<méthode>` (lecture GET, action POST).
- Toute route porte une garde : `require_jwt` (administrateur réel) ; `require_session` ou
  `require_personne` posés **explicitement** sur les seules routes d'usager ; lecture : `require_lecture`.
- Socket `/run/secubox/<module>.sock`, jamais un port TCP direct.
- Stats lourdes : tâche de fond + cache fichier (`.claude/reference/PERF-CACHE.md`), jamais pour start/stop/ban.

**Paquets / frontend / fichiers**
- Version `X.Y.Z-N~bookworm1`, `debian/compat` 13, `Standards-Version: 4.6.2` ; `postinst`
  `systemctl enable --now`, `prerm` `systemctl stop`. Source modifiée et déployée = version montée.
- Frontend `htdocs` porté de LuCI : ne pas modifier le JS/CSS/HTML porté (`scripts/rewrite-xhr.py`).
  Look & feel des webui de gestion : `.claude/WEBUI-PANEL-GUIDELINES.md`.
- En-tête SPDX CMSD-1.0 sur tout fichier (`scripts/license-headers.py`).
- Ne pas utiliser `uci`/LuCI, ne pas écrire de secrets en clair, ne pas mentionner « CyberMind Produits SASU ».

## Flux de travail

- **Issue → worktree → PR.** Tout travail non trivial (≥ 3 fichiers, > 30 min, issue étiquetée) :
  `gh issue create`, puis `scripts/agent-worktree.sh start --issue <N>` ; commits `type: message (ref #N)` ;
  `scripts/agent-worktree.sh finish`. Le checkout principal reste réservé à `master` et au travail humain.
  Pas de worktree pour une édition triviale d'un fichier de suivi. Détail : `.claude/reference/WORKTREES.md`.
- **Fermeture d'issue** (arbitrée le 2026-10-02) : une issue ne se ferme qu'une fois terminée **et**
  déployée, par marqueur machine-lisible (`closes #N` dans `HISTORY.md`/`WIP.md`) puis
  `scripts/sync-issues.sh` ; jamais sur texte libre. Commits : `(ref #N)` en cours, `closes #N`
  seulement une fois déployé. Détail : `.claude/reference/WORKFLOW-ISSUES.md`.
- **Suivi** après chaque livraison : entrée datée dans `.claude/HISTORY.md`, `.claude/WIP.md`
  (déplacer le fait, pointer le suivant), `.claude/MIGRATION-MAP.md` si module terminé, README du
  paquet si l'API, un modèle Pydantic, le TOML ou `debian/control` changent.
- Un déploiement sur une box se fait par paquet (jamais d'édition à chaud), puis dépôt `apt.secubox.in`.

## Lire quoi, quand

| Besoin | Fichier | Quand |
|---|---|---|
| Où en est-on, quoi faire | `.claude/WIP.md` | « continue / next » |
| Backlog actif | `.claude/TODO.md` | planifier |
| Règles de code permanentes | `.claude/RULES-CODE.md` | avant tout code nouveau ou modifié |
| Conformité d'un module | `.claude/MODULE-COMPLIANCE.md` | avant de coder un module |
| Patterns RPCD→FastAPI, LXC | `.claude/PATTERNS.md` | en codant (grep) |
| État de migration des modules | `.claude/MIGRATION-MAP.md` | statut |
| Commandes de build / déploiement | `.claude/QUICKSHEET-REFERENCE.md`, `docs/TOOLS.md`, `.claude/reference/COMMANDES.md` | builder |
| Charte UI, panels admin | `.claude/DESIGN-CHARTER.md`, `.claude/WEBUI-PANEL-GUIDELINES.md` | frontend |
| Style des docs | `.claude/WIKI-STYLE-GUIDE.md` | docs |
| Stack, conventions, ANSSI, ZKP | `.claude/reference/PROJET-CONNAISSANCES.md` | contexte de fond |
| Structure du dépôt, priorités | `.claude/reference/PROJET-STRUCTURE.md` | s'orienter |
| WAF, routes `sbxwaf` | `.claude/reference/SECURITE-WAF.md` | vhost, exposition |
| CSPN, double-buffer, audit | `.claude/reference/CSPN.md` | config sensible |
| Exposition Tor/DNS/mesh | `.claude/reference/EXPOSITION-PUNK.md` | `secubox-exposure` |
| Shell Debian | `.claude/reference/SHELL-DEBIAN.md` | scripts |
| Eye Remote (boot media) | `.claude/reference/API-EYE-REMOTE.md` | module eye-remote |
| Historique, anciens chantiers | `.claude/archive/INDEX.md` | **sur demande seulement** |

Index de `.claude/reference/` : `.claude/reference/README.md`.

## Garde-fous automatiques (Claude Code)

`.claude/settings.json` : permissions (Bash autorisé d'office — autorisation durable du 2026-10-02 : push,
PR, merge, fermeture d'issue, ssh, sudo ; refusés : suppressions catastrophiques `rm -rf /`, `~`, `$HOME`, et lecture de secrets) ; `.claude/hooks/` : lint du seul fichier touché après chaque édition ;
`.claude/agents/` : `relecteur-securite` (lecture seule), `correcteur-lint`. Réglages propres à une
machine : `.claude/settings.local.json` (ignoré par git).

Auteur : Gérald Kerma <devel@cybermind.fr> — https://cybermind.fr · https://secubox.in
