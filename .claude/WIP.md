<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WIP — chantier en cours + Next Up
*Mis à jour : 2026-10-02 (#1863).* Moins de 200 lignes, par construction : l'historique du
travail fait est dans `HISTORY.md` (mois courant) et `archive/` (le reste, sur demande).

## 🔄 Chantier en cours — #1863 : sessions Claude Code sobres en contexte

Branche `docs/1863-sessions-claude-code-sobres-en-contexte`. Livrables : archives par mois avec
preuve de zéro perte, une seule source d'instructions (`AGENTS.md`), `RULES-CODE.md`, permissions,
hooks PostToolUse, subagents, skills. Périmètre : `.claude/`, `AGENTS.md`, `CLAUDE.md`,
`.gitignore` — rien sous `packages/`, `common/`, `image/`, `scripts/`, ni en CI.

## 🟡 En vol — poussé, à ouvrir ou fusionner (voir détail dans `TODO.md`)

- **#1858 / #1859** WAF : PR #1860 et PR #1861 ouvertes, déployées gk2 (secubox-waf 1.10.42,
  secubox-waf-ng 1.18.12).
- **#1857** accès délégués retirés : déployé gk2 (webos 1.0.395, sbxid 0.4.17, vault 2.0.15) ;
  PR à ouvrir ; à valider au navigateur (SSO Nextcloud, « Mes sites », tuiles).
- **#1862** RustDesk décommissionné : gk2 fait, dépôt poussé, PR à ouvrir.
- **#1855** Coffre : fusionné (PR #1856), déployé gk2. gk2 est **scellé** depuis le dernier
  redémarrage du Coffre — rouvrir par la connexion admin.

## ⬜ Next Up (dans l'ordre)

1. **#1851** Coffre P3 — secrets de démarrage en niveau 0 : JWT, graines TOTP, ~49 secrets,
   un par un, redémarrage unitaire, `retirer-clair` seulement après vérification.
2. **#1766** nac : blocage / quarantaine sans effet réseau. **#1754** `set_real_ip_from`.
   **#1366** clé apt en clair. **#1516** dossiers en 0777.
3. **#1743** podman/docker hors des paquets ; **#1418 / #1506** paquets en chevauchement.
4. gk3 : `secubox-hardening` inactif, `hall.gk3` 421 — à expliquer.
5. Suites identité #1405 : demandes côté utilisateur, certificat client, SSO par rejeu.

## Règles de tenue de ce fichier

- Ce fichier ne porte que le chantier en cours et le Next Up. Une fois fait, l'item part dans
  `HISTORY.md` (entrée datée) ; `HISTORY.md` du mois précédent part dans `archive/HISTORY/`.
- Découpe des archives : `archive/decoupe.py` ; preuve : `archive/reassembler.py`.
