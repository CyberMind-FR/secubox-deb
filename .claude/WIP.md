<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WIP — chantier en cours + Next Up
*Mis à jour : 2026-10-02.* Moins de 200 lignes, par construction : l'historique du
travail fait est dans `HISTORY.md` (mois courant) et `archive/` (le reste, sur demande).

## ✅ Fusionné et nettoyé le 2026-10-02

PR #1856 (Coffre), #1860 (WAF règles), #1861 (sbxwaf), #1864 (accès délégués retirés), #1865
(RustDesk), #1866 (sessions Claude Code sobres) : fusionnées, issues fermées (#1855, #1857, #1858,
#1859, #1862, #1863, #1581, #1808, #1684), worktrees et branches supprimés. Reste ouvert :
**#1748** (déployer gk3, garde-fou CI contre les fusions qui écrasent master).

## 🔄 Chantier en cours — aucun

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
