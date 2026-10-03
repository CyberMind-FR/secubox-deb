<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WIP — chantier en cours + Next Up
*Mis à jour : 2026-10-02.* Moins de 200 lignes, par construction : l'historique du
travail fait est dans `HISTORY.md` (mois courant) et `archive/` (le reste, sur demande).

## ✅ Fusionné et nettoyé le 2026-10-02 et 03

PR #1856 (Coffre), #1860/#1861 (WAF), #1864 (accès délégués retirés), #1865 (RustDesk), #1866
(Claude Code), puis le 03/10 : pare-feu #1306 (fermée) et base unique livrée par secubox-hardening,
real_ip nginx #1754 (fermée), dossiers photo #1516 (fermée), NAC appliqué à nftables #1766, santé
(veille pondérée, test dynamique du WAF), assistance, Reporter, menu p2p, garde-fou CI #1748, clé
apt protégée au niveau 0 #1366. Détail : `HISTORY.md` (octobre).

## 🔄 Chantier en cours — #1917 VoiceStudio : livré, reste la validation par une personne connectée

- Livré et vérifié : `secubox-voicestudio` 0.2.4 sur gk3 (LXC natif, bascule faite, gk2 le consomme par le maillage,
  pare-feu, API sous bac à sable) ; **webui d'administration** `/voicestudio/` et **page d'usager**
  `/voicestudio/usager.html` ; **carte « Voix » du Hall** (`secubox-webos` 1.0.398, déployé gk2 et gk3 : le Hall ne
  relaie que `/usager/`, aucune route d'administration à son origine ; sur gk2 la carte dit « pas installé »).
- **#1743 : podman purgé** sur gk2 et gk3 (gk3 : 11 Go rendus) ; plus aucun runtime OCI nulle part, dettes de la liste
  retirées. Il ne reste de #1743 que le test de dépôt qui l'empêche de revenir.
- **Reste à valider par une personne connectée** (je n'ai pas d'identifiants web) : les deux pages et la carte du Hall
  au navigateur (dire, dicter au micro), puis fermer #1917 (`closes #1917` dans `HISTORY.md` +
  `scripts/sync-issues.sh --apply`) et #1743.

## ⏸️ Suspendu

- **#1851** Coffre P3, secrets au niveau 0 : suspendu le 03/10 (clé d'hôte sur le même disque sur gk2,
  gain limité aux copies partielles ; liaison TPM2 implicite sur gk3). Rien de plus n'est migré.
- **#1902** liaison au TPM2 explicite et optionnelle (défaut identique partout) : mise de côté.

## ⬜ Next Up (dans l'ordre)

1. **#1748** audit des autres fusions suspectes (nextcloud c43ffe9b0, metrics/core 7ebe27403, toolbox,
   nac discovery) : lignes de master retirées toujours absentes, à examiner une à une.
2. **#1903** sauvegardes chiffrées par défaut ; **#1904** un groupe par secret (issus de l'évaluation #1851).
3. **#1366** gestes humains : export hors ligne sur clé USB puis effacement du poste ; sort de
   `publish-packages.yml` ; clé de mise en scène 31848880.
4. **#1766** à valider (NAC) ; gk3 : dpi, mediaflow, sentinelle-gsm absents de son jeu de paquets.
5. **#1418 / #1506** paquets en chevauchement (#1743 : fait, à fermer après validation de #1917).
6. Suites identité #1405 : demandes côté utilisateur, certificat client, SSO par rejeu.

## Règles de tenue de ce fichier

- Ce fichier ne porte que le chantier en cours et le Next Up. Une fois fait, l'item part dans
  `HISTORY.md` (entrée datée) ; `HISTORY.md` du mois précédent part dans `archive/HISTORY/`.
- Découpe des archives : `archive/decoupe.py` ; preuve : `archive/reassembler.py`.
