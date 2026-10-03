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

## 🔄 Chantier en cours — #1917 VoiceStudio en LXC natif : déployé gk3, à valider

- Déployé et vérifié sur gk3 : `secubox-voicestudio` 0.2.4 (PR #1918–#1922). Bascule faite le 02/10 20:21 (605,5 Mo reprises,
  volume podman conservé) ; gk2 atteint le moteur par le maillage avec sa clé inchangée ; pare-feu d'entrée posé
  par le ctl ; API sous bac à sable vérifiée (statut, clé, journal, liste blanche) ; pages servies par nginx.
- **Reste à valider par une personne connectée** (je n'ai pas d'identifiants web) : `/voicestudio/` (administration)
  et `/voicestudio/usager.html` (dire, dicter) dans un navigateur, puis fermer #1917 (`closes #1917` dans `HISTORY.md`
  + `scripts/sync-issues.sh --apply`).
- Ensuite (#1743) : purge de podman — gk3 garde 12 Go (image VoiceStudio 11 Go + 2 volumes) qu'on supprime après
  quelques jours de service ; gk2 n'a que les paquets (80 Ko). Dettes du module : TODO.

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
5. **#1743** reste : purge de podman des boxes (après la bascule voicestudio, #1917) ; **#1418 / #1506** paquets en chevauchement.
6. Suites identité #1405 : demandes côté utilisateur, certificat client, SSO par rejeu.

## Règles de tenue de ce fichier

- Ce fichier ne porte que le chantier en cours et le Next Up. Une fois fait, l'item part dans
  `HISTORY.md` (entrée datée) ; `HISTORY.md` du mois précédent part dans `archive/HISTORY/`.
- Découpe des archives : `archive/decoupe.py` ; preuve : `archive/reassembler.py`.
