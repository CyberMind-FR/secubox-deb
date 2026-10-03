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

## 🔄 Chantier en cours — #1917 VoiceStudio : livré et déployé sur gk3, reste la validation connectée

- **Livré et vérifié (hors session connectée)** : `secubox-voicestudio` 0.3.2 sur gk3 — LXC natif, API, console d'administration
  `/voicestudio/`, page d'usager `/voicestudio/usager.html`, **interface native du studio** sur
  `https://voicestudio.gk3.secubox.in/` (construite dans le LXC avec bun épinglé ; administrateurs seulement : `auth_request` →
  `/gate`, clé posée par nginx ; 401 sur tous les chemins sans administrateur). Hall (`secubox-webos` 1.0.399, gk2 + gk3) :
  deux entrées « VoiceStudio » (état ; agrandie = interface native ; ⚙️ = console) et « Voix » (dire, dicter).
- **Relais du maillage** : gk2 relaie `voicestudio.gk3.secubox.in` → `10.10.0.5:9080` (outil officiel
  `secubox-relais-maillage relayer …`, posé à la main car le minuteur horaire n'avait pas encore pris le nom).
- **Mémoire (2026-10-03)** : la synthèse vocale chargeait un modèle de ≈ 3,6 Go ; le tueur de mémoire global abattait le moteur (swap plein) et le
  frontal public coupait à 30 s (« HTTP 504 »). Corrigé et DÉPLOYÉ : swap disque 8 Go sur /srv/secubox (system-tuning 1.2.5), mise en sommeil des
  autres conteneurs endormables avant une synthèse (voicestudio 0.4.3), modèle rendu après 60 s, délais 300 s / 330 s / 10 min (HAProxy 1.8.24 sur
  gk2, webos 1.0.401). Essai réel : 109 s à froid, 0 OOM. **À savoir** : le grand modèle prend 110-140 s sur gk3 ; « Dire » sans voix nommée passe désormais par la voix rapide Piper (0.5.0, < 1 s).
- **Reste à valider par une personne connectée en administrateur** (je n'ai pas d'identifiants web) : (1) `/voicestudio/` ;
  (2) `https://voicestudio.gk3.secubox.in/` — l'interface native chargée avec la session (assistant de première
  utilisation, voix, doublage ; le moteur migré a peut-être déjà ses préférences) ; (3) la carte « Voix » du Hall (dire, dicter
  au micro) ; (4) l'agrandissement de la carte « VoiceStudio » dans le Hall (cadre sur le domaine du studio). Puis fermer
  #1917 et #1743 (`closes #…` dans `HISTORY.md` + `scripts/sync-issues.sh --apply`).

## ⏸️ Suspendu

- **#1851** Coffre P3, secrets au niveau 0 : suspendu le 03/10 (clé d'hôte sur le même disque sur gk2,
  gain limité aux copies partielles ; liaison TPM2 implicite sur gk3). Rien de plus n'est migré.
- **#1902** liaison au TPM2 explicite et optionnelle (défaut identique partout) : mise de côté.

## ⬜ Next Up (dans l'ordre)

0. **#1954** mode auto ad-guard TV : EN SERVICE sur la TV (1.4.2, règles importées, TV en `auto`). Reste : observer quelques jours (candidats proposés, seuils à calibrer), seconde TV (android-22) non traitée, mineurs reportés (HISTORY). **#1938** : packager l'adresse IPv6 `…::200`, les fichiers DNS manuels et le drop-in Unbound.
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
