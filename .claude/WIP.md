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

0a. **Alpha 9 = Trixie** (parent #1997, technique #1294) : migration en place VALIDÉE sur gk3 et gk2 (2026-10-05) ; noyau MOCHAbin stock Debian 6.12.111-2secubox (DSA/bridge/HSR/WAN intégrés) DÉFAUT et seul noyau de gk2 (secubox-5 retiré). Reste : release v3.0.0-alpha.9 (correctif PR #2016 fusionné ; tag à recréer après purge des runs obsolètes, puis ISO d'installation à la main), cycle systemd secubox-security-posture.socket, voice/freeboxtv/wg-mesh/g2/streamlit-audit/peertube-backlog sur gk2, clone MOCHAbin de répétition (#1998), radio PeerTube + sas ytsas (#2002), CI en double sur tag (#1991).
0b. **#1962** secubox-webfilter : **P1 et P2 livrées et déployées** (0.2.1, gk2 ; essai réel de blocage fait et validé). Reste P3 (apprentissage, parking), P4 (association DPI). Mineurs différés dans le registre de relecture. **#1973** DPI : étiquetage des destinations vues par IP seule. **#1974** export des compteurs du toolbox vers ad-guard. **#1938** : paquetage fait (`secubox-dns-lan` 0.1.0, déployé) ; reste le réglage Freebox (DNS IPv6), le certificat de gk3 et la plage DHCP. Règles RTL9 à l'essai jusqu'au 2026-10-05 matin.
0c. **#2050** simplification des modules avant la beta : vague 0 presque finie (reste : écrivains concurrents de `unbound.conf.d`/`torrc`/`nftables.conf`, surf et mesh en socket Unix), vague 1 commencée (reste : manifeste `component.toml`, gabarit postinst/rules, composant app-lxc, banc de montée de version), vague 2 FAITE (S1, S2, N1, D1, D2, S4, N3, N5, M2, M8 ; M3 et I2 écartés, voir dossier §16) ; vague 3a FAITE et déployée (qos, streamlit, media, mqtt, backup, metrics, ai-gateway) ; vague 3b (ytsas←torrent) FAITE ; vagues 3c/3d FAITES (media←freeboxtv, repo←release, jitsi←turn) ; M1, M4, N4, S5, M7 (sauf surf), R3, R4 (tor←proxypac,macro), S3, R1 (haproxy←vhost,exposure), R5 (annuaire←openpgp, p2p←meshname) FAITES (I5 sans objet)  ; I1 (auth←users,sbxid,oidc) et S6 (security-posture←cve-triage,antirootkit) FAITES et déployées ; N2 (system absorbe system-hub, admin, ksm, system-tuning ; unités root conservées) FAITE en source, NON déployée (à demander avant) ; vague 3r FAITE en source (cdn←mirror, qos←nettweak), NON déployée ; surf et mesh sur socket Unix FAITS (surf 1.0.32 déployé gk2, vérifié 200 avant/après, port 9082 fermé ; mesh 2.0.8 publié, NON installé : il est arrêté sur gk2 et son postinst le démarrerait) ; D3/D4 faits et déployés (bibliothèque adoptée par webfilter, dns-lan, ad-guard) et vortex-dns retiré ; M9 abandonné (décision du propriétaire, gain faible/risque réel) ; reste : S7 (waf+waf-ng), D3/D4 (à trancher), wireguard/reality, vague 5 (méta-paquets en vues générées). 52 transitoires à retirer un cycle après publication. Retirer les transitoires un cycle après leur publication.
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

## CI Sync 2026-10-05
- Packages: 168
- Endpoints: 2705
- Migration: 71%
- Commits: 6124

## CI Sync 2026-10-06
- Packages: 167
- Endpoints: 2662
- Migration: 70%
- Commits: 6215

## CI Sync 2026-10-07
- Packages: 168
- Endpoints: 2248
- Migration: 54%
- Commits: 6295
