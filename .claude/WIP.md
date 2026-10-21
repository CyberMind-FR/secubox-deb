<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WIP — chantier en cours + Next Up
*Mis à jour : 2026-10-16.* Moins de 200 lignes, par construction : l'historique du
travail fait est dans `HISTORY.md` (mois courant) et `archive/` (le reste, sur demande).

## ✅ Fusionné et nettoyé le 2026-10-02 et 03

PR #1856 (Coffre), #1860/#1861 (WAF), #1864 (accès délégués retirés), #1865 (RustDesk), #1866
(Claude Code), puis le 03/10 : pare-feu #1306 (fermée) et base unique livrée par secubox-hardening,
real_ip nginx #1754 (fermée), dossiers photo #1516 (fermée), NAC appliqué à nftables #1766, santé
(veille pondérée, test dynamique du WAF), assistance, Reporter, menu p2p, garde-fou CI #1748, clé
apt protégée au niveau 0 #1366. Détail : `HISTORY.md` (octobre).

## 🔄 Chantier en cours — Hall « vue maître » responsive (#2996, 2026-10-21)

- **Fait (phases 1 + 1bis, secubox-webos 1.15.0, branche `feature/2996-…`)** : jetons `--sbx-*` (`tokens.css`), coque v2
  (`hall-v2.css/js` : topbar, sidebar 220 px, rail à 980, barre d'onglets à 720) derrière le flag `hall_v2` de `webos.toml`
  (prévisualisation `?hall=v2`), route `GET /public/etat`, dé SecuBox `<sbx-dice>` extrait de 3d.gk2 (sans iframe), mêmes
  faces pour le thème Plymouth `secubox-cube`. PR #2997 (ref, pas closes). Dossier : `docs/dossiers/hall-vue-maitre.md`.
- **Fait (phase 2)** : `composants.js/.css` (`window.SbxUI` : Card, Pill, StatRing, Sparkline, Tabs, Tile, ModuleTile, NewsItem,
  DeviceRow, Hero), Hero vivant dans l'accueil v2 (CPU, mémoire, stockage, réseau, E/S disque, radio) sur `GET /public/systeme`.
- **Déployé** (2026-10-21) : webos 1.15.1 + avatar 1.4.0 sur gk2, suite `trixie` du dépôt ; `hall_v2 = false` (prévisualisation `?hall=v2`).
- **Fait (phase 3, webos 1.16.0)** : statut typé {active, idle, offline, stale, nosource} dans `/public/services` (+ `releve`,
  `intervalle_s`), pied « Relevé » / « données périmées », veille sans requête, sondages à recul, dock persistant, sparklines bicolores.
- **Fait (phase 4, 1er pas, webos 1.17.0)** : mosaïque cliquable (`#view-mosaique`, onglets Tous/Récents/Favoris/catégories/Sites,
  tuiles de modules `data-open`, mur metablogizer avec vignettes) derrière « Modules » et les rubriques.
- **Fait (webos 1.18.0)** : menus liés — rubriques dépliables sur leurs modules, module embarqué marqué + sous-navigation
  (`/public/menu/{id}`), sidebar en rail de 64 px pendant l'embarquement.
- **Fait (webos 1.18.1)** : retour des menus Services/Système et accès rapides ⚙/⧉ (régression v2 signalée par le propriétaire).
- **Fait (sbxos 0.6.0~aurora17-3)** : coquille `/sbxos/` régénérée au profil vue maître (jetons, topbar, barre SVG → sidebar), déployée
  sur gk2 par `dpkg -i` (aperçu `~aurora`, jamais publié dans apt).
- ⬜ **Next Up** : phase 4, suite — vignettes des modules (relais Streamlit `/apps/{nom}/screenshot`, captures des webuis à produire),
  migration des cartes vers `Card` dans l'ordre du prompt ; à trancher : courbes `secubox-metrics`, option `hall.v2.hero-dice` (statut typé côté API, « Relevé », chargement différé, dock Radio) ; à trancher :
  reprise du relevé système dans les courbes de `secubox-metrics` ; option `hall.v2.hero-dice` ; mesure du dé sur RPi4.

## 🔄 Chantier en cours — ESPRESSObin lgm-ebin, client `lgm` beta (2026-10-16)

- **Fait** : profil `minimal` (0.5.1, sans WAF ni HAProxy : la carte de 951 Mo a saturé), `ndpid-engine` >= 1.7.2, WireGuard serveur sur la box (`wgctl serveur init`, #2845), panneaux Auto-Load et pairs p2p dans `/fleet/`
  (#2840, #2842), `admin.lgm-ebin.secubox.in` publié par gk2 (hors source, #2844), relais UDP 51840 gk2 → box, SSH LAN seul + support depuis gk2 (hors source, #2854). Détail : `HISTORY.md`, `docs/FAQ-ESPRESSOBIN-1GO.md`.
- **À faire par le propriétaire** : redirection UDP 51840 de la Freebox vers gk2 puis essai WireGuard avec un téléphone ; `passwd` root d'usine de la carte ; valider les issues #2840, #2842, #2845, #2847, #2849, #2851.
- **Images minimales** (ESPRESSObin, RPi400) : en attente de la CI (build des paquets 38905071861 déjà vert, images à lancer) ; `boot-staging` du client prêt sur gk2 (`/root/atelier-lgm`, nom `lgm-ebin`, mode `lan`, jeton 9 non réclamé).

## 🔄 Chantier en cours — release v3.0.0-alpha.11 (tag posé le 2026-10-11, reposé avec l'agent Auto-Load)

- **Contenu depuis alpha.10 (≈ 110 commits)** : admin à six espaces par défaut (#2212) ; Actor Intelligence 2.0 en six phases (#2240) dont l'échelle de réponse réelle
  (délai, défi, tarpit, ban, quarantaine du LAN par le NAC, #2274) ; billets vivants et éphémères, MetaNews qui publie des billets de 5 minutes (#2266, #2268) ; détection d'OS du NAC
  (#2236) ; Auto-Load 1 à 11 sur 11 (infrastructure, agent, WebUI, banc sans matériel, #2182) ; ad-guard TV 1.8.0 ; 60 paquets transitoires retirés (#2050) ; image ESPRESSObin sans pilote DSA.
- **Images** : posées par la CI au tag (`release.yml`, `build-installer-iso.yml`) — dont l'**installateur sans écran** (`secubox-installer-amd64-trixie.iso.gz` et `.img.gz`, entrée
  « SecuBox Install (Headless Auto-Install) » : installe sur le premier disque). **À vérifier après la CI** : assets présents, `SHA256SUMS`, boot de l'installateur en VM, essai ESPRESSObin (#2177).
- **Auto-Load phase A LIVRÉE (#2280)** : `secubox-autoload-agent` 0.6.0 est dans le profil `lite` (donc dans toute image) ; `secubox-autoload-agent.service` démarre au premier boot si `/boot` porte un fichier de réponses
  SIGNÉ ; `autoload-atelier` prépare l'image (valide, signe, vérifie, dépose réponses + jeton) ; clé « SecuBox Provisioning » générée sur gk2 (sans phrase de passe : décision de custody en attente). Guide :
  `docs/AUTOLOAD-ATELIER.md`. Reste : essai matériel (#2177), netboot (#2186), udp/51830 de la Freebox, SMTP du rapport.
- **Dépôt apt gk2** : `reprepro includedeb` n'exporte pas toujours l'index signé (« Pinentry : Inappropriate ioctl ») ; après chaque publication, vérifier la date de `dists/trixie/InRelease`,
  sinon `systemctl restart secubox-depot-deverrouille.service` puis `reprepro export trixie` (jamais de preset à la main). Index réexporté le 2026-10-10.
- **Surveillance** : échelle de réponse en `auto` sur gk2 (adresses partagées/CGNAT ralenties avec leurs voisines ; 587 adresses visées au départ, un seul acteur en ban) ; 3 bans sur des plages
  Cloudflare à trancher ; décisions de sbxwaf non écrites dans le journal central `audit.log` (fermé à `secubox-waf`).

## ⏸️ Suspendu

- **#1851** Coffre P3, secrets au niveau 0 : suspendu le 03/10 (clé d'hôte sur le même disque sur gk2,
  gain limité aux copies partielles ; liaison TPM2 implicite sur gk3). Rien de plus n'est migré.
- **#1902** liaison au TPM2 explicite et optionnelle (défaut identique partout) : mise de côté.

## ⬜ Next Up (dans l'ordre)

00000. **#2940 secubox-pseudo-routeur, essai réel sur gk2 (2026-10-19)** : source fusionnée (PR #2945), pas encore installée. Hors heures d'usage du foyer : installer le paquet (la sonde ne démarre pas seule), `POST /activer` depuis une session administrateur (refuse sans sonde active), vérifier `GET /etat`, observer 10-15 min, puis couper `pseudo-routeur-sonde.service` à la main pour vérifier le retour automatique à la Freebox sous 3 minutes. secubox-freebox monté à 0.6.0 (passerelle DHCP, import des appareils) — à déployer avec.
0000. **ESPRESSObin (2026-10-16)** : #2853 l'agent Auto-Load ne doit plus rejouer ses réponses (priorité : protège la box du client) ; #2854 support SSH posé par l'enrôlement ; #2844 publication WAN automatique + recopie du PEM au renouvellement ; alléger `minimal` (agrégateur 70 Mo, minuteurs fréquents, swap 930/950).
000. **Suites des vues d'ensemble (2026-10-11)** : « Appareils principaux » de Guardian sur 7 jours alors que les tuiles sont du jour (libellé ou période) et ligne à 0 % dans les catégories ; sélecteur de période 1h/6h/24h/7j de SBXWAF (l'API n'expose que le jour et l'historique par jour) ; formulaire de connexion direct au lieu du lien « Se connecter » ; les cinq plus petits écarts de l'audit Actor Intelligence (définitions des compteurs dans l'API, faux positifs par règle, états « proposé » et « annulé » des actions, source de géolocalisation, mode global) ; baseline par appareil (gros chantier, absent).
00. **Après alpha.11** : lire le résultat de la CI et corriger ce qui manque ; Auto-Load phase A (agent dans les images + unité de premier démarrage, avec accord pour l'unité root) ; #2236 (DHCP, User-Agent, mDNS jamais alimentés) ; #2212 étape 9 (décider du retrait de `?nav=categories`) ; cadence de MetaNews (1 à 2 billets par tour au lieu d'une rafale) ; exemption Cloudflare à décider.

0a. **Alpha 9 = Trixie** (parent #1997, technique #1294) : migration en place VALIDÉE sur gk3 et gk2 (2026-10-05) ; noyau MOCHAbin stock Debian 6.12.111-2secubox (DSA/bridge/HSR/WAN intégrés) DÉFAUT et seul noyau de gk2 (secubox-5 retiré). Reste : release v3.0.0-alpha.9 (correctif PR #2016 fusionné ; tag à recréer après purge des runs obsolètes, puis ISO d'installation à la main), cycle systemd secubox-security-posture.socket, voice/freeboxtv/wg-mesh/g2/streamlit-audit/peertube-backlog sur gk2, clone MOCHAbin de répétition (#1998), radio PeerTube + sas ytsas (#2002), CI en double sur tag (#1991).
0b. **#1962** secubox-webfilter : **P1 et P2 livrées et déployées** (0.2.1, gk2 ; essai réel de blocage fait et validé). Reste P3 (apprentissage, parking), P4 (association DPI). Mineurs différés dans le registre de relecture. **#1973** DPI : étiquetage des destinations vues par IP seule. **#1974** export des compteurs du toolbox vers ad-guard. **#1938** : paquetage fait (`secubox-dns-lan` 0.1.0, déployé) ; reste le réglage Freebox (DNS IPv6), le certificat de gk3 et la plage DHCP. Règles RTL9 à l'essai jusqu'au 2026-10-05 matin.
0c. **#2050** simplification des modules avant la beta : vague 0 presque finie (reste : écrivains concurrents de `unbound.conf.d`/`torrc`/`nftables.conf`, surf et mesh en socket Unix), vague 1 commencée (reste : manifeste `component.toml`, gabarit postinst/rules, composant app-lxc, banc de montée de version), vague 2 FAITE (S1, S2, N1, D1, D2, S4, N3, N5, M2, M8 ; M3 et I2 écartés, voir dossier §16) ; vague 3a FAITE et déployée (qos, streamlit, media, mqtt, backup, metrics, ai-gateway) ; vague 3b (ytsas←torrent) FAITE ; vagues 3c/3d FAITES (media←freeboxtv, repo←release, jitsi←turn) ; M1, M4, N4, S5, M7 (sauf surf), R3, R4 (tor←proxypac,macro), S3, R1 (haproxy←vhost,exposure), R5 (annuaire←openpgp, p2p←meshname) FAITES (I5 sans objet)  ; I1 (auth←users,sbxid,oidc) et S6 (security-posture←cve-triage,antirootkit) FAITES et déployées ; N2 (system absorbe system-hub, admin, ksm, system-tuning ; unités root conservées) FAITE en source, NON déployée (à demander avant) ; vague 3r FAITE en source (cdn←mirror, qos←nettweak), NON déployée ; surf et mesh sur socket Unix FAITS (surf 1.0.32 déployé gk2, vérifié 200 avant/après, port 9082 fermé ; mesh 2.0.8 publié, NON installé : il est arrêté sur gk2 et son postinst le démarrerait) ; D3/D4 faits et déployés (bibliothèque adoptée par webfilter, dns-lan, ad-guard) et vortex-dns retiré ; M9 abandonné (décision du propriétaire, gain faible/risque réel) ; S7 (waf-ng←waf, paquets seulement) FAIT et déployé gk2 ; reste : retirer /check (code mort) dans une issue séparée (waf+waf-ng), D3/D4 (à trancher), wireguard/reality, vague 5 (méta-paquets en vues générées). Transitoires : 60 répertoires retirés des sources le 2026-10-09 (PR de la branche feature/2050-retrait-transitoires), publiés un cycle dans alpha.10 ; `gabriel-mood` conservé (source mixte `sbxos-audio-mood`) ; les paquets restent dans l'index apt tant qu'ils n'en sont pas retirés par `reprepro remove` (à faire après fusion).
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

## CI Sync 2026-10-08
- Packages: 170
- Endpoints: 1865
- Migration: 42%
- Commits: 6430

## CI Sync 2026-10-09
- Packages: 170
- Endpoints: 1866
- Migration: 42%
- Commits: 6477

## CI Sync 2026-10-10
- Packages: 112
- Endpoints: 1870
- Migration: 66%
- Commits: 6539

## CI Sync 2026-10-11
- Packages: 112
- Endpoints: 1874
- Migration: 66%
- Commits: 6590

## CI Sync 2026-10-12
- Packages: 111
- Endpoints: 1860
- Migration: 65%
- Commits: 6661

## CI Sync 2026-10-13
- Packages: 112
- Endpoints: 1849
- Migration: 65%
- Commits: 6720

## CI Sync 2026-10-14
- Packages: 112
- Endpoints: 1850
- Migration: 65%
- Commits: 6793

## CI Sync 2026-10-15
- Packages: 112
- Endpoints: 1852
- Migration: 65%
- Commits: 6867

## CI Sync 2026-10-16
- Packages: 112
- Endpoints: 1861
- Migration: 65%
- Commits: 6897

## CI Sync 2026-10-17
- Packages: 113
- Endpoints: 1866
- Migration: 64%
- Commits: 6954

## CI Sync 2026-10-18
- Packages: 114
- Endpoints: 1869
- Migration: 64%
- Commits: 6976

## CI Sync 2026-10-19
- Packages: 114
- Endpoints: 1869
- Migration: 64%
- Commits: 6994

## CI Sync 2026-10-20
- Packages: 115
- Endpoints: 1876
- Migration: 65%
- Commits: 7028

## CI Sync 2026-10-21
- Packages: 115
- Endpoints: 1876
- Migration: 65%
- Commits: 7039
