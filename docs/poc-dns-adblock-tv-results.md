<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# POC « DNS AdBlock TV » — rapport final (#1943)

> **Validation partielle sur une Freebox TV réelle (2026-10-03).** Une seule TV (Android TV, 192.168.1.95), une seule application (replay France TV),
> une session d'environ 40 minutes. Les mesures du §6 viennent du banc local ; celles des §7 à §12 viennent de cette session. Rien n'est extrapolé
> à d'autres applications, d'autres chaînes ou la seconde TV, qui n'ont pas été testées.

## 1. Objectif
Mesurer ce que le filtrage DNS d'une SecuBox bloque réellement, pour des appareils choisis, en mode OBSERVE (aucun blocage) et BLOCK. Formulation retenue :
**réduction des domaines publicitaires/tracking résolus par DNS** — jamais « suppression de publicités ».

## 2. Architecture
Voir `docs/poc-dns-adblock-tv.md` §4. Résumé : une **vue Unbound par mode** rattache chaque appareil du périmètre ; le journal d'Unbound alimente des compteurs
(`secubox-adguard-dnsfeed`) ; l'API `/api/v1/ad-guard/adblock-tv/*` et l'onglet « DNS AdBlock TV » pilotent et lisent. Intégré à `secubox-ad-guard` 1.2.0.

## 3. Installation
```
apt install secubox-ad-guard                       # 1.2.0 ; le POC est INACTIF par défaut
# activer : onglet « DNS AdBlock TV » (ajouter l'appareil, cocher Activé), puis
systemctl enable --now secubox-ad-guard-dnsfeed     # compteurs
```
## 4. Configuration
`/etc/secubox/ad-guard.toml` : `[adblock_tv] retention_jours = 30`. État (appareils, modes) : `/var/lib/secubox/ad-guard/dnstv/etat.json`. Liste personnalisée :
`/var/lib/secubox/ad-guard/dnstv/custom.txt`. Drop-in généré : `/etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf`.
**Retour arrière** : `sudo secubox-adguard-tv disable && sudo systemctl disable --now secubox-ad-guard-dnsfeed` (le retrait du paquet le fait aussi).

## 5. Méthodologie de test
- **Banc local** (`tools/dns-limits-lab.py`) : trois Unbound (amont fictif `.sbxlab`, « box » avec la configuration réellement générée par le POC, « résolveur externe »), des
  « appareils » = adresses 127.0.0.x. Chaque cas est **observé** (réponses DNS + journal réel d'Unbound), jamais supposé.
- **Tests automatiques** (`packages/secubox-ad-guard/tests`) : bibliothèque, contrôleur root, API, outil client, interface (Chromium), banc Unbound.
- **Appareil réel** : `tools/tv-before-after.py` (phases A/B/C par différence de relevés) — **à jouer**, voir `docs/poc-dns-adblock-tv.md` §7 et `packages/secubox-ad-guard/reports/tv-before-after.md`.

## 6. Résultats (banc local)
| Cas | Observation (réponses DNS réelles) | Conclusion |
|---|---|---|
| A — pub sur domaine distinct (`ads.cdn-pub.sbxlab`) | OBSERVE : NOERROR ; BLOCK : NXDOMAIN | bloquable |
| B — tracking sur domaine distinct (`metrics.tracker.sbxlab`) | OBSERVE : NOERROR ; BLOCK : NXDOMAIN | bloquable |
| C — pub et vidéo, même nom (`video.studio.sbxlab`) | OBSERVE : NOERROR ; BLOCK : NXDOMAIN | insuffisant : bloquer le nom supprime AUSSI la vidéo |
| D — pub dans le flux (`stream.studio.sbxlab`) | BLOCK : NOERROR ; classé : None | insuffisant : le nom du flux est résolu même en BLOCK (aucun nom publicitaire distinct) |
| E — IP codée en dur | 0 requête DNS émise, 0 ligne ajoutée au journal | contourné : sans requête DNS, la box ne voit ni ne bloque rien |
| F — DoH / résolveur externe | résolu par l'externe : NOERROR ; requêtes vues par la box : 0 | contourné : la box ne voit aucune requête de cet appareil |
| G — domaine partagé (`cdn.sharedcloud.sbxlab`) | OBSERVE : NOERROR ; BLOCK : NXDOMAIN | faux positif : le contenu légitime du même domaine est bloqué |
| Isolement | autre client : NXDOMAIN ; appareil observé : NOERROR | le POC n'altère pas le puits de production pour les autres clients ; l'appareil observé en est exempté |
| Site ordinaire | BLOCK : NOERROR | jamais touché |

Journal réel d'Unbound lu par l'analyseur : 13 événements, décisions {'ALLOWED': 8, 'BLOCKED': 5, 'UPSTREAM_ERROR': 0}, clients ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4'].
Données brutes : `packages/secubox-ad-guard/reports/dns-limits.json`, `…/dns-test.json`.

## 7. Domaines bloqués
Phase C (blocage, TV seule) : 144 requêtes, 79 refusées (NXDOMAIN), 4 domaines, 0 erreur amont. Bloqués : `videos-pub.ftv-publicite.fr` (liste personnalisée,
appris par comparaison des phases E et P), `aes.eu-central.3px.axp.amazon-adsystem.com`, `aax-events-cell02-cf.eu-central.3px.axp.amazon-adsystem.com`,
`ad.doubleclick.net`. Le motif `c.2mdn.net` (vidéos de pub Google) était aussi actif mais n'a reçu aucune requête pendant la phase C. Le jeu de listes
reste court et non exhaustif.

## 8. Domaines nécessaires
Autorisés et nécessaires à la lecture (lecture démarrée, vidéo vue) : `cloudreplay.ftven.fr`, `k7.ftven.fr`, `hdfauth.ftven.fr`, `geo-info.ftven.fr`,
`medias.france.tv`, `proxy-mediation.yatta.francetv.fr`, `assets.webservices.francetelevisions.fr`. `7cd77.v.fwmrm.net` (FreeWheel) est demandé avant et pendant les coupures :
il n'a **pas** été bloqué, donc on ne sait pas s'il est nécessaire. `gcdn.2mdn.net`, vu sans pub en phase E, est bloqué par la liste générale d'ad-guard pour les autres appareils :
non testé sur la TV.

## 9. Faux positifs
Aucun faux positif constaté : la lecture a démarré normalement en blocage et aucune erreur n'est apparue. Un seul scénario a été essayé (nouvelle série, pré-roll).

## 10. Limites
Voir §6 (C, D, E, F, G) et `/adblock-tv/limites`. De plus : la box ne voit **que** les requêtes qui lui parviennent ; un appareil qui utilise l'IPv6 de la Freebox, DoH ou DoT lui échappe (constaté sur ce réseau pour l'IPv6, #1938).

## 11. DNS bypass
Détection **sans inspection HTTPS** : appareils visibles (ARP/NDP) mais **silencieux** côté DNS de la box (`/adblock-tv/bypass`), et DNS PATH TEST. La box ne peut **pas** voir un DNS externe qui ne passe pas par elle : limite documentée, pas contournée.

## 12. Impact sur la TV
Constaté par l'opérateur : lors d'un pré-roll de 6 secondes en phase C, **écran noir d'environ 6 s, sans pub, puis lecture normale**, sans message d'erreur.
Le DNS supprime donc le contenu de la pub mais pas le créneau : le serveur d'insertion (FreeWheel) répond encore et la TV attend la durée prévue. Non mesuré :
la durée du noir avec une pub plus longue, les coupures en milieu de programme, les autres applications.

## 13. Ce que le DNS permet
Bloquer un **nom** publicitaire ou de pistage distinct (A, B), observer ce qu'un appareil résout (liste de domaines, volume, catégories), mesurer l'effet d'un filtrage appareil par appareil, sans MITM.

## 14. Ce que le DNS ne permet pas
Séparer une publicité de sa vidéo quand elles partagent un nom (C) ou un flux (D) ; filtrer une application qui n'interroge pas le DNS (E) ou qui passe par DoH/DoT (F) ; éviter les faux positifs sur un domaine partagé (G).

## 15. Étape suivante pour SecuBox Gold
1. Jouer la procédure A/B/C sur les 2 Freebox TV et compléter `packages/secubox-ad-guard/reports/tv-before-after.md` (domaines nécessaires, faux positifs, fonctions cassées).
2. Corriger l'exemption par vue vide de `secubox-adblock-sync` (§5 de l'audit) après vérification sur Unbound 1.17.
3. Brancher le POC sur les listes publiques de `secubox-adblock-sync` (versionnées, validées) plutôt que le jeu de test.
4. Si l'objectif est de limiter les publicités **intégrées** ou servies depuis le même domaine : le DNS ne suffit pas ; c'est une autre étude (hors périmètre, et sans MITM).
