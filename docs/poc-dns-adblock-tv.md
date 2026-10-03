<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# POC « DNS AdBlock TV » — audit du dépôt et proposition (phase 1, #1943)

> Document de conception. Les résultats mesurés sont dans `docs/poc-dns-adblock-tv-results.md`.
> Règle de langage : on mesure la **réduction des domaines publicitaires/tracking résolus par DNS**. Une publicité intégrée au flux vidéo
> n'est pas visible du DNS : le POC le **démontre**, il ne le prétend pas.

## 1. Architecture actuelle (relevée le 2026-10-03)

| Élément | État |
|---|---|
| Résolveur des clients LAN | **Unbound** (gk2 : 1.17 ; Debian 13 : 1.22), écoute `192.168.1.200` (+ ULA/IPv6 depuis #1938), `access-control 192.168.0.0/16`. |
| Puits DNS de production | `secubox-ad-guard` + `secubox-adblock-sync` : compile les listes (EasyList/OISD/HaGeZi…) et écrit `95-secubox-adblock.conf` = **658 316** `local-zone … always_nxdomain`. |
| Exemptions | `secubox-adblock-sync` exempte des IP par **vue** Unbound (`sbx-allow`). *(Voir §5 : cette exemption ne fonctionne pas telle qu'écrite.)* |
| Autres briques DNS | `secubox-dns` (zones BIND d'autorité), `secubox-dns-guard` (anomalies, blocage dnsmasq), `secubox-vortex-dns` (RPZ + flux de menaces), `secubox-dns-provider`. |
| DHCP/DNS des clients | La Freebox distribue **gk2 comme DNS en IPv4**, mais son DNS **IPv6** (`fd0f:ee:b0::1`) passe avant : contournement réel constaté (#1938). |
| Journal des requêtes | **Absent** : Unbound n'a pas `log-queries` ; `ad-guard` reçoit ses détections de la toolbox (couche HTTP), pas du DNS. |
| Modèle de données `ad-guard` | `AdCategory` (advertising, tracking, analytics, telemetry, social, malware, cryptominer), `DeviceType.SMART_TV`, `BlockAction.MONITOR` (= OBSERVE), tables SQLite `detections`, `devices`, `device_domains`, rétention 30 j. |
| Conventions | `packages/secubox-<m>/{api,www,debian}`, socket Unix, `require_jwt`/`require_lecture`, sudoers à arguments exacts + contrôleur root (`secubox-adblock-sync`), SPDX CMSD-1.0, version montée à chaque livraison. Le module est servi **dans l'agrégateur** (chargement `sbx_pkg_*`) : sous-modules en import relatif. |

## 2. Composants réutilisables
- `ad-guard` : catégories, type d'appareil Smart TV, action MONITOR, base SQLite, UI (`www/ad-guard`), tâche périodique de nettoyage, patron « API → sudo → contrôleur root ».
- Unbound : **vues par client** (`access-control-view`) et zones locales ; journalisation native (`log-queries`, `log-replies`, `log-local-actions`).
- `secubox-dhcp-probe` (#1935) : sonde DHCP en lecture seule, utile au diagnostic de chemin DNS.

## 3. Composants manquants (construits par ce POC, dans `secubox-ad-guard` 1.2.0)
1. **Source DNS réelle** : analyseur du journal d'Unbound → compteurs par jour / appareil / domaine / décision (`ALLOWED`, `BLOCKED`, `UPSTREAM_ERROR`).
2. **Modes par appareil** OBSERVE / BLOCK / off, **dynamiques**, par vue Unbound — sans toucher au puits de production ni aux autres clients.
3. **DNS PATH TEST** : sonde unique → la box l'a-t-elle reçue ? ; détection des appareils « silencieux » côté DNS.
4. Listes de test **versionnées** (`lists/` + `MANIFEST.json`) et validation ; liste personnalisée de l'exploitant.
5. Outils : client de test DNS, **banc local des limites A–G** (vrai Unbound), procédure A/B/C sur appareil réel.

## 4. Implémentation minimale retenue
```
Appareil (Freebox TV) ── DNS ──► Unbound ──┬─ vue sbx-tv-observe : tout résolu, journalisé
                                            ├─ vue sbx-tv-block   : listes du POC → NXDOMAIN
                                            └─ autres clients     : puits de production, inchangé
                                  journal ──► secubox-adguard-dnsfeed ──► compteurs SQLite ──► API /adblock-tv/* ──► onglet « DNS AdBlock TV »
```
- État (appareils, modes) : `/var/lib/secubox/ad-guard/dnstv/etat.json`, écrit par l'API, **revalidé** par le contrôleur root.
- Configuration Unbound : un seul drop-in `94-secubox-adguard-tv.conf` (généré) ; le retirer remet tout en l'état.
- Inactif par défaut ; aucun démon du POC n'est activé à l'installation.
- Pas de MITM, pas de cookie, pas d'URL : un nom de domaine, une adresse, une décision, un compteur.

## 5. Trouvaille hors périmètre : l'exemption par vue VIDE ne marche pas
Mesuré avec Unbound 1.22 sur un banc local : un client rattaché à une vue **sans zone** reste bloqué par les zones globales, que `view-first` soit
`yes` ou `no`. Une vue qui contient une zone transparente couvrant tout (`local-zone: "." transparent`) exempte réellement. Le POC l'applique pour
ses vues. `secubox-adblock-sync` (allowlist d'IP) est dans le cas fautif — **non modifié ici** (comportement de production), à traiter à part ; à vérifier
aussi sur Unbound 1.17 (gk2).

## 6. Où placer la SecuBox, et faire utiliser son DNS aux appareils (phase 6)
La SecuBox est un **résolveur**, pas la passerelle : aucun routage n'est nécessaire.
1. **DNS distribué par DHCP** : Freebox OS → DHCP → « Serveur DNS 1 » = IP de la box (déjà `192.168.1.200` sur ce réseau). Vérifier avec `secubox-dhcp-probe -i <interface> --attendu <IP box>`.
2. **IPv6** : la Freebox annonce son propre résolveur IPv6 ; un appareil qui l'utilise **contourne** la box (#1938). Désactiver l'IPv6 sur l'appareil, ou ne comparer que le trafic IPv4.
3. **Adresse fixe** : donner à chaque Freebox TV un bail statique (Freebox OS → DHCP → Baux statiques) pour la repérer de façon stable.
4. **Vérifier que les requêtes arrivent** : *DNS PATH TEST* (onglet, ou `POST /adblock-tv/sonde` puis `GET /adblock-tv/path-test?nom=…`). Si la box ne voit rien, l'appareil utilise un autre résolveur.
5. **Compteurs « par appareil »** : la Freebox ne masque pas les clients qui interrogent **directement** gk2 en LAN ; la source vue par Unbound est leur adresse réelle. Les requêtes relayées par la Freebox apparaîtraient sous `192.168.1.254` (à constater sur le banc).

## 7. Procédure sur un vrai appareil (2 Freebox TV disponibles)
```
# 1. déclarer l'appareil et vérifier le chemin DNS (onglet « DNS AdBlock TV », ou API)
# 2. phase A : la TV avec son DNS habituel — on ne note que le fonctionnement
tv-before-after.py debut A --ip 192.168.1.50 ;  … 5 à 10 min d'usage … ;  tv-before-after.py fin A --note "…"
# 3. phase B : OBSERVE   4. phase C : BLOCK  (mêmes usages à chaque fois)
tv-before-after.py debut B --ip 192.168.1.50 ;  …  ;  tv-before-after.py fin B --note "…"
tv-before-after.py debut C --ip 192.168.1.50 ;  …  ;  tv-before-after.py fin C --note "ce qui ne marche plus : …"
tv-before-after.py rapport          # écrit reports/tv-before-after.md
```
La phase A n'est pas mesurable côté box (la TV n'utilise pas son DNS) : c'est volontaire, elle sert de **référence fonctionnelle**.

## 8. Apprentissage différentiel des domaines publicitaires / pistage / consentement (ajout du 2026-10-03)
Idée de l'exploitant : ne garder que le **flux vidéo par défaut** et bloquer le reste autour. Mise en œuvre mesurée, en deux phases OBSERVE :
- **E (essentiel)** : la TV lit seulement son flux vidéo par défaut, sans coupure publicitaire ni bandeau cookies.
- **P (pubs)** : mêmes usages, en laissant passer les coupures publicitaires et les bandeaux de consentement.
```
tv-before-after.py debut E --ip 192.168.1.50 ;  … ;  tv-before-after.py fin E --note "flux par défaut seul"
tv-before-after.py debut P --ip 192.168.1.50 ;  … ;  tv-before-after.py fin P --note "avec coupures pub et bandeaux"
tv-before-after.py apprendre E P                 # domaines vus en P et JAMAIS en E
tv-before-after.py apprendre E P --appliquer     # → liste personnalisée ; puis phase C (BLOCK) et contrôle sur la TV
```
**Ce que cela peut et ne peut pas faire** — c'est exactement la frontière des cas A–G du banc :
- une publicité servie par un **domaine distinct** du flux (A, B) apparaît dans la différence : bloquable ;
- une publicité servie par le **même domaine** que la vidéo (C) ou **insérée dans le flux** (D) n'apparaît **pas** : aucun candidat n'est inventé ;
- un domaine **partagé** entre contenu et publicité (G) apparaît s'il n'est pas dans le flux de base, mais peut casser un service : à vérifier phase C ;
- mettre en liste blanche « seul le flux par défaut passe » (refus par défaut de tout le reste) est une **étape ultérieure**, plus risquée (elle peut couper les mises à jour,
  l'heure, les services de la Freebox) ; elle n'est pas implémentée : elle suppose d'abord un apprentissage complet de ce qui est nécessaire.
Pistes ensuite : une catégorie `consent` dans les listes (bandeaux cookies/consentement), et l'apprentissage continu par appareil.
