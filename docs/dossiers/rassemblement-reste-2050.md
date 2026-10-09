<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# #2050 — ce qui reste du rassemblement : propositions (2026-10-08)

État de départ : vagues 0 à 3 faites et déployées sur gk2 (N2 et 3r le 2026-10-08), `surf` et `mesh` sur socket Unix. Ce document ne code rien :
il décrit trois chantiers, ce qu'on a constaté sur la box, et une recommandation à valider avant toute modification.

## D3 / D4 — listes de blocage DNS

**Constaté sur gk2 (lecture seule) :**
- **Un seul moteur vivant : Unbound** (actif). `dnsmasq` est inactif ; seul `dns-guard` (inactif lui aussi) le vise pour bloquer.
- Quatre fichiers de listes dans `/etc/unbound/unbound.conf.d/`, de trois auteurs différents :
  `95-secubox-adblock.conf` (ad-guard, 657 374 domaines), `93-secubox-webfilter.conf` (webfilter, 426 926), `94-secubox-adguard-tv.conf` (ad-guard TV, 39)
  et des fichiers statiques (`60-noms`, `96-*`, `97-*`, `98-lxc`…).
- **Les listes sont complémentaires, pas redondantes** : seulement 1 614 domaines en commun entre adblock et webfilter (1 082 693 au total).
  Fusionner les *données* n'apporterait rien ; la redondance est dans le *code* (chacun rend son fichier, lance son `checkconf` et son `reload`).
- `vortex-dns` est actif mais son flux RPZ n'est branché à rien (aucun fichier RPZ côté Unbound) : un pipeline dormant.

**Décisions du propriétaire (2026-10-08) : « go » aux recommandations ; `vortex-dns` : RETIRER. Faits : D3, D4 pour webfilter et dns-lan, retrait de vortex-dns (voir HISTORY). Reste : adoption par ad-guard TV et adblock.**

**Recommandation.**
1. **D3 : un seul moteur, Unbound.** Retirer le chemin « blocage par dnsmasq » de `dns-guard` (la détection d'anomalies reste) ; `dnsmasq` n'est plus
   recommandé par `dns-guard` ni `vortex-dns`. Gain : une surface de moins, aucun comportement perdu sur la box (dnsmasq y est arrêté).
2. **D4 : une bibliothèque commune de rendu des vues Unbound** dans `secubox_core` (écriture atomique, `unbound-checkconf`, `reload`, retour arrière,
   ligne d'audit, verrou unique) utilisée par `webfilter`, `ad-guard` (adblock et TV), `vortex-dns` et `dns`. C'est la vraie fusion utile : un seul
   propriétaire de `unbound.conf.d`.
3. `vortex-dns` : soit on branche son RPZ via la bibliothèque (liste « menaces » à côté des listes « pubs » et « catégories »), soit on le retire.
   **À décider** : l'a-t-on voulu actif ?
4. Ne pas fusionner `webfilter`, `ad-guard`, `vortex-dns` en un paquet : trois familles de listes, trois usages, trois propriétaires fonctionnels.

**Risque** : un `reload` d'Unbound mal fait coupe la résolution de tout le réseau. Mesures : tests sur `unbound-checkconf` factice, déploiement
d'abord sur gk3, annonce de la coupure possible (règle « annoncer toute coupure DNS »).

## S7 — `waf` + `waf-ng`

**Constaté :**
- `waf` : API Python (≈ 2 100 lignes), pages, sudoers, unité `secubox-waf` (`User=secubox`, socket `/run/secubox/waf.sock`). `waf-ng` : le moteur Go `sbxwaf`
  (ban nft natif) et `actord`, unités `secubox-waf-ng` et `secubox-actord`.
- **Deux voies de ban cohabitent** : le Go pose ses bans nft lui-même ; l'API Python en a une deuxième (`_ban_ip` → `sudo wafctl ban`, auto-ban par sévérité).
  C'est une redondance de comportement, pas seulement de paquets.

**Recommandation (sans toucher au moteur).**
1. Regrouper les *paquets* : `waf-ng` absorbe `waf` comme composant (deux unités, deux processus, deux comptes conservés ; `waf` devient transitoire).
2. Traiter séparément (issue dédiée) la **voie de ban dupliquée** : décider laquelle fait foi (le Go, qui survit au redémarrage grâce au journal) et ramener l'API
   Python à une lecture.
3. Ordre : source → tests → un seul déploiement hors heures de pointe, avec `waf-ng` redémarré en dernier, et contrôle de `/proc/<pid>/cmdline`
   (le drop-in du leurre peut masquer un changement d'unité : voir le test de non-dérive, waf-ng 1.18.17).

**Constat sur la voie de ban dupliquée (2026-10-08).** Le ban automatique de l'API Python n'existe que dans `POST /check` (garde JWT), censé être appelé par HAProxy ;
aucun appelant dans le dépôt, aucun appel dans les journaux d'accès de gk2, et HAProxy route vers `sbxwaf` (127.0.0.1:8085). C'est du **code mort**, pas une voie concurrente
en service. Le bouton de bannissement manuel du tableau de bord (`wafctl ban`) est légitime et reste. Suite proposée, dans une issue séparée : retirer `/check` et
`_should_autoban`/`_check_rate_limit` de l'API Python, avec test de non-régression sur les routes du tableau de bord.

**Risque** : élevé (le WAF protège tout le trafic public ; une erreur coupe ou ouvre la box). **À ne faire qu'avec l'accord explicite du propriétaire.**

## M9 — démons Go (`bbs`, `radio`, `metanews`, `socialrelay`) — **ABANDONNÉ (décision du propriétaire, 2026-10-08)**

**Faits vérifiés (corrigeant une première lecture trop optimiste) :**
- `radio` et `metanews` ont des `vendor/` strictement identiques (même `modules.txt`, mêmes `go.mod` et `go.sum`, 1 569 fichiers communs).
- `socialrelay` NE l'est PAS : Go 1.25 là où les autres sont en 1.22, `golang.org/x/sys` v0.47.0 contre v0.19.0, `x/net` et `go-qrcode` en plus. `bbs` a son propre arbre (29 Mo).
- Le dépôt git stocke une seule fois les fichiers identiques (objets dédupliqués, 1,9 Go compressé) : les « 580 Mo dupliqués » sont dans la copie de travail et les checkouts de CI, pas dans le dépôt.
- Unifier demandait de monter `radio` et `metanews` aux versions de `socialrelay` (donc Go 1.25) : changement de build de deux services en production.

**Décision : abandon.** Gain faible (copie de travail, cohérence des mises à jour de dépendances), risque réel (build et déploiement de démons actifs). À rouvrir seulement
si une montée de dépendance de sécurité oblige à toucher les quatre vendors en même temps ; le partage du `vendor/` entre `radio` et `metanews` par un lien reste possible
(≈ 192 Mo de copie de travail) sans changer aucune dépendance.

## Hors cycle
- ~~Retirer les 52 paquets transitoires~~ : FAIT le 2026-10-09 (60 répertoires `Section: oldlibs` retirés des sources, un cycle après leur publication dans alpha.10 ; `gabriel-mood`, dans `sbxos-audio-mood`, est conservé : source mixte). Reste : générer les méta-paquets en vues (vague 5).
- WireGuard / Reality : reporté (privilèges et tunnels).
- `surf` tourne encore en root (dette notée ; un utilisateur dédié demande de valider le rendu Chromium).
