<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Roadmap SecuBox-DEB

État du projet au **31 octobre 2026**. Roadmap sans échéances contractuelles : elle distingue les fonctions réellement livrées, celles intégrées mais encore à consolider, et les travaux restant à réaliser. Une présence dans le dépôt ne signifie pas qu'une fonction est validée sur toutes les plateformes.

## État réel du projet

| Repère | État |
|---|---|
| Version de développement publiée | **v3.0.0-alpha.19**, pré-version du 27 octobre 2026 |
| Système de base | **Debian 13 Trixie** ; Bookworm n'est plus la base de développement |
| Architecture | ARM64 et amd64 |
| Dépôt de paquets | `apt.secubox.in`, suite Trixie |
| Contenu | Environ 190 paquets et méta-paquets, selon le périmètre compté |
| Maturité | Prototype fonctionnel et utilisé sur plusieurs nœuds ; pas une version stable certifiée |

**Parc de référence documenté dans alpha.19 : quatre box en service sur trois types de matériel** : deux MOCHAbin Armada 7040, un PC x86 et un Raspberry Pi 400. Les tests et retours sur ESPRESSObin complètent cette base matérielle.

## Livré et utilisable

| Domaine | Réalisations attestées |
|---|---|
| Système | Debian 13 Trixie, paquets APT, profils d'installation, images et chaîne CI/CD |
| Pare-feu | nftables avec politique restrictive, gestion des règles et fonctions réseau |
| Protection web | WAF **SBX WAF / sbxwaf**, intégré au frontal HAProxy TLS |
| DNS | Unbound, DNS local, filtrage DNS et ad-guard selon profil |
| Accès distant | WireGuard, enrôlement par QR et maillage entre nœuds |
| Réseau MOCHAbin | Mode routeur persistant, bridge LAN, DHCP, DNS, NAT, pare-feu, isolement de ports et retour arrière temporisé |
| Supervision réseau | Panneau Réseau : WAN, LAN, switch, clients, NAC, tunnels, conteneurs et maillage |
| Interface | Dashboard et Hall v2, vue maître, accès rapide et applications |
| Services hébergés | LXC et services activables par profil : fichiers, mail, partage SMB, visio, podcast et autres services présents dans les images |
| Exploitation | Sauvegardes sous /data, watchdogs, gestion mémoire et mécanismes de cycle de vie |
| Démarrage et déploiement | Images ARM et amd64, Live USB amd64, VM VirtualBox/QEMU, installateur amd64 ; netboot et flash eMMC sur les cibles documentées |

Les fonctions disponibles dépendent du profil, de la plateforme, de la mémoire et de l'image publiée. Consulter les notes de version et la matrice matérielle avant tout déploiement.

## Plateformes et modes de déploiement

| Cible | Niveau documenté | Usage / réserve |
|---|---|---|
| MOCHAbin Armada 7040, 4 ou 8 Go | Testée, en service | Plateforme de référence pour les fonctions réseau avancées et les profils plus complets |
| ESPRESSObin v7 / Ultra, 1 ou 2 Go | Testée | Profils adaptés aux ressources ; le profil minimal 1 Go exclut notamment les composants trop lourds |
| Raspberry Pi 4 / 400 | Images et tests documentés | Nœud, passerelle ou usage de démonstration selon profil et interfaces réseau |
| PC amd64 physique | Live et installation permanente documentés | Réemploi de PC, mini-PC et machines x86-64 compatibles |
| VirtualBox / QEMU | Parcours de test documenté | Démonstration, validation et développement |
| ClearFog, NanoPi, Banana Pi et autres cartes | Selon portage | Ne pas les présenter comme supportées tant que le port et les tests ne sont pas validés |

### Live USB et installation

- **Live USB amd64** : démarrage de SecuBox depuis une clé USB sur un PC compatible, pour découvrir et tester sans installer immédiatement sur le disque interne.
- **Installation amd64** : installateur et parcours d'installation permanente disponibles dans les artefacts de release.
- **Virtualisation** : lancement facilité sous VirtualBox ; QEMU est documenté, y compris pour l'émulation ARM64.
- **ARM** : images dédiées et procédures propres aux cartes, bootloaders et supports de stockage.

La persistance des données, la compatibilité matérielle et les fonctions disponibles doivent être vérifiées pour chaque image Live. Le Live USB n'est pas à assimiler automatiquement à une installation permanente.

## Intégré, mais à consolider

| Sujet | Situation réelle | Travail restant |
|---|---|---|
| Agrégateur FastAPI | Service central présent ; montage progressif des modules, relais vers sockets dédiées, watchdog et états de santé | Réduire les pointes mémoire/CPU, fiabiliser le démarrage sous charge et poursuivre la migration module par module |
| Profils mémoire | Profils `minimal`, `lite`, `isp`, `full` disponibles dans le projet | Mesures reproductibles par plateforme, seuils de charge et documentation des compromis |
| DPI / nDPI | Moteur et intégration présents dans la chaîne ; classification en cours de validation | Réduire la consommation, améliorer l'étiquetage et la qualité des observations ; une classification n'est pas une preuve d'attaque |
| Auto-provisioning | Briques d'auto-chargement et d'association de nœuds présentes | Reprendre les cas de premier démarrage, de récupération d'installation et de fin de provisioning |
| Maillage | Association WireGuard et relais entre nœuds opérationnels dans le périmètre documenté | Étendre et tester les scénarios inter-LAN et les politiques de zones |
| Netboot / flash | Outils serveur, publication, déclencheurs, overlay et flash eMMC présents dans le dépôt | Validation complète par carte, tests de récupération et sécurisation du cycle A/B avant généralisation |
| Services applicatifs | Plusieurs services sont intégrés et empaquetés | Vérifier chaque service sur chaque profil ; corriger les écarts de ressources et de compatibilité Python/Debian |

### Points de vigilance connus

- La consommation CPU et mémoire reste élevée sur MOCHAbin et Raspberry Pi 400 dans certains scénarios.
- Le service de métriques a été identifié comme consommateur mémoire important dans les notes alpha.19.
- Les listes DNS RPZ ont été mesurées mais ne sont pas considérées comme livrées dans alpha.19 en raison de leur surcoût mémoire.
- Le premier démarrage du Raspberry Pi 400, la reprise d'anciennes installations et certains parcours de provisioning restent à reprendre.
- Une pré-version alpha ne doit pas être installée sans précaution sur la connexion principale d'un foyer ou d'une organisation.

## Priorités de développement

### P0 — Fiabilité et sobriété

1. Réduire la consommation mémoire et CPU de l'agrégateur, des métriques et des services lourds.
2. Stabiliser les profils, notamment le profil minimal 1 Go et les profils adaptés aux petites cartes.
3. Rendre les démarrages, redémarrages, mises à jour et retours arrière prévisibles.
4. Établir une matrice de tests reproductibles sur MOCHAbin, ESPRESSObin, Raspberry Pi et amd64.
5. Améliorer les sauvegardes, la restauration et la validation de l'état après mise à jour.

### P1 — Réseau fédéré et administration

1. Finaliser les scénarios de réseau inter-LAN et les zones NAC en réseau routé.
2. Consolider l'association automatique, le relais et la supervision des nœuds WireGuard.
3. Finaliser les parcours de provisioning et de récupération des box.
4. Poursuivre le pilotage centralisé du parc avec des états signés et vérifiables.
5. Renforcer l'observabilité réseau et la corrélation des événements sans confondre signal technique et preuve d'incident.

### P2 — Détection et protection

1. Continuer l'amélioration de SBX WAF, de ses règles, de ses modes de détection et de ses journaux.
2. Consolider le pipeline DPI/nDPI et la classification des destinations.
3. Poursuivre l'analyse comportementale, la mémoire des acteurs et la corrélation temporelle lorsque les ressources le permettent.
4. Documenter les limites, faux positifs, modes d'observation et conditions d'activation de chaque protection.

### P3 — Sécurité matérielle et chaîne de confiance

1. Étudier l'intégration de clés cryptographiques matérielles, dont Nitrokey, pour les usages compatibles.
2. Définir les parcours de gestion des identités, clés GPG/OpenPGP, signatures et authentification forte.
3. Renforcer la chaîne de publication, de vérification des images et de mise à jour.
4. Préparer un dossier de sécurité structuré et des tests indépendants.

**Nitrokey, SBX-Key et les fonctions cryptographiques associées sont des axes d'intégration, pas des fonctions à déclarer déjà opérationnelles sans validation du modèle de clé et des parcours logiciels.**

## Extensions matérielles et offres à qualifier

Ces éléments relèvent de la configuration commerciale ou de travaux d'intégration ; ils ne changent pas le statut logiciel des plateformes :

- Extensions SSD selon interface et capacité.
- Écrans LCD externes pour supervision locale.
- Clé cryptographique Nitrokey et configuration associée.
- Configurations amd64 sur mini-PC, PC recyclés et serveurs compatibles.
- Clé USB SecuBox Live pour découverte et tests.
- Matériel et intégrations sur mesure, sur devis.
- Offres de licensing pour entreprises, intégrateurs, collectivités et partenaires, selon périmètre contractuel.

Les options SSD, LCD et Nitrokey doivent être qualifiées par plateforme. Elles ne sont pas supposées incluses dans les configurations de base.

## Portages matériels : wishlist

Les portages suivants restent conditionnés à la disponibilité du matériel, à un sponsor et à des tests réels : MACCHIATObin, HoneyComb LX2K, Banana Pi BPI-R4, NanoPi R6S, NanoPC-T6 et Traverse Ten64. Le Raspberry Pi 5 doit également faire l'objet d'une validation dédiée avant d'être annoncé comme supporté.

## Certification et assurance sécurité

- La préparation d'un dossier de sécurité et la documentation des exigences peuvent progresser en parallèle du développement.
- Les tests de couverture, la revue cryptographique et l'audit externe restent à mener ou à compléter.
- **La certification ANSSI CSPN n'est pas obtenue.** Une éventuelle évaluation et une soumission ne pourront être annoncées qu'après définition du périmètre, audit et validation par les organismes compétents.

## Écosystème et modèle économique

SecuBox constitue le socle technique de l'écosystème Gondwana, aux côtés d'**AletheiaVox**. La feuille de route logicielle reste distincte de la feuille de route commerciale.

Les voies commerciales envisagées comprennent l'achat de box, la location, les abonnements de services et de maintenance, les configurations sur mesure sur devis et les offres de licensing. La première tranche de financement envisagée pour le projet est de **80 000 €** ; la campagne est en préparation et n'est pas ouverte. Ces éléments sont des orientations de financement et d'offre, pas des fonctionnalités déjà livrées.

## Règles de mise à jour de cette roadmap

- Une fonction passe en « livré » après intégration, tests identifiables et documentation suffisante.
- Une fonction présente dans le dépôt mais non validée sur le matériel reste « en consolidation » ou « expérimentale ».
- Les souhaits, portages sponsorisés et pistes de recherche restent dans la wishlist.
- Les numéros de version et dates doivent suivre les releases réellement publiées.
- Les notes de version priment pour le détail d'une release ; la matrice matérielle prime pour le statut de support d'une carte.

Références : [Releases](https://github.com/CyberMind-FR/secubox-deb/releases) · [README](https://github.com/CyberMind-FR/secubox-deb) · [Hardware Matrix](https://github.com/CyberMind-FR/secubox-deb/wiki/Hardware-Matrix) · [Notes alpha.19](https://github.com/CyberMind-FR/secubox-deb/blob/master/docs/release-notes/v3.0.0-alpha.19.md)

---

*Dernière mise à jour : 2026-10-31*
