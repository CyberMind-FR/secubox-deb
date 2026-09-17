<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-ndpid-engine — le moteur DPI vivant

## Pourquoi ce paquet existe

`sbxdpi` (secubox-toolbox-ng) agrège des événements de flux et les sert au
tableau de bord. Il ne les PRODUIT pas : il les lit sur le socket distributeur
de `nDPIsrvd`.

Or ce socket n'a jamais existé sur la box. `nDPId` et `nDPIsrvd` n'y étaient pas
installés, et `ndpid` n'a **aucun candidat** dans les dépôts Debian — c'est un
projet séparé (github.com/utoni/nDPId) qui se compile.

Le paquet `secubox-ndpid` déclarait pourtant `Depends: ndpid | ndpi-reader`.
L'alternative était satisfaite par `ndpiReader`, l'outil de DÉMONSTRATION de
libndpi, qui écrit du CSV dans un fichier et ne parle à personne. La dépendance
était donc verte, et la chaîne morte : `sbxdpi` servait un instantané gelé —
`connected: false`, `total_flows` figé, `hosts` et `fingerprints` à zéro.

## Ce qu'il apporte

    nDPId ──(socket collecteur)──> nDPIsrvd ──(socket distributeur)──> sbxdpi

Les deux binaires, compilés avec **nDPI 6.1.0 liée statiquement**. La libndpi
4.2 du système n'est pas touchée : nDPId exige ≥ 5.0.0, et remplacer la lib
système casserait tout ce qui s'appuie dessus.

## Construire

La compilation est NATIVE, sur la box (arm64) :

    bash construire.sh

Elle produit le `.deb` dans `/data/build`. Compiler ailleurs demanderait une
chaîne croisée arm64 complète pour du C, plus une libndpi croisée — beaucoup de
machinerie pour un binaire qu'on ne rebâtit que lors d'une montée de version.
