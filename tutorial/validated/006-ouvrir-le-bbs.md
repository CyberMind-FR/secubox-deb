---
id: community.bbs.ouvrir
title: Ouvrir le BBS et lire un salon
module: secubox-bbs
level: debutant
duration: 4m
statut: verifie
canonical: ../fiches/community/ouvrir-le-bbs.md
source:
  package: packages/secubox-bbs/
  api: GET /api/v1/bbs/threads
  web_route: https://bbs.<domaine>/
---
<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->


# Ouvrir le BBS et lire un salon

Un BBS organise la discussion en **salons → fils → messages**.

## Étapes
1. Ouvrir **BBS** depuis le tableau de bord.
2. Entrer dans un salon.
3. Ouvrir un fil et lire les messages dans l'ordre.

## Visibilité
- `local` : contenu réservé aux membres connectés.
- `public` : contenu lisible publiquement.

## Source technique
`packages/secubox-bbs/` · `GET /api/v1/bbs/threads` · `https://bbs.<domaine>/` · champs `threads.visibility` et `posts.visibility`.

Le tutoriel « Poster un message » reste `À documenter` tant qu'il n'est pas vérifié.
