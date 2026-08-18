---
id: communication.webmail.ouvrir
title: Ouvrir le webmail
module: secubox-mail
level: debutant
duration: 2m
statut: verifie
canonical: ../fiches/communication/ouvrir-le-webmail.md
source:
  package: packages/secubox-mail/
  service: secubox-mail.service
  api: GET /api/v1/mail/status
  web_route: https://webmail.<domaine>/
---
<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->


# Ouvrir le webmail

## Étapes
1. Depuis le tableau de bord, ouvrir **Webmail**.
2. Saisir l'adresse de courriel complète, par exemple `prenom@exemple.fr`, et le mot de passe.
3. Vérifier que la boîte de réception s'affiche.

## Point important
L'identifiant du webmail est l'adresse de courriel complète, domaine compris.

## Source technique
`packages/secubox-mail/` · `secubox-mail.service` · `GET /api/v1/mail/status` · `https://webmail.<domaine>/`
