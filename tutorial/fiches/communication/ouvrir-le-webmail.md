---
id: communication.webmail.ouvrir
title: Ouvrir le webmail
module: secubox-mail
category: communication
level: debutant
duration: 2m
role: utilisateur
statut: verifie
prerequisites:
  - id: getting-started.premiere-connexion
    label: Être connecté à la SecuBox
steps:
  - action: Ouvrir l'application Webmail depuis le tableau de bord.
    expected_result: La page de connexion du webmail s'affiche.
  - action: Saisir son adresse de courriel COMPLÈTE et son mot de passe.
    expected_result: La boîte de réception s'ouvre.
success_criteria: La liste de vos messages reçus s'affiche.
troubleshooting:
  - symptom: Mot de passe refusé
    cause: Identifiant saisi sans le domaine
    fix: Saisir l'adresse entière, par exemple prenom@exemple.fr
  - symptom: La page reste blanche
    cause: Le service met du temps à répondre
    fix: Patienter quelques secondes puis recharger.
  - symptom: « Service indisponible »
    cause: Le service de messagerie ne tourne pas
    fix: Signaler l'heure à l'administrateur.
next:
  - communication.webmail.envoyer
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

## Objectif

Accéder à sa messagerie depuis un navigateur, sans rien installer.

## Temps nécessaire

2 minutes.

## Niveau

Débutant.

## Avant de commencer

- Être connecté à la SecuBox.
- Connaître son **adresse de courriel complète**, par exemple
  `prenom@exemple.fr`.

## Étapes

### 1. Ouvrir l'application Webmail

Depuis le tableau de bord, ouvrez **Webmail**.

→ *Une page de connexion s'affiche, intitulée **SecuBox Webmail**.*

### 2. Se connecter avec l'adresse complète

Saisissez votre **adresse entière** — pas seulement la partie avant l'arobase —
puis votre mot de passe.

→ *Votre boîte de réception s'ouvre.*

> **C'est le piège le plus fréquent.** Saisir `prenom` au lieu de
> `prenom@exemple.fr` fait échouer la connexion sans que le message d'erreur ne
> l'explique.

## Ça marche si…

Vous voyez la liste de vos messages reçus.

## Si ça ne marche pas

| Ce que vous voyez | Ce qui se passe | Quoi faire |
|---|---|---|
| « Mot de passe refusé » | L'identifiant est incomplet | Saisir l'adresse entière, avec le domaine |
| Page blanche | Le service est lent à répondre | Patienter, puis recharger |
| « Service indisponible » | Le service ne tourne pas | Signaler l'heure à l'administrateur |

## À retenir

1. Le webmail s'ouvre dans le navigateur, sans installation.
2. L'identifiant est l'**adresse complète**, avec le domaine.
3. En cas de refus, c'est presque toujours le domaine qui manque.

## Pour aller plus loin

- [Envoyer un courriel](envoyer-un-courriel.md)

---

**Source technique**

```text
package:  packages/secubox-mail/
service:  secubox-mail.service
api:      GET /api/v1/mail/status
web:      https://webmail.<domaine>/
```
