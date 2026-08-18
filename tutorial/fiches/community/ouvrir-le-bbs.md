---
id: community.bbs.ouvrir
title: Ouvrir le BBS et lire un salon
module: secubox-bbs
category: community
level: debutant
duration: 4m
role: utilisateur
statut: verifie
prerequisites:
  - id: getting-started.premiere-connexion
    label: Être connecté à la SecuBox
steps:
  - action: Ouvrir l'application BBS depuis le tableau de bord.
    expected_result: La liste des salons s'affiche.
  - action: Ouvrir un salon.
    expected_result: Les fils de discussion du salon s'affichent.
  - action: Ouvrir un fil.
    expected_result: Les messages s'affichent, du plus ancien au plus récent.
success_criteria: Vous lisez une discussion entière.
troubleshooting:
  - symptom: Un salon est vide
    cause: Personne n'y a encore écrit
    fix: C'est normal sur un BBS récent.
  - symptom: Certains fils ne sont pas visibles
    cause: Ils sont en visibilité « locale » — réservés aux membres connectés
    fix: Se connecter avec son compte BBS.
next:
  - community.bbs.poster
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

## Objectif

Lire les discussions de votre communauté.

## Temps nécessaire

4 minutes.

## Niveau

Débutant.

## Un mot sur le BBS

Un **BBS** est un forum : des **salons** par thème, des **fils** de discussion
dans chaque salon, et des **messages** dans chaque fil.

C'est le plus ancien format de discussion en ligne, et l'un des plus lisibles :
tout est rangé, rien ne défile.

## Étapes

### 1. Ouvrir le BBS

Depuis le tableau de bord, ouvrez **BBS**.

→ *La liste des salons s'affiche.*

### 2. Entrer dans un salon

Cliquez sur celui qui vous intéresse.

→ *Vous voyez les fils de discussion, les plus récents d'abord.*

### 3. Ouvrir un fil

Cliquez sur un titre.

→ *Les messages s'affichent dans l'ordre, du plus ancien au plus récent.*

## Public ou local

Chaque fil est **public** ou **local**.

- **Local** : lisible seulement par les membres connectés.
- **Public** : lisible par tout le monde, y compris hors de la SecuBox.

Si vous ne voyez pas un fil dont on vous a parlé, il est probablement local et
vous n'êtes pas connecté.

## Ça marche si…

Vous lisez une discussion du début à la fin.

## Si ça ne marche pas

| Ce que vous voyez | Ce qui se passe | Quoi faire |
|---|---|---|
| Un salon vide | Personne n'y a écrit | Normal sur un BBS récent |
| Un fil annoncé reste invisible | Il est en visibilité locale | Se connecter avec son compte BBS |

## À retenir

1. Salons → fils → messages.
2. Un fil est public ou local.
3. Ce qui est local demande d'être connecté.

## Pour aller plus loin

- Poster un message — `À documenter`

---

**Source technique**

```text
package:  packages/secubox-bbs/
api:      GET /api/v1/bbs/threads
web:      https://bbs.<domaine>/
schema:   threads.visibility, posts.visibility  ('local' | 'public')
```
