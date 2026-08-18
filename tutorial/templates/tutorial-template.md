---
# ── Fiche source. C'est CE bloc que la Content Factory consomme. ──────────
# Le corps Markdown en dessous est la version « article » ; tous les autres
# formats (mémo, diaporama, vidéo, aide contextuelle, FAQ) se dérivent d'ici.
id: communication.webmail.login          # <domaine>.<module>.<action>
title: Se connecter au Webmail
module: secubox-mail                      # tel qu'il figure au catalogue
category: communication
level: debutant                           # debutant|intermediaire|avance|admin
duration: 2m
role: utilisateur                         # utilisateur|administrateur

prerequisites:
  - id: getting-started.compte
    label: Disposer d'un compte SecuBox

steps:
  - action: Ouvrir l'adresse du webmail dans le navigateur.
    expected_result: La page de connexion SecuBox Webmail s'affiche.
  - action: Saisir son identifiant et son mot de passe.
    expected_result: La boîte de réception s'ouvre.

success_criteria: La liste des messages reçus s'affiche.

troubleshooting:
  - symptom: Mot de passe refusé
    cause: Identifiant saisi sans le domaine
    fix: Saisir l'adresse complète, par exemple `prenom@exemple.fr`.

next:
  - communication.webmail.envoyer

# Ce qui permet de VÉRIFIER la fiche contre le code. Sans ces lignes, une fiche
# fausse est indiscernable d'une fiche juste.
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


# Se connecter au Webmail

## Objectif

Lire et écrire ses courriels depuis un navigateur, sans rien installer.

## Temps nécessaire

2 minutes.

## Niveau

Débutant.

## Avant de commencer

- Un compte SecuBox — celui qu'on vous a remis.
- L'adresse de votre webmail. Elle ressemble à `webmail.exemple.fr`.

## Étapes

### 1. Ouvrir le webmail

Saisissez l'adresse du webmail dans la barre du navigateur.

→ *La page de connexion s'affiche, avec le titre **SecuBox Webmail**.*

### 2. Saisir vos identifiants

Entrez votre identifiant et votre mot de passe, puis validez.

→ *Votre boîte de réception s'ouvre.*

## Ça marche si…

Vous voyez la liste de vos messages reçus.

## Si ça ne marche pas

| Ce que vous voyez | Ce qui se passe | Quoi faire |
|---|---|---|
| « Mot de passe refusé » | L'identifiant est incomplet | Saisir l'adresse entière, `prenom@exemple.fr` |
| La page ne s'ouvre pas | L'adresse est mal orthographiée | Vérifier l'adresse auprès de votre administrateur |
| La page s'ouvre puis reste vide | La boîte est vide, ou le chargement est lent | Patienter, puis recharger |

## À retenir

1. Le webmail s'ouvre dans un navigateur, sans installation.
2. L'identifiant est une **adresse complète**, avec le domaine.
3. C'est le même compte que vos autres services SecuBox.

## Pour aller plus loin

- [Envoyer un courriel](./envoyer.md)

---

**Source technique** — pour vérifier cette fiche contre le code :

```text
package:   packages/secubox-mail/
service:   secubox-mail.service
api:       GET /api/v1/mail/status
web:       https://webmail.<domaine>/
```

<!--
COMMENT SE SERVIR DE CE MODÈLE

1. Copier ce fichier dans tutorial/fiches/<categorie>/<nom>.md
2. Remplir l'en-tête YAML AVANT d'écrire le corps. C'est lui qui sera lu par
   la Content Factory ; le corps n'est qu'un des formats produits.
3. Vérifier chaque affirmation technique DANS LE DÉPÔT. Ce qui n'est pas
   vérifiable s'écrit `À documenter`, jamais une valeur plausible.
4. 5 à 8 étapes. Au-delà, c'est deux tutoriels.
5. Une étape = une action + son résultat visible. Sans le résultat attendu,
   le lecteur ne sait pas s'il peut continuer.
6. Le tableau « Si ça ne marche pas » part de CE QUE L'UTILISATEUR VOIT, jamais
   de la cause technique : il ne connaît que le symptôme.
-->
