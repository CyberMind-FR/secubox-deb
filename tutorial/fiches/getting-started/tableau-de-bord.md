---
id: getting-started.tableau-de-bord
title: Comprendre le tableau de bord
module: secubox-hub
category: getting-started
level: debutant
duration: 5m
role: utilisateur
statut: verifie
prerequisites:
  - id: getting-started.premiere-connexion
    label: Être connecté
steps:
  - action: Observer la page d'accueil après connexion.
    expected_result: Les applications disponibles sont listées.
  - action: Cliquer sur une application.
    expected_result: L'application s'ouvre.
  - action: Revenir au tableau de bord.
    expected_result: On retrouve la liste.
success_criteria: Vous savez ouvrir une application et revenir en arrière.
troubleshooting:
  - symptom: Une application citée par un collègue n'apparaît pas
    cause: Elle n'est pas installée, ou votre compte n'y a pas accès
    fix: Demander à l'administrateur.
  - symptom: Une application affiche une erreur à l'ouverture
    cause: Le service correspondant ne tourne pas
    fix: Signaler l'application concernée et l'heure à l'administrateur.
next:
  - getting-started.trouver-une-application
source:
  package: packages/secubox-hub/
  web_route: /index.html
---

# Comprendre le tableau de bord

## Objectif

Savoir se repérer sur la page qui s'ouvre après la connexion.

## Temps nécessaire

5 minutes.

## Niveau

Débutant.

## Avant de commencer

Être connecté — voir [Première connexion](premiere-connexion.md).

## Étapes

### 1. Regarder ce qui est affiché

Le tableau de bord liste **les applications auxquelles votre compte a accès**.

→ *Vous ne voyez pas tout ce que la SecuBox contient : seulement ce qui vous
concerne. C'est normal.*

### 2. Ouvrir une application

Cliquez sur l'une d'elles.

→ *Elle s'ouvre. Vous n'avez pas à vous reconnecter : le compte est le même
partout.*

### 3. Revenir

Revenez au tableau de bord.

→ *Vous retrouvez la liste.*

## Ça marche si…

Vous savez ouvrir une application, puis revenir à la liste.

## Si ça ne marche pas

| Ce que vous voyez | Ce qui se passe | Quoi faire |
|---|---|---|
| Une application manque | Non installée, ou pas d'accès pour votre compte | Demander à l'administrateur |
| Une application affiche une erreur | Le service ne tourne pas | Signaler l'application et l'heure |
| La liste est vide | Aucun accès attribué | Demander à l'administrateur |

## À retenir

1. Le tableau de bord ne montre que ce à quoi vous avez accès.
2. Un seul compte pour toutes les applications.
3. C'est le point de retour quand on est perdu.

## Pour aller plus loin

- [Trouver une application](trouver-une-application.md)

---

**Source technique**

```text
package:  packages/secubox-hub/
web:      /index.html
```
