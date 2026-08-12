---
id: getting-started.premiere-connexion
title: Première connexion
module: secubox-hub
category: getting-started
level: debutant
duration: 2m
role: utilisateur
statut: verifie
prerequisites:
  - id: getting-started.concept
    label: Savoir ce qu'est une SecuBox
steps:
  - action: Ouvrir l'adresse de la SecuBox dans le navigateur.
    expected_result: La page de connexion s'affiche.
  - action: Saisir son identifiant et son mot de passe.
    expected_result: Le tableau de bord s'ouvre.
success_criteria: Le tableau de bord affiche la liste de vos applications.
troubleshooting:
  - symptom: Mot de passe refusé
    cause: Erreur de saisie, ou majuscules actives
    fix: Ressaisir en vérifiant la touche Verr. Maj.
  - symptom: La page ne s'ouvre pas du tout
    cause: Adresse incorrecte, ou SecuBox injoignable depuis ce réseau
    fix: Vérifier l'adresse ; depuis l'extérieur, un accès distant est nécessaire.
  - symptom: On revient sans cesse à la page de connexion
    cause: Les cookies sont bloqués par le navigateur
    fix: Autoriser les cookies pour cette adresse.
next:
  - getting-started.tableau-de-bord
source:
  package: packages/secubox-hub/
  web_route: /login.html
  vhost: packages/secubox-hub/nginx/webui.conf
---

# Première connexion

## Objectif

Entrer dans votre SecuBox pour la première fois.

## Temps nécessaire

2 minutes.

## Niveau

Débutant.

## Avant de commencer

- L'**adresse** de votre SecuBox. Elle vous a été communiquée ; elle ressemble
  à `secubox.exemple.fr`.
- Vos **identifiants** : un nom d'utilisateur et un mot de passe.

## Étapes

### 1. Ouvrir l'adresse

Saisissez l'adresse de votre SecuBox dans la barre du navigateur.

→ *Une page de connexion s'affiche.*

### 2. Se connecter

Entrez votre identifiant et votre mot de passe, puis validez.

→ *Le tableau de bord s'ouvre : c'est votre point de départ pour tout le reste.*

## Ça marche si…

Vous voyez le tableau de bord, avec la liste de vos applications.

## Si ça ne marche pas

| Ce que vous voyez | Ce qui se passe | Quoi faire |
|---|---|---|
| « Mot de passe refusé » | Erreur de saisie | Vérifier la touche **Verr. Maj** et ressaisir |
| La page ne s'ouvre pas | Adresse erronée, ou SecuBox injoignable d'ici | Vérifier l'adresse ; de l'extérieur, il faut un accès distant |
| On revient toujours à la connexion | Le navigateur bloque les cookies | Autoriser les cookies pour cette adresse |

## À retenir

1. Une seule adresse donne accès à tout.
2. Un seul compte sert à toutes les applications.
3. Le tableau de bord est le point de départ.

## Pour aller plus loin

- [Comprendre le tableau de bord](tableau-de-bord.md)

---

**Source technique**

```text
package:  packages/secubox-hub/
web:      /login.html
vhost:    packages/secubox-hub/nginx/webui.conf  (listen 9080, default_server)
```
