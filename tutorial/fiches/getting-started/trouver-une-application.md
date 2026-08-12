---
id: getting-started.trouver-une-application
title: Trouver une application
module: secubox-hub
category: getting-started
level: debutant
duration: 3m
role: utilisateur
statut: verifie
prerequisites:
  - id: getting-started.tableau-de-bord
    label: Savoir lire le tableau de bord
steps:
  - action: Parcourir la liste des applications du tableau de bord.
    expected_result: Chaque application porte un nom et une fonction.
  - action: Ouvrir celle qui correspond au besoin.
    expected_result: L'application s'ouvre.
success_criteria: Vous ouvrez l'application correspondant à ce que vous voulez faire.
troubleshooting:
  - symptom: Je ne sais pas laquelle choisir
    cause: Les noms de produits ne disent pas toujours la fonction
    fix: Se reporter au tableau « Je veux… » ci-dessous.
  - symptom: L'application que je cherche n'existe pas
    cause: Elle n'est pas installée sur cette SecuBox
    fix: Demander à l'administrateur si le module peut être ajouté.
next:
  - communication.webmail.ouvrir
source:
  package: packages/secubox-hub/
  catalog: tutorial/catalog/modules.md
---

# Trouver une application

## Objectif

Savoir quelle application ouvrir selon ce que vous voulez faire.

## Temps nécessaire

3 minutes.

## Niveau

Débutant.

## Le tableau qui répond à la question

Les noms de produits ne disent pas toujours leur fonction. Voici la traduction.

| Je veux… | J'ouvre | Nom du module |
|---|---|---|
| écrire ou lire un courriel | **Webmail** | `secubox-mail` |
| ranger, partager mes fichiers | **Nextcloud** | `secubox-nextcloud` |
| retrouver mes photos | **PhotoPrism** | `secubox-photoprism` |
| lire ou écrire sur le forum | **BBS** | `secubox-bbs` |
| discuter en direct | **Matrix** | `secubox-matrix` |
| publier vers l'extérieur | **Mastodon** | `secubox-mastodon` |
| regarder ou publier une vidéo | **PeerTube** | `secubox-peertube` |
| écouter ma musique | **Lyrion** | `secubox-lyrion` |
| ma médiathèque | **Jellyfin** | `secubox-jellyfin` |
| publier un podcast | **Podcaster** | `secubox-podcaster` |
| publier un billet | **Billets** | `secubox-billets` |

## Étapes

### 1. Identifier son besoin

Cherchez d'abord **ce que vous voulez faire**, pas le nom du produit.

### 2. Ouvrir depuis le tableau de bord

→ *L'application s'ouvre, sans nouvelle connexion.*

## Ça marche si…

Vous ouvrez du premier coup l'application correspondant à votre besoin.

## Si ça ne marche pas

| Ce que vous voyez | Quoi faire |
|---|---|
| Je ne sais pas laquelle choisir | Utiliser le tableau ci-dessus |
| Elle n'est pas dans la liste | Le module n'est pas installé — demander à l'administrateur |

## À retenir

1. Partez du besoin, pas du nom du produit.
2. Tout s'ouvre depuis le tableau de bord.
3. Ce qui n'est pas listé n'est pas installé.

## Pour aller plus loin

- [Ouvrir le webmail](../communication/ouvrir-le-webmail.md)
- Le [catalogue complet](../../catalog/modules.md) — 173 modules, vue technique

---

**Source technique**

```text
package:  packages/secubox-hub/
liste:    tutorial/catalog/modules.md  (généré depuis le dépôt)
```
