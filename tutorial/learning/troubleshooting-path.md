# Parcours dépannage

Classé par **ce que vous voyez**. Vous ne connaissez pas la cause — c'est
justement pourquoi vous êtes ici.

## Je ne peux pas me connecter

| Ce que vous voyez | Voir |
|---|---|
| « Mot de passe refusé » | `À documenter` |
| La page de connexion revient en boucle | `À documenter` |
| « Votre session a expiré » | `À documenter` |

## La page ne s'affiche pas

| Ce que vous voyez | Ce que ça veut dire | Voir |
|---|---|---|
| **403 Forbidden** | Le site existe mais n'a rien à montrer | `À documenter` |
| **404** | L'adresse ne correspond à rien | `À documenter` |
| **421 Requête mal aiguillée** | Le nom n'est pas routé | `À documenter` |
| **502 Service indisponible** | Le service derrière ne répond pas | `À documenter` |
| **504** | Le service met trop longtemps | `À documenter` |

> Les pages d'erreur 5xx de SecuBox expliquent déjà le contexte et l'état du
> service. Ces fiches doivent s'accorder avec elles plutôt que les répéter —
> deux explications différentes du même incident valent moins qu'une.

## Le site affiche le contenu d'un autre site

Cause connue et corrigée en 2026-08 : le domaine n'était pas déclaré, et le
serveur servait le premier site venu — en **200**, sans erreur.

Si cela se reproduit, c'est un défaut de publication, pas de votre côté.
Signalez-le : `À documenter` (procédure à écrire).

## Mon courriel ne part pas / n'arrive pas

`À documenter`

## Mon fichier ne se téléverse pas

`À documenter`

---

## Pourquoi tant de « À documenter »

Parce que ces fiches n'existent pas encore, et qu'annoncer un lien mort serait
pire que d'annoncer un manque. Le [rapport
d'audit](../AUDIT-DOCUMENTATION.md) chiffre cette dette.
