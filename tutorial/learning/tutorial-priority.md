# Priorité des tutoriels

La priorité se déduit de **l'usage réel**, pas de la richesse technique d'un
module. Un module qui expose 46 routes d'API n'est pas prioritaire pour autant :
ce qui compte est le nombre de gens bloqués sans la fiche.

Critère retenu, dans cet ordre :

1. **Sans cette fiche, on ne peut rien faire du tout.**
2. On s'en sert toutes les semaines.
3. On s'en sert quand on a compris le reste.
4. On engage la machine.

---

## P0 — sans quoi rien n'est possible

Neuf fiches. C'est le minimum vital : quelqu'un qui reçoit une SecuBox et n'a
que ces neuf-là s'en sort.

| # | Tutoriel | Module | Pourquoi P0 |
|---|---|---|---|
| 1 | Première connexion | `secubox-auth` | Sans elle, rien d'autre n'est atteignable |
| 2 | Comprendre le tableau de bord | `secubox-hub` | Sinon on ne trouve aucune application |
| 3 | Trouver une application | `secubox-hub` | 138 modules ont une interface web |
| 4 | Ouvrir et se connecter au webmail | `secubox-mail` | Usage n°1 attendu |
| 5 | Envoyer un courriel | `secubox-mail` | Le geste qui justifie le webmail |
| 6 | Ouvrir Nextcloud | `secubox-nextcloud` | Usage n°2 attendu |
| 7 | Déposer et partager un fichier | `secubox-nextcloud` | Le geste qui justifie Nextcloud |
| 8 | Changer son mot de passe | `secubox-auth` | Premier réflexe de sécurité |
| 9 | Obtenir de l'aide | — | Sans quoi le premier blocage est définitif |

## P1 — usage courant

| Tutoriel | Module |
|---|---|
| Recevoir et lire son courrier | `secubox-mail` |
| Les contacts | `secubox-mail` |
| Ouvrir le BBS, lire un salon | `secubox-bbs` |
| Poster, répondre | `secubox-bbs` |
| Créer un dossier, télécharger | `secubox-nextcloud` |
| Regarder une vidéo | `secubox-peertube` |
| Écouter sa musique | `secubox-lyrion` |
| Se connecter de l'extérieur | `secubox-wireguard` |

## P2 — quand on a pris ses marques

| Tutoriel | Module |
|---|---|
| Synchroniser son ordinateur | `secubox-nextcloud` |
| Discuter en direct | `secubox-matrix` |
| Publier sur Mastodon, comprendre la fédération | `secubox-mastodon` |
| Publier une vidéo, un podcast | `secubox-peertube`, `secubox-podcaster` |
| Publier un billet, du BBS au public | `secubox-billets`, `secubox-bbs` |
| Double authentification | `secubox-auth` |
| Joindre un fichier sur le BBS | `secubox-bbs` |

## P3 — administration

| Tutoriel | Module |
|---|---|
| Créer un compte | `secubox-auth` |
| Installer un module | `secubox-hub` |
| Démarrer, arrêter, redémarrer un service | `secubox-system` |
| Publier un service sur internet | `secubox-haproxy` |
| Obtenir et renouveler un certificat | `secubox-haproxy` |
| Lire les journaux | `secubox-system` |
| Surveiller les ressources | `secubox-system-tuning` |
| Naviguer par Tor | `secubox-tor` |
| Ce que le pare-feu bloque | `secubox-crowdsec` |

---

## Les 20 premiers tutoriels à produire

Dans cet ordre. Les neuf premiers sont les P0 ci-dessus.

| Rang | Tutoriel | Vérifiable dans le dépôt |
|---|---|---|
| 1 | Première connexion | `packages/secubox-auth/` |
| 2 | Comprendre le tableau de bord | `packages/secubox-hub/` |
| 3 | Trouver une application | `packages/secubox-hub/` |
| 4 | Ouvrir le webmail | `packages/secubox-mail/` |
| 5 | Se connecter au webmail | `packages/secubox-mail/` |
| 6 | Envoyer un courriel | `packages/secubox-mail/` |
| 7 | Ouvrir Nextcloud | `packages/secubox-nextcloud/` |
| 8 | Déposer un fichier | `packages/secubox-nextcloud/` |
| 9 | Partager un fichier | `packages/secubox-nextcloud/` |
| 10 | Changer son mot de passe | `packages/secubox-auth/` |
| 11 | Obtenir de l'aide | — |
| 12 | Ouvrir le BBS | `packages/secubox-bbs/` |
| 13 | Lire un salon | `packages/secubox-bbs/` |
| 14 | Poster un message | `packages/secubox-bbs/` |
| 15 | Répondre à un message | `packages/secubox-bbs/` |
| 16 | Télécharger un fichier | `packages/secubox-nextcloud/` |
| 17 | Recevoir et lire son courrier | `packages/secubox-mail/` |
| 18 | Regarder une vidéo | `packages/secubox-peertube/` |
| 19 | Qu'est-ce qu'une SecuBox ? | — |
| 20 | Utilisateur ou administrateur ? | — |

**Aucune de ces vingt fiches ne sera rédigée sans vérification dans le dépôt.**
Les trois sans chemin (11, 19, 20) sont des fiches de concept : elles
n'affirment rien de technique et n'ont donc rien à vérifier.
