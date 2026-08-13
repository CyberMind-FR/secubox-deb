# Parcours d'apprentissage

On n'apprend pas SecuBox module par module. On l'apprend **par ce qu'on veut
faire**.

Le catalogue range 173 modules ; personne ne commence par là. Ce parcours suit
un ordre d'usage : à la fin de chaque saison, on sait faire quelque chose
d'entier.

> **Corrigé sur le dépôt.** Le découpage initial supposait des modules `chat`
> et `roundcube` distincts. Ils n'existent pas : Roundcube est **contenu dans**
> `secubox-mail`, et la discussion instantanée passe par `secubox-matrix`.
> Les saisons ci-dessous ne mentionnent que ce que le dépôt contient réellement.

---

## Saison 0 — Découvrir

Ce qu'il faut savoir avant tout le reste.

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 0.1 | Qu'est-ce qu'une SecuBox ? | Débutant | — |
| 0.2 | Première connexion | Débutant | `secubox-auth` |
| 0.3 | Comprendre le tableau de bord | Débutant | `secubox-hub` |
| 0.4 | Trouver une application | Débutant | `secubox-hub` |
| 0.5 | Utilisateur ou administrateur ? | Débutant | — |
| 0.6 | Changer son mot de passe | Débutant | `secubox-auth` |
| 0.7 | Obtenir de l'aide | Débutant | — |

**À la fin** : on sait entrer, se repérer, et trouver ce qu'on cherche.

---

## Saison 1 — Communiquer

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 1.1 | Ouvrir le webmail | Débutant | `secubox-mail` |
| 1.2 | Se connecter au webmail | Débutant | `secubox-mail` |
| 1.3 | Envoyer un courriel | Débutant | `secubox-mail` |
| 1.4 | Recevoir et lire | Débutant | `secubox-mail` |
| 1.5 | Les contacts | Débutant | `secubox-mail` |
| 1.6 | Discuter en direct | Intermédiaire | `secubox-matrix` |
| 1.7 | Découvrir le BBS | Débutant | `secubox-bbs` |
| 1.8 | Lire un salon | Débutant | `secubox-bbs` |
| 1.9 | Poster un message | Débutant | `secubox-bbs` |
| 1.10 | Répondre | Débutant | `secubox-bbs` |
| 1.11 | Joindre un fichier | Intermédiaire | `secubox-bbs` |

**À la fin** : on écrit à quelqu'un, et on participe à une conversation.

---

## Saison 2 — Mes fichiers

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 2.1 | Ouvrir Nextcloud | Débutant | `secubox-nextcloud` |
| 2.2 | Déposer un fichier | Débutant | `secubox-nextcloud` |
| 2.3 | Créer un dossier | Débutant | `secubox-nextcloud` |
| 2.4 | Partager un fichier | Débutant | `secubox-nextcloud` |
| 2.5 | Télécharger un fichier | Débutant | `secubox-nextcloud` |
| 2.6 | Synchroniser son ordinateur | Intermédiaire | `secubox-nextcloud` |
| 2.7 | Les photos | Intermédiaire | `secubox-photoprism` |

**À la fin** : ses fichiers sont chez soi, accessibles et partageables.

---

## Saison 3 — Communauté

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 3.1 | Qu'est-ce que la fédération ? | Débutant | — |
| 3.2 | Publier sur Mastodon | Intermédiaire | `secubox-mastodon` |
| 3.3 | Suivre quelqu'un ailleurs | Intermédiaire | `secubox-mastodon` |
| 3.4 | Publier un billet | Intermédiaire | `secubox-billets` |
| 3.5 | Du BBS au billet public | Intermédiaire | `secubox-bbs` |
| 3.6 | Inviter quelqu'un | Intermédiaire | `secubox-bbs` |

**À la fin** : on s'adresse au-delà de sa propre SecuBox.

---

## Saison 4 — Médias

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 4.1 | Regarder une vidéo | Débutant | `secubox-peertube` |
| 4.2 | Publier une vidéo | Intermédiaire | `secubox-peertube` |
| 4.3 | Écouter sa musique | Débutant | `secubox-lyrion` |
| 4.4 | Sa médiathèque | Débutant | `secubox-jellyfin` |
| 4.5 | Publier un podcast | Intermédiaire | `secubox-podcaster` |

**À la fin** : on héberge et diffuse ses propres médias.

---

## Saison 5 — Vie privée et sécurité

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 5.1 | Un bon mot de passe | Débutant | `secubox-auth` |
| 5.2 | La double authentification | Intermédiaire | `secubox-auth` |
| 5.3 | Partager sans exposer | Intermédiaire | `secubox-nextcloud` |
| 5.4 | Se connecter de l'extérieur | Intermédiaire | `secubox-wireguard` |
| 5.5 | Naviguer par Tor | Avancé | `secubox-tor` |
| 5.6 | Ce que le pare-feu bloque | Avancé | `secubox-crowdsec` |
| 5.7 | Sauvegarder ses données | Intermédiaire | `À documenter` |

**À la fin** : on comprend ce qui protège quoi, et pourquoi.

---

## Saison 6 — Administration

| # | Tutoriel | Niveau | Module |
|---|---|---|---|
| 6.1 | Créer un compte | Administrateur | `secubox-auth` |
| 6.2 | Installer un module | Administrateur | `secubox-hub` |
| 6.3 | Démarrer et arrêter un service | Administrateur | `secubox-system` |
| 6.4 | Publier un service sur internet | Administrateur | `secubox-haproxy` |
| 6.5 | Obtenir un certificat | Administrateur | `secubox-haproxy` |
| 6.6 | Lire les journaux | Administrateur | `secubox-system` |
| 6.7 | Surveiller les ressources | Administrateur | `secubox-system-tuning` |
| 6.8 | Sauvegarder et restaurer | Administrateur | `À documenter` |

**À la fin** : on tient sa SecuBox, on ne la subit pas.

---

## À vérifier / futur module

Ce qui figurait au découpage initial et n'a **pas** de module identifié :

| Sujet | État |
|---|---|
| Sauvegarde / restauration générale | `À documenter` — aucun module dédié repéré |
| Calendrier, agenda | `HYPOTHÈSE À VALIDER` — probablement dans Nextcloud |
| Groupes et modération communautaire | `À documenter` |

Ces sujets ne seront pas rédigés tant que leur support réel n'est pas établi.
Écrire un tutoriel sur une fonction supposée est le plus sûr moyen de perdre la
confiance du lecteur au premier essai.
