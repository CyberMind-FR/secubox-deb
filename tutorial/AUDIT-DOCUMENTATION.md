<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Rapport d'audit documentaire

**Date** : 2026-08-12
**Méthode** : `scripts/tutorial-audit.py`, exécuté sur le dépôt.
**Portée** : `packages/secubox-*`

Tous les chiffres ci-dessous sont **mesurés**. Aucun n'est estimé.

---

## 1. Ce que contient SecuBox

| | |
|---|---|
| **Modules** | **173** |
| Modules avec manifeste `secubox.yaml` | 132 |
| Modules **sans** manifeste | **41** |
| Modules avec interface web | 138 |
| Modules avec API | 140 |
| **Routes d'API au total** | **2 807** |
| Modules dont l'API exige un jeton | 114 |
| Modules avec outil en ligne de commande | 63 |
| Modules tournant en conteneur LXC | 24 |
| Modules avec README | 143 |
| Modules **sans** README | **30** |
| Modules **sans aucun test** | **117** |

## 2. Ce que la documentation couvre aujourd'hui

| | |
|---|---|
| Fiches rédigées et vérifiées | **6** |
| Fiches prévues aux vingt premières | 20 |
| Modules couverts par au moins une fiche | 4 sur 173 |

**Couverture réelle : 2,3 %.** Le chiffre est brutal ; il est juste. Cette
première passe construit les fondations et un échantillon vérifié, pas un
corpus.

## 3. Ce qui manque, et ce que cela coûte

### 41 modules sans manifeste

Sans `debian/secubox.yaml`, le module n'a ni catégorie, ni tier, ni description
machine. Il **n'apparaît dans aucun filtre** et ne peut pas être classé
automatiquement.

Parmi eux, des modules qui comptent :

`secubox-aggregator`, `secubox-bbs`, `secubox-billets`, `secubox-certs`,
`secubox-grafana`, `secubox-assist`, `secubox-health-doctor`…

`secubox-bbs` est particulièrement gênant : c'est l'un des modules les plus
exposés à l'utilisateur, et il est invisible au catalogue structuré.

**Coût** : la future application de documentation ne pourra pas les proposer
au filtrage. Ils existeront sans être trouvables.

### 30 modules sans README

Aucun point d'entrée pour comprendre ce que fait le module sans lire son code.

### Catégories inexploitables

| Catégorie | Modules |
|---|---|
| `misc` | 73 |
| `À documenter` | 41 |
| toutes les autres réunies | 59 |

**114 modules sur 173 n'ont pas de catégorie utile.** Le champ existe mais ne
range rien : on ne peut pas construire un parcours dessus.

C'est pourquoi le [parcours d'apprentissage](learning/learning-path.md) est
organisé **par usage** et non par catégorie. Ce n'est pas un choix éditorial,
c'est une contrainte constatée.

## 4. Incohérences relevées

| Constat | Détail |
|---|---|
| Deux modules `chat` et `roundcube` supposés | **N'existent pas.** Roundcube est dans `secubox-mail` ; la discussion passe par `secubox-matrix` |
| Vhost spécifique à une board dans un paquet | `packages/secubox-nextcloud/nginx/nextcloud-vhost.conf` porte `server_name nc.gk2.secubox.in` — le paquet n'est donc pas réinstallable ailleurs sans édition |
| Modules Go absents du décompte d'API | `secubox-bbs` ressort à 0 route ; il en a. Limite de l'outil, pas du module |
| 117 modules sans test | Aucune fiche ne peut s'appuyer sur un test pour affirmer un comportement |

Trois défauts fonctionnels ont également été relevés **et non corrigés**, comme
demandé : voir [CODE-ISSUES-DISCOVERED](CODE-ISSUES-DISCOVERED.md).

## 5. Modules les plus importants à documenter

Déduits de l'exposition à l'utilisateur, pas de la richesse technique.

| Module | Pourquoi | État |
|---|---|---|
| `secubox-hub` | porte d'entrée de tout le reste | 3 fiches |
| `secubox-auth` | sans lui, aucun accès | 0 fiche |
| `secubox-mail` | usage n°1 attendu, 46 routes | 1 fiche |
| `secubox-nextcloud` | usage n°2 attendu | 0 fiche |
| `secubox-bbs` | cœur communautaire | 1 fiche |
| `secubox-peertube` | média le plus visible | 0 fiche |

## 6. Modules difficiles à documenter

| Module | Difficulté |
|---|---|
| `secubox-haproxy` | la chaîne HAProxy → WAF → nginx → module est invisible à l'utilisateur et pourtant cause la plupart des erreurs |
| `secubox-crowdsec` | 31 routes, concepts de sécurité peu intuitifs |
| `secubox-wireguard` | dépend de conditions réseau extérieures à la board |
| `secubox-mastodon` | la fédération demande d'expliquer un modèle avant tout geste |
| `secubox-aggregator` | infrastructure pure, aucun geste utilisateur, mais cause de pannes visibles |

## 7. Informations manquantes

| Manque | Effet |
|---|---|
| Sauvegarde / restauration | **Aucun module identifié.** Sujet critique, non documentable en l'état |
| Calendrier, agenda | `HYPOTHÈSE À VALIDER` — probablement Nextcloud |
| Modération communautaire | `À documenter` |
| Valeurs de la charte graphique | à reprendre de `.claude/DESIGN-CHARTER.md` |
| Rôles utilisateur/admin par module | aucun manifeste ne les déclare |

L'absence de piste sur **la sauvegarde** est le manque le plus sérieux : c'est
la contrepartie directe de l'auto-hébergement, et un utilisateur qui perd ses
données parce que personne ne lui a expliqué comment les sauvegarder perd bien
plus que du temps.

## 8. Recommandations

Par ordre de rendement.

1. **Écrire les 14 fiches P0 restantes.** Elles couvrent le trajet complet d'un
   nouvel utilisateur.
2. **Ajouter un manifeste aux 41 modules qui n'en ont pas**, en commençant par
   `secubox-bbs`, `secubox-billets` et `secubox-aggregator`.
3. **Rendre les catégories utiles.** 73 modules en `misc` rendent le champ
   inerte. Un vocabulaire arrêté et appliqué le rendrait exploitable.
4. **Élargir l'inventaire aux modules Go**, pour que `secubox-bbs` cesse
   d'apparaître sans API.
5. **Établir la sauvegarde**, puis la documenter. Dans cet ordre.
6. **Sortir le vhost `nc.gk2.secubox.in`** du paquet Nextcloud.
7. **Fixer les valeurs de la charte graphique**, seul point encore ouvert du
   design system.

## Les 20 premiers tutoriels à produire

Liste, ordre et chemin de vérification : voir
[tutorial-priority.md](learning/tutorial-priority.md).

**Six sont écrits** (rangs 1 à 4, plus le webmail et le BBS). Les quatorze
autres restent à produire.

---

## Comment reproduire ce rapport

```bash
python3 scripts/tutorial-audit.py
```

Les chiffres sont recalculés depuis le dépôt à chaque exécution. S'ils divergent
de ce document, **c'est ce document qui a vieilli** — et il faut le redater.
