<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-mastodon — instance fédérée (LXC natif)

Panneau d'administration et API pour une instance **Mastodon** installée
nativement dans un LXC Debian dédié : Ruby, PostgreSQL, Redis, Sidekiq et Puma,
gérés par systemd **dans** le conteneur.

---

## Ce que le paquet installe, et ce qu'il n'installe pas

| | |
|---|---|
| Le paquet | panneau, API, `mastodonctl`, vhost et route nginx, entrée de menu |
| `mastodonctl install` | conteneur, dépendances, base, secrets |
| **Vous** | gemmes, schéma, premier compte propriétaire |

Les trois dernières étapes ne sont pas automatisées, et ce n'est pas un oubli :
la compilation des gemmes dure **plus d'une heure** sur cette carte, et la
création du compte demande un nom et un courriel qu'un script ne doit pas
choisir à votre place.

---

## Le domaine est irréversible

Il est **gravé dans chaque adresse d'utilisateur** et dans les signatures
échangées avec les autres instances. Le changer après la première fédération ne
renomme pas votre instance : il la fait disparaître pour tous ceux qui vous
suivent.

`mastodonctl install` refuse de démarrer sans domaine configuré. Ce refus coûte
une minute ; s'en apercevoir après coûte les comptes distants.

---

## Installation

```bash
apt install secubox-mastodon

cp /etc/secubox/mastodon.toml.example /etc/secubox/mastodon.toml
# renseignez [instance] domain — irréversible

systemctl enable --now secubox-mastodon    # le panneau, léger
mastodonctl install                        # le conteneur, long
```

Le service de l'hôte est **léger et toujours joignable**, même conteneur
éteint. C'est ce qui permet au panneau de distinguer « le module est absent »
de « l'instance est éteinte » — deux situations qui appellent des gestes
différents.

---

## Quatre états distincts

`mastodonctl status` les rend séparément, et le panneau les montre en chaîne :

1. la **configuration** existe-t-elle ;
2. le **domaine** est-il défini ;
3. le **conteneur** existe-t-il, et tourne-t-il ;
4. l'**instance** répond-elle sur le port 3000.

Un conteneur allumé dont Puma est mort n'est pas « en marche ». Les confondre
envoie chercher la panne dans le réseau.

---

## Inscriptions

**Fermées par défaut**, sur invitation. Une instance ouverte sur internet se
remplit de comptes automatisés en quelques heures, et la modération retombe sur
quelqu'un.

```bash
mastodonctl invite     # 7 jours, affichée une seule fois
```

---

## Réseau

Le port 3000 n'est joignable **que depuis l'hôte**, par le pont des conteneurs.
HAProxy reste le seul frontal exposé — ouvrir 3000 au LAN court-circuiterait
l'inspection.

Le vhost est livré dans `sites-available/mastodon.conf`, **non activé** :
activer demande aussi une entrée HAProxy et un enregistrement DNS, qu'un paquet
ne décide pas seul.

Le flux temps réel passe en **WebSocket** sur le port 4000 ; sans les en-têtes
`Upgrade`, le fil ne se met plus à jour tout seul.

---

## Ressources

Mastodon demande davantage que les autres modules du parc : **2 Go de mémoire
au minimum**. En dessous, l'installation aboutit mais Sidekiq se fait tuer par
le noyau dès la première file chargée — et le symptôme est « les messages
n'arrivent plus », pas « mémoire insuffisante ».

---

## Suppression

`purge` **ne supprime ni le conteneur ni les secrets**. Une instance fédérée
contient des comptes, des messages et des relations avec d'autres serveurs ;
les effacer parce qu'un paquet est retiré serait une perte irréversible décidée
par un outil.
