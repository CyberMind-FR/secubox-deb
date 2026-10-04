<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-webfilter

Filtrage de contenus par catégories (#1962). **Phase 1 : observe seulement.** Le module classe les requêtes DNS de chaque appareil
par catégorie (contenu adulte, jeux d'argent, phishing et malware) et montre ce que le filtrage **aurait** bloqué. Rien n'est bloqué
et aucune zone n'est écrite dans Unbound : ni rechargement, ni coupure du DNS.

## Fonctionnement

1. `secubox-webfilter-sync` télécharge les listes publiques du catalogue (https seulement, taille plafonnée, ancienne version gardée en cas
   d'échec ou de liste tronquée) et construit un **index compact** par source (une empreinte de 64 bits par domaine).
2. `secubox-webfilter-feed` suit `journalctl -u unbound`, classe chaque nom demandé (le nom ou l'un de ses parents est listé) et compte par
   jour, appareil, catégorie et domaine dans `/var/lib/secubox/webfilter/webfilter.db` (30 jours, `0640`). Les requêtes de la box sont exclues.
3. `secubox-webfilter-api` (socket `/run/secubox/webfilter.sock`) et le panneau `/webfilter/` affichent le résultat.

Les listes sont **téléchargées à l'exécution, jamais livrées** : seule leur utilisation compte pour la licence, rappelée dans le panneau.

## Configuration : `/etc/secubox/webfilter.toml`

Catégories (`id`, `libelle`, `mode = "observe"`) et sources (`nom`, `url` https, `format` = `domaines` ou `hosts`, `licence`, `taille_max` en
octets, au plus 200 000 000). Le fichier est validé à chaque lecture ; une valeur invalide est refusée avec un message, jamais appliquée.
Le mode `block` n'existe pas dans cette version.

Listes retenues par défaut (vérifiées le 2026-10-04) : HaGeZi NSFW (GPL-3.0), HaGeZi gambling medium (GPL-3.0), Block List Project phishing
(MIT), URLhaus d'abuse.ch.

## API : `/api/v1/webfilter/`

| Route | Garde | Contenu |
|---|---|---|
| `GET /health` | aucune | état du module |
| `GET /etat` | `require_lecture` | catégories, mode, sources (nom, licence, taille, date) et requêtes classées sur 7 jours, **sans nom d'appareil** |
| `GET /stats?jours=1..30` | `require_jwt` | décompte par catégorie et par appareil |
| `GET /categories/{id}/domaines?jours=&n=` | `require_jwt` | domaines les plus vus d'une catégorie |
| `POST /sync` | `require_jwt` | dépose `/var/lib/secubox/webfilter/sync.demande` ; l'unité `secubox-webfilter-sync.path` lance la synchronisation (202 ; 409 si une demande récente existe) |

## Vie privée

Le décompte par appareil est une **donnée de navigation** : réservé à l'administrateur, conservé 30 jours, jamais exporté hors de la box. Le
filtrage d'un appareil est visible dans le panneau ; aucune surveillance cachée.

## Services

`secubox-webfilter.service` (API), `secubox-webfilter-feed.service` (comptage), `secubox-webfilter-sync.service` (oneshot) déclenché par
`secubox-webfilter-sync.path` (demande) et `secubox-webfilter-sync.timer` (toutes les 6 h). Utilisateur dédié `secubox-webfilter` (groupe
`secubox`, plus `systemd-journal` pour le comptage), bac à sable systemd strict, profils AppArmor `enforce` (`/etc/apparmor.d/secubox-webfilter`).

## Limites

Un résolveur DoH, un VPN ou une adresse IP directe contournent un filtre DNS. Une collision d'empreinte (≈ 10⁻¹⁰ pour 4,6 millions de
domaines) ne fait qu'ajouter un faux classement en mode observe. Le parking n'a pas de liste publique : il passe par l'apprentissage (phase 3).

## Tests

`python -m pytest tests` (99 tests, dont un banc navigateur Playwright pour le panneau, ignoré si Playwright est absent).
