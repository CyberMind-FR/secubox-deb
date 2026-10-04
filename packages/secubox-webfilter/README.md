<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-webfilter

Filtrage de contenus par catégories (#1962). Le module classe les requêtes DNS de chaque appareil par catégorie (contenu adulte, jeux
d'argent, phishing et malware). **Phase 1 : observe** (ce que le filtrage *aurait* bloqué). **Phase 2 : profils et blocage** : un profil met chaque
catégorie en `observe` ou `block` ; un appareil est rattaché à un profil par adresse MAC, avec des exceptions. Tant qu'aucun profil ne bloque, rien
n'est écrit dans Unbound : ni rechargement, ni coupure du DNS.

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


## Phase 2 : profils, appareils, blocage

- **Profils** (`/var/lib/secubox/webfilter/config.json`, écrit par l'API) : mode `observe` ou `block` par catégorie, autorisations par domaine. `defaut`
  s'applique à tout appareil non assigné et ne se supprime pas. Modèles `enfants` et `adultes` proposés, jamais appliqués d'office.
- **Appareils** : clé = adresse MAC (IPv4 et IPv6 ensemble, d'après `ip neigh`), profil et exceptions par catégorie. Les appareils gérés par **ad-guard**
  (TV, streamers) gardent leur filtrage propre et ne sont pas assignables ici : leur vue est plus précise que celle du réseau entier.
- **Blocage** : une vue d'Unbound **par configuration effective distincte** (deux appareils de même configuration partagent la même vue : la mémoire dépend
  du nombre de configurations, pas d'appareils). Le réseau entier (`[reseau] lan` de `/etc/secubox/webfilter.toml`) pointe vers `wf-defaut` ; chaque appareil
  assigné a une entrée `/32` ou `/128` plus précise. Zones `always_nxdomain` ; les autorisations sont des zones `transparent` plus précises.
- **Application** : `POST /api/v1/webfilter/appliquer` dépose `appliquer.demande` ; l'unité root `secubox-webfilter-apply` (déclenchée par
  `secubox-webfilter-apply.path`, jamais par sudo) lance `secubox-webfilter-ctl apply`, qui valide `config.json` comme une entrée hostile, génère
  `/etc/unbound/unbound.conf.d/93-secubox-webfilter.conf`, vérifie le budget de zones (`[limites] zones_max`), contrôle avec `unbound-checkconf`, recharge
  Unbound et **restaure l'ancien fichier octet pour octet** en cas d'échec. Un fichier généré identique ne déclenche **aucun rechargement**.
- **Nuit** : `secubox-webfilter-apply.timer` applique les changements en attente à 04:00. Un rechargement coupe le DNS 7 à 10 s (mesuré : 6,9 s avec le
  puits d'ad-guard seul, 9,4 s avec 312 000 zones de catégories en plus). La synchronisation des listes ne recharge jamais Unbound.
- **Audit** : chaque changement effectif (profil, mode d'une catégorie, appareil, application, refus, échec) est écrit dans `/var/log/secubox/audit.log`
  par le contrôleur root (module `webfilter-ctl`).
- **Comptage** : « bloqué » et « aurait bloqué » sont comptés à part d'après `carte.json` (adresse → profil et modes), publiée par le contrôleur.

| Route (`/api/v1/webfilter/`, `require_jwt`) | Rôle |
|---|---|
| `GET/POST /profils`, `DELETE /profils/{nom}` | profils (modèles inclus) |
| `GET /appareils`, `POST/DELETE /appareils/{mac}` | appareils assignés et vus récemment |
| `GET /appliquer`, `POST /appliquer` | en attente, estimation (zones, mémoire, durée), dernier résultat ; demande d'application |

`/etat` (`require_lecture`) dit `mode_global: "block"` dès qu'un profil bloque, sans nom de profil ni d'appareil.

**Configuration** : renseigner `[reseau] lan` dans `/etc/secubox/webfilter.toml` (vide par défaut : le paquet n'applique jamais les réseaux d'un autre site).
