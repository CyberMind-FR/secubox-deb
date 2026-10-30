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
3. `secubox-webfilter-api` (socket `/run/secubox/webfilter.sock`) et le panneau `/webfilter/` affichent le résultat. Le panneau suit le profil Aurora (`.claude/AURORA-REFERENCE.md`) : confirmations intégrées à la page (jamais `confirm()`, que le navigateur du Hall ignore), `?embed=1`, `?demo=1`. Le NAC (carte de l'appareil) et Guardian (panneau Filtrage web) le lisent en lecture seule.

## Domaines toujours bloqués (`bloque`)

Un profil et un appareil peuvent porter une liste `bloque` : ces domaines sont refusés (NXDOMAIN, sous-domaines compris) **quel que soit le mode des catégories**,
même quand la catégorie qui les liste est en `observe` pour cet appareil (exception voulue). La liste de l'appareil s'ajoute à celle de son profil ; un blocage
l'emporte sur une autorisation du même nom ; une autorisation sur un domaine parent ne débloque pas un sous-domaine forcé. Forme canonique exigée
(minuscules, sans schéma ni chemin), 200 domaines au plus. La clé n'est écrite dans `config.json` que si elle sert : une configuration sans domaine forcé reste
identique à celle d'avant. API : `bloque` sur `POST /profils` et `POST /appareils/<mac>`, relu par `GET /profils` et `GET /appareils`.

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
  `93-secubox-webfilter.conf`, vérifie le budget de zones (`[limites] zones_max`) et le **dépose** dans `/var/lib/secubox-dns-listes/sources` (0.5.0,
  #3205). Le service root `secubox-dns-listes` (secubox-core ≥ 1.8.3) compile webfilter, adblock et adult en un seul `92-secubox-listes.conf` à
  étiquettes (chaque domaine une fois au lieu d'une copie par vue), contrôle avec `unbound-checkconf`, recharge Unbound et **remet tout l'état
  précédent** au moindre échec ; son état se lit dans `/var/lib/secubox-dns-listes/etat.json`. Un rendu identique n'est **pas redéposé** (rien n'est
  recompilé). Le contrôleur ne touche plus Unbound : ni `unbound-checkconf`, ni `unbound-control`, ni accès réseau.
- **Nuit** : `secubox-webfilter-apply.timer` applique les changements en attente à 04:00. La synchronisation des listes ne recharge jamais Unbound.
- **Adresses rémanentes (0.5.3, #3005)** : la carte d'un appareil assigné ne dépend plus de la seule table de voisinage au moment de l'application
  (`ip -j neigh` à 04:00 : un portable passé sur un autre réseau la nuit perdait son adresse Wi-Fi du jour et retombait dans `wf-defaut`). Le démon
  `secubox-webfilter-feed` tient `remanence.json` (dossier d'état, compte du service, `0640`, écriture atomique) : pour chaque adresse vue dans le journal
  d'Unbound **et** rattachée à un MAC par la table de voisinage, le dernier MAC et la date. Clé = adresse : jamais deux MAC pour une adresse ; un bail
  réattribué passe au dernier vu. Le contrôleur fusionne cet historique (non expiré) avec la table du moment, qui l'emporte. Les appareils non assignés
  n'entrent pas dans la carte, comme avant ; leurs adresses sont retenues pour trancher les conflits. `connus.json` reste la liste des appareils vus
  dans les 5 dernières minutes (panneau).
- **Ré-application amortie** : quand une adresse d'un appareil assigné manque à la carte appliquée (ou qu'une adresse de la carte sert un autre MAC),
  le démon dépose `appliquer.demande` (création exclusive), au plus une fois par fenêtre d'amortissement, jamais pendant une application (marqueur
  `application.en-cours` posé par le contrôleur, ignoré au-delà de 30 min) ni pendant une compilation de `secubox-dns-listes` (`etat.json` « en-cours »).
  Une adresse signalée ne l'est plus tant qu'elle ne change pas de MAC.

| Clé (`[appareils]` de `/etc/secubox/webfilter.toml`) | Défaut | Bornes | Rôle |
|---|---|---|---|
| `retention_jours` | 14 | 0 à 90 | durée pendant laquelle une adresse vue reste dans la carte de son appareil ; 0 = table de voisinage seule (comportement d'avant 0.5.3) |
| `reapplication_min` | 30 | 5 à 1440 | au plus une demande d'application automatique par fenêtre |

Section absente : valeurs par défaut. Le démon relit la section toutes les 5 minutes ; le contrôleur à chaque application.
- **Audit** : chaque changement effectif (profil, mode d'une catégorie, appareil, application, refus, échec) est écrit dans `/var/log/secubox/audit.log`
  par le contrôleur root (module `webfilter-ctl`).
- **Comptage** : « bloqué » et « aurait bloqué » sont comptés à part d'après `carte.json` (adresse → profil et modes), publiée par le contrôleur.

| Route (`/api/v1/webfilter/`, `require_jwt`) | Rôle |
|---|---|
| `GET/POST /profils`, `DELETE /profils/{nom}` | profils (modèles inclus) |
| `GET /appareils`, `POST/DELETE /appareils/{mac}` | appareils assignés et vus récemment |
| `GET /appliquer`, `POST /appliquer` | en attente, estimation (zones, mémoire, durée), dernier résultat ; demande d'application |

`/etat` (`require_lecture`) dit `mode_global: "block"` dès qu'un profil bloque, sans nom de profil ni d'appareil. `mode_global: "inconnu"` si la configuration des profils
est illisible par l'API (#3172) : jamais « observe » par défaut. `config.json` appartient au service ; s'il
appartient à root, le contrôleur le lui rend au début de chaque application (par descripteur, audité).

**Configuration** : renseigner `[reseau] lan` dans `/etc/secubox/webfilter.toml` (vide par défaut : le paquet n'applique jamais les réseaux d'un autre site).

## Limites de la phase 2

- **Le décompte « bloqué » peut subir une surestimation** : il ne tient pas compte des autorisations par domaine ni des adresses exclues (ad-guard, adresse en
  double) qui se trouvent dans le réseau par défaut. Jamais l'inverse : un blocage n'est jamais compté s'il n'a pas eu lieu pour la catégorie du profil.
- **Une adresse jamais vue** pendant la rétention (appareil neuf, adresse IPv6 temporaire nouvelle) reste au profil `defaut` jusqu'à l'application que le
  démon demande (au plus une par `reapplication_min`, suivie de la compilation de `secubox-dns-listes`, quelques minutes). Les adresses IPv6 temporaires
  changent chaque jour : chacune peut déclencher une application, bornée par l'amortissement.
- **Une adresse réattribuée** garde la vue de l'ancien appareil jusqu'à l'application que le démon demande en voyant le nouveau MAC.
- **L'usurpation d'une adresse MAC** sur le réseau local fait hériter du profil de l'appareil usurpé : un filtre DNS n'est pas un contrôle d'accès.
- **AppArmor** n'existe pas dans le noyau de gk2 : les profils livrés ne protègent rien sur cette box.
- Sans `config.json`, le contrôleur ne fait rien (« inchangé ») ; sans catégorie en `block`, il n'écrit aucun drop-in et retire celui qui existe.
