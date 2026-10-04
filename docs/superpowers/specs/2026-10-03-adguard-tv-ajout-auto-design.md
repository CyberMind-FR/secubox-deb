<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ad-guard TV — ajout automatique des TV et streamers (#1959)

Suite de #1954 (mode `auto`, en service sur « TV banc » depuis le 2026-10-03, validé par le propriétaire sur 2 TV réelles).

## 1. Décisions du propriétaire (2026-10-03)

- **Détection par comportement DNS** (option A) : on reconnaît une TV ou un streamer à ce qu'elle demande, pas à son nom ni à son constructeur.
- **Mode par défaut `auto` avec le profil de base** (option a) : un appareil détecté est ajouté en mode `auto` et reçoit comme règles **confirmées** le profil de base
  (les 35 domaines validés sur les 2 TV réelles au départ, puis le profil agrégé du §6). Le mode par défaut est un **réglage visible** dans le panneau.
- **Listes complètes + règles spécifiques** : les appareils surveillés gardent le **puits de production complet** (~658 000 domaines) ET reçoivent leurs règles propres (§3).
- **Apprentissage et agrégation** : chaque appareil apprend ses candidats (#1954) ; ce qui est confirmé sur plusieurs appareils est **agrégé** en un profil commun qui
  alimente les nouveaux appareils et nourrit les candidats des autres (§6).

## 2. Objectif et hors-périmètre

**Objectif.** Une TV ou un streamer qui commence à utiliser gk2 comme DNS est repéré, ajouté au périmètre, protégé comme « TV banc » et visible dans le panneau,
sans action de l'administrateur. Les adresses IPv4 et IPv6 d'un même appareil restent regroupées, y compris quand l'IPv6 de confidentialité change.

**Hors périmètre.**
- Un appareil dont le DNS ne passe pas par gk2 (ni en IPv4 ni en IPv6) n'est pas visible : c'est un réglage de la Freebox, pas de ce module. NB : la seconde TV
  (MAC `38:07:16:94:fb:5b`, `192.168.1.128`) **est** vue, en IPv6 : 991 requêtes vers gk2 sur la seule adresse `2a01:e0a:dec:c4e0:4951:…` (relevé du 2026-10-03), alors que son adresse IPv4
  n'apparaît pas. C'est la preuve qu'il faut regrouper par MAC, jamais par adresse. Elle est aujourd'hui sous le puits complet seul, hors périmètre.
- Aucune inspection HTTPS, aucun nom d'appareil lu chez la Freebox, aucune écoute DHCP.
- Pas de classification fine (TV, streamer, console, téléphone) : une seule étiquette « TV/streamer probable », avec sa preuve affichée.

## 3. Les listes complètes restent actives pour les appareils surveillés

**Aujourd'hui** (#1954, vérifié le 2026-10-03) : un appareil en `observe`, `block` ou `auto` a une vue Unbound avec `local-zone: "." transparent`, qui le **sort du puits de
production** : seules ses règles s'appliquent (« TV banc » n'a que 35 domaines). Ce n'est pas ce que veut le propriétaire.

**Décision** : en mode `auto`, la vue de l'appareil est écrite avec **`view-first: yes`** et **sans** zone transparente : le puits de production s'applique, et les règles de la
vue (essai ou confirmées) s'y ajoutent.

**Mesuré sur l'Unbound 1.17.1 de gk2 (instance jetable, 2026-10-03)** :

| Vue de l'appareil | nom bloqué par la liste globale | nom servi par la liste globale | règle propre de la vue |
|---|---|---|---|
| aucune vue | refusé | servi | — |
| vue vide | refusé | servi | — |
| **`view-first: yes` + règle** | **refusé** | **servi** | **refusée** |
| `"." transparent` (mode actuel) | (non protégé) | **non servi** (liste globale cachée) | refusée |

L'ajout et le retrait de règles **à chaud** (`view_local_zone`) fonctionnent aussi dans une vue `view-first: yes`.

**Conséquences.**
- **Pourquoi c'est sûr (raisonnement du propriétaire, 2026-10-03)** : avant le POC, le DNS bloquait déjà la liste complète pour la TV (le puits est actif sur gk2 : 656 516 zones,
  `sinkhole.enabled = 1`) et la lecture fonctionnait ; avec les 35 règles seules, la lecture fonctionne aussi. Si les deux ensembles n'ont chacun aucun domaine nécessaire à la lecture,
  leur **réunion** n'en a pas non plus. Le comportement « liste complète + règles » est donc la réunion de deux états déjà validés. Hypothèse à garder : le contenu regardé est le même
  (même application) ; un autre service pourrait avoir un domaine nécessaire dans l'une des listes.
- Réglage **par appareil** `puits` (booléen, défaut `true` en `auto`) conservé : `false` rend l'ancien comportement (vue transparente), en un clic, pour revenir en arrière.
- Les 32 domaines des listes de test sont pour la plupart déjà dans le puits : le **profil de base** n'a plus besoin de les répéter ; il garde ce que le puits ne couvre pas
  (le moteur marque « déjà couvert par les listes » quand il le sait). Pour les appareils en `puits=false`, le profil complet reste appliqué.
- Les modes `observe` et `block` ne changent pas (ils restent transparents : on y mesure ce qu'un appareil résout SANS filtre).

## 4. Détection (module pur `api/dnstv_detecteur.py`)

Entrée : pour chaque source (adresse regroupée par MAC), ses requêtes des dernières 24 h (`dnstv_counts`, `dnstv_recents`) classées par `ClasseurServices`
(`lists/services.txt`). Sortie : une liste de `Detection(mac, adresses, score, preuve)`.

**Signal.** Une source est « TV/streamer probable » si, sur les 2 derniers jours (compteurs par jour de `dnstv_counts`, qui conservent tout, contrairement à `dnstv_recents`) :
- elle a interrogé au moins `min_declencheurs` fois (départ : 5) un domaine d'insertion publicitaire (`[adblock_tv_auto] declencheurs`, aujourd'hui `fwmrm.net`) — un pic isolé,
  par exemple un lien suivi une fois, ne suffit pas,
- **et** au moins `min_services` (départ : 2) services distincts de type `contenu` ou `qualite_video`.

Les compteurs par jour n'ont pas d'heure : on ne vérifie donc pas « plusieurs fenêtres de 10 minutes ». Le seuil de requêtes tient ce rôle.

**Les requêtes de la box elle-même sont exclues du journal** (`dnstv_recents` et compteurs) : gk2 s'interroge lui-même ≈ 11 000 fois en 20 minutes, ce qui saturait la table des requêtes récentes
(plafond de 20 000 lignes, soit ≈ 35 minutes d'historique) et limitait déjà la détection des coupures de #1954. Le démon d'alimentation ignore les adresses locales de la box.

La preuve (nombre de requêtes, services vus) est enregistrée et affichée.

**Limite à dire clairement.** Le DNS ne distingue pas une TV d'un téléphone ou d'un ordinateur qui regarde un replay avec les mêmes services : les trois peuvent
passer le signal. D'où les garde-fous du §6. Les seuils viennent d'**un** cas réel (replay France TV) : ils sont des valeurs de départ, à calibrer.

## 5. Ajout, suivi des adresses et profil de base

**Identité = adresse MAC** (table des voisins : `lire_voisins`), pas le nom. Le nom est généré (`TV` + 4 derniers hexadécimaux de la MAC, unique) et modifiable
par l'administrateur ; le nom reste la clé des règles (comportement de #1954, collision refusée par `valider_etat`).

**Ajout** : l'appareil est écrit dans `etat.json` (`clients` : une entrée par adresse, même nom) avec le mode par défaut, puis ses règles de base sont créées dans
`regles.json` à l'état **confirmé** (origine `auto`, motif « profil de base »). Les deux écritures se font sous le verrou existant `dnstv_regles.verrou()`.

**Profil de base (graine)** : fichier versionné `lists/profil-tv-base.txt` (en-tête `# version:`, empreinte dans `MANIFEST.json`) = les 35 domaines validés (les 32 des listes du
POC + `ftv-publicite.fr`, `c.2mdn.net`, `7cd77.v.fwmrm.net`). Changer la graine ne modifie pas les appareils déjà ajoutés. Le profil effectif est la graine **plus** l'agrégation (§6).

**Suivi des adresses** : à chaque passage, les adresses (IPv4/IPv6) que la table des voisins rattache à la MAC d'un appareil ajouté automatiquement sont ajoutées à
`etat.json` avec son nom ; une adresse non vue depuis 7 jours est retirée. Cela règle l'IPv6 de confidentialité qui change. Plafond global de 32 adresses (limite de
`valider_etat`) : au-delà, on cesse d'ajouter et on le signale.

**Appliquer sans multiplier les coupures.** Un nouvel appareil ou une nouvelle adresse change les vues Unbound : il faut un **rechargement complet** (≈ 10 s sans DNS,
mesuré). Les ajouts sont donc **regroupés** : au plus un rechargement par heure, et au plus `max_par_jour` nouveaux appareils par jour (départ : 3).

## 6. Apprentissage et agrégation

Chaque appareil `auto` apprend ses candidats comme dans #1954. L'**agrégation** les met en commun, sans jamais appliquer de blocage sans confirmation humaine, sauf pour la graine :

1. **Profil agrégé** (`profil-agrege.json`, écrit par le moteur sous le verrou) : pour chaque domaine, la liste des appareils où il est **confirmé** et sa dernière confirmation.
   Un domaine confirmé sur au moins `min_appareils_agreg` appareils distincts (départ : 2) entre dans le profil agrégé, avec sa provenance.
2. **Nouvel appareil** : il reçoit en règles **confirmées** la graine + le profil agrégé (§5), origine `auto`, motif « profil de base » / « profil agrégé (N appareils) ».
3. **Appareils existants** : un domaine entré dans le profil agrégé leur est proposé comme **candidat** (score relevé, motif « confirmé sur N autres appareils »), jamais appliqué seul :
   il suit l'essai et la confirmation de #1954.
4. **Retrait** : si un domaine du profil agrégé est retiré par signal de casse sur un appareil (#1954), il perd sa confirmation sur cet appareil ; sous le seuil
   `min_appareils_agreg`, il sort du profil agrégé (les appareils qui l'ont déjà gardent leur règle).
5. **Affichage** : le panneau montre le profil agrégé (domaine, appareils, dernière confirmation) et, pour chaque règle, si elle vient de la graine, de l'agrégation, de
   l'apprentissage local ou de l'administrateur.

Limite : l'agrégation généralise à partir de peu d'appareils ; un domaine confirmé sur deux TV peut ne pas convenir à un troisième : d'où l'essai et le retrait en un clic.

## 7. Garde-fous

1. **Désactivé par défaut dans le paquet** (`ajout_auto = false` dans `etat.json`) : une mise à jour ne change jamais le DNS toute seule. Activé par l'administrateur dans le
   panneau (sur gk2, à la demande du propriétaire, après déploiement).
2. **Plafond quotidien** et **un rechargement par heure** (§5).
3. **Exclusions** : jamais la box elle-même, ni la passerelle, ni une adresse locale ; liste `ignores` (par MAC) alimentée par le bouton « Retirer et ne plus ajouter ».
4. **Retrait en un clic** depuis le panneau : l'appareil sort du périmètre (retour au puits de production) et sa MAC est ignorée.
5. **Journal d'audit** : chaque ajout, retrait et suivi d'adresse écrit une ligne (`/var/log/secubox/audit.log`) avec la preuve ; visible dans le journal du panneau.
6. **Aucune règle de blocage hors du profil de base** : les candidats appris ensuite suivent le cycle de #1954 (essai, confirmation).
7. Un appareil ajouté automatiquement porte `origine: "auto"` et reste distinguable de ceux déclarés par l'administrateur.

## 8. Données et API

`etat.json` gagne : `mode_defaut` (`off|auto`, défaut `auto` ; `observe` et `block` sortent un appareil du puits de production et restent réservés à la déclaration manuelle — revue de sécurité du 2026-10-03), `ajout_auto` (booléen, défaut faux), `ignores` (liste de MAC) ; chaque client gagne
`mac` (optionnel), `origine` (`admin|auto`), `ajoute` (horodatage), `preuve` (texte court), `puits` (booléen, défaut vrai en `auto` : puits de production complet, §3). Tout est revalidé par `valider_etat` (comme pour #1954).

Routes (`require_lecture` en lecture, `require_jwt` en écriture) : `GET /auto/profil` (profil agrégé et provenance), `POST /auto/appareils/{nom}/puits` (`puits` vrai/faux), `GET /auto/detection` (appareils détectés, preuve, ajoutés ou non), `POST /auto/detection/reglage`
(`ajout_auto`, `mode_defaut`), `POST /auto/appareils/{nom}/ignorer` (retire et ignore). Le moteur reste la minuterie de #1954.

## 9. Panneau

Dans la carte « Mode automatique » : interrupteur « Ajout automatique », sélecteur « Mode par défaut » avec l'avertissement du §3 ; liste des appareils (badge
« ajouté automatiquement le … », preuve, adresses regroupées) avec « Retirer et ne plus ajouter » ; appareils détectés non ajoutés (plafond atteint, exclus) ; journal.
Rendu par `textContent` uniquement.

## 10. Tests

- Détecteur : rejeu d'événements issus des phases réelles E/P/C → la TV est détectée ; un téléphone qui ne demande que des services `contenu` sans insertion publicitaire
  ne l'est pas ; un pic isolé ne l'est pas ; la box, la passerelle et les adresses locales sont exclues.
- Rendu Unbound : vue `auto` avec `view-first: yes` et sans zone transparente quand `puits=true` ; vue transparente quand `puits=false` ; test sur un vrai Unbound jetable (puits global + règle de la vue, ajout à chaud).
- Agrégation : seuil `min_appareils_agreg`, nouvel appareil reçoit graine + agrégé, appareils existants reçoivent des CANDIDATS (jamais des règles actives), retrait sous le seuil.
- Ajout : nom unique et stable, règles de base créées confirmées, collision de nom refusée, plafond, un rechargement par heure, MAC ignorée jamais rajoutée.
- Suivi des adresses : nouvelle IPv6 rattachée, adresse vieille de 7 jours retirée, plafond de 32.
- Sécurité : donnée hostile (MAC, nom, domaine) jamais écrite dans la configuration Unbound ; `ajout_auto` faux ne modifie rien.
- Interface : navigateur réel, texte piégé, API absente.
- Essai réel sur gk2 avant de conclure : détection d'un appareil de test, ajout, application, retrait.

## 11. Livraison

`secubox-ad-guard` 1.5.0, documenté (HISTORY, WIP, README, TOML `[adblock_tv_auto]` : `min_declencheurs`, `min_services`, `min_fenetres`, `max_par_jour`), déployé par paquet sur gk2,
agrégateur redémarré (il sert le module dans son processus), vérifié **par l'adresse publique**. L'issue #1959 ne se ferme qu'après déploiement et validation du propriétaire.

## 12. Risques assumés

- Faux positifs de détection (téléphone, ordinateur) : atténués par les garde-fous, pas supprimés ; le coût est qu'un appareil reçoive le profil de base et la surveillance.
- **Faux positifs des listes** : avec le puits complet, une liste publique peut bloquer un nom nécessaire à un AUTRE service que celui validé. Mitigation : réglage `puits` par appareil, retour arrière en un clic, et un premier essai sur « TV banc » avec le propriétaire (la réunion de deux états validés est attendue sûre, mais la combinaison n'a pas été jouée telle quelle).
- **Mémoire/performance** : `view-first` n'ajoute pas de copie de la liste (les zones globales sont partagées) ; à vérifier par la mesure du temps de rechargement et de la mémoire d'Unbound sur gk2.
- Seuils non calibrés (un cas réel) et détection sur compteurs par jour (sans heure). À ajuster après quelques jours.
- Un appareil dont l'IPv6 de confidentialité change plus vite que le passage de la minuterie reste suivi avec un retard d'au plus une minute, plus un éventuel rechargement
  (≤ 1 par heure) : pendant ce délai, la nouvelle adresse est traitée comme un appareil inconnu (puits de production).
- **Usurpation d'adresse source (risque résiduel, revue du 2026-10-03)** : un appareil du LAN peut forger des requêtes DNS avec l'adresse source d'un autre ; Unbound journalise la victime, et la table des voisins la rattache à sa MAC. Le signal de détection peut donc être produit pour un voisin. Conséquences bornées : 3 ajouts par jour, un changement du périmètre par heure, profil de base seulement (`mode_defaut` limité à `auto|off`), retrait en un clic et audit de chaque ajout. Les voisins pris en compte sont ceux de l'interface du LAN seulement (ni `br-lxc` ni `wg*`), une adresse n'est rattachée que si le DNS de la box l'a vue, et un appareil n'a jamais plus de 4 adresses.

