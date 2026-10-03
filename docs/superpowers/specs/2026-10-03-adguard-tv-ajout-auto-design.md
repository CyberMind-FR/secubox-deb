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
- Un appareil dont le DNS ne passe pas par gk2 n'est pas visible : la TV `192.168.1.128` utilise le DNS de la Freebox (aucune requête vers gk2 en 20 minutes
  le 2026-10-03). Cela dépend des réglages de la Freebox, pas de ce module.
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
- C'est un **changement de comportement** pour « TV banc » validée : elle passerait du blocage par 35 règles seules au puits complet + 35 règles. Les listes publiques
  peuvent bloquer un nom dont la TV a besoin (faux positif) : c'est le risque principal, voir §12. Réglage **par appareil** `puits` (booléen, défaut `true` en `auto`) : `false`
  rend l'ancien comportement (vue transparente), en un clic, pour revenir en arrière.
- Les 32 domaines des listes de test sont pour la plupart déjà dans le puits : le **profil de base** n'a plus besoin de les répéter ; il garde ce que le puits ne couvre pas
  (le moteur marque « déjà couvert par les listes » quand il le sait). Pour les appareils en `puits=false`, le profil complet reste appliqué.
- Les modes `observe` et `block` ne changent pas (ils restent transparents : on y mesure ce qu'un appareil résout SANS filtre).

## 4. Détection (module pur `api/dnstv_detecteur.py`)

Entrée : pour chaque source (adresse regroupée par MAC), ses requêtes des dernières 24 h (`dnstv_counts`, `dnstv_recents`) classées par `ClasseurServices`
(`lists/services.txt`). Sortie : une liste de `Detection(mac, adresses, score, preuve)`.

**Signal.** Une source est « TV/streamer probable » si, sur 24 h :
- elle a interrogé au moins `min_declencheurs` fois (départ : 5) un domaine d'insertion publicitaire (`[adblock_tv_auto] declencheurs`, aujourd'hui `fwmrm.net`),
- **et** au moins `min_services` (départ : 2) services distincts de type `contenu` ou `qualite_video`,
- **et** dans au moins `min_fenetres` (départ : 2) fenêtres distinctes de 10 minutes (un pic isolé, par exemple un lien suivi une fois, ne suffit pas).

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

`etat.json` gagne : `mode_defaut` (`off|observe|auto|block`, défaut `auto`), `ajout_auto` (booléen, défaut faux), `ignores` (liste de MAC) ; chaque client gagne
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
- **Faux positifs des listes** : avec le puits complet, une liste publique peut bloquer un nom dont la TV a besoin (non mesuré sur « TV banc » : elle n'a jamais eu le puits complet avec ses règles). Mitigation : réglage `puits` par appareil, essai sur la TV **avec le propriétaire présent** avant de généraliser, et le retour arrière en un clic.
- **Mémoire/performance** : `view-first` n'ajoute pas de copie de la liste (les zones globales sont partagées) ; à vérifier par la mesure du temps de rechargement et de la mémoire d'Unbound sur gk2.
- Seuils non calibrés (un cas réel). À ajuster après quelques jours.
- Un appareil dont l'IPv6 de confidentialité change plus vite que le passage de la minuterie reste suivi avec un retard d'au plus une minute, plus un éventuel rechargement
  (≤ 1 par heure) : pendant ce délai, la nouvelle adresse est traitée comme un appareil inconnu (puits de production).
