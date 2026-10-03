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
- **Mode par défaut `auto` avec le profil de base** (option a) : un appareil détecté est ajouté en mode `auto` et reçoit comme règles **confirmées** les 35 domaines
  validés sur les 2 TV réelles. Le mode par défaut est un **réglage visible** dans le panneau.

## 2. Objectif et hors-périmètre

**Objectif.** Une TV ou un streamer qui commence à utiliser gk2 comme DNS est repéré, ajouté au périmètre, protégé comme « TV banc » et visible dans le panneau,
sans action de l'administrateur. Les adresses IPv4 et IPv6 d'un même appareil restent regroupées, y compris quand l'IPv6 de confidentialité change.

**Hors périmètre.**
- Un appareil dont le DNS ne passe pas par gk2 n'est pas visible : la TV `192.168.1.128` utilise le DNS de la Freebox (aucune requête vers gk2 en 20 minutes
  le 2026-10-03). Cela dépend des réglages de la Freebox, pas de ce module.
- Aucune inspection HTTPS, aucun nom d'appareil lu chez la Freebox, aucune écoute DHCP.
- Pas de classification fine (TV, streamer, console, téléphone) : une seule étiquette « TV/streamer probable », avec sa preuve affichée.

## 3. Fait que l'administrateur doit connaître

Un appareil en `observe`, `block` ou `auto` **sort du puits DNS de production** (~658 000 domaines) : seules ses règles s'appliquent. Ajouter un appareil
automatiquement lui retire donc sa protection actuelle ; le profil de base la remplace par les 35 règles validées. C'est le choix (a) du propriétaire. Il est dit dans le
panneau, à côté du réglage du mode par défaut (le mode `off` laisse l'appareil sous le puits).

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

**Profil de base** : fichier versionné `lists/profil-tv-base.txt` (en-tête `# version:`, empreinte dans `MANIFEST.json`) = les 35 domaines validés (les 32 des listes du
POC + `ftv-publicite.fr`, `c.2mdn.net`, `7cd77.v.fwmrm.net`). Changer le profil ne modifie pas les appareils déjà ajoutés.

**Suivi des adresses** : à chaque passage, les adresses (IPv4/IPv6) que la table des voisins rattache à la MAC d'un appareil ajouté automatiquement sont ajoutées à
`etat.json` avec son nom ; une adresse non vue depuis 7 jours est retirée. Cela règle l'IPv6 de confidentialité qui change. Plafond global de 32 adresses (limite de
`valider_etat`) : au-delà, on cesse d'ajouter et on le signale.

**Appliquer sans multiplier les coupures.** Un nouvel appareil ou une nouvelle adresse change les vues Unbound : il faut un **rechargement complet** (≈ 10 s sans DNS,
mesuré). Les ajouts sont donc **regroupés** : au plus un rechargement par heure, et au plus `max_par_jour` nouveaux appareils par jour (départ : 3).

## 6. Garde-fous

1. **Désactivé par défaut dans le paquet** (`ajout_auto = false` dans `etat.json`) : une mise à jour ne change jamais le DNS toute seule. Activé par l'administrateur dans le
   panneau (sur gk2, à la demande du propriétaire, après déploiement).
2. **Plafond quotidien** et **un rechargement par heure** (§5).
3. **Exclusions** : jamais la box elle-même, ni la passerelle, ni une adresse locale ; liste `ignores` (par MAC) alimentée par le bouton « Retirer et ne plus ajouter ».
4. **Retrait en un clic** depuis le panneau : l'appareil sort du périmètre (retour au puits de production) et sa MAC est ignorée.
5. **Journal d'audit** : chaque ajout, retrait et suivi d'adresse écrit une ligne (`/var/log/secubox/audit.log`) avec la preuve ; visible dans le journal du panneau.
6. **Aucune règle de blocage hors du profil de base** : les candidats appris ensuite suivent le cycle de #1954 (essai, confirmation).
7. Un appareil ajouté automatiquement porte `origine: "auto"` et reste distinguable de ceux déclarés par l'administrateur.

## 7. Données et API

`etat.json` gagne : `mode_defaut` (`off|observe|auto|block`, défaut `auto`), `ajout_auto` (booléen, défaut faux), `ignores` (liste de MAC) ; chaque client gagne
`mac` (optionnel), `origine` (`admin|auto`), `ajoute` (horodatage), `preuve` (texte court). Tout est revalidé par `valider_etat` (comme pour #1954).

Routes (`require_lecture` en lecture, `require_jwt` en écriture) : `GET /auto/detection` (appareils détectés, preuve, ajoutés ou non), `POST /auto/detection/reglage`
(`ajout_auto`, `mode_defaut`), `POST /auto/appareils/{nom}/ignorer` (retire et ignore). Le moteur reste la minuterie de #1954.

## 8. Panneau

Dans la carte « Mode automatique » : interrupteur « Ajout automatique », sélecteur « Mode par défaut » avec l'avertissement du §3 ; liste des appareils (badge
« ajouté automatiquement le … », preuve, adresses regroupées) avec « Retirer et ne plus ajouter » ; appareils détectés non ajoutés (plafond atteint, exclus) ; journal.
Rendu par `textContent` uniquement.

## 9. Tests

- Détecteur : rejeu d'événements issus des phases réelles E/P/C → la TV est détectée ; un téléphone qui ne demande que des services `contenu` sans insertion publicitaire
  ne l'est pas ; un pic isolé ne l'est pas ; la box, la passerelle et les adresses locales sont exclues.
- Ajout : nom unique et stable, règles de base créées confirmées, collision de nom refusée, plafond, un rechargement par heure, MAC ignorée jamais rajoutée.
- Suivi des adresses : nouvelle IPv6 rattachée, adresse vieille de 7 jours retirée, plafond de 32.
- Sécurité : donnée hostile (MAC, nom, domaine) jamais écrite dans la configuration Unbound ; `ajout_auto` faux ne modifie rien.
- Interface : navigateur réel, texte piégé, API absente.
- Essai réel sur gk2 avant de conclure : détection d'un appareil de test, ajout, application, retrait.

## 10. Livraison

`secubox-ad-guard` 1.5.0, documenté (HISTORY, WIP, README, TOML `[adblock_tv_auto]` : `min_declencheurs`, `min_services`, `min_fenetres`, `max_par_jour`), déployé par paquet sur gk2,
agrégateur redémarré (il sert le module dans son processus), vérifié **par l'adresse publique**. L'issue #1959 ne se ferme qu'après déploiement et validation du propriétaire.

## 11. Risques assumés

- Faux positifs (téléphone, ordinateur) : atténués par les garde-fous, pas supprimés ; le coût est qu'un appareil perde le puits de production et gagne 35 règles.
- Seuils non calibrés (un cas réel). À ajuster après quelques jours.
- Un appareil dont l'IPv6 de confidentialité change plus vite que le passage de la minuterie reste suivi avec un retard d'au plus une minute, plus un éventuel rechargement
  (≤ 1 par heure) : pendant ce délai, la nouvelle adresse est traitée comme un appareil inconnu (puits de production).
