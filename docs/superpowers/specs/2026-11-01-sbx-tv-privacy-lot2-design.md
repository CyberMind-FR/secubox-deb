<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBX TV PRIVACY — lot 2 « taxonomie unique » (#3374)

Une seule taxonomie pour classer ce qu'une TV demande, une garde de sûreté sur le moteur AUTO, et une
API de lecture et de correction. Ni injection de publicité, ni contournement des DRM. Aucun nouveau moteur :
on réutilise les listes livrées (`lists/*.txt` + manifeste), `services.txt`, le profil de base et les règles.

## Les 10 catégories (`api/dnstv_taxonomie.py`)

`PUBLICITE`, `TRACKING`, `TELEMETRIE`, `STREAMING`, `CDN`, `DRM`, `AUTHENTIFICATION`, `MISE_A_JOUR`,
`SERVICES_CONSTRUCTEUR`, `INCONNU`.

Catégories **protégées** (jamais bloquées par le moteur AUTO) : `STREAMING`, `CDN`, `DRM`,
`AUTHENTIFICATION`, `MISE_A_JOUR`, `INCONNU`.

### Correspondance depuis les taxonomies existantes

| Ancienne valeur | Origine | Nouvelle |
|---|---|---|
| `advertising` | `dnstv.CATEGORIES` | PUBLICITE |
| `tracking` | `dnstv.CATEGORIES` | TRACKING |
| `telemetry` | `dnstv.CATEGORIES` | TELEMETRIE |
| `social` | `dnstv.CATEGORIES` (widgets sociaux = pistage) | TRACKING |
| `custom` | liste de l'exploitant (faite pour bloquer) | PUBLICITE |
| `contenu` | `TYPES_SERVICE` | STREAMING |
| `publicite` | `TYPES_SERVICE` | PUBLICITE |
| `mesure_audience`, `analytique` | `TYPES_SERVICE` | TRACKING |
| `qualite_video` | `TYPES_SERVICE` (NPAW, Quanteec : mesure de QoS) | TELEMETRIE |
| `cdn` | `TYPES_SERVICE` | CDN |
| `connectivite`, `systeme` | `TYPES_SERVICE` | SERVICES_CONSTRUCTEUR |
| `inconnu` | `TYPES_SERVICE` | INCONNU |
| `analytics` | `main.AdCategory` | TRACKING |
| `malware`, `cryptominer` | `main.AdCategory` (hors périmètre vie privée) | INCONNU |

Les anciennes valeurs restent dans les réponses (`categorie` de `/stats`, `/live`…) ; la nouvelle s'ajoute.

## Schéma d'une classification

```json
{"domaine": "k7.ftven.fr", "mac": "aa:bb:cc:dd:ee:ff" | null, "categorie": "STREAMING",
 "source": "liste", "confiance": 90, "derniere_observation": 1793548800 | null,
 "ancienne": "contenu" | null, "protegee": true}
```

- `source` ∈ `liste` / `apprentissage` / `ndpi` / `manuelle` / `profil`. `ndpi` est réservé : aucun flux
  nDPI → ad-guard n'existe (audit) ; rien ne l'émet au lot 2.
- Ordre de décision : correction **manuelle** (par MAC, puis globale ; confiance 100) ; sinon suffixe le plus
  long parmi la référence TV (`lists/reference-tv.txt`, 90), les listes livrées (80) et `services.txt` (70),
  la référence gagnant à suffixe égal ; sinon **profil** de base (`profil-tv-base.txt`, PUBLICITE, 70) ;
  sinon **apprentissage** (domaine présent dans les règles, INCONNU, confiance = score de la règle) ;
  sinon INCONNU, source `liste`, confiance 0.
- L'apprentissage ne donne jamais de catégorie bloquable : sinon il se justifierait lui-même.
- `derniere_observation` : `MAX(ts)` de `dnstv_recents` et dernier jour de `dnstv_counts` pour les adresses
  de l'appareil.

## Référence TV (`lists/reference-tv.txt`, au manifeste)

Format `suffixe CATEGORIE  # source`. Uniquement des domaines sourcés dans le dépôt :
- 7 domaines France TV « nécessaires à la lecture » (`docs/poc-dns-adblock-tv-results.md` §8) → STREAMING ;
- dépôts de mises à jour nommés dans `secubox-nac/api/osdetect.py` (`windowsupdate.com`,
  `deb.debian.org`, `archive.ubuntu.com`) → MISE_A_JOUR ; `samsungotn.net` (Samsung OTN) → MISE_A_JOUR ;
- CDN génériques de `dnstv_detect.LISTE_NOIRE` (`cloudfront.net`, `akamaized.net`, `akamaiedge.net`) → CDN.

**DRM et AUTHENTIFICATION : aucune entrée.** Aucun domaine Widevine, PlayReady ou FairPlay n'est
cité dans le dépôt ni mesuré au banc ; on n'invente rien. Ces domaines restent INCONNU, donc protégés.

## Garde de sûreté

`dnstv_taxonomie.blocage_auto_permis(categorie)` est faux pour les 6 catégories protégées. Elle est
appliquée aux **passages automatiques vers un état bloquant** (essai ou confirmé), et à eux seuls :

1. `dnstv_auto.tick` : candidat détecté → essai automatique (`auto_essai`) ;
2. `dnstv_auto.tick` : candidat agrégé (« confirmé sur N appareils ») → essai automatique ;
3. `dnstv_auto._confirmer_les_essais_echus` : essai → confirmé (`confirmation_auto`) ; un essai protégé
   n'est pas confirmé, l'expiration normale le retire ;
4. `dnstv_profil.equiper` (ajout automatique d'un appareil) : un domaine protégé du profil n'est pas posé.

Les **propositions** (candidats) restent : un humain décide. Le mode `block` (listes) et toute action
de l'administrateur (`origine="admin"`) sont inchangés. Une correction manuelle de catégorie (vers PUBLICITE,
TRACKING, TELEMETRIE, SERVICES_CONSTRUCTEUR) rend de nouveau un domaine éligible au moteur AUTO.

`tick(…, taxo=None)` : sans taxonomie fournie, la catégorie vient du classeur des listes déjà passé
(`classer`) via la correspondance ; `secubox-adguard-auto` fournit la taxonomie complète (référence,
services, profil, corrections manuelles).

## Corrections manuelles (`classification.json` dans `DOSSIER_ETAT`)

```json
{"version": 1, "manuelles": [{"domaine": "x.example", "mac": "", "categorie": "PUBLICITE", "maj": 1793548800}]}
```

`mac` vide = toute la maison. 2000 entrées au plus. Lecture `O_NOFOLLOW` revalidée, écriture atomique
(`mkstemp` + `os.replace`) sous `dnstv_regles.verrou`. MAC tronquée dans les journaux.

## Routes

- `GET /adblock-tv/classification?mac=&categorie=&limite=` — `require_lecture`. Domaines observés
  (récents, 30 jours de `dnstv_counts`), domaines des règles et corrections manuelles, avec la
  classification ci-dessus. Rend aussi `categories` et `protegees`.
- `POST /adblock-tv/classification` — `require_jwt`. Corps `{"domaine", "categorie" | null, "mac" | null}`,
  `extra=forbid`, domaine validé par `dnstv.valider_domaine`, catégorie de la liste ; `null` retire la
  correction. Aucun effet DNS immédiat : le moteur AUTO en tient compte au passage suivant.

## Version

`secubox-ad-guard` 1.18.0-1~trixie1.
