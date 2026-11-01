<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SBX TV PRIVACY — lot 3 « protection » (#3374)

Rendre la protection pilotable par un utilisateur lambda sans lui donner de quoi la durcir : modes nommés,
exceptions unifiées, journal des décisions, retour en un geste, bouton « Ça ne marche plus ? Je débloque »
(page /tv-privacy/ et webapp kiosque), analyseur agrégé côté serveur. Ni injection de publicité, ni contournement
des DRM, ni modification du flux vidéo. Message honnête affiché partout : « bloque les pubs que la TV va
chercher, pas celles qu'un service insère dans sa propre vidéo ».

## 1. Modes

| Nom (API, interface) | Valeur stockée dans `etat.json` | Effet |
|---|---|---|
| `OBSERVE` | `observe` | aucun blocage, journalisation |
| `PROTECT` | `block` | listes livrées en NXDOMAIN (l'ancien BLOCK) |
| `AUTO` | `auto` | règles apprises (essai, confirmé), garde du lot 2 |
| `OFF` | `off` | hors périmètre (puits de production) |

- Le stockage ne change pas : le contrôleur root, Unbound et les box existantes gardent `block`. **Aucune
  migration de mode** (gk2 reste en auto).
- `POST /mode` accepte `protect` (alias) et `block` ; toute réponse garde `mode` (valeur stockée, lisible par
  l'ancien code) et ajoute `mode_nom` (`OBSERVE`/`PROTECT`/`AUTO`/`OFF`). `dnstv.normaliser_mode`, `dnstv.nom_mode`.
- Défaut des nouvelles installations : `ETAT_DEFAUT.mode_defaut = "auto"` (déjà) **et** `ajout_auto = true`
  posé par la configuration du paquet (`[adblock_tv] ajout_auto_initial = true`, lu une seule fois quand `etat.json`
  n'existe pas encore). Une box qui a déjà un état garde le sien.

## 2. Exceptions unifiées (`api/dnstv_exceptions.py`)

Un seul modèle, `exceptions.json` (0640, `DOSSIER_ETAT`, écrit sous `dnstv_regles.verrou`, atomique) :

```json
{"version": 1, "exceptions": [{"mac": "aa:bb:cc:dd:ee:ff", "domaine": "x.example", "type": "autoriser|bloquer",
  "origine": "admin", "maj": 1793548800}]}
```

- `autoriser` (liste blanche appareil × domaine) : le moteur AUTO ne propose, n'essaie ni ne confirme plus ce
  domaine pour cet appareil ; une règle active de ce couple est retirée (origine admin) ; si l'appareil est en
  AUTO avec puits complet, l'autorisation au puits (`etat.autorisations`, #1965) est posée aussi (branchement).
- `bloquer` (liste noire par appareil) : règle `confirme` d'origine `admin` dans `regles.json` (le contrôleur
  l'applique et l'audite déjà). Retirer l'exception retire la règle.
- 500 exceptions au plus, 50 par appareil. MAC canonique, domaine validé, `extra=forbid`.
- Mécanismes existants, conservés et branchés en **lecture** dans la vue unifiée (`GET /protection/exceptions`) :
  autorisations au puits par appareil (source `puits`), suspects jugés légitimes (`/simple/suspects/legitime`,
  source `suspect-legitime`, toute la maison). **Hors champ, documentés** : liste blanche globale de `main.py`
  (table SQLite héritée, vide sur gk2) et `adult-exempt-ip/mac` (filtre adulte, autre finalité).

## 3. Journal des décisions (`api/dnstv_journal.py`)

- `decisions.jsonl` (0640) dans `DOSSIER_ETAT`, une ligne JSON par décision :
  `{ts, appareil (nom), mac (tronquée), domaine, categorie, action, origine, motif}`.
  `action` ∈ `blocage`, `deblocage`, `essai`, `confirmation`, `retrait`, `rejet`, `candidat`, `observe`, `pause`,
  `reprise`, `exception`. `origine` ∈ `auto`, `admin`, `usager`.
- Borné : 1 Mio ; au-delà, rotation vers `decisions.jsonl.1` (une génération). Écrit sous le verrou des règles.
- Les transitions de règles sont **déduites de l'historique de `dnstv_regles`** (`depuis_regles(avant, après)`) :
  moteur (`secubox-adguard-auto`) et routes passent par la même fonction.
- `GET /protection/journal` (`require_lecture_nominative`) : **agrégé par défaut** (appareil × domaine × action
  sur la fenêtre, comptes, premier/dernier horodatage) ; `detail=1` ligne à ligne, administrateur réel seulement.
- `GET /protection/journal.csv` (`require_jwt`) : export CSV (MAC tronquée, cellules neutralisées contre l'injection
  de formule).
- Audit : chaque geste qui change le DNS passe par le contrôleur (`apply`, `regles-appliquer`), qui écrit déjà
  `audit.log` (`audit_appareils`, `audit_transitions`) ; aucun nouveau verbe sudo.

## 4. Retour en un geste et pause minutée (`api/dnstv_protection.py`)

- `POST /protection/observe` `{"appareil": nom | null}` (`require_jwt`) : l'appareil (ou tous) passe en `observe`.
- `POST /protection/pause` `{"appareil": nom | null, "minutes": 15 | 60 | 240}` (`require_jwt`) : les appareils
  protégés passent en `observe` ; leurs modes d'avant sont gardés dans `pauses.json` avec l'échéance.
- `POST /protection/reprendre` `{"appareil": nom | null}` : reprise immédiate.
- Reprise automatique : `secubox-adguard-auto` (minuterie d'une minute) appelle `reprendre_echues` sous le verrou,
  restaure les modes, journalise `reprise` et demande `regles-appliquer` (audit).
- Une pause ne relance jamais un appareil que l'administrateur a changé entre-temps (mode courant ≠ `observe` : on
  oublie la pause sans rien restaurer).

## 5. Route lambda « Ça ne marche plus ? Je débloque »

- `GET /protection/usager/tv` : `[{id, nom, protege, pause_jusqu_a}]` — nom seulement, **jamais** MAC, IP ni domaine.
- `POST /protection/usager/debloquer` `{"tv": id | "toutes", "geste": "pause" | "observe", "minutes": 15|60|240}`.
- Garde : **`require_personne`** (AGENTS.md : garde d'usager posée explicitement). Elle refuse le tableau de bord
  anonyme (pas de session), l'invité, la session plafonnée, le jeton à portée et le porteur délégué du pilotage ;
  elle porte la garde d'origine pour le cookie. `require_session` admettrait l'invité : écarté.
- Bornes : seuls deux gestes, qui **relâchent** la protection ; aucun durcissement, aucune liste, aucun historique.
  Débit : 5 gestes / 10 min par porteur, 20 / 10 min pour la box (429 au-delà). Journal `origine=usager`
  (acteur = `sub` filtré) puis `apply` (audit root).
- Kiosque : servi par le maître, il appelle l'API **locale** (`/api/v1/ad-guard/...`, même origine) avec la session
  de l'usager ; il ne passe pas par le relais du pilotage. La route lambda n'est donc **pas** déclarée dans
  `routes-ouvertes.d` (le porteur délégué est d'ailleurs refusé par `require_personne`). Les routes admin
  `observe|pause|reprendre|exceptions` y sont déclarées pour la page relayée.

## 6. Constats terrain

- Référence : `license.oqee.net` DRM ; `api.oqee.net`, `img1.oqee.net`, `img2.oqee.net`, `stream.proxad.net`
  STREAMING (source « mesure gk2 2026-11-01 ») ; manifeste à jour.
- Suffixe de recherche : `dnstv.domaine_reel` retire `.home`, `.lan`, `.localdomain` ajoutés par la TV si le reste
  est un domaine valide à deux étiquettes au moins. Appliqué à l'ingestion (`Analyseur`) et à la classification,
  aux agrégats et au journal (données anciennes).
- Portée des corrections : un parent (ex. `free.fr`) vers une catégorie bloquable est refusé s'il couvre une
  entrée **protégée de `services.txt`** (en plus de la référence).
- Cache de classification : SQLite `classification-cache.db` (0640, remplacé atomiquement) au lieu d'un JSON de
  16 Mo relu à chaque appel (et tronqué à 16 Mio : cache perdu au-delà). Toutes les lectures sont des requêtes
  bornées (`LIMIT/OFFSET`, agrégats SQL).

## 7. Analyseur et événements agrégés (côté serveur)

- `GET /protection/analyse` (`require_lecture_nominative`) : paramètres fermés — `fenetre` ∈ `1h|24h|7j|30j`,
  `mac` (≤ 8, répétable), `categorie` (≤ 10), `decision` ∈ `bloque|autorise|candidat|protege` (combinables),
  `source`, `confiance_min/max` 0-100, `q` (sous-chaîne, ≤ 64, `[a-z0-9.-]`), `agreger` ∈
  `domaine|racine|categorie|appareil|aucun`, `decalage` ≥ 0, `limite` 1-200 (25 par défaut). Rend `metriques`
  (domaines distincts, requêtes, part bloquée, par catégorie, top 5 appareils et domaines, nouveaux), `agregats`
  (comptes et part bloquée, triés), `lignes` (page) et `total`. Lecteur non administrateur : MAC tronquée.
- `GET /protection/analyse.csv` (`require_jwt`) : le résultat filtré complet (borné à 50 000 lignes).
- `GET /protection/evenements?heures=1|24` : requêtes récentes agrégées par appareil × domaine réel (occurrences,
  premier, dernier, décision dominante, nouveauté), triées blocages puis nouveautés puis fréquence ; `detail=1`
  (administrateur) donne les lignes de chaque groupe.
- Fenêtre : filtre sur la dernière observation ; les compteurs du cache sont ceux de 30 jours (jour UTC), dit dans
  l'interface. « Nouveau » : première observation dans la fenêtre.

## 8. Vues de /tv-privacy/

- Coque de l'administration : `/shared/sidebar.js` et `sidebar-light.css`, entrée « SBX TV Privacy » sélectionnée,
  hors `?embed=1` et démonstration ; CSP `script-src 'self' 'sha256-…'`, `style-src 'self' 'sha256-…'`.
- Vue générale : événements agrégés (1 h / 24 h) ; bouton « Ça ne marche plus ? Je débloque ».
- Analyseur : métriques, filtres retirables un à un, agrégats dépliables, listing paginé côté serveur (25 par page).
- Protection : modes par appareil (OBSERVE / PROTECT / AUTO), retour en OBSERVE (un ou tous), pause 15 min / 1 h /
  4 h et reprise, exceptions (ajout, retrait), journal agrégé, export CSV.
- Diagnostic : erreurs DNS récentes (agrégées), autorisations et exceptions, pauses en cours, derniers retraits.
- Texte réseau toujours par `textContent`.

## 9. Webapp kiosque

Carte « Ça ne marche plus ? Je débloque » dans l'écran Sécurité : choix de la TV (par nom) ou « toutes les TV »,
pause 15 min / 1 h / 4 h ou « repasser en observation », retour visuel (« protection en pause pour TV salon
pendant 1 h »), message honnête. Garde utilisateur bornée côté API.

## Passe 2 (après relectures)

- **Audit (S2)** : chaque geste (pause, observe, reprise, exception) passe AVANT toute écriture par le verbe root borné
  `secubox-adguard-tv audit-protection` (JSON sur l'entrée standard : `acteur`, `origine` usager|admin|auto, `geste`, `cibles`,
  `minutes`, `domaine`, `type`, revalidés par root ; sudoers étendu). Un audit impossible refuse le geste (502). La reprise
  automatique est auditée au mieux (acteur « moteur ») : elle rétablit la protection et n'est jamais bloquée par l'audit.
- **Je débloque (S3, décision du propriétaire)** : l'usager ne fait qu'une PAUSE de 24 h au plus (15 min, 1 h, 4 h, 24 h), reprise
  automatique. Le retour en OBSERVE sans échéance est réservé à l'administrateur (onglet Protection).
- **Lecteur délégué (S1)** : `/protection/evenements` et `/protection/diagnostic` ne rendent ni l'adresse du client ni le motif
  (qui nomme l'acteur) à un lecteur qui n'est pas administrateur réel.
- **Exceptions (S4, I1)** : `exceptions.json` est écrit avant l'application et restauré si elle échoue. Une exception a un effet en
  AUTO comme en PROTECT, selon le mode EFFECTIF (pause comprise) : en PROTECT, l'appareil reçoit une vue propre
  `sbx-tv-block-<slug>` où « autoriser » prime sur la liste livrée (zone transparente) et « bloquer » ajoute une zone NXDOMAIN ;
  les appareils PROTECT sans exception gardent la vue commune. OBSERVE sans pause : « bloquer » est refusé (422, aucun effet) ;
  OFF : refusé. Plafond d'autorisations : 409 explicite. Bloquer une catégorie protégée autre qu'INCONNU exige `force`.
- **Première installation (I2)** : le postinst (`configure`, `$2` vide, aucun `etat.json`) pose l'état initial (AUTO, ajout
  automatique selon `ajout_auto_initial`) ; un état absent ne l'active jamais ; une mise à niveau ne change rien.
- **« Nouveaux » (I3)** : non calculé (None) pour 1 h et 24 h, la première vue étant au jour UTC.
- Mineurs : cache SQLite corrompu = `cache: false` ; ménage des temporaires orphelins et de l'ancien JSON à chaque passage du
  moteur (et par le postinst) ; un changement de mode oublie la pause ; `.a-appliquer` posé à la reprise avant la réécriture des
  pauses ; `sub` absent = 403 ; le débit ne décompte que les gestes appliqués.

### Reportés

- M1 : les données anciennes à suffixe `.home` de `dnstv_counts` restent des domaines distincts dans le cache de l'analyseur (les
  nouvelles sont rattachées à l'ingestion ; elles disparaissent avec la rétention de 30 jours).
- M2 : journal, un pas peut manquer quand l'historique d'une règle est saturé (10) et qu'une transition tombe à la même seconde.
- M7 : sans objet depuis I2 (le TOML n'est plus lu par `lire_etat`, seulement par le postinst).
- Doute 4 : la liste d'usager montre tout le périmètre hors `off` (enceinte comprise) ; filtrer par profil TV plus tard.
- Doute 5 : kiosque sans ad-guard : masquer la carte si `/protection/usager/tv` répond 404.

## Versions

`secubox-ad-guard` 1.20.0-1~trixie1 ; `secubox-kiosque` 0.3.0-1~trixie1.
