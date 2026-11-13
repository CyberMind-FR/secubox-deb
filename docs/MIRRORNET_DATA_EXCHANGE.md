<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MirrorNet v1 — Plan 3 : échange de données

Issue #3643 · **CONCEPTION** · marquage EXISTANT / À ÉTENDRE / NOUVEAU (voir `MIRRORNET_ARCHITECTURE.md`).

Un **jeu de données** est une offre (`ServiceOffer`, `kind = "dataset"`) dont le contenu est une suite de **versions
immuables** : un manifeste signé + des objets opaques adressés par empreinte. C'est le mécanisme de « version de
service » déjà conçu pour l'hébergement (`docs/mirrornet/replication.md` § 2), appliqué à des données.

## 1. Ce qui existe

| Brique | Référence | Statut |
|---|---|---|
| `ConfigBlob` signé, versionné, avec `payload_uri` | `secubox-annuaire/annuaire/model.py:538-575` | EXISTANT ; `payload_uri` sans appelant |
| Journal répliqué par pull, chaîné BLAKE2b | `annuaire/log.py`, `annuaire/mesh_sync.py` | EXISTANT |
| Relevés signés de flotte (métriques, modules, état) | `MetricSnapshot`, `ModulesSnapshot`, `StatusSnapshot` | EXISTANT — premier flux de données maillé |
| Bans fédérés signés | `BanRecord` (`model.py:723`) | EXISTANT |
| Objets opaques `/data/mirrornet/objets/<blake2b>`, écoute `:8471` | `docs/mirrornet/replication.md` § 2-3 | CONÇU (A21), NOUVEAU |
| Droits du maillage par pair | autoload #3305 | EXISTANT |

## 2. Classes d'accès

| Classe | Qui peut s'abonner | Où vit le contenu | Données personnelles | Statut |
|---|---|---|---|---|
| `public` | tout nœud non révoqué ; publiable au-delà du maillage | fournisseur + copies + caches | **interdites** | NOUVEAU |
| `communaute` | membres (MEMBER, niveau ≥ LIMITED) | fournisseur + copies + caches des membres | interdites sauf agrégées/anonymisées | NOUVEAU |
| `specialise` | abonnés approuvés (approbation PENDING) | fournisseur + copies chez abonnés | interdites sauf base légale déclarée | NOUVEAU |
| `professionnel` | abonnés approuvés sous contrat (référence de contrat dans l'abonnement) | fournisseur + abonnés, **pas** de cache tiers | selon contrat, base légale obligatoire | NOUVEAU |
| `prive` | **aucun abonnement externe** : organisation du fournisseur seulement | fournisseur seul | possible, jamais redistribuées | NOUVEAU |

Règle d'or : **la classe est imposée à la source** (le fournisseur la signe dans le manifeste) **et revérifiée à
l'abonnement** (le nœud qui reçoit refuse ce que sa classe interdit, par exemple un cache tiers d'une donnée
`professionnel`). Une donnée `prive` n'a jamais de `payload_uri` accessible hors du fournisseur.

## 3. Manifeste d'une version (NOUVEAU)

Annoncé comme `ConfigBlob` de scope `dataset.<service_id>.v.<empreinte16>`, signé par le fournisseur :

```toml
dataset      = "meteo-gk6"          # identifiant lisible, unique chez le fournisseur
service_id   = "9f3c…"              # l'offre (kind = dataset)
version      = 412                  # entier croissant
parent       = "b2:…"               # version précédente ("" pour la première)
empreinte    = "b2:…"               # BLAKE2b-256 de l'objet (archive ou fichier)
taille       = 18234
format       = "application/x-ndjson"
schema       = "b2:…"               # empreinte d'un schéma JSON publié comme objet (facultatif)
licence      = "ODbL-1.0"           # SPDX, obligatoire
provenance   = "capteur:gk6/bme280" # source déclarée ; « dérivé:<empreinte> » pour une donnée enrichie
classe       = "communaute"
fraicheur_s  = 600                  # âge maximal attendu entre deux versions
qualite      = { completude = 0.98, methode = "auto" }   # déclarée par le fournisseur, jamais une note décernée
cree_le      = "2026-11-10T06:00:00Z"
donnees_personnelles = "non"        # non | agregees | base_legale:<référence>
```

- **Provenance** : chaîne `parent` + `provenance` ; une donnée dérivée cite l'empreinte de sa source. Toute version est
  signée par le did du fournisseur ; rien n'est accepté sans signature valide et non révoquée.
- **Fraîcheur** : un abonné calcule `maintenant - cree_le` ; au-delà de `fraicheur_s` × 2, le jeu est « périmé »
  (affiché, et non facturé à l'usage pour la période — `MIRRORNET_ECONOMY.md` § 5).
- **Qualité** : indicateurs déclarés + indicateurs mesurés par les abonnés (fraîcheur réelle, disponibilité, versions
  invalides) ; pas de note subjective en v1.

## 4. Transfert, synchronisation, cache

```mermaid
sequenceDiagram
  autonumber
  participant P as Fournisseur gk6
  participant J as Journal
  participant R as Copie / cache (gk2)
  participant A as Abonné gk12
  P->>P: nouvelle version → objet /data/mirrornet/objets/<b2>
  P->>J: ConfigBlob dataset.<id>.v.<b2:16> (manifeste signé)
  J-->>A: pull (60 s)
  A->>A: abonnement Actif ? classe compatible ? version > courante ?
  alt cache autorisé par la classe et disponible
    A->>R: GET :8471/objets/<b2> (wg-mesh)
  else
    A->>P: GET :8471/objets/<b2>
  end
  A->>A: vérifie empreinte BLAKE2b + taille ; rejette sinon (audit)
  A->>A: installe chez le module consommateur (adaptateur) ; garde N versions
  A-->>P: accusé de réception signé (base du relevé d'usage)
```

- Les objets sont **opaques** pour `secubox-mirrornet` (jamais extraits, `docs/mirrornet/architecture.md` décision 1) ;
  le module consommateur extrait sous son compte et dans son arbre.
- **Cache distribué** : un nœud qui détient un objet peut le servir à un abonné **si la classe le permet** (`public`,
  `communaute`, `specialise`) ; il devient alors « relais » au sens de l'économie, prouvé par l'accusé signé de l'abonné.
- Synchronisation : par version entière (pas de diff en v1) ; reprise par empreinte ; conflit impossible (un seul
  écrivain : le fournisseur ; une version est immuable).
- Quotas : par jeu (`quota_mo` côté copie, `docs/mirrornet/distributed-hosting.md`) et par abonné (`quotas` de l'offre).

## 5. Exemples visés

| Jeu | Classe | Fournisseur type | Remarque |
|---|---|---|---|
| Observations météo locales | `public` | box avec capteur | aucune donnée personnelle |
| Cartographie locale (tuiles, POI) | `public` / `communaute` | box communautaire | licence ODbL |
| Renseignement réseau (bans, IoC) | `communaute` | toute box (sbxwaf) | déjà en partie : `BanRecord` |
| OSINT enrichi | `specialise` | box experte | jamais de données personnelles brutes |
| Supervision d'infrastructure | `prive` / `professionnel` | organisation | sous contrat |

## 6. Vie privée

- Le manifeste déclare `donnees_personnelles` ; `public` et `communaute` les refusent à la publication (contrôle à la
  source) et à l'abonnement (contrôle à la réception).
- `base_legale:<référence>` obligatoire pour `specialise`/`professionnel` contenant des données personnelles ; la
  référence est affichée à l'abonné avant l'abonnement.
- Retrait : une version peut être **retirée** (`ConfigBlob` de retrait signé) ; les copies et caches la suppriment à
  réception ; l'abonné est notifié. L'immutabilité d'une version ne vaut que pour son intégrité, pas pour sa durée de vie.

## 7. API (NOUVEAU, `/api/v1/mirrornet/`)

| Route | Garde | Rôle |
|---|---|---|
| `GET /datasets` | `require_lecture` | catalogue local des jeux (filtré : confiance, classe) |
| `GET /datasets/{id}` | `require_lecture` | offre + dernière version + fraîcheur mesurée |
| `GET /datasets/{id}/metadata` | `require_lecture` | manifestes (versions, schéma, licence, provenance) |
| `POST /datasets/publish` | `require_jwt` | publie une version (objet déjà produit par l'adaptateur du module) |
| `POST /datasets/{id}/subscribe` | `require_jwt` | abonnement (même cycle de vie que les services) |
| `POST /datasets/{id}/retract` | `require_jwt` | retrait d'une version (fournisseur) |

Objets entre pairs : `GET :8471/objets/<empreinte>` (écoute maillée, pairs enrôlés seulement, droits vérifiés par
`secubox-mirrornet` avant service).
