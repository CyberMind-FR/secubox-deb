<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Peer Replication — versions, transfert vérifié, réconciliation (#3429, phase B)

CONCEPTION, non implémentée. Composants N6 (A21) et N8 (A22). Marquage : EXISTANT / À ÉTENDRE / NOUVEAU.

Arbitrages (`architecture.md` § 0, la vision du 2026-11-03 fait foi) : mirrornet transporte et vérifie des **objets
opaques**, l'adaptateur du module exporte et installe (décision 1) ; un `ConfigBlob` par **version de service**
(décision 2) ; la réplication est **automatique** (aucun geste) ; **aucune signature de contenu en A21** (décision 3
reportée) : l'authenticité d'une version est celle du **nœud source** dans le maillage (entrée d'annuaire signée par sa
box, transport WireGuard).

## 1. Ce qui existe et ce qui manque

| Élément | Statut | Référence |
|---|---|---|
| `ConfigBlob` signé (Ed25519 de la box), version monotone, `content_hash` BLAKE2b, `payload_uri` | EXISTANT | `secubox-annuaire/annuaire/model.py:538-575` ; verbe `verbs.py:1802-1823` |
| Réplication du journal par pull, signature vérifiée à l'ajout | EXISTANT | `annuaire/mesh_sync.py:146` (`sync_once`), `log.py:112-140` |
| Application 4R idempotente par version | EXISTANT | `annuaire/config_apply.py` |
| Récupération d'un `payload_uri` | ABSENT | aucun appelant (audit distribué E5) |
| Versions immuables + bascule atomique | ABSENT | audit distribué § 2 |
| Chaîne `parent` | ABSENT | `ConfigBlob` est dernier-écrivain-gagne (R1) |
| Helper d'extraction confinée | EXISTANT, reste **dans metablogizer** | `secubox-metablogizer/composants/publish/api/main.py:812` (`_extract_archive`) — `.claude/RULES-CODE.md` § 1 cite encore `secubox-publish/api/main.py` (à corriger) |

## 2. Version de service (NOUVEAU, décision 2)

Une version = une **archive** produite par l'adaptateur `exporter` (opaque pour mirrornet) + un **descripteur** :

```toml
service    = "toto"
module     = "metablogizer"
numero     = 7
parent     = "b2:9f…"          # empreinte de la version 6, "" pour la première
racine     = "b2:01…"          # empreinte de la version 1 : identité du contenu dans la durée
empreinte  = "b2:41…"          # BLAKE2b-256 de l'archive
taille     = 1834221
cree_le    = "2026-11-03T10:00:00Z"
origine    = "local:gk9"       # local:<nœud> | usb:<nœud>:<id-support>
sig_contenu = ""               # réservé à la signature de site (chantier ultérieur)
```

- Annonce : `ConfigBlob` scope `service.<nom>.v.<empreinte[:16]>`, écrit et **signé par la box du nœud source**,
  `payload` = descripteur, `payload_uri = mirrornet://<nœud>/objets/<empreinte>`. Seul le nœud **titulaire** du nom
  (`distributed-hosting.md` § 6) prolonge la chaîne servie sous le nom court ; les versions d'un nœud non titulaire
  restent attachées à son nom de nœud.
- Stockage : `/data/mirrornet/objets/<empreinte>` (immuable, 0640), **jamais extrait par mirrornet**.
- Installation : `installer` puis `activer` de l'adaptateur ; le module extrait sous son compte et dans son arbre
  (metablogizer : `/srv/metablogizer/sites`, `sbin/metablogizerctl:8`), versions côte à côte, bascule atomique
  (`rename(2)` d'un lien `courante`) chez lui ; plafonds de l'adaptateur : 20 000 entrées, quota, aucun lien sortant ni
  périphérique.

## 3. Transfert automatique (NOUVEAU)

```
copie élue (placement, distributed-hosting.md § 7)          source (nœud source ou toute copie qui a l'objet)
  │ mesh_sync : annonce service.toto.v.41…, entrée signée par un nœud enrôlé non révoqué ? sinon ignorée
  │ GET http://<ip-wg-mesh>:8471/objets/b2:41…  (wg-mesh seulement, pair enrôlé)
  │◀──────────────── flux de l'archive (Range pour reprise)
  │ BLAKE2b == empreinte annoncée ? sinon supprimer, audit, autre source
  │ parent connu ? sinon chercher la parente d'abord (§ 5)
  │ adaptateur : installer(empreinte) → activer(empreinte)   (refus → ancienne servie, audit)
  │ sonde déclarée par le module renvoie la nouvelle empreinte
```

- Aucun geste : une copie élue tire et installe d'elle-même ; un refus (quota, module absent) est annoncé et provoque
  un nouveau placement.
- Confiance : l'**annonce** est crue parce qu'elle est signée par la box d'un nœud enrôlé (niveau affiché ≥ LIMITED,
  filtrage effectif A22) ; l'**objet** est cru parce que son empreinte correspond, d'où qu'il vienne.
- Contrôle d'accès : nginx `:8471` sur l'IP wg-mesh seulement ; nft n'ouvre 8471 que sur `wg-mesh` ; refus d'une
  adresse absente de `pairs-enroles.json` (`secubox-pilotage/README.md:21`).
- Bande passante : un transfert à la fois par copie ; débit plafonné (défaut 4 Mo/s). Différentiel : après A21.
- Disque : refus si `/data` n'a pas `2 × taille` libre ; jamais sur la racine (gk2 > 90 %, R7).

## 4. Réconciliation (statique A21, autres types A22)

1. Une annonce non signée par la box d'un nœud enrôlé, ou émise par un nœud révoqué, est ignorée.
2. Même chaîne, copie en retard : elle **avance** (fast-forward), y compris quand le nœud source revient.
3. **Pas de divergence en A21** : seul le nœud titulaire prolonge sa chaîne. Une version d'un **autre** nœud au même nom
   est soit le même contenu (même empreinte ou même `racine` → miroir), soit une revendication concurrente traitée par
   la règle de conflit (`distributed-hosting.md` § 6), jamais une branche de la chaîne du titulaire.
4. Source révoquée : ses versions ne sont plus servies sous le nom court (suspendu) ; aucune autre version n'est
   promue d'office (`distributed-hosting.md` § 6.5).
5. Microblog (A22) : fusion des journaux par ordre déterministe ; doublon ignoré ; édition concurrente : deux révisions.
6. CMS (A22) : écritures au seul écrivain ; ancien écrivain revenu après promotion rétrogradé, écritures exportées,
   jamais fusionnées.

Chantier ultérieur (avec la signature de site) : chaîne prolongeable depuis plusieurs nœuds par le même propriétaire,
divergence au même parent résolue par l'ancêtre commun.

## 5. Rattrapage d'un nœud absent

Rejeu du journal (EXISTANT), reconstruction de la chaîne de chaque service depuis les annonces, téléchargement de la
tête (et des ancêtres manquants dans la limite de `garder`), purge au-delà.

## 6. Interfaces

| Interface | Statut |
|---|---|
| détection de publication : `GET <prefixe>/publications` de l'adaptateur (`distributed-hosting.md` § 4) | NOUVEAU, côté module |
| API adaptateur `exporter` / `installer` / `activer` / `desinstaller` / `etat` | NOUVEAU, côté module |
| `GET /api/v1/mirrornet/versions/{nom}` (chaîne, état par copie) `require_lecture` | NOUVEAU |
| `annuairectl config publish` pour les annonces | EXISTANT, appelé via l'API annuaire (`POST /config/...`, `secubox-annuaire/api/main.py`) |
| nginx `:8471/objets/<empreinte>` | NOUVEAU |

## 7. Risques

Nœud source compromis mais non révoqué : ses versions sont diffusées (limite assumée de l'A21 sans signature de
contenu ; révocation du nœud = remède, signature = chantier ultérieur). Archive volumineuse sur box 1 Go : extraction en
flux. Journal qui croît d'une annonce par version : purge au-delà de `garder` par `ConfigBlob` révoqué
(`POST /config/revoke`, EXISTANT `secubox-annuaire/api/main.py:839`).
