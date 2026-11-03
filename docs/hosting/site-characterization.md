<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Caractérisation d'un site distribué (#3420, phase 2) — PROPOSITION, NON IMPLÉMENTÉE

Fondée sur l'audit `docs/audit/distributed-hosting-audit.md`. Rien ici n'est codé ; chaque choix
marqué **[arbitrage]** attend le propriétaire.

Principe directeur : **un site appartient à son propriétaire, pas à son serveur.** La box qui sert
un site n'en est qu'une dépositaire ; l'autorité est la signature du propriétaire sur une version.

## 1. Conventions reprises

- Configuration en **TOML** sous `/etc/secubox/` ; noms de champs en **français** (convention de
  `premier_pas/provision.py`, `relais-maillage.toml`, `annuaire/droits.py`).
- Identités `did:plc:` Ed25519 de l'annuaire ; signatures canoniques (`annuaire/crypto.py`).
- Réplication par **`ConfigBlob`** (`annuaire/model.py:538`) : un écrivain par scope, version
  monotone, `content_hash` BLAKE2b, `payload_uri` pour le volumineux, application 4R
  (`config_apply.py`). Aucun secret dans un blob.
- Tout trafic public : HAProxy → `sbxwaf` → nginx ; jamais de bypass hors `waf_bypass` déclaratif.

## 2. Manifeste de site

Fichier `/etc/secubox/sites/<nom>.toml`, publié dans le maillage comme `ConfigBlob` de scope
`site:<nom>` signé par **le propriétaire** (pas par la box). `site.json` de metablogizer reste le
manifeste d'affichage ; ses champs communs (name/domain/aliases/source_url) sont repris.

```toml
# /etc/secubox/sites/carnet.toml
[site]
nom          = "carnet"                      # [a-z0-9-], 63 au plus (comme site.json)
domaine      = "carnet.gk2.net"
alias        = ["www.carnet.gk2.net"]
categorie    = "statique"                    # statique | blog | microblog | cms | dynamique | api | media
proprietaire = "did:plc:…"                   # identité qui signe les versions
module       = "metablogizer"                # module qui sait servir cette catégorie

[source]
type         = "secubox"                     # secubox | usb | externe | serveur
reference    = "did:plc:…"                   # secubox : did de la box maître
# usb      : empreinte du support (voir § 5)
# externe  : "https://git…/carnet.git" + empreinte de clé de signature attendue
# serveur  : URL + empreinte TLS ou clé de signature attendue

[replication]
strategie    = "versions-atomiques"          # versions-atomiques | journal | maitre-ecrit | instantanes
repliques    = ["did:plc:…", "did:plc:…"]    # pairs autorisés à tenir une copie
minimum      = 2                             # copies vivantes visées
quota_mo     = 512                           # plafond disque par réplique, sur /data
garder       = 5                             # versions conservées

[disponibilite]
mode         = "lecture-seule-en-absence"    # lecture-seule-en-absence | promotion-manuelle
sante        = "/healthz"                    # sonde HTTP
delai_bascule_s = 120

[exposition]
waf_bypass   = false                         # reporté tel quel dans haproxy.toml ; défaut false
tor          = false
```

Champs exclus volontairement : clés privées, mots de passe, jetons (références `ref:/etc/secubox/secrets/…`
seulement, comme `provision.py`).

Version publiée : un second `ConfigBlob` de scope `site:<nom>:version` porte
`{numero, empreinte_contenu, payload_uri, parent, signe_par}`. Le `parent` (empreinte de la version
précédente) donne une **chaîne** : c'est ce qui permet de détecter une divergence au lieu de
l'écraser (§ 6).

## 3. Catégories et stratégies

| Catégorie | Stratégie | Disponibilité | Cohérence | Base existante |
|---|---|---|---|---|
| **statique** | `versions-atomiques` : archive immuable par version, adressée par empreinte ; chaque réplique la vérifie puis bascule un lien `courante` (swap atomique) | active-active en lecture (tous servent) | forte par version (même empreinte partout) ; pas d'écriture côté réplique | metablogizer, `metablog-sync`, `config_apply` |
| **blog** (statique généré) | idem statique ; la génération se fait chez le maître | active-active | idem | metablogizer |
| **microblog** | `journal` : événements signés et chaînés, rejoués par les répliques ; l'écriture reste au maître | lecture partout ; écriture au maître, ou **file locale** d'événements signés par l'auteur, fusionnée au retour **[arbitrage]** | causale (chaîne) ; fusion déterministe par (horodatage, did, empreinte) | `billets/api/services/eventlog.py` |
| **cms** (base de données) | `maitre-ecrit` par défaut : un seul écrivain ; répliques en **lecture seule** depuis des instantanés signés | répliques servent la dernière version en lecture seule ; promotion d'une réplique **manuelle** | forte côté maître ; retard borné côté répliques | `backupctl`, `pg_dump` ; pas de CMS PHP aujourd'hui |
| **dynamique** (streamlit…) | `maitre-ecrit` ; code versionné comme un statique, état applicatif non répliqué | redémarrable ailleurs sur promotion | pas d'état partagé garanti | streamlit LXC |
| **api** | `maitre-ecrit` ; active-active **seulement** si l'API se déclare sans état (`sans_etat = true`) | idem | à la charge de l'API | — |
| **media** | `versions-atomiques` par objet (fichiers immuables adressés par empreinte), index au maître | active-active en lecture | forte par objet | podcaster, peertube (PostgreSQL → `maitre-ecrit`) |

**ACTIVE-ACTIVE en écriture** : refusé par défaut pour toute catégorie avec base ; il ne s'ouvrirait
que sur une donnée prouvée convergente (journal à fusion déterministe). Pas de VRRP/keepalived : la
bascule est applicative (sonde + route), conformément à la décision du 2026-07-13.

### Répartition de charge sans point central

Trois couches, de la moins à la plus intrusive **[arbitrage sur l'ordre]** :

1. **Multi-cibles dans `sbxwaf`** : une route `hôte → [cibles]` avec sonde et repli (écart E1).
   Chaque box exposée sert le nom et relaie vers les répliques vivantes du maillage. Le WAF reste
   sur le chemin.
2. **Relais à plusieurs pairs** : `secubox-relais-maillage` accepte un groupe de pairs par nom
   (écart E2).
3. **DNS multi-A** avec retrait sur santé, par chaque box exposée sur ses propres enregistrements
   (écart E3) ; certificat obtenu par **chaque** box en DNS-01 (pas de clé privée partagée).

Tant qu'une seule box est sur Internet (gk2), (1) et (2) donnent la tolérance aux pannes des pairs,
pas celle de gk2 : le point central disparaît seulement avec (3) et au moins deux box exposées.

## 4. Source maître

| Type | Identité | Ce qui fait autorité |
|---|---|---|
| `secubox` | `did:plc:` de la box | la signature du **propriétaire** sur la version ; la box maître n'est que le lieu d'écriture habituel |
| `usb` | empreinte du support (§ 5) | fichier `site.toml` + archive, signature détachée du propriétaire |
| `externe` (git, Gitea) | URL + empreinte de clé de signature attendue | commits ou étiquettes **signés** ; un amont non signé n'est pas une source |
| `serveur` | URL + empreinte | archive signée |

La box qui « a » la source ne peut publier qu'une version signée par une clé du propriétaire
listée dans le manifeste ; elle ne devient jamais propriétaire du site.

## 5. Cycle de vie d'une source USB

Jamais de confiance parce que branché.

1. **Reconnaissance** : étiquette `SBXSITE` (modèle `SBXPROFIL`), montage en **lecture seule**,
   `nodev,nosuid,noexec`, par une unité root confinée, démonté après lecture.
2. **Identité du support** : fichier `support.toml` (identifiant aléatoire du support, propriétaire,
   date) signé par le propriétaire ; complété par le numéro de série USB **à titre indicatif
   seulement** (falsifiable).
3. **Signature** : chaque `site.toml` et chaque archive porte une signature détachée (OpenPGP via
   `gpgv` contre le trousseau du propriétaire, comme `provision.py`, ou Ed25519 du did) **[arbitrage :
   OpenPGP ou Ed25519]**.
4. **Intégrité** : empreinte BLAKE2b de l'archive vérifiée avant toute copie ; schéma TOML strict
   (clé inconnue = refus).
5. **Versions** : la clé porte des versions numérotées avec `parent` ; la box compare à la chaîne
   connue.
6. **Proposition de synchronisation** : la box **propose** dans la webui (« version 7 du site
   carnet trouvée sur la clé de X ; la publiée est la 6 ») ; l'adoption est un geste de l'usager,
   audité dans `/var/log/secubox/audit.log`.
7. **Révocation d'un support perdu** : le propriétaire publie un `RevocationNotice` (modèle annuaire
   existant, `model.py:361`) sur l'identifiant du support ; toute box du maillage refuse ensuite ce
   support, même avec des signatures valides antérieures à la révocation **[arbitrage : refuser
   aussi les versions déjà adoptées depuis ce support ?]**.

## 6. Réconciliation au retour du maître

Règles explicites, dans l'ordre :

1. Le maître annonce sa dernière version (numéro, empreinte, parent).
2. **Même chaîne, maître en retard** (les répliques ont une version plus récente signée par le
   propriétaire, ex. publiée depuis l'USB) : le maître **avance** (fast-forward), sans perte.
3. **Même chaîne, maître en avance** : les répliques avancent.
4. **Divergence** (deux versions au même parent, signées) : **aucun écrasement**. Les deux branches
   sont conservées ; le site reste servi sur la dernière version commune ou sur celle du maître
   **[arbitrage]** ; le propriétaire tranche dans la webui. Audit des deux empreintes.
5. **Microblog** : fusion des journaux par ordre déterministe ; un événement en double (même
   empreinte) est ignoré ; une édition concurrente du même billet → les deux révisions sont gardées,
   la plus récente affichée, l'autre visible en historique.
6. **CMS / base** : les écritures n'ont eu lieu qu'au maître (`maitre-ecrit`) ; si une réplique a été
   **promue** pendant l'absence, le maître revenant est **rétrogradé** en réplique et reçoit
   l'instantané de la promue ; ses écritures non répliquées sont mises de côté (export), jamais
   fusionnées automatiquement.
7. Toute version non signée par une clé du propriétaire est rejetée, d'où qu'elle vienne.

Note : `metablog-sync` (`git reset --hard`) et le dernier-écrivain-gagne de `ConfigBlob` ne
suffisent pas pour (4) : la chaîne `parent` est l'ajout nécessaire.

## 7. Découpage proposé

| Lot | Contenu | Avant bêta ? |
|---|---|---|
| **A** | Manifeste `site.toml` + schéma strict + objet propriétaire ; lecture seule, sans réplication | oui (petit, sans effet réseau) |
| **B** | Versions atomiques locales pour metablogizer (archive par empreinte, lien `courante`, retour arrière) | oui |
| **C** | Publication d'une version comme `ConfigBlob` signé + récupération par `payload_uri` + application 4R chez les répliques (statique seulement) | possible, si A et B sont stables |
| **D** | Multi-cibles avec sonde dans `sbxwaf` (WAF conservé) + relais à plusieurs pairs | après (touche le WAF de gk2, seul exposé) |
| **E** | Source USB : `SBXSITE`, identité de support, signature, proposition, révocation | après |
| **F** | Réconciliation par chaîne de versions (fast-forward, divergence conservée, arbitrage webui) | après |
| **G** | Microblog par journal (billets) et instantanés `maitre-ecrit` pour bases (CMS, peertube) | après |
| **H** | DNS multi-A avec retrait sur santé, certificats DNS-01 par box ; plusieurs box exposées | après, et seulement sur décision d'exposer d'autres box que gk2 |

## 8. Questions d'arbitrage

1. Signature des versions : OpenPGP du propriétaire (`gpgv`, déjà utilisé) ou Ed25519 du did ?
2. Le propriétaire d'un site est-il un did de **personne** (nouveau) ou le did d'une box ?
3. En divergence, quelle version servir en attendant la décision : dernière commune ou celle du
   maître ?
4. Microblog : autorise-t-on l'écriture hors maître (file locale fusionnée) ou lecture seule ?
5. Promotion d'une réplique de CMS : manuelle seulement, ou automatique après délai ?
6. Accepte-t-on d'exposer d'autres box que gk2 sur Internet (condition du « sans point central ») ?
7. Révocation d'un support : invalide-t-elle rétroactivement les versions adoptées depuis lui ?
8. Faut-il un CMS PHP (aucun aujourd'hui) ou s'en tenir à billets/bbs/metablogizer ?
