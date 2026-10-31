<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Droits du maillage conditionnés aux abonnements (#3305)

Décisions du propriétaire (2026-10-31) : un service du maillage n'est rendu à une box que si son abonnement est **actif** et que
sa **formule l'inclut** ; formule interne **« atelier »** (tous services) pour gk2 et les box de l'atelier ; box sans abonnement
au déploiement : **5 jours de grâce**, puis coupure.

## 1. Inventaire des échanges du maillage (wg-mesh 10.10.0.0/24)

| Échange | Fichier | Sens | Point de contrôle fournisseur | Décision |
|---|---|---|---|---|
| Offres de services (`GET :8799/api/v1/annuaire/services`) | `secubox-annuaire/api/main.py`, `nginx/annuaire-mesh.conf.tpl` | pair → fournisseur (tirage) | route `/services` (pair marqué `X-SecuBox-Maillage`, adresse `X-Real-IP`) | **service `annuaire-offres`** |
| Réplication du journal (`GET :8799/…/log/export`) : offres, souscriptions, **bans** (`ban_publish`/`ban_revoke`), nœuds, configs, assistance | `annuaire/verbs.py:export_entries`, `annuaire/mesh_sync.py` | pair → fournisseur (tirage) | route `/log/export` : **filtrage par opération** | `ban_*` ⇒ **`bans-waf`** ; `service_*` ⇒ **`annuaire-offres`** ; nœuds, configs, identités, assistance : socle, jamais coupés (administration) |
| Application de l'union des bans en nft | `annuairectl bans-apply`, `annuaire/threatmesh.py` | local (box) | — | côté box : sans `bans-waf`, seules les bans **de la box elle-même** sont appliquées |
| Dépôt OpenPGP inter-box (`POST :8799/…/openpgp/boite/depot`, `GET …/openpgp/annuaire/export`) | `composants/openpgp` | pair → destinataire | démon openpgp | identifiant **`openpgp`** réservé — application : point ouvert |
| Macro (sortie Tor, etc.) `POST :8798/api/v1/p2p-macro/grant/<id>` | `secubox-p2p` (`macro_grant.py`) | consommateur → fournisseur | route grant | identifiant **`macro`** réservé — application : point ouvert |
| Relevés de flotte (`/fleet/self`, `/fleet/modules/self`, `/noeud/adresses`) | `secubox-annuaire` | maître → box | — | supervision du maître, **jamais coupée** |
| Canal de pilotage `:8472` | `secubox-pilotage` | box → maître | — | administration, **jamais coupée** |
| Tunnel Auto-Load `:8470` (wg-autoload 10.64.0.0/16) | `secubox-autoload` | box → hub | `livraison_autorisee` | déjà conditionné à l'abonnement (#3303) |
| Flux de menaces publics (`secubox-threatfeed`) | `secubox-threatmesh` | Internet → box | — | hors maillage, non concerné |

## 2. Plan

1. **Auto-Load** (source de vérité, sur le maître) : `SERVICES_MAILLAGE = (annuaire-offres, bans-waf, openpgp, macro)` ;
   colonne `services` des formules ; formule `atelier` semée (tous services) ; table `abonnements_maillage` (pair du maillage
   par nom + empreinte → formule, statut, échéance, ou rattachement à une box Auto-Load) ; début de grâce mémorisé à la première
   migration ; `autoloadctl maillage-formule` et routes `GET/POST /maillage` ; projection publique root
   `autoload-public/droits-maillage.json` écrite avec `pairs-publics.json`.
2. **Annuaire** (fournisseur) : `annuaire/droits.py` — décision par adresse source → pair enrôlé (`p2p-public/pairs-enroles.json`) →
   ligne de droits. Pas de projection sur la box : aucune politique (la box n'est pas le maître). Projection présente : pair sans
   droit ⇒ refus (403) et audit ; pair sans ligne ⇒ autorisé jusqu'à la fin de grâce. `/services` gardée par `annuaire-offres`,
   `/log/export` filtrée par opération ; nouvelle route `GET :8799/…/droits/self` (droits de l'appelant).
3. **Box** : `mesh_sync` relève `droits/self` du pair qui a une politique et le garde (`droits-self.json`) ; `bans-apply` n'applique
   l'union fédérée que si `bans-waf` est accordé (réponse de moins de 48 h) — sinon les seules bans de la box. Retour du droit :
   reprise au passage suivant.
