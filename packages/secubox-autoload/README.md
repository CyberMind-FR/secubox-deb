<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-autoload

Provisionnement réseau « Auto-Load », **côté infrastructure** (`admin.gk2.secubox.in`). Parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`. Ce paquet ne s'installe pas sur une box cliente (l'agent côté box viendra en `secubox-autoload-agent`).

**État (0.3.0) :** le registre des jetons clients (#2185), le tunnel WireGuard côté infrastructure (#2189) et le service d'enrôlement et de panel (#2190). La WebUI vient ensuite (#2191).

## Jetons

- Un jeton **par box** : 128 bits aléatoires, préfixe `gk2_` (un jeton qui fuit se repère), soit `gk2_` + 32 caractères hexadécimaux, affichés **une seule fois** à l'émission, stockés sous forme d'**empreinte SHA-256**.
- **Usage unique** : la réclamation consomme le jeton et lie la box à sa **clé publique WireGuard** (générée sur la box, jamais dans l'image). Une même clé ne peut pas porter deux jetons.
- États : `emis` → `reclame`, ou `revoque` (à tout moment). Durée de vie avant réclamation : 90 jours par défaut, 365 au plus.
- **Abonnement par client** (`actif`, `suspendu`, `revoque`) : non actif = réclamation et nouvelles livraisons refusées. Une box déjà en service **garde toutes ses fonctions locales**.
- **Refus uniforme** : inconnu, expiré, déjà pris, révoqué, abonnement non actif, mauvaise clé : toujours « jeton refusé ». La vraie raison est dans l'audit.
- **Série préenregistrée** : un client « déjà pré-évalué » est préenregistré par numéro de série ; sa box reçoit son jeton à la volée (`reclamer_par_serie`), une seule fois.
- **Révocation** d'un jeton ou d'un lot ; sur un jeton déjà réclamé, rend la clé publique à retirer du tunnel (#2189).

## Tunnel (0.2.0, #2189)

Étoile : chaque box ouvre un tunnel WireGuard **sortant** vers ce hub (interface `wg-autoload`).

- Plage **10.64.0.0/16** (hub 10.64.0.1), **UDP 51830** ; distincte de `wg-mesh` (10.10.0.0/24, 51822) et `wg-ephemeral` (10.11.0.0/24, 51825).
- Un pair n'a droit qu'à **sa propre adresse /32** : les clients ne se voient pas.
- Adresses attribuées de façon idempotente et atomique ; une adresse ou une clé **retirée n'est jamais réattribuée** (une clé retirée exige un nouveau jeton).
- La clé privée du hub n'est **jamais** dans la configuration : `PostUp = wg set %i private-key /etc/secubox/secrets/autoload-hub.key` (0600).
- `autoloadctl tunnel-sync` valide (`wg-quick strip`), pose `wg-autoload.conf` atomiquement (0600) puis `wg syncconf` : aucun pair existant n'est coupé ; en cas d'échec l'ancienne configuration reste.
- Pare-feu : l'infrastructure ouvre UNIQUEMENT udp/51830 en entrée (règle à poser avec le service d'enrôlement, #2190).

## Service d'enrôlement et panel (0.3.0, #2190)

Deux applications dans un processus (`/usr/sbin/secubox-autoload-api`), utilisateur dédié `secubox-autoload`, unité durcie, profil AppArmor enforce.

**Publique** (socket `/run/secubox/autoload.sock`, derrière nginx sur `admin.gk2.secubox.in`, préfixe `/api/v1/autoload`) :

| Route | Garde | Rôle |
|---|---|---|
| `POST /enrol` | **le jeton est la preuve** (publique assumée) | `{jeton|serie, cle_pub}` → `{client, profil, lot, tunnel}` ; refus uniforme 403 ; 10 essais refusés par 10 min et par source (429) ; la même clé peut rejouer après une coupure |
| `GET /health` | sonde | `{ok}` |
| `GET /boxes`, `/jetons`, `/prerapports`, `/prerapports/{empreinte}` | `require_lecture` | suivi : statut (en attente, préparation, en cours, terminé, révoqué) et progression en %, jamais la valeur d'un jeton |
| `POST /jetons` | `require_jwt` | `{client, profil, lot?, serie?, duree_jours}` → la valeur `gk2_…`, montrée **une seule fois** |
| `POST /jetons/{id}/revoquer` | `require_jwt` | révoque, retire le pair du tunnel et l'applique |
| `POST /clients/{client}/abonnement` | `require_jwt` | `{statut, mois?, formule?}` (échéance calendaire) |
| `POST /series` | `require_jwt` | préenregistre un numéro de série |
| `POST /prerapports/{empreinte}/refuser` | `require_jwt` | refuse un pré-rapport pendant le délai de grâce |

**Tunnel** (TCP `10.64.0.1:8470`, uniquement dans WireGuard, `IP_FREEBIND`) : `POST /progression`, `POST /prerapport`, `GET /prerapport/{empreinte}/refus`. L'identité de la box est l'**adresse source de la connexion** (WireGuard ne laisse passer d'un pair que sa propre adresse) ; aucun en-tête n'est cru, et ces routes n'existent pas dans l'application publique.

Le service n'est pas root : il dépose `sync.demande`, l'unité root `secubox-autoload-sync` (CAP_NET_ADMIN seulement) lance `autoloadctl tunnel-sync` et rend l'accusé `sync.fait`.

Pare-feu : `udp/51830` en entrée et `tcp/8470` depuis `wg-autoload` seulement (`/etc/nftables.d/zz-secubox-autoload.nft`). La **redirection udp/51830 de la Freebox vers gk2** est à faire à la main. Journal d'audit : `/var/log/secubox/autoload-audit.log`.

## Audit

Chaque émission, réclamation, refus (avec la raison), révocation et changement d'abonnement est ajouté à `/var/log/secubox/audit.log` (JSON, module `autoload`). **Jamais la valeur d'un jeton.**

## Commandes (root)

    autoloadctl emettre --client client-042 --profil lite [--lot lot-2026-10] [--serie S] [--duree-jours 90]   # la valeur est imprimée une fois
    autoloadctl preenregistrer --serie SBX-0001-AB --client client-042 --profil isp
    autoloadctl lister [--etat emis|reclame|revoque] [--client C] [--lot L] [--json]
    autoloadctl revoquer (--id N | --lot L) --motif "…"
    autoloadctl abonnement --client client-042 --statut suspendu
    autoloadctl tunnel-init      # clé du hub (0600) ; affiche sa clé publique
    autoloadctl tunnel-sync      # applique les pairs actifs (wg syncconf)

Données : `/var/lib/secubox/autoload/jetons.db` (0600, dossier 0750). Variables : `SECUBOX_AUTOLOAD_DB`, `SECUBOX_AUTOLOAD_AUDIT` (tests).

## Tests

    python3 -m pytest packages/secubox-autoload/tests
