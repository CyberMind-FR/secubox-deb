<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-autoload

Provisionnement réseau « Auto-Load », **côté infrastructure** (`admin.gk2.secubox.in`). Parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`. Ce paquet ne s'installe pas sur une box cliente (l'agent côté box viendra en `secubox-autoload-agent`).

**État (0.1.0, #2185) :** le registre des jetons clients et sa CLI. Le point d'enrôlement HTTPS, le tunnel et le panel viennent avec #2189 à #2191.

## Jetons

- Un jeton **par box** : 128 bits aléatoires (32 caractères hexadécimaux), affichés **une seule fois** à l'émission, stockés sous forme d'**empreinte SHA-256**.
- **Usage unique** : la réclamation consomme le jeton et lie la box à sa **clé publique WireGuard** (générée sur la box, jamais dans l'image). Une même clé ne peut pas porter deux jetons.
- États : `emis` → `reclame`, ou `revoque` (à tout moment). Durée de vie avant réclamation : 90 jours par défaut, 365 au plus.
- **Abonnement par client** (`actif`, `suspendu`, `revoque`) : non actif = réclamation et nouvelles livraisons refusées. Une box déjà en service **garde toutes ses fonctions locales**.
- **Refus uniforme** : inconnu, expiré, déjà pris, révoqué, abonnement non actif, mauvaise clé : toujours « jeton refusé ». La vraie raison est dans l'audit.
- **Série préenregistrée** : un client « déjà pré-évalué » est préenregistré par numéro de série ; sa box reçoit son jeton à la volée (`reclamer_par_serie`), une seule fois.
- **Révocation** d'un jeton ou d'un lot ; sur un jeton déjà réclamé, rend la clé publique à retirer du tunnel (#2189).

## Audit

Chaque émission, réclamation, refus (avec la raison), révocation et changement d'abonnement est ajouté à `/var/log/secubox/audit.log` (JSON, module `autoload`). **Jamais la valeur d'un jeton.**

## Commandes (root)

    autoloadctl emettre --client client-042 --profil lite [--lot lot-2026-10] [--serie S] [--duree-jours 90]   # la valeur est imprimée une fois
    autoloadctl preenregistrer --serie SBX-0001-AB --client client-042 --profil isp
    autoloadctl lister [--etat emis|reclame|revoque] [--client C] [--lot L] [--json]
    autoloadctl revoquer (--id N | --lot L) --motif "…"
    autoloadctl abonnement --client client-042 --statut suspendu

Données : `/var/lib/secubox/autoload/jetons.db` (0600, dossier 0750). Variables : `SECUBOX_AUTOLOAD_DB`, `SECUBOX_AUTOLOAD_AUDIT` (tests).

## Tests

    python3 -m pytest packages/secubox-autoload/tests
