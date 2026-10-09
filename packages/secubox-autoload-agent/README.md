<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-autoload-agent

Provisionnement réseau « Auto-Load », **côté box cliente**. Parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`. Le côté infrastructure est `secubox-autoload`.

**État (0.3.0) :** le tunnel sortant (#2189), le moteur de provisioning (#2187) et la validation (#2188). C'est une bibliothèque tant que le point d'enrôlement HTTPS n'existe pas (#2190) ; le rapport final (#2192) vient ensuite.

## Tunnel (`autoload_agent/tunnel.py`)

- La clé WireGuard est générée **sur la box** (`/etc/secubox/secrets/autoload-wg.key`, 0600). Jamais dans l'image, jamais en argument de commande ni dans la configuration (`PostUp = wg set %i private-key <fichier>`). Une clé existante n'est **jamais** remplacée : la box garde son identité.
- Configuration **sortante seulement** : pas de `ListenPort`, pas de route par défaut (`AllowedIPs` = le hub `10.64.0.1/32`), `PersistentKeepalive = 25`. Aucun port entrant côté client.
- Ce que répond l'infrastructure est **validé avant d'écrire un fichier** : nom d'hôte épinglé (`admin.gk2.secubox.in`), adresse /32 dans `10.64.0.0/16` hors hub, clés WireGuard, aucun retour à la ligne, aucun champ inconnu.
- Si l'activation de `wg-quick@wg-autoload` échoue, la configuration posée est retirée.

## Moteur (`autoload_agent/moteur.py`, #2187)

    fichier de réponses signé → clé WireGuard → enrôlement → tunnel → plan → VALIDATION → installation → application

- **Reprise** : chaque étape réussie est notée dans l'état (`/var/lib/secubox/autoload-agent/etat.json`, 0600). Après un échec ou une coupure, le parcours reprend à la première étape non faite et **ne rejoue pas l'enrôlement** (le jeton est à usage unique). Un parcours terminé ne refait rien.
- **Plan** : simulation `apt-get -s install secubox-lite|secubox-isp|secubox-full` ; la liste des paquets à installer est remise au valideur et au rapport.
- **Validation** : point d'injection (#2188). **Sans valideur explicite, le défaut refuse** : rien n'est installé.
- **Rien du réseau n'est exécuté** : réponse du tunnel validée avant écriture, noms de paquets filtrés, fichier du jeton refusé s'il est lisible par d'autres comptes, commandes en listes d'arguments avec délai.
- **Application** : `premier-pasctl appliquer` (réseau, comptes) puis `secubox-profilectl apply <profil> --yes` (4R, audit).
- Rapport (sans secret) : `/var/lib/secubox/autoload-agent/rapport.json`.

## Validation (`autoload_agent/validation.py`, #2188)

Le moteur remet son plan à un valideur. Le **pré-rapport** dit ce qui va arriver (profil, paquets, réseau, comptes créés) et seulement **qu'il y a** des secrets, jamais leur valeur ni le nom de leur fichier ; il est écrit en 0600 et identifié par son empreinte SHA-256.

- **Auto (zero-touch)** : le pré-rapport est publié à l'infrastructure, puis un **délai de grâce** (`[provision].grace_min`, 15 minutes par défaut, 0 à 1440) pendant lequel l'opérateur peut refuser. **Fermé par défaut** : pré-rapport non publiable, ou refus non consultable = on n'applique pas.
- **Manuel (one-shot)** : applique seulement si l'opérateur confirme l'**empreinte de ce pré-rapport** ; la confirmation d'un autre plan ne vaut rien ; sans confirmation avant l'échéance, refus.
- `pour_mode(mode, …)` choisit le valideur selon `[provision].mode`.

## Tests

    python3 -m pytest packages/secubox-autoload-agent/tests
