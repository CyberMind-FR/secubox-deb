<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🛡️ Security Operations Center

SOC with world clock, threat map, tickets

**Category:** Dashboard

## Screenshot

![Security Operations Center](../../docs/screenshots/vm/soc.png)

## Features

- World clock
- Threat map
- Ticket system
- P2P intel
- Alerts

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-soc
```

## Configuration

Configuration file: `/etc/secubox/soc.toml`

## API Endpoints

- `GET /api/v1/soc/status` - Module status
- `GET /api/v1/soc/health` - Health check

## SADE — Cyber Defense Live

Console de défense active du SOC : page `/soc/defense.html`, routes montées sous `/defense` (préfixe `/api/v1/soc`
côté public). Elle agrège actord, le WAF et le maillage ; une source injoignable s'affiche « relevé indisponible ».

### Routes `/defense/*`

| Route | Garde | Rôle |
|---|---|---|
| `GET /status`, `/threats`, `/threats/{id}`, `/actions`, `/mesh`, `/incidents`, `/policies`, `/proposals` | `require_lecture` | Vues de lecture |
| `POST /mode` | `require_jwt` | Change le mode (audit écrit avant le COMMIT) |
| `POST /approve`, `POST /refuse` | `require_jwt` | Approuve ou refuse une proposition, désignée par son empreinte ; `simuler: true` ne fait rien et ne trace que le verdict |
| `POST /reprendre` | `require_jwt` | Débloque une décision restée `en_cours` (retour `en_attente`) |
| `POST /liste-blanche`, `POST /liste-blanche/retirer` | `require_jwt` | Ajoute (`{cidr, motif}`) ou retire (`{cidr}`) un réseau protégé : au plus /24 en IPv4, /48 en IPv6 (jamais un préfixe IPv6 qui porte de l IPv4), 64 ajouts ; ajout et retrait confirmés dans la page ; entrées système non retirables ; audit `sade-liste-blanche-ajout` / `-retrait` avant le COMMIT. Aussi en ligne de commande : `cd /usr/lib/secubox/soc && runuser -u secubox -- python3 -m api.liste_blanche lister\|ajouter <cidr> <motif>\|retirer <cidr>` |

Lectures : chaque source est lue avec un délai de 20 s. Une vue est servie 15 s depuis le cache. Quand une source
est muette, le dernier relevé complet de moins de 15 min reste servi, avec son heure (`releve_a`) : la page affiche
alors « RELEVÉ DU HH:MM », jamais « EN DIRECT ». `/mesh` donne le nom d'hôte de la box (`identifiant` = nœud
threatmesh) et `pairs_silencieux` (attendu depuis threatmesh 1.2.0, #3450). `/incidents` regroupe les événements
identiques d'une même minute (`n`) ; un outil deviné par actord (« …? ») est écrit « … (probable) ».

### Modes

- `observe` (défaut) : lecture seule, aucun geste.
- `reactive` : ouvert ; la file d'approbation agit, sur approbation d'un administrateur.
- `active` : ouvert. Le chemin manuel de `reactive` reste valable, et l'exécuteur automatique du cas sûr
  (`secubox-soc-sade-auto.timer`, toutes les 2 min) bannit seul les propositions d'actord de score 60 à 79 (bande
  contenir ; 80 à 94 exigerait une récidive confirmée par le code, non livrée en v1 : proposé), d'au plus
  8 adresses publiques hors liste blanche, passerelles et pairs du maillage, pour 24 h au plus (4 h par défaut), par
  `sudo wafctl ban`. Pairs : `/var/lib/secubox/p2p/wg_mesh.json` (`mesh_ip`, `endpoint` ; surcharge
  `SECUBOX_SOC_WG_MESH`) — illisible ⇒ aucun ban du passage (`pairs_illisibles`), absent ⇒ box sans maillage — plus
  threatmesh `/peers` s'il répond. Seules les propositions **vues pour la première fois après le passage en ACTIVE**
  (`propositions_vues`, migration 0002, comparée à `mode.depuis`) sont traitées : l'arriéré reste à la main. Plafond
  de 20 adresses par heure : au-delà, retour en `observe` (même par-dessus un passage concurrent en `reactive` : plus
  strict seulement), audit `sade-auto-plafond`, et la page affiche « retour en OBSERVE par le plafond (HH:MM) ». Un
  refus humain lie l'exécuteur par empreinte ET par adresse : une adresse refusée un jour par un opérateur exclut toute
  proposition qui la contient. Seuls les verdicts de garde de `wafctl` (`refus:privee|protegee|box|pair|invalide`,
  adresse privée ou invalide) concluent `refuse` ; tout autre échec (garde illisible, nft, délai, sudo) remet la
  décision `en_attente` et arrête le passage. Un passage n'entame plus de proposition après 3 min. Hors mode `active`,
  l'exécuteur ne bannit rien (il note seulement la première vue des propositions).

  **Limite v1 — à faire avant d'activer ACTIVE** : l'adresse publique de sortie de la box et l'adresse publique du
  poste d'administration ne sont PAS détectées automatiquement. Les ajouter à la liste blanche avant de passer en
  `active` (sinon elles seraient bannissables si actord les proposait).
- `/policies` porte un bloc `auto` : `plafond_heure`, `bans_derniere_heure` (adresses réclamées par l'exécuteur sur
  l'heure glissante, tout état confondu : le compte du plafond, affiché « Décisions automatiques : n / 20 sur
  l'heure »), `score` (`[60, 79]`), `ttl_max_s`, `adresses_max`, `mode_par` (auteur du dernier changement de mode :
  `sade-auto` pour tous, un nom humain pour l'administrateur seulement, sinon `null`) et `mode_depuis`.
- `aggressive` : refusé par `POST /mode` avec 409 `gestes_non_livres`.

### Données et audit

- Base SQLite `/var/lib/secubox/soc/defense.db` (surcharge : variable `SECUBOX_SOC_DEFENSE_DB`) : mode, décisions,
  liste blanche, première vue des propositions ; schéma par migrations (`api/migrations/0001-defense.sql`,
  `0002-propositions-vues.sql`).
- Chaque décision de sécurité est écrite, avec fsync, dans `/var/log/secubox/audit.log` (append-only) avant d'être
  validée ; si l'audit échoue, rien n'est fait (503 `audit_indisponible`). Format : UNE ligne JSON par décision
  (`json.dumps`, `ensure_ascii=True`, comme `secubox_core.auth`), clés dans l'ordre `ts` (ISO-8601 UTC), `module`
  (`"soc"`), `action`, `operateur`, puis les champs propres à l'action (`empreinte`, `acteur`, `adresses`, `geste`,
  `duree`, `score`, `generation`, `issue`, `cause`, `verdict`, `operation` pour une simulation, …).
  Valeurs de `action` : `sade-mode`, `sade-simule`, `sade-approuve-demande`, `sade-approuve-resultat`, `sade-refuse`,
  `sade-approuve-refus`, `sade-refuse-refus`, `sade-reprise`, et, pour l'exécuteur (`operateur` = `sade-auto`) :
  `sade-auto-demande` (avant les bans), `sade-auto-resultat` (issue) et `sade-auto-plafond` (retour en observe).
- Unité `secubox-soc-sade-auto.service` (oneshot, utilisateur `secubox`, `NoNewPrivileges=no` pour sudo, exception
  § 10) lancée par `secubox-soc-sade-auto.timer` ; le sudoers `SBX_WAF_BANMANUEL` de secubox-waf-ng accorde `wafctl ban`.

### Compteurs de `/defense/status`

- `evenements_24h` : somme de l'activité 24 h d'actord, calculée sur ses 5000 derniers événements seulement ;
  `evenements_24h_plafonne` vaut `true` quand l'échantillon est plein (ou de taille inconnue) : le chiffre est alors un
  minimum (la page affiche « ≥ N, échantillon plafonné par actord »).
- `a_valider` : propositions d'actord en attente de décision (même règle que `/defense/proposals`), `null` si la base
  d'état est illisible.
- `blocages_actifs` : bans que le WAF déclare appliqués (`application.ok`) ; `blocages_enregistres` : bans inscrits au
  WAF ; `blocages_application` : état d'application du WAF. `application.ok` faux : 0 actif ; absent : `null`.

### Liste blanche

Réseaux jamais bannis : RFC 1918, boucle locale, lien-local, CGNAT, ::1, fc00::/7, fe80::/10. Les entrées amorcées
sont verrouillées par des triggers SQL (ni suppression, ni modification, ni remplacement). Toute adresse d'une
proposition est contrôlée ; échec fermé.

### Approbation

- Une décision est identifiée par l'**empreinte** de la proposition (sha256 de geste, adresses normalisées triées et
  ttl), jamais par l'identifiant d'acteur, renuméroté au redémarrage d'actord. Le serveur la recalcule sur la
  proposition courante d'actord ; sans correspondance : 409 `proposition_changee`, rien n'est fait.
- La décision est réclamée (`en_cours`, mode relu, audit fsync, une transaction BEGIN IMMEDIATE) avant tout appel
  au WAF ; un double clic ou une réclamation concurrente donne 409 `deja_traitee`.
- `POST /reprendre` ne ramène une décision `en_cours` à `en_attente` que si sa demande dépasse le délai maximal des
  appels au WAF + 60 s.
- Seul geste exécutable : `ban`, soit un `POST /ban` du WAF par adresse (au plus 32), avec le jeton administrateur de
  l'appelant relayé ; arrêt au premier échec. Les autres gestes (par exemple la quarantaine) ne sont pas exécutables.

### Confidentialité

Les adresses et l'empreinte ne sont rendues qu'aux administrateurs (`require_jwt`). Un lecteur ne voit que des
cibles masquées (`cible-N`), y compris dans les textes libres.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
