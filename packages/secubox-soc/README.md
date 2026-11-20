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

### Modes

- `observe` (défaut) : lecture seule, aucun geste.
- `reactive` : ouvert ; la file d'approbation agit, sur approbation d'un administrateur.
- `active` et `aggressive` : refusés par `POST /mode` avec 409 `gestes_non_livres`.

### Données et audit

- Base SQLite `/var/lib/secubox/soc/defense.db` (surcharge : variable `SECUBOX_SOC_DEFENSE_DB`) : mode, décisions,
  liste blanche ; schéma par migrations (`api/migrations/0001-defense.sql`).
- Chaque décision de sécurité est écrite, avec fsync, dans `/var/log/secubox/audit.log` (append-only) avant d'être
  validée ; si l'audit échoue, rien n'est fait (503 `audit_indisponible`). Format : UNE ligne JSON par décision
  (`json.dumps`, `ensure_ascii=True`, comme `secubox_core.auth`), clés dans l'ordre `ts` (ISO-8601 UTC), `module`
  (`"soc"`), `action`, `operateur`, puis les champs propres à l'action (`empreinte`, `acteur`, `adresses`, `geste`,
  `duree`, `score`, `generation`, `issue`, `cause`, `verdict`, `operation` pour une simulation, …).
  Valeurs de `action` : `sade-mode`, `sade-simule`, `sade-approuve-demande`, `sade-approuve-resultat`, `sade-refuse`,
  `sade-approuve-refus`, `sade-refuse-refus`, `sade-reprise`.

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
