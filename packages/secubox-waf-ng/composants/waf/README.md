<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Category:** Security

## Screenshot

![Web Application Firewall](../../docs/screenshots/vm/waf.png)

## Features

- OWASP rules
- Custom rules
- Request logging

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-waf
```

## Configuration

Configuration file: `/etc/secubox/waf.toml`

## API Endpoints

- `GET /api/v1/waf/status` - Module status
- `GET /api/v1/waf/health` - Health check
- `GET /api/v1/waf/enforcement[?statut=active|expired|released]` - actions défensives (bans de sbxwaf) : type, cible, raison, durée, échéance, rollback (#2240)
- `GET /api/v1/waf/enforcement/mode` - `PASSIVE_ONLY` / `SIMULATION` / `ACTIVE`, par source (acteurs, campagnes) et global
- `GET /api/v1/waf/decisions` - décisions des bans automatiques : `BLOCKED`, `WOULD_BLOCK` (simulation), `OBSERVE` (écarté, avec le motif)
- `POST /api/v1/waf/enforcement/{id}/rollback` - annule une action active (retire l'adresse du set nft), audité dans `/var/log/secubox/audit.log` ; `require_jwt`
- `GET /api/v1/waf/php/signaux` - signaux de l'analyse PHP de sbxwaf sur 24 h (`require_lecture`, #3273) : `familles` (`php2shell`, `roundcube`, `nextcloud`, `php_requete`, `outil`), `regles`, `vhosts`, `adresses` publiques (jamais « local » ni une adresse privée), `etat` (`ok` / `inconnu`) ; les lignes d'état de gravité `audit` ne sont pas comptées. Lu dans le relevé `/var/lib/secubox/waf/php-signaux.json`, recalculé toutes les 60 s en tâche de fond : le journal n'est jamais relu à la requête. Relevé absent : `etat: inconnu`, compteurs `null`.
- `GET /api/v1/waf/detections` - gagne l'entrée `analyse_php` (mode `detect`, vhosts armés lus dans `/etc/secubox/waf/vhost_profiles.json`, `<n> signaux en 24 h`) ; la page Menaces affiche la carte « Analyse des requêtes PHP » et la page Attaquants la signature PHP de chaque adresse.

Les trois lectures (`require_lecture`) relisent les fichiers de sbxwaf (`bans.jsonl`, `actor-ban-etat.json`, `campagne-ban-etat.json`) ; rien n'est recopié.

### Compte de service `ai-ban` (#3716)

Garde `require_ai_ban` (jeton EdDSA par requête, usage unique, lié au corps), **pas** `require_jwt` : exception écrite à `RULES-CODE` § 3. Servies par l'agrégateur seul (`SECUBOX_WAF_GESTES_IA=1`) ; ailleurs 503 `processus`. Détail des corps, motifs, clés et rotation : [`README.md` du paquet](../../README.md).

- `POST /api/v1/waf/ai/ban` - `{geste: "ban", cible, duree_s, mode: clic|auto, conseil, motif}` → `{id, cible, fin, audit}` ; IPv4 publique ou /24 exact, 1 h à 7 j, `auto` : bloc, 24 h au plus, cas sûr recontrôlé ; plafonds d'office 5/h et 20/j, du compte 30/h et 100/j ; refus 409 `{"detail": {"motif"}}`.
- `POST /api/v1/waf/ai/unban` - `{geste: "unban", id}` → `{id, etat}` (`annule`, `echu`, `deja_annule`, `couvert`) ; seulement un ban posé par `ai-ban`, jamais un ban qu'une autre source couvre.
- `GET /api/v1/waf/ai/etat` - sans corps → `{actifs, compteurs, plafonds}`.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
