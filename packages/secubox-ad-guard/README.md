<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🚫 AdGuard

AdGuard Home DNS blocking

**Category:** DNS

## Screenshot

![AdGuard](../../docs/screenshots/vm/ad-guard.png)

## Features

- Ad blocking
- Tracking protection
- Parental control
- Statistics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ad-guard
```

## Configuration

Configuration file: `/etc/secubox/ad-guard.toml`

## API Endpoints

- `GET /api/v1/ad-guard/status` - Module status
- `GET /api/v1/ad-guard/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).


## POC « DNS AdBlock TV » (1.2.0, #1943)

Mesure ce que le filtrage DNS bloque réellement pour des appareils choisis (Freebox TV) : **OBSERVE** (rien n'est bloqué, on compte ce qui l'aurait été) ou
**BLOCK**. Formulation : *réduction des domaines publicitaires/tracking résolus par DNS* — pas une suppression de publicités. Ni MITM, ni cookie, ni URL.
**Inactif par défaut.** Conception et audit : `docs/poc-dns-adblock-tv.md` ; résultats : `docs/poc-dns-adblock-tv-results.md`.

| Pièce | Rôle |
|---|---|
| `api/dnstv.py`, `api/dnstv_routes.py` | bibliothèque (analyseur du journal d'Unbound, classeur, état, SQLite, configuration Unbound) et routes `/api/v1/ad-guard/adblock-tv/*` |
| `sbin/secubox-adguard-tv` | **seule porte root** : `apply` / `disable` / `status` ; relit et revalide l'état, refuse les liens symboliques, `unbound-checkconf` avant de garder |
| `sbin/secubox-adguard-dnsfeed` | démon (`secubox`) : compteurs par jour / appareil / domaine / décision (`ALLOWED`, `BLOCKED`, `UPSTREAM_ERROR`) depuis `journalctl -u unbound` |
| `lists/` | jeu de test versionné (`# version:`, `MANIFEST.json`) : advertising, tracking, telemetry, social, custom |
| `tools/dns-tv-test.py` | test côté client : résolution, temps, statut ; `BLOCKED` seulement avec un résolveur de référence |
| `tools/dns-limits-lab.py` | banc local (vrai Unbound) qui **démontre** les limites A–G |
| `tools/tv-before-after.py` | procédure A/B/C sur un appareil réel, par différence de relevés |

Routes (`require_lecture` en lecture, `require_jwt` pour agir) : `status`, `etat`, `clients`, `mode`, `stats`, `export`, `clients/vus`, `custom`, `sonde`, `path-test`, `bypass`, `limites`.

```
# activer
(onglet « DNS AdBlock TV » : ajouter l'appareil, cocher Activé)   puis   systemctl enable --now secubox-ad-guard-dnsfeed
# tests
cd packages/secubox-ad-guard && python3 -m pytest tests          # le banc Unbound se saute si `unbound` est absent
python3 tools/dns-limits-lab.py --rapport reports/dns-limits.json
python3 tools/dns-tv-test.py --serveur 192.168.1.200 --reference 1.1.1.1 --list tools/test-domains.txt --rapport reports/dns-test.json
# retour arrière (le retrait du paquet le fait aussi)
sudo secubox-adguard-tv disable && sudo systemctl disable --now secubox-ad-guard-dnsfeed
```

Limite connue du module existant : l'exemption d'un client par une vue Unbound **vide** (allowlist d'IP de `secubox-adblock-sync`) ne fonctionne pas ;
une vue doit contenir une zone transparente (`local-zone: "." transparent`). Voir l'audit, §5.
