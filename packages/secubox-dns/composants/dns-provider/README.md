<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌐 DNS Provider

External DNS provider integration

**Category:** DNS

## Screenshot

![DNS Provider](../../docs/screenshots/vm/dns-provider.png)

## Features

- Cloudflare
- Route53
- DigitalOcean
- Dynamic DNS

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns-provider
```

## Configuration

Configuration file: `/etc/secubox/dns-provider.toml`

## API Endpoints

- `GET /api/v1/dns-provider/status` - Module status
- `GET /api/v1/dns-provider/health` - Health check

## Joker DNS des pairs du maillage (`secubox-dns-joker`, 1.6.3, #3206)

`secubox-dns-joker assurer <domaine-du-pair> <ipv4-publique> <zone-autorisée>` (root) assure `*.<nœud> A <ip>` dans
une zone gérée par un fournisseur **Gandi activé**. Appelé par `secubox-relais-maillage` avant le certificat joker
d'un pair (son défi DNS-01 masquait le joker parent). Idempotent ; refuse une zone non autorisée (le relais passe sa
zone parente), un libellé déjà utilisé dans la zone (sauf son `*.<nœud> A` et son `_acme-challenge.<nœud> TXT`), une
IP non publique ; n'écrase jamais ; relit après création ; sortie JSON, codes 0 (créé ou déjà juste), 2 (usage),
3 (refus), 1 (échec du fournisseur). L'adaptateur Gandi rend désormais les refus de Gandi (502) au lieu d'un succès.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
