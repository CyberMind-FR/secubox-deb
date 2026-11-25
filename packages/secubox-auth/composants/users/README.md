<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 👥 User Management

Unified identity management

**Category:** Access

## Screenshot

![User Management](../../docs/screenshots/vm/users.png)

## Features

- User CRUD
- Groups
- Service provisioning
- RBAC

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-users
```

## Configuration

Configuration file: `/etc/secubox/users.toml`

## API Endpoints

- `GET /api/v1/users/status` - Module status
- `GET /api/v1/users/health` - Health check

## `usersctl` et comptes sans mot de passe (#3708)

`usersctl semer [--machine NOM]`, `usersctl desactiver-admins-sans-mot-de-passe`,
`usersctl renommer-compte-machine ANCIEN NOUVEAU` : voir le README de secubox-auth. Retour arrière d'une désactivation :
`usersctl set-password NOM` puis `usersctl enable NOM`.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
