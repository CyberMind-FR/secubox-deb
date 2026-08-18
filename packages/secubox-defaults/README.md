<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-defaults

Ships `/etc/default/secubox`, the single source of truth for the SecuBox
board identity:

- `SECUBOX_HOSTNAME` — short board name (e.g. `gk2`).
- `SECUBOX_DOMAIN_SUFFIX` — domain root (e.g. `secubox.in`).

Composed canonical admin URL: `https://admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX}/`.

Consumers (`secubox-haproxy` API, render scripts, …) read this file at startup
and refresh on `dpkg-trigger secubox-defaults-changed`.

After hand-editing `/etc/default/secubox`:

```bash
curl -fsS -X POST --unix-socket /run/secubox/haproxy.sock \
     http://localhost/webui/refresh
/usr/local/bin/secubox-render-nginx-webui
/usr/local/bin/secubox-haproxy-regen-safe
```
