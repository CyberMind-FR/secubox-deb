<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌐 Exposure Settings

Unified exposure management

**Category:** Privacy

## Screenshot

![Exposure Settings](../../docs/screenshots/vm/exposure.png)

## Features

- Tor exposure
- SSL certs
- DNS records
- Mesh access

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-exposure
```

## Configuration

Configuration file: `/etc/secubox/exposure.toml`

## API Endpoints

- `GET /api/v1/exposure/status` - Module status
- `GET /api/v1/exposure/health` - Health check
- `GET /api/v1/exposure/{vhost}` - Read the current reach/mesh state for a vhost
- `POST /api/v1/exposure/{vhost}` - Set the reach/mesh state for a vhost (fail-safe apply, audited)

## Exposure switch

Each vhost carries a per-vhost **reach** setting that controls who may
reach it, independent of the global Tor/DNS/Mesh (Punk Exposure) channels
documented above.

### Reach levels

| Reach       | Meaning                                              |
|-------------|-------------------------------------------------------|
| `localhost` | Only reachable from 127.0.0.1 (loopback)               |
| `lan`       | Reachable from the local network/mesh CIDR (default)   |
| `wan`       | Reachable from anywhere (public)                       |

The default reach for a newly-adopted vhost is **`lan`**. A vhost that is
**already public** at adoption time is seeded to **`wan`** instead — the
switch never silently re-confines a currently-public service.

An independent boolean, **`mesh`**, additionally allows the Gondwana mesh
CIDR through regardless of `reach` (useful for `localhost`/`lan` vhosts
that should still be reachable from other mesh nodes).

### Snippet

Each vhost's reach state is rendered as an nginx snippet at:

```
/etc/nginx/snippets/exposure/<vhost>.conf
```

The snippet contains the `allow`/`deny` rules matching the selected reach
(plus the mesh CIDR `allow` line when `mesh` is enabled). It is written
atomically (write-temp + rename) so nginx never observes a half-written
file.

### Wiring a vhost

A vhost opts into the switch by adding a single `include` line inside its
gated `location` block (typically `location /`), **after** any existing
auth/ACL directives it already enforces:

```nginx
location / {
    include /etc/nginx/snippets/exposure/<vhost>.conf;
    ...
}
```

If the snippet file is missing (e.g. the package has not yet adopted the
vhost), the fail-safe default applies — always run `nginx -t` after wiring
and before reload.

### real_ip dependency

For the `wan`-deny rules to be effective, nginx must see the **real
client IP**, not the upstream proxy's IP (HAProxy in the default SecuBox
topology). This requires `secubox-hub`'s lan-geo real_ip configuration —
`set_real_ip_from` (trusting the HAProxy/proxy hop) and `real_ip_header`
(e.g. `X-Forwarded-For` or `proxy_protocol`) — to be active in the nginx
config. Without it, all requests appear to originate from the proxy's
address and reach/deny rules will not behave as expected.

## Onions (#3112, #3123)

Tout service onion vise le frontal HAProxy `onion-in` (`127.0.0.1:9180`, ou `onion_in_port` de
`haproxy.toml`) : le webui (`POST /tor/emancipate_webui`), les vhosts (portée Tor) et metablogizer.
Jamais nginx :9080 ni `http-in` :80 en direct. Le frontal refuse tout Host non `.onion`, efface
l'adresse annoncée par le client et pose le marqueur non LAN 192.0.2.80 avant l'inspection sbxwaf. La
route sbxwaf `<onion>.onion` → webui (nginx :9080) est posée par `secubox-waf-route`.

`/tor/add` est en liste blanche : `local_port` absent ou égal au port du frontal, sinon 400.
`/emancipate` avec Tor passe aussi par le frontal ; le port du service ne sert qu'au maillage et au DNS.
Avant d'écrire un service dans `torrc.d`, l'API ajoute `%include /etc/tor/torrc.d/*.conf` au torrc s'il
manque : le torrc de Debian ne l'inclut pas par défaut.

Migration, idempotente : `secubox-exposure-tor-reconcile` tourne au démarrage. Le postinst le lance
aussi sur les box qui ont un service onion, après avoir régénéré HAProxy si `onion-in` manque.

- Il réécrit **sur place** chaque `HiddenServicePort` qui vise 127.0.0.1:80 ou :9080 (dans le torrc,
  `torrc.d` et `/etc/tor/secubox-metablogizer.d`), par écriture atomique.
- `HiddenServiceDir` ne change pas, donc la clé et l'adresse `.onion` restent les mêmes.
- Il met à jour `exposure.json`, recharge Tor une fois et écrit une ligne d'audit `migrate_onion` par
  service. La ligne nomme qui a lancé : `postinst` ou `reconcile`.
- Tout `HiddenServicePort` qui reste hors du frontal est signalé sur stderr et dans l'audit
  (`onion_non_migre`, avec son `HiddenServiceDir`).

Le postinst redémarre ensuite le démon (`try-restart`) pour qu'il charge la nouvelle garde. Si la
régénération échoue, les onions restent fermés, et non ouverts vers nginx.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
