<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-reality

SecuBox Reality — VLESS+Reality+Vision egress-point manager.

Manages VLESS+Reality+Vision egress points backed by Xray-core: x25519 identity provisioning, Reality dest/SNI sanity validation (TLS1.3 + X25519), per-instance hardened systemd units, client vless:// links with QR codes, and a sliding-window volume-guard (soft warn / hard disable) that preserves egress identity across a stop.

Paquet Debian : version `0.2.2-1~bookworm1`, architecture `all`.

## Contenu

- `menu.d/` : entrée de menu
- `secubox_reality/` : fichiers du module
- `webui/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/reality.sock`.
- `secubox-reality-monitor.service` : SecuBox Reality volume-guard sweep (oneshot) (utilisateur `secubox`), lance `python3`
- `secubox-reality-monitor.timer` : SecuBox Reality volume-guard sweep — every 5 minutes
- `secubox-reality.service` : SecuBox Reality API (utilisateur `secubox`), lance `python3`
- `secubox-xray@.service` : SecuBox Reality egress point %i (Xray-core, VLESS+Reality+Vision), lance `xray`

## API

| Méthode | Route | Garde |
|---|---|---|
| `POST` | `/servers` | aucune |
| `GET` | `/servers` | aucune |
| `GET` | `/servers/{server_id}` | aucune |
| `DELETE` | `/servers/{server_id}` | aucune |
| `POST` | `/validate-target` | aucune |
| `POST` | `/apply` | aucune |
| `POST` | `/clients` | aucune |
| `GET` | `/clients` | aucune |
| `DELETE` | `/clients/{client_id}` | aucune |
| `GET` | `/link` | aucune |
| `GET` | `/guard` | aucune |
| `PUT` | `/guard` | aucune |
| `GET` | `/stats` | aucune |
| `GET` | `/healthz` | aucune |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.
