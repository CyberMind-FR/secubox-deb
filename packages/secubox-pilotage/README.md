<!--
SPDX-License-Identifier: LicenseRef-CMSD-1.0
Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
Source-Disclosed License — All rights reserved except as expressly granted.
See LICENCE-CMSD-1.0.md for terms.
-->
# secubox-pilotage — maître du pilotage distant (#3126, L1 « Voir »)

Reçoit des agents (`secubox-pilotage-agent`) des box du maillage et d'Auto-Load leurs relevés TR-181 et leurs notifications, tient l'inventaire
par box (SQLite) et l'expose à l'administrateur. Lecture seule : Get, GetSupportedDM, Notify et `Device.X_SECUBOX_Releve.Mesurer()`.

## Exécution
| Élément | Valeur |
|---|---|
| Service | `secubox-pilotage.service`, utilisateur `secubox-pilotage`, `/usr/sbin/secubox-pilotage-api` |
| Administration | `/run/secubox/pilotage.sock` (0660, groupe `secubox`) ; nginx `/api/v1/pilotage/` (`secubox-routes.d/pilotage.conf`), toutes les routes `require_jwt` ; module dédié de l'agrégateur (`DEDICATED_MODULES`) |
| Canal | `/run/secubox/pilotage-canal.sock` (0660, groupe `www-data`), jamais sur une IP de tunnel hors nginx |
| Processus | une seule boucle asyncio, les deux applis en `lifespan="on"` (les files sont en mémoire, la relève est partagée) |
| Données | `/var/lib/secubox/pilotage/` (0750 `secubox-pilotage`, créé par le postinst : systemd-tmpfiles refuse ce chemin) |
| Audit | `/var/log/secubox/audit.log` (propriétaire et droits inchangés ; ACL `u:secubox-pilotage:rw-`, reposée par l'unité de l'écouteur après rotation) |
| AppArmor | `secubox-pilotage-api`, enforce |

## Écouteurs de tunnel
`secubox-pilotage-ecoute` (root) rend `/etc/nginx/conf.d/secubox-pilotage-canal.conf` : un `server` par IP de tunnel présente,
`10.10.0.1:8472` (wg-mesh) et `10.64.0.1:8472` (wg-autoload), `X-Real-IP $remote_addr` (écrase tout en-tête client : c'est l'identité de la
box), `client_max_body_size 256k`, `proxy_read_timeout 60s`. Fichier retiré si `nginx -t` échoue ; nginx rechargé seulement si le rendu change.
Il insère à chaud (avant le `drop` de `inet secubox_filter`) et dans `/etc/nftables.conf` :

    iifname "wg-mesh" ip saddr 10.10.0.0/24 tcp dport 8472 accept
    iifname "wg-autoload" ip saddr 10.64.0.0/16 tcp dport 8472 accept

Déclencheurs : `secubox-pilotage-ecoute.path` (changement de `wg_mesh.json` ou de `pairs-publics.json`) et `.timer` (5 min).

## Tests
`cd packages/secubox-pilotage && python3 -m pytest -q`
