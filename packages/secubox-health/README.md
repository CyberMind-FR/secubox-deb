<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-health

SecuBox health probers (vhost + module health monitoring).

Reconstitue en paquet source les sondes de santé de la board, jusque-là déployées à la main sur gk2 (aucune source dépôt) : - secubox-health-prober (prober.py) : sonde chaque vhost via nginx et écrit /var/cache/secubox/health/status.json. Ignore désormais les vhosts lifecycle=on-demand (modules.d) — les sonder les maintenait éveillés et neutralisait secubox-sleeper (scale-to-zero). - secubox-module-prober (module_prober.py) : santé par socket unix /health.

Paquet Debian : version `1.0.2-1~bookworm1`, architecture `all`.

## Contenu

- `conf/` : configuration livrée
- `src/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

- `secubox-health-prober.service` : SecuBox Health Prober - VHost monitoring (utilisateur `secubox`), lance `python3`
- `secubox-module-prober.service` : SecuBox Module Health Prober (utilisateur `root`), lance `python3`

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-health`.
