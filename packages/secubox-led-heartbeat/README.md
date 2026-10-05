<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-led-heartbeat

SecuBox LED heartbeat status indicator.

Visual system health indicator using MOCHAbin RGB LEDs.

Displays system health, security status, and resource usage via the IS31FL3199 I2C LED controller (3 RGB LEDs).

LED mapping: - LED 1: Health status (pulsing green/yellow/red) - LED 2: Security status (steady, flashing on threat) - LED 3: Capacity (CPU/memory load)

Paquet Debian : version `2.1.4-1~bookworm1`, architecture `all`.

## Contenu

- `boot/` : fichiers du module
- `etc/` : fichiers du module
- `kmod/` : fichiers du module
- `systemd/` : unités systemd
- `usr/` : fichiers du module

## Exécution

- `secubox-healthbump.service` : SecuBox HealthBump LED Status Check (3-tier with I2C safety), lance `secubox-healthbump`
- `secubox-healthbump.timer` : SecuBox HealthBump LED Timer (every 30 seconds)
- `secubox-led-heartbeat.service` : SecuBox LED Heartbeat Status Indicator (utilisateur `root`), lance `secubox-led-heartbeat`
- `secubox-led-pulse.service` : SecuBox LED Pulse Daemon - Continuous visual status, lance `secubox-led-pulse`
- `secubox-led-trigger.service` : SecuBox LED Timer Triggers Setup, lance `secubox-led-trigger`
- `secubox-leds.service` : SecuBox LED Configuration, lance `modprobe`

## Dépendances SecuBox

`secubox-core`.
