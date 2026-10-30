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

## Pilote des LED par DKMS (#3290)

Le noyau Debian stock (6.12.x) n'active pas `CONFIG_LEDS_IS31FL319X`. Le paquet livre les
sources du pilote (`kmod/`, référence Linux v6.12.107) dans `/usr/src/secubox-leds-<version>/`
avec un `dkms.conf` (`AUTOINSTALL=yes` : reconstruit à chaque nouveau noyau).

- `secubox-led-dkms install|remove <version>`, appelé par le postinst/prerm : `dkms add`,
  `build`, `install`, puis `modprobe leds-is31fl319x` sans redémarrage.
- **MOCHAbin seulement** (`secubox-led-board`) et jamais quand le bus I²C est neutralisé
  (`blacklist i2c_mv64xxx` ou `install i2c_mv64xxx /bin/false` dans `/etc`, `/run`, `/usr/lib`
  ou `/lib/modprobe.d/`, `modprobe.blacklist=` du noyau, ou `i2c-1` absent) : c'est le cas de **gk2**,
  où le paquet reste inerte (rien construit, rien chargé, aucune levée tentée).
- `dkms` et `linux-headers-arm64` sont en **Suggests** (ni Depends ni Recommends, qu'apt
  installerait par défaut, y compris sur gk2 et le rpi400) : sur un MOCHAbin avec LED, les
  installer explicitement (`apt-get install dkms linux-headers-arm64`, puis
  `dpkg-reconfigure secubox-led-heartbeat`). Leur absence donne ce message, pas un échec.
- Un échec de build ne fait jamais échouer `dpkg` (message, code 0 ; journal dans
  `/var/lib/dkms/secubox-leds/<version>/build/make.log`).
- Secure Boot : le module doit être signé par une clé MOK inscrite ; un message le rappelle,
  rien n'est contourné.
- Un noyau qui fournit déjà le pilote (in-tree) court-circuite DKMS ; un module déjà installé
  pour ce noyau et cette version n'est pas reconstruit ; il n'est retiré qu'à la désinstallation.
- Au démarrage, `secubox-leds.service` lance `secubox-led-dkms check` : avertissement dans le
  journal si la puce est présente sans module pour le noyau courant (noyau installé sans en-têtes).
- Les variables `SECUBOX_*` du script ne servent qu'aux tests (`SECUBOX_TEST=1`, hors root).

Chargement au démarrage : `modules-load.d/secubox-leds.conf`, puis `secubox-leds.service`
(`After=systemd-modules-load.service`) pour le cycle unbind/bind.

### Délai entre écritures I²C (`write_delay_us`)

En mai 2026, sur 6.12.85, le contrôleur `mv64xxx` se bloquait (`mv64xxx_i2c_fsm: Ctlr Error`)
après des écritures LED rapides ; seul un redémarrage le rendait. Contournement retenu : 1 ms
après chaque écriture du pilote. Paramètre de module `write_delay_us` (µs, 0..100000, défaut 1000,
0 = pilote amont) : `modprobe leds-is31fl319x write_delay_us=2000` ou
`/sys/module/leds_is31fl319x/parameters/write_delay_us`.
