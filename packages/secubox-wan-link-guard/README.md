<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-wan-link-guard

WAN mvpp2 marginal-link guard for SecuBox (MOCHAbin).

Board-specific watchdog for the MOCHAbin (Marvell Armada, mvpp2) WAN port, which recurrently goes dead on gk2 through three stacked faults: the MAC TX wedges under upstream flow-control PAUSE frames, gigabit auto-negotiation is marginal through the intermediate hub, and a parasite default route/duplicate host IP appears on lan0.

Ships a oneshot guard (ethtool pause-off + renegotiate + route/addr cleanup — never `ip link down/up`, which wedges the comphy), a boot+30s timer, a systemd .link that disables flow-control the moment eth2 appears, and a flow-control backstop unit. Tunable via /etc/default/secubox-wan-link-guard.

MOCHAbin-only: on other boards eth2/lan0 do not match and the guard is a no-op. See /usr/share/doc/secubox/FAQ-NETWORK-WAN-RECOVERY.md (ref #913).

Paquet Debian : version `1.0.1-1~bookworm1`, architecture `all`.

## Contenu

- `network/` : fichiers du module
- `sbin/` : exécutables
- `systemd/` : unités systemd

## Exécution

- `secubox-eth2-flowctl-off.service` : SecuBox: disable eth2 flow-control pause (mvpp2 MAC TX wedge workaround), lance `ethtool`
- `secubox-wan-link-guard.service` : SecuBox WAN link guard (mvpp2 eth2: pause-off + renegotiate + route), lance `secubox-wan-link-guard`
- `secubox-wan-link-guard.timer` : SecuBox WAN link guard — periodic check
