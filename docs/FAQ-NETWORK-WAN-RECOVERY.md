<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# FAQ — WAN injoignable sur MOCHAbin (ARP marche, unicast mort)

*Panne récurrente. Playbook de diagnostic + recovery. Créé 2026-07-28 après une session d'investigation exhaustive.*

## Symptôme

gk2 (MOCHAbin, Armada 7040) devient **injoignable sur le LAN/WAN** :
- `ping` vers la gateway (`192.168.1.254`) et Internet → **100% de perte**.
- `arping <gateway>` → **0 réponse**.
- Pas de bail DHCP (aucun `DHCPOFFER`).
- **MAIS** : le lien physique est up (`carrier=1`, `Link is Up 1Gbps/Full`), gk2 **reçoit** du broadcast (`rx_packets` monte), et `tx_packets` monte avec `tx_dropped=0`.
- Bref : **l'ARP/broadcast semble partir, mais aucun unicast n'aboutit, dans les deux sens.**

## ⭐ SOLUTION COMPLÈTE (2026-07-28) — 3 problèmes EMPILÉS + watchdog permanent

Après une longue investigation : ce n'était PAS un seul bug mais **3 problèmes cumulés**, d'où l'échec de tout fix isolé. **Un hub/switch est intercalé entre gk2 et la Freebox.**

| # | Problème | Symptôme | Fix |
|---|---|---|---|
| **1** | **Flow-control PAUSE** wedge le TX du MAC mvpp2 | `good_octets_sent=0` (le MAC n'émet rien) | `ethtool -A eth2 autoneg off rx off tx off` |
| **2** | **Négociation gigabit MARGINALE** (à cause du hub en face) — le lien accroche au hasard | TX compte mais `.254` muette ; « marche puis KO » | **`ethtool -r eth2` (restart autoneg) en boucle jusqu'à ce que `.254` réponde** (souvent 2-3 essais) |
| **3** | **Route `default via lan0` parasite** + `.200` dupliquée sur `lan0` | internet KO alors que `.254` répond ; weak-host ARP | `ip route del default dev lan0` ; `ip addr del 192.168.1.200/24 dev lan0` ; forcer `default via .254 dev eth2` |

### Preuves décisives

- **U-Boot pinge `.254`** → HW/PHY/câble OK, bug 100% Linux/L1-négo.
- **`ethtool -S eth2` → `good_octets_sent=0`** pendant un ping = TX MAC pausé (couche 1).
- **`ethtool -r eth2` × N → `.254` répond au bout de 2-3 essais** = négociation gigabit marginale (couche 2, le hub).
- **`ip route` → `default via .254 dev lan0 linkdown`** hijacke le routage (couche 3).

### Fix permanent installé : `secubox-wan-link-guard`

Script `/usr/local/sbin/secubox-wan-link-guard` + `secubox-wan-link-guard.service` (au boot) + `.timer` (toutes les 30s). À chaque passage, idempotent et non-disruptif quand tout va bien :
1. `ethtool -A eth2 autoneg off rx off tx off` (couche 1)
2. supprime la route/IP `lan0` parasite + force `default via .254 dev eth2` (couche 3)
3. si `.254` ne répond pas → **`ethtool -r eth2` en boucle (max 6)** jusqu'à accroche (couche 2)

⚠️ **La VRAIE cause racine physique = le hub/switch intercalé** qui rend la négo gigabit marginale. Le watchdog est un contournement software efficace ; le fix propre serait de **retirer le hub** (gk2 direct sur la Freebox) ou le remplacer par un switch gigabit correct. Mais le watchdog maintient gk2 en ligne sans intervention.

---

## Détail couche 1 — flow-control (cause racine — CONFIRMÉE 2026-07-28) ✅

**Le flow-control (PAUSE frames) bloque le TX du MAC mvpp2 de gk2.** Preuve irréfutable via `ethtool -S eth2` :

```
good_octets_received: 787531   ← RX marche
good_octets_sent: 0            ← le MAC hardware n'émet AUCUN octet (reste 0 même pendant un ping)
fc_received: 31796             ← gk2 reçoit un FLOT de PAUSE frames (flow-control)
```

Le compteur logiciel `tx_packets` monte (le kernel croit émettre) mais le **compteur matériel `good_octets_sent` reste bloqué à 0** : le MAC est mis en **pause permanente** par les PAUSE frames reçues → rien n'atteint le fil → tout unicast (ARP/ICMP/DHCP) meurt, RX intact. Kernel-**indépendant** (les 3 variantes 6.6.137 / 6.12.85 échouent). **U-Boot marche** car il ne négocie pas ce flow-control (cf. test plus bas).

**Incohérence révélatrice** : `ethtool -a eth2` montre `RX: off` (configuré) mais `RX negotiated: on` — le HW honore quand même la pause négociée par autoneg.

### ✅ LE FIX (confirmé, immédiat)

```bash
ethtool -A eth2 autoneg off rx off tx off
```

Effet immédiat vérifié : `good_octets_sent` se met à monter, `arping 192.168.1.254` répond, `ping` = 0% perte. **C'est volatile** (perdu au reboot) → d'où la récurrence (« résolu à chaque fois » = ré-appliqué à la main). Rendu **permanent** (voir plus bas).

⚠️ **NE JAMAIS** faire `ip link set eth2 down; up` — ça **wedge** en plus le port mvpp2/comphy (état différent, qui lui exige un cold-boot). Voir mémoire `project_mochabin_wan_mvpp2_hazard`.

*(Question ouverte : pourquoi la Freebox floode-t-elle des PAUSE frames vers gk2 ? — port Freebox, duplex, ou congestion. Non bloquant : ignorer la pause côté gk2 suffit. À creuser si ça revient malgré le fix permanent.)*

## Ce qui NE sert à RIEN (déjà éliminé, ne pas reperdre du temps dessus)

- `nft flush ruleset` complet (le pare-feu n'y est pour rien)
- offloads (`ethtool -K` off), conntrack (jamais plein), NAT, ebtables, XDP/eBPF, policy-routing (`ip rule`)
- conflit d'IP (`arping -D` = pas de doublon)
- **cold power-cycle** complet (débranchage secteur ≥30s) → ne corrige PAS
- **câble neuf**, **autre port**, **reboot Freebox** → ne corrigent PAS
- changer d'IP (.210), passer le câble sur un port LAN (lan0) → même échec

## Test décisif : U-Boot (tranche HW vs Linux en 2 min)

Le bootloader est **Tow-Boot 2022.07**. Via la console série (`/dev/ttyUSB0`, 115200 8N1) :

1. Reboot : `sync; sync; reboot -f` (le `-f` évite le hang unmount du SSD USB `/data` ; sinon `reboot` peut se bloquer 180s sur `sd [sdb] timing out`).
2. **Interrompre l'autoboot** : spammer **ESC** (`\x1b`) ou **Ctrl+C** dès l'apparition d'U-Boot (PAS ENTER — ENTER sélectionne un noyau dans le menu).
3. Dans le menu boîte : descendre (flèche bas `\x1b[B` ×7) jusqu'à **« Firmware Console »** → ENTER → prompt `=>`.
4. Mapping U-Boot : `eth0=mvpp2-0, eth1=mvpp2-1 [PRIME], eth2=mvpp2-2`. Le câble WAN = **eth2 = mvpp2-2**.
5. Tester :
   ```
   setenv ipaddr 192.168.1.200
   setenv netmask 255.255.255.0
   setenv gatewayip 192.168.1.254
   setenv ethact mvpp2-2
   ping 192.168.1.254
   ```
   - `host 192.168.1.254 is alive` → **HW sain, bug Linux** (cas nominal de cette panne).
   - échec → alors seulement suspecter câble/port/Freebox.
6. Retour Linux : `boot` (ou `run bootcmd`).

Note : `Net: Requested port mode (25) not supported` / `Wrong port mode (25)` dans U-Boot = le **cage SFP+ 10G vide** (Comphy-4 SFI0), **normal**, sans rapport avec eth2.

## Fix permanent (installé 2026-07-28)

Deux mécanismes pour que `ethtool -A eth2 autoneg off rx off tx off` survive au reboot :

1. **networkd `.link`** (natif, appliqué par udevd dès l'apparition d'eth2 — couvre le DHCP au boot) — `/etc/systemd/network/10-secubox-eth2-noflowctl.link` :

```ini
[Match]
OriginalName=eth2

[Link]
AutoNegotiationFlowControl=no
RXFlowControl=no
TXFlowControl=no
```

2. **Service systemd backstop** (garanti, commande exacte) — `/etc/systemd/system/secubox-eth2-flowctl-off.service`, `Type=oneshot`, `ExecStart=/sbin/ethtool -A eth2 autoneg off rx off tx off`, `enable`d sur `multi-user.target`.

⚠️ **NE PAS** tenter unbind/rebind du driver (`/sys/bus/platform/drivers/mvpp2/{unbind,bind}`) : le re-probe **échoue en `-12 ENOMEM`** (mémoire DMA fragmentée après le boot) et **supprime TOUS les netdevs mvpp2** (eth1/eth2 + switch lan0-3) → box sans réseau, reboot obligatoire. Testé, à proscrire.

### À faire — durcir dans la source (pas encore fait)

Le fix ci-dessus est **live sur gk2**. Pour la durabilité inter-reflash, backporter le `.link` + le service dans le paquet board (`board/mochabin/` + `secubox-net-detect`) — cf. **#913**. Tant que ce n'est pas fait, un reflash/réinstall perd le fix.

## Config attendue

- WAN = `eth2` (câble sur le port WAN isolé), `192.168.1.200/24`, gw `192.168.1.254`, DHCP.
- Piège récurrent : au boot la route par défaut se recolle parfois sur **`lan0` (linkdown)** alors que le câble est sur eth2 → corriger : `ip route replace default via 192.168.1.254 dev eth2`. Le masquerade LXC doit viser la vraie iface WAN (`oif eth2 masquerade`) — cf. HISTORY:2509.
- Fix permanent en cours : **#913** (netplan `.200` statique coexistant avec DHCP, board + `secubox-net-detect`).

## Accès de secours

- Console série : `minicom -D /dev/ttyUSB0` (ou `ssh`/`cat` sur `/dev/ttyUSB0`), 115200 8N1. Login `root` / `secubox`.
- SSH normal (quand le réseau marche) : `ssh root@192.168.1.200` (clé).
