# Smart-Strip — Interface HMI modulaire

> **Référence:** SBX-STR-01 v1.1
> **Statut:** Spec ready for fabrication
> **Date:** 2026-04-27

## Vue d'ensemble

Le **Smart-Strip** est l'interface HMI modulaire de SecuBox : 6 indicateurs lumineux RGB (SK6812-MINI-E) couplés à 6 zones tactiles capacitives invisibles. Un microcontrôleur RP2350A embarqué décharge le processeur principal de la gestion temps-réel.

## Caractéristiques techniques

| Paramètre | Valeur |
|-----------|--------|
| MCU | Raspberry Pi RP2350A (dual M33 + TrustZone-M, 150 MHz) |
| Touch IC | Microchip AT42QT2120-XU (12 ch I²C) |
| LEDs | 6× SK6812-MINI-E (RGB side-emit, 5V) |
| Flash | Winbond W25Q32JV (4 MB QSPI) |
| Dimensions | 85 × 15 × 1.6 mm |

## Connectivité

### USB-C 2.0 Device (mode primary)

| Champ | Valeur |
|-------|--------|
| VID | `0x1209` (pid.codes) |
| PID | `0x4242` |
| Interfaces | HID Consumer Page + CDC ACM |

### JST-SH 4-pin I²C (mode secondary)

| Pin | Signal |
|-----|--------|
| 1 | GND |
| 2 | 3V3 |
| 3 | SDA (GPIO6) |
| 4 | SCL (GPIO7) |

Adresse I²C : **0x42** (Qwiic / STEMMA QT compatible)

## Mapping fonctionnel

Chemin Hamiltonien AUTH → MESH :

| Index | Icône | Rôle | Couleur charte |
|-------|-------|------|----------------|
| 0 | AUTH | VPN / chiffrement | `#C04E24` |
| 1 | WALL | Pare-feu nftables/CrowdSec | `#9A6010` |
| 2 | BOOT | Système / OS | `#803018` |
| 3 | MIND | Charge IA / CPU | `#3D35A0` |
| 4 | ROOT | Privilèges / intégrité | `#0A5840` |
| 5 | MESH | Maillage WireGuard/Tailscale | `#104A88` |

## Protocole CDC

```bnf
<cmd>      ::= <set_led> | <set_all> | <anim> | <hbt> | <reset> | <status>
<set_led>  ::= "SET_LED" <sp> <idx> <sp> <byte> <sp> <byte> <sp> <byte>
<set_all>  ::= "SET_ALL" <sp> <byte> <sp> <byte> <sp> <byte>
<anim>     ::= "ANIM" <sp> <byte>
<hbt>      ::= "HBT"
```

### Heartbeat / Panic

Le host **doit** envoyer `HBT\n` toutes les **1000 ms**. Sans heartbeat pendant **3000 ms**, le module bascule en `panic_animation()`.

## Fichiers

| Fichier | Description |
|---------|-------------|
| [Fiche technique complète](../docs/hardware/smart-strip-v1.1.md) | Spec 550 lignes |
| [Simulateur interactif](../docs/hardware/smart-strip/simulator.html) | Mockup HTML |
| `packages/secubox-smart-strip/firmware/` | Parser CDC, ring buffer |
| `packages/secubox-smart-strip/host/` | Driver Python unifié |

## Simulateur

Un simulateur interactif est disponible pour tester les animations :

```bash
# Ouvrir le simulateur dans le navigateur
xdg-open docs/hardware/smart-strip/simulator.html
```

## BOM

| Phase | Coût unitaire |
|-------|---------------|
| Proto JLCPCB qty 100 | ~9,55€ |
| Production Eurocircuits CSPN | ~14,50€ |
| Tarif public | 39-49€ TTC |

## Roadmap

- [ ] Schéma KiCad v1.1 (netlist)
- [ ] Layout PCB 85×15 mm
- [ ] Firmware MicroPython PoC
- [ ] Firmware C/C++ TinyUSB prod
- [ ] Premier batch qty 5
