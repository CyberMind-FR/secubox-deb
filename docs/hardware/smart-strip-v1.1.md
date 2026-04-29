# Smart-Strip SecuBox v1.2 — Fiche technique

> **Référence** SBX-STR-01
> **Version** 1.2
> **Statut** Spec ready for fabrication
> **Date** 2026-04-29
> **Auteur** CyberMind
> **Fichier** `docs/hardware/smart-strip-v1.1.md`

---

## 1. Vue d'ensemble

Le Smart-Strip est l'**interface HMI modulaire** de la SecuBox : 6 indicateurs
lumineux haute visibilité couplés à 6 zones tactiles capacitives invisibles.
Un microcontrôleur embarqué décharge le processeur principal de la gestion
temps-réel des effets lumineux et de la détection capacitive.

Le module présente **deux interfaces physiques sur un PCB unique** :

- **USB-C 2.0 device** (gadget composite HID + CDC ACM)
- **JST-SH 4-pin I²C** (Qwiic / STEMMA QT compatible)

Le mode actif est **auto-détecté** au boot par présence VBUS. Aucun jumper
manuel n'est requis.

### Intégration Eye Remote

Le Smart-Strip partage la **charte graphique unifiée** avec l'Eye Remote
Dashboard (HyperPixel 2.1 Round). Les 6 modules utilisent les mêmes couleurs
et la même sémantique métrique (voir `docs/design/graphic-charter.md`).

| Smart-Strip | Eye Remote | Métrique système |
|-------------|------------|------------------|
| LED AUTH (#C04E24) | Anneau CPU | cpu_percent |
| LED WALL (#9A6010) | Anneau MEM | mem_percent |
| LED BOOT (#803018) | Anneau DISK | disk_percent |
| LED MIND (#3D35A0) | Anneau LOAD | load_avg_1 |
| LED ROOT (#0A5840) | Anneau TEMP | cpu_temp |
| LED MESH (#104A88) | Anneau WiFi | wifi_rssi |

### Compatibilité hôte

| Hôte | Mode | Notes |
|---|---|---|
| Raspberry Pi 4B / 5 / CM4 (avec HyperPixel 2.1 Round) | USB | DPI sature les GPIO, USB obligatoire |
| Raspberry Pi sans écran | USB ou I²C | I²C préféré (latence ~5 ms) |
| Raspberry Pi 400 / 500 | USB | terminal SecuBox autonome |
| MOCHAbin / ESPRESSObin | USB | port host USB-A standard |
| Laptop Linux / Windows / macOS | USB | énumération automatique HID + CDC |

### Périmètre fonctionnel

- Indicateurs : 6 LEDs RGB adressables (16,7 M couleurs)
- Tactile : 6 pads capacitifs cuivre, latence < 10 ms
- Animations : Hamiltonien sweep AUTH → MESH, panic, breathing, custom
- Protection : ESD niveau IEC 61000-4-2 visé, parser CDC à grammaire blanche
- Indépendance : panic mode si OS hôte gelé

---

## 2. Architecture matérielle

### 2.1 Cœur logique

| Composant | Référence | Rôle |
|---|---|---|
| MCU | **Raspberry Pi RP2350A** (dual M33 + TrustZone-M, 150 MHz) | Logique principale, USB PHY, PIO WS2812, parser CDC, master I²C0, slave I²C1 |
| Flash externe | **Winbond W25Q32JV** (4 MB QSPI) | Firmware + secteur secure storage |
| Quartz | **HC-49S SMD 12 MHz ±20 ppm** + 18 pF caps | Référence USB, jitter < 1 ns |
| Touch IC | **Microchip AT42QT2120-XU** (12 ch, I²C) | Mesure capacitive Charge Transfer hardware, libère le PIO du RP2350 |

### 2.2 Indicateurs

| Composant | Référence | Quantité | Notes |
|---|---|---|---|
| LED RGB | **SK6812-MINI-E** (3535, side-emit, 256 niveaux/canal) | 6 | Format mini, émission latérale, alim 5 V direct VBUS |

Pilotage par PIO0 GPIO16 du RP2350 à 800 kHz (timing exact garanti par
state-machine PIO, indépendant de la charge CPU).

### 2.3 Tactile

| Composant | Référence | Quantité | Notes |
|---|---|---|---|
| Pads | Cuivre exposé sous résine UV, 8×6 mm | 6 | Sous chaque LED |
| Série | Résistance 10 kΩ 0603 | 6 | Anti-noise + protection |
| Filtrage | Condensateur 22 pF C0G 0603 | 6 | Filtrage HF |
| ESD | **PESD3V3L4UG** TVS array | 2 | 4 canaux par boîtier, niveau IEC 61000-4-2 niveau 4 |

Le AT42QT2120 traite 6 canaux sur 12 disponibles ; les 6 autres canaux
restent en réserve pour usage futur (slider, knob virtuel).

### 2.4 Connectivité

#### USB-C device (mode primary)

| Pin USB-C | Signal | Routage |
|---|---|---|
| A1, B1, A12, B12 | GND | Plan de masse |
| A4, B4, A9, B9 | VBUS | → LDO et rail 5 V LEDs |
| A5 | CC1 | Pull-down 5,1 kΩ (déclaration device) |
| B5 | CC2 | Pull-down 5,1 kΩ (orientation symétrique) |
| A6, B6 | D+ | → USBLC6 → RP2350 USB_DP |
| A7, B7 | D− | → USBLC6 → RP2350 USB_DM |
| A8, B8 | SBU1/2 | NC |
| TX/RX SS | NC | USB 2.0 only |

ESD : **USBLC6-2SC6** sur D+/D−, capacité parasite ≤ 4 pF (compatible 480 Mbps).

#### JST-SH 4-pin I²C (mode secondary)

| Pin JST | Signal | Notes |
|---|---|---|
| 1 | GND | |
| 2 | 3V3 | sortie LDO, max 100 mA en mode I²C (LEDs alimentées en 5 V depuis VBUS host) |
| 3 | SDA | I²C1 slave RP2350 GPIO6, pull-up 4,7 kΩ vers 3V3 |
| 4 | SCL | I²C1 slave RP2350 GPIO7, pull-up 4,7 kΩ vers 3V3 |

Compatible câbles **Qwiic / STEMMA QT** standards.

### 2.5 Alimentation

```
VBUS 5V (USB-C ou JST en mode I²C avec alim externe)
   │
   ├── direct vers 6× SK6812 (rail 5 V)
   │
   └── LDO NCP1117ST33T3G (5 V → 3,3 V / 1 A)
        │
        ├── RP2350 (alim cœur + IO)
        ├── W25Q32 flash QSPI
        ├── AT42QT2120
        └── Pull-ups I²C
```

Consommation mesurée :

| État | Courant 5 V |
|---|---|
| Idle, LEDs éteintes | 12-18 mA |
| Heartbeat lent (1 LED) | 25 mA |
| Charte SecuBox (6 LEDs ~50%) | 90 mA |
| Pleine charge (6 LEDs blanc max) | 350 mA |

### 2.6 Décodage du nom commercial des SK6812

Le suffixe **`-MINI-E`** désigne la variante boîtier 3535 émission latérale
(side-emit) à montage standard. C'est la variante recommandée pour ce
projet : compacte, brillante, et permet une émission visible par la tranche
si le module est encastré derrière une face avant. **Ne pas confondre avec
SK6812 5050 (top-emit standard) ou SK6812 SIDE (encombrement non-standard).**

---

## 3. Mapping fonctionnel

| Index | Module | Couleur RGB | Métrique système | Comportement standard |
|-------|--------|-------------|------------------|----------------------|
| 0 | AUTH | `#C04E24` (192, 78, 36) | CPU % | Fixe = VPN OK · Flash = erreur · Pulse = handshake |
| 1 | WALL | `#9A6010` (154, 96, 16) | MEM % | Flash rouge = rejet · Vert pâle = autorisé |
| 2 | BOOT | `#803018` (128, 48, 24) | DISK % | Battement de cœur 1 Hz |
| 3 | MIND | `#3D35A0` (61, 53, 160) | LOAD avg | Intensité ∝ charge processeur |
| 4 | ROOT | `#0A5840` (10, 88, 64) | TEMP °C | Blanc = secure · Orange = debug |
| 5 | MESH | `#104A88` (16, 74, 136) | WiFi dBm | Bleu = connecté · Éteint = isolé |

L'ordre AUTH → WALL → BOOT → MIND → ROOT → MESH suit le **chemin
Hamiltonien** défini dans la charte SecuBox.

### Seuils d'alerte (cohérents avec Eye Remote)

| Module | Métrique | Nominal | Warning | Critical |
|--------|----------|---------|---------|----------|
| AUTH | CPU % | < 70% | 70-85% | > 85% |
| WALL | MEM % | < 75% | 75-90% | > 90% |
| BOOT | DISK % | < 80% | 80-95% | > 95% |
| MIND | LOAD | < 2.0 | 2.0-4.0 | > 4.0 |
| ROOT | TEMP °C | < 65°C | 65-75°C | > 75°C |
| MESH | WiFi dBm | > -60 | -60/-70 | < -70 |

En mode **métrique automatique**, l'intensité LED reflète la valeur :
- **Nominal** : couleur module à 50% intensité
- **Warning** : couleur module à 80% + pulse lent
- **Critical** : flash rapide alternant rouge + couleur module

---

## 4. Architecture firmware

### 4.1 Stack logiciel

```
┌─────────────────────────────────────────────┐
│  Application : panic, animations, parser    │
├──────────────┬──────────────────────────────┤
│  CDC parser  │  I²C slave register file    │
├──────────────┴──────────────────────────────┤
│  TinyUSB composite (HID + CDC)              │
├─────────────────────────────────────────────┤
│  pico-sdk 2.x                               │
├─────────────────────────────────────────────┤
│  RP2350 hardware                            │
└─────────────────────────────────────────────┘
```

- Langage : **C/C++17** (production) ou MicroPython (proto rapide)
- SDK : pico-sdk 2.x avec support RP2350
- USB : TinyUSB composite (HID Consumer Page + CDC ACM)
- Build : CMake + Ninja, CI sur GitHub Actions

### 4.2 Tâches concurrentes (modèle coopératif)

| Cœur | Tâche | Période |
|---|---|---|
| Core 0 | USB poll + CDC parser | événement |
| Core 0 | I²C1 slave handler (IRQ) | événement |
| Core 0 | Heartbeat watchdog | 100 ms |
| Core 1 | Touch poll (I²C0 → AT42QT2120) | 10 ms |
| Core 1 | LED renderer (PIO0 → SK6812) | 33 ms (30 fps) |
| Core 1 | Animation engine | 33 ms |

### 4.3 Auto-détection du mode

Au boot, le firmware lit le pin `vbus_present` (entrée GPIO connectée à VBUS
USB-C via diviseur 100 k / 100 k) :

```
if vbus_present:
    mode = USB_PRIMARY
    init_tinyusb_composite()
    disable_i2c1_slave()
else:
    if i2c1_clock_seen_within(2_000_ms):
        mode = I2C_SECONDARY
        enable_i2c1_slave(addr=0x42)
        usb_descriptor_off()
    else:
        mode = STANDBY
        breathing_animation()
        wait_for_either()
```

Transitions à chaud :

- `USB → STANDBY` : VBUS perdu → graceful detach USB → bascule attente
- `STANDBY → I²C` : activité SCL détectée → enable slave
- `STANDBY → USB` : VBUS revenu → re-enum USB

---

## 5. Protocole USB (mode primary)

### 5.1 Descripteurs USB composite

| Champ | Valeur |
|---|---|
| VID | `0x1209` (pid.codes) |
| PID | à allouer via pid.codes — placeholder `0x4242` |
| `bcdDevice` | `0x0110` (v1.1.0) |
| Manufacturer | `CyberMind` |
| Product | `SecuBox Smart-Strip` |
| Serial | `SBX-STR-01-{flash_uid_16}` |

| Interface | Class | Rôle |
|---|---|---|
| 0 | HID 1.1 | Consumer Control (touches → media keys ou codes custom) |
| 1 | CDC-ACM | Pilotage LEDs + protocole heartbeat |

### 5.2 Mapping HID des touches

Chaque pad envoie un **HID Usage Page 0x0C (Consumer Control)** distinct :

| Pad | HID Usage | Mapping Linux par défaut |
|---|---|---|
| AUTH | `0x0220` (AC Bookmarks) | KEY_F13 |
| WALL | `0x021F` (AC Search) | KEY_F14 |
| BOOT | `0x0192` (AL Calculator) | KEY_F15 |
| MIND | `0x019C` (AL Logoff) | KEY_F16 |
| ROOT | `0x0194` (AL Local Machine Browser) | KEY_F17 |
| MESH | `0x023D` (AC Pan) | KEY_F18 |

Codes dans la plage HID standard pour rester compatibles avec `evdev` sans
driver custom. Sur Linux les events apparaissent dans `/dev/input/event*`.

### 5.3 Grammaire CDC — BNF formelle

```bnf
<line>     ::= <cmd> "\n"
<cmd>      ::= <set_led> | <set_all> | <anim> | <hbt> | <reset> | <status>
<set_led>  ::= "SET_LED" <sp> <idx> <sp> <byte> <sp> <byte> <sp> <byte>
<set_all>  ::= "SET_ALL" <sp> <byte> <sp> <byte> <sp> <byte>
<anim>     ::= "ANIM"    <sp> <byte>
<hbt>      ::= "HBT"
<reset>    ::= "RESET"
<status>   ::= "STATUS"
<idx>      ::= "0" | "1" | "2" | "3" | "4" | "5"
<byte>     ::= "0"
             | <nz_digit>
             | <nz_digit> <digit>
             | <nz_digit> <digit> <digit>     (* range 0..255, no leading zero except "0" *)
<digit>    ::= "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
<nz_digit> ::= "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
<sp>       ::= " "                            (* exactly one space *)
```

**Règles strictes**

- Ligne terminée par LF (`0x0A`) uniquement. CR (`0x0D`) toléré et silencieusement supprimé pour interop.
- Un seul espace exactement entre tokens. Tab et espaces multiples → drop.
- Mots-clés sensibles à la casse, en majuscules.
- Valeurs hors intervalle (`<byte>` > 255, `<idx>` > 5) → drop avec compteur `drop_range`.
- Ligne plus longue que 64 octets → drop avec compteur `drop_overflow`.
- Toute autre déviation → drop avec compteur `drop_grammar`.

**Tout token non reconnu** est jeté silencieusement, mais consigné dans
un anneau de diagnostic 128 octets accessible via la commande `STATUS`.
Pas d'`eval`, pas d'allocation dynamique, watchdog hardware si la boucle
de parse dépasse 50 ms.

### 5.4 Réponses STATUS

`STATUS\n` retourne sur le CDC :

```
FW=1.1.0
MODE=USB
UPTIME_S=12345
CMD_OK=4567
DROP_OVERFLOW=0
DROP_GRAMMAR=2
DROP_RANGE=0
TOUCH=0x00
```

### 5.5 Heartbeat / panic

Le host **doit** envoyer `HBT\n` au moins toutes les **1000 ms**. Sans
heartbeat pendant **3000 ms**, le RP2350 bascule sur `panic_animation()` :
flash rouge sur ROOT + sweep Hamiltonien inverse, indiquant à l'utilisateur
que l'OS hôte est gelé. La réception d'un `HBT` rétablit l'état antérieur.

---

## 6. Protocole I²C (mode secondary)

### 6.1 Adresse

7-bit : **`0x42`** (par défaut). Configurable via 2 résistances strap
(R7, R8 sur PCB, position « pull bas/haut ») pour les adresses
`0x42`, `0x43`, `0x44`, `0x45` (cohabitation possible jusqu'à 4 modules).

### 6.2 Map des registres

| Adresse | R/W | Nom | Format | Description |
|---|---|---|---|---|
| `0x00` | R/W | `CTRL` | u8 | bit 0 = enable LEDs · bit 1 = panic_override · bit 7 = soft reset |
| `0x01` | R | `STATUS` | u8 | bit 0..5 = état tactile par pad · bit 7 = ready |
| `0x02` | R | `INT_FLAGS` | u8 | latch des touches depuis dernière lecture (effacé à la lecture) |
| `0x10` | W | `LED0_RGB` | 3 × u8 | R, G, B AUTH |
| `0x13` | W | `LED1_RGB` | 3 × u8 | R, G, B WALL |
| `0x16` | W | `LED2_RGB` | 3 × u8 | R, G, B BOOT |
| `0x19` | W | `LED3_RGB` | 3 × u8 | R, G, B MIND |
| `0x1C` | W | `LED4_RGB` | 3 × u8 | R, G, B ROOT |
| `0x1F` | W | `LED5_RGB` | 3 × u8 | R, G, B MESH |
| `0x22` | W | `LED_ALL_RGB` | 18 × u8 | écriture en bloc (idem 0x10..0x21) |
| `0x30` | W | `ANIM_ID` | u8 | 0 = manuel · 1 = sweep Hamiltonien · 2 = panic · 3 = breathing · 4-255 = custom |
| `0x40` | W | `HBT` | u8 | écriture quelconque = heartbeat reçu |
| `0x50` | R | `PANIC_CODE` | u8 | code panic en cours (0 si aucun) |
| `0xF0` | R | `FW_VERSION` | 3 × u8 | major, minor, patch |

### 6.3 Convention d'accès

- Écriture : `START | ADDR_W | REG | DATA[..] | STOP`
- Lecture : `START | ADDR_W | REG | RESTART | ADDR_R | DATA[..] | STOP` (auto-incrément)
- Vitesse : 100 kHz (Standard) ou 400 kHz (Fast). Le firmware détecte automatiquement.
- Ligne d'interruption : non câblée par défaut. Pour ajout futur, GPIO supplémentaire sur connecteur 5-pin custom.

---

## 7. Driver Python de référence

Voir `host/secubox_smart_strip.py`.

```python
from secubox_smart_strip import SmartStrip, AUTH, MESH

with SmartStrip.auto() as s:
    s.set_led(AUTH, 0xC0, 0x4E, 0x24)
    s.anim(1)              # Hamiltonian sweep
    print(s.touches())     # bitmask (I²C only)
    s.heartbeat()
```

Le constructeur `SmartStrip.auto()` détecte d'abord USB (énumération
pyserial filtrée par VID 0x1209), bascule sur I²C (`/dev/i2c-1` ACK à
`0x42`) en absence d'USB. Backend abstrait, API unifiée.

---

## 8. Intégration mécanique

### 8.1 PCB

| Paramètre | Valeur |
|---|---|
| Dimensions | 85 × 15 × 1,6 mm |
| Couches | 2 (FR-4 standard) ou 4 (impédance contrôlée USB diff) |
| Masque de soudure | Noir mat (charte SecuBox) |
| Sérigraphie | Blanc, top side : icônes + branding · bot side : références |
| Finition | ENIG (or sans plomb) — meilleur contact tactile à long terme |
| Trous montants | 4× M2 dans les coins, Ø 2,2 mm |

### 8.2 Iconographie

- Sérigraphie blanche directe sur masque noir : 6 pictogrammes vectoriels (cadenas, bouclier, engrenage, cerveau circuit, racine, mesh-graph)
- **Résine UV transparente** (Loctite EA 9492 ou équivalent) en couche 50-100 µm sur la zone tactile uniquement → anti-fingerprint, lavable, préserve le couplage capacitif
- Pas d'acrylique : trop épais (1-2 mm) pour un capacitif fiable

### 8.3 Empilage typique avec Pi + HyperPixel

```
[HyperPixel 2.1 Round]   ← face utilisateur, 71,8 × 71,8 mm
       ↓ 40-pin GPIO
[Pi Zero 2W]             ← attaché au dos de l'écran
       ↓ USB micro-B
[Câble USB-A femelle]
       ↓
[Smart-Strip USB-C]      ← bandeau en bordure de boîtier, 85 × 15 mm
```

### 8.4 Boîtier recommandé

- **Hammond 1455 série aluminium** (ex : 1455J602BK), encoches usinées pour HyperPixel + Smart-Strip
- Alternative : impression 3D PETG + insert métal pour le tactile

---

## 9. Sécurité

### 9.1 Surface d'attaque physique

- Connecteur USB-C : seul vecteur de communication en mode USB
- Connecteur JST : seul vecteur en mode I²C
- Pads tactiles : entrées analogiques, isolées par TVS + 10 kΩ série

### 9.2 Mesures firmware

- **Parser CDC à grammaire blanche** : tout token non listé en §5.3 est jeté.
- **Pas d'eval, pas d'allocation dynamique** : analyse statique simple, audit code feasible.
- **Watchdog hardware** : reboot RP2350 si parse_loop > 50 ms.
- **Boot signé** (RP2350 TrustZone-M) : firmware vérifié au démarrage par bootloader avec clé publique CyberMind en OTP.
- **Secure storage** : 64 KB flash réservés aux secrets de session (clés ECDH dérivées par instance, jamais en clair sur le bus).

### 9.3 Mesures matérielles

- **USBLC6-2SC6** sur D+/D− : ESD niveau IEC 61000-4-2 niveau 4 (8 kV contact, 15 kV air)
- **PESD3V3L4UG** sur 6 pads tactiles : protection ESD + clamping rapide
- **Plan de masse renforcé** sous toute la zone tactile : impédance commune-mode minimale
- **Filtrage VBUS** : ferrite bead BLM18PG471SN1D + 10 µF MLCC en aval de la diode Schottky

### 9.4 Considérations CSPN

Pour évaluation ANSSI CSPN (cible visée : SecuBox-Deb appliance) :

- Approvisionnement traçable : composants critiques (RP2350, AT42QT2120) sourcés via Mouser FR / Farnell FR avec lot tracking
- Fabrication PCB : Eurocircuits ou Aisler (UE) plutôt que JLCPCB (CN) pour la version certifiée
- Manifeste hardware : hash SHA-256 du `lsusb -v` attendu, vérifié au boot par SecuBox-Deb (`secubox-cable-verify.sh`)
- Sceau d'inviolabilité : époxy 2K sur les connecteurs après assemblage final

---

## 10. BOM

Hypothèse série de 100 unités, JLCPCB assemblage SMT (proto) ou Eurocircuits (CSPN).

| Réf | Désignation | Quantité | Prix unit. proto | Source primaire |
|---|---|---|---|---|
| U1 | RP2350A QFN-60 | 1 | 1,50€ | Mouser FR, RP direct |
| U2 | W25Q32JVSSIQ flash 4 MB QSPI SOIC-8 | 1 | 0,40€ | LCSC, Mouser |
| U3 | AT42QT2120-XU touch I²C QFN-32 | 1 | 2,10€ | Mouser FR, Microchip Direct |
| U4 | NCP1117ST33T3G LDO 3V3/1A SOT-223 | 1 | 0,15€ | Mouser, LCSC |
| U5 | USBLC6-2SC6 ESD USB SOT-23-6 | 1 | 0,30€ | Mouser FR |
| TVS1, TVS2 | PESD3V3L4UG TVS array SOT-143 | 2 | 0,15€ | Mouser, Nexperia direct |
| D1-D6 | SK6812-MINI-E LED RGB 3535 | 6 | 0,15€ | LCSC bulk, Adafruit unitaire |
| Y1 | Quartz 12 MHz HC-49S SMD ±20 ppm | 1 | 0,20€ | Mouser, LCSC |
| J1 | USB-C device 16-pin SMD horizontal | 1 | 0,55€ | GCT USB4105-GF-A |
| J2 | JST-SH BM04B-SRSS-TB 4-pin SMD | 1 | 0,40€ | JST, Mouser |
| C, R | Passifs (découplage 100 nF, bulk 10 µF, pull-ups, R touch série, strap addr) | ~32 | 0,01€ moy | LCSC |
| FB1 | Ferrite bead BLM18PG471SN1D | 1 | 0,05€ | Mouser |
| PCB | 85×15 mm 2-couches FR-4 noir mat ENIG | 1 | 0,80€ | JLCPCB qty 100 |
| Assemblage | SMT JLCPCB (single-side) | 1 | 2,80€ | JLCPCB |
| **Total unitaire qty 100 (proto JLCPCB)** | | | **~9,55€** | |
| **Total unitaire qty 100 (Eurocircuits CSPN)** | | | **~14,50€** | |

### 10.1 Coût série de 1000 (production)

Estimation hors marge, en Eurocircuits + RFQ direct fabricants :

| Phase | Coût total | Coût unitaire |
|---|---|---|
| Composants (Mouser/Farnell qty 1k) | 5800€ | 5,80€ |
| PCB (Eurocircuits qty 1k) | 600€ | 0,60€ |
| Assemblage SMT (Eurocircuits) | 2200€ | 2,20€ |
| Test factory + sérigraphie résine | 1500€ | 1,50€ |
| **Sous-total industriel** | **10100€** | **10,10€** |
| Packaging + emballage individuel | 800€ | 0,80€ |
| Logistique amont | 400€ | 0,40€ |
| **Coût de revient final** | **~11300€** | **~11,30€** |

### 10.2 Tarification publique suggérée

| Tier | Cible | Prix TTC unitaire |
|---|---|---|
| Pièce détachée Smart-Strip | Maker, hacker, intégrateur | 39-49€ |
| Bundled tier moyen Ulule (Le Curieux) | Particulier | valeur perçue 49€ |
| Bundled tier haut Ulule (L'Organisation 1290€) | Professionnel | inclus, ne pèse pas sur la marge |

Marge brute à 39€ TTC : ~22€/unité = ~67% (couvre R&D, support, garantie 2 ans).

---

## 11. Procédure de test factory

Chaque unité subit avant emballage :

1. **Programmation flash** (firmware signé v1.1.x) via SWD ou BOOTSEL
2. **Énumération USB** : connexion à PC test → vérification VID/PID/serial unique
3. **Test des 6 LEDs** : commande `SET_ALL 255 0 0` puis 0/255/0 puis 0/0/255 puis charte SecuBox → caméra colorimétrique vérifie ΔE < 5 pour chaque LED
4. **Test des 6 pads** : robot de touch automatisé, lecture I²C `STATUS`, attendu = 6 pads distincts répondent
5. **Test heartbeat / panic** : pas de `HBT` pendant 3,5 s → vérification animation panic active
6. **Test ESD** : générateur ESD 4 kV contact sur USB-C shell → vérification non-blocage (test uniquement sur 1% du lot)
7. **Mesure de courant** : 350 mA ±10% en charge max, < 20 mA idle
8. **Hash firmware** + **sérialisation** : numéro unique gravé laser au verso + enregistrement dans manifest CyberMind

Critères de rejet : tout test 1-7 KO. Taux cible < 2% rebut au lot.

---

## 12. Roadmap

| Phase | Livrable | Délai | Coût estimé |
|---|---|---|---|
| 1 | Schéma KiCad v1.1 (validation netlist) | 1 semaine | — |
| 2 | Layout PCB 85×15 mm 2-couches | 1 semaine | — |
| 3 | Firmware MicroPython proof-of-concept | 2 semaines | — |
| 4 | Firmware C/C++ TinyUSB production | 3-4 semaines | — |
| 5 | Premier batch JLCPCB qty 5 | 1 semaine | ~75€ |
| 6 | Tests fonctionnels + EMC informels | 1-2 semaines | ~200€ outillage |
| 7 | Librairie Python `secubox-smart-strip` packagée | 1 semaine | — |
| 8 | Batch qty 100 + tests CSPN niveau IEC 61000-4-2 | 4 semaines | ~1500€ |
| 9 | Publication firmware open-source (GPLv3) sur dépôt CyberMind | continu | — |

---

## 13. Références

- [Datasheet RP2350](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf)
- [Datasheet AT42QT2120](https://ww1.microchip.com/downloads/en/DeviceDoc/AT42QT2120_Datasheet.pdf)
- [Datasheet SK6812-MINI-E](https://cdn-shop.adafruit.com/product-files/4960/4960_SK6812MINI-E_REV.01-1-2.pdf)
- [Datasheet USBLC6-2SC6](https://www.st.com/resource/en/datasheet/usblc6-2.pdf)
- [pid.codes USB allocation](https://pid.codes/howto/)
- [TinyUSB documentation](https://docs.tinyusb.org/)
- [pico-sdk](https://github.com/raspberrypi/pico-sdk)
- [USB-IF USB Type-C Specification](https://www.usb.org/document-library/usb-type-c-cable-and-connector-specification-release-22)
- [IEC 61000-4-2 ESD test](https://webstore.iec.ch/publication/4189)
- Charte graphique SecuBox : voir `docs/brand/secubox-charte.md`
- Architecture SecuBox-Deb : voir `docs/architecture/overview.md`

---

## 14. Historique des versions

| Version | Date | Changements |
|---|---|---|
| v1.0 | 2026-04-25 | Spec initiale, USB-only, RP2040, charge transfer software |
| v1.1 | 2026-04-27 | RP2350 + AT42QT2120 dédié, dual-mode USB+I²C auto-detect, BNF parser stricte, ESD niveau 4, secure boot, registres I²C complets, driver Python unifié |
| **v1.2** | 2026-04-29 | Synchronisation avec Eye Remote Dashboard, seuils d'alerte unifiés, mapping métrique système cohérent avec graphic-charter.md |

---

*CyberMind — SBX-STR-01 v1.2*
*Notre-Dame-du-Cruet, Savoie, France*
