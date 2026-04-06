# ESPRESSObin — Guide d'installation SecuBox

[English](ESPRESSObin) | [中文](ESPRESSObin-ZH)

Guide complet pour installer SecuBox sur les cartes GlobalScale ESPRESSObin via U-Boot.

## Variantes matérielles

| Modèle | SoC | CPU | RAM | eMMC | Sortie |
|--------|-----|-----|-----|------|--------|
| ESPRESSObin v5 | Armada 3720 | 2× A53 @ 800MHz | 512Mo-1Go | — | 2017 |
| ESPRESSObin v7 | Armada 3720 | 2× A53 @ 1.2GHz | 1-2Go | 0/4/8Go | 2019 |
| ESPRESSObin Ultra | Armada 3720 | 2× A53 @ 1.2GHz | 1-4Go | 8Go | 2020 |

**Support SecuBox :**
- ✅ ESPRESSObin v7 (recommandé)
- ✅ ESPRESSObin Ultra
- ⚠️ ESPRESSObin v5 (limité — 512Mo/1Go RAM, pas de profil SECUBOX_LITE)

## Limites de stockage eMMC

| Configuration | eMMC | Taille image max | Option build |
|---------------|------|------------------|--------------|
| Sans eMMC | — | SD uniquement | — |
| eMMC 4Go | 4 Go | **3.5 Go** | `--size 3.5G` |
| eMMC 8Go | 8 Go | 6 Go | défaut 4G OK |

**Important :**
- Image SecuBox par défaut : **3.5Go** (compatible toutes variantes eMMC)
- `gzwrite` nécessite ~350Mo de RAM pour le buffer de décompression
- Laisser 500Mo+ libres pour le wear leveling sur eMMC

## Disposition de la carte et connecteurs

```
┌─────────────────────────────────────────────────────────┐
│  ESPRESSObin v7 / Ultra                                 │
│                                                         │
│  ┌─────┐  ┌─────┐  ┌─────┐     ┌──────────┐            │
│  │ WAN │  │LAN 1│  │LAN 2│     │ USB 3.0  │            │
│  │ RJ45│  │ RJ45│  │ RJ45│     │  (bleu)  │            │
│  └─────┘  └─────┘  └─────┘     └──────────┘            │
│    eth0     lan0     lan1         USB                  │
│                                                         │
│  [PWR]  [RST]                  ┌──────────┐  ┌──────┐  │
│                                │  µSD     │  │ USB  │  │
│  ○○○○○○ ← UART (J1)            │  slot    │  │ 2.0  │  │
│  123456                        └──────────┘  └──────┘  │
│                                    mmc0       USB      │
│  [DIP SW] ← Mode de boot                               │
│  1 2 3 4 5                                             │
│                                                         │
│           ┌─────────────────┐                          │
│           │     eMMC        │ ← mmc1 (sous la carte)   │
│           │     (8Go)       │                          │
│           └─────────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

## Console série (UART)

### Brochage — Connecteur J1 (6 broches)

```
Broche 1: GND    ← Connecter au GND de l'adaptateur USB-TTL
Broche 2: NC
Broche 3: NC
Broche 4: RX     ← Connecter au TX de l'adaptateur USB-TTL
Broche 5: TX     ← Connecter au RX de l'adaptateur USB-TTL
Broche 6: NC
```

**Paramètres :** 115200 baud, 8N1, pas de contrôle de flux

```bash
# Linux
screen /dev/ttyUSB0 115200
# ou
minicom -D /dev/ttyUSB0 -b 115200

# macOS
screen /dev/tty.usbserial-* 115200

# Windows: PuTTY → Serial → COM3 → 115200
```

## Modes de boot (DIP switches)

L'interrupteur DIP à 5 positions contrôle la source de boot et la vitesse CPU.

### Source de boot (SW1-SW3)

| SW1 | SW2 | SW3 | Source de boot |
|-----|-----|-----|----------------|
| OFF | OFF | OFF | SPI NOR Flash (U-Boot par défaut) |
| ON  | OFF | OFF | eMMC |
| OFF | ON  | OFF | Carte SD |
| ON  | ON  | OFF | UART (recovery) |
| OFF | OFF | ON  | SATA (si présent) |

### Vitesse CPU (SW4)

| SW4 | Fréquence CPU |
|-----|---------------|
| OFF | 1.2 GHz (défaut) |
| ON  | 800 MHz (consommation réduite) |

### Mode debug (SW5)

| SW5 | Mode |
|-----|------|
| OFF | Normal |
| ON  | Debug / JTAG activé |

**Pour un fonctionnement SecuBox normal :** Tous les interrupteurs sur OFF (boot depuis SPI NOR qui charge U-Boot → puis boot depuis eMMC/SD)

## Procédure de flash U-Boot

### Méthode 1 : Clé USB avec gzwrite (Recommandé)

#### Préparer la clé USB

```bash
# Sur votre PC
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Formater la clé en FAT32 ou ext4
sudo mkfs.vfat /dev/sdb1
# ou
sudo mkfs.ext4 /dev/sdb1

# Copier l'image
sudo mount /dev/sdb1 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

#### Flasher via U-Boot

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found

=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB

=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
314543223 bytes read in 3422 ms (87.7 MiB/s)

=> gzwrite mmc 1 $loadaddr $filesize
Uncompressed size: 3758096384 bytes (3.5 GiB)
writing to mmc 1...
3758096384 bytes written in 142568 ms (25.1 MiB/s)
```

### Méthode 2 : Carte SD avec gzwrite

```
=> mmc dev 0
=> ls mmc 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz

=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### Méthode 3 : Boot réseau TFTP

Si vous avez un serveur TFTP :

```
=> setenv serverip 192.168.1.100
=> setenv ipaddr 192.168.1.50
=> setenv loadaddr 0x1000000
=> tftpboot $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize
```

### Méthode 4 : mmc write brut (non compressé)

Pour les fichiers `.img` non compressés (plus lent, nécessite une clé USB plus grande) :

```
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img
=> mmc dev 1
=> mmc write $loadaddr 0 $filesize
```

**Note :** `mmc write` attend un nombre de blocs, pas d'octets. Calculer : `blocs = filesize / 512`

## Configurer l'ordre de boot

Après le flash, définir l'eMMC comme boot principal :

```
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

=> reset
```

## Méthodes de boot automatique

Les images SecuBox incluent deux méthodes de boot automatique :

### Méthode A : boot.scr (Recommandé)

U-Boot recherche automatiquement `boot.scr` sur la partition boot :

```
=> load mmc 1:2 $loadaddr /boot/boot.scr
=> source $loadaddr
```

Ou manuellement :
```
=> setenv bootcmd "load mmc 1:2 0x1000000 /boot/boot.scr; source 0x1000000"
=> saveenv
```

### Méthode B : extlinux.conf (Distroboot)

Si U-Boot supporte distroboot :

```
=> run distro_bootcmd
```

Cela recherche automatiquement `/boot/extlinux/extlinux.conf`.

### Boot manuel (Secours)

Si le boot automatique échoue :

```
=> setenv loadaddr 0x1000000
=> setenv fdt_addr 0x2000000

=> load mmc 1:2 $loadaddr /boot/Image
=> load mmc 1:2 $fdt_addr /boot/dtbs/marvell/armada-3720-espressobin-v7.dtb

=> setenv bootargs "root=LABEL=rootfs rootfstype=ext4 rootwait console=ttyMV0,115200"
=> booti $loadaddr - $fdt_addr
```

## Référence des périphériques U-Boot

| Périphérique | U-Boot | Linux | Description |
|--------------|--------|-------|-------------|
| Carte SD | `mmc 0` | `/dev/mmcblk0` | Slot microSD |
| eMMC | `mmc 1` | `/dev/mmcblk1` | eMMC interne |
| USB | `usb 0` | `/dev/sda` | Stockage USB |
| SPI NOR | `sf 0` | `/dev/mtd0` | Firmware U-Boot |

## Interfaces réseau (Linux)

L'ESPRESSObin utilise un switch DSA Marvell 88E6341 :

| Interface | U-Boot | Linux | Rôle | IP (défaut) |
|-----------|--------|-------|------|-------------|
| eth0 | — | eth0 | WAN (amont) | Client DHCP |
| lan0 | — | lan0 | Port LAN 1 | Membre br-lan |
| lan1 | — | lan1 | Port LAN 2 | Membre br-lan |
| — | — | br-lan | Bridge LAN | 192.168.1.1/24 |

## Dépannage

### USB non détecté

```
=> usb reset
=> usb tree
=> usb info
```

Essayer un autre port USB ou une clé USB 2.0 (certaines clés USB 3.0 posent problème).

### eMMC non détecté

```
=> mmc list
mmc@d0000: 0 (SD)
mmc@d8000: 1 (eMMC)

=> mmc dev 1
=> mmc info
Device: mmc@d8000
Manufacturer ID: 15
OEM: 100
Name: 8GTF4
Bus Speed: 52000000
Mode: MMC High Speed (52MHz)
Capacity: 7.3 GiB
```

Si `mmc dev 1` échoue, la carte n'a peut-être pas d'eMMC — utiliser la carte SD.

### gzwrite échoue — Mémoire insuffisante

```
=> setenv loadaddr 0x1000000
```

Pour les cartes 1Go, vérifier que l'image est compressée (`.img.gz`).

### Le boot échoue — boot_targets incorrect

```
=> print boot_targets
boot_targets=mmc0 usb0 mmc1

=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
=> reset
```

### Réinitialiser l'environnement U-Boot

```
=> env default -a
=> saveenv
=> reset
```

### Vérifier l'environnement

```
=> print
=> print bootcmd
=> print boot_targets
```

## Recovery — Boot UART

Si U-Boot est corrompu :

1. Configurer les DIP switches : SW1=ON, SW2=ON, SW3=OFF (mode boot UART)
2. Utiliser `mvebu_xmodem` ou `kwboot` pour charger U-Boot via série
3. Flasher un nouveau U-Boot sur SPI NOR
4. Remettre les DIP switches en position normale

```bash
# Recovery Linux (nécessite kwboot)
sudo kwboot -t -b u-boot-espressobin.bin /dev/ttyUSB0 -B 115200
```

## Post-installation

### Identifiants par défaut

| Utilisateur | Mot de passe |
|-------------|--------------|
| root | secubox |
| secubox | secubox |

### Premières étapes

```bash
# Connexion via série ou SSH
ssh root@192.168.1.1

# Changer les mots de passe
passwd root
passwd secubox

# Vérifier le statut
secubox-status

# Accéder à l'interface web
# https://192.168.1.1:8443
```

### Vérifier le réseau

```bash
# Vérifier les interfaces
ip link show

# Vérifier le bridge
bridge link show

# Vérifier les adresses IP
ip addr show
```

## Notes de performance (ESPRESSObin vs MOCHAbin)

| Métrique | ESPRESSObin v7 | MOCHAbin |
|----------|----------------|----------|
| CPU | 2× A53 @ 1.2GHz | 4× A72 @ 1.4GHz |
| RAM | 1-2 Go | 4 Go |
| Réseau | 3× GbE | 4× GbE + 2× 10GbE |
| Mode DPI | Passif uniquement | Inline capable |
| CrowdSec | Mode lite | Mode complet |
| Profil SecuBox | secubox-lite | secubox-full |

## Voir aussi

- [[ARM-Installation]] — Guide d'installation ARM général
- [[Installation]] — Installation x86/VM
- [[Live-USB]] — Essayer sans installer
- [[Modules]] — Modules SecuBox disponibles
- [Wiki ESPRESSObin](http://wiki.espressobin.net/) — Wiki matériel officiel
- [Marvell Armada 3720](https://www.marvell.com/embedded-processors/armada-3700/) — Documentation SoC
