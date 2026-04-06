# Installation ARM via U-Boot

[English](ARM-Installation) | [中文](ARM-Installation-ZH)

Ce guide explique comment installer SecuBox sur les cartes ARM (Marvell Armada) en utilisant U-Boot pour flasher l'image sur l'eMMC depuis une clé USB ou une carte SD.

## Cartes supportées

| Carte | SoC | RAM | Profil |
|-------|-----|-----|--------|
| ESPRESSObin v7 | Armada 3720 | 1-2 Go | secubox-lite |
| ESPRESSObin Ultra | Armada 3720 | 1-4 Go | secubox-lite |
| MOCHAbin | Armada 7040 | 4 Go | secubox-full |

## Limites de stockage eMMC

| Carte | eMMC | Image max | Par défaut |
|-------|------|-----------|------------|
| ESPRESSObin v7 (sans eMMC) | — | SD uniquement | — |
| ESPRESSObin v7 (4Go) | 4 Go | **3,5 Go** | Utiliser `--size 3.5G` |
| ESPRESSObin v7 (8Go) | 8 Go | 6 Go | 4 Go |
| ESPRESSObin Ultra | 8 Go | 6 Go | 4 Go |
| MOCHAbin | 8 Go | 6 Go | 4 Go |

**Notes :**
- Laisser environ 500 Mo à 2 Go libres pour la partition de données et l'usure de la mémoire
- Pour les cartes avec eMMC de 4 Go : compiler avec `--size 3.5G`
- Le MOCHAbin peut utiliser SATA/NVMe pour des installations plus volumineuses
- `gzwrite` nécessite de la RAM pour la décompression (environ 350 Mo de tampon)

## Prérequis

- Adaptateur console série (USB-TTL)
- Clé USB ou carte SD avec l'image
- Terminal série : `screen`, `minicom` ou PuTTY

### Paramètres de la console série

```
Baud rate:    115200
Data bits:    8
Parity:       None
Stop bits:    1
Flow control: None
```

```bash
# Linux
screen /dev/ttyUSB0 115200
# ou
minicom -D /dev/ttyUSB0 -b 115200
```

## Préparer le support de démarrage

### Option A : Clé USB (Recommandé)

Formater une clé USB avec une partition FAT32 ou ext4 et copier l'image :

```bash
# Download the image
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# Mount USB drive (assuming /dev/sdb1)
sudo mount /dev/sdb1 /mnt

# Copy image
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/

# Unmount
sudo umount /mnt
```

### Option B : Clé USB Live SecuBox

Si vous utilisez une clé USB Live SecuBox, copier l'image sur la partition de persistance (partition 4) :

```bash
# The persistence partition is already ext4
sudo mount /dev/sdX4 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

## Procédure de flash via U-Boot

### 1. Accéder à U-Boot

Connecter la console série et allumer la carte. Appuyer sur une touche pour arrêter le démarrage automatique :

```
Hit any key to stop autoboot:  0
=>
```

### 2. Initialiser l'USB

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found
```

### 3. Vérifier le stockage

```
=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB
```

### 4. Lister les fichiers

Pour une partition FAT32 (partition 1) :
```
=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

Pour une partition ext4 (partition 4 sur USB Live) :
```
=> ls usb 0:4
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

### 5. Flasher sur l'eMMC

```bash
# Set load address (needs ~350MB free RAM)
=> setenv loadaddr 0x1000000

# Load image from USB
# For FAT32 (partition 1):
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# For ext4 (partition 4):
=> load usb 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# Write to eMMC with automatic decompression
=> gzwrite mmc 1 $loadaddr $filesize
```

La commande `gzwrite` décompresse et écrit directement sur l'eMMC. Cela prend 2 à 5 minutes selon la taille de l'image.

### 6. Configurer l'ordre de démarrage

```bash
# Set eMMC as primary boot device
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

# Reboot
=> reset
```

## Alternative : Flash depuis une carte SD

Si l'image est sur une carte SD au lieu d'une clé USB :

```bash
=> mmc dev 0                    # Select SD card
=> ls mmc 0:1                   # List files
=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize    # Write to eMMC
```

## Référence des périphériques de démarrage

| Périphérique | U-Boot | Description |
|--------------|--------|-------------|
| Carte SD | `mmc 0` | Emplacement microSD |
| eMMC | `mmc 1` | eMMC interne (cible d'installation) |
| USB | `usb 0` | Stockage USB |
| SATA | `scsi 0` | Disque SATA (MOCHAbin) |

## Notes spécifiques aux cartes

### ESPRESSObin v7

- **eMMC** : Optionnel, peut nécessiter un démarrage depuis SD si absent
- **RAM** : Les modèles 1 Go ont un espace limité, utiliser `loadaddr 0x1000000`
- **Réseau** : eth0=WAN, lan0/lan1=LAN (switch DSA)

### ESPRESSObin Ultra

- **eMMC** : 8 Go intégré
- **RAM** : Jusqu'à 4 Go
- **Réseau** : Identique au v7

### MOCHAbin

- **eMMC** : 8 Go intégré
- **RAM** : 4 Go (peut charger des images plus volumineuses)
- **Réseau** : Plusieurs ports 10GbE + GbE
- **SATA** : Peut également installer sur un disque SATA

```bash
# MOCHAbin: Flash to SATA instead of eMMC
=> scsi scan
=> gzwrite scsi 0 $loadaddr $filesize
```

## Dépannage

### USB non détecté

```bash
=> usb reset
=> usb tree        # Show USB device tree
=> usb info        # Detailed USB info
```

### eMMC non détecté

```bash
=> mmc list        # List MMC devices
=> mmc dev 1       # Select eMMC
=> mmc info        # Show eMMC info
```

### Échec du chargement (fichier non trouvé)

```bash
=> ls usb 0        # List all partitions
=> ls usb 0:1      # Try partition 1
=> ls usb 0:2      # Try partition 2
```

### Mémoire insuffisante

Pour les cartes avec 1 Go de RAM, s'assurer qu'aucune autre donnée n'est chargée :

```bash
=> setenv loadaddr 0x1000000    # Use lower address
```

### Réinitialiser l'environnement

```bash
=> env default -a
=> saveenv
```

### Vérifier l'environnement actuel

```bash
=> print                    # Show all variables
=> print boot_targets       # Show boot order
=> print loadaddr           # Show load address
```

## Post-installation

Après le flash, la carte démarre automatiquement sur SecuBox.

### Identifiants par défaut

| Utilisateur | Mot de passe |
|-------------|--------------|
| root | secubox |
| secubox | secubox |

### Premières étapes

1. Se connecter via SSH : `ssh root@<IP>`
2. Changer les mots de passe : `passwd`
3. Accéder à l'interface Web : `https://<IP>:8443`

### Interfaces réseau

| Carte | WAN | LAN |
|-------|-----|-----|
| ESPRESSObin | eth0 | lan0, lan1 |
| MOCHAbin | eth0 | eth1-eth4, sfp0-sfp1 |

## Voir aussi

- [[Installation]] - Guide d'installation général
- [[Live-USB]] - Essayer sans installer
- [[Modules]] - Modules disponibles
