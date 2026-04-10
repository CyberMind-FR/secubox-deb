# ARM-Installation über U-Boot

[English](ARM-Installation) | [Français](ARM-Installation-FR) | [中文](ARM-Installation-ZH)

Diese Anleitung behandelt die Installation von SecuBox auf ARM-Boards (Marvell Armada) unter Verwendung von U-Boot zum Flashen des Images auf eMMC von USB oder SD-Karte.

## Unterstützte Boards

| Board | SoC | RAM | Profil |
|-------|-----|-----|--------|
| ESPRESSObin v7 | Armada 3720 | 1-2 GB | secubox-lite |
| ESPRESSObin Ultra | Armada 3720 | 1-4 GB | secubox-lite |
| MOCHAbin | Armada 7040 | 4 GB | secubox-full |

## eMMC-Speichergrenzen

| Board | eMMC | Max Image | Standard |
|-------|------|-----------|----------|
| ESPRESSObin v7 (ohne eMMC) | — | Nur SD | — |
| ESPRESSObin v7 (4GB) | 4 GB | **3,5 GB** | `--size 3.5G` verwenden |
| ESPRESSObin v7 (8GB) | 8 GB | 6 GB | 4 GB |
| ESPRESSObin Ultra | 8 GB | 6 GB | 4 GB |
| MOCHAbin | 8 GB | 6 GB | 4 GB |

**Hinweise:**
- ~500MB-2GB für Datenpartition und Wear-Leveling freilassen
- Für 4GB eMMC-Boards: mit `--size 3.5G` bauen
- MOCHAbin kann SATA/NVMe für größere Installationen verwenden
- `gzwrite` benötigt RAM zum Dekomprimieren (~350MB Puffer)

## Voraussetzungen

- Serieller Konsolenadapter (USB-TTL)
- USB-Laufwerk oder SD-Karte mit dem Image
- Serielles Terminal: `screen`, `minicom` oder PuTTY

### Serielle Konsoleneinstellungen

```
Baudrate:     115200
Datenbits:    8
Parität:      Keine
Stoppbits:    1
Flusskontrolle: Keine
```

```bash
# Linux
screen /dev/ttyUSB0 115200
# oder
minicom -D /dev/ttyUSB0 -b 115200
```

## Boot-Medium vorbereiten

### Option A: USB-Laufwerk (Empfohlen)

Formatieren Sie ein USB-Laufwerk mit einer FAT32- oder ext4-Partition und kopieren Sie das Image:

```bash
# Image herunterladen
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# USB-Laufwerk mounten (angenommen /dev/sdb1)
sudo mount /dev/sdb1 /mnt

# Image kopieren
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/

# Unmounten
sudo umount /mnt
```

### Option B: SecuBox Live USB

Bei Verwendung eines SecuBox Live USB kopieren Sie das Image auf die Persistenz-Partition (Partition 4):

```bash
# Die Persistenz-Partition ist bereits ext4
sudo mount /dev/sdX4 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

## U-Boot Flash-Prozedur

### 1. U-Boot aufrufen

Serielle Konsole verbinden und Board einschalten. Beliebige Taste drücken, um Autoboot zu stoppen:

```
Hit any key to stop autoboot:  0
=>
```

### 2. USB initialisieren

```
=> usb reset
resetting USB...
USB XHCI 1.00
scanning bus usb@58000 for devices... 2 USB Device(s) found
scanning usb for storage devices... 1 Storage Device(s) found
```

### 3. Speicher verifizieren

```
=> usb storage
  Device 0: Vendor: Kingston Rev:  Prod: DataTraveler 3.0
            Type: Removable Hard Disk
            Capacity: 29510.4 MB = 28.8 GB
```

### 4. Dateien auflisten

Für FAT32-Partition (Partition 1):
```
=> ls usb 0:1
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

Für ext4-Partition (Partition 4 auf Live USB):
```
=> ls usb 0:4
       314543223 secubox-espressobin-v7-bookworm.img.gz
```

### 5. Auf eMMC flashen

```bash
# Ladeadresse setzen (benötigt ~350MB freien RAM)
=> setenv loadaddr 0x1000000

# Image von USB laden
# Für FAT32 (Partition 1):
=> load usb 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# Für ext4 (Partition 4):
=> load usb 0:4 $loadaddr secubox-espressobin-v7-bookworm.img.gz

# Auf eMMC schreiben mit automatischer Dekomprimierung
=> gzwrite mmc 1 $loadaddr $filesize
```

Der Befehl `gzwrite` dekomprimiert und schreibt direkt auf eMMC. Dies dauert 2-5 Minuten je nach Image-Größe.

### 6. Boot-Reihenfolge konfigurieren

```bash
# eMMC als primäres Boot-Gerät setzen
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

# Neustart
=> reset
```

## Alternative: Von SD-Karte flashen

Wenn das Image auf der SD-Karte statt USB ist:

```bash
=> mmc dev 0                    # SD-Karte auswählen
=> ls mmc 0:1                   # Dateien auflisten
=> setenv loadaddr 0x1000000
=> load mmc 0:1 $loadaddr secubox-espressobin-v7-bookworm.img.gz
=> gzwrite mmc 1 $loadaddr $filesize    # Auf eMMC schreiben
```

## Boot-Geräte-Referenz

| Gerät | U-Boot | Beschreibung |
|-------|--------|--------------|
| SD-Karte | `mmc 0` | microSD-Slot |
| eMMC | `mmc 1` | Internes eMMC (Installationsziel) |
| USB | `usb 0` | USB-Speicher |
| SATA | `scsi 0` | SATA-Laufwerk (MOCHAbin) |

## Board-spezifische Hinweise

### ESPRESSObin v7

- **eMMC**: Optional, muss möglicherweise von SD booten falls nicht vorhanden
- **RAM**: 1GB-Modelle haben begrenzten Speicher, `loadaddr 0x1000000` verwenden
- **Netzwerk**: eth0=WAN, lan0/lan1=LAN (DSA Switch)

### ESPRESSObin Ultra

- **eMMC**: 8GB eingebaut
- **RAM**: Bis zu 4GB
- **Netzwerk**: Wie v7

### MOCHAbin

- **eMMC**: 8GB eingebaut
- **RAM**: 4GB (kann größere Images halten)
- **Netzwerk**: Mehrere 10GbE + GbE Ports
- **SATA**: Kann auch auf SATA-Laufwerk installieren

```bash
# MOCHAbin: Auf SATA statt eMMC flashen
=> scsi scan
=> gzwrite scsi 0 $loadaddr $filesize
```

## Fehlerbehebung

### USB nicht erkannt

```bash
=> usb reset
=> usb tree        # USB-Gerätebaum anzeigen
=> usb info        # Detaillierte USB-Info
```

### eMMC nicht erkannt

```bash
=> mmc list        # MMC-Geräte auflisten
=> mmc dev 1       # eMMC auswählen
=> mmc info        # eMMC-Info anzeigen
```

### Laden fehlgeschlagen (Datei nicht gefunden)

```bash
=> ls usb 0        # Alle Partitionen auflisten
=> ls usb 0:1      # Partition 1 versuchen
=> ls usb 0:2      # Partition 2 versuchen
```

### Speicher erschöpft

Für 1GB-Boards sicherstellen, dass keine anderen Daten geladen sind:

```bash
=> setenv loadaddr 0x1000000    # Niedrigere Adresse verwenden
```

### Umgebung zurücksetzen

```bash
=> env default -a
=> saveenv
```

### Aktuelle Umgebung prüfen

```bash
=> print                    # Alle Variablen anzeigen
=> print boot_targets       # Boot-Reihenfolge anzeigen
=> print loadaddr           # Ladeadresse anzeigen
```

## Nach der Installation

Nach dem Flashen bootet das Board SecuBox automatisch.

### Standard-Zugangsdaten

| Benutzer | Passwort |
|----------|----------|
| root | secubox |
| secubox | secubox |

### Erste Schritte

1. Per SSH verbinden: `ssh root@<IP>`
2. Passwörter ändern: `passwd`
3. Web UI aufrufen: `https://<IP>:8443`

### Netzwerkschnittstellen

| Board | WAN | LAN |
|-------|-----|-----|
| ESPRESSObin | eth0 | lan0, lan1 |
| MOCHAbin | eth0 | eth1-eth4, sfp0-sfp1 |

## Siehe auch

- [[Installation]] - Allgemeine Installationsanleitung
- [[Live-USB]] - Ausprobieren ohne Installation
- [[MODULES-DE|Module]] - Verfügbare Module
