# ESPRESSObin — SecuBox Installationsanleitung

[English](ESPRESSObin) | [Français](ESPRESSObin-FR) | [中文](ESPRESSObin-ZH)

Vollständige Anleitung zur Installation von SecuBox auf GlobalScale ESPRESSObin-Boards über U-Boot.

## Hardware-Varianten

| Modell | SoC | CPU | RAM | eMMC | Release |
|--------|-----|-----|-----|------|---------|
| ESPRESSObin v5 | Armada 3720 | 2× A53 @ 800MHz | 512MB-1GB | — | 2017 |
| ESPRESSObin v7 | Armada 3720 | 2× A53 @ 1.2GHz | 1-2GB | 0/4/8GB | 2019 |
| ESPRESSObin Ultra | Armada 3720 | 2× A53 @ 1.2GHz | 1-4GB | 8GB | 2020 |

**SecuBox-Unterstützung:**
- ✅ ESPRESSObin v7 (empfohlen)
- ✅ ESPRESSObin Ultra
- ⚠️ ESPRESSObin v5 (eingeschränkt — 512MB/1GB RAM, kein SECUBOX_LITE-Profil)

## eMMC-Speichergrenzen

| Konfiguration | eMMC | Max Image-Größe | Build-Flag |
|---------------|------|-----------------|------------|
| Ohne eMMC | — | Nur SD | — |
| 4GB eMMC | 4 GB | **3,5 GB** | `--size 3.5G` |
| 8GB eMMC | 8 GB | 6 GB | Standard 4G OK |

**Wichtig:**
- Standard SecuBox-Image: **3,5GB** (passt auf alle eMMC-Varianten)
- `gzwrite` benötigt ~350MB RAM für Dekomprimierungspuffer
- 500MB+ für Wear-Leveling auf eMMC freilassen

## Board-Layout & Anschlüsse

```
┌─────────────────────────────────────────────────────────┐
│  ESPRESSObin v7 / Ultra                                 │
│                                                         │
│  ┌─────┐  ┌─────┐  ┌─────┐     ┌──────────┐            │
│  │ WAN │  │LAN 1│  │LAN 2│     │ USB 3.0  │            │
│  │ RJ45│  │ RJ45│  │ RJ45│     │  (blau)  │            │
│  └─────┘  └─────┘  └─────┘     └──────────┘            │
│    eth0     lan0     lan1         USB                  │
│                                                         │
│  [PWR]  [RST]                  ┌──────────┐  ┌──────┐  │
│                                │  µSD     │  │ USB  │  │
│  ○○○○○○ ← UART (J1)            │  Slot    │  │ 2.0  │  │
│  123456                        └──────────┘  └──────┘  │
│                                    mmc0       USB      │
│  [DIP SW] ← Boot-Modus                                 │
│  1 2 3 4 5                                             │
│                                                         │
│           ┌─────────────────┐                          │
│           │     eMMC        │ ← mmc1 (Unterseite)      │
│           │     (8GB)       │                          │
│           └─────────────────┘                          │
└─────────────────────────────────────────────────────────┘
```

## Serielle Konsole (UART)

### Pinbelegung — J1 Header (6-Pin)

```
Pin 1: GND    ← Mit USB-TTL GND verbinden
Pin 2: NC
Pin 3: NC
Pin 4: RX     ← Mit USB-TTL TX verbinden
Pin 5: TX     ← Mit USB-TTL RX verbinden
Pin 6: NC
```

**Einstellungen:** 115200 Baud, 8N1, keine Flusskontrolle

```bash
# Linux
screen /dev/ttyUSB0 115200
# oder
minicom -D /dev/ttyUSB0 -b 115200

# macOS
screen /dev/tty.usbserial-* 115200

# Windows: PuTTY → Serial → COM3 → 115200
```

## DIP-Schalter Boot-Modi

Der 5-Positionen DIP-Schalter steuert Boot-Quelle und CPU-Geschwindigkeit.

### Boot-Quelle (SW1-SW3)

| SW1 | SW2 | SW3 | Boot-Quelle |
|-----|-----|-----|-------------|
| AUS | AUS | AUS | SPI NOR Flash (Standard U-Boot) |
| AN  | AUS | AUS | eMMC |
| AUS | AN  | AUS | SD-Karte |
| AN  | AN  | AUS | UART (Recovery) |
| AUS | AUS | AN  | SATA (falls vorhanden) |

### CPU-Geschwindigkeit (SW4)

| SW4 | CPU-Frequenz |
|-----|--------------|
| AUS | 1,2 GHz (Standard) |
| AN  | 800 MHz (reduzierter Stromverbrauch) |

### Debug-Modus (SW5)

| SW5 | Modus |
|-----|-------|
| AUS | Normal |
| AN  | Debug / JTAG aktiviert |

**Für normalen SecuBox-Betrieb:** Alle Schalter AUS (bootet von SPI NOR, das U-Boot lädt → dann Boot von eMMC/SD)

## U-Boot Boot-Skripte (Einfachste Methode)

Vorkompilierte U-Boot-Skripte automatisieren den Boot- und Flash-Prozess.

### Verfügbare Skripte

| Skript | Zweck | Beschreibung |
|--------|-------|--------------|
| `boot-usb.scr` | Live USB Boot | System direkt von USB booten |
| `flash-emmc.scr` | Auf eMMC flashen | Image auf internen Speicher schreiben |
| `boot.scr` | eMMC Boot | Normaler Boot nach Installation |

### USB-Laufwerk vorbereiten

```bash
# Skripte und Image herunterladen
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz
wget https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/board/espressobin-v7/boot-usb.scr
wget https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/board/espressobin-v7/flash-emmc.scr

# USB als FAT32 formatieren
sudo mkfs.vfat -F 32 /dev/sdb1

# Dateien kopieren
sudo mount /dev/sdb1 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo cp boot-usb.scr /mnt/boot.scr
sudo cp flash-emmc.scr /mnt/
sudo umount /mnt
```

### Live USB Boot (Ohne Installation)

Direkt von USB booten, um SecuBox zu testen:

```
Marvell>> usb start
Marvell>> load usb 0:1 $loadaddr boot.scr
Marvell>> source $loadaddr
```

Das System bootet von USB. Daten sind nicht persistent.

### Auf eMMC installieren

SecuBox auf internen eMMC-Speicher flashen:

```
Marvell>> usb start
Marvell>> load usb 0:1 $loadaddr flash-emmc.scr
Marvell>> source $loadaddr
```

Anweisungen folgen, warten bis Flash abgeschlossen (~3 Min), dann:

```
Marvell>> reset
```

USB-Laufwerk entfernen. SecuBox bootet von eMMC.

---

## U-Boot Manuelle Flash-Prozedur

### Methode 1: USB-Laufwerk mit gzwrite (Empfohlen)

#### USB-Laufwerk vorbereiten

```bash
# Auf Ihrem PC
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-espressobin-v7-bookworm.img.gz

# USB als FAT32 oder ext4 formatieren
sudo mkfs.vfat /dev/sdb1
# oder
sudo mkfs.ext4 /dev/sdb1

# Image kopieren
sudo mount /dev/sdb1 /mnt
sudo cp secubox-espressobin-v7-bookworm.img.gz /mnt/
sudo umount /mnt
```

#### Über U-Boot flashen

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

## Boot-Reihenfolge konfigurieren

Nach dem Flashen eMMC als primären Boot setzen:

```
=> setenv boot_targets "mmc1 mmc0 usb0"
=> saveenv
Saving Environment to SPI Flash... done

=> reset
```

## U-Boot Gerätereferenz

| Gerät | U-Boot | Linux | Beschreibung |
|-------|--------|-------|--------------|
| SD-Karte | `mmc 0` | `/dev/mmcblk0` | microSD-Slot |
| eMMC | `mmc 1` | `/dev/mmcblk1` | Internes eMMC |
| USB | `usb 0` | `/dev/sda` | USB-Speicher |
| SPI NOR | `sf 0` | `/dev/mtd0` | U-Boot Firmware |

## Netzwerkschnittstellen (Linux)

ESPRESSObin verwendet einen Marvell 88E6341 DSA-Switch:

| Schnittstelle | U-Boot | Linux | Rolle | IP (Standard) |
|---------------|--------|-------|-------|---------------|
| eth0 | — | eth0 | WAN (Upstream) | DHCP-Client |
| lan0 | — | lan0 | LAN Port 1 | br-lan Mitglied |
| lan1 | — | lan1 | LAN Port 2 | br-lan Mitglied |
| — | — | br-lan | LAN Bridge | 192.168.1.1/24 |

## Fehlerbehebung

### USB nicht erkannt

```
=> usb reset
=> usb tree
=> usb info
```

Anderen USB-Port oder USB 2.0 Laufwerk versuchen (einige USB 3.0 Laufwerke haben Probleme).

### eMMC nicht erkannt

```
=> mmc list
mmc@d0000: 0 (SD)
mmc@d8000: 1 (eMMC)

=> mmc dev 1
=> mmc info
```

Wenn `mmc dev 1` fehlschlägt, hat das Board möglicherweise kein eMMC — SD-Karte verwenden.

### gzwrite fehlgeschlagen — Speicher erschöpft

```
=> setenv loadaddr 0x1000000
```

Für 1GB-Boards sicherstellen, dass das Image komprimiert ist (`.img.gz`).

## Nach der Installation

### Standard-Zugangsdaten

| Benutzer | Passwort |
|----------|----------|
| root | secubox |
| secubox | secubox |

### Erste Schritte

```bash
# Per Serial oder SSH verbinden
ssh root@192.168.1.1

# Passwörter ändern
passwd root
passwd secubox

# Status prüfen
secubox-status

# Web UI aufrufen
# https://192.168.1.1:8443
```

## Leistungsvergleich (ESPRESSObin vs MOCHAbin)

| Metrik | ESPRESSObin v7 | MOCHAbin |
|--------|----------------|----------|
| CPU | 2× A53 @ 1.2GHz | 4× A72 @ 1.4GHz |
| RAM | 1-2 GB | 4 GB |
| Netzwerk | 3× GbE | 4× GbE + 2× 10GbE |
| DPI-Modus | Nur passiv | Inline-fähig |
| CrowdSec | Lite-Modus | Vollmodus |
| SecuBox-Profil | secubox-lite | secubox-full |

## Siehe auch

- [[ARM-Installation]] — Allgemeine ARM-Installationsanleitung
- [[Installation]] — x86/VM Installation
- [[Live-USB]] — Ausprobieren ohne Installation
- [[MODULES-DE|Module]] — Verfügbare SecuBox-Module
- [ESPRESSObin Wiki](http://wiki.espressobin.net/) — Offizielles Hardware-Wiki
- [Marvell Armada 3720](https://www.marvell.com/embedded-processors/armada-3700/) — SoC-Dokumentation
