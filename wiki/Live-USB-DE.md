# Live USB Anleitung

[English](Live-USB) | [Français](Live-USB-FR) | [中文](Live-USB-ZH)

Booten Sie SecuBox direkt von einem USB-Laufwerk mit allen vorinstallierten Paketen.

## Download

**Neueste Version:** [secubox-live-amd64-bookworm.img.gz](https://github.com/CyberMind-FR/secubox-deb/releases/latest)

## Funktionen

| Funktion | Beschreibung |
|----------|--------------|
| UEFI Boot | Moderner GRUB-Bootloader |
| SquashFS | Komprimiertes Root (~250MB) |
| Persistenz | Änderungen über Neustarts speichern |
| Slipstream | Alle 30+ SecuBox-Pakete enthalten |

## Auf USB flashen

### Linux / macOS

```bash
# USB-Gerät finden
lsblk

# Flashen (ersetzen Sie /dev/sdX durch Ihr Gerät!)
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
sync
```

### Windows

1. [Rufus](https://rufus.ie/) oder [balenaEtcher](https://etcher.balena.io/) herunterladen
2. Die `.img.gz`-Datei entpacken, um `.img` zu erhalten
3. Die `.img`-Datei auswählen
4. Ihr USB-Laufwerk auswählen
5. Auf Schreiben/Flashen klicken

## Boot-Menü-Optionen

| Option | Beschreibung |
|--------|--------------|
| **SecuBox Live** | Normaler Boot mit Persistenz |
| **Safe Mode** | Minimale Treiber für Fehlerbehebung |
| **No Persistence** | Neustart, Änderungen werden nicht gespeichert |
| **To RAM** | Gesamtes System in Speicher laden |

## Standard-Zugangsdaten

| Dienst | Benutzername | Passwort |
|--------|--------------|----------|
| Web UI | admin | admin |
| SSH | root | secubox |
| SSH | secubox | secubox |

**Wichtig:** Ändern Sie die Passwörter nach dem ersten Start!

## Netzwerkzugang

Nach dem Booten:

1. IP finden: `ip addr` oder Router-DHCP-Leases prüfen
2. Web UI: `https://<IP>:8443`
3. SSH: `ssh root@<IP>`

Standard-Netzwerkkonfiguration:
- DHCP-Client auf allen Schnittstellen
- Fallback: 192.168.1.1/24

## Persistenz

Änderungen werden automatisch gespeichert:
- `/home/*` - Benutzerdateien
- `/etc/*` - Konfiguration
- `/var/log/*` - Protokolle
- Installierte Pakete

### Persistenz zurücksetzen

```bash
# Mit "No Persistence" booten, dann:
sudo mkfs.ext4 -L persistence /dev/sdX3
```

## Partitionslayout

| Partition | Größe | Typ | Zweck |
|-----------|-------|-----|-------|
| p1 | 512MB | EFI | GRUB-Bootloader |
| p2 | 2GB | FAT32 | Live-System (SquashFS) |
| p3 | Rest | ext4 | Persistenz |

## Verifizierung

```bash
# Prüfsummen herunterladen
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/SHA256SUMS

# Verifizieren
sha256sum -c SHA256SUMS --ignore-missing
```

## Fehlerbehebung

### USB bootet nicht

1. BIOS/UEFI aufrufen (F2, F12, Del, Esc)
2. USB-Boot aktivieren
3. Secure Boot deaktivieren
4. USB als erstes Boot-Gerät setzen

### Schwarzer Bildschirm

1. "Safe Mode" aus Boot-Menü versuchen
2. `nomodeset` zu Kernel-Parametern hinzufügen:
   - Bei GRUB `e` drücken
   - `nomodeset` zur `linux`-Zeile hinzufügen
   - Strg+X drücken

### Kein Netzwerk

```bash
ip link show
sudo systemctl restart networking
sudo dhclient eth0
```

## Aus Quellcode bauen

```bash
git clone https://github.com/CyberMind-FR/secubox-deb
cd secubox-deb
sudo bash image/build-live-usb.sh --size 8G --slipstream
```

## Siehe auch

- [[Installation]] - Dauerhafte Installation
- [[Configuration]] - Systemkonfiguration
- [[Troubleshooting]] - Weitere Lösungen
