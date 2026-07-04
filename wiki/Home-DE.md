# SecuBox

**CyberMind · Gondwana · Notre-Dame-du-Cruet · Savoie** | [EN](Home) | [FR](Home-FR) | [中文](Home-ZH)

Vollständige Sicherheitsappliance-Lösung, portiert von OpenWrt auf Debian bookworm. Entwickelt für GlobalScale ARM64-Boards (MOCHAbin, ESPRESSObin) und x86_64-Systeme. **125 Pakete** mit **2000+ API-Endpunkten**.

---

## 🔴 BOOT — Schnellstart

### VirtualBox (2 Minuten) ⭐

Testen Sie SecuBox sofort in VirtualBox — kein USB-Laufwerk erforderlich:

```bash
# Neuestes Image herunterladen
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
gunzip secubox-live-amd64-bookworm.img.gz

# In VDI-Format konvertieren
VBoxManage convertfromraw secubox-live-amd64-bookworm.img secubox-live.vdi --format VDI

# VM erstellen und starten
curl -sLO https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh
chmod +x create-vbox-vm.sh
./create-vbox-vm.sh secubox-live.vdi
```

**Einzeiler mit automatischem Download:**

```bash
curl -sL https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/image/create-vbox-vm.sh | bash -s -- --download
```

Siehe [[Live-USB-VirtualBox]] für vollständige Dokumentation.

### Live USB (Hardware) ⚡

Direkt von USB auf physischer Hardware booten:

```bash
wget https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz
zcat secubox-live-amd64-bookworm.img.gz | sudo dd of=/dev/sdX bs=4M status=progress
```

Siehe [[Live-USB]] für vollständige Anleitung.

### APT-Installation (Bestehendes Debian)

```bash
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt install secubox-full   # oder secubox-lite
```

Siehe [[Installation]] für detaillierte Anweisungen.

---

## 🟠 AUTH — Zugangsdaten

| Dienst | Benutzername | Passwort |
|--------|--------------|----------|
| **Web UI** | admin | secubox |
| **SSH** | root | secubox |
| **Zugang** | https://localhost:9443 | SSH Port 2222 |

---

## 🟢 ROOT — Systemanforderungen

| Board | SoC | Profil | Anwendungsfall |
|-------|-----|--------|----------------|
| MOCHAbin | Armada 7040 | Full | Enterprise Gateway |
| ESPRESSObin v7 | Armada 3720 | Lite | Home/SMB Router |
| ESPRESSObin Ultra | Armada 3720 | Lite+ | Home mit Wi-Fi |
| Raspberry Pi 400 | BCM2711 | Full | Maker-Projekte |
| VM x86_64 | Beliebig | Full | Test/Entwicklung |
| QEMU ARM64 | Emuliert | Full | ARM-Tests auf x86 |

---

## 🟣 MIND — Funktionsübersicht

| Stack | Beschreibung | Module |
|-------|--------------|--------|
| 🟠 **AUTH** | Authentifizierung, ZeroTrust, MFA | auth, portal, users, nac |
| 🟡 **WALL** | Firewall, CrowdSec, WAF, IDS/IPS | crowdsec, waf, threats, ipblock |
| 🔴 **BOOT** | Deployment, Bereitstellung | cloner, vault, vm, rezapp |
| 🟣 **MIND** | KI, Verhaltensanalyse, DPI | dpi, netifyd, ai-insights, soc |
| 🟢 **ROOT** | System, CLI, Härtung | core, hub, system, console |
| 🔵 **MESH** | Netzwerk, WireGuard, QoS | wireguard, haproxy, netmodes, turn |

**Gesamt: 125 Pakete**

Siehe [[Module|MODULES-DE]] für vollständige Moduldokumentation.

---

## 🔵 MESH — Dokumentation

### Erste Schritte
- [[VirtualBox Schnellstart|Live-USB-VirtualBox]] ⭐
- [[Live-USB]] — Bootfähiges USB-Handbuch
- [[ARM-Installation]] — ARM-Boards & U-Boot ⚡
- [[QEMU-ARM64]] — ARM-Emulation auf x86 🖥️

### Konfiguration
- [[Configuration]] — Systemkonfiguration
- [[Troubleshooting]] — Häufige Probleme

### Referenz
- [[Module|MODULES-DE]] — Alle 125 Module
- [[API-Reference]] — REST API (2000+ Endpunkte)

---

## 🟡 WALL — Sicherheitsfunktionen

- **CrowdSec** — Community-getriebenes IDS/IPS
- **WAF** — 300+ ModSecurity-Regeln
- **nftables** — Standard-DROP-Richtlinie
- **AI-Insights** — ML-Bedrohungserkennung
- **IPBlock** — Automatisierte Blocklist-Verwaltung
- **MAC-Guard** — MAC-Adresskontrolle

---

## Links

- [GitHub Repository](https://github.com/CyberMind-FR/secubox-deb)
- [Releases](https://github.com/CyberMind-FR/secubox-deb/releases)
- [Issues](https://github.com/CyberMind-FR/secubox-deb/issues)
- [CyberMind](https://cybermind.fr)

---

## Lizenz

**CMSD-1.0** (CyberMind Source-Disclosed License) — Quellcode einsehbar, Rechte vorbehalten.

| ✅ Erlaubt | ❌ Verboten |
|-----------|------------|
| Code lesen und studieren | Produktionseinsatz |
| Kompilieren für Tests/Audits | Weiterverteilung oder Ableitungen |
| Sicherheitsforschung veröffentlichen | Integration in andere Produkte |
| Akademische/journalistische Zitate | Als SaaS anbieten |

**ANSSI CSPN Ready**: Audits durch akkreditierte Labore (CESTI, CC-Äquivalente) ohne vorherige Genehmigung erlaubt.

Siehe [LICENCE-CMSD-1.0.md](https://github.com/CyberMind-FR/secubox-deb/blob/master/LICENCE-CMSD-1.0.md) (FR, maßgeblich) oder [LICENSE-CMSD-1.0.en.md](https://github.com/CyberMind-FR/secubox-deb/blob/master/LICENSE-CMSD-1.0.en.md) (EN).

---

*© 2024-2026 [CyberMind](https://cybermind.fr) · Gérald Kerma · Notre-Dame-du-Cruet, Savoie*
