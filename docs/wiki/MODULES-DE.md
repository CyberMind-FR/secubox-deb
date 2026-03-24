# SecuBox Module

*Vollständige Moduldokumentation*

**Module insgesamt:** 47

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Übersicht

| Module | Kategorie | Beschreibung |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Zentrales Dashboard |
| 🛡️ **Security Operations Center** | Dashboard | SOC mit Weltuhr, Bedrohungskarte |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT zu Debian Migration |
| 🛡️ **CrowdSec** | Security | Kollaborative Sicherheits-Engine |
| 🔥 **Web Application Firewall** | Security | WAF mit 300+ Regeln |
| 🔥 **Vortex Firewall** | Security | nftables Bedrohungsdurchsetzung |
| 🔒 **System Hardening** | Security | Kernel- und Systemhärtung |
| 🔍 **MITM Proxy** | Security | Verkehrsinspektion und WAF-Proxy |
| 🔐 **Auth Guardian** | Security | Authentifizierungsverwaltung |
| 🛡️ **Network Access Control** | Security | Client-Guardian und NAC |
| 🌐 **Network Modes** | Network | Netzwerktopologie-Konfiguration |
| 📊 **QoS Manager** | Network | QoS mit HTB/VLAN |
| 📈 **Traffic Shaping** | Network | TC/CAKE Verkehrsformung |
| ⚡ **HAProxy** | Network | Load-Balancer-Dashboard |
| 🚀 **CDN Cache** | Network | Content-Delivery-Cache |
| 🏗️ **Virtual Hosts** | Network | Nginx Virtual Host Verwaltung |
| 🌍 **DNS Server** | DNS | BIND DNS-Zonenverwaltung |
| 🛡️ **Vortex DNS** | DNS | DNS-Firewall mit RPZ |
| 📡 **Mesh DNS** | DNS | Mesh-Netzwerk-Domänenauflösung |
| 🔗 **WireGuard VPN** | VPN | Moderne VPN-Verwaltung |
| 🕸️ **Mesh Network** | VPN | Mesh-Netzwerk (Yggdrasil) |
| 🔗 **P2P Network** | VPN | Peer-to-Peer-Netzwerk |
| 🧅 **Tor Network** | Privacy | Tor-Anonymität und versteckte Dienste |
| 🌐 **Exposure Settings** | Privacy | Einheitliche Exposition (Tor, SSL, DNS, Mesh) |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP Hamiltonian-Verwaltung |
| 📊 **Netdata** | Monitoring | Echtzeit-Systemüberwachung |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI mit netifyd |
| 📱 **Device Intelligence** | Monitoring | Asset-Erkennung und Fingerprinting |
| 👁️ **Watchdog** | Monitoring | Service- und Container-Überwachung |
| 🎬 **Media Flow** | Monitoring | Medienverkehrsanalyse |
| 🔐 **Login Portal** | Access | Authentifizierungsportal mit JWT |
| 👥 **User Management** | Access | Einheitliche Identitätsverwaltung |
| 📦 **Services Portal** | Services | C3Box-Dienstportal |
| 🦊 **Gitea** | Services | Git-Server (LXC) |
| ☁️ **Nextcloud** | Services | Dateisynchronisierung (LXC) |
| 📧 **Mail Server** | Email | Postfix/Dovecot-Mailserver |
| 💌 **Webmail** | Email | Roundcube/SOGo-Webmail |
| 📰 **Publishing Platform** | Publishing | Einheitliches Veröffentlichungs-Dashboard |
| 💧 **Droplet** | Publishing | Datei-Upload und Veröffentlichung |
| 📝 **Metablogizer** | Publishing | Statischer Site-Publisher mit Tor |
| 🎨 **Streamlit** | Apps | Streamlit-App-Plattform |
| ⚡ **StreamForge** | Apps | Streamlit-App-Entwicklung |
| 📦 **APT Repository** | Apps | APT-Repository-Verwaltung |
| ⚙️ **System Hub** | System | Systemkonfiguration und -verwaltung |
| 💾 **Backup Manager** | System | System- und LXC-Backup |

---

## Module

### 🏠 SecuBox Hub

**Kategorie:** Dashboard

Zentrales Dashboard

**Features:**
- Systemübersicht
- Service-Überwachung
- Schnellaktionen
- Metriken

![SecuBox Hub](screenshots/vm/hub.png)

---

### 🛡️ Security Operations Center

**Kategorie:** Dashboard

SOC mit Weltuhr, Bedrohungskarte

**Features:**
- Weltuhr
- Bedrohungskarte
- Ticketsystem
- P2P-Intel
- Warnungen

![Security Operations Center](screenshots/vm/soc.png)

---

### 📋 Migration Roadmap

**Kategorie:** Dashboard

OpenWRT zu Debian Migration

**Features:**
- Fortschrittsverfolgung
- Modulstatus
- Kategorieansicht

![Migration Roadmap](screenshots/vm/roadmap.png)

---

### 🛡️ CrowdSec

**Kategorie:** Security

Kollaborative Sicherheits-Engine

**Features:**
- Entscheidungsverwaltung
- Warnungen
- Bouncers
- Sammlungen

![CrowdSec](screenshots/vm/crowdsec.png)

---

### 🔥 Web Application Firewall

**Kategorie:** Security

WAF mit 300+ Regeln

**Features:**
- OWASP-Regeln
- Eigene Regeln
- CrowdSec-Integration

![Web Application Firewall](screenshots/vm/waf.png)

---

### 🔥 Vortex Firewall

**Kategorie:** Security

nftables Bedrohungsdurchsetzung

**Features:**
- IP-Blocklisten
- nftables-Sets
- Bedrohungsfeeds

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

---

### 🔒 System Hardening

**Kategorie:** Security

Kernel- und Systemhärtung

**Features:**
- Sysctl-Härtung
- Modul-Blacklist
- Sicherheitsbewertung

![System Hardening](screenshots/vm/hardening.png)

---

### 🔍 MITM Proxy

**Kategorie:** Security

Verkehrsinspektion und WAF-Proxy

**Features:**
- Verkehrsinspektion
- Anforderungsprotokollierung
- Auto-Ban

![MITM Proxy](screenshots/vm/mitmproxy.png)

---

### 🔐 Auth Guardian

**Kategorie:** Security

Authentifizierungsverwaltung

**Features:**
- OAuth2
- LDAP
- 2FA
- Sitzungen

![Auth Guardian](screenshots/vm/auth.png)

---

### 🛡️ Network Access Control

**Kategorie:** Security

Client-Guardian und NAC

**Features:**
- Gerätesteuerung
- MAC-Filterung
- Quarantäne

![Network Access Control](screenshots/vm/nac.png)

---

### 🌐 Network Modes

**Kategorie:** Network

Netzwerktopologie-Konfiguration

**Features:**
- Router-Modus
- Bridge-Modus
- AP-Modus
- VLAN

![Network Modes](screenshots/vm/netmodes.png)

---

### 📊 QoS Manager

**Kategorie:** Network

QoS mit HTB/VLAN

**Features:**
- Bandbreitenkontrolle
- VLAN-Richtlinien
- 802.1p PCP

![QoS Manager](screenshots/vm/qos.png)

---

### 📈 Traffic Shaping

**Kategorie:** Network

TC/CAKE Verkehrsformung

**Features:**
- Pro-Schnittstelle QoS
- CAKE-Algorithmus
- Statistiken

![Traffic Shaping](screenshots/vm/traffic.png)

---

### ⚡ HAProxy

**Kategorie:** Network

Load-Balancer-Dashboard

**Features:**
- Backend-Verwaltung
- Statistiken
- ACLs
- SSL-Terminierung

![HAProxy](screenshots/vm/haproxy.png)

---

### 🚀 CDN Cache

**Kategorie:** Network

Content-Delivery-Cache

**Features:**
- Cache-Verwaltung
- Bereinigung
- Statistiken

![CDN Cache](screenshots/vm/cdn.png)

---

### 🏗️ Virtual Hosts

**Kategorie:** Network

Nginx Virtual Host Verwaltung

**Features:**
- Site-Verwaltung
- SSL-Zertifikate
- Reverse-Proxy

![Virtual Hosts](screenshots/vm/vhost.png)

---

### 🌍 DNS Server

**Kategorie:** DNS

BIND DNS-Zonenverwaltung

**Features:**
- Zonenverwaltung
- Einträge
- DNSSEC

![DNS Server](screenshots/vm/dns.png)

---

### 🛡️ Vortex DNS

**Kategorie:** DNS

DNS-Firewall mit RPZ

**Features:**
- Blocklisten
- RPZ
- Bedrohungsfeeds

![Vortex DNS](screenshots/vm/vortex-dns.png)

---

### 📡 Mesh DNS

**Kategorie:** DNS

Mesh-Netzwerk-Domänenauflösung

**Features:**
- mDNS/Avahi
- Lokales DNS
- Diensterkennung

![Mesh DNS](screenshots/vm/meshname.png)

---

### 🔗 WireGuard VPN

**Kategorie:** VPN

Moderne VPN-Verwaltung

**Features:**
- Peer-Verwaltung
- QR-Codes
- Verkehrsstatistiken

![WireGuard VPN](screenshots/vm/wireguard.png)

---

### 🕸️ Mesh Network

**Kategorie:** VPN

Mesh-Netzwerk (Yggdrasil)

**Features:**
- Peer-Erkennung
- Routing
- Verschlüsselung

![Mesh Network](screenshots/vm/mesh.png)

---

### 🔗 P2P Network

**Kategorie:** VPN

Peer-to-Peer-Netzwerk

**Features:**
- Direktverbindungen
- NAT-Traversal
- Verschlüsselung

![P2P Network](screenshots/vm/p2p.png)

---

### 🧅 Tor Network

**Kategorie:** Privacy

Tor-Anonymität und versteckte Dienste

**Features:**
- Schaltkreise
- Versteckte Dienste
- Bridges

![Tor Network](screenshots/vm/tor.png)

---

### 🌐 Exposure Settings

**Kategorie:** Privacy

Einheitliche Exposition (Tor, SSL, DNS, Mesh)

**Features:**
- Tor-Exposition
- SSL-Zertifikate
- DNS-Einträge
- Mesh-Zugang

![Exposure Settings](screenshots/vm/exposure.png)

---

### 🔐 Zero-Knowledge Proofs

**Kategorie:** Privacy

ZKP Hamiltonian-Verwaltung

**Features:**
- Beweisgenerierung
- Verifizierung
- Schlüsselverwaltung

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

---

### 📊 Netdata

**Kategorie:** Monitoring

Echtzeit-Systemüberwachung

**Features:**
- Metriken
- Warnungen
- Diagramme
- Plugins

![Netdata](screenshots/vm/netdata.png)

---

### 🔬 Deep Packet Inspection

**Kategorie:** Monitoring

DPI mit netifyd

**Features:**
- Protokollerkennung
- App-Identifizierung
- Flussanalyse

![Deep Packet Inspection](screenshots/vm/dpi.png)

---

### 📱 Device Intelligence

**Kategorie:** Monitoring

Asset-Erkennung und Fingerprinting

**Features:**
- ARP-Scanning
- MAC-Vendor-Suche
- OS-Erkennung

![Device Intelligence](screenshots/vm/device-intel.png)

---

### 👁️ Watchdog

**Kategorie:** Monitoring

Service- und Container-Überwachung

**Features:**
- Gesundheitsprüfungen
- Auto-Neustart
- Warnungen

![Watchdog](screenshots/vm/watchdog.png)

---

### 🎬 Media Flow

**Kategorie:** Monitoring

Medienverkehrsanalyse

**Features:**
- Stream-Erkennung
- Bandbreitennutzung
- Protokollanalyse

![Media Flow](screenshots/vm/mediaflow.png)

---

### 🔐 Login Portal

**Kategorie:** Access

Authentifizierungsportal mit JWT

**Features:**
- JWT-Auth
- Sitzungen
- Passwortwiederherstellung

![Login Portal](screenshots/vm/portal.png)

---

### 👥 User Management

**Kategorie:** Access

Einheitliche Identitätsverwaltung

**Features:**
- Benutzer-CRUD
- Gruppen
- Service-Bereitstellung

![User Management](screenshots/vm/users.png)

---

### 📦 Services Portal

**Kategorie:** Services

C3Box-Dienstportal

**Features:**
- Service-Links
- Statusübersicht
- Schnellzugriff

![Services Portal](screenshots/vm/c3box.png)

---

### 🦊 Gitea

**Kategorie:** Services

Git-Server (LXC)

**Features:**
- Repositories
- Benutzer
- SSH/HTTP
- LFS

![Gitea](screenshots/vm/gitea.png)

---

### ☁️ Nextcloud

**Kategorie:** Services

Dateisynchronisierung (LXC)

**Features:**
- Dateisync
- WebDAV
- CalDAV
- CardDAV

![Nextcloud](screenshots/vm/nextcloud.png)

---

### 📧 Mail Server

**Kategorie:** Email

Postfix/Dovecot-Mailserver

**Features:**
- Domänen
- Postfächer
- DKIM
- SpamAssassin
- ClamAV

![Mail Server](screenshots/vm/mail.png)

---

### 💌 Webmail

**Kategorie:** Email

Roundcube/SOGo-Webmail

**Features:**
- Web-Oberfläche
- Adressbuch
- Kalender

![Webmail](screenshots/vm/webmail.png)

---

### 📰 Publishing Platform

**Kategorie:** Publishing

Einheitliches Veröffentlichungs-Dashboard

**Features:**
- Multi-Plattform
- Planung
- Analysen

![Publishing Platform](screenshots/vm/publish.png)

---

### 💧 Droplet

**Kategorie:** Publishing

Datei-Upload und Veröffentlichung

**Features:**
- Datei-Upload
- Freigabelinks
- Ablauf

![Droplet](screenshots/vm/droplet.png)

---

### 📝 Metablogizer

**Kategorie:** Publishing

Statischer Site-Publisher mit Tor

**Features:**
- Statische Sites
- Tor-Veröffentlichung
- Vorlagen

![Metablogizer](screenshots/vm/metablogizer.png)

---

### 🎨 Streamlit

**Kategorie:** Apps

Streamlit-App-Plattform

**Features:**
- App-Hosting
- Bereitstellung
- Verwaltung

![Streamlit](screenshots/vm/streamlit.png)

---

### ⚡ StreamForge

**Kategorie:** Apps

Streamlit-App-Entwicklung

**Features:**
- Vorlagen
- Code-Editor
- Vorschau

![StreamForge](screenshots/vm/streamforge.png)

---

### 📦 APT Repository

**Kategorie:** Apps

APT-Repository-Verwaltung

**Features:**
- Paketverwaltung
- GPG-Signierung
- Multi-Distro

![APT Repository](screenshots/vm/repo.png)

---

### ⚙️ System Hub

**Kategorie:** System

Systemkonfiguration und -verwaltung

**Features:**
- Einstellungen
- Protokolle
- Dienste
- Updates

![System Hub](screenshots/vm/system.png)

---

### 💾 Backup Manager

**Kategorie:** System

System- und LXC-Backup

**Features:**
- Config-Backup
- LXC-Snapshots
- Wiederherstellung

![Backup Manager](screenshots/vm/backup.png)

---

