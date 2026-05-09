# SecuBox Module

*Vollständige Moduldokumentation*

**Module insgesamt:** 105

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Übersicht

| Module | Kategorie | Beschreibung |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Zentrales Dashboard und Kontrollzentrum |
| 🛡️ **Security Operations Center** | Dashboard | SOC mit Weltuhr, Bedrohungskarte, Tickets |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT zu Debian Migration-Tracking |
| 📈 **System Metrics** | Dashboard | Echtzeit-Systemmetriken-Dashboard |
| ⚙️ **Admin Panel** | Dashboard | Systemverwaltungspanel |
| 🛡️ **CrowdSec** | Security | Kollaborative Sicherheits-Engine mit Verhaltensanalyse |
| 🔥 **Web Application Firewall** | Security | WAF mit 300+ OWASP-Sicherheitsregeln |
| 🔥 **Vortex Firewall** | Security | nftables-basierte Bedrohungsdurchsetzungs-Firewall |
| 🔒 **System Hardening** | Security | Kernel- und Systemhärtung für ANSSI CSPN-Konformität |
| 🔍 **MITM Proxy** | Security | Verkehrsinspektion und WAF-Proxy mit Auto-Ban |
| 🔐 **Auth Guardian** | Security | Einheitliche Authentifizierungsverwaltung |
| 🛡️ **Network Access Control** | Security | Client-Guardian und NAC mit Quarantäne |
| 🚫 **IP Block Manager** | Security | IP- und Netzwerksperrverwaltung |
| 🔐 **MAC Guard** | Security | MAC-Adress-Zugangskontrolle |
| 📡 **Traffic Interceptor** | Security | Netzwerkverkehrs-Interception und -Analyse |
| 🍪 **Cookie Manager** | Security | Cookie- und Sitzungssicherheitsverwaltung |
| ⚠️ **Threat Dashboard** | Security | Einheitliche Bedrohungsvisualisierung |
| 🔬 **Threat Analyst** | Security | KI-gestützte Bedrohungsanalyse |
| 🔴 **CVE Triage** | Security | CVE-Schwachstellenverfolgung und -Triage |
| 🛡️ **Wazuh SIEM** | Security | Wazuh SIEM-Integration |
| 🔒 **OSSEC HIDS** | Security | OSSEC-hostbasierte Einbruchserkennung |
| 🦞 **OpenClaw Scanner** | Security | Netzwerk-Schwachstellen-Scanner |
| 🔌 **IoT Guard** | Security | IoT-Gerätesicherheitsüberwachung |
| 🌐 **Network Modes** | Network | Netzwerktopologie-Konfiguration |
| 📊 **QoS Manager** | Network | QoS mit HTB/VLAN |
| 📈 **Traffic Shaping** | Network | TC/CAKE Verkehrsformung |
| ⚡ **HAProxy** | Network | Load Balancer mit TLS 1.3 |
| 🚀 **CDN Cache** | Network | Content-Delivery-Cache |
| 🏗️ **Virtual Hosts** | Network | Nginx Virtual Host Verwaltung |
| 🛤️ **Routing Manager** | Network | Statisches und richtlinienbasiertes Routing |
| 🔧 **Network Tweaks** | Network | Netzwerk-Kernelparameter-Tuning |
| 🔍 **Network Diagnostics** | Network | Netzwerk-Diagnosetools |
| 📉 **Network Anomaly** | Network | Netzwerk-Anomalieerkennung |
| 📶 **Modem Manager** | Network | 3G/4G/5G-Modemverwaltung |
| 🌍 **DNS Server** | DNS | BIND DNS-Zonenverwaltung |
| 🛡️ **Vortex DNS** | DNS | DNS-Firewall mit RPZ-Blocklisten |
| 📡 **Mesh DNS** | DNS | Mesh-Netzwerk-Domänenauflösung |
| 🛡️ **DNS Guard** | DNS | DNS-basierter Bedrohungsschutz |
| 🌐 **DNS Provider** | DNS | Externe DNS-Anbieter-Integration |
| 🚫 **AdGuard** | DNS | AdGuard Home DNS-Blockierung |
| 🔗 **WireGuard VPN** | VPN | Modernes VPN mit Kernel-Integration |
| 🕸️ **Mesh Network** | VPN | Mesh-Netzwerk mit Yggdrasil |
| 🔗 **P2P Network** | VPN | Peer-to-Peer-Netzwerk |
| 🔗 **MasterLink** | VPN | SecuBox Mesh-Föderation |
| 🧅 **Tor Network** | Privacy | Tor-Anonymität und versteckte Dienste |
| 🌐 **Exposure Settings** | Privacy | Einheitliche Expositionsverwaltung |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP Hamiltonian-Authentifizierung |
| 💬 **SimpleX Chat** | Privacy | Datenschutzorientiertes Messaging |
| 🔐 **Secret Vault** | Privacy | Geheimnis- und Anmeldedatenverwaltung |
| 📊 **Netdata** | Monitoring | Echtzeit-Systemüberwachung |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI mit netifyd/nDPId |
| 🔬 **Netifyd DPI** | Monitoring | Netifyd Deep Packet Inspection |
| 🔬 **nDPId** | Monitoring | nDPI-Daemon für Verkehrsanalyse |
| 📱 **Device Intelligence** | Monitoring | Asset-Erkennung und Fingerprinting |
| 👁️ **Watchdog** | Monitoring | Service- und Container-Überwachung |
| 🎬 **Media Flow** | Monitoring | Medienverkehrsanalyse |
| 👀 **Glances** | Monitoring | System-Überwachungs-Dashboard |
| 🔐 **Login Portal** | Access | Authentifizierungsportal mit JWT |
| 👥 **User Management** | Access | Einheitliche Identitätsverwaltung |
| 🪪 **Identity Provider** | Access | SAML/OIDC-Identitätsanbieter |
| 📦 **Services Portal** | Services | C3Box-Dienstportal |
| 🦊 **Gitea** | Services | Git-Server (LXC) |
| ☁️ **Nextcloud** | Services | Dateisynchronisierung (LXC) |
| 🦙 **Ollama** | AI | Lokaler LLM-Server |
| 🤖 **LocalAI** | AI | OpenAI-kompatible lokale API |
| 🚪 **AI Gateway** | AI | AI-Modell-API-Gateway |
| 💡 **AI Insights** | AI | KI-gestützte Sicherheitseinblicke |
| 🧠 **LocalRecall** | AI | Lokales RAG-Gedächtnissystem |
| 🔌 **MCP Server** | AI | Model Context Protocol-Server |
| 📧 **Mail Server** | Email | Postfix/Dovecot-Mailserver |
| 💌 **Webmail** | Email | Roundcube/SOGo-Webmail |
| 📤 **SMTP Relay** | Email | SMTP-Relay und Smarthost |
| 💬 **Jabber/XMPP** | Email | XMPP-Messaging-Server |
| 🎬 **Jellyfin** | Media | Medienserver |
| 🎵 **Lyrion Music** | Media | Musik-Streaming-Server |
| 📻 **Web Radio** | Media | Internet-Radio-Streaming |
| 📸 **PhotoPrism** | Media | KI-gestützte Fotoverwaltung |
| 📺 **PeerTube** | Media | Föderierte Videoplattform |
| 🌊 **Torrent** | Media | BitTorrent-Client |
| 📰 **Newsbin** | Media | Usenet/NNTP-Client |
| 📰 **Publishing Platform** | Publishing | Einheitliches Veröffentlichungs-Dashboard |
| 💧 **Droplet** | Publishing | Datei-Upload und Veröffentlichung |
| 📝 **Metablogizer** | Publishing | Statischer Site-Publisher mit Tor |
| ✏️ **Hexo Blog** | Publishing | Statischer Blog-Generator |
| 🐘 **GoToSocial** | Publishing | ActivityPub-Social-Server |
| 📡 **CyberFeed** | Publishing | RSS/Atom-Feed-Aggregator |
| 🎨 **Streamlit** | Apps | Streamlit-App-Plattform |
| ⚡ **StreamForge** | Apps | Streamlit-App-Entwicklung |
| 📦 **APT Repository** | Apps | APT-Repository-Verwaltung |
| 🏠 **Domoticz** | IoT | Hausautomation |
| 🏡 **Home Assistant** | IoT | Hausautomations-Hub |
| 📡 **Zigbee Gateway** | IoT | Zigbee2MQTT-Gateway |
| 📡 **MQTT Broker** | IoT | Mosquitto MQTT-Broker |
| 💬 **Matrix Server** | Communication | Matrix/Synapse-Chat-Server |
| 📹 **Jitsi Meet** | Communication | Videokonferenzen |
| 📞 **VoIP Server** | Communication | Asterisk/FreePBX VoIP |
| 🔄 **TURN Server** | Communication | TURN/STUN-Relay-Server |
| ⚙️ **System Hub** | System | Systemkonfiguration und -verwaltung |
| 💾 **Backup Manager** | System | System- und LXC-Backup |
| 📋 **Config Advisor** | System | Konfigurationsempfehlungen |
| 📊 **Reporter** | System | Systemberichterstattung und -analyse |
| 🪞 **Mirror Manager** | System | APT-Mirror-Verwaltung |
| 📀 **System Cloner** | System | System-Image-Klonen |
| 👁️ **Eye Remote** | System | Remote-Verwaltungsoberfläche |
| 🖥️ **RTTY Console** | System | Remote-Terminal-Zugriff |

---

## Module

### AI

#### 🦙 Ollama

Lokaler LLM-Server

**Funktionen:** Modellverwaltung, API, Chat, GPU-Unterstützung

#### 🤖 LocalAI

OpenAI-kompatible lokale API

**Funktionen:** OpenAI-API, Mehrere Modelle, Embeddings, Bildgenerierung

#### 🚪 AI Gateway

AI-Modell-API-Gateway

**Funktionen:** Ratenbegrenzung, Lastverteilung, Caching, Protokollierung

#### 💡 AI Insights

KI-gestützte Sicherheitseinblicke

**Funktionen:** Anomalieerkennung, Empfehlungen, Vorhersagen, Berichte

#### 🧠 LocalRecall

Lokales RAG-Gedächtnissystem

**Funktionen:** Vektorspeicher, Semantische Suche, Dokumentenindizierung, API

#### 🔌 MCP Server

Model Context Protocol-Server

**Funktionen:** Tool-Integration, Kontextverwaltung, Multi-Modell, API

---

### Access

#### 🔐 Login Portal

Authentifizierungsportal mit JWT

**Funktionen:** JWT-Auth, Sitzungen, Passwortwiederherstellung, Captive Portal

#### 👥 User Management

Einheitliche Identitätsverwaltung

**Funktionen:** Benutzer-CRUD, Gruppen, Service-Bereitstellung, RBAC

#### 🪪 Identity Provider

SAML/OIDC-Identitätsanbieter

**Funktionen:** SAML 2.0, OpenID Connect, Föderation, SSO

---

### Apps

#### 🎨 Streamlit

Streamlit-App-Plattform

**Funktionen:** App-Hosting, Bereitstellung, Verwaltung, Logs

#### ⚡ StreamForge

Streamlit-App-Entwicklung

**Funktionen:** Vorlagen, Code-Editor, Vorschau, Deploy

#### 📦 APT Repository

APT-Repository-Verwaltung

**Funktionen:** Paketverwaltung, GPG-Signierung, Multi-Distro, Uploads

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse-Chat-Server

**Funktionen:** E2E-Verschlüsselung, Föderation, Bridges, Anrufe

#### 📹 Jitsi Meet

Videokonferenzen

**Funktionen:** Videoanrufe, Bildschirmfreigabe, Aufnahme, Lobby

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**Funktionen:** Extensions, Trunks, IVR, Voicemail

#### 🔄 TURN Server

TURN/STUN-Relay-Server

**Funktionen:** NAT-Traversal, WebRTC, TLS, Statistiken

---

### DNS

#### 🌍 DNS Server

BIND DNS-Zonenverwaltung

**Funktionen:** Zonenverwaltung, Einträge, DNSSEC, Reverse-DNS

#### 🛡️ Vortex DNS

DNS-Firewall mit RPZ-Blocklisten

**Funktionen:** Blocklisten, RPZ, Bedrohungsfeeds, DoH/DoT

#### 📡 Mesh DNS

Mesh-Netzwerk-Domänenauflösung

**Funktionen:** mDNS/Avahi, Lokales DNS, Diensterkennung, Mesh-Integration

#### 🛡️ DNS Guard

DNS-basierter Bedrohungsschutz

**Funktionen:** Malware-Blockierung, Phishing-Schutz, Analysen, Whitelist

#### 🌐 DNS Provider

Externe DNS-Anbieter-Integration

**Funktionen:** Cloudflare, Route53, DigitalOcean, Dynamisches DNS

#### 🚫 AdGuard

AdGuard Home DNS-Blockierung

**Funktionen:** Werbungsblockierung, Tracking-Schutz, Jugendschutz, Statistiken

---

### Dashboard

#### 🏠 SecuBox Hub

Zentrales Dashboard und Kontrollzentrum

**Funktionen:** Systemübersicht, Service-Überwachung, Schnellaktionen, Metriken

#### 🛡️ Security Operations Center

SOC mit Weltuhr, Bedrohungskarte, Tickets

**Funktionen:** Weltuhr, Bedrohungskarte, Ticketsystem, P2P-Intel, Warnungen

#### 📋 Migration Roadmap

OpenWRT zu Debian Migration-Tracking

**Funktionen:** Fortschrittsverfolgung, Modulstatus, Kategorieansicht

#### 📈 System Metrics

Echtzeit-Systemmetriken-Dashboard

**Funktionen:** CPU/Speicher, Netzwerkstatistiken, Disk-I/O, Verlaufsdaten

#### ⚙️ Admin Panel

Systemverwaltungspanel

**Funktionen:** Benutzerverwaltung, Systemkonfiguration, Logs, Diagnose

---

### Email

#### 📧 Mail Server

Postfix/Dovecot-Mailserver

**Funktionen:** Domänen, Postfächer, DKIM, SpamAssassin, ClamAV

#### 💌 Webmail

Roundcube/SOGo-Webmail

**Funktionen:** Web-Oberfläche, Adressbuch, Kalender, Mobil

#### 📤 SMTP Relay

SMTP-Relay und Smarthost

**Funktionen:** Relay, Authentifizierung, Ratenbegrenzung, Protokollierung

#### 💬 Jabber/XMPP

XMPP-Messaging-Server

**Funktionen:** Chat, Gruppen, Dateiübertragung, Föderation

---

### IoT

#### 🏠 Domoticz

Hausautomation

**Funktionen:** Geräte, Szenen, Skripte, Verlauf

#### 🏡 Home Assistant

Hausautomations-Hub

**Funktionen:** Integrationen, Automatisierungen, Dashboard, Sprache

#### 📡 Zigbee Gateway

Zigbee2MQTT-Gateway

**Funktionen:** Gerätekopplung, MQTT, Gruppen, OTA-Updates

#### 📡 MQTT Broker

Mosquitto MQTT-Broker

**Funktionen:** Topics, ACL, TLS, WebSocket

---

### Media

#### 🎬 Jellyfin

Medienserver

**Funktionen:** Video-Streaming, Live-TV, Transcoding, Mobile Apps

#### 🎵 Lyrion Music

Musik-Streaming-Server

**Funktionen:** Musikbibliothek, Playlists, Radio, Multi-Room

#### 📻 Web Radio

Internet-Radio-Streaming

**Funktionen:** Radiosender, Aufnahme, Zeitplan, Favoriten

#### 📸 PhotoPrism

KI-gestützte Fotoverwaltung

**Funktionen:** Gesichtserkennung, Auto-Tagging, Suche, Alben

#### 📺 PeerTube

Föderierte Videoplattform

**Funktionen:** Video-Hosting, Föderation, Live-Streaming, Kommentare

#### 🌊 Torrent

BitTorrent-Client

**Funktionen:** Downloads, RSS, Fernsteuerung, Bandbreitenlimits

#### 📰 Newsbin

Usenet/NNTP-Client

**Funktionen:** NZB-Downloads, Auto-Verarbeitung, Suche, Kategorien

---

### Monitoring

#### 📊 Netdata

Echtzeit-Systemüberwachung

**Funktionen:** Metriken, Warnungen, Diagramme, Plugins

#### 🔬 Deep Packet Inspection

DPI mit netifyd/nDPId

**Funktionen:** Protokollerkennung, App-Identifizierung, Flussanalyse, Statistiken

#### 🔬 Netifyd DPI

Netifyd Deep Packet Inspection

**Funktionen:** Anwendungserkennung, Protokollanalyse, Flussstatistiken, API

#### 🔬 nDPId

nDPI-Daemon für Verkehrsanalyse

**Funktionen:** Protokollerkennung, Flussverfolgung, JSON-API, Echtzeit

#### 📱 Device Intelligence

Asset-Erkennung und Fingerprinting

**Funktionen:** ARP-Scanning, MAC-Vendor-Suche, OS-Erkennung, Dienste

#### 👁️ Watchdog

Service- und Container-Überwachung

**Funktionen:** Gesundheitsprüfungen, Auto-Neustart, Warnungen, Logs

#### 🎬 Media Flow

Medienverkehrsanalyse

**Funktionen:** Stream-Erkennung, Bandbreitennutzung, Protokollanalyse, QoE

#### 👀 Glances

System-Überwachungs-Dashboard

**Funktionen:** CPU/Speicher, Disk/Netzwerk, Docker, Web-UI

---

### Network

#### 🌐 Network Modes

Netzwerktopologie-Konfiguration

**Funktionen:** Router-Modus, Bridge-Modus, AP-Modus, VLAN

#### 📊 QoS Manager

QoS mit HTB/VLAN

**Funktionen:** Bandbreitenkontrolle, VLAN-Richtlinien, 802.1p PCP, Pro-Benutzer-Limits

#### 📈 Traffic Shaping

TC/CAKE Verkehrsformung

**Funktionen:** Pro-Schnittstelle QoS, CAKE-Algorithmus, Statistiken, Echtzeit-Graphen

#### ⚡ HAProxy

Load Balancer mit TLS 1.3

**Funktionen:** Backend-Verwaltung, Statistiken, ACLs, SSL-Terminierung, Health-Checks

#### 🚀 CDN Cache

Content-Delivery-Cache

**Funktionen:** Cache-Verwaltung, Bereinigung, Statistiken, Edge-Regeln

#### 🏗️ Virtual Hosts

Nginx Virtual Host Verwaltung

**Funktionen:** Site-Verwaltung, SSL-Zertifikate, Reverse-Proxy, Let's Encrypt

#### 🛤️ Routing Manager

Statisches und richtlinienbasiertes Routing

**Funktionen:** Statische Routen, Policy-Routing, Multi-WAN, Failover

#### 🔧 Network Tweaks

Netzwerk-Kernelparameter-Tuning

**Funktionen:** TCP-Tuning, Puffergrößen, Überlastungskontrolle, Profile

#### 🔍 Network Diagnostics

Netzwerk-Diagnosetools

**Funktionen:** Ping/Traceroute, DNS-Suche, Port-Scan, Geschwindigkeitstest

#### 📉 Network Anomaly

Netzwerk-Anomalieerkennung

**Funktionen:** Verkehrs-Baselines, Anomalie-Warnungen, ML-Erkennung, Visualisierung

#### 📶 Modem Manager

3G/4G/5G-Modemverwaltung

**Funktionen:** Verbindungsstatus, Signalstärke, SMS, Failover

---

### Privacy

#### 🧅 Tor Network

Tor-Anonymität und versteckte Dienste

**Funktionen:** Schaltkreise, Versteckte Dienste, Bridges, Transparenter Proxy

#### 🌐 Exposure Settings

Einheitliche Expositionsverwaltung

**Funktionen:** Tor-Exposition, SSL-Zertifikate, DNS-Einträge, Mesh-Zugang

#### 🔐 Zero-Knowledge Proofs

ZKP Hamiltonian-Authentifizierung

**Funktionen:** Beweisgenerierung, Verifizierung, Schlüsselverwaltung, MirrorNet

#### 💬 SimpleX Chat

Datenschutzorientiertes Messaging

**Funktionen:** E2E-Verschlüsselung, Keine Benutzer-IDs, Selbst gehostet, Gruppen

#### 🔐 Secret Vault

Geheimnis- und Anmeldedatenverwaltung

**Funktionen:** Verschlüsselter Speicher, Zugriffskontrolle, Rotation, Audit

---

### Publishing

#### 📰 Publishing Platform

Einheitliches Veröffentlichungs-Dashboard

**Funktionen:** Multi-Plattform, Planung, Analysen, Vorlagen

#### 💧 Droplet

Datei-Upload und Veröffentlichung

**Funktionen:** Datei-Upload, Freigabelinks, Ablauf, Passwortschutz

#### 📝 Metablogizer

Statischer Site-Publisher mit Tor

**Funktionen:** Statische Sites, Tor-Veröffentlichung, Vorlagen, Markdown

#### ✏️ Hexo Blog

Statischer Blog-Generator

**Funktionen:** Markdown, Themes, Plugins, Deploy

#### 🐘 GoToSocial

ActivityPub-Social-Server

**Funktionen:** Mastodon-kompatibel, Föderation, Medien, Datenschutz

#### 📡 CyberFeed

RSS/Atom-Feed-Aggregator

**Funktionen:** Feed-Verwaltung, Kategorien, Suche, Export

---

### Security

#### 🛡️ CrowdSec

Kollaborative Sicherheits-Engine mit Verhaltensanalyse

**Funktionen:** Entscheidungsverwaltung, Warnungen, Bouncers, Sammlungen, Community-Blocklisten

#### 🔥 Web Application Firewall

WAF mit 300+ OWASP-Sicherheitsregeln

**Funktionen:** OWASP-Regeln, Eigene Regeln, CrowdSec-Integration, Anforderungsprotokollierung

#### 🔥 Vortex Firewall

nftables-basierte Bedrohungsdurchsetzungs-Firewall

**Funktionen:** IP-Blocklisten, nftables-Sets, Bedrohungsfeeds, Geo-Blocking

#### 🔒 System Hardening

Kernel- und Systemhärtung für ANSSI CSPN-Konformität

**Funktionen:** Sysctl-Härtung, Modul-Blacklist, Sicherheitsbewertung, AppArmor

#### 🔍 MITM Proxy

Verkehrsinspektion und WAF-Proxy mit Auto-Ban

**Funktionen:** Verkehrsinspektion, Anforderungsprotokollierung, Auto-Ban, SSL-Interception

#### 🔐 Auth Guardian

Einheitliche Authentifizierungsverwaltung

**Funktionen:** OAuth2, LDAP, 2FA/TOTP, Sitzungen

#### 🛡️ Network Access Control

Client-Guardian und NAC mit Quarantäne

**Funktionen:** Gerätesteuerung, MAC-Filterung, Quarantäne, VLAN-Zuweisung

#### 🚫 IP Block Manager

IP- und Netzwerksperrverwaltung

**Funktionen:** IP-Blocklisten, Netzwerkbereiche, Temporäre Sperren, Import/Export

#### 🔐 MAC Guard

MAC-Adress-Zugangskontrolle

**Funktionen:** MAC-Whitelist/Blacklist, Auto-Erkennung, Warnungen, VLAN-Bindung

#### 📡 Traffic Interceptor

Netzwerkverkehrs-Interception und -Analyse

**Funktionen:** Paketerfassung, Protokollanalyse, Sitzungsverfolgung, Forensik

#### 🍪 Cookie Manager

Cookie- und Sitzungssicherheitsverwaltung

**Funktionen:** Cookie-Richtlinien, Sitzungssicherheit, SameSite-Durchsetzung, Audit

#### ⚠️ Threat Dashboard

Einheitliche Bedrohungsvisualisierung

**Funktionen:** Bedrohungsfeeds, Angriffszeitachse, Schweregrade, Korrelation

#### 🔬 Threat Analyst

KI-gestützte Bedrohungsanalyse

**Funktionen:** ML-Erkennung, Verhaltensanalyse, IOC-Extraktion, Berichte

#### 🔴 CVE Triage

CVE-Schwachstellenverfolgung und -Triage

**Funktionen:** CVE-Datenbank, Betroffene Pakete, Risikobewertung, Behebung

#### 🛡️ Wazuh SIEM

Wazuh SIEM-Integration

**Funktionen:** Log-Analyse, Dateiintegrität, Schwachstellenerkennung, Compliance

#### 🔒 OSSEC HIDS

OSSEC-hostbasierte Einbruchserkennung

**Funktionen:** Log-Analyse, Rootkit-Erkennung, Dateiintegrität, Aktive Reaktion

#### 🦞 OpenClaw Scanner

Netzwerk-Schwachstellen-Scanner

**Funktionen:** Port-Scanning, Diensterkennung, Schwachstellenprüfungen, Berichte

#### 🔌 IoT Guard

IoT-Gerätesicherheitsüberwachung

**Funktionen:** Geräte-Fingerprinting, Anomalieerkennung, Isolation, Firmware-Prüfungen

---

### Services

#### 📦 Services Portal

C3Box-Dienstportal

**Funktionen:** Service-Links, Statusübersicht, Schnellzugriff, Kategorien

#### 🦊 Gitea

Git-Server (LXC)

**Funktionen:** Repositories, Benutzer, SSH/HTTP, LFS, Actions

#### ☁️ Nextcloud

Dateisynchronisierung (LXC)

**Funktionen:** Dateisync, WebDAV, CalDAV, CardDAV, Talk

---

### System

#### ⚙️ System Hub

Systemkonfiguration und -verwaltung

**Funktionen:** Einstellungen, Protokolle, Dienste, Updates

#### 💾 Backup Manager

System- und LXC-Backup

**Funktionen:** Config-Backup, LXC-Snapshots, Wiederherstellung, Planung

#### 📋 Config Advisor

Konfigurationsempfehlungen

**Funktionen:** Sicherheits-Audit, Best Practices, Optimierung, Berichte

#### 📊 Reporter

Systemberichterstattung und -analyse

**Funktionen:** Berichte, Planung, Export, E-Mail

#### 🪞 Mirror Manager

APT-Mirror-Verwaltung

**Funktionen:** Mirror-Sync, Bandbreite, Planung, Cache

#### 📀 System Cloner

System-Image-Klonen

**Funktionen:** Disk-Imaging, Clone auf USB, Wiederherstellung, Kompression

#### 👁️ Eye Remote

Remote-Verwaltungsoberfläche

**Funktionen:** USB-Gadget, Serielle Konsole, Boot-Medium, Wiederherstellung

#### 🖥️ RTTY Console

Remote-Terminal-Zugriff

**Funktionen:** Web-Terminal, SSH, Dateiübertragung, Aufnahme

---

### VPN

#### 🔗 WireGuard VPN

Modernes VPN mit Kernel-Integration

**Funktionen:** Peer-Verwaltung, QR-Codes, Verkehrsstatistiken, Multi-Tunnel

#### 🕸️ Mesh Network

Mesh-Netzwerk mit Yggdrasil

**Funktionen:** Peer-Erkennung, Routing, Verschlüsselung, IPv6-Overlay

#### 🔗 P2P Network

Peer-to-Peer-Netzwerk

**Funktionen:** Direktverbindungen, NAT-Traversal, Verschlüsselung, DHT

#### 🔗 MasterLink

SecuBox Mesh-Föderation

**Funktionen:** Box-Erkennung, Föderation, Gemeinsame Richtlinien, Sync

---

