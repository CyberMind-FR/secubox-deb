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

![Ollama](screenshots/vm/ollama.png)

#### 🤖 LocalAI

OpenAI-kompatible lokale API

**Funktionen:** OpenAI-API, Mehrere Modelle, Embeddings, Bildgenerierung

![LocalAI](screenshots/vm/localai.png)

#### 🚪 AI Gateway

AI-Modell-API-Gateway

**Funktionen:** Ratenbegrenzung, Lastverteilung, Caching, Protokollierung

![AI Gateway](screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

KI-gestützte Sicherheitseinblicke

**Funktionen:** Anomalieerkennung, Empfehlungen, Vorhersagen, Berichte

![AI Insights](screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

Lokales RAG-Gedächtnissystem

**Funktionen:** Vektorspeicher, Semantische Suche, Dokumentenindizierung, API

![LocalRecall](screenshots/vm/localrecall.png)

#### 🔌 MCP Server

Model Context Protocol-Server

**Funktionen:** Tool-Integration, Kontextverwaltung, Multi-Modell, API

![MCP Server](screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

Authentifizierungsportal mit JWT

**Funktionen:** JWT-Auth, Sitzungen, Passwortwiederherstellung, Captive Portal

![Login Portal](screenshots/vm/portal.png)

#### 👥 User Management

Einheitliche Identitätsverwaltung

**Funktionen:** Benutzer-CRUD, Gruppen, Service-Bereitstellung, RBAC

![User Management](screenshots/vm/users.png)

#### 🪪 Identity Provider

SAML/OIDC-Identitätsanbieter

**Funktionen:** SAML 2.0, OpenID Connect, Föderation, SSO

![Identity Provider](screenshots/vm/identity.png)

---

### Apps

#### 🎨 Streamlit

Streamlit-App-Plattform

**Funktionen:** App-Hosting, Bereitstellung, Verwaltung, Logs

![Streamlit](screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Streamlit-App-Entwicklung

**Funktionen:** Vorlagen, Code-Editor, Vorschau, Deploy

![StreamForge](screenshots/vm/streamforge.png)

#### 📦 APT Repository

APT-Repository-Verwaltung

**Funktionen:** Paketverwaltung, GPG-Signierung, Multi-Distro, Uploads

![APT Repository](screenshots/vm/repo.png)

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse-Chat-Server

**Funktionen:** E2E-Verschlüsselung, Föderation, Bridges, Anrufe

![Matrix Server](screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

Videokonferenzen

**Funktionen:** Videoanrufe, Bildschirmfreigabe, Aufnahme, Lobby

![Jitsi Meet](screenshots/vm/jitsi.png)

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**Funktionen:** Extensions, Trunks, IVR, Voicemail

![VoIP Server](screenshots/vm/voip.png)

#### 🔄 TURN Server

TURN/STUN-Relay-Server

**Funktionen:** NAT-Traversal, WebRTC, TLS, Statistiken

![TURN Server](screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

BIND DNS-Zonenverwaltung

**Funktionen:** Zonenverwaltung, Einträge, DNSSEC, Reverse-DNS

![DNS Server](screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

DNS-Firewall mit RPZ-Blocklisten

**Funktionen:** Blocklisten, RPZ, Bedrohungsfeeds, DoH/DoT

![Vortex DNS](screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Mesh-Netzwerk-Domänenauflösung

**Funktionen:** mDNS/Avahi, Lokales DNS, Diensterkennung, Mesh-Integration

![Mesh DNS](screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

DNS-basierter Bedrohungsschutz

**Funktionen:** Malware-Blockierung, Phishing-Schutz, Analysen, Whitelist

![DNS Guard](screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

Externe DNS-Anbieter-Integration

**Funktionen:** Cloudflare, Route53, DigitalOcean, Dynamisches DNS

![DNS Provider](screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

AdGuard Home DNS-Blockierung

**Funktionen:** Werbungsblockierung, Tracking-Schutz, Jugendschutz, Statistiken

![AdGuard](screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

Zentrales Dashboard und Kontrollzentrum

**Funktionen:** Systemübersicht, Service-Überwachung, Schnellaktionen, Metriken

![SecuBox Hub](screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

SOC mit Weltuhr, Bedrohungskarte, Tickets

**Funktionen:** Weltuhr, Bedrohungskarte, Ticketsystem, P2P-Intel, Warnungen

![Security Operations Center](screenshots/vm/soc.png)

#### 📋 Migration Roadmap

OpenWRT zu Debian Migration-Tracking

**Funktionen:** Fortschrittsverfolgung, Modulstatus, Kategorieansicht

![Migration Roadmap](screenshots/vm/roadmap.png)

#### 📈 System Metrics

Echtzeit-Systemmetriken-Dashboard

**Funktionen:** CPU/Speicher, Netzwerkstatistiken, Disk-I/O, Verlaufsdaten

![System Metrics](screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

Systemverwaltungspanel

**Funktionen:** Benutzerverwaltung, Systemkonfiguration, Logs, Diagnose

![Admin Panel](screenshots/vm/admin.png)

---

### Email

#### 📧 Mail Server

Postfix/Dovecot-Mailserver

**Funktionen:** Domänen, Postfächer, DKIM, SpamAssassin, ClamAV

![Mail Server](screenshots/vm/mail.png)

#### 💌 Webmail

Roundcube/SOGo-Webmail

**Funktionen:** Web-Oberfläche, Adressbuch, Kalender, Mobil

![Webmail](screenshots/vm/webmail.png)

#### 📤 SMTP Relay

SMTP-Relay und Smarthost

**Funktionen:** Relay, Authentifizierung, Ratenbegrenzung, Protokollierung

![SMTP Relay](screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

XMPP-Messaging-Server

**Funktionen:** Chat, Gruppen, Dateiübertragung, Föderation

![Jabber/XMPP](screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

Hausautomation

**Funktionen:** Geräte, Szenen, Skripte, Verlauf

![Domoticz](screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

Hausautomations-Hub

**Funktionen:** Integrationen, Automatisierungen, Dashboard, Sprache

![Home Assistant](screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Zigbee2MQTT-Gateway

**Funktionen:** Gerätekopplung, MQTT, Gruppen, OTA-Updates

![Zigbee Gateway](screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Mosquitto MQTT-Broker

**Funktionen:** Topics, ACL, TLS, WebSocket

![MQTT Broker](screenshots/vm/mqtt.png)

---

### Media

#### 🎬 Jellyfin

Medienserver

**Funktionen:** Video-Streaming, Live-TV, Transcoding, Mobile Apps

![Jellyfin](screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

Musik-Streaming-Server

**Funktionen:** Musikbibliothek, Playlists, Radio, Multi-Room

![Lyrion Music](screenshots/vm/lyrion.png)

#### 📻 Web Radio

Internet-Radio-Streaming

**Funktionen:** Radiosender, Aufnahme, Zeitplan, Favoriten

![Web Radio](screenshots/vm/webradio.png)

#### 📸 PhotoPrism

KI-gestützte Fotoverwaltung

**Funktionen:** Gesichtserkennung, Auto-Tagging, Suche, Alben

![PhotoPrism](screenshots/vm/photoprism.png)

#### 📺 PeerTube

Föderierte Videoplattform

**Funktionen:** Video-Hosting, Föderation, Live-Streaming, Kommentare

![PeerTube](screenshots/vm/peertube.png)

#### 🌊 Torrent

BitTorrent-Client

**Funktionen:** Downloads, RSS, Fernsteuerung, Bandbreitenlimits

![Torrent](screenshots/vm/torrent.png)

#### 📰 Newsbin

Usenet/NNTP-Client

**Funktionen:** NZB-Downloads, Auto-Verarbeitung, Suche, Kategorien

![Newsbin](screenshots/vm/newsbin.png)

---

### Monitoring

#### 📊 Netdata

Echtzeit-Systemüberwachung

**Funktionen:** Metriken, Warnungen, Diagramme, Plugins

![Netdata](screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

DPI mit netifyd/nDPId

**Funktionen:** Protokollerkennung, App-Identifizierung, Flussanalyse, Statistiken

![Deep Packet Inspection](screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Netifyd Deep Packet Inspection

**Funktionen:** Anwendungserkennung, Protokollanalyse, Flussstatistiken, API

![Netifyd DPI](screenshots/vm/netifyd.png)

#### 🔬 nDPId

nDPI-Daemon für Verkehrsanalyse

**Funktionen:** Protokollerkennung, Flussverfolgung, JSON-API, Echtzeit

![nDPId](screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

Asset-Erkennung und Fingerprinting

**Funktionen:** ARP-Scanning, MAC-Vendor-Suche, OS-Erkennung, Dienste

![Device Intelligence](screenshots/vm/device-intel.png)

#### 👁️ Watchdog

Service- und Container-Überwachung

**Funktionen:** Gesundheitsprüfungen, Auto-Neustart, Warnungen, Logs

![Watchdog](screenshots/vm/watchdog.png)

#### 🎬 Media Flow

Medienverkehrsanalyse

**Funktionen:** Stream-Erkennung, Bandbreitennutzung, Protokollanalyse, QoE

![Media Flow](screenshots/vm/mediaflow.png)

#### 👀 Glances

System-Überwachungs-Dashboard

**Funktionen:** CPU/Speicher, Disk/Netzwerk, Docker, Web-UI

![Glances](screenshots/vm/glances.png)

---

### Network

#### 🌐 Network Modes

Netzwerktopologie-Konfiguration

**Funktionen:** Router-Modus, Bridge-Modus, AP-Modus, VLAN

![Network Modes](screenshots/vm/netmodes.png)

#### 📊 QoS Manager

QoS mit HTB/VLAN

**Funktionen:** Bandbreitenkontrolle, VLAN-Richtlinien, 802.1p PCP, Pro-Benutzer-Limits

![QoS Manager](screenshots/vm/qos.png)

#### 📈 Traffic Shaping

TC/CAKE Verkehrsformung

**Funktionen:** Pro-Schnittstelle QoS, CAKE-Algorithmus, Statistiken, Echtzeit-Graphen

![Traffic Shaping](screenshots/vm/traffic.png)

#### ⚡ HAProxy

Load Balancer mit TLS 1.3

**Funktionen:** Backend-Verwaltung, Statistiken, ACLs, SSL-Terminierung, Health-Checks

![HAProxy](screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

Content-Delivery-Cache

**Funktionen:** Cache-Verwaltung, Bereinigung, Statistiken, Edge-Regeln

![CDN Cache](screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Nginx Virtual Host Verwaltung

**Funktionen:** Site-Verwaltung, SSL-Zertifikate, Reverse-Proxy, Let's Encrypt

![Virtual Hosts](screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

Statisches und richtlinienbasiertes Routing

**Funktionen:** Statische Routen, Policy-Routing, Multi-WAN, Failover

![Routing Manager](screenshots/vm/routes.png)

#### 🔧 Network Tweaks

Netzwerk-Kernelparameter-Tuning

**Funktionen:** TCP-Tuning, Puffergrößen, Überlastungskontrolle, Profile

![Network Tweaks](screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

Netzwerk-Diagnosetools

**Funktionen:** Ping/Traceroute, DNS-Suche, Port-Scan, Geschwindigkeitstest

![Network Diagnostics](screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

Netzwerk-Anomalieerkennung

**Funktionen:** Verkehrs-Baselines, Anomalie-Warnungen, ML-Erkennung, Visualisierung

![Network Anomaly](screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

3G/4G/5G-Modemverwaltung

**Funktionen:** Verbindungsstatus, Signalstärke, SMS, Failover

![Modem Manager](screenshots/vm/modem.png)

---

### Privacy

#### 🧅 Tor Network

Tor-Anonymität und versteckte Dienste

**Funktionen:** Schaltkreise, Versteckte Dienste, Bridges, Transparenter Proxy

![Tor Network](screenshots/vm/tor.png)

#### 🌐 Exposure Settings

Einheitliche Expositionsverwaltung

**Funktionen:** Tor-Exposition, SSL-Zertifikate, DNS-Einträge, Mesh-Zugang

![Exposure Settings](screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

ZKP Hamiltonian-Authentifizierung

**Funktionen:** Beweisgenerierung, Verifizierung, Schlüsselverwaltung, MirrorNet

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

Datenschutzorientiertes Messaging

**Funktionen:** E2E-Verschlüsselung, Keine Benutzer-IDs, Selbst gehostet, Gruppen

![SimpleX Chat](screenshots/vm/simplex.png)

#### 🔐 Secret Vault

Geheimnis- und Anmeldedatenverwaltung

**Funktionen:** Verschlüsselter Speicher, Zugriffskontrolle, Rotation, Audit

![Secret Vault](screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

Einheitliches Veröffentlichungs-Dashboard

**Funktionen:** Multi-Plattform, Planung, Analysen, Vorlagen

![Publishing Platform](screenshots/vm/publish.png)

#### 💧 Droplet

Datei-Upload und Veröffentlichung

**Funktionen:** Datei-Upload, Freigabelinks, Ablauf, Passwortschutz

![Droplet](screenshots/vm/droplet.png)

#### 📝 Metablogizer

Statischer Site-Publisher mit Tor

**Funktionen:** Statische Sites, Tor-Veröffentlichung, Vorlagen, Markdown

![Metablogizer](screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

Statischer Blog-Generator

**Funktionen:** Markdown, Themes, Plugins, Deploy

![Hexo Blog](screenshots/vm/hexo.png)

#### 🐘 GoToSocial

ActivityPub-Social-Server

**Funktionen:** Mastodon-kompatibel, Föderation, Medien, Datenschutz

![GoToSocial](screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

RSS/Atom-Feed-Aggregator

**Funktionen:** Feed-Verwaltung, Kategorien, Suche, Export

![CyberFeed](screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

Kollaborative Sicherheits-Engine mit Verhaltensanalyse

**Funktionen:** Entscheidungsverwaltung, Warnungen, Bouncers, Sammlungen, Community-Blocklisten

![CrowdSec](screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

WAF mit 300+ OWASP-Sicherheitsregeln

**Funktionen:** OWASP-Regeln, Eigene Regeln, CrowdSec-Integration, Anforderungsprotokollierung

![Web Application Firewall](screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

nftables-basierte Bedrohungsdurchsetzungs-Firewall

**Funktionen:** IP-Blocklisten, nftables-Sets, Bedrohungsfeeds, Geo-Blocking

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

Kernel- und Systemhärtung für ANSSI CSPN-Konformität

**Funktionen:** Sysctl-Härtung, Modul-Blacklist, Sicherheitsbewertung, AppArmor

![System Hardening](screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

Verkehrsinspektion und WAF-Proxy mit Auto-Ban

**Funktionen:** Verkehrsinspektion, Anforderungsprotokollierung, Auto-Ban, SSL-Interception

![MITM Proxy](screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

Einheitliche Authentifizierungsverwaltung

**Funktionen:** OAuth2, LDAP, 2FA/TOTP, Sitzungen

![Auth Guardian](screenshots/vm/auth.png)

#### 🛡️ Network Access Control

Client-Guardian und NAC mit Quarantäne

**Funktionen:** Gerätesteuerung, MAC-Filterung, Quarantäne, VLAN-Zuweisung

![Network Access Control](screenshots/vm/nac.png)

#### 🚫 IP Block Manager

IP- und Netzwerksperrverwaltung

**Funktionen:** IP-Blocklisten, Netzwerkbereiche, Temporäre Sperren, Import/Export

![IP Block Manager](screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

MAC-Adress-Zugangskontrolle

**Funktionen:** MAC-Whitelist/Blacklist, Auto-Erkennung, Warnungen, VLAN-Bindung

![MAC Guard](screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

Netzwerkverkehrs-Interception und -Analyse

**Funktionen:** Paketerfassung, Protokollanalyse, Sitzungsverfolgung, Forensik

![Traffic Interceptor](screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Cookie- und Sitzungssicherheitsverwaltung

**Funktionen:** Cookie-Richtlinien, Sitzungssicherheit, SameSite-Durchsetzung, Audit

![Cookie Manager](screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

Einheitliche Bedrohungsvisualisierung

**Funktionen:** Bedrohungsfeeds, Angriffszeitachse, Schweregrade, Korrelation

![Threat Dashboard](screenshots/vm/threats.png)

#### 🔬 Threat Analyst

KI-gestützte Bedrohungsanalyse

**Funktionen:** ML-Erkennung, Verhaltensanalyse, IOC-Extraktion, Berichte

![Threat Analyst](screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

CVE-Schwachstellenverfolgung und -Triage

**Funktionen:** CVE-Datenbank, Betroffene Pakete, Risikobewertung, Behebung

![CVE Triage](screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Wazuh SIEM-Integration

**Funktionen:** Log-Analyse, Dateiintegrität, Schwachstellenerkennung, Compliance

![Wazuh SIEM](screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

OSSEC-hostbasierte Einbruchserkennung

**Funktionen:** Log-Analyse, Rootkit-Erkennung, Dateiintegrität, Aktive Reaktion

![OSSEC HIDS](screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

Netzwerk-Schwachstellen-Scanner

**Funktionen:** Port-Scanning, Diensterkennung, Schwachstellenprüfungen, Berichte

![OpenClaw Scanner](screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

IoT-Gerätesicherheitsüberwachung

**Funktionen:** Geräte-Fingerprinting, Anomalieerkennung, Isolation, Firmware-Prüfungen

![IoT Guard](screenshots/vm/iot-guard.png)

---

### Services

#### 📦 Services Portal

C3Box-Dienstportal

**Funktionen:** Service-Links, Statusübersicht, Schnellzugriff, Kategorien

![Services Portal](screenshots/vm/c3box.png)

#### 🦊 Gitea

Git-Server (LXC)

**Funktionen:** Repositories, Benutzer, SSH/HTTP, LFS, Actions

![Gitea](screenshots/vm/gitea.png)

#### ☁️ Nextcloud

Dateisynchronisierung (LXC)

**Funktionen:** Dateisync, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](screenshots/vm/nextcloud.png)

---

### System

#### ⚙️ System Hub

Systemkonfiguration und -verwaltung

**Funktionen:** Einstellungen, Protokolle, Dienste, Updates

![System Hub](screenshots/vm/system.png)

#### 💾 Backup Manager

System- und LXC-Backup

**Funktionen:** Config-Backup, LXC-Snapshots, Wiederherstellung, Planung

![Backup Manager](screenshots/vm/backup.png)

#### 📋 Config Advisor

Konfigurationsempfehlungen

**Funktionen:** Sicherheits-Audit, Best Practices, Optimierung, Berichte

![Config Advisor](screenshots/vm/config-advisor.png)

#### 📊 Reporter

Systemberichterstattung und -analyse

**Funktionen:** Berichte, Planung, Export, E-Mail

![Reporter](screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

APT-Mirror-Verwaltung

**Funktionen:** Mirror-Sync, Bandbreite, Planung, Cache

![Mirror Manager](screenshots/vm/mirror.png)

#### 📀 System Cloner

System-Image-Klonen

**Funktionen:** Disk-Imaging, Clone auf USB, Wiederherstellung, Kompression

![System Cloner](screenshots/vm/cloner.png)

#### 👁️ Eye Remote

Remote-Verwaltungsoberfläche

**Funktionen:** USB-Gadget, Serielle Konsole, Boot-Medium, Wiederherstellung

![Eye Remote](screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

Remote-Terminal-Zugriff

**Funktionen:** Web-Terminal, SSH, Dateiübertragung, Aufnahme

![RTTY Console](screenshots/vm/rtty.png)

---

### VPN

#### 🔗 WireGuard VPN

Modernes VPN mit Kernel-Integration

**Funktionen:** Peer-Verwaltung, QR-Codes, Verkehrsstatistiken, Multi-Tunnel

![WireGuard VPN](screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

Mesh-Netzwerk mit Yggdrasil

**Funktionen:** Peer-Erkennung, Routing, Verschlüsselung, IPv6-Overlay

![Mesh Network](screenshots/vm/mesh.png)

#### 🔗 P2P Network

Peer-to-Peer-Netzwerk

**Funktionen:** Direktverbindungen, NAT-Traversal, Verschlüsselung, DHT

![P2P Network](screenshots/vm/p2p.png)

#### 🔗 MasterLink

SecuBox Mesh-Föderation

**Funktionen:** Box-Erkennung, Föderation, Gemeinsame Richtlinien, Sync

![MasterLink](screenshots/vm/master-link.png)

---

