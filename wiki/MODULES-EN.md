# SecuBox Modules

*Complete module documentation*

**Total modules:** 128

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Overview

| Modules | Category | Description |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Central dashboard and control center |
| 🛡️ **Security Operations Center** | Dashboard | SOC with world clock, threat map, tickets |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT to Debian migration tracking |
| 📈 **System Metrics** | Dashboard | Real-time system metrics dashboard |
| ⚙️ **Admin Panel** | Dashboard | System administration panel |
| 🛡️ **CrowdSec** | Security | Collaborative security engine with behavior analysis |
| 🔥 **Web Application Firewall** | Security | WAF with 300+ OWASP security rules |
| 🔥 **Vortex Firewall** | Security | nftables-based threat enforcement firewall |
| 🔒 **System Hardening** | Security | Kernel and system hardening for ANSSI CSPN compliance |
| 🔍 **MITM Proxy** | Security | Traffic inspection and WAF proxy with auto-ban |
| 🔐 **Auth Guardian** | Security | Unified authentication management |
| 🛡️ **Network Access Control** | Security | Client guardian and NAC with quarantine |
| 🚫 **IP Block Manager** | Security | IP and network blocking management |
| 🔐 **MAC Guard** | Security | MAC address access control |
| 📡 **Traffic Interceptor** | Security | Network traffic interception and analysis |
| 🍪 **Cookie Manager** | Security | Cookie and session security management |
| ⚠️ **Threat Dashboard** | Security | Unified threat visualization |
| 🔬 **Threat Analyst** | Security | AI-powered threat analysis |
| 🔴 **CVE Triage** | Security | CVE vulnerability tracking and triage |
| 🛡️ **Wazuh SIEM** | Security | Wazuh SIEM integration |
| 🔒 **OSSEC HIDS** | Security | OSSEC host-based intrusion detection |
| 🦞 **OpenClaw Scanner** | Security | Network vulnerability scanner |
| 🔌 **IoT Guard** | Security | IoT device security monitoring |
| 🌐 **Network Modes** | Network | Network topology configuration |
| 📊 **QoS Manager** | Network | Quality of Service with HTB/VLAN |
| 📈 **Traffic Shaping** | Network | TC/CAKE traffic shaping |
| ⚡ **HAProxy** | Network | Load balancer with TLS 1.3 |
| 🚀 **CDN Cache** | Network | Content delivery cache |
| 🏗️ **Virtual Hosts** | Network | Nginx virtual host management |
| 🛤️ **Routing Manager** | Network | Static and policy-based routing |
| 🔧 **Network Tweaks** | Network | Network kernel parameters tuning |
| 🔍 **Network Diagnostics** | Network | Network troubleshooting tools |
| 📉 **Network Anomaly** | Network | Network anomaly detection |
| 📶 **Modem Manager** | Network | 3G/4G/5G modem management |
| 🌍 **DNS Server** | DNS | BIND DNS zone management |
| 🛡️ **Vortex DNS** | DNS | DNS firewall with RPZ blocklists |
| 📡 **Mesh DNS** | DNS | Mesh network domain resolution |
| 🛡️ **DNS Guard** | DNS | DNS-based threat protection |
| 🌐 **DNS Provider** | DNS | External DNS provider integration |
| 🚫 **AdGuard** | DNS | AdGuard Home DNS blocking |
| 🔗 **WireGuard VPN** | VPN | Modern VPN with kernel integration |
| 🕸️ **Mesh Network** | VPN | Mesh networking with Yggdrasil |
| 🔗 **P2P Network** | VPN | Peer-to-peer networking |
| 🔗 **MasterLink** | VPN | SecuBox mesh federation |
| 🧅 **Tor Network** | Privacy | Tor anonymity and hidden services |
| 🌐 **Exposure Settings** | Privacy | Unified exposure management |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP Hamiltonian authentication |
| 💬 **SimpleX Chat** | Privacy | Privacy-focused messaging |
| 🔐 **Secret Vault** | Privacy | Secrets and credentials management |
| 📊 **Netdata** | Monitoring | Real-time system monitoring |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI with netifyd/nDPId |
| 🔬 **Netifyd DPI** | Monitoring | Netifyd deep packet inspection |
| 🔬 **nDPId** | Monitoring | nDPI daemon for traffic analysis |
| 📱 **Device Intelligence** | Monitoring | Asset discovery and fingerprinting |
| 👁️ **Watchdog** | Monitoring | Service and container monitoring |
| 🎬 **Media Flow** | Monitoring | Media traffic analytics |
| 👀 **Glances** | Monitoring | System monitoring dashboard |
| 🔐 **Login Portal** | Access | Authentication portal with JWT |
| 👥 **User Management** | Access | Unified identity management |
| 🪪 **Identity Provider** | Access | SAML/OIDC identity provider |
| 📦 **Services Portal** | Services | C3Box services portal |
| 🦊 **Gitea** | Services | Git server (LXC) |
| ☁️ **Nextcloud** | Services | File sync (LXC) |
| 🦙 **Ollama** | AI | Local LLM server |
| 🤖 **LocalAI** | AI | OpenAI-compatible local API |
| 🚪 **AI Gateway** | AI | AI model API gateway |
| 💡 **AI Insights** | AI | AI-powered security insights |
| 🧠 **LocalRecall** | AI | Local RAG memory system |
| 🔌 **MCP Server** | AI | Model Context Protocol server |
| 📧 **Mail Server** | Email | Postfix/Dovecot mail server |
| 💌 **Webmail** | Email | Roundcube/SOGo webmail |
| 📤 **SMTP Relay** | Email | SMTP relay and smarthost |
| 💬 **Jabber/XMPP** | Email | XMPP messaging server |
| 🎬 **Jellyfin** | Media | Media server |
| 🎵 **Lyrion Music** | Media | Music streaming server |
| 📻 **Web Radio** | Media | Internet radio streaming |
| 📸 **PhotoPrism** | Media | AI-powered photo management |
| 📺 **PeerTube** | Media | Federated video platform |
| 🌊 **Torrent** | Media | BitTorrent client |
| 📰 **Newsbin** | Media | Usenet/NNTP client |
| 📰 **Publishing Platform** | Publishing | Unified publishing dashboard |
| 💧 **Droplet** | Publishing | File upload and publish |
| 📝 **Metablogizer** | Publishing | Static site publisher with Tor |
| ✏️ **Hexo Blog** | Publishing | Static blog generator |
| 🐘 **GoToSocial** | Publishing | ActivityPub social server |
| 📡 **CyberFeed** | Publishing | RSS/Atom feed aggregator |
| 🎨 **Streamlit** | Apps | Streamlit app platform |
| ⚡ **StreamForge** | Apps | Streamlit app development |
| 📦 **APT Repository** | Apps | APT repository management |
| 🏠 **Domoticz** | IoT | Home automation |
| 🏡 **Home Assistant** | IoT | Home automation hub |
| 📡 **Zigbee Gateway** | IoT | Zigbee2MQTT gateway |
| 📡 **MQTT Broker** | IoT | Mosquitto MQTT broker |
| 💬 **Matrix Server** | Communication | Matrix/Synapse chat server |
| 📹 **Jitsi Meet** | Communication | Video conferencing |
| 📞 **VoIP Server** | Communication | Asterisk/FreePBX VoIP |
| 🔄 **TURN Server** | Communication | TURN/STUN relay server |
| ⚙️ **System Hub** | System | System configuration and management |
| 💾 **Backup Manager** | System | System and LXC backup |
| 📋 **Config Advisor** | System | Configuration recommendations |
| 📊 **Reporter** | System | System reporting and analytics |
| 🪞 **Mirror Manager** | System | APT mirror management |
| 📀 **System Cloner** | System | System image cloning |
| 👁️ **Eye Remote** | System | Remote management interface |
| 🖥️ **RTTY Console** | System | Remote terminal access |
| 🔐 **Authelia SSO** | Access | Single sign-on identity provider (AUTH-BRIDGE) |
| 🧑 **Avatar Manager** | Apps | Identity and avatar manager |
| 📜 **Certificate Manager** | Security | ACME / TLS certificate manager |
| 📻 **FM Relay** | Media | rtl_fm to Icecast MP3 mount with live RDS metadata |
| 📊 **Grafana** | Monitoring | Security metrics dashboards |
| ❤️ **Hub Health** | Dashboard | Service health and status board |
| 🧠 **KSM Optimizer** | System | Kernel same-page memory optimization dashboard |
| 🪞 **MagicMirror** | Apps | MagicMirror smart-display management |
| 🧪 **Metabolizer** | Monitoring | Log processor and analyzer |
| 🗄️ **Metoblizer** | Monitoring | Centralized log aggregator |
| 📇 **Metacatalog** | Services | Service catalog and registry |
| 🍺 **PicoBrew** | IoT | Homebrew / fermentation controller |
| 🎙️ **Podcaster** | Media | Modern podcast manager |
| 🤖 **ReDroid** | Apps | Android-in-container runtime |
| 📦 **RezApp** | Services | Application deployment and management |
| 🖥️ **RustDesk** | Access | Self-hosted remote desktop relay |
| 🔌 **SaaS Relay** | Network | SaaS / API proxy relay |
| 🎯 **Security Posture** | Security | Honest board-truthful security scorecard |
| 📡 **SENTINELLE-GSM** | Security | Passive rogue-BTS sensor (MIND layer) |
| 🕸️ **ThreatMesh** | Security | Sovereign threat-intel mesh (CrowdSec CAPI replacement) |
| 🧰 **ToolBoX (Cabine)** | Security | Captive AP + consented MITM privacy analyzer |
| 💻 **VM Manager** | System | Virtualization management |
| 🔎 **YaCy** | Network | Peer-to-peer search engine |

---

## Modules

### AI

#### 🦙 Ollama

Local LLM server

**Features:** Model management, API, Chat, GPU support

![Ollama](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ollama.png)

#### 🤖 LocalAI

OpenAI-compatible local API

**Features:** OpenAI API, Multiple models, Embeddings, Image generation

![LocalAI](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/localai.png)

#### 🚪 AI Gateway

AI model API gateway

**Features:** Rate limiting, Load balancing, Caching, Logging

![AI Gateway](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

AI-powered security insights

**Features:** Anomaly detection, Recommendations, Predictions, Reports

![AI Insights](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

Local RAG memory system

**Features:** Vector storage, Semantic search, Document indexing, API

![LocalRecall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/localrecall.png)

#### 🔌 MCP Server

Model Context Protocol server

**Features:** Tool integration, Context management, Multi-model, API

![MCP Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

Authentication portal with JWT

**Features:** JWT auth, Sessions, Password recovery, Captive portal

![Login Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/portal.png)

#### 👥 User Management

Unified identity management

**Features:** User CRUD, Groups, Service provisioning, RBAC

![User Management](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/users.png)

#### 🪪 Identity Provider

SAML/OIDC identity provider

**Features:** SAML 2.0, OpenID Connect, Federation, SSO

![Identity Provider](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/identity.png)

#### 🔐 Authelia SSO

Single sign-on identity provider (AUTH-BRIDGE)

**Features:** SSO, 2FA / TOTP, Access policies, LDAP / file backend

![Authelia SSO](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/authelia.png)

#### 🖥️ RustDesk

Self-hosted remote desktop relay

**Features:** Relay server, ID server, Sessions, Self-hosted

![RustDesk](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rustdesk.png)

---

### Apps

#### 🎨 Streamlit

Streamlit app platform

**Features:** App hosting, Deployment, Management, Logs

![Streamlit](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Streamlit app development

**Features:** Templates, Code editor, Preview, Deploy

![StreamForge](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamforge.png)

#### 📦 APT Repository

APT repository management

**Features:** Package management, GPG signing, Multi-distro, Uploads

![APT Repository](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/repo.png)

#### 🧑 Avatar Manager

Identity and avatar manager

**Features:** Identity profiles, Avatar generation, Per-user assets

![Avatar Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/avatar.png)

#### 🪞 MagicMirror

MagicMirror smart-display management

**Features:** Module layout, Widgets, Themes, Remote control

![MagicMirror](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/magicmirror.png)

#### 🤖 ReDroid

Android-in-container runtime

**Features:** Android container, ADB, App install, Screen view

![ReDroid](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/redroid.png)

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse chat server

**Features:** E2E encryption, Federation, Bridges, Calls

![Matrix Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

Video conferencing

**Features:** Video calls, Screen share, Recording, Lobby

![Jitsi Meet](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jitsi.png)

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**Features:** Extensions, Trunks, IVR, Voicemail

![VoIP Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/voip.png)

#### 🔄 TURN Server

TURN/STUN relay server

**Features:** NAT traversal, WebRTC, TLS, Statistics

![TURN Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

BIND DNS zone management

**Features:** Zone management, Records, DNSSEC, Reverse DNS

![DNS Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

DNS firewall with RPZ blocklists

**Features:** Blocklists, RPZ, Threat feeds, DoH/DoT

![Vortex DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Mesh network domain resolution

**Features:** mDNS/Avahi, Local DNS, Service discovery, Mesh integration

![Mesh DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

DNS-based threat protection

**Features:** Malware blocking, Phishing protection, Analytics, Whitelist

![DNS Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

External DNS provider integration

**Features:** Cloudflare, Route53, DigitalOcean, Dynamic DNS

![DNS Provider](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

AdGuard Home DNS blocking

**Features:** Ad blocking, Tracking protection, Parental control, Statistics

![AdGuard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

Central dashboard and control center

**Features:** System overview, Service monitoring, Quick actions, Metrics

![SecuBox Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

SOC with world clock, threat map, tickets

**Features:** World clock, Threat map, Ticket system, P2P intel, Alerts

![Security Operations Center](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/soc.png)

#### 📋 Migration Roadmap

OpenWRT to Debian migration tracking

**Features:** Progress tracking, Module status, Category view

![Migration Roadmap](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/roadmap.png)

#### 📈 System Metrics

Real-time system metrics dashboard

**Features:** CPU/Memory, Network stats, Disk I/O, Historical data

![System Metrics](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

System administration panel

**Features:** User management, System config, Logs, Diagnostics

![Admin Panel](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/admin.png)

#### ❤️ Hub Health

Service health and status board

**Features:** Service health, Socket checks, Uptime, Degradation alerts

![Hub Health](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/health.png)

---

### Email

#### 📧 Mail Server

Postfix/Dovecot mail server

**Features:** Domains, Mailboxes, DKIM, SpamAssassin, ClamAV

![Mail Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mail.png)

#### 💌 Webmail

Roundcube/SOGo webmail

**Features:** Web interface, Address book, Calendar, Mobile

![Webmail](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/webmail.png)

#### 📤 SMTP Relay

SMTP relay and smarthost

**Features:** Relay, Authentication, Rate limiting, Logging

![SMTP Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

XMPP messaging server

**Features:** Chat, Groups, File transfer, Federation

![Jabber/XMPP](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

Home automation

**Features:** Devices, Scenes, Scripts, History

![Domoticz](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

Home automation hub

**Features:** Integrations, Automations, Dashboard, Voice

![Home Assistant](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Features:** Device pairing, MQTT, Groups, OTA updates

![Zigbee Gateway](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Mosquitto MQTT broker

**Features:** Topics, ACL, TLS, WebSocket

![MQTT Broker](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mqtt.png)

#### 🍺 PicoBrew

Homebrew / fermentation controller

**Features:** Temperature control, Recipes, Fermentation log, Sensors

![PicoBrew](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/picobrew.png)

---

### Media

#### 🎬 Jellyfin

Media server

**Features:** Video streaming, Live TV, Transcoding, Mobile apps

![Jellyfin](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

Music streaming server

**Features:** Music library, Playlists, Radio, Multi-room

![Lyrion Music](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/lyrion.png)

#### 📻 Web Radio

Internet radio streaming

**Features:** Radio stations, Recording, Schedule, Favorites

![Web Radio](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/webradio.png)

#### 📸 PhotoPrism

AI-powered photo management

**Features:** Face recognition, Auto-tagging, Search, Albums

![PhotoPrism](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/photoprism.png)

#### 📺 PeerTube

Federated video platform

**Features:** Video hosting, Federation, Live streaming, Comments

![PeerTube](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/peertube.png)

#### 🌊 Torrent

BitTorrent client

**Features:** Downloads, RSS, Remote control, Bandwidth limits

![Torrent](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/torrent.png)

#### 📰 Newsbin

Usenet/NNTP client

**Features:** NZB downloads, Auto-processing, Search, Categories

![Newsbin](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/newsbin.png)

#### 📻 FM Relay

rtl_fm to Icecast MP3 mount with live RDS metadata

**Features:** SDR FM capture, Icecast stream, RDS metadata, Station presets

![FM Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/fmrelay.png)

#### 🎙️ Podcaster

Modern podcast manager

**Features:** Feed management, Episodes, Transcoding, RSS publish

![Podcaster](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/podcaster.png)

---

### Monitoring

#### 📊 Netdata

Real-time system monitoring

**Features:** Metrics, Alerts, Charts, Plugins

![Netdata](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

DPI with netifyd/nDPId

**Features:** Protocol detection, App identification, Flow analysis, Statistics

![Deep Packet Inspection](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Netifyd deep packet inspection

**Features:** Application detection, Protocol analysis, Flow stats, API

![Netifyd DPI](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netifyd.png)

#### 🔬 nDPId

nDPI daemon for traffic analysis

**Features:** Protocol detection, Flow tracking, JSON API, Real-time

![nDPId](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

Asset discovery and fingerprinting

**Features:** ARP scanning, MAC vendor lookup, OS detection, Services

![Device Intelligence](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/device-intel.png)

#### 👁️ Watchdog

Service and container monitoring

**Features:** Health checks, Auto-restart, Alerts, Logs

![Watchdog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/watchdog.png)

#### 🎬 Media Flow

Media traffic analytics

**Features:** Stream detection, Bandwidth usage, Protocol analysis, QoE

![Media Flow](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mediaflow.png)

#### 👀 Glances

System monitoring dashboard

**Features:** CPU/Memory, Disk/Network, Docker, Web UI

![Glances](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/glances.png)

#### 📊 Grafana

Security metrics dashboards

**Features:** Time-series dashboards, Alerting, Data sources, Panels

![Grafana](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/grafana.png)

#### 🧪 Metabolizer

Log processor and analyzer

**Features:** Log parsing, Pattern analysis, Pipelines, Enrichment

![Metabolizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metabolizer.png)

#### 🗄️ Metoblizer

Centralized log aggregator

**Features:** Log collection, Central store, Search, Retention

![Metoblizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metoblizer.png)

---

### Network

#### 🌐 Network Modes

Network topology configuration

**Features:** Router mode, Bridge mode, AP mode, VLAN

![Network Modes](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netmodes.png)

#### 📊 QoS Manager

Quality of Service with HTB/VLAN

**Features:** Bandwidth control, VLAN policies, 802.1p PCP, Per-user limits

![QoS Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/qos.png)

#### 📈 Traffic Shaping

TC/CAKE traffic shaping

**Features:** Per-interface QoS, CAKE algorithm, Statistics, Real-time graphs

![Traffic Shaping](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/traffic.png)

#### ⚡ HAProxy

Load balancer with TLS 1.3

**Features:** Backend management, Stats, ACLs, SSL termination, Health checks

![HAProxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

Content delivery cache

**Features:** Cache management, Purge, Statistics, Edge rules

![CDN Cache](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Nginx virtual host management

**Features:** Site management, SSL certificates, Reverse proxy, Let's Encrypt

![Virtual Hosts](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

Static and policy-based routing

**Features:** Static routes, Policy routing, Multi-WAN, Failover

![Routing Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/routes.png)

#### 🔧 Network Tweaks

Network kernel parameters tuning

**Features:** TCP tuning, Buffer sizes, Congestion control, Profiles

![Network Tweaks](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

Network troubleshooting tools

**Features:** Ping/Traceroute, DNS lookup, Port scan, Speed test

![Network Diagnostics](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

Network anomaly detection

**Features:** Traffic baselines, Anomaly alerts, ML detection, Visualization

![Network Anomaly](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

3G/4G/5G modem management

**Features:** Connection status, Signal strength, SMS, Failover

![Modem Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/modem.png)

#### 🔌 SaaS Relay

SaaS / API proxy relay

**Features:** API proxy, Rate limiting, Routing, Credentials vault

![SaaS Relay](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/saas-relay.png)

#### 🔎 YaCy

Peer-to-peer search engine

**Features:** P2P index, Crawler, Private search, Federation

![YaCy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/yacy.png)

---

### Privacy

#### 🧅 Tor Network

Tor anonymity and hidden services

**Features:** Circuits, Hidden services, Bridges, Transparent proxy

![Tor Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/tor.png)

#### 🌐 Exposure Settings

Unified exposure management

**Features:** Tor exposure, SSL certs, DNS records, Mesh access

![Exposure Settings](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

ZKP Hamiltonian authentication

**Features:** Proof generation, Verification, Key management, MirrorNet

![Zero-Knowledge Proofs](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

Privacy-focused messaging

**Features:** E2E encryption, No user IDs, Self-hosted, Groups

![SimpleX Chat](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/simplex.png)

#### 🔐 Secret Vault

Secrets and credentials management

**Features:** Encrypted storage, Access control, Rotation, Audit

![Secret Vault](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

Unified publishing dashboard

**Features:** Multi-platform, Scheduling, Analytics, Templates

![Publishing Platform](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/publish.png)

#### 💧 Droplet

File upload and publish

**Features:** File upload, Share links, Expiration, Password protection

![Droplet](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/droplet.png)

#### 📝 Metablogizer

Static site publisher with Tor

**Features:** Static sites, Tor publishing, Templates, Markdown

![Metablogizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

Static blog generator

**Features:** Markdown, Themes, Plugins, Deploy

![Hexo Blog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hexo.png)

#### 🐘 GoToSocial

ActivityPub social server

**Features:** Mastodon compatible, Federation, Media, Privacy

![GoToSocial](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

RSS/Atom feed aggregator

**Features:** Feed management, Categories, Search, Export

![CyberFeed](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

Collaborative security engine with behavior analysis

**Features:** Decision management, Alerts, Bouncers, Collections, Community blocklists

![CrowdSec](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Features:** OWASP rules, Custom rules, CrowdSec integration, Request logging

![Web Application Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

nftables-based threat enforcement firewall

**Features:** IP blocklists, nftables sets, Threat feeds, Geo-blocking

![Vortex Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

Kernel and system hardening for ANSSI CSPN compliance

**Features:** Sysctl hardening, Module blacklist, Security score, AppArmor

![System Hardening](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

Traffic inspection and WAF proxy with auto-ban

**Features:** Traffic inspection, Request logging, Auto-ban, SSL interception

![MITM Proxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

Unified authentication management

**Features:** OAuth2, LDAP, 2FA/TOTP, Session management

![Auth Guardian](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/auth.png)

#### 🛡️ Network Access Control

Client guardian and NAC with quarantine

**Features:** Device control, MAC filtering, Quarantine, VLAN assignment

![Network Access Control](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nac.png)

#### 🚫 IP Block Manager

IP and network blocking management

**Features:** IP blocklists, Network ranges, Temporary bans, Import/Export

![IP Block Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

MAC address access control

**Features:** MAC whitelist/blacklist, Auto-discovery, Alerts, VLAN binding

![MAC Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

Network traffic interception and analysis

**Features:** Packet capture, Protocol analysis, Session tracking, Forensics

![Traffic Interceptor](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Cookie and session security management

**Features:** Cookie policies, Session security, SameSite enforcement, Audit

![Cookie Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

Unified threat visualization

**Features:** Threat feeds, Attack timeline, Severity levels, Correlation

![Threat Dashboard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threats.png)

#### 🔬 Threat Analyst

AI-powered threat analysis

**Features:** ML detection, Behavioral analysis, IOC extraction, Reports

![Threat Analyst](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

CVE vulnerability tracking and triage

**Features:** CVE database, Affected packages, Risk scoring, Remediation

![CVE Triage](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Wazuh SIEM integration

**Features:** Log analysis, File integrity, Vulnerability detection, Compliance

![Wazuh SIEM](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

OSSEC host-based intrusion detection

**Features:** Log analysis, Rootkit detection, File integrity, Active response

![OSSEC HIDS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

Network vulnerability scanner

**Features:** Port scanning, Service detection, Vulnerability checks, Reports

![OpenClaw Scanner](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

IoT device security monitoring

**Features:** Device fingerprinting, Anomaly detection, Isolation, Firmware checks

![IoT Guard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/iot-guard.png)

#### 📜 Certificate Manager

ACME / TLS certificate manager

**Features:** ACME issuance, Renewal, SAN / wildcard, Inventory

![Certificate Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/certs.png)

#### 🎯 Security Posture

Honest board-truthful security scorecard

**Features:** Scorecard, Control checks, Gaps, Trend

![Security Posture](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/security-posture.png)

#### 📡 SENTINELLE-GSM

Passive rogue-BTS sensor (MIND layer)

**Features:** IMSI-catcher detection, Cell survey, Anomaly alerts, Passive RF

![SENTINELLE-GSM](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/sentinelle.png)

#### 🕸️ ThreatMesh

Sovereign threat-intel mesh (CrowdSec CAPI replacement)

**Features:** P2P intel sharing, Sovereign feed, Confidence gating, Blocklist sync

![ThreatMesh](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/threatmesh.png)

#### 🧰 ToolBoX (Cabine)

Captive AP + consented MITM privacy analyzer

**Features:** Captive portal, R0-R4 levels, Tracker exposure, Tor egress

![ToolBoX (Cabine)](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/toolbox.png)

---

### Services

#### 📦 Services Portal

C3Box services portal

**Features:** Service links, Status overview, Quick access, Categories

![Services Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/c3box.png)

#### 🦊 Gitea

Git server (LXC)

**Features:** Repositories, Users, SSH/HTTP, LFS, Actions

![Gitea](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/gitea.png)

#### ☁️ Nextcloud

File sync (LXC)

**Features:** File sync, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nextcloud.png)

#### 📇 Metacatalog

Service catalog and registry

**Features:** Service registry, Discovery, Metadata, Catalog UI

![Metacatalog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metacatalog.png)

#### 📦 RezApp

Application deployment and management

**Features:** App deploy, Lifecycle, Config, Status

![RezApp](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rezapp.png)

---

### System

#### ⚙️ System Hub

System configuration and management

**Features:** Settings, Logs, Services, Updates

![System Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/system.png)

#### 💾 Backup Manager

System and LXC backup

**Features:** Config backup, LXC snapshots, Restore, Scheduling

![Backup Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/backup.png)

#### 📋 Config Advisor

Configuration recommendations

**Features:** Security audit, Best practices, Optimization, Reports

![Config Advisor](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/config-advisor.png)

#### 📊 Reporter

System reporting and analytics

**Features:** Reports, Scheduling, Export, Email

![Reporter](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

APT mirror management

**Features:** Mirror sync, Bandwidth, Scheduling, Cache

![Mirror Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mirror.png)

#### 📀 System Cloner

System image cloning

**Features:** Disk imaging, Clone to USB, Restore, Compression

![System Cloner](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cloner.png)

#### 👁️ Eye Remote

Remote management interface

**Features:** USB gadget, Serial console, Boot media, Recovery

![Eye Remote](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

Remote terminal access

**Features:** Web terminal, SSH, File transfer, Recording

![RTTY Console](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/rtty.png)

#### 🧠 KSM Optimizer

Kernel same-page memory optimization dashboard

**Features:** Page sharing stats, Memory saved, Tuning, Per-VM view

![KSM Optimizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/ksm.png)

#### 💻 VM Manager

Virtualization management

**Features:** VM lifecycle, Console, Snapshots, Resource limits

![VM Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vm.png)

---

### VPN

#### 🔗 WireGuard VPN

Modern VPN with kernel integration

**Features:** Peer management, QR codes, Traffic stats, Multi-tunnel

![WireGuard VPN](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

Mesh networking with Yggdrasil

**Features:** Peer discovery, Routing, Encryption, IPv6 overlay

![Mesh Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mesh.png)

#### 🔗 P2P Network

Peer-to-peer networking

**Features:** Direct connections, NAT traversal, Encryption, DHT

![P2P Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/p2p.png)

#### 🔗 MasterLink

SecuBox mesh federation

**Features:** Box discovery, Federation, Shared policies, Sync

![MasterLink](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/master-link.png)

---

