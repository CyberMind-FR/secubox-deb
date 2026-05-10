# SecuBox Modules

*Complete module documentation*

**Total modules:** 105

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

---

## Modules

### AI

#### 🦙 Ollama

Local LLM server

**Features:** Model management, API, Chat, GPU support

![Ollama](screenshots/vm/ollama.png)

#### 🤖 LocalAI

OpenAI-compatible local API

**Features:** OpenAI API, Multiple models, Embeddings, Image generation

![LocalAI](screenshots/vm/localai.png)

#### 🚪 AI Gateway

AI model API gateway

**Features:** Rate limiting, Load balancing, Caching, Logging

![AI Gateway](screenshots/vm/ai-gateway.png)

#### 💡 AI Insights

AI-powered security insights

**Features:** Anomaly detection, Recommendations, Predictions, Reports

![AI Insights](screenshots/vm/ai-insights.png)

#### 🧠 LocalRecall

Local RAG memory system

**Features:** Vector storage, Semantic search, Document indexing, API

![LocalRecall](screenshots/vm/localrecall.png)

#### 🔌 MCP Server

Model Context Protocol server

**Features:** Tool integration, Context management, Multi-model, API

![MCP Server](screenshots/vm/mcp-server.png)

---

### Access

#### 🔐 Login Portal

Authentication portal with JWT

**Features:** JWT auth, Sessions, Password recovery, Captive portal

![Login Portal](screenshots/vm/portal.png)

#### 👥 User Management

Unified identity management

**Features:** User CRUD, Groups, Service provisioning, RBAC

![User Management](screenshots/vm/users.png)

#### 🪪 Identity Provider

SAML/OIDC identity provider

**Features:** SAML 2.0, OpenID Connect, Federation, SSO

![Identity Provider](screenshots/vm/identity.png)

---

### Apps

#### 🎨 Streamlit

Streamlit app platform

**Features:** App hosting, Deployment, Management, Logs

![Streamlit](screenshots/vm/streamlit.png)

#### ⚡ StreamForge

Streamlit app development

**Features:** Templates, Code editor, Preview, Deploy

![StreamForge](screenshots/vm/streamforge.png)

#### 📦 APT Repository

APT repository management

**Features:** Package management, GPG signing, Multi-distro, Uploads

![APT Repository](screenshots/vm/repo.png)

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse chat server

**Features:** E2E encryption, Federation, Bridges, Calls

![Matrix Server](screenshots/vm/matrix.png)

#### 📹 Jitsi Meet

Video conferencing

**Features:** Video calls, Screen share, Recording, Lobby

![Jitsi Meet](screenshots/vm/jitsi.png)

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**Features:** Extensions, Trunks, IVR, Voicemail

![VoIP Server](screenshots/vm/voip.png)

#### 🔄 TURN Server

TURN/STUN relay server

**Features:** NAT traversal, WebRTC, TLS, Statistics

![TURN Server](screenshots/vm/turn.png)

---

### DNS

#### 🌍 DNS Server

BIND DNS zone management

**Features:** Zone management, Records, DNSSEC, Reverse DNS

![DNS Server](screenshots/vm/dns.png)

#### 🛡️ Vortex DNS

DNS firewall with RPZ blocklists

**Features:** Blocklists, RPZ, Threat feeds, DoH/DoT

![Vortex DNS](screenshots/vm/vortex-dns.png)

#### 📡 Mesh DNS

Mesh network domain resolution

**Features:** mDNS/Avahi, Local DNS, Service discovery, Mesh integration

![Mesh DNS](screenshots/vm/meshname.png)

#### 🛡️ DNS Guard

DNS-based threat protection

**Features:** Malware blocking, Phishing protection, Analytics, Whitelist

![DNS Guard](screenshots/vm/dns-guard.png)

#### 🌐 DNS Provider

External DNS provider integration

**Features:** Cloudflare, Route53, DigitalOcean, Dynamic DNS

![DNS Provider](screenshots/vm/dns-provider.png)

#### 🚫 AdGuard

AdGuard Home DNS blocking

**Features:** Ad blocking, Tracking protection, Parental control, Statistics

![AdGuard](screenshots/vm/ad-guard.png)

---

### Dashboard

#### 🏠 SecuBox Hub

Central dashboard and control center

**Features:** System overview, Service monitoring, Quick actions, Metrics

![SecuBox Hub](screenshots/vm/hub.png)

#### 🛡️ Security Operations Center

SOC with world clock, threat map, tickets

**Features:** World clock, Threat map, Ticket system, P2P intel, Alerts

![Security Operations Center](screenshots/vm/soc.png)

#### 📋 Migration Roadmap

OpenWRT to Debian migration tracking

**Features:** Progress tracking, Module status, Category view

![Migration Roadmap](screenshots/vm/roadmap.png)

#### 📈 System Metrics

Real-time system metrics dashboard

**Features:** CPU/Memory, Network stats, Disk I/O, Historical data

![System Metrics](screenshots/vm/metrics.png)

#### ⚙️ Admin Panel

System administration panel

**Features:** User management, System config, Logs, Diagnostics

![Admin Panel](screenshots/vm/admin.png)

---

### Email

#### 📧 Mail Server

Postfix/Dovecot mail server

**Features:** Domains, Mailboxes, DKIM, SpamAssassin, ClamAV

![Mail Server](screenshots/vm/mail.png)

#### 💌 Webmail

Roundcube/SOGo webmail

**Features:** Web interface, Address book, Calendar, Mobile

![Webmail](screenshots/vm/webmail.png)

#### 📤 SMTP Relay

SMTP relay and smarthost

**Features:** Relay, Authentication, Rate limiting, Logging

![SMTP Relay](screenshots/vm/smtp-relay.png)

#### 💬 Jabber/XMPP

XMPP messaging server

**Features:** Chat, Groups, File transfer, Federation

![Jabber/XMPP](screenshots/vm/jabber.png)

---

### IoT

#### 🏠 Domoticz

Home automation

**Features:** Devices, Scenes, Scripts, History

![Domoticz](screenshots/vm/domoticz.png)

#### 🏡 Home Assistant

Home automation hub

**Features:** Integrations, Automations, Dashboard, Voice

![Home Assistant](screenshots/vm/homeassistant.png)

#### 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Features:** Device pairing, MQTT, Groups, OTA updates

![Zigbee Gateway](screenshots/vm/zigbee.png)

#### 📡 MQTT Broker

Mosquitto MQTT broker

**Features:** Topics, ACL, TLS, WebSocket

![MQTT Broker](screenshots/vm/mqtt.png)

---

### Media

#### 🎬 Jellyfin

Media server

**Features:** Video streaming, Live TV, Transcoding, Mobile apps

![Jellyfin](screenshots/vm/jellyfin.png)

#### 🎵 Lyrion Music

Music streaming server

**Features:** Music library, Playlists, Radio, Multi-room

![Lyrion Music](screenshots/vm/lyrion.png)

#### 📻 Web Radio

Internet radio streaming

**Features:** Radio stations, Recording, Schedule, Favorites

![Web Radio](screenshots/vm/webradio.png)

#### 📸 PhotoPrism

AI-powered photo management

**Features:** Face recognition, Auto-tagging, Search, Albums

![PhotoPrism](screenshots/vm/photoprism.png)

#### 📺 PeerTube

Federated video platform

**Features:** Video hosting, Federation, Live streaming, Comments

![PeerTube](screenshots/vm/peertube.png)

#### 🌊 Torrent

BitTorrent client

**Features:** Downloads, RSS, Remote control, Bandwidth limits

![Torrent](screenshots/vm/torrent.png)

#### 📰 Newsbin

Usenet/NNTP client

**Features:** NZB downloads, Auto-processing, Search, Categories

![Newsbin](screenshots/vm/newsbin.png)

---

### Monitoring

#### 📊 Netdata

Real-time system monitoring

**Features:** Metrics, Alerts, Charts, Plugins

![Netdata](screenshots/vm/netdata.png)

#### 🔬 Deep Packet Inspection

DPI with netifyd/nDPId

**Features:** Protocol detection, App identification, Flow analysis, Statistics

![Deep Packet Inspection](screenshots/vm/dpi.png)

#### 🔬 Netifyd DPI

Netifyd deep packet inspection

**Features:** Application detection, Protocol analysis, Flow stats, API

![Netifyd DPI](screenshots/vm/netifyd.png)

#### 🔬 nDPId

nDPI daemon for traffic analysis

**Features:** Protocol detection, Flow tracking, JSON API, Real-time

![nDPId](screenshots/vm/ndpid.png)

#### 📱 Device Intelligence

Asset discovery and fingerprinting

**Features:** ARP scanning, MAC vendor lookup, OS detection, Services

![Device Intelligence](screenshots/vm/device-intel.png)

#### 👁️ Watchdog

Service and container monitoring

**Features:** Health checks, Auto-restart, Alerts, Logs

![Watchdog](screenshots/vm/watchdog.png)

#### 🎬 Media Flow

Media traffic analytics

**Features:** Stream detection, Bandwidth usage, Protocol analysis, QoE

![Media Flow](screenshots/vm/mediaflow.png)

#### 👀 Glances

System monitoring dashboard

**Features:** CPU/Memory, Disk/Network, Docker, Web UI

![Glances](screenshots/vm/glances.png)

---

### Network

#### 🌐 Network Modes

Network topology configuration

**Features:** Router mode, Bridge mode, AP mode, VLAN

![Network Modes](screenshots/vm/netmodes.png)

#### 📊 QoS Manager

Quality of Service with HTB/VLAN

**Features:** Bandwidth control, VLAN policies, 802.1p PCP, Per-user limits

![QoS Manager](screenshots/vm/qos.png)

#### 📈 Traffic Shaping

TC/CAKE traffic shaping

**Features:** Per-interface QoS, CAKE algorithm, Statistics, Real-time graphs

![Traffic Shaping](screenshots/vm/traffic.png)

#### ⚡ HAProxy

Load balancer with TLS 1.3

**Features:** Backend management, Stats, ACLs, SSL termination, Health checks

![HAProxy](screenshots/vm/haproxy.png)

#### 🚀 CDN Cache

Content delivery cache

**Features:** Cache management, Purge, Statistics, Edge rules

![CDN Cache](screenshots/vm/cdn.png)

#### 🏗️ Virtual Hosts

Nginx virtual host management

**Features:** Site management, SSL certificates, Reverse proxy, Let's Encrypt

![Virtual Hosts](screenshots/vm/vhost.png)

#### 🛤️ Routing Manager

Static and policy-based routing

**Features:** Static routes, Policy routing, Multi-WAN, Failover

![Routing Manager](screenshots/vm/routes.png)

#### 🔧 Network Tweaks

Network kernel parameters tuning

**Features:** TCP tuning, Buffer sizes, Congestion control, Profiles

![Network Tweaks](screenshots/vm/nettweak.png)

#### 🔍 Network Diagnostics

Network troubleshooting tools

**Features:** Ping/Traceroute, DNS lookup, Port scan, Speed test

![Network Diagnostics](screenshots/vm/netdiag.png)

#### 📉 Network Anomaly

Network anomaly detection

**Features:** Traffic baselines, Anomaly alerts, ML detection, Visualization

![Network Anomaly](screenshots/vm/network-anomaly.png)

#### 📶 Modem Manager

3G/4G/5G modem management

**Features:** Connection status, Signal strength, SMS, Failover

![Modem Manager](screenshots/vm/modem.png)

---

### Privacy

#### 🧅 Tor Network

Tor anonymity and hidden services

**Features:** Circuits, Hidden services, Bridges, Transparent proxy

![Tor Network](screenshots/vm/tor.png)

#### 🌐 Exposure Settings

Unified exposure management

**Features:** Tor exposure, SSL certs, DNS records, Mesh access

![Exposure Settings](screenshots/vm/exposure.png)

#### 🔐 Zero-Knowledge Proofs

ZKP Hamiltonian authentication

**Features:** Proof generation, Verification, Key management, MirrorNet

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

#### 💬 SimpleX Chat

Privacy-focused messaging

**Features:** E2E encryption, No user IDs, Self-hosted, Groups

![SimpleX Chat](screenshots/vm/simplex.png)

#### 🔐 Secret Vault

Secrets and credentials management

**Features:** Encrypted storage, Access control, Rotation, Audit

![Secret Vault](screenshots/vm/vault.png)

---

### Publishing

#### 📰 Publishing Platform

Unified publishing dashboard

**Features:** Multi-platform, Scheduling, Analytics, Templates

![Publishing Platform](screenshots/vm/publish.png)

#### 💧 Droplet

File upload and publish

**Features:** File upload, Share links, Expiration, Password protection

![Droplet](screenshots/vm/droplet.png)

#### 📝 Metablogizer

Static site publisher with Tor

**Features:** Static sites, Tor publishing, Templates, Markdown

![Metablogizer](screenshots/vm/metablogizer.png)

#### ✏️ Hexo Blog

Static blog generator

**Features:** Markdown, Themes, Plugins, Deploy

![Hexo Blog](screenshots/vm/hexo.png)

#### 🐘 GoToSocial

ActivityPub social server

**Features:** Mastodon compatible, Federation, Media, Privacy

![GoToSocial](screenshots/vm/gotosocial.png)

#### 📡 CyberFeed

RSS/Atom feed aggregator

**Features:** Feed management, Categories, Search, Export

![CyberFeed](screenshots/vm/cyberfeed.png)

---

### Security

#### 🛡️ CrowdSec

Collaborative security engine with behavior analysis

**Features:** Decision management, Alerts, Bouncers, Collections, Community blocklists

![CrowdSec](screenshots/vm/crowdsec.png)

#### 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Features:** OWASP rules, Custom rules, CrowdSec integration, Request logging

![Web Application Firewall](screenshots/vm/waf.png)

#### 🔥 Vortex Firewall

nftables-based threat enforcement firewall

**Features:** IP blocklists, nftables sets, Threat feeds, Geo-blocking

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

#### 🔒 System Hardening

Kernel and system hardening for ANSSI CSPN compliance

**Features:** Sysctl hardening, Module blacklist, Security score, AppArmor

![System Hardening](screenshots/vm/hardening.png)

#### 🔍 MITM Proxy

Traffic inspection and WAF proxy with auto-ban

**Features:** Traffic inspection, Request logging, Auto-ban, SSL interception

![MITM Proxy](screenshots/vm/mitmproxy.png)

#### 🔐 Auth Guardian

Unified authentication management

**Features:** OAuth2, LDAP, 2FA/TOTP, Session management

![Auth Guardian](screenshots/vm/auth.png)

#### 🛡️ Network Access Control

Client guardian and NAC with quarantine

**Features:** Device control, MAC filtering, Quarantine, VLAN assignment

![Network Access Control](screenshots/vm/nac.png)

#### 🚫 IP Block Manager

IP and network blocking management

**Features:** IP blocklists, Network ranges, Temporary bans, Import/Export

![IP Block Manager](screenshots/vm/ipblock.png)

#### 🔐 MAC Guard

MAC address access control

**Features:** MAC whitelist/blacklist, Auto-discovery, Alerts, VLAN binding

![MAC Guard](screenshots/vm/mac-guard.png)

#### 📡 Traffic Interceptor

Network traffic interception and analysis

**Features:** Packet capture, Protocol analysis, Session tracking, Forensics

![Traffic Interceptor](screenshots/vm/interceptor.png)

#### 🍪 Cookie Manager

Cookie and session security management

**Features:** Cookie policies, Session security, SameSite enforcement, Audit

![Cookie Manager](screenshots/vm/cookies.png)

#### ⚠️ Threat Dashboard

Unified threat visualization

**Features:** Threat feeds, Attack timeline, Severity levels, Correlation

![Threat Dashboard](screenshots/vm/threats.png)

#### 🔬 Threat Analyst

AI-powered threat analysis

**Features:** ML detection, Behavioral analysis, IOC extraction, Reports

![Threat Analyst](screenshots/vm/threat-analyst.png)

#### 🔴 CVE Triage

CVE vulnerability tracking and triage

**Features:** CVE database, Affected packages, Risk scoring, Remediation

![CVE Triage](screenshots/vm/cve-triage.png)

#### 🛡️ Wazuh SIEM

Wazuh SIEM integration

**Features:** Log analysis, File integrity, Vulnerability detection, Compliance

![Wazuh SIEM](screenshots/vm/wazuh.png)

#### 🔒 OSSEC HIDS

OSSEC host-based intrusion detection

**Features:** Log analysis, Rootkit detection, File integrity, Active response

![OSSEC HIDS](screenshots/vm/ossec.png)

#### 🦞 OpenClaw Scanner

Network vulnerability scanner

**Features:** Port scanning, Service detection, Vulnerability checks, Reports

![OpenClaw Scanner](screenshots/vm/openclaw.png)

#### 🔌 IoT Guard

IoT device security monitoring

**Features:** Device fingerprinting, Anomaly detection, Isolation, Firmware checks

![IoT Guard](screenshots/vm/iot-guard.png)

---

### Services

#### 📦 Services Portal

C3Box services portal

**Features:** Service links, Status overview, Quick access, Categories

![Services Portal](screenshots/vm/c3box.png)

#### 🦊 Gitea

Git server (LXC)

**Features:** Repositories, Users, SSH/HTTP, LFS, Actions

![Gitea](screenshots/vm/gitea.png)

#### ☁️ Nextcloud

File sync (LXC)

**Features:** File sync, WebDAV, CalDAV, CardDAV, Talk

![Nextcloud](screenshots/vm/nextcloud.png)

---

### System

#### ⚙️ System Hub

System configuration and management

**Features:** Settings, Logs, Services, Updates

![System Hub](screenshots/vm/system.png)

#### 💾 Backup Manager

System and LXC backup

**Features:** Config backup, LXC snapshots, Restore, Scheduling

![Backup Manager](screenshots/vm/backup.png)

#### 📋 Config Advisor

Configuration recommendations

**Features:** Security audit, Best practices, Optimization, Reports

![Config Advisor](screenshots/vm/config-advisor.png)

#### 📊 Reporter

System reporting and analytics

**Features:** Reports, Scheduling, Export, Email

![Reporter](screenshots/vm/reporter.png)

#### 🪞 Mirror Manager

APT mirror management

**Features:** Mirror sync, Bandwidth, Scheduling, Cache

![Mirror Manager](screenshots/vm/mirror.png)

#### 📀 System Cloner

System image cloning

**Features:** Disk imaging, Clone to USB, Restore, Compression

![System Cloner](screenshots/vm/cloner.png)

#### 👁️ Eye Remote

Remote management interface

**Features:** USB gadget, Serial console, Boot media, Recovery

![Eye Remote](screenshots/vm/eye-remote.png)

#### 🖥️ RTTY Console

Remote terminal access

**Features:** Web terminal, SSH, File transfer, Recording

![RTTY Console](screenshots/vm/rtty.png)

---

### VPN

#### 🔗 WireGuard VPN

Modern VPN with kernel integration

**Features:** Peer management, QR codes, Traffic stats, Multi-tunnel

![WireGuard VPN](screenshots/vm/wireguard.png)

#### 🕸️ Mesh Network

Mesh networking with Yggdrasil

**Features:** Peer discovery, Routing, Encryption, IPv6 overlay

![Mesh Network](screenshots/vm/mesh.png)

#### 🔗 P2P Network

Peer-to-peer networking

**Features:** Direct connections, NAT traversal, Encryption, DHT

![P2P Network](screenshots/vm/p2p.png)

#### 🔗 MasterLink

SecuBox mesh federation

**Features:** Box discovery, Federation, Shared policies, Sync

![MasterLink](screenshots/vm/master-link.png)

---

