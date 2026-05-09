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

#### 🤖 LocalAI

OpenAI-compatible local API

**Features:** OpenAI API, Multiple models, Embeddings, Image generation

#### 🚪 AI Gateway

AI model API gateway

**Features:** Rate limiting, Load balancing, Caching, Logging

#### 💡 AI Insights

AI-powered security insights

**Features:** Anomaly detection, Recommendations, Predictions, Reports

#### 🧠 LocalRecall

Local RAG memory system

**Features:** Vector storage, Semantic search, Document indexing, API

#### 🔌 MCP Server

Model Context Protocol server

**Features:** Tool integration, Context management, Multi-model, API

---

### Access

#### 🔐 Login Portal

Authentication portal with JWT

**Features:** JWT auth, Sessions, Password recovery, Captive portal

#### 👥 User Management

Unified identity management

**Features:** User CRUD, Groups, Service provisioning, RBAC

#### 🪪 Identity Provider

SAML/OIDC identity provider

**Features:** SAML 2.0, OpenID Connect, Federation, SSO

---

### Apps

#### 🎨 Streamlit

Streamlit app platform

**Features:** App hosting, Deployment, Management, Logs

#### ⚡ StreamForge

Streamlit app development

**Features:** Templates, Code editor, Preview, Deploy

#### 📦 APT Repository

APT repository management

**Features:** Package management, GPG signing, Multi-distro, Uploads

---

### Communication

#### 💬 Matrix Server

Matrix/Synapse chat server

**Features:** E2E encryption, Federation, Bridges, Calls

#### 📹 Jitsi Meet

Video conferencing

**Features:** Video calls, Screen share, Recording, Lobby

#### 📞 VoIP Server

Asterisk/FreePBX VoIP

**Features:** Extensions, Trunks, IVR, Voicemail

#### 🔄 TURN Server

TURN/STUN relay server

**Features:** NAT traversal, WebRTC, TLS, Statistics

---

### DNS

#### 🌍 DNS Server

BIND DNS zone management

**Features:** Zone management, Records, DNSSEC, Reverse DNS

#### 🛡️ Vortex DNS

DNS firewall with RPZ blocklists

**Features:** Blocklists, RPZ, Threat feeds, DoH/DoT

#### 📡 Mesh DNS

Mesh network domain resolution

**Features:** mDNS/Avahi, Local DNS, Service discovery, Mesh integration

#### 🛡️ DNS Guard

DNS-based threat protection

**Features:** Malware blocking, Phishing protection, Analytics, Whitelist

#### 🌐 DNS Provider

External DNS provider integration

**Features:** Cloudflare, Route53, DigitalOcean, Dynamic DNS

#### 🚫 AdGuard

AdGuard Home DNS blocking

**Features:** Ad blocking, Tracking protection, Parental control, Statistics

---

### Dashboard

#### 🏠 SecuBox Hub

Central dashboard and control center

**Features:** System overview, Service monitoring, Quick actions, Metrics

#### 🛡️ Security Operations Center

SOC with world clock, threat map, tickets

**Features:** World clock, Threat map, Ticket system, P2P intel, Alerts

#### 📋 Migration Roadmap

OpenWRT to Debian migration tracking

**Features:** Progress tracking, Module status, Category view

#### 📈 System Metrics

Real-time system metrics dashboard

**Features:** CPU/Memory, Network stats, Disk I/O, Historical data

#### ⚙️ Admin Panel

System administration panel

**Features:** User management, System config, Logs, Diagnostics

---

### Email

#### 📧 Mail Server

Postfix/Dovecot mail server

**Features:** Domains, Mailboxes, DKIM, SpamAssassin, ClamAV

#### 💌 Webmail

Roundcube/SOGo webmail

**Features:** Web interface, Address book, Calendar, Mobile

#### 📤 SMTP Relay

SMTP relay and smarthost

**Features:** Relay, Authentication, Rate limiting, Logging

#### 💬 Jabber/XMPP

XMPP messaging server

**Features:** Chat, Groups, File transfer, Federation

---

### IoT

#### 🏠 Domoticz

Home automation

**Features:** Devices, Scenes, Scripts, History

#### 🏡 Home Assistant

Home automation hub

**Features:** Integrations, Automations, Dashboard, Voice

#### 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Features:** Device pairing, MQTT, Groups, OTA updates

#### 📡 MQTT Broker

Mosquitto MQTT broker

**Features:** Topics, ACL, TLS, WebSocket

---

### Media

#### 🎬 Jellyfin

Media server

**Features:** Video streaming, Live TV, Transcoding, Mobile apps

#### 🎵 Lyrion Music

Music streaming server

**Features:** Music library, Playlists, Radio, Multi-room

#### 📻 Web Radio

Internet radio streaming

**Features:** Radio stations, Recording, Schedule, Favorites

#### 📸 PhotoPrism

AI-powered photo management

**Features:** Face recognition, Auto-tagging, Search, Albums

#### 📺 PeerTube

Federated video platform

**Features:** Video hosting, Federation, Live streaming, Comments

#### 🌊 Torrent

BitTorrent client

**Features:** Downloads, RSS, Remote control, Bandwidth limits

#### 📰 Newsbin

Usenet/NNTP client

**Features:** NZB downloads, Auto-processing, Search, Categories

---

### Monitoring

#### 📊 Netdata

Real-time system monitoring

**Features:** Metrics, Alerts, Charts, Plugins

#### 🔬 Deep Packet Inspection

DPI with netifyd/nDPId

**Features:** Protocol detection, App identification, Flow analysis, Statistics

#### 🔬 Netifyd DPI

Netifyd deep packet inspection

**Features:** Application detection, Protocol analysis, Flow stats, API

#### 🔬 nDPId

nDPI daemon for traffic analysis

**Features:** Protocol detection, Flow tracking, JSON API, Real-time

#### 📱 Device Intelligence

Asset discovery and fingerprinting

**Features:** ARP scanning, MAC vendor lookup, OS detection, Services

#### 👁️ Watchdog

Service and container monitoring

**Features:** Health checks, Auto-restart, Alerts, Logs

#### 🎬 Media Flow

Media traffic analytics

**Features:** Stream detection, Bandwidth usage, Protocol analysis, QoE

#### 👀 Glances

System monitoring dashboard

**Features:** CPU/Memory, Disk/Network, Docker, Web UI

---

### Network

#### 🌐 Network Modes

Network topology configuration

**Features:** Router mode, Bridge mode, AP mode, VLAN

#### 📊 QoS Manager

Quality of Service with HTB/VLAN

**Features:** Bandwidth control, VLAN policies, 802.1p PCP, Per-user limits

#### 📈 Traffic Shaping

TC/CAKE traffic shaping

**Features:** Per-interface QoS, CAKE algorithm, Statistics, Real-time graphs

#### ⚡ HAProxy

Load balancer with TLS 1.3

**Features:** Backend management, Stats, ACLs, SSL termination, Health checks

#### 🚀 CDN Cache

Content delivery cache

**Features:** Cache management, Purge, Statistics, Edge rules

#### 🏗️ Virtual Hosts

Nginx virtual host management

**Features:** Site management, SSL certificates, Reverse proxy, Let's Encrypt

#### 🛤️ Routing Manager

Static and policy-based routing

**Features:** Static routes, Policy routing, Multi-WAN, Failover

#### 🔧 Network Tweaks

Network kernel parameters tuning

**Features:** TCP tuning, Buffer sizes, Congestion control, Profiles

#### 🔍 Network Diagnostics

Network troubleshooting tools

**Features:** Ping/Traceroute, DNS lookup, Port scan, Speed test

#### 📉 Network Anomaly

Network anomaly detection

**Features:** Traffic baselines, Anomaly alerts, ML detection, Visualization

#### 📶 Modem Manager

3G/4G/5G modem management

**Features:** Connection status, Signal strength, SMS, Failover

---

### Privacy

#### 🧅 Tor Network

Tor anonymity and hidden services

**Features:** Circuits, Hidden services, Bridges, Transparent proxy

#### 🌐 Exposure Settings

Unified exposure management

**Features:** Tor exposure, SSL certs, DNS records, Mesh access

#### 🔐 Zero-Knowledge Proofs

ZKP Hamiltonian authentication

**Features:** Proof generation, Verification, Key management, MirrorNet

#### 💬 SimpleX Chat

Privacy-focused messaging

**Features:** E2E encryption, No user IDs, Self-hosted, Groups

#### 🔐 Secret Vault

Secrets and credentials management

**Features:** Encrypted storage, Access control, Rotation, Audit

---

### Publishing

#### 📰 Publishing Platform

Unified publishing dashboard

**Features:** Multi-platform, Scheduling, Analytics, Templates

#### 💧 Droplet

File upload and publish

**Features:** File upload, Share links, Expiration, Password protection

#### 📝 Metablogizer

Static site publisher with Tor

**Features:** Static sites, Tor publishing, Templates, Markdown

#### ✏️ Hexo Blog

Static blog generator

**Features:** Markdown, Themes, Plugins, Deploy

#### 🐘 GoToSocial

ActivityPub social server

**Features:** Mastodon compatible, Federation, Media, Privacy

#### 📡 CyberFeed

RSS/Atom feed aggregator

**Features:** Feed management, Categories, Search, Export

---

### Security

#### 🛡️ CrowdSec

Collaborative security engine with behavior analysis

**Features:** Decision management, Alerts, Bouncers, Collections, Community blocklists

#### 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Features:** OWASP rules, Custom rules, CrowdSec integration, Request logging

#### 🔥 Vortex Firewall

nftables-based threat enforcement firewall

**Features:** IP blocklists, nftables sets, Threat feeds, Geo-blocking

#### 🔒 System Hardening

Kernel and system hardening for ANSSI CSPN compliance

**Features:** Sysctl hardening, Module blacklist, Security score, AppArmor

#### 🔍 MITM Proxy

Traffic inspection and WAF proxy with auto-ban

**Features:** Traffic inspection, Request logging, Auto-ban, SSL interception

#### 🔐 Auth Guardian

Unified authentication management

**Features:** OAuth2, LDAP, 2FA/TOTP, Session management

#### 🛡️ Network Access Control

Client guardian and NAC with quarantine

**Features:** Device control, MAC filtering, Quarantine, VLAN assignment

#### 🚫 IP Block Manager

IP and network blocking management

**Features:** IP blocklists, Network ranges, Temporary bans, Import/Export

#### 🔐 MAC Guard

MAC address access control

**Features:** MAC whitelist/blacklist, Auto-discovery, Alerts, VLAN binding

#### 📡 Traffic Interceptor

Network traffic interception and analysis

**Features:** Packet capture, Protocol analysis, Session tracking, Forensics

#### 🍪 Cookie Manager

Cookie and session security management

**Features:** Cookie policies, Session security, SameSite enforcement, Audit

#### ⚠️ Threat Dashboard

Unified threat visualization

**Features:** Threat feeds, Attack timeline, Severity levels, Correlation

#### 🔬 Threat Analyst

AI-powered threat analysis

**Features:** ML detection, Behavioral analysis, IOC extraction, Reports

#### 🔴 CVE Triage

CVE vulnerability tracking and triage

**Features:** CVE database, Affected packages, Risk scoring, Remediation

#### 🛡️ Wazuh SIEM

Wazuh SIEM integration

**Features:** Log analysis, File integrity, Vulnerability detection, Compliance

#### 🔒 OSSEC HIDS

OSSEC host-based intrusion detection

**Features:** Log analysis, Rootkit detection, File integrity, Active response

#### 🦞 OpenClaw Scanner

Network vulnerability scanner

**Features:** Port scanning, Service detection, Vulnerability checks, Reports

#### 🔌 IoT Guard

IoT device security monitoring

**Features:** Device fingerprinting, Anomaly detection, Isolation, Firmware checks

---

### Services

#### 📦 Services Portal

C3Box services portal

**Features:** Service links, Status overview, Quick access, Categories

#### 🦊 Gitea

Git server (LXC)

**Features:** Repositories, Users, SSH/HTTP, LFS, Actions

#### ☁️ Nextcloud

File sync (LXC)

**Features:** File sync, WebDAV, CalDAV, CardDAV, Talk

---

### System

#### ⚙️ System Hub

System configuration and management

**Features:** Settings, Logs, Services, Updates

#### 💾 Backup Manager

System and LXC backup

**Features:** Config backup, LXC snapshots, Restore, Scheduling

#### 📋 Config Advisor

Configuration recommendations

**Features:** Security audit, Best practices, Optimization, Reports

#### 📊 Reporter

System reporting and analytics

**Features:** Reports, Scheduling, Export, Email

#### 🪞 Mirror Manager

APT mirror management

**Features:** Mirror sync, Bandwidth, Scheduling, Cache

#### 📀 System Cloner

System image cloning

**Features:** Disk imaging, Clone to USB, Restore, Compression

#### 👁️ Eye Remote

Remote management interface

**Features:** USB gadget, Serial console, Boot media, Recovery

#### 🖥️ RTTY Console

Remote terminal access

**Features:** Web terminal, SSH, File transfer, Recording

---

### VPN

#### 🔗 WireGuard VPN

Modern VPN with kernel integration

**Features:** Peer management, QR codes, Traffic stats, Multi-tunnel

#### 🕸️ Mesh Network

Mesh networking with Yggdrasil

**Features:** Peer discovery, Routing, Encryption, IPv6 overlay

#### 🔗 P2P Network

Peer-to-peer networking

**Features:** Direct connections, NAT traversal, Encryption, DHT

#### 🔗 MasterLink

SecuBox mesh federation

**Features:** Box discovery, Federation, Shared policies, Sync

---

