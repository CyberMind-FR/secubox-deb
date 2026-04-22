# SecuBox Modules

*Complete module documentation*

**Total modules:** 124

[🇬🇧 English](MODULES-EN.md) | [🇫🇷 Français](MODULES-FR.md) | [🇩🇪 Deutsch](MODULES-DE.md) | [🇨🇳 中文](MODULES-ZH.md)

---

## Overview

| Modules | Category | Description |
|--------|----------|-------------|
| 🏠 **SecuBox Hub** | Dashboard | Central dashboard and control center |
| 🛡️ **Security Operations Center** | Dashboard | SOC with world clock, threat map, tickets |
| 📋 **Migration Roadmap** | Dashboard | OpenWRT to Debian migration tracking |
| 🛡️ **CrowdSec** | Security | Collaborative security engine |
| 🔥 **Web Application Firewall** | Security | WAF with 300+ security rules |
| 🔥 **Vortex Firewall** | Security | nftables threat enforcement |
| 🔒 **System Hardening** | Security | Kernel and system hardening |
| 🔍 **MITM Proxy** | Security | Traffic inspection and WAF proxy |
| 🔐 **Auth Guardian** | Security | Authentication management |
| 🛡️ **Network Access Control** | Security | Client guardian and NAC |
| 🌐 **Network Modes** | Network | Network topology configuration |
| 📊 **QoS Manager** | Network | Quality of Service with HTB/VLAN |
| 📈 **Traffic Shaping** | Network | TC/CAKE traffic shaping |
| ⚡ **HAProxy** | Network | Load balancer dashboard |
| 🚀 **CDN Cache** | Network | Content delivery cache |
| 🏗️ **Virtual Hosts** | Network | Nginx virtual host management |
| 🌍 **DNS Server** | DNS | BIND DNS zone management |
| 🛡️ **Vortex DNS** | DNS | DNS firewall with RPZ |
| 📡 **Mesh DNS** | DNS | Mesh network domain resolution |
| 🔗 **WireGuard VPN** | VPN | Modern VPN management |
| 🕸️ **Mesh Network** | VPN | Mesh networking (Yggdrasil) |
| 🔗 **P2P Network** | VPN | Peer-to-peer networking |
| 🧅 **Tor Network** | Privacy | Tor anonymity and hidden services |
| 🌐 **Exposure Settings** | Privacy | Unified exposure (Tor, SSL, DNS, Mesh) |
| 🔐 **Zero-Knowledge Proofs** | Privacy | ZKP Hamiltonian management |
| 📊 **Netdata** | Monitoring | Real-time system monitoring |
| 🔬 **Deep Packet Inspection** | Monitoring | DPI with netifyd |
| 📱 **Device Intelligence** | Monitoring | Asset discovery and fingerprinting |
| 👁️ **Watchdog** | Monitoring | Service and container monitoring |
| 🎬 **Media Flow** | Monitoring | Media traffic analytics |
| 📊 **Metrics Dashboard** | Monitoring | Real-time system metrics |
| 🔐 **Login Portal** | Access | Authentication portal with JWT |
| 👥 **User Management** | Access | Unified identity management |
| 📦 **Services Portal** | Services | C3Box services portal |
| 🦊 **Gitea** | Services | Git server (LXC) |
| ☁️ **Nextcloud** | Services | File sync (LXC) |
| 📧 **Mail Server** | Email | Postfix/Dovecot mail server |
| 💌 **Webmail** | Email | Roundcube/SOGo webmail |
| 📰 **Publishing Platform** | Publishing | Unified publishing dashboard |
| 💧 **Droplet** | Publishing | File upload and publish |
| 📝 **Metablogizer** | Publishing | Static site publisher with Tor |
| 🎨 **Streamlit** | Apps | Streamlit app platform |
| ⚡ **StreamForge** | Apps | Streamlit app development |
| 📦 **APT Repository** | Apps | APT repository management |
| ⚙️ **System Hub** | System | System configuration and management |
| 💾 **Backup Manager** | System | System and LXC backup |

---

## Modules

### 🏠 SecuBox Hub

**Category:** Dashboard

Central dashboard and control center

**Features:**
- System overview
- Service monitoring
- Quick actions
- Metrics

![SecuBox Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hub.png)

---

### 🛡️ Security Operations Center

**Category:** Dashboard

SOC with world clock, threat map, tickets

**Features:**
- World clock
- Threat map
- Ticket system
- P2P intel
- Alerts

![Security Operations Center](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/soc.png)

---

### 📋 Migration Roadmap

**Category:** Dashboard

OpenWRT to Debian migration tracking

**Features:**
- Progress tracking
- Module status
- Category view

![Migration Roadmap](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/roadmap.png)

---

### 🛡️ CrowdSec

**Category:** Security

Collaborative security engine

**Features:**
- Decision management
- Alerts
- Bouncers
- Collections

![CrowdSec](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/crowdsec.png)

---

### 🔥 Web Application Firewall

**Category:** Security

WAF with 300+ security rules

**Features:**
- OWASP rules
- Custom rules
- CrowdSec integration

![Web Application Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/waf.png)

---

### 🔥 Vortex Firewall

**Category:** Security

nftables threat enforcement

**Features:**
- IP blocklists
- nftables sets
- Threat feeds

![Vortex Firewall](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-firewall.png)

---

### 🔒 System Hardening

**Category:** Security

Kernel and system hardening

**Features:**
- Sysctl hardening
- Module blacklist
- Security score

![System Hardening](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/hardening.png)

---

### 🔍 MITM Proxy

**Category:** Security

Traffic inspection and WAF proxy

**Features:**
- Traffic inspection
- Request logging
- Auto-ban

![MITM Proxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mitmproxy.png)

---

### 🔐 Auth Guardian

**Category:** Security

Authentication management

**Features:**
- OAuth2
- LDAP
- 2FA
- Session management

![Auth Guardian](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/auth.png)

---

### 🛡️ Network Access Control

**Category:** Security

Client guardian and NAC

**Features:**
- Device control
- MAC filtering
- Quarantine

![Network Access Control](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nac.png)

---

### 🌐 Network Modes

**Category:** Network

Network topology configuration

**Features:**
- Router mode
- Bridge mode
- AP mode
- VLAN

![Network Modes](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netmodes.png)

---

### 📊 QoS Manager

**Category:** Network

Quality of Service with HTB/VLAN

**Features:**
- Bandwidth control
- VLAN policies
- 802.1p PCP

![QoS Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/qos.png)

---

### 📈 Traffic Shaping

**Category:** Network

TC/CAKE traffic shaping

**Features:**
- Per-interface QoS
- CAKE algorithm
- Statistics

![Traffic Shaping](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/traffic.png)

---

### ⚡ HAProxy

**Category:** Network

Load balancer dashboard

**Features:**
- Backend management
- Stats
- ACLs
- SSL termination

![HAProxy](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/haproxy.png)

---

### 🚀 CDN Cache

**Category:** Network

Content delivery cache

**Features:**
- Cache management
- Purge
- Statistics

![CDN Cache](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/cdn.png)

---

### 🏗️ Virtual Hosts

**Category:** Network

Nginx virtual host management

**Features:**
- Site management
- SSL certificates
- Reverse proxy

![Virtual Hosts](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vhost.png)

---

### 🌍 DNS Server

**Category:** DNS

BIND DNS zone management

**Features:**
- Zone management
- Records
- DNSSEC

![DNS Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dns.png)

---

### 🛡️ Vortex DNS

**Category:** DNS

DNS firewall with RPZ

**Features:**
- Blocklists
- RPZ
- Threat feeds

![Vortex DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/vortex-dns.png)

---

### 📡 Mesh DNS

**Category:** DNS

Mesh network domain resolution

**Features:**
- mDNS/Avahi
- Local DNS
- Service discovery

![Mesh DNS](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/meshname.png)

---

### 🔗 WireGuard VPN

**Category:** VPN

Modern VPN management

**Features:**
- Peer management
- QR codes
- Traffic stats

![WireGuard VPN](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/wireguard.png)

---

### 🕸️ Mesh Network

**Category:** VPN

Mesh networking (Yggdrasil)

**Features:**
- Peer discovery
- Routing
- Encryption

![Mesh Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mesh.png)

---

### 🔗 P2P Network

**Category:** VPN

Peer-to-peer networking

**Features:**
- Direct connections
- NAT traversal
- Encryption

![P2P Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/p2p.png)

---

### 🧅 Tor Network

**Category:** Privacy

Tor anonymity and hidden services

**Features:**
- Circuits
- Hidden services
- Bridges

![Tor Network](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/tor.png)

---

### 🌐 Exposure Settings

**Category:** Privacy

Unified exposure (Tor, SSL, DNS, Mesh)

**Features:**
- Tor exposure
- SSL certs
- DNS records
- Mesh access

![Exposure Settings](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/exposure.png)

---

### 🔐 Zero-Knowledge Proofs

**Category:** Privacy

ZKP Hamiltonian management

**Features:**
- Proof generation
- Verification
- Key management

![Zero-Knowledge Proofs](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/zkp.png)

---

### 📊 Netdata

**Category:** Monitoring

Real-time system monitoring

**Features:**
- Metrics
- Alerts
- Charts
- Plugins

![Netdata](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/netdata.png)

---

### 🔬 Deep Packet Inspection

**Category:** Monitoring

DPI with netifyd

**Features:**
- Protocol detection
- App identification
- Flow analysis

![Deep Packet Inspection](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/dpi.png)

---

### 📱 Device Intelligence

**Category:** Monitoring

Asset discovery and fingerprinting

**Features:**
- ARP scanning
- MAC vendor lookup
- OS detection

![Device Intelligence](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/device-intel.png)

---

### 👁️ Watchdog

**Category:** Monitoring

Service and container monitoring

**Features:**
- Health checks
- Auto-restart
- Alerts

![Watchdog](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/watchdog.png)

---

### 🎬 Media Flow

**Category:** Monitoring

Media traffic analytics

**Features:**
- Stream detection
- Bandwidth usage
- Protocol analysis

![Media Flow](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mediaflow.png)

---

### 📊 Metrics Dashboard

**Category:** Monitoring

Real-time system metrics dashboard

**Features:**
- System overview
- Service status
- WAF/CrowdSec stats
- Connection monitoring
- Live updates

![Metrics Dashboard](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metrics.png)

---

### 🔐 Login Portal

**Category:** Access

Authentication portal with JWT

**Features:**
- JWT auth
- Sessions
- Password recovery

![Login Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/portal.png)

---

### 👥 User Management

**Category:** Access

Unified identity management

**Features:**
- User CRUD
- Groups
- Service provisioning

![User Management](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/users.png)

---

### 📦 Services Portal

**Category:** Services

C3Box services portal

**Features:**
- Service links
- Status overview
- Quick access

![Services Portal](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/c3box.png)

---

### 🦊 Gitea

**Category:** Services

Git server (LXC)

**Features:**
- Repositories
- Users
- SSH/HTTP
- LFS

![Gitea](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/gitea.png)

---

### ☁️ Nextcloud

**Category:** Services

File sync (LXC)

**Features:**
- File sync
- WebDAV
- CalDAV
- CardDAV

![Nextcloud](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/nextcloud.png)

---

### 📧 Mail Server

**Category:** Email

Postfix/Dovecot mail server

**Features:**
- Domains
- Mailboxes
- DKIM
- SpamAssassin
- ClamAV

![Mail Server](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/mail.png)

---

### 💌 Webmail

**Category:** Email

Roundcube/SOGo webmail

**Features:**
- Web interface
- Address book
- Calendar

![Webmail](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/webmail.png)

---

### 📰 Publishing Platform

**Category:** Publishing

Unified publishing dashboard

**Features:**
- Multi-platform
- Scheduling
- Analytics

![Publishing Platform](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/publish.png)

---

### 💧 Droplet

**Category:** Publishing

File upload and publish

**Features:**
- File upload
- Share links
- Expiration

![Droplet](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/droplet.png)

---

### 📝 Metablogizer

**Category:** Publishing

Static site publisher with Tor

**Features:**
- Static sites
- Tor publishing
- Templates

![Metablogizer](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/metablogizer.png)

---

### 🎨 Streamlit

**Category:** Apps

Streamlit app platform

**Features:**
- App hosting
- Deployment
- Management

![Streamlit](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamlit.png)

---

### ⚡ StreamForge

**Category:** Apps

Streamlit app development

**Features:**
- Templates
- Code editor
- Preview

![StreamForge](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/streamforge.png)

---

### 📦 APT Repository

**Category:** Apps

APT repository management

**Features:**
- Package management
- GPG signing
- Multi-distro

![APT Repository](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/repo.png)

---

### ⚙️ System Hub

**Category:** System

System configuration and management

**Features:**
- Settings
- Logs
- Services
- Updates

![System Hub](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/system.png)

---

### 💾 Backup Manager

**Category:** System

System and LXC backup

**Features:**
- Config backup
- LXC snapshots
- Restore

![Backup Manager](https://raw.githubusercontent.com/CyberMind-FR/secubox-deb/master/docs/screenshots/vm/backup.png)

---

### 🚫 Ad Guard

**Category:** Security

Ad and tracker detection with per-device statistics

**Features:**
- Blocklist management
- Delayed blacklisting workflow
- Device-type classification
- Per-device statistics

---

### 🖥️ System Administration

**Category:** System

Advanced system administration dashboard

**Features:**
- System status overview
- Systemd service management
- System logs viewer
- APT updates management

---

### 🤖 AI Gateway

**Category:** AI

AI Data Sovereignty Gateway

**Features:**
- Data sovereignty controls
- AI traffic routing
- Privacy-preserving AI access

---

### 🧠 AI Insights

**Category:** AI

ML-based threat detection and security insights

**Features:**
- ML-based threat detection
- Anomaly detection
- Log analysis with trained models
- CrowdSec and Suricata integration

---

### 🎭 Avatar Manager

**Category:** Access

Identity and avatar management

**Features:**
- Avatar upload
- Identity sync across services
- Service integration

---

### 💾 System Cloner

**Category:** System

System backup and restore

**Features:**
- Compressed backup creation
- Backup management
- System restore

---

### 🔧 Config Advisor

**Category:** Security

Security configuration advisor

**Features:**
- Security configuration analysis
- Best practices recommendations
- Configuration scoring

---

### 🖥️ Console TUI

**Category:** System

Terminal-based dashboard

**Features:**
- Live system metrics
- Service management
- Network interface status
- Real-time log viewer

---

### 🍪 Cookie Tracker

**Category:** Privacy

Cookie tracking and privacy compliance

**Features:**
- Third-party cookie detection
- Tracker identification
- GDPR compliance checking

---

### 🔐 CVE Triage

**Category:** Security

CVE vulnerability triage

**Features:**
- Vulnerability assessment
- CVE tracking
- Risk prioritization

---

### 📡 CyberFeed

**Category:** Security

Threat intelligence feed aggregator

**Features:**
- Multi-source threat feed aggregation
- IP and domain blocklist management
- Export to nftables, unbound, dnsmasq

---

### 🛡️ DNS Guard

**Category:** DNS

DNS anomaly detection

**Features:**
- DNS traffic analysis
- Anomaly detection
- Threat alerting

---

### 🌐 DNS Provider

**Category:** DNS

Multi-provider DNS API management

**Features:**
- OVH, Gandi, Cloudflare, AWS Route53 support
- ACME DNS-01 challenge support
- Dynamic DNS

---

### 🏠 Domoticz

**Category:** Automation

Home automation management

**Features:**
- Device management
- Room/scene organization
- Z-Wave, Zigbee, 433MHz support

---

### 📊 Glances

**Category:** Monitoring

System monitoring with Glances

**Features:**
- Real-time CPU, memory, disk, network stats
- Hardware sensors
- Process list

---

### 🦣 GoToSocial

**Category:** Communication

ActivityPub/Fediverse server

**Features:**
- Account management
- Federation controls
- Moderation tools

---

### 📝 Hexo

**Category:** Publishing

Static blog generator

**Features:**
- Multiple blog management
- Theme gallery
- Plugin management

---

### 🏡 Home Assistant

**Category:** Automation

IoT hub integration

**Features:**
- Entity and device browser
- Automation management
- HACS integration

---

### 🆔 Identity

**Category:** Privacy

Decentralized identity

**Features:**
- Decentralized identity management
- Identity verification
- Privacy-preserving auth

---

### 🔍 Interceptor

**Category:** Security

HTTP/HTTPS traffic interception

**Features:**
- SSL/TLS inspection
- Request/response modification
- Traffic recording

---

### 📱 IoT Guard

**Category:** Security

IoT device security

**Features:**
- IoT device monitoring
- Security policy enforcement
- Threat detection

---

### 🚫 IP Block

**Category:** Security

IP blocklist manager

**Features:**
- Multiple blocklist sources
- nftables set integration
- Auto-update scheduling

---

### 💬 Jabber/XMPP

**Category:** Communication

Prosody XMPP server

**Features:**
- User accounts
- Virtual hosts
- Federation

---

### 🎬 Jellyfin

**Category:** Media

Media server management

**Features:**
- Library configuration
- Hardware acceleration
- Backup/restore

---

### 🎥 Jitsi Meet

**Category:** Communication

Video conferencing

**Features:**
- JWT, LDAP authentication
- Recording and streaming
- Breakout rooms

---

### 💾 KSM

**Category:** System

Kernel Same-page Merging

**Features:**
- Enable/disable KSM
- Memory savings statistics
- Configuration tuning

---

### 🤖 LocalAI

**Category:** AI

Self-hosted LLM inference

**Features:**
- OpenAI-compatible API
- Model gallery
- Chat interface

---

### 🧠 LocalRecall

**Category:** AI

AI memory system

**Features:**
- AI context storage
- Memory retrieval
- Context management

---

### 🎵 Lyrion Music Server

**Category:** Media

Lyrion Music Server for Squeezebox

**Features:**
- Squeezebox player control
- Library management
- Backup and restore

---

### 🔒 MAC Guard

**Category:** Security

MAC address-based network access control

**Features:**
- MAC address whitelist/blacklist
- Device discovery
- Alert on unknown devices

---

### 🪞 MagicMirror

**Category:** Apps

Smart display platform

**Features:**
- MagicMirror configuration
- Module management
- Display controls

---

### 📬 Mail LXC

**Category:** Email

Mail server LXC container

**Features:**
- Postfix MTA
- Dovecot IMAP/POP3
- OpenDKIM signing

---

### 🔗 Master Link

**Category:** Network

Mesh node enrollment

**Features:**
- Node enrollment
- Mesh link management
- Topology coordination

---

### 💬 Matrix Synapse

**Category:** Communication

Federated chat server

**Features:**
- User and room management
- Bridge support
- Federation

---

### 🤖 MCP Server

**Category:** AI

Model Context Protocol server

**Features:**
- AI context protocol support
- Model communication
- Context sharing

---

### 📋 Metabolizer

**Category:** Monitoring

Log processor and analyzer

**Features:**
- Journalctl log analysis
- Pattern extraction
- Error trend analysis

---

### 📚 Metacatalog

**Category:** Services

Service catalog and registry

**Features:**
- Service health status
- Dependency mapping
- API endpoint documentation

---

### 🪞 Mirror/CDN

**Category:** Network

Local mirror and CDN caching

**Features:**
- Nginx caching proxy
- Cache statistics
- Bandwidth optimization

---

### 📦 MMPM

**Category:** Apps

MagicMirror Package Manager

**Features:**
- Browse MagicMirror modules
- Install/update/remove modules

---

### 📡 MQTT

**Category:** Automation

Mosquitto MQTT broker

**Features:**
- Client connection tracking
- Topic monitoring
- User and ACL management

---

### 🔬 nDPId

**Category:** Monitoring

Deep Packet Inspection with nDPI

**Features:**
- JA3/JA4 TLS fingerprinting
- Protocol detection
- Risk scoring

---

### 🔧 Network Diagnostics

**Category:** Network

Network troubleshooting tools

**Features:**
- Ping, traceroute, DNS lookup
- WHOIS, MTR
- Port scanning, bandwidth testing

---

### ⚙️ Network Tuning

**Category:** Network

Sysctl and TCP/IP optimization

**Features:**
- Tuning profiles
- TCP settings
- Persistent configuration

---

### 🔍 Network Anomaly

**Category:** Security

Network anomaly detection

**Features:**
- Traffic analysis
- Anomaly detection
- Alert generation

---

### 📰 Newsbin

**Category:** Apps

Usenet downloader (SABnzbd)

**Features:**
- NZB file handling
- Download queue
- Category organization

---

### 🦙 Ollama

**Category:** AI

Local LLM inference

**Features:**
- Model pulling
- Chat completion
- Text generation APIs

---

### 🕵️ OpenClaw OSINT

**Category:** Security

Open Source Intelligence

**Features:**
- Domain reconnaissance
- IP intelligence
- Subdomain discovery

---

### 🛡️ OSSEC HIDS

**Category:** Security

Host-based Intrusion Detection

**Features:**
- Alert viewing
- File integrity monitoring
- Rootkit detection

---

### 📹 PeerTube

**Category:** Media

Federated video platform

**Features:**
- Video and channel management
- Federation (ActivityPub)
- Plugin management

---

### 📸 PhotoPrism

**Category:** Media

AI-powered photo management

**Features:**
- AI-powered face recognition
- Photo library indexing
- Album management

---

### 🍺 PicoBrew

**Category:** Automation

Homebrew/fermentation controller

**Features:**
- Temperature monitoring
- Fermentation profiles
- Recipe management

---

### 📱 Redroid

**Category:** Apps

Android in container

**Features:**
- Android container management
- ADB access
- App installation

---

### 📊 Reporter

**Category:** System

System report generation

**Features:**
- PDF/HTML reports
- Scheduled generation
- Security reports

---

### 📦 RezApp

**Category:** Apps

Application deployment

**Features:**
- Application templates
- Docker/LXC deployment
- Health monitoring

---

### 🛣️ Routes

**Category:** Network

Routing table manager

**Features:**
- View IPv4/IPv6 routes
- Add/delete routes
- Policy routing rules

---

### 🖥️ RTTY

**Category:** System

Remote terminal access

**Features:**
- Terminal sessions
- Access token management
- Web interface

---

### 🔌 SaaS Relay

**Category:** Services

Secure API proxy relay

**Features:**
- Proxy configuration
- API key management
- Rate limiting

---

### 🔐 SimpleX Chat

**Category:** Communication

Privacy-focused messaging

**Features:**
- Zero-knowledge messaging
- No user identifiers
- TLS certificate management

---

### 📧 SMTP Relay

**Category:** Email

Email forwarding

**Features:**
- Queue management
- Smarthost configuration
- Monitoring

---

### 🛡️ SOC Agent

**Category:** Security

Edge node agent

**Features:**
- Metrics collection
- Alert aggregation
- Remote command execution

---

### 🏢 SOC Gateway

**Category:** Security

Central fleet monitoring hub

**Features:**
- Node registration
- Fleet-wide metrics
- Threat correlation

---

### 🌐 SOC Web

**Category:** Dashboard

Fleet monitoring dashboard

**Features:**
- Fleet overview
- Real-time alerts
- Threat visualization

---

### 🤖 Threat Analyst

**Category:** AI

AI threat analysis

**Features:**
- AI-powered analysis
- Automated assessment
- Intelligence correlation

---

### ⚠️ Threats Dashboard

**Category:** Security

Unified security threats

**Features:**
- Aggregated alerts
- Threat intelligence
- Incident tracking

---

### 📥 Torrent

**Category:** Apps

BitTorrent client (Transmission)

**Features:**
- Magnet links, URLs, files
- Speed limiting
- RSS feed subscriptions

---

### 📞 TURN/STUN Server

**Category:** Communication

WebRTC relay server

**Features:**
- coturn service
- User management
- Temporary credentials

---

### 🔐 Vault

**Category:** Security

Encrypted secrets management

**Features:**
- Secure storage
- Audit logging
- Rotation support

---

### 💻 VM Manager

**Category:** System

Virtual machine management

**Features:**
- KVM/QEMU VMs
- LXC containers
- Resource management

---

### 📞 VoIP/PBX

**Category:** Communication

Asterisk/FreePBX management

**Features:**
- Extension management
- SIP trunks
- Call detail records

---

### 🛡️ Wazuh SIEM

**Category:** Security

Wazuh SIEM integration

**Features:**
- Agent/manager management
- Alert viewing
- Security monitoring

---

### 📬 Webmail LXC

**Category:** Email

Roundcube webmail container

**Features:**
- Roundcube webmail
- Nginx + PHP-FPM
- Auto-configuration

---

### 📻 Web Radio

**Category:** Media

Internet radio streaming

**Features:**
- Station management
- Icecast/Liquidsoap server
- Recording functionality

---

### 📡 Zigbee

**Category:** Automation

Zigbee2MQTT gateway

**Features:**
- Device pairing
- MQTT integration
- Network topology

---

