# SecuBox Modules

*Complete module documentation*

**Total modules:** 47

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

![SecuBox Hub](screenshots/vm/hub.png)

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

![Security Operations Center](screenshots/vm/soc.png)

---

### 📋 Migration Roadmap

**Category:** Dashboard

OpenWRT to Debian migration tracking

**Features:**
- Progress tracking
- Module status
- Category view

![Migration Roadmap](screenshots/vm/roadmap.png)

---

### 🛡️ CrowdSec

**Category:** Security

Collaborative security engine

**Features:**
- Decision management
- Alerts
- Bouncers
- Collections

![CrowdSec](screenshots/vm/crowdsec.png)

---

### 🔥 Web Application Firewall

**Category:** Security

WAF with 300+ security rules

**Features:**
- OWASP rules
- Custom rules
- CrowdSec integration

![Web Application Firewall](screenshots/vm/waf.png)

---

### 🔥 Vortex Firewall

**Category:** Security

nftables threat enforcement

**Features:**
- IP blocklists
- nftables sets
- Threat feeds

![Vortex Firewall](screenshots/vm/vortex-firewall.png)

---

### 🔒 System Hardening

**Category:** Security

Kernel and system hardening

**Features:**
- Sysctl hardening
- Module blacklist
- Security score

![System Hardening](screenshots/vm/hardening.png)

---

### 🔍 MITM Proxy

**Category:** Security

Traffic inspection and WAF proxy

**Features:**
- Traffic inspection
- Request logging
- Auto-ban

![MITM Proxy](screenshots/vm/mitmproxy.png)

---

### 🔐 Auth Guardian

**Category:** Security

Authentication management

**Features:**
- OAuth2
- LDAP
- 2FA
- Session management

![Auth Guardian](screenshots/vm/auth.png)

---

### 🛡️ Network Access Control

**Category:** Security

Client guardian and NAC

**Features:**
- Device control
- MAC filtering
- Quarantine

![Network Access Control](screenshots/vm/nac.png)

---

### 🌐 Network Modes

**Category:** Network

Network topology configuration

**Features:**
- Router mode
- Bridge mode
- AP mode
- VLAN

![Network Modes](screenshots/vm/netmodes.png)

---

### 📊 QoS Manager

**Category:** Network

Quality of Service with HTB/VLAN

**Features:**
- Bandwidth control
- VLAN policies
- 802.1p PCP

![QoS Manager](screenshots/vm/qos.png)

---

### 📈 Traffic Shaping

**Category:** Network

TC/CAKE traffic shaping

**Features:**
- Per-interface QoS
- CAKE algorithm
- Statistics

![Traffic Shaping](screenshots/vm/traffic.png)

---

### ⚡ HAProxy

**Category:** Network

Load balancer dashboard

**Features:**
- Backend management
- Stats
- ACLs
- SSL termination

![HAProxy](screenshots/vm/haproxy.png)

---

### 🚀 CDN Cache

**Category:** Network

Content delivery cache

**Features:**
- Cache management
- Purge
- Statistics

![CDN Cache](screenshots/vm/cdn.png)

---

### 🏗️ Virtual Hosts

**Category:** Network

Nginx virtual host management

**Features:**
- Site management
- SSL certificates
- Reverse proxy

![Virtual Hosts](screenshots/vm/vhost.png)

---

### 🌍 DNS Server

**Category:** DNS

BIND DNS zone management

**Features:**
- Zone management
- Records
- DNSSEC

![DNS Server](screenshots/vm/dns.png)

---

### 🛡️ Vortex DNS

**Category:** DNS

DNS firewall with RPZ

**Features:**
- Blocklists
- RPZ
- Threat feeds

![Vortex DNS](screenshots/vm/vortex-dns.png)

---

### 📡 Mesh DNS

**Category:** DNS

Mesh network domain resolution

**Features:**
- mDNS/Avahi
- Local DNS
- Service discovery

![Mesh DNS](screenshots/vm/meshname.png)

---

### 🔗 WireGuard VPN

**Category:** VPN

Modern VPN management

**Features:**
- Peer management
- QR codes
- Traffic stats

![WireGuard VPN](screenshots/vm/wireguard.png)

---

### 🕸️ Mesh Network

**Category:** VPN

Mesh networking (Yggdrasil)

**Features:**
- Peer discovery
- Routing
- Encryption

![Mesh Network](screenshots/vm/mesh.png)

---

### 🔗 P2P Network

**Category:** VPN

Peer-to-peer networking

**Features:**
- Direct connections
- NAT traversal
- Encryption

![P2P Network](screenshots/vm/p2p.png)

---

### 🧅 Tor Network

**Category:** Privacy

Tor anonymity and hidden services

**Features:**
- Circuits
- Hidden services
- Bridges

![Tor Network](screenshots/vm/tor.png)

---

### 🌐 Exposure Settings

**Category:** Privacy

Unified exposure (Tor, SSL, DNS, Mesh)

**Features:**
- Tor exposure
- SSL certs
- DNS records
- Mesh access

![Exposure Settings](screenshots/vm/exposure.png)

---

### 🔐 Zero-Knowledge Proofs

**Category:** Privacy

ZKP Hamiltonian management

**Features:**
- Proof generation
- Verification
- Key management

![Zero-Knowledge Proofs](screenshots/vm/zkp.png)

---

### 📊 Netdata

**Category:** Monitoring

Real-time system monitoring

**Features:**
- Metrics
- Alerts
- Charts
- Plugins

![Netdata](screenshots/vm/netdata.png)

---

### 🔬 Deep Packet Inspection

**Category:** Monitoring

DPI with netifyd

**Features:**
- Protocol detection
- App identification
- Flow analysis

![Deep Packet Inspection](screenshots/vm/dpi.png)

---

### 📱 Device Intelligence

**Category:** Monitoring

Asset discovery and fingerprinting

**Features:**
- ARP scanning
- MAC vendor lookup
- OS detection

![Device Intelligence](screenshots/vm/device-intel.png)

---

### 👁️ Watchdog

**Category:** Monitoring

Service and container monitoring

**Features:**
- Health checks
- Auto-restart
- Alerts

![Watchdog](screenshots/vm/watchdog.png)

---

### 🎬 Media Flow

**Category:** Monitoring

Media traffic analytics

**Features:**
- Stream detection
- Bandwidth usage
- Protocol analysis

![Media Flow](screenshots/vm/mediaflow.png)

---

### 🔐 Login Portal

**Category:** Access

Authentication portal with JWT

**Features:**
- JWT auth
- Sessions
- Password recovery

![Login Portal](screenshots/vm/portal.png)

---

### 👥 User Management

**Category:** Access

Unified identity management

**Features:**
- User CRUD
- Groups
- Service provisioning

![User Management](screenshots/vm/users.png)

---

### 📦 Services Portal

**Category:** Services

C3Box services portal

**Features:**
- Service links
- Status overview
- Quick access

![Services Portal](screenshots/vm/c3box.png)

---

### 🦊 Gitea

**Category:** Services

Git server (LXC)

**Features:**
- Repositories
- Users
- SSH/HTTP
- LFS

![Gitea](screenshots/vm/gitea.png)

---

### ☁️ Nextcloud

**Category:** Services

File sync (LXC)

**Features:**
- File sync
- WebDAV
- CalDAV
- CardDAV

![Nextcloud](screenshots/vm/nextcloud.png)

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

![Mail Server](screenshots/vm/mail.png)

---

### 💌 Webmail

**Category:** Email

Roundcube/SOGo webmail

**Features:**
- Web interface
- Address book
- Calendar

![Webmail](screenshots/vm/webmail.png)

---

### 📰 Publishing Platform

**Category:** Publishing

Unified publishing dashboard

**Features:**
- Multi-platform
- Scheduling
- Analytics

![Publishing Platform](screenshots/vm/publish.png)

---

### 💧 Droplet

**Category:** Publishing

File upload and publish

**Features:**
- File upload
- Share links
- Expiration

![Droplet](screenshots/vm/droplet.png)

---

### 📝 Metablogizer

**Category:** Publishing

Static site publisher with Tor

**Features:**
- Static sites
- Tor publishing
- Templates

![Metablogizer](screenshots/vm/metablogizer.png)

---

### 🎨 Streamlit

**Category:** Apps

Streamlit app platform

**Features:**
- App hosting
- Deployment
- Management

![Streamlit](screenshots/vm/streamlit.png)

---

### ⚡ StreamForge

**Category:** Apps

Streamlit app development

**Features:**
- Templates
- Code editor
- Preview

![StreamForge](screenshots/vm/streamforge.png)

---

### 📦 APT Repository

**Category:** Apps

APT repository management

**Features:**
- Package management
- GPG signing
- Multi-distro

![APT Repository](screenshots/vm/repo.png)

---

### ⚙️ System Hub

**Category:** System

System configuration and management

**Features:**
- Settings
- Logs
- Services
- Updates

![System Hub](screenshots/vm/system.png)

---

### 💾 Backup Manager

**Category:** System

System and LXC backup

**Features:**
- Config backup
- LXC snapshots
- Restore

![Backup Manager](screenshots/vm/backup.png)

---

