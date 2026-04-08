# SecuBox Modules

**CyberMind · Gondwana** | [FR](MODULES-FR) | [DE](MODULES-DE) | [中文](MODULES-ZH) | **v1.5.10**

Complete list of SecuBox packages organized by the **Six-Stack Architecture**.

---

## 🟠 AUTH — Authentication Stack

*Accès contrôlé · Identité vérifiée · Zero-Trust*

### secubox-auth
**OAuth2 & Captive Portal**
- OAuth2/OIDC provider
- Captive portal for guests
- Voucher system
- Social login integration
- RADIUS backend

### secubox-portal
**Authentication Portal**
- JWT-based login/logout
- Session management
- Password reset
- Multi-user support

### secubox-users
**Unified Identity Management**
- Central user database
- 7-service synchronization
- LDAP integration
- Group management
- Password policies

### secubox-nac
**Network Access Control**
- Device fingerprinting
- MAC-based access
- VLAN assignment
- Guest isolation
- Quarantine network

### secubox-mac-guard
**MAC Address Control**
- Device whitelist/blacklist
- MAC monitoring
- Network segment enforcement
- Real-time alerts

### secubox-avatar
**Identity Management**
- User profiles
- Avatar storage
- Federated identity

---

## 🟡 WALL — Security Stack

*nftables · CrowdSec · IDS/IPS actif*

### secubox-crowdsec
**IDS/IPS with CrowdSec**
- Real-time threat detection
- Community blocklists
- Decision management (ban/captcha)
- Bouncer integration
- Custom scenarios

### secubox-waf
**Web Application Firewall**
- 300+ ModSecurity rules
- OWASP Core Rule Set
- Custom rule support
- SQL injection protection
- XSS prevention

### secubox-threats
**Threat Dashboard**
- Unified threat view
- Attack visualization
- Trend analysis
- Alert aggregation

### secubox-ipblock
**IP Blocklist Manager**
- Multiple blocklist sources
- Auto-update schedules
- nftables integration
- Whitelist management

### secubox-ai-insights
**ML Threat Detection**
- Behavioral analysis
- Anomaly detection
- Pattern recognition
- Automated alerts

### secubox-cyberfeed
**Threat Feed Aggregator**
- Multiple threat feeds
- IOC collection
- Feed normalization

### secubox-interceptor
**Traffic Interception**
- Transparent proxy
- SSL inspection
- Traffic analysis

### secubox-cookies
**Cookie Analysis**
- Cookie inspection
- Tracking detection
- Privacy compliance

### secubox-wazuh
**SIEM Integration**
- Wazuh agent management
- Log correlation
- Compliance monitoring

### secubox-ossec
**Host-based IDS**
- File integrity monitoring
- Log analysis
- Rootkit detection

### secubox-openclaw
**OSINT Tool**
- Open source intelligence
- Reconnaissance
- Threat research

---

## 🔴 BOOT — Deployment Stack

*Provisioning · Boot rapide · Terrain*

### secubox-cloner
**System Imaging**
- Full disk imaging
- Incremental backups
- Restoration wizard
- Image compression

### secubox-vault
**Config Backup/Restore**
- Configuration snapshots
- Encrypted backup
- Versioned history
- Remote sync

### secubox-vm
**QEMU/KVM Virtualization**
- VM management
- Disk provisioning
- Network configuration
- Snapshot control

### secubox-rezapp
**App Deployment**
- Container management
- Service deployment
- Rollback support

### secubox-admin
**Admin Dashboard**
- Central administration
- User management
- System overview

### secubox-mirror
**Mirror/CDN**
- Package mirrors
- Content distribution
- Cache management

---

## 🟣 MIND — Intelligence Stack

*Automatisation · Analyse comportementale · nDPId*

### secubox-dpi
**Deep Packet Inspection**
- Application detection (netifyd)
- Protocol classification
- Flow analysis
- Bandwidth monitoring
- Top talkers

### secubox-netifyd
**DPI Daemon Management**
- netifyd service control
- Detection status
- Flow monitoring
- Application statistics

### secubox-soc-agent
**Edge Node Metrics Agent**
- System metrics collection
- Security alert forwarding
- HMAC-signed upstream push
- Remote command execution
- One-time enrollment tokens

### secubox-soc-gateway
**SOC Aggregation Gateway**
- Node registry and health tracking
- Fleet-wide metrics aggregation
- Cross-node threat correlation
- WebSocket real-time alerts
- Hierarchical mode

### secubox-soc-web
**React Web Dashboard**
- Fleet overview
- Unified alert stream
- Threat map visualization
- Node detail management

### secubox-netdata
**Real-time Monitoring**
- System metrics
- Network statistics
- Custom dashboards
- Alert configuration

### secubox-metrics
**Metrics Collection**
- Prometheus format
- Custom metrics
- Dashboard integration

### secubox-glances
**System Monitor**
- Resource overview
- Process monitoring
- Network stats

### secubox-reporter
**System Reports**
- Automated reports
- Scheduled delivery
- Multi-format export

### secubox-metabolizer
**Log Processor**
- Log parsing
- Pattern extraction
- Event correlation

### secubox-metacatalog
**Service Catalog**
- Service registry
- Discovery
- Health tracking

---

## 🟢 ROOT — System Stack

*Debian durci · Accès console · Bas niveau*

### secubox-core
**Shared Libraries & Framework**
- Python shared library (`secubox_core`)
- JWT authentication framework
- Configuration management (TOML)
- Logging utilities
- nginx base configuration

### secubox-hub
**Central Dashboard**
- Main web interface
- Module status overview
- System health monitoring
- Alert aggregation
- Dynamic menu generation

### secubox-system
**System Management**
- Service control
- Log viewer
- Package updates
- Reboot/shutdown
- Backup/restore

### secubox-console
**Terminal TUI Dashboard**
- Textual-based interface
- Live system metrics
- Service management
- Real-time log streaming

### secubox-hardening
**Security Hardening**
- Kernel parameters
- Service lockdown
- File permissions
- Audit logging

### secubox-routes
**Routing Table View**
- Route visualization
- Policy routing
- Gateway management

### secubox-nettweak
**Network Tuning**
- TCP optimization
- Buffer sizing
- Congestion control

### secubox-ksm
**Kernel Same-page Merging**
- Memory deduplication
- KSM statistics
- Performance tuning

### secubox-rtty
**Remote Terminal**
- WebSocket terminal
- Remote access
- Session recording

### secubox-netdiag
**Network Diagnostics**
- Ping/traceroute
- DNS lookup
- Port scanning

### secubox-picobrew
**Homebrew Controller**
- Brew monitoring
- Temperature control
- Recipe management

---

## 🔵 MESH — Network Stack

*WireGuard · Tailscale · Topologie mesh*

### secubox-wireguard
**VPN Dashboard**
- Interface management
- Peer configuration
- Key generation
- QR code export
- Traffic statistics

### secubox-haproxy
**Load Balancer & Proxy**
- Backend server pools
- Health checks
- SSL/TLS termination
- ACL rules
- Statistics dashboard

### secubox-netmodes
**Network Modes**
- Router mode
- Bridge mode
- Access Point mode
- Netplan configuration
- Interface bonding

### secubox-qos
**Quality of Service**
- HTB traffic shaping
- Priority queues
- Bandwidth limits
- Per-device rules
- Real-time stats

### secubox-vhost
**Virtual Hosts**
- nginx vhost management
- ACME certificates
- Reverse proxy
- SSL configuration

### secubox-cdn
**CDN Cache**
- Squid proxy cache
- nginx caching
- Cache purge API
- Hit rate statistics

### secubox-turn
**TURN/STUN Server**
- WebRTC relay
- NAT traversal
- Authentication

### secubox-mqtt
**MQTT Broker**
- Mosquitto broker
- Topic management
- Client authentication

### secubox-smtp-relay
**Mail Relay**
- SMTP forwarding
- TLS encryption
- Queue management

### secubox-saas-relay
**SaaS Proxy**
- Service proxy
- API gateway
- Rate limiting

### secubox-dns
**DNS Server**
- BIND9 zones
- DNSSEC support
- Dynamic updates

### secubox-dns-provider
**DNS API (OVH, Gandi)**
- DNS provider integration
- Record management
- ACME challenges

---

## Applications

### Media & Communication

| Package | Description |
|---------|-------------|
| secubox-ollama | LLM inference, Ollama API proxy |
| secubox-localai | Alternative LLM backend |
| secubox-jellyfin | Media server LXC |
| secubox-lyrion | Music server |
| secubox-photoprism | Photo management |
| secubox-peertube | Video platform LXC |
| secubox-webradio | Internet radio |
| secubox-matrix | Synapse chat server LXC |
| secubox-jitsi | Video conferencing LXC |
| secubox-jabber | XMPP server |
| secubox-simplex | Secure messaging |
| secubox-gotosocial | Fediverse server |

### Home Automation

| Package | Description |
|---------|-------------|
| secubox-homeassistant | IoT hub LXC |
| secubox-zigbee | Zigbee2MQTT gateway |
| secubox-domoticz | Home automation |
| secubox-magicmirror | Smart display |
| secubox-mmpm | MagicMirror package manager |

### Publishing & Content

| Package | Description |
|---------|-------------|
| secubox-hexo | Static blog generator |
| secubox-gitea | Git server LXC |
| secubox-nextcloud | File sync LXC |
| secubox-droplet | File publisher |
| secubox-streamlit | Streamlit platform |
| secubox-streamforge | Streamlit manager |
| secubox-metablogizer | Static site generator |
| secubox-publish | Publishing dashboard |
| secubox-c3box | Services portal |

### Email

| Package | Description |
|---------|-------------|
| secubox-mail | Email server (Postfix/Dovecot) |
| secubox-webmail | Roundcube webmail |

### Downloads

| Package | Description |
|---------|-------------|
| secubox-torrent | BitTorrent client |
| secubox-newsbin | Usenet client |

### VoIP

| Package | Description |
|---------|-------------|
| secubox-voip | VoIP/PBX LXC |

---

## Metapackages

### secubox-full
Installs all 125 modules. Recommended for:
- MOCHAbin
- VMs with 4+ GB RAM
- Full-featured deployments

### secubox-lite
Installs core modules only. Recommended for:
- ESPRESSObin (limited RAM)
- Minimal deployments
- Edge devices

---

## See Also

- [[Installation]] — How to install
- [[API-Reference]] — Module APIs (2000+ endpoints)
- [[Configuration]] — Configuration guide

---

*© 2026 CyberMind · Notre-Dame-du-Cruet, Savoie*
