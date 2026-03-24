# SecuBox Modules

[Francais](Modules-FR) | [中文](Modules-ZH)

Complete list of SecuBox packages and their functionality.

## Core Modules

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

### secubox-portal
**Authentication Portal**

- JWT-based login/logout
- Session management
- Password reset
- Multi-user support

## Security Modules

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
- Request/response filtering
- SQL injection protection
- XSS prevention

### secubox-auth
**OAuth2 & Captive Portal**

- OAuth2/OIDC provider
- Captive portal for guests
- Voucher system
- Social login integration
- RADIUS backend

### secubox-nac
**Network Access Control**

- Device fingerprinting
- MAC-based access
- VLAN assignment
- Guest isolation
- Quarantine network

### secubox-users
**Unified Identity Management**

- Central user database
- 7-service synchronization
- LDAP integration
- Group management
- Password policies

## Network Modules

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

### secubox-dpi
**Deep Packet Inspection**

- Application detection (netifyd)
- Protocol classification
- Flow analysis
- Bandwidth monitoring
- Top talkers

### secubox-qos
**Quality of Service**

- HTB traffic shaping
- Priority queues
- Bandwidth limits
- Per-device rules
- Real-time stats

### secubox-netmodes
**Network Modes**

- Router mode
- Bridge mode
- Access Point mode
- Netplan configuration
- Interface bonding

### secubox-vhost
**Virtual Hosts**

- nginx vhost management
- ACME certificates
- Reverse proxy
- SSL configuration
- Domain routing

### secubox-cdn
**CDN Cache**

- Squid proxy cache
- nginx caching
- Cache purge API
- Storage management
- Hit rate statistics

## Monitoring Modules

### secubox-netdata
**Real-time Monitoring**

- System metrics
- Network statistics
- Custom dashboards
- Alert configuration
- Historical data

### secubox-mediaflow
**Media Streaming Detection**

- Stream detection
- Bandwidth usage
- Protocol identification
- Quality metrics

### secubox-metrics
**Metrics Collection**

- Prometheus format
- Custom metrics
- API endpoints
- Dashboard integration

## DNS & Email Modules

### secubox-dns
**DNS Server**

- BIND9 zones
- DNSSEC support
- Dynamic updates
- Zone management UI
- Query logging

### secubox-mail
**Email Server**

- Postfix MTA
- Dovecot IMAP/POP3
- SpamAssassin
- DKIM signing
- Virtual domains

### secubox-mail-lxc
**Mail LXC Container**

- Isolated mail environment
- Resource limits
- Easy deployment

### secubox-webmail
**Webmail Interface**

- Roundcube / SOGo
- Calendar integration
- Address book
- Sieve filters

## Publishing Modules

### secubox-droplet
**File Publisher**

- Drag & drop upload
- Public/private sharing
- Expiring links
- Access logging

### secubox-streamlit
**Streamlit Platform**

- Python app hosting
- Data dashboards
- Interactive apps
- Multiple instances

### secubox-streamforge
**Streamlit Manager**

- App deployment
- Version control
- Resource management

### secubox-metablogizer
**Static Site Generator**

- Markdown content
- Tor hidden service
- Theme support
- RSS feeds

### secubox-publish
**Publishing Dashboard**

- Unified interface
- All publishing tools
- Content management

## System Modules

### secubox-system
**System Management**

- Service control
- Log viewer
- Package updates
- Reboot/shutdown
- Backup/restore

### secubox-hardening
**Security Hardening**

- Kernel parameters
- Service lockdown
- File permissions
- Audit logging

## Metapackages

### secubox-full
Installs all modules. Recommended for:
- MOCHAbin
- VMs with 2+ GB RAM
- Full-featured deployments

### secubox-lite
Installs core modules only. Recommended for:
- ESPRESSObin (limited RAM)
- Minimal deployments
- Edge devices

## See Also

- [[Installation]] - How to install
- [[API-Reference]] - Module APIs
- [[Configuration]] - Configuration guide
