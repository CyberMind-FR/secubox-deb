# SecuBox Modules Documentation

*Last Updated: 2026-03-24*

**Total: 46 modules | ~900+ API endpoints**

This document catalogs all SecuBox Debian modules, their features, and UI screenshots locations.

---

## Module Overview by Category

### Dashboard & Core
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-hub | `🏠` | `/` | Main dashboard, system overview |
| secubox-portal | `🔐` | `/portal/` | Login, authentication portal |
| secubox-soc | `🛡️` | `/soc/` | Security Operations Center |
| secubox-roadmap | `📋` | `/roadmap/` | Migration progress tracker |

### Security & Firewall
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-crowdsec | `🛡️` | `/crowdsec/` | Collaborative security engine |
| secubox-waf | `🔥` | `/waf/` | Web Application Firewall |
| secubox-vortex-firewall | `🔥` | `/vortex-firewall/` | nftables threat enforcement |
| secubox-mitmproxy | `🔍` | `/mitmproxy/` | Traffic inspection proxy |
| secubox-hardening | `🔒` | `/hardening/` | System hardening tools |

### Network & Traffic
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-netmodes | `🌐` | `/netmodes/` | Network mode configuration |
| secubox-qos | `📊` | `/qos/` | Quality of Service (HTB/CAKE) |
| secubox-traffic | `📈` | `/traffic/` | Traffic shaping (TC/CAKE) |
| secubox-haproxy | `⚡` | `/haproxy/` | Load balancer, reverse proxy |
| secubox-cdn | `🚀` | `/cdn/` | CDN cache management |

### DNS & Domain
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-dns | `🌍` | `/dns/` | BIND DNS server |
| secubox-vortex-dns | `🛡️` | `/vortex-dns/` | DNS firewall, RPZ, threat feeds |
| secubox-meshname | `📡` | `/meshname/` | Mesh DNS, mDNS, Avahi |

### VPN & Mesh
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-wireguard | `🔗` | `/wireguard/` | WireGuard VPN manager |
| secubox-mesh | `🕸️` | `/mesh/` | Mesh networking |
| secubox-p2p | `🔗` | `/p2p/` | P2P networking |
| secubox-tor | `🧅` | `/tor/` | Tor circuits, hidden services |
| secubox-exposure | `🌐` | `/exposure/` | Tor, SSL, DNS, Mesh exposure |

### Monitoring & Analytics
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-netdata | `📊` | `/netdata/` | Real-time performance monitoring |
| secubox-dpi | `🔬` | `/dpi/` | Deep packet inspection (netifyd) |
| secubox-device-intel | `📱` | `/device-intel/` | Asset discovery, fingerprinting |
| secubox-watchdog | `👁️` | `/watchdog/` | Service & container monitoring |
| secubox-mediaflow | `🎬` | `/mediaflow/` | Media stream analytics |

### Access Control
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-auth | `🔐` | `/auth/` | Authentication guardian |
| secubox-nac | `🛡️` | `/nac/` | Network Access Control |
| secubox-users | `👥` | `/users/` | Unified identity management |

### Hosting & Services
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-vhost | `🏗️` | `/vhost/` | Virtual host manager |
| secubox-c3box | `📦` | `/c3box/` | Services portal |
| secubox-gitea | `🦊` | `/gitea/` | Git server (LXC) |
| secubox-nextcloud | `☁️` | `/nextcloud/` | File sync (LXC) |

### Email & Communication
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-mail | `📧` | `/mail/` | Postfix/Dovecot mail server |
| secubox-webmail | `💌` | `/webmail/` | Roundcube/SOGo webmail |
| secubox-mail-lxc | — | — | LXC mail backend (no UI) |
| secubox-webmail-lxc | — | — | LXC webmail backend (no UI) |

### Publishing & Content
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-publish | `📰` | `/publish/` | Unified publishing platform |
| secubox-droplet | `💧` | `/droplet/` | File upload/publish |
| secubox-metablogizer | `📝` | `/metablogizer/` | Blog sites, Tor publish |

### Applications & Development
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-streamlit | `🎨` | `/streamlit/` | Streamlit app manager |
| secubox-streamforge | `⚡` | `/streamforge/` | App templates, deployment |
| secubox-repo | `📦` | `/repo/` | Package repository |

### System & Backup
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-system | `⚙️` | `/system/` | System administration |
| secubox-backup | `💾` | `/backup/` | Config/container backup |

### Advanced Security
| Module | Icon | Path | Description |
|--------|------|------|-------------|
| secubox-zkp | `🔐` | `/zkp/` | Zero-knowledge proofs |

---

## Detailed Module Documentation

### 1. secubox-hub (Dashboard)
**Path:** `/`
**API:** `/api/v1/hub/`
**Endpoints:** 40+

The main SecuBox dashboard providing:
- System health overview
- Quick stats from all modules
- Service status monitoring
- Resource usage metrics
- Quick actions panel

**Screenshot Location:** `docs/screenshots/hub.png`

---

### 2. secubox-soc (Security Operations Center)
**Path:** `/soc/`
**API:** `/api/v1/soc/`
**Endpoints:** 20+

Real-time SOC dashboard featuring:
- **World Clock:** 10 timezone display (UTC, EST, PST, GMT, CET, MSK, GST, SGT, JST, AEST)
- **World Threat Map:** SVG map with 30 country coordinates, real-time threat visualization
- **Ticket System:** Create, assign, track security incidents
- **Threat Intel:** IOC management (IPs, domains, hashes)
- **P2P Intel:** Peer-to-peer threat sharing
- **Alerts:** Real-time security alerts
- **WebSocket:** Live updates

**API Endpoints:**
```
GET  /clock          - World timezone data
GET  /map/threats    - Threat heat map by region
GET  /map/attacks    - Live attack feed (CrowdSec)
GET  /tickets        - List tickets
POST /tickets        - Create ticket
PUT  /tickets/{id}   - Update ticket
GET  /intel          - Threat indicators
POST /intel          - Add indicator
GET  /peers          - P2P peer list
POST /peers          - Add peer
GET  /alerts         - Alert feed
POST /alerts         - Create alert
GET  /stats          - SOC statistics
WS   /ws             - Real-time updates
```

**Screenshot Location:** `docs/screenshots/soc.png`

---

### 3. secubox-crowdsec
**Path:** `/crowdsec/`
**API:** `/api/v1/crowdsec/`
**Endpoints:** 54

Collaborative security featuring:
- Decision management (bans, captchas)
- Alert visualization
- Bouncer configuration
- Collection management
- Metrics dashboard

**Screenshot Location:** `docs/screenshots/crowdsec.png`

---

### 4. secubox-vortex-firewall
**Path:** `/vortex-firewall/`
**API:** `/api/v1/vortex-firewall/`
**Endpoints:** 15+

Threat-based firewall enforcement:
- nftables integration
- Threat feed ingestion
- IP reputation blocking
- Geo-blocking
- Rate limiting

**Screenshot Location:** `docs/screenshots/vortex-firewall.png`

---

### 5. secubox-vortex-dns
**Path:** `/vortex-dns/`
**API:** `/api/v1/vortex-dns/`
**Endpoints:** 20+

DNS security layer:
- Response Policy Zones (RPZ)
- Threat feed integration
- Domain blocking
- DNS sinkhole
- Query logging

**Screenshot Location:** `docs/screenshots/vortex-dns.png`

---

### 6. secubox-device-intel
**Path:** `/device-intel/`
**API:** `/api/v1/device-intel/`
**Endpoints:** 25+

Network asset intelligence:
- Device discovery
- OS fingerprinting
- Service detection
- Vulnerability assessment
- Asset inventory

**Screenshot Location:** `docs/screenshots/device-intel.png`

---

### 7. secubox-meshname
**Path:** `/meshname/`
**API:** `/api/v1/meshname/`
**Endpoints:** 15+

Mesh DNS services:
- mDNS/Avahi integration
- Local name resolution
- Service discovery
- Mesh node naming

**Screenshot Location:** `docs/screenshots/meshname.png`

---

### 8. secubox-wireguard
**Path:** `/wireguard/`
**API:** `/api/v1/wireguard/`
**Endpoints:** 28+

WireGuard VPN management:
- Peer management
- Key generation
- QR code configs
- Traffic stats
- Interface control

**Screenshot Location:** `docs/screenshots/wireguard.png`

---

### 9. secubox-qos
**Path:** `/qos/`
**API:** `/api/v1/qos/`
**Endpoints:** 80+

Traffic shaping (HTB + VLAN):
- Class-based queuing
- Bandwidth allocation
- VLAN tagging
- Priority rules
- Real-time stats

**Screenshot Location:** `docs/screenshots/qos.png`

---

### 10. secubox-waf
**Path:** `/waf/`
**API:** `/api/v1/waf/`
**Endpoints:** 300+ rules

Web Application Firewall:
- OWASP rule sets
- Custom rules
- Request inspection
- CrowdSec integration
- Audit logging

**Screenshot Location:** `docs/screenshots/waf.png`

---

### 11. secubox-netdata
**Path:** `/netdata/`
**API:** `/api/v1/netdata/`
**Endpoints:** 16

Real-time monitoring:
- System metrics
- Process monitoring
- Network stats
- Disk I/O
- Custom charts

**Screenshot Location:** `docs/screenshots/netdata.png`

---

### 12. secubox-dpi
**Path:** `/dpi/`
**API:** `/api/v1/dpi/`
**Endpoints:** 40+

Deep Packet Inspection:
- Protocol detection
- Application identification
- Traffic classification
- Flow analysis
- netifyd integration

**Screenshot Location:** `docs/screenshots/dpi.png`

---

### 13. secubox-tor
**Path:** `/tor/`
**API:** `/api/v1/tor/`
**Endpoints:** 15+

Tor network services:
- Circuit management
- Hidden services
- Bridge configuration
- Traffic analysis
- Exit policies

**Screenshot Location:** `docs/screenshots/tor.png`

---

### 14. secubox-mail
**Path:** `/mail/`
**API:** `/api/v1/mail/`
**Endpoints:** 25+

Mail server (Postfix/Dovecot):
- Domain management
- Mailbox creation
- Alias configuration
- DKIM/SPF/DMARC
- Queue management

**Screenshot Location:** `docs/screenshots/mail.png`

---

### 15. secubox-roadmap
**Path:** `/roadmap/`
**API:** `/api/v1/roadmap/`
**Endpoints:** 5

Development tracking:
- Migration progress
- Module status
- Category overview
- Completion metrics

**Screenshot Location:** `docs/screenshots/roadmap.png`

---

## CRT P31 Phosphor Theme

All modules use the CRT P31 phosphor green terminal aesthetic:

```css
:root {
    --p31-peak: #33ff66;    /* Bright green */
    --p31-hot: #66ffaa;     /* Hot phosphor */
    --p31-mid: #22cc44;     /* Mid intensity */
    --p31-dim: #0f8822;     /* Dim text */
    --p31-ghost: #052210;   /* Ghost/border */
    --p31-decay: #ffb347;   /* Decay/warning */
    --tube-black: #050803;  /* CRT black */
    --tube-deep: #080d05;   /* Deep background */
    --tube-bezel: #0d1208;  /* Bezel color */
}
```

Shared CSS files:
- `/shared/crt-system.css` - Full CRT styling
- `/shared/sidebar.css` - Navigation sidebar

---

## Screenshots Directory

To add module screenshots:

```bash
# Create screenshots directory
mkdir -p docs/screenshots

# Screenshot naming convention
docs/screenshots/<module-name>.png
```

### Screenshot Checklist

- [ ] hub.png
- [ ] soc.png
- [ ] crowdsec.png
- [ ] vortex-firewall.png
- [ ] vortex-dns.png
- [ ] device-intel.png
- [ ] meshname.png
- [ ] wireguard.png
- [ ] qos.png
- [ ] waf.png
- [ ] netdata.png
- [ ] dpi.png
- [ ] tor.png
- [ ] mail.png
- [ ] roadmap.png
- [ ] portal.png
- [ ] netmodes.png
- [ ] traffic.png
- [ ] haproxy.png
- [ ] cdn.png
- [ ] dns.png
- [ ] mesh.png
- [ ] p2p.png
- [ ] exposure.png
- [ ] mediaflow.png
- [ ] watchdog.png
- [ ] auth.png
- [ ] nac.png
- [ ] users.png
- [ ] vhost.png
- [ ] c3box.png
- [ ] gitea.png
- [ ] nextcloud.png
- [ ] webmail.png
- [ ] publish.png
- [ ] droplet.png
- [ ] metablogizer.png
- [ ] streamlit.png
- [ ] streamforge.png
- [ ] repo.png
- [ ] system.png
- [ ] backup.png
- [ ] hardening.png
- [ ] zkp.png

---

## API Authentication

All API endpoints require JWT authentication:

```javascript
const token = localStorage.getItem('sbx_token');
fetch('/api/v1/<module>/endpoint', {
    headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
    }
});
```

Unauthenticated requests redirect to `/portal/login.html`.

---

## Module Architecture

```
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   └── main.py          # FastAPI application
├── debian/
│   ├── control          # Package metadata
│   ├── rules            # Build rules
│   ├── postinst         # Post-install script
│   ├── prerm            # Pre-remove script
│   └── *.service        # Systemd unit
├── menu.d/
│   └── XX-<module>.json # Sidebar menu entry
├── nginx/
│   └── <module>.conf    # Nginx proxy config
└── www/
    └── <module>/
        └── index.html   # Frontend UI
```

---

## Building Modules

```bash
# Build single module
cd packages/secubox-<module>
dpkg-buildpackage -us -uc -b

# Build all modules
bash scripts/build-all-local.sh bookworm amd64

# Deploy to device
bash scripts/deploy.sh secubox-<module> root@192.168.1.1
```

---

*Generated by SecuBox Development Team*
