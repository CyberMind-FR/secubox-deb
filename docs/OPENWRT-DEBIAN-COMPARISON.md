# SecuBox: OpenWRT vs Debian Module Comparison

*Generated: 2026-03-26*

## Summary

| Platform | Modules | UI Pages | API Endpoints | Notes |
|----------|---------|----------|---------------|-------|
| **OpenWRT** | 103 luci-app | ~103 | Shell/RPCD | LuCI + ubus |
| **Debian** | 52 packages | 49 | ~1000+ | FastAPI + REST |

---

## Migration Status by Category

### Core Infrastructure

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-secubox | secubox-hub | ✅ | Main dashboard |
| luci-app-secubox-portal | secubox-portal | ✅ | Auth portal |
| luci-app-system-hub | secubox-system | ✅ | System config |
| secubox-core | secubox-core | ✅ | Shared library |
| — | secubox-daemon | ✅ | Go mesh daemon (NEW) |
| — | secubox-full | ✅ | Metapackage |
| — | secubox-lite | ✅ | Metapackage |

### Security (🛡️)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-crowdsec-dashboard | secubox-crowdsec | ✅ | 54 endpoints |
| luci-app-auth-guardian | secubox-auth | ✅ | OAuth2/JWT |
| luci-app-client-guardian | secubox-nac | ✅ | Network access control |
| luci-app-wireguard-dashboard | secubox-wireguard | ✅ | VPN tunnel management |
| luci-app-tor-shield | secubox-tor | ✅ | Anonymity network |
| luci-app-vortex-dns | secubox-vortex-dns | ✅ | DNS firewall + RPZ |
| luci-app-vortex-firewall | secubox-vortex-firewall | ✅ | nftables enforcement |
| luci-app-mitmproxy | secubox-mitmproxy | ✅ | Traffic inspection |
| — | secubox-waf | ✅ | Web App Firewall (NEW) |
| — | secubox-hardening | ✅ | Kernel hardening (NEW) |
| luci-app-secubox-users | secubox-users | ✅ | Unified identity |
| luci-app-zkp | secubox-zkp | ✅ | Zero-Knowledge Proof |
| luci-app-wazuh | — | ⬜ | SIEM/XDR |
| luci-app-ipblocklist | — | ⬜ | IP blocklists |
| luci-app-cve-triage | — | ⬜ | CVE management |
| luci-app-threat-analyst | — | ⬜ | Threat analysis |
| luci-app-mac-guardian | — | ⬜ | MAC filtering |
| luci-app-cookie-tracker | — | ⬜ | Cookie analysis |

### Network (🌐)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-network-modes | secubox-netmodes | ✅ | Network topology |
| luci-app-bandwidth-manager | secubox-qos | ✅ | HTB + VLAN |
| luci-app-traffic-shaper | secubox-traffic | ✅ | TC/CAKE QoS |
| luci-app-haproxy | secubox-haproxy | ✅ | Load balancer |
| luci-app-cdn-cache | secubox-cdn | ✅ | CDN cache |
| luci-app-vhost-manager | secubox-vhost | ✅ | Nginx vhosts |
| luci-app-exposure | secubox-exposure | ✅ | Unified exposure |
| luci-app-meshname-dns | secubox-meshname | ✅ | Mesh DNS/mDNS |
| luci-app-dns-master | secubox-dns | ✅ | BIND zones |
| luci-app-dpi-dual | secubox-dpi | ✅ | Deep packet inspection |
| luci-app-secubox-mesh | secubox-mesh | ✅ | Yggdrasil mesh |
| luci-app-secubox-p2p | secubox-p2p | ✅ | P2P networking |
| luci-app-secubox-netifyd | — | ⬜ | Netifyd agent (merged with DPI) |
| luci-app-network-tweaks | — | ⬜ | Network optimization |
| luci-app-network-anomaly | — | ⬜ | Traffic anomaly |
| luci-app-dns-provider | — | ⬜ | DNS providers |
| luci-app-dnsguard | — | ⬜ | DNS filtering |
| luci-app-routes-status | — | ⬜ | Route monitoring |
| luci-app-ksm-manager | — | ⬜ | KSM memory |
| luci-app-mqtt-bridge | — | ⬜ | MQTT bridge |

### Monitoring (📈)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-netdata-dashboard | secubox-netdata | ✅ | 16 endpoints |
| luci-app-media-flow | secubox-mediaflow | ✅ | Media analytics |
| luci-app-device-intel | secubox-device-intel | ✅ | Asset discovery |
| luci-app-metrics-dashboard | secubox-metrics | ✅ | Real-time metrics |
| — | secubox-soc | ✅ | SOC dashboard (NEW) |
| — | secubox-watchdog | ✅ | Health monitoring (NEW) |
| luci-app-glances | — | ⬜ | System metrics |
| luci-app-ndpid | — | ⬜ | nDPI daemon |
| luci-app-service-registry | — | ⬜ | Service discovery |

### Applications (🎯)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-mailserver | secubox-mail | ✅ | Postfix/Dovecot |
| — | secubox-webmail | ✅ | Roundcube/SOGo |
| — | secubox-mail-lxc | ✅ | LXC backend |
| — | secubox-webmail-lxc | ✅ | LXC backend |
| luci-app-gitea | secubox-gitea | ✅ | Git server |
| luci-app-nextcloud | secubox-nextcloud | ✅ | File sync |
| luci-app-streamlit | secubox-streamlit | ✅ | Streamlit apps |
| luci-app-streamlit-forge | secubox-streamforge | ✅ | App development |
| — | secubox-c3box | ✅ | Services portal (NEW) |
| luci-app-ollama | — | ⬜ | Local LLM |
| luci-app-localai | — | ⬜ | LocalAI |
| luci-app-ai-gateway | — | ⬜ | AI gateway |
| luci-app-ai-insights | — | ⬜ | AI analytics |
| luci-app-jellyfin | — | ⬜ | Media server |
| luci-app-lyrion | — | ⬜ | Music server |
| luci-app-jitsi | — | ⬜ | Video conferencing |
| luci-app-matrix | — | ⬜ | Matrix chat |
| luci-app-simplex | — | ⬜ | SimpleX chat |
| luci-app-jabber | — | ⬜ | XMPP |
| luci-app-gotosocial | — | ⬜ | Fediverse |
| luci-app-peertube | — | ⬜ | Video platform |
| luci-app-magicmirror2 | — | ⬜ | Smart mirror |
| luci-app-zigbee2mqtt | — | ⬜ | Zigbee gateway |
| luci-app-domoticz | — | ⬜ | Home automation |
| luci-app-picobrew | — | ⬜ | Brewing |
| luci-app-webradio | — | ⬜ | Internet radio |
| luci-app-photoprism | — | ⬜ | Photo management |
| luci-app-turn | — | ⬜ | TURN server |
| luci-app-voip | — | ⬜ | VoIP |

### Publishing (📤)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-droplet | secubox-droplet | ✅ | File publisher |
| luci-app-metablogizer | secubox-metablogizer | ✅ | Static sites + Tor |
| — | secubox-publish | ✅ | Unified publishing (NEW) |
| luci-app-hexojs | — | ⬜ | Hexo sites |
| luci-app-metabolizer | — | ⬜ | Content processing |
| luci-app-metacatalog | — | ⬜ | Content catalog |
| luci-app-reporter | — | ⬜ | Report generator |
| luci-app-newsbin | — | ⬜ | Usenet |
| luci-app-torrent | — | ⬜ | BitTorrent |

### System (📦)

| OpenWRT | Debian | Status | Notes |
|---------|--------|--------|-------|
| luci-app-backup | secubox-backup | ✅ | Config backup |
| luci-app-repo | secubox-repo | ✅ | APT repository |
| — | secubox-roadmap | ✅ | Migration tracker (NEW) |
| luci-app-config-vault | — | ⬜ | Config vault |
| luci-app-config-advisor | — | ⬜ | Config advisor |
| luci-app-cloner | — | ⬜ | System clone |
| luci-app-vm | — | ⬜ | VM management |
| luci-app-interceptor | — | ⬜ | Packet interceptor |
| luci-app-secubox-netdiag | — | ⬜ | Network diagnostics |
| luci-app-secubox-mirror | — | ⬜ | Mirror sync |
| luci-app-secubox-admin | — | ⬜ | Admin console |
| luci-app-secubox-security-threats | — | ⬜ | Threat dashboard |
| luci-app-master-link | — | ⬜ | Master-slave link |
| luci-app-rtty-remote | — | ⬜ | Remote terminal |
| luci-app-mmpm | — | ⬜ | Package manager |
| luci-app-saas-relay | — | ⬜ | SaaS relay |
| luci-app-openclaw | — | ⬜ | OpenClaw |
| luci-app-rezapp | — | ⬜ | RezApp |
| luci-app-localrecall | — | ⬜ | Local search |
| luci-app-avatar-tap | — | ⬜ | Avatar tap |
| luci-app-media-hub | — | ⬜ | Media hub |
| luci-app-cyberfeed | — | ⬜ | Cyber feed |
| luci-app-iot-guard | — | ⬜ | IoT protection |
| luci-app-smtp-relay | — | ⬜ | SMTP relay |

---

## Debian-Only Modules (NEW)

These modules exist only in SecuBox-DEB and have no OpenWRT equivalent:

| Module | Description |
|--------|-------------|
| secubox-daemon | Go mesh daemon (secuboxd, secuboxctl) |
| secubox-soc | Security Operations Center dashboard |
| secubox-waf | Web Application Firewall (CrowdSec) |
| secubox-hardening | Kernel sysctl + module blacklist |
| secubox-publish | Unified publishing platform |
| secubox-c3box | Services portal with topology |
| secubox-roadmap | Migration roadmap tracker |
| secubox-watchdog | Container/service health monitoring |
| secubox-full | Metapackage (all modules) |
| secubox-lite | Metapackage (essential modules) |

---

## Statistics

### Migration Progress

| Category | OpenWRT | Debian | Migrated | Pending |
|----------|---------|--------|----------|---------|
| Core | 3 | 7 | 3 | 0 |
| Security | 18 | 14 | 12 | 6 |
| Network | 20 | 14 | 12 | 8 |
| Monitoring | 9 | 6 | 5 | 4 |
| Applications | 28 | 9 | 7 | 21 |
| Publishing | 9 | 3 | 2 | 7 |
| System | 24 | 3 | 2 | 22 |
| **Total** | **103** | **52** | **43** | **68** |

### API Endpoints (Debian)

| Module | Endpoints | Status |
|--------|-----------|--------|
| secubox-hub | 40+ | ✅ |
| secubox-crowdsec | 54 | ✅ |
| secubox-qos | 80+ | ✅ |
| secubox-dpi | 40+ | ✅ |
| secubox-system | 35+ | ✅ |
| secubox-wireguard | 28+ | ✅ |
| secubox-cdn | 25+ | ✅ |
| secubox-nac | 25+ | ✅ |
| secubox-netmodes | 25+ | ✅ |
| secubox-auth | 20+ | ✅ |
| secubox-mediaflow | 20+ | ✅ |
| secubox-netdata | 16 | ✅ |
| Other modules | ~600+ | ✅ |
| **Total** | **~1000+** | ✅ |

---

## Technology Comparison

| Feature | OpenWRT | Debian |
|---------|---------|--------|
| Base OS | OpenWRT 23.05 | Debian Bookworm 12 |
| Arch | MIPS/ARM | ARM64/AMD64 |
| Init | procd | systemd |
| UI Framework | LuCI | Custom CRT Theme |
| Backend | Shell + RPCD | FastAPI + Python |
| API Style | ubus JSON-RPC | REST API |
| Config | UCI (/etc/config) | TOML/YAML |
| Firewall | fw3 (iptables) | nftables |
| Packages | opkg | apt/dpkg |
| Containers | — | LXC/Incus |
| Repo | Custom feed | apt.secubox.in |

---

## Roadmap

### Phase 5: Applications (Next)

Priority modules to migrate:

1. **luci-app-ollama** → secubox-ollama (AI/LLM)
2. **luci-app-jellyfin** → secubox-jellyfin (Media)
3. **luci-app-zigbee2mqtt** → secubox-zigbee (IoT)
4. **luci-app-matrix** → secubox-matrix (Chat)
5. **luci-app-jitsi** → secubox-jitsi (Video)

### Phase 6: System Tools

1. **luci-app-config-vault** → secubox-vault
2. **luci-app-cloner** → secubox-cloner
3. **luci-app-vm** → secubox-vm (Incus)

### Phase 7: Security Extensions

1. **luci-app-wazuh** → secubox-wazuh (SIEM)
2. **luci-app-cve-triage** → secubox-cve
3. **luci-app-threat-analyst** → secubox-threat

---

## References

- OpenWRT Source: `/home/reepost/CyberMindStudio/secubox-openwrt/`
- Debian Source: `/home/reepost/CyberMindStudio/secubox-deb/secubox-deb/`
- UI Guide: `docs/UI-GUIDE.md`
- Migration Map: `.claude/MIGRATION-MAP.md`
