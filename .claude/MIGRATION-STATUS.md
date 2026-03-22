# SecuBox Migration Status: OpenWrt → Debian

Generated: 2025-03-22

## Summary

| Metric | Count |
|--------|-------|
| OpenWrt luci-app modules | 102 |
| Debian packages created | 35 |
| Packages with real backends (sbin/*) | 7 |
| Migration coverage | ~34% |

---

## Migration Status by Module

### ✅ Fully Migrated (Real Backend + Three-Fold Architecture)

| Debian Package | OpenWrt Source | RPCD Lines | Backend Script | Status |
|----------------|----------------|------------|----------------|--------|
| secubox-haproxy | luci-app-haproxy | 1,769 | haproxyctl | ✅ Complete |
| secubox-streamlit | luci-app-streamlit | 2,319 | streamlitctl | ✅ Complete |
| secubox-metablogizer | luci-app-metablogizer | 2,821 | metablogizerctl | ✅ Complete |
| secubox-vhost | luci-app-vhost-manager | 735 | vhostctl | ✅ Complete |
| secubox-gitea | luci-app-gitea | 1,027 | giteactl | ✅ Complete |
| secubox-mail | luci-app-mailserver | ~500 | mailctl, mailserverctl | ✅ Complete |
| secubox-crowdsec | luci-app-crowdsec-dashboard | 2,812 | crowdsecctl | ✅ Complete |

### 🔄 Partial Migration (API exists, needs real backend)

| Debian Package | OpenWrt Source | RPCD Lines | API Lines | Priority |
|----------------|----------------|------------|-----------|----------|
| secubox-wireguard | luci-app-wireguard-dashboard | 1,636 | 560 | HIGH |
| secubox-netdata | luci-app-netdata-dashboard | 682 | 271 | MEDIUM |
| secubox-qos | luci-app-bandwidth-manager | 3,068 | 733 | MEDIUM |
| secubox-system | luci-app-system-hub | 2,417 | 501 | MEDIUM |
| secubox-netmodes | luci-app-network-modes | 2,668 | 404 | MEDIUM |
| secubox-nac | luci-app-client-guardian | 1,755 | 401 | MEDIUM |
| secubox-dpi | luci-app-dpi-dual + netifyd | 1,753 | 391 | MEDIUM |
| secubox-cdn | luci-app-cdn-cache | 943 | 493 | LOW |
| secubox-waf | luci-app-mitmproxy | 809 | 481 | LOW |
| secubox-auth | luci-app-auth-guardian | 517 | 179 | LOW |
| secubox-streamforge | luci-app-streamlit-forge | 737 | 287 | LOW |
| secubox-droplet | luci-app-droplet | ~300 | 281 | LOW |
| secubox-mediaflow | luci-app-media-flow | 579 | 192 | LOW |

### ⬜ Not Yet Migrated (High Value)

| OpenWrt Module | RPCD Lines | Complexity | Description |
|----------------|------------|------------|-------------|
| luci-app-hexojs | 3,768 | Complex | Static site generator |
| luci-app-cloner | 1,667 | Medium | System backup/clone |
| luci-app-service-registry | 1,640 | Medium | Service discovery |
| luci-app-tor-shield | 1,022 | Medium | Tor hidden services |
| luci-app-exposure | 768 | Medium | Attack surface analysis |
| luci-app-webradio | 767 | Easy | Internet radio |
| luci-app-ndpid | 767 | Medium | nDPI integration |
| luci-app-jabber | 763 | Medium | XMPP server |
| luci-app-mqtt-bridge | 673 | Medium | IoT MQTT bridge |
| luci-app-dnsguard | 642 | Medium | DNS filtering |

### ⬜ Not Yet Migrated (Medium Value - Applications)

| OpenWrt Module | RPCD Lines | Description |
|----------------|------------|-------------|
| luci-app-peertube | 816 | Video streaming |
| luci-app-jellyfin | ~400 | Media server |
| luci-app-localai | 527 | Local AI/LLM |
| luci-app-ollama | ~400 | Ollama LLM |
| luci-app-photoprism | ~400 | Photo management |
| luci-app-simplex | ~300 | Private messaging |
| luci-app-matrix | ~300 | Matrix chat server |
| luci-app-jitsi | ~400 | Video conferencing |
| luci-app-zigbee2mqtt | ~400 | Zigbee home automation |
| luci-app-domoticz | ~300 | Home automation |

### ⬜ Not Yet Migrated (Infrastructure)

| OpenWrt Module | RPCD Lines | Description |
|----------------|------------|-------------|
| luci-app-network-tweaks | 939 | Network optimization |
| luci-app-ksm-manager | 939 | Kernel memory mgmt |
| luci-app-traffic-shaper | 568 | Traffic shaping |
| luci-app-backup | ~400 | System backup |
| luci-app-config-vault | ~300 | Config management |
| luci-app-routes-status | ~200 | Route monitoring |
| luci-app-interceptor | ~300 | Traffic interception |

---

## Recommended Migration Phases

### Phase 1: Core Security (Priority: HIGH)
Complete the security stack for appliance functionality.

1. **secubox-crowdsec** - Add crowdsecctl with LAPI integration
2. **secubox-wireguard** - Add wgctl for tunnel management
3. **secubox-dnsguard** - Create new package for DNS filtering

### Phase 2: Network Management (Priority: HIGH)
Essential network configuration and monitoring.

4. **secubox-netmodes** - Add netmodesctl for bridge/router/AP modes
5. **secubox-qos** - Add qosctl for bandwidth management
6. **secubox-dpi** - Add dpict for deep packet inspection

### Phase 3: System Administration (Priority: MEDIUM)
System management and monitoring tools.

7. **secubox-system** - Add systemctl wrapper + diagnostics
8. **secubox-backup** - Create new package for backup/restore
9. **secubox-nac** - Add nacctl for network access control

### Phase 4: Applications Platform (Priority: MEDIUM)
Application hosting and management.

10. **secubox-tor** - Create new package for Tor services
11. **secubox-exposure** - Port attack surface analyzer
12. **secubox-hexojs** - Port static site generator (largest module)

### Phase 5: Media & Communications (Priority: LOW)
Entertainment and communication services.

13. **secubox-jellyfin** - Media server
14. **secubox-webradio** - Internet radio
15. **secubox-matrix** - Chat server
16. **secubox-jitsi** - Video conferencing

### Phase 6: AI & Automation (Priority: LOW)
AI assistants and automation.

17. **secubox-ollama** - Local LLM
18. **secubox-localai** - AI gateway
19. **secubox-zigbee2mqtt** - Home automation

---

## Architecture Patterns to Apply

### Three-Fold Architecture
All modules should implement:
- **/components** - System components list
- **/status** - Health and runtime state
- **/access** - Connection URLs and ports

### Control Scripts (sbin/)
Each module needs a `<module>ctl` script with:
- Container management (install/start/stop/status)
- Configuration generation
- Migration from OpenWrt (`migrate` command)
- Service-specific operations

### UI Tabs
Standard tab structure:
- Components | Status | Access | [Module-specific] | Actions

---

## Files to Create per Module

```
packages/secubox-<module>/
├── api/
│   ├── __init__.py
│   └── main.py              # FastAPI with three-fold endpoints
├── sbin/
│   └── <module>ctl          # Control script (bash)
├── www/<module>/
│   └── index.html           # Tabbed UI
├── debian/
│   ├── control
│   ├── rules                # Include sbin installation
│   ├── changelog
│   ├── postinst
│   ├── prerm
│   └── secubox-<module>.service
└── menu.d/
    └── XX-<module>.json
```

---

## Estimated Effort

| Phase | Modules | Estimated Hours |
|-------|---------|-----------------|
| Phase 1 | 3 | 15-20 |
| Phase 2 | 3 | 20-25 |
| Phase 3 | 3 | 15-20 |
| Phase 4 | 3 | 25-30 |
| Phase 5 | 4 | 20-25 |
| Phase 6 | 3 | 15-20 |
| **Total** | **19** | **110-140** |

---

## Next Immediate Actions

1. **secubox-crowdsec**: Add `crowdsecctl` with:
   - CrowdSec LAPI communication
   - Decision list/ban management
   - Bouncer configuration
   - Migration of scenarios/parsers

2. **secubox-wireguard**: Add `wgctl` with:
   - Peer management (add/remove/list)
   - Key generation
   - Interface configuration
   - QR code generation for mobile

3. **secubox-dnsguard**: Create new package with:
   - AdGuard Home / Pi-hole integration
   - Blocklist management
   - Query logging
   - Per-client filtering
