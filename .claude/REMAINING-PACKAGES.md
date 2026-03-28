# REMAINING PACKAGES — OpenWrt → Debian Migration
*Generated: 2026-03-28*

## Summary

| Category | Count | Status |
|----------|-------|--------|
| **Already Ported (renamed)** | 25 | ✅ Complete |
| **Phase 8: Applications** | 21 | ⬜ To Do |
| **Phase 9: System Tools** | 22 | ⬜ To Do |
| **Phase 10: Security Extensions** | 10 | ⬜ To Do |
| **Total Remaining** | 53 | — |

---

## Already Ported (Different Names)

These OpenWrt packages exist in Debian with renamed equivalents:

| OpenWrt (`luci-app-*`) | Debian (`secubox-*`) | Status |
|------------------------|----------------------|--------|
| crowdsec-dashboard | crowdsec | ✅ |
| netdata-dashboard | netdata | ✅ |
| wireguard-dashboard | wireguard | ✅ |
| network-modes | netmodes | ✅ |
| client-guardian | nac | ✅ |
| auth-guardian | auth | ✅ |
| bandwidth-manager | qos | ✅ |
| media-flow | mediaflow | ✅ |
| cdn-cache | cdn | ✅ |
| vhost-manager | vhost | ✅ |
| dpi-dual | dpi | ✅ |
| secubox | hub | ✅ |
| dns-master | dns | ✅ |
| mailserver | mail | ✅ |
| traffic-shaper | traffic | ✅ |
| tor-shield | tor | ✅ |
| secubox-mesh | mesh | ✅ |
| secubox-p2p | p2p | ✅ |
| secubox-users | users | ✅ |
| secubox-portal | portal | ✅ |
| meshname-dns | meshname | ✅ |
| streamlit-forge | streamforge | ✅ |
| metrics-dashboard | metrics | ✅ |
| dnsguard | dns-guard | ✅ |
| service-registry | c3box | ✅ |

---

## Phase 8: Applications (21 packages)

**Priority: High — User-facing services**

| OpenWrt Package | Target Debian | Complexity | Notes |
|-----------------|---------------|------------|-------|
| ~~**ollama**~~ | secubox-ollama | ~~Medium~~ | ~~LLM inference, API proxy~~ ✅ |
| ~~**localai**~~ | secubox-localai | ~~Medium~~ | ~~Alternative LLM backend~~ ✅ |
| ~~**jellyfin**~~ | secubox-jellyfin | ~~Medium~~ | ~~Media server, LXC~~ ✅ |
| **photoprism** | secubox-photoprism | Complex | Photo management, Go |
| **homeassistant** | secubox-homeassistant | Complex | IoT hub, LXC |
| ~~**zigbee2mqtt**~~ | secubox-zigbee | ~~Medium~~ | ~~Zigbee gateway~~ ✅ |
| **domoticz** | secubox-domoticz | Medium | Home automation |
| **matrix** | secubox-matrix | Complex | Chat server, Synapse |
| **jitsi** | secubox-jitsi | Complex | Video conferencing |
| **gotosocial** | secubox-gotosocial | Medium | Fediverse server |
| **peertube** | secubox-peertube | Complex | Video platform |
| **hexojs** | secubox-hexo | Easy | Static blog generator |
| **magicmirror2** | secubox-magicmirror | Medium | Smart display |
| ~~**lyrion**~~ | secubox-lyrion | ~~Medium~~ | ~~Music server~~ ✅ |
| **webradio** | secubox-webradio | Easy | Internet radio |
| **voip** | secubox-voip | Complex | VoIP/PBX |
| **jabber** | secubox-jabber | Medium | XMPP server |
| **simplex** | secubox-simplex | Medium | Secure messaging |
| **torrent** | secubox-torrent | Easy | BitTorrent client |
| **newsbin** | secubox-newsbin | Easy | Usenet client |
| **mmpm** | secubox-mmpm | Easy | MagicMirror package manager |

---

## Phase 9: System Tools (22 packages)

**Priority: Medium — Infrastructure utilities**

| OpenWrt Package | Target Debian | Complexity | Notes |
|-----------------|---------------|------------|-------|
| **config-vault** | secubox-vault | Medium | Config backup/restore |
| **cloner** | secubox-cloner | Medium | System imaging |
| **vm** | secubox-vm | Complex | QEMU/KVM virtualization |
| **glances** | secubox-glances | Easy | System monitor |
| **rtty-remote** | secubox-rtty | Easy | Remote terminal |
| **network-tweaks** | secubox-nettweak | Easy | Network tuning |
| **routes-status** | secubox-routes | Easy | Routing table view |
| **ksm-manager** | secubox-ksm | Easy | Kernel same-page merging |
| **reporter** | secubox-reporter | Medium | System reports |
| **metabolizer** | secubox-metabolizer | Medium | Log processor |
| **metacatalog** | secubox-metacatalog | Medium | Service catalog |
| **saas-relay** | secubox-saas-relay | Medium | SaaS proxy |
| **rezapp** | secubox-rezapp | Medium | App deployment |
| **picobrew** | secubox-picobrew | Medium | Homebrew controller |
| **turn** | secubox-turn | Medium | TURN/STUN server |
| **smtp-relay** | secubox-smtp-relay | Easy | Mail relay |
| **mqtt-bridge** | secubox-mqtt | Medium | MQTT broker |
| **cyberfeed** | secubox-cyberfeed | Medium | Threat feed aggregator |
| **avatar-tap** | secubox-avatar | Easy | Identity management |
| **secubox-admin** | secubox-admin | Easy | Admin dashboard |
| **secubox-mirror** | secubox-mirror | Medium | Mirror/CDN |
| **secubox-netdiag** | secubox-netdiag | Easy | Network diagnostics |

---

## Phase 10: Security Extensions (10 packages)

**Priority: High for enterprise — Advanced security**

| OpenWrt Package | Target Debian | Complexity | Notes |
|-----------------|---------------|------------|-------|
| **wazuh** | secubox-wazuh | Complex | SIEM, requires agent |
| **ai-insights** | secubox-ai-insights | Medium | ML threat detection |
| **ipblocklist** | secubox-ipblock | Easy | IP blocklist manager |
| **interceptor** | secubox-interceptor | Medium | Traffic interception |
| **cookie-tracker** | secubox-cookies | Easy | Cookie analysis |
| **mac-guardian** | secubox-mac-guard | Easy | MAC address control |
| **dns-provider** | secubox-dns-provider | Medium | DNS API (OVH, Gandi) |
| **secubox-security-threats** | secubox-threats | Medium | Threat dashboard |
| **openclaw** | secubox-openclaw | Medium | OSINT tool |
| **secubox-netifyd** | secubox-netifyd | Medium | DPI daemon |

---

## Migration Priority

### Immediate (Next Sprint)
1. `secubox-ollama` — High user demand for local AI
2. `secubox-jellyfin` — Popular media server
3. `secubox-vault` — Essential for backup/restore

### Short-term (Phase 8)
4. `secubox-homeassistant` — IoT ecosystem
5. `secubox-zigbee` — Smart home devices
6. `secubox-matrix` — Secure communications

### Medium-term (Phase 9-10)
7. System tools as needed
8. Security extensions for enterprise deployments

---

## Notes

- **Complex packages** requiring LXC: homeassistant, matrix, jitsi, wazuh
- **Go-based packages**: photoprism, gotosocial (may need cross-compile)
- **Easy ports**: Dashboard-only apps with existing daemons in Debian repos
- Total estimated effort: 6-12 months for full coverage
