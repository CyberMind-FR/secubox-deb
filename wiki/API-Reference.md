# API Reference

[Français](API-Reference-FR) | [中文](API-Reference-ZH)

All SecuBox modules expose REST APIs via Unix sockets, proxied by nginx at `/api/v1/<module>/`.

**Total: 48 modules | ~1000+ API endpoints**

---

## Authentication

### Login

```bash
curl -X POST https://localhost/api/v1/portal/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}'
```

Response:
```json
{
  "success": true,
  "token": "eyJ...",
  "username": "admin",
  "role": "admin"
}
```

### Using Token

```bash
curl https://localhost/api/v1/hub/status \
  -H 'Authorization: Bearer <token>'
```

---

## Common Endpoints

All modules implement:

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Module status |
| `/health` | GET | No | Health check |

---

## Core Modules

### Hub API (`/api/v1/hub/`)

Dashboard and module management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | System status and module health |
| `/modules` | GET | Yes | List all installed modules |
| `/alerts` | GET | No | System alerts |
| `/monitoring` | GET | Yes | CPU, memory, load metrics |
| `/settings` | GET | Yes | System configuration |
| `/dashboard` | GET | No | Complete dashboard data |
| `/widgets` | GET | Yes | Dashboard widget configuration |
| `/save_widgets` | POST | Yes | Save widget preferences |
| `/security_summary` | GET | Yes | Security overview |
| `/network_summary` | GET | No | Network interface summary |
| `/quick_actions` | GET | Yes | Available quick actions |
| `/execute_action` | POST | Yes | Execute system action |
| `/notifications` | GET | Yes | System notifications |
| `/dismiss_notification` | POST | Yes | Dismiss notification |
| `/dismiss_all_notifications` | POST | Yes | Dismiss all |
| `/theme` | GET | Yes | Current UI theme |
| `/set_theme` | POST | Yes | Set UI theme |
| `/version` | GET | Yes | SecuBox version info |
| `/about` | GET | Yes | Product information |
| `/module_control` | POST | Yes | Start/stop/restart module |
| `/module_status` | GET | Yes | Status of specific module |
| `/module_logs` | GET | Yes | Recent logs of module |
| `/uptime` | GET | Yes | System uptime |
| `/cpu` | GET | Yes | CPU statistics |
| `/memory` | GET | Yes | Memory statistics |
| `/disk` | GET | Yes | Disk statistics |
| `/network_stats` | GET | Yes | Network I/O statistics |
| `/recent_events` | GET | Yes | Recent system events |
| `/system_health` | GET | No | System health score |
| `/preferences` | GET | Yes | User preferences |
| `/save_preferences` | POST | Yes | Save preferences |
| `/logs` | GET | Yes | System journal logs |
| `/check_updates` | GET | Yes | Check for updates |
| `/apply_updates` | POST | Yes | Apply pending updates |
| `/menu` | GET | No | Dynamic sidebar menu |

### Portal API (`/api/v1/portal/`)

Authentication and session management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Portal status |
| `/login` | POST | No | Authenticate user |
| `/logout` | POST | No | End session |
| `/verify` | GET | No | Verify current session |
| `/recover` | POST | No | Password recovery |
| `/sessions` | GET | Yes | List active sessions |
| `/users` | GET | Yes | List all users (admin) |
| `/users/create` | POST | Yes | Create new user (admin) |
| `/users/change-password` | POST | Yes | Change password |

### System API (`/api/v1/system/`)

System administration and diagnostics.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | System status overview |
| `/info` | GET | No | System information |
| `/resources` | GET | No | CPU/memory/disk usage |
| `/services` | GET | No | Services list |
| `/network` | GET | No | Network interfaces |
| `/security` | GET | No | Security status |
| `/packages` | GET | No | Installed SecuBox packages |
| `/restart_services` | POST | Yes | Restart SecuBox services |
| `/reload_firewall` | POST | Yes | Reload nftables |
| `/sync_time` | POST | Yes | Sync with NTP |
| `/clear_cache` | POST | Yes | Clear system caches |
| `/check_updates` | GET | Yes | Check for updates |
| `/apply_updates` | POST | Yes | Apply updates |
| `/shutdown` | POST | Yes | Shutdown system |
| `/reboot` | POST | Yes | Reboot system |
| `/settings` | POST | Yes | Update hostname/timezone |
| `/health_score` | GET | Yes | System health score |
| `/services_list` | GET | Yes | Detailed service list |
| `/logs` | GET | Yes | System logs |
| `/diagnostics` | GET | Yes | Diagnostic report |
| `/service_control` | POST | Yes | Control specific service |
| `/backup` | POST | Yes | Create configuration backup |
| `/restore_config` | POST | Yes | Restore from backup |
| `/get_storage` | GET | Yes | Disk usage per partition |
| `/collect_diagnostics` | POST | Yes | Collect diagnostic report |
| `/list_diagnostics` | GET | Yes | List diagnostic reports |

---

## Security Modules

### CrowdSec API (`/api/v1/crowdsec/`)

Intrusion detection and prevention.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/components` | GET | No | System components |
| `/access` | GET | No | Connection endpoints |
| `/metrics` | GET | Yes | CrowdSec metrics |
| `/decisions` | GET | Yes | Active decisions (bans) |
| `/alerts` | GET | Yes | Security alerts |
| `/bouncers` | GET | Yes | Bouncer status |
| `/ban` | POST | Yes | Ban IP address |
| `/unban` | POST | Yes | Unban IP address |
| `/nftables` | GET | Yes | nftables statistics |
| `/service/start` | POST | Yes | Start CrowdSec |
| `/service/stop` | POST | Yes | Stop CrowdSec |
| `/service/restart` | POST | Yes | Restart CrowdSec |
| `/console/status` | GET | Yes | Console connection status |
| `/console/enroll` | POST | Yes | Enroll to CrowdSec Console |
| `/migrate` | POST | Yes | Migrate from OpenWrt |

#### Ban IP Example
```bash
curl -X POST https://localhost/api/v1/crowdsec/ban \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.168.1.100","duration":"24h","reason":"manual"}'
```

### WAF API (`/api/v1/waf/`)

Web Application Firewall with 300+ rules.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | WAF status |
| `/info` | GET | Yes | Detailed WAF info |
| `/categories` | GET | No | WAF rule categories |
| `/rules` | GET | Yes | All WAF rules |
| `/rules/{category}` | GET | Yes | Rules for category |
| `/category/{category}/toggle` | POST | Yes | Enable/disable category |
| `/stats` | GET | No | Threat statistics |
| `/alerts` | GET | No | Recent threat alerts |
| `/bans` | GET | No | Active IP bans |
| `/ban` | POST | Yes | Manually ban IP |
| `/unban/{ip}` | POST | Yes | Remove IP ban |
| `/check` | POST | Yes | Check request for threats |
| `/reload` | POST | Yes | Reload WAF rules |
| `/whitelist` | GET | Yes | Get whitelisted IPs |
| `/whitelist` | POST | Yes | Add/remove from whitelist |

### MITMProxy WAF API (`/api/v1/mitmproxy/`)

Inline traffic inspection and protection.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Proxy WAF status |
| `/settings` | GET | No | Proxy settings |
| `/alerts` | GET | No | Recent alerts |
| `/threat_stats` | GET | No | Threat statistics |
| `/bans` | GET | No | Current IP bans |
| `/waf_rules` | GET | No | WAF rules config |
| `/save_settings` | POST | Yes | Save proxy settings |
| `/set_mode` | POST | Yes | Set proxy mode |
| `/start` | POST | Yes | Start proxy |
| `/stop` | POST | Yes | Stop proxy |
| `/restart` | POST | Yes | Restart proxy |
| `/setup_firewall` | POST | Yes | Setup firewall rules |
| `/clear_firewall` | POST | Yes | Clear firewall rules |
| `/wan_setup` | POST | Yes | Setup WAN protection |
| `/unban` | POST | Yes | Unban IP |
| `/toggle_waf_category` | POST | Yes | Toggle WAF category |

### Hardening API (`/api/v1/hardening/`)

Kernel and system hardening.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Hardening status |
| `/components` | GET | No | Hardening components |
| `/access` | GET | No | Access information |
| `/benchmark` | POST | Yes | Run security benchmark |
| `/apply` | POST | Yes | Apply hardening settings |
| `/install` | POST | Yes | Install hardening |

### NAC API (`/api/v1/nac/`)

Network Access Control.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | NAC system status |
| `/clients` | GET | Yes | List connected clients |
| `/zones` | GET | Yes | Network zones |
| `/portal_config` | GET | Yes | Portal configuration |
| `/parental_rules` | GET | Yes | Parental control rules |
| `/alerts` | GET | Yes | New client alerts |
| `/logs` | GET | Yes | DHCP/NAC logs |
| `/add_to_zone` | POST | Yes | Move client to zone |
| `/remove_from_zone` | POST | Yes | Remove client from zone |
| `/set_parental_rule` | POST | Yes | Set parental controls |
| `/approve_client` | POST | Yes | Approve new client |
| `/ban_client` | POST | Yes | Ban client |
| `/unban_client` | POST | Yes | Unban client |
| `/quarantine_client` | POST | Yes | Quarantine client |
| `/update_client` | POST | Yes | Update client info |
| `/sync_zones` | GET | Yes | Sync zones with nftables |

### Auth Guardian API (`/api/v1/auth/`)

Captive portal and authentication.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | Auth system status |
| `/sessions` | GET | Yes | Active sessions |
| `/vouchers` | GET | Yes | Guest vouchers |
| `/oauth_providers` | GET | Yes | OAuth providers |
| `/splash_config` | GET | Yes | Splash page config |
| `/bypass_rules` | GET | Yes | Bypass rules |
| `/generate_vouchers` | POST | Yes | Create vouchers |
| `/redeem_voucher` | POST | No | Redeem voucher |
| `/set_provider` | POST | Yes | Configure OAuth provider |
| `/delete_provider` | POST | Yes | Remove provider |
| `/create_voucher` | POST | Yes | Create single voucher |
| `/delete_voucher` | POST | Yes | Delete voucher |
| `/revoke_session` | POST | Yes | Revoke session |
| `/get_logs` | GET | Yes | Authentication logs |

---

## Network Modules

### Network Modes API (`/api/v1/netmodes/`)

Network topology configuration.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | Current network mode |
| `/get_current_mode` | GET | Yes | Current mode details |
| `/get_available_modes` | GET | Yes | Available network modes |
| `/get_interfaces` | GET | Yes | Network interfaces |
| `/preview_changes` | GET | Yes | Preview mode changes |
| `/set_mode` | POST | Yes | Prepare mode change |
| `/apply_mode` | POST | Yes | Apply network mode |
| `/confirm_mode` | POST | Yes | Confirm mode working |
| `/rollback` | POST | Yes | Rollback to previous |
| `/validate_config` | GET | Yes | Validate netplan config |
| `/router_config` | GET | Yes | Router mode config |
| `/ap_config` | GET | Yes | Access point config |
| `/sniffer_config` | GET | Yes | Sniffer mode config |
| `/relay_config` | GET | Yes | Relay mode config |
| `/dmz_config` | GET | Yes | DMZ config |
| `/travel_config` | GET | Yes | Travel mode config |
| `/multiwan_config` | GET | Yes | Multi-WAN config |
| `/vpnrelay_config` | GET | Yes | VPN relay config |
| `/travel_scan_networks` | GET | Yes | Scan WiFi networks |
| `/generate_wireguard_keys` | POST | Yes | Generate WG keys |
| `/enable_tcp_bbr` | POST | Yes | Enable TCP BBR |

### WireGuard API (`/api/v1/wireguard/`)

VPN tunnel management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/components` | GET | No | Components |
| `/status` | GET | No | Health status |
| `/access` | GET | No | Connection endpoints |
| `/interfaces` | GET | No | WireGuard interfaces |
| `/interface/{name}/up` | POST | Yes | Bring interface up |
| `/interface/{name}/down` | POST | Yes | Bring interface down |
| `/peers` | GET | No | Peer list |
| `/peer` | POST | Yes | Add new peer |
| `/peer` | DELETE | Yes | Remove peer |
| `/peer/{name}/config` | GET | Yes | Peer config file |
| `/peer/{name}/qr` | GET | Yes | Peer QR code |
| `/genkey` | POST | Yes | Generate keypair |
| `/genpsk` | POST | Yes | Generate PSK |
| `/migrate` | POST | Yes | Migrate from OpenWrt |

#### Add Peer Example
```bash
curl -X POST https://localhost/api/v1/wireguard/peer \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"mobile","allowed_ips":"10.0.0.2/32"}'
```

### QoS API (`/api/v1/qos/`)

Traffic shaping and bandwidth management. 80+ endpoints.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | QoS status |
| `/classes` | GET | Yes | Traffic classes |
| `/rules` | GET | Yes | Classification rules |
| `/quotas` | GET | Yes | Bandwidth quotas |
| `/usage` | GET | Yes | Current bandwidth usage |
| `/clients` | GET | Yes | Per-client stats |
| `/schedules` | GET | Yes | Bandwidth schedules |
| `/apply_qos` | POST | Yes | Apply QoS config |
| `/set_quota` | POST | Yes | Set client quota |
| `/add_rule` | POST | Yes | Add classification rule |
| `/add_class` | POST | Yes | Add traffic class |
| `/realtime` | GET | Yes | Realtime bandwidth |
| `/bandwidth_history` | GET | Yes | Historical usage |
| `/top_talkers` | GET | Yes | Top bandwidth consumers |
| `/vlans` | GET | Yes | List VLAN interfaces |
| `/vlan/{interface}` | GET | Yes | Get VLAN policy |
| `/vlan/{interface}/policy` | POST | Yes | Set VLAN policy |
| `/vlan/create` | POST | Yes | Create VLAN |
| `/vlan/apply_all` | POST | Yes | Apply to all VLANs |
| `/pcp/mappings` | GET | Yes | Get 802.1p mappings |
| `/pcp/mapping` | POST | Yes | Set PCP mapping |
| `/parental` | GET | Yes | Parental controls |
| `/set_parental` | POST | Yes | Set parental rule |
| `/dpi_apps` | GET | Yes | DPI-detected apps |
| `/add_dpi_rule` | POST | Yes | Add DPI rule |

### DPI API (`/api/v1/dpi/`)

Deep Packet Inspection. 40+ endpoints.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | DPI status |
| `/flows` | GET | Yes | Active flows |
| `/applications` | GET | Yes | Detected applications |
| `/devices` | GET | Yes | Connected devices |
| `/risks` | GET | Yes | Security risks |
| `/talkers` | GET | Yes | Top talkers |
| `/apps` | GET | Yes | Applications list |
| `/protocols` | GET | Yes | Detected protocols |
| `/categories` | GET | Yes | App categories |
| `/top_apps` | GET | Yes | Top applications |
| `/bandwidth_by_app` | GET | Yes | BW per application |
| `/bandwidth_by_device` | GET | Yes | BW per device |
| `/active_flows` | GET | Yes | Current flows |
| `/flow_details` | GET | Yes | Detailed flow info |
| `/realtime` | GET | Yes | Realtime DPI stats |
| `/stats` | GET | Yes | DPI statistics |
| `/block_rules` | GET | Yes | App blocking rules |
| `/add_block_rule` | POST | Yes | Create block rule |
| `/delete_block_rule` | POST | Yes | Delete block rule |
| `/alerts` | GET | Yes | DPI alerts |
| `/dns_queries` | GET | Yes | DNS queries |
| `/ssl_flows` | GET | Yes | SSL/TLS flows |
| `/ssl_fingerprints` | GET | Yes | SSL fingerprints |
| `/settings` | GET | Yes | DPI settings |
| `/save_settings` | POST | Yes | Save settings |
| `/start` | POST | Yes | Start DPI |
| `/stop` | POST | Yes | Stop DPI |
| `/restart` | POST | Yes | Restart DPI |
| `/setup_mirred` | POST | Yes | Setup tc mirred |

### Traffic API (`/api/v1/traffic/`)

TC/CAKE QoS traffic shaping.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Traffic shaping status |
| `/interfaces` | GET | Yes | Network interfaces |
| `/policy/{interface}` | GET | Yes | Interface policy |
| `/policy/{interface}` | POST | Yes | Set interface policy |
| `/policy/{interface}` | DELETE | Yes | Remove policy |
| `/apply` | POST | Yes | Apply all policies |
| `/stats/{interface}` | GET | Yes | Interface statistics |
| `/presets` | GET | Yes | Available presets |

---

## Services Modules

### HAProxy API (`/api/v1/haproxy/`)

Load balancer management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | HAProxy status |
| `/components` | GET | No | Components |
| `/access` | GET | No | Connection endpoints |
| `/stats` | GET | Yes | HAProxy statistics |
| `/backends` | GET | Yes | Backend servers |
| `/frontends` | GET | Yes | Frontend listeners |
| `/acls` | GET | Yes | Access control lists |
| `/waf/status` | GET | Yes | WAF integration status |
| `/waf/toggle` | POST | Yes | Toggle WAF |
| `/waf/routes` | GET | Yes | WAF routes |
| `/waf/sync-routes` | POST | Yes | Sync routes to WAF |
| `/reload` | POST | Yes | Reload configuration |
| `/restart` | POST | Yes | Restart service |

### VHost API (`/api/v1/vhost/`)

Virtual host management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | VHost status |
| `/components` | GET | No | Components |
| `/access` | GET | No | Connection endpoints |
| `/vhosts` | GET | Yes | List virtual hosts |
| `/vhost/{domain}` | GET | Yes | Virtual host details |
| `/vhost` | POST | Yes | Create virtual host |
| `/vhost/{domain}` | PUT | Yes | Update virtual host |
| `/vhost/{domain}` | DELETE | Yes | Delete virtual host |
| `/certificates` | GET | No | SSL certificates |
| `/certificate/issue` | POST | Yes | Issue Let's Encrypt cert |
| `/reload` | POST | Yes | Reload nginx |
| `/test` | POST | Yes | Test configuration |
| `/migrate` | POST | Yes | Migrate from OpenWrt |
| `/logs/{domain}` | GET | Yes | Virtual host logs |

### Netdata API (`/api/v1/netdata/`)

System monitoring proxy.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Netdata status |
| `/info` | GET | Yes | Netdata info |
| `/charts` | GET | Yes | Available charts |
| `/data` | GET | Yes | Chart data |
| `/stats` | GET | No | System stats |
| `/cpu` | GET | Yes | CPU metrics |
| `/memory` | GET | Yes | Memory metrics |
| `/disk` | GET | Yes | Disk metrics |
| `/network` | GET | Yes | Network metrics |
| `/processes` | GET | Yes | Process list |
| `/sensors` | GET | Yes | Hardware sensors |
| `/alerts` | GET | Yes | Active alerts |
| `/alarms` | GET | Yes | Alarm list |
| `/restart_netdata` | POST | Yes | Restart service |
| `/secubox_logs` | GET | Yes | SecuBox logs |

### CDN Cache API (`/api/v1/cdn/`)

Content caching and delivery.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | CDN cache status |
| `/policies` | GET | Yes | Caching policies |
| `/cache_stats` | GET | Yes | Cache statistics |
| `/purge` | POST | Yes | Purge cache |
| `/add_policy` | POST | Yes | Add cache policy |
| `/remove_policy` | POST | Yes | Remove policy |
| `/cache_list` | GET | Yes | Cached objects |
| `/top_domains` | GET | Yes | Top cached domains |
| `/bandwidth_savings` | POST | Yes | Calculate savings |
| `/purge_cache` | POST | Yes | Purge all cache |
| `/purge_domain` | POST | Yes | Purge domain cache |
| `/preload_url` | GET | Yes | Preload URL to cache |
| `/hit_ratio` | GET | Yes | Cache hit ratio |
| `/cache_size` | GET | Yes | Cache size info |
| `/mesh/status` | GET | Yes | Mesh cache status |
| `/mesh/peers` | GET | Yes | Mesh peers |
| `/mesh/add_peer` | POST | Yes | Add mesh peer |
| `/mesh/sync` | POST | Yes | Sync cache |

### Media Flow API (`/api/v1/mediaflow/`)

Streaming service detection.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | Media flow status |
| `/services` | GET | Yes | Detected services |
| `/clients` | GET | Yes | Connected clients |
| `/history` | GET | Yes | Stream history |
| `/alerts` | GET | Yes | Alerts |
| `/get_active_streams` | GET | Yes | Active streams |
| `/get_stats_by_service` | GET | Yes | Stats per service |
| `/get_stats_by_client` | GET | Yes | Stats per client |
| `/set_alert` | POST | Yes | Create alert |
| `/delete_alert` | POST | Yes | Delete alert |
| `/get_settings` | GET | Yes | Settings |
| `/set_settings` | POST | Yes | Save settings |
| `/start_netifyd` | POST | Yes | Start DPI |
| `/stop_netifyd` | POST | Yes | Stop DPI |

---

## Application Modules

### Mail API (`/api/v1/mail/`)

Email server management (Postfix/Dovecot).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Mail server status |
| `/components` | GET | No | Mail components |
| `/access` | GET | No | Connection info |
| `/users` | GET | Yes | Mail users |
| `/user` | POST | Yes | Create user |
| `/user/{email}` | DELETE | Yes | Delete user |
| `/aliases` | GET | Yes | Mail aliases |
| `/alias` | POST | Yes | Create alias |
| `/domains` | GET | Yes | Mail domains |
| `/domain` | POST | Yes | Add domain |
| `/dkim/status` | GET | Yes | DKIM status |
| `/dkim/setup` | POST | Yes | Setup DKIM |
| `/dkim/keygen` | POST | Yes | Generate DKIM keys |
| `/spam/status` | GET | Yes | SpamAssassin status |
| `/spam/setup` | POST | Yes | Setup SpamAssassin |
| `/spam/enable` | POST | Yes | Enable spam filter |
| `/spam/disable` | POST | Yes | Disable spam filter |
| `/grey/status` | GET | Yes | Postgrey status |
| `/grey/setup` | POST | Yes | Setup greylisting |
| `/av/status` | GET | Yes | ClamAV status |
| `/av/setup` | POST | Yes | Setup antivirus |
| `/av/update` | POST | Yes | Update virus defs |
| `/acme/status` | GET | Yes | SSL cert status |
| `/acme/issue` | POST | Yes | Issue certificate |
| `/webmail/install` | POST | Yes | Install webmail |
| `/webmail/start` | POST | Yes | Start webmail |
| `/webmail/stop` | POST | Yes | Stop webmail |
| `/settings` | GET | Yes | Mail settings |
| `/settings` | POST | Yes | Save settings |
| `/logs` | GET | Yes | Mail logs |
| `/repair/{user}` | POST | Yes | Repair mailbox |

### DNS API (`/api/v1/dns/`)

BIND DNS server management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | DNS server status |
| `/zones` | GET | Yes | DNS zones |
| `/zone/{name}` | GET | Yes | Zone details |
| `/zone` | POST | Yes | Create zone |
| `/zone/{name}` | DELETE | Yes | Delete zone |
| `/records/{zone}` | GET | Yes | Zone records |
| `/record` | POST | Yes | Add record |
| `/record` | DELETE | Yes | Delete record |
| `/dnssec/status/{zone}` | GET | Yes | DNSSEC status |
| `/dnssec/enable/{zone}` | POST | Yes | Enable DNSSEC |
| `/reload` | POST | Yes | Reload BIND |

### Users API (`/api/v1/users/`)

Unified identity management for 7 services.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | Yes | Users system status |
| `/users` | GET | Yes | List all users |
| `/user/{username}` | GET | Yes | User details |
| `/user` | POST | Yes | Create user |
| `/user/{username}` | PUT | Yes | Update user |
| `/user/{username}` | DELETE | Yes | Delete user |
| `/user/{username}/enable` | POST | Yes | Enable user |
| `/user/{username}/disable` | POST | Yes | Disable user |
| `/user/{username}/passwd` | POST | Yes | Change password |
| `/groups` | GET | Yes | List groups |
| `/group` | POST | Yes | Create group |
| `/group/{name}` | DELETE | Yes | Delete group |
| `/import` | POST | Yes | Bulk import users |
| `/export` | GET | Yes | Export users |
| `/sync` | POST | Yes | Sync to services |

### Gitea API (`/api/v1/gitea/`)

Git server management (LXC).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Gitea status |
| `/components` | GET | No | Components |
| `/access` | GET | No | Connection info |
| `/install` | POST | Yes | Install Gitea LXC |
| `/start` | POST | Yes | Start container |
| `/stop` | POST | Yes | Stop container |
| `/restart` | POST | Yes | Restart container |
| `/users` | GET | Yes | Gitea users |
| `/repos` | GET | Yes | Repositories |
| `/backup` | POST | Yes | Backup Gitea |
| `/restore` | POST | Yes | Restore backup |

### Nextcloud API (`/api/v1/nextcloud/`)

File sync and collaboration (LXC).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Nextcloud status |
| `/components` | GET | No | Components |
| `/access` | GET | No | Connection info |
| `/install` | POST | Yes | Install Nextcloud LXC |
| `/start` | POST | Yes | Start container |
| `/stop` | POST | Yes | Stop container |
| `/restart` | POST | Yes | Restart container |
| `/users` | GET | Yes | Nextcloud users |
| `/storage` | GET | Yes | Storage info |
| `/apps` | GET | Yes | Installed apps |
| `/backup` | POST | Yes | Backup data |
| `/restore` | POST | Yes | Restore backup |

---

## Container & Infrastructure Modules

### Backup API (`/api/v1/backup/`)

System and container backup.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Backup status |
| `/list` | GET | Yes | List backups |
| `/create` | POST | Yes | Create backup |
| `/restore/{id}` | POST | Yes | Restore backup |
| `/delete/{id}` | DELETE | Yes | Delete backup |
| `/schedule` | GET | Yes | Backup schedule |
| `/schedule` | POST | Yes | Set schedule |
| `/containers` | GET | Yes | LXC containers |
| `/container/{name}/backup` | POST | Yes | Backup container |
| `/container/{name}/restore` | POST | Yes | Restore container |

### Watchdog API (`/api/v1/watchdog/`)

Service and endpoint monitoring.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Watchdog status |
| `/monitors` | GET | Yes | List monitors |
| `/monitor` | POST | Yes | Create monitor |
| `/monitor/{id}` | DELETE | Yes | Delete monitor |
| `/alerts` | GET | Yes | Active alerts |
| `/history` | GET | Yes | Alert history |
| `/containers` | GET | Yes | Container status |
| `/services` | GET | Yes | Service status |
| `/endpoints` | GET | Yes | Endpoint checks |

### Tor API (`/api/v1/tor/`)

Tor network integration.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Tor status |
| `/circuits` | GET | Yes | Active circuits |
| `/hidden_services` | GET | Yes | Hidden services |
| `/hidden_service` | POST | Yes | Create .onion |
| `/hidden_service/{name}` | DELETE | Yes | Delete .onion |
| `/exit_policy` | GET | Yes | Exit policy |
| `/bandwidth` | GET | Yes | Bandwidth stats |
| `/start` | POST | Yes | Start Tor |
| `/stop` | POST | Yes | Stop Tor |
| `/new_identity` | POST | Yes | Request new identity |

### Exposure API (`/api/v1/exposure/`)

Service exposure settings (Tor, SSL, DNS, Mesh).

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Exposure status |
| `/tor` | GET | Yes | Tor exposure config |
| `/tor` | POST | Yes | Set Tor exposure |
| `/ssl` | GET | Yes | SSL exposure config |
| `/ssl` | POST | Yes | Set SSL exposure |
| `/dns` | GET | Yes | DNS exposure config |
| `/dns` | POST | Yes | Set DNS exposure |
| `/mesh` | GET | Yes | Mesh exposure config |
| `/mesh` | POST | Yes | Set mesh exposure |
| `/all` | GET | Yes | All exposure settings |

---

## Intelligence Modules

### Device Intel API (`/api/v1/device-intel/`)

Asset discovery and fingerprinting.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Discovery status |
| `/devices` | GET | Yes | Discovered devices |
| `/device/{mac}` | GET | Yes | Device details |
| `/device/{mac}` | PUT | Yes | Update device info |
| `/scan` | POST | Yes | Trigger active scan |
| `/vendors` | GET | Yes | MAC vendor lookup |
| `/dhcp_leases` | GET | Yes | DHCP leases |
| `/arp_table` | GET | Yes | ARP table |
| `/interfaces` | GET | Yes | Network interfaces |
| `/trusted` | GET | Yes | Trusted devices |
| `/trust/{mac}` | POST | Yes | Mark as trusted |
| `/untrust/{mac}` | POST | Yes | Remove trust |

### Vortex DNS API (`/api/v1/vortex-dns/`)

DNS firewall with threat feeds.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | DNS firewall status |
| `/blocklists` | GET | Yes | Active blocklists |
| `/blocklist` | POST | Yes | Add blocklist |
| `/blocklist/{id}` | DELETE | Yes | Remove blocklist |
| `/rules` | GET | Yes | Custom rules |
| `/rule` | POST | Yes | Add custom rule |
| `/rule/{id}` | DELETE | Yes | Delete rule |
| `/feeds` | GET | Yes | Threat feeds |
| `/feed/{name}/update` | POST | Yes | Update feed |
| `/stats` | GET | Yes | Block statistics |
| `/query_log` | GET | Yes | DNS query log |

### Vortex Firewall API (`/api/v1/vortex-firewall/`)

nftables threat enforcement.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Firewall status |
| `/blocklists` | GET | Yes | IP blocklists |
| `/blocklist` | POST | Yes | Add blocklist |
| `/blocklist/{id}` | DELETE | Yes | Remove blocklist |
| `/rules` | GET | Yes | Custom IP rules |
| `/rule` | POST | Yes | Add custom rule |
| `/rule/{id}` | DELETE | Yes | Delete rule |
| `/feeds` | GET | Yes | Threat feeds |
| `/feed/{name}/update` | POST | Yes | Update feed |
| `/stats` | GET | Yes | Block statistics |
| `/nftables/sets` | GET | Yes | nftables sets |

### SOC API (`/api/v1/soc/`)

Security Operations Center dashboard.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | SOC status |
| `/clock` | GET | No | World clock (10 zones) |
| `/map` | GET | No | World threat map |
| `/tickets` | GET | Yes | Security tickets |
| `/ticket` | POST | Yes | Create ticket |
| `/ticket/{id}` | PUT | Yes | Update ticket |
| `/ticket/{id}` | DELETE | Yes | Delete ticket |
| `/intel` | GET | Yes | Threat intel IOCs |
| `/intel` | POST | Yes | Add IOC |
| `/peers` | GET | Yes | P2P intel peers |
| `/alerts` | GET | Yes | Security alerts |
| `/stats` | GET | Yes | SOC statistics |
| `/ws` | WebSocket | Yes | Real-time updates |

### Metrics API (`/api/v1/metrics/`)

Real-time system metrics dashboard.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Metrics status |
| `/health` | GET | No | Health check |
| `/overview` | GET | No | System overview |
| `/waf_stats` | GET | No | WAF statistics |
| `/connections` | GET | No | TCP connections |
| `/all` | GET | No | All metrics combined |
| `/refresh` | POST | Yes | Force refresh cache |
| `/certs` | GET | No | SSL certificates |
| `/vhosts` | GET | No | Virtual hosts |

### Meshname API (`/api/v1/meshname/`)

Mesh network DNS resolution.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Meshname status |
| `/nodes` | GET | Yes | Mesh nodes |
| `/node` | POST | Yes | Register node |
| `/node/{id}` | DELETE | Yes | Unregister node |
| `/hosts` | GET | Yes | mDNS hosts |
| `/resolve/{name}` | GET | Yes | Resolve mesh name |
| `/test` | GET | Yes | DNS resolver test |

---

## Other Modules

### Mesh API (`/api/v1/mesh/`)

Yggdrasil mesh network.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Mesh network status |
| `/peers` | GET | Yes | Connected peers |
| `/add_peer` | POST | Yes | Add peer |
| `/remove_peer` | POST | Yes | Remove peer |
| `/routes` | GET | Yes | Routing table |
| `/keys` | GET | Yes | Node keys |

### P2P API (`/api/v1/p2p/`)

Peer-to-peer networking.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | P2P status |
| `/peers` | GET | Yes | Connected peers |
| `/discover` | POST | Yes | Discover peers |
| `/share` | POST | Yes | Share resource |
| `/resources` | GET | Yes | Shared resources |

### ZKP API (`/api/v1/zkp/`)

Zero-knowledge proof system.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | ZKP status |
| `/generate` | POST | Yes | Generate proof |
| `/verify` | POST | Yes | Verify proof |
| `/challenges` | GET | Yes | Active challenges |

### Repo API (`/api/v1/repo/`)

APT repository management.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Repository status |
| `/components` | GET | No | Components |
| `/access` | GET | No | Access info |
| `/packages` | GET | Yes | List packages |
| `/add_package` | POST | Yes | Add package |
| `/remove_package` | POST | Yes | Remove package |
| `/sign` | POST | Yes | Sign repository |
| `/sync` | POST | Yes | Sync to remote |

### Roadmap API (`/api/v1/roadmap/`)

Migration tracking.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/status` | GET | No | Roadmap status |
| `/phases` | GET | No | Migration phases |
| `/modules` | GET | No | Module status |
| `/progress` | GET | No | Overall progress |

---

## Error Responses

```json
{
  "success": false,
  "error": "Unauthorized",
  "code": 401
}
```

| Code | Description |
|------|-------------|
| 400 | Bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 500 | Server error |

---

## Rate Limiting

- 100 requests/minute per IP (unauthenticated)
- 1000 requests/minute per user (authenticated)

---

## WebSocket

Real-time updates available at `wss://localhost/api/v1/<module>/ws`:

```javascript
const ws = new WebSocket('wss://localhost/api/v1/soc/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Update:', data);
};
```

Modules with WebSocket support:
- `/api/v1/soc/ws` — SOC real-time alerts
- `/api/v1/dpi/ws` — Flow updates
- `/api/v1/qos/ws` — Bandwidth stats

---

## Architecture Notes

**Socket-Based Communication:**
- Each module runs on Unix socket: `/run/secubox/<module>.sock`
- Nginx reverse-proxies: `http+unix:///run/secubox/<module>.sock`

**Authentication Pattern:**
- JWT tokens via `Authorization: Bearer <token>`
- Issued by `/api/v1/portal/login`
- 24-hour expiration by default

**Three-fold Commands:**
Modules with `*ctl` CLI tools expose:
- `/components` — System components (public)
- `/access` — Connection endpoints (public)

---

## See Also

- [[Installation]] - Setup guide
- [[Modules]] - Module details
- [[Configuration]] - API configuration
