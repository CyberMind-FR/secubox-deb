# Modules — Networking Stack

Network modules for routing, VPN, DNS, and traffic management.

---

## Overview

| Module | Function | Status |
|--------|----------|--------|
| secubox-wireguard | WireGuard VPN | ✅ Active |
| secubox-haproxy | Load balancer/proxy | ✅ Active |
| secubox-qos | Bandwidth management | ✅ Active |
| secubox-mesh | P2P mesh network | ✅ Active |
| secubox-dns | DNS resolver | ✅ Active |
| secubox-vortex-dns | Advanced DNS | ✅ Active |
| secubox-netmodes | Network modes | ✅ Active |
| secubox-routes | Routing manager | ✅ Active |

---

## secubox-wireguard

Native WireGuard VPN management.

### Features
- Peer management
- QR code generation
- Traffic stats
- Multi-tunnel support

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/wireguard/status` | Tunnel status |
| GET | `/api/v1/wireguard/peers` | List peers |
| POST | `/api/v1/wireguard/peers` | Add peer |
| DELETE | `/api/v1/wireguard/peers/{id}` | Remove peer |
| GET | `/api/v1/wireguard/qr/{id}` | Peer QR code |

---

## secubox-haproxy

High-availability proxy and load balancer.

### Features
- TLS 1.3 termination
- HTTP/2 support
- Health checks
- Rate limiting

### Configuration
```toml
[haproxy]
stats_enabled = true
stats_port = 8404

[haproxy.frontends.https]
bind = "*:443"
mode = "http"
default_backend = "secubox"
```

---

## secubox-qos

Traffic shaping and bandwidth management.

### Features
- HTB queuing
- Per-client limits
- Priority classes
- Real-time stats

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/qos/status` | QoS status |
| GET | `/api/v1/qos/classes` | Traffic classes |
| POST | `/api/v1/qos/limit` | Set client limit |
| GET | `/api/v1/qos/stats` | Bandwidth stats |

---

## secubox-mesh

P2P mesh networking (Tailscale/WireGuard based).

### Features
- Zero-config VPN
- NAT traversal
- Exit nodes
- ACL management

---

## secubox-dns / secubox-vortex-dns

DNS resolver with filtering.

### Features
- Unbound resolver
- Ad/tracker blocking
- DNS-over-TLS/HTTPS
- Custom blocklists

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/dns/status` | Resolver status |
| GET | `/api/v1/dns/stats` | Query statistics |
| GET | `/api/v1/dns/blocklists` | Active blocklists |
| POST | `/api/v1/dns/block` | Add domain to block |

---

## secubox-netmodes

Network mode management (router/bridge/single).

### Modes
| Mode | Description |
|------|-------------|
| router | WAN + LAN bridge, NAT |
| bridge | All interfaces bridged |
| single | Single interface, no bridge |

### Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/netmodes/current` | Current mode |
| POST | `/api/v1/netmodes/set` | Change mode |
| GET | `/api/v1/netmodes/interfaces` | Interface list |

---

## secubox-routes

Static and dynamic routing.

### Features
- Static route management
- Policy routing
- Route monitoring
- Failover rules

---

## Installation

```bash
# Install all network modules
sudo apt install secubox-wireguard secubox-haproxy secubox-qos secubox-dns

# Or install meta-package
sudo apt install secubox-networking
```

---

## See Also

- [[Modules]] — All modules
- [[Modules-Security]] — Security modules
- [[Configuration]] — Network configuration

---

*← Back to [[Home|SecuBox OS]]*
