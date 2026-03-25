# SecuBox Mesh Daemon for OpenWrt

## Objective
Port the SecuBox mesh daemon (secuboxd) from Debian/Go to OpenWrt, maintaining
full compatibility with the Debian version for cross-platform mesh networking.

## Architecture Overview

### Components to Implement

1. **secuboxd** - Mesh daemon (C or Lua for OpenWrt)
   - Identity management (Ed25519 keypairs, DID generation)
   - mDNS service discovery (use umdns or avahi)
   - Topology management with mesh gate election
   - Telemetry collection (system stats)
   - Unix socket control server at `/var/run/secuboxd/topo.sock`

2. **secuboxctl** - CLI management tool
   - Commands: mesh status, mesh peers, mesh topology, mesh nodes
   - Commands: node info, node rotate, telemetry latest

3. **c3box** - Web dashboard (LuCI app or standalone uhttpd CGI)
   - SVG topology visualization
   - Real-time node/edge rendering
   - Connects to secuboxd via Unix socket

### Protocol Compatibility

**mDNS Service Advertisement:**
- Service: `_secubox._udp.local`
- Port: 51820 (WireGuard)
- TXT records:
  - `did=<node-did>`
  - `role=<edge|relay|air-gapped>`
  - `version=0.1.0`

**Control Socket Protocol:**
- Path: `/var/run/secuboxd/topo.sock`
- Format: Newline-terminated commands, JSON responses
- Commands:
  - `mesh.status` → `{"state":"running","peer_count":N,"role":"edge","mesh_gate":"did:...","uptime":123}`
  - `mesh.peers` → `[{"did":"...","address":"10.42.x.x","role":"edge","last_seen":"..."}]`
  - `mesh.topology` → `{"nodes":[...],"edges":[...],"mesh_gate":"..."}`
  - `mesh.nodes` → `[{"did":"...","role":"...","address":"...","zkp_valid":true}]`
  - `node.info` → `{"did":"...","role":"...","public_key":"...","zkp_valid":true}`
  - `node.rotate` → `{"success":true,"new_expiry":"..."}`
  - `telemetry.latest` → `{"cpu_percent":5.2,"memory_percent":45.0,...}`
  - `ping` → `{"pong":true}`

### OpenWrt-Specific Implementation

**Package Structure:**
```
package/secubox/secubox-mesh/
├── Makefile                 # OpenWrt package makefile
├── files/
│   ├── secuboxd.init        # procd init script
│   ├── secuboxd.config      # UCI config template
│   └── secuboxd.hotplug     # Network hotplug script
└── src/
    ├── secuboxd.c           # Main daemon (or Lua)
    ├── discovery.c          # mDNS via umdns
    ├── topology.c           # Mesh topology
    ├── identity.c           # Ed25519 identity
    ├── control.c            # Unix socket server
    └── telemetry.c          # System stats
```

**UCI Configuration (/etc/config/secubox):**
```
config mesh 'mesh'
    option enabled '1'
    option role 'edge'
    option subnet '10.42.0.0/16'
    option mdns_service '_secubox._udp'
    option beacon_interval '30'

config node 'node'
    option did ''
    option keypair '/etc/secubox/node.key'

config telemetry 'telemetry'
    option enabled '1'
    option interval '60'
    option db '/tmp/secubox/telemetry.db'
```

**procd Init Script:**
```sh
#!/bin/sh /etc/rc.common
START=95
STOP=10
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /usr/bin/secuboxd
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

### Dependencies
- libubox (JSON, uloop)
- libubus (optional, for ubus integration)
- umdns or avahi-daemon (mDNS)
- libopenssl or mbedtls (Ed25519)
- wireguard-tools

### LuCI Integration (luci-app-secubox-mesh)
```
luci-app-secubox-mesh/
├── htdocs/luci-static/resources/secubox-mesh/
│   ├── mesh.js              # Topology visualization
│   └── mesh.css
├── luasrc/
│   ├── controller/secubox-mesh.lua
│   └── view/secubox-mesh/
│       └── index.htm
└── root/
    └── usr/libexec/rpcd/luci.secubox-mesh  # RPCD backend
```

### Testing Interoperability

1. Start Debian secuboxd on one machine
2. Start OpenWrt secuboxd on another machine
3. Both should discover each other via mDNS
4. Verify with: `secuboxctl mesh peers` on both sides
5. Topology should show both nodes connected

### Key Differences from Debian Version

| Aspect | Debian (Go) | OpenWrt (C/Lua) |
|--------|-------------|-----------------|
| mDNS | zeroconf lib | umdns/avahi |
| Config | YAML file | UCI |
| Init | systemd | procd |
| JSON | encoding/json | libubox/json |
| Crypto | Go stdlib | mbedtls/openssl |
| Web UI | Go HTTP | uhttpd/LuCI |

### Build Commands

```bash
# In OpenWrt buildroot
./scripts/feeds update -a
./scripts/feeds install secubox-mesh luci-app-secubox-mesh
make menuconfig  # Select packages
make package/secubox-mesh/compile V=s
make package/luci-app-secubox-mesh/compile V=s
```

## Success Criteria

- [ ] secuboxd starts and creates control socket
- [ ] mDNS service advertised and discoverable
- [ ] Peers discovered from Debian nodes
- [ ] secuboxctl commands work identically
- [ ] C3BOX/LuCI shows topology visualization
- [ ] Mesh gate election works across platforms

---

## Reference: Debian Implementation

The Debian implementation is located at:
- `daemon/cmd/secuboxd/` - Main daemon
- `daemon/cmd/secuboxctl/` - CLI tool
- `daemon/c3box/` - Web dashboard
- `daemon/internal/discovery/` - mDNS discovery (zeroconf)
- `daemon/internal/topology/` - Mesh topology management
- `daemon/internal/identity/` - Ed25519 identity
- `daemon/internal/control/` - Unix socket server
- `daemon/internal/telemetry/` - System metrics

---

*CyberMind — SecuBox — 2026*
