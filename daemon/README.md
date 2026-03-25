# SecuBox Mesh Daemon

Go-based mesh networking daemon for SecuBox with Zero-Knowledge Proof authentication.

## Components

- **secuboxd** — Mesh daemon with mDNS discovery, WireGuard topology, and ZKP (GK-HAM-2025)
- **secuboxctl** — CLI tool for managing mesh network
- **c3box** — Situational awareness dashboard backend

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SecuBox Mesh Network                     │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │    Node A    │────│    Node B    │────│    Node C    │  │
│  │   (edge)     │    │   (relay)    │    │ (air-gapped) │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                   │          │
│         └─────────────WireGuard─────────────────┘          │
│                            │                               │
│                      Mesh Gate                             │
│                   (elected relay)                          │
└─────────────────────────────────────────────────────────────┘
```

## Modules

### internal/identity
- DID (Decentralized Identifier) generation and management
- Ed25519 keypair management
- ZKP Hamiltonian proof generation and rotation (24h PFS)

### internal/discovery
- mDNS service advertisement and peer discovery
- WireGuard beacon heartbeats
- Peer lifecycle management

### internal/topology
- Mesh network graph management
- Mesh gate election (relay > edge > air-gapped)
- Route convergence via netlink

### internal/telemetry
- System metrics collection (CPU, memory, disk)
- Security metrics (nftables rules, CrowdSec bans)
- SQLite persistence with 24h retention

### pkg/hamiltonian
- GK-HAM-2025 Zero-Knowledge Proof implementation
- Hamiltonian cycle based authentication
- Proof generation and verification

### pkg/config
- YAML configuration loading
- Node, mesh, telemetry, and ZKP settings

## Build

```bash
# Build all binaries
make build

# Cross-compile for ARM64
make build-arm64

# Run tests
make test

# Install to system
sudo make install
```

## Configuration

```yaml
# /etc/secubox/secuboxd.yaml
node:
  role: edge              # edge | relay | air-gapped
  did: ""                 # auto-generated if empty
  keypair: /etc/secubox/node.key

mesh:
  transport: wireguard
  subnet: 10.42.0.0/16
  mdns_service: _secubox._udp
  beacon_interval: 30     # seconds
  peer_timeout: 120       # seconds

telemetry:
  interval: 60            # seconds
  db: /var/lib/secuboxd/telemetry.db

zkp:
  enabled: true
  rotation_hours: 24
  hamiltonian_graph: /etc/secubox/hamgraph.json
```

## Usage

```bash
# Start daemon
secuboxd --config /etc/secubox/secuboxd.yaml

# CLI commands
secuboxctl mesh status    # Show mesh status
secuboxctl mesh peers     # List mesh peers
secuboxctl node info      # Show node info
secuboxctl node rotate    # Rotate ZKP keys
```

## C3BOX Dashboard

The C3BOX backend serves the situational awareness dashboard:

```bash
# Start C3BOX
c3box --listen :8080 --static /usr/share/c3box/www
```

Access: http://localhost:8080

## Author

Gerald KERMA <devel@cybermind.fr>
https://cybermind.fr | https://secubox.in
