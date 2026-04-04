# secubox-netdiag

Network Diagnostics Module for SecuBox — Troubleshooting Tools

## Features

### Tools Tab
- **Ping**: ICMP ping with RTT statistics (min/avg/max, packet loss)
- **Traceroute**: Path tracing with hop-by-hop timing
- **DNS Lookup**: Query A, AAAA, MX, NS, TXT, CNAME, SOA records
- **WHOIS**: Domain and IP registration lookup
- **MTR**: My Traceroute — combined ping + traceroute
- **Port Scan**: TCP port scanning (restricted to local network)

### Interfaces Tab
- List all network interfaces
- Display MAC address, MTU, state
- Show IPv4/IPv6 addresses
- Interface up/down status

### Routes Tab
- IPv4 routing table
- IPv6 routing table
- ARP neighbor table

### Connections Tab
- Active TCP/UDP connections
- Connection states (ESTABLISHED, LISTEN, etc.)
- Local and remote addresses
- Process information
- Listening ports

### Bandwidth Testing
- iperf3 integration for throughput testing
- Cached results for quick access

## API Endpoints

All endpoints require JWT authentication except `/health`.

### Status
- `GET /status` — Module status and available tools
- `GET /health` — Health check (public)

### Diagnostic Tools
- `POST /ping` — Ping host `{host, count}`
- `POST /traceroute` — Traceroute `{host, max_hops}`
- `POST /dns` — DNS lookup `{domain, record_type, server}`
- `POST /whois` — WHOIS lookup `{target}`
- `POST /mtr` — MTR `{host, count}`
- `POST /nmap` — Nmap scan `{host, scan_type}` (local only)
- `POST /portscan` — Port scan `{host, ports}` (local only)

### Network Information
- `GET /interfaces` — List network interfaces
- `GET /routes` — Routing table (IPv4/IPv6)
- `GET /arp` — ARP neighbor table
- `GET /connections` — Active connections
- `GET /ports` — Listening ports

### Bandwidth
- `GET /bandwidth` — Get last test results
- `POST /bandwidth` — Run bandwidth test `{server, duration}`

## Security

- **Port scanning is restricted to local/private network addresses only**
- All tool inputs are sanitized to prevent command injection
- JWT authentication required for all diagnostic operations

## Dependencies

- `iputils-ping` — ping utility
- `traceroute` — traceroute utility
- `dnsutils` — dig for DNS lookups
- `whois` — WHOIS client
- `mtr-tiny` — MTR utility
- `nmap` — Network mapper
- `net-tools` — Traditional network tools
- `iproute2` — ip command suite
- `iperf3` (recommended) — Bandwidth testing

## Configuration

The service runs as root to allow access to network diagnostics tools.
Unix socket: `/run/secubox/netdiag.sock`

## Author

Gerald KERMA <devel@cybermind.fr>
CyberMind — https://cybermind.fr
