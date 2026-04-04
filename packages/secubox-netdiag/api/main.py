"""
SecuBox-Deb :: secubox-netdiag
Network Diagnostics Module — Troubleshooting Tools
CyberMind — https://cybermind.fr
Author: Gerald Kerma <devel@cybermind.fr>
License: Proprietary / ANSSI CSPN candidate
"""

from fastapi import FastAPI, APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger
import subprocess
import asyncio
import json
import socket
import re
from pathlib import Path
from typing import Optional, List

app = FastAPI(
    title="secubox-netdiag",
    version="1.0.0",
    root_path="/api/v1/netdiag"
)
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("netdiag")


# ══════════════════════════════════════════════════════════════════
# Status & Health Endpoints
# ══════════════════════════════════════════════════════════════════

@router.get("/status")
async def status(user=Depends(require_jwt)):
    """Module status and available tools."""
    tools = {
        "ping": _tool_available("ping"),
        "traceroute": _tool_available("traceroute"),
        "dig": _tool_available("dig"),
        "whois": _tool_available("whois"),
        "mtr": _tool_available("mtr"),
        "nmap": _tool_available("nmap"),
        "ss": _tool_available("ss"),
        "ip": _tool_available("ip"),
        "iperf3": _tool_available("iperf3"),
    }
    return {
        "module": "netdiag",
        "version": "1.0.0",
        "tools_available": tools,
        "tools_count": sum(1 for v in tools.values() if v),
    }


@router.get("/health")
async def health():
    """Health check endpoint (public)."""
    return {"status": "ok", "module": "netdiag", "version": "1.0.0"}


def _tool_available(tool: str) -> bool:
    """Check if a tool is available on the system."""
    result = subprocess.run(["which", tool], capture_output=True)
    return result.returncode == 0


# ══════════════════════════════════════════════════════════════════
# Ping
# ══════════════════════════════════════════════════════════════════

class PingRequest(BaseModel):
    host: str = Field(..., description="Host to ping (IP or hostname)")
    count: int = Field(default=4, ge=1, le=20, description="Number of packets")


@router.post("/ping")
async def ping(req: PingRequest, user=Depends(require_jwt)):
    """Ping a host and return results."""
    # Validate host - basic sanitization
    host = _sanitize_host(req.host)
    if not host:
        raise HTTPException(400, "Invalid host")

    try:
        result = subprocess.run(
            ["ping", "-c", str(req.count), "-W", "2", host],
            capture_output=True, text=True, timeout=30
        )

        # Parse statistics
        stats = _parse_ping_stats(result.stdout)

        return {
            "success": result.returncode == 0,
            "host": host,
            "count": req.count,
            "output": result.stdout,
            "stats": stats,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "host": host, "error": "Timeout"}
    except Exception as e:
        log.error("ping error: %s", e)
        return {"success": False, "host": host, "error": str(e)}


def _parse_ping_stats(output: str) -> dict:
    """Parse ping output for statistics."""
    stats = {
        "packets_transmitted": 0,
        "packets_received": 0,
        "packet_loss": 100.0,
        "rtt_min": None,
        "rtt_avg": None,
        "rtt_max": None,
    }

    # Parse packet statistics
    match = re.search(r'(\d+) packets transmitted, (\d+) (packets )?received', output)
    if match:
        stats["packets_transmitted"] = int(match.group(1))
        stats["packets_received"] = int(match.group(2))
        if stats["packets_transmitted"] > 0:
            stats["packet_loss"] = round(
                (1 - stats["packets_received"] / stats["packets_transmitted"]) * 100, 1
            )

    # Parse RTT
    match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)', output)
    if match:
        stats["rtt_min"] = float(match.group(1))
        stats["rtt_avg"] = float(match.group(2))
        stats["rtt_max"] = float(match.group(3))

    return stats


# ══════════════════════════════════════════════════════════════════
# Traceroute
# ══════════════════════════════════════════════════════════════════

class TracerouteRequest(BaseModel):
    host: str = Field(..., description="Target host")
    max_hops: int = Field(default=30, ge=1, le=64, description="Maximum hops")


@router.post("/traceroute")
async def traceroute(req: TracerouteRequest, user=Depends(require_jwt)):
    """Traceroute to a host."""
    host = _sanitize_host(req.host)
    if not host:
        raise HTTPException(400, "Invalid host")

    try:
        result = subprocess.run(
            ["traceroute", "-m", str(req.max_hops), "-w", "2", host],
            capture_output=True, text=True, timeout=120
        )

        hops = _parse_traceroute(result.stdout)

        return {
            "success": result.returncode == 0,
            "host": host,
            "output": result.stdout,
            "hops": hops,
            "hop_count": len(hops),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "host": host, "error": "Timeout (max 120s)"}
    except Exception as e:
        log.error("traceroute error: %s", e)
        return {"success": False, "host": host, "error": str(e)}


def _parse_traceroute(output: str) -> list:
    """Parse traceroute output into hop list."""
    hops = []
    for line in output.strip().split('\n')[1:]:  # Skip header
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            hop = {
                "number": parts[0] if parts[0].isdigit() else None,
                "host": parts[1] if len(parts) > 1 else "*",
                "times": [],
            }
            # Extract times (ms values)
            for part in parts[2:]:
                if part.replace('.', '').isdigit():
                    hop["times"].append(float(part))
            hops.append(hop)
    return hops


# ══════════════════════════════════════════════════════════════════
# DNS Lookup
# ══════════════════════════════════════════════════════════════════

class DNSRequest(BaseModel):
    domain: str = Field(..., description="Domain to lookup")
    record_type: str = Field(default="A", description="Record type (A, AAAA, MX, NS, TXT, CNAME, SOA)")
    server: Optional[str] = Field(default=None, description="DNS server to query")


@router.post("/dns")
async def dns_lookup(req: DNSRequest, user=Depends(require_jwt)):
    """DNS lookup for a domain."""
    domain = _sanitize_host(req.domain)
    if not domain:
        raise HTTPException(400, "Invalid domain")

    record_type = req.record_type.upper()
    if record_type not in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]:
        raise HTTPException(400, "Invalid record type")

    cmd = ["dig", "+short", "+time=5", domain, record_type]
    if req.server:
        server = _sanitize_host(req.server)
        if server:
            cmd.insert(1, f"@{server}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        # Also get verbose output
        verbose_cmd = ["dig", "+time=5", domain, record_type]
        if req.server:
            verbose_cmd.insert(1, f"@{_sanitize_host(req.server)}")
        verbose = subprocess.run(verbose_cmd, capture_output=True, text=True, timeout=15)

        records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]

        return {
            "success": True,
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "verbose": verbose.stdout,
            "server": req.server,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "domain": domain, "error": "Timeout"}
    except Exception as e:
        log.error("dns error: %s", e)
        return {"success": False, "domain": domain, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# WHOIS
# ══════════════════════════════════════════════════════════════════

class WhoisRequest(BaseModel):
    target: str = Field(..., description="Domain or IP to query")


@router.post("/whois")
async def whois_lookup(req: WhoisRequest, user=Depends(require_jwt)):
    """WHOIS lookup for a domain or IP."""
    target = _sanitize_host(req.target)
    if not target:
        raise HTTPException(400, "Invalid target")

    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True, text=True, timeout=30
        )

        # Parse key fields
        parsed = _parse_whois(result.stdout)

        return {
            "success": result.returncode == 0,
            "target": target,
            "output": result.stdout,
            "parsed": parsed,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "target": target, "error": "Timeout"}
    except Exception as e:
        log.error("whois error: %s", e)
        return {"success": False, "target": target, "error": str(e)}


def _parse_whois(output: str) -> dict:
    """Extract key fields from WHOIS output."""
    fields = {}
    patterns = {
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creat(?:ed|ion) Date:\s*(.+)",
        "expiry_date": r"(?:Expir(?:y|ation) Date|Registry Expiry Date):\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "status": r"(?:Domain )?Status:\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            fields[key] = matches if len(matches) > 1 else matches[0]

    return fields


# ══════════════════════════════════════════════════════════════════
# Network Ports (Local)
# ══════════════════════════════════════════════════════════════════

@router.get("/ports")
async def list_ports(user=Depends(require_jwt)):
    """List listening ports on the system."""
    try:
        result = subprocess.run(
            ["ss", "-tulnp"],
            capture_output=True, text=True, timeout=10
        )

        ports = _parse_ss_output(result.stdout)

        return {
            "success": True,
            "ports": ports,
            "count": len(ports),
            "raw": result.stdout,
        }
    except Exception as e:
        log.error("ports error: %s", e)
        return {"success": False, "error": str(e)}


def _parse_ss_output(output: str) -> list:
    """Parse ss output into port list."""
    ports = []
    lines = output.strip().split('\n')[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            local_addr = parts[4]
            # Parse address:port
            if ':' in local_addr:
                addr, port = local_addr.rsplit(':', 1)
                ports.append({
                    "proto": parts[0],
                    "state": parts[1] if len(parts) > 1 else "LISTEN",
                    "local_addr": addr,
                    "local_port": int(port) if port.isdigit() else port,
                    "process": parts[-1] if 'users:' in line else None,
                })

    return sorted(ports, key=lambda x: x.get("local_port", 0) if isinstance(x.get("local_port"), int) else 0)


# ══════════════════════════════════════════════════════════════════
# Port Scan (Local Only)
# ══════════════════════════════════════════════════════════════════

class PortScanRequest(BaseModel):
    host: str = Field(..., description="Host to scan (local network only)")
    ports: str = Field(default="1-1024", description="Port range (e.g., '80,443' or '1-1024')")


@router.post("/portscan")
async def port_scan(req: PortScanRequest, user=Depends(require_jwt)):
    """Scan ports on a host (local network only for security)."""
    host = _sanitize_host(req.host)
    if not host:
        raise HTTPException(400, "Invalid host")

    # Security: Only allow local/private network scans
    if not _is_local_network(host):
        raise HTTPException(403, "Port scanning only allowed on local network addresses")

    # Sanitize ports input
    ports = re.sub(r'[^0-9,\-]', '', req.ports)
    if not ports:
        ports = "1-1024"

    try:
        # Use nmap if available, otherwise nc
        if _tool_available("nmap"):
            result = subprocess.run(
                ["nmap", "-p", ports, "--open", "-T4", host],
                capture_output=True, text=True, timeout=120
            )
            open_ports = _parse_nmap_output(result.stdout)
        else:
            # Fallback: simple nc check for common ports
            open_ports = await _nc_scan(host, ports)
            result = type('obj', (object,), {'stdout': f"Scanned ports: {ports}"})()

        return {
            "success": True,
            "host": host,
            "ports_scanned": ports,
            "open_ports": open_ports,
            "output": result.stdout,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "host": host, "error": "Scan timeout"}
    except Exception as e:
        log.error("portscan error: %s", e)
        return {"success": False, "host": host, "error": str(e)}


def _parse_nmap_output(output: str) -> list:
    """Parse nmap output for open ports."""
    ports = []
    in_ports = False

    for line in output.split('\n'):
        if 'PORT' in line and 'STATE' in line:
            in_ports = True
            continue
        if in_ports:
            if not line.strip() or 'Nmap' in line:
                break
            parts = line.split()
            if len(parts) >= 2:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else ""
                if '/' in port_proto:
                    port, proto = port_proto.split('/')
                    if state.lower() == "open":
                        ports.append({
                            "port": int(port),
                            "proto": proto,
                            "state": state,
                            "service": service,
                        })

    return ports


async def _nc_scan(host: str, ports_spec: str) -> list:
    """Simple netcat-based port scan fallback."""
    open_ports = []
    ports_to_scan = []

    # Parse port specification
    for part in ports_spec.split(','):
        if '-' in part:
            start, end = part.split('-')
            ports_to_scan.extend(range(int(start), min(int(end) + 1, int(start) + 100)))
        else:
            ports_to_scan.append(int(part))

    # Limit to 100 ports
    ports_to_scan = ports_to_scan[:100]

    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append({"port": port, "proto": "tcp", "state": "open"})
            sock.close()
        except:
            pass

    return open_ports


def _is_local_network(host: str) -> bool:
    """Check if host is on local/private network."""
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(host)
        parts = [int(p) for p in ip.split('.')]

        # Check private ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if ip == "::1" or ip.startswith("fe80:"):
            return True

        return False
    except:
        return False


# ══════════════════════════════════════════════════════════════════
# Network Interfaces
# ══════════════════════════════════════════════════════════════════

@router.get("/interfaces")
async def interfaces(user=Depends(require_jwt)):
    """List network interfaces with details."""
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=10
        )

        interfaces = json.loads(result.stdout) if result.returncode == 0 else []

        # Enrich with link info
        link_result = subprocess.run(
            ["ip", "-j", "link", "show"],
            capture_output=True, text=True, timeout=10
        )
        links = json.loads(link_result.stdout) if link_result.returncode == 0 else []
        link_map = {l.get("ifname"): l for l in links}

        ifaces = []
        for iface in interfaces:
            name = iface.get("ifname", "")
            link_info = link_map.get(name, {})

            # Get addresses
            addresses = []
            for addr_info in iface.get("addr_info", []):
                addresses.append({
                    "address": addr_info.get("local", ""),
                    "prefix": addr_info.get("prefixlen", 0),
                    "family": addr_info.get("family", ""),
                })

            ifaces.append({
                "name": name,
                "mac": link_info.get("address", ""),
                "mtu": link_info.get("mtu", 0),
                "state": link_info.get("operstate", "unknown"),
                "flags": link_info.get("flags", []),
                "addresses": addresses,
                "type": link_info.get("link_type", ""),
            })

        return {
            "success": True,
            "interfaces": ifaces,
            "count": len(ifaces),
        }
    except Exception as e:
        log.error("interfaces error: %s", e)
        return {"success": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# Routing Table
# ══════════════════════════════════════════════════════════════════

@router.get("/routes")
async def routes(user=Depends(require_jwt)):
    """Show routing table."""
    try:
        result = subprocess.run(
            ["ip", "-j", "route", "show"],
            capture_output=True, text=True, timeout=10
        )

        routes = json.loads(result.stdout) if result.returncode == 0 else []

        # Also get IPv6 routes
        result6 = subprocess.run(
            ["ip", "-j", "-6", "route", "show"],
            capture_output=True, text=True, timeout=10
        )
        routes6 = json.loads(result6.stdout) if result6.returncode == 0 else []

        return {
            "success": True,
            "ipv4": routes,
            "ipv6": routes6,
            "count": len(routes) + len(routes6),
        }
    except Exception as e:
        log.error("routes error: %s", e)
        return {"success": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# ARP Table
# ══════════════════════════════════════════════════════════════════

@router.get("/arp")
async def arp_table(user=Depends(require_jwt)):
    """Show ARP table."""
    try:
        result = subprocess.run(
            ["ip", "-j", "neigh", "show"],
            capture_output=True, text=True, timeout=10
        )

        neighbors = json.loads(result.stdout) if result.returncode == 0 else []

        # Format entries
        entries = []
        for n in neighbors:
            entries.append({
                "ip": n.get("dst", ""),
                "mac": n.get("lladdr", ""),
                "interface": n.get("dev", ""),
                "state": n.get("state", []),
            })

        return {
            "success": True,
            "entries": entries,
            "count": len(entries),
        }
    except Exception as e:
        log.error("arp error: %s", e)
        return {"success": False, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# Active Connections
# ══════════════════════════════════════════════════════════════════

@router.get("/connections")
async def connections(user=Depends(require_jwt)):
    """Show active network connections."""
    try:
        result = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True, text=True, timeout=10
        )

        conns = _parse_connections(result.stdout)

        return {
            "success": True,
            "connections": conns,
            "count": len(conns),
            "raw": result.stdout,
        }
    except Exception as e:
        log.error("connections error: %s", e)
        return {"success": False, "error": str(e)}


def _parse_connections(output: str) -> list:
    """Parse ss output for active connections."""
    connections = []
    lines = output.strip().split('\n')[1:]  # Skip header

    for line in lines:
        parts = line.split()
        if len(parts) >= 5:
            connections.append({
                "proto": parts[0],
                "state": parts[1],
                "recv_q": parts[2] if len(parts) > 2 else "0",
                "send_q": parts[3] if len(parts) > 3 else "0",
                "local": parts[4] if len(parts) > 4 else "",
                "remote": parts[5] if len(parts) > 5 else "",
                "process": parts[-1] if 'users:' in line else "",
            })

    return connections


# ══════════════════════════════════════════════════════════════════
# MTR
# ══════════════════════════════════════════════════════════════════

class MTRRequest(BaseModel):
    host: str = Field(..., description="Target host")
    count: int = Field(default=10, ge=1, le=30, description="Number of pings per hop")


@router.post("/mtr")
async def mtr(req: MTRRequest, user=Depends(require_jwt)):
    """Run MTR (My Traceroute) to a host."""
    host = _sanitize_host(req.host)
    if not host:
        raise HTTPException(400, "Invalid host")

    if not _tool_available("mtr"):
        raise HTTPException(503, "mtr not installed")

    try:
        result = subprocess.run(
            ["mtr", "-r", "-c", str(req.count), "-w", host],
            capture_output=True, text=True, timeout=120
        )

        hops = _parse_mtr(result.stdout)

        return {
            "success": result.returncode == 0,
            "host": host,
            "count": req.count,
            "output": result.stdout,
            "hops": hops,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "host": host, "error": "Timeout"}
    except Exception as e:
        log.error("mtr error: %s", e)
        return {"success": False, "host": host, "error": str(e)}


def _parse_mtr(output: str) -> list:
    """Parse MTR output."""
    hops = []
    for line in output.strip().split('\n')[2:]:  # Skip headers
        if not line.strip() or line.startswith('Start'):
            continue
        parts = line.split()
        if len(parts) >= 8:
            hops.append({
                "hop": parts[0].rstrip('.'),
                "host": parts[1],
                "loss": parts[2],
                "sent": parts[3],
                "last": parts[4],
                "avg": parts[5],
                "best": parts[6],
                "worst": parts[7],
                "stdev": parts[8] if len(parts) > 8 else "0.0",
            })
    return hops


# ══════════════════════════════════════════════════════════════════
# Nmap Scan
# ══════════════════════════════════════════════════════════════════

class NmapRequest(BaseModel):
    host: str = Field(..., description="Target host (local network only)")
    scan_type: str = Field(default="quick", description="Scan type: quick, full, services")


@router.post("/nmap")
async def nmap_scan(req: NmapRequest, user=Depends(require_jwt)):
    """Run basic nmap scan on a host (local network only)."""
    host = _sanitize_host(req.host)
    if not host:
        raise HTTPException(400, "Invalid host")

    # Security: Only allow local network scans
    if not _is_local_network(host):
        raise HTTPException(403, "Nmap scanning only allowed on local network addresses")

    if not _tool_available("nmap"):
        raise HTTPException(503, "nmap not installed")

    # Build command based on scan type
    if req.scan_type == "quick":
        cmd = ["nmap", "-T4", "-F", host]
    elif req.scan_type == "services":
        cmd = ["nmap", "-T4", "-sV", "--top-ports", "100", host]
    elif req.scan_type == "full":
        cmd = ["nmap", "-T4", "-p-", host]
    else:
        cmd = ["nmap", "-T4", "-F", host]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )

        open_ports = _parse_nmap_output(result.stdout)

        return {
            "success": result.returncode == 0,
            "host": host,
            "scan_type": req.scan_type,
            "output": result.stdout,
            "open_ports": open_ports,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "host": host, "error": "Scan timeout (max 5 min)"}
    except Exception as e:
        log.error("nmap error: %s", e)
        return {"success": False, "host": host, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# Bandwidth Test
# ══════════════════════════════════════════════════════════════════

BANDWIDTH_CACHE = Path("/var/cache/secubox/netdiag/bandwidth.json")


@router.get("/bandwidth")
async def get_bandwidth(user=Depends(require_jwt)):
    """Get last bandwidth test results."""
    if BANDWIDTH_CACHE.exists():
        try:
            return json.loads(BANDWIDTH_CACHE.read_text())
        except:
            pass
    return {"success": False, "error": "No bandwidth test results available"}


class BandwidthRequest(BaseModel):
    server: Optional[str] = Field(default=None, description="iperf3 server address")
    duration: int = Field(default=10, ge=5, le=30, description="Test duration in seconds")


@router.post("/bandwidth")
async def run_bandwidth(req: BandwidthRequest, user=Depends(require_jwt)):
    """Run bandwidth test using iperf3."""
    if not _tool_available("iperf3"):
        raise HTTPException(503, "iperf3 not installed")

    # Use public iperf3 servers if none specified
    server = _sanitize_host(req.server) if req.server else "iperf.he.net"

    try:
        # Run iperf3 test
        result = subprocess.run(
            ["iperf3", "-c", server, "-t", str(req.duration), "-J"],
            capture_output=True, text=True, timeout=req.duration + 30
        )

        if result.returncode == 0:
            data = json.loads(result.stdout)

            # Extract summary
            end = data.get("end", {})
            streams = end.get("streams", [{}])
            stream = streams[0] if streams else {}
            sender = stream.get("sender", {})
            receiver = stream.get("receiver", {})

            summary = {
                "success": True,
                "server": server,
                "duration": req.duration,
                "sent_bytes": sender.get("bytes", 0),
                "sent_bps": sender.get("bits_per_second", 0),
                "sent_mbps": round(sender.get("bits_per_second", 0) / 1_000_000, 2),
                "received_bytes": receiver.get("bytes", 0),
                "received_bps": receiver.get("bits_per_second", 0),
                "received_mbps": round(receiver.get("bits_per_second", 0) / 1_000_000, 2),
                "timestamp": data.get("start", {}).get("timestamp", {}).get("time", ""),
            }

            # Cache results
            BANDWIDTH_CACHE.parent.mkdir(parents=True, exist_ok=True)
            BANDWIDTH_CACHE.write_text(json.dumps(summary, indent=2))

            return summary
        else:
            return {
                "success": False,
                "server": server,
                "error": result.stderr or "iperf3 test failed",
            }

    except subprocess.TimeoutExpired:
        return {"success": False, "server": server, "error": "Test timeout"}
    except json.JSONDecodeError:
        return {"success": False, "server": server, "error": "Failed to parse iperf3 output"}
    except Exception as e:
        log.error("bandwidth error: %s", e)
        return {"success": False, "server": server, "error": str(e)}


# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════

def _sanitize_host(host: str) -> Optional[str]:
    """Sanitize and validate host input."""
    if not host:
        return None

    # Remove dangerous characters
    host = host.strip()

    # Basic validation
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-._:]+$', host):
        return None

    # Reject obviously bad inputs
    if any(c in host for c in [';', '&', '|', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\r']):
        return None

    # Length check
    if len(host) > 253:
        return None

    return host


app.include_router(router)
