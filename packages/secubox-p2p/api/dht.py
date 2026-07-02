# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-p2p :: dht

Implémentation d'une DHT (Distributed Hash Table) basée sur Kademlia
pour la découverte de pairs distribuée.

Cette DHT permet:
- Découverte de pairs à travers différents sous-réseaux
- Résilience aux nœuds temporairement hors ligne
- Scalabilité pour grand nombre de nœuds
- Intégration avec le mesh WireGuard existant

Spec: Issue P2P-EVO-2026-07-001
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

import aiohttp
from aiohttp import web

log = logging.getLogger("secubox.p2p.dht")

# Constants
DHT_PORT = 6881  # Port standard DHT (compatible avec BitTorrent DHT)
KAD_B = 8  # Bucket size (Kademlia parameter)
KAD_CONCURRENCY = 3  # Concurrent requests per lookup
NODE_ID_LENGTH = 20  # 160-bit node IDs (SHA-1)
MAX_PEERS = 1000  # Maximum peers to store
PEER_TIMEOUT = 900  # 15 minutes peer timeout


@dataclass
class DHTNode:
    """Represents a node in the DHT network."""
    node_id: str  # 20-byte hex string
    ip: str
    port: int
    last_seen: float = field(default_factory=time.time)
    
    def is_expired(self) -> bool:
        """Check if this node entry has expired."""
        return time.time() - self.last_seen > PEER_TIMEOUT
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "port": self.port,
            "last_seen": self.last_seen
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DHTNode":
        """Create from dictionary."""
        return cls(
            node_id=data["node_id"],
            ip=data["ip"],
            port=data["port"],
            last_seen=data.get("last_seen", time.time())
        )


@dataclass
class DHTBucket:
    """Kademlia bucket for storing nodes."""
    nodes: List[DHTNode] = field(default_factory=list)
    last_changed: float = field(default_factory=time.time)
    
    def add_node(self, node: DHTNode) -> bool:
        """Add node to bucket if not full and not already present."""
        # Check if node already exists
        existing_ids = {n.node_id for n in self.nodes}
        if node.node_id in existing_ids:
            # Update existing node
            for i, n in enumerate(self.nodes):
                if n.node_id == node.node_id:
                    self.nodes[i] = node
                    return False
        
        # If bucket is full, don't add
        if len(self.nodes) >= KAD_B:
            return False
        
        # Add new node
        self.nodes.append(node)
        self.last_changed = time.time()
        return True
    
    def get_nodes(self, exclude_id: Optional[str] = None) -> List[DHTNode]:
        """Get nodes from bucket, optionally excluding one."""
        if exclude_id:
            return [n for n in self.nodes if n.node_id != exclude_id and not n.is_expired()]
        return [n for n in self.nodes if not n.is_expired()]
    
    def remove_expired(self) -> int:
        """Remove expired nodes and return count removed."""
        initial_count = len(self.nodes)
        self.nodes = [n for n in self.nodes if not n.is_expired()]
        return initial_count - len(self.nodes)


class DHTNetwork:
    """
    Kademlia-based DHT network implementation.
    
    This provides distributed peer discovery and service announcement
    for the SecuBox P2P network.
    """
    
    def __init__(self, node_id: Optional[str] = None, ip: str = "0.0.0.0", port: int = DHT_PORT):
        """
        Initialize DHT network.
        
        Args:
            node_id: Optional node ID (20-byte hex string). If None, generated.
            ip: IP address to bind to
            port: Port to listen on
        """
        self.node_id = node_id or self._generate_node_id()
        self.ip = ip
        self.port = port
        
        # Routing table: 160-bit ID space divided into buckets
        self.buckets: List[DHTBucket] = [DHTBucket() for _ in range(160)]
        
        # Store key-value pairs (for service discovery)
        self.store: Dict[str, Tuple[Any, float]] = {}  # key -> (value, expiry)
        
        # Known bootstrap nodes
        self.bootstrap_nodes: List[Tuple[str, int]] = []
        
        # UDP socket for DHT communication
        self.socket: Optional[socket.socket] = None
        self.server_task: Optional[asyncio.Task] = None
        
        # Peer discovery state
        self.known_peers: Dict[str, DHTNode] = {}
        self.peer_lock = asyncio.Lock()
        
        # HTTP server for REST API
        self.web_app: Optional[web.Application] = None
        self.web_runner: Optional[web.AppRunner] = None
        self.web_site: Optional[web.TCPSite] = None
        
        log.info(f"DHT node initialized: {self.node_id[:8]}... on {ip}:{port}")
    
    def _generate_node_id(self) -> str:
        """Generate a random 20-byte node ID."""
        # Use SHA-1 of random bytes + current time for uniqueness
        random_bytes = random.randbytes(20)
        timestamp = str(time.time()).encode()
        hash_input = random_bytes + timestamp
        return hashlib.sha1(hash_input).hexdigest()
    
    def _get_bucket_index(self, node_id: str) -> int:
        """Get bucket index for a node ID (XOR distance from our ID)."""
        # Calculate XOR distance and find first differing bit
        xor_result = int(self.node_id, 16) ^ int(node_id, 16)
        
        # Find position of highest set bit
        if xor_result == 0:
            return 0
        
        distance = 159  # Max distance
        for i in range(159, -1, -1):
            if xor_result & (1 << i):
                distance = i
                break
        
        return distance
    
    def add_bootstrap_node(self, ip: str, port: int):
        """Add a bootstrap node for initial connection."""
        self.bootstrap_nodes.append((ip, port))
        log.info(f"Added bootstrap node: {ip}:{port}")
    
    async def start(self, web_port: int = 8732):
        """Start DHT network (UDP listener + HTTP API)."""
        # Start UDP listener
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.ip, self.port))
        self.socket.setblocking(False)
        
        # Create loop for UDP messages
        loop = asyncio.get_event_loop()
        self.server_task = loop.create_task(self._udp_server())
        
        # Start HTTP API
        await self._start_web_api(web_port)
        
        log.info(f"DHT network started on {self.ip}:{self.port} (UDP) and :{web_port} (HTTP)")
        
        # Perform initial bootstrap
        await self.bootstrap()
    
    async def stop(self):
        """Stop DHT network."""
        if self.server_task:
            self.server_task.cancel()
            try:
                await self.server_task
            except asyncio.CancelledError:
                pass
        
        if self.socket:
            self.socket.close()
        
        if self.web_runner:
            await self.web_runner.cleanup()
        
        log.info("DHT network stopped")
    
    async def _udp_server(self):
        """UDP server for DHT messages."""
        loop = asyncio.get_event_loop()
        
        while True:
            try:
                data, addr = await loop.run_in_executor(
                    None, self.socket.recvfrom, 4096
                )
                await self._handle_message(data, addr)
            except Exception as e:
                log.error(f"UDP server error: {e}")
                await asyncio.sleep(1)
    
    async def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming DHT message."""
        try:
            message = self._parse_message(data)
            message_type = message.get("y", "")
            transaction_id = message.get("t")
            
            log.debug(f"Received DHT message: {message_type} from {addr}")
            
            if message_type == "q":  # Query
                query_type = message.get("q", "")
                if query_type == "ping":
                    await self._handle_ping(message, addr, transaction_id)
                elif query_type == "find_node":
                    await self._handle_find_node(message, addr, transaction_id)
                elif query_type == "get_peers":
                    await self._handle_get_peers(message, addr, transaction_id)
                elif query_type == "announce_peer":
                    await self._handle_announce_peer(message, addr, transaction_id)
                
            elif message_type == "r":  # Response
                await self._handle_response(message, addr)
            
        except Exception as e:
            log.error(f"Error handling DHT message: {e}")
    
    def _parse_message(self, data: bytes) -> Dict[str, Any]:
        """Parse bencoded DHT message."""
        # Simple JSON parsing for now (can be extended to bencode)
        try:
            # Try JSON first
            return json.loads(data.decode('utf-8'))
        except:
            # Fallback to basic bencode parsing
            return self._bdecode(data)
    
    def _bencode(self, data: Any) -> bytes:
        """Bencode encoding."""
        if isinstance(data, int):
            return f"i{data}e".encode()
        elif isinstance(data, bytes):
            return f"{len(data)}:".encode() + data
        elif isinstance(data, str):
            return f"{len(data)}:".encode() + data.encode()
        elif isinstance(data, list):
            return b"l" + b"".join(self._bencode(item) for item in data) + b"e"
        elif isinstance(data, dict):
            items = []
            # Sort keys for consistent encoding
            for key in sorted(data.keys()):
                items.append(self._bencode(key) + self._bencode(data[key]))
            return b"d" + b"".join(items) + b"e"
        else:
            raise TypeError(f"Cannot bencode {type(data)}")
    
    def _bdecode(self, data: bytes) -> Any:
        """Bencode decoding."""
        if not data:
            raise ValueError("Empty data")
        
        first_char = data[0:1]
        
        if first_char == b"i":
            # Integer
            end = data.index(b"e", 1)
            return int(data[1:end])
        elif first_char == b"l":
            # List
            items = []
            rest = data[1:]
            while rest[0:1] != b"e":
                item, rest = self._bdecode_single(rest)
                items.append(item)
            return items
        elif first_char == b"d":
            # Dictionary
            result = {}
            rest = data[1:]
            while rest[0:1] != b"e":
                key, rest = self._bdecode_single(rest)
                value, rest = self._bdecode_single(rest)
                result[key] = value
            return result
        else:
            # String
            colon_pos = data.index(b":")
            length = int(data[:colon_pos])
            start = colon_pos + 1
            end = start + length
            return data[start:end].decode('utf-8')
    
    def _bdecode_single(self, data: bytes) -> Tuple[Any, bytes]:
        """Decode a single bencoded item and return (item, remaining_data)."""
        if data[0:1] == b"i":
            end = data.index(b"e", 1) + 1
            return int(data[1:end-1]), data[end:]
        elif data[0:1] == b"l":
            items = []
            rest = data[1:]
            while rest[0:1] != b"e":
                item, rest = self._bdecode_single(rest)
                items.append(item)
            return items, rest[1:]
        elif data[0:1] == b"d":
            result = {}
            rest = data[1:]
            while rest[0:1] != b"e":
                key, rest = self._bdecode_single(rest)
                value, rest = self._bdecode_single(rest)
                result[key] = value
            return result, rest[1:]
        else:
            colon_pos = data.index(b":")
            length = int(data[:colon_pos])
            start = colon_pos + 1
            end = start + length
            return data[start:end].decode('utf-8'), data[end:]
    
    async def _handle_ping(self, message: Dict, addr: Tuple[str, int], transaction_id: str):
        """Handle ping query."""
        node_id = message.get("a", {}).get("id", "")
        
        # Add or update node in routing table
        async with self.peer_lock:
            dht_node = DHTNode(
                node_id=node_id,
                ip=addr[0],
                port=addr[1],
                last_seen=time.time()
            )
            bucket_idx = self._get_bucket_index(node_id)
            self.buckets[bucket_idx].add_node(dht_node)
        
        # Send pong response
        response = {
            "y": "r",
            "t": transaction_id,
            "r": {
                "id": self.node_id
            }
        }
        await self._send_message(response, addr)
    
    async def _handle_find_node(self, message: Dict, addr: Tuple[str, int], transaction_id: str):
        """Handle find_node query."""
        target_id = message.get("a", {}).get("target", "")
        
        # Find closest nodes to target
        closest_nodes = await self._find_closest_nodes(target_id, exclude_id=None)
        
        # Convert to DHT format
        nodes_list = []
        for node in closest_nodes[:KAD_B]:  # Return up to KAD_B nodes
            nodes_list.append({
                "id": node.node_id,
                "ip": node.ip,
                "port": node.port
            })
        
        response = {
            "y": "r",
            "t": transaction_id,
            "r": {
                "id": self.node_id,
                "nodes": nodes_list
            }
        }
        await self._send_message(response, addr)
    
    async def _handle_get_peers(self, message: Dict, addr: Tuple[str, int], transaction_id: str):
        """Handle get_peers query."""
        infohash = message.get("a", {}).get("infohash", "")
        
        # For now, return known peers (will be enhanced for service discovery)
        known_peers = []
        async with self.peer_lock:
            for node in self.known_peers.values():
                if not node.is_expired():
                    known_peers.append({
                        "id": node.node_id,
                        "ip": node.ip,
                        "port": node.port
                    })
        
        response = {
            "y": "r",
            "t": transaction_id,
            "r": {
                "id": self.node_id,
                "nodes": known_peers,
                "values": []  # Can be used for service values
            }
        }
        await self._send_message(response, addr)
    
    async def _handle_announce_peer(self, message: Dict, addr: Tuple[str, int], transaction_id: str):
        """Handle announce_peer query."""
        announced_node = message.get("a", {}).get("node", {})
        node_id = announced_node.get("id", "")
        ip = announced_node.get("ip", addr[0])
        port = announced_node.get("port", addr[1])
        
        # Store announced peer
        async with self.peer_lock:
            dht_node = DHTNode(
                node_id=node_id,
                ip=ip,
                port=port,
                last_seen=time.time()
            )
            self.known_peers[node_id] = dht_node
            
            # Also add to routing table
            bucket_idx = self._get_bucket_index(node_id)
            self.buckets[bucket_idx].add_node(dht_node)
        
        # Clean up expired peers
        await self._cleanup_expired()
        
        response = {
            "y": "r",
            "t": transaction_id,
            "r": {
                "id": self.node_id
            }
        }
        await self._send_message(response, addr)
    
    async def _handle_response(self, message: Dict, addr: Tuple[str, int]):
        """Handle response message."""
        # For now, just log responses
        response_type = message.get("r", {}).get("id", "")
        log.debug(f"Received DHT response from {response_type[:8]}...")
        
        # Extract nodes from response and add to routing table
        nodes = message.get("r", {}).get("nodes", [])
        async with self.peer_lock:
            for node_data in nodes:
                dht_node = DHTNode(
                    node_id=node_data["id"],
                    ip=node_data["ip"],
                    port=node_data["port"],
                    last_seen=time.time()
                )
                bucket_idx = self._get_bucket_index(dht_node.node_id)
                self.buckets[bucket_idx].add_node(dht_node)
    
    async def _send_message(self, message: Dict, addr: Tuple[str, int]):
        """Send DHT message to address."""
        try:
            # Use JSON encoding for now
            data = json.dumps(message).encode('utf-8')
            self.socket.sendto(data, addr)
            log.debug(f"Sent DHT message to {addr[0]}:{addr[1]}")
        except Exception as e:
            log.error(f"Failed to send DHT message: {e}")
    
    async def _find_closest_nodes(self, target_id: str, exclude_id: Optional[str] = None) -> List[DHTNode]:
        """Find closest nodes to target ID using Kademlia algorithm."""
        # Get all non-expired nodes
        all_nodes = []
        for bucket in self.buckets:
            all_nodes.extend(bucket.get_nodes(exclude_id))
        
        # Sort by XOR distance to target
        def xor_distance(node_id: str) -> int:
            return int(target_id, 16) ^ int(node_id, 16)
        
        all_nodes.sort(key=lambda n: xor_distance(n.node_id))
        
        return all_nodes[:KAD_B]  # Return closest KAD_B nodes
    
    async def bootstrap(self):
        """Bootstrap DHT network by connecting to known nodes."""
        if not self.bootstrap_nodes:
            log.warning("No bootstrap nodes configured")
            return
        
        log.info(f"Bootstrapping DHT network with {len(self.bootstrap_nodes)} nodes")
        
        # Send find_node to bootstrap nodes to populate routing table
        for ip, port in self.bootstrap_nodes:
            try:
                await self._send_find_node(self.node_id, (ip, port))
            except Exception as e:
                log.error(f"Failed to bootstrap with {ip}:{port}: {e}")
    
    async def _send_find_node(self, target_id: str, addr: Tuple[str, int]) -> List[DHTNode]:
        """Send find_node request and wait for response."""
        transaction_id = self._generate_transaction_id()
        
        message = {
            "y": "q",
            "t": transaction_id,
            "q": "find_node",
            "a": {
                "id": self.node_id,
                "target": target_id
            }
        }
        
        # We don't wait for response in this simple implementation
        # In a full implementation, we'd track the transaction
        await self._send_message(message, addr)
        
        # Return nodes from routing table as fallback
        return await self._find_closest_nodes(target_id)
    
    def _generate_transaction_id(self) -> str:
        """Generate a random transaction ID."""
        return str(random.randint(0, 2**32 - 1))
    
    async def _cleanup_expired(self):
        """Clean up expired nodes from routing table."""
        total_removed = 0
        async with self.peer_lock:
            for bucket in self.buckets:
                removed = bucket.remove_expired()
                total_removed += removed
            
            # Also clean known_peers
            self.known_peers = {k: v for k, v in self.known_peers.items() if not v.is_expired()}
        
        if total_removed > 0:
            log.info(f"Cleaned up {total_removed} expired nodes")
    
    # ===== Public API Methods =====
    
    async def announce_peer(self, node_id: str, ip: str, port: int) -> bool:
        """Announce a peer to the DHT network."""
        async with self.peer_lock:
            dht_node = DHTNode(
                node_id=node_id,
                ip=ip,
                port=port,
                last_seen=time.time()
            )
            self.known_peers[node_id] = dht_node
            
            # Add to routing table
            bucket_idx = self._get_bucket_index(node_id)
            self.buckets[bucket_idx].add_node(dht_node)
        
        # Broadcast to known peers
        await self._broadcast_announce(dht_node)
        
        return True
    
    async def _broadcast_announce(self, node: DHTNode):
        """Broadcast peer announcement to known nodes."""
        message = {
            "y": "q",
            "t": self._generate_transaction_id(),
            "q": "announce_peer",
            "a": {
                "id": self.node_id,
                "node": {
                    "id": node.node_id,
                    "ip": node.ip,
                    "port": node.port
                }
            }
        }
        
        async with self.peer_lock:
            for known_node in list(self.known_peers.values())[:10]:  # Limit to 10
                try:
                    await self._send_message(message, (known_node.ip, known_node.port))
                except Exception as e:
                    log.error(f"Failed to announce to {known_node.ip}:{known_node.port}: {e}")
    
    async def find_peers(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Find peers in the DHT network."""
        async with self.peer_lock:
            all_peers = []
            for node in self.known_peers.values():
                if not node.is_expired():
                    all_peers.append({
                        "node_id": node.node_id,
                        "ip": node.ip,
                        "port": node.port,
                        "last_seen": node.last_seen
                    })
            
            # Sort by most recently seen
            all_peers.sort(key=lambda x: x["last_seen"], reverse=True)
            
            return all_peers[:limit]
    
    async def store_value(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Store a value in the DHT."""
        expiry = time.time() + ttl
        self.store[key] = (value, expiry)
        
        # In a full implementation, we'd replicate to other nodes
        # For now, just store locally
        
        return True
    
    async def get_value(self, key: str) -> Optional[Any]:
        """Get a value from the DHT."""
        if key in self.store:
            value, expiry = self.store[key]
            if time.time() < expiry:
                return value
            else:
                del self.store[key]
        return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get DHT statistics."""
        total_peers = 0
        for bucket in self.buckets:
            total_peers += len(bucket.get_nodes())
        
        return {
            "node_id": self.node_id[:8] + "...",
            "total_peers": total_peers,
            "known_peers": len(self.known_peers),
            "store_size": len(self.store),
            "uptime": time.time() - self._start_time
        }
    
    async def _start_web_api(self, port: int):
        """Start HTTP API for DHT management."""
        self._start_time = time.time()
        self.web_app = web.Application()
        
        # Routes
        self.web_app.router.add_get("/dht/peers", self.http_get_peers)
        self.web_app.router.add_post("/dht/announce", self.http_announce_peer)
        self.web_app.router.add_get("/dht/stats", self.http_get_stats)
        self.web_app.router.add_get("/dht/find/{node_id}", self.http_find_node)
        self.web_app.router.add_post("/dht/store/{key}", self.http_store_value)
        self.web_app.router.add_get("/dht/value/{key}", self.http_get_value)
        
        # Start server
        self.web_runner = web.AppRunner(self.web_app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "0.0.0.0", port)
        await self.web_site.start()
        
        log.info(f"DHT HTTP API started on port {port}")
    
    async def http_get_peers(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get peers."""
        limit = int(request.query.get("limit", 50))
        peers = await self.find_peers(limit)
        return web.json_response(peers)
    
    async def http_announce_peer(self, request: web.Request) -> web.Response:
        """HTTP endpoint to announce a peer."""
        data = await request.json()
        node_id = data.get("node_id")
        ip = data.get("ip")
        port = data.get("port", DHT_PORT)
        
        if not node_id or not ip:
            return web.json_response({"error": "node_id and ip required"}, status=400)
        
        success = await self.announce_peer(node_id, ip, port)
        return web.json_response({"success": success})
    
    async def http_get_stats(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get DHT stats."""
        stats = await self.get_stats()
        return web.json_response(stats)
    
    async def http_find_node(self, request: web.Request) -> web.Response:
        """HTTP endpoint to find nodes close to a given ID."""
        node_id = request.match_info["node_id"]
        nodes = await self._find_closest_nodes(node_id)
        
        result = []
        for node in nodes:
            result.append({
                "node_id": node.node_id,
                "ip": node.ip,
                "port": node.port
            })
        
        return web.json_response(result)
    
    async def http_store_value(self, request: web.Request) -> web.Response:
        """HTTP endpoint to store a value in DHT."""
        key = request.match_info["key"]
        data = await request.json()
        value = data.get("value")
        ttl = data.get("ttl", 3600)
        
        success = await self.store_value(key, value, ttl)
        return web.json_response({"success": success})
    
    async def http_get_value(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get a value from DHT."""
        key = request.match_info["key"]
        value = await self.get_value(key)
        
        if value is None:
            return web.json_response({"error": "not found"}, status=404)
        
        return web.json_response({"key": key, "value": value})


# Global DHT instance
_dht_instance: Optional[DHTNetwork] = None


async def get_dht_instance() -> DHTNetwork:
    """Get or create global DHT instance."""
    global _dht_instance
    if _dht_instance is None:
        _dht_instance = DHTNetwork()
        await _dht_instance.start()
    return _dht_instance


async def shutdown_dht():
    """Shutdown global DHT instance."""
    global _dht_instance
    if _dht_instance:
        await _dht_instance.stop()
        _dht_instance = None


if __name__ == "__main__":
    # Test DHT functionality
    import sys
    
    async def test_dht():
        # Create DHT instance
        dht = DHTNetwork(port=6882)
        await dht.start(web_port=8733)
        
        # Add some test data
        await dht.announce_peer(
            node_id="a" * 40,  # Test node ID
            ip="127.0.0.1",
            port=6881
        )
        
        # Get peers
        peers = await dht.find_peers()
        print(f"Known peers: {len(peers)}")
        for peer in peers:
            print(f"  {peer['node_id'][:8]}... {peer['ip']}:{peer['port']}")
        
        # Get stats
        stats = await dht.get_stats()
        print(f"Stats: {stats}")
        
        # Store and retrieve value
        await dht.store_value("test_key", {"message": "Hello DHT!"})
        value = await dht.get_value("test_key")
        print(f"Stored and retrieved value: {value}")
        
        # Wait for a while
        print("Running DHT server... Press Ctrl+C to stop")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await dht.stop()
            print("DHT server stopped")
    
    asyncio.run(test_dht())
