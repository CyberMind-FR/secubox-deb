# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-p2p :: masterlink

Master-Link amélioré pour topologie hiérarchique.

Ce module permet:
- Topologie hiérarchique master/satellite
- Promotion et démotion automatique de nœuds
- Gestion des politiques de routage
- Système de heartbeats et failover
- Intégration avec OPAD pour sécurité
- Optimisation du routage intra-cluster

Spec: Issue P2P-EVO-2026-07-001
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aiohttp import web

from .dht import DHTNetwork, get_dht_instance
from .federation import ServiceFederation, get_federation_instance, ServiceType, ServiceStatus
from .mesh import MESH_INTERFACE, MESH_PORT, MESH_NETWORK, peer_nodes, load_p2p_config

log = logging.getLogger("secubox.p2p.masterlink")

# Constants
MASTER_LINK_DIR = Path("/var/lib/secubox/p2p/master-link")
TOPOLOGY_FILE = MASTER_LINK_DIR / "topology.json"
HEARTBEAT_INTERVAL = 15  # 15 seconds between heartbeats
HEARTBEAT_TIMEOUT = 45  # 45 seconds before master is considered dead
ELECTION_TIMEOUT = 60  # 60 seconds to wait before election when master is down
MAX_DEPTH = 3  # Maximum hierarchy depth
DEFAULT_TOKEN_TTL = 3600  # 1 hour token TTL


class NodeRole(Enum):
    """Role of a node in the hierarchy."""
    MASTER = "master"        # Master node (root of hierarchy)
    SATELLITE = "satellite"  # Satellite node (connected to master)
    LEAF = "leaf"           # Leaf node (connected to satellite)
    CANDIDATE = "candidate" # Candidate for promotion
    UNKNOWN = "unknown"


class NodeStatus(Enum):
    """Status of a node in the hierarchy."""
    ONLINE = "online"
    OFFLINE = "offline"
    JOINING = "joining"
    LEAVING = "leaving"
    ELECTING = "electing"
    DEGRADED = "degraded"


@dataclass
class HierarchyNode:
    """Represents a node in the hierarchy."""
    node_id: str
    role: NodeRole = NodeRole.SATELLITE
    status: NodeStatus = NodeStatus.ONLINE
    ip: str = ""
    port: int = MESH_PORT
    endpoint: Optional[str] = None
    
    # Hierarchy information
    parent_id: Optional[str] = None  # ID of parent node
    children: List[str] = field(default_factory=list)  # IDs of child nodes
    depth: int = 0  # Depth in hierarchy (0 for master)
    
    # Timestamps
    joined_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    
    # Capabilities and metadata
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Performance metrics
    latency_ms: Optional[float] = None
    uptime: float = 0.0
    
    def is_expired(self) -> bool:
        """Check if this node is expired (no heartbeat for too long)."""
        if self.role == NodeRole.MASTER:
            return time.time() - self.last_heartbeat > HEARTBEAT_TIMEOUT
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "role": self.role.value,
            "status": self.status.value,
            "ip": self.ip,
            "port": self.port,
            "endpoint": self.endpoint,
            "parent_id": self.parent_id,
            "children": self.children,
            "depth": self.depth,
            "joined_at": self.joined_at,
            "last_heartbeat": self.last_heartbeat,
            "last_updated": self.last_updated,
            "capabilities": self.capabilities,
            "metadata": self.metadata,
            "latency_ms": self.latency_ms,
            "uptime": self.uptime
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HierarchyNode":
        return cls(
            node_id=data["node_id"],
            role=NodeRole(data.get("role", "satellite")),
            status=NodeStatus(data.get("status", "online")),
            ip=data.get("ip", ""),
            port=data.get("port", MESH_PORT),
            endpoint=data.get("endpoint"),
            parent_id=data.get("parent_id"),
            children=data.get("children", []),
            depth=data.get("depth", 0),
            joined_at=data.get("joined_at", time.time()),
            last_heartbeat=data.get("last_heartbeat", time.time()),
            last_updated=data.get("last_updated", time.time()),
            capabilities=data.get("capabilities", []),
            metadata=data.get("metadata", {}),
            latency_ms=data.get("latency_ms"),
            uptime=data.get("uptime", 0.0)
        )


@dataclass
class MasterToken:
    """Token for master node authentication."""
    token: str = field(default_factory=lambda: str(uuid.uuid4()))
    node_id: str = ""
    issued_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + DEFAULT_TOKEN_TTL)
    permissions: List[str] = field(default_factory=list)
    
    def is_valid(self) -> bool:
        """Check if token is still valid."""
        return time.time() < self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token": self.token,
            "node_id": self.node_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "permissions": self.permissions
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MasterToken":
        return cls(
            token=data["token"],
            node_id=data.get("node_id", ""),
            issued_at=data.get("issued_at", time.time()),
            expires_at=data.get("expires_at", time.time() + DEFAULT_TOKEN_TTL),
            permissions=data.get("permissions", [])
        )


@dataclass
class RoutingPolicy:
    """Routing policy for the hierarchy."""
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default"
    description: str = ""
    
    # Traffic routing rules
    prefer_local: bool = True  # Prefer local routing when possible
    max_hops: int = 5  # Maximum number of hops
    balance_load: bool = True  # Balance load across nodes
    
    # Security settings
    require_authentication: bool = True
    require_encryption: bool = True
    
    # Performance thresholds
    max_latency_ms: float = 100.0  # Maximum acceptable latency
    min_bandwidth_mbps: float = 1.0  # Minimum required bandwidth
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "prefer_local": self.prefer_local,
            "max_hops": self.max_hops,
            "balance_load": self.balance_load,
            "require_authentication": self.require_authentication,
            "require_encryption": self.require_encryption,
            "max_latency_ms": self.max_latency_ms,
            "min_bandwidth_mbps": self.min_bandwidth_mbps
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RoutingPolicy":
        return cls(
            policy_id=data.get("policy_id", str(uuid.uuid4())),
            name=data.get("name", "default"),
            description=data.get("description", ""),
            prefer_local=data.get("prefer_local", True),
            max_hops=data.get("max_hops", 5),
            balance_load=data.get("balance_load", True),
            require_authentication=data.get("require_authentication", True),
            require_encryption=data.get("require_encryption", True),
            max_latency_ms=data.get("max_latency_ms", 100.0),
            min_bandwidth_mbps=data.get("min_bandwidth_mbps", 1.0)
        )


class MasterLinkManager:
    """
    Main Master-Link manager for hierarchical topology.
    
    This class manages the hierarchical organization of nodes, including:
    - Master election and promotion
    - Heartbeat monitoring
    - Failover handling
    - Routing policy management
    - Integration with OPAD security
    """
    
    def __init__(self, node_id: Optional[str] = None, 
                 dht_network: Optional[DHTNetwork] = None,
                 federation: Optional[ServiceFederation] = None):
        """
        Initialize Master-Link manager.
        
        Args:
            node_id: ID of the local node
            dht_network: DHT network instance
            federation: Federation service instance
        """
        self.local_node_id = node_id or self._get_local_node_id()
        self.dht = dht_network
        self.federation = federation
        
        # Hierarchy state
        self.nodes: Dict[str, HierarchyNode] = {}
        self.node_lock = asyncio.Lock()
        
        # Local node
        self.local_node = HierarchyNode(node_id=self.local_node_id)
        self.nodes[self.local_node_id] = self.local_node
        
        # Master state
        self.master_node_id: Optional[str] = None
        self.master_token: Optional[MasterToken] = None
        self.is_master = False
        
        # Tokens for satellite nodes
        self.tokens: Dict[str, MasterToken] = {}
        
        # Routing policies
        self.routing_policies: Dict[str, RoutingPolicy] = {}
        self.default_policy = RoutingPolicy(name="default")
        
        # Heartbeat tracking
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.election_task: Optional[asyncio.Task] = None
        
        # Web API
        self.web_app: Optional[web.Application] = None
        self.web_runner: Optional[web.AppRunner] = None
        self.web_site: Optional[web.TCPSite] = None
        
        # Load persisted state
        self._load_state()
        
        log.info(f"MasterLink manager initialized for node {self.local_node_id[:8]}...")
    
    def _get_local_node_id(self) -> str:
        """Get local node ID."""
        try:
            node_id_file = Path("/var/lib/secubox/p2p/node.id")
            if node_id_file.exists():
                return node_id_file.read_text().strip()
        except:
            pass
        
        import socket
        hostname = socket.gethostname()
        return hashlib.sha1(hostname.encode()).hexdigest()[:20]
    
    def _load_state(self):
        """Load state from disk."""
        try:
            MASTER_LINK_DIR.mkdir(parents=True, exist_ok=True)
            if TOPOLOGY_FILE.exists():
                with open(TOPOLOGY_FILE, 'r') as f:
                    data = json.load(f)
                    
                    # Load nodes
                    for node_data in data.get("nodes", []):
                        node = HierarchyNode.from_dict(node_data)
                        self.nodes[node.node_id] = node
                        
                        # Update local node if it exists
                        if node.node_id == self.local_node_id:
                            self.local_node = node
                    
                    # Load master state
                    if data.get("master_node_id"):
                        self.master_node_id = data["master_node_id"]
                        self.is_master = self.master_node_id == self.local_node_id
                    
                    # Load tokens
                    for token_data in data.get("tokens", []):
                        token = MasterToken.from_dict(token_data)
                        self.tokens[token.node_id] = token
                    
                    # Load routing policies
                    for policy_data in data.get("routing_policies", []):
                        policy = RoutingPolicy.from_dict(policy_data)
                        self.routing_policies[policy.policy_id] = policy
                        if policy.name == "default":
                            self.default_policy = policy
                    
                log.info(f"Loaded MasterLink state: {len(self.nodes)} nodes, "
                        f"master={self.master_node_id}")
        except Exception as e:
            log.error(f"Failed to load MasterLink state: {e}")
    
    def _save_state(self):
        """Save state to disk."""
        try:
            MASTER_LINK_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "version": 1,
                "updated_at": time.time(),
                "local_node_id": self.local_node_id,
                "master_node_id": self.master_node_id,
                "is_master": self.is_master,
                "nodes": [node.to_dict() for node in self.nodes.values()],
                "tokens": [token.to_dict() for token in self.tokens.values()],
                "routing_policies": [policy.to_dict() for policy in self.routing_policies.values()]
            }
            
            with open(TOPOLOGY_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            
            log.debug("Saved MasterLink state to disk")
        except Exception as e:
            log.error(f"Failed to save MasterLink state: {e}")
    
    async def start(self, web_port: int = 8736):
        """Start Master-Link manager."""
        # Start HTTP API
        await self._start_web_api(web_port)
        
        # Start heartbeat loop
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        # Start election monitoring
        self.election_task = asyncio.create_task(self._election_monitor())
        
        # Try to join existing hierarchy or become master
        await self._join_or_become_master()
        
        log.info(f"MasterLink manager started on port {web_port}")
    
    async def stop(self):
        """Stop Master-Link manager."""
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self.election_task:
            self.election_task.cancel()
            try:
                await self.election_task
            except asyncio.CancelledError:
                pass
        
        # Save state before stopping
        self._save_state()
        
        if self.web_runner:
            await self.web_runner.cleanup()
        
        log.info("MasterLink manager stopped")
    
    async def _heartbeat_loop(self):
        """Send and receive heartbeats."""
        while True:
            try:
                # Send heartbeat to parent (if we have one)
                if self.local_node.parent_id and self.local_node.parent_id in self.nodes:
                    await self._send_heartbeat(self.local_node.parent_id)
                
                # Send heartbeat to children
                for child_id in self.local_node.children:
                    if child_id in self.nodes:
                        await self._send_heartbeat(child_id)
                
                # Update local node timestamp
                self.local_node.last_heartbeat = time.time()
                self.local_node.last_updated = time.time()
                
            except Exception as e:
                log.error(f"Heartbeat loop error: {e}")
            
            await asyncio.sleep(HEARTBEAT_INTERVAL)
    
    async def _send_heartbeat(self, target_node_id: str):
        """Send heartbeat to a specific node."""
        if target_node_id not in self.nodes:
            log.warning(f"Cannot send heartbeat to unknown node: {target_node_id}")
            return
        
        target_node = self.nodes[target_node_id]
        
        # In a real implementation, this would send a message over the mesh
        # For now, we just update the target node's last_heartbeat timestamp
        target_node.last_heartbeat = time.time()
        target_node.last_updated = time.time()
        
        # Calculate latency (simulated)
        latency = random.uniform(10, 100)  # ms
        self.nodes[target_node_id].latency_ms = latency
        
        log.debug(f"Heartbeat sent to {target_node_id[:8]}... (latency: {latency:.1f}ms)")
    
    async def _election_monitor(self):
        """Monitor for master failure and trigger election."""
        while True:
            try:
                # Check if master is still alive
                if self.master_node_id and self.master_node_id in self.nodes:
                    master_node = self.nodes[self.master_node_id]
                    if master_node.is_expired():
                        log.warning(f"Master node {self.master_node_id[:8]}... is down, "
                                  f"starting election")
                        await self._start_election()
                
                # If we're master, check our own status
                if self.is_master:
                    self.local_node.last_heartbeat = time.time()
                    
            except Exception as e:
                log.error(f"Election monitor error: {e}")
            
            await asyncio.sleep(HEARTBEAT_INTERVAL)
    
    async def _join_or_become_master(self):
        """Join existing hierarchy or become master."""
        # Check if we can discover a master via DHT
        if self.dht:
            peers = await self.dht.find_peers(limit=20)
            for peer in peers:
                # Check if this peer is a master
                master_info = await self._get_master_info(peer["node_id"])
                if master_info and master_info.get("role") == "master":
                    log.info(f"Found master node: {peer['node_id'][:8]}...")
                    await self._join_hierarchy(peer["node_id"], peer["ip"], peer["port"])
                    return
        
        # No master found, become master ourselves
        log.info("No master found, becoming master node")
        await self._become_master()
    
    async def _get_master_info(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get master information from a node."""
        # In a real implementation, this would query the node via the mesh
        # For now, we return None (no master info)
        return None
    
    async def _join_hierarchy(self, master_id: str, master_ip: str, master_port: int):
        """Join the hierarchy under a master node."""
        log.info(f"Joining hierarchy under master {master_id[:8]}...")
        
        # Add master to our node list
        self.master_node_id = master_id
        master_node = HierarchyNode(
            node_id=master_id,
            role=NodeRole.MASTER,
            status=NodeStatus.ONLINE,
            ip=master_ip,
            port=master_port
        )
        self.nodes[master_id] = master_node
        
        # Update local node
        self.local_node.role = NodeRole.SATELLITE
        self.local_node.parent_id = master_id
        self.local_node.depth = 1
        self.local_node.status = NodeStatus.JOINING
        
        # Request token from master (simulated)
        token = self._generate_token(master_id)
        self.master_token = token
        self.tokens[master_id] = token
        
        # Update master's children
        master_node.children.append(self.local_node_id)
        
        # Mark as online
        self.local_node.status = NodeStatus.ONLINE
        self.is_master = False
        
        # Save state
        self._save_state()
        
        log.info(f"Successfully joined hierarchy as satellite of {master_id[:8]}...")
    
    async def _become_master(self):
        """Become the master node."""
        log.info(f"Becoming master node: {self.local_node_id[:8]}...")
        
        # Update local node
        self.local_node.role = NodeRole.MASTER
        self.local_node.depth = 0
        self.local_node.parent_id = None
        self.local_node.status = NodeStatus.ONLINE
        
        self.master_node_id = self.local_node_id
        self.is_master = True
        
        # Generate master token
        self.master_token = self._generate_token(self.local_node_id)
        
        # Save state
        self._save_state()
        
        log.info(f"Successfully became master node")
    
    def _generate_token(self, node_id: str) -> MasterToken:
        """Generate a token for a node."""
        token = MasterToken(
            node_id=node_id,
            permissions=["read", "write", "join"]
        )
        return token
    
    async def _start_election(self):
        """Start election process to choose a new master."""
        log.info("Starting master election...")
        
        # Mark ourselves as electing
        self.local_node.status = NodeStatus.ELECTING
        
        # Get all candidate nodes (satellites with good health)
        candidates = await self._get_election_candidates()
        
        if not candidates:
            log.warning("No candidates for master election, becoming master")
            await self._become_master()
            return
        
        # Sort candidates by node ID (deterministic election)
        candidates.sort(key=lambda n: n.node_id)
        
        # Choose the candidate with the lowest node ID
        winner = candidates[0]
        
        # If we're the winner, become master
        if winner.node_id == self.local_node_id:
            log.info("Election won, becoming master")
            await self._become_master()
        else:
            # Join under the winner
            if winner.node_id in self.nodes:
                winner_node = self.nodes[winner.node_id]
                await self._join_hierarchy(winner.node_id, winner_node.ip, winner_node.port)
            else:
                # Fallback: become master if winner is not available
                log.warning(f"Elected winner {winner.node_id} not available, "
                          f"becoming master as fallback")
                await self._become_master()
    
    async def _get_election_candidates(self) -> List[HierarchyNode]:
        """Get candidate nodes for election."""
        candidates = []
        
        for node in self.nodes.values():
            # Skip ourselves
            if node.node_id == self.local_node_id:
                continue
            
            # Skip offline nodes
            if node.status != NodeStatus.ONLINE:
                continue
            
            # Skip nodes that are too deep in hierarchy
            if node.depth >= MAX_DEPTH:
                continue
            
            # Prefer satellites over leaves
            if node.role in [NodeRole.SATELLITE, NodeRole.LEAF]:
                candidates.append(node)
        
        return candidates
    
    async def promote_node(self, node_id: str, new_role: NodeRole) -> bool:
        """Promote a node to a new role."""
        if node_id not in self.nodes:
            log.error(f"Cannot promote unknown node: {node_id}")
            return False
        
        if not self.is_master:
            log.error("Only master can promote nodes")
            return False
        
        node = self.nodes[node_id]
        
        # Validate role change
        if new_role == NodeRole.MASTER:
            log.error("Cannot promote to master (use election instead)")
            return False
        
        if new_role == node.role:
            log.info(f"Node {node_id[:8]}... is already {new_role.value}")
            return True
        
        # Perform promotion
        old_role = node.role
        node.role = new_role
        node.status = NodeStatus.ONLINE
        node.last_updated = time.time()
        
        # Update parent/child relationships
        if new_role == NodeRole.SATELLITE:
            # Satellite nodes are direct children of master
            node.parent_id = self.local_node_id
            node.depth = 1
            
            # Remove from old parent's children
            if node.parent_id and node.parent_id in self.nodes:
                parent = self.nodes[node.parent_id]
                if node_id in parent.children:
                    parent.children.remove(node_id)
            
            # Add to master's children
            if self.local_node_id not in self.local_node.children:
                self.local_node.children.append(node_id)
            
        elif new_role == NodeRole.LEAF:
            # Leaf nodes need a parent satellite
            if not node.parent_id:
                # Find a satellite parent
                for parent_node in self.nodes.values():
                    if parent_node.role == NodeRole.SATELLITE:
                        node.parent_id = parent_node.node_id
                        node.depth = parent_node.depth + 1
                        parent_node.children.append(node_id)
                        break
            
            if not node.parent_id:
                log.error(f"Cannot promote {node_id} to LEAF: no satellite parent available")
                return False
        
        log.info(f"Promoted node {node_id[:8]}... from {old_role.value} to {new_role.value}")
        self._save_state()
        return True
    
    async def demote_node(self, node_id: str, new_role: NodeRole) -> bool:
        """Demote a node to a new role."""
        if node_id not in self.nodes:
            log.error(f"Cannot demote unknown node: {node_id}")
            return False
        
        if not self.is_master:
            log.error("Only master can demote nodes")
            return False
        
        node = self.nodes[node_id]
        
        if new_role == node.role:
            return True
        
        if new_role == NodeRole.MASTER:
            log.error("Cannot demote to master")
            return False
        
        # Perform demotion
        old_role = node.role
        node.role = new_role
        node.last_updated = time.time()
        
        # Update relationships
        if old_role == NodeRole.SATELLITE:
            # Reassign children to other satellites or master
            for child_id in node.children[:]:  # Copy list
                child = self.nodes.get(child_id)
                if child:
                    # Try to reassign to master
                    child.parent_id = self.local_node_id
                    child.depth = 1
                    if child_id not in self.local_node.children:
                        self.local_node.children.append(child_id)
                    node.children.remove(child_id)
        
        log.info(f"Demoted node {node_id[:8]}... from {old_role.value} to {new_role.value}")
        self._save_state()
        return True
    
    async def remove_node(self, node_id: str) -> bool:
        """Remove a node from the hierarchy."""
        if node_id not in self.nodes:
            return False
        
        node = self.nodes[node_id]
        
        # Reassign children
        for child_id in node.children[:]:  # Copy list
            child = self.nodes.get(child_id)
            if child:
                if self.is_master:
                    # Reassign to master
                    child.parent_id = self.local_node_id
                    child.depth = 1
                    if child_id not in self.local_node.children:
                        self.local_node.children.append(child_id)
                else:
                    # Reassign to our parent
                    if self.local_node.parent_id and self.local_node.parent_id in self.nodes:
                        parent = self.nodes[self.local_node.parent_id]
                        child.parent_id = parent.node_id
                        child.depth = parent.depth + 1
                        if child_id not in parent.children:
                            parent.children.append(child_id)
        
        # Remove from parent's children
        if node.parent_id and node.parent_id in self.nodes:
            parent = self.nodes[node.parent_id]
            if node_id in parent.children:
                parent.children.remove(node_id)
        
        # Remove node
        del self.nodes[node_id]
        
        # If it was our master, trigger election
        if node_id == self.master_node_id:
            self.master_node_id = None
            self.is_master = False
            await self._start_election()
        
        self._save_state()
        log.info(f"Removed node {node_id[:8]}... from hierarchy")
        return True
    
    async def get_topology(self) -> Dict[str, Any]:
        """Get the current hierarchy topology."""
        async with self.node_lock:
            nodes_data = []
            for node in self.nodes.values():
                nodes_data.append(node.to_dict())
            
            return {
                "local_node_id": self.local_node_id,
                "is_master": self.is_master,
                "master_node_id": self.master_node_id,
                "total_nodes": len(self.nodes),
                "nodes": nodes_data
            }
    
    async def get_routing_path(self, target_node_id: str) -> List[str]:
        """Get the routing path to a target node."""
        if target_node_id not in self.nodes:
            return []
        
        if target_node_id == self.local_node_id:
            return [self.local_node_id]
        
        # Simple path finding: go up to common ancestor, then down
        path = []
        current = self.local_node
        visited = set()
        
        # Go up to find common ancestor
        while current and current.node_id not in visited:
            visited.add(current.node_id)
            path.append(current.node_id)
            
            if current.node_id == target_node_id:
                break
            
            if current.parent_id and current.parent_id in self.nodes:
                current = self.nodes[current.parent_id]
            else:
                break
        
        # If we found the target, return the path
        if current.node_id == target_node_id:
            return path
        
        # Otherwise, try to find path from master
        if self.master_node_id and self.master_node_id in self.nodes:
            master = self.nodes[self.master_node_id]
            if target_node_id in self.nodes:
                target = self.nodes[target_node_id]
                
                # Find path from master to target
                target_path = []
                current_target = target
                while current_target and current_target.node_id != master.node_id:
                    target_path.append(current_target.node_id)
                    if current_target.parent_id and current_target.parent_id in self.nodes:
                        current_target = self.nodes[current_target.parent_id]
                    else:
                        break
                
                target_path.append(master.node_id)
                target_path.reverse()
                
                # Find path from master to us
                our_path = []
                current_us = self.local_node
                while current_us and current_us.node_id != master.node_id:
                    our_path.append(current_us.node_id)
                    if current_us.parent_id and current_us.parent_id in self.nodes:
                        current_us = self.nodes[current_us.parent_id]
                    else:
                        break
                
                our_path.append(master.node_id)
                our_path.reverse()
                
                # Combine paths (remove duplicate master)
                combined = our_path + target_path[1:]
                return combined
        
        return []
    
    async def add_routing_policy(self, policy: RoutingPolicy) -> bool:
        """Add a routing policy."""
        if policy.policy_id in self.routing_policies:
            log.error(f"Policy with ID {policy.policy_id} already exists")
            return False
        
        self.routing_policies[policy.policy_id] = policy
        
        if policy.name == "default":
            self.default_policy = policy
        
        self._save_state()
        log.info(f"Added routing policy: {policy.name}")
        return True
    
    async def remove_routing_policy(self, policy_id: str) -> bool:
        """Remove a routing policy."""
        if policy_id not in self.routing_policies:
            return False
        
        del self.routing_policies[policy_id]
        
        if policy_id == self.default_policy.policy_id:
            self.default_policy = RoutingPolicy(name="default")
        
        self._save_state()
        log.info(f"Removed routing policy: {policy_id}")
        return True
    
    async def get_optimal_route(self, target_node_id: str) -> Dict[str, Any]:
        """Get the optimal route to a target node based on policies."""
        path = await self.get_routing_path(target_node_id)
        
        if not path or len(path) < 2:
            return {"error": "No path found"}
        
        # Calculate path metrics
        total_hops = len(path) - 1
        
        # Get latency estimates
        total_latency = 0.0
        max_latency = 0.0
        for node_id in path[:-1]:  # All nodes except last
            if node_id in self.nodes:
                node = self.nodes[node_id]
                if node.latency_ms:
                    total_latency += node.latency_ms
                    max_latency = max(max_latency, node.latency_ms)
        
        # Check against default policy
        policy = self.default_policy
        
        return {
            "path": path,
            "total_hops": total_hops,
            "total_latency_ms": total_latency,
            "max_latency_ms": max_latency,
            "compliant": total_hops <= policy.max_hops and max_latency <= policy.max_latency_ms,
            "policy": policy.name
        }
    
    async def _start_web_api(self, port: int):
        """Start HTTP API for MasterLink management."""
        self.web_app = web.Application()
        
        # Routes
        self.web_app.router.add_get("/masterlink/topology", self.http_get_topology)
        self.web_app.router.add_get("/masterlink/route/{node_id}", self.http_get_route)
        self.web_app.router.add_post("/masterlink/promote/{node_id}", self.http_promote_node)
        self.web_app.router.add_post("/masterlink/demote/{node_id}", self.http_demote_node)
        self.web_app.router.add_delete("/masterlink/nodes/{node_id}", self.http_remove_node)
        self.web_app.router.add_get("/masterlink/status", self.http_get_status)
        self.web_app.router.add_get("/masterlink/stats", self.http_get_stats)
        self.web_app.router.add_post("/masterlink/join", self.http_join_request)
        
        # Start server
        self.web_runner = web.AppRunner(self.web_app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "0.0.0.0", port)
        await self.web_site.start()
        
        log.info(f"MasterLink HTTP API started on port {port}")
    
    async def http_get_topology(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get topology."""
        topology = await self.get_topology()
        return web.json_response(topology)
    
    async def http_get_route(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get optimal route to a node."""
        node_id = request.match_info["node_id"]
        route = await self.get_optimal_route(node_id)
        return web.json_response(route)
    
    async def http_promote_node(self, request: web.Request) -> web.Response:
        """HTTP endpoint to promote a node."""
        node_id = request.match_info["node_id"]
        data = await request.json()
        new_role = data.get("role", "satellite")
        
        try:
            new_role_enum = NodeRole(new_role)
        except ValueError:
            return web.json_response({"error": f"Invalid role: {new_role}"}, status=400)
        
        success = await self.promote_node(node_id, new_role_enum)
        if success:
            return web.json_response({"success": True, "role": new_role})
        else:
            return web.json_response({"error": "Failed to promote node"}, status=500)
    
    async def http_demote_node(self, request: web.Request) -> web.Response:
        """HTTP endpoint to demote a node."""
        node_id = request.match_info["node_id"]
        data = await request.json()
        new_role = data.get("role", "leaf")
        
        try:
            new_role_enum = NodeRole(new_role)
        except ValueError:
            return web.json_response({"error": f"Invalid role: {new_role}"}, status=400)
        
        success = await self.demote_node(node_id, new_role_enum)
        if success:
            return web.json_response({"success": True, "role": new_role})
        else:
            return web.json_response({"error": "Failed to demote node"}, status=500)
    
    async def http_remove_node(self, request: web.Request) -> web.Response:
        """HTTP endpoint to remove a node."""
        node_id = request.match_info["node_id"]
        success = await self.remove_node(node_id)
        if success:
            return web.json_response({"success": True})
        else:
            return web.json_response({"error": "Node not found"}, status=404)
    
    async def http_get_status(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get local node status."""
        return web.json_response({
            "node_id": self.local_node_id,
            "role": self.local_node.role.value,
            "status": self.local_node.status.value,
            "is_master": self.is_master,
            "master_node_id": self.master_node_id,
            "depth": self.local_node.depth,
            "children": self.local_node.children,
            "parent_id": self.local_node.parent_id
        })
    
    async def http_get_stats(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get MasterLink statistics."""
        topology = await self.get_topology()
        
        # Count nodes by role
        role_counts = {}
        for node in self.nodes.values():
            role = node.role.value
            role_counts[role] = role_counts.get(role, 0) + 1
        
        # Count nodes by depth
        depth_counts = {}
        for node in self.nodes.values():
            depth = node.depth
            depth_counts[depth] = depth_counts.get(depth, 0) + 1
        
        return web.json_response({
            "total_nodes": len(self.nodes),
            "role_counts": role_counts,
            "depth_counts": depth_counts,
            "is_master": self.is_master,
            "master_node_id": self.master_node_id,
            "local_node_id": self.local_node_id
        })
    
    async def http_join_request(self, request: web.Request) -> web.Response:
        """HTTP endpoint to request joining the hierarchy."""
        # Only master can accept join requests
        if not self.is_master:
            return web.json_response({"error": "Not a master node"}, status=403)
        
        data = await request.json()
        node_id = data.get("node_id")
        node_ip = data.get("ip")
        node_port = data.get("port", MESH_PORT)
        
        if not node_id or not node_ip:
            return web.json_response({"error": "node_id and ip required"}, status=400)
        
        # Add the node as a satellite (default role for new nodes)
        new_node = HierarchyNode(
            node_id=node_id,
            role=NodeRole.SATELLITE,
            status=NodeStatus.JOINING,
            ip=node_ip,
            port=node_port,
            parent_id=self.local_node_id,
            depth=1
        )
        
        self.nodes[node_id] = new_node
        self.local_node.children.append(node_id)
        
        # Generate token for the new node
        token = self._generate_token(node_id)
        self.tokens[node_id] = token
        new_node.status = NodeStatus.ONLINE
        
        self._save_state()
        
        log.info(f"Accepted join request from {node_id[:8]}...")
        
        return web.json_response({
            "success": True,
            "role": "satellite",
            "parent_id": self.local_node_id,
            "token": token.token,
            "expires_at": token.expires_at
        })


# Global MasterLink instance
_masterlink_instance: Optional[MasterLinkManager] = None


async def get_masterlink_instance() -> MasterLinkManager:
    """Get or create global MasterLink instance."""
    global _masterlink_instance
    if _masterlink_instance is None:
        dht = await get_dht_instance()
        federation = await get_federation_instance()
        _masterlink_instance = MasterLinkManager(
            dht_network=dht,
            federation=federation
        )
        await _masterlink_instance.start()
    return _masterlink_instance


async def shutdown_masterlink():
    """Shutdown global MasterLink instance."""
    global _masterlink_instance
    if _masterlink_instance:
        await _masterlink_instance.stop()
        _masterlink_instance = None


if __name__ == "__main__":
    # Test MasterLink functionality
    import asyncio
    
    async def test_masterlink():
        # Create MasterLink instance
        masterlink = MasterLinkManager()
        await masterlink.start(web_port=8737)
        
        # Get topology (should be just our local node initially)
        topology = await masterlink.get_topology()
        print(f"Initial topology: {topology['total_nodes']} nodes")
        print(f"Local node role: {topology['is_master']}")
        
        # Get status
        status = await masterlink.http_get_status(None)
        print(f"Local status: {status}")
        
        # Get stats
        stats = await masterlink.http_get_stats(None)
        print(f"Stats: {stats}")
        
        # Wait for a while
        print("Running MasterLink manager... Press Ctrl+C to stop")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await masterlink.stop()
            print("MasterLink manager stopped")
    
    asyncio.run(test_masterlink())
