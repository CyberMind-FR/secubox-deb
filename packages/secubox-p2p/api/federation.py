# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: secubox-p2p :: federation

Système de fédération de services entre nœuds P2P.

Ce module permet:
- Annonce de services disponibles sur chaque nœud
- Découverte de services à travers le mesh
- Gestion des versions et compatibilité
- Health checks distribués
- Intégration avec la DHT pour propagation

Spec: Issue P2P-EVO-2026-07-001
CyberMind — https://cybermind.fr
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aiohttp import web

from .dht import DHTNetwork, get_dht_instance
from .mesh import MESH_INTERFACE, MESH_PORT

log = logging.getLogger("secubox.p2p.federation")

# Constants
FEDERATION_DIR = Path("/var/lib/secubox/p2p/federation")
SERVICE_REGISTRY_FILE = FEDERATION_DIR / "services.json"
SERVICE_TTL = 3600  # 1 hour service TTL
HEALTH_CHECK_INTERVAL = 30  # 30 seconds between health checks
MAX_SERVICE_VERSIONS = 5  # Maximum versions to keep per service


class ServiceStatus(Enum):
    """Status of a federated service."""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    STARTING = "starting"
    STOPPING = "stopping"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    """Types of federated services."""
    API = "api"           # REST API service
    STORAGE = "storage"    # Storage service
    PROXY = "proxy"       # Proxy service
    MONITORING = "monitoring"  # Monitoring service
    AUTH = "auth"        # Authentication service
    DNS = "dns"          # DNS service
    MESH = "mesh"        # Mesh networking service
    CUSTOM = "custom"     # Custom service type


@dataclass
class ServiceHealth:
    """Health status of a service."""
    status: ServiceStatus = ServiceStatus.UNKNOWN
    last_check: float = field(default_factory=time.time)
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "last_check": self.last_check,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "version": self.version
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceHealth":
        return cls(
            status=ServiceStatus(data.get("status", "unknown")),
            last_check=data.get("last_check", time.time()),
            latency_ms=data.get("latency_ms"),
            error=data.get("error"),
            version=data.get("version")
        )


@dataclass
class ServiceInstance:
    """Represents a single service instance."""
    instance_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    service_name: str
    service_type: ServiceType = ServiceType.CUSTOM
    node_id: str
    node_ip: str
    node_port: int
    version: str = "1.0.0"
    endpoint: Optional[str] = None  # e.g., "http://ip:port/api"
    metadata: Dict[str, Any] = field(default_factory=dict)
    health: ServiceHealth = field(default_factory=ServiceHealth)
    registered_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    ttl: int = SERVICE_TTL
    
    def is_expired(self) -> bool:
        """Check if this service instance has expired."""
        return time.time() - self.last_updated > self.ttl
    
    def update_health(self, health: ServiceHealth):
        """Update health status."""
        self.health = health
        self.last_updated = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "service_name": self.service_name,
            "service_type": self.service_type.value,
            "node_id": self.node_id,
            "node_ip": self.node_ip,
            "node_port": self.node_port,
            "version": self.version,
            "endpoint": self.endpoint,
            "metadata": self.metadata,
            "health": self.health.to_dict(),
            "registered_at": self.registered_at,
            "last_updated": self.last_updated,
            "ttl": self.ttl
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceInstance":
        health = ServiceHealth.from_dict(data.get("health", {}))
        return cls(
            instance_id=data.get("instance_id", str(uuid.uuid4())),
            service_name=data["service_name"],
            service_type=ServiceType(data.get("service_type", "custom")),
            node_id=data["node_id"],
            node_ip=data["node_ip"],
            node_port=data.get("node_port", 80),
            version=data.get("version", "1.0.0"),
            endpoint=data.get("endpoint"),
            metadata=data.get("metadata", {}),
            health=health,
            registered_at=data.get("registered_at", time.time()),
            last_updated=data.get("last_updated", time.time()),
            ttl=data.get("ttl", SERVICE_TTL)
        )
    
    def get_dht_key(self) -> str:
        """Get DHT key for this service instance."""
        return f"service:{self.service_name}:{self.node_id}"


@dataclass
class FederatedService:
    """Represents a federated service across multiple nodes."""
    service_name: str
    service_type: ServiceType = ServiceType.CUSTOM
    description: str = ""
    versions: Dict[str, List[ServiceInstance]] = field(default_factory=dict)
    total_instances: int = 0
    healthy_instances: int = 0
    last_updated: float = field(default_factory=time.time)
    
    def add_instance(self, instance: ServiceInstance):
        """Add a service instance."""
        if instance.service_name != self.service_name:
            raise ValueError(f"Service name mismatch: {instance.service_name} vs {self.service_name}")
        
        # Add to versions
        if instance.version not in self.versions:
            self.versions[instance.version] = []
        
        # Replace existing instance with same ID
        existing_indices = [i for i, inst in enumerate(self.versions[instance.version]) 
                          if inst.instance_id == instance.instance_id]
        if existing_indices:
            self.versions[instance.version][existing_indices[0]] = instance
        else:
            self.versions[instance.version].append(instance)
        
        # Update counts
        self.total_instances = sum(len(inst_list) for inst_list in self.versions.values())
        self.healthy_instances = sum(1 for inst_list in self.versions.values() 
                                    for inst in inst_list if inst.health.status == ServiceStatus.ONLINE)
        self.last_updated = time.time()
        
        # Limit versions
        if len(self.versions) > MAX_SERVICE_VERSIONS:
            # Remove oldest version
            oldest_version = min(self.versions.keys())
            del self.versions[oldest_version]
            self.total_instances = sum(len(inst_list) for inst_list in self.versions.values())
    
    def remove_expired_instances(self) -> int:
        """Remove expired instances and return count removed."""
        total_removed = 0
        for version in list(self.versions.keys()):
            initial_count = len(self.versions[version])
            self.versions[version] = [inst for inst in self.versions[version] if not inst.is_expired()]
            removed = initial_count - len(self.versions[version])
            total_removed += removed
            
            # Remove empty versions
            if not self.versions[version]:
                del self.versions[version]
        
        # Recalculate counts
        self.total_instances = sum(len(inst_list) for inst_list in self.versions.values())
        self.healthy_instances = sum(1 for inst_list in self.versions.values() 
                                    for inst in inst_list if inst.health.status == ServiceStatus.ONLINE)
        
        return total_removed
    
    def get_instances(self, version: Optional[str] = None) -> List[ServiceInstance]:
        """Get instances, optionally filtered by version."""
        if version:
            return list(self.versions.get(version, []))
        
        result = []
        for inst_list in self.versions.values():
            result.extend(inst_list)
        return result
    
    def get_healthy_instances(self) -> List[ServiceInstance]:
        """Get only healthy instances."""
        return [inst for inst_list in self.versions.values() 
                for inst in inst_list if inst.health.status == ServiceStatus.ONLINE]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "service_name": self.service_name,
            "service_type": self.service_type.value,
            "description": self.description,
            "versions": {v: [inst.to_dict() for inst in inst_list] 
                        for v, inst_list in self.versions.items()},
            "total_instances": self.total_instances,
            "healthy_instances": self.healthy_instances,
            "last_updated": self.last_updated
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FederatedService":
        service = cls(
            service_name=data["service_name"],
            service_type=ServiceType(data.get("service_type", "custom")),
            description=data.get("description", ""),
            total_instances=data.get("total_instances", 0),
            healthy_instances=data.get("healthy_instances", 0),
            last_updated=data.get("last_updated", time.time())
        )
        
        # Load versions
        for version, instances in data.get("versions", {}).items():
            service.versions[version] = [
                ServiceInstance.from_dict(inst) for inst in instances
            ]
        
        return service


class ServiceFederation:
    """
    Main federation service manager.
    
    This class manages the discovery, registration, and health monitoring
    of services across the P2P network.
    """
    
    def __init__(self, dht_network: Optional[DHTNetwork] = None):
        """
        Initialize service federation.
        
        Args:
            dht_network: DHT network instance for service propagation
        """
        self.dht = dht_network
        self.services: Dict[str, FederatedService] = {}
        self.service_lock = asyncio.Lock()
        self.health_check_tasks: Dict[str, asyncio.Task] = {}
        self.web_app: Optional[web.Application] = None
        self.web_runner: Optional[web.AppRunner] = None
        self.web_site: Optional[web.TCPSite] = None
        
        # Load persisted services
        self._load_services()
        
        log.info("Service Federation initialized")
    
    def _load_services(self):
        """Load services from disk."""
        try:
            FEDERATION_DIR.mkdir(parents=True, exist_ok=True)
            if SERVICE_REGISTRY_FILE.exists():
                with open(SERVICE_REGISTRY_FILE, 'r') as f:
                    data = json.load(f)
                    for service_data in data.get("services", []):
                        service = FederatedService.from_dict(service_data)
                        self.services[service.service_name] = service
                log.info(f"Loaded {len(self.services)} services from disk")
        except Exception as e:
            log.error(f"Failed to load services: {e}")
    
    def _save_services(self):
        """Save services to disk."""
        try:
            FEDERATION_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "services": [s.to_dict() for s in self.services.values()],
                "updated_at": time.time()
            }
            with open(SERVICE_REGISTRY_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            log.debug("Saved services to disk")
        except Exception as e:
            log.error(f"Failed to save services: {e}")
    
    async def start(self, web_port: int = 8734):
        """Start federation service."""
        # Start HTTP API
        await self._start_web_api(web_port)
        
        # Start health check loop
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        
        log.info(f"Service Federation started on port {web_port}")
    
    async def stop(self):
        """Stop federation service."""
        if hasattr(self, 'health_check_task'):
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
        
        # Save services before stopping
        self._save_services()
        
        if self.web_runner:
            await self.web_runner.cleanup()
        
        log.info("Service Federation stopped")
    
    async def _health_check_loop(self):
        """Periodically check health of all services."""
        while True:
            try:
                await self._perform_health_checks()
            except Exception as e:
                log.error(f"Health check loop error: {e}")
            
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
    
    async def _perform_health_checks(self):
        """Perform health checks on all services."""
        async with self.service_lock:
            for service in self.services.values():
                for instance in service.get_instances():
                    await self._check_instance_health(instance)
        
        # Clean up expired instances
        total_removed = 0
        for service in self.services.values():
            removed = service.remove_expired_instances()
            total_removed += removed
        
        if total_removed > 0:
            log.info(f"Cleaned up {total_removed} expired service instances")
            self._save_services()
    
    async def _check_instance_health(self, instance: ServiceInstance) -> ServiceHealth:
        """Check health of a service instance."""
        try:
            start_time = time.time()
            
            # Try to connect to the service
            # This is a basic check - can be extended per service type
            if instance.endpoint:
                # Simple HTTP check
                try:
                    import aiohttp
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get(f"{instance.endpoint}/health") as response:
                            latency = (time.time() - start_time) * 1000  # ms
                            if response.status == 200:
                                health = ServiceHealth(
                                    status=ServiceStatus.ONLINE,
                                    latency_ms=latency,
                                    version=instance.version
                                )
                            else:
                                health = ServiceHealth(
                                    status=ServiceStatus.DEGRADED,
                                    latency_ms=latency,
                                    error=f"HTTP {response.status}",
                                    version=instance.version
                                )
                except asyncio.TimeoutError:
                    health = ServiceHealth(
                        status=ServiceStatus.OFFLINE,
                        latency_ms=(time.time() - start_time) * 1000,
                        error="Timeout",
                        version=instance.version
                    )
                except Exception as e:
                    health = ServiceHealth(
                        status=ServiceStatus.OFFLINE,
                        latency_ms=(time.time() - start_time) * 1000,
                        error=str(e),
                        version=instance.version
                    )
            else:
                # For services without endpoint, just mark as online
                # (health is determined by node connectivity)
                health = ServiceHealth(
                    status=ServiceStatus.ONLINE,
                    version=instance.version
                )
            
            # Update instance health
            instance.update_health(health)
            
            # Log significant changes
            if health.status != instance.health.status:
                log.info(f"Service {instance.service_name}@{instance.node_id} "
                        f"status changed: {instance.health.status.value} -> {health.status.value}")
            
            return health
            
        except Exception as e:
            log.error(f"Error checking health for {instance.service_name}: {e}")
            return ServiceHealth(
                status=ServiceStatus.UNKNOWN,
                error=str(e)
            )
    
    async def register_service(self, 
                               service_name: str, 
                               service_type: str = "custom",
                               node_id: str = "",
                               node_ip: str = "",
                               node_port: int = 0,
                               version: str = "1.0.0",
                               endpoint: Optional[str] = None,
                               metadata: Optional[Dict[str, Any]] = None,
                               ttl: int = SERVICE_TTL) -> ServiceInstance:
        """
        Register a new service instance.
        
        Args:
            service_name: Name of the service
            service_type: Type of service (api, storage, etc.)
            node_id: ID of the node providing the service
            node_ip: IP address of the node
            node_port: Port of the node
            version: Service version
            endpoint: Optional service endpoint URL
            metadata: Optional service metadata
            ttl: Time-to-live for the registration
            
        Returns:
            The registered service instance
        """
        async with self.service_lock:
            # Get or create federated service
            if service_name not in self.services:
                self.services[service_name] = FederatedService(
                    service_name=service_name,
                    service_type=ServiceType(service_type)
                )
            
            service = self.services[service_name]
            
            # Create service instance
            instance = ServiceInstance(
                service_name=service_name,
                service_type=ServiceType(service_type),
                node_id=node_id or self._get_local_node_id(),
                node_ip=node_ip or self._get_local_ip(),
                node_port=node_port or MESH_PORT,
                version=version,
                endpoint=endpoint,
                metadata=metadata or {},
                ttl=ttl
            )
            
            # Add to service
            service.add_instance(instance)
            
            # Store in DHT for propagation
            if self.dht:
                dht_key = instance.get_dht_key()
                await self.dht.store_value(dht_key, instance.to_dict(), ttl)
            
            # Save to disk
            self._save_services()
            
            # Start health check for this instance
            self._start_instance_health_check(instance)
            
            log.info(f"Registered service: {service_name} v{version} at {node_ip}:{node_port}")
            
            return instance
    
    async def unregister_service(self, instance_id: str) -> bool:
        """Unregister a service instance."""
        async with self.service_lock:
            for service in self.services.values():
                for version, instances in list(service.versions.items()):
                    for i, instance in enumerate(instances):
                        if instance.instance_id == instance_id:
                            # Remove from DHT
                            if self.dht:
                                dht_key = instance.get_dht_key()
                                await self.dht.store_value(dht_key, None, 0)  # Remove
                            
                            # Remove instance
                            instances.pop(i)
                            
                            # Clean up empty versions
                            if not instances:
                                del service.versions[version]
                            
                            self._save_services()
                            log.info(f"Unregistered service instance: {instance_id}")
                            return True
        
        return False
    
    async def discover_services(self, 
                             service_name: Optional[str] = None,
                             service_type: Optional[str] = None,
                             healthy_only: bool = False) -> List[Dict[str, Any]]:
        """
        Discover services in the federation.
        
        Args:
            service_name: Filter by service name
            service_type: Filter by service type
            healthy_only: Only return healthy instances
            
        Returns:
            List of service instance dictionaries
        """
        async with self.service_lock:
            result = []
            
            for service in self.services.values():
                # Filter by name
                if service_name and service.service_name != service_name:
                    continue
                
                # Filter by type
                if service_type and service.service_type.value != service_type:
                    continue
                
                # Get instances
                instances = service.get_healthy_instances() if healthy_only else service.get_instances()
                
                for instance in instances:
                    result.append(instance.to_dict())
            
            return result
    
    async def discover_from_dht(self, service_name: str) -> List[Dict[str, Any]]:
        """Discover service instances from DHT."""
        if not self.dht:
            return []
        
        # Query DHT for service instances
        dht_key_prefix = f"service:{service_name}:"
        
        # In a full implementation, we'd do a DHT lookup for keys starting with this prefix
        # For now, we'll use the DHT's get_value for specific keys
        # This is a simplified version
        
        # Try to get all known service instances
        result = []
        for node in await self.dht.find_peers(limit=100):
            # Try to get service info from this node
            node_id = node["node_id"]
            dht_key = f"service:{service_name}:{node_id}"
            value = await self.dht.get_value(dht_key)
            if value:
                result.append(value)
        
        return result
    
    def _start_instance_health_check(self, instance: ServiceInstance):
        """Start health check task for a specific instance."""
        # For now, we use the global health check loop
        # In a more sophisticated implementation, each instance could have its own check schedule
        pass
    
    def _get_local_node_id(self) -> str:
        """Get local node ID."""
        try:
            # Try to read from node ID file
            node_id_file = Path("/var/lib/secubox/p2p/node.id")
            if node_id_file.exists():
                return node_id_file.read_text().strip()
        except:
            pass
        
        # Fallback: generate from hostname
        import socket
        hostname = socket.gethostname()
        return hashlib.sha1(hostname.encode()).hexdigest()[:20]
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            import socket
            # Get first non-localhost IP
            host = socket.gethostname()
            addrs = socket.getaddrinfo(host, None)
            for addr in addrs:
                ip = addr[4][0]
                if ip.startswith("127.") or ip.startswith("::1"):
                    continue
                if ":" in ip:  # IPv6
                    return f"[{ip}]"
                return ip
        except:
            pass
        return "127.0.0.1"
    
    async def _start_web_api(self, port: int):
        """Start HTTP API for service federation."""
        self.web_app = web.Application()
        
        # Routes
        self.web_app.router.add_post("/federation/services", self.http_register_service)
        self.web_app.router.add_get("/federation/services", self.http_discover_services)
        self.web_app.router.add_get("/federation/services/{service_name}", self.http_get_service)
        self.web_app.router.add_delete("/federation/services/{instance_id}", self.http_unregister_service)
        self.web_app.router.add_get("/federation/health", self.http_get_health)
        self.web_app.router.add_get("/federation/stats", self.http_get_stats)
        
        # Start server
        self.web_runner = web.AppRunner(self.web_app)
        await self.web_runner.setup()
        self.web_site = web.TCPSite(self.web_runner, "0.0.0.0", port)
        await self.web_site.start()
        
        log.info(f"Service Federation HTTP API started on port {port}")
    
    async def http_register_service(self, request: web.Request) -> web.Response:
        """HTTP endpoint to register a service."""
        try:
            data = await request.json()
            
            service_name = data.get("service_name")
            if not service_name:
                return web.json_response({"error": "service_name required"}, status=400)
            
            instance = await self.register_service(
                service_name=service_name,
                service_type=data.get("service_type", "custom"),
                node_id=data.get("node_id", ""),
                node_ip=data.get("node_ip", ""),
                node_port=data.get("node_port", 0),
                version=data.get("version", "1.0.0"),
                endpoint=data.get("endpoint"),
                metadata=data.get("metadata", {}),
                ttl=data.get("ttl", SERVICE_TTL)
            )
            
            return web.json_response(instance.to_dict())
            
        except Exception as e:
            log.error(f"Failed to register service: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def http_discover_services(self, request: web.Request) -> web.Response:
        """HTTP endpoint to discover services."""
        try:
            service_name = request.query.get("service_name")
            service_type = request.query.get("service_type")
            healthy_only = request.query.get("healthy_only", "false").lower() == "true"
            
            services = await self.discover_services(
                service_name=service_name,
                service_type=service_type,
                healthy_only=healthy_only
            )
            
            return web.json_response(services)
            
        except Exception as e:
            log.error(f"Failed to discover services: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def http_get_service(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get a specific service."""
        service_name = request.match_info["service_name"]
        
        async with self.service_lock:
            if service_name not in self.services:
                return web.json_response({"error": "Service not found"}, status=404)
            
            service = self.services[service_name]
            return web.json_response(service.to_dict())
    
    async def http_unregister_service(self, request: web.Request) -> web.Response:
        """HTTP endpoint to unregister a service."""
        instance_id = request.match_info["instance_id"]
        
        success = await self.unregister_service(instance_id)
        if success:
            return web.json_response({"success": True})
        else:
            return web.json_response({"error": "Service instance not found"}, status=404)
    
    async def http_get_health(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get service health status."""
        service_name = request.query.get("service_name")
        
        async with self.service_lock:
            if service_name and service_name in self.services:
                services = [self.services[service_name]]
            else:
                services = list(self.services.values())
            
            result = []
            for service in services:
                result.append({
                    "service_name": service.service_name,
                    "total_instances": service.total_instances,
                    "healthy_instances": service.healthy_instances,
                    "versions": list(service.versions.keys())
                })
            
            return web.json_response(result)
    
    async def http_get_stats(self, request: web.Request) -> web.Response:
        """HTTP endpoint to get federation statistics."""
        async with self.service_lock:
            total_services = len(self.services)
            total_instances = sum(s.total_instances for s in self.services.values())
            healthy_instances = sum(s.healthy_instances for s in self.services.values())
            
            return web.json_response({
                "total_services": total_services,
                "total_instances": total_instances,
                "healthy_instances": healthy_instances,
                "service_types": {s.service_type.value: s.total_instances 
                                for s in self.services.values()}
            })


# Global federation instance
_federation_instance: Optional[ServiceFederation] = None


async def get_federation_instance() -> ServiceFederation:
    """Get or create global federation instance."""
    global _federation_instance
    if _federation_instance is None:
        dht = await get_dht_instance()
        _federation_instance = ServiceFederation(dht_network=dht)
        await _federation_instance.start()
    return _federation_instance


async def shutdown_federation():
    """Shutdown global federation instance."""
    global _federation_instance
    if _federation_instance:
        await _federation_instance.stop()
        _federation_instance = None


if __name__ == "__main__":
    # Test federation functionality
    import asyncio
    
    async def test_federation():
        # Create federation instance
        federation = ServiceFederation()
        await federation.start(web_port=8735)
        
        # Register a service
        instance = await federation.register_service(
            service_name="test-service",
            service_type="api",
            node_id="test-node-1",
            node_ip="127.0.0.1",
            node_port=8080,
            version="1.0.0",
            endpoint="http://127.0.0.1:8080",
            metadata={"description": "Test API service"}
        )
        print(f"Registered service: {instance.service_name}")
        
        # Discover services
        services = await federation.discover_services()
        print(f"Discovered {len(services)} services")
        for service in services:
            print(f"  {service['service_name']} v{service['version']} at {service['node_ip']}:{service['node_port']}")
        
        # Get stats
        stats = await federation.http_get_stats(None)
        print(f"Stats: {stats}")
        
        # Wait for a while
        print("Running federation server... Press Ctrl+C to stop")
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await federation.stop()
            print("Federation server stopped")
    
    asyncio.run(test_federation())
