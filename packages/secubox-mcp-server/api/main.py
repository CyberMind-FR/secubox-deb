"""SecuBox MCP Server - Model Context Protocol for AI Integration
Provides MCP (Model Context Protocol) interface for Claude and other AI assistants
to interact with SecuBox security modules.

Features:
- JSON-RPC 2.0 over stdio transport
- Resource exposure (logs, configs, alerts)
- Tool registration (security actions)
- Prompt templates for security analysis
- Multi-module aggregation with caching
- Configurable module port mapping
"""
import os
import json
import logging
import asyncio
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable, Tuple
from enum import Enum
from functools import lru_cache
import time

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/mcp-server.toml")
DATA_DIR = Path("/var/lib/secubox/mcp-server")
TOOLS_FILE = DATA_DIR / "tools.json"
SESSIONS_FILE = DATA_DIR / "sessions.jsonl"
CACHE_DIR = Path("/tmp/secubox/mcp-cache")

# MCP Protocol Version
MCP_VERSION = "2024-11-05"

# Module socket mapping - Unix sockets in /run/secubox/
MODULE_SOCKETS = {
    "ai-gateway": "/run/secubox/ai-gateway.sock",
    "localrecall": "/run/secubox/localrecall.sock",
    "master-link": "/run/secubox/master-link.sock",
    "threat-analyst": "/run/secubox/threat-analyst.sock",
    "cve-triage": "/run/secubox/cve-triage.sock",
    "iot-guard": "/run/secubox/iot-guard.sock",
    "config-advisor": "/run/secubox/config-advisor.sock",
    "mcp-server": "/run/secubox/mcp-server.sock",
    "dns-guard": "/run/secubox/dns-guard.sock",
    "network-anomaly": "/run/secubox/network-anomaly.sock",
    "identity": "/run/secubox/identity.sock",
    "system-hub": "/run/secubox/system-hub.sock",
}

# Cache TTL in seconds
CACHE_TTL = {
    "status": 30,
    "alerts": 60,
    "config": 300,
    "logs": 30,
}

app = FastAPI(title="SecuBox MCP Server", version="1.0.0")
logger = logging.getLogger("secubox.mcp-server")


class MCPMessageType(str, Enum):
    INITIALIZE = "initialize"
    INITIALIZED = "initialized"
    TOOLS_LIST = "tools/list"
    TOOLS_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCES_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPTS_GET = "prompts/get"
    PING = "ping"
    PONG = "pong"


class MCPError(BaseModel):
    code: int
    message: str
    data: Optional[Any] = None


class MCPRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    method: str
    params: Optional[Dict[str, Any]] = None


class MCPResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[MCPError] = None


class MCPTool(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any]


class MCPResource(BaseModel):
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: Optional[str] = None


class MCPPrompt(BaseModel):
    name: str
    description: Optional[str] = None
    arguments: Optional[List[Dict[str, Any]]] = None


class MCPSession(BaseModel):
    id: str
    client_name: Optional[str] = None
    client_version: Optional[str] = None
    capabilities: Dict[str, Any] = {}
    created_at: str
    last_activity: str


class CacheManager:
    """Simple in-memory cache with TTL."""

    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self._memory_cache: Dict[str, Tuple[Any, float]] = {}
        cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str, ttl: int = 60) -> Optional[Any]:
        """Get cached value if not expired."""
        if key in self._memory_cache:
            value, timestamp = self._memory_cache[key]
            if time.time() - timestamp < ttl:
                return value

        # Try file cache
        cache_file = self.cache_dir / f"{key.replace('/', '_')}.json"
        if cache_file.exists():
            try:
                stat = cache_file.stat()
                if time.time() - stat.st_mtime < ttl:
                    with open(cache_file) as f:
                        return json.load(f)
            except Exception:
                pass
        return None

    def set(self, key: str, value: Any):
        """Set cache value."""
        self._memory_cache[key] = (value, time.time())

        # Also persist to file for cross-request caching
        try:
            cache_file = self.cache_dir / f"{key.replace('/', '_')}.json"
            with open(cache_file, "w") as f:
                json.dump(value, f)
        except Exception:
            pass

    def invalidate(self, key: str):
        """Invalidate cache entry."""
        self._memory_cache.pop(key, None)
        cache_file = self.cache_dir / f"{key.replace('/', '_')}.json"
        if cache_file.exists():
            cache_file.unlink()

    def clear(self):
        """Clear all cache."""
        self._memory_cache.clear()
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except Exception:
                pass


class MCPServer:
    """MCP protocol server for SecuBox integration."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tools_file = data_dir / "tools.json"
        self.sessions_file = data_dir / "sessions.jsonl"
        self.cache = CacheManager(CACHE_DIR)
        self._ensure_dirs()
        self.sessions: Dict[str, MCPSession] = {}
        self._register_tools()
        self._register_resources()
        self._register_prompts()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def _get_module_socket(self, module: str) -> str:
        """Get Unix socket path for a module."""
        return MODULE_SOCKETS.get(module, f"/run/secubox/{module}.sock")

    async def _call_module(self, module: str, path: str, method: str = "GET",
                           params: Dict = None, json_data: Dict = None) -> Dict:
        """Call a module via its Unix socket."""
        socket_path = self._get_module_socket(module)

        if not Path(socket_path).exists():
            return {"error": f"Module {module} socket not found"}

        try:
            transport = httpx.AsyncHTTPTransport(uds=socket_path)
            async with httpx.AsyncClient(transport=transport, timeout=10.0) as client:
                url = f"http://localhost{path}"
                if method == "GET":
                    response = await client.get(url, params=params)
                else:
                    response = await client.post(url, json=json_data or params)

                if response.status_code == 200:
                    return response.json()
                else:
                    return {"error": f"HTTP {response.status_code}", "detail": response.text[:200]}
        except httpx.TimeoutException:
            return {"error": f"Timeout connecting to {module}"}
        except Exception as e:
            return {"error": str(e)}

    def _register_tools(self):
        """Register available tools."""
        self.tools: Dict[str, MCPTool] = {
            "secubox.waf.status": MCPTool(
                name="secubox.waf.status",
                description="Get WAF (mitmproxy) status and recent threat statistics",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "required": []
                }
            ),
            "secubox.waf.threats": MCPTool(
                name="secubox.waf.threats",
                description="List recent WAF threats and blocked requests",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "description": "Hours to look back", "default": 24},
                        "limit": {"type": "integer", "description": "Max results", "default": 50}
                    }
                }
            ),
            "secubox.crowdsec.alerts": MCPTool(
                name="secubox.crowdsec.alerts",
                description="Get CrowdSec security alerts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "default": 20}
                    }
                }
            ),
            "secubox.crowdsec.decisions": MCPTool(
                name="secubox.crowdsec.decisions",
                description="List CrowdSec active decisions (bans)",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            "secubox.dns.analyze": MCPTool(
                name="secubox.dns.analyze",
                description="Analyze a domain for DGA, tunneling, or malicious patterns",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Domain to analyze"}
                    },
                    "required": ["domain"]
                }
            ),
            "secubox.dns.blocklist": MCPTool(
                name="secubox.dns.blocklist",
                description="Get current DNS blocklist",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            "secubox.network.anomalies": MCPTool(
                name="secubox.network.anomalies",
                description="Get network anomaly alerts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "hours": {"type": "integer", "default": 24}
                    }
                }
            ),
            "secubox.iot.devices": MCPTool(
                name="secubox.iot.devices",
                description="List discovered IoT devices on the network",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "risk_level": {"type": "string", "enum": ["critical", "high", "medium", "low", "safe"]}
                    }
                }
            ),
            "secubox.cve.scan": MCPTool(
                name="secubox.cve.scan",
                description="Check for CVE vulnerabilities in installed packages",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "package": {"type": "string", "description": "Package name to check (optional)"}
                    }
                }
            ),
            "secubox.audit.run": MCPTool(
                name="secubox.audit.run",
                description="Run security configuration audit (ANSSI CSPN checks)",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            "secubox.identity.info": MCPTool(
                name="secubox.identity.info",
                description="Get node identity and DID information",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            "secubox.mesh.peers": MCPTool(
                name="secubox.mesh.peers",
                description="List mesh network peers",
                inputSchema={
                    "type": "object",
                    "properties": {}
                }
            ),
            "secubox.localrecall.search": MCPTool(
                name="secubox.localrecall.search",
                description="Search local recall memory for security context",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query"},
                        "category": {"type": "string", "description": "Optional category filter"}
                    },
                    "required": ["query"]
                }
            ),
            "secubox.ai.query": MCPTool(
                name="secubox.ai.query",
                description="Query the AI gateway for security analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "prompt": {"type": "string", "description": "Analysis prompt"},
                        "context": {"type": "string", "description": "Additional context"}
                    },
                    "required": ["prompt"]
                }
            ),
            "secubox.threat.generate_rule": MCPTool(
                name="secubox.threat.generate_rule",
                description="Generate a security rule from threat data",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "threat_type": {"type": "string", "enum": ["ip", "domain", "pattern"]},
                        "indicator": {"type": "string", "description": "IOC value"},
                        "rule_type": {"type": "string", "enum": ["nftables", "crowdsec", "waf"]}
                    },
                    "required": ["threat_type", "indicator"]
                }
            )
        }

    def _register_resources(self):
        """Register available resources."""
        self.resources: Dict[str, MCPResource] = {
            "secubox://logs/waf": MCPResource(
                uri="secubox://logs/waf",
                name="WAF Logs",
                description="Recent mitmproxy WAF logs",
                mimeType="application/jsonl"
            ),
            "secubox://logs/crowdsec": MCPResource(
                uri="secubox://logs/crowdsec",
                name="CrowdSec Logs",
                description="CrowdSec security logs",
                mimeType="text/plain"
            ),
            "secubox://logs/dns": MCPResource(
                uri="secubox://logs/dns",
                name="DNS Guard Logs",
                description="DNS security and blocking logs",
                mimeType="application/jsonl"
            ),
            "secubox://config/haproxy": MCPResource(
                uri="secubox://config/haproxy",
                name="HAProxy Configuration",
                description="Current HAProxy configuration",
                mimeType="text/plain"
            ),
            "secubox://config/nginx": MCPResource(
                uri="secubox://config/nginx",
                name="Nginx Configuration",
                description="Current nginx configuration",
                mimeType="text/plain"
            ),
            "secubox://config/nftables": MCPResource(
                uri="secubox://config/nftables",
                name="Firewall Rules",
                description="Current nftables firewall rules",
                mimeType="text/plain"
            ),
            "secubox://alerts/all": MCPResource(
                uri="secubox://alerts/all",
                name="All Security Alerts",
                description="Aggregated alerts from all modules",
                mimeType="application/json"
            ),
            "secubox://status/all": MCPResource(
                uri="secubox://status/all",
                name="System Status",
                description="Status of all SecuBox modules",
                mimeType="application/json"
            )
        }

    def _register_prompts(self):
        """Register prompt templates."""
        self.prompts: Dict[str, MCPPrompt] = {
            "security-summary": MCPPrompt(
                name="security-summary",
                description="Generate a security status summary",
                arguments=[
                    {"name": "timeframe", "description": "Time period (e.g., '24h', '7d')", "required": False}
                ]
            ),
            "threat-analysis": MCPPrompt(
                name="threat-analysis",
                description="Analyze a specific threat or attack pattern",
                arguments=[
                    {"name": "ip", "description": "Source IP to analyze", "required": False},
                    {"name": "domain", "description": "Domain to analyze", "required": False}
                ]
            ),
            "incident-report": MCPPrompt(
                name="incident-report",
                description="Generate an incident report",
                arguments=[
                    {"name": "alert_id", "description": "Alert ID to report on", "required": True}
                ]
            ),
            "hardening-recommendations": MCPPrompt(
                name="hardening-recommendations",
                description="Get security hardening recommendations based on audit",
                arguments=[]
            )
        }

    def create_session(self, client_info: Dict = None) -> MCPSession:
        """Create a new MCP session."""
        import uuid
        session_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"

        session = MCPSession(
            id=session_id,
            client_name=client_info.get("name") if client_info else None,
            client_version=client_info.get("version") if client_info else None,
            capabilities=client_info.get("capabilities", {}) if client_info else {},
            created_at=now,
            last_activity=now
        )
        self.sessions[session_id] = session
        return session

    async def handle_request(self, request: MCPRequest) -> MCPResponse:
        """Handle MCP request."""
        try:
            method = request.method
            params = request.params or {}

            if method == "initialize":
                return await self._handle_initialize(request, params)
            elif method == "tools/list":
                return await self._handle_tools_list(request)
            elif method == "tools/call":
                return await self._handle_tools_call(request, params)
            elif method == "resources/list":
                return await self._handle_resources_list(request)
            elif method == "resources/read":
                return await self._handle_resources_read(request, params)
            elif method == "prompts/list":
                return await self._handle_prompts_list(request)
            elif method == "prompts/get":
                return await self._handle_prompts_get(request, params)
            elif method == "ping":
                return MCPResponse(id=request.id, result={})
            else:
                return MCPResponse(
                    id=request.id,
                    error=MCPError(code=-32601, message=f"Method not found: {method}")
                )
        except Exception as e:
            logger.error(f"MCP request error: {e}")
            return MCPResponse(
                id=request.id,
                error=MCPError(code=-32603, message=str(e))
            )

    async def _handle_initialize(self, request: MCPRequest, params: Dict) -> MCPResponse:
        """Handle initialize request."""
        client_info = params.get("clientInfo", {})
        session = self.create_session(client_info)

        return MCPResponse(
            id=request.id,
            result={
                "protocolVersion": MCP_VERSION,
                "serverInfo": {
                    "name": "secubox-mcp-server",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"subscribe": False, "listChanged": True},
                    "prompts": {"listChanged": True}
                }
            }
        )

    async def _handle_tools_list(self, request: MCPRequest) -> MCPResponse:
        """List available tools."""
        return MCPResponse(
            id=request.id,
            result={"tools": [t.model_dump() for t in self.tools.values()]}
        )

    async def _handle_tools_call(self, request: MCPRequest, params: Dict) -> MCPResponse:
        """Execute a tool."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name not in self.tools:
            return MCPResponse(
                id=request.id,
                error=MCPError(code=-32602, message=f"Tool not found: {tool_name}")
            )

        result = await self._execute_tool(tool_name, arguments)
        return MCPResponse(
            id=request.id,
            result={"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
        )

    async def _execute_tool(self, tool_name: str, args: Dict) -> Any:
        """Execute tool and return result."""
        # Tool to module/endpoint mapping
        tool_mapping = {
            "secubox.waf.status": ("threat-analyst", "/status", "GET", True),
            "secubox.waf.threats": ("threat-analyst", "/alerts", "GET", True),
            "secubox.crowdsec.alerts": (None, "cscli alerts list -o json", "CMD", False),
            "secubox.crowdsec.decisions": (None, "cscli decisions list -o json", "CMD", False),
            "secubox.dns.analyze": ("dns-guard", "/analyze", "POST", False),
            "secubox.dns.blocklist": ("dns-guard", "/blocklist", "GET", True),
            "secubox.network.anomalies": ("network-anomaly", "/alerts", "GET", True),
            "secubox.iot.devices": ("iot-guard", "/devices", "GET", True),
            "secubox.cve.scan": ("cve-triage", "/cves", "GET", True),
            "secubox.audit.run": ("config-advisor", "/audit", "POST", False),
            "secubox.identity.info": ("identity", "/identity", "GET", True),
            "secubox.mesh.peers": ("master-link", "/peers", "GET", True),
            "secubox.localrecall.search": ("localrecall", "/search", "POST", False),
            "secubox.ai.query": ("ai-gateway", "/query", "POST", False),
        }

        if tool_name not in tool_mapping:
            return {"error": f"Tool {tool_name} not implemented"}

        module, path, method, cacheable = tool_mapping[tool_name]

        # Check cache for cacheable GET requests
        cache_key = f"tool_{tool_name}_{hash(json.dumps(args, sort_keys=True))}"
        if cacheable and method == "GET":
            cached = self.cache.get(cache_key, ttl=CACHE_TTL.get("status", 30))
            if cached is not None:
                return cached

        if method == "CMD":
            # Execute shell command
            try:
                result = subprocess.run(
                    path.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = json.loads(result.stdout) if result.stdout else {"output": result.stderr or "No output"}
                return output
            except json.JSONDecodeError:
                return {"output": result.stdout if result.stdout else result.stderr}
            except subprocess.TimeoutExpired:
                return {"error": "Command timed out"}
            except Exception as e:
                return {"error": str(e)}
        else:
            # Call module via Unix socket
            if method == "GET":
                result = await self._call_module(module, path, "GET", params=args)
            else:
                result = await self._call_module(module, path, "POST", json_data=args)

            if cacheable and "error" not in result:
                self.cache.set(cache_key, result)
            return result

    async def _handle_resources_list(self, request: MCPRequest) -> MCPResponse:
        """List available resources."""
        return MCPResponse(
            id=request.id,
            result={"resources": [r.model_dump() for r in self.resources.values()]}
        )

    async def _handle_resources_read(self, request: MCPRequest, params: Dict) -> MCPResponse:
        """Read a resource."""
        uri = params.get("uri")

        if uri not in self.resources:
            return MCPResponse(
                id=request.id,
                error=MCPError(code=-32602, message=f"Resource not found: {uri}")
            )

        content = await self._read_resource(uri)
        return MCPResponse(
            id=request.id,
            result={
                "contents": [{
                    "uri": uri,
                    "mimeType": self.resources[uri].mimeType,
                    "text": content
                }]
            }
        )

    async def _read_resource(self, uri: str) -> str:
        """Read resource content."""
        resource_readers = {
            "secubox://logs/waf": self._read_waf_logs,
            "secubox://logs/crowdsec": self._read_crowdsec_logs,
            "secubox://logs/dns": self._read_dns_logs,
            "secubox://config/haproxy": self._read_haproxy_config,
            "secubox://config/nftables": self._read_nftables,
            "secubox://config/nginx": self._read_nginx_config,
            "secubox://alerts/all": self._read_all_alerts,
            "secubox://status/all": self._read_all_status,
        }

        # Check cache for expensive resources
        cache_key = f"resource_{uri.replace('://', '_').replace('/', '_')}"
        cached = self.cache.get(cache_key, ttl=CACHE_TTL.get("logs", 30))
        if cached is not None:
            return cached

        reader = resource_readers.get(uri)
        if reader:
            result = await reader()
            self.cache.set(cache_key, result)
            return result
        return ""

    async def _read_waf_logs(self) -> str:
        """Read WAF (mitmproxy) logs."""
        log_paths = [
            Path("/var/log/mitmproxy/waf.jsonl"),
            Path("/var/log/secubox/waf.jsonl"),
            Path("/var/log/mitmproxy/access.log"),
        ]
        for log_file in log_paths:
            if log_file.exists():
                try:
                    lines = log_file.read_text().strip().split("\n")
                    return "\n".join(lines[-100:])
                except Exception as e:
                    continue
        return "No WAF logs found"

    async def _read_crowdsec_logs(self) -> str:
        """Read CrowdSec logs."""
        log_paths = [
            Path("/var/log/crowdsec.log"),
            Path("/var/log/crowdsec/crowdsec.log"),
        ]
        for log_file in log_paths:
            if log_file.exists():
                try:
                    lines = log_file.read_text().strip().split("\n")
                    return "\n".join(lines[-100:])
                except Exception:
                    continue

        # Try journalctl as fallback
        try:
            result = subprocess.run(
                ["journalctl", "-u", "crowdsec", "-n", "100", "--no-pager"],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout:
                return result.stdout
        except Exception:
            pass

        return "No CrowdSec logs found"

    async def _read_dns_logs(self) -> str:
        """Read DNS Guard logs."""
        log_file = Path("/var/log/secubox/dns-guard.jsonl")
        if log_file.exists():
            try:
                lines = log_file.read_text().strip().split("\n")
                return "\n".join(lines[-100:])
            except Exception:
                pass
        return "No DNS logs found"

    async def _read_haproxy_config(self) -> str:
        """Read HAProxy configuration."""
        config_file = Path("/etc/haproxy/haproxy.cfg")
        if config_file.exists():
            return config_file.read_text()
        return "HAProxy config not found"

    async def _read_nginx_config(self) -> str:
        """Read nginx configuration."""
        config_file = Path("/etc/nginx/nginx.conf")
        if config_file.exists():
            return config_file.read_text()
        return "Nginx config not found"

    async def _read_nftables(self) -> str:
        """Read nftables firewall rules."""
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout or "No rules found"
        except FileNotFoundError:
            # Try iptables as fallback
            try:
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return result.stdout or "No rules found"
            except Exception:
                pass
        except Exception as e:
            return f"Error reading firewall rules: {e}"
        return "No firewall rules found"

    async def _read_all_alerts(self) -> str:
        """Aggregate alerts from all security modules."""
        alerts = {
            "waf": [],
            "crowdsec": [],
            "dns": [],
            "anomaly": [],
            "iot": [],
            "cve": [],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # Fetch from each module concurrently via Unix sockets
        async def fetch_alerts(module: str, path: str, key: str):
            try:
                data = await self._call_module(module, path, "GET")
                if "error" not in data:
                    if isinstance(data, list):
                        alerts[key] = data[:20]
                    elif isinstance(data, dict) and "alerts" in data:
                        alerts[key] = data["alerts"][:20]
                    else:
                        alerts[key] = [data] if data else []
            except Exception as e:
                alerts[key] = [{"error": str(e)}]

        await asyncio.gather(
            fetch_alerts("threat-analyst", "/alerts", "waf"),
            fetch_alerts("dns-guard", "/alerts", "dns"),
            fetch_alerts("network-anomaly", "/alerts", "anomaly"),
            fetch_alerts("iot-guard", "/alerts", "iot"),
            fetch_alerts("cve-triage", "/cves", "cve"),
            return_exceptions=True
        )

        # Also try CrowdSec CLI
        try:
            result = subprocess.run(
                ["cscli", "alerts", "list", "-o", "json", "-l", "20"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                alerts["crowdsec"] = json.loads(result.stdout)
        except Exception:
            pass

        return json.dumps(alerts, indent=2)

    async def _read_all_status(self) -> str:
        """Get status from all SecuBox modules."""
        status = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "modules": {}
        }

        async def fetch_status(module: str):
            try:
                data = await self._call_module(module, "/status", "GET")
                if "error" not in data:
                    status["modules"][module] = data
                else:
                    status["modules"][module] = {"status": "error", "error": data.get("error")}
            except Exception as e:
                status["modules"][module] = {"status": "error", "error": str(e)}

        # Fetch all module statuses concurrently
        await asyncio.gather(
            *[fetch_status(module) for module in MODULE_SOCKETS.keys()],
            return_exceptions=True
        )

        # Count healthy/unhealthy
        healthy = sum(1 for m in status["modules"].values()
                      if isinstance(m, dict) and m.get("status") in ["ok", "healthy"])
        status["summary"] = {
            "total": len(MODULE_SOCKETS),
            "healthy": healthy,
            "unhealthy": len(MODULE_SOCKETS) - healthy
        }

        return json.dumps(status, indent=2)

    async def _handle_prompts_list(self, request: MCPRequest) -> MCPResponse:
        """List available prompts."""
        return MCPResponse(
            id=request.id,
            result={"prompts": [p.model_dump() for p in self.prompts.values()]}
        )

    async def _handle_prompts_get(self, request: MCPRequest, params: Dict) -> MCPResponse:
        """Get a prompt template."""
        prompt_name = params.get("name")
        arguments = params.get("arguments", {})

        if prompt_name not in self.prompts:
            return MCPResponse(
                id=request.id,
                error=MCPError(code=-32602, message=f"Prompt not found: {prompt_name}")
            )

        prompt_content = await self._render_prompt(prompt_name, arguments)
        return MCPResponse(
            id=request.id,
            result={
                "description": self.prompts[prompt_name].description,
                "messages": [{"role": "user", "content": {"type": "text", "text": prompt_content}}]
            }
        )

    async def _render_prompt(self, name: str, args: Dict) -> str:
        """Render prompt template with arguments."""
        if name == "security-summary":
            timeframe = args.get("timeframe", "24h")
            return f"""Generate a security status summary for the last {timeframe}.
Include:
- Total threats blocked by WAF
- CrowdSec alerts and bans
- Network anomalies detected
- IoT device status
- Configuration compliance score

Use the available tools to gather current data."""

        elif name == "threat-analysis":
            ip = args.get("ip")
            domain = args.get("domain")
            target = ip or domain or "recent threats"
            return f"""Analyze the threat: {target}
Include:
- Attack patterns and techniques
- Associated indicators of compromise
- Recommended mitigations
- Historical activity"""

        elif name == "incident-report":
            alert_id = args.get("alert_id")
            return f"""Generate an incident report for alert: {alert_id}
Include:
- Executive summary
- Timeline of events
- Impact assessment
- Root cause analysis
- Remediation steps taken
- Recommendations"""

        elif name == "hardening-recommendations":
            return """Based on the security audit results, provide hardening recommendations.
Run the audit tool first, then analyze the results and suggest:
- Critical fixes needed
- Configuration improvements
- Best practices to implement
- Long-term security roadmap"""

        return ""

    def get_stats(self) -> Dict[str, Any]:
        """Get MCP server statistics."""
        return {
            "sessions": len(self.sessions),
            "tools": len(self.tools),
            "resources": len(self.resources),
            "prompts": len(self.prompts)
        }


# Global instance
mcp_server = MCPServer(DATA_DIR)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    stats = mcp_server.get_stats()
    return {
        "module": "mcp-server",
        "status": "ok",
        "version": "1.0.0",
        "mcp_version": MCP_VERSION,
        "tools": stats["tools"],
        "resources": stats["resources"]
    }


@app.get("/health")
async def health():
    """Health check."""
    return {"status": "healthy"}


@app.get("/stats", dependencies=[Depends(require_jwt)])
async def get_stats():
    """Get MCP server statistics."""
    return mcp_server.get_stats()


@app.post("/rpc", dependencies=[Depends(require_jwt)])
async def handle_rpc(request: MCPRequest):
    """Handle MCP JSON-RPC request over HTTP."""
    response = await mcp_server.handle_request(request)
    return response


@app.get("/tools", dependencies=[Depends(require_jwt)])
async def list_tools():
    """List available tools."""
    return {"tools": list(mcp_server.tools.values())}


@app.get("/resources", dependencies=[Depends(require_jwt)])
async def list_resources():
    """List available resources."""
    return {"resources": list(mcp_server.resources.values())}


@app.get("/prompts", dependencies=[Depends(require_jwt)])
async def list_prompts():
    """List available prompts."""
    return {"prompts": list(mcp_server.prompts.values())}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for MCP communication."""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            request = MCPRequest(**json.loads(data))
            response = await mcp_server.handle_request(request)
            await websocket.send_text(json.dumps(response.model_dump()))
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")


@app.post("/cache/clear", dependencies=[Depends(require_jwt)])
async def clear_cache():
    """Clear MCP server cache."""
    mcp_server.cache.clear()
    return {"status": "cleared"}


@app.get("/cache/stats", dependencies=[Depends(require_jwt)])
async def cache_stats():
    """Get cache statistics."""
    memory_entries = len(mcp_server.cache._memory_cache)
    file_entries = len(list(CACHE_DIR.glob("*.json"))) if CACHE_DIR.exists() else 0
    return {
        "memory_entries": memory_entries,
        "file_entries": file_entries,
        "cache_dir": str(CACHE_DIR)
    }


@app.get("/modules", dependencies=[Depends(require_jwt)])
async def list_modules():
    """List all registered SecuBox modules and their sockets."""
    return {
        "modules": MODULE_SOCKETS,
        "count": len(MODULE_SOCKETS)
    }


@app.post("/tools/{tool_name}/call", dependencies=[Depends(require_jwt)])
async def call_tool_direct(tool_name: str, arguments: Dict[str, Any] = {}):
    """Directly call a tool without MCP protocol overhead."""
    if tool_name not in mcp_server.tools:
        raise HTTPException(status_code=404, detail=f"Tool not found: {tool_name}")

    result = await mcp_server._execute_tool(tool_name, arguments)
    return {"tool": tool_name, "result": result}


@app.get("/resources/{uri:path}/read", dependencies=[Depends(require_jwt)])
async def read_resource_direct(uri: str):
    """Directly read a resource without MCP protocol overhead."""
    full_uri = f"secubox://{uri}"
    if full_uri not in mcp_server.resources:
        raise HTTPException(status_code=404, detail=f"Resource not found: {full_uri}")

    content = await mcp_server._read_resource(full_uri)
    return {
        "uri": full_uri,
        "content": content,
        "mimeType": mcp_server.resources[full_uri].mimeType
    }


# ============================================================================
# Startup / Shutdown
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"MCP Server started - {len(mcp_server.tools)} tools, {len(mcp_server.resources)} resources")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    logger.info("MCP Server stopped")
