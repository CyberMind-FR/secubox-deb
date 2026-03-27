"""SecuBox MCP Server - Model Context Protocol for AI Integration
Provides MCP (Model Context Protocol) interface for Claude and other AI assistants
to interact with SecuBox security modules.

Features:
- JSON-RPC 2.0 over stdio transport
- Resource exposure (logs, configs, alerts)
- Tool registration (security actions)
- Prompt templates for security analysis
- Multi-module aggregation
"""
import os
import json
import logging
import asyncio
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable
from enum import Enum

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

# MCP Protocol Version
MCP_VERSION = "2024-11-05"

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


class MCPServer:
    """MCP protocol server for SecuBox integration."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.tools_file = data_dir / "tools.json"
        self.sessions_file = data_dir / "sessions.jsonl"
        self._ensure_dirs()
        self.sessions: Dict[str, MCPSession] = {}
        self._register_tools()
        self._register_resources()
        self._register_prompts()

    def _ensure_dirs(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)

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
            "secubox://config/haproxy": MCPResource(
                uri="secubox://config/haproxy",
                name="HAProxy Configuration",
                description="Current HAProxy configuration",
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
        # Call appropriate SecuBox module API
        module_map = {
            "secubox.waf.status": ("http://127.0.0.1:8010/status", "GET"),
            "secubox.waf.threats": ("http://127.0.0.1:8010/alerts", "GET"),
            "secubox.crowdsec.alerts": ("cscli alerts list -o json", "CMD"),
            "secubox.crowdsec.decisions": ("cscli decisions list -o json", "CMD"),
            "secubox.dns.analyze": ("http://127.0.0.1:8030/analyze", "POST"),
            "secubox.dns.blocklist": ("http://127.0.0.1:8030/blocklist", "GET"),
            "secubox.network.anomalies": ("http://127.0.0.1:8031/alerts", "GET"),
            "secubox.iot.devices": ("http://127.0.0.1:8032/devices", "GET"),
            "secubox.cve.scan": ("http://127.0.0.1:8033/cves", "GET"),
            "secubox.audit.run": ("http://127.0.0.1:8034/audit", "POST"),
            "secubox.identity.info": ("http://127.0.0.1:8035/identity", "GET"),
            "secubox.mesh.peers": ("http://127.0.0.1:8036/peers", "GET"),
        }

        if tool_name not in module_map:
            return {"error": f"Tool {tool_name} not implemented"}

        endpoint, method = module_map[tool_name]

        if method == "CMD":
            # Execute shell command
            try:
                result = subprocess.run(
                    endpoint.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                return json.loads(result.stdout) if result.stdout else {"output": result.stderr}
            except Exception as e:
                return {"error": str(e)}
        else:
            # HTTP request
            try:
                async with httpx.AsyncClient() as client:
                    if method == "GET":
                        response = await client.get(endpoint, params=args, timeout=10.0)
                    else:
                        response = await client.post(endpoint, json=args, timeout=10.0)
                    return response.json()
            except Exception as e:
                return {"error": str(e)}

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
            "secubox://config/haproxy": self._read_haproxy_config,
            "secubox://config/nftables": self._read_nftables,
            "secubox://alerts/all": self._read_all_alerts,
            "secubox://status/all": self._read_all_status,
        }

        reader = resource_readers.get(uri)
        if reader:
            return await reader()
        return ""

    async def _read_waf_logs(self) -> str:
        log_file = Path("/var/log/mitmproxy/waf.jsonl")
        if log_file.exists():
            lines = log_file.read_text().strip().split("\n")
            return "\n".join(lines[-100:])
        return "No WAF logs found"

    async def _read_crowdsec_logs(self) -> str:
        log_file = Path("/var/log/crowdsec.log")
        if log_file.exists():
            lines = log_file.read_text().strip().split("\n")
            return "\n".join(lines[-100:])
        return "No CrowdSec logs found"

    async def _read_haproxy_config(self) -> str:
        config_file = Path("/etc/haproxy/haproxy.cfg")
        if config_file.exists():
            return config_file.read_text()
        return "HAProxy config not found"

    async def _read_nftables(self) -> str:
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    async def _read_all_alerts(self) -> str:
        alerts = {"waf": [], "crowdsec": [], "dns": [], "anomaly": []}
        # Aggregate from all modules
        return json.dumps(alerts, indent=2)

    async def _read_all_status(self) -> str:
        modules = ["waf", "crowdsec", "dns-guard", "network-anomaly", "iot-guard"]
        status = {}
        for module in modules:
            try:
                async with httpx.AsyncClient() as client:
                    port = 8010 + modules.index(module)
                    response = await client.get(f"http://127.0.0.1:{port}/status", timeout=2.0)
                    status[module] = response.json()
            except Exception:
                status[module] = {"status": "unavailable"}
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


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("MCP Server started")
