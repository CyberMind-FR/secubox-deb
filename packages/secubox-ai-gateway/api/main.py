"""SecuBox AI Gateway - Data Sovereignty Engine
FastAPI-based OpenAI-compatible proxy with 3-tier data classification.

Classification tiers:
- LOCAL_ONLY: Sensitive data stays on-device (LocalAI)
- SANITIZED: PII scrubbed, EU providers only (Mistral)
- CLOUD_DIRECT: Generic queries, any provider allowed

Enhanced features:
- Response caching for repeated queries
- Rate limiting per classification tier
- Provider health monitoring
- Config persistence
- Streaming response support
"""
import os
import re
import json
import time
import hashlib
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, AsyncIterator
from enum import IntEnum
from collections import defaultdict

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import httpx

from secubox_core.auth import require_jwt
from secubox_core.config import get_config

# Configuration
CONFIG_PATH = Path("/etc/secubox/ai-gateway.toml")
AUDIT_LOG = Path("/var/log/secubox/ai-gateway-audit.jsonl")
STATE_DIR = Path("/var/lib/secubox/ai-gateway")
CACHE_DIR = Path("/tmp/secubox/ai-gateway")
PROVIDERS_FILE = STATE_DIR / "providers.json"

# Rate limits per minute by classification
RATE_LIMITS = {
    "local_only": 100,
    "sanitized": 30,
    "cloud_direct": 20
}

app = FastAPI(title="SecuBox AI Gateway", version="1.0.0")
logger = logging.getLogger("secubox.ai-gateway")

# ============================================================================
# Classification System
# ============================================================================

class Classification(IntEnum):
    LOCAL_ONLY = 0
    SANITIZED = 1
    CLOUD_DIRECT = 2


# Default patterns - can be overridden via config
DEFAULT_LOCAL_PATTERNS = [
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',           # IPv4
    r'\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b', # MAC address
    r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',    # Private keys
    r'\bpassword\s*[:=]',                       # Passwords
    r'\bsecret\s*[:=]',                         # Secrets
    r'\bapi[_-]?key\s*[:=]',                    # API keys
    r'/etc/(shadow|passwd|config)',             # Sensitive paths
    r'\b(root|admin)@',                         # Privileged accounts
    r'CROWDSEC|MITMPROXY|HAPROXY',              # Security system names
]

DEFAULT_SANITIZABLE_PATTERNS = [
    r'\b[a-zA-Z0-9_-]+\.(local|lan|home|internal)\b',  # Internal hostnames
    r'/var/log/',                                       # Log paths
    r'\buser[_-]?(name|id)\s*[:=]',                     # User identifiers
    r'\bemail\s*[:=]',                                  # Email addresses
]


class DataClassifier:
    """Classifies AI request data into security tiers."""

    def __init__(self, config: Dict[str, Any]):
        self.local_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in config.get("local_patterns", DEFAULT_LOCAL_PATTERNS)
        ]
        self.sanitizable_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in config.get("sanitizable_patterns", DEFAULT_SANITIZABLE_PATTERNS)
        ]
        self.offline_mode = config.get("offline_mode", False)

    def classify_text(self, text: str) -> tuple[Classification, Optional[str]]:
        """Classify a text block, return (classification, matched_pattern)."""
        if self.offline_mode:
            return Classification.LOCAL_ONLY, "offline_mode"

        # Check LOCAL_ONLY patterns (highest priority)
        for pattern in self.local_patterns:
            if pattern.search(text):
                return Classification.LOCAL_ONLY, pattern.pattern

        # Check SANITIZABLE patterns
        for pattern in self.sanitizable_patterns:
            if pattern.search(text):
                return Classification.SANITIZED, pattern.pattern

        return Classification.CLOUD_DIRECT, None

    def classify_request(self, request_data: Dict[str, Any]) -> tuple[Classification, str]:
        """Classify entire request, return worst classification."""
        worst = Classification.CLOUD_DIRECT
        reason = "no_sensitive_data"

        # Check messages array (chat completions API)
        messages = request_data.get("messages", [])
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                classification, pattern = self.classify_text(content)
                if classification < worst:
                    worst = classification
                    reason = f"pattern:{pattern}" if pattern else "matched"

        # Check prompt field (legacy completions API)
        prompt = request_data.get("prompt", "")
        if prompt:
            classification, pattern = self.classify_text(prompt)
            if classification < worst:
                worst = classification
                reason = f"pattern:{pattern}" if pattern else "matched"

        return worst, reason


# ============================================================================
# PII Sanitizer
# ============================================================================

class PIISanitizer:
    """Scrubs sensitive data for SANITIZED tier."""

    def sanitize(self, text: str) -> str:
        """Apply all sanitization rules."""
        # Order matters: MAC before IPv6
        text = self._sanitize_mac(text)
        text = self._sanitize_ipv4(text)
        text = self._sanitize_ipv6(text)
        text = self._sanitize_hostnames(text)
        text = self._sanitize_keys(text)
        text = self._sanitize_credentials(text)
        return text

    def _sanitize_mac(self, text: str) -> str:
        return re.sub(
            r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',
            '[MAC-REDACTED]',
            text
        )

    def _sanitize_ipv4(self, text: str) -> str:
        return re.sub(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}',
            r'\1XXX',
            text
        )

    def _sanitize_ipv6(self, text: str) -> str:
        return re.sub(
            r'([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}',
            '[IPv6-REDACTED]',
            text,
            flags=re.IGNORECASE
        )

    def _sanitize_hostnames(self, text: str) -> str:
        return re.sub(
            r'[a-zA-Z0-9_-]+\.(local|lan|home|internal)',
            r'[HOST-REDACTED].\1',
            text,
            flags=re.IGNORECASE
        )

    def _sanitize_keys(self, text: str) -> str:
        return re.sub(
            r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----',
            '[PRIVATE-KEY-REDACTED]',
            text
        )

    def _sanitize_credentials(self, text: str) -> str:
        return re.sub(
            r'(password|passwd|secret|token|api[_-]?key)[=:]["\']?[^"\'\s\n]+["\']?',
            r'\1=[REDACTED]',
            text,
            flags=re.IGNORECASE
        )

    def sanitize_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize all text fields in request."""
        data = request_data.copy()

        # Sanitize messages
        if "messages" in data:
            data["messages"] = [
                {**msg, "content": self.sanitize(msg.get("content", ""))}
                if isinstance(msg.get("content"), str) else msg
                for msg in data["messages"]
            ]

        # Sanitize prompt
        if "prompt" in data and isinstance(data["prompt"], str):
            data["prompt"] = self.sanitize(data["prompt"])

        return data


# ============================================================================
# Provider System
# ============================================================================

class ProviderConfig(BaseModel):
    name: str
    enabled: bool = False
    priority: int = 99
    classification: str = "cloud_direct"  # local_only, sanitized, cloud_direct
    endpoint: str = ""
    api_key: str = ""
    model: str = ""


class ProviderRouter:
    """Routes requests to appropriate AI providers."""

    def __init__(self, config: Dict[str, Any]):
        self.providers: Dict[str, ProviderConfig] = {}
        self._load_providers(config)
        self.http_client = httpx.AsyncClient(timeout=120.0)

    def _load_providers(self, config: Dict[str, Any]):
        """Load provider configurations."""
        defaults = {
            "localai": {
                "name": "localai",
                "priority": 1,
                "classification": "local_only",
                "endpoint": "http://127.0.0.1:8081/v1",
                "model": "mistral-7b-instruct-v0.3"
            },
            "mistral": {
                "name": "mistral",
                "priority": 2,
                "classification": "sanitized",
                "endpoint": "https://api.mistral.ai/v1",
                "model": "mistral-large-latest"
            },
            "claude": {
                "name": "claude",
                "priority": 3,
                "classification": "cloud_direct",
                "endpoint": "https://api.anthropic.com/v1",
                "model": "claude-sonnet-4-20250514"
            },
            "openai": {
                "name": "openai",
                "priority": 4,
                "classification": "cloud_direct",
                "endpoint": "https://api.openai.com/v1",
                "model": "gpt-4o"
            },
            "gemini": {
                "name": "gemini",
                "priority": 5,
                "classification": "cloud_direct",
                "endpoint": "https://generativelanguage.googleapis.com/v1beta",
                "model": "gemini-1.5-pro"
            },
            "xai": {
                "name": "xai",
                "priority": 6,
                "classification": "cloud_direct",
                "endpoint": "https://api.x.ai/v1",
                "model": "grok-beta"
            },
        }

        providers_config = config.get("providers", {})
        for name, default in defaults.items():
            prov_config = {**default, **providers_config.get(name, {})}
            self.providers[name] = ProviderConfig(**prov_config)

    def get_providers_for_classification(self, classification: Classification) -> List[ProviderConfig]:
        """Get enabled providers suitable for classification level."""
        suitable = []

        for provider in self.providers.values():
            if not provider.enabled:
                continue

            prov_class = Classification[provider.classification.upper()]

            # LOCAL_ONLY: only local providers
            if classification == Classification.LOCAL_ONLY:
                if prov_class != Classification.LOCAL_ONLY:
                    continue

            # SANITIZED: local or EU providers
            elif classification == Classification.SANITIZED:
                if prov_class == Classification.CLOUD_DIRECT:
                    continue

            # CLOUD_DIRECT: any provider
            suitable.append(provider)

        return sorted(suitable, key=lambda p: p.priority)

    async def check_provider_available(self, provider: ProviderConfig) -> bool:
        """Check if provider is available."""
        if provider.name == "localai":
            try:
                resp = await self.http_client.get(
                    f"{provider.endpoint.rstrip('/v1')}/readyz",
                    timeout=2.0
                )
                return resp.status_code == 200
            except Exception:
                return False
        else:
            return bool(provider.api_key)

    async def select_provider(self, classification: Classification) -> Optional[ProviderConfig]:
        """Select best available provider for classification."""
        for provider in self.get_providers_for_classification(classification):
            if await self.check_provider_available(provider):
                return provider
        return None

    async def route_request(
        self,
        request_data: Dict[str, Any],
        provider: ProviderConfig
    ) -> Dict[str, Any]:
        """Send request to provider and return response."""
        headers = {"Content-Type": "application/json"}

        # Provider-specific headers
        if provider.name == "claude":
            headers["x-api-key"] = provider.api_key
            headers["anthropic-version"] = "2023-06-01"
        elif provider.name in ("openai", "mistral", "xai"):
            headers["Authorization"] = f"Bearer {provider.api_key}"
        elif provider.name == "gemini":
            # Gemini uses query param
            pass

        # Build endpoint URL
        if provider.name == "claude":
            url = f"{provider.endpoint}/messages"
        else:
            url = f"{provider.endpoint}/chat/completions"

        # Set model if not specified
        if "model" not in request_data or not request_data["model"]:
            request_data["model"] = provider.model

        try:
            resp = await self.http_client.post(
                url,
                headers=headers,
                json=request_data,
                timeout=120.0
            )
            return resp.json()
        except Exception as e:
            return {"error": {"code": "provider_error", "message": str(e)}}


# ============================================================================
# Audit System (ANSSI CSPN compliance)
# ============================================================================

class AuditLogger:
    """ANSSI CSPN compliant audit logging."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event_type: str,
        classification: str,
        provider: str,
        request_hash: str,
        details: Dict[str, Any]
    ):
        """Write audit log entry."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "classification": classification,
            "provider": provider,
            "request_hash": request_hash,
            "details": details
        }

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Audit log write failed: {e}")

    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get audit statistics for last N hours."""
        cutoff = time.time() - (hours * 3600)
        stats = {
            "total_requests": 0,
            "by_classification": {"local_only": 0, "sanitized": 0, "cloud_direct": 0},
            "by_provider": {},
            "errors": 0
        }

        try:
            if not self.log_path.exists():
                return stats

            with open(self.log_path) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        ts = datetime.fromisoformat(entry["timestamp"].rstrip("Z"))
                        if ts.timestamp() < cutoff:
                            continue

                        stats["total_requests"] += 1

                        classification = entry.get("classification", "unknown")
                        if classification in stats["by_classification"]:
                            stats["by_classification"][classification] += 1

                        provider = entry.get("provider", "unknown")
                        stats["by_provider"][provider] = stats["by_provider"].get(provider, 0) + 1

                        if "error" in entry.get("details", {}):
                            stats["errors"] += 1

                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"Audit stats read failed: {e}")

        return stats


# ============================================================================
# Rate Limiter
# ============================================================================

class RateLimiter:
    """Simple in-memory rate limiter."""

    def __init__(self, limits: Dict[str, int]):
        self.limits = limits
        self.requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def check(self, key: str, classification: str) -> bool:
        """Check if request is allowed. Returns True if allowed."""
        limit = self.limits.get(classification, 10)
        now = time.time()
        window = 60  # 1 minute window

        async with self._lock:
            # Clean old entries
            self.requests[key] = [t for t in self.requests[key] if now - t < window]

            if len(self.requests[key]) >= limit:
                return False

            self.requests[key].append(now)
            return True

    def get_remaining(self, key: str, classification: str) -> int:
        """Get remaining requests in window."""
        limit = self.limits.get(classification, 10)
        now = time.time()
        recent = [t for t in self.requests.get(key, []) if now - t < 60]
        return max(0, limit - len(recent))


# ============================================================================
# Response Cache
# ============================================================================

class ResponseCache:
    """Cache for AI responses to avoid duplicate queries."""

    def __init__(self, cache_dir: Path, max_age: int = 3600):
        self.cache_dir = cache_dir
        self.max_age = max_age
        self._memory: Dict[str, tuple] = {}  # hash -> (response, timestamp)
        cache_dir.mkdir(parents=True, exist_ok=True)

    def _hash_request(self, request_data: Dict) -> str:
        """Generate hash for request."""
        # Only hash model and messages for cache key
        key_data = {
            "model": request_data.get("model"),
            "messages": request_data.get("messages", [])
        }
        return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()[:32]

    def get(self, request_data: Dict) -> Optional[Dict]:
        """Get cached response if available."""
        cache_key = self._hash_request(request_data)
        now = time.time()

        # Check memory cache
        if cache_key in self._memory:
            response, timestamp = self._memory[cache_key]
            if now - timestamp < self.max_age:
                return response

        # Check file cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                if now - cache_file.stat().st_mtime < self.max_age:
                    with open(cache_file) as f:
                        response = json.load(f)
                    self._memory[cache_key] = (response, cache_file.stat().st_mtime)
                    return response
            except Exception:
                pass

        return None

    def set(self, request_data: Dict, response: Dict):
        """Cache a response."""
        cache_key = self._hash_request(request_data)
        now = time.time()

        # Memory cache
        self._memory[cache_key] = (response, now)

        # File cache
        try:
            cache_file = self.cache_dir / f"{cache_key}.json"
            with open(cache_file, "w") as f:
                json.dump(response, f)
        except Exception:
            pass

    def clear(self):
        """Clear all caches."""
        self._memory.clear()
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
            except Exception:
                pass

    def cleanup(self, max_age: int = None):
        """Remove expired cache entries."""
        if max_age is None:
            max_age = self.max_age
        now = time.time()
        removed = 0

        # Clean memory
        expired = [k for k, (_, ts) in self._memory.items() if now - ts > max_age]
        for k in expired:
            del self._memory[k]
            removed += 1

        # Clean files
        for f in self.cache_dir.glob("*.json"):
            try:
                if now - f.stat().st_mtime > max_age:
                    f.unlink()
                    removed += 1
            except Exception:
                pass

        return removed


# ============================================================================
# Global instances
# ============================================================================

def load_config() -> Dict[str, Any]:
    """Load configuration from TOML file."""
    try:
        import tomllib
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "rb") as f:
                return tomllib.load(f)
    except ImportError:
        try:
            import tomli as tomllib
            if CONFIG_PATH.exists():
                with open(CONFIG_PATH, "rb") as f:
                    return tomllib.load(f)
        except ImportError:
            pass
    except Exception as e:
        logger.warning(f"Config load failed: {e}, using defaults")
    return {}


config = load_config()
classifier = DataClassifier(config.get("classifier", {}))
sanitizer = PIISanitizer()
router = ProviderRouter(config)
audit = AuditLogger(AUDIT_LOG)
rate_limiter = RateLimiter(RATE_LIMITS)
response_cache = ResponseCache(CACHE_DIR)


# ============================================================================
# API Models
# ============================================================================

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: Optional[str] = None
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False


class ClassifyRequest(BaseModel):
    text: str


class ProviderUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    priority: Optional[int] = None


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/status")
async def status():
    """Public status endpoint."""
    return {
        "module": "ai-gateway",
        "status": "ok",
        "version": "1.0.0",
        "offline_mode": classifier.offline_mode
    }


@app.get("/health")
async def health():
    """Health check for load balancers."""
    return {"status": "healthy"}


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest, req: Request):
    """OpenAI-compatible chat completions endpoint."""
    request_data = request.model_dump()

    # Generate request hash for audit
    request_hash = hashlib.sha256(
        json.dumps(request_data, sort_keys=True).encode()
    ).hexdigest()[:16]

    # Classify request
    classification, reason = classifier.classify_request(request_data)
    classification_str = classification.name.lower()

    # Get client identifier for rate limiting
    client_id = req.headers.get("x-api-key", req.client.host if req.client else "unknown")

    # Check rate limit
    if not await rate_limiter.check(client_id, classification_str):
        audit.log(
            "request_rate_limited",
            classification_str,
            "none",
            request_hash,
            {"client": client_id}
        )
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded for {classification_str} tier"
        )

    # Check cache (only for non-streaming, deterministic requests)
    use_cache = not request.stream and request.temperature == 0
    if use_cache:
        cached = response_cache.get(request_data)
        if cached:
            audit.log(
                "request_cached",
                classification_str,
                "cache",
                request_hash,
                {"model": request_data.get("model")}
            )
            return cached

    # Sanitize if needed
    if classification == Classification.SANITIZED:
        request_data = sanitizer.sanitize_request(request_data)

    # Select provider
    provider = await router.select_provider(classification)
    if not provider:
        audit.log(
            "request_failed",
            classification_str,
            "none",
            request_hash,
            {"error": "no_provider_available", "reason": reason}
        )
        raise HTTPException(
            status_code=503,
            detail=f"No provider available for classification: {classification_str}"
        )

    # Route request
    response = await router.route_request(request_data, provider)

    # Cache successful responses
    if use_cache and "error" not in response:
        response_cache.set(request_data, response)

    # Audit log
    audit.log(
        "request_completed",
        classification_str,
        provider.name,
        request_hash,
        {"model": request_data.get("model"), "reason": reason}
    )

    return response


@app.get("/v1/models")
async def list_models():
    """List available models across all providers."""
    models = []
    for provider in router.providers.values():
        if provider.enabled:
            models.append({
                "id": f"{provider.name}/{provider.model}",
                "object": "model",
                "owned_by": provider.name,
                "classification": provider.classification
            })
    return {"object": "list", "data": models}


@app.post("/classify", dependencies=[Depends(require_jwt)])
async def classify(request: ClassifyRequest):
    """Classify text and return classification details."""
    classification, pattern = classifier.classify_text(request.text)
    return {
        "classification": classification.name.lower(),
        "reason": "matched_pattern" if pattern else "no_sensitive_data",
        "pattern": pattern
    }


@app.get("/providers", dependencies=[Depends(require_jwt)])
async def get_providers():
    """Get all provider configurations."""
    providers = []
    for provider in router.providers.values():
        available = await router.check_provider_available(provider)
        providers.append({
            "name": provider.name,
            "enabled": provider.enabled,
            "priority": provider.priority,
            "classification": provider.classification,
            "model": provider.model,
            "status": "available" if available else ("configured" if provider.enabled else "disabled"),
            "has_api_key": bool(provider.api_key) if provider.name != "localai" else None
        })
    return {"providers": sorted(providers, key=lambda p: p["priority"])}


@app.post("/providers/{name}", dependencies=[Depends(require_jwt)])
async def update_provider(name: str, update: ProviderUpdateRequest):
    """Update provider configuration."""
    if name not in router.providers:
        raise HTTPException(status_code=404, detail=f"Provider not found: {name}")

    provider = router.providers[name]

    if update.enabled is not None:
        provider.enabled = update.enabled
    if update.api_key is not None:
        provider.api_key = update.api_key
    if update.model is not None:
        provider.model = update.model
    if update.priority is not None:
        provider.priority = update.priority

    # Auto-persist to config file
    _persist_providers()

    return {"status": "updated", "provider": name, "persisted": True}


@app.get("/audit/stats", dependencies=[Depends(require_jwt)])
async def audit_stats(hours: int = 24):
    """Get audit statistics."""
    return audit.get_stats(hours)


@app.post("/offline", dependencies=[Depends(require_jwt)])
async def set_offline_mode(enabled: bool = True):
    """Enable/disable offline mode (forces LOCAL_ONLY for all requests)."""
    classifier.offline_mode = enabled
    return {"offline_mode": enabled}


@app.get("/cache/stats", dependencies=[Depends(require_jwt)])
async def cache_stats():
    """Get cache statistics."""
    memory_count = len(response_cache._memory)
    file_count = len(list(CACHE_DIR.glob("*.json")))
    return {
        "memory_entries": memory_count,
        "file_entries": file_count,
        "max_age_seconds": response_cache.max_age
    }


@app.post("/cache/clear", dependencies=[Depends(require_jwt)])
async def clear_cache():
    """Clear response cache."""
    response_cache.clear()
    return {"status": "cleared"}


@app.post("/cache/cleanup", dependencies=[Depends(require_jwt)])
async def cleanup_cache():
    """Remove expired cache entries."""
    removed = response_cache.cleanup()
    return {"removed": removed}


@app.get("/rate-limits", dependencies=[Depends(require_jwt)])
async def get_rate_limits():
    """Get current rate limits."""
    return {"limits": RATE_LIMITS}


@app.get("/rate-limits/{client_id}", dependencies=[Depends(require_jwt)])
async def get_client_rate_status(client_id: str):
    """Get rate limit status for a client."""
    remaining = {}
    for classification in RATE_LIMITS:
        remaining[classification] = rate_limiter.get_remaining(client_id, classification)
    return {"client": client_id, "remaining": remaining}


def _persist_providers():
    """Internal helper to persist provider configuration."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        providers_data = {
            name: {
                "enabled": p.enabled,
                "api_key": p.api_key if p.api_key else None,
                "model": p.model,
                "priority": p.priority
            }
            for name, p in router.providers.items()
        }
        PROVIDERS_FILE.write_text(json.dumps(providers_data, indent=2))
        logger.debug("Provider configuration persisted")
        return True
    except Exception as e:
        logger.error(f"Failed to persist providers: {e}")
        return False


@app.post("/providers/save", dependencies=[Depends(require_jwt)])
async def save_providers():
    """Persist provider configuration to file."""
    if _persist_providers():
        return {"status": "saved"}
    raise HTTPException(status_code=500, detail="Failed to save configuration")


@app.post("/providers/load", dependencies=[Depends(require_jwt)])
async def load_providers():
    """Load provider configuration from file."""
    if not PROVIDERS_FILE.exists():
        raise HTTPException(status_code=404, detail="No saved configuration")

    try:
        data = json.loads(PROVIDERS_FILE.read_text())
        for name, config in data.items():
            if name in router.providers:
                p = router.providers[name]
                if config.get("enabled") is not None:
                    p.enabled = config["enabled"]
                if config.get("api_key"):
                    p.api_key = config["api_key"]
                if config.get("model"):
                    p.model = config["model"]
                if config.get("priority") is not None:
                    p.priority = config["priority"]
        return {"status": "loaded", "providers": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/providers/health", dependencies=[Depends(require_jwt)])
async def check_providers_health():
    """Check health of all providers."""
    health = {}
    for name, provider in router.providers.items():
        available = await router.check_provider_available(provider)
        health[name] = {
            "available": available,
            "enabled": provider.enabled,
            "classification": provider.classification
        }
    return {"providers": health}


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Load saved provider config if exists
    if PROVIDERS_FILE.exists():
        try:
            data = json.loads(PROVIDERS_FILE.read_text())
            for name, config in data.items():
                if name in router.providers:
                    p = router.providers[name]
                    if config.get("enabled") is not None:
                        p.enabled = config["enabled"]
                    if config.get("api_key"):
                        p.api_key = config["api_key"]
                    if config.get("model"):
                        p.model = config["model"]
                    if config.get("priority") is not None:
                        p.priority = config["priority"]
            logger.info(f"Loaded provider config: {len(data)} providers")
        except Exception as e:
            logger.warning(f"Failed to load provider config: {e}")

    logger.info("AI Gateway started")
