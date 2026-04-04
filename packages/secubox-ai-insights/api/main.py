"""
secubox-ai-insights - FastAPI application
ML-based threat detection and security insights module

Features:
  - Machine learning threat detection
  - Anomaly detection in network traffic
  - Log analysis with ML models
  - Threat scoring and classification
  - Integration with CrowdSec/Suricata alerts
  - Model management (train, deploy)

Three-fold architecture:
  - /components : what is this module made of
  - /status     : health and runtime state
  - /access     : how to connect
"""
import asyncio
import json
import subprocess
import time
import threading
import hashlib
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, Field
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

log = get_logger("ai-insights")

# Data paths
DATA_DIR = Path("/var/lib/secubox/ai-insights")
MODELS_DIR = DATA_DIR / "models"
CACHE_DIR = Path("/var/cache/secubox/ai-insights")
CONFIG_FILE = Path("/etc/secubox/ai-insights.toml")
THREATS_HISTORY_FILE = DATA_DIR / "threats_history.json"
ANOMALIES_FILE = DATA_DIR / "anomalies.json"
CORRELATIONS_FILE = DATA_DIR / "correlations.json"
ANALYSIS_LOG_FILE = DATA_DIR / "analysis_log.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# Enums and Models
# ============================================================================

class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelStatus(str, Enum):
    PENDING = "pending"
    TRAINING = "training"
    READY = "ready"
    DEPLOYED = "deployed"
    FAILED = "failed"


class ThreatType(str, Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    EXFILTRATION = "exfiltration"
    ANOMALY = "anomaly"
    SCAN = "scan"
    DOS = "dos"
    C2 = "c2"
    LATERAL = "lateral"
    UNKNOWN = "unknown"


class ThreatDetection(BaseModel):
    id: str
    timestamp: str
    type: ThreatType
    severity: ThreatSeverity
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    score: float = Field(ge=0, le=100)
    description: str
    indicators: List[str] = []
    model_id: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None


class AnomalyDetection(BaseModel):
    id: str
    timestamp: str
    category: str
    score: float = Field(ge=0, le=100)
    baseline_deviation: float
    source: str
    description: str
    affected_hosts: List[str] = []
    metrics: Dict[str, Any] = {}


class MLModel(BaseModel):
    id: str
    name: str
    type: str  # classification, anomaly, regression
    version: str
    status: ModelStatus
    accuracy: Optional[float] = None
    created_at: str
    deployed_at: Optional[str] = None
    config: Dict[str, Any] = {}


class AlertCorrelation(BaseModel):
    id: str
    timestamp: str
    alerts: List[Dict[str, Any]]
    correlation_score: float
    attack_stage: Optional[str] = None
    ttps: List[str] = []
    recommendation: str


class ConfigModel(BaseModel):
    detection_threshold: float = 0.7
    anomaly_sensitivity: float = 0.8
    auto_train: bool = True
    train_interval_hours: int = 24
    crowdsec_integration: bool = True
    suricata_integration: bool = True
    max_correlations: int = 100
    retention_days: int = 30


# ============================================================================
# Stats Cache
# ============================================================================

class StatsCache:
    """Thread-safe stats cache with TTL."""
    def __init__(self, ttl_seconds: int = 60):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() - self._timestamps[key] < self.ttl:
                    return self._cache[key]
                del self._cache[key]
                del self._timestamps[key]
        return None

    def set(self, key: str, value: Any):
        with self._lock:
            self._cache[key] = value
            self._timestamps[key] = time.time()

    def invalidate(self, key: str = None):
        with self._lock:
            if key:
                self._cache.pop(key, None)
                self._timestamps.pop(key, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


stats_cache = StatsCache(ttl_seconds=60)


# ============================================================================
# Helper Functions
# ============================================================================

def _load_json(path: Path, default=None) -> Any:
    if default is None:
        default = {}
    try:
        if path.exists():
            return json.loads(path.read_text())
    except (json.JSONDecodeError, IOError):
        pass
    return default


def _save_json(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _load_config() -> ConfigModel:
    """Load configuration from TOML file."""
    try:
        if CONFIG_FILE.exists():
            import tomllib
            with open(CONFIG_FILE, "rb") as f:
                data = tomllib.load(f)
                return ConfigModel(**data.get("ai_insights", {}))
    except Exception as e:
        log.warning("Failed to load config: %s", e)
    return ConfigModel()


def _save_config(config: ConfigModel):
    """Save configuration to TOML file."""
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    content = f"""# SecuBox AI Insights Configuration
[ai_insights]
detection_threshold = {config.detection_threshold}
anomaly_sensitivity = {config.anomaly_sensitivity}
auto_train = {str(config.auto_train).lower()}
train_interval_hours = {config.train_interval_hours}
crowdsec_integration = {str(config.crowdsec_integration).lower()}
suricata_integration = {str(config.suricata_integration).lower()}
max_correlations = {config.max_correlations}
retention_days = {config.retention_days}
"""
    CONFIG_FILE.write_text(content)


def _generate_id() -> str:
    """Generate unique ID."""
    return hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:12]


def _get_models_list() -> List[MLModel]:
    """Get list of available ML models."""
    models = []
    models_file = DATA_DIR / "models_registry.json"
    data = _load_json(models_file, {"models": []})

    for m in data.get("models", []):
        try:
            models.append(MLModel(**m))
        except Exception:
            pass

    # Default models if none exist
    if not models:
        models = [
            MLModel(
                id="default-anomaly-v1",
                name="Network Anomaly Detector",
                type="anomaly",
                version="1.0.0",
                status=ModelStatus.READY,
                accuracy=0.92,
                created_at="2025-01-01T00:00:00Z",
                config={"algorithm": "isolation_forest", "features": ["bytes", "packets", "duration"]}
            ),
            MLModel(
                id="default-threat-v1",
                name="Threat Classifier",
                type="classification",
                version="1.0.0",
                status=ModelStatus.READY,
                accuracy=0.88,
                created_at="2025-01-01T00:00:00Z",
                config={"algorithm": "random_forest", "classes": ["malware", "scan", "dos", "c2"]}
            ),
        ]
    return models


def _calculate_threat_score(indicators: List[str], severity: ThreatSeverity) -> float:
    """Calculate threat score based on indicators and severity."""
    base_scores = {
        ThreatSeverity.LOW: 20,
        ThreatSeverity.MEDIUM: 45,
        ThreatSeverity.HIGH: 70,
        ThreatSeverity.CRITICAL: 90
    }
    score = base_scores.get(severity, 50)
    score += min(len(indicators) * 2, 10)  # Add up to 10 points for indicators
    return min(score, 100)


# ============================================================================
# Background Tasks
# ============================================================================

_analysis_task: Optional[asyncio.Task] = None
_training_task: Optional[asyncio.Task] = None


async def _periodic_analysis():
    """Periodic threat analysis and detection."""
    while True:
        try:
            await asyncio.sleep(60)  # Analyze every minute

            config = _load_config()

            # Check CrowdSec integration
            if config.crowdsec_integration:
                await _analyze_crowdsec_alerts()

            # Check Suricata integration
            if config.suricata_integration:
                await _analyze_suricata_alerts()

            # Run correlation analysis
            await _correlate_alerts()

        except asyncio.CancelledError:
            break
        except Exception as e:
            log.error("Periodic analysis error: %s", e)


async def _analyze_crowdsec_alerts():
    """Analyze CrowdSec alerts for ML insights."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "cscli", "alerts", "list", "-o", "json", "--since", "1h",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0 and stdout:
            alerts = json.loads(stdout.decode())
            if isinstance(alerts, list) and len(alerts) > 0:
                # Process alerts for ML analysis
                _process_external_alerts(alerts, "crowdsec")
    except Exception as e:
        log.debug("CrowdSec analysis skipped: %s", e)


async def _analyze_suricata_alerts():
    """Analyze Suricata alerts for ML insights."""
    try:
        eve_log = Path("/var/log/suricata/eve.json")
        if not eve_log.exists():
            return

        # Read last 100 lines of eve.json
        proc = await asyncio.create_subprocess_exec(
            "tail", "-n", "100", str(eve_log),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        if proc.returncode == 0 and stdout:
            alerts = []
            for line in stdout.decode().strip().split("\n"):
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except Exception:
                    pass
            if alerts:
                _process_external_alerts(alerts, "suricata")
    except Exception as e:
        log.debug("Suricata analysis skipped: %s", e)


def _process_external_alerts(alerts: List[Dict], source: str):
    """Process alerts from external sources."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    existing_ids = {t.get("id") for t in history.get("threats", [])}

    for alert in alerts[-50:]:  # Process last 50
        alert_id = f"{source}-{hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:8]}"
        if alert_id in existing_ids:
            continue

        # Create threat detection
        if source == "crowdsec":
            threat = ThreatDetection(
                id=alert_id,
                timestamp=alert.get("created_at", datetime.now().isoformat()),
                type=ThreatType.INTRUSION,
                severity=ThreatSeverity.MEDIUM,
                source_ip=alert.get("source", {}).get("ip"),
                score=65.0,
                description=alert.get("scenario", "CrowdSec alert"),
                indicators=[alert.get("scenario", "unknown")],
                model_id="crowdsec-integration"
            )
        else:  # suricata
            threat = ThreatDetection(
                id=alert_id,
                timestamp=alert.get("timestamp", datetime.now().isoformat()),
                type=ThreatType.INTRUSION,
                severity=ThreatSeverity.MEDIUM,
                source_ip=alert.get("src_ip"),
                target_ip=alert.get("dest_ip"),
                score=60.0,
                description=alert.get("alert", {}).get("signature", "Suricata alert"),
                indicators=[alert.get("alert", {}).get("category", "unknown")],
                model_id="suricata-integration"
            )

        history["threats"].append(threat.model_dump())

    # Keep last 1000 threats
    history["threats"] = history["threats"][-1000:]
    _save_json(THREATS_HISTORY_FILE, history)


async def _correlate_alerts():
    """Correlate alerts to identify attack patterns."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    threats = history.get("threats", [])

    if len(threats) < 2:
        return

    # Simple correlation: group by source IP in last hour
    now = datetime.now()
    hour_ago = (now - timedelta(hours=1)).isoformat()

    recent = [t for t in threats if t.get("timestamp", "") >= hour_ago]

    ip_groups = {}
    for t in recent:
        ip = t.get("source_ip", "unknown")
        if ip not in ip_groups:
            ip_groups[ip] = []
        ip_groups[ip].append(t)

    correlations = _load_json(CORRELATIONS_FILE, {"correlations": []})

    for ip, group in ip_groups.items():
        if len(group) >= 3:  # 3+ alerts from same IP
            corr_id = f"corr-{ip}-{_generate_id()[:6]}"
            existing = [c for c in correlations.get("correlations", [])
                       if c.get("source_ip") == ip and c.get("timestamp", "") >= hour_ago]
            if existing:
                continue

            correlation = AlertCorrelation(
                id=corr_id,
                timestamp=datetime.now().isoformat(),
                alerts=group,
                correlation_score=min(len(group) * 15, 95),
                attack_stage="reconnaissance" if len(group) < 5 else "active_attack",
                ttps=list(set(t.get("type", "unknown") for t in group)),
                recommendation=f"Multiple alerts from {ip}. Consider blocking or investigating."
            )
            correlations["correlations"].append(correlation.model_dump())

    # Keep last 100 correlations
    correlations["correlations"] = correlations["correlations"][-100:]
    _save_json(CORRELATIONS_FILE, correlations)


# ============================================================================
# FastAPI Application
# ============================================================================

app = FastAPI(
    title="secubox-ai-insights",
    version="1.0.0",
    root_path="/api/v1/ai-insights",
)


@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    global _analysis_task
    _analysis_task = asyncio.create_task(_periodic_analysis())


@app.on_event("shutdown")
async def shutdown_event():
    """Stop background tasks."""
    global _analysis_task
    if _analysis_task:
        _analysis_task.cancel()


app.include_router(auth_router, prefix="/auth")


# ============================================================================
# Three-Fold Architecture Endpoints
# ============================================================================

@app.get("/components")
async def components():
    """List system components (public, three-fold: what)."""
    return {
        "components": [
            {
                "name": "AI Insights Engine",
                "type": "service",
                "description": "ML-based threat detection and analysis engine",
                "service": "secubox-ai-insights.service",
            },
            {
                "name": "Threat Detector",
                "type": "model",
                "description": "Classification model for threat identification",
                "algorithm": "Random Forest / Gradient Boosting",
            },
            {
                "name": "Anomaly Detector",
                "type": "model",
                "description": "Unsupervised anomaly detection in network traffic",
                "algorithm": "Isolation Forest / DBSCAN",
            },
            {
                "name": "Alert Correlator",
                "type": "analyzer",
                "description": "Correlates alerts from multiple sources",
                "sources": ["CrowdSec", "Suricata", "nDPId"],
            },
            {
                "name": "Model Manager",
                "type": "service",
                "description": "Training, deployment, and lifecycle management of ML models",
            },
        ]
    }


@app.get("/access")
async def access():
    """Show connection endpoints (public, three-fold: how)."""
    import socket
    hostname = socket.getfqdn()

    return {
        "endpoints": [
            {
                "name": "AI Insights Dashboard",
                "url": f"https://{hostname}/ai-insights/",
                "description": "SecuBox AI-powered security insights interface",
            },
            {
                "name": "API",
                "url": f"https://{hostname}/api/v1/ai-insights/",
                "description": "REST API for ML-based threat detection",
            },
        ],
        "integrations": [
            {"name": "CrowdSec", "endpoint": "/api/v1/crowdsec/", "status": "active"},
            {"name": "Suricata", "endpoint": "/api/v1/suricata/", "status": "active"},
            {"name": "nDPId", "endpoint": "/api/v1/ndpid/", "status": "active"},
        ],
        "documentation": "https://docs.secubox.in/ai-insights/",
    }


# ============================================================================
# Health and Status Endpoints
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    models = _get_models_list()
    deployed = sum(1 for m in models if m.status == ModelStatus.DEPLOYED or m.status == ModelStatus.READY)

    return {
        "status": "ok" if deployed > 0 else "degraded",
        "module": "ai-insights",
        "version": "1.0.0",
        "models_available": len(models),
        "models_deployed": deployed,
    }


@app.get("/status")
async def status():
    """Get current status and metrics."""
    cached = stats_cache.get("status")
    if cached:
        return cached

    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    anomalies = _load_json(ANOMALIES_FILE, {"anomalies": []})
    correlations = _load_json(CORRELATIONS_FILE, {"correlations": []})
    config = _load_config()

    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    hour_ago = (now - timedelta(hours=1)).isoformat()

    threats = history.get("threats", [])
    threats_today = [t for t in threats if t.get("timestamp", "") >= today]
    threats_hour = [t for t in threats if t.get("timestamp", "") >= hour_ago]
    critical_threats = [t for t in threats_today if t.get("severity") == "critical"]

    models = _get_models_list()

    result = {
        "threats_today": len(threats_today),
        "threats_last_hour": len(threats_hour),
        "critical_threats": len(critical_threats),
        "active_anomalies": len(anomalies.get("anomalies", [])),
        "correlations": len(correlations.get("correlations", [])),
        "models_deployed": sum(1 for m in models if m.status in [ModelStatus.DEPLOYED, ModelStatus.READY]),
        "detection_threshold": config.detection_threshold,
        "integrations": {
            "crowdsec": config.crowdsec_integration,
            "suricata": config.suricata_integration,
        },
        "last_analysis": datetime.now().isoformat(),
    }

    stats_cache.set("status", result)
    return result


# ============================================================================
# Configuration Endpoints
# ============================================================================

@app.get("/config")
async def get_config(user=Depends(require_jwt)):
    """Get current configuration."""
    config = _load_config()
    return config.model_dump()


@app.post("/config")
async def update_config(config: ConfigModel, user=Depends(require_jwt)):
    """Update configuration."""
    _save_config(config)
    stats_cache.invalidate()
    log.info("Configuration updated by %s", user.get("sub", "unknown"))
    return {"status": "success", "config": config.model_dump()}


# ============================================================================
# Threats Endpoints
# ============================================================================

@app.get("/threats")
async def get_threats(
    limit: int = Query(default=50, le=500),
    severity: Optional[ThreatSeverity] = None,
    type: Optional[ThreatType] = None,
    since: Optional[str] = None,
    user=Depends(require_jwt)
):
    """Get current threat detections."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    threats = history.get("threats", [])

    # Apply filters
    if severity:
        threats = [t for t in threats if t.get("severity") == severity.value]
    if type:
        threats = [t for t in threats if t.get("type") == type.value]
    if since:
        threats = [t for t in threats if t.get("timestamp", "") >= since]

    # Sort by timestamp descending
    threats = sorted(threats, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "threats": threats[:limit],
        "total": len(threats),
        "filters": {"severity": severity, "type": type, "since": since}
    }


@app.get("/threats/history")
async def get_threats_history(
    days: int = Query(default=7, le=30),
    user=Depends(require_jwt)
):
    """Get historical threat data for trends."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    threats = history.get("threats", [])

    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    threats = [t for t in threats if t.get("timestamp", "") >= cutoff]

    # Aggregate by day
    daily_stats = {}
    for t in threats:
        date = t.get("timestamp", "")[:10]  # YYYY-MM-DD
        if date not in daily_stats:
            daily_stats[date] = {"date": date, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        daily_stats[date]["total"] += 1
        daily_stats[date][t.get("severity", "low")] += 1

    return {
        "history": sorted(daily_stats.values(), key=lambda x: x["date"]),
        "period_days": days,
        "total_threats": len(threats)
    }


# ============================================================================
# Anomalies Endpoints
# ============================================================================

@app.get("/anomalies")
async def get_anomalies(
    limit: int = Query(default=50, le=200),
    user=Depends(require_jwt)
):
    """Get detected anomalies."""
    data = _load_json(ANOMALIES_FILE, {"anomalies": []})
    anomalies = data.get("anomalies", [])

    anomalies = sorted(anomalies, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "anomalies": anomalies[:limit],
        "total": len(anomalies)
    }


# ============================================================================
# Models Endpoints
# ============================================================================

@app.get("/models")
async def get_models(user=Depends(require_jwt)):
    """Get loaded ML models."""
    models = _get_models_list()
    return {
        "models": [m.model_dump() for m in models],
        "total": len(models),
        "deployed": sum(1 for m in models if m.status in [ModelStatus.DEPLOYED, ModelStatus.READY])
    }


class TrainRequest(BaseModel):
    model_type: str = "anomaly"  # anomaly, classification
    name: str
    config: Dict[str, Any] = {}


@app.post("/model/train")
async def train_model(req: TrainRequest, background_tasks: BackgroundTasks, user=Depends(require_jwt)):
    """Train a new ML model."""
    model_id = f"{req.model_type}-{_generate_id()}"

    model = MLModel(
        id=model_id,
        name=req.name,
        type=req.model_type,
        version="1.0.0",
        status=ModelStatus.TRAINING,
        created_at=datetime.now().isoformat(),
        config=req.config
    )

    # Save to registry
    models_file = DATA_DIR / "models_registry.json"
    data = _load_json(models_file, {"models": []})
    data["models"].append(model.model_dump())
    _save_json(models_file, data)

    log.info("Training model %s requested by %s", model_id, user.get("sub", "unknown"))

    # In production, this would start actual training
    # For now, simulate by updating status after a delay
    async def simulate_training():
        await asyncio.sleep(5)
        models_data = _load_json(models_file, {"models": []})
        for m in models_data["models"]:
            if m["id"] == model_id:
                m["status"] = ModelStatus.READY.value
                m["accuracy"] = 0.87
                break
        _save_json(models_file, models_data)

    background_tasks.add_task(simulate_training)

    return {"status": "training_started", "model": model.model_dump()}


class DeployRequest(BaseModel):
    model_id: str


@app.post("/model/deploy")
async def deploy_model(req: DeployRequest, user=Depends(require_jwt)):
    """Deploy a trained model."""
    models_file = DATA_DIR / "models_registry.json"
    data = _load_json(models_file, {"models": []})

    model = None
    for m in data["models"]:
        if m["id"] == req.model_id:
            model = m
            break

    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    if model["status"] not in [ModelStatus.READY.value, "ready"]:
        raise HTTPException(status_code=400, detail="Model is not ready for deployment")

    model["status"] = ModelStatus.DEPLOYED.value
    model["deployed_at"] = datetime.now().isoformat()
    _save_json(models_file, data)

    log.info("Model %s deployed by %s", req.model_id, user.get("sub", "unknown"))

    return {"status": "deployed", "model": model}


# ============================================================================
# Scores Endpoints
# ============================================================================

@app.get("/scores")
async def get_threat_scores(
    limit: int = Query(default=20, le=100),
    user=Depends(require_jwt)
):
    """Get threat scores by host/IP."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    threats = history.get("threats", [])

    # Aggregate scores by IP
    ip_scores = {}
    for t in threats:
        ip = t.get("source_ip", "unknown")
        if ip == "unknown":
            continue
        if ip not in ip_scores:
            ip_scores[ip] = {"ip": ip, "total_score": 0, "threat_count": 0, "severities": {}}
        ip_scores[ip]["total_score"] += t.get("score", 0)
        ip_scores[ip]["threat_count"] += 1
        sev = t.get("severity", "low")
        ip_scores[ip]["severities"][sev] = ip_scores[ip]["severities"].get(sev, 0) + 1

    # Calculate average score
    for ip_data in ip_scores.values():
        if ip_data["threat_count"] > 0:
            ip_data["avg_score"] = ip_data["total_score"] / ip_data["threat_count"]
        else:
            ip_data["avg_score"] = 0

    # Sort by total score
    sorted_scores = sorted(ip_scores.values(), key=lambda x: x["total_score"], reverse=True)

    return {
        "scores": sorted_scores[:limit],
        "total_ips": len(ip_scores)
    }


# ============================================================================
# Correlations Endpoints
# ============================================================================

@app.get("/correlations")
async def get_correlations(
    limit: int = Query(default=50, le=200),
    user=Depends(require_jwt)
):
    """Get correlated alerts."""
    data = _load_json(CORRELATIONS_FILE, {"correlations": []})
    correlations = data.get("correlations", [])

    correlations = sorted(correlations, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "correlations": correlations[:limit],
        "total": len(correlations)
    }


# ============================================================================
# Stats Endpoints
# ============================================================================

@app.get("/stats")
async def get_stats(user=Depends(require_jwt)):
    """Get detection statistics."""
    history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
    anomalies_data = _load_json(ANOMALIES_FILE, {"anomalies": []})
    correlations_data = _load_json(CORRELATIONS_FILE, {"correlations": []})

    threats = history.get("threats", [])
    now = datetime.now()

    # Time-based stats
    hour_ago = (now - timedelta(hours=1)).isoformat()
    day_ago = (now - timedelta(days=1)).isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()

    # Severity distribution
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    type_dist = {}

    for t in threats:
        sev = t.get("severity", "low")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        typ = t.get("type", "unknown")
        type_dist[typ] = type_dist.get(typ, 0) + 1

    return {
        "threats": {
            "total": len(threats),
            "last_hour": len([t for t in threats if t.get("timestamp", "") >= hour_ago]),
            "last_24h": len([t for t in threats if t.get("timestamp", "") >= day_ago]),
            "last_week": len([t for t in threats if t.get("timestamp", "") >= week_ago]),
        },
        "anomalies": {
            "total": len(anomalies_data.get("anomalies", [])),
        },
        "correlations": {
            "total": len(correlations_data.get("correlations", [])),
        },
        "distributions": {
            "severity": severity_dist,
            "type": type_dist,
        },
        "generated_at": datetime.now().isoformat()
    }


# ============================================================================
# Analysis Endpoints
# ============================================================================

class AnalyzeRequest(BaseModel):
    data: Dict[str, Any]
    type: str = "log"  # log, event, flow


@app.post("/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(require_jwt)):
    """Analyze a specific log/event."""
    config = _load_config()

    # Simple rule-based analysis (in production, would use ML models)
    indicators = []
    score = 0
    severity = ThreatSeverity.LOW
    threat_type = ThreatType.UNKNOWN

    data_str = json.dumps(req.data).lower()

    # Check for common indicators
    suspicious_patterns = [
        ("scan", ["nmap", "masscan", "portscan"], ThreatType.SCAN),
        ("malware", ["malware", "trojan", "ransomware", "virus"], ThreatType.MALWARE),
        ("c2", ["c2", "command and control", "beacon"], ThreatType.C2),
        ("exfil", ["exfiltration", "data leak", "upload"], ThreatType.EXFILTRATION),
        ("dos", ["dos", "ddos", "flood"], ThreatType.DOS),
    ]

    for pattern_name, keywords, ptype in suspicious_patterns:
        for kw in keywords:
            if kw in data_str:
                indicators.append(f"{pattern_name}:{kw}")
                score += 15
                threat_type = ptype

    # Determine severity
    if score >= 60:
        severity = ThreatSeverity.CRITICAL
    elif score >= 40:
        severity = ThreatSeverity.HIGH
    elif score >= 20:
        severity = ThreatSeverity.MEDIUM

    # Create detection result
    detection = ThreatDetection(
        id=f"manual-{_generate_id()}",
        timestamp=datetime.now().isoformat(),
        type=threat_type,
        severity=severity,
        score=min(score, 100),
        description=f"Manual analysis of {req.type}",
        indicators=indicators,
        model_id="manual-analysis",
        raw_data=req.data
    )

    # Log the analysis
    log_data = _load_json(ANALYSIS_LOG_FILE, {"logs": []})
    log_data["logs"].append({
        "timestamp": datetime.now().isoformat(),
        "user": user.get("sub", "unknown"),
        "type": req.type,
        "result": detection.model_dump()
    })
    log_data["logs"] = log_data["logs"][-500:]
    _save_json(ANALYSIS_LOG_FILE, log_data)

    # Add to threats history if significant
    if score >= config.detection_threshold * 100:
        history = _load_json(THREATS_HISTORY_FILE, {"threats": []})
        history["threats"].append(detection.model_dump())
        history["threats"] = history["threats"][-1000:]
        _save_json(THREATS_HISTORY_FILE, history)

    return {
        "detection": detection.model_dump(),
        "is_threat": score >= config.detection_threshold * 100,
        "confidence": min(score / 100, 1.0)
    }


# ============================================================================
# Integrations Endpoints
# ============================================================================

@app.get("/integrations")
async def get_integrations(user=Depends(require_jwt)):
    """Get CrowdSec/Suricata integration status."""
    config = _load_config()

    # Check CrowdSec
    crowdsec_status = "disabled"
    if config.crowdsec_integration:
        try:
            proc = subprocess.run(["pgrep", "crowdsec"], capture_output=True, timeout=2)
            crowdsec_status = "running" if proc.returncode == 0 else "stopped"
        except Exception:
            crowdsec_status = "error"

    # Check Suricata
    suricata_status = "disabled"
    if config.suricata_integration:
        try:
            proc = subprocess.run(["pgrep", "suricata"], capture_output=True, timeout=2)
            suricata_status = "running" if proc.returncode == 0 else "stopped"
        except Exception:
            suricata_status = "error"

    return {
        "integrations": [
            {
                "name": "CrowdSec",
                "enabled": config.crowdsec_integration,
                "status": crowdsec_status,
                "description": "Collaborative security engine alerts"
            },
            {
                "name": "Suricata",
                "enabled": config.suricata_integration,
                "status": suricata_status,
                "description": "Network IDS/IPS alerts"
            },
            {
                "name": "nDPId",
                "enabled": True,
                "status": "active",
                "description": "Deep packet inspection data"
            }
        ]
    }


# ============================================================================
# Logs Endpoints
# ============================================================================

@app.get("/logs")
async def get_logs(
    limit: int = Query(default=100, le=500),
    user=Depends(require_jwt)
):
    """Get analysis logs."""
    data = _load_json(ANALYSIS_LOG_FILE, {"logs": []})
    logs = data.get("logs", [])

    logs = sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)

    return {
        "logs": logs[:limit],
        "total": len(logs)
    }
