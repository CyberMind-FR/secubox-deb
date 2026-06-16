# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
SecuBox Security Posture - FastAPI Endpoints

Provides REST API for:
- DEFCON level security health
- CSPN compliance status
- TPN Media compliance status
- Performance monitoring
- Combined security dashboard

API Endpoints:
    GET  /api/v1/security-posture/defcon           - DEFCON level and score
    GET  /api/v1/security-posture/cspn            - CSPN compliance report
    GET  /api/v1/security-posture/tpn             - TPN Media compliance report
    GET  /api/v1/security-posture/performance     - Performance metrics
    GET  /api/v1/security-posture/overview        - Combined overview
    GET  /api/v1/security-posture/health          - Service health
    POST /api/v1/security-posture/checks/run     - Run all compliance checks
    GET  /api/v1/security-posture/bottlenecks     - Performance bottlenecks
    GET  /api/v1/security-posture/recommendations - Optimization recommendations

Security:
    - All endpoints accessible via unix socket only
    - No authentication required (security via socket permissions)
    - Intended to be mounted under /api/v1/security-posture/
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Try to import secubox_core, but make it optional for standalone testing
try:
    from secubox_core.config import get_config
    SECUBOX_CORE_AVAILABLE = True
except ImportError:
    SECUBOX_CORE_AVAILABLE = False
    get_config = lambda: {}

from .defcon import defcon_engine, DefconLevel
from .cspn_compliance import cspn_checker
from .tpn_compliance import tpn_checker
from .performance import performance_monitor

logger = logging.getLogger("secubox.security-posture")

# Create FastAPI app
app = FastAPI(
    title="SecuBox Security Posture",
    description=(
        "DEFCON-level security health monitoring with CSPN and TPN Media compliance. "
        "Provides real-time security posture assessment, performance monitoring, "
        "and compliance reporting."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Add CORS middleware (for development/testing via HTTP)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# ============================================================================
# DEFCON Endpoints
# ============================================================================

@app.get("/defcon")
async def get_defcon():
    """
    Get current DEFCON level and security score.
    
    Returns:
        - DEFCON level (1-5)
        - Security score (0-100)
        - Color and emoji indicators
        - Per-category scores
        - Compliance status (CSPN/TPN)
        - All indicator details
    """
    try:
        # Collect fresh metrics
        metrics = await defcon_engine.collect_all_metrics(use_cache=False)
        score = defcon_engine.calculate_score(metrics)
        defcon_info = await defcon_engine.get_defcon_info(score, metrics)
        
        return JSONResponse(
            content=defcon_info,
            headers={"Cache-Control": "public, max-age=30"}
        )
    except Exception as e:
        logger.error(f"DEFCON endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )


@app.get("/defcon/summary")
async def get_defcon_summary():
    """
    Get DEFCON summary (lightweight, no metric collection).
    
    Returns:
        - DEFCON level
        - Security score
        - Color and emoji
    """
    try:
        return await defcon_engine.get_summary()
    except Exception as e:
        logger.error(f"DEFCON summary error: {e}")
        return {"error": str(e), "defcon": "defcon_5", "score": 0.0}


@app.get("/defcon/indicators")
async def get_defcon_indicators():
    """
    Get all DEFCON indicator details.
    
    Returns:
        - List of all indicators with current values
        - Status, weights, thresholds
        - CSPN/TPN requirement mappings
    """
    try:
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "indicators": defcon_engine.get_indicator_details()
        }
    except Exception as e:
        logger.error(f"Indicators endpoint error: {e}")
        return {"error": str(e)}


@app.get("/defcon/category/{category}")
async def get_defcon_category(category: str):
    """
    Get DEFCON indicators for a specific category.
    
    Categories: network, threat, access, data, resilience
    """
    try:
        indicators = defcon_engine.get_indicator_details()
        category_indicators = {
            k: v for k, v in indicators.items()
            if v.get("category") == category
        }
        
        if not category_indicators:
            raise HTTPException(
                status_code=404,
                detail=f"Category '{category}' not found"
            )
        
        return {
            "category": category,
            "indicators": category_indicators
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Category endpoint error: {e}")
        return {"error": str(e)}


# ============================================================================
# CSPN Compliance Endpoints
# ============================================================================

@app.get("/cspn")
async def get_cspn_compliance():
    """
    Get full CSPN compliance report.
    
    Returns:
        - Compliance summary
        - All requirements with status
        - Pass/fail counts
        - Certificate readiness
    """
    try:
        report = await cspn_checker.run_all_checks()
        return JSONResponse(
            content=report,
            headers={"Cache-Control": "public, max-age=60"}
        )
    except Exception as e:
        logger.error(f"CSPN compliance error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )


@app.get("/cspn/summary")
async def get_cspn_summary():
    """
    Get CSPN compliance summary.
    
    Returns:
        - Compliance score
        - Pass/fail percentages
        - Certificate readiness
    """
    try:
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "summary": cspn_checker.get_summary()
        }
    except Exception as e:
        logger.error(f"CSPN summary error: {e}")
        return {"error": str(e)}


@app.get("/cspn/requirements")
async def get_cspn_requirements():
    """
    Get all CSPN requirements.
    """
    try:
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "requirements": cspn_checker.get_all_requirements()
        }
    except Exception as e:
        logger.error(f"CSPN requirements error: {e}")
        return {"error": str(e)}


@app.get("/cspn/requirements/{req_id}")
async def get_cspn_requirement(req_id: str):
    """
    Get a specific CSPN requirement.
    """
    try:
        requirement = cspn_checker.get_requirement(req_id)
        if requirement is None:
            raise HTTPException(status_code=404, detail=f"Requirement {req_id} not found")
        return requirement
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"CSPN requirement error: {e}")
        return {"error": str(e)}


@app.get("/cspn/certificate/readiness")
async def get_cspn_certificate_readiness():
    """
    Get CSPN certificate readiness status.
    
    Returns:
        - Ready status
        - Compliance score
        - Blocking issues
        - Recommendations
    """
    try:
        return cspn_checker.get_certificate_readiness()
    except Exception as e:
        logger.error(f"CSPN readiness error: {e}")
        return {"error": str(e), "ready": False}


# ============================================================================
# TPN Media Compliance Endpoints
# ============================================================================

@app.get("/tpn")
async def get_tpn_compliance():
    """
    Get full TPN Media compliance report.
    
    Returns:
        - TPN compliance summary
        - CSPN compliance (related)
        - All TPN requirements with status
    """
    try:
        report = await tpn_checker.run_all_checks()
        return JSONResponse(
            content=report,
            headers={"Cache-Control": "public, max-age=60"}
        )
    except Exception as e:
        logger.error(f"TPN compliance error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )


@app.get("/tpn/summary")
async def get_tpn_summary():
    """
    Get TPN Media compliance summary.
    """
    try:
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "summary": tpn_checker.get_summary()
        }
    except Exception as e:
        logger.error(f"TPN summary error: {e}")
        return {"error": str(e)}


@app.get("/tpn/requirements")
async def get_tpn_requirements():
    """
    Get all TPN Media requirements.
    """
    try:
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "requirements": tpn_checker.get_all_requirements()
        }
    except Exception as e:
        logger.error(f"TPN requirements error: {e}")
        return {"error": str(e)}


@app.get("/tpn/requirements/{req_id}")
async def get_tpn_requirement(req_id: str):
    """
    Get a specific TPN requirement.
    """
    try:
        requirement = tpn_checker.get_requirement(req_id)
        if requirement is None:
            raise HTTPException(status_code=404, detail=f"Requirement {req_id} not found")
        return requirement
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"TPN requirement error: {e}")
        return {"error": str(e)}


@app.get("/tpn/certificate/readiness")
async def get_tpn_certificate_readiness():
    """
    Get TPN Media certificate readiness status.
    
    Returns:
        - CSPN readiness
        - TPN readiness
        - Overall readiness
        - Blocking issues
        - Recommendations
    """
    try:
        return tpn_checker.get_media_certificate_readiness()
    except Exception as e:
        logger.error(f"TPN readiness error: {e}")
        return {"error": str(e), "ready": False}


# ============================================================================
# Performance Endpoints
# ============================================================================

@app.get("/performance")
async def get_performance():
    """
    Get all performance metrics.
    
    Returns:
        - All performance metrics with values
        - Status, thresholds
        - Category scores
    """
    try:
        metrics = performance_monitor.collect_all_metrics()
        
        return JSONResponse(
            content={
                "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
                "metrics": {
                    name: {
                        "name": m.name,
                        "category": m.category.value,
                        "value": m.value,
                        "unit": m.unit,
                        "status": m.get_status().value,
                        "status_color": m.get_status_color(),
                        "threshold_ok": m.threshold_ok,
                        "threshold_warning": m.threshold_warning,
                        "threshold_critical": m.threshold_critical,
                        "description": m.description,
                        "recommendation": m.recommendation,
                    }
                    for name, m in performance_monitor.metrics.items()
                },
                "summary": performance_monitor.get_summary()
            },
            headers={"Cache-Control": "public, max-age=15"}
        )
    except Exception as e:
        logger.error(f"Performance endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )


@app.get("/performance/summary")
async def get_performance_summary():
    """
    Get performance summary.
    """
    try:
        return performance_monitor.get_summary()
    except Exception as e:
        logger.error(f"Performance summary error: {e}")
        return {"error": str(e)}


@app.get("/performance/bottlenecks")
async def get_performance_bottlenecks():
    """
    Get detected performance bottlenecks.
    
    Returns:
        - List of bottlenecks
        - Severity, description, impact
        - Recommendations for each
    """
    try:
        bottlenecks = performance_monitor.detect_bottlenecks()
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "bottlenecks": [
                {
                    "name": b.name,
                    "resource_type": b.resource_type.value,
                    "severity": b.severity,
                    "description": b.description,
                    "impact": b.impact,
                    "metric_value": b.metric_value,
                    "threshold": b.threshold,
                    "timestamp": b.timestamp,
                    "recommendations": b.recommendations,
                }
                for b in bottlenecks
            ],
            "count": len(bottlenecks)
        }
    except Exception as e:
        logger.error(f"Bottlenecks error: {e}")
        return {"error": str(e), "bottlenecks": []}


@app.get("/performance/recommendations")
async def get_performance_recommendations():
    """
    Get performance optimization recommendations.
    
    Returns:
        - List of recommendations
        - Severity levels
        - Specific actions
    """
    try:
        return performance_monitor.get_recommendations()
    except Exception as e:
        logger.error(f"Recommendations error: {e}")
        return {"error": str(e), "recommendations": []}


@app.get("/performance/history")
async def get_performance_history(hours: int = 24):
    """
    Get performance history.
    
    Args:
        hours: Time window for history (default: 24)
    """
    try:
        return performance_monitor.get_performance_history(hours)
    except Exception as e:
        logger.error(f"History error: {e}")
        return {"error": str(e), "history": []}


# ============================================================================
# Combined Overview Endpoints
# ============================================================================

@app.get("/overview")
async def get_security_overview():
    """
    Get combined security posture overview.
    
    Returns:
        - DEFCON level and score
        - CSPN compliance
        - TPN Media compliance
        - Performance summary
        - Combined recommendations
    """
    try:
        # Collect all data
        defcon_info = await defcon_engine.get_defcon_info()
        cspn_summary = cspn_checker.get_summary()
        tpn_summary = tpn_checker.get_summary()
        perf_summary = performance_monitor.get_summary()
        
        # Calculate combined score (weighted average)
        combined_score = round(
            (defcon_info["score"] * 0.4) +
            (cspn_summary.get("compliance_score", 0) * 0.3) +
            (tpn_summary.get("compliance_score", 0) * 0.2) +
            (perf_summary["score"] * 0.1),
            1
        )
        
        # Determine overall status
        if combined_score >= 85:
            overall_status = "excellent"
            overall_color = "#22c55e"
            overall_emoji = "🟢"
        elif combined_score >= 70:
            overall_status = "good"
            overall_color = "#86efac"
            overall_emoji = "🟢"
        elif combined_score >= 50:
            overall_status = "fair"
            overall_color = "#eab308"
            overall_emoji = "🟡"
        elif combined_score >= 30:
            overall_status = "poor"
            overall_color = "#f97316"
            overall_emoji = "🟠"
        else:
            overall_status = "critical"
            overall_color = "#ef4444"
            overall_emoji = "🔴"
        
        return {
            "timestamp": asyncio.get_event_loop().now().isoformat() + "Z",
            "combined_score": combined_score,
            "overall_status": overall_status,
            "overall_color": overall_color,
            "overall_emoji": overall_emoji,
            "defcon": {
                "level": defcon_info["level"],
                "level_name": defcon_info["level_name"],
                "score": defcon_info["score"],
                "color": defcon_info["color"],
                "emoji": defcon_info["emoji"],
                "blink": defcon_info.get("blink", False),
                "description": defcon_info["description"],
            },
            "cspn": {
                "compliant": cspn_summary.get("is_compliant", False),
                "score": cspn_summary.get("compliance_score", 0),
            },
            "tpn_media": {
                "compliant": tpn_summary.get("is_compliant", False),
                "score": tpn_summary.get("compliance_score", 0),
            },
            "performance": {
                "score": perf_summary["score"],
                "status": perf_summary["status"],
                "bottlenecks": perf_summary["bottlenecks"],
            },
            "recommendations": self._get_combined_recommendations(
                defcon_info, cspn_summary, tpn_summary, perf_summary
            )
        }
    except Exception as e:
        logger.error(f"Overview error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )
    
    def _get_combined_recommendations(self, defcon_info: Dict, cspn_summary: Dict,
                                       tpn_summary: Dict, perf_summary: Dict) -> List[Dict]:
        """Get combined recommendations from all sources."""
        recommendations = []
        
        # DEFCON recommendations
        if "recommendations" in defcon_info:
            for rec in defcon_info["recommendations"][:3]:  # Top 3
                recommendations.append({
                    "source": "defcon",
                    "severity": "high" if "🔴" in rec or "🚨" in rec else "medium",
                    "text": rec
                })
        
        # CSPN recommendations
        if not cspn_summary.get("is_compliant", True):
            recommendations.append({
                "source": "cspn",
                "severity": "high",
                "text": f"CSPN compliance score {cspn_summary.get('compliance_score', 0)}% - Address failing checks"
            })
        
        # TPN recommendations
        if not tpn_summary.get("is_compliant", True):
            recommendations.append({
                "source": "tpn",
                "severity": "high",
                "text": f"TPN Media compliance score {tpn_summary.get('compliance_score', 0)}% - Address media-specific requirements"
            })
        
        # Performance recommendations
        if perf_summary.get("bottlenecks", 0) > 0:
            recommendations.append({
                "source": "performance",
                "severity": "medium",
                "text": f"{perf_summary.get('bottlenecks', 0)} performance bottlenecks detected - Review and optimize"
            })
        
        return recommendations


@app.get("/health")
async def health_check():
    """
    Health check endpoint for service monitoring.
    
    Returns:
        - Service status
        - Version
        - Dependencies health
    """
    try:
        return {
            "status": "ok",
            "service": "secubox-security-posture",
            "version": "1.0.0",
            "defcon_engine": "ok",
            "cspn_checker": "ok",
            "tpn_checker": "ok",
            "performance_monitor": "ok",
        }
    except Exception as e:
        return {
            "status": "error",
            "service": "secubox-security-posture",
            "error": str(e)
        }


@app.post("/checks/run")
async def run_all_checks(background_tasks: BackgroundTasks):
    """
    Run all compliance checks (CSPN + TPN).
    
    This triggers fresh collection and checking of all requirements.
    """
    try:
        # Run checks in background
        background_tasks.add_task(cspn_checker.run_all_checks)
        background_tasks.add_task(tpn_checker.run_all_checks)
        background_tasks.add_task(defcon_engine.collect_all_metrics)
        background_tasks.add_task(performance_monitor.collect_all_metrics)
        
        return {
            "status": "started",
            "message": "All compliance and performance checks started in background",
            "checks": [
                "cspn_compliance",
                "tpn_media_compliance",
                "defcon_metrics",
                "performance_metrics"
            ]
        }
    except Exception as e:
        logger.error(f"Run checks error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "status": "error"}
        )


# ============================================================================
# Startup
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    logger.info("SecuBox Security Posture starting...")
    
    try:
        # Collect initial metrics
        await defcon_engine.collect_all_metrics(use_cache=False)
        logger.info("DEFCON engine initialized")
        
        # Run initial compliance checks
        await cspn_checker.run_all_checks()
        logger.info("CSPN checker initialized")
        
        await tpn_checker.run_all_checks()
        logger.info("TPN checker initialized")
        
        # Collect initial performance metrics
        performance_monitor.collect_all_metrics()
        logger.info("Performance monitor initialized")
        
        logger.info("SecuBox Security Posture started successfully")
        
    except Exception as e:
        logger.error(f"Startup error: {e}")
        # Don't fail startup on errors


# ============================================================================
# Background Tasks
# ============================================================================

async def background_refresh():
    """Background task to refresh metrics periodically."""
    while True:
        try:
            await asyncio.sleep(60)  # Refresh every 60 seconds
            await defcon_engine.collect_all_metrics(use_cache=False)
            performance_monitor.collect_all_metrics()
            logger.debug("Metrics refreshed")
        except Exception as e:
            logger.error(f"Background refresh error: {e}")
        except asyncio.CancelledError:
            break


# Start background task on startup
@app.on_event("startup")
async def start_background_tasks():
    asyncio.create_task(background_refresh())


# ============================================================================
# For standalone testing
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting SecuBox Security Posture server...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8082,
        log_level="info",
        access_log=True
    )
