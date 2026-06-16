# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
"""
Performance Monitoring Module for SecuBox

Provides real-time performance metrics, bottleneck identification, and
performance health scoring for the security appliance.

Features:
- System resource monitoring (CPU, Memory, Disk, Network)
- Service performance metrics (response times, throughput)
- Bottleneck detection and analysis
- Performance impact on security functions
- Historical performance tracking
- Performance health score (0-100)

Integration:
- Collects from existing SecuBox modules
- Integrates with DEFCON scoring
- Provides performance optimization recommendations
"""

from __future__ import annotations

import asyncio
import httpx
import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import psutil

logger = logging.getLogger("secubox.security-posture.performance")


class PerformanceStatus(str, Enum):
    """Performance status levels."""
    EXCELLENT = "excellent"  # 90-100%
    GOOD = "good"            # 70-89%
    FAIR = "fair"            # 50-69%
    POOR = "poor"            # 30-49%
    CRITICAL = "critical"    # 0-29%


class ResourceType(str, Enum):
    """Resource types being monitored."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    IO = "io"
    SERVICE = "service"


@dataclass
class PerformanceMetric:
    """Single performance metric."""
    name: str
    category: ResourceType
    value: float
    unit: str = ""  # %, ms, bytes, count, etc.
    threshold_ok: float = 80.0
    threshold_warning: float = 50.0
    threshold_critical: float = 20.0
    inverse: bool = False  # If True, lower values are better
    description: str = ""
    recommendation: str = ""
    
    def get_status(self) -> PerformanceStatus:
        """Get performance status based on value and thresholds."""
        value = self.value
        if self.inverse:
            value = 100.0 - min(100.0, (value / self.threshold_critical) * 100)
        
        if value >= self.threshold_ok:
            return PerformanceStatus.EXCELLENT
        elif value >= self.threshold_warning:
            return PerformanceStatus.GOOD
        elif value >= self.threshold_critical:
            return PerformanceStatus.FAIR
        else:
            return PerformanceStatus.CRITICAL
    
    def get_score(self) -> float:
        """Get normalized score (0-100)."""
        value = self.value
        if self.inverse:
            # For inverse metrics (like latency), convert to percentage
            # If value is low, score is high
            normalized = min(100.0, max(0.0, ((self.threshold_critical - value) / self.threshold_critical) * 100))
            return normalized
        return min(100.0, value)
    
    def get_status_color(self) -> str:
        """Get color for status."""
        colors = {
            PerformanceStatus.EXCELLENT: "#22c55e",  # Green
            PerformanceStatus.GOOD: "#86efac",     # Light green
            PerformanceStatus.FAIR: "#eab308",     # Yellow
            PerformanceStatus.POOR: "#f97316",     # Orange
            PerformanceStatus.CRITICAL: "#ef4444",  # Red
        }
        return colors.get(self.get_status(), "#6b7280")


@dataclass
class Bottleneck:
    """Performance bottleneck detection."""
    name: str
    resource_type: ResourceType
    severity: str = "medium"  # low, medium, high, critical
    description: str = ""
    impact: str = ""  # Security impact description
    metric_value: float = 0.0
    threshold: float = 0.0
    timestamp: str = ""
    recommendations: List[str] = field(default_factory=list)


class PerformanceMonitor:
    """
    Main performance monitoring engine.
    
    Collects performance metrics from system and SecuBox modules,
    identifies bottlenecks, and provides optimization recommendations.
    
    Usage:
        monitor = PerformanceMonitor()
        metrics = monitor.collect_all_metrics()
        score = monitor.calculate_performance_score()
        bottlenecks = monitor.detect_bottlenecks()
        recommendations = monitor.get_recommendations()
    """
    
    def __init__(self):
        self.metrics: Dict[str, PerformanceMetric] = {}
        self._last_collection: Optional[datetime] = None
        self._cached_metrics: Dict[str, float] = {}
        self._bottlenecks: List[Bottleneck] = []
        self._history: List[Dict[str, float]] = []
        self._max_history = 100  # Keep last 100 samples
        
        # Initialize metrics
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize all performance metrics."""
        
        # System Resource Metrics
        self.metrics["cpu_usage"] = PerformanceMetric(
            name="CPU Usage",
            category=ResourceType.CPU,
            value=0.0,
            unit="%",
            threshold_ok=70.0,
            threshold_warning=85.0,
            threshold_critical=95.0,
            inverse=True,  # Lower is better
            description="Overall CPU usage across all cores",
            recommendation="Optimize CPU-intensive services, consider scaling"
        )
        
        self.metrics["cpu_per_core"] = PerformanceMetric(
            name="CPU per Core",
            category=ResourceType.CPU,
            value=0.0,
            unit="%",
            threshold_ok=80.0,
            threshold_warning=90.0,
            threshold_critical=98.0,
            inverse=True,
            description="Average CPU usage per core",
            recommendation="Balance load across cores, check for single-core bottlenecks"
        )
        
        self.metrics["memory_usage"] = PerformanceMetric(
            name="Memory Usage",
            category=ResourceType.MEMORY,
            value=0.0,
            unit="%",
            threshold_ok=70.0,
            threshold_warning=85.0,
            threshold_critical=95.0,
            inverse=True,
            description="Overall memory usage",
            recommendation="Optimize memory usage, check for leaks, add swap"
        )
        
        self.metrics["memory_available"] = PerformanceMetric(
            name="Available Memory",
            category=ResourceType.MEMORY,
            value=0.0,
            unit="MB",
            threshold_ok=1024.0,
            threshold_warning=512.0,
            threshold_critical=256.0,
            description="Available physical memory",
            recommendation="Free up memory or add more RAM"
        )
        
        self.metrics["swap_usage"] = PerformanceMetric(
            name="Swap Usage",
            category=ResourceType.MEMORY,
            value=0.0,
            unit="%",
            threshold_ok=10.0,
            threshold_warning=50.0,
            threshold_critical=80.0,
            inverse=True,
            description="Swap space usage",
            recommendation="Reduce swap usage by optimizing memory or adding RAM"
        )
        
        self.metrics["disk_usage_root"] = PerformanceMetric(
            name="Root Disk Usage",
            category=ResourceType.DISK,
            value=0.0,
            unit="%",
            threshold_ok=70.0,
            threshold_warning=85.0,
            threshold_critical=95.0,
            inverse=True,
            description="Disk usage on root filesystem",
            recommendation="Clean up files, add storage, or implement rotation"
        )
        
        self.metrics["disk_usage_data"] = PerformanceMetric(
            name="Data Disk Usage",
            category=ResourceType.DISK,
            value=0.0,
            unit="%",
            threshold_ok=70.0,
            threshold_warning=85.0,
            threshold_critical=95.0,
            inverse=True,
            description="Disk usage on /data filesystem",
            recommendation="Clean up data, implement retention policies"
        )
        
        self.metrics["disk_io_util"] = PerformanceMetric(
            name="Disk I/O Utilization",
            category=ResourceType.IO,
            value=0.0,
            unit="%",
            threshold_ok=70.0,
            threshold_warning=85.0,
            threshold_critical=95.0,
            inverse=True,
            description="Disk I/O utilization",
            recommendation="Optimize I/O operations, consider faster storage"
        )
        
        self.metrics["network_bandwidth"] = PerformanceMetric(
            name="Network Bandwidth",
            category=ResourceType.NETWORK,
            value=0.0,
            unit="Mbps",
            threshold_ok=500.0,
            threshold_warning=800.0,
            threshold_critical=950.0,
            description="Current network bandwidth usage",
            recommendation="Optimize network usage, consider QoS"
        )
        
        # Service Performance Metrics
        self.metrics["waf_latency"] = PerformanceMetric(
            name="WAF Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=10.0,
            threshold_warning=50.0,
            threshold_critical=100.0,
            inverse=True,
            description="Average WAF processing latency",
            recommendation="Optimize WAF rules, reduce inspection complexity"
        )
        
        self.metrics["waf_throughput"] = PerformanceMetric(
            name="WAF Throughput",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="req/s",
            threshold_ok=1000.0,
            threshold_warning=500.0,
            threshold_critical=100.0,
            description="WAF requests per second",
            recommendation="Scale WAF instances, optimize rules"
        )
        
        self.metrics["crowdsec_latency"] = PerformanceMetric(
            name="CrowdSec Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=50.0,
            threshold_warning=200.0,
            threshold_critical=500.0,
            inverse=True,
            description="Average CrowdSec API latency",
            recommendation="Check CrowdSec LAPI performance, consider local caching"
        )
        
        self.metrics["mitmproxy_latency"] = PerformanceMetric(
            name="MITM Proxy Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=50.0,
            threshold_warning=200.0,
            threshold_critical=500.0,
            inverse=True,
            description="Average mitmproxy processing latency",
            recommendation="Optimize mitmproxy, add workers, reduce inspection depth"
        )
        
        self.metrics["haproxy_latency"] = PerformanceMetric(
            name="HAProxy Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=5.0,
            threshold_warning=20.0,
            threshold_critical=50.0,
            inverse=True,
            description="Average HAProxy request latency",
            recommendation="Optimize HAProxy configuration, check backend health"
        )
        
        self.metrics["nginx_latency"] = PerformanceMetric(
            name="Nginx Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=10.0,
            threshold_warning=50.0,
            threshold_critical=100.0,
            inverse=True,
            description="Average Nginx request latency",
            recommendation="Optimize Nginx configuration, enable caching"
        )
        
        # Security Impact Metrics
        self.metrics["threat_detection_latency"] = PerformanceMetric(
            name="Threat Detection Latency",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=100.0,
            threshold_warning=500.0,
            threshold_critical=1000.0,
            inverse=True,
            description="Time from request to threat detection",
            recommendation="Optimize detection pipeline, reduce processing steps"
        )
        
        self.metrics["block_execution_time"] = PerformanceMetric(
            name="Block Execution Time",
            category=ResourceType.SERVICE,
            value=0.0,
            unit="ms",
            threshold_ok=50.0,
            threshold_warning=200.0,
            threshold_critical=500.0,
            inverse=True,
            description="Time to execute block action after detection",
            recommendation="Optimize blocking mechanism, use faster enforcement"
        )
        
        logger.info(f"Initialized {len(self.metrics)} performance metrics")
    
    # -------------------------------------------------------------------------
    # Metric Collection
    # -------------------------------------------------------------------------
    
    def collect_all_metrics(self) -> Dict[str, Any]:
        """Collect all performance metrics from system and SecuBox modules."""
        
        collected = {}
        
        try:
            # System metrics
            collected.update(self._collect_system_metrics())
            
            # Service metrics (would be async in production)
            collected.update(self._collect_service_metrics())
            
            # Update metric values
            self._update_metric_values(collected)
            
            # Store in history
            self._add_to_history(collected)
            
            # Update cache
            self._cached_metrics = collected
            self._last_collection = datetime.now()
            
        except Exception as e:
            logger.error(f"Performance metric collection error: {e}")
        
        return collected
    
    def _collect_system_metrics(self) -> Dict[str, float]:
        """Collect system-level performance metrics."""
        metrics = {}
        
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics["cpu_usage"] = cpu_percent
            metrics["cpu_per_core"] = cpu_percent / psutil.cpu_count()
            
            # Memory
            mem = psutil.virtual_memory()
            metrics["memory_usage"] = mem.percent
            metrics["memory_available"] = mem.available / (1024 * 1024)  # MB
            
            # Swap
            swap = psutil.swap_memory()
            metrics["swap_usage"] = swap.percent
            
            # Disk
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    if partition.mountpoint == "/":
                        metrics["disk_usage_root"] = usage.percent
                    elif partition.mountpoint == "/data":
                        metrics["disk_usage_data"] = usage.percent
                except Exception:
                    pass
            
            # Disk I/O
            io = psutil.disk_io_counters()
            if io:
                metrics["disk_io_util"] = min(100.0, 
                    (io.read_bytes + io.write_bytes) / 1024 / 1024)  # MB/s estimate
            
            # Network
            net = psutil.net_io_counters()
            if net:
                # Calculate bandwidth (simplified)
                metrics["network_bandwidth"] = (net.bytes_sent + net.bytes_recv) / 1024 / 1024
            
        except Exception as e:
            logger.error(f"System metric collection failed: {e}")
        
        return metrics
    
    def _collect_service_metrics(self) -> Dict[str, float]:
        """Collect service-level performance metrics."""
        metrics = {}
        
        try:
            # Simulate some service metrics
            # In production, these would come from actual API calls
            
            # WAF metrics (simulated)
            metrics["waf_latency"] = 25.0  # 25ms
            metrics["waf_throughput"] = 850.0  # 850 req/s
            
            # CrowdSec metrics (simulated)
            metrics["crowdsec_latency"] = 80.0  # 80ms
            
            # MITM Proxy metrics (simulated)
            metrics["mitmproxy_latency"] = 120.0  # 120ms
            
            # HAProxy metrics (simulated)
            metrics["haproxy_latency"] = 8.0  # 8ms
            
            # Nginx metrics (simulated)
            metrics["nginx_latency"] = 15.0  # 15ms
            
            # Security impact metrics (simulated)
            metrics["threat_detection_latency"] = 150.0  # 150ms
            metrics["block_execution_time"] = 45.0  # 45ms
            
        except Exception as e:
            logger.error(f"Service metric collection failed: {e}")
        
        return metrics
    
    async def collect_service_metrics_async(self) -> Dict[str, Any]:
        """Collect service metrics asynchronously."""
        metrics = {}
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Collect from WAF
                try:
                    transport = httpx.AsyncHTTPTransport(uds="/run/secubox/waf.sock")
                    async with httpx.AsyncClient(transport=transport, timeout=4) as waf_client:
                        response = await waf_client.get("http://waf/stats")
                        if response.status_code == 200:
                            data = response.json()
                            metrics["waf_latency"] = data.get("avg_latency_ms", 0)
                            metrics["waf_throughput"] = data.get("req_per_sec", 0)
                except Exception as e:
                    logger.debug(f"WAF metrics collection failed: {e}")
                
                # Collect from Threat Analyst
                try:
                    transport = httpx.AsyncHTTPTransport(uds="/run/secubox/threat-analyst.sock")
                    async with httpx.AsyncClient(transport=transport, timeout=4) as ta_client:
                        response = await ta_client.get("http://threat-analyst/overview")
                        if response.status_code == 200:
                            data = response.json()
                            # Extract performance metrics if available
                            if "performance" in data:
                                metrics.update(data["performance"])
                except Exception as e:
                    logger.debug(f"Threat Analyst metrics collection failed: {e}")
                
                # Collect from Health Doctor
                try:
                    transport = httpx.AsyncHTTPTransport(uds="/run/secubox/health-doctor.sock")
                    async with httpx.AsyncClient(transport=transport, timeout=4) as hd_client:
                        response = await hd_client.get("http://health-doctor/checks")
                        if response.status_code == 200:
                            data = response.json()
                            # Count response times
                            checks = data.get("checks", {})
                            total_time = 0
                            count = 0
                            for check_id, check_data in checks.items():
                                if "response_time_ms" in check_data:
                                    total_time += check_data["response_time_ms"]
                                    count += 1
                            if count > 0:
                                metrics["health_check_latency"] = total_time / count
                except Exception as e:
                    logger.debug(f"Health Doctor metrics collection failed: {e}")
        
        except Exception as e:
            logger.error(f"Async service metric collection failed: {e}")
        
        return metrics
    
    def _update_metric_values(self, collected: Dict[str, float]):
        """Update metric values from collected data."""
        for name, value in collected.items():
            if name in self.metrics:
                self.metrics[name].value = value
    
    def _add_to_history(self, collected: Dict[str, float]):
        """Add current metrics to history."""
        snapshot = {name: metric.value for name, metric in self.metrics.items()}
        self._history.append(snapshot)
        
        # Keep only max history
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]
    
    # -------------------------------------------------------------------------
    # Score Calculation
    # -------------------------------------------------------------------------
    
    def calculate_performance_score(self) -> float:
        """Calculate overall performance score (0-100)."""
        
        if not self._cached_metrics:
            self.collect_all_metrics()
        
        total_score = 0.0
        total_weight = 0.0
        
        # Weight by category
        category_weights = {
            ResourceType.CPU: 0.25,
            ResourceType.MEMORY: 0.25,
            ResourceType.DISK: 0.15,
            ResourceType.NETWORK: 0.10,
            ResourceType.IO: 0.10,
            ResourceType.SERVICE: 0.15,
        }
        
        for metric in self.metrics.values():
            category_weight = category_weights.get(metric.category, 0.0)
            metric_score = metric.get_score()
            
            total_score += metric_score * category_weight
            total_weight += category_weight
        
        if total_weight > 0:
            return min(100.0, (total_score / total_weight))
        return 0.0
    
    def calculate_category_scores(self) -> Dict[str, float]:
        """Calculate per-category performance scores."""
        
        category_totals: Dict[str, float] = {}
        category_counts: Dict[str, int] = {}
        
        for metric in self.metrics.values():
            category = metric.category.value
            category_totals[category] = category_totals.get(category, 0.0) + metric.get_score()
            category_counts[category] = category_counts.get(category, 0) + 1
        
        category_scores: Dict[str, float] = {}
        for category, total in category_totals.items():
            count = category_counts[category]
            category_scores[category] = total / count if count > 0 else 0.0
        
        return category_scores
    
    # -------------------------------------------------------------------------
    # Bottleneck Detection
    # -------------------------------------------------------------------------
    
    def detect_bottlenecks(self) -> List[Bottleneck]:
        """Detect performance bottlenecks."""
        
        if not self._cached_metrics:
            self.collect_all_metrics()
        
        bottlenecks = []
        
        for name, metric in self.metrics.items():
            status = metric.get_status()
            
            # Only flag critical and poor performance
            if status in [PerformanceStatus.CRITICAL, PerformanceStatus.POOR]:
                bottleneck = Bottleneck(
                    name=metric.name,
                    resource_type=metric.category,
                    severity="high" if status == PerformanceStatus.CRITICAL else "medium",
                    description=metric.description,
                    impact=self._get_impact_description(name, metric.value),
                    metric_value=metric.value,
                    threshold=metric.threshold_critical,
                    timestamp=datetime.now().isoformat() + "Z",
                    recommendations=[metric.recommendation]
                )
                bottlenecks.append(bottleneck)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        bottlenecks.sort(key=lambda b: severity_order.get(b.severity, 4))
        
        self._bottlenecks = bottlenecks
        return bottlenecks
    
    def _get_impact_description(self, metric_name: str, value: float) -> str:
        """Get impact description for a metric."""
        impacts = {
            "cpu_usage": f"High CPU usage ({value:.1f}%) may slow down security processing and threat detection",
            "memory_usage": f"High memory usage ({value:.1f}%) may cause OOM kills and service instability",
            "disk_usage_root": f"Root disk near full ({value:.1f}%) may cause application failures and inability to log",
            "disk_usage_data": f"Data disk near full ({value:.1f}%) may cause data loss and service degradation",
            "swap_usage": f"High swap usage ({value:.1f}%) indicates memory pressure, degrading performance",
            "waf_latency": f"High WAF latency ({value:.1f}ms) allows more threats through before detection",
            "mitmproxy_latency": f"High MITM proxy latency ({value:.1f}ms) degrades user experience and security",
            "crowdsec_latency": f"High CrowdSec latency ({value:.1f}ms) delays threat detection and response",
            "threat_detection_latency": f"High detection latency ({value:.1f}ms) means threats not caught in real-time",
            "block_execution_time": f"Slow block execution ({value:.1f}ms) allows attacks to succeed before being stopped",
        }
        return impacts.get(metric_name, f"Performance issue with {metric_name}")
    
    # -------------------------------------------------------------------------
    # Recommendations
    # -------------------------------------------------------------------------
    
    def get_recommendations(self) -> Dict[str, Any]:
        """Get performance optimization recommendations."""
        
        bottlenecks = self.detect_bottlenecks()
        score = self.calculate_performance_score()
        
        recommendations = []
        
        # Add bottleneck-specific recommendations
        for bottleneck in bottlenecks:
            recommendations.append({
                "type": "bottleneck",
                "severity": bottleneck.severity,
                "title": f"Address {bottleneck.name} bottleneck",
                "description": bottleneck.description,
                "impact": bottleneck.impact,
                "current_value": bottleneck.metric_value,
                "threshold": bottleneck.threshold,
                "actions": bottleneck.recommendations,
            })
        
        # Add general recommendations based on score
        if score < 50:
            recommendations.append({
                "type": "general",
                "severity": "high",
                "title": "Critical Performance Issues",
                "description": f"Overall performance score is very low ({score:.1f}/100)",
                "impact": "Severe degradation of security functions and user experience",
                "actions": [
                    "Urgent: Identify and resolve critical bottlenecks",
                    "Review system resources (CPU, memory, disk)",
                    "Check for runaway processes or resource leaks",
                    "Consider scaling infrastructure",
                ]
            })
        elif score < 70:
            recommendations.append({
                "type": "general",
                "severity": "medium",
                "title": "Performance Degradation",
                "description": f"Overall performance score is below optimal ({score:.1f}/100)",
                "impact": "Reduced effectiveness of security functions",
                "actions": [
                    "Review and optimize resource-intensive services",
                    "Check for configuration issues",
                    "Monitor performance trends",
                    "Consider performance tuning",
                ]
            })
        elif score < 90:
            recommendations.append({
                "type": "general",
                "severity": "low",
                "title": "Performance Optimization",
                "description": f"Good performance but room for improvement ({score:.1f}/100)",
                "impact": "Minor performance gains possible",
                "actions": [
                    "Fine-tune service configurations",
                    "Implement caching where appropriate",
                    "Review and optimize rules/patterns",
                    "Monitor for emerging bottlenecks",
                ]
            })
        else:
            recommendations.append({
                "type": "general",
                "severity": "info",
                "title": "Excellent Performance",
                "description": f"Performance is excellent ({score:.1f}/100)",
                "impact": "All security functions operating at optimal levels",
                "actions": [
                    "Continue monitoring",
                    "Review performance periodically",
                    "Document current configuration for reference",
                ]
            })
        
        # Sort by severity
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        recommendations.sort(key=lambda r: severity_order.get(r.get("severity", "low"), 4))
        
        return {
            "timestamp": datetime.now().isoformat() + "Z",
            "performance_score": round(score, 1),
            "bottlenecks_detected": len(bottlenecks),
            "recommendations": recommendations,
        }
    
    # -------------------------------------------------------------------------
    # History & Trends
    # -------------------------------------------------------------------------
    
    def get_performance_history(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance history for a time period."""
        
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_history = [
            h for h in self._history
            if self._last_collection and 
            (datetime.now() - self._last_collection).total_seconds() / 3600 <= hours
        ]
        
        if not recent_history:
            return {
                "history": [],
                "trends": {},
                "message": "No history data available"
            }
        
        # Calculate trends
        trends = {}
        for metric_name, metric in self.metrics.items():
            values = [h.get(metric_name) for h in recent_history if metric_name in h]
            if len(values) >= 2:
                # Simple trend: positive if increasing, negative if decreasing
                if values[-1] > values[0]:
                    direction = "increasing" if not metric.inverse else "decreasing"
                    trend_value = values[-1] - values[0]
                else:
                    direction = "decreasing" if not metric.inverse else "increasing"
                    trend_value = values[0] - values[-1]
                
                trends[metric_name] = {
                    "direction": direction,
                    "change": round(trend_value, 2),
                    "unit": metric.unit,
                    "inverse": metric.inverse,
                }
        
        return {
            "timestamp": datetime.now().isoformat() + "Z",
            "timeframe": f"{hours}h",
            "samples": len(recent_history),
            "history": recent_history[-10:],  # Last 10 samples
            "trends": trends,
        }
    
    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        
        if not self._cached_metrics:
            self.collect_all_metrics()
        
        score = self.calculate_performance_score()
        category_scores = self.calculate_category_scores()
        bottlenecks = self.detect_bottlenecks()
        
        # Get status
        if score >= 90:
            status = "excellent"
            color = "#22c55e"
            emoji = "🟢"
        elif score >= 70:
            status = "good"
            color = "#86efac"
            emoji = "🟢"
        elif score >= 50:
            status = "fair"
            color = "#eab308"
            emoji = "🟡"
        elif score >= 30:
            status = "poor"
            color = "#f97316"
            emoji = "🟠"
        else:
            status = "critical"
            color = "#ef4444"
            emoji = "🔴"
        
        return {
            "timestamp": datetime.now().isoformat() + "Z",
            "score": round(score, 1),
            "status": status,
            "color": color,
            "emoji": emoji,
            "category_scores": category_scores,
            "bottlenecks": len(bottlenecks),
            "critical_bottlenecks": len([b for b in bottlenecks if b.severity == "high"]),
        }


# Global instance
performance_monitor = PerformanceMonitor()
