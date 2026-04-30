#!/usr/bin/env python3
"""
SecuBox Performance Benchmark - Locust Load Test Scenarios

Load testing scenarios for SecuBox API endpoints.

Usage:
    # Web UI mode
    locust -f locustfile.py --host https://192.168.255.250

    # Headless mode
    locust -f locustfile.py --host https://192.168.255.250 \
           --headless -u 10 -r 2 -t 60s

    # ESPRESSObin (light load)
    locust -f locustfile.py --host https://192.168.255.250 \
           --headless -u 5 -r 1 -t 120s --tags lite

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import json
import time
from locust import HttpUser, task, between, tag, events
from locust.runners import MasterRunner


class SecuBoxUser(HttpUser):
    """Simulates a typical SecuBox dashboard user."""

    # Wait 1-3 seconds between requests (realistic browsing)
    wait_time = between(1, 3)

    # Auth token
    token = None

    def on_start(self):
        """Login and get JWT token."""
        try:
            resp = self.client.post(
                "/api/v1/hub/login",
                json={"username": "admin", "password": "secubox"},
                verify=False,
                catch_response=True
            )
            if resp.status_code == 200:
                data = resp.json()
                self.token = data.get("access_token")
                resp.success()
            else:
                resp.failure(f"Login failed: {resp.status_code}")
        except Exception as e:
            print(f"Login error: {e}")

    @property
    def auth_headers(self):
        """Headers with auth token."""
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    # ========== Public Endpoints (No Auth) ==========

    @task(10)
    @tag("public", "lite")
    def get_system_metrics(self):
        """Most common: system metrics for dashboard."""
        self.client.get(
            "/api/v1/system/metrics",
            verify=False,
            name="/api/v1/system/metrics"
        )

    @task(5)
    @tag("public", "lite")
    def get_system_info(self):
        """System info (hostname, uptime)."""
        self.client.get(
            "/api/v1/system/info",
            verify=False,
            name="/api/v1/system/info"
        )

    @task(3)
    @tag("public")
    def get_public_info(self):
        """Hub public info (version, auth mode)."""
        self.client.get(
            "/api/v1/hub/public/info",
            verify=False,
            name="/api/v1/hub/public/info"
        )

    # ========== Authenticated Endpoints ==========

    @task(8)
    @tag("auth", "lite")
    def get_hub_monitoring(self):
        """Main monitoring endpoint (CPU, mem, load)."""
        self.client.get(
            "/api/v1/hub/monitoring",
            headers=self.auth_headers,
            verify=False,
            name="/api/v1/hub/monitoring"
        )

    @task(5)
    @tag("auth")
    def get_hub_status(self):
        """Hub status with module info."""
        self.client.get(
            "/api/v1/hub/status",
            headers=self.auth_headers,
            verify=False,
            name="/api/v1/hub/status"
        )

    @task(3)
    @tag("auth")
    def get_hub_modules(self):
        """List active modules."""
        self.client.get(
            "/api/v1/hub/modules",
            headers=self.auth_headers,
            verify=False,
            name="/api/v1/hub/modules"
        )

    @task(2)
    @tag("auth", "heavy")
    def get_system_services(self):
        """List all services (heavier query)."""
        self.client.get(
            "/api/v1/system/services",
            headers=self.auth_headers,
            verify=False,
            name="/api/v1/system/services"
        )

    @task(1)
    @tag("auth", "heavy")
    def get_system_logs(self):
        """Get recent logs (I/O heavy)."""
        self.client.get(
            "/api/v1/system/logs?limit=50",
            headers=self.auth_headers,
            verify=False,
            name="/api/v1/system/logs"
        )


class StressUser(HttpUser):
    """High-frequency API stress testing."""

    # No wait - maximum throughput
    wait_time = between(0, 0.1)

    @task
    @tag("stress")
    def hammer_metrics(self):
        """Stress test the metrics endpoint."""
        self.client.get(
            "/api/v1/system/metrics",
            verify=False,
            name="/api/v1/system/metrics [STRESS]"
        )


class CacheTestUser(HttpUser):
    """Test cache effectiveness."""

    wait_time = between(0.5, 1)

    @task
    @tag("cache")
    def rapid_metrics(self):
        """Rapid requests to test cache hit ratio."""
        start = time.time()
        self.client.get(
            "/api/v1/system/metrics",
            verify=False,
            name="/api/v1/system/metrics [CACHE]"
        )
        elapsed = time.time() - start

        # Log if response was slow (likely cache miss)
        if elapsed > 0.1:
            print(f"Slow response: {elapsed*1000:.0f}ms (possible cache miss)")


# ========== Event Handlers ==========

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts."""
    print("=" * 60)
    print("SecuBox Load Test Starting")
    print(f"Target: {environment.host}")
    if isinstance(environment.runner, MasterRunner):
        print(f"Workers: {environment.runner.worker_count}")
    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops."""
    print("\n" + "=" * 60)
    print("SecuBox Load Test Complete")
    print("=" * 60)

    # Print summary
    stats = environment.stats
    print(f"\nTotal Requests: {stats.total.num_requests}")
    print(f"Failures: {stats.total.num_failures}")
    print(f"Median Response: {stats.total.median_response_time}ms")
    print(f"P95 Response: {stats.total.get_response_time_percentile(0.95)}ms")
    print(f"P99 Response: {stats.total.get_response_time_percentile(0.99)}ms")
    print(f"RPS: {stats.total.current_rps:.1f}")


# ========== Custom Scenarios ==========

class EspressoBinUser(HttpUser):
    """Light load for ESPRESSObin (1GB RAM)."""

    # Slower pace for constrained device
    wait_time = between(2, 5)

    @task(5)
    def get_metrics_light(self):
        """Primary metrics endpoint."""
        self.client.get(
            "/api/v1/system/metrics",
            verify=False,
            name="/api/v1/system/metrics [LITE]"
        )

    @task(2)
    def get_monitoring_light(self):
        """Hub monitoring."""
        self.client.get(
            "/api/v1/hub/monitoring",
            verify=False,
            name="/api/v1/hub/monitoring [LITE]"
        )


class MochabinUser(HttpUser):
    """Heavy load for MOCHAbin (8GB RAM)."""

    # Faster pace for capable device
    wait_time = between(0.5, 1.5)

    token = None

    def on_start(self):
        """Login."""
        try:
            resp = self.client.post(
                "/api/v1/hub/login",
                json={"username": "admin", "password": "secubox"},
                verify=False
            )
            if resp.status_code == 200:
                self.token = resp.json().get("access_token")
        except Exception:
            pass

    @property
    def auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    @task(10)
    def get_all_metrics(self):
        """Full metrics suite."""
        self.client.get("/api/v1/system/metrics", verify=False)
        self.client.get("/api/v1/system/resources", verify=False)
        self.client.get("/api/v1/hub/monitoring", headers=self.auth_headers, verify=False)

    @task(5)
    def get_services(self):
        """Heavy: list all services."""
        self.client.get(
            "/api/v1/system/services",
            headers=self.auth_headers,
            verify=False
        )

    @task(3)
    def get_modules(self):
        """Module status."""
        self.client.get(
            "/api/v1/hub/modules",
            headers=self.auth_headers,
            verify=False
        )
