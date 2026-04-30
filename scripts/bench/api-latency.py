#!/usr/bin/env python3
"""
SecuBox Performance Benchmark - API Latency Measurement

Measures response times for SecuBox API endpoints.
Outputs JSON report with P50, P95, P99 latencies.

Usage:
    ./api-latency.py --host 192.168.255.250 --requests 100
    ./api-latency.py --host 10.55.0.1 --endpoints /api/v1/system/metrics

CyberMind - https://cybermind.fr
Author: Gerald Kerma <gandalf@gk2.net>
"""

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

try:
    import httpx
except ImportError:
    print("ERROR: httpx required. Install with: pip3 install httpx")
    sys.exit(1)


# Default endpoints to test
DEFAULT_ENDPOINTS = [
    "/api/v1/system/metrics",
    "/api/v1/system/info",
    "/api/v1/system/resources",
    "/api/v1/hub/status",
    "/api/v1/hub/monitoring",
    "/api/v1/hub/public/info",
]


@dataclass
class LatencyResult:
    """Result for a single endpoint."""
    endpoint: str
    requests: int
    successful: int
    failed: int
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    errors: List[str]


@dataclass
class BenchmarkReport:
    """Full benchmark report."""
    host: str
    timestamp: str
    total_requests: int
    total_duration_s: float
    results: List[LatencyResult]


async def measure_endpoint(
    client: httpx.AsyncClient,
    url: str,
    requests: int,
    token: Optional[str] = None
) -> LatencyResult:
    """Measure latency for a single endpoint."""
    latencies: List[float] = []
    errors: List[str] = []

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for i in range(requests):
        start = time.perf_counter()
        try:
            resp = await client.get(url, headers=headers, timeout=10.0)
            elapsed = (time.perf_counter() - start) * 1000  # ms

            if resp.status_code == 200:
                latencies.append(elapsed)
            else:
                errors.append(f"HTTP {resp.status_code}")
        except httpx.TimeoutException:
            errors.append("Timeout")
        except httpx.ConnectError as e:
            errors.append(f"Connect: {e}")
        except Exception as e:
            errors.append(str(e))

        # Small delay between requests
        await asyncio.sleep(0.05)

    if not latencies:
        return LatencyResult(
            endpoint=url,
            requests=requests,
            successful=0,
            failed=len(errors),
            min_ms=0, max_ms=0, mean_ms=0, median_ms=0,
            p95_ms=0, p99_ms=0,
            errors=errors[:5]  # Limit error samples
        )

    sorted_latencies = sorted(latencies)
    p95_idx = int(len(sorted_latencies) * 0.95)
    p99_idx = int(len(sorted_latencies) * 0.99)

    return LatencyResult(
        endpoint=url,
        requests=requests,
        successful=len(latencies),
        failed=len(errors),
        min_ms=round(min(latencies), 2),
        max_ms=round(max(latencies), 2),
        mean_ms=round(statistics.mean(latencies), 2),
        median_ms=round(statistics.median(latencies), 2),
        p95_ms=round(sorted_latencies[p95_idx] if p95_idx < len(sorted_latencies) else sorted_latencies[-1], 2),
        p99_ms=round(sorted_latencies[p99_idx] if p99_idx < len(sorted_latencies) else sorted_latencies[-1], 2),
        errors=errors[:5]
    )


async def get_auth_token(client: httpx.AsyncClient, base_url: str) -> Optional[str]:
    """Get JWT token for authenticated endpoints."""
    login_url = urljoin(base_url, "/api/v1/hub/login")
    try:
        resp = await client.post(
            login_url,
            json={"username": "admin", "password": "secubox"},
            timeout=10.0
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("access_token")
    except Exception as e:
        print(f"Warning: Could not get auth token: {e}")
    return None


async def run_benchmark(
    host: str,
    endpoints: List[str],
    requests: int,
    use_https: bool = True
) -> BenchmarkReport:
    """Run full benchmark suite."""
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{host}"

    start_time = time.time()
    results: List[LatencyResult] = []

    async with httpx.AsyncClient(verify=False) as client:
        # Get auth token
        token = await get_auth_token(client, base_url)
        if token:
            print(f"Authenticated successfully")
        else:
            print(f"Running without authentication (public endpoints only)")

        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            print(f"Testing {endpoint}...", end=" ", flush=True)

            result = await measure_endpoint(client, url, requests, token)
            results.append(result)

            if result.successful > 0:
                print(f"P50={result.median_ms}ms P99={result.p99_ms}ms ({result.successful}/{requests})")
            else:
                print(f"FAILED ({result.errors[0] if result.errors else 'unknown'})")

    duration = time.time() - start_time

    return BenchmarkReport(
        host=host,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        total_requests=sum(r.requests for r in results),
        total_duration_s=round(duration, 2),
        results=results
    )


def print_report(report: BenchmarkReport):
    """Print formatted report."""
    print("\n" + "=" * 70)
    print(f"SecuBox API Latency Report")
    print(f"Host: {report.host}")
    print(f"Time: {report.timestamp}")
    print(f"Duration: {report.total_duration_s}s")
    print("=" * 70)

    print(f"\n{'Endpoint':<45} {'P50':>8} {'P99':>8} {'OK':>6}")
    print("-" * 70)

    for r in report.results:
        status = f"{r.successful}/{r.requests}"
        print(f"{r.endpoint:<45} {r.median_ms:>7.1f}ms {r.p99_ms:>7.1f}ms {status:>6}")

    print("-" * 70)

    # Summary
    all_p99 = [r.p99_ms for r in report.results if r.successful > 0]
    all_p50 = [r.median_ms for r in report.results if r.successful > 0]

    if all_p99:
        print(f"\nOverall P50: {statistics.mean(all_p50):.1f}ms")
        print(f"Overall P99: {max(all_p99):.1f}ms (worst endpoint)")

        # Performance verdict
        worst_p99 = max(all_p99)
        if worst_p99 < 100:
            print("\nVerdict: EXCELLENT")
        elif worst_p99 < 500:
            print("\nVerdict: GOOD")
        elif worst_p99 < 1000:
            print("\nVerdict: ACCEPTABLE")
        else:
            print("\nVerdict: NEEDS OPTIMIZATION")


def main():
    parser = argparse.ArgumentParser(
        description="SecuBox API Latency Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Test ESPRESSObin
    %(prog)s --host 192.168.255.250 --requests 50

    # Test specific endpoint
    %(prog)s --host 10.55.0.1 --endpoints /api/v1/system/metrics

    # Output JSON
    %(prog)s --host 192.168.255.250 --json > report.json
"""
    )

    parser.add_argument("--host", required=True, help="Target host IP or hostname")
    parser.add_argument("--requests", type=int, default=50, help="Requests per endpoint (default: 50)")
    parser.add_argument("--endpoints", nargs="*", help="Endpoints to test (default: standard set)")
    parser.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS")
    parser.add_argument("--json", action="store_true", help="Output JSON report")

    args = parser.parse_args()

    endpoints = args.endpoints or DEFAULT_ENDPOINTS

    if not args.json:
        print(f"SecuBox API Latency Benchmark")
        print(f"Target: {args.host}")
        print(f"Requests per endpoint: {args.requests}")
        print(f"Endpoints: {len(endpoints)}")
        print()

    report = asyncio.run(run_benchmark(
        host=args.host,
        endpoints=endpoints,
        requests=args.requests,
        use_https=not args.http
    ))

    if args.json:
        # Convert to JSON-serializable dict
        report_dict = {
            "host": report.host,
            "timestamp": report.timestamp,
            "total_requests": report.total_requests,
            "total_duration_s": report.total_duration_s,
            "results": [asdict(r) for r in report.results]
        }
        print(json.dumps(report_dict, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
