#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox Health Prober - Background service for vhost health monitoring
Writes buffered metrics to /var/cache/secubox/health/status.json
"""

import asyncio
import aiohttp
import json
import subprocess
import tomllib
from pathlib import Path
from datetime import datetime, timezone
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("health-prober")

CONFIG_FILE = Path("/etc/secubox/health.toml")
CACHE_FILE = Path("/var/cache/secubox/health/status.json")
HAPROXY_CFG = Path("/etc/haproxy/haproxy.cfg")

def load_config():
    if CONFIG_FILE.exists():
        return tomllib.loads(CONFIG_FILE.read_text())
    return {"settings": {"probe_interval_seconds": 60, "timeout_ms": 5000}}

def _ondemand_domains():
    """Domaines des modules lifecycle=on-demand (à NE PAS sonder : le probe HTTP
    les maintiendrait éveillés et empêcherait secubox-sleeper de les endormir,
    et via @sbx_wake les réveillerait). Best-effort : erreur => set() (on sonde
    tout, comportement d'avant le patch), jamais d'exception qui tue le prober."""
    doms = set()
    try:
        import glob
        for f in glob.glob("/etc/secubox/modules.d/*.toml"):
            try:
                m = tomllib.loads(Path(f).read_text())
            except Exception:
                continue
            if str(m.get("lifecycle", "")).strip() == "on-demand":
                dom = (m.get("portal") or {}).get("domain")
                if isinstance(dom, str) and dom:
                    doms.add(dom)
    except Exception:
        return set()
    return doms


def get_vhosts_from_haproxy():
    vhosts = []
    if not HAPROXY_CFG.exists():
        return vhosts
    
    content = HAPROXY_CFG.read_text()
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("acl host_") and "hdr(host)" in line:
            parts = line.split()
            if len(parts) >= 5:
                domain = parts[-1]
                if "." in domain and not domain.startswith("$"):
                    vhosts.append(domain)
    
    _od = _ondemand_domains()
    return [v for v in set(vhosts) if v not in _od]

async def probe_vhost(session, domain, timeout_ms, config):
    url = "http://127.0.0.1/"
    headers = {"Host": domain}
    timeout = aiohttp.ClientTimeout(total=timeout_ms / 1000)
    
    result = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "unknown",
        "status_code": None,
        "latency_ms": None,
        "error": None
    }
    
    try:
        start = asyncio.get_event_loop().time()
        async with session.get(url, timeout=timeout, ssl=False, headers=headers) as resp:
            latency = (asyncio.get_event_loop().time() - start) * 1000
            result["status_code"] = resp.status
            result["latency_ms"] = round(latency, 2)
            
            alert_threshold = config.get("settings", {}).get("alert_threshold_ms", 500)
            
            if resp.status == 200:
                body = await resp.text()
                # Placeholders are not "down" - they are "placeholder"
                is_placeholder = "SecuBox Domain" in body or "SecuBox Protected" in body or "nginx_vhosts" in body
                
                if is_placeholder:
                    result["status"] = "placeholder"  # Changed from "down"
                    result["error"] = "placeholder_page"
                elif latency > alert_threshold:
                    result["status"] = "slow"
                else:
                    result["status"] = "ok"
            elif resp.status in [301, 302, 303, 307, 308]:
                result["status"] = "ok"
            elif resp.status == 503:
                result["status"] = "down"
            else:
                result["status"] = "down"
                
    except asyncio.TimeoutError:
        result["status"] = "down"
        result["error"] = "timeout"
    except aiohttp.ClientError as e:
        result["status"] = "down"
        result["error"] = str(e)[:100]
    except Exception as e:
        result["status"] = "down"
        result["error"] = str(e)[:100]
    
    return result

async def probe_all(config):
    vhosts = get_vhosts_from_haproxy()
    timeout_ms = config.get("settings", {}).get("timeout_ms", 5000)
    
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total": len(vhosts),
        "ok": 0,
        "slow": 0,
        "down": 0,
        "placeholder": 0,
        "error": 0,
        "vhosts": {}
    }
    
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [probe_vhost(session, domain, timeout_ms, config) for domain in vhosts]
        probes = await asyncio.gather(*tasks, return_exceptions=True)
        
        for probe in probes:
            if isinstance(probe, Exception):
                continue
            domain = probe["domain"]
            status = probe["status"]
            results["vhosts"][domain] = probe
            
            if status == "ok":
                results["ok"] += 1
            elif status == "slow":
                results["slow"] += 1
            elif status == "placeholder":
                results["placeholder"] += 1
            elif status == "down":
                results["down"] += 1
            else:
                results["error"] += 1
    
    # Health % only counts configured vhosts (not placeholders)
    real_vhosts = results["total"] - results["placeholder"]
    if real_vhosts > 0:
        results["health_pct"] = round((results["ok"] + results["slow"]) / real_vhosts * 100, 1)
    else:
        results["health_pct"] = 100  # All placeholders = no real services to check
    
    return results

def write_cache(results):
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(results, indent=2))
    logger.info("Cache updated: %d OK, %d slow, %d placeholder, %d down", 
                results["ok"], results["slow"], results["placeholder"], results["down"])

async def main():
    config = load_config()
    interval = config.get("settings", {}).get("probe_interval_seconds", 60)
    logger.info("Health prober started, interval=%ds", interval)
    
    while True:
        try:
            results = await probe_all(config)
            write_cache(results)
        except Exception as e:
            logger.error("Probe failed: %s", e)
        await asyncio.sleep(interval)

if __name__ == "__main__":
    asyncio.run(main())
