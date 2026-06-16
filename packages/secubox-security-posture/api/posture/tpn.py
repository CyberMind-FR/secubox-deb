# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — TPN media-protection overlay
CyberMind — https://cybermind.fr

A small, HONEST media (anti-piracy / content-protection) overlay. Only signals
with a real public data source are scored:
  - anti-piracy DNS layer active   (dns-guard /status — public)
  - TLS health on served vhosts     (certs /status, vhost /access — public)
Signals whose source requires authentication (nDPId torrent/streaming
classification) are UNKNOWN; policy items (DRM, HSTS, pinning, geo-block) are
MANUAL. Nothing is faked — this replaces v1's ~95% stub.
"""

from __future__ import annotations

from typing import List

from . import sources

PASS, FAIL, MANUAL, UNKNOWN = "pass", "fail", "manual", "unknown"


async def run_report() -> dict:
    items: List[dict] = []

    # Anti-piracy DNS layer (real, public).
    ok, dg = await sources.socket_get("dns-guard", "/status")
    if ok and isinstance(dg, dict) and dg.get("blocklist_count") is not None:
        cnt = dg.get("blocklist_count") or 0
        items.append({"id": "TPN-DNS-01", "title": "Anti-piracy DNS blocklist active",
                      "status": PASS if cnt > 0 else FAIL,
                      "detail": f"{cnt} DNS blocklist entries enforced",
                      "remediation": "Enable piracy/malware DNS feeds in /dns-guard/",
                      "link": "/dns-guard/"})
    else:
        items.append({"id": "TPN-DNS-01", "title": "Anti-piracy DNS blocklist active",
                      "status": UNKNOWN, "detail": "dns-guard status unavailable", "link": "/dns-guard/"})

    # TLS on served (potentially media) vhosts (real, public).
    ok, cs = await sources.socket_get("certs", "/status")
    if ok and isinstance(cs, dict) and cs.get("health_percent") is not None:
        hp = cs["health_percent"]
        items.append({"id": "TPN-TLS-01", "title": "Valid TLS on served content vhosts",
                      "status": PASS if hp >= 90 else FAIL,
                      "detail": f"certificate health {hp}%",
                      "remediation": "Renew expiring certs for content vhosts: /certs/",
                      "link": "/certs/"})
    else:
        items.append({"id": "TPN-TLS-01", "title": "Valid TLS on served content vhosts",
                      "status": UNKNOWN, "detail": "certs status unavailable", "link": "/certs/"})

    # vhost TLS coverage (real, public).
    ok, va = await sources.socket_get("vhost", "/access")
    if ok and isinstance(va, dict) and isinstance(va.get("vhosts"), list) and va["vhosts"]:
        vh = va["vhosts"]
        ssl = sum(1 for v in vh if v.get("ssl"))
        items.append({"id": "TPN-TLS-02", "title": "Served vhosts over HTTPS",
                      "status": PASS if ssl == len(vh) else FAIL,
                      "detail": f"{ssl}/{len(vh)} vhosts on TLS",
                      "remediation": "Move plain-HTTP content vhosts to TLS", "link": "/vhost/"})

    # Torrent / streaming DPI classification — source requires nDPId auth.
    items.append({"id": "TPN-DPI-01", "title": "Torrent/P2P traffic classified absent",
                  "status": UNKNOWN, "detail": "nDPId classification requires authenticated access",
                  "link": "/dpi/"})
    items.append({"id": "TPN-DPI-02", "title": "Streaming services identified",
                  "status": UNKNOWN, "detail": "nDPId classification requires authenticated access",
                  "link": "/dpi/"})

    # Policy items — human-judged.
    for rid, title in (("TPN-DRM-01", "DRM / content-protection headers"),
                       ("TPN-HSTS-01", "HSTS enforced on media vhosts"),
                       ("TPN-PIN-01", "Certificate pinning policy"),
                       ("TPN-GEO-01", "Geo-blocking enforcement")):
        items.append({"id": rid, "title": title, "status": MANUAL,
                      "detail": "operator-defined media policy"})

    scored = [i for i in items if i["status"] in (PASS, FAIL)]
    passed = sum(1 for i in scored if i["status"] == PASS)
    return {
        "score": round(100 * passed / len(scored), 1) if scored else None,
        "passed": passed,
        "scored": len(scored),
        "manual": sum(1 for i in items if i["status"] == MANUAL),
        "unknown": sum(1 for i in items if i["status"] == UNKNOWN),
        "total": len(items),
        "items": items,
    }
