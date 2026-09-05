# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — real signal collectors
CyberMind — https://cybermind.fr

One async coroutine per module-domain. Each returns a list of Indicators built
only from data actually fetched over public sibling sockets / unprivileged
/proc. When a source is unreachable the indicator is
emitted as UNKNOWN (with provenance.ok = False); when a property can only be
judged by a human it is MANUAL. Nothing is ever invented.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import List, Optional

from . import sources
from .model import Indicator, Provenance, Status
from .scoring import status_of

AUDIT_LOG = "/var/log/secubox/audit.log"


# ---- indicator builders ----------------------------------------------------

def _scored(id, domain, label, value, source, *, weight=1.0, detail="",
            remediation=None, link=None, ok=0.8, warn=0.5) -> Indicator:
    value = max(0.0, min(1.0, float(value)))
    return Indicator(
        id=id, domain=domain, label=label, status=status_of(value, ok, warn),
        provenance=Provenance(source, ok=True), value=value, weight=weight,
        detail=detail, remediation=remediation, link=link,
    )


def _unknown(id, domain, label, source, *, weight=1.0, note="source unreachable",
             remediation=None, link=None) -> Indicator:
    return Indicator(
        id=id, domain=domain, label=label, status=Status.UNKNOWN,
        provenance=Provenance(source, ok=False, note=note), value=None,
        weight=weight, detail=note, remediation=remediation, link=link,
    )


def _manual(id, domain, label, source, *, note="human-judged", link=None) -> Indicator:
    return Indicator(
        id=id, domain=domain, label=label, status=Status.MANUAL,
        provenance=Provenance(source, ok=True, note=note), value=None,
        weight=1.0, detail=note, link=link,
    )


class Probe:
    """Shared, pre-fetched cross-domain signal (health-doctor backbone)."""

    def __init__(self):
        self.hd: dict = {}

    async def prefetch(self):
        ok, data = await sources.socket_get("health-doctor", "/checks")
        self.hd = (data or {}).get("checks", {}) if ok and isinstance(data, dict) else {}

    def svc_ok(self, *names) -> Optional[bool]:
        """True/False if any named health-doctor check is found; None if absent."""
        seen = False
        good = False
        for n in names:
            c = self.hd.get(n)
            if isinstance(c, dict) and "ok" in c:
                seen = True
                good = good or bool(c["ok"])
        return good if seen else None


# ---- ROOT (system & Debian health) ----------------------------------------

async def collect_root(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []
    ok, m = await sources.socket_get("system", "/metrics")
    src = "socket:system.sock /metrics"
    if ok and isinstance(m, dict):
        cpu = m.get("cpu_percent")
        mem = m.get("mem_percent")
        disk = m.get("disk_percent")
        load = m.get("load_avg_1")
        if cpu is not None:
            out.append(_scored("cpu_headroom", "root", "CPU headroom",
                               1 - cpu / 100, src, detail=f"CPU at {cpu:.0f}%",
                               remediation="Investigate top processes: systemctl status / htop",
                               link="/system/"))
        if mem is not None:
            out.append(_scored("mem_headroom", "root", "Memory headroom",
                               1 - mem / 100, src, detail=f"Memory at {mem:.0f}%",
                               remediation="Check memory hogs; consider KSM (secubox-ksm)",
                               link="/system/"))
        if disk is not None:
            out.append(_scored("disk_headroom", "root", "Disk headroom",
                               1 - disk / 100, src, weight=1.5,
                               detail=f"Root filesystem at {disk:.0f}%", ok=0.85, warn=0.6,
                               remediation="Free space / rotate logs: journalctl --vacuum-size=200M",
                               link="/system/"))
        if load is not None:
            cores = sources.cpu_count()
            out.append(_scored("load_headroom", "root", "Load headroom",
                               1 - min(1.0, load / cores), src,
                               detail=f"1-min load {load:.2f} on {cores} cores", link="/system/"))
    else:
        # Unprivileged /proc fallback so ROOT is never fully blind.
        load = sources.read_loadavg()
        memr = sources.read_mem_available_ratio()
        if load is not None:
            cores = sources.cpu_count()
            out.append(_scored("load_headroom", "root", "Load headroom",
                               1 - min(1.0, load / cores), "/proc/loadavg",
                               detail=f"1-min load {load:.2f} on {cores} cores", link="/system/"))
        if memr is not None:
            out.append(_scored("mem_headroom", "root", "Memory headroom", memr,
                               "/proc/meminfo", detail=f"{memr*100:.0f}% available", link="/system/"))
        if load is None and memr is None:
            out.append(_unknown("system_metrics", "root", "System metrics", src,
                                note="system.sock and /proc both unavailable", link="/system/"))

    # Failed systemd units via public /services.
    ok, s = await sources.socket_get("system", "/services")
    if ok and isinstance(s, dict) and isinstance(s.get("services"), list):
        svcs = s["services"]
        total = len(svcs)
        active = sum(1 for x in svcs if x.get("active"))
        if total:
            out.append(_scored("service_health", "root", "Service health",
                               active / total, "socket:system.sock /services", weight=1.5,
                               detail=f"{active}/{total} units active",
                               remediation="systemctl --failed ; restart the failed unit",
                               link="/system/", ok=0.95, warn=0.8))
    else:
        out.append(_unknown("service_health", "root", "Service health",
                            "socket:system.sock /services", link="/system/"))

    # Audit-log freshness (CSPN immutable-log requirement). Unprivileged read.
    try:
        st = Path(AUDIT_LOG).stat()
        age_h = (time.time() - st.st_mtime) / 3600.0
        fresh = 1.0 if age_h < 24 else (0.5 if age_h < 72 else 0.0)
        out.append(_scored("audit_log_fresh", "root", "Audit log freshness", fresh,
                           AUDIT_LOG, detail=f"last write {age_h:.1f}h ago", ok=0.9, warn=0.4,
                           remediation="Verify /var/log/secubox/audit.log is being written",
                           link="/system/"))
    except Exception:
        out.append(_unknown("audit_log_fresh", "root", "Audit log freshness",
                            AUDIT_LOG, note="audit.log not readable", link="/system/"))
    return out


# ---- WALL (firewall / WAF / IDS) -------------------------------------------

async def collect_wall(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []

    # WAF running + rule coverage (public).
    ok, st = await sources.socket_get("waf", "/stats")
    if ok and isinstance(st, dict):
        running = bool(st.get("running"))
        rules = st.get("rules_loaded", 0) or 0
        out.append(_scored("waf_running", "wall", "WAF inspection", 1.0 if (running and rules) else 0.0,
                           "socket:waf.sock /stats", weight=1.5,
                           detail=f"WAF {'running' if running else 'stopped'}, {rules} rules loaded",
                           remediation="systemctl status secubox-waf ; reload WAF rules", link="/waf/"))
    ok, cat = await sources.socket_get("waf", "/categories")
    if ok and isinstance(cat, dict) and isinstance(cat.get("categories"), dict):
        cats = cat["categories"].values()
        total = len(cats)
        enabled = sum(1 for c in cats if c.get("enabled"))
        if total:
            out.append(_scored("waf_rule_coverage", "wall", "WAF rule coverage", enabled / total,
                               "socket:waf.sock /categories",
                               detail=f"{enabled}/{total} OWASP categories enabled",
                               remediation="Enable more WAF categories in /waf/", link="/waf/",
                               ok=0.8, warn=0.5))
    return out


# ---- AUTH (authentication & zero-trust) ------------------------------------

async def collect_auth(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []
    ok, h = await sources.socket_get("auth", "/health")
    up = ok and isinstance(h, dict) and h.get("status") == "ok"
    out.append(_scored("auth_service", "auth", "Auth service", 1.0 if up else 0.0,
                       "socket:auth.sock /health", weight=1.5,
                       detail="auth-guardian responding" if up else "auth service down",
                       remediation="systemctl status secubox-auth", link="/auth/"))

    # Cross-check via health-doctor backbone if present.
    sok = probe.svc_ok("secubox-auth", "auth", "authelia")
    if sok is not None:
        out.append(_scored("auth_health_doctor", "auth", "Auth health check", 1.0 if sok else 0.0,
                           "socket:health-doctor.sock /checks",
                           detail="health-doctor reports auth OK" if sok else "health-doctor flags auth",
                           link="/auth/"))

    # SSH exposure (public system /security).
    ok, sec = await sources.socket_get("system", "/security")
    if ok and isinstance(sec, dict) and sec.get("ssh_status"):
        ssh = str(sec["ssh_status"]).lower()
        good = any(k in ssh for k in ("key", "hardened", "disabled", "off"))
        out.append(_scored("ssh_hardening", "auth", "SSH exposure", 1.0 if good else 0.5,
                           "socket:system.sock /security", detail=f"sshd: {sec['ssh_status']}",
                           remediation="Disable password auth; key-only SSH", link="/system/",
                           ok=0.9, warn=0.5))

    # MFA / session policy require authenticated introspection → honestly MANUAL.
    out.append(_manual("mfa_policy", "auth", "MFA enrollment policy",
                       "socket:auth.sock /status (auth required)",
                       note="requires authenticated session to verify", link="/auth/"))
    return out


# ---- MESH (network / VPN / certs / DNS) ------------------------------------

async def collect_mesh(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []

    # TLS certificate health (public).
    ok, cs = await sources.socket_get("certs", "/status")
    if ok and isinstance(cs, dict) and cs.get("health_percent") is not None:
        out.append(_scored("cert_health", "mesh", "TLS certificate health",
                           cs["health_percent"] / 100, "socket:certs.sock /status", weight=1.5,
                           detail=f"cert health {cs['health_percent']}%",
                           remediation="Renew expiring certs: /certs/", link="/certs/", ok=0.9, warn=0.6))
    else:
        out.append(_unknown("cert_health", "mesh", "TLS certificate health",
                            "socket:certs.sock /status", link="/certs/"))

    # WireGuard peers (public /peers).
    ok, wg = await sources.socket_get("wireguard", "/peers")
    if ok and isinstance(wg, dict) and wg.get("peer_count"):
        pc = wg.get("peer_count") or 0
        onl = wg.get("online_peers") or 0
        out.append(_scored("wg_peer_health", "mesh", "WireGuard peers", (onl / pc) if pc else 0.0,
                           "socket:wireguard.sock /peers", detail=f"{onl}/{pc} peers online",
                           remediation="Check peer handshakes: wg show", link="/wireguard/",
                           ok=0.7, warn=0.3))
    # vhost TLS coverage (public /access: vhosts[].ssl).
    ok, va = await sources.socket_get("vhost", "/access")
    if ok and isinstance(va, dict) and isinstance(va.get("vhosts"), list) and va["vhosts"]:
        vh = va["vhosts"]
        ssl = sum(1 for v in vh if v.get("ssl"))
        out.append(_scored("vhost_tls", "mesh", "vhost TLS coverage", ssl / len(vh),
                           "socket:vhost.sock /access", detail=f"{ssl}/{len(vh)} vhosts on TLS",
                           remediation="Issue certs for plain-HTTP vhosts", link="/vhost/", ok=0.9, warn=0.6))
    # DNS blocklist active (public dns-guard /status).
    ok, dg = await sources.socket_get("dns-guard", "/status")
    if ok and isinstance(dg, dict) and dg.get("blocklist_count") is not None:
        cnt = dg.get("blocklist_count") or 0
        out.append(_scored("dns_blocklist", "mesh", "DNS blocklist", 1.0 if cnt > 0 else 0.0,
                           "socket:dns-guard.sock /status", detail=f"{cnt} blocklist entries",
                           remediation="Enable DNS blocklists in /dns-guard/", link="/dns-guard/"))
    return out


# ---- MIND (DPI / behavioural) ----------------------------------------------

async def collect_mind(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []
    # DPI engine liveness via health-doctor backbone.
    sok = probe.svc_ok("ndpid", "secubox-dpi", "dpi")
    if sok is not None:
        out.append(_scored("dpi_active", "mind", "DPI engine", 1.0 if sok else 0.0,
                           "socket:health-doctor.sock /checks", weight=1.5,
                           detail="DPI/nDPId reporting" if sok else "DPI engine down",
                           remediation="systemctl status ndpid", link="/dpi/"))
    else:
        out.append(_unknown("dpi_active", "mind", "DPI engine",
                            "socket:health-doctor.sock /checks", link="/dpi/"))

    # DNS anomaly pressure (public dns-guard /status alerts_24h: lower is better).
    ok, dg = await sources.socket_get("dns-guard", "/status")
    if ok and isinstance(dg, dict) and dg.get("alerts_24h") is not None:
        alerts = dg.get("alerts_24h") or 0
        # 0 alerts → 1.0 ; degrade linearly, floor at 20 alerts/24h.
        val = max(0.0, 1.0 - alerts / 20.0)
        out.append(_scored("dns_anomaly", "mind", "DNS anomaly pressure", val,
                           "socket:dns-guard.sock /status", detail=f"{alerts} DNS alerts in 24h",
                           remediation="Review DGA/tunnelling alerts in /dns-guard/", link="/dns-guard/",
                           ok=0.8, warn=0.4))

    # Behavioural anomaly detection requires authenticated network-anomaly API.
    out.append(_manual("behavioural_anomaly", "mind", "Behavioural anomaly engine",
                       "socket:network-anomaly.sock (auth required)",
                       note="requires authenticated access to inspect", link="/dpi/"))
    return out


# ---- BOOT (hardening / backup / integrity) ---------------------------------

async def collect_boot(probe: Probe) -> List[Indicator]:
    out: List[Indicator] = []
    # System hardening posture (try public hardening status).
    ok, hd = await sources.socket_get("hardening", "/status")
    pct = None
    if ok and isinstance(hd, dict):
        pct = hd.get("percentage") if hd.get("percentage") is not None else hd.get("score")
    if pct is not None:
        out.append(_scored("hardening_score", "boot", "System hardening", float(pct) / 100,
                           "socket:hardening.sock /status", weight=1.5,
                           detail=f"hardening benchmark {pct}%",
                           remediation="Apply hardening recommendations in /hardening/", link="/hardening/",
                           ok=0.85, warn=0.6))
    else:
        out.append(_unknown("hardening_score", "boot", "System hardening",
                            "socket:hardening.sock /status", link="/hardening/"))

    # Service-integrity backbone from health-doctor (overall passing ratio).
    if probe.hd:
        total = len(probe.hd)
        good = sum(1 for c in probe.hd.values() if isinstance(c, dict) and c.get("ok"))
        if total:
            out.append(_scored("service_integrity", "boot", "Service integrity", good / total,
                               "socket:health-doctor.sock /checks", weight=1.5,
                               detail=f"{good}/{total} health checks passing",
                               remediation="Resolve failing checks in /system/", link="/system/",
                               ok=0.9, warn=0.7))
    # Backup freshness needs authenticated backup API.
    out.append(_manual("backup_freshness", "boot", "Backup freshness",
                       "socket:backup.sock /history (auth required)",
                       note="requires authenticated access to verify", link="/system/"))
    return out


async def collect_all() -> List[Indicator]:
    """Run every domain collector concurrently and flatten the result."""
    probe = Probe()
    await probe.prefetch()
    groups = await asyncio.gather(
        collect_root(probe), collect_wall(probe), collect_auth(probe),
        collect_mesh(probe), collect_mind(probe), collect_boot(probe),
        return_exceptions=True,
    )
    out: List[Indicator] = []
    for g in groups:
        if isinstance(g, list):
            out.extend(g)
    return out
