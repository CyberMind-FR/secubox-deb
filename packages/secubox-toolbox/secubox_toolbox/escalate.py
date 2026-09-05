# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""
SecuBox-Deb :: ToolBoX escalation evaluator (Phase 13.D #527)

Closes the detection → enforcement loop : reads the social-mapping
(operator-grade / anti-bot) + device-blocks aggregates, applies
operator-tunable thresholds, and escalates high-confidence repeat
offenders to the enforcement plane :

  - escalate a tracker/operator-grade HOST → resolve its IPs and add
    them to the 13.A blacklist set (audited, with a TTL),
  - escalate a DEVICE over the DoH/bypass threshold → 13.C quarantine.

**Everything is DEFAULT OFF.** Each source is enabled independently via
env flags (mirrors the SECUBOX_DOH_BLOCK pattern). Every action is
logged to the append-only CSPN audit log and is reversible (nft
timeouts + operator unban). This module decides + records ; the thin
`secubox-escalate` wrapper invokes it on a timer.
"""
from __future__ import annotations

import logging
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Dict, List

from . import ip_dns

log = logging.getLogger("secubox.toolbox.escalate")

NFT = "/usr/sbin/nft"
TABLE = "inet secubox_blacklist"
AUDIT_LOG = Path("/var/log/secubox/audit.log")
ESCALATE_TTL = os.environ.get("SECUBOX_ESCALATE_TTL", "4h")
PURE_TRACKERS_PATH = os.environ.get(
    "SECUBOX_PURE_TRACKERS", "/var/lib/secubox/toolbox/pure-trackers.txt")


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip() in ("1", "true", "yes", "on")


def load_policy() -> Dict:
    """Operator policy from env (all default OFF). The systemd unit /
    a drop-in sets these ; nothing escalates until an operator opts in."""
    return {
        "opgrade_enabled": _flag("SECUBOX_ESCALATE_OPGRADE"),
        "opgrade_min_clients": int(os.environ.get("SECUBOX_ESCALATE_OPGRADE_MIN_CLIENTS", "2")),
        "opgrade_min_events": int(os.environ.get("SECUBOX_ESCALATE_OPGRADE_MIN_EVENTS", "20")),
        "antibot_enabled": _flag("SECUBOX_ESCALATE_ANTIBOT"),
        "antibot_min_challenges": int(os.environ.get("SECUBOX_ESCALATE_ANTIBOT_MIN", "50")),
        "device_doh_enabled": _flag("SECUBOX_ESCALATE_DEVICE_DOH"),
        "device_doh_threshold": int(os.environ.get("SECUBOX_ESCALATE_DEVICE_DOH_THRESHOLD", "200")),
        "window_hours": int(os.environ.get("SECUBOX_ESCALATE_WINDOW_H", "24")),
    }


def _audit(msg: str) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with AUDIT_LOG.open("a") as f:
            f.write(f"{ts} secubox-escalate {msg}\n")
    except Exception as e:  # pragma: no cover
        log.warning("audit write failed: %s", e)


def _resolve_ips(host: str, timeout: float = 2.0) -> List[str]:
    out: List[str] = []
    try:
        socket.setdefaulttimeout(timeout)
        for fam, *_rest, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip and ip not in out:
                out.append(ip)
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(None)
    return out


def _nft_add_blacklist(ip: str) -> bool:
    setname = "blacklist_v6" if ":" in ip else "blacklist_v4"
    try:
        r = subprocess.run(
            [NFT, "add", "element", "inet", "secubox_blacklist", setname,
             "{ " + ip + " timeout " + ESCALATE_TTL + " }"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _nft_quarantine(ip: str) -> bool:
    setname = "quarantine_v6" if ":" in ip else "quarantine_v4"
    try:
        r = subprocess.run(
            [NFT, "add", "element", "inet", "secubox_blacklist", setname,
             "{ " + ip + " timeout " + ESCALATE_TTL + " }"],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def pure_tracker_ip_drop(pure_path: str = PURE_TRACKERS_PATH,
                         allowlist_path: str = ip_dns.CDN_ALLOWLIST_PATH,
                         enforce: bool = False, ip_drop: bool = False) -> int:
    """Drop the IPs of confirmed pure-tracker domains into the nft blacklist,
    excluding CDN/cloud ranges. No-op unless enforce AND ip_drop. Returns the
    number of IPs dropped. Reversible (TTL) + audited."""
    if not (enforce and ip_drop):
        return 0
    try:
        hosts = [ln.split()[0].lower()
                 for ln in Path(pure_path).read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
    except OSError:
        return 0
    # NOTE: a missing/unreadable CDN allowlist yields [] → every resolved pure
    # IP becomes eligible to drop (fail-open). Bounded by the conservative
    # pure-only source and the dark double-gate, but keep the shipped allowlist
    # present in production.
    nets = ip_dns.load_cdn_allowlist(allowlist_path)
    ips = ip_dns.exclusive_tracker_ips(hosts, _resolve_ips, nets)
    dropped_ips = []
    for ip in sorted(ips):
        if _nft_add_blacklist(ip):
            dropped_ips.append(ip)
    if dropped_ips:
        _audit(f"ESCALATE pure-tracker-ip dropped={len(dropped_ips)} "
               f"ips={','.join(dropped_ips)} ttl={ESCALATE_TTL}")
    return len(dropped_ips)


def evaluate_and_apply() -> Dict:
    """Run one escalation cycle. Returns a summary of actions taken.
    No-op (beyond reading aggregates) unless a source is opted-in."""
    policy = load_policy()
    summary: Dict = {
        "ts": int(time.time()),
        "policy": {k: v for k, v in policy.items()},
        "opgrade_escalated": 0,
        "antibot_escalated": 0,
        "devices_quarantined": 0,
        "ips_added": 0,
        "actions": [],
    }

    # Anti-Track v2 (#633): pure-tracker exclusive-IP drop (dark unless armed).
    try:
        from .filters import get_filters as _gf
        _f = _gf()
        _n = pure_tracker_ip_drop(enforce=bool(_f.get("privacy_enforce")),
                                  ip_drop=bool(_f.get("privacy_ip_drop")))
        if _n:
            summary["actions"].append(f"pure-tracker-ip drop x{_n}")
    except Exception as e:
        log.warning("pure_tracker_ip_drop step failed: %s", e)

    from . import social as _social
    from . import device_blocks as _devblk

    win = policy["window_hours"]
    agg = _social.aggregate(hours=win)

    # ── operator-grade / state-adjacent hosts ──
    if policy["opgrade_enabled"]:
        for row in agg.get("by_opgrade", []):
            vendor = row.get("opgrade_vendor", "?")
            clients = int(row.get("clients", 0) or 0)
            events = int(row.get("events", 0) or 0)
            if clients < policy["opgrade_min_clients"] or events < policy["opgrade_min_events"]:
                continue
            # The aggregate is keyed by vendor, not host — escalate the
            # vendor's known host fragments by resolving them. We use the
            # social_opgrade src sites? No — opgrade is host-stable in
            # social_host_meta. Resolve the vendor's representative hosts.
            # Conservative: skip if we can't map a concrete host.
            host = _OPGRADE_VENDOR_HOST.get(vendor)
            if not host:
                continue
            ips = _resolve_ips(host)
            added = 0
            for ip in ips:
                if _nft_add_blacklist(ip):
                    added += 1
            if added:
                summary["opgrade_escalated"] += 1
                summary["ips_added"] += added
                summary["actions"].append(f"opgrade {vendor} -> +{added} ip ({host})")
                _audit(f"ESCALATE opgrade vendor={vendor} host={host} clients={clients} events={events} ips=+{added} ttl={ESCALATE_TTL}")

    # ── anti-bot endpoints (opt-in ; many are legit infra) ──
    if policy["antibot_enabled"]:
        for row in agg.get("by_antibot", []):
            vendor = row.get("antibot_vendor", "?")
            challenges = int(row.get("challenges", 0) or 0)
            if challenges < policy["antibot_min_challenges"]:
                continue
            summary["antibot_escalated"] += 1
            summary["actions"].append(f"antibot {vendor} flagged ({challenges})")
            _audit(f"FLAG antibot vendor={vendor} challenges={challenges} (no auto-ban — review)")

    # ── per-device DoH / bypass over threshold → quarantine ──
    if policy["device_doh_enabled"]:
        dev = _devblk.aggregate(hours=win)
        for d in dev.get("by_device", []):
            doh = int(d.get("doh", 0) or 0)
            ip = d.get("ip", "")
            if doh < policy["device_doh_threshold"] or not ip or ip == "unknown":
                continue
            if ip.startswith("ip:"):
                ip = ip[3:]
            if _nft_quarantine(ip):
                summary["devices_quarantined"] += 1
                summary["actions"].append(f"quarantine device {ip} (doh={doh})")
                _audit(f"QUARANTINE device ip={ip} doh_attempts={doh} ttl={ESCALATE_TTL}")

    return summary


# Representative resolvable host per operator-grade vendor (data-broker
# surfaces). Telco header-enrichment + consortium IDs aren't host-pinnable
# this way, so they're skipped (flagged only). Conservative on purpose.
_OPGRADE_VENDOR_HOST = {
    "LiveRamp": "rlcdn.com",
    "Oracle-BlueKai": "bluekai.com",
    "Acxiom": "acxiom.com",
    "Neustar": "agkn.com",
    "Tapad": "tapad.com",
    "Experian": "experian.com",
}
