# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Security Posture — CSPN compliance backbone
CyberMind — https://cybermind.fr

ANSSI CSPN requirement matrix with REAL, repaired checks. Two design fixes over
v1: (1) each requirement owns its check coroutine and results are gathered into
a {req_id: result} dict — no positional ``zip`` misalignment; (2) requirements
with no automatable signal are reported MANUAL (documented), never faked.

The pure parsers (tls_min_ok / audit_timestamps_ok / nft_has_drop_policy /
count_exposed_ports) are unit-tested in tests/test_cspn_parse.py.
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import List, Optional

from . import sources

HAPROXY_CFG = "/etc/haproxy/haproxy.cfg"
AUDIT_LOG = "/var/log/secubox/audit.log"

# Status strings for CSPN entries (distinct from the posture Status enum).
PASS, FAIL, MANUAL, UNKNOWN = "pass", "fail", "manual", "unknown"

_ISO = re.compile(r"^\s*\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")


# ---- pure parsers (unit-tested) -------------------------------------------

def tls_min_ok(haproxy_cfg: str) -> Optional[bool]:
    """True if HAProxy disables TLS 1.0/1.1. None if no ssl-default-bind-options."""
    for line in haproxy_cfg.splitlines():
        if "ssl-default-bind-options" in line:
            return ("no-tlsv10" in line) and ("no-tlsv11" in line)
    return None


def audit_timestamps_ok(lines: List[str]) -> Optional[bool]:
    """True if every non-empty sample line starts with an RFC 3339 timestamp."""
    samples = [ln for ln in lines if ln.strip()]
    if not samples:
        return None
    return all(_ISO.match(ln) for ln in samples)


def nft_has_drop_policy(nft_output: str) -> bool:
    """True if an input/forward chain declares 'policy drop'."""
    return bool(re.search(r"policy\s+drop", nft_output))


def count_exposed_ports(ss_output: str) -> int:
    """Count listening sockets bound to a wildcard (externally reachable) address.

    Only the Local Address:Port column counts — it is the second-to-last token
    on an `ss -tln` LISTEN row (the last token is the Peer Address, which is
    itself a wildcard and must not be counted).
    """
    count = 0
    for line in ss_output.splitlines():
        toks = line.split()
        if "LISTEN" not in line or len(toks) < 2:
            continue
        local = toks[-2]
        if local.startswith("0.0.0.0:") or local.startswith("*:") or local.startswith("[::]:"):
            count += 1
    return count


# ---- requirement matrix ----------------------------------------------------

# id -> (title, category, automatable). Automatable=False → MANUAL.
REQUIREMENTS = [
    ("CRY-01", "TLS 1.2+ enforced (no SSLv3/TLS1.0/1.1)", "cryptography", True),
    ("CRY-04", "Private key files restricted (≤0600)", "cryptography", True),
    ("ACL-01", "Services run as non-root dedicated users", "access", True),
    ("ACL-02", "AppArmor profiles enforced", "access", True),
    ("NET-01", "nftables default-drop policy", "network", True),
    ("NET-02", "Minimal externally-exposed port surface", "network", True),
    ("LOG-01", "Security audit log present & fresh", "logging", True),
    ("LOG-02", "Audit log RFC 3339 timestamps", "logging", True),
    ("CRY-02", "Strong cipher suites configured", "cryptography", False),
    ("AUT-01", "JWT enforced on privileged endpoints", "authentication", False),
    ("DAT-01", "Config double-buffer / 4R rollback", "data", False),
]


async def _check_cry01() -> dict:
    try:
        cfg = Path(HAPROXY_CFG).read_text()
    except Exception:
        return {"status": UNKNOWN, "detail": "haproxy.cfg not readable"}
    res = tls_min_ok(cfg)
    if res is None:
        return {"status": UNKNOWN, "detail": "no ssl-default-bind-options directive"}
    return {"status": PASS if res else FAIL,
            "detail": "TLS 1.0/1.1 disabled" if res else "TLS 1.0/1.1 still allowed",
            "remediation": "Add 'ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11' to haproxy.cfg"}


async def _check_cry04() -> dict:
    bad = []
    checked = 0
    for base in ("/etc/secubox/secrets", "/etc/letsencrypt/live"):
        p = Path(base)
        if not p.exists():
            continue
        try:
            for key in list(p.rglob("*.key")) + list(p.rglob("privkey*.pem")):
                checked += 1
                mode = key.stat().st_mode & 0o077
                if mode:
                    bad.append(str(key))
        except Exception:
            return {"status": UNKNOWN, "detail": f"{base} not traversable"}
    if checked == 0:
        return {"status": UNKNOWN, "detail": "no key files visible to inspect"}
    return {"status": PASS if not bad else FAIL,
            "detail": f"{checked} key file(s) checked, {len(bad)} too permissive",
            "remediation": "chmod 600 on private keys"}


async def _check_acl01() -> dict:
    # Unprivileged: list processes and confirm secubox daemons aren't root.
    out = await _run("ps -eo user,comm")
    if out is None:
        return {"status": UNKNOWN, "detail": "ps unavailable"}
    root_secubox = [ln for ln in out.splitlines()
                    if ln.split() and ln.split()[0] == "root" and "secubox" in ln]
    return {"status": PASS if not root_secubox else FAIL,
            "detail": "no secubox daemon running as root" if not root_secubox
            else f"{len(root_secubox)} secubox proc(s) as root",
            "remediation": "Run each daemon under its dedicated secubox-<module> user"}


async def _check_acl02() -> dict:
    ok, sec = await sources.socket_get("system", "/security")
    if not ok or not isinstance(sec, dict) or not sec.get("apparmor"):
        return {"status": UNKNOWN, "detail": "apparmor status unavailable"}
    aa = str(sec["apparmor"]).lower()
    good = "enforc" in aa or aa in ("ok", "active", "enabled")
    return {"status": PASS if good else FAIL, "detail": f"AppArmor: {sec['apparmor']}",
            "remediation": "aa-enforce SecuBox profiles"}


async def _check_net01() -> dict:
    out = await _run("nft list ruleset")  # unprivileged may fail → UNKNOWN
    if out is None:
        return {"status": UNKNOWN, "detail": "nft ruleset not readable"}
    ok_drop = nft_has_drop_policy(out)
    return {"status": PASS if ok_drop else FAIL,
            "detail": "default-drop policy present" if ok_drop else "no default-drop policy",
            "remediation": "Set 'policy drop' on input/forward chains"}


async def _check_net02() -> dict:
    out = await _run("ss -tln")
    if out is None:
        return {"status": UNKNOWN, "detail": "ss unavailable"}
    n = count_exposed_ports(out)
    # Posture heuristic: a hardened appliance keeps the wildcard surface small.
    status = PASS if n <= 8 else FAIL
    return {"status": status, "detail": f"{n} wildcard-exposed listening ports",
            "remediation": "Bind internal services to 127.0.0.1; close unused ports"}


async def _check_log01() -> dict:
    try:
        st = Path(AUDIT_LOG).stat()
    except Exception:
        return {"status": FAIL, "detail": "audit.log missing",
                "remediation": "Ensure /var/log/secubox/audit.log is created and written"}
    age_h = (time.time() - st.st_mtime) / 3600.0
    return {"status": PASS if age_h < 72 else FAIL,
            "detail": f"audit.log last write {age_h:.1f}h ago",
            "remediation": "Verify audit logging pipeline is active"}


async def _check_log02() -> dict:
    try:
        lines = Path(AUDIT_LOG).read_text(errors="ignore").splitlines()[-10:]
    except Exception:
        return {"status": UNKNOWN, "detail": "audit.log not readable"}
    res = audit_timestamps_ok(lines)
    if res is None:
        return {"status": UNKNOWN, "detail": "audit.log empty"}
    return {"status": PASS if res else FAIL,
            "detail": "RFC 3339 timestamps" if res else "non-RFC3339 timestamps",
            "remediation": "Emit RFC 3339 timestamps in the audit log"}


_CHECKS = {
    "CRY-01": _check_cry01, "CRY-04": _check_cry04, "ACL-01": _check_acl01,
    "ACL-02": _check_acl02, "NET-01": _check_net01, "NET-02": _check_net02,
    "LOG-01": _check_log01, "LOG-02": _check_log02,
}


async def _run(cmd: str, timeout: float = 4.0) -> Optional[str]:
    """Run an unprivileged shell command; None on failure/timeout/non-zero."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        if proc.returncode != 0:
            return None
        return out.decode(errors="ignore")
    except Exception:
        return None


async def run_report() -> dict:
    """Run all CSPN checks. Returns a structured, honest compliance report."""
    coros = {rid: _CHECKS[rid]() for rid in _CHECKS}
    results = await asyncio.gather(*coros.values(), return_exceptions=True)
    by_id = {}
    for rid, res in zip(coros.keys(), results):  # keys/values share order — safe
        by_id[rid] = res if isinstance(res, dict) else {"status": UNKNOWN, "detail": "check error"}

    items: List[dict] = []
    for rid, title, category, automatable in REQUIREMENTS:
        if not automatable:
            items.append({"id": rid, "title": title, "category": category,
                          "status": MANUAL, "detail": "human-judged / not auto-verifiable"})
            continue
        r = by_id.get(rid, {"status": UNKNOWN, "detail": "not run"})
        items.append({"id": rid, "title": title, "category": category, **r})

    scored = [i for i in items if i["status"] in (PASS, FAIL)]
    passed = sum(1 for i in scored if i["status"] == PASS)
    total_scored = len(scored)
    score = round(100 * passed / total_scored, 1) if total_scored else None
    return {
        "score": score,
        "passed": passed,
        "scored": total_scored,
        "manual": sum(1 for i in items if i["status"] == MANUAL),
        "unknown": sum(1 for i in items if i["status"] == UNKNOWN),
        "total": len(items),
        "items": items,
    }
