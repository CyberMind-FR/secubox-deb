# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Reality — target sanity validation (MIND stage)
CyberMind — https://cybermind.fr

A Reality ``dest``/SNI camouflage target must itself be a real TLS 1.3 +
X25519 site — otherwise the "reality" of the handshake collapses and the
egress point is trivially fingerprintable. ``validate_target`` shells out to
``openssl s_client`` to probe this before ``router.py``'s ``/apply`` endpoint
is allowed to provision anything against it (unless the caller forces it).
"""
from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, List

OPENSSL_BIN = "openssl"
_PROBE_TIMEOUT = 12

# OpenSSL has printed the negotiated protocol in at least two output shapes
# across versions/configs: the classic "SSL-Session:" dump ("Protocol  :
# TLSv1.3") and the terser one-line handshake summary OpenSSL 3.x prints by
# default ("New, TLSv1.3, Cipher is ..."). Match either defensively.
_TLS13_RE = re.compile(r"(?:Protocol\s*:\s*TLSv1\.3|New,\s*TLSv1\.3\s*,)", re.IGNORECASE)
_X25519_TEMP_KEY_RE = re.compile(r"Server Temp Key:\s*X25519", re.IGNORECASE)
_ALPN_RE = re.compile(r"ALPN protocol:\s*(\S+)", re.IGNORECASE)


class ValidatorError(RuntimeError):
    """Raised only on hard failures to invoke openssl itself."""


def _run_probe(host: str, port: int, timeout: int = _PROBE_TIMEOUT) -> Dict[str, Any]:
    """Run one openssl s_client TLS1.3/X25519 probe against host:port.

    Never raises for network-level failures (refused, timeout, TLS alert) —
    those are reported as ``reachable=False`` in the returned dict. Only a
    missing/broken openssl binary raises ``ValidatorError``.
    """
    cmd = [
        OPENSSL_BIN,
        "s_client",
        "-tls1_3",
        "-groups",
        "X25519",
        "-alpn",
        "h2,http/1.1",
        "-servername",
        host,
        "-connect",
        f"{host}:{port}",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ValidatorError(f"openssl binary not found: {OPENSSL_BIN}") from exc
    except subprocess.TimeoutExpired:
        return {"reachable": False, "raw": "", "reason": "timeout"}

    output = f"{proc.stdout}\n{proc.stderr}"
    # A non-zero exit paired with a BIO/connect error means the TCP/TLS
    # handshake itself never happened (refused, no route, reset) — that is
    # a reachability failure, distinct from "connected but not TLS1.3".
    connect_failed = proc.returncode != 0 and re.search(
        r"connect:errno|BIO_connect|Connection refused|Connection timed out|"
        r"No route to host|Name or service not known",
        output,
        re.IGNORECASE,
    )
    if connect_failed:
        return {"reachable": False, "raw": output, "reason": "connection failed"}

    return {"reachable": True, "raw": output, "returncode": proc.returncode}


def validate_target(host: str, port: int = 443) -> Dict[str, Any]:
    """Probe ``host:port`` and report TLS1.3 / X25519 / ALPN / reachability.

    Returns a dict with keys: ``ok``, ``reachable``, ``tls13``, ``x25519``,
    ``alpn`` (list[str]), ``reason`` (set when ``ok`` is False).
    """
    probe = _run_probe(host, port)
    if not probe["reachable"]:
        return {
            "ok": False,
            "reachable": False,
            "tls13": False,
            "x25519": False,
            "alpn": [],
            "reason": probe.get("reason", "unreachable"),
        }

    raw = probe["raw"]
    tls13 = bool(_TLS13_RE.search(raw))
    x25519 = bool(_X25519_TEMP_KEY_RE.search(raw))
    alpn: List[str] = sorted(set(_ALPN_RE.findall(raw)))

    ok = tls13 and x25519
    result: Dict[str, Any] = {
        "ok": ok,
        "reachable": True,
        "tls13": tls13,
        "x25519": x25519,
        "alpn": alpn,
    }
    if not ok:
        missing = []
        if not tls13:
            missing.append("TLS1.3")
        if not x25519:
            missing.append("X25519 temp key")
        result["reason"] = f"target does not offer {', '.join(missing)}"
    return result


# --- MIND: apply gate ---------------------------------------------------


def refuse_apply_if_insane(validation: Dict[str, Any], force: bool = False) -> None:
    """Raise ``ValueError`` if ``validation`` says the target is not sane,
    unless ``force`` is set (operator override, still logged by the caller).
    """
    if force:
        return
    if not validation.get("ok"):
        raise ValueError(
            "Reality dest/SNI failed sanity validation: "
            f"{validation.get('reason', 'unknown reason')} "
            "(pass force=true to override)"
        )
