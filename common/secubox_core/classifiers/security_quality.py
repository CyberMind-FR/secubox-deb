# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Security quality scorer (#492) : grade a destination on observable signals.

Two modes :
  - PASSIVE  : TLS version + JA4 + SNI presence + ALPN (no decryption needed)
  - ACTIVE   : adds HTTPS headers (HSTS, CSP) + cookies attrs (Secure/HttpOnly/SameSite)

Output : A+/A/B/C/D/F grade + per-criterion breakdown.

Phase 4 will add live cert chain analysis + CT log lookup + HSTS preload check.
"""
from __future__ import annotations


# Cipher categories — TLS 1.3 only uses AEAD ciphers (good). TLS 1.2 mix.
_WEAK_CIPHERS = {
    # CBC mode = vulnerable to padding oracle attacks
    "RSA_WITH_AES_128_CBC", "RSA_WITH_AES_256_CBC",
    "RSA_WITH_3DES_EDE_CBC",
    # RC4 deprecated
    "RSA_WITH_RC4_128",
    # Export-grade — should never see in 2025+
    "RSA_EXPORT",
}


def _grade_to_score(grade: str) -> int:
    return {"A+": 100, "A": 90, "B": 75, "C": 60, "D": 40, "F": 0}.get(grade, 50)


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def grade_passive(
    *,
    tls_version: str | None = None,
    alpn_protocols: list | None = None,
    sni: str | None = None,
    ja4_known_client: bool = False,
    is_e2e_messaging: bool = False,
) -> dict:
    """Grade a flow we can only observe transport-side (whitelisted/pinned/E2E)."""
    score = 50
    reasons: list[dict] = []

    # TLS version
    if tls_version in ("13", "1.3", "TLSv1.3"):
        score += 30
        reasons.append({"+": 30, "why": "TLS 1.3 (modern AEAD ciphers, no downgrade)"})
    elif tls_version in ("12", "1.2", "TLSv1.2"):
        score += 15
        reasons.append({"+": 15, "why": "TLS 1.2 (acceptable but legacy)"})
    elif tls_version in ("11", "1.1", "TLSv1.1", "10", "1.0", "TLSv1.0"):
        score -= 30
        reasons.append({"-": 30, "why": "TLS legacy (deprecated, vulnerable)"})
    elif tls_version is None:
        score += 5
        reasons.append({"~": 0, "why": "TLS version unknown (HTTP or pre-handshake)"})

    # ALPN
    if alpn_protocols:
        if "h3" in alpn_protocols or "h3-29" in alpn_protocols:
            score += 10
            reasons.append({"+": 10, "why": "HTTP/3 (QUIC, modern transport)"})
        elif "h2" in alpn_protocols:
            score += 5
            reasons.append({"+": 5, "why": "HTTP/2"})

    # SNI present (encrypted SNI / ECH not yet detectable here)
    if sni:
        score += 5
        reasons.append({"+": 5, "why": "SNI present (standard practice)"})

    # JA4 known-good
    if ja4_known_client:
        score += 10
        reasons.append({"+": 10, "why": "JA4 fingerprint matches known-good client"})

    # E2E bonus (Signal/Threema/etc. — even though opaque, the design is strong)
    if is_e2e_messaging:
        score += 5
        reasons.append({"+": 5, "why": "E2E messaging design (Signal protocol or similar)"})

    score = max(0, min(100, score))
    return {
        "grade": _score_to_grade(score),
        "score": score,
        "mode": "passive",
        "reasons": reasons,
    }


def grade_active(
    *,
    tls_version: str | None = None,
    alpn_protocols: list | None = None,
    sni: str | None = None,
    headers: dict | None = None,
    cookies_attrs: list[dict] | None = None,
    mixed_content_detected: bool = False,
) -> dict:
    """Grade a flow we fully inspected via MITM."""
    base = grade_passive(tls_version=tls_version, alpn_protocols=alpn_protocols, sni=sni)
    score = base["score"]
    reasons = list(base["reasons"])
    headers = {k.lower(): v for k, v in (headers or {}).items()}

    # HSTS
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "max-age=31536000" in hsts or "max-age=63072000" in hsts:
            score += 10
            reasons.append({"+": 10, "why": "HSTS strong (1y+)"})
            if "preload" in hsts.lower():
                score += 5
                reasons.append({"+": 5, "why": "HSTS preload eligible"})
        else:
            score += 3
            reasons.append({"+": 3, "why": "HSTS present but weak max-age"})
    else:
        score -= 10
        reasons.append({"-": 10, "why": "HSTS missing (downgrade attack possible)"})

    # CSP
    csp = headers.get("content-security-policy", "")
    if csp:
        if "default-src 'none'" in csp or "default-src 'self'" in csp:
            score += 8
            reasons.append({"+": 8, "why": "CSP strict"})
        elif "unsafe-inline" not in csp and "unsafe-eval" not in csp:
            score += 4
            reasons.append({"+": 4, "why": "CSP present (moderate)"})
    else:
        score -= 5
        reasons.append({"-": 5, "why": "CSP missing"})

    # X-Frame-Options / X-Content-Type-Options (basic hardening)
    if "x-content-type-options" in headers:
        score += 2
        reasons.append({"+": 2, "why": "X-Content-Type-Options: nosniff"})

    # Cookies
    if cookies_attrs:
        weak_cookies = 0
        strong_cookies = 0
        for c in cookies_attrs:
            if c.get("secure") and c.get("httponly") and c.get("samesite") in ("strict", "lax"):
                strong_cookies += 1
            else:
                weak_cookies += 1
        if strong_cookies and not weak_cookies:
            score += 5
            reasons.append({"+": 5, "why": f"All {strong_cookies} cookies have Secure+HttpOnly+SameSite"})
        elif weak_cookies:
            score -= 5
            reasons.append({"-": 5, "why": f"{weak_cookies} cookies missing Secure/HttpOnly/SameSite"})

    # Mixed content = critical demerit
    if mixed_content_detected:
        score -= 20
        reasons.append({"-": 20, "why": "Mixed HTTP+HTTPS content (man-in-the-middle window)"})

    score = max(0, min(100, score))
    return {
        "grade": _score_to_grade(score),
        "score": score,
        "mode": "active",
        "reasons": reasons,
    }


def aggregate_per_host(events: list[dict]) -> dict:
    """Compute per-host quality aggregate from a list of mitm events.

    Each event payload should optionally have :
      - tls_version, alpn_protocols, sni (from JA4 / handshake)
      - headers, set_cookie_attrs (from MITM-inspected response)
      - analysis_status ('inspected' | 'bypassed-*' | 'pinned-*' | 'e2e-opaque')

    Returns {host: {grade, score, mode, samples_count, last_seen_ms}}.
    """
    by_host: dict[str, dict] = {}
    for ev in events:
        payload = ev.get("payload") or ev
        host = payload.get("host") or payload.get("sni") or "?"
        if host == "?" or not host:
            continue
        if host in by_host:
            by_host[host]["samples_count"] += 1
            by_host[host]["last_seen_ms"] = max(
                by_host[host]["last_seen_ms"], payload.get("ts_ms", 0)
            )
            continue
        analysis_status = payload.get("analysis_status", "")
        if analysis_status.startswith("bypassed") or analysis_status.startswith("pinned"):
            g = grade_passive(
                tls_version=payload.get("tls_version"),
                alpn_protocols=payload.get("alpn_protocols"),
                sni=payload.get("sni"),
                ja4_known_client=bool(payload.get("ja4_known_client")),
            )
        elif analysis_status == "e2e-opaque":
            g = grade_passive(
                tls_version=payload.get("tls_version") or "13",
                sni=payload.get("sni"),
                is_e2e_messaging=True,
            )
        else:
            g = grade_active(
                tls_version=payload.get("tls_version"),
                alpn_protocols=payload.get("alpn_protocols"),
                sni=payload.get("sni"),
                headers=payload.get("response_headers"),
                cookies_attrs=payload.get("set_cookie_attrs"),
                mixed_content_detected=bool(payload.get("mixed_content")),
            )
        by_host[host] = {
            **g,
            "host": host,
            "samples_count": 1,
            "last_seen_ms": payload.get("ts_ms", 0),
            "analysis_status": analysis_status or "inspected",
        }
    return by_host
