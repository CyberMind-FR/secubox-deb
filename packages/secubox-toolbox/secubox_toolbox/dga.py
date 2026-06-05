# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""DGA (Domain Generation Algorithm) detection — heuristic.

Simple, low-false-positive heuristic adapté à un device user :
- Shannon entropy of the subdomain (high entropy = random-ish chars)
- Length of randomly-generated subdomain (> 20 chars suspicious)
- Vowel/consonant ratio (very low = random)
- Digit ratio (very high = random)
- Common-LD allowlist exception (skip well-known TLDs/SLDs)

Returns a score (0-100) + indicators list (human-readable reasons).
"""
from __future__ import annotations

import math
from collections import Counter

# Allowlist : domains we always trust (TLD or 2LD). Reduces noise on legit CDN.
ALLOWLIST_2LD = {
    "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "akamaized.net",
    "amazonaws.com", "cloudfront.net", "cloudflare.com", "cloudflare.net",
    "fastly.net", "fastlylb.net", "azureedge.net", "azurefd.net",
    "windowsupdate.com", "microsoft.com", "office.com", "office365.com",
    "google.com", "googleusercontent.com", "googleapis.com", "gstatic.com",
    "apple.com", "icloud.com", "icloud-content.com", "itunes.apple.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "twitter.com", "twimg.com", "tiktokv.com", "tiktokcdn.com",
    "1e100.net",  # Google global infra
}

VOWELS = set("aeiouy")
CONSONANTS = set("bcdfghjklmnpqrstvwxz")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt = Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def _check_allowlist(host: str) -> bool:
    h = host.lower()
    for d in ALLOWLIST_2LD:
        if h == d or h.endswith("." + d):
            return True
    return False


def dga_score(host: str) -> tuple[int, list[str]]:
    """Return (score 0-100, list of human-readable reasons).
    Phase 2a heuristic — Phase 3 will add ML classifier."""
    if not host or "." not in host:
        return (0, [])
    if _check_allowlist(host):
        return (0, ["allowlist_match"])

    indicators: list[str] = []
    score = 0
    parts = host.lower().split(".")
    # The "interesting" subdomain part = everything before the public suffix.
    # Heuristic : take the leftmost label of length > 4 (skip "www", "api" etc).
    candidate = next((p for p in parts[:-2] if len(p) > 4), "")
    if not candidate:
        return (0, [])

    # 1. Shannon entropy
    ent = shannon_entropy(candidate)
    if ent > 3.8:
        score += 35
        indicators.append(f"high_entropy({ent:.2f})")
    elif ent > 3.3:
        score += 15
        indicators.append(f"medium_entropy({ent:.2f})")

    # 2. Subdomain length
    if len(candidate) > 25:
        score += 25
        indicators.append(f"long_subdomain({len(candidate)})")
    elif len(candidate) > 20:
        score += 15
        indicators.append(f"long_subdomain({len(candidate)})")

    # 3. Vowel ratio (very low = random)
    letters = [c for c in candidate if c.isalpha()]
    if letters:
        vow_ratio = sum(1 for c in letters if c in VOWELS) / len(letters)
        if vow_ratio < 0.15:
            score += 20
            indicators.append(f"low_vowel_ratio({vow_ratio:.2f})")
        elif vow_ratio < 0.25:
            score += 10
            indicators.append(f"low_vowel_ratio({vow_ratio:.2f})")

    # 4. Digit ratio
    digit_ratio = sum(1 for c in candidate if c.isdigit()) / len(candidate)
    if digit_ratio > 0.5:
        score += 20
        indicators.append(f"high_digit_ratio({digit_ratio:.2f})")
    elif digit_ratio > 0.35:
        score += 10
        indicators.append(f"high_digit_ratio({digit_ratio:.2f})")

    return (min(score, 100), indicators)


def analyze_hosts(hosts: list[str]) -> list[dict]:
    """Run dga_score on a list of hosts, return only suspicious ones (score >= 30)."""
    out = []
    for h in hosts:
        score, indicators = dga_score(h)
        if score >= 30:
            out.append({"host": h, "score": score, "indicators": indicators})
    return sorted(out, key=lambda x: -x["score"])
