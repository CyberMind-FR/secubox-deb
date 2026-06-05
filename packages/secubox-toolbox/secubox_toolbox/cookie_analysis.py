# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Cookie analysis : identify trackers + providers + categorize.

Phase 2a+ heuristic: pattern matching sur les noms de cookies bien connus,
mapping vers fournisseur + catégorie (analytics / advertising / social / etc.).

Database extensible — pour Phase 3 on chargera depuis cookiepedia ou EasyList.
"""
from __future__ import annotations

import re

# Pattern → (provider, category, emoji)
COOKIE_PATTERNS = [
    # ── Analytics ──
    (re.compile(r"^_ga(_|$|t)"),         "Google Analytics",       "analytics",  "📊"),
    (re.compile(r"^_gid$"),              "Google Analytics",       "analytics",  "📊"),
    (re.compile(r"^_gat"),               "Google Analytics",       "analytics",  "📊"),
    (re.compile(r"^_gcl_au$"),           "Google Ads conversion",  "advertising", "💰"),
    (re.compile(r"^_pk_(id|ses|cvar)"),  "Matomo / Piwik",         "analytics",  "📊"),
    (re.compile(r"^plausible_"),         "Plausible",              "analytics",  "📊"),
    (re.compile(r"^_mkto_trk$"),         "Marketo",                "analytics",  "📊"),
    (re.compile(r"^__hssc$|^__hstc$"),   "HubSpot",                "analytics",  "📊"),
    (re.compile(r"^mp_[a-z0-9]+_mixpanel"), "Mixpanel",            "analytics",  "📊"),
    (re.compile(r"^amplitude_"),         "Amplitude",              "analytics",  "📊"),
    (re.compile(r"^optimizelyEndUserId$"), "Optimizely",           "analytics",  "📊"),
    (re.compile(r"^_hjSession"),         "Hotjar",                 "analytics",  "📊"),
    (re.compile(r"^_hjFirstSeen$"),      "Hotjar",                 "analytics",  "📊"),
    (re.compile(r"^crisp-client/session/"), "Crisp Chat",          "analytics",  "💬"),
    # ── Advertising / Tracking ──
    (re.compile(r"^_fbp$|^fr$"),         "Facebook Pixel",         "advertising","🎯"),
    (re.compile(r"^IDE$"),               "Google DoubleClick",     "advertising","🎯"),
    (re.compile(r"^NID$"),               "Google",                 "advertising","🎯"),
    (re.compile(r"^DSID$"),              "Google DoubleClick",     "advertising","🎯"),
    (re.compile(r"^uid$|^bcookie$|^lidc$"), "LinkedIn Insight",    "advertising","💼"),
    (re.compile(r"^MUID$|^_uetsid$|^_uetvid$"), "Microsoft Clarity / Bing Ads", "advertising", "🎯"),
    (re.compile(r"^_pin_unauth$|^_pinterest_ct_"),  "Pinterest",   "advertising","📌"),
    (re.compile(r"^tt_appInfo$|^tt_webid"),  "TikTok",             "advertising","🎵"),
    (re.compile(r"^_ttp$"),              "TikTok Pixel",           "advertising","🎵"),
    (re.compile(r"^ANID$"),              "Google",                 "advertising","🎯"),
    (re.compile(r"^__qca$"),             "Quantcast",              "advertising","🎯"),
    (re.compile(r"^__gads$|^__gpi$"),    "Google AdSense",         "advertising","💰"),
    (re.compile(r"^test_cookie$"),       "Google",                 "advertising","🎯"),
    # ── Social ──
    (re.compile(r"^c_user$|^xs$|^datr$"), "Facebook",              "social",     "👥"),
    (re.compile(r"^sb$|^locale$|^wd$"),  "Facebook",               "social",     "👥"),
    (re.compile(r"^twid$|^ct0$|^auth_token$"), "Twitter / X",      "social",     "👥"),
    (re.compile(r"^li_at$"),             "LinkedIn",               "social",     "👥"),
    (re.compile(r"^IG_"),                "Instagram",              "social",     "👥"),
    # ── Auth / Session (legit, no tracker) ──
    (re.compile(r"^session(_id)?$|^sessionid$"), "Session generic", "session",   "🔑"),
    (re.compile(r"^csrftoken$|^_csrf$"), "CSRF token",             "session",    "🔒"),
    (re.compile(r"^XSRF-TOKEN$"),        "XSRF token",             "session",    "🔒"),
    (re.compile(r"^remember_token$"),    "Remember-me",            "session",    "🔑"),
    (re.compile(r"^PHPSESSID$"),         "PHP session",            "session",    "🔑"),
    (re.compile(r"^JSESSIONID$"),        "Java session",           "session",    "🔑"),
    (re.compile(r"^connect\.sid$"),      "Express.js session",     "session",    "🔑"),
    # ── CDN / infra ──
    (re.compile(r"^__cf_bm$|^cf_clearance$"), "Cloudflare",        "infra",      "☁"),
    (re.compile(r"^_dd_s$"),             "Datadog RUM",            "monitoring", "📈"),
]


def classify_cookie_name(name: str) -> dict:
    """Returns {provider, category, emoji} for a single cookie name.
    Unknown → {provider: 'unknown', category: 'other', emoji: '❔'}."""
    for pattern, provider, category, emoji in COOKIE_PATTERNS:
        if pattern.search(name):
            return {"provider": provider, "category": category, "emoji": emoji}
    return {"provider": "unknown", "category": "other", "emoji": "❔"}


def parse_cookie_header(header_value: str) -> list[str]:
    """Parse 'Cookie:' or 'Set-Cookie:' value, return list of cookie NAMES."""
    if not header_value:
        return []
    names = []
    for part in header_value.split(";"):
        if "=" in part:
            n = part.split("=", 1)[0].strip()
            if n:
                names.append(n)
    return names


def analyze_cookie_events(cookie_events: list[dict]) -> dict:
    """Aggregate cookie events into stats + per-provider breakdown.

    Input : list of {url, set_cookie_count, cookie_count, ...} from local_store
    (note : Phase 1.5 stored only counts, not names. Phase 2a+ local_store
    should store names. Until then, this function works on whatever's present.)

    Returns :
      {
        providers: {provider: {count, category, emoji}, ...},
        categories: {category: count, ...},
        unknown_count: int,
      }
    """
    providers: dict[str, dict] = {}
    categories: dict[str, int] = {}
    unknown_count = 0

    for ev in cookie_events:
        # The cookie name might be in `set_cookie_names` or `cookie_names` if Phase 2a+
        # local_store. Backward-compat : skip if absent.
        for key in ("set_cookie_names", "cookie_names"):
            names = ev.get(key, [])
            if not isinstance(names, list):
                continue
            for n in names:
                cls = classify_cookie_name(n)
                p = cls["provider"]
                if p == "unknown":
                    unknown_count += 1
                else:
                    if p not in providers:
                        providers[p] = {"count": 0, "category": cls["category"],
                                        "emoji": cls["emoji"]}
                    providers[p]["count"] += 1
                cat = cls["category"]
                categories[cat] = categories.get(cat, 0) + 1

    return {
        "providers": providers,
        "categories": categories,
        "unknown_count": unknown_count,
    }


# Quick lookup for live use in /report endpoints
def top_providers(cookie_events: list[dict], limit: int = 10) -> list[dict]:
    """Returns top providers by hit count : [{provider, count, category, emoji}, ...]"""
    stats = analyze_cookie_events(cookie_events)
    return sorted(
        [{"provider": p, **v} for p, v in stats["providers"].items()],
        key=lambda x: -x["count"],
    )[:limit]
