# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""DPI / app classification : host → app category + emoji.

Strategy : pure-Python heuristic + (optional, Phase 2b) query to secubox-dpi
unix socket for nDPI/netifyd results.

Phase 2a+ : heuristic database below — extensible.
"""
from __future__ import annotations

import re

# (pattern, category, app_name, emoji)
APP_PATTERNS = [
    # ── Streaming video ──
    (re.compile(r"(^|\.)youtube\.com$|googlevideo\.com$|ytimg\.com$"), "streaming", "YouTube", "📺"),
    (re.compile(r"(^|\.)netflix\.com$|nflxvideo\.net$|nflximg\.net$"), "streaming", "Netflix", "🎬"),
    (re.compile(r"(^|\.)spotify\.com$|spotifycdn\.com$|scdn\.co$"),    "streaming", "Spotify", "🎵"),
    (re.compile(r"(^|\.)twitch\.tv$|jtvnw\.net$"),                     "streaming", "Twitch", "📺"),
    (re.compile(r"(^|\.)peertube\."),                                  "streaming", "PeerTube", "📺"),
    (re.compile(r"(^|\.)tiktokv?\.com$|tiktokcdn\.com$"),              "streaming", "TikTok", "🎵"),
    (re.compile(r"(^|\.)disneyplus\.com$|dssott\.com$"),               "streaming", "Disney+", "🎬"),
    (re.compile(r"(^|\.)deezer\.com$|dzcdn\.net$"),                    "streaming", "Deezer", "🎵"),
    # ── Social ──
    (re.compile(r"(^|\.)facebook\.com$|fbcdn\.net$|messenger\.com$"),  "social", "Facebook", "👥"),
    (re.compile(r"(^|\.)instagram\.com$|cdninstagram\.com$"),          "social", "Instagram", "📷"),
    (re.compile(r"(^|\.)twitter\.com$|x\.com$|twimg\.com$"),           "social", "X / Twitter", "🐦"),
    (re.compile(r"(^|\.)reddit\.com$|redd\.it$|redditmedia\.com$"),    "social", "Reddit", "👾"),
    (re.compile(r"(^|\.)linkedin\.com$|licdn\.com$"),                  "social", "LinkedIn", "💼"),
    (re.compile(r"(^|\.)pinterest\.com$|pinimg\.com$"),                "social", "Pinterest", "📌"),
    (re.compile(r"(^|\.)mastodon\.social$|fediverse\.|piaille\."),     "social", "Mastodon", "🐘"),
    (re.compile(r"(^|\.)bsky\.social$|bsky\.app$"),                    "social", "Bluesky", "🦋"),
    # ── Messaging E2E ──
    (re.compile(r"(^|\.)signal\.org$|whispersystems\.org$"),           "messaging-e2e", "Signal", "🔒"),
    (re.compile(r"(^|\.)whatsapp\.com$|whatsapp\.net$"),               "messaging", "WhatsApp", "💬"),
    (re.compile(r"(^|\.)telegram\.org$|t\.me$"),                       "messaging", "Telegram", "✈"),
    (re.compile(r"(^|\.)matrix\.org$"),                                "messaging-e2e", "Matrix", "🟢"),
    (re.compile(r"(^|\.)threema\."),                                   "messaging-e2e", "Threema", "🔒"),
    (re.compile(r"(^|\.)simplex\."),                                   "messaging-e2e", "SimpleX", "🔒"),
    # ── Search engines ──
    (re.compile(r"(^|\.)duckduckgo\.com$"),                            "search", "DuckDuckGo", "🦆"),
    (re.compile(r"(^|\.)google\.[a-z.]+$"),                            "search", "Google", "🔍"),
    (re.compile(r"(^|\.)bing\.com$"),                                  "search", "Bing", "🔍"),
    (re.compile(r"(^|\.)startpage\.com$"),                             "search", "Startpage", "🔍"),
    (re.compile(r"(^|\.)qwant\.com$"),                                 "search", "Qwant", "🔍"),
    # ── Cloud / file sync ──
    (re.compile(r"(^|\.)dropbox\.com$|dropboxapi\.com$"),              "cloud", "Dropbox", "📦"),
    (re.compile(r"(^|\.)icloud\.com$|icloud-content\.com$"),           "cloud", "iCloud", "☁"),
    (re.compile(r"(^|\.)drive\.google\.com$|googleusercontent\.com$"), "cloud", "Google Drive", "☁"),
    (re.compile(r"(^|\.)onedrive\.live\.com$"),                        "cloud", "OneDrive", "☁"),
    (re.compile(r"(^|\.)nextcloud\.|.*\.nc\."),                        "cloud", "Nextcloud", "☁"),
    # ── Dev / code ──
    (re.compile(r"(^|\.)github\.com$|githubusercontent\.com$"),        "dev", "GitHub", "🐙"),
    (re.compile(r"(^|\.)gitlab\.com$"),                                "dev", "GitLab", "🦊"),
    (re.compile(r"(^|\.)stackoverflow\.com$|stackexchange\.com$"),     "dev", "Stack Overflow", "📚"),
    # ── Banking / fin ──
    (re.compile(r"(^|\.)revolut\.com$"),                               "banking", "Revolut", "🏦"),
    (re.compile(r"(^|\.)paypal\.com$"),                                "banking", "PayPal", "🏦"),
    (re.compile(r"(^|\.)stripe\.com$|js\.stripe\.com$"),               "banking", "Stripe", "🏦"),
    (re.compile(r"(^|\.)societegenerale\.fr$|sgmarkets\.com$"),        "banking", "Société Générale", "🏦"),
    (re.compile(r"(^|\.)bnpparibas\.|labanquepostale\."),              "banking", "Banque FR", "🏦"),
    (re.compile(r"(^|\.)credit-agricole\.|ca-paris\.|ca-bretagne\."),  "banking", "Crédit Agricole", "🏦"),
    # ── Email / collab ──
    (re.compile(r"(^|\.)gmail\.com$|googlemail\.com$"),                "email", "Gmail", "📧"),
    (re.compile(r"(^|\.)outlook\.com$|outlook\.office\.com$"),         "email", "Outlook", "📧"),
    (re.compile(r"(^|\.)proton\.me$|protonmail\."),                    "email-e2e", "Proton Mail", "🔒"),
    (re.compile(r"(^|\.)tutanota\."),                                  "email-e2e", "Tutanota", "🔒"),
    # ── Apple ecosystem ──
    (re.compile(r"(^|\.)apple\.com$|apple-cloudkit\.com$|aaplimg\.com$"), "apple", "Apple Service", "🍎"),
    (re.compile(r"(^|\.)mzstatic\.com$|itunes\.apple\.com$"),          "apple", "Apple iTunes/Store", "🍎"),
    (re.compile(r"push\.apple\.com$|courier\.push\.apple\.com$"),      "apple", "Apple Push", "🍎"),
    (re.compile(r"smoot\.apple\.com$"),                                "apple", "Apple Search", "🍎"),
    # ── Tor / privacy ──
    (re.compile(r"(\.onion$)|(torproject\.org$)"),                     "anon", "Tor", "🧅"),
    (re.compile(r"(^|\.)tailscale\.com$"),                             "vpn", "Tailscale", "🔐"),
    (re.compile(r"(^|\.)mullvad\.net$|protonvpn\."),                   "vpn", "VPN", "🔐"),
    # ── CDN / infra (lower priority) ──
    (re.compile(r"(^|\.)cloudfront\.net$|cloudfront\.aws\."),          "cdn", "CloudFront", "☁"),
    (re.compile(r"(^|\.)cloudflare\.com$|cf-ipv6\.com$"),              "cdn", "Cloudflare", "☁"),
    (re.compile(r"(^|\.)fastly\.net$|fastlylb\.net$"),                 "cdn", "Fastly", "☁"),
    (re.compile(r"(^|\.)akamai(edge|technologies)?\.net$"),            "cdn", "Akamai", "☁"),
    (re.compile(r"(^|\.)1e100\.net$"),                                 "cdn", "Google infra", "☁"),
]

CATEGORY_EMOJI = {
    "streaming": "📺",
    "social": "👥",
    "messaging-e2e": "🔒",
    "messaging": "💬",
    "search": "🔍",
    "cloud": "☁",
    "dev": "💻",
    "banking": "🏦",
    "email": "📧",
    "email-e2e": "🔒",
    "apple": "🍎",
    "anon": "🧅",
    "vpn": "🔐",
    "cdn": "☁",
    "other": "❔",
}


def classify_host(host: str) -> dict:
    """Returns {category, app, emoji} for a hostname. Unknown → other."""
    if not host:
        return {"category": "other", "app": "?", "emoji": "❔"}
    h = host.lower()
    for pattern, category, app, emoji in APP_PATTERNS:
        if pattern.search(h):
            return {"category": category, "app": app, "emoji": emoji}
    return {"category": "other", "app": "?", "emoji": "❔"}


def analyze_hosts(hosts: list[str]) -> dict:
    """Aggregate by category : returns {by_category: {cat: [{app, emoji, count, hosts[]}, ...]}, top_apps[]}"""
    by_app: dict[str, dict] = {}
    by_category: dict[str, int] = {}
    for h in hosts:
        cls = classify_host(h)
        key = f"{cls['app']}|{cls['category']}"
        if key not in by_app:
            by_app[key] = {"app": cls["app"], "category": cls["category"],
                            "emoji": cls["emoji"], "count": 0, "hosts": []}
        by_app[key]["count"] += 1
        if len(by_app[key]["hosts"]) < 5:
            by_app[key]["hosts"].append(h)
        by_category[cls["category"]] = by_category.get(cls["category"], 0) + 1

    apps_list = sorted(by_app.values(), key=lambda x: -x["count"])
    return {
        "top_apps": apps_list[:20],
        "by_category": by_category,
        "category_emoji": CATEGORY_EMOJI,
    }
