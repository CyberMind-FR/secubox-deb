# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""DPI / app classification : host → app category + emoji.

Strategy : pure-Python heuristic + (optional, Phase 2b) query to secubox-dpi
unix socket for nDPI results.

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
    # ── News / médias FR ──
    (re.compile(r"(^|\.)lemonde\.fr$"),                                "news", "Le Monde", "📰"),
    (re.compile(r"(^|\.)lefigaro\.fr$"),                               "news", "Le Figaro", "📰"),
    (re.compile(r"(^|\.)liberation\.fr$"),                             "news", "Libération", "📰"),
    (re.compile(r"(^|\.)mediapart\.fr$"),                              "news", "Mediapart", "📰"),
    (re.compile(r"(^|\.)francetv|france(info|culture|inter|24)\.fr$"), "news", "France Médias", "📺"),
    (re.compile(r"(^|\.)afp\.com$"),                                   "news", "AFP", "📰"),
    (re.compile(r"(^|\.)lequipe\.fr$"),                                "news", "L'Équipe", "⚽"),
    (re.compile(r"(^|\.)20minutes\.fr$|leparisien\.fr$|ouest-france\.fr$"), "news", "Presse locale", "📰"),
    # ── News / médias intl ──
    (re.compile(r"(^|\.)bbc\.(co\.uk|com)$"),                          "news", "BBC", "📰"),
    (re.compile(r"(^|\.)nytimes\.com$|nyt\.com$"),                     "news", "NYT", "📰"),
    (re.compile(r"(^|\.)theguardian\.com$"),                           "news", "The Guardian", "📰"),
    (re.compile(r"(^|\.)reuters\.com$"),                               "news", "Reuters", "📰"),
    (re.compile(r"(^|\.)cnn\.com$|cnn\.io$"),                          "news", "CNN", "📰"),
    (re.compile(r"(^|\.)dw\.com$|deutsche\.welle"),                    "news", "DW", "📰"),
    (re.compile(r"(^|\.)france24\.com$|rfi\.fr$"),                     "news", "France 24/RFI", "📰"),
    # ── Wikipedia / open content ──
    (re.compile(r"(^|\.)wikipedia\.org$|wikimedia\.org$"),             "knowledge", "Wikipedia", "📚"),
    (re.compile(r"(^|\.)wiktionary\.org$"),                            "knowledge", "Wiktionary", "📚"),
    (re.compile(r"(^|\.)wikibooks\.org$|wikidata\.org$"),              "knowledge", "Wikimedia", "📚"),
    (re.compile(r"(^|\.)archive\.org$"),                               "knowledge", "Internet Archive", "📚"),
    # ── AI / LLM ──
    (re.compile(r"(^|\.)openai\.com$|chatgpt\.com$"),                  "ai", "OpenAI / ChatGPT", "🤖"),
    (re.compile(r"(^|\.)anthropic\.com$|claude\.ai$"),                 "ai", "Anthropic / Claude", "🤖"),
    (re.compile(r"(^|\.)mistral\.ai$"),                                "ai", "Mistral AI", "🤖"),
    (re.compile(r"(^|\.)gemini\.google\.com$|bard\.google\.com$"),     "ai", "Google Gemini", "🤖"),
    (re.compile(r"(^|\.)copilot\.microsoft\.com$"),                    "ai", "Copilot", "🤖"),
    (re.compile(r"(^|\.)huggingface\.co$|hf\.co$"),                    "ai", "Hugging Face", "🤖"),
    (re.compile(r"(^|\.)perplexity\.ai$"),                             "ai", "Perplexity", "🤖"),
    (re.compile(r"(^|\.)ollama\.|ollama\.ai$"),                        "ai", "Ollama", "🤖"),
    (re.compile(r"(^|\.)midjourney\.com$"),                            "ai", "Midjourney", "🎨"),
    (re.compile(r"(^|\.)stability\.ai$|stablediffusion"),              "ai", "Stable Diffusion", "🎨"),
    # ── E-commerce ──
    (re.compile(r"(^|\.)amazon\.[a-z.]+$|amzn\."),                     "ecommerce", "Amazon", "📦"),
    (re.compile(r"(^|\.)ebay\.[a-z.]+$"),                              "ecommerce", "eBay", "🛒"),
    (re.compile(r"(^|\.)etsy\.com$"),                                  "ecommerce", "Etsy", "🛍"),
    (re.compile(r"(^|\.)aliexpress\.|alibaba\.com$"),                  "ecommerce", "Ali Express", "📦"),
    (re.compile(r"(^|\.)shopify\.com$|myshopify\.com$"),               "ecommerce", "Shopify", "🛒"),
    (re.compile(r"(^|\.)vinted\."),                                    "ecommerce", "Vinted", "👕"),
    (re.compile(r"(^|\.)leboncoin\.fr$"),                              "ecommerce", "Leboncoin", "🪑"),
    (re.compile(r"(^|\.)cdiscount\.com$|fnac\.com$|darty\.com$"),      "ecommerce", "E-commerce FR", "🛒"),
    (re.compile(r"(^|\.)booking\.com$"),                               "travel", "Booking", "🏨"),
    (re.compile(r"(^|\.)airbnb\.[a-z.]+$"),                            "travel", "Airbnb", "🏡"),
    (re.compile(r"(^|\.)blablacar\.[a-z.]+$"),                         "travel", "BlaBlaCar", "🚗"),
    (re.compile(r"(^|\.)sncf\.com$|oui\.sncf$|sncf-connect\."),        "travel", "SNCF", "🚆"),
    (re.compile(r"(^|\.)ratp\.fr$|stif\."),                            "travel", "RATP", "🚇"),
    # ── Gouv / admin ──
    (re.compile(r"(^|\.)gouv\.fr$"),                                   "gov-fr", "Service Public", "🇫🇷"),
    (re.compile(r"(^|\.)impots\.gouv\.fr$"),                           "gov-fr", "Impôts", "🇫🇷"),
    (re.compile(r"(^|\.)ants\.gouv\.fr$"),                             "gov-fr", "ANTS", "🇫🇷"),
    (re.compile(r"(^|\.)ameli\.fr$|cnam-tlsa\."),                      "gov-fr", "Assurance Maladie", "🏥"),
    (re.compile(r"(^|\.)caf\.fr$"),                                    "gov-fr", "CAF", "🇫🇷"),
    (re.compile(r"(^|\.)francetravail\.fr$|pole-emploi\.fr$"),         "gov-fr", "France Travail", "🇫🇷"),
    # ── Productivité / collab ──
    (re.compile(r"(^|\.)notion\.so$|notion-static\."),                 "productivity", "Notion", "📝"),
    (re.compile(r"(^|\.)slack\.com$|slack-edge\.com$"),                "productivity", "Slack", "💬"),
    (re.compile(r"(^|\.)discord\.(com|gg)$|discordapp\.net$"),         "productivity", "Discord", "🎮"),
    (re.compile(r"(^|\.)teams\.microsoft\.com$|teams\.live\.com$"),    "productivity", "MS Teams", "💼"),
    (re.compile(r"(^|\.)zoom\.us$|zoomgov\.com$"),                     "productivity", "Zoom", "📹"),
    (re.compile(r"(^|\.)meet\.jit\.si$|jitsi\.org$"),                  "productivity", "Jitsi", "📹"),
    (re.compile(r"(^|\.)bigbluebutton\."),                             "productivity", "BBB", "📹"),
    (re.compile(r"(^|\.)trello\.com$"),                                "productivity", "Trello", "📋"),
    (re.compile(r"(^|\.)asana\.com$"),                                 "productivity", "Asana", "📋"),
    (re.compile(r"(^|\.)atlassian\.com$|jira\."),                      "productivity", "Atlassian", "📋"),
    (re.compile(r"(^|\.)figma\.com$"),                                 "productivity", "Figma", "🎨"),
    (re.compile(r"(^|\.)canva\.com$"),                                 "productivity", "Canva", "🎨"),
    # ── Maps ──
    (re.compile(r"(^|\.)maps\.google\.com$|maps\.gstatic\."),          "maps", "Google Maps", "🗺"),
    (re.compile(r"(^|\.)openstreetmap\.org$|tile\.openstreetmap"),     "maps", "OpenStreetMap", "🗺"),
    (re.compile(r"(^|\.)mapbox\.com$"),                                "maps", "Mapbox", "🗺"),
    (re.compile(r"(^|\.)waze\.com$"),                                  "maps", "Waze", "🗺"),
    (re.compile(r"(^|\.)citymapper\.com$"),                            "maps", "Citymapper", "🗺"),
    # ── Gaming ──
    (re.compile(r"(^|\.)steamcommunity\.com$|steampowered\.com$|steamstatic\."), "gaming", "Steam", "🎮"),
    (re.compile(r"(^|\.)epicgames\.com$"),                             "gaming", "Epic Games", "🎮"),
    (re.compile(r"(^|\.)playstation\.com$|playstation\.net$"),         "gaming", "PlayStation", "🎮"),
    (re.compile(r"(^|\.)xbox\.com$|xboxlive\.com$"),                   "gaming", "Xbox Live", "🎮"),
    (re.compile(r"(^|\.)nintendo\.com$|nintendo\.net$"),               "gaming", "Nintendo", "🎮"),
    (re.compile(r"(^|\.)blizzard\.com$|battle\.net$"),                 "gaming", "Battle.net", "🎮"),
    (re.compile(r"(^|\.)minecraft\.net$"),                             "gaming", "Minecraft", "🎮"),
    (re.compile(r"(^|\.)roblox\.com$|rbxcdn\.com$"),                   "gaming", "Roblox", "🎮"),
    (re.compile(r"(^|\.)riotgames\.com$"),                             "gaming", "Riot Games", "🎮"),
    # ── Crypto / Exchanges ──
    (re.compile(r"(^|\.)binance\.[a-z.]+$"),                           "crypto", "Binance", "₿"),
    (re.compile(r"(^|\.)kraken\.com$"),                                "crypto", "Kraken", "₿"),
    (re.compile(r"(^|\.)coinbase\.com$"),                              "crypto", "Coinbase", "₿"),
    (re.compile(r"(^|\.)crypto\.com$"),                                "crypto", "Crypto.com", "₿"),
    (re.compile(r"(^|\.)okx\.com$"),                                   "crypto", "OKX", "₿"),
    (re.compile(r"(^|\.)blockchain\.com$|blockchain\.info$"),          "crypto", "Blockchain", "₿"),
    (re.compile(r"(^|\.)metamask\.io$"),                               "crypto", "MetaMask", "🦊"),
    # ── Ads / tracking (mirror secubox-ad-guard patterns) ──
    (re.compile(r"(^|\.)doubleclick\.net$|googleadservices\.com$|googlesyndication\.com$"), "ads", "Google Ads", "🎯"),
    (re.compile(r"(^|\.)scorecardresearch\.com$|comscore\.com$"),      "ads", "ComScore", "🎯"),
    (re.compile(r"(^|\.)hotjar\.com$|mixpanel\.com$|amplitude\.com$|segment\.[a-z]+$"), "ads", "Analytics", "📊"),
    (re.compile(r"(^|\.)criteo\.[a-z.]+$|adnxs\.com$|rubiconproject\.com$|smartadserver\.com$"), "ads", "Ad Network", "🎯"),
    (re.compile(r"(^|\.)taboola\.com$|outbrain\.com$"),                "ads", "Native Ads", "🎯"),
    (re.compile(r"(^|\.)newrelic\.com$|datadog(hq|\.com)|sentry\.io$"), "monitor", "APM", "📊"),
    # ── CDN / infra (lower priority — fallback) ──
    (re.compile(r"(^|\.)cloudfront\.net$|cloudfront\.aws\."),          "cdn", "CloudFront", "☁"),
    (re.compile(r"(^|\.)cloudflare\.com$|cf-ipv6\.com$"),              "cdn", "Cloudflare", "☁"),
    (re.compile(r"(^|\.)fastly\.net$|fastlylb\.net$"),                 "cdn", "Fastly", "☁"),
    (re.compile(r"(^|\.)akamai(edge|technologies)?\.net$"),            "cdn", "Akamai", "☁"),
    (re.compile(r"(^|\.)1e100\.net$"),                                 "cdn", "Google infra", "☁"),
    (re.compile(r"(^|\.)ovhcloud\.com$|ovh\.[a-z.]+$"),                "cdn", "OVH", "☁"),
    (re.compile(r"(^|\.)hetzner\.|scaleway\."),                        "cdn", "EU cloud", "☁"),
    (re.compile(r"(^|\.)digitalocean\.com$"),                          "cdn", "DigitalOcean", "☁"),
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
    "news": "📰",
    "knowledge": "📚",
    "ai": "🤖",
    "ecommerce": "📦",
    "travel": "🚆",
    "gov-fr": "🇫🇷",
    "productivity": "📝",
    "maps": "🗺",
    "gaming": "🎮",
    "crypto": "₿",
    "ads": "🎯",
    "monitor": "📊",
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
