# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>

"""Avatar analysis : UA + Client Hints → device emoji + readable name."""
from __future__ import annotations

import re

# Devices identification patterns. Order = priority (first match wins).
DEVICE_PATTERNS = [
    # ── iPhone ──
    (re.compile(r"iPhone\s?OS\s?(\d+_\d+)|iPhone.*OS\s?(\d+_\d+)", re.I),
     "iPhone", "📱", "iPhone iOS {}"),
    (re.compile(r"iPhone", re.I), "iPhone", "📱", "iPhone"),
    # ── iPad ──
    (re.compile(r"iPad", re.I), "iPad", "📱", "iPad"),
    # ── Mac ──
    (re.compile(r"Mac OS X (\d+[._]\d+)", re.I), "Mac", "💻", "macOS {}"),
    (re.compile(r"Macintosh", re.I), "Mac", "💻", "Mac"),
    # ── Android ──
    (re.compile(r"Pixel\s?(\d+)", re.I), "Pixel", "📱", "Pixel {}"),
    (re.compile(r"SM-[A-Z]\d+", re.I), "Samsung", "📱", "Samsung"),
    (re.compile(r"Android (\d+)", re.I), "Android", "📱", "Android {}"),
    (re.compile(r"Android", re.I), "Android", "📱", "Android"),
    # ── Windows ──
    (re.compile(r"Windows NT 11"), "Windows", "💻", "Windows 11"),
    (re.compile(r"Windows NT 10"), "Windows", "💻", "Windows 10"),
    (re.compile(r"Windows NT"), "Windows", "💻", "Windows"),
    # ── Linux ──
    (re.compile(r"Linux", re.I), "Linux", "🐧", "Linux"),
    # ── Game / IoT ──
    (re.compile(r"PlayStation", re.I), "PlayStation", "🎮", "PlayStation"),
    (re.compile(r"Xbox", re.I), "Xbox", "🎮", "Xbox"),
    (re.compile(r"Nintendo", re.I), "Nintendo", "🎮", "Nintendo"),
    (re.compile(r"AppleTV", re.I), "Apple TV", "📺", "Apple TV"),
    (re.compile(r"Roku", re.I), "Roku", "📺", "Roku"),
    # ── Bot / known clients ──
    (re.compile(r"curl/", re.I), "curl", "🛠", "curl"),
    (re.compile(r"wget/", re.I), "wget", "🛠", "wget"),
]

BROWSER_PATTERNS = [
    (re.compile(r"Edg/(\d+)"),       "Edge",   "🪟", "Edge {}"),
    (re.compile(r"Chrome/(\d+)"),    "Chrome", "🟢", "Chrome {}"),
    (re.compile(r"Firefox/(\d+)"),   "Firefox","🦊", "Firefox {}"),
    (re.compile(r"Safari/(\d+)"),    "Safari", "🧭", "Safari"),
    (re.compile(r"OPR/(\d+)|Opera/(\d+)"), "Opera", "🔴", "Opera"),
    (re.compile(r"DuckDuckGo/(\d+)"), "DuckDuckGo", "🦆", "DuckDuckGo {}"),
]


def classify_user_agent(ua: str) -> dict:
    """Returns {device, device_emoji, os_label, browser, browser_emoji, browser_label, raw}."""
    if not ua:
        return {"device": "unknown", "device_emoji": "❔", "os_label": "?",
                "browser": "unknown", "browser_emoji": "❔", "browser_label": "?",
                "raw": ""}
    device_match = None
    device_label = "unknown"
    for pattern, label, emoji, template in DEVICE_PATTERNS:
        m = pattern.search(ua)
        if m:
            # Try to fill the template with first non-None group
            groups = [g for g in m.groups() if g]
            if groups and "{}" in template:
                device_label = template.format(groups[0].replace("_", "."))
            else:
                device_label = template
            device_match = {"device": label, "device_emoji": emoji,
                             "os_label": device_label}
            break
    if not device_match:
        device_match = {"device": "unknown", "device_emoji": "❔",
                         "os_label": ua[:50]}
    browser_match = None
    for pattern, label, emoji, template in BROWSER_PATTERNS:
        m = pattern.search(ua)
        if m:
            groups = [g for g in m.groups() if g]
            if groups and "{}" in template:
                bl = template.format(groups[0])
            else:
                bl = template
            browser_match = {"browser": label, "browser_emoji": emoji, "browser_label": bl}
            break
    if not browser_match:
        browser_match = {"browser": "unknown", "browser_emoji": "❔", "browser_label": "?"}

    return {**device_match, **browser_match, "raw": ua[:200]}


def analyze_user_agents(ua_set: set[str] | list[str]) -> dict:
    """Aggregate a set of UAs : returns {devices, browsers, most_common, raw_count}."""
    if not ua_set:
        return {"devices": {}, "browsers": {}, "most_common": None, "raw_count": 0}
    devices: dict[str, dict] = {}
    browsers: dict[str, dict] = {}
    for ua in ua_set:
        cls = classify_user_agent(ua)
        d = cls["device"]
        if d not in devices:
            devices[d] = {"count": 0, "emoji": cls["device_emoji"], "os_label": cls["os_label"]}
        devices[d]["count"] += 1
        b = cls["browser"]
        if b not in browsers:
            browsers[b] = {"count": 0, "emoji": cls["browser_emoji"], "label": cls["browser_label"]}
        browsers[b]["count"] += 1
    # Most common device
    most_common = max(devices.items(), key=lambda x: x[1]["count"])[0] if devices else None
    return {
        "devices": devices,
        "browsers": browsers,
        "most_common": most_common,
        "most_common_emoji": devices[most_common]["emoji"] if most_common else "❔",
        "raw_count": len(ua_set),
    }
