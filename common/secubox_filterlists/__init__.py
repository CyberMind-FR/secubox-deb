# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Modular filter-list resource (#740)
CyberMind — https://cybermind.fr

One shared place that fetches + parses ad / tracker / script filter lists from
many sources (hosts files, EasyList/AdGuard syntax, NoScript-style script
blockers) and compiles them into TYPED outputs consumed by BOTH blocking
pipelines:

    sources ──parse──┬─► dns-domains.txt   → ad-guard → Unbound NXDOMAIN (LAN-wide)
                     ├─► net-rules.json     → ad_ghost MITM 204 (R3)
                     ├─► cosmetic.json      → ad_ghost element-hide (##selector)
                     └─► scriptlets.json    → privacy_guard / NoScript (script block)

Each source is modular (declared in sources.json, toggle-able). A source has a
``format`` (how to parse) and the ``kinds`` of output it can feed. The curated
hosts/domain lists (OISD, HaGeZi) are DNS-native; EasyList contributes its
DNS-safe subset (``||domain^`` with no path) plus cosmetic + scriptlet rules.

Pure functions (the parsers) are unit-testable; ``compile_lists`` does the I/O.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# ── Paths ────────────────────────────────────────────────────────────────
DATA_DIR = Path("/var/lib/secubox/filterlists")
CACHE_DIR = DATA_DIR / "cache"
SOURCES_FILE = Path("/etc/secubox/toolbox/filter-sources.json")

OUT_DNS = DATA_DIR / "dns-domains.txt"
OUT_NET = DATA_DIR / "net-rules.json"
OUT_COSMETIC = DATA_DIR / "cosmetic.json"
OUT_SCRIPTLETS = DATA_DIR / "scriptlets.json"
OUT_STATS = DATA_DIR / "stats.json"

# Whitelist (operator) — domains never sinkholed, applied at compile time.
WHITELIST_DOMAINS = Path("/var/lib/secubox/filterlists/whitelist-domains.txt")

CACHE_TTL = 6 * 3600  # refetch a source at most every 6h

# ── Source registry ──────────────────────────────────────────────────────
# format: hosts | domains | easylist
# kinds:  which outputs this source can feed
DEFAULT_SOURCES: Dict[str, dict] = {
    "oisd-small": {
        "url": "https://small.oisd.nl/domainswild",
        "format": "domains", "kinds": ["dns"], "enabled": True,
        "desc": "OISD small — curated, low-breakage DNS blocklist",
    },
    "hagezi-pro": {
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.txt",
        "format": "domains", "kinds": ["dns"], "enabled": False,
        "desc": "HaGeZi Pro — ads + tracking + telemetry (~150k, opt-in: heavy on RAM)",
    },
    "stevenblack": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts", "kinds": ["dns"], "enabled": False,
        "desc": "StevenBlack unified hosts",
    },
    "easylist": {
        "url": "https://easylist.to/easylist/easylist.txt",
        "format": "easylist", "kinds": ["dns", "net", "cosmetic", "scriptlet"],
        "enabled": True, "desc": "EasyList — base ad rules (network + cosmetic)",
    },
    "easyprivacy": {
        "url": "https://easylist.to/easylist/easyprivacy.txt",
        "format": "easylist", "kinds": ["dns", "net", "cosmetic", "scriptlet"],
        "enabled": True, "desc": "EasyPrivacy — tracking + telemetry",
    },
    "adguard-base": {
        "url": "https://filters.adtidy.org/extension/ublock/filters/2_without_easylist.txt",
        "format": "easylist", "kinds": ["dns", "net", "cosmetic", "scriptlet"],
        "enabled": False, "desc": "AdGuard Base (uBlock flavour)",
    },
    # NoScript-style: block scripts from known script/ad CDNs. uBlock encodes
    # this as `||host^$script`; we honour the $script option (see parser).
    "ublock-privacy": {
        "url": "https://ublockorigin.github.io/uAssets/filters/privacy.txt",
        "format": "easylist", "kinds": ["net", "cosmetic", "scriptlet"],
        "enabled": False, "desc": "uBlock privacy — scriptlets + script blocking",
    },
}


# ── Domain helpers ───────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$")


def _valid_domain(d: str) -> bool:
    d = d.strip().lower().rstrip(".")
    if not d or len(d) > 253 or " " in d:
        return False
    return bool(_DOMAIN_RE.match(d))


# ── Parsers (pure) ───────────────────────────────────────────────────────
def parse_hosts(text: str) -> Set[str]:
    """Hosts-file format: ``0.0.0.0 domain`` / ``127.0.0.1 domain``."""
    out: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
            cand = parts[1].strip().lower()
            if cand not in ("localhost", "localhost.localdomain") and _valid_domain(cand):
                out.add(cand)
        elif len(parts) == 1 and _valid_domain(parts[0]):
            out.add(parts[0].lower())
    return out


def parse_domains(text: str) -> Set[str]:
    """Plain / wildcard domain list (one per line; ``*.x`` or ``x``)."""
    out: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!|@/":
            continue
        cand = line.lstrip("*.").lower().rstrip(".")
        if _valid_domain(cand):
            out.add(cand)
    return out


# EasyList network rule: ||domain^ (optionally with $options). We only lift the
# DNS-safe subset: anchored domain, no path, no element-specific options.
_EL_NET_DOMAIN = re.compile(r"^\|\|([a-z0-9.\-*]+)\^(\$(?P<opts>[a-z0-9,\-~]+))?$", re.I)
# Cosmetic: domains##selector  or  ##selector (generic). Exception: #@#
_EL_COSMETIC = re.compile(r"^(?P<domains>[^#]*)#(?P<excl>@?)#(?P<sel>.+)$")
# Scriptlet injection: ##+js(...)  /  domains##+js(...)
_EL_SCRIPTLET = re.compile(r"^(?P<domains>[^#]*)#(?P<excl>@?)#\+js\((?P<body>.*)\)$")

# Options that still permit a clean DNS block (whole-domain semantics).
_DNS_SAFE_OPTS = {"third-party", "3p", "all", "doc", "document", "popup", "important"}


@dataclass
class EasyListResult:
    dns_domains: Set[str] = field(default_factory=set)
    net_rules: List[str] = field(default_factory=list)            # raw network rules
    cosmetic: Dict[str, List[str]] = field(default_factory=dict)  # domain|"*" -> selectors
    cosmetic_excl: Dict[str, List[str]] = field(default_factory=dict)
    scriptlets: Dict[str, List[str]] = field(default_factory=dict)
    exceptions: Set[str] = field(default_factory=set)             # @@ allowlisted domains


def parse_easylist(text: str) -> EasyListResult:
    r = EasyListResult()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] == "!" or line.startswith("[Adblock"):
            continue

        # Scriptlet (must test before generic cosmetic).
        m = _EL_SCRIPTLET.match(line)
        if m:
            body = m.group("body").strip()
            doms = [d for d in m.group("domains").split(",") if d]
            for d in (doms or ["*"]):
                r.scriptlets.setdefault(d.lower(), []).append(body)
            continue

        # Cosmetic element-hide.
        m = _EL_COSMETIC.match(line)
        if m and not line.startswith("||"):
            sel = m.group("sel").strip()
            doms = [d for d in m.group("domains").split(",") if d]
            target = r.cosmetic_excl if m.group("excl") else r.cosmetic
            for d in (doms or ["*"]):
                target.setdefault(d.lower(), []).append(sel)
            continue

        # Exception network rule @@||domain^ -> allowlist domain.
        if line.startswith("@@"):
            mm = _EL_NET_DOMAIN.match(line[2:])
            if mm:
                dom = mm.group(1).lstrip("*.").lower()
                if _valid_domain(dom):
                    r.exceptions.add(dom)
            continue

        # Network rule.
        mm = _EL_NET_DOMAIN.match(line)
        if mm:
            dom = mm.group(1).lstrip("*.").lower()
            opts = mm.group("opts")
            opt_set = set(opts.split(",")) if opts else set()
            # DNS-safe only when every option keeps whole-domain semantics.
            if _valid_domain(dom) and (not opt_set or opt_set <= _DNS_SAFE_OPTS):
                r.dns_domains.add(dom)
            r.net_rules.append(line)
        elif line and not line.startswith("@@"):
            # Generic network rule (substring/regex) — keep for MITM matching.
            r.net_rules.append(line)
    return r


# ── Fetch (cached) ───────────────────────────────────────────────────────
def _fetch(name: str, url: str, force: bool = False) -> Optional[str]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / f"{name}.txt"
    if not force and cache.exists() and (time.time() - cache.stat().st_mtime) < CACHE_TTL:
        return cache.read_text(encoding="utf-8", errors="replace")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuBox-Deb/filterlists"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8", errors="replace")
        cache.write_text(data, encoding="utf-8")
        return data
    except Exception:
        # Stale cache is better than nothing.
        if cache.exists():
            return cache.read_text(encoding="utf-8", errors="replace")
        return None


# ── Config ───────────────────────────────────────────────────────────────
def load_sources() -> Dict[str, dict]:
    """Merge default registry with operator overrides in SOURCES_FILE."""
    sources = {k: dict(v) for k, v in DEFAULT_SOURCES.items()}
    try:
        if SOURCES_FILE.exists():
            override = json.loads(SOURCES_FILE.read_text())
            for name, cfg in override.get("sources", {}).items():
                if name in sources:
                    sources[name].update(cfg)
                else:
                    sources[name] = cfg
    except Exception:
        pass
    return sources


def _load_whitelist() -> Set[str]:
    out: Set[str] = set()
    if WHITELIST_DOMAINS.exists():
        for line in WHITELIST_DOMAINS.read_text().splitlines():
            d = line.strip().lower()
            if d and not d.startswith("#") and _valid_domain(d):
                out.add(d)
    return out


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ── Compile ──────────────────────────────────────────────────────────────
def compile_lists(force: bool = False) -> Dict[str, object]:
    """Fetch every enabled source, parse, merge, and write typed outputs.

    Returns a stats dict (also persisted to stats.json). Whitelisted domains and
    EasyList ``@@`` exceptions are removed from the DNS set so we never sinkhole
    a load-bearing host.
    """
    sources = load_sources()
    whitelist = _load_whitelist()

    dns: Set[str] = set()
    net: List[str] = []
    cosmetic: Dict[str, List[str]] = {}
    cosmetic_excl: Dict[str, List[str]] = {}
    scriptlets: Dict[str, List[str]] = {}
    exceptions: Set[str] = set()
    per_source: Dict[str, dict] = {}

    for name, cfg in sources.items():
        if not cfg.get("enabled"):
            continue
        text = _fetch(name, cfg["url"], force=force)
        if text is None:
            per_source[name] = {"ok": False, "dns": 0}
            continue
        fmt = cfg.get("format")
        added_dns = 0
        if fmt == "hosts":
            d = parse_hosts(text)
            dns |= d
            added_dns = len(d)
        elif fmt == "domains":
            d = parse_domains(text)
            dns |= d
            added_dns = len(d)
        elif fmt == "easylist":
            el = parse_easylist(text)
            if "dns" in cfg.get("kinds", []):
                dns |= el.dns_domains
                added_dns = len(el.dns_domains)
            if "net" in cfg.get("kinds", []):
                net.extend(el.net_rules)
            if "cosmetic" in cfg.get("kinds", []):
                for k, v in el.cosmetic.items():
                    cosmetic.setdefault(k, []).extend(v)
                for k, v in el.cosmetic_excl.items():
                    cosmetic_excl.setdefault(k, []).extend(v)
            if "scriptlet" in cfg.get("kinds", []):
                for k, v in el.scriptlets.items():
                    scriptlets.setdefault(k, []).extend(v)
            exceptions |= el.exceptions
        per_source[name] = {"ok": True, "dns": added_dns}

    # Apply allowlists to the DNS set (never sinkhole these).
    drop = whitelist | exceptions
    dns_final = sorted(d for d in dns if d not in drop)

    # De-dup cosmetic selectors.
    cosmetic = {k: sorted(set(v)) for k, v in cosmetic.items()}
    scriptlets = {k: sorted(set(v)) for k, v in scriptlets.items()}

    _atomic_write(OUT_DNS, "\n".join(dns_final) + "\n")
    _atomic_write(OUT_NET, json.dumps(sorted(set(net)), ensure_ascii=False))
    _atomic_write(OUT_COSMETIC, json.dumps(cosmetic, ensure_ascii=False))
    _atomic_write(OUT_SCRIPTLETS, json.dumps(scriptlets, ensure_ascii=False))

    stats = {
        "ts": int(time.time()),
        "dns_domains": len(dns_final),
        "net_rules": len(set(net)),
        "cosmetic_domains": len(cosmetic),
        "scriptlet_domains": len(scriptlets),
        "exceptions": len(exceptions),
        "whitelisted": len(whitelist),
        "sources": per_source,
    }
    _atomic_write(OUT_STATS, json.dumps(stats, indent=2))
    return stats


if __name__ == "__main__":
    import sys
    force = "--force" in sys.argv
    print(json.dumps(compile_lists(force=force), indent=2))
