#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: audit-packages
Scans packages/secubox-*/ and produces a consolidation-oriented inventory.

Outputs (under out/):
  packages.json          full structured inventory
  packages.dot           graphviz: Depends edges between secubox-* packages
  empty-packages.txt     packages with no nginx route, no service, no api
  clusters-by-prefix.txt packages grouped by hyphen-prefix (cluster hints)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PKG_DIR = REPO / "packages"
OUT_DIR = REPO / "out"

# Match a single "Package: <name>" stanza header and its body until blank line / EOF.
PACKAGE_STANZA_RE = re.compile(
    r"^Package:\s*(\S+)\s*$(?P<body>(?:\n(?!Package:).*)*)",
    re.MULTILINE,
)
DEPENDS_LINE_RE = re.compile(r"^(Depends|Pre-Depends|Recommends|Suggests):\s*(.+(?:\n[ \t].*)*)", re.MULTILINE)
SOURCE_RE = re.compile(r"^Source:\s*(\S+)", re.MULTILINE)
SECTION_RE = re.compile(r"^Section:\s*(\S+)", re.MULTILINE)
DESCRIPTION_RE = re.compile(r"^Description:\s*(.+)$", re.MULTILINE)
EXECSTART_RE = re.compile(r"^ExecStart=(.+)$", re.MULTILINE)
NGINX_LOCATION_RE = re.compile(r"^\s*location\s+([^\s{]+)", re.MULTILINE)


def parse_depends(value: str) -> list[str]:
    """Parse a Depends line value into individual package atoms."""
    # Flatten continuation, drop version constraints + alternatives + whitespace.
    flat = re.sub(r"\s+", " ", value)
    atoms = []
    for atom in flat.split(","):
        # Pick first alternative from `pkg1 | pkg2`.
        first = atom.split("|")[0].strip()
        # Strip version constraint `(>= 1.0)` etc.
        first = re.sub(r"\s*\(.*\)$", "", first).strip()
        if first:
            atoms.append(first)
    return atoms


def parse_control(control_path: Path) -> list[dict]:
    """Return one dict per Package: stanza in the control file."""
    if not control_path.is_file():
        return []
    text = control_path.read_text(encoding="utf-8", errors="replace")
    source_m = SOURCE_RE.search(text)
    source = source_m.group(1) if source_m else None
    section_m = SECTION_RE.search(text)
    section = section_m.group(1) if section_m else None

    packages = []
    for m in PACKAGE_STANZA_RE.finditer(text):
        name = m.group(1)
        body = m.group("body") or ""
        # Re-attach the Package: line so depends regex sees the stanza in isolation.
        stanza = f"Package: {name}{body}"
        deps = {"depends": [], "pre_depends": [], "recommends": [], "suggests": []}
        for dm in DEPENDS_LINE_RE.finditer(stanza):
            key = dm.group(1).lower().replace("-", "_")
            deps[key] = parse_depends(dm.group(2))
        desc_m = DESCRIPTION_RE.search(stanza)
        packages.append(
            {
                "binary": name,
                "source": source or name,
                "section": section,
                "description": desc_m.group(1).strip() if desc_m else "",
                **deps,
            }
        )
    return packages


def find_services(pkg_root: Path) -> list[dict]:
    """Find systemd unit files shipped by the package."""
    services = []
    for path in list(pkg_root.glob("debian/*.service")) + list(pkg_root.glob("systemd/*.service")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        execs = [m.group(1).strip() for m in EXECSTART_RE.finditer(text)]
        services.append(
            {
                "unit": path.name,
                "path": str(path.relative_to(REPO)),
                "exec_starts": execs,
            }
        )
    return services


def find_nginx_routes(pkg_root: Path) -> list[str]:
    """Extract `location <path>` directives from nginx/ snippets."""
    routes: list[str] = []
    nginx_dir = pkg_root / "nginx"
    if not nginx_dir.is_dir():
        return routes
    for conf in nginx_dir.rglob("*.conf"):
        try:
            text = conf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in NGINX_LOCATION_RE.finditer(text):
            routes.append(m.group(1).strip())
    return sorted(set(routes))


def find_api_modules(pkg_root: Path) -> list[str]:
    """Return relative paths to api/main.py files."""
    return sorted(
        str(p.relative_to(REPO))
        for p in pkg_root.rglob("api/main.py")
    )


def detect_emptiness(entry: dict) -> bool:
    """Empty = no service, no nginx route, no api, no www, no frontend build, not a metapackage."""
    if entry.get("is_metapackage"):
        return False
    return not (
        entry["services"]
        or entry["nginx_routes"]
        or entry["api_modules"]
        or entry["has_www"]
        or entry.get("has_frontend_build")
        or entry.get("ships_files")
    )


def cluster_prefix(name: str) -> str:
    """Group key from a secubox-* package name (drop leading secubox-, keep first segment)."""
    base = name.removeprefix("secubox-")
    return base.split("-", 1)[0] if "-" in base else base


# Hand-curated fuzzy clusters: packages whose names don't share a hyphenated
# prefix but plausibly belong together. The audit produces evidence (deps,
# routes, services) inside each cluster so the operator can decide per-merge.
FUZZY_CLUSTERS: dict[str, list[str]] = {
    "stream*": ["secubox-streamforge", "secubox-streamlit"],
    "meta*": [
        "secubox-metablogizer",
        "secubox-metalogizer",
        "secubox-metacatalog",
    ],
    "mesh*": [
        "secubox-mesh",
        "secubox-meshname",
        "secubox-master-link",
        "secubox-mirror",
        "secubox-p2p",
        "secubox-daemon",  # WireGuard mesh daemon
    ],
    "dns-all": [
        "secubox-dns",
        "secubox-dns-guard",
        "secubox-dns-provider",
        "secubox-vortex-dns",
        "secubox-ad-guard",  # DNS sinkhole class
    ],
    "threats-all": [
        "secubox-threats",
        "secubox-threat-analyst",
        "secubox-cve-triage",
        "secubox-network-anomaly",
        "secubox-cyberfeed",
        "secubox-ipblock",
        "secubox-openclaw",
    ],
    "publishing": [
        "secubox-droplet",
        "secubox-cloner",
        "secubox-publish",
        "secubox-backup",  # adjacency: export-this-box family
        "secubox-reporter",
    ],
    "waf-stack": [
        "secubox-waf",
        "secubox-mitmproxy",
        "secubox-haproxy",
        "secubox-interceptor",
    ],
    "ai-all": [
        "secubox-ai-gateway",
        "secubox-ai-insights",
        "secubox-localai",
        "secubox-ollama",
        "secubox-mcp-server",
    ],
    "magicmirror": [
        "secubox-magicmirror",
        "secubox-mmpm",
    ],
    "system-hub": [
        "secubox-system",
        "secubox-system-hub",
        "secubox-admin",
        "secubox-hub",
    ],
    "soc-all": [
        "secubox-soc",
        "secubox-soc-agent",
        "secubox-soc-gateway",
        "secubox-soc-web",
    ],
    "mail-all": [
        "secubox-mail",
        "secubox-mail-lxc",
        "secubox-webmail",
        "secubox-webmail-lxc",
        "secubox-smtp-relay",
    ],
    "dpi-all": [
        "secubox-dpi",
        "secubox-ndpid",
        "secubox-netifyd",
        "secubox-mediaflow",
    ],
    "traffic-qos": [
        "secubox-traffic",
        "secubox-qos",
        "secubox-nettweak",
    ],
    "identity-users": [
        "secubox-identity",
        "secubox-users",
        "secubox-avatar",
        "secubox-auth",
        "secubox-portal",
        "secubox-authelia",
    ],
    "monitoring": [
        "secubox-netdata",
        "secubox-glances",
        "secubox-metrics",
        "secubox-health-doctor",
        "secubox-watchdog",
        "secubox-device-intel",
    ],
}


def build_inventory() -> dict:
    inv: dict[str, dict] = {}
    for pkg_root in sorted(PKG_DIR.glob("secubox-*")):
        if not pkg_root.is_dir():
            continue
        binaries = parse_control(pkg_root / "debian" / "control")
        services = find_services(pkg_root)
        routes = find_nginx_routes(pkg_root)
        apis = find_api_modules(pkg_root)
        www_dir = pkg_root / "www"
        has_frontend_build = any(
            (pkg_root / d).is_dir()
            for d in ("dist", "public", "src", "output", "kiosk", "helper", "ui")
        )
        # Packages that ship config/data directories under packages/<name>/
        # (most commonly etc/, share/, lib/, sbin/, firmware/, host/, cmd/, internal/)
        ships_files = any(
            (pkg_root / d).is_dir()
            for d in ("etc", "share", "lib", "sbin", "firmware", "host", "cmd", "internal", "go")
        )
        # Or via debian/<pkg>.install
        install_file = pkg_root / "debian" / f"{pkg_root.name}.install"
        if not ships_files and install_file.is_file():
            try:
                ships_files = bool(install_file.read_text(encoding="utf-8", errors="replace").strip())
            except OSError:
                pass

        # Primary binary = one matching pkg_root name, else first.
        primary = next(
            (b for b in binaries if b["binary"] == pkg_root.name),
            binaries[0] if binaries else None,
        )
        if primary is None:
            primary = {
                "binary": pkg_root.name,
                "source": pkg_root.name,
                "description": "(no debian/control)",
                "depends": [],
                "pre_depends": [],
                "recommends": [],
                "suggests": [],
            }

        section = primary.get("section") if primary else None
        is_metapackage = section == "metapackages"
        # Include extra binaries' depends so split-binary sources (e.g. daemon+c3box) count
        all_deps = list(primary["depends"])
        for b in binaries:
            if b["binary"] != pkg_root.name:
                all_deps.extend(b["depends"])

        entry = {
            "package": pkg_root.name,
            "path": str(pkg_root.relative_to(REPO)),
            "section": section,
            "is_metapackage": is_metapackage,
            "description": primary["description"],
            "depends": primary["depends"],
            "pre_depends": primary["pre_depends"],
            "recommends": primary["recommends"],
            "suggests": primary["suggests"],
            "all_secubox_deps": sorted({d for d in all_deps if d.startswith("secubox-")}),
            "extra_binaries": [b["binary"] for b in binaries if b["binary"] != pkg_root.name],
            "services": services,
            "nginx_routes": routes,
            "api_modules": apis,
            "has_www": www_dir.is_dir() and any(www_dir.iterdir()),
            "has_frontend_build": has_frontend_build,
            "ships_files": ships_files,
            "cluster_prefix": cluster_prefix(pkg_root.name),
        }
        entry["is_empty"] = detect_emptiness(entry)
        inv[pkg_root.name] = entry
    return inv


def write_json(inventory: dict, path: Path) -> None:
    path.write_text(json.dumps(inventory, indent=2, sort_keys=True), encoding="utf-8")


def write_dot(inventory: dict, path: Path) -> None:
    """Graphviz: nodes = secubox-* packages; edges = secubox-* -> secubox-* depends."""
    known = set(inventory.keys())
    lines = ["digraph secubox_packages {", "  rankdir=LR;", '  node [shape=box, fontsize=10];']

    by_cluster: dict[str, list[str]] = defaultdict(list)
    for name, entry in inventory.items():
        by_cluster[entry["cluster_prefix"]].append(name)

    for cluster, members in sorted(by_cluster.items()):
        if len(members) < 2:
            continue
        lines.append(f'  subgraph "cluster_{cluster}" {{')
        lines.append(f'    label="{cluster} ({len(members)})";')
        lines.append('    style=dashed; color=grey50;')
        for m in sorted(members):
            badge = " [E]" if inventory[m]["is_empty"] else ""
            lines.append(f'    "{m}" [label="{m}{badge}"];')
        lines.append("  }")

    # Standalone nodes
    for name, entry in sorted(inventory.items()):
        if len(by_cluster[entry["cluster_prefix"]]) < 2:
            badge = " [E]" if entry["is_empty"] else ""
            lines.append(f'  "{name}" [label="{name}{badge}"];')

    # Edges
    for name, entry in sorted(inventory.items()):
        for dep in entry["depends"] + entry["pre_depends"]:
            if dep in known and dep != name:
                lines.append(f'  "{name}" -> "{dep}";')
        for dep in entry["recommends"]:
            if dep in known and dep != name:
                lines.append(f'  "{name}" -> "{dep}" [style=dashed, color=grey];')

    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_empty(inventory: dict, path: Path) -> None:
    lines = ["# Packages with no service / no nginx route / no api / no www", ""]
    empties = [n for n, e in inventory.items() if e["is_empty"]]
    for name in sorted(empties):
        e = inventory[name]
        desc = e["description"] or "(no description)"
        lines.append(f"- {name} — {desc}")
    lines.append("")
    lines.append(f"Total empty: {len(empties)}/{len(inventory)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_clusters(inventory: dict, path: Path) -> None:
    by_cluster: dict[str, list[str]] = defaultdict(list)
    for name, entry in inventory.items():
        by_cluster[entry["cluster_prefix"]].append(name)

    lines = ["# Packages grouped by name prefix (consolidation hints)", ""]
    for cluster, members in sorted(by_cluster.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(members) < 2:
            continue
        lines.append(f"## {cluster} ({len(members)})")
        for m in sorted(members):
            e = inventory[m]
            marks = []
            if e["is_empty"]:
                marks.append("EMPTY")
            if not e["services"]:
                marks.append("no-svc")
            if not e["nginx_routes"]:
                marks.append("no-route")
            mark_str = f"  [{', '.join(marks)}]" if marks else ""
            desc = (e["description"] or "")[:80]
            lines.append(f"- {m} — {desc}{mark_str}")
        lines.append("")

    standalone = [n for n, e in inventory.items() if len(by_cluster[e["cluster_prefix"]]) < 2]
    lines.append(f"## standalone ({len(standalone)})")
    for m in sorted(standalone):
        e = inventory[m]
        marks = []
        if e["is_empty"]:
            marks.append("EMPTY")
        mark_str = f"  [{', '.join(marks)}]" if marks else ""
        desc = (e["description"] or "")[:80]
        lines.append(f"- {m} — {desc}{mark_str}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_fuzzy_clusters(inventory: dict, path: Path) -> None:
    """Emit the hand-curated fuzzy clusters with evidence per member."""
    lines = ["# Fuzzy clusters (hand-curated candidates for consolidation)", ""]
    lines.append("Marks: [META] metapackage  [EMPTY] no content  [no-svc] no service")
    lines.append("       [no-route] no nginx route  [→N] depends on N other secubox-* pkgs")
    lines.append("")
    seen: set[str] = set()
    for cluster, members in FUZZY_CLUSTERS.items():
        lines.append(f"## {cluster} ({len(members)})")
        for m in members:
            seen.add(m)
            e = inventory.get(m)
            if not e:
                lines.append(f"- {m} — **MISSING from packages/**")
                continue
            marks = []
            if e["is_metapackage"]:
                marks.append("META")
            if e["is_empty"]:
                marks.append("EMPTY")
            if not e["services"]:
                marks.append("no-svc")
            if not e["nginx_routes"]:
                marks.append("no-route")
            ndeps = len(e["all_secubox_deps"])
            if ndeps:
                marks.append(f"→{ndeps}")
            mark_str = f"  [{', '.join(marks)}]" if marks else ""
            desc = (e["description"] or "")[:80]
            lines.append(f"- {m} — {desc}{mark_str}")
            if e["nginx_routes"]:
                lines.append(f"    routes: {', '.join(e['nginx_routes'])}")
            if e["services"]:
                lines.append(f"    services: {', '.join(s['unit'] for s in e['services'])}")
            if e["all_secubox_deps"]:
                lines.append(f"    secubox-deps: {', '.join(e['all_secubox_deps'])}")
        lines.append("")
    lines.append(f"## Coverage")
    lines.append(f"Packages assigned to a fuzzy cluster: {len(seen)} / {len(inventory)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if not PKG_DIR.is_dir():
        raise SystemExit(f"packages/ not found at {PKG_DIR}")
    OUT_DIR.mkdir(exist_ok=True)
    inventory = build_inventory()
    write_json(inventory, OUT_DIR / "packages.json")
    write_dot(inventory, OUT_DIR / "packages.dot")
    write_empty(inventory, OUT_DIR / "empty-packages.txt")
    write_clusters(inventory, OUT_DIR / "clusters-by-prefix.txt")
    write_fuzzy_clusters(inventory, OUT_DIR / "clusters-fuzzy.txt")
    total = len(inventory)
    empty = sum(1 for e in inventory.values() if e["is_empty"])
    metas = sum(1 for e in inventory.values() if e["is_metapackage"])
    print(f"audit-packages: scanned {total} packages, {empty} empty, {metas} metapackages")
    print(f"  -> {OUT_DIR}/packages.json")
    print(f"  -> {OUT_DIR}/packages.dot")
    print(f"  -> {OUT_DIR}/empty-packages.txt")
    print(f"  -> {OUT_DIR}/clusters-by-prefix.txt")
    print(f"  -> {OUT_DIR}/clusters-fuzzy.txt")


if __name__ == "__main__":
    main()
