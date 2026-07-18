# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — export installateur (lecture seule)
CyberMind — https://cybermind.fr

Résout l'ensemble désiré ON d'un profil (via state.resolve, pur) et le mappe
sur les paquets Debian propriétaires (units -> dpkg -S, repli secubox-<id>).
Un module dont le paquet reste introuvable part dans `unresolved` — JAMAIS un
paquet fabriqué : un installateur qui omet un module en silence casse l'image.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from .manifest import Manifest
from .state import ON, Profile, resolve

_UNIT_DIRS = ("/usr/lib/systemd/system/", "/lib/systemd/system/",
              "/etc/systemd/system/")


@dataclass(frozen=True)
class ExportResult:
    profile: str
    on_ids: list[str]
    packages: list[str]
    unresolved: list[str]
    rss_estimate_mo: int


def _run(argv: list[str]) -> tuple[int | None, str]:
    """rc=None => la commande n'a PAS pu s'exécuter (à distinguer d'un rc!=0,
    réponse authentique). Même contrat que cli._run / observe._run_cmd."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def _package_for_unit(unit: str, run) -> str | None:
    for base in _UNIT_DIRS:
        rc, out = run(["dpkg", "-S", base + unit])
        if rc == 0 and ":" in out:
            return out.splitlines()[0].split(":", 1)[0].strip()
    rc, out = run(["dpkg", "-S", unit])       # bare name (dpkg matches the path)
    if rc == 0 and ":" in out:
        return out.splitlines()[0].split(":", 1)[0].strip()
    return None


def _installed(pkg: str, run) -> bool:
    rc, out = run(["dpkg-query", "-W", "-f=${Status}", pkg])
    return rc == 0 and "install ok installed" in out


def resolve_packages(manifests: dict[str, Manifest], profile: Profile | None,
                     pins: dict[str, str], *, run=_run,
                     rss_kb: dict[str, int] | None = None) -> ExportResult:
    rss_kb = rss_kb or {}
    on = [m for _, m in sorted(manifests.items()) if resolve(m, profile, pins) == ON]
    packages: set[str] = set()
    unresolved: list[str] = []
    for m in on:
        pkg = None
        for u in m.units:
            pkg = _package_for_unit(u, run)
            if pkg:
                break
        if not pkg:
            candidate = f"secubox-{m.id}"
            if _installed(candidate, run):
                pkg = candidate
        if pkg:
            packages.add(pkg)
        else:
            unresolved.append(m.id)
    rss_mo = int(sum(rss_kb.get(m.id, 0) for m in on) / 1024)
    return ExportResult(
        profile=profile.name if profile else "",
        on_ids=[m.id for m in on],
        packages=sorted(packages),
        unresolved=sorted(unresolved),
        rss_estimate_mo=rss_mo,
    )


def format_pkglist(r: ExportResult) -> str:
    return "\n".join(r.packages)


def format_apt(r: ExportResult) -> str:
    return "apt-get install -y" + ("" if not r.packages else " " + " ".join(r.packages))


def format_json(r: ExportResult) -> str:
    return json.dumps({
        "profile": r.profile, "on_ids": r.on_ids, "packages": r.packages,
        "unresolved": r.unresolved, "rss_estimate_mo": r.rss_estimate_mo,
    }, ensure_ascii=False, indent=2)
