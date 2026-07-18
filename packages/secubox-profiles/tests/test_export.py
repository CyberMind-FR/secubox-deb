# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.export import (ExportResult, format_apt, format_json, format_pkglist,
                        resolve_packages)
from api.manifest import Manifest
from api.state import Profile


def _m(mid, units=(), protected=False):
    return Manifest(id=mid, category="infra", runtime="native",
                    exposure="lan", units=tuple(units), protected=protected)


def _fake_run(mapping):
    """mapping: unit-or-path substring -> package name (dpkg -S hit).
    dpkg-query -W install-check succeeds for packages in `mapping.values()`."""
    pkgs = set(mapping.values())

    def run(argv):
        if argv[:2] == ["dpkg", "-S"]:
            target = argv[2]
            for key, pkg in mapping.items():
                if key in target:
                    return 0, f"{pkg}: {target}\n"
            return 1, ""
        if argv[:1] == ["dpkg-query"]:
            pkg = argv[-1]
            return (0, "install ok installed") if pkg in pkgs else (1, "")
        return None, ""
    return run


def test_resolve_maps_units_to_packages_deduped_sorted():
    manifests = {
        "auth": _m("auth", ["secubox-auth.service"], protected=True),
        "waf": _m("waf", ["secubox-waf.service"]),
        "off1": _m("off1", ["secubox-off1.service"]),
    }
    profile = Profile(name="p", label="p", on=frozenset({"waf"}))  # off1 not listed
    run = _fake_run({"secubox-auth.service": "secubox-auth",
                     "secubox-waf.service": "secubox-waf"})
    r = resolve_packages(manifests, profile, {}, run=run)
    assert r.on_ids == ["auth", "waf"]          # protected auth + listed waf, off1 excluded
    assert r.packages == ["secubox-auth", "secubox-waf"]
    assert r.unresolved == []


def test_fallback_to_secubox_id_when_no_unit():
    # core is protected (always ON) and has no units → must fall back to the
    # secubox-<id> package name, verified installed via dpkg-query.
    manifests = {"core": _m("core", units=(), protected=True)}

    def run(argv):
        if argv[:1] == ["dpkg-query"]:
            return (0, "install ok installed") if argv[-1] == "secubox-core" else (1, "")
        if argv[:2] == ["dpkg", "-S"]:
            return 1, ""                      # no unit → no dpkg -S hit
        return None, ""
    r = resolve_packages(manifests, None, {}, run=run)
    assert r.packages == ["secubox-core"]
    assert r.unresolved == []


def test_truly_unknown_module_is_unresolved_never_fabricated():
    manifests = {"ghost": _m("ghost", ["secubox-ghost.service"])}
    profile = Profile(name="p", label="p", on=frozenset({"ghost"}))

    def run(argv):
        if argv[:2] == ["dpkg", "-S"]:
            return 1, ""                     # dpkg -S: not found
        if argv[:1] == ["dpkg-query"]:
            return 1, ""                     # secubox-ghost NOT installed
        return None, ""
    r = resolve_packages(manifests, profile, {}, run=run)
    assert r.packages == []
    assert r.unresolved == ["ghost"]


def test_dpkg_cannot_run_degrades_to_unresolved_not_a_package():
    manifests = {"waf": _m("waf", ["secubox-waf.service"])}
    profile = Profile(name="p", label="p", on=frozenset({"waf"}))

    def run(argv):
        return None, ""                       # rc=None everywhere: command could not run
    r = resolve_packages(manifests, profile, {}, run=run)
    assert r.packages == []
    assert r.unresolved == ["waf"]


def test_rss_estimate_summed_over_on_set():
    manifests = {"a": _m("a", ["secubox-a.service"]),
                 "b": _m("b", ["secubox-b.service"], protected=True)}
    profile = Profile(name="p", label="p", on=frozenset({"a"}))
    run = _fake_run({"secubox-a.service": "secubox-a", "secubox-b.service": "secubox-b"})
    r = resolve_packages(manifests, profile, {}, run=run,
                         rss_kb={"a": 20480, "b": 10240})  # 20 + 10 Mo
    assert r.rss_estimate_mo == 30


def test_formatters():
    r = ExportResult(profile="lite", on_ids=["auth", "waf"],
                     packages=["secubox-auth", "secubox-waf"],
                     unresolved=["ghost"], rss_estimate_mo=42)
    assert format_pkglist(r) == "secubox-auth\nsecubox-waf"
    assert format_apt(r) == "apt-get install -y secubox-auth secubox-waf"
    doc = json.loads(format_json(r))
    assert doc["profile"] == "lite" and doc["packages"] == ["secubox-auth", "secubox-waf"]
    assert doc["unresolved"] == ["ghost"] and doc["rss_estimate_mo"] == 42
