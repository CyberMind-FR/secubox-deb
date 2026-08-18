<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Profils fonctionnels + export installateur — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship four functional optimized profile tiers (grounded in real gk2 inventory) and a read-only `export` subcommand that emits the Debian package list for a profile's active modules only.

**Architecture:** Data files (`profiles/*.toml`) shipped read-only + postinst-seeded; a pure `api/export.py` (resolve desired-ON via existing `state.resolve`, map module→package via `units`→`dpkg -S` with fallback, three formatters); a thin `export` CLI subcommand; packaging + version bump.

**Tech Stack:** Python 3.11 stdlib only (`tomllib`, `subprocess`, `json`, `dataclasses`), existing `secubox-profiles` Phase-1 code.

## Global Constraints

- Python 3.11, stdlib only. SPDX 4-line header on every new `.py`. Copyright `Gérald Kerma <devel@cybermind.fr>`.
- Phase-1 discipline: **read-only**. No `apply`, no writes to systemd/LXC. `export` and profile files never toggle anything.
- Reuse, do not reimplement: `state.resolve(m, profile, pins)`, `state.load_profile`, `state.load_pins`, `manifest.load_all`, `manifest.Manifest` (fields: `id, category, runtime, exposure, units:tuple, lxc, portal_domain, priority, protected, needs`). `state.ON`/`OFF` constants.
- `_run` contract (copied from `cli._run`): returns `(rc, stdout)` where `rc is None` means the command could NOT run (OSError/timeout) — never fabricate a `(1, "")`. A dpkg failure must degrade to `unresolved`, never to a made-up package.
- Profile `on` lists are EXHAUSTIVE. `name` in each TOML MUST equal the filename stem (enforced by `load_profile`).
- Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO Claude reference.
- Tests run per-directory: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q` (never combine package dirs; `api` name collides — see `pytest.ini`).
- The installer export must NEVER silently drop a module: unresolved modules are always surfaced (JSON field + stderr warning).

---

### Task 1: Les quatre profils + packaging + test de cohérence

**Files:**
- Create: `packages/secubox-profiles/profiles/full.toml`
- Create: `packages/secubox-profiles/profiles/lite.toml`
- Create: `packages/secubox-profiles/profiles/secure-gateway.toml`
- Create: `packages/secubox-profiles/profiles/media-lab.toml`
- Modify: `packages/secubox-profiles/debian/install`
- Modify: `packages/secubox-profiles/debian/postinst`
- Test: `packages/secubox-profiles/tests/test_profiles_data.py`

**Interfaces:**
- Consumes: `state.load_profile` (validates `name`==stem, `on` is list[str]).
- Produces: four installable profile files under `/usr/share/secubox/profiles/`, seeded to `/etc/secubox/profiles/`.

- [ ] **Step 1: Write the failing cohérence test**

Create `packages/secubox-profiles/tests/test_profiles_data.py`. It loads every shipped profile via the real `load_profile` and asserts each `on` id is a plausible module id (non-empty, no whitespace) and that `name`==stem. (Cross-checking against live manifests needs the board; here we validate structure + the invariant `load_profile` enforces.)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from pathlib import Path

import pytest

from api.state import load_profile

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"
PROFILE_FILES = sorted(PROFILES_DIR.glob("*.toml"))
EXPECTED = {"full", "lite", "secure-gateway", "media-lab"}


def test_all_four_profiles_ship():
    assert {p.stem for p in PROFILE_FILES} == EXPECTED


@pytest.mark.parametrize("path", PROFILE_FILES, ids=lambda p: p.stem)
def test_profile_loads_and_name_matches_stem(path):
    prof = load_profile(path)          # raises StateError if name != stem or bad 'on'
    assert prof.name == path.stem
    assert prof.on, f"{path.stem}: empty on-list"
    for mid in prof.on:
        assert mid and mid == mid.strip() and " " not in mid, f"bad id {mid!r}"


def test_protected_core_present_in_every_profile():
    # aggregator/auth/core are protected (always ON) but every functional tier
    # lists them explicitly for readability; guard that nobody drops them.
    for path in PROFILE_FILES:
        on = load_profile(path).on
        assert {"core", "auth", "aggregator"} <= on, f"{path.stem} missing protected"
```

- [ ] **Step 2: Run — must fail**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_profiles_data.py -q`
Expected: FAIL (no `profiles/` dir / files yet → `test_all_four_profiles_ship` fails, params empty).

- [ ] **Step 3: Create the four profile files**

Create `packages/secubox-profiles/profiles/secure-gateway.toml`:

```toml
name  = "secure-gateway"
label = "Secure Gateway — appliance durcie"
on = [
  "aggregator", "auth", "certs", "core", "crowdsec", "dns",
  "dns-guard", "dns-provider", "exposure", "haproxy", "hardening", "ipblock",
  "users", "vortex-firewall", "waf", "waf-ng", "waf-ratelimit",
]
```

Create `packages/secubox-profiles/profiles/lite.toml`:

```toml
name  = "lite"
label = "Lite — daily-driver optimisé"
on = [
  "ad-guard", "admin", "aggregator", "annuaire", "auth", "backup",
  "cdn", "certs", "core", "crowdsec", "cs-bridge", "dns",
  "dns-guard", "dns-provider", "exposure", "haproxy", "hardening", "health-doctor",
  "hub", "ipblock", "led-trigger", "leds", "mesh", "netdata",
  "network-ready", "p2p", "portal", "routes", "runtime", "system",
  "users", "vhost", "vortex-firewall", "waf", "waf-ng", "waf-ratelimit",
  "watchdog", "wireguard",
]
```

Create `packages/secubox-profiles/profiles/media-lab.toml`:

```toml
name  = "media-lab"
label = "Media Lab — box maison-média"
on = [
  "ad-guard", "admin", "aggregator", "annuaire", "appstore", "auth",
  "avatar", "backup", "billets", "c3box", "cdn", "certs",
  "cloner", "config-advisor", "cookies", "core", "crowdsec", "cs-bridge",
  "cyberfeed", "dns", "dns-guard", "dns-provider", "dpi", "dpi-flowcap",
  "droplet", "exposure", "eye-remote", "eye-remote-dhcp", "fmrelay", "frigate",
  "gitea", "glances", "grafana", "haproxy", "hardening", "health-doctor",
  "health-prober", "hub", "identity", "ipblock", "ksm", "led-heartbeat",
  "led-trigger", "leds", "localrecall", "lyrion", "mail", "mcp-server",
  "mesh", "meshname", "metablogizer", "metacatalog", "metrics", "mirror",
  "mitmproxy", "modem", "module-prober", "mqtt", "nac", "ndpid",
  "netboot", "netdata", "netdiag", "netifyd", "netmodes", "nettweak",
  "network-ready", "nextcloud", "p2p", "peertube", "photoprism", "podcaster",
  "portal", "proxypac", "publish", "qos", "reality", "repo",
  "reporter", "rezapp", "roadmap", "routes", "rtty", "runtime",
  "rustdesk", "saas-relay", "streamforge", "streamlit", "streamlit-routes", "system",
  "threats", "tor", "traffic", "turn", "users", "vault",
  "vhost", "vm", "vortex-dns", "vortex-firewall", "waf", "waf-ng",
  "waf-ratelimit", "watchdog", "wireguard", "yacy", "zigbee", "zkp",
]
```

Create `packages/secubox-profiles/profiles/full.toml`:

```toml
name  = "full"
label = "Full — loadout courant (baseline)"
on = [
  "ad-guard", "admin", "aggregator", "annuaire", "appstore", "auth",
  "avatar", "backup", "billets", "c3box", "cdn", "certs",
  "cloner", "config-advisor", "cookies", "core", "crowdsec", "cs-bridge",
  "cve-triage", "cyberfeed", "dns", "dns-guard", "dns-provider", "dpi",
  "dpi-flowcap", "droplet", "exposure", "eye-remote", "eye-remote-dhcp", "fmrelay",
  "frigate", "gitea", "glances", "grafana", "haproxy", "hardening",
  "health-doctor", "health-prober", "hub", "identity", "interceptor", "ipblock",
  "ksm", "led-heartbeat", "led-trigger", "leds", "localrecall", "lyrion",
  "mail", "mcp-server", "mesh", "meshname", "metablogizer", "metabolizer",
  "metacatalog", "metoblizer", "metrics", "mirror", "mitmproxy", "modem",
  "module-prober", "mqtt", "nac", "ndpid", "netboot", "netdata",
  "netdiag", "netifyd", "netmodes", "nettweak", "network-anomaly", "network-ready",
  "nextcloud", "p2p", "peertube", "photoprism", "podcaster", "portal",
  "proxypac", "publish", "qos", "reality", "repo", "reporter",
  "rezapp", "roadmap", "routes", "rtty", "runtime", "rustdesk",
  "saas-relay", "security-posture", "soc", "streamforge", "streamlit", "streamlit-routes",
  "system", "threat-analyst", "threatmesh", "threats", "toolbox", "toolbox-mitm",
  "tor", "traffic", "turn", "users", "vault", "vhost",
  "vm", "vortex-dns", "vortex-firewall", "waf", "waf-ng", "waf-ratelimit",
  "watchdog", "wireguard", "yacy", "zigbee", "zkp",
]
```

- [ ] **Step 4: Run — must pass**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_profiles_data.py -q`
Expected: PASS (4 files, all load, names match, protected present).

- [ ] **Step 5: Ship the profiles (packaging)**

In `packages/secubox-profiles/debian/install`, add a line (match the existing column style):

```
profiles/*.toml        usr/share/secubox/profiles/
```

In `packages/secubox-profiles/debian/postinst`, inside the `configure` case AFTER the `install -d ... /etc/secubox/profiles` line, seed missing profiles WITHOUT overwriting operator edits:

```sh
        # Seed reference profiles into the operator-editable dir on first
        # install only — never overwrite an edited profile on upgrade.
        for f in /usr/share/secubox/profiles/*.toml; do
            [ -e "$f" ] || continue
            dest="/etc/secubox/profiles/$(basename "$f")"
            if [ ! -e "$dest" ]; then
                install -o secubox -g secubox -m 644 "$f" "$dest"
            fi
        done
```

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-profiles/profiles packages/secubox-profiles/debian/install packages/secubox-profiles/debian/postinst packages/secubox-profiles/tests/test_profiles_data.py
git commit -m "feat(profiles): four functional tiers (full/lite/secure-gateway/media-lab) + seed

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2: `api/export.py` — résolution pure module→paquet + formatteurs

**Files:**
- Create: `packages/secubox-profiles/api/export.py`
- Test: `packages/secubox-profiles/tests/test_export.py`

**Interfaces:**
- Consumes: `state.resolve`, `state.ON`, `state.Profile`, `manifest.Manifest`.
- Produces: `resolve_packages(manifests, profile, pins, *, run=_run, rss_kb=None) -> ExportResult`; `ExportResult(profile, on_ids, packages, unresolved, rss_estimate_mo)`; `format_pkglist(r) -> str`, `format_apt(r) -> str`, `format_json(r) -> str`; `_run(argv) -> tuple[int|None, str]`.

- [ ] **Step 1: Write the failing tests**

Create `packages/secubox-profiles/tests/test_export.py`:

```python
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
```

- [ ] **Step 2: Run — must fail**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_export.py -q`
Expected: FAIL `ModuleNotFoundError: No module named 'api.export'`.

- [ ] **Step 3: Implement `api/export.py`**

```python
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
from pathlib import Path

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
```

- [ ] **Step 4: Run — must pass**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_export.py -q`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-profiles/api/export.py packages/secubox-profiles/tests/test_export.py
git commit -m "feat(profiles): export.py — resolve a profile's active modules to Debian packages

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3: sous-commande CLI `export` + bump version + README

**Files:**
- Modify: `packages/secubox-profiles/api/cli.py`
- Modify: `packages/secubox-profiles/debian/changelog`
- Modify: `packages/secubox-profiles/README.md`
- Test: `packages/secubox-profiles/tests/test_cli.py` (extend if present; else create)

**Interfaces:**
- Consumes: `export.resolve_packages`, `export.format_pkglist/apt/json`; existing `_paths`, `_load_profile_or_none`, `load_all`, `load_pins`, `_observe_all`, `observe.Actual`.
- Produces: `secubox-profilectl export <profile> [--format pkglist|apt|json]`.

- [ ] **Step 1: Write the failing CLI test**

Add to `packages/secubox-profiles/tests/test_cli.py` (create the file with the SPDX header if it does not exist). This test drives `cli.main(["export", ...])` against a tmp `--root`, monkeypatching the dpkg-facing `run` and the observer so it needs no board.

```python
def test_export_pkglist_from_tmp_root(tmp_path, monkeypatch, capsys):
    import api.cli as cli
    import api.export as export
    root = tmp_path / "etc-secubox"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    (root / "modules.d" / "waf.toml").write_text(
        'id="waf"\ncategory="security"\nruntime="native"\nexposure="lan"\n'
        'units=["secubox-waf.service"]\nprotected=false\n')
    (root / "modules.d" / "auth.toml").write_text(
        'id="auth"\ncategory="security"\nruntime="native"\nexposure="lan"\n'
        'units=["secubox-auth.service"]\nprotected=true\n')
    (root / "profiles" / "p.toml").write_text('name="p"\non=["waf"]\n')

    def fake_run(argv):
        if argv[:2] == ["dpkg", "-S"]:
            if "secubox-waf.service" in argv[2]:
                return 0, "secubox-waf: " + argv[2] + "\n"
            if "secubox-auth.service" in argv[2]:
                return 0, "secubox-auth: " + argv[2] + "\n"
            return 1, ""
        return None, ""
    monkeypatch.setattr(export, "_run", fake_run)

    rc = cli.main(["--root", str(root), "export", "p", "--format", "pkglist"])
    out = capsys.readouterr().out.strip().splitlines()
    assert rc == 0
    assert out == ["secubox-auth", "secubox-waf"]   # protected auth + listed waf


def test_export_unknown_profile_errors(tmp_path):
    import api.cli as cli
    root = tmp_path / "etc-secubox"
    (root / "modules.d").mkdir(parents=True)
    (root / "profiles").mkdir(parents=True)
    assert cli.main(["--root", str(root), "export", "nope"]) == 2  # StateError -> rc 2
```

- [ ] **Step 2: Run — must fail**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q`
Expected: FAIL (no `export` subparser → argparse SystemExit, or AttributeError).

- [ ] **Step 3: Wire the `export` subcommand in `cli.py`**

Add the import near the others:

```python
from .export import format_apt, format_json, format_pkglist, resolve_packages
```

Add the handler (place beside `_cmd_diff`). It observes RSS best-effort (same batched path as status/diff) so the estimate is real on-box, but never fails if observation is unavailable:

```python
def _cmd_export(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    profile = _load_profile_or_none(root, args.profile)  # StateError -> rc 2 if unknown
    pins = load_pins(pins_file)
    actuals = _observe_all(manifests, load_routes())
    rss_kb = {mid: (a.rss_kb or 0) for mid, a in actuals.items()}
    result = resolve_packages(manifests, profile, pins, rss_kb=rss_kb)
    if result.unresolved:
        print("⚠️  paquet introuvable pour: " + ", ".join(result.unresolved)
              + " — exclus de la liste (installateur incomplet).", file=sys.stderr)
    fmt = {"pkglist": format_pkglist, "apt": format_apt, "json": format_json}[args.format]
    print(fmt(result))
    return 0
```

Register the subparser in `main` (after the `scan` parser). `export` requires a profile name (positional), so it does not fall back to the active profile:

```python
    sp = sub.add_parser("export", help="liste des paquets des modules actifs d'un profil")
    sp.add_argument("profile", help="nom du profil à exporter")
    sp.add_argument("--format", choices=["pkglist", "apt", "json"], default="pkglist")
    sp.set_defaults(func=_cmd_export)
```

Note: `_load_profile_or_none` raises `StateError` on an unknown profile; a non-None name never returns None, so `_cmd_export` always has a real profile (the export of "nothing" is not a valid request).

- [ ] **Step 4: Run — must pass**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q`
Expected: PASS.

- [ ] **Step 5: Bump version + README**

Prepend to `packages/secubox-profiles/debian/changelog`:

```
secubox-profiles (0.3.0-1~bookworm1) bookworm; urgency=medium

  * Ship four functional profile tiers: full, lite, secure-gateway, media-lab
    (seeded into /etc/secubox/profiles on install, never overwriting edits).
  * New read-only CLI: secubox-profilectl export <profile> [--format
    pkglist|apt|json] — the Debian package list of a profile's active modules,
    for building a slim installer/image. Unresolved modules are surfaced, never
    silently dropped.

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 18 Jul 2026 12:00:00 +0200

```

In `README.md`, add a short "Profils & export" section documenting the four tiers, the pin-precedence caveat (a pinned-off module still shows in `diff`), and the three `export` formats. Keep it brief.

- [ ] **Step 6: Full suite + commit**

Run: `.venv/bin/python -m pytest packages/secubox-profiles/tests -q`
Expected: all prior Phase-1 tests + the new profile/export/cli tests pass.

```bash
git add packages/secubox-profiles/api/cli.py packages/secubox-profiles/debian/changelog packages/secubox-profiles/README.md packages/secubox-profiles/tests/test_cli.py
git commit -m "feat(profiles): secubox-profilectl export subcommand (0.3.0)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

- **Couverture spec** : profils 4 tiers (Task 1) ; livraison read-only + seed (Task 1 packaging) ; export pur module→paquet + repli + unresolved + 3 formats (Task 2) ; CLI export read-only (Task 3) ; version + README + caveat pins (Task 3). ✓
- **Placeholders** : aucun — chaque étape porte code + commande + attendu.
- **Cohérence des types** : `resolve_packages(manifests, profile, pins, *, run, rss_kb)` défini Task 2, consommé Task 3 ; `ExportResult` champs identiques dans formatteurs et test ; `_load_profile_or_none`/`_paths`/`_observe_all` réutilisés tels quels (signatures inchangées).
- **Sûreté Phase 1** : aucun write, aucun toggle ; export lit dpkg seulement ; unresolved jamais masqué.
