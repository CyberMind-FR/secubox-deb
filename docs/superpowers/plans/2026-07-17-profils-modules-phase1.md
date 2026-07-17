# Profils & modules — Phase 1 (lecture seule) — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer l'inventaire des modules SecuBox — taxonomie, coût RAM/CPU réel, état observé et diff vs profil désiré — **sans jamais rien allumer ni éteindre**.

**Architecture:** Manifestes plats TOML par module (`/etc/secubox/modules.d/<id>.toml`), un profiler (`scan`) qui les dérive du réel et mesure le coût, des fonctions **pures** de résolution d'état (protected > pin > profil > défaut) et de calcul de diff, et une CLI `secubox-profilectl` limitée à `scan`/`status`/`diff`. Aucun actionneur n'est écrit en Phase 1 : `apply` arrive en Phase 3.

**Tech Stack:** Python 3.11 (board : 3.11.2), `tomllib` (stdlib, lecture), dataclasses gelées, pytest. Aucune dépendance nouvelle.

**Spec:** `docs/superpowers/specs/2026-07-17-profils-modules-design.md`

## Global Constraints

- **Phase 1 est en lecture seule.** Aucun `systemctl enable/disable/start/stop`, aucun `lxc-start/stop`, aucune écriture dans `haproxy-routes.json`. Le seul fichier écrit est un manifeste par `scan`. Un test qui muterait l'état de la board est un échec de conception.
- **Python 3.11** : `tomllib` lit le TOML ; il n'existe **pas** d'écrivain TOML en stdlib — l'émetteur de `scan` est écrit à la main (schéma fixe et petit), pas de nouvelle dépendance.
- **En-tête SPDX obligatoire** en tête de chaque fichier Python et Bash, format exact ci-dessous (`.claude/CLAUDE.md`).
- **Ordre de résolution, sans exception** : `protected` → `pin` → `profil.on` → `off`.
- **Ordre du plan de changements** : tous les `stop` avant tous les `start` ; `stop` par priorité **croissante** (le moins prioritaire éteint en premier), `start` par priorité **décroissante** (le plus prioritaire allumé en premier).
- **`protected` est un refus, pas un avertissement** : tout diff qui éteindrait un module protégé lève `ProtectedViolation`.
- **Valeurs d'énumération exactes** : `runtime` ∈ {`native`, `lxc`} ; `exposure` ∈ {`public`, `lan`, `internal`} ; `category` ∈ {`media`, `security`, `network`, `infra`, `dev`, `mesh`}.
- **Tests par répertoire uniquement** : `python3 -m pytest packages/secubox-profiles/tests -q`. Ne jamais lancer `pytest common/ packages/` (collision du nom `api` sur `sys.path`, cf. `pytest.ini`).
- **Commits** : se terminent par `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`. Aucune référence à Claude Code.

En-tête SPDX Python (copier tel quel) :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
```

---

## Structure des fichiers

```
packages/secubox-profiles/
├── api/
│   ├── __init__.py       # vide
│   ├── manifest.py       # schéma Manifest + chargement/validation
│   ├── state.py          # chargement profil/pins + résolution état désiré (pur)
│   ├── observe.py        # sondes lecture seule (systemd/lxc/portail) → Actual
│   ├── diff.py           # désiré vs observé → plan ordonné (pur)
│   ├── scan.py           # profiler : dérive les manifestes + mesure le coût
│   └── cli.py            # secubox-profilectl : scan/status/diff
├── sbin/
│   └── secubox-profilectl
└── tests/
    ├── conftest.py
    ├── test_manifest.py
    ├── test_state.py
    ├── test_observe.py
    ├── test_diff.py
    └── test_scan.py
```

Responsabilité par fichier : `manifest` = ce qu'est un module ; `state` = ce qu'on veut ; `observe` = ce qui est ; `diff` = l'écart ; `scan` = découverte du réel ; `cli` = surface. `observe` est le **seul** fichier qui touche le système ; tout le reste est pur et testable sans board.

---

### Task 1 : Schéma et chargement des manifestes

**Files:**
- Create: `packages/secubox-profiles/api/__init__.py` (vide)
- Create: `packages/secubox-profiles/api/manifest.py`
- Create: `packages/secubox-profiles/tests/conftest.py`
- Test: `packages/secubox-profiles/tests/test_manifest.py`

**Interfaces:**
- Consumes: rien.
- Produces: `Manifest` (dataclass gelée), `load_manifest(path: Path) -> Manifest`, `load_all(dir: Path) -> dict[str, Manifest]`, `ManifestError(Exception)`.

- [ ] **Step 1 : conftest**

Créer `packages/secubox-profiles/tests/conftest.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path

# Rend `api` importable en top-level (miroir du layout runtime sous
# /usr/lib/secubox/profiles), comme le conftest de secubox-billets.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

- [ ] **Step 2 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_manifest.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.manifest import Manifest, ManifestError, load_all, load_manifest

FULL = """
id        = "peertube"
category  = "media"
runtime   = "lxc"
exposure  = "public"
units     = ["secubox-peertube.service"]
lxc       = "peertube"
portal    = { domain = "peertube.gk2.secubox.in" }
priority  = 40
protected = false
needs     = ["auth"]
"""

MINIMAL = """
id       = "lyrion"
category = "media"
runtime  = "native"
exposure = "lan"
units    = ["secubox-lyrion.service"]
"""


def test_load_full_manifest(tmp_path):
    p = tmp_path / "peertube.toml"
    p.write_text(FULL)
    m = load_manifest(p)
    assert m == Manifest(
        id="peertube", category="media", runtime="lxc", exposure="public",
        units=("secubox-peertube.service",), lxc="peertube",
        portal_domain="peertube.gk2.secubox.in", priority=40,
        protected=False, needs=("auth",),
    )


def test_defaults_are_applied(tmp_path):
    # Un manifeste minimal doit rester valide : la plupart des 134 modules
    # n'ont ni LXC, ni portail, ni deps.
    p = tmp_path / "lyrion.toml"
    p.write_text(MINIMAL)
    m = load_manifest(p)
    assert m.lxc is None and m.portal_domain is None
    assert m.priority == 50 and m.protected is False and m.needs == ()


@pytest.mark.parametrize("field,bad", [
    ("runtime", '"docker"'),
    ("exposure", '"world"'),
    ("category", '"divers"'),
])
def test_rejects_unknown_enum(tmp_path, field, bad):
    # Une valeur inconnue doit échouer bruyamment : un manifeste mal typé
    # deviendrait une décision d'extinction erronée en Phase 3.
    src = MINIMAL.replace(f'{field} = "' + {"runtime": "native", "exposure": "lan",
                                            "category": "media"}[field] + '"',
                          f"{field} = {bad}")
    p = tmp_path / "bad.toml"
    p.write_text(src)
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_lxc_runtime_without_lxc_name(tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text(MINIMAL.replace('runtime  = "native"', 'runtime  = "lxc"'))
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_priority_out_of_range(tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text(MINIMAL + "\npriority = 101\n")
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_rejects_id_mismatching_filename(tmp_path):
    # L'id pilote pins/profils ; s'il diverge du nom de fichier, un pin
    # viserait un module fantôme.
    p = tmp_path / "autre.toml"
    p.write_text(MINIMAL)
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_load_all_indexes_by_id_and_skips_non_toml(tmp_path):
    (tmp_path / "lyrion.toml").write_text(MINIMAL)
    (tmp_path / "peertube.toml").write_text(FULL)
    (tmp_path / "notes.txt").write_text("ignore me")
    all_m = load_all(tmp_path)
    assert sorted(all_m) == ["lyrion", "peertube"]
    assert all_m["peertube"].runtime == "lxc"
```

- [ ] **Step 3 : lancer le test — il doit échouer**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_manifest.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.manifest'`.

- [ ] **Step 4 : implémenter**

Créer `packages/secubox-profiles/api/__init__.py` vide, puis `packages/secubox-profiles/api/manifest.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — schéma et chargement des manifestes module
CyberMind — https://cybermind.fr

Un manifeste décrit le CYCLE DE VIE d'un module : ses units, son runtime, son
exposition, sa priorité. Il ne duplique pas menu.d/ (path, ordre, icône), qui
reste la source UI avec son propre cycle de vie.

La validation est stricte et bruyante : en Phase 3 un manifeste mal typé
deviendrait une décision d'extinction erronée. Mieux vaut refuser au chargement.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

RUNTIMES = ("native", "lxc")
EXPOSURES = ("public", "lan", "internal")
CATEGORIES = ("media", "security", "network", "infra", "dev", "mesh")

DEFAULT_PRIORITY = 50


class ManifestError(Exception):
    """Manifeste illisible ou invalide."""


@dataclass(frozen=True)
class Manifest:
    id: str
    category: str
    runtime: str
    exposure: str
    units: tuple[str, ...]
    lxc: str | None = None
    portal_domain: str | None = None
    priority: int = DEFAULT_PRIORITY
    protected: bool = False
    needs: tuple[str, ...] = ()


def _require(d: dict, key: str, path: Path):
    if key not in d:
        raise ManifestError(f"{path}: champ obligatoire manquant: {key}")
    return d[key]


def _enum(value, allowed: tuple[str, ...], key: str, path: Path) -> str:
    if value not in allowed:
        raise ManifestError(f"{path}: {key}={value!r} invalide (attendu: {', '.join(allowed)})")
    return value


def load_manifest(path: Path) -> Manifest:
    """Charge et valide un manifeste. Lève ManifestError sur tout écart."""
    try:
        d = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"{path}: illisible: {exc}") from exc

    mid = _require(d, "id", path)
    # L'id pilote pins et profils : s'il diverge du nom de fichier, un pin
    # viserait un module qui n'existe pas sous ce nom.
    if mid != path.stem:
        raise ManifestError(f"{path}: id={mid!r} ne correspond pas au nom de fichier {path.stem!r}")

    runtime = _enum(_require(d, "runtime", path), RUNTIMES, "runtime", path)
    lxc = d.get("lxc")
    if runtime == "lxc" and not lxc:
        raise ManifestError(f"{path}: runtime='lxc' exige le champ lxc=<nom du conteneur>")

    units = _require(d, "units", path)
    if not isinstance(units, list) or not all(isinstance(u, str) for u in units):
        raise ManifestError(f"{path}: units doit être une liste de chaînes")

    priority = d.get("priority", DEFAULT_PRIORITY)
    if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 100:
        raise ManifestError(f"{path}: priority={priority!r} hors bornes (entier 0-100)")

    portal = d.get("portal") or {}
    if not isinstance(portal, dict):
        raise ManifestError(f"{path}: portal doit être une table")

    return Manifest(
        id=mid,
        category=_enum(_require(d, "category", path), CATEGORIES, "category", path),
        runtime=runtime,
        exposure=_enum(_require(d, "exposure", path), EXPOSURES, "exposure", path),
        units=tuple(units),
        lxc=lxc,
        portal_domain=portal.get("domain"),
        priority=priority,
        protected=bool(d.get("protected", False)),
        needs=tuple(d.get("needs", ())),
    )


def load_all(directory: Path) -> dict[str, Manifest]:
    """Charge tous les *.toml d'un répertoire, indexés par id."""
    out: dict[str, Manifest] = {}
    for p in sorted(Path(directory).glob("*.toml")):
        m = load_manifest(p)
        out[m.id] = m
    return out
```

- [ ] **Step 5 : lancer le test — il doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_manifest.py -q
```
Attendu : `9 passed`.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-profiles/api/__init__.py packages/secubox-profiles/api/manifest.py \
        packages/secubox-profiles/tests/conftest.py packages/secubox-profiles/tests/test_manifest.py
git commit -m "feat(profiles): schéma et chargement des manifestes module

Valide strictement : un manifeste mal typé deviendrait une décision
d'extinction erronée en Phase 3.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2 : Résolution de l'état désiré (profils + pins)

**Files:**
- Create: `packages/secubox-profiles/api/state.py`
- Test: `packages/secubox-profiles/tests/test_state.py`

**Interfaces:**
- Consumes: `Manifest` de `api.manifest`.
- Produces: `Profile` (dataclass gelée : `name: str`, `label: str`, `on: frozenset[str]`), `load_profile(path) -> Profile`, `load_pins(path) -> dict[str, str]`, `resolve(m: Manifest, profile: Profile | None, pins: dict[str, str]) -> str` (retourne `"on"` ou `"off"`), `StateError(Exception)`.

- [ ] **Step 1 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_state.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.manifest import Manifest
from api.state import Profile, StateError, load_pins, load_profile, resolve


def mk(mid, protected=False):
    return Manifest(id=mid, category="media", runtime="native", exposure="lan",
                    units=(f"secubox-{mid}.service",), protected=protected)


MEDIA = Profile(name="media", label="🎬 Média", on=frozenset({"lyrion", "peertube"}))


def test_listed_in_profile_is_on():
    assert resolve(mk("lyrion"), MEDIA, {}) == "on"


def test_not_listed_is_off():
    # Profil exhaustif : ce qui n'est pas listé est éteint.
    assert resolve(mk("gitea"), MEDIA, {}) == "off"


def test_pin_on_beats_profile_off():
    assert resolve(mk("gitea"), MEDIA, {"gitea": "on"}) == "on"


def test_pin_off_beats_profile_on():
    assert resolve(mk("lyrion"), MEDIA, {"lyrion": "off"}) == "off"


def test_protected_beats_pin_off():
    # Non négociable : sans ça, un pin peut verrouiller l'utilisateur
    # hors de sa propre box.
    assert resolve(mk("auth", protected=True), MEDIA, {"auth": "off"}) == "on"


def test_protected_beats_profile_omission():
    assert resolve(mk("auth", protected=True), MEDIA, {}) == "on"


def test_no_profile_means_only_pins_and_protected():
    # Aucun profil actif : on n'éteint rien de protégé, et les pins valent.
    assert resolve(mk("auth", protected=True), None, {}) == "on"
    assert resolve(mk("gitea"), None, {"gitea": "on"}) == "on"
    assert resolve(mk("gitea"), None, {}) == "off"


def test_load_profile(tmp_path):
    p = tmp_path / "media.toml"
    p.write_text('name = "media"\nlabel = "🎬 Média"\non = ["lyrion", "peertube"]\n')
    prof = load_profile(p)
    assert prof.name == "media" and prof.label == "🎬 Média"
    assert prof.on == frozenset({"lyrion", "peertube"})


def test_load_profile_rejects_name_mismatch(tmp_path):
    p = tmp_path / "media.toml"
    p.write_text('name = "autre"\nlabel = "x"\non = []\n')
    with pytest.raises(StateError):
        load_profile(p)


def test_load_pins(tmp_path):
    p = tmp_path / "pins.toml"
    p.write_text('gitea = "on"\ndpi = "off"\n')
    assert load_pins(p) == {"gitea": "on", "dpi": "off"}


def test_load_pins_missing_file_is_empty(tmp_path):
    # Pas de pins = cas normal, pas une erreur.
    assert load_pins(tmp_path / "absent.toml") == {}


def test_load_pins_rejects_bad_value(tmp_path):
    p = tmp_path / "pins.toml"
    p.write_text('gitea = "maybe"\n')
    with pytest.raises(StateError):
        load_pins(p)
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_state.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.state'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-profiles/api/state.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — état désiré (profils + pins)
CyberMind — https://cybermind.fr

Les profils sont EXHAUSTIFS : ce qui n'est pas listé est éteint, donc basculer
donne le même résultat quel que soit l'état de départ. Les pins réconcilient ce
déterminisme avec le toggle individuel : ils survivent aux bascules.

`resolve` est une fonction pure — c'est la règle la plus critique du système et
elle doit être testable sans board.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest

ON, OFF = "on", "off"


class StateError(Exception):
    """Profil ou pins illisible/invalide."""


@dataclass(frozen=True)
class Profile:
    name: str
    label: str
    on: frozenset[str]


def load_profile(path: Path) -> Profile:
    path = Path(path)
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise StateError(f"{path}: profil illisible: {exc}") from exc
    name = d.get("name")
    if name != path.stem:
        raise StateError(f"{path}: name={name!r} ne correspond pas au fichier {path.stem!r}")
    on = d.get("on", [])
    if not isinstance(on, list) or not all(isinstance(x, str) for x in on):
        raise StateError(f"{path}: 'on' doit être une liste d'ids")
    return Profile(name=name, label=d.get("label", name), on=frozenset(on))


def load_pins(path: Path) -> dict[str, str]:
    """Pins absents = cas normal (aucune surcharge), pas une erreur."""
    path = Path(path)
    if not path.exists():
        return {}
    try:
        d = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise StateError(f"{path}: pins illisibles: {exc}") from exc
    for k, v in d.items():
        if v not in (ON, OFF):
            raise StateError(f"{path}: pin {k}={v!r} invalide (attendu 'on' ou 'off')")
    return dict(d)


def resolve(m: Manifest, profile: Profile | None, pins: dict[str, str]) -> str:
    """État désiré d'un module. Ordre strict, sans exception :

        protected → ON toujours   (sinon on peut se verrouiller hors de la box)
        épinglé   → valeur du pin
        listé     → ON
        sinon     → OFF
    """
    if m.protected:
        return ON
    pin = pins.get(m.id)
    if pin in (ON, OFF):
        return pin
    if profile is not None and m.id in profile.on:
        return ON
    return OFF
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_state.py -q
```
Attendu : `12 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-profiles/api/state.py packages/secubox-profiles/tests/test_state.py
git commit -m "feat(profiles): résolution de l'état désiré (protected > pin > profil > off)

Profils exhaustifs + pins persistants. resolve() est pure : c'est la règle la
plus critique du système, elle doit être testable sans board.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3 : Sondes d'état réel (lecture seule)

**Files:**
- Create: `packages/secubox-profiles/api/observe.py`
- Test: `packages/secubox-profiles/tests/test_observe.py`

**Interfaces:**
- Consumes: `Manifest` de `api.manifest`.
- Produces: `Actual` (dataclass gelée : `enabled: bool | None`, `active: bool | None`, `lxc_running: bool | None`, `lxc_autostart: bool | None`, `portal_routed: bool | None`, `rss_kb: int | None`), `observe(m: Manifest, *, run=..., routes: set[str] | None = None) -> Actual`, `load_routes(path: Path) -> set[str]`, `is_on(a: Actual) -> bool`.

`run` est injecté (signature `run(argv: list[str]) -> tuple[int, str]`) pour que les tests n'appellent jamais le vrai `systemctl`. Défaut : `_run_cmd`.

- [ ] **Step 1 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_observe.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.manifest import Manifest
from api.observe import Actual, is_on, load_routes, observe


def fake_run(table):
    """table: {(argv tuple): (rc, stdout)}"""
    def _run(argv):
        return table.get(tuple(argv), (1, ""))
    return _run


NATIVE = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                  units=("secubox-lyrion.service",))
LXC = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
               units=("secubox-peertube.service",), lxc="peertube",
               portal_domain="peertube.gk2.secubox.in")


def test_observe_native_enabled_and_active():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is True and a.active is True
    assert a.lxc_running is None and a.lxc_autostart is None
    assert a.portal_routed is None   # pas de portail déclaré


def test_observe_native_disabled():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (1, "disabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (3, "inactive\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(NATIVE, run=run, routes=set())
    assert a.enabled is False and a.active is False


def test_observe_lxc_and_portal():
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-peertube.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-peertube.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-peertube.service", "-p", "MainPID", "--value"): (0, "0\n"),
        ("lxc-info", "-n", "peertube", "-s"): (0, "State: RUNNING\n"),
        ("lxc-info", "-n", "peertube", "-c", "lxc.start.auto"): (0, "lxc.start.auto = 1\n"),
    })
    a = observe(LXC, run=run, routes={"peertube.gk2.secubox.in"})
    assert a.lxc_running is True and a.lxc_autostart is True
    assert a.portal_routed is True


def test_lxc_state_unknown_is_none_not_false():
    # lxc-info échoue depuis le contexte non privilégié de l'API (motif connu de
    # cette box : lxc_state='absent' alors que le service répond). Inconnu doit
    # rester None — surtout pas False, qui déclencherait un faux 'à allumer'.
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-peertube.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-peertube.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-peertube.service", "-p", "MainPID", "--value"): (0, "0\n"),
    })
    a = observe(LXC, run=run, routes=set())
    assert a.lxc_running is None and a.lxc_autostart is None
    assert a.portal_routed is False   # portail déclaré mais absent des routes


def test_rss_read_from_mainpid(tmp_path, monkeypatch):
    run = fake_run({
        ("systemctl", "is-enabled", "secubox-lyrion.service"): (0, "enabled\n"),
        ("systemctl", "is-active", "secubox-lyrion.service"): (0, "active\n"),
        ("systemctl", "show", "secubox-lyrion.service", "-p", "MainPID", "--value"): (0, "4242\n"),
    })
    status = tmp_path / "4242"
    status.mkdir()
    (status / "status").write_text("Name:\tpython3\nVmRSS:\t  123456 kB\n")
    monkeypatch.setattr("api.observe.PROC", tmp_path)
    a = observe(NATIVE, run=run, routes=set())
    assert a.rss_kb == 123456


def test_is_on_requires_enabled_and_active():
    assert is_on(Actual(enabled=True, active=True)) is True
    assert is_on(Actual(enabled=True, active=False)) is False
    assert is_on(Actual(enabled=False, active=True)) is False


def test_load_routes(tmp_path):
    p = tmp_path / "haproxy-routes.json"
    p.write_text(json.dumps({"peertube.gk2.secubox.in": ["127.0.0.1", 9000],
                             "billets.gk2.secubox.in": ["127.0.0.1", 8910]}))
    assert load_routes(p) == {"peertube.gk2.secubox.in", "billets.gk2.secubox.in"}


def test_load_routes_missing_file_is_empty(tmp_path):
    assert load_routes(tmp_path / "absent.json") == set()
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_observe.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.observe'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-profiles/api/observe.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — sondes d'état réel (LECTURE SEULE)
CyberMind — https://cybermind.fr

Seul fichier du module qui touche le système. Il n'exécute QUE des commandes de
lecture (is-enabled, is-active, show, lxc-info). Aucun enable/disable/start/stop
n'a sa place ici : Phase 1 est en lecture seule.

L'état réel est OBSERVÉ, jamais supposé depuis un état stocké — un paquet
réinstallé ré-`enable` son unit dans son postinst (motif imposé par le CLAUDE.md
du projet), donc un état mémorisé ment.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROC = Path("/proc")
ROUTES_FILE = Path("/etc/secubox/waf/haproxy-routes.json")

_TIMEOUT = 5


@dataclass(frozen=True)
class Actual:
    enabled: bool | None = None
    active: bool | None = None
    lxc_running: bool | None = None
    lxc_autostart: bool | None = None
    portal_routed: bool | None = None
    rss_kb: int | None = None


def _run_cmd(argv: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def load_routes(path: Path = ROUTES_FILE) -> set[str]:
    """Domaines routés par le WAF. Fichier absent = aucune route (pas une erreur)."""
    path = Path(path)
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return set()


def _rss_kb(pid: str) -> int | None:
    if not pid or pid == "0":
        return None
    try:
        for line in (PROC / pid / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def observe(m, *, run=_run_cmd, routes: set[str] | None = None) -> Actual:
    """État réel d'un module. Tout ce qui n'est pas déterminable reste None —
    jamais False : un False inventé produirait une fausse décision."""
    unit = m.units[0] if m.units else None
    enabled = active = rss = None
    if unit:
        rc, _ = run(["systemctl", "is-enabled", unit])
        enabled = rc == 0
        rc, _ = run(["systemctl", "is-active", unit])
        active = rc == 0
        rc, out = run(["systemctl", "show", unit, "-p", "MainPID", "--value"])
        if rc == 0:
            rss = _rss_kb(out.strip())

    lxc_running = lxc_autostart = None
    if m.runtime == "lxc" and m.lxc:
        rc, out = run(["lxc-info", "-n", m.lxc, "-s"])
        # lxc-info échoue depuis le contexte non privilégié de l'API : on laisse
        # None plutôt que d'affirmer "arrêté" à tort.
        if rc == 0:
            lxc_running = "RUNNING" in out.upper()
        rc, out = run(["lxc-info", "-n", m.lxc, "-c", "lxc.start.auto"])
        if rc == 0:
            lxc_autostart = out.strip().endswith("1")

    portal_routed = None
    if m.portal_domain is not None:
        portal_routed = m.portal_domain in (routes if routes is not None else load_routes())

    return Actual(enabled=enabled, active=active, lxc_running=lxc_running,
                  lxc_autostart=lxc_autostart, portal_routed=portal_routed, rss_kb=rss)


def is_on(a: Actual) -> bool:
    """Un module est ON s'il est enabled ET actif. `enabled` seul survit au
    reboot mais ne sert à rien maintenant ; `active` seul ne survit pas."""
    return bool(a.enabled) and bool(a.active)
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_observe.py -q
```
Attendu : `8 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-profiles/api/observe.py packages/secubox-profiles/tests/test_observe.py
git commit -m "feat(profiles): sondes d'état réel en lecture seule

L'inconnu reste None, jamais False : lxc-info échoue depuis le contexte non
privilégié de l'API (lxc_state='absent' alors que le service répond), et un
False inventé produirait une fausse décision d'allumage.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 4 : Calcul du diff ordonné

**Files:**
- Create: `packages/secubox-profiles/api/diff.py`
- Test: `packages/secubox-profiles/tests/test_diff.py`

**Interfaces:**
- Consumes: `Manifest` (`api.manifest`), `Profile`/`resolve` (`api.state`), `Actual`/`is_on` (`api.observe`).
- Produces: `Change` (dataclass gelée : `id: str`, `action: str` ∈ {`start`,`stop`}, `reason: str`, `priority: int`), `ProtectedViolation(Exception)`, `plan_changes(manifests: dict[str, Manifest], profile, pins, actuals: dict[str, Actual]) -> list[Change]`.

- [ ] **Step 1 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_diff.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import pytest

from api.diff import Change, ProtectedViolation, plan_changes
from api.manifest import Manifest
from api.observe import Actual
from api.state import Profile


def mk(mid, priority=50, protected=False):
    return Manifest(id=mid, category="media", runtime="native", exposure="lan",
                    units=(f"secubox-{mid}.service",), priority=priority,
                    protected=protected)


def on():
    return Actual(enabled=True, active=True)


def off():
    return Actual(enabled=False, active=False)


def test_no_changes_when_already_converged():
    ms = {"lyrion": mk("lyrion")}
    prof = Profile(name="media", label="m", on=frozenset({"lyrion"}))
    assert plan_changes(ms, prof, {}, {"lyrion": on()}) == []


def test_start_what_profile_wants_and_stop_what_it_does_not():
    ms = {"lyrion": mk("lyrion"), "gitea": mk("gitea")}
    prof = Profile(name="media", label="m", on=frozenset({"lyrion"}))
    actual = {"lyrion": off(), "gitea": on()}
    changes = plan_changes(ms, prof, {}, actual)
    assert {(c.id, c.action) for c in changes} == {("lyrion", "start"), ("gitea", "stop")}


def test_all_stops_come_before_all_starts():
    # La box a ~2 Go libres : allumer avant d'éteindre ferait un pic fatal.
    ms = {"a": mk("a", priority=10), "b": mk("b", priority=90)}
    prof = Profile(name="p", label="p", on=frozenset({"a"}))
    changes = plan_changes(ms, prof, {}, {"a": off(), "b": on()})
    assert [c.action for c in changes] == ["stop", "start"]


def test_stops_ordered_by_ascending_priority():
    # Le moins prioritaire s'éteint en premier ; le plus prioritaire tient
    # le plus longtemps.
    ms = {"hi": mk("hi", priority=90), "lo": mk("lo", priority=10), "mid": mk("mid", priority=50)}
    prof = Profile(name="p", label="p", on=frozenset())
    actual = {k: on() for k in ms}
    changes = plan_changes(ms, prof, {}, actual)
    assert [c.id for c in changes] == ["lo", "mid", "hi"]


def test_starts_ordered_by_descending_priority():
    ms = {"hi": mk("hi", priority=90), "lo": mk("lo", priority=10), "mid": mk("mid", priority=50)}
    prof = Profile(name="p", label="p", on=frozenset({"hi", "lo", "mid"}))
    actual = {k: off() for k in ms}
    changes = plan_changes(ms, prof, {}, actual)
    assert [c.id for c in changes] == ["hi", "mid", "lo"]


def test_protected_module_never_stopped():
    # Refus, pas avertissement : sans ça un profil éteint l'auth et
    # l'utilisateur perd tout moyen de revenir.
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    plan = plan_changes(ms, prof, {}, {"auth": on()})
    assert plan == []   # protected → désiré ON → déjà ON → aucun changement


def test_protected_module_off_is_started_not_refused():
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    plan = plan_changes(ms, prof, {}, {"auth": off()})
    assert [(c.id, c.action) for c in plan] == [("auth", "start")]


def test_pin_off_on_protected_module_is_refused():
    ms = {"auth": mk("auth", protected=True)}
    prof = Profile(name="p", label="p", on=frozenset())
    with pytest.raises(ProtectedViolation):
        plan_changes(ms, prof, {"auth": "off"}, {"auth": on()})


def test_change_carries_reason():
    ms = {"gitea": mk("gitea")}
    prof = Profile(name="media", label="m", on=frozenset())
    c = plan_changes(ms, prof, {}, {"gitea": on()})[0]
    assert c.reason and isinstance(c.reason, str)


def test_module_without_observation_is_skipped():
    # Un manifeste sans observation (module absent de la board) ne doit pas
    # produire de changement fantôme.
    ms = {"ghost": mk("ghost")}
    prof = Profile(name="p", label="p", on=frozenset({"ghost"}))
    assert plan_changes(ms, prof, {}, {}) == []
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_diff.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.diff'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-profiles/api/diff.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — diff état désiré vs état réel
CyberMind — https://cybermind.fr

Fonction pure : produit un plan ORDONNÉ de changements. Phase 1 se contente de
l'afficher ; Phase 3 l'exécutera. L'ordre est une décision de sûreté, pas une
préférence esthétique :

  * tous les stop avant tous les start — la box tourne sur ~2 Go libres, allumer
    avant d'éteindre ferait un pic fatal ;
  * stop par priorité croissante  — le moins prioritaire s'éteint en premier ;
  * start par priorité décroissante — le plus prioritaire s'allume en premier.
"""
from __future__ import annotations

from dataclasses import dataclass

from .manifest import Manifest
from .observe import Actual, is_on
from .state import OFF, ON, Profile, resolve

START, STOP = "start", "stop"


class ProtectedViolation(Exception):
    """Un changement tenterait d'éteindre un module protégé."""


@dataclass(frozen=True)
class Change:
    id: str
    action: str
    reason: str
    priority: int


def plan_changes(manifests: dict[str, Manifest], profile: Profile | None,
                 pins: dict[str, str], actuals: dict[str, Actual]) -> list[Change]:
    """Plan ordonné pour converger vers l'état désiré.

    Lève ProtectedViolation si un pin tente d'éteindre un module protégé — un
    refus, pas un avertissement : un profil qui éteint l'auth laisse
    l'utilisateur sans aucun moyen de revenir.
    """
    for mid, m in manifests.items():
        if m.protected and pins.get(mid) == OFF:
            raise ProtectedViolation(
                f"{mid} est protégé et ne peut pas être épinglé sur 'off'")

    stops: list[Change] = []
    starts: list[Change] = []
    for mid, m in sorted(manifests.items()):
        actual = actuals.get(mid)
        if actual is None:
            continue  # module non observé : pas de changement fantôme
        desired = resolve(m, profile, pins)
        currently_on = is_on(actual)
        if desired == ON and not currently_on:
            starts.append(Change(id=mid, action=START, priority=m.priority,
                                 reason=_reason(m, profile, pins, ON)))
        elif desired == OFF and currently_on:
            stops.append(Change(id=mid, action=STOP, priority=m.priority,
                                reason=_reason(m, profile, pins, OFF)))

    stops.sort(key=lambda c: (c.priority, c.id))            # moins prioritaire d'abord
    starts.sort(key=lambda c: (-c.priority, c.id))          # plus prioritaire d'abord
    return stops + starts


def _reason(m: Manifest, profile: Profile | None, pins: dict[str, str], desired: str) -> str:
    if m.protected:
        return "module protégé (toujours allumé)"
    if pins.get(m.id) in (ON, OFF):
        return f"épinglé sur '{pins[m.id]}'"
    if profile is not None and m.id in profile.on:
        return f"listé dans le profil '{profile.name}'"
    if profile is not None:
        return f"absent du profil '{profile.name}'"
    return "aucun profil actif"
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_diff.py -q
```
Attendu : `10 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-profiles/api/diff.py packages/secubox-profiles/tests/test_diff.py
git commit -m "feat(profiles): diff ordonné désiré vs réel

Ordre = décision de sûreté : stops avant starts (la box a ~2 Go libres, un pic
d'allumage la tuerait), stops par priorité croissante, starts par décroissante.
Un pin 'off' sur un module protégé est refusé, pas averti.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 5 : Profiler `scan` — dériver les manifestes du réel

**Files:**
- Create: `packages/secubox-profiles/api/scan.py`
- Test: `packages/secubox-profiles/tests/test_scan.py`

**Interfaces:**
- Consumes: `Manifest`, `RUNTIMES`/`EXPOSURES`/`CATEGORIES` (`api.manifest`), `load_routes` (`api.observe`).
- Produces: `discover(*, units: list[str], lxc_names: set[str], routes: set[str], menu_dir: Path) -> list[Manifest]`, `to_toml(m: Manifest) -> str`, `write_drafts(manifests, out_dir: Path, *, force: bool = False) -> list[Path]`.

- [ ] **Step 1 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_scan.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.manifest import Manifest, load_manifest
from api.scan import discover, to_toml, write_drafts


def menu(tmp_path, mid, category="mesh"):
    d = tmp_path / "menu.d"
    d.mkdir(exist_ok=True)
    (d / f"{mid}.json").write_text(json.dumps(
        {"id": mid, "name": mid.title(), "category": category, "path": f"/{mid}/"}))
    return d


def test_discover_native_module(tmp_path):
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion"))
    assert len(m) == 1
    assert m[0].id == "lyrion" and m[0].runtime == "native"
    assert m[0].units == ("secubox-lyrion.service",)


def test_discover_marks_lxc_runtime(tmp_path):
    m = discover(units=["secubox-peertube.service"], lxc_names={"peertube"}, routes=set(),
                 menu_dir=menu(tmp_path, "peertube"))[0]
    assert m.runtime == "lxc" and m.lxc == "peertube"


def test_discover_marks_public_exposure_from_routes(tmp_path):
    m = discover(units=["secubox-peertube.service"], lxc_names=set(),
                 routes={"peertube.gk2.secubox.in"},
                 menu_dir=menu(tmp_path, "peertube"))[0]
    assert m.exposure == "public" and m.portal_domain == "peertube.gk2.secubox.in"


def test_discover_lan_only_when_menu_but_no_route(tmp_path):
    # Lyrion : a une entrée de menu (accès LAN) mais aucune route WAF publique.
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion"))[0]
    assert m.exposure == "lan"


def test_discover_internal_when_no_menu_and_no_route(tmp_path):
    (tmp_path / "menu.d").mkdir()
    m = discover(units=["secubox-core.service"], lxc_names=set(), routes=set(),
                 menu_dir=tmp_path / "menu.d")[0]
    assert m.exposure == "internal"


def test_discover_protects_the_core_set(tmp_path):
    # Sans ça, le tout premier scan produirait des manifestes qui autorisent
    # à éteindre l'auth.
    (tmp_path / "menu.d").mkdir()
    got = {m.id: m for m in discover(
        units=["secubox-auth.service", "secubox-aggregator.service", "secubox-lyrion.service"],
        lxc_names=set(), routes=set(), menu_dir=tmp_path / "menu.d")}
    assert got["auth"].protected is True
    assert got["aggregator"].protected is True
    assert got["lyrion"].protected is False


def test_discover_maps_unknown_menu_category_to_infra(tmp_path):
    # menu.d utilise ses propres catégories UI ("mesh") : on ne les recopie
    # pas aveuglément dans la taxonomie de déploiement.
    m = discover(units=["secubox-lyrion.service"], lxc_names=set(), routes=set(),
                 menu_dir=menu(tmp_path, "lyrion", category="n-importe-quoi"))[0]
    assert m.category in ("media", "security", "network", "infra", "dev", "mesh")


def test_to_toml_roundtrips_through_the_loader(tmp_path):
    # L'émetteur est écrit à la main (pas d'écrivain TOML en stdlib) : le seul
    # test qui compte est que le loader relise ce qu'on a écrit.
    src = Manifest(id="peertube", category="media", runtime="lxc", exposure="public",
                   units=("secubox-peertube.service",), lxc="peertube",
                   portal_domain="peertube.gk2.secubox.in", priority=40,
                   protected=False, needs=("auth",))
    p = tmp_path / "peertube.toml"
    p.write_text(to_toml(src))
    assert load_manifest(p) == src


def test_to_toml_roundtrips_minimal_manifest(tmp_path):
    src = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                   units=("secubox-lyrion.service",))
    p = tmp_path / "lyrion.toml"
    p.write_text(to_toml(src))
    assert load_manifest(p) == src


def test_write_drafts_never_overwrites_without_force(tmp_path):
    # Un manifeste corrigé à la main fait autorité sur une dérivation.
    out = tmp_path / "modules.d"
    out.mkdir()
    existing = out / "lyrion.toml"
    existing.write_text("# corrigé à la main\n")
    m = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                 units=("secubox-lyrion.service",))
    written = write_drafts([m], out, force=False)
    assert written == []
    assert existing.read_text() == "# corrigé à la main\n"


def test_write_drafts_overwrites_with_force(tmp_path):
    out = tmp_path / "modules.d"
    out.mkdir()
    (out / "lyrion.toml").write_text("# ancien\n")
    m = Manifest(id="lyrion", category="media", runtime="native", exposure="lan",
                 units=("secubox-lyrion.service",))
    written = write_drafts([m], out, force=True)
    assert written == [out / "lyrion.toml"]
    assert load_manifest(out / "lyrion.toml") == m
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_scan.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.scan'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-profiles/api/scan.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — profiler : dérive les manifestes du réel
CyberMind — https://cybermind.fr

On ne rédige pas 134 manifestes à la main : `scan` les dérive des units
systemd, des conteneurs LXC, des routes WAF et des menu.d/ existants, puis
l'opérateur corrige. Un manifeste corrigé fait ensuite autorité — d'où le
refus d'écraser sans --force.

Il n'existe pas d'écrivain TOML en stdlib (tomllib est en lecture seule) et le
schéma est petit et fixe : l'émetteur est écrit à la main plutôt que d'ajouter
une dépendance. Le test qui compte est l'aller-retour to_toml -> load_manifest.
"""
from __future__ import annotations

import json
from pathlib import Path

from .manifest import CATEGORIES, Manifest

MENU_DIR = Path("/usr/share/secubox/menu.d")

# Le noyau protégé : éteindre l'un de ceux-là retire à l'utilisateur le moyen
# de rallumer quoi que ce soit. Le premier scan doit déjà les marquer.
PROTECTED_IDS = frozenset({"auth", "aggregator", "core", "nginx", "firewall", "profiles"})

UNIT_PREFIX = "secubox-"
UNIT_SUFFIX = ".service"


def _id_from_unit(unit: str) -> str:
    return unit[len(UNIT_PREFIX):-len(UNIT_SUFFIX)]


def _menu_index(menu_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in sorted(Path(menu_dir).glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(d, dict) and d.get("id"):
            out[d["id"]] = d
    return out


def _category(menu: dict | None) -> str:
    # menu.d porte des catégories UI qui ne sont pas la taxonomie de
    # déploiement ; on ne recopie que celles qui coïncident, sinon infra.
    cat = (menu or {}).get("category")
    return cat if cat in CATEGORIES else "infra"


def _route_for(mid: str, routes: set[str]) -> str | None:
    for r in sorted(routes):
        if r.split(".")[0] == mid:
            return r
    return None


def discover(*, units: list[str], lxc_names: set[str], routes: set[str],
             menu_dir: Path = MENU_DIR) -> list[Manifest]:
    """Dérive un manifeste par unit secubox-*.service."""
    menus = _menu_index(menu_dir)
    out: list[Manifest] = []
    for unit in sorted(units):
        if not (unit.startswith(UNIT_PREFIX) and unit.endswith(UNIT_SUFFIX)):
            continue
        mid = _id_from_unit(unit)
        menu = menus.get(mid)
        domain = _route_for(mid, routes)
        if domain:
            exposure = "public"
        elif menu:
            exposure = "lan"       # entrée de menu mais pas de route publique (ex. lyrion)
        else:
            exposure = "internal"
        out.append(Manifest(
            id=mid,
            category=_category(menu),
            runtime="lxc" if mid in lxc_names else "native",
            exposure=exposure,
            units=(unit,),
            lxc=mid if mid in lxc_names else None,
            portal_domain=domain,
            protected=mid in PROTECTED_IDS,
        ))
    return out


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_list(items) -> str:
    return "[" + ", ".join(_toml_str(str(i)) for i in items) + "]"


def to_toml(m: Manifest) -> str:
    """Émet un manifeste. Aller-retour garanti avec load_manifest."""
    lines = [
        "# SPDX-License-Identifier: LicenseRef-CMSD-1.0",
        "# Manifeste dérivé par `secubox-profilectl scan` — corrigez-le, il fera",
        "# ensuite autorité (scan n'écrase pas sans --force).",
        f"id        = {_toml_str(m.id)}",
        f"category  = {_toml_str(m.category)}",
        f"runtime   = {_toml_str(m.runtime)}",
        f"exposure  = {_toml_str(m.exposure)}",
        f"units     = {_toml_list(m.units)}",
    ]
    if m.lxc:
        lines.append(f"lxc       = {_toml_str(m.lxc)}")
    if m.portal_domain:
        lines.append(f"portal    = {{ domain = {_toml_str(m.portal_domain)} }}")
    lines.append(f"priority  = {m.priority}")
    lines.append(f"protected = {'true' if m.protected else 'false'}")
    if m.needs:
        lines.append(f"needs     = {_toml_list(m.needs)}")
    return "\n".join(lines) + "\n"


def write_drafts(manifests, out_dir: Path, *, force: bool = False) -> list[Path]:
    """Écrit les manifestes dérivés. N'écrase JAMAIS sans force : un manifeste
    corrigé à la main fait autorité sur une dérivation."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for m in manifests:
        p = out_dir / f"{m.id}.toml"
        if p.exists() and not force:
            continue
        p.write_text(to_toml(m), encoding="utf-8")
        written.append(p)
    return written
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_scan.py -q
```
Attendu : `11 passed`.

- [ ] **Step 5 : commit**

```bash
git add packages/secubox-profiles/api/scan.py packages/secubox-profiles/tests/test_scan.py
git commit -m "feat(profiles): profiler scan — dérive les manifestes du réel

134 manifestes ne s'écrivent pas à la main : on les dérive des units, LXC,
routes WAF et menu.d, puis l'opérateur corrige — et scan n'écrase plus.
Émetteur TOML écrit à la main (tomllib est en lecture seule), validé par
aller-retour avec le loader.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 6 : CLI `secubox-profilectl` (scan/status/diff) + packaging

**Files:**
- Create: `packages/secubox-profiles/api/cli.py`
- Create: `packages/secubox-profiles/sbin/secubox-profilectl`
- Create: `packages/secubox-profiles/debian/control`
- Create: `packages/secubox-profiles/debian/rules`
- Create: `packages/secubox-profiles/debian/install`
- Create: `packages/secubox-profiles/debian/changelog`
- Create: `packages/secubox-profiles/debian/compat`
- Create: `packages/secubox-profiles/README.md`
- Test: `packages/secubox-profiles/tests/test_cli.py`

**Interfaces:**
- Consumes: tout ce qui précède.
- Produces: `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1 : test qui échoue**

Créer `packages/secubox-profiles/tests/test_cli.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

import pytest

from api.cli import main

MANIFEST = """
id       = "lyrion"
category = "media"
runtime  = "native"
exposure = "lan"
units    = ["secubox-lyrion.service"]
priority = 30
"""


@pytest.fixture()
def root(tmp_path):
    (tmp_path / "modules.d").mkdir()
    (tmp_path / "modules.d" / "lyrion.toml").write_text(MANIFEST)
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "media.toml").write_text(
        'name = "media"\nlabel = "🎬 Média"\non = ["lyrion"]\n')
    return tmp_path


def test_status_json_lists_modules(root, capsys, monkeypatch):
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True, rss_kb=1024)})
    rc = main(["--root", str(root), "status", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["modules"][0]["id"] == "lyrion"
    assert out["modules"][0]["on"] is True
    assert out["modules"][0]["category"] == "media"


def test_diff_reports_no_change_when_converged(root, capsys, monkeypatch):
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True)})
    rc = main(["--root", str(root), "diff", "--profile", "media", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["changes"] == []


def test_diff_reports_stop_for_module_absent_from_profile(root, capsys, monkeypatch):
    (root / "profiles" / "vide.toml").write_text('name = "vide"\nlabel = "v"\non = []\n')
    monkeypatch.setattr("api.cli._observe_all",
                        lambda ms, routes: {"lyrion": __import__(
                            "api.observe", fromlist=["Actual"]).Actual(
                                enabled=True, active=True)})
    rc = main(["--root", str(root), "diff", "--profile", "vide", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["changes"] == [{"id": "lyrion", "action": "stop", "priority": 30,
                               "reason": "absent du profil 'vide'"}]


def test_diff_unknown_profile_errors(root, capsys):
    rc = main(["--root", str(root), "diff", "--profile", "fantome", "--json"])
    assert rc == 2


def test_apply_is_not_a_command_in_phase_1(root):
    # Garde-fou : Phase 1 est en lecture seule. Si `apply` apparaît ici, c'est
    # que quelqu'un a court-circuité la Phase 3.
    with pytest.raises(SystemExit):
        main(["--root", str(root), "apply"])
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.cli'`.

- [ ] **Step 3 : implémenter la CLI**

Créer `packages/secubox-profiles/api/cli.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: profiles — CLI secubox-profilectl
CyberMind — https://cybermind.fr

Phase 1 : LECTURE SEULE. `scan`, `status`, `diff` — et rien d'autre. `apply`
n'existe pas encore : il arrive en Phase 3, avec snapshot 4R, application
séquentielle et audit.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .diff import ProtectedViolation, plan_changes
from .manifest import ManifestError, load_all
from .observe import Actual, is_on, load_routes, observe
from .scan import discover, write_drafts
from .state import StateError, load_pins, load_profile

DEFAULT_ROOT = Path("/etc/secubox")


def _paths(root: Path):
    return (root / "modules.d", root / "profiles",
            root / "profiles" / "pins.toml", root / "profiles" / "active")


def _observe_all(manifests, routes):
    return {mid: observe(m, routes=routes) for mid, m in manifests.items()}


def _active_profile_name(root: Path, override: str | None) -> str | None:
    if override:
        return override
    _, _, _, active = _paths(root)
    if active.exists():
        name = active.read_text(encoding="utf-8").strip()
        return name or None
    return None


def _load_profile_or_none(root: Path, name: str | None):
    if not name:
        return None
    _, prof_dir, _, _ = _paths(root)
    p = prof_dir / f"{name}.toml"
    if not p.exists():
        raise StateError(f"profil inconnu: {name} ({p} absent)")
    return load_profile(p)


def _cmd_status(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    routes = load_routes()
    actuals = _observe_all(manifests, routes)
    rows = []
    for mid, m in sorted(manifests.items()):
        a = actuals.get(mid, Actual())
        rows.append({
            "id": mid, "category": m.category, "runtime": m.runtime,
            "exposure": m.exposure, "priority": m.priority,
            "protected": m.protected, "on": is_on(a), "rss_kb": a.rss_kb,
        })
    if args.json:
        print(json.dumps({"modules": rows}, ensure_ascii=False))
        return 0
    for r in sorted(rows, key=lambda r: (-r["priority"], r["id"])):
        rss = f"{r['rss_kb'] / 1024:.0f} Mo" if r["rss_kb"] else "—"
        print(f"{'🟢' if r['on'] else '⚫'} {r['id']:<20} {r['category']:<9} "
              f"{r['runtime']:<7} {r['exposure']:<9} prio={r['priority']:<3} {rss:>8}"
              f"{'  🔒' if r['protected'] else ''}")
    return 0


def _cmd_diff(args) -> int:
    root = Path(args.root)
    mod_dir, _, pins_file, _ = _paths(root)
    manifests = load_all(mod_dir)
    profile = _load_profile_or_none(root, _active_profile_name(root, args.profile))
    pins = load_pins(pins_file)
    actuals = _observe_all(manifests, load_routes())
    changes = plan_changes(manifests, profile, pins, actuals)
    payload = [{"id": c.id, "action": c.action, "priority": c.priority,
                "reason": c.reason} for c in changes]
    if args.json:
        print(json.dumps({"changes": payload}, ensure_ascii=False))
        return 0
    if not changes:
        print("✅ rien à changer — l'état réel correspond déjà au profil.")
        return 0
    print(f"{len(changes)} changement(s) — Phase 1 n'applique rien :")
    for c in changes:
        print(f"  {'⛔ stop ' if c.action == 'stop' else '▶️  start'} {c.id:<20} ({c.reason})")
    return 0


def _cmd_scan(args) -> int:
    root = Path(args.root)
    mod_dir, _, _, _ = _paths(root)
    rc, out = _run(["systemctl", "list-unit-files", "secubox-*.service",
                    "--no-legend", "--plain"])
    units = [line.split()[0] for line in out.splitlines() if line.strip()]
    rc, out = _run(["lxc-ls", "-1"])
    lxc_names = {n.strip() for n in out.splitlines() if n.strip()}
    manifests = discover(units=units, lxc_names=lxc_names, routes=load_routes())
    written = write_drafts(manifests, mod_dir, force=args.force)
    skipped = len(manifests) - len(written)
    print(f"{len(manifests)} module(s) découvert(s) — {len(written)} manifeste(s) écrit(s), "
          f"{skipped} conservé(s) (déjà présents ; --force pour écraser).")
    return 0


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="secubox-profilectl",
        description="Inventaire et diff des modules SecuBox (Phase 1 : lecture seule).")
    p.add_argument("--root", default=str(DEFAULT_ROOT),
                   help="racine de config (défaut: /etc/secubox)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("status", help="état et coût de chaque module")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_status)

    sp = sub.add_parser("diff", help="ce qu'un profil changerait (n'applique rien)")
    sp.add_argument("--profile", default=None)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_diff)

    sp = sub.add_parser("scan", help="dériver les manifestes du réel")
    sp.add_argument("--force", action="store_true",
                    help="écraser les manifestes existants (ils font autorité par défaut)")
    sp.set_defaults(func=_cmd_scan)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ManifestError, StateError) as exc:
        print(f"erreur: {exc}", file=sys.stderr)
        return 2
    except ProtectedViolation as exc:
        print(f"refusé: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests/test_cli.py -q
```
Attendu : `5 passed`.

- [ ] **Step 5 : entrypoint + packaging**

Créer `packages/secubox-profiles/sbin/secubox-profilectl` (`chmod 755`) :

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-profilectl
set -euo pipefail
readonly MODULE="profiles"
readonly VERSION="0.1.0"
cd /usr/lib/secubox/profiles
exec /usr/bin/python3 -m api.cli "$@"
```

Créer `packages/secubox-profiles/debian/control` :

```
Source: secubox-profiles
Section: admin
Priority: optional
Maintainer: Gerald KERMA <devel@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-profiles
Architecture: all
Depends: ${misc:Depends}, python3 (>= 3.11), secubox-core
Description: SecuBox — inventaire et profils de modules (phase 1, lecture seule)
 Manifestes de modules, profiler de configuration, état et diff.
 Phase 1 n'applique aucun changement : scan/status/diff uniquement.
```

Créer `packages/secubox-profiles/debian/compat` contenant `13`.

Créer `packages/secubox-profiles/debian/rules` (`chmod 755`) :

```makefile
#!/usr/bin/make -f
%:
	dh $@
```

Créer `packages/secubox-profiles/debian/install` :

```
api/*.py               usr/lib/secubox/profiles/api/
sbin/secubox-profilectl usr/sbin/
```

Créer `packages/secubox-profiles/debian/changelog` :

```
secubox-profiles (0.1.0-1~bookworm1) bookworm; urgency=medium

  * Phase 1 : manifestes, profiler scan, status, diff (lecture seule).

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 17 Jul 2026 12:00:00 +0200
```

Créer `packages/secubox-profiles/README.md` :

```markdown
# secubox-profiles

Inventaire et profils des modules SecuBox. **Phase 1 : lecture seule.**

## Commandes

    secubox-profilectl scan [--force]   # dérive les manifestes du réel
    secubox-profilectl status [--json]  # état, taxonomie et coût RAM par module
    secubox-profilectl diff --profile <nom> [--json]   # ce qu'un profil changerait

`apply` n'existe pas encore (Phase 3) : rien n'est jamais allumé ni éteint ici.

## Fichiers

| Chemin | Rôle |
|---|---|
| `/etc/secubox/modules.d/<id>.toml` | manifeste module (cycle de vie) |
| `/etc/secubox/profiles/<nom>.toml` | profil (état désiré, exhaustif) |
| `/etc/secubox/profiles/pins.toml` | surcharges individuelles persistantes |
| `/etc/secubox/profiles/active` | nom du profil actif |

`menu.d/` reste la source UI (path, ordre, icône) et n'est pas dupliqué ici.

## Manifeste

    id        = "peertube"
    category  = "media"     # media|security|network|infra|dev|mesh
    runtime   = "lxc"       # native|lxc
    exposure  = "public"    # public|lan|internal
    units     = ["secubox-peertube.service"]
    lxc       = "peertube"
    portal    = { domain = "peertube.gk2.secubox.in" }
    priority  = 40          # 0-100
    protected = false       # true = jamais éteignable
    needs     = ["auth"]

Un manifeste corrigé à la main fait autorité : `scan` ne l'écrase pas sans `--force`.

## Tests

    python3 -m pytest packages/secubox-profiles/tests -q
```

- [ ] **Step 6 : suite complète**

```bash
.venv/bin/python -m pytest packages/secubox-profiles/tests -q
```
Attendu : `55 passed`.

- [ ] **Step 7 : vérifier sur la vraie board (lecture seule)**

```bash
scp -r packages/secubox-profiles/api root@192.168.1.200:/tmp/profiles-api
ssh root@192.168.1.200 'cd /tmp && mkdir -p profiles && mv profiles-api profiles/api 2>/dev/null; \
  cd /tmp/profiles && mkdir -p /tmp/root/modules.d /tmp/root/profiles && \
  python3 -m api.cli --root /tmp/root scan && python3 -m api.cli --root /tmp/root status | head -20'
```
Attendu : `scan` découvre ~187 modules et écrit les manifestes dans `/tmp/root/modules.d` ; `status` liste les modules avec catégorie, runtime, exposition, priorité et RSS. **Aucun service ne doit changer d'état** — vérifier avec `systemctl list-units "secubox-*" --state=running | wc -l` avant/après : le nombre doit être identique.

- [ ] **Step 8 : commit**

```bash
git add packages/secubox-profiles/
git commit -m "feat(profiles): CLI secubox-profilectl (scan/status/diff) + paquet

Phase 1 en lecture seule : apply n'existe pas, un test le verrouille.
Vérifié sur gk2 : scan découvre les modules et status affiche taxonomie +
coût RSS, sans changer l'état d'un seul service.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

**Couverture du spec (Phase 1)** :

| Exigence du spec | Tâche |
|---|---|
| Manifeste plat, schéma + taxonomie (`runtime`/`exposure`/`category`/`priority`/`protected`/`needs`) | 1 |
| `menu.d` non dupliqué | 1 (le manifeste ne porte ni nom ni icône), 5 (`_menu_index` lit menu.d en source) |
| Profils exhaustifs + pins + ordre `protected > pin > profil > off` | 2 |
| Noyau protégé | 2 (résolution), 4 (refus), 5 (`PROTECTED_IDS` dès le premier scan) |
| État observé, jamais supposé | 3 |
| `diff` : stops avant starts, priorité croissante/décroissante | 4 |
| Profiler : dérive + mesure du coût | 5 (dérive), 3 (`rss_kb`), 6 (affichage) |
| `scan` n'écrase pas un manifeste corrigé | 5 |
| CLI `scan`/`status`/`diff` | 6 |
| **Lecture seule** | 6 (test `test_apply_is_not_a_command_in_phase_1`), 3 (aucune commande mutante) |

Hors Phase 1, donc absent de ce plan (et c'est voulu) : `apply`, snapshot 4R, réconciliation au boot, `Requires`→`Wants`, panneau webui, module Companion, stats par catégorie, métriques mesh.

**Placeholders** : aucun — chaque étape porte son code complet et sa commande exacte.

**Cohérence des types** : `Manifest` (Task 1) est consommé tel quel par 2/3/4/5 ; `Profile`/`resolve` (2) par 4 ; `Actual`/`is_on` (3) par 4 et 6 ; `Change` (4) par 6. Les noms `load_manifest`/`load_all`/`load_profile`/`load_pins`/`resolve`/`observe`/`is_on`/`load_routes`/`plan_changes`/`discover`/`to_toml`/`write_drafts`/`main` sont identiques partout où ils apparaissent.
