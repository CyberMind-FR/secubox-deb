<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Générateur de règles WAF « produit absent » — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Générer, dans `secubox-cve-triage`, des règles WAF en mode `detect` qui fichent les scanners sondant des produits absents de la box — à partir d'un sous-ensemble Nuclei vendored, filtré par deux barrières de présence.

**Architecture:** Pipeline de fonctions **pures** (extraction Nuclei → candidat ; oracle de présence à deux barrières) plus un adaptateur d'inventaire mince (dpkg ∪ vhosts ∪ modules) et un émetteur additif/atomique qui écrit une seule catégorie `product_absent_probes` dans `waf-rules.json`. Sortie toujours en `detect`, jamais armée.

**Tech Stack:** Python 3.11, `PyYAML` (à ajouter aux deps), stdlib. Aucune autre dépendance.

**Spec:** `docs/superpowers/specs/2026-07-18-waf-product-absent-generator-design.md`

## Global Constraints

- **Zéro faux positif par construction.** Un candidat n'est généré que s'il franchit **les deux** barrières : (1) famille d'appliance connue-absente ET (2) absent de `dpkg ∪ vhosts routés ∪ modules`.
- **Dans le doute, PRÉSENT.** Toute source de présence illisible/indéterminable ⟹ on ne génère rien (mieux vaut rater une sonde que bannir un vrai utilisateur).
- **Sortie toujours en `mode: "detect"`.** Aucun chemin de code n'émet `escalate` ni `block`. La promotion en `escalate` est une décision humaine, hors de ce générateur.
- **Additif et idempotent.** Régénérer ne modifie QUE la catégorie `product_absent_probes` ; les 17 autres catégories de `waf-rules.json` sont préservées. Écriture atomique (temp + `os.replace`).
- **Modules purs sans import de `api.main`.** `api/main.py` lit la config à l'import (comme secubox-waf/users) ; les modules `wafgen/*` ne doivent PAS l'importer, pour rester testables sans board — même leçon que `redact.py`.
- **Vendored, pas de réseau au runtime.** Le service ne clone rien ; il lit le sous-ensemble embarqué. La curation est un script mainteneur hors-ligne.
- Python 3.11, `PyYAML` (`python3-yaml`, à ajouter à `debian/control`). SPDX 4-line header sur chaque `.py`. Commits terminés par `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`. Aucune référence à Claude.
- Tests **par répertoire** : `.venv/bin/python -m pytest packages/secubox-cve-triage/tests -q`. Jamais `pytest common/ packages/` (collision `api`, cf. `pytest.ini`).

En-tête SPDX (copier tel quel) :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
```

---

## Structure des fichiers

```
packages/secubox-cve-triage/
├── api/
│   └── wafgen/
│       ├── __init__.py       # vide
│       ├── extract.py        # PUR : template Nuclei (dict) → Candidate | Rejection
│       ├── presence.py       # PUR : les 2 barrières (appliance allowlist + union)
│       ├── inventory.py      # MINCE : dpkg ∪ routes ∪ menu.d → (present_set, complete)
│       └── emit.py           # ADDITIF/ATOMIQUE : écrit product_absent_probes
├── sbin/
│   └── secubox-cvectl        # CLI : waf-rules generate [--dry-run|--apply]
├── nuclei-subset/            # sous-ensemble vendored (data, shippé) + LICENSE
│   ├── LICENSE               # attribution MIT ProjectDiscovery
│   └── *.yaml                # templates KEV appliance à sonde URL-extractible
├── scripts/
│   └── curate-nuclei-subset.sh   # mainteneur hors-ligne (non runtime)
├── debian/control            # MODIFIER : + python3-yaml
├── debian/install            # MODIFIER : shipper wafgen/, sbin, nuclei-subset/
└── tests/
    ├── conftest.py
    ├── test_extract.py
    ├── test_presence.py
    ├── test_inventory.py
    └── test_emit.py
```

Chaque fichier a une responsabilité : `extract` = ce qu'est une sonde ; `presence` = a-t-on ce produit ; `inventory` = collecte des sources ; `emit` = écrit la catégorie. `inventory` est le seul à toucher le système ; tout le reste est pur.

---

### Task 1 : Extraction Nuclei → candidat (pur)

**Files:**
- Create: `packages/secubox-cve-triage/api/__init__.py` (s'il n'existe pas — vérifier ; ne pas écraser)
- Create: `packages/secubox-cve-triage/api/wafgen/__init__.py` (vide)
- Create: `packages/secubox-cve-triage/api/wafgen/extract.py`
- Create: `packages/secubox-cve-triage/tests/conftest.py`
- Test: `packages/secubox-cve-triage/tests/test_extract.py`

**Interfaces:**
- Consumes: rien (prend un dict déjà parsé).
- Produces: `Candidate` (dataclass gelée : `cve, vendor, product, cpe, path, severity`), `Rejection` (dataclass gelée : `reason: str`), `extract(template: dict) -> Candidate | Rejection`, `is_kev(template: dict) -> bool`.

- [ ] **Step 1 : conftest**

Créer `packages/secubox-cve-triage/tests/conftest.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import sys
from pathlib import Path

# Rend `api` importable en top-level (miroir du layout runtime sous
# /usr/lib/secubox/cve-triage). Les modules wafgen n'importent pas api.main,
# donc pas de lecture de config à l'import.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
```

- [ ] **Step 2 : tests qui échouent**

Créer `packages/secubox-cve-triage/tests/test_extract.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.wafgen.extract import Candidate, Rejection, extract, is_kev

# A clean GET-path template — the kind that becomes a rule.
CLEAN = {
    "id": "CVE-2024-3400",
    "info": {"severity": "critical",
             "classification": {"cve-id": "CVE-2024-3400",
                                "cpe": "cpe:2.3:a:paloaltonetworks:pan-os:*"},
             "metadata": {"vendor": "paloaltonetworks", "product": "pan-os"}},
    "tags": "cve,cve2024,panos,rce,kev,vuln",
    "http": [{"method": "GET",
              "path": ["{{BaseURL}}/api/v1/totp/user-backup"]}],
}

# A raw/unsafe smuggling template — NOT URL-extractable (real F5 CVE-2023-46747 shape).
RAW = {
    "id": "CVE-2023-46747",
    "info": {"severity": "critical", "metadata": {"vendor": "f5", "product": "big-ip"}},
    "tags": "cve,f5,kev",
    "http": [{"raw": ["POST /tmui/login.jsp HTTP/1.1\n..."], "unsafe": True}],
}


def test_clean_template_extracts_a_candidate():
    c = extract(CLEAN)
    assert isinstance(c, Candidate)
    assert c.cve == "CVE-2024-3400"
    assert c.vendor == "paloaltonetworks"
    assert c.product == "pan-os"
    assert c.path == "/api/v1/totp/user-backup"
    assert c.severity == "critical"


def test_raw_template_is_rejected():
    r = extract(RAW)
    assert isinstance(r, Rejection)
    assert "raw" in r.reason.lower()


def test_multistep_template_is_rejected():
    # More than one http block, or a path list with >1 entry → not a single
    # deterministic probe.
    t = dict(CLEAN, http=[{"method": "GET", "path": ["{{BaseURL}}/a", "{{BaseURL}}/b"]}])
    assert isinstance(extract(t), Rejection)


def test_path_with_non_baseurl_placeholder_is_rejected():
    # {{BaseURL}} is fine; any other {{...}} means the probe isn't a fixed URL.
    t = dict(CLEAN, http=[{"method": "GET", "path": ["{{BaseURL}}/x?u={{username}}"]}])
    r = extract(t)
    assert isinstance(r, Rejection)
    assert "placeholder" in r.reason.lower()


def test_body_matcher_only_template_is_rejected():
    # No http path at all (e.g. a network/dns template) → nothing to extract.
    t = {"id": "CVE-2024-9999", "info": {"severity": "high",
         "metadata": {"vendor": "f5", "product": "big-ip"}}, "tags": "cve,kev"}
    assert isinstance(extract(t), Rejection)


def test_missing_vendor_or_product_is_rejected():
    # Without vendor/product the presence oracle can't reason — reject.
    t = dict(CLEAN, info={"severity": "high", "classification": {"cve-id": "CVE-2024-3400"}})
    assert isinstance(extract(t), Rejection)


def test_path_is_regex_escaped_ready():
    # A path with regex-special chars must round-trip literally (the emitter
    # will escape; extract returns the raw path unchanged).
    t = dict(CLEAN, http=[{"method": "GET", "path": ["{{BaseURL}}/mgmt/tm/util/bash"]}])
    assert extract(t).path == "/mgmt/tm/util/bash"


def test_is_kev_reads_the_tag():
    assert is_kev(CLEAN) is True
    assert is_kev(dict(CLEAN, tags="cve,cve2024,rce")) is False
```

- [ ] **Step 3 : lancer — doit échouer**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_extract.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.wafgen'`.

- [ ] **Step 4 : implémenter**

Créer `packages/secubox-cve-triage/api/wafgen/__init__.py` vide, puis `packages/secubox-cve-triage/api/wafgen/extract.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — extraction d'une sonde URL depuis un template Nuclei
CyberMind — https://cybermind.fr

Un template Nuclei ne devient une règle QUE si sa sonde est une requête à chemin
d'URL déterministe. sbxwaf matche une regex sur path+query+body+UA ; on ne peut
donc pas transformer un exploit `raw:`/multi-étapes/body-matcher en règle. Chaque
rejet est explicite (avec sa raison) — le silence surestimerait la couverture.

Fonction pure : prend un dict déjà parsé (le YAML est chargé ailleurs), pour
rester testable sans fichier ni réseau.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# `{{BaseURL}}` est le seul placeholder autorisé : il est remplacé par l'hôte à
# la volée. Tout autre `{{...}}` (username, rand, hex_encode…) signifie que la
# sonde n'est pas une URL fixe → on ne peut pas la matcher déterministement.
_PLACEHOLDER_RE = re.compile(r"\{\{(?!BaseURL\}\})[^}]*\}\}")
_BASEURL_RE = re.compile(r"^\{\{BaseURL\}\}")


@dataclass(frozen=True)
class Candidate:
    cve: str
    vendor: str
    product: str
    cpe: str
    path: str
    severity: str


@dataclass(frozen=True)
class Rejection:
    reason: str


def is_kev(template: dict) -> bool:
    """True si le template porte le tag KEV (exploité pour de vrai)."""
    tags = template.get("tags", "")
    if isinstance(tags, list):
        tags = ",".join(tags)
    return "kev" in [t.strip().lower() for t in str(tags).split(",")]


def _meta(template: dict) -> dict:
    info = template.get("info", {}) or {}
    return info.get("metadata", {}) or {}


def _classification(template: dict) -> dict:
    info = template.get("info", {}) or {}
    return info.get("classification", {}) or {}


def extract(template: dict) -> Candidate | Rejection:
    """template Nuclei parsé → Candidate (sonde URL extractible) ou Rejection."""
    meta = _meta(template)
    vendor = (meta.get("vendor") or "").strip().lower()
    product = (meta.get("product") or "").strip().lower()
    if not vendor or not product:
        return Rejection("missing vendor/product metadata")

    http = template.get("http") or template.get("requests") or []
    if not isinstance(http, list) or len(http) != 1:
        return Rejection("not a single http block (multi-step or none)")
    block = http[0]

    if block.get("raw") is not None or block.get("unsafe"):
        return Rejection("raw/unsafe request — not a URL path")

    paths = block.get("path")
    if not isinstance(paths, list) or len(paths) != 1:
        return Rejection("not a single path (multi-request or body-only)")
    raw_path = paths[0]

    if _PLACEHOLDER_RE.search(raw_path):
        return Rejection("path contains a non-BaseURL placeholder")
    path = _BASEURL_RE.sub("", raw_path)
    if not path.startswith("/"):
        return Rejection("path is not anchored at /")

    cls = _classification(template)
    cve = cls.get("cve-id") or template.get("id") or ""
    info = template.get("info", {}) or {}
    return Candidate(
        cve=cve,
        vendor=vendor,
        product=product,
        cpe=cls.get("cpe", ""),
        path=path,
        severity=info.get("severity", "high"),
    )
```

- [ ] **Step 5 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_extract.py -q
```
Attendu : `8 passed`.

- [ ] **Step 6 : preuve par mutation**

Remplacer temporairement `if block.get("raw") is not None or block.get("unsafe"):` par `if False:`, relancer → `test_raw_template_is_rejected` **FAIL**. Restaurer, reconfirmer. Consigner.

- [ ] **Step 7 : commit**

```bash
git add packages/secubox-cve-triage/api/__init__.py packages/secubox-cve-triage/api/wafgen/ \
        packages/secubox-cve-triage/tests/conftest.py packages/secubox-cve-triage/tests/test_extract.py
git commit -m "feat(cve-triage): extract a URL probe from a Nuclei template

Pure function: only a single-http, single-path, BaseURL-only GET/POST becomes a
candidate. raw/unsafe/multi-step/body-matcher templates are rejected with a
reason — sbxwaf matches URL regex, so a non-URL exploit can't become a rule.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2 : L'oracle de présence — les deux barrières (pur)

**Files:**
- Create: `packages/secubox-cve-triage/api/wafgen/presence.py`
- Test: `packages/secubox-cve-triage/tests/test_presence.py`

**Interfaces:**
- Consumes: `Candidate` de `api.wafgen.extract`.
- Produces: `APPLIANCE_VENDORS` (frozenset), `is_appliance(candidate) -> bool`, `should_generate(candidate, present: set[str], present_complete: bool) -> bool`.

- [ ] **Step 1 : tests qui échouent**

Créer `packages/secubox-cve-triage/tests/test_presence.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api.wafgen.extract import Candidate
from api.wafgen.presence import APPLIANCE_VENDORS, is_appliance, should_generate


def cand(vendor="f5", product="big-ip", path="/mgmt/tm/util/bash"):
    return Candidate(cve="CVE-2023-1", vendor=vendor, product=product,
                     cpe=f"cpe:2.3:a:{vendor}:{product}:*", path=path, severity="high")


def test_appliance_families_are_recognised():
    for v in ("f5", "paloaltonetworks", "ivanti", "citrix", "fortinet"):
        assert is_appliance(cand(vendor=v)) is True


def test_non_appliance_vendor_is_not():
    for v in ("php", "wordpress", "nginx", "apache"):
        assert is_appliance(cand(vendor=v)) is False


def test_generate_requires_BOTH_appliance_AND_absent():
    # appliance + absent from the union → generate.
    assert should_generate(cand(), present=set(), present_complete=True) is True


def test_present_in_union_is_never_generated():
    # Even an appliance vendor: if the product is somehow present, do not generate.
    assert should_generate(cand(), present={"big-ip"}, present_complete=True) is False


def test_non_appliance_is_never_generated_even_if_absent():
    assert should_generate(cand(vendor="php", product="php"),
                           present=set(), present_complete=True) is False


def test_incomplete_inventory_generates_nothing():
    # Fail-safe: if a presence source could not be read, treat as present →
    # never generate (better to miss a probe than ban a real user).
    assert should_generate(cand(), present=set(), present_complete=False) is False


def test_present_match_is_case_insensitive_and_on_vendor_or_product():
    assert should_generate(cand(), present={"F5"}, present_complete=True) is False
    assert should_generate(cand(), present={"BIG-IP"}, present_complete=True) is False
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_presence.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.wafgen.presence'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-cve-triage/api/wafgen/presence.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — oracle de présence (deux barrières)
CyberMind — https://cybermind.fr

Le mode d'échec à tuer : croire un produit absent alors qu'il est présent → règle
qui matche du trafic légitime → en escalate, ban d'un vrai utilisateur. D'où deux
garde-fous indépendants ; un candidat ne passe que s'il franchit les deux.

Fonction pure : `present` (l'union des sources) et `present_complete` (toutes les
sources ont-elles été lues) sont injectés — la collecte réelle est dans
inventory.py. Règle de sûreté : dans le doute, PRÉSENT (ne rien générer).
"""
from __future__ import annotations

from .extract import Candidate

# Familles d'équipements réseau qu'une box Debian SecuBox n'est CATÉGORIQUEMENT
# jamais. Assertion humaine, versionnée — pas dérivée automatiquement. Un vendor
# hors de cette liste n'est jamais généré, même « prouvé absent » (le mapping
# serait trop faillible).
APPLIANCE_VENDORS = frozenset({
    "f5", "paloaltonetworks", "ivanti", "citrix", "fortinet", "cisco",
    "vmware", "sonicwall", "zyxel", "dlink", "netgear", "juniper",
})


def is_appliance(candidate: Candidate) -> bool:
    """Barrière 1 : le vendor est-il une famille d'appliance connue-absente ?"""
    return candidate.vendor.strip().lower() in APPLIANCE_VENDORS


def should_generate(candidate: Candidate, present: set[str], present_complete: bool) -> bool:
    """Un candidat n'est généré que s'il franchit LES DEUX barrières.

    Barrière 1 : famille d'appliance (is_appliance).
    Barrière 2 : absent de l'union de présence — ET l'union est complète.
    Dans le doute (present_complete=False), on refuse : PRÉSENT par défaut.
    """
    if not present_complete:
        return False
    if not is_appliance(candidate):
        return False
    lowered = {p.strip().lower() for p in present}
    if candidate.vendor.strip().lower() in lowered:
        return False
    if candidate.product.strip().lower() in lowered:
        return False
    return True
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_presence.py -q
```
Attendu : `7 passed`.

- [ ] **Step 5 : preuve par mutation**

Remplacer `if not present_complete: return False` par `if not present_complete: pass`, relancer → `test_incomplete_inventory_generates_nothing` **FAIL**. Restaurer, reconfirmer. Puis remplacer le `and` implicite en retirant la Barrière 1 (`if not is_appliance(...)` → `if False`), relancer → `test_non_appliance_is_never_generated_even_if_absent` **FAIL**. Restaurer. Consigner les deux.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-cve-triage/api/wafgen/presence.py packages/secubox-cve-triage/tests/test_presence.py
git commit -m "feat(cve-triage): presence oracle — appliance allowlist AND absence

Two barriers, both required: (1) the vendor is a known-absent appliance family;
(2) the product is absent from the presence union AND the union was fully read.
In doubt (incomplete inventory) → present → generate nothing. Better to miss a
probe than ban a real user.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 3 : L'adaptateur d'inventaire (dpkg ∪ vhosts ∪ modules)

**Files:**
- Create: `packages/secubox-cve-triage/api/wafgen/inventory.py`
- Test: `packages/secubox-cve-triage/tests/test_inventory.py`

**Interfaces:**
- Consumes: rien (sources injectées).
- Produces: `gather_present(*, run=..., routes_path=..., menu_dir=...) -> tuple[set[str], bool]` — retourne `(present_set, complete)`. `complete=False` si une source a échoué.

- [ ] **Step 1 : tests qui échouent**

Créer `packages/secubox-cve-triage/tests/test_inventory.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.wafgen.inventory import gather_present


def fake_run(rc, out):
    def _run(argv):
        return rc, out
    return _run


def test_union_of_the_three_sources(tmp_path):
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text(json.dumps({"nextcloud.gk2.secubox.in": ["127.0.0.1", 9080]}))
    menu = tmp_path / "menu.d"
    menu.mkdir()
    (menu / "peertube.json").write_text(json.dumps({"id": "peertube"}))
    run = fake_run(0, "nginx|1.24|arm64\nopenssl|3.0|arm64\n")

    present, complete = gather_present(run=run, routes_path=routes, menu_dir=menu)

    assert complete is True
    assert "nginx" in present            # dpkg
    assert "nextcloud" in present         # vhost first label
    assert "peertube" in present          # menu.d id


def test_dpkg_failure_marks_incomplete(tmp_path):
    (tmp_path / "menu.d").mkdir()
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text("{}")
    run = fake_run(1, "")   # dpkg-query failed

    present, complete = gather_present(run=run, routes_path=routes, menu_dir=tmp_path / "menu.d")
    assert complete is False   # a source failed → caller must treat as present


def test_unreadable_routes_marks_incomplete(tmp_path):
    (tmp_path / "menu.d").mkdir()
    run = fake_run(0, "nginx|1.24|arm64\n")
    # routes file exists but is corrupt
    routes = tmp_path / "haproxy-routes.json"
    routes.write_text("{ not json")

    present, complete = gather_present(run=run, routes_path=routes, menu_dir=tmp_path / "menu.d")
    assert complete is False


def test_absent_routes_file_is_complete_and_empty(tmp_path):
    # No routes file at all is a legitimate "no public vhosts", not a failure.
    (tmp_path / "menu.d").mkdir()
    run = fake_run(0, "nginx|1.24|arm64\n")
    present, complete = gather_present(run=run, routes_path=tmp_path / "absent.json",
                                       menu_dir=tmp_path / "menu.d")
    assert complete is True
    assert "nginx" in present
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_inventory.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.wafgen.inventory'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-cve-triage/api/wafgen/inventory.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — collecte de l'union de présence
CyberMind — https://cybermind.fr

Trois sources : les paquets dpkg de l'hôte, les vhosts routés par le WAF, et les
modules secubox. La source « vhosts » est CRUCIALE : nextcloud/gitea tournent en
LXC, absents du dpkg hôte mais routés — sans elle on générerait une règle qui
bannirait un vrai utilisateur.

Retourne (present_set, complete). complete=False dès qu'UNE source échoue :
l'appelant (should_generate) refuse alors de générer — fail-safe présent.
`run`/`routes_path`/`menu_dir` sont injectés pour tester sans board.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

ROUTES_PATH = Path("/etc/secubox/waf/haproxy-routes.json")
MENU_DIR = Path("/usr/share/secubox/menu.d")


def _run_cmd(argv: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.returncode, p.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def gather_present(*, run=_run_cmd, routes_path: Path = ROUTES_PATH,
                   menu_dir: Path = MENU_DIR) -> tuple[set[str], bool]:
    """Union { dpkg } ∪ { premiers labels des vhosts } ∪ { ids menu.d }.

    complete=False si une source obligatoire échoue → l'appelant traite tout
    comme présent (ne génère rien).
    """
    present: set[str] = set()
    complete = True

    # 1. dpkg — obligatoire ; un échec rend l'inventaire incomplet.
    rc, out = run(["dpkg-query", "-W", "-f=${Package}|${Version}|${Architecture}\n"])
    if rc != 0:
        complete = False
    else:
        for line in out.splitlines():
            name = line.split("|", 1)[0].strip().lower()
            if name:
                present.add(name)

    # 2. vhosts routés — le premier label du domaine (nextcloud.gk2… → nextcloud).
    #    Fichier absent = pas de vhosts (légitime) ; présent mais illisible =
    #    source indéterminable → incomplet.
    routes_path = Path(routes_path)
    if routes_path.exists():
        try:
            for domain in json.loads(routes_path.read_text(encoding="utf-8")):
                label = str(domain).split(".", 1)[0].strip().lower()
                if label:
                    present.add(label)
        except (OSError, json.JSONDecodeError):
            complete = False

    # 3. modules secubox — les ids de menu.d. Répertoire absent = pas de modules.
    menu_dir = Path(menu_dir)
    if menu_dir.exists():
        for p in sorted(menu_dir.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                complete = False
                continue
            mid = (d.get("id") or "").strip().lower() if isinstance(d, dict) else ""
            if mid:
                present.add(mid)

    return present, complete
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_inventory.py -q
```
Attendu : `4 passed`.

- [ ] **Step 5 : preuve par mutation**

Remplacer `if rc != 0: complete = False` par `if rc != 0: pass`, relancer → `test_dpkg_failure_marks_incomplete` **FAIL**. Restaurer. Consigner.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-cve-triage/api/wafgen/inventory.py packages/secubox-cve-triage/tests/test_inventory.py
git commit -m "feat(cve-triage): gather the presence union (dpkg + vhosts + modules)

Returns (present_set, complete). The vhosts source is what catches nextcloud/
gitea running in LXC — absent from host dpkg but routed. complete=False on any
source failure so the oracle refuses to generate (fail-safe present).

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 4 : L'émetteur — catégorie `product_absent_probes` (additif, atomique)

**Files:**
- Create: `packages/secubox-cve-triage/api/wafgen/emit.py`
- Test: `packages/secubox-cve-triage/tests/test_emit.py`

**Interfaces:**
- Consumes: `Candidate` de `api.wafgen.extract`.
- Produces: `CATEGORY_KEY = "product_absent_probes"`, `build_category(candidates: list[Candidate], *, now: str) -> dict`, `write_category(rules_path: Path, candidates: list[Candidate], *, now: str) -> None`.

- [ ] **Step 1 : tests qui échouent**

Créer `packages/secubox-cve-triage/tests/test_emit.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json

from api.wafgen.emit import CATEGORY_KEY, build_category, write_category
from api.wafgen.extract import Candidate


def cand(cve="CVE-2024-3400", vendor="paloaltonetworks", product="pan-os",
         path="/api/v1/totp/user-backup"):
    return Candidate(cve=cve, vendor=vendor, product=product,
                     cpe=f"cpe:2.3:a:{vendor}:{product}:*", path=path, severity="critical")


def _rules_file(tmp_path):
    p = tmp_path / "waf-rules.json"
    p.write_text(json.dumps({
        "_meta": {"version": "1.2.0"},
        "categories": {
            "sqli": {"name": "SQLi", "severity": "critical",
                     "patterns": [{"id": "sqli-001", "pattern": "union select", "desc": "x"}]},
        },
    }, indent=2))
    return p


def test_category_is_always_detect_mode():
    c = build_category([cand()], now="2026-07-18T00:00:00Z")
    assert c["mode"] == "detect"
    assert c["generated"] is True


def test_pattern_path_is_regex_escaped():
    # A path with regex-special chars must be escaped so it matches literally.
    c = build_category([cand(path="/mgmt/tm/util/bash.php?x=1")], now="2026-07-18T00:00:00Z")
    pat = c["patterns"][0]["pattern"]
    assert "\\.php" in pat and "\\?" in pat


def test_write_preserves_the_other_categories(tmp_path):
    p = _rules_file(tmp_path)
    write_category(p, [cand()], now="2026-07-18T00:00:00Z")
    d = json.loads(p.read_text())
    # sqli untouched, product_absent_probes added.
    assert "sqli" in d["categories"]
    assert d["categories"]["sqli"]["patterns"][0]["id"] == "sqli-001"
    assert CATEGORY_KEY in d["categories"]
    assert d["categories"][CATEGORY_KEY]["mode"] == "detect"
    assert d["_meta"]["version"] == "1.2.0"


def test_regenerate_is_idempotent(tmp_path):
    p = _rules_file(tmp_path)
    write_category(p, [cand()], now="2026-07-18T00:00:00Z")
    first = p.read_text()
    write_category(p, [cand()], now="2026-07-18T00:00:00Z")
    assert p.read_text() == first


def test_regenerate_replaces_only_its_own_category(tmp_path):
    p = _rules_file(tmp_path)
    write_category(p, [cand(cve="CVE-2024-3400")], now="2026-07-18T00:00:00Z")
    write_category(p, [cand(cve="CVE-2023-46747", vendor="f5", product="big-ip",
                            path="/mgmt/tm/util/bash")], now="2026-07-18T00:00:00Z")
    d = json.loads(p.read_text())
    ids = [x["id"] for x in d["categories"][CATEGORY_KEY]["patterns"]]
    assert any("2023-46747" in i for i in ids)
    assert not any("2024-3400" in i for i in ids)   # replaced, not appended
    assert "sqli" in d["categories"]


def test_empty_candidates_writes_an_empty_category(tmp_path):
    p = _rules_file(tmp_path)
    write_category(p, [], now="2026-07-18T00:00:00Z")
    d = json.loads(p.read_text())
    assert d["categories"][CATEGORY_KEY]["patterns"] == []
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_emit.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.wafgen.emit'`.

- [ ] **Step 3 : implémenter**

Créer `packages/secubox-cve-triage/api/wafgen/emit.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — émission de la catégorie product_absent_probes
CyberMind — https://cybermind.fr

Écrit UNE seule catégorie dans waf-rules.json, en mode `detect` (jamais escalate
ni block — la promotion est humaine). Additif : les 17 autres catégories sont
préservées ; on remplace uniquement product_absent_probes (idempotent). Écriture
atomique (temp + os.replace) pour ne jamais corrompre le fichier du WAF frontal.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .extract import Candidate

CATEGORY_KEY = "product_absent_probes"


def build_category(candidates: list[Candidate], *, now: str) -> dict:
    """Construit la catégorie (toujours mode=detect). Le pattern est le chemin
    échappé en regex (matche littéralement) — le but est de reconnaître la sonde,
    pas de généraliser la vuln."""
    patterns = []
    for c in candidates:
        patterns.append({
            "id": f"{c.vendor}-{c.cve}".lower(),
            "pattern": re.escape(c.path),
            "desc": f"{c.vendor} {c.product} probe (product absent)",
            "cve": c.cve,
            "vendor": c.vendor,
            "source": "nuclei",
        })
    return {
        "name": "Product-absent scanner probes (generated)",
        "severity": "high",
        "mode": "detect",          # JAMAIS escalate/block — promotion humaine
        "generated": True,
        "generated_at": now,
        "patterns": patterns,
    }


def write_category(rules_path: Path, candidates: list[Candidate], *, now: str) -> None:
    """Remplace product_absent_probes dans waf-rules.json, préserve le reste,
    écrit atomiquement. Un waf-rules.json absent/illisible lève — l'appelant
    (CLI) décide quoi en faire ; on ne crée pas un fichier de règles vide."""
    rules_path = Path(rules_path)
    data = json.loads(rules_path.read_text(encoding="utf-8"))
    cats = data.setdefault("categories", {})
    cats[CATEGORY_KEY] = build_category(candidates, now=now)

    tmp = rules_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, rules_path)
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_emit.py -q
```
Attendu : `6 passed`.

- [ ] **Step 5 : preuve par mutation**

Remplacer `"mode": "detect",` par `"mode": "escalate",`, relancer → `test_category_is_always_detect_mode` **FAIL** (garde-fou : jamais armé). Restaurer. Puis remplacer `re.escape(c.path)` par `c.path`, relancer → `test_pattern_path_is_regex_escaped` **FAIL**. Restaurer. Consigner les deux.

- [ ] **Step 6 : commit**

```bash
git add packages/secubox-cve-triage/api/wafgen/emit.py packages/secubox-cve-triage/tests/test_emit.py
git commit -m "feat(cve-triage): emit product_absent_probes — detect-only, additive, atomic

Writes one category in detect mode (never escalate/block; promotion is human),
replacing only its own key so the 17 shipped categories are preserved, idempotent,
atomic temp+os.replace. The pattern is the regex-escaped path — recognise the
probe, don't generalise the vuln.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 5 : La CLI + le sous-ensemble vendored + le packaging

**Files:**
- Create: `packages/secubox-cve-triage/api/wafgen/generate.py` (orchestration, testable)
- Create: `packages/secubox-cve-triage/sbin/secubox-cvectl`
- Create: `packages/secubox-cve-triage/nuclei-subset/LICENSE`
- Create: `packages/secubox-cve-triage/nuclei-subset/CVE-2024-3400.yaml`
- Create: `packages/secubox-cve-triage/nuclei-subset/CVE-2024-21887.yaml`
- Create: `packages/secubox-cve-triage/scripts/curate-nuclei-subset.sh`
- Modify: `packages/secubox-cve-triage/debian/control`
- Modify: `packages/secubox-cve-triage/debian/install`
- Create: `packages/secubox-cve-triage/README.md` (section générateur)
- Test: `packages/secubox-cve-triage/tests/test_generate.py`

**Interfaces:**
- Consumes: `extract`, `is_kev` (extract) ; `should_generate` (presence) ; `gather_present` (inventory) ; `write_category`, `build_category` (emit).
- Produces: `generate(subset_dir, present, present_complete) -> tuple[list[Candidate], list[tuple[str,str]]]` — retourne `(retenus, rejets)` où chaque rejet est `(fichier, raison)`. `main(argv) -> int`.

- [ ] **Step 1 : tests qui échouent**

Créer `packages/secubox-cve-triage/tests/test_generate.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import textwrap

from api.wafgen.generate import generate


def _write(dir_, name, body):
    (dir_ / name).write_text(textwrap.dedent(body))


def test_generate_keeps_appliance_absent_kev_and_rejects_the_rest(tmp_path):
    subset = tmp_path / "nuclei-subset"
    subset.mkdir()
    # kept: appliance (paloalto), absent, KEV, clean path
    _write(subset, "keep.yaml", """
        id: CVE-2024-3400
        info:
          severity: critical
          classification: {cve-id: CVE-2024-3400, cpe: "cpe:2.3:a:paloaltonetworks:pan-os:*"}
          metadata: {vendor: paloaltonetworks, product: pan-os}
        tags: cve,kev,rce
        http:
          - method: GET
            path: ["{{BaseURL}}/api/v1/totp/user-backup"]
    """)
    # rejected: not KEV
    _write(subset, "notkev.yaml", """
        id: CVE-2024-1
        info:
          severity: high
          metadata: {vendor: f5, product: big-ip}
        tags: cve,rce
        http:
          - method: GET
            path: ["{{BaseURL}}/x"]
    """)
    # rejected: raw
    _write(subset, "raw.yaml", """
        id: CVE-2024-2
        info: {severity: high, metadata: {vendor: f5, product: big-ip}}
        tags: cve,kev
        http:
          - raw: ["POST /x HTTP/1.1"]
            unsafe: true
    """)

    kept, rejected = generate(subset, present=set(), present_complete=True)

    assert [c.cve for c in kept] == ["CVE-2024-3400"]
    rej_names = {name for name, _ in rejected}
    assert "notkev.yaml" in rej_names and "raw.yaml" in rej_names


def test_present_product_is_rejected_by_the_oracle(tmp_path):
    subset = tmp_path / "nuclei-subset"
    subset.mkdir()
    _write(subset, "f5.yaml", """
        id: CVE-2023-46747
        info:
          severity: critical
          classification: {cve-id: CVE-2023-46747, cpe: "cpe:2.3:a:f5:big-ip:*"}
          metadata: {vendor: f5, product: big-ip}
        tags: cve,kev
        http:
          - method: GET
            path: ["{{BaseURL}}/mgmt/tm/util/bash"]
    """)
    # f5 is somehow present → not generated, and recorded as a rejection reason.
    kept, rejected = generate(subset, present={"f5"}, present_complete=True)
    assert kept == []
    assert any("present" in reason.lower() for _, reason in rejected)


def test_incomplete_inventory_generates_nothing(tmp_path):
    subset = tmp_path / "nuclei-subset"
    subset.mkdir()
    _write(subset, "f5.yaml", """
        id: CVE-2023-46747
        info:
          severity: critical
          classification: {cve-id: CVE-2023-46747}
          metadata: {vendor: f5, product: big-ip}
        tags: cve,kev
        http:
          - method: GET
            path: ["{{BaseURL}}/mgmt/tm/util/bash"]
    """)
    kept, _ = generate(subset, present=set(), present_complete=False)
    assert kept == []
```

- [ ] **Step 2 : lancer — doit échouer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_generate.py -q
```
Attendu : `ModuleNotFoundError: No module named 'api.wafgen.generate'`.

- [ ] **Step 3 : implémenter l'orchestration**

Créer `packages/secubox-cve-triage/api/wafgen/generate.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — orchestration du générateur
CyberMind — https://cybermind.fr

Parcourt le sous-ensemble Nuclei vendored, applique KEV + extraction + les deux
barrières de présence, retourne (retenus, rejets-avec-raison). N'écrit rien :
la CLI décide (dry-run par défaut).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .extract import Candidate, Rejection, extract, is_kev
from .presence import is_appliance, should_generate


def generate(subset_dir: Path, present: set[str],
             present_complete: bool) -> tuple[list[Candidate], list[tuple[str, str]]]:
    """(retenus, [(fichier, raison de rejet)])."""
    kept: list[Candidate] = []
    rejected: list[tuple[str, str]] = []

    for p in sorted(Path(subset_dir).glob("*.yaml")):
        try:
            tmpl = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            rejected.append((p.name, f"unparseable: {exc}"))
            continue
        if not isinstance(tmpl, dict):
            rejected.append((p.name, "not a template mapping"))
            continue

        if not is_kev(tmpl):
            rejected.append((p.name, "not KEV (not known-exploited)"))
            continue

        result = extract(tmpl)
        if isinstance(result, Rejection):
            rejected.append((p.name, result.reason))
            continue

        if not should_generate(result, present, present_complete):
            why = ("inventory incomplete → present" if not present_complete
                   else "not an appliance family" if not is_appliance(result)
                   else "product is present on this box")
            rejected.append((p.name, why))
            continue

        kept.append(result)

    return kept, rejected
```

- [ ] **Step 4 : lancer — doit passer**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_generate.py -q
```
Attendu : `3 passed`.

- [ ] **Step 5 : la CLI**

Créer `packages/secubox-cve-triage/sbin/secubox-cvectl` (`chmod 755`) :

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-cvectl
set -euo pipefail
readonly MODULE="cve-triage"
readonly VERSION="1.1.0"
cd /usr/lib/secubox/cve-triage
exec /usr/bin/python3 -m api.wafgen.cli "$@"
```

Créer `packages/secubox-cve-triage/api/wafgen/cli.py` :

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: cve-triage — CLI waf-rules generate
CyberMind — https://cybermind.fr

Dry-run par défaut : montre ce qui SERAIT généré (retenus + rejets avec raison)
sans écrire. --apply écrit la catégorie product_absent_probes en mode detect.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .emit import write_category
from .generate import generate
from .inventory import gather_present

SUBSET_DIR = Path("/usr/lib/secubox/cve-triage/nuclei-subset")
RULES_PATH = Path("/etc/secubox/waf/waf-rules.json")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="secubox-cvectl")
    sub = p.add_subparsers(dest="group", required=True)
    wr = sub.add_parser("waf-rules")
    wsub = wr.add_subparsers(dest="cmd", required=True)
    gen = wsub.add_parser("generate", help="generate product-absent probe rules")
    gen.add_argument("--apply", action="store_true",
                     help="write the category (default: dry-run, write nothing)")
    gen.add_argument("--subset", default=str(SUBSET_DIR))
    gen.add_argument("--rules", default=str(RULES_PATH))
    args = p.parse_args(argv)

    present, complete = gather_present()
    kept, rejected = generate(Path(args.subset), present, complete)

    print(f"presence union: {len(present)} product(s), complete={complete}")
    print(f"kept: {len(kept)} probe(s), rejected: {len(rejected)}")
    for c in kept:
        print(f"  ✓ {c.cve:<16} {c.vendor}/{c.product}  {c.path}")
    for name, why in rejected:
        print(f"  ✗ {name}: {why}")

    if not args.apply:
        print("dry-run — nothing written (use --apply to write).")
        return 0
    if not complete:
        print("refusing to write: presence inventory incomplete (fail-safe).",
              file=sys.stderr)
        return 3
    write_category(Path(args.rules), kept, now=_now())
    print(f"wrote {len(kept)} probe(s) to product_absent_probes (mode=detect) in {args.rules}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6 : le sous-ensemble vendored initial + licence + script de curation**

Créer `packages/secubox-cve-triage/nuclei-subset/LICENSE` :

```
The templates in this directory are vendored from projectdiscovery/nuclei-templates
(https://github.com/projectdiscovery/nuclei-templates), MIT License.

Copyright (c) 2020-2026 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

Créer `packages/secubox-cve-triage/nuclei-subset/CVE-2024-3400.yaml` (PAN-OS, KEV, chemin GET propre — transcrit de la forme réelle) :

```yaml
id: CVE-2024-3400
info:
  name: Palo Alto PAN-OS - Command Injection
  severity: critical
  classification:
    cve-id: CVE-2024-3400
    cpe: cpe:2.3:a:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*
  metadata:
    vendor: paloaltonetworks
    product: pan-os
  tags: cve,cve2024,panos,rce,kev,vuln
http:
  - method: GET
    path:
      - "{{BaseURL}}/global-protect/portal/css/bootstrap.min.css"
```

Créer `packages/secubox-cve-triage/nuclei-subset/CVE-2024-21887.yaml` (Ivanti, KEV, chemin GET propre) :

```yaml
id: CVE-2024-21887
info:
  name: Ivanti Connect Secure - Command Injection
  severity: critical
  classification:
    cve-id: CVE-2024-21887
    cpe: cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*
  metadata:
    vendor: ivanti
    product: connect_secure
  tags: cve,cve2024,ivanti,rce,kev,vuln
http:
  - method: GET
    path:
      - "{{BaseURL}}/api/v1/totp/user-backup"
```

Créer `packages/secubox-cve-triage/scripts/curate-nuclei-subset.sh` (`chmod 755`) — mainteneur hors-ligne :

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: curate-nuclei-subset — MAINTAINER-ONLY, offline, NOT runtime.
# Clones nuclei-templates and copies KEV + appliance-family + URL-extractable
# templates into nuclei-subset/. Run before a release to refresh the vendored
# set; the .deb ships the copies, the service never clones anything.
set -euo pipefail
readonly OUT="$(dirname "$0")/../nuclei-subset"
readonly TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates "$TMP/nt"
echo "Review candidates by hand; copy the appliance/KEV/clean-path ones into $OUT."
echo "Vendors of interest: f5 paloaltonetworks ivanti citrix fortinet cisco vmware."
grep -rlE "kev" "$TMP/nt/http/cves" | head -50
```

- [ ] **Step 7 : packaging**

Ajouter `python3-yaml` aux `Depends` de `packages/secubox-cve-triage/debian/control` (après `python3`). Vérifier la ligne `Depends:` existante et y insérer `python3-yaml,`.

Dans `packages/secubox-cve-triage/debian/install`, ajouter (adapter au style existant — lire d'abord) :

```
api/wafgen/*.py         usr/lib/secubox/cve-triage/api/wafgen/
sbin/secubox-cvectl     usr/sbin/
nuclei-subset/*         usr/lib/secubox/cve-triage/nuclei-subset/
```

- [ ] **Step 8 : suite complète + vérif YAML réelle**

```bash
.venv/bin/python -m pytest packages/secubox-cve-triage/tests -q
```
Attendu : `28 passed` (8+7+4+6+3).

Vérifier que les deux templates vendored passent le pipeline réel :

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-cve-triage
.venv/bin/python -c "
import sys; sys.path.insert(0,'.')
from pathlib import Path
from api.wafgen.generate import generate
kept, rej = generate(Path('nuclei-subset'), present=set(), present_complete=True)
print('retenus:', [c.cve for c in kept])
print('rejets :', rej)
assert len(kept) == 2, kept
print('les 2 templates vendored produisent bien un candidat ✓')
"
```
Attendu : les 2 CVE retenus.

- [ ] **Step 9 : commit**

```bash
git add packages/secubox-cve-triage/
git commit -m "feat(cve-triage): secubox-cvectl waf-rules generate + vendored Nuclei subset

CLI (dry-run by default, --apply to write) orchestrates extract + presence +
emit. Ships a small vendored Nuclei subset (MIT, with LICENSE) of appliance/KEV/
URL-extractable templates + an offline maintainer curation script. Adds
python3-yaml to Depends. --apply refuses to write when the presence inventory is
incomplete (fail-safe).

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 6 : Panel — onglet règles générées

**Files:**
- Modify: `packages/secubox-cve-triage/api/main.py` (ajouter les routes GET `/waf-rules` + POST `/waf-rules/generate`)
- Modify: `packages/secubox-cve-triage/www/cve-triage/index.html` (onglet)

**Interfaces:**
- Consumes: `generate`, `gather_present`, `write_category` (wafgen) ; `require_jwt` (secubox_core).
- Produces: routes `/waf-rules` (aperçu : retenus + rejets, dry-run) et `/waf-rules/generate` (POST `--apply`).

- [ ] **Step 1 : implémenter les routes**

Dans `packages/secubox-cve-triage/api/main.py`, à côté des routes existantes (après les `@router.get(...)` du domaine feeds), ajouter :

```python
@router.get("/waf-rules", dependencies=[Depends(require_jwt)])
async def waf_rules_preview():
    """Dry-run: what would be generated (kept + rejections), writes nothing."""
    from .wafgen.generate import generate
    from .wafgen.inventory import gather_present
    from pathlib import Path
    present, complete = gather_present()
    kept, rejected = generate(Path("/usr/lib/secubox/cve-triage/nuclei-subset"),
                              present, complete)
    return {
        "present_count": len(present), "inventory_complete": complete,
        "kept": [{"cve": c.cve, "vendor": c.vendor, "product": c.product,
                  "path": c.path} for c in kept],
        "rejected": [{"file": n, "reason": r} for n, r in rejected],
    }


@router.post("/waf-rules/generate", dependencies=[Depends(require_jwt)])
async def waf_rules_generate():
    """Apply: write product_absent_probes (detect mode). Refuses if inventory
    is incomplete (fail-safe)."""
    from .wafgen.generate import generate
    from .wafgen.inventory import gather_present
    from .wafgen.emit import write_category
    from datetime import datetime, timezone
    from pathlib import Path
    present, complete = gather_present()
    if not complete:
        raise HTTPException(409, "presence inventory incomplete — refusing (fail-safe)")
    kept, rejected = generate(Path("/usr/lib/secubox/cve-triage/nuclei-subset"),
                              present, complete)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_category(Path("/etc/secubox/waf/waf-rules.json"), kept, now=now)
    return {"success": True, "written": len(kept), "mode": "detect",
            "rejected": len(rejected)}
```

**Note à l'implémenteur** : `require_jwt`, `HTTPException`, `router`/`app` sont déjà importés dans `main.py` — vérifier leurs noms exacts et réutiliser. Ne pas ré-importer différemment.

- [ ] **Step 2 : l'onglet webui**

Dans `packages/secubox-cve-triage/www/cve-triage/index.html`, ajouter un onglet « WAF probes » qui appelle `GET /api/v1/cve-triage/waf-rules`, affiche `kept` (cve/vendor/path) et `rejected` (file/reason), plus un bouton « Generate » qui POST `/waf-rules/generate` puis rafraîchit. Suivre le style cyan hybrid-skin déjà présent dans le fichier (réutiliser ses classes `.card`/`.btn`/`.tab` ; lire l'existant). `esc()` sur toute valeur d'API ; lire le token depuis `localStorage.getItem('sbx_token')` ; 401 → toast.

`node --check` le JS extrait.

- [ ] **Step 3 : vérifier que le module se charge encore**

```bash
cd /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/packages/secubox-cve-triage
python3 -c "import ast; ast.parse(open('api/main.py').read()); print('main.py parse ✓')"
```
(La suite `tests/` reste verte — les routes ajoutées n'importent wafgen que dans le corps des handlers, pas au niveau module, donc elles n'introduisent pas de lecture de config supplémentaire.)

- [ ] **Step 4 : commit**

```bash
git add packages/secubox-cve-triage/api/main.py packages/secubox-cve-triage/www/cve-triage/index.html
git commit -m "feat(cve-triage): panel tab for generated WAF probes (dry-run + apply)

GET /waf-rules previews kept + rejections (writes nothing); POST /waf-rules/
generate applies (detect mode), refusing on an incomplete presence inventory.
Cyan hybrid-skin tab, esc()'d, sbx_token auth.

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

**Couverture du spec** :

| Exigence du spec | Tâche |
|---|---|
| Source vendored Nuclei (MIT, pas de git-pull runtime) | 5 (subset + LICENSE + curation script) |
| Extraction : sonde URL, rejets journalisés | 1 |
| Barrière 1 : allowlist appliance | 2 |
| Barrière 2 : union dpkg ∪ vhosts ∪ modules | 3 |
| Fail-safe « dans le doute présent » | 2 (`present_complete`), 3 (`complete`), 5 (CLI refuse), 6 (409) |
| Trou LXC/vhost (nextcloud absent dpkg mais routé) | 3 (source vhosts + test) |
| Sortie catégorie `detect`, additive, idempotente, atomique | 4 |
| Jamais escalate/block (jamais armé) | 4 (test + mutation) |
| CLI dry-run par défaut | 5 |
| Panel onglet | 6 |
| Tests capables d'échouer (mutation) | 1,2,3,4 |

Hors périmètre, donc absent (voulu) : git-pull runtime, promotion auto detect→escalate, génération hors appliance, généralisation des patterns, corrélation ASN/JA4.

**Placeholders** : aucun — chaque étape porte son code et sa commande. Les « notes à l'implémenteur » (routes de `main.py`, style du panel) demandent de **lire l'existant** plutôt que d'inventer — instruction, pas trou.

**Cohérence des types** : `Candidate` (Task 1) consommé par 2/4/5 ; `should_generate(candidate, present, present_complete)` (Task 2) appelé identiquement en 5 ; `gather_present() -> (set, bool)` (Task 3) consommé en 5/6 ; `write_category(rules_path, candidates, *, now)` / `CATEGORY_KEY` (Task 4) consommés en 5/6 ; `generate(subset_dir, present, present_complete) -> (kept, rejected)` (Task 5) consommé en 6. Noms stables partout.
