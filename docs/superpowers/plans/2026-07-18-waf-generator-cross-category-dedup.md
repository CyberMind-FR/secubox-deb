<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# WAF generator — dédup inter-catégories — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** The product-absent generator must not emit a probe pattern that already exists in another WAF category (e.g. the hand-written `cve_2024` blocking category), because a blocking category wins and the generated `detect` rule would never log — pure redundancy. Skip such candidates, recording an explicit rejection reason.

**Architecture:** A new pure `emit.existing_patterns(rules_path)` returns `{pattern_string: category_key}` for every category EXCEPT `product_absent_probes` (excluding our own key preserves idempotence). `generate()` gains an optional `existing` map and, after a candidate passes the presence barriers, rejects it if `re.escape(path)` is already covered. CLI + both panel routes build the map from the live rules file and pass it.

**Tech Stack:** Python 3.11 stdlib (`json`, `re`) + existing wafgen modules.

## Global Constraints

- Python 3.11 stdlib only. SPDX 4-line header preserved on every file. Copyright `Gérald Kerma <devel@cybermind.fr>`.
- Backward compatible: `generate()`'s new param is keyword-only with a default that means "no dedup" — existing 3-arg callers and tests keep working unchanged.
- Dedup is **best-effort**, never a safety gate: a missing/corrupt rules file → empty map → no dedup (worst case a duplicate, which is today's behaviour). This is NOT `write_category`'s fail-closed path.
- **Exclude `emit.CATEGORY_KEY` (`product_absent_probes`) from the existing map.** Including it would make the 2nd `--apply` see our own prior patterns as "already covered" and regenerate nothing — breaking idempotence. This is the one invariant a reviewer must confirm.
- Dedup runs LAST (kev → extract → presence barriers → dedup): only a candidate that would otherwise be kept is dedup-checked.
- Pattern comparison uses `re.escape(candidate.path)` — the exact form `build_category` stores — matched by EXACT string equality against stored pattern strings (no regex-subset guessing, which could falsely claim coverage).
- Detect-only / additive / atomic invariants of `write_category` are untouched. No escalate/block anywhere.
- Tests per-directory: `.venv/bin/python -m pytest packages/secubox-cve-triage/tests -q`. Commit messages end `Co-Authored-By: Gerald KERMA <devel@cybermind.fr>`, NO Claude reference.

---

### Task 1: `emit.existing_patterns()` + `generate()` dédup (purs, testés)

**Files:**
- Modify: `packages/secubox-cve-triage/api/wafgen/emit.py` (add `existing_patterns`)
- Modify: `packages/secubox-cve-triage/api/wafgen/generate.py` (add `existing` param + dedup)
- Test: `packages/secubox-cve-triage/tests/test_emit.py` (add existing_patterns tests)
- Test: `packages/secubox-cve-triage/tests/test_generate.py` (add dedup tests)

**Interfaces:**
- Produces: `emit.existing_patterns(rules_path: Path) -> dict[str, str]`; `generate(subset_dir, present, present_complete, *, existing: dict[str, str] | None = None) -> tuple[list[Candidate], list[tuple[str, str]]]`.

- [ ] **Step 1: Write failing tests for `existing_patterns`**

Add to `packages/secubox-cve-triage/tests/test_emit.py`:

```python
def test_existing_patterns_maps_pattern_to_category_excluding_own_key(tmp_path):
    from api.wafgen.emit import existing_patterns
    rules = tmp_path / "waf-rules.json"
    rules.write_text(json.dumps({"categories": {
        "cve_2024": {"patterns": [{"pattern": "/mgmt/tm/util/bash"},
                                  {"pattern": "/api/v1/totp/user\\-backup"}]},
        "product_absent_probes": {"patterns": [{"pattern": "/should/not/appear"}]},
    }}))
    got = existing_patterns(rules)
    assert got["/mgmt/tm/util/bash"] == "cve_2024"
    assert got["/api/v1/totp/user\\-backup"] == "cve_2024"
    assert "/should/not/appear" not in got   # our own key excluded → idempotence


def test_existing_patterns_missing_or_corrupt_file_is_empty(tmp_path):
    from api.wafgen.emit import existing_patterns
    assert existing_patterns(tmp_path / "nope.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json")
    assert existing_patterns(bad) == {}
```

- [ ] **Step 2: Run — must fail** (`ImportError`/`AttributeError` for `existing_patterns`).

Run: `.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_emit.py -q`

- [ ] **Step 3: Implement `existing_patterns` in `emit.py`**

Add after `CATEGORY_KEY` (uses the already-imported `json`, `Path`):

```python
def existing_patterns(rules_path: Path) -> dict[str, str]:
    """Map chaque pattern-string -> sa catégorie, SAUF notre propre
    CATEGORY_KEY. Exclure product_absent_probes est vital : sinon un 2e --apply
    verrait nos propres patterns comme « déjà couverts » et régénérerait zéro
    (idempotence cassée). Best-effort : fichier absent/corrompu -> {} (aucune
    dédup, jamais une erreur — la dédup n'est pas un garde de sûreté, contrairement
    à write_category qui, lui, lève)."""
    try:
        data = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    cats = data.get("categories", {})
    if not isinstance(cats, dict):
        return {}
    out: dict[str, str] = {}
    for cat_key, cat in cats.items():
        if cat_key == CATEGORY_KEY or not isinstance(cat, dict):
            continue
        for pat in cat.get("patterns", []):
            if isinstance(pat, dict) and isinstance(pat.get("pattern"), str):
                out.setdefault(pat["pattern"], cat_key)
    return out
```

- [ ] **Step 4: Run — must pass.**

- [ ] **Step 5: Write failing tests for `generate` dedup**

Add to `packages/secubox-cve-triage/tests/test_generate.py` (reuses the existing `_write` helper + `generate` import):

```python
import re


def test_candidate_already_covered_by_another_category_is_rejected(tmp_path):
    subset = tmp_path / "nuclei-subset"
    subset.mkdir()
    _write(subset, "ivanti.yaml", """
        id: CVE-2024-21887
        info:
          severity: critical
          classification: {cve-id: CVE-2024-21887, cpe: "cpe:2.3:a:ivanti:connect_secure:*"}
          metadata: {vendor: ivanti, product: connect_secure}
          tags: cve,kev
        http:
          - method: GET
            path: ["{{BaseURL}}/api/v1/totp/user-backup"]
    """)
    # cve_2024 already covers this exact path (stored re.escape'd)
    existing = {re.escape("/api/v1/totp/user-backup"): "cve_2024"}
    kept, rejected = generate(subset, present=set(), present_complete=True,
                              existing=existing)
    assert kept == []
    assert any("already covered by cve_2024" in reason for _, reason in rejected)


def test_no_dedup_when_existing_absent_keeps_candidate(tmp_path):
    subset = tmp_path / "nuclei-subset"
    subset.mkdir()
    _write(subset, "ivanti.yaml", """
        id: CVE-2024-21887
        info:
          severity: critical
          classification: {cve-id: CVE-2024-21887, cpe: "cpe:2.3:a:ivanti:connect_secure:*"}
          metadata: {vendor: ivanti, product: connect_secure}
          tags: cve,kev
        http:
          - method: GET
            path: ["{{BaseURL}}/api/v1/totp/user-backup"]
    """)
    kept, _ = generate(subset, present=set(), present_complete=True)  # existing default None
    assert [c.cve for c in kept] == ["CVE-2024-21887"]
```

- [ ] **Step 6: Run — must fail** (dedup not implemented; first test keeps the candidate).

- [ ] **Step 7: Implement dedup in `generate.py`**

Add `import re` at the top (after `from pathlib import Path`). Change the signature and add the dedup check as the LAST step before `kept.append`:

```python
def generate(subset_dir: Path, present: set[str], present_complete: bool,
             *, existing: dict[str, str] | None = None
             ) -> tuple[list[Candidate], list[tuple[str, str]]]:
    """(retenus, [(fichier, raison de rejet)]). `existing` mappe pattern-string
    -> catégorie (voir emit.existing_patterns) : un candidat dont le pattern y
    figure déjà est rejeté (redondance ; une catégorie bloquante l'emporterait
    sur notre detect). None/{} => aucune dédup."""
    existing = existing or {}
    kept: list[Candidate] = []
    rejected: list[tuple[str, str]] = []
    # ... (boucle inchangée jusqu'après should_generate) ...
```

Right before `kept.append(result)`, insert:

```python
        pattern = re.escape(result.path)
        if pattern in existing:
            rejected.append((p.name, f"already covered by {existing[pattern]}"))
            continue

        kept.append(result)
```

- [ ] **Step 8: Run — must pass.** Then the full module suite:

Run: `.venv/bin/python -m pytest packages/secubox-cve-triage/tests -q`
Expected: all prior + 4 new pass.

- [ ] **Step 9: Commit**

```bash
git add packages/secubox-cve-triage/api/wafgen/emit.py packages/secubox-cve-triage/api/wafgen/generate.py packages/secubox-cve-triage/tests/test_emit.py packages/secubox-cve-triage/tests/test_generate.py
git commit -m "feat(cve-triage): skip generated probes already covered by another WAF category

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

### Task 2: câbler CLI + panel pour passer `existing`

**Files:**
- Modify: `packages/secubox-cve-triage/api/wafgen/cli.py`
- Modify: `packages/secubox-cve-triage/api/main.py` (both `/waf-rules` routes)
- Modify: `packages/secubox-cve-triage/debian/changelog`
- Test: `packages/secubox-cve-triage/tests/test_cli.py` (extend if present, else create)

**Interfaces:**
- Consumes: `emit.existing_patterns`, `generate(..., existing=...)`.

- [ ] **Step 1: Write the failing CLI test**

Add to `packages/secubox-cve-triage/tests/test_cli.py` (create with SPDX header if absent). Drives `wafgen.cli.main` with a tmp subset + a tmp rules file whose foreign category already covers the template's path, asserting dry-run rejects it as already-covered:

```python
def test_cli_dedups_against_existing_rules(tmp_path, monkeypatch, capsys):
    import re
    from api.wafgen import cli
    subset = tmp_path / "subset"
    subset.mkdir()
    (subset / "ivanti.yaml").write_text(
        'id: CVE-2024-21887\n'
        'info:\n  severity: critical\n'
        '  classification: {cve-id: CVE-2024-21887, cpe: "cpe:2.3:a:ivanti:connect_secure:*"}\n'
        '  metadata: {vendor: ivanti, product: connect_secure}\n'
        '  tags: cve,kev\n'
        'http:\n  - method: GET\n    path: ["{{BaseURL}}/api/v1/totp/user-backup"]\n')
    rules = tmp_path / "waf-rules.json"
    rules.write_text('{"categories": {"cve_2024": {"patterns": [{"pattern": "'
                     + re.escape("/api/v1/totp/user-backup") + '"}]}}}')
    monkeypatch.setattr(cli, "gather_present", lambda: (set(), True))

    rc = cli.main(["waf-rules", "generate",
                   "--subset", str(subset), "--rules", str(rules)])  # dry-run
    out = capsys.readouterr().out
    assert rc == 0
    assert "kept: 0 probe(s)" in out
    assert "already covered by cve_2024" in out
```

- [ ] **Step 2: Run — must fail** (CLI doesn't dedup yet → kept 1).

Run: `.venv/bin/python -m pytest packages/secubox-cve-triage/tests/test_cli.py -q`

- [ ] **Step 3: Wire `wafgen/cli.py`**

Add the import: `from .emit import existing_patterns, write_category` (replace the existing `from .emit import write_category`). Change the generate call in `main()`:

```python
    present, complete = gather_present()
    kept, rejected = generate(Path(args.subset), present, complete,
                              existing=existing_patterns(Path(args.rules)))
```

- [ ] **Step 4: Wire both panel routes in `main.py`**

In `waf_rules_preview()`: import and pass existing:

```python
    from .wafgen.generate import generate
    from .wafgen.inventory import gather_present
    from .wafgen.emit import existing_patterns

    present, complete = gather_present()
    kept, rejected = generate(
        Path("/usr/lib/secubox/cve-triage/nuclei-subset"), present, complete,
        existing=existing_patterns(Path("/etc/secubox/waf/waf-rules.json")),
    )
```

In `waf_rules_generate()`: add `existing_patterns` to the emit import already there and pass it:

```python
    from .wafgen.emit import existing_patterns, write_category
    ...
    kept, rejected = generate(
        Path("/usr/lib/secubox/cve-triage/nuclei-subset"), present, complete,
        existing=existing_patterns(Path("/etc/secubox/waf/waf-rules.json")),
    )
```

- [ ] **Step 5: Run — must pass; then full suite**

Run: `.venv/bin/python -m pytest packages/secubox-cve-triage/tests -q`
Also `python3 -c "import ast; ast.parse(open('packages/secubox-cve-triage/api/main.py').read())"` to confirm main.py parses.

- [ ] **Step 6: Bump changelog + commit**

Prepend to `packages/secubox-cve-triage/debian/changelog`:

```
secubox-cve-triage (1.1.1-1~bookworm1) bookworm; urgency=medium

  * WAF generator: skip probes already covered by another WAF category
    (e.g. the hand-written cve_2024 blocking rules) — a blocking category wins,
    so a duplicate detect rule would never log. Rejected with an explicit
    "already covered by <category>" reason, visible in dry-run. Our own
    product_absent_probes category is excluded from the check (idempotence).

 -- Gerald KERMA <devel@cybermind.fr>  Fri, 18 Jul 2026 14:00:00 +0200

```

```bash
git add packages/secubox-cve-triage/api/wafgen/cli.py packages/secubox-cve-triage/api/main.py packages/secubox-cve-triage/debian/changelog packages/secubox-cve-triage/tests/test_cli.py
git commit -m "feat(cve-triage): CLI + panel pass existing patterns for cross-category dedup (1.1.1)

Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
```

---

## Auto-revue du plan

- **Couverture** : dédup pur (Task 1: emit.existing_patterns + generate.existing) ; câblage CLI + 2 routes panel + changelog (Task 2). ✓
- **Idempotence** : CATEGORY_KEY exclu de existing_patterns — testé (`test_existing_patterns_..._excluding_own_key`).
- **Backward-compat** : `existing` keyword-only default None ; test `test_no_dedup_when_existing_absent_keeps_candidate` + tous les appels 3-args existants inchangés.
- **Sûreté** : best-effort ({} sur fichier absent/corrompu), jamais un garde ; detect-only/additif/atomique de write_category intacts ; aucun escalate/block.
- **Types** : `existing_patterns -> dict[str,str]` consommé par `generate(existing=...)` identiquement en CLI et panel.
