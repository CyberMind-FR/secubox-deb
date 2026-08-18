<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Anti-Track v2 — Plan 2c (bypass seed + #filtres /list) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the empty `#filtres` panel by adding the missing `GET /admin/filter-control/list` JSON endpoint (tagged by source), and move the inline cert-pinned bypass seed into a package-owned file merged 3-way (seed + operator-static + cert-pin-learned) so the panel shows seed/static/learned with badges.

**Architecture:** A package-owned read-only `mitm-bypass-seed.conf` holds the curated cert-pinned hosts (moved verbatim from the current inline `_MITM_BYPASS_DEFAULT_ENTRIES` — behavior-preserving). `mitm-bypass.conf` becomes purely operator-owned (created empty). The launch script merges three sources into `ignore_hosts`. A new tagged-read helper + `/list` route feed the panel; the frontend already renders `source`.

**Tech Stack:** FastAPI (`api.py`), the launch shell script, vanilla JS panel. pytest. Issue #633.

**Spec:** `docs/superpowers/specs/2026-06-17-anti-track-v2-plan2c-bypass-seed-design.md` (read §0 Discovery — the `/list` endpoint is the keystone).

**Conventions:** worktree `secubox-deb-worktrees/633-…` branch `feature/633-…`; commits end `(ref #633)`. Paths relative to `packages/secubox-toolbox/`.

**Verified facts (from api.py / index.html / launch script):**
- `api.py`: `MITM_BYPASS_FILE = Path("/var/lib/secubox/toolbox/mitm-bypass.conf")`, `_MITM_BYPASS_DEFAULT_ENTRIES` (a list of header-comment + regex strings), `_ensure_bypass_file()` writes the defaults if absent, `_load_bypass_entries()` returns non-comment/non-blank lines from the static file. Routes: `GET /admin/filter-control` (HTML), `/add`, `/remove`, `/regex` — **NO `/list`**. Router is `@router.get(...)`.
- `loadFilters()` (index.html) fetches `/admin/filter-control/list`, reads `d.hosts` (array), each item `host = h.host || h.pattern`, badge `h.source`.
- launch script `sbin/secubox-toolbox-mitm-wg-launch`: `BYPASS_FILE=/var/lib/secubox/toolbox/mitm-bypass.conf`, `DYNAMIC_FILE=/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf`, loop `for src in "$BYPASS_FILE" "$DYNAMIC_FILE"; do` composing the `ignore_hosts` regex.
- `debian/rules` `override_dh_auto_install` already does `cp -r conf debian/secubox-toolbox/usr/lib/secubox/toolbox/`.

---

### Task 1: move the seed to a package file; operator file starts empty

**Files:**
- Create: `packages/secubox-toolbox/conf/mitm-bypass-seed.conf`
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py` (add `MITM_BYPASS_SEED_FILE` const; `_ensure_bypass_file` writes an empty operator file)
- Modify: `packages/secubox-toolbox/debian/rules` (ship the seed to the lib dir)
- Test: `packages/secubox-toolbox/tests/test_bypass_sources.py`

- [ ] **Step 1: Create the seed file from the existing inline defaults**

Open `api.py`, find `_MITM_BYPASS_DEFAULT_ENTRIES` (a Python list of strings: comment lines + regex patterns). Copy its content VERBATIM into `packages/secubox-toolbox/conf/mitm-bypass-seed.conf`, one entry per line (strip the Python list quoting/commas — each list element becomes a raw line). Prepend this header (replacing the existing first comment lines):
```text
# SecuBox ToolBoX :: Anti-Track v2 (#633) cert-pinned bypass SEED (package-owned).
# TLS passthrough (NOT decrypted) — required for apps with cert pinning / E2E.
# This is the package default; operator additions go in mitm-bypass.conf,
# auto-learned hosts in mitm-bypass-dynamic.conf. All three are merged into
# ignore_hosts by secubox-toolbox-mitm-wg-launch. Regex, one per line, # comments.
```
Keep every existing pattern line (Signal/WhatsApp/Telegram/Apple/banks/googleapis/
facebook/ad-networks/Xiaomi/etc.) EXACTLY — this is behavior-preserving; do not trim
the broad-but-pinned entries (they break apps if MITM'd, per the inline comments).

- [ ] **Step 2: Write the failing test** (`packages/secubox-toolbox/tests/test_bypass_sources.py`)

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
import re, pathlib

PKG = pathlib.Path(__file__).resolve().parents[1]
SEED = PKG / "conf" / "mitm-bypass-seed.conf"


def _patterns(path):
    out = []
    for ln in path.read_text().splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def test_seed_file_exists_and_nonempty():
    assert SEED.exists()
    pats = _patterns(SEED)
    assert len(pats) >= 15            # the curated set


def test_seed_patterns_form_valid_ignore_hosts_alternation():
    pats = _patterns(SEED)
    # every line compiles, and the joined alternation (how mitmproxy consumes it)
    re.compile("(?:" + "|".join(pats) + ")")
    # spot-check a couple of expected hosts are covered
    alt = re.compile("(?:" + "|".join(pats) + ")")
    assert alt.search("api.whatsapp.net")
    assert alt.search("gateway.icloud.com")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bypass_sources.py -q`
Expected: FAIL — seed file does not exist yet.

- [ ] **Step 4: Make it pass** — the seed file from Step 1 should satisfy the tests. Run again:

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bypass_sources.py -q`
Expected: PASS (2 passed). If `test_seed_patterns_form_valid_ignore_hosts_alternation` fails to compile, a pattern line has a regex typo introduced during the copy — fix it to match the api.py original.

- [ ] **Step 5: Point api.py at the seed; operator file starts empty**

In `api.py`, after the `MITM_BYPASS_FILE = ...` line add:
```python
MITM_BYPASS_SEED_FILE = Path(os.environ.get(
    "SECUBOX_BYPASS_SEED", "/usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf"))
MITM_BYPASS_DYNAMIC_FILE = Path(os.environ.get(
    "SECUBOX_BYPASS_DYNAMIC", "/var/lib/secubox/toolbox/mitm-bypass-dynamic.conf"))
```
(`os` and `Path` are already imported in api.py — confirm with `grep -n "^import os\|from pathlib" secubox_toolbox/api.py`; if `os` is missing, add `import os`.)

Change `_ensure_bypass_file()` so the OPERATOR file is created EMPTY (the curated
defaults now live in the package seed):
```python
def _ensure_bypass_file() -> None:
    if not MITM_BYPASS_FILE.exists():
        MITM_BYPASS_FILE.parent.mkdir(parents=True, exist_ok=True)
        MITM_BYPASS_FILE.write_text(
            "# SecuBox ToolBoX :: operator bypass additions (regex, one per line).\n"
            "# Package cert-pinned defaults live in the read-only seed file;\n"
            "# auto-learned hosts in mitm-bypass-dynamic.conf. Edit via "
            "/admin/filter-control.\n")
```
Leave the `_MITM_BYPASS_DEFAULT_ENTRIES` list in place for now (it is no longer
written by `_ensure_bypass_file`, but `/regex` / other readers may reference it —
Task 2 removes the dependency; deleting it here is optional cleanup, skip to keep
the diff focused).

- [ ] **Step 6: Ship the seed via debian/rules**

In `debian/rules` `override_dh_auto_install`, the `cp -r conf …` line already copies
the whole `conf/` dir to `/usr/lib/secubox/toolbox/conf/` — so `conf/mitm-bypass-seed.conf`
ships automatically at the path `MITM_BYPASS_SEED_FILE` expects. Confirm:
Run: `cd packages/secubox-toolbox && grep -n "cp -r conf" debian/rules`
Expected: the `cp -r conf` line is present (no rules change needed). If `conf/` is
NOT copied, add `cp -r conf debian/secubox-toolbox/usr/lib/secubox/toolbox/`.

- [ ] **Step 7: Commit**

```bash
git add packages/secubox-toolbox/conf/mitm-bypass-seed.conf packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_bypass_sources.py packages/secubox-toolbox/debian/rules
git commit -m "feat(toolbox): package-owned cert-pinned bypass seed; operator file starts empty (ref #633)"
```

---

### Task 2: tagged `_load_bypass_tagged()` + `GET /admin/filter-control/list`

**Files:**
- Modify: `packages/secubox-toolbox/secubox_toolbox/api.py`
- Test: `packages/secubox-toolbox/tests/test_bypass_sources.py`

- [ ] **Step 1: Write the failing test (append)**

```python
import importlib, json


def test_load_bypass_tagged_dedups_priority(tmp_path, monkeypatch):
    seed = tmp_path / "seed.conf"; seed.write_text("# h\nseedonly.com\nshared.com\n")
    static = tmp_path / "static.conf"; static.write_text("# h\nstaticonly.com\nshared.com\n")
    dyn = tmp_path / "dyn.conf"; dyn.write_text("# h\nlearnedonly.com\nshared.com\n")
    import secubox_toolbox.api as api
    monkeypatch.setattr(api, "MITM_BYPASS_SEED_FILE", seed)
    monkeypatch.setattr(api, "MITM_BYPASS_FILE", static)
    monkeypatch.setattr(api, "MITM_BYPASS_DYNAMIC_FILE", dyn)
    tagged = api._load_bypass_tagged()
    by = {t["pattern"]: t["source"] for t in tagged}
    assert by["seedonly.com"] == "seed"
    assert by["staticonly.com"] == "static"
    assert by["learnedonly.com"] == "learned"
    assert by["shared.com"] == "seed"          # priority seed > static > learned
    # one row per pattern (deduped)
    assert sum(1 for t in tagged if t["pattern"] == "shared.com") == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bypass_sources.py::test_load_bypass_tagged_dedups_priority -q`
Expected: FAIL — `AttributeError: module 'secubox_toolbox.api' has no attribute '_load_bypass_tagged'`

- [ ] **Step 3: Implement the helper + route in `api.py`**

Add the helper near `_load_bypass_entries`:
```python
def _read_patterns(path: "Path") -> list:
    try:
        return [ln.strip() for ln in path.read_text().splitlines()
                if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


def _load_bypass_tagged() -> list:
    """All bypass patterns across the three sources, one row per pattern, tagged
    with the most authoritative source (seed > static > learned)."""
    seen: dict = {}
    for source, path in (("seed", MITM_BYPASS_SEED_FILE),
                         ("static", MITM_BYPASS_FILE),
                         ("learned", MITM_BYPASS_DYNAMIC_FILE)):
        for pat in _read_patterns(path):
            if pat not in seen:        # first wins → seed > static > learned
                seen[pat] = source
    return [{"pattern": p, "source": s} for p, s in sorted(seen.items())]
```
Add the route alongside the other `/admin/filter-control/*` routes:
```python
@router.get("/admin/filter-control/list")
async def admin_filter_list() -> dict:
    """JSON for the #filtres panel — tagged bypass patterns (seed/static/learned)."""
    return {"hosts": _load_bypass_tagged(), "count": len(_load_bypass_tagged())}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-toolbox && python -m pytest tests/test_bypass_sources.py -q`
Expected: PASS (3 passed). Then full suite `python -m pytest tests/ -q`.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/secubox_toolbox/api.py packages/secubox-toolbox/tests/test_bypass_sources.py
git commit -m "feat(toolbox): add tagged /admin/filter-control/list endpoint for #filtres panel (ref #633)"
```

---

### Task 3: 3-way merge in the launch script

**Files:**
- Modify: `packages/secubox-toolbox/sbin/secubox-toolbox-mitm-wg-launch`

- [ ] **Step 1: Inspect the merge loop**

Run: `cd packages/secubox-toolbox && grep -n "BYPASS_FILE=\|DYNAMIC_FILE=\|for src in" sbin/secubox-toolbox-mitm-wg-launch`
Confirm `BYPASS_FILE` / `DYNAMIC_FILE` definitions and the `for src in "$BYPASS_FILE" "$DYNAMIC_FILE"; do` loop.

- [ ] **Step 2: Add the seed source**

After the `DYNAMIC_FILE=...` line, add:
```sh
SEED_FILE=/usr/lib/secubox/toolbox/conf/mitm-bypass-seed.conf
```
Change the merge loop from:
```sh
for src in "$BYPASS_FILE" "$DYNAMIC_FILE"; do
```
to:
```sh
for src in "$SEED_FILE" "$BYPASS_FILE" "$DYNAMIC_FILE"; do
```
(The loop already guards file existence and the downstream `sort -u` dedups across
sources — so the seed's patterns merge + dedup with operator + learned entries.)

- [ ] **Step 3: Verify**

Run: `cd packages/secubox-toolbox && bash -n sbin/secubox-toolbox-mitm-wg-launch` (no syntax error).
Run: `grep -n "SEED_FILE\|for src in" sbin/secubox-toolbox-mitm-wg-launch` — confirm `$SEED_FILE` is first in the loop.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/sbin/secubox-toolbox-mitm-wg-launch
git commit -m "feat(toolbox): merge package bypass seed into ignore_hosts (3-way) (ref #633)"
```

---

### Task 4: `#filtres` panel — source-badge legend

**Files:**
- Modify: `packages/secubox-toolbox/www/toolbox/index.html` (`loadFilters` + a small legend)

`loadFilters()` already renders `h.source` as a dim span. This task adds a one-line
legend so the badges are intelligible, and maps the raw source to an emoji badge.

- [ ] **Step 1: Inspect current loadFilters + panel markup**

Run: `cd packages/secubox-toolbox && grep -n "loadFilters\|panel-filtres\|id=.filters\|Hosts bypass" www/toolbox/index.html`
Read the `loadFilters` function and the `#panel-filtres` section.

- [ ] **Step 2: Update `loadFilters` to badge the source**

Replace the `el.innerHTML = items.map(...)` block in `loadFilters` with one that maps
source → emoji and renders a badge:
```javascript
    const BADGE = {seed: '🌱 seed', static: '✋ static', learned: '🔍 learned'};
    el.innerHTML = items.map(h => {
        const host = typeof h === 'string' ? h : (h.host || h.pattern || JSON.stringify(h));
        const src = (typeof h === 'object' && h.source) ? h.source : '';
        const badge = BADGE[src] || src;
        return `<li><code>${host}</code>${badge ? ` <span style="color:var(--p31-dim,#888);font-size:0.72rem">${badge}</span>` : ''}</li>`;
    }).join('');
```

- [ ] **Step 3: Add a legend under the panel heading**

In the `#panel-filtres` section, immediately after the existing description line
(the `<p>`/text under `<h2>🚦 Hosts bypassés ...`), add:
```html
            <p style="font-size:0.72rem;color:#888">Sources : 🌱 seed (paquet) · ✋ static (opérateur) · 🔍 learned (cert-pin auto)</p>
```
(Match the surrounding indentation/markup style.)

- [ ] **Step 4: Verify (static check — no JS test harness in this package)**

Run: `cd packages/secubox-toolbox && grep -n "BADGE\|🌱 seed\|Sources :" www/toolbox/index.html`
Expected: the BADGE map in `loadFilters` and the legend line both present.
Run: `python -c "import pathlib; t=pathlib.Path('www/toolbox/index.html').read_text(); assert t.count('loadFilters')>=1 and '🌱 seed' in t; print('ok')"`

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-toolbox/www/toolbox/index.html
git commit -m "feat(toolbox): #filtres panel source badges + legend (seed/static/learned) (ref #633)"
```

---

### Task 5: packaging + full gate

**Files:**
- Modify: `packages/secubox-toolbox/debian/changelog`

- [ ] **Step 1: Confirm seed ships + module changes ship**

Run: `cd packages/secubox-toolbox && grep -n "cp -r conf\|cp -r secubox_toolbox\|cp -r www" debian/rules`
Expected: `conf` (ships the seed), `secubox_toolbox` (ships api.py), and the www copy (ships index.html) all present. Report.

- [ ] **Step 2: Bump changelog**

New top entry `2.6.46-1~bookworm1` (after `2.6.45`), dch format, author `Gerald KERMA <devel@cybermind.fr>`, dated 2026-06-17:
```
  * Anti-Track v2 Plan 2c (#633): fix empty #filtres panel — add the missing
    GET /admin/filter-control/list (tagged seed/static/learned) + source badges.
    Move the inline cert-pinned bypass defaults into a package-owned
    mitm-bypass-seed.conf (operator file now starts empty); launch script merges
    seed + operator + learned into ignore_hosts (behavior-preserving).
```

- [ ] **Step 3: Full gate**

Run: `cd packages/secubox-toolbox && python -m pytest tests/ -q` (expect all green, ~55).
Run: `python -c "import ast; ast.parse(open('secubox_toolbox/api.py').read()); print('ok')"`.
Run: `bash -n sbin/secubox-toolbox-mitm-wg-launch`.
Run: `dpkg-parsechangelog -l debian/changelog | grep Version` → `2.6.46-1~bookworm1`.
Run: `git status --short` → empty after commit.

- [ ] **Step 4: Commit**

```bash
git add packages/secubox-toolbox/debian/changelog
git commit -m "chore(toolbox): changelog for Anti-Track v2 Plan 2c (ref #633)"
```

---

## Self-Review

**Spec coverage (revised scope, §0):**
- §0 primary — missing `/list` endpoint (tagged) → Task 2. ✓
- §0 secondary — move inline seed → package file, operator file empty → Task 1. ✓
- §2/§3 seed file (verbatim, behavior-preserving incl. pinned-but-broad entries) → Task 1. ✓
- §2 3-way merge → Task 3. ✓
- §4 tagged read (seed>static>learned dedup) → Task 2 `_load_bypass_tagged`. ✓
- §5 source badges + legend → Task 4. ✓
- §6 tests (seed valid alternation; tagged dedup priority; missing source skipped via `_read_patterns` OSError→[]) → Tasks 1, 2. ✓
- Packaging → Tasks 1, 5. ✓
- **Behavior-preservation note:** the seed keeps the existing broad-but-pinned
  entries (googleapis/facebook) verbatim — removing them would re-MITM pinned apps
  and break them (per the inline comments). The spec's "conservative" guidance
  governs FUTURE additions, not removing battle-tested entries. Recorded so it
  isn't read as a contradiction with §3.

**Placeholder scan:** none — Task 1 Step 1 is "copy these exact existing lines from
`_MITM_BYPASS_DEFAULT_ENTRIES`" (a precise, in-repo source), not a vague fill-in.

**Type consistency:** `_load_bypass_tagged() -> list[{pattern,source}]` (Task 2) ↔
the `/list` route returning `{"hosts": [...]}` ↔ `loadFilters` reading `d.hosts` +
`h.pattern`/`h.source` (Task 4). `MITM_BYPASS_SEED_FILE`/`MITM_BYPASS_DYNAMIC_FILE`
consistent across Tasks 1/2 and the test monkeypatches. `SEED_FILE` path in the
launch script (Task 3) matches `MITM_BYPASS_SEED_FILE` default.

**Rollout:** behavior-preserving (same bypass coverage via the seed); the panel
becomes populated (the `/list` fix). TLS-passthrough is orthogonal to
`privacy_enforce` (pinned apps need it regardless), so 2c is NOT dark-gated — but
it's behavior-neutral on the ignore_hosts set. No shared-dir mode changes; seed is
read-only under `/usr/lib/secubox/toolbox/conf/`.
