<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# MetaBlogizer site.json Schema + Version Metadata — Design

**Date:** 2026-05-12
**Author:** Gandalf (CyberMind), with Claude
**Status:** Draft for approval
**Issue:** [#101](https://github.com/CyberMind-FR/secubox-deb/issues/101) (sub-project C of [#49](https://github.com/CyberMind-FR/secubox-deb/issues/49))
**Depends on:** [#93](https://github.com/CyberMind-FR/secubox-deb/pull/93) (merged), [#97](https://github.com/CyberMind-FR/secubox-deb/pull/97) (merged), [#99](https://github.com/CyberMind-FR/secubox-deb/pull/99) (merged)

## Context

The 166 MetaBlogizer sites live in `/srv/metablogizer/sites/<name>/`. 61 currently have a `site.json` with informal fields (`name`, `domain`, `published`, sometimes `title`, `description`). The other 105 have no `site.json` at all. All 166 are mirrored in Gitea as `gandalf/metablog-<name>` with `v1.0.0` tag (from sub-B). The 28 Streamlit apps from sub-F are at `gandalf/streamlit-<app>`.

The existing FastAPI exposes `/sites` (returns `{sites: [...], count: N}` from a `load_sites()` reader) and `/site/{name}`. Both are JWT-protected via `Depends(require_jwt)`. The reader doesn't enforce a schema today.

Sub-project D (Dashboard) needs versioned metadata: which Gitea tag is each site at, when was it last updated, does it have a linked Streamlit app. C provides that without touching content.

## Goal

A formal `site.json` schema, a backfill for the 105 sites without one, and an API that surfaces enriched metadata (including the current Gitea tag) for every site.

## Non-goals

- Editing site content — only metadata files
- Dashboard UI (sub-D)
- Webhook on Gitea tag push (sub-E)
- Migrating existing `title`/`description` data — preserved verbatim

## Decisions taken in brainstorming

| Decision | Choice | Rationale |
|----------|--------|-----------|
| `version` policy when site.json lacks it | Auto-read from git tag (`git describe --tags --exact-match` → fallback `git describe --tags`) | site.json stays optional; no drift between file and reality |
| Backfill for 105 sites without site.json | Complete — `{name, domain, published, version, streamlit_app}` with streamlit_app auto-detected from Gitea | Get all 166 sites schema-valid in one pass |
| Backfill for the 61 with site.json | Preserve verbatim; `--force` flag to merge missing fields | Don't lose manual edits |
| Schema format | JSON Schema draft-07 | Standard, validated by `jsonschema` Python lib |
| `last_updated` policy | Derived: `git log -1 --format=%cI` of `HEAD` if absent | One source of truth |
| Validation runtime | Lazy at read time in `_load_site_json()` — log warnings, don't reject | Permissive: an invalid file shouldn't break the dashboard |
| API enrichment | All API responses run through `enrich()` so consumers always see the full shape | Single contract between API and downstream (D) |

## Schema

`packages/secubox-metablogizer/schema/site.json.schema.json` (JSON Schema draft-07):

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://apt.secubox.in/schema/metablog/site.json",
  "title": "MetaBlogizer site.json",
  "type": "object",
  "required": ["name", "domain", "published"],
  "additionalProperties": true,
  "properties": {
    "name":           {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,62}$"},
    "domain":         {"type": "string", "format": "hostname"},
    "published":      {"type": "boolean"},
    "version":        {"type": ["string", "null"], "pattern": "^v[0-9]+\\.[0-9]+\\.[0-9]+$"},
    "title":          {"type": ["string", "null"]},
    "description":    {"type": ["string", "null"]},
    "category":       {"type": ["string", "null"]},
    "streamlit_app":  {"type": ["string", "null"], "description": "Name of the gandalf/streamlit-<X> repo on Gitea, if any"},
    "tags":           {"type": "array", "items": {"type": "string"}},
    "last_updated":   {"type": ["string", "null"], "format": "date-time"}
  }
}
```

`additionalProperties: true` because some sites already carry ad-hoc fields (e.g. `auto-deploy`, `mirror`) the schema doesn't yet model — we don't want to strip them on read.

## Architecture

### Component 1 — Validator + enricher (`api/site_schema.py`)

A small Python module sitting next to `api/main.py`:

```python
# packages/secubox-metablogizer/api/site_schema.py
"""site.json schema validator + enricher."""
from __future__ import annotations
import json
import subprocess
from pathlib import Path
from typing import Any
import jsonschema  # already in secubox-core deps

SCHEMA_PATH = Path(__file__).parent.parent / "schema" / "site.json.schema.json"

def load_schema() -> dict:
    with SCHEMA_PATH.open() as f:
        return json.load(f)

def validate(doc: dict) -> tuple[bool, list[str]]:
    """Return (ok, errors). Permissive: doc may have extra fields."""
    schema = load_schema()
    validator = jsonschema.Draft7Validator(schema)
    errors = [f"{'.'.join(map(str, e.path)) or '<root>'}: {e.message}"
              for e in validator.iter_errors(doc)]
    return (not errors, errors)

def _git(*args: str, cwd: Path) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(cwd), *args],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None

def enrich(doc: dict, app_dir: Path) -> dict:
    """Fill derived fields (version, last_updated) if missing."""
    out = dict(doc)
    if not out.get("version") and (app_dir / ".git").exists():
        out["version"] = _git("describe", "--tags", "--exact-match", cwd=app_dir) \
                      or _git("describe", "--tags", "--always", cwd=app_dir)
    if not out.get("last_updated") and (app_dir / ".git").exists():
        out["last_updated"] = _git("log", "-1", "--format=%cI", cwd=app_dir)
    return out
```

### Component 2 — Backfill script (`scripts/metablog-site-backfill.sh`)

Walks `/srv/metablogizer/sites/*` on the MOCHAbin via SSH (same pattern as PR #97):

```
For each <name> in /srv/metablogizer/sites/:
  If site.json missing:
    streamlit_app := "streamlit-<name>" if Gitea has gandalf/streamlit-<name>.git else null
    version := first existing tag from `git describe --tags --exact-match` on the local .git, else "v1.0.0"
    Write site.json with: {name, domain=<name>.gk2.secubox.in, published=true, version, streamlit_app}
  Else:
    If --force: merge missing fields (preserve all existing keys + values)
    Else: skip (preserve verbatim)
```

Flags:

- `--dry-run` (print actions, don't write)
- `--force` (merge missing fields into existing site.json)
- `--site <name>` (limit to one)

Output: `output/metablog-backfill-report.json` with per-site action (`created` / `merged` / `skip-already-complete` / `fail-<reason>`).

### Component 3 — API extension

`packages/secubox-metablogizer/api/main.py` already has `load_sites()` and `/sites` + `/site/{name}` endpoints. Modify:

- `_load_site_json(name)` (new helper, or inline in `load_sites`):
  - Read `<sites_root>/<name>/site.json` if present, else `{}`
  - Run `enrich(doc, sites_root/name)`
  - Run `validate(doc)`; on errors, log a warning at `WARNING` level with the per-field errors, but still return the doc
  - Always overlay `name = <dir>` to guarantee the field is present even if site.json forgot it
- `/sites` and `/site/{name}` continue returning the same shape, now with the enriched fields automatically present.

Keep `Depends(require_jwt)` on both endpoints (no change).

### Component 4 — Smoke test (`tests/scripts/test-metablog-site-schema.sh`)

Two gates:

1. **Backfill dry-run** — runs `--dry-run` and asserts the report shows 105 `would-create` + 61 `skip-already-complete`. (Counts may shift over time; the test reads the report and asserts `would-create + skip >= 166` instead of hardcoding.)
2. **Schema validation** — for each of the 166 sites, fetch the site.json (or generate it via enrich), run `validate()`, expect `(True, [])`.
3. **API surface** — `curl --unix-socket /run/secubox/metablogizer.sock http://x/sites -H "Authorization: Bearer ${JWT}"` returns 166 entries, every entry has `version` populated (file or git fallback).

The test should NOT need to actually run the live backfill — gate 1 is dry-run, gate 2 reads from disk, gate 3 hits the live API.

## File-level changes

| Action | Path | Purpose |
|--------|------|---------|
| Create | `packages/secubox-metablogizer/schema/site.json.schema.json` | JSON Schema draft-07 |
| Create | `packages/secubox-metablogizer/api/site_schema.py` | `load_schema()`, `validate()`, `enrich()` |
| Modify | `packages/secubox-metablogizer/api/main.py` | Add `_load_site_json` helper that uses the validator/enricher; update `load_sites()` to call it |
| Modify | `packages/secubox-metablogizer/debian/control` | Add `python3-jsonschema` to `Depends:` if not already there |
| Create | `scripts/metablog-site-backfill.sh` | Backfill orchestrator (SSH to MOCHAbin) |
| Create | `tests/scripts/test-metablog-site-schema.sh` | 3-gate smoke |
| Modify | `packages/secubox-metablogizer/README.md` | Document schema + backfill |
| Modify | `.gitignore` | Ignore `output/metablog-backfill-report.json` |
| Modify | `.claude/WIP.md`, `.claude/HISTORY.md` | Session 164 entry |

## Validation gate

The change is "done" when:

1. `bash scripts/metablog-site-backfill.sh --dry-run` reports `would-create + skip-already-complete >= 166`.
2. Backfill actually run on the MOCHAbin produces 166 schema-valid `site.json` files.
3. `bash tests/scripts/test-metablog-site-schema.sh` passes all 3 gates.
4. `curl ... /api/v1/metablogizer/sites` returns 166 entries, each with non-null `version`.
5. At least 5 random sites in the response have `streamlit_app` populated (those whose corresponding `gandalf/streamlit-<name>.git` exists).

## Error handling

| Failure | Detection | Response |
|---------|-----------|----------|
| `jsonschema` not installed | `import` fails at API startup | Log critical, fall back to no validation (preserves API uptime) |
| Site.json malformed JSON | `json.load` raises | Log warning per-site, return `{name: <dir>}` enriched with git data |
| `git` not available in the API runtime | `subprocess` returns FileNotFoundError | `enrich()` leaves fields null; not a fatal error |
| Backfill: target dir vanished mid-run | `mkdir`/`write` fails | Record as `fail-no-dir` in report; continue with next site |
| Streamlit repo check: Gitea unreachable | `git ls-remote` fails | Set `streamlit_app = null` and continue; do not fail the whole site |

## Testing

Operational + module-level Python. Two layers:

1. **`api/site_schema.py`** — pytest tests for `validate()` on representative docs (valid, missing required, malformed version pattern, extra fields), and `enrich()` on a temp git repo.
2. **Smoke test** — the 3-gate script above for end-to-end on the live MOCHAbin.

## Open questions

None blocking. The schema's `additionalProperties: true` keeps it forward-compatible.

## Licensing

CMSD-1.0. Python module gets the SecuBox header (per `.claude/CLAUDE.md` Python convention); JSON Schema gets a comment at the top of the file referencing the license tag. Bash scripts: handled by license-headers tool (#81).
