# Task 5 Report — Portable backup (`api/publish/backup.py`)

## Status: DONE

## Steps executed

1. Wrote `packages/secubox-metablogizer/api/tests/test_publish_backup.py` verbatim from `.superpowers/sdd/task-5-brief.md`.
2. Ran the test to confirm failure:
   ```
   cd packages/secubox-metablogizer && PYTHONPATH=api <venv>/bin/python -m pytest api/tests/test_publish_backup.py -q
   ```
   Result: `ModuleNotFoundError: No module named 'publish.backup'` (collection error), as expected.
3. Wrote `packages/secubox-metablogizer/api/publish/backup.py` verbatim from the brief (`export_site` / `import_site`, git-bundle-or-plain-tar + manifest.json).
4. Re-ran the same command:
   ```
   2 passed, 3 warnings in 0.08s
   ```
   The 3 warnings are `DeprecationWarning` from Python 3.12's `tarfile.extractall` about the future (3.14) default extraction filter — pre-existing stdlib deprecation, not a code defect, not something the brief asked to address.
5. Committed:
   ```
   git add packages/secubox-metablogizer/api/publish/backup.py packages/secubox-metablogizer/api/tests/test_publish_backup.py
   git commit -m "feat(metablogizer): portable .sbxsite backup (git bundle + manifest) with restore

   Co-Authored-By: Gerald KERMA <devel@cybermind.fr>"
   ```
   Commit: `b91b42e3`

## Concerns

- None blocking. The brief's exact code worked as-is in this sandbox (git available, `git bundle create --all` and `git clone` from a local bundle path both function normally).
- Minor, non-actionable: `tarfile.extractall()` without a `filter=` argument triggers a `DeprecationWarning` under Python 3.12 (defaults change in 3.14). The brief's code doesn't set a filter and the task said to implement it verbatim, so left as-is — flagging for awareness only, in case Task 6 or a later hardening pass wants `filter="data"`.
- `import_site` trusts the tarball content when extracting into a temp dir (`t.extractall(tdp)` comment says "trusted operator artifact") — consistent with the brief's stated trust model for `.sbxsite` files produced by `export_site`.

---

Note: this file previously contained an unrelated report ("Emancipate the webui .onion...") from a different task/branch that had been mistakenly saved at this path in this worktree. That content has been replaced above with the actual Task 5 (MetaBlogizer backup) report; the prior content is preserved in git history if needed.

---

## Follow-up: security hardening — path traversal fix (2026-07-11)

### Findings addressed

1. **Critical — unsanitized `manifest["name"]`.** `import_site` built `target = dest_root / name` directly from the operator-supplied manifest. An absolute `name` (e.g. `/etc/cron.d/x`) discards `dest_root` entirely (`Path.__truediv__` semantics), and a `..`-laden name traverses out of `dest_root`. Fixed by validating `name` immediately after `manifest = json.loads(...)`:
   ```python
   name = manifest.get("name")
   if not name or "/" in name or "\\" in name or name in (".", ".."):
       raise ValueError(f"invalid site name in manifest: {name!r}")
   ```
   This also turns a missing `name` key into a clear `ValueError` instead of an opaque `KeyError` (previously flagged as a minor issue).

2. **Critical — unfiltered `tarfile.extractall()` (tar-slip / CVE-2007-4559 class).** Both extractions in `import_site` were unfiltered:
   - outer `.sbxsite` extraction into the temp staging dir
   - inner `content.tar` extraction into `target`

   Both now pass `filter="data"` (Python 3.12 stdlib feature, available on both the board and the repo `.venv`), which rejects absolute paths, `..` traversal, and unsafe symlinks/devices. This also resolves the `DeprecationWarning` noted in the original report (3.14 will default to `"data"` anyway).

`export_site` and the git-bundle path logic were left untouched, per the brief.

### Regression test added

Appended `test_import_rejects_traversal_name` to `api/tests/test_publish_backup.py`: hand-builds a `.sbxsite` (tar.gz of `content.tar` + `manifest.json` with `"name": "../../etc"`) and asserts `import_site` raises `ValueError`.

### Test command and output

```
cd /home/reepost/CyberMindStudio/secubox-deb-worktrees/832-metablogizer-publisher-wizard/packages/secubox-metablogizer && PYTHONPATH=api /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest api/tests/test_publish_backup.py -q
```
```
...                                                                      [100%]
3 passed in 0.09s
```

All 3 tests pass (the 2 pre-existing round-trip tests + the new traversal-rejection test), with no deprecation warnings now that `filter="data"` is explicit.

### Commit

`fix(metablogizer): harden .sbxsite import against path traversal (name + tar filter)`

### Concerns

- None blocking. `filter="data"` requires Python ≥ 3.12 (confirmed available: board and `.venv` both run 3.12). If this module is ever run under an older Python, `extractall(..., filter="data")` would raise instead of silently falling back — acceptable since the target runtime is fixed at 3.12.
