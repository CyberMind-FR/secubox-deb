# Task 4 — Python metatag reader (`common/secubox_core/media_buffer.py`)

**Status:** DONE

**Commit:** `d6ef7d25` — "feat(core): media-buffer metatag reader (dedup by id, fail-empty) (ref #812)"
(local only, not pushed, per instructions)

## Test command + result

```
cd common && PYTHONPATH=. python3 -m pytest secubox_core/tests/test_media_buffer.py -q
```
Result: **8 passed** (0 failed).

Full `secubox_core/tests/` suite also run for regression check: 31 passed, 5
pre-existing failures in `test_auth_rewire.py` — unrelated to this task
(local-env `/etc/secubox` 0750-parent traversal `PermissionError`, a known
issue per project memory, not touched by this change).

## What was built

- `common/secubox_core/media_buffer.py`:
  - `MEDIA_BUFFER_PATH = "/data/secubox/media-buffer/media-buffer.jsonl"`
  - `_tail_lines` — copied verbatim in structure/behavior from
    `media_catch.py` (bounded `max_bytes` tail read off disk, drops a
    partial first line on a mid-file seek, swallows `OSError`/decode
    errors).
  - `_deduped_records(path, max_lines, max_bytes)` — internal helper: parses
    the tail into `{id: record}`, later lines overwrite earlier ones
    (last-writer-wins), skipping records without an `id` and swallowing
    per-line JSON errors.
  - `read_records(path, mac_hash=None, max_lines=2000, max_bytes=16MiB)` —
    deduped, optionally filtered by `mac_hash`, sorted newest-first by
    `first_ts` descending. Fail-empty on any file error.
  - `record_by_id(rec_id, path, max_lines, max_bytes)` — deduped single
    lookup, `None` on missing/absent file.
  - SPDX header copied from `media_catch.py`.
  - Pure stdlib (`json`, `os`, `pathlib`) — no FastAPI/third-party.

- `common/secubox_core/tests/test_media_buffer.py` — 8 tests covering:
  dedup keeps the janitor's expired flip (plan's exact test case),
  `record_by_id` missing → `None`, mac_hash filter, fail-empty on missing
  file, fail-empty on corrupt/partial lines mixed with valid ones,
  fail-empty on a genuinely empty file, newest-first ordering, and an
  extra case verifying `max_lines` bounds the tail-read result count
  (kept most-recently-appended lines).

## Deviations from the plan

- Added `max_bytes` as an explicit parameter (default `16 * 1024 * 1024`,
  matching `media_catch.py`'s default) on both public functions and on the
  internal `_deduped_records` helper, rather than hardcoding it — mirrors
  `media_catch.aggregate`'s signature style and gives callers/tests the
  same knob `media_catch.py` exposes. Not requested explicitly by the
  Task 4 spec but consistent with the "mirror media_catch.py" instruction.
  No other deviations; all four required test cases from the plan (dedup
  + expired flip, mac_hash filter, fail-empty variants, newest-first) are
  present verbatim or as closely-mirrored variants.

## Concerns

None blocking. Note for Task 5 (DPI API) implementer: `record_by_id`
returns `None` for a missing id (no exception) — matches the plan's stated
`-> dict | None` signature. The API layer will need to turn that into its
own `HTTPException(410, …)` as specified in Task 5; this module does not
raise.

Note: found a stale `task-4-report.md` already in this directory belonging
to an unrelated feature (exposure API, #793) — overwritten per the parent
task's explicit instruction to ignore/replace stale same-numbered reports
from other features.

## Addendum — regression tests for copy-pasted `_tail_lines` (test-only, ref #812)

`_tail_lines` in `media_buffer.py` is a byte-for-byte copy of the
previously-buggy-then-fixed version in `media_catch.py` (ref #785 Fix 1),
but the original 8 media_buffer tests never drove the `size > max_bytes`
seek branch. Added two tests to
`common/secubox_core/tests/test_media_buffer.py`:

- `test_bounded_tail_read_drops_partial_first_line` — 20 fixed-width JSONL
  records (byte-identical 87-byte lines) read with `max_bytes=200`; asserts
  the mid-line seek's partial first record (`r017`) is dropped and only the
  2 full trailing records (`r018`, `r019`) are returned, newest-first, with
  no crash.
- `test_valid_json_missing_id_or_first_ts` — a record missing `id` is
  excluded (can't be deduped), a record missing `first_ts` is still
  returned and sorts as if `first_ts=0`; asserts `read_records` does not
  raise either way.

Both were verified against the current implementation before being added
(manual repro scripts) — no production code was touched.

- Status: done
- Commit: (see below)
- Test summary: 10 passed (8 original + 2 new) — `pytest secubox_core/tests/test_media_buffer.py -q`
- Bug surfaced by new tests: none — both target already-correct behavior (regression lock-in only)
- Concerns: none blocking
