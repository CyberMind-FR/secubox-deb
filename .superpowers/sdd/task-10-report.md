# Task 10 Report: webui — lifecycle/wake_class/sleep-state + manual sleep/wake (secubox-profiles, ref #896)

**Status:** Done.

(Note: this file previously held an unrelated stale Task-10 report for a
different plan — a `secubox-metablogizer` packaging task — overwritten
here since it did not belong to this plan.)

## What was implemented

- `packages/secubox-profiles/api/web.py`:
  - `_build_status_payload(manifests, actuals)` — each module row now also
    carries `lifecycle` (the **effective** value from
    `lifecycle.effective_lifecycle(m)`, so a protected module reads
    `"always-on"` regardless of its declared manifest value — consistent
    with how `protected` is already surfaced), `wake_class` (raw
    `m.wake_class`), `sleep_state`, and `wake_budget_s`.
    `sleep_state ∈ {"up","asleep","n/a"}`: `"n/a"` when
    `effective_lifecycle(m)` is `always-on`/`manual`; otherwise `"up"` if
    `observe.is_on(a)` else `"asleep"`. **`"waking"` is deliberately NOT
    modeled** — the only candidate signal (`api/waker.py`'s
    `waker-active.json`) is a best-effort anti-storm lock, not a reliable
    "in-progress" probe; inventing a third state off it would be exactly
    the fragile probe the task brief warned against. Documented inline.
    `wake_budget_s` is `lifecycle.wake_budget(m)` for sleepable modules,
    `None` for `n/a` ones.
  - Refactored `_run_ctl_json(verb)` into a shared `_run_ctl_json_argv(argv)`
    (same parse-report-first-then-rc logic, now argv-agnostic) plus three
    thin builders: `_run_ctl_json(verb)` (apply/rollback, unchanged
    behavior), `_run_wake_ctl(module)`, `_run_sleep_ctl(module)`.
  - New `POST /api/v1/profiles/wake` and `POST /api/v1/profiles/sleep`
    (`ModuleAction{module: str}` body): both JWT-gated
    (`Depends(require_jwt)`), both refuse **locally** (structural refusal,
    before any sudo call — same posture as the pin protected-off check)
    via a shared `_sleepable_module_or_error(mod_dir, module)`: unknown
    module → 404, non-sleepable (`always-on`/`manual`, incl.
    protected-forced) → 409. Both then run under `_apply_lock` (same
    process-local serialization as apply/rollback) and delegate to the
    ctl, returning its JSON report as-is (refused/rolled_back statuses
    surface in the 200 body, exactly like apply's `rolled_back` already
    does — the caller/panel classifies the status, not the HTTP code).

- `packages/secubox-profiles/sudoers.d/secubox-profiles` — **two new
  grants** (visudo -c passes):
  ```
  secubox ALL=(root) NOPASSWD: /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/secubox-wakectl wake *
  secubox ALL=(root) NOPASSWD: /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/secubox-profilectl apply --only * --yes --json
  ```
  Both were **required**, not deferrable:
  - The existing `secubox-wakectl wake *` grant (from Task 6/waker) is
    **fire-and-forget** (no `--wait --pipe`) — used by `api/waker.py`'s
    `_fire_wake`, which never blocks a public request on the outcome. The
    panel's manual Wake button needs the *synchronous* report to show the
    operator what happened, which is a **different, additional** command
    line (`--wait --pipe` inserted) that does not match the existing rule.
  - `/sleep` reuses the existing `apply` actuator (no new privileged code
    path) scoped to one module via `--only <id>`, but the only sudoers rule
    for `apply` was the exact-string `apply --yes --json` (no `--only`) —
    a genuinely new, bounded wildcard grant was needed.
  Both wildcards are safe for the same reason already documented for the
  pre-existing wake grant (quoted/extended in the file): sudo matches argv
  via `execve`, never a shell, so glob metacharacters in a module id are
  inert; and the downstream CLI (`secubox-wakectl`/`secubox-profilectl`)
  only ever acts on ids it recognizes from `modules.d` — an unrecognized id
  either gets `status=refused` (wake) or silently filters the plan to
  nothing (sleep's `--only`), never arbitrary execution.

- `packages/secubox-profiles/www/profiles/index.html` — each module row
  gained one more grid column: a `sleep_state` pill (🟢 up / 🌙 asleep /
  the raw lifecycle label for n/a) plus, when sleepable, the one
  applicable manual action button (💤 Sleep when up, ⚡ Wake when asleep,
  titled with the `wake_budget_s` estimate; no button for n/a). Wired via
  a `data-act="wake"|"sleep"` click handler mirroring the existing
  pin-button pattern: POST to the new routes, refresh() on completion,
  toast/errorToast based on the returned report's `status`/`failed`.
  Sleep asks `confirm()` first (it stops a running module); Wake does not
  (idempotent no-op if already up). New column hidden on the existing
  mobile media query alongside meta/prio/rss/member (unchanged narrow
  layout otherwise). Verified with `node --check` on the extracted
  `<script>` body (no syntax errors).

## TDD: RED → GREEN

- Added tests to `tests/test_web.py` (status payload extension, wake/sleep
  delegation-argv, 404, 409, JWT-gating) — ran first to confirm RED:
  `python -m pytest tests/test_web.py -q -k "lifecycle_wake_class or wake_route or sleep_route or wake_and_sleep"`
  → **6 failed** (routes/fields didn't exist yet; the JWT test failed
  because the routes 404'd before ever reaching `require_jwt`, i.e. it
  wasn't a false-positive pass).
- Implemented the payload extension, the two routes, and the sudoers
  grants.
- GREEN: same command → **8 passed**.

## Test results

```
cd packages/secubox-profiles && python -m pytest tests/test_web.py -q
```
**44 passed** (8 new, 36 pre-existing untouched).

Full suite:
```
cd packages/secubox-profiles && python -m pytest tests/ -q
```
**236 passed**, 3 warnings (pre-existing FastAPI `on_event` deprecation
warnings, unrelated).

## mypy vs. baseline

Non-strict (`mypy api/`): **3 errors** before and after — identical
(`api/scan.py:80`, `api/snapshot.py:55`, `api/web.py:49` import-not-found
for `secubox_core.auth`, all pre-existing, none touched).

`--strict` (matches Task 7's comparison method): baseline **93 errors in
12 files** (checked via `git stash` of this task's 4 changed files) →
after this task **102 errors in 12 files** (+9). All 9 new errors are
instances of the **same two categories already pervasive throughout
`web.py`** before this task (every existing nested route handler in the
file is already untyped the same way): `no-untyped-def` (missing
return/param annotation — the 3 new nested route-scoped helpers
`_sleepable_module_or_error`, `wake_module`, `sleep_module` follow the
exact same unannotated-`_claims=Depends(...)` idiom as every pre-existing
handler like `set_pin`/`apply_active`) and `type-arg` (bare `dict` return
annotation — the 3 new top-level ctl helpers `_run_ctl_json_argv`,
`_run_wake_ctl`, `_run_sleep_ctl` return bare `dict`, matching ~15
pre-existing bare-`dict` returns elsewhere in the same file). No new
error *category* was introduced.

## Delegation argv (webui→ctl)

- `POST /wake {module}` →
  `sudo -n /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/secubox-wakectl wake <module> --json`
- `POST /sleep {module}` →
  `sudo -n /usr/bin/systemd-run --wait --pipe --collect --quiet /usr/sbin/secubox-profilectl apply --only <module> --yes --json`

Both under `_apply_lock` (process-local asyncio.Lock, same one apply/
rollback/active already share) and `Depends(require_jwt)`.

## What T12 must wire

- Nothing new beyond what earlier tasks already deferred to T12 (nginx
  `@waker` include wiring, WAF route file, etc.) — **no new sudoers grant
  is deferred here**; both grants this task needed were shipped and
  `visudo -c`'d in this task, since the brief called them out as a real
  requirement, not deferrable.
- The panel's new column is additive CSS/markup only; no server-side
  wiring is needed beyond the two routes added here.

## Self-review

- Confirmed `test_web_module_has_no_actuation_helper` (greps `web.py` for
  `systemctl start/stop/enable/disable`, `lxc-start/lxc-stop`) still
  passes — the new code only ever shells out through `_ctl_run` to
  `sudo`/`secubox-wakectl`/`secubox-profilectl`, never touches
  systemd/LXC directly.
- Confirmed `/wake` and `/sleep` reject unknown/non-sleepable modules
  **before** calling `_ctl_run` at all (asserted via a `called=[]` list in
  the 404/409 tests), matching the "never actuate for a refusal" posture
  already used for the pin protected-off check.
- Confirmed the two new sudoers lines with `visudo -cf
  sudoers.d/secubox-profiles` (parses clean) — chose to ship them now
  rather than defer, per the brief's explicit instruction that a
  genuinely-needed grant is not deferrable.
- Extracted the panel's `<script>` body and ran `node --check` on it to
  catch any JS syntax errors from the new markup-building code before
  committing.
- Verified the `sleep_state`/`wake_budget_s` semantics against a 3rd,
  on-demand/urgent fixture module (`podcast`, deliberately left
  unobserved by the test's `_observe_all` stub) to prove the
  `is_on()`-driven None→False→"asleep" coalescing, not just the two
  pre-existing fixture modules (`lyrion` eager/observed-on, `auth`
  protected/always-on).

## Concerns

- `/sleep`'s reuse of `apply --only <module>` is correct **only** because
  `plan_changes` already computes a STOP for any currently-up sleepable
  module that is not desired ON (absent from the active profile / not
  pinned on) — this is the common case for genuinely on-demand modules,
  which typically aren't listed as profile members. If an operator adds a
  sleepable module to the active profile's `on` list (making it
  desired-ON), a manual Sleep click becomes a **safe no-op**
  (`changed: []`, no error) rather than a forced stop, because `apply`
  will always want to re-converge it back on. This is intentional
  (avoids fighting the declared desired state) but may surprise an
  operator who expects Sleep to always work — flagging in case a
  dedicated "force sleep" actuator (bypassing desired-state) is wanted
  later.
- `sleep_state`'s `"waking"` value from the brief's enum is not emitted by
  this implementation (only `"up"`/`"asleep"`/`"n/a"`) — deliberately, per
  the brief's own permission to omit it absent a reliable signal. Noted
  in code and here in case a future task adds a proper in-progress probe.
