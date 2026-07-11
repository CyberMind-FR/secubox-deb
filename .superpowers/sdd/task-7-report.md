# Task 7 Report — MetaBlogizer Publish Wizard UI

**Status:** Done.

(Note: this file previously held an unrelated stale Task-7 report for a
different plan — "Tor enhancement Phase 1 — webui #tor tab" — overwritten
here since it did not belong to this plan.)

## What was added

- `packages/secubox-metablogizer/www/metablogizer/index.html`:
  - New `<section class="card" id="publish-wizard">` placed right after the
    existing Sites card, inside `<main>` (before `</main>`), with the
    5-step stepper (`#wiz-steps`), name/domain/file inputs, Publish +
    Download-backup buttons, and a `<pre id="wiz-result" class="result">`
    output area.
  - New CSS block appended inside the page's existing `<style>` (after the
    touch-friendly-buttons media query): `.wizard-steps`, `.wizard-steps
    span.ok/.fail`, `#wiz-result.result`. Colors for ok/fail reuse the
    page's existing `var(--green)` / `var(--red)` tokens (the CRT phosphor
    palette) instead of the brief's hardcoded hex (`#148C66` / `#C04E24`),
    which would have clashed visually with the rest of the page.
  - New `<script>` block placed after the page's main `<script>` (which
    declares `token()` / `API` / `headers()` / `refresh()`) and before
    `crt-engine.js`. It is an IIFE that:
    - Reuses the page's real `token()` helper (reads both `sbx_token` and
      `secubox_token`) instead of the brief's illustrative `tok()` that
      only reads `sbx_token`.
    - Reuses the page's `API` constant (`/api/v1/metablogizer`) for the
      wizard/export URLs rather than hardcoding the full path.
    - Mirrors the exact multipart-fetch + 401-retry-without-header +
      redirect-to-login pattern already used by `uploadSiteContent()`
      elsewhere in the same file, for consistency.
    - Renders the JSON result via `out.textContent = JSON.stringify(...)`
      (never `innerHTML`) — safe against XSS from server data.
    - Calls the page's existing `refresh()` on successful publish so the
      Sites table picks up the new/updated site immediately.
  - Inputs use the page's existing bare `<input>` inside `.form-group`
    (no invented `form-input` class — the file's existing CSS rule
    `.form-group input { ... }` already styles any `<input>` inside a
    `.form-group`, so adding an unused class would have been dead weight).

## Endpoint contract verified against source (read-only, no `.py` touched)

Confirmed field names/response shape against
`packages/secubox-metablogizer/api/routers/publish.py`:
- `POST {API}/publish/wizard` — multipart fields `name`, `domain` (optional),
  `file`; JWT via `Depends(require_jwt)` (accepts Bearer **or** SSO session
  cookie, per `common/secubox_core/auth.py`). Response:
  `{ok, domain, steps: {content: {index_present}, version, route: {route_ok},
  cert}}` — matches the JS's `d.steps.content.index_present` /
  `d.steps.route.route_ok` reads exactly.
- `GET {API}/publish/export/{name}` — also JWT-gated but accepts the SSO
  session cookie, so the plain `window.location = ...` navigation (no
  Authorization header possible on a top-level nav) works because the
  browser sends the session cookie automatically.

## Validation

- Extracted the new `<script>` block (the one containing `wiz-go`) via a
  small Python regex script into a standalone `.js` file and ran
  `node --check` (node v22.20.0, available in this environment) —
  **no syntax error**.
- Also checked: no duplicate `id=` attributes introduced anywhere in the
  file; `<section>`, `<script>`, `<style>` tag counts balanced
  (open == close) after the edit.
- Did not run the app live (Task 11 is the manual/live verification step
  per the brief); this task's scope is UI-only markup/JS/CSS, and the API
  side (Task 6) was not modified.

## Helpers reused (per the "match existing conventions" instruction)

- `token()` — the page's real dual-key localStorage reader (`sbx_token` /
  `secubox_token`), not the brief's single-key illustrative `tok()`.
- `API` constant and the existing `refresh()` function.
- The `uploadSiteContent()` multipart-fetch/401-retry/login-redirect idiom.
- Existing `.card` / `.btn` / `.btn.primary` / `.form-group` classes; no new
  classes introduced beyond the wizard-specific `.wizard-steps` / `.result`
  that the brief itself calls for.

## Concerns

- None blocking. Two intentional, documented deviations from the brief's
  literal snippet (both strict improvements for matching the page's real
  conventions, not functional gaps): `var(--green)`/`var(--red)` instead of
  hardcoded hex, and reuse of the page's `API` constant instead of a
  hardcoded absolute path.
- The wizard's `content`/`route`/`cert` step markers assume the response
  shapes from `publish/routing.py` / `publish/certs.py` always include the
  keys the JS reads (`index_present`, `route_ok`); this mirrors the brief's
  own snippet verbatim and was cross-checked against the actual
  `publish_wizard()` handler in `api/routers/publish.py`, so no gap found.
