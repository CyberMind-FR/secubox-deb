# Task 2 report — Tee download + upload bodies (non-blocking async writer)

**Status:** DONE_WITH_CONCERNS (one minor test-scope deviation, see below)

**Commit:** `0a5e71abfd417b97c35cbf4f5121720911cbfbc9`
`feat(sbxmitm): tee media up/download bodies into the buffer (ref #812)`

## Test commands + results

Run from `packages/secubox-toolbox-ng/`:

| Command | Result |
|---|---|
| `go build ./cmd/sbxmitm` | PASS (no output) |
| `go vet ./cmd/sbxmitm` | PASS (no output) |
| `go test ./cmd/sbxmitm/ -run 'TestTee' -v` | PASS — `TestTeeDownloadStreamsAndCaptures`, `TestTeeNonBlockingDropsWhenFull` |
| `go test ./cmd/sbxmitm/ -run 'TestMediaBuffer' -v` | PASS — all 4 existing TestMediaBuffer* still green |
| `go test ./cmd/sbxmitm/` (whole package) | PASS — `ok ... 1.518s` (WS/banner/uchrome/csp/etc. unaffected) |
| `go test -race ./cmd/sbxmitm/ -run 'TestTee\|TestMediaBuffer'` | PASS — `ok ... 1.063s`, **no data races** |

`gofmt -w` applied to `main.go`, `mediabuffer.go`, `mediabuffer_test.go`.

## Non-blocking async writer implementation

- **Bounded channel:** `ObjectWriter.ch chan []byte`, capacity `mediaBufferChanCap = 64` (overridable via `MediaBuffer.chanCap` for tests). Chunks are copies of the reader buffer (io.TeeReader reuses it), so ≤~2 MiB in flight worst case.
- **Write is I/O-free:** copies `p` and does a **non-blocking** `select { case ch<-cp: default: }`. On the `default` branch it sets `dropped=true`/`truncated=true` and returns `len(p), nil`. It never touches the disk, never blocks, never errors — proven by `TestTeeNonBlockingDropsWhenFull` (depth-1 queue + a `blockingWriteCloser` pinning the drain goroutine; a 5000-write burst is bounded by a 3s timeout that would fail if any Write blocked).
- **Background goroutine:** `drain()` started in `Capture` (`go w.drain()`). It exclusively owns `sink`/`written` (no lock on the hot write → clean under `-race`), enforces `perObjectCeil` (truncate + close sink), keeps receiving after a ceiling/IO error so senders never wedge, and on channel close fsyncs (real files only) + closes the sink, then `close(w.done)`.
- **Drop policy:** full channel drops that chunk, flags `truncated`; object becomes partial; flow proceeds unaffected.
- **Close(finalBytes):** mutex-guards idempotency (`closed`), then `close(ch)` (sole closer) → waits `<-done` so the metatag is appended only after all queued bytes are flushed + file closed (a reader seeing the metatag sees complete bytes).
- **Deadlock/leak avoidance:** `drain` always terminates once `ch` is closed; `Close` is the only closer of `ch`. Write serialises its send against `close(ch)` under `mu` (checks `closed` first) → no send-on-closed panic. Safe if Write is never called (empty file, metatag written) or called after/concurrent with Close (becomes a no-op). Goroutine cannot leak because `teeReadCloser.Close` (invoked by `defer resp.Body.Close()` for download and by the Transport closing `req.Body` for upload — the http.Client closes the request body even on error) always calls `w.Close`.

## main.go wiring

- `mbuf *MediaBuffer` field added beside `media *mediaCatcher`.
- Constructed in `main()`: `NewMediaBuffer(*mediaBufferRoot, *mediaBuffer, *mediaBufferPerObj)`.
- Flags added: `--media-buffer` (bool, **default false**), `--media-buffer-root` (`/data/secubox/media-buffer`), `--media-buffer-per-object` (`512<<20`). Task 6 formalises retention/size-ceil flags + janitor + packaging.
- **Download tee:** right after the `px.media.record(...)` block; 2xx + `IsMedia` → `resp.Body = teeReadCloser(resp.Body, Capture(..., "down", resp.ContentLength))`. Consumed by `streamResponse`'s `io.Copy`; finalised by the existing `defer resp.Body.Close()`.
- **Upload tee:** just before `resp, err := up.Do(req)`; `req.Body != nil` + `IsMedia` → `req.Body = teeReadCloser(req.Body, Capture(..., "up", req.ContentLength))`.
- `teeReadCloser(rc, w)` added in mediabuffer.go: `io.TeeReader` for reads, tracks `total`, `Close()` closes the underlying body AND calls `w.Close(total)` (once); nil-safe, error-swallowing.

## Deviation / concern

- **Test scope (minor):** the plan's Task-2 Step-1 says to "drive the proxy handler" through an httptest upstream. `mitmPipeline` cannot be driven end-to-end against a test upstream with the existing helpers: it constructs `newUchromeTransport(...)` internally with **no RootCAs override seam** (unlike `uchrome_test.go`, which sets `tr.rootCAs`), so a self-signed httptest TLS origin is rejected by cert verification and there's no CONNECT/TLS handler harness. This is not a blocker for the deliverable: `TestTeeDownloadStreamsAndCaptures` uses a real `httptest` upstream and wires the download tee **exactly as `mitmPipeline` does** (`teeReadCloser(resp.Body, mbuf.Capture(...))` → `io.ReadAll` → `Close`), asserting (a) full byte-for-byte client body, (b) captured object == body, (c) metatag line. It exercises the identical capture/tee/async-writer path; only the surrounding TLS plumbing is not re-driven (already covered by uchrome/transparent tests).
- **Janitor not started** (correct — Task 3). Buffer dir tmpfiles/packaging not added (correct — Task 6).
- No other concerns: build/vet/full-package/-race all clean.

---

## Review fix pass (2026-07-04)

**Status:** DONE — CRITICAL correctness bug fixed + regression test added + 3 minor cleanups.

### CRITICAL fix: defer-before-reassignment goroutine/capture leak

`main.go`'s `mitmPipeline` had `defer resp.Body.Close()` (line ~439) registered
*before* the #812 download tee (line ~477) reassigns `resp.Body =
teeReadCloser(resp.Body, w)`. A plain `defer resp.Body.Close()` binds the
method-value receiver **at the defer statement**, so it closed the *original*
upstream body only — the tee's `Close()` (and therefore `w.Close(total)`,
which flushes the sink, appends the metatag, and closes `w.done` to unblock
`drain`) never ran on any media download. Net effect: every media download
capture silently produced zero bytes on disk, no metatag line, and leaked the
`drain` goroutine + open sink fd forever.

**Fix:** `defer func() { resp.Body.Close() }()` — the closure defers
evaluation of `resp.Body` to return time, so it always closes whatever
`resp.Body` currently is (the tee when armed, the original body otherwise).
Added an inline comment explaining the defer-binding-time gotcha. Confirmed
`resp` is never reassigned (only `.Body` is), `streamResponse` only
`io.Copy`s and the inject path only `io.ReadAll`s — this deferred close
remains the sole closer; `teeReadCloser.Close` is `sync.Once`-guarded so no
double-close risk.

### Regression test

Added `TestTeeDeferOrderingMatchesMainGo` to `mediabuffer_test.go`: drives a
real `httptest` media response through the exact same statement order as
`mitmPipeline` (defer registered on `resp.Body` *before* it is reassigned to
`teeReadCloser(...)`, inside an inner func so the deferred close actually
fires before assertions run), then asserts (a) the `drain` goroutine's `done`
channel closes within a bounded timeout (no leak) and (b) the metatag line
was appended with the right fields, and (c) the captured object on disk
matches the streamed body byte-for-byte.

**Verified the test catches the regression**: temporarily replaced the
closure with the buggy plain `defer resp.Body.Close()` form (same position,
before reassignment) — the test failed with `drain goroutine never exited —
w.Close was never called (defer captured the wrong body)` (timed out after
2s). Restored the closure form afterwards; `git diff` on the test file shows
only the intended addition (leftover edit fully reverted).

### Minor cleanups (mediabuffer.go)

1. Removed the dead write-only `dropped` field from `ObjectWriter` (only
   `truncated` was ever read, in the metatag record) — updated the two
   comments that referenced it (`mu` field-group comment, `Write` doc-comment).
2. `Capture`'s `contentLen` parameter: added a doc-comment noting it's
   reserved for a future Phase (no upfront size guard in Phase 1; the
   per-object ceiling is enforced only as bytes actually arrive in `drain`).
3. `ObjectWriter.Close`: added a comment explaining it is intentionally
   allowed to block on `<-done` — unlike `Write`, which must never block the
   live proxied stream — because by the time `Close` runs the body has
   already been fully streamed to the client.

### Test commands + results (from `packages/secubox-toolbox-ng/`)

| Command | Result |
|---|---|
| `gofmt -w cmd/sbxmitm/{main,mediabuffer,mediabuffer_test}.go` | clean, no diffs after |
| `go build ./cmd/sbxmitm` | PASS |
| `go vet ./cmd/sbxmitm` | PASS |
| `go test -count=1 ./cmd/sbxmitm/` | PASS — `ok ... 1.359s`, whole package green |
| `go test -race -count=1 ./cmd/sbxmitm/ -run 'TestTee\|TestMediaBuffer'` | PASS — `ok ... 1.077s`, no data races |
| Manual: buggy plain-defer form in new test | **FAILS** as expected (goroutine-leak timeout) — confirms the test is a real regression guard |

### Concerns

None. The fix is minimal (one `defer` line + comment), the regression test
reproduces the exact bug ordering from `main.go` rather than a synthetic
approximation, and the minor cleanups are comment/dead-field only — no
behavioural change to the non-blocking write contract.
