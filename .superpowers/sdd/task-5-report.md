# Task 5 Report: C2 learner daemon wiring + `/c2` endpoints + seeded config (#826)

**Status**: COMPLETE
**Commit**: `db22668f` — `feat(sentinel): wire C2 learner into daemon + /c2 endpoints + seeded allowlist (ref #826)`

## Test summary

```
cd packages/secubox-toolbox-ng && go test ./cmd/sbx-sentinel/... ./internal/sentinel/...
ok  	.../secubox-toolbox-ng/cmd/sbx-sentinel	0.453s
ok  	.../secubox-toolbox-ng/internal/sentinel	0.886s
```
`go build ./...` clean. `gofmt -l` clean.

## What changed

- `cmd/sbx-sentinel/main.go`: `buildAnalyzers` now wraps `sentinel.NewBehavioral()` in `sentinel.NewC2Learner(..., sentinel.C2Config{...5 SENTINEL_C2_* env vars via getenvDefault...})` and appends the `C2Learner` (not the raw `Behavioral`) to the pipeline — analyzer count is still 3 (spyware, c2-learner, yara). Added package-level `var c2Learner *sentinel.C2Learner` (set inside `buildAnalyzers`) so `run()`'s optional status-HTTP goroutine can pass it to `serveStatus`. Added fail-safe `readLinesFile(path) []string` (missing/unreadable → nil; skips blank/`#`-comment lines) used for `SENTINEL_C2_BROWSER_JA4`.
- `cmd/sbx-sentinel/http.go`: `newStatusMux(store, c2)` and `serveStatus(ctx, addr, store, c2)` signatures extended with `*sentinel.C2Learner`. When `c2 != nil`, registers `GET /c2/learned`, `GET /c2/candidates`, `POST /c2/allow` (form/JSON `host`, 400 on empty, 500 on `c2.Allow` error, else `{"ok":true}`). Nil `c2` → routes simply not registered (no panic, no behavior change for existing `/stats`/`/verdicts`).
- `cmd/sbx-sentinel/http_test.go`: updated the 4 pre-existing `newStatusMux(store)` call sites to `newStatusMux(store, nil)`; added `TestC2Endpoints` (GET learned/candidates → 200, POST allow with `host=fp.example` → 200).
- `cmd/sbx-sentinel/wiring_test.go`: **incidental fix required to keep tests green** — `TestBuildAnalyzersReturnsThree` asserted a `*sentinel.Behavioral` type was present in the returned slice; since `buildAnalyzers` now appends the wrapping `*sentinel.C2Learner` instead, updated the type-switch case to check for `*sentinel.C2Learner`. Not in the original brief's file list but necessary for the existing test suite to still compile/pass — `TestBuildAnalyzersLoadsBasePack` and `TestDefaultConfigWiresPipeline` needed no changes (analyzer count stays 3; the spyware verdict path they exercise is unaffected).
- `debian/c2-allow.txt` (new) + `debian/browser-ja4.txt` (new): seed files, verbatim per brief.
- `debian/rules`: added `install -d .../etc/secubox/sentinel` + two `install -m 0644` lines for the two seeds (allow file under `/etc/secubox/sentinel/`, browser-JA4 under the already-created `/usr/share/secubox/sentinel/`).
- `debian/sentinel.env`: appended the 5 `SENTINEL_C2_*` vars with defaults matching the code, inserted before the "Live feed source URLs" section.
- No tmpfiles change needed: `/var/lib/secubox/sentinel` (candidates/learned JSON) is already created 0750 secubox-toolbox by the existing `tmpfiles/zz-secubox-sentinel.conf`.

## Blocking concerns

None. `git add` was scoped to only `cmd/sbx-sentinel/` and the `debian/` files touched — two unrelated pre-existing modified files in this worktree (`.superpowers/sdd/task-2-report.md`, `task-4-report.md`, apparently from a different/earlier session reusing this worktree) were left untouched and unstaged.

---

## Review-fix pass — `/c2/allow` writability in packaged deploy (2026-07-07)

**Status**: COMPLETE
**Commit**: `<see final report below>` — `fix(sentinel): make /c2/allow writable in packaged deploy (RW path + ownership) + sanitize Add (ref #826)`

Three review findings on the Task 5 work fixed:

### Finding 1 (CRITICAL) — `/c2/allow` could never write in production

`sbx-sentinel.service` runs `User=secubox-toolbox` under `ProtectSystem=strict` with
`ReadOnlyPaths=/etc/secubox`, and the seeded `c2-allow.txt` ships root:root — so
`C2Allow.Add`'s write to `/etc/secubox/sentinel/c2-allow.txt` would fail (EROFS from
the mount namespace and/or EACCES from ownership). Fixed both halves:

- `debian/sbx-sentinel.service`: added `ReadWritePaths=/etc/secubox/sentinel` (nested
  under the existing `ReadOnlyPaths=/etc/secubox`, which systemd allows — re-grants
  write to just that subtree, rest of `/etc/secubox` stays read-only).
- `debian/postinst` (`configure` branch, right after the existing daemon-reload /
  no-enable comment block): added a fail-safe block that `chown`s
  `/etc/secubox/sentinel` + `c2-allow.txt` to `secubox-toolbox:secubox-toolbox` and
  `chmod 0750` the dir. **`/etc/secubox` itself is never touched** — only the
  `sentinel/` subdir and its file, consistent with the project's shared-parent
  traversal constraint (parent must stay 0755).

### Finding 2 (Important) — doc comment claimed JSON support that doesn't exist

`cmd/sbx-sentinel/http.go`'s package doc said `POST /c2/allow` accepts "form/JSON
`host`", but the handler only calls `r.FormValue("host")` (form-encoded/query only,
no JSON body parsing — and none was added, since the portal already posts
form-encoded). Corrected the comment to say x-www-form-urlencoded/query only.

### Finding 3 (Minor) — newline injection in `C2Allow.Add`

`internal/sentinel/c2allow.go`'s `Add` wrote `host` as a raw line with no
sanitization, so a network caller posting `host=good.com\nevil.com` could inject a
second allowlist entry. Since this is now reachable over the network via
`POST /c2/allow`, added a guard: `Add` rejects (returns nil, no write — fail-safe,
not an error) any host containing `\n`, `\r`, or a space. Added regression test
`TestC2AllowAddRejectsInjection` to `c2allow_test.go`.

### Verification

```
cd packages/secubox-toolbox-ng && go test ./internal/sentinel/ -run TestC2Allow -race -v
=== RUN   TestC2AllowSuffixAndLan
--- PASS: TestC2AllowSuffixAndLan (0.00s)
=== RUN   TestC2AllowFailSafeMissingFiles
--- PASS: TestC2AllowFailSafeMissingFiles (0.00s)
=== RUN   TestC2AllowAddAppends
--- PASS: TestC2AllowAddAppends (0.00s)
=== RUN   TestC2AllowAddRejectsInjection
--- PASS: TestC2AllowAddRejectsInjection (0.00s)
=== RUN   TestC2AllowAddConcurrent
--- PASS: TestC2AllowAddConcurrent (0.00s)
PASS
ok  	github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel	1.017s
```

`go build ./...` clean (exit 0). Confirmed via grep:
`ReadWritePaths=/etc/secubox/sentinel` present in `debian/sbx-sentinel.service`;
`etc/secubox/sentinel` chown/chmod block present in `debian/postinst`'s `configure`
branch, guarded fail-safe (`|| true` throughout, dir-existence check first).

### Files changed

- `packages/secubox-toolbox-ng/debian/sbx-sentinel.service`
- `packages/secubox-toolbox-ng/debian/postinst`
- `packages/secubox-toolbox-ng/internal/sentinel/c2allow.go`
- `packages/secubox-toolbox-ng/internal/sentinel/c2allow_test.go`
- `packages/secubox-toolbox-ng/cmd/sbx-sentinel/http.go` (doc comment only)
