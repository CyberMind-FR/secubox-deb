<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Media Buffer — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture whole-file media (download + upload) flowing through R3/sbxmitm into a time-bounded rolling buffer on `/data`, expose an admin/owner-gated replay link per capture, and keep only the metatag after the bytes evict — surfaced in a new DPI *Media* tab.

**Architecture:** A new `mediabuffer.go` in sbxmitm tees media response/request bodies (non-splice hosts) into `/data/secubox/media-buffer/<session>/`, appending a durable metatag line to `media-buffer.jsonl`. A janitor goroutine evicts bytes older than the window (LRU under a size ceiling), leaving the metatag. `secubox-dpi` reads the metatag log and serves list/replay/thumb endpoints (all plain `def` — aggregator-mounted). Phase 1 is whole-file only; HLS reassembly = Phase 2, kbin links = Phase 3 (separate plans).

**Tech Stack:** Go (sbxmitm, stdlib + existing `internal/reload`), Python 3.11 / FastAPI (secubox-dpi), vanilla JS (dpi www), fpdf/matplotlib untouched.

## Global Constraints

- **Non-blocking capture**: the tee MUST NEVER slow or fail the proxied flow. On any error / full channel / write failure → abandon *that object's* capture, mark the metatag `dropped`/`truncated`, forward the flow unchanged. A media catcher must never affect the proxied response (same contract as `mediacatch.go:record`).
- **Splice/passthrough hosts are never captured** — reuse the existing verdict: only `verdict == "allow" || verdict == "mitm"` flows reach the hook; splice returns earlier. Do not add a new bypass.
- **Perms**: buffer root `/data/secubox/media-buffer` is `0750 secubox:secubox`. Never touch `/run/secubox` (1777) or `/etc/secubox` (0755) parent perms. No secrets written.
- **Aggregator SPOF**: every new `secubox-dpi` path operation is a plain `def` (FastAPI threadpools it off the shared loop) — never bare `async def` doing blocking I/O (ref #808).
- **Retention**: time-only, default `RETENTION_SECS=1200` (20 min). Size ceiling `SIZE_CEIL_BYTES` default `24*1024*1024*1024` evicts LRU early only under pressure. Per-object ceiling `PER_OBJECT_CEIL` default `512*1024*1024`.
- **Metatag log** `media-buffer.jsonl` is append-only; readers are fail-empty + bounded tail-read (mirror `common/secubox_core/media_catch.py`).
- **Feature-flagged OFF** by default: sbxmitm `--media-buffer` flag (default false); dpi endpoints return empty/`404` gracefully when the log is absent.
- **SPDX header** on every new file (CMSD-1.0, per `.claude/CLAUDE.md`).

---

## File Structure

- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer.go` — buffer store, object writer, metatag append.
- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_test.go` — unit tests.
- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_janitor.go` — eviction (time + LRU), `nowFn` seam.
- Create `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_janitor_test.go`.
- Modify `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` — flag, construct buffer, tee download (`resp.Body`) + upload (`req.Body`), start janitor.
- Create `common/secubox_core/media_buffer.py` — metatag reader (mirror `media_catch.py`).
- Create `common/secubox_core/tests/test_media_buffer.py`.
- Modify `packages/secubox-dpi/api/main.py` — `require_admin_or_owner`, `GET /media/buffer`, `GET /media/replay/{id}`, `GET /media/thumb/{id}`.
- Create `packages/secubox-dpi/tests/test_media_buffer_api.py`.
- Modify `packages/secubox-dpi/www/` (index.html + its JS) — *Media* tab gallery.
- Create/modify `packages/secubox-toolbox-ng/debian/*.tmpfiles` (or dpi tmpfiles) — `d /data/secubox/media-buffer 0750 secubox secubox -`.

---

### Task 1: Buffer store + metatag writer (`mediabuffer.go`)

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_test.go`

**Interfaces:**
- Produces (consumed by Task 2 tee + Task 3 janitor + Python reader):
  - `type MediaBuffer struct { … }`
  - `func NewMediaBuffer(root string, enabled bool, perObjectCeil int64) *MediaBuffer`
  - `func (b *MediaBuffer) IsMedia(ctype, path string) bool` — reuse `mediaKind` from mediacatch.go; media = non-empty kind OR ctype prefix `video/`,`audio/`, or a download filename with a media extension.
  - `func (b *MediaBuffer) Capture(mac, host, url, path, ctype, direction string, contentLen int64) *ObjectWriter` — returns nil if disabled / not media / over a sane guard; else creates `root/<session_id>/object-0.<ext>` and returns a writer. `direction` ∈ `"up"|"down"`.
  - `type ObjectWriter struct { … }` implementing `io.Writer`; `Write` stops accepting after `perObjectCeil` (sets `truncated`, discards excess, never errors the caller); `func (w *ObjectWriter) Close(finalBytes int64)` finalizes + appends the metatag line.
  - metatag JSON shape (Task 4 + Task 5 depend on these exact keys): `{"id","session_id","first_ts","last_ts","mac_hash","host","url","direction","kind","ctype","bytes","segments","truncated","buffer_ref","expired"}` (`segments:0`, `buffer_ref:session_id`, `expired:false` at write time).

- [ ] **Step 1: Write failing test — IsMedia + non-media rejection**

```go
func TestMediaBufferIsMedia(t *testing.T) {
	b := NewMediaBuffer(t.TempDir(), true, 512<<20)
	cases := []struct{ ctype, path string; want bool }{
		{"video/mp4", "/v.mp4", true},
		{"audio/mpeg", "/a.mp3", true},
		{"application/vnd.apple.mpegurl", "/index.m3u8", true},
		{"text/html", "/page", false},
		{"application/json", "/api", false},
	}
	for _, c := range cases {
		if got := b.IsMedia(c.ctype, c.path); got != c.want {
			t.Errorf("IsMedia(%q,%q)=%v want %v", c.ctype, c.path, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL (undefined MediaBuffer)**
Run: `cd packages/secubox-toolbox-ng && go test ./cmd/sbxmitm/ -run TestMediaBufferIsMedia`
Expected: build error / FAIL.

- [ ] **Step 3: Write failing test — Capture writes object + metatag, honors ceiling**

```go
func TestMediaBufferCaptureAndMetatag(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 10) // 10-byte ceiling
	w := b.Capture("mac1", "cdn.example", "https://cdn.example/v.mp4", "/v.mp4", "video/mp4", "down", 4)
	if w == nil { t.Fatal("Capture returned nil for media") }
	n, _ := w.Write([]byte("0123456789ABCDEF")) // 16 > 10 → truncated
	_ = n
	w.Close(16)

	// object file exists under a session dir
	var objs, metas int
	filepath.WalkDir(root, func(p string, d fs.DirEntry, _ error) error {
		if d == nil || d.IsDir() { return nil }
		if strings.HasPrefix(d.Name(), "object-") { objs++ }
		if d.Name() == "media-buffer.jsonl" { metas++ }
		return nil
	})
	if objs != 1 || metas != 1 { t.Fatalf("objs=%d metas=%d want 1/1", objs, metas) }

	line := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if line["truncated"] != true { t.Error("expected truncated=true past ceiling") }
	if line["direction"] != "down" || line["mac_hash"] != "mac1" { t.Error("metatag fields wrong") }
	if line["kind"] == "" { t.Error("kind should be set") }
}
```
(`lastJSONL` + `fs`/`filepath` helpers: add to the test file.)

- [ ] **Step 4: Run — expect FAIL**
Run: `go test ./cmd/sbxmitm/ -run TestMediaBufferCaptureAndMetatag`

- [ ] **Step 5: Implement `mediabuffer.go`**
- SPDX header. `package main`.
- `session_id`/`id` via `crypto/rand` hex (NOT `math/rand`).
- `Capture`: guard `b==nil || !enabled || !IsMedia`; derive ext from ctype/path; `os.MkdirAll(root/<session>, 0o750)`; open `object-0.<ext>` `O_CREATE|O_WRONLY|O_TRUNC 0o640`.
- `ObjectWriter.Write`: track written; once ≥ `perObjectCeil`, set `truncated`, drop the rest, **return len(p), nil** (never error the TeeReader).
- `Close(finalBytes)`: fsync best-effort; append one metatag line to `root/media-buffer.jsonl` (`O_CREATE|O_APPEND 0o640`), keep line ≤ a few KB; swallow all errors.
- Mirror `mediacatch.go` defensiveness: every method nil-safe + error-swallowing.

- [ ] **Step 6: Run — expect PASS**
Run: `go test ./cmd/sbxmitm/ -run 'TestMediaBuffer'`

- [ ] **Step 7: Commit**
```bash
git add packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer.go packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_test.go
git commit -m "feat(sbxmitm): media buffer store + metatag writer (ref #812)"
```

---

### Task 2: Tee download + upload bodies in `main.go`

**Files:**
- Modify: `packages/secubox-toolbox-ng/cmd/sbxmitm/main.go` (proxy struct ~line 113; construction ~line 605; download hook ~line 437; add an upload tee before `up.Do(req)` ~line 413)
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_test.go` (add a handler-level tee test using an `httptest` upstream, mirroring `websocket_test.go`'s style)

**Interfaces:**
- Consumes: `MediaBuffer.Capture` / `ObjectWriter` (Task 1); the existing `verdict`, `clientHash`, `host`, `req`, `resp` locals at the hook site.
- Produces: nothing new for later tasks (side-effect: buffer files + metatag lines).

- [ ] **Step 1: Write failing test — a media download is teed to the buffer**
Drive `px.handle`-equivalent path with an `httptest` upstream returning `Content-Type: video/mp4` + a body; assert (a) the client still receives the full body byte-for-byte, (b) a buffer object with the same bytes exists, (c) a metatag line was written. (Model the wiring on `main_test.go`/`uchrome_test.go` existing helpers — reuse their proxy construction.)

- [ ] **Step 2: Run — expect FAIL**
Run: `go test ./cmd/sbxmitm/ -run TestTeeDownload`

- [ ] **Step 3: Add the proxy field + construction**
- Struct (~line 113): add `mbuf *MediaBuffer` beside `media *mediaCatcher`.
- Construction (~line 605): `mbuf: NewMediaBuffer(*mediaBufferRoot, *mediaBuffer, *mediaBufferPerObj)` (flags from Task 6; for now wire the vars).

- [ ] **Step 4: Wrap `resp.Body` (download) at the existing media hook**
At `main.go:~437`, immediately after the `px.media.record(...)` block, add:
```go
// R4 media buffer — tee the full response body into the rolling buffer so it can
// be replayed for a short window. Non-blocking: TeeReader failures never touch the
// client stream (ObjectWriter.Write never errors); a nil writer is a no-op.
if px.mbuf != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
	ctype := resp.Header.Get("Content-Type")
	if px.mbuf.IsMedia(ctype, req.URL.Path) {
		if w := px.mbuf.Capture(clientHash, host,
			"https://"+host+req.URL.RequestURI(), req.URL.Path, ctype, "down",
			resp.ContentLength); w != nil {
			resp.Body = teeReadCloser(resp.Body, w) // wraps: reads pass through, copy to w; Close closes both + w.Close(n)
		}
	}
}
```
Implement `teeReadCloser(rc io.ReadCloser, w *ObjectWriter) io.ReadCloser` in `mediabuffer.go`: `io.TeeReader(rc, w)` for reads, tracking total; `Close()` closes the underlying body and calls `w.Close(total)`. Errors from `w` are swallowed.

- [ ] **Step 5: Tee the upload (`req.Body`) before `up.Do(req)`**
Just before `resp, err := up.Do(req)` (~line 413), for a media request content-type (`req.Header.Get("Content-Type")`) on a non-splice flow:
```go
if px.mbuf != nil && req.Body != nil {
	rct := req.Header.Get("Content-Type")
	if px.mbuf.IsMedia(rct, req.URL.Path) {
		if w := px.mbuf.Capture(clientHash, host,
			"https://"+host+req.URL.RequestURI(), req.URL.Path, rct, "up",
			req.ContentLength); w != nil {
			req.Body = teeReadCloser(req.Body, w)
		}
	}
}
```
(Upload direction; the tee copies the request body as the upstream reads it.)

- [ ] **Step 6: Run tests + full package**
Run: `go test ./cmd/sbxmitm/` — all green (WS/banner/etc. unaffected).

- [ ] **Step 7: Commit**
```bash
git commit -am "feat(sbxmitm): tee media up/download bodies into the buffer (ref #812)"
```

---

### Task 3: Janitor — time + LRU eviction (`mediabuffer_janitor.go`)

**Files:**
- Create: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_janitor.go`
- Test: `packages/secubox-toolbox-ng/cmd/sbxmitm/mediabuffer_janitor_test.go`
- Modify: `main.go` — start `go buf.RunJanitor(ctx)` at startup when enabled.

**Interfaces:**
- Consumes: buffer root + `media-buffer.jsonl` (Task 1 layout).
- Produces: `func (b *MediaBuffer) SweepOnce(now int64)` (testable unit) and `func (b *MediaBuffer) RunJanitor(ctx context.Context)` (30s ticker calling SweepOnce). `nowFn func() int64` field on MediaBuffer, default `time.Now().Unix`, replaceable in tests.

- [ ] **Step 1: Write failing test — expired session bytes removed, metatag flipped**
```go
func TestJanitorEvictsExpiredKeepsMetatag(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.retentionSecs = 60
	w := b.Capture("mac1","h","https://h/v.mp4","/v.mp4","video/mp4","down",3)
	w.Write([]byte("abc")); w.Close(3)
	sess := lastJSONL(t, filepath.Join(root,"media-buffer.jsonl"))["session_id"].(string)
	// advance 61s past first_ts
	b.SweepOnce(b.nowFn() + 61)
	if _, err := os.Stat(filepath.Join(root, sess)); !os.IsNotExist(err) {
		t.Fatal("session dir should be evicted")
	}
	m := lastJSONL(t, filepath.Join(root,"media-buffer.jsonl"))
	if m["expired"] != true || m["buffer_ref"] != nil {
		t.Fatalf("metatag not flipped to expired: %v", m)
	}
}
```

- [ ] **Step 2: Run — expect FAIL** · Run: `go test ./cmd/sbxmitm/ -run TestJanitor`

- [ ] **Step 3: Write failing test — LRU eviction under size ceiling** (oldest session dir removed first when total > `sizeCeil`, even before expiry).

- [ ] **Step 4: Run — expect FAIL**

- [ ] **Step 5: Implement janitor**
- `SweepOnce(now)`: read all metatag lines (last-writer-wins per `id`); for each non-expired with `first_ts + retentionSecs <= now` → `os.RemoveAll(root/session)`, rewrite metatag `expired:true, buffer_ref:null` (append a corrected line — the reader takes the last line per `id`). Then if `du(root) > sizeCeil`, remove oldest session dirs (by `first_ts`) until under, flipping their metatags too.
- Metatag "flip" = append a new JSONL line with same `id` and `expired:true` (append-only; the Python reader dedups by `id`, last wins). Document this in a comment.
- `RunJanitor(ctx)`: `time.NewTicker(30s)`, call `SweepOnce(nowFn())`, exit on `ctx.Done()`.

- [ ] **Step 6: Run — expect PASS** · Run: `go test ./cmd/sbxmitm/ -run 'TestJanitor'`

- [ ] **Step 7: Wire startup in main.go** — after constructing `mbuf`, if enabled: `go px.mbuf.RunJanitor(rootCtx)`.

- [ ] **Step 8: Commit**
```bash
git commit -am "feat(sbxmitm): media buffer janitor — time + LRU eviction, metatag survives (ref #812)"
```

---

### Task 4: Python metatag reader (`common/secubox_core/media_buffer.py`)

**Files:**
- Create: `common/secubox_core/media_buffer.py`
- Test: `common/secubox_core/tests/test_media_buffer.py`

**Interfaces:**
- Produces (consumed by Task 5): `read_records(path: str = MEDIA_BUFFER_PATH, mac_hash: str | None = None, max_lines: int = 2000) -> list[dict]` — bounded tail-read, fail-empty, **dedup by `id` (last line wins)** so janitor's `expired` flip is honored, newest-first, filtered to `mac_hash` when given. `MEDIA_BUFFER_PATH = "/data/secubox/media-buffer/media-buffer.jsonl"`. Also `record_by_id(id, path=…) -> dict | None`.

- [ ] **Step 1: Failing test — dedup by id keeps the expired flip; mac filter; fail-empty**
```python
def test_read_records_dedup_and_expired(tmp_path):
    p = tmp_path / "media-buffer.jsonl"
    p.write_text(
        '{"id":"a","mac_hash":"m1","first_ts":1,"expired":false,"buffer_ref":"s1"}\n'
        '{"id":"a","mac_hash":"m1","first_ts":1,"expired":true,"buffer_ref":null}\n'
        '{"id":"b","mac_hash":"m2","first_ts":2,"expired":false,"buffer_ref":"s2"}\n')
    from secubox_core import media_buffer as mb
    recs = mb.read_records(str(p))
    assert len(recs) == 2                       # deduped
    a = mb.record_by_id("a", str(p))
    assert a["expired"] is True                 # last line wins
    assert [r["id"] for r in mb.read_records(str(p), mac_hash="m2")] == ["b"]
    assert mb.read_records(str(tmp_path/"missing.jsonl")) == []   # fail-empty
```

- [ ] **Step 2: Run — expect FAIL** · Run: `cd common && PYTHONPATH=. python -m pytest secubox_core/tests/test_media_buffer.py -q`

- [ ] **Step 3: Implement** — mirror `media_catch.py`'s `_tail_lines` (bounded `max_bytes` tail read, drop partial first line), parse JSON per line swallowing errors, dedup by `id` (dict keyed by id, later overwrites), filter by `mac_hash`, sort by `first_ts` desc. SPDX header.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit** `git commit -am "feat(core): media-buffer metatag reader (dedup by id, fail-empty) (ref #812)"`

---

### Task 5: DPI API — list / replay / thumb (`secubox-dpi/api/main.py`)

**Files:**
- Modify: `packages/secubox-dpi/api/main.py` (add after the existing `/media_types` endpoint area; `router = APIRouter()` at line 133)
- Test: `packages/secubox-dpi/tests/test_media_buffer_api.py`

**Interfaces:**
- Consumes: `secubox_core.media_buffer.read_records / record_by_id` (Task 4); `require_jwt` (already imported).
- Produces: three routes + `require_admin_or_owner`. All **plain `def`** (blocking file I/O → threadpool; ref #808).

Routes:
- `GET /media/buffer` → `def media_buffer_list(user=Depends(require_jwt))`: admin → all records; else → `read_records(mac_hash=<user's mac_hash>)`. Return `{"items": [...], "count": n}`. (Owner's `mac_hash` resolution: reuse however the module already maps a JWT `sub`→persona; if none exists in Phase 1, non-admin sees `[]` and a `TODO(phase3)` comment — do not invent a mapping.)
- `GET /media/replay/{rec_id}` → `def media_replay(rec_id, user=Depends(require_admin_or_owner))`: look up `record_by_id`; if `expired` or missing bytes → `HTTPException(410, "media evicted — metatag only")`; else `FileResponse(<buffer object path>, media_type=ctype)`. **Audit** each call to `/var/log/secubox/audit.log` (append: ts, sub, rec_id, host, ip). Validate `rec_id` matches `^[0-9a-f]{8,32}$`; resolve the object path from the record's `session_id` under `MEDIA_BUFFER_ROOT` — never from client input (path-traversal safe).
- `GET /media/thumb/{rec_id}` → `def`: serve `<session>/thumb.jpg` if present else a 1x1/placeholder (Phase 1 may return 404; thumbnail generation is optional/Phase 2).
- `require_admin_or_owner(user=Depends(require_jwt))`: admin role → allow; else allow only if the requested record's `mac_hash` == user's persona mac_hash (Phase 1: admin-only effectively; owner path lands with Phase 3 mapping — comment it).

- [ ] **Step 1: Failing test — list dedups + scopes; replay 410 on expired; traversal-safe id**
```python
def test_media_buffer_list_and_replay(tmp_path, monkeypatch):
    # point the module at a temp buffer with one live + one expired record
    ...
    from api import main as m
    monkeypatch.setattr(m, "MEDIA_BUFFER_ROOT", str(tmp_path))
    # admin sees all
    out = m.media_buffer_list(user={"role":"admin","sub":"root"})
    assert out["count"] == 2
    # replay expired -> 410
    with pytest.raises(HTTPException) as e:
        m.media_replay("<expired_id>", user={"role":"admin","sub":"root"})
    assert e.value.status_code == 410
    # bad id rejected
    with pytest.raises(HTTPException):
        m.media_replay("../etc/passwd", user={"role":"admin","sub":"root"})
```

- [ ] **Step 2: Run — expect FAIL** · Run: `cd packages/secubox-dpi && PYTHONPATH=../../common:. python -m pytest tests/test_media_buffer_api.py -q` (temp ACL for `/var/lib/secubox/dpi` per the known local-env note if import mkdir fails).

- [ ] **Step 3: Implement the three routes + dependency** (plain `def`, path-traversal-safe, audit append best-effort). Add `MEDIA_BUFFER_ROOT = "/data/secubox/media-buffer"`.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit** `git commit -am "feat(dpi): media-buffer list/replay/thumb API (admin/owner, audited, 410-on-evict) (ref #812)"`

---

### Task 6: sbxmitm flags + packaging (buffer dir, feature flag)

**Files:**
- Modify: `main.go` — add flags `--media-buffer` (bool, default false), `--media-buffer-root` (default `/data/secubox/media-buffer`), `--media-buffer-per-object` (int64, default 512 MiB), `--media-buffer-retention` (int, default 1200), `--media-buffer-size-ceil` (int64, default 24 GiB). Wire into `NewMediaBuffer` + janitor.
- Modify/Create tmpfiles: `d /data/secubox 0755 secubox secubox -` + `d /data/secubox/media-buffer 0750 secubox secubox -` (in the dpi package tmpfiles, which is already deployed, OR toolbox-ng's).
- Modify the sbxmitm systemd unit / worker env (`packages/secubox-toolbox/...` R3 worker units) to pass `--media-buffer` when the feature is enabled (default off).

- [ ] **Step 1** Add flags (mirror the existing `--media-catch` flag definition & plumbing in `main.go`).
- [ ] **Step 2** `go build ./cmd/sbxmitm` — compiles.
- [ ] **Step 3** Add the tmpfiles lines; `git grep` an existing `.tmpfiles` in the target package to match format.
- [ ] **Step 4** Add the `--media-buffer` arg to the worker unit(s) behind an env toggle (documented default OFF).
- [ ] **Step 5: Commit** `git commit -am "feat(sbxmitm): media-buffer flags + /data buffer dir tmpfiles (ref #812)"`

---

### Task 7: DPI *Media* gallery tab (frontend)

**Files:**
- Modify: `packages/secubox-dpi/www/` — the dpi dashboard `index.html` (+ its JS). Follow the existing tab pattern the module already uses (e.g. the media_types cards added in #785).

**Steps (manual-tested; no unit harness for vanilla JS):**
- [ ] **Step 1** Add a *Media* tab/section: fetch `GET /api/v1/dpi/media/buffer` (Bearer `sbx_token` — the canonical key, ref #810), render cards `{thumb (or kind emoji), host, device (short mac_hash), ⬆/⬇, kind, size, age}`.
- [ ] **Step 2** Card actions: `▶ Play` (open `/api/v1/dpi/media/replay/{id}` in a `<video>/<audio>` or new tab) + `⬇ Download`; disable + show “métatag seul (expiré)” when `expired`.
- [ ] **Step 3** Poll refresh every ~15 s (the list endpoint is cheap; add API-side double-caching later if needed per CLAUDE.md).
- [ ] **Step 4** Use the C3BOX palette + JetBrains Mono per `.claude/DESIGN-CHARTER.md`.
- [ ] **Step 5: Commit** `git commit -am "feat(dpi): Media tab — live capture gallery with replay/download (ref #812)"`

---

## Phase 1 Done-Definition

Capturing a direct `.mp4` download (and a media upload) through R3 with `--media-buffer` on produces a replayable link in the DPI *Media* tab for ~20 min, then the card greys to metatag-only after the janitor evicts the bytes — admin-gated and audited. `go test ./cmd/sbxmitm/` + `pytest` (dpi + core) all green.

**Phase 2** (separate plan): HLS/DASH session grouping + rewritten local manifest + `/media/replay/{id}/seg/{n}`.
**Phase 3** (separate plan): kbin per-persona replay links, JWT→persona owner scoping, operator deny-list, thumbnail generation.
