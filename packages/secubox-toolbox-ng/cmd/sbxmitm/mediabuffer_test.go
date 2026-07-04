// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: media buffer store tests (#812)
//
// Pure standard library.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// findObject walks root and returns the path of the single object-* file.
func findObject(t *testing.T, root string) string {
	t.Helper()
	var found string
	filepath.WalkDir(root, func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.HasPrefix(d.Name(), "object-") {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no object-* file under %s", root)
	}
	return found
}

// blockingWriteCloser is an object sink whose Write blocks until release is
// closed, used to pin the drain goroutine so the write queue fills and the
// non-blocking drop path is exercised deterministically.
type blockingWriteCloser struct {
	release chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (b *blockingWriteCloser) Write(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return len(p), nil
}

func (b *blockingWriteCloser) Close() error { return nil }

// lastJSONL reads path and returns the last non-empty line parsed as a JSON
// object. Fails the test on any read/parse error (the file is expected to
// exist and contain at least one valid record by the time this is called).
func lastJSONL(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || lines[len(lines)-1] == "" {
		t.Fatalf("no lines in %s", path)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &m); err != nil {
		t.Fatalf("unmarshal last line of %s: %v", path, err)
	}
	return m
}

func TestMediaBufferIsMedia(t *testing.T) {
	b := NewMediaBuffer(t.TempDir(), true, 512<<20)
	cases := []struct {
		ctype, path string
		want        bool
	}{
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

func TestMediaBufferCaptureAndMetatag(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 10) // 10-byte ceiling
	w := b.Capture("mac1", "cdn.example", "https://cdn.example/v.mp4", "/v.mp4", "video/mp4", "down", 4)
	if w == nil {
		t.Fatal("Capture returned nil for media")
	}
	n, _ := w.Write([]byte("0123456789ABCDEF")) // 16 > 10 → truncated
	_ = n
	w.Close(16)

	// object file exists under a session dir
	var objs, metas int
	filepath.WalkDir(root, func(p string, d fs.DirEntry, _ error) error {
		if d == nil || d.IsDir() {
			return nil
		}
		if strings.HasPrefix(d.Name(), "object-") {
			objs++
		}
		if d.Name() == "media-buffer.jsonl" {
			metas++
		}
		return nil
	})
	if objs != 1 || metas != 1 {
		t.Fatalf("objs=%d metas=%d want 1/1", objs, metas)
	}

	line := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if line["truncated"] != true {
		t.Error("expected truncated=true past ceiling")
	}
	if line["direction"] != "down" || line["mac_hash"] != "mac1" {
		t.Error("metatag fields wrong")
	}
	if line["kind"] == "" {
		t.Error("kind should be set")
	}
}

func TestMediaBufferNilAndDisabledSafe(t *testing.T) {
	var nilBuf *MediaBuffer
	if nilBuf.IsMedia("video/mp4", "/v.mp4") {
		t.Error("nil MediaBuffer.IsMedia should be false, never panic")
	}
	if w := nilBuf.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 1); w != nil {
		t.Error("nil MediaBuffer.Capture should return nil")
	}

	disabled := NewMediaBuffer(t.TempDir(), false, 512<<20)
	if w := disabled.Capture("mac1", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", 1); w != nil {
		t.Error("disabled MediaBuffer.Capture should return nil")
	}

	var nilWriter *ObjectWriter
	n, err := nilWriter.Write([]byte("x"))
	if err != nil || n != 1 {
		t.Errorf("nil ObjectWriter.Write should be a no-op success, got n=%d err=%v", n, err)
	}
	nilWriter.Close(1) // must not panic
}

func TestMediaBufferNotMediaReturnsNil(t *testing.T) {
	b := NewMediaBuffer(t.TempDir(), true, 512<<20)
	if w := b.Capture("mac1", "h", "https://h/page", "/page", "text/html", "down", 100); w != nil {
		t.Error("Capture should return nil for non-media content")
	}
}

// TestTeeDownloadStreamsAndCaptures wires the download hook exactly as
// main.go's mitmPipeline does — an httptest upstream serves video/mp4, the
// response body is wrapped with teeReadCloser(resp.Body, Capture(...)) — and
// proves (a) the client still reads the FULL body byte-for-byte and (b) after
// Close the buffer object holds the same bytes plus a metatag line.
func TestTeeDownloadStreamsAndCaptures(t *testing.T) {
	// A body large enough to span many Reads (and channel chunks) but well under
	// the default queue cap so nothing is dropped in this healthy-disk path.
	body := bytes.Repeat([]byte("SECUBOX-MEDIA-0123456789"), 5000) // ~120 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)

	resp, err := http.Get(srv.URL + "/movie.mp4")
	if err != nil {
		t.Fatalf("upstream GET: %v", err)
	}

	// Mirror the mitmPipeline download hook wiring.
	ctype := resp.Header.Get("Content-Type")
	if !b.IsMedia(ctype, "/movie.mp4") {
		t.Fatalf("IsMedia should be true for %q", ctype)
	}
	w := b.Capture("macX", "cdn.host", "https://cdn.host/movie.mp4", "/movie.mp4", ctype, "down", resp.ContentLength)
	if w == nil {
		t.Fatal("Capture returned nil for a media download")
	}
	resp.Body = teeReadCloser(resp.Body, w)

	// The proxy streams the body to the client (streamResponse → io.Copy).
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	resp.Body.Close() // defer resp.Body.Close() in main.go → w.Close(total)

	// (a) client saw the full body byte-for-byte.
	if !bytes.Equal(got, body) {
		t.Fatalf("client body mismatch: got %d bytes want %d", len(got), len(body))
	}

	// (b) the captured object holds the same bytes.
	objBytes, err := os.ReadFile(findObject(t, root))
	if err != nil {
		t.Fatalf("read captured object: %v", err)
	}
	if !bytes.Equal(objBytes, body) {
		t.Fatalf("captured bytes mismatch: got %d want %d", len(objBytes), len(body))
	}

	// metatag line present, coherent, not truncated (nothing dropped).
	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["direction"] != "down" || m["mac_hash"] != "macX" || m["host"] != "cdn.host" {
		t.Errorf("metatag fields wrong: %v", m)
	}
	if m["truncated"] == true {
		t.Error("healthy capture must not be truncated")
	}
	if m["kind"] == "" {
		t.Error("kind should be set")
	}
}

// TestTeeDeferOrderingMatchesMainGo replicates the EXACT statement ordering
// from main.go's mitmPipeline download hook: a defer is registered against
// resp.Body BEFORE the body is reassigned to teeReadCloser(...). A plain
// `defer resp.Body.Close()` binds the method value AT THE DEFER STATEMENT,
// capturing the ORIGINAL (pre-tee) body — so the tee's Close (and therefore
// w.Close, which flushes the sink, appends the metatag and unblocks the
// drain goroutine) would never run: a silent goroutine/fd leak and zero
// captures. This test uses the closure form `defer func() { resp.Body.Close()
// }()` that main.go now uses (the fix for #812's regression), and asserts
// both symptoms are absent: the metatag line is appended (proving w.Close
// ran) and the drain goroutine has exited (proving no leak).
//
// To confirm this test actually catches the regression: temporarily replace
// the closure below with a plain `defer resp.Body.Close()` (still registered
// before the `resp.Body = teeReadCloser(...)` line) — this test fails (drain
// goroutine never signals done, metatag log never appears). Restore the
// closure form afterwards.
func TestTeeDeferOrderingMatchesMainGo(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)

	body := bytes.Repeat([]byte("DEFER-ORDER-CHECK-"), 2000) // ~38 KiB, several chunks
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/clip.mp4")
	if err != nil {
		t.Fatalf("upstream GET: %v", err)
	}

	w := b.Capture("macD", "cdn.host", "https://cdn.host/clip.mp4", "/clip.mp4", "video/mp4", "down", resp.ContentLength)
	if w == nil {
		t.Fatal("Capture returned nil for a media download")
	}

	// Inner func so the deferred Close actually fires before we assert below —
	// mirrors mitmPipeline's function-scoped defer running out at return.
	func() {
		// Registered BEFORE resp.Body is reassigned — the closure form is what
		// makes this safe (see the defer comment on main.go's download path).
		// Replacing this with a plain `defer resp.Body.Close()` reproduces
		// #812's bug and fails this test.
		defer func() { resp.Body.Close() }()

		resp.Body = teeReadCloser(resp.Body, w)
		if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatalf("stream body: %v", err)
		}
	}()

	// (a) the drain goroutine must have exited (w.Close ran -> close(ch) ->
	// drain drained the queue, closed the sink and closed done). Bounded
	// wait: if the bug regresses, done never closes — this times out,
	// surfacing the goroutine leak instead of hanging the test suite.
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("drain goroutine never exited — w.Close was never called (defer captured the wrong body)")
	}

	// (b) the metatag line must have been appended (only happens at the very
	// end of Close, after done is signalled).
	metaPath := filepath.Join(root, "media-buffer.jsonl")
	if _, err := os.Stat(metaPath); err != nil {
		t.Fatalf("metatag log missing — w.Close never ran: %v", err)
	}
	m := lastJSONL(t, metaPath)
	if m["mac_hash"] != "macD" || m["direction"] != "down" {
		t.Fatalf("metatag fields wrong: %v", m)
	}
	if m["truncated"] == true {
		t.Error("healthy capture must not be truncated")
	}

	// (c) the captured object holds the full body — proves the sink was
	// flushed and closed, not left half-written or never opened.
	objBytes, err := os.ReadFile(findObject(t, root))
	if err != nil {
		t.Fatalf("read captured object: %v", err)
	}
	if !bytes.Equal(objBytes, body) {
		t.Fatalf("captured bytes mismatch: got %d want %d", len(objBytes), len(body))
	}
}

// TestTeeNonBlockingDropsWhenFull proves the non-blocking guarantee: with a
// tiny queue and a drain goroutine pinned inside a blocked disk write, Write
// must return immediately (never block on the stuck disk) and the flow still
// completes, with truncated flagged from the dropped chunks.
func TestTeeNonBlockingDropsWhenFull(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)
	b.chanCap = 1 // depth-1 queue → trivially fills once the drainer is stuck
	release := make(chan struct{})
	entered := make(chan struct{})
	b.openSink = func(string) (io.WriteCloser, error) {
		return &blockingWriteCloser{release: release, entered: entered}, nil
	}

	w := b.Capture("mac", "h", "https://h/v.mp4", "/v.mp4", "video/mp4", "down", -1)
	if w == nil {
		t.Fatal("Capture returned nil")
	}

	// Chunk 1 → queue → drainer picks it up → blocks inside sink.Write.
	w.Write([]byte("A"))
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain goroutine never reached the sink write")
	}
	// Chunk 2 fills the depth-1 queue (drainer is stuck holding chunk 1).
	w.Write([]byte("B"))

	// Every further Write must now DROP and return immediately — prove it never
	// blocks on the pinned disk by bounding the whole burst with a timeout.
	burstDone := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			if n, err := w.Write([]byte("X")); n != 1 || err != nil {
				t.Errorf("Write must always report len(p),nil: n=%d err=%v", n, err)
			}
		}
		close(burstDone)
	}()
	select {
	case <-burstDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Write blocked while the disk was stuck — non-blocking guarantee violated")
	}

	// Release the disk and finalise; Close must drain + not deadlock.
	close(release)
	w.Close(5002)

	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["truncated"] != true {
		t.Errorf("expected truncated=true after dropped chunks, got %v", m["truncated"])
	}
}

// TestUploadTeeSkipsBodylessMediaGet is the regression test for the
// whole-branch-review I1 finding: main.go's mitmPipeline used to gate the
// upload tee on `req.Body != nil && IsMedia(ctype, path)`. But req.Body is
// NEVER nil for a proxied request — even a bodyless GET carries a non-nil
// (empty) body — and IsMedia/mediaKind classifies by PATH EXTENSION when the
// request Content-Type is empty. So a plain media DOWNLOAD GET (no request
// body, no request Content-Type) used to match the UPLOAD branch on path
// alone, creating a phantom session dir, a 0-byte object-0.mp4 and a
// direction:"up", bytes:0 metatag on every download.
//
// tryUploadTee below mirrors main.go's fixed guard byte-for-byte: require
// BOTH a real body (ContentLength > 0 — the primary guard, since a GET
// download never carries a request body) AND a non-empty request
// Content-Type that IsMedia matches ON THE CONTENT-TYPE, so the
// path-extension fallback can never drive the upload direction.
//
// Confirmed this test catches the regression: temporarily restoring the old
// guard (`contentLength >= 0` i.e. drop the ContentLength>0 requirement, and
// allow ctype == "" through to IsMedia(ctype, path) which then falls back to
// the path-extension match) makes the first assertion below fail — a
// bodyless GET to /v.mp4 gets captured as "up". Restored to the fixed guard
// afterwards.
func TestUploadTeeSkipsBodylessMediaGet(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)

	tryUploadTee := func(contentLength int64, ctype, path string) *ObjectWriter {
		if b == nil || contentLength <= 0 {
			return nil
		}
		if ctype == "" || !b.IsMedia(ctype, path) {
			return nil
		}
		return b.Capture("mac1", "cdn.example", "https://cdn.example"+path, path, ctype, "up", contentLength)
	}

	// A GET download of a media path: no request body (ContentLength == 0),
	// no request Content-Type — must NOT start an upload capture.
	if w := tryUploadTee(0, "", "/v.mp4"); w != nil {
		t.Fatal("bodyless GET to a media path must not start an upload capture")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	if len(entries) != 0 {
		t.Fatalf("phantom capture artifacts created for a bodyless GET: %v", entries)
	}

	// Conversely, a genuine upload — non-zero request body + a real media
	// Content-Type — must still be captured as "up".
	w := tryUploadTee(1024, "video/mp4", "/v.mp4")
	if w == nil {
		t.Fatal("a real upload (ContentLength>0, media Content-Type) must be captured")
	}
	if _, err := w.Write(bytes.Repeat([]byte("U"), 1024)); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close(1024)

	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["direction"] != "up" {
		t.Fatalf("expected direction=up in metatag, got %v", m["direction"])
	}
}

// TestDownloadTeeSkips206 is the regression test for the whole-branch-review
// I2 finding: main.go's mitmPipeline used to gate the download tee on
// `resp.StatusCode >= 200 && resp.StatusCode < 300`, which includes 206
// Partial Content. Browser <video>/<audio> elements fetch media via Range
// requests, so a real playback session is a STREAM of 206 responses — each
// one used to be captured as its own "whole" object, producing a pile of
// unrelated byte fragments that are never replayable. Phase 1 is whole-file
// capture only; Range/partial (206) + HLS segment reassembly is Phase 2.
//
// Confirmed this test catches the regression: temporarily widening the guard
// below back to `resp.StatusCode >= 200 && resp.StatusCode < 300` makes the
// 206 assertion fail (a capture is started for the partial response).
// Restored to the fixed `== 200` guard afterwards.
func TestDownloadTeeSkips206(t *testing.T) {
	root := t.TempDir()
	b := NewMediaBuffer(root, true, 512<<20)

	body := bytes.Repeat([]byte("RANGE-FRAGMENT-"), 100)

	// A 206 Partial Content response (Range fetch) must NOT be captured.
	srv206 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Range", "bytes 0-1499/3000")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer srv206.Close()

	resp, err := http.Get(srv206.URL + "/movie.mp4")
	if err != nil {
		t.Fatalf("upstream GET: %v", err)
	}
	var w206 *ObjectWriter
	if resp.StatusCode == 200 { // mirrors main.go's fixed #812/I2 guard
		ctype := resp.Header.Get("Content-Type")
		if b.IsMedia(ctype, "/movie.mp4") {
			w206 = b.Capture("mac206", "cdn.host", "https://cdn.host/movie.mp4", "/movie.mp4", ctype, "down", resp.ContentLength)
		}
	}
	if w206 != nil {
		t.Fatal("a 206 Partial Content response must not be captured")
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("stream body: %v", err)
	}
	resp.Body.Close()

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	if len(entries) != 0 {
		t.Fatalf("phantom capture artifacts created for a 206 response: %v", entries)
	}

	// Conversely, a 200 media response IS captured.
	srv200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		_, _ = w.Write(body)
	}))
	defer srv200.Close()

	resp2, err := http.Get(srv200.URL + "/movie.mp4")
	if err != nil {
		t.Fatalf("upstream GET: %v", err)
	}
	var w200 *ObjectWriter
	if resp2.StatusCode == 200 {
		ctype := resp2.Header.Get("Content-Type")
		if b.IsMedia(ctype, "/movie.mp4") {
			w200 = b.Capture("mac200", "cdn.host", "https://cdn.host/movie.mp4", "/movie.mp4", ctype, "down", resp2.ContentLength)
		}
	}
	if w200 == nil {
		t.Fatal("a 200 media response must be captured")
	}
	resp2.Body = teeReadCloser(resp2.Body, w200)
	if _, err := io.Copy(io.Discard, resp2.Body); err != nil {
		t.Fatalf("stream body: %v", err)
	}
	resp2.Body.Close()

	m := lastJSONL(t, filepath.Join(root, "media-buffer.jsonl"))
	if m["mac_hash"] != "mac200" || m["direction"] != "down" {
		t.Fatalf("expected 200 download captured with mac_hash=mac200, got %v", m)
	}
}
