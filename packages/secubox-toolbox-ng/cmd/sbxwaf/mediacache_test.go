// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — media-cache tests (Task 6.1 TDD)
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// makeResp builds a minimal *http.Response suitable for MaybeStore.
// ct is Content-Type; maxAge is the max-age directive (0 = omit = use DEFAULT_TTL);
// negative means "no-store" in Cache-Control.
func makeResp(statusCode int, ct string, maxAge int, body []byte) *http.Response {
	hdr := http.Header{}
	if ct != "" {
		hdr.Set("Content-Type", ct)
	}
	switch {
	case maxAge < 0:
		hdr.Set("Cache-Control", "no-store")
	case maxAge > 0:
		hdr.Set("Cache-Control", fmt.Sprintf("max-age=%d", maxAge))
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     hdr,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// makeGET builds a minimal GET *http.Request for the given url.
func makeGET(rawURL string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	return req
}

// --- TestMediaCacheStoreAndGet ---------------------------------------------------

func TestMediaCacheStoreAndGet(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/image.png"
	body := []byte("PNG_BYTES")

	req := makeGET(testURL)
	resp := makeResp(200, "image/png", 3600, body)

	mc.MaybeStore(req, resp, body, testURL)

	got, hdr, ok := mc.Get(testURL, "")
	if !ok {
		t.Fatal("expected cache hit, got miss")
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: got %q want %q", got, body)
	}
	if ct := hdr.Get("Content-Type"); ct != "image/png" {
		t.Fatalf("Content-Type mismatch: got %q", ct)
	}
}

// --- TestMediaCacheRejectsNonMedia -----------------------------------------------

func TestMediaCacheRejectsNonMedia(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/page.html"
	body := []byte("<html>hello</html>")

	req := makeGET(testURL)
	resp := makeResp(200, "text/html", 3600, body)

	mc.MaybeStore(req, resp, body, testURL)

	_, _, ok := mc.Get(testURL, "")
	if ok {
		t.Fatal("text/html must not be cached")
	}
}

// --- TestMediaCacheRejectsOversize -----------------------------------------------

func TestMediaCacheRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/bigvideo.mp4"
	// 16 MiB + 1 byte — just over the limit
	bigBody := make([]byte, 16*1024*1024+1)

	req := makeGET(testURL)
	resp := makeResp(200, "video/mp4", 3600, bigBody)

	mc.MaybeStore(req, resp, bigBody, testURL)

	_, _, ok := mc.Get(testURL, "")
	if ok {
		t.Fatal("oversized object must not be cached")
	}
}

// --- TestMediaCacheExpiry --------------------------------------------------------

func TestMediaCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	// Use a time seam: set nowFn to control the clock.
	mc := NewMediaCache(dir)

	// Fix "now" at epoch so we can advance it.
	epoch := time.Unix(1_000_000, 0)
	mc.nowFn = func() time.Time { return epoch }

	const testURL = "http://example.com/icon.png"
	body := []byte("ICO")

	req := makeGET(testURL)
	// TTL = 1 second
	resp := makeResp(200, "image/png", 1, body)

	mc.MaybeStore(req, resp, body, testURL)

	// Before expiry: should hit.
	if _, _, ok := mc.Get(testURL, ""); !ok {
		t.Fatal("expected hit before TTL expires")
	}

	// Advance clock past TTL.
	mc.nowFn = func() time.Time { return epoch.Add(2 * time.Second) }

	if _, _, ok := mc.Get(testURL, ""); ok {
		t.Fatal("expected miss after TTL expires")
	}
}

// --- TestMediaCacheHandlerServesHit ---------------------------------------------

// TestMediaCacheHandlerServesHit verifies that the handler serves a cached
// response without hitting the upstream backend.
func TestMediaCacheHandlerServesHit(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://media.example.com/logo.png"
	// The handler computes vhostCacheURL = "https://" + host + path, so
	// pre-populate with the same key format to ensure a cache hit.
	const cacheKey = "https://media.example.com/logo.png"
	body := []byte("PNG_DATA")

	// Pre-populate cache directly using the same key the handler will use.
	req := makeGET(testURL)
	resp := makeResp(200, "image/png", 3600, body)
	mc.MaybeStore(req, resp, body, cacheKey)

	// Backend that must NOT be called.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend was called on a cache hit — should have been short-circuited")
		http.Error(w, "backend called", http.StatusInternalServerError)
	}))
	defer backend.Close()

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	h, p, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}

	srv := &Server{
		mediaCache: mc,
		routeLookup: func(host string) (string, int, bool) {
			if host == "media.example.com" {
				return h, p, true
			}
			return "", 0, false
		},
	}

	handler := srv.handler()

	httpReq := httptest.NewRequest(http.MethodGet, testURL, nil)
	httpReq.Host = "media.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httpReq)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	got, _ := io.ReadAll(res.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: got %q want %q", got, body)
	}
	if v := res.Header.Get("X-SecuBox-Cache"); v != "hit" {
		t.Fatalf("expected X-SecuBox-Cache: hit, got %q", v)
	}
}

// --- TestMediaCacheNoStoreSkipped -----------------------------------------------

func TestMediaCacheNoStoreSkipped(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/priv.png"
	body := []byte("PNG")

	req := makeGET(testURL)
	resp := makeResp(200, "image/png", -1, body) // -1 → no-store

	mc.MaybeStore(req, resp, body, testURL)

	if _, _, ok := mc.Get(testURL, ""); ok {
		t.Fatal("no-store response must not be cached")
	}
}

// --- TestMediaCacheStatsIncrement -----------------------------------------------

func TestMediaCacheStatsIncrement(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/audio.mp3"
	body := []byte("MP3")

	req := makeGET(testURL)
	resp := makeResp(200, "audio/mpeg", 3600, body)
	mc.MaybeStore(req, resp, body, testURL)

	s1 := mc.Stats()
	if s1.Stored != 1 {
		t.Fatalf("expected Stored=1, got %d", s1.Stored)
	}

	// Hit
	mc.Get(testURL, "")
	s2 := mc.Stats()
	if s2.Hits != 1 {
		t.Fatalf("expected Hits=1, got %d", s2.Hits)
	}

	// Miss
	mc.Get("http://example.com/notfound.mp3", "")
	s3 := mc.Stats()
	if s3.Misses != 1 {
		t.Fatalf("expected Misses=1, got %d", s3.Misses)
	}
}

// --- TestMediaCacheEviction -----------------------------------------------------

func TestMediaCacheEviction(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	// Set a tiny cap so we can trigger eviction easily.
	// 100 bytes total, each object ~30 bytes.
	mc.maxTotal = 100

	for i := 0; i < 5; i++ {
		u := fmt.Sprintf("http://example.com/img%d.png", i)
		body := make([]byte, 30)
		req := makeGET(u)
		resp := makeResp(200, "image/png", 3600, body)
		mc.MaybeStore(req, resp, body, u)
	}

	s := mc.Stats()
	if s.Evicted == 0 {
		t.Fatalf("expected evictions with a 100-byte cap and 5×30-byte objects")
	}

	// Confirm total is at or below cap.
	if s.BytesCached > mc.maxTotal {
		t.Fatalf("total %d exceeds cap %d after eviction", s.BytesCached, mc.maxTotal)
	}
}

// --- TestMediaCacheNonGETNotCached ----------------------------------------------

func TestMediaCacheNonGETNotCached(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://example.com/upload.png"
	body := []byte("PNG")

	// POST, not GET
	req, _ := http.NewRequest(http.MethodPost, testURL, nil)
	resp := makeResp(200, "image/png", 3600, body)
	mc.MaybeStore(req, resp, body, testURL)

	if _, _, ok := mc.Get(testURL, ""); ok {
		t.Fatal("POST response must not be cached")
	}
}

// --- TestMediaCachePersistenceAcrossRestart ------------------------------------

func TestMediaCachePersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	mc1 := NewMediaCache(dir)

	const testURL = "http://example.com/persist.png"
	body := []byte("PERSIST")

	req := makeGET(testURL)
	resp := makeResp(200, "image/png", 3600, body)
	mc1.MaybeStore(req, resp, body, testURL)

	// "Restart": new cache instance pointing at same dir.
	mc2 := NewMediaCache(dir)

	got, _, ok := mc2.Get(testURL, "")
	if !ok {
		t.Fatal("expected cache hit after restart (on-disk persistence)")
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch after restart: got %q want %q", got, body)
	}
}

// --- TestMediaCacheHandlerMissStores -------------------------------------------

// TestMediaCacheHandlerMissStores verifies that on a cache miss the handler
// proxies to the backend, stores the response, and subsequent requests are
// served from cache.
func TestMediaCacheHandlerMissStores(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	body := []byte("IMAGE_FROM_BACKEND")
	calls := 0

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer backend.Close()

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	h, p, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}

	srv := &Server{
		mediaCache: mc,
		routeLookup: func(host string) (string, int, bool) {
			if host == "media.example.com" {
				return h, p, true
			}
			return "", 0, false
		},
	}
	handler := srv.handler()

	// First request: miss → backend called → stored.
	req1 := httptest.NewRequest(http.MethodGet, "http://media.example.com/img.png", nil)
	req1.Host = "media.example.com"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec1.Code)
	}
	got1, _ := io.ReadAll(rec1.Result().Body)
	if !bytes.Equal(got1, body) {
		t.Fatalf("first request body mismatch: %q", got1)
	}
	if calls != 1 {
		t.Fatalf("expected 1 backend call, got %d", calls)
	}

	// Second request: should hit cache.
	req2 := httptest.NewRequest(http.MethodGet, "http://media.example.com/img.png", nil)
	req2.Host = "media.example.com"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", rec2.Code)
	}
	if v := rec2.Header().Get("X-SecuBox-Cache"); v != "hit" {
		t.Fatalf("expected X-SecuBox-Cache: hit on second request, got %q", v)
	}
	if calls != 1 {
		t.Fatalf("expected still 1 backend call (cache hit), got %d", calls)
	}
}

// --- TestMediaCacheHandlerOversizeStreamsFullBody -------------------------------

// TestMediaCacheHandlerOversizeStreamsFullBody is a regression guard for the
// overflow branch of cachingResponseWriter.Write.  It verifies that when an
// upstream returns a media response whose body exceeds 16 MiB (the cache object
// cap), the FULL body is still forwarded to the client — not truncated — and that
// the object is NOT stored in the cache (Get → ok=false).
//
// This test guards against any future refactor that might accidentally return
// early or drop bytes when the overflow flag is set, silently truncating large
// progressive-video downloads.
func TestMediaCacheHandlerOversizeStreamsFullBody(t *testing.T) {
	const oversizeLen = 16*1024*1024 + 64*1024 // 16 MiB + 64 KiB

	// Build a deterministic body so we can checksum it end-to-end.
	bigBody := make([]byte, oversizeLen)
	for i := range bigBody {
		bigBody[i] = byte(i & 0xff)
	}
	wantSum := sha256.Sum256(bigBody)

	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "http://video.example.com/big.mp4"

	// Backend returns a video/mp4 response larger than maxObj.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(bigBody); err != nil {
			t.Errorf("backend Write error: %v", err)
		}
	}))
	defer backend.Close()

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	h, p, err := splitHostPort(backendAddr)
	if err != nil {
		t.Fatalf("splitHostPort: %v", err)
	}

	srv := &Server{
		mediaCache: mc,
		routeLookup: func(host string) (string, int, bool) {
			if host == "video.example.com" {
				return h, p, true
			}
			return "", 0, false
		},
	}
	handler := srv.handler()

	req := httptest.NewRequest(http.MethodGet, testURL, nil)
	req.Host = "video.example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	res := rec.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	// Read the FULL client body and verify nothing was truncated.
	gotBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll response body: %v", err)
	}
	if len(gotBody) != oversizeLen {
		t.Fatalf("client received %d bytes, want %d (full body truncated!)", len(gotBody), oversizeLen)
	}
	gotSum := sha256.Sum256(gotBody)
	if gotSum != wantSum {
		t.Fatal("client body checksum mismatch — content corrupted in overflow path")
	}

	// Verify the oversize object was NOT cached.
	_, _, cached := mc.Get(testURL, "")
	if cached {
		t.Fatal("oversize object must NOT be cached (exceeds 16 MiB per-object cap)")
	}
}

// --- TestMediaCacheVhostIsolation -----------------------------------------------

// TestMediaCacheVhostIsolation verifies that two different vhosts serving the
// same asset path receive independent cache entries.  Without vhost-aware keys
// a /logo.png stored for siteA would collide with the lookup for siteB — cross-
// tenant content bleed.
//
// This mirrors the Python media_cache.py behaviour where r.pretty_url (full URL
// including host) is used as the cache key instead of path-only.
func TestMediaCacheVhostIsolation(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const path = "/x.png"
	const hostA = "siteA.example.com"
	const hostB = "siteB.example.com"

	keyA := "https://" + hostA + path
	keyB := "https://" + hostB + path

	bodyA := []byte("LOGO_FOR_SITE_A")
	bodyB := []byte("LOGO_FOR_SITE_B")

	// Store an object for host A only.
	reqA := makeGET("http://" + hostA + path)
	respA := makeResp(200, "image/png", 3600, bodyA)
	mc.MaybeStore(reqA, respA, bodyA, keyA)

	// Host A should hit with its own content.
	got, _, ok := mc.Get(keyA, "")
	if !ok {
		t.Fatal("expected cache HIT for host A")
	}
	if !bytes.Equal(got, bodyA) {
		t.Fatalf("host A body mismatch: got %q want %q", got, bodyA)
	}

	// Host B — same path, different vhost — must be a MISS (vhost isolation).
	_, _, ok = mc.Get(keyB, "")
	if ok {
		t.Fatal("expected cache MISS for host B (vhost isolation violated — cross-tenant bleed)")
	}

	// Store a different object for host B.
	reqB := makeGET("http://" + hostB + path)
	respB := makeResp(200, "image/png", 3600, bodyB)
	mc.MaybeStore(reqB, respB, bodyB, keyB)

	// Now host B hits with its own content, not host A's.
	got, _, ok = mc.Get(keyB, "")
	if !ok {
		t.Fatal("expected cache HIT for host B after store")
	}
	if !bytes.Equal(got, bodyB) {
		t.Fatalf("host B body mismatch: got %q want %q", got, bodyB)
	}

	// Host A must still serve its own content unchanged.
	got, _, ok = mc.Get(keyA, "")
	if !ok {
		t.Fatal("expected cache HIT for host A to persist after host B was stored")
	}
	if !bytes.Equal(got, bodyA) {
		t.Fatalf("host A body mismatch after host B store: got %q want %q", got, bodyA)
	}
}

// Ensure os is used (for t.TempDir reference to filesystem).
var _ = os.DevNull

// --- Content-Encoding preservation (issue #777) ---------------------------------

// respWithCE builds a cacheable response carrying a Content-Encoding header.
func respWithCE(ct, ce string, maxAge int, body []byte) *http.Response {
	r := makeResp(200, ct, maxAge, body)
	if ce != "" {
		r.Header.Set("Content-Encoding", ce)
	}
	return r
}

// A gzip body must round-trip WITH its Content-Encoding so a gzip-capable client
// can decode it. This is the core fix: without the replayed header the browser
// reads 0x1F as text (U+001F) and the asset is dead.
func TestMediaCachePreservesContentEncoding(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "https://yacy.example/js/app.js"
	// The cache is byte-opaque; a gzip-magic prefix is enough to exercise it.
	gzBody := []byte{0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03}

	mc.MaybeStore(makeGET(testURL),
		respWithCE("application/javascript", "gzip", 3600, gzBody), gzBody, testURL)

	got, hdr, ok := mc.Get(testURL, "gzip, deflate, br")
	if !ok {
		t.Fatal("expected hit for gzip-capable client")
	}
	if !bytes.Equal(got, gzBody) {
		t.Fatalf("body mismatch")
	}
	if ce := hdr.Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding not replayed: got %q want gzip", ce)
	}
}

// An encoded entry must MISS when the client cannot decode that coding, so the
// caller proxies upstream instead of handing over undecodable bytes.
func TestMediaCacheEncodedMissesWhenClientCannotDecode(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "https://yacy.example/js/app2.js"
	gzBody := []byte{0x1f, 0x8b, 0x08, 0x00}
	mc.MaybeStore(makeGET(testURL),
		respWithCE("application/javascript", "gzip", 3600, gzBody), gzBody, testURL)

	if _, _, ok := mc.Get(testURL, "identity"); ok {
		t.Fatal("expected miss for client not accepting gzip")
	}
	if _, _, ok := mc.Get(testURL, ""); ok {
		t.Fatal("expected miss for client with empty Accept-Encoding")
	}
	if _, _, ok := mc.Get(testURL, "gzip;q=0, identity"); ok {
		t.Fatal("expected miss when gzip is refused via q=0")
	}
}

// A legacy entry (gzip body stored by the pre-fix cache with no recorded
// Content-Encoding) must be evicted and treated as a miss — serving it as
// identity is exactly the corruption bug.
func TestMediaCacheEvictsCorruptLegacyGzip(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "https://yacy.example/js/legacy.js"
	gzBody := []byte{0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad}
	// makeResp sets no Content-Encoding → ce="" is persisted, mimicking the old binary.
	mc.MaybeStore(makeGET(testURL),
		makeResp(200, "application/javascript", 3600, gzBody), gzBody, testURL)

	if _, _, ok := mc.Get(testURL, "gzip"); ok {
		t.Fatal("expected corrupt legacy gzip entry to be evicted, got hit")
	}
	if _, _, ok := mc.Get(testURL, "gzip"); ok {
		t.Fatal("entry should remain evicted on the second lookup")
	}
}

// --- encodingAccepted table (M1: trailing-param q-value) ------------------------

func TestEncodingAcceptedTable(t *testing.T) {
	cases := []struct {
		ae, coding string
		want       bool
	}{
		{"gzip, deflate, br", "gzip", true},
		{"gzip, deflate, br", "br", true},
		{"gzip, deflate", "zstd", false},
		{"*", "gzip", true},
		{"*;q=0", "gzip", false},
		{"gzip;q=0, identity", "gzip", false},
		{"gzip;q=0;x=y, identity", "gzip", false}, // trailing param after q= must still reject
		{"gzip;q=1.0", "gzip", true},
		{"  GZIP ;q=0.5 ", "gzip", true},          // case + whitespace
		{"", "gzip", false},
		{"anything", "", true},        // identity coding always ok
		{"", "identity", true},        // identity coding always ok
	}
	for _, c := range cases {
		if got := encodingAccepted(c.ae, c.coding); got != c.want {
			t.Errorf("encodingAccepted(%q, %q) = %v, want %v", c.ae, c.coding, got, c.want)
		}
	}
}

// --- I1: legacy non-gzip (brotli/deflate/zstd) text entry must self-heal --------

func TestMediaCacheEvictsCorruptLegacyNonGzipText(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "https://yacy.example/js/legacy-br.js"
	// A brotli/zstd body has no gzip magic but is not valid UTF-8 — simulate with
	// raw bytes that are invalid UTF-8 and don't start 0x1f8b.
	brBody := []byte{0x8b, 0x02, 0x80, 0xff, 0xfe, 0x00, 0x41}
	if utf8.Valid(brBody) {
		t.Fatal("test body must be invalid UTF-8")
	}
	mc.MaybeStore(makeGET(testURL),
		makeResp(200, "application/javascript", 3600, brBody), brBody, testURL)

	// Recorded ce="" (makeResp sets none) + non-UTF-8 JS body → corrupt legacy →
	// must be evicted, not served as identity.
	if _, _, ok := mc.Get(testURL, "br"); ok {
		t.Fatal("expected corrupt legacy non-gzip text entry to be evicted, got hit")
	}
}

// A legitimate identity JS body (valid UTF-8, ce="") must still be served.
func TestMediaCacheServesValidIdentityText(t *testing.T) {
	dir := t.TempDir()
	mc := NewMediaCache(dir)

	const testURL = "https://yacy.example/js/plain.js"
	body := []byte("/* hello */ console.log('héllo');") // valid UTF-8
	mc.MaybeStore(makeGET(testURL),
		makeResp(200, "application/javascript", 3600, body), body, testURL)

	got, hdr, ok := mc.Get(testURL, "gzip")
	if !ok {
		t.Fatal("expected hit for valid identity JS body")
	}
	if !bytes.Equal(got, body) {
		t.Fatal("body mismatch")
	}
	if ce := hdr.Get("Content-Encoding"); ce != "" {
		t.Fatalf("identity body must have no Content-Encoding, got %q", ce)
	}
}
