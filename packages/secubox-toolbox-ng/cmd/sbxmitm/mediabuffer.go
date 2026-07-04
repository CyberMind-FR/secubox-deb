// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: R4 media buffer store (#812)
//
// Phase 1 of the SecuBox Media Buffer: unlike mediacatch.go (which only
// records cloneable media URLs, never bodies), this tees the actual bytes of
// whole-file media downloads/uploads flowing through R3/sbxmitm into a
// time-bounded rolling buffer on /data, so an admin/owner can replay a short
// recent capture. Only the metatag (never the bytes) is meant to outlive the
// retention window — that eviction is handled by the janitor (a later file).
//
// Non-blocking capture contract (same as mediacatch.go:record): every method
// here is nil-safe and swallows its own errors. Crucially the capture is
// designed to sit behind an io.TeeReader wrapped around the LIVE client stream,
// so it must NEVER slow or fail the proxied flow (design §4.2, §7). To honour
// that on ARM eMMC — where an inline os.File.Write on the read path would add
// latency and could stall a large-media transfer — ObjectWriter.Write does NOT
// touch the disk: it copies the chunk into a bounded channel and returns
// immediately. A background goroutine (started at Capture) drains the channel
// and performs the real writes. If the channel is full the chunk is DROPPED
// (metatag flagged truncated) and Write still returns len(p), nil — the flow is
// never blocked, never errored.
//
// Pure standard library.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// mediaBufferLogName is the append-only JSONL metatag log living directly
// under the buffer root. One line per write (Capture's Close, and later the
// janitor's eviction flip) — never rewritten in place; readers dedup by "id"
// keeping the last line (mirrors common/secubox_core/media_catch.py's
// tail-read + last-writer-wins convention).
const mediaBufferLogName = "media-buffer.jsonl"

// mediaBufferLineMax keeps each metatag line small: URLs are the only
// unbounded field here. Matches mediacatch.go's 4096 cap, which is the size
// that keeps an O_APPEND write atomic across the 4 concurrent worker processes
// (PIPE_BUF); a longer line risks torn/interleaved appends corrupting the log.
// Over-long lines (very long signed CDN URLs) are dropped rather than written.
const mediaBufferLineMax = 4096

// mediaBufferChanCap bounds how many not-yet-persisted body chunks may queue
// behind a single object's writer. It caps the RAM a slow disk can pin (chunks
// are copies of the reader's buffer, typically ≤32 KiB each → ≤~2 MiB in
// flight) and, once full, is the signal to DROP (truncate) rather than block
// the proxied stream — the non-blocking guarantee. Small enough to bound
// memory, large enough that a healthy /data never drops.
const mediaBufferChanCap = 64

// defaultRetentionSecs is the Phase 1 time-eviction window (design §Global
// Constraints: "Retention: time-only, default RETENTION_SECS=1200 (20 min)").
const defaultRetentionSecs int64 = 1200

// defaultSizeCeilBytes is the Phase 1 LRU pressure valve (24 GiB) — the
// janitor (mediabuffer_janitor.go) only evicts early, by oldest first_ts, when
// the buffer root exceeds this even before an object's retention has elapsed.
const defaultSizeCeilBytes int64 = 24 << 30

// MediaBuffer is the buffer store: it decides whether a flow is capturable
// media and, if so, opens a per-object file under a fresh session directory
// and returns a writer for it. It holds no long-lived resources of its own
// (no open file handles) besides the metatag log, which is opened/appended
// per write — mirroring mediaCatcher's own defensiveness.
type MediaBuffer struct {
	root          string
	enabled       bool
	perObjectCeil int64

	// retentionSecs / sizeCeilBytes are the janitor's (mediabuffer_janitor.go)
	// eviction knobs — time-window and LRU size ceiling respectively. Wired
	// with sane Phase 1 defaults here so NewMediaBuffer's signature never has
	// to change for other callers/tasks; tests may poke them directly (they
	// are unexported, same-package fields, e.g. `b.retentionSecs = 60`).
	retentionSecs int64
	sizeCeilBytes int64

	// nowFn is the janitor's clock seam: defaults to the real wall clock but
	// is replaceable in tests so eviction timing is deterministic.
	nowFn func() int64

	// janitorTick overrides RunJanitor's ticker period; zero means the real
	// default (30s). Test-only seam so RunJanitor's ticking behaviour itself
	// (not just SweepOnce) can be exercised without a real 30s wait.
	janitorTick time.Duration

	// chanCap is the per-object write-queue depth (default mediaBufferChanCap).
	// Overridable in tests to force the drop-when-full path deterministically.
	chanCap int

	// openSink opens the on-disk object sink. Default nil → a real os.File via
	// os.OpenFile. Overridable in tests to inject a slow/blocking WriteCloser
	// that proves Write stays non-blocking while the disk is stuck.
	openSink func(path string) (io.WriteCloser, error)
}

// NewMediaBuffer constructs a MediaBuffer rooted at root (expected to already
// exist as /data/secubox/media-buffer, 2750 secubox-toolbox:secubox with the
// setgid bit — the workers write as secubox-toolbox, the dpi reader is group
// secubox, and setgid propagates group `secubox` to the objects we create; see
// the tmpfiles file. This constructor does not create root; Capture creates only
// the per-session subdirectories). enabled false is the feature-flagged-off
// default: every method becomes a safe no-op (Capture always returns nil).
func NewMediaBuffer(root string, enabled bool, perObjectCeil int64) *MediaBuffer {
	return &MediaBuffer{
		root:          root,
		enabled:       enabled,
		perObjectCeil: perObjectCeil,
		chanCap:       mediaBufferChanCap,
		retentionSecs: defaultRetentionSecs,
		sizeCeilBytes: defaultSizeCeilBytes,
		nowFn:         func() int64 { return time.Now().Unix() },
	}
}

// IsMedia reports whether a response/request with this Content-Type / path
// should be considered capturable media. It reuses mediaKind (mediacatch.go),
// which already covers ctype prefixes ("video/", "audio/"), manifest
// mimetypes/extensions (HLS .m3u8, DASH .mpd) and known media file
// extensions — any non-empty classification counts as media. Also true for
// segmentKind (Phase 2, #812): an HLS/DASH segment chunk is media that should
// be buffered even in the ambiguous-ctype cases (e.g. a .m4s served as
// application/octet-stream) that mediaKind's coarser rules don't recognise on
// their own. nil-safe.
func (b *MediaBuffer) IsMedia(ctype, path string) bool {
	if b == nil {
		return false
	}
	return mediaKind(path, ctype) != "" || segmentKind(path, ctype)
}

// segmentKind reports whether path/ctype identify an HLS/DASH segment CHUNK
// (as opposed to a whole-file video/audio download or a manifest). Segments
// are ordinary 200 downloads like any other media object (Phase 1's ==200
// gate already applies) but must be tagged kind="segment" — not "video" — so
// the DPI gallery can hide them and Phase 2's replay-time URL join can find
// them (see Capture below, which gives segmentKind precedence over
// mediaKind's video/audio classification).
//
// True for: path ending .ts, .m4s or .m4v (HLS transport-stream / fMP4 /
// DASH chunk extensions), or ctype video/mp2t (a.k.a. video/MP2T) or
// video/iso.segment. Deliberately FALSE for whole-file .mp4/.webm/.mkv/.mov
// and for .m3u8/.mpd manifests — those must keep classifying as "video" /
// "manifest" via mediaKind, unchanged. When ctype is ambiguous (e.g.
// application/octet-stream, or empty) only the path extension decides — a
// bare "some binary blob" ctype must NOT be guessed into "segment" without a
// segment-shaped path.
func segmentKind(path, ctype string) bool {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if strings.HasSuffix(p, ".ts") || strings.HasSuffix(p, ".m4s") || strings.HasSuffix(p, ".m4v") {
		return true
	}
	switch strings.ToLower(ctype) {
	case "video/mp2t", "video/iso.segment":
		return true
	}
	return false
}

// Capture decides whether to start recording a flow's body and, if so,
// creates root/<session_id>/object-0.<ext>, starts the background drain
// goroutine and returns a writer for it. Returns nil when: the buffer is nil,
// disabled, the content isn't media, or a sane guard trips (empty root,
// session/object creation failure) — in every nil case the caller is expected
// to skip teeing entirely, so the proxied flow is completely unaffected.
//
// contentLen is reserved (unused in Phase 1 — no upfront size guard against
// the advertised Content-Length; the per-object ceiling is enforced only as
// bytes actually arrive, in drain). A later phase may use it to skip Capture
// outright for declared-oversized objects.
func (b *MediaBuffer) Capture(mac, host, url, path, ctype, direction string, contentLen int64) *ObjectWriter {
	if b == nil || !b.enabled || b.root == "" {
		return nil
	}
	if !b.IsMedia(ctype, path) {
		return nil
	}

	sessionID, err := randHex(16)
	if err != nil || sessionID == "" {
		return nil
	}
	id, err := randHex(8)
	if err != nil || id == "" {
		return nil
	}

	sessDir := filepath.Join(b.root, sessionID)
	if err := os.MkdirAll(sessDir, 0o750); err != nil {
		return nil
	}
	objPath := filepath.Join(sessDir, "object-0"+extForCapture(path, ctype))

	var sink io.WriteCloser
	if b.openSink != nil {
		sink, err = b.openSink(objPath)
	} else {
		sink, err = os.OpenFile(objPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	}
	if err != nil || sink == nil {
		return nil
	}

	qcap := b.chanCap
	if qcap <= 0 {
		qcap = mediaBufferChanCap
	}

	// kind: mediaKind's coarser ctype-prefix rule ("video/" → "video") would
	// otherwise misclassify an HLS/DASH segment (e.g. .ts served video/mp2t)
	// as a whole video. segmentKind takes precedence when it matches — Phase
	// 2 (#812) needs kind="segment" so the DPI gallery can hide it and the
	// replay-time manifest join can find it — but whole-file .mp4/video/*
	// and .m3u8/.mpd manifests are unaffected (segmentKind is false for both).
	kind := mediaKind(path, ctype)
	if segmentKind(path, ctype) {
		kind = "segment"
	}

	w := &ObjectWriter{
		buf:           b,
		sink:          sink,
		ch:            make(chan []byte, qcap),
		done:          make(chan struct{}),
		id:            id,
		sessionID:     sessionID,
		mac:           mac,
		host:          host,
		url:           url,
		direction:     direction,
		kind:          kind,
		ctype:         ctype,
		firstTS:       time.Now().Unix(),
		perObjectCeil: b.perObjectCeil,
	}
	go w.drain()
	return w
}

// metatagPath is root/media-buffer.jsonl.
func (b *MediaBuffer) metatagPath() string {
	return filepath.Join(b.root, mediaBufferLogName)
}

// appendMetatag appends one metatag JSON line, best-effort. Errors (encode
// failure, open failure, oversized line) are swallowed — a media buffer must
// never affect the proxied flow, and a missing/short log is simply read as
// "no capture happened" by consumers (fail-empty, per the Python reader).
func (b *MediaBuffer) appendMetatag(rec mediaBufferRecord) {
	if b == nil || b.root == "" {
		return
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	data = append(data, '\n')
	if len(data) > mediaBufferLineMax {
		return
	}
	f, err := os.OpenFile(b.metatagPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(data)
}

// mediaBufferRecord is the metatag line shape. Field names/keys are relied
// upon verbatim by the janitor (eviction flip), the Python reader
// (common/secubox_core/media_buffer.py) and the DPI API — do not rename.
type mediaBufferRecord struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	FirstTS   int64  `json:"first_ts"`
	LastTS    int64  `json:"last_ts"`
	MacHash   string `json:"mac_hash"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	Direction string `json:"direction"`
	Kind      string `json:"kind"`
	CType     string `json:"ctype"`
	Bytes     int64  `json:"bytes"`
	Segments  int    `json:"segments"`
	Truncated bool   `json:"truncated"`
	// BufferRef is the session id while the bytes are on disk, and JSON null once
	// the janitor (Task 3) evicts them — hence *string (a plain string can only
	// marshal to "" , never null). Set to &sessionID at write time.
	BufferRef *string `json:"buffer_ref"`
	Expired   bool    `json:"expired"`
}

// ObjectWriter is the per-object capture in progress. It implements io.Writer
// so it can sit behind an io.TeeReader wrapped around a live response/request
// body. Write is deliberately trivial and non-blocking: it copies the chunk
// (the TeeReader reuses its buffer) and hands it to a bounded channel, which a
// background goroutine (drain) drains to disk. Full channel → the chunk is
// dropped and truncated is set, but Write still returns len(p), nil — the
// proxied stream is never slowed, blocked or errored.
type ObjectWriter struct {
	buf *MediaBuffer

	ch   chan []byte   // bounded queue of copied body chunks (Write → drain)
	done chan struct{} // closed by drain when it has exited (flushed + sink closed)

	// mu guards closed / truncated and serialises the channel send against
	// Close's close(ch) so Write never sends on a closed channel.
	mu        sync.Mutex
	closed    bool
	truncated bool

	// sink, written are owned exclusively by the drain goroutine after Capture
	// (no other goroutine touches them) → no locking needed for the hot write.
	sink    io.WriteCloser
	written int64

	// immutable after Capture.
	id            string
	sessionID     string
	mac           string
	host          string
	url           string
	direction     string
	kind          string
	ctype         string
	firstTS       int64
	perObjectCeil int64
}

// drain is the background writer: it owns the sink and the written counter,
// pulling copied chunks off ch and persisting them until perObjectCeil, then
// silently discarding the rest (flagging truncated). It keeps receiving even
// after the sink is closed/errored so senders never wedge, and on channel
// close it fsyncs + closes the sink and signals done. Runs once per object.
func (w *ObjectWriter) drain() {
	defer close(w.done)
	for chunk := range w.ch {
		if w.sink == nil {
			continue // ceiling hit or IO error earlier: swallow the rest.
		}
		remaining := w.perObjectCeil - w.written
		if remaining <= 0 {
			w.setTruncated()
			w.closeSink()
			continue
		}
		toWrite := chunk
		if int64(len(toWrite)) > remaining {
			toWrite = toWrite[:remaining]
			w.setTruncated()
		}
		if len(toWrite) > 0 {
			n, err := w.sink.Write(toWrite)
			w.written += int64(n)
			if err != nil {
				// Disk/IO trouble: stop persisting, keep draining, never surface it.
				w.setTruncated()
				w.closeSink()
			}
		}
	}
	// Channel closed and fully drained → finalise the sink.
	w.closeSink()
}

// closeSink fsyncs (best-effort, only real files) and closes the sink once.
func (w *ObjectWriter) closeSink() {
	if w.sink == nil {
		return
	}
	if f, ok := w.sink.(*os.File); ok {
		_ = f.Sync()
	}
	_ = w.sink.Close()
	w.sink = nil
}

// setTruncated flags the capture as truncated/partial (ceiling, IO error, or
// a dropped chunk). Cheap, mutex-guarded — called from both drain and Write.
func (w *ObjectWriter) setTruncated() {
	w.mu.Lock()
	w.truncated = true
	w.mu.Unlock()
}

// Write copies p and enqueues it for the background drainer, then returns
// immediately. It NEVER blocks and NEVER errors: a full queue (slow disk) drops
// the chunk and flags truncated; a closed writer is a silent no-op. The
// caller (an io.TeeReader in front of the real proxied stream) always sees the
// full len(p) written with a nil error, so the client stream is never disturbed.
func (w *ObjectWriter) Write(p []byte) (int, error) {
	n := len(p)
	if w == nil {
		return n, nil
	}
	w.mu.Lock()
	if w.closed || w.ch == nil {
		w.mu.Unlock()
		return n, nil
	}
	// Copy: io.TeeReader hands us the reader's own buffer, reused on the next
	// Read — we must not retain p.
	cp := make([]byte, n)
	copy(cp, p)
	select {
	case w.ch <- cp:
	default:
		// Queue full: the disk can't keep up. Drop this chunk rather than block
		// or slow the proxied flow (design §7). The object becomes partial.
		w.truncated = true
	}
	w.mu.Unlock()
	return n, nil
}

// Close signals the drainer that no more chunks are coming, waits for it to
// flush what is already queued and close the file, then appends the metatag
// line recording finalBytes — the total flow size as observed by the caller,
// which may exceed what was persisted when truncated is set. nil-safe;
// idempotent (a second call is a no-op); safe if Write was never called or is
// called concurrently/after Close (that Write becomes a no-op, never a
// send-on-closed-channel panic). Never deadlocks: drain always terminates once
// ch is closed, and Close is the sole closer of ch.
//
// Close is intentionally allowed to BLOCK here (waiting on <-done to drain
// whatever is still queued) — unlike Write, which must never block the live
// proxied stream. By the time Close runs, the body has already been fully
// streamed to the client (it is invoked from the tee's Close, itself deferred
// until the response/request is done), so blocking here only delays this
// flow's own finalisation/metatag, never the client's bytes.
func (w *ObjectWriter) Close(finalBytes int64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	ch := w.ch
	done := w.done
	w.mu.Unlock()

	if ch != nil {
		close(ch) // no more chunks — unblocks drain's range once emptied.
	}
	if done != nil {
		<-done // wait for queued chunks to flush + sink close (metatag then sees complete bytes).
	}

	w.mu.Lock()
	truncated := w.truncated
	w.mu.Unlock()

	rec := mediaBufferRecord{
		ID:        w.id,
		SessionID: w.sessionID,
		FirstTS:   w.firstTS,
		LastTS:    time.Now().Unix(),
		MacHash:   w.mac,
		Host:      w.host,
		URL:       w.url,
		Direction: w.direction,
		Kind:      w.kind,
		CType:     w.ctype,
		Bytes:     finalBytes,
		Segments:  0,
		Truncated: truncated,
		BufferRef: &w.sessionID,
		Expired:   false,
	}
	w.buf.appendMetatag(rec)
}

// teeReadableCloser wraps a response/request body so every byte the proxy reads
// on its way to/from the client is mirrored into an ObjectWriter, WITHOUT
// changing what the caller reads. Reads go through an io.TeeReader; Close both
// closes the underlying body AND finalises the capture (w.Close(total)). The
// capture side is entirely best-effort — a nil writer or any ObjectWriter
// hiccup never affects the reads or the Close error surfaced upstream.
type teeReadableCloser struct {
	rc    io.ReadCloser
	tee   io.Reader
	w     *ObjectWriter
	total int64
	once  sync.Once
}

// teeReadCloser wraps rc so its bytes are teed into w as the proxy streams the
// body, tracking the total read; Close closes rc and calls w.Close(total). A
// nil w yields rc unwrapped (no-op). Errors from w are swallowed.
func teeReadCloser(rc io.ReadCloser, w *ObjectWriter) io.ReadCloser {
	if w == nil {
		return rc
	}
	t := &teeReadableCloser{rc: rc, w: w}
	t.tee = io.TeeReader(rc, w) // each Read copies the bytes into w (non-blocking).
	return t
}

func (t *teeReadableCloser) Read(p []byte) (int, error) {
	n, err := t.tee.Read(p)
	t.total += int64(n)
	return n, err
}

func (t *teeReadableCloser) Close() error {
	err := t.rc.Close()
	t.once.Do(func() {
		if t.w != nil {
			t.w.Close(t.total)
		}
	})
	return err
}

// extForCapture picks a file extension for the on-disk object, preferring
// the URL path's own extension (when short/plausible) and falling back to a
// Content-Type-derived guess. Cosmetic only — every reader resolves the
// object by session dir + "object-0*" glob, not by exact extension.
func extForCapture(path, ctype string) string {
	p := strings.ToLower(path)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		if ext := p[i:]; len(ext) >= 2 && len(ext) <= 6 {
			return ext
		}
	}

	ct := strings.ToLower(ctype)
	switch {
	case strings.Contains(ct, "mpegurl"):
		return ".m3u8"
	case strings.Contains(ct, "dash+xml"):
		return ".mpd"
	case strings.HasPrefix(ct, "video/webm"):
		return ".webm"
	case strings.HasPrefix(ct, "video/"):
		return ".mp4"
	case strings.HasPrefix(ct, "audio/mpeg"):
		return ".mp3"
	case strings.HasPrefix(ct, "audio/"):
		return ".m4a"
	}
	return ".bin"
}

// randHex returns n random bytes hex-encoded, sourced from crypto/rand (NOT
// math/rand — these ids are used as on-disk directory names and must not be
// guessable/collide across concurrent worker processes).
func randHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
