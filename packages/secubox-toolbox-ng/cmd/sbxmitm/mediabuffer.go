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
// here is nil-safe and swallows its own errors. ObjectWriter.Write in
// particular must NEVER return an error and must NEVER block or slow the
// proxied flow — it is designed to sit behind an io.TeeReader wrapped around
// the live client stream, so any hiccup here must be invisible upstream.
//
// Pure standard library.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
// unbounded field here, so this is generous but still bounds a single
// misbehaving line from corrupting the atomic-append assumption other
// readers/writers rely on.
const mediaBufferLineMax = 8192

// MediaBuffer is the buffer store: it decides whether a flow is capturable
// media and, if so, opens a per-object file under a fresh session directory
// and returns a writer for it. It holds no long-lived resources of its own
// (no open file handles) besides the metatag log, which is opened/appended
// per write — mirroring mediaCatcher's own defensiveness.
type MediaBuffer struct {
	root          string
	enabled       bool
	perObjectCeil int64
}

// NewMediaBuffer constructs a MediaBuffer rooted at root (expected to already
// exist as /data/secubox/media-buffer, 0750 secubox:secubox — this
// constructor does not create it; Capture creates only the per-session
// subdirectories). enabled false is the feature-flagged-off default: every
// method becomes a safe no-op (Capture always returns nil).
func NewMediaBuffer(root string, enabled bool, perObjectCeil int64) *MediaBuffer {
	return &MediaBuffer{root: root, enabled: enabled, perObjectCeil: perObjectCeil}
}

// IsMedia reports whether a response/request with this Content-Type / path
// should be considered capturable media. It reuses mediaKind (mediacatch.go),
// which already covers ctype prefixes ("video/", "audio/"), manifest
// mimetypes/extensions (HLS .m3u8, DASH .mpd) and known media file
// extensions — any non-empty classification counts as media. nil-safe.
func (b *MediaBuffer) IsMedia(ctype, path string) bool {
	if b == nil {
		return false
	}
	return mediaKind(path, ctype) != ""
}

// Capture decides whether to start recording a flow's body and, if so,
// creates root/<session_id>/object-0.<ext> and returns a writer for it.
// Returns nil when: the buffer is nil, disabled, the content isn't media, or
// a sane guard trips (empty root, session/object creation failure) — in
// every nil case the caller is expected to skip teeing entirely, so the
// proxied flow is completely unaffected.
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
	f, err := os.OpenFile(objPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil
	}

	return &ObjectWriter{
		buf:           b,
		f:             f,
		id:            id,
		sessionID:     sessionID,
		mac:           mac,
		host:          host,
		url:           url,
		direction:     direction,
		kind:          mediaKind(path, ctype),
		ctype:         ctype,
		firstTS:       time.Now().Unix(),
		perObjectCeil: b.perObjectCeil,
	}
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
	BufferRef string `json:"buffer_ref"`
	Expired   bool   `json:"expired"`
}

// ObjectWriter is the per-object capture in progress. It implements
// io.Writer so it can sit behind an io.TeeReader wrapped around a live
// response/request body: Write must be cheap, must never error, and must
// stop persisting once perObjectCeil bytes have been written (the excess is
// silently dropped, truncated is flagged, and the caller still sees a normal
// len(p), nil so the proxied stream is never disturbed).
type ObjectWriter struct {
	buf *MediaBuffer

	mu      sync.Mutex
	f       *os.File
	closed  bool
	written int64

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
	truncated     bool
}

// Write persists up to perObjectCeil total bytes to the object file, then
// silently discards the rest (flagging truncated). It always reports the
// full len(p) written with a nil error, regardless of what actually landed
// on disk — callers (an io.TeeReader in front of the real proxied stream)
// must never observe a failure here.
func (w *ObjectWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed || w.f == nil {
		return len(p), nil
	}

	remaining := w.perObjectCeil - w.written
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil
	}

	toWrite := p
	if int64(len(toWrite)) > remaining {
		toWrite = toWrite[:remaining]
		w.truncated = true
	}
	if len(toWrite) > 0 {
		n, err := w.f.Write(toWrite)
		w.written += int64(n)
		if err != nil {
			// Disk/IO trouble: stop trying to persist further bytes for this
			// object, but the flow keeps going — never surface this upward.
			w.truncated = true
			_ = w.f.Close()
			w.f = nil
		}
	}
	return len(p), nil
}

// Close finalizes the object (fsync best-effort, close the file) and appends
// the metatag line recording finalBytes — the total size of the flow as
// observed by the caller, which may exceed what was actually persisted when
// truncated is set. nil-safe; safe to call at most meaningfully once (a
// second call is a harmless no-op).
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
	lastTS := time.Now().Unix()
	if w.f != nil {
		_ = w.f.Sync()
		_ = w.f.Close()
		w.f = nil
	}
	rec := mediaBufferRecord{
		ID:        w.id,
		SessionID: w.sessionID,
		FirstTS:   w.firstTS,
		LastTS:    lastTS,
		MacHash:   w.mac,
		Host:      w.host,
		URL:       w.url,
		Direction: w.direction,
		Kind:      w.kind,
		CType:     w.ctype,
		Bytes:     finalBytes,
		Segments:  0,
		Truncated: w.truncated,
		BufferRef: w.sessionID,
		Expired:   false,
	}
	buf := w.buf
	w.mu.Unlock()

	buf.appendMetatag(rec)
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
