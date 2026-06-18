// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: gzip-aware banner injection (#662)
//
// The transparency-banner inject (injectLoader) scans the HTML body for
// <head>/<body>. Browsers send `Accept-Encoding: gzip, br`, so most upstream
// responses come back COMPRESSED — and a compressed body has no plaintext
// <head>/<body> for injectLoader to find, so it silently no-ops (the banner
// vanished on every gzip page). mitmPipeline now pins the upstream request to
// `Accept-Encoding: gzip` (dropping br/zstd/deflate we cannot decode with the
// stdlib), so every response is either gzip or identity.
//
// This file holds the gzip helpers + the single inject-path transform that
// decompresses (if gzip) → injectLoader → recompresses, fail-open on any error
// so a banner asset never breaks the page.
//
// Pure standard library — compress/gzip only; no external modules (brotli/zstd
// are NOT in the stdlib, which is exactly why we constrain the wire to gzip).
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

// gunzipCap bounds the decompressed output so a maliciously-crafted gzip body
// (a "decompression bomb") cannot blow the worker's memory. The upstream body
// itself is already read under an 8MiB LimitReader; 32MiB of inflated HTML is a
// generous ceiling for a single page. Exceeding it → treated as an error
// (caller fails open and serves the original compressed bytes).
const gunzipCap = 32 << 20

// gunzipBytes inflates a gzip-compressed body. It is defensive on two axes:
//   - a malformed/non-gzip input returns an error (caller fails open),
//   - the decompressed output is capped at gunzipCap; if the stream would
//     exceed it, that is reported as an error too (decompression-bomb guard).
func gunzipBytes(in []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	// Read up to gunzipCap+1 so we can tell "exactly at the cap" (fine) from
	// "the stream is bigger than the cap" (bomb → error).
	out, err := io.ReadAll(io.LimitReader(zr, gunzipCap+1))
	if err != nil {
		return nil, err
	}
	if len(out) > gunzipCap {
		return nil, errGunzipTooLarge
	}
	return out, nil
}

// errGunzipTooLarge is returned by gunzipBytes when the decompressed stream
// exceeds gunzipCap (decompression-bomb guard).
var errGunzipTooLarge = errString("gunzip output exceeds cap")

// errString is a tiny stdlib-only error type (avoids importing errors/fmt for
// one sentinel).
type errString string

func (e errString) Error() string { return string(e) }

// gzipBytes compresses in with the default gzip level. It never errors: the
// gzip.Writer only writes into an in-memory bytes.Buffer, which cannot fail.
func gzipBytes(in []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(in)
	_ = zw.Close()
	return buf.Bytes()
}

// injectIntoBody runs the transparency-banner injection over a (possibly
// gzip-compressed) HTML body, returning the new body bytes to serve and whether
// the body was rewritten.
//
//   - encoding == "" (identity): injectLoader runs directly on body; the result
//     is returned (ok=true). The caller MUST update Content-Length to len(out).
//   - encoding == "gzip" (case-insensitive): the body is gunzipped, injected,
//     then RE-gzipped so the client transfer stays compressed (the tunnel is
//     perf-sensitive). The caller keeps Content-Encoding: gzip and sets
//     Content-Length to len(out).
//   - any other encoding (br/zstd/deflate — should not occur after the upstream
//     Accept-Encoding pin, but be safe): pass through untouched, ok=false.
//
// Fail-open: if gunzip fails (corrupt / not-actually-gzip / bomb), the ORIGINAL
// bytes are returned with ok=false so the page is never broken.
//
// idempotency / placement live entirely inside injectLoader (unchanged).
func injectIntoBody(body []byte, encoding, clientHash string, wg bool) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		return injectLoader(body, clientHash, wg), true
	case "gzip":
		plain, err := gunzipBytes(body)
		if err != nil {
			return body, false // fail open: serve the original compressed bytes
		}
		injected := injectLoader(plain, clientHash, wg)
		return gzipBytes(injected), true
	default:
		return body, false // unknown encoding we cannot decode → pass through
	}
}
