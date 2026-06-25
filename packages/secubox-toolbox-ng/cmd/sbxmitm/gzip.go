// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: compression-aware banner injection (#662)
//
// The transparency-banner inject (injectLoader) scans the HTML body for
// <head>/<body>. Browsers send `Accept-Encoding: gzip, deflate, br, zstd`, so
// most upstream responses come back COMPRESSED — and a compressed body has no
// plaintext <head>/<body> for injectLoader to find, so it silently no-ops.
//
// #662 — we NO LONGER downgrade the upstream Accept-Encoding to gzip (that
// override was itself an anti-bot tell). The client's real AE is forwarded
// verbatim, so a response can come back gzip, br, zstd, or identity. This file
// decodes EACH of those, runs the inject over the plaintext, and RE-ENCODES in
// the SAME encoding (gzip→gzip, br→br, zstd→zstd) so AE preservation no longer
// costs us injection AND the client transfer stays compressed. Everything fails
// open (serve the ORIGINAL bytes on any decode/encode error — never corrupt a
// page); unknown encodings pass through untouched.
//
// Dependencies (cgo-free, pure-Go):
//   - compress/gzip                        (stdlib)
//   - github.com/andybalholm/brotli        (br)
//   - github.com/klauspost/compress/zstd   (zstd)
package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// gunzipCap bounds the decompressed output of EVERY codec (gzip/br/zstd) so a
// maliciously-crafted body (a "decompression bomb") cannot blow the worker's
// memory. The upstream body itself is already read under an 8MiB LimitReader;
// 32MiB of inflated HTML is a generous ceiling for a single page. Exceeding it →
// treated as an error (caller fails open and serves the original compressed
// bytes). Named gunzipCap for history; applies uniformly to br + zstd too.
const gunzipCap = 32 << 20

// readCapped inflates a decompressing reader with the gunzipCap bomb guard,
// shared by gzip/br/zstd. Reads up to gunzipCap+1 so "exactly at the cap" (fine)
// is distinguished from "over the cap" (bomb → error).
func readCapped(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, gunzipCap+1))
	if err != nil {
		return nil, err
	}
	if len(out) > gunzipCap {
		return nil, errGunzipTooLarge
	}
	return out, nil
}

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
	return readCapped(zr)
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

// unbrotliBytes inflates a brotli-compressed body with the gunzipCap bomb guard.
// A malformed/non-brotli input or an over-cap stream returns an error (caller
// fails open). Pure-Go (github.com/andybalholm/brotli — cgo-free).
func unbrotliBytes(in []byte) ([]byte, error) {
	return readCapped(brotli.NewReader(bytes.NewReader(in)))
}

// brotliBytes compresses in with brotli at the default quality. It writes into
// an in-memory buffer; Close flushes the final block. The bytes.Buffer cannot
// fail, but brotli.Writer.Write/Close return errors → surfaced so the caller
// fails open rather than serving a truncated stream.
func brotliBytes(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	if _, err := bw.Write(in); err != nil {
		_ = bw.Close()
		return nil, err
	}
	if err := bw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// unzstdBytes inflates a zstd-compressed body with the gunzipCap bomb guard. A
// malformed/non-zstd input or an over-cap stream returns an error (caller fails
// open). Pure-Go (github.com/klauspost/compress/zstd — cgo-free). The decoder is
// created per-call WITHOUT concurrency goroutines (WithDecoderConcurrency(1)) so
// nothing is left running, then Closed.
func unzstdBytes(in []byte) ([]byte, error) {
	zr, err := zstd.NewReader(bytes.NewReader(in), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return readCapped(zr)
}

// zstdBytes compresses in with zstd at the default level. The encoder is created
// per-call and Closed (flushing the final frame). Errors are surfaced so the
// caller fails open rather than serving a truncated frame.
func zstdBytes(in []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(in); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// injectHTML applies BOTH HTML transforms in one pass over the DECOMPRESSED
// body: the transparency-banner (always, via the INLINE script) AND, for R3 (wg)
// clients, the ad/popup-hiding cosmetic <style> (#662 — the cutover left this
// unported). Both are idempotent (own guard markers) and order-independent;
// running them in the same decompressed step means the cosmetic style benefits
// from the gzip handling exactly like the banner. The cosmetic style is gated to
// wg because it is an R3-tunnel opt-in behaviour (mirrors the Python addon's
// _is_r3plus gate).
//
// #662 — scriptBody is the COMPLETE inline banner IIFE pre-fetched server-side
// from the portal (fetchInlineBanner). We INLINE it (injectInlineBanner) instead
// of a <script src="/__toolbox/loader.js"> tag so a site's SERVICE WORKER has no
// same-origin request to hijack. An empty scriptBody (fetch failed/skipped) makes
// the banner inject a no-op — fail-open, page intact. The cosmetic <style> is
// already inline and SW-immune, so it is UNCHANGED.
func injectHTML(plain []byte, scriptBody string, wg bool, host string) []byte {
	// NOTE (#740): meta-tag Trusted Types stripping was tried here to render the
	// banner on franceinfo/leparisien/20minutes, but rewriting a site's meta CSP
	// regressed pages that depend on it (x/twitter banner vanished). Reverted —
	// strict-TT sites need the banner built via DOM API (createElement/textContent,
	// not innerHTML) so no TT bypass is needed at all. stripMetaTrustedTypes is
	// kept (unused) for reference.
	_ = stripMetaTrustedTypes
	out := injectInlineBanner(plain, scriptBody)
	if wg {
		out = injectCosmetic(out, host)
	}
	return out
}

// injectIntoBody runs the HTML injection (inline banner + R3 cosmetic style) over
// a (possibly compressed) HTML body, returning the new body bytes to serve and
// whether the body was rewritten. scriptBody (#662) is the COMPLETE inline banner
// IIFE pre-fetched from the portal; "" → the banner inject is skipped (fail-open).
//
//   - encoding == "" (identity): injectHTML runs directly on body; the result
//     is returned (ok=true). The caller MUST update Content-Length to len(out).
//   - encoding ∈ {gzip, br, zstd} (case-insensitive): the body is decoded,
//     injected, then RE-ENCODED in the SAME codec so the client transfer stays
//     compressed (the tunnel is perf-sensitive) and Content-Encoding is
//     UNCHANGED. The caller sets Content-Length to len(out). BOTH the banner and
//     the cosmetic style are injected on the decompressed body, so the cosmetic
//     CSS lands on compressed pages too (the common case).
//   - any other encoding (deflate, multi-value, …): pass through untouched,
//     ok=false.
//
// Fail-open: if the decode OR the re-encode fails (corrupt / mislabelled / bomb /
// encoder error), the ORIGINAL bytes are returned with ok=false so the page is
// never broken or corrupted.
//
// The 32MiB decompression-bomb cap (gunzipCap) is enforced uniformly across
// gzip/br/zstd. idempotency / placement live inside injectInlineBanner/injectCosmetic.
func injectIntoBody(body []byte, encoding, scriptBody string, wg bool, host string) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		return injectHTML(body, scriptBody, wg, host), true
	case "gzip":
		plain, err := gunzipBytes(body)
		if err != nil {
			return body, false // fail open: serve the original compressed bytes
		}
		return gzipBytes(injectHTML(plain, scriptBody, wg, host)), true
	case "br":
		plain, err := unbrotliBytes(body)
		if err != nil {
			return body, false // fail open
		}
		reenc, err := brotliBytes(injectHTML(plain, scriptBody, wg, host))
		if err != nil {
			return body, false // fail open: never serve a truncated br frame
		}
		return reenc, true
	case "zstd":
		plain, err := unzstdBytes(body)
		if err != nil {
			return body, false // fail open
		}
		reenc, err := zstdBytes(injectHTML(plain, scriptBody, wg, host))
		if err != nil {
			return body, false // fail open: never serve a truncated zstd frame
		}
		return reenc, true
	default:
		return body, false // unknown encoding we cannot decode → pass through
	}
}
