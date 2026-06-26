// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: httpcodec — gzip/br/zstd codec primitives
//
// Extracted from cmd/sbxmitm so that cmd/sbxwaf (and future consumers) can
// reuse the same compression primitives without importing an internal
// main-package symbol. Behaviour is identical to the original: each codec
// decodes and re-encodes under a 32 MiB decompression-bomb cap (gunzipCap).
//
// Exported surface:
//   - GunzipBytes / GzipBytes
//   - UnbrotliBytes / BrotliBytes
//   - UnzstdBytes / ZstdBytes
//   - Decode(encoding, body) — dispatches on encoding string
//   - Encode(encoding, body) — dispatches on encoding string
//
// encoding ∈ {"", "gzip", "br", "zstd"} (case-insensitive, trimmed).
// "" is the identity passthrough (returns body, nil).
// Unknown encodings return an error.
//
// Dependencies (cgo-free, pure-Go):
//   - compress/gzip                        (stdlib)
//   - github.com/andybalholm/brotli        (br)
//   - github.com/klauspost/compress/zstd   (zstd)
package httpcodec

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// gunzipCap bounds the decompressed output of EVERY codec (gzip/br/zstd) so a
// maliciously-crafted body (a "decompression bomb") cannot blow the worker's
// memory. The upstream body itself is already read under an 8 MiB LimitReader;
// 32 MiB of inflated HTML is a generous ceiling for a single page. Exceeding it →
// treated as an error (caller fails open and serves the original compressed
// bytes). Named gunzipCap for history; applies uniformly to br + zstd too.
const gunzipCap = 32 << 20

// readCapped inflates a decompressing reader with the gunzipCap bomb guard,
// shared by gzip/br/zstd. Reads up to gunzipCap+1 so "exactly at the cap"
// (fine) is distinguished from "over the cap" (bomb → error).
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

// errGunzipTooLarge is returned by GunzipBytes (and the br/zstd equivalents)
// when the decompressed stream exceeds gunzipCap (decompression-bomb guard).
var errGunzipTooLarge = errString("gunzip output exceeds cap")

// errString is a tiny stdlib-only error type (avoids importing errors/fmt for
// one sentinel).
type errString string

func (e errString) Error() string { return string(e) }

// GunzipBytes inflates a gzip-compressed body. It is defensive on two axes:
//   - a malformed/non-gzip input returns an error (caller fails open),
//   - the decompressed output is capped at gunzipCap; if the stream would
//     exceed it, that is reported as an error too (decompression-bomb guard).
func GunzipBytes(in []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return readCapped(zr)
}

// GzipBytes compresses in with the default gzip level. It never errors: the
// gzip.Writer only writes into an in-memory bytes.Buffer, which cannot fail.
func GzipBytes(in []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(in)
	_ = zw.Close()
	return buf.Bytes()
}

// UnbrotliBytes inflates a brotli-compressed body with the gunzipCap bomb guard.
// A malformed/non-brotli input or an over-cap stream returns an error (caller
// fails open). Pure-Go (github.com/andybalholm/brotli — cgo-free).
func UnbrotliBytes(in []byte) ([]byte, error) {
	return readCapped(brotli.NewReader(bytes.NewReader(in)))
}

// BrotliBytes compresses in with brotli at the default quality. It writes into
// an in-memory buffer; Close flushes the final block. The bytes.Buffer cannot
// fail, but brotli.Writer.Write/Close return errors → surfaced so the caller
// fails open rather than serving a truncated stream.
func BrotliBytes(in []byte) ([]byte, error) {
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

// UnzstdBytes inflates a zstd-compressed body with the gunzipCap bomb guard. A
// malformed/non-zstd input or an over-cap stream returns an error (caller fails
// open). Pure-Go (github.com/klauspost/compress/zstd — cgo-free). The decoder is
// created per-call WITHOUT concurrency goroutines (WithDecoderConcurrency(1)) so
// nothing is left running, then Closed.
func UnzstdBytes(in []byte) ([]byte, error) {
	zr, err := zstd.NewReader(bytes.NewReader(in), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return readCapped(zr)
}

// ZstdBytes compresses in with zstd at the default level. The encoder is created
// per-call and Closed (flushing the final frame). Errors are surfaced so the
// caller fails open rather than serving a truncated frame.
func ZstdBytes(in []byte) ([]byte, error) {
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

// Decode decompresses body using the given Content-Encoding.
// encoding is trimmed and lowercased before matching.
// "" is the identity passthrough (returns body, nil).
// Supported: "", "gzip", "br", "zstd".
// Any other encoding returns an error.
func Decode(encoding string, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		return body, nil
	case "gzip":
		return GunzipBytes(body)
	case "br":
		return UnbrotliBytes(body)
	case "zstd":
		return UnzstdBytes(body)
	default:
		return nil, fmt.Errorf("httpcodec: unsupported encoding %q", encoding)
	}
}

// Encode compresses body using the given Content-Encoding.
// encoding is trimmed and lowercased before matching.
// "" is the identity passthrough (returns body, nil).
// Supported: "", "gzip", "br", "zstd".
// Any other encoding returns an error.
func Encode(encoding string, body []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		return body, nil
	case "gzip":
		return GzipBytes(body), nil
	case "br":
		return BrotliBytes(body)
	case "zstd":
		return ZstdBytes(body)
	default:
		return nil, fmt.Errorf("httpcodec: unsupported encoding %q", encoding)
	}
}
