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
// Codec primitives (GunzipBytes / GzipBytes / UnbrotliBytes / BrotliBytes /
// UnzstdBytes / ZstdBytes) live in internal/httpcodec so that cmd/sbxwaf can
// reuse them. This file only contains the sbxmitm-specific inject logic.
//
// Dependencies (cgo-free, pure-Go):
//   - compress/gzip                        (stdlib)
//   - github.com/andybalholm/brotli        (br)
//   - github.com/klauspost/compress/zstd   (zstd)
package main

import (
	"strings"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/httpcodec"
)

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
func injectHTML(plain []byte, scriptBody, nonce string, wg bool) []byte {
	out := injectInlineBanner(plain, scriptBody, nonce)
	if wg {
		out = injectCosmetic(out)
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
// The 32 MiB decompression-bomb cap (gunzipCap) is enforced uniformly across
// gzip/br/zstd inside internal/httpcodec. idempotency / placement live inside
// injectInlineBanner/injectCosmetic.
func injectIntoBody(body []byte, encoding, scriptBody, nonce string, wg bool) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "":
		return injectHTML(body, scriptBody, nonce, wg), true
	case "gzip":
		plain, err := httpcodec.GunzipBytes(body)
		if err != nil {
			return body, false // fail open: serve the original compressed bytes
		}
		return httpcodec.GzipBytes(injectHTML(plain, scriptBody, nonce, wg)), true
	case "br":
		plain, err := httpcodec.UnbrotliBytes(body)
		if err != nil {
			return body, false // fail open
		}
		reenc, err := httpcodec.BrotliBytes(injectHTML(plain, scriptBody, nonce, wg))
		if err != nil {
			return body, false // fail open: never serve a truncated br frame
		}
		return reenc, true
	case "zstd":
		plain, err := httpcodec.UnzstdBytes(body)
		if err != nil {
			return body, false // fail open
		}
		reenc, err := httpcodec.ZstdBytes(injectHTML(plain, scriptBody, nonce, wg))
		if err != nil {
			return body, false // fail open: never serve a truncated zstd frame
		}
		return reenc, true
	default:
		return body, false // unknown encoding we cannot decode → pass through
	}
}
