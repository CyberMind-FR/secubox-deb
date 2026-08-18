// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: gzip-aware banner injection tests (#662)
//
// Covers the LIVE bug: the banner only injected into UNCOMPRESSED HTML, so
// gzip pages (the common case — browsers send Accept-Encoding: gzip,br) lost
// the banner. These tests pin the decompress→inject→recompress transform and
// its fail-open behaviour.
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/httpcodec"
)

func TestGzipRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("hello world"),
		[]byte(`<html><head><title>x</title></head><body>hi</body></html>`),
		bytes.Repeat([]byte("AB"), 100000), // larger, compressible payload
	}
	for _, x := range cases {
		got, err := httpcodec.GunzipBytes(httpcodec.GzipBytes(x))
		if err != nil {
			t.Fatalf("GunzipBytes(GzipBytes(%d bytes)) errored: %v", len(x), err)
		}
		if !bytes.Equal(got, x) {
			t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(x))
		}
	}
}

func TestGunzipNonGzipFails(t *testing.T) {
	// Plain bytes that are not a gzip stream → error, no panic.
	if _, err := httpcodec.GunzipBytes([]byte("this is definitely not gzip")); err == nil {
		t.Fatal("GunzipBytes on non-gzip input must error")
	}
}

func TestInjectIntoBodyGzip(t *testing.T) {
	// End-to-end-ish: HTML with <head>, gzipped, run through the exact transform
	// the inject path uses. Result must gunzip back to an injected, intact doc.
	html := `<html><head><title>page</title></head><body>content</body></html>`
	out, ok := injectIntoBody(httpcodec.GzipBytes([]byte(html)), "gzip", inlineTestScript, "", true, "")
	if !ok {
		t.Fatal("gzip inject must report ok=true")
	}
	plain, err := httpcodec.GunzipBytes(out)
	if err != nil {
		t.Fatalf("re-gzipped output must gunzip cleanly: %v", err)
	}
	s := string(plain)
	if !strings.Contains(s, bannerGuard) {
		t.Fatalf("banner guard %q absent after gzip inject:\n%s", bannerGuard, s)
	}
	// Document otherwise intact: original head/body content preserved.
	if !strings.Contains(s, "<title>page</title>") || !strings.Contains(s, "<body>content</body>") {
		t.Fatalf("original document content displaced:\n%s", s)
	}
	// The loader tag landed inside <head>.
	if !strings.Contains(s, `<head><!-- `+bannerGuard) {
		t.Fatalf("loader tag not inserted right after <head>:\n%s", s)
	}
}

func TestInjectIntoBodyGzipCaseInsensitiveEncoding(t *testing.T) {
	html := `<head></head>`
	out, ok := injectIntoBody(httpcodec.GzipBytes([]byte(html)), "GZIP", inlineTestScript, "", false, "")
	if !ok {
		t.Fatal("Content-Encoding GZIP (upper) must be recognised → ok=true")
	}
	plain, err := httpcodec.GunzipBytes(out)
	if err != nil {
		t.Fatalf("gunzip failed: %v", err)
	}
	if !strings.Contains(string(plain), bannerGuard) {
		t.Fatalf("banner absent for upper-case GZIP encoding: %s", plain)
	}
}

func TestInjectIntoBodyGzipFailOpen(t *testing.T) {
	// Bytes labelled gzip but NOT gzip → fail open: original bytes, ok=false,
	// no panic.
	bad := []byte("not gzip at all <head></head>")
	out, ok := injectIntoBody(bad, "gzip", inlineTestScript, "", false, "")
	if ok {
		t.Fatal("corrupt gzip body must fail open (ok=false)")
	}
	if !bytes.Equal(out, bad) {
		t.Fatalf("fail-open must return the ORIGINAL bytes untouched")
	}
}

func TestInjectIntoBodyIdentity(t *testing.T) {
	// Identity (empty Content-Encoding): inject directly, grown body returned.
	html := []byte(`<html><head></head><body>hi</body></html>`)
	out, ok := injectIntoBody(html, "", inlineTestScript, "", false, "")
	if !ok {
		t.Fatal("identity inject must report ok=true")
	}
	if !bytes.Contains(out, []byte(bannerGuard)) {
		t.Fatalf("banner absent on identity inject: %s", out)
	}
	if len(out) <= len(html) {
		t.Fatalf("identity inject must GROW the body: got %d, was %d", len(out), len(html))
	}
}

func TestInjectIntoBodyUnknownEncodingPassthrough(t *testing.T) {
	// #662 — gzip/br/zstd are now ALL decoded+re-encoded; deflate (and any other
	// codec / multi-value AE) remains an unknown encoding we pass through.
	body := []byte("\x78\x9c some deflate-ish bytes")
	out, ok := injectIntoBody(body, "deflate", inlineTestScript, "", false, "")
	if ok {
		t.Fatal("unknown encoding must pass through (ok=false)")
	}
	if !bytes.Equal(out, body) {
		t.Fatalf("unknown-encoding passthrough must be byte-for-byte")
	}
}

func TestGunzipBombGuard(t *testing.T) {
	// A body that inflates beyond gunzipCap must be rejected (not OOM the worker).
	// gzip of >32MiB of zeros compresses to a small blob but inflates past the
	// cap → GunzipBytes returns an error → inject path fails open.
	const bombCap = 32 << 20 // mirrors httpcodec.gunzipCap
	big := httpcodec.GzipBytes(make([]byte, bombCap+1024))
	if _, err := httpcodec.GunzipBytes(big); err == nil {
		t.Fatal("GunzipBytes must reject output exceeding gunzipCap")
	}
	// And via the inject path: fail open, original bytes preserved.
	out, ok := injectIntoBody(big, "gzip", inlineTestScript, "", false, "")
	if ok {
		t.Fatal("over-cap gzip body must fail open through injectIntoBody")
	}
	if !bytes.Equal(out, big) {
		t.Fatal("over-cap fail-open must return the original compressed bytes")
	}
}

func TestGunzipExactlyAtCap(t *testing.T) {
	// A body that inflates to EXACTLY gunzipCap is allowed (boundary).
	const bombCap = 32 << 20 // mirrors httpcodec.gunzipCap
	payload := make([]byte, bombCap)
	got, err := httpcodec.GunzipBytes(httpcodec.GzipBytes(payload))
	if err != nil {
		t.Fatalf("exactly-at-cap payload must be allowed: %v", err)
	}
	if len(got) != bombCap {
		t.Fatalf("at-cap length mismatch: got %d, want %d", len(got), bombCap)
	}
}
