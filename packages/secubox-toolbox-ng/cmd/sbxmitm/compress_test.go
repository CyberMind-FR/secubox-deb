// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: br + zstd inject round-trip tests (#662)
//
// Since #662 stopped downgrading Accept-Encoding, upstream responses can come
// back br or zstd. These tests pin: codec round-trip (decode(encode(x))==x), an
// HTML doc encoded br/zstd → injectIntoBody → decode → guard present + intact,
// fail-open on corrupt-labelled bytes, the bomb cap applies, and the encoding
// stays the SAME across the inject.
package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// TestAcceptEncodingPreserved pins the #662 behaviour change: the request
// mutation the pipeline performs (anonymizeRequest — the only header mutation
// before the upstream RoundTrip) must NOT add, remove, or rewrite
// Accept-Encoding. A client's real AE (`gzip, deflate, br, zstd`) must reach the
// origin verbatim, and a request without AE must stay without one. The old
// `req.Header.Set("Accept-Encoding","gzip")` override is gone.
func TestAcceptEncodingPreserved(t *testing.T) {
	// Client sent a real browser AE → it survives untouched.
	h := http.Header{}
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	anonymizeRequest(h)
	if got := h.Get("Accept-Encoding"); got != "gzip, deflate, br, zstd" {
		t.Fatalf("client Accept-Encoding must pass through verbatim, got %q", got)
	}

	// Client sent NO AE → none is added (adding one is itself a bot tell).
	h2 := http.Header{}
	anonymizeRequest(h2)
	if _, ok := h2["Accept-Encoding"]; ok {
		t.Fatalf("no Accept-Encoding must be injected when the client sent none, got %q", h2.Get("Accept-Encoding"))
	}
}

func TestBrotliRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("hello world"),
		[]byte(`<html><head><title>x</title></head><body>hi</body></html>`),
		bytes.Repeat([]byte("AB"), 100000),
	}
	for _, x := range cases {
		enc, err := brotliBytes(x)
		if err != nil {
			t.Fatalf("brotliBytes(%d): %v", len(x), err)
		}
		got, err := unbrotliBytes(enc)
		if err != nil {
			t.Fatalf("unbrotliBytes(%d): %v", len(x), err)
		}
		if !bytes.Equal(got, x) {
			t.Fatalf("brotli round-trip mismatch: got %d want %d", len(got), len(x))
		}
	}
}

func TestZstdRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(""),
		[]byte("hello world"),
		[]byte(`<html><head><title>x</title></head><body>hi</body></html>`),
		bytes.Repeat([]byte("AB"), 100000),
	}
	for _, x := range cases {
		enc, err := zstdBytes(x)
		if err != nil {
			t.Fatalf("zstdBytes(%d): %v", len(x), err)
		}
		got, err := unzstdBytes(enc)
		if err != nil {
			t.Fatalf("unzstdBytes(%d): %v", len(x), err)
		}
		if !bytes.Equal(got, x) {
			t.Fatalf("zstd round-trip mismatch: got %d want %d", len(got), len(x))
		}
	}
}

func TestInjectIntoBodyBrotli(t *testing.T) {
	html := `<html><head><title>page</title></head><body>content</body></html>`
	enc, err := brotliBytes([]byte(html))
	if err != nil {
		t.Fatal(err)
	}
	out, ok := injectIntoBody(enc, "br", inlineTestScript, true, "")
	if !ok {
		t.Fatal("br inject must report ok=true")
	}
	plain, err := unbrotliBytes(out)
	if err != nil {
		t.Fatalf("re-brotli'd output must decode cleanly (encoding stays br): %v", err)
	}
	s := string(plain)
	if !strings.Contains(s, bannerGuard) {
		t.Fatalf("banner guard absent after br inject:\n%s", s)
	}
	if !strings.Contains(s, "<title>page</title>") || !strings.Contains(s, "<body>content</body>") {
		t.Fatalf("original document content displaced:\n%s", s)
	}
}

func TestInjectIntoBodyZstd(t *testing.T) {
	html := `<html><head><title>page</title></head><body>content</body></html>`
	enc, err := zstdBytes([]byte(html))
	if err != nil {
		t.Fatal(err)
	}
	out, ok := injectIntoBody(enc, "zstd", inlineTestScript, true, "")
	if !ok {
		t.Fatal("zstd inject must report ok=true")
	}
	plain, err := unzstdBytes(out)
	if err != nil {
		t.Fatalf("re-zstd'd output must decode cleanly (encoding stays zstd): %v", err)
	}
	s := string(plain)
	if !strings.Contains(s, bannerGuard) {
		t.Fatalf("banner guard absent after zstd inject:\n%s", s)
	}
	if !strings.Contains(s, "<title>page</title>") || !strings.Contains(s, "<body>content</body>") {
		t.Fatalf("original document content displaced:\n%s", s)
	}
}

func TestInjectIntoBodyBrotliCaseInsensitive(t *testing.T) {
	enc, _ := brotliBytes([]byte(`<head></head>`))
	out, ok := injectIntoBody(enc, "BR", inlineTestScript, false, "")
	if !ok {
		t.Fatal("Content-Encoding BR (upper) must be recognised → ok=true")
	}
	plain, err := unbrotliBytes(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), bannerGuard) {
		t.Fatalf("banner absent for upper-case BR: %s", plain)
	}
}

func TestInjectIntoBodyBrotliFailOpen(t *testing.T) {
	bad := []byte("not brotli at all <head></head>")
	out, ok := injectIntoBody(bad, "br", inlineTestScript, false, "")
	if ok {
		t.Fatal("corrupt br body must fail open (ok=false)")
	}
	if !bytes.Equal(out, bad) {
		t.Fatal("br fail-open must return the ORIGINAL bytes untouched")
	}
}

func TestInjectIntoBodyZstdFailOpen(t *testing.T) {
	bad := []byte("not zstd at all <head></head>")
	out, ok := injectIntoBody(bad, "zstd", inlineTestScript, false, "")
	if ok {
		t.Fatal("corrupt zstd body must fail open (ok=false)")
	}
	if !bytes.Equal(out, bad) {
		t.Fatal("zstd fail-open must return the ORIGINAL bytes untouched")
	}
}

func TestBrotliZstdBombGuard(t *testing.T) {
	zeros := make([]byte, gunzipCap+4096)
	brBomb, err := brotliBytes(zeros)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbrotliBytes(brBomb); err == nil {
		t.Fatal("unbrotliBytes must reject output exceeding gunzipCap")
	}
	// fail-open through the inject path.
	if out, ok := injectIntoBody(brBomb, "br", inlineTestScript, false, ""); ok || !bytes.Equal(out, brBomb) {
		t.Fatal("over-cap br body must fail open with original bytes")
	}

	zsBomb, err := zstdBytes(zeros)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unzstdBytes(zsBomb); err == nil {
		t.Fatal("unzstdBytes must reject output exceeding gunzipCap")
	}
	if out, ok := injectIntoBody(zsBomb, "zstd", inlineTestScript, false, ""); ok || !bytes.Equal(out, zsBomb) {
		t.Fatal("over-cap zstd body must fail open with original bytes")
	}
}
