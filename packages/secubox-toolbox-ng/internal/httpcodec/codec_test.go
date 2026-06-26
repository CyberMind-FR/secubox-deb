// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: httpcodec — codec tests
package httpcodec

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// TestCodecRoundTrip verifies that Encode then Decode returns the original bytes
// for each supported encoding, and that Decode with an unknown encoding errors.
func TestCodecRoundTrip(t *testing.T) {
	for _, enc := range []string{"gzip", "br", "zstd"} {
		in := []byte("<html>hello</html>")
		comp, err := Encode(enc, in)
		if err != nil {
			t.Fatalf("Encode %s: %v", enc, err)
		}
		out, err := Decode(enc, comp)
		if err != nil || string(out) != string(in) {
			t.Fatalf("%s round-trip: %v %q", enc, err, out)
		}
	}
}

// TestIdentityPassthrough verifies that encoding "" is an identity passthrough
// in both Encode and Decode.
func TestIdentityPassthrough(t *testing.T) {
	in := []byte("hello world")
	out, err := Encode("", in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("Encode identity: %v %q", err, out)
	}
	out, err = Decode("", in)
	if err != nil || string(out) != string(in) {
		t.Fatalf("Decode identity: %v %q", err, out)
	}
}

// TestUnknownEncodingErrors verifies that Decode with an unknown encoding errors.
func TestUnknownEncodingErrors(t *testing.T) {
	b := []byte("whatever")
	_, err := Decode("deflate", b)
	if err == nil {
		t.Fatal("Decode('deflate', b) expected error, got nil")
	}
	_, err = Encode("deflate", b)
	if err == nil {
		t.Fatal("Encode('deflate', b) expected error, got nil")
	}
}

// TestDecompressionBombCap verifies that a >32 MiB inflated body hits the bomb cap.
// We construct a real gzip stream that would expand to >32 MiB.
func TestDecompressionBombCap(t *testing.T) {
	// Build a gzip stream containing 33 MiB of zeroes.
	const size = 33 << 20
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(make([]byte, size))
	_ = zw.Close()
	bomb := buf.Bytes()

	_, err := GunzipBytes(bomb)
	if err == nil {
		t.Fatal("GunzipBytes >32MiB: expected bomb-cap error, got nil")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Fatalf("GunzipBytes >32MiB: expected cap error, got: %v", err)
	}
}
