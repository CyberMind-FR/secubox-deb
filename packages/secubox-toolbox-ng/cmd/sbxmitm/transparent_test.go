// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// Tests for the transparent SO_ORIGINAL_DST sockaddr parser (#662 Phase 6 prep).
//
// Only the PURE parser (parseOrigDst) is unit-tested here: it decodes a raw
// sockaddr byte blob with no syscall, so it is fully covered offline. The real
// getsockopt(SO_ORIGINAL_DST) glue (origDst) cannot be exercised without an nft
// DNAT redirect in the kernel — end-to-end transparent capture is validated at
// Phase 5 shadow on the board, NOT in unit tests (documented in transparent.go).
package main

import (
	"encoding/binary"
	"testing"
)

// mkSockaddrIn4 builds a 16-byte sockaddr_in: family(2 host-order) + port(BE) +
// 4-byte addr + 8 pad. familyLE controls whether the 2 family bytes are written
// little-endian (low byte first, the x86/arm64 host order) or big-endian, so we
// can prove parseOrigDst tolerates both.
func mkSockaddrIn4(family uint16, port uint16, a, b, c, d byte, familyLE bool) []byte {
	buf := make([]byte, 16)
	if familyLE {
		binary.LittleEndian.PutUint16(buf[0:2], family)
	} else {
		binary.BigEndian.PutUint16(buf[0:2], family)
	}
	binary.BigEndian.PutUint16(buf[2:4], port) // port is always network order
	buf[4], buf[5], buf[6], buf[7] = a, b, c, d
	return buf
}

// mkSockaddrIn6 builds a 28-byte sockaddr_in6: family(2) + port(BE) +
// flowinfo(4) + 16-byte addr + scope_id(4).
func mkSockaddrIn6(family uint16, port uint16, addr [16]byte, familyLE bool) []byte {
	buf := make([]byte, 28)
	if familyLE {
		binary.LittleEndian.PutUint16(buf[0:2], family)
	} else {
		binary.BigEndian.PutUint16(buf[0:2], family)
	}
	binary.BigEndian.PutUint16(buf[2:4], port)
	copy(buf[8:24], addr[:])
	return buf
}

func TestParseOrigDstIPv4(t *testing.T) {
	cases := []struct {
		name     string
		raw      []byte
		wantHost string
		wantPort int
	}{
		{"le-family", mkSockaddrIn4(2, 443, 93, 184, 216, 34, true), "93.184.216.34", 443},
		{"be-family", mkSockaddrIn4(2, 8080, 10, 99, 1, 10, false), "10.99.1.10", 8080},
		{"high-port", mkSockaddrIn4(2, 65535, 1, 2, 3, 4, true), "1.2.3.4", 65535},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := parseOrigDst(tc.raw)
			if err != nil {
				t.Fatalf("parseOrigDst: %v", err)
			}
			if host != tc.wantHost || port != tc.wantPort {
				t.Fatalf("parseOrigDst = %q:%d want %q:%d", host, port, tc.wantHost, tc.wantPort)
			}
		})
	}
}

func TestParseOrigDstIPv6(t *testing.T) {
	// 2606:2800:220:1:248:1893:25c8:1946 (example.com-ish), port 443.
	addr := [16]byte{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
		0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}
	for _, le := range []bool{true, false} {
		raw := mkSockaddrIn6(10, 443, addr, le)
		host, port, err := parseOrigDst(raw)
		if err != nil {
			t.Fatalf("parseOrigDst(le=%v): %v", le, err)
		}
		want := "2606:2800:220:1:248:1893:25c8:1946"
		if host != want || port != 443 {
			t.Fatalf("parseOrigDst(le=%v) = %q:%d want %q:443", le, host, port, want)
		}
	}
}

func TestParseOrigDstPortBigEndian(t *testing.T) {
	// Port 0x01BB = 443; assert it is read big-endian (network order), not the
	// host-order 0xBB01 = 47873.
	raw := mkSockaddrIn4(2, 0x01BB, 8, 8, 8, 8, true)
	_, port, err := parseOrigDst(raw)
	if err != nil {
		t.Fatal(err)
	}
	if port != 443 {
		t.Fatalf("port = %d want 443 (big-endian decode)", port)
	}
}

func TestParseOrigDstErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"too-short-v4", make([]byte, 4)},     // family fits but no addr
		{"too-short-v6", mkV6Short()},          // AF_INET6 but < 24 bytes
		{"unknown-family", mkSockaddrIn4(7, 443, 1, 2, 3, 4, true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseOrigDst(tc.raw); err == nil {
				t.Fatalf("parseOrigDst(%s) = nil err, want error", tc.name)
			}
		})
	}
}

// mkV6Short returns an AF_INET6 blob truncated before the 16-byte address.
func mkV6Short() []byte {
	buf := make([]byte, 10) // family + port + flowinfo + 2 bytes of addr
	binary.LittleEndian.PutUint16(buf[0:2], 10)
	binary.BigEndian.PutUint16(buf[2:4], 443)
	return buf
}
