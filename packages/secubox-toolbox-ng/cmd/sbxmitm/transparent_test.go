// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
//go:build linux

// Tests for the transparent SO_ORIGINAL_DST sockaddr parser (#662 Phase 6 prep).
//
// Only the PURE parser (parseOrigDst) is unit-tested here: it decodes a raw
// sockaddr byte blob with no syscall, so it is fully covered offline. The real
// getsockopt(SO_ORIGINAL_DST) glue (origDst) cannot be exercised without an nft
// DNAT redirect in the kernel — end-to-end transparent capture is validated at
// Phase 5 shadow on the board, NOT in unit tests (documented in transparent.go).
package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
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
		{"unknown-family-4", make([]byte, 4)}, // all-zero family=0 → unknown-family branch
		{"too-short-v4", mkV4Short()},         // valid AF_INET family but 4≤len<8 → sockaddr_in <8 guard
		{"too-short-v6", mkV6Short()},         // AF_INET6 but < 24 bytes
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

// mkV4Short returns a blob with a valid AF_INET family byte but a total length
// in [4,8): it passes the >=4 length check and matches the AF_INET case, so it
// exercises parseOrigDst's sockaddr_in `<8` guard (not the unknown-family path).
func mkV4Short() []byte {
	buf := make([]byte, 6)                     // family(2) + port(2) but no full 4-byte address
	binary.LittleEndian.PutUint16(buf[0:2], 2) // AF_INET
	binary.BigEndian.PutUint16(buf[2:4], 443)
	return buf
}

// ── sniFromClientHello ───────────────────────────────────────────────────────

// mkClientHello hand-assembles a minimal but structurally-valid TLS
// ClientHello record. If withSNI is true a server_name extension carrying
// `sni` (a single host_name entry) is appended; otherwise NO extensions are
// emitted (extensions length 0).
//
// Record layout assembled here (see sniFromClientHello for the parser):
//
//	record header : type=0x16 (handshake) | version 0x0303 | record_len(2)
//	handshake     : type=0x01 (ClientHello) | hs_len(3)
//	body          : client_version 0x0303 | random(32) |
//	                session_id_len=0 |
//	                cipher_suites_len(2)=2 | cipher 0x002f |
//	                compression_len=1 | method 0x00 |
//	                extensions_len(2) | [ server_name ext ]
//	server_name   : ext_type 0x0000 | ext_len(2) |
//	                list_len(2) | name_type 0x00 | name_len(2) | host bytes
func mkClientHello(sni string, withSNI bool) []byte {
	body := []byte{0x03, 0x03}               // client_version TLS1.2
	body = append(body, make([]byte, 32)...) // random (zeros)
	body = append(body, 0x00)                // session_id_len = 0
	// cipher_suites: length 2, one suite TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	body = append(body, 0x00, 0x02, 0x00, 0x2f)
	// compression_methods: length 1, method null (0x00)
	body = append(body, 0x01, 0x00)

	var exts []byte
	if withSNI {
		host := []byte(sni)
		var sn []byte
		sn = append(sn, 0x00)                                // name_type = host_name
		sn = append(sn, byte(len(host)>>8), byte(len(host))) // name_len(2)
		sn = append(sn, host...)
		var list []byte
		list = append(list, byte(len(sn)>>8), byte(len(sn))) // server_name_list len(2)
		list = append(list, sn...)
		exts = append(exts, 0x00, 0x00)                          // ext_type = server_name
		exts = append(exts, byte(len(list)>>8), byte(len(list))) // ext_len(2)
		exts = append(exts, list...)
	}
	body = append(body, byte(len(exts)>>8), byte(len(exts))) // extensions_len(2)
	body = append(body, exts...)

	// handshake header: type 0x01 + 3-byte length
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// record header: type 0x16 + version 0x0303 + 2-byte length
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestSNIFromClientHello(t *testing.T) {
	// Sanity: the hand-assembled blob parses with our own parser.
	good := mkClientHello("example.com", true)
	if sni, ok := sniFromClientHello(good); !ok || sni != "example.com" {
		t.Fatalf("sniFromClientHello(valid) = %q,%v want example.com,true", sni, ok)
	}

	cases := []struct {
		name    string
		rec     []byte
		wantSNI string
		wantOK  bool
	}{
		{"with-sni", mkClientHello("secubox.in", true), "secubox.in", true},
		{"no-sni-ext", mkClientHello("", false), "", false},
		{"nil", nil, "", false},
		{"empty", []byte{}, "", false},
		{"non-handshake-record", []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}, "", false},
		{"truncated-header", []byte{0x16, 0x03}, "", false},
		// valid record header claiming length 100 but body truncated.
		{"truncated-body", []byte{0x16, 0x03, 0x03, 0x00, 0x64, 0x01, 0x00, 0x00}, "", false},
		// truncate a known-good blob mid-extensions.
		{"truncated-good", good[:len(good)-3], "", false},
		{"not-clienthello-hs", func() []byte {
			b := mkClientHello("x.example", true)
			b[5] = 0x02 // handshake type ServerHello, not ClientHello
			return b
		}(), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sni, ok := sniFromClientHello(tc.rec)
			if ok != tc.wantOK || sni != tc.wantSNI {
				t.Fatalf("sniFromClientHello = %q,%v want %q,%v", sni, ok, tc.wantSNI, tc.wantOK)
			}
		})
	}
}

func TestSNIFromClientHelloNoPanic(t *testing.T) {
	// Fuzz-ish: every truncation of a valid blob must return cleanly, never panic.
	good := mkClientHello("example.com", true)
	for i := 0; i <= len(good); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on good[:%d]: %v", i, r)
				}
			}()
			_, _ = sniFromClientHello(good[:i])
		}()
	}
}

// ── prefixConn (replayable client conn) ──────────────────────────────────────

// fakeConn adapts an io.ReadWriteCloser to net.Conn for prefixConn tests.
type fakeConn struct{ io.ReadWriteCloser }

func (fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type rwc struct {
	*bytes.Reader
	w *bytes.Buffer
}

func (r rwc) Write(p []byte) (int, error) { return r.w.Write(p) }
func (rwc) Close() error                  { return nil }

func TestPrefixConnReplaysBufferedThenLive(t *testing.T) {
	live := bytes.NewReader([]byte("LIVE-DATA"))
	wbuf := &bytes.Buffer{}
	underlying := fakeConn{rwc{Reader: live, w: wbuf}}

	pc := &prefixConn{prefix: []byte("PEEKED"), Conn: underlying}

	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "PEEKEDLIVE-DATA" {
		t.Fatalf("prefixConn read = %q want PEEKEDLIVE-DATA", got)
	}
	// Writes delegate straight through to the underlying conn.
	if _, err := pc.Write([]byte("OUT")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if wbuf.String() != "OUT" {
		t.Fatalf("underlying write = %q want OUT", wbuf.String())
	}
}

func TestPrefixConnEmptyPrefix(t *testing.T) {
	live := bytes.NewReader([]byte("ONLY-LIVE"))
	underlying := fakeConn{rwc{Reader: live, w: &bytes.Buffer{}}}
	pc := &prefixConn{Conn: underlying}
	got, _ := io.ReadAll(pc)
	if string(got) != "ONLY-LIVE" {
		t.Fatalf("prefixConn read = %q want ONLY-LIVE", got)
	}
}
