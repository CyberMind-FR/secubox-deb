// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
//go:build linux

// SecuBox-Deb :: toolbox-ng :: transparent SO_ORIGINAL_DST accept path
// (#662 Phase 6 prep)
//
// The live R3 engine runs transparent: nft DNAT redirects the client's TCP SYN
// to this worker, which recovers the ORIGINAL destination via
// getsockopt(SOL_IP, SO_ORIGINAL_DST) (IPv4) or
// getsockopt(SOL_IPV6, IP6T_SO_ORIGINAL_DST=80) (IPv6). This is a SECOND listen
// mode behind --transparent; the CONNECT PoC (main.go handleConnect) is left
// EXACTLY as-is.
//
// This is DARK — never wired to live traffic yet. The pure parser (parseOrigDst)
// is unit-tested; the syscall glue (origDst) and end-to-end transparent capture
// can only be exercised behind a real nft DNAT redirect, validated at Phase 5
// shadow on the board, NOT in unit tests.
//
// Pure standard library — syscall + net + crypto/tls; no external modules.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
	"unsafe"
)

// SO_ORIGINAL_DST is the Netfilter getsockopt that returns the pre-DNAT
// destination sockaddr. Same value (80) for IPv4 (SOL_IP) and IPv6
// (SOL_IPV6, where it is named IP6T_SO_ORIGINAL_DST).
const soOriginalDst = 80

// parseOrigDst decodes a raw sockaddr blob (as returned by getsockopt
// SO_ORIGINAL_DST) into host + port. It is PURE — no syscall — so it is fully
// unit-testable offline.
//
// IPv4 sockaddr_in (16 bytes): [0:2]=family (AF_INET=2, host byte order),
// [2:4]=port (BIG-endian / network order), [4:8]=4-byte address.
// IPv6 sockaddr_in6 (≥24 bytes): [0:2]=family (AF_INET6=10), [2:4]=port (BE),
// [4:8]=flowinfo, [8:24]=16-byte address.
//
// The family field is host byte order in the kernel; on x86/arm64 (little-end)
// AF_INET=2 lands in the low byte. We accept the family if EITHER the LE or BE
// 16-bit read matches the expected constant, so the parser is endianness-robust
// across architectures.
func parseOrigDst(raw []byte) (host string, port int, err error) {
	if len(raw) < 4 {
		return "", 0, fmt.Errorf("sockaddr too short: %d bytes", len(raw))
	}
	famLE := binary.LittleEndian.Uint16(raw[0:2])
	famBE := binary.BigEndian.Uint16(raw[0:2])
	p := int(binary.BigEndian.Uint16(raw[2:4])) // port is network order

	switch {
	case famLE == syscall.AF_INET || famBE == syscall.AF_INET:
		if len(raw) < 8 {
			return "", 0, fmt.Errorf("sockaddr_in too short: %d bytes", len(raw))
		}
		ip := net.IPv4(raw[4], raw[5], raw[6], raw[7])
		return ip.String(), p, nil
	case famLE == syscall.AF_INET6 || famBE == syscall.AF_INET6:
		if len(raw) < 24 {
			return "", 0, fmt.Errorf("sockaddr_in6 too short: %d bytes", len(raw))
		}
		ip := make(net.IP, 16)
		copy(ip, raw[8:24])
		return ip.String(), p, nil
	default:
		return "", 0, fmt.Errorf("unknown sockaddr family: LE=%d BE=%d", famLE, famBE)
	}
}

// origDst recovers the pre-DNAT original destination of a transparently
// redirected TCP connection via getsockopt(SO_ORIGINAL_DST). v4 vs v6 is chosen
// by the local address family. stdlib-only (syscall.Syscall6 on the raw fd via
// SyscallConn). Linux-only by build tag.
func origDst(conn *net.TCPConn) (host string, port int, err error) {
	level := syscall.SOL_IP
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok && la.IP.To4() == nil && la.IP != nil {
		level = syscall.SOL_IPV6
	}
	rc, err := conn.SyscallConn()
	if err != nil {
		return "", 0, err
	}
	// A sockaddr_in6 is 28 bytes; size the buffer for the larger of the two.
	buf := make([]byte, 28)
	size := uint32(len(buf))
	var goErr error
	ctrlErr := rc.Control(func(fd uintptr) {
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(level),
			uintptr(soOriginalDst),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			goErr = errno
		}
	})
	if ctrlErr != nil {
		return "", 0, ctrlErr
	}
	if goErr != nil {
		return "", 0, goErr
	}
	return parseOrigDst(buf[:size])
}

// ── ClientHello SNI peek (no decryption) ─────────────────────────────────────

// recordingReader tees every byte it reads off the underlying reader into an
// in-memory buffer, so the exact bytes consumed during the ClientHello peek can
// be re-fed to either the upstream (splice) or a tls.Server (mitm/allow/block).
type recordingReader struct {
	r   io.Reader
	buf bytes.Buffer
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		rr.buf.Write(p[:n])
	}
	return n, err
}

// prefixConn is a net.Conn whose Read drains an internal prefix buffer (the
// bytes already peeked off the wire) before delegating to the underlying conn;
// every other net.Conn method delegates straight through. This re-presents the
// recorded ClientHello bytes to a tls.Server / upstream that must see the
// original handshake.
type prefixConn struct {
	prefix []byte
	off    int
	net.Conn
}

func (pc *prefixConn) Read(p []byte) (int, error) {
	if pc.off < len(pc.prefix) {
		n := copy(p, pc.prefix[pc.off:])
		pc.off += n
		return n, nil
	}
	return pc.Conn.Read(p)
}

// peekClientHello reads exactly the first TLS record (the ClientHello) off conn
// WITHOUT consuming it from the caller's perspective: the bytes are recorded so
// they can be replayed. It returns the recorded record bytes (the full set of
// bytes read off the wire, which equals the first TLS record) for replay.
func peekClientHello(conn net.Conn) (record []byte, err error) {
	rr := &recordingReader{r: conn}
	// TLS record header: type(1) + version(2) + length(2).
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(rr, hdr); err != nil {
		return rr.buf.Bytes(), err
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	// Sanity cap: a ClientHello must fit in a single record (max 16KiB payload).
	if recLen < 0 || recLen > (1<<14) {
		return rr.buf.Bytes(), fmt.Errorf("clienthello record length out of range: %d", recLen)
	}
	if _, err := io.ReadFull(rr, make([]byte, recLen)); err != nil {
		return rr.buf.Bytes(), err
	}
	return rr.buf.Bytes(), nil
}

// sniFromClientHello extracts the SNI host_name from a raw TLS ClientHello
// record. It is PURE (no I/O) and defensive: every slice is bounds-checked and
// any malformed/short input or absent SNI returns ("", false) — it never panics.
//
// Record framing parsed here:
//
//	record header  : type=0x16 (handshake) | version(2) | length(2)
//	handshake hdr  : type=0x01 (ClientHello) | length(3)
//	body           : client_version(2) | random(32) |
//	                 session_id_len(1) + session_id |
//	                 cipher_suites_len(2) + cipher_suites |
//	                 compression_len(1) + compression_methods |
//	                 extensions_len(2) + extensions
//	extension      : ext_type(2) | ext_len(2) + ext_data
//	server_name    : list_len(2) | name_type(1)=0 | name_len(2) + host
func sniFromClientHello(record []byte) (string, bool) {
	// record header (5) — type 0x16 handshake.
	if len(record) < 5 || record[0] != 0x16 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(record[3:5]))
	body := record[5:]
	if len(body) < recLen {
		return "", false
	}
	body = body[:recLen]

	// handshake header (4) — type 0x01 ClientHello + 3-byte length.
	if len(body) < 4 || body[0] != 0x01 {
		return "", false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hs := body[4:]
	if len(hs) < hsLen {
		return "", false
	}
	hs = hs[:hsLen]

	// client_version(2) + random(32).
	if len(hs) < 34 {
		return "", false
	}
	p := hs[34:]

	// session_id: len(1) + data.
	if len(p) < 1 {
		return "", false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return "", false
	}
	p = p[sidLen:]

	// cipher_suites: len(2) + data.
	if len(p) < 2 {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < csLen {
		return "", false
	}
	p = p[csLen:]

	// compression_methods: len(1) + data.
	if len(p) < 1 {
		return "", false
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", false
	}
	p = p[cmLen:]

	// extensions: len(2) + entries.
	if len(p) < 2 {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extLen {
		return "", false
	}
	ext := p[:extLen]

	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if len(ext) < elen {
			return "", false
		}
		data := ext[:elen]
		ext = ext[elen:]
		if etype != 0x0000 { // server_name
			continue
		}
		// server_name_list: list_len(2) + entries.
		if len(data) < 2 {
			return "", false
		}
		listLen := int(binary.BigEndian.Uint16(data[0:2]))
		list := data[2:]
		if len(list) < listLen {
			return "", false
		}
		list = list[:listLen]
		// First entry: name_type(1) + name_len(2) + host.
		if len(list) < 3 {
			return "", false
		}
		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if nameType != 0x00 || len(list) < nameLen { // 0 = host_name
			return "", false
		}
		return string(list[:nameLen]), true
	}
	return "", false
}

// ── transparent accept path ──────────────────────────────────────────────────

// runTransparent runs the transparent (SO_ORIGINAL_DST) accept loop: listen on
// addr, and for each nft-DNAT'd connection recover its pre-DNAT destination and
// dispatch to handleTransparent. Linux-only (build-tagged).
func runTransparent(px *Proxy, addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("transparent listen: %v", err)
	}
	log.Printf("sbxmitm TRANSPARENT listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go px.handleTransparent(conn)
	}
}

// handleTransparent serves one transparently-redirected client connection:
//  1. recover the pre-DNAT original destination via SO_ORIGINAL_DST,
//  2. PEEK the ClientHello off the raw conn without consuming it,
//  3. parse the SNI and Decide WITHOUT decrypting,
//  4. splice  → raw TCP passthrough to the ORIGINAL dst, replaying the peeked
//     ClientHello first; NEVER terminate TLS (cert-pinned/own-infra safe),
//  5. allow/mitm/block → NOW tls.Server over the replayable conn (so the TLS
//     server still sees the original ClientHello) and run the shared pipeline.
func (px *Proxy) handleTransparent(client net.Conn) {
	defer client.Close()

	tcp, ok := client.(*net.TCPConn)
	if !ok {
		return // transparent mode only accepts raw TCP conns
	}
	// R3 WG client? The data-wg attribute of the injected loader mirrors the
	// Python _loader_script (ip.startswith("10.99.1.")) — derived from the same
	// client conn peer IP that feeds clientHashFromConn.
	wg := false
	if peer, _, perr := net.SplitHostPort(client.RemoteAddr().String()); perr == nil {
		wg = strings.HasPrefix(peer, "10.99.1.")
	}
	dstHost, dstPort, err := origDst(tcp)
	if err != nil {
		return // no original-dst (not DNAT'd) → drop; nothing safe to do
	}
	dialAddr := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	// Peek the ClientHello WITHOUT decrypting. The recorded bytes are replayed
	// to whatever we hand the conn to next (upstream for splice, tls.Server
	// otherwise) so the original handshake is preserved byte-for-byte.
	hello, perr := peekClientHello(client)
	if perr != nil {
		return // could not read a ClientHello → nothing safe to do
	}
	sni, _ := sniFromClientHello(hello)
	decisionHost := sni
	if decisionHost == "" {
		decisionHost = dstHost // no SNI → fall back to the captured dst IP
	}

	// Clamped to the calling peer's R-level (#rlevel-per-peer) via the SAME
	// helper handleConnect uses, so the two accept paths never drift.
	verdict := px.decideForPeer(peerIP(client), decisionHost, sni)

	if verdict == "splice" {
		// Passthrough: raw TCP to the REAL captured destination, never the SNI,
		// NEVER terminating TLS. Replay the peeked ClientHello to the upstream
		// first, then pipe raw bytes both directions over the raw client conn.
		up, derr := net.Dial("tcp", dialAddr)
		if derr != nil {
			return
		}
		defer up.Close()
		if _, werr := up.Write(hello); werr != nil {
			return
		}
		go func() { _, _ = io.Copy(up, client) }()
		_, _ = io.Copy(client, up)
		return
	}

	// allow / mitm / block → re-present the peeked ClientHello to a tls.Server
	// over a replayable conn, then run the shared pipeline dialling the captured
	// original-dst (NOT the SNI).
	replay := &prefixConn{prefix: hello, Conn: client}
	// The capture hook relays the ja4 ClientHello payload for this handshake,
	// tagged with the REAL transparent peer IP from the raw client conn (#662).
	// nil when the relay gate is off. Emitted around Decide → blocked/allowed
	// alike, matching the Python addon's per-tls_clienthello behaviour.
	var ja4 string // SNI-independent client-stack fp, captured at handshake below
	tconn := tls.Server(replay, px.serverTLSConfigCapture(px.captureAndEmitJA4(client),
		func(s string) { ja4 = s }))
	if err := tconn.Handshake(); err != nil {
		return
	}
	defer tconn.Close()
	px.mitmPipeline(tconn, client, decisionHost, verdict, dialAddr, wg, ja4)
}
