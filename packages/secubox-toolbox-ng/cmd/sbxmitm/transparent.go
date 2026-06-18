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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
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

// handleTransparent serves one transparently-redirected client connection:
// recover the original destination, terminate TLS with a forged-by-SNI leaf,
// then either splice raw TCP to the ORIGINAL dst (passthrough) or run the shared
// MITM pipeline dialling that original dst (NOT the SNI).
func (px *Proxy) handleTransparent(client net.Conn) {
	defer client.Close()

	tcp, ok := client.(*net.TCPConn)
	if !ok {
		return // transparent mode only accepts raw TCP conns
	}
	dstHost, dstPort, err := origDst(tcp)
	if err != nil {
		return // no original-dst (not DNAT'd) → drop; nothing safe to do
	}
	dialAddr := net.JoinHostPort(dstHost, fmt.Sprintf("%d", dstPort))

	// TLS-terminate to read the real ClientHello SNI for the decision. The
	// forged leaf is minted by SNI in serverTLSConfig's GetCertificate.
	tconn := tls.Server(client, px.serverTLSConfig())
	if err := tconn.Handshake(); err != nil {
		return
	}
	defer tconn.Close()
	sni := tconn.ConnectionState().ServerName
	decisionHost := sni
	if decisionHost == "" {
		decisionHost = dstHost // no SNI → fall back to the captured dst IP
	}

	verdict := px.pol.Decide(decisionHost, sni)

	if verdict == "splice" {
		// Passthrough: raw TCP to the REAL captured destination, never the SNI.
		// (We have already consumed the ClientHello terminating TLS, so a true
		// byte-splice would need the raw ClientHello preserved — the live engine
		// peeks before terminating; this DARK path documents the dial target.)
		up, derr := net.Dial("tcp", dialAddr)
		if derr != nil {
			return
		}
		defer up.Close()
		go func() { _, _ = io.Copy(up, tconn) }()
		_, _ = io.Copy(tconn, up)
		return
	}

	// allow / mitm / block → shared pipeline, dialling the captured original-dst.
	px.mitmPipeline(tconn, client, decisionHost, verdict, dialAddr)
}
