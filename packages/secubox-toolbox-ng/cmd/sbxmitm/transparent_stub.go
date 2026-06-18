// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
//go:build !linux

// SecuBox-Deb :: toolbox-ng :: transparent mode non-linux stub (#662).
//
// SO_ORIGINAL_DST recovery is Netfilter-specific (Linux-only). The real
// transparent accept path lives in transparent.go behind //go:build linux. This
// stub lets the package still compile (and `GOOS=darwin go build ./...`) on
// non-linux: invoking transparent mode there is a hard error, never silently
// degraded. handleTransparent is stubbed too in case it is referenced.
package main

import (
	"log"
	"net"
)

// runTransparent is the non-linux counterpart of the linux accept loop: it
// refuses to start, because transparent SO_ORIGINAL_DST capture requires Linux.
func runTransparent(px *Proxy, addr string) {
	_ = px
	_ = addr
	log.Fatal("transparent mode requires linux (SO_ORIGINAL_DST)")
}

// handleTransparent is a non-linux stub; it can never be reached because
// runTransparent log.Fatals first. Present so any reference still links.
func (px *Proxy) handleTransparent(client net.Conn) {
	_ = client
	log.Fatal("transparent mode requires linux (SO_ORIGINAL_DST)")
}
