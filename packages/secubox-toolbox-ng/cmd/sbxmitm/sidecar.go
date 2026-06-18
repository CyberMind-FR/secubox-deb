// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sidecar emit helper (#662 Phase 4)
//
// Fire-and-forget POST to a unix-socket'd SecuBox module, mirroring the Python
// addons' _common.fire_forget_post: it NEVER blocks the proxy flow and NEVER
// raises into the caller. The live engine will relay extracted signals to the
// existing module sockets; this is the transport only — NOT yet wired into the
// live request/response path (Phase 5+ wiring).
//
// Addon → socket mapping the live engine will use (verbatim from the Python
// addons' TARGET constants, packages/secubox-toolbox/mitmproxy_addons/*.py):
//
//	addon         socket path                       route
//	cookies   →   /run/secubox/cookies.sock         POST /inject
//	dpi       →   /run/secubox/dpi.sock             POST /classify
//	avatar    →   /run/secubox/avatar.sock          POST /fingerprint
//	ja4       →   /run/secubox/threat-analyst.sock  POST /ja4
//	soc_relay →   /run/secubox/soc.sock             POST /event
//	social_graph: in-process (no socket) — correlated inside the engine, not emitted.
//
// emit takes the full socket PATH (not an http+unix:// URL) plus the route in
// the payload's destination; callers build the path from the table above.
//
// Pure standard library — no external modules, no go.sum.
package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// emitTimeout caps the whole connect+write+read so a slow/dead module socket
// can never wedge the engine. Mirrors the Python httpx timeout=2.
const emitTimeout = 2 * time.Second

// emit fires a fire-and-forget POST of payload to the given unix socket at
// route, in a detached goroutine. It returns immediately and never blocks the
// caller; all errors (missing socket, dead peer, timeout) are swallowed —
// dropping a relayed signal must never break a client flow. Mirrors
// _common.fire_forget_post + queue_async (create_task, never raise).
//
// route is the HTTP path on the module (e.g. "/inject", "/classify"); use the
// addon→socket table above to pick socketPath + route together.
func emit(socketPath, route string, payload []byte) {
	go emitSync(socketPath, route, payload)
}

// emitSync performs the actual POST synchronously (under emitTimeout). Exposed
// (lowercase, same-package) so tests can observe delivery deterministically
// without racing the goroutine. Returns an error only for the test's benefit;
// emit() discards it.
func emitSync(socketPath, route string, payload []byte) error {
	if route == "" {
		route = "/"
	}
	ctx, cancel := context.WithTimeout(context.Background(), emitTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return err // dead/missing socket — swallowed by emit()
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	// Minimal HTTP/1.1 POST. Host is a placeholder (unix transport); the module
	// FastAPI apps ignore it. Connection: close so the peer EOFs after replying.
	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: secubox.local\r\nContent-Type: application/json\r\n"+
			"Content-Length: %d\r\nConnection: close\r\n\r\n",
		route, len(payload))
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	// Best-effort drain so the peer sees a clean close; we don't parse the
	// response (fire-and-forget). Errors here are irrelevant.
	buf := make([]byte, 512)
	_, _ = conn.Read(buf)
	return nil
}
