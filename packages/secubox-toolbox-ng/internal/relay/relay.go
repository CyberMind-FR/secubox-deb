// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: internal/relay — unix-socket POST transport
//
// Extracted from cmd/sbxmitm/sidecar.go so that cmd/sbxwaf can reuse the same
// fire-and-forget unix-socket POST helper. Behaviour is identical to the
// original: a detached-goroutine Emit that NEVER blocks, and a synchronous
// EmitSync for test-observable delivery.
//
// Addon → socket mapping (for reference; callers supply the paths):
//
//	addon         socket path                       route
//	cookies   →   /run/secubox/cookies.sock         POST /inject
//	dpi       →   /run/secubox/dpi.sock             POST /classify
//	avatar    →   /run/secubox/avatar.sock          POST /fingerprint
//	ja4       →   /run/secubox/threat-analyst.sock  POST /ja4
//	soc_relay →   /run/secubox/soc.sock             POST /event
//
// Pure standard library — no external modules, no go.sum entries added.
package relay

import (
	"context"
	"fmt"
	"net"
	"time"
)

// EmitTimeout caps the whole connect+write+read so a slow/dead module socket
// can never wedge the engine. Mirrors the Python httpx timeout=2.
const EmitTimeout = 2 * time.Second

// Emit fires a fire-and-forget POST of payload to the given unix socket at
// route, in a detached goroutine. It returns immediately and never blocks the
// caller; all errors (missing socket, dead peer, timeout) are swallowed —
// dropping a relayed signal must never break a client flow. Mirrors
// _common.fire_forget_post + queue_async (create_task, never raise).
//
// route is the HTTP path on the module (e.g. "/inject", "/classify").
func Emit(socketPath, route string, payload []byte) {
	go EmitSync(socketPath, route, payload) //nolint:errcheck
}

// EmitSync performs the actual POST synchronously (under EmitTimeout).
// Exported so tests can observe delivery deterministically without racing
// the goroutine, and so cmd/sbxwaf can make synchronous calls when needed.
// Returns an error only for the caller's benefit; Emit() discards it.
func EmitSync(socketPath, route string, payload []byte) error {
	if route == "" {
		route = "/"
	}
	ctx, cancel := context.WithTimeout(context.Background(), EmitTimeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return err // dead/missing socket — swallowed by Emit()
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
