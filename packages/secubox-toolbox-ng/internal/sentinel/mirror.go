// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Bounded fire-and-forget mirror channel: cmd/sbxmitm's hot path calls Emit
// per suspicious flow to hand it off to the async sbx-sentinel analyzer
// (Task 8) over a local unix socket. Per the plan's "async fail-safe"
// constraint, a down/slow analyzer must never stall sbxmitm — Emit is
// non-blocking and drops-with-count on a full queue rather than waiting.
package sentinel

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MirrorMsg is one flow observation mirrored to the analyzer. It is
// JSON-encoded and newline-delimited on the wire; Body is capped to the
// Mirror's configured bodyCap before it is queued.
type MirrorMsg struct {
	Meta FlowMeta
	Body []byte
	TS   int64
}

// reconnect backoff bounds for the writer goroutine: it never spins on a
// down/refusing socket, but also never waits so long that a recovered
// analyzer sits idle for an unreasonable time.
const (
	mirrorBackoffMin = 100 * time.Millisecond
	mirrorBackoffMax = 5 * time.Second
)

// Mirror is a bounded fire-and-forget client that ships MirrorMsg values to
// a unix-socket-listening analyzer. Construct with NewMirror; call Close
// when done. All exported methods are safe for concurrent use.
type Mirror struct {
	socketPath string
	bodyCap    int

	ch      chan MirrorMsg
	dropped uint64 // atomic

	closeOnce sync.Once
	done      chan struct{}
	wg        sync.WaitGroup
}

// NewMirror returns a Mirror that queues up to queue messages and dials
// socketPath in a background goroutine to ship them, truncating each
// message's Body to bodyCap bytes at Emit time. The background writer
// starts immediately; a not-yet-listening socketPath is fine — the writer
// retries with a bounded backoff.
func NewMirror(socketPath string, queue int, bodyCap int) *Mirror {
	if queue <= 0 {
		queue = 1
	}
	if bodyCap < 0 {
		bodyCap = 0
	}
	m := &Mirror{
		socketPath: socketPath,
		bodyCap:    bodyCap,
		ch:         make(chan MirrorMsg, queue),
		done:       make(chan struct{}),
	}
	m.wg.Add(1)
	go m.run()
	return m
}

// Emit queues msg for delivery to the analyzer. It NEVER blocks: msg.Body is
// always copied (and truncated to bodyCap if needed) into a fresh
// right-sized slice first, so the queued MirrorMsg never aliases the
// caller's backing array — sbxmitm's hot path may reuse/pool that buffer
// the instant Emit returns. The message is then offered to the internal
// channel with a non-blocking select — on a full channel (queue saturated,
// e.g. analyzer down/slow) Emit increments the dropped counter and returns
// immediately. This is best-effort mirroring only; a dropped or later
// send-failed message is simply lost, never retried.
func (m *Mirror) Emit(msg MirrorMsg) {
	n := len(msg.Body)
	if m.bodyCap >= 0 && n > m.bodyCap {
		n = m.bodyCap
	}
	if n > 0 {
		b := make([]byte, n)
		copy(b, msg.Body)
		msg.Body = b
	} else {
		msg.Body = nil
	}

	select {
	case m.ch <- msg:
	default:
		atomic.AddUint64(&m.dropped, 1)
	}
}

// Dropped returns the number of messages dropped so far because the
// internal queue was full when Emit was called.
func (m *Mirror) Dropped() uint64 {
	return atomic.LoadUint64(&m.dropped)
}

// Close stops the background writer goroutine and waits for it to exit. It
// does not attempt to flush queued messages; Close is meant for clean
// shutdown, not guaranteed delivery (this is a best-effort mirror).
func (m *Mirror) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)
	})
	m.wg.Wait()
	return nil
}

// run is the background writer: it dials socketPath, writes queued messages
// as newline-delimited JSON, and reconnects with a bounded exponential
// backoff on any dial or write error. It never spins: a persistently down
// analyzer just accumulates backoff up to mirrorBackoffMax. Messages that
// fail to send are dropped (fire-and-forget), not retried.
func (m *Mirror) run() {
	defer m.wg.Done()

	backoff := mirrorBackoffMin
	for {
		conn, err := net.Dial("unix", m.socketPath)
		if err != nil {
			if !m.sleepBackoff(&backoff) {
				return
			}
			continue
		}
		backoff = mirrorBackoffMin

		if !m.drain(conn) {
			conn.Close()
			return
		}
		conn.Close()

		// drain returned false only on shutdown (handled above); a
		// write-error return from drain falls through here to
		// reconnect after a short backoff.
		if !m.sleepBackoff(&backoff) {
			return
		}
	}
}

// drain writes queued messages to conn until either the connection errors
// (returns true, meaning "reconnect") or m is closing (returns false,
// meaning "shut down"). It intentionally does not return on an empty queue:
// it blocks on the channel/done select so the connection is reused for the
// life of the Mirror rather than reconnecting per-message.
func (m *Mirror) drain(conn net.Conn) bool {
	w := bufio.NewWriter(conn)
	enc := json.NewEncoder(w)

	for {
		select {
		case <-m.done:
			return false
		case msg := <-m.ch:
			if err := enc.Encode(msg); err != nil {
				log.Printf("sentinel: mirror write failed, reconnecting: %v", err)
				return true
			}
			if err := w.Flush(); err != nil {
				log.Printf("sentinel: mirror flush failed, reconnecting: %v", err)
				return true
			}
		}
	}
}

// sleepBackoff waits for the current backoff duration (or until Close),
// doubling backoff up to mirrorBackoffMax for the caller's next iteration.
// It returns false if m is closing (caller should stop), true otherwise.
func (m *Mirror) sleepBackoff(backoff *time.Duration) bool {
	t := time.NewTimer(*backoff)
	defer t.Stop()

	select {
	case <-m.done:
		return false
	case <-t.C:
	}

	next := *backoff * 2
	if next > mirrorBackoffMax {
		next = mirrorBackoffMax
	}
	*backoff = next
	return true
}
