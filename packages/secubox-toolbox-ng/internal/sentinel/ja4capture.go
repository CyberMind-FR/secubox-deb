// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// JA4Capture is an optional, operator-triggered recorder of observed
// (host, JA4) pairs. The C2 auto-learn "non_browser_ja" signal needs a set of
// KNOWN-browser JA4 fingerprints to suppress admin-dashboard false positives,
// but those fingerprints are version-specific and cannot be guessed — the
// accurate source is the operator's OWN live traffic. Enabling capture
// (SENTINEL_JA4_CAPTURE=<file>) writes newline-delimited "host<TAB>ja4" for a
// while; the operator then keeps the fingerprints seen against known browser
// destinations as browser-ja4.txt. Disabled (empty path) is a zero-cost no-op.

import (
	"os"
	"sync"
)

// ja4CaptureCap bounds the in-memory dedup set (and thus the file) so a
// long-running capture can never grow without limit.
const ja4CaptureCap = 20000

type JA4Capture struct {
	mu   sync.Mutex
	seen map[string]bool // "host\tja4" keys already written
	f    *os.File
}

// NewJA4Capture opens path for append and returns a recorder, or nil (a safe
// no-op) when path is empty or unopenable — capture must never break the daemon.
func NewJA4Capture(path string) *JA4Capture {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil
	}
	return &JA4Capture{seen: make(map[string]bool), f: f}
}

// Observe records one (host, ja4) pair, deduped and bounded. No-op on a nil
// receiver, empty fields, or once the cap is reached. Never panics.
func (c *JA4Capture) Observe(host, ja4 string) {
	if c == nil || host == "" || ja4 == "" {
		return
	}
	key := host + "\t" + ja4
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[key] || len(c.seen) >= ja4CaptureCap {
		return
	}
	c.seen[key] = true
	_, _ = c.f.WriteString(key + "\n")
}
