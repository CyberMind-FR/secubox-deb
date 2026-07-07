// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

package sentinel

// C2 auto-learn false-positive gate (#823 C2 autolearn): a host is "allowed"
// (never learned as C2) if it is a box-owned vhost, a private/loopback IP
// literal, or listed (suffix-matched) in the operator allowlist. Every source
// is fail-safe: a missing/corrupt file contributes no entries, never an error.

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type C2Allow struct {
	allowFile string
	boxFile   string

	mu     sync.RWMutex
	suffix map[string]bool // host suffixes (allow entries + box vhosts), lowercased

	addMu sync.Mutex // serializes Add's read-modify-write of allowFile
}

// NewC2Allow builds the gate from an operator allowlist file (one host/suffix
// per line, # comments allowed) and a box-domains source (a HAProxy
// routes JSON whose KEYS are the box's own vhost domains). Either path may be
// "" or missing. Loads immediately (fail-safe).
func NewC2Allow(allowFile, boxFile string) *C2Allow {
	a := &C2Allow{allowFile: allowFile, boxFile: boxFile}
	a.Reload()
	return a
}

// Reload re-reads both sources into a fresh suffix set. Fail-safe.
func (a *C2Allow) Reload() {
	set := make(map[string]bool)
	for _, l := range readLinesSafe(a.allowFile) {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		set[l] = true
	}
	for _, d := range readBoxDomainsSafe(a.boxFile) {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			set[d] = true
		}
	}
	a.mu.Lock()
	a.suffix = set
	a.mu.Unlock()
}

// Allowed reports whether host must NOT be learned as C2. Empty host → true
// (never learn a blank). Private/loopback/link-local IP literals → true.
// Otherwise suffix-matched against the allow set.
func (a *C2Allow) Allowed(host string) bool {
	if host == "" {
		return true
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	// exact + progressive parent-suffix match: a.b.c matches entries a.b.c, b.c, c
	labels := strings.Split(h, ".")
	for i := 0; i < len(labels); i++ {
		if a.suffix[strings.Join(labels[i:], ".")] {
			return true
		}
	}
	return false
}

// Add appends host to the operator allowlist file (atomic rewrite). The
// in-memory set is refreshed by a subsequent Reload (caller's responsibility,
// so a batch of Adds costs one reload).
//
// host is reachable over the network (POST /c2/allow), so it is sanitized:
// anything containing a newline, carriage return, or space is rejected
// (fail-safe — the invalid host is simply ignored, no error, no write) to
// prevent a single call from injecting extra allowlist lines. A bare
// single-label host (no ".") is also rejected: Allowed's progressive-suffix
// match would let it blind-match an entire TLD.
func (a *C2Allow) Add(host string) error {
	a.addMu.Lock()
	defer a.addMu.Unlock()
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || a.allowFile == "" {
		return nil
	}
	if strings.ContainsAny(host, "\n\r ") {
		return nil
	}
	if !strings.Contains(host, ".") {
		// A bare label (e.g. "com", "localhost") would suffix-match an
		// entire TLD (or worse) via the progressive-suffix check in
		// Allowed, blinding detection far beyond the intended host.
		// Fail-safe ignore — no write.
		return nil
	}
	existing := readLinesSafe(a.allowFile)
	for _, l := range existing {
		if strings.ToLower(strings.TrimSpace(l)) == host {
			return nil // already present
		}
	}
	existing = append(existing, host)
	return atomicWriteFile(a.allowFile, []byte(strings.Join(existing, "\n")+"\n"), 0o644)
}

// readLinesSafe returns the file's lines, or nil on any error.
func readLinesSafe(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\n")
}

// readBoxDomainsSafe returns the KEYS of a HAProxy-routes-style JSON object
// (the box's own vhost domains), or nil on any error.
func readBoxDomainsSafe(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		log.Printf("sentinel c2allow: box-domains %s unparseable (ignored): %v", path, err)
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// atomicWriteFile writes data to path via a temp file + rename in the same dir.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".c2tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
