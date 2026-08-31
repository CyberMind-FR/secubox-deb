// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: go-level filtering + enhancements
//
// The declarative filtering layer that "emancipates" raw nDPId output, in the
// same style as sbx-sentinel's c2allow.go: line-based *.txt conffiles under
// /etc/secubox/dpi/, loaded fail-safe and hot-reloaded on mtime change via
// internal/reload. Four inputs:
//
//   - box domains (haproxy-routes.json keys) → FIRST-PARTY exemption: our own
//     vhosts/traffic are never dropped and are flagged so the dashboard can
//     separate "us" from "the wild";
//   - deny list  → apps/protocols/categories/hosts dropped from the stats
//     (noise: DHCP, mDNS, whatever the operator mutes);
//   - allow list → pins that override the deny list (keep even if muted);
//   - risk-mute  → nDPI risk names/ids not surfaced (false-positive control).
//
// Every source is fail-safe: a missing/corrupt file loads as the empty set,
// never an error.
package main

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// decision is the per-event verdict from classify.
type decision struct {
	drop       bool // remove from stats entirely
	firstParty bool // our own vhost/LAN traffic (exempt + flagged)
}

type filter struct {
	mu       sync.RWMutex
	allow    map[string]bool // exact app/proto/host pins (override deny)
	deny     map[string]bool // exact app/proto/category/host to drop
	riskMute map[string]bool // risk names/ids to not surface
	box      map[string]bool // our own vhost domains (suffix-matched)

	watcher *reload.Watcher
}

// loadBoxDomains reads the top-level keys of haproxy-routes.json into a
// lowercased set (each key is one of our vhost domains). Fail-safe: missing or
// non-object JSON → empty set.
func loadBoxDomains(path string) map[string]bool {
	out := map[string]bool{}
	buf, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf, &m); err != nil {
		return out
	}
	for k := range m {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			out[k] = true
		}
	}
	return out
}

func newFilter(cfg Config) *filter {
	f := &filter{
		allow:    reload.LoadLines(cfg.AllowFile, true),
		deny:     reload.LoadLines(cfg.DenyFile, true),
		riskMute: reload.LoadLines(cfg.RiskMute, true),
		box:      loadBoxDomains(cfg.BoxDomains),
	}
	f.watcher = reload.NewWatcher(cfg.ReloadEvery,
		reload.Target{
			Path: cfg.AllowFile, LastMtime: reload.StatMtime(cfg.AllowFile),
			Load:  func(p string) any { return reload.LoadLines(p, true) },
			Apply: func(v any) { f.mu.Lock(); f.allow = v.(map[string]bool); f.mu.Unlock() },
		},
		reload.Target{
			Path: cfg.DenyFile, LastMtime: reload.StatMtime(cfg.DenyFile),
			Load:  func(p string) any { return reload.LoadLines(p, true) },
			Apply: func(v any) { f.mu.Lock(); f.deny = v.(map[string]bool); f.mu.Unlock() },
		},
		reload.Target{
			Path: cfg.RiskMute, LastMtime: reload.StatMtime(cfg.RiskMute),
			Load:  func(p string) any { return reload.LoadLines(p, true) },
			Apply: func(v any) { f.mu.Lock(); f.riskMute = v.(map[string]bool); f.mu.Unlock() },
		},
		reload.Target{
			Path: cfg.BoxDomains, LastMtime: reload.StatMtime(cfg.BoxDomains),
			Load:  func(p string) any { return loadBoxDomains(p) },
			Apply: func(v any) { f.mu.Lock(); f.box = v.(map[string]bool); f.mu.Unlock() },
		},
	)
	return f
}

// classify runs the filtering pipeline for one flow event. It calls the
// throttled hot-path reload check, then decides under a read lock.
func (f *filter) classify(ev *dpiEvent) decision {
	f.watcher.Maybe()

	host := strings.ToLower(ev.NDPI.Hostname)
	app := strings.ToLower(ev.app())
	master := strings.ToLower(ev.master())
	cat := strings.ToLower(ev.category())

	f.mu.RLock()
	defer f.mu.RUnlock()

	firstParty := (host != "" && suffixMatch(f.box, host)) ||
		isLocalIP(ev.DstIP) || isLocalIP(ev.SrcIP)

	// First-party traffic is ours: never dropped, always flagged.
	if firstParty {
		return decision{drop: false, firstParty: true}
	}

	// Allow pins win over deny.
	if f.allow[app] || f.allow[master] || (host != "" && f.allow[host]) {
		return decision{drop: false}
	}

	if f.deny[app] || f.deny[master] || f.deny[cat] || (host != "" && f.deny[host]) {
		return decision{drop: true}
	}
	return decision{drop: false}
}

// riskMuted reports whether a risk name/id is muted (case-insensitive).
func (f *filter) riskMuted(name string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.riskMute[strings.ToLower(strings.TrimSpace(name))]
}

// counts returns the current filter set sizes (for the /health surface).
func (f *filter) counts() (allow, deny, mute, box int) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.allow), len(f.deny), len(f.riskMute), len(f.box)
}

// suffixMatch reports whether host matches any set entry, testing host and each
// of its parent suffixes ("a.b.c" matches entries "a.b.c", "b.c", "c").
func suffixMatch(set map[string]bool, host string) bool {
	if len(set) == 0 || host == "" {
		return false
	}
	h := host
	for {
		if set[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// isLocalIP reports whether s is a private/loopback/link-local literal — the
// LAN side of a flow, which is first-party by construction.
func isLocalIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}
