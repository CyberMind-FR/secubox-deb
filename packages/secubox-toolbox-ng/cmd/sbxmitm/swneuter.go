// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxmitm — targeted Service-Worker neuter (#753)
//
// PWA news sites (leparisien, cnn…) serve their main HTML document from a
// Service-Worker cache, so the navigation never reaches the MITM and the
// transparency banner can't be injected. For an operator-curated allow-list of
// hosts, we answer the SW SCRIPT fetch with a self-unregistering SW: the browser
// updates to it, it unregisters + drops caches, and the NEXT navigation is a
// fresh network fetch the MITM injects the banner into. PASSIVE (no forced
// reload). Targeted-strict: an empty list neuters nothing.
package main

import (
	"net/http"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// NeuterSW is the self-unregistering SW body served for allow-listed hosts.
// It unregisters itself and clears all caches on activate; it NEVER calls
// client.navigate(), so the current page is not force-reloaded — the banner
// returns on the next navigation.
const NeuterSW = `self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){
  e.waitUntil((async function(){
    try { var ks = await caches.keys(); await Promise.all(ks.map(function(k){ return caches.delete(k); })); } catch (_) {}
    try { await self.registration.unregister(); } catch (_) {}
  })());
});
`

// swCandMapCap bounds the candidate buffer (mirrors adCandMapCap).
const swCandMapCap = 4096

// SWNeuter holds the hot-reloadable allow-list + the auto-learn candidate buffer.
type SWNeuter struct {
	mu      sync.RWMutex
	hosts   map[string]bool // allow-list (lowercased; suffix-matched via hostMatches)
	watcher *reload.Watcher

	cmu  sync.Mutex
	cand map[string]int64 // host -> hits (SW hosts NOT yet on the allow-list)
}

// newSWNeuter loads the allow-list file and registers a hot-reload watcher.
// A missing/unreadable file yields an empty (no-op) list.
func newSWNeuter(path string) *SWNeuter {
	s := &SWNeuter{
		hosts: reload.LoadLines(path, true),
		cand:  map[string]int64{},
	}
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load:      func(p string) any { return reload.LoadLines(p, true) },
		Apply: func(v any) {
			m := v.(map[string]bool)
			s.mu.Lock()
			s.hosts = m
			s.mu.Unlock()
		},
	}
	s.watcher = reload.NewWatcher(reload.DefaultReloadThrottle, target)
	return s
}

// Maybe triggers a hot-reload check (cheap: one stat + mtime compare).
func (s *SWNeuter) Maybe() {
	if s != nil && s.watcher != nil {
		s.watcher.Maybe()
	}
}

// Match reports whether host is on the allow-list (exact or dotted-suffix).
func (s *SWNeuter) Match(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return hostMatches(host, s.hosts)
}

// RecordCandidate tallies a SW host not on the allow-list (auto-learn proposal).
func (s *SWNeuter) RecordCandidate(host string) {
	h := strings.Trim(strings.ToLower(host), ".")
	if h == "" {
		return
	}
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if _, ok := s.cand[h]; ok {
		s.cand[h]++
	} else if len(s.cand) < swCandMapCap {
		s.cand[h] = 1
	}
}

// snapshotCandidates atomically reads-and-clears the candidate buffer.
func (s *SWNeuter) snapshotCandidates() []string {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if len(s.cand) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.cand))
	for h := range s.cand {
		out = append(out, h)
	}
	s.cand = map[string]int64{}
	return out
}

// isSWScriptRequest reports whether req is a Service-Worker SCRIPT fetch.
// Browsers send the spec-mandated `Service-Worker: script` header on the
// register() fetch and every update check — reliable and host-agnostic.
func isSWScriptRequest(req *http.Request) bool {
	return req != nil && strings.EqualFold(req.Header.Get("Service-Worker"), "script")
}
