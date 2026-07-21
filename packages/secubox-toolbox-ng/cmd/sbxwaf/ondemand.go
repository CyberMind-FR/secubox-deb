// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — on-demand-vhosts.json loader
//
// SecuBox scale-to-zero (#896): the profiles side (Task 13) writes the set of
// "on-demand" public vhosts — services whose lifecycle is on-demand and that
// may currently be asleep — to /etc/secubox/waf/on-demand-vhosts.json, a
// plain JSON array of vhost strings:
//
//	["dashboard.example.com", "rare-tool.example.com"]
//
// When the sleeper stops an on-demand service, its haproxy-routes.json entry
// is removed (Routes.Lookup returns ok=false for it). Without this set the
// handler would answer 421 Misdirected Request for a perfectly legitimate
// vhost that is simply asleep. OnDemand lets the 421 site distinguish
// "unknown host" (real 421) from "known on-demand host with no live route"
// (proxy to the waker instead — see wakerproxy.go).
//
// Hot-reload mirrors routes.go / rules.go exactly:
//   - reload.NewWatcher(throttle=0, target) — throttle 0 so tests calling
//     Maybe() see the change immediately; production callers may layer their
//     own throttle around Maybe() if needed.
//   - reload.StatMtime is used for the initial LastMtime (the initial load
//     already happened synchronously in LoadOnDemand, so the first Maybe()
//     must NOT immediately reload the same content again).
//   - The Target.Load func re-parses the file; Target.Apply atomically swaps
//     the set under the RWLock.
package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// OnDemand is a hot-reloadable, RW-locked set of on-demand vhosts. Create
// with LoadOnDemand; call Contains on the hot path; call Maybe() to pick up
// on-disk changes (same idiom as Routes / Rules).
type OnDemand struct {
	mu      sync.RWMutex
	entries map[string]bool // key: lowercased bare hostname

	// watcher handles mtime tracking + Apply callbacks (throttle=0 → eager).
	// Nil for OnDemand values built directly by tests (no hot-reload wanted).
	watcher *reload.Watcher
}

// loadOnDemandJSON parses path as a JSON array of vhost strings into a set.
// A missing/unreadable file or malformed JSON yields an empty (never-matching)
// set — best-effort, mirrors loadRoutesJSON / loadRulesJSON.
func loadOnDemandJSON(path string) map[string]bool {
	out := map[string]bool{}

	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		log.Printf("sbxwaf/ondemand: parse %s: %v", path, err)
		return out
	}

	for _, host := range arr {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		out[host] = true
	}
	return out
}

// LoadOnDemand parses path as an on-demand-vhosts.json file and returns an
// *OnDemand ready for Contains. A missing or unreadable file yields an empty
// (but functional) OnDemand — every Contains returns false until a valid
// file appears and Maybe() picks up the reload.
func LoadOnDemand(path string) *OnDemand {
	o := &OnDemand{}

	// Initial load.
	o.entries = loadOnDemandJSON(path)

	// Register the reload target. throttle=0 so Maybe() fires immediately in
	// tests; production can wrap with its own throttle like Routes.Maybe().
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load: func(p string) any {
			return loadOnDemandJSON(p)
		},
		Apply: func(v any) {
			parsed := v.(map[string]bool)
			o.mu.Lock()
			o.entries = parsed
			o.mu.Unlock()
		},
	}
	o.watcher = reload.NewWatcher(0, target)
	return o
}

// Maybe triggers a hot-reload check — stats the on-demand-vhosts file and
// atomically swaps the set if the mtime changed. Cheap when nothing changed
// (one stat + one time compare). Call from the request hot path (mirrors
// Routes.Maybe() / Rules.Maybe()). A nil watcher (OnDemand values built
// directly by tests without LoadOnDemand) is a no-op.
func (o *OnDemand) Maybe() {
	if o == nil || o.watcher == nil {
		return
	}
	o.watcher.Maybe()
}

// Contains reports whether host is a known on-demand vhost. host is
// lowercased and port-stripped before the map probe, matching
// Routes.Lookup's normalisation of the caller-supplied host.
func (o *OnDemand) Contains(host string) bool {
	if o == nil {
		return false
	}

	h := strings.ToLower(strings.TrimSpace(host))
	if bare, _, err := net.SplitHostPort(h); err == nil {
		h = bare
	}

	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.entries[h]
}
