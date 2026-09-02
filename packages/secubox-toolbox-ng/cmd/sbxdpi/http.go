// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxdpi :: read-only /api/v1/dpi/ surface
//
// Served over the /run/secubox/dpi-live.sock unix socket. Read-only, GET-only,
// no auth in the daemon by design: the socket is local and carries only
// aggregate counters (protocol/app/category/ip-pair) — no request bodies, no
// PII. JWT enforcement lives at the nginx + FastAPI layer that fronts this
// socket (the project's Depends(require_jwt) model), exactly as sbx-sentinel's
// status surface is fronted by the toolbox portal. Paths carry the full
// /api/v1/dpi/ prefix so nginx can proxy_pass straight through.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

const defaultTopLimit = 12

func newDPIMux(agg *aggregator, filt *filter, enr *enricher, sess *sessionTracker) *http.ServeMux {
	mux := http.NewServeMux()

	// Liveness + connection state to nDPIsrvd + filter sizes.
	mux.HandleFunc("/api/v1/dpi/health", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		snap := agg.snapshot()
		allow, deny, mute, box := filt.counts()
		writeJSON(w, map[string]any{
			"ok":          true,
			"connected":   snap.Connected,
			"total_flows": snap.TotalFlows,
			"total_bytes": snap.TotalBytes,
			"filtered":    snap.Filtered,
			"updated_at":  snap.UpdatedAt,
			"filters":     map[string]int{"allow": allow, "deny": deny, "risk_mute": mute, "box_domains": box},
		})
	})

	// Full snapshot (everything the cardlet needs in one round-trip).
	mux.HandleFunc("/api/v1/dpi/stats", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, agg.snapshot())
	})

	mux.HandleFunc("/api/v1/dpi/top_protocols", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, topN(agg.snapshot().Protocols, limitOf(r)))
	})
	mux.HandleFunc("/api/v1/dpi/top_apps", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, topN(agg.snapshot().Apps, limitOf(r)))
	})
	mux.HandleFunc("/api/v1/dpi/top_categories", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, topN(agg.snapshot().Categories, limitOf(r)))
	})
	mux.HandleFunc("/api/v1/dpi/talkers", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, topN(agg.snapshot().Talkers, limitOf(r)))
	})
	// Top destinations SNI/DNS (#DPI-sémantique) — pivot des règles usage/CDN.
	mux.HandleFunc("/api/v1/dpi/hosts", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, topN(agg.snapshot().Hosts, limitOf(r)))
	})
	// Vue USAGE (#DPI-sémantique) : les destinations SNI classées par famille
	// d'usage / infrastructure / application via les règles versionnées, plus la
	// liste unknown-first des hôtes non classifiés. Enrichissement additif, dérivé
	// de hosts[] — n'altère pas le pipeline de stats.
	mux.HandleFunc("/api/v1/dpi/usage", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, enr.report(agg.snapshot().Hosts))
	})
	// LEARNER (#DPI-sémantique L5) : suggestions de règles issues des inconnus
	// (regroupés par domaine racine). OBSERVE→CORRELATE→SUGGEST ; l'ACCEPT (écrit
	// une règle) est un acte humain via la FastAPI JWT, jamais ici.
	mux.HandleFunc("/api/v1/dpi/suggestions", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, suggestFromUnknown(enr.report(agg.snapshot().Hosts).Unknown))
	})
	// SESSIONS d'usage (#DPI-sémantique L3) : flux corrélés par device+usage+fenêtre.
	mux.HandleFunc("/api/v1/dpi/sessions", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		writeJSON(w, sess.snapshot(time.Now().Unix()))
	})
	mux.HandleFunc("/api/v1/dpi/risks", func(w http.ResponseWriter, r *http.Request) {
		if !getOnly(w, r) {
			return
		}
		risks := agg.snapshot().Risks
		if n := limitOf(r); n > 0 && n < len(risks) {
			risks = risks[:n]
		}
		writeJSON(w, risks)
	})

	return mux
}

func getOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// limitOf parses ?limit= (1..500), defaulting to defaultTopLimit.
func limitOf(r *http.Request) int {
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
			return n
		}
	}
	return defaultTopLimit
}

func topN(s []kv, n int) []kv {
	if n > 0 && n < len(s) {
		return s[:n]
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("sbxdpi: JSON encode failed: %v", err)
	}
}
