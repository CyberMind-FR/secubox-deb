// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Optional read-only status HTTP surface for sbx-sentinel. It is OFF by
// default (only stood up when Config.HTTPAddr / SENTINEL_HTTP_ADDR is set) and
// serves GET-only endpoints backed by the verdict Store:
//
//   - GET /stats    → {"detections":N,"blocked":N,"spyware":N} for a sidebar.
//   - GET /verdicts → the recent verdicts, each with its RenderReport text.
//
// When the daemon was built with the #826 C2 auto-learn analyzer wired
// (production default — see buildAnalyzers in main.go), three more routes
// are registered:
//
//   - GET  /c2/learned     → the confirmed learned-C2 set ([]sentinel.LearnedC2).
//   - GET  /c2/candidates  → the in-progress candidate set ([]sentinel.C2Candidate).
//   - POST /c2/allow       → operator "Ignorer": an x-www-form-urlencoded (or
//     query-string) `host` param moves a learned/candidate host onto the
//     allowlist. NOT a JSON body — r.FormValue only parses form/query values.
//     The only write this surface accepts — it edits the local allow-list
//     file only, never the network.
//
// This is a minimal local read for an operator/portal; carries no PII beyond
// mac_hash and does NOT route through the WAF-bypass path. The richer
// operator UI (verdicts panel, per-report view) belongs in the separate
// Python secubox-toolbox portal — see debian/README.sentinel.md for the
// intended /api/v1/toolbox/sentinel/* routes it should expose.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// statusRecentLimit bounds how many verdicts /stats and /verdicts read from
// the (TTL-bounded, small-by-design) store per request.
const statusRecentLimit = 500

// sentinelStats is the sidebar metrics line: total detections, how many were
// neutralized (block/strip/sinkhole), and how many were commercial-spyware
// class.
type sentinelStats struct {
	Detections int `json:"detections"`
	Blocked    int `json:"blocked"`
	Spyware    int `json:"spyware"`
}

// verdictView is one verdict as surfaced over HTTP: the verdict fields plus
// the pre-rendered human report. Identity is mac_hash only.
type verdictView struct {
	Class      sentinel.ThreatClass `json:"class"`
	Severity   int                  `json:"severity"`
	Confidence int                  `json:"confidence"`
	Action     sentinel.Action      `json:"action"`
	Evidence   map[string]string    `json:"evidence,omitempty"`
	MacHash    string               `json:"mac_hash"`
	TS         int64                `json:"ts"`
	Report     string               `json:"report"`
}

// isNeutralized reports whether act actually neutralized the flow.
func isNeutralized(act sentinel.Action) bool {
	switch act {
	case sentinel.ActionBlock, sentinel.ActionStrip, sentinel.ActionSinkhole:
		return true
	default:
		return false
	}
}

// computeStats aggregates the sidebar metrics from a verdict slice.
func computeStats(vs []sentinel.Verdict) sentinelStats {
	var s sentinelStats
	s.Detections = len(vs)
	for _, v := range vs {
		if isNeutralized(v.Action) {
			s.Blocked++
		}
		if strings.HasPrefix(string(v.Class), "spyware_") {
			s.Spyware++
		}
	}
	return s
}

// newStatusMux builds the read-only status router over store. Exposed
// (unexported to the package) so http_test.go can exercise the handlers
// directly with httptest, independent of run()'s listener lifecycle.
//
// c2 is the C2 auto-learn analyzer (#826); when nil (the daemon was built
// without one, e.g. a test-injected pipeline) the /c2/* routes are simply
// not registered — a request to them 404s rather than panicking.
func newStatusMux(store *sentinel.Store, c2 *sentinel.C2Learner) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		recent, err := store.Recent(statusRecentLimit)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		writeJSON(w, computeStats(recent))
	})

	mux.HandleFunc("/verdicts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		limit := statusRecentLimit
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= statusRecentLimit {
				limit = n
			}
		}
		var (
			recent []sentinel.Verdict
			err    error
		)
		if mac := r.URL.Query().Get("mac"); mac != "" {
			recent, err = store.ByMac(mac, limit)
		} else {
			recent, err = store.Recent(limit)
		}
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		out := make([]verdictView, 0, len(recent))
		for _, v := range recent {
			out = append(out, verdictView{
				Class:      v.Class,
				Severity:   v.Severity,
				Confidence: v.Confidence,
				Action:     v.Action,
				Evidence:   v.Evidence,
				MacHash:    v.MacHash,
				TS:         v.TS,
				Report:     sentinel.RenderReport(v),
			})
		}
		writeJSON(w, out)
	})

	// Read-only C2 auto-learn views + the operator "Ignorer" allow-list
	// write (#826). Registered only when a C2Learner is actually wired —
	// the daemon still runs fine without one (fail-safe).
	if c2 != nil {
		mux.HandleFunc("/c2/learned", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			writeJSON(w, c2.Learned())
		})
		mux.HandleFunc("/c2/candidates", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			writeJSON(w, c2.Candidates())
		})
		mux.HandleFunc("/c2/allow", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			host := r.FormValue("host")
			if host == "" {
				http.Error(w, "host required", http.StatusBadRequest)
				return
			}
			if err := c2.Allow(host); err != nil {
				http.Error(w, "allow failed", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]bool{"ok": true})
		})
	}

	return mux
}

// writeJSON marshals v as JSON to w, best-effort.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("sbx-sentinel: status JSON encode failed: %v", err)
	}
}

// serveStatus runs the read-only status HTTP server on addr until ctx is
// cancelled, then shuts it down gracefully. A ListenAndServe error other than
// the expected post-Shutdown ErrServerClosed is logged (the daemon's core
// socket/store keeps running regardless — the status surface is non-critical).
func serveStatus(ctx context.Context, addr string, store *sentinel.Store, c2 *sentinel.C2Learner) {
	srv := &http.Server{
		Addr:              addr,
		Handler:           newStatusMux(store, c2),
		ReadHeaderTimeout: 5 * time.Second,
	}

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("sbx-sentinel: status HTTP server error: %v", err)
	}
	<-shutdownDone
}
