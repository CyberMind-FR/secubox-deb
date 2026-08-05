// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — wake on upstream refusal (#746)
//
// #896 shipped one wake trigger: an on-demand vhost with NO live route goes to
// the waker instead of 421. That covers a sleeper that also tore the route
// down.
//
// A Streamlit app (#746) fails the other way: its route in
// haproxy-routes.json is permanent (host -> 10.100.0.50:<port>, present
// whether the app runs or not), so Lookup succeeds and the no-route branch is
// never reached. What is missing is the process behind the port — the dial
// gets ECONNREFUSED and the visitor receives the themed 502 page, forever.
//
// These tests pin the second trigger: on-demand + connection refused -> waker.
package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// refusedAddr returns an ip/port pair guaranteed to refuse connections: a
// listener is opened to reserve a real free port, then closed immediately.
func refusedAddr(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	_ = ln.Close()
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// stubWaker starts an HTTP server on a unix socket and records the path it is
// asked for. Mirrors the harness TestOnDemandProxiesToWaker already uses.
func stubWaker(t *testing.T, name string, gotPath *string) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), name)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*gotPath = r.URL.Path
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "waking up…")
		}),
	}
	go srv.Serve(ln) //nolint:errcheck
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	return sockPath
}

// The #746 case proper: the route resolves, the upstream refuses, the vhost is
// declared on-demand — the visitor must get the waker splash, not a 502 that
// no amount of waiting will ever resolve.
func TestOnDemandUpstreamRefusedProxiesToWaker(t *testing.T) {
	var gotPath string
	sockPath := stubWaker(t, "waker-refused.sock", &gotPath)

	ip, port := refusedAddr(t)
	srv := &Server{
		routeLookup: func(host string) (string, int, bool) { return ip, port, true },
		onDemand:    &OnDemand{entries: map[string]bool{"asleep.example.com": true}},
		wakerSocket: sockPath,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://asleep.example.com/", nil)
	req.Host = "asleep.example.com"
	srv.handler().ServeHTTP(rec, req)

	if gotPath != "/_wake/asleep.example.com" {
		t.Fatalf("expected the waker to be asked for /_wake/asleep.example.com, got %q "+
			"(body: %s)", gotPath, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "502") {
		t.Fatalf("expected the waker splash, got a 502 error page: %s", rec.Body.String())
	}
}

// The regression guard that matters most: extending the trigger must not turn
// every ordinary backend outage into a wake attempt. A vhost nobody declared
// on-demand keeps the themed 502 it has always had.
func TestUpstreamRefusedWithoutOnDemandKeepsErrorPage(t *testing.T) {
	var gotPath string
	sockPath := stubWaker(t, "waker-unused.sock", &gotPath)

	ip, port := refusedAddr(t)
	srv := &Server{
		routeLookup: func(host string) (string, int, bool) { return ip, port, true },
		onDemand:    &OnDemand{entries: map[string]bool{"other.example.com": true}},
		wakerSocket: sockPath,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://plain.example.com/", nil)
	req.Host = "plain.example.com"
	srv.handler().ServeHTTP(rec, req)

	if gotPath != "" {
		t.Fatalf("waker must not be called for a vhost that is not on-demand, got %q", gotPath)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 for a non-on-demand refused upstream, got %d", rec.Code)
	}
}

// A slow upstream is a LIVE upstream. Waking something already running would
// be a no-op at best, and at worst a wake storm aimed at a service that is
// merely overloaded — on a board that is CPU-constrained by construction.
// Only "connection refused" (502) means nobody is listening.
func TestWakeOnRefusalIgnoresTimeoutAndOtherCodes(t *testing.T) {
	srv := &Server{
		onDemand: &OnDemand{entries: map[string]bool{"asleep.example.com": true}},
	}
	if !srv.wakeOnRefusal(http.StatusBadGateway, "asleep.example.com") {
		t.Fatal("502 on an on-demand vhost must wake")
	}
	for _, code := range []int{
		http.StatusGatewayTimeout,     // 504 — upstream alive but slow
		http.StatusServiceUnavailable, // 503 — anything else
		http.StatusOK,
	} {
		if srv.wakeOnRefusal(code, "asleep.example.com") {
			t.Fatalf("code %d must never trigger a wake", code)
		}
	}
	if srv.wakeOnRefusal(http.StatusBadGateway, "plain.example.com") {
		t.Fatal("a vhost outside the on-demand set must never wake")
	}
	var nilOnDemand *Server = &Server{}
	if nilOnDemand.wakeOnRefusal(http.StatusBadGateway, "asleep.example.com") {
		t.Fatal("no on-demand set configured must never wake")
	}
}

// The cached-proxy path in routes.go has its own ErrorHandler, built inside
// buildEntries where the *Server is not in scope. It must honour the same
// trigger — otherwise the behaviour would depend on whether the request went
// through a cached proxy or the handler's fallback, which is exactly the kind
// of two-code-paths-disagreeing defect this module has been burned by twice
// (#958, #959).
func TestCachedProxyWakesOnRefusal(t *testing.T) {
	var gotPath string
	sockPath := stubWaker(t, "waker-cached.sock", &gotPath)

	ip, port := refusedAddr(t)
	srv := &Server{
		onDemand:    &OnDemand{entries: map[string]bool{"asleep.example.com": true}},
		wakerSocket: sockPath,
	}
	// Built through LoadRoutes, not hand-assembled: only that path installs the
	// reload watcher the handler calls on every request, and it is also the
	// path production uses — a hand-built *Routes would exercise proxies the
	// real service never builds.
	routesFile := filepath.Join(t.TempDir(), "haproxy-routes.json")
	if err := os.WriteFile(routesFile, []byte(
		`{"asleep.example.com": ["`+ip+`", `+strconv.Itoa(port)+`]}`), 0o644); err != nil {
		t.Fatalf("write routes: %v", err)
	}
	routes := LoadRoutes(routesFile, nil)
	routes.onUpstreamError = srv.wakeUpstreamFailure
	srv.routes = routes
	srv.routeLookup = routes.Lookup

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://asleep.example.com/", nil)
	req.Host = "asleep.example.com"
	srv.handler().ServeHTTP(rec, req)

	if gotPath != "/_wake/asleep.example.com" {
		t.Fatalf("cached proxy must wake too; waker got %q (body: %s)",
			gotPath, rec.Body.String())
	}
}
