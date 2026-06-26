// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — host-native reverse-proxy skeleton
//
// Phase 0 Task 1.1: skeleton binary with flags, CA load, route-lookup stub,
// and an HTTP handler that reverse-proxies mapped hosts and stamps
// X-SecuBox-WAF: inspected on every response.
//
// Task 1.2: wired the real Routes loader (LoadRoutes / *Routes) so --routes
// parses haproxy-routes.json and the handler uses cached per-backend
// *httputil.ReverseProxy instances (no per-request allocation).
//
// Later tasks wire in the rules engine (Task 2.1) and ban table (Task 3.1).
// Server keeps the routeLookup func field so tests can still drive it without
// file I/O; main() sets it to routes.Lookup when --routes is provided.
//
// Design decision — Server struct:
//   - ca        *forge.CA          wired from --ca-cert/--ca-key (lazy: nil when
//                                  flags are empty, so tests don't need PEM files)
//   - routes    *Routes            hot-reload map; nil when --routes is empty
//   - routeLookup func(host)(ip,port,ok) — set to routes.Lookup in main(), or
//                                  injected directly by tests
//   - upstreamTimeout time.Duration
//
//   Rules / Ban fields will be added in Tasks 2.1 / 3.1.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/forge"
)

// Server is the sbxwaf reverse-proxy core.
type Server struct {
	// ca holds the loaded forging CA. May be nil when --ca-cert/--ca-key are not
	// provided (tests, non-TLS deployments).
	ca *forge.CA

	// routes is the hot-reloadable route map loaded from --routes.
	// Nil when --routes is empty (dev mode / no routes file).
	routes *Routes

	// routeLookup resolves a bare hostname (no port) to a backend ip:port.
	// Returns ok=false for unmapped hosts (→ 421).
	// In main(), set to routes.Lookup when routes != nil; tests can inject
	// a custom closure directly.
	routeLookup func(host string) (ip string, port int, ok bool)

	// upstreamTimeout is the per-request dial+response timeout for the
	// reverse-proxy transport.
	upstreamTimeout time.Duration
}

// handler returns an http.Handler that:
//  1. Calls routes.Maybe() (hot-reload check) if routes is set.
//  2. Strips the port from req.Host and calls routeLookup.
//  3. Returns 421 Misdirected Request for unmapped hosts.
//  4. Uses the cached *httputil.ReverseProxy from Routes (no per-request
//     allocation) when routes is set; falls back to a freshly-built proxy for
//     test-injected routeLookup closures that bypass Routes.
//  5. Adds X-SecuBox-WAF: inspected to every proxied response.
func (s *Server) handler() http.Handler {
	timeout := s.upstreamTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// Shared transport: one connection pool for all proxied backends.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}

	// Inject the transport into the Routes proxy cache so cached proxies share
	// the same pool.  Must be done before the first request; handler() is called
	// once at startup so this is safe.
	if s.routes != nil {
		s.routes.transport = transport
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hot-reload check: stat the routes file and swap the map if mtime changed.
		// Cheap when nothing changed (throttle=0 means one stat per call, but stat
		// is O(1) and not on the inner response path).
		if s.routes != nil {
			s.routes.Maybe()
		}

		// Strip port from Host header to get the bare hostname for lookup.
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			// No port present — use the Host value directly.
			host = r.Host
		}
		host = strings.ToLower(strings.TrimSpace(host))

		ip, port, ok := s.routeLookup(host)
		if !ok {
			http.Error(w, "421 Misdirected Request: no route for host "+host,
				http.StatusMisdirectedRequest)
			return
		}

		// Use the cached proxy from Routes when available (Task 1.2 perf goal:
		// no per-request *httputil.ReverseProxy allocation).
		var proxy *httputil.ReverseProxy
		if s.routes != nil {
			proxy = s.routes.ProxyFor(host)
		}
		if proxy == nil {
			// Fallback: tests that inject routeLookup without a *Routes, or a
			// race between Maybe() reload and ProxyFor (new entry not yet cached).
			target := &url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort(ip, strconv.Itoa(port)),
			}
			proxy = httputil.NewSingleHostReverseProxy(target)
			proxy.Transport = transport
			proxy.ModifyResponse = func(resp *http.Response) error {
				resp.Header.Set("X-SecuBox-WAF", "inspected")
				return nil
			}
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				w.Header().Set("X-SecuBox-WAF", "inspected")
				http.Error(w, "502 Bad Gateway: "+err.Error(), http.StatusBadGateway)
			}
		}

		proxy.ServeHTTP(w, r)
	})
}

// splitHostPort splits "host:port" into its components, parsing port as int.
// Exported to package scope so tests can call it directly.
func splitHostPort(addr string) (host string, port int, err error) {
	h, ps, e := net.SplitHostPort(addr)
	if e != nil {
		return "", 0, e
	}
	p, e := strconv.Atoi(ps)
	if e != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", ps, e)
	}
	return h, p, nil
}

func main() {
	listen := flag.String("listen", ":8080", "address to listen on (e.g. :8080 or 0.0.0.0:8080)")
	caCert := flag.String("ca-cert", "", "path to CA certificate PEM file (required for TLS forging)")
	caKey := flag.String("ca-key", "", "path to CA private key PEM file (or combined cert+key bundle)")
	routesFile := flag.String("routes", "", "path to haproxy-routes.json (hot-reloaded on mtime change)")
	rules := flag.String("rules", "", "path to rules file (loaded by Task 2.1)")
	upstreamTimeout := flag.Duration("upstream-timeout", 10*time.Second, "per-request upstream timeout")
	flag.Parse()

	// Silence "unused variable" lint for flags consumed in later tasks.
	_ = rules

	srv := &Server{
		upstreamTimeout: *upstreamTimeout,
	}

	// Wire in the real Routes loader when --routes is provided.
	if *routesFile != "" {
		r := LoadRoutes(*routesFile)
		srv.routes = r
		srv.routeLookup = r.Lookup
		log.Printf("sbxwaf: routes loaded from %s (%d entries)", *routesFile, func() int {
			r.mu.RLock()
			n := len(r.entries)
			r.mu.RUnlock()
			return n
		}())
	} else {
		// No routes file: answer 421 to every request (smoke-test / dev mode).
		srv.routeLookup = func(host string) (string, int, bool) {
			return "", 0, false
		}
	}

	// CA load is lazy: skip if flags are empty (dev mode / no TLS forging needed).
	if *caCert != "" || *caKey != "" {
		if *caCert == "" || *caKey == "" {
			log.Fatal("sbxwaf: --ca-cert and --ca-key must both be provided together")
		}
		ca, err := forge.LoadCA(*caCert, *caKey)
		if err != nil {
			log.Fatalf("sbxwaf: load CA: %v", err)
		}
		srv.ca = ca
		log.Printf("sbxwaf: CA loaded from %s", *caCert)
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("sbxwaf: listening on %s", *listen)
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatalf("sbxwaf: %v", err)
	}
}
