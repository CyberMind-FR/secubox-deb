// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — host-native reverse-proxy skeleton
//
// Phase 0 Task 1.1: skeleton binary with flags, CA load, route-lookup stub,
// and an HTTP handler that reverse-proxies mapped hosts and stamps
// X-SecuBox-WAF: inspected on every response.
//
// Later tasks wire in the real Routes loader (Task 1.2), rules engine (Task 2.1)
// and ban table (Task 3.1). For now Server holds a routeLookup func field so
// tests can drive it without any file I/O.
//
// Design decision — Server struct:
//   - ca        *forge.CA          wired from --ca-cert/--ca-key (lazy: nil when
//                                  flags are empty, so tests don't need PEM files)
//   - routeLookup func(host)(ip,port,ok) — stub for Task 1.2 to replace with
//                                  *Routes; kept as a field so both tests and
//                                  cmd/main can inject it cleanly
//   - upstreamTimeout time.Duration
//
//   Routes / Rules / Ban fields will be added in Tasks 1.2 / 2.1 / 3.1 as those
//   packages are implemented. They are NOT declared here to avoid stub coupling.
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

// Server is the sbxwaf reverse-proxy core. Fields intentionally minimal for
// Task 1.1; later tasks will extend the struct.
type Server struct {
	// ca holds the loaded forging CA. May be nil when --ca-cert/--ca-key are not
	// provided (tests, non-TLS deployments).
	ca *forge.CA

	// routeLookup resolves a bare hostname (no port) to a backend ip:port.
	// Returns ok=false for unmapped hosts (→ 421).
	// Task 1.2 will replace this with a *Routes wrapper loaded from --routes.
	routeLookup func(host string) (ip string, port int, ok bool)

	// upstreamTimeout is the per-request dial+response timeout for the
	// reverse-proxy transport.
	upstreamTimeout time.Duration
}

// handler returns an http.Handler that:
//  1. Strips the port from req.Host and calls routeLookup.
//  2. Returns 421 Misdirected Request for unmapped hosts.
//  3. Reverse-proxies matched requests to http://ip:port via httputil.ReverseProxy.
//  4. Adds X-SecuBox-WAF: inspected to every proxied response.
func (s *Server) handler() http.Handler {
	timeout := s.upstreamTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		target := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(ip, strconv.Itoa(port)),
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = transport

		// ModifyResponse stamps the WAF sentinel header on every proxied response.
		proxy.ModifyResponse = func(resp *http.Response) error {
			resp.Header.Set("X-SecuBox-WAF", "inspected")
			return nil
		}

		// ErrorHandler: surface transport errors as 502 with the WAF header.
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("X-SecuBox-WAF", "inspected")
			http.Error(w, "502 Bad Gateway: "+err.Error(), http.StatusBadGateway)
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
	routes := flag.String("routes", "", "path to routes JSON/TOML file (loaded by Task 1.2)")
	rules := flag.String("rules", "", "path to rules file (loaded by Task 2.1)")
	upstreamTimeout := flag.Duration("upstream-timeout", 10*time.Second, "per-request upstream timeout")
	flag.Parse()

	// Silence "unused variable" lint for flags consumed in later tasks.
	_ = routes
	_ = rules

	srv := &Server{
		upstreamTimeout: *upstreamTimeout,
		// routeLookup: nil-safe stub — all hosts unmapped until Task 1.2 wires
		// in the real Routes loader. This lets the binary start without a routes
		// file and answer 421 to every request (useful for smoke-testing).
		routeLookup: func(host string) (string, int, bool) {
			return "", 0, false
		},
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
