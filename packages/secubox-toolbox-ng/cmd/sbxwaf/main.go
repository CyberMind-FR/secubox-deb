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
// Task 3.2: graduated WARNING/BAN responses + threat log.
//   - Server gains ban *Ban and threatLog *ThreatLog fields.
//   - On a WAF hit: ban.Record(clientIP, now) → if banned → writeBan + log
//     "banned"; else → writeWarning + log "warning".
//   - threatLog is set by main() via NewThreatLog(--threat-log path).
//   - crowdsec seam: Server.crowdsec (nil-able interface, see below) is the
//     hook point for Task 4.1 — call crowdsec.Report(ip, cat, sev) when
//     banned, guarded by nil-check so the field is entirely optional.
//
// Design decision — Server struct:
//   - ca        *forge.CA          wired from --ca-cert/--ca-key (lazy: nil when
//                                  flags are empty, so tests don't need PEM files)
//   - routes    *Routes            hot-reload map; nil when --routes is empty
//   - routeLookup func(host)(ip,port,ok) — set to routes.Lookup in main(), or
//                                  injected directly by tests
//   - upstreamTimeout time.Duration
//   - ban       *Ban               sliding-window ban state; NewBan(300s,3) in main()
//   - threatLog *ThreatLog         append-only JSON threat log; NewThreatLog in main()
//   - crowdsec  CrowdSecReporter   Task 4.1 seam — nil until wired; see interface below
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
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

// CrowdSecReporter is the seam for Task 4.1 — CrowdSec LAPI bridge.
// When a client IP is banned, the handler calls crowdsec.Report if the field
// is non-nil.  Task 4.1 implements a concrete type (e.g. *CrowdSecClient) and
// wires it into Server.crowdsec in main().
//
// TODO(task-4.1): implement CrowdSecClient satisfying this interface and wire
// it via --crowdsec-url / --crowdsec-machine-id / --crowdsec-password flags.
type CrowdSecReporter interface {
	// Report submits a ban alert for ip to the CrowdSec LAPI.
	// cat and sev are the WAF category and severity strings.
	// Must be non-blocking (should run in a goroutine if the LAPI call can block).
	Report(ip, cat, sev string)
}

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

	// transport is the shared *http.Transport used by all reverse-proxy
	// instances.  Constructed in main() BEFORE LoadRoutes so that startup-built
	// proxies use the same tuned pool.  When nil, handler() creates a local
	// transport from upstreamTimeout (backwards-compat for test-only Servers
	// that don't inject a transport).
	transport http.RoundTripper

	// rules is the hot-reloadable WAF rule set loaded from --rules.
	// Nil when --rules is empty (pass-through mode, no inspection).
	// Wired in main() via LoadRules; tests can inject directly.
	rules *Rules

	// ban tracks per-IP threat hit counts in a sliding window.
	// Wired in main() via NewBan(300s, 3); tests can inject directly.
	// Nil means no ban tracking (legacy: plain 403 on WAF hit).
	ban *Ban

	// threatLog appends one JSON line per WAF hit to the threats log file.
	// Wired in main() via NewThreatLog(--threat-log); tests can inject.
	// Nil means no threat logging.
	threatLog *ThreatLog

	// crowdsec is the Task 4.1 CrowdSec LAPI bridge seam.
	// Nil until Task 4.1 is implemented and wired in main().
	// When non-nil: called with (ip, cat, sev) whenever an IP reaches BAN.
	crowdsec CrowdSecReporter
}

// handler returns an http.Handler that:
//  1. Calls routes.Maybe() (hot-reload check) if routes is set.
//  2. Strips the port from req.Host and calls routeLookup.
//  3. Returns 421 Misdirected Request for unmapped hosts.
//  4. Uses the cached *httputil.ReverseProxy from Routes (no per-request
//     allocation) when routes is set; falls back to a freshly-built proxy for
//     test-injected routeLookup closures that bypass Routes.
//  5. Adds X-SecuBox-WAF: inspected to every proxied response.
//  6. (Task 2.2) When rules != nil, inspects the request before proxying:
//     - Computes clientIP (XFF when peer is a trusted proxy, else peer).
//     - Skips inspection for private/RFC1918 CIDRs (privateCIDR).
//     - Skips inspection for static assets and health/status paths (staticAsset).
//     - Skips inspection for NC mobile-auth paths (ncBypass).
//     - Reads up to maxBodyInspect bytes for inspection; restores the FULL
//       body (prefix + remaining stream via io.MultiReader) so the upstream
//       proxy always receives every byte intact — no truncation.
//     - On WAF hit: returns 403 Forbidden (Task 3.2 refines to WARNING/BAN).
//     - Adds Connection: close to upstream requests (#496).
func (s *Server) handler() http.Handler {
	// Use the shared transport injected at construction time (main() builds it
	// before LoadRoutes so startup proxies already reference it).  Fall back to
	// a fresh local transport for test Servers that don't inject one.
	transport := s.transport
	if transport == nil {
		timeout := s.upstreamTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			ResponseHeaderTimeout: timeout,
		}
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

		// Task 2.2 — Request inspection.
		// Only when rules are loaded; otherwise pass through unconditionally.
		if s.rules != nil {
			// Add Connection: close to upstream requests (#496, mirrors Python).
			r.Header.Set("Connection", "close")

			ip := clientIP(r)
			// Determine the path for skip-list checks. Use RawPath when available
			// (Go only sets it when the path contains percent-encoded chars that
			// differ from the decoded form), falling back to Path. This ensures
			// we pass the still-encoded path to staticAsset/ncBypass (which do
			// lowercasing but do not need decoded content for suffix/contains checks).
			rawPath := r.URL.RawPath
			if rawPath == "" {
				rawPath = r.URL.Path
			}

			skip := privateCIDR(ip) || staticAsset(rawPath) || ncBypass(rawPath)
			if !skip {
				// Read up to maxBodyInspect bytes for WAF inspection, then
				// restore the FULL body (prefix + remaining stream) so the
				// upstream proxy receives every byte intact.
				//
				// Streaming approach: we buffer at most 1 MiB (the inspection
				// window), then forward a MultiReader of that buffer + the
				// unconsumed tail of r.Body.  This keeps memory bounded even
				// for multi-GB uploads (PeerTube / Nextcloud file uploads).
				var bodyBytes []byte
				if r.Body != nil {
					prefix, _ := io.ReadAll(io.LimitReader(r.Body, maxBodyInspect))
					bodyBytes = prefix
					// Restore: prefix already read + remaining stream not yet consumed.
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
				}

				cat, sev, hit := s.rules.Match(
					r.Method,
					rawPath,
					r.URL.RawQuery,
					string(bodyBytes),
					r.Header.Get("User-Agent"),
				)
				if hit {
					// Task 3.2 — graduated WARNING/BAN response.
					//
					// When ban is wired (always in production), record the hit and
					// return a graduated response:
					//   count < threshold → WARNING (403, warning page)
					//   count >= threshold → BAN    (403, ban page)
					//
					// When ban is nil (legacy / no ban tracking), fall back to a
					// plain 403 so tests that don't inject ban still pass.
					if s.ban == nil {
						http.Error(w, "403 Forbidden: WAF blocked this request", http.StatusForbidden)
						return
					}

					count, banned := s.ban.Record(ip, time.Now().Unix())
					action := "warning"
					if banned {
						action = "banned"
					}

					// Log threat (best-effort: nil threatLog is a no-op).
					if s.threatLog != nil {
						s.threatLog.Record(ThreatRecord{
							ClientIP: ip,
							Host:     r.Host,
							Method:   r.Method,
							Path:     rawPath,
							Category: cat,
							Severity: sev,
							// rules.Match does not return a rule ID in its current
							// signature (returns cat, sev, hit). RuleID is left empty
							// here; Task 2.x can extend Match to return it if needed.
							RuleID: "",
							Action: action,
							UA:     r.Header.Get("User-Agent"),
						})
					}

					log.Printf("sbxwaf: THREAT [%s] %s (%d/%d): %s",
						sev, ip, count, 3, cat)

					if banned {
						// Task 4.1 seam — notify CrowdSec LAPI when non-nil.
						if s.crowdsec != nil {
							go s.crowdsec.Report(ip, cat, sev)
						}
						writeBan(w)
					} else {
						writeWarning(w, cat)
					}
					return
				}
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
	threatLog := flag.String("threat-log", "/var/log/secubox/waf-threats.log",
		"path for append-only WAF threat log (NDJSON, one record per hit)")
	flag.Parse()

	// rules is consumed below when --rules is provided.

	// Build the shared transport FIRST so it can be passed to LoadRoutes.
	// Every proxy — startup-built and reload-built — will share this pool and
	// dial timeout.  The same pointer is stored in srv.transport for the
	// handler's fallback path.
	sharedTransport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: *upstreamTimeout,
		}).DialContext,
		ResponseHeaderTimeout: *upstreamTimeout,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}

	srv := &Server{
		upstreamTimeout: *upstreamTimeout,
		transport:       sharedTransport,
		// Task 3.2: graduated ban (window=300s, threshold=3, matches Python
		// BAN_WINDOW=300 / BAN_THRESHOLD=3 from secubox_waf.py lines 82-83).
		ban: NewBan(300*time.Second, 3),
		// Task 3.2: append-only threat log.
		threatLog: NewThreatLog(*threatLog),
		// crowdsec: nil — wired in Task 4.1 via --crowdsec-* flags.
	}
	log.Printf("sbxwaf: ban window=300s threshold=3; threat-log=%s", *threatLog)

	// Wire in the WAF rules engine when --rules is provided.
	if *rules != "" {
		srv.rules = LoadRules(*rules)
		log.Printf("sbxwaf: WAF rules loaded from %s", *rules)
	}

	// Wire in the real Routes loader when --routes is provided.
	if *routesFile != "" {
		r := LoadRoutes(*routesFile, sharedTransport)
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
