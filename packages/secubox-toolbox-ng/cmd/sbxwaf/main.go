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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/forge"
	"golang.org/x/net/http/httpguts"
)

// isWebSocketUpgrade reports whether r is a WebSocket handshake, using the same
// header semantics as net/http/httputil.ReverseProxy: the Connection header must
// contain the "Upgrade" token (comma list, case-insensitive) AND Upgrade must be
// "websocket". #796 — we must NOT rewrite Connection on these requests, or the
// ReverseProxy stops tunnelling the WebSocket.
func isWebSocketUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h["Connection"], "Upgrade") &&
		strings.EqualFold(h.Get("Upgrade"), "websocket")
}

// upstreamErrorCode maps a round-trip error to the appropriate HTTP error code,
// mirroring the Python error() hook logic (~line 1106):
//   - net.Error with Timeout() → 504 Gateway Timeout
//   - connection refused / dial failure → 502 Bad Gateway
//   - all other errors → 503 Service Unavailable
func upstreamErrorCode(err error) int {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return http.StatusGatewayTimeout // 504
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "dial") {
		return http.StatusBadGateway // 502
	}
	return http.StatusServiceUnavailable // 503
}

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

	// escalateBan counts hits on `escalate`-mode categories in a SEPARATE
	// sliding window (long, e.g. 24h) from `ban`. escalate observes (passes,
	// logs "detect") until this counter says banned, then bans via crowdsec.
	// Nil means escalate behaves like detect (observe, never ban).
	escalateBan *Ban

	// threatLog appends one JSON line per WAF hit to the threats log file.
	// Wired in main() via NewThreatLog(--threat-log); tests can inject.
	// Nil means no threat logging.
	threatLog *ThreatLog

	// crowdsec is the Task 4.1 CrowdSec LAPI bridge seam.
	// Nil until Task 4.1 is implemented and wired in main().
	// When non-nil: called with (ip, cat, sev) whenever an IP reaches BAN.
	crowdsec CrowdSecReporter

	// maxBodyInspect is the per-request body inspection cap in bytes.
	// Only the first maxBodyInspect bytes of the request body are passed to
	// Rules.Match; the remainder is streamed to the upstream uninspected.
	// Payloads injected beyond this offset will NOT be detected — this is a
	// documented parity gap vs the Python WAF (full-body scan).
	// Set from --max-body-inspect; defaults to defaultMaxBodyInspect (1 MiB).
	// When a body exceeds the cap an AUDIT log line is emitted (action:
	// "body-inspect-truncated") so truncation events are operator-visible.
	maxBodyInspect int64

	// trustedHosts is the set of hostnames that bypass WAF inspection entirely.
	// Mirrors Python check_request whitelist (secubox_waf.py:761-763):
	// git.gk2.secubox.in, git.secubox.in, admin.gk2.secubox.in, 10.100.0.1:9080.
	// Gitea push payloads and admin panel forms routinely contain content that
	// would trip WAF rules — this skip prevents false-positive bans on internal
	// services. Configurable via --waf-skip-hosts.
	trustedHosts map[string]struct{}

	// cookieAudit is the Task 5.1 RGPD Set-Cookie ledger.
	// When non-nil, ModifyResponse calls Record for every upstream response.
	// Nil means auditing is disabled (--cookie-audit-log="").
	cookieAudit *CookieAudit

	// mediaCache is the Task 6.1 response media cache.
	// When non-nil, GET requests are served from cache on a hit (bypassing
	// the upstream); cacheable responses on a miss are stored after proxying.
	// Nil means caching is disabled (--media-cache-dir="").
	mediaCache *MediaCache

	// visits is the #747 non-attacker visit-statistics aggregator. When non-nil,
	// every LEGITIMATE (non-blocked, non-misdirected) response is tallied by
	// client-type / OS / vhost / status / top-IP and flushed to a JSON snapshot
	// the WAF API geo-maps for the dashboard Visits panel. Nil disables it.
	visits *VisitStats

	// widgetHosts are the first-party host suffixes (gk2.secubox.in, …) into whose
	// HTML responses the WAF injects the SecuBox health banner (#747). Empty
	// disables injection. Set from --widget-hosts.
	widgetHosts []string

	// bannerOrigin is the canonical Hub origin (absolute, e.g.
	// https://admin.gk2.secubox.in) the injected health-banner loads its asset +
	// metrics APIs from (CDN-injected mode). Empty disables injection.
	bannerOrigin string
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
		// #747 — wrap the writer so we can tally the visit's final status. The
		// defer records every LEGITIMATE response (excludes the WAF-block 403 and
		// the unmapped-host 421) into the visit-stats aggregator.
		var visitHost string
		if s.visits != nil {
			sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			w = sr
			defer func() {
				if sr.status != http.StatusForbidden && sr.status != http.StatusMisdirectedRequest {
					s.visits.Record(visitHost, r.UserAgent(), clientIP(r), sr.status)
				}
			}()
		}

		// Hot-reload check: stat the routes file and swap the map if mtime changed.
		// Cheap when nothing changed (throttle=0 means one stat per call, but stat
		// is O(1) and not on the inner response path).
		if s.routes != nil {
			s.routes.Maybe()
		}
		// Same for the rules file: an operator flipping a category to detect (or
		// editing any rule) must take effect without restarting the WAF that
		// fronts every vhost. Match takes an RLock, Apply takes the Lock — the
		// swap is race-safe (go test -race clean). Same one-stat cost as routes.
		if s.rules != nil {
			s.rules.Maybe()
		}

		// Strip port from Host header to get the bare hostname for lookup.
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			// No port present — use the Host value directly.
			host = r.Host
		}
		host = strings.ToLower(strings.TrimSpace(host))
		visitHost = host

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
				// Task 5.1: record Set-Cookie to RGPD ledger when enabled.
				// host is bound per-request (outer HandlerFunc scope).
				if ca := s.cookieAudit; ca != nil {
					ca.Record(host, resp.Request, resp)
				}
				// #747: inject the SecuBox health/visit widget on first-party HTML.
				applyWidget(resp, host, s.bannerOrigin, s.widgetHosts)
				return nil
			}
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				// Task 7.1: themed error pages — mirror the Python error() hook mapping.
				// Timeout → 504, connection refused → 502, other → 503.
				code := upstreamErrorCode(err)
				reqHost := r.Host
				if bare, _, e := net.SplitHostPort(reqHost); e == nil {
					reqHost = bare
				}
				writeErrorPage(w, code, reqHost)
			}
		}

		// Task 2.2 — Request inspection.
		// Only when rules are loaded; otherwise pass through unconditionally.
		if s.rules != nil {
			// Add Connection: close to upstream requests (#496, mirrors Python) —
			// but NEVER on a WebSocket upgrade: that would clobber Connection:
			// Upgrade and stop httputil.ReverseProxy from tunnelling the WS,
			// turning wss:// vhosts into a plain GET → 404/1006 (#796).
			if !isWebSocketUpgrade(r.Header) {
				r.Header.Set("Connection", "close")
			}

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

			// Trusted-host skip: bypass WAF inspection for known internal hosts
			// (matches Python check_request whitelist in secubox_waf.py:761-763).
			// Checked AFTER privateCIDR/static/NC so that the cheap skips run first.
			if !skip && s.isTrustedHost(r.Host) {
				skip = true
			}

			if !skip {
				// Read up to s.maxBodyInspect bytes for WAF inspection, then
				// restore the FULL body (prefix + remaining stream) so the
				// upstream proxy receives every byte intact.
				//
				// Streaming approach: we buffer at most maxBodyInspect bytes (the
				// inspection window), then forward a MultiReader of that buffer +
				// the unconsumed tail of r.Body. This keeps memory bounded even
				// for multi-GB uploads (PeerTube / Nextcloud file uploads).
				//
				// PARITY GAP: only the first maxBodyInspect bytes are inspected.
				// A payload appended after that offset is NOT detected. When a body
				// exceeds the cap, an AUDIT log line is emitted so truncation is
				// operator-visible (action="body-inspect-truncated"). See
				// docs/CUTOVER.md for the documented detection gap.
				cap := s.maxBodyInspect
				if cap <= 0 {
					cap = defaultMaxBodyInspect
				}
				var bodyBytes []byte
				if r.Body != nil {
					prefix, _ := io.ReadAll(io.LimitReader(r.Body, cap))
					bodyBytes = prefix
					// Restore: prefix already read + remaining stream not yet consumed.
					r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))

					// Emit audit log when inspection was truncated (Content-Length known
					// or body read returned exactly cap bytes → likely more data follows).
					if int64(len(prefix)) == cap {
						if s.threatLog != nil {
							s.threatLog.Record(ThreatRecord{
								ClientIP: ip,
								Host:     r.Host,
								Method:   r.Method,
								Path:     rawPath,
								Category: "body-inspect-truncated",
								Severity: "audit",
								Action:   "body-inspect-truncated",
								UA:       r.Header.Get("User-Agent"),
							})
						}
						log.Printf("sbxwaf: AUDIT body-inspect-truncated host=%s path=%s ip=%s cap=%d",
							r.Host, rawPath, ip, cap)
					}
				}

				cat, sev, mode, hit := s.rules.Match(
					r.Method,
					rawPath,
					r.URL.RawQuery,
					string(bodyBytes),
					r.Header.Get("User-Agent"),
				)
				if hit && mode == modeDetect {
					// Observe only: log it, let it through. A detect category
					// must be as harmless as enabled:false, minus the log line
					// — so NO ban, NO CrowdSec report, NO nft decision, NO
					// ban-counter increment.
					if s.threatLog != nil {
						s.threatLog.Record(ThreatRecord{
							ClientIP: ip,
							Host:     r.Host,
							Method:   r.Method,
							Path:     rawPath,
							Category: cat,
							Severity: sev,
							RuleID:   "",
							Action:   "detect",
							UA:       r.Header.Get("User-Agent"),
						})
					}
					hit = false // fall through to the normal proxy path
				}
				if hit && mode == modeEscalate {
					// Observe first, ban a persistent scanner. Uses a SEPARATE
					// counter (escalateBan) so probes for absent products never
					// mix with the block-mode ban signal. Self-contained: it does
					// NOT fall through to the block path below, which would double
					// count into s.ban.
					if s.escalateBan == nil {
						// No counter → observe like detect, never ban.
						s.logEscalate(r, ip, rawPath, cat, sev, "detect")
						hit = false
					} else if count, banned := s.escalateBan.Record(ip, time.Now().Unix()); banned {
						// Threshold crossed: ban for real, exactly as the block
						// path's ban branch does — but gated on escalateBan.
						s.logEscalate(r, ip, rawPath, cat, sev, "banned")
						// Mirror the block path's journald line so an operator
						// tailing `journalctl -u secubox-waf-ng` for THREAT sees
						// escalate bans too — otherwise a banned scanner is
						// visible in the dashboard JSON but silent in the logs.
						log.Printf("sbxwaf: THREAT [%s] %s (escalate %d): %s", sev, ip, count, cat)
						if s.crowdsec != nil {
							go s.crowdsec.Report(ip, cat, sev)
						}
						writeBan(w)
						return
					} else {
						// Still observing: log and let it through.
						s.logEscalate(r, ip, rawPath, cat, sev, "detect")
						hit = false
					}
				}
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

		// Task 6.1 — media cache hit: serve from disk, bypass upstream.
		// Only for GET requests; cache is nil-safe.
		//
		// Cache key is composed from vhost + path+query so that two different
		// vhosts serving the same asset path (/logo.png) get distinct keys and
		// never cross-contaminate each other's cached content (vhost isolation;
		// mirrors Python media_cache.py r.pretty_url which includes the host).
		if s.mediaCache != nil && r.Method == http.MethodGet {
			vhostCacheURL := "https://" + r.Host + r.URL.RequestURI()
			if cachedBody, cachedHdr, hit := s.mediaCache.Get(vhostCacheURL, r.Header.Get("Accept-Encoding")); hit {
				for k, vs := range cachedHdr {
					for _, v := range vs {
						w.Header().Set(k, v)
					}
				}
				w.Header().Set("X-SecuBox-Cache", "hit")
				w.Header().Set("X-SecuBox-WAF", "inspected")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(cachedBody)
				return
			}

			// Cache miss: wrap the proxy's ModifyResponse to capture and store the
			// response body after proxying. We need a wrapping proxy here so we can
			// intercept ModifyResponse without altering the cached proxy instance.
			//
			// Strategy: build a thin wrapper around the real proxy's transport that
			// buffers (up to maxObj bytes) and stores the response body.  We cannot
			// override proxy.ModifyResponse on a shared cached proxy safely, so
			// instead we use a ResponseWriter wrapper that tees the body to cache.
			//
			// Use a capturing ResponseWriter: let the upstream write normally to
			// the real ResponseWriter but simultaneously capture response headers +
			// body for MaybeStore.  The client always receives the full body —
			// we only buffer up to maxObj bytes for the cache and discard the rest
			// (the real body still flows through to the client).
			cw := &cachingResponseWriter{
				ResponseWriter: w,
				maxCapture:     s.mediaCache.maxObj,
			}

			// Wire a ModifyResponse on the fallback proxy path that we'll replace
			// if using a cached proxy. For the cached-proxy path, we instead use
			// a post-ServeHTTP hook via cw.
			//
			// Build an ad-hoc proxy that wraps the response via ModifyResponse.
			// We clone the existing proxy's behaviour but intercept ModifyResponse
			// to capture the body.  This avoids mutating the shared proxy instance.
			//
			// Simplest correct approach: let the real proxy handle the response
			// (including its own ModifyResponse for WAF headers), then store
			// whatever cw captured.
			proxy.ServeHTTP(cw, r)

			// After proxying: if the response was cacheable and we captured enough
			// of the body, store it.  The full body was already written to the
			// client by the real proxy — we only stored a copy.
			// Synchronous: MaybeStore is fast (disk write) and must complete before
			// the next request can get a cache hit.
			sc := cw.statusCode
			if sc == 0 {
				sc = http.StatusOK // implicit 200 when WriteHeader was never called
			}
			if sc == http.StatusOK && cw.captured {
				s.mediaCache.MaybeStore(r, &http.Response{
					StatusCode: sc,
					Header:     cw.respHeader,
				}, cw.body, vhostCacheURL)
			}
			return
		}

		proxy.ServeHTTP(w, r)
	})
}

// logEscalate writes one threat record for an escalate-mode hit. `action` is
// "detect" while observing and "banned" once the threshold is crossed.
func (s *Server) logEscalate(r *http.Request, ip, rawPath, cat, sev, action string) {
	if s.threatLog == nil {
		return
	}
	s.threatLog.Record(ThreatRecord{
		ClientIP: ip,
		Host:     r.Host,
		Method:   r.Method,
		Path:     rawPath,
		Category: cat,
		Severity: sev,
		RuleID:   "",
		Action:   action,
		UA:       r.Header.Get("User-Agent"),
	})
}

// parseTrustedHosts parses a comma-separated list of hostnames into a set.
// Empty entries are silently skipped.
func parseTrustedHosts(csv string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, h := range strings.Split(csv, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			m[strings.ToLower(h)] = struct{}{}
		}
	}
	return m
}

// isTrustedHost reports whether the given Host header value (with optional port)
// belongs to the trusted-host whitelist. Matches the Python check_request
// trusted-host skip (secubox_waf.py:761-763). Checked before WAF inspection so
// internal services (gitea, admin panel) are never WAF-inspected or banned.
func (s *Server) isTrustedHost(hostHeader string) bool {
	if len(s.trustedHosts) == 0 {
		return false
	}
	lh := strings.ToLower(strings.TrimSpace(hostHeader))
	if _, ok := s.trustedHosts[lh]; ok {
		return true
	}
	// Also check bare hostname (without port) in case hostHeader includes a port.
	bare, _, err := net.SplitHostPort(lh)
	if err == nil {
		if _, ok := s.trustedHosts[bare]; ok {
			return true
		}
	}
	return false
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
	threatLog := flag.String("threat-log", "/var/log/secubox/waf/waf-threats.log",
		"path for append-only WAF threat log (NDJSON, one record per hit)")
	// Task 4.1: CrowdSec LAPI bridge flags.
	crowdsecURL := flag.String("crowdsec-url", "",
		"CrowdSec LAPI base URL (e.g. http://10.100.0.1:8080); empty disables the bridge")
	crowdsecJWTFile := flag.String("crowdsec-jwt-file", "",
		"path to file containing the CrowdSec LAPI JWT/API key (read once at startup)")
	crowdsecBanDuration := flag.String("crowdsec-ban-duration", "4h",
		"ban duration forwarded to CrowdSec decisions (e.g. 4h, 24h)")
	crowdsecCscli := flag.String("crowdsec-cscli", "cscli",
		"cscli binary used to inject ban decisions when no --crowdsec-jwt-file is set "+
			"(the proven path the WAF dashboard's manual ban uses); empty disables the cscli fallback")
	// Task 5.1: RGPD Set-Cookie ledger.
	cookieAuditLog := flag.String("cookie-audit-log", DefaultCookieAuditLog,
		"path for RGPD cookie audit JSONL ledger (one record per Set-Cookie); empty disables")
	// Task 6.1: response media cache.
	mediaCacheDir := flag.String("media-cache-dir", "/var/cache/secubox/waf/media",
		"directory for the response media cache (16 MiB/obj, 2 GiB total); empty disables")
	// #747: non-attacker visit statistics — aggregate legit traffic (client type,
	// OS, vhost, status, top IPs) flushed to a JSON snapshot the WAF API geo-maps.
	visitsStats := flag.String("visits-stats", "/var/log/secubox/waf/visits-stats.json",
		"path for the non-attacker visit-stats JSON snapshot (client type/OS/vhost/geo); empty disables")
	// #747: WAF-injected SecuBox health banner on FIRST-PARTY sites (HTML only).
	widgetHosts := flag.String("widget-hosts", "gk2.secubox.in,secubox.in,cybermind.fr,maegia.tv",
		"comma-separated first-party host suffixes to inject the SecuBox health banner into; empty disables")
	bannerOrigin := flag.String("health-banner-origin", "https://admin.gk2.secubox.in",
		"absolute Hub origin the injected health banner loads its asset + metrics APIs from (CDN-injected); empty disables")
	// Body inspection cap: only the first N bytes of the request body are scanned.
	// Payloads beyond this offset are NOT inspected (documented parity gap vs Python full-body scan).
	// Raise for stricter coverage; truncation events are always audit-logged regardless of this cap.
	maxBodyInspectFlag := flag.Int64("max-body-inspect", defaultMaxBodyInspect,
		"max bytes of request body to inspect for WAF rules (default 1 MiB); truncation is audit-logged")
	// Trusted-host skip: WAF inspection is bypassed for these hostnames (comma-separated).
	// Mirrors Python check_request whitelist (secubox_waf.py:761-763).
	// Default list matches the Python source: git.gk2.secubox.in, git.secubox.in,
	// admin.gk2.secubox.in, 10.100.0.1:9080.
	wafSkipHosts := flag.String("waf-skip-hosts",
		"git.gk2.secubox.in,git.secubox.in,admin.gk2.secubox.in,10.100.0.1:9080",
		"comma-separated hostnames to bypass WAF inspection entirely (mirrors Python trusted-host list)")
	// escalate mode: separate long-window counter (a slow scanner probing over
	// hours/days must still trip a ban even though each individual probe is
	// only observed, not blocked).
	escalateWindow := flag.Duration("escalate-window", 24*time.Hour,
		"sliding window for escalate-mode categories (a slow scanner needs a long window)")
	escalateThreshold := flag.Int("escalate-threshold", 3,
		"probes within the escalate window before an IP is banned")
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

	// Task 5.1: RGPD cookie-audit ledger. Disabled when --cookie-audit-log is empty.
	var cookieAudit *CookieAudit
	if *cookieAuditLog != "" {
		cookieAudit = NewCookieAudit(*cookieAuditLog)
		log.Printf("sbxwaf: cookie-audit ledger enabled → %s", *cookieAuditLog)
	}

	// Task 6.1: response media cache. Disabled when --media-cache-dir is empty.
	var mediaCache *MediaCache
	if *mediaCacheDir != "" {
		mediaCache = NewMediaCache(*mediaCacheDir)
		log.Printf("sbxwaf: media-cache enabled → %s (maxObj=16MiB, maxTotal=2GiB)", *mediaCacheDir)
	}

	// #747: non-attacker visit statistics. Disabled when --visits-stats is empty.
	var visits *VisitStats
	if *visitsStats != "" {
		visits = NewVisitStats(*visitsStats)
		log.Printf("sbxwaf: visit-stats enabled → %s (flush %s)", *visitsStats, visitFlushInterval)
	}

	srv := &Server{
		upstreamTimeout: *upstreamTimeout,
		transport:       sharedTransport,
		// Task 3.2: graduated ban (window=300s, threshold=3, matches Python
		// BAN_WINDOW=300 / BAN_THRESHOLD=3 from secubox_waf.py lines 82-83).
		ban: NewBan(300*time.Second, 3),
		// escalate mode: separate long-window counter (default 24h/3).
		escalateBan: NewBan(*escalateWindow, *escalateThreshold),
		// Task 3.2: append-only threat log.
		threatLog: NewThreatLog(*threatLog),
		// crowdsec: wired below when --crowdsec-url and --crowdsec-jwt-file are set.
		// Task 5.1: RGPD cookie-audit ledger.
		cookieAudit: cookieAudit,
		// Task 6.1: response media cache.
		mediaCache: mediaCache,
		// #747: non-attacker visit statistics.
		visits: visits,
		// #747: first-party host suffixes + Hub origin for the injected health banner.
		widgetHosts:  splitCSV(*widgetHosts),
		bannerOrigin: strings.TrimSpace(*bannerOrigin),
		// Body inspection cap (--max-body-inspect).
		maxBodyInspect: *maxBodyInspectFlag,
		// Trusted-host skip (--waf-skip-hosts): mirrors Python whitelist.
		trustedHosts: parseTrustedHosts(*wafSkipHosts),
	}
	log.Printf("sbxwaf: ban window=300s threshold=3; threat-log=%s", *threatLog)
	log.Printf("sbxwaf: body-inspect cap=%d bytes; trusted-skip hosts=%d", *maxBodyInspectFlag, len(srv.trustedHosts))

	// Task 4.1: wire CrowdSec LAPI bridge when both --crowdsec-url and
	// --crowdsec-jwt-file are provided.  The JWT is read from a file so the
	// secret never appears in the process command line or environment.
	if *crowdsecURL != "" && *crowdsecJWTFile != "" {
		jwtBytes, err := os.ReadFile(*crowdsecJWTFile)
		if err != nil {
			log.Fatalf("sbxwaf: crowdsec: read jwt-file %q: %v", *crowdsecJWTFile, err)
		}
		jwt := strings.TrimSpace(string(jwtBytes))
		srv.crowdsec = NewCrowdSecClient(*crowdsecURL, jwt, *crowdsecBanDuration)
		log.Printf("sbxwaf: CrowdSec LAPI bridge enabled → %s (ban-duration=%s)",
			*crowdsecURL, *crowdsecBanDuration)
	} else if *crowdsecURL != "" && *crowdsecCscli != "" {
		// No JWT file: use the cscli fallback (the LAPI /v1/alerts path 500s on
		// this build and JWTs expire hourly). This is the path that actually
		// creates a bouncer-enforced nft drop, so auto-bans finally take effect.
		srv.crowdsec = NewCscliReporter(*crowdsecCscli, *crowdsecBanDuration)
		log.Printf("sbxwaf: CrowdSec bridge enabled via cscli %q (ban-duration=%s)",
			*crowdsecCscli, *crowdsecBanDuration)
	} else if *crowdsecURL != "" || *crowdsecJWTFile != "" {
		log.Printf("sbxwaf: crowdsec bridge disabled — set --crowdsec-url (+ --crowdsec-cscli or --crowdsec-jwt-file)")
	}

	// Wire in the WAF rules engine when --rules is provided.
	if *rules != "" {
		srv.rules = LoadRules(*rules)
		log.Printf("sbxwaf: WAF rules loaded from %s", *rules)
	}

	// Wire in the real Routes loader when --routes is provided.
	if *routesFile != "" {
		r := LoadRoutes(*routesFile, sharedTransport)
		// Task 5.1: inject cookie audit so Routes-built proxies also record cookies.
		r.cookieAudit = cookieAudit
		r.widgetHosts = srv.widgetHosts
		r.bannerOrigin = srv.bannerOrigin
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
