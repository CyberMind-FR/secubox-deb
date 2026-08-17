// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — haproxy-routes.json loader
//
// Implements Routes: a hot-reloadable, RW-locked map of
//
//	host → backend(ip, port, *httputil.ReverseProxy)
//
// JSON shape (matches the production haproxy-routes.json):
//
//	{ "domain.example.com": ["127.0.0.1", 3000], … }
//
// Malformed entries (wrong JSON type, missing/bad port) are skipped without
// panicking. Lookup lowercases and strips the port from the caller-supplied
// host before the map probe, matching what the handler already does to
// req.Host.
//
// Performance: a *httputil.ReverseProxy is constructed once per backend
// ip:port at load/reload time (never per-request). The shared *http.Transport
// is injected from the Server so all proxied connections share the same
// connection pool. Proxies are keyed by "ip:port" in a separate sync.Map so
// that entries with the same backend but different virtual-host names share
// one proxy instance.
//
// Hot-reload mirrors cmd/sbxmitm/policy.go:
//   - reload.NewWatcher(throttle=0, target) — throttle is 0 so tests call
//     Maybe() and it fires immediately; production callers may layer their own
//     throttle around Maybe() if needed (same pattern as Policy.maybeReload).
//   - reload.StatMtime is used for the initial LastMtime.
//   - The Target.Load func re-parses the file; Target.Apply atomically swaps
//     the routes map under the RWLock.
package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/reload"
)

// routeEntry holds the resolved backend for one virtual host.
type routeEntry struct {
	ip    string
	port  int
	proxy *httputil.ReverseProxy
}

// Routes is a hot-reloadable, RW-locked map of bare hostname → routeEntry.
// Create with LoadRoutes; call Lookup on the hot path; call Maybe() (or embed
// in a reload-driven ticker) to pick up on-disk changes.
type Routes struct {
	mu      sync.RWMutex
	entries map[string]routeEntry // key: lowercased bare hostname

	// proxyCache deduplices *httputil.ReverseProxy instances across entries that
	// share the same ip:port backend. Key: "ip:port" string. This map is only
	// written by loadRoutes (called from within the reload mutex), so no
	// additional locking is needed for writes; reads happen under mu.RLock.
	proxyCache sync.Map // map[string]*httputil.ReverseProxy

	// transport is shared across all proxied connections (set once at
	// construction; nil means httputil uses its default transport, which is
	// fine for tests that don't inject one).
	transport http.RoundTripper

	// cookieAudit is the Task 5.1 RGPD ledger. When non-nil, every
	// ModifyResponse built by buildEntries calls Record. Set once at
	// LoadRoutes time; never mutated afterwards.
	cookieAudit *CookieAudit

	// #747: first-party host suffixes + Hub origin for the injected SecuBox health
	// banner. Read inside ModifyResponse; set in main() after LoadRoutes.
	widgetHosts []string
	// widgetExclude : applications tierces non injectees. Elles restent
	// inspectees et protegees — seul le bandeau s'arrete.
	widgetExclude []string
	bannerOrigin  string

	// #746: onUpstreamError, when non-nil, gets first refusal on an upstream
	// failure before the themed error page is written. It returns true when it
	// has fully answered the request (the caller must then write nothing).
	//
	// This is the seam that lets the scale-to-zero wake path reach the cached
	// proxies' ErrorHandler, which is built here in buildEntries where the
	// *Server — and therefore its on-demand set and waker proxy — is not in
	// scope. Set in main() after LoadRoutes; read inside the closure at request
	// time, never captured, so hot-reloaded proxies see it too.
	onUpstreamError func(w http.ResponseWriter, req *http.Request, code int, host string) bool

	// watcher handles mtime tracking + Apply callbacks (throttle=0 → eager).
	watcher *reload.Watcher
}

// loadRoutesJSON parses the haproxy-routes.json format into a map.
// Malformed entries are skipped (logged at DEBUG level) without panicking.
// Returns nil on a fatal parse error (unreadable file / root JSON syntax).
func loadRoutesJSON(path string) map[string][2]string {
	data, err := os.ReadFile(path)
	if err != nil {
		// Missing file is best-effort (same as reload.LoadLines).
		return map[string][2]string{}
	}

	// Parse as map[string]json.RawMessage so we can inspect each value.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("sbxwaf/routes: parse %s: %v", path, err)
		return map[string][2]string{}
	}

	out := make(map[string][2]string, len(raw))
	for host, val := range raw {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}

		// Expect a 2-element JSON array: ["ip", port].
		var arr []json.RawMessage
		if err := json.Unmarshal(val, &arr); err != nil || len(arr) < 2 {
			log.Printf("sbxwaf/routes: skipping %q: not a 2-element array", host)
			continue
		}

		var ip string
		if err := json.Unmarshal(arr[0], &ip); err != nil || ip == "" {
			log.Printf("sbxwaf/routes: skipping %q: bad ip field", host)
			continue
		}

		// Port may be encoded as a JSON number or a string.
		var portStr string
		var portNum float64
		if err := json.Unmarshal(arr[1], &portNum); err == nil {
			portStr = strconv.Itoa(int(portNum))
		} else if err := json.Unmarshal(arr[1], &portStr); err != nil {
			log.Printf("sbxwaf/routes: skipping %q: bad port field", host)
			continue
		}
		// Validate port range.
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			log.Printf("sbxwaf/routes: skipping %q: port %q out of range", host, portStr)
			continue
		}

		out[host] = [2]string{ip, portStr}
	}
	return out
}

// buildEntries converts a parsed map into routeEntry values, reusing existing
// proxy instances from proxyCache where the backend ip:port is unchanged.
func (r *Routes) buildEntries(parsed map[string][2]string) map[string]routeEntry {
	entries := make(map[string]routeEntry, len(parsed))
	for host, pair := range parsed {
		ip, portStr := pair[0], pair[1]
		key := net.JoinHostPort(ip, portStr)

		// Reuse proxy from cache if already built for this backend.
		var proxy *httputil.ReverseProxy
		if v, ok := r.proxyCache.Load(key); ok {
			proxy = v.(*httputil.ReverseProxy)
		} else {
			port, _ := strconv.Atoi(portStr)
			target := &url.URL{
				Scheme: "http",
				Host:   net.JoinHostPort(ip, strconv.Itoa(port)),
			}
			p := httputil.NewSingleHostReverseProxy(target)
			p.Transport = r.transport
			// ModifyResponse stamps the WAF sentinel header (mirrors handler's
			// inline proxy; centralised here so cached proxies also stamp it).
			// Task 5.1: also records Set-Cookie headers to the RGPD ledger.
			// We read r.cookieAudit inside the closure (not captured at buildEntries
			// call time) so that the audit wired in main() after LoadRoutes is
			// visible to both startup-built and hot-reload-built proxies.
			p.ModifyResponse = func(resp *http.Response) error {
				resp.Header.Set("X-SecuBox-WAF", "inspected")
				reqHost := ""
				if resp.Request != nil {
					reqHost = resp.Request.Host
				}
				if ca := r.cookieAudit; ca != nil {
					ca.Record(reqHost, resp.Request, resp)
				}
				// #747: inject the SecuBox health/visit widget on first-party HTML.
				if bare, _, e := net.SplitHostPort(reqHost); e == nil {
					reqHost = bare
				}
				applyWidget(resp, strings.ToLower(reqHost), r.bannerOrigin, r.widgetHosts, r.widgetExclude)
				return nil
			}
			p.ErrorHandler = func(w http.ResponseWriter, req *http.Request, err error) {
				// Task 7.1: themed error pages — mirror the Python error() hook mapping.
				code := upstreamErrorCode(err)
				reqHost := req.Host
				if bare, _, e := net.SplitHostPort(reqHost); e == nil {
					reqHost = bare
				}
				reqHost = strings.ToLower(strings.TrimSpace(reqHost))
				log.Printf("sbxwaf: upstream error host=%s path=%s -> %d: %v", reqHost, req.URL.Path, code, err)
				// #746: give the wake hook first refusal. Read from r at
				// request time, not captured at buildEntries time — same
				// discipline as r.cookieAudit above, so a hook wired in
				// main() after LoadRoutes is visible to proxies built at
				// startup AND to those built by a hot reload.
				if h := r.onUpstreamError; h != nil && h(w, req, code, reqHost) {
					return
				}
				writeErrorPage(w, code, reqHost)
			}
			r.proxyCache.Store(key, p)
			proxy = p
		}

		port, _ := strconv.Atoi(portStr)
		entries[host] = routeEntry{ip: ip, port: port, proxy: proxy}
	}
	return entries
}

// LoadRoutes parses path as a haproxy-routes.json file and returns a *Routes
// ready for Lookup.  A missing or unreadable file yields an empty (but
// functional) Routes — the caller will get ok=false for every Lookup until a
// valid file appears and Maybe() triggers a reload.
//
// transport is the shared *http.Transport (connection pool + dial timeout) that
// every reverse-proxy built at load time — and at each hot-reload — will use.
// Passing nil falls back to http.DefaultTransport gracefully (useful in tests
// that don't care about transport tuning).
func LoadRoutes(path string, transport http.RoundTripper) *Routes {
	if transport == nil {
		transport = http.DefaultTransport
	}
	r := &Routes{transport: transport}

	// Initial load.
	parsed := loadRoutesJSON(path)
	r.entries = r.buildEntries(parsed)

	// Register the reload target.  throttle=0 so Maybe() fires immediately in
	// tests; production can wrap with its own throttle like Policy.maybeReload.
	target := reload.Target{
		Path:      path,
		LastMtime: reload.StatMtime(path),
		Load: func(p string) any {
			return loadRoutesJSON(p)
		},
		Apply: func(v any) {
			parsed := v.(map[string][2]string)
			newEntries := r.buildEntries(parsed)
			r.mu.Lock()
			r.entries = newEntries
			r.mu.Unlock()
		},
	}
	r.watcher = reload.NewWatcher(0, target)
	return r
}

// Maybe triggers a hot-reload check — stats the routes file and atomically
// swaps the map if the mtime changed.  Cheap when nothing changed (one stat +
// one time compare).  Call from the request hot path (or from a ticker).
// Mirrors Policy.maybeReload but without the extra Policy-level throttle layer
// since the Watcher's own throttle=0 is intentional for test eagerness; a
// production wrapper can add its own rate gate.
func (r *Routes) Maybe() {
	r.watcher.Maybe()
}

// Lookup resolves host to a backend (ip, port). host is lowercased and
// port-stripped before the map probe.  Returns ok=false for unmapped hosts.
func (r *Routes) Lookup(host string) (ip string, port int, ok bool) {
	// Normalise: lowercase + strip port.
	h := strings.ToLower(strings.TrimSpace(host))
	if bare, _, err := net.SplitHostPort(h); err == nil {
		h = bare
	}

	r.mu.RLock()
	e, found := r.entries[h]
	r.mu.RUnlock()

	if !found {
		return "", 0, false
	}
	return e.ip, e.port, true
}

// ProxyFor returns the cached *httputil.ReverseProxy for host, or nil if the
// host is not mapped.  Used by the handler to avoid per-request allocation.
func (r *Routes) ProxyFor(host string) *httputil.ReverseProxy {
	h := strings.ToLower(strings.TrimSpace(host))
	if bare, _, err := net.SplitHostPort(h); err == nil {
		h = bare
	}

	r.mu.RLock()
	e, found := r.entries[h]
	r.mu.RUnlock()

	if !found {
		return nil
	}
	return e.proxy
}
