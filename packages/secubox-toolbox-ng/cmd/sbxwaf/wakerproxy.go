// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — reverse proxy to the on-demand waker
//
// SecuBox scale-to-zero (#896): when a request arrives for a vhost that is
// registered as on-demand (OnDemand.Contains) but currently has no live route
// (the sleeper stopped it), the WAF must NOT answer 421 — it must reverse-proxy
// the request to the waker, a Python service listening on a unix socket
// (/run/secubox/waker.sock) that serves a splash page and fires the wake.
//
// The proxy is built exactly once (sync.Once, per Server instance) and reused
// for every request — mirrors the codebase's build-once/cache discipline for
// *httputil.ReverseProxy (see routes.go's proxyCache). Only the Director's
// rewritten path (/_wake/<host>) varies per request; the proxy itself,
// its Transport and its unix-socket dial function never change.
package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

// defaultWakerSocket is the production path to the waker's unix socket.
// Server.wakerSocket overrides this (tests inject a stub socket path).
const defaultWakerSocket = "/run/secubox/waker.sock"

// wakerSocketPath returns the socket path to dial: s.wakerSocket if set,
// otherwise the production default.
func (s *Server) wakerSocketPath() string {
	if s.wakerSocket != "" {
		return s.wakerSocket
	}
	return defaultWakerSocket
}

// wakerProxy returns the lazily-built, cached *httputil.ReverseProxy that
// forwards requests to the waker over a unix socket. Built once per Server
// instance and reused for every on-demand request afterwards.
func (s *Server) wakerProxy() *httputil.ReverseProxy {
	s.wakerProxyOnce.Do(func() {
		sockPath := s.wakerSocketPath()

		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		}

		proxy := &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				host, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					host = req.Host
				}
				// Normalize exactly like OnDemand.Contains / Routes.Lookup
				// (lowercase + trim) so the wake key sent to the waker matches
				// the lowercase portal_domain stored in on-demand-vhosts.json
				// regardless of the casing a client sent in its Host header.
				// Without this, a mixed-case Host would pass the on-demand
				// gate (case-insensitive) but miss the waker's exact-match
				// lookup, leaving the service permanently unwoken.
				host = strings.ToLower(strings.TrimSpace(host))
				// Dummy scheme/host: the Transport ignores them and always
				// dials the unix socket above; only the rewritten path
				// carries the information the waker needs.
				req.URL.Scheme = "http"
				req.URL.Host = "waker.sock"
				req.URL.Path = "/_wake/" + host
				req.URL.RawQuery = ""
				req.Host = "waker.sock"
			},
			Transport: transport,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				// The waker itself being unreachable is a genuine 503 — there is
				// no further fallback (mirrors upstreamErrorCode's default case).
				http.Error(w, "503 Service Unavailable: waker unreachable", http.StatusServiceUnavailable)
			},
		}
		s.wakerProxyInst = proxy
	})
	return s.wakerProxyInst
}
