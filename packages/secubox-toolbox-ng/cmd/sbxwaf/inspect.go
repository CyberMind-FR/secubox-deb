// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf — request inspection + skip-lists
//
// Task 2.2: wires the Rules engine into the HTTP handler with:
//   - CIDR-based trusted-network bypass (RFC1918 + loopback)
//   - Static-asset skip (.js/.css/.png/... and /health, /status, system_health)
//   - NC mobile-token bypass (/index.php/login/v2/, /ocs/v2.php/core/login)
//   - Body read capped at 1 MiB for inspection; full body forwarded via
//     io.MultiReader (prefix + remaining stream) — no truncation on large uploads
//   - clientIP extraction: prefer leftmost XFF only when peer is a trusted proxy
//
// Ported faithfully from:
//   packages/secubox-mitmproxy/addons/secubox_waf.py
//     - _is_whitelisted / _WL_NETS (lines 28-47)
//     - get_real_client_ip (lines 193-219)
//     - check_request static/health fast-path (lines 764-769)
//
// Connection: close is added to upstream requests per issue #496 (Python parity).
package main

import (
	"net"
	"net/http"
	"strings"
)

// trustedProxies mirrors Python's TRUSTED_PROXIES set (secubox_waf.py line 176).
// Used to decide whether to trust an X-Forwarded-For header: we only use XFF
// when the immediate peer (r.RemoteAddr) is one of these known proxy IPs.
var trustedProxies = map[string]struct{}{
	"10.100.0.1":    {},
	"127.0.0.1":     {},
	"172.17.0.1":    {},
	"192.168.255.1": {},
}

// privateCIDRs mirrors Python's _WL_NETS (secubox_waf.py lines 33-38):
// loopback + RFC1918 + IPv6 loopback + ULA.
// Parsed once at package init; clientIP addresses in these ranges bypass
// the WAF entirely (LAN operators must never be banned).
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
	} {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, ipNet)
		}
	}
}

// privateCIDR reports whether ip (plain IP string, no port) falls within any
// of the trusted private networks defined above.
// Mirrors Python's _is_whitelisted (secubox_waf.py lines 40-47).
func privateCIDR(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// staticExtensions is the set of lowercase file extensions that skip inspection.
// Mirrors Python's check_request fast-path (secubox_waf.py line 766).
var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
	".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".map",
}

// staticAsset reports whether the request path looks like a static asset or a
// health/status endpoint that should skip WAF inspection.
// Mirrors Python check_request (secubox_waf.py lines 764-769):
//   - extension match (path.endswith(ext) for ext in static_exts)
//   - /health, /status, system_health substrings
func staticAsset(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return strings.Contains(lower, "/health") ||
		strings.Contains(lower, "/status") ||
		strings.Contains(lower, "system_health")
}

// ncBypassPaths are Nextcloud mobile-token endpoints that must never be blocked.
// These paths carry opaque login tokens that can look like attack payloads; blocking
// them would break the NC mobile clients permanently.
var ncBypassPaths = []string{
	"/index.php/login/v2/",
	"/ocs/v2.php/core/login",
}

// ncBypass reports whether the path is a Nextcloud mobile authentication
// endpoint that should be exempt from WAF inspection.
func ncBypass(path string) bool {
	lower := strings.ToLower(path)
	for _, p := range ncBypassPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// clientIP extracts the real client IP from the request.
//
// Strategy (mirrors Python get_real_client_ip, secubox_waf.py lines 193-219):
//  1. Parse the immediate peer from r.RemoteAddr.
//  2. If the peer is a trusted proxy (trustedProxies), take the LEFTMOST
//     non-empty entry from X-Forwarded-For as the real client IP.
//  3. Otherwise, the peer itself is the client (no proxy trust).
//
// Note: the Python version iterates XFF looking for the first non-trusted-proxy
// IP. We simplify to leftmost XFF when the peer is trusted, which is the common
// HAProxy → mitmproxy topology where HAProxy appends its own IP last and sets
// XFF to the original client.
func clientIP(r *http.Request) string {
	// Parse peer IP (strip port from RemoteAddr).
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without port (unusual but handle gracefully).
		peerHost = r.RemoteAddr
	}

	// Only trust XFF when the immediate peer is a known proxy.
	if _, trusted := trustedProxies[peerHost]; trusted {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the leftmost entry (original client in a well-behaved chain).
			parts := strings.SplitN(xff, ",", 2)
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}

	return peerHost
}

// maxBodyInspect is the maximum number of bytes read from the request body for
// WAF inspection. Chosen to balance coverage vs. memory: 1 MiB is large enough
// to catch typical POST-based injection payloads.
const maxBodyInspect = 1 << 20 // 1 MiB
