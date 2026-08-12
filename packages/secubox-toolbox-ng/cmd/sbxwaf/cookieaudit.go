// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: cookieaudit — RGPD Set-Cookie ledger
//
// Task 5.1: For every Set-Cookie header in an upstream response, append one
// JSONL record to a ledger file. Cookie values are SHA256-hashed in-process —
// the raw value NEVER leaves this component.
//
// Port from packages/secubox-mitmproxy/addons/cookie_audit.py (parse_set_cookie
// + CookieAudit._append). Go's http.Response.Cookies() does not expose the
// SameSite attribute, so we parse the raw "Set-Cookie" header strings directly
// (same approach as the Python parse_set_cookie function).
//
// Architecture:
//   - A buffered channel (size cookieAuditChanSize) decouples Record callers
//     from disk I/O. Record is non-blocking: when the channel is full the
//     record is dropped (dropCount incremented) rather than blocking the HTTP
//     response path.
//   - A single writer goroutine drains the channel and appends to the ledger
//     (O_WRONLY|O_CREATE|O_APPEND, 0640). The file is opened once at
//     construction and held open for the lifetime of the CookieAudit to avoid
//     per-record open/close overhead.
//   - Close() closes the channel (draining it first) and waits for the writer
//     to exit. Safe to call multiple times via sync.Once.
//
// Ledger path default: /var/log/secubox/cookie-audit/server.jsonl
// Configurable via --cookie-audit-log flag in main().
//
// JSON record fields (mirrors Python cookie_audit.py record):
//
//	ts              — RFC 3339 UTC timestamp
//	vhost           — bare hostname from the request (Host header)
//	url_path        — request URL path
//	method          — HTTP method
//	status          — response status code (int)
//	name            — cookie name
//	value_hash      — sha256(raw_value).hexdigest()
//	domain          — cookie Domain attribute (leading '.' stripped, omitted if absent)
//	path            — cookie Path attribute (omitted if absent)
//	secure          — bool
//	httponly        — bool
//	samesite        — SameSite attribute value (omitted if absent)
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// cookieAuditChanSize is the depth of the async record channel.
// At 256 entries the buffer absorbs short bursts without blocking; records
// beyond this are dropped (counted but never block the response path).
const cookieAuditChanSize = 256

// DefaultCookieAuditLog is the production ledger path, matching the Python
// addon's DEFAULT_LEDGER constant.
const DefaultCookieAuditLog = "/var/log/secubox/cookie-audit/server.jsonl"

// cookieRecord is the JSON shape written to the ledger.
// Fields mirror the Python parse_set_cookie + response hook dict.
type cookieRecord struct {
	TS        string  `json:"ts"`
	Vhost     string  `json:"vhost"`
	URLPath   string  `json:"url_path"`
	Method    string  `json:"method"`
	Status    int     `json:"status"`
	Name      string  `json:"name"`
	ValueHash string  `json:"value_hash"`
	Domain    *string `json:"domain"` // null when absent
	Path      *string `json:"path"`   // null when absent
	Secure    bool    `json:"secure"`
	HTTPOnly  bool    `json:"httponly"`
	SameSite  *string `json:"samesite"` // null when absent
}

// CookieAudit appends one JSONL record per Set-Cookie header to a ledger.
// Goroutine-safe. Record is non-blocking (drop-on-full channel policy).
type CookieAudit struct {
	ch        chan cookieRecord
	file      *os.File
	wg        sync.WaitGroup
	closeOnce sync.Once
	dropCount atomic.Int64 // atomic counter for concurrent Record calls
}

// NewCookieAudit creates a CookieAudit that writes to path.
// The parent directory is created (0755) if it does not exist. The ledger file
// is opened with O_APPEND|O_CREATE. Panics if the directory cannot be created
// or the file cannot be opened — startup time, not the request path.
func NewCookieAudit(path string) *CookieAudit {
	dir := path
	// Trim the file name to get the directory.
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		dir = path[:idx]
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		// Fatal at startup — the operator must fix the path.
		panic(fmt.Sprintf("cookieaudit: mkdir %s: %v", dir, err))
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		panic(fmt.Sprintf("cookieaudit: open %s: %v", path, err))
	}

	ca := &CookieAudit{
		ch:   make(chan cookieRecord, cookieAuditChanSize),
		file: f,
	}

	ca.wg.Add(1)
	go ca.writer()

	return ca
}

// writer drains the channel and appends JSONL records to the ledger.
// Runs as a single goroutine for the lifetime of the CookieAudit.
func (ca *CookieAudit) writer() {
	defer ca.wg.Done()
	for rec := range ca.ch {
		data, err := json.Marshal(rec)
		if err != nil {
			// json.Marshal with plain strings is unreachable in practice.
			fmt.Fprintf(os.Stderr, "cookieaudit: marshal failed: %v\n", err)
			continue
		}
		data = append(data, '\n')
		if _, err := ca.file.Write(data); err != nil {
			fmt.Fprintf(os.Stderr, "cookieaudit: write failed: %v\n", err)
		}
	}
}

// Close drains the channel (waits for the writer goroutine) and closes the
// underlying file. Safe to call multiple times.
func (ca *CookieAudit) Close() {
	ca.closeOnce.Do(func() {
		close(ca.ch)
		ca.wg.Wait()
		_ = ca.file.Close()
	})
}

// Record enumerates the Set-Cookie headers in resp, builds one cookieRecord per
// cookie, SHA256-hashes the value, and sends to the async channel.
// NON-BLOCKING: if the channel is full, the record is dropped (never blocks
// the HTTP response path).
func (ca *CookieAudit) Record(host string, req *http.Request, resp *http.Response) {
	if ca == nil || resp == nil {
		return
	}

	rawCookies := resp.Header["Set-Cookie"]
	if len(rawCookies) == 0 {
		return
	}

	// Collect context fields once per call.
	ts := time.Now().UTC().Format(time.RFC3339)
	method := ""
	urlPath := ""
	status := resp.StatusCode
	if req != nil {
		method = req.Method
		if req.URL != nil {
			urlPath = req.URL.Path
		}
	}

	for _, raw := range rawCookies {
		rec, ok := parseSetCookieRaw(raw)
		if !ok {
			continue
		}
		rec.TS = ts
		rec.Vhost = host
		rec.URLPath = urlPath
		rec.Method = method
		rec.Status = status

		// Non-blocking send: drop if the channel is full.
		select {
		case ca.ch <- rec:
		default:
			ca.dropCount.Add(1)
		}
	}
}

// parseSetCookieRaw parses a raw Set-Cookie header string into a cookieRecord
// (with only the cookie-level fields populated; context fields are set by
// Record). Returns ok=false if the header is malformed (no name=value pair).
//
// We parse the raw string directly rather than using http.Response.Cookies()
// because Go's net/http cookie parser does not expose the SameSite attribute.
// The parsing logic mirrors Python's parse_set_cookie function in cookie_audit.py.
func parseSetCookieRaw(raw string) (cookieRecord, bool) {
	if raw == "" {
		return cookieRecord{}, false
	}

	// Split on ';': first token is name=value, the rest are attributes.
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return cookieRecord{}, false
	}

	// name=value (first token).
	nameVal := strings.TrimSpace(parts[0])
	eqIdx := strings.IndexByte(nameVal, '=')
	if eqIdx < 0 {
		// No '=' in the first token — malformed cookie.
		return cookieRecord{}, false
	}
	name := strings.TrimSpace(nameVal[:eqIdx])
	if name == "" {
		return cookieRecord{}, false
	}
	rawValue := strings.TrimSpace(nameVal[eqIdx+1:])

	// SHA256 the raw value — never store it.
	sum := sha256.Sum256([]byte(rawValue))
	valueHash := fmt.Sprintf("%x", sum)

	rec := cookieRecord{
		Name:      name,
		ValueHash: valueHash,
		Secure:    false,
		HTTPOnly:  false,
	}

	// Parse attributes.
	for _, attr := range parts[1:] {
		attr = strings.TrimSpace(attr)
		if attr == "" {
			continue
		}
		k, v, _ := strings.Cut(attr, "=")
		k = strings.TrimSpace(strings.ToLower(k))
		v = strings.TrimSpace(v)

		switch k {
		case "domain":
			d := strings.TrimLeft(v, ".")
			if d == "" {
				// Empty after stripping dot → treat as absent (null).
				break
			}
			rec.Domain = &d
		case "path":
			if v != "" {
				rec.Path = &v
			}
		case "secure":
			rec.Secure = true
		case "httponly":
			rec.HTTPOnly = true
		case "samesite":
			if v != "" {
				rec.SameSite = &v
			}
			// expires, max-age, and other attributes are intentionally ignored
			// (not RGPD-relevant per the Python addon's design decision).
		}
	}

	return rec, true
}
