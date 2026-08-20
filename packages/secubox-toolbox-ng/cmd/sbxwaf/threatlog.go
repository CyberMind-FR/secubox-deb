// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
//
// SecuBox-Deb :: toolbox-ng :: sbxwaf :: threatlog — append-only WAF threat log
//
// Task 3.2: ported from packages/secubox-mitmproxy/addons/secubox_waf.py
// (log_threat, lines ~883-906).  One JSON object per line, O_APPEND|O_CREATE,
// 0640 permissions.  Failures are best-effort: log to stderr, never crash the
// request path.
//
// Log path: /var/log/secubox/waf-threats.log (configurable via --threat-log).
//
// JSON fields (mirrors Python log_threat entry):
//
//	timestamp  — RFC 3339 (time.RFC3339)
//	client_ip  — extracted client IP (after XFF resolution)
//	host       — HTTP Host header
//	method     — HTTP method
//	path       — request path
//	category   — WAF category ID (e.g. "sqli", "xss")
//	severity   — "low"|"medium"|"high"|"critical"
//	rule_id    — matched rule ID (empty string when Match() did not return one)
//	action     — "detect" | "warning" | "banned"
//	user_agent — User-Agent header
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ThreatRecord holds the fields for one WAF threat event.
// All fields are plain strings so JSON marshalling is trivial and the struct
// is easy to construct in the handler without type assertions.
type ThreatRecord struct {
	ClientIP string
	Host     string
	Method   string
	Path     string
	Category string
	Severity string
	RuleID   string
	Action   string // "detect" | "warning" | "banned"
	UA       string
	Tool     string // #1070 phase C : outil identifié (nuclei, sqlmap…) si certain
	JA4      string // #1070 phase E : empreinte TLS JA4 (via HAProxy), clé anti-spoof
}

// ThreatLog appends JSON threat records to a file, one per line.
// It is goroutine-safe; a sync.Mutex serialises concurrent appends.
type ThreatLog struct {
	path string
	mu   sync.Mutex
}

// NewThreatLog creates a ThreatLog that writes to path.
// The file is created (or appended to) on first Record call — not at
// construction time, so creating the struct never fails even if the
// directory doesn't exist yet.
func NewThreatLog(path string) *ThreatLog {
	return &ThreatLog{path: path}
}

// logEntry is the JSON shape written to the threat log.
// Field names mirror the Python log_threat dict keys.
type logEntry struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Category  string `json:"category"`
	Severity  string `json:"severity"`
	RuleID    string `json:"rule_id"`
	Action    string `json:"action"`
	UserAgent string `json:"user_agent"`
	Tool      string `json:"tool,omitempty"`
	JA4       string `json:"ja4,omitempty"`
}

// Record appends one JSON line to the threat log for the given ThreatRecord.
// On any I/O error the error is printed to stderr — the request is never
// interrupted by a log write failure (best-effort, mirrors Python except clause).
func (l *ThreatLog) Record(rec ThreatRecord) {
	entry := logEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		ClientIP:  rec.ClientIP,
		Host:      rec.Host,
		Method:    rec.Method,
		Path:      rec.Path,
		Category:  rec.Category,
		Severity:  rec.Severity,
		RuleID:    rec.RuleID,
		Action:    rec.Action,
		UserAgent: rec.UA,
		Tool:      rec.Tool,
		JA4:       rec.JA4,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// json.Marshal only fails on unmarshalable types; with plain strings this
		// is unreachable in practice, but handle it defensively.
		fmt.Fprintf(os.Stderr, "sbxwaf/threatlog: marshal failed: %v\n", err)
		return
	}
	// Append newline to produce NDJSON (one object per line).
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	// O_APPEND|O_CREATE, 0640 — never truncate, readable by secubox group.
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbxwaf/threatlog: open %s: %v\n", l.path, err)
		return
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "sbxwaf/threatlog: write %s: %v\n", l.path, err)
	}
}
