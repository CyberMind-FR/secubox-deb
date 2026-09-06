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
	"net"
	"os"
	"sync"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/emit"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/envelope"
	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/actor/features"
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
	path    string
	mu      sync.Mutex
	emitter *emit.Emitter // #1240 : émission Actor Intelligence (facultative)
}

// NewThreatLog creates a ThreatLog that writes to path.
// The file is created (or appended to) on first Record call — not at
// construction time, so creating the struct never fails even if the
// directory doesn't exist yet.
func NewThreatLog(path string) *ThreatLog {
	return &ThreatLog{path: path}
}

// SetEmitter branche (facultativement) l'émission des Event Envelopes vers
// sbx-actord (RFC-0013). Nil = pas d'émission. L'émission est fire-and-forget :
// elle ne peut jamais ralentir ni interrompre le chemin requête du WAF.
func (l *ThreatLog) SetEmitter(e *emit.Emitter) { l.emitter = e }

// sevToInt projette la sévérité WAF (low/medium/high/critical) sur 0..100.
func sevToInt(s string) int {
	switch s {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 40
	}
}

// entryToEnvelope projette un événement WAF sur l'Event Envelope v1 (RFC-0013
// §2). Les champs non disponibles au WAF (ASN, pays, credential) restent vides —
// aucune valeur inventée. path_shape et ua_family réutilisent internal/actor/
// features (parité de forme avec le clustering).
func entryToEnvelope(e *logEntry) *envelope.Envelope {
	action := envelope.ActionObserve
	if e.Action == "banned" {
		action = envelope.ActionBlock
	}
	uaFam := e.Tool // outil déjà identifié (nuclei, sqlmap…) prime
	if uaFam == "" {
		uaFam = features.UAFamily(e.UserAgent)
	}
	var tags []string
	if e.Category != "" {
		tags = append(tags, e.Category)
	}
	if e.NegativeSpace != "" {
		tags = append(tags, e.NegativeSpace)
	}
	return &envelope.Envelope{
		EventID:         envelope.NewEventID(),
		Timestamp:       time.Now().Unix(),
		Sensor:          envelope.SensorWAF,
		SrcIP:           e.ClientIP,
		DstService:      e.Host,
		Vhost:           e.Host,
		Transport:       "tls",
		Protocol:        "https",
		Action:          action,
		RuleID:          e.RuleID,
		Severity:        sevToInt(e.Severity),
		PathShape:       features.PathShape(e.Path),
		UserAgentFamily: uaFam,
		TLSFingerprint:  e.JA4,
		BehaviorTags:    tags,
	}
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
	// #1240 P0-A : étiquette « negative space » — known_negative | high_value_probe.
	// Présente UNIQUEMENT pour les sondes de reconnaissance ; absente pour les
	// attaques à charge utile (sqli, xss…) et les 404 anodines.
	NegativeSpace string `json:"negative_space,omitempty"`
}

// Record appends one JSON line to the threat log for the given ThreatRecord.
// On any I/O error the error is printed to stderr — the request is never
// interrupted by a log write failure (best-effort, mirrors Python except clause).
func (l *ThreatLog) Record(rec ThreatRecord) {
	// LE TRAFIC INTERNE N'EST PAS UN ATTAQUANT (#1131am). Un health check, le
	// watchdog, l'agrégateur, le fetch des métriques de la bannière depuis
	// 127.0.0.1 : sans X-Forwarded-For réel, clientIP retombe sur le PAIR
	// (127.0.0.1 / la passerelle LAN), et « attaquants persistants » se
	// retrouvait dominé par 127.0.0.1 (68k faux positifs). On AGRÈGE tout le
	// privé/loopback sous un seul repère « local » : un bucket clairement
	// interne, pas une IP d'attaquant qu'on classerait en tête.
	clientIP := rec.ClientIP
	if privateCIDR(clientIP) {
		clientIP = "local"
	}
	entry := logEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		ClientIP:  clientIP,
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

	// LECTURE « NEGATIVE SPACE » (#1240, P0-A). On ÉTIQUETTE l'événement selon
	// qu'il s'agit d'une sonde de reconnaissance (appât connu / sonde haute
	// valeur) plutôt que d'une charge utile ou d'une 404 quelconque. Pure
	// OBSERVATION : aucun ban, aucun blocage — c'est la matière première du
	// profileur (caractérisation d'attaquants). `routed=false` : on ne
	// journalise ici que des événements déjà retenus comme menace.
	if v := classifyPath(rec.Path, false, rec.Category); v.Signal {
		entry.NegativeSpace = v.Class
	}

	// Émission Actor Intelligence (RFC-0013), best-effort et NON BLOQUANTE : si
	// actord est absent/lent/tombé, l'enveloppe est déposée et la requête n'attend
	// jamais. Le trafic interne (agrégé sous "local" plus haut) n'est pas un
	// acteur → non émis ; on n'émet que pour une IP source réelle.
	if l.emitter != nil && entry.ClientIP != "local" && net.ParseIP(entry.ClientIP) != nil {
		l.emitter.Emit(entryToEnvelope(&entry))
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
