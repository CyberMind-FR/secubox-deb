// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Reporter: turns a Verdict into a human-readable proposal/solution report —
// what was detected (threat class), the evidence backing it (the matched
// IOC/rule from Verdict.Evidence), whether it was neutralized or only
// reported, and a class-keyed recommended mitigation.
//
// Privacy (plan Global Constraints): the ONLY identity a report carries is the
// Verdict.MacHash — there is no raw PII (no client IP, no real MAC, no user
// identity) in a Verdict to begin with, and this reporter renders only the
// MacHash plus the Evidence map (threat indicators), never a struct dump.
package sentinel

import (
	"sort"
	"strings"
	"text/template"
	"time"
)

// reportView is the flattened, presentation-ready shape RenderReport feeds to
// the template — computed strings only, so the template stays logic-free.
type reportView struct {
	Class       ThreatClass
	ClassHuman  string
	Severity    int
	Confidence  int
	MacHash     string
	Time        string
	Disposition string
	Evidence    []kv
	Mitigation  string
}

// kv is one evidence key/value pair, rendered in sorted-key order for a
// deterministic report.
type kv struct {
	Key   string
	Value string
}

// classHuman gives each ThreatClass a short human label for the report header.
var classHuman = map[ThreatClass]string{
	ClassMalware:          "Malware",
	ClassTrojan:           "Trojan",
	ClassBotnetC2:         "Botnet command-and-control",
	ClassPhishing:         "Phishing",
	ClassSpywarePegasus:   "Commercial spyware — Pegasus (NSO Group)",
	ClassSpywarePredator:  "Commercial spyware — Predator (Intellexa/Cytrox)",
	ClassSpywareIntellexa: "Commercial spyware — Intellexa",
	ClassZeroClick:        "Zero-click delivery (heuristic)",
}

// mitigations gives each ThreatClass its recommended-action line. The spyware
// classes intentionally reference the device (mac_hash) + evidence
// preservation + an on-device MVT scan; zero-click is report-only advice;
// botnet_c2 is block-C2 + inspect-device. Unknown classes fall back to
// mitigationDefault.
var mitigations = map[ThreatClass]string{
	ClassSpywarePegasus:   "Isolate device {{.MacHash}} from the network, preserve evidence, and consider an on-device MVT (Mobile Verification Toolkit) scan.",
	ClassSpywarePredator:  "Isolate device {{.MacHash}} from the network, preserve evidence, and consider an on-device MVT (Mobile Verification Toolkit) scan.",
	ClassSpywareIntellexa: "Isolate device {{.MacHash}} from the network, preserve evidence, and consider an on-device MVT (Mobile Verification Toolkit) scan.",
	ClassZeroClick:        "Reported (not blocked) to avoid breaking legitimate messaging/link delivery — advise the user not to open unexpected one-time links and to keep the device updated.",
	ClassBotnetC2:         "Block the C2 endpoint and inspect the device for a persistent implant or beaconing process.",
	ClassMalware:          "Quarantine the delivered payload and run a full anti-malware scan on the affected device.",
	ClassTrojan:           "Quarantine the delivered payload and run a full anti-malware scan on the affected device.",
	ClassPhishing:         "Warn the user: the destination impersonates a trusted service to harvest credentials — do not enter any secrets.",
}

const mitigationDefault = "Review the flagged connection and correlate it with device activity before deciding on a response."

// reportTemplate is the human-readable report body. It is logic-free: every
// decision (disposition wording, mitigation) is resolved into reportView
// before rendering.
var reportTemplate = template.Must(template.New("sentinel-report").Parse(
	`SecuBox Sentinel — Threat Report
================================

Detection  : {{.ClassHuman}} ({{.Class}})
Severity   : {{.Severity}}/100
Confidence : {{.Confidence}}/100
Device     : {{.MacHash}}
Observed   : {{.Time}}

Disposition: {{.Disposition}}

Evidence:
{{range .Evidence}}  - {{.Key}}: {{.Value}}
{{end}}
Recommended mitigation:
  {{.Mitigation}}
`))

// isNeutralizingAction reports whether act actually neutralized the flow
// (block / strip / sinkhole) as opposed to report-only.
func isNeutralizingAction(act Action) bool {
	switch act {
	case ActionBlock, ActionStrip, ActionSinkhole:
		return true
	default:
		return false
	}
}

// disposition renders the human disposition line for v.Action.
func disposition(act Action) string {
	if isNeutralizingAction(act) {
		return "NEUTRALIZED — the connection was blocked before any data reached the destination."
	}
	return "REPORTED (not blocked) — the connection was allowed through; this detection is heuristic/low-confidence and is flagged for operator review."
}

// mitigationFor resolves the class-keyed mitigation line, expanding the
// {{.MacHash}} placeholder (spyware lines reference the device) against v.
func mitigationFor(v Verdict) string {
	tmpl, ok := mitigations[v.Class]
	if !ok {
		return mitigationDefault
	}
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	t, err := template.New("mitigation").Parse(tmpl)
	if err != nil {
		return mitigationDefault
	}
	var sb strings.Builder
	if err := t.Execute(&sb, v); err != nil {
		return mitigationDefault
	}
	return sb.String()
}

// sortedEvidence returns v.Evidence as key-sorted kv pairs for a deterministic
// report body.
func sortedEvidence(ev map[string]string) []kv {
	keys := make([]string, 0, len(ev))
	for k := range ev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]kv, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv{Key: k, Value: ev[k]})
	}
	return out
}

// RenderReport renders v into a human-readable proposal/solution report. It
// never panics: the template is pre-compiled and validated (template.Must),
// and any per-call execution error degrades to the header-only string rather
// than crashing a caller on the reporting path.
func RenderReport(v Verdict) string {
	human, ok := classHuman[v.Class]
	if !ok {
		human = string(v.Class)
	}

	ts := "unknown"
	if v.TS > 0 {
		ts = time.Unix(v.TS, 0).UTC().Format(time.RFC3339)
	}

	view := reportView{
		Class:       v.Class,
		ClassHuman:  human,
		Severity:    v.Severity,
		Confidence:  v.Confidence,
		MacHash:     v.MacHash,
		Time:        ts,
		Disposition: disposition(v.Action),
		Evidence:    sortedEvidence(v.Evidence),
		Mitigation:  mitigationFor(v),
	}

	var sb strings.Builder
	if err := reportTemplate.Execute(&sb, view); err != nil {
		// Fail-safe: never let a reporting error escape to the caller.
		return "SecuBox Sentinel — Threat Report (render error)\nclass: " + string(v.Class) + "\ndevice: " + v.MacHash + "\n"
	}
	return sb.String()
}
