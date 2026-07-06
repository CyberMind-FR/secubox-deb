// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// SecuBox-Deb :: toolbox-ng :: sbxmitm :: inline Sentinel gate (#823)
//
// The per-flow hook that wires the internal/sentinel inline IOC gate into the
// live sbxmitm response path: it maps a flow's observable metadata to a
// neutralization action (block/strip/sinkhole) for a HIGH-CONFIDENCE known-infra
// IOC hit, and otherwise mirrors the flow (bounded, fire-and-forget) to the
// async sbx-sentinel analyzer.
//
// FAIL-OPEN is the whole contract of this file: a Sentinel setup problem (the
// engine off, a missing/corrupt pack, a nil hook, an internal panic) must NEVER
// break a normal browse. Every path here — a disabled hook, a nil receiver, a
// gate error — degrades to a transparent passthrough (ActionReport, no block
// page). Gate.Match already recovers from panics; this hook adds the disabled/
// nil guards on top so the integration cannot introduce a fail-closed path.
//
// HOT PATH: inspect on the common benign flow is one gate Match (throttled
// MaybeReload + a few O(1) IOCSet map lookups) plus, on a miss/report, one
// bounded non-blocking mirror Emit. No YARA, no heavy analysis inline — that is
// the async daemon's job. See BenchmarkSentinelInspectMiss.
package main

import (
	"fmt"
	"html"
	"log"
	"os"
	"strings"
	"time"

	"github.com/CyberMind-FR/secubox-deb/secubox-toolbox-ng/internal/sentinel"
)

// Sentinel env flags (read by newSentinelHook; wired at construction in main).
const (
	envSentinelEnabled    = "SENTINEL_ENABLED"     // "1"/"true"/"yes"/"on" → enable the gate (anything else → disabled no-op)
	envSentinelPackDir    = "SENTINEL_PACK_DIR"    // shipped base IOC pack directory
	envSentinelOverlayDir = "SENTINEL_OVERLAY_DIR" // live-feed overlay pack directory (optional)
	envSentinelMirrorSock = "SENTINEL_MIRROR_SOCK" // unix socket the async analyzer listens on (optional; empty → no mirror)
)

// mirror bounds: cap the queue so a down/slow analyzer never grows memory, and
// cap each mirrored body so a large response never bloats the queue. The mirror
// is best-effort — a full queue drops-with-count (see internal/sentinel Mirror).
const (
	sentinelMirrorQueue   = 1024
	sentinelMirrorBodyCap = 8 << 10 // 8 KiB
)

// sentinelHook is the per-proxy inline Sentinel gate. A zero value (enabled ==
// false, nil gate/mirror) is a valid, safe no-op passthrough — this is the
// fail-open default returned by newSentinelHook when Sentinel is off or its pack
// fails to load. All methods tolerate a nil receiver.
type sentinelHook struct {
	gate    *sentinel.Gate
	mirror  *sentinel.Mirror
	enabled bool
}

// newSentinelHook builds the hook from the environment. When SENTINEL_ENABLED is
// unset/false, OR the pack directory fails to load, it returns a DISABLED hook
// whose methods are transparent no-ops — a Sentinel setup problem must never
// break the proxy (fail-open). Only a clean, enabled, successfully-loaded pack
// yields an active gate.
func newSentinelHook() *sentinelHook {
	if !envEnabled(os.Getenv(envSentinelEnabled)) {
		return &sentinelHook{} // disabled: byte-identical passthrough
	}

	packDir := os.Getenv(envSentinelPackDir)
	overlayDir := os.Getenv(envSentinelOverlayDir)
	loader, err := sentinel.NewLoader(packDir, overlayDir)
	if err != nil {
		// Fail-open: a bad/missing base pack disables detection, never the proxy.
		log.Printf("sentinel: DISABLED — pack load failed (fail-open), proxy unaffected: %v", err)
		return &sentinelHook{}
	}

	var mirror *sentinel.Mirror
	if sock := os.Getenv(envSentinelMirrorSock); sock != "" {
		mirror = sentinel.NewMirror(sock, sentinelMirrorQueue, sentinelMirrorBodyCap)
	}

	log.Printf("sentinel: ENABLED (pack=%q overlay=%q mirror=%q)", packDir, overlayDir, os.Getenv(envSentinelMirrorSock))
	return &sentinelHook{
		gate:    sentinel.NewGate(loader),
		mirror:  mirror,
		enabled: true,
	}
}

// envEnabled reports whether an env value means "on".
func envEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// inspect maps one flow to a neutralization decision. It NEVER panics and is
// fail-open at every step:
//
//   - a nil or disabled hook returns (ActionReport, nil) — a transparent
//     passthrough — without touching the gate or the mirror;
//   - Gate.Match recovers internally and returns nil on any error;
//   - a nil verdict (no IOC hit) mirrors the flow (bounded) and returns
//     (ActionReport, nil);
//   - FinalizeAction downgrades every heuristic/low-confidence hit to
//     ActionReport before it can ever neutralize (the block/report split);
//   - ActionBlock/ActionSinkhole return a Sentinel block page for the caller to
//     write INSTEAD of the upstream response;
//   - ActionStrip returns (ActionStrip, nil) — the caller drops the body;
//   - anything else mirrors and returns (ActionReport, nil).
//
// respBody is the (optionally truncated) upstream body to attach to a mirror
// message; it may be nil on the hot path to avoid buffering — the FlowMeta is
// the load-bearing content and the Mirror caps the body regardless.
func (h *sentinelHook) inspect(meta sentinel.FlowMeta, respBody []byte) (sentinel.Action, []byte) {
	if h == nil || !h.enabled || h.gate == nil {
		return sentinel.ActionReport, nil
	}

	v := h.gate.Match(meta) // never panics; nil on no-match or any internal error
	if v == nil {
		h.emit(meta, respBody)
		return sentinel.ActionReport, nil
	}

	switch action := sentinel.FinalizeAction(v); action {
	case sentinel.ActionBlock, sentinel.ActionSinkhole:
		return action, sentinelBlockPage(v)
	case sentinel.ActionStrip:
		return sentinel.ActionStrip, nil
	default: // ActionReport or any unexpected value → report-only
		h.emit(meta, respBody)
		return sentinel.ActionReport, nil
	}
}

// emit hands a flow off to the async analyzer over the bounded mirror. It is a
// no-op when no mirror is configured; the Mirror's own Emit is non-blocking and
// drops-with-count on a full queue, so this never stalls the proxy.
func (h *sentinelHook) emit(meta sentinel.FlowMeta, body []byte) {
	if h == nil || h.mirror == nil {
		return
	}
	h.mirror.Emit(sentinel.MirrorMsg{Meta: meta, Body: body, TS: time.Now().Unix()})
}

// sentinelBlockPageTemplate is a minimal, self-contained, cyberpunk-styled block
// page in the C3BOX palette (no sbxwaf template is reusable across the binary
// boundary). The "sbx-sentinel-blocked" HTML comment is a machine-readable
// marker for tests and log parsers; %s is the (HTML-escaped) threat class.
const sentinelBlockPageTemplate = `<!DOCTYPE html>
<!-- sbx-sentinel-blocked -->
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecuBox Sentinel — Connection Blocked</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0a0a0f;color:#e8e6d9;font-family:"JetBrains Mono",ui-monospace,monospace}
.card{max-width:34rem;padding:2.5rem;border:1px solid #6e40c9;border-radius:12px;
background:rgba(20,18,30,.85);box-shadow:0 0 40px rgba(110,64,201,.35);text-align:center}
h1{margin:0 0 .5rem;color:#e63946;font-size:1.6rem;letter-spacing:.04em}
.class{color:#c9a84c;font-weight:700}
p{color:#6b6b7a;line-height:1.5}
.tag{margin-top:1.5rem;font-size:.75rem;color:#00d4ff;letter-spacing:.12em;text-transform:uppercase}
</style></head>
<body><div class="card">
<h1>⛔ Connection Blocked</h1>
<p>SecuBox Sentinel neutralized this connection: it matched a high-confidence
threat indicator of class <span class="class">%s</span>.</p>
<p>No data was exchanged with the destination. If you believe this is an error,
contact your SecuBox operator.</p>
<div class="tag">SecuBox · Sentinel · Defensive Threat Engine</div>
</div></body></html>
`

// sentinelBlockPage renders the block page for verdict v (its threat class is
// shown to the user, HTML-escaped). v is expected non-nil (inspect only calls
// this on a real hit) but a nil v degrades to a generic "threat" label rather
// than panicking.
func sentinelBlockPage(v *sentinel.Verdict) []byte {
	class := "threat"
	if v != nil && v.Class != "" {
		class = string(v.Class)
	}
	return []byte(fmt.Sprintf(sentinelBlockPageTemplate, html.EscapeString(class)))
}
