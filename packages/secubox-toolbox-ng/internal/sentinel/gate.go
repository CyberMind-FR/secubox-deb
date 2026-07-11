// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

// Inline gate matcher: the per-flow hot-path lookup that maps a flow's
// observable metadata (host, URL, fingerprints, hashes) to the highest-
// severity matching IOC, if any. This is IOC hash/trie matching ONLY — never
// YARA or heavy analysis — and it must never panic: a Sentinel bug is fail-
// open (the flow passes uninspected) rather than fail-closed (browsing
// breaks), which is why the whole body runs under a recover().
package sentinel

import (
	"log"
	"time"
)

// FlowMeta is the observable metadata of one flow, gathered by cmd/sbxmitm's
// transparent handler, that the gate matches against loaded IOCs.
type FlowMeta struct {
	Host       string
	URL        string
	ClientIP   string
	JA3        string
	JA4        string
	CertSHA1   string
	FileSHA256 string
	MacHash    string
}

// Gate matches FlowMeta against a Loader's current IOCSet. Zero value is not
// usable; use NewGate. A Gate may also be constructed directly with a nil
// loader (e.g. in tests) — Match still never panics in that case.
type Gate struct {
	loader *Loader
}

// NewGate returns a Gate backed by l.
func NewGate(l *Loader) *Gate {
	return &Gate{loader: l}
}

// Match checks m against the gate's current IOC set in cheap-to-expensive
// order (domain, ip, ja4, ja3, cert-sha1, file-sha256, then url-regex last)
// and returns a Verdict built from the highest-Severity hit, or nil if
// nothing matched. It calls the loader's MaybeReload first so the gate
// always evaluates against the latest merged pack state (MaybeReload
// throttles its own disk I/O, so this is cheap on the hot path).
//
// Match never panics: any failure (including a nil loader) is recovered and
// treated as no match, since a Sentinel bug must never break browsing.
func (g *Gate) Match(m FlowMeta) (v *Verdict) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sentinel: gate match recovered from panic (fail-open): %v", r)
			v = nil
		}
	}()

	g.loader.MaybeReload()
	set := g.loader.Set()

	var best *IOC

	if ioc, ok := set.MatchDomain(m.Host); ok {
		best = ioc
	}
	if ioc, ok := set.MatchIP(m.ClientIP); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}
	if ioc, ok := set.MatchJA4(m.JA4); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}
	if ioc, ok := set.MatchJA3(m.JA3); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}
	if ioc, ok := set.MatchCertSHA1(m.CertSHA1); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}
	if ioc, ok := set.MatchFileSHA256(m.FileSHA256); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}
	if ioc, ok := set.MatchURL(m.URL); ok && (best == nil || ioc.Severity > best.Severity) {
		best = ioc
	}

	if best == nil {
		return nil
	}

	// Confidence for a direct IOC hit equals its severity: the entry came
	// from known/curated infrastructure content, not a probabilistic
	// heuristic, so severity and confidence coincide here (behavioral/
	// spyware scoring — Task 6 — is where the two diverge).
	return &Verdict{
		Class:      best.Class,
		Severity:   best.Severity,
		Confidence: best.Severity,
		Action:     best.Action,
		Evidence: map[string]string{
			"ioc_type":  string(best.Type),
			"ioc_value": best.Value,
			"source":    best.Source,
		},
		MacHash: m.MacHash,
		TS:      time.Now().Unix(),
	}
}
